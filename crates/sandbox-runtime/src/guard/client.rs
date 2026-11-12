//! The real [`GuardProbe`]: a client of `/run/wssp-guard/guard.sock`.
//!
//! Every `status()` is one fresh socket request (never cached). The
//! expectations are the caller's own `boot_id` and CLOCK_BOOTTIME, plus the
//! deployment digest the guard returned for this process's last
//! `push_deployment` (`configured:false` expects `not_configured`). The daemon
//! (E3) installs it with `IncusKvmRuntime::set_guard_probe(Arc::new(..))`
//! and calls [`SocketGuardProbe::push_deployment`] on every connect and
//! change; clones share the push state.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandbox_protocol::SandboxErrorCode;

use super::ceiling::EgressCeiling;
use super::protocol::{PolicyAnswer, Reply, Request};
use crate::RuntimeError;
use crate::egress::DomainBlocklist;
use crate::guard_probe::{
    GuardExpectations, GuardProbe, GuardStatus, GuardUnhealthy, MIN_GUARD_VERSION, boottime_now_ns,
    evaluate_guard, read_boot_id,
};

#[derive(Debug, Clone)]
pub struct SocketGuardProbe {
    socket: PathBuf,
    timeout: Duration,
    /// `None`: never pushed in this process. `Some(None)`: pushed
    /// `configured:false`. `Some(Some(d))`: pushed content with digest `d`.
    pushed: Arc<Mutex<Option<Option<String>>>>,
}

impl Default for SocketGuardProbe {
    fn default() -> Self {
        Self::new(super::SOCKET_PATH)
    }
}

fn unreachable(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(SandboxErrorCode::UnsupportedCapability, message)
}

impl SocketGuardProbe {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: Duration::from_secs(2),
            pushed: Arc::new(Mutex::new(None)),
        }
    }

    fn call(&self, request: &Request) -> Result<Reply, RuntimeError> {
        super::protocol::call(&self.socket, request, self.timeout)
            .map_err(|err| unreachable(format!("egress guard unreachable: {err}")))
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Option<Option<String>>> {
        self.pushed.lock().unwrap_or_else(|err| err.into_inner())
    }

    /// `policy`: per-source state, digest and validated domain list (for
    /// `EgressSettings.domain_blocklist` at materialization).
    pub fn policy(&self) -> Result<PolicyAnswer, RuntimeError> {
        match self.call(&Request::Policy {})? {
            Reply::Policy { policy } => Ok(policy),
            Reply::Error { message, .. } => Err(unreachable(message)),
            _ => Err(unreachable("unexpected guard reply")),
        }
    }
}

impl GuardProbe for SocketGuardProbe {
    fn status(&self) -> Result<GuardStatus, RuntimeError> {
        match self.call(&Request::Status {})? {
            Reply::Status { status } => Ok(*status),
            Reply::Error { message, .. } => Err(unreachable(message)),
            _ => Err(unreachable("unexpected guard reply")),
        }
    }

    fn expectations(&self) -> Result<GuardExpectations, RuntimeError> {
        Ok(GuardExpectations {
            min_guard_version: MIN_GUARD_VERSION.max(super::GUARD_VERSION),
            boot_id: read_boot_id()?,
            now_boottime_ns: boottime_now_ns()?,
            deployment_digest: self.slot().clone().flatten(),
        })
    }

    /// `push_deployment` (accepted only from the daemon uid). On success the
    /// guard's digest becomes this probe's expected deployment digest.
    fn push_deployment(
        &self,
        configured: bool,
        entries: Vec<String>,
    ) -> Result<String, RuntimeError> {
        match self.call(&Request::PushDeployment {
            configured,
            entries,
        })? {
            Reply::Pushed { digest, .. } => {
                *self.slot() = Some(configured.then(|| digest.clone()));
                Ok(digest)
            }
            Reply::Error {
                code,
                message,
                line,
            } => Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                match line {
                    Some(line) => {
                        format!("guard refused the push ({code:?}, entry {line}): {message}")
                    }
                    None => format!("guard refused the push ({code:?}): {message}"),
                },
            )),
            _ => Err(unreachable("unexpected guard reply")),
        }
    }

    /// `ceiling`: the egress ceiling and the status of the same guard
    /// publication. Refused unless that status is healthy for this daemon
    /// (version, boot, lease, sources, pushed deployment digest) and a
    /// ceiling is present.
    fn egress_ceiling(&self) -> Result<EgressCeiling, RuntimeError> {
        match self.call(&Request::Ceiling {})? {
            Reply::Ceiling { status, ceiling } => {
                let expect = self.expectations()?;
                evaluate_guard(&status, &expect).map_err(GuardUnhealthy::error)?;
                ceiling.ok_or_else(|| unreachable("the guard published no egress ceiling"))
            }
            Reply::Error { message, .. } => Err(unreachable(message)),
            _ => Err(unreachable("unexpected guard reply")),
        }
    }

    /// The union of both sources' enforced (last valid) domain lists with
    /// their digests. Any guard error refuses: a create never proceeds
    /// without the operator's domain blocklist.
    fn domain_blocklist(&self) -> Result<DomainBlocklist, RuntimeError> {
        let policy = self.policy()?;
        let mut names: Vec<String> = policy
            .root
            .domains
            .iter()
            .chain(policy.deployment.domains.iter())
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        Ok(DomainBlocklist {
            root_digest: policy.root.digest,
            deployment_digest: policy.deployment.digest,
            names,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::protocol::{Handler, ServerConfig, SourcePolicy, serve_connection};
    use crate::guard::sources::SourceState;
    use crate::guard_probe::{FakeGuardProbe, check_guard};
    use std::os::unix::net::UnixListener;

    struct Answer(GuardStatus);

    impl Handler for Answer {
        fn handle(&self, request: Request) -> Reply {
            match request {
                Request::Status {} => Reply::Status {
                    status: Box::new(self.0.clone()),
                },
                Request::PushDeployment { configured, .. } => Reply::Pushed {
                    digest: "sha256:abc".into(),
                    state: if configured {
                        SourceState::Valid {
                            digest: "sha256:abc".into(),
                            cidrs: 1,
                            domains: 0,
                        }
                    } else {
                        SourceState::NotConfigured {
                            digest: "sha256:abc".into(),
                        }
                    },
                },
                Request::Ceiling {} => Reply::Ceiling {
                    status: Box::new(self.0.clone()),
                    ceiling: Some(EgressCeiling::new(
                        &crate::guard::ruleset::GuardInputs {
                            protected4: vec![
                                crate::guard::net::Ipv4Net::parse_cidr("10.0.0.0/8").unwrap(),
                            ],
                            ..Default::default()
                        },
                        vec![],
                    )),
                },
                Request::Policy {} => {
                    let source = |digest: &str, domains: &[&str]| SourcePolicy {
                        state: SourceState::Valid {
                            digest: digest.into(),
                            cidrs: 0,
                            domains: domains.len(),
                        },
                        digest: Some(digest.into()),
                        domains: domains.iter().map(|d| d.to_string()).collect(),
                        cidrs: 0,
                    };
                    Reply::Policy {
                        policy: PolicyAnswer {
                            root: source("sha256:root", &["b.example", "a.example"]),
                            deployment: source("sha256:dep", &["a.example", "c.example"]),
                        },
                    }
                }
            }
        }
    }

    fn serve_n(answer: GuardStatus, n: usize) -> (PathBuf, std::thread::JoinHandle<()>) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("wssp-gc-{}-{nanos}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let handler = Answer(answer);
            for _ in 0..n {
                let (stream, _) = listener.accept().unwrap();
                serve_connection(stream, Some(1000), ServerConfig::new(1000), &handler);
            }
        });
        (path, handle)
    }

    #[test]
    fn domain_blocklist_is_the_deduplicated_union_with_both_digests() {
        let (path, server) = serve_n(FakeGuardProbe::healthy_status(&[]), 1);
        let probe = SocketGuardProbe::new(&path);
        let list = probe.domain_blocklist().unwrap();
        assert_eq!(list.names, ["a.example", "b.example", "c.example"]);
        assert_eq!(list.root_digest.as_deref(), Some("sha256:root"));
        assert_eq!(list.deployment_digest.as_deref(), Some("sha256:dep"));
        server.join().unwrap();
        std::fs::remove_file(&path).unwrap();
        // Unreachable guard: no blocklist, so no create.
        assert!(probe.domain_blocklist().is_err());
    }

    #[test]
    fn egress_ceiling_requires_a_healthy_status_from_the_same_answer() {
        let now = boottime_now_ns().unwrap();
        let mut healthy = FakeGuardProbe::healthy_status(&[]);
        healthy.boot_id = read_boot_id().unwrap();
        healthy.verified_boottime_ns = now;
        healthy.lease_until_boottime_ns = now + 15_000_000_000;
        let (path, server) = serve_n(healthy.clone(), 1);
        let probe = SocketGuardProbe::new(&path);
        let ceiling = probe.egress_ceiling().unwrap();
        assert!(ceiling.refuses("10.1.1.1".parse().unwrap()));
        assert!(!ceiling.refuses("1.1.1.1".parse().unwrap()));
        server.join().unwrap();
        std::fs::remove_file(&path).unwrap();

        // Not ok, or an expired lease: no ceiling (fail closed).
        let mut sick = healthy.clone();
        sick.ok = false;
        let mut stale = healthy;
        stale.lease_until_boottime_ns = 1;
        stale.verified_boottime_ns = 0;
        for status in [sick, stale] {
            let (path, server) = serve_n(status, 1);
            let probe = SocketGuardProbe::new(&path);
            assert!(probe.egress_ceiling().is_err());
            server.join().unwrap();
            std::fs::remove_file(&path).unwrap();
        }
        // Unreachable: no ceiling.
        assert!(probe.egress_ceiling().is_err());
    }

    #[test]
    fn unreachable_socket_refuses() {
        let probe = SocketGuardProbe::new("/nonexistent/wssp-guard.sock");
        assert!(probe.status().is_err());
        assert!(check_guard(&probe).is_err());
    }

    #[test]
    fn status_is_fetched_fresh_and_push_sets_the_expected_digest() {
        let status = FakeGuardProbe::healthy_status(&[]);
        let (path, server) = serve_n(status.clone(), 3);
        let probe = SocketGuardProbe::new(&path);
        assert_eq!(probe.expectations().unwrap().deployment_digest, None);
        assert_eq!(probe.status().unwrap(), status);
        assert_eq!(
            probe.push_deployment(true, vec!["1.1.1.1".into()]).unwrap(),
            "sha256:abc"
        );
        assert_eq!(
            probe
                .clone()
                .expectations()
                .unwrap()
                .deployment_digest
                .as_deref(),
            Some("sha256:abc")
        );
        probe.push_deployment(false, vec![]).unwrap();
        assert_eq!(probe.expectations().unwrap().deployment_digest, None);
        server.join().unwrap();
        std::fs::remove_file(&path).unwrap();
        // Real clock and boot id are read, never a cached value.
        let expect = probe.expectations().unwrap();
        assert!(!expect.boot_id.is_empty() && expect.now_boottime_ns > 0);
    }
}
