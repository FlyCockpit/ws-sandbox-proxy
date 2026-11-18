//! `wssp-guard __wssp-guard`: the root guard service loop.
//!
//! On any event (route/address/link monitor, nftables monitor, root-file
//! change, deployment push) or every 5 s: read routes (all tables), links,
//! addresses, the full ruleset and qdiscs plus the root file; classify;
//! compile; apply the whole table in one `nft -f -` transaction; read it
//! back and compare semantically; publish status. The periodic pass always
//! re-applies, which renews the dead-man; event passes re-apply only when
//! the inputs changed and otherwise just verify the readback (so our own
//! apply events cannot loop).
//!
//! Any failure in that sequence quarantines:
//!
//! 1. the same table with `live_bridges` empty, applied and read back;
//! 2. a conntrack cleanup OBLIGATION for the sandbox subnets, retried on
//!    every pass until confirmed under the verified quarantine table — a
//!    delete followed by a SUCCESSFUL filtered readback that lists zero
//!    entries (forwarding is never restored while it is owed);
//! 3. the FENCE — every `wsn-*` bridge and port taken administratively down
//!    and read back — whenever the table alone cannot guarantee the cut:
//!    the supported packet path is not established by a current
//!    classification (a finding such as an XDP/tc redirect that never meets
//!    netfilter, a dead monitor or a failed classification — raised BEFORE
//!    the cleanup is attempted), an unverified quarantine table, or an
//!    unconfirmed cleanup.
//!
//! Forwarding comes back only from a CURRENT healthy classification: the
//! cleanup confirmed, the live table applied and verified, then the fenced
//! links (recorded by name and ifindex in `fenced.json` before they went
//! down) brought back up and read back. A restart never replays an older
//! table: the kernel table stays as the previous instance left it (its
//! dead-man keeps expiring) until the new instance classifies the node.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sandbox_runtime::guard::ceiling::EgressCeiling;
use sandbox_runtime::guard::net::Ipv4Net;
use sandbox_runtime::guard::net::protected4;
use sandbox_runtime::guard::path::{
    ExcludedBridge, HOST_FIREWALL_REASON, PathInputs, PathReport, SandboxLink, sandbox_links,
};
use sandbox_runtime::guard::protocol::{
    ErrorCode, Handler, PolicyAnswer, Reply, Request, ServerConfig, SourcePolicy,
};
use sandbox_runtime::guard::ruleset::{GatewayPair, GuardInputs, compile, verify_readback};
use sandbox_runtime::guard::sources::{self, PolicyContent, Source, deny4, domain_union_fits};
use sandbox_runtime::guard::status::{new_instance_id, source_reason, source_status};
use sandbox_runtime::guard::{
    CHILD_TIMEOUT, GUARD_VERSION, LEASE, LIVE_TIMEOUT, RESYNC_INTERVAL, TABLE,
};
use sandbox_runtime::guard_probe::{
    GuardGateway, GuardSourceState, GuardSourceStatus, GuardSources, GuardStatus,
};

use super::paths::Paths;
use super::{GuardConfig, preflight, tools};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Changed,
    MonitorDied(&'static str),
    Pushed,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedSource {
    content: PolicyContent,
}

struct Published {
    status: GuardStatus,
    policy: PolicyAnswer,
    /// The egress ceiling of the last healthy pass; `None` unless `status`
    /// is ok (`{"op":"ceiling"}` answers both from this one snapshot).
    ceiling: Option<EgressCeiling>,
}

pub(super) struct Shared {
    paths: Paths,
    /// Deployment source is written by the socket thread, read by the loop.
    deployment: Mutex<Source>,
    /// Serialize durable publication and its matching in-memory acceptance.
    publish: Mutex<()>,
    published: Mutex<Published>,
    events: Mutex<mpsc::Sender<Event>>,
}

fn source_policy(source: &Source) -> SourcePolicy {
    SourcePolicy {
        state: source.state.clone(),
        digest: source.last_valid.as_ref().map(PolicyContent::digest),
        domains: source.domains().to_vec(),
        cidrs: source.cidrs().len(),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl Handler for Shared {
    fn handle(&self, request: Request) -> Reply {
        match request {
            Request::Status {} => Reply::Status {
                status: Box::new(lock(&self.published).status.clone()),
            },
            Request::Policy {} => Reply::Policy {
                policy: lock(&self.published).policy.clone(),
            },
            Request::Ceiling {} => {
                let published = lock(&self.published);
                Reply::Ceiling {
                    status: Box::new(published.status.clone()),
                    ceiling: published.ceiling.clone(),
                }
            }
            Request::PushDeployment {
                configured,
                entries,
            } => {
                if !configured && !entries.is_empty() {
                    return Reply::error(
                        ErrorCode::InvalidRequest,
                        "configured:false carries no entries",
                    );
                }
                let content = match sources::parse_entries(&entries) {
                    Ok(content) => content,
                    Err(err) => {
                        return Reply::Error {
                            code: ErrorCode::InvalidSource,
                            message: err.reason,
                            line: err.line,
                        };
                    }
                };
                let _publish = lock(&self.publish);
                // Durable first: a crash after the reply never loses it.
                if let Err(err) = persist_source(&self.paths.deployment_source(), &content) {
                    tracing::error!(error = %err, "cannot persist the deployment source");
                    return Reply::error(ErrorCode::Internal, "cannot persist the push");
                }
                let digest = content.digest();
                let state = {
                    let mut deployment = lock(&self.deployment);
                    deployment.accept(content, configured);
                    deployment.state.clone()
                };
                let _ = lock(&self.events).send(Event::Pushed);
                Reply::Pushed { digest, state }
            }
        }
    }
}

/// Write `bytes` durably: temp file in the same directory, fsync, rename,
/// fsync the directory.
pub(super) fn durable_write(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("path has no directory"))?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("guard"),
        new_instance_id()?
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    let result = (|| {
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn persist_source(path: &Path, content: &PolicyContent) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let body = serde_json::to_vec(&PersistedSource {
        content: content.clone(),
    })
    .map_err(std::io::Error::other)?;
    durable_write(path, &body, 0o600)
}

fn load_source(path: &Path) -> Option<PolicyContent> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<PersistedSource>(&bytes) {
        Ok(record) => Some(record.content),
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "ignoring an unreadable persisted source");
            None
        }
    }
}

/// Fingerprint of the root list and its directory (polled every second;
/// any change triggers a resync, so edits apply live).
fn root_fingerprint(path: &Path) -> Vec<i64> {
    let mut print = Vec::new();
    for p in [path.parent().unwrap_or(path), path] {
        match std::fs::symlink_metadata(p) {
            Ok(meta) => print.extend([
                meta.dev() as i64,
                meta.ino() as i64,
                meta.size() as i64,
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec(),
                i64::from(meta.mode()),
                i64::from(meta.uid()),
            ]),
            Err(_) => print.push(-1),
        }
    }
    print
}

pub(super) struct Snapshot {
    pub(super) routes: serde_json::Value,
    pub(super) links: serde_json::Value,
    pub(super) addresses: serde_json::Value,
    pub(super) ruleset: serde_json::Value,
    pub(super) qdiscs: serde_json::Value,
}

fn read_snapshot() -> Result<Snapshot> {
    Ok(Snapshot {
        routes: tools::json(
            "ip",
            &["-j", "-4", "route", "show", "table", "all"],
            CHILD_TIMEOUT,
        )?,
        links: tools::json("ip", &["-j", "-d", "link", "show"], CHILD_TIMEOUT)?,
        addresses: tools::json("ip", &["-j", "-4", "addr", "show"], CHILD_TIMEOUT)?,
        ruleset: tools::json("nft", &["-j", "list", "ruleset"], CHILD_TIMEOUT)?,
        qdiscs: tools::json("tc", &["-j", "qdisc", "show"], CHILD_TIMEOUT)?,
    })
}

enum Classified {
    /// With the node's own addresses (for the egress ceiling).
    Healthy(GuardInputs, PathReport, Vec<Ipv4Net>),
    /// Packet-path findings: quarantine plus conntrack deletion.
    UnsupportedPath(GuardInputs, PathReport),
}

fn classify(
    snapshot: &Snapshot,
    deny: Vec<sandbox_runtime::guard::net::Ipv4Net>,
) -> Result<Classified> {
    let routes = sandbox_runtime::guard::routes::classify(&snapshot.routes)
        .map_err(anyhow::Error::msg)
        .context("route classification")?;
    let report = sandbox_runtime::guard::path::check(&PathInputs {
        ruleset: &snapshot.ruleset,
        links: &snapshot.links,
        addresses: &snapshot.addresses,
        qdiscs: &snapshot.qdiscs,
        uplinks: &routes.uplinks,
    })
    .map_err(anyhow::Error::msg)
    .context("packet-path check")?;
    let node4 = routes.node4;
    let inputs = GuardInputs {
        protected4: protected4().map_err(anyhow::Error::msg)?.to_vec(),
        scope4: routes.scope4,
        deny4: deny,
        uplinks: routes.uplinks,
        gateways: report.bridges.clone(),
        live_bridges: report.bridges.iter().map(|p| p.bridge.clone()).collect(),
    }
    .canonical();
    Ok(if report.findings.is_empty() {
        Classified::Healthy(inputs, report, node4)
    } else {
        Classified::UnsupportedPath(inputs, report)
    })
}

/// Host side effects of a resync. Behind a trait so the quarantine state
/// machine (cleanup obligation, fence, restart) is unit-tested without root
/// (`daemon_tests.rs`); [`SystemOps`] is the only production impl.
pub(super) trait Ops {
    fn snapshot(&self) -> Result<Snapshot>;
    /// Replace the whole table in one `nft -f -` transaction.
    fn apply(&self, inputs: &GuardInputs, live_timeout_secs: u64) -> Result<()>;
    /// Semantic readback of the installed table against `inputs`.
    fn readback(&self, inputs: &GuardInputs) -> Result<()>;
    /// The conntrack cleanup capability is present and works (ctnetlink).
    fn conntrack_probe(&self) -> Result<()>;
    /// Delete every conntrack entry whose original source is in `subnets`.
    /// `Ok` only means the delete did not report a definite error: conntrack
    /// exits 1 both for "nothing matched" and for operational failures, so
    /// a delete is never proof of cleanup on its own.
    fn conntrack_delete(&self, subnets: &[Ipv4Net]) -> Result<()>;
    /// Filtered readback: how many conntrack entries whose original source
    /// is in `subnets` remain. `Ok(0)` from a SUCCESSFUL listing is the only
    /// confirmation of cleanup; any listing failure is an error.
    fn conntrack_remaining(&self, subnets: &[Ipv4Net]) -> Result<usize>;
    /// `ip -j -4 addr show`.
    fn addresses(&self) -> Result<serde_json::Value>;
    /// `ip -j -d link show`.
    fn links(&self) -> Result<serde_json::Value>;
    /// `ip link set dev <name> up|down`.
    fn set_link(&self, name: &str, up: bool) -> Result<()>;
}

pub(super) struct SystemOps;

impl Ops for SystemOps {
    fn snapshot(&self) -> Result<Snapshot> {
        read_snapshot()
    }

    fn apply(&self, inputs: &GuardInputs, live_timeout_secs: u64) -> Result<()> {
        let text = compile(inputs, live_timeout_secs).map_err(anyhow::Error::msg)?;
        let output = tools::run("nft", &["-f", "-"], Some(text.as_bytes()), CHILD_TIMEOUT)?;
        if !output.success {
            bail!("`nft -f -` failed: {}", output.stderr_line());
        }
        Ok(())
    }

    fn readback(&self, inputs: &GuardInputs) -> Result<()> {
        let listing = tools::json(
            "nft",
            &["-j", "list", "table", "inet", TABLE],
            CHILD_TIMEOUT,
        )?;
        verify_readback(inputs, &listing).map_err(anyhow::Error::msg)
    }

    fn conntrack_probe(&self) -> Result<()> {
        if !tools::available("conntrack") {
            bail!(CONNTRACK_UNAVAILABLE);
        }
        // `-C` reads the table counter over ctnetlink: proves the module
        // and the capability without dumping the table.
        let output = tools::run("conntrack", &["-C"], None, CHILD_TIMEOUT)?;
        if !output.success {
            bail!("`conntrack -C` failed: {}", output.stderr_line());
        }
        Ok(())
    }

    /// ctnetlink delete of every conntrack entry whose original source is a
    /// sandbox subnet (§2.0.1): removes any (software or hardware)
    /// flowtable entry for those flows; the quarantined guard then drops the
    /// next packet before conntrack can confirm (or re-offload) it.
    fn conntrack_delete(&self, subnets: &[Ipv4Net]) -> Result<()> {
        if subnets.is_empty() {
            return Ok(());
        }
        if !tools::available("conntrack") {
            bail!(CONNTRACK_UNAVAILABLE);
        }
        for net in subnets {
            let (address, mask) = source_filter(net);
            let output = tools::run(
                "conntrack",
                &["-D", "-f", "ipv4", "-s", &address, "--mask-src", &mask],
                None,
                CHILD_TIMEOUT,
            )?;
            // Exit 1 is ambiguous (nothing matched, or an operational
            // error): tolerated here, settled by `conntrack_remaining`.
            if !output.success && output.code != Some(1) {
                bail!(
                    "conntrack delete for `{net}` failed: {}",
                    output.stderr_line()
                );
            }
        }
        Ok(())
    }

    /// `conntrack -L` with the same source filter: exits 0 on a successful
    /// dump (also when it is empty) and prints one entry per line.
    fn conntrack_remaining(&self, subnets: &[Ipv4Net]) -> Result<usize> {
        if subnets.is_empty() {
            return Ok(0);
        }
        if !tools::available("conntrack") {
            bail!(CONNTRACK_UNAVAILABLE);
        }
        let mut remaining = 0;
        for net in subnets {
            let (address, mask) = source_filter(net);
            let output = tools::run(
                "conntrack",
                &["-L", "-f", "ipv4", "-s", &address, "--mask-src", &mask],
                None,
                CHILD_TIMEOUT,
            )?;
            if !output.success {
                bail!(
                    "conntrack readback for `{net}` failed: {}",
                    output.stderr_line()
                );
            }
            remaining += String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count();
        }
        Ok(remaining)
    }

    fn addresses(&self) -> Result<serde_json::Value> {
        tools::json("ip", &["-j", "-4", "addr", "show"], CHILD_TIMEOUT)
    }

    fn links(&self) -> Result<serde_json::Value> {
        tools::json("ip", &["-j", "-d", "link", "show"], CHILD_TIMEOUT)
    }

    fn set_link(&self, name: &str, up: bool) -> Result<()> {
        let state = if up { "up" } else { "down" };
        let output = tools::run(
            "ip",
            &["link", "set", "dev", name, state],
            None,
            CHILD_TIMEOUT,
        )?;
        if !output.success {
            bail!(
                "`ip link set dev {name} {state}` failed: {}",
                output.stderr_line()
            );
        }
        Ok(())
    }
}

const CONNTRACK_UNAVAILABLE: &str = "conntrack_unavailable";

/// `-s <address> --mask-src <mask>` for an original-source subnet filter.
fn source_filter(net: &Ipv4Net) -> (String, String) {
    let mask = std::net::Ipv4Addr::from(if net.prefix() == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(net.prefix()))
    });
    (net.address().to_string(), mask.to_string())
}

/// Why a pass cannot admit forwarding.
struct Refusal {
    reason: String,
    /// The current (healthy-shaped) inputs, when classification got that far.
    base: Option<GuardInputs>,
    report: Option<PathReport>,
    /// A CURRENT classification established that sandbox packets traverse
    /// the guard's table (no packet-path finding). When it did not — a
    /// finding (XDP/tc redirect, offload), a dead monitor, a failed
    /// classification — the table cannot be relied on to cut running
    /// traffic, so the fence is mandatory.
    path_established: bool,
}

impl Refusal {
    /// A refusal before (or without) a current classification: the packet
    /// path is unknown.
    fn unknown_path(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            base: None,
            report: None,
            path_established: false,
        }
    }
}

fn same_link(a: &SandboxLink, b: &SandboxLink) -> bool {
    a.name == b.name && a.ifindex == b.ifindex
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FenceRecord {
    links: Vec<SandboxLink>,
}

fn load_fence(path: &Path) -> Vec<SandboxLink> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    match serde_json::from_slice::<FenceRecord>(&bytes) {
        Ok(record) => record.links,
        Err(err) => {
            tracing::error!(path = %path.display(), error = %err, "unreadable fence record; links it named stay down until an operator brings them up");
            Vec::new()
        }
    }
}

pub(super) struct Daemon {
    shared: Arc<Shared>,
    ops: Box<dyn Ops>,
    instance_id: String,
    boot_id: String,
    generation: u64,
    repairs: u64,
    root: Source,
    last_applied: Option<GuardInputs>,
    last_good_report: Option<PathReport>,
    /// The egress ceiling of the table verified by the last healthy pass;
    /// cleared by every quarantine.
    ceiling: Option<EgressCeiling>,
    verified_ns: Option<u64>,
    lease_ns: Option<u64>,
    monitor_failed: Option<&'static str>,
    quarantine_reason: Option<String>,
    /// A conntrack cleanup is owed: set on every quarantine entry, retried
    /// on every pass, cleared only by a confirmed delete under a verified
    /// quarantine table. Forwarding is never restored while it is owed.
    cleanup_pending: bool,
    cleanup_error: Option<&'static str>,
    /// Sandbox links this guard took administratively down (persisted in
    /// `fenced.json` BEFORE they go down). Brought back up only after a
    /// current healthy classification and a verified live table.
    fenced: Vec<SandboxLink>,
}

impl Daemon {
    pub(super) fn new(
        shared: Arc<Shared>,
        ops: Box<dyn Ops>,
        instance_id: String,
        boot_id: String,
        root: Source,
    ) -> Self {
        // Older guards persisted `applied.json` and replayed it on start;
        // a historical healthy table must never be re-installed (it would
        // reopen forwarding that a quarantine cut). The kernel table is
        // left exactly as the previous instance installed it.
        let _ = std::fs::remove_file(shared.paths.state_dir().join("applied.json"));
        let fenced = load_fence(&shared.paths.fenced());
        Self {
            // A previous instance fenced links: it was in a quarantine whose
            // cleanup may not have been confirmed.
            cleanup_pending: !fenced.is_empty(),
            fenced,
            shared,
            ops,
            instance_id,
            boot_id,
            generation: 0,
            repairs: 0,
            root,
            last_applied: None,
            last_good_report: None,
            ceiling: None,
            verified_ns: None,
            lease_ns: None,
            monitor_failed: None,
            quarantine_reason: None,
            cleanup_error: None,
        }
    }

    fn refresh_root(&mut self) {
        let read = sources::read_root_file(&self.shared.paths.root_blocklist(), 0);
        match sources::root_state(read) {
            Ok(content) => {
                let changed = self.root.last_valid.as_ref() != Some(&content);
                self.root.accept_root_file(content.clone());
                if changed
                    && let Err(err) = persist_source(&self.shared.paths.root_source(), &content)
                {
                    tracing::warn!(error = %err, "cannot persist the root source");
                }
            }
            Err(state) => {
                if self.root.state != state {
                    tracing::warn!(
                        state = state.label(),
                        "root egress blocklist is not usable; keeping the last valid list"
                    );
                }
                self.root.reject(state);
            }
        }
    }

    /// Classify the CURRENT node. `Ok` only when forwarding may be admitted.
    /// The packet path is classified first, so every later refusal knows
    /// whether the quarantine table alone can cut running traffic.
    fn evaluate(
        &mut self,
        deployment: &Source,
    ) -> Result<(GuardInputs, PathReport, Vec<Ipv4Net>), Box<Refusal>> {
        if let Some(name) = self.monitor_failed {
            // Without the monitors a redirect installed between passes goes
            // unseen: the path is not established.
            return Err(Box::new(Refusal::unknown_path(format!(
                "monitor_failed:{name}"
            ))));
        }
        let deny = deny4(&self.root, deployment);
        let (inputs, path, node4) = match self.ops.snapshot().and_then(|s| classify(&s, deny)) {
            Err(err) => {
                tracing::error!(error = %format!("{err:#}"), "classification failed");
                return Err(Box::new(Refusal::unknown_path("classification_failed")));
            }
            Ok(Classified::UnsupportedPath(inputs, path)) => {
                return Err(Box::new(Refusal {
                    reason: format!("unsupported_packet_path:{}", path.findings.join(",")),
                    base: Some(inputs),
                    report: Some(path),
                    path_established: false,
                }));
            }
            Ok(Classified::Healthy(inputs, path, node4)) => (inputs, path, node4),
        };
        let refuse = |reason: String, inputs: GuardInputs, path: PathReport| {
            Box::new(Refusal {
                reason,
                base: Some(inputs),
                report: Some(path),
                path_established: true,
            })
        };
        // A source with no usable snapshot (never valid, nothing persisted)
        // is unknown content, not an empty deny set.
        for (name, source) in [("root", &self.root), ("deployment", deployment)] {
            if source.last_valid.is_none() {
                return Err(refuse(format!("source_unusable:{name}"), inputs, path));
            }
        }
        if let Err(err) = self.ops.conntrack_probe() {
            tracing::error!(error = %format!("{err:#}"), "conntrack cleanup capability missing");
            return Err(refuse(CONNTRACK_UNAVAILABLE.into(), inputs, path));
        }
        Ok((inputs, path, node4))
    }

    /// Cut sandbox forwarding: the quarantine table (empty `live_bridges`),
    /// the conntrack cleanup obligation, and — when the table alone cannot
    /// guarantee the cut — the link fence. `path_established` is true only
    /// when a current classification showed the supported packet path.
    fn quarantine(
        &mut self,
        reason: String,
        base: Option<GuardInputs>,
        path_established: bool,
    ) -> Vec<String> {
        if self.quarantine_reason.as_deref() != Some(reason.as_str()) {
            tracing::error!(%reason, "guard quarantine: sandbox forwarding cut");
            // Every quarantine entry owes a cleanup: an established or
            // offloaded flow must not outlive the cut.
            self.cleanup_pending = true;
        }
        let deployment = lock(&self.shared.deployment).clone();
        let mut inputs = base
            .or_else(|| self.last_applied.clone())
            .unwrap_or_else(|| GuardInputs {
                protected4: protected4().map(<[_]>::to_vec).unwrap_or_default(),
                ..GuardInputs::default()
            });
        inputs.deny4 = deny4(&self.root, &deployment);
        let quarantined = inputs.quarantined().canonical();
        let mut reasons = vec![reason.clone()];
        // The fence is independent of the table and of conntrack: no XDP or
        // tc redirect, and no surviving (offloaded) flow, crosses a link
        // that is administratively down. With the path unknown it goes up
        // FIRST, before the table and the cleanup: a bypass must not keep
        // recreating entries while the cleanup runs.
        let mut fenced = false;
        if !path_established {
            self.fence(&mut reasons);
            fenced = true;
        }
        // No dead-man to renew while quarantined: re-apply only when the
        // quarantine table changed or is missing/altered (our own apply
        // events must not re-trigger an apply). Either way it is verified.
        let in_place = self.last_applied.as_ref() == Some(&quarantined)
            && self.ops.readback(&quarantined).is_ok();
        let table_ok = in_place
            || {
                let applied = self.ops.apply(&quarantined, LIVE_TIMEOUT.as_secs());
                if applied.is_ok() {
                    self.last_applied = Some(quarantined.clone());
                }
                match applied.and_then(|()| self.ops.readback(&quarantined)) {
                    Ok(()) => true,
                    Err(err) => {
                        tracing::error!(error = %format!("{err:#}"), "quarantine apply or readback failed");
                        reasons.push("quarantine_unverified".into());
                        false
                    }
                }
            };
        if self.cleanup_pending {
            self.settle_cleanup(table_ok);
        }
        reasons.extend(self.cleanup_error.map(str::to_string));
        if !fenced && (!table_ok || self.cleanup_pending) {
            self.fence(&mut reasons);
        }
        self.quarantine_reason = Some(reason);
        self.ceiling = None;
        self.verified_ns = None;
        self.lease_ns = None;
        reasons
    }

    fn fence(&mut self, reasons: &mut Vec<String>) {
        match self.raise_fence() {
            Ok(()) => reasons.push(format!("fenced_links:{}", self.fenced.len())),
            Err(err) => {
                tracing::error!(error = %format!("{err:#}"), "quarantine fence not verified");
                reasons.push("fence_unverified".into());
            }
        }
    }

    /// One attempt at the owed conntrack cleanup. Only under a verified
    /// quarantine table: otherwise the next packet would recreate (and
    /// could re-offload) the entry.
    fn settle_cleanup(&mut self, table_ok: bool) {
        let result = if !table_ok {
            Err("conntrack_cleanup_blocked")
        } else {
            let subnets = self.ops.addresses().and_then(|listing| {
                sandbox_runtime::guard::path::sandbox_subnets(&listing).map_err(anyhow::Error::msg)
            });
            match subnets {
                Err(err) => {
                    tracing::error!(error = %format!("{err:#}"), "cannot read the sandbox subnets");
                    Err("conntrack_cleanup_failed")
                }
                Ok(subnets) => self
                    .ops
                    .conntrack_delete(&subnets)
                    .map_err(|err| {
                        tracing::error!(error = %format!("{err:#}"), "conntrack delete failed");
                        if err.to_string() == CONNTRACK_UNAVAILABLE {
                            CONNTRACK_UNAVAILABLE
                        } else {
                            "conntrack_delete_failed"
                        }
                    })
                    // A delete that did not error is not proof (conntrack
                    // exits 1 for "nothing matched" and for operational
                    // errors alike): only a successful filtered readback of
                    // zero entries confirms the cleanup.
                    .and_then(|()| match self.ops.conntrack_remaining(&subnets) {
                        Ok(0) => Ok(()),
                        Ok(remaining) => {
                            tracing::error!(remaining, "conntrack entries survived the delete");
                            Err("conntrack_cleanup_unconfirmed")
                        }
                        Err(err) => {
                            tracing::error!(error = %format!("{err:#}"), "conntrack readback failed");
                            Err("conntrack_cleanup_unconfirmed")
                        }
                    }),
            }
        };
        match result {
            Ok(()) => {
                tracing::info!("quarantine conntrack cleanup confirmed");
                self.cleanup_pending = false;
                self.cleanup_error = None;
            }
            Err(code) => self.cleanup_error = Some(code),
        }
    }

    fn persist_fence(&self) -> std::io::Result<()> {
        let path = self.shared.paths.fenced();
        if self.fenced.is_empty() {
            return match std::fs::remove_file(&path) {
                Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err),
                _ => Ok(()),
            };
        }
        let body = serde_json::to_vec(&FenceRecord {
            links: self.fenced.clone(),
        })
        .map_err(std::io::Error::other)?;
        durable_write(&path, &body, 0o600)
    }

    /// Take every sandbox bridge and port administratively down, then read
    /// the links back: verified only when none is up. A down device has a
    /// noop qdisc (nothing transmits), `mirred` and XDP redirects refuse a
    /// down target, and the tun driver refuses guest writes to a down tap.
    fn raise_fence(&mut self) -> Result<()> {
        let targets = sandbox_links(&self.ops.links()?).map_err(anyhow::Error::msg)?;
        let mut added = false;
        for link in targets.iter().filter(|l| l.up) {
            if !self.fenced.iter().any(|f| same_link(f, link)) {
                self.fenced.push(link.clone());
                added = true;
            }
        }
        if added {
            self.fenced.sort();
            // Durable BEFORE the links go down, so a crash in between still
            // knows what to restore. A failed write never stops the fence.
            if let Err(err) = self.persist_fence() {
                tracing::error!(error = %err, "cannot persist the fence record");
            }
        }
        // Ports first (sorted), then bridges.
        for link in targets.iter().filter(|l| l.up) {
            if let Err(err) = self.ops.set_link(&link.name, false) {
                tracing::error!(link = %link.name, error = %format!("{err:#}"), "cannot take a sandbox link down");
            }
        }
        let after = sandbox_links(&self.ops.links()?).map_err(anyhow::Error::msg)?;
        if let Some(up) = after.iter().find(|l| l.up) {
            bail!("sandbox link `{}` is still up", up.name);
        }
        Ok(())
    }

    /// Restore the links this guard fenced (same name and ifindex; bridges
    /// before ports). Called only after a current healthy classification,
    /// a confirmed cleanup and a verified live table.
    fn lift_fence(&mut self) -> Result<()> {
        if self.fenced.is_empty() {
            return Ok(());
        }
        let current = sandbox_links(&self.ops.links()?).map_err(anyhow::Error::msg)?;
        let mut todo: Vec<&SandboxLink> = current
            .iter()
            .filter(|l| !l.up && self.fenced.iter().any(|f| same_link(f, l)))
            .collect();
        todo.sort_by_key(|l| (!l.bridge, l.name.clone()));
        for link in todo {
            self.ops.set_link(&link.name, true)?;
        }
        let after = sandbox_links(&self.ops.links()?).map_err(anyhow::Error::msg)?;
        if let Some(down) = after
            .iter()
            .find(|l| !l.up && self.fenced.iter().any(|f| same_link(f, l)))
        {
            bail!("fenced link `{}` did not come back up", down.name);
        }
        // Links that are gone (deleted VM, detached port) are dropped.
        self.fenced.clear();
        self.persist_fence().context("removing the fence record")?;
        tracing::info!("quarantine fence lifted: sandbox links restored");
        Ok(())
    }

    /// One pass. `renew` forces an apply (periodic dead-man renewal).
    pub(super) fn resync(&mut self, renew: bool) {
        self.refresh_root();
        let deployment = lock(&self.shared.deployment).clone();
        let (quarantine, report) = match self.evaluate(&deployment) {
            Err(refusal) => (
                Some(self.quarantine(refusal.reason, refusal.base, refusal.path_established)),
                refusal.report,
            ),
            Ok((inputs, path, node4)) => self.admit(inputs, path, node4, renew),
        };
        self.publish(quarantine, report, &deployment);
    }

    /// A current healthy classification: settle an owed cleanup (still
    /// under quarantine), apply and verify the live table, lift the fence.
    fn admit(
        &mut self,
        inputs: GuardInputs,
        path: PathReport,
        node4: Vec<Ipv4Net>,
        renew: bool,
    ) -> (Option<Vec<String>>, Option<PathReport>) {
        if self.cleanup_pending {
            let reason = self
                .quarantine_reason
                .clone()
                .unwrap_or_else(|| "conntrack_cleanup_pending".into());
            // `inputs` is a current healthy classification: the path is
            // established, only the owed cleanup holds the cut.
            let reasons = self.quarantine(reason, Some(inputs.clone()), true);
            if self.cleanup_pending {
                return (Some(reasons), Some(path));
            }
        }
        if let Err(err) = self.apply_and_verify(&inputs, renew) {
            tracing::error!(error = %format!("{err:#}"), "apply or readback failed");
            let reasons = self.quarantine("readback_failed".into(), Some(inputs), true);
            return (Some(reasons), Some(path));
        }
        if let Err(err) = self.lift_fence() {
            tracing::error!(error = %format!("{err:#}"), "cannot lift the quarantine fence");
            self.ceiling = None;
            self.verified_ns = None;
            self.lease_ns = None;
            return (Some(vec!["fence_restore_failed".into()]), Some(path));
        }
        if self.quarantine_reason.take().is_some() {
            tracing::info!("guard recovered: sandbox forwarding restored");
        }
        self.cleanup_error = None;
        self.ceiling = Some(EgressCeiling::new(&inputs, node4));
        self.generation += 1;
        self.last_good_report = Some(path.clone());
        (None, Some(path))
    }

    fn apply_and_verify(&mut self, inputs: &GuardInputs, renew: bool) -> Result<()> {
        let unchanged = self.last_applied.as_ref() == Some(inputs);
        if unchanged && !renew && self.ops.readback(inputs).is_ok() {
            // Verified without touching the table.
        } else {
            let repaired = unchanged && !renew;
            self.ops.apply(inputs, LIVE_TIMEOUT.as_secs())?;
            self.last_applied = Some(inputs.clone());
            self.ops.readback(inputs)?;
            if repaired {
                self.repairs += 1;
                tracing::warn!("guard table was missing or altered; re-applied");
            }
        }
        let now = boottime_ns()?;
        self.verified_ns = Some(now);
        self.lease_ns = Some(now + LEASE.as_nanos() as u64);
        Ok(())
    }

    fn publish(
        &mut self,
        quarantine: Option<Vec<String>>,
        report: Option<PathReport>,
        deployment: &Source,
    ) {
        let applied = self.last_applied.clone().unwrap_or_default();
        let mut reasons = Vec::new();
        let quarantined = quarantine.as_ref().map(|r| r[0].clone());
        if let Some(q) = quarantine {
            reasons.extend(q);
        }
        for (name, source) in [("root", &self.root), ("deployment", deployment)] {
            reasons.extend(source_reason(name, source));
        }
        if !domain_union_fits(&self.root, deployment) {
            reasons.push("domain_blocklist_too_large".into());
        }
        let current = report.as_ref().or(self.last_good_report.as_ref());
        let excluded: Vec<ExcludedBridge> = current.map(|r| r.excluded.clone()).unwrap_or_default();
        // A host firewall that drops `wsn-*` traffic leaves every new
        // sandbox without DHCP/DNS: unhealthy (no new sandboxes), never a
        // quarantine (it cannot let a packet skip the guard).
        let host_firewall: Vec<String> =
            current.map(|r| r.host_firewall.clone()).unwrap_or_default();
        if !host_firewall.is_empty() {
            reasons.push(format!(
                "{HOST_FIREWALL_REASON}:{}",
                host_firewall.join(",")
            ));
        }
        // Excluded bridges are reported, never fatal for the others.
        reasons.extend(
            excluded
                .iter()
                .map(|e| format!("excluded_bridge:{}:{}", e.bridge, e.reason)),
        );
        let fits = domain_union_fits(&self.root, deployment);
        let counts = [
            ("protected4", applied.protected4.len()),
            ("scope4", applied.scope4.len()),
            ("deny4", applied.deny4.len()),
            ("uplinks", applied.uplinks.len()),
            ("gateways", applied.gateways.len()),
            ("live_bridges", applied.live_bridges.len()),
            ("excluded_bridges", excluded.len()),
            ("repairs", self.repairs as usize),
            ("fenced_links", self.fenced.len()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v as u64))
        .collect();
        let status = GuardStatus {
            guard_version: GUARD_VERSION,
            instance_id: self.instance_id.clone(),
            boot_id: self.boot_id.clone(),
            generation: self.generation,
            // The last resync fully succeeded and nothing is quarantined
            // (source health is reported in `sources`).
            ok: quarantined.is_none()
                && self.lease_ns.is_some()
                && fits
                && host_firewall.is_empty(),
            quarantined,
            reasons,
            sources: GuardSources {
                root: source_status(&self.root),
                deployment: source_status(deployment),
            },
            live_bridges: applied.live_bridges.clone(),
            gateways: applied
                .gateways
                .iter()
                .map(|pair: &GatewayPair| GuardGateway {
                    bridge: pair.bridge.clone(),
                    gateway: pair.gateway,
                })
                .collect(),
            uplinks: applied.uplinks.clone(),
            counts,
            verified_boottime_ns: self.verified_ns.unwrap_or(0),
            lease_until_boottime_ns: self.lease_ns.unwrap_or(0),
        };
        let policy = PolicyAnswer {
            root: source_policy(&self.root),
            deployment: source_policy(deployment),
        };
        if let Ok(body) = serde_json::to_vec_pretty(&status)
            && let Err(err) = durable_write(&self.shared.paths.status_file(), &body, 0o644)
        {
            tracing::warn!(error = %err, "cannot write the status file");
        }
        let ceiling = if status.ok {
            self.ceiling.clone()
        } else {
            None
        };
        *lock(&self.shared.published) = Published {
            status,
            policy,
            ceiling,
        };
    }
}

fn boottime_ns() -> Result<u64> {
    sandbox_runtime::guard_probe::boottime_now_ns().map_err(anyhow::Error::msg)
}

fn bind_socket(path: &Path) -> Result<UnixListener> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt as _;
        if !meta.file_type().is_socket() {
            bail!("`{}` exists and is not a socket", path.display());
        }
        std::fs::remove_file(path)
            .with_context(|| format!("removing stale `{}`", path.display()))?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding `{}`", path.display()))?;
    // Any local uid may connect; writes are authorized per request by
    // SO_PEERCRED (daemon uid only).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .map(|cred| cred.uid.as_raw())
        .map_err(std::io::Error::from)
}

fn spawn_monitors(
    events: &mpsc::Sender<Event>,
    failed: &mut Option<&'static str>,
) -> Vec<std::process::Child> {
    let mut children = Vec::new();
    for (name, program, args) in [
        ("ip", "ip", &["monitor", "route", "address", "link"][..]),
        ("nft", "nft", &["monitor"][..]),
    ] {
        let line_tx = events.clone();
        let exit_tx = events.clone();
        match tools::monitor(
            program,
            args,
            move || {
                let _ = line_tx.send(Event::Changed);
            },
            move || {
                let _ = exit_tx.send(Event::MonitorDied(name));
            },
        ) {
            Ok(child) => children.push(child),
            Err(err) => {
                tracing::error!(monitor = name, error = %err, "cannot start a monitor");
                *failed = Some(name);
            }
        }
    }
    children
}

pub fn run() -> Result<()> {
    let paths = Paths::system();
    preflight::check_service(&paths)?;
    let config = GuardConfig::load(&paths.config())?;
    let boot_id = sandbox_runtime::guard_probe::read_boot_id().map_err(anyhow::Error::msg)?;
    let instance_id = new_instance_id().context("instance id")?;
    std::fs::create_dir_all(paths.state_dir()).context("state directory")?;

    let (tx, rx) = mpsc::channel();
    let deployment = Source::starting(load_source(&paths.deployment_source()));
    let root = Source::starting(load_source(&paths.root_source()));
    let placeholder = placeholder_status(&instance_id, &boot_id);
    let shared = Arc::new(initial_shared(
        &root,
        placeholder,
        paths.clone(),
        deployment,
        tx.clone(),
    ));
    let mut daemon = Daemon::new(
        shared.clone(),
        Box::new(SystemOps),
        instance_id,
        boot_id,
        root,
    );

    let listener = bind_socket(&paths.socket())?;
    let server_shared: Arc<dyn Handler> = shared.clone();
    let daemon_uid = config.daemon_uid;
    std::thread::spawn(move || {
        let stop = AtomicBool::new(false);
        if let Err(err) = sandbox_runtime::guard::protocol::serve(
            &listener,
            &peer_uid,
            ServerConfig::new(daemon_uid),
            server_shared,
            &stop,
        ) {
            tracing::error!(error = %err, "guard socket stopped");
        }
    });

    let mut monitors = spawn_monitors(&tx, &mut daemon.monitor_failed);
    tracing::info!(
        instance = %daemon.instance_id,
        daemon_uid = config.daemon_uid,
        "wssp egress guard running"
    );
    daemon.resync(true);
    let mut next_periodic = Instant::now() + RESYNC_INTERVAL;
    let mut fingerprint = root_fingerprint(&paths.root_blocklist());
    loop {
        let wait = next_periodic
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(1));
        let events = tools::coalesce(&rx, wait, Duration::from_millis(100), |event| match event {
            Event::MonitorDied(name) => Some(name),
            _ => None,
        });
        if let Some(name) = events.died.first() {
            tracing::error!(monitor = name, "monitor exited");
            daemon.monitor_failed = Some(name);
        }
        let current = root_fingerprint(&paths.root_blocklist());
        let root_changed = current != fingerprint;
        fingerprint = current;
        let periodic = Instant::now() >= next_periodic;
        if periodic || events.changed || root_changed {
            daemon.resync(periodic);
            if periodic {
                next_periodic = Instant::now() + RESYNC_INTERVAL;
            }
        }
        if daemon.monitor_failed.is_some() {
            for mut child in monitors.drain(..) {
                let _ = child.kill();
                let _ = child.wait();
            }
            // Drain stale exit notices from the killed monitors before
            // restarting, so they do not re-quarantine the new ones.
            std::thread::sleep(Duration::from_millis(200));
            let mut failed = None;
            monitors = spawn_monitors(&tx, &mut failed);
            while rx.try_recv().is_ok() {}
            daemon.monitor_failed = failed;
            if failed.is_none() {
                let _ = tx.send(Event::Changed);
            }
        }
    }
}

fn placeholder_status(instance_id: &str, boot_id: &str) -> GuardStatus {
    let unknown = GuardSourceStatus {
        state: GuardSourceState::Unknown,
        digest: None,
    };
    GuardStatus {
        guard_version: GUARD_VERSION,
        instance_id: instance_id.to_string(),
        boot_id: boot_id.to_string(),
        generation: 0,
        ok: false,
        quarantined: None,
        reasons: vec!["starting".into()],
        sources: GuardSources {
            root: unknown.clone(),
            deployment: unknown,
        },
        live_bridges: Vec::new(),
        gateways: Vec::new(),
        uplinks: Vec::new(),
        counts: Default::default(),
        verified_boottime_ns: 0,
        lease_until_boottime_ns: 0,
    }
}

fn initial_shared(
    root: &Source,
    status: GuardStatus,
    paths: Paths,
    deployment: Source,
    tx: mpsc::Sender<Event>,
) -> Shared {
    let policy = PolicyAnswer {
        root: source_policy(root),
        deployment: source_policy(&deployment),
    };
    Shared {
        paths,
        deployment: Mutex::new(deployment),
        publish: Mutex::new(()),
        published: Mutex::new(Published {
            status,
            policy,
            ceiling: None,
        }),
        events: Mutex::new(tx),
    }
}

#[cfg(test)]
#[path = "daemon_tests.rs"]
mod tests;
