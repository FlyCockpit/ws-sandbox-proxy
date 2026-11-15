//! Bounded, connection-scoped file work. Replies contain masked content only.
use super::agent_policy::AgentPolicy;
use sandbox_protocol::*;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
#[cfg(target_os = "linux")]
mod linux;
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
struct Shared {
    policy: Mutex<AgentPolicy>,
    owner: String,
    protected: Vec<PathBuf>,
    #[cfg(target_os = "linux")]
    secret: zeroize::Zeroizing<Vec<u8>>,
    key: [u8; 32],
    serial: Mutex<()>,
}
struct Job {
    cancelled: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}
pub(super) struct HostFiles {
    shared: Arc<Shared>,
    jobs: Vec<Job>,
    tx: mpsc::Sender<(u64, DaemonControlMessage)>,
    rx: mpsc::Receiver<(u64, DaemonControlMessage)>,
}
struct Context<'a> {
    shared: &'a Shared,
    cancelled: &'a AtomicBool,
    req: &'a HostFileRequestV11,
}
impl Context<'_> {
    fn check(&self) -> Result<(), HostFileError> {
        let p = lock(&self.shared.policy);
        if self.cancelled.load(Ordering::Acquire) {
            return Err(HostFileError::PolicyChanged);
        }
        if !p.enabled {
            return Err(HostFileError::HostFilesOff);
        }
        if p.roots.is_empty() {
            return Err(HostFileError::NoRoots);
        }
        p.authorize(
            self.req.agent_policy_revision(),
            self.req.owner_id(),
            &self.shared.owner,
        )
        .map_err(|r| match r {
            HostExecRejectReason::HostCommandsOff => HostFileError::HostFilesOff,
            HostExecRejectReason::PolicyChanged => HostFileError::PolicyChanged,
            _ => HostFileError::OwnerMismatch,
        })
    }
    #[cfg(target_os = "linux")]
    fn etag(&self, content: &[u8]) -> String {
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        digest.update(&self.shared.key);
        digest.update(content);
        format!("h:{}", &encode_chunk_data(digest.finish().as_ref())[..22])
    }
}
impl HostFiles {
    pub fn new(
        policy: AgentPolicy,
        owner: String,
        secret: &[u8],
        extra_protected: Vec<PathBuf>,
    ) -> anyhow::Result<Self> {
        let mut protected = vec![
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
            crate::paths::config_dir()?,
            crate::paths::data_dir()?,
        ];
        protected.extend(extra_protected);
        let protected = protected
            .into_iter()
            .flat_map(|path| {
                let canonical = path.canonicalize().ok();
                std::iter::once(path).chain(canonical)
            })
            .collect();
        let mut key = [0; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key)
            .map_err(|_| anyhow::anyhow!("host file key initialization failed"))?;
        let (tx, rx) = mpsc::channel();
        Ok(Self {
            shared: Arc::new(Shared {
                policy: Mutex::new(policy),
                owner,
                protected,
                #[cfg(target_os = "linux")]
                secret: zeroize::Zeroizing::new(secret.to_vec()),
                key,
                serial: Mutex::new(()),
            }),
            jobs: Vec::new(),
            tx,
            rx,
        })
    }
    pub fn update(&self, policy: AgentPolicy) {
        *lock(&self.shared.policy) = policy;
        self.cancel_pending();
    }
    pub fn cancel_pending(&self) {
        for job in &self.jobs {
            job.cancelled.store(true, Ordering::Release);
        }
    }
    pub fn request(&mut self, req: HostFileRequestV11) -> Option<DaemonControlMessage> {
        self.reap();
        let fail = |error| {
            DaemonControlMessage::HostFileResult(HostFileResultV11 {
                request_id: req.request_id().into(),
                ok: false,
                result: None,
                error: Some(error),
            })
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let ctx = Context {
            shared: &self.shared,
            cancelled: &cancelled,
            req: &req,
        };
        if let Err(e) = ctx.check() {
            return Some(fail(e));
        }
        if !req.is_valid() {
            return Some(fail(HostFileError::InvalidInput));
        }
        if self.jobs.len() >= 8 {
            return Some(fail(HostFileError::Limit));
        }
        let shared = self.shared.clone();
        let cancel = cancelled.clone();
        let tx = self.tx.clone();
        let request_id = req.request_id().to_owned();
        let failed_id = request_id.clone();
        let thread = std::thread::Builder::new()
            .name("wssp-host-file".into())
            .spawn(move || {
                let _serial = lock(&shared.serial);
                let ctx = Context {
                    shared: &shared,
                    cancelled: &cancel,
                    req: &req,
                };
                #[cfg(target_os = "linux")]
                let result = ctx.check().and_then(|_| linux::run(&ctx));
                #[cfg(not(target_os = "linux"))]
                let result = ctx.check().and(Err(HostFileError::PathDenied));
                let result = result.and_then(|value| ctx.check().map(|_| value));
                let frame = match result {
                    Ok(value) => HostFileResultV11 {
                        request_id,
                        ok: true,
                        result: Some(value),
                        error: None,
                    },
                    Err(error) => HostFileResultV11 {
                        request_id,
                        ok: false,
                        result: None,
                        error: Some(error),
                    },
                };
                let _ = tx.send((
                    req.agent_policy_revision(),
                    DaemonControlMessage::HostFileResult(frame),
                ));
            });
        match thread {
            Ok(thread) => {
                self.jobs.push(Job { cancelled, thread });
                None
            }
            Err(_) => Some(DaemonControlMessage::HostFileResult(HostFileResultV11 {
                request_id: failed_id,
                ok: false,
                result: None,
                error: Some(HostFileError::IoError),
            })),
        }
    }
    fn reap(&mut self) {
        let mut i = 0;
        while i < self.jobs.len() {
            if self.jobs[i].thread.is_finished() {
                let job = self.jobs.swap_remove(i);
                let _ = job.thread.join();
            } else {
                i += 1;
            }
        }
    }
    pub fn replies(&mut self) -> Vec<DaemonControlMessage> {
        self.reap();
        let policy = lock(&self.shared.policy);
        self.rx
            .try_iter()
            .map(|(revision, mut frame)| {
                if let DaemonControlMessage::HostFileResult(result) = &mut frame
                    && result.ok
                    && (revision != policy.revision || !policy.enabled || policy.roots.is_empty())
                {
                    result.ok = false;
                    result.result = None;
                    result.error = Some(HostFileError::PolicyChanged);
                }
                frame
            })
            .collect()
    }
}
impl Drop for HostFiles {
    fn drop(&mut self) {
        self.cancel_pending();
        for job in self.jobs.drain(..) {
            let _ = job.thread.join();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn policy_changes_also_fence_successes_already_queued_for_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let mut policy = AgentPolicy {
            enabled: true,
            max_ms: 1000,
            roots: vec![dir.path().canonicalize().unwrap()],
            revision: 1,
        };
        let mut files = HostFiles::new(
            policy.clone(),
            "owner".into(),
            b"fixture-secret",
            Vec::new(),
        )
        .unwrap();
        files
            .tx
            .send((
                1,
                DaemonControlMessage::HostFileResult(HostFileResultV11 {
                    request_id: "queued".into(),
                    ok: true,
                    error: None,
                    result: Some(HostFileValueV11::Write(HostFileWriteV11 {
                        etag: "h:abcdefghijklmnopqrstuv".into(),
                        size: 0,
                        created: true,
                    })),
                }),
            ))
            .unwrap();
        policy.enabled = false;
        policy.revision = 2;
        files.update(policy);
        assert!(matches!(
            files.replies().as_slice(),
            [DaemonControlMessage::HostFileResult(HostFileResultV11 {
                ok: false,
                error: Some(HostFileError::PolicyChanged),
                result: None,
                ..
            })]
        ));
    }
    #[test]
    fn at_most_eight_pending_operations_and_cancel_is_checked() {
        let dir = tempfile::tempdir().unwrap();
        let policy = AgentPolicy {
            enabled: true,
            max_ms: 1000,
            roots: vec![dir.path().canonicalize().unwrap()],
            revision: 1,
        };
        let mut files =
            HostFiles::new(policy, "owner".into(), b"fixture-secret", Vec::new()).unwrap();
        let req:HostFileRequestV11=serde_json::from_value(serde_json::json!({"op":"list","connectionEpoch":1,"requestId":"file-list","ownerId":"owner","agentPolicyRevision":1,"path":dir.path().to_str().unwrap()})).unwrap();
        let cancelled = AtomicBool::new(true);
        let ctx = Context {
            shared: &files.shared,
            cancelled: &cancelled,
            req: &req,
        };
        assert_eq!(ctx.check(), Err(HostFileError::PolicyChanged));
        let barrier = Arc::new(std::sync::Barrier::new(9));
        for _ in 0..8 {
            let b = barrier.clone();
            files.jobs.push(Job {
                cancelled: Arc::new(AtomicBool::new(false)),
                thread: std::thread::spawn(move || {
                    b.wait();
                }),
            });
        }
        let reply = files.request(req);
        barrier.wait();
        assert!(matches!(
            reply,
            Some(DaemonControlMessage::HostFileResult(HostFileResultV11 {
                error: Some(HostFileError::Limit),
                ..
            }))
        ));
    }
}
