//! Preview tunnels: `tunnel.ports` frames (a tunnel sandbox's declared ports
//! changed at runtime) run off the relay loop. A change waits for the
//! sandbox's lifecycle lock inside the runtime, so each runs on its own
//! worker; frames are coalesced per sandbox (the highest revision wins: the
//! host records only revisions above its own), served in arrival order (a
//! sandbox queued again while it runs goes to the back, so a retried failure
//! never starves a waiting sandbox), and at most one runs per sandbox. Replies are drained by the relay loop like tunnel statuses.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use sandbox_protocol::{TunnelPortsOutcomeV11, TunnelPortsStatusV11, TunnelPortsV11};
use sandbox_runtime::SandboxRuntime;

/// Concurrent changes (each mostly waits on host IO or a lifecycle lock).
const WORKERS: usize = 4;
/// Most distinct sandboxes queued; beyond it a frame is answered `failed`
/// at once (the server retries).
const MAX_QUEUED: usize = 4096;

#[derive(Default)]
struct State {
    queued: BTreeMap<String, TunnelPortsV11>,
    /// Queued sandbox ids in arrival order (each once).
    order: VecDeque<String>,
    running: HashSet<String>,
    replies: VecDeque<TunnelPortsStatusV11>,
}

pub(crate) struct TunnelPortsWorker {
    runtime: Arc<dyn SandboxRuntime>,
    state: Mutex<State>,
    wake: Condvar,
}

static INSTALLED: OnceLock<Arc<TunnelPortsWorker>> = OnceLock::new();

/// Start the workers once per process.
pub(crate) fn install(runtime: Arc<dyn SandboxRuntime>) {
    if INSTALLED.get().is_some() {
        return;
    }
    let worker = Arc::new(TunnelPortsWorker::new(runtime));
    if INSTALLED.set(worker.clone()).is_ok() {
        for index in 0..WORKERS {
            let worker = worker.clone();
            let _ = std::thread::Builder::new()
                .name(format!("wssp-tunnel-ports-{index}"))
                .spawn(move || worker.run());
        }
    }
}

pub(crate) fn installed() -> Option<&'static Arc<TunnelPortsWorker>> {
    INSTALLED.get()
}

impl TunnelPortsWorker {
    fn new(runtime: Arc<dyn SandboxRuntime>) -> Self {
        Self {
            runtime,
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
        }
    }

    /// Queue a frame (validated by the relay's parser).
    pub(crate) fn submit(&self, frame: TunnelPortsV11) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(queued) = state.queued.get_mut(&frame.sandbox_id) {
            if frame.revision > queued.revision {
                *queued = frame;
            }
            return;
        }
        if state.queued.len() >= MAX_QUEUED {
            state.replies.push_back(TunnelPortsStatusV11 {
                sandbox_id: frame.sandbox_id,
                revision: frame.revision,
                outcome: TunnelPortsOutcomeV11::Failed,
            });
            return;
        }
        state.order.push_back(frame.sandbox_id.clone());
        state.queued.insert(frame.sandbox_id.clone(), frame);
        drop(state);
        self.wake.notify_one();
    }

    /// Replies for the relay to send.
    pub(crate) fn drain(&self) -> Vec<TunnelPortsStatusV11> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replies
            .drain(..)
            .collect()
    }

    fn next(&self) -> TunnelPortsV11 {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            // The oldest queued sandbox that is not running already.
            let ready = state
                .order
                .iter()
                .position(|id| !state.running.contains(id));
            if let Some(at) = ready
                && let Some(id) = state.order.remove(at)
                && let Some(frame) = state.queued.remove(&id)
            {
                state.running.insert(id);
                return frame;
            }
            state = self.wake.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn run(&self) {
        loop {
            let frame = self.next();
            let reply = self.apply(&frame);
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.running.remove(&frame.sandbox_id);
            if state.replies.len() >= MAX_QUEUED {
                state.replies.pop_front();
            }
            state.replies.push_back(reply);
            drop(state);
            // A frame for this sandbox may have queued while it ran.
            self.wake.notify_all();
        }
    }

    fn apply(&self, frame: &TunnelPortsV11) -> TunnelPortsStatusV11 {
        let sandbox_id = frame.sandbox_id.as_str();
        let result = self.runtime.update_tunnel_ports(
            sandbox_id,
            frame.revision,
            &frame.ports,
            &|allowed: &[u16]| {
                if let Some(tunnels) = super::tunnel::installed() {
                    tunnels.restrict(sandbox_id, allowed);
                }
            },
        );
        // Whatever the runtime could do (no plan here, an Incus error, a
        // busy sandbox), a client forwarding a port this change no longer
        // declares stops now; the server re-applies a narrowed one.
        if !matches!(&result, Ok(update) if update.outcome == TunnelPortsOutcomeV11::Applied)
            && let Some(tunnels) = super::tunnel::installed()
        {
            tunnels.restrict(sandbox_id, &frame.ports);
        }
        match result {
            Ok(update) => {
                tracing::info!(sandbox = %sandbox_id, revision = frame.revision, ports = ?frame.ports, outcome = ?update.outcome, recorded = update.revision, "tunnel ports change");
                TunnelPortsStatusV11 {
                    sandbox_id: frame.sandbox_id.clone(),
                    revision: update.revision,
                    outcome: update.outcome,
                }
            }
            Err(error) => {
                tracing::warn!(sandbox = %sandbox_id, revision = frame.revision, %error, "tunnel ports change failed");
                TunnelPortsStatusV11 {
                    sandbox_id: frame.sandbox_id.clone(),
                    revision: frame.revision,
                    outcome: TunnelPortsOutcomeV11::Failed,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_runtime::FakeRuntime;

    fn frame(id: &str, revision: u64, ports: &[u16]) -> TunnelPortsV11 {
        TunnelPortsV11 {
            sandbox_id: id.into(),
            revision,
            ports: ports.to_vec(),
        }
    }

    #[test]
    fn frames_coalesce_to_the_newest_revision_per_sandbox() {
        let fake = Arc::new(FakeRuntime::new());
        fake.set_tunnel_target("sbx-1", std::net::Ipv4Addr::new(10, 0, 0, 2), vec![3000]);
        let worker = TunnelPortsWorker::new(fake.clone());
        worker.submit(frame("sbx-1", 2, &[3000, 4000]));
        worker.submit(frame("sbx-1", 1, &[1]));
        worker.submit(frame("sbx-1", 3, &[4000]));
        worker.submit(frame("sbx-2", 1, &[5173]));
        let first = worker.next();
        let second = worker.next();
        let mut seen = vec![
            (first.sandbox_id.clone(), first.revision),
            (second.sandbox_id.clone(), second.revision),
        ];
        seen.sort();
        assert_eq!(
            seen,
            vec![("sbx-1".to_string(), 3), ("sbx-2".to_string(), 1)]
        );
        // The applied one updates the plan; an absent sandbox says so.
        let applied = worker.apply(&first);
        let absent = worker.apply(&second);
        let (one, two) = if first.sandbox_id == "sbx-1" {
            (applied, absent)
        } else {
            (absent, applied)
        };
        assert_eq!(one.outcome, TunnelPortsOutcomeV11::Applied);
        assert_eq!(one.revision, 3);
        assert_eq!(
            fake.tunnel_target("sbx-1"),
            Some((std::net::Ipv4Addr::new(10, 0, 0, 2), vec![4000]))
        );
        assert_eq!(two.outcome, TunnelPortsOutcomeV11::Absent);
    }

    #[test]
    fn sandboxes_run_in_arrival_order_and_a_retry_goes_to_the_back() {
        let worker = TunnelPortsWorker::new(Arc::new(FakeRuntime::new()));
        // Low ids first in the map, but "sbx-z" arrived first.
        worker.submit(frame("sbx-z", 1, &[3000]));
        worker.submit(frame("sbx-a", 1, &[3000]));
        let first = worker.next();
        assert_eq!(first.sandbox_id, "sbx-z");
        // sbx-z is queued again (a resend) while it runs; sbx-b arrives.
        worker.submit(frame("sbx-z", 2, &[3000]));
        worker.submit(frame("sbx-b", 1, &[3000]));
        worker.state.lock().unwrap().running.remove("sbx-z");
        let order: Vec<String> = (0..3).map(|_| worker.next().sandbox_id).collect();
        assert_eq!(order, vec!["sbx-a", "sbx-z", "sbx-b"]);
    }

    #[test]
    fn one_change_per_sandbox_runs_at_a_time() {
        let fake = Arc::new(FakeRuntime::new());
        let worker = Arc::new(TunnelPortsWorker::new(fake));
        worker.submit(frame("sbx-1", 1, &[3000]));
        let running = worker.next();
        assert_eq!(running.revision, 1);
        // A newer frame for the running sandbox waits for it.
        worker.submit(frame("sbx-1", 2, &[4000]));
        let waiter = {
            let worker = worker.clone();
            std::thread::spawn(move || worker.next())
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!waiter.is_finished(), "the second change waits");
        {
            let mut state = worker.state.lock().unwrap();
            state.running.remove("sbx-1");
        }
        worker.wake.notify_all();
        assert_eq!(waiter.join().unwrap().revision, 2);
    }
}
