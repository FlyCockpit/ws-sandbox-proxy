//! Stalled receipt resolution (reconnect plan WP2 item 4, D11).
//!
//! Reconciliation resolves an unresolved journaled receipt (Intent/Effect
//! after a restart or a revoked carry) by querying the runtime for its
//! sandbox. A query that stalls (a wedged Incus call) used to end the whole
//! session after 30 s, and every reconnect stalled on it again. Now each
//! resolution runs on its own process-scoped worker, tracked here:
//!
//! - at most one per sandbox, one per operation, and
//!   [`MAX_IN_FLIGHT`] (= `PENDING_RECEIPTS_MAX`) in total. A receipt that
//!   would exceed a cap gets no worker: it stays journaled and is picked up
//!   by a later reconnect, as a busy sandbox's receipt is;
//! - after [`RESOLUTION_WAIT`] the receipt is *deferred*: the worker keeps
//!   running, reconciliation goes on, and `reconcile.complete` names it in
//!   `pendingReceipts` (when negotiated) so the server settles nothing in
//!   the meantime;
//! - its sandbox is busy for the census, the expiry pass and admission
//!   inventories (nothing waits on its lock);
//! - the dispatch loop delivers the completed receipt in the same session
//!   (`ReceiptConfirmed` then clears it from the journal); if the session
//!   ends first the result is journaled and replays on the next reconnect.
use super::journal::{HostJournal, HostReceipt};
use anyhow::Result;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

/// How long reconciliation waits for one resolution before deferring it.
pub(super) const RESOLUTION_WAIT: Duration = Duration::from_secs(30);
/// Global bound on resolutions in flight (and so on `pendingReceipts`).
pub(super) const MAX_IN_FLIGHT: usize = sandbox_protocol::PENDING_RECEIPTS_MAX;

struct InFlight {
    operation_id: String,
    sandbox_id: String,
    /// `None` until the worker finished.
    done: Option<Result<HostReceipt>>,
    rx: mpsc::Receiver<Result<HostReceipt>>,
}

impl InFlight {
    fn poll(&mut self) -> bool {
        if self.done.is_none() {
            match self.rx.try_recv() {
                Ok(result) => self.done = Some(result),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.done = Some(Err(anyhow::anyhow!("receipt query worker stopped")));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.done.is_some()
    }
}

/// Why a receipt got no worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// This operation, or another of its sandbox, is still resolving.
    Busy,
    /// [`MAX_IN_FLIGHT`] resolutions are running.
    AtCap,
}

/// Process-scoped: shared by every session of one daemon.
pub(super) struct InFlightResolutions {
    entries: Mutex<Vec<InFlight>>,
    wait: Duration,
}

impl Default for InFlightResolutions {
    fn default() -> Self {
        Self::with_wait(RESOLUTION_WAIT)
    }
}

impl InFlightResolutions {
    pub(super) fn with_wait(wait: Duration) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            wait,
        }
    }

    /// How long reconciliation waits before deferring a resolution.
    pub(super) fn wait(&self) -> Duration {
        self.wait
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<InFlight>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sandboxes whose resolution worker is still running: nothing may wait
    /// on their lock.
    pub(super) fn busy_sandboxes(&self) -> HashSet<String> {
        self.lock()
            .iter_mut()
            .filter_map(|entry| (!entry.poll()).then(|| entry.sandbox_id.clone()))
            .collect()
    }

    /// Operations still resolving (or resolved but not yet delivered), sorted:
    /// `reconcile.complete` `pendingReceipts`. At most [`MAX_IN_FLIGHT`].
    pub(super) fn pending(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .lock()
            .iter()
            .map(|entry| entry.operation_id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// Starts resolving `receipt` on its own worker, unless a cap holds.
    pub(super) fn start(
        &self,
        journal: &Arc<HostJournal>,
        runtime: &Arc<dyn sandbox_runtime::SandboxRuntime>,
        receipt: HostReceipt,
    ) -> Result<(), Refused> {
        self.start_with(receipt, {
            let (journal, runtime) = (journal.clone(), runtime.clone());
            move |receipt| super::reconcile::resolve_receipt(&journal, runtime.as_ref(), receipt)
        })
    }

    fn start_with(
        &self,
        receipt: HostReceipt,
        resolve: impl FnOnce(HostReceipt) -> Result<HostReceipt> + Send + 'static,
    ) -> Result<(), Refused> {
        let mut entries = self.lock();
        if entries.iter().any(|entry| {
            entry.operation_id == receipt.operation_id || entry.sandbox_id == receipt.sandbox_id
        }) {
            return Err(Refused::Busy);
        }
        if entries.len() >= MAX_IN_FLIGHT {
            return Err(Refused::AtCap);
        }
        let (tx, rx) = mpsc::sync_channel(1);
        entries.push(InFlight {
            operation_id: receipt.operation_id.clone(),
            sandbox_id: receipt.sandbox_id.clone(),
            done: None,
            rx,
        });
        // A detached query keeps the exclusive journal lock with the process:
        // it cannot race another process's reconciliation.
        std::thread::Builder::new()
            .name("wssp-receipt-query".into())
            .spawn(move || {
                let _ = tx.send(resolve(receipt));
            })
            .map_err(|_| {
                entries.pop();
                Refused::AtCap
            })?;
        Ok(())
    }

    /// The finished resolution of `operation_id`, removing it.
    pub(super) fn take(&self, operation_id: &str) -> Option<Result<HostReceipt>> {
        let mut entries = self.lock();
        let index = entries
            .iter_mut()
            .position(|entry| entry.operation_id == operation_id && entry.poll())?;
        entries.remove(index).done
    }

    /// Every finished resolution, removed, in start order.
    pub(super) fn take_finished(&self) -> Vec<(String, Result<HostReceipt>)> {
        let mut entries = self.lock();
        let mut finished = Vec::new();
        let mut index = 0;
        while index < entries.len() {
            if entries[index].poll() {
                let entry = entries.remove(index);
                if let Some(done) = entry.done {
                    finished.push((entry.operation_id, done));
                }
            } else {
                index += 1;
            }
        }
        finished
    }

    #[cfg(test)]
    pub(super) fn start_for_test(
        &self,
        receipt: HostReceipt,
        resolve: impl FnOnce(HostReceipt) -> Result<HostReceipt> + Send + 'static,
    ) -> Result<(), Refused> {
        self.start_with(receipt, resolve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(op: &str, sandbox: &str) -> HostReceipt {
        let dispatch: sandbox_protocol::OperationDispatch =
            serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
                "operationId":op, "sandboxId":sandbox, "kind":"sandbox.stop",
                "idempotencyKey":op, "generation":1, "attempt":1,
                "bodyHash":"a".repeat(64)}))
            .unwrap();
        let binding = super::super::journal::TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        super::super::journal::unrecorded_intent_from_dispatch(&binding, &dispatch)
    }

    /// A worker held until its sender fires.
    fn held() -> (
        mpsc::Sender<()>,
        impl FnOnce(HostReceipt) -> Result<HostReceipt> + Send + 'static,
    ) {
        let (release, gate) = mpsc::channel::<()>();
        (release, move |receipt| {
            let _ = gate.recv();
            Ok(receipt)
        })
    }

    #[test]
    fn caps_hold_per_operation_per_sandbox_and_globally() {
        let resolutions = InFlightResolutions::default();
        let mut releases = Vec::new();
        for index in 0..MAX_IN_FLIGHT {
            let (release, work) = held();
            releases.push(release);
            resolutions
                .start_for_test(
                    receipt(&format!("op-{index}"), &format!("sbx-{index}")),
                    work,
                )
                .expect("under the cap");
        }
        // Same operation, and another operation of a resolving sandbox.
        let (_r, work) = held();
        assert_eq!(
            resolutions.start_for_test(receipt("op-0", "sbx-x"), work),
            Err(Refused::Busy)
        );
        let (_r, work) = held();
        assert_eq!(
            resolutions.start_for_test(receipt("op-y", "sbx-0"), work),
            Err(Refused::Busy)
        );
        // Global cap: deferred without starting a worker.
        let (_r, work) = held();
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = started.clone();
        assert_eq!(
            resolutions.start_for_test(receipt("op-z", "sbx-z"), move |r| {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                work(r)
            }),
            Err(Refused::AtCap)
        );
        assert_eq!(resolutions.pending().len(), MAX_IN_FLIGHT);
        assert_eq!(resolutions.busy_sandboxes().len(), MAX_IN_FLIGHT);
        // One finishes: its sandbox is free again, a new one fits, and the
        // finished result is taken exactly once.
        releases.remove(0).send(()).unwrap();
        let finished = loop {
            let finished = resolutions.take_finished();
            if !finished.is_empty() {
                break finished;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0].0, "op-0");
        assert!(resolutions.take("op-0").is_none());
        assert!(!resolutions.busy_sandboxes().contains("sbx-0"));
        let (release, work) = held();
        resolutions
            .start_for_test(receipt("op-z", "sbx-z"), work)
            .expect("a slot freed");
        assert!(!started.load(std::sync::atomic::Ordering::SeqCst));
        for release in releases.into_iter().chain([release]) {
            release.send(()).unwrap();
        }
    }
}
