//! Definitive authority revocation: an explicit server verdict
//! (`credential_revoked` / `owner_unavailable`, as a 4003 close reason or an
//! upgrade refusal code) — never a plain 401/403 or a transport drop. The
//! server can no longer deliver stops to this host, so the daemon records a
//! durable "authority revoked" marker in its journal and STOPS every
//! wssp-managed VM it hosts, retrying in-process until a fresh inventory
//! confirms each one stopped or absent. It never destroys anything: disks
//! stay, no deletion starts. The marker survives restarts (every start
//! re-applies the stop before serving), and is cleared only once a session
//! registers again (re-enrollment or unban), after which the server starts
//! sandboxes through the normal cold start.
use super::journal::HostJournal;
use sandbox_protocol::SandboxLifecycleState;
use sandbox_runtime::{RuntimePermit, SandboxRuntime, StopSandboxRequest};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MARKER: &str = "AUTHORITY-REVOKED";

/// Bounds of the revocation stop. Every runtime call gets its OWN permit, so a
/// slow graceful shutdown can never starve the forced stop of a later VM, and
/// every retry cycle starts with fresh permits.
#[derive(Clone, Copy, Debug)]
pub(super) struct StopBudgets {
    pub(super) inventory: Duration,
    /// Guest shutdown wait handed to the runtime (like lease expiry).
    pub(super) graceful_timeout: Duration,
    /// Permit for the graceful call (the timeout plus runtime overhead).
    pub(super) graceful: Duration,
    /// Permit for the forced stop that follows a graceful miss.
    pub(super) forced: Duration,
    pub(super) backoff_initial: Duration,
    pub(super) backoff_max: Duration,
}
impl StopBudgets {
    pub(super) const DEFAULT: Self = Self {
        inventory: Duration::from_secs(30),
        graceful_timeout: Duration::from_secs(15),
        graceful: Duration::from_secs(20),
        forced: Duration::from_secs(60),
        backoff_initial: Duration::from_secs(1),
        backoff_max: Duration::from_secs(30),
    };
}

/// Startup re-application: a few bounded cycles before dialing. Whatever is
/// left stays an obligation: a session that registers proves restored
/// authority (and clears the marker); every other exit retries it in
/// [`super::expiry::ExpiryService::wait_idle_with`] until confirmed.
pub(super) const STARTUP_CYCLES: usize = 3;

/// The explicit server verdicts (close reason or upgrade refusal code) that
/// this enrolled credential is revoked or its owner banned/deleting. Unknown,
/// malformed or wrong-secret credentials never carry them.
pub(super) fn is_revocation_verdict(code: &str) -> bool {
    matches!(code, "credential_revoked" | "owner_unavailable")
}

/// Marks a terminal credential error that carries an explicit verdict.
#[derive(Debug)]
pub(super) struct AuthorityRevoked;
impl std::fmt::Display for AuthorityRevoked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("host authority revoked by the server")
    }
}

/// True only for a terminal credential error carrying an explicit verdict;
/// a plain 401/403 (e.g. a mistyped token) never stops anything.
pub(super) fn is_authority_revocation(error: &anyhow::Error) -> bool {
    crate::exit::code_for(error) == crate::exit::ExitCode::CredentialInactive
        && error.downcast_ref::<AuthorityRevoked>().is_some()
}

pub(super) fn is_revoked(journal: &HostJournal) -> bool {
    journal
        .state_dir()
        .is_some_and(|dir| dir.join(MARKER).exists())
}

/// Latch the revocation in memory, then run one cycle (marker write and
/// stops). The returned obligation is independent of the marker: a failed
/// marker write is retried along with every unconfirmed stop, so
/// [`super::expiry::ExpiryService::wait_idle_with`] keeps going until both
/// the marker is durable and every managed VM is confirmed stopped.
pub(super) fn revoke_and_stop(
    journal: &HostJournal,
    runtime: &dyn SandboxRuntime,
    cancelled: &dyn Fn() -> bool,
) -> StopObligation {
    let mut obligation = StopObligation::latched(StopBudgets::DEFAULT);
    obligation.poll(journal, runtime, cancelled);
    obligation
}

/// Up to `max_cycles` stop cycles with backoff, while the marker exists.
/// True once a fresh inventory confirms every managed VM stopped or absent.
pub(super) fn enforce(
    journal: &HostJournal,
    runtime: &dyn SandboxRuntime,
    budgets: StopBudgets,
    cancelled: &dyn Fn() -> bool,
    max_cycles: usize,
) -> bool {
    let mut obligation = StopObligation::new(budgets);
    for cycle in 0..max_cycles {
        if cycle > 0 {
            while Instant::now() < obligation.next_attempt && !cancelled() {
                std::thread::sleep(
                    (obligation.next_attempt - Instant::now()).min(Duration::from_millis(50)),
                );
            }
        }
        if !obligation.poll(journal, runtime, cancelled) {
            return true;
        }
        if cancelled() {
            break;
        }
    }
    false
}

/// The per-host stop obligation while the marker exists: retried with
/// backoff until a fresh inventory shows no managed VM running.
#[derive(Debug)]
pub(super) struct StopObligation {
    budgets: StopBudgets,
    next_attempt: Instant,
    backoff: Duration,
    done: bool,
    /// In-memory revocation latch: set by a verdict in this process, it keeps
    /// the obligation alive even if the durable marker cannot be written.
    latched: bool,
    marker_pending: bool,
}
impl StopObligation {
    /// The obligation of a recorded marker (startup, any later exit).
    pub(super) fn new(budgets: StopBudgets) -> Self {
        Self {
            budgets,
            next_attempt: Instant::now(),
            backoff: budgets.backoff_initial,
            done: false,
            latched: false,
            marker_pending: false,
        }
    }

    /// The obligation of a verdict received by this process: it must write
    /// the marker and stop every VM, retrying both, whatever the disk does.
    pub(super) fn latched(budgets: StopBudgets) -> Self {
        Self {
            latched: true,
            marker_pending: true,
            ..Self::new(budgets)
        }
    }

    /// Runs one cycle when due. True while the obligation remains; false once
    /// the marker is durable (when latched) and every VM is confirmed
    /// stopped, or when an unlatched obligation's marker was lifted.
    pub(super) fn poll(
        &mut self,
        journal: &HostJournal,
        runtime: &dyn SandboxRuntime,
        cancelled: &dyn Fn() -> bool,
    ) -> bool {
        if self.done || (!self.latched && !is_revoked(journal)) {
            return false;
        }
        if Instant::now() < self.next_attempt {
            return true;
        }
        if self.marker_pending {
            match journal.persist_marker(MARKER, b"revoked\n") {
                Ok(()) => self.marker_pending = false,
                // Retried with the stops; the latch keeps this pass alive.
                Err(error) => tracing::warn!(
                    error = %error,
                    "could not record the authority revocation durably; retrying"
                ),
            }
        }
        let stopped = stop_cycle(journal, runtime, self.budgets, cancelled);
        if stopped && !self.marker_pending {
            self.done = true;
            return false;
        }
        tracing::warn!(
            retry_in_ms = self.backoff.as_millis() as u64,
            stopped,
            marker_pending = self.marker_pending,
            "authority revoked: the stop is not yet confirmed and durable; retrying"
        );
        self.next_attempt = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(self.budgets.backoff_max);
        true
    }
}

/// Ids of the managed VMs not yet stopped or absent; None when the inventory
/// is unavailable (an unconfirmed cycle).
fn running_vms(runtime: &dyn SandboxRuntime, budget: Duration) -> Option<Vec<String>> {
    let runtime = runtime.with_cancellation(Arc::new(RuntimePermit::with_timeout(budget)));
    match runtime.sandbox_inventory() {
        Ok(inventory) => Some(
            inventory
                .into_iter()
                .filter(|entry| {
                    !matches!(
                        entry.state,
                        SandboxLifecycleState::Stopped
                            | SandboxLifecycleState::Deleted
                            | SandboxLifecycleState::Absent
                    )
                })
                .map(|entry| entry.sandbox_id)
                .collect(),
        ),
        Err(error) => {
            tracing::warn!(code = %error.code, "authority revoked: inventory unavailable");
            None
        }
    }
}

/// One cycle: stop every running managed VM (graceful under its own permit,
/// then forced under a fresh one), then confirm with a fresh inventory.
/// Idempotent; never destroys.
fn stop_cycle(
    journal: &HostJournal,
    runtime: &dyn SandboxRuntime,
    budgets: StopBudgets,
    cancelled: &dyn Fn() -> bool,
) -> bool {
    let Some(running) = running_vms(runtime, budgets.inventory) else {
        return false;
    };
    if running.is_empty() {
        return true;
    }
    for sandbox_id in &running {
        if cancelled() {
            return false;
        }
        stop_one(journal, runtime, sandbox_id, budgets);
    }
    let confirmed = running_vms(runtime, budgets.inventory).is_some_and(|left| left.is_empty());
    if confirmed {
        tracing::warn!(
            stopped = running.len(),
            "host authority revoked: every running sandbox VM was stopped; disks are kept"
        );
    }
    confirmed
}

fn stop_one(
    journal: &HostJournal,
    runtime: &dyn SandboxRuntime,
    sandbox_id: &str,
    budgets: StopBudgets,
) {
    let fingerprint = journal
        .lease(sandbox_id)
        .and_then(|record| record.template_fingerprint)
        .unwrap_or_default();
    let request = StopSandboxRequest {
        template_fingerprint: fingerprint,
        sandbox_id: sandbox_id.to_owned(),
        instance_name: sandbox_runtime::default_incus_instance_name(sandbox_id),
        operation_id: "authority-revoked".into(),
        idempotency_key: format!("authority-revoked:{sandbox_id}"),
    };
    let graceful =
        runtime.with_cancellation(Arc::new(RuntimePermit::with_timeout(budgets.graceful)));
    if graceful
        .stop_sandbox_graceful(&request, budgets.graceful_timeout)
        .is_ok()
    {
        return;
    }
    let forced = runtime.with_cancellation(Arc::new(RuntimePermit::with_timeout(budgets.forced)));
    if let Err(error) = forced.stop_sandbox(&request) {
        tracing::warn!(state = ?error.state(), "authority revoked: a VM could not be stopped yet");
    }
}

/// A registered session proves restored authority. The marker is removed
/// through the journal IO latch: a surviving marker would
/// stop valid guests at the next start, so a failed delete closes admission
/// and reports the host unschedulable like any failed journal write.
pub(super) fn clear(journal: &HostJournal) {
    if !journal
        .state_dir()
        .is_some_and(|dir| dir.join(MARKER).exists())
    {
        return;
    }
    match journal.remove_marker(MARKER) {
        Ok(()) => tracing::info!("host authority restored; the revocation stop is lifted"),
        Err(error) => {
            tracing::error!(error = %error, "could not clear the revocation marker")
        }
    }
}

/// Header carrying the server's verdict on a 401/403 upgrade refusal.
pub(super) const REFUSAL_HEADER: &str = "x-wssp-credential-refusal";

/// The refusal verdict of a 401/403 upgrade response: the header (always
/// complete once the status line parsed), else a bounded JSON body `code`.
pub(super) fn upgrade_refusal_code(
    headers: &tungstenite::http::HeaderMap,
    body: Option<&[u8]>,
) -> Option<String> {
    if let Some(value) = headers.get(REFUSAL_HEADER).and_then(|v| v.to_str().ok()) {
        return Some(value.to_owned());
    }
    let body = body.filter(|body| body.len() <= 4096)?;
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("code")?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_relay::journal::TransportBindingV11;
    use crate::sandbox_relay::test_support::FixtureRuntime;
    use sandbox_runtime::{CreateSandboxRequest, FakeRuntime, RuntimeError};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FAST: StopBudgets = StopBudgets {
        inventory: Duration::from_millis(500),
        graceful_timeout: Duration::from_millis(50),
        graceful: Duration::from_millis(100),
        forced: Duration::from_millis(100),
        backoff_initial: Duration::from_millis(5),
        backoff_max: Duration::from_millis(20),
    };

    fn journal(dir: &std::path::Path) -> Arc<HostJournal> {
        let journal = unmarked_journal(dir);
        journal.persist_marker(MARKER, b"revoked\n").unwrap();
        journal
    }

    fn unmarked_journal(dir: &std::path::Path) -> Arc<HostJournal> {
        let binding = TransportBindingV11 {
            server: "wss://revocation.test/ws/sandbox-host".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir, &binding).unwrap())
    }

    fn seed(fake: &FakeRuntime, ids: &[&str]) {
        let runtime: &dyn SandboxRuntime = fake;
        for id in ids {
            runtime
                .create_fixture(&CreateSandboxRequest::for_test(id, &format!("key-{id}")))
                .unwrap();
        }
    }

    fn running(fake: &FakeRuntime) -> Vec<String> {
        running_vms(fake, Duration::from_secs(5)).unwrap()
    }

    /// Consumes one injected failure; false once none are left.
    fn take_one(left: &AtomicUsize) -> bool {
        let mut current = left.load(Ordering::SeqCst);
        while current > 0 {
            match left.compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return true,
                Err(seen) => current = seen,
            }
        }
        false
    }

    fn transient() -> RuntimeError {
        RuntimeError::new(
            sandbox_protocol::SandboxErrorCode::UnknownOutcome,
            "transient fault",
        )
    }

    /// Each slow graceful miss runs longer than any single permit in total;
    /// per-VM permits keep every forced stop admitted.
    #[test]
    fn slow_guests_fall_back_to_forced_stops_under_fresh_permits() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let fake = FakeRuntime::new()
            .with_graceful_stop()
            .with_lifecycle_hook(|stage| {
                if stage == "stop_graceful" {
                    // The guest ignores the shutdown until its timeout.
                    std::thread::sleep(Duration::from_millis(80));
                    return Err(transient());
                }
                Ok(())
            });
        seed(&fake, &["sbx-a", "sbx-b", "sbx-c"]);
        let started = Instant::now();
        assert!(enforce(&journal, &fake, FAST, &|| false, 1));
        assert!(started.elapsed() > FAST.forced, "work exceeded one permit");
        assert!(running(&fake).is_empty());
    }

    #[test]
    fn transient_inventory_failure_is_retried_until_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let failures = AtomicUsize::new(3);
        let fake = FakeRuntime::new().with_inventory_hook(move |stage| {
            if stage == "inventory" && take_one(&failures) {
                return Err(transient());
            }
            Ok(())
        });
        seed(&fake, &["sbx-a", "sbx-b"]);
        // One cycle cannot confirm anything: the obligation remains.
        assert!(!enforce(&journal, &fake, FAST, &|| false, 1));
        assert!(enforce(&journal, &fake, FAST, &|| false, 10));
        assert!(running(&fake).is_empty());
    }

    #[test]
    fn transient_stop_failure_is_retried_until_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let failures = Arc::new(AtomicUsize::new(3));
        let left = failures.clone();
        // No graceful support: every attempt goes straight to the forced stop.
        let fake = FakeRuntime::new().with_lifecycle_hook(move |stage| {
            if stage == "stop" && take_one(&left) {
                return Err(transient());
            }
            Ok(())
        });
        seed(&fake, &["sbx-a", "sbx-b"]);
        let mut obligation = StopObligation::new(FAST);
        let mut cycles = 0;
        while obligation.poll(&journal, &fake, &|| false) {
            cycles += 1;
            assert!(cycles < 1000, "the obligation never settled");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(failures.load(Ordering::SeqCst), 0);
        assert!(running(&fake).is_empty());
        // Confirmed: no further runtime work.
        assert!(!obligation.poll(&journal, &fake, &|| false));
    }

    /// A pass interrupted after its first stop leaves the marker; the next
    /// process (a fresh obligation over the same journal) resumes it.
    #[test]
    fn restart_mid_pass_resumes_from_the_durable_marker() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let fake = FakeRuntime::new();
        seed(&fake, &["sbx-a", "sbx-b", "sbx-c"]);
        let interrupted = AtomicUsize::new(0);
        let cancel_after_first = || interrupted.fetch_add(1, Ordering::SeqCst) >= 1;
        assert!(!enforce(&journal, &fake, FAST, &cancel_after_first, 3));
        assert_eq!(running(&fake).len(), 2, "interrupted mid-pass");
        assert!(is_revoked(&journal));
        assert!(enforce(&journal, &fake, FAST, &|| false, 1));
        assert!(running(&fake).is_empty());
    }

    #[test]
    fn a_lifted_marker_ends_the_obligation_without_runtime_work() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        clear(&journal);
        let fake = FakeRuntime::new();
        seed(&fake, &["sbx-a"]);
        assert!(!StopObligation::new(FAST).poll(&journal, &fake, &|| false));
        assert_eq!(running(&fake), vec!["sbx-a".to_owned()]);
    }

    /// Lifting the marker is a journal write. A failed
    /// unlink latches the journal (admission closes, the host reports itself
    /// unschedulable) instead of only warning; a successful one leaves the
    /// journal healthy.
    #[test]
    fn a_failed_marker_removal_latches_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let failing = journal(dir.path());
        failing.io.fail_writes();
        clear(&failing);
        assert!(failing.io_failed(), "a failed delete closes admission");
        assert!(is_revoked(&failing), "the marker survives");

        let dir = tempfile::tempdir().unwrap();
        let healthy = journal(dir.path());
        clear(&healthy);
        assert!(!is_revoked(&healthy));
        assert!(!healthy.io_failed());
        // Absent: nothing to remove, nothing latched.
        clear(&healthy);
        assert!(!healthy.io_failed());
    }

    /// `wait_idle` must not return while the obligation remains, even with
    /// no accepted lease to wait for.
    #[test]
    fn wait_idle_holds_until_every_vm_is_confirmed_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let failures = AtomicUsize::new(5);
        let fake = FakeRuntime::new().with_inventory_hook(move |stage| {
            if stage == "inventory" && take_one(&failures) {
                return Err(transient());
            }
            Ok(())
        });
        seed(&fake, &["sbx-a", "sbx-b"]);
        let runtime: Arc<dyn SandboxRuntime> = Arc::new(fake.clone());
        let expiry = super::super::expiry::ExpiryService::start(
            runtime,
            journal.clone(),
            super::super::authority::HostAuthority::with_journal(journal.clone()),
        );
        let shutdown = super::super::connect::ShutdownSignal::default();
        expiry.wait_idle_with(&shutdown, StopObligation::new(FAST));
        assert!(running(&fake).is_empty());
    }

    /// A verdict whose marker cannot be written yet still stops every VM
    /// through transient runtime failures, and keeps retrying the marker
    /// until it is durable.
    #[test]
    fn a_failed_marker_write_keeps_the_latched_obligation_alive() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let journal = unmarked_journal(dir.path());
        let set_mode = |mode| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap()
        };
        set_mode(0o500);
        if journal.persist_marker("PROBE", b"x").is_ok() {
            // Running with CAP_DAC_OVERRIDE: the fault cannot be injected.
            set_mode(0o700);
            return;
        }
        let stop_failures = Arc::new(AtomicUsize::new(2));
        let inventory_failures = Arc::new(AtomicUsize::new(2));
        let (stops, inventories) = (stop_failures.clone(), inventory_failures.clone());
        // Faults apply to the obligation's calls, not to the test's own checks.
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let inventory_armed = armed.clone();
        let fake = FakeRuntime::new()
            .with_lifecycle_hook(move |stage| {
                if stage == "stop" && take_one(&stops) {
                    return Err(transient());
                }
                Ok(())
            })
            .with_inventory_hook(move |stage| {
                if stage == "inventory"
                    && inventory_armed.load(Ordering::SeqCst)
                    && take_one(&inventories)
                {
                    return Err(transient());
                }
                Ok(())
            });
        seed(&fake, &["sbx-a", "sbx-b"]);
        let running = |fake: &FakeRuntime| {
            armed.store(false, Ordering::SeqCst);
            let left = running(fake);
            armed.store(true, Ordering::SeqCst);
            left
        };
        let mut obligation = StopObligation::latched(FAST);
        let mut polls = 0;
        // Every VM ends up stopped while the marker still cannot be written.
        while !running(&fake).is_empty() {
            assert!(obligation.poll(&journal, &fake, &|| false));
            polls += 1;
            assert!(polls < 1000, "the stops never settled");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!is_revoked(&journal));
        assert!(
            obligation.poll(&journal, &fake, &|| false),
            "marker still pending"
        );
        set_mode(0o700);
        while obligation.poll(&journal, &fake, &|| false) {
            polls += 1;
            assert!(polls < 2000, "the marker was never written");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(is_revoked(&journal));
        assert!(running(&fake).is_empty());
        assert_eq!(stop_failures.load(Ordering::SeqCst), 0);
        assert_eq!(inventory_failures.load(Ordering::SeqCst), 0);
    }

    /// Without a latch, a missing marker is no obligation.
    #[test]
    fn an_unlatched_obligation_needs_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let journal = unmarked_journal(dir.path());
        let fake = FakeRuntime::new();
        seed(&fake, &["sbx-a"]);
        assert!(!StopObligation::new(FAST).poll(&journal, &fake, &|| false));
        assert_eq!(running(&fake).len(), 1);
    }
}
