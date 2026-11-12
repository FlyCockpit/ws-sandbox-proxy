//! Session side: run the per-command proofs that retire UNKNOWN
//! `command.run` receipts (see `journal/retire.rs`). Proofs (VM stopped or
//! absent, the guest rebooted, or the root retire helper's scope proof) run
//! on the relay's observation worker, never on the session thread or the
//! control worker that carries cancels and stdin. Under decision 1 a due
//! command's whole guest scope is killed first; a command still running is
//! re-observed inside the session, paced (`RetirePacing`).
use std::sync::Arc;

use sandbox_protocol::TransportBindingV11;
use sandbox_runtime::SandboxRuntime;

use super::authority::HostAuthority;
use super::journal::{CommandRetirement, HostJournal, RetirePacing, RetireSettle};
use super::supervisor::RelaySupervisor;

/// One relay session's retirement authority. Created before `hello`
/// (unnegotiated); dropped on every exit of the session, which revokes
/// `commandRetire` and bumps the token, so a proof taken in the session can
/// never kill, re-defer or delete after it ended (during backoff, a failed
/// dial or before the next `hello.ok`).
pub(super) struct SessionScope(Arc<HostJournal>);
impl SessionScope {
    pub(super) fn begin(journal: &Arc<HostJournal>) -> Self {
        journal.set_command_retire(false);
        Self(journal.clone())
    }
}
impl Drop for SessionScope {
    fn drop(&mut self) {
        self.0.set_command_retire(false);
    }
}

#[cfg(test)]
thread_local! {
    /// Test pacing for the daemon thread (adoption tests): production
    /// intervals would make in-session retries take minutes.
    pub(super) static PACING_OVERRIDE: std::cell::Cell<Option<RetirePacing>> =
        const { std::cell::Cell::new(None) };
}

fn pacing() -> RetirePacing {
    #[cfg(test)]
    if let Some(pacing) = PACING_OVERRIDE.with(std::cell::Cell::get) {
        return pacing;
    }
    RetirePacing::PRODUCTION
}

/// Start every due retirement. Work with a live owner (carried, adopted or
/// still running here) settles itself and is skipped. A full observation
/// queue re-defers the entry. Every path settles the journal entry exactly
/// once, after its proof is done (or was never started).
pub(super) fn start(
    journal: &Arc<HostJournal>,
    authority: &HostAuthority,
    runtime: &Arc<dyn SandboxRuntime>,
    relay: &RelaySupervisor,
    binding: &TransportBindingV11,
) {
    start_with(journal, authority, runtime, binding, pacing(), |work| {
        relay.observe(work)
    });
}

pub(super) fn start_with(
    journal: &Arc<HostJournal>,
    authority: &HostAuthority,
    runtime: &Arc<dyn SandboxRuntime>,
    binding: &TransportBindingV11,
    pacing: RetirePacing,
    observe: impl Fn(Box<dyn FnOnce() + Send>) -> anyhow::Result<()>,
) {
    for retirement in journal.take_retirements(&pacing) {
        let operation_id = retirement.request.operation_id.clone();
        let session = retirement.session;
        if authority.pending(&operation_id).is_some() {
            journal.settle_retirement(&operation_id, session, RetireSettle::Done, &pacing);
            continue;
        }
        let worker_journal = journal.clone();
        let authority = authority.clone();
        let runtime = runtime.clone();
        let binding = binding.clone();
        let queued = observe(Box::new(move || {
            // Settles on every exit of the proof, panics included.
            let mut settle = Settle {
                journal: &worker_journal,
                retirement: &retirement,
                outcome: RetireSettle::Done,
                pacing,
            };
            settle.outcome = retire(
                &worker_journal,
                &authority,
                runtime.as_ref(),
                &binding,
                &retirement,
                &pacing,
            );
        }));
        if queued.is_err() {
            journal.settle_retirement(
                &operation_id,
                session,
                RetireSettle::Retry(Some(pacing.queue_full)),
                &pacing,
            );
        }
    }
}

/// Settles one attempt's journal entry when the proof ends (U2).
struct Settle<'a> {
    journal: &'a HostJournal,
    retirement: &'a CommandRetirement,
    outcome: RetireSettle,
    pacing: RetirePacing,
}
impl Drop for Settle<'_> {
    fn drop(&mut self) {
        self.journal.settle_retirement(
            &self.retirement.request.operation_id,
            self.retirement.session,
            self.outcome,
            &self.pacing,
        );
    }
}

fn retire(
    journal: &HostJournal,
    authority: &HostAuthority,
    runtime: &dyn SandboxRuntime,
    binding: &TransportBindingV11,
    retirement: &CommandRetirement,
    pacing: &RetirePacing,
) -> RetireSettle {
    let operation_id = &retirement.request.operation_id;
    // I2 at check time (R9), for every mode: still this session's request,
    // ownerless, and the same retirable attempt.
    if !journal.retirement_current(retirement) || authority.pending(operation_id).is_some() {
        return RetireSettle::Done;
    }
    // Diagnostics: operation id, mode and the runtime's constant verdict
    // label only, never guest output.
    let mode = retirement.request.mode.as_arg();
    let proof = match runtime.retire_command_group(&retirement.request) {
        Ok(sandbox_runtime::RetireObservation::Gone(proof)) => proof,
        Ok(observation @ sandbox_runtime::RetireObservation::Running { not_due }) => {
            tracing::info!(
                operation_id = %operation_id,
                mode,
                verdict = observation.verdict(),
                "UNKNOWN command still running; re-observing in this session"
            );
            return RetireSettle::Retry(not_due.map(|remaining| remaining + pacing.not_due_pad));
        }
        Ok(observation @ sandbox_runtime::RetireObservation::Parked) => {
            tracing::info!(
                operation_id = %operation_id,
                mode,
                verdict = observation.verdict(),
                "UNKNOWN command of a guest-root sandbox not provable from the host; parked until \
                 the VM stops or its QEMU process changes"
            );
            return RetireSettle::Park;
        }
        Err(error) => {
            tracing::info!(
                operation_id = %operation_id,
                mode,
                verdict = error.diagnostic().unwrap_or("error"),
                code = error.code.as_str(),
                "UNKNOWN command not proven gone; receipt retained"
            );
            return RetireSettle::Done;
        }
    };
    let verdict = proof.verdict();
    // An owner that appeared meanwhile keeps its receipt.
    if authority.pending(operation_id).is_some() {
        return RetireSettle::Done;
    }
    // The journal re-checks, right before the delete, that the session this
    // proof was taken in is still the current negotiated one.
    match journal.retire_unknown_command(
        binding,
        &retirement.confirmation,
        &proof,
        retirement.session,
    ) {
        Ok(true) => tracing::info!(
            operation_id = %operation_id,
            mode,
            verdict,
            "retired an UNKNOWN command receipt after proving it gone"
        ),
        Ok(false) => {}
        Err(_) => tracing::warn!(
            operation_id = %operation_id,
            mode,
            verdict,
            "command receipt retirement journal IO failed; receipt retained"
        ),
    }
    RetireSettle::Done
}
