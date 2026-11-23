//! Live attach and free.
//!
//! - **Attach** runs the launch sequence for the attach's one lease on the
//!   running VM: residue `scrub` entries first (verified absent), then the
//!   install bundle, restore, env into memory, `credential.installed`. It
//!   holds the guest slot (wait ≤ 10 s, then a retryable failure) and on
//!   failure drops only the attached lease's env, never a sibling's.
//! - **Free** packs without quiesce, seals and uploads (unless `skip`),
//!   then revokes the lease's env at once — every terminal opened with it
//!   closes on the terminal host's next tick — and scrubs only when allowed:
//!   after COMMITTED / UNCHANGED / an authorized DISCARDED, a durable envelope
//!   under the newest acked key, or a pack error (the owner chose removal);
//!   never after REJECTED (the binding stays open for the next teardown).
//!   A free revoked after sealing records its capture under the teardown
//!   attempt so the superseding stop joins it.
//!
//! Nothing here logs a value, a path or a frame body.

use super::*;
use sandbox_protocol::{
    CredentialLeaseKind, CredentialTeardownOutcomeV11, TeardownCaptureV11, TeardownScrubV11,
};
use sandbox_runtime::RuntimePermit;

use super::super::journal::{BindingPhase, BindingPurpose, BindingRecord};
use super::super::slot::{ATTACH_FREE_SLOT_WAIT, SlotError};
use super::teardown::{capturable, login_capturable};

/// The journal record of a LOGIN binding, first seen in its finish's spec.
/// Non-secret: ids, the spec's lease entry (declared paths) and phase.
fn login_binding(guest: &CredentialGuest, lease: &SpecLeaseV11, binding_id: &str) -> BindingRecord {
    BindingRecord {
        binding_id: binding_id.to_owned(),
        lease_id: lease.lease_id.clone(),
        sandbox_id: guest.sandbox_id.clone(),
        credential_id: lease.credential_id.clone(),
        instance_id: lease.instance_id.clone(),
        // No install spec: the binding was granted without a bundle.
        spec_digest: String::new(),
        copy_back: false,
        exclusive: lease.exclusive,
        purpose: BindingPurpose::Login,
        install_intent: None,
        installed_seq: None,
        phase: BindingPhase::Active,
        teardown: None,
        scrubbed_verified: false,
        spec: Some(lease.clone()),
        // A LOGIN binding never proxies (the login sandbox gets no bundle).
        proxy_handles: Vec::new(),
    }
}

/// A terminal's credential env and the leases it came from.
pub type TerminalEnv = (Vec<(String, String)>, BTreeSet<String>);

/// Why a free could not run. Fixed, non-secret classes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeFailure {
    /// The guest slot stayed busy for 10 s: nothing was touched; retry.
    Busy,
    /// No longer wanted (a stop or kill superseded it).
    Cancelled,
    /// The spec does not name one open binding of this sandbox.
    SpecInvalid,
}

impl FreeFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "credential slot busy",
            Self::Cancelled => "credential free cancelled",
            Self::SpecInvalid => "credential spec invalid",
        }
    }
}

/// A free's capture result inside this module.
enum FreeCaptured {
    /// No capture was due (skip, copy-back off, shareable, env-only).
    None,
    Acked {
        capture_id: String,
        kid_r: String,
        outcome: CaptureAckOutcome,
        reason_ok: bool,
    },
    Durable {
        capture_id: String,
        kid_r: String,
    },
    PackFailed,
}

impl CredentialService {
    /// `credential.attach`: only `inject` leases and
    /// `scrub` residue are accepted. On failure the attached leases' env
    /// leaves memory; siblings keep theirs.
    pub fn attach(
        &self,
        runtime: &dyn SandboxRuntime,
        target: &LaunchTarget,
        spec: &CredentialSpecV11,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<Vec<CredentialInstalledV11>, LaunchFailure> {
        if spec.leases.is_empty()
            || spec
                .leases
                .iter()
                .any(|l| l.action != SpecLeaseAction::Inject)
            || spec
                .residue
                .iter()
                .any(|r| r.action != SpecResidueAction::Scrub)
        {
            return Err(LaunchFailure::SpecInvalid);
        }
        let coord = self.coord(&target.guest.sandbox_id);
        let permit = Arc::new(RuntimePermit::with_timeout(
            SPEC_WAIT + BUNDLE_WAIT + ACK_WAIT,
        ));
        let result = match coord
            .slot
            .acquire(SlotUser::Attach, ATTACH_FREE_SLOT_WAIT, &permit)
        {
            Ok(_guard) => {
                let runtime = runtime.with_cancellation(permit.clone());
                let wanted = || still_wanted() && !permit.is_cancelled();
                self.launch_inner(runtime.as_ref(), target, spec, &wanted)
            }
            Err(SlotError::Revoked) => Err(LaunchFailure::Cancelled),
            Err(_) => Err(LaunchFailure::Install),
        };
        if result.is_err() {
            for lease in &spec.leases {
                self.revoke_lease(&lease.lease_id);
            }
        }
        result
    }

    /// `credential.free`. Returns the receipt's outcome for the
    /// freed binding; a `Busy` or `Cancelled` free touched nothing that the
    /// superseding operation does not own.
    pub fn free(
        &self,
        runtime: &dyn SandboxRuntime,
        guest: &CredentialGuest,
        sandbox_owner_id: &str,
        operation_id: &str,
        spec: &CredentialSpecV11,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<Vec<CredentialTeardownOutcomeV11>, FreeFailure> {
        let [lease] = spec.leases.as_slice() else {
            return Err(FreeFailure::SpecInvalid);
        };
        let (Some(binding_id), true) = (
            lease.binding_id.clone(),
            spec.sandbox_id == guest.sandbox_id
                && matches!(
                    lease.action,
                    SpecLeaseAction::None | SpecLeaseAction::ScrubOnly
                ),
        ) else {
            return Err(FreeFailure::SpecInvalid);
        };
        // A login finish: the LOGIN lease's free captures kind
        // `login` and never scrubs (the login sandbox is destroyed after the
        // save, or kept for a retry). It is never a `skip`.
        let login = lease.kind == CredentialLeaseKind::Login;
        if login
            && (lease.action != SpecLeaseAction::None
                || lease.delivery != CredentialDelivery::Guest)
        {
            return Err(FreeFailure::SpecInvalid);
        }
        let binding = self.inner.store.journal().binding(&binding_id).cloned();
        if binding.as_ref().is_some_and(|b| {
            b.sandbox_id != guest.sandbox_id
                || b.lease_id != lease.lease_id
                || (b.purpose == BindingPurpose::Login) != login
        }) {
            return Err(FreeFailure::SpecInvalid);
        }
        let coord = self.coord(&guest.sandbox_id);
        let permit = Arc::new(RuntimePermit::with_timeout(ACK_WAIT * 2));
        let _guard = match coord
            .slot
            .acquire(SlotUser::Free, ATTACH_FREE_SLOT_WAIT, &permit)
        {
            Ok(guard) => guard,
            Err(SlotError::Revoked) => return Err(FreeFailure::Cancelled),
            Err(_) => return Err(FreeFailure::Busy),
        };
        let scoped = runtime.with_cancellation(permit.clone());
        let wanted = || still_wanted() && !permit.is_cancelled();
        if !wanted() {
            return Err(FreeFailure::Cancelled);
        }
        let current_kid = self
            .inner
            .store
            .journal()
            .key_slot()
            .map(|k| k.kid_r.clone());
        // The server granted the LOGIN binding when the login sandbox became
        // READY, with no bundle: the host first learns it from this spec.
        let binding = match binding {
            None if login => {
                let record = login_binding(guest, lease, &binding_id);
                if self
                    .inner
                    .store
                    .journal()
                    .record_binding(record.clone())
                    .is_err()
                {
                    return Err(FreeFailure::SpecInvalid);
                }
                Some(record)
            }
            other => other,
        };

        // --- capture (pack without quiesce → seal → upload → outcome) --------
        let skip = lease.action == SpecLeaseAction::ScrubOnly;
        let captured = match binding.as_ref() {
            Some(b)
                if !skip
                    && (if login {
                        login_capturable(b)
                    } else {
                        capturable(b)
                    }) =>
            {
                match self.capture_for_free(
                    scoped.as_ref(),
                    guest,
                    sandbox_owner_id,
                    operation_id,
                    &binding_id,
                    &wanted,
                ) {
                    FreeCapture::Sealed(entry) => {
                        match self.upload_within(&entry, ACK_WAIT, &wanted) {
                            Ok(Some(ack)) => FreeCaptured::Acked {
                                capture_id: entry.capture_id.clone(),
                                kid_r: entry.kid_r.clone(),
                                outcome: ack.outcome,
                                reason_ok: ack.reason.is_some_and(CaptureAckReason::is_discard),
                            },
                            Ok(None) => FreeCaptured::Durable {
                                capture_id: entry.capture_id.clone(),
                                kid_r: entry.kid_r.clone(),
                            },
                            Err(_) => {
                                // Sealed but revoked mid-upload: the stop that
                                // superseded this free joins the capture (a
                                // login capture just uploads on its own).
                                if !login {
                                    self.record_revoked_free(
                                        guest,
                                        operation_id,
                                        &binding_id,
                                        &entry,
                                    );
                                }
                                return Err(FreeFailure::Cancelled);
                            }
                        }
                    }
                    FreeCapture::RevokedRecorded(_) => return Err(FreeFailure::Cancelled),
                    FreeCapture::Abandoned if !wanted() => return Err(FreeFailure::Cancelled),
                    FreeCapture::Abandoned => FreeCaptured::PackFailed,
                }
            }
            _ => FreeCaptured::None,
        };

        // --- revoke env at once (terminals opened with it close) -------------
        self.revoke_lease(&lease.lease_id);

        if login {
            return Ok(vec![self.finish_login_free(lease, &binding_id, &captured)]);
        }

        // --- outcome rules ----------------------------------------------
        let (wire, scrub_ok, resolved) = match &captured {
            FreeCaptured::None => (TeardownCaptureV11::None, true, true),
            FreeCaptured::Acked {
                capture_id,
                kid_r,
                outcome,
                reason_ok,
            } => {
                let (scrub_ok, resolved) = match outcome {
                    CaptureAckOutcome::Committed | CaptureAckOutcome::Unchanged => (true, true),
                    CaptureAckOutcome::Discarded => (*reason_ok, *reason_ok),
                    CaptureAckOutcome::Deferred => {
                        (current_kid.as_deref() == Some(kid_r.as_str()), false)
                    }
                    CaptureAckOutcome::Rejected => (false, false),
                };
                (
                    TeardownCaptureV11::Acked {
                        capture_id: capture_id.clone(),
                        outcome: *outcome,
                    },
                    scrub_ok,
                    resolved,
                )
            }
            FreeCaptured::Durable { capture_id, kid_r } => (
                TeardownCaptureV11::Durable {
                    capture_id: capture_id.clone(),
                },
                current_kid.as_deref() == Some(kid_r.as_str()),
                false,
            ),
            // The owner chose removal: scrub anyway.
            FreeCaptured::PackFailed => (
                TeardownCaptureV11::Failed {
                    reason: "pack_failed".to_owned(),
                },
                true,
                true,
            ),
        };

        // --- scrub ------------------------------------------------------------
        let mut scrub = TeardownScrubV11::NotRun;
        if scrub_ok {
            let paths = super::super::ops::included_paths(lease);
            let verified = scrub_paths(scoped.as_ref(), guest, paths).unwrap_or(false);
            let last = self.push(DaemonControlMessage::CredentialScrubbed(
                CredentialScrubbedV11 {
                    sandbox_id: guest.sandbox_id.clone(),
                    binding_ids: vec![binding_id.clone()],
                    verified_absent: verified,
                },
            ));
            scrub = if verified {
                TeardownScrubV11::Verified
            } else {
                TeardownScrubV11::Failed
            };
            if binding.is_some() {
                let mut journal = self.inner.store.journal();
                let recorded = if verified && resolved {
                    // Settled: the server releases the lease on this receipt.
                    journal.forget_binding(&binding_id)
                } else {
                    // Not capturable again (a durable envelope still resolves
                    // it, or the scrub is retried by the next stop).
                    if verified {
                        let _ = journal.mark_scrubbed(std::slice::from_ref(&binding_id));
                    }
                    journal.set_phase(&binding_id, BindingPhase::Stopped)
                };
                if recorded.is_err() {
                    tracing::warn!("credential free could not be journaled");
                }
            }
            let _ = self.flush(last, &wanted);
        }
        Ok(vec![CredentialTeardownOutcomeV11 {
            lease_id: Some(lease.lease_id.clone()),
            binding_id,
            capture: wire,
            scrub,
        }])
    }

    /// The login finish's receipt: never a scrub. A COMMITTED or
    /// UNCHANGED login is settled (the binding is forgotten; the server
    /// destroys the sandbox next). Anything else keeps the LOGIN binding
    /// live, so the user can fix the login in the terminal and finish again;
    /// a durable envelope resolves the login when it uploads.
    fn finish_login_free(
        &self,
        lease: &SpecLeaseV11,
        binding_id: &str,
        captured: &FreeCaptured,
    ) -> CredentialTeardownOutcomeV11 {
        let (wire, saved) = match captured {
            FreeCaptured::None => (TeardownCaptureV11::None, false),
            FreeCaptured::Acked {
                capture_id,
                outcome,
                ..
            } => (
                TeardownCaptureV11::Acked {
                    capture_id: capture_id.clone(),
                    outcome: *outcome,
                },
                matches!(
                    outcome,
                    CaptureAckOutcome::Committed | CaptureAckOutcome::Unchanged
                ),
            ),
            FreeCaptured::Durable { capture_id, .. } => (
                TeardownCaptureV11::Durable {
                    capture_id: capture_id.clone(),
                },
                false,
            ),
            FreeCaptured::PackFailed => (
                TeardownCaptureV11::Failed {
                    reason: "pack_failed".to_owned(),
                },
                false,
            ),
        };
        if saved
            && self
                .inner
                .store
                .journal()
                .forget_binding(binding_id)
                .is_err()
        {
            tracing::warn!("credential login finish could not be journaled");
        }
        CredentialTeardownOutcomeV11 {
            lease_id: Some(lease.lease_id.clone()),
            binding_id: binding_id.to_owned(),
            capture: wire,
            scrub: TeardownScrubV11::NotRun,
        }
    }

    /// A free revoked after sealing (mid-upload): its envelope is recorded
    /// under the open teardown attempt so the superseding stop joins it.
    fn record_revoked_free(
        &self,
        guest: &CredentialGuest,
        operation_id: &str,
        binding_id: &str,
        entry: &OutboxEntry,
    ) {
        let recorded = (|| -> anyhow::Result<()> {
            let mut journal = self.inner.store.journal();
            let attempt = journal.open_or_join_teardown(&guest.sandbox_id, operation_id)?;
            journal.record_teardown_capture(binding_id, &attempt.attempt_id, &entry.capture_id)
        })();
        if recorded.is_err() {
            tracing::warn!("revoked free's capture could not be recorded");
        }
    }

    /// Lease ids whose env is installed for `sandbox_id` right now (the
    /// terminal host closes a session when one it was opened with is gone).
    pub fn installed_env_leases(&self, sandbox_id: &str) -> BTreeSet<String> {
        lock(&self.inner.env)
            .get(sandbox_id)
            .map(|entry| entry.leases.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Test hook: env of one lease as if a bundle had installed it.
    #[cfg(test)]
    pub fn install_test_env(&self, sandbox_id: &str, lease_id: &str, name: &str, value: &[u8]) {
        lock(&self.inner.env)
            .entry(sandbox_id.to_owned())
            .or_default()
            .leases
            .insert(
                lease_id.to_owned(),
                InstalledEnv {
                    values: vec![(
                        name.to_owned(),
                        crate::sandbox_relay::credentials::SecretBytes::copy_from(value),
                    )],
                },
            );
    }

    /// Credential env for a terminal: the values plus the leases they came
    /// from. Never waits (the terminal host runs on the socket loop): env
    /// still being restored after a daemon restart is `EnvPending`.
    pub fn env_with_leases(&self, sandbox_id: &str) -> Result<TerminalEnv, EnvPending> {
        let envs = lock(&self.inner.env);
        let Some(entry) = envs.get(sandbox_id) else {
            return Ok((Vec::new(), BTreeSet::new()));
        };
        if !entry.pending.is_empty() {
            return Err(EnvPending);
        }
        let mut leases = BTreeSet::new();
        let mut values = Vec::new();
        for (lease_id, env) in &entry.leases {
            if env.values.is_empty() {
                continue;
            }
            leases.insert(lease_id.clone());
            for (name, value) in &env.values {
                if let Ok(value) = std::str::from_utf8(value.expose()) {
                    values.push((name.clone(), value.to_owned()));
                }
            }
        }
        Ok((values, leases))
    }
}
