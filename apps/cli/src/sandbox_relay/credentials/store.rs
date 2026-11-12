//! `CredentialStore`: the daemon's durable credential state behind short
//! locks (journal, outbox) plus the return-key transition barrier.
//!
//! Lock discipline: the journal and the outbox mutexes are never held
//! together and never across a wait on the relay, the guest or another
//! lock. A seal holds the barrier's READ guard for the whole
//! pack → seal → envelope-durable span; installing a newer return key takes
//! the WRITE guard, which blocks new seals under the old kid and waits for
//! in-flight ones to become durable.

use anyhow::{Context, Result, bail};
use sandbox_protocol::{
    CaptureAckOutcome, CaptureKind, CensusEntryV11, CensusPendingV11, CensusQuarantinedV11,
    CredentialCaptureAckV11, CredentialCensusV11, CredentialReturnKeyAckV11,
    CredentialReturnKeyV11, ReturnKeyRefusal, paginate_census,
};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard};

use super::SecretBytes;
use super::envelope;
use super::journal::{CredentialJournal, KeyAcceptance, KeySlot, QuarantineRecord};
use super::outbox::{Outbox, OutboxEntry, QuarantineOutcome};
use super::seal::{ReturnAad, ReturnPublicKey};

pub const CREDENTIALS_DIR: &str = "credentials";

/// The seal key currently in force.
#[derive(Debug, Clone)]
pub struct SealKey {
    pub slot: KeySlot,
    pub public: ReturnPublicKey,
}

impl SealKey {
    fn from_slot(slot: KeySlot) -> Result<Self> {
        let public = ReturnPublicKey::parse(&slot.public_key, &slot.kid_r)
            .map_err(|_| anyhow::anyhow!("return key does not match its kid"))?;
        Ok(Self { slot, public })
    }
}

/// Everything a capture binds besides the server's return key in the authenticated additional data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureContext {
    pub host_owner_id: String,
    pub host_id: String,
    pub sandbox_owner_id: String,
    pub sandbox_id: String,
    pub lease_id: String,
    pub binding_id: String,
    pub instance_id: String,
    pub credential_id: String,
    pub capture_id: String,
    pub kind: CaptureKind,
    /// Empty unless the capture recaptures a residue row.
    pub residue_id: String,
}

/// What the daemon may do with a binding's guest files after an ack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckEffect {
    /// COMMITTED, UNCHANGED or an authorized DISCARDED: resolved, scrub ok.
    Resolved { scrub_allowed: bool },
    /// DEFERRED: the envelope stays durable; scrub allowed only when it is
    /// sealed under the current (newest acked) key.
    Deferred { scrub_allowed: bool },
    /// REJECTED: never scrub; the envelope is quarantined.
    Rejected { quarantined: bool },
}

pub struct CredentialStore {
    journal: Mutex<CredentialJournal>,
    outbox: Mutex<Outbox>,
    barrier: RwLock<Option<SealKey>>,
    alerts: Mutex<Vec<String>>,
    #[cfg(test)]
    pub(crate) before_durable: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl CredentialStore {
    /// Opens `<data>/credentials/{journal.json,outbox/}`.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let dir: PathBuf = data_dir.join(CREDENTIALS_DIR);
        let journal = CredentialJournal::open(&dir)?;
        let outbox = Outbox::open(&dir)?;
        let key = journal
            .key_slot()
            .cloned()
            .map(SealKey::from_slot)
            .transpose()?;
        Ok(Self {
            journal: Mutex::new(journal),
            outbox: Mutex::new(outbox),
            barrier: RwLock::new(key),
            alerts: Mutex::new(Vec::new()),
            #[cfg(test)]
            before_durable: Mutex::new(None),
        })
    }

    /// Short journal lock: never hold it across a wait.
    pub fn journal(&self) -> MutexGuard<'_, CredentialJournal> {
        lock(&self.journal)
    }

    pub fn outbox(&self) -> MutexGuard<'_, Outbox> {
        lock(&self.outbox)
    }

    /// Alerts raised (quarantine full, key substitution); drained by the
    /// relay into events.
    pub fn take_alerts(&self) -> Vec<String> {
        std::mem::take(&mut *lock(&self.alerts))
    }

    fn alert(&self, text: &str) {
        lock(&self.alerts).push(text.to_owned());
    }

    pub fn current_key_epoch(&self) -> u64 {
        self.read_key().as_ref().map_or(0, |k| k.slot.epoch)
    }

    fn read_key(&self) -> RwLockReadGuard<'_, Option<SealKey>> {
        self.barrier
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // --- return key installation -------------------------------------

    /// Handles `credential.return.key`: acceptance rule, durable slot, then
    /// the barrier switch, then the ack (the caller follows it with a
    /// complete census).
    pub fn install_return_key(
        &self,
        frame: &CredentialReturnKeyV11,
    ) -> Result<CredentialReturnKeyAckV11> {
        if !frame.is_valid() {
            bail!("invalid return key frame");
        }
        let slot = KeySlot {
            kid_r: frame.kid_r.clone(),
            epoch: frame.epoch,
            public_key: frame.public_key.clone(),
            server_origin: frame.server_origin.clone(),
        };
        let key = SealKey::from_slot(slot.clone())?;
        // (a) persist under the acceptance rule (short journal lock).
        let accepted = self.journal().offer_return_key(slot)?;
        let refused = match accepted {
            KeyAcceptance::Accepted { .. } => {
                // (b)+(c) block new old-kid seals, wait for in-flight ones to
                // become durable, then switch.
                let mut guard = self
                    .barrier
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *guard = Some(key);
                None
            }
            KeyAcceptance::Duplicate => None,
            KeyAcceptance::Stale { .. } => Some(ReturnKeyRefusal::Stale),
            KeyAcceptance::Substitution { .. } => {
                self.alert("return key substitution refused");
                Some(ReturnKeyRefusal::Substitution)
            }
        };
        // (d) the ack.
        let current = self.read_key();
        let current_kid = current.as_ref().map(|k| k.slot.kid_r.clone());
        let current_epoch = current.as_ref().map_or(frame.epoch, |k| k.slot.epoch);
        drop(current);
        let mut retired: Vec<(String, u64)> = self
            .journal()
            .state()
            .retired_kids
            .iter()
            .map(|(k, e)| (k.clone(), *e))
            .collect();
        retired.sort_by_key(|(_, e)| std::cmp::Reverse(*e));
        retired.truncate(sandbox_protocol::CREDENTIAL_RETIRED_KIDS_MAX);
        let pending_under_retired = self
            .outbox()
            .pending()
            .filter(|e| Some(&e.kid_r) != current_kid.as_ref())
            .count() as u32;
        Ok(CredentialReturnKeyAckV11 {
            kid_r: frame.kid_r.clone(),
            epoch: frame.epoch,
            current_epoch,
            retired_kids: retired.into_iter().map(|(k, _)| k).collect(),
            pending_under_retired,
            refused,
        })
    }

    // --- capture (pack → seal → durable) --------------------------------------

    /// Produces the plaintext (`pack`), seals it for `ctx` under the current
    /// key and writes it self-verified durable. The barrier read guard spans
    /// pack, sequence allocation, seal and durable write, so a key switch
    /// waits for it and the envelope's kid is never retired mid-flight.
    pub fn seal_capture_with(
        &self,
        ctx: &CaptureContext,
        now_ms: u64,
        pack: impl FnOnce() -> Result<SecretBytes>,
    ) -> Result<OutboxEntry> {
        let guard = self.read_key();
        let Some(key) = guard.as_ref() else {
            bail!("no acked return key: capture cannot be sealed");
        };
        let plaintext = pack()?;
        let capture_seq = self.journal().allocate_capture_seq(&ctx.lease_id)?;
        let aad = ReturnAad {
            server_origin: key.slot.server_origin.clone(),
            host_owner_id: ctx.host_owner_id.clone(),
            host_id: ctx.host_id.clone(),
            sandbox_owner_id: ctx.sandbox_owner_id.clone(),
            sandbox_id: ctx.sandbox_id.clone(),
            lease_id: ctx.lease_id.clone(),
            binding_id: ctx.binding_id.clone(),
            instance_id: ctx.instance_id.clone(),
            credential_id: ctx.credential_id.clone(),
            capture_seq,
            capture_id: ctx.capture_id.clone(),
            kind: ctx.kind.as_str().to_owned(),
            residue_id: ctx.residue_id.clone(),
        };
        let sealed = super::seal::seal(plaintext.expose(), &key.public, &aad)
            .map_err(|e| anyhow::anyhow!("seal capture: {e:?}"))?;
        let env = envelope::build(&key.public, &aad, &sealed, now_ms)
            .map_err(|e| anyhow::anyhow!("build envelope: {e:?}"))?;
        #[cfg(test)]
        if let Some(hook) = lock(&self.before_durable).as_ref() {
            hook();
        }
        let entry = self.outbox().write_durable(&env)?;
        drop(guard);
        Ok(entry)
    }

    /// Worst-case sealed envelope for a definition's `maxBytes` (pre-check).
    pub fn worst_case_envelope_bytes(max_bytes: u64) -> u64 {
        login_definition::limits::bundle_max_encoded_bytes(max_bytes as usize) as u64
            + 9
            + envelope::MAX_HEADER_BYTES as u64
            + super::seal::SEAL_OVERHEAD as u64
    }

    /// Applies `credential.capture.ack` to the outbox.
    pub fn apply_capture_ack(&self, ack: &CredentialCaptureAckV11) -> Result<AckEffect> {
        if !ack.is_valid() {
            bail!("invalid capture ack");
        }
        let current_kid = self.read_key().as_ref().map(|k| k.slot.kid_r.clone());
        // The binding's teardown record learns the outcome before the outbox
        // forgets the envelope (a joining operation reports it; a crash in
        // between never re-packs under a capture id the server holds).
        self.journal()
            .record_teardown_ack(&ack.capture_id, ack.outcome)?;
        let mut outbox = self.outbox();
        match ack.outcome {
            CaptureAckOutcome::Committed
            | CaptureAckOutcome::Unchanged
            | CaptureAckOutcome::Discarded => {
                outbox.resolve(&ack.capture_id)?;
                Ok(AckEffect::Resolved {
                    scrub_allowed: true,
                })
            }
            CaptureAckOutcome::Deferred => {
                let under_current = outbox
                    .pending()
                    .find(|e| e.capture_id == ack.capture_id)
                    .is_some_and(|e| Some(&e.kid_r) == current_kid.as_ref());
                Ok(AckEffect::Deferred {
                    scrub_allowed: under_current,
                })
            }
            CaptureAckOutcome::Rejected => {
                let Some(entry) = outbox
                    .pending()
                    .find(|e| e.capture_id == ack.capture_id)
                    .cloned()
                else {
                    // Already quarantined (replayed ack) or unknown.
                    let known = outbox.quarantined().any(|e| e.capture_id == ack.capture_id);
                    return Ok(AckEffect::Rejected { quarantined: known });
                };
                let outcome = outbox.quarantine(&ack.capture_id)?;
                drop(outbox);
                match outcome {
                    QuarantineOutcome::Quarantined => {
                        self.journal().record_quarantined(
                            &ack.capture_id,
                            QuarantineRecord {
                                lease_id: entry.lease_id,
                                kid_r: entry.kid_r,
                            },
                        )?;
                        Ok(AckEffect::Rejected { quarantined: true })
                    }
                    QuarantineOutcome::FullHeld => {
                        self.alert("credential quarantine full: rejected envelope held");
                        Ok(AckEffect::Rejected { quarantined: false })
                    }
                }
            }
        }
    }

    /// `credential.quarantine.discard` → ids to confirm in
    /// `credential.quarantine.discarded`.
    pub fn discard_quarantined(&self, capture_ids: &[String]) -> Result<Vec<String>> {
        let done = self.outbox().discard_quarantined(capture_ids)?;
        self.journal().forget_quarantined(&done)?;
        Ok(done)
    }

    // --- census -----------------------------------------------------------------

    /// A complete census: one entry per journaled binding with its
    /// unresolved envelopes (quarantined ones excluded), quarantined on
    /// page 0, `keyEpoch` = the slot epoch.
    pub fn census(&self) -> Result<Vec<CredentialCensusV11>> {
        let key_epoch = self.current_key_epoch();
        let (pending, quarantined): (Vec<OutboxEntry>, Vec<OutboxEntry>) = {
            let outbox = self.outbox();
            (
                outbox.pending().cloned().collect(),
                outbox.quarantined().cloned().collect(),
            )
        };
        let journal = self.journal();
        let mut entries = Vec::new();
        for b in journal.state().bindings.values() {
            let mine: Vec<CensusPendingV11> = pending
                .iter()
                .filter(|e| e.binding_id == b.binding_id)
                .map(|e| CensusPendingV11 {
                    capture_id: e.capture_id.clone(),
                    kid_r: e.kid_r.clone(),
                    kind: e.kind,
                })
                .collect();
            if mine.len() > sandbox_protocol::CREDENTIAL_CENSUS_PENDING_MAX {
                bail!("binding exceeds the unresolved envelope invariant");
            }
            let attempt = journal
                .teardown_attempt(&b.sandbox_id)
                .filter(|a| a.state == super::journal::AttemptState::Open)
                .map(|a| a.attempt_id.clone());
            entries.push(CensusEntryV11 {
                lease_id: b.lease_id.clone(),
                binding_id: b.binding_id.clone(),
                sandbox_id: b.sandbox_id.clone(),
                state: b.phase.into(),
                teardown_attempt_id: attempt,
                scrubbed_verified: b.scrubbed_verified,
                pending: mine,
            });
        }
        drop(journal);
        // Envelopes whose binding the journal no longer knows still count:
        // the server must resolve them before any rebind (drain).
        let known: std::collections::BTreeSet<&str> =
            entries.iter().map(|e| e.binding_id.as_str()).collect();
        let mut orphans: std::collections::BTreeMap<String, CensusEntryV11> = Default::default();
        for e in pending
            .iter()
            .filter(|e| !known.contains(e.binding_id.as_str()))
        {
            let entry = orphans
                .entry(e.binding_id.clone())
                .or_insert_with(|| CensusEntryV11 {
                    lease_id: e.lease_id.clone(),
                    binding_id: e.binding_id.clone(),
                    sandbox_id: e.sandbox_id.clone(),
                    state: sandbox_protocol::CensusBindingState::Stopped,
                    teardown_attempt_id: None,
                    scrubbed_verified: false,
                    pending: Vec::new(),
                });
            entry.pending.push(CensusPendingV11 {
                capture_id: e.capture_id.clone(),
                kid_r: e.kid_r.clone(),
                kind: e.kind,
            });
        }
        entries.extend(orphans.into_values());
        let quarantined = quarantined
            .into_iter()
            .map(|e| CensusQuarantinedV11 {
                capture_id: e.capture_id,
                lease_id: e.lease_id,
                kid_r: e.kid_r,
            })
            .collect();
        paginate_census(key_epoch, quarantined, entries).context("credential census exceeds bounds")
    }
}
