//! Periodic checkpoints.
//!
//! Every `checkpointIntervalMin` an ACTIVE exclusive copy-back GUEST binding
//! with files is packed without quiesce, hashed in memory (SHA-256) and,
//! when the bytes changed since this process last sealed one, sealed as a
//! `checkpoint` envelope that replaces any pending checkpoint of its lease
//! (outbox coalescing). A checkpoint:
//!
//! - never waits for the guest slot (`try_acquire(Checkpoint)`): a busy slot
//!   skips this tick and the binding is retried on the next one;
//! - skips a binding with a teardown record, a sandbox with an open
//!   teardown attempt, a revoked slot and a lease the server revoked;
//! - never scrubs and never changes a binding's phase;
//! - uploads after the slot is released and never waits for the outcome
//!   (the ack resolves the outbox entry on arrival; a census re-uploads
//!   whatever is still pending after a reconnect).
//!
//! Nothing here logs a value, a path or a frame body.

use super::*;
use sandbox_runtime::RuntimePermit;
use std::thread::JoinHandle;

use super::super::journal::AttemptState;
use super::super::ops::capture_binding_if;

/// How often the timer looks for due checkpoints.
pub const CHECKPOINT_TICK: Duration = Duration::from_secs(30);
/// One checkpoint's pack + seal; a stop preempts it sooner through the slot.
const CHECKPOINT_PACK_BUDGET: Duration = Duration::from_secs(60);
/// Frames already queued above which a checkpoint upload is left to the
/// next census (bounds memory while the relay is down).
const CHECKPOINT_UPLOAD_BACKLOG: usize = 256;

/// Resolves a sandbox's checkpoint target (the connect loop reads the host
/// lease journal).
pub type CheckpointTargets = Arc<dyn Fn(&str) -> Option<CheckpointTarget> + Send + Sync>;

/// The guest a checkpoint packs from and the AAD's sandbox owner.
#[derive(Debug, Clone)]
pub struct CheckpointTarget {
    pub guest: CredentialGuest,
    pub sandbox_owner_id: String,
}

/// What one due binding's checkpoint did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointOutcome {
    /// Sealed durable (and uploaded unless `uploaded` is false).
    Sealed {
        binding_id: String,
        capture_id: String,
        uploaded: bool,
    },
    /// The packed bytes match the last sealed checkpoint: nothing sealed.
    Unchanged { binding_id: String },
    /// Not taken this tick (fixed, non-secret class).
    Skipped {
        binding_id: String,
        reason: &'static str,
    },
}

/// Per-binding schedule and the digest of the last sealed checkpoint.
#[derive(Debug, Clone, Copy)]
pub(super) struct CheckpointMark {
    due: Instant,
    last: Option<[u8; 32]>,
}

#[derive(Debug, Default)]
pub(super) struct Checkpoints {
    marks: HashMap<String, CheckpointMark>,
    /// Leases the server revoked (`credential.revoke`): never checkpointed.
    revoked: BTreeSet<String>,
}

/// The binding's checkpoint interval when it is checkpointable at all.
fn interval_of(binding: &BindingRecord) -> Option<Duration> {
    if binding.phase != BindingPhase::Active
        || binding.teardown.is_some()
        || binding.purpose == BindingPurpose::Login
        || !binding.copy_back
        || !binding.exclusive
    {
        return None;
    }
    let spec = binding.spec.as_ref()?;
    if spec.delivery != CredentialDelivery::Guest || !spec.files.includes_paths() {
        return None;
    }
    spec.checkpoint_interval_min
        .filter(|m| (5..=240).contains(m))
        .map(|m| Duration::from_secs(u64::from(m) * 60))
}

impl CredentialService {
    /// Records a server revocation for the checkpoint timer.
    pub(super) fn forget_checkpoints_of_lease(&self, lease_id: &str) {
        let mut checkpoints = lock(&self.inner.checkpoints);
        checkpoints.revoked.insert(lease_id.to_owned());
        // Bounded: one entry per revoked lease of this process lifetime,
        // pruned once no journaled binding names it.
        if checkpoints.revoked.len() > 4096 {
            let live: BTreeSet<String> = self
                .inner
                .store
                .journal()
                .state()
                .bindings
                .values()
                .map(|b| b.lease_id.clone())
                .collect();
            checkpoints.revoked.retain(|id| live.contains(id));
        }
    }

    /// One timer tick: every checkpointable binding whose interval elapsed
    /// is checkpointed (a binding first seen is scheduled one interval out).
    /// `target` resolves a sandbox's guest identity (None: skipped).
    pub fn run_due_checkpoints(
        &self,
        runtime: &dyn SandboxRuntime,
        now: Instant,
        target: &dyn Fn(&str) -> Option<CheckpointTarget>,
    ) -> Vec<CheckpointOutcome> {
        let eligible: Vec<(BindingRecord, Duration)> = self
            .inner
            .store
            .journal()
            .state()
            .bindings
            .values()
            .filter_map(|b| interval_of(b).map(|i| (b.clone(), i)))
            .collect();
        let due: Vec<(BindingRecord, Duration)> =
            {
                let mut checkpoints = lock(&self.inner.checkpoints);
                checkpoints
                    .marks
                    .retain(|id, _| eligible.iter().any(|(b, _)| &b.binding_id == id));
                eligible
                    .into_iter()
                    .filter(|(b, interval)| {
                        let mark = checkpoints.marks.entry(b.binding_id.clone()).or_insert(
                            CheckpointMark {
                                due: now + *interval,
                                last: None,
                            },
                        );
                        mark.due <= now
                    })
                    .collect()
            };
        due.into_iter()
            .map(|(binding, interval)| {
                let outcome = self.checkpoint_one(runtime, &binding, target);
                // A busy slot is retried on the next tick; everything else
                // waits a full interval.
                let retry = matches!(
                    &outcome,
                    CheckpointOutcome::Skipped {
                        reason: "slot_busy",
                        ..
                    }
                );
                if !retry
                    && let Some(mark) = lock(&self.inner.checkpoints)
                        .marks
                        .get_mut(&binding.binding_id)
                {
                    mark.due = now + interval;
                }
                outcome
            })
            .collect()
    }

    fn checkpoint_one(
        &self,
        runtime: &dyn SandboxRuntime,
        binding: &BindingRecord,
        target: &dyn Fn(&str) -> Option<CheckpointTarget>,
    ) -> CheckpointOutcome {
        let binding_id = binding.binding_id.clone();
        let skipped = |reason| CheckpointOutcome::Skipped {
            binding_id: binding_id.clone(),
            reason,
        };
        if lock(&self.inner.checkpoints)
            .revoked
            .contains(&binding.lease_id)
        {
            return skipped("revoked");
        }
        let store = &self.inner.store;
        let Some(host_owner) = self.host_owner() else {
            return skipped("not_registered");
        };
        if store.current_key_epoch() == 0 {
            return skipped("no_return_key");
        }
        let Some(target) = target(&binding.sandbox_id) else {
            return skipped("no_target");
        };
        let Some(lease) = binding.spec.clone() else {
            return skipped("no_spec");
        };
        if !store.outbox().has_room(
            &binding.lease_id,
            CaptureKind::Checkpoint,
            CredentialStore::worst_case_envelope_bytes(lease.max_bytes),
        ) {
            return skipped("no_room");
        }
        let coord = self.coord(&binding.sandbox_id);
        let permit = Arc::new(RuntimePermit::with_timeout(CHECKPOINT_PACK_BUDGET));
        // Never waits: a teardown, install, attach or free holding the slot
        // wins, and a stop preempts this holder through its permit.
        let guard = match coord.slot.try_acquire(SlotUser::Checkpoint, &permit) {
            Ok(guard) => guard,
            Err(super::super::slot::SlotError::Revoked) => return skipped("revoked"),
            Err(_) => return skipped("slot_busy"),
        };
        // Re-read under the slot: a teardown that opened its attempt (or
        // reserved this binding) in the meantime wins.
        let current = {
            let journal = store.journal();
            let attempt_open = journal
                .teardown_attempt(&binding.sandbox_id)
                .is_some_and(|a| a.state == AttemptState::Open);
            journal
                .binding(&binding.binding_id)
                .filter(|b| !attempt_open && interval_of(b).is_some())
                .cloned()
        };
        let Some(current) = current else {
            return skipped("teardown");
        };
        let last = lock(&self.inner.checkpoints)
            .marks
            .get(&current.binding_id)
            .and_then(|m| m.last);
        let ctx = CaptureContext {
            host_owner_id: host_owner,
            host_id: self.inner.host_id.clone(),
            sandbox_owner_id: target.sandbox_owner_id.clone(),
            sandbox_id: current.sandbox_id.clone(),
            lease_id: current.lease_id.clone(),
            binding_id: current.binding_id.clone(),
            instance_id: current.instance_id.clone(),
            credential_id: current.credential_id.clone(),
            capture_id: random_id("cap"),
            kind: CaptureKind::Checkpoint,
            residue_id: String::new(),
        };
        let scoped = runtime.with_cancellation(permit.clone());
        let mut digest: Option<[u8; 32]> = None;
        let sealed = capture_binding_if(
            store,
            scoped.as_ref(),
            &target.guest,
            &lease,
            &ctx,
            now_ms(),
            |bytes| {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
                digest = Some(hash);
                last != Some(hash)
            },
        );
        drop(guard);
        let entry = match sealed {
            Ok(Some(entry)) => entry,
            Ok(None) => return CheckpointOutcome::Unchanged { binding_id },
            Err(_) => {
                tracing::warn!("credential checkpoint could not be sealed");
                return skipped("capture_failed");
            }
        };
        if let Some(mark) = lock(&self.inner.checkpoints)
            .marks
            .get_mut(&current.binding_id)
        {
            mark.last = digest;
        }
        let uploaded = self.send_checkpoint(&entry);
        CheckpointOutcome::Sealed {
            binding_id,
            capture_id: entry.capture_id,
            uploaded,
        }
    }

    /// Queues `capture.begin` + chunks without waiting for the outcome.
    /// Returns false when the frame backlog says the relay is not draining
    /// (the next census uploads the pending envelope).
    fn send_checkpoint(&self, entry: &OutboxEntry) -> bool {
        if lock(&self.inner.frames).queue.len() > CHECKPOINT_UPLOAD_BACKLOG {
            return false;
        }
        let Ok(envelope) = self.inner.store.outbox().read(&entry.capture_id) else {
            return false;
        };
        let chunks: Vec<String> = envelope
            .bytes
            .chunks(CREDENTIAL_CHUNK_RAW_BYTES)
            .map(encode_chunk_data)
            .collect();
        let begin = CredentialCaptureBeginV11 {
            capture_id: entry.capture_id.clone(),
            lease_id: entry.lease_id.clone(),
            binding_id: entry.binding_id.clone(),
            kid_r: entry.kid_r.clone(),
            kind: entry.kind,
            envelope_digest: envelope.digest_hex(),
            envelope_len: envelope.bytes.len() as u64,
            chunk_count: chunks.len() as u32,
        };
        drop(envelope);
        if !begin.is_valid() {
            return false;
        }
        self.push(DaemonControlMessage::CredentialCaptureBegin(begin));
        for (seq, data) in chunks.into_iter().enumerate() {
            self.push(DaemonControlMessage::CredentialCaptureChunk(
                CredentialCaptureChunkV11 {
                    capture_id: entry.capture_id.clone(),
                    seq: seq as u32,
                    data,
                },
            ));
        }
        true
    }

    /// Starts the checkpoint timer: every `tick`, [`Self::run_due_checkpoints`].
    /// Dropping the returned handle stops it and joins the thread.
    pub fn start_checkpoints(
        &self,
        runtime: Arc<dyn SandboxRuntime>,
        target: CheckpointTargets,
        tick: Duration,
    ) -> CheckpointTimer {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let service = self.clone();
        let log_dispatch = tracing::dispatcher::get_default(|dispatch| dispatch.clone());
        let worker = std::thread::Builder::new()
            .name("wssp-credential-checkpoints".into())
            .spawn(move || {
                let _log = tracing::dispatcher::set_default(&log_dispatch);
                let mut next = Instant::now() + tick;
                while !flag.load(Ordering::SeqCst) {
                    let now = Instant::now();
                    if now >= next {
                        service.run_due_checkpoints(runtime.as_ref(), now, target.as_ref());
                        next = Instant::now() + tick;
                    }
                    std::thread::sleep(POLL.min(next.saturating_duration_since(Instant::now())));
                }
            })
            .ok();
        CheckpointTimer { stop, worker }
    }
}

/// The running checkpoint timer; stopped and joined on drop.
#[derive(Debug)]
pub struct CheckpointTimer {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for CheckpointTimer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
