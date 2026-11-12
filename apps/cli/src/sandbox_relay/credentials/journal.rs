//! Credential journal `<data>/credentials/journal.json`.
//!
//! Non-secret state only: per-sandbox teardown attempts, per-binding records
//! (install intent, installed sequence, teardown capture, scrub proof),
//! per-lease capture sequence allocation, the return-key slot and the
//! quarantined envelope ids. Every mutation is one atomic write (0600 temp,
//! fsync, rename, directory fsync) made before the caller acts on it, so a
//! crash replays from what was durable. No value, env name/value pair or
//! file content is ever stored here (the generic file staging and file IO paths
//! are not used by credential modules).

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub const JOURNAL_FILE: &str = "journal.json";
const VERSION: u32 = 1;
/// The journal is small control data; anything larger is corruption.
const JOURNAL_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// The host's durable return-key slot `{kidR, epoch, publicKey}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeySlot {
    pub kid_r: String,
    pub epoch: u64,
    /// Unpadded base64url X25519 public key (public material).
    pub public_key: String,
    pub server_origin: String,
}

/// Result of offering a `credential.return.key` to the slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAcceptance {
    /// `epoch > slot.epoch`: persisted; the caller now switches the seal kid.
    Accepted { retired: Option<KeySlot> },
    /// Same epoch, same kid and key: idempotent re-ack.
    Duplicate,
    /// `epoch < slot.epoch`: ignored (a delayed older key never wins back).
    Stale { current_epoch: u64 },
    /// Same epoch, different kid or key: refused, slot unchanged, alert.
    Substitution { current_epoch: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Open,
    Aborted,
    Done,
}

/// One teardown attempt per sandbox: stop, kill, free, local expiry
/// and server expiry STOP open it or join the open one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeardownAttempt {
    pub attempt_id: String,
    pub op_ids: Vec<String>,
    pub state: AttemptState,
    /// Set together with `Aborted` (one write) when a user stop/kill was
    /// refused: the host lease row must be re-bound to `generation` before
    /// the FAILED receipt. The lease journal (one file per sandbox) is a
    /// projection of this record: applied right after this write and
    /// replayed at startup while `applied` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebind: Option<RebindRecord>,
}

/// The re-bind a refused user stop/kill owes the host lease row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RebindRecord {
    pub generation: u64,
    pub applied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingPurpose {
    Install,
    Recover,
    Login,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingPhase {
    /// Granted; files may be on the disk from `installIntent` onwards.
    Installing,
    Active,
    Teardown,
    /// The VM stopped with this binding's files possibly on disk.
    Stopped,
    /// Enforcement loss or failed capture: the server recaptures on start.
    RecoveryRequired,
}

impl From<BindingPhase> for sandbox_protocol::CensusBindingState {
    fn from(phase: BindingPhase) -> Self {
        use sandbox_protocol::CensusBindingState as S;
        match phase {
            BindingPhase::Installing => S::Installing,
            BindingPhase::Active => S::Active,
            BindingPhase::Teardown => S::Teardown,
            BindingPhase::Stopped | BindingPhase::RecoveryRequired => S::Stopped,
        }
    }
}

/// Fsynced before the first guest write of an install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallIntent {
    pub request_id: String,
    pub storage_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeardownCaptureState {
    /// A capture id is reserved for this binding in the attempt.
    Reserved,
    /// The envelope is self-verified durable in the outbox.
    Durable,
    /// The server answered (any outcome).
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingTeardown {
    pub attempt_id: String,
    pub capture_id: String,
    pub state: TeardownCaptureState,
    /// The server's answer once `Resolved`, so an operation joining the
    /// attempt later reports the same outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<sandbox_protocol::CaptureAckOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingRecord {
    pub binding_id: String,
    pub lease_id: String,
    pub sandbox_id: String,
    pub credential_id: String,
    pub instance_id: String,
    pub spec_digest: String,
    pub copy_back: bool,
    pub exclusive: bool,
    pub purpose: BindingPurpose,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_intent: Option<InstallIntent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_seq: Option<u64>,
    pub phase: BindingPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown: Option<BindingTeardown>,
    pub scrubbed_verified: bool,
    /// The operation spec's (non-secret) lease entry the binding was granted
    /// under: declared paths, env names, `maxBytes`, delivery. A daemon
    /// restart rebuilds the bundle rules from it to validate a
    /// `restore_env`/`proxy` bundle after a daemon restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<sandbox_protocol::SpecLeaseV11>,
    /// Proxy mode: one guest handle per proxied env entry, in entry
    /// order. Journaled before the guest sees them, so a daemon restart keeps
    /// the guest's base URLs valid (503 until the `proxy` restore bundle).
    /// A handle is a capability for the proxy, not the credential value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_handles: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseRecord {
    /// Next `captureSeq`; never reused, persisted before a seq is handed out.
    pub next_capture_seq: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_attempt: Option<TeardownAttempt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuarantineRecord {
    pub lease_id: String,
    pub kid_r: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialJournalFile {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_slot: Option<KeySlot>,
    /// Kids this host sealed under before, with their epochs (census ack).
    pub retired_kids: BTreeMap<String, u64>,
    pub sandboxes: BTreeMap<String, SandboxRecord>,
    pub bindings: BTreeMap<String, BindingRecord>,
    pub leases: BTreeMap<String, LeaseRecord>,
    pub quarantined: BTreeMap<String, QuarantineRecord>,
    /// Every `captureSeq` handed out under a lease record that lifecycle GC
    /// has since dropped is below this: a lease seen again (a RECOVER
    /// binding of a lease whose record was collected) continues above it,
    /// so a sequence is never reused (the server accepts only increasing
    /// sequences per lease).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub capture_seq_floor: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Lifecycle GC, run on every commit: per-lease sequence records and
/// per-sandbox attempt records live only while something still needs them,
/// so the journal stays bounded by the live bindings instead of growing with
/// every lease and sandbox the host ever saw.
///
/// - A lease record stays while a binding or a quarantined envelope names
///   the lease; a dropped one raises `capture_seq_floor` to its next
///   sequence. Pending captures (outbox envelopes) already carry their
///   sequence, and the floor keeps any later one above it.
/// - A sandbox record stays while the sandbox has a binding, its attempt is
///   open, or a refused teardown's re-bind is still unapplied (the lease
///   journal replays it from here at startup).
fn collect_garbage(file: &mut CredentialJournalFile) {
    let leases: BTreeSet<&str> = file
        .bindings
        .values()
        .map(|b| b.lease_id.as_str())
        .chain(file.quarantined.values().map(|q| q.lease_id.as_str()))
        .collect();
    let sandboxes: BTreeSet<&str> = file
        .bindings
        .values()
        .map(|b| b.sandbox_id.as_str())
        .collect();
    let mut floor = file.capture_seq_floor;
    file.leases.retain(|id, record| {
        let keep = leases.contains(id.as_str());
        if !keep {
            floor = floor.max(record.next_capture_seq);
        }
        keep
    });
    file.capture_seq_floor = floor;
    file.sandboxes.retain(|id, record| {
        sandboxes.contains(id.as_str())
            || record.teardown_attempt.as_ref().is_some_and(|attempt| {
                attempt.state == AttemptState::Open || attempt.rebind.is_some_and(|r| !r.applied)
            })
    });
}

/// Opening or joining a teardown attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptHandle {
    pub attempt_id: String,
    pub joined: bool,
}

#[derive(Debug)]
pub struct CredentialJournal {
    dir: PathBuf,
    file: CredentialJournalFile,
}

fn random_id(prefix: &str) -> Result<String> {
    let mut bytes = [0u8; 12];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
        .map_err(|_| anyhow::anyhow!("system randomness unavailable"))?;
    Ok(format!("{prefix}{}", super::seal::hex(&bytes)))
}

/// Durable small-file write: 0600 temp, fsync, rename, directory fsync.
pub(crate) fn persist_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut tmp = tempfile::Builder::new()
        .prefix(".tmp")
        .tempfile_in(dir)
        .with_context(|| format!("create temp file in `{}`", dir.display()))?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(dir.join(name))
        .map_err(|e| e.error)
        .with_context(|| format!("rename `{name}`"))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Creates `path` as a 0700 directory (or checks an existing one).
pub(crate) fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create `{}`", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

impl CredentialJournal {
    /// Opens `<credentials dir>/journal.json`, creating an empty journal.
    pub fn open(dir: &Path) -> Result<Self> {
        private_dir(dir)?;
        let path = dir.join(JOURNAL_FILE);
        let file = match fs::metadata(&path) {
            Ok(meta) => {
                if meta.len() > JOURNAL_MAX_BYTES {
                    bail!("credential journal is oversized");
                }
                let file: CredentialJournalFile = serde_json::from_slice(&fs::read(&path)?)
                    .context("parse credential journal")?;
                if file.version != VERSION {
                    bail!("unsupported credential journal version");
                }
                file
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => CredentialJournalFile {
                version: VERSION,
                ..Default::default()
            },
            Err(err) => return Err(err).context("stat credential journal"),
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            file,
        })
    }

    pub fn state(&self) -> &CredentialJournalFile {
        &self.file
    }

    /// Applies `change` to a copy, collects what no lifecycle needs any
    /// more, and persists it; memory changes only after the write is
    /// durable, so a failed write leaves both unchanged. A journal the
    /// reader would refuse (over `JOURNAL_MAX_BYTES`) is never committed:
    /// the change fails instead of disabling credentials at the next start.
    fn commit<T>(
        &mut self,
        change: impl FnOnce(&mut CredentialJournalFile) -> Result<T>,
    ) -> Result<T> {
        let mut next = self.file.clone();
        let out = change(&mut next)?;
        collect_garbage(&mut next);
        let bytes = serde_json::to_vec(&next)?;
        if bytes.len() as u64 > JOURNAL_MAX_BYTES {
            bail!("credential journal would exceed its size bound");
        }
        persist_atomic(&self.dir, JOURNAL_FILE, &bytes)?;
        self.file = next;
        Ok(out)
    }

    // --- return-key slot ---------------------------------------------------

    pub fn key_slot(&self) -> Option<&KeySlot> {
        self.file.key_slot.as_ref()
    }

    /// The host acceptance rule: persist only `epoch >
    /// slot.epoch`; same epoch + same key is a re-ack; same epoch with a
    /// different kid or key is a substitution; an older epoch is stale.
    pub fn offer_return_key(&mut self, key: KeySlot) -> Result<KeyAcceptance> {
        if let Some(slot) = &self.file.key_slot {
            if key.epoch < slot.epoch {
                return Ok(KeyAcceptance::Stale {
                    current_epoch: slot.epoch,
                });
            }
            if key.epoch == slot.epoch {
                return Ok(
                    if key.kid_r == slot.kid_r && key.public_key == slot.public_key {
                        KeyAcceptance::Duplicate
                    } else {
                        KeyAcceptance::Substitution {
                            current_epoch: slot.epoch,
                        }
                    },
                );
            }
        }
        self.commit(|file| {
            let retired = file.key_slot.replace(key);
            if let Some(old) = &retired {
                file.retired_kids.insert(old.kid_r.clone(), old.epoch);
            }
            Ok(KeyAcceptance::Accepted { retired })
        })
    }

    // --- capture sequence --------------------------------------------------

    /// Allocates the next `captureSeq` for `lease_id` (starting at 1),
    /// durable before it is returned: a crash never reuses a sequence.
    pub fn allocate_capture_seq(&mut self, lease_id: &str) -> Result<u64> {
        self.commit(|file| {
            let floor = file.capture_seq_floor;
            let lease = file.leases.entry(lease_id.to_owned()).or_default();
            let seq = lease.next_capture_seq.max(floor).max(1);
            if seq >= sandbox_protocol::CREDENTIAL_EPOCH_MAX {
                bail!("capture sequence exhausted");
            }
            lease.next_capture_seq = seq + 1;
            Ok(seq)
        })
    }

    // --- bindings ------------------------------------------------------------

    pub fn binding(&self, binding_id: &str) -> Option<&BindingRecord> {
        self.file.bindings.get(binding_id)
    }

    pub fn bindings_of(&self, sandbox_id: &str) -> impl Iterator<Item = &BindingRecord> {
        self.file
            .bindings
            .values()
            .filter(move |b| b.sandbox_id == sandbox_id)
    }

    /// Records a granted binding (from `credential.bundle.begin`).
    pub fn record_binding(&mut self, record: BindingRecord) -> Result<()> {
        if !sandbox_protocol::valid_credential_id(&record.binding_id) {
            bail!("invalid binding id");
        }
        self.commit(|file| {
            match file.bindings.get(&record.binding_id) {
                Some(existing) if existing.lease_id != record.lease_id => {
                    bail!("binding is already recorded for another lease")
                }
                Some(_) => {}
                None => {
                    file.bindings.insert(record.binding_id.clone(), record);
                }
            }
            Ok(())
        })
    }

    fn with_binding<T>(
        &mut self,
        binding_id: &str,
        change: impl FnOnce(&mut BindingRecord) -> Result<T>,
    ) -> Result<T> {
        self.commit(|file| {
            let binding = file
                .bindings
                .get_mut(binding_id)
                .ok_or_else(|| anyhow::anyhow!("unknown credential binding"))?;
            change(binding)
        })
    }

    /// Fsynced BEFORE the first guest write (`installIntent`).
    pub fn set_install_intent(&mut self, binding_id: &str, intent: InstallIntent) -> Result<()> {
        self.with_binding(binding_id, |b| {
            b.install_intent = Some(intent);
            b.scrubbed_verified = false;
            Ok(())
        })
    }

    pub fn mark_installed(&mut self, binding_id: &str, storage_seq: u64) -> Result<()> {
        self.with_binding(binding_id, |b| {
            if b.install_intent.as_ref().map(|i| i.storage_seq) != Some(storage_seq) {
                bail!("install does not match its recorded intent");
            }
            b.installed_seq = Some(storage_seq);
            b.phase = BindingPhase::Active;
            Ok(())
        })
    }

    /// Records the proxied entries' guest handles before any is used.
    pub fn set_proxy_handles(&mut self, binding_id: &str, handles: Vec<String>) -> Result<()> {
        self.with_binding(binding_id, |b| {
            b.proxy_handles = handles;
            Ok(())
        })
    }

    pub fn set_phase(&mut self, binding_id: &str, phase: BindingPhase) -> Result<()> {
        self.with_binding(binding_id, |b| {
            b.phase = phase;
            Ok(())
        })
    }

    /// Scrub verified absent: the disk no longer holds this binding's files.
    pub fn mark_scrubbed(&mut self, binding_ids: &[String]) -> Result<()> {
        self.commit(|file| {
            for id in binding_ids {
                if let Some(b) = file.bindings.get_mut(id) {
                    b.scrubbed_verified = true;
                }
            }
            Ok(())
        })
    }

    /// Forgets a binding once the server has settled it (terminal lease and
    /// scrub verified, or sandbox deleted).
    pub fn forget_binding(&mut self, binding_id: &str) -> Result<()> {
        self.commit(|file| {
            file.bindings.remove(binding_id);
            Ok(())
        })
    }

    /// Enforcement loss (without the slot state lock): every binding of the
    /// sandbox becomes recovery-required in one short journal write.
    pub fn mark_recovery_required(&mut self, sandbox_id: &str) -> Result<()> {
        self.commit(|file| {
            for b in file.bindings.values_mut() {
                if b.sandbox_id == sandbox_id {
                    b.phase = BindingPhase::RecoveryRequired;
                }
            }
            Ok(())
        })
    }

    // --- teardown attempts -------------------------------------------

    pub fn teardown_attempt(&self, sandbox_id: &str) -> Option<&TeardownAttempt> {
        self.file
            .sandboxes
            .get(sandbox_id)
            .and_then(|s| s.teardown_attempt.as_ref())
    }

    /// Opens a fresh attempt unless one is `open`, which `op_id` then joins.
    /// An aborted or done attempt is never joined.
    pub fn open_or_join_teardown(
        &mut self,
        sandbox_id: &str,
        op_id: &str,
    ) -> Result<AttemptHandle> {
        let fresh = random_id("att")?;
        self.commit(|file| {
            let record = file.sandboxes.entry(sandbox_id.to_owned()).or_default();
            if record
                .teardown_attempt
                .as_ref()
                .and_then(|a| a.rebind)
                .is_some_and(|r| !r.applied)
            {
                // The refused attempt's re-bind must reach the lease journal
                // before a new attempt replaces its record.
                bail!("a refused teardown's re-bind is still owed");
            }
            if let Some(attempt) = record.teardown_attempt.as_mut()
                && attempt.state == AttemptState::Open
            {
                if !attempt.op_ids.iter().any(|id| id == op_id) {
                    attempt.op_ids.push(op_id.to_owned());
                }
                return Ok(AttemptHandle {
                    attempt_id: attempt.attempt_id.clone(),
                    joined: true,
                });
            }
            record.teardown_attempt = Some(TeardownAttempt {
                attempt_id: fresh.clone(),
                op_ids: vec![op_id.to_owned()],
                state: AttemptState::Open,
                rebind: None,
            });
            Ok(AttemptHandle {
                attempt_id: fresh,
                joined: false,
            })
        })
    }

    /// The binding's capture for `attempt_id`: the recorded one when the
    /// binding already captured in this attempt (one capture per binding per
    /// attempt), else a fresh capture id reserved durably. A record from a
    /// different attempt is ignored and replaced.
    pub fn reserve_teardown_capture(
        &mut self,
        binding_id: &str,
        attempt_id: &str,
    ) -> Result<BindingTeardown> {
        let fresh = random_id("cap")?;
        self.with_binding(binding_id, |b| {
            if let Some(t) = &b.teardown
                && t.attempt_id == attempt_id
            {
                return Ok(t.clone());
            }
            let t = BindingTeardown {
                attempt_id: attempt_id.to_owned(),
                capture_id: fresh,
                state: TeardownCaptureState::Reserved,
                outcome: None,
            };
            b.teardown = Some(t.clone());
            b.phase = BindingPhase::Teardown;
            Ok(t)
        })
    }

    pub fn set_teardown_capture_state(
        &mut self,
        binding_id: &str,
        capture_id: &str,
        state: TeardownCaptureState,
    ) -> Result<()> {
        self.with_binding(binding_id, |b| match b.teardown.as_mut() {
            Some(t) if t.capture_id == capture_id => {
                t.state = state;
                Ok(())
            }
            _ => bail!("teardown capture is not recorded for this binding"),
        })
    }

    /// Rearm after a refused user stop/kill, in ONE journal
    /// write: the attempt becomes `aborted` (never joined again), `op_id` is
    /// recorded on it so a replay of the same operation answers the same
    /// refusal, the host lease-row re-bind to `generation` is recorded as
    /// owed, and the bindings' teardown records are cleared (their sealed
    /// envelopes stay in the outbox and resolve normally), so the next stop
    /// opens a new attempt and captures the live files again.
    pub fn abort_teardown_with_rebind(
        &mut self,
        sandbox_id: &str,
        op_id: &str,
        generation: u64,
    ) -> Result<()> {
        let fresh = random_id("att")?;
        self.commit(|file| {
            let record = file.sandboxes.entry(sandbox_id.to_owned()).or_default();
            let attempt = record
                .teardown_attempt
                .get_or_insert_with(|| TeardownAttempt {
                    attempt_id: fresh,
                    op_ids: Vec::new(),
                    state: AttemptState::Aborted,
                    rebind: None,
                });
            attempt.state = AttemptState::Aborted;
            if !attempt.op_ids.iter().any(|id| id == op_id) {
                attempt.op_ids.push(op_id.to_owned());
            }
            let generation = attempt
                .rebind
                .map_or(generation, |r| r.generation.max(generation));
            attempt.rebind = Some(RebindRecord {
                generation,
                applied: false,
            });
            for b in file.bindings.values_mut() {
                if b.sandbox_id == sandbox_id {
                    b.teardown = None;
                    if b.phase == BindingPhase::Teardown {
                        b.phase = BindingPhase::Active;
                    }
                }
            }
            Ok(())
        })
    }

    /// The refusal `op_id` already received (replay after a crash between
    /// the abort and the FAILED receipt): the owed re-bind generation.
    pub fn refused_teardown(&self, sandbox_id: &str, op_id: &str) -> Option<u64> {
        self.teardown_attempt(sandbox_id)
            .filter(|a| a.state == AttemptState::Aborted && a.op_ids.iter().any(|id| id == op_id))
            .and_then(|a| a.rebind.map(|r| r.generation))
    }

    /// Re-binds recorded but not yet confirmed applied to the lease journal.
    pub fn pending_rebinds(&self) -> Vec<(String, u64)> {
        self.file
            .sandboxes
            .iter()
            .filter_map(|(id, s)| {
                let r = s.teardown_attempt.as_ref()?.rebind?;
                (!r.applied).then(|| (id.clone(), r.generation))
            })
            .collect()
    }

    pub fn mark_rebind_applied(&mut self, sandbox_id: &str, generation: u64) -> Result<()> {
        let owed = self
            .teardown_attempt(sandbox_id)
            .and_then(|a| a.rebind)
            .is_some_and(|r| r.generation == generation && !r.applied);
        if !owed {
            return Ok(());
        }
        self.commit(|file| {
            if let Some(r) = file
                .sandboxes
                .get_mut(sandbox_id)
                .and_then(|s| s.teardown_attempt.as_mut())
                .and_then(|a| a.rebind.as_mut())
            {
                r.applied = true;
            }
            Ok(())
        })
    }

    /// Records a teardown capture made outside the attempt's runner: a
    /// revoked free that already sealed records its envelope
    /// under the open attempt so the superseding stop joins it.
    pub fn record_teardown_capture(
        &mut self,
        binding_id: &str,
        attempt_id: &str,
        capture_id: &str,
    ) -> Result<()> {
        self.with_binding(binding_id, |b| {
            b.teardown = Some(BindingTeardown {
                attempt_id: attempt_id.to_owned(),
                capture_id: capture_id.to_owned(),
                state: TeardownCaptureState::Durable,
                outcome: None,
            });
            b.phase = BindingPhase::Teardown;
            Ok(())
        })
    }

    /// Applies a capture ack to the binding whose teardown owns `capture_id`
    /// (recorded before the outbox forgets the envelope, so a crash in
    /// between never re-packs under a capture id the server already holds).
    pub fn record_teardown_ack(
        &mut self,
        capture_id: &str,
        outcome: sandbox_protocol::CaptureAckOutcome,
    ) -> Result<bool> {
        let known = self.file.bindings.values().any(|b| {
            b.teardown
                .as_ref()
                .is_some_and(|t| t.capture_id == capture_id && t.outcome != Some(outcome))
        });
        if !known {
            return Ok(false);
        }
        self.commit(|file| {
            for b in file.bindings.values_mut() {
                if let Some(t) = b.teardown.as_mut()
                    && t.capture_id == capture_id
                {
                    t.state = TeardownCaptureState::Resolved;
                    t.outcome = Some(outcome);
                }
            }
            Ok(true)
        })
    }

    /// The VM stopped (or was destroyed) after a teardown: the attempt is
    /// done; bindings the disk no longer holds (destroyed, or scrub
    /// verified) are forgotten — their unresolved envelopes stay in the
    /// outbox and the census lists them — and the rest are `stopped`
    /// (recovery-required ones keep that phase).
    pub fn settle_teardown(&mut self, sandbox_id: &str, destroyed: bool) -> Result<()> {
        self.commit(|file| {
            if let Some(attempt) = file
                .sandboxes
                .get_mut(sandbox_id)
                .and_then(|s| s.teardown_attempt.as_mut())
                && attempt.state == AttemptState::Open
            {
                attempt.state = AttemptState::Done;
            }
            file.bindings.retain(|_, b| {
                b.sandbox_id != sandbox_id
                    || !(destroyed
                        || (b.scrubbed_verified && b.phase != BindingPhase::RecoveryRequired))
            });
            for b in file.bindings.values_mut() {
                if b.sandbox_id == sandbox_id && b.phase != BindingPhase::RecoveryRequired {
                    b.phase = BindingPhase::Stopped;
                    b.teardown = None;
                }
            }
            Ok(())
        })
    }

    /// Marks the given bindings recovery-required (a system stop whose
    /// capture failed: the next start recaptures the disk).
    pub fn mark_bindings_recovery_required(&mut self, binding_ids: &[String]) -> Result<()> {
        if binding_ids.is_empty() {
            return Ok(());
        }
        self.commit(|file| {
            for id in binding_ids {
                if let Some(b) = file.bindings.get_mut(id) {
                    b.phase = BindingPhase::RecoveryRequired;
                }
            }
            Ok(())
        })
    }

    // --- quarantine ids ------------------------------------------------------

    pub fn record_quarantined(&mut self, capture_id: &str, record: QuarantineRecord) -> Result<()> {
        self.commit(|file| {
            file.quarantined.insert(capture_id.to_owned(), record);
            Ok(())
        })
    }

    pub fn forget_quarantined(&mut self, capture_ids: &[String]) -> Result<()> {
        self.commit(|file| {
            for id in capture_ids {
                file.quarantined.remove(id);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn key(kid: &str, epoch: u64, pk: char) -> KeySlot {
        KeySlot {
            kid_r: kid.into(),
            epoch,
            public_key: pk.to_string().repeat(43),
            server_origin: "https://wssp.example.com".into(),
        }
    }

    pub(crate) fn binding(id: &str, lease: &str, sandbox: &str) -> BindingRecord {
        BindingRecord {
            binding_id: id.into(),
            lease_id: lease.into(),
            sandbox_id: sandbox.into(),
            credential_id: "cred-1".into(),
            instance_id: "inst-1".into(),
            spec_digest: "a".repeat(64),
            copy_back: true,
            exclusive: true,
            purpose: BindingPurpose::Install,
            install_intent: None,
            installed_seq: None,
            phase: BindingPhase::Installing,
            teardown: None,
            scrubbed_verified: false,
            spec: None,
            proxy_handles: Vec::new(),
        }
    }

    /// Lease and sandbox records are collected with their
    /// bindings' lifecycle, and a lease seen again never reuses a sequence.
    #[test]
    fn final_5_lifecycle_gc_bounds_the_journal_and_keeps_sequences_increasing() {
        let d = dir();
        let mut j = CredentialJournal::open(d.path()).unwrap();
        for n in 0..50 {
            let (b, l, s) = (
                format!("bind-{n}"),
                format!("lease-{n}"),
                format!("sbx-{n}"),
            );
            j.record_binding(binding(&b, &l, &s)).unwrap();
            assert_eq!(j.allocate_capture_seq(&l).unwrap(), (n as u64) * 2 + 1);
            j.allocate_capture_seq(&l).unwrap();
            j.open_or_join_teardown(&s, "op-stop").unwrap();
            j.settle_teardown(&s, true).unwrap();
        }
        // Every sandbox was destroyed: nothing per lease or sandbox remains.
        let state = j.state();
        assert!(state.bindings.is_empty());
        assert!(state.leases.is_empty(), "lease records collected");
        assert!(state.sandboxes.is_empty(), "sandbox records collected");
        assert_eq!(state.capture_seq_floor, 101);
        // A collected lease seen again continues above every handed-out seq.
        j.record_binding(binding("bind-again", "lease-0", "sbx-again"))
            .unwrap();
        assert_eq!(j.allocate_capture_seq("lease-0").unwrap(), 101);
        let reopened = CredentialJournal::open(d.path()).unwrap();
        assert_eq!(reopened.state().capture_seq_floor, 101);
        assert_eq!(reopened.state().leases.len(), 1);
    }

    /// GC keeps what a lifecycle still needs: a lease named by a
    /// quarantined envelope, an open attempt, and an unapplied re-bind
    /// until it is applied.
    #[test]
    fn final_5_gc_keeps_quarantined_leases_open_attempts_and_unapplied_rebinds() {
        let d = dir();
        let mut j = CredentialJournal::open(d.path()).unwrap();
        j.record_binding(binding("bind-q", "lease-q", "sbx-q"))
            .unwrap();
        j.allocate_capture_seq("lease-q").unwrap();
        j.record_quarantined(
            "cap-q",
            QuarantineRecord {
                lease_id: "lease-q".into(),
                kid_r: "1111111111111111".into(),
            },
        )
        .unwrap();
        j.forget_binding("bind-q").unwrap();
        assert!(j.state().leases.contains_key("lease-q"));
        j.forget_quarantined(&["cap-q".into()]).unwrap();
        assert!(!j.state().leases.contains_key("lease-q"));

        j.open_or_join_teardown("sbx-open", "op-1").unwrap();
        assert!(j.state().sandboxes.contains_key("sbx-open"));

        j.record_binding(binding("bind-r", "lease-r", "sbx-r"))
            .unwrap();
        j.open_or_join_teardown("sbx-r", "op-stop").unwrap();
        j.abort_teardown_with_rebind("sbx-r", "op-stop", 7).unwrap();
        j.forget_binding("bind-r").unwrap();
        assert_eq!(j.pending_rebinds(), vec![("sbx-r".to_owned(), 7)]);
        let reopened = CredentialJournal::open(d.path()).unwrap();
        assert_eq!(reopened.pending_rebinds(), vec![("sbx-r".to_owned(), 7)]);
        j.mark_rebind_applied("sbx-r", 7).unwrap();
        // The next write collects the applied record.
        j.forget_binding("none").unwrap();
        assert!(!j.state().sandboxes.contains_key("sbx-r"));
    }

    /// A write the reader would refuse is never committed; the
    /// journal on disk and in memory stay loadable and unchanged.
    #[test]
    fn final_5_a_write_over_the_read_bound_fails_and_commits_nothing() {
        let d = dir();
        let mut j = CredentialJournal::open(d.path()).unwrap();
        j.record_binding(binding("bind-1", "lease-1", "sbx-1"))
            .unwrap();
        let mut huge = binding("bind-huge", "lease-huge", "sbx-huge");
        huge.instance_id = "i".repeat(JOURNAL_MAX_BYTES as usize + 1);
        assert!(j.record_binding(huge).is_err());
        assert!(j.binding("bind-huge").is_none());
        let reopened = CredentialJournal::open(d.path()).unwrap();
        assert!(reopened.binding("bind-1").is_some());
        assert!(reopened.binding("bind-huge").is_none());
    }

    /// Return-key acceptance-rule table: older / same-epoch same key /
    /// same-epoch substitution / newer — and the slot survives a reopen.
    #[test]
    fn key_slot_follows_the_epoch_acceptance_rule() {
        let d = dir();
        let mut j = CredentialJournal::open(d.path()).unwrap();
        assert_eq!(
            j.offer_return_key(key("1111111111111111", 1, 'A')).unwrap(),
            KeyAcceptance::Accepted { retired: None }
        );
        let r2 = key("2222222222222222", 2, 'B');
        assert_eq!(
            j.offer_return_key(r2.clone()).unwrap(),
            KeyAcceptance::Accepted {
                retired: Some(key("1111111111111111", 1, 'A'))
            }
        );
        // Delayed R1 after R2: refused as stale, slot stays R2.
        assert_eq!(
            j.offer_return_key(key("1111111111111111", 1, 'A')).unwrap(),
            KeyAcceptance::Stale { current_epoch: 2 }
        );
        assert_eq!(
            j.offer_return_key(r2.clone()).unwrap(),
            KeyAcceptance::Duplicate
        );
        // Same epoch, different kid or different key: substitution.
        for sub in [
            key("3333333333333333", 2, 'B'),
            key("2222222222222222", 2, 'C'),
        ] {
            assert_eq!(
                j.offer_return_key(sub).unwrap(),
                KeyAcceptance::Substitution { current_epoch: 2 }
            );
        }
        assert_eq!(j.key_slot(), Some(&r2));
        let reopened = CredentialJournal::open(d.path()).unwrap();
        assert_eq!(reopened.key_slot(), Some(&r2));
        assert_eq!(
            reopened.state().retired_kids.get("1111111111111111"),
            Some(&1)
        );
        // The persisted file is private.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(d.path().join(JOURNAL_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{mode:o}");
        }
    }

    #[test]
    fn capture_seq_is_durable_and_never_reused_across_reopen() {
        let d = dir();
        let mut j = CredentialJournal::open(d.path()).unwrap();
        // Sequences are allocated for bound leases (a lease record lives as
        // long as a binding names it; see the GC tests).
        j.record_binding(binding("bind-1", "lease-1", "sbx-1"))
            .unwrap();
        j.record_binding(binding("bind-2", "lease-2", "sbx-1"))
            .unwrap();
        assert_eq!(j.allocate_capture_seq("lease-1").unwrap(), 1);
        assert_eq!(j.allocate_capture_seq("lease-1").unwrap(), 2);
        assert_eq!(j.allocate_capture_seq("lease-2").unwrap(), 1);
        drop(j);
        let mut j = CredentialJournal::open(d.path()).unwrap();
        assert_eq!(j.allocate_capture_seq("lease-1").unwrap(), 3);
    }

    #[test]
    fn teardown_attempts_join_only_while_open_and_rearm_clears_captures() {
        let d = dir();
        let mut j = CredentialJournal::open(d.path()).unwrap();
        j.record_binding(binding("b1", "l1", "s1")).unwrap();
        let first = j.open_or_join_teardown("s1", "stop-1").unwrap();
        assert!(!first.joined);
        let cap = j.reserve_teardown_capture("b1", &first.attempt_id).unwrap();
        // Server expiry STOP joins the open attempt and reuses the capture.
        let joined = j.open_or_join_teardown("s1", "expiry-stop").unwrap();
        assert!(joined.joined);
        assert_eq!(joined.attempt_id, first.attempt_id);
        assert_eq!(
            j.reserve_teardown_capture("b1", &joined.attempt_id)
                .unwrap(),
            cap
        );
        // Failed user stop: abort + clear + owed re-bind in one write; the
        // next stop does not join and gets a fresh capture.
        j.abort_teardown_with_rebind("s1", "stop-1", 7).unwrap();
        assert!(j.binding("b1").unwrap().teardown.is_none());
        assert_eq!(j.refused_teardown("s1", "stop-1"), Some(7));
        assert_eq!(j.refused_teardown("s1", "stop-2"), None);
        assert_eq!(j.pending_rebinds(), vec![("s1".to_owned(), 7)]);
        j.mark_rebind_applied("s1", 7).unwrap();
        assert!(j.pending_rebinds().is_empty());
        let second = j.open_or_join_teardown("s1", "stop-2").unwrap();
        assert!(!second.joined);
        assert_ne!(second.attempt_id, first.attempt_id);
        let cap2 = j
            .reserve_teardown_capture("b1", &second.attempt_id)
            .unwrap();
        assert_ne!(cap2.capture_id, cap.capture_id);
        // Crash replay: the reopened journal has the same attempt and capture.
        let j2 = CredentialJournal::open(d.path()).unwrap();
        assert_eq!(
            j2.teardown_attempt("s1").unwrap().attempt_id,
            second.attempt_id
        );
        assert_eq!(j2.binding("b1").unwrap().teardown.as_ref(), Some(&cap2));
    }

    #[test]
    fn install_intent_precedes_installed_and_must_match() {
        let d = dir();
        let mut j = CredentialJournal::open(d.path()).unwrap();
        j.record_binding(binding("b1", "l1", "s1")).unwrap();
        assert!(j.mark_installed("b1", 3).is_err());
        j.set_install_intent(
            "b1",
            InstallIntent {
                request_id: "r1".into(),
                storage_seq: 3,
            },
        )
        .unwrap();
        assert!(j.mark_installed("b1", 4).is_err());
        j.mark_installed("b1", 3).unwrap();
        assert_eq!(j.binding("b1").unwrap().phase, BindingPhase::Active);
        // A binding id cannot be re-recorded for another lease.
        assert!(j.record_binding(binding("b1", "other", "s1")).is_err());
    }
}
