//! Credential outbox `<data>/credentials/outbox/` and its quarantine
//! `outbox/rejected/`.
//!
//! An envelope is written 0600 to a temp file, fsynced, renamed, the
//! directory fsynced, then re-read and verified ("self-verified durable").
//! Pending envelopes are the unresolved ones; a REJECTED envelope moves to
//! quarantine, where it is retained (never auto-deleted), is no longer
//! pending, is not counted toward the per-lease or outbox limits, and is
//! reported in the census `quarantined` list until the server names it in
//! `credential.quarantine.discard`. When the quarantine is full the envelope
//! stays in the outbox as unresolved (fail closed) and an alert is raised.

use anyhow::{Context, Result, bail};
use sandbox_protocol::CaptureKind;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::envelope::{self, Envelope};

pub const OUTBOX_DIR: &str = "outbox";
pub const QUARANTINE_DIR: &str = "rejected";
pub const ENVELOPE_EXT: &str = "wsco";
pub const OUTBOX_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const OUTBOX_MAX_ENVELOPES: usize = 512;
/// Invariant: ≤ 8 unresolved envelopes per lease; a 9th non-evictable one
/// is a capture failure.
pub const LEASE_MAX_UNRESOLVED: usize = 8;
pub const QUARANTINE_MAX_ENVELOPES: usize = 64;
pub const QUARANTINE_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Index entry, rebuilt from the envelope headers at open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    pub capture_id: String,
    pub lease_id: String,
    pub binding_id: String,
    pub sandbox_id: String,
    pub kid_r: String,
    pub kind: CaptureKind,
    pub capture_seq: u64,
    pub bytes: u64,
    pub digest_hex: String,
    /// REJECTED by the server but the quarantine was full: still unresolved.
    pub rejected_held: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxError {
    /// The lease already has `LEASE_MAX_UNRESOLVED` unresolved envelopes.
    LeaseFull,
    /// Global bound reached and nothing evictable remains.
    QuotaExceeded,
}

impl std::fmt::Display for OutboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LeaseFull => "lease has the maximum number of unresolved capture envelopes",
            Self::QuotaExceeded => "credential outbox quota exceeded",
        })
    }
}
impl std::error::Error for OutboxError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineOutcome {
    Quarantined,
    /// Quarantine full: the envelope stays unresolved in the outbox; alert.
    FullHeld,
}

#[derive(Debug)]
pub struct Outbox {
    dir: PathBuf,
    rejected: PathBuf,
    pending: BTreeMap<String, OutboxEntry>,
    quarantined: BTreeMap<String, OutboxEntry>,
}

fn kind_from(text: &str) -> Option<CaptureKind> {
    serde_json::from_value(serde_json::Value::String(text.to_owned())).ok()
}

fn entry_of(env: &Envelope) -> Result<OutboxEntry> {
    let aad = &env.header.aad;
    Ok(OutboxEntry {
        capture_id: aad.capture_id.clone(),
        lease_id: aad.lease_id.clone(),
        binding_id: aad.binding_id.clone(),
        sandbox_id: aad.sandbox_id.clone(),
        kid_r: env.header.kid_r.clone(),
        kind: kind_from(&aad.kind).context("unknown capture kind in envelope")?,
        capture_seq: aad.capture_seq,
        bytes: env.bytes.len() as u64,
        digest_hex: env.digest_hex(),
        rejected_held: false,
    })
}

fn file_name(capture_id: &str) -> Result<String> {
    if !sandbox_protocol::valid_credential_id(capture_id) {
        bail!("invalid capture id");
    }
    Ok(format!("{capture_id}.{ENVELOPE_EXT}"))
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn scan(dir: &Path) -> Result<BTreeMap<String, OutboxEntry>> {
    let mut out = BTreeMap::new();
    for item in fs::read_dir(dir)? {
        let path = item?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with(".tmp") {
            // An interrupted write never became durable: remove it.
            fs::remove_file(&path)?;
            continue;
        }
        if !path.is_file() || !name.ends_with(ENVELOPE_EXT) {
            continue;
        }
        if fs::metadata(&path)?.len() > sandbox_protocol::CREDENTIAL_ENVELOPE_MAX_BYTES as u64 {
            bail!("oversized credential envelope `{name}`");
        }
        let env = envelope::parse(fs::read(&path)?)
            .map_err(|_| anyhow::anyhow!("corrupt credential envelope `{name}`"))?;
        let entry = entry_of(&env)?;
        if file_name(&entry.capture_id)? != name {
            bail!("credential envelope `{name}` does not match its header");
        }
        out.insert(entry.capture_id.clone(), entry);
    }
    Ok(out)
}

impl Outbox {
    /// Opens `<credentials dir>/outbox` (and its quarantine), rebuilding the
    /// index from the self-verifying envelope headers.
    pub fn open(credentials_dir: &Path) -> Result<Self> {
        let dir = credentials_dir.join(OUTBOX_DIR);
        let rejected = dir.join(QUARANTINE_DIR);
        super::journal::private_dir(&dir)?;
        super::journal::private_dir(&rejected)?;
        Ok(Self {
            pending: scan(&dir)?,
            quarantined: scan(&rejected)?,
            dir,
            rejected,
        })
    }

    /// Unresolved envelopes (quarantined ones excluded).
    pub fn pending(&self) -> impl Iterator<Item = &OutboxEntry> {
        self.pending.values()
    }

    pub fn quarantined(&self) -> impl Iterator<Item = &OutboxEntry> {
        self.quarantined.values()
    }

    pub fn pending_for_lease(&self, lease_id: &str) -> usize {
        self.pending
            .values()
            .filter(|e| e.lease_id == lease_id)
            .count()
    }

    fn pending_bytes(&self) -> u64 {
        self.pending.values().map(|e| e.bytes).sum()
    }

    pub fn read(&self, capture_id: &str) -> Result<Envelope> {
        let path = self.dir.join(file_name(capture_id)?);
        envelope::parse(fs::read(&path)?)
            .map_err(|_| anyhow::anyhow!("corrupt credential envelope"))
    }

    /// Pre-check before any guest effect (N11): is there room for a sealed
    /// envelope of `worst_case_bytes` for `lease_id` of `kind`?
    pub fn has_room(&self, lease_id: &str, kind: CaptureKind, worst_case_bytes: u64) -> bool {
        self.plan_room(lease_id, kind, worst_case_bytes).is_ok()
    }

    /// Checkpoint envelopes to evict (oldest first) so a new one fits.
    fn plan_room(
        &self,
        lease_id: &str,
        kind: CaptureKind,
        bytes: u64,
    ) -> Result<Vec<String>, OutboxError> {
        // Newest pending checkpoint per lease only: a new checkpoint replaces
        // the lease's older pending checkpoints.
        let replaced: Vec<&OutboxEntry> = if kind == CaptureKind::Checkpoint {
            self.pending
                .values()
                .filter(|e| e.lease_id == lease_id && e.kind == CaptureKind::Checkpoint)
                .collect()
        } else {
            Vec::new()
        };
        if self.pending_for_lease(lease_id) - replaced.len() >= LEASE_MAX_UNRESOLVED {
            return Err(OutboxError::LeaseFull);
        }
        let mut evict: Vec<String> = replaced.iter().map(|e| e.capture_id.clone()).collect();
        let mut count = self.pending.len() - evict.len();
        let mut total = self.pending_bytes() - replaced.iter().map(|e| e.bytes).sum::<u64>();
        let mut candidates: Vec<&OutboxEntry> = self
            .pending
            .values()
            .filter(|e| e.kind.evictable() && !evict.contains(&e.capture_id))
            .collect();
        candidates.sort_by_key(|e| e.capture_seq);
        let mut candidates = candidates.into_iter();
        while count + 1 > OUTBOX_MAX_ENVELOPES || total + bytes > OUTBOX_MAX_BYTES {
            // Only teardown/free/expiry/recovery/login envelopes (never
            // evicted themselves) may evict other leases' checkpoints; a new
            // checkpoint that does not fit is simply not taken.
            let victim = if kind.evictable() {
                None
            } else {
                candidates.next()
            };
            let Some(victim) = victim else {
                return Err(OutboxError::QuotaExceeded);
            };
            evict.push(victim.capture_id.clone());
            count -= 1;
            total -= victim.bytes;
        }
        Ok(evict)
    }

    /// Writes `env` self-verified durable, applying checkpoint coalescing
    /// and eviction. Fails closed (nothing written) when it cannot fit.
    pub fn write_durable(&mut self, env: &Envelope) -> Result<OutboxEntry> {
        let entry = entry_of(env)?;
        if self.pending.contains_key(&entry.capture_id)
            || self.quarantined.contains_key(&entry.capture_id)
        {
            let existing = self.read(&entry.capture_id)?;
            if existing.digest != env.digest {
                bail!("a different envelope already exists for this capture");
            }
            return Ok(entry);
        }
        let evict = self.plan_room(&entry.lease_id, entry.kind, entry.bytes)?;
        let name = file_name(&entry.capture_id)?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".tmp")
            .tempfile_in(&self.dir)
            .context("create envelope temp file")?;
        tmp.write_all(&env.bytes)?;
        tmp.as_file().sync_all()?;
        tmp.persist(self.dir.join(&name))
            .map_err(|e| e.error)
            .context("rename envelope")?;
        sync_dir(&self.dir)?;
        // Self-verify: re-read and check length and digest.
        let back = self.read(&entry.capture_id)?;
        if back.digest != env.digest || back.bytes.len() != env.bytes.len() {
            let _ = fs::remove_file(self.dir.join(&name));
            bail!("credential envelope failed its post-write verification");
        }
        self.pending.insert(entry.capture_id.clone(), entry.clone());
        for victim in evict {
            self.remove_pending(&victim)?;
        }
        Ok(entry)
    }

    fn remove_pending(&mut self, capture_id: &str) -> Result<()> {
        let path = self.dir.join(file_name(capture_id)?);
        match fs::remove_file(&path) {
            Ok(()) => sync_dir(&self.dir)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).context("remove resolved envelope"),
        }
        self.pending.remove(capture_id);
        Ok(())
    }

    /// COMMITTED / UNCHANGED / authorized DISCARDED: the envelope is resolved.
    pub fn resolve(&mut self, capture_id: &str) -> Result<()> {
        self.remove_pending(capture_id)
    }

    /// REJECTED: move to quarantine (rename, fsync both directories). A full
    /// quarantine keeps the envelope unresolved in the outbox (fail closed).
    pub fn quarantine(&mut self, capture_id: &str) -> Result<QuarantineOutcome> {
        let Some(entry) = self.pending.get(capture_id).cloned() else {
            if self.quarantined.contains_key(capture_id) {
                return Ok(QuarantineOutcome::Quarantined);
            }
            bail!("unknown credential envelope");
        };
        let used: u64 = self.quarantined.values().map(|e| e.bytes).sum();
        if self.quarantined.len() >= QUARANTINE_MAX_ENVELOPES
            || used + entry.bytes > QUARANTINE_MAX_BYTES
        {
            if let Some(held) = self.pending.get_mut(capture_id) {
                held.rejected_held = true;
            }
            return Ok(QuarantineOutcome::FullHeld);
        }
        let name = file_name(capture_id)?;
        fs::rename(self.dir.join(&name), self.rejected.join(&name))
            .context("move envelope to quarantine")?;
        sync_dir(&self.rejected)?;
        sync_dir(&self.dir)?;
        self.pending.remove(capture_id);
        let mut entry = entry;
        entry.rejected_held = false;
        self.quarantined.insert(capture_id.to_owned(), entry);
        Ok(QuarantineOutcome::Quarantined)
    }

    /// `credential.quarantine.discard`: delete the named quarantined
    /// envelopes. Returns the ids actually discarded (unknown ids are not
    /// confirmed, so the server keeps asking only for real ones).
    pub fn discard_quarantined(&mut self, capture_ids: &[String]) -> Result<Vec<String>> {
        let mut done = Vec::new();
        for id in capture_ids {
            if !self.quarantined.contains_key(id) {
                continue;
            }
            match fs::remove_file(self.rejected.join(file_name(id)?)) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err).context("discard quarantined envelope"),
            }
            self.quarantined.remove(id);
            done.push(id.clone());
        }
        if !done.is_empty() {
            sync_dir(&self.rejected)?;
        }
        Ok(done)
    }
}
