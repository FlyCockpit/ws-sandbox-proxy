//! Verified root growth at create: the daemon's fixed, host-pushed root
//! helper (`root-grow-helper.py`) grows the guest's root partition and
//! filesystem to the sandbox's disk, and reports what it measured; this
//! module decides. A sandbox created larger than its image's root must not
//! start with a root that never grew, so a create whose root did not reach
//! its disk fails `guest_unavailable` with reason `root_disk_not_grown` (the
//! VM is destroyed like any create readiness failure).
//!
//! - wssp owns growth (the community prep turns cloud-init's off), so it
//!   never depends on cloud-init running in an image.
//! - Create only: a sandbox's disk never changes after create, so start and
//!   reconnect have nothing to grow, and a start never fails on it.
//! - Hygiene, not a security control: the record is guest-attested (a guest
//!   root can lie about its own disk). It never feeds capacity accounting.
//! - The record is integers and constant tokens only, never guest text.
use std::time::Duration;

use sandbox_protocol::{ReadinessFailureReason, SandboxErrorCode};

use super::client::{BoundInstance, IncusClient, IncusCommandOutput};
use crate::error::RuntimeError;

/// The helper source, pushed per exec (never an in-image copy).
pub(super) const ROOT_GROW_HELPER: &str = include_str!("root-grow-helper.py");
/// One helper exec: `growpart`, an online filesystem grow and re-measures,
/// each bounded inside the helper (larger disks get a longer resize budget).
pub(super) const ROOT_GROW_DEADLINE: Duration = Duration::from_secs(150);

const MIB: u64 = 1 << 20;
/// A grown partition ends within this of its disk's end (growpart's 1 MiB
/// alignment plus the 33-sector backup GPT).
const PARTITION_TAIL_MAX: u64 = 2 * MIB;
/// A grown ext4/xfs filesystem fills its partition to within this (block
/// rounding, xfs's last allocation group).
const FS_TAIL_MAX: u64 = 4 * MIB;
/// btrfs keeps a little more unallocated at the device's end.
const BTRFS_TAIL_MAX: u64 = 16 * MIB;

/// Seconds of the exec deadline the helper leaves unused, so its record
/// always arrives before the daemon stops waiting.
const BUDGET_MARGIN_SECS: u64 = 5;

/// `python3 -I -S -B -c <helper> grow <nonce> <expected-disk-bytes>
/// <budget-seconds>`, every field host-derived. The helper bounds its tools
/// and settle loop by the budget and still prints its measurement.
pub(super) fn root_grow_argv(nonce: &str, disk_bytes: u64, deadline: Duration) -> Vec<String> {
    vec![
        "python3".into(),
        "-I".into(),
        "-S".into(),
        "-B".into(),
        "-c".into(),
        ROOT_GROW_HELPER.into(),
        "grow".into(),
        nonce.into(),
        disk_bytes.to_string(),
        deadline
            .as_secs()
            .saturating_sub(BUDGET_MARGIN_SECS)
            .max(1)
            .to_string(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RootLayout {
    /// The root filesystem is on a partition of the disk.
    Partition,
    /// The root filesystem is on the whole disk.
    Whole,
    /// Device mapper, LVM, LUKS, md or anything else: not grown by wssp.
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RootFsType {
    Ext4,
    Xfs,
    Btrfs,
    Other,
}

/// What the helper measured after growing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RootRecord {
    pub disk_bytes: u64,
    pub part_end_bytes: u64,
    pub part_bytes: u64,
    pub fstype: RootFsType,
    /// The filesystem's own size (superblock); 0 when unreadable.
    pub fs_bytes: u64,
    pub layout: RootLayout,
    /// `statvfs("/")` total (excludes filesystem overhead).
    pub statvfs_bytes: u64,
}

/// Strictly parse the single stderr record (empty stdout, exit 0). Anything
/// else (including the helper's own `error` record) is `None`.
pub(super) fn parse_root_record(nonce: &str, out: &IncusCommandOutput) -> Option<RootRecord> {
    if out.exit_code != 0 || !out.stdout.is_empty() {
        return None;
    }
    let body = out
        .stderr
        .strip_prefix(&format!("WSSP_ROOT {nonce} "))?
        .strip_suffix('\n')?;
    if body.contains('\n') {
        return None;
    }
    let fields: Vec<&str> = body.split(' ').collect();
    let [disk, part_end, part, fstype, fs, layout, statvfs] = fields[..] else {
        return None;
    };
    let int = |field: &str| -> Option<u64> {
        if field.is_empty() || field.len() > 20 || !field.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        field.parse().ok()
    };
    Some(RootRecord {
        disk_bytes: int(disk)?,
        part_end_bytes: int(part_end)?,
        part_bytes: int(part)?,
        fstype: match fstype {
            "ext4" => RootFsType::Ext4,
            "xfs" => RootFsType::Xfs,
            "btrfs" => RootFsType::Btrfs,
            "other" => RootFsType::Other,
            _ => return None,
        },
        fs_bytes: int(fs)?,
        layout: match layout {
            "partition" => RootLayout::Partition,
            "whole" => RootLayout::Whole,
            "unsupported" => RootLayout::Unsupported,
            _ => return None,
        },
        statvfs_bytes: int(statvfs)?,
    })
}

/// Whether the root filled the sandbox's disk (`expected` bytes). Ok, or the
/// constant diagnostic label of the failed check.
pub(super) fn decide_root(expected: u64, record: Option<RootRecord>) -> Result<(), &'static str> {
    let Some(r) = record else {
        return Err("no_record");
    };
    // Nothing wssp can grow or measure exactly (for device mapper the
    // helper's sizes are the logical device's, not the disk's): accept a
    // root that already uses (nearly) the whole configured disk, as an image
    // registered at its native size does, and refuse one that clearly did
    // not grow.
    if r.layout == RootLayout::Unsupported || r.fstype == RootFsType::Other {
        return if r.statvfs_bytes.saturating_mul(10) >= expected.saturating_mul(9) {
            Ok(())
        } else {
            Err("layout_unsupported")
        };
    }
    // The guest sees a disk smaller than the one wssp configured. Never `==`:
    // a storage driver may round a volume up.
    if r.disk_bytes < expected {
        return Err("disk_small");
    }
    if r.part_end_bytes > r.disk_bytes || r.part_bytes > r.part_end_bytes {
        return Err("record_invalid");
    }
    if r.layout == RootLayout::Partition && r.disk_bytes - r.part_end_bytes > PARTITION_TAIL_MAX {
        return Err("partition_not_grown");
    }
    let tail = if r.fstype == RootFsType::Btrfs {
        BTRFS_TAIL_MAX
    } else {
        FS_TAIL_MAX
    };
    if r.fs_bytes == 0 || r.fs_bytes.saturating_add(tail) < r.part_bytes {
        return Err("fs_not_grown");
    }
    Ok(())
}

fn not_grown(label: &'static str) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::GuestUnavailable,
        format!("guest root did not grow to the sandbox disk ({label})"),
    )
    .with_readiness_reason(ReadinessFailureReason::RootDiskNotGrown)
    .with_diagnostic(label)
}

/// Fence and cancellation codes keep their own retryable meaning.
fn keeps_code(error: &RuntimeError) -> bool {
    matches!(
        error.code,
        SandboxErrorCode::IdempotencyConflict
            | SandboxErrorCode::UnknownOutcome
            | SandboxErrorCode::Cancelled
            | SandboxErrorCode::SandboxNotRunning
    ) || error.is_enforcement_inconclusive()
}

impl IncusClient {
    /// One root-grow helper exec as guest root in the bound instance,
    /// decided per [`decide_root`] against `disk_bytes`. Fence and
    /// cancellation errors propagate.
    pub(super) fn guest_root_grow_step(
        &self,
        bound: &BoundInstance,
        disk_bytes: u64,
    ) -> Result<(), RuntimeError> {
        let nonce = super::client::random_nonce()?;
        // Inside readiness the client's agent timeout is the remaining
        // readiness budget; the helper never outlives it.
        let deadline = ROOT_GROW_DEADLINE.min(self.agent_timeout);
        let argv = root_grow_argv(&nonce, disk_bytes, deadline);
        let record = match self.exec_root_helper_bounded(bound, &argv, deadline) {
            Ok(out) => parse_root_record(&nonce, &out),
            Err(error) => {
                let error = error.into_error();
                if keeps_code(&error) {
                    return Err(error);
                }
                None
            }
        };
        decide_root(disk_bytes, record).map_err(not_grown)
    }
}

#[cfg(test)]
#[path = "root_grow_tests.rs"]
mod tests;
