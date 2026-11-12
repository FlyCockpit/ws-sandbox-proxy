//! Local storage evidence. None of these observations grants release authority
//! without the caller's journal, generation and network-cleanup fences.
use crate::RuntimeError;
use sandbox_protocol::SandboxErrorCode;

pub const STORAGE_MARKER_VOLUME: &str = "wssp-pool-marker";
pub const GIB_BYTES: u64 = 1 << 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePoolIdentity {
    pub name: String,
    pub storage_id: String,
}

impl StoragePoolIdentity {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        validate_pool_name(&self.name)?;
        if self.storage_id.len() != 32
            || !self
                .storage_id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(storage_error("invalid storage marker identity"));
        }
        Ok(())
    }
}

pub(crate) fn validate_pool_name(name: &str) -> Result<(), RuntimeError> {
    if name.is_empty()
        || name.len() > 63
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(storage_error("invalid storage pool name"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDisk {
    pub pool: StoragePoolIdentity,
    pub disk_gi_b: u32,
}
impl RootDisk {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        self.pool.validate()?;
        sandbox_protocol::vm_root_charge_gi_b(self.disk_gi_b)
            .map(|_| ())
            .map_err(|_| storage_error("invalid root disk size"))
    }
    pub fn size_bytes(&self) -> u64 {
        u64::from(self.disk_gi_b) * GIB_BYTES
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageDriver {
    Dir,
    Lvm,
    Zfs,
    Btrfs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageResources {
    total_bytes: u64,
    used_bytes: u64,
}
impl StorageResources {
    pub fn new(total_bytes: u64, used_bytes: u64) -> Result<Self, RuntimeError> {
        if total_bytes == 0 || used_bytes > total_bytes {
            return Err(storage_error("invalid storage pool resources"));
        }
        Ok(Self {
            total_bytes,
            used_bytes,
        })
    }
    pub fn total_bytes(self) -> u64 {
        self.total_bytes
    }
    pub fn used_bytes(self) -> u64 {
        self.used_bytes
    }
    pub fn free_bytes(self) -> u64 {
        self.total_bytes - self.used_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePoolObservation {
    pub pool: StoragePoolIdentity,
    pub driver: StorageDriver,
    pub resources: StorageResources,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootVolume {
    pub instance_name: String,
    /// Invalid or unavailable size evidence must not erase an orphan root.
    pub size_bytes: Option<u64>,
}

/// A completed walk with a fresh marker/resources recheck after enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRootCensus {
    pub observation: StoragePoolObservation,
    pub roots: Vec<RootVolume>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalUsage {
    /// Credit A, always <= the caller's reconstructed commitments C.
    pub charged_bytes: u64,
    pub trusted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAbsenceProof {
    pub(crate) pool: StoragePoolIdentity,
    pub(crate) instance_name: String,
}
impl RootAbsenceProof {
    pub fn pool(&self) -> &StoragePoolIdentity {
        &self.pool
    }
    pub fn instance_name(&self) -> &str {
        &self.instance_name
    }
}

pub(crate) fn storage_error(message: &str) -> RuntimeError {
    RuntimeError::new(SandboxErrorCode::Internal, message)
}

pub(crate) fn root_mismatch() -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::VmSizeMismatch,
        "pinned root disk differs; refusing storage access",
    )
}
