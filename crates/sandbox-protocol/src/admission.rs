//! Bounded host image-availability observations. Scheduling enforcement is activated separately.
use serde::{Deserialize, Serialize};

pub const AVAILABILITY_PAGE_MAX: usize = 100;
pub const AVAILABILITY_TOTAL_MAX: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AvailabilityBinding {
    pub revision_id: String,
    pub artifact: String,
    pub manifest_hash: String,
    pub architecture: String,
}
impl AvailabilityBinding {
    pub fn valid(&self) -> bool {
        !self.revision_id.is_empty()
            && self.revision_id.len() <= 128
            && self.artifact.len() == 71
            && self.artifact.starts_with("sha256:")
            && self.artifact[7..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.manifest_hash.len() == 64
            && self
                .manifest_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && matches!(self.architecture.as_str(), "x86_64" | "aarch64")
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityStatus {
    Present,
    Missing,
    Rejected,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AvailabilityVerdict {
    pub binding: AvailabilityBinding,
    pub status: AvailabilityStatus,
    /// Present entries only: compressed image size and format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

pub fn valid_availability_page(
    request_id: &str,
    epoch: u64,
    page: u64,
    bindings: &[AvailabilityBinding],
) -> bool {
    valid_availability_fence(request_id, epoch, page)
        && bindings.len() <= AVAILABILITY_PAGE_MAX
        && bindings.iter().all(AvailabilityBinding::valid)
        && bindings.iter().enumerate().all(|(i, b)| {
            bindings[..i]
                .iter()
                .all(|prior| prior.revision_id != b.revision_id)
        })
}

pub fn valid_availability_fence(request_id: &str, epoch: u64, page: u64) -> bool {
    !request_id.is_empty()
        && request_id.len() <= 128
        && epoch > 0
        && epoch <= i32::MAX as u64
        && page < AVAILABILITY_TOTAL_MAX / AVAILABILITY_PAGE_MAX as u64
}
