//! Pure guest allocation policy. The bounds and fixtures are shared with TS.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Number;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid VM size or capacity")]
pub struct VmSizeError;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmSizeLimits {
    pub cpu_count_min: u32,
    pub cpu_count_max: u32,
    pub cpu_count_default: u32,
    pub memory_mi_b_min: u32,
    pub memory_mi_b_max: u32,
    pub memory_mi_b_default: u32,
    pub memory_mi_b_step: u32,
    pub host_memory_budget_mi_b_max: u32,
    pub disk_gi_b_min: u32,
    pub disk_gi_b_max: u32,
    pub disk_gi_b_default: u32,
    pub host_vcpu_budget_min: u32,
    pub host_vcpu_budget_max: u32,
    pub host_vcpu_budget_default_threads_multiplier: u32,
    pub vm_host_overhead_mi_b: u32,
    pub host_memory_reserve: HostMemoryReserve,
    pub root_disk_overhead_gi_b: u32,
    pub default_storage_capacity_percent: u32,
    pub default_storage_headroom_percent: u32,
    pub host_managed_sandbox_ceiling: u32,
    pub storage_pool_max: usize,
    pub storage_capacity_gi_b_max: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostMemoryReserve {
    pub minimum_mi_b: u32,
    pub percent: u32,
}

/// Manifest initialization is fallible; malformed bounds never panic or admit.
pub fn vm_size_limits() -> Result<&'static VmSizeLimits, VmSizeError> {
    static LIMITS: OnceLock<Result<VmSizeLimits, VmSizeError>> = OnceLock::new();
    LIMITS
        .get_or_init(|| {
            let limits: VmSizeLimits = serde_json::from_str(include_str!(
                "../../../packages/sandbox-contracts/src/vm-size-limits.json"
            ))
            .map_err(|_| VmSizeError)?;
            if limits.disk_gi_b_min == 0
                || limits.disk_gi_b_default < limits.disk_gi_b_min
                || limits.disk_gi_b_default > limits.disk_gi_b_max
                || limits.host_vcpu_budget_min == 0
                || limits.host_vcpu_budget_max < limits.host_vcpu_budget_min
                || limits.host_vcpu_budget_default_threads_multiplier == 0
                || limits.host_memory_reserve.percent > 100
                || limits.default_storage_capacity_percent > 100
                || limits.default_storage_headroom_percent > 100
                || limits.host_managed_sandbox_ceiling == 0
                || limits.storage_pool_max == 0
                || limits.cpu_count_min == 0
                || limits.cpu_count_min > limits.cpu_count_default
                || limits.cpu_count_default > limits.cpu_count_max
                || limits.memory_mi_b_step == 0
                || limits.memory_mi_b_min == 0
                || limits.memory_mi_b_min > limits.memory_mi_b_default
                || limits.memory_mi_b_default > limits.memory_mi_b_max
                || limits.memory_mi_b_max > limits.host_memory_budget_mi_b_max
                || !limits
                    .memory_mi_b_default
                    .is_multiple_of(limits.memory_mi_b_step)
            {
                return Err(VmSizeError);
            }
            Ok(limits)
        })
        .as_ref()
        .map_err(|_| VmSizeError)
}

// JSON 1, 1.0 and 1e0 have the same meaning in TS. Reject fractions, negative,
// unsafe and overflowing values before the bounded integer conversion.
fn integer(value: Number) -> Result<u32, VmSizeError> {
    let number = value.as_f64().ok_or(VmSizeError)?;
    if !number.is_finite()
        || number.fract() != 0.0
        || !(0.0..=f64::from(u32::MAX)).contains(&number)
    {
        return Err(VmSizeError);
    }
    Ok(number as u32)
}

fn optional_number<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Number>, D::Error> {
    Number::deserialize(deserializer).map(Some)
}

pub(crate) fn optional_dimension<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u32>, D::Error> {
    let number = Number::deserialize(deserializer)?;
    integer(number).map(Some).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "serde_json::Value")]
pub struct VmSize {
    pub cpu_count: u32,
    pub memory_mi_b: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawSize {
    cpu_count: Number,
    memory_mi_b: Number,
}
impl TryFrom<serde_json::Value> for VmSize {
    type Error = VmSizeError;
    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        if !value.is_object() {
            return Err(VmSizeError);
        }
        let raw: RawSize = serde_json::from_value(value).map_err(|_| VmSizeError)?;
        Self::try_from(raw)
    }
}
impl TryFrom<RawSize> for VmSize {
    type Error = VmSizeError;
    fn try_from(raw: RawSize) -> Result<Self, Self::Error> {
        Self::new(integer(raw.cpu_count)?, integer(raw.memory_mi_b)?)
    }
}
impl VmSize {
    pub fn new(cpu_count: u32, memory_mi_b: u32) -> Result<Self, VmSizeError> {
        let limits = vm_size_limits()?;
        if !(limits.cpu_count_min..=limits.cpu_count_max).contains(&cpu_count)
            || !(limits.memory_mi_b_min..=limits.memory_mi_b_max).contains(&memory_mi_b)
            || !memory_mi_b.is_multiple_of(limits.memory_mi_b_step)
        {
            return Err(VmSizeError);
        }
        Ok(Self {
            cpu_count,
            memory_mi_b,
        })
    }
    pub fn defaults() -> Result<Self, VmSizeError> {
        let limits = vm_size_limits()?;
        Self::new(limits.cpu_count_default, limits.memory_mi_b_default)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "serde_json::Value")]
pub struct VmSizeOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_mi_b: Option<u32>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawOverrides {
    #[serde(default, deserialize_with = "optional_number")]
    cpu_count: Option<Number>,
    #[serde(default, deserialize_with = "optional_number")]
    memory_mi_b: Option<Number>,
}
impl TryFrom<serde_json::Value> for VmSizeOverrides {
    type Error = VmSizeError;
    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        if !value.is_object() {
            return Err(VmSizeError);
        }
        let raw: RawOverrides = serde_json::from_value(value).map_err(|_| VmSizeError)?;
        Self::try_from(raw)
    }
}
impl TryFrom<RawOverrides> for VmSizeOverrides {
    type Error = VmSizeError;
    fn try_from(raw: RawOverrides) -> Result<Self, Self::Error> {
        let value = Self {
            cpu_count: raw.cpu_count.map(integer).transpose()?,
            memory_mi_b: raw.memory_mi_b.map(integer).transpose()?,
        };
        value.resolve(VmSize::defaults()?)?;
        Ok(value)
    }
}
impl VmSizeOverrides {
    pub fn resolve(self, revision: VmSize) -> Result<VmSize, VmSizeError> {
        VmSize::new(revision.cpu_count, revision.memory_mi_b)?;
        VmSize::new(
            self.cpu_count.unwrap_or(revision.cpu_count),
            self.memory_mi_b.unwrap_or(revision.memory_mi_b),
        )
    }
    pub fn revision_defaults(self) -> Result<VmSize, VmSizeError> {
        self.resolve(VmSize::defaults()?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "serde_json::Value")]
pub struct VmCapacity {
    pub memory_budget_mi_b: u32,
    pub max_cpu_count: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCapacity {
    memory_budget_mi_b: Number,
    max_cpu_count: Number,
}
impl TryFrom<serde_json::Value> for VmCapacity {
    type Error = VmSizeError;
    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        if !value.is_object() {
            return Err(VmSizeError);
        }
        let raw: RawCapacity = serde_json::from_value(value).map_err(|_| VmSizeError)?;
        Self::try_from(raw)
    }
}
impl TryFrom<RawCapacity> for VmCapacity {
    type Error = VmSizeError;
    fn try_from(raw: RawCapacity) -> Result<Self, Self::Error> {
        Self::new(
            integer(raw.memory_budget_mi_b)?,
            integer(raw.max_cpu_count)?,
        )
    }
}
impl VmCapacity {
    pub fn new(memory_budget_mi_b: u32, max_cpu_count: u32) -> Result<Self, VmSizeError> {
        let limits = vm_size_limits()?;
        if !(limits.memory_mi_b_min..=limits.host_memory_budget_mi_b_max)
            .contains(&memory_budget_mi_b)
            || !memory_budget_mi_b.is_multiple_of(limits.memory_mi_b_step)
            || !(limits.cpu_count_min..=limits.cpu_count_max).contains(&max_cpu_count)
        {
            return Err(VmSizeError);
        }
        Ok(Self {
            memory_budget_mi_b,
            max_cpu_count,
        })
    }
    pub fn max_memory_mi_b(self) -> Result<u32, VmSizeError> {
        Self::new(self.memory_budget_mi_b, self.max_cpu_count)?;
        Ok(self
            .memory_budget_mi_b
            .saturating_sub(vm_size_limits()?.vm_host_overhead_mi_b)
            .min(vm_size_limits()?.memory_mi_b_max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Deserialize)]
    struct Case {
        name: String,
        kind: String,
        input: serde_json::Value,
        valid: bool,
        expected: Option<serde_json::Value>,
    }
    #[test]
    fn vm_size_ts_rust_parity() {
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../fixtures/vm_size_cases.json")).unwrap();
        for case in cases {
            let result = match case.kind.as_str() {
                "size" => serde_json::from_value::<VmSize>(case.input)
                    .map(|v| serde_json::to_value(v).unwrap()),
                "overrides" => serde_json::from_value::<VmSizeOverrides>(case.input)
                    .map(|v| serde_json::to_value(v).unwrap()),
                "revision" => serde_json::from_value::<VmSizeOverrides>(case.input)
                    .map(|v| serde_json::to_value(v.revision_defaults().unwrap()).unwrap()),
                "capacity" => serde_json::from_value::<VmCapacity>(case.input)
                    .map(|v| serde_json::to_value(v).unwrap()),
                _ => panic!("unknown fixture kind"),
            };
            assert_eq!(result.is_ok(), case.valid, "{}", case.name);
            if let Some(expected) = case.expected {
                assert_eq!(result.unwrap(), expected, "{}", case.name);
            }
        }
    }
    #[test]
    fn independently_resolves_and_derives_without_cpu_sum_or_overflow() {
        let revision = VmSize::new(8, 4096).unwrap();
        let overrides: VmSizeOverrides = serde_json::from_str(r#"{"memoryMiB":2048}"#).unwrap();
        assert_eq!(
            overrides.resolve(revision).unwrap(),
            VmSize::new(8, 2048).unwrap()
        );
        assert_eq!(
            VmCapacity::new(512, 32).unwrap().max_memory_mi_b().unwrap(),
            192
        );
        assert_eq!(
            VmCapacity::new(16777216, 1)
                .unwrap()
                .max_memory_mi_b()
                .unwrap(),
            65536
        );
        assert!(VmSize::new(u32::MAX, u32::MAX).is_err());
        assert!(VmCapacity::new(u32::MAX, u32::MAX).is_err());
    }
}

/// Shared policy helpers; B3/B4 route admission/detection through these at cutover.
pub fn vm_live_memory_charge_mi_b(memory: u32) -> Result<u32, VmSizeError> {
    VmSize::new(vm_size_limits()?.cpu_count_min, memory)?;
    memory
        .checked_add(vm_size_limits()?.vm_host_overhead_mi_b)
        .ok_or(VmSizeError)
}
pub fn vm_root_charge_gi_b(disk: u32) -> Result<u32, VmSizeError> {
    let limits = vm_size_limits()?;
    if !(limits.disk_gi_b_min..=limits.disk_gi_b_max).contains(&disk) {
        return Err(VmSizeError);
    }
    disk.checked_add(limits.root_disk_overhead_gi_b)
        .ok_or(VmSizeError)
}
pub fn host_vcpu_budget_default(threads: u32) -> Result<u32, VmSizeError> {
    let limits = vm_size_limits()?;
    let budget = threads
        .checked_mul(limits.host_vcpu_budget_default_threads_multiplier)
        .ok_or(VmSizeError)?;
    if !(limits.host_vcpu_budget_min..=limits.host_vcpu_budget_max).contains(&budget) {
        return Err(VmSizeError);
    }
    Ok(budget)
}
pub fn host_memory_reserve_bytes(total: u64) -> Result<u64, VmSizeError> {
    let limits = vm_size_limits()?;
    let percentage =
        (u128::from(total) * u128::from(limits.host_memory_reserve.percent)).div_ceil(100);
    u64::try_from(percentage.max(u128::from(limits.host_memory_reserve.minimum_mi_b) * 1024 * 1024))
        .map_err(|_| VmSizeError)
}
pub fn host_memory_budget_from_bytes(total: u64) -> Result<u64, VmSizeError> {
    let limits = vm_size_limits()?;
    let mib = 1024_u64 * 1024;
    let reserve = host_memory_reserve_bytes(total)?;
    Ok(
        total.saturating_sub(reserve) / (mib * u64::from(limits.memory_mi_b_step))
            * u64::from(limits.memory_mi_b_step),
    )
}

#[cfg(test)]
mod capacity_policy_tests {
    use super::*;
    #[test]
    fn capacity_policy_defaults_rounding_and_checked_charges() {
        assert_eq!(vm_live_memory_charge_mi_b(512).unwrap(), 832);
        assert_eq!(vm_root_charge_gi_b(32).unwrap(), 33);
        assert_eq!(host_vcpu_budget_default(32).unwrap(), 64);
        assert!(host_vcpu_budget_default(0).is_err());
        assert!(host_vcpu_budget_default(u32::MAX).is_err());
        assert_eq!(
            host_memory_budget_from_bytes(124 * 1024 * 1024 * 1024).unwrap(),
            95232
        );
        assert_eq!(
            host_memory_budget_from_bytes(4 * 1024 * 1024 * 1024 - 1).unwrap(),
            0
        );
        assert_eq!(host_memory_budget_from_bytes(1024).unwrap(), 0);
        assert!(
            host_memory_budget_from_bytes(u64::MAX).unwrap()
                > u64::from(vm_size_limits().unwrap().host_memory_budget_mi_b_max)
        );
    }
}
