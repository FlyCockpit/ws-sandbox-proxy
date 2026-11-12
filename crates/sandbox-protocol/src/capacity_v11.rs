//! Strict staged capacity/storage shapes, deliberately absent from negotiation and WireCodes.
use crate::vm_size::{VmCapacity, VmSize, VmSizeError, vm_size_limits};
use serde::{Deserialize, Serialize};

fn scalar(v: u64) -> bool {
    v <= 9_007_199_254_740_991
}
fn id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
fn name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 63
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

fn wire_name(field: &str) -> String {
    let field = field.strip_prefix("r#").unwrap_or(field);
    let mut out = String::new();
    let mut upper = false;
    for c in field.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.push(c.to_ascii_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}
fn normalize_numbers(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => fields.values_mut().for_each(normalize_numbers),
        serde_json::Value::Array(values) => values.iter_mut().for_each(normalize_numbers),
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64()
                && (0.0..=9_007_199_254_740_991.0).contains(&f)
                && f.fract() == 0.0
            {
                *n = serde_json::Number::from(f as u64);
            }
        }
        _ => {}
    }
}
// One field definition for public serialization and private strict deserialization.
macro_rules! checked {
    ($public:ident, $raw:ident, { $( $field:ident : $ty:ty ),* $(,)? }, $v:ident, $valid:expr) => {
        checked!($public, $raw, { $($field: $ty),* }, optional {}, $v, $valid);
    };
    // `optional` fields may be absent (their default) and are never encoded
    // at their default, so older peers' frames stay byte-identical.
    ($public:ident, $raw:ident, { $( $field:ident : $ty:ty ),* $(,)? }, optional { $( $ofield:ident : $oty:ty ),* $(,)? }, $v:ident, $valid:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase", try_from = "serde_json::Value")]
        pub struct $public {
            $(pub $field: $ty,)*
            $(#[serde(default, skip_serializing_if = "is_default")] pub $ofield: $oty,)*
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct $raw { $($field: $ty,)* $(#[serde(default)] $ofield: $oty,)* }
        impl TryFrom<serde_json::Value> for $public {
            type Error = VmSizeError;
            fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
                let mut value = value;
                normalize_numbers(&mut value);
                // Nullable scalar fields are required, rather than silently omitted.
                let object = value.as_object().ok_or(VmSizeError)?;
                $(if !object.contains_key(&wire_name(stringify!($field))) { return Err(VmSizeError); })*
                let raw: $raw = serde_json::from_value(value).map_err(|_| VmSizeError)?;
                let $v = Self { $($field: raw.$field,)* $($ofield: raw.$ofield,)* };
                if $valid { Ok($v) } else { Err(VmSizeError) }
            }
        }
    }
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

checked!(VmSizeV11, RawVmSizeV11, {
    cpu_count: u32,
    memory_mi_b: u32,
    disk_gi_b: u32,
}, v, VmSize::new(v.cpu_count, v.memory_mi_b).is_ok() && crate::vm_size::vm_root_charge_gi_b(v.disk_gi_b).is_ok());

impl VmSizeV11 {
    pub fn defaults() -> Result<Self, VmSizeError> {
        let l = vm_size_limits()?;
        Ok(Self {
            cpu_count: l.cpu_count_default,
            memory_mi_b: l.memory_mi_b_default,
            disk_gi_b: l.disk_gi_b_default,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "serde_json::Value")]
pub struct VmSizeOverridesV11 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_mi_b: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_gi_b: Option<u32>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawOverrides {
    #[serde(default, deserialize_with = "crate::vm_size::optional_dimension")]
    cpu_count: Option<u32>,
    #[serde(default, deserialize_with = "crate::vm_size::optional_dimension")]
    memory_mi_b: Option<u32>,
    #[serde(default, deserialize_with = "crate::vm_size::optional_dimension")]
    disk_gi_b: Option<u32>,
}
impl TryFrom<serde_json::Value> for VmSizeOverridesV11 {
    type Error = VmSizeError;
    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        if !value.is_object() {
            return Err(VmSizeError);
        }
        let raw: RawOverrides = serde_json::from_value(value).map_err(|_| VmSizeError)?;
        let value = Self {
            cpu_count: raw.cpu_count,
            memory_mi_b: raw.memory_mi_b,
            disk_gi_b: raw.disk_gi_b,
        };
        value.clone().resolve(VmSizeV11::defaults()?)?;
        Ok(value)
    }
}
impl VmSizeOverridesV11 {
    pub fn resolve(self, revision: VmSizeV11) -> Result<VmSizeV11, VmSizeError> {
        VmSize::new(revision.cpu_count, revision.memory_mi_b)?;
        crate::vm_size::vm_root_charge_gi_b(revision.disk_gi_b)?;
        let value = VmSizeV11 {
            cpu_count: self.cpu_count.unwrap_or(revision.cpu_count),
            memory_mi_b: self.memory_mi_b.unwrap_or(revision.memory_mi_b),
            disk_gi_b: self.disk_gi_b.unwrap_or(revision.disk_gi_b),
        };
        VmSize::new(value.cpu_count, value.memory_mi_b)?;
        crate::vm_size::vm_root_charge_gi_b(value.disk_gi_b)?;
        Ok(value)
    }
}

checked!(VmCapacityV11, RawVmCapacityV11, {
    memory_budget_mi_b: u32,
    max_cpu_count: u32,
    vcpu_budget: u32,
}, v, VmCapacity::new(v.memory_budget_mi_b, v.max_cpu_count).is_ok() && vm_size_limits().is_ok_and(|l| (l.host_vcpu_budget_min..=l.host_vcpu_budget_max).contains(&v.vcpu_budget)));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapacityReason {
    Ram,
    Vcpu,
    Disk,
    Storage,
    Ceiling,
    /// One sandbox holds the most non-terminal `command.run` receipts a host
    /// keeps for it (`max(64, max_concurrent_commands)`); stopping the
    /// sandbox frees them.
    #[serde(rename = "sandbox_receipts")]
    SandboxReceipts,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageHealth {
    Healthy,
    Unavailable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageReason {
    Missing,
    Identity,
    Permission,
    Unsupported,
    Io,
    Incomplete,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapacitySource {
    Implicit,
    Explicit,
}

fn valid_usage(total: Option<u64>, used: Option<u64>, free: Option<u64>) -> bool {
    match (total, used, free) {
        (None, None, None) => true,
        (Some(t), Some(u), Some(f)) => scalar(t) && t > 0 && u <= t && f == t - u,
        _ => false,
    }
}

checked!(StorageHealthV11, RawStorageHealthV11, {
    name: String,
    marker: String,
    health: StorageHealth,
    reason: Option<StorageReason>,
    total_bytes: Option<u64>,
    used_bytes: Option<u64>,
    free_bytes: Option<u64>,
}, v, name(&v.name) && id(&v.marker) && valid_usage(v.total_bytes, v.used_bytes, v.free_bytes));

checked!(StoragePoolV11, RawStoragePoolV11, {
    name: String,
    marker: String,
    health: StorageHealth,
    reason: Option<StorageReason>,
    total_bytes: Option<u64>,
    used_bytes: Option<u64>,
    free_bytes: Option<u64>,
    capacity_gi_b: u32,
    total_based_capacity_gi_b: Option<u64>,
    capacity_source: CapacitySource,
    derivation_total_bytes: Option<u64>,
    derivation_free_bytes: Option<u64>,
    derivation_committed_bytes: Option<u64>,
    derivation_actual_bytes: Option<u64>,
    derivation_headroom_bytes: Option<u64>,
    implicit_ceiling_gi_b: Option<u64>,
    draining: bool,
}, v, name(&v.name) && id(&v.marker) && valid_usage(v.total_bytes, v.used_bytes, v.free_bytes) && v.valid_derivation() && vm_size_limits().is_ok_and(|l| v.capacity_gi_b <= l.storage_capacity_gi_b_max));

impl StoragePoolV11 {
    fn valid_derivation(&self) -> bool {
        let inputs = [
            self.total_based_capacity_gi_b,
            self.derivation_total_bytes,
            self.derivation_free_bytes,
            self.derivation_committed_bytes,
            self.derivation_actual_bytes,
            self.derivation_headroom_bytes,
            self.implicit_ceiling_gi_b,
        ];
        if self.capacity_source == CapacitySource::Explicit {
            return self.capacity_gi_b > 0 && inputs.iter().all(Option::is_none);
        }
        if let [
            Some(b),
            Some(t),
            Some(f),
            Some(c),
            Some(a),
            Some(h),
            Some(p),
        ] = inputs
        {
            inputs.into_iter().flatten().all(scalar)
                && t > 0
                && f <= t
                && a <= c
                && h <= t
                && u64::from(self.capacity_gi_b) <= b.min(p)
        } else {
            false
        }
    }
}
fn unique_pools<'a>(pools: impl IntoIterator<Item = (&'a str, &'a str)>) -> bool {
    let mut names = std::collections::BTreeSet::new();
    let mut markers = std::collections::BTreeSet::new();
    pools
        .into_iter()
        .all(|(n, m)| names.insert(n) && markers.insert(m))
}

checked!(HostStaticCapacityV11, RawHostStaticCapacityV11, {
    vm_capacity: VmCapacityV11,
    storage_pools: Vec<StoragePoolV11>,
}, v, vm_size_limits().is_ok_and(|l| v.storage_pools.len() <= l.storage_pool_max) && unique_pools(v.storage_pools.iter().map(|p| (p.name.as_str(), p.marker.as_str()))));

checked!(HostInventoryV11, RawHostInventoryV11, {
    host_id: String,
    schedulable: bool,
    sandbox_count: u32,
}, v, !v.host_id.is_empty() && v.host_id.chars().count() <= 128 && vm_size_limits().is_ok_and(|l| v.sandbox_count <= l.host_managed_sandbox_ceiling));

checked!(PinnedAllocationV11, RawPinnedAllocationV11, {
    cpu_count: u32,
    memory_mi_b: u32,
    disk_gi_b: u32,
    storage_pool_name: String,
    storage_marker: String,
    charged_memory_mi_b: u32,
    charged_vcpu: u32,
    root_charge_gi_b: u32,
}, v, VmSize::new(v.cpu_count, v.memory_mi_b).is_ok() && crate::vm_size::vm_root_charge_gi_b(v.disk_gi_b).is_ok() && name(&v.storage_pool_name) && id(&v.storage_marker) && v.charged_memory_mi_b >= v.memory_mi_b && v.charged_memory_mi_b <= i32::MAX as u32 && v.charged_vcpu == v.cpu_count && v.root_charge_gi_b >= v.disk_gi_b && v.root_charge_gi_b <= i32::MAX as u32);

checked!(HostAdmissionV11, RawHostAdmissionV11, {
    r#type: String,
    journal_id: String,
    connection_epoch: u32,
    runtime_kind: crate::RuntimeKind,
    schedulable: bool,
    egress_policy: bool,
    terminal: bool,
    image: Option<crate::ImageAdmissionV11>,
    vm_capacity: VmCapacityV11,
    storage_pools: Vec<StoragePoolV11>,
}, v, v.r#type == "host.admission" && v.image.as_ref().is_none_or(crate::ImageAdmissionV11::is_valid) && crate::control::valid_journal_identity(&v.journal_id) && v.connection_epoch > 0 && v.connection_epoch <= i32::MAX as u32 && vm_size_limits().is_ok_and(|l| v.storage_pools.len() <= l.storage_pool_max) && unique_pools(v.storage_pools.iter().map(|p| (p.name.as_str(), p.marker.as_str()))));

checked!(HostInventoryUpdateV11, RawHostInventoryUpdateV11, {
    r#type: String,
    id: String,
    connection_epoch: u32,
    observation_sequence: u64,
    inventory: HostInventoryV11,
    storage_pools: Vec<StorageHealthV11>,
}, v, v.r#type == "inventory.update" && !v.id.is_empty() && v.id.chars().count() <= 128 && v.connection_epoch > 0 && v.connection_epoch <= i32::MAX as u32 && scalar(v.observation_sequence) && vm_size_limits().is_ok_and(|l| v.storage_pools.len() <= l.storage_pool_max) && unique_pools(v.storage_pools.iter().map(|p| (p.name.as_str(), p.marker.as_str()))));

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayVersionV11 {
    #[serde(rename = "1.0")]
    V11,
}
checked!(DaemonCapabilitiesBaseV11, RawDaemonCapabilitiesBaseV11, {
    protocol_version: RelayVersionV11,
    binary_frames: bool,
    cancellation: bool,
    operation_wal: bool,
    host_inventory: bool,
    max_binary_chunk_bytes: u32,
    stream_window_chunks: u32,
    runtime_kind: crate::RuntimeKind,
    egress_policy: bool,
    terminal: bool,
    host_terminal: bool,
    require_host_terminal_totp: bool,
    policy_revision: u64,
    host_managed_sandbox_ceiling: u32,
}, v, scalar(v.policy_revision) && v.binary_frames && v.cancellation && v.operation_wal && v.host_inventory && v.max_binary_chunk_bytes as usize == crate::SANDBOX_BINARY_CHUNK_MAX_BYTES && v.stream_window_chunks as usize == crate::SANDBOX_STREAM_WINDOW_CHUNKS && vm_size_limits().is_ok_and(|l| v.host_managed_sandbox_ceiling == l.host_managed_sandbox_ceiling));
/// Hello capabilities with a required lease ceiling; null means unlimited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "serde_json::Value")]
pub struct DaemonCapabilitiesV11 {
    #[serde(flatten)]
    pub base: DaemonCapabilitiesBaseV11,
    pub max_lease_ms: Option<u64>,
    /// Optional image-cache runtime features.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<crate::ImageCapabilitiesV11>,
    /// Optional resolver refusal diagnostics.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub egress_refused_hints: bool,
    /// Optional template start and ready command support.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub template_startup: bool,
    /// Optional credential runtime features.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<crate::CredentialCapabilitiesV11>,
    /// Required open-egress and guard capability evidence.
    pub egress: crate::EgressCapabilitiesV11,
    /// Required command-output chunk ceiling offered to the server.
    #[serde(deserialize_with = "crate::egress::present")]
    pub max_output_chunk_bytes: Option<u32>,
    /// Optional graceful quiesce support.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub quiesce: bool,
    /// Required support for per-entry inventory census results.
    pub census_entry_results: bool,
    /// Optional reattachment grace for detached sandbox terminals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_resume: Option<crate::TerminalResumeCapabilityV11>,
    /// Required support for receipts still being resolved after reconnect.
    pub pending_receipts: bool,
    /// Required support for per-entry connected expiry results.
    pub expiry_status_results: bool,
    /// Required observation ordering for connected expiry results.
    pub observation_fence: bool,
    /// Required support for retiring unknown commands on host proof.
    pub command_retire: bool,
    /// Optional guest sudo runtime support.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub guest_sudo: bool,
    /// Optional stopped-disk transfer support; requires image fetching.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disk_offload: bool,
}
impl TryFrom<serde_json::Value> for DaemonCapabilitiesV11 {
    type Error = VmSizeError;
    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        let mut value = value;
        let object = value.as_object_mut().ok_or(VmSizeError)?;
        let max_lease_ms = match object.remove("maxLeaseMs") {
            None => return Err(VmSizeError),
            Some(serde_json::Value::Null) => None,
            Some(raw) => {
                let mut raw = raw;
                normalize_numbers(&mut raw);
                Some(raw.as_u64().ok_or(VmSizeError)?)
            }
        };
        if !crate::valid_lease_ceiling(max_lease_ms) {
            return Err(VmSizeError);
        }
        let image = match object.remove("image") {
            None => None,
            Some(raw) => {
                let image: crate::ImageCapabilitiesV11 =
                    serde_json::from_value(raw).map_err(|_| VmSizeError)?;
                if !image.is_valid() {
                    return Err(VmSizeError);
                }
                Some(image)
            }
        };
        // Only an explicit boolean; `false` is legal but never encoded.
        let egress_refused_hints = match object.remove("egressRefusedHints") {
            None => false,
            Some(serde_json::Value::Bool(value)) => value,
            Some(_) => return Err(VmSizeError),
        };
        let template_startup = match object.remove("templateStartup") {
            None => false,
            Some(serde_json::Value::Bool(value)) => value,
            Some(_) => return Err(VmSizeError),
        };
        let credentials = match object.remove("credentials") {
            None => None,
            Some(raw) => {
                let credentials: crate::CredentialCapabilitiesV11 =
                    serde_json::from_value(raw).map_err(|_| VmSizeError)?;
                if !credentials.is_valid() {
                    return Err(VmSizeError);
                }
                Some(credentials)
            }
        };
        let egress = match object.remove("egress") {
            None => return Err(VmSizeError),
            Some(raw) => serde_json::from_value::<crate::EgressCapabilitiesV11>(raw)
                .map_err(|_| VmSizeError)?,
        };
        // The chunk ceiling is required and must be in the shared range.
        let max_output_chunk_bytes = match object.remove("maxOutputChunkBytes") {
            None => return Err(VmSizeError),
            Some(raw) => {
                let mut raw = raw;
                normalize_numbers(&mut raw);
                let bytes = raw
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or(VmSizeError)?;
                if !crate::valid_output_chunk_bytes(bytes) {
                    return Err(VmSizeError);
                }
                Some(bytes)
            }
        };
        let quiesce = match object.remove("quiesce") {
            None => false,
            Some(serde_json::Value::Bool(value)) => value,
            Some(_) => return Err(VmSizeError),
        };
        // Core protocol features require an explicit `true`.
        let census_entry_results = match object.remove("censusEntryResults") {
            None => return Err(VmSizeError),
            Some(serde_json::Value::Bool(true)) => true,
            Some(_) => return Err(VmSizeError),
        };
        // Core protocol features require an explicit `true`.
        let mut offer = |name: &str| match object.remove(name) {
            None if matches!(name, "guestSudo" | "diskOffload") => Ok(false),
            None => Err(VmSizeError),
            Some(serde_json::Value::Bool(true)) => Ok(true),
            Some(_) => Err(VmSizeError),
        };
        let pending_receipts = offer("pendingReceipts")?;
        let expiry_status_results = offer("expiryStatusResults")?;
        let observation_fence = offer("observationFence")?;
        let command_retire = offer("commandRetire")?;
        let guest_sudo = offer("guestSudo")?;
        let disk_offload = offer("diskOffload")?;
        // Offload staging and restore fetch ride on the image cache.
        if disk_offload && !image.as_ref().is_some_and(|image| image.fetch) {
            return Err(VmSizeError);
        }
        let terminal_resume = match object.remove("terminalResume") {
            None => None,
            Some(raw) => {
                let mut raw = raw;
                normalize_numbers(&mut raw);
                let capability: crate::TerminalResumeCapabilityV11 =
                    serde_json::from_value(raw).map_err(|_| VmSizeError)?;
                if !capability.is_valid() {
                    return Err(VmSizeError);
                }
                Some(capability)
            }
        };
        Ok(Self {
            base: DaemonCapabilitiesBaseV11::try_from(value)?,
            max_lease_ms,
            image,
            egress_refused_hints,
            template_startup,
            credentials,
            egress,
            max_output_chunk_bytes,
            quiesce,
            census_entry_results,
            terminal_resume,
            pending_receipts,
            expiry_status_results,
            observation_fence,
            command_retire,
            guest_sudo,
            disk_offload,
        })
    }
}
fn optional_daemon_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonHelloV11 {
    pub host_id: String,
    pub label: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_daemon_version"
    )]
    pub version: Option<String>,
    pub capabilities: DaemonCapabilitiesV11,
}
checked!(HostHelloV11, RawHostHelloV11, {
    r#type: String,
    id: String,
    protocol_version: RelayVersionV11,
    supported_protocol_versions: Vec<RelayVersionV11>,
    daemon: DaemonHelloV11,
    inventory: HostInventoryV11,
    vm_capacity: VmCapacityV11,
    storage_pools: Vec<StoragePoolV11>,
}, optional {
    // WP7: a reconnect while quiescing; only with the `quiesce` capability.
    quiescing: bool,
}, v, (!v.quiescing || v.daemon.capabilities.quiesce) && v.r#type == "hello" && !v.id.is_empty() && v.id.chars().count() <= 128 && v.supported_protocol_versions.len() == 1 && v.daemon.host_id == v.inventory.host_id && v.daemon.label.chars().count() <= 256 && v.daemon.version.as_ref().is_none_or(|v| v.chars().count() <= 128) && vm_size_limits().is_ok_and(|l| v.storage_pools.len() <= l.storage_pool_max) && unique_pools(v.storage_pools.iter().map(|p| (p.name.as_str(), p.marker.as_str()))));

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
    fn capacity_v11_ts_rust_parity() {
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../fixtures/capacity_cases.json")).unwrap();
        for c in cases {
            let result = match c.kind.as_str() {
                "size" => serde_json::from_value::<VmSizeV11>(c.input)
                    .map(|v| serde_json::to_value(v).unwrap()),
                "overrides" => serde_json::from_value::<VmSizeOverridesV11>(c.input)
                    .map(|v| serde_json::to_value(v).unwrap()),
                "revision" => serde_json::from_value::<VmSizeOverridesV11>(c.input).map(|v| {
                    serde_json::to_value(v.resolve(VmSizeV11::defaults().unwrap()).unwrap())
                        .unwrap()
                }),
                "capacity" => serde_json::from_value::<VmCapacityV11>(c.input)
                    .map(|v| serde_json::to_value(v).unwrap()),
                "pool" => serde_json::from_value::<StoragePoolV11>(c.input)
                    .map(|v| serde_json::to_value(v).unwrap()),
                "inventory" => serde_json::from_value::<HostInventoryUpdateV11>(c.input)
                    .map(|v| serde_json::to_value(v).unwrap()),
                "hello" => serde_json::from_value::<HostHelloV11>(c.input)
                    .map(|v| serde_json::to_value(v).unwrap()),
                "allocation" => serde_json::from_value::<PinnedAllocationV11>(c.input)
                    .map(|v| serde_json::to_value(v).unwrap()),
                _ => panic!("unknown fixture kind"),
            };
            assert_eq!(result.is_ok(), c.valid, "{}: {:?}", c.name, result);
            if let Some(expected) = c.expected {
                assert_eq!(result.unwrap(), expected, "{}", c.name);
            }
        }
    }
    #[test]
    fn overrides_cannot_hide_an_invalid_revision() {
        let overrides: VmSizeOverridesV11 = serde_json::from_str(r#"{"diskGiB":32}"#).unwrap();
        let mut revision = VmSizeV11::defaults().unwrap();
        revision.disk_gi_b = 0;
        assert!(overrides.resolve(revision).is_err());
    }
    #[test]
    fn capacity_v11_fixture_is_active() {
        let fixture = include_str!("../fixtures/control_hello_daemon.json");
        serde_json::from_str::<HostHelloV11>(fixture).unwrap();
        assert!(crate::known_protocol_version("1.0"));
        assert!(crate::parse_daemon_control_for_version(fixture, "1.0").is_ok());
        for reason in ["ram", "vcpu", "disk", "storage", "ceiling"] {
            serde_json::from_value::<CapacityReason>(serde_json::json!(reason)).unwrap();
        }
        assert!(serde_json::from_str::<CapacityReason>("\"path\"").is_err());
    }
}
