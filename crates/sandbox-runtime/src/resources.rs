//! Read-only physical totals reported by the runtime daemon.
use crate::RuntimeError;
use sandbox_protocol::SandboxErrorCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostResources {
    memory_total_bytes: u64,
    cpu_threads: u64,
}
impl HostResources {
    pub fn new(memory_total_bytes: u64, cpu_threads: u64) -> Result<Self, RuntimeError> {
        if memory_total_bytes == 0 || cpu_threads == 0 {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "invalid daemon host resources",
            ));
        }
        Ok(Self {
            memory_total_bytes,
            cpu_threads,
        })
    }
    /// Incus reports installed RAM; the kernel can reserve some of it for
    /// firmware/devices. Admission uses the lower usable physical total.
    pub(crate) fn with_meminfo(self, text: &str) -> Result<Self, RuntimeError> {
        let bytes = text
            .lines()
            .find_map(|line| {
                let mut words = line.split_whitespace();
                (words.next()? == "MemTotal:").then_some(())?;
                let kib = words.next()?.parse::<u64>().ok()?;
                (words.next()? == "kB" && words.next().is_none()).then_some(())?;
                kib.checked_mul(1024).filter(|bytes| *bytes > 0)
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "kernel memory total unavailable",
                )
            })?;
        Self::new(self.memory_total_bytes.min(bytes), self.cpu_threads)
    }
    pub fn memory_total_bytes(&self) -> u64 {
        self.memory_total_bytes
    }
    pub fn cpu_threads(&self) -> u64 {
        self.cpu_threads
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn from_daemon(value: serde_json::Value) -> Result<Self, RuntimeError> {
        #[derive(serde::Deserialize)]
        struct Memory {
            total: u64,
        }
        #[derive(serde::Deserialize)]
        struct Cpu {
            total: u64,
        }
        #[derive(serde::Deserialize)]
        struct Resources {
            memory: Memory,
            cpu: Cpu,
        }
        let totals: Resources = serde_json::from_value(value).map_err(|_| {
            RuntimeError::new(SandboxErrorCode::Internal, "invalid daemon host resources")
        })?;
        Self::new(totals.memory.total, totals.cpu.total)
    }
}

pub(crate) fn validate_vm_size(size: sandbox_protocol::VmSize) -> Result<(), RuntimeError> {
    sandbox_protocol::VmSize::new(size.cpu_count, size.memory_mi_b)
        .map(|_| ())
        .map_err(|_| RuntimeError::new(SandboxErrorCode::ProtocolError, "invalid VM size"))
}

/// Narrow inventory decoding, never a start-fence equivalence normalizer.
#[cfg(target_os = "linux")]
pub(crate) fn configured_vm_size(
    config: &serde_json::Map<String, serde_json::Value>,
) -> Result<sandbox_protocol::VmSize, RuntimeError> {
    fn dimension(
        config: &serde_json::Map<String, serde_json::Value>,
        key: &str,
        default: u32,
        suffix: &str,
    ) -> Option<u32> {
        let Some(value) = config.get(key) else {
            return Some(default);
        };
        let text = value.as_str()?;
        let digits = text.strip_suffix(suffix)?;
        let number: u32 = digits.parse().ok()?;
        (text == format!("{number}{suffix}")).then_some(number)
    }
    let invalid = || {
        RuntimeError::new(
            SandboxErrorCode::VmSizeMismatch,
            "noncanonical effective VM allocation",
        )
    };
    let defaults = sandbox_protocol::VmSize::defaults().map_err(|_| invalid())?;
    let cpu = dimension(config, "limits.cpu", defaults.cpu_count, "").ok_or_else(invalid)?;
    let memory =
        dimension(config, "limits.memory", defaults.memory_mi_b, "MiB").ok_or_else(invalid)?;
    sandbox_protocol::VmSize::new(cpu, memory).map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_total_caps_installed_ram_and_rejects_unreadable_totals() {
        let resources = HostResources::new(128 * 1024 * 1024 * 1024, 32).unwrap();
        assert_eq!(
            resources
                .with_meminfo("MemTotal:       131009336 kB\nMemFree: 123 kB")
                .unwrap()
                .memory_total_bytes(),
            131009336 * 1024
        );
        assert_eq!(
            resources.with_meminfo("MemTotal: 999999999 kB").unwrap(),
            resources
        );
        for text in [
            "",
            "MemTotal: 0 kB",
            "MemTotal: 123 MB",
            "MemTotal: 18446744073709551615 kB",
        ] {
            assert!(resources.with_meminfo(text).is_err());
        }
    }

    #[test]
    fn host_resources_constructor_enforces_positive_totals() {
        assert!(HostResources::new(0, 1).is_err());
        assert!(HostResources::new(1, 0).is_err());
        let resources = HostResources::new(1, 2).unwrap();
        assert_eq!(resources.memory_total_bytes(), 1);
        assert_eq!(resources.cpu_threads(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_totals_are_positive_u64_not_node_daemon_memory_or_cpu() {
        let resources = HostResources::from_daemon(serde_json::json!({
            "memory": {"total": 1234567890123_u64}, "cpu": {"total": 93}
        }))
        .unwrap();
        assert_eq!(resources.memory_total_bytes, 1234567890123);
        assert_eq!(resources.cpu_threads, 93);
        for bad in [
            "{}",
            r#"{"memory":{"total":1}}"#,
            r#"{"memory":{"total":0},"cpu":{"total":1}}"#,
            r#"{"memory":{"total":1},"cpu":{"total":0}}"#,
            r#"{"memory":{"total":-1},"cpu":{"total":2}}"#,
            r#"{"memory":{"total":"8192"},"cpu":{"total":2}}"#,
            r#"{"memory":{"total":1},"cpu":{"total":1.5}}"#,
            r#"{"memory":{"total":18446744073709551616},"cpu":{"total":2}}"#,
            r#"{"memory":{"total":1},"cpu":{"total":18446744073709551616}}"#,
        ] {
            assert!(
                HostResources::from_daemon(serde_json::from_str(bad).unwrap()).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            HostResources::from_daemon(serde_json::json!({
                "memory": {"total": u64::MAX}, "cpu": {"total": u64::MAX}
            }))
            .unwrap()
            .memory_total_bytes,
            u64::MAX
        );
    }
}

/// Exact canonical equality, including dimension-specific absent defaults.
#[cfg(target_os = "linux")]
pub(crate) fn verify_vm_size(
    config: &serde_json::Map<String, serde_json::Value>,
    expected: sandbox_protocol::VmSize,
    allow_absent: bool,
) -> Result<(), RuntimeError> {
    validate_vm_size(expected)?;
    let defaults = sandbox_protocol::VmSize::defaults().map_err(|_| {
        RuntimeError::new(SandboxErrorCode::ProtocolError, "invalid VM size defaults")
    })?;
    for (key, value, is_default) in [
        (
            "limits.cpu",
            expected.cpu_count.to_string(),
            expected.cpu_count == defaults.cpu_count,
        ),
        (
            "limits.memory",
            format!("{}MiB", expected.memory_mi_b),
            expected.memory_mi_b == defaults.memory_mi_b,
        ),
    ] {
        let matches = match config.get(key) {
            Some(observed) => observed.as_str() == Some(value.as_str()),
            None => allow_absent || is_default,
        };
        if !matches {
            return Err(RuntimeError::new(
                SandboxErrorCode::VmSizeMismatch,
                "effective VM allocation differs; refusing start",
            ));
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod allocation_tests {
    use super::*;
    use sandbox_protocol::VmSize;
    use serde_json::json;

    #[test]
    fn exact_fence_and_inventory_decode_accept_only_canonical_allocations() {
        let sized = VmSize::new(2, 2048).unwrap();
        let defaults = VmSize::defaults().unwrap();
        for (config, expected, valid) in [
            (json!({}), defaults, true),
            (json!({}), sized, false),
            (
                json!({"limits.cpu":"2"}),
                VmSize::new(2, 1024).unwrap(),
                true,
            ),
            (
                json!({"limits.memory":"2048MiB"}),
                VmSize::new(1, 2048).unwrap(),
                true,
            ),
            (json!({"limits.cpu":"2"}), sized, false),
            (json!({"limits.memory":"2048MiB"}), sized, false),
            (
                json!({"limits.cpu":"2", "limits.memory":"2048MiB"}),
                sized,
                true,
            ),
            (
                json!({"limits.cpu":"02", "limits.memory":"2048MiB"}),
                sized,
                false,
            ),
            (
                json!({"limits.cpu":"2", "limits.memory":"2GiB"}),
                sized,
                false,
            ),
            (
                json!({"limits.cpu":"2", "limits.memory":"2147483648"}),
                sized,
                false,
            ),
            (
                json!({"limits.cpu":"0-1", "limits.memory":"2048MiB"}),
                sized,
                false,
            ),
            (
                json!({"limits.cpu":"2", "limits.memory":"02048MiB"}),
                sized,
                false,
            ),
            (
                json!({"limits.cpu":"2", "limits.memory":"2048MiB "}),
                sized,
                false,
            ),
            (
                json!({"limits.cpu":"2", "limits.memory":"50%"}),
                sized,
                false,
            ),
            (
                json!({"limits.cpu":2, "limits.memory":"2048MiB"}),
                sized,
                false,
            ),
        ] {
            let config = config.as_object().unwrap();
            assert_eq!(
                verify_vm_size(config, expected, false).is_ok(),
                valid,
                "{config:?} {expected:?}"
            );
            if valid {
                assert_eq!(configured_vm_size(config).unwrap(), expected);
            } else if config.len() == 2 {
                assert!(configured_vm_size(config).is_err(), "{config:?}");
            }
        }
        for bad in ["02", "+2", " 2", "2 ", "2\n", "2vCPU"] {
            assert!(
                configured_vm_size(json!({"limits.cpu":bad}).as_object().unwrap()).is_err(),
                "{bad:?}"
            );
        }
        for bad in [
            "0MiB",
            "513MiB",
            "65537MiB",
            "4294967296MiB",
            "-1MiB",
            "+2048MiB",
            " 2048MiB",
            "2048 MiB",
            "2048mib",
        ] {
            assert!(configured_vm_size(json!({"limits.memory":bad}).as_object().unwrap()).is_err());
        }
    }
}
