//! Daemon-derived guest RAM admission contract and independent optional overrides.
use anyhow::{Result, bail};
use sandbox_protocol::{
    VmCapacity, host_memory_budget_from_bytes, host_memory_reserve_bytes, vm_size_limits,
};
use sandbox_runtime::{HostResources, HostRuntimeKind};
use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Clone, Copy, Default)]
pub struct CapacityOverrides {
    pub vcpu_budget: Option<u32>,
    pub memory_mib: Option<u32>,
    pub cpu_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedResources {
    pub memory_total_bytes: u64,
    pub cpu_threads: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedCapacity {
    pub vcpu_budget: Option<u32>,
    pub memory_budget_mi_b: Option<u32>,
    pub max_cpu_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapacityInspection {
    pub vcpu_budget: Option<u32>,
    pub vcpu_source: &'static str,
    pub runtime: &'static str,
    pub detected: Option<DetectedResources>,
    pub derived: Option<DerivedCapacity>,
    pub effective: Option<VmCapacity>,
    pub memory_source: &'static str,
    pub cpu_source: &'static str,
    pub detection_error: Option<&'static str>,
    pub memory_error: Option<&'static str>,
    pub warnings: Vec<&'static str>,
    #[serde(skip)]
    missing_memory: bool,
    #[serde(skip)]
    missing_cpu: bool,
}

impl CapacityInspection {
    pub fn require_complete(&self) -> Result<()> {
        let mut missing = Vec::new();
        if self.missing_memory {
            missing.push("--sandbox-memory-mib");
        }
        if self.missing_cpu {
            missing.push("--max-sandbox-cpu-count");
        }
        if self.vcpu_budget.is_none() {
            missing.push("--sandbox-vcpu-budget");
        }
        anyhow::ensure!(
            missing.is_empty(),
            "capacity unavailable; supply {} or repair daemon resource access",
            missing.join(" and ")
        );
        Ok(())
    }
    pub fn require_vcpu_budget(&self) -> Result<u32> {
        self.vcpu_budget.ok_or_else(|| anyhow::anyhow!("runtime resource detection failed; supply --sandbox-vcpu-budget or repair daemon resource access"))
    }
    pub fn require_capacity(&self) -> Result<VmCapacity> {
        if let Some(capacity) = self.effective {
            return Ok(capacity);
        }
        let missing = match (self.missing_memory, self.missing_cpu) {
            (true, true) => "--sandbox-memory-mib and --max-sandbox-cpu-count",
            (true, false) => "--sandbox-memory-mib",
            (false, true) => "--max-sandbox-cpu-count",
            (false, false) => "valid capacity overrides",
        };
        let reason = self
            .memory_error
            .or(self.detection_error)
            .unwrap_or("capacity unavailable");
        bail!("{reason}; supply {missing} or repair daemon resource access")
    }
}

pub fn derive_capacity(resources: HostResources, kind: HostRuntimeKind) -> Result<DerivedCapacity> {
    let limits = vm_size_limits()?;
    if kind == HostRuntimeKind::Fake {
        return Ok(DerivedCapacity {
            vcpu_budget: Some(8),
            memory_budget_mi_b: Some(4096),
            max_cpu_count: Some(4),
        });
    }
    // Derive independently: unusable guest RAM must not hide valid CPU or totals.
    let aligned = host_memory_budget_from_bytes(resources.memory_total_bytes())?;
    let memory = aligned.min(u64::from(limits.host_memory_budget_mi_b_max));
    let cpu = resources.cpu_threads().min(u64::from(limits.cpu_count_max));
    let memory = u32::try_from(memory)?;
    let cpu = u32::try_from(cpu)?;
    Ok(DerivedCapacity {
        vcpu_budget: Some(
            ((u128::from(resources.cpu_threads())
                * u128::from(limits.host_vcpu_budget_default_threads_multiplier))
            .min(u128::from(limits.host_vcpu_budget_max))) as u32,
        ),
        memory_budget_mi_b: VmCapacity::new(memory, 1)
            .ok()
            .map(|v| v.memory_budget_mi_b),
        max_cpu_count: VmCapacity::new(512, cpu).ok().map(|v| v.max_cpu_count),
    })
}

/// Errors from the daemon are never formatted into output: they can contain
/// arbitrary subprocess text. Both commands use this same scalar-only view.
pub fn inspect_capacity(
    kind: HostRuntimeKind,
    flags: CapacityOverrides,
    config: &Config,
    resources: Result<HostResources>,
) -> Result<CapacityInspection> {
    let vcpu = flags.vcpu_budget.or(config.sandbox_vcpu_budget);
    let limits = vm_size_limits()?;
    if vcpu
        .is_some_and(|v| !(limits.host_vcpu_budget_min..=limits.host_vcpu_budget_max).contains(&v))
    {
        bail!("invalid sandbox vCPU budget override (1..8192)");
    }
    let memory = flags.memory_mib.or(config.sandbox_memory_mib);
    let cpu = flags.cpu_count.or(config.max_sandbox_cpu_count);
    if let Some(value) = memory {
        VmCapacity::new(value, 1).map_err(|_| {
            anyhow::anyhow!(if flags.memory_mib.is_some() {
                "invalid --sandbox-memory-mib override"
            } else {
                "invalid config file value for `sandbox_memory_mib`"
            })
        })?;
    }
    if let Some(value) = cpu {
        VmCapacity::new(512, value).map_err(|_| {
            anyhow::anyhow!(if flags.cpu_count.is_some() {
                "invalid --max-sandbox-cpu-count override"
            } else {
                "invalid config file value for `max_sandbox_cpu_count`"
            })
        })?;
    }
    let (totals, derived, detection_error) = match resources {
        Ok(totals) => {
            let derived = derive_capacity(totals, kind)?;
            (
                Some(DetectedResources {
                    memory_total_bytes: totals.memory_total_bytes(),
                    cpu_threads: totals.cpu_threads(),
                }),
                Some(derived),
                None,
            )
        }
        Err(_) => (None, None, Some("runtime resource detection failed")),
    };
    let derived_memory = derived.and_then(|v| v.memory_budget_mi_b);
    let derived_cpu = derived.and_then(|v| v.max_cpu_count);
    let effective_memory = memory.or(derived_memory);
    let effective_cpu = cpu.or(derived_cpu);
    let effective = effective_memory
        .zip(effective_cpu)
        .map(|(memory, cpu)| VmCapacity::new(memory, cpu))
        .transpose()?;
    let mut warnings = Vec::new();
    if detection_error.is_some() && effective.is_some() {
        warnings.push("WARNING: runtime resource detection failed; trusting both configured capacity overrides");
    }
    if let (Some(memory), Some(totals)) = (memory, totals.as_ref()) {
        if u64::from(memory) * 1024 * 1024 > totals.memory_total_bytes {
            warnings.push("WARNING: configured guest RAM budget exceeds total RAM; the operator is responsible for host headroom");
        } else if derived_memory.is_none_or(|budget| memory > budget) {
            warnings.push("WARNING: configured guest RAM budget removes the default reserve; the operator is responsible for host headroom");
        }
    }
    if derived_cpu.is_some_and(|detected| cpu.is_some_and(|c| c > detected)) {
        warnings.push("WARNING: configured per-VM CPU cap exceeds detected CPU threads");
    }
    let limits = vm_size_limits()?;
    let memory_clamped = if kind != HostRuntimeKind::Fake
        && let Some(t) = totals.as_ref()
    {
        t.memory_total_bytes
            .saturating_sub(host_memory_reserve_bytes(t.memory_total_bytes)?)
            / (1024 * 1024)
            > u64::from(limits.host_memory_budget_mi_b_max)
    } else {
        false
    };
    let cpu_clamped = kind != HostRuntimeKind::Fake
        && totals
            .as_ref()
            .is_some_and(|t| t.cpu_threads > u64::from(limits.cpu_count_max));
    Ok(CapacityInspection {
        vcpu_budget: vcpu.or(derived.and_then(|v| v.vcpu_budget)),
        vcpu_source: source(
            flags.vcpu_budget,
            config.sandbox_vcpu_budget,
            derived.and_then(|v| v.vcpu_budget),
            false,
        ),
        runtime: match kind {
            HostRuntimeKind::Fake => "fake",
            #[cfg(target_os = "linux")]
            HostRuntimeKind::IncusKvm => "incus",
        },
        memory_error: if totals.is_some() && derived_memory.is_none() {
            Some("detected guest RAM budget is below 512 MiB")
        } else {
            None
        },
        detected: totals,
        derived,
        effective,
        detection_error,
        warnings,
        memory_source: source(
            flags.memory_mib,
            config.sandbox_memory_mib,
            derived_memory,
            memory_clamped,
        ),
        cpu_source: source(
            flags.cpu_count,
            config.max_sandbox_cpu_count,
            derived_cpu,
            cpu_clamped,
        ),
        missing_memory: effective_memory.is_none(),
        missing_cpu: effective_cpu.is_none(),
    })
}

fn source(
    flag: Option<u32>,
    toml: Option<u32>,
    detected: Option<u32>,
    clamped: bool,
) -> &'static str {
    if flag.is_some() {
        "flag"
    } else if toml.is_some() {
        "toml"
    } else if detected.is_none() {
        "unavailable"
    } else if clamped {
        "clamped"
    } else {
        "detected"
    }
}

/// Keep a last good resolution across relay sessions. Transient daemon errors
/// cannot terminate an established daemon or silently change its static budget.
pub fn resolve_session_capacity(
    view: CapacityInspection,
    last_good: &mut Option<CapacityInspection>,
) -> Result<VmCapacity> {
    if view.detection_error.is_some()
        && let Some(previous) = last_good.as_ref()
    {
        tracing::warn!(
            "runtime resource detection failed on reconnect; reusing last good host capacity"
        );
        return previous.require_capacity();
    }
    view.require_complete()?;
    let capacity = view.require_capacity()?;
    for warning in &view.warnings {
        tracing::warn!(warning = *warning, "host capacity warning");
    }
    tracing::info!(
        memory_budget_mib = capacity.memory_budget_mi_b,
        max_cpu_count = capacity.max_cpu_count,
        memory_source = view.memory_source,
        cpu_source = view.cpu_source,
        detected_memory_bytes = view.detected.as_ref().map(|v| v.memory_total_bytes),
        detected_cpu_threads = view.detected.as_ref().map(|v| v.cpu_threads),
        derived_memory_mib = view.derived.and_then(|v| v.memory_budget_mi_b),
        derived_cpu_count = view.derived.and_then(|v| v.max_cpu_count),
        "effective host capacity"
    );
    if view.memory_source == "clamped" || view.cpu_source == "clamped" {
        tracing::info!("detected host capacity clamped to protocol limits");
    }
    *last_good = Some(view);
    Ok(capacity)
}

/// Read-only, project-independent query with IncusClient's bounded host timeout.
/// Config inspection must never provision a project or start a runtime.
pub fn detect_resources(kind: HostRuntimeKind) -> Result<HostResources> {
    match kind {
        HostRuntimeKind::Fake => Ok(HostResources::new(8 * 1024 * 1024 * 1024, 4)?),
        #[cfg(target_os = "linux")]
        HostRuntimeKind::IncusKvm => {
            let config = sandbox_runtime::IncusConfig::from_env();
            Ok(
                sandbox_runtime::IncusClient::new(config.binary, config.project)
                    .host_resources()?,
            )
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    fn totals(mib: u64, cpu: u64) -> HostResources {
        HostResources::new(mib * 1024 * 1024, cpu).unwrap()
    }
    #[test]
    fn detected_formula_boundaries_clamp_and_fake_defaults() {
        for (memory, cpu, budget, cap) in [
            (4608, 1, 512, 1),
            (16 * 1024, 8, 12288, 8),
            (16 * 1024 + 255, 128, 12288, 32),
            (32 * 1024, 64, 24576, 32),
            (32 * 1024 * 1024, 4096, 16777216, 32),
        ] {
            let view = inspect_capacity(
                HostRuntimeKind::IncusKvm,
                CapacityOverrides::default(),
                &Config::default(),
                Ok(totals(memory, cpu)),
            )
            .unwrap();
            assert!(
                view.effective.is_some(),
                "detected budgets must clamp before validation"
            );
            assert_eq!(
                view.require_capacity().unwrap(),
                VmCapacity::new(budget, cap).unwrap()
            );
        }
        assert!(
            derive_capacity(totals(2048, 4), HostRuntimeKind::IncusKvm)
                .unwrap()
                .memory_budget_mi_b
                .is_none()
        );
        assert_eq!(
            derive_capacity(
                HostResources::new(u64::MAX, u64::MAX).unwrap(),
                HostRuntimeKind::IncusKvm
            )
            .unwrap()
            .memory_budget_mi_b,
            Some(16777216)
        );
        assert_eq!(
            derive_capacity(totals(8192, 4), HostRuntimeKind::Fake)
                .unwrap()
                .memory_budget_mi_b,
            Some(4096)
        );
    }

    #[test]
    fn failed_detection_requires_exactly_missing_overrides_flags_config_and_mixed() {
        for use_config_memory in [false, true] {
            for use_config_cpu in [false, true] {
                for memory in [None, Some(8192)] {
                    for cpu in [None, Some(4)] {
                        let config = Config {
                            sandbox_memory_mib: memory.filter(|_| use_config_memory),
                            max_sandbox_cpu_count: cpu.filter(|_| use_config_cpu),
                            ..Config::default()
                        };
                        let flags = CapacityOverrides {
                            vcpu_budget: None,
                            memory_mib: memory.filter(|_| !use_config_memory),
                            cpu_count: cpu.filter(|_| !use_config_cpu),
                        };
                        let view = inspect_capacity(
                            HostRuntimeKind::IncusKvm,
                            flags,
                            &config,
                            Err(anyhow::anyhow!("untrusted subprocess diagnostic")),
                        )
                        .unwrap();
                        assert!(view.detected.is_none());
                        assert!(view.derived.is_none());
                        assert_eq!(
                            view.detection_error,
                            Some("runtime resource detection failed")
                        );
                        let json = serde_json::to_string(&view).unwrap();
                        assert!(!json.contains("untrusted"));
                        if memory.is_some() && cpu.is_some() {
                            assert_eq!(
                                view.require_capacity().unwrap(),
                                VmCapacity::new(8192, 4).unwrap()
                            );
                            assert_eq!(view.warnings.len(), 1);
                        } else {
                            let error = view.require_capacity().unwrap_err().to_string();
                            assert_eq!(error.contains("--sandbox-memory-mib"), memory.is_none());
                            assert_eq!(error.contains("--max-sandbox-cpu-count"), cpu.is_none());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn low_memory_detection_preserves_totals_and_independent_cpu_matrix() {
        for memory_in_toml in [false, true] {
            for cpu_in_toml in [false, true] {
                for memory in [None, Some(1024)] {
                    for cpu in [None, Some(2)] {
                        let config = Config {
                            sandbox_memory_mib: memory.filter(|_| memory_in_toml),
                            max_sandbox_cpu_count: cpu.filter(|_| cpu_in_toml),
                            ..Config::default()
                        };
                        let view = inspect_capacity(
                            HostRuntimeKind::IncusKvm,
                            CapacityOverrides {
                                vcpu_budget: None,
                                memory_mib: memory.filter(|_| !memory_in_toml),
                                cpu_count: cpu.filter(|_| !cpu_in_toml),
                            },
                            &config,
                            Ok(totals(2048, 4)),
                        )
                        .unwrap();
                        assert_eq!(
                            view.detected.as_ref().unwrap().memory_total_bytes,
                            2 * 1024 * 1024 * 1024
                        );
                        assert_eq!(view.detected.as_ref().unwrap().cpu_threads, 4);
                        assert_eq!(view.derived.unwrap().max_cpu_count, Some(4));
                        assert!(view.derived.unwrap().memory_budget_mi_b.is_none());
                        assert!(view.detection_error.is_none());
                        assert!(view.memory_error.unwrap().contains("below 512 MiB"));
                        if let Some(memory) = memory {
                            assert_eq!(
                                view.require_capacity().unwrap(),
                                VmCapacity::new(memory, cpu.unwrap_or(4)).unwrap()
                            );
                        } else {
                            let error = view.require_capacity().unwrap_err().to_string();
                            assert!(error.contains("--sandbox-memory-mib"));
                            assert!(!error.contains("--max-sandbox-cpu-count"));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn reconnect_detection_failure_reuses_last_good_but_first_connect_fails() {
        let inspect = |resources| {
            inspect_capacity(
                HostRuntimeKind::IncusKvm,
                CapacityOverrides::default(),
                &Config::default(),
                resources,
            )
            .unwrap()
        };
        let mut previous = None;
        assert!(
            resolve_session_capacity(inspect(Err(anyhow::anyhow!("timeout"))), &mut previous)
                .is_err()
        );
        let expected =
            resolve_session_capacity(inspect(Ok(totals(16384, 8))), &mut previous).unwrap();
        for _ in 0..2 {
            assert_eq!(
                resolve_session_capacity(inspect(Err(anyhow::anyhow!("timeout"))), &mut previous)
                    .unwrap(),
                expected
            );
        }
        assert_eq!(
            resolve_session_capacity(inspect(Ok(totals(32768, 4))), &mut previous).unwrap(),
            VmCapacity::new(24576, 4).unwrap()
        );
    }

    #[test]
    fn distinct_memory_warnings_and_unavailable_sources() {
        for (memory, message) in [
            (13312, "removes the default reserve"),
            (16384, "removes the default reserve"),
            (16640, "exceeds total RAM"),
        ] {
            let view = inspect_capacity(
                HostRuntimeKind::IncusKvm,
                CapacityOverrides {
                    vcpu_budget: None,
                    memory_mib: Some(memory),
                    cpu_count: None,
                },
                &Config::default(),
                Ok(totals(16384, 8)),
            )
            .unwrap();
            assert_eq!(view.warnings.len(), 1);
            assert!(view.warnings[0].contains(message));
        }
        let view = inspect_capacity(
            HostRuntimeKind::IncusKvm,
            CapacityOverrides::default(),
            &Config::default(),
            Err(anyhow::anyhow!("timeout")),
        )
        .unwrap();
        assert_eq!(view.cpu_source, "unavailable");
        assert_eq!(view.memory_source, "unavailable");
        assert!(
            view.require_capacity()
                .unwrap_err()
                .to_string()
                .contains("or repair daemon resource access")
        );
    }

    #[test]
    fn independent_precedence_invalid_overrides_and_scalar_overcommit_warnings() {
        let config = Config {
            sandbox_memory_mib: Some(4096),
            max_sandbox_cpu_count: Some(2),
            ..Config::default()
        };
        for (flags, expected, memory_source, cpu_source) in [
            (CapacityOverrides::default(), (4096, 2), "toml", "toml"),
            (
                CapacityOverrides {
                    vcpu_budget: None,
                    memory_mib: Some(8192),
                    cpu_count: None,
                },
                (8192, 2),
                "flag",
                "toml",
            ),
            (
                CapacityOverrides {
                    vcpu_budget: None,
                    memory_mib: None,
                    cpu_count: Some(16),
                },
                (4096, 16),
                "toml",
                "flag",
            ),
            (
                CapacityOverrides {
                    vcpu_budget: None,
                    memory_mib: Some(16384),
                    cpu_count: Some(16),
                },
                (16384, 16),
                "flag",
                "flag",
            ),
        ] {
            let view = inspect_capacity(
                HostRuntimeKind::IncusKvm,
                flags,
                &config,
                Ok(totals(16384, 8)),
            )
            .unwrap();
            assert_eq!(
                view.require_capacity().unwrap(),
                VmCapacity::new(expected.0, expected.1).unwrap()
            );
            assert_eq!(
                (view.memory_source, view.cpu_source),
                (memory_source, cpu_source)
            );
            assert_eq!(
                view.warnings.len(),
                usize::from(expected.0 > 12288) + usize::from(expected.1 > 8)
            );
        }
        for (memory, cpu) in [(0, 1), (513, 1), (16777472, 1), (512, 0), (512, 33)] {
            assert!(
                inspect_capacity(
                    HostRuntimeKind::IncusKvm,
                    CapacityOverrides {
                        vcpu_budget: None,
                        memory_mib: Some(memory),
                        cpu_count: Some(cpu),
                    },
                    &Config::default(),
                    Ok(totals(16384, 8))
                )
                .is_err()
            );
        }
        let config = Config {
            sandbox_memory_mib: Some(8192),
            ..Config::default()
        };
        let view = inspect_capacity(
            HostRuntimeKind::IncusKvm,
            CapacityOverrides::default(),
            &config,
            Ok(totals(16384, 8)),
        )
        .unwrap();
        assert_eq!(
            view.require_capacity().unwrap(),
            VmCapacity::new(8192, 8).unwrap()
        );
        assert_eq!(view.cpu_source, "detected");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod vcpu_tests {
    use super::*;
    #[test]
    fn independent_vcpu_precedence_default_bounds_and_missing_dimensions() {
        let resources = HostResources::new(124 * 1024 * 1024 * 1024, 32).unwrap();
        let config = Config {
            sandbox_vcpu_budget: Some(60),
            ..Config::default()
        };
        for (flag, expected, source) in [(None, 60, "toml"), (Some(64), 64, "flag")] {
            let view = inspect_capacity(
                HostRuntimeKind::IncusKvm,
                CapacityOverrides {
                    vcpu_budget: flag,
                    ..CapacityOverrides::default()
                },
                &config,
                Ok(resources),
            )
            .unwrap();
            assert_eq!(view.vcpu_budget, Some(expected));
            assert_eq!(view.vcpu_source, source);
        }
        let view = inspect_capacity(
            HostRuntimeKind::IncusKvm,
            CapacityOverrides::default(),
            &Config::default(),
            Ok(resources),
        )
        .unwrap();
        assert_eq!(view.vcpu_budget, Some(64));
        assert_eq!(view.require_capacity().unwrap().memory_budget_mi_b, 95232);
        let view = inspect_capacity(
            HostRuntimeKind::IncusKvm,
            CapacityOverrides::default(),
            &Config::default(),
            Err(anyhow::anyhow!("untrusted daemon text")),
        )
        .unwrap();
        let error = view.require_complete().unwrap_err().to_string();
        for name in [
            "--sandbox-vcpu-budget",
            "--sandbox-memory-mib",
            "--max-sandbox-cpu-count",
        ] {
            assert!(error.contains(name));
        }
        assert!(!error.contains("untrusted"));
        for value in [0, 8193, u32::MAX] {
            assert!(
                inspect_capacity(
                    HostRuntimeKind::IncusKvm,
                    CapacityOverrides {
                        vcpu_budget: Some(value),
                        ..CapacityOverrides::default()
                    },
                    &Config::default(),
                    Ok(resources)
                )
                .is_err()
            );
        }
        let fake = inspect_capacity(
            HostRuntimeKind::Fake,
            CapacityOverrides::default(),
            &Config::default(),
            Ok(resources),
        )
        .unwrap();
        assert_eq!(fake.vcpu_budget, Some(8));
    }
}
