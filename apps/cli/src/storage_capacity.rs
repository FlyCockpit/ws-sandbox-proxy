//! Frozen connection caps. Polls can change health, never these derivation inputs.
use crate::{config::Config, sandbox_relay::journal::HostJournal};
use anyhow::{Context, Result};
use sandbox_protocol::{capacity_v11::*, vm_size_limits};
use sandbox_runtime::{GIB_BYTES, SandboxRuntime, StoragePoolIdentity, StorageResources};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Derivation {
    pub total_based_capacity_gi_b: u64,
    pub capacity_gi_b: u64,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub committed_bytes: u64,
    pub actual_bytes: u64,
    pub headroom_bytes: u64,
}
pub fn derive(
    resources: StorageResources,
    commitments: u64,
    actual: u64,
    ceiling: Option<u64>,
) -> Result<Derivation> {
    derive_with_image_reserve(resources, commitments, actual, ceiling, 0)
}

/// [`derive`] with the managed image cache carved out (M1): the cache, its
/// staging and the daemon image store grow after hello, so their budget is
/// subtracted from what new roots may use here, frozen like every other input.
pub fn derive_with_image_reserve(
    resources: StorageResources,
    commitments: u64,
    actual: u64,
    ceiling: Option<u64>,
    image_reserve: u64,
) -> Result<Derivation> {
    let limits = vm_size_limits()?;
    let t = u128::from(resources.total_bytes());
    let h = (t * u128::from(limits.default_storage_headroom_percent)).div_ceil(100);
    let b = t * u128::from(limits.default_storage_capacity_percent) / 100;
    let a = actual.min(commitments);
    let available = (u128::from(resources.free_bytes()) + u128::from(a))
        .saturating_sub(h)
        .saturating_sub(u128::from(image_reserve));
    let capacity = b
        .min(available)
        .min(u128::from(ceiling.unwrap_or(u64::MAX)) * u128::from(GIB_BYTES))
        / u128::from(GIB_BYTES);
    Ok(Derivation {
        total_based_capacity_gi_b: (b / u128::from(GIB_BYTES)).try_into()?,
        capacity_gi_b: capacity
            .min(u128::from(limits.storage_capacity_gi_b_max))
            .try_into()?,
        total_bytes: resources.total_bytes(),
        free_bytes: resources.free_bytes(),
        committed_bytes: commitments,
        actual_bytes: a,
        headroom_bytes: h.try_into()?,
    })
}

/// Connect initializes identity; inspection uses bounded IncusClient reads only.
/// Called under the private journal directory lock before hello.
pub fn connect_pools(
    runtime: &dyn SandboxRuntime,
    config: &Config,
    journal: &HostJournal,
) -> Result<Vec<StoragePoolV11>> {
    connect_pools_until(runtime, config, journal, &|| false)
}

/// [`connect_pools`] for a census that can be cut short. `interrupted` says
/// whether shutdown was requested or the census permit was revoked (or its
/// bound expired). R2-2: a pool that fails while it is true was not observed,
/// not found damaged. This is decided from that state, never from the error
/// text: an interrupted Incus call surfaces as many different errors
/// (`cancelled`, `preempted`, `internal: … marker is incomplete`,
/// `unknown_outcome: incus command ended without a confirmed outcome`).
pub fn connect_pools_until(
    runtime: &dyn SandboxRuntime,
    config: &Config,
    journal: &HostJournal,
    interrupted: &dyn Fn() -> bool,
) -> Result<Vec<StoragePoolV11>> {
    config.validate_storage()?;
    let names = if config.storage_pools.is_empty() {
        vec![runtime.default_storage_pool()?]
    } else {
        config
            .storage_pools
            .iter()
            .map(|p| p.name.clone())
            .collect()
    };
    let lineages = journal.pool_lineages();
    let mut pools = Vec::new();
    for name in names {
        let expected = lineages.iter().find(|p| p.name == name);
        let explicit = config.storage_pools.iter().find(|p| p.name == name);
        let result = (|| -> Result<StoragePoolV11> {
            let pool = runtime.initialize_storage_pool(&name, expected)?;
            let observation = runtime.observe_storage_pool(&pool)?;
            let retained = journal.retained_roots();
            let charged: Vec<_> = retained
                .iter()
                .filter(|(_, r)| r.root().pool == pool)
                .collect();
            let c = charged.iter().try_fold(0u64, |sum, (_, r)| {
                sum.checked_add(u64::from(r.allocation.root_charge_gi_b) * GIB_BYTES)
                    .context("root commitment overflow")
            })?;
            let census = runtime.storage_root_census(&pool)?;
            anyhow::ensure!(
                census.roots.iter().all(|r| charged
                    .iter()
                    .any(|(id, _)| sandbox_runtime::default_incus_instance_name(id)
                        == r.instance_name)),
                "unbound roots require original journal recovery"
            );
            let roots: Vec<_> = charged
                .iter()
                .map(|(id, _)| sandbox_runtime::default_incus_instance_name(id))
                .collect();
            let actual = runtime
                .storage_physical_usage(&pool, &roots, c)?
                .charged_bytes;
            let prior = journal.implicit_ceiling(&pool.storage_id);
            // Carve-out (M1): every configured pool, including `dir`, gives up
            // min(cap, derived) to the image cache. Without a device
            // identity for the daemon image store this is the conservative
            // superset of the plan's same-device rule.
            let reserve = config
                .image_cache_gib
                .bytes_for(observation.resources.total_bytes());
            let d = derive_with_image_reserve(observation.resources, c, actual, prior, reserve)?;
            let mut frame = pool_frame(pool, observation.resources, d, d.capacity_gi_b, explicit)?;
            journal.freeze_pool(
                &mut frame,
                d.capacity_gi_b,
                prior.is_none() && c == 0 && census.roots.is_empty(),
            )?;
            Ok(frame)
        })();
        match result {
            Ok(pool) => pools.push(pool),
            Err(error) => {
                // R2-2: a census cancelled by shutdown (or its bound) is not a
                // damaged pool; say what actually happened.
                if interrupted() {
                    tracing::info!(pool=%name, reason=%format!("{error:#}"),
                        "storage pool not observed: the census was interrupted");
                } else {
                    tracing::warn!(pool=%name, reason=%format!("{error:#}"),
                        "storage unavailable; restore original pool marker/backing storage and journal");
                }
                // Unbound pools have no identity to advertise. Bound pools retain
                // their last durable ceiling without pretending a healthy report.
                // An initially unavailable static tuple cannot authorize new roots
                // after health-only recovery: server newRootsAllowed freezes this
                // at hello, matching local admission. Reconnect must derive it.
                if let Some(pool) = expected
                    && let Some(mut frame) = journal.pool_snapshot(&pool.storage_id)
                {
                    frame.health = StorageHealth::Unavailable;
                    frame.reason = Some(StorageReason::Incomplete);
                    frame.total_bytes = None;
                    frame.used_bytes = None;
                    frame.free_bytes = None;
                    if let Some(explicit) = explicit {
                        frame.capacity_gi_b = explicit.capacity_gib;
                        frame.draining = explicit.draining;
                    }
                    if (explicit.is_none() && frame.capacity_source == CapacitySource::Implicit)
                        || (explicit.is_some() && frame.capacity_source == CapacitySource::Explicit)
                    {
                        pools.push(frame);
                    }
                }
            }
        }
    }
    Ok(pools)
}
fn pool_frame(
    pool: StoragePoolIdentity,
    resources: StorageResources,
    d: Derivation,
    p: u64,
    explicit: Option<&crate::config::StoragePoolConfig>,
) -> Result<StoragePoolV11> {
    anyhow::ensure!(
        resources.total_bytes() <= 9_007_199_254_740_991,
        "storage resources exceed wire scalar bounds"
    );
    let implicit = explicit.is_none();
    Ok(StoragePoolV11 {
        name: pool.name,
        marker: pool.storage_id,
        health: StorageHealth::Healthy,
        reason: None,
        total_bytes: Some(resources.total_bytes()),
        used_bytes: Some(resources.used_bytes()),
        free_bytes: Some(resources.free_bytes()),
        capacity_gi_b: explicit.map_or(d.capacity_gi_b.try_into()?, |p| p.capacity_gib),
        total_based_capacity_gi_b: implicit.then_some(d.total_based_capacity_gi_b),
        capacity_source: if implicit {
            CapacitySource::Implicit
        } else {
            CapacitySource::Explicit
        },
        derivation_total_bytes: implicit.then_some(d.total_bytes),
        derivation_free_bytes: implicit.then_some(d.free_bytes),
        derivation_committed_bytes: implicit.then_some(d.committed_bytes),
        derivation_actual_bytes: implicit.then_some(d.actual_bytes),
        derivation_headroom_bytes: implicit.then_some(d.headroom_bytes),
        implicit_ceiling_gi_b: implicit.then_some(p),
        draining: explicit.is_some_and(|p| p.draining),
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolInspection {
    pub name: Option<String>,
    pub source: &'static str,
    pub configured_capacity_gi_b: Option<u32>,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub total_based_capacity_gi_b: Option<u64>,
    pub effective: Option<StoragePoolV11>,
    pub error: Option<&'static str>,
}
/// No runtime construction, project initialization, marker writes or journal lock.
pub fn inspect(config: &Config) -> Vec<PoolInspection> {
    #[cfg(target_os = "linux")]
    {
        let c = sandbox_runtime::IncusConfig::from_env();
        let client = sandbox_runtime::IncusClient::new(c.binary, c.project);
        let names = if config.storage_pools.is_empty() {
            match sandbox_protocol::VmSize::defaults()
                .ok()
                .and_then(|s| client.profile_root_device(s).ok())
            {
                Some((_, name)) => vec![(name, None)],
                None => {
                    return vec![PoolInspection {
                        name: None,
                        source: "implicit",
                        configured_capacity_gi_b: None,
                        total_bytes: None,
                        free_bytes: None,
                        total_based_capacity_gi_b: None,
                        effective: None,
                        error: Some("profile-root pool inspection unavailable"),
                    }];
                }
            }
        } else {
            config
                .storage_pools
                .iter()
                .map(|p| (p.name.clone(), Some(p)))
                .collect()
        };
        let ledgers = crate::sandbox_relay::journal::storage::preview_ledgers();
        names.into_iter().map(|(name, explicit)| {
            let resources = client.storage_resources(&name).ok().map(|(_,r)|r);
            let effective = (|| -> Result<StoragePoolV11> {
                let pool = client.read_storage_marker(&name)?;
                let ledgers = ledgers.as_ref().map_err(|_|anyhow::anyhow!("journal preview unavailable"))?;
                let matching:Vec<_> = ledgers.iter().filter(|l|l.ceilings.contains_key(&pool.storage_id)).collect();
                anyhow::ensure!(matching.len() == 1,"missing or ambiguous original journal");
                let ledger=matching[0];
                let (_,p)=ledger.ceilings.get(&pool.storage_id).context("missing ceiling")?;
                let charged:Vec<_>=ledger.roots.iter().filter(|(_,r)|r.root().pool == pool).collect();
                let census=client.storage_root_census(&pool)?;
                anyhow::ensure!(census.roots.iter().all(|r|charged.iter().any(|(id,_)|sandbox_runtime::default_incus_instance_name(id)==r.instance_name)),"unbound root");
                let c=charged.iter().try_fold(0u64,|sum,(_,r)|sum.checked_add(u64::from(r.allocation.root_charge_gi_b)*GIB_BYTES).context("root commitment overflow"))?;
                let names:Vec<_>=charged.iter().map(|(id,_)|sandbox_runtime::default_incus_instance_name(id)).collect();
                let actual=client.storage_physical_usage(&pool,&names,c)?.charged_bytes;
                let observation=client.observe_storage_pool(&pool)?;
                let d=derive(observation.resources,c,actual,Some(*p))?;
                pool_frame(pool,observation.resources,d,d.capacity_gi_b.min(*p),explicit)
            })().ok();
            let error=effective.is_none().then_some("effective-cap-unavailable: original journal and healthy marker required; connect initializes an unbound pool");
            PoolInspection { name:Some(name),source:if explicit.is_some(){"toml"}else{"implicit"},configured_capacity_gi_b:explicit.map(|p|p.capacity_gib),total_bytes:resources.map(|r|r.total_bytes()),free_bytes:resources.map(|r|r.free_bytes()),total_based_capacity_gi_b:resources.and_then(|r|derive(r,0,0,None).ok()).map(|d|d.total_based_capacity_gi_b),effective,error }
        }).collect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Vec::new()
    }
}

/// Bounded parallel pool reads keep an unhealthy pool from delaying siblings.
pub fn observe_health(
    runtime: std::sync::Arc<dyn SandboxRuntime>,
    pools: &[StoragePoolV11],
) -> Vec<StorageHealthV11> {
    std::thread::scope(|scope| {
        let workers: Vec<_> = pools
            .iter()
            .map(|p| {
                let runtime = runtime.clone();
                scope.spawn(move || {
                    let runtime = runtime.with_cancellation(std::sync::Arc::new(
                        sandbox_runtime::RuntimePermit::with_timeout(
                            std::time::Duration::from_secs(4),
                        ),
                    ));
                    let pool = StoragePoolIdentity {
                        name: p.name.clone(),
                        storage_id: p.marker.clone(),
                    };
                    let result = runtime.observe_storage_pool(&pool);
                    let reason = result
                        .as_ref()
                        .err()
                        .map(|err| err.storage_reason().unwrap_or(StorageReason::Io));
                    let observation = result.ok();
                    StorageHealthV11 {
                        name: p.name.clone(),
                        marker: p.marker.clone(),
                        health: if observation.is_some() {
                            StorageHealth::Healthy
                        } else {
                            StorageHealth::Unavailable
                        },
                        reason,
                        total_bytes: observation.as_ref().map(|o| o.resources.total_bytes()),
                        used_bytes: observation.as_ref().map(|o| o.resources.used_bytes()),
                        free_bytes: observation.as_ref().map(|o| o.resources.free_bytes()),
                    }
                })
            })
            .collect();
        workers.into_iter().filter_map(|w| w.join().ok()).collect()
    })
}

pub fn admission_frame(
    journal: &HostJournal,
    connection_epoch: u32,
    runtime_kind: sandbox_protocol::RuntimeKind,
    egress_policy: bool,
    terminal: bool,
    capacity: &HostStaticCapacityV11,
) -> HostAdmissionV11 {
    HostAdmissionV11 {
        r#type: "host.admission".into(),
        journal_id: journal.instance_id().to_owned(),
        connection_epoch,
        runtime_kind,
        schedulable: true,
        egress_policy,
        terminal,
        image: None,
        vm_capacity: capacity.vm_capacity.clone(),
        storage_pools: capacity.storage_pools.clone(),
    }
}

#[cfg(test)]
#[path = "storage_capacity_tests.rs"]
mod tests;

/// The sole active 1.0 hello carries the frozen capacity tuple.
pub fn hello_frame(
    daemon: DaemonHelloV11,
    schedulable: bool,
    sandbox_count: u32,
    capacity: &HostStaticCapacityV11,
) -> HostHelloV11 {
    HostHelloV11 {
        r#type: "hello".into(),
        id: "hello-1".into(),
        protocol_version: RelayVersionV11::V11,
        supported_protocol_versions: vec![RelayVersionV11::V11],
        inventory: HostInventoryV11 {
            host_id: daemon.host_id.clone(),
            schedulable,
            sandbox_count,
        },
        daemon,
        vm_capacity: capacity.vm_capacity.clone(),
        storage_pools: capacity.storage_pools.clone(),
        quiescing: false,
    }
}
pub fn inventory_frame(
    host_id: &str,
    connection_epoch: u32,
    sequence: u64,
    sandbox_count: u32,
    storage_pools: Vec<StorageHealthV11>,
) -> HostInventoryUpdateV11 {
    HostInventoryUpdateV11 {
        r#type: "inventory.update".into(),
        id: format!("storage-{sequence}"),
        connection_epoch,
        observation_sequence: sequence,
        inventory: HostInventoryV11 {
            host_id: host_id.into(),
            schedulable: true,
            sandbox_count,
        },
        storage_pools,
    }
}

/// Reconstruct live facts independently of retained-root lifetime. An unreadable
/// original pool preserves the durable possible-live charge.
pub fn reconstruct_live(runtime: &dyn SandboxRuntime, journal: &HostJournal) -> Result<()> {
    reconstruct_live_except(runtime, journal, &std::collections::HashSet::new())
}

/// [`reconstruct_live`] that leaves `busy` sandboxes alone: work carried
/// across a relay transport drop (or queued/active lifecycle work) may still
/// create or start that VM, so absence observed now proves nothing about it.
pub fn reconstruct_live_except(
    runtime: &dyn SandboxRuntime,
    journal: &HostJournal,
    busy: &std::collections::HashSet<String>,
) -> Result<()> {
    for (id, root) in journal.retained_roots() {
        if busy.contains(&id) {
            continue;
        }
        // A crash between the retained-root snapshot and the first receipt
        // cannot have issued Effect. Reclaim only with fresh root AND settled
        // VM/network absence; the journal rechecks every obligation afterward.
        if journal.root_never_issued(&id, root.generation)
            && matches!(runtime.query_sandbox(&id, None, None), Ok(None))
            && let Ok(proof) = runtime.prove_root_absent(
                &root.root(),
                &sandbox_runtime::default_incus_instance_name(&id),
            )
        {
            journal.release_never_issued_root(&id, root.generation, &proof)?;
            continue;
        }
        if runtime.observe_storage_pool(&root.root().pool).is_ok()
            && matches!(runtime.sandbox_may_be_running(&id), Ok(false))
            && runtime.observe_storage_pool(&root.root().pool).is_ok()
        {
            journal.release_retained(&id, root.generation, false)?;
        }
    }
    Ok(())
}
