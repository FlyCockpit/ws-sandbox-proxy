//! Session-owned periodic host-state reports whose server-side record has a
//! TTL that a dispatch or an Intent-phase adoption re-checks:
//!
//! - `host.egress-state` (§2.5): the egress-guard lease, 15 s
//!   (`EGRESS_GUARD_LEASE_MS`), checked by the create egress gate.
//! - `inventory.update` storage health: a pool observation is fresh for 15 s
//!   (`STORAGE_HEALTH_STALE_MS`), checked by the retained-storage gate of a
//!   create or a cold reconnect.
//!
//! A hello resets both on the server (the guard lease to none, storage to the
//! hello's own observation), so they are renewed on the session's cadence
//! from `hello.ok` on: by the reconciliation readers (receipts, adoption,
//! audit, census) and then by the dispatch loop, through this one owner. A
//! reconnect's adoption of a create that issued nothing yet re-runs those
//! gates; renewing only from the dispatch loop (after `reconcile.complete`)
//! refused every such adoption.
//!
//! Cadence uses an injected [`LeaseClock`] (real elapsed time; tests step a
//! fake one). Every report is the live verdict: an unhealthy guard or pool is
//! reported as such, and the server refuses exactly as it would a dispatch.
use super::clock::LeaseClock;
use super::egress_state::{EGRESS_STATE_INTERVAL, EgressReport, NodeEgress};
use anyhow::{Context, Result};
use sandbox_protocol::capacity_v11::{StorageHealthV11, StoragePoolV11};
use sandbox_protocol::{DaemonControlMessage, HostInventorySnapshot, WireCodes};
use std::sync::{Arc, mpsc};

/// An observation older than this is never published, and local admission
/// treats storage health as unknown once the last fresh one is this old. The
/// server's `STORAGE_HEALTH_STALE_MS` uses the same bound.
pub(super) const STORAGE_FRESH_MS: u64 = 15_000;

/// The storage poll period: production's, or a debug test daemon's
/// widening (5-10 s, validated by `test_timing`).
fn storage_poll_ms() -> u64 {
    #[cfg(debug_assertions)]
    return storage_poll_ms_for(super::test_timing::installed_runtime_test_timing());
    #[cfg(not(debug_assertions))]
    super::test_timing::STORAGE_POLL_MS
}

/// [`storage_poll_ms`] for the given `WSSP_TEST_RUNTIME_TIMING` override.
#[cfg(debug_assertions)]
pub(super) fn storage_poll_ms_for(timing: Option<super::test_timing::RuntimeTestTiming>) -> u64 {
    timing
        .and_then(|timing| timing.storage_poll)
        .map_or(super::test_timing::STORAGE_POLL_MS, |poll| {
            u64::try_from(poll.as_millis()).unwrap_or(super::test_timing::STORAGE_POLL_MS)
        })
}

type Socket = tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>;
type Observation = (Vec<StorageHealthV11>, u64);

pub(super) struct HostReports {
    clock: Arc<LeaseClock>,
    host_id: String,
    sandbox_count: u32,
    /// This session's epoch and vocabulary, from `hello.ok`. Nothing is sent
    /// before it; storage is still observed for local admission.
    session: Option<(u32, WireCodes)>,
    egress: Option<Arc<NodeEgress>>,
    egress_sequence: u64,
    egress_last: Option<(EgressReport, u64)>,
    /// `NodeEgress::progress` at the last report: a push or a guard turning
    /// healthy is reported at once, not at the next renewal.
    egress_progress_sent: u64,
    runtime: Arc<dyn sandbox_runtime::SandboxRuntime>,
    pools: Vec<StoragePoolV11>,
    observer: Option<mpsc::SyncSender<Box<dyn FnOnce() + Send>>>,
    health_tx: mpsc::SyncSender<Observation>,
    health_rx: mpsc::Receiver<Observation>,
    observing: bool,
    poll_at: Option<u64>,
    fresh_at: u64,
    storage_sequence: u64,
    /// Storage publication paused (reconciliation census, see `hold_storage`).
    storage_held: bool,
    /// The last fresh observation, for local admission.
    health: Option<Vec<StorageHealthV11>>,
    /// WP2: whether the host may be placed on (false once the journal IO
    /// latch is set), carried by every storage report.
    schedulable: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Pool health as of [`Self::storage_sequence`] (the hello's own
    /// observation until the first report): what the server judges root
    /// evidence stamped with that sequence against (WP2 re-offers).
    published: super::evidence::PoolHealth,
}

impl HostReports {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<LeaseClock>,
        host_id: String,
        sandbox_count: u32,
        egress: Option<Arc<NodeEgress>>,
        runtime: Arc<dyn sandbox_runtime::SandboxRuntime>,
        pools: Vec<StoragePoolV11>,
        observer: Option<mpsc::SyncSender<Box<dyn FnOnce() + Send>>>,
        schedulable: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Self> {
        let (health_tx, health_rx) = mpsc::sync_channel(1);
        let published = pools
            .iter()
            .map(|pool| {
                (
                    pool.name.clone(),
                    pool.marker.clone(),
                    pool.health == sandbox_protocol::capacity_v11::StorageHealth::Healthy,
                )
            })
            .collect();
        Ok(Self {
            fresh_at: clock.now_ms()?,
            clock,
            host_id,
            sandbox_count,
            session: None,
            egress,
            egress_sequence: 0,
            egress_last: None,
            egress_progress_sent: 0,
            runtime,
            pools,
            observer,
            health_tx,
            health_rx,
            observing: false,
            poll_at: None,
            storage_sequence: 0,
            storage_held: false,
            health: None,
            schedulable,
            published,
        })
    }

    /// `hello.ok`: reports flow on this epoch from now on.
    pub fn attach(&mut self, epoch: u64, wire: WireCodes) -> Result<()> {
        self.session = Some((u32::try_from(epoch)?, wire));
        Ok(())
    }

    /// The sequence of the last published storage observation. Root evidence
    /// observed after it (the reconciliation census) carries it: the server
    /// refuses root evidence older than the pool's last observation.
    pub fn storage_sequence(&self) -> u64 {
        self.storage_sequence
    }

    /// Pool health as published with [`Self::storage_sequence`].
    pub fn published_health(&self) -> super::evidence::PoolHealth {
        self.published.clone()
    }

    /// Pause (or resume) storage observation and publication while census
    /// root evidence stamped with [`Self::storage_sequence`] is collected and
    /// sent: a newer observation reaching the server first would make that
    /// evidence stale. The pause spans one page's root-observation window;
    /// the egress lease keeps renewing.
    pub fn hold_storage(&mut self, held: bool) {
        self.storage_held = held;
    }

    /// No fresh storage observation for the freshness bound.
    pub fn storage_expired(&self) -> Result<bool> {
        Ok(self.clock.now_ms()?.saturating_sub(self.fresh_at) >= STORAGE_FRESH_MS)
    }

    /// The newest fresh observation not yet taken (local admission).
    pub fn take_health(&mut self) -> Option<Vec<StorageHealthV11>> {
        self.health.take()
    }

    /// Sends every report that is due. Cheap when nothing is: called from
    /// every socket read of the session.
    pub fn tick(&mut self, socket: &mut Socket) -> Result<()> {
        let now = self.clock.now_ms()?;
        self.tick_egress(socket, now)?;
        self.tick_storage(socket, now)
    }

    fn tick_egress(&mut self, socket: &mut Socket, now: u64) -> Result<()> {
        let (Some((epoch, _)), Some(node)) = (self.session, &self.egress) else {
            return Ok(());
        };
        let progress = node.progress();
        let report = node.report();
        let interval = u64::try_from(EGRESS_STATE_INTERVAL.as_millis())?;
        let due = match &self.egress_last {
            None => true,
            Some((last, at)) => {
                !last.same_state(&report)
                    || progress != self.egress_progress_sent
                    || now.saturating_sub(*at) >= interval
            }
        };
        if !due {
            return Ok(());
        }
        self.egress_sequence += 1;
        socket.send(tungstenite::Message::Text(
            super::plain_frame(&DaemonControlMessage::HostEgressState(
                report.message(epoch, self.egress_sequence),
            ))?
            .into(),
        ))?;
        self.egress_last = Some((report, now));
        self.egress_progress_sent = progress;
        Ok(())
    }

    fn tick_storage(&mut self, socket: &mut Socket, now: u64) -> Result<()> {
        if let Ok((health, started)) = self.health_rx.try_recv() {
            self.observing = false;
            // Queuing behind other work must not make an old healthy
            // snapshot fresh again; a held session drops it unpublished.
            if !self.storage_held && now.saturating_sub(started) < STORAGE_FRESH_MS {
                self.fresh_at = started;
                self.storage_sequence = self
                    .storage_sequence
                    .checked_add(1)
                    .context("storage observation sequence exhausted")?;
                if let Some((epoch, wire)) = self.session {
                    let update = DaemonControlMessage::InventoryUpdate {
                        id: format!("storage-{}", self.storage_sequence),
                        connection_epoch: epoch,
                        observation_sequence: self.storage_sequence,
                        inventory: HostInventorySnapshot {
                            host_id: self.host_id.clone(),
                            schedulable: (self.schedulable)(),
                            sandbox_count: self.sandbox_count,
                        },
                        storage_pools: health.clone(),
                    };
                    socket.send(tungstenite::Message::Text(
                        super::spell(wire, &update, None)?.into(),
                    ))?;
                }
                self.published = health
                    .iter()
                    .map(|pool| {
                        (
                            pool.name.clone(),
                            pool.marker.clone(),
                            pool.health == sandbox_protocol::capacity_v11::StorageHealth::Healthy,
                        )
                    })
                    .collect();
                self.health = Some(health);
            }
        }
        if self.observing
            || self.storage_held
            || self
                .poll_at
                .is_some_and(|at| now.saturating_sub(at) < storage_poll_ms())
        {
            return Ok(());
        }
        let Some(observer) = &self.observer else {
            return Ok(());
        };
        let (runtime, pools, tx, clock) = (
            self.runtime.clone(),
            self.pools.clone(),
            self.health_tx.clone(),
            self.clock.clone(),
        );
        // Health publication never waits for network policy or a root census.
        let work: Box<dyn FnOnce() + Send> = Box::new(move || {
            // A clock failure publishes nothing (never fresh), and the
            // next poll retries.
            let started = clock.now_ms().unwrap_or(0);
            let health = crate::storage_capacity::observe_health(runtime, &pools);
            let _ = tx.try_send((health, started));
        });
        if observer.try_send(work).is_ok() {
            self.observing = true;
            self.poll_at = Some(now);
        }
        Ok(())
    }
}
