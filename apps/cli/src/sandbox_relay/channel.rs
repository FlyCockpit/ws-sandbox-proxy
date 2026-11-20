//! CLI channels on the node (wssp-ssh): `channel.*` frames from the server
//! drive one guest process each (`pty` or `exec`), started by the runtime in
//! its own guest scope as the sandbox's guest user.
//!
//! One decider. [`ChannelHost`] lives on the socket thread and owns every
//! wire-visible fact of every channel (phase, sequence numbers, credit,
//! eofs, timers) and the channel's byte IO ([`ChannelIo`], non-blocking). It
//! makes every decision in one place: [`Chan::decide`] is the only close
//! path, and [`Chan::finish`] the only emitter of `channel.exit`. Because the
//! decision, every stdin hand-over, every guest read and every data frame
//! run on this one thread, nothing crosses a channel after its close
//! decision. A tick never blocks: it queues its frames, and the socket
//! writes follow once it has decided everything, so a blocking write never
//! separates a check from the action it guards. A guest read happens only
//! when its frame can be sent at once; the frame then waits at most for the
//! rest of its tick's flush.
//!
//! Each channel also has a custodian thread ([`custodian`]): it holds the
//! process ([`ChannelCustody`]), the capacity slot and the durable registry
//! entry, and decides nothing. It spawns (that carries no secret and starts
//! no workload: the guest waits for the preamble the socket thread writes),
//! then closes exactly as ordered, answers every order with one `Ended`,
//! and settles (reap, retried scope kills). Two fixed rules: a vanished
//! owner (relay loss) means kill, and the channel's absolute deadline means
//! kill. The only lock left is [`ChannelSlots`]' counter.
//!
//! Phases: `Opening → Starting → Running → Draining → Closing → Unsettled →
//! (removed)`. Close semantics follow sshd: a `client` close is a normal
//! close (the session hangs up; detached processes survive). Every other
//! close (revoke, lifecycle, protocol, limits, relay loss, shutdown) and
//! every close before READY kill-closes the channel's guest scope and proves
//! it gone before its capacity is released.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use sandbox_protocol::{
    CHANNEL_BULK_DATA_MAX_BYTES, CHANNEL_BULK_WINDOW_FRAMES, CHANNEL_FENCE_VIOLATION_LIMIT,
    CHANNEL_MAX_CHANNELS_PER_GUEST_CREATOR, CHANNEL_MAX_CHANNELS_PER_HOST,
    CHANNEL_MAX_PTY_CHANNELS_PER_HOST, CHANNEL_OPENS_PER_MINUTE_PER_GUEST_CREATOR,
    CHANNEL_OPENS_PER_MINUTE_PER_HOST, CHANNEL_PTY_DATA_MAX_BYTES, CHANNEL_PTY_WINDOW_FRAMES,
    ChannelCloseIntent, ChannelDataKind, ChannelDataMetadata, ChannelExitFrames, ChannelFence,
    ChannelKind, ChannelNotice, ChannelPtyParams, ChannelPtySize, ChannelSignal, ChannelStream,
    ChannelTarget, ChannelsCapability, DaemonControlMessage, OperationDispatch,
    ProtocolErrorDetail, SandboxErrorCode, ServerControlMessage, encode_channel_frame,
};
use sandbox_runtime::{
    ChannelBirth, ChannelClose, ChannelCustody, ChannelEnd, ChannelExitStatus, ChannelIo,
    ChannelMode, ChannelOutput, ChannelRead, ChannelScope, ChannelScopeRef, ChannelSignalOutcome,
    FrameFilter, GuestFrame, GuestIdentity, KillScopesRequest, ProcessSignal, PtySize,
    SandboxRuntime, ScopeKill, SpawnChannelRequest,
};

use super::authority::HostAuthority;
use super::journal::{HostJournal, TransportBindingV11};
use super::terminal::Outgoing;

const AUDIT_LOGS: usize = 16;
const OPEN_RATE_WINDOW: Duration = Duration::from_secs(60);
/// The guest must report READY within this bound of the open (spawn,
/// prompt, preamble), or the channel is kill-closed.
const SETUP_DEADLINE: Duration = Duration::from_secs(30);
/// A channel whose oldest unacknowledged output frame is this old closes with
/// `backpressure` (clients acknowledge delivered output promptly).
const STALL_TIMEOUT: Duration = Duration::from_secs(60);
/// After the wrapper's EXIT: end once every open stream proved idle (2 s
/// after EXIT) or at the hard cap (60 s after EXIT), whichever is first.
const EXIT_DRAIN: Duration = Duration::from_secs(2);
const EXIT_DRAIN_MAX: Duration = Duration::from_secs(60);
/// A stream is idle when reads with credit found nothing for this long.
const IDLE_PROOF: Duration = Duration::from_millis(250);
/// Retry cadence of an uncertain scope kill.
#[cfg(not(test))]
const SETTLE_RETRY: Duration = Duration::from_secs(30);
/// Unit tests retry fast so an uncertain kill settles within a test.
#[cfg(test)]
const SETTLE_RETRY: Duration = Duration::from_millis(100);
/// The custodian's own deadline kill sits this far past the owner's, so the
/// owner normally decides expiry itself (the custodian's rule is the
/// backstop for a blocked or vanished owner).
const CUSTODY_DEADLINE_MARGIN: Duration = Duration::from_secs(2);
/// How often an idle custodian looks at its lanes and its deadline.
const CUSTODY_POLL: Duration = Duration::from_millis(20);
const ENDED_TOMBSTONES: usize = 256;
/// Data frames forwarded per socket-loop tick across every channel.
const TICK_DATA_FRAMES: usize = 16;
/// Unacknowledged output frames across the host (4 MiB of bulk frames): half
/// the relay's serialized-queue high water, so bulk alone never pauses it.
const HOST_UNACKED_FRAMES: u64 = 128;
/// One sandbox owner's share of the host cap, so no single tenant can hold
/// all of it.
const CREATOR_UNACKED_FRAMES: u64 = HOST_UNACKED_FRAMES / 2;
/// Group signals in flight per channel (more: `state_conflict`).
const SIGNALS_IN_FLIGHT: usize = 4;
/// Durable registry entries: `<journal dir>/channel-scope-<unit>`.
const REGISTRY_PREFIX: &str = "channel-scope-";
const REGISTRY_VERSION: &str = "wssp-channel-scope-v1";
/// The node offers these kinds when its runtime implements channels.
pub(super) const OFFERED_KINDS: [ChannelKind; 2] = [ChannelKind::Pty, ChannelKind::Exec];

/// The hello's `channels` offer.
pub(super) fn capability(runtime: &dyn SandboxRuntime) -> Option<ChannelsCapability> {
    runtime.channel_capability().then(|| ChannelsCapability {
        kinds: OFFERED_KINDS.to_vec(),
    })
}

fn window(kind: ChannelKind) -> u64 {
    match kind {
        ChannelKind::Pty => CHANNEL_PTY_WINDOW_FRAMES,
        ChannelKind::Exec => CHANNEL_BULK_WINDOW_FRAMES,
    }
}

fn frame_bytes(kind: ChannelKind) -> usize {
    match kind {
        ChannelKind::Pty => CHANNEL_PTY_DATA_MAX_BYTES,
        ChannelKind::Exec => CHANNEL_BULK_DATA_MAX_BYTES,
    }
}

// ------------------------------------------------------------ capacity ----

#[derive(Debug, Default)]
struct SlotState {
    live: usize,
    pty: usize,
    per_creator: HashMap<String, usize>,
    opens: VecDeque<(Instant, String)>,
    /// Scope units of every channel of this process whose end is not settled
    /// (across reconnects): a unit is never admitted twice.
    units: BTreeSet<String>,
}

/// Process-wide channel capacity; a slot is charged until its channel's end
/// is settled (client reaped and scope released or proven killed).
#[derive(Debug, Default)]
pub(super) struct ChannelSlots {
    state: Mutex<SlotState>,
    idle: Condvar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotRefusal {
    RateLimited,
    HostCapacity,
    /// The scope unit belongs to a channel that is not settled yet.
    InUse,
}

#[derive(Debug)]
struct SlotGuard {
    slots: Arc<ChannelSlots>,
    pty: bool,
    creator: String,
    unit: Option<String>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut state = self.slots.lock();
        state.live = state.live.saturating_sub(1);
        if self.pty {
            state.pty = state.pty.saturating_sub(1);
        }
        if let Some(count) = state.per_creator.get_mut(&self.creator) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_creator.remove(&self.creator);
            }
        }
        if let Some(unit) = &self.unit {
            state.units.remove(unit);
        }
        drop(state);
        self.slots.idle.notify_all();
    }
}

impl ChannelSlots {
    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Check and charge in one step; `unit` is reserved until the slot drops
    /// (the custodian drops it after the settled end).
    fn try_acquire(
        self: &Arc<Self>,
        pty: bool,
        creator: &str,
        unit: Option<&str>,
        now: Instant,
    ) -> Result<SlotGuard, SlotRefusal> {
        let mut state = self.lock();
        if unit.is_some_and(|unit| state.units.contains(unit)) {
            return Err(SlotRefusal::InUse);
        }
        while state
            .opens
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= OPEN_RATE_WINDOW)
        {
            state.opens.pop_front();
        }
        let creator_opens = state.opens.iter().filter(|(_, c)| c == creator).count();
        if state.opens.len() >= CHANNEL_OPENS_PER_MINUTE_PER_HOST
            || creator_opens >= CHANNEL_OPENS_PER_MINUTE_PER_GUEST_CREATOR
        {
            return Err(SlotRefusal::RateLimited);
        }
        let per_creator = state.per_creator.get(creator).copied().unwrap_or(0);
        if state.live >= CHANNEL_MAX_CHANNELS_PER_HOST
            || (pty && state.pty >= CHANNEL_MAX_PTY_CHANNELS_PER_HOST)
            || per_creator >= CHANNEL_MAX_CHANNELS_PER_GUEST_CREATOR
        {
            return Err(SlotRefusal::HostCapacity);
        }
        state.opens.push_back((now, creator.to_string()));
        state.live += 1;
        if pty {
            state.pty += 1;
        }
        *state.per_creator.entry(creator.to_string()).or_default() += 1;
        if let Some(unit) = unit {
            state.units.insert(unit.to_string());
        }
        Ok(SlotGuard {
            slots: self.clone(),
            pty,
            creator: creator.to_string(),
            unit: unit.map(str::to_string),
        })
    }

    #[cfg(test)]
    pub(super) fn live(&self) -> usize {
        self.lock().live
    }

    /// Wait (bounded) until every channel slot is released. Shutdown only.
    pub(super) fn wait_idle(&self, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        let mut state = self.lock();
        while state.live > 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            state = self
                .idle
                .wait_timeout(state, remaining)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|e| e.into_inner().0);
        }
        true
    }
}

// ------------------------------------------------------------ registry ----

/// One durable entry: a channel scope whose cleanup is not settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RegistryEntry {
    pub unit: String,
    pub sandbox_id: String,
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
}

impl RegistryEntry {
    fn encode(&self) -> Vec<u8> {
        format!(
            "{REGISTRY_VERSION}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.unit,
            self.sandbox_id,
            self.template_fingerprint,
            self.guest.guest_uid,
            self.guest.guest_gid,
            self.guest.guest_home,
            self.guest.guest_shell
        )
        .into_bytes()
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let lines: Vec<&str> = text.strip_suffix('\n')?.split('\n').collect();
        let [
            version,
            unit,
            sandbox_id,
            fingerprint,
            uid,
            gid,
            home,
            shell,
        ] = lines.as_slice()
        else {
            return None;
        };
        if *version != REGISTRY_VERSION {
            return None;
        }
        sandbox_runtime::validate_channel_scope_unit(unit).ok()?;
        let guest = GuestIdentity {
            guest_uid: uid.parse().ok()?,
            guest_gid: gid.parse().ok()?,
            guest_home: home.to_string(),
            guest_shell: shell.to_string(),
        };
        guest.validate().ok()?;
        Some(Self {
            unit: unit.to_string(),
            sandbox_id: sandbox_id.to_string(),
            template_fingerprint: fingerprint.to_string(),
            guest,
        })
    }
}

/// The durable active-channel registry in the journal directory (host side;
/// the guest cannot touch it).
pub(super) struct ChannelRegistry {
    journal: Arc<HostJournal>,
}

impl ChannelRegistry {
    pub(super) fn new(journal: Arc<HostJournal>) -> Self {
        Self { journal }
    }

    fn name(unit: &str) -> String {
        format!("{REGISTRY_PREFIX}{unit}")
    }

    fn record(&self, entry: &RegistryEntry) -> Result<()> {
        self.journal
            .persist_marker(&Self::name(&entry.unit), &entry.encode())
    }

    fn contains(&self, unit: &str) -> bool {
        self.dir()
            .is_some_and(|dir| dir.join(Self::name(unit)).exists())
    }

    fn forget(&self, unit: &str) -> Result<()> {
        self.journal.remove_marker(&Self::name(unit))
    }

    fn dir(&self) -> Option<PathBuf> {
        self.journal.state_dir().map(Path::to_path_buf)
    }

    /// Every readable entry; unreadable ones are reported and skipped.
    pub(super) fn entries(&self) -> Vec<RegistryEntry> {
        let Some(dir) = self.dir() else {
            return Vec::new();
        };
        let Ok(listing) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut entries = Vec::new();
        for item in listing.flatten() {
            let name = item.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(unit) = name.strip_prefix(REGISTRY_PREFIX) else {
                continue;
            };
            match std::fs::read(item.path())
                .ok()
                .and_then(|bytes| RegistryEntry::decode(&bytes))
            {
                Some(entry) if entry.unit == unit => entries.push(entry),
                _ => tracing::warn!("ignoring an unreadable channel registry entry"),
            }
        }
        entries
    }
}

/// Daemon start: kill exactly the registered scopes of a previous process
/// (each sandbox in one batch), forget the proven ones, retry the rest.
pub(super) fn sweep_registry(runtime: Arc<dyn SandboxRuntime>, registry: Arc<ChannelRegistry>) {
    // Synchronous, before this process can open any channel.
    let snapshot: Vec<RegistryEntry> = registry.entries();
    let spawned = thread::Builder::new()
        .name("wssp-channel-sweep".into())
        .spawn(move || {
            // Only the entries of a previous process: a snapshot taken before
            // this process opens any channel. Channels opened later write
            // their own entries and are never swept while they run.
            let mut pending = snapshot;
            loop {
                if pending.is_empty() {
                    return;
                }
                let entries = std::mem::take(&mut pending);
                let mut by_sandbox: HashMap<(String, String), Vec<RegistryEntry>> =
                    HashMap::new();
                for entry in entries {
                    by_sandbox
                        .entry((entry.sandbox_id.clone(), entry.template_fingerprint.clone()))
                        .or_default()
                        .push(entry);
                }
                for ((sandbox_id, fingerprint), entries) in by_sandbox {
                    let request = KillScopesRequest {
                        sandbox_id,
                        template_fingerprint: fingerprint,
                        guest: entries[0].guest.clone(),
                        scopes: entries
                            .iter()
                            .map(|entry| ChannelScopeRef {
                                unit: entry.unit.clone(),
                                forget: false,
                            })
                            .collect(),
                    };
                    let gone: BTreeSet<String> = match runtime.kill_channel_scopes(&request) {
                        Ok(results) => results
                            .into_iter()
                            .filter(|(_, kill)| *kill == ScopeKill::Gone)
                            .map(|(unit, _)| unit)
                            .collect(),
                        Err(error) => {
                            tracing::warn!(code = ?error.code, "channel scope sweep failed; retrying");
                            BTreeSet::new()
                        }
                    };
                    for entry in entries {
                        if gone.contains(&entry.unit) {
                            if registry.forget(&entry.unit).is_err() {
                                tracing::warn!("channel registry entry removal failed");
                                pending.push(entry);
                            }
                        } else {
                            pending.push(entry);
                        }
                    }
                }
                thread::sleep(SETTLE_RETRY);
            }
        });
    if spawned.is_err() {
        tracing::warn!("channel scope sweep could not start; the next start retries");
    }
}

// ----------------------------------------------------------- custodian ----

/// Owner → custodian orders. At most: one close, one kill upgrade, `Done`.
enum Order {
    Close(ChannelClose),
    /// The owner reported the settled end and forgets the channel.
    Done,
}

/// Custodian → owner events. The custodian never blocks on the owner.
enum Evt {
    Spawned(Box<dyn ChannelIo>),
    /// The spawn failed; an `Ended` follows.
    OpenFailed(SandboxErrorCode),
    Signal(ChannelSignalOutcome),
    /// The current end; `answers` marks the one reply to a close order
    /// (otherwise an update: a deadline kill, a settled reap or retry).
    Ended {
        end: ChannelEnd,
        answers: bool,
    },
}

struct Custodian {
    runtime: Arc<dyn SandboxRuntime>,
    registry: Arc<ChannelRegistry>,
    entry: RegistryEntry,
    orders: mpsc::Receiver<Order>,
    signals: mpsc::Receiver<(ChannelBirth, ProcessSignal)>,
    events: mpsc::Sender<Evt>,
    /// Absolute end of the channel's life, fixed at admission.
    deadline: Instant,
    custody: Option<Box<dyn ChannelCustody>>,
    end: Option<ChannelEnd>,
    /// The host client was ended (after a close with a settled scope, or a
    /// later kill proof).
    terminated: bool,
    next_kill: Instant,
    /// The owner sent `Done` or vanished: nobody to report to any more.
    released: bool,
    /// The deadline rule ran.
    deadline_killed: bool,
}

/// Nothing was spawned, so no scope exists.
const NOTHING_SPAWNED: ChannelEnd = ChannelEnd {
    reaped: true,
    scope: ChannelScope::Released,
};

impl Custodian {
    fn send(&self, event: Evt) {
        let _ = self.events.send(event);
    }

    fn kill_scope(&self, forget: bool) -> ChannelScope {
        let request = KillScopesRequest {
            sandbox_id: self.entry.sandbox_id.clone(),
            template_fingerprint: self.entry.template_fingerprint.clone(),
            guest: self.entry.guest.clone(),
            scopes: vec![ChannelScopeRef {
                unit: self.entry.unit.clone(),
                forget,
            }],
        };
        let gone = self
            .runtime
            .kill_channel_scopes(&request)
            .is_ok_and(|results| results.iter().all(|(_, kill)| *kill == ScopeKill::Gone));
        if gone {
            ChannelScope::Killed
        } else {
            ChannelScope::Uncertain
        }
    }

    /// Close as told (first close), or upgrade a released scope to a kill.
    fn close(&mut self, how: ChannelClose) -> ChannelEnd {
        match self.end {
            None => {
                let end = match &mut self.custody {
                    Some(custody) => custody.close(how),
                    None => NOTHING_SPAWNED,
                };
                self.terminated = end.scope != ChannelScope::Uncertain;
                self.next_kill = Instant::now() + SETTLE_RETRY;
                self.end = Some(end);
                end
            }
            Some(mut end) => {
                if let ChannelClose::Kill { forget } = how
                    && end.scope == ChannelScope::Released
                    && self.custody.is_some()
                {
                    end.scope = self.kill_scope(forget);
                    self.next_kill = Instant::now() + SETTLE_RETRY;
                    self.end = Some(end);
                }
                end
            }
        }
    }

    /// Reap and retry an unproven kill; report what changed.
    fn reconcile(&mut self) {
        let Some(mut end) = self.end else { return };
        let before = end;
        if end.scope == ChannelScope::Uncertain && Instant::now() >= self.next_kill {
            end.scope = self.kill_scope(false);
            self.next_kill = Instant::now() + SETTLE_RETRY;
        }
        match &mut self.custody {
            None => end.reaped = true,
            // The scope is proven gone now: end the client and release stdin
            // (also when the client already exited on its own).
            Some(custody) if !self.terminated && end.scope != ChannelScope::Uncertain => {
                self.terminated = true;
                end.reaped = custody.terminate() || end.reaped;
            }
            Some(custody) if !end.reaped => end.reaped = custody.reap_confirmed(),
            Some(_) => {}
        }
        self.end = Some(end);
        if end != before && !self.released {
            self.send(Evt::Ended {
                end,
                answers: false,
            });
        }
    }

    fn settled(&self) -> bool {
        self.end.is_some_and(|end| end.settled())
    }

    fn run(mut self, request: SpawnChannelRequest, slot: SlotGuard) {
        // Durable first: a crash after this point leaves an entry the next
        // start's sweep kills; nothing launches without it.
        let recorded = self.registry.record(&self.entry).is_ok();
        let before_spawn = match self.orders.try_recv() {
            Ok(Order::Close(_)) => Some(true),
            Ok(Order::Done) | Err(mpsc::TryRecvError::Disconnected) => Some(false),
            Err(mpsc::TryRecvError::Empty) => None,
        };
        if !recorded {
            self.send(Evt::OpenFailed(SandboxErrorCode::Internal));
            self.end = Some(NOTHING_SPAWNED);
            self.send(Evt::Ended {
                end: NOTHING_SPAWNED,
                answers: before_spawn == Some(true),
            });
            if before_spawn == Some(false) {
                self.released = true;
            }
        } else if let Some(answers) = before_spawn {
            // Closed (or the owner vanished) before the spawn: nothing runs.
            self.end = Some(NOTHING_SPAWNED);
            self.released = !answers;
            self.send(Evt::Ended {
                end: NOTHING_SPAWNED,
                answers,
            });
        } else if Instant::now() >= self.deadline {
            self.end = Some(NOTHING_SPAWNED);
            self.send(Evt::Ended {
                end: NOTHING_SPAWNED,
                answers: false,
            });
        } else {
            match self.runtime.spawn_channel(&request) {
                Ok(spawned) => {
                    self.custody = Some(spawned.custody);
                    self.send(Evt::Spawned(spawned.io));
                }
                Err(failure) => {
                    self.send(Evt::OpenFailed(failure.error.code));
                    let end = match failure.custody {
                        Some(mut custody) => {
                            let end = custody.close(ChannelClose::Kill { forget: false });
                            self.terminated = end.scope != ChannelScope::Uncertain;
                            self.custody = Some(custody);
                            end
                        }
                        None => NOTHING_SPAWNED,
                    };
                    self.next_kill = Instant::now() + SETTLE_RETRY;
                    self.end = Some(end);
                    self.send(Evt::Ended {
                        end,
                        answers: false,
                    });
                }
            }
        }
        self.serve();
        if recorded && self.registry.forget(&self.entry.unit).is_err() {
            tracing::warn!("channel registry entry removal failed; the next start sweeps it");
        }
        // The end is settled: the process (if any) is reaped and its scope
        // released or proven gone.
        drop(self.custody.take());
        drop(slot);
    }

    fn serve(&mut self) {
        loop {
            self.reconcile();
            if self.released && self.settled() {
                return;
            }
            // Orders first, then the deadline, then at most one signal: a
            // close never waits behind queued signals, only behind the one
            // helper already running.
            match self.orders.try_recv() {
                Ok(order) => {
                    self.on_order(order);
                    continue;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.owner_gone();
                    continue;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            // Fixed rule: the absolute deadline kills, until `Done` also a
            // released scope (a normal close or natural end still settling).
            if !self.deadline_killed && !self.released && Instant::now() >= self.deadline {
                self.deadline_killed = true;
                let end = self.close(ChannelClose::Kill { forget: false });
                self.send(Evt::Ended {
                    end,
                    answers: false,
                });
                continue;
            }
            if let Ok((birth, signal)) = self.signals.try_recv() {
                let outcome = match (&mut self.custody, self.end) {
                    (Some(custody), None) => custody.signal(&birth, signal),
                    _ => ChannelSignalOutcome::Ended,
                };
                if !self.released {
                    self.send(Evt::Signal(outcome));
                }
                continue;
            }
            match self.orders.recv_timeout(CUSTODY_POLL) {
                Ok(order) => self.on_order(order),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => self.owner_gone(),
            }
        }
    }

    fn on_order(&mut self, order: Order) {
        match order {
            Order::Close(how) => {
                let end = self.close(how);
                self.send(Evt::Ended { end, answers: true });
            }
            Order::Done => self.released = true,
        }
    }

    /// Fixed rule: a vanished owner (relay loss) before `Done` kills, a
    /// released scope too.
    fn owner_gone(&mut self) {
        if !self.released {
            self.released = true;
            self.close(ChannelClose::Kill { forget: false });
        }
        if !self.settled() {
            thread::sleep(CUSTODY_POLL);
        }
    }
}

// --------------------------------------------------------------- owner ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The custodian is recording the registry entry and spawning.
    Opening,
    /// Spawned: waiting for PROMPT, writing the preamble, waiting for READY.
    Starting,
    Running,
    /// The wrapper's EXIT was read; output drains until [`end_due`].
    Draining {
        exit_at: Instant,
    },
    /// Decided (or ended): the IO is gone, orders are outstanding.
    Closing,
    /// `channel.exit{reaped: false}` was sent; waiting for the settled end.
    Unsettled,
}

#[derive(Debug, Default, Clone)]
struct OutStream {
    /// Data frames forwarded so far.
    sent: u64,
    /// Highest acknowledged seq + 1.
    acked: u64,
    /// Send times of the unacknowledged frames, oldest first (at most one
    /// window).
    unacked_since: VecDeque<Instant>,
}

/// Whether a draining (or running) channel's output has ended. Pure.
///
/// - every stream reached EOF;
/// - or 2 s after EXIT every open stream proved idle: reads with credit
///   available found nothing for [`IDLE_PROOF`] (a survivor holding the
///   pipes silent);
/// - or 60 s after EXIT in any case (a survivor that keeps writing, or a
///   client too slow for the contract's cap).
fn end_due(
    phase: Phase,
    streams: &[ChannelOutput],
    eof: [bool; 2],
    idle_since: [Option<Instant>; 2],
    now: Instant,
) -> bool {
    if streams.iter().all(|s| eof[*s as usize]) {
        return matches!(phase, Phase::Running | Phase::Draining { .. });
    }
    let Phase::Draining { exit_at } = phase else {
        return false;
    };
    let since = now.saturating_duration_since(exit_at);
    since >= EXIT_DRAIN_MAX
        || (since >= EXIT_DRAIN
            && streams.iter().all(|s| {
                eof[*s as usize]
                    || idle_since[*s as usize]
                        .is_some_and(|at| now.saturating_duration_since(at) >= IDLE_PROOF)
            }))
}

/// Unacknowledged bulk (exec) frames of live channels: across the host and
/// per sandbox owner. Recomputed every tick, charged per frame sent.
#[derive(Debug, Default)]
struct BulkCredit {
    host: u64,
    by_creator: HashMap<String, u64>,
}

impl BulkCredit {
    fn allows(&self, creator: &str) -> bool {
        self.host < HOST_UNACKED_FRAMES
            && self.by_creator.get(creator).copied().unwrap_or(0) < CREATOR_UNACKED_FRAMES
    }

    fn charge(&mut self, creator: &str, frames: u64) {
        self.host += frames;
        *self.by_creator.entry(creator.to_string()).or_default() += frames;
    }

    fn refund(&mut self, creator: &str, frames: u64) {
        self.host = self.host.saturating_sub(frames);
        if let Some(held) = self.by_creator.get_mut(creator) {
            *held = held.saturating_sub(frames);
        }
    }
}

/// One channel, owned by the socket thread.
struct Chan {
    fence: ChannelFence,
    kind: ChannelKind,
    phase: Phase,
    io: Option<Box<dyn ChannelIo>>,
    orders: mpsc::SyncSender<Order>,
    signals: mpsc::SyncSender<(ChannelBirth, ProcessSignal)>,
    events: mpsc::Receiver<Evt>,
    filter: FrameFilter,
    /// The env + secret preamble, until it is handed over (the go).
    preamble: Option<Vec<u8>>,
    /// A pty's current size.
    size: Option<PtySize>,
    prompted: bool,
    refused: bool,
    birth: Option<ChannelBirth>,
    exit: Option<ChannelExitStatus>,
    out: [OutStream; 2],
    eof: [bool; 2],
    eof_sent: [bool; 2],
    idle_since: [Option<Instant>; 2],
    /// Round-robin cursor over the streams.
    next_stream: usize,
    /// Admitted stdin frames not yet handed to the guest, in order.
    pending_in: VecDeque<(u64, Vec<u8>)>,
    input_next: u64,
    input_acked: u64,
    /// Stdin acks to send (frames dropped because the workload ended).
    acks_due: Vec<u64>,
    /// `channel.eof` for stdin arrived; its frame count.
    stdin_eof: Option<u64>,
    stdin_closed: bool,
    violations: u32,
    credential_leases: BTreeSet<String>,
    /// The sandbox owner (its share of the host cap).
    creator: String,
    deadline: Instant,
    setup_deadline: Instant,
    intent: Option<ChannelCloseIntent>,
    error: Option<(SandboxErrorCode, String)>,
    decided: bool,
    kill_ordered: bool,
    /// Close orders without their `Ended` answer yet.
    outstanding: u32,
    end: Option<ChannelEnd>,
    exit_sent: bool,
    exit_settled: bool,
    /// The custodian answered for the last time (`Done` sent): remove.
    gone: bool,
}

/// A tick's outgoing frames, in order. The tick only appends here; the
/// socket writes happen after it ([`ChannelHost::poll_with`]), so no write
/// can ever block between a decision and the action it guards.
type Outbox<'a> = &'a mut Vec<Outgoing>;

/// The socket writer of a flush.
type Send<'a> = &'a mut dyn FnMut(Outgoing) -> Result<()>;

/// The owner's clock: real time plus the test offset (zero in production).
fn skew_now(skew: &std::sync::atomic::AtomicU64) -> Instant {
    Instant::now() + Duration::from_millis(skew.load(std::sync::atomic::Ordering::SeqCst))
}

/// Time and authority for the owner's decisions. A tick never blocks on
/// the socket (its frames are queued and written after it); a check is
/// made right before the decisions it guards, with nothing that can wait
/// in between.
struct Judge {
    journal: Arc<HostJournal>,
    authority: HostAuthority,
    credentials: Option<super::credentials::service::CredentialService>,
    skew: Arc<std::sync::atomic::AtomicU64>,
    /// Runs at every authority lookup (tests: a lock wait inside it).
    #[cfg(test)]
    hook: CheckHook,
}

#[cfg(test)]
type CheckFn = Box<dyn FnMut(&ChannelFence) + std::marker::Send>;
#[cfg(test)]
type CheckHook = Arc<Mutex<Option<CheckFn>>>;

impl Judge {
    fn now(&self) -> Instant {
        skew_now(&self.skew)
    }

    fn refusal(&self, chan: &Chan) -> Option<ChannelCloseIntent> {
        #[cfg(test)]
        if let Some(hook) = self.hook.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            hook(&chan.fence);
        }
        let (sandbox_id, generation) = target(&chan.fence);
        sandbox_refusal(
            &self.journal,
            &self.authority,
            self.credentials.as_ref(),
            sandbox_id,
            generation,
            &chan.credential_leases,
        )
    }

    /// Apply an authority loss and the absolute deadline as of now (both
    /// kill; in every phase, so a settling close is upgraded too).
    fn check(&self, chan: &mut Chan) {
        if let Some(intent) = self.refusal(chan) {
            chan.decide(Some(intent), None, true);
        }
        if self.now() >= chan.deadline {
            chan.decide(Some(ChannelCloseIntent::Expired), None, true);
        }
    }

    /// The setup deadline as of now: a channel not running by then is
    /// killed (read after any lookup that may have waited).
    fn check_setup(&self, chan: &mut Chan) {
        if matches!(chan.phase, Phase::Opening | Phase::Starting)
            && self.now() >= chan.setup_deadline
        {
            chan.decide(
                None,
                Some((SandboxErrorCode::Timeout, "channel setup timed out".into())),
                true,
            );
        }
    }
}

fn text(message: DaemonControlMessage) -> Outgoing {
    Outgoing::Text(Box::new(message))
}

impl Chan {
    fn streams(&self) -> &'static [ChannelOutput] {
        match (self.kind, self.phase) {
            (ChannelKind::Pty, _) => &[ChannelOutput::Stdout],
            // Before READY only the frame stream is read: the workload's
            // stdout (and its EOF) stays in the pipe until READY.
            (ChannelKind::Exec, Phase::Opening | Phase::Starting) => &[ChannelOutput::Stderr],
            (ChannelKind::Exec, _) => &[ChannelOutput::Stdout, ChannelOutput::Stderr],
        }
    }

    fn all_streams(&self) -> &'static [ChannelOutput] {
        match self.kind {
            ChannelKind::Pty => &[ChannelOutput::Stdout],
            ChannelKind::Exec => &[ChannelOutput::Stdout, ChannelOutput::Stderr],
        }
    }

    fn frame_stream(&self) -> ChannelOutput {
        match self.kind {
            ChannelKind::Pty => ChannelOutput::Stdout,
            ChannelKind::Exec => ChannelOutput::Stderr,
        }
    }

    /// Output frames sent and not acknowledged (both streams).
    fn unacked(&self) -> u64 {
        self.out
            .iter()
            .map(|out| out.sent.saturating_sub(out.acked))
            .sum()
    }

    /// Holds output credit (counts against the host cap).
    fn live(&self) -> bool {
        matches!(
            self.phase,
            Phase::Starting | Phase::Running | Phase::Draining { .. }
        )
    }

    /// The single close path. `kill` selects a kill close; a close before
    /// READY is always one. Dropping the IO here (same thread as every read,
    /// write and data frame) is the cut-off: nothing crosses afterwards.
    fn decide(
        &mut self,
        intent: Option<ChannelCloseIntent>,
        error: Option<(SandboxErrorCode, String)>,
        kill: bool,
    ) {
        match self.phase {
            Phase::Opening | Phase::Starting | Phase::Running | Phase::Draining { .. } => {
                let how = if kill || self.birth.is_none() {
                    ChannelClose::Kill {
                        forget: self.birth.is_some(),
                    }
                } else if matches!(self.phase, Phase::Draining { .. }) {
                    ChannelClose::Finish
                } else {
                    ChannelClose::Hangup(
                        (self.kind == ChannelKind::Exec)
                            .then(|| self.birth.clone())
                            .flatten(),
                    )
                };
                self.intent = intent;
                self.error = error;
                self.decided = true;
                self.cut(how);
            }
            Phase::Closing | Phase::Unsettled if kill && !self.kill_ordered => {
                // A kill-class decision during a normal close or natural end
                // (or while its end settles) still kills the scope.
                if !self.exit_sent {
                    self.intent = intent;
                    self.error = error;
                }
                self.decided = true;
                self.order(ChannelClose::Kill {
                    forget: self.birth.is_some(),
                });
            }
            _ => {}
        }
    }

    /// The natural end: no intent, a normal finish.
    fn end_naturally(&mut self) {
        self.cut(ChannelClose::Finish);
    }

    fn cut(&mut self, how: ChannelClose) {
        self.io = None;
        self.preamble = None;
        // Never handed over; the server's credit returns with the exit.
        self.pending_in.clear();
        self.acks_due.clear();
        self.phase = Phase::Closing;
        self.order(how);
    }

    fn order(&mut self, how: ChannelClose) {
        self.kill_ordered |= how.is_kill();
        // Capacity 4 > the most ever sent (close, kill upgrade, done).
        if self.orders.try_send(Order::Close(how)).is_ok() {
            self.outstanding += 1;
        }
    }

    fn violation(&mut self, message: &str) {
        self.decide(
            Some(ChannelCloseIntent::ProtocolViolation),
            Some((SandboxErrorCode::ProtocolError, message.to_string())),
            true,
        );
    }

    /// The single emitter of `channel.exit` (eofs first).
    fn finish(&mut self, outbox: Outbox<'_>) {
        let Some(end) = self.end else {
            return;
        };
        if self.outstanding > 0 {
            return;
        }
        let frames = ChannelExitFrames {
            stdout: self.out[0].sent,
            stderr: self.out[1].sent,
        };
        if !self.exit_sent {
            if self.birth.is_some() && self.kind == ChannelKind::Exec {
                for stream in [ChannelOutput::Stdout, ChannelOutput::Stderr] {
                    let index = stream as usize;
                    if !self.eof_sent[index] {
                        self.eof_sent[index] = true;
                        outbox.push(text(DaemonControlMessage::ChannelEof {
                            fence: self.fence.clone(),
                            stream: wire_stream(stream),
                            frames: self.out[index].sent,
                        }));
                    }
                }
            }
            let status = match (self.exit, end.scope) {
                (Some(status), _) => status,
                (None, ChannelScope::Killed) if self.kill_ordered => ChannelExitStatus::Signal(9),
                _ => ChannelExitStatus::Unknown,
            };
            let error = self
                .error
                .as_ref()
                .map(|(code, message)| error_detail(&self.fence, *code, message));
            let status = (error.is_none() || self.birth.is_some()).then_some(status);
            outbox.push(exit_frame(
                &self.fence,
                status,
                self.intent,
                error,
                end.settled(),
                frames,
            ));
            self.exit_sent = true;
            self.exit_settled = end.settled();
        } else if end.settled() && !self.exit_settled {
            outbox.push(exit_frame(&self.fence, None, None, None, true, frames));
            self.exit_settled = true;
        }
        if end.settled() && self.outstanding == 0 {
            let _ = self.orders.try_send(Order::Done);
            self.gone = true;
        } else {
            self.phase = Phase::Unsettled;
        }
    }

    /// Custodian events (never block).
    fn drain_events(&mut self, outbox: Outbox<'_>) {
        loop {
            let event = match self.events.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty) => return,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // The custodian is gone (it never leaves unsettled; a
                    // panic is the only way here).
                    if !self.exit_sent {
                        self.outstanding = 0;
                        self.end = Some(ChannelEnd {
                            reaped: false,
                            scope: ChannelScope::Uncertain,
                        });
                        if self.error.is_none() {
                            self.error =
                                Some((SandboxErrorCode::Internal, "channel process failed".into()));
                        }
                        self.finish(outbox);
                    }
                    self.gone = true;
                    return;
                }
            };
            match event {
                Evt::Spawned(io) => {
                    if self.phase == Phase::Opening {
                        self.io = Some(io);
                        self.phase = Phase::Starting;
                    }
                    // Decided while opening: the IO is dropped at once.
                }
                Evt::OpenFailed(code) => {
                    if !self.decided {
                        let message = if code == SandboxErrorCode::UnsupportedCapability {
                            "Unsupported capability: channels"
                        } else {
                            "channel setup failed"
                        };
                        self.error = Some((code, message.to_string()));
                        self.decided = true;
                    }
                    self.io = None;
                    self.phase = Phase::Closing;
                }
                Evt::Signal(outcome) => {
                    let code = match outcome {
                        ChannelSignalOutcome::Delivered => None,
                        ChannelSignalOutcome::Unsupported => Some(ChannelNotice::UnsupportedSignal),
                        ChannelSignalOutcome::Ended => Some(ChannelNotice::StateConflict),
                    };
                    if let Some(code) = code
                        && !self.exit_sent
                    {
                        outbox.push(text(DaemonControlMessage::ChannelError {
                            fence: self.fence.clone(),
                            code,
                        }));
                    }
                }
                Evt::Ended { end, answers } => {
                    if answers {
                        self.outstanding = self.outstanding.saturating_sub(1);
                    }
                    self.end = Some(end);
                    if !matches!(self.phase, Phase::Closing | Phase::Unsettled) {
                        // The custodian's own rule fired: its deadline kill.
                        self.io = None;
                        self.pending_in.clear();
                        self.acks_due.clear();
                        self.phase = Phase::Closing;
                        self.kill_ordered = true;
                        if !self.decided {
                            self.decided = true;
                            self.intent = Some(ChannelCloseIntent::Expired);
                        }
                    }
                    self.finish(outbox);
                }
            }
        }
    }

    /// The setup step may hand the preamble over now.
    fn admissible(&self, now: Instant) -> bool {
        self.phase == Phase::Starting && now < self.deadline && now < self.setup_deadline
    }

    fn setup_failed(&mut self) {
        let (code, message) = if self.refused {
            (
                SandboxErrorCode::UnsupportedCapability,
                "guest_scope_unavailable: the guest has no usable systemd scope",
            )
        } else {
            (SandboxErrorCode::GuestUnavailable, "channel setup failed")
        };
        self.decide(None, Some((code, message.to_string())), true);
    }

    /// Stdin: hand admitted frames over in order; ack each one handed over.
    fn write_stdin(&mut self, outbox: Outbox<'_>) {
        for seq in self.acks_due.drain(..) {
            self.input_acked += 1;
            outbox.push(text(DaemonControlMessage::ChannelAck {
                fence: self.fence.clone(),
                stream: ChannelStream::Stdin,
                seq,
            }));
        }
        loop {
            if self.phase != Phase::Running {
                return;
            }
            let Some(io) = &mut self.io else {
                return;
            };
            let Some((seq, bytes)) = self.pending_in.pop_front() else {
                break;
            };
            match io.try_write(bytes) {
                Ok(()) => {}
                Err(refused) if !refused.closed => {
                    self.pending_in.push_front((seq, refused.bytes));
                    break;
                }
                // The process stopped reading for good; drop quietly (its
                // exit follows) but keep the server's credit moving.
                Err(_) => {}
            }
            self.input_acked += 1;
            outbox.push(text(DaemonControlMessage::ChannelAck {
                fence: self.fence.clone(),
                stream: ChannelStream::Stdin,
                seq,
            }));
        }
        let Some(io) = &mut self.io else {
            return;
        };
        if self.pending_in.is_empty()
            && self.stdin_eof == Some(self.input_next)
            && !self.stdin_closed
            && io.close_stdin()
        {
            self.stdin_closed = true;
        }
    }

    /// A read may happen only when its frame can be sent at once. Pty
    /// channels are exempt from the host cap and the per-owner share; so is
    /// a starting channel's frame stream (its PROMPT/READY reads carry at
    /// most one data frame, so the cap is exceeded by at most one frame per
    /// starting channel and a full cap never stalls setups).
    fn can_send(&self, budget: usize, credit: &BulkCredit) -> bool {
        budget > 0
            && self.io.is_some()
            && self.unacked() < window(self.kind)
            && (self.kind == ChannelKind::Pty
                || self.phase == Phase::Starting
                || credit.allows(&self.creator))
    }

    /// Guest output, read only when its frame can be sent at once.
    fn read_output(
        &mut self,
        judge: &Judge,
        budget: &mut usize,
        credit: &mut BulkCredit,
        outbox: Outbox<'_>,
    ) -> Result<()> {
        if !self.live() {
            return Ok(());
        }
        if !self.can_send(*budget, credit) {
            // Unread bytes may be waiting: nothing is proven idle.
            self.idle_since = [None, None];
            return Ok(());
        }
        let mut quiet = 0;
        // Streams found empty (with credit) in this tick: only those keep an
        // idle proof; a stream the tick could not look at proves nothing.
        let mut empty_now = [false, false];
        while self.can_send(*budget, credit) && self.live() {
            let streams = self.streams();
            let open: Vec<ChannelOutput> = streams
                .iter()
                .copied()
                .filter(|s| !self.eof[*s as usize])
                .collect();
            if open.is_empty() || quiet >= open.len() {
                break;
            }
            let stream = open[self.next_stream % open.len()];
            self.next_stream = self.next_stream.wrapping_add(1);
            let Some(io) = &mut self.io else { break };
            match io.try_read(stream) {
                ChannelRead::WouldBlock => {
                    quiet += 1;
                    empty_now[stream as usize] = true;
                    self.idle_since[stream as usize].get_or_insert_with(|| judge.now());
                }
                // Every read costs budget, also one whose bytes the setup
                // filter drops: guest chatter can never hold the loop.
                ChannelRead::Data(bytes) => {
                    quiet = 0;
                    *budget = budget.saturating_sub(1);
                    empty_now[stream as usize] = false;
                    self.idle_since[stream as usize] = None;
                    self.on_bytes(stream, &bytes, judge, credit, outbox)?;
                }
                ChannelRead::Eof => {
                    quiet = 0;
                    *budget = budget.saturating_sub(1);
                    self.on_eof(stream, judge, credit, outbox)?;
                }
            }
        }
        for stream in [ChannelOutput::Stdout, ChannelOutput::Stderr] {
            if !empty_now[stream as usize] {
                self.idle_since[stream as usize] = None;
            }
        }
        Ok(())
    }

    fn on_bytes(
        &mut self,
        stream: ChannelOutput,
        bytes: &[u8],
        judge: &Judge,
        credit: &mut BulkCredit,
        outbox: Outbox<'_>,
    ) -> Result<()> {
        let data = if stream == self.frame_stream() {
            let (data, frames) = self.filter.feed(bytes);
            for frame in frames {
                self.on_frame(frame, judge, outbox);
            }
            data
        } else {
            bytes.to_vec()
        };
        if self.live() && !data.is_empty() {
            self.data_frame(stream, &data, judge, credit, outbox)?;
        }
        Ok(())
    }

    fn on_frame(&mut self, frame: GuestFrame, judge: &Judge, outbox: Outbox<'_>) {
        match frame {
            GuestFrame::Prompt => self.prompted = true,
            GuestFrame::Refused => self.refused = true,
            GuestFrame::Ready(birth) => {
                // The secret is only in the preamble: READY implies it went.
                if self.phase == Phase::Starting && self.preamble.is_none() {
                    self.birth = Some(birth);
                    self.phase = Phase::Running;
                    outbox.push(text(DaemonControlMessage::ChannelReady {
                        fence: self.fence.clone(),
                        pty: self.size.map(|size| ChannelPtySize {
                            rows: size.rows(),
                            cols: size.cols(),
                        }),
                    }));
                }
            }
            GuestFrame::Exit(status) => {
                self.exit = Some(status);
                if self.phase == Phase::Running {
                    self.phase = Phase::Draining {
                        exit_at: judge.now(),
                    };
                    // The workload is gone: unwritten stdin is dropped, its
                    // credit returned.
                    for (seq, _) in self.pending_in.drain(..) {
                        self.acks_due.push(seq);
                    }
                }
            }
        }
    }

    fn data_frame(
        &mut self,
        stream: ChannelOutput,
        data: &[u8],
        judge: &Judge,
        credit: &mut BulkCredit,
        outbox: Outbox<'_>,
    ) -> Result<()> {
        let index = stream as usize;
        let frame = encode_channel_frame(
            &ChannelDataMetadata {
                r#type: ChannelDataKind::Data,
                fence: self.fence.clone(),
                stream: wire_stream(stream),
                seq: self.out[index].sent,
            },
            data,
        )?;
        self.out[index].sent += 1;
        // Stamped as sent now (not at the tick's start).
        self.out[index].unacked_since.push_back(judge.now());
        if self.kind == ChannelKind::Exec {
            credit.charge(&self.creator, 1);
        }
        outbox.push(Outgoing::Binary(frame));
        Ok(())
    }

    fn on_eof(
        &mut self,
        stream: ChannelOutput,
        judge: &Judge,
        credit: &mut BulkCredit,
        outbox: Outbox<'_>,
    ) -> Result<()> {
        let index = stream as usize;
        if stream == self.frame_stream() {
            let rest = self.filter.finish();
            if self.birth.is_some() && !rest.is_empty() {
                self.data_frame(stream, &rest, judge, credit, outbox)?;
            }
        }
        self.eof[index] = true;
        if self.phase == Phase::Starting {
            // The launcher or wrapper ended before READY.
            self.setup_failed();
            return Ok(());
        }
        if !self.eof_sent[index] && self.kind == ChannelKind::Exec {
            self.eof_sent[index] = true;
            outbox.push(text(DaemonControlMessage::ChannelEof {
                fence: self.fence.clone(),
                stream: wire_stream(stream),
                frames: self.out[index].sent,
            }));
        }
        Ok(())
    }
}

fn key(fence: &ChannelFence) -> (String, String) {
    (fence.connection_id.clone(), fence.channel_id.clone())
}

fn target(fence: &ChannelFence) -> (&str, u64) {
    match &fence.target {
        ChannelTarget::Sandbox {
            sandbox_id,
            generation,
        } => (sandbox_id, *generation),
    }
}

fn wire_stream(stream: ChannelOutput) -> ChannelStream {
    match stream {
        ChannelOutput::Stdout => ChannelStream::Stdout,
        ChannelOutput::Stderr => ChannelStream::Stderr,
    }
}

/// The lease authority of a channel: `None` while it may run.
fn sandbox_refusal(
    journal: &HostJournal,
    authority: &HostAuthority,
    credentials: Option<&super::credentials::service::CredentialService>,
    sandbox_id: &str,
    generation: u64,
    credential_leases: &BTreeSet<String>,
) -> Option<ChannelCloseIntent> {
    let current = journal
        .lease(sandbox_id)
        .is_some_and(|row| row.generation == generation)
        && !authority.terminal_superseded(sandbox_id, generation);
    if !current {
        Some(ChannelCloseIntent::Superseded)
    } else if !journal.work_allowed(sandbox_id, generation, "channel.open") {
        Some(ChannelCloseIntent::Expired)
    } else if !credential_leases.is_empty()
        && credentials.is_none_or(|service| {
            let installed = service.installed_env_leases(sandbox_id);
            !credential_leases.is_subset(&installed)
        })
    {
        Some(ChannelCloseIntent::Revoked)
    } else {
        None
    }
}

fn error_detail(
    fence: &ChannelFence,
    code: SandboxErrorCode,
    message: &str,
) -> ProtocolErrorDetail {
    ProtocolErrorDetail {
        reason: None,
        code: code.into(),
        message: message.to_string(),
        operation_id: None,
        sandbox_id: Some(target(fence).0.to_string()),
    }
}

fn exit_frame(
    fence: &ChannelFence,
    status: Option<ChannelExitStatus>,
    intent: Option<ChannelCloseIntent>,
    error: Option<ProtocolErrorDetail>,
    reaped: bool,
    frames: ChannelExitFrames,
) -> Outgoing {
    let (exit_code, signal) = match status {
        Some(ChannelExitStatus::Code(code)) => (Some(code), None),
        Some(ChannelExitStatus::Signal(signal)) => (None, Some(signal)),
        Some(ChannelExitStatus::Unknown) | None => (None, None),
    };
    Outgoing::Text(Box::new(DaemonControlMessage::ChannelExit {
        fence: fence.clone(),
        exit_code,
        signal,
        intent,
        error,
        reaped,
        frames,
    }))
}

/// Per-connection channel dispatch (lives on the socket-loop thread).
pub(super) struct ChannelHost {
    slots: Arc<ChannelSlots>,
    registry: Arc<ChannelRegistry>,
    runtime: Arc<dyn SandboxRuntime>,
    journal: Arc<HostJournal>,
    authority: HostAuthority,
    host_id: String,
    epoch: Option<u64>,
    binding: Option<TransportBindingV11>,
    negotiated: bool,
    channels: HashMap<(String, String), Chan>,
    /// Round-robin offset of the forwarding order.
    rr: usize,
    tombstones: VecDeque<(String, String)>,
    audits: usize,
    credentials: Option<super::credentials::service::CredentialService>,
    quiesce: Option<Arc<super::quiesce::QuiesceState>>,
    /// Test clock offset in milliseconds (zero in production).
    skew: Arc<std::sync::atomic::AtomicU64>,
    #[cfg(test)]
    ticking: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    check_hook: CheckHook,
}

impl ChannelHost {
    pub(super) fn new(
        slots: Arc<ChannelSlots>,
        registry: Arc<ChannelRegistry>,
        runtime: Arc<dyn SandboxRuntime>,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        host_id: String,
    ) -> Self {
        Self {
            slots,
            registry,
            runtime,
            journal,
            authority,
            host_id,
            epoch: None,
            binding: None,
            negotiated: false,
            channels: HashMap::new(),
            rr: 0,
            tombstones: VecDeque::new(),
            audits: 0,
            credentials: None,
            quiesce: None,
            skew: Arc::default(),
            #[cfg(test)]
            ticking: Arc::default(),
            #[cfg(test)]
            check_hook: Arc::default(),
        }
    }

    pub(super) fn set_quiesce(&mut self, quiesce: Arc<super::quiesce::QuiesceState>) {
        self.quiesce = Some(quiesce);
    }

    pub(super) fn set_credentials(
        &mut self,
        credentials: Option<super::credentials::service::CredentialService>,
    ) {
        self.credentials = credentials;
    }

    /// `hello.ok` established the epoch; `negotiated` is its `channels` echo.
    pub(super) fn enable(&mut self, epoch: u64, binding: TransportBindingV11, negotiated: bool) {
        self.epoch = Some(epoch);
        self.binding = Some(binding);
        self.negotiated = negotiated;
    }

    fn now(&self) -> Instant {
        skew_now(&self.skew)
    }

    #[cfg(test)]
    pub(super) fn advance(&mut self, by: Duration) {
        self.skew.fetch_add(
            u64::try_from(by.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    /// A handle on the test clock (advance it from inside a send hook).
    #[cfg(test)]
    pub(super) fn clock_handle(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.skew.clone()
    }

    #[cfg(test)]
    pub(super) fn live_channels(&self) -> usize {
        self.channels.len()
    }

    fn audit(&mut self, reason: &str) {
        if self.audits < AUDIT_LOGS {
            self.audits += 1;
            tracing::warn!("channel frame dropped ({reason})");
        }
    }

    fn connection_matches(&self, fence: &ChannelFence) -> Result<bool> {
        let Some(epoch) = self.epoch else {
            bail!("channel frame before hello.ok");
        };
        if !self.negotiated {
            bail!("unnegotiated channel frame");
        }
        Ok(fence.host_id == self.host_id && fence.epoch == epoch)
    }

    /// The live channel the frame names, with its full fence matched.
    fn channel_for(&mut self, fence: &ChannelFence) -> Result<Option<&mut Chan>> {
        let matches = self.connection_matches(fence)?;
        let key = key(fence);
        if !self.channels.contains_key(&key) {
            if !self.tombstones.contains(&key) {
                self.audit("foreign channel frame");
            }
            return Ok(None);
        }
        let exact = matches
            && self
                .channels
                .get(&key)
                .is_some_and(|chan| chan.fence == *fence);
        if !exact {
            self.audit("channel fence mismatch");
            self.violation(&key);
            return Ok(None);
        }
        Ok(self.channels.get_mut(&key))
    }

    fn violation(&mut self, key: &(String, String)) {
        if let Some(chan) = self.channels.get_mut(key) {
            chan.violations += 1;
            if chan.violations >= CHANNEL_FENCE_VIOLATION_LIMIT {
                chan.violation("repeated channel protocol violations");
            }
        }
    }

    fn judge(&self) -> Judge {
        Judge {
            journal: self.journal.clone(),
            authority: self.authority.clone(),
            credentials: self.credentials.clone(),
            skew: self.skew.clone(),
            #[cfg(test)]
            hook: self.check_hook.clone(),
        }
    }

    /// Install a hook run at every authority lookup (tests).
    #[cfg(test)]
    pub(super) fn set_check_hook(&self, hook: Option<CheckFn>) {
        *self.check_hook.lock().unwrap_or_else(|e| e.into_inner()) = hook;
    }

    fn refusal(&self, chan: &Chan) -> Option<ChannelCloseIntent> {
        self.judge().refusal(chan)
    }

    /// Server channel control frames. Returns frames to send at once.
    pub(super) fn handle_control(
        &mut self,
        message: ServerControlMessage,
    ) -> Result<Vec<Outgoing>> {
        let notice = |fence: ChannelFence, code: ChannelNotice| {
            Ok(vec![text(DaemonControlMessage::ChannelError {
                fence,
                code,
            })])
        };
        match message {
            ServerControlMessage::ChannelOpen {
                fence,
                kind,
                argv,
                login,
                cwd,
                env,
                pty,
            } => self.open(fence, kind, argv, login, cwd, env, pty),
            ServerControlMessage::ChannelAck { fence, stream, seq } => {
                let Some(chan) = self.channel_for(&fence)? else {
                    return Ok(Vec::new());
                };
                let index = match stream {
                    ChannelStream::Stdout => 0,
                    ChannelStream::Stderr => 1,
                    ChannelStream::Stdin => {
                        chan.violation("channel ack names stdin");
                        return Ok(Vec::new());
                    }
                };
                let out = &mut chan.out[index];
                if seq >= out.sent {
                    chan.violation("channel ack outside the window");
                    return Ok(Vec::new());
                }
                if seq >= out.acked {
                    // Cumulative: a repeated (or older) ack returns nothing.
                    for _ in out.acked..=seq {
                        out.unacked_since.pop_front();
                    }
                    out.acked = seq + 1;
                }
                Ok(Vec::new())
            }
            ServerControlMessage::ChannelEof {
                fence,
                stream,
                frames,
            } => {
                let Some(chan) = self.channel_for(&fence)? else {
                    return Ok(Vec::new());
                };
                if matches!(chan.phase, Phase::Closing | Phase::Unsettled) {
                    // Decided: stdin frames in flight were dropped uncounted.
                    return Ok(Vec::new());
                }
                // The relay is ordered: every stdin frame precedes the eof,
                // and input after it is refused, so a count other than the
                // frames received could never complete.
                if stream != ChannelStream::Stdin
                    || chan.stdin_eof.is_some()
                    || frames != chan.input_next
                {
                    chan.violation("invalid channel eof");
                    return Ok(Vec::new());
                }
                chan.stdin_eof = Some(frames);
                Ok(Vec::new())
            }
            ServerControlMessage::ChannelResize { fence, rows, cols } => {
                let Some(chan) = self.channel_for(&fence)? else {
                    return Ok(Vec::new());
                };
                let Ok(size) = PtySize::new(rows, cols) else {
                    chan.violation("invalid channel size");
                    return Ok(Vec::new());
                };
                if chan.kind != ChannelKind::Pty {
                    return notice(fence, ChannelNotice::StateConflict);
                }
                if let Some(io) = &mut chan.io
                    && io.resize(size).is_ok()
                {
                    chan.size = Some(size);
                }
                Ok(Vec::new())
            }
            ServerControlMessage::ChannelSignal { fence, signal } => {
                let Some(chan) = self.channel_for(&fence)? else {
                    return Ok(Vec::new());
                };
                if chan.kind != ChannelKind::Exec {
                    return notice(fence, ChannelNotice::UnsupportedSignal);
                }
                let signal = match signal {
                    ChannelSignal::Term => ProcessSignal::Sigterm,
                    ChannelSignal::Int => ProcessSignal::Sigint,
                    ChannelSignal::Hup => ProcessSignal::Sighup,
                    ChannelSignal::Kill => {
                        // KILL is a kill close of the scope (the end carries
                        // signal 9); it never waits behind output credit.
                        chan.decide(None, None, true);
                        return Ok(Vec::new());
                    }
                };
                let queued = chan.phase == Phase::Running
                    && chan
                        .birth
                        .clone()
                        .is_some_and(|birth| chan.signals.try_send((birth, signal)).is_ok());
                if queued {
                    Ok(Vec::new())
                } else {
                    notice(fence, ChannelNotice::StateConflict)
                }
            }
            ServerControlMessage::ChannelClose { fence, intent } => {
                let Some(chan) = self.channel_for(&fence)? else {
                    return Ok(Vec::new());
                };
                chan.decide(Some(intent), None, intent != ChannelCloseIntent::Client);
                Ok(Vec::new())
            }
            _ => bail!("not a channel frame"),
        }
    }

    /// One `channel.data` (stdin) frame from the server.
    pub(super) fn handle_input(
        &mut self,
        metadata: ChannelDataMetadata,
        body: Vec<u8>,
    ) -> Result<()> {
        let ChannelDataKind::Data = metadata.r#type;
        let key = key(&metadata.fence);
        let Some(chan) = self.channel_for(&metadata.fence)? else {
            return Ok(());
        };
        if matches!(chan.phase, Phase::Closing | Phase::Unsettled) {
            // Already decided: in flight before the server saw the close.
            return Ok(());
        }
        if metadata.stream != ChannelStream::Stdin
            || body.len() > frame_bytes(chan.kind)
            || chan.stdin_eof.is_some()
        {
            chan.violation("invalid channel input frame");
            return Ok(());
        }
        // Per-frame lease authority: no byte is admitted after a loss.
        let refusal = self.channels.get(&key).and_then(|chan| self.refusal(chan));
        let Some(chan) = self.channels.get_mut(&key) else {
            return Ok(());
        };
        if let Some(intent) = refusal {
            chan.decide(Some(intent), None, true);
            return Ok(());
        }
        if metadata.seq < chan.input_next {
            self.violation(&key);
            return Ok(());
        }
        if metadata.seq > chan.input_next {
            chan.violation("channel input sequence gap");
            return Ok(());
        }
        match chan.phase {
            Phase::Running => {
                if chan.input_next - chan.input_acked >= window(chan.kind) {
                    chan.violation("channel input beyond its window");
                    return Ok(());
                }
                chan.pending_in.push_back((metadata.seq, body));
            }
            // The workload is gone: dropped, its credit returned.
            Phase::Draining { .. } => chan.acks_due.push(metadata.seq),
            _ => {
                chan.violation("channel input before ready");
                return Ok(());
            }
        }
        chan.input_next += 1;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn open(
        &mut self,
        fence: ChannelFence,
        kind: ChannelKind,
        argv: Option<Vec<String>>,
        login: bool,
        cwd: Option<String>,
        env: Option<std::collections::BTreeMap<String, String>>,
        pty: Option<ChannelPtyParams>,
    ) -> Result<Vec<Outgoing>> {
        let key = key(&fence);
        if !self.connection_matches(&fence)? {
            self.audit("foreign channel open");
            // Naming a live channel with the wrong fence is a violation.
            self.violation(&key);
            return Ok(Vec::new());
        }
        if self.channels.contains_key(&key) || self.tombstones.contains(&key) {
            self.audit("duplicate channel open");
            self.violation(&key);
            return Ok(Vec::new());
        }
        let frames = ChannelExitFrames {
            stdout: 0,
            stderr: 0,
        };
        let refuse = |code: SandboxErrorCode, message: &str| {
            Ok(vec![exit_frame(
                &fence,
                None,
                None,
                Some(error_detail(&fence, code, message)),
                true,
                frames,
            )])
        };
        if self.quiesce.as_ref().is_some_and(|q| q.quiescing()) {
            return refuse(
                SandboxErrorCode::Disconnected,
                "host is restarting; try again shortly",
            );
        }
        let (sandbox_id, generation) = target(&fence);
        let Ok(unit) = sandbox_runtime::channel_scope_unit(&fence.connection_id, &fence.channel_id)
        else {
            return refuse(SandboxErrorCode::ProtocolError, "invalid channel id");
        };
        if self.registry.contains(&unit) {
            // A reused id would collide with a scope still being cleaned up.
            return refuse(SandboxErrorCode::StateConflict, "channel id is in use");
        }
        let (mode, size) = match (kind, pty) {
            (ChannelKind::Pty, Some(pty)) => match PtySize::new(pty.rows, pty.cols) {
                Ok(size) => (
                    ChannelMode::Pty {
                        size,
                        term: pty.term,
                    },
                    Some(size),
                ),
                Err(_) => return refuse(SandboxErrorCode::ProtocolError, "invalid channel size"),
            },
            (ChannelKind::Exec, None) => (ChannelMode::Exec, None),
            _ => return refuse(SandboxErrorCode::ProtocolError, "invalid channel kind"),
        };
        // The journal binding is the only identity source.
        let Some(record) = self.journal.lease(sandbox_id) else {
            return refuse(
                SandboxErrorCode::SandboxNotFound,
                "sandbox has no accepted lease",
            );
        };
        let bound = self.binding.as_ref().is_some_and(|b| *b == record.binding);
        if !bound
            || record.generation != generation
            || !self
                .journal
                .work_allowed(sandbox_id, generation, "channel.open")
            || self.authority.terminal_superseded(sandbox_id, generation)
        {
            return refuse(
                SandboxErrorCode::StateConflict,
                "channel binding is not the current sandbox generation",
            );
        }
        // Build VMs (which may run guest root) never open a channel.
        if record.build_id.is_some() {
            return refuse(
                SandboxErrorCode::UnsupportedCapability,
                "build sandboxes have no channels",
            );
        }
        let (Some(template_fingerprint), Some(guest)) =
            (record.template_fingerprint.clone(), record.guest.clone())
        else {
            return refuse(
                SandboxErrorCode::UnsupportedCapability,
                "sandbox has no recorded guest identity",
            );
        };
        if !self.runtime.channel_capability() {
            return refuse(
                SandboxErrorCode::UnsupportedCapability,
                "Unsupported capability: channels",
            );
        }
        let mut process_env =
            match self
                .journal
                .execution_env(sandbox_id, generation, record.private_config.as_ref())
            {
                Ok(env) => env,
                Err(_) => return refuse(SandboxErrorCode::ProtocolError, "channel setup failed"),
            };
        let mut credential_leases = BTreeSet::new();
        if let Some(service) = &self.credentials {
            match service.env_with_leases(sandbox_id) {
                Ok((extra, leases)) => {
                    for (name, value) in extra {
                        if !process_env.iter().any(|(existing, _)| *existing == name) {
                            process_env.push((name, value));
                        }
                    }
                    credential_leases = leases;
                }
                Err(_) => {
                    return refuse(
                        SandboxErrorCode::CredentialEnvPending,
                        "credential env pending",
                    );
                }
            }
        }
        // Client env (COLORTERM, LANG, LC_*; the wire validated the names)
        // never overrides the sandbox's own values.
        for (name, value) in env.into_iter().flatten() {
            if !process_env.iter().any(|(existing, _)| *existing == name) {
                process_env.push((name, value));
            }
        }
        let now_ms = match self.journal.clock.now_ms() {
            Ok(now) => now,
            Err(_) => return refuse(SandboxErrorCode::ProtocolError, "channel setup failed"),
        };
        let mut lifetime = sandbox_runtime::PTY_MAX_SESSION;
        if !process_env.is_empty() || !credential_leases.is_empty() {
            // Env-bearing channels never outlive the lease they were opened under.
            let remaining =
                Duration::from_millis(record.lease.deadline_unix_ms.saturating_sub(now_ms));
            if remaining.is_zero() {
                return refuse(SandboxErrorCode::StateConflict, "channel setup failed");
            }
            lifetime = lifetime.min(remaining);
        }
        // Both nonces are minted here; the secret and the env exist only in
        // the preamble this thread hands over after the guest's PROMPT.
        let (Ok(nonce), Ok(secret)) = (
            sandbox_runtime::channel_nonce(),
            sandbox_runtime::channel_nonce(),
        ) else {
            return refuse(SandboxErrorCode::Internal, "channel setup failed");
        };
        let Ok(preamble) = sandbox_runtime::channel_preamble(&process_env, &secret) else {
            return refuse(SandboxErrorCode::ProtocolError, "invalid channel request");
        };
        let request = SpawnChannelRequest {
            template_fingerprint: template_fingerprint.clone(),
            sandbox_id: sandbox_id.to_string(),
            connection_id: fence.connection_id.clone(),
            channel_id: fence.channel_id.clone(),
            guest: guest.identity(),
            mode,
            argv,
            login,
            cwd,
            nonce: nonce.clone(),
        };
        if request.validate().is_err() {
            return refuse(SandboxErrorCode::ProtocolError, "invalid channel request");
        }
        let creator = record.sandbox_owner_id.clone();
        let slot = match self.slots.try_acquire(
            kind == ChannelKind::Pty,
            &creator,
            Some(&unit),
            Instant::now(),
        ) {
            Ok(slot) => slot,
            Err(SlotRefusal::RateLimited) => {
                return refuse(SandboxErrorCode::RateLimited, "channel open rate exceeded");
            }
            Err(SlotRefusal::HostCapacity) => {
                return refuse(
                    SandboxErrorCode::RateLimited,
                    "host channel capacity exhausted",
                );
            }
            // A reused id would collide with a scope still being cleaned up
            // (possibly by a channel of an earlier connection).
            Err(SlotRefusal::InUse) => {
                return refuse(SandboxErrorCode::StateConflict, "channel id is in use");
            }
        };
        let entry = RegistryEntry {
            unit,
            sandbox_id: sandbox_id.to_string(),
            template_fingerprint,
            guest: guest.identity(),
        };
        let (orders_tx, orders_rx) = mpsc::sync_channel(4);
        let (signals_tx, signals_rx) = mpsc::sync_channel(SIGNALS_IN_FLIGHT);
        let (events_tx, events_rx) = mpsc::channel();
        let custodian = Custodian {
            runtime: self.runtime.clone(),
            registry: self.registry.clone(),
            entry,
            orders: orders_rx,
            signals: signals_rx,
            events: events_tx,
            deadline: Instant::now() + lifetime + CUSTODY_DEADLINE_MARGIN,
            custody: None,
            end: None,
            terminated: false,
            next_kill: Instant::now(),
            released: false,
            deadline_killed: false,
        };
        if thread::Builder::new()
            .name("wssp-channel".into())
            .spawn(move || custodian.run(request, slot))
            .is_err()
        {
            // The closure (and its slot) was dropped with the failed spawn.
            return refuse(SandboxErrorCode::Internal, "channel setup failed");
        }
        let now = self.now();
        let deadline = now + lifetime;
        self.channels.insert(
            key,
            Chan {
                filter: FrameFilter::new(&nonce, &secret),
                fence,
                kind,
                phase: Phase::Opening,
                io: None,
                orders: orders_tx,
                signals: signals_tx,
                events: events_rx,
                preamble: Some(preamble),
                size,
                prompted: false,
                refused: false,
                birth: None,
                exit: None,
                out: [OutStream::default(), OutStream::default()],
                eof: [false; 2],
                eof_sent: [false; 2],
                idle_since: [None; 2],
                next_stream: 0,
                pending_in: VecDeque::new(),
                input_next: 0,
                input_acked: 0,
                acks_due: Vec::new(),
                stdin_eof: None,
                stdin_closed: false,
                violations: 0,
                credential_leases,
                creator,
                deadline,
                setup_deadline: (now + SETUP_DEADLINE).min(deadline),
                intent: None,
                error: None,
                decided: false,
                kill_ordered: false,
                outstanding: 0,
                end: None,
                exit_sent: false,
                exit_settled: false,
                gone: false,
            },
        );
        Ok(Vec::new())
    }

    /// Supersede channels on lifecycle dispatches (stop, kill, newer
    /// generation): kill-closes; the runtime stop itself also ends them.
    pub(super) fn on_dispatch(&mut self, dispatch: &OperationDispatch) {
        for chan in self.channels.values_mut() {
            let (sandbox_id, generation) = target(&chan.fence);
            if sandbox_id != dispatch.sandbox_id {
                continue;
            }
            let intent = match dispatch.kind.as_str() {
                "sandbox.stop" | "sandbox.kill" => Some(ChannelCloseIntent::SandboxStopped),
                "sandbox.create" | "sandbox.reconnect" if dispatch.generation > generation => {
                    Some(ChannelCloseIntent::Superseded)
                }
                _ => None,
            };
            if let Some(intent) = intent {
                chan.decide(Some(intent), None, true);
            }
        }
    }

    /// Stop every channel with `intent` (kill-class).
    fn stop_all(&mut self, intent: ChannelCloseIntent) {
        for chan in self.channels.values_mut() {
            chan.decide(Some(intent), None, true);
        }
    }

    /// [`Self::poll_with`] collecting the frames (tests).
    #[cfg(test)]
    pub(super) fn poll(&mut self) -> Result<Vec<Outgoing>> {
        let mut frames = Vec::new();
        self.poll_with(&mut |frame| {
            frames.push(frame);
            Ok(())
        })?;
        Ok(frames)
    }

    fn bulk_credit(&self) -> BulkCredit {
        let mut credit = BulkCredit::default();
        for chan in self.channels.values() {
            if chan.kind == ChannelKind::Exec && chan.live() {
                credit.charge(&chan.creator, chan.unacked());
            }
        }
        credit
    }

    /// One socket-loop tick, then its flush. Every decision, guest read,
    /// stdin hand-over and frame of every channel happens in the tick (or in
    /// the frame handlers above), on this thread, without blocking: its
    /// frames only queue. The socket writes follow in order once the tick
    /// has decided everything, so a write that blocks across a deadline or
    /// an authority loss delays only frames decided before it; the next tick
    /// acts on what changed. A failed write ends the session (and with it
    /// every channel); unwritten frames are never needed again.
    pub(super) fn poll_with(&mut self, send: Send<'_>) -> Result<()> {
        let mut outbox = Vec::new();
        #[cfg(test)]
        self.ticking
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let ticked = self.tick(&mut outbox);
        #[cfg(test)]
        self.ticking
            .store(false, std::sync::atomic::Ordering::SeqCst);
        ticked?;
        for frame in outbox {
            send(frame)?;
        }
        Ok(())
    }

    /// Whether a tick is deciding (tests: a flush write must never see it).
    #[cfg(test)]
    pub(super) fn ticking_handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.ticking.clone()
    }

    fn tick(&mut self, outbox: Outbox<'_>) -> Result<()> {
        let now = self.now();
        let judge = self.judge();
        let keys: Vec<(String, String)> = self.channels.keys().cloned().collect();
        // Events, authority and deadlines.
        for key in &keys {
            let Some(chan) = self.channels.get_mut(key) else {
                continue;
            };
            // Authority and the absolute deadline right before the events, in
            // every phase (also while a normal close or an unsettled end is
            // in progress): a loss seen now upgrades a close whose settled
            // answer is already queued (the exit then waits for the kill's
            // answer too).
            judge.check(chan);
            chan.drain_events(outbox);
            if chan.gone {
                continue;
            }
            judge.check_setup(chan);
        }
        // One stall rule: a channel whose oldest unacknowledged output frame
        // is 60 s old closes with `backpressure`. It needs no thresholds and
        // no view of contention: every holder of credit, small or large,
        // returns each frame within 60 s or is closed (and its credit with
        // it), so nothing pins the host cap.
        for chan in self.channels.values_mut().filter(|chan| chan.live()) {
            let stalled = chan.out.iter().any(|out| {
                out.unacked_since
                    .front()
                    .is_some_and(|sent| now.saturating_duration_since(*sent) >= STALL_TIMEOUT)
            });
            if stalled {
                chan.decide(Some(ChannelCloseIntent::Backpressure), None, true);
            }
        }
        // Fair, bounded IO: pty channels first, then bulk ones, each group
        // rotated per tick; at most `TICK_DATA_FRAMES` data frames per tick,
        // `HOST_UNACKED_FRAMES` unacknowledged bulk frames across the host
        // and half of that per sandbox owner, so the socket loop returns to
        // reading acks, heartbeats and closes and no tenant holds the cap.
        let mut order: Vec<(bool, (String, String))> = self
            .channels
            .iter()
            .map(|(key, chan)| (chan.kind != ChannelKind::Pty, key.clone()))
            .collect();
        order.sort();
        let pty = order.iter().filter(|(bulk, _)| !bulk).count();
        let rr = self.rr;
        self.rr = self.rr.wrapping_add(1);
        if pty > 0 {
            order[..pty].rotate_left(rr % pty);
        }
        if order.len() > pty {
            let bulk = order.len() - pty;
            order[pty..].rotate_left(rr % bulk);
        }
        let mut credit = self.bulk_credit();
        let mut budget = TICK_DATA_FRAMES;
        for (_, key) in order {
            let Some(chan) = self.channels.get_mut(&key) else {
                continue;
            };
            if chan.gone {
                continue;
            }
            // This channel's IO decisions rest on checks right before them:
            // another channel's check in this tick may have waited on a
            // journal or credential lock since the ones before its events.
            judge.check(chan);
            judge.check_setup(chan);
            chan.write_stdin(outbox);
            chan.read_output(&judge, &mut budget, &mut credit, outbox)?;
            // The go: the preamble is handed over only after the guest's
            // PROMPT, while the channel is still starting, inside its
            // deadlines, with its authority intact (the check above), and
            // (pty) once the host tty is raw.
            if chan.prompted && chan.preamble.is_some() {
                let ready = chan.admissible(judge.now())
                    && chan.io.as_mut().is_some_and(|io| io.input_ready());
                if ready
                    && let (Some(io), Some(preamble)) = (&mut chan.io, chan.preamble.take())
                    && let Err(refusal) = io.try_write(preamble)
                {
                    if refusal.closed {
                        chan.setup_failed();
                    } else {
                        chan.preamble = Some(refusal.bytes);
                    }
                }
            }
            if end_due(
                chan.phase,
                chan.all_streams(),
                chan.eof,
                chan.idle_since,
                judge.now(),
            ) {
                if chan.kind == ChannelKind::Exec {
                    credit.refund(&chan.creator, chan.unacked());
                }
                chan.end_naturally();
            }
        }
        let gone: Vec<(String, String)> = self
            .channels
            .iter()
            .filter(|(_, chan)| chan.gone)
            .map(|(key, _)| key.clone())
            .collect();
        for key in gone {
            self.channels.remove(&key);
            self.tombstones.push_back(key);
            while self.tombstones.len() > ENDED_TOMBSTONES {
                self.tombstones.pop_front();
            }
        }
        Ok(())
    }

    /// Graceful shutdown: every channel closes with `shutdown`; bounded.
    pub(super) fn shutdown(
        &mut self,
        bound: Duration,
        mut send: impl FnMut(Outgoing) -> Result<()>,
    ) -> Result<()> {
        self.stop_all(ChannelCloseIntent::Shutdown);
        let deadline = Instant::now() + bound;
        while self.channels.values().any(|chan| !chan.exit_sent) && Instant::now() < deadline {
            self.poll_with(&mut send)?;
            thread::sleep(CUSTODY_POLL);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "channel_tests.rs"]
mod tests;
