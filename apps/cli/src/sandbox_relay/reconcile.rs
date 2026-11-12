//! Receipt inventory is emitted after authenticated hello, before fresh dispatch.
//! Interrupted work stays unknown; no running process is adopted after restart.
//! Work carried across a relay transport drop (same process, live worker) is
//! adopted, settled by receipt, or revoked by the adoption step, before the census.
use super::journal::{HostJournal, ReceiptPhase, TransportBindingV11};
use super::journal_key::KeyControl;
#[cfg(test)]
use crate::sandbox_relay::test_support::FixtureRuntime;
use anyhow::{Context, Result, bail};
use sandbox_protocol::{
    DaemonControlMessage, OperationState, ProtocolErrorDetail, SandboxErrorCode,
};

/// What the reconnect's adoption step needs from the process-scoped owners
/// of work carried across a relay transport drop.
pub(super) struct Adoption<'a> {
    pub authority: &'a super::authority::HostAuthority,
    pub relay: &'a super::supervisor::RelaySupervisor,
    /// The connection epoch `hello.ok` assigned to this session.
    pub epoch: u64,
    /// Process-scoped receipt resolutions (WP2): deferred, not dropped, when
    /// a runtime query stalls.
    pub resolutions: &'a super::resolutions::InFlightResolutions,
}

impl Adoption<'_> {
    /// Sandboxes a census must not wait on: carried or pending lifecycle
    /// work, and queued or active lifecycle jobs.
    pub(super) fn busy(&self) -> std::collections::HashSet<String> {
        let mut busy = self.authority.pending_lifecycle_sandboxes();
        busy.extend(self.relay.lifecycle_busy());
        busy.extend(self.resolutions.busy_sandboxes());
        busy
    }
}

/// The daemon never sends more adoption frames in one session (the server's
/// bound); further carried work is revoked locally.
const MAX_ADOPT_FRAMES: usize = 512;

/// Server pushes held while reconciliation owns the socket. Bounds the
/// buffer: each frame is at most one JSON control frame.
const MAX_DEFERRED_PUSHES: usize = 64;

/// Server-initiated control frames that may legitimately arrive between
/// `hello.ok` and `reconcile.complete`: the server sends them on its own
/// schedule, not in answer to a reconciliation frame. Anything else still
/// fails reconciliation.
///
/// Policy is never held behind workload reconciliation: the deployment
/// egress blocklist (E6) is applied the moment it arrives (the guard monitor
/// is woken to push it), because receipt, adoption, audit and census waits
/// can add up to minutes while running guests keep the old deny set. Only
/// frames that need post-registration state (the host-terminal lane) are
/// kept, in arrival order, for the dispatch loop to process first once the
/// session is registered.
#[derive(Default)]
pub(super) struct DeferredPushes {
    frames: std::collections::VecDeque<tungstenite::Utf8Bytes>,
    /// Receives `egress.blocklist` during reconciliation.
    egress: Option<std::sync::Arc<super::egress_state::NodeEgress>>,
    /// The session's periodic host reports. Every reconciliation read ticks
    /// them, as the dispatch loop does afterwards (`host_reports`).
    reports: Option<super::host_reports::HostReports>,
    evidence: super::evidence::Evidence,
    /// The session's server-silence deadline (WP2): idle read time while a
    /// reconciliation phase awaits no answer counts toward it, as in the
    /// dispatch loop. `None`: the default for a 5 s heartbeat.
    silence: Option<std::time::Duration>,
}

impl DeferredPushes {
    /// The session's host reports, ticked by every reconciliation read.
    pub(super) fn install_reports(&mut self, reports: super::host_reports::HostReports) {
        self.reports = Some(reports);
    }

    pub(super) fn reports(&mut self) -> Option<&mut super::host_reports::HostReports> {
        self.reports.as_mut()
    }

    /// The session's server-silence deadline (`server_silence_deadline`).
    pub(super) fn set_silence_deadline(&mut self, deadline: std::time::Duration) {
        self.silence = Some(deadline);
    }

    fn silence_deadline(&self) -> std::time::Duration {
        self.silence.unwrap_or_else(|| {
            super::connect::server_silence_deadline(std::time::Duration::from_secs(5))
        })
    }

    /// This session's re-offer ledger (used with `expiryStatusResults`).
    pub(super) fn evidence(&mut self) -> &mut super::evidence::Evidence {
        &mut self.evidence
    }

    /// Pool health published with the current storage sequence (empty
    /// without reports).
    pub(super) fn published_health(&mut self) -> super::evidence::PoolHealth {
        self.reports()
            .map(|reports| reports.published_health())
            .unwrap_or_default()
    }

    /// Names receipts that are still resolving when reconciliation finishes.
    fn complete(
        &self,
        resolutions: &super::resolutions::InFlightResolutions,
    ) -> DaemonControlMessage {
        DaemonControlMessage::ReconcileComplete {
            pending_receipts: Some(resolutions.pending()),
        }
    }

    /// Sends the host reports that are due (none without installed reports).
    pub(super) fn tick_reports(
        &mut self,
        socket: &mut tungstenite::WebSocket<
            tungstenite::stream::MaybeTlsStream<std::net::TcpStream>,
        >,
    ) -> Result<()> {
        match &mut self.reports {
            Some(reports) => reports.tick(socket),
            None => Ok(()),
        }
    }

    /// Apply `egress.blocklist` frames that arrive during reconciliation to
    /// `egress` at once (same handling as the dispatch loop). Without a node
    /// egress state the frame is dropped, as the dispatch loop drops it.
    pub(super) fn handle_egress_with(
        &mut self,
        egress: Option<std::sync::Arc<super::egress_state::NodeEgress>>,
    ) {
        self.egress = egress;
    }

    /// Pushes that need post-registration state: the host-terminal lane,
    /// which the server opens on registration alone.
    fn deferrable(message: &sandbox_protocol::ServerControlMessage) -> bool {
        use sandbox_protocol::ServerControlMessage as M;
        matches!(
            message,
            M::HostTerminalPolicyRaise { .. }
                | M::TerminalOpen { .. }
                | M::TerminalResize { .. }
                | M::TerminalClose { .. }
                | M::TerminalAck { .. }
        )
    }

    /// Consumes a server push: applies an egress blocklist at once, keeps
    /// `text` when `message` is a deferrable push. `Ok(false)` for any other
    /// frame. Errors once the bound is reached: a peer that floods pushes
    /// during reconciliation is not a peer to buffer for.
    fn defer(
        &mut self,
        message: &sandbox_protocol::ServerControlMessage,
        text: &tungstenite::Utf8Bytes,
    ) -> Result<bool> {
        if let sandbox_protocol::ServerControlMessage::EgressBlocklist(list) = message {
            if let Some(node) = &self.egress {
                node.receive_blocklist(list);
            }
            return Ok(true);
        }
        if !Self::deferrable(message) {
            return Ok(false);
        }
        if self.frames.len() >= MAX_DEFERRED_PUSHES {
            bail!("too many server pushes during reconciliation");
        }
        self.frames.push_back(text.clone());
        Ok(true)
    }

    /// The next held frame, in arrival order, for the dispatch loop.
    pub(super) fn next(&mut self) -> Option<tungstenite::Message> {
        self.frames.pop_front().map(tungstenite::Message::Text)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.frames.len()
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn reconcile_after_hello(
    journal: &std::sync::Arc<HostJournal>,
    binding: &TransportBindingV11,
    runtime: &std::sync::Arc<dyn sandbox_runtime::SandboxRuntime>,
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: sandbox_protocol::WireCodes,
    expiry: &super::expiry::ExpiryService,
    epoch: Option<u64>,
    adoption: Option<&Adoption<'_>>,
    deferred: &mut DeferredPushes,
) -> Result<ExpiryReported> {
    let key_control = KeyControl {
        journal,
        binding,
        epoch,
        credentials: adoption.and_then(|a| a.relay.credentials()),
    };
    if binding.host_owner_id.is_empty() {
        bail!("hello has no owner binding");
    }
    // Carried work is still owned by a live worker. It is neither crash
    // residue to resolve nor a receipt to replay here: the adoption step
    // below adopts it, receipts it, or revokes it.
    let carried: std::collections::HashSet<String> = adoption
        .map(|a| {
            a.authority
                .carried()
                .into_iter()
                .map(|(id, _)| id)
                .collect()
        })
        .unwrap_or_default();
    // Receipt resolutions outlive sessions (WP2). One that finished since the
    // last session already journaled its result, which the replay below
    // reports; a failed one is retried below.
    let session_resolutions = super::resolutions::InFlightResolutions::default();
    let resolutions = adoption.map_or(&session_resolutions, |a| a.resolutions);
    for (operation_id, finished) in resolutions.take_finished() {
        if let Err(error) = finished {
            tracing::warn!(
                operation_id,
                "receipt resolution failed ({error:#}); retrying"
            );
        }
    }
    // Never wait on a sandbox whose carried or in-flight lifecycle work, or a
    // still-running receipt resolution, may hold its lock (live finding R-1).
    let mut busy = adoption.map(Adoption::busy).unwrap_or_default();
    busy.extend(resolutions.busy_sandboxes());
    // Carried work is adopted, and the dispatch
    // audit answered, before any receipt is replayed. A receipt resolution
    // may wait up to 30 s; waiting on stalled ones first could exhaust the
    // carry grace and revoke healthy carried commands. Independent: carried
    // receipts are skipped by the replay below (`carried`), adoption sends
    // only the carried attempts' own receipts, and the audit's verdict reads
    // the journal, which replay only shrinks for operations the server has
    // then settled (no longer unacknowledged).
    if let Some(adoption) = adoption {
        adopt_carried(
            journal,
            binding,
            socket,
            wire,
            key_control,
            adoption,
            deferred,
        )?;
        // Only a reconnect of this process can own an older epoch's frames.
        if adoption.authority.attached_before(adoption.epoch) {
            audit_dispatches(journal, socket, wire, key_control, adoption, deferred)?;
        }
    }
    // Present later lifecycle evidence before its predecessors. The server can
    // settle old UNKNOWN rows and return cleanup-bound confirmations in this
    // same inventory pass. Admission still waits for the entire inventory.
    let mut receipts = journal.matching(binding)?;
    receipts.sort_by_key(|receipt| std::cmp::Reverse(receipt.generation));
    for mut receipt in receipts {
        if carried.contains(&receipt.operation_id) {
            continue;
        }
        // R-1: resolving an older unresolved receipt queries the runtime for
        // its sandbox, whose lock carried lifecycle work may hold. Defer it
        // to a later reconnect (the server reconciles it as before).
        if receipt.phase != ReceiptPhase::Result && busy.contains(&receipt.sandbox_id) {
            continue;
        }
        let operation_id = receipt.operation_id.clone();
        // File content is transient until C27-C30. Reporting unknown prevents
        // claiming a usable download without bytes. The server may still confirm
        // its exact-binding terminal row; only our local Result can be reclaimed.
        if !receipt.digest_pruned && receipt.phase != ReceiptPhase::Result {
            // A stalled or capped resolution is deferred, never fatal: the
            // receipt stays journaled (WP2).
            let Some(resolved) = resolve_without_blocking_reader(
                resolutions,
                journal,
                runtime,
                receipt,
                socket,
                key_control,
                deferred,
            )?
            else {
                continue;
            };
            receipt = resolved;
        } else {
            // No download bytes after restart. Do not rewrite the durable result.
            receipt = reportable_receipt(receipt);
        }
        send_receipt(socket, wire, receipt)?;
        // One outstanding inventory entry bounds both peer queues on large journals.
        await_receipt_ack(
            socket,
            journal,
            binding,
            key_control,
            deferred,
            &operation_id,
        )?;
    }
    // A receipt deferred above still holds its sandbox: the census must not
    // wait on it either (WP2).
    busy.extend(resolutions.busy_sandboxes());
    // Ruling (d): both passes can block on the host daemon; the socket is
    // read (and a blocklist applied) while they run.
    let handle = expiry.handle();
    while_reading(
        socket,
        "expiry reconciliation",
        key_control,
        deferred,
        move |fence| {
            handle.reconcile_until(super::expiry::RECONCILE_BUDGET, &|| fence.is_cancelled())
        },
    )??;
    let failures = expiry.failures();
    let completions = expiry.completions();
    // Per-entry results: storage health keeps renewing through the
    // census. Each page observes its roots right before it is sent and
    // carries the sequence of the last observation published before
    // that, so the server (which applies frames in order) judges it
    // against exactly that observation. An entry it refused only for
    // stale storage is not counted as reported: the dispatch loop
    // republishes its expiry arm under a current observation.
    let states = {
        let (journal, runtime, failures) = (journal.clone(), runtime.clone(), failures.clone());
        while_reading(
            socket,
            "inventory census",
            key_control,
            deferred,
            move |fence| {
                let runtime = runtime.with_cancellation(fence);
                inventory_states_skipping(&journal, runtime.as_ref(), &failures, &busy)
            },
        )??
    };
    send_census_judged(
        socket,
        journal,
        runtime,
        states,
        key_control,
        wire,
        deferred,
    )?;
    socket.send(tungstenite::Message::Text(
        super::plain_frame(&deferred.complete(resolutions))?.into(),
    ))?;
    Ok(expiry_digest(&failures, &completions))
}

/// How often reconciliation heartbeats while it waits on the server: the
/// session cadence (5 s in production), so it stays well inside the silence
/// deadline even when a debug build's `WSSP_TEST_RELAY_TIMING` shortens it.
fn reconcile_heartbeat() -> std::time::Duration {
    super::connect::session_heartbeat(std::time::Duration::from_secs(5))
}

fn await_receipt_ack(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    journal: &HostJournal,
    binding: &TransportBindingV11,
    key_control: KeyControl<'_>,
    deferred: &mut DeferredPushes,
    operation_id: &str,
) -> Result<()> {
    await_server(
        socket,
        "receipt",
        Some(key_control),
        deferred,
        |message| match message {
            sandbox_protocol::ServerControlMessage::ReceiptAck {
                operation_id: acknowledged,
            } if acknowledged == operation_id => Ok(true),
            sandbox_protocol::ServerControlMessage::ReceiptConfirmed(confirmed)
                if confirmed.operation_id == operation_id =>
            {
                journal.confirm(binding, &confirmed)?;
                Ok(false)
            }
            sandbox_protocol::ServerControlMessage::HeartbeatPong { .. } => Ok(false),
            _ => bail!("unexpected reconciliation response"),
        },
    )
}

/// The receipt a host reports for a journaled Result. Download bytes never
/// survive a session, so a successful `file.get` is reported as unknown.
pub(super) fn reportable_receipt(
    mut receipt: super::journal::HostReceipt,
) -> super::journal::HostReceipt {
    if receipt.kind == "file.get" && receipt.state == OperationState::Succeeded {
        receipt.state = OperationState::UnknownOutcome;
        receipt.result = None;
        receipt.error_code = Some(SandboxErrorCode::UnknownOutcome.into());
        receipt.error_message = Some("download bytes no longer retained".into());
    }
    receipt
}

/// The adoption step (before `expiry.reconcile()` and the census). Each
/// carried attempt, newest generation first, is adopted by the server for
/// this epoch, settled by its exact receipt (finished while detached), or
/// revoked. With nothing carried, no frame is sent.
fn adopt_carried(
    journal: &HostJournal,
    binding: &TransportBindingV11,
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: sandbox_protocol::WireCodes,
    key_control: KeyControl<'_>,
    adoption: &Adoption<'_>,
    deferred: &mut DeferredPushes,
) -> Result<()> {
    let carried = adoption.authority.carried();
    if carried.is_empty() {
        return Ok(());
    }
    let (mut adopted, mut revoked, mut receipted, mut sent) = (0usize, 0usize, 0usize, 0usize);
    for (id, work) in carried {
        let receipt = journal.lookup(&id).filter(|receipt| {
            receipt.binds(binding)
                && !receipt.digest_pruned
                && receipt.generation == work.generation
                && receipt.attempt == work.attempt
        });
        let Some(receipt) = receipt else {
            adoption.authority.revoke_carried(&id);
            revoked += 1;
            continue;
        };
        // Finished while detached and nothing left to stream: the exact
        // receipt settles it. Output still draining needs the live window,
        // so such a command is adopted instead.
        if receipt.phase == ReceiptPhase::Result
            && !adoption
                .relay
                .output_open(&id, work.generation, work.attempt)
        {
            send_receipt(socket, wire, reportable_receipt(receipt))?;
            await_receipt_ack(socket, journal, binding, key_control, deferred, &id)?;
            adoption.authority.complete(&id);
            receipted += 1;
            continue;
        }
        // Review #1: never adopt an attempt no worker will execute or finish
        // (its worker ended without a definite Result). Receipt recovery and
        // server reconciliation settle it, exactly as before adoption.
        // A finished attempt whose output still drains is adopted below:
        // its completion is queued and publishes once adopted.
        if receipt.phase != ReceiptPhase::Result
            && !adoption.authority.owned(&id, work.generation, work.attempt)
        {
            adoption.authority.revoke_carried(&id);
            revoked += 1;
            continue;
        }
        if sent >= MAX_ADOPT_FRAMES {
            adoption.authority.revoke_carried(&id);
            revoked += 1;
            continue;
        }
        let Some(body_hash) = receipt.server_request_hash().map(str::to_owned) else {
            adoption.authority.revoke_carried(&id);
            revoked += 1;
            continue;
        };
        sent += 1;
        socket.send(tungstenite::Message::Text(
            super::spell(
                wire,
                &DaemonControlMessage::OperationAdopt {
                    sandbox_owner_id: receipt.sandbox_owner_id.clone(),
                    operation_id: id.clone(),
                    sandbox_id: receipt.sandbox_id.clone(),
                    generation: work.generation,
                    attempt: work.attempt,
                    body_hash,
                    idempotency_key: receipt.idempotency_key.clone(),
                    kind: receipt.kind.clone(),
                    // Stable while unadopted: the effect gate holds Intent work.
                    phase: if receipt.phase == ReceiptPhase::Intent {
                        sandbox_protocol::AdoptPhase::Intent
                    } else {
                        sandbox_protocol::AdoptPhase::Effect
                    },
                    stdin_next_sequence: adoption.authority.stdin_next(&id),
                },
                None,
            )?
            .into(),
        ))?;
        let mut answer = false;
        await_server(
            socket,
            "adoption",
            Some(key_control),
            deferred,
            |message| match message {
                sandbox_protocol::ServerControlMessage::OperationAdoptResult {
                    operation_id,
                    generation,
                    attempt,
                    adopted,
                } if operation_id == id
                    && generation == work.generation
                    && attempt == work.attempt =>
                {
                    answer = adopted;
                    Ok(true)
                }
                sandbox_protocol::ServerControlMessage::HeartbeatPong { .. } => Ok(false),
                _ => bail!("unexpected adoption response"),
            },
        )?;
        if answer
            && adoption
                .authority
                .adopt(&id, work.generation, work.attempt, adoption.epoch)
        {
            // R2-1: the adopting session must learn the process identity even
            // if its first publication died with the old transport.
            adoption
                .relay
                .republish_started(&id, work.generation, work.attempt);
            adopted += 1;
            continue;
        }
        // Refused, or adopted after the grace revoked it: revoked either way.
        // A Result that already exists is settled now; a later one by the
        // late-receipt rule when its completion drains.
        adoption.authority.revoke_carried(&id);
        revoked += 1;
        if let Some(result) = journal
            .lookup(&id)
            .filter(|r| r.phase == ReceiptPhase::Result && !r.digest_pruned)
            && adoption
                .authority
                .take_late(&id, work.generation, work.attempt)
        {
            send_receipt(socket, wire, reportable_receipt(result))?;
            await_receipt_ack(socket, journal, binding, key_control, deferred, &id)?;
        }
    }
    tracing::info!(
        adopted,
        revoked,
        receipted,
        "carried relay work reconciled after reconnect"
    );
    Ok(())
}

/// Live finding B-1: the server may have sent work on an older epoch that
/// died with the transport. Page through every attempt it still believes is
/// unacknowledged and answer with a positive verdict: `received: false` only
/// when this process attached that epoch (it owned that socket) and neither
/// its journal nor its authority has any record of the operation. The
/// server then dispatches it again instead of reconciling it UNKNOWN.
fn audit_dispatches(
    journal: &HostJournal,
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: sandbox_protocol::WireCodes,
    key_control: KeyControl<'_>,
    adoption: &Adoption<'_>,
    deferred: &mut DeferredPushes,
) -> Result<()> {
    let (mut audited, mut undelivered) = (0usize, 0usize);
    for page in 0..=1024u64 {
        socket.send(tungstenite::Message::Text(
            super::spell(
                wire,
                &DaemonControlMessage::DispatchAuditRequest { page },
                None,
            )?
            .into(),
        ))?;
        let mut reply = None;
        await_server(
            socket,
            "dispatch audit",
            Some(key_control),
            deferred,
            |message| match message {
                sandbox_protocol::ServerControlMessage::DispatchAuditPage {
                    page: answered,
                    complete,
                    entries,
                } if answered == page => {
                    reply = Some((complete, entries));
                    Ok(true)
                }
                sandbox_protocol::ServerControlMessage::HeartbeatPong { .. } => Ok(false),
                sandbox_protocol::ServerControlMessage::ProtocolError { .. } => {
                    bail!("relay server refused dispatch audit")
                }
                _ => bail!("unexpected dispatch audit response"),
            },
        )?;
        let Some((complete, entries)) = reply else {
            bail!("dispatch audit page missing");
        };
        let verdicts: Vec<_> = entries
            .into_iter()
            .map(|entry| {
                let never_received = adoption.authority.attached_epoch(entry.connection_epoch)
                    && journal.lookup(&entry.operation_id).is_none()
                    && adoption.authority.pending(&entry.operation_id).is_none();
                audited += 1;
                undelivered += usize::from(never_received);
                sandbox_protocol::DispatchAuditVerdict {
                    operation_id: entry.operation_id,
                    generation: entry.generation,
                    attempt: entry.attempt,
                    received: !never_received,
                }
            })
            .collect();
        socket.send(tungstenite::Message::Text(
            super::spell(
                wire,
                &DaemonControlMessage::DispatchAuditResult {
                    page,
                    entries: verdicts,
                },
                None,
            )?
            .into(),
        ))?;
        if complete {
            break;
        }
    }
    if audited > 0 {
        tracing::info!(
            audited,
            undelivered,
            "dispatch audit: undelivered work is dispatched again"
        );
    }
    Ok(())
}

/// Test census of managed instances and their durable leases.
#[cfg(test)]
pub(super) fn inventory_census(
    journal: &HostJournal,
    runtime: &dyn sandbox_runtime::SandboxRuntime,
    failures: &super::expiry::ExpiryFailures,
) -> Result<Vec<sandbox_protocol::InventoryEntry>> {
    inventory_census_skipping(journal, runtime, failures, &Default::default())
}

/// [`inventory_census`] that does not wait on `busy` sandboxes.
#[cfg(test)]
pub(super) fn inventory_census_skipping(
    journal: &HostJournal,
    runtime: &dyn sandbox_runtime::SandboxRuntime,
    failures: &super::expiry::ExpiryFailures,
    busy: &std::collections::HashSet<String>,
) -> Result<Vec<sandbox_protocol::InventoryEntry>> {
    inventory_census_filtered(journal, runtime, failures, None, busy, true)
}

/// Managed instances and durable leases without root evidence. Each page
/// observes its roots right before sending ([`observe_entry_root`]).
fn inventory_states_skipping(
    journal: &HostJournal,
    runtime: &dyn sandbox_runtime::SandboxRuntime,
    failures: &super::expiry::ExpiryFailures,
    busy: &std::collections::HashSet<String>,
) -> Result<Vec<sandbox_protocol::InventoryEntry>> {
    inventory_census_filtered(journal, runtime, failures, None, busy, false)
}

fn inventory_census_filtered(
    journal: &HostJournal,
    runtime: &dyn sandbox_runtime::SandboxRuntime,
    failures: &super::expiry::ExpiryFailures,
    selected: Option<&std::collections::BTreeSet<&String>>,
    busy: &std::collections::HashSet<String>,
    observe_roots: bool,
) -> Result<Vec<sandbox_protocol::InventoryEntry>> {
    let instances = if let Some(ids) = selected {
        // Expiry publication must not inspect unrelated running VMs' DNS/ACLs.
        // Each targeted observation still verifies the exact journal binding.
        let mut entries = Vec::new();
        for id in ids {
            let lease = journal.lease(id);
            let state = runtime
                .query_sandbox(
                    id,
                    None,
                    lease
                        .as_ref()
                        .and_then(|l| l.template_fingerprint.as_deref()),
                )
                .map_err(|e| anyhow::anyhow!(e.message))?;
            if let Some(state) = state {
                entries.push(sandbox_runtime::RuntimeInventoryEntry {
                    sandbox_id: (*id).clone(),
                    state,
                    configured_size: sandbox_runtime::ConfiguredSize::Unobserved(
                        sandbox_runtime::RuntimeError::new(
                            SandboxErrorCode::Internal,
                            "size not observed for expiry status",
                        ),
                    ),
                });
            }
        }
        entries
    } else {
        runtime
            .sandbox_inventory_skipping(busy)
            .map_err(|e| anyhow::anyhow!(e.message))?
    };
    let mut census = std::collections::BTreeMap::new();
    for entry in instances {
        census.insert(entry.sandbox_id, (entry.state, None));
    }
    // An unavailable pool is inconclusive, never synthesized VM/root absence.
    for (id, root) in journal.retained_roots() {
        if selected.is_some_and(|ids| !ids.contains(&id)) {
            continue;
        }
        if runtime.observe_storage_pool(&root.root().pool).is_err() {
            census.insert(
                id,
                (sandbox_protocol::SandboxLifecycleState::Unreachable, None),
            );
        } else {
            census
                .entry(id)
                .or_insert((sandbox_protocol::SandboxLifecycleState::Absent, None));
        }
    }
    for row in journal.leases() {
        if selected.is_some_and(|ids| !ids.contains(&row.sandbox_id)) {
            continue;
        }
        let expiry_failure = failures
            .get(&row.sandbox_id)
            .filter(|f| {
                row.expired
                    && !row.expiry_complete
                    && f.generation == row.generation
                    && f.revision == row.lease.revision
            })
            .map(|f| f.failure.clone());
        let lease = sandbox_protocol::InventoryLease {
            generation: row.generation,
            lease: row.lease,
            expired: row.expired,
            expiry_complete: row.expiry_complete,
            timer_expired: row.timer_expired && row.expired,
            expiry_failure,
        };
        census
            .entry(row.sandbox_id)
            .or_insert((sandbox_protocol::SandboxLifecycleState::Absent, None))
            .1 = Some(lease);
    }
    // Recheck after the entire walk: disappearing backing storage cannot
    // turn an earlier VM-only observation into release authority.
    for (id, root) in journal.retained_roots() {
        if selected.is_some_and(|ids| !ids.contains(&id)) {
            continue;
        }
        if runtime.observe_storage_pool(&root.root().pool).is_err()
            && let Some(entry) = census.get_mut(&id)
        {
            entry.0 = sandbox_protocol::SandboxLifecycleState::Unreachable;
        }
    }
    if census.len() as u64
        > sandbox_protocol::INVENTORY_MAX_PAGES
            * sandbox_protocol::INVENTORY_PAGE_MAX_ENTRIES as u64
    {
        bail!("managed inventory exceeds census capacity");
    }
    census
        .into_iter()
        .map(|(sandbox_id, (state, lease))| {
            if !sandbox_protocol::valid_inventory_sandbox_id(&sandbox_id) {
                bail!("managed instance has an invalid sandbox id");
            }
            let mut entry = sandbox_protocol::InventoryEntry {
                sandbox_owner_id: journal.sandbox_owner(&sandbox_id),
                root: None,
                sandbox_id,
                state,
                lease,
            };
            if observe_roots {
                observe_entry_root(journal, runtime, &mut entry);
            }
            Ok(entry)
        })
        .collect()
}

/// `sandbox_id`'s bound root allocation (retained, or its lease's), and
/// whether the lease records its root deleted.
fn bound_allocation(
    journal: &HostJournal,
    sandbox_id: &str,
) -> Option<(sandbox_protocol::capacity_v11::PinnedAllocationV11, bool)> {
    let retained = journal
        .retained_roots()
        .remove(sandbox_id)
        .map(|r| (r.allocation, false));
    retained.or_else(|| {
        journal
            .leases()
            .into_iter()
            .find(|r| r.sandbox_id == sandbox_id)
            .and_then(|r| r.allocation.map(|a| (a, r.root_deleted)))
    })
}

/// The journal's pool binding (`name`, `marker`) of each entry observed
/// without a root: the pool whose recovery can cure its refusal.
pub(super) fn pool_bindings(
    journal: &HostJournal,
    entries: &[sandbox_protocol::InventoryEntry],
) -> std::collections::BTreeMap<String, super::evidence::PoolBinding> {
    entries
        .iter()
        .filter(|entry| entry.root.is_none())
        .filter_map(|entry| {
            let (allocation, _) = bound_allocation(journal, &entry.sandbox_id)?;
            Some((
                entry.sandbox_id.clone(),
                (allocation.storage_pool_name, allocation.storage_marker),
            ))
        })
        .collect()
}

/// Observes `entry`'s bound root (retained, or its lease's allocation), if
/// any, into `entry.root` (sequence 0: the caller stamps it). Exact-root
/// absence with network cleanup supersedes the earlier VM power state.
fn observe_entry_root(
    journal: &HostJournal,
    runtime: &dyn sandbox_runtime::SandboxRuntime,
    entry: &mut sandbox_protocol::InventoryEntry,
) {
    let bound = bound_allocation(journal, &entry.sandbox_id);
    let root = bound.and_then(|(a, deleted)| {
        let root = super::journal::storage::allocation_root(&a);
        let name = sandbox_runtime::default_incus_instance_name(&entry.sandbox_id);
        let census = runtime.storage_root_census(&root.pool).ok()?;
        let volume = census.roots.iter().find(|r| r.instance_name == name);
        if volume.is_some_and(|v| v.size_bytes != Some(root.size_bytes()))
            || runtime.observe_storage_pool(&root.pool).is_err()
        {
            return None;
        }
        let network_cleanup_complete = if deleted && volume.is_none() {
            match runtime.prove_root_absent(&root, &name) {
                Ok(_) => true,
                // A pinned-root mismatch is conclusive absence-without-cleanup
                // evidence. Timeouts, cancellation and IO failures are not.
                Err(error) if error.code == sandbox_protocol::SandboxErrorCode::VmSizeMismatch => {
                    false
                }
                Err(_) => return None,
            }
        } else {
            false
        };
        Some(sandbox_protocol::RootObservation {
            storage_pool_name: a.storage_pool_name,
            storage_marker: a.storage_marker,
            disk_gi_b: a.disk_gi_b,
            state: if volume.is_some() {
                sandbox_protocol::RootState::Present
            } else {
                sandbox_protocol::RootState::Absent
            },
            network_cleanup_complete,
            observation_sequence: 0,
        })
    });
    // The VM census can precede a concurrent destroy. Exact-root
    // absence is observed later and includes a positive VM-absence
    // check, so that stronger proof supersedes the earlier power state.
    if root.as_ref().is_some_and(|root| {
        root.state == sandbox_protocol::RootState::Absent && root.network_cleanup_complete
    }) {
        entry.state = sandbox_protocol::SandboxLifecycleState::Absent;
    }
    entry.root = root;
}

/// Last published state of a sandbox's lease arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExpiryArmState {
    /// The arm's expiry completed, on the first attempt or after failures.
    Complete,
    /// The arm's expiry is still failing; the attempt count is published so a
    /// retry changes the digest.
    Failing(u32),
}

/// Last published expiry arm per sandbox: (generation, revision, state).
pub(super) type ExpiryReported = std::collections::BTreeMap<String, (u64, u64, ExpiryArmState)>;

/// While connected, publish each sandbox whose expiry arm appeared, changed or
/// cleared since `reported`, with its current instance state and lease, so the
/// server neither waits for a reconnect nor guesses. Completions are tracked
/// independently of failures: a first-attempt success is published too.
pub(super) fn expiry_digest(
    failures: &super::expiry::ExpiryFailures,
    completions: &super::expiry::ExpiryCompletions,
) -> ExpiryReported {
    let mut digest: ExpiryReported = completions
        .iter()
        .map(|(id, &(generation, revision))| {
            (id.clone(), (generation, revision, ExpiryArmState::Complete))
        })
        .collect();
    for (id, f) in failures {
        // A live failure is the newer truth for its sandbox.
        digest.insert(
            id.clone(),
            (
                f.generation,
                f.revision,
                ExpiryArmState::Failing(f.failure.attempts),
            ),
        );
    }
    digest
}

/// Runs on the observation worker: it reads the runtime inventory.
/// A sandbox's lease arm as the journal holds it: what one targeted
/// observation is bound to (`None`: no lease). A renewal (a new revision of
/// the same arm) is not part of it: it changes no VM state, and continuous
/// renewals must not keep an observation from ever being offered. The revision attached is the newest the journal holds.
fn lease_arm(journal: &HostJournal, id: &str) -> Option<(u64, bool, bool)> {
    journal
        .lease(id)
        .map(|row| (row.generation, row.expired, row.expiry_complete))
}

/// Targeted observation of `selected` (connected evidence). The runtime state
/// is read before the journal lease is attached, and a lifecycle dispatch can
/// replace the lease in between (a reconnect admitted while the worker saw
/// the old VM stopped). Each entry is therefore bound to the lease arm
/// snapshotted *before* observing: one whose arm changed meanwhile is never
/// offered (it is returned as `raced`, retried by the next observation).
/// A lifecycle admitted *before* the snapshot whose result follows it is
/// ordered by the server instead (`observationFence`, see `evidence.rs`).
fn observe_selected(
    journal: &HostJournal,
    runtime: &dyn sandbox_runtime::SandboxRuntime,
    failures: &super::expiry::ExpiryFailures,
    selected: &std::collections::BTreeSet<&String>,
) -> Result<(
    Vec<sandbox_protocol::InventoryEntry>,
    std::collections::BTreeSet<String>,
)> {
    let before: std::collections::BTreeMap<&String, _> = selected
        .iter()
        .map(|id| (*id, lease_arm(journal, id)))
        .collect();
    let observed = inventory_census_filtered(
        journal,
        runtime,
        failures,
        Some(selected),
        &Default::default(),
        true,
    )?;
    let mut raced = std::collections::BTreeSet::new();
    for id in selected {
        if before.get(id).copied().flatten() != lease_arm(journal, id) {
            raced.insert((*id).clone());
        }
    }
    let entries = observed
        .into_iter()
        .filter(|entry| {
            !raced.contains(&entry.sandbox_id)
                && entry
                    .lease
                    .as_ref()
                    .map(|l| (l.generation, l.expired, l.expiry_complete))
                    == before.get(&entry.sandbox_id).copied().flatten()
        })
        .collect();
    Ok((entries, raced))
}

/// One connected evidence offer (`expiryStatusResults`), observed on the
/// observation worker.
pub(super) struct ExpiryOffer {
    /// Observed entries to offer, ascending.
    pub entries: Vec<sandbox_protocol::InventoryEntry>,
    /// Arms whose digest changed since `reported`: the change each reports
    /// (`None` clears it).
    pub changes: std::collections::BTreeMap<String, Option<(u64, u64, ExpiryArmState)>>,
    /// Entries re-offered by the ledger.
    pub reoffered: std::collections::BTreeSet<String>,
    /// Entries whose lease changed while observing: neither offered nor
    /// reported, the next observation retries them.
    pub raced: std::collections::BTreeSet<String>,
    /// The journal's pool binding of offered entries without a root.
    pub bindings: std::collections::BTreeMap<String, super::evidence::PoolBinding>,
}

/// Observes every arm whose digest changed since `reported`, plus the
/// `reoffer` entries the ledger has due. Changed arms without a lease are
/// reported without an offer; re-offered entries are kept with or without one
/// (census evidence for a retained root carries none).
pub(super) fn expiry_status_offer(
    journal: &HostJournal,
    runtime: &dyn sandbox_runtime::SandboxRuntime,
    failures: &super::expiry::ExpiryFailures,
    completions: &super::expiry::ExpiryCompletions,
    reported: &ExpiryReported,
    reoffer: std::collections::BTreeSet<String>,
    blocked: &std::collections::BTreeSet<String>,
) -> Result<ExpiryOffer> {
    let changes = expiry_changes(failures, completions, reported, blocked);
    let selected: std::collections::BTreeSet<&String> =
        changes.keys().chain(reoffer.iter()).collect();
    let (entries, raced) = if selected.is_empty() {
        (Vec::new(), Default::default())
    } else {
        observe_selected(journal, runtime, failures, &selected)?
    };
    let entries: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            reoffer.contains(&e.sandbox_id)
                || (changes.contains_key(&e.sandbox_id) && e.lease.is_some())
        })
        .collect();
    let bindings = pool_bindings(journal, &entries);
    Ok(ExpiryOffer {
        entries,
        changes,
        reoffered: reoffer,
        raced,
        bindings,
    })
}

/// Arms whose digest changed since `reported` (`None`: cleared), except the
/// `blocked` ones a pending re-offer paces.
pub(super) fn expiry_changes(
    failures: &super::expiry::ExpiryFailures,
    completions: &super::expiry::ExpiryCompletions,
    reported: &ExpiryReported,
    blocked: &std::collections::BTreeSet<String>,
) -> std::collections::BTreeMap<String, Option<(u64, u64, ExpiryArmState)>> {
    let current = expiry_digest(failures, completions);
    current
        .iter()
        .filter(|(id, v)| reported.get(*id) != Some(*v))
        .map(|(id, v)| (id.clone(), Some(*v)))
        .chain(
            reported
                .keys()
                .filter(|id| !current.contains_key(*id))
                .map(|id| (id.clone(), None)),
        )
        .filter(|(id, _)| !blocked.contains(id))
        .collect()
}

/// The census with per-entry results (`censusEntryResults`). Pages are
/// strictly ascending and acknowledged one at a time. Each page's roots are
/// observed right before it is sent (while the socket is read) and stamped
/// with the last published storage sequence; publication pauses only for
/// that window, so the page reaches the server ahead of any newer
/// observation, and storage renews between pages and during every ACK wait.
/// Every ACK must judge exactly its page's entries. Returns the ids the
/// server refused for stale storage (e.g. health that aged out while the
/// server was busy).
fn send_census_judged(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    journal: &std::sync::Arc<HostJournal>,
    runtime: &std::sync::Arc<dyn sandbox_runtime::SandboxRuntime>,
    states: Vec<sandbox_protocol::InventoryEntry>,
    key_control: KeyControl<'_>,
    wire: sandbox_protocol::WireCodes,
    deferred: &mut DeferredPushes,
) -> Result<std::collections::BTreeSet<String>> {
    let mut stale = std::collections::BTreeSet::new();
    let mut pages: Vec<Vec<sandbox_protocol::InventoryEntry>> = states
        .chunks(sandbox_protocol::INVENTORY_PAGE_MAX_ENTRIES)
        .map(<[_]>::to_vec)
        .collect();
    if pages.is_empty() {
        pages.push(Vec::new());
    }
    let last = pages.len() - 1;
    for (index, entries) in pages.into_iter().enumerate() {
        let page = index as u64;
        let sequence = deferred.reports().map_or(0, |reports| {
            reports.hold_storage(true);
            reports.storage_sequence()
        });
        let health = deferred.published_health();
        let mut entries = {
            let (journal, runtime) = (journal.clone(), runtime.clone());
            while_reading(
                socket,
                "inventory census roots",
                key_control,
                deferred,
                move |fence| {
                    let runtime = runtime.with_cancellation(fence);
                    let mut entries = entries;
                    for entry in &mut entries {
                        observe_entry_root(&journal, runtime.as_ref(), entry);
                    }
                    entries
                },
            )?
        };
        for root in entries.iter_mut().filter_map(|entry| entry.root.as_mut()) {
            root.observation_sequence = sequence;
        }
        socket.send(tungstenite::Message::Text(
            super::spell(
                wire,
                &DaemonControlMessage::SandboxInventory {
                    page,
                    complete: index == last,
                    entries: entries.clone(),
                },
                None,
            )?
            .into(),
        ))?;
        if let Some(reports) = deferred.reports() {
            reports.hold_storage(false);
        }
        let mut judged = Vec::new();
        await_server(
            socket,
            "inventory",
            Some(key_control),
            deferred,
            |message| match message {
                sandbox_protocol::ServerControlMessage::InventoryAck {
                    page: acknowledged,
                    entry_results,
                } if acknowledged == page => {
                    judged = entry_results
                        .filter(|results| sandbox_protocol::census_results_match(&entries, results))
                        .context("inventory acknowledgement does not judge its page")?;
                    Ok(true)
                }
                sandbox_protocol::ServerControlMessage::HeartbeatPong { .. } => Ok(false),
                _ => bail!("unexpected inventory response"),
            },
        )?;
        stale.extend(
            judged
                .iter()
                .filter(|r| r.outcome == sandbox_protocol::CensusEntryOutcome::StaleStorage)
                .map(|r| r.sandbox_id.clone()),
        );
        let bindings = pool_bindings(journal, &entries);
        deferred
            .evidence
            .record_census(&entries, &judged, &bindings, sequence, &health);
    }
    Ok(stale)
}

/// What the server sent instead of the awaited answer, for the session-drop
/// log, read from the raw frame. A `protocol.error` is the server's refusal
/// and carries its message (a fixed server string, never a secret); any other
/// frame is named by its type only, never its body.
pub(super) fn server_refusal(text: &str) -> String {
    let frame = serde_json::from_str::<serde_json::Value>(text).ok();
    let field = |name: &str| {
        frame
            .as_ref()
            .and_then(|frame| frame.get(name)?.as_str().map(str::to_owned))
    };
    match field("type").as_deref() {
        Some("protocol.error") => format!(
            "relay server refused ({}): {}",
            field("failure").unwrap_or_default(),
            field("message").unwrap_or_default()
        ),
        Some(kind) => format!("relay server sent {kind}"),
        None => "relay server sent an unreadable frame".into(),
    }
}

/// A `protocol.error` frame is the server's verdict on the session (WP2):
/// carried work is revoked. Any other unexpected frame only fails the phase.
#[cfg(test)]
pub(super) fn verdict_for_test(text: &str, error: anyhow::Error) -> anyhow::Error {
    server_verdict(text, error)
}

fn server_verdict(text: &str, error: anyhow::Error) -> anyhow::Error {
    let refused = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .is_some_and(|frame| frame.get("type").and_then(|t| t.as_str()) == Some("protocol.error"));
    if refused {
        error.context(super::connect::ServerVerdict)
    } else {
        error
    }
}

fn await_server(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    what: &str,
    key_control: Option<KeyControl<'_>>,
    deferred: &mut DeferredPushes,
    mut on: impl FnMut(sandbox_protocol::ServerControlMessage) -> Result<bool>,
) -> Result<()> {
    // The session's server-silence deadline (30 s in production; a debug
    // build's `WSSP_TEST_RELAY_TIMING` silence floor shortens it).
    let deadline = std::time::Instant::now() + deferred.silence_deadline();
    let mut beat = std::time::Instant::now();
    loop {
        if std::time::Instant::now() > deadline {
            // A server this silent during reconciliation is a lost transport.
            return Err(anyhow::anyhow!("{what} acknowledgement timed out")
                .context(super::connect::TransportLost));
        }
        deferred.tick_reports(socket)?;
        if beat.elapsed() >= reconcile_heartbeat() {
            socket.send(tungstenite::Message::Text(
                super::plain_frame(&DaemonControlMessage::Heartbeat {
                    id: "reconcile-heartbeat".into(),
                    sent_at: None,
                    policy_reconciler: None,
                })?
                .into(),
            ))?;
            beat = std::time::Instant::now();
        }
        match socket.read() {
            Ok(tungstenite::Message::Text(text)) => {
                let message = if let Some(control) = key_control {
                    let Some(message) = control.parse(&text, socket)? else {
                        continue;
                    };
                    message
                } else {
                    sandbox_protocol::parse_server_control(&text)?
                };
                if deferred.defer(&message, &text)? {
                    continue;
                }
                let refused = server_refusal(&text);
                match on(message) {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    // Name what the server actually sent: a refusal carries
                    // its (static, secret-free) reason, anything else its type.
                    Err(error) => return Err(server_verdict(&text, error.context(refused))),
                }
            }
            Ok(tungstenite::Message::Ping(data)) => {
                socket.send(tungstenite::Message::Pong(data))?
            }
            // A close frame means the same thing here as in the dispatch loop:
            // 4003 is terminal, every other close reconnects.
            Ok(tungstenite::Message::Close(frame)) => {
                return Err(super::connect::close_during_read(
                    frame.as_ref().map(|frame| u16::from(frame.code)),
                    frame.as_ref().map(|frame| frame.reason.as_str()),
                ));
            }
            Ok(_) => bail!("reconciliation connection closed"),
            Err(tungstenite::Error::Io(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(err) => return Err(err.into()),
        }
    }
}

/// Journaled receipts keep the precise code; `wire` spells it for the peer.
pub(super) fn send_receipt(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: sandbox_protocol::WireCodes,
    receipt: super::journal::HostReceipt,
) -> Result<()> {
    if receipt.digest_pruned {
        socket.send(tungstenite::Message::Text(
            super::plain_frame(&DaemonControlMessage::OperationReceiptPruned {
                sandbox_owner_id: receipt.sandbox_owner_id,
                operation_id: receipt.operation_id,
                sandbox_id: receipt.sandbox_id,
                generation: receipt.generation,
                attempt: receipt.attempt,
                idempotency_key: receipt.idempotency_key,
                kind: receipt.kind,
            })?
            .into(),
        ))?;
        return Ok(());
    }
    let server_request_hash = receipt
        .server_request_hash()
        .ok_or_else(|| anyhow::anyhow!("receipt digest unavailable"))?
        .to_owned();
    let reason = receipt.error_reason();
    socket.send(tungstenite::Message::Text(
        super::spell(
            wire,
            &DaemonControlMessage::OperationReceipt {
                sandbox_owner_id: receipt.sandbox_owner_id,
                operation_id: receipt.operation_id,
                sandbox_id: receipt.sandbox_id,
                generation: receipt.generation,
                attempt: receipt.attempt,
                body_hash: server_request_hash,
                idempotency_key: receipt.idempotency_key,
                kind: receipt.kind,
                state: receipt.state,
                result: receipt.result,
                error: receipt.error_code.map(|code| ProtocolErrorDetail {
                    reason,
                    code,
                    message: receipt.error_message.unwrap_or_default(),
                    operation_id: None,
                    sandbox_id: None,
                }),
                // The journaled launch mode.
                launch_mode: receipt.launch_mode,
            },
            None,
        )?
        .into(),
    ))?;
    Ok(())
}

/// Inventory is evidence only for lifecycle operations. A VM's existence cannot
/// establish whether an arbitrary command or file mutation completed.
pub fn resolve_receipt(
    journal: &HostJournal,
    runtime: &dyn sandbox_runtime::SandboxRuntime,
    receipt: super::journal::HostReceipt,
) -> Result<super::journal::HostReceipt> {
    if receipt.digest_pruned {
        return Ok(receipt);
    }
    if receipt.phase == ReceiptPhase::Intent
        && matches!(
            receipt.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect"
        )
    {
        // Intent proves only THIS attempt unissued. The shared classifier
        // also needs first-attempt lineage and the kind-specific runtime proof.
        let first = journal.first_allocation_receipt(&receipt);
        // A journaled restore resolves with create
        // proofs (root absence), never the reconnect storage check.
        let kind = receipt
            .allocation_kind()
            .unwrap_or(sandbox_runtime::AllocationKind::Create);
        let state = super::supervisor::pinned_refusal_state(
            runtime,
            kind,
            first,
            &receipt.sandbox_id,
            receipt.allocation.as_ref(),
        );
        return journal.record_result(
            &receipt.operation_id,
            state,
            None,
            // Not issued, not cancelled: nobody asked for a cancel (B-2).
            Some(SandboxErrorCode::HostEffectNotIssued),
            Some("allocation interrupted before issue".into()),
        );
    }
    if receipt.kind == "sandbox.lease.renew" {
        return journal.record_reconciled_result(
            &receipt.operation_id,
            if receipt.lease.is_some() {
                OperationState::Succeeded
            } else {
                OperationState::Failed
            },
            receipt
                .lease
                .as_ref()
                .map(|r| serde_json::json!({ "lease": r.lease })),
            receipt
                .lease
                .is_none()
                .then_some(SandboxErrorCode::StateConflict.into()),
            receipt
                .lease
                .is_none()
                .then(|| "renewal interrupted before lease decision".into()),
        );
    }
    if matches!(
        receipt.kind.as_str(),
        "sandbox.create" | "sandbox.reconnect"
    ) && receipt.lease.is_none()
    {
        // VM existence alone cannot prove an effective lease.
        return journal.record_reconciled_result(
            &receipt.operation_id,
            OperationState::UnknownOutcome,
            None,
            Some(SandboxErrorCode::UnknownOutcome.into()),
            Some("missing durable lease decision".into()),
        );
    }
    // Readiness failure already owns durable cleanup even if a later probe is
    // healthy. Preserve that observed cause until the server can settle it.
    if receipt.phase == ReceiptPhase::Effect
        && matches!(
            receipt.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect"
        )
        && receipt.error_code == Some(SandboxErrorCode::GuestUnavailable.into())
    {
        return Ok(journal.lookup(&receipt.operation_id).unwrap_or(receipt));
    }
    // The worker persists Effect before any guest IO, so an Intent-only
    // upload was never issued: chunks were still arriving when the process
    // died. Destination bytes that already match are not this attempt's
    // evidence; settle as not issued instead of manufacturing a success.
    if receipt.phase == ReceiptPhase::Intent && receipt.kind == "file.put" {
        return journal.record_result(
            &receipt.operation_id,
            OperationState::Failed,
            None,
            // Not issued, not cancelled: nobody asked for a cancel (B-2).
            Some(SandboxErrorCode::HostEffectNotIssued),
            Some("upload interrupted before issue".into()),
        );
    }
    // C28: an interrupted upload is settled from guest evidence, keyed by the
    // attempt-derived staging identity. Positive only for the exact bytes.
    if receipt.kind == "file.put"
        && let Some(file) = &receipt.file_put
    {
        let outcome = match sandbox_runtime::resolve_managed_instance_name(
            &receipt.sandbox_id,
            file.incus_name.as_deref(),
        ) {
            Ok(instance_name) => {
                runtime.recover_file_put(&sandbox_runtime::RecoverFilePutRequest {
                    template_fingerprint: receipt.template_fingerprint.clone().unwrap_or_default(),
                    guest: sandbox_runtime::GuestIdentity {
                        guest_uid: file.guest_uid,
                        guest_gid: file.guest_gid,
                        guest_home: file.guest_home.clone(),
                        guest_shell: file.guest_shell.clone(),
                    },
                    sandbox_id: receipt.sandbox_id.clone(),
                    instance_name,
                    operation_id: receipt.operation_id.clone(),
                    generation: receipt.generation,
                    attempt: receipt.attempt,
                    path: file.path.clone(),
                    size: file.size,
                    sha256: file.sha256.clone(),
                })
            }
            Err(error) => Err(error.into()),
        };
        let finished = super::supervisor::finish_effect(
            &receipt.operation_id,
            &receipt.sandbox_id,
            receipt.generation,
            receipt.attempt,
            outcome.map(|proof| {
                proof.map(|response| {
                    (
                        Some(serde_json::json!({
                            "path": response.path,
                            "size": response.bytes_written,
                        })),
                        None,
                        None,
                    )
                })
            }),
        );
        return journal.record_reconciled_result(
            &receipt.operation_id,
            finished.state,
            finished.payload,
            finished.error.as_ref().map(|error| error.code.clone()),
            finished.error.map(|error| error.message),
        );
    }
    // A capture interrupted by a restart: its disposable VM and snapshot are
    // removed, but whether `incus publish` already produced an (unaliased)
    // image is not provable, so the outcome stays unknown. The server then
    // releases the capture hold and creates no revision.
    if receipt.kind == "sandbox.capture" && receipt.phase == ReceiptPhase::Effect {
        // P2-12: until the leftovers are proven gone the receipt stays
        // unresolved (the server keeps the capture's hold); the next
        // reconciliation retries the cleanup.
        if runtime
            .discard_capture(&receipt.sandbox_id, &receipt.operation_id)
            .is_err()
        {
            return Ok(journal.lookup(&receipt.operation_id).unwrap_or(receipt));
        }
        return journal.record_reconciled_result(
            &receipt.operation_id,
            OperationState::UnknownOutcome,
            None,
            Some(SandboxErrorCode::UnknownOutcome.into()),
            Some("capture interrupted by a daemon restart; capture VM and snapshot removed".into()),
        );
    }
    let outcome = sandbox_runtime::reconcile_effect(
        runtime,
        &receipt.kind,
        &receipt.sandbox_id,
        // A new root (a create, or a restore: offload §8.7) is bound to its
        // own create key; a cold or warm reconnect reuses its root's binding.
        (receipt.allocation_kind() == Some(sandbox_runtime::AllocationKind::Create))
            .then_some(receipt.idempotency_key.as_str()),
        receipt.template_fingerprint.as_deref(),
    );
    let finished = super::supervisor::finish_effect(
        &receipt.operation_id,
        &receipt.sandbox_id,
        receipt.generation,
        receipt.attempt,
        outcome.map(|proof| {
            proof.map(|state| {
                let mut result = serde_json::json!({ "state": state });
                if let Some(row) = &receipt.lease {
                    // M7: a READY-based create ACKs its settled deadline.
                    let lease =
                        if row.lease.from_ready_ms.is_some() && receipt.kind == "sandbox.create" {
                            journal
                                .settle_ready(&receipt.sandbox_id, receipt.generation, &row.lease)
                                .unwrap_or_else(|_| row.lease.clone())
                        } else {
                            row.lease.clone()
                        };
                    result["lease"] = serde_json::json!(lease);
                }
                (Some(result), None, None)
            })
        }),
    );
    journal.record_reconciled_result(
        &receipt.operation_id,
        finished.state,
        finished.payload,
        finished.error.as_ref().map(|error| error.code.clone()),
        finished.error.map(|error| error.message),
    )
}

/// Resolves `receipt` on a process-scoped worker while this thread reads the
/// socket. `None` when it was deferred (WP2): it got no worker (its sandbox
/// or the global bound is busy: a later reconnect picks it up), or its query
/// outlived the wait (it keeps running; `reconcile.complete` names it and the
/// dispatch loop delivers it).
fn resolve_without_blocking_reader(
    resolutions: &super::resolutions::InFlightResolutions,
    journal: &std::sync::Arc<HostJournal>,
    runtime: &std::sync::Arc<dyn sandbox_runtime::SandboxRuntime>,
    receipt: super::journal::HostReceipt,
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    key_control: KeyControl<'_>,
    deferred: &mut DeferredPushes,
) -> Result<Option<super::journal::HostReceipt>> {
    let operation_id = receipt.operation_id.clone();
    if let Err(refused) = resolutions.start(journal, runtime, receipt) {
        tracing::info!(
            operation_id,
            ?refused,
            "receipt resolution deferred to a later reconnect"
        );
        return Ok(None);
    }
    let deadline = std::time::Instant::now() + resolutions.wait();
    let mut pump = Pump::new();
    loop {
        if let Some(finished) = resolutions.take(&operation_id) {
            return finished.map(Some);
        }
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                operation_id,
                "receipt query stalled; deferred while reconciliation continues"
            );
            return Ok(None);
        }
        pump_control(socket, "receipt query", key_control, deferred, &mut pump)?;
    }
}

/// Ruling (d): runs `work` (a runtime inventory, census or expiry pass that
/// can block on the host daemon for a long time) on a worker while this
/// thread, the socket's only owner, keeps reading control frames. So from
/// `hello.ok` to `reconcile.complete` the socket is always being read: either
/// by an acknowledgement wait (`await_server`) or here. An authenticated
/// `egress.blocklist` is applied the moment it arrives
/// (`DeferredPushes::defer`), never after the workload pass.
///
/// No deadline: the work keeps the bound it had when it ran on this thread
/// (host-call timeouts). Policy sync never waits for inventory across a
/// transport loss: a socket failure returns at once, without
/// joining the worker. The worker is fenced: `work` receives a permit that is
/// revoked on that return (scope its runtime with it, so held host calls are
/// cancelled), and its result goes to a channel only this call reads, so an
/// obsolete worker's result can never be applied to a later session.
pub(super) fn while_reading<T: Send + 'static>(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    what: &str,
    key_control: KeyControl<'_>,
    deferred: &mut DeferredPushes,
    work: impl FnOnce(std::sync::Arc<sandbox_runtime::RuntimePermit>) -> T + Send + 'static,
) -> Result<T> {
    while_pumping(what, work, |pump| {
        pump_control(socket, what, key_control, deferred, pump)
    })
}

/// Per-phase socket pump state: the reconciliation heartbeat and the idle
/// read time counted toward the server-silence deadline.
pub(super) struct Pump {
    beat: std::time::Instant,
    silent: std::time::Duration,
}

impl Pump {
    fn new() -> Self {
        Self {
            beat: std::time::Instant::now(),
            silent: std::time::Duration::ZERO,
        }
    }
}

/// [`while_reading`] with the socket read abstracted (tests drive it).
fn while_pumping<T: Send + 'static>(
    what: &str,
    work: impl FnOnce(std::sync::Arc<sandbox_runtime::RuntimePermit>) -> T + Send + 'static,
    mut pump: impl FnMut(&mut Pump) -> Result<()>,
) -> Result<T> {
    /// Revokes the worker's permit on every exit that did not take its
    /// result (a pump failure, a panic): the worker is obsolete.
    struct Fence(std::sync::Arc<sandbox_runtime::RuntimePermit>);
    impl Drop for Fence {
        fn drop(&mut self) {
            self.0.revoke();
        }
    }
    let fence = Fence(std::sync::Arc::new(
        sandbox_runtime::RuntimePermit::default(),
    ));
    let permit = fence.0.clone();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("wssp-reconcile-work".into())
        .spawn(move || {
            // The receiver is gone once the session that started this
            // worker ended: the result is dropped, never applied.
            let _ = tx.send(work(permit));
        })?;
    let mut state = Pump::new();
    loop {
        match rx.try_recv() {
            Ok(result) => return Ok(result),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                bail!("{what} worker panicked")
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        pump(&mut state)?;
    }
}

/// One bounded socket read for a phase that awaits no server answer: pushes
/// are handled as during acknowledgement waits (blocklists applied, terminal
/// frames held), pongs ignored, pings answered, and a heartbeat sent every
/// 5 s. Any other frame fails the phase, as an acknowledgement wait would.
/// WP2: idle read time counts toward the session's server-silence deadline
/// (a pong answers every heartbeat), so a blackholed server ends the phase
/// as a lost transport instead of holding it for the whole worker.
fn pump_control(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    what: &str,
    key_control: KeyControl<'_>,
    deferred: &mut DeferredPushes,
    pump: &mut Pump,
) -> Result<()> {
    deferred.tick_reports(socket)?;
    let beat = &mut pump.beat;
    if beat.elapsed() >= reconcile_heartbeat() {
        socket.send(tungstenite::Message::Text(
            super::plain_frame(&DaemonControlMessage::Heartbeat {
                id: "reconcile-query".into(),
                sent_at: None,
                policy_reconciler: None,
            })?
            .into(),
        ))?;
        *beat = std::time::Instant::now();
    }
    let read_started = std::time::Instant::now();
    let read = socket.read();
    if !matches!(&read, Err(tungstenite::Error::Io(err)) if matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )) {
        pump.silent = std::time::Duration::ZERO;
    }
    match read {
        Ok(tungstenite::Message::Ping(data)) => socket.send(tungstenite::Message::Pong(data))?,
        Ok(tungstenite::Message::Text(text)) => {
            let Some(message) = key_control.parse(&text, socket)? else {
                return Ok(());
            };
            if deferred.defer(&message, &text)? {
                return Ok(());
            }
            if !matches!(
                message,
                sandbox_protocol::ServerControlMessage::HeartbeatPong { .. }
            ) {
                let refused = server_refusal(&text);
                return Err(server_verdict(
                    &text,
                    anyhow::anyhow!("unexpected frame during {what}").context(refused),
                ));
            }
        }
        Err(tungstenite::Error::Io(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
            ) =>
        {
            pump.silent += read_started.elapsed();
            if pump.silent >= deferred.silence_deadline() {
                return Err(anyhow::anyhow!(
                    "relay server silent for {}s during {what}",
                    pump.silent.as_secs()
                )
                .context(super::connect::TransportLost));
            }
        }
        Err(err) => return Err(err.into()),
        // Same close classification as the dispatch loop (see await_server).
        Ok(tungstenite::Message::Close(frame)) => {
            return Err(super::connect::close_during_read(
                frame.as_ref().map(|frame| u16::from(frame.code)),
                frame.as_ref().map(|frame| frame.reason.as_str()),
            ));
        }
        Ok(_) => bail!("{what} connection closed"),
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::journal::{Decision, intent_from_dispatch};
    use super::*;
    use sandbox_protocol::OperationDispatch;
    use std::net::{TcpListener, TcpStream};

    /// Injects only the final absence proof; all other observations use the
    /// real fake runtime and its pinned storage validation.
    struct RootProofRuntime {
        inner: sandbox_runtime::FakeRuntime,
        failures: std::sync::Mutex<std::collections::VecDeque<sandbox_runtime::RuntimeError>>,
    }
    impl sandbox_runtime::SandboxRuntime for RootProofRuntime {
        fn with_cancellation(
            &self,
            permit: Arc<sandbox_runtime::RuntimePermit>,
        ) -> Box<dyn sandbox_runtime::SandboxRuntime> {
            self.inner.with_cancellation(permit)
        }
        fn query_sandbox(
            &self,
            id: &str,
            key: Option<&str>,
            fingerprint: Option<&str>,
        ) -> Result<Option<sandbox_protocol::SandboxLifecycleState>, sandbox_runtime::RuntimeError>
        {
            self.inner.query_sandbox(id, key, fingerprint)
        }
        fn observe_storage_pool(
            &self,
            pool: &sandbox_runtime::StoragePoolIdentity,
        ) -> Result<sandbox_runtime::StoragePoolObservation, sandbox_runtime::RuntimeError>
        {
            self.inner.observe_storage_pool(pool)
        }
        fn storage_root_census(
            &self,
            pool: &sandbox_runtime::StoragePoolIdentity,
        ) -> Result<sandbox_runtime::StorageRootCensus, sandbox_runtime::RuntimeError> {
            self.inner.storage_root_census(pool)
        }
        fn prove_root_absent(
            &self,
            root: &sandbox_runtime::RootDisk,
            name: &str,
        ) -> Result<sandbox_runtime::RootAbsenceProof, sandbox_runtime::RuntimeError> {
            if let Some(error) = self.failures.lock().unwrap().pop_front() {
                return Err(error);
            }
            self.inner.prove_root_absent(root, name)
        }
        fn run_command(
            &self,
            request: &sandbox_runtime::RunCommandRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::RunCommandResponse> {
            self.inner.run_command(request)
        }
        fn read_file(
            &self,
            request: &sandbox_runtime::ReadFileRequest,
        ) -> Result<sandbox_runtime::ReadFileResponse, sandbox_runtime::RuntimeError> {
            self.inner.read_file(request)
        }
        fn write_file(
            &self,
            request: &sandbox_runtime::WriteFileRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::WriteFileResponse> {
            self.inner.write_file(request)
        }
        fn probe_sandbox(
            &self,
            request: &sandbox_runtime::ProbeSandboxRequest,
        ) -> Result<sandbox_runtime::ProbeSandboxResponse, sandbox_runtime::RuntimeError> {
            self.inner.probe_sandbox(request)
        }
        fn stop_sandbox(
            &self,
            request: &sandbox_runtime::StopSandboxRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::StopSandboxResponse> {
            self.inner.stop_sandbox(request)
        }
        fn list_dir(
            &self,
            request: &sandbox_runtime::ListDirRequest,
        ) -> Result<sandbox_runtime::ListDirResponse, sandbox_runtime::RuntimeError> {
            self.inner.list_dir(request)
        }
        fn stat_path(
            &self,
            request: &sandbox_runtime::StatPathRequest,
        ) -> Result<sandbox_runtime::EntryInfo, sandbox_runtime::RuntimeError> {
            self.inner.stat_path(request)
        }
        fn mkdir(
            &self,
            request: &sandbox_runtime::MkdirRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::MkdirResponse> {
            self.inner.mkdir(request)
        }
        fn remove_path(
            &self,
            request: &sandbox_runtime::RemovePathRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::RemovePathResponse> {
            self.inner.remove_path(request)
        }
        fn move_path(
            &self,
            request: &sandbox_runtime::MovePathRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::EntryInfo> {
            self.inner.move_path(request)
        }
        fn cancel_operation(&self, operation_id: &str) -> sandbox_runtime::EffectOutcome<()> {
            self.inner.cancel_operation(operation_id)
        }
        fn list_processes(
            &self,
            request: &sandbox_runtime::ListProcessesRequest,
        ) -> Result<sandbox_runtime::ListProcessesResponse, sandbox_runtime::RuntimeError> {
            self.inner.list_processes(request)
        }
        fn signal_process(
            &self,
            request: &sandbox_runtime::SignalProcessRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::SignalOutcome> {
            self.inner.signal_process(request)
        }
        fn write_stdin(
            &self,
            request: &sandbox_runtime::WriteStdinRequest,
        ) -> sandbox_runtime::EffectOutcome<()> {
            self.inner.write_stdin(request)
        }
        fn create_snapshot(
            &self,
            request: &sandbox_runtime::SnapshotRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::SnapshotResponse> {
            self.inner.create_snapshot(request)
        }
        fn restore_snapshot(
            &self,
            request: &sandbox_runtime::SnapshotRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::SnapshotResponse> {
            self.inner.restore_snapshot(request)
        }
        fn fork_sandbox(
            &self,
            request: &sandbox_runtime::ForkSandboxRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::ForkSandboxResponse> {
            self.inner.fork_sandbox(request)
        }
    }

    #[test]
    fn root_proof_timeout_and_cancellation_are_inconclusive_until_observed_again() {
        use crate::sandbox_relay::test_support::FixtureRuntime;
        use sandbox_runtime::*;
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://proof.test".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal =
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap();
        let allocation = crate::sandbox_relay::test_support::allocation();
        let dispatch: OperationDispatch = serde_json::from_value(serde_json::json!({
            "sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "generation":1, "attempt":1,
            "kind":"sandbox.create", "idempotencyKey":"create", "bodyHash":"a".repeat(64),
            "cpuCount":1, "memoryMiB":1024, "allocation":allocation,
            "lease":{"revision":1,"deadlineUnixMs":sandbox_protocol::HostLease::for_test().deadline_unix_ms,"action":"destroy","expiryPolicy":"retry-force-60s"}
        })).unwrap();
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
            .unwrap();
        journal.accept_fixture_lease(&dispatch).unwrap();
        assert!(journal.expire_lease_now_for_test("sbx", 1, 1));
        let row = journal.lease("sbx").unwrap();
        journal.finish_expiry(&row).unwrap();
        assert!(journal.lease("sbx").unwrap().root_deleted);
        let inner = FakeRuntime::new();
        inner.fixture_root().unwrap();
        let cancelled = RuntimePermit::default();
        cancelled.revoke();
        let runtime = RootProofRuntime {
            inner: inner.clone(),
            failures: std::sync::Mutex::new(std::collections::VecDeque::from([
                sandbox_runtime::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::Timeout,
                    "proof timed out",
                ),
                cancelled.admit().unwrap_err(),
                sandbox_runtime::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::VmSizeMismatch,
                    "pinned root differs",
                ),
            ])),
        };
        let mut entry = sandbox_protocol::InventoryEntry {
            sandbox_owner_id: Some("owner".into()),
            sandbox_id: "sbx".into(),
            state: sandbox_protocol::SandboxLifecycleState::Stopped,
            lease: None,
            root: None,
        };
        for _ in 0..2 {
            observe_entry_root(&journal, &runtime, &mut entry);
            assert!(entry.root.is_none(), "failed proof is not settled evidence");
            assert_eq!(
                entry.state,
                sandbox_protocol::SandboxLifecycleState::Stopped
            );
        }
        observe_entry_root(&journal, &runtime, &mut entry);
        assert_eq!(
            entry.root.as_ref().unwrap().state,
            sandbox_protocol::RootState::Absent
        );
        assert!(!entry.root.as_ref().unwrap().network_cleanup_complete);
        observe_entry_root(&journal, &runtime, &mut entry);
        assert!(entry.root.as_ref().unwrap().network_cleanup_complete);
        assert_eq!(entry.state, sandbox_protocol::SandboxLifecycleState::Absent);
        // A real volume must remain Present even with a journaled deletion.
        inner
            .create_fixture(&CreateSandboxRequest::for_test("sbx", "recreated"))
            .unwrap();
        observe_entry_root(&journal, &runtime, &mut entry);
        assert_eq!(
            entry.root.as_ref().unwrap().state,
            sandbox_protocol::RootState::Present
        );
        assert!(!entry.root.as_ref().unwrap().network_cleanup_complete);
    }

    #[test]
    fn reconciliation_heartbeats_on_the_session_cadence_inside_the_silence_deadline() {
        // No knob installed: production cadence and deadline (5 s, 30 s).
        assert_eq!(reconcile_heartbeat(), std::time::Duration::from_secs(5));
        let deadline = super::super::connect::server_silence_deadline(reconcile_heartbeat());
        assert_eq!(deadline, std::time::Duration::from_secs(30));
        assert!(reconcile_heartbeat().saturating_mul(6) <= deadline);
    }
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn interrupted_create_intent_requires_first_claim_and_absence() {
        use sandbox_runtime::{CreateSandboxRequest, FakeRuntime};
        for attempt in [1, 2] {
            for leased in [false, true] {
                for observation in ["absent", "present", "error"] {
                    let dir = tempfile::tempdir().unwrap();
                    let binding = TransportBindingV11 {
                        server: "wss://create.test".into(),
                        host_owner_id: "owner".into(),
                        host_id: "host".into(),
                    };
                    let create = CreateSandboxRequest::for_test("sbx", "create");
                    let d: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
                        "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
                        "cpuCount":1, "memoryMiB":1024, "generation":1, "attempt":attempt,
                        "idempotencyKey":"create", "bodyHash":"a".repeat(64),
                        "lease":create.lease, "templateDigest":create.template_digest,
                        "incusFingerprint":create.incus_fingerprint, "architecture":"x86_64"
                    }))
                    .unwrap();
                    let mut fake = FakeRuntime::new();
                    fake.fixture_root().unwrap();
                    if observation == "present" {
                        fake.create_fixture(&create).unwrap();
                    }
                    if observation == "error" {
                        fake = fake.with_inventory_hook(|_| {
                            Err(sandbox_runtime::RuntimeError::new(
                                SandboxErrorCode::Internal,
                                "lookup unavailable",
                            ))
                        });
                    }
                    {
                        let journal = crate::sandbox_relay::test_support::open_ready_journal(
                            dir.path(),
                            &binding,
                        )
                        .unwrap();
                        journal
                            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                            .unwrap();
                        if leased {
                            journal.accept_fixture_lease(&d).unwrap();
                        }
                    }
                    let journal = crate::sandbox_relay::test_support::open_ready_journal(
                        dir.path(),
                        &binding,
                    )
                    .unwrap();
                    let receipt =
                        resolve_receipt(&journal, &fake, journal.lookup("create").unwrap())
                            .unwrap();
                    assert_eq!(
                        receipt.state,
                        if attempt == 1 && !leased && observation == "absent" {
                            OperationState::Failed
                        } else {
                            OperationState::UnknownOutcome
                        },
                        "attempt={attempt}, leased={leased}, {observation}"
                    );
                    assert_eq!(
                        receipt.error_code,
                        Some(SandboxErrorCode::HostEffectNotIssued.into())
                    );
                }
            }
        }
    }

    /// An interrupted restore reconnect resolves with
    /// CREATE proofs. Root absent on a first attempt: never issued. A stopped
    /// partial instance (which a cold reconnect would release on) stays
    /// UNKNOWN; so does a retry.
    #[test]
    fn interrupted_restore_intent_resolves_with_create_proofs() {
        use sandbox_runtime::{
            CreateSandboxRequest, FakeRuntime, SandboxRuntime, StopSandboxRequest,
        };
        const DISK: &str =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        for attempt in [1, 2] {
            for observation in ["absent", "partial-stopped"] {
                let dir = tempfile::tempdir().unwrap();
                let binding = TransportBindingV11 {
                    server: "wss://restore.test".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let create = CreateSandboxRequest::for_test("sbx", "create");
                let fake = FakeRuntime::new();
                fake.fixture_root().unwrap();
                if observation == "partial-stopped" {
                    fake.create_fixture(&create).unwrap();
                    fake.stop_sandbox(&StopSandboxRequest {
                        template_fingerprint: create.template_digest.clone(),
                        sandbox_id: "sbx".into(),
                        instance_name: "wssp-sbx-sbx".into(),
                        operation_id: "stop".into(),
                        idempotency_key: "stop".into(),
                    })
                    .unwrap();
                }
                let d: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
                    "operationId":"restore", "sandboxId":"sbx", "kind":"sandbox.reconnect", "allocation": crate::sandbox_relay::test_support::allocation(),
                    "cpuCount":1, "memoryMiB":1024, "generation":3, "attempt":attempt,
                    "idempotencyKey":"restore", "bodyHash":"a".repeat(64),
                    "lease":create.lease, "templateDigest":create.template_digest,
                    "incusFingerprint":create.incus_fingerprint, "architecture":"x86_64",
                    "image": {"fingerprint": DISK, "sizeBytes": 4096, "format": "unified", "source": "fetch"},
                    "restore": {"offloadId": "off-1", "seq": 1, "fingerprint": DISK},
                    "launchMode": "new_root"
                }))
                .unwrap();
                {
                    let journal = crate::sandbox_relay::test_support::open_ready_journal(
                        dir.path(),
                        &binding,
                    )
                    .unwrap();
                    journal
                        .record_intent(&intent_from_dispatch(&journal, &binding, &d))
                        .unwrap();
                }
                let journal =
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap();
                let receipt = journal.lookup("restore").unwrap();
                assert_eq!(
                    receipt.launch_mode,
                    Some(sandbox_protocol::LaunchMode::NewRoot)
                );
                let receipt = resolve_receipt(&journal, &fake, receipt).unwrap();
                assert_eq!(
                    receipt.state,
                    if attempt == 1 && observation == "absent" {
                        OperationState::Failed
                    } else {
                        OperationState::UnknownOutcome
                    },
                    "attempt={attempt}, {observation}"
                );
                assert_eq!(
                    receipt.error_code,
                    Some(SandboxErrorCode::HostEffectNotIssued.into())
                );
                assert_eq!(
                    receipt.launch_mode,
                    Some(sandbox_protocol::LaunchMode::NewRoot)
                );
            }
        }
    }

    #[test]
    fn interrupted_reconnect_intent_requires_first_claim_and_not_running() {
        use sandbox_runtime::{
            CreateSandboxRequest, FakeRuntime, SandboxRuntime, StopSandboxRequest,
        };
        for history in ["first", "retry", "accepted-lease", "other-receipt"] {
            for observation in ["absent", "stopped", "running", "error"] {
                let dir = tempfile::tempdir().unwrap();
                let binding = TransportBindingV11 {
                    server: "wss://reconnect.test".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let create = CreateSandboxRequest::for_test("sbx", "create");
                let mut fake = FakeRuntime::new();
                fake.fixture_root().unwrap();
                if matches!(observation, "stopped" | "running") {
                    fake.create_fixture(&create).unwrap();
                    if observation == "stopped" {
                        fake.stop_sandbox(&StopSandboxRequest {
                            template_fingerprint: CreateSandboxRequest::for_test("sbx", "seed")
                                .template_digest
                                .clone(),
                            sandbox_id: "sbx".into(),
                            instance_name: "wssp-sbx-sbx".into(),
                            operation_id: "stop".into(),
                            idempotency_key: "stop".into(),
                        })
                        .unwrap();
                    }
                }
                if observation == "error" {
                    fake = fake.with_inventory_hook(|stage| {
                        assert_eq!(stage, "running");
                        Err(sandbox_runtime::RuntimeError::new(
                            SandboxErrorCode::Internal,
                            "lookup unavailable",
                        ))
                    });
                }
                let mut d: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
                    "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
                    "cpuCount":1, "memoryMiB":1024, "generation":1, "attempt":1,
                    "idempotencyKey":"create", "bodyHash":"a".repeat(64),
                    "lease":create.lease, "templateDigest":create.template_digest,
                    "incusFingerprint":create.incus_fingerprint, "architecture":"x86_64"
                }))
                .unwrap();
                {
                    let journal = crate::sandbox_relay::test_support::open_ready_journal(
                        dir.path(),
                        &binding,
                    )
                    .unwrap();
                    journal
                        .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                        .unwrap();
                    journal.accept_fixture_lease(&d).unwrap();
                    d.kind = "sandbox.reconnect".into();
                    d.operation_id = "reconnect".into();
                    d.idempotency_key = "reconnect".into();
                    d.generation = 3;
                    d.lease.as_mut().unwrap().revision = 3;
                    d.attempt = if history == "retry" { 2 } else { 1 };
                    journal
                        .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                        .unwrap();
                    if history == "accepted-lease" {
                        journal.accept_fixture_lease(&d).unwrap();
                    }
                    if history == "other-receipt" {
                        let mut other = d.clone();
                        other.operation_id = "other".into();
                        other.idempotency_key = "other".into();
                        journal
                            .record_fixture_intent(&intent_from_dispatch(
                                &journal, &binding, &other,
                            ))
                            .unwrap();
                        journal.record_effect("other").unwrap();
                    }
                    assert_eq!(journal.first_allocation_attempt(&d), history == "first");
                }
                let journal =
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap();
                assert_eq!(journal.first_allocation_attempt(&d), history == "first");
                let receipt =
                    resolve_receipt(&journal, &fake, journal.lookup("reconnect").unwrap()).unwrap();
                assert_eq!(
                    receipt.state,
                    if history == "first" && matches!(observation, "absent" | "stopped") {
                        OperationState::Failed
                    } else {
                        OperationState::UnknownOutcome
                    },
                    "{history}, {observation}"
                );
                assert_eq!(
                    receipt.error_code,
                    Some(SandboxErrorCode::HostEffectNotIssued.into())
                );
            }
        }
    }

    /// A close frame that arrives while awaiting a reconciliation
    /// acknowledgement is classified exactly like one in the dispatch loop:
    /// 4003 terminates with CredentialInactive; 1000/None and 1001 are
    /// retryable transport losses.
    #[test]
    fn close_during_receipt_acknowledgement_keeps_close_classification() {
        use tungstenite::protocol::frame::coding::CloseCode;
        for variant in ["credential", "clean", "clean-no-code", "going-away"] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let dispatch: OperationDispatch =
                serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
                    "operationId":"op", "sandboxId":"sbx", "kind":"command.run", "resultVersion":1, "processId":"proc-op",
                    "idempotencyKey":"key", "generation":1, "attempt":1,
                    "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }))
                .unwrap();
            {
                let journal =
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap();
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                    .unwrap();
                journal.record_effect("op").unwrap();
                journal
                    .record_result(
                        "op",
                        OperationState::Failed,
                        None,
                        Some(SandboxErrorCode::GuestOperationFailed),
                        Some("recorded".into()),
                    )
                    .unwrap();
            }
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap(),
            );
            let runtime: Arc<dyn sandbox_runtime::SandboxRuntime> = Arc::new({
                let fake = sandbox_runtime::FakeRuntime::new();
                fake.fixture_root().unwrap();
                fake
            });
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            tcp.set_read_timeout(Some(Duration::from_millis(10)))
                .unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut socket = tungstenite::WebSocket::from_raw_socket(
                tungstenite::stream::MaybeTlsStream::Plain(tcp),
                tungstenite::protocol::Role::Client,
                None,
            );
            let server = std::thread::spawn(move || {
                let mut wire = tungstenite::WebSocket::from_raw_socket(
                    peer,
                    tungstenite::protocol::Role::Server,
                    None,
                );
                wire.read().expect("receipt frame");
                let frame = match variant {
                    "credential" => Some(tungstenite::protocol::CloseFrame {
                        code: CloseCode::Library(4003),
                        reason: "credential_inactive".into(),
                    }),
                    "clean" => Some(tungstenite::protocol::CloseFrame {
                        code: CloseCode::Normal,
                        reason: "bye".into(),
                    }),
                    "clean-no-code" => None,
                    _ => Some(tungstenite::protocol::CloseFrame {
                        code: CloseCode::Away,
                        reason: "server_shutdown".into(),
                    }),
                };
                wire.close(frame).expect("close");
            });
            let expiry = super::super::expiry::ExpiryService::start(
                runtime.clone(),
                journal.clone(),
                super::super::authority::HostAuthority::with_journal(journal.clone()),
            );
            let error = reconcile_after_hello(
                &journal,
                &binding,
                &runtime,
                &mut socket,
                sandbox_protocol::WireCodes::CURRENT,
                &expiry,
                None,
                None,
                &mut DeferredPushes::default(),
            )
            .expect_err("close interrupts reconciliation");
            drop(expiry);
            server.join().unwrap();
            match variant {
                "credential" => {
                    assert_eq!(
                        crate::exit::code_for(&error),
                        crate::exit::ExitCode::CredentialInactive,
                        "4003 stays terminal during reconciliation"
                    );
                    assert!(
                        error
                            .downcast_ref::<super::super::connect::RetryableSession>()
                            .is_none(),
                        "a terminal close is not retried"
                    );
                }
                "clean" | "clean-no-code" => {
                    // A server close is never a reason to exit (P0-1).
                    assert!(
                        super::super::connect::transport_lost(&error),
                        "a 1000/None close during reconciliation is a transport loss"
                    );
                    assert!(
                        error
                            .downcast_ref::<super::super::connect::RetryableSession>()
                            .is_some(),
                        "a 1000/None close is retried"
                    );
                }
                _ => {
                    assert!(
                        error
                            .downcast_ref::<super::super::connect::RetryableSession>()
                            .is_some(),
                        "1001 going away stays retryable"
                    );
                    assert_ne!(
                        crate::exit::code_for(&error),
                        crate::exit::ExitCode::CredentialInactive
                    );
                }
            }
        }
    }

    /// The receipt-resolution reader (`resolve_without_blocking_reader`)
    /// classifies close frames the same way; the gate holds the resolution
    /// query so the close deterministically arrives first.
    #[test]
    fn close_during_receipt_resolution_keeps_close_classification() {
        use super::super::connect::RetryableSession;
        use sandbox_runtime::{
            CreateSandboxRequest, CreateSandboxResponse, EntryInfo, FakeRuntime,
            ForkSandboxRequest, ForkSandboxResponse, KillSandboxRequest, KillSandboxResponse,
            ListDirRequest, ListDirResponse, ListProcessesRequest, ListProcessesResponse,
            MkdirRequest, MkdirResponse, MovePathRequest, ProbeSandboxRequest,
            ProbeSandboxResponse, ReadFileRequest, ReadFileResponse, ReconnectSandboxRequest,
            ReconnectSandboxResponse, RemovePathRequest, RemovePathResponse, RunCommandRequest,
            RunCommandResponse, RuntimeError, SandboxRuntime, SignalProcessRequest,
            SnapshotRequest, SnapshotResponse, StatPathRequest, StopSandboxRequest,
            StopSandboxResponse, WriteFileRequest, WriteFileResponse, WriteStdinRequest,
        };
        use std::sync::Barrier;
        use tungstenite::protocol::frame::coding::CloseCode;

        struct GatedRuntime {
            inner: FakeRuntime,
            gate: Arc<Barrier>,
        }
        impl SandboxRuntime for GatedRuntime {
            fn egress_guard_check(&self) -> Result<(), sandbox_runtime::RuntimeError> {
                self.inner.egress_guard_check()
            }
            fn observe_storage_pool(
                &self,
                pool: &sandbox_runtime::StoragePoolIdentity,
            ) -> Result<sandbox_runtime::StoragePoolObservation, RuntimeError> {
                self.inner.observe_storage_pool(pool)
            }
            fn storage_root_census(
                &self,
                pool: &sandbox_runtime::StoragePoolIdentity,
            ) -> Result<sandbox_runtime::StorageRootCensus, RuntimeError> {
                self.inner.storage_root_census(pool)
            }
            fn prove_root_absent(
                &self,
                root: &sandbox_runtime::RootDisk,
                name: &str,
            ) -> Result<sandbox_runtime::RootAbsenceProof, RuntimeError> {
                self.inner.prove_root_absent(root, name)
            }
            fn query_sandbox(
                &self,
                sandbox_id: &str,
                create_key: Option<&str>,
                template_fingerprint: Option<&str>,
            ) -> Result<Option<sandbox_protocol::SandboxLifecycleState>, RuntimeError> {
                self.gate.wait();
                self.inner
                    .query_sandbox(sandbox_id, create_key, template_fingerprint)
            }
            fn with_cancellation(
                &self,
                cancelled: Arc<sandbox_runtime::RuntimePermit>,
            ) -> Box<dyn SandboxRuntime> {
                let _ = cancelled;
                Box::new(GatedRuntime {
                    inner: self.inner.clone(),
                    gate: self.gate.clone(),
                })
            }
            fn create_sandbox_on_storage(
                &self,
                request: &CreateSandboxRequest,
                root: &sandbox_runtime::RootDisk,
            ) -> sandbox_runtime::EffectOutcome<CreateSandboxResponse> {
                self.inner.create_sandbox_on_storage(request, root)
            }
            fn kill_sandbox_on_storage(
                &self,
                request: &KillSandboxRequest,
                root: &sandbox_runtime::RootDisk,
            ) -> sandbox_runtime::EffectOutcome<KillSandboxResponse> {
                self.inner.kill_sandbox_on_storage(request, root)
            }
            fn run_command(
                &self,
                request: &RunCommandRequest,
            ) -> sandbox_runtime::EffectOutcome<RunCommandResponse> {
                self.inner.run_command(request)
            }
            fn read_file(
                &self,
                request: &ReadFileRequest,
            ) -> Result<ReadFileResponse, RuntimeError> {
                self.inner.read_file(request)
            }
            fn write_file(
                &self,
                request: &WriteFileRequest,
            ) -> sandbox_runtime::EffectOutcome<WriteFileResponse> {
                self.inner.write_file(request)
            }
            fn probe_sandbox(
                &self,
                request: &ProbeSandboxRequest,
            ) -> Result<ProbeSandboxResponse, RuntimeError> {
                self.inner.probe_sandbox(request)
            }
            fn reconnect_sandbox_on_storage(
                &self,
                request: &ReconnectSandboxRequest,
                root: &sandbox_runtime::RootDisk,
            ) -> sandbox_runtime::EffectOutcome<ReconnectSandboxResponse> {
                self.inner.reconnect_sandbox_on_storage(request, root)
            }
            fn stop_sandbox(
                &self,
                request: &StopSandboxRequest,
            ) -> sandbox_runtime::EffectOutcome<StopSandboxResponse> {
                self.inner.stop_sandbox(request)
            }
            fn list_dir(&self, request: &ListDirRequest) -> Result<ListDirResponse, RuntimeError> {
                self.inner.list_dir(request)
            }
            fn stat_path(&self, request: &StatPathRequest) -> Result<EntryInfo, RuntimeError> {
                self.inner.stat_path(request)
            }
            fn mkdir(
                &self,
                request: &MkdirRequest,
            ) -> sandbox_runtime::EffectOutcome<MkdirResponse> {
                self.inner.mkdir(request)
            }
            fn remove_path(
                &self,
                request: &RemovePathRequest,
            ) -> sandbox_runtime::EffectOutcome<RemovePathResponse> {
                self.inner.remove_path(request)
            }
            fn move_path(
                &self,
                request: &MovePathRequest,
            ) -> sandbox_runtime::EffectOutcome<EntryInfo> {
                self.inner.move_path(request)
            }
            fn cancel_operation(&self, operation_id: &str) -> sandbox_runtime::EffectOutcome<()> {
                self.inner.cancel_operation(operation_id)
            }
            fn list_processes(
                &self,
                request: &ListProcessesRequest,
            ) -> Result<ListProcessesResponse, RuntimeError> {
                self.inner.list_processes(request)
            }
            fn signal_process(
                &self,
                request: &SignalProcessRequest,
            ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::SignalOutcome> {
                self.inner.signal_process(request)
            }
            fn write_stdin(
                &self,
                request: &WriteStdinRequest,
            ) -> sandbox_runtime::EffectOutcome<()> {
                self.inner.write_stdin(request)
            }
            fn create_snapshot(
                &self,
                request: &SnapshotRequest,
            ) -> sandbox_runtime::EffectOutcome<SnapshotResponse> {
                self.inner.create_snapshot(request)
            }
            fn restore_snapshot(
                &self,
                request: &SnapshotRequest,
            ) -> sandbox_runtime::EffectOutcome<SnapshotResponse> {
                self.inner.restore_snapshot(request)
            }
            fn fork_sandbox(
                &self,
                request: &ForkSandboxRequest,
            ) -> sandbox_runtime::EffectOutcome<ForkSandboxResponse> {
                self.inner.fork_sandbox(request)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let dispatch: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
            "operationId":"op", "sandboxId":"sbx", "kind":"sandbox.reconnect", "allocation": crate::sandbox_relay::test_support::allocation(),
            "idempotencyKey":"key", "generation":1, "attempt":1,
            "incusFingerprint":CreateSandboxRequest::for_test("sbx", "key").template_digest,
            "lease": sandbox_protocol::HostLease::for_test(),
            "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }))
        .unwrap();
        {
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                .unwrap();
            journal.accept_fixture_lease(&dispatch).unwrap();
            journal.record_effect("op").unwrap();
        }
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap(),
        );
        let gate = Arc::new(Barrier::new(2));
        let runtime: Arc<dyn SandboxRuntime> = Arc::new(GatedRuntime {
            inner: {
                let fake = FakeRuntime::new();
                fake.fixture_root().unwrap();
                fake
            },
            gate: gate.clone(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        tcp.set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut socket = tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        );
        let server = std::thread::spawn(move || {
            let mut wire = tungstenite::WebSocket::from_raw_socket(
                peer,
                tungstenite::protocol::Role::Server,
                None,
            );
            // The resolution query is gated: this close deterministically
            // arrives while the reader waits on it.
            wire.close(Some(tungstenite::protocol::CloseFrame {
                code: CloseCode::Away,
                reason: "server_shutdown".into(),
            }))
            .expect("close");
        });
        let expiry = super::super::expiry::ExpiryService::start(
            runtime.clone(),
            journal.clone(),
            super::super::authority::HostAuthority::with_journal(journal.clone()),
        );
        let error = reconcile_after_hello(
            &journal,
            &binding,
            &runtime,
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &expiry,
            None,
            None,
            &mut DeferredPushes::default(),
        )
        .expect_err("close interrupts receipt resolution");
        gate.wait();
        drop(expiry);
        server.join().unwrap();
        assert!(
            error.downcast_ref::<RetryableSession>().is_some(),
            "1001 during receipt resolution stays retryable"
        );
        assert_ne!(
            crate::exit::code_for(&error),
            crate::exit::ExitCode::CredentialInactive
        );
    }

    #[test]
    fn c14_recorded_diagnostics_survive_restart_reconciliation_and_wire_publication() {
        for (kind, code) in [
            ("command.run", SandboxErrorCode::RequestTooLarge),
            ("file.put", SandboxErrorCode::GuestOperationFailed),
            ("sandbox.reconnect", SandboxErrorCode::IdempotencyConflict),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let dispatch: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
                "operationId":"diagnostic", "sandboxId":"sbx", "kind":kind,
                "idempotencyKey":"key", "generation":1, "attempt":1,
                "incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").template_digest,
                "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            })).unwrap();
            let message = format!("recorded {kind} diagnosis");
            {
                let journal =
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap();
                assert!(journal.matching(&binding).unwrap().is_empty());
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                    .unwrap();
                journal.record_effect("diagnostic").unwrap();
                journal
                    .record_result(
                        "diagnostic",
                        OperationState::UnknownOutcome,
                        None,
                        Some(code),
                        Some(message.clone()),
                    )
                    .unwrap();
            }
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap(),
            );
            let runtime: Arc<dyn sandbox_runtime::SandboxRuntime> = Arc::new({
                let fake = sandbox_runtime::FakeRuntime::new();
                fake.fixture_root().unwrap();
                fake
            });
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            tcp.set_read_timeout(Some(Duration::from_millis(10)))
                .unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut socket = tungstenite::WebSocket::from_raw_socket(
                tungstenite::stream::MaybeTlsStream::Plain(tcp),
                tungstenite::protocol::Role::Client,
                None,
            );
            let expected_message = message.clone();
            let server = std::thread::spawn(move || {
                let mut wire = tungstenite::WebSocket::from_raw_socket(
                    peer,
                    tungstenite::protocol::Role::Server,
                    None,
                );
                let frame = wire.read().unwrap();
                let report: serde_json::Value =
                    serde_json::from_str(frame.to_text().unwrap()).unwrap();
                assert_eq!(report["state"], "unknown_outcome");
                assert_eq!(report["error"]["code"], serde_json::to_value(code).unwrap());
                assert_eq!(report["error"]["message"], expected_message);
                wire.send(tungstenite::Message::Text(
                    serde_json::json!({"type":"receipt.ack","operationId":"diagnostic"})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                crate::sandbox_relay::test_support::ack_reconciliation(&mut wire);
            });
            let expiry = super::super::expiry::ExpiryService::start(
                runtime.clone(),
                journal.clone(),
                super::super::authority::HostAuthority::with_journal(journal.clone()),
            );
            reconcile_after_hello(
                &journal,
                &binding,
                &runtime,
                &mut socket,
                sandbox_protocol::WireCodes::CURRENT,
                &expiry,
                None,
                None,
                &mut DeferredPushes::default(),
            )
            .unwrap();
            drop(expiry);
            server.join().unwrap();
            // Process restart: the runtime and the journal (and its lock)
            // are discarded together.
            drop(runtime);
            drop(journal);
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let retained = journal.lookup("diagnostic").unwrap();
            assert_eq!(retained.phase, ReceiptPhase::Effect);
            assert_eq!(retained.error_code, Some(code.into()));
            assert_eq!(retained.error_message.as_deref(), Some(message.as_str()));
            // Positive evidence can supersede the diagnostic; an uncertain stale
            // writer can neither clear it nor overwrite a terminal completion.
            let resolved = journal
                .record_reconciled_result(
                    "diagnostic",
                    OperationState::Succeeded,
                    Some(serde_json::json!({"state":"ready"})),
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(resolved.error_code, None);
            let stale = journal
                .record_reconciled_result(
                    "diagnostic",
                    OperationState::UnknownOutcome,
                    None,
                    Some(SandboxErrorCode::UnknownOutcome.into()),
                    None,
                )
                .unwrap();
            assert_eq!(stale, resolved);
        }
    }

    #[test]
    fn download_reconnect_reclaims_only_two_sided_terminal_receipts() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        // This fixture is also asserted against the production server's commit,
        // lost-confirmation and reconnect path in session-manager.test.ts.
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/download_recovery.json"
        ))
        .unwrap();
        for local_terminal in [false, true] {
            for server_terminal in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let binding = TransportBindingV11 {
                    server: "wss://example".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let mut value = fixture["receipt"].clone();
                // Deserialize just the operation binding as a dispatch.
                for key in ["type", "state", "result", "error"] {
                    value.as_object_mut().unwrap().remove(key);
                }
                value["path"] = serde_json::json!("/download");
                let dispatch: OperationDispatch = serde_json::from_value(value).unwrap();
                {
                    let journal = crate::sandbox_relay::test_support::open_ready_journal(
                        dir.path(),
                        &binding,
                    )
                    .unwrap();
                    assert!(journal.matching(&binding).unwrap().is_empty());
                    assert!(matches!(
                        journal
                            .record_fixture_intent(&intent_from_dispatch(
                                &journal, &binding, &dispatch
                            ))
                            .unwrap(),
                        Decision::Fresh
                    ));
                    journal.record_effect("op-1").unwrap();
                    if local_terminal {
                        journal
                            .record_result(
                                "op-1",
                                OperationState::Succeeded,
                                Some(serde_json::json!({"path":"/download", "size":2})),
                                None,
                                None,
                            )
                            .unwrap();
                    }
                }
                // Process restart loses all transient bytes, not durable state.
                let journal = Arc::new(
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap(),
                );
                let runtime: Arc<dyn sandbox_runtime::SandboxRuntime> = Arc::new({
                    let fake = sandbox_runtime::FakeRuntime::new();
                    fake.fixture_root().unwrap();
                    fake
                });
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                tcp.set_read_timeout(Some(Duration::from_millis(10)))
                    .unwrap();
                let (peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut socket = tungstenite::WebSocket::from_raw_socket(
                    tungstenite::stream::MaybeTlsStream::Plain(tcp),
                    tungstenite::protocol::Role::Client,
                    None,
                );
                let mut wire = tungstenite::WebSocket::from_raw_socket(
                    peer,
                    tungstenite::protocol::Role::Server,
                    None,
                );
                let fixture = fixture.clone();
                let server = std::thread::spawn(move || {
                    let frame = wire.read().unwrap();
                    let report: serde_json::Value =
                        serde_json::from_str(frame.to_text().unwrap()).unwrap();
                    assert_eq!(report["state"], "unknown_outcome");
                    if local_terminal {
                        assert_eq!(report, fixture["receipt"]);
                    }
                    if server_terminal {
                        wire.send(tungstenite::Message::Text(
                            fixture["confirmation"].to_string().into(),
                        ))
                        .unwrap();
                    }
                    wire.send(tungstenite::Message::Text(
                        serde_json::json!({"type":"receipt.ack","operationId":"op-1"})
                            .to_string()
                            .into(),
                    ))
                    .unwrap();
                    crate::sandbox_relay::test_support::ack_reconciliation(&mut wire);
                });
                let expiry = super::super::expiry::ExpiryService::start(
                    runtime.clone(),
                    journal.clone(),
                    super::super::authority::HostAuthority::with_journal(journal.clone()),
                );
                reconcile_after_hello(
                    &journal,
                    &binding,
                    &runtime,
                    &mut socket,
                    sandbox_protocol::WireCodes::CURRENT,
                    &expiry,
                    None,
                    None,
                    &mut DeferredPushes::default(),
                )
                .unwrap();
                drop(expiry);
                server.join().unwrap();
                let reclaimed = local_terminal && server_terminal;
                assert_eq!(journal.lookup("op-1").is_none(), reclaimed);
                // Process restart also discards the runtime, then the
                // journal and its lock.
                drop(runtime);
                drop(journal);
                let reopened =
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap();
                assert_eq!(
                    reopened.matching(&binding).unwrap().len(),
                    usize::from(!reclaimed)
                );
                if !local_terminal {
                    assert_eq!(reopened.lookup("op-1").unwrap().phase, ReceiptPhase::Effect);
                }
            }
        }
    }
    #[test]
    fn effect_receipt_reentry_requires_the_operations_expected_end_state() {
        use sandbox_protocol::OperationState;
        use sandbox_runtime::{
            CreateSandboxRequest, FakeRuntime, SandboxRuntime, StopSandboxRequest,
            UnsupportedRuntime,
        };
        for kind in [
            "sandbox.create",
            "sandbox.reconnect",
            "sandbox.stop",
            "sandbox.kill",
            "command.run",
        ] {
            for observed in [
                "absent",
                "ready",
                "stopped",
                "query_error",
                "wrong_template",
                "missing_template",
                "stopped_wrong_template",
                "stopped_missing_template",
            ] {
                let dir = tempfile::tempdir().unwrap();
                let binding = TransportBindingV11 {
                    server: "wss://example".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let fake = FakeRuntime::new();
                fake.fixture_root().unwrap();
                if matches!(
                    observed,
                    "ready"
                        | "stopped"
                        | "wrong_template"
                        | "missing_template"
                        | "stopped_wrong_template"
                        | "stopped_missing_template"
                ) {
                    fake.create_fixture(&CreateSandboxRequest::for_test("sbx", "key"))
                        .unwrap();
                }
                if observed.starts_with("stopped") {
                    fake.stop_sandbox(&StopSandboxRequest {
                        template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test(
                            "sbx", "key",
                        )
                        .template_digest,
                        sandbox_id: "sbx".into(),
                        instance_name: "wssp-sbx-sbx".into(),
                        operation_id: "stop".into(),
                        idempotency_key: "stop".into(),
                    })
                    .unwrap();
                }
                let mut dispatch: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner", "operationId":"op", "sandboxId":"sbx", "incusFingerprint":CreateSandboxRequest::for_test("sbx", "key").template_digest, "kind":kind, "lease": sandbox_protocol::HostLease::for_test(), "idempotencyKey":"key", "generation":1, "attempt":1, "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})).unwrap();
                if observed.ends_with("wrong_template") {
                    dispatch.incus_fingerprint = Some(format!("sha256:{}", "b".repeat(64)));
                } else if observed.ends_with("missing_template") {
                    dispatch.incus_fingerprint = None;
                }
                {
                    let journal = crate::sandbox_relay::test_support::open_ready_journal(
                        dir.path(),
                        &binding,
                    )
                    .unwrap();
                    journal
                        .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                        .unwrap();
                    if matches!(kind, "sandbox.create" | "sandbox.reconnect") {
                        journal.accept_fixture_lease(&dispatch).unwrap();
                    }
                    journal.record_effect("op").unwrap();
                }
                let journal =
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap();
                let unsupported = UnsupportedRuntime::new();
                let runtime: &dyn SandboxRuntime = if observed == "query_error" {
                    &unsupported
                } else {
                    &fake
                };
                let resolved =
                    resolve_receipt(&journal, runtime, journal.lookup("op").unwrap()).unwrap();
                let expected = matches!(
                    (kind, observed),
                    ("sandbox.create" | "sandbox.reconnect", "ready")
                        | ("sandbox.stop", "stopped" | "absent")
                        | ("sandbox.kill", "absent")
                );
                assert_eq!(
                    resolved.state,
                    if expected {
                        OperationState::Succeeded
                    } else {
                        OperationState::UnknownOutcome
                    },
                    "{kind}/{observed}"
                );
                assert_eq!(
                    resolved.phase,
                    if expected {
                        ReceiptPhase::Result
                    } else {
                        ReceiptPhase::Effect
                    }
                );
                if expected {
                    let state = match (kind, observed) {
                        ("sandbox.kill", "absent") => "deleted",
                        (_, state) => state,
                    };
                    let mut result = serde_json::json!({ "state": state });
                    if matches!(kind, "sandbox.create" | "sandbox.reconnect") {
                        result["lease"] = serde_json::json!(dispatch.lease);
                    }
                    assert_eq!(resolved.result, Some(result));
                }
                drop(journal);
                let reopened =
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap();
                let persisted = reopened.lookup("op").unwrap();
                assert_eq!(persisted.state, resolved.state);
                assert_eq!(persisted.result, resolved.result);
            }
        }
    }

    /// An observational warm reconnect that crashes after Effect recovers with
    /// the immutable queued lease in its ACK — never the renewed lease it
    /// observed — because the server fences the ACK on the queued tuple
    /// (`recordSandboxOperation`'s lease check). The recovered result must be
    /// exactly what a live completion would have sent.
    #[test]
    fn recovered_observational_reconnect_acks_the_queued_lease() {
        use sandbox_runtime::{CreateSandboxRequest, FakeRuntime};
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        fake.create_fixture(&CreateSandboxRequest::for_test("sbx", "key"))
            .unwrap();
        let dispatch = |id: &str, kind: &str, hash: char| -> OperationDispatch {
            serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner", "operationId":id, "sandboxId":"sbx", "kind":kind, "lease": sandbox_protocol::HostLease::for_test(), "idempotencyKey":id, "generation":1, "attempt":1, "bodyHash":hash.to_string().repeat(64)})).unwrap()
        };
        {
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let create = dispatch("create", "sandbox.create", 'a');
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &create))
                .unwrap();
            journal.accept_fixture_lease(&create).unwrap();
            journal
                .record_result(
                    "create",
                    OperationState::Succeeded,
                    Some(serde_json::json!({"state":"ready","lease":create.lease})),
                    None,
                    None,
                )
                .unwrap();
            // A renewal lands, then the queued revision-1 reconnect is
            // delivered. The renewal is the effective lease for runtime work.
            let mut renew = dispatch("renew", "sandbox.lease.renew", 'b');
            renew.lease.as_mut().unwrap().revision = 2;
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &renew))
                .unwrap();
            assert_eq!(journal.accept_fixture_lease(&renew).unwrap().revision, 2);
            let mut warm = dispatch("warm", "sandbox.reconnect", 'c');
            warm.incus_fingerprint =
                Some(CreateSandboxRequest::for_test("sbx", "key").template_digest);
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &warm))
                .unwrap();
            assert_eq!(
                journal.accept_fixture_lease(&warm).unwrap().revision,
                2,
                "observes the renewal as the effective lease"
            );
            journal.record_effect("warm").unwrap();
            // Crash after Effect, before Result.
        }
        let journal =
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap();
        let resolved = resolve_receipt(&journal, &fake, journal.lookup("warm").unwrap()).unwrap();
        assert_eq!(resolved.state, OperationState::Succeeded);
        assert_eq!(resolved.phase, ReceiptPhase::Result);
        assert_eq!(
            resolved.result.as_ref().unwrap()["lease"]["revision"],
            1,
            "the ACK echoes the immutable queued lease, not the observed one"
        );
    }

    /// A capture interrupted by a daemon restart (Effect, no Result): the
    /// recovery removes the capture VM and snapshot and settles UNKNOWN —
    /// never SUCCEEDED (no fingerprint) and never FAILED (a publish may have
    /// produced an image). An Intent-only capture issued nothing.
    #[test]
    fn interrupted_capture_discards_its_vm_and_stays_unknown() {
        use sandbox_protocol::OperationState;
        use sandbox_runtime::FakeRuntime;
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let fake = FakeRuntime::new();
        let dispatch: OperationDispatch = serde_json::from_value(serde_json::json!({
            "sandboxOwnerId":"owner", "operationId":"cap-op", "sandboxId":"sbx",
            "kind":"sandbox.capture", "idempotencyKey":"key", "generation":1, "attempt":1,
            "capture": {"scrubPaths": [], "stopped": false, "upload": false},
            "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}))
        .unwrap();
        {
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                .unwrap();
            journal.record_effect("cap-op").unwrap();
        }
        let journal =
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap();
        // Cleanup not yet verified: the receipt stays in Effect, unresolved.
        fake.set_discard_capture_fails(true);
        let pending = resolve_receipt(&journal, &fake, journal.lookup("cap-op").unwrap()).unwrap();
        assert_eq!(pending.phase, ReceiptPhase::Effect);
        assert_ne!(pending.state, OperationState::UnknownOutcome);
        fake.set_discard_capture_fails(false);
        let resolved = resolve_receipt(&journal, &fake, journal.lookup("cap-op").unwrap()).unwrap();
        assert_eq!(resolved.state, OperationState::UnknownOutcome);
        assert_eq!(
            resolved.error_code,
            Some(SandboxErrorCode::UnknownOutcome.into())
        );
        assert_eq!(
            fake.discarded_captures(),
            [
                ("sbx".to_owned(), "cap-op".to_owned()),
                ("sbx".to_owned(), "cap-op".to_owned())
            ]
        );
    }

    /// G2: after a host crash, an interrupted `file.put` is settled from guest
    /// evidence through the durable receipt manifest, and survives reopening.
    /// Only Effect-phase receipts consult the guest: an Intent-only receipt
    /// means the upload never finished and no write was issued, so matching
    /// destination bytes are not this attempt's evidence.
    #[test]
    fn interrupted_file_put_receipt_is_recovered_from_guest_evidence() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        use sandbox_protocol::OperationState;
        use sandbox_runtime::{CreateSandboxRequest, FakeRuntime, FileContent, SandboxRuntime};
        for (phase, holds_bytes) in [
            (ReceiptPhase::Effect, true),
            (ReceiptPhase::Effect, false),
            // Pre-existing matching content must not promote a never-issued
            // upload to SUCCEEDED.
            (ReceiptPhase::Intent, true),
            (ReceiptPhase::Intent, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let fake = FakeRuntime::new();
            fake.fixture_root().unwrap();
            fake.create_fixture(&CreateSandboxRequest::for_test("sbx", "key"))
                .unwrap();
            let bytes = b"\0recovered\xff";
            let content = FileContent::from_bytes(bytes).unwrap();
            if holds_bytes {
                fake.write_file(&sandbox_runtime::WriteFileRequest {
                    template_fingerprint: CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "sbx".into(),
                    instance_name: "wssp-sbx-sbx".into(),
                    operation_id: "op".into(),
                    generation: 1,
                    attempt: 1,
                    idempotency_key: "key".into(),
                    path: "/home/user/out.bin".into(),
                    bytes: content.clone(),
                    guest: Default::default(),
                })
                .unwrap();
            }
            let dispatch: OperationDispatch =
                serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
                "operationId":"op", "sandboxId":"sbx", "kind":"file.put", "idempotencyKey":"key",
                "generation":1, "attempt":1, "path":"/home/user/out.bin",
                "fileSize": bytes.len(), "fileSha256": content.digest(),
                "incusFingerprint": CreateSandboxRequest::for_test("sbx", "key").template_digest,
                "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}))
                .unwrap();
            {
                let journal =
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap();
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                    .unwrap();
                if phase == ReceiptPhase::Effect {
                    journal.record_effect("op").unwrap();
                }
            }
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let stored = journal.lookup("op").unwrap();
            assert_eq!(
                stored
                    .file_put
                    .as_ref()
                    .map(|file| (file.size, file.sha256.as_str())),
                Some((bytes.len() as u64, content.digest()))
            );
            let resolved = resolve_receipt(&journal, &fake, stored).unwrap();
            if phase == ReceiptPhase::Intent {
                assert_eq!(resolved.state, OperationState::Failed, "{phase:?}");
                assert_eq!(
                    resolved.error_code,
                    Some(SandboxErrorCode::HostEffectNotIssued.into()),
                    "{phase:?}"
                );
            } else if holds_bytes {
                assert_eq!(resolved.state, OperationState::Succeeded);
                assert_eq!(resolved.phase, ReceiptPhase::Result);
                assert_eq!(
                    resolved.result,
                    Some(serde_json::json!({"path": "/home/user/out.bin", "size": bytes.len()}))
                );
            } else {
                assert_eq!(resolved.state, OperationState::UnknownOutcome);
            }
            drop(journal);
            let reopened =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            assert_eq!(reopened.lookup("op").unwrap().state, resolved.state);
        }
    }

    /// The census is ascending, paginated, and terminated by exactly one
    /// `complete` page even when the host manages nothing. A durable lease
    /// whose instance is gone is reported as explicit absence.
    #[test]
    fn census_pages_every_managed_instance_and_lease_in_order() {
        use sandbox_runtime::{CreateSandboxRequest, FakeRuntime};
        for count in [0usize, 1, 64, 65, 130] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap(),
            );
            let fake = FakeRuntime::new();
            fake.fixture_root().unwrap();
            for index in 0..count {
                fake.create_fixture(&CreateSandboxRequest::for_test(
                    &format!("sbx-{index:03}"),
                    &format!("key-{index}"),
                ))
                .unwrap();
            }
            let dispatch: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner", "operationId":"op", "sandboxId":"zz-gone", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "lease": sandbox_protocol::HostLease::for_test(), "idempotencyKey":"key", "generation":1, "attempt":1, "bodyHash":"a".repeat(64)})).unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                .unwrap();
            journal.accept_fixture_lease(&dispatch).unwrap();
            let census = inventory_census(&journal, &fake, &Default::default()).unwrap();
            assert_eq!(census.len(), count + 1);
            assert!(census.windows(2).all(|w| w[0].sandbox_id < w[1].sandbox_id));
            let gone = census.last().unwrap();
            assert_eq!(gone.sandbox_id, "zz-gone");
            assert_eq!(gone.state, sandbox_protocol::SandboxLifecycleState::Absent);
            assert_eq!(gone.lease.as_ref().unwrap().generation, 1);

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            tcp.set_read_timeout(Some(Duration::from_millis(10)))
                .unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut socket = tungstenite::WebSocket::from_raw_socket(
                tungstenite::stream::MaybeTlsStream::Plain(tcp),
                tungstenite::protocol::Role::Client,
                None,
            );
            let server = std::thread::spawn(move || {
                let mut wire = tungstenite::WebSocket::from_raw_socket(
                    peer,
                    tungstenite::protocol::Role::Server,
                    None,
                );
                let mut pages = Vec::new();
                loop {
                    let frame = wire.read().unwrap();
                    match sandbox_protocol::parse_daemon_control(frame.to_text().unwrap()).unwrap()
                    {
                        DaemonControlMessage::SandboxInventory {
                            page,
                            complete,
                            entries,
                        } => {
                            pages.push((page, complete, entries.len()));
                            wire.send(tungstenite::Message::Text(
                                serde_json::json!({"type":"inventory.ack","page":page, "entryResults": entries.iter().map(|entry| serde_json::json!({"sandboxId":entry.sandbox_id,"outcome":"converged"})).collect::<Vec<_>>()})
                                    .to_string()
                                    .into(),
                            ))
                            .unwrap();
                            if complete {
                                return pages;
                            }
                        }
                        other => panic!("unexpected {other:?}"),
                    }
                }
            });
            let runtime: Arc<dyn sandbox_runtime::SandboxRuntime> = Arc::new(fake);
            send_census_judged(
                &mut socket,
                &journal,
                &runtime,
                census,
                KeyControl {
                    journal: &journal,
                    binding: &binding,
                    epoch: Some(1),
                    credentials: None,
                },
                sandbox_protocol::WireCodes::negotiated(
                    sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION,
                ),
                &mut DeferredPushes::default(),
            )
            .unwrap();
            let pages = server.join().unwrap();
            let expected = (count + 1).div_ceil(64);
            assert_eq!(pages.len(), expected);
            assert!(
                pages
                    .iter()
                    .enumerate()
                    .all(|(index, (page, complete, _))| {
                        *page == index as u64 && *complete == (index + 1 == expected)
                    })
            );
            assert_eq!(pages.iter().map(|p| p.2).sum::<usize>(), count + 1);
        }
    }

    /// The judged census (`censusEntryResults`): each ACK must judge exactly
    /// its page; entries refused for stale storage are returned (their
    /// expiry arms are not counted as reported), and an ACK that does not
    /// answer its page, or answers nothing, fails reconciliation.
    #[test]
    fn judged_census_returns_stale_entries_and_refuses_an_unanswered_page() {
        let entry = |id: &str| sandbox_protocol::InventoryEntry {
            sandbox_owner_id: Some("owner".into()),
            sandbox_id: id.into(),
            state: sandbox_protocol::SandboxLifecycleState::Stopped,
            lease: None,
            root: None,
        };
        let mixed = serde_json::json!({"type":"inventory.ack","page":0,"entryResults":[
            {"sandboxId":"sbx-a","outcome":"converged"},
            {"sandboxId":"sbx-b","outcome":"stale_storage"},
            {"sandboxId":"sbx-c","outcome":"not_converged"}]});
        let reordered = serde_json::json!({"type":"inventory.ack","page":0,"entryResults":[
            {"sandboxId":"sbx-b","outcome":"converged"},
            {"sandboxId":"sbx-a","outcome":"converged"},
            {"sandboxId":"sbx-c","outcome":"converged"}]});
        let unjudged = serde_json::json!({"type":"inventory.ack","page":0});
        for (ack, expected) in [
            (mixed, Some(vec!["sbx-b".to_string()])),
            (reordered, None),
            (unjudged, None),
            (
                serde_json::json!({"type":"inventory.ack","page":7,"entryResults":[]}),
                None,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap(),
            );
            let runtime: Arc<dyn sandbox_runtime::SandboxRuntime> =
                Arc::new(sandbox_runtime::FakeRuntime::new());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            tcp.set_read_timeout(Some(Duration::from_millis(10)))
                .unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut socket = tungstenite::WebSocket::from_raw_socket(
                tungstenite::stream::MaybeTlsStream::Plain(tcp),
                tungstenite::protocol::Role::Client,
                None,
            );
            let server = std::thread::spawn(move || {
                let mut wire = tungstenite::WebSocket::from_raw_socket(
                    peer,
                    tungstenite::protocol::Role::Server,
                    None,
                );
                loop {
                    let tungstenite::Message::Text(text) = wire.read().unwrap() else {
                        continue;
                    };
                    if let DaemonControlMessage::SandboxInventory { complete, .. } =
                        sandbox_protocol::parse_daemon_control(&text).unwrap()
                    {
                        assert!(complete);
                        break;
                    }
                }
                wire.send(tungstenite::Message::Text(ack.to_string().into()))
                    .unwrap();
                // Keep the transport open until the daemon decided.
                let _ = wire.read();
            });
            let key_control = KeyControl {
                journal: &journal,
                binding: &binding,
                epoch: None,
                credentials: None,
            };
            let result = send_census_judged(
                &mut socket,
                &journal,
                &runtime,
                vec![entry("sbx-a"), entry("sbx-b"), entry("sbx-c")],
                key_control,
                sandbox_protocol::WireCodes::CURRENT,
                &mut DeferredPushes::default(),
            );
            drop(socket);
            server.join().unwrap();
            match expected {
                Some(stale) => assert_eq!(result.unwrap().into_iter().collect::<Vec<_>>(), stale),
                None => assert!(result.is_err()),
            }
        }
    }

    /// A targeted observation reads the VM state, then the
    /// journal lease. A lease arm that changes in between (a reconnect's new
    /// generation) must never be attached to the older VM observation: the
    /// entry is withheld as raced, and the next observation offers it under
    /// the lease it was observed with. A renewal is not such
    /// a change (it moves no VM state), so renewals overlapping every read
    /// never keep the entry from being offered.
    #[test]
    fn a_lease_change_during_an_observation_withholds_the_mixed_entry() {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap(),
        );
        let dispatch =
            |id: &str, generation: u64, kind: &str, revision: u64| -> OperationDispatch {
                serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
                "operationId": id, "sandboxId": "sbx", "generation": generation, "attempt": 1,
                "kind": kind,
                "idempotencyKey": id, "bodyHash": "a".repeat(64),
                "lease": { "revision": revision,
                    "deadlineUnixMs": sandbox_protocol::HostLease::for_test().deadline_unix_ms,
                    "action": "stop", "expiryPolicy": "retry-force-60s" } }))
                .unwrap()
            };
        let create = dispatch("create", 1, "sandbox.create", 1);
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &create))
            .unwrap();
        journal.accept_fixture_lease(&create).unwrap();
        // What the next VM read does to the lease: renew it, or install a
        // reconnect's new generation.
        #[derive(Clone, Copy, PartialEq)]
        enum During {
            Nothing,
            Renew,
            Reconnect,
        }
        let during = Arc::new(std::sync::Mutex::new(During::Nothing));
        let revision = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let runtime = {
            let (journal, binding, during, revision) = (
                journal.clone(),
                binding.clone(),
                during.clone(),
                revision.clone(),
            );
            sandbox_runtime::FakeRuntime::new().with_query_hook(move |id| {
                if id != "sbx" {
                    return Ok(());
                }
                let now = *during.lock().unwrap();
                let next = match now {
                    During::Nothing => return Ok(()),
                    During::Renew => {
                        let r = revision.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        dispatch(&format!("renew-{r}"), 1, "sandbox.lease.renew", r)
                    }
                    During::Reconnect => {
                        *during.lock().unwrap() = During::Nothing;
                        let r = revision.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        dispatch("reconnect", 2, "sandbox.reconnect", r)
                    }
                };
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &next))
                    .unwrap();
                journal.accept_fixture_lease(&next).unwrap();
                Ok(())
            })
        };
        let failures = super::super::expiry::ExpiryFailures::default();
        let completions = super::super::expiry::ExpiryCompletions::default();
        let reoffer = std::collections::BTreeSet::from(["sbx".to_owned()]);
        let observe = || {
            expiry_status_offer(
                &journal,
                &runtime,
                &failures,
                &completions,
                &ExpiryReported::new(),
                reoffer.clone(),
                &Default::default(),
            )
            .unwrap()
        };
        // Continuous renewals: every read overlaps one, and every
        // observation is still offered, with the newest revision.
        *during.lock().unwrap() = During::Renew;
        for _ in 0..3 {
            let offer = observe();
            assert!(offer.raced.is_empty());
            assert_eq!(offer.entries.len(), 1);
            let lease = offer.entries[0].lease.as_ref().unwrap();
            assert_eq!(
                lease.lease.revision,
                revision.load(std::sync::atomic::Ordering::SeqCst)
            );
        }
        // A reconnect's new lease during the read: withheld as raced.
        *during.lock().unwrap() = During::Reconnect;
        let offer = observe();
        assert!(offer.entries.is_empty(), "{:?}", offer.entries);
        assert_eq!(offer.raced, reoffer);
        // Nothing changes during the next observation: offered, bound to the
        // lease it was observed with.
        let offer = observe();
        assert!(offer.raced.is_empty());
        assert_eq!(offer.entries.len(), 1);
        assert_eq!(offer.entries[0].lease.as_ref().unwrap().generation, 2);
    }

    /// WP2 (C11 at unit level): a server that goes silent while a census
    /// worker blocks ends the phase as a lost transport within the session's
    /// silence deadline (detach + reconnect), instead of holding the session
    /// for the whole worker. A server that keeps answering heartbeats does not.
    #[test]
    fn silence_during_census_is_a_transport_loss() {
        for answers in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap(),
            );
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            tcp.set_read_timeout(Some(Duration::from_millis(10)))
                .unwrap();
            let (peer, _) = listener.accept().unwrap();
            let mut socket = tungstenite::WebSocket::from_raw_socket(
                tungstenite::stream::MaybeTlsStream::Plain(tcp),
                tungstenite::protocol::Role::Client,
                None,
            );
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let server = {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    peer.set_read_timeout(Some(Duration::from_millis(20)))
                        .unwrap();
                    let mut wire = tungstenite::WebSocket::from_raw_socket(
                        peer,
                        tungstenite::protocol::Role::Server,
                        None,
                    );
                    // Blackholed: read nothing, send nothing. Answering: a
                    // ping every 100 ms keeps the transport demonstrably live.
                    while !stop.load(std::sync::atomic::Ordering::Acquire) {
                        if answers {
                            let _ = wire.send(tungstenite::Message::Ping(Vec::new().into()));
                            let _ = wire.read();
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                })
            };
            let mut deferred = DeferredPushes::default();
            deferred.set_silence_deadline(Duration::from_millis(500));
            let key_control = KeyControl {
                journal: &journal,
                binding: &binding,
                epoch: None,
                credentials: None,
            };
            let started = std::time::Instant::now();
            // The census worker blocks far past the deadline.
            let result = while_reading(
                &mut socket,
                "inventory census",
                key_control,
                &mut deferred,
                |fence| {
                    let until = std::time::Instant::now() + Duration::from_secs(2);
                    while std::time::Instant::now() < until && !fence.is_cancelled() {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                },
            );
            stop.store(true, std::sync::atomic::Ordering::Release);
            server.join().unwrap();
            if answers {
                result.expect("a live server never trips the silence deadline");
                continue;
            }
            let error = result.expect_err("silence ends the phase");
            assert!(
                super::super::connect::transport_lost(&error),
                "silence is a transport loss: {error:#}"
            );
            assert_eq!(
                super::super::connect::session_end(&error, false, false),
                super::super::connect::SessionEnd::Detach
            );
            assert!(
                started.elapsed() < Duration::from_millis(1500),
                "the deadline, not the worker, ended it: {:?}",
                started.elapsed()
            );
        }
    }

    const BLOCKLIST_FRAME: &str = r#"{"type":"egress.blocklist","configured":false,"entries":[],"digest":"sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"}"#;

    /// Runs a full reconciliation on an empty journal against `serve`, the
    /// server side of the socket.
    fn reconcile_against(
        serve: impl FnOnce(&mut tungstenite::WebSocket<TcpStream>) + Send + 'static,
    ) -> (Result<ExpiryReported>, DeferredPushes) {
        reconcile_against_with(None, serve)
    }

    /// A host terminal push: needs post-registration state, so it is held.
    fn terminal_frame(sequence: u64) -> String {
        serde_json::to_string(&sandbox_protocol::ServerControlMessage::TerminalAck {
            fence: sandbox_protocol::TerminalFence {
                session_id: "s1".into(),
                operation_id: "o1".into(),
                host_id: "host".into(),
                epoch: 1,
                target: sandbox_protocol::TerminalTargetV11::Host {},
            },
            sequence,
        })
        .unwrap()
    }

    fn reconcile_against_with(
        egress: Option<Arc<crate::sandbox_relay::egress_state::NodeEgress>>,
        serve: impl FnOnce(&mut tungstenite::WebSocket<TcpStream>) + Send + 'static,
    ) -> (Result<ExpiryReported>, DeferredPushes) {
        reconcile_against_runtime(egress, sandbox_runtime::FakeRuntime::new(), serve)
    }

    fn reconcile_against_runtime(
        egress: Option<Arc<crate::sandbox_relay::egress_state::NodeEgress>>,
        fake: sandbox_runtime::FakeRuntime,
        serve: impl FnOnce(&mut tungstenite::WebSocket<TcpStream>) + Send + 'static,
    ) -> (Result<ExpiryReported>, DeferredPushes) {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap(),
        );
        let runtime: Arc<dyn sandbox_runtime::SandboxRuntime> = Arc::new({
            fake.fixture_root().unwrap();
            fake
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        tcp.set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut socket = tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        );
        let server = std::thread::spawn(move || {
            let mut wire = tungstenite::WebSocket::from_raw_socket(
                peer,
                tungstenite::protocol::Role::Server,
                None,
            );
            serve(&mut wire);
        });
        let expiry = super::super::expiry::ExpiryService::start(
            runtime.clone(),
            journal.clone(),
            super::super::authority::HostAuthority::with_journal(journal.clone()),
        );
        let mut deferred = DeferredPushes::default();
        deferred.handle_egress_with(egress);
        let result = reconcile_after_hello(
            &journal,
            &binding,
            &runtime,
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &expiry,
            None,
            None,
            &mut deferred,
        );
        drop(socket);
        drop(expiry);
        let _ = server.join();
        (result, deferred)
    }

    fn send_text(wire: &mut tungstenite::WebSocket<TcpStream>, text: &str) {
        wire.send(tungstenite::Message::Text(text.to_owned().into()))
            .unwrap();
    }

    /// A host-terminal push can reach the daemon while reconciliation awaits
    /// an acknowledgement. Reconciliation keeps it, in order, for the
    /// dispatch loop instead of dropping the session.
    #[test]
    fn server_pushes_during_reconciliation_are_held_in_order() {
        let (result, mut deferred) = reconcile_against(|wire| {
            send_text(wire, &terminal_frame(1));
            let census = wire.read().unwrap();
            assert!(census.to_text().unwrap().contains("sandbox.inventory"));
            send_text(wire, &terminal_frame(2));
            send_text(
                wire,
                r#"{"type":"inventory.ack","page":0,"entryResults":[]}"#,
            );
            let complete = wire.read().unwrap();
            assert!(complete.to_text().unwrap().contains("reconcile.complete"));
        });
        result.expect("a server push does not abort reconciliation");
        assert_eq!(deferred.len(), 2);
        let first = deferred.next().unwrap();
        assert_eq!(first.to_text().unwrap(), terminal_frame(1));
        let second = deferred.next().unwrap();
        assert_eq!(second.to_text().unwrap(), terminal_frame(2));
        assert!(deferred.next().is_none());
    }

    /// The server sends `egress.blocklist` right after
    /// `hello.ok`. It reaches the node egress state (and wakes the guard
    /// monitor) WHILE reconciliation still awaits its acknowledgement, not
    /// after the whole receipt/adoption/audit/census pass, and is not held.
    #[test]
    fn an_egress_blocklist_during_reconciliation_reaches_the_guard_at_once() {
        let node = Arc::new(crate::sandbox_relay::egress_state::NodeEgress::new(
            None,
            &crate::config::Config::default(),
        ));
        let _ = node.deployment_and_wake();
        let observed = Arc::new(std::sync::Mutex::new(None));
        let (watch, seen) = (node.clone(), observed.clone());
        let (result, deferred) = reconcile_against_with(Some(node.clone()), move |wire| {
            let census = wire.read().unwrap();
            assert!(census.to_text().unwrap().contains("sandbox.inventory"));
            send_text(wire, BLOCKLIST_FRAME);
            // The inventory is still unacknowledged: reconciliation is
            // mid-flight. The list must land now.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let state = loop {
                let state = watch.deployment_and_wake();
                if state.0.is_some() || std::time::Instant::now() > deadline {
                    break state;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            *seen.lock().unwrap() = Some(state);
            send_text(
                wire,
                r#"{"type":"inventory.ack","page":0,"entryResults":[]}"#,
            );
            let complete = wire.read().unwrap();
            assert!(complete.to_text().unwrap().contains("reconcile.complete"));
        });
        result.expect("a blocklist does not abort reconciliation");
        let (desired, woken) = observed.lock().unwrap().take().unwrap();
        assert_eq!(
            desired,
            Some(crate::sandbox_relay::egress_state::DeploymentList {
                configured: false,
                entries: Vec::new(),
            }),
            "applied during reconciliation"
        );
        assert!(woken, "the guard monitor is woken to push it");
        assert_eq!(deferred.len(), 0, "a blocklist is never held");
    }

    /// The reconciliation census blocks on the
    /// host daemon (here: an inventory that only returns once the node has
    /// the blocklist, or after 5 s). A blocklist the server sends meanwhile
    /// reaches the node egress state (and wakes the monitor) while the census
    /// is still running, not after it.
    #[test]
    fn a_blocklist_reaches_the_guard_while_a_slow_census_runs() {
        let node = Arc::new(crate::sandbox_relay::egress_state::NodeEgress::new(
            None,
            &crate::config::Config::default(),
        ));
        let _ = node.deployment_and_wake();
        // (calls, calls that saw the list before returning, any wake seen)
        let seen = Arc::new(std::sync::Mutex::new((0usize, 0usize, false)));
        let (watch, record) = (node.clone(), seen.clone());
        let fake = sandbox_runtime::FakeRuntime::new().with_inventory_hook(move |_| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut woken = false;
            let applied = loop {
                let (desired, wake) = watch.deployment_and_wake();
                woken |= wake;
                if desired.is_some() {
                    break true;
                }
                if std::time::Instant::now() > deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let mut record = record.lock().unwrap();
            record.0 += 1;
            record.1 += usize::from(applied);
            record.2 |= woken;
            Ok(())
        });
        let (result, deferred) = reconcile_against_runtime(Some(node), fake, |wire| {
            // Sent before the daemon's census exists: only a reader running
            // during the census pass can apply it.
            send_text(wire, BLOCKLIST_FRAME);
            let census = wire.read().unwrap();
            assert!(census.to_text().unwrap().contains("sandbox.inventory"));
            send_text(
                wire,
                r#"{"type":"inventory.ack","page":0,"entryResults":[]}"#,
            );
            let complete = wire.read().unwrap();
            assert!(complete.to_text().unwrap().contains("reconcile.complete"));
        });
        result.expect("a blocklist does not abort reconciliation");
        let (calls, applied, woken) = *seen.lock().unwrap();
        assert!(calls > 0, "the census ran the inventory");
        assert_eq!(applied, calls, "applied before every inventory finished");
        assert!(woken, "the guard monitor is woken to push it");
        assert_eq!(deferred.len(), 0, "a blocklist is never held");
    }

    /// Holding is not leniency: a frame that is neither the awaited answer
    /// nor a deferrable push still fails reconciliation.
    #[test]
    fn unexpected_frames_during_reconciliation_still_fail() {
        let (result, deferred) = reconcile_against(|wire| {
            let _ = wire.read();
            send_text(wire, r#"{"type":"receipt.ack","operationId":"other"}"#);
        });
        let error = result.expect_err("unexpected frame fails reconciliation");
        assert!(format!("{error:#}").contains("unexpected inventory response"));
        assert_eq!(deferred.len(), 0);
    }

    /// E3-B-03: the server's refusal reaches the daemon log. A census the
    /// server refuses names the server's reason, not just "unexpected".
    #[test]
    fn a_refused_census_names_the_server_reason() {
        let (result, _) = reconcile_against(|wire| {
            let _ = wire.read();
            send_text(
                wire,
                r#"{"type":"protocol.error","failure":"protocol_error","message":"Host inventory conflicts with server records."}"#,
            );
        });
        let error = format!("{:#}", result.expect_err("a refusal fails reconciliation"));
        assert!(
            error.contains(
                "relay server refused (protocol_error): Host inventory conflicts with server records."
            ),
            "{error}"
        );
        assert!(error.contains("unexpected inventory response"), "{error}");
    }

    /// Any other unexpected frame is named by its type only, never its body.
    #[test]
    fn an_unexpected_frame_is_named_by_type() {
        let (result, _) = reconcile_against(|wire| {
            let _ = wire.read();
            send_text(wire, r#"{"type":"receipt.ack","operationId":"other"}"#);
        });
        let error = format!("{:#}", result.expect_err("unexpected frame fails"));
        assert!(error.contains("relay server sent receipt.ack"), "{error}");
        assert!(!error.contains("other"), "{error}");
    }

    /// The held buffer is bounded: one push past the bound fails the session.
    /// A transport loss (the pump fails) returns at once,
    /// without joining the worker; the obsolete worker's permit is revoked
    /// (its host calls are cancelled), and its late result never reaches the
    /// next session's call, which gets only its own worker's result.
    #[test]
    fn a_lost_session_fences_its_worker_and_never_applies_its_result() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let old_done = Arc::new(AtomicBool::new(false));
        let old_saw_fence = Arc::new(AtomicBool::new(false));
        let (done, saw) = (old_done.clone(), old_saw_fence.clone());
        let started = std::time::Instant::now();
        let lost = while_pumping(
            "old inventory",
            move |fence| {
                let _ = release_rx.recv_timeout(Duration::from_secs(30));
                saw.store(fence.is_cancelled(), Ordering::Release);
                done.store(true, Ordering::Release);
                "stale"
            },
            |_| bail!("connection reset"),
        );
        assert!(lost.is_err(), "the transport loss is returned");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the transport loss waited for the obsolete worker"
        );
        assert!(
            !old_done.load(Ordering::Acquire),
            "the old worker is still held"
        );
        // The next session's worker lets the obsolete one finish (and send
        // its result) before returning its own.
        let done = old_done.clone();
        let fresh = while_pumping(
            "new inventory",
            move |_| {
                release_tx.send(()).unwrap();
                while !done.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                "fresh"
            },
            |_| {
                std::thread::sleep(Duration::from_millis(5));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            fresh, "fresh",
            "only this session's worker result is applied"
        );
        assert!(
            old_saw_fence.load(Ordering::Acquire),
            "the obsolete worker's permit was revoked"
        );
    }

    #[test]
    fn held_server_pushes_are_bounded() {
        let (result, deferred) = reconcile_against(|wire| {
            let _ = wire.read();
            for sequence in 0..=MAX_DEFERRED_PUSHES {
                send_text(wire, &terminal_frame(sequence as u64));
            }
            send_text(
                wire,
                r#"{"type":"inventory.ack","page":0,"entryResults":[]}"#,
            );
        });
        let error = result.expect_err("an unbounded push stream fails reconciliation");
        assert!(format!("{error:#}").contains("too many server pushes"));
        assert_eq!(deferred.len(), MAX_DEFERRED_PUSHES);
    }
}
