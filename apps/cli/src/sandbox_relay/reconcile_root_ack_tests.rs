//! Exact root retirement ACK, local capacity and recovery regressions.
use super::cleanup_tests::cleanup_journal;
use super::*;
use crate::sandbox_relay::test_support::open_ready_journal;
use sandbox_protocol::OperationDispatch;
use sandbox_runtime::{FakeRuntime, SandboxRuntime};
use std::sync::Arc;

fn binding() -> TransportBindingV11 {
    TransportBindingV11 {
        server: "wss://cleanup.test".into(),
        host_owner_id: "owner".into(),
        host_id: "host".into(),
    }
}

fn retirement_result() -> sandbox_protocol::CensusEntryResult {
    sandbox_protocol::CensusEntryResult {
        sandbox_id: "sbx".into(),
        outcome: sandbox_protocol::CensusEntryOutcome::Converged,
        root_retired: true,
    }
}

fn observe_retirement(
    journal: &HostJournal,
    runtime: &FakeRuntime,
) -> (Vec<sandbox_protocol::InventoryEntry>, RootRetirements) {
    let fences = root_retirement_fences(journal, ["sbx".to_string()]);
    let entries = inventory_census(journal, runtime, &Default::default()).unwrap();
    assert!(entries[0].root.as_ref().unwrap().network_cleanup_complete);
    (entries, fences)
}

#[test]
fn root_retirement_ack_releases_capacity_in_session_and_survives_receipt_recovery() {
    for (with_lease, compact_lease) in [(true, false), (false, false), (true, true)] {
        let dir = tempfile::tempdir().unwrap();
        let binding = binding();
        let journal = cleanup_journal(dir.path(), &binding, with_lease, compact_lease);
        let runtime = Arc::new(FakeRuntime::new());
        runtime.fixture_root().unwrap();
        let original = journal.retained_roots()["sbx"].clone();
        let ceiling = journal.implicit_ceiling(&original.allocation.storage_marker);
        assert_eq!(journal.lease("sbx").is_some(), with_lease && !compact_lease);
        let (entries, _) = observe_retirement(&journal, &runtime);
        // A dropped socket/ACK loses no charged identity, including without a lease.
        drop(journal);
        let journal = Arc::new(open_ready_journal(dir.path(), &binding).unwrap());
        assert_eq!(journal.retained_roots()["sbx"], original);
        assert_eq!(
            inventory_census(&journal, runtime.as_ref(), &Default::default()).unwrap(),
            entries
        );

        let mut admission = super::super::live_admission::LiveSandboxAdmission::new(
            8,
            sandbox_protocol::VmCapacity::new(8192, 8).unwrap(),
        );
        admission.rebuild(&[], &journal, &binding).unwrap();
        assert_eq!(
            admission.held(),
            0,
            "root-only charge has no live reservation"
        );
        let mut pool = journal
            .pool_snapshot(&original.allocation.storage_marker)
            .unwrap();
        pool.capacity_gi_b = original.allocation.root_charge_gi_b;
        admission.set_pools(vec![pool]);
        let next: OperationDispatch = serde_json::from_value(serde_json::json!({
            "sandboxOwnerId":"owner", "operationId":"next", "sandboxId":"next", "kind":"sandbox.create",
            "generation":1, "attempt":1, "idempotencyKey":"next", "bodyHash":"a".repeat(64),
            "allocation":original.allocation, "cpuCount":1, "memoryMiB":1024
        })).unwrap();
        assert_eq!(
            admission.try_acquire_pinned(&next),
            Err(SandboxErrorCode::HostCapacity)
        );

        // Drive the production census sender and strict wire ACK parser. The
        // server repeats retirement even though it already detached the row.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_millis(10)))
            .unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = tungstenite::accept(peer).unwrap();
            let frame = wire.read().unwrap();
            let sandbox_protocol::DaemonControlMessage::SandboxInventory { page, entries, .. } =
                sandbox_protocol::parse_daemon_control(frame.to_text().unwrap()).unwrap()
            else {
                panic!("inventory expected")
            };
            assert!(entries[0].root.as_ref().unwrap().network_cleanup_complete);
            wire.send(tungstenite::Message::Text(serde_json::json!({"type":"inventory.ack", "page":page, "entryResults":[{"sandboxId":"sbx","outcome":"converged","rootRetired":true}]}).to_string().into())).unwrap();
        });
        let (mut socket, _) = tungstenite::client(
            "ws://localhost/",
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
        )
        .unwrap();
        let scoped: Arc<dyn SandboxRuntime> = runtime.clone();
        send_census_judged(
            &mut socket,
            &journal,
            &scoped,
            entries,
            &Default::default(),
            KeyControl {
                journal: &journal,
                binding: &binding,
                epoch: None,
                credentials: None,
            },
            sandbox_protocol::WireCodes::CURRENT,
            &mut DeferredPushes::default(),
            None,
        )
        .unwrap();
        server.join().unwrap();
        assert!(journal.retained_roots().is_empty());
        assert_eq!(
            journal.root_deleted_generation("sbx"),
            Some(if compact_lease { 6 } else { 5 })
        );
        assert_eq!(
            journal.implicit_ceiling(&original.allocation.storage_marker),
            ceiling
        );
        admission.refresh_retained(&journal);
        admission.try_acquire_pinned(&next).unwrap();
        assert_eq!(
            admission.held(),
            1,
            "next root admitted without daemon restart"
        );
        assert!(
            journal.lookup("op-1").is_some() != compact_lease,
            "only compacted lineage has confirmed the old create receipt"
        );
        if !compact_lease {
            assert_eq!(
                journal.lookup("op-5").unwrap().state,
                OperationState::Failed
            );
        }
        drop(journal);
        let journal = open_ready_journal(dir.path(), &binding).unwrap();
        assert!(
            journal.retained_roots().is_empty(),
            "old create receipt cannot resurrect charge"
        );
        let committed: u64 = journal
            .retained_roots()
            .values()
            .map(|r| u64::from(r.allocation.root_charge_gi_b))
            .sum();
        assert_eq!(committed, 0);
        assert_eq!(
            journal.implicit_ceiling(&original.allocation.storage_marker),
            ceiling
        );
    }
}

#[test]
fn retirement_ack_rejects_stale_attempt_new_generation_and_busy_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let journal = cleanup_journal(dir.path(), &binding, false, false);
    let runtime = FakeRuntime::new();
    runtime.fixture_root().unwrap();
    let (entries, fences) = observe_retirement(&journal, &runtime);
    let results = [retirement_result()];
    for _busy_kind in ["queued", "carried", "active", "resolving"] {
        retire_acknowledged_roots(
            &journal,
            &entries,
            &results,
            &fences,
            &std::collections::HashSet::from(["sbx".into()]),
        )
        .unwrap();
        assert_eq!(journal.retained_roots().len(), 1);
    }
    let mut retry = journal.lookup("op-5").unwrap();
    retry.attempt += 1;
    retry.operation_id = "retry-attempt".into();
    retry.idempotency_key = "retry-attempt".into();
    journal.record_intent(&retry).unwrap();
    assert!(journal.root_retirement_fence("sbx").is_none());
    journal.record_effect("retry-attempt").unwrap();
    journal
        .record_result(
            "retry-attempt",
            OperationState::Failed,
            None,
            Some(SandboxErrorCode::Internal),
            Some("failed".into()),
        )
        .unwrap();
    retire_acknowledged_roots(&journal, &entries, &results, &fences, &Default::default()).unwrap();
    assert_eq!(
        journal.retained_roots().len(),
        1,
        "same generation retry invalidates old ACK"
    );
    let (entries, fences) = observe_retirement(&journal, &runtime);
    let mut newer = journal.lookup("op-1").unwrap();
    newer.operation_id = "new-generation".into();
    newer.idempotency_key = "new-generation".into();
    newer.generation = 6;
    journal.record_intent(&newer).unwrap();
    assert!(
        journal.root_retirement_fence("sbx").is_none(),
        "pending lifecycle blocks observation authority"
    );
    retire_acknowledged_roots(&journal, &entries, &results, &fences, &Default::default()).unwrap();
    assert_eq!(journal.retained_roots()["sbx"].generation, 6);
    journal.record_effect("new-generation").unwrap();
    journal
        .record_result(
            "new-generation",
            OperationState::Failed,
            None,
            Some(SandboxErrorCode::Internal),
            Some("failed".into()),
        )
        .unwrap();
    retire_acknowledged_roots(&journal, &entries, &results, &fences, &Default::default()).unwrap();
    assert_eq!(
        journal.retained_roots()["sbx"].generation,
        6,
        "completed newer work remains charged"
    );
}

#[test]
fn retirement_persistence_failure_and_partial_evidence_keep_charge() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let journal = cleanup_journal(dir.path(), &binding, false, false);
    let runtime = FakeRuntime::new();
    runtime.fixture_root().unwrap();
    let (entries, fences) = observe_retirement(&journal, &runtime);
    let mut adopted_only = retirement_result();
    adopted_only.root_retired = false;
    retire_acknowledged_roots(
        &journal,
        &entries,
        &[adopted_only],
        &fences,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(journal.retained_roots().len(), 1);
    for partial in [None, Some(false)] {
        let mut entries = entries.clone();
        if partial.is_none() {
            entries[0].root = None;
        } else {
            entries[0].root.as_mut().unwrap().network_cleanup_complete = false;
        }
        assert!(
            retire_acknowledged_roots(
                &journal,
                &entries,
                &[retirement_result()],
                &fences,
                &Default::default()
            )
            .is_err()
        );
        assert_eq!(journal.retained_roots().len(), 1);
    }
    for mismatch in ["owner", "marker", "pool", "disk"] {
        let mut mismatched = entries.clone();
        let root = mismatched[0].root.as_mut().unwrap();
        match mismatch {
            "marker" => root.storage_marker = "b".repeat(32),
            "pool" => root.storage_pool_name = "other".into(),
            "disk" => root.disk_gi_b += 1,
            _ => mismatched[0].sandbox_owner_id = Some("other".into()),
        }
        let refused = retire_acknowledged_roots(
            &journal,
            &mismatched,
            &[retirement_result()],
            &fences,
            &Default::default(),
        )
        .unwrap();
        assert!(refused.contains("sbx"));
        assert_eq!(journal.retained_roots().len(), 1);
    }
    journal.io.fail_writes();
    assert!(
        retire_acknowledged_roots(
            &journal,
            &entries,
            &[retirement_result()],
            &fences,
            &Default::default()
        )
        .is_err()
    );
    assert!(journal.io_failed());
    assert_eq!(journal.retained_roots().len(), 1);
    drop(journal);
    let journal = open_ready_journal(dir.path(), &binding).unwrap();
    assert_eq!(
        journal.retained_roots().len(),
        1,
        "failed deletion never publishes a tombstone"
    );
}

#[test]
fn connected_root_only_retirement_uses_its_exact_batch_and_reoffers_races() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let journal = cleanup_journal(dir.path(), &binding, false, false);
    let runtime = FakeRuntime::new();
    runtime.fixture_root().unwrap();
    let offer = || {
        expiry_status_offer(
            &journal,
            &runtime,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            std::collections::BTreeSet::from(["sbx".into()]),
            &Default::default(),
            &Default::default(),
        )
        .unwrap()
    };
    let offered = offer();
    assert!(offered.entries[0].lease.is_none());
    let mut evidence = super::super::evidence::Evidence::default();
    let frames = evidence.offer(
        offered.entries,
        &offered.changes,
        &offered.bindings,
        1,
        &Default::default(),
        std::time::Instant::now(),
    );
    let sandbox_protocol::DaemonControlMessage::SandboxExpiryStatus {
        batch: Some(batch), ..
    } = frames[0]
    else {
        panic!("batch expected")
    };
    let results = [retirement_result()];
    assert!(evidence.acknowledged_entries(batch + 1, &results).is_err());
    let entries = evidence.acknowledged_entries(batch, &results).unwrap();
    let mut raced_entry = entries.clone();
    let mut retry = journal.lookup("op-5").unwrap();
    retry.attempt += 1;
    journal.record_intent(&retry).unwrap();
    invalidate_raced_root_proofs(&journal, &mut raced_entry, &offered.retirements);
    assert!(
        !raced_entry[0]
            .root
            .as_ref()
            .unwrap()
            .network_cleanup_complete
    );
    let raced = retire_acknowledged_roots(
        &journal,
        &entries,
        &results,
        &offered.retirements,
        &Default::default(),
    )
    .unwrap();
    assert!(raced.contains("sbx"));
    let mut refused = results;
    refused[0].root_retired = false;
    refused[0].outcome = sandbox_protocol::CensusEntryOutcome::Superseded;
    let mut reported = ExpiryReported::new();
    evidence
        .acknowledge(batch, &refused, &mut reported)
        .unwrap();
    assert!(evidence.due(2, &Default::default()).contains("sbx"));
    let offered = offer();
    let raced = retire_acknowledged_roots(
        &journal,
        &offered.entries,
        &[retirement_result()],
        &offered.retirements,
        &Default::default(),
    )
    .unwrap();
    assert!(raced.is_empty());
    assert!(journal.retained_roots().is_empty());
}
