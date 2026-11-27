//! F11-b: retained failed cleanup roots must be provable without a deleted lease.
use super::*;
use crate::sandbox_relay::journal::intent_from_dispatch;
use crate::sandbox_relay::test_support::{allocation, open_ready_journal};
use sandbox_protocol::{OperationDispatch, RootState, SandboxLifecycleState};
use sandbox_runtime::{FakeRuntime, SandboxRuntime};
use std::sync::Arc;

pub(super) fn cleanup_journal(
    path: &std::path::Path,
    binding: &TransportBindingV11,
    with_lease: bool,
    compact_lease: bool,
) -> Arc<HostJournal> {
    let journal = open_ready_journal(path, binding).unwrap();
    let allocation = allocation();
    // Failed boot retains the allocation; STOP/absent releases only live work.
    // Persist the same Effect/FAILED receipts as exhausted cleanup KILLs;
    // do not seed a retained-root fixture or manufacture census evidence.
    for (generation, kind) in [
        (1, "sandbox.create"),
        (2, "sandbox.stop"),
        (3, "sandbox.kill"),
        (4, "sandbox.kill"),
        (5, "sandbox.kill"),
    ] {
        let id = format!("op-{generation}");
        let mut value = serde_json::json!({
            "sandboxOwnerId":"owner", "operationId":id, "sandboxId":"sbx",
            "generation":generation, "attempt":1, "kind":kind,
            "idempotencyKey":id, "bodyHash":"a".repeat(64), "allocation":allocation,
            "cpuCount":1, "memoryMiB":1024
        });
        if generation == 1 && with_lease {
            value["lease"] = serde_json::json!({
                "revision":1, "deadlineUnixMs":sandbox_protocol::HostLease::for_test().deadline_unix_ms,
                "action":"stop", "expiryPolicy":"retry-force-60s"
            });
        }
        let dispatch: OperationDispatch = serde_json::from_value(value).unwrap();
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, binding, &dispatch))
            .unwrap();
        if generation == 1 && with_lease {
            journal.accept_fixture_lease(&dispatch).unwrap();
        }
        journal.record_effect(&id).unwrap();
        if kind == "sandbox.stop" {
            journal
                .record_result(
                    &id,
                    OperationState::Succeeded,
                    Some(serde_json::json!({"state":"absent"})),
                    None,
                    None,
                )
                .unwrap();
        } else {
            journal
                .record_result(
                    &id,
                    OperationState::Failed,
                    None,
                    Some(SandboxErrorCode::Internal),
                    Some("cleanup failed".into()),
                )
                .unwrap();
        }
        if generation == 1 && compact_lease {
            // A real VM-only absent observation retires the inactive lease,
            // retaining its root. Subsequent failed cleanup never proves deletion.
            let runtime = FakeRuntime::new();
            runtime.fixture_root().unwrap();
            assert!(runtime.query_sandbox("sbx", None, None).unwrap().is_none());
            journal
                .retire_inactive_lease(&journal.lease("sbx").unwrap(), true)
                .unwrap();
        }
    }
    if compact_lease {
        for r in journal.matching(binding).unwrap() {
            journal
                .confirm(
                    binding,
                    &sandbox_protocol::ReceiptConfirmation {
                        sandbox_owner_id: r.sandbox_owner_id.clone(),
                        operation_id: r.operation_id.clone(),
                        sandbox_id: r.sandbox_id.clone(),
                        generation: r.generation,
                        attempt: r.attempt,
                        body_hash: r.server_request_hash().unwrap().to_owned(),
                        idempotency_key: r.idempotency_key.clone(),
                        kind: r.kind.clone(),
                        cleanup_generation: Some(6),
                        retire_command: false,
                    },
                )
                .unwrap();
        }
        journal.maintain().unwrap();
        assert!(
            journal.lease("sbx").is_none(),
            "production lease compaction removed the lease"
        );
        assert_eq!(
            journal.retained_roots().len(),
            1,
            "compaction retains the charged root"
        );
    }
    drop(journal);
    Arc::new(open_ready_journal(path, binding).unwrap())
}

#[test]
fn failed_cleanup_kill_census_requires_independent_network_absence() {
    let dir = tempfile::tempdir().unwrap();
    let binding = TransportBindingV11 {
        server: "wss://cleanup.test".into(),
        host_owner_id: "owner".into(),
        host_id: "host".into(),
    };
    let journal = cleanup_journal(dir.path(), &binding, true, false);
    let allocation = allocation();
    let runtime = FakeRuntime::new();
    let root = runtime.fixture_root().unwrap();
    assert_eq!(
        journal.lookup("op-5").unwrap().state,
        OperationState::Failed
    );
    assert!(!journal.retained_roots()["sbx"].live);
    assert!(!journal.lease("sbx").unwrap().root_deleted);
    let bound = bound_allocation(&journal, "sbx").unwrap();
    assert_eq!(bound.0, allocation);
    assert!(!bound.1, "failed KILL never journals root deletion");

    // Exercise both state gathering and the later page-root observation used
    // on a real reconnect. No fabricated root/network evidence is supplied.
    for pending in [true, false] {
        runtime.set_network_cleanup_pending("sbx", pending);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_millis(10)))
            .unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = tungstenite::accept(peer).unwrap();
            crate::sandbox_relay::test_support::ack_reconciliation(&mut wire)
        });
        let (mut socket, _) = tungstenite::client(
            "ws://localhost/",
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
        )
        .unwrap();
        let scoped: Arc<dyn SandboxRuntime> = Arc::new(runtime.clone());
        let expiry = super::super::expiry::ExpiryService::start(
            scoped.clone(),
            journal.clone(),
            super::super::authority::HostAuthority::with_journal(journal.clone()),
        );
        reconcile_after_hello(
            &journal,
            &binding,
            &scoped,
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &expiry,
            None,
            None,
            &mut DeferredPushes::default(),
        )
        .unwrap();
        drop(expiry);
        let entries = server.join().unwrap();
        let entry = entries
            .iter()
            .find(|entry| entry.sandbox_id == "sbx")
            .unwrap();
        assert_eq!(entry.sandbox_owner_id.as_deref(), Some("owner"));
        assert_eq!(entry.state, SandboxLifecycleState::Absent);
        let observed = entry.root.as_ref().unwrap();
        assert_eq!(observed.state, RootState::Absent);
        assert_eq!(observed.storage_pool_name, allocation.storage_pool_name);
        assert_eq!(observed.storage_marker, allocation.storage_marker);
        assert_eq!(observed.disk_gi_b, allocation.disk_gi_b);
        assert_eq!(observed.network_cleanup_complete, !pending);
    }
    // A retained orphan volume, a different disk size, and a missing original
    // pool all remain non-release evidence even after network cleanup finishes.
    let name = sandbox_runtime::default_incus_instance_name("sbx");
    runtime.seed_orphan_root(&name, root.clone());
    let entries = inventory_census(&journal, &runtime, &Default::default()).unwrap();
    assert_eq!(entries[0].root.as_ref().unwrap().state, RootState::Present);
    assert!(!entries[0].root.as_ref().unwrap().network_cleanup_complete);
    let mut wrong_root = root.clone();
    wrong_root.disk_gi_b += 1;
    runtime.seed_orphan_root(&name, wrong_root);
    let entries = inventory_census(&journal, &runtime, &Default::default()).unwrap();
    assert!(
        entries[0].root.is_none(),
        "a different root size proves nothing"
    );
    runtime.seed_orphan_root(&name, root.clone());
    runtime.delete_orphan_root(&root, &name).unwrap();
    assert!(
        !sandbox_runtime::UnsupportedRuntime::new()
            .prove_network_cleanup_complete("sbx")
            .unwrap()
    );
    // A carried worker is still authoritative: absence synthesized because
    // inventory skipped it must never acquire new cleanup proof.
    let entries = inventory_census_skipping(
        &journal,
        &runtime,
        &Default::default(),
        &std::collections::HashSet::from(["sbx".into()]),
    )
    .unwrap();
    assert!(!entries[0].root.as_ref().unwrap().network_cleanup_complete);
    runtime.set_storage_pool_available(&root.pool.name, false);
    let entries = inventory_census(&journal, &runtime, &Default::default()).unwrap();
    assert_eq!(entries[0].state, SandboxLifecycleState::Unreachable);
    assert!(
        entries[0].root.is_none(),
        "unavailable original pool is inconclusive"
    );
}
