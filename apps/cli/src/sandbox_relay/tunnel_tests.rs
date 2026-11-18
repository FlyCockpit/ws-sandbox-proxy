//! Tunnel manager tests with a stand-in client: a Python script speaking the
//! client's `--state-dir … daemon` contract (newline JSON on `daemon.sock`,
//! exit 3 for a gone tunnel). The token picks its behaviour.

use super::*;
use sandbox_runtime::FakeRuntime;

const FAKE_CLIENT: &str = r#"#!/usr/bin/env python3
import ctypes, json, os, socket, sys
# Like the real client: non-dumpable, so its /proc/<pid> is owned by root.
ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)
state = sys.argv[sys.argv.index("--state-dir") + 1]
os.makedirs(state, mode=0o700, exist_ok=True)
token = os.environ.get("TUNNEL_TOKEN", "")
with open(os.path.join(state, "seen.json"), "w") as f:
    json.dump({"argv": sys.argv, "target": os.environ.get("TUNNEL_TARGET_HOST"),
               "server": os.environ.get("TUNNEL_SERVER"), "token_set": bool(token),
               "env_keys": sorted(os.environ.keys())}, f)
if "exitthree" in token:
    sys.exit(3)
if "crash" in token:
    sys.exit(1)
path = os.path.join(state, "daemon.sock")
try:
    os.unlink(path)
except FileNotFoundError:
    pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
srv.listen(4)
ports = []
while True:
    conn, _ = srv.accept()
    f = conn.makefile("rw")
    line = f.readline()
    req = json.loads(line)
    if req["type"] == "expose" and "experr" in token:
        f.write(json.dumps({"type": "error", "message": "declaration failed"}) + "\n")
        f.flush()
        conn.close()
        continue
    if req["type"] == "expose":
        ports = req["ports"]
        with open(os.path.join(state, "ports.json"), "w") as p:
            json.dump(ports, p)
    status = {"state": "connected" if ports else "connecting", "tunnel_id": "abc123def4",
              "ports": [{"port": p, "connected": "pending" not in token} for p in ports]}
    f.write(json.dumps({"type": "status", "status": status}) + "\n")
    f.flush()
    conn.close()
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    key: String,
    base: PathBuf,
    /// Sandboxes whose lease here has lapsed.
    lapsed: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Sandboxes with no lease row here at all.
    absent: Arc<Mutex<std::collections::HashSet<String>>>,
    runtime: Arc<FakeRuntime>,
    manager: TunnelManager,
}

fn fixture(tamper: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let client = dir.path().join("tunnel-client");
    std::fs::write(&client, FAKE_CLIENT).unwrap();
    std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o555)).unwrap();
    let mut sha = file_sha256(&client).unwrap();
    if tamper {
        sha = "0".repeat(64);
    }
    // Unique per fixture: a sweep never touches another test's clients.
    let key = node_key(dir.path());
    let base = node_base(&dir.path().join("run"), &key);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&base)
        .unwrap();
    let runtime = Arc::new(FakeRuntime::new());
    let lapsed = Arc::new(Mutex::new(std::collections::HashSet::<String>::new()));
    // Held here: "foreign-*" sandboxes are another user's, "gone-*" (and
    // lapsed ones) are not held by this host; the rest are the owner's.
    let absent = Arc::new(Mutex::new(std::collections::HashSet::<String>::new()));
    let held = lapsed.clone();
    let missing = absent.clone();
    let holder: Holder = Arc::new(move |sandbox_id: &str| {
        if sandbox_id.starts_with("gone-") || missing.lock().unwrap().contains(sandbox_id) {
            LeaseHere::Unknown
        } else if held.lock().unwrap().contains(sandbox_id) {
            LeaseHere::Lapsed
        } else {
            LeaseHere::Live {
                own: !sandbox_id.starts_with("foreign-"),
            }
        }
    });
    let manager = TunnelManager::with_base(
        TunnelSettings {
            client,
            client_sha256: sha,
            max_tunnels: 2,
            allow_for_others: false,
        },
        runtime.clone(),
        holder.clone(),
        base.clone(),
    );
    Fixture {
        _dir: dir,
        key,
        base,
        lapsed,
        absent,
        runtime,
        manager,
    }
}

fn apply(sandbox: &str, generation: u64, token: &str, ports: Vec<u16>) -> TunnelApplyV11 {
    TunnelApplyV11 {
        sandbox_id: sandbox.into(),
        generation,
        server: "https://tunnel.example.com".into(),
        token: format!("tntun_{token}"),
        ports,
    }
}

/// The running client's pid (the manager owns it; there is no pid file).
fn client_pid(f: &Fixture, sandbox: &str) -> i32 {
    for _ in 0..50 {
        if let Some(child) = f.manager.entries.lock().unwrap()[sandbox].child.as_ref() {
            return i32::try_from(child.id()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(100));
        f.manager.poll();
    }
    panic!("no running client for {sandbox}");
}

fn wait_for(f: &Fixture, mut done: impl FnMut(&[TunnelStatusV11]) -> bool) -> Vec<TunnelStatusV11> {
    let mut seen = Vec::new();
    for _ in 0..100 {
        f.manager.poll();
        seen.extend(f.manager.drain_events());
        if done(&seen) {
            return seen;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("condition not reached; saw {seen:?}");
}

#[test]
fn apply_without_a_recorded_plan_is_refused() {
    let f = fixture(false);
    f.manager
        .apply(apply("sbx-1", 1, "aaaaaaaaaaaaaaaaaaaa", vec![3000]));
    f.manager.poll();
    let events = f.manager.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].error, Some(TunnelErrorV11::Refused));
    assert!(!f.base.join("sbx-1").exists());
}

#[test]
fn undeclared_ports_are_refused() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 1, "aaaaaaaaaaaaaaaaaaaa", vec![3000, 4000]));
    f.manager.poll();
    let events = f.manager.drain_events();
    assert_eq!(events[0].error, Some(TunnelErrorV11::Refused));
}

#[test]
fn a_tampered_client_never_runs() {
    let f = fixture(true);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 1, "aaaaaaaaaaaaaaaaaaaa", vec![3000]));
    f.manager.poll();
    let events = f.manager.drain_events();
    assert_eq!(events[0].error, Some(TunnelErrorV11::Refused));
    assert!(
        !f.base
            .join("sbx-1")
            .join("client")
            .join("seen.json")
            .exists()
    );
}

#[test]
fn client_gets_the_recorded_target_and_token_only_through_its_environment() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000, 5173]);
    f.manager
        .apply(apply("sbx-1", 1, "secretsecretsecret01", vec![5173]));
    let events = wait_for(&f, |seen| {
        seen.iter()
            .any(|status| status.state == TunnelStateV11::Connected)
    });
    let connected = events
        .iter()
        .find(|status| status.state == TunnelStateV11::Connected)
        .unwrap();
    assert_eq!(connected.generation, 1);
    assert_eq!(connected.tunnel_id.as_deref(), Some("abc123def4"));
    let state = f.base.join("sbx-1").join("client");
    let seen: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(state.join("seen.json")).unwrap()).unwrap();
    assert_eq!(seen["target"], "10.9.8.2");
    assert_eq!(seen["server"], "https://tunnel.example.com");
    assert_eq!(seen["token_set"], true);
    assert!(
        !seen["argv"].to_string().contains("tntun_"),
        "token must never be in argv"
    );
    let ports: Vec<u16> =
        serde_json::from_str(&std::fs::read_to_string(state.join("ports.json")).unwrap()).unwrap();
    assert_eq!(ports, vec![5173]);
    // A stale or repeated generation changes nothing.
    f.manager
        .apply(apply("sbx-1", 1, "otherotherotherother", vec![3000]));
    f.manager.poll();
    assert!(f.manager.drain_events().is_empty());
    // Clear stops and reaps the client and removes its state.
    f.manager.clear(&TunnelClearV11 {
        sandbox_id: "sbx-1".into(),
        generation: 1,
    });
    f.manager.poll();
    assert!(!f.base.join("sbx-1").exists());
    let events = f.manager.drain_events();
    assert_eq!(events.last().unwrap().state, TunnelStateV11::Stopped);
}

#[test]
fn a_gone_tunnel_is_terminal_and_not_restarted() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 1, "exitthreeexitthree00", vec![3000]));
    let events = wait_for(&f, |seen| {
        seen.iter()
            .any(|status| status.error == Some(TunnelErrorV11::TunnelGone))
    });
    assert!(
        events
            .iter()
            .all(|status| status.error != Some(TunnelErrorV11::ClientFailed))
    );
    // A newer generation starts again.
    f.manager
        .apply(apply("sbx-1", 2, "secretsecretsecret02", vec![3000]));
    wait_for(&f, |seen| {
        seen.iter()
            .any(|status| status.generation == 2 && status.state == TunnelStateV11::Connected)
    });
    f.manager.stop_all();
}

#[test]
fn teardown_stop_reaps_and_the_node_limit_holds() {
    let f = fixture(false);
    for id in ["sbx-1", "sbx-2", "sbx-3"] {
        f.runtime
            .set_tunnel_target(id, "10.9.8.2".parse().unwrap(), vec![3000]);
        f.manager
            .apply(apply(id, 1, "secretsecretsecret03", vec![3000]));
    }
    f.manager.poll();
    let events = f.manager.drain_events();
    assert!(events.iter().any(
        |status| status.sandbox_id == "sbx-3" && status.error == Some(TunnelErrorV11::Refused)
    ));
    let pid = client_pid(&f, "sbx-1");
    f.manager.stop("sbx-1");
    assert!(!f.base.join("sbx-1").exists());
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "client reaped"
    );
    f.manager.stop_all();
    assert!(!f.base.join("sbx-2").exists());
}

#[test]
fn a_teardown_fences_queued_applies_until_a_new_bridge_exists() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 1, "secretsecretsecret04", vec![3000]));
    f.manager.poll();
    assert!(f.base.join("sbx-1").exists());
    // An apply queued before the teardown hook ran: the recorded plan still
    // exists, but the network is being torn down.
    f.manager
        .apply(apply("sbx-1", 2, "secretsecretsecret05", vec![3000]));
    f.manager.stop("sbx-1");
    f.manager.poll();
    assert!(!f.base.join("sbx-1").exists(), "no client after teardown");
    let events = f.manager.drain_events();
    assert!(
        events
            .iter()
            .any(|status| status.state == TunnelStateV11::Stopped)
    );
    assert!(
        events
            .iter()
            .any(|status| status.generation == 2 && status.error == Some(TunnelErrorV11::Refused))
    );
    // A new bridge for the sandbox re-admits applies.
    f.manager.network_created("sbx-1");
    f.manager
        .apply(apply("sbx-1", 3, "secretsecretsecret06", vec![3000]));
    f.manager.poll();
    assert!(client_pid(&f, "sbx-1") > 0);
    f.manager.stop_all();
}

#[test]
fn a_new_daemon_sweeps_an_earlier_daemons_clients_whatever_their_binary() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 1, "secretsecretsecret07", vec![3000]));
    f.manager.poll();
    let pid = client_pid(&f, "sbx-1");
    // An earlier daemon's client has long been running: wait until it is.
    let seen = f.base.join("sbx-1").join("client").join("seen.json");
    for _ in 0..100 {
        if seen.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Non-dumpable like the real client: its /proc files are root's (the
    // directory too, on some kernels), so only the `Uid:` line identifies
    // the owner.
    let uid = nix::unistd::geteuid().as_raw();
    let proc_owner = std::fs::metadata(format!("/proc/{pid}/status"))
        .unwrap()
        .uid();
    assert!(
        uid == 0 || proc_owner == 0,
        "stand-in client is still dumpable"
    );
    assert_eq!(effective_uid(pid), Some(uid));
    // Found by its argv even when a race already removed its directory
    // (the running client may still be writing into it: retried).
    for _ in 0..50 {
        let _ = std::fs::remove_dir_all(f.base.join("sbx-1"));
        if !f.base.join("sbx-1").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!f.base.join("sbx-1").exists());
    // A stray directory without a client is removed.
    std::fs::create_dir_all(f.base.join("sbx-2")).unwrap();
    // The earlier daemon "crashed": its manager is gone without stop_all.
    let base = f.base.clone();
    let key = f.key.clone();
    std::mem::forget(f.manager);
    // Found by its node key alone, even without a runtime directory now.
    sweep_leftovers_of(&key, None).unwrap();
    sweep_leftovers_of(&key, Some(&base)).unwrap();
    // Our own child is a zombie until reaped; it must at least be dead.
    let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    assert!(
        state.is_empty() || state.contains(") Z "),
        "client still running: {state}"
    );
    assert!(!base.join("sbx-1").exists() && !base.join("sbx-2").exists());
}

#[test]
fn only_this_nodes_state_directories_identify_a_client() {
    let key = "0123456789abcdef";
    let argv = |args: &[&str]| args.join("\0").into_bytes();
    let state = |path: &str| argv(&["/opt/tunnel", "--state-dir", path, "daemon"]);
    assert!(runs_client_of(
        &state("/run/user/1000/wssp/tunnels/0123456789abcdef/sbx-1/client"),
        key
    ));
    // Whatever runtime directory the earlier daemon had.
    assert!(runs_client_of(
        &state("/tmp/elsewhere/wssp/tunnels/0123456789abcdef/sbx-1/client"),
        key
    ));
    for bad in [
        argv(&[
            "/opt/tunnel",
            "--state-dir",
            "/run/user/1000/wssp/tunnels/0123456789abcdef/sbx-1/client",
        ]),
        state("/run/user/1000/wssp/tunnels/fedcba9876543210/sbx-1/client"),
        state("/run/user/1000/wssp/tunnels/0123456789abcdef/../client"),
        state("/run/user/1000/wssp/tunnels/0123456789abcdef/sbx-1/client/x"),
        state("relative/wssp/tunnels/0123456789abcdef/sbx-1/client"),
        state("/x/../wssp/tunnels/0123456789abcdef/sbx-1/client"),
    ] {
        assert!(!runs_client_of(&bad, key));
    }
}

#[test]
fn a_clear_fences_every_older_apply() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    // The clear for generation 3 overtakes a delayed generation-2 apply.
    f.manager.clear(&TunnelClearV11 {
        sandbox_id: "sbx-1".into(),
        generation: 3,
    });
    f.manager
        .apply(apply("sbx-1", 2, "secretsecretsecret08", vec![3000]));
    f.manager.poll();
    assert!(
        !f.base.join("sbx-1").exists(),
        "no client for a cleared generation"
    );
    // A teardown removes the entry, not the floor.
    f.manager
        .apply(apply("sbx-1", 4, "secretsecretsecret09", vec![3000]));
    f.manager.poll();
    assert!(f.base.join("sbx-1").exists());
    f.manager.stop("sbx-1");
    f.manager.network_created("sbx-1");
    f.manager
        .apply(apply("sbx-1", 4, "secretsecretsecret10", vec![3000]));
    f.manager.poll();
    assert!(
        !f.base.join("sbx-1").exists(),
        "a repeated generation stays stale"
    );
    // Once the network and plan are gone the floor goes with them.
    f.manager.network_removed("sbx-1");
    assert!(f.manager.floors.lock().unwrap().is_empty());
    f.manager.stop_all();
}

#[test]
fn a_clear_below_the_floor_is_confirmed_and_spares_the_newer_client() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 5, "secretsecretsecret30", vec![3000]));
    f.manager.poll();
    let pid = client_pid(&f, "sbx-1");
    f.manager.drain_events();
    // The control plane re-sends an older generation's clear until it hears
    // the stop confirmed: it is confirmed, and the client applied above it
    // keeps running.
    f.manager.clear(&TunnelClearV11 {
        sandbox_id: "sbx-1".into(),
        generation: 3,
    });
    f.manager.poll();
    let events = f.manager.drain_events();
    assert!(
        events
            .iter()
            .any(|status| status.generation == 3 && status.state == TunnelStateV11::Stopped),
        "{events:?}"
    );
    assert_eq!(f.manager.entries.lock().unwrap()["sbx-1"].generation, 5);
    assert!(
        f.base.join("sbx-1").exists(),
        "the newer client keeps its state"
    );
    assert!(
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok(),
        "the newer client still runs"
    );
    assert_eq!(
        f.manager.floors.lock().unwrap()["sbx-1"],
        5,
        "the floor never drops"
    );
    // Its own generation's clear stops it and is confirmed as well.
    f.manager.clear(&TunnelClearV11 {
        sandbox_id: "sbx-1".into(),
        generation: 5,
    });
    f.manager.poll();
    let events = f.manager.drain_events();
    assert!(
        events
            .iter()
            .any(|status| status.generation == 5 && status.state == TunnelStateV11::Stopped)
    );
    assert!(!f.manager.entries.lock().unwrap().contains_key("sbx-1"));
    f.manager.stop_all();
}

#[test]
fn a_full_queue_reports_its_refusal_only_after_the_older_client_stopped() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 1, "secretsecretsecret31", vec![3000]));
    f.manager.poll();
    let pid = client_pid(&f, "sbx-1");
    f.manager.drain_events();
    // Fill the queue with other sandboxes' clears (one per sandbox).
    for i in 0..MAX_QUEUED {
        f.manager.clear(&TunnelClearV11 {
            sandbox_id: format!("fill-{i}"),
            generation: 1,
        });
    }
    f.manager
        .apply(apply("sbx-1", 2, "secretsecretsecret32", vec![3000]));
    // No report yet: a report at generation 2 would tell the control plane
    // the generation-1 client is gone while it still runs.
    assert!(
        f.manager
            .drain_events()
            .iter()
            .all(|status| status.sandbox_id != "sbx-1"),
    );
    f.manager.poll();
    assert!(
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_err(),
        "the older client was reaped"
    );
    let mine: Vec<_> = f
        .manager
        .drain_events()
        .into_iter()
        .filter(|status| status.sandbox_id == "sbx-1")
        .collect();
    assert_eq!(mine.len(), 2, "{mine:?}");
    assert_eq!(mine[0].error, Some(TunnelErrorV11::Refused));
    assert_eq!(mine[0].generation, 2);
    assert_eq!(mine[1].state, TunnelStateV11::Stopped);
    assert_eq!(mine[1].generation, 2);
    f.manager.stop_all();
}

#[test]
fn reapplying_an_ended_client_needs_a_free_slot() {
    let f = fixture(false);
    for id in ["sbx-1", "sbx-2", "sbx-3"] {
        f.runtime
            .set_tunnel_target(id, "10.9.8.2".parse().unwrap(), vec![3000]);
    }
    // sbx-1 ends (gone); sbx-2 and sbx-3 then take both slots.
    f.manager
        .apply(apply("sbx-1", 1, "exitthreeexitthree01", vec![3000]));
    wait_for(&f, |seen| {
        seen.iter()
            .any(|status| status.error == Some(TunnelErrorV11::TunnelGone))
    });
    f.manager
        .apply(apply("sbx-2", 1, "secretsecretsecret11", vec![3000]));
    f.manager
        .apply(apply("sbx-3", 1, "secretsecretsecret12", vec![3000]));
    f.manager.poll();
    f.manager.drain_events();
    f.manager
        .apply(apply("sbx-1", 2, "secretsecretsecret13", vec![3000]));
    f.manager.poll();
    let events = f.manager.drain_events();
    assert!(events.iter().any(|status| status.sandbox_id == "sbx-1"
        && status.generation == 2
        && status.error == Some(TunnelErrorV11::Refused)));
    // A live client's replacement needs no extra slot.
    f.manager
        .apply(apply("sbx-2", 2, "secretsecretsecret14", vec![3000]));
    f.manager.poll();
    let events = f.manager.drain_events();
    assert!(events.iter().any(|status| status.sandbox_id == "sbx-2"
        && status.generation == 2
        && status.state == TunnelStateV11::Connecting));
    f.manager.stop_all();
}

#[test]
fn only_a_held_sandbox_and_another_users_only_with_consent() {
    let f = fixture(false);
    for id in ["foreign-1", "gone-1"] {
        f.runtime
            .set_tunnel_target(id, "10.9.8.2".parse().unwrap(), vec![3000]);
        f.manager
            .apply(apply(id, 1, "secretsecretsecret15", vec![3000]));
    }
    f.manager.poll();
    let events = f.manager.drain_events();
    for id in ["foreign-1", "gone-1"] {
        assert!(
            events
                .iter()
                .any(|status| status.sandbox_id == id
                    && status.error == Some(TunnelErrorV11::Refused))
        );
        assert!(!f.base.join(id).exists());
    }
}

#[test]
fn a_refused_generation_stops_the_older_client() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 1, "secretsecretsecret16", vec![3000]));
    f.manager.poll();
    let pid = client_pid(&f, "sbx-1");
    f.manager
        .apply(apply("sbx-1", 2, "secretsecretsecret17", vec![4000]));
    f.manager.poll();
    assert!(!f.base.join("sbx-1").exists());
    let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    assert!(state.is_empty(), "older client reaped: {state}");
}

#[test]
fn a_clear_for_a_sandbox_not_on_the_host_still_fences_its_return() {
    let f = fixture(false);
    // Evicted: no lease row, no network. Clear 10 arrives meanwhile.
    f.absent.lock().unwrap().insert("sbx-9".into());
    f.manager.clear(&TunnelClearV11 {
        sandbox_id: "sbx-9".into(),
        generation: 10,
    });
    f.manager.poll();
    f.manager.poll();
    // Restored onto this host (a new bridge, a live lease): a delayed older
    // apply still starts nothing; a newer one does.
    f.absent.lock().unwrap().remove("sbx-9");
    f.manager.network_created("sbx-9");
    f.runtime
        .set_tunnel_target("sbx-9", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-9", 9, "secretsecretsecret18", vec![3000]));
    f.manager.poll();
    assert!(
        !f.base.join("sbx-9").exists(),
        "a cleared generation started"
    );
    f.manager
        .apply(apply("sbx-9", 11, "secretsecretsecret24", vec![3000]));
    f.manager.poll();
    assert!(f.base.join("sbx-9").exists());
    f.manager.stop_all();
}

#[test]
fn a_clear_fences_even_while_the_plan_cannot_be_read() {
    let f = fixture(false);
    // No readable target yet (e.g. an Incus query failing): still fenced.
    f.manager.clear(&TunnelClearV11 {
        sandbox_id: "sbx-1".into(),
        generation: 10,
    });
    f.manager.poll();
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 9, "secretsecretsecret23", vec![3000]));
    f.manager.poll();
    assert!(!f.base.join("sbx-1").exists());
}

#[test]
fn connected_only_when_every_port_is_declared() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 1, "pendingpendingpending1", vec![3000]));
    for _ in 0..10 {
        f.manager.poll();
        std::thread::sleep(Duration::from_millis(50));
    }
    let events = f.manager.drain_events();
    assert!(
        events
            .iter()
            .any(|status| status.state == TunnelStateV11::Connecting)
    );
    assert!(
        events
            .iter()
            .all(|status| status.state != TunnelStateV11::Connected)
    );
    f.manager.stop_all();
}

#[test]
fn coalescing_keeps_every_fence() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    // A delayed lower clear must not erase a newer one, nor a stale apply
    // replace a newer apply.
    f.manager.clear(&TunnelClearV11 {
        sandbox_id: "sbx-1".into(),
        generation: 10,
    });
    f.manager.clear(&TunnelClearV11 {
        sandbox_id: "sbx-1".into(),
        generation: 9,
    });
    f.manager
        .apply(apply("sbx-1", 10, "secretsecretsecret19", vec![3000]));
    f.manager.poll();
    assert!(
        !f.base.join("sbx-1").exists(),
        "cleared generation 10 resurrected"
    );
    f.manager
        .apply(apply("sbx-1", 12, "secretsecretsecret20", vec![3000]));
    f.manager
        .apply(apply("sbx-1", 11, "secretsecretsecret21", vec![3000]));
    f.manager.poll();
    assert_eq!(f.manager.entries.lock().unwrap()["sbx-1"].generation, 12);
    f.manager.stop_all();
}

#[test]
fn a_lapsed_lease_stops_the_client_for_good() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 1, "secretsecretsecret22", vec![3000]));
    f.manager.poll();
    let pid = client_pid(&f, "sbx-1");
    f.lapsed.lock().unwrap().insert("sbx-1".into());
    let events = wait_for(&f, |seen| {
        seen.iter()
            .any(|status| status.state == TunnelStateV11::Stopped)
    });
    assert!(events.iter().all(|status| status.generation == 1));
    assert!(!f.base.join("sbx-1").exists());
    let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    assert!(state.is_empty(), "client reaped: {state}");
    f.manager.poll();
    assert!(f.manager.entries.lock().unwrap()["sbx-1"].child.is_none());
}

#[test]
fn an_expose_error_reply_is_retried_not_trusted() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000]);
    f.manager
        .apply(apply("sbx-1", 1, "experrexperrexperr01", vec![3000]));
    for _ in 0..10 {
        f.manager.poll();
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !f.base
            .join("sbx-1")
            .join("client")
            .join("ports.json")
            .exists()
    );
    assert!(
        f.manager
            .drain_events()
            .iter()
            .all(|status| status.state != TunnelStateV11::Connected)
    );
    f.manager.stop_all();
}

#[test]
fn a_port_change_stops_only_a_client_forwarding_an_undeclared_port() {
    let f = fixture(false);
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![3000, 4000]);
    f.manager
        .apply(apply("sbx-1", 1, "secretsecretsecret16", vec![3000, 4000]));
    f.manager.poll();
    let pid = client_pid(&f, "sbx-1");
    // An add (every forwarded port is still allowed): the client keeps running.
    f.manager.restrict("sbx-1", &[3000, 4000]);
    assert!(f.base.join("sbx-1").exists());
    // A removal of a forwarded port: stopped and reaped before the ACL changes.
    f.manager.restrict("sbx-1", &[4000]);
    assert!(!f.base.join("sbx-1").exists());
    let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    assert!(state.is_empty(), "client reaped: {state}");
    let events = f.manager.drain_events();
    assert!(
        events
            .iter()
            .any(|status| status.generation == 1 && status.state == TunnelStateV11::Stopped)
    );
    // A restart never forwards a port the plan no longer declares.
    f.runtime
        .set_tunnel_target("sbx-1", "10.9.8.2".parse().unwrap(), vec![4000]);
    f.manager
        .apply(apply("sbx-1", 2, "secretsecretsecret17", vec![3000]));
    f.manager.poll();
    assert!(!f.base.join("sbx-1").exists(), "undeclared port refused");
    f.manager.stop_all();
}
