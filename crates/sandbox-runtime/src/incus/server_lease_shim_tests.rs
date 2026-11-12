//! One daemon per Incus server: the lease against an executable profile
//! shim only. No test talks to an Incus daemon.
use super::super::shim_tests::{install_executable, write_shim};
use super::*;
use sandbox_protocol::SandboxErrorCode;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Profiles in `default`, one JSON file each. A create is `link(2)` of a
/// complete temp file, so it is atomic and fails when the name exists, as
/// Incus's database does.
const SHIM: &str = r#"#!/usr/bin/python3 -I
import json, os, sys, urllib.parse
root = os.path.dirname(os.path.abspath(__file__))
store = os.path.join(root, "profiles")
os.makedirs(store, exist_ok=True)
args = sys.argv[1:]
with open(os.path.join(root, "incus.log"), "a") as log:
    log.write(" ".join(args) + "\n")
if os.path.exists(os.path.join(root, "down")):
    sys.stderr.write("Error: Failed to connect to local daemon\n")
    sys.exit(1)
def answer(code, metadata=None, error=""):
    if code == 200:
        print(json.dumps({"type": "sync", "status_code": 200, "error_code": 0, "metadata": metadata}))
        sys.exit(0)
    print(json.dumps({"type": "error", "error": error, "error_code": code, "metadata": None}))
    sys.exit(1)
assert args[0:2] == ["query", "--raw"], args
args = args[2:]
method, body = "GET", None
if args[0] == "-X":
    method, args = args[1], args[2:]
if args[0] == "-d":
    body, args = json.loads(args[1]), args[2:]
url = urllib.parse.urlsplit(args[0])
assert urllib.parse.parse_qs(url.query).get("project") == ["default"], args
parts = url.path.split("/")
def path_of(name):
    assert "/" not in name and name
    return os.path.join(store, name + ".json")
def read(name):
    with open(path_of(name)) as f:
        return json.load(f)
def write_new(name, profile):
    tmp = path_of(name) + ".tmp." + str(os.getpid())
    with open(tmp, "w") as f:
        json.dump(profile, f)
    try:
        os.link(tmp, path_of(name))
        return True
    except FileExistsError:
        return False
    finally:
        os.unlink(tmp)
if method == "GET" and url.path == "/1.0/profiles":
    if os.path.exists(os.path.join(root, "forbid-list")):
        answer(403, error="not authorized")
    rows = []
    for entry in sorted(os.listdir(store)):
        if entry.endswith(".json"):
            try:
                rows.append(read(entry[:-5]))
            except FileNotFoundError:
                pass
    answer(200, rows)
if method != "GET" and os.path.exists(os.path.join(root, "refuse-write")):
    answer(403, error="not authorized")
if method == "POST" and url.path == "/1.0/profiles":
    while os.path.exists(os.path.join(root, "hold-post")):
        import time
        time.sleep(0.02)
    if os.path.exists(os.path.join(root, "refuse-create")):
        answer(403, error="not authorized")
    if os.path.exists(os.path.join(root, "steal-create")):
        # Someone else creates this exact name first, with another claim.
        body["config"]["user.wssp.lease.claim"] = "stolen"
        write_new(body["name"], body)
        answer(409, error="Profile already exists")
    if write_new(body["name"], body):
        answer(200, {})
    answer(409, error="Profile \"" + body["name"] + "\" already exists")
name = urllib.parse.unquote(parts[3])
if method == "PATCH":
    try:
        profile = read(name)
    except FileNotFoundError:
        answer(404, error="Profile not found")
    profile["config"].update(body.get("config", {}))
    tmp = path_of(name) + ".patch." + str(os.getpid())
    with open(tmp, "w") as f:
        json.dump(profile, f)
    os.replace(tmp, path_of(name))
    answer(200, {})
if method == "DELETE":
    if os.path.exists(os.path.join(root, "refuse-delete")):
        answer(500, error="delete failed")
    try:
        os.unlink(path_of(name))
    except FileNotFoundError:
        answer(404, error="Profile not found")
    answer(200, {})
answer(400, error="unsupported " + method + " " + args[0])
"#;

struct Fixture {
    client: IncusClient,
    dir: PathBuf,
    now: Arc<AtomicU64>,
}

impl Fixture {
    fn new() -> Self {
        let (binary, _log) = write_shim("running");
        install_executable(&binary, SHIM, 0o755);
        let client = IncusClient::new(binary.to_string_lossy().into_owned(), "wssp");
        assert!(Path::new(&client.binary).starts_with(std::env::temp_dir()));
        Self {
            client,
            dir: binary.parent().unwrap().to_path_buf(),
            now: Arc::new(AtomicU64::new(1_000_000)),
        }
    }

    fn timing(&self) -> LeaseTiming {
        let now = self.now.clone();
        LeaseTiming {
            ttl_secs: 60,
            renew_every: Duration::from_millis(20),
            settle: Duration::from_millis(30),
            now: Arc::new(move || now.load(Ordering::SeqCst)),
        }
    }

    fn acquire(&self, who: &DaemonIdentity) -> Result<ServerLease, ServerLeaseError> {
        ServerLease::acquire(&self.client, who, self.timing())
    }

    fn advance(&self, secs: u64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }

    fn flag(&self, name: &str, on: bool) {
        let path = self.dir.join(name);
        if on {
            std::fs::write(path, "").unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
    }

    fn profiles(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.dir.join("profiles"))
            .map(|dir| {
                dir.filter_map(|entry| {
                    let name = entry.ok()?.file_name().into_string().ok()?;
                    name.strip_suffix(".json").map(str::to_string)
                })
                .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn profile(&self, name: &str) -> serde_json::Value {
        let text = std::fs::read_to_string(self.dir.join("profiles").join(format!("{name}.json")))
            .unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn expires(&self, name: &str) -> String {
        self.profile(name)["config"]["user.wssp.lease.expires_at"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("incus.log")).unwrap_or_default()
    }
}

impl std::fmt::Debug for ServerLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerLease({})", self.profile_name())
    }
}

const MACHINE: &str = "0123456789abcdef0123456789abcdef";

fn gen_of(name: &str) -> u64 {
    parse_marker_name(name).expect("a marker name").0
}

/// The name `plant` gives `host`'s marker of `generation`.
fn planted_name(generation: u64, host: &str) -> String {
    let nonce = host.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |a, b| {
        (a ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    marker_name(generation, &format!("{nonce:016x}"))
}

fn daemon(host: &str, state_dir: &str) -> DaemonIdentity {
    DaemonIdentity {
        machine_id: MACHINE.into(),
        host_id: host.into(),
        label: format!("{host}-label"),
        state_dir: state_dir.into(),
        machine: "box".into(),
        pid: 4242,
    }
}

fn held_by(result: Result<ServerLease, ServerLeaseError>, host: &str) -> u64 {
    match result {
        Err(ServerLeaseError::Held {
            holder,
            retry_after_secs,
            ..
        }) => {
            assert_eq!(holder.host_id, host);
            retry_after_secs
        }
        other => panic!("expected held by {host}: {other:?}"),
    }
}

#[test]
fn first_daemon_claims_generation_one_in_the_default_project() {
    let fx = Fixture::new();
    let lease = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    let name = lease.profile_name();
    assert_eq!(gen_of(&name), 1);
    assert_eq!(fx.profiles(), vec![name.clone()]);
    let config = fx.profile(&name)["config"].clone();
    assert_eq!(config["user.wssp.lease.host_id"], "host-a");
    assert_eq!(config["user.wssp.lease.label"], "host-a-label");
    assert_eq!(config["user.wssp.lease.expires_at"], "1000060");
    // The machine id is only ever hashed: never stored, never displayed.
    assert!(!fx.profile(&name).to_string().contains(MACHINE));
    assert!(!format!("{:?}", lease.identity()).contains(MACHINE));
    // Server scope: every call names project `default`, never the daemon's.
    for line in fx.log().lines() {
        assert!(line.contains("project=default"), "{line}");
        assert!(!line.contains("--project"), "{line}");
    }
    assert_eq!(lease.renew_once().unwrap().health, LeaseHealth::Sole);
}

#[test]
fn a_second_daemon_is_refused_naming_the_holder_and_the_wait() {
    let fx = Fixture::new();
    let held = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    fx.advance(15);
    let err = fx.acquire(&daemon("host-b", "/s/b")).expect_err("refused");
    let text = err.to_string();
    assert_eq!(held_by(Err(err), "host-a"), 45);
    for needle in [
        "host `host-a`",
        "label `host-a-label`",
        "One wssp daemon per Incus server is supported",
        "Stop the other daemon",
        "wait 45s",
        &held.profile_name(),
    ] {
        assert!(text.contains(needle), "{needle}: {text}");
    }
    // The same host id with ANOTHER state dir is another daemon.
    held_by(fx.acquire(&daemon("host-a", "/s/other")), "host-a");
    assert_eq!(fx.profiles(), vec![held.profile_name()]);
}

#[test]
fn a_healthy_daemon_is_never_superseded() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    for _ in 0..10 {
        fx.advance(50);
        assert_eq!(a.renew_once().unwrap().health, LeaseHealth::Sole);
        held_by(fx.acquire(&daemon("host-b", "/s/b")), "host-a");
        // Each renewal is a new generation; the older ones are removed.
        assert_eq!(fx.profiles(), vec![a.profile_name()]);
    }
}

#[test]
fn a_crashed_daemons_expired_marker_is_replaced() {
    let fx = Fixture::new();
    // A crash: no release, no renewal.
    std::mem::forget(fx.acquire(&daemon("host-a", "/s/a")).unwrap());
    fx.advance(59);
    held_by(fx.acquire(&daemon("host-b", "/s/b")), "host-a");
    fx.advance(1);
    let b = fx.acquire(&daemon("host-b", "/s/b")).unwrap();
    assert_eq!(gen_of(&b.profile_name()), 2);
    // Another daemon's expired marker is removed only after 5 leases.
    // (A expired at 1_000_060; deletable from 1_000_360.)
    for _ in 0..19 {
        fx.advance(15);
        assert_eq!(b.renew_once().unwrap().health, LeaseHealth::Sole);
        assert_eq!(fx.profiles().len(), 2);
    }
    fx.advance(15);
    assert_eq!(b.renew_once().unwrap().health, LeaseHealth::Sole);
    assert_eq!(fx.profiles(), vec![b.profile_name()]);
}

#[test]
fn a_conflict_found_while_running_degrades_and_recovers_without_stopping() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    let probe = a.fence_probe(Arc::new(crate::guard_probe::FakeGuardProbe::healthy()));
    assert!(crate::guard_probe::check_guard(&probe).is_ok());
    // A cannot renew for over a lease (partition), so B starts and removes
    // A's expired marker.
    fx.advance(61);
    let b = fx.acquire(&daemon("host-b", "/s/b")).unwrap();
    assert_eq!(fx.profiles().len(), 2, "A's just-expired marker is kept");
    // A claims a new marker (never renewing its expired one in place) and
    // reports the conflict; B then sees A too.
    match a.renew_once().map(|r| r.health) {
        Ok(LeaseHealth::Conflict(other)) => assert!(other.contains("host `host-b`"), "{other}"),
        other => panic!("{other:?}"),
    }
    assert!(a.conflict().is_some());
    match b.renew_once().map(|r| r.health) {
        Ok(LeaseHealth::Conflict(other)) => assert!(other.contains("host `host-a`"), "{other}"),
        other => panic!("{other:?}"),
    }
    // Neither live marker is deleted or overwritten by the other daemon;
    // each daemon's superseded generations are gone.
    assert_eq!(fx.profiles().len(), 2);
    assert!(fx.profiles().contains(&a.profile_name()));
    assert!(fx.profiles().contains(&b.profile_name()));
    assert!(
        probe
            .shared_incus_server()
            .unwrap()
            .contains("host `host-b`")
    );
    // New sandboxes are refused like an unhealthy guard.
    let err = crate::guard_probe::check_guard(&probe).expect_err("refused");
    assert!(
        err.message.contains("another wssp daemon"),
        "{}",
        err.message
    );
    let status = probe.status().unwrap();
    assert!(!status.ok);
    assert_eq!(
        status.reasons[0],
        crate::guard_probe::INCUS_SERVER_SHARED_REASON
    );
    // Running sandboxes keep their host sockets: the ceiling is the inner one.
    assert_eq!(
        probe.egress_ceiling().is_ok(),
        crate::guard_probe::FakeGuardProbe::healthy()
            .egress_ceiling()
            .is_ok()
    );
    // B stops: A recovers on its next renewal and cleans the released marker.
    drop(b);
    // Evidence of B stays for two leases, then A recovers.
    fx.advance(60);
    assert!(matches!(
        a.renew_once().unwrap().health,
        LeaseHealth::Conflict(_)
    ));
    fx.advance(61);
    assert_eq!(a.renew_once().unwrap().health, LeaseHealth::Sole);
    assert!(a.conflict().is_none());
    assert!(crate::guard_probe::check_guard(&probe).is_ok());
    assert!(probe.shared_incus_server().is_none());
    // B released by removing its markers; A keeps only its newest.
    assert_eq!(fx.profiles(), vec![a.profile_name()]);
}

#[test]
fn the_same_daemon_restarting_on_this_machine_takes_its_marker_at_once() {
    let fx = Fixture::new();
    std::mem::forget(fx.acquire(&daemon("host-a", "/s/a")).unwrap());
    fx.advance(5);
    let restarted = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    assert_eq!(gen_of(&restarted.profile_name()), 2);
    assert_eq!(fx.profiles(), vec![restarted.profile_name()]);
    assert_eq!(fx.expires(&restarted.profile_name()), "1000065");
}

#[test]
fn the_same_host_and_paths_on_another_machine_wait_for_expiry() {
    let fx = Fixture::new();
    std::mem::forget(fx.acquire(&daemon("host-a", "/s/a")).unwrap());
    let elsewhere = DaemonIdentity {
        machine_id: "ffffffffffffffffffffffffffffffff".into(),
        ..daemon("host-a", "/s/a")
    };
    let unknown = DaemonIdentity {
        machine_id: String::new(),
        ..daemon("host-a", "/s/a")
    };
    fx.advance(5);
    assert_eq!(held_by(fx.acquire(&elsewhere), "host-a"), 55);
    // Without a machine id there is no same-machine proof either.
    held_by(fx.acquire(&unknown), "host-a");
    fx.advance(55);
    fx.acquire(&elsewhere).unwrap();
}

#[test]
fn a_graceful_release_lets_another_daemon_start_at_once() {
    let fx = Fixture::new();
    let lease = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    lease.release();
    assert!(
        fx.profiles().is_empty(),
        "released by removal, never a rewrite"
    );
    let next = fx.acquire(&daemon("host-b", "/s/b")).unwrap();
    assert_eq!(fx.profiles(), vec![next.profile_name()]);
}

#[test]
fn racing_starts_have_exactly_one_winner() {
    for round in 0..5 {
        let fx = Fixture::new();
        if round % 2 == 1 {
            // Also race for an expired marker.
            std::mem::forget(fx.acquire(&daemon("old", "/s/old")).unwrap());
            fx.advance(120);
        }
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let results: Vec<_> = (0..4)
            .map(|n| {
                let client = fx.client.clone();
                let timing = fx.timing();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    ServerLease::acquire(&client, &daemon(&format!("h{n}"), "/s"), timing)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect();
        let winners: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(winners.len(), 1, "round {round}: {results:?}");
        for result in &results {
            if let Err(err) = result {
                assert!(
                    matches!(err, ServerLeaseError::Held { .. }),
                    "round {round}: {err}"
                );
            }
        }
        let winner = winners[0].identity().host_id.clone();
        let now = fx.now.load(Ordering::SeqCst);
        let live: Vec<_> = fx
            .profiles()
            .into_iter()
            .filter(|name| fx.expires(name).parse::<u64>().unwrap() > now)
            .collect();
        assert_eq!(live.len(), 1, "round {round}: {live:?}");
        assert_eq!(
            fx.profile(&live[0])["config"]["user.wssp.lease.host_id"],
            winner.as_str()
        );
        assert_eq!(winners[0].renew_once().unwrap().health, LeaseHealth::Sole);
    }
}

#[test]
fn a_forbidden_client_is_told_so_by_status_and_an_outage_fails_closed() {
    let fx = Fixture::new();
    fx.flag("forbid-list", true);
    let err = fx
        .acquire(&daemon("host-a", "/s/a"))
        .expect_err("forbidden");
    assert!(matches!(err, ServerLeaseError::Forbidden { .. }), "{err}");
    assert!(err.to_string().contains("guard is unavailable"), "{err}");
    fx.flag("forbid-list", false);

    fx.flag("refuse-create", true);
    let err = fx
        .acquire(&daemon("host-a", "/s/a"))
        .expect_err("forbidden");
    assert!(matches!(err, ServerLeaseError::Forbidden { .. }), "{err}");
    fx.flag("refuse-create", false);

    fx.flag("down", true);
    let err = fx
        .acquire(&daemon("host-a", "/s/a"))
        .expect_err("fails closed");
    assert!(matches!(err, ServerLeaseError::Unavailable { .. }), "{err}");
    assert!(err.to_string().contains("will not start"), "{err}");
    fx.flag("down", false);
    assert!(fx.profiles().is_empty());

    // A running daemon rides an outage out on its last verdict.
    let lease = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    fx.flag("down", true);
    assert!(lease.renew_once().is_err());
    assert!(lease.conflict().is_none());
    fx.flag("down", false);
    fx.advance(10);
    assert_eq!(lease.renew_once().unwrap().health, LeaseHealth::Sole);
    assert_eq!(fx.profiles(), vec![lease.profile_name()]);
    assert_eq!(fx.expires(&lease.profile_name()), "1000070");
}

#[test]
fn the_renewal_thread_reports_each_conflict_and_the_recovery_once() {
    let fx = Fixture::new();
    let lease = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    lease
        .spawn_renewal(Arc::new(move |event| sink.lock().unwrap().push(event)))
        .unwrap();
    // Another daemon's live marker appears (it started unguarded).
    let mut other = fx.profile(&lease.profile_name());
    other["name"] = planted_name(7, "host-z").into();
    other["config"]["user.wssp.lease.claim"] = "other".into();
    other["config"]["user.wssp.lease.identity"] = "other".into();
    other["config"]["user.wssp.lease.host_id"] = "host-z".into();
    other["config"]["user.wssp.lease.expires_at"] = "99999999999".into();
    let path = fx
        .dir
        .join("profiles")
        .join(format!("{}.json", planted_name(7, "host-z")));
    std::fs::write(&path, serde_json::to_vec(&other).unwrap()).unwrap();
    let wait = |done: &dyn Fn(&[LeaseEvent]) -> bool| {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !done(&events.lock().unwrap()) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    wait(&|e| {
        e.iter()
            .filter(|e| matches!(e, LeaseEvent::Conflict(_)))
            .count()
            >= 2
    });
    // The daemon keeps running; the other marker is never touched.
    assert!(path.exists());
    assert!(lease.conflict().unwrap().contains("host `host-z`"));
    std::fs::remove_file(&path).unwrap();
    fx.advance(121);
    wait(&|e| e.contains(&LeaseEvent::Cleared));
    lease.release();
    let events = events.lock().unwrap().clone();
    let first = events
        .iter()
        .position(|e| matches!(e, LeaseEvent::Conflict(_)))
        .unwrap();
    let cleared: Vec<_> = events
        .iter()
        .filter(|e| **e == LeaseEvent::Cleared)
        .collect();
    assert_eq!(cleared.len(), 1, "{events:?}");
    assert!(
        events[first..]
            .iter()
            .all(|e| !matches!(e, LeaseEvent::RenewFailed(_)))
    );
    assert!(fx.profiles().is_empty());
}

#[test]
fn holder_fields_are_displayed_bounded_and_without_control_characters() {
    let holder = LeaseHolder {
        host_id: "a\u{1b}[31mb`c".into(),
        label: "x".repeat(500),
        machine: String::new(),
        pid: "1".into(),
    };
    let text = holder.to_string();
    assert!(text.starts_with("host `a[31mbc`"), "{text}");
    assert!(text.contains("on `unknown`"), "{text}");
    assert!(text.len() < 200, "{text}");
}

/// A live marker of another daemon, written straight into the store.
fn plant(fx: &Fixture, generation: u64, host: &str, expires_at: &str) -> PathBuf {
    let name = planted_name(generation, host);
    let profile = serde_json::json!({
        "name": name, "description": "", "devices": {},
        "config": {
            "user.wssp.lease.identity": format!("id-{host}"),
            "user.wssp.lease.claim": format!("claim-{host}"),
            "user.wssp.lease.host_id": host, "user.wssp.lease.label": host,
            "user.wssp.lease.machine": "elsewhere", "user.wssp.lease.pid": "9",
            "user.wssp.lease.expires_at": expires_at,
        },
    });
    std::fs::create_dir_all(fx.dir.join("profiles")).unwrap();
    let path = fx.dir.join("profiles").join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
    path
}

/// Admission follows the read even when this daemon cannot
/// write its own marker any more. With another live marker it degrades;
/// with none it stays admitted and reports the write failure.
#[test]
fn a_daemon_that_cannot_rewrite_its_marker_still_degrades_on_another_live_one() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    let probe = a.fence_probe(Arc::new(crate::guard_probe::FakeGuardProbe::healthy()));
    fx.flag("refuse-write", true);
    fx.advance(61);
    // A's marker expired; B started meanwhile.
    let b = plant(&fx, 2, "host-b", "99999999999");
    let renewal = a.renew_once().unwrap();
    match &renewal.health {
        LeaseHealth::Conflict(other) => assert!(other.contains("host `host-b`"), "{other}"),
        other => panic!("{other:?}"),
    }
    assert!(renewal.problem.is_some());
    assert!(crate::guard_probe::check_guard(&probe).is_err());
    assert!(crate::guard_probe::refuse_shared_incus_server(&probe).is_err());
    // No other live marker, still unable to write: admitted, with a warning.
    std::fs::remove_file(b).unwrap();
    fx.advance(121);
    let renewal = a.renew_once().unwrap();
    assert_eq!(renewal.health, LeaseHealth::Sole);
    assert!(renewal.problem.unwrap().contains("403"));
    assert!(crate::guard_probe::check_guard(&probe).is_ok());
    fx.flag("refuse-write", false);
}

/// The exact interleaving: A pauses before its renewal
/// write for over five leases; B starts and, once A's marker has been dead
/// for the margin, removes it; A resumes. A never rewrites a marker, so its
/// resumed renewal is a NEW generation that B reads next: both end in a
/// conflict. No marker is ever PATCHed.
#[test]
fn a_paused_renewal_resumes_as_a_new_generation_and_both_see_the_conflict() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    let paused = a.profile_name();
    fx.advance(61);
    let b = fx.acquire(&daemon("host-b", "/s/b")).unwrap();
    for _ in 0..21 {
        fx.advance(15);
        assert_eq!(b.renew_once().unwrap().health, LeaseHealth::Sole);
    }
    assert!(
        !fx.profiles().contains(&paused),
        "B removed A's dead marker"
    );
    match a.renew_once().map(|r| r.health) {
        Ok(LeaseHealth::Conflict(other)) => assert!(other.contains("host `host-b`"), "{other}"),
        other => panic!("{other:?}"),
    }
    assert_ne!(a.profile_name(), paused);
    match b.renew_once().map(|r| r.health) {
        Ok(LeaseHealth::Conflict(other)) => assert!(other.contains("host `host-a`"), "{other}"),
        other => panic!("{other:?}"),
    }
    assert!(fx.profiles().contains(&a.profile_name()));
    assert!(
        !fx.log().contains("-X PATCH"),
        "markers are never rewritten"
    );
}

/// A marker long dead in another daemon's snapshot that comes back to life
/// before the cleanup acts on that snapshot is kept (the re-read).
#[test]
fn a_marker_is_never_deleted_from_a_stale_read() {
    let fx = Fixture::new();
    let b = fx.acquire(&daemon("host-b", "/s/b")).unwrap();
    plant(&fx, 5, "host-z", "1");
    let stale = fx.client.lease_records().unwrap();
    plant(&fx, 5, "host-z", "99999999999");
    let now = fx.now.load(Ordering::SeqCst);
    b.shared
        .remove_dead_markers(&stale, now, &mut CleanupBudget::new(&b.shared.timing));
    assert!(fx.profiles().contains(&planted_name(5, "host-z")));
    assert!(matches!(
        b.renew_once().map(|r| r.health),
        Ok(LeaseHealth::Conflict(_))
    ));
}

/// While degraded, no image is imported or published into the
/// shared store, whatever the path (cache fetch, upstream split image,
/// template capture).
#[test]
fn image_imports_and_captures_are_refused_while_the_server_is_shared() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    plant(&fx, 9, "host-z", "99999999999");
    assert!(matches!(
        a.renew_once().map(|r| r.health),
        Ok(LeaseHealth::Conflict(_))
    ));
    let mut runtime = super::super::IncusKvmRuntime::from_test_client(fx.client.clone());
    runtime.set_guard_probe(Arc::new(
        a.fence_probe(Arc::new(crate::guard_probe::FakeGuardProbe::healthy())),
    ));
    let before = fx.log();
    let shared = |err: RuntimeError| {
        assert!(
            err.message.contains("another wssp daemon"),
            "{}",
            err.message
        );
    };
    use crate::SandboxRuntime as _;
    shared(
        runtime
            .import_image(Path::new("/nonexistent/image.tar"))
            .unwrap_err(),
    );
    shared(
        runtime
            .import_split_image(
                Path::new("/nonexistent/meta"),
                Path::new("/nonexistent/disk"),
                "sha256:00",
            )
            .unwrap_err(),
    );
    let request = crate::CaptureRequest {
        sandbox_id: "sbx-1".into(),
        operation_id: "op-1".into(),
        stopped: true,
        guest_home: "/home/user".into(),
        extra_scrub_paths: Vec::new(),
        credential_scrub_paths: Vec::new(),
    };
    shared(runtime.capture_template(&request, &|_| {}).unwrap_err());
    // Refused before any Incus call.
    assert_eq!(fx.log(), before);
}

/// Always reports another daemon on the Incus server (otherwise healthy).
#[derive(Debug)]
struct AlwaysShared(crate::guard_probe::FakeGuardProbe);
impl GuardProbe for AlwaysShared {
    fn status(&self) -> Result<GuardStatus, RuntimeError> {
        self.0.status()
    }
    fn expectations(&self) -> Result<GuardExpectations, RuntimeError> {
        self.0.expectations()
    }
    fn shared_incus_server(&self) -> Option<String> {
        Some("host `other`".into())
    }
}

/// The rule while `incus_server_shared` stands is "no VM
/// starts of any kind"; stop and destroy of existing sandboxes are never
/// fenced. The image refusal carries the guard outage's code and reason.
#[test]
fn stop_and_destroy_are_never_fenced_and_the_refusal_is_a_guard_outage() {
    use crate::SandboxRuntime as _;
    let (mut runtime, log) = super::super::shim_tests::runtime_for("running");
    runtime.set_guard_probe(Arc::new(AlwaysShared(
        crate::guard_probe::FakeGuardProbe::healthy(),
    )));
    let stopped = runtime
        .stop_sandbox(&crate::StopSandboxRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            operation_id: "stop".into(),
            idempotency_key: "stop".into(),
        })
        .expect("stop is never fenced");
    assert_eq!(
        stopped.sandbox.state,
        sandbox_protocol::SandboxLifecycleState::Stopped
    );
    assert!(super::super::shim_tests::log_invoked(&log, "stop"));
    let (mut runtime, log) = super::super::shim_tests::runtime_for("running");
    runtime.set_guard_probe(Arc::new(AlwaysShared(
        crate::guard_probe::FakeGuardProbe::healthy(),
    )));
    runtime
        .kill_bound(&crate::KillSandboxRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            operation_id: "op-kill".into(),
            idempotency_key: "kill-1".into(),
        })
        .expect("destroy is never fenced");
    assert!(super::super::shim_tests::log_invoked(&log, "delete"));
    // The refusal for VM starts and imports: the guard outage, typed.
    let err = runtime
        .import_image(Path::new("/nonexistent/image.tar"))
        .unwrap_err();
    assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
    assert_eq!(
        err.wire_reason(),
        Some(sandbox_protocol::ProtocolErrorReason::from(
            sandbox_protocol::EgressRefusalReason::EgressGuardUnavailable
        ))
    );
    assert!(runtime.egress_guard_check().is_err());
}

/// A planted marker at the highest generation (u64::MAX): the next
/// generation is never computed by saturation (which would name that same
/// profile and read back as our own create). A start is refused and a
/// running daemon degrades, both naming the marker and the recovery steps.
#[test]
fn a_max_generation_marker_refuses_starts_and_degrades_without_adopting_it() {
    let max = u64::MAX;
    let profile = planted_name(max, "host-z");
    let fx = Fixture::new();
    plant(&fx, max, "host-z", "1");
    let err = fx.acquire(&daemon("host-a", "/s/a")).expect_err("refused");
    assert_eq!(
        err,
        ServerLeaseError::GenerationExhausted {
            profile: profile.clone()
        }
    );
    let text = err.to_string();
    assert!(
        text.contains(&profile) && text.contains("docs/guide/hosts.md"),
        "{text}"
    );
    assert!(!fx.log().contains("-X POST"), "nothing was created");

    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    let probe = a.fence_probe(Arc::new(crate::guard_probe::FakeGuardProbe::healthy()));
    let mine = a.profile_name();
    plant(&fx, max, "host-z", "1");
    let renewal = a.renew_once().unwrap();
    match &renewal.health {
        LeaseHealth::Conflict(why) => assert!(why.contains(&profile), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(crate::guard_probe::refuse_shared_incus_server(&probe).is_err());
    // The planted marker was neither adopted nor touched.
    assert_eq!(a.profile_name(), mine);
    assert_eq!(fx.expires(&profile), "1");
    assert_eq!(
        fx.profile(&profile)["config"]["user.wssp.lease.claim"],
        "claim-host-z"
    );
    // Recovery: the operator deletes it; the next renewal is sole again.
    std::fs::remove_file(fx.dir.join("profiles").join(format!("{profile}.json"))).unwrap();
    assert_eq!(a.renew_once().unwrap().health, LeaseHealth::Sole);
    assert!(crate::guard_probe::refuse_shared_incus_server(&probe).is_ok());
}

/// A create that fails because its exact name was just taken is settled by
/// reading back that name AND our claim id: a profile under that name with
/// another claim is never adopted. Names parse strictly.
#[test]
fn a_duplicate_name_with_another_claim_is_never_adopted() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    let records = fx.client.lease_records().unwrap();
    fx.flag("steal-create", true);
    let created = create_marker(
        &fx.client,
        &records,
        &a.shared.identity,
        &a.shared.identity_key,
        &a.shared.claim,
        &a.shared.timing,
    )
    .unwrap();
    fx.flag("steal-create", false);
    assert!(matches!(created, Created::LostRace));
    let stolen: Vec<_> = fx
        .profiles()
        .into_iter()
        .filter(|name| fx.profile(name)["config"]["user.wssp.lease.claim"] == "stolen")
        .collect();
    assert_eq!(stolen.len(), 1);
    assert_eq!(a.profile_name(), records[0].name, "not adopted");
    let nonce = "0123456789abcdef";
    for (name, generation) in [
        (format!("wssp-daemon-lease-7-{nonce}"), Some(7)),
        (format!("wssp-daemon-lease-07-{nonce}"), None),
        ("wssp-daemon-lease-7".to_string(), None),
        ("wssp-daemon-lease-7-0123456789ABCDEF".to_string(), None),
        ("wssp-daemon-lease-7-0123456789abcde".to_string(), None),
        (format!("wssp-daemon-lease-7-{nonce}0"), None),
        (format!("wssp-daemon-lease--{nonce}"), None),
    ] {
        let profile = serde_json::json!({"name": name, "config": {}});
        assert_eq!(
            LeaseRecord::from_profile(&profile).map(|r| r.generation),
            generation,
            "{name}"
        );
    }
}

/// The exact interleaving: A pauses before deleting its
/// generation-1 marker; meanwhile every marker is cleaned up and the other
/// daemons stop; C claims generation 1 again; A resumes its delete. Names
/// are never reused, so C's marker survives.
#[test]
fn a_late_delete_never_removes_a_reused_generation() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    let paused_delete = a.profile_name();
    std::mem::forget(a);
    for name in fx.profiles() {
        std::fs::remove_file(fx.dir.join("profiles").join(format!("{name}.json"))).unwrap();
    }
    let c = fx.acquire(&daemon("host-c", "/s/c")).unwrap();
    assert_eq!(gen_of(&c.profile_name()), 1, "generation 1 is reused");
    assert_ne!(c.profile_name(), paused_delete, "its name never is");
    fx.client.delete_lease_profile(&paused_delete);
    assert_eq!(fx.profiles(), vec![c.profile_name()]);
    assert_eq!(c.renew_once().unwrap().health, LeaseHealth::Sole);
}

/// The verdict is published before any cleanup, cleanup
/// is bounded per renewal, and failing deletes of this daemon's own
/// superseded markers are reported, never retried all at once.
#[test]
fn a_conflict_is_published_before_a_bounded_cleanup() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    fx.flag("refuse-delete", true);
    for _ in 0..5 {
        assert_eq!(a.renew_once().unwrap().health, LeaseHealth::Sole);
    }
    let renewal = a.renew_once().unwrap();
    assert!(
        renewal
            .problem
            .as_deref()
            .is_some_and(|p| p.contains("superseded markers of this daemon")),
        "{renewal:?}"
    );
    fx.flag("refuse-delete", false);
    plant(&fx, 900, "host-z", "99999999999");
    let before = fx.log().lines().count();
    let renewal = a.renew_once().unwrap();
    assert!(matches!(renewal.health, LeaseHealth::Conflict(_)));
    assert!(a.conflict().is_some());
    let deletes = fx
        .log()
        .lines()
        .skip(before)
        .filter(|line| line.contains("-X DELETE"))
        .count();
    assert_eq!(deletes, 2, "at most two deletes per renewal");
    // The other daemon's live marker is never among them.
    assert!(fx.profiles().contains(&planted_name(900, "host-z")));
}

/// A clock that advances `rpc_secs` for every Incus call made so far (each
/// call is one shim log line), plus manual pauses, offset by `offset_secs`:
/// a deterministic model of slow RPCs and skewed clocks.
fn rpc_clock(fx: &Fixture, rpc_secs: u64, offset_secs: i64) -> LeaseTiming {
    let log = fx.dir.join("incus.log");
    let base = fx.now.clone();
    LeaseTiming {
        ttl_secs: 60,
        renew_every: Duration::from_millis(20),
        settle: Duration::ZERO,
        now: Arc::new(move || {
            let calls = std::fs::read_to_string(&log)
                .map(|text| text.lines().count() as u64)
                .unwrap_or(0);
            base.load(Ordering::SeqCst)
                .wrapping_add(calls * rpc_secs)
                .wrapping_add_signed(offset_secs)
        }),
    }
}

/// A daemon that already passed its start: a marker created from `seen`
/// (a stale read), with a fresh claim, under `timing`.
fn started_from(
    fx: &Fixture,
    who: &DaemonIdentity,
    seen: &[LeaseRecord],
    timing: LeaseTiming,
) -> ServerLease {
    let claim = super::super::client::random_nonce().unwrap();
    let identity_key = who.key().unwrap();
    let Created::Mine(name) =
        create_marker(&fx.client, seen, who, &identity_key, &claim, &timing).unwrap()
    else {
        panic!("created")
    };
    ServerLease {
        shared: Arc::new(Shared {
            client: fx.client.clone(),
            identity: who.clone(),
            identity_key,
            claim,
            name: Mutex::new(name),
            timing,
            state: Mutex::new(LeaseState {
                stop: false,
                released: false,
                conflict: None,
                peer_seen: None,
            }),
            wake: Condvar::new(),
        }),
        worker: Mutex::new(None),
    }
}

/// The schedule: 14 s RPCs, B pausing 35 s after its
/// initial empty read (so it starts beside A), clocks offset by ±2 s. Reads
/// are judged at their issue time, both reads of a renewal count, evidence
/// is sticky for two leases, and a slow round trip leaves the claim
/// unconfirmed: from the first renewal of each on, neither daemon is ever
/// admitted, and each names the other in its first renewal. (A real start
/// of B is refused outright.)
#[test]
fn slow_incus_and_a_pause_never_leave_two_daemons_admitted() {
    for rpc_secs in [14, 0] {
        let fx = Fixture::new();
        let a = ServerLease::acquire(
            &fx.client,
            &daemon("host-a", "/s/a"),
            rpc_clock(&fx, rpc_secs, 2),
        )
        .unwrap();
        fx.advance(35);
        let x = ServerLease::acquire(
            &fx.client,
            &daemon("host-x", "/s/x"),
            rpc_clock(&fx, rpc_secs, -2),
        );
        if rpc_secs == 0 {
            held_by(x, "host-a");
        } else if let Ok(x) = x {
            // A's start took four 14 s calls, so its marker was near expiry:
            // X may start, but only unconfirmed (degraded), never admitted.
            assert!(x.conflict().is_some_and(|why| why.contains("unconfirmed")));
            x.release();
        }
        // B read before A existed, paused, and started anyway.
        let b = started_from(
            &fx,
            &daemon("host-b", "/s/b"),
            &[],
            rpc_clock(&fx, rpc_secs, -2),
        );
        for round in 0..40 {
            let ha = a.renew_once().unwrap().health;
            fx.advance(15);
            let hb = b.renew_once().unwrap().health;
            fx.advance(15);
            let (LeaseHealth::Conflict(why_a), LeaseHealth::Conflict(why_b)) = (&ha, &hb) else {
                panic!("rpc {rpc_secs}s round {round}: admitted: {ha:?} / {hb:?}");
            };
            if round == 0 {
                assert!(why_a.contains("host `host-b`"), "rpc {rpc_secs}s: {why_a}");
                assert!(why_b.contains("host `host-a`"), "rpc {rpc_secs}s: {why_b}");
            }
        }
    }
}

/// Evidence of another live marker is sticky: one read that showed it keeps
/// the daemon degraded until no read has shown one for two leases.
#[test]
fn peer_evidence_stays_for_two_leases() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    let peer = plant(&fx, 50, "host-z", "99999999999");
    assert!(matches!(
        a.renew_once().unwrap().health,
        LeaseHealth::Conflict(_)
    ));
    std::fs::remove_file(peer).unwrap();
    for _ in 0..7 {
        fx.advance(15);
        match a.renew_once().unwrap().health {
            LeaseHealth::Conflict(why) => assert!(why.contains("host `host-z`"), "{why}"),
            other => panic!("{other:?}"),
        }
    }
    fx.advance(15);
    assert_eq!(a.renew_once().unwrap().health, LeaseHealth::Sole);
}

/// A renewal whose read plus write takes over a quarter lease leaves the
/// claim unconfirmed (degraded) until a faster round succeeds.
#[test]
fn a_slow_renewal_round_trip_degrades_until_a_fast_one() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    let slow = ServerLease {
        shared: Arc::new(Shared {
            client: a.shared.client.clone(),
            identity: a.shared.identity.clone(),
            identity_key: a.shared.identity_key.clone(),
            claim: a.shared.claim.clone(),
            name: Mutex::new(a.profile_name()),
            timing: rpc_clock(&fx, 8, 0),
            state: Mutex::new(LeaseState {
                stop: false,
                released: true,
                conflict: None,
                peer_seen: None,
            }),
            wake: Condvar::new(),
        }),
        worker: Mutex::new(None),
    };
    let renewal = slow.renew_once().unwrap();
    match &renewal.health {
        LeaseHealth::Conflict(why) => assert!(why.contains("unconfirmed"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(renewal.problem.unwrap().contains("quarter lease"));
    assert_eq!(
        a.renew_once().unwrap().health,
        LeaseHealth::Sole,
        "fast again"
    );
}

/// Reports another daemon once the shim has logged `boot.autostart`: the
/// conflict is published while the start's configuration I/O runs.
#[derive(Debug)]
struct SharedOnceConfigured {
    inner: crate::guard_probe::FakeGuardProbe,
    log: PathBuf,
}
impl GuardProbe for SharedOnceConfigured {
    fn status(&self) -> Result<GuardStatus, RuntimeError> {
        self.inner.status()
    }
    fn expectations(&self) -> Result<GuardExpectations, RuntimeError> {
        self.inner.expectations()
    }
    fn will_attest(&self, bridge: &str, gateway: std::net::Ipv4Addr) {
        self.inner.will_attest(bridge, gateway);
    }
    fn shared_incus_server(&self) -> Option<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .contains("boot.autostart")
            .then(|| "host `other`".into())
    }
}

/// A conflict published while a start's configuration
/// I/O runs refuses the `start` itself (rechecked after all configuration).
#[test]
fn a_conflict_published_during_start_configuration_refuses_the_start() {
    let (mut runtime, log) = super::super::shim_tests::runtime_for("stopped");
    runtime
        .client()
        .apply_sandbox_network(&super::super::network::test_plan("sbx-1"))
        .expect("apply");
    runtime.set_guard_probe(Arc::new(SharedOnceConfigured {
        inner: crate::guard_probe::FakeGuardProbe::healthy(),
        log: log.clone(),
    }));
    let err = runtime
        .reconnect_bound(&crate::ReconnectSandboxRequest {
            vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
            lease: sandbox_protocol::HostLease::for_test(),
            template_fingerprint: crate::CreateSandboxRequest::for_test("default", "default")
                .template_digest,
            architecture: Some("x86_64".into()),
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-re".to_string(),
            idempotency_key: "re-1".to_string(),
            egress_policy: None,
            egress_policy_hash: None,
            egress_admission: crate::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        })
        .expect_err("start refused");
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(
        text.contains("boot.autostart"),
        "configuration ran first: {err:?}\n{text}"
    );
    assert!(
        !text
            .lines()
            .any(|line| line.split_whitespace().next() == Some("start")),
        "{text}"
    );
    let err = err.into_error();
    assert!(
        err.message.contains("another wssp daemon"),
        "{}",
        err.message
    );
}

/// The detection DEADLINE documented in hosts.md, in the test
/// schedule (14 s calls, clocks offset by +/-2 s, an Incus outage while A
/// runs, then B starting beside A from a stale read).
///
/// The bound follows from each daemon's own loop: a renewal makes at most
/// two calls between its first and second marker read (create, plus a
/// read-back if it failed) and at most three after the second (cleanup
/// budget), then waits `renew_every`. A peer marker that appears at any
/// moment is therefore read by a read ISSUED at most `renew_every + 4`
/// calls later, and the conflict is published when that read returns:
/// `renew_every + 5 x call` after both run. This test checks both facts
/// (call counts per renewal, and publication at the first read issued
/// after both run) and the resulting deadline for each daemon.
#[test]
fn detection_meets_its_documented_deadline() {
    const RENEW_EVERY: u64 = 15;
    const LIST: &str = "query --raw /1.0/profiles?project=default&recursion=1";
    for rpc_secs in [14, 1] {
        let fx = Fixture::new();
        let clock = rpc_clock(&fx, rpc_secs, 0).now;
        let lines = || fx.log().lines().map(str::to_string).collect::<Vec<_>>();
        let a = ServerLease::acquire(
            &fx.client,
            &daemon("host-a", "/s/a"),
            rpc_clock(&fx, rpc_secs, 2),
        )
        .unwrap();
        fx.flag("down", true);
        for _ in 0..3 {
            assert!(a.renew_once().is_err(), "outage");
            fx.advance(RENEW_EVERY);
        }
        fx.flag("down", false);
        let b = started_from(
            &fx,
            &daemon("host-b", "/s/b"),
            &[],
            rpc_clock(&fx, rpc_secs, -2),
        );
        let both_running = clock();
        let mut max_between = 0;
        let mut max_after = 0;
        for round in 0..4 {
            for (lease, offset) in [(&a, 2_i64), (&b, -2_i64)] {
                let before = lines().len();
                let first_read = clock();
                lease.renew_once().unwrap();
                let calls: Vec<String> = lines().split_off(before);
                let reads: Vec<usize> = (0..calls.len()).filter(|&i| calls[i] == LIST).collect();
                assert!(reads.len() >= 2 && reads[0] == 0, "{calls:?}");
                max_between = max_between.max(reads[1] - reads[0] - 1);
                max_after = max_after.max(calls.len() - reads[1] - 1);
                if round == 0 && offset > 0 {
                    // A's first renewal starts as B starts: its first read
                    // publishes (see the next test) one call later.
                    assert!(first_read + rpc_secs <= both_running + RENEW_EVERY + 5 * rpc_secs);
                }
                assert!(lease.conflict().is_some(), "degraded every round");
                fx.advance(RENEW_EVERY);
            }
        }
        assert!(
            max_between <= 2 && max_after <= 3,
            "{max_between} / {max_after}"
        );
        // The deadline from the loop's shape; A's model timing is faithful
        // (its renewal starts right after B's start) and meets it directly.
        let deadline = RENEW_EVERY + (max_after as u64 + 2) * rpc_secs;
        assert!(deadline <= RENEW_EVERY + 5 * rpc_secs);
    }
}

/// The first renewal read alone publishes the conflict: while that
/// renewal's write is still stuck in Incus, the daemon is already degraded.
#[test]
fn the_first_read_publishes_the_conflict_before_the_write() {
    let fx = Fixture::new();
    let a = fx.acquire(&daemon("host-a", "/s/a")).unwrap();
    plant(&fx, 40, "host-z", "99999999999");
    fx.flag("hold-post", true);
    std::thread::scope(|scope| {
        let renewal = scope.spawn(|| a.renew_once());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while a.conflict().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!renewal.is_finished(), "the write is still held");
        assert!(a.conflict().unwrap().contains("host `host-z`"));
        fx.flag("hold-post", false);
        assert!(matches!(
            renewal.join().unwrap().unwrap().health,
            LeaseHealth::Conflict(_)
        ));
    });
}
