//! The guard's quarantine state machine against a fake host.
//! No root, no nft, no links touched.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;

#[derive(Debug, Clone)]
struct Link {
    name: &'static str,
    ifindex: u64,
    master: Option<&'static str>,
    kind: &'static str,
    up: bool,
}

#[derive(Debug, Default)]
struct Host {
    /// The installed `inet wssp_guard` table.
    table: Option<GuardInputs>,
    applies: Vec<GuardInputs>,
    links: Vec<Link>,
    uplink_clsact: bool,
    snapshot_fails: bool,
    conntrack_missing: bool,
    conntrack_delete_fails: bool,
    deletes: usize,
    /// Conntrack entries from the sandbox subnets.
    entries: usize,
    /// The delete exits 1 on an operational error (indistinguishable from
    /// "nothing matched"): reported as success, nothing removed.
    delete_silently_fails: bool,
    /// The filtered readback (`conntrack -L`) itself fails.
    readback_fails: bool,
    /// Per delete: whether any sandbox link was still up when it ran.
    sandbox_up_at_delete: Vec<bool>,
    /// Links that ignore `ip link set … down` (fence readback must catch it).
    stuck_up: Vec<&'static str>,
    /// Extra `nft -j list ruleset` items (a host firewall).
    ruleset: Vec<Value>,
}

#[derive(Clone, Default)]
struct FakeOps(Arc<Mutex<Host>>);

impl FakeOps {
    fn host(&self) -> std::sync::MutexGuard<'_, Host> {
        self.0.lock().unwrap()
    }

    fn link_up(&self, name: &str) -> bool {
        self.host()
            .links
            .iter()
            .find(|l| l.name == name)
            .unwrap()
            .up
    }

    fn set_up(&self, name: &str, up: bool) {
        let mut host = self.host();
        host.links.iter_mut().find(|l| l.name == name).unwrap().up = up;
    }

    fn live(&self) -> Vec<String> {
        self.host()
            .table
            .as_ref()
            .map(|t| t.live_bridges.clone())
            .unwrap_or_default()
    }

    fn link_listing(host: &Host) -> Value {
        Value::Array(
            host.links
                .iter()
                .map(|l| {
                    let mut entry = json!({
                        "ifindex": l.ifindex,
                        "ifname": l.name,
                        "flags": if l.up { json!(["BROADCAST", "UP"]) } else { json!(["BROADCAST"]) },
                        "linkinfo": {"info_kind": l.kind},
                    });
                    if let Some(master) = l.master {
                        entry["master"] = json!(master);
                    }
                    entry
                })
                .collect(),
        )
    }
}

fn addresses() -> Value {
    json!([
        {"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24}]},
        {"ifname":"wsn-a","addr_info":[{"family":"inet","local":"10.250.1.1","prefixlen":24}]},
        {"ifname":"wsn-b","addr_info":[{"family":"inet","local":"10.250.2.1","prefixlen":24}]},
        {"ifname":"wsn-c","addr_info":[{"family":"inet","local":"10.250.3.1","prefixlen":24}]}
    ])
}

impl Ops for FakeOps {
    fn snapshot(&self) -> Result<Snapshot> {
        let host = self.host();
        if host.snapshot_fails {
            bail!("`ip -j route` printed malformed JSON");
        }
        Ok(Snapshot {
            routes: json!([
                {"dst":"default","gateway":"192.0.2.1","dev":"eth0","flags":[]},
                {"dst":"192.0.2.0/24","dev":"eth0","flags":[]},
                {"dst":"10.250.1.0/24","dev":"wsn-a","flags":[]},
                {"dst":"10.250.2.0/24","dev":"wsn-b","flags":[]},
                {"dst":"203.0.114.0/24","dev":"eth0","flags":[]},
                {"type":"local","dst":"45.33.0.7","dev":"eth0","table":"local","flags":[]}
            ]),
            links: Self::link_listing(&host),
            addresses: addresses(),
            ruleset: json!({"nftables": host.ruleset.clone()}),
            qdiscs: if host.uplink_clsact {
                json!([{"kind":"clsact","handle":"ffff:","dev":"eth0","parent":"ffff:fff1"}])
            } else {
                json!([])
            },
        })
    }

    fn apply(&self, inputs: &GuardInputs, _live_timeout_secs: u64) -> Result<()> {
        let mut host = self.host();
        host.table = Some(inputs.clone());
        host.applies.push(inputs.clone());
        Ok(())
    }

    fn readback(&self, inputs: &GuardInputs) -> Result<()> {
        if self.host().table.as_ref() == Some(inputs) {
            Ok(())
        } else {
            bail!("readback mismatch")
        }
    }

    fn conntrack_probe(&self) -> Result<()> {
        if self.host().conntrack_missing {
            bail!(CONNTRACK_UNAVAILABLE);
        }
        Ok(())
    }

    fn conntrack_delete(&self, subnets: &[Ipv4Net]) -> Result<()> {
        let mut host = self.host();
        assert!(
            !subnets.is_empty(),
            "the cleanup scope is the sandbox subnets"
        );
        if host.conntrack_missing {
            bail!(CONNTRACK_UNAVAILABLE);
        }
        if host.conntrack_delete_fails {
            bail!("conntrack delete failed: Operation not permitted");
        }
        host.deletes += 1;
        let up = host
            .links
            .iter()
            .any(|l| l.up && (l.name.starts_with("wsn-") || l.master.is_some()));
        host.sandbox_up_at_delete.push(up);
        if !host.delete_silently_fails {
            host.entries = 0;
        }
        Ok(())
    }

    fn conntrack_remaining(&self, subnets: &[Ipv4Net]) -> Result<usize> {
        let host = self.host();
        assert!(!subnets.is_empty());
        if host.readback_fails {
            bail!("conntrack readback failed: Operation not permitted");
        }
        Ok(host.entries)
    }

    fn addresses(&self) -> Result<Value> {
        Ok(addresses())
    }

    fn links(&self) -> Result<Value> {
        Ok(Self::link_listing(&self.host()))
    }

    fn set_link(&self, name: &str, up: bool) -> Result<()> {
        let mut host = self.host();
        let stuck = host.stuck_up.contains(&name);
        let link = host
            .links
            .iter_mut()
            .find(|l| l.name == name)
            .ok_or_else(|| anyhow::anyhow!("no link `{name}`"))?;
        if !(stuck && !up) {
            link.up = up;
        }
        Ok(())
    }
}

/// eth0 uplink; wsn-a with a VM tap, wsn-b with a VM tap, wsn-c an
/// administratively down bridge (the guard must never bring it up).
fn host() -> FakeOps {
    let ops = FakeOps::default();
    ops.host().links = vec![
        Link {
            name: "eth0",
            ifindex: 2,
            master: None,
            kind: "",
            up: true,
        },
        Link {
            name: "wsn-a",
            ifindex: 10,
            master: None,
            kind: "bridge",
            up: true,
        },
        Link {
            name: "tapa",
            ifindex: 11,
            master: Some("wsn-a"),
            kind: "tun",
            up: true,
        },
        Link {
            name: "wsn-b",
            ifindex: 20,
            master: None,
            kind: "bridge",
            up: true,
        },
        Link {
            name: "tapb",
            ifindex: 21,
            master: Some("wsn-b"),
            kind: "tun",
            up: true,
        },
        Link {
            name: "wsn-c",
            ifindex: 30,
            master: None,
            kind: "bridge",
            up: false,
        },
    ];
    ops
}

/// Every well-formed bridge is live, whatever its admin state (the guard's
/// table does not care; the fence is a separate, recorded cut).
const LIVE: [&str; 3] = ["wsn-a", "wsn-b", "wsn-c"];

struct Rig {
    _dir: tempfile::TempDir,
    paths: Paths,
    daemon: Daemon,
}

fn rig_with(ops: &FakeOps, deployment: Option<PolicyContent>, prepare: impl FnOnce(&Paths)) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    std::fs::create_dir_all(paths.state_dir()).unwrap();
    prepare(&paths);
    let (tx, _rx) = mpsc::channel();
    // The root file under a temp dir is not root-owned (refused): the
    // persisted root snapshot stays enforced, which is all these tests need.
    let root = Source::starting(Some(PolicyContent::default()));
    let shared = Arc::new(initial_shared(
        &root,
        placeholder_status("i", "b"),
        paths.clone(),
        Source::starting(deployment),
        tx,
    ));
    let daemon = Daemon::new(shared, Box::new(ops.clone()), "i".into(), "b".into(), root);
    Rig {
        _dir: dir,
        paths,
        daemon,
    }
}

fn rig(ops: &FakeOps) -> Rig {
    rig_with(ops, Some(PolicyContent::default()), |_| {})
}

fn status(rig: &Rig) -> GuardStatus {
    lock(&rig.daemon.shared.published).status.clone()
}

fn all_sandbox_links_down(ops: &FakeOps) -> bool {
    ["wsn-a", "tapa", "wsn-b", "tapb", "wsn-c"]
        .iter()
        .all(|name| !ops.link_up(name))
}

#[test]
fn a_healthy_node_forwards_and_touches_no_link() {
    let ops = host();
    let mut rig = rig(&ops);
    rig.daemon.resync(true);
    assert_eq!(ops.live(), LIVE);
    let status = status(&rig);
    assert_eq!(status.quarantined, None, "{:?}", status.reasons);
    assert!(status.lease_until_boottime_ns > 0);
    assert!(ops.link_up("tapa") && ops.link_up("wsn-b"));
    assert_eq!(ops.host().deletes, 0);
}

/// The credential proxy's egress ceiling is published only from a healthy
/// pass, with the status of that same publication, and covers the drop
/// sets plus the node's own addresses; a quarantine withdraws it.
#[test]
fn the_egress_ceiling_is_published_only_while_healthy() {
    let ops = host();
    let mut rig = rig(&ops);
    let ceiling = |rig: &Rig| match rig.daemon.shared.handle(Request::Ceiling {}) {
        Reply::Ceiling { status, ceiling } => (status.ok, ceiling),
        other => panic!("{other:?}"),
    };
    assert_eq!(ceiling(&rig), (false, None), "nothing before a pass");
    rig.daemon.resync(true);
    let (ok, published) = ceiling(&rig);
    assert!(ok);
    let published = published.expect("a healthy pass publishes the ceiling");
    // A node address and a routed public prefix (neither is protected).
    for refused in ["45.33.0.7", "203.0.114.9", "10.250.1.9", "127.0.0.1"] {
        assert!(published.refuses(refused.parse().unwrap()), "{refused}");
    }
    assert!(!published.refuses("1.1.1.1".parse().unwrap()));

    ops.host().snapshot_fails = true;
    rig.daemon.resync(true);
    assert_eq!(ceiling(&rig), (false, None), "a quarantine withdraws it");
}

/// E1-A-01: a ufw-style drop policy with no `wsn+` allow is reported as
/// unhealthy (no new sandboxes) with the chain, but never quarantines or
/// fences: running sandboxes keep their links and the table stays live.
#[test]
fn a_host_firewall_that_drops_bridge_traffic_is_unhealthy_but_not_quarantined() {
    let ops = host();
    ops.host().ruleset = vec![
        json!({"chain":{"family":"ip","table":"filter","name":"INPUT","hook":"input","prio":0,"type":"filter","policy":"drop"}}),
    ];
    let mut rig = rig(&ops);
    rig.daemon.resync(true);
    let blocked = status(&rig);
    assert_eq!(blocked.quarantined, None, "{:?}", blocked.reasons);
    assert!(!blocked.ok);
    assert!(
        blocked
            .reasons
            .contains(&"host_firewall_blocks_sandboxes:ip/filter/INPUT".to_string()),
        "{:?}",
        blocked.reasons
    );
    assert_eq!(ops.live(), LIVE);
    assert!(ops.link_up("tapa") && ops.link_up("wsn-b"));

    // `sudo ufw allow in on wsn+`: healthy on the next pass.
    ops.host().ruleset.push(
        json!({"rule":{"family":"ip","table":"filter","chain":"ufw-user-input","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wsn*"}},{"accept":null}
        ]}}),
    );
    rig.daemon.resync(true);
    let fixed = status(&rig);
    assert!(fixed.ok, "{:?}", fixed.reasons);
    assert!(
        !fixed.reasons.iter().any(|r| r.starts_with("host_firewall")),
        "{:?}",
        fixed.reasons
    );
}

/// P1-1: a tc redirect on the uplink bypasses the guard's table, so the
/// quarantine takes every sandbox bridge and port down (read back), keeps
/// them down while the finding persists, and restores exactly those links
/// once a current classification is healthy again.
#[test]
fn packet_path_quarantine_fences_sandbox_links_until_the_path_is_healthy() {
    let ops = host();
    let mut rig = rig(&ops);
    rig.daemon.resync(true);

    ops.host().uplink_clsact = true;
    rig.daemon.resync(false);
    let quarantined = status(&rig);
    assert_eq!(
        quarantined.quarantined.as_deref(),
        Some("unsupported_packet_path:tc_clsact:eth0")
    );
    assert!(ops.live().is_empty(), "the table cut is applied as well");
    assert!(all_sandbox_links_down(&ops), "{:?}", ops.host().links);
    assert!(ops.link_up("eth0"), "the uplink is never fenced");
    assert!(
        quarantined.reasons.iter().any(|r| r == "fenced_links:4"),
        "{:?}",
        quarantined.reasons
    );
    assert_eq!(quarantined.lease_until_boottime_ns, 0);
    assert!(rig.paths.fenced().exists(), "recorded before going down");
    assert_eq!(ops.host().deletes, 1, "the cleanup ran under the cut");

    // Something (Incus) brings a port back up while the finding persists:
    // the next pass fences it again.
    ops.set_up("tapa", true);
    rig.daemon.resync(false);
    assert!(all_sandbox_links_down(&ops));

    // A link that will not go down: the fence is not verified.
    ops.set_up("tapb", true);
    ops.host().stuck_up = vec!["tapb"];
    rig.daemon.resync(false);
    assert!(
        status(&rig).reasons.iter().any(|r| r == "fence_unverified"),
        "{:?}",
        status(&rig).reasons
    );
    ops.host().stuck_up.clear();

    // The path is healthy again: restored, bridges before ports, and the
    // bridge that was already down stays down.
    ops.host().uplink_clsact = false;
    rig.daemon.resync(false);
    let healthy = status(&rig);
    assert_eq!(healthy.quarantined, None, "{:?}", healthy.reasons);
    assert_eq!(ops.live(), LIVE);
    for name in ["wsn-a", "tapa", "wsn-b", "tapb"] {
        assert!(ops.link_up(name), "{name} restored");
    }
    assert!(
        !ops.link_up("wsn-c"),
        "never brought up a link it did not fence"
    );
    assert!(!rig.paths.fenced().exists());
    assert!(healthy.lease_until_boottime_ns > 0);
}

/// P1-2: the cleanup is an obligation for EVERY quarantine (here a
/// classification failure, which used to request none), retried on every
/// pass until confirmed; meanwhile the fence holds and forwarding is not
/// restored even when the node classifies healthy again.
#[test]
fn conntrack_cleanup_is_retried_until_confirmed_and_fences_meanwhile() {
    let ops = host();
    let mut rig = rig(&ops);
    rig.daemon.resync(true);

    {
        let mut host = ops.host();
        host.snapshot_fails = true;
        host.conntrack_delete_fails = true;
    }
    rig.daemon.resync(false);
    let first = status(&rig);
    assert_eq!(first.quarantined.as_deref(), Some("classification_failed"));
    assert!(
        first.reasons.iter().any(|r| r == "conntrack_delete_failed"),
        "{:?}",
        first.reasons
    );
    assert!(all_sandbox_links_down(&ops), "independent fence");

    // Same quarantine reason: still retried (it used to run only on entry).
    rig.daemon.resync(false);
    assert!(rig.daemon.cleanup_pending);

    // The node is healthy again but the cleanup is still owed.
    ops.host().snapshot_fails = false;
    rig.daemon.resync(true);
    let owed = status(&rig);
    assert!(owed.quarantined.is_some(), "{:?}", owed.reasons);
    assert!(ops.live().is_empty());
    assert!(all_sandbox_links_down(&ops));
    assert_eq!(owed.lease_until_boottime_ns, 0);

    // Confirmed: then (and only then) forwarding comes back.
    ops.host().conntrack_delete_fails = false;
    rig.daemon.resync(true);
    let healthy = status(&rig);
    assert_eq!(healthy.quarantined, None, "{:?}", healthy.reasons);
    assert_eq!(ops.host().deletes, 1);
    assert_eq!(ops.live(), LIVE);
    assert!(ops.link_up("tapa") && ops.link_up("tapb"));
    assert!(!rig.daemon.cleanup_pending);
}

/// P1-2: no traffic is admitted without the conntrack cleanup capability.
#[test]
fn the_conntrack_capability_is_required_before_admitting_traffic() {
    let ops = host();
    ops.host().conntrack_missing = true;
    let mut rig = rig(&ops);
    rig.daemon.resync(true);
    let refused = status(&rig);
    assert_eq!(
        refused.quarantined.as_deref(),
        Some("conntrack_unavailable")
    );
    assert!(ops.live().is_empty());
    assert_eq!(refused.lease_until_boottime_ns, 0);
    assert!(all_sandbox_links_down(&ops), "no cleanup possible: fenced");

    ops.host().conntrack_missing = false;
    rig.daemon.resync(true);
    assert_eq!(status(&rig).quarantined, None);
    assert_eq!(ops.live(), LIVE);
}

/// P1-3: a source with no usable snapshot is unknown content, never an
/// empty deny set; the guard quarantines until the source is known.
#[test]
fn a_source_without_a_usable_snapshot_quarantines() {
    let ops = host();
    let mut rig = rig_with(&ops, None, |_| {});
    rig.daemon.resync(true);
    assert_eq!(
        status(&rig).quarantined.as_deref(),
        Some("source_unusable:deployment")
    );
    assert!(ops.live().is_empty());
    assert!(ops.host().applies.iter().all(|t| t.live_bridges.is_empty()));

    // The daemon's explicit push makes it known.
    lock(&rig.daemon.shared.deployment).accept(PolicyContent::default(), false);
    rig.daemon.resync(true);
    assert_eq!(status(&rig).quarantined, None);
    assert_eq!(ops.live(), LIVE);
}

/// P1-4: a restart never replays a historical healthy table. The kernel
/// table the previous (quarantined) instance left stays in place, and no
/// table with live bridges is installed before a CURRENT healthy
/// classification.
#[test]
fn a_restart_never_replays_a_historical_healthy_table() {
    let ops = host();
    // What the previous instance applied last: its quarantine table.
    let quarantine_table = GuardInputs {
        protected4: protected4().unwrap().to_vec(),
        ..GuardInputs::default()
    };
    ops.host().table = Some(quarantine_table.clone());
    ops.host().snapshot_fails = true;
    let mut rig = rig_with(&ops, Some(PolicyContent::default()), |paths| {
        // An older guard's healthy-resync record, with live bridges.
        let stale = json!({
            "boot_id": "b",
            "verified_boottime_ns": 1,
            "inputs": GuardInputs {
                live_bridges: vec!["wsn-a".into(), "wsn-b".into()],
                ..quarantine_table.clone()
            },
        });
        std::fs::write(
            paths.state_dir().join("applied.json"),
            serde_json::to_vec(&stale).unwrap(),
        )
        .unwrap();
    });
    assert!(ops.host().applies.is_empty(), "start touches no table");
    assert!(!rig.paths.state_dir().join("applied.json").exists());

    rig.daemon.resync(true);
    assert_eq!(
        status(&rig).quarantined.as_deref(),
        Some("classification_failed")
    );
    assert!(
        ops.host().applies.iter().all(|t| t.live_bridges.is_empty()),
        "{:?}",
        ops.host().applies
    );
    assert!(ops.live().is_empty());

    ops.host().snapshot_fails = false;
    rig.daemon.resync(true);
    assert_eq!(ops.live(), LIVE);
}

/// P1-1/P1-4: a fence the previous instance raised survives the restart and
/// is lifted only after the new instance's own cleanup and healthy pass.
#[test]
fn a_restarted_guard_lifts_a_recorded_fence_only_after_a_healthy_pass() {
    let ops = host();
    ops.set_up("tapa", false);
    ops.set_up("wsn-a", false);
    ops.host().uplink_clsact = true;
    let record = FenceRecord {
        links: vec![
            SandboxLink {
                name: "tapa".into(),
                ifindex: 11,
                bridge: false,
                up: true,
            },
            SandboxLink {
                name: "wsn-a".into(),
                ifindex: 10,
                bridge: true,
                up: true,
            },
            // Same name, different ifindex: not ours to bring up.
            SandboxLink {
                name: "wsn-c".into(),
                ifindex: 99,
                bridge: true,
                up: true,
            },
        ],
    };
    let mut rig = rig_with(&ops, Some(PolicyContent::default()), |paths| {
        std::fs::write(paths.fenced(), serde_json::to_vec(&record).unwrap()).unwrap();
    });
    rig.daemon.resync(true);
    assert!(status(&rig).quarantined.is_some());
    assert!(!ops.link_up("tapa") && !ops.link_up("wsn-a"));

    ops.host().uplink_clsact = false;
    rig.daemon.resync(true);
    assert_eq!(status(&rig).quarantined, None, "{:?}", status(&rig).reasons);
    assert!(ops.link_up("tapa") && ops.link_up("wsn-a"));
    assert!(!ops.link_up("wsn-c"));
    assert!(ops.host().deletes >= 1);
    assert!(!rig.paths.fenced().exists());
}

/// A quarantine whose packet path is UNKNOWN (dead monitor,
/// failed classification) fences the links even when the quarantine table
/// verifies and the conntrack cleanup is confirmed: nothing established
/// that sandbox packets traverse that table. The links come back only
/// after a current healthy classification.
#[test]
fn an_unknown_packet_path_fences_even_when_table_and_cleanup_succeed() {
    let ops = host();
    let mut rig = rig(&ops);
    rig.daemon.resync(true);
    assert!(ops.link_up("tapa"));

    rig.daemon.monitor_failed = Some("nft");
    rig.daemon.resync(false);
    let dead = status(&rig);
    assert_eq!(dead.quarantined.as_deref(), Some("monitor_failed:nft"));
    assert!(ops.live().is_empty());
    assert!(!rig.daemon.cleanup_pending, "cleanup confirmed");
    assert!(all_sandbox_links_down(&ops), "{:?}", ops.host().links);
    assert!(
        dead.reasons.iter().any(|r| r == "fenced_links:4"),
        "{:?}",
        dead.reasons
    );

    // Monitors back, but classification fails: still unknown, still fenced.
    rig.daemon.monitor_failed = None;
    ops.host().snapshot_fails = true;
    ops.set_up("tapa", true);
    rig.daemon.resync(false);
    assert_eq!(
        status(&rig).quarantined.as_deref(),
        Some("classification_failed")
    );
    assert!(all_sandbox_links_down(&ops), "{:?}", ops.host().links);

    // A current healthy classification restores them.
    ops.host().snapshot_fails = false;
    rig.daemon.resync(true);
    assert_eq!(status(&rig).quarantined, None, "{:?}", status(&rig).reasons);
    for name in ["wsn-a", "tapa", "wsn-b", "tapb"] {
        assert!(ops.link_up(name), "{name} restored");
    }
}

/// When the packet path is unknown the fence goes up BEFORE
/// the cleanup runs (a bypass could otherwise recreate entries between the
/// delete and the cut).
#[test]
fn an_unknown_packet_path_fences_before_the_cleanup_runs() {
    let ops = host();
    let mut rig = rig(&ops);
    rig.daemon.resync(true);
    ops.host().snapshot_fails = true;
    ops.host().entries = 2;
    rig.daemon.resync(false);
    let host = ops.host();
    assert_eq!(host.deletes, 1);
    assert_eq!(
        host.sandbox_up_at_delete,
        vec![false],
        "every sandbox link was already down when the delete ran"
    );
}

/// A delete that reports success (conntrack's ambiguous
/// exit code 1) is not cleanup. Only a successful filtered readback of zero entries
/// confirms it; until then the obligation stays owed, the links stay
/// fenced and forwarding is not restored, even on a healthy node.
#[test]
fn a_cleanup_is_confirmed_only_by_an_empty_successful_readback() {
    let ops = host();
    let mut rig = rig(&ops);
    rig.daemon.resync(true);

    {
        let mut host = ops.host();
        host.uplink_clsact = true;
        host.entries = 3;
        host.delete_silently_fails = true;
    }
    rig.daemon.resync(false);
    let first = status(&rig);
    assert!(rig.daemon.cleanup_pending, "{:?}", first.reasons);
    assert!(
        first
            .reasons
            .iter()
            .any(|r| r == "conntrack_cleanup_unconfirmed"),
        "{:?}",
        first.reasons
    );
    assert!(all_sandbox_links_down(&ops));

    // The node classifies healthy again: the owed cleanup still holds the cut.
    ops.host().uplink_clsact = false;
    rig.daemon.resync(true);
    let owed = status(&rig);
    assert!(owed.quarantined.is_some(), "{:?}", owed.reasons);
    assert!(ops.live().is_empty());
    assert!(all_sandbox_links_down(&ops));
    assert_eq!(owed.lease_until_boottime_ns, 0);

    // The delete works but the readback fails: still unconfirmed.
    {
        let mut host = ops.host();
        host.delete_silently_fails = false;
        host.readback_fails = true;
    }
    rig.daemon.resync(true);
    assert!(rig.daemon.cleanup_pending);
    assert!(
        status(&rig)
            .reasons
            .iter()
            .any(|r| r == "conntrack_cleanup_unconfirmed"),
        "{:?}",
        status(&rig).reasons
    );
    assert!(all_sandbox_links_down(&ops));

    // A successful, empty readback confirms it: forwarding comes back.
    ops.host().readback_fails = false;
    rig.daemon.resync(true);
    let healthy = status(&rig);
    assert_eq!(healthy.quarantined, None, "{:?}", healthy.reasons);
    assert!(!rig.daemon.cleanup_pending);
    assert_eq!(ops.live(), LIVE);
    assert!(ops.link_up("tapa") && ops.link_up("tapb"));
}

#[test]
fn concurrent_pushes_publish_the_same_durable_and_in_memory_source() {
    let ops = host();
    let rig = rig(&ops);
    let shared = &rig.daemon.shared;
    let barrier = std::sync::Barrier::new(16);
    std::thread::scope(|scope| {
        for n in 1..=16 {
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                let reply = shared.handle(Request::PushDeployment {
                    configured: true,
                    entries: vec![format!("192.0.2.{n}/32")],
                });
                assert!(matches!(reply, Reply::Pushed { .. }), "{reply:?}");
            });
        }
    });
    let durable = load_source(&rig.paths.deployment_source()).unwrap();
    let accepted = lock(&shared.deployment).last_valid.clone().unwrap();
    assert_eq!(durable.digest(), accepted.digest());
    assert!(
        std::fs::read_dir(rig.paths.state_dir())
            .unwrap()
            .all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
    );
}

#[test]
fn concurrent_durable_writes_use_independent_exclusive_temp_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("published");
    let barrier = std::sync::Barrier::new(16);
    std::thread::scope(|scope| {
        for byte in 0u8..16 {
            let path = &path;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                durable_write(path, &vec![byte; 8192], 0o600).unwrap();
            });
        }
    });
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), 8192);
    assert!(bytes.iter().all(|byte| *byte == bytes[0]));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
