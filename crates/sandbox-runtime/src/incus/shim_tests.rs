//! Executable-shim tests: a fake `incus` binary, never a live VM.

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_protocol::SandboxErrorCode;

use super::client::IncusClient;
use super::exec::ExecSupervisor;
use super::kvm::{IncusConfig, IncusKvmRuntime};
use crate::r#trait::{
    CreateSandboxRequest, GuestIdentity, KillSandboxRequest, ListDirRequest, ListProcessesRequest,
    MkdirRequest, MovePathRequest, ProcessSignal, ReadFileRequest, ReconnectSandboxRequest,
    RemovePathRequest, RunCommandRequest, SandboxRuntime, SignalProcessRequest, StatPathRequest,
    StopSandboxRequest, WriteFileRequest,
};

// Exercise real binding before every typed adapter. Fault modes can reject this
// preflight; no test-only capability constructor or name-taking effect exists.
macro_rules! bound_call {
    ($client:expr, $method:ident($($args:expr),* $(,)?)) => {{
        let client = &$client;
        (|| {
            let bound = client.bind_instance("wssp-sbx-sbx-1", "sbx-1", &create_req().template_digest, None)?;
            client.$method(&bound, $($args),*)
        })()
    }};
}
fn list_request(client: &IncusClient, path: &str, depth: u32) -> ListDirRequest {
    ListDirRequest {
        template_fingerprint: create_req().template_digest,
        guest: client.guest.clone(),
        sandbox_id: "sbx-1".into(),
        instance_name: "wssp-sbx-sbx-1".into(),
        operation_id: "op-list".into(),
        idempotency_key: "list-1".into(),
        path: path.into(),
        depth,
        limit: crate::metadata::DIRECTORY_LIMIT,
        generation: 1,
        continuation: None,
    }
}

macro_rules! run_bound {
    ($supervisor:expr, $method:ident($request:expr $(, $args:expr)* $(,)?)) => {{
        let supervisor = &$supervisor;
        let request = $request;
        (|| {
            let bound = supervisor.bind(request)?;
            supervisor.$method(&bound, request $(, $args)*)
        })()
    }};
}

static SHIM_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Stable interception point for the environment transport rig.
pub(super) const PYTHON_TRANSPORT_HOOK: &str = "# WSSP_PYTHON_TRANSPORT_HOOK";

/// Owns every shim directory the current thread created and removes them when
/// the thread ends. libtest runs each test on its own thread, so the directory
/// outlives every client/runtime the test holds (including ones moved into
/// worker threads the test joins), and is removed on success AND on panic:
/// unwinding a test thread runs its thread-local destructors. This is the one
/// chokepoint: `write_shim` is the only place a shim directory is created.
struct ShimDirs(RefCell<Vec<PathBuf>>);

impl Drop for ShimDirs {
    fn drop(&mut self) {
        for dir in self.0.get_mut().drain(..) {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

thread_local! {
    static SHIM_DIRS: ShimDirs = const { ShimDirs(RefCell::new(Vec::new())) };
}

pub(super) fn write_shim(mode: &str) -> (PathBuf, PathBuf) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SHIM_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "wssp-incus-shim-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("shim dir");
    SHIM_DIRS.with(|dirs| dirs.0.borrow_mut().push(dir.clone()));
    let path = dir.join("incus");
    let log = dir.join("incus.log");
    install_executable(&path, &shim_script(mode, &log), 0o755);
    (path, log)
}

/// Set (to the scratch dir) in a test process re-run by `run_contained`.
pub(super) const CONTAINED_ENV: &str = "WSSP_CONTAINED_TEST_DIR";

/// The scratch dir when this process is a `run_contained` child.
pub(super) fn contained_dir() -> Option<PathBuf> {
    std::env::var_os(CONTAINED_ENV).map(PathBuf::from)
}

/// Re-runs exactly the test `name` (its path in this crate) in a contained
/// child process and asserts it passed. A `sh` leads a NEW process group and
/// waits for the test binary, so the child's pid differs from its group id
/// and a regression that signals "the daemon's own group" can only kill that
/// group, never the test runner; such a death fails here. The child's stdin
/// is a pipe, never /dev/null, so it can tell an inherited stdin apart.
pub(super) fn run_contained(name: &str, dir: &Path) {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Stdio;
    let exe = std::env::current_exe().expect("test binary");
    let child = Command::new("/bin/sh")
        // Not `exec`: the shell stays the group leader the child belongs to.
        .args(["-c", "\"$@\"; exit $?", "sh"])
        .arg(exe)
        .args([name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CONTAINED_ENV, dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn contained test child");
    let group = child.id();
    let output = child.wait_with_output().expect("contained test child");
    // Leftovers of a failed child (its own-group processes) die with the
    // group this test created; never the runner's group.
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{group}")])
        .stderr(Stdio::null())
        .status();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "contained {name} failed (signal {:?}): {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.signal(),
        output.status,
    );
}

/// Creates an executable script without this process ever holding a writable
/// descriptor to it. A fork on any other test thread inherits every open
/// descriptor (O_CLOEXEC only closes it at the child's exec), so writing the
/// script in-process lets a concurrent fork keep it open for writing and our
/// own exec of it fails with ETXTBSY. Only the `cp` child opens the target for
/// writing; the in-process write goes to a sibling file that is never executed.
pub(super) fn install_executable(path: &Path, contents: &str, mode: u32) {
    let mut staged = path.as_os_str().to_owned();
    staged.push(".src");
    let staged = PathBuf::from(staged);
    let instrumented = scrub_capture_script(path, contents);
    fs::write(&staged, instrumented).expect("write executable source");
    let status = Command::new("cp")
        .arg(&staged)
        .arg(path)
        .status()
        .expect("spawn cp");
    assert!(status.success(), "cp {staged:?} -> {path:?}: {status}");
    fs::remove_file(&staged).expect("remove executable source");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

#[test]
fn shim_dirs_are_removed_when_their_thread_ends_even_on_panic() {
    let ok = std::thread::spawn(|| {
        let (path, _) = write_shim("running");
        let dir = path.parent().unwrap().to_path_buf();
        assert!(dir.is_dir(), "shim dir exists while its thread runs");
        dir
    })
    .join()
    .expect("thread");
    assert!(
        !ok.exists(),
        "shim dir {ok:?} leaked after a passing thread"
    );

    let (sender, receiver) = std::sync::mpsc::channel();
    let panicked = std::thread::spawn(move || {
        let (path, _) = write_shim("running");
        sender.send(path.parent().unwrap().to_path_buf()).unwrap();
        panic!("simulated failing test");
    })
    .join();
    assert!(panicked.is_err());
    let dir = receiver.recv().expect("dir");
    assert!(
        !dir.exists(),
        "shim dir {dir:?} leaked after a panicking thread"
    );
}

/// Logical DNS lifetime clock shared with the executable shim. Work-delay
/// pins append elapsed seconds instead of sleeping when this clock is installed.
/// The append log leaves the epoch immutable and each advance is one write,
/// so cloned clients and shim processes observe the same clock.
#[derive(Debug)]
pub(super) struct DnsTestClock {
    advances: PathBuf,
    permit_now: std::sync::Arc<std::sync::Mutex<std::time::Instant>>,
}

impl super::dns::DnsClock for DnsTestClock {
    fn unix_now(&self) -> Result<u64, crate::RuntimeError> {
        let advances = fs::read_to_string(&self.advances).map_err(|err| {
            crate::RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot read the logical DNS clock: {err}"),
            )
        })?;
        Ok(1_700_000_000
            + advances
                .lines()
                .map(|line| line.parse::<u64>().expect("seconds"))
                .sum::<u64>())
    }
}

impl DnsTestClock {
    pub(super) fn install(client: &mut IncusClient) -> std::sync::Arc<Self> {
        let dir = client
            .state_dir
            .as_ref()
            .expect("fixture state dir")
            .parent()
            .unwrap();
        let clock = std::sync::Arc::new(Self {
            advances: dir.join("dns-clock-advances"),
            permit_now: std::sync::Arc::new(std::sync::Mutex::new(std::time::Instant::now())),
        });
        fs::write(&clock.advances, "").unwrap();
        client.dns_clock = clock.clone();
        clock
    }

    pub(super) fn now(&self) -> u64 {
        super::dns::DnsClock::unix_now(self).unwrap()
    }

    pub(super) fn advance(&self, seconds: u64) {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.advances)
            .unwrap();
        file.write_all(format!("{seconds}\n").as_bytes()).unwrap();
        *self.permit_now.lock().unwrap() += Duration::from_secs(seconds);
    }

    /// Give a permit the same logical advances as the DNS fixture, keeping
    /// its production Instant deadline comparison and avoiding a real wait.
    pub(super) fn permit(&self, timeout: Duration) -> crate::RuntimePermit {
        crate::RuntimePermit::with_test_clock(timeout, self.permit_now.clone())
    }
}

/// Guest terminate helper deadline under the shims (see `client_for_project`).
pub(super) const SHIM_GUEST_TERMINATE_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn client_for(mode: &str) -> IncusClient {
    client_for_project(mode, "default").0
}

/// Client plus the shim log path (the shim dir hosts the test journal).
pub(super) fn client_for_with_log(mode: &str) -> (IncusClient, PathBuf) {
    client_for_project(mode, "default")
}

fn client_for_project(mode: &str, project: &str) -> (IncusClient, PathBuf) {
    let (path, log) = write_shim(mode);
    let config = path.parent().unwrap().join("config");
    fs::create_dir_all(&config).unwrap();
    for (key, value) in [
        ("user.flycockpit.sandbox_id", "sbx-1"),
        ("user.flycockpit.create_idempotency_key", "create-1"),
        (
            "user.flycockpit.template_digest",
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        ),
        (
            "volatile.base_image",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        ),
    ] {
        fs::write(config.join(key), value).unwrap();
    }
    seed_local_nic_override(path.parent().unwrap(), mode);
    let mut client = IncusClient::new(path.to_string_lossy().into_owned(), project.to_string());
    // Deterministic subnet allocation and per-test cleanup journals.
    client.host_routes = Some(Vec::new());
    client.state_dir = Some(path.parent().unwrap().join("host-state"));
    // Model the administrator-provisioned shared lock directory.
    let lock_dir = path.parent().unwrap().join("daemon-locks");
    fs::create_dir_all(&lock_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lock_dir, fs::Permissions::from_mode(0o2770)).unwrap();
    }
    client.daemon_lock_dir_override = Some(lock_dir);
    // The shim runs the guest terminate helper against the HOST's /proc
    // (hundreds of processes, scanned by a shell loop several times per
    // TERM/KILL round), not a VM's: on a loaded 8-core host one run was
    // measured at 2.2-4.3 s of wall time, over the 2 s a VM gets. A finite
    // hang guard keeps every stop proof; the 2 s VM deadline is not what
    // these tests assert.
    client.guest_terminate_timeout_override = Some(SHIM_GUEST_TERMINATE_TIMEOUT);
    (client, log)
}

/// Pre-existing healthy C35 VMs carry a LOCAL eth0 override (recorded by
/// their init); legacy-mode fixtures model pre-C35 VMs without one. With the
/// local/expanded device split, this seeding is what distinguishes them.
fn seed_local_nic_override(statedir: &Path, mode: &str) {
    if matches!(mode, "egress_legacy_nic" | "egress_legacy_nic_stopped") {
        return;
    }
    if mode == "egress_drifted_local_nic_stopped" {
        // A C35 VM whose LOCAL eth0 drifted back to the unrestricted bridge:
        // repair must use `config device set` (the device is local), never
        // `override` (which Incus only accepts for inherited devices).
        fs::write(
            statedir.join("device-eth0"),
            "eth0,network=incusbr0,security.mac_filtering=true",
        )
        .unwrap();
        return;
    }
    let (network, _) = super::network::sandbox_network_names("sbx-1");
    fs::write(
        statedir.join("device-eth0"),
        format!(
            "eth0,network={network},security.mac_filtering=true,security.ipv4_filtering=true,security.ipv6_filtering=true,security.port_isolation=true"
        ),
    )
    .unwrap();
}

fn seed_existing_incus_project(
    shim_binary: &Path,
    name: &str,
    profiles_shared: bool,
    images_shared: bool,
) {
    let statedir = shim_binary.parent().expect("shim parent");
    let mut created = String::new();
    if statedir.join("created-projects").exists() {
        created = fs::read_to_string(statedir.join("created-projects"))
            .unwrap_or_default()
            .trim_end()
            .to_string();
        if !created.is_empty() {
            created.push('\n');
        }
    }
    created.push_str(name);
    fs::write(statedir.join("created-projects"), format!("{created}\n")).expect("seed");
    let profiles = if profiles_shared { "false" } else { "true" };
    let images = if images_shared { "false" } else { "true" };
    let body = format!(
        r#"{{"name":"{name}","config":{{"features.profiles":"{profiles}","features.images":"{images}","features.storage.volumes":"true"}}}}"#
    );
    fs::write(statedir.join(format!("project-{name}")), body).expect("project metadata");
    if profiles_shared {
        fs::write(statedir.join("shared-profiles"), "").expect("shared profiles");
    }
    if images_shared {
        fs::write(statedir.join("shared-images"), "").expect("shared images");
    }
}

fn seed_race_project_metadata(
    shim_binary: &Path,
    name: &str,
    profiles_shared: bool,
    images_shared: bool,
) {
    let statedir = shim_binary.parent().expect("shim parent");
    let profiles = if profiles_shared { "false" } else { "true" };
    let images = if images_shared { "false" } else { "true" };
    let body = format!(
        r#"{{"name":"{name}","config":{{"features.profiles":"{profiles}","features.images":"{images}","features.storage.volumes":"true"}}}}"#
    );
    fs::write(statedir.join(format!("project-{name}")), body).expect("project metadata");
}

pub(super) fn runtime_for(mode: &str) -> (IncusKvmRuntime, PathBuf) {
    runtime_for_project(mode, "default")
}

fn runtime_for_project(mode: &str, project: &str) -> (IncusKvmRuntime, PathBuf) {
    let (path, log) = write_shim(mode);
    let config = path.parent().unwrap().join("config");
    fs::create_dir_all(&config).unwrap();
    for (key, value) in [
        ("user.flycockpit.sandbox_id", "sbx-1"),
        ("user.flycockpit.create_idempotency_key", "create-1"),
        (
            "user.flycockpit.template_digest",
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        ),
        (
            "volatile.base_image",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        ),
    ] {
        fs::write(config.join(key), value).unwrap();
    }
    seed_local_nic_override(path.parent().unwrap(), mode);
    let mut runtime = IncusKvmRuntime::new(IncusConfig {
        binary: path.to_string_lossy().into_owned(),
        project: project.to_string(),
    })
    .expect("runtime");
    runtime.override_network_test_state(path.parent().unwrap().join("host-state"), Vec::new());
    // See `client_for_project`.
    runtime.client_mut().guest_terminate_timeout_override = Some(SHIM_GUEST_TERMINATE_TIMEOUT);
    (runtime, log)
}

fn log_invoked_start(log: &Path) -> bool {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .any(|line| line.split_whitespace().next() == Some("start"))
}

pub(super) fn log_invoked(log: &Path, cmd: &str) -> bool {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .any(|line| line.split_whitespace().next() == Some(cmd))
}

fn query_invocations(log: &Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.split_whitespace().next() == Some("query"))
        .map(str::to_string)
        .collect()
}

fn true_probe_invocations(log: &Path) -> usize {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            tokens.first().copied() == Some("exec")
                && tokens.windows(2).any(|pair| pair == ["--", "true"])
        })
        .count()
}

fn assert_query_contract(log: &Path, project: &str) {
    let lines = query_invocations(log);
    assert!(
        !lines.is_empty(),
        "expected query invocations for project `{project}`: {}",
        fs::read_to_string(log).unwrap_or_default()
    );
    let encoded = project.replace(' ', "%20").replace('/', "%2F");
    for line in &lines {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        assert!(
            !tokens.contains(&"--project"),
            "query must not receive --project: {line}"
        );
        assert!(tokens.contains(&"--raw"), "query must use --raw: {line}");
        let path = tokens
            .iter()
            .copied()
            .find(|token| token.starts_with('/'))
            .expect("query path");
        if path.starts_with("/1.0/projects/") {
            assert!(
                path.contains("project=default"),
                "project metadata queries must use the default project namespace: {line}"
            );
        } else {
            assert!(
                path.contains(&format!("project={project}"))
                    || path.contains(&format!("project={encoded}")),
                "query path must include configured project `{project}`: {line}"
            );
        }
    }
}

fn assert_stopped_without_start(err: impl Into<crate::EffectError>, log: &Path, family: &str) {
    let err = err.into();
    assert_eq!(
        err.code,
        SandboxErrorCode::SandboxNotRunning,
        "{family} should be sandbox_not_running"
    );
    assert!(
        !log_invoked_start(log),
        "{family} must not invoke start: {}",
        fs::read_to_string(log).unwrap_or_default()
    );
}

pub(super) fn run_req(op: &str) -> RunCommandRequest {
    RunCommandRequest {
        template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key").template_digest,
        generation: 1,
        attempt: 1,
        sandbox_id: "sbx-1".to_string(),
        instance_name: "wssp-sbx-sbx-1".to_string(),
        operation_id: op.to_string(),
        idempotency_key: format!("key-{op}"),
        argv: vec!["true".to_string()],
        script: None,
        cwd: None,
        timeout_ms: None,
        env: Vec::new(),
        stdin: None,
        guest: GuestIdentity::default(),
        build_step: None,
    }
}

pub(super) fn create_req() -> CreateSandboxRequest {
    let mut req = CreateSandboxRequest::for_test("sbx-1", "create-1");
    req.instance_name = "wssp-sbx-sbx-1".to_string();
    req
}

fn stat_req(path: &str) -> StatPathRequest {
    StatPathRequest {
        template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key").template_digest,
        guest: Default::default(),
        sandbox_id: "sbx-1".to_string(),
        instance_name: "wssp-sbx-sbx-1".to_string(),
        operation_id: "op-stat".to_string(),
        idempotency_key: "stat-1".to_string(),
        path: path.to_string(),
    }
}

fn shim_script(mode: &str, log: &Path) -> String {
    let log = log.display();
    format!(
        r#"#!/bin/sh
logfile='{log}'
statedir=$(dirname "$0")
# A controllable work duration for DNS TTL tests. Command/cancellation
# stalls keep using real sleep; only completed work advances logical time.
dns_work_delay() {{
  if [ -f "$statedir/dns-clock-advances" ]; then
    printf '%s\n' "$1" >> "$statedir/dns-clock-advances"
  else
    sleep "$1"
  fi
}}
started="$statedir/started"
ready="$statedir/ready"
statehits="$statedir/statehits"
project=""
while [ $# -gt 0 ]; do
  case "$1" in
    --project)
      if [ -z "$2" ]; then echo "Error: --project requires an argument" >&2; exit 1; fi
      project=$2
      shift 2
      ;;
    --quiet)
      shift
      ;;
    --*)
      echo "Error: unknown flag $1" >&2
      exit 1
      ;;
    *)
      break
      ;;
  esac
done
cmd=$1
shift || true
mode='{mode}'
if [ -z "$cmd" ]; then
  echo "Error: missing command" >&2
  exit 1
fi
if [ "$cmd" != "query" ] && [ -z "$project" ]; then
  echo "Error: missing --project" >&2
  exit 1
fi
# Projects without network isolation inherit the default project's networks:
# the shim records each resource's owning project and models that visibility.
cur_project=${{project:-default}}
res_project() {{
  if [ -f "$1.project" ]; then cat "$1.project"; else printf 'default'; fi
}}
project_visible() {{
  [ "$1" = "$cur_project" ] && return 0
  [ "$cur_project" != "default" ] && [ "$1" = "default" ] && return 0
  return 1
}}
# Bridged-NIC device option allowlist, grounded in the INSTALLED Incus 6.0.0
# documentation (/usr/share/doc/incus/reference/devices_nic.md, "nictype:
# bridged"): security.acls* are OVN-NIC-only options and a real supported
# host REJECTS them on a bridged NIC. The shim enforces the same contract so
# tests cannot pass with NIC options a real daemon would refuse.
validate_bridged_nic_spec() {{
  nic_spec=$1
  disk_name=root
  if [ -f "$statedir/profile-root-name" ]; then disk_name=$(cat "$statedir/profile-root-name"); fi
  if [ "${{nic_spec%%,*}}" = "$disk_name" ]; then
    disk_oldifs=$IFS; IFS=,; set -- $nic_spec; IFS=$disk_oldifs; shift
    for kv in "$@"; do
      case "${{kv%%=*}}" in type|path|pool|size) ;; *) exit 1 ;; esac
    done
    return 0
  fi
  oldifs=$IFS; IFS=,
  set -- $nic_spec
  IFS=$oldifs
  shift
  for kv in "$@"; do
    nic_key=${{kv%%=*}}
    case "$nic_key" in
      type|nictype|network|parent|name|mtu|hwaddr|host_name|queue.tx.length|boot.priority|vlan|vlan.tagged|ipv4.address|ipv4.routes|ipv4.routes.external|ipv6.address|ipv6.routes|ipv6.routes.external|limits.egress|limits.ingress|limits.max|limits.priority|security.mac_filtering|security.ipv4_filtering|security.ipv6_filtering|security.port_isolation) ;;
      *) echo "Error: Invalid device option \"$nic_key\" for a bridged NIC" >&2; exit 1 ;;
    esac
  done
}}
if [ -n "$logfile" ]; then
  # ONE append per invocation (C36 r32): concurrent shim processes (the
  # refresh pass and the autonomous lease watcher) must never interleave
  # their partial writes — a single short O_APPEND write is atomic, so
  # the log stays line-oriented under concurrency.
  logline="$cmd"
  for arg in "$@"; do
    # Escape embedded newlines (raw.dnsmasq values) so the log stays
    # line-oriented: one invocation, one line.
    escaped=$(printf '%s' "$arg" | awk 'BEGIN{{ORS=""}} NR>1{{printf "\\n"}} {{printf "%s",$0}}')
    logline="$logline $escaped"
  done
  printf '%s\n' "$logline" >> "$logfile"
fi
case "$cmd" in
  version)
    if [ "$mode" = "json_cli_error" ]; then
      printf '{{"type":"error","error":"Forbidden","error_code":403}}\n'
      exit 1
    fi
    exit 0
    ;;
  start)
    if [ "$mode" = "json_cli_error" ]; then
      printf '{{"type":"error","error":"Forbidden","error_code":403}}\n'
      exit 1
    fi
    # Test injection (C37): crash the first start AFTER the verified-policy
    # fence passed — the VM stays stopped, the retry must re-verify and
    # resume. One-shot: the pin is consumed.
    # Test injection (E-11): the daemon refuses EVERY start with the
    # recorded stderr (exit 1); the VM stays as it was.
    if [ -f "$statedir/start-error-signal" ]; then
      cat "$statedir/start-error-signal" >&2
      kill -9 $$
    fi
    if [ -f "$statedir/start-error-exit0" ]; then
      cat "$statedir/start-error-exit0" >&2
      exit 0
    fi
    if [ -f "$statedir/start-error" ]; then
      cat "$statedir/start-error" >&2
      exit 1
    fi
    # Test injection (HR-R5): a translated CLI unless the caller pins C.
    if [ -f "$statedir/start-error-localized" ]; then
      if [ "${{LC_ALL:-}}" = C ]; then
        cat "$statedir/start-error-localized" >&2
      else
        sed 's/^Error: /Erreur : /' "$statedir/start-error-localized" >&2
      fi
      exit 1
    fi
    if [ -f "$statedir/fail-start-once" ]; then
      rm -f "$statedir/fail-start-once"
      echo "Error: start pinned by test" >&2
      exit 1
    fi
    # Test injection (C37): enforcement breaks DURING boot — the start lands
    # after the pre-start fence passed, and the sandbox ACL gains an
    # allow-all egress rule before readiness evidence is collected. The
    # readiness fence must catch it; without it the VM would read Ready on an
    # unenforced network.
    if [ -f "$statedir/tamper-acl-on-start" ]; then
      tamper_acl=$(ls "$statedir/acls"/wssp-acl-*.egress 2>/dev/null | head -1)
      if [ -n "$tamper_acl" ]; then
        printf 'action=allow\n' >> "$tamper_acl"
      fi
    fi
    if [ "$mode" = "lifecycle_incomplete_start" ]; then
      exit 0
    fi
    if [ "$mode" = "lifecycle_post_query_denied" ]; then
      : > "$statedir/post-issue-effect"
      exit 0
    fi
    if [ -f "$statedir/allocation-list" ]; then rm -f "$statedir/stopped-instance"; fi
    : > "$started"
    exit 0
    ;;
  stop)
    if [ "$mode" = "c32_stop_once" ] && [ ! -f "$statedir/stop-failed" ]; then
      : > "$statedir/stop-failed"
      exit 1
    fi
    if [ "$mode" = "json_cli_error" ]; then
      printf '{{"type":"error","error":"Forbidden","error_code":403}}\n'
      exit 1
    fi
    if [ "$mode" = "lifecycle_incomplete_stop" ]; then
      exit 0
    fi
    if [ "$mode" = "graceful_ignored" ]; then
      # C55: the guest ignores the shutdown request; only a forced stop works.
      case " $* " in *" --force "*) ;; *) exit 1 ;; esac
    fi
    if [ "$mode" = "lifecycle_post_query_denied" ]; then
      : > "$statedir/post-issue-effect"
      exit 0
    fi
    : > "$statedir/stopped-instance"
    exit 0
    ;;
  init|launch)
    rm -f "$statedir/deleted-instance"
    : > "$statedir/launched"
    # A freshly initialized instance has NO local devices: anything recorded
    # belongs to a previous incarnation of the name.
    rm -f "$statedir"/device-* 2>/dev/null || true
    saw_profile=0
    previous=""
    for argument in "$@"; do
      if [ "$previous" = "-c" ]; then
        mkdir -p "$statedir/config"
        key=${{argument%%=*}}
        value=${{argument#*=}}
        printf '%s' "$value" > "$statedir/config/$key"
      fi
      if [ "$previous" = "--" ]; then
        printf '%s' "$argument" > "$statedir/config/volatile.base_image"
      fi
      if [ "$previous" = "--device" ]; then
        dev=${{argument%%,*}}
        validate_bridged_nic_spec "$argument"
        # Incus semantics: init --device MERGES onto the profile's device of
        # the same name — inherited properties not named here SURVIVE
        # (R22-F2: the runtime must therefore install the NIC post-init).
        merged="$dev"
        profile_spec="type=nic,network=incusbr0"
      if [ "$dev" = "root" ]; then profile_spec="type=disk,path=/,pool=default"; fi
        if [ -f "$statedir/profile-$dev" ]; then
          profile_spec=$(cat "$statedir/profile-$dev")
        fi
        for kv in $profile_spec $(printf '%s' "$argument" | tr ',' ' '); do
          case "$kv" in
          *=*)
            key=${{kv%%=*}}
            merged=$(printf '%s' "$merged" | tr ',' '\n' | grep -v "^$key=" | grep -v '^$' | tr '\n' ',')
            merged="${{merged%,}}"
            merged="$merged,$kv"
            ;;
          esac
        done
        printf '%s' "$merged" > "$statedir/device-$dev"
      fi
      if [ "$previous" = "--profile" ] && [ "$argument" = "default" ]; then
        saw_profile=1
      fi
      previous=$argument
    done
    if [ "$saw_profile" != 1 ]; then
      # Launches must explicitly select the audited profile; an image's own
      # profile list is never trusted (C35).
      echo "Error: init must explicitly select --profile default" >&2
      exit 1
    fi
    if [ "$mode" = "c32_delayed_init" ]; then
      [ "$cmd" != "launch" ] || : > "$started"
      : > "$statedir/init-entered"
      while [ ! -f "$statedir/release-init" ]; do sleep 0.01; done
    fi
    case "$mode" in fix6_launch_absent) exit 1 ;; esac
    saw_dd=0
    for arg in "$@"; do
      if [ "$arg" = "--" ]; then
        saw_dd=1
      fi
    done
    if [ "$saw_dd" != 1 ]; then
      echo "Error: launch requires -- before image and name" >&2
      exit 1
    fi
    if [ "$project" != "default" ]; then
      if [ ! -f "$statedir/shared-profiles" ] || [ ! -f "$statedir/shared-images" ]; then
        echo "Error: project profile missing root disk or nic" >&2
        exit 1
      fi
    fi
    exit 0
    ;;
  delete)
    if [ -f "$statedir/refuse-delete" ]; then
      echo 'Error: delete unavailable' >&2
      exit 1
    fi
    if [ "$mode" = "permission" ]; then
      echo '{{"type":"error","error":"Forbidden","error_code":403}}'
      exit 1
    fi
    if [ "$mode" = "lifecycle_incomplete_delete" ]; then
      exit 0
    fi
    if [ "$mode" = "lifecycle_post_query_denied" ]; then
      : > "$statedir/post-issue-effect"
      exit 0
    fi
    : > "$statedir/deleted-instance"
    if [ "$mode" = "delete_applied_transport_stall" ]; then sleep 5; fi
    exit 0
    ;;
  project)
    if [ "$project" != "default" ]; then
      echo "Error: bootstrap must use an existing project" >&2
      exit 1
    fi
    sub=$1
    shift || true
    case "$sub" in
      list)
        printf '['
        printf '{{"name":"default"}},{{"name":"custom"}}'
        if [ -f "$statedir/created-projects" ]; then
          while IFS= read -r p; do
            [ -n "$p" ] || continue
            printf ',{{"name":"%s"}}' "$p"
          done < "$statedir/created-projects"
        fi
        printf ']\n'
        exit 0
        ;;
      create)
        name=$1
        shift
        if [ -z "$name" ]; then
          echo "Error: project create requires a name" >&2
          exit 1
        fi
        if [ "$mode" = "project_create_race" ] && [ -f "$statedir/project-$name" ]; then
          echo "Error: Project already exists" >&2
          exit 1
        fi
        saw_profiles=0
        saw_images=0
        while [ $# -gt 0 ]; do
          case "$1" in
            --config)
              case "$2" in
                features.profiles=false) saw_profiles=1 ;;
                features.images=false) saw_images=1 ;;
                features.storage.volumes=true) ;;
                *)
                  echo "Error: project must share profiles and images with default" >&2
                  exit 1
                  ;;
              esac
              shift 2
              ;;
            *)
              echo "Error: unknown project create argument $1" >&2
              exit 1
              ;;
          esac
        done
        if [ "$saw_profiles" != 1 ] || [ "$saw_images" != 1 ]; then
          echo "Error: project must share profiles and images with default" >&2
          exit 1
        fi
        : > "$statedir/shared-profiles"
        : > "$statedir/shared-images"
        printf '%s' "{{\"name\":\"$name\",\"config\":{{\"features.profiles\":\"false\",\"features.images\":\"false\",\"features.storage.volumes\":\"true\"}}}}" > "$statedir/project-$name"
        echo "$name" >> "$statedir/created-projects"
        exit 0
        ;;
      *)
        echo "Error: unknown project subcommand $sub" >&2
        exit 1
        ;;
    esac
    ;;
  storage)
    if [ "$1 $2 $3" = "volume file pull" ]; then
      printf 'wssp-storage-v1\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
      exit 0
    fi
    echo '[{{"name":"default"}}]'
    exit 0
    ;;
  network)
    sub=$1
    shift || true
    case "$sub" in
      list)
        printf '[{{"name":"incusbr0","managed":true,"type":"bridge"}}'
        if [ -d "$statedir/networks" ]; then
          for f in "$statedir"/networks/*.conf; do
            [ -e "$f" ] || continue
            project_visible "$(res_project "${{f%.conf}}")" || continue
            printf ',{{"name":"%s","managed":true,"type":"bridge"}}' "$(basename "$f" .conf)"
          done
        fi
        printf ']\n'
        exit 0
        ;;
      create)
        name=$1
        shift || true
        case "$name" in
          wsn-*) ;;
          *)
            echo "Error: refusing to create an unmanaged network $name" >&2
            exit 1
            ;;
        esac
        # Linux IFNAMSIZ: bridge names are interface names, 15 chars max.
        if [ ${{#name}} -gt 15 ]; then
          echo "Error: interface name too long: $name" >&2
          exit 1
        fi
        if [ "$mode" = "egress_network_create_fail" ]; then
          echo "Error: network backend unavailable" >&2
          exit 1
        fi
        if [ -f "$statedir/networks/$name.conf" ]; then
          echo "Error: Network already exists" >&2
          exit 1
        fi
        mkdir -p "$statedir/networks"
        : > "$statedir/networks/$name.conf"
        printf '%s' "$cur_project" > "$statedir/networks/$name.project"
        while [ $# -gt 0 ]; do
          case "$1" in
            --type)
              if [ "$2" != "bridge" ]; then
                echo "Error: sandbox networks must be bridges" >&2
                exit 1
              fi
              shift 2
              ;;
            *=*)
              # Multiline values (raw.dnsmasq) live in a side file so the
              # line-oriented .conf store stays parseable.
              case "$1" in
                raw.dnsmasq=*)
                  printf '%s' "${{1#raw.dnsmasq=}}" > "$statedir/networks/$name.raw"
                  ;;
                *)
                  printf '%s\n' "$1" >> "$statedir/networks/$name.conf"
                  ;;
              esac
              shift
              ;;
            *)
              echo "Error: unknown network create argument $1" >&2
              exit 1
              ;;
          esac
        done
        exit 0
        ;;
      set)
        # network set <name> <key> <value>
        name=$1
        key=$2
        value=$3
        if [ ! -f "$statedir/networks/$name.conf" ] || [ "$(res_project "$statedir/networks/$name")" != "$cur_project" ]; then
          echo "Error: Network not found" >&2
          exit 1
        fi
        if [ "$key" = "raw.dnsmasq" ]; then
          if [ -f "$statedir/fail-raw-dnsmasq" ]; then
            echo "Error: dnsmasq reload failed" >&2
            exit 1
          fi
          printf '%s' "$value" > "$statedir/networks/$name.raw"
          exit 0
        fi
        python3 - "$statedir/networks/$name.conf" "$key" "$value" <<'PYSET'
import sys,pathlib
p = pathlib.Path(sys.argv[1])
key, value = sys.argv[2], sys.argv[3]
lines = [l for l in p.read_text().splitlines() if not l.startswith(key + "=")]
lines.append(key + "=" + value)
p.write_text("\n".join(lines) + "\n")
PYSET
        exit 0
        ;;
      delete)
        name=$1
        if [ -f "$statedir/fail-delete-$name" ]; then
          echo "Error: delete pinned by test" >&2
          exit 1
        fi
        if [ "$mode" = "egress_network_delete_fail" ] || {{ {{ [ "$mode" = "egress_apply_fail_teardown_fail" ] || [ "$mode" = "egress_teardown_fail" ]; }} && [ ! -f "$statedir/teardown-allowed" ]; }}; then
          echo "Error: network is in use" >&2
          exit 1
        fi
        if [ ! -f "$statedir/networks/$name.conf" ] || [ "$(res_project "$statedir/networks/$name")" != "$cur_project" ]; then
          echo "Error: Network not found" >&2
          exit 1
        fi
        rm -f "$statedir/networks/$name.conf" "$statedir/networks/$name.project" "$statedir/networks/$name.raw"
        exit 0
        ;;
      acl)
        if [ "$mode" = "egress_acl_unsupported" ]; then
          echo "Error: network ACLs are not supported by this server" >&2
          exit 1
        fi
        aclsub=$1
        shift || true
        case "$aclsub" in
          list)
            printf '['
            first=1
            if [ -d "$statedir/acls" ]; then
              for f in "$statedir"/acls/*.conf; do
                [ -e "$f" ] || continue
                project_visible "$(res_project "${{f%.conf}}")" || continue
                if [ "$first" = 1 ]; then first=0; else printf ','; fi
                printf '{{"name":"%s"}}' "$(basename "$f" .conf)"
              done
            fi
            printf ']\n'
            exit 0
            ;;
          set)
            # network acl set <name> <key> <value>
            name=$1
            key=$2
            value=$3
            if [ ! -f "$statedir/acls/$name.conf" ] || [ "$(res_project "$statedir/acls/$name")" != "$cur_project" ]; then
              echo "Error: ACL not found" >&2
              exit 1
            fi
            python3 - "$statedir/acls/$name.conf" "$key" "$value" <<'PYSET'
import sys,pathlib
p = pathlib.Path(sys.argv[1])
key, value = sys.argv[2], sys.argv[3]
lines = [l for l in p.read_text().splitlines() if not l.startswith(key + "=")]
lines.append(key + "=" + value)
p.write_text("\n".join(lines) + "\n")
PYSET
            exit 0
            ;;
          create)
            name=$1
            shift || true
            case "$name" in
              wssp-acl-*) ;;
              *)
                echo "Error: refusing to create an unmanaged ACL $name" >&2
                exit 1
                ;;
            esac
            if [ -f "$statedir/acls/$name.conf" ]; then
              echo "Error: ACL already exists" >&2
              exit 1
            fi
            mkdir -p "$statedir/acls"
            : > "$statedir/acls/$name.conf"
            : > "$statedir/acls/$name.ingress"
            : > "$statedir/acls/$name.egress"
            printf '%s' "$cur_project" > "$statedir/acls/$name.project"
            while [ $# -gt 0 ]; do
              case "$1" in
                *=*)
                  printf '%s\n' "$1" >> "$statedir/acls/$name.conf"
                  shift
                  ;;
                *)
                  echo "Error: unknown acl create argument $1" >&2
                  exit 1
                  ;;
              esac
            done
            exit 0
            ;;
          rule)
            ruleop=$1
            # PROBE (c58-g1-r2 reviewer): crash-like fault injection. Let N
            # mutations (ACL rule add/remove, network PATCH/set) succeed,
            # then fail every later one until the pin is removed.
            if [ -s "$statedir/fail-mutations-after" ]; then
              left=$(cat "$statedir/fail-mutations-after")
              if [ "$left" -gt 0 ] 2>/dev/null; then
                echo $((left - 1)) > "$statedir/fail-mutations-after"
              else
                if [ -f "$statedir/crash-snapshot" ] && [ ! -d "$statedir.crash" ]; then cp -a "$statedir" "$statedir.crash"; fi
                if [ -f "$statedir/fail-mutations-uncertain" ]; then
                  echo "Error: Post \"https://incus.internal/1.0/network-acls/x\": read: connection reset by peer" >&2
                  exit 1
                fi
                echo "Error: injected crash" >&2
                exit 1
              fi
            fi
            if [ "$ruleop" != "add" ] && [ "$ruleop" != "remove" ]; then
              echo "Error: unknown acl rule subcommand $1" >&2
              exit 1
            fi
            shift
            name=$1
            direction=$2
            shift 2 || true
            if [ "$ruleop" = "remove" ]; then
              # network acl rule remove <acl> <direction> k=v... [--force]
              # Incus semantics: every given key=value must match; without
              # --force exactly one rule may match; zero matches is an error.
              # Test injection (C36 r9): stretch REMOVAL passes across
              # wall-clock seconds (pin content = seconds per removal).
              if [ -f "$statedir/slow-acl-removals" ]; then
                dns_work_delay "$(cat "$statedir/slow-acl-removals")"
              fi
              # Logical cleanup work, scoped to grant identities so setup's
              # preventive-fence releases do not consume the cleanup budget.
              if [ -f "$statedir/slow-acl-grant-removals" ]; then
                case " $* " in
                  *"description=wssp-dns-g"*|*"description=wssp-dns-reject-g"*)
                    dns_work_delay "$(cat "$statedir/slow-acl-grant-removals")"
                    ;;
                esac
              fi
              # Test injection (C36 r8): crash a refresh right after the
              # revocation marker is persisted, before the first removal.
              if [ -f "$statedir/fail-acl-rule-remove" ]; then
                echo "Error: rule removal rejected" >&2
                exit 1
              fi
              # Test injection (C36 r18 F3): the daemon REFUSES removal of
              # ALLOW rules with a rejection that is neither proven absence
              # nor a duplicate-match refusal — the allow stays installed.
              # An unproven withdrawal must fence the destination and leave
              # its companions untouched, never proceed as if withdrawn.
              if [ -f "$statedir/fail-acl-allow-remove" ]; then
                case " $* " in
                  *"action="*) ;;
                  *"description=wssp-dns-"*)
                    echo "Error: rule removal rejected by policy" >&2
                    exit 1
                    ;;
                esac
              fi
              # Test injection (C36 r26 F3): refuse a removal only when
              # its selectors carry the PINNED substring (the file's
              # content, e.g. one grant's full allow tag) — a PARTIAL
              # withdrawal failure: the sibling grant over the same
              # destination withdraws cleanly while this grant's allow
              # stays installed.
              if [ -f "$statedir/fail-acl-allow-remove-only" ]; then
                case " $* " in
                  *"action="*) ;;
                  *"description=wssp-dns-"*)
                    only_pin=$(cat "$statedir/fail-acl-allow-remove-only")
                    if [ -n "$only_pin" ]; then
                      case " $* " in
                        *"$only_pin"*)
                          echo "Error: rule removal rejected by policy" >&2
                          exit 1
                          ;;
                      esac
                    fi
                    ;;
                esac
              fi
              # Test injection (C36 r21 F2): the daemon REFUSES removal of
              # DNS REJECT COMPANION rules outright (exit 1, rule stays
              # installed): an unproven companion-withdrawal VERDICT, not
              # a transport failure — the settle must keep the obligation
              # armed instead of retiring it with stranded deny-leftovers.
              if [ -f "$statedir/fail-acl-reject-remove" ]; then
                case " $* " in
                  *"description=wssp-dns-reject-"*)
                    echo "Error: rule removal rejected by policy" >&2
                    exit 1
                    ;;
                esac
              fi
              # Test injection (C36 r22 F1): a DUPLICATE-MATCH refusal on
              # DNS allow removals — the plain (non --force) attempt exits
              # 1 with the daemon's needs-force verdict, exactly the
              # refusal that triggers the primitive's --force retry. The
              # retry itself proceeds (and may be stretched by
              # slow-acl-removals above), so a test can prove the retry
              # spends only what remains of the caller's deadline.
              if [ -f "$statedir/duplicate-acl-allow-remove" ]; then
                case " $* " in
                  *" --force "*) ;;
                  *"action="*) ;;
                  *"description=wssp-dns-reject-"*) ;;
                  *"description=wssp-dns-quarantine-"*) ;;
                  *"description=wssp-dns-lease-quarantine-"*) ;;
                  *"description=wssp-dns-"*)
                    echo "Error: More than one matching rule found, use --force" >&2
                    exit 1
                    ;;
                esac
              fi
              # Test injection (C36 r19, renewal linearization): a true
              # BARRIER on DNS allow removals — the removal blocks until
              # $statedir/release-allow-barrier appears, so a test can
              # hold an expiry settle IN FLIGHT while a renewal re-arms.
              if [ -f "$statedir/barrier-acl-allow-remove" ] && [ ! -f "$statedir/release-allow-barrier" ]; then
                case " $* " in
                  *"action="*) ;;
                  *"description=wssp-dns-"*)
                    barrier_spun=0
                    while [ ! -f "$statedir/release-allow-barrier" ] && [ "$barrier_spun" -lt 180 ]; do
                      sleep 1
                      barrier_spun=$((barrier_spun + 1))
                    done
                    ;;
                esac
              fi
              # Test injection (C36 r21 F2): a true BARRIER on DNS REJECT
              # COMPANION removals — blocks until release-reject-barrier
              # appears, so a test can stall one expiry's companion
              # cleanup while a second grant's deadline must still be
              # enforced on time. The spin precedes the mutation below,
              # so a killed attempt never partially applies.
              if [ -f "$statedir/barrier-acl-reject-remove" ] && [ ! -f "$statedir/release-reject-barrier" ]; then
                case " $* " in
                  *"description=wssp-dns-reject-"*)
                    : > "$statedir/reject-remove-entered"
                    barrier_spun=0
                    while [ ! -f "$statedir/release-reject-barrier" ] && [ "$barrier_spun" -lt 180 ]; do
                      sleep 1
                      barrier_spun=$((barrier_spun + 1))
                    done
                    ;;
                esac
              fi
              # Test injection (C36 r21 F2): a true BARRIER on LEASE-FENCE
              # removals — blocks until release-lease-fence-barrier
              # appears, so a test can stall the clean-expiry fence
              # withdrawal while a second grant's deadline must still be
              # enforced on time.
              if [ -f "$statedir/barrier-acl-lease-fence-remove" ] && [ ! -f "$statedir/release-lease-fence-barrier" ]; then
                case " $* " in
                  *"description=wssp-dns-lease-quarantine-"*)
                    : > "$statedir/lease-fence-remove-entered"
                    barrier_spun=0
                    while [ ! -f "$statedir/release-lease-fence-barrier" ] && [ "$barrier_spun" -lt 180 ]; do
                      sleep 1
                      barrier_spun=$((barrier_spun + 1))
                    done
                    ;;
                esac
              fi
              # Test injection (C36 r33 F1): a true BARRIER on
              # REFRESH-FENCE removals — blocks until
              # release-fence-barrier appears, so a test can hold a
              # journaled fence-release retry (which holds the lease
              # owner lock) stalled while another grant's expiry must
              # still be enforced on time. The spin precedes the
              # mutation below, so a killed attempt never partially
              # applies. Non-empty file content narrows the match to
              # removals naming that fence tag, so other fences release
              # normally.
              if [ -f "$statedir/barrier-acl-fence-remove" ] && [ ! -f "$statedir/release-fence-barrier" ]; then
                fence_pat="$(cat "$statedir/barrier-acl-fence-remove")"
                fence_pat="${{fence_pat:-description=wssp-dns-quarantine-}}"
                case " $* " in
                  *"$fence_pat"*)
                    barrier_spun=0
                    while [ ! -f "$statedir/release-fence-barrier" ] && [ "$barrier_spun" -lt 180 ]; do
                      sleep 1
                      barrier_spun=$((barrier_spun + 1))
                    done
                    ;;
                esac
              fi
              # Test injection (C36 r33 F1): EVERY removal of the
              # refresh fence named by the file's content fails
              # uncertainly until the test removes the file — a journaled
              # release survives a reconcile retry, a plan-phase release,
              # AND the commit-time drain while a sibling fence still
              # releases.
              if [ -f "$statedir/fail-acl-fence-remove-tag" ]; then
                fence_pat="$(cat "$statedir/fail-acl-fence-remove-tag")"
                case " $* " in
                  *"$fence_pat"*)
                    echo "Error: Post \"https://incus.internal/1.0/network-acls/$name\": read: connection reset by peer" >&2
                    exit 1
                    ;;
                esac
              fi
              # Test injection (C36 r33 F2): the FIRST refresh-fence
              # removal fails uncertainly (the daemon may or may not have
              # applied it), then the hook self-clears — the commit-time
              # drain's retry succeeds, exercising the drain-to-commit
              # snapshot handoff.
              if [ -f "$statedir/fail-acl-fence-remove-once" ]; then
                case " $* " in
                  *"description=wssp-dns-quarantine-"*)
                    rm -f "$statedir/fail-acl-fence-remove-once"
                    echo "Error: Post \"https://incus.internal/1.0/network-acls/$name\": read: connection reset by peer" >&2
                    exit 1
                    ;;
                esac
              fi
              # Test injection (C36 r17 F4): model the Incus daemon ACCEPTING
              # a rule REMOVAL but applying it only after N seconds while the
              # CLI reports a transport failure (uncertain outcome). Used to
              # prove uncertain broadening removals (fence releases) are
              # journaled, and that a re-issued fence under a FRESH identity
              # cannot be struck by the deferred removal of the old one.
              if [ -f "$statedir/defer-acl-rule-remove" ]; then
                case " $* " in
                  *"description=wssp-dns-quarantine-"*)
                defer_secs=$(cat "$statedir/defer-acl-rule-remove")
                if [ "$defer_secs" = "queue" ]; then
                  printf '%s\n' "$statedir/acls/$name.$direction" "$@" > "$statedir/queued-remove-$$"
                  echo "Error: Post \"https://incus.internal/1.0/network-acls/$name\": read: connection reset by peer" >&2
                  exit 1
                fi
                defer_py="$statedir/defer-remove-$$.py"
                printf '%s\n'                   'import sys,time,pathlib,fcntl'                   "time.sleep($defer_secs)"                   'lockf = open(sys.argv[1] + ".lock", "a")'                   'fcntl.flock(lockf, fcntl.LOCK_EX)'                   'p = pathlib.Path(sys.argv[1])'                   'args = sys.argv[2:]'                   'kv = [a for a in args if a != "--force"]'                   'lines = p.read_text().splitlines()'                   'def m(line):'                   '    tokens = line.split()'                   '    return all(any(t == pair for t in tokens) for pair in kv)'                   'kept = [l for l in lines if not m(l)]'                   'if len(kept) != len(lines):'                   '    staged = p.with_name(p.name + ".tmp")'                   '    staged.write_text("\n".join(kept) + ("\n" if kept else ""))'                   '    staged.replace(p)'                   > "$defer_py"
                ( setsid python3 "$defer_py" "$statedir/acls/$name.$direction" "$@" >/dev/null 2>&1 & )
                echo "Error: Post \"https://incus.internal/1.0/network-acls/$name\": read: connection reset by peer" >&2
                exit 1
                  ;;
                esac
              fi
              if [ ! -f "$statedir/acls/$name.conf" ]; then
                echo "Error: ACL not found" >&2
                exit 1
              fi
              # The real daemon serializes rule mutations server-side; the
              # pass and the expiry lease may legitimately race removals
              # (C36 r17 F3). Take a per-file lock so the read-modify-write
              # below cannot lose a concurrent add/remove (C36 r19).
              (
                flock -w 120 9 || exit 1
                python3 - "$statedir/acls/$name.$direction" "$@" <<'PYRM'
import sys,pathlib
p = pathlib.Path(sys.argv[1])
args = [a for a in sys.argv[2:]]
force = "--force" in args
kv = [a for a in args if a != "--force"]
lines = p.read_text().splitlines()
def matches(line):
    tokens = line.split()
    return all(any(t == pair for t in tokens) for pair in kv)
kept = [l for l in lines if not matches(l)]
removed = len(lines) - len(kept)
if removed == 0:
    print("Error: No matching rule(s) found", file=sys.stderr)
    sys.exit(1)
if removed > 1 and not force:
    print("Error: More than one matching rule, use --force", file=sys.stderr)
    sys.exit(1)
staged = p.with_name(p.name + ".tmp")
staged.write_text("\n".join(kept) + ("\n" if kept else ""))
staged.replace(p)
PYRM
              ) 9>"$statedir/acls/$name.$direction.lock"
              exit $?
            fi
            if [ ! -f "$statedir/acls/$name.conf" ]; then
              echo "Error: ACL not found" >&2
              exit 1
            fi
            if [ "$direction" != "ingress" ] && [ "$direction" != "egress" ]; then
              echo "Error: rule direction must be ingress or egress" >&2
              exit 1
            fi
            # Test injection (C37 R6): a true BARRIER on LEASE-FENCE ADDS —
            # parks the blind pre-fence's fence installation until
            # release-lease-fence-add-barrier appears, so a test can
            # observe the transition marking AT the shared mutation
            # boundary (acquired before the first actual mutation lands).
            # The spin precedes the mutation below, so a killed attempt
            # never partially applies.
            if [ -f "$statedir/barrier-acl-lease-fence-add" ] && [ ! -f "$statedir/release-lease-fence-add-barrier" ]; then
              case " $* " in
                *"description=wssp-dns-lease-quarantine-"*)
                  barrier_spun=0
                  while [ ! -f "$statedir/release-lease-fence-add-barrier" ] && [ "$barrier_spun" -lt 180 ]; do
                    sleep 1
                    barrier_spun=$((barrier_spun + 1))
                  done
                  ;;
              esac
            fi
            if [ "$mode" = "egress_rule_add_fail" ] || [ "$mode" = "egress_apply_fail_teardown_fail" ] || [ -f "$statedir/fail-acl-rule-add" ]; then
              echo "Error: rule rejected" >&2
              exit 1
            fi
            # Test injection (C36 r8/r9): stretch ACL work across wall-clock
            # seconds so grant expiries captured at planning time go stale
            # (pin content = seconds per addition).
            if [ -f "$statedir/slow-acl-ops" ]; then
              dns_work_delay "$(cat "$statedir/slow-acl-ops")"
            fi
            # Test injection (C36 r18): stall FENCE adds only (a reject
            # rule WITHOUT a destination_port — companions always carry
            # one), so preventive fencing alone burns the grant's clock.
            if [ -f "$statedir/slow-acl-fence-add" ]; then
              case " $* " in
                *" action=reject "*)
                  case " $* " in
                    *" destination_port="*) ;;
                    *) sleep "$(cat "$statedir/slow-acl-fence-add")" ;;
                  esac
                  ;;
              esac
            fi
            # Test injection (C36 r13): stall the ALLOW mutation ITSELF
            # (before applying) so a bounded-by-remaining-lifetime add is
            # killed at its safe deadline and the allow never lands.
            if [ -f "$statedir/slow-acl-allow-add" ]; then
              case " $* " in
                *" action=allow "*)
                  sleep "$(cat "$statedir/slow-acl-allow-add")"
                  ;;
              esac
            fi
            # Test injection (C36 r14): model the Incus DAEMON accepting
            # the allow mutation and applying it ASYNCHRONOUSLY after N
            # seconds while the CLI stalls forever — killing the CLI at
            # its deadline does not cancel the daemon-side apply, which
            # lands behind the withdrawal and readback. The detached
            # applier survives the CLI kill in its own session. Pin
            # `queue`: the accepted request is queued (`queued-add-<pid>`)
            # and lands only when the test applies it, at the point of the
            # fault history it intends, not after a wall-clock delay.
            if [ -f "$statedir/defer-acl-allow-add" ]; then
              case " $* " in
                *" action=allow "*)
                  defer_secs=$(cat "$statedir/defer-acl-allow-add")
                  if [ "$defer_secs" = "queue" ]; then
                    printf '%s\n' "$statedir/acls/$name.$direction" "$@" > "$statedir/queued-add-$$"
                    : > "$statedir/defer-acl-allow-add.armed"
                    sleep 1000
                  fi
                  # A daemon-side rule-add applies against the ACL ROW by name:
                  # if the ACL was deleted in the window (create rollback),
                  # the update fails and the rule never lands. Model that —
                  # the applier drops the rule when the ACL is absent.
                  # The applier first writes `defer-acl-allow-add.armed` FROM
                  # INSIDE its own session: once it exists the applier has
                  # escaped the CLI's process group, so a test may cancel
                  # (group-kill) the CLI without killing the "daemon" too.
                  ( setsid sh -c ": > \"$statedir/defer-acl-allow-add.armed\"; sleep $defer_secs; [ -f \"$statedir/acls/$name.conf\" ] || exit 0; flock -w 240 \"$statedir/acls/$name.$direction.lock\" -c \"printf '%s\\n' \\\"$*\\\" >> \\\"$statedir/acls/$name.$direction\\\"\"" >/dev/null 2>&1 & )
                  sleep 1000
                  ;;
              esac
            fi
            # Test injection (C36 r17): deferred daemon-side allow apply
            # scoped to additions whose argv contains the tag substring
            # (pin content: "<seconds> <substring>") — sibling grants'
            # additions are unaffected.
            if [ -f "$statedir/defer-acl-allow-add-tag" ]; then
              defer_spec=$(cat "$statedir/defer-acl-allow-add-tag")
              defer_secs=${{defer_spec%% *}}
              defer_tag=${{defer_spec#* }}
              case " $* " in
                *" action=allow "*)
                  case " $* " in
                    *"$defer_tag"*)
                      if [ "$defer_secs" = "queue" ]; then
                        printf '%s\n' "$statedir/acls/$name.$direction" "$@" > "$statedir/queued-add-$$"
                        sleep 1000
                      fi
                      # A daemon-side rule-add applies against the ACL ROW by name:
                  # if the ACL was deleted in the window (create rollback),
                  # the update fails and the rule never lands. Model that —
                  # the applier drops the rule when the ACL is absent.
                  ( setsid sh -c "sleep $defer_secs; [ -f \"$statedir/acls/$name.conf\" ] || exit 0; flock -w 240 \"$statedir/acls/$name.$direction.lock\" -c \"printf '%s\\n' \\\"$*\\\" >> \\\"$statedir/acls/$name.$direction\\\"\"" >/dev/null 2>&1 & )
                      sleep 1000
                      ;;
                  esac
                  ;;
              esac
            fi
            # Test injection (C36 r16): the daemon ACCEPTS the deferred
            # allow apply, but the CLI exits NONZERO WITHOUT acknowledging
            # it — a connection failure after acceptance, NOT a rejection.
            # Pin content: "<seconds>" or "<seconds> <substring>" to scope
            # the hook to matching rule additions (C36 r21 F4: the create
            # path's BASE allow rules must stay unaffected). C36 r27 F2:
            # MULTIPLE lines, one "<seconds> <substring>" pin each — a
            # composition can defer several distinct additions in one pass.
            if [ -f "$statedir/defer-acl-allow-add-fail" ]; then
              case " $* " in
                *" action=allow "*)
                  defer_secs=""
                  while IFS= read -r defer_line || [ -n "$defer_line" ]; do
                    [ -n "$defer_line" ] || continue
                    defer_candidate=${{defer_line%% *}}
                    defer_tag=""
                    case "$defer_line" in
                      *" "*) defer_tag=${{defer_line#* }} ;;
                    esac
                    case " $* " in
                      *"$defer_tag"*) defer_secs=$defer_candidate; break ;;
                    esac
                  done < "$statedir/defer-acl-allow-add-fail"
                  if [ -n "$defer_secs" ]; then
                  if [ "$defer_secs" = "queue" ]; then
                    printf '%s\n' "$statedir/acls/$name.$direction" "$@" > "$statedir/queued-add-$$"
                    echo "Error: Post \"https://incus.internal/1.0/network-acls/$name\": read: connection reset by peer" >&2
                    exit 1
                  fi
                  # A daemon-side rule-add applies against the ACL ROW by name:
                  # if the ACL was deleted in the window (create rollback),
                  # the update fails and the rule never lands. Model that —
                  # the applier drops the rule when the ACL is absent.
                  ( setsid sh -c "sleep $defer_secs; [ -f \"$statedir/acls/$name.conf\" ] || exit 0; flock -w 240 \"$statedir/acls/$name.$direction.lock\" -c \"printf '%s\\n' \\\"$*\\\" >> \\\"$statedir/acls/$name.$direction\\\"\"" >/dev/null 2>&1 & )
                  echo "Error: Post \"https://incus.internal/1.0/network-acls/$name\": read: connection reset by peer" >&2
                  exit 1
                  fi
                  ;;
              esac
            fi
            # Epoch tests must exercise the refresh allocator even if the
            # autonomous watcher races the recorded denial. Refuse only its
            # lease-fence adds; the refresh's own preventive fence must hold.
            if [ -f "$statedir/fail-acl-lease-fence-add" ]; then
              case " $* " in
                *"description=wssp-dns-lease-quarantine-"*)
                  echo "Error: lease fence rejected" >&2
                  exit 1
                  ;;
              esac
            fi
            # Test injection (C36 r17 F2): fail only FENCE additions (a
            # destination-wide reject without a port): the preventive deny
            # must fail closed BEFORE the broadening allow is ever issued.
            if [ -f "$statedir/fail-acl-fence-add" ]; then
              case " $* " in
                *" action=reject "*)
                  case " $* " in
                    *" destination_port="*) ;;
                    *)
                      echo "Error: fence rejected" >&2
                      exit 1
                      ;;
                  esac
                  ;;
              esac
            fi
            # Test injection: fail only ALLOW rule additions (C36 r1/r2
            # interruption window: reject companions must land first).
            if [ -f "$statedir/fail-acl-rule-add-allow" ]; then
              case " $* " in
                *" action=allow "*)
                  echo "Error: rule rejected" >&2
                  exit 1
                  ;;
              esac
            fi
            # Test injection: fail only REJECT rule additions (C36 r4: reject
            # REPAIR must first withdraw the overlapping allow).
            if [ -f "$statedir/fail-acl-rule-add-reject" ]; then
              case " $* " in
                *" action=reject "*)
                  echo "Error: rule rejected" >&2
                  exit 1
                  ;;
              esac
            fi
            if [ "$mode" = "egress_rule_partial" ]; then
              existing=$(cat "$statedir/acls/$name.ingress" "$statedir/acls/$name.egress" | wc -l)
              if [ "$existing" -ge 1 ]; then
                echo "Error: rule rejected mid-apply" >&2
                exit 1
              fi
            fi
            # Same serialization as removals (C36 r19): a rule add racing
            # a removal's read-modify-write must not be lost.
            (
              flock -w 120 9 || exit 1
              printf '%s\n' "$*" >> "$statedir/acls/$name.$direction"
            ) 9>"$statedir/acls/$name.$direction.lock"
            exit 0
            ;;
          delete)
            name=$1
            if {{ [ "$mode" = "egress_apply_fail_teardown_fail" ] || [ "$mode" = "egress_teardown_fail" ]; }} && [ ! -f "$statedir/teardown-allowed" ]; then
              echo "Error: ACL is in use" >&2
              exit 1
            fi
            if [ ! -f "$statedir/acls/$name.conf" ] || [ "$(res_project "$statedir/acls/$name")" != "$cur_project" ]; then
              echo "Error: ACL not found" >&2
              exit 1
            fi
            rm -f "$statedir/acls/$name.conf" "$statedir/acls/$name.ingress" "$statedir/acls/$name.egress" "$statedir/acls/$name.project"
            exit 0
            ;;
          *)
            echo "Error: unknown network acl subcommand $aclsub" >&2
            exit 1
            ;;
        esac
        ;;
      *)
        echo "Error: unknown network subcommand $sub" >&2
        exit 1
        ;;
    esac
    ;;
  profile)
    if [ "$1" != "list" ] || [ "$2" != "--format" ] || [ "$3" != "json" ]; then
      echo "Error: invalid profile contract" >&2
      exit 1
    fi
    if [ "$mode" = "empty_profile" ]; then
      echo '[{{"name":"default","devices":{{}}}}]'
    elif [ "$mode" = "unsafe_profile" ]; then
      echo '[{{"name":"default","devices":{{"root":{{"type":"disk","path":"/","pool":"default"}},"eth0":{{"type":"nic","network":"incusbr0"}},"eth1":{{"type":"nic","network":"incusbr0"}},"proxy0":{{"type":"proxy","listen":"tcp:0.0.0.0:8080","connect":"tcp:127.0.0.1:80"}},"hostdata":{{"type":"disk","path":"/srv","source":"/srv"}}}}}}]'
    else
      # The default profile's root disk NAME is fixture-driven: valid hosts
      # may name it "rootfs" instead of "root" (R20-F1).
      rootname=root
      if [ -f "$statedir/profile-root-name" ]; then
        rootname=$(cat "$statedir/profile-root-name")
      fi
      # profile-config (C37): key=value lines the default profile carries in
      # its config map — only matching exact allocation keys are permitted.
      pcfg=""
      if [ -f "$statedir/profile-config" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
          [ -n "$line" ] || continue
          k=${{line%%=*}}
          v=${{line#*=}}
          if [ -n "$pcfg" ]; then pcfg="$pcfg,"; fi
          pcfg="$pcfg\"$k\":\"$v\""
        done < "$statedir/profile-config"
      fi
      echo '[{{"name":"default","config":{{'"$pcfg"'}},"devices":{{"'"$rootname"'":{{"type":"disk","path":"/","pool":"default"}},"eth0":{{"type":"nic","network":"incusbr0"}}}}}}]'
    fi
    exit 0
    ;;
  query)
    if [ -n "$project" ]; then
      echo "Error: --project cannot be used with the query command" >&2
      exit 1
    fi
    raw=0
    method=GET
    data_inline=
    data_file=
    if_match=
    while [ $# -gt 0 ]; do
      case "$1" in
        --raw)
          raw=1
          shift
          ;;
        --project)
          echo "Error: --project cannot be used with the query command" >&2
          exit 1
          ;;
        -X|--request)
          method=$2
          shift 2
          ;;
        -d|--data)
          data_inline=$2
          shift 2
          ;;
        --data-file)
          # Real Incus (E-26): `--data-file` exists only from 7.4.0; an
          # older CLI fails flag parsing before contacting the daemon.
          if [ -f "$statedir/cli-without-data-file" ]; then
            echo "Error: unknown flag: --data-file" >&2
            exit 1
          fi
          data_file=$2
          shift 2
          ;;
        --header|-H)
          if [ -f "$statedir/cli-without-query-headers" ]; then
            echo "Error: unknown flag: --header" >&2
            exit 1
          fi
          case "$2" in If-Match:*) if_match=${{2#If-Match: }} ;; esac
          shift 2
          ;;
        --wait)
          shift
          ;;
        --*)
          echo "Error: unknown flag $1" >&2
          exit 1
          ;;
        *)
          break
          ;;
      esac
    done
    qpath=$1
    if [ -z "$qpath" ]; then
      echo "Error: query requires exactly one URL argument" >&2
      exit 1
    fi
    shift
    if [ $# -gt 0 ]; then
      echo "Error: query takes exactly one argument" >&2
      exit 1
    fi
    case "$qpath" in
      /1.0/resources|*'?project='*|*'&project='*) ;;
      *)
        echo "Error: query path must include project parameter" >&2
        exit 1
        ;;
    esac
    # Test injection (C36 r22 F1): a ONE-SHOT barrier on individual
    # network-acl READS. The file content is a SKIP COUNT: that many
    # matching reads pass (the count decrements), then the next read
    # consumes the barrier and parks until release-acl-read-barrier
    # appears; every later read proceeds immediately. Lets a test park
    # a SPECIFIC read and prove it is deadline-bounded: the parked read
    # is killed at the next live expiry and the retry is fast.
    if [ -f "$statedir/barrier-acl-read" ]; then
      case "$qpath" in
        /1.0/network-acls/?*)
          read_skips=$(cat "$statedir/barrier-acl-read" 2>/dev/null)
          case "$read_skips" in ''|*[!0-9]*) read_skips=0 ;; esac
          if [ "$read_skips" -gt 0 ]; then
            printf '%s' "$((read_skips - 1))" > "$statedir/barrier-acl-read"
          else
            rm -f "$statedir/barrier-acl-read"
            barrier_spun=0
            while [ ! -f "$statedir/release-acl-read-barrier" ] && [ "$barrier_spun" -lt 240 ]; do
              sleep 1
              barrier_spun=$((barrier_spun + 1))
            done
          fi
          ;;
      esac
    fi
    # Test injection (cg retire preflight): every instance STATE read answers
    # only after the given whole number of seconds.
    if [ -f "$statedir/slow-instance-state-query" ]; then
      case "$qpath" in
        /1.0/instances/*/state*) sleep "$(cat "$statedir/slow-instance-state-query")" ;;
      esac
    fi
    # Test injection (cg retire preflight): a ONE-SHOT stall of an instance
    # READ (/1.0/instances/<name>...). Same SKIP COUNT protocol as the ACL
    # barrier above; the stalled read never answers on its own within the
    # client default, so only the caller's deadline ends it.
    if [ -f "$statedir/stall-instance-query" ]; then
      case "$qpath" in
        /1.0/instances/?*)
          stall_skips=$(cat "$statedir/stall-instance-query" 2>/dev/null)
          case "$stall_skips" in ''|*[!0-9]*) stall_skips=0 ;; esac
          if [ "$stall_skips" -gt 0 ]; then
            printf '%s' "$((stall_skips - 1))" > "$statedir/stall-instance-query"
          else
            rm -f "$statedir/stall-instance-query"
            stall_spun=0
            while [ "$stall_spun" -lt 240 ]; do
              sleep 1
              stall_spun=$((stall_spun + 1))
            done
          fi
          ;;
      esac
    fi
    emit_error() {{
      code=$1
      msg=$2
      if [ "$raw" = 1 ]; then
        printf '{{"type":"error","status":"%s","status_code":%s,"error":"%s","error_code":%s}}\n' "$msg" "$code" "$msg" "$code"
        exit 0
      fi
      echo "Error: $msg" >&2
      exit 1
    }}
    emit_instance() {{
      if [ "$raw" = 1 ] && [ -f "$statedir/instance-metadata" ]; then
        printf '{{"type":"sync","status_code":200,"error_code":0,"metadata":'
        cat "$statedir/instance-metadata"
        printf '}}\n'
        exit 0
      fi
      status=$1
      scode=$2
      if [ "$raw" = 1 ]; then
        python3 - "$statedir" "$status" "$scode" "$mode" <<'PYCODE'
import hashlib,json,sys,pathlib
statedir = pathlib.Path(sys.argv[1])
config_dir = statedir / "config"
config = {{p.name: p.read_text() for p in config_dir.iterdir()}} if config_dir.exists() else {{}}
sandbox_id = config.get("user.flycockpit.sandbox_id", "sbx-1")
# Incus semantics: `devices` holds LOCAL devices only; `expanded_devices` is
# the effective set — profile devices merged with local overrides. The
# default profile contributes a root disk and a plain NIC on incusbr0;
# `init --device`/`config device override` record a local eth0 override.
root_name = "root"
if (statedir / "profile-root-name").exists():
    root_name = (statedir / "profile-root-name").read_text().strip()
profile = {{root_name:{{"type":"disk","path":"/","pool":"default"}},"eth0":{{"type":"nic","network":"incusbr0"}}}}
# profile-eth0: a fixture-driven INHERITED NIC spec (e.g. a legacy
# nictype=bridged,parent=br0 device) so repair runs against real
# inheritance semantics (R20-F2).
if (statedir / "profile-eth0").exists():
    pspec = (statedir / "profile-eth0").read_text().strip()
    pnic = {{}}
    for token in pspec.split(","):
        if "=" in token:
            k, v = token.split("=", 1)
            pnic[k] = v
    pnic["type"] = "nic"
    profile["eth0"] = pnic
local = {{}}
if (statedir / "device-eth0").exists():
    spec = (statedir / "device-eth0").read_text().strip()
    nic = {{}}
    for token in spec.split(",")[1:]:
        if "=" in token:
            k, v = token.split("=", 1)
            nic[k] = v
    nic["type"] = "nic"
    local["eth0"] = nic
if (statedir / ("device-" + root_name)).exists():
    spec = (statedir / ("device-" + root_name)).read_text().strip()
    device = {{}}
    for token in spec.split(",")[1:]:
        if "=" in token:
            k,v = token.split("=",1)
            device[k] = v
    device["type"] = "disk"
    device["path"] = "/"
    local[root_name] = device
expanded = dict(profile)
if not (statedir / "force-legacy-devices").exists():
    # force-legacy-devices models daemon-side drift: the reported effective
    # set ignores the recorded override.
    expanded.update(local)
if sys.argv[4] == "egress_expanded_extra":
    # An extra INHERITED device: invisible in local devices, present only in
    # the effective expanded set.
    expanded["proxy0"] = {{"type":"proxy","listen":"tcp:0.0.0.0:8080","connect":"tcp:127.0.0.1:80"}}
if sys.argv[4] == "egress_permissive_nic":
    # A NIC-level permissive ACL list widening the deny-default policy: every
    # pinned property matches, only the unexpected override differs.
    expanded["eth0"]["security.acls"] = "permissive-acl"
# Incus semantics: `expanded_config` is the EFFECTIVE config — profile and
# image config merged under the instance's local keys (C37 launch-config
# verification reads exactly this). `profile-config` models keys carried by
# the profile; `image-config` also models an already-existing instance's
# unaudited effective config for the late start-fence tests. Ordinary Incus
# image properties themselves are namespaced under image.*.
def keyval_fixture(name):
    out = {{}}
    p = statedir / name
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out
expanded_config = keyval_fixture("profile-config")
expanded_config.update(keyval_fixture("image-config"))
expanded_config.update(config)
print(json.dumps({{"type":"sync","status_code":200,"error_code":0,"metadata":{{"name":"wssp-sbx-sbx-1","status":sys.argv[2],"status_code":int(sys.argv[3]),"type":"virtual-machine","architecture":"x86_64","config":config,"expanded_config":expanded_config,"devices":local,"expanded_devices":expanded}}}}))
PYCODE
      else
        printf '{{"name":"wssp-sbx-sbx-1","status":"%s","status_code":%s,"type":"virtual-machine"}}\n' "$status" "$scode"
      fi
      exit 0
    }}
    emit_state() {{
      status=$1
      scode=$2
      processes=$3
      qpid=${{4:-1}}
      if [ "$raw" = 1 ]; then
        printf '{{"type":"sync","status":"Success","status_code":200,"error":"","error_code":0,"metadata":{{"status":"%s","status_code":%s,"pid":%s,"processes":%s}}}}\n' "$status" "$scode" "$qpid" "$processes"
      else
        printf '{{"status":"%s","status_code":%s,"pid":%s,"processes":%s}}\n' "$status" "$scode" "$qpid" "$processes"
      fi
      exit 0
    }}
    emit_project() {{
      body=$1
      if [ "$raw" = 1 ]; then
        printf '{{"type":"sync","status":"Success","status_code":200,"error":"","error_code":0,"metadata":%s}}\n' "$body"
      else
        printf '%s\n' "$body"
      fi
      exit 0
    }}
    query_deny() {{
      if [ "$mode" = "gone" ] || [ "$mode" = "kill_nosuch_instance" ]; then
        emit_error 404 "Not Found"
      fi
      if [ "$mode" = "permission" ] || [ "$mode" = "probe_denied" ]; then
        emit_error 403 "Forbidden"
      fi
    }}
    post_issue_inventory() {{
      if [ ! -f "$statedir/post-issue-effect" ]; then
        return 1
      fi
      if [ "$mode" = "post_issue_stopped" ]; then
        emit_state Stopped 102 0
      fi
      if [ "$mode" = "post_issue_gone" ]; then
        emit_error 404 "Not Found"
      fi
      if [ "$mode" = "post_issue_denied" ]; then
        emit_error 403 "Forbidden"
      fi
      return 0
    }}
    if [ "$mode" = "deadline_edge" ]; then
      case "$qpath" in
        */state*) sleep 1.7 ;;
      esac
    fi
    if [ "$mode" = "query_blocked" ]; then
      # Blocks until released (60 s hang guard); a query that ever gets
      # past here leaves a marker.
      i=0
      while [ ! -f "$statedir/release-query" ] && [ "$i" -lt 1200 ]; do sleep 0.05; i=$((i+1)); done
      : > "$statedir/query-finished"
    fi
    if [ "$mode" = "slow_query_700" ]; then
      sleep 0.7
    fi
    if [ "$mode" = "slow_query_1200" ]; then
      sleep 1.2
    fi
    case "$qpath" in
      /1.0/storage-pools/default\?*)
        emit_project '{{"name":"default","driver":"dir","status":"Created","config":{{}}}}'
        ;;
      /1.0/storage-pools/default/resources\?*)
        emit_project '{{"space":{{"total":1099511627776,"used":68719476736}}}}'
        ;;
      /1.0/storage-pools/default/volumes/custom/wssp-pool-marker\?*)
        emit_project '{{"name":"wssp-pool-marker","type":"custom","content_type":"filesystem","config":{{"size":"1GiB","user.wssp.storage-id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}'
        ;;
      /1.0/storage-pools/default/volumes/virtual-machine/*/state\?*)
        if [ -f "$statedir/deleted-instance" ] || {{ [ "$mode" = "c37_start_gated" ] && [ ! -f "$statedir/launched" ]; }}; then emit_error 404 "Not Found"; fi
        emit_project '{{"usage":{{"total":34359738368}}}}'
        ;;
      /1.0/storage-pools/default/volumes/virtual-machine/*\?*)
        if [ -f "$statedir/deleted-instance" ] || {{ [ "$mode" = "c37_start_gated" ] && [ ! -f "$statedir/launched" ]; }}; then emit_error 404 "Not Found"; fi
        emit_project '{{"name":"wssp-sbx-sbx-1","type":"virtual-machine","content_type":"block","config":{{"size":"32GiB"}}}}'
        ;;
      /1.0/storage-pools/default/volumes\?*)
        if [ -f "$statedir/deleted-instance" ] || {{ [ "$mode" = "c37_start_gated" ] && [ ! -f "$statedir/launched" ]; }}; then emit_project '[]'; fi
        emit_project '[{{"name":"wssp-sbx-sbx-1","type":"virtual-machine","content_type":"block","config":{{"size":"32GiB"}}}}]'
        ;;
      /1.0/resources)
        if [ -f "$statedir/resources-response" ]; then cat "$statedir/resources-response"; exit 0; fi
        if [ "$mode" = "resources_denied" ]; then emit_error 403 "Forbidden"; fi
        if [ "$mode" = "resources_malformed" ]; then printf 'not json'; exit 0; fi
        if [ "$mode" = "resources_timeout" ]; then
          touch "$statedir/resources-entered"
          sleep 30
        fi
        printf '{{"type":"sync","status_code":200,"error_code":0,"metadata":{{"memory":{{"total":1234567890123}},"cpu":{{"total":93}}}}}}\n'
        exit 0
        ;;
      /1.0|/1.0\?*)
        # CVE-2025-52890 (GHSA-p7fw-vjjm-2rwp): 6.12/6.13 advertise
        # network_acl but cannot reliably enforce anti-spoofing; the fixed
        # boundary is 6.14.
        if [ "$mode" = "egress_daemon_unsupported" ]; then
          printf '{{"type":"sync","status_code":200,"error_code":0,"metadata":{{"api_extensions":[],"environment":{{"server_version":"6.14","server_name":"%s"}}}}}}\n' "shim-$(basename "$statedir")"
        elif [ "$mode" = "egress_old_daemon" ]; then
          printf '{{"type":"sync","status_code":200,"error_code":0,"metadata":{{"api_extensions":["network_acl"],"environment":{{"server_version":"5.21.2","server_name":"%s"}}}}}}\n' "shim-$(basename "$statedir")"
        elif [ "$mode" = "egress_vulnerable_6_12" ]; then
          printf '{{"type":"sync","status_code":200,"error_code":0,"metadata":{{"api_extensions":["network_acl"],"environment":{{"server_version":"6.12","server_name":"%s"}}}}}}\n' "shim-$(basename "$statedir")"
        elif [ "$mode" = "egress_vulnerable_6_13" ]; then
          printf '{{"type":"sync","status_code":200,"error_code":0,"metadata":{{"api_extensions":["network_acl"],"environment":{{"server_version":"6.13.1","server_name":"%s"}}}}}}\n' "shim-$(basename "$statedir")"
        else
          printf '{{"type":"sync","status_code":200,"error_code":0,"metadata":{{"api_extensions":["network_acl"],"environment":{{"server_version":"6.14","server_name":"%s"}}}}}}\n' "shim-$(basename "$statedir")"
        fi
        exit 0
        ;;
      /1.0/networks/*)
        nname=${{qpath#/1.0/networks/}}
        nname=${{nname%%\?*}}
        qproj=${{qpath#*project=}}
        qproj=${{qproj%%\&*}}
        qproj=${{qproj:-default}}
        # Test injection: the daemon cannot answer a network read.
        if [ -f "$statedir/fail-network-query" ] && [ "$method" != "PATCH" ]; then
          emit_error 500 "Internal Server Error"
        fi
        if [ -f "$statedir/networks/$nname.conf" ]; then
          rp=$(res_project "$statedir/networks/$nname")
          if [ "$rp" != "$qproj" ] && {{ [ "$qproj" = "default" ] || [ "$rp" != "default" ]; }}; then
            emit_error 404 "Not Found"
          fi
          if [ "$method" = "PATCH" ]; then
            # Config-merge PATCH. The body comes the ways real `incus query`
            # accepts one (E-26, cmd/incus/query.go 6.14.0-7.5.1):
            # `--data-file -` (stdin) or `--data-file <path>` (7.4+), or an
            # inline `-d <json>`. `-d` is NEVER a file or stdin reference:
            # Incus json-decodes the value and otherwise sends it as a JSON
            # string, which the network endpoint rejects with HTTP 400 — so
            # `-d @-` fails here exactly as it does on a real daemon. The
            # DNS publish path uses stdin because argv caps a single value
            # at MAX_ARG_STRLEN (128 KiB on 4 KiB-page Linux) and an
            # in-bound policy renders past that.
            # Test injection (C36 r9): publication itself consumes wall-clock
            # seconds (pin content = seconds per PATCH).
            if [ -f "$statedir/slow-publish" ]; then
              dns_work_delay "$(cat "$statedir/slow-publish")"
            fi
            body_file=$(mktemp "$statedir/.patch-body.XXXXXX")
            if [ -n "$data_inline" ] && [ -n "$data_file" ]; then
              rm -f "$body_file"
              echo "Error: --data cannot be used with --data-file" >&2
              exit 1
            fi
            case "$data_file" in
              -) cat > "$body_file" ;;
              '') printf '%s' "$data_inline" > "$body_file" ;;
              *) cat "$data_file" > "$body_file" ;;
            esac
            if ! python3 -c 'import json,sys; sys.exit(0 if isinstance(json.load(open(sys.argv[1])), dict) else 1)' "$body_file" 2>/dev/null; then
              rm -f "$body_file"
              emit_error 400 "json: cannot unmarshal string into Go value of type api.NetworkPut"
            fi
            # PROBE (c58-g1-r2 reviewer): crash-like fault injection. Let N
            # mutations (ACL rule add/remove, network PATCH/set) succeed,
            # then fail every later one until the pin is removed.
            if [ -s "$statedir/fail-mutations-after" ]; then
              left=$(cat "$statedir/fail-mutations-after")
              if [ "$left" -gt 0 ] 2>/dev/null; then
                echo $((left - 1)) > "$statedir/fail-mutations-after"
              else
                if [ -f "$statedir/crash-snapshot" ] && [ ! -d "$statedir.crash" ]; then cp -a "$statedir" "$statedir.crash"; fi
                if [ -f "$statedir/fail-mutations-uncertain" ]; then
                  echo "Error: Post \"https://incus.internal/1.0/network-acls/x\": read: connection reset by peer" >&2
                  exit 1
                fi
                echo "Error: injected crash" >&2
                exit 1
              fi
            fi
            if [ -f "$statedir/fail-raw-dnsmasq" ] && grep -q '"raw.dnsmasq"' "$body_file"; then
              rm -f "$body_file"
              echo "Error: dnsmasq reload failed" >&2
              exit 1
            fi
            python3 - "$statedir" "$nname" "$body_file" <<'PYPATCH'
import json,sys,pathlib
statedir = pathlib.Path(sys.argv[1])
name = sys.argv[2]
body = json.loads(pathlib.Path(sys.argv[3]).read_text())
conf_path = statedir / "networks" / (name + ".conf")
lines = conf_path.read_text().splitlines()
for key, value in body.get("config", {{}}).items():
    if key == "raw.dnsmasq":
        (statedir / "networks" / (name + ".raw")).write_text(value)
        continue
    lines = [l for l in lines if not l.startswith(key + "=")]
    lines.append(key + "=" + value)
conf_path.write_text("\n".join(lines) + "\n")
pathlib.Path(sys.argv[3]).unlink(missing_ok=True)
print(json.dumps({{"type":"sync","status_code":200,"error_code":0,"metadata":None}}))
PYPATCH
            exit 0
          fi
          python3 - "$statedir" "$nname" "$mode" <<'PYNET'
import json,sys,pathlib
statedir = pathlib.Path(sys.argv[1])
name = sys.argv[2]
conf = {{}}
for line in (statedir / "networks" / (name + ".conf")).read_text().splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        conf[k] = v
raw = statedir / "networks" / (name + ".raw")
if raw.exists():
    conf["raw.dnsmasq"] = raw.read_text()
if sys.argv[3] == "egress_readback_mismatch":
    conf.pop("security.acls.default.egress.action", None)
print(json.dumps({{"type":"sync","status_code":200,"error_code":0,"metadata":{{"name":name,"type":"bridge","managed":True,"config":conf}}}}))
PYNET
          exit 0
        fi
        emit_error 404 "Not Found"
        ;;
      /1.0/network-acls/*)
        aname=${{qpath#/1.0/network-acls/}}
        aname=${{aname%%\?*}}
        qproj=${{qpath#*project=}}
        qproj=${{qproj%%\&*}}
        qproj=${{qproj:-default}}
        if [ "$method" = PUT ]; then
          body_file=$(mktemp "$statedir/.acl-body.XXXXXX")
          case "$data_file" in
            -) cat > "$body_file" ;;
            '') printf '%s' "$data_inline" > "$body_file" ;;
            *) cat "$data_file" > "$body_file" ;;
          esac
          python3 - "$statedir" "$aname" "$body_file" "$if_match" "$mode" <<'PYACLPUT'
import json,sys,pathlib,fcntl,hashlib,time
root,name,body,header,mode = sys.argv[1:]
root = pathlib.Path(root)
base = root / "acls" / name
def fail(code, message):
    print(json.dumps({{"type":"error", "error_code":code, "error":message}}))
    sys.exit(1)
if not base.with_suffix(".conf").exists(): fail(404, "Not Found")
locks=[]
for direction in ("ingress", "egress"):
    lock=open(str(base)+"."+direction+".lock", "a")
    fcntl.flock(lock,fcntl.LOCK_EX)
    locks.append(lock)
def read_rules(direction):
    result=[]
    for line in pathlib.Path(str(base)+"."+direction).read_text().splitlines():
        fields=dict(token.split("=",1) for token in line.split() if "=" in token)
        fields.setdefault("state","enabled")
        # Go's NetworkACLRule fields, in declaration order, with omitempty.
        result.append({{k:fields.get(k,"") for k in ("action","source","destination","protocol","source_port","destination_port","icmp_type","icmp_code","description","state") if fields.get(k,"") or k in ("action","state")}})
    return result
conf=dict(line.split("=",1) for line in pathlib.Path(str(base)+".conf").read_text().splitlines() if "=" in line)
current=[name,"",read_rules("ingress"),read_rules("egress"),dict(sorted(conf.items()))]
encoded=json.dumps(current,separators=(",",":"),ensure_ascii=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")+"\n"
if header.strip('"') != hashlib.sha256(encoded.encode()).hexdigest(): fail(412, "ETag mismatch")
new=json.loads(pathlib.Path(body).read_text())
if mode in ("egress_rule_add_fail", "egress_apply_fail_teardown_fail") or (root/"fail-acl-rule-add").exists(): fail(400,"ACL update rejected")
if (root/"fail-acl-put").exists(): fail(400,"ACL update rejected")
if (root/"slow-acl-put").exists(): time.sleep(float((root/"slow-acl-put").read_text()))
# Snapshot the actual request for batch/atomicity assertions.
(root/"last-acl-put.json").write_text(json.dumps(new))
# Text files are the shim's canonical CLI-property representation, not JSON
# object insertion order. Enabled state is implicit here, as for rule-add;
# GET below always materializes it, just like the real daemon.
fields=("action","protocol","source","destination","source_port","destination_port","description","icmp_type","icmp_code","state")
for direction in ("ingress","egress"):
    pathlib.Path(str(base)+"."+direction).write_text("".join(" ".join(k+"="+str(rule[k]) for k in fields if k in rule and not (k=="state" and rule[k]=="enabled"))+"\n" for rule in new[direction]))
pathlib.Path(str(base)+".conf").write_text("".join(k+"="+v+"\n" for k,v in new["config"].items()))
pathlib.Path(body).unlink()
print(json.dumps({{"type":"sync","status_code":200,"error_code":0,"metadata":None}}))
PYACLPUT
          exit $?
        fi
        # Test injection (C36 r18 F4): the next N ACL READS fail with a
        # transport error (pin content = N, decremented per failure). A
        # failed expiry-lease observation must never settle obligations.
        # A permanent release wins over a decrement racing the test's release.
        # An in-flight reader may rewrite the counter after it was unlinked.
        if [ ! -f "$statedir/release-acl-read-failures" ] && [ -s "$statedir/fail-acl-read" ]; then
          fails_left=$(cat "$statedir/fail-acl-read")
          if [ "$fails_left" -gt 0 ] 2>/dev/null; then
            echo $((fails_left - 1)) > "$statedir/fail-acl-read"
            echo "Error: Get \"https://incus.internal/1.0/network-acls/$aname?project=default\": read: connection reset by peer" >&2
            exit 1
          fi
        fi
        # Test injection (C37 R4): succeed the next N ACL reads, then fail
        # exactly one with a transport error — models a failure landing on
        # the verification's INNER readback while the outer read succeeded.
        if [ -s "$statedir/fail-acl-read-after" ]; then
          skips_left=$(cat "$statedir/fail-acl-read-after")
          if [ "$skips_left" -gt 0 ] 2>/dev/null; then
            echo $((skips_left - 1)) > "$statedir/fail-acl-read-after"
          else
            rm -f "$statedir/fail-acl-read-after"
            echo "Error: Get \"https://incus.internal/1.0/network-acls/$aname?project=default\": read: connection reset by peer" >&2
            exit 1
          fi
        fi
        # Test injection (C37 R4): ONE ACL read fails with a transport
        # error, but only once the instance EXISTS (post-start) — so a
        # create's apply-time reads succeed and the failure lands exactly
        # on the readiness observation.
        if [ -f "$statedir/fail-acl-read-once-running" ]; then
          if [ -f "$started" ]; then
            rm -f "$statedir/fail-acl-read-once-running"
            echo "Error: Get \"https://incus.internal/1.0/network-acls/$aname?project=default\": read: connection reset by peer" >&2
            exit 1
          fi
        fi
        if [ -f "$statedir/acls/$aname.conf" ]; then
          rp=$(res_project "$statedir/acls/$aname")
          if [ "$rp" != "$qproj" ] && {{ [ "$qproj" = "default" ] || [ "$rp" != "default" ]; }}; then
            emit_error 404 "Not Found"
          fi
          python3 - "$statedir" "$aname" "$mode" <<'PYACL'
import json,sys,pathlib,fcntl
statedir = pathlib.Path(sys.argv[1])
name = sys.argv[2]
conf = {{}}
for line in (statedir / "acls" / (name + ".conf")).read_text().splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        conf[k] = v
# The real daemon serves a consistent snapshot; rule files are mutated
# under an exclusive flock (C36 r19), so readers take the shared lock to
# never observe a torn read-modify-write.
locks = []
for direction in ("ingress", "egress"):
    lockf = open(statedir / "acls" / (name + "." + direction + ".lock"), "a")
    fcntl.flock(lockf, fcntl.LOCK_SH)
    locks.append(lockf)
def rules(direction):
    out = []
    for line in (statedir / "acls" / (name + "." + direction)).read_text().splitlines():
        rule = {{}}
        for token in line.split():
            if "=" in token:
                k, v = token.split("=", 1)
                rule[k] = v
        # Incus reports every rule with an explicit effective state.
        if sys.argv[3] != "egress_rule_state_missing":
            rule.setdefault("state", "enabled")
        out.append(rule)
    return out
print(json.dumps({{"type":"sync","status_code":200,"error_code":0,"metadata":{{"name":name,"config":conf,"ingress":rules("ingress"),"egress":rules("egress")}}}}))
PYACL
          exit 0
        fi
        emit_error 404 "Not Found"
        ;;
      /1.0/images/aliases/*)
        if [ "$mode" = "image_missing_project" ]; then emit_error 404 "Project not found"; fi
        if [ "$mode" = "image_missing_project_generic" ]; then emit_error 404 "Not Found"; fi
        if [ "$mode" = "image_missing_project_cli_generic" ]; then printf 'Error: not found\n' >&2; exit 1; fi
        if [ "$mode" = "image_missing_751_json" ]; then python3 -c 'import json; print(json.dumps({{"type":"error","error_code":404,"error":"Image \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\" not found"}}))'; exit 1; fi
        if [ "$mode" = "image_missing_751_cli" ]; then printf 'Error: Image "ubuntu/24.04/cloud" not found\n' >&2; exit 1; fi
        if [ "$mode" = "image_missing_json" ]; then emit_error 404 "Not Found"; fi
        if [ "$mode" = "image_missing_751_cli_mismatch" ]; then printf 'Error: Image "different-image" not found\n' >&2; exit 1; fi
        if [ "$mode" = "image_missing_cli" ]; then printf 'Error: Image not found\n' >&2; exit 1; fi
        target=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
        [ ! -f "$statedir/alias-moved" ] || target=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        printf '{{"type":"sync","status_code":200,"error_code":0,"metadata":{{"target":"%s","type":"virtual-machine"}}}}\n' "$target"
        exit 0
        ;;
      /1.0/images/*)
        if [ "$mode" = "image_missing_project" ]; then emit_error 404 "Project not found"; fi
        if [ "$mode" = "image_missing_project_generic" ]; then emit_error 404 "Not Found"; fi
        if [ "$mode" = "image_missing_project_cli_generic" ]; then printf 'Error: not found\n' >&2; exit 1; fi
        if [ "$mode" = "image_missing_751_json" ]; then python3 -c 'import json; print(json.dumps({{"type":"error","error_code":404,"error":"Image \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\" not found"}}))'; exit 1; fi
        if [ "$mode" = "image_missing_751_cli" ]; then printf 'Error: Image "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" not found\n' >&2; exit 1; fi
        if [ "$mode" = "image_missing_json" ]; then emit_error 404 "Not Found"; fi
        if [ "$mode" = "image_missing_751_cli_mismatch" ]; then printf 'Error: Image "different-image" not found\n' >&2; exit 1; fi
        if [ "$mode" = "image_missing_cli" ]; then printf 'Error: Image not found\n' >&2; exit 1; fi
        fp=${{qpath#/1.0/images/}}
        fp=${{fp%%\?*}}
        python3 - "$statedir" "$fp" <<'PYIMAGE'
import json,sys,pathlib
statedir = pathlib.Path(sys.argv[1])
properties = {{"os": "Ubuntu", "description": "test image"}}
p = statedir / "image-config"
if p.exists():
    properties.update(line.split("=", 1) for line in p.read_text().splitlines() if "=" in line)
print(json.dumps({{"type":"sync", "status_code":200, "error_code":0,
    "metadata":{{"fingerprint":sys.argv[2], "architecture":"x86_64", "type":"virtual-machine", "properties":properties}}}}))
PYIMAGE
        exit 0
        ;;
      /1.0/projects/*)
        case "$mode" in
          image_missing_project|image_missing_project_generic|image_missing_project_cli_generic) emit_error 404 "Not Found" ;;
        esac
        pname=${{qpath#/1.0/projects/}}
        pname=${{pname%%\?*}}
        if [ -f "$statedir/project-$pname" ]; then
          emit_project "$(cat "$statedir/project-$pname")"
        fi
        if [ "$pname" = "default" ]; then
          emit_project '{{"name":"default","config":{{}}}}'
        fi
        if [ "$pname" = "custom" ]; then
          emit_project '{{"name":"custom","config":{{"features.profiles":"false","features.images":"false","features.storage.volumes":"true"}}}}'
        fi
        emit_error 404 "Not Found"
        ;;
      */files*)
        query_deny
        if [ "$mode" = "push_fail_error_json" ]; then
          printf '{{"type":"error","error_code":401,"error":"guest file bytes"}}'
          exit 0
        fi
        printf 'guest-file-bytes\n'
        exit 0
        ;;
      */state*)
        case "$mode" in
          fix6_*_denied) emit_error 403 "Forbidden" ;;
          fix6_*_garbled) printf 'garbled'; exit 0 ;;
          fix6_*_absent) emit_error 404 "Not Found" ;;
          fix6_*_stopped) emit_state Stopped 102 0 ;;
        esac
        if [ "$mode" = "pull_flaky_query" ] && [ -f "$statedir/read-issued" ]; then
          rm -f "$statedir/read-issued"
          emit_error 500 "Internal Server Error"
        fi
        query_deny
        post_issue_inventory && exit 0
        if [ -f "$statedir/stopped-instance" ]; then
          emit_state Stopped 102 0
        fi
        if {{ [ "$mode" = "stopped" ] || [ "$mode" = "c32_delayed_init" ]; }} && [ ! -f "$started" ]; then
          emit_state Stopped 102 0
        fi
        hits=0
        if [ -f "$statehits" ]; then
          hits=$(cat "$statehits")
        fi
        hits=$((hits + 1))
        printf '%s' "$hits" > "$statehits"
        # Guest-initiated reboot (Ubuntu 26.04 first boot): once the agent has
        # been seen, the VM is Stopped for `reboot-down` state reads, then
        # Running again under a new QEMU pid.
        case "$mode" in
          first_boot_reboot|reboot_mid_readiness|reboot_stays_stopped|reboot_loop|reboot_error_state|teardown_error_agent_wait|teardown_error_mid_readiness|reboot_after_every_pass|frozen_after_check|slow_network|same_pid_reset|stopped_then_stalled|stopped_then_metadata_stall|slow_metadata_after_network|raw_identity|bootstrap_reboot_once|bootstrap_reboot_always)
            if [ "$mode" = slow_metadata_after_network ] && [ -f "$statedir/network-done" ]; then
              printf '3' > "$statedir/slow-metadata"
            fi
            # After the first Stopped read every binding refresh stalls.
            if [ "$mode" = stopped_then_metadata_stall ] && [ -f "$statedir/rebooting" ]; then
              printf '30' > "$statedir/slow-metadata"
              emit_state Stopped 102 -1 0
            fi
            [ ! -f "$statedir/frozen" ] || emit_state Frozen 110 1 0
            # After the first Stopped read every state query stalls.
            if [ -f "$statedir/stalling" ]; then sleep 30; emit_state Stopped 102 -1 0; fi
            if [ "$mode" = stopped_then_stalled ] && [ -f "$statedir/rebooting" ]; then
              : > "$statedir/stalling"
              emit_state Stopped 102 -1 0
            fi
            if [ -f "$statedir/rebooting" ]; then
              down=$(cat "$statedir/rebooting")
              if [ "$mode" = reboot_error_state ]; then emit_state Error 112 -1 0; fi
              # Incus reports Error while the old QEMU process is still alive
              # but its monitor is gone: one read as the reboot tears it down.
              case "$mode" in
                teardown_error_*)
                  if [ ! -f "$statedir/teardown-error" ]; then
                    : > "$statedir/teardown-error"
                    emit_state Error 112 -1 0
                  fi
                  ;;
              esac
              if [ "$mode" = reboot_stays_stopped ] || [ "$down" -gt 0 ]; then
                printf '%s' "$((down - 1))" > "$statedir/rebooting"
                emit_state Stopped 102 -1 0
              fi
              rm -f "$statedir/rebooting"
              boots=$(cat "$statedir/boots" 2>/dev/null || echo 1)
              printf '%s' "$((boots + 1))" > "$statedir/boots"
            fi
            emit_state Running 103 1 "$((100 + $(cat "$statedir/boots" 2>/dev/null || echo 1)))"
            ;;
        esac
        processes=1
        if [ "$mode" = "agent_down" ] || [ "$mode" = "c37_agent_down" ] || [ "$mode" = "metrics_disabled" ] || [ "$mode" = "agent_warming" ]; then
          processes=-1
        fi
        if [ "$mode" = "agent_down_after_ready" ] && [ "$hits" -gt 1 ]; then
          processes=-1
        fi
        emit_state Running 103 "$processes"
        ;;
      *)
        if [ -f "$statedir/fail-instance-read" ]; then emit_error 503 "Temporarily unavailable"; fi
        # Instance metadata (the binding refresh) stalls once the test armed it.
        if [ -f "$statedir/slow-metadata" ]; then sleep "$(cat "$statedir/slow-metadata")"; fi
        if [ -f "$statedir/deleted-instance" ]; then
          emit_error 404 "Not Found"
        fi
        case "$mode" in
          fix6_new_*|c32_delayed_init) [ -f "$statedir/launched" ] || emit_error 404 "Not Found" ;;
          fix6_launch_absent) emit_error 404 "Not Found" ;;
          fix6_cold_*) [ -f "$started" ] || emit_instance Stopped 102 ;;
          # C37: a fresh-init lifecycle with a truthful power state — absent
          # until init, Stopped until start lands (models a crash between
          # init and start, or a start whose evidence never arrives).
          c37_start_gated | c37_agent_down)
            if [ ! -f "$statedir/launched" ]; then emit_error 404 "Not Found"; fi
            # E-11: a post-start power state other than Stopped/Running.
            if [ -f "$statedir/instance-status" ]; then
              read -r forced_status forced_code < "$statedir/instance-status"
              emit_instance "$forced_status" "$forced_code"
            fi
            if [ ! -f "$started" ]; then emit_instance Stopped 102; fi
            ;;
        esac
        query_deny
        if [ -f "$statedir/post-issue-effect" ]; then
          if [ "$mode" = "lifecycle_post_query_denied" ]; then
            emit_error 403 "Forbidden"
          fi
          if [ "$mode" = "post_issue_gone" ]; then
            emit_error 404 "Not Found"
          fi
          if [ "$mode" = "post_issue_denied" ]; then
            emit_error 403 "Forbidden"
          fi
          if [ "$mode" = "post_issue_stopped" ]; then
            emit_instance Stopped 102
          fi
        fi
        if [ -f "$statedir/deleted-instance" ]; then
          emit_error 404 "Not Found"
        fi
        if [ -f "$statedir/stopped-instance" ]; then
          emit_instance Stopped 102
        fi
        if [ "$mode" = "lifecycle_incomplete_start" ]; then
          emit_instance Stopped 102
        fi
        if {{ [ "$mode" = "stopped" ] || [ "$mode" = "c32_delayed_init" ] || [ "$mode" = "egress_legacy_nic_stopped" ] || [ "$mode" = "egress_drifted_local_nic_stopped" ]; }} && [ ! -f "$started" ]; then
          emit_instance Stopped 102
        fi
        emit_instance Running 103
        ;;
    esac
    ;;
  config)
    case "$mode" in fix6_metadata) exit 1 ;; esac
    if [ "$1" = "device" ] && [ "$2" = "override" ]; then
      # fail-device-override: pin file makes the NIC repair fail (read-back/
      # repair failure inside the reconnect crash window).
      if [ -f "$statedir/fail-device-override" ]; then
        echo "Error: device override rejected" >&2
        exit 1
      fi
      # config device override <instance> <device> k=v... — Incus semantics:
      # override only applies to INHERITED devices; a local device (recorded
      # by init --device or a previous set) cannot be overridden.
      dev=$4
      if [ -f "$statedir/device-$dev" ]; then
        echo "Error: The device already exists" >&2
        exit 1
      fi
      shift 4 || true
      # Incus semantics: override starts from the INHERITED device and
      # applies the given keys — unspecified inherited properties SURVIVE.
      merged="$dev"
      profile_spec="type=nic,network=incusbr0"
      if [ -f "$statedir/profile-$dev" ]; then
        profile_spec=$(cat "$statedir/profile-$dev")
      fi
      for kv in $profile_spec "$@"; do
        case "$kv" in
        *=*)
          key=${{kv%%=*}}
          merged=$(printf '%s' "$merged" | tr ',' '\n' | grep -v "^$key=" | grep -v '^$' | tr '\n' ',')
          merged="${{merged%,}}"
          merged="$merged,$kv"
          ;;
        esac
      done
      validate_bridged_nic_spec "$merged"
      printf '%s' "$merged" > "$statedir/device-$dev"
      exit 0
    fi
    if [ "$1" = "device" ] && [ "$2" = "set" ]; then
      # config device set <instance> <device> k=v... — Incus semantics: set
      # only applies to LOCAL devices; an inherited device needs override.
      dev=$4
      if [ ! -f "$statedir/device-$dev" ]; then
        echo "Error: The device doesn't exist" >&2
        exit 1
      fi
      shift 4 || true
      # Incus semantics: set MERGES keys into the local device — properties
      # not named on the command line are preserved.
      merged=$(cat "$statedir/device-$dev")
      for kv in "$@"; do
        case "$kv" in
        *=*)
          key=${{kv%%=*}}
          merged=$(printf '%s' "$merged" | tr ',' '\n' | grep -v "^$key=" | grep -v '^$' | tr '\n' ',')
          merged="${{merged%,}}"
          merged="$merged,$kv"
          ;;
        esac
      done
      validate_bridged_nic_spec "$merged"
      printf '%s' "$merged" > "$statedir/device-$dev"
      exit 0
    fi
    if [ "$1" = "device" ] && [ "$2" = "add" ]; then
      # config device add <instance> <device> <type> k=v... — Incus
      # semantics: creates a LOCAL device; a local device with the profile
      # device's name REPLACES the inherited one wholesale (unlike
      # override, which merges keys).
      dev=$4
      if [ -f "$statedir/device-$dev" ]; then
        echo "Error: The device already exists" >&2
        exit 1
      fi
      # fail-device-add: pin file makes the NIC replacement fail.
      if [ -f "$statedir/fail-device-add" ]; then
        echo "Error: device add rejected" >&2
        exit 1
      fi
      shift 5 || true
      spec=$(printf '%s' "$*" | tr ' ' ',')
      validate_bridged_nic_spec "$dev,$spec"
      printf '%s' "$dev,$spec" > "$statedir/device-$dev"
      exit 0
    fi
    if [ "$1" = "device" ] && [ "$2" = "remove" ]; then
      # config device remove <instance> <device> — local devices only.
      dev=$4
      if [ ! -f "$statedir/device-$dev" ]; then
        echo "Error: The device doesn't exist" >&2
        exit 1
      fi
      rm "$statedir/device-$dev"
      exit 0
    fi
    if [ "$2" != "--" ]; then
      echo "Error: config positionals require --" >&2
      exit 1
    fi
    if [ "$mode" = "json_cli_error" ]; then
      printf '{{"type":"error","error":"Forbidden","error_code":403}}\n'
      exit 1
    fi
    if [ "$mode" = "gone" ]; then
      echo "Error: Instance not found" >&2
      exit 1
    fi
    if [ "$mode" = "permission" ]; then
      echo "Error: Permission denied" >&2
      exit 1
    fi
    if [ "$mode" = "mixed_inventory_fallback" ]; then
      [ "$3" = "wssp-sbx-sbx-1" ] || exit 1
      printf 'sbx-1\n'
      exit 0
    fi
    sub=$1
    shift
    shift
    inst=$1
    key=$2
    val=$3
    if [ "$sub" = "set" ]; then
      if [ "$mode" != "config_set_no_readback" ]; then
        mkdir -p "$statedir/config"
        printf '%s' "$val" > "$statedir/config/$key"
      fi
      exit 0
    fi
    if [ "$sub" = "get" ]; then
      if [ -f "$statedir/config/$key" ]; then
        cat "$statedir/config/$key"
      fi
      exit 0
    fi
    exit 0
    ;;
  exec)
    execcwd=
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do
      [ "$1" != --cwd ] || execcwd=${{2:-}}
      shift
    done
    [ "$1" = "--" ] && shift
    # A template whose declared uid cannot enter the 0750 HOME: as that uid,
    # every exec with HOME as its cwd is "Command not executable" (126).
    if {{ [ "$mode" = "home_not_searchable" ] || [ "$mode" = raw_identity ] || [ "${{mode#bootstrap_}}" != "$mode" ]; }} && [ "$execcwd" = /home/user ]; then
      echo "Error: Command not executable" >&2
      exit 126
    fi
    # Plan §10: the root retire helper and the guest boot read report the
    # verdict/boot the test planted (never a host cgroup or boot id).
    if [ "${{1:-}}" = python3 ] && [ "${{4:-}}" = -B ] && [ "${{5:-}}" = -c ]; then
      case "${{6:-}}" in
        *"wssp guest-sudo-helper"*)
          printf '%s\n' "$7" >> "$statedir/sudo-log"
          case "$7" in
            grant) verdict='granted sudo_ws' ;;
            revoke) verdict='revoked sudo_ws' ;;
            *) verdict='clean sudo_ws' ;;
          esac
          if [ -f "$statedir/sudo-verdict-$7" ]; then verdict=$(cat "$statedir/sudo-verdict-$7"); fi
          printf 'WSSP_SUDO %s %s\n' "$8" "$verdict" >&2
          exit 0
          ;;
        *"wssp root-grow-helper"*)
          printf '%s %s\n' "$7" "$9" >> "$statedir/root-log"
          part=$(( $9 - 1048576 ))
          verdict="$9 $9 $part ext4 $part partition $part"
          if [ -f "$statedir/root-verdict" ]; then verdict=$(cat "$statedir/root-verdict"); fi
          printf 'WSSP_ROOT %s %s\n' "$8" "$verdict" >&2
          exit 0
          ;;
        *"Plan §10 retire helper"*)
          verdict=absent
          if [ -f "$statedir/retire-verdict" ]; then verdict=$(cat "$statedir/retire-verdict"); fi
          boot=00000000-0000-4000-8000-000000000001
          if [ -f "$statedir/retire-boot" ]; then boot=$(cat "$statedir/retire-boot"); fi
          printf 'WSSP_RETIRE %s %s %s\n' "$8" "$boot" "$verdict" >&2
          exit 0
          ;;
      esac
    fi
    if [ "${{1:-}}" = /bin/sh ] && [ "${{4:-}}" = wssp-boot ]; then
      [ "$mode" != boot_unreadable ] || exit 1
      boot=00000000-0000-4000-8000-000000000001
      if [ -f "$statedir/retire-boot" ]; then boot=$(cat "$statedir/retire-boot"); fi
      printf 'WSSP_BOOT %s %s\n' "$5" "$boot" >&2
      exit 0
    fi
    # The real helper drops root after initgroups; the shim never runs it
    # against host accounts. Preserve the inner fixture command exactly.
    if [ "${{2:-}}" = -I ] && [ "${{3:-}}" = -S ] && [ "${{4:-}}" = -c ]; then shift 8; fi
    guestcmd=${{1:-}}
    # Normalize the signal-only missing-interpreter launcher for the shim's
    # helper fault modes; passthrough still executes the exact Python source.
    if [ "$guestcmd" = /bin/sh ] && [ "${{4:-}}" = wssp-signal ]; then
      shift 4
      set -- python3 -I -c "$@"
      guestcmd=python3
    fi
    case "$guestcmd" in
      systemctl)
        # Bootstrap readiness's boot settle. A raw upstream guest (raw_*,
        # bootstrap_*) has no /home/user; the settle never needs it.
        n=$(cat "$statedir/settles" 2>/dev/null || echo 0)
        printf '%s' "$((n + 1))" > "$statedir/settles"
        if [ "$*" != "systemctl is-system-running --wait" ]; then exit 2; fi
        # The guest reboots under the settle: the first time, or every time.
        if {{ [ "$mode" = bootstrap_reboot_once ] && [ "$n" -eq 0 ]; }} || [ "$mode" = bootstrap_reboot_always ]; then
          printf '0' > "$statedir/rebooting"
          exit 137
        fi
        case "$mode" in
          bootstrap_degraded) echo degraded; exit 1 ;;
          bootstrap_maintenance) echo maintenance; exit 1 ;;
          bootstrap_starting_once) if [ "$n" -eq 0 ]; then echo starting; exit 1; fi ;;
        esac
        echo running
        exit 0
        ;;
      true)
        if [ "$mode" = "probe_denied" ]; then
          echo "Error: Permission denied" >&2
          exit 1
        fi
        if [ "$mode" = "agent_down" ] || [ "$mode" = "c37_agent_down" ]; then
          echo "Error: The instance's agent isn't currently running" >&2
          exit 1
        fi
        # The first agent probe lands as the guest reboots (reboot_loop: every
        # probe does): the VM goes down for one state read.
        if {{ [ "$mode" = first_boot_reboot ] || [ "$mode" = reboot_stays_stopped ] || [ "$mode" = reboot_error_state ] || [ "$mode" = teardown_error_agent_wait ] || [ "$mode" = stopped_then_stalled ] || [ "$mode" = stopped_then_metadata_stall ]; }} && [ ! -f "$statedir/boots" ]; then
          printf '1' > "$statedir/rebooting"
          echo "Error: The instance's agent isn't currently running" >&2
          exit 1
        fi
        if [ "$mode" = reboot_loop ]; then
          printf '1' > "$statedir/rebooting"
          echo "Error: The instance's agent isn't currently running" >&2
          exit 1
        fi
        if [ "$mode" = "agent_warming" ]; then
          probehits="$statedir/probehits"
          phits=0
          if [ -f "$probehits" ]; then
            phits=$(cat "$probehits")
          fi
          phits=$((phits + 1))
          printf '%s' "$phits" > "$probehits"
          if [ "$phits" -eq 1 ]; then
            echo "Error: The instance's agent isn't currently running" >&2
            exit 1
          fi
        fi
        : > "$ready"
        exit 0
        ;;
      python3|/usr/bin/python3|/usr/local/bin/python3)
        if [ "${{2:-}}" != "-I" ]; then echo "helper must run isolated" >&2; exit 1; fi
        action=${{5:-}}
        nonce=${{7:-}}
        # Test injection: hold the real group-pidfd signal helper in flight
        # (before it runs) until released or its transport is killed.
        if [ "$mode" = "passthrough" ] && [ "$action" = wssp-signal ] && [ -f "$statedir/hold-signal-helper" ]; then
          : > "$statedir/signal-helper-entered"
          while [ ! -f "$statedir/release-signal-helper" ]; do sleep 0.01; done
          : > "$statedir/signal-helper-resumed"
          exec "$@"
        fi
        # WSSP_PYTHON_TRANSPORT_HOOK
        if [ "$mode" = "passthrough" ] || [ "$mode" = "noready" ]; then exec "$@"; fi
        if [ "$mode" = "slow_listing" ]; then exec python3 "$statedir/inject.py" "$@"; fi
        if [ -f "$statedir/record-then-drop" ]; then
          : > "$statedir/post-issue-effect"
          printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
          echo 'Error: websocket: close 1006 (abnormal closure)' >&2
          exit 1
        fi
        if [ "$action" = stat ] || [ "$action" = list ] || [ "$action" = mkdir ] || [ "$action" = ensure-dir ] || [ "$action" = remove ] || [ "$action" = rename ]; then
          case "$mode" in
            post_issue_stopped|post_issue_gone|post_issue_denied) : > "$statedir/post-issue-effect"; exit 1;;
            cli_transport_loss) exit 1;;
          esac
          case "$mode" in
            enoent|filename_enoent) printf 'WSSP_STATUS %s fs_not_found none\n' "$nonce" >&2; exit 1;;
            guest_perm) printf 'WSSP_STATUS %s fs_permission_denied none\n' "$nonce" >&2; exit 1;;
            exec_denied|exec_no_banner|exec_guest_error_text|agent_down|agent_down_after_ready) echo 'sentinel guest diagnostic' >&2; exit 1;;
          esac
          if [ "$mode" = stopped ] && [ ! -f "$started" ]; then exit 1; fi
          case "$action" in
            mkdir|ensure-dir|remove|rename)
              printf 'WSSP_COMMIT_READY %s\n' "$nonce"
              fence=$(dd bs=1 count=1 2>/dev/null)
              if [ "$fence" != C ]; then : > "$statedir/fence-refused"; printf 'WSSP_STATUS %s cancelled none\n' "$nonce" >&2; exit 1; fi
              ;;
          esac
          python3 -I -c 'import json,sys; action,path,options=sys.argv[1:]; o=json.loads(options); entry=dict(name=path.rsplit("/",1)[-1] or "/",path=path,type="file",size=4,mode=420,permissions="rw-r--r--",uid=1000,gid=1000,owner=None,group=None,modifiedTime=None,symlinkTarget=None); target=o.get("destPath",path); entry["path"]=target; entry["name"]=target.rsplit("/",1)[-1] or "/"; result=dict(type="file.stat",entry=entry) if action=="stat" else dict(type="file.mkdir",created=True) if action in ("mkdir","ensure-dir") else dict(type="file.remove",removed=True) if action=="remove" else dict(type="file.rename",entry=entry) if action=="rename" else dict(type="file.list",path=path,depth=o["depth"],items=[],nextCursor=None,consistency="live"); print(json.dumps(dict(result=result,continuation=None)))' "$action" "${{6:-}}" "${{9:-}}"
          printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
          exit 0
        fi
        if [ "$action" = read ]; then
          case "$mode" in
            enoent|filename_enoent) printf 'WSSP_STATUS %s fs_not_found none\n' "$nonce" >&2; exit 1;;
            guest_perm) printf 'WSSP_STATUS %s fs_permission_denied none\n' "$nonce" >&2; exit 1;;
            read_denied) exit 1;;
          esac
        fi
        if [ "$mode" = "pull_flaky_query" ] && [ "$action" = "read" ]; then
          : > "$statedir/read-issued"
          printf 'WSSP_STATUS %s fs_is_directory none\n' "$nonce" >&2
          exit 1
        fi
        if [ "$mode" = "pull_ok_nonzero" ] && [ "$action" = "read" ]; then
          printf 'guest-file-bytes\n'
          printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
          exit 1
        fi
        case "$mode" in
          post_issue_stopped|post_issue_gone|post_issue_denied) : > "$statedir/post-issue-effect"; exit 1;;
          file_eloop|permission|files_denied|push_fail_error_json|cli_transport_loss|files_storage_error|agent_down|agent_down_after_ready) exit 1;;
        esac
        if [ "$action" = "read" ]; then printf 'guest-file-bytes\n'; fi
        if [ "$action" = "put" ]; then
          dd bs=1 count="${{8:-0}}" of=/dev/null 2>/dev/null
          printf 'WSSP_COMMIT_READY %s\n' "$nonce"
          fence=$(dd bs=1 count=1 2>/dev/null)
          if [ "$fence" != C ]; then printf 'WSSP_STATUS %s cancelled none\n' "$nonce" >&2; exit 1; fi
        fi
        printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
        exit 0
        ;;
      /bin/sh|sh)
        helper=${{4:-}}
        nonce=${{5:-}}
        gpath=${{6:-}}
        if {{ [ "$mode" = "stopped" ] || [ "$mode" = "c32_delayed_init" ]; }} && [ ! -f "$started" ]; then
          echo "Error: The instance isn't running" >&2
          exit 1
        fi
        if [ "$mode" = "exec_denied" ]; then
          echo "Error: Permission denied" >&2
          exit 1
        fi
        if [ "$mode" = "cli_transport_loss" ]; then
          echo "Error: simulated transport loss after helper exec" >&2
          exit 1
        fi
        if [ "$mode" = "post_issue_stopped" ] || [ "$mode" = "post_issue_gone" ] || [ "$mode" = "post_issue_denied" ]; then
          : > "$statedir/post-issue-effect"
          echo "Error: simulated transport loss after effect" >&2
          exit 1
        fi
        if [ "$mode" = "agent_down" ] || [ "$mode" = "c37_agent_down" ] || [ "$mode" = "agent_down_after_ready" ]; then
          echo "Error: The instance's agent isn't currently running" >&2
          exit 1
        fi
        # Test injection (G3R-1): the terminate helper really runs, but its
        # reply is lost in transport.
        if [ "$mode" = "passthrough" ] && [ "$helper" = wssp-terminate ] && [ -f "$statedir/lose-terminate-reply" ]; then
          "$@" 2>/dev/null
          echo "Error: websocket: close 1006 (abnormal closure)" >&2
          exit 1
        fi
        if [ "$mode" = "passthrough" ] || [ "$mode" = "noready" ]; then
          exec "$@"
        fi
        if [ "$mode" = "exec_no_banner" ]; then
          echo "Error: Instance not found" >&2
          exit 1
        fi
        if [ "$mode" = "exec_guest_error_text" ]; then
          echo "Error: Instance not found" >&2
          printf 'WSSP_STATUS %s guest_operation_failed\n' "$nonce" >&2
          exit 1
        fi
        case "$helper" in
          wssp-readable)
            if [ "$mode" = "enoent" ] || [ "$mode" = "filename_enoent" ]; then
              printf "stat: cannot statx '%s': No such file or directory\n" "$gpath" >&2
              exit 1
            fi
            [ "$mode" != "read_denied" ] || exit 1
            printf 'WSSP_READABLE %s\n' "$nonce"
            exit 0
            ;;
          wssp-readiness)
            case "$mode" in
              missing_user|home_not_searchable|raw_identity|bootstrap_*) printf 'WSSP_NOT_READY %s user\n' "$nonce"; exit 1 ;;
              wrong_home) printf 'WSSP_NOT_READY %s home\n' "$nonce"; exit 1 ;;
              wrong_shell) printf 'WSSP_NOT_READY %s shell\n' "$nonce"; exit 1 ;;
              wrong_arch) printf 'WSSP_NOT_READY %s arch\n' "$nonce"; exit 1 ;;
              missing_agent) printf 'WSSP_NOT_READY %s injected-text\n' "$nonce"; exit 1 ;;
            esac
            # The guest reboots under the first readiness script: it dies
            # without its record and the VM restarts under a new QEMU pid.
            if {{ [ "$mode" = reboot_mid_readiness ] || [ "$mode" = teardown_error_mid_readiness ]; }} && [ ! -f "$statedir/boots" ]; then
              printf '0' > "$statedir/rebooting"
              exit 137
            fi
            # Incus resets the guest inside the same QEMU process: the state
            # stays Running under the same pid, only the boot id changes.
            if [ "$mode" = same_pid_reset ] && [ ! -f "$statedir/reset-done" ]; then
              : > "$statedir/reset-done"
              printf '00000000-0000-4000-8000-000000000002' > "$statedir/retire-boot"
              exit 137
            fi
            printf 'WSSP_READY %s\n' "$nonce"
            exit 0
            ;;
          wssp-linger)
            case "$mode" in
              linger_allowed) printf 'WSSP_LINGER %s allowed\n' "$nonce" ;;
              linger_enabled) printf 'WSSP_LINGER %s enabled\n' "$nonce" ;;
              *) printf 'WSSP_LINGER %s blocked\n' "$nonce" ;;
            esac
            exit 0
            ;;
          wssp-network)
            [ "$mode" != no_guest_network ] || exit 3
            # The guest reboots (new QEMU pid) right after every pass.
            if [ "$mode" = reboot_after_every_pass ]; then
              boots=$(cat "$statedir/boots" 2>/dev/null || echo 1)
              printf '%s' "$((boots + 1))" > "$statedir/boots"
            fi
            [ "$mode" != frozen_after_check ] || : > "$statedir/frozen"
            [ "$mode" != slow_network ] || sleep 10
            # The last check takes 1.5 s; the binding refresh after the next
            # state read (the final boot read's) then stalls 3 s.
            if [ "$mode" = slow_metadata_after_network ]; then sleep 1.5; : > "$statedir/network-done"; fi
            printf 'WSSP_NET %s\n' "$nonce"
            exit 0
            ;;
          wssp-stat|wssp-list|wssp-mkdir|wssp-remove|wssp-move)
            if [ "$mode" = "gone" ]; then
              echo "Error: Instance not found" >&2
              exit 1
            fi
            if [ "$mode" = "enoent" ] || [ "$mode" = "filename_enoent" ]; then
              printf "stat: cannot statx '%s': No such file or directory\n" "$gpath" >&2
              printf 'WSSP_STATUS %s guest_operation_failed\n' "$nonce" >&2
              exit 1
            fi
            if [ "$mode" = "guest_perm" ]; then
              printf "stat: cannot statx '%s': Permission denied\n" "$gpath" >&2
              printf 'WSSP_STATUS %s guest_operation_failed\n' "$nonce" >&2
              exit 1
            fi
            if [ "$mode" = "permission" ]; then
              echo "Error: Permission denied" >&2
              exit 1
            fi
            if [ "$helper" = "wssp-stat" ]; then
              printf 'regular file|4|644\n'
            fi
            printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
            exit 0
            ;;
          wssp-kill)
            if [ "$mode" = "passthrough" ]; then
              target=${{6:-}}
              sig=${{7:-}}
              kill -s "$sig" -- "$target" 2>/dev/null || true
              printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
              exit 0
            fi
            if [ "$mode" = "gone" ] || [ "$mode" = "kill_nosuch_instance" ]; then
              echo "Error: No such instance" >&2
              exit 1
            fi
            if [ "$mode" = "guest_perm" ]; then
              printf 'WSSP_STATUS %s guest_permission_denied\n' "$nonce" >&2
              exit 1
            fi
            if [ "$mode" = "kill_nosuch_process" ]; then
              printf 'WSSP_STATUS %s process_not_found\n' "$nonce" >&2
              exit 1
            fi
            if [ "$mode" = "permission" ]; then
              echo "Error: Permission denied" >&2
              exit 1
            fi
            printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
            exit 0
            ;;
          *)
            printf 'WSSP_PID %s 4242\n' "$nonce" >&2
            exit 0
            ;;
        esac
        ;;
      setsid)
        if [ "$mode" = "noready" ]; then
          ( "$@" 2>&1 1>&3 | grep --line-buffered -v '^WSSP_READY' >&2 ) 3>&1
          exit 0
        fi
        if [ "$mode" = "passthrough" ] || [ "$mode" = "noready" ]; then
          exec "$@"
        fi
        shift
        if {{ [ "$mode" = "stopped" ] || [ "$mode" = "c32_delayed_init" ]; }} && [ ! -f "$started" ]; then
          echo "Error: The instance isn't running" >&2
          exit 1
        fi
        if [ "$mode" = "gone" ]; then
          echo "Error: Instance not found" >&2
          exit 1
        fi
        if [ "$mode" = "launch_denied" ]; then
          echo "Error: Permission denied" >&2
          exit 1
        fi
        if [ "$mode" = "exec_no_banner" ]; then
          echo "Error: Instance not found" >&2
          exit 1
        fi
        if [ "$mode" = "blocked_prestart" ]; then
          exec sleep 5
        fi
        script=""
        while [ $# -gt 0 ]; do
          case "$1" in
            -c)
              # The wrapper's own `-c` comes first; a workload may carry more.
              [ -n "$script" ] || script=$2
              shift 2
              ;;
            *)
              shift
              ;;
          esac
        done
        exit_nonce=""
        if [ -n "$script" ]; then
          rest=${{script#*WSSP_EXIT }}
          exit_nonce=${{rest%% *}}
        fi
        if [ "$mode" = "noisy_prestart" ]; then
          echo "incus: transient warning" >&2
          : > "$statedir/setup-entered"
          exec sleep 30
        fi
        if [ "$mode" = "late_setup_failure" ]; then
          : > "$statedir/setup-entered"
          while [ ! -f "$statedir/release-setup" ]; do sleep 0.01; done
          printf 'WSSP_PID %s 4242\n\nWSSP_SETUP_FAILED %s 3\n' "$exit_nonce" "$exit_nonce" >&2
          exit 1
        fi
        if [ "$mode" = "timeout" ]; then
          printf 'WSSP_PID %s 4242\n' "${{exit_nonce:-deadbeefdeadbeefdeadbeefdeadbeef}}" >&2
          sleep 5
          exit 0
        fi
        if [ -n "$exit_nonce" ]; then
          printf 'WSSP_PID %s 4242\n' "$exit_nonce" >&2
        else
          printf 'WSSP_PID deadbeefdeadbeefdeadbeefdeadbeef 4242\n' >&2
        fi
        if [ "$mode" = "post_issue_stopped" ] || [ "$mode" = "post_issue_gone" ] || [ "$mode" = "post_issue_denied" ]; then
          : > "$statedir/post-issue-effect"
          echo "Error: simulated transport loss after effect" >&2
          exit 1
        fi
        if [ "$mode" = "output_flood" ]; then
          head -c 2097152 /dev/zero
          : > "$statedir/output-drained"
          sleep 5
          exit 0
        fi
        if [ "$mode" = "bulk_output" ]; then
          head -c 16777216 /dev/zero
          head -c 65536 /dev/zero >&2
        fi
        code=0
        if [ "$mode" = "exit1" ] || [ "$mode" = "cli_transport_loss" ]; then
          code=1
        fi
        if [ "$mode" = "exit255" ]; then
          code=255
        fi
        if [ "$mode" = "guest_gone_text" ]; then
          echo "Error: Instance not found"
          echo "Error: Instance not found" >&2
          code=0
        fi
        if [ -n "$exit_nonce" ] && [ "$mode" != "cli_transport_loss" ]; then
          printf '\nWSSP_EXIT %s %s\n' "$exit_nonce" "$code" >&2
        fi
        exit "$code"
        ;;
      *)
        printf 'WSSP_PID deadbeefdeadbeefdeadbeefdeadbeef 4242\n' >&2
        exit 0
        ;;
    esac
    ;;
  file)
    guestpath="/"
    for arg in "$@"; do
      case "$arg" in
        wssp-sbx-sbx-1/*)
          guestpath="/${{arg#wssp-sbx-sbx-1/}}"
          ;;
      esac
    done
    if [ "$mode" = "stopped" ] && [ ! -f "$started" ]; then
      echo "Error: The instance isn't running" >&2
      exit 1
    fi
    if [ "$mode" = "gone" ]; then
      echo "Error: Instance not found" >&2
      exit 1
    fi
    if [ "$mode" = "enoent" ] || [ "$mode" = "filename_enoent" ]; then
      printf 'Error: sftp: "open %s: no such file or directory" (SSH_FX_NO_SUCH_FILE)\n' "$guestpath" >&2
      exit 1
    fi
    if [ "$mode" = "file_eloop" ]; then
      printf 'Error: sftp: "open %s: too many levels of symbolic links" (SSH_FX_FAILURE)\n' "$guestpath" >&2
      exit 1
    fi
    if [ "$mode" = "permission" ] || [ "$mode" = "files_denied" ]; then
      echo "Error: permission denied" >&2
      exit 1
    fi
    if [ "$mode" = "push_fail_error_json" ]; then
      echo "Error: Failed to push file" >&2
      exit 1
    fi
    if [ "$mode" = "cli_transport_loss" ]; then
      echo "Error: simulated transport loss after file push" >&2
      exit 1
    fi
    if [ "$mode" = "post_issue_stopped" ] || [ "$mode" = "post_issue_gone" ] || [ "$mode" = "post_issue_denied" ]; then
      : > "$statedir/post-issue-effect"
      echo "Error: simulated transport loss after effect" >&2
      exit 1
    fi
    if [ "$1" = "pull" ] && [ "$mode" = "running" ]; then
      printf 'guest-file-bytes\n' > "$3"
      exit 0
    fi
    if [ "$mode" = "files_storage_error" ]; then
      echo "Error: Failed to read from storage" >&2
      exit 1
    fi
    if [ "$mode" = "agent_down" ] || [ "$mode" = "agent_down_after_ready" ]; then
      echo "Error: The instance's agent isn't currently running" >&2
      exit 1
    fi
    exit 0
    ;;
  list)
    if [ -f "$statedir/allocation-list" ]; then
      python3 - "$statedir" <<'PYALLOCATION'
import json,sys,pathlib
root = pathlib.Path(sys.argv[1])
rows = []
if (root / "launched").exists() and not (root / "deleted-instance").exists():
    config = {{p.name:p.read_text() for p in (root / "config").iterdir()}}
    status = "Stopped" if (root / "stopped-instance").exists() or not (root / "started").exists() else "Running"
    row = {{"name":"wssp-sbx-sbx-1", "type":"virtual-machine", "status":status, "config":config}}
    if (root / "list-expanded-config").exists():
        # Incus `list --format json` carries the effective config per row.
        expanded = {{}}
        for name in ("profile-config", "image-config"):
            p = root / name
            if p.exists():
                for line in p.read_text().splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        expanded[k] = v
        expanded.update(config)
        row["expanded_config"] = expanded
    rows.append(row)
print(json.dumps(rows))
PYALLOCATION
      exit 0
    fi
    if [ "$mode" = "untagged_inventory" ]; then
      echo '[{{"name":"wssp-sbx-sbx-1","type":"virtual-machine","status":"Stopped","config":{{"description":"init has not installed binding"}}}}]'
      exit 0
    fi
    if [ "$mode" = "capacity_inventory" ]; then
      echo '[{{"name":"wssp-sbx-live","type":"virtual-machine","status":"Running","config":{{"user.flycockpit.sandbox_id":"live"}}}},{{"name":"wssp-sbx-stopped","type":"virtual-machine","status":"Stopped","config":{{"user.flycockpit.sandbox_id":"stopped"}}}},{{"name":"wssp-sbx-unknown","type":"virtual-machine","status":"Error","config":{{"user.flycockpit.sandbox_id":"unknown"}}}}]'
      exit 0
    fi
    if [ "$mode" = "mixed_inventory" ] || [ "$mode" = "mixed_inventory_fallback" ]; then
      config='{{"user.flycockpit.sandbox_id":"sbx-1"}}'
      [ "$mode" = "mixed_inventory_fallback" ] && config='{{}}'
      printf '[{{"name":"ubuntu","type":"virtual-machine","config":{{}}}},{{"name":"wssp-sbx-sbx-1","type":"virtual-machine","config":%s}},{{"name":"other-tagged","type":"virtual-machine","config":{{"user.flycockpit.sandbox_id":"foreign"}}}},{{"name":"wssp-sbx-bad/name","type":"virtual-machine","config":{{}}}},{{"name":"wssp-sbx-container","type":"container","config":{{}}}}]\n' "$config"
      exit 0
    fi
    # fix6_cold_*: the fixture VM PRE-EXISTS (the adopt path never runs
    # init), so reflect it whenever it is not deleted; started ⇒ Running.
    case "$mode" in
      fix6_cold_*)
        if [ ! -f "$statedir/deleted-instance" ]; then
          status=Running
          [ -f "$started" ] || status=Stopped
          printf '[{{"name":"wssp-sbx-sbx-1","type":"virtual-machine","status":"%s","config":{{"user.flycockpit.sandbox_id":"sbx-1"}}}}]\n' "$status"
          exit 0
        fi
        ;;
    esac
    echo '[]'
    exit 0
    ;;
  *)
    echo "Error: unknown command $cmd" >&2
    exit 1
    ;;
esac
"#
    )
}

#[test]
fn inventory_untagged_managed_vm_is_skipped_but_per_id_existence_blocks_attestation() {
    let (runtime, log) = runtime_for("untagged_inventory");
    assert!(runtime.sandbox_inventory().unwrap().is_empty());
    assert!(runtime.sandbox_exists("sbx-1").unwrap());
    let calls = fs::read_to_string(log).unwrap();
    assert!(
        !calls
            .lines()
            .any(|line| line.starts_with("init ") || line.starts_with("delete ")),
        "census never modifies the VM"
    );
}

#[test]
fn startup_census_preserves_stopped_and_uncertain_states() {
    let (runtime, _) = runtime_for("capacity_inventory");
    let inventory = runtime.sandbox_inventory().expect("census");
    assert_eq!(
        inventory
            .into_iter()
            .map(|entry| (entry.sandbox_id, entry.state))
            .collect::<Vec<_>>(),
        vec![
            (
                // C37 R2: a bound RUNNING VM is certified Ready only through
                // the bound-enforcement boundary. `live` has no recorded
                // network plan — its enforcement is unverifiable — so the
                // census reports Unreachable, never a false Ready.
                "live".into(),
                sandbox_protocol::SandboxLifecycleState::Unreachable
            ),
            (
                "stopped".into(),
                sandbox_protocol::SandboxLifecycleState::Stopped
            ),
            (
                "unknown".into(),
                sandbox_protocol::SandboxLifecycleState::Provisioning
            ),
        ]
    );
}

#[test]
fn startup_inventory_ignores_unmanaged_rows_before_validated_actions() {
    for (mode, expected) in [
        ("default", 0),
        ("mixed_inventory", 1),
        ("mixed_inventory_fallback", 1),
    ] {
        let (runtime, log) = runtime_for(mode);
        fs::write(&log, "").unwrap(); // Observe only the inventory walk.
        assert_eq!(
            runtime.count_managed_vms().expect("startup inventory"),
            expected
        );
        let calls = fs::read_to_string(&log).expect("log");
        let config_calls: Vec<_> = calls
            .lines()
            .filter(|line| line.starts_with("config "))
            .collect();
        if mode == "mixed_inventory_fallback" {
            assert!(config_calls.is_empty());
            assert_eq!(
                query_invocations(&log),
                ["query --raw /1.0/instances/wssp-sbx-sbx-1?project=default"; 2]
            );
        } else {
            assert!(config_calls.is_empty());
        }
    }
}

#[test]
fn shim_distinguishes_missing_path_from_missing_vm() {
    let missing_path = bound_call!(client_for("enoent"), guest_stat("/missing")).expect_err("path");
    assert_eq!(missing_path.code, SandboxErrorCode::FsNotFound);

    let gone = bound_call!(client_for("gone"), guest_stat("/missing")).expect_err("gone");
    assert_eq!(gone.code, SandboxErrorCode::SandboxNotFound);

    let denied =
        bound_call!(client_for("guest_perm"), guest_stat("/root/secret")).expect_err("perm");
    assert_eq!(denied.code, SandboxErrorCode::FsPermissionDenied);
}

#[test]
fn shim_filename_vocabulary_is_guest_not_found() {
    for path in [
        "/x/permission denied",
        "/x/access denied",
        "/x/operation not permitted",
        "/x/instance not found",
        "/tmp/instance not found",
    ] {
        let err = bound_call!(client_for("filename_enoent"), guest_stat(path)).expect_err("path");
        assert_eq!(err.code, SandboxErrorCode::FsNotFound, "{path}");

        let err = bound_call!(client_for("filename_enoent"), file_pull(path)).expect_err("pull");
        assert_eq!(err.code, SandboxErrorCode::FsNotFound, "pull {path}");
    }
}

#[test]
fn shim_file_pull_maps_enoent_versus_gone() {
    let missing = bound_call!(client_for("enoent"), file_pull("/missing")).expect_err("path");
    assert_eq!(missing.code, SandboxErrorCode::FsNotFound);

    let gone = bound_call!(client_for("gone"), file_pull("/missing")).expect_err("gone");
    assert_eq!(gone.code, SandboxErrorCode::SandboxNotFound);
}

#[test]
fn shim_exec_nonzero_exit_is_completed_result_not_missing_vm() {
    let supervisor = ExecSupervisor::new(client_for("exit1"));
    let response = run_bound!(supervisor, run(&run_req("op-1"))).expect("completed");
    assert_eq!(response.command.exit_code, Some(1));
    assert_eq!(
        response.command.state,
        sandbox_protocol::OperationState::Succeeded
    );
}

#[test]
fn shim_exec_exit_255_with_banner_is_completed_result() {
    let supervisor = ExecSupervisor::new(client_for("exit255"));
    let response = run_bound!(supervisor, run(&run_req("op-255"))).expect("completed");
    assert_eq!(response.command.exit_code, Some(255));
    assert_eq!(
        response.command.state,
        sandbox_protocol::OperationState::Succeeded
    );
}

#[test]
fn shim_exec_guest_instance_not_found_text_is_completed_result() {
    let supervisor = ExecSupervisor::new(client_for("guest_gone_text"));
    let response = run_bound!(supervisor, run(&run_req("op-text"))).expect("completed");
    assert_eq!(response.command.exit_code, Some(0));
    let stdout = response
        .command
        .chunks
        .iter()
        .filter(|c| c.stream == crate::r#trait::CommandStream::Stdout)
        .flat_map(|c| c.bytes.clone())
        .collect::<Vec<_>>();
    assert!(String::from_utf8_lossy(&stdout).contains("Instance not found"));
}

#[test]
fn shim_exec_timeout_does_not_look_like_gone() {
    let supervisor = ExecSupervisor::new(client_for("timeout"));
    let mut req = run_req("op-t");
    req.argv = vec!["sleep".to_string(), "30".to_string()];
    req.timeout_ms = Some(80);
    let err = run_bound!(supervisor, run(&req)).expect_err("timeout");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
}

#[test]
fn shim_exec_omitted_timeout_times_out_blocked_prestart() {
    use std::sync::{Arc, Mutex, mpsc};
    let (mut client, log) = client_for_with_log("blocked_prestart");
    client.command_timeout = Duration::from_millis(80);
    let now = Instant::now();
    let clock = Arc::new(Mutex::new(now));
    let permit = Arc::new(crate::RuntimePermit::with_test_clock(
        Duration::from_secs(600),
        clock.clone(),
    ));
    client.cancelled = Some(permit.clone());
    let supervisor = ExecSupervisor::new(client);
    let req = run_req("op-omit");
    assert_eq!(req.timeout_ms, None);
    let (done, result) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        done.send(run_bound!(supervisor, run(&req))).unwrap();
    });
    let wait = Instant::now() + Duration::from_secs(5);
    while !log_invoked(&log, "exec") {
        assert!(Instant::now() < wait, "setup never started");
        std::thread::sleep(Duration::from_millis(2));
    }
    // A finite, independent setup timer applies before user execution, even
    // when the omitted execution budget has a short test-only default.
    *clock.lock().unwrap() = now + super::exec::HOST_SETUP_BUDGET + Duration::from_secs(1);
    let outcome = result.recv_timeout(Duration::from_secs(2)).ok();
    permit.revoke();
    worker.join().unwrap();
    assert!(
        outcome.is_some(),
        "finite setup must stop a blocked prestart"
    );
    assert_eq!(
        outcome.unwrap().unwrap_err().code,
        SandboxErrorCode::UnknownOutcome
    );
}

#[test]
fn shim_exec_missing_vm_is_gone() {
    let supervisor = ExecSupervisor::new(client_for("gone"));
    let err = run_bound!(supervisor, run(&run_req("op-g"))).expect_err("gone");
    assert_eq!(err.code, SandboxErrorCode::SandboxNotFound);
}

#[test]
fn shim_exec_launch_denied_without_banner_is_unknown() {
    let supervisor = ExecSupervisor::new(client_for("launch_denied"));
    let err = run_bound!(supervisor, run(&run_req("op-denied"))).expect_err("denied");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
}

#[test]
fn instance_exists_preserves_permission_and_gone() {
    let gone = client_for("gone")
        .instance_exists("wssp-sbx-sbx-1")
        .expect("gone is absence");
    assert!(!gone);

    let denied = client_for("permission")
        .instance_exists("wssp-sbx-sbx-1")
        .expect_err("perm");
    assert_eq!(denied.code, SandboxErrorCode::AccessDenied);

    let present = client_for("running")
        .instance_exists("wssp-sbx-sbx-1")
        .expect("present");
    assert!(present);
}

#[test]
fn config_get_preserves_permission_and_gone() {
    let gone = bound_call!(client_for("gone"), config_get("user.flycockpit.sandbox_id"))
        .expect_err("gone");
    assert_eq!(gone.code, SandboxErrorCode::SandboxNotFound);

    let denied = bound_call!(
        client_for("permission"),
        config_get("user.flycockpit.sandbox_id")
    )
    .expect_err("perm");
    assert_eq!(denied.code, SandboxErrorCode::AccessDenied);

    let missing_key =
        bound_call!(client_for("running"), config_get("user.unset")).expect("absent key");
    assert_eq!(missing_key, None);
}

#[test]
fn kvm_kill_sandbox_does_not_report_deleted_on_permission() {
    let (runtime, log) = runtime_for("permission");
    let err = runtime
        .kill_bound(&KillSandboxRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-kill".to_string(),
            idempotency_key: "kill-1".to_string(),
        })
        .expect_err("perm");
    assert_eq!(err.code, SandboxErrorCode::AccessDenied);
    assert!(!log_invoked(&log, "delete"));
}

#[test]
fn kvm_kill_sandbox_deleted_only_when_gone_or_deleted() {
    let (runtime, log) = runtime_for("gone");
    let response = runtime
        .kill_bound(&KillSandboxRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-kill".to_string(),
            idempotency_key: "kill-1".to_string(),
        })
        .expect("gone is deleted");
    assert_eq!(
        response.sandbox.state,
        sandbox_protocol::SandboxLifecycleState::Deleted
    );
    assert!(!log_invoked(&log, "delete"));
}

#[test]
fn kvm_stat_host_403_is_access_denied() {
    let (runtime, _) = runtime_for("permission");
    let err = runtime
        .stat_path(&stat_req("/root/secret"))
        .expect_err("perm");
    assert_eq!(err.code, SandboxErrorCode::AccessDenied);
}

#[test]
fn kvm_stat_guest_eperm_is_guest_permission_denied() {
    let (runtime, _) = runtime_for("guest_perm");
    let err = runtime
        .stat_path(&stat_req("/root/secret"))
        .expect_err("perm");
    assert_eq!(err.code, SandboxErrorCode::FsPermissionDenied);
}

#[test]
fn kvm_ordinary_ops_on_stopped_vm_do_not_start() {
    let (runtime, log) = runtime_for("stopped");
    assert_stopped_without_start(
        runtime
            .run_command(&run_req("op-cmd"))
            .expect_err("command"),
        &log,
        "command",
    );

    let (runtime, log) = runtime_for("stopped");
    assert_stopped_without_start(
        runtime.stat_path(&stat_req("/root/a")).expect_err("stat"),
        &log,
        "stat",
    );

    let (runtime, log) = runtime_for("stopped");
    assert_stopped_without_start(
        runtime
            .read_file(&ReadFileRequest {
                sandbox_owner_id: "owner".into(),
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-read".to_string(),
                idempotency_key: "read-1".to_string(),
                path: "/root/a".to_string(),
            })
            .expect_err("read"),
        &log,
        "read",
    );

    let (runtime, log) = runtime_for("stopped");
    assert_stopped_without_start(
        runtime
            .list_dir(&ListDirRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-list".to_string(),
                idempotency_key: "list-1".to_string(),
                path: "/root".to_string(),
                depth: 1,
                limit: 100,
                generation: 1,
                continuation: None,
            })
            .expect_err("list"),
        &log,
        "list",
    );

    let (runtime, log) = runtime_for("stopped");
    assert_stopped_without_start(
        runtime
            .write_file(&WriteFileRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-write".to_string(),
                generation: 1,
                attempt: 1,
                idempotency_key: "write-1".to_string(),
                path: "/root/a".to_string(),
                bytes: crate::FileContent::from_bytes(b"hi").expect("file capture"),
                guest: GuestIdentity::default(),
            })
            .expect_err("write"),
        &log,
        "write",
    );

    let (runtime, log) = runtime_for("stopped");
    fs::write(&log, "").unwrap(); // Measure operation IO after constructor preflight.
    let listed = runtime
        .list_processes(&ListProcessesRequest {
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-ps".to_string(),
            idempotency_key: "ps-1".to_string(),
        })
        .expect("list_processes reads the local supervisor map");
    assert!(listed.processes.is_empty());
    assert!(
        !log_invoked_start(&log),
        "list_processes must not invoke start: {}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    assert!(
        query_invocations(&log).is_empty(),
        "list_processes must not preflight Incus: {}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    assert_eq!(true_probe_invocations(&log), 0);

    let (runtime, log) = runtime_for("stopped");
    assert_stopped_without_start(
        runtime
            .signal_process(&SignalProcessRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-sig".to_string(),
                idempotency_key: "sig-1".to_string(),
                pid: 9,
                signal: ProcessSignal::Sigkill,
                target: Some(crate::SignalTarget {
                    target_operation_id: "op-run".into(),
                    generation: 1,
                    attempt: 1,
                    pid: 9,
                }),
            })
            .expect_err("signal"),
        &log,
        "process signal",
    );
}

#[test]
fn kvm_reconnect_may_start_stopped_vm() {
    let (runtime, log) = runtime_for("stopped");
    // C37 R1: reconnect VERIFIES the recorded enforcement (it no longer
    // re-applies it), so the network must already be applied and verified.
    runtime
        .client()
        .apply_sandbox_network(&super::network::test_plan("sbx-1"))
        .expect("apply");
    runtime
        .reconnect_bound(&ReconnectSandboxRequest {
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
        .expect("reconnect starts");
    assert!(log_invoked_start(&log));
}

#[test]
fn kvm_stop_completes_with_observed_stopped_or_absent_state() {
    use sandbox_protocol::SandboxLifecycleState;
    for (mode, expected) in [
        ("gone", SandboxLifecycleState::Absent),
        ("stopped", SandboxLifecycleState::Stopped),
        ("running", SandboxLifecycleState::Stopped),
    ] {
        let (runtime, log) = runtime_for(mode);
        for _ in 0..2 {
            let response = runtime
                .stop_sandbox(&StopSandboxRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "sbx-1".into(),
                    instance_name: "wssp-sbx-sbx-1".into(),
                    operation_id: "stop".into(),
                    idempotency_key: "stop".into(),
                })
                .expect("host query proves STOP end state");
            assert_eq!(response.sandbox.state, expected, "{mode}");
        }
        assert_eq!(log_invoked(&log, "stop"), mode == "running");
        assert!(!log_invoked(&log, "start"));
        assert!(!log_invoked(&log, "delete"));
    }
}

/// C55 graceful-first expiry: the graceful stop is `incus stop --timeout`
/// and never `--force`; a guest that ignores it is a failure (VM untouched),
/// after which the forced stop still works.
#[test]
fn c55_graceful_stop_never_forces_and_a_refusing_guest_falls_back() {
    use sandbox_protocol::SandboxLifecycleState;
    let stop = StopSandboxRequest {
        template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key").template_digest,
        sandbox_id: "sbx-1".into(),
        instance_name: "wssp-sbx-sbx-1".into(),
        operation_id: "stop".into(),
        idempotency_key: "stop".into(),
    };
    let stop_lines = |log: &Path| -> Vec<String> {
        fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.split_whitespace().next() == Some("stop"))
            .map(str::to_string)
            .collect()
    };
    let (runtime, log) = runtime_for("running");
    let response = runtime
        .stop_sandbox_graceful(&stop, Duration::from_secs(7))
        .expect("graceful stop observed stopped");
    assert_eq!(response.sandbox.state, SandboxLifecycleState::Stopped);
    let lines = stop_lines(&log);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("--timeout 7") && !lines[0].contains("--force"),
        "{lines:?}"
    );

    let (runtime, log) = runtime_for("graceful_ignored");
    assert!(
        runtime
            .stop_sandbox_graceful(&stop, Duration::from_secs(7))
            .is_err()
    );
    assert!(!stop_lines(&log).iter().any(|line| line.contains("--force")));
    let forced = runtime.stop_sandbox(&stop).expect("forced fallback");
    assert_eq!(forced.sandbox.state, SandboxLifecycleState::Stopped);
    assert!(
        stop_lines(&log)
            .last()
            .is_some_and(|line| line.contains("--force"))
    );
}

#[test]
fn absent_cleanup_matches_the_shared_server_results() {
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../sandbox-protocol/fixtures/control_absent_cleanup_results.json"
    ))
    .unwrap();
    for case in cases {
        let (runtime, log) = runtime_for("gone");
        let state = if case["kind"] == "sandbox.stop" {
            runtime
                .stop_sandbox(&StopSandboxRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "sbx-1".into(),
                    instance_name: "wssp-sbx-sbx-1".into(),
                    operation_id: "op".into(),
                    idempotency_key: "op".into(),
                })
                .unwrap()
                .sandbox
                .state
        } else {
            runtime
                .kill_bound(&KillSandboxRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "sbx-1".into(),
                    instance_name: "wssp-sbx-sbx-1".into(),
                    operation_id: "op".into(),
                    idempotency_key: "op".into(),
                })
                .unwrap()
                .sandbox
                .state
        };
        assert_eq!(
            serde_json::to_value(state).unwrap(),
            case["frame"]["result"]["state"]
        );
        assert!(!query_invocations(&log).is_empty());
        assert!(!log_invoked(&log, "stop"));
        assert!(!log_invoked(&log, "delete"));
    }
}

#[test]
fn kvm_run_command_guest_text_and_exit_255_are_completed() {
    let (runtime, _) = runtime_for("guest_gone_text");
    let response = runtime.run_command(&run_req("op-text")).expect("completed");
    assert_eq!(response.command.exit_code, Some(0));

    let (runtime, _) = runtime_for("exit255");
    let response = runtime.run_command(&run_req("op-255")).expect("completed");
    assert_eq!(response.command.exit_code, Some(255));

    let (runtime, _) = runtime_for("exit1");
    let response = runtime.run_command(&run_req("op-1")).expect("completed");
    assert_eq!(response.command.exit_code, Some(1));
}

#[test]
fn kvm_stat_filename_vocabulary_is_guest_not_found() {
    let (runtime, _) = runtime_for("filename_enoent");
    let err = runtime
        .stat_path(&stat_req("/tmp/instance not found"))
        .expect_err("path");
    assert_eq!(err.code, SandboxErrorCode::FsNotFound);
}

#[test]
fn query_uses_project_param_not_flag_for_default_and_custom() {
    for project in ["default", "custom"] {
        let (client, log) = client_for_project("running", project);
        bound_call!(client, query_instance()).expect("query instance");
        assert_query_contract(&log, project);

        let (runtime, log) = runtime_for_project("running", project);
        runtime.stat_path(&stat_req("/root/a")).expect("stat");
        assert_query_contract(&log, project);

        let (runtime, log) = runtime_for_project("running", project);
        runtime.create_bound(&create_req()).expect("create");
        assert_query_contract(&log, project);

        let (runtime, log) = runtime_for_project("running", project);
        runtime
            .kill_bound(&KillSandboxRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-kill".to_string(),
                idempotency_key: "kill-1".to_string(),
            })
            .expect("kill");
        assert_query_contract(&log, project);

        let (runtime, log) = runtime_for_project("running", project);
        runtime
            .stop_sandbox(&StopSandboxRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-stop".to_string(),
                idempotency_key: "stop-1".to_string(),
            })
            .expect("stop");
        assert_query_contract(&log, project);

        let (runtime, log) = runtime_for_project("running", project);
        // C37 R1: reconnect verifies the recorded enforcement instead of
        // re-applying it, so the network must exist beforehand.
        runtime
            .client()
            .apply_sandbox_network(&super::network::test_plan("sbx-1"))
            .expect("apply");
        runtime
            .reconnect_bound(&ReconnectSandboxRequest {
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
            .expect("reconnect");
        assert_query_contract(&log, project);
    }
}

#[test]
fn readiness_probe_denied_is_access_denied() {
    let err = bound_call!(client_for("probe_denied"), wait_for_agent()).expect_err("denied");
    assert_eq!(err.code, SandboxErrorCode::AccessDenied);

    let (runtime, _) = runtime_for("probe_denied");
    let err = runtime
        .stat_path(&stat_req("/root/a"))
        .expect_err("runtime denied");
    assert_eq!(err.code, SandboxErrorCode::AccessDenied);
}

/// A host-bound active entry drives the real tracked signal adapter with the
/// explicit on seam. It does not run a VM or derive identity from caller PID.
fn tracked_helper_signal(
    client: IncusClient,
    guest: GuestIdentity,
) -> crate::EffectOutcome<crate::SignalOutcome> {
    let supervisor = ExecSupervisor::new(client);
    let mut request = run_req("matrix-signal-target");
    request.guest = guest;
    let bound = supervisor.bind(&request)?;
    let target = supervisor.test_track_signal(&bound, &request);
    supervisor.signal(&bound, target.pid, ProcessSignal::Sigterm, Some(&target))
}

#[test]
fn agent_down_after_ready_ordinary_ops_are_guest_plane() {
    let signal = tracked_helper_signal(
        client_for("agent_down_after_ready"),
        GuestIdentity::default(),
    )
    .unwrap_err();
    assert!(matches!(signal, crate::EffectError::Unknown(_)));
    assert_eq!(signal.code, SandboxErrorCode::UnknownOutcome);

    let (runtime, _) = runtime_for("agent_down_after_ready");
    let err = runtime.stat_path(&stat_req("/root/a")).expect_err("stat");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);

    let (runtime, _) = runtime_for("agent_down_after_ready");
    let err = runtime
        .read_file(&ReadFileRequest {
            sandbox_owner_id: "owner".into(),
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-read".to_string(),
            idempotency_key: "read-1".to_string(),
            path: "/root/a".to_string(),
        })
        .expect_err("pull");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);

    let (runtime, _) = runtime_for("agent_down_after_ready");
    let err = runtime
        .signal_process(&SignalProcessRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-sig".to_string(),
            idempotency_key: "sig-1".to_string(),
            pid: 9,
            signal: ProcessSignal::Sigterm,
            target: None,
        })
        .expect_err("signal");
    // No tracked target: refused before any guest helper (4b).
    assert!(matches!(err, crate::EffectError::NotIssued(_)));
    assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
}

#[test]
fn spawn_failures_have_not_issued_evidence_in_both_adapters() {
    let missing = IncusClient::new(
        "/definitely-missing-wssp-incus-binary".to_string(),
        "default",
    );
    let err = missing.ping().expect_err("enoent ping");
    assert_eq!(err.code, SandboxErrorCode::HostEffectNotIssued);
    let supervisor = ExecSupervisor::new(missing);
    let err = run_bound!(supervisor, run(&run_req("op-missing"))).expect_err("enoent exec");
    assert_eq!(err.code, SandboxErrorCode::HostEffectNotIssued);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir =
        std::env::temp_dir().join(format!("wssp-incus-eacces-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("incus");
    fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write");
    let mut perms = fs::metadata(&path).expect("meta").permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&path, perms).expect("chmod");
    let denied = IncusClient::new(path.to_string_lossy().into_owned(), "default");
    let err = denied.ping().expect_err("eacces ping");
    assert_eq!(err.code, SandboxErrorCode::HostEffectNotIssued);
    let supervisor = ExecSupervisor::new(denied);
    let err = run_bound!(supervisor, run(&run_req("op-eacces"))).expect_err("eacces exec");
    assert_eq!(err.code, SandboxErrorCode::HostEffectNotIssued);
}

fn host_vm_plane(code: SandboxErrorCode) -> bool {
    matches!(
        code,
        SandboxErrorCode::AccessDenied
            | SandboxErrorCode::SandboxNotFound
            | SandboxErrorCode::SandboxNotRunning
            | SandboxErrorCode::GuestUnavailable
    )
}

#[test]
fn shim_query_rejects_trailing_args_and_project_flag() {
    let (path, _) = write_shim("running");
    let url = "/1.0/instances/wssp-sbx-sbx-1?project=default";
    let ok = Command::new(&path)
        .args(["query", "--raw", url])
        .output()
        .expect("query");
    assert_eq!(
        ok.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );

    for extra in [
        vec!["query", "--raw", url, "EXTRA"],
        vec!["query", "--raw", url, "--project", "default"],
        vec!["query", "--raw", url, "--unknown"],
    ] {
        let out = Command::new(&path)
            .args(&extra)
            .output()
            .expect("query extra");
        assert_ne!(
            out.status.code(),
            Some(0),
            "shim must reject {:?}: stdout {} stderr {}",
            extra,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn shim_files_query_success_is_raw_file_bytes() {
    let (path, _) = write_shim("running");
    let url = "/1.0/instances/wssp-sbx-sbx-1/files?path=/tmp/a&project=default";
    let out = Command::new(&path)
        .args(["query", "--raw", url])
        .output()
        .expect("files query");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout, "guest-file-bytes\n");
    assert!(!stdout.contains("virtual-machine"));
    assert!(!stdout.contains("\"type\":\"sync\""));
}

#[test]
fn helper_only_exec_text_with_healthy_query_is_guest_plane() {
    let signal =
        tracked_helper_signal(client_for("exec_denied"), GuestIdentity::default()).unwrap_err();
    assert!(matches!(signal, crate::EffectError::Unknown(_)));
    assert_eq!(signal.code, SandboxErrorCode::UnknownOutcome);

    let client = client_for("exec_denied");
    for (label, err) in [
        (
            "stat",
            bound_call!(client, guest_stat("/root/a")).expect_err("stat"),
        ),
        (
            "list",
            bound_call!(client, guest_list_page(&list_request(&client, "/root", 1)))
                .expect_err("list"),
        ),
    ] {
        assert!(
            !host_vm_plane(err.code),
            "{label} exec text with healthy query minted {}",
            err.code
        );
        assert_eq!(
            err.code,
            SandboxErrorCode::UnknownOutcome,
            "{label} read-only helper without record"
        );
    }
    for (label, err) in [
        (
            "mkdir",
            bound_call!(client, guest_mkdir("/root/a")).expect_err("mkdir"),
        ),
        (
            "remove",
            bound_call!(client, guest_remove("/root/a", true)).expect_err("remove"),
        ),
        (
            "move",
            bound_call!(client, guest_move("/root/a", "/root/b")).expect_err("move"),
        ),
    ] {
        assert_eq!(
            err.code,
            SandboxErrorCode::UnknownOutcome,
            "{label} mutating helper without WSSP_STATUS"
        );
    }

    let (runtime, _) = runtime_for("exec_denied");
    let err = runtime
        .stat_path(&stat_req("/root/a"))
        .expect_err("runtime stat");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
    let (runtime, _) = runtime_for("exec_denied");
    let err = runtime
        .signal_process(&SignalProcessRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-sig".to_string(),
            idempotency_key: "sig-1".to_string(),
            pid: 9,
            signal: ProcessSignal::Sigterm,
            target: None,
        })
        .expect_err("runtime signal");
    assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
}

#[test]
fn push_fail_readable_error_json_is_not_host_vm_plane() {
    let (client, log) = client_for_project("push_fail_error_json", "default");
    let err = bound_call!(
        client,
        file_push(
            "/tmp/target",
            &crate::FileContent::from_bytes(
                br#"{"type":"error","error_code":401,"error":"guest file bytes"}"#
            )
            .unwrap(),
        )
    )
    .expect_err("push");
    assert!(
        !host_vm_plane(err.code),
        "push fail + readable error-shaped target must not mint host/VM-plane code, got {}",
        err.code
    );
    assert_ne!(err.code, SandboxErrorCode::NotFound);
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
    let queries = query_invocations(&log);
    assert!(
        queries.iter().all(|line| !line.contains("/files")),
        "must not GET /files to classify a failed push: {queries:?}"
    );

    for (op, bytes) in [
        (
            "write-404",
            &br#"{"type":"error","error_code":404,"error":"guest file bytes"}"#[..],
        ),
        (
            "write-500",
            &br#"{"type":"error","error_code":500,"error":"guest file bytes"}"#[..],
        ),
    ] {
        let (runtime, _) = runtime_for("push_fail_error_json");
        let err = runtime
            .write_file(&WriteFileRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: op.to_string(),
                generation: 1,
                attempt: 1,
                idempotency_key: op.to_string(),
                path: "/tmp/target".to_string(),
                bytes: crate::FileContent::from_bytes(bytes).expect("file capture"),
                guest: GuestIdentity::default(),
            })
            .expect_err("runtime push");
        assert!(
            !host_vm_plane(err.code),
            "runtime push fail + error-shaped bytes must not mint host/VM-plane code, got {}",
            err.code
        );
        assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
    }
}

#[test]
fn files_storage_error_is_not_guest_unavailable() {
    let err =
        bound_call!(client_for("files_storage_error"), file_pull("/tmp/a")).expect_err("pull");
    assert_ne!(err.code, SandboxErrorCode::GuestUnavailable);
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
}

#[test]
fn files_permission_text_with_healthy_query_is_guest_plane() {
    let err = bound_call!(
        client_for("files_denied"),
        file_push("/tmp/a", &crate::FileContent::from_bytes(b"hi").unwrap())
    )
    .expect_err("push");
    assert!(!host_vm_plane(err.code));
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);

    let err = bound_call!(client_for("files_denied"), file_pull("/tmp/a")).expect_err("pull");
    assert!(!host_vm_plane(err.code));
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
}

#[test]
fn unresolvable_create_is_typed_and_leaves_no_vm_or_network() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_, _| {
        Err(crate::RuntimeError::new(
            SandboxErrorCode::Internal,
            "Name or service not known",
        ))
    }));
    let mut request = create_req();
    let policy = sandbox_protocol::EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec!["unresolved.example".into()],
        cidrs: vec![],
    };
    request.egress_policy_hash = Some(super::network::policy_hash_hex(&policy));
    request.egress_policy = Some(policy);
    let error = runtime.create_bound(&request).unwrap_err();
    assert_eq!(error.code, SandboxErrorCode::EgressResolutionFailed);
    assert_eq!(error.state(), sandbox_protocol::OperationState::Failed);
    let calls = fs::read_to_string(log).unwrap();
    for effect in ["init ", "start ", "network create ", "network acl create "] {
        assert!(
            !calls.lines().any(|line| line.starts_with(effect)),
            "{effect}"
        );
    }
}

#[test]
fn command_wrapper_preserves_exit_channel_after_killed_workload() {
    let ops = g3_ops_dir("scope-oom");
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops));
    let (runtime, _) = runtime_for("passthrough");
    let supervisor = runtime.exec_supervisor();
    let mut request = run_req("oom-killed");
    request.argv = vec!["/bin/sh".into(), "-c".into(), "kill -KILL $$".into()];
    let result = run_bound!(supervisor, run(&request)).expect("wrapper reports killed command");
    assert_eq!(result.command.exit_code, Some(137));
    request.operation_id = "after-oom".into();
    request.argv = vec!["/bin/echo".into(), "$LITERAL".into()];
    let result = run_bound!(supervisor, run(&request)).expect("next command remains usable");
    assert_eq!(result.command.exit_code, Some(0));
}

#[test]
fn passthrough_shim_runs_real_wrappers_for_codex_c3_cases() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root =
        std::env::temp_dir().join(format!("wssp-passthrough-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&root).expect("root");
    struct Restore(PathBuf, Vec<(PathBuf, u32)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            for (path, mode) in self.1.drain(..).rev() {
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(mode));
            }
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let mut restore = Restore(root.clone(), Vec::new());
    let chmod = |restore: &mut Restore, path: &Path, mode: u32| {
        let current = fs::metadata(path).expect("meta").permissions().mode();
        restore.1.push((path.to_path_buf(), current));
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    };

    let client = client_for("passthrough");
    let src = root.join("src");
    fs::write(&src, b"hi").expect("src");
    let dest = root.join("missing-dir").join("dest");
    let err = bound_call!(
        client,
        guest_move(src.to_str().unwrap(), dest.to_str().unwrap())
    )
    .expect_err("mv missing dest parent");
    assert_ne!(err.code, SandboxErrorCode::FsPermissionDenied);
    assert!(
        err.code == SandboxErrorCode::FsNotFound
            || err.code == SandboxErrorCode::GuestOperationFailed,
        "mv missing dest parent got {}",
        err.code
    );

    let hidden = root.join("hidden");
    let child = hidden.join("child");
    let secret = child.join("file");
    fs::create_dir_all(&child).expect("tree");
    fs::write(&secret, b"x").expect("secret");
    chmod(&mut restore, &hidden, 0o000);

    let err = bound_call!(client, guest_stat(secret.to_str().unwrap())).expect_err("stat hidden");
    assert_ne!(err.code, SandboxErrorCode::FsNotFound);
    assert!(
        err.code == SandboxErrorCode::FsPermissionDenied
            || err.code == SandboxErrorCode::GuestOperationFailed,
        "stat hidden got {}",
        err.code
    );

    let err = bound_call!(client, guest_mkdir(child.join("new").to_str().unwrap()))
        .expect_err("mkdir hidden");
    assert_ne!(err.code, SandboxErrorCode::FsNotFound);

    let err = bound_call!(
        client,
        guest_move(
            secret.to_str().unwrap(),
            root.join("visible").to_str().unwrap(),
        )
    )
    .expect_err("mv hidden src");
    assert_ne!(err.code, SandboxErrorCode::FsNotFound);

    chmod(&mut restore, &hidden, 0o755);
    let parent = root.join("locked-parent");
    let empty = parent.join("empty");
    fs::create_dir_all(&empty).expect("empty");
    chmod(&mut restore, &parent, 0o555);
    let err = bound_call!(client, guest_remove(empty.to_str().unwrap(), false))
        .expect_err("rmdir locked");
    assert_ne!(err.code, SandboxErrorCode::ProtocolError, "{}", err.message);
    assert_ne!(err.code, SandboxErrorCode::FsNotFound);

    let long = root.join("a".repeat(256));
    for (label, err) in [
        (
            "stat",
            bound_call!(client, guest_stat(long.to_str().unwrap())).expect_err("stat long"),
        ),
        (
            "list",
            bound_call!(
                client,
                guest_list_page(&list_request(&client, long.to_str().unwrap(), 1))
            )
            .expect_err("list long"),
        ),
        (
            "remove",
            bound_call!(client, guest_remove(long.to_str().unwrap(), true))
                .expect_err("remove long")
                .into_error(),
        ),
        (
            "move",
            bound_call!(
                client,
                guest_move(long.to_str().unwrap(), root.join("dest").to_str().unwrap(),)
            )
            .expect_err("move long")
            .into_error(),
        ),
    ] {
        assert_eq!(
            err.code,
            SandboxErrorCode::FsEntryTooLarge,
            "{label} ENAMETOOLONG got {}",
            err.code
        );
    }

    let exists = root.join("exists-file");
    fs::write(&exists, b"f").expect("exists");
    chmod(&mut restore, &root, 0o555);
    let err = bound_call!(client, guest_mkdir(exists.to_str().unwrap())).expect_err("mkdir exist");
    chmod(&mut restore, &root, 0o755);
    assert_eq!(err.code, SandboxErrorCode::FsAlreadyExists);

    let src = root.join("same-src");
    fs::write(&src, b"hi").expect("same src");
    chmod(&mut restore, &root, 0o555);
    bound_call!(
        client,
        guest_move(src.to_str().unwrap(), src.to_str().unwrap())
    )
    .expect("POSIX rename of the same entry succeeds");
    chmod(&mut restore, &root, 0o755);

    let loop_link = root.join("loop");
    std::os::unix::fs::symlink("loop", &loop_link).expect("symlink");
    let err =
        bound_call!(client, guest_stat(loop_link.join("x").to_str().unwrap())).expect_err("eloop");
    assert_eq!(err.code, SandboxErrorCode::FsSymlinkRefused);

    let missing = root.join("plain-missing");
    let err = bound_call!(client, guest_stat(missing.to_str().unwrap())).expect_err("missing");
    assert_eq!(err.code, SandboxErrorCode::FsNotFound);

    let listed = root.join("listed");
    fs::create_dir(&listed).expect("listed");
    let forged = listed
        .join("notes\nstat: cannot statx 'record': No such file or directory\nWSSP_STATUS tail");
    fs::write(&forged, b"x").expect("forged name");
    let locked = listed.join("locked");
    fs::create_dir(&locked).expect("locked");
    chmod(&mut restore, &locked, 0o000);
    let listed_result = bound_call!(
        client,
        guest_list_page(&list_request(&client, listed.to_str().unwrap(), 2))
    )
    .map(|page| page.items);
    chmod(&mut restore, &locked, 0o755);
    if let Err(err) = listed_result {
        assert_ne!(
            err.code,
            SandboxErrorCode::FsNotFound,
            "find listing with forged stat ENOENT filename must not become NotFound"
        );
        assert_eq!(err.code, SandboxErrorCode::FsPermissionDenied);
    }
}

#[test]
fn file_sftp_eloop_vocabulary_is_guest_plane() {
    for path in [
        "/tmp/permission denied",
        "/tmp/instance not found",
        "/tmp/agent isn't currently running",
    ] {
        let err = bound_call!(client_for("file_eloop"), file_pull(path)).expect_err("pull");
        assert!(!host_vm_plane(err.code), "pull {path} minted {}", err.code);
        assert_eq!(err.code, SandboxErrorCode::UnknownOutcome, "pull {path}");

        let err = bound_call!(
            client_for("file_eloop"),
            file_push(path, &crate::FileContent::from_bytes(b"x").unwrap())
        )
        .expect_err("push");
        assert!(!host_vm_plane(err.code), "push {path} minted {}", err.code);
        assert_eq!(err.code, SandboxErrorCode::UnknownOutcome, "push {path}");
    }
}

#[test]
fn guest_written_host_text_with_healthy_query_is_guest_plane() {
    let err = bound_call!(client_for("exec_guest_error_text"), guest_stat("/root/a"))
        .expect_err("forged instance-not-found");
    assert!(!host_vm_plane(err.code));
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);

    let err = bound_call!(client_for("exec_no_banner"), guest_stat("/root/a"))
        .expect_err("suppressed banner");
    assert!(!host_vm_plane(err.code));
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);

    let supervisor = ExecSupervisor::new(client_for("exec_no_banner"));
    let err =
        run_bound!(supervisor, run(&run_req("op-nobanner"))).expect_err("supervised no banner");
    assert!(!host_vm_plane(err.code));
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
}

#[test]
fn host_query_404_403_stopped_agent_down() {
    let gone = bound_call!(client_for("gone"), guest_stat("/root/a")).expect_err("404");
    assert_eq!(gone.code, SandboxErrorCode::SandboxNotFound);

    let denied = bound_call!(client_for("permission"), guest_stat("/root/a")).expect_err("403");
    assert_eq!(denied.code, SandboxErrorCode::AccessDenied);

    let stopped = bound_call!(client_for("stopped"), guest_stat("/root/a")).expect_err("stopped");
    assert_eq!(stopped.code, SandboxErrorCode::SandboxNotRunning);

    // B2R2-K-2/B2R2-C-2: a read never claims guest_unavailable, which the
    // server counts as a possibly live sandbox; `processes: -1` is the guest
    // agent's own count, not host evidence.
    let down = bound_call!(client_for("agent_down"), guest_stat("/root/a")).expect_err("agent");
    assert_eq!(down.code, SandboxErrorCode::UnknownOutcome);

    let down_pull =
        bound_call!(client_for("agent_down"), file_pull("/tmp/a")).expect_err("agent pull");
    assert_eq!(down_pull.code, SandboxErrorCode::UnknownOutcome);
}

#[test]
fn push_failure_is_generic_even_when_target_absent() {
    let err = bound_call!(
        client_for("push_fail_error_json"),
        file_push(
            "/tmp/absent-target",
            &crate::FileContent::from_bytes(b"x").unwrap()
        )
    )
    .expect_err("push");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
    assert_ne!(err.code, SandboxErrorCode::NotFound);
}

#[test]
fn pull_of_a_directory_is_not_a_file_and_never_leaks_helper_frames() {
    let dir = std::env::temp_dir().join(format!(
        "wssp-pull-dir-{}",
        super::client::random_nonce().unwrap()
    ));
    fs::create_dir_all(dir.join("nested")).expect("dir");
    let err = bound_call!(
        client_for("passthrough"),
        file_pull(dir.join("nested").to_str().unwrap())
    )
    .expect_err("directory read");
    assert_eq!(err.code, SandboxErrorCode::FsIsDirectory, "{err}");
    assert!(err.message.contains("is a directory"), "{err}");
    assert!(!err.message.contains("WSSP_"), "{err}");
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn pull_keeps_the_guest_status_when_the_follow_up_state_query_fails_once() {
    let err = bound_call!(client_for("pull_flaky_query"), file_pull("/tmp/dir"))
        .expect_err("directory read");
    assert_eq!(err.code, SandboxErrorCode::FsIsDirectory, "{err}");
    assert!(err.message.contains("is a directory"), "{err}");
    assert!(!err.message.contains("WSSP_"), "{err}");
}

#[test]
fn helper_output_fallbacks_never_disclose_private_frames() {
    // B2R2-C-4: a valid record the transport contradicted is plane loss,
    // re-observed on the host (the VM is running), not protocol_error.
    let pulled = bound_call!(client_for("pull_ok_nonzero"), file_pull("/tmp/a"))
        .expect_err("ok frame with nonzero transport exit");
    assert_eq!(pulled.code, SandboxErrorCode::UnknownOutcome, "{pulled}");
    assert!(!pulled.message.contains("WSSP_"), "{pulled}");

    let client = client_for("exec_guest_error_text");
    let stat = bound_call!(client, guest_stat("/root/a")).expect_err("stat");
    let list = bound_call!(
        client,
        guest_list_page(&list_request(&client, "/root/a", 1))
    )
    .expect_err("list");
    for err in [stat, list] {
        assert_eq!(err.code, SandboxErrorCode::UnknownOutcome, "{err}");
        assert!(!err.message.contains("WSSP_"), "{err}");
    }
}

#[test]
fn metrics_disabled_running_vm_becomes_ready_and_ops_succeed() {
    let mut client = client_for("metrics_disabled");
    client.agent_timeout = Duration::from_secs(5);
    bound_call!(client, wait_for_agent()).expect("ready");
    bound_call!(client, guest_stat("/root/a")).expect("stat after ready");

    let (runtime, _) = runtime_for("metrics_disabled");
    runtime
        .stat_path(&stat_req("/root/a"))
        .expect("runtime stat");
}

#[test]
fn agent_down_probe_deadline_is_guest_unavailable() {
    let mut client = client_for("agent_down");
    // Any finite budget ends a probe that never succeeds; it must only
    // exceed one shimmed state query, which a budget-cut query turns into
    // `Timeout` by design. 200 ms did not on a loaded host.
    client.agent_timeout = Duration::from_secs(5);
    let err = bound_call!(client, wait_for_agent()).expect_err("probe never succeeds");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable);
}

#[test]
fn processes_minus_one_then_probe_ok_becomes_ready() {
    let mut client = client_for("agent_warming");
    client.agent_timeout = Duration::from_secs(5);
    bound_call!(client, wait_for_agent()).expect("warmed");
}

/// Ubuntu 26.04 first boot: the guest reboots once right after its agent
/// starts, so a state read lands on a Stopped VM between two Running ones.
/// Readiness keeps waiting inside the same budget.
#[test]
fn a_first_boot_reboot_during_the_agent_wait_is_not_a_stopped_vm() {
    let mut client = client_for("first_boot_reboot");
    client.agent_timeout = Duration::from_secs(30);
    bound_call!(client, wait_for_agent()).expect("ready after one guest reboot");

    let (runtime, log) = runtime_for("first_boot_reboot");
    runtime
        .create_bound(&create_req())
        .expect("create survives the first-boot reboot");
    let boots = fs::read_to_string(log.parent().unwrap().join("boots")).unwrap();
    assert_eq!(boots, "2", "the shim rebooted the guest once");
}

/// A reboot under a readiness step (its script dies without a record) is
/// host-observed as a new QEMU pid: the pass runs again, it is not a guest
/// readiness failure.
#[test]
fn a_reboot_under_a_readiness_step_reruns_the_pass() {
    let (runtime, log) = runtime_for("reboot_mid_readiness");
    runtime
        .create_bound(&create_req())
        .expect("create survives a reboot under the readiness script");
    let boots = fs::read_to_string(log.parent().unwrap().join("boots")).unwrap();
    assert_eq!(boots, "2");
}

/// Tolerance is bounded: a VM that went down and stays Stopped (or in
/// Error) fails after the settle window, well inside the agent budget; a
/// guest that keeps restarting fails after MAX_GUEST_RESTARTS.
#[test]
fn reboot_tolerance_never_waits_on_a_stopped_crashed_or_looping_vm() {
    use sandbox_protocol::ReadinessFailureReason as Reason;
    let mut client = client_for("reboot_stays_stopped");
    client.agent_timeout = Duration::from_secs(60);
    client.reboot_settle = Duration::from_millis(500);
    let started = Instant::now();
    let err = bound_call!(client, wait_for_agent()).expect_err("stays stopped");
    assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning, "{err}");
    assert_eq!(err.readiness_reason(), Some(Reason::VmNotRunning));
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{:?}",
        started.elapsed()
    );

    let mut client = client_for("reboot_error_state");
    client.agent_timeout = Duration::from_secs(60);
    client.reboot_settle = Duration::from_millis(500);
    let started = Instant::now();
    let err = bound_call!(client, wait_for_agent()).expect_err("error state");
    assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning, "{err}");
    assert_eq!(err.readiness_reason(), Some(Reason::VmNotRunning));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );

    let mut client = client_for("reboot_loop");
    client.agent_timeout = Duration::from_secs(60);
    let err = bound_call!(client, wait_for_agent()).expect_err("restart loop");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err}");
    assert_eq!(err.readiness_reason(), Some(Reason::GuestRestarts));

    // Through create, each is the cleanup-triggering readiness failure and
    // carries its reason onto the wire.
    let (mut runtime, _) = runtime_for("reboot_error_state");
    runtime.client_mut().reboot_settle = Duration::from_millis(500);
    let err = runtime
        .create_bound(&create_req())
        .unwrap_err()
        .into_error();
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err}");
    assert_eq!(
        err.wire_reason(),
        Some(sandbox_protocol::ProtocolErrorReason::Readiness(
            Reason::VmNotRunning
        ))
    );
}

/// Incus reports Error for the instant the old QEMU process of a restarting
/// VM is alive with its monitor gone. A state read landing there during the
/// Ubuntu 26.04 first-boot reboot (about 13 s after start, live chaos stack
/// 2026-11-07: `vm_not_running` after 23.6 s) is a reboot phase, in the
/// agent wait and in the post-pass validation alike.
#[test]
fn a_teardown_error_read_during_a_guest_reboot_is_a_restart() {
    let mut client = client_for("teardown_error_agent_wait");
    client.agent_timeout = Duration::from_secs(30);
    bound_call!(client, wait_for_agent()).expect("ready after the reboot");

    for mode in ["teardown_error_agent_wait", "teardown_error_mid_readiness"] {
        let (runtime, log) = runtime_for(mode);
        runtime
            .create_bound(&create_req())
            .unwrap_or_else(|err| panic!("{mode}: create survives the reboot: {err}"));
        let dir = log.parent().unwrap();
        assert!(
            dir.join("teardown-error").exists(),
            "{mode}: Error was read"
        );
        let boots = fs::read_to_string(dir.join("boots")).unwrap();
        assert_eq!(boots, "2", "{mode}: the shim rebooted the guest once");
    }

    // Every `vm_not_running` names its path, the Incus status it read and
    // the time since the VM was last seen Running (host facts only).
    let assert_detail = |err: &crate::RuntimeError, parts: &[&str]| {
        assert_eq!(
            err.readiness_reason(),
            Some(sandbox_protocol::ReadinessFailureReason::VmNotRunning),
            "{err}"
        );
        let detail = err
            .not_running_detail()
            .map(ToString::to_string)
            .unwrap_or_default();
        for part in parts {
            assert!(err.message.contains(part), "{part:?} missing: {err}");
            assert!(
                detail.contains(part),
                "{part:?} missing from detail {detail:?}"
            );
        }
    };
    let mut client = client_for("reboot_error_state");
    client.agent_timeout = Duration::from_secs(30);
    client.reboot_settle = Duration::from_millis(500);
    let err = bound_call!(client, wait_for_agent()).expect_err("lasting Error");
    assert_detail(
        &err,
        &[
            "readiness path settle",
            "observed status Error/112",
            "last seen Running ",
            " ms ago",
        ],
    );

    let mut client = client_for("stopped");
    client.agent_timeout = Duration::from_secs(5);
    let err = bound_call!(client, wait_for_agent()).expect_err("never started");
    assert_detail(
        &err,
        &[
            "readiness path pre_run_stop",
            "observed status Stopped/102",
            "last seen Running never",
        ],
    );

    let (runtime, _) = runtime_for("frozen_after_check");
    let err = runtime
        .create_bound(&create_req())
        .expect_err("frozen after the checks")
        .into_error();
    assert_detail(
        &err,
        &[
            "readiness path validate_pass",
            "observed status Frozen/110",
            " ms ago",
        ],
    );
}

/// P2-1: Incus can reset a guest inside the same QEMU process (state stays
/// Running, pid unchanged). The guest kernel's boot id still changes, so the
/// failed pass runs again instead of failing readiness.
#[test]
fn a_same_pid_reset_under_a_readiness_step_reruns_the_pass() {
    let (runtime, log) = runtime_for("same_pid_reset");
    runtime
        .create_bound(&create_req())
        .expect("create survives an in-process guest reset");
    assert!(log.parent().unwrap().join("reset-done").exists());
}

/// P2-2: a restart after the last allowed pass is `guest_restarts`, never
/// READY: every pass result is validated, including the final one.
#[test]
fn a_reboot_after_every_pass_is_guest_restarts_never_ready() {
    let (runtime, _) = runtime_for("reboot_after_every_pass");
    let err = runtime
        .create_bound(&create_req())
        .expect_err("a guest that restarts after every pass is never ready")
        .into_error();
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err}");
    assert_eq!(
        err.readiness_reason(),
        Some(sandbox_protocol::ReadinessFailureReason::GuestRestarts)
    );
}

/// P2-3: a non-Running, non-boot state observed after the checks (Frozen
/// here) invalidates them: `vm_not_running`, never READY.
#[test]
fn a_frozen_vm_after_the_checks_is_never_ready() {
    let (runtime, _) = runtime_for("frozen_after_check");
    let err = runtime
        .create_bound(&create_req())
        .expect_err("frozen after the checks")
        .into_error();
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err}");
    assert_eq!(
        err.readiness_reason(),
        Some(sandbox_protocol::ReadinessFailureReason::VmNotRunning)
    );
}

/// P2-4: each guest check is clamped to the remaining shared budget, and a
/// budget spent before the final host observation is `agent_timeout`.
#[test]
fn a_check_that_outlives_the_budget_is_agent_timeout_never_ready() {
    let (mut runtime, _) = runtime_for("slow_network");
    runtime.client_mut().agent_timeout = Duration::from_millis(1500);
    let started = Instant::now();
    let err = runtime
        .create_bound(&create_req())
        .expect_err("the network check outlives the budget")
        .into_error();
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err}");
    assert_eq!(
        err.readiness_reason(),
        Some(sandbox_protocol::ReadinessFailureReason::AgentTimeout)
    );
    // Clamped: the 10 s network check never ran to completion.
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
}

/// P2-5: once the VM was seen Stopped, a stalled state query is cut at the
/// settle bound and fails `vm_not_running`, not at the (longer) budget.
#[test]
fn a_stalled_query_after_a_stop_is_bounded_by_the_settle_window() {
    use sandbox_protocol::ReadinessFailureReason as Reason;
    let mut client = client_for("stopped_then_stalled");
    client.agent_timeout = Duration::from_secs(60);
    client.reboot_settle = Duration::from_millis(1500);
    let started = Instant::now();
    let err = bound_call!(client, wait_for_agent()).expect_err("stalled after a stop");
    assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning, "{err}");
    assert_eq!(err.readiness_reason(), Some(Reason::VmNotRunning));
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
}

/// Codex R2-1: the binding refresh inside the final observations is bounded
/// by the shared deadline too; a refresh that eats the budget is
/// `agent_timeout`, never a late READY.
#[test]
fn a_binding_refresh_past_the_deadline_is_agent_timeout_never_ready() {
    // Budget 4 s; the network check takes 1.5 s, so at most 2.5 s remain for
    // the final boot read, whose binding refresh stalls 3 s (less than the
    // full 4 s client timeout).
    let (mut runtime, _) = runtime_for("slow_metadata_after_network");
    runtime.client_mut().agent_timeout = Duration::from_secs(4);
    let err = runtime
        .create_bound(&create_req())
        .expect_err("the final observation outlives the budget")
        .into_error();
    assert_eq!(
        err.readiness_reason(),
        Some(sandbox_protocol::ReadinessFailureReason::AgentTimeout),
        "{err}"
    );
}

/// Codex R2-2: after a Stopped read, a stalled instance-metadata query (the
/// binding refresh, not `/state`) is also cut at the settle bound.
#[test]
fn a_stalled_binding_refresh_after_a_stop_is_bounded_by_the_settle_window() {
    let mut client = client_for("stopped_then_metadata_stall");
    client.agent_timeout = Duration::from_secs(60);
    // Longer than one 2 s poll, so a capped refresh actually runs.
    client.reboot_settle = Duration::from_secs(3);
    let started = Instant::now();
    let err = bound_call!(client, wait_for_agent()).expect_err("stalled after a stop");
    assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning, "{err}");
    assert_eq!(
        err.readiness_reason(),
        Some(sandbox_protocol::ReadinessFailureReason::VmNotRunning)
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
}

/// Live P2-1: a declared uid that cannot enter HOME (wrong uid/gid against a
/// 0750 home) fails fast as `guest_user`: readiness execs run with cwd `/`,
/// so the agent probe answers and the identity script names the mismatch.
#[test]
fn a_wrong_uid_fails_fast_as_guest_user_not_agent_timeout() {
    let (mut runtime, _) = runtime_for("home_not_searchable");
    let agent_timeout = Duration::from_secs(60);
    runtime.client_mut().agent_timeout = agent_timeout;
    let started = Instant::now();
    let err = runtime
        .create_bound(&create_req())
        .expect_err("wrong uid")
        .into_error();
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err}");
    assert_eq!(
        err.readiness_reason(),
        Some(sandbox_protocol::ReadinessFailureReason::GuestUser)
    );
    // Fast means before the agent budget ran out, the only wait a
    // non-fast failure would add. The shimmed create before readiness
    // takes over 10 s by itself when the suite shares a busy host.
    assert!(started.elapsed() < agent_timeout, "{:?}", started.elapsed());
}

/// Live 1: an unreadable boot id is never READY (it counts as a restart,
/// so a guest whose boot never reads ends `guest_restarts`).
#[test]
fn an_unreadable_boot_id_is_never_ready() {
    let (runtime, _) = runtime_for("boot_unreadable");
    let err = runtime
        .create_bound(&create_req())
        .expect_err("boot id never reads")
        .into_error();
    assert_eq!(
        err.readiness_reason(),
        Some(sandbox_protocol::ReadinessFailureReason::GuestRestarts),
        "{err}"
    );
}

/// Readiness has ONE budget: after a slow state query spent part of it, the
/// probe runs with what is left, and its exit 0 is final (no deadline
/// recheck after the probe). Built so only that first probe can succeed: a
/// dropped or overruled first probe would need a second pass (another 1.7 s
/// query after a 2 s readiness poll), which cannot fit the 4 s budget, so
/// exactly one probe ran. The real-time `wait_process` final-poll edge is
/// `client::tests::run_process_keeps_a_child_that_exits_inside_the_final_poll`.
#[test]
fn wait_for_agent_gives_the_probe_the_budget_a_slow_state_query_left() {
    let (mut client, log) = client_for_with_log("deadline_edge");
    client.agent_timeout = Duration::from_secs(4);
    bound_call!(client, wait_for_agent())
        .expect("binding, a 1.7 s Running state query and the probe fit one 4 s budget");
    let log = fs::read_to_string(log).unwrap();
    let probes = log
        .lines()
        .filter(|line| line.starts_with("exec ") && line.ends_with(" true"))
        .count();
    assert_eq!(probes, 1, "{log}");
}

/// A state query that never answers is cut by the readiness budget. The
/// shim's queries block until released, which the test never does, so no
/// query can have finished (structural: no `query-finished` marker) and the
/// wait can only have ended through its own deadline. The elapsed bound only
/// separates the 200 ms budget from every other bound on this path (the
/// shim's 60 s hang guard, the production agent budget): it is not the edge
/// under test, so it leaves room for kill and reap under load.
#[test]
fn wait_for_agent_bounds_a_slow_state_query() {
    let (mut client, log) = client_for_with_log("query_blocked");
    let statedir = log.parent().unwrap().to_path_buf();
    client.agent_timeout = Duration::from_millis(200);
    let started = Instant::now();
    let err = bound_call!(client, wait_for_agent())
        .expect_err("blocked query must not hang past the budget");
    let elapsed = started.elapsed();
    assert_eq!(
        err.code,
        SandboxErrorCode::Timeout,
        "hung query before a Running/Starting fact is Timeout, got {}",
        err.code
    );
    assert!(
        !statedir.join("query-finished").exists(),
        "the wait returned only after a query finished"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "budget 200ms, blocked query, elapsed {elapsed:?}"
    );
    // Release any shim the kill missed, so none outlives the test.
    fs::write(statedir.join("release-query"), b"").unwrap();
}

#[test]
fn ordinary_stats_bind_and_recheck_without_readiness_probes() {
    let (runtime, log) = runtime_for("running");
    fs::write(&log, "").unwrap(); // Constructor project verification is separate.
    for i in 0..10 {
        runtime
            .stat_path(&StatPathRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: format!("op-stat-{i}"),
                idempotency_key: format!("stat-{i}"),
                path: "/root/a".to_string(),
            })
            .expect("stat");
    }
    let queries = query_invocations(&log);
    assert!(
        queries.len() == 20,
        "10 stats must bind and recheck once each, got {}: {}",
        queries.len(),
        fs::read_to_string(&log).unwrap_or_default()
    );
    assert_eq!(
        true_probe_invocations(&log),
        0,
        "ordinary stats must not run readiness true probes: {}",
        fs::read_to_string(&log).unwrap_or_default()
    );
}

#[test]
fn json_shaped_host_cli_errors_are_not_access_denied() {
    let ping = client_for("json_cli_error").ping().expect_err("ping");
    assert_ne!(ping.code, SandboxErrorCode::AccessDenied);
    assert_eq!(ping.code, SandboxErrorCode::Internal);

    let start = bound_call!(
        client_for("json_cli_error"),
        start_bound(sandbox_protocol::VmSize::defaults().unwrap())
    );
    assert_ne!(
        start
            .as_ref()
            .err()
            .map(|err| err.code)
            .unwrap_or(SandboxErrorCode::Internal),
        SandboxErrorCode::AccessDenied
    );

    let stop = bound_call!(client_for("json_cli_error"), stop_force());
    assert_ne!(
        stop.as_ref()
            .err()
            .map(|err| err.code)
            .unwrap_or(SandboxErrorCode::Internal),
        SandboxErrorCode::AccessDenied
    );

    let config = bound_call!(
        client_for("json_cli_error"),
        config_set("user.flycockpit.sandbox_id", "sbx-1")
    )
    .expect_err("config");
    assert_ne!(config.code, SandboxErrorCode::AccessDenied);
    assert!(matches!(config, crate::EffectError::Unknown(_)));
}

#[test]
fn refuse_root_is_path_refused_not_access_denied() {
    let mkdir = bound_call!(client_for("running"), guest_mkdir("/")).expect_err("mkdir");
    assert_eq!(mkdir.code, SandboxErrorCode::PathRefused);
    assert_ne!(mkdir.code, SandboxErrorCode::AccessDenied);

    let remove = bound_call!(client_for("running"), guest_remove("/", true)).expect_err("remove");
    assert_eq!(remove.code, SandboxErrorCode::PathRefused);

    let move_from =
        bound_call!(client_for("running"), guest_move("/", "/tmp/x")).expect_err("move from");
    assert_eq!(move_from.code, SandboxErrorCode::PathRefused);

    let move_to =
        bound_call!(client_for("running"), guest_move("/tmp/x", "/")).expect_err("move to");
    assert_eq!(move_to.code, SandboxErrorCode::PathRefused);

    let (runtime, _) = runtime_for("running");
    let err = runtime
        .mkdir(&MkdirRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-mk".to_string(),
            idempotency_key: "mk-root".to_string(),
            path: "/".to_string(),
        })
        .expect_err("runtime mkdir");
    assert_eq!(err.code, SandboxErrorCode::PathRefused);

    let (runtime, _) = runtime_for("running");
    let err = runtime
        .remove_path(&RemovePathRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-rm".to_string(),
            idempotency_key: "rm-root".to_string(),
            path: "/".to_string(),
            recursive: true,
        })
        .expect_err("runtime remove");
    assert_eq!(err.code, SandboxErrorCode::PathRefused);

    let (runtime, _) = runtime_for("running");
    let err = runtime
        .move_path(&MovePathRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-mv".to_string(),
            idempotency_key: "mv-root".to_string(),
            from: "/".to_string(),
            to: "/tmp/x".to_string(),
        })
        .expect_err("runtime move");
    assert_eq!(err.code, SandboxErrorCode::PathRefused);
}

#[test]
fn ensure_project_shares_initialized_profile_idempotently() {
    let (client, log) = client_for_project("running", "wssp");
    client.ensure_project().expect("create");
    client.ensure_project().expect("idempotent");
    let text = fs::read_to_string(&log).expect("log");
    let creates = text
        .lines()
        .filter(|line| line.split_whitespace().take(2).eq(["project", "create"]))
        .count();
    assert_eq!(creates, 1, "{text}");
    assert!(
        text.contains("project create wssp --config features.profiles=false"),
        "{text}"
    );
    assert!(text.contains("features.images=false"), "{text}");
    assert!(text.contains("profile list --format json"), "{text}");
    // C37: create_vm's start is fenced on a verified applied network policy.
    let plan = super::network::test_plan("sbx-1");
    client.apply_sandbox_network(&plan).expect("apply");
    client.create_vm(&create_req(), &plan).expect("launch");
    let text = fs::read_to_string(&log).expect("log");
    assert!(
        text.contains(
            "-- abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 wssp-sbx-sbx-1"
        ),
        "{text}"
    );
}

#[test]
fn launch_in_new_project_fails_without_profile_devices() {
    let (client, _) = client_for_project("running", "wssp");
    let err = client
        .create_vm(&create_req(), &super::network::test_plan("sbx-1"))
        .expect_err("missing profile");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
}

#[test]
fn kvm_runtime_new_provisions_project_before_launch() {
    let (_runtime, log) = runtime_for_project("running", "wssp");
    let text = fs::read_to_string(&log).expect("log");
    assert!(text.contains("project create wssp"), "{text}");
    assert!(
        text.contains("project create wssp --config features.profiles=false"),
        "{text}"
    );
    assert!(text.contains("features.images=false"), "{text}");
    assert!(text.contains("profile list --format json"), "{text}");
}

#[test]
fn ensure_project_rejects_existing_private_image_store() {
    let (client, log) = client_for_project("running", "wssp");
    seed_existing_incus_project(Path::new(&client.binary), "wssp", true, false);
    let err = client.ensure_project().expect_err("private image store");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    assert!(err.message.contains("features.images=false"));
    assert!(err.message.contains("WSSP_INCUS_PROJECT=default"));
    let text = fs::read_to_string(&log).expect("log");
    assert!(
        !text
            .lines()
            .any(|line| line.split_whitespace().take(2).eq(["project", "create"])),
        "must not mutate an existing project: {text}"
    );
    assert!(
        text.contains("query --raw /1.0/projects/wssp?project=default"),
        "{text}"
    );
}

#[test]
fn ensure_project_accepts_existing_shared_project() {
    let (client, log) = client_for_project("running", "wssp");
    seed_existing_incus_project(Path::new(&client.binary), "wssp", true, true);
    client.ensure_project().expect("shared project");
    client.ensure_project().expect("idempotent");
    let text = fs::read_to_string(&log).expect("log");
    assert!(
        !text
            .lines()
            .any(|line| line.split_whitespace().take(2).eq(["project", "create"])),
        "{text}"
    );
    assert!(
        text.contains("query --raw /1.0/projects/wssp?project=default"),
        "{text}"
    );
}

#[test]
fn startup_rejects_uninitialized_default_profile() {
    let (client, _) = client_for_project("empty_profile", "wssp");
    let err = client
        .ensure_project()
        .expect_err("empty profile cannot launch VMs");
    assert!(err.message.contains("root disk"));
}

#[test]
fn metadata_values_cannot_be_parsed_as_incus_options() {
    let (client, log) = client_for_project("running", "wssp");
    bound_call!(
        client,
        config_set("user.wssp.idempotency_key", "--project=default",)
    )
    .expect("literal metadata");
    let text = fs::read_to_string(log).expect("log");
    assert!(
        text.contains("config set -- wssp-sbx-sbx-1 user.wssp.idempotency_key --project=default")
    );
    assert!(bound_call!(client, config_set("--project", "default")).is_err());
}

#[test]
fn supervised_command_wssp_exit_proves_terminal_exit_code() {
    let supervisor = ExecSupervisor::new(client_for("exit1"));
    let response = run_bound!(supervisor, run(&run_req("op-exit"))).expect("terminal");
    assert_eq!(response.command.exit_code, Some(1));
    assert_eq!(
        response.command.state,
        sandbox_protocol::OperationState::Succeeded
    );
}

#[test]
fn post_issue_inventory_never_mints_terminal_failed_for_mutations() {
    for mode in ["post_issue_stopped", "post_issue_gone", "post_issue_denied"] {
        let signal = tracked_helper_signal(client_for(mode), GuestIdentity::default()).unwrap_err();
        assert!(matches!(signal, crate::EffectError::Unknown(_)), "{mode}");
        assert_eq!(signal.code, SandboxErrorCode::UnknownOutcome, "{mode}");

        assert_eq!(
            bound_call!(
                client_for(mode),
                file_push("/tmp/x", &crate::FileContent::from_bytes(b"data").unwrap())
            )
            .expect_err("push")
            .code,
            SandboxErrorCode::UnknownOutcome,
            "push in {mode}"
        );
        for err in [
            bound_call!(client_for(mode), guest_mkdir("/root/a")).expect_err("mkdir"),
            bound_call!(client_for(mode), guest_remove("/root/a", true)).expect_err("remove"),
            bound_call!(client_for(mode), guest_move("/root/a", "/root/b")).expect_err("move"),
        ] {
            assert_eq!(err.code, SandboxErrorCode::UnknownOutcome, "in {mode}");
        }
        let supervisor = ExecSupervisor::new(client_for(mode));
        let response = run_bound!(supervisor, run(&run_req(&format!("cmd-{mode}"))))
            .expect_err("command inconclusive");
        if mode == "post_issue_stopped" {
            assert_eq!(response.state(), sandbox_protocol::OperationState::Failed);
            assert_eq!(response.code, SandboxErrorCode::GuestUnavailable);
        } else {
            assert_eq!(
                response.state(),
                sandbox_protocol::OperationState::UnknownOutcome,
                "command in {mode}"
            );
        }
    }
}

#[test]
fn lifecycle_post_attempt_query_errors_are_unknown() {
    let client = client_for("lifecycle_post_query_denied");
    // C37: start is fenced on verified network enforcement; apply first so
    // the start reaches the post-issue observation this test exercises.
    client
        .apply_sandbox_network(&super::network::test_plan("sbx-1"))
        .expect("apply");
    for err in [
        bound_call!(
            client,
            start_bound(sandbox_protocol::VmSize::defaults().unwrap())
        )
        .expect_err("start"),
        bound_call!(client, stop_force()).expect_err("stop"),
        bound_call!(client, delete_force()).expect_err("delete"),
    ] {
        assert!(matches!(err, crate::EffectError::Unknown(_)));
    }
}

#[test]
fn config_set_requires_readback_proof() {
    let client = client_for("running");
    bound_call!(client, config_set("user.test", "expected")).expect("verified set");
    let client = client_for("config_set_no_readback");
    assert_eq!(
        bound_call!(client, config_set("user.test", "expected"))
            .expect_err("unverified")
            .code,
        SandboxErrorCode::UnknownOutcome
    );
}

#[test]
fn lifecycle_cli_success_without_inventory_proof_is_unknown() {
    assert_eq!(
        bound_call!(client_for("lifecycle_incomplete_stop"), stop_force())
            .expect_err("stop")
            .code,
        SandboxErrorCode::UnknownOutcome
    );
    assert_eq!(
        bound_call!(client_for("lifecycle_incomplete_delete"), delete_force())
            .expect_err("delete")
            .code,
        SandboxErrorCode::UnknownOutcome
    );
    // C37: start's verified-policy fence runs pre-issue; apply the network so
    // this test still reaches the post-issue inventory proof it exercises.
    let client = client_for("lifecycle_incomplete_start");
    client
        .apply_sandbox_network(&super::network::test_plan("sbx-1"))
        .expect("apply");
    assert_eq!(
        bound_call!(
            client,
            start_bound(sandbox_protocol::VmSize::defaults().unwrap())
        )
        .expect_err("start")
        .code,
        SandboxErrorCode::UnknownOutcome
    );
}

#[test]
fn incus_spawn_failure_is_host_effect_not_issued() {
    let client = IncusClient::new(
        "/nonexistent-wssp-incus-binary".to_string(),
        "default".to_string(),
    );
    assert_eq!(
        client.ping().expect_err("ping").code,
        SandboxErrorCode::HostEffectNotIssued
    );
}

/// B2-C-2: through the real host path (spawn plus kill deadline) a slow
/// guest listing reaches its own precise `fs_listing_limit` before the host
/// kills it, because the guest budget ends inside the host deadline.
#[test]
fn listing_time_budget_is_reached_through_the_host_before_its_kill_deadline() {
    let mut client = client_for("slow_listing");
    let statedir = Path::new(&client.binary).parent().unwrap().to_path_buf();
    // Run the real helper locally with a slow scandir, never a VM.
    fs::write(
        statedir.join("inject.py"),
        "import os, sys\na = sys.argv[1:]\nslow = '_orig = os.scandir\\ndef _slow(fd):\\n    time.sleep(0.4)\\n    return _orig(fd)\\nos.scandir = _slow\\n'\na[3] = a[3].replace('try:\\n    run()', slow + 'try:\\n    run()')\nos.execvp(a[0], a)\n",
    )
    .unwrap();
    let tree = statedir.join("tree");
    for index in 0..12 {
        fs::create_dir_all(tree.join(format!("d{index:02}/inner"))).unwrap();
    }
    client.agent_timeout = std::time::Duration::from_secs(4);
    let (host, guest) = crate::metadata::observation_budgets(client.agent_timeout);
    assert!(guest < host);
    let started = std::time::Instant::now();
    let err = bound_call!(
        client,
        guest_list_page(&list_request(&client, tree.to_str().unwrap(), 2))
    )
    .expect_err("slow list");
    assert!(started.elapsed() < host, "{:?}", started.elapsed());
    assert_eq!(err.code, SandboxErrorCode::FsListingLimit);
    assert_eq!(
        err.failure().unwrap().effect,
        sandbox_protocol::results::FailureEffect::None
    );
    // Default dispatch timeouts keep the full shared 30 s guest budget.
    assert_eq!(
        crate::metadata::observation_budgets(std::time::Duration::from_secs(120)),
        (
            crate::metadata::OBSERVATION_TIMEOUT + crate::metadata::OBSERVATION_SLACK,
            crate::metadata::OBSERVATION_TIMEOUT
        )
    );
}

/// B2-K-2: a stat or download whose helper left no record is plane loss.
/// The host re-observes the VM: stopped → sandbox_not_running, otherwise
/// unknown_outcome (B2R2-K-2: never guest_unavailable, even with the agent
/// gone) — never protocol_error, and never an effect other than none for a
/// read-only observation.
#[test]
fn read_only_observation_without_a_record_rechecks_the_vm() {
    for (mode, expected) in [
        ("post_issue_stopped", SandboxErrorCode::SandboxNotRunning),
        ("agent_down", SandboxErrorCode::UnknownOutcome),
        ("cli_transport_loss", SandboxErrorCode::UnknownOutcome),
        ("post_issue_gone", SandboxErrorCode::UnknownOutcome),
    ] {
        let stat = bound_call!(client_for(mode), guest_stat("/tmp/x")).expect_err("stat");
        let pull = bound_call!(client_for(mode), file_pull("/tmp/x")).expect_err("pull");
        for (label, err) in [("stat", stat), ("pull", pull)] {
            assert_eq!(err.code, expected, "{label} in {mode}");
            assert!(
                err.failure()
                    .is_none_or(|f| f.effect == sandbox_protocol::results::FailureEffect::None),
                "{label} in {mode}"
            );
        }
    }
}

/// B2R2-C-4: a valid `ok` record followed by the transport's own error line
/// and a non-zero exit is plane loss too: the host re-observes the VM
/// instead of reporting protocol_error.
#[test]
fn a_valid_record_then_a_transport_drop_rechecks_the_vm() {
    for (mode, expected) in [
        ("post_issue_stopped", SandboxErrorCode::SandboxNotRunning),
        ("running", SandboxErrorCode::UnknownOutcome),
    ] {
        let (client, log) = client_for_with_log(mode);
        fs::write(log.parent().unwrap().join("record-then-drop"), b"").unwrap();
        let stat = bound_call!(client, guest_stat("/tmp/x")).expect_err("stat");
        let list = bound_call!(client, guest_list_page(&list_request(&client, "/tmp/x", 1)))
            .expect_err("list");
        let pull = bound_call!(client, file_pull("/tmp/x")).expect_err("pull");
        for (label, err) in [("stat", stat), ("list", list), ("pull", pull)] {
            assert_eq!(err.code, expected, "{label} in {mode}: {err}");
            assert!(
                err.failure()
                    .is_none_or(|f| f.effect == sandbox_protocol::results::FailureEffect::None),
                "{label} in {mode}"
            );
        }
    }
}

#[test]
fn cli_transport_loss_without_completion_is_unknown() {
    let (runtime, _) = runtime_for("cli_transport_loss");
    let client = client_for("cli_transport_loss");
    assert_eq!(
        bound_call!(
            client,
            file_push("/tmp/x", &crate::FileContent::from_bytes(b"data").unwrap())
        )
        .expect_err("push")
        .code,
        SandboxErrorCode::UnknownOutcome
    );
    for err in [
        bound_call!(client, guest_mkdir("/root/a")).expect_err("mkdir"),
        bound_call!(client, guest_remove("/root/a", true)).expect_err("remove"),
        bound_call!(client, guest_move("/root/a", "/root/b")).expect_err("move"),
    ] {
        assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
    }
    let supervisor = ExecSupervisor::new(client);
    let response = run_bound!(supervisor, run(&run_req("cmd-loss"))).expect_err("command");
    assert_eq!(
        response.state(),
        sandbox_protocol::OperationState::UnknownOutcome
    );
    assert_eq!(
        runtime
            .write_file(&WriteFileRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "put-loss".to_string(),
                generation: 1,
                attempt: 1,
                idempotency_key: "put-loss".to_string(),
                path: "/tmp/x".to_string(),
                bytes: crate::FileContent::from_bytes(b"x").expect("file capture"),
                guest: GuestIdentity::default(),
            })
            .expect_err("write")
            .code,
        SandboxErrorCode::UnknownOutcome
    );
}

#[test]
fn ensure_project_rejects_create_race_private_image_store() {
    let (client, log) = client_for_project("project_create_race", "wssp");
    seed_race_project_metadata(Path::new(&client.binary), "wssp", true, false);
    let err = client.ensure_project().expect_err("race private images");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    assert!(err.message.contains("features.images=false"));
    let text = fs::read_to_string(&log).expect("log");
    assert!(
        text.contains("query --raw /1.0/projects/wssp?project=default"),
        "{text}"
    );
}

/// Current host UID, so the real helper's owner check matches in passthrough.
fn local_uid() -> u32 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|ids| ids.split_whitespace().next().map(str::to_string))
        })
        .and_then(|uid| uid.parse().ok())
        .unwrap_or(1000)
}

/// 4b, approved Branch A: the real open-then-verify helper delivers to the
/// tracked process GROUP, reaching the user child under the exact wrapper,
/// which then reports its own exit.
/// Shared conformance table: the same host-map race and qualifier cases run
/// against FakeRuntime and Incus. A definite mismatch is never a gone verdict.
fn signal_resolution_table(
    base: &crate::SignalTarget,
    mut signal: impl FnMut(crate::SignalTarget) -> crate::EffectOutcome<crate::SignalOutcome>,
) {
    for (row, code, state) in [
        (
            "missing",
            SandboxErrorCode::UnknownOutcome,
            sandbox_protocol::OperationState::UnknownOutcome,
        ),
        (
            "generation",
            SandboxErrorCode::ProcessNotFound,
            sandbox_protocol::OperationState::Failed,
        ),
        (
            "attempt",
            SandboxErrorCode::ProcessNotFound,
            sandbox_protocol::OperationState::Failed,
        ),
        (
            "pid",
            SandboxErrorCode::ProcessNotFound,
            sandbox_protocol::OperationState::Failed,
        ),
    ] {
        let mut target = base.clone();
        match row {
            "missing" => target.target_operation_id = "missing".into(),
            "generation" => target.generation += 1,
            "attempt" => target.attempt += 1,
            "pid" => target.pid += 1,
            _ => unreachable!(),
        }
        let err = signal(target).unwrap_err();
        assert_eq!(err.code, code, "{row}");
        assert_eq!(err.state(), state, "{row}");
    }
}

#[test]
fn signal_resolution_shared_table_fake_and_incus_with_no_helper_for_mismatch() {
    let (runtime, log) = runtime_for("passthrough");
    let ops = log.parent().unwrap().join("ops");
    fs::create_dir_all(&ops).unwrap();
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops));
    let supervisor = runtime.exec_supervisor();
    let worker = runtime.exec_supervisor();
    let mut request = run_req("resolution-op");
    request.argv = vec!["sleep".into(), "30".into()];
    request.guest.guest_uid = local_uid();
    let live = request.clone();
    let handle = std::thread::spawn(move || run_bound!(worker, run(&live)));
    let deadline = Instant::now() + Duration::from_secs(5);
    let birth = loop {
        if let Some(birth) = supervisor.active_birth(&request.operation_id) {
            break birth;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    };
    let bound = supervisor.bind(&request).unwrap();
    let target = crate::SignalTarget {
        target_operation_id: request.operation_id.clone(),
        generation: request.generation,
        attempt: request.attempt,
        pid: birth.pid,
    };
    let baseline = fs::read(&log).unwrap();
    signal_resolution_table(&target, |target| {
        // Pass each target's PID so the host qualifier check is exercised.
        let result = supervisor.signal(&bound, target.pid, ProcessSignal::Sigterm, Some(&target));
        assert_eq!(
            fs::read(&log).unwrap(),
            baseline,
            "refusal must precede helper or query IO"
        );
        if let Err(error) = &result
            && error.code == SandboxErrorCode::ProcessNotFound
        {
            assert!(matches!(error, crate::EffectError::NotIssued(_)));
        }
        result
    });
    supervisor.cancel(&request.operation_id).unwrap();
    let _ = handle.join().unwrap();
    let missing = supervisor
        .signal(&bound, target.pid, ProcessSignal::Sigterm, Some(&target))
        .unwrap_err();
    assert_eq!(
        missing.state(),
        sandbox_protocol::OperationState::UnknownOutcome,
        "finished active-map miss"
    );

    let fake = crate::FakeRuntime::with_command_delay(Duration::from_secs(30));
    fake.create_fixture(&create_req()).unwrap();
    let output = crate::CommandOutput::default();
    let worker = fake.clone();
    let sink = output.clone();
    let live = request.clone();
    let handle = std::thread::spawn(move || worker.run_command_stream(&live, &sink));
    let deadline = Instant::now() + Duration::from_secs(5);
    let birth = loop {
        if let Some(birth) = output.start() {
            break birth;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    };
    let target = crate::SignalTarget {
        pid: birth.pid,
        ..target
    };
    let call = |target: crate::SignalTarget, signal| {
        fake.signal_process(&SignalProcessRequest {
            template_fingerprint: request.template_fingerprint.clone(),
            guest: request.guest.clone(),
            sandbox_id: request.sandbox_id.clone(),
            instance_name: request.instance_name.clone(),
            operation_id: "sig-resolution".into(),
            idempotency_key: "sig-resolution".into(),
            pid: target.pid,
            signal,
            target: Some(target),
        })
    };
    signal_resolution_table(&target, |t| call(t, ProcessSignal::Sigterm));
    call(target.clone(), ProcessSignal::Sigkill).unwrap();
    let _ = handle.join().unwrap();
    let missing = call(target, ProcessSignal::Sigterm).unwrap_err();
    assert_eq!(
        missing.state(),
        sandbox_protocol::OperationState::UnknownOutcome,
        "finished active-map miss"
    );
}

#[test]
fn tracked_sigterm_reaches_user_child_under_wrapper() {
    use std::sync::mpsc;
    use std::thread;
    let ops_dir = std::env::temp_dir().join(format!(
        "wssp-term-ops-{}",
        SHIM_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&ops_dir).expect("ops dir");
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops_dir));
    let marker = std::env::temp_dir().join(format!(
        "wssp-term-marker-{}-{}",
        std::process::id(),
        SHIM_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_file(&marker);
    let (runtime, _) = runtime_for("passthrough");
    let supervisor = runtime.exec_supervisor();
    let worker = runtime.exec_supervisor();
    let marker_arg = marker.to_string_lossy().to_string();
    let mut request = run_req("term-op");
    request.argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("trap 'touch {marker_arg}; exit 143' TERM; echo ready >&2; sleep 120 & wait"),
    ];
    request.timeout_ms = Some(20_000);
    request.guest.guest_uid = local_uid();
    let (done, rx) = mpsc::channel();
    let live = request.clone();
    let handle = thread::spawn(move || {
        let _ = done.send(run_bound!(worker, run(&live)));
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let birth = loop {
        if let Some(birth) = supervisor.active_birth("term-op") {
            break birth;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for start identity"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let target = crate::SignalTarget {
        target_operation_id: "term-op".into(),
        generation: request.generation,
        attempt: request.attempt,
        pid: birth.pid,
    };
    let bound = supervisor.bind(&request).unwrap();
    let outcome = supervisor
        .signal(&bound, birth.pid, ProcessSignal::Sigterm, Some(&target))
        .expect("group delivery")
        .into_value();
    assert_eq!(outcome, crate::SignalOutcome::ProcessGroup);
    let response = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("command finished")
        .expect("response");
    // Delivery is not death: the command's own natural exit status is kept.
    assert_eq!(response.command.exit_code, Some(143));
    assert_eq!(
        response.command.state,
        sandbox_protocol::OperationState::Succeeded
    );
    assert!(marker.exists(), "TERM trap must run in the user child");
    handle.join().unwrap();
    let _ = fs::remove_file(&marker);
}

/// 4b gap: an IN-FLIGHT tracked group-pidfd helper is preempted by the
/// lifecycle path. Sandbox stop/kill admission revokes every older permit
/// of that sandbox first, which kills the helper's transport; the lifecycle
/// effect then completes. The helper never resumes and no HUP is delivered.
#[test]
fn in_flight_tracked_signal_helper_is_preempted_by_stop_or_kill_with_no_late_effect() {
    use std::sync::{Arc, mpsc};
    use std::thread;
    for teardown in ["stop", "kill"] {
        let ops_dir = std::env::temp_dir().join(format!(
            "wssp-preempt-ops-{}-{}",
            std::process::id(),
            SHIM_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&ops_dir).expect("ops dir");
        let _ops = super::exec::set_test_guest_ops_dir(Some(ops_dir));
        let marker = std::env::temp_dir().join(format!(
            "wssp-preempt-marker-{}-{}",
            std::process::id(),
            SHIM_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_file(&marker);
        let (runtime, log) = runtime_for("passthrough");
        let state = log.parent().unwrap().to_path_buf();
        fs::write(state.join("hold-signal-helper"), b"").unwrap();
        let supervisor = runtime.exec_supervisor();
        let worker = runtime.exec_supervisor();
        let marker_arg = marker.to_string_lossy().to_string();
        let mut request = run_req("preempt-op");
        // Only a delivered HUP touches the marker; teardown's own cleanup
        // (TERM/KILL) cannot forge the late effect this test looks for.
        request.argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("trap 'touch {marker_arg}; exit 129' HUP; echo ready >&2; sleep 120 & wait"),
        ];
        request.timeout_ms = Some(20_000);
        request.guest.guest_uid = local_uid();
        let (done, command_rx) = mpsc::channel();
        let live = request.clone();
        let command = thread::spawn(move || {
            let _ = done.send(run_bound!(worker, run(&live)));
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let birth = loop {
            if let Some(birth) = supervisor.active_birth("preempt-op") {
                break birth;
            }
            assert!(Instant::now() < deadline, "no start identity");
            thread::sleep(Duration::from_millis(20));
        };
        let target = crate::SignalTarget {
            target_operation_id: "preempt-op".into(),
            generation: request.generation,
            attempt: request.attempt,
            pid: birth.pid,
        };
        let bound = supervisor.bind(&request).unwrap();
        let permit = Arc::new(crate::RuntimePermit::default());
        let scoped = runtime.exec_supervisor().with_cancellation(permit.clone());
        let (signal_tx, signal_rx) = mpsc::channel();
        let signaller = thread::spawn(move || {
            let _ = signal_tx.send(scoped.signal(
                &bound,
                birth.pid,
                ProcessSignal::Sighup,
                Some(&target),
            ));
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !state.join("signal-helper-entered").exists() {
            assert!(Instant::now() < deadline, "signal helper never started");
            thread::sleep(Duration::from_millis(5));
        }
        // Lifecycle admission: revoke the in-flight signal's permit.
        let preempted_at = Instant::now();
        permit.revoke();
        let outcome = signal_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("revocation preempts the helper well before its 10 s deadline");
        assert!(preempted_at.elapsed() < Duration::from_secs(3));
        let error = outcome.expect_err("a preempted helper is never a delivery");
        // Issued then cut: uncertain, never success or a teardown-grade code.
        assert!(
            matches!(error, crate::EffectError::Unknown(_)),
            "{teardown}: {error:?}"
        );
        assert_ne!(error.code, SandboxErrorCode::GuestUnavailable);
        signaller.join().unwrap();
        // The lifecycle effect itself then completes on its own path.
        let lifecycle = if teardown == "stop" {
            runtime
                .stop_sandbox(&StopSandboxRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "sbx-1".to_string(),
                    instance_name: "wssp-sbx-sbx-1".to_string(),
                    operation_id: "op-stop".to_string(),
                    idempotency_key: "stop-1".to_string(),
                })
                .map(|_| ())
        } else {
            runtime
                .kill_bound(&KillSandboxRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "sbx-1".to_string(),
                    instance_name: "wssp-sbx-sbx-1".to_string(),
                    operation_id: "op-kill".to_string(),
                    idempotency_key: "kill-1".to_string(),
                })
                .map(|_| ())
        };
        assert!(lifecycle.is_ok(), "{teardown}: {lifecycle:?}");
        // Releasing the held helper now has nothing left to resume.
        fs::write(state.join("release-signal-helper"), b"").unwrap();
        thread::sleep(Duration::from_millis(500));
        assert!(
            !state.join("signal-helper-resumed").exists(),
            "{teardown}: the preempted helper resumed"
        );
        assert!(!marker.exists(), "{teardown}: late HUP effect");
        // Clean up through the command's own single cancellation owner.
        let _ = supervisor.cancel("preempt-op");
        let _ = command_rx.recv_timeout(Duration::from_secs(10));
        command.join().unwrap();
        assert!(
            !marker.exists(),
            "{teardown}: late HUP effect after cleanup"
        );
        let _ = fs::remove_file(&marker);
    }
}

#[test]
fn live_start_binding_is_host_clocked_published_once_and_repeated_in_the_final_result() {
    use std::sync::mpsc;
    use std::thread;
    let ops_dir = std::env::temp_dir().join(format!(
        "wssp-birth-ops-{}-{}",
        std::process::id(),
        SHIM_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&ops_dir).expect("ops dir");
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops_dir.clone()));
    let (runtime, _) = runtime_for("passthrough");
    let output = crate::CommandOutput::default();
    let supervisor = runtime.exec_supervisor();
    let worker = runtime.exec_supervisor().with_output(output.clone());
    let mut request = run_req("birth-op");
    request.argv = vec!["/bin/sh".into(), "-c".into(), "sleep 1; echo out".into()];
    request.timeout_ms = Some(10_000);
    let before = super::exec::host_now_ms();
    let (done, rx) = mpsc::channel();
    let live = request.clone();
    let handle = thread::spawn(move || {
        let _ = done.send(run_bound!(worker, run(&live)));
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let birth = loop {
        if let Some(birth) = supervisor.active_birth("birth-op") {
            break birth;
        }
        assert!(Instant::now() < deadline, "start record never bound");
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(Some(birth.pid), supervisor.active_guest_pid("birth-op"));
    assert!(birth.started_at_ms >= before && birth.started_at_ms <= super::exec::host_now_ms());
    let (_, description) = supervisor.active_process("birth-op").expect("tracked");
    assert_eq!(description.cmd, "/bin/sh");
    assert_eq!(output.take_unpublished_start(), Some(birth.clone()));
    assert_eq!(
        output.take_unpublished_start(),
        None,
        "published at most once"
    );
    let response = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("finished")
        .expect("response");
    assert_eq!(response.command.birth, Some(birth.clone()));
    assert_eq!(response.command.exit_code, Some(0));
    handle.join().unwrap();

    // Fast exit: no live decision is required for final identity.
    let fast_output = crate::CommandOutput::default();
    let fast = runtime.exec_supervisor().with_output(fast_output.clone());
    let mut quick = run_req("birth-fast");
    quick.argv = vec!["true".into()];
    let response = run_bound!(fast, run(&quick)).expect("fast");
    let fast_birth = response.command.birth.clone().expect("fast identity");
    assert_ne!(fast_birth.pid, birth.pid);
    assert_eq!(fast_output.start(), Some(fast_birth));
    let _ = std::fs::remove_dir_all(ops_dir);
}

#[test]
fn scoped_exec_wait_and_later_helper_spawns_obey_revocation() {
    use std::sync::{Arc, mpsc};
    for supervised in [false, true] {
        let (runtime, log) = runtime_for("blocked_prestart");
        let bound = runtime
            .client()
            .bind_instance(
                "wssp-sbx-sbx-1",
                "sbx-1",
                &create_req().template_digest,
                None,
            )
            .unwrap();
        let permit = Arc::new(crate::RuntimePermit::default());
        let scoped = runtime.with_cancellation(permit.clone());
        let exec = runtime.exec_supervisor().with_cancellation(permit.clone());
        let (done, result) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let request = run_req("revoked-command");
            let outcome = if supervised {
                run_bound!(
                    exec,
                    run_with_admission(&request, || {
                        Ok((Arc::new(std::sync::atomic::AtomicBool::new(false)), ()))
                    })
                )
            } else {
                scoped.run_command(&request)
            };
            done.send(outcome).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !log_invoked(&log, "exec") {
            assert!(Instant::now() < deadline, "exec did not start");
            std::thread::sleep(Duration::from_millis(2));
        }
        permit.revoke();
        let error = result
            .recv_timeout(Duration::from_secs(2))
            .expect("revocation interrupts exec wait")
            .expect_err("preempted");
        assert_eq!(error.code, SandboxErrorCode::UnknownOutcome);
        worker.join().unwrap();
        let before = fs::read_to_string(&log).unwrap();
        let exec = runtime.exec_supervisor().with_cancellation(permit.clone());
        assert_eq!(
            run_bound!(exec, run(&run_req("later")))
                .expect_err("spawn fenced")
                .code,
            SandboxErrorCode::UnknownOutcome
        );
        let target = crate::SignalTarget {
            target_operation_id: "revoked-command".into(),
            generation: 1,
            attempt: 1,
            pid: 4242,
        };
        for signal in [ProcessSignal::Sigterm, ProcessSignal::Sigkill] {
            let error = exec
                .signal(&bound, 4242, signal, Some(&target))
                .expect_err("signal fenced");
            // A host-side permit/fence refusal is never a teardown-grade code.
            assert!(
                matches!(error, crate::EffectError::NotIssued(_)),
                "{signal:?}"
            );
            assert_ne!(error.code, SandboxErrorCode::GuestUnavailable);
        }
        assert_eq!(
            exec.cancel("revoked-command")
                .expect_err("cancel helper fenced")
                .code,
            SandboxErrorCode::UnknownOutcome
        );
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            before,
            "no new Incus process after revocation"
        );
    }
}

#[test]
fn lifecycle_readiness_and_existing_create_failures_are_unknown_after_issue() {
    for observation in ["denied", "garbled", "absent", "stopped"] {
        for operation in ["new", "cold", "existing"] {
            let mode = format!("fix6_{operation}_{observation}");
            let (runtime, log) = runtime_for(&mode);
            if operation == "existing" {
                let config = log.parent().unwrap().join("config");
                fs::create_dir_all(&config).unwrap();
                fs::write(config.join("user.flycockpit.sandbox_id"), "sbx-1").unwrap();
                fs::write(
                    config.join("user.flycockpit.create_idempotency_key"),
                    "create-1",
                )
                .unwrap();
            }
            if operation == "cold" {
                // C37 R1: reconnect verifies the recorded enforcement
                // instead of re-applying it — apply first so the flow
                // reaches the post-issue observation this test exercises.
                runtime
                    .client()
                    .apply_sandbox_network(&super::network::test_plan("sbx-1"))
                    .expect("apply");
            }
            let error = if operation == "cold" {
                runtime
                    .reconnect_bound(&ReconnectSandboxRequest {
                        vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                        lease: sandbox_protocol::HostLease::for_test(),
                        template_fingerprint: crate::CreateSandboxRequest::for_test(
                            "default", "default",
                        )
                        .template_digest,
                        architecture: Some("x86_64".into()),
                        guest: Default::default(),
                        sandbox_id: "sbx-1".into(),
                        instance_name: "wssp-sbx-sbx-1".into(),
                        operation_id: "reconnect".into(),
                        idempotency_key: "reconnect".into(),
                        egress_policy: None,
                        egress_policy_hash: None,
                        egress_admission: crate::egress::EgressAdmission::PERMITTED,
                        guest_sudo: false,
                    })
                    .unwrap_err()
            } else {
                runtime.create_bound(&create_req()).unwrap_err()
            };
            assert!(
                matches!(error, crate::EffectError::Unknown(_)),
                "{mode}: {error:?}"
            );
            assert_eq!(
                error.state(),
                sandbox_protocol::OperationState::UnknownOutcome
            );
            if operation == "new" {
                assert!(log_invoked(&log, "init"));
                assert!(
                    !log_invoked(&log, "delete"),
                    "cleanup requires durable server intent"
                );
            } else if operation == "cold" {
                assert!(log_invoked_start(&log));
            }
        }
    }
    let (runtime, log) = runtime_for("fix6_metadata");
    fs::remove_file(
        log.parent()
            .unwrap()
            .join("config/user.flycockpit.sandbox_id"),
    )
    .unwrap();
    // Existing immutable identity is now audited before any network work.
    // Missing metadata on an existing VM cannot prove that a previous
    // create attempt was ineffective, even before this attempt mutates it.
    assert!(matches!(
        runtime.create_bound(&create_req()).unwrap_err(),
        crate::EffectError::Unknown(_)
    ));
    assert!(!log_invoked(&log, "init"));
    assert!(!log_invoked(&log, "network"));
    assert!(!log_invoked(&log, "config"));
    let (runtime, log) = runtime_for("fix6_launch_absent");
    assert!(matches!(
        runtime.create_bound(&create_req()).unwrap_err(),
        crate::EffectError::Unknown(_)
    ));
    assert!(log_invoked(&log, "init"));
}

#[test]
fn c10_cancel_while_running_stops_writer_before_cancelled() {
    use std::sync::mpsc;
    use std::thread;
    let ops_dir = std::env::temp_dir().join(format!(
        "wssp-c10-ops-{}",
        SHIM_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&ops_dir).expect("ops dir");
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops_dir));
    let (runtime, log) = runtime_for("passthrough");
    let supervisor = runtime.exec_supervisor();
    let worker = runtime.exec_supervisor();
    let armed = log.parent().unwrap().join("writer-armed");
    let request = RunCommandRequest {
template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key").template_digest,
        sandbox_id: "sbx-1".to_string(),
        instance_name: "wssp-sbx-sbx-1".to_string(),
        operation_id: "c10-writer".to_string(),
        idempotency_key: "c10-writer".to_string(),
        generation: 1,
        attempt: 1,
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            // TERM is ignored, so this test covers KILL-driven cancellation
            // (no exit frame); `g3_e20_*` covers a TERM death (frame 143).
            "trap '' TERM; printf armed > \"$1\"; echo armed >&2; while true; do printf '.' >&2; done".to_string(),
            "wssp-writer".to_string(),
            armed.to_string_lossy().into_owned(),
        ],
        script: None,
        cwd: None,
        timeout_ms: Some(5_000),
        env: Vec::new(),
        stdin: None,
            guest: GuestIdentity::default(),
        build_step: None,
    };
    let (done, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let _ = done.send(run_bound!(worker, run(&request)));
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !armed.exists() || supervisor.active_guest_pid("c10-writer").is_none() {
        assert!(Instant::now() < deadline, "timed out before writer armed");
        thread::sleep(Duration::from_millis(5));
    }
    supervisor.cancel("c10-writer").expect("cancel request");
    // A hang guard, not a deadline under test: the TERM-ignoring workload
    // takes the full TERM, grace and KILL rounds of the terminate helper,
    // several seconds under the shims on a loaded host.
    let response = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("command finished")
        .expect("response");
    assert_eq!(
        response.command.state,
        sandbox_protocol::OperationState::Cancelled
    );
    let stderr = String::from_utf8_lossy(
        response
            .command
            .chunks
            .iter()
            .find(|chunk| chunk.stream == crate::CommandStream::Stderr)
            .map(|chunk| chunk.bytes.as_slice())
            .unwrap_or(&[]),
    );
    assert!(
        stderr.contains("armed"),
        "writer must have started before cancel: {stderr}"
    );
    let _ = handle.join();
    // The terminate helper's argv follows a multi-line script argument; the
    // log escapes embedded newlines (C36), so match the whole line content
    // instead of relying on the script spill starting a new log line.
    assert!(
        fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("wssp-terminate"),
        "guest group cleanup must run"
    );
}

#[test]
fn c10_guest_cancel_cleanup_runs_termination_helper() {
    let ops_dir = std::env::temp_dir().join(format!(
        "wssp-c10-kill-ops-{}",
        SHIM_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&ops_dir).expect("ops dir");
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops_dir));
    let (runtime, log) = runtime_for("passthrough");
    let supervisor = runtime.exec_supervisor();
    let request = RunCommandRequest {
        template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key").template_digest,
        sandbox_id: "sbx-1".to_string(),
        instance_name: "wssp-sbx-sbx-1".to_string(),
        operation_id: "c10-kill".to_string(),
        idempotency_key: "c10-kill".to_string(),
        generation: 1,
        attempt: 1,
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "trap '' TERM; echo ready >&2; sleep 120".to_string(),
        ],
        script: None,
        cwd: None,
        timeout_ms: Some(5_000),
        env: Vec::new(),
        stdin: None,
        guest: GuestIdentity::default(),
        build_step: None,
    };
    let (done, rx) = std::sync::mpsc::channel();
    let worker = runtime.exec_supervisor();
    let handle = std::thread::spawn(move || {
        let _ = done.send(run_bound!(worker, run(&request)));
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while supervisor.active_guest_pid("c10-kill").is_none() {
        assert!(Instant::now() < deadline, "timed out waiting for guest pid");
        std::thread::sleep(Duration::from_millis(5));
    }
    supervisor.cancel("c10-kill").expect("cancel");
    // A hang guard, not a deadline under test: the TERM-ignoring workload
    // takes the full TERM, grace and KILL rounds of the terminate helper,
    // several seconds under the shims on a loaded host.
    let response = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("join")
        .expect("response");
    assert_eq!(
        response.command.state,
        sandbox_protocol::OperationState::Cancelled
    );
    let text = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.contains("wssp-terminate"),
        "TERM must escalate to KILL for cancel cleanup: {text}"
    );
    let _ = handle.join();
}

#[test]
fn c14_all_guest_adapters_apply_identity_and_owned_upload_mode() {
    let _ops = super::exec::set_test_guest_ops_dir(None);
    let (base, log) = client_for_project("running", "wssp");
    let guest = GuestIdentity {
        guest_uid: 1234,
        guest_gid: 2345,
        guest_home: "/home/declared".into(),
        guest_shell: "/bin/zsh".into(),
    };
    let client = base.with_guest(&guest);
    let _ = tracked_helper_signal(base.clone(), guest.clone());
    bound_call!(client, exec_argv(&["true".into()])).unwrap();
    bound_call!(client, guest_mkdir("/home/declared/repo")).unwrap();
    bound_call!(client, guest_stat("/home/declared/repo/file")).unwrap();
    bound_call!(
        client,
        guest_list_page(&list_request(&client, "/home/declared/repo", 1))
    )
    .unwrap();
    bound_call!(
        client,
        guest_move("/home/declared/repo/a", "/home/declared/repo/b",)
    )
    .unwrap();
    bound_call!(client, guest_remove("/home/declared/repo/b", false)).unwrap();
    bound_call!(
        client,
        file_push(
            "/home/declared/repo/file",
            &crate::FileContent::from_bytes(b"hello").unwrap()
        )
    )
    .unwrap();
    bound_call!(client, file_pull("/home/declared/repo/file")).unwrap();
    let mut request = run_req("identity");
    request.guest = guest;
    request.env = vec![
        ("HOME".into(), "/root".into()),
        ("SHELL".into(), "/bin/false".into()),
    ];
    let _ = run_bound!(ExecSupervisor::new(base), run(&request));
    let log = fs::read_to_string(log).unwrap();
    let execs: Vec<_> = log.lines().filter(|l| l.starts_with("exec ")).collect();
    // The tracked signal helper replaces the removed blind kill adapter.
    assert!(execs.len() >= 10, "{log}");
    assert!(
        execs.iter().any(|line| line.contains("wssp-signal")),
        "signal adapter missing: {log}"
    );
    for line in execs {
        let identity = if line.contains("-- python3 -I -S -c") {
            assert!(line.contains("1234 2345 setsid -w"), "{line}");
            "--user 0 --group 0"
        } else {
            "--user 1234 --group 2345"
        };
        assert!(
            line.contains(&format!(
                "{identity} --cwd /home/declared --env HOME=/home/declared --env SHELL=/bin/zsh"
            )),
            "{line}"
        );
        assert!(!line.contains("HOME=/root"), "{line}");
    }
    // Isolated mode keeps guest-writable module shadows (`hashlib.py` in the
    // guest home) out of every helper invocation.
    assert!(log.contains("-- python3 -I -c"), "{log}");
    assert!(!log.contains("-- python3 -c"), "{log}");
    assert!(log.contains("/home/declared/.wssp/ops"));
}

#[test]
fn c14_readiness_failure_never_completes_create_or_reconnect() {
    for mode in [
        "missing_user",
        "wrong_home",
        "wrong_shell",
        "wrong_arch",
        "missing_agent",
    ] {
        let (runtime, _) = runtime_for(mode);
        let error = runtime.create_bound(&create_req()).unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::GuestUnavailable, "{mode}");
        assert_eq!(
            error.state(),
            sandbox_protocol::OperationState::UnknownOutcome
        );
        // The failed check travels as a constant reason; an unknown guest
        // label is the generic one and never reaches any message.
        use sandbox_protocol::ReadinessFailureReason as Reason;
        let error = error.into_error();
        let expected = match mode {
            "missing_user" => Reason::GuestUser,
            "wrong_home" => Reason::GuestHome,
            "wrong_shell" => Reason::GuestShell,
            "wrong_arch" => Reason::Architecture,
            _ => Reason::GuestCheck,
        };
        assert_eq!(error.readiness_reason(), Some(expected), "{mode}");
        assert_eq!(
            error.wire_reason(),
            Some(sandbox_protocol::ProtocolErrorReason::Readiness(expected)),
            "{mode}"
        );
        assert!(!error.message.contains("injected"), "{error}");
        let error = runtime
            .reconnect_bound(&ReconnectSandboxRequest {
                vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                lease: sandbox_protocol::HostLease::for_test(),
                template_fingerprint: crate::CreateSandboxRequest::for_test("default", "default")
                    .template_digest,
                sandbox_id: "sbx-1".into(),
                instance_name: "wssp-sbx-sbx-1".into(),
                operation_id: "cold".into(),
                idempotency_key: "cold".into(),
                guest: Default::default(),
                architecture: Some("x86_64".into()),
                egress_policy: None,
                egress_policy_hash: None,
                egress_admission: crate::egress::EgressAdmission::PERMITTED,
                guest_sudo: false,
            })
            .unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::GuestUnavailable, "{mode}");
    }
}

/// E1-A-01: a guest that never gets a DHCP lease is never Ready; the
/// failure is the typed `guest_network_unavailable`, not READY.
#[test]
fn a_guest_without_an_ipv4_default_route_never_becomes_ready() {
    let (runtime, log) = runtime_for("no_guest_network");
    let error = runtime.create_bound(&create_req()).unwrap_err();
    assert_eq!(error.code, SandboxErrorCode::GuestNetworkUnavailable);
    assert!(
        error.message.contains("guest_network_unavailable"),
        "{}",
        error.message
    );
    let log = fs::read_to_string(log).unwrap();
    assert!(log.contains("wssp-network"), "{log}");
    // The healthy path probes the network too.
    let (runtime, log) = runtime_for("running");
    runtime.create_bound(&create_req()).expect("create");
    assert!(fs::read_to_string(log).unwrap().contains("wssp-network"));
}

#[test]
fn guest_network_script_requires_a_non_loopback_default_route() {
    let dir = std::env::temp_dir().join(format!(
        "wssp-guest-network-{}-{}",
        std::process::id(),
        SHIM_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    SHIM_DIRS.with(|dirs| dirs.0.borrow_mut().push(dir.clone()));
    let header =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
    for (name, table, ok) in [
        (
            "dhcp",
            format!(
                "{header}enp5s0\t00000000\t011D8D0A\t0003\t0\t0\t100\t00000000\t0\t0\t0\nenp5s0\t001D8D0A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
            ),
            true,
        ),
        ("none", header.to_string(), false),
        (
            "link_only",
            format!("{header}enp5s0\t001D8D0A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"),
            false,
        ),
        (
            "loopback",
            format!("{header}lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"),
            false,
        ),
    ] {
        let path = dir.join(name);
        fs::write(&path, table).unwrap();
        let output = Command::new("/bin/sh")
            .args([
                "-c",
                super::client::GUEST_NETWORK_SCRIPT,
                "wssp-network",
                "n0",
                path.to_str().unwrap(),
                "1",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.success(), ok, "{name}: {output:?}");
        if ok {
            assert_eq!(output.stdout, b"WSSP_NET n0\n");
        } else {
            assert_eq!(output.status.code(), Some(3), "{name}");
            assert!(output.stdout.is_empty(), "{name}");
        }
    }
}

/// B2-C-1: the dispatch permit is revoked (or closed) after the host accepted
/// the readiness helper's READY but before it wrote `C`. The host-refused fence
/// is runtime work preemption: it keeps its retryable code and never becomes
/// the cleanup-triggering GuestUnavailable, for create and reconnect alike.
#[test]
fn readiness_fence_refusal_between_ready_and_commit_never_becomes_guest_unavailable() {
    for (kind, close) in [
        ("create", false),
        ("create", true),
        ("reconnect", false),
        ("reconnect", true),
    ] {
        let (mut runtime, log) = runtime_for("running");
        let statedir = log.parent().unwrap().to_path_buf();
        fs::write(statedir.join("device-root"), "root,pool=default,size=32GiB").unwrap();
        if kind == "reconnect" {
            runtime
                .create_bound(&create_req())
                .expect("bootstrap create");
        }
        // Holding the shim's stdin read AFTER printing READY cannot hold the
        // host's socket write: C may already be buffered by then. Pause the
        // host itself after READY and before issue_commit admits the permit.
        let (commit_ready, ready) = std::sync::mpsc::sync_channel(1);
        let (resume, commit_resume) = std::sync::mpsc::sync_channel(1);
        let commit_resume = std::sync::Mutex::new(commit_resume);
        runtime.client_mut().mutation_commit_hook = Some(super::client::TestMutationCommitHook(
            std::sync::Arc::new(move || {
                commit_ready.send(()).expect("notify commit readiness");
                commit_resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(20))
                    .expect("resume commit admission");
            }),
        ));
        let permit = std::sync::Arc::new(crate::RuntimePermit::default());
        let scoped = runtime.with_cancellation(permit.clone());
        let worker = std::thread::spawn(move || {
            if kind == "create" {
                scoped.create_bound(&create_req()).map(|_| ())
            } else {
                scoped
                    .reconnect_bound(&ReconnectSandboxRequest {
                        vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                        lease: sandbox_protocol::HostLease::for_test(),
                        template_fingerprint: crate::CreateSandboxRequest::for_test(
                            "default", "default",
                        )
                        .template_digest,
                        sandbox_id: "sbx-1".into(),
                        instance_name: "wssp-sbx-sbx-1".into(),
                        operation_id: "warm".into(),
                        idempotency_key: "warm".into(),
                        guest: Default::default(),
                        architecture: Some("x86_64".into()),
                        egress_policy: None,
                        egress_policy_hash: None,
                        egress_admission: crate::egress::EgressAdmission::PERMITTED,
                        guest_sudo: false,
                    })
                    .map(|_| ())
            }
        });
        ready
            .recv_timeout(Duration::from_secs(20))
            .expect("host accepted READY before commit admission");
        if close {
            permit.close();
        } else {
            permit.revoke();
        }
        resume.send(()).expect("release commit admission");
        let error = worker.join().unwrap().expect_err("preempted readiness");
        assert!(
            statedir.join("fence-refused").exists(),
            "{kind}: the fence was refused"
        );
        assert_ne!(
            error.code,
            SandboxErrorCode::GuestUnavailable,
            "{kind} {close}"
        );
        assert_eq!(
            error.code,
            SandboxErrorCode::UnknownOutcome,
            "{kind} {close}"
        );
        assert_eq!(
            error.state(),
            sandbox_protocol::OperationState::UnknownOutcome,
            "{kind} {close}"
        );
    }
}

#[test]
fn c14_probe_state_matrix_requires_positive_host_and_guest_evidence() {
    use crate::{ProbeSandboxRequest, SandboxLiveProbeState as State};
    for (mode, expected) in [
        ("running", State::GuestReady),
        ("stopped", State::Stopped),
        ("gone", State::ConfirmedAbsent),
        ("permission", State::Unreachable),
        ("missing_agent", State::Unreachable),
        ("missing_user", State::Unreachable),
        ("wrong_arch", State::Unreachable),
        ("exec_no_banner", State::Unreachable),
    ] {
        let (runtime, _) = runtime_for(mode);
        if !matches!(mode, "gone" | "permission" | "stopped") {
            // C37 R2: a RUNNING VM is certified only through the
            // bound-enforcement boundary — a running VM with NO enforcement
            // applied is never certifiable, and the boundary fires before
            // guest evidence. Apply the sandbox network for every running
            // leg so this matrix isolates HOST/GUEST evidence.
            runtime
                .client()
                .apply_sandbox_network(&super::network::test_plan("sbx-1"))
                .expect("apply enforcement");
        }
        let result = runtime
            .probe_sandbox(&ProbeSandboxRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("default", "default")
                    .template_digest,
                sandbox_id: "sbx-1".into(),
                instance_name: "wssp-sbx-sbx-1".into(),
                operation_id: "probe".into(),
                idempotency_key: "probe".into(),
                guest: Default::default(),
                architecture: Some("x86_64".into()),
            })
            .unwrap();
        assert_eq!(result.state, expected, "{mode}");
    }
}

#[test]
fn probe_reports_a_running_vm_without_enforcement_unreachable() {
    // C37 R2 (inverse of the matrix's running leg): a bound, RUNNING VM with
    // no enforcement applied must NEVER certify GuestReady.
    use crate::ProbeSandboxRequest;
    let (runtime, _) = runtime_for("running");
    let err = runtime
        .probe_sandbox(&ProbeSandboxRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("default", "default")
                .template_digest,
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            operation_id: "probe".into(),
            idempotency_key: "probe".into(),
            guest: Default::default(),
            architecture: Some("x86_64".into()),
        })
        .expect_err("a running, unenforced VM never probes GuestReady");
    assert_eq!(
        err.code,
        SandboxErrorCode::GuestUnavailable,
        "the probe surfaces the bound-enforcement boundary's code: {err:?}"
    );
}

#[test]
fn c14_alias_resolution_and_replay_use_local_fingerprint_inventory() {
    let (runtime, log) = runtime_for_project("fix6_new_ready", "wssp");
    let original = runtime
        .resolve_image_ref("images:ubuntu/24.04/cloud")
        .unwrap();
    let mut request = create_req();
    request.incus_fingerprint = Some(original.fingerprint.clone());
    request.template_digest = original.fingerprint.clone();
    fs::write(log.parent().unwrap().join("alias-moved"), "").unwrap();
    assert_ne!(
        runtime
            .resolve_image_ref("images:ubuntu/24.04/cloud")
            .unwrap()
            .fingerprint,
        original.fingerprint
    );
    runtime.create_bound(&request).unwrap();
    runtime.create_bound(&request).unwrap();
    let content = fs::read_to_string(&log).unwrap();
    let launches: Vec<_> = content.lines().filter(|l| l.starts_with("init ")).collect();
    assert_eq!(launches.len(), 1);
    assert!(launches[0].contains(&original.fingerprint[7..]));
    assert!(!launches[0].contains("images:"));
    assert!(content.contains("/1.0/images/aliases/ubuntu%2F24.04%2Fcloud?project=wssp"));
    assert_query_contract(&log, "wssp");
}

/// P2: the linger probe reports the guest user's self-linger, never gates
/// readiness, and only ever asks polkit (it never changes linger).
#[test]
fn linger_probe_reports_blocked_allowed_or_enabled_without_gating_readiness() {
    use crate::GuestLinger;
    for (mode, expected) in [
        ("fix6_new_ready", GuestLinger::Blocked),
        ("linger_allowed", GuestLinger::Allowed),
        ("linger_enabled", GuestLinger::Enabled),
    ] {
        let (runtime, _) = runtime_for(mode);
        let created = runtime
            .create_bound(&create_req())
            .unwrap_or_else(|err| panic!("{mode}: {err:?}"));
        assert_eq!(created.into_value().guest_linger, Some(expected), "{mode}");
    }

    let (shim, _) = write_shim("running");
    let dir = shim.parent().unwrap();
    // A user name with no linger file on any host running this test.
    install_executable(
        &dir.join("id"),
        "#!/bin/sh\necho wssp-linger-probe-nobody\n",
        0o755,
    );
    for (pkcheck, state) in [
        (Some(0), "allowed"),
        (Some(1), "blocked"),
        (None, "blocked"),
    ] {
        let _ = fs::remove_file(dir.join("pkcheck"));
        if let Some(code) = pkcheck {
            install_executable(
                &dir.join("pkcheck"),
                &format!(
                    "#!/bin/sh\n[ \"$1 $2\" = '--action-id org.freedesktop.login1.set-self-linger' ] || exit 9\nexit {code}\n"
                ),
                0o755,
            );
        }
        let output = Command::new("/bin/sh")
            .args([
                "-c",
                super::client::GUEST_LINGER_SCRIPT,
                "wssp-linger",
                "nonce",
            ])
            // Only the stubs: a host's own pkcheck must not answer.
            .env("PATH", dir.display().to_string())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("WSSP_LINGER nonce {state}\n"),
            "{pkcheck:?}"
        );
    }
}

#[test]
fn c14_readiness_script_checks_passwd_home_shell_uid_gid_and_architecture() {
    let (shim, _) = write_shim("running");
    let dir = shim.parent().unwrap();
    let home = dir.join("home");
    fs::create_dir_all(home.join("repo")).unwrap();
    for (name, body) in [
        (
            "getent",
            r#"[ "$CASE" != missing_user ] || exit 2
home=$HOME
shell=$SHELL
[ "$CASE" != wrong_home ] || home=/different
[ "$CASE" != wrong_shell ] || shell=/different
printf 'declared:x:1234:2345::%s:%s\n' "$home" "$shell""#,
        ),
        (
            "id",
            "if [ \"$1\" = -u ]; then echo 1234; else echo 2345; fi",
        ),
        ("uname", "echo x86_64"),
        ("stat", "echo 1234:2345"),
    ] {
        install_executable(&dir.join(name), &format!("#!/bin/sh\n{body}\n"), 0o755);
    }
    for case in [
        "valid",
        "missing_user",
        "wrong_home",
        "wrong_shell",
        "missing_shell",
        "wrong_uid",
        "wrong_gid",
        "wrong_arch",
    ] {
        let output = Command::new("/bin/sh")
            .args([
                "-c",
                super::client::GUEST_READY_SCRIPT,
                "wssp-readiness",
                "nonce",
                if case == "wrong_uid" { "3456" } else { "1234" },
                if case == "wrong_gid" { "3456" } else { "2345" },
                if case == "wrong_arch" {
                    "aarch64"
                } else {
                    "x86_64"
                },
                "required",
            ])
            .env("HOME", &home)
            .env(
                "SHELL",
                if case == "missing_shell" {
                    "/not-present"
                } else {
                    "/bin/sh"
                },
            )
            .env("CASE", case)
            .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            case == "valid",
            "{case}: {output:?}"
        );
        let label = match case {
            "valid" => None,
            "wrong_home" => Some("home"),
            "wrong_shell" | "missing_shell" => Some("shell"),
            "wrong_arch" => Some("arch"),
            _ => Some("user"),
        };
        match label {
            None => assert_eq!(output.stdout, b"WSSP_READY nonce\n"),
            Some(label) => assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                format!("WSSP_NOT_READY nonce {label}\n"),
                "{case}"
            ),
        }
    }
}

#[test]
fn c14_crash_reconciliation_requires_persisted_readiness_and_live_guest_evidence() {
    for mode in ["fix6_new_ready", "missing_user", "missing_agent"] {
        let (runtime, log) = runtime_for(mode);
        let request = create_req();
        let _ = runtime.create_bound(&request);
        let metadata_file = log.parent().unwrap().join("instance-metadata");
        // Recovery verifies egress enforcement: the fixture's effective
        // devices carry the audited pinned NIC on the sandbox bridge.
        let (network, _) = super::network::sandbox_network_names("sbx-1");
        let pinned_nic = serde_json::json!({
            "type": "nic", "network": network,
            "security.mac_filtering": "true", "security.ipv4_filtering": "true",
            "security.ipv6_filtering": "true", "security.port_isolation": "true",
        });
        let metadata = serde_json::json!({
            "name": "wssp-sbx-sbx-1", "status": "Running", "status_code": 103,
            "type": "virtual-machine", "architecture": "x86_64", "config": {
                "user.flycockpit.sandbox_id": "sbx-1",
                "user.flycockpit.create_idempotency_key": "create-1",
                "user.flycockpit.template_digest": request.template_digest,
                "volatile.base_image": &request.template_digest[7..],
                "user.flycockpit.readiness": serde_json::to_string(&super::client::ReadinessSpec {
                    guest: request.guest.clone(), architecture: "x86_64".into(), mode: Default::default(), privilege: Default::default(), root_disk_bytes: None,
                }).unwrap()
            },
            "devices": { "eth0": pinned_nic },
            "expanded_devices": {
                "root": { "type": "disk", "path": "/", "pool": "default" },
                "eth0": pinned_nic,
            }
        });
        // Binding tags normally come from launch; seed them for failure fixtures.
        let config = log.parent().unwrap().join("config");
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join("user.flycockpit.sandbox_id"), "sbx-1").unwrap();
        fs::write(
            config.join("user.flycockpit.create_idempotency_key"),
            "create-1",
        )
        .unwrap();
        // Running alone, even with matching create key, is not readiness proof.
        let _ = fs::remove_file(config.join("user.flycockpit.readiness"));
        assert!(
            runtime
                .query_sandbox("sbx-1", Some("create-1"), Some(&request.template_digest))
                .is_err()
        );
        fs::write(&metadata_file, serde_json::to_vec(&metadata).unwrap()).unwrap();
        let observed =
            runtime.query_sandbox("sbx-1", Some("create-1"), Some(&request.template_digest));
        if mode == "fix6_new_ready" {
            assert_eq!(
                observed.unwrap(),
                Some(sandbox_protocol::SandboxLifecycleState::Ready)
            );
        } else {
            assert!(observed.is_err(), "{mode}");
        }
    }
}

#[test]
fn c14_bad_fingerprints_never_issue_launch() {
    let (client, log) = client_for_project("running", "default");
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../sandbox-protocol/fixtures/template_identity.json"
    ))
    .unwrap();
    for case in fixture["fingerprints"].as_array().unwrap() {
        if case["valid"] == true {
            continue;
        }
        let error = client
            .create_vm(
                &CreateSandboxRequest {
                    vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                    lease: sandbox_protocol::HostLease::for_test(),
                    incus_fingerprint: Some(case["value"].as_str().unwrap().into()),
                    template_digest: case["value"].as_str().unwrap().into(),
                    ..create_req()
                },
                &super::network::test_plan("sbx-1"),
            )
            .unwrap_err();
        assert!(
            matches!(error, crate::EffectError::NotIssued(_)),
            "{error:?}"
        );
        assert_eq!(error.code, SandboxErrorCode::ProtocolError);
    }
    assert!(!log_invoked(&log, "init"));
}

#[test]
fn c14_foreign_tags_and_base_image_never_authorize_existing_vm() {
    for stopped in [false, true] {
        for defect in ["sandbox", "template", "base-image", "untagged-image-b"] {
            let (runtime, log) = runtime_for(if stopped { "stopped" } else { "running" });
            let config = log.parent().unwrap().join("config");
            match defect {
                "sandbox" => {
                    fs::write(config.join("user.flycockpit.sandbox_id"), "foreign").unwrap()
                }
                "template" => fs::write(
                    config.join("user.flycockpit.template_digest"),
                    format!("sha256:{}", "b".repeat(64)),
                )
                .unwrap(),
                "base-image" => {
                    fs::write(config.join("volatile.base_image"), "b".repeat(64)).unwrap()
                }
                _ => {
                    fs::remove_file(config.join("user.flycockpit.sandbox_id")).unwrap();
                    fs::remove_file(config.join("user.flycockpit.create_idempotency_key")).unwrap();
                    fs::write(config.join("volatile.base_image"), "b".repeat(64)).unwrap();
                }
            }
            let create = create_req();
            let fp = create.template_digest.clone();
            let stop = StopSandboxRequest {
                template_fingerprint: fp.clone(),
                sandbox_id: create.sandbox_id.clone(),
                instance_name: create.instance_name.clone(),
                operation_id: "stop".into(),
                idempotency_key: "stop".into(),
            };
            let kill = KillSandboxRequest {
                template_fingerprint: fp.clone(),
                sandbox_id: create.sandbox_id.clone(),
                instance_name: create.instance_name.clone(),
                operation_id: "kill".into(),
                idempotency_key: "kill".into(),
            };
            let upload = WriteFileRequest {
                template_fingerprint: fp,
                sandbox_id: create.sandbox_id.clone(),
                instance_name: create.instance_name.clone(),
                operation_id: "upload".into(),
                idempotency_key: "upload".into(),
                generation: 1,
                attempt: 1,
                path: "/home/user/file".into(),
                bytes: crate::FileContent::from_bytes(b"x").expect("file capture"),
                guest: GuestIdentity::default(),
            };
            for error in [
                runtime.stop_sandbox(&stop).unwrap_err(),
                runtime.kill_bound(&kill).unwrap_err(),
                runtime.write_file(&upload).unwrap_err(),
                runtime.run_command(&run_req("foreign")).unwrap_err(),
            ] {
                assert_eq!(
                    error.code,
                    SandboxErrorCode::IdempotencyConflict,
                    "{defect}"
                );
            }
            assert_eq!(
                runtime
                    .exec_supervisor()
                    .bind(&run_req("foreign-direct"))
                    .unwrap_err()
                    .code,
                SandboxErrorCode::IdempotencyConflict
            );
            assert_eq!(
                runtime
                    .stat_path(&stat_req("/home/user/file"))
                    .unwrap_err()
                    .code,
                SandboxErrorCode::IdempotencyConflict
            );
            assert_eq!(
                runtime.create_bound(&create).unwrap_err().code,
                SandboxErrorCode::IdempotencyConflict,
                "{defect}"
            );
            let reconnect = ReconnectSandboxRequest {
                vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                lease: sandbox_protocol::HostLease::for_test(),
                template_fingerprint: create.template_digest.clone(),
                architecture: create.architecture.clone(),
                guest: create.guest.clone(),
                sandbox_id: create.sandbox_id.clone(),
                instance_name: create.instance_name.clone(),
                operation_id: "reconnect".into(),
                idempotency_key: "reconnect".into(),
                egress_policy: None,
                egress_policy_hash: None,
                egress_admission: crate::egress::EgressAdmission::PERMITTED,
                guest_sudo: false,
            };
            assert_eq!(
                runtime.reconnect_bound(&reconnect).unwrap_err().code,
                SandboxErrorCode::IdempotencyConflict,
                "{defect}"
            );
            let probe = crate::ProbeSandboxRequest {
                template_fingerprint: create.template_digest.clone(),
                architecture: create.architecture,
                guest: create.guest,
                sandbox_id: create.sandbox_id.clone(),
                instance_name: create.instance_name,
                operation_id: "probe".into(),
                idempotency_key: "probe".into(),
            };
            assert_eq!(
                runtime.probe_sandbox(&probe).unwrap_err().code,
                SandboxErrorCode::IdempotencyConflict,
                "{defect}"
            );
            assert_eq!(
                runtime
                    .query_sandbox(&create.sandbox_id, None, Some(&create.template_digest))
                    .unwrap_err()
                    .code,
                SandboxErrorCode::IdempotencyConflict
            );
            for effect in [
                "init",
                "start",
                "stop",
                "delete",
                "config set",
                "exec",
                "file",
            ] {
                assert!(!log_invoked(&log, effect), "{defect}: {effect}");
            }
            assert!(!fs::read_to_string(log).unwrap().contains("config set"));
        }
    }
}

#[test]
fn c14_missing_read_preflight_preserves_file_and_pid_absence() {
    for mode in ["enoent", "filename_enoent"] {
        let (client, log) = client_for_project(mode, "default");
        let bound = client
            .bind_instance(
                "wssp-sbx-sbx-1",
                "sbx-1",
                &create_req().template_digest,
                None,
            )
            .unwrap();
        assert_eq!(
            client.file_pull(&bound, "/missing").unwrap_err().code,
            SandboxErrorCode::FsNotFound
        );
        assert!(
            !log_invoked(&log, "file"),
            "absence must not fall back to the Incus file API"
        );
    }
    let client = client_for("read_denied");
    let bound = client
        .bind_instance(
            "wssp-sbx-sbx-1",
            "sbx-1",
            &create_req().template_digest,
            None,
        )
        .unwrap();
    assert_eq!(
        client.file_pull(&bound, "/unreadable").unwrap_err().code,
        SandboxErrorCode::UnknownOutcome
    );
}

#[test]
fn c14_captured_binding_rechecks_foreign_replacement_before_effect() {
    let (runtime, log) = runtime_for("running");
    let request = run_req("captured");
    let exec = runtime.exec_supervisor();
    let bound = exec.bind(&request).unwrap();
    fs::write(
        log.parent()
            .unwrap()
            .join("config/user.flycockpit.sandbox_id"),
        "foreign",
    )
    .unwrap();
    for error in [
        runtime
            .client()
            .stop_force(&bound)
            .unwrap_err()
            .into_error(),
        runtime
            .client()
            .delete_force(&bound)
            .unwrap_err()
            .into_error(),
        runtime
            .client()
            .file_push(
                &bound,
                "/file",
                &crate::FileContent::from_bytes(b"x").unwrap(),
            )
            .unwrap_err()
            .into_error(),
        runtime
            .client()
            .exec_argv(&bound, &["true".into()])
            .unwrap_err(),
        exec.run(&bound, &request).unwrap_err().into_error(),
        runtime.client().file_pull(&bound, "/file").unwrap_err(),
    ] {
        assert_eq!(error.code, SandboxErrorCode::IdempotencyConflict);
    }
    let (other, other_log) = runtime_for("running");
    assert_eq!(
        other
            .client()
            .exec_argv(&bound, &["true".into()])
            .unwrap_err()
            .code,
        SandboxErrorCode::IdempotencyConflict
    );
    assert!(
        !log_invoked(&other_log, "exec"),
        "capabilities cannot cross clients"
    );
    for effect in ["exec", "stop", "delete", "file"] {
        assert!(!log_invoked(&log, effect));
    }
}

#[test]
fn stalled_output_drains_real_child_pipes_and_disconnect_reaps_group() {
    let (client, log) = client_for_project("output_flood", "default");
    let drained = log.parent().unwrap().join("output-drained");
    let output = crate::CommandOutput::default();
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    let supervisor = ExecSupervisor::new(client)
        .with_output(output.clone())
        .with_cancellation(permit.clone());
    let worker = std::thread::spawn(move || run_bound!(supervisor, run(&run_req("flood"))));
    let deadline = Instant::now() + Duration::from_secs(5);
    while output.total() == 0 {
        assert!(!worker.is_finished(), "first output precedes exit");
        assert!(Instant::now() < deadline, "first output never arrived");
        std::thread::sleep(Duration::from_millis(5));
    }
    // No relay consumer at all: pipe pumps must still finish the entire flood.
    while !drained.exists() {
        assert!(
            Instant::now() < deadline,
            "stalled receiver blocked pipe draining"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    permit.revoke();
    let started = Instant::now();
    let outcome = worker.join().unwrap().unwrap_err();
    assert_eq!(
        outcome.state(),
        sandbox_protocol::OperationState::UnknownOutcome
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        outcome
            .command()
            .unwrap()
            .command
            .chunks
            .iter()
            .map(|c| c.bytes.len())
            .sum::<usize>()
            <= 32768
    );
    assert_eq!(output.total(), 2 * 1024 * 1024);
    assert_eq!(output.retained(), 1024 * 1024);
}

/// D3a: frame evidence never throttles guest output. 16 MiB of stdout (and
/// 64 KiB of stderr) flows through the real pipe pumps far faster than the
/// supervisor's 20 ms evidence pass; before, each pump blocked on a 4-slot
/// evidence channel drained 8 chunks per pass (~3 MiB/s, ~5 s here).
#[test]
fn bulk_output_is_not_gated_by_the_evidence_pass() {
    let output = crate::CommandOutput::default();
    let supervisor = ExecSupervisor::new(client_for("bulk_output")).with_output(output.clone());
    let started = Instant::now();
    let response = run_bound!(supervisor, run(&run_req("bulk"))).expect("completed");
    let elapsed = started.elapsed();
    // The final EXIT frame survived 16 MiB of output ahead of it.
    assert_eq!(response.command.exit_code, Some(0));
    assert_eq!(output.total(), 16 * 1024 * 1024 + 65536);
    assert!(elapsed < Duration::from_secs(2), "16 MiB took {elapsed:?}");
}

#[test]
fn c32_boot_paths_disable_autostart_and_revoke_between_init_and_start() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    runtime.create_bound(&create_req()).unwrap();
    let text = fs::read_to_string(&log).unwrap();
    assert!(text.contains("init --vm"));
    assert!(text.contains("boot.autostart=false"));
    assert!(text.contains("config set -- wssp-sbx-sbx-1 boot.autostart false"));
    assert!(!text.lines().any(|l| l.starts_with("launch ")));
    assert!(text.find("init --vm").unwrap() < text.find("start wssp-sbx-sbx-1").unwrap());
    // Use a real stopped VM shim and an already-revoked permit: start/config
    // subprocesses must be rejected at the real process admission boundary.
    let (runtime, log) = runtime_for("stopped");
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    permit.revoke();
    let scoped = runtime.with_cancellation(permit);
    let result = scoped.reconnect_bound(&ReconnectSandboxRequest {
        vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
        lease: sandbox_protocol::HostLease::for_test(),
        template_fingerprint: create_req().template_digest,
        architecture: Some("x86_64".into()),
        guest: Default::default(),
        sandbox_id: "sbx-1".into(),
        instance_name: "wssp-sbx-sbx-1".into(),
        operation_id: "cold".into(),
        idempotency_key: "cold".into(),
        egress_policy: None,
        egress_policy_hash: None,
        egress_admission: crate::egress::EgressAdmission::PERMITTED,
        guest_sudo: false,
    });
    assert!(result.is_err());
    assert!(!log_invoked_start(&log));
}
#[test]
fn c32_cleanup_budget_interrupts_real_blocked_incus_io() {
    let (runtime, log) = runtime_for("slow_query_1200");
    let scoped = runtime.with_cancellation(std::sync::Arc::new(
        crate::RuntimePermit::with_timeout(Duration::from_millis(80)),
    ));
    let started = Instant::now();
    let error = scoped
        .stop_sandbox(&StopSandboxRequest {
            template_fingerprint: create_req().template_digest,
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            operation_id: "expiry".into(),
            idempotency_key: "expiry".into(),
        })
        .unwrap_err();
    assert_eq!(error.code, SandboxErrorCode::UnknownOutcome);
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "cumulative expiry budget failed to preempt child IO"
    );
    assert!(!log_invoked_start(&log));
}

#[test]
fn c32_cancelled_allocation_can_only_leave_a_stopped_instance() {
    let (runtime, log) = runtime_for("c32_delayed_init");
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    let scoped = runtime.with_cancellation(permit.clone());
    let dir = log.parent().unwrap();
    std::thread::scope(|scope| {
        let allocation = scope.spawn(|| scoped.create_bound(&create_req()));
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !dir.join("init-entered").exists() {
            if allocation.is_finished() || std::time::Instant::now() >= deadline {
                // Release even on failure so the scoped worker cannot hang.
                permit.revoke();
                fs::write(dir.join("release-init"), "").unwrap();
                panic!("allocation did not reach the init barrier");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Cancellation is ordered AFTER init's effect and BEFORE its reply.
        // A launch regression has already booted the instance at this barrier.
        permit.revoke();
        fs::write(dir.join("release-init"), "").unwrap();
        let error = allocation.join().unwrap().unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::UnknownOutcome);
    });
    assert!(log_invoked(&log, "init") || log_invoked(&log, "launch"));
    assert_eq!(
        runtime
            .query_sandbox("sbx-1", None, Some(&create_req().template_digest))
            .unwrap(),
        Some(sandbox_protocol::SandboxLifecycleState::Stopped),
        "cancelled allocation booted after its permit expired"
    );
    assert!(!log_invoked_start(&log));
}
#[test]
fn c32_incus_failed_force_stop_is_retryable_and_success_is_idempotent() {
    let (runtime, log) = runtime_for("c32_stop_once");
    let request = StopSandboxRequest {
        template_fingerprint: create_req().template_digest,
        sandbox_id: "sbx-1".into(),
        instance_name: "wssp-sbx-sbx-1".into(),
        operation_id: "expiry".into(),
        idempotency_key: "expiry".into(),
    };
    assert_eq!(
        runtime.stop_sandbox(&request).unwrap_err().code,
        SandboxErrorCode::UnknownOutcome
    );
    for _ in 0..2 {
        assert_eq!(
            runtime.stop_sandbox(&request).unwrap().sandbox.state,
            sandbox_protocol::SandboxLifecycleState::Stopped
        );
    }
    let text = fs::read_to_string(&log).unwrap();
    assert_eq!(text.lines().filter(|l| l.starts_with("stop ")).count(), 2);
    assert!(text.contains("stop wssp-sbx-sbx-1 --force"));
    assert!(!log_invoked_start(&log));
}

/// R18-F3: a sandbox/name mismatch is rejected BEFORE the allocation lock
/// and any network apply — no bridge, ACL, or provisioning intent may be
/// created under a sandbox id whose cleanup paths never reclaim it.
#[test]
fn mismatched_name_is_rejected_before_any_network_provisioning() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let mut req = create_req();
    req.sandbox_id = "other-sandbox".to_string();
    req.instance_name = "wssp-sbx-sbx-1".to_string();
    let err = runtime.create_bound(&req).unwrap_err();
    assert_eq!(
        err.code,
        SandboxErrorCode::IdempotencyConflict,
        "mismatch is a conflict: {err}"
    );
    let statedir = log.parent().expect("log parent").to_path_buf();
    let log = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !log.lines().any(|l| l.contains("network create")
            || l.contains("network acl create")
            || l.contains(" init ")),
        "no network or VM mutation reaches the daemon: {log}"
    );
    assert!(
        !statedir
            .join("host-state/network-cleanups/other-sandbox.json")
            .exists(),
        "no provisioning intent was journaled"
    );
}

// ---- C58 G3: typed command outcomes (E-19, E-20, TQ-HOST1) ----

fn g3_ops_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "wssp-g3-{label}-{}-{}",
        std::process::id(),
        SHIM_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("ops dir");
    dir
}

fn g3_command(op: &str, script: &str, timeout_ms: u64) -> RunCommandRequest {
    let mut request = run_req(op);
    request.argv = vec!["/bin/sh".into(), "-c".into(), script.into()];
    request.timeout_ms = Some(timeout_ms);
    request
}

fn g3_group_alive(pgid: u32) -> bool {
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            fs::read_to_string(entry.path().join("stat"))
                .ok()
                .and_then(|stat| {
                    let fields: Vec<String> = stat
                        .rsplit_once(") ")?
                        .1
                        .split_whitespace()
                        .map(str::to_string)
                        .collect();
                    fields.get(2).cloned()
                })
                .is_some_and(|group| group == pgid.to_string())
        })
}

/// Start `request` on a passthrough shim, wait for its banner, cancel it and
/// return the settled outcome.
fn g3_cancel_after_banner(
    runtime: &IncusKvmRuntime,
    request: RunCommandRequest,
    ready: Option<&Path>,
) -> crate::EffectOutcome<crate::RunCommandResponse> {
    let supervisor = runtime.exec_supervisor();
    let worker = runtime.exec_supervisor();
    let op = request.operation_id.clone();
    let (done, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let _ = done.send(run_bound!(worker, run(&request)));
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    while supervisor.active_guest_pid(&op).is_none() || ready.is_some_and(|path| !path.exists()) {
        assert!(
            Instant::now() < deadline,
            "timed out before the command ran"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    supervisor.cancel(&op).expect("cancel request");
    let outcome = rx.recv_timeout(Duration::from_secs(20)).expect("settled");
    let _ = handle.join();
    outcome
}

/// E-19: a guest-side `timeoutMs` expiry whose stop is proven (the helper
/// signalled the running command and saw its group gone) is FAILED with the
/// stable `timeout` code, carries the guest PID, and leaves nothing running.
#[test]
fn g3_e19_proven_deadline_stop_is_a_typed_timeout() {
    let _ops = super::exec::set_test_guest_ops_dir(Some(g3_ops_dir("e19")));
    let (runtime, _log) = runtime_for("passthrough");
    let supervisor = runtime.exec_supervisor();
    let request = g3_command("g3-timeout", "echo started; sleep 30", 1_000);
    let started = Instant::now();
    let err = run_bound!(supervisor, run(&request)).expect_err("deadline");
    assert!(
        matches!(err, crate::EffectError::Completed(_)),
        "a proven stop is a completed failure: {err:?}"
    );
    assert_eq!(
        err.state(),
        sandbox_protocol::OperationState::Failed,
        "{err:?}"
    );
    assert_eq!(err.code, SandboxErrorCode::Timeout, "{err:?}");
    let response = err.command().expect("timeout keeps the command record");
    assert_eq!(
        response.command.state,
        sandbox_protocol::OperationState::Failed
    );
    assert_eq!(response.command.exit_code, None);
    let pgid = response.command.guest_pid.expect("guest pid");
    assert!(!g3_group_alive(pgid), "the timed-out group is gone");
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "the timeout settles promptly: {:?}",
        started.elapsed()
    );
}

/// E-19 inverse: a deadline stop whose helper record cannot be parsed (the
/// `timeout` shim answers every helper with an unrelated line) has no proof,
/// so the outcome stays UNKNOWN — never a confirmed timeout.
#[test]
fn g3_e19_unproven_deadline_stop_stays_unknown() {
    let supervisor = ExecSupervisor::new(client_for("timeout"));
    let mut request = run_req("g3-timeout-unproven");
    request.argv = vec!["sleep".into(), "30".into()];
    request.timeout_ms = Some(80);
    let err = run_bound!(supervisor, run(&request)).expect_err("deadline");
    assert!(matches!(err, crate::EffectError::Unknown(_)), "{err:?}");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
}

/// E-19 inverse: a command that handles TERM and reports its own exit status
/// keeps that status. The stop happened, but the command's own report is the
/// evidence, and it is not a signal death.
#[test]
fn g3_e19_deadline_stop_never_overrides_a_reported_non_signal_exit() {
    let _ops = super::exec::set_test_guest_ops_dir(Some(g3_ops_dir("e19-handled")));
    let (runtime, _log) = runtime_for("passthrough");
    let supervisor = runtime.exec_supervisor();
    let request = g3_command(
        "g3-timeout-handled",
        "trap 'exit 0' TERM; echo started; while :; do sleep 0.05; done",
        1_000,
    );
    let response = run_bound!(supervisor, run(&request))
        .expect("the command reported its own exit")
        .into_value();
    assert_eq!(
        response.command.state,
        sandbox_protocol::OperationState::Succeeded
    );
    assert_eq!(response.command.exit_code, Some(0));
}

/// E-20: cancelling a command that dies to TERM (no trap) is CANCELLED. The
/// wrapper's exit frame (143) after an attributed stop is the stop's result,
/// not a natural exit.
#[test]
fn g3_e20_cancel_of_a_term_honouring_command_is_cancelled() {
    let ops = g3_ops_dir("e20");
    let ready = ops.join("ready");
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops.clone()));
    let (runtime, _log) = runtime_for("passthrough");
    let request = g3_command(
        "g3-cancel",
        &format!("echo started; : > '{}'; sleep 60", ready.display()),
        30_000,
    );
    let response = g3_cancel_after_banner(&runtime, request, Some(&ready))
        .expect("a proven cancel completes")
        .into_value();
    assert_eq!(
        response.command.state,
        sandbox_protocol::OperationState::Cancelled,
        "{response:?}"
    );
    let pgid = response.command.guest_pid.expect("guest pid");
    assert!(!g3_group_alive(pgid), "the cancelled group is gone");
}

/// E-20 inverse: a command that exits 143 on its own, with no stop, keeps
/// SUCCEEDED/143 — both `exit 143` and a self-inflicted SIGTERM death.
#[test]
fn g3_e20_self_exit_143_without_a_stop_stays_succeeded() {
    let _ops = super::exec::set_test_guest_ops_dir(Some(g3_ops_dir("e20-self")));
    let (runtime, _log) = runtime_for("passthrough");
    let supervisor = runtime.exec_supervisor();
    for (op, script) in [
        ("g3-exit-143", "exit 143"),
        ("g3-self-term", "kill -TERM $$; sleep 5"),
    ] {
        let response = run_bound!(supervisor, run(&g3_command(op, script, 10_000)))
            .expect("natural exit")
            .into_value();
        assert_eq!(
            response.command.state,
            sandbox_protocol::OperationState::Succeeded,
            "{op}"
        );
        assert_eq!(response.command.exit_code, Some(143), "{op}");
    }
}

/// E-20 inverse: a cancelled command that handles TERM and exits 0 keeps its
/// own result (SUCCEEDED/0): only a signal death is attributed to the stop.
#[test]
fn g3_e20_cancel_never_overrides_a_reported_non_signal_exit() {
    let ops = g3_ops_dir("e20-handled");
    let ready = ops.join("ready");
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops.clone()));
    let (runtime, _log) = runtime_for("passthrough");
    let request = g3_command(
        "g3-cancel-handled",
        &format!(
            "trap 'exit 0' TERM; : > '{}'; while :; do sleep 0.05; done",
            ready.display()
        ),
        30_000,
    );
    let response = g3_cancel_after_banner(&runtime, request, Some(&ready))
        .expect("the command reported its own exit")
        .into_value();
    assert_eq!(
        response.command.state,
        sandbox_protocol::OperationState::Succeeded
    );
    assert_eq!(response.command.exit_code, Some(0));
}

/// TQ-HOST1: an invalid upload destination is refused before any guest
/// invocation: NotIssued (FAILED), and no helper ever runs.
#[test]
fn g3_tq_host1_invalid_upload_path_is_not_issued() {
    for path in ["/home/../etc/passwd", "relative/path", "/"] {
        let (runtime, log) = runtime_for("running");
        let err = runtime
            .write_file(&WriteFileRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "g3-put".to_string(),
                generation: 1,
                attempt: 1,
                idempotency_key: "g3-put".to_string(),
                path: path.to_string(),
                bytes: crate::FileContent::from_bytes(b"hi").expect("file capture"),
                guest: GuestIdentity::default(),
            })
            .expect_err("invalid path");
        assert!(
            matches!(err, crate::EffectError::NotIssued(_)),
            "{path}: {err:?}"
        );
        assert_eq!(
            err.state(),
            sandbox_protocol::OperationState::Failed,
            "{path}"
        );
        assert!(
            !fs::read_to_string(&log)
                .unwrap_or_default()
                .contains("python3"),
            "{path}: no file helper may run"
        );
    }
}

// ---- C58 G3 r2: lost helper replies and bounded stop retries (G3R-1/2/4) ----

/// G3R-1: the deadline stop's helper ran (TERM delivered, group gone) but its
/// reply was lost. The 143 frame may be that stop's result, so the outcome is
/// UNKNOWN — never a certain SUCCEEDED/143, never an unproven timeout.
#[test]
fn g3r_lost_helper_reply_after_a_deadline_stop_is_unknown() {
    let _ops = super::exec::set_test_guest_ops_dir(Some(g3_ops_dir("g3r-a")));
    let (runtime, log) = runtime_for("passthrough");
    fs::write(log.parent().unwrap().join("lose-terminate-reply"), b"").unwrap();
    let supervisor = runtime.exec_supervisor();
    let request = g3_command("g3r-timeout-lost", "echo started; sleep 30", 1_000);
    let err = run_bound!(supervisor, run(&request)).expect_err("no certain result");
    assert!(matches!(err, crate::EffectError::Unknown(_)), "{err:?}");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome, "{err:?}");
}

/// G3R-1, cancel: the same lost reply after a cancel stop is UNKNOWN, not a
/// natural SUCCEEDED/143.
#[test]
fn g3r_lost_helper_reply_after_a_cancel_stop_is_unknown() {
    let ops = g3_ops_dir("g3r-a2");
    let ready = ops.join("ready");
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops.clone()));
    let (runtime, log) = runtime_for("passthrough");
    fs::write(log.parent().unwrap().join("lose-terminate-reply"), b"").unwrap();
    let request = g3_command(
        "g3r-cancel-lost",
        &format!("echo started; : > '{}'; sleep 60", ready.display()),
        30_000,
    );
    let err =
        g3_cancel_after_banner(&runtime, request, Some(&ready)).expect_err("no certain result");
    assert!(matches!(err, crate::EffectError::Unknown(_)), "{err:?}");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome, "{err:?}");
}

/// Relay-mode owner (`observe_unknown` keeps it) whose stop helper never
/// yields a record: the `timeout` shim answers every helper with an unrelated
/// line. Returns the settled outcome, the interim publications and the shim log.
fn g3r_relay_stop_with_failing_helper(
    cancel: bool,
) -> (Option<Result<(), SandboxErrorCode>>, u64, String) {
    let (runtime, log) = runtime_for("timeout");
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    let supervisor = runtime.exec_supervisor().with_cancellation(permit.clone());
    let canceller = supervisor.clone();
    let mut request = run_req(if cancel {
        "g3r-relay-cancel"
    } else {
        "g3r-relay-timeout"
    });
    request.argv = vec!["sleep".into(), "30".into()];
    request.timeout_ms = Some(if cancel { 30_000 } else { 80 });
    let op = request.operation_id.clone();
    let interim = std::sync::Arc::new(AtomicU64::new(0));
    let seen = interim.clone();
    let (done, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let bound = supervisor.bind(&request).unwrap();
        let out = supervisor.run_with_updates(
            &bound,
            &request,
            || {
                Ok((
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    (),
                ))
            },
            move |_| {
                seen.fetch_add(1, Ordering::Relaxed);
                true
            },
        );
        let _ = done.send(out.map(|_| ()).map_err(|err| err.code));
    });
    if cancel {
        let deadline = Instant::now() + Duration::from_secs(20);
        while canceller.active_guest_pid(&op).is_none() {
            assert!(Instant::now() < deadline, "no banner");
            std::thread::sleep(Duration::from_millis(5));
        }
        canceller.cancel(&op).expect("cancel request");
    }
    // Bounded: 3 helper attempts (each well under the 2 s helper timeout on
    // this shim) plus the local fallback. Never needs a revocation.
    let settled = rx.recv_timeout(Duration::from_secs(20)).ok();
    if settled.is_none() {
        permit.revoke();
    }
    let _ = handle.join();
    (
        settled,
        interim.load(Ordering::Relaxed),
        fs::read_to_string(&log).unwrap_or_default(),
    )
}

/// G3R-2/G3R-4 (P2-3): a relay-mode timeout whose helper never proves
/// anything settles UNKNOWN in bounded time without a revocation, stopping
/// only the local transport, and frees the command worker.
#[test]
fn g3r_relay_timeout_with_an_unprovable_helper_settles_unknown() {
    let (settled, interim, log) = g3r_relay_stop_with_failing_helper(false);
    assert_eq!(
        settled,
        Some(Err(SandboxErrorCode::UnknownOutcome)),
        "a timeout must settle without revocation"
    );
    assert!(
        interim <= 1,
        "at most one interim UNKNOWN publication: {interim}"
    );
    // P2-3: exhausted/unprovable stops never send a blind numeric guest
    // SIGKILL and never read back or adopt an advisory PID file.
    assert!(!log.contains("wssp-kill"), "no blind guest SIGKILL: {log}");
    // The wrapper itself writes the advisory file; nothing else may touch it.
    assert!(
        log.lines()
            .filter(|line| line.contains(".pid"))
            .all(|line| line.contains("setsid -w /bin/sh -c")),
        "no PID-file adoption: {log}"
    );
}

/// G3R-2, cancel: a user cancel has the same bounded owner loop.
#[test]
fn g3r_relay_cancel_with_an_unprovable_helper_settles_unknown() {
    let (settled, interim, log) = g3r_relay_stop_with_failing_helper(true);
    assert_eq!(
        settled,
        Some(Err(SandboxErrorCode::UnknownOutcome)),
        "a cancel must settle without revocation"
    );
    assert!(
        interim <= 1,
        "at most one interim UNKNOWN publication: {interim}"
    );
    // P2-3: exhausted/unprovable stops never send a blind numeric guest
    // SIGKILL and never read back or adopt an advisory PID file.
    assert!(!log.contains("wssp-kill"), "no blind guest SIGKILL: {log}");
    // The wrapper itself writes the advisory file; nothing else may touch it.
    assert!(
        log.lines()
            .filter(|line| line.contains(".pid"))
            .all(|line| line.contains("setsid -w /bin/sh -c")),
        "no PID-file adoption: {log}"
    );
}

/// G3R-4 (P2-3), direct API: an unprovable deadline stop settles UNKNOWN
/// with no blind guest SIGKILL; guest work may remain (sandbox stop/kill is
/// the recovery).
#[test]
fn g3r_direct_timeout_fallback_never_sends_a_blind_guest_sigkill() {
    let (runtime, log) = runtime_for("timeout");
    let supervisor = runtime.exec_supervisor();
    let mut request = run_req("g3r-direct-timeout");
    request.argv = vec!["sleep".into(), "30".into()];
    request.timeout_ms = Some(80);
    let err = run_bound!(supervisor, run(&request)).expect_err("deadline");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
    let log = fs::read_to_string(&log).unwrap_or_default();
    assert!(!log.contains("wssp-kill"), "no blind guest SIGKILL: {log}");
    // The wrapper itself writes the advisory file; nothing else may touch it.
    assert!(
        log.lines()
            .filter(|line| line.contains(".pid"))
            .all(|line| line.contains("setsid -w /bin/sh -c")),
        "no PID-file adoption: {log}"
    );
}

// Test-only instrumentation lives in the executable fixture, never in the
// production spawn boundary. /proc records the actual initial child environ.
fn scrub_capture_script(path: &Path, contents: &str) -> String {
    let Some(dir) = std::env::var_os("WSSP_SCRUB_TEST_CAPTURE") else {
        return contents.to_string();
    };
    let log = PathBuf::from(dir).join("children.jsonl");
    format!(
        r#"#!/usr/bin/python3 -I
import json, os, subprocess, sys
initial = open("/proc/self/environ", "rb").read().split(b"\0")
os.environ.clear()
os.environ.update(v.decode().split("=", 1) for v in initial if v)
descendant = subprocess.check_output(["/usr/bin/env", "-0"]).split(b"\0")
record = {{"program": {program}, "args": sys.argv[1:],
           "env": [v.decode() for v in initial if v],
           "descendant": [v.decode() for v in descendant if v]}}
fd = os.open({log}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
os.write(fd, (json.dumps(record) + "\n").encode())
os.close(fd)
os.execv("/bin/sh", ["/bin/sh", "-c", {body}, {program}] + sys.argv[1:])
"#,
        program = serde_json::to_string(&path.to_string_lossy()).unwrap(),
        log = serde_json::to_string(&log.to_string_lossy()).unwrap(),
        body = serde_json::to_string(contents).unwrap(),
    )
}

#[test]
fn incus_children_scrub_host_credentials() {
    use std::os::unix::process::CommandExt;
    // These are inert fixtures, injected only into an isolated test process.
    // Never mutate this runner's global environment.
    const FIXTURES: &[(&str, &str)] = &[
        ("WSSP_HOST_TOKEN", "wssp_host_scrub_fixture"),
        ("WSSP_DEVICE_TOKEN", "wssp_device_scrub_fixture"),
        ("WSSP_SDK_TOKEN", "wssp_sdk_scrub_fixture"),
        ("WSSP_PRIVATE_CONFIG_HMAC_SECRET", "scrub-hmac-fixture"),
        ("WSSP_CONFIG", "scrub-config-fixture"),
        ("WORKLOAD_SECRET", "scrub-workload-fixture"),
        ("SHELL", "/scrub-host-shell"),
        ("LANG", "fr_FR.UTF-8"),
        ("LC_ALL", "fr_FR.UTF-8"),
        ("LC_MESSAGES", "fr_FR.UTF-8"),
        ("LD_PRELOAD", ""),
        ("PYTHONPATH", "/scrub-workload-fixture"),
    ];
    if std::env::var_os("WSSP_SCRUB_TEST_CAPTURE").is_none() {
        let (binary, _) = write_shim("running");
        let dir = binary.parent().unwrap();
        // A separate directory for PATH ensures every kill fixture is captured.
        let bin = dir.join("bin");
        fs::create_dir(&bin).unwrap();
        install_executable(
            &bin.join("kill"),
            "#!/bin/sh\nexec /bin/kill \"$@\"\n",
            0o755,
        );
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "incus::shim_tests::incus_children_scrub_host_credentials",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("HOME", dir)
            .env("INCUS_DIR", dir.join("client-dir"))
            .env("INCUS_SOCKET", dir.join("client.socket"))
            .env("INCUS_CONF", dir.join("client.conf"))
            .envs(FIXTURES.iter().copied())
            .env("WSSP_SCRUB_TEST_CAPTURE", dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated env harness failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    for &(key, value) in FIXTURES {
        assert_eq!(
            std::env::var(key).unwrap(),
            value,
            "fixture precondition: {key}"
        );
    }
    let capture = PathBuf::from(std::env::var_os("WSSP_SCRUB_TEST_CAPTURE").unwrap());
    install_executable(
        &capture.join("bin/kill"),
        "#!/bin/sh\nexec /bin/kill \"$@\"\n",
        0o755,
    );
    // Real adapters, real binding, file helper, supervised exec and readiness.
    c14_all_guest_adapters_apply_identity_and_owned_upload_mode();
    metrics_disabled_running_vm_becomes_ready_and_ops_succeed();
    // passthrough executes the modeled guest target, rather than fabricating
    // command output. Check its actual inherited environment too.
    let guest = bound_call!(
        client_for("passthrough"),
        exec_argv(&["/usr/bin/env".into(), "-0".into()])
    )
    .unwrap();
    assert_eq!(guest.exit_code, 0);
    for key in [
        "WSSP_HOST_TOKEN",
        "WSSP_DEVICE_TOKEN",
        "WSSP_SDK_TOKEN",
        "WSSP_PRIVATE_CONFIG_HMAC_SECRET",
        "WSSP_CONFIG",
        "WORKLOAD_SECRET",
    ] {
        assert!(
            !guest
                .stdout
                .split('\0')
                .any(|entry| entry.starts_with(&format!("{key}="))),
            "host fixture reached the modeled guest: {key}"
        );
    }
    let client = client_for("running");
    client
        .run_with_stdin_timed(&["version"], b"{}", false, Duration::from_secs(2))
        .unwrap();
    // PTY and admission argv view, including hangup escalation.
    super::pty_shim_tests::scrub_environment_pty_cases();

    // Both kill constructors: tracked signalling, a revoked admission, and
    // cleanup of timed-out/cancelled local clients via wait_process.
    let mut child = Command::new("sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .unwrap();
    IncusClient::kill_process_group_cancellable(child.id(), None).unwrap();
    assert!(!child.wait().unwrap().success());
    let revoked = crate::RuntimePermit::default();
    revoked.revoke();
    assert!(IncusClient::kill_process_group_cancellable(999_999_999, Some(&revoked)).is_err());
    shim_exec_timeout_does_not_look_like_gone();
    scoped_exec_wait_and_later_helper_spawns_obey_revocation();

    // Generic host-call timeout and cancellation use the separate cleanup
    // kill constructor, rather than ExecSupervisor's tracked kill method.
    let mut blocked = client_for("running");
    let marker = Path::new(&blocked.binary)
        .parent()
        .unwrap()
        .join("host-call-started");
    install_executable(
        Path::new(&blocked.binary),
        &format!(
            "#!/bin/sh\nprintf started > '{}'\nsleep 30\n",
            marker.display()
        ),
        0o755,
    );
    let timeout = blocked
        .run_bounded(&["version"], false, Duration::from_millis(500))
        .unwrap_err();
    assert_eq!(timeout.code, SandboxErrorCode::Timeout);
    fs::remove_file(&marker).unwrap();
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    blocked.cancelled = Some(permit.clone());
    let worker = std::thread::spawn(move || {
        blocked.run_bounded(&["version"], false, Duration::from_secs(10))
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "host call did not start");
        std::thread::sleep(Duration::from_millis(2));
    }
    permit.revoke();
    assert_eq!(
        worker.join().unwrap().unwrap_err().code,
        SandboxErrorCode::UnknownOutcome
    );

    let dir = PathBuf::from(std::env::var_os("WSSP_SCRUB_TEST_CAPTURE").unwrap());
    let records: Vec<serde_json::Value> = fs::read_to_string(dir.join("children.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let mut kills = 0;
    let mut execs = 0;
    let mut files = 0;
    let mut terminals = 0;
    let mut generic = 0;
    for record in records {
        let kill = Path::new(record["program"].as_str().unwrap())
            .file_name()
            .unwrap()
            == "kill";
        let args: Vec<&str> = record["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let exec = args.contains(&"exec");
        let terminal = args.contains(&"-t");
        // portable-pty injects the passwd-database shell in as_command(),
        // even after env_clear(); this is baseline behavior, not inheritance.
        let pty_shell = crate::host_child::incus_pty_command("unused").get_shell();
        for field in ["env", "descendant"] {
            for entry in record[field].as_array().unwrap() {
                let entry = entry.as_str().unwrap();
                let (key, value) = entry.split_once('=').unwrap();
                assert!(
                    !FIXTURES.iter().any(|(k, _)| *k == key)
                        || (key == "LC_ALL" && value == "C")
                        || (terminal && key == "SHELL" && value == pty_shell),
                    "fixture name leaked to {field}: {key}"
                );
                assert!(
                    !value.contains("scrub_fixture") && !value.contains("scrub-workload-fixture"),
                    "fixture value leaked to {field}: {key}"
                );
                let allowed = key == "PATH"
                    || (!kill
                        && ["HOME", "INCUS_DIR", "INCUS_SOCKET", "INCUS_CONF"].contains(&key))
                    || (!kill && !exec && key == "LC_ALL" && value == "C")
                    || (terminal && key == "TERM" && value == super::pty::PTY_TERM)
                    || (terminal && key == "SHELL" && value == pty_shell);
                assert!(allowed, "unexpected child environment key: {key}");
            }
        }
        let env: Vec<&str> = record["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        if kill {
            kills += 1;
            assert_eq!(env.len(), 1);
        } else {
            for key in ["PATH", "HOME", "INCUS_DIR", "INCUS_SOCKET", "INCUS_CONF"] {
                let expected = format!("{key}={}", std::env::var(key).unwrap());
                assert!(
                    env.contains(&expected.as_str()),
                    "missing allowlisted {key}"
                );
            }
            if exec {
                execs += 1;
                files += usize::from(args.contains(&super::files::HELPER));
                terminals += usize::from(terminal);
                assert!(!env.iter().any(|entry| entry.starts_with("LC_")));
            } else {
                generic += 1;
                assert!(env.contains(&"LC_ALL=C"));
            }
        }
    }
    assert!(
        kills >= 4,
        "tracked, PTY, timeout and cancellation kill paths: {kills}"
    );
    assert!(
        execs >= 10 && files >= 2 && terminals >= 2 && generic >= 2,
        "missing constructor coverage: exec={execs} file={files} pty={terminals} generic={generic}"
    );
}

#[test]
fn exact_image_missing_json_and_cli_are_typed_for_fingerprint_and_alias() {
    for mode in [
        "image_missing_json",
        "image_missing_cli",
        "image_missing_751_json",
        "image_missing_751_cli",
    ] {
        let (client, log) = client_for_with_log(mode);
        seed_existing_incus_project(Path::new(&client.binary), "default", true, true);
        for image in [
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "images:ubuntu/24.04/cloud",
        ] {
            let error = client.resolve_image_ref(image).unwrap_err();
            assert_eq!(error.code, SandboxErrorCode::NotFound, "{mode}: {error:?}");
            assert_eq!(error.message, "incus image was not found");
        }
        let queries = fs::read_to_string(log).unwrap();
        assert!(queries.contains("/1.0/images/aliases/"));
        assert!(queries.contains("/1.0/images/abcdef"));
        assert!(!queries.contains("init "));
    }
}

#[test]
fn quoted_missing_image_for_another_ref_is_not_absence() {
    let (client, log) = client_for_with_log("image_missing_751_cli_mismatch");
    seed_existing_incus_project(Path::new(&client.binary), "default", true, true);
    for image in [
        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "images:ubuntu/24.04/cloud",
    ] {
        let error = client.resolve_image_ref(image).unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::Internal, "{image}: {error:?}");
    }
    let queries = fs::read_to_string(log).unwrap();
    assert!(queries.contains("/1.0/images/aliases/"));
    assert!(queries.contains("/1.0/images/abcdef"));
    assert!(
        !queries.contains("query --raw /1.0/projects/"),
        "mismatched text is not image absence evidence"
    );
}

#[test]
fn missing_project_is_not_exact_image_absence() {
    for mode in [
        "image_missing_project",
        "image_missing_project_generic",
        "image_missing_project_cli_generic",
    ] {
        let client = client_for(mode);
        for image in [
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "images:ubuntu/24.04/cloud",
        ] {
            let error = client.resolve_image_ref(image).unwrap_err();
            assert_eq!(error.code, SandboxErrorCode::Internal);
            assert_eq!(error.message, "incus image lookup failed");
        }
    }
}

/// D-20: exact wrappers on temp-dir Incus shims; logical time crosses 120s.
#[test]
fn d20_timerless_shim_clock_direct_and_supervised_authority_matrix() {
    use std::sync::{Arc, Mutex, atomic::AtomicBool, mpsc};
    for supervised in [false, true] {
        for ending in [
            "complete", "cancel", "expiry", "shorten", "offline", "revoke",
        ] {
            let _ops = super::exec::set_test_guest_ops_dir(Some(g3_ops_dir("d20")));
            let (runtime, log) = runtime_for("passthrough");
            let now = Instant::now();
            let clock = Arc::new(Mutex::new(now));
            let permit = Arc::new(crate::RuntimePermit::with_test_clock(
                Duration::from_secs(600),
                clock.clone(),
            ));
            let supervisor = runtime.exec_supervisor().with_cancellation(permit.clone());
            let worker = supervisor.clone();
            let scoped = runtime.with_cancellation(permit.clone());
            let gate = log.with_extension("finish");
            let mut request = g3_command(
                "d20-zero",
                &format!("while [ ! -f '{}' ]; do sleep 0.02; done", gate.display()),
                0,
            );
            request.env = vec![("DEFAULT".into(), "present".into())];
            let (done, result) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                let outcome = if supervised {
                    run_bound!(
                        worker,
                        run_with_admission(&request, || Ok((Arc::new(AtomicBool::new(false)), ())))
                    )
                } else {
                    scoped.run_command(&request)
                };
                done.send(outcome).unwrap();
            });
            let wait = Instant::now() + Duration::from_secs(5);
            while supervisor.active_birth("d20-zero").is_none() {
                assert!(Instant::now() < wait, "command never started");
                std::thread::sleep(Duration::from_millis(2));
            }
            let guest_pid = supervisor.active_birth("d20-zero").unwrap().pid;
            *clock.lock().unwrap() = now + Duration::from_secs(121);
            // Allow the actual wait loop to observe the advanced clock.
            std::thread::sleep(Duration::from_millis(80));
            let survived = result.try_recv();
            let was_active = survived.is_err();
            match ending {
                "complete" => fs::write(&gate, b"done").unwrap(),
                "cancel" => {
                    supervisor.cancel("d20-zero").unwrap();
                }
                "expiry" => {
                    *clock.lock().unwrap() = now + Duration::from_secs(601);
                }
                // Host lease shortening/offline teardown/revocation all revoke
                // this exact scoped authority; none edits the command deadline.
                _ => permit.revoke(),
            }
            let outcome = if let Ok(outcome) = survived {
                Some(outcome)
            } else {
                result.recv_timeout(Duration::from_secs(15)).ok()
            };
            permit.revoke();
            fs::write(&gate, b"cleanup").unwrap();
            handle.join().unwrap();
            // UNKNOWN can leave guest work alive. Keep the fixture's gate
            // until its real wrapper observes it; never signal by advisory PID.
            let cleanup_deadline = Instant::now() + Duration::from_secs(3);
            while fs::read_to_string(format!("/proc/{guest_pid}/stat"))
                .ok()
                .is_some_and(|stat| {
                    !stat
                        .rsplit_once(") ")
                        .is_some_and(|(_, rest)| rest.starts_with("Z "))
                })
                && Instant::now() < cleanup_deadline
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(
                outcome.is_some(),
                "{ending}, supervised={supervised}: authority/EOF/cancel must settle without a command timer"
            );
            let outcome = outcome.unwrap();
            assert!(was_active, "zero ended at the 120s fallback");
            match ending {
                "complete" => assert!(outcome.is_ok(), "{outcome:?}"),
                "cancel" => assert_eq!(
                    outcome.unwrap().command.state,
                    sandbox_protocol::OperationState::Cancelled
                ),
                _ => assert_eq!(outcome.unwrap_err().code, SandboxErrorCode::UnknownOutcome),
            }
        }
    }
}

#[test]
fn d20_positive_shim_clock_fires_at_execution_deadline() {
    use std::sync::{Arc, Mutex, atomic::AtomicBool, mpsc};
    for (supervised, timeout_ms) in [false, true].into_iter().flat_map(|supervised| {
        [120_000, 300_000, 1_800_000].map(|timeout_ms| (supervised, timeout_ms))
    }) {
        let _ops = super::exec::set_test_guest_ops_dir(Some(g3_ops_dir("d20-positive")));
        let (runtime, _) = runtime_for("passthrough");
        let now = Instant::now();
        let clock = Arc::new(Mutex::new(now));
        let permit = Arc::new(crate::RuntimePermit::with_test_clock(
            Duration::from_secs(3600),
            clock.clone(),
        ));
        let supervisor = runtime.exec_supervisor().with_cancellation(permit.clone());
        let worker = supervisor.clone();
        let scoped = runtime.with_cancellation(permit.clone());
        let request = g3_command("d20-positive", "sleep 30", timeout_ms);
        let (done, result) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let outcome = if supervised {
                run_bound!(
                    worker,
                    run_with_admission(&request, || Ok((Arc::new(AtomicBool::new(false)), ())))
                )
            } else {
                scoped.run_command(&request)
            };
            done.send(outcome).unwrap();
        });
        let wait = Instant::now() + Duration::from_secs(5);
        while supervisor.active_birth("d20-positive").is_none() {
            assert!(Instant::now() < wait, "command never started");
            std::thread::sleep(Duration::from_millis(2));
        }
        // A still-valid long lease (including any renewal) does not alter the
        // command's execution-start-bound deadline.
        // Let the supervisor consume the fixed start frame before advancing.
        assert!(result.recv_timeout(Duration::from_millis(100)).is_err());
        if timeout_ms > 120_000 {
            *clock.lock().unwrap() = now + Duration::from_secs(241);
            assert!(
                result.recv_timeout(Duration::from_millis(100)).is_err(),
                "requested timeout must survive both the default and sleep-240 boundary"
            );
            assert!(supervisor.active_birth("d20-positive").is_some());
        }
        *clock.lock().unwrap() = now + Duration::from_millis(timeout_ms + 1000);
        let outcome = result.recv_timeout(Duration::from_secs(5)).ok();
        permit.revoke();
        handle.join().unwrap();
        assert_eq!(
            outcome
                .expect("positive command timer must fire")
                .unwrap_err()
                .code,
            SandboxErrorCode::Timeout
        );
    }
}

#[test]
fn d20_timerless_setup_hang_stays_finite_on_shim_clock() {
    use std::sync::{Arc, Mutex, mpsc};
    for supervised in [false, true] {
        let (runtime, log) = runtime_for("blocked_prestart");
        let now = Instant::now();
        let clock = Arc::new(Mutex::new(now));
        let permit = Arc::new(crate::RuntimePermit::with_test_clock(
            Duration::from_secs(600),
            clock.clone(),
        ));
        let worker = runtime.exec_supervisor().with_cancellation(permit.clone());
        let scoped = runtime.with_cancellation(permit.clone());
        let mut request = run_req("d20-setup");
        request.timeout_ms = Some(0);
        let (done, result) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let outcome = if supervised {
                run_bound!(
                    worker,
                    run_with_admission(&request, || Ok((
                        Arc::new(std::sync::atomic::AtomicBool::new(false)),
                        ()
                    )))
                )
            } else {
                scoped.run_command(&request)
            };
            done.send(outcome).unwrap();
        });
        let wait = Instant::now() + Duration::from_secs(5);
        while !log_invoked(&log, "exec") {
            assert!(Instant::now() < wait, "setup never started");
            std::thread::sleep(Duration::from_millis(2));
        }
        *clock.lock().unwrap() = now + super::exec::HOST_SETUP_BUDGET + Duration::from_secs(1);
        let outcome = result.recv_timeout(Duration::from_secs(2)).ok();
        permit.revoke();
        handle.join().unwrap();
        assert_eq!(
            outcome
                .expect("setup bound must remain finite for zero")
                .unwrap_err()
                .code,
            SandboxErrorCode::UnknownOutcome
        );
    }
}

/// BZ-C-1 reviewer probe: strip only the optional READY line, preserving
/// nonce-bound PID/EXIT framing and the real `sleep 25` user process.
#[test]
fn bzr1_probe_readyless_command_survives_setup_bound() {
    use std::sync::{Arc, Mutex, atomic::AtomicBool, mpsc};
    for supervised in [false, true] {
        for timeout in [None, Some(20_000), Some(0)] {
            let ops_dir = g3_ops_dir("bzr1");
            let _ops = super::exec::set_test_guest_ops_dir(Some(ops_dir.clone()));
            let (runtime, _) = runtime_for("noready");
            let now = Instant::now();
            let clock = Arc::new(Mutex::new(now));
            let permit = Arc::new(crate::RuntimePermit::with_test_clock(
                Duration::from_secs(600),
                clock.clone(),
            ));
            let supervisor = runtime.exec_supervisor().with_cancellation(permit.clone());
            let worker = supervisor.clone();
            let scoped = runtime.with_cancellation(permit.clone());
            let mut request = g3_command("bzr1-noready", "sleep 25", 1);
            request.timeout_ms = timeout;
            let (done, result) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                let outcome = if supervised {
                    run_bound!(
                        worker,
                        run_with_admission(&request, || Ok((Arc::new(AtomicBool::new(false)), ())))
                    )
                } else {
                    scoped.run_command(&request)
                };
                done.send(outcome).unwrap();
            });
            let wait = Instant::now() + Duration::from_secs(5);
            while !ops_dir.join("bzr1-noready.pid").exists() {
                assert!(Instant::now() < wait, "wrapper never wrote pid file");
                std::thread::sleep(Duration::from_millis(2));
            }
            // Let the pipe pump and wait loop observe the PID at the start clock.
            std::thread::sleep(Duration::from_millis(200));
            for elapsed in [
                Duration::from_secs(6),
                super::exec::HOST_SETUP_BUDGET + Duration::from_secs(1),
            ] {
                *clock.lock().unwrap() = now + elapsed;
                assert!(
                    result.recv_timeout(Duration::from_millis(200)).is_err(),
                    "timeout={timeout:?}, supervised={supervised}: running command stopped by setup deadline"
                );
            }
            assert!(
                supervisor.active_birth("bzr1-noready").is_none(),
                "READY really is absent"
            );
            if timeout == Some(20_000) {
                *clock.lock().unwrap() = now + Duration::from_secs(20);
            }
            let outcome = result.recv_timeout(Duration::from_secs(30)).ok();
            permit.revoke();
            handle.join().unwrap();
            let outcome =
                outcome.expect("command must settle at its own deadline or natural completion");
            if timeout == Some(20_000) {
                assert_eq!(outcome.unwrap_err().code, SandboxErrorCode::Timeout);
            } else {
                let response = outcome.unwrap();
                assert_eq!(response.command.exit_code, Some(0));
                assert!(response.command.birth.is_none());
            }
        }
    }
}

#[test]
fn bz_host_setup_allows_late_typed_helper_failure() {
    use std::sync::{Arc, Mutex, atomic::AtomicBool, mpsc};
    for timeout in [None, Some(1), Some(0)] {
        let (runtime, log) = runtime_for("late_setup_failure");
        let now = Instant::now();
        let clock = Arc::new(Mutex::new(now));
        let permit = Arc::new(crate::RuntimePermit::with_test_clock(
            Duration::from_secs(600),
            clock.clone(),
        ));
        let worker = runtime.exec_supervisor().with_cancellation(permit.clone());
        let mut request = run_req("bz-setup-failure");
        request.timeout_ms = timeout;
        let (done, result) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            done.send(run_bound!(
                worker,
                run_with_admission(&request, || Ok((Arc::new(AtomicBool::new(false)), ())))
            ))
            .unwrap();
        });
        let dir = log.parent().unwrap();
        let wait = Instant::now() + Duration::from_secs(5);
        while !dir.join("setup-entered").exists() {
            assert!(Instant::now() < wait, "setup never started");
            std::thread::sleep(Duration::from_millis(2));
        }
        // The helper consumes its full 5000ms, plus VM-agent delivery latency.
        *clock.lock().unwrap() = now + super::env_frame::SETUP_BUDGET + Duration::from_millis(100);
        let early = result.recv_timeout(Duration::from_millis(200));
        fs::write(dir.join("release-setup"), b"done").unwrap();
        let was_early = early.is_ok();
        let outcome = early
            .ok()
            .or_else(|| result.recv_timeout(Duration::from_secs(3)).ok());
        permit.revoke();
        handle.join().unwrap();
        assert!(!was_early, "host deadline preempted helper setup failure");
        let error = outcome.unwrap().unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::HostEffectNotIssued);
        assert_eq!(error.state(), sandbox_protocol::OperationState::Failed);
    }
}

/// BZR2-C-1/K-1: deciding that stderr is not a banner must not end setup.
#[test]
fn bzr2_non_banner_head_keeps_setup_finite() {
    use std::sync::{Arc, Mutex, atomic::AtomicBool, mpsc};
    for supervised in [false, true] {
        for timeout in [Some(0), None, Some(120_000)] {
            let (runtime, log) = runtime_for("noisy_prestart");
            let now = Instant::now();
            let clock = Arc::new(Mutex::new(now));
            let permit = Arc::new(crate::RuntimePermit::with_test_clock(
                Duration::from_secs(600),
                clock.clone(),
            ));
            let supervisor = runtime.exec_supervisor().with_cancellation(permit.clone());
            let worker = supervisor.clone();
            let scoped = runtime.with_cancellation(permit.clone());
            let mut request = run_req("bzr2-noisy");
            request.timeout_ms = timeout;
            let (done, result) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                let outcome = if supervised {
                    run_bound!(
                        worker,
                        run_with_admission(&request, || Ok((Arc::new(AtomicBool::new(false)), ())))
                    )
                } else {
                    scoped.run_command(&request)
                };
                done.send(outcome).unwrap();
            });
            let wait = Instant::now() + Duration::from_secs(5);
            while !log.parent().unwrap().join("setup-entered").exists() {
                assert!(Instant::now() < wait, "noisy setup never started");
                std::thread::sleep(Duration::from_millis(2));
            }
            // Let the wait loop decide the non-banner head before advancing.
            std::thread::sleep(Duration::from_millis(200));
            assert!(supervisor.active_birth("bzr2-noisy").is_none());
            *clock.lock().unwrap() =
                now + super::exec::HOST_SETUP_BUDGET - Duration::from_millis(1);
            let early = result.recv_timeout(Duration::from_millis(200));
            *clock.lock().unwrap() = now + super::exec::HOST_SETUP_BUDGET;
            let was_early = early.is_ok();
            let outcome = if let Ok(outcome) = early {
                Some(outcome)
            } else {
                result.recv_timeout(Duration::from_secs(3)).ok()
            };
            permit.revoke();
            handle.join().unwrap();
            assert!(!was_early, "setup stopped before its bound");
            let error = outcome
                .expect("non-banner stderr must not disarm the host setup bound")
                .unwrap_err();
            assert_eq!(
                error.code,
                SandboxErrorCode::UnknownOutcome,
                "timeout={timeout:?}, supervised={supervised}"
            );
            assert_eq!(
                error.state(),
                sandbox_protocol::OperationState::UnknownOutcome
            );
        }
    }
}

pub(super) trait FixtureRuntime {
    fn create_bound(
        &self,
        r: &crate::CreateSandboxRequest,
    ) -> crate::EffectOutcome<crate::CreateSandboxResponse>;
    fn reconnect_bound(
        &self,
        r: &crate::ReconnectSandboxRequest,
    ) -> crate::EffectOutcome<crate::ReconnectSandboxResponse>;
    fn kill_bound(
        &self,
        r: &crate::KillSandboxRequest,
    ) -> crate::EffectOutcome<crate::KillSandboxResponse>;
}
impl FixtureRuntime for dyn crate::SandboxRuntime {
    fn create_bound(
        &self,
        r: &crate::CreateSandboxRequest,
    ) -> crate::EffectOutcome<crate::CreateSandboxResponse> {
        self.create_sandbox_on_storage(r, &fixture_root(self)?)
    }
    fn reconnect_bound(
        &self,
        r: &crate::ReconnectSandboxRequest,
    ) -> crate::EffectOutcome<crate::ReconnectSandboxResponse> {
        self.reconnect_sandbox_on_storage(r, &fixture_root(self)?)
    }
    fn kill_bound(
        &self,
        r: &crate::KillSandboxRequest,
    ) -> crate::EffectOutcome<crate::KillSandboxResponse> {
        self.kill_sandbox_on_storage(r, &fixture_root(self)?)
    }
}
fn fixture_root(
    runtime: &dyn crate::SandboxRuntime,
) -> Result<crate::RootDisk, crate::RuntimeError> {
    Ok(crate::RootDisk {
        pool: runtime.initialize_storage_pool("default", None)?,
        disk_gi_b: sandbox_protocol::vm_size_limits()
            .map_err(|_| {
                crate::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::Internal,
                    "invalid policy",
                )
            })?
            .disk_gi_b_default,
    })
}

#[test]
fn qualification_delete_timeout_settles_when_host_proves_absence() {
    let mut client = client_for("delete_applied_transport_stall");
    client.agent_timeout = Duration::from_millis(500);
    bound_call!(client, delete_force()).expect("daemon absence settles the timed-out delete");
}

#[test]
fn qualification_dir_unpack_outlives_the_ordinary_agent_deadline() {
    let (mut runtime, log) = runtime_for("c32_delayed_init");
    // The same budget also bounds the readiness that follows the unpack,
    // which alone measured 8-9 s of shimmed agent probes on a loaded host;
    // 20 s matches the storage fixture's room for parallel readiness. The
    // unpack is then held past it, so it outlives the agent deadline.
    let agent_timeout = Duration::from_secs(20);
    runtime.override_agent_timeout(agent_timeout);
    let dir = log.parent().unwrap();
    std::thread::scope(|scope| {
        let create = scope.spawn(|| runtime.create_bound(&create_req()));
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !dir.join("init-entered").exists() {
            if create.is_finished() || std::time::Instant::now() >= deadline {
                fs::write(dir.join("release-init"), "").unwrap();
                panic!("create never reached image unpack");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(agent_timeout + Duration::from_secs(2));
        fs::write(dir.join("release-init"), "").unwrap();
        assert_eq!(
            create.join().unwrap().unwrap().sandbox.state,
            sandbox_protocol::SandboxLifecycleState::Ready
        );
    });
}

/// D1: a build-root command reaches `incus exec` with the root identity, the
/// root identity helper and root's pid directory; the same request without
/// the flag keeps the declared guest identity.
#[test]
fn build_root_command_runs_incus_exec_as_root_only_when_flagged() {
    let exec_line = |root: bool| {
        let (client, log) = client_for_with_log("exit1");
        let supervisor = ExecSupervisor::new(client);
        let mut request = run_req(if root { "op-root" } else { "op-user" });
        request.build_step = root.then_some(crate::BuildStep::Root);
        let response = run_bound!(supervisor, run(&request)).expect("completed");
        assert_eq!(response.command.exit_code, Some(1));
        fs::read_to_string(&log)
            .unwrap()
            .lines()
            .rfind(|line| line.starts_with("exec ") && line.contains("wssp-run"))
            .expect("exec logged")
            .to_string()
    };
    let root = exec_line(true);
    assert!(
        root.contains("--user 0 --group 0 --cwd /root --env HOME=/root --env SHELL=/bin/sh --"),
        "{root}"
    );
    assert!(root.contains("os.setgroups([0])"), "{root}");
    assert!(root.contains("/run/wssp/ops/op-root.pid"), "{root}");
    assert!(!root.contains("HOME=/home/user"), "{root}");
    let user = exec_line(false);
    assert!(
        user.contains("--user 0 --group 0 --cwd /home/user --env HOME=/home/user"),
        "{user}"
    );
    assert!(user.contains("os.setuid(uid)") && !user.contains("os.setgroups([0])"));
    assert!(user.contains("/home/user/.wssp/ops/op-user.pid"), "{user}");
}

/// D1: a COPY step runs the fixed helper as guest root with argv built from
/// the typed body; the request itself carries no argv, script or env.
#[test]
fn build_copy_step_runs_the_fixed_helper_as_root() {
    let (client, log) = client_for_with_log("running");
    let supervisor = ExecSupervisor::new(client);
    let mut request = run_req("op-copy");
    request.argv = Vec::new();
    request.build_step = Some(crate::BuildStep::Copy(sandbox_protocol::BuildCopyV11 {
        context_path: "/var/tmp/wssp-build/b-1/context.tar".into(),
        sha256: "a".repeat(64),
        src: vec!["app".into()],
        dest: "/srv/app/".into(),
        owner: sandbox_protocol::BuildCopyOwnerV11::User,
        mode: Some(0o644),
    }));
    let response = run_bound!(supervisor, run(&request)).expect("completed");
    assert_eq!(response.command.exit_code, Some(0));
    let line = fs::read_to_string(&log)
        .unwrap()
        .lines()
        .rfind(|line| line.starts_with("exec ") && line.contains("wssp-run"))
        .expect("exec logged")
        .to_string();
    assert!(
        line.contains("--user 0 --group 0 --cwd /root --env HOME=/root"),
        "{line}"
    );
    assert!(
        line.contains("wssp-run python3 -I -B -c import errno, os, stat"),
        "{line}"
    );
    assert!(
        line.ends_with(&format!(
            "/var/tmp/wssp-build/b-1/context.tar {} /srv/app/ 1000 1000 420 app",
            "a".repeat(64)
        )),
        "{line}"
    );
    // Argv on a COPY step is refused before any effect.
    let mut mixed = request.clone();
    mixed.operation_id = "op-copy-2".into();
    mixed.argv = vec!["sh".into()];
    assert!(run_bound!(supervisor, run(&mixed)).is_err());
}

/// Guest sudo (plan step 11): every create runs exactly one helper step after
/// readiness (grant, revoke, or revoke plus the audit), a failing grant or a
/// root-granted audit fails readiness with its own reason, and a probe never
/// runs the helper.
#[test]
fn guest_sudo_step_runs_once_per_create_and_fails_with_its_reason() {
    use crate::GuestPrivilege;
    use sandbox_protocol::ReadinessFailureReason as R;
    for (privilege, mode) in [
        (
            GuestPrivilege {
                sudo: true,
                audit: false,
            },
            "grant",
        ),
        (
            GuestPrivilege {
                sudo: false,
                audit: true,
            },
            "revoke-audit",
        ),
        (GuestPrivilege::default(), "revoke"),
    ] {
        let (runtime, _) = runtime_for("fix6_new_ready");
        let dir = Path::new(&runtime.client().binary)
            .parent()
            .unwrap()
            .to_path_buf();
        let mut req = create_req();
        req.guest_privilege = privilege;
        runtime
            .create_bound(&req)
            .unwrap_or_else(|err| panic!("{mode}: {err:?}"));
        assert_eq!(
            fs::read_to_string(dir.join("sudo-log")).unwrap(),
            format!("{mode}\n"),
            "{mode}"
        );
    }
    for (privilege, step, verdict, reason) in [
        (
            GuestPrivilege {
                sudo: true,
                audit: false,
            },
            "grant",
            "not_effective sudo_ws",
            R::GuestSudoUnavailable,
        ),
        (
            GuestPrivilege {
                sudo: false,
                audit: true,
            },
            "revoke-audit",
            "root_granted sudo_ws group_docker",
            R::GuestRootGranted,
        ),
    ] {
        let (runtime, _) = runtime_for("fix6_new_ready");
        let dir = Path::new(&runtime.client().binary)
            .parent()
            .unwrap()
            .to_path_buf();
        fs::write(dir.join(format!("sudo-verdict-{step}")), verdict).unwrap();
        let mut req = create_req();
        req.guest_privilege = privilege;
        let err = match runtime.create_bound(&req) {
            Err(err) => err.into_error(),
            Ok(_) => panic!("{step}: created"),
        };
        assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{step}");
        assert_eq!(err.readiness_reason(), Some(reason), "{step}");
    }
}
