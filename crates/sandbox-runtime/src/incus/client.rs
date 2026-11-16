//! Thin wrapper around the `incus` CLI (`--project`, JSON list output).

use super::effect_completion;
use crate::before_issue::incus as pre;
use crate::effect::EffectResult;
use crate::{EffectError, EffectOutcome};
use sandbox_protocol::ReadinessFailureReason;
use std::collections::{HashMap, VecDeque};
#[cfg(test)]
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_protocol::SandboxErrorCode;

use crate::error::RuntimeError;
use crate::r#trait::validate_managed_instance_name;

mod images;

pub const METADATA_SANDBOX_ID: &str = "user.flycockpit.sandbox_id";
const METADATA_CREATE_IDEMPOTENCY: &str = "user.flycockpit.create_idempotency_key";
const METADATA_TEMPLATE_DIGEST: &str = "user.flycockpit.template_digest";
/// The disk image a restored instance was initialized
/// from, written by `create_vm` only on a restore. The guest cannot write
/// Incus config; binding never trusts it without the caller's hint.
pub const METADATA_RESTORE_BASE: &str = "user.flycockpit.restore_base";

/// Who an instance must be for a caller. The template
/// tag is always the template fingerprint; a restored lineage's base image
/// is its `restore_base` instead of the template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingIdentity {
    pub template_fingerprint: String,
    pub restore_base: Option<String>,
}

/// Restore bases by sandbox id, fed by the daemon from its journaled lease
/// records and from server-sent `diskBaseFingerprint` (never from instance
/// config). Shared by every clone of one client.
pub(crate) type RestoreBases =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>;

/// THE base-image predicate of both bind functions.
/// - `restore_hint = Some(h)`: `volatile.base_image == h == restore tag`;
/// - `restore_hint = None` (template lineage): `volatile.base_image == template`;
/// - `owned` (autonomous fail-safe binding only): either arm, deciding the
///   restore arm by a well-formed tag alone (the host owns its Incus).
pub(crate) fn base_bound(
    base_image: Option<&str>,
    template: &str,
    restore_tag: Option<&str>,
    restore_hint: Option<&str>,
    owned: bool,
) -> bool {
    let Some(base) = base_image else {
        return false;
    };
    if owned {
        return base == template
            || restore_tag.is_some_and(|tag| crate::is_incus_fingerprint(tag) && base == tag);
    }
    match restore_hint {
        Some(hint) => base == hint && restore_tag == Some(hint),
        None => base == template,
    }
}
const DEFAULT_AGENT_TIMEOUT_SECS: u64 = 120;
/// Process-wait slack past a graceful stop's guest timeout (C55).
const GRACEFUL_STOP_SLACK_SECS: u64 = 5;
const READINESS_POLL: Duration = Duration::from_secs(2);

type AclEditQueues =
    std::sync::Arc<std::sync::Mutex<HashMap<String, VecDeque<std::sync::Arc<()>>>>>;

/// A queued edit owns the ACL only while its token is first. Dropping a
/// cancelled waiter removes its token too, so it cannot strand successors.
pub(super) struct AclEditTurn {
    queues: AclEditQueues,
    name: String,
    token: std::sync::Arc<()>,
}
impl AclEditTurn {
    fn enqueue(queues: &AclEditQueues, name: &str) -> Self {
        let token = std::sync::Arc::new(());
        queues
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .entry(name.to_owned())
            .or_default()
            .push_back(token.clone());
        Self {
            queues: queues.clone(),
            name: name.to_owned(),
            token,
        }
    }
    fn ready(&self) -> bool {
        self.queues
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(&self.name)
            .and_then(|queue| queue.front())
            .is_some_and(|token| std::sync::Arc::ptr_eq(token, &self.token))
    }
}
impl Drop for AclEditTurn {
    fn drop(&mut self) {
        let mut queues = self.queues.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(queue) = queues.get_mut(&self.name) {
            queue.retain(|token| !std::sync::Arc::ptr_eq(token, &self.token));
            if queue.is_empty() {
                queues.remove(&self.name);
            }
        }
    }
}

/// Service-owned control-plane children, including permit-independent expiry
/// work. A relay reconnect leaves them alone; final daemon shutdown closes
/// spawn admission and kills/reaps the exact owned process groups.
#[derive(Debug, Clone, Default)]
pub(crate) struct HostChildren(std::sync::Arc<std::sync::Mutex<HostChildrenState>>);
#[derive(Debug, Default)]
struct HostChildrenState {
    closed: bool,
    pids: std::collections::HashSet<u32>,
}
struct OwnedHostChild {
    children: HostChildren,
    pid: u32,
}
impl Drop for OwnedHostChild {
    fn drop(&mut self) {
        self.children
            .0
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .pids
            .remove(&self.pid);
    }
}
impl HostChildren {
    pub(super) fn is_closed(&self) -> bool {
        self.0.lock().unwrap_or_else(|err| err.into_inner()).closed
    }
    fn spawn(
        &self,
        before: crate::before_issue::BeforeIssue<'_>,
        command: &mut Command,
    ) -> EffectResult<crate::before_issue::Issued<(std::process::Child, OwnedHostChild)>> {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        if state.closed {
            return Err(crate::before_issue::not_issued(RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "host runtime is shutting down",
            )));
        }
        pre::spawn(before, command).map(|issued| {
            issued.map(|child| {
                let pid = child.id();
                state.pids.insert(pid);
                (
                    child,
                    OwnedHostChild {
                        children: self.clone(),
                        pid,
                    },
                )
            })
        })
    }
    fn shutdown(&self) -> Result<(), RuntimeError> {
        {
            // Close spawn admission before signalling, serialized with child
            // registration and removal from this service-owned registry.
            let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
            state.closed = true;
            let groups: Vec<_> = state
                .pids
                .iter()
                .filter_map(|pid| host_group_kill_arg(*pid, own_process_group()))
                .collect();
            if !groups.is_empty() {
                let mut command =
                    crate::host_child::command("kill", crate::host_child::Environment::PathOnly);
                command
                    .args(["-KILL", "--"])
                    .args(groups)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                // One bounded signal helper for all owned groups.
                run_process_cancellable(command, Duration::from_secs(5), None)
                    .map_err(EffectError::into_error)?;
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !self
            .0
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .pids
            .is_empty()
        {
            if Instant::now() >= deadline {
                return Err(RuntimeError::new(
                    SandboxErrorCode::UnknownOutcome,
                    "host runtime children did not finish reaping during shutdown",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}

/// Guest filesystem helpers: run the tool under `LC_ALL=C` and emit only ok /
/// generic failure. Specific guest-plane codes are derived on the host from the
/// tool's own diagnostic line (GNU coreutils grammar), never from `test(1)`
/// probes of parents or later state.
#[cfg(test)]
pub(super) const GUEST_READABLE_SCRIPT: &str = r#"
export LC_ALL=C
stat -L -- "$2" >/dev/null || exit 1
test -r "$2" && printf 'WSSP_READABLE %s\n' "$1"
"#;

#[cfg(test)]
pub(super) const GUEST_STAT_SCRIPT: &str = r#"
export LC_ALL=C
nonce=$1
path=$2
if stat -c '%F|%s|%a' -- "$path"; then
  printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
  exit 0
fi
printf 'WSSP_STATUS %s guest_operation_failed\n' "$nonce" >&2
exit 1
"#;

#[cfg(test)]
pub(super) const GUEST_LIST_SCRIPT: &str = r#"
export LC_ALL=C
nonce=$1
path=$2
depth=$3
if find "$path" -mindepth 1 -maxdepth "$depth" -printf '%y\t%s\t%p\0'; then
  printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
  exit 0
fi
printf 'WSSP_STATUS %s guest_operation_failed\n' "$nonce" >&2
exit 1
"#;

#[cfg(test)]
pub(super) const GUEST_MKDIR_SCRIPT: &str = r#"
export LC_ALL=C
nonce=$1
path=$2
if mkdir -p -- "$path"; then
  printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
  exit 0
fi
printf 'WSSP_STATUS %s guest_operation_failed\n' "$nonce" >&2
exit 1
"#;

#[cfg(test)]
pub(super) const GUEST_REMOVE_SCRIPT: &str = r#"
export LC_ALL=C
nonce=$1
path=$2
shift 2
if "$@"; then
  printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
  exit 0
fi
printf 'WSSP_STATUS %s guest_operation_failed\n' "$nonce" >&2
exit 1
"#;

#[cfg(test)]
pub(super) const GUEST_MOVE_SCRIPT: &str = r#"
export LC_ALL=C
nonce=$1
from=$2
to=$3
if mv -- "$from" "$to"; then
  printf 'WSSP_STATUS %s ok\n' "$nonce" >&2
  exit 0
fi
printf 'WSSP_STATUS %s guest_operation_failed\n' "$nonce" >&2
exit 1
"#;

// Runs outside the target group. A successful signal is NOT disappearance.
// A fresh nonce binds the final observation; the command nonce also prevents a
// recycled leader PID from authorizing signals to an unrelated process group.
//
// E-19/E-20 attribution: the final status is `group_terminated` only when the
// user command was still running at the moment this helper signalled it — a
// live (non-zombie) direct child of the wrapper leader inside the group.
// Otherwise (the group was already gone, or only the wrapper or orphaned
// descendants remained) it is `group_gone`: disappearance without a stop this
// helper can claim. The leader's PID cannot be reused while its group exists,
// so `ppid = pgid` names the wrapper's own child.
pub(super) const GUEST_TERMINATE_SCRIPT: &str = r#"
export LC_ALL=C
nonce=$1
pgid=$2
command_nonce=$3
[ -r /proc/self/stat ] || exit 1
group_present() {
  for f in /proc/[0-9]*/stat; do
    IFS= read -r record 2>/dev/null < "$f" || continue
    fields=${record##*) }
    set -- $fields
    [ "$3" = "$pgid" ] && return 0
  done
  return 1
}
command_running() {
  for f in /proc/[0-9]*/stat; do
    IFS= read -r record 2>/dev/null < "$f" || continue
    fields=${record##*) }
    set -- $fields
    [ "$2" = "$pgid" ] && [ "$3" = "$pgid" ] || continue
    case "$1" in Z|X|x) continue ;; esac
    return 0
  done
  return 1
}
verdict=gone
gone() { printf 'WSSP_STATUS %s group_%s\n' "$nonce" "$verdict" >&2; }
if ! group_present; then gone; exit 0; fi
if [ -r "/proc/$pgid/cmdline" ]; then
  case "$(tr '\000' ' ' < "/proc/$pgid/cmdline")" in
    *"WSSP_PID $command_nonce "*) ;;
    *) exit 1 ;;
  esac
fi
if command_running; then verdict=terminated; fi
/bin/kill -s TERM -- "-$pgid" 2>/dev/null || true
i=0
while [ "$i" -lt 5 ]; do
  if ! group_present; then gone; exit 0; fi
  sleep 0.05
  i=$((i+1))
done
/bin/kill -s KILL -- "-$pgid" 2>/dev/null || true
i=0
while [ "$i" -lt 20 ]; do
  if ! group_present; then gone; exit 0; fi
  sleep 0.05
  i=$((i+1))
done
exit 1
"#;

// Read-only readiness runs with the declared numeric identity, never root. The
// nonce response proves the agent executed the checks, not merely CLI exit zero.
pub(super) const GUEST_READY_SCRIPT: &str = r#"
set -eu
nonce=$1
uid=$2
gid=$3
arch=$4
fail() { printf 'WSSP_NOT_READY %s %s\n' "$nonce" "$1"; exit 1; }
entry=$(getent passwd "$uid") || fail user
IFS=: read -r user password actual_uid actual_gid gecos home shell <<EOF
$entry
EOF
[ "$actual_uid" = "$uid" ] || fail user
[ "$actual_gid" = "$gid" ] || fail user
[ "$home" = "$HOME" ] || fail home
[ "$shell" = "$SHELL" ] || fail shell
[ "$(id -u)" = "$uid" ] || fail user
[ "$(id -g)" = "$gid" ] || fail user
[ "$(uname -m)" = "$arch" ] || fail arch
{ [ -d "$HOME" ] && [ -w "$HOME" ] && [ -x "$HOME" ]; } || fail home
[ -x "$SHELL" ] || fail shell
[ "$(stat -c %u:%g -- "$HOME")" = "$uid:$gid" ] || fail home
if [ "$5" = required ] || [ -e "$HOME/repo" ]; then
  { [ -d "$HOME/repo" ] && [ -w "$HOME/repo" ] && [ -x "$HOME/repo" ]; } || fail repo
  [ "$(stat -c %u:%g -- "$HOME/repo")" = "$uid:$gid" ] || fail repo
fi
for tool in setsid sh stat find mkdir mv rm kill sync python3; do command -v "$tool" >/dev/null || fail tooling; done
setsid -w true || fail tooling
printf 'WSSP_READY %s\n' "$nonce"
"#;

/// Boot settle argv (bootstrap readiness), run as the declared uid.
/// Pause between boot-settle answers that carry no settled state.
const BOOT_SETTLE_RETRY: Duration = Duration::from_millis(500);
pub(super) const GUEST_SETTLE_ARGV: [&str; 3] = ["systemctl", "is-system-running", "--wait"];

/// What one boot settle observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BootSettle {
    /// `running` or `degraded`.
    Settled,
    /// Anything else (still booting, stopping, maintenance, no answer).
    Unsettled,
}

/// A boot that never settled (bootstrap readiness, outside the restart loop).
pub(super) fn boot_unsettled() -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::GuestUnavailable,
        "the guest's boot did not settle (`systemctl is-system-running`)",
    )
    .with_readiness_reason(ReadinessFailureReason::GuestCheck)
}

/// The guest user's linger (diagnostic, run as the guest user once ready):
/// `enabled` when logind's linger file exists, `allowed` when polkit
/// authorizes `org.freedesktop.login1.set-self-linger` for this very process
/// without interaction (stock Ubuntu 26.04), otherwise `blocked`. `pkcheck`
/// only asks; it never changes linger.
pub(super) const GUEST_LINGER_SCRIPT: &str = r#"
set -u
nonce=$1
user=$(id -un) || exit 1
state=blocked
if [ -e "/var/lib/systemd/linger/$user" ]; then
  state=enabled
elif command -v pkcheck >/dev/null 2>&1 \
  && pkcheck --action-id org.freedesktop.login1.set-self-linger --process $$ >/dev/null 2>&1; then
  state=allowed
fi
printf 'WSSP_LINGER %s %s\n' "$nonce" "$state"
"#;

/// The failed check a readiness script reported (`WSSP_NOT_READY <nonce>
/// <label>`), mapped through a fixed allowlist: the label is guest output, so
/// only a known constant is ever kept.
fn readiness_script_reason(stdout: &str, nonce: &str) -> ReadinessFailureReason {
    let label = stdout
        .strip_prefix("WSSP_NOT_READY ")
        .and_then(|rest| rest.strip_prefix(nonce))
        .and_then(|rest| rest.strip_prefix(' '))
        .and_then(|rest| rest.strip_suffix('\n'));
    match label {
        Some("user") => ReadinessFailureReason::GuestUser,
        Some("home") => ReadinessFailureReason::GuestHome,
        Some("shell") => ReadinessFailureReason::GuestShell,
        Some("arch") => ReadinessFailureReason::Architecture,
        Some("repo") => ReadinessFailureReason::GuestRepo,
        Some("tooling") => ReadinessFailureReason::GuestTooling,
        _ => ReadinessFailureReason::GuestCheck,
    }
}

/// Readiness also requires guest networking (E1-A-01): an IPv4 default
/// route on a non-loopback interface in `$2` (`/proc/net/route`), polled
/// once a second for up to `$3` tries. DHCP installs the address before the
/// route, so a default route means the guest has an address on it.
pub(super) const GUEST_NETWORK_SCRIPT: &str = r#"
set -eu
nonce=$1
routes=$2
tries=$3
i=0
while :; do
  if [ -r "$routes" ]; then
    while read -r iface dest rest; do
      if [ "$dest" = 00000000 ] && [ "$iface" != lo ]; then
        printf 'WSSP_NET %s\n' "$nonce"
        exit 0
      fi
    done < "$routes"
  fi
  i=$((i + 1))
  [ "$i" -lt "$tries" ] || exit 3
  sleep 1
done
"#;

/// How long readiness waits for the guest's DHCP lease (one try a second).
pub(super) const GUEST_NETWORK_TRIES: u32 = 30;

pub(super) const METADATA_READINESS: &str = "user.flycockpit.readiness";
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct ReadinessSpec {
    pub guest: crate::GuestIdentity,
    pub architecture: String,
    /// Bootstrap readiness for a community prep build VM, written only at
    /// create from the daemon's gate proof and read by allocation recovery
    /// and probes (I11). A pre-feature spec reads `standard`.
    #[serde(default)]
    pub mode: crate::ReadinessMode,
    /// Guest sudo, written only at create and read by allocation recovery
    /// (grant or revoke on a running VM) and by every reconnect's check
    /// against the lease. No root flag and no guest name (S3, T2). A
    /// pre-feature spec reads `{sudo: false}`.
    #[serde(default)]
    pub privilege: SpecPrivilege,
    /// The disk a fresh create grew its root to (none for a restore or
    /// without a bound root disk), so allocation recovery of that create
    /// re-runs the root growth check. A pre-feature spec reads none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_disk_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SpecPrivilege {
    pub sudo: bool,
}

impl SpecPrivilege {
    /// Only the effective grant is persisted (never the audit bit).
    pub(super) fn of(privilege: crate::GuestPrivilege) -> Self {
        Self {
            sudo: privilege.sudo,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IncusClient {
    pub(crate) host_children: HostChildren,
    /// Census IO remains cancellable even when recovery clears the issuing
    /// operation permit for expiry fencing. Autonomous watchers clear this.
    pub(crate) inspection_permit: Option<std::sync::Arc<crate::RuntimePermit>>,
    /// FIFO serialization for whole-ACL CLI rewrites, shared by clones.
    pub(crate) acl_edits: AclEditQueues,
    /// 0 unknown, 1 old CLI without query headers, 2 conditional PUT supported.
    pub(crate) acl_update_mode: std::sync::Arc<std::sync::atomic::AtomicU8>,
    /// Exercise recovery of pre-batching, per-identity journal histories even
    /// when a test starts from a clean ACL. Production selects this path only
    /// while unresolved mutation/fence obligations exist.
    #[cfg(test)]
    pub(crate) force_legacy_dns_recovery: bool,
    /// Operation-scoped expected binding, supplied by storage-aware callers.
    pub(crate) expected_root: Option<crate::RootDisk>,
    /// Time source for persisted DNS answer/lease lifetimes. Host command
    /// cancellation and IO budgets continue to use the real monotonic clock.
    pub(crate) dns_clock: std::sync::Arc<dyn super::dns::DnsClock>,
    /// Egress guard attestation for the start fence (§2.0.5): one fresh
    /// `status` per start. Fails closed until a guard client is installed
    /// (`IncusKvmRuntime::set_guard_probe`); unit tests use a healthy fake.
    pub(crate) guard_probe: std::sync::Arc<dyn crate::guard_probe::GuardProbe>,
    /// How long the start fence waits for a just-created bridge to appear
    /// in the guard's sets (§2.0.5: up to 5 s).
    pub(crate) guard_fence_wait: std::time::Duration,
    /// Retryable dispatch refusal, not destructive authority. Shared by all
    /// guest IO adapters; only a fresh coherent verification clears an entry.
    pub(crate) policy_refusals: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// Restore bases, see [`RestoreBases`].
    pub(crate) restore_bases: RestoreBases,
    /// B12: build VMs' in-memory DNS stubs (refused-name hints).
    pub(crate) dns_stubs: std::sync::Arc<super::dns_stub::DnsStubs>,
    /// The subset of `policy_refusals` whose LAST reconciler cause was an
    /// owed DNS refresh (C58 G1-R1-3): only these may be refreshed while
    /// refused, because the refresh is what clears that cause.
    pub(crate) owed_refusals: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    pub(crate) loss_lifecycle: std::sync::Arc<
        std::sync::Mutex<Option<std::sync::Arc<dyn crate::EnforcementLossLifecycle>>>,
    >,
    pub guest: crate::GuestIdentity,
    /// D1: this scoped client executes as guest root (template-build steps
    /// only). Set solely by the command supervisor from `run_as_root`.
    pub(crate) exec_as_root: bool,
    /// Where the host's `/proc` is read for the QEMU identity (tests point
    /// it at a fixture tree).
    pub(crate) proc_root: std::path::PathBuf,
    pub cancelled: Option<std::sync::Arc<crate::RuntimePermit>>,
    /// Create's locked mutation section waits for an admitted CLI call to
    /// settle even after revocation. Killing the CLI does not cancel Incus's
    /// daemon operation. Every subsequent spawn still checks the permit.
    pub(crate) settle_create: bool,
    /// Close authority over live terminal sessions (C51), shared by clones:
    /// every VM stop/delete effect closes and reaps the sandbox's PTYs.
    pub(crate) pty_sessions: crate::pty::PtyRegistry,
    pub binary: String,
    pub project: String,
    pub agent_timeout: Duration,
    /// How long readiness tolerates a VM, once seen Running, being out of
    /// Running (a guest-initiated reboot) before it is a stopped VM.
    pub reboot_settle: Duration,
    /// Default supervised-command bound when `timeout_ms` is omitted.
    pub command_timeout: Duration,
    /// query body mode: 0 unknown, 1 pre-7.4 inline-only, 2 data-file capable.
    /// Clones share the detection; no extra version/probe process is needed.
    pub(crate) query_body_mode: std::sync::Arc<std::sync::atomic::AtomicU8>,
    pub(crate) dns_priority: super::dns_refresh::DnsPriorityRegistry,
    /// Durable host-side state (pending network cleanups). Tests point this at
    /// a scratch directory; production resolves the data dir per invocation.
    pub state_dir: Option<std::path::PathBuf>,
    /// Test override for the host route table consulted during sandbox subnet
    /// allocation. `None` reads `/proc/net/route`.
    pub host_routes: Option<Vec<(u32, u8)>>,
    /// Test override for egress domain resolution. `None` uses the bounded
    /// system resolver.
    #[cfg(test)]
    pub resolver: Option<TestResolver>,
    #[cfg(test)]
    pub(crate) resolver_pool: Option<std::sync::Arc<super::network::ResolverPool>>,
    /// Per-sandbox serialization for apply/teardown/journal updates: a drain
    /// must never delete between a fence read and a restamp by a concurrent
    /// retry. Shared across clones so scoped cleanup clients serialize with
    /// their issuer. Entries are Weak and reclaimed under the registry
    /// mutex: the map never grows permanently, and every lookup/insert is
    /// serialized so concurrent callers always obtain the SAME lock.
    pub sandbox_locks: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Weak<std::sync::Mutex<()>>>>,
    >,
    /// Test hook: consulted inside the fenced teardown after the incarnation
    /// fence passes and before the deletion, proving the sandbox lock
    /// serializes the fence-to-delete window.
    #[cfg(test)]
    pub fence_barrier: Option<std::sync::Arc<std::sync::Barrier>>,
    /// Park actual create/reconnect readiness after verification, without
    /// holding the lifecycle gate, to exercise concurrent policy observations.
    #[cfg(test)]
    pub readiness_barrier: Option<std::sync::Arc<std::sync::Barrier>>,
    #[cfg(test)]
    pub create_barrier: Option<(&'static str, std::sync::Arc<std::sync::Barrier>)>,
    /// Observe planning entry even when it reuses local evidence without IO.
    #[cfg(test)]
    pub network_planning_count: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    pub readiness_after_agent_barrier: Option<std::sync::Arc<std::sync::Barrier>>,
    /// Park after command/staging preparation, or inspect the short admission
    /// section. Never installed in production.
    #[cfg(test)]
    pub guest_spawn_hook: Option<TestGuestSpawnHook>,
    /// Pause after accepting mutation READY, before commit admission. No
    /// permit guard is held, so tests can deterministically revoke or close it.
    #[cfg(test)]
    pub mutation_commit_hook: Option<TestMutationCommitHook>,
    /// Test hook: consulted inside the DNS lease settlement commit — under
    /// the commit lock, post-validation, pre-persistence — so a test can
    /// interleave a refresh commit and prove the serialization (C36 r20 F3).
    #[cfg(test)]
    pub dns_commit_barrier: Option<std::sync::Arc<std::sync::Barrier>>,
    #[cfg(test)]
    pub(crate) dns_commit_hold: Option<std::sync::Arc<DnsCommitHold>>,
    /// Freeze permit time for functional fault tests; individual command
    /// waits retain this finite budget.
    #[cfg(test)]
    pub(crate) policy_observation_budget_override: Option<Duration>,
    /// Observe the actual withdrawal boundary's destination and caller budget.
    #[cfg(test)]
    pub(crate) dns_withdrawal_budgets: Option<DnsWithdrawalBudgets>,
    /// Observe the actual per-attempt command deadline, including force retries.
    #[cfg(test)]
    pub(crate) dns_withdrawal_attempts: Option<DnsWithdrawalAttempts>,
    /// Observe a successful pre-fence and its cache size under the lease
    /// owner lock, before settlement can withdraw the allow or fence.
    #[cfg(test)]
    pub(crate) dns_prefence_hook: Option<TestDnsPrefenceHook>,
    /// Revoke the original caller after halt's ownership observation.
    #[cfg(test)]
    pub(crate) halt_observation_revoke: Option<std::sync::Arc<crate::RuntimePermit>>,
    /// Test hook: consulted in the refresh commit BEFORE the commit lock
    /// is taken — so a test can let a lease settlement COMPLETE (mutations
    /// and its own commit) while a refresh is parked, then have the
    /// refresh commit its stale snapshot as the LAST writer (C36 r21 F6).
    #[cfg(test)]
    pub dns_commit_pre_lock_barrier: Option<std::sync::Arc<std::sync::Barrier>>,
    /// Test hook: make strict directory fsyncs fail, proving durable journal
    /// hierarchy creation fails closed before any host mutation.
    #[cfg(test)]
    pub fail_dir_sync: bool,
    /// Test hook: fail the strict fsync for one specific directory, so tests
    /// can prove a retry resyncs the exact parent chain of a half-durable
    /// hierarchy.
    #[cfg(test)]
    pub fail_dir_sync_for: Option<std::path::PathBuf>,
    /// Test override for the allocation-lock wait budget.
    #[cfg(test)]
    pub allocation_lock_wait: Option<std::time::Duration>,
    /// Test-only override for the provisioned daemon lock directory.
    #[cfg(test)]
    pub daemon_lock_dir_override: Option<std::path::PathBuf>,
    /// Test-only euid override, modelling a non-owner lock-file acquisition
    /// (real cross-UID fixtures need root).
    #[cfg(test)]
    pub lock_file_euid_override: Option<u32>,
    /// Test-only override for the enforcement-observation coherence budget,
    /// so the exhaustion path is exercised without a 25s stall (C37 R4).
    #[cfg(test)]
    pub coherence_budget_override: Option<std::time::Duration>,
}

impl IncusClient {
    /// The shared lock serializing all network apply/teardown/journal work
    /// for one sandbox. Bind the Arc, then lock it for the whole section:
    /// `let lock = client.sandbox_lock(id); let _guard = lock.lock()...;`.
    pub(crate) fn sandbox_lock(&self, sandbox_id: &str) -> std::sync::Arc<std::sync::Mutex<()>> {
        let mut locks = self
            .sandbox_locks
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(existing) = locks.get(sandbox_id).and_then(std::sync::Weak::upgrade) {
            return existing;
        }
        // Reclaim dead entries while holding the registry mutex: reclamation
        // and insertion are one serialized section, so no concurrent caller
        // can resurrect a stale entry or insert a second lock for this id.
        locks.retain(|_, weak| weak.strong_count() > 0);
        let lock = std::sync::Arc::new(std::sync::Mutex::new(()));
        locks.insert(sandbox_id.to_string(), std::sync::Arc::downgrade(&lock));
        lock
    }

    /// Test hook: registry size, to prove entries are reclaimed.
    #[cfg(test)]
    pub(crate) fn sandbox_lock_registry_len(&self) -> usize {
        self.sandbox_locks
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .len()
    }
}

#[cfg(test)]
pub(crate) type DnsWithdrawalBudgets =
    std::sync::Arc<std::sync::Mutex<Vec<(String, Option<Duration>)>>>;

#[cfg(test)]
pub(crate) type DnsWithdrawalAttempts =
    std::sync::Arc<std::sync::Mutex<Vec<(String, bool, Option<std::time::Instant>)>>>;

/// A domain-resolution function: hostname to resolved addresses.
#[cfg(test)]
pub type ResolveFn = std::sync::Arc<
    dyn Fn(&str, std::time::Duration) -> Result<Vec<std::net::IpAddr>, RuntimeError> + Send + Sync,
>;

/// Injectable domain resolver for deterministic egress tests.
#[cfg(test)]
#[derive(Clone)]
pub struct TestResolver(pub ResolveFn);

#[cfg(test)]
pub type GuestSpawnFn = std::sync::Arc<dyn Fn(&Command, bool) + Send + Sync>;

#[cfg(test)]
#[derive(Clone)]
pub struct TestGuestSpawnHook(pub GuestSpawnFn);

#[cfg(test)]
impl std::fmt::Debug for TestGuestSpawnHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestGuestSpawnHook(..)")
    }
}

#[cfg(test)]
#[derive(Clone)]
pub struct TestMutationCommitHook(pub std::sync::Arc<dyn Fn() + Send + Sync>);

#[cfg(test)]
impl std::fmt::Debug for TestMutationCommitHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestMutationCommitHook(..)")
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestDnsPrefenceHook(pub std::sync::Arc<dyn Fn(usize) + Send + Sync>);

#[cfg(test)]
impl std::fmt::Debug for TestDnsPrefenceHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestDnsPrefenceHook(..)")
    }
}

#[cfg(test)]
impl std::fmt::Debug for TestResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestResolver(..)")
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct DnsCommitHold {
    pub(crate) entered: std::sync::atomic::AtomicBool,
    pub(crate) duration: Duration,
}

/// Verified physical instance identity. Only `IncusClient::bind_instance` can
/// construct this capability; a managed name alone cannot authorize an effect.
/// It is a snapshot, not a lock. Effects recheck the binding before guest IO.
#[derive(Debug, Clone)]
pub struct BoundInstance {
    name: String,
    sandbox_id: String,
    fingerprint: String,
    create_key: Option<String>,
    binary: String,
    project: String,
    observed: HostInstance,
}

impl BoundInstance {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn is_running(&self) -> bool {
        self.observed.is_running()
    }
    pub fn is_stopped(&self) -> bool {
        self.observed.is_stopped()
    }
}

#[derive(Debug, Clone)]
pub struct IncusCommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Host-authoritative instance record from `incus query /1.0/instances/<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInstance {
    pub name: String,
    pub status: String,
    pub status_code: u64,
}

impl HostInstance {
    pub fn is_running(&self) -> bool {
        status_is_running(&self.status, self.status_code)
    }

    pub fn is_stopped(&self) -> bool {
        status_is_stopped(&self.status, self.status_code)
    }

    pub fn is_starting(&self) -> bool {
        status_is_starting(&self.status, self.status_code)
    }
}

/// Host-authoritative VM runtime record from `incus query /1.0/instances/<name>/state`.
///
/// Neither readiness nor a read's plane-loss re-observation
/// (`observation_plane_failure`) consumes `processes`: Incus v6.0.x sets that
/// field to `-1`
/// both when the agent is down and when `security.agent.metrics=false`, and a
/// successful agent-state fetch copies the guest agent's own count. Agent
/// availability is proven by a guest `true` exec probe instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInstanceState {
    pub status: String,
    pub status_code: u64,
    /// The VM's QEMU process id while it runs (Incus reports 0 when stopped).
    /// Incus handles a guest-initiated reboot by restarting the VM (its state
    /// briefly leaves Running), so a changed pid is host-side restart
    /// evidence even when no state read lands in that window.
    pub pid: Option<u64>,
}

impl HostInstanceState {
    pub fn is_running(&self) -> bool {
        status_is_running(&self.status, self.status_code)
    }

    pub fn is_stopped(&self) -> bool {
        status_is_stopped(&self.status, self.status_code)
    }

    pub fn is_starting(&self) -> bool {
        status_is_starting(&self.status, self.status_code)
    }

    /// A state a guest-initiated reboot passes through: Running, Stopping,
    /// Stopped, Starting, or Error. Incus reports Error while a QEMU process
    /// is alive but its monitor is unreachable, which the old process of a
    /// restarting VM passes through as it is torn down; an Error that
    /// persists is still bounded by the reboot settle window. Frozen and
    /// every other state are not.
    fn is_reboot_phase(&self) -> bool {
        self.is_running()
            || self.is_starting()
            || self.is_stopped()
            || status_is_stopping(&self.status, self.status_code)
            || status_is_error(&self.status, self.status_code)
    }
}

/// Readiness tolerates guest-initiated restarts (an Ubuntu 26.04 instance
/// reboots once during first boot) inside the UNCHANGED agent budget: one
/// deadline spans every agent wait of one readiness pass. A VM that stays
/// out of Running for [`REBOOT_SETTLE`] (`reboot_settle`, a lasting Error
/// included), restarts more than [`MAX_GUEST_RESTARTS`] times, or enters a
/// non-boot state (Frozen, ...) still fails.
pub(super) const REBOOT_SETTLE: Duration = Duration::from_secs(15);
pub(super) const MAX_GUEST_RESTARTS: u32 = 2;
/// The least readiness budget of a bootstrap (community prep) build VM.
pub(super) const BOOTSTRAP_AGENT_TIMEOUT: Duration = Duration::from_secs(300);

/// The state of one readiness pass, shared by its agent waits.
#[derive(Debug)]
pub(super) struct AgentWait {
    budget: Duration,
    settle: Duration,
    deadline: Instant,
    saw_running: bool,
    saw_running_or_starting: bool,
    restarts: u32,
    pid: Option<u64>,
    /// The guest kernel's boot id when the agent last answered.
    boot: Option<String>,
    /// A down observation [`IncusClient::validate_pass`] already counted:
    /// the next agent wait does not count it again.
    down_counted: bool,
    /// When a host state read last saw the VM Running.
    last_running: Option<Instant>,
}

/// What re-observing the guest after a readiness pass established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PassValidation {
    /// Same boot, still Running: the pass result stands.
    Stable,
    /// The guest restarted: run the pass again.
    Restarted,
    /// The host state or the boot id could not be read. Never READY: a passed
    /// pass runs again (counted like a restart); a failed one keeps its error.
    Unobserved,
}

impl AgentWait {
    /// Count a pass that could not be validated like a restart (bounded).
    pub(super) fn unobserved_pass(&mut self, name: &str) -> Result<(), RuntimeError> {
        self.restarted(name)
    }

    /// The whole budget of this readiness pass.
    #[cfg(test)]
    pub(super) fn budget(&self) -> Duration {
        self.budget
    }

    /// Guest restarts this readiness tolerated so far.
    pub(super) fn restarts(&self) -> u32 {
        self.restarts
    }

    /// The budget-exhausted readiness failure (`agent_timeout`).
    pub(super) fn deadline_error(&self, name: &str) -> RuntimeError {
        guest_unavailable_timeout(name, self.budget)
    }

    pub(super) fn new(budget: Duration, settle: Duration) -> Self {
        Self {
            budget,
            settle,
            deadline: Instant::now() + budget,
            saw_running: false,
            saw_running_or_starting: false,
            restarts: 0,
            pid: None,
            boot: None,
            down_counted: false,
            last_running: None,
        }
    }

    pub(super) fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Record one restart; past the bound it is a readiness failure.
    fn restarted(&mut self, name: &str) -> Result<(), RuntimeError> {
        self.restarts += 1;
        if self.restarts > MAX_GUEST_RESTARTS {
            return Err(RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                format!(
                    "incus VM `{name}` restarted {} times during readiness",
                    self.restarts
                ),
            )
            .with_readiness_reason(ReadinessFailureReason::GuestRestarts));
        }
        Ok(())
    }

    /// One host state observation: Running with a new QEMU pid is a restart.
    fn observe_pid(&mut self, name: &str, state: &HostInstanceState) -> Result<(), RuntimeError> {
        if let Some(pid) = state.pid {
            if self.pid.is_some_and(|known| known != pid) {
                self.restarted(name)?;
            }
            self.pid = Some(pid);
        }
        Ok(())
    }
}

fn status_is_running(status: &str, status_code: u64) -> bool {
    status.eq_ignore_ascii_case("running") || status_code == 103
}

fn status_is_stopped(status: &str, status_code: u64) -> bool {
    status.eq_ignore_ascii_case("stopped") || status_code == 102
}

fn status_is_starting(status: &str, status_code: u64) -> bool {
    status.eq_ignore_ascii_case("starting") || status_code == 106
}

fn status_is_stopping(status: &str, status_code: u64) -> bool {
    status.eq_ignore_ascii_case("stopping") || status_code == 107
}

fn status_is_error(status: &str, status_code: u64) -> bool {
    status.eq_ignore_ascii_case("error") || status_code == 112
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ListedInstance {
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    #[serde(rename = "type")]
    pub instance_type: String,
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,
    /// Effective (profile-merged) config, when the list rows carry it. The
    /// census sizes a VM from it instead of one instance query per VM.
    #[serde(default)]
    pub expanded_config: Option<serde_json::Map<String, serde_json::Value>>,
}

impl IncusClient {
    pub fn new(binary: impl Into<String>, project: impl Into<String>) -> Self {
        Self {
            host_children: Default::default(),
            inspection_permit: None,
            acl_edits: Default::default(),
            acl_update_mode: Default::default(),
            #[cfg(test)]
            force_legacy_dns_recovery: false,
            expected_root: None,
            dns_clock: std::sync::Arc::new(super::dns::RealDnsClock),
            #[cfg(not(test))]
            guard_probe: std::sync::Arc::new(crate::guard_probe::UnavailableGuardProbe),
            #[cfg(test)]
            guard_probe: std::sync::Arc::new(crate::guard_probe::FakeGuardProbe::healthy()),
            #[cfg(not(test))]
            guard_fence_wait: std::time::Duration::from_secs(5),
            #[cfg(test)]
            guard_fence_wait: std::time::Duration::from_millis(200),
            policy_refusals: Default::default(),
            restore_bases: Default::default(),
            dns_stubs: Default::default(),
            owed_refusals: Default::default(),
            loss_lifecycle: Default::default(),
            guest: crate::GuestIdentity::default(),
            exec_as_root: false,
            proc_root: std::path::PathBuf::from("/proc"),
            cancelled: None,
            settle_create: false,
            pty_sessions: Default::default(),
            binary: binary.into(),
            project: project.into(),
            agent_timeout: agent_timeout_from_env(),
            reboot_settle: REBOOT_SETTLE,
            command_timeout: Duration::from_secs(120),
            query_body_mode: Default::default(),
            dns_priority: Default::default(),
            state_dir: None,
            host_routes: None,
            #[cfg(test)]
            resolver: None,
            #[cfg(test)]
            resolver_pool: None,
            sandbox_locks: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(test)]
            fence_barrier: None,
            #[cfg(test)]
            readiness_barrier: None,
            #[cfg(test)]
            create_barrier: None,
            #[cfg(test)]
            network_planning_count: None,
            #[cfg(test)]
            readiness_after_agent_barrier: None,
            #[cfg(test)]
            guest_spawn_hook: None,
            #[cfg(test)]
            mutation_commit_hook: None,
            #[cfg(test)]
            dns_commit_barrier: None,
            #[cfg(test)]
            dns_commit_hold: None,
            #[cfg(test)]
            policy_observation_budget_override: None,
            #[cfg(test)]
            dns_withdrawal_budgets: None,
            #[cfg(test)]
            dns_withdrawal_attempts: None,
            #[cfg(test)]
            dns_prefence_hook: None,
            #[cfg(test)]
            halt_observation_revoke: None,
            #[cfg(test)]
            dns_commit_pre_lock_barrier: None,
            #[cfg(test)]
            fail_dir_sync: false,
            #[cfg(test)]
            fail_dir_sync_for: None,
            #[cfg(test)]
            allocation_lock_wait: None,
            #[cfg(test)]
            daemon_lock_dir_override: None,
            #[cfg(test)]
            lock_file_euid_override: None,
            #[cfg(test)]
            coherence_budget_override: None,
        }
    }

    /// Point the client's durable host-side state (pending network cleanups,
    /// persisted plans, locks) at `dir`. The node daemon passes the state
    /// directory it already resolved for the relay so the runtime never
    /// needs its own environment channel.
    pub fn set_host_state_dir(&mut self, dir: impl Into<std::path::PathBuf>) {
        self.state_dir = Some(dir.into());
    }

    /// Resolve an egress grant domain: test override when present, else the
    /// bounded, cancellation-aware system resolver.
    /// `wait` clamps this lookup to the remaining compilation budget.
    pub(crate) fn resolve_domain(
        &self,
        sandbox_id: &str,
        domain: &str,
        wait: std::time::Duration,
    ) -> Result<Vec<std::net::IpAddr>, RuntimeError> {
        #[cfg(test)]
        if let Some(resolver) = &self.resolver {
            return (resolver.0)(domain, wait);
        }
        // Include the project in the host-wide pool's owner key. Clones and
        // concurrent create/refresh callers share the same sandbox allowance.
        let owner = format!("{}/{sandbox_id}", self.project);
        #[cfg(test)]
        if let Some(pool) = &self.resolver_pool {
            return pool.lookup(&owner, domain, wait);
        }
        super::network::bounded_lookup(&owner, domain, wait)
    }

    pub fn with_guest(&self, guest: &crate::GuestIdentity) -> Self {
        Self {
            guest: guest.clone(),
            ..self.clone()
        }
    }

    /// A client whose execs run as guest root (D1: build steps only). The
    /// declared guest identity stays bound and validated.
    pub(super) fn with_root_exec(&self, root: bool) -> Self {
        Self {
            exec_as_root: root,
            ..self.clone()
        }
    }

    /// Guest root's `incus exec` identity: `HOME=/root`, `SHELL=/bin/sh`,
    /// cwd `/root` unless given. Only the build path reaches it.
    pub(super) fn guest_exec_args_root(cwd: Option<&str>) -> Result<Vec<String>, RuntimeError> {
        let cwd = cwd.unwrap_or("/root");
        validate_guest_path(cwd)?;
        Ok(vec![
            "--user".into(),
            "0".into(),
            "--group".into(),
            "0".into(),
            "--cwd".into(),
            cwd.into(),
            "--env".into(),
            "HOME=/root".into(),
            "--env".into(),
            "SHELL=/bin/sh".into(),
        ])
    }

    pub(super) fn guest_exec_args(&self, cwd: Option<&str>) -> Result<Vec<String>, RuntimeError> {
        self.guest.validate()?;
        if self.exec_as_root {
            return Self::guest_exec_args_root(cwd);
        }
        let cwd = cwd.unwrap_or(&self.guest.guest_home);
        validate_guest_path(cwd)?;
        Ok(vec![
            "--user".into(),
            self.guest.guest_uid.to_string(),
            "--group".into(),
            self.guest.guest_gid.to_string(),
            "--cwd".into(),
            cwd.into(),
            "--env".into(),
            format!("HOME={}", self.guest.guest_home),
            "--env".into(),
            format!("SHELL={}", self.guest.guest_shell),
        ])
    }

    /// The ONE guest-spawn admission boundary. Keep the positively bound
    /// sandbox identity through all preparation (including file staging).
    /// Refusal publication and local spawn linearize under the SAME mutex.
    /// Neither ownership daemon IO nor child/daemon waits run under it; urgent
    /// restrictive stop/expiry do not acquire it. RuntimePermit still fences
    /// revocation through spawn independently of retryable policy uncertainty.
    pub(super) fn spawn_guest(
        &self,
        bound: &BoundInstance,
        command: &mut Command,
    ) -> EffectResult<std::process::Child> {
        self.admit_guest_spawn(bound, command, |before, command| {
            command.process_group(0);
            pre::spawn(before, command)
        })
    }

    /// The admission section shared by every guest spawn (piped `incus exec`
    /// and the C51 PTY child). `command` is the spawn's argv view: piped
    /// spawns run it; the PTY spawn passes a never-spawned mirror so test
    /// hooks observe the same argv.
    pub(super) fn admit_guest_spawn<T>(
        &self,
        bound: &BoundInstance,
        command: &mut Command,
        spawn: impl for<'phase> FnOnce(
            crate::before_issue::BeforeIssue<'phase>,
            &mut Command,
        ) -> EffectResult<crate::before_issue::Issued<T>>,
    ) -> EffectResult<T> {
        pre::phase(
            |before| {
                self.check_request_binding(
                    bound,
                    bound.name(),
                    &bound.sandbox_id,
                    &bound.fingerprint,
                )
                .map_err(crate::before_issue::not_issued)?;
                #[cfg(test)]
                if let Some(hook) = &self.guest_spawn_hook {
                    (hook.0)(command, false);
                }
                let _permit = self
                    .cancelled
                    .as_ref()
                    .map(|p| p.admit())
                    .transpose()
                    .map_err(crate::before_issue::not_issued)?;
                let refusals = self
                    .policy_refusals
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if refusals.contains(&bound.sandbox_id) {
                    return Err(crate::before_issue::not_issued(RuntimeError::new(
                        SandboxErrorCode::Internal,
                        "policy reconciliation has not verified guest dispatch; retry after verification",
                    ).enforcement_inconclusive()));
                }
                #[cfg(test)]
                if let Some(hook) = &self.guest_spawn_hook {
                    (hook.0)(command, true);
                }
                let spawned = spawn(before, command);
                drop(refusals);
                spawned
            },
            Ok,
        )
    }

    /// Only synthetic local process tests construct a capability without the
    /// daemon ownership read. Production capabilities remain positively bound.
    #[cfg(test)]
    pub(super) fn local_test_bound(&self) -> BoundInstance {
        BoundInstance {
            name: "wssp-sbx-sbx-1".into(),
            sandbox_id: "sbx-1".into(),
            fingerprint: crate::CreateSandboxRequest::for_test("sbx-1", "key").template_digest,
            create_key: None,
            binary: self.binary.clone(),
            project: self.project.clone(),
            observed: HostInstance {
                name: "wssp-sbx-sbx-1".into(),
                status: "Running".into(),
                status_code: 103,
            },
        }
    }

    pub fn metadata_keys() -> (&'static str, &'static str, &'static str) {
        (
            METADATA_SANDBOX_ID,
            METADATA_CREATE_IDEMPOTENCY,
            METADATA_TEMPLATE_DIGEST,
        )
    }

    pub fn ping(&self) -> Result<(), RuntimeError> {
        let out = self.run(&["version"], false)?;
        if out.exit_code != 0 {
            return Err(host_cli_error("version", &out));
        }
        Ok(())
    }

    pub fn ensure_project(&self) -> Result<(), RuntimeError> {
        validate_incus_identifier(&self.project, "project")?;
        if self.project != "default" {
            // Bootstrap through the always-existing default project.
            let administration = Self {
                project: "default".to_string(),
                ..self.clone()
            };
            let list = administration.run(&["project", "list", "--format", "json"], false)?;
            if list.exit_code != 0 {
                return Err(host_cli_error("project list", &list));
            }
            let projects: Vec<serde_json::Value> =
                serde_json::from_str(&list.stdout).map_err(|err| {
                    RuntimeError::new(
                        SandboxErrorCode::Internal,
                        format!("failed to parse incus project list JSON: {err}"),
                    )
                })?;
            let exists = projects
                .iter()
                .any(|row| row.get("name").and_then(|v| v.as_str()) == Some(&self.project));
            if !exists {
                let create = administration.run(
                    &[
                        "project",
                        "create",
                        &self.project,
                        "--config",
                        "features.profiles=false",
                        "--config",
                        "features.images=false",
                        "--config",
                        "features.storage.volumes=true",
                    ],
                    false,
                )?;
                if create.exit_code != 0 && !already_exists(&create) {
                    return Err(host_cli_error("project create", &create));
                }
                if create.exit_code != 0 && already_exists(&create) {
                    administration.verify_dedicated_project_sharing(&self.project)?;
                }
            } else {
                administration.verify_dedicated_project_sharing(&self.project)?;
            }
        }
        self.verify_project_storage_volumes()?;
        self.ensure_default_profile()
    }

    /// Dedicated projects must share the default project's profiles and image
    /// store. Read-only verification for operator-created projects.
    fn verify_dedicated_project_sharing(&self, name: &str) -> Result<(), RuntimeError> {
        validate_incus_identifier(name, "project")?;
        let path = project_query_url(name)?;
        let metadata = self.query_raw(&path)?;
        let config = metadata
            .get("config")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| dedicated_project_sharing_error(name))?;
        for key in ["features.profiles", "features.images"] {
            match config.get(key).and_then(serde_json::Value::as_str) {
                Some("false") => {}
                _ => return Err(dedicated_project_sharing_error(name)),
            }
        }
        Ok(())
    }

    /// New projects share the initialized default project's profiles. Verify the
    /// effective profile before accepting work (also covers existing projects).
    pub fn ensure_default_profile(&self) -> Result<(), RuntimeError> {
        let out = self.run(&["profile", "list", "--format", "json"], false)?;
        if out.exit_code != 0 {
            return Err(host_cli_error("profile list", &out));
        }
        let profiles: Vec<serde_json::Value> =
            serde_json::from_str(&out.stdout).map_err(|err| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("invalid default profile: {err}"),
                )
            })?;
        let devices = profiles
            .iter()
            .find(|profile| profile.get("name").and_then(|v| v.as_str()) == Some("default"))
            .and_then(|profile| profile.get("devices"))
            .and_then(|v| v.as_object());
        let root = devices.is_some_and(|devices| {
            devices.values().any(|device| {
                device.get("type").and_then(|v| v.as_str()) == Some("disk")
                    && device.get("path").and_then(|v| v.as_str()) == Some("/")
                    && device
                        .get("pool")
                        .and_then(|v| v.as_str())
                        .is_some_and(|v| !v.is_empty())
            })
        });
        let nic = devices.is_some_and(|devices| {
            devices.values().any(|device| {
                device.get("type").and_then(|v| v.as_str()) == Some("nic")
                    && ["network", "parent"].iter().any(|key| {
                        device
                            .get(key)
                            .and_then(|v| v.as_str())
                            .is_some_and(|v| !v.is_empty())
                    })
            })
        });
        if !root || !nic {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "initialize the Incus default profile with a root disk storage pool and network interface",
            ));
        }
        Ok(())
    }

    fn query_instance_by_name(&self, name: &str) -> Result<HostInstance, RuntimeError> {
        validate_managed_instance_name(name)?;
        let path = instance_query_url(name, &self.project)?;
        let envelope = self.query_raw(&path)?;
        parse_instance_metadata(&envelope, name)
    }

    /// Reject template properties named like unaudited launch configuration
    /// before allocating network resources. Incus copies ordinary properties
    /// into `image.*`; this conservative template policy supplements (never
    /// replaces) the effective instance-config fence at every start.
    pub(crate) fn verify_template_launch_config(
        &self,
        fingerprint: &str,
        vm_size: sandbox_protocol::VmSize,
    ) -> Result<(), RuntimeError> {
        let fingerprint = crate::normalize_incus_fingerprint(fingerprint)?;
        let metadata = self.query_raw(&image_query_url(&fingerprint[7..], &self.project)?)?;
        let properties = metadata
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "template image properties are not auditable; refusing allocation",
                )
            })?;
        for key in properties.keys() {
            if crate::image_validate::REFUSED_PROPERTY_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix))
                && !key.starts_with("user.flycockpit.")
                && key != "limits.cpu"
                && key != "limits.memory"
            {
                return Err(RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    format!(
                        "template image carries unaudited config property `{key}`; refusing allocation"
                    ),
                ));
            }
        }
        crate::resources::verify_vm_size(properties, vm_size, true)
    }

    /// Host-authoritative image metadata for operator refs and fingerprints.
    pub fn resolve_image_ref(
        &self,
        image_ref: &str,
    ) -> Result<crate::ResolvedHostImage, RuntimeError> {
        if !crate::is_incus_image_ref(image_ref) && !crate::is_incus_fingerprint(image_ref) {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                format!("`{image_ref}` is not a valid Incus image ref or fingerprint"),
            ));
        }
        let fingerprint = if crate::is_incus_fingerprint(image_ref) {
            crate::normalize_incus_fingerprint(image_ref)?
        } else {
            // A CLI qualifier never selects a remote daemon: registration is local.
            let alias = image_ref
                .split_once(':')
                .map_or(image_ref, |(_, alias)| alias);
            let path = with_query_params(
                &format!("/1.0/images/aliases/{}", percent_encode(alias)),
                &[("project", self.project.as_str())],
            );
            let metadata = self.query_raw(&path)?;
            crate::image::fingerprint_from_incus(
                metadata
                    .get("target")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        RuntimeError::new(
                            SandboxErrorCode::ProtocolError,
                            "alias has no fingerprint target",
                        )
                    })?,
            )?
        };
        let metadata = self.query_raw(&image_query_url(&fingerprint[7..], &self.project)?)?;
        let resolved = parse_image_metadata(&metadata, image_ref)?;
        if resolved.fingerprint != fingerprint
            || metadata.get("type").and_then(|v| v.as_str()) != Some("virtual-machine")
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "image inventory fingerprint or VM type differs",
            ));
        }
        Ok(resolved)
    }

    /// Record (or clear) the restore base the daemon bound for a sandbox.
    pub fn set_restore_base(&self, sandbox_id: &str, restore_base: Option<&str>) {
        let mut bases = self.restore_bases.lock().unwrap_or_else(|e| e.into_inner());
        match restore_base {
            Some(base) => {
                bases.insert(sandbox_id.to_owned(), base.to_owned());
            }
            None => {
                bases.remove(sandbox_id);
            }
        }
    }

    /// The identity a caller holding `fingerprint` (the template) binds
    /// `sandbox_id` with: the restore base comes from the daemon's lease
    /// record or dispatch, never from the instance.
    pub fn binding_identity(&self, sandbox_id: &str, fingerprint: &str) -> BindingIdentity {
        BindingIdentity {
            template_fingerprint: fingerprint.to_owned(),
            restore_base: self
                .restore_bases
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(sandbox_id)
                .cloned(),
        }
    }

    pub fn bind_instance(
        &self,
        name: &str,
        sandbox_id: &str,
        fingerprint: &str,
        create_key: Option<&str>,
    ) -> Result<BoundInstance, RuntimeError> {
        let identity = self.binding_identity(sandbox_id, fingerprint);
        self.bind_instance_as(name, sandbox_id, &identity, create_key)
    }

    /// [`Self::bind_instance`] with an explicit [`BindingIdentity`] (a
    /// restore's create binds the identity its request carries).
    pub fn bind_instance_as(
        &self,
        name: &str,
        sandbox_id: &str,
        identity: &BindingIdentity,
        create_key: Option<&str>,
    ) -> Result<BoundInstance, RuntimeError> {
        let fingerprint = identity.template_fingerprint.as_str();
        validate_managed_instance_name(name)?;
        let metadata = self.query_raw(&instance_query_url(name, &self.project)?)?;
        let config = metadata.get("config");
        let get = |key| config.and_then(|v| v.get(key)).and_then(|v| v.as_str());
        let (id_tag, key_tag, template_tag) = Self::metadata_keys();
        let template = get(template_tag).unwrap_or_default();
        let actual = get("volatile.base_image")
            .and_then(|raw| crate::image::fingerprint_from_incus(raw).ok());
        if metadata.get("type").and_then(|v| v.as_str()) != Some("virtual-machine")
            || crate::default_incus_instance_name(sandbox_id) != name
            || get(id_tag) != Some(sandbox_id)
            || !crate::is_incus_fingerprint(template)
            || !base_bound(
                actual.as_deref(),
                template,
                get(METADATA_RESTORE_BASE),
                identity.restore_base.as_deref(),
                false,
            )
            || fingerprint != template
            || create_key.is_some_and(|expected| get(key_tag) != Some(expected))
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "instance sandbox, template or base image binding differs",
            ));
        }
        Ok(BoundInstance {
            name: name.into(),
            sandbox_id: sandbox_id.into(),
            fingerprint: fingerprint.into(),
            create_key: create_key.map(str::to_owned),
            binary: self.binary.clone(),
            project: self.project.clone(),
            observed: parse_instance_metadata(&metadata, name)?,
        })
    }

    /// C37 R3: ownership-fenced binding for AUTONOMOUS cleanup (the
    /// enforcement-loss drain), where no caller-supplied identity exists.
    /// The fence is the managed name, the VM type, the sandbox-id tag, and
    /// the recorded template/base-image consistency — everything provable
    /// without a caller identity. A foreign or inconsistently labeled
    /// instance conflicts and is never touched by the drain.
    pub(crate) fn bind_owned_instance(
        &self,
        name: &str,
        sandbox_id: &str,
    ) -> Result<BoundInstance, RuntimeError> {
        validate_managed_instance_name(name)?;
        let metadata = self.query_raw(&instance_query_url(name, &self.project)?)?;
        let config = metadata.get("config");
        let get = |key| config.and_then(|v| v.get(key)).and_then(|v| v.as_str());
        let (id_tag, _key_tag, template_tag) = Self::metadata_keys();
        let template = get(template_tag).unwrap_or_default();
        let actual = get("volatile.base_image")
            .and_then(|raw| crate::image::fingerprint_from_incus(raw).ok());
        if metadata.get("type").and_then(|v| v.as_str()) != Some("virtual-machine")
            || crate::default_incus_instance_name(sandbox_id) != name
            || get(id_tag) != Some(sandbox_id)
            || !crate::is_incus_fingerprint(template)
            || !base_bound(
                actual.as_deref(),
                template,
                get(METADATA_RESTORE_BASE),
                None,
                true,
            )
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "instance ownership or image identity is not provable",
            ));
        }
        Ok(BoundInstance {
            name: name.into(),
            sandbox_id: sandbox_id.into(),
            fingerprint: template.into(),
            create_key: None,
            binary: self.binary.clone(),
            project: self.project.clone(),
            observed: parse_instance_metadata(&metadata, name)?,
        })
    }

    pub(super) fn check_request_binding(
        &self,
        bound: &BoundInstance,
        name: &str,
        sandbox_id: &str,
        fingerprint: &str,
    ) -> Result<(), RuntimeError> {
        if bound.name != name
            || bound.sandbox_id != sandbox_id
            || bound.fingerprint != fingerprint
            || bound.binary != self.binary
            || bound.project != self.project
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "request differs from bound instance",
            ));
        }
        Ok(())
    }

    pub(super) fn refresh_binding(
        &self,
        bound: &BoundInstance,
    ) -> Result<BoundInstance, RuntimeError> {
        if bound.binary != self.binary || bound.project != self.project {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "instance client binding differs",
            ));
        }
        self.bind_instance(
            bound.name(),
            &bound.sandbox_id,
            &bound.fingerprint,
            bound.create_key.as_deref(),
        )
    }

    pub fn query_instance(&self, bound: &BoundInstance) -> Result<HostInstance, RuntimeError> {
        Ok(self.refresh_binding(bound)?.observed)
    }

    pub(super) fn inventory_sandbox_id(&self, name: &str) -> Result<Option<String>, RuntimeError> {
        let metadata = self.query_raw(&instance_query_url(name, &self.project)?)?;
        Ok(metadata
            .get("config")
            .and_then(|v| v.get(METADATA_SANDBOX_ID))
            .and_then(|v| v.as_str())
            .map(str::to_owned))
    }

    /// A clone whose every host and guest call (binding refresh, queries,
    /// exec preparation) ends within `limit`: readiness bounds whole calls,
    /// not only their final command.
    pub(super) fn bounded(&self, limit: Duration) -> IncusClient {
        let mut bounded = self.clone();
        bounded.agent_timeout = limit.max(Duration::from_millis(1));
        bounded
    }

    /// The running VM's QEMU identity (R11, S7, C3), read outside any
    /// journal lock: the Incus pid p1, `/proc/p1/cmdline` (its `-name` must
    /// name this instance), `/proc/p1/stat` (field 22, `starttime`), then
    /// the Incus pid again; `None` unless both reads agree and every check
    /// passes, the safe direction. No `/proc/<pid>/ns/*` read: a non-root
    /// daemon cannot read incusd's QEMU namespaces.
    pub(crate) fn qemu_identity(&self, name: &str) -> Option<crate::QemuIdentity> {
        self.qemu_identity_inner(name, None)
    }

    /// [`Self::qemu_identity`] with both Incus reads inside one absolute
    /// `deadline`: the remaining budget is recomputed before each read, so
    /// the pair never takes longer than the caller's budget. An exhausted
    /// budget is `None`, the safe direction.
    pub(crate) fn qemu_identity_by(
        &self,
        name: &str,
        deadline: Instant,
    ) -> Option<crate::QemuIdentity> {
        self.qemu_identity_inner(name, Some(deadline))
    }

    fn qemu_identity_inner(
        &self,
        name: &str,
        deadline: Option<Instant>,
    ) -> Option<crate::QemuIdentity> {
        let read_pid = || -> Option<u64> {
            validate_managed_instance_name(name).ok()?;
            let path = instance_state_query_url(name, &self.project).ok()?;
            let timeout = match deadline {
                Some(deadline) => Some(deadline.saturating_duration_since(Instant::now()))
                    .filter(|left| !left.is_zero())?,
                None => self.host_call_timeout(),
            };
            let envelope = self.query_raw_timed(&path, timeout).ok()?;
            let state = parse_instance_state_metadata(&envelope, name).ok()?;
            state
                .is_running()
                .then_some(state.pid?)
                .filter(|pid| *pid > 0)
        };
        let pid = read_pid()?;
        let cmdline = std::fs::read(self.proc_root.join(pid.to_string()).join("cmdline")).ok()?;
        let stat = std::fs::read(self.proc_root.join(pid.to_string()).join("stat")).ok()?;
        if read_pid()? != pid || !qemu_cmdline_names(&cmdline, name, &self.project) {
            return None;
        }
        Some(crate::QemuIdentity {
            pid,
            start_ticks: proc_stat_starttime(&stat)?,
        })
    }

    pub fn query_instance_state(
        &self,
        bound: &BoundInstance,
    ) -> Result<HostInstanceState, RuntimeError> {
        self.query_instance_state_timed(bound, self.host_call_timeout())
    }

    /// B2-K-2: a read-only guest observation ended with no exact
    /// nonce-bound record. That is plane loss, not malformed guest output:
    /// re-observe the VM from the host (constant messages, never stderr). A
    /// stopped VM is `sandbox_not_running`; anything else is
    /// `unknown_outcome`.
    ///
    /// B2R2-C-2/B2R2-K-2: a running VM is never `guest_unavailable` here.
    /// The only agent signal in the state record is `processes`, which is the
    /// guest agent's own count (see [`HostInstanceState`]), and the server
    /// counts any FAILED `guest_unavailable` attempt as a possibly live
    /// sandbox (`hasPossiblyLiveSandboxAttempt`), so a read must not claim it.
    pub(super) fn observation_plane_failure(&self, bound: &BoundInstance) -> RuntimeError {
        match self.query_instance_state(bound) {
            Ok(state) if !state.is_running() => sandbox_not_running(bound.name()),
            _ => RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "guest observation did not complete",
            )
            .filesystem(sandbox_protocol::results::FailureEffect::None),
        }
    }

    fn query_instance_state_timed(
        &self,
        bound: &BoundInstance,
        timeout: Duration,
    ) -> Result<HostInstanceState, RuntimeError> {
        let name = bound.name();
        // The binding refresh shares the caller's bound (a readiness deadline
        // or the stopped settle window), never the full client timeout.
        self.bounded(timeout).refresh_binding(bound)?;
        validate_managed_instance_name(name)?;
        let path = instance_state_query_url(name, &self.project)?;
        let envelope = self.query_raw_timed(&path, timeout)?;
        parse_instance_state_metadata(&envelope, name)
    }

    pub fn instance_exists(&self, name: &str) -> Result<bool, RuntimeError> {
        match self.query_instance_by_name(name) {
            Ok(_) => Ok(true),
            Err(err) if err.code == SandboxErrorCode::SandboxNotFound => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub(super) fn instance_may_be_running(&self, name: &str) -> Result<bool, RuntimeError> {
        match self.query_instance_by_name(name) {
            Ok(instance) => Ok(!instance.is_stopped()),
            Err(err) if err.code == SandboxErrorCode::SandboxNotFound => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub fn config_get(
        &self,
        bound: &BoundInstance,
        key: &str,
    ) -> Result<Option<String>, RuntimeError> {
        let name = bound.name();
        self.refresh_binding(bound)?;
        validate_managed_instance_name(name)?;
        validate_config_pair(key, "")?;
        let out = self.run(&["config", "get", "--", name, key], false)?;
        if out.exit_code == 0 {
            let value = out.stdout.trim();
            return Ok(if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            });
        }
        Err(self.instance_cli_error(name, "config get", &out))
    }

    fn instance_cli_error(
        &self,
        name: &str,
        action: &str,
        out: &IncusCommandOutput,
    ) -> RuntimeError {
        match self.query_instance_by_name(name) {
            Err(err) => err,
            Ok(_) => host_cli_error(action, out),
        }
    }

    pub fn config_set(&self, bound: &BoundInstance, key: &str, value: &str) -> EffectOutcome<()> {
        let name = bound.name();
        pre::phase(
            |before| {
                pre::bound(&before, self, bound)?;
                pre::name(&before, name)?;
                pre::config(&before, key, value)?;

                before.issue(|| self.run_effect(&["config", "set", "--", name, key, value], false))
            },
            |issued| {
                let _ = issued;
                effect_completion::config(self, bound, key, value)
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn pause_create_for_test(&self, phase: &str) {
        if let Some((target, barrier)) = &self.create_barrier
            && *target == phase
        {
            barrier.wait();
            barrier.wait();
        }
    }

    pub(crate) fn create_vm(
        &self,
        request: &crate::CreateSandboxRequest,
        plan: &super::network::SandboxNetworkPlan,
    ) -> EffectOutcome<()> {
        request
            .lease
            .validate_now()
            .map_err(|message| RuntimeError::new(SandboxErrorCode::StateConflict, message))?;
        crate::resources::validate_vm_size(request.vm_size)?;
        let cpu = request.vm_size.cpu_count.to_string();
        let memory = format!("{}MiB", request.vm_size.memory_mi_b);
        let lease = serde_json::to_string(&request.lease)
            .map_err(|_| RuntimeError::new(SandboxErrorCode::ProtocolError, "invalid lease"))?;
        pre::phase(
            |before| {
                pre::guest(&before, &request.guest)?;
                let fingerprint = pre::launch_image(&before, request)?;
                let privilege = SpecPrivilege::of(request.guest_privilege);
                let root_disk_bytes = match (&request.restore, &self.expected_root) {
                    (None, Some(root)) => Some(root.size_bytes()),
                    _ => None,
                };
                let spec = serde_json::to_string(&ReadinessSpec {
                    guest: request.guest.clone(),
                    architecture: request.architecture.clone().unwrap_or_default(),
                    mode: request.readiness,
                    privilege,
                    root_disk_bytes,
                })
                .map_err(|_| {
                    RuntimeError::new(
                        SandboxErrorCode::ProtocolError,
                        "invalid readiness metadata",
                    )
                })?;
                let mut config: Vec<(&str, &str)> = vec![
                    (METADATA_SANDBOX_ID, &request.sandbox_id),
                    (METADATA_CREATE_IDEMPOTENCY, &request.idempotency_key),
                    (METADATA_TEMPLATE_DIGEST, &request.template_digest),
                    ("security.agent.metrics", "true"),
                    ("boot.autostart", "false"),
                    ("limits.cpu", &cpu),
                    ("limits.memory", &memory),
                    (METADATA_READINESS, &spec),
                    ("user.flycockpit.lease", &lease),
                ];
                // A restore tags its base image and pins the
                // stored copy's cloud-init instance id (no first boot rerun).
                if let Some(restore) = &request.restore {
                    config.push((METADATA_RESTORE_BASE, &fingerprint));
                    if let Some(id) = restore.cloud_init_instance_id.as_deref() {
                        config.push(("volatile.cloud-init.instance-id", id));
                    }
                }
                let identity = BindingIdentity {
                    template_fingerprint: request.template_digest.clone(),
                    restore_base: request.restore.as_ref().map(|_| fingerprint.clone()),
                };
                before.issue(|| {
                    self.init_vm(
                        &fingerprint,
                        &request.instance_name,
                        plan,
                        request.vm_size,
                        &identity,
                        &config,
                    )
                })
            },
            Ok,
        )
    }

    fn init_vm(
        &self,
        image: &str,
        name: &str,
        plan: &super::network::SandboxNetworkPlan,
        vm_size: sandbox_protocol::VmSize,
        identity: &BindingIdentity,
        config: &[(&str, &str)],
    ) -> EffectOutcome<()> {
        pre::phase(
            |before| {
                pre::name(&before, name)?;
                let image = pre::image(&before, Some(image), "")?;
                // Explicitly select the audited profile: without this, an
                // image can nominate its own profile list and smuggle in
                // devices the launch preflight rejected on `default`.
                let mut args = vec![
                    "init".to_string(),
                    "--vm".to_string(),
                    "--profile".to_string(),
                    "default".to_string(),
                ];
                for (key, value) in config {
                    pre::config(&before, key, value)?;
                    args.extend(["-c".to_string(), format!("{key}={value}")]);
                }
                if let Some(root) = &self.expected_root {
                    // Closed root keys make this merge auditable. Select the
                    // final pool before init; never create then move a disk.
                    let (root_name, _) = self.profile_root_device(vm_size)?;
                    pre::storage_pool(&before, self, &root.pool)?;
                    args.extend([
                        "--storage".into(),
                        root.pool.name.clone(),
                        "--device".into(),
                        format!("{root_name},size={}GiB", root.disk_gi_b),
                    ]);
                }
                // The NIC is a COMPLETE local shadow after init. Never use
                // --device for eth0, whose inherited keys could survive merge.
                args.extend(["--".into(), image[7..].into(), name.into()]);

                before.issue(|| {
                    self.run_timed_effect(
                        &args,
                        false,
                        self.agent_timeout.max(Duration::from_secs(600)),
                    )
                })
            },
            |issued| {
                if issued.exit_code != 0 {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::UnknownOutcome,
                        "init CLI did not complete successfully",
                    )
                    .filesystem(sandbox_protocol::results::FailureEffect::Unknown)
                    .into());
                }
                // Init has completed positively. Finish the stopped disk's
                // binding/NIC configuration even after Stop revoked boot.
                // This scope retains the original deadline and cannot start
                // a guest; launch below uses the original revoked permit.
                let mut settling = self.clone();
                if self.settle_create {
                    settling.cancelled = self
                        .cancelled
                        .as_ref()
                        .map(|permit| std::sync::Arc::new(permit.settlement()));
                }
                let expected = |key| {
                    config
                        .iter()
                        .find(|(k, _)| *k == key)
                        .map(|(_, v)| *v)
                        .unwrap_or_default()
                };
                let bound = settling.bind_instance_as(
                    name,
                    expected(METADATA_SANDBOX_ID),
                    identity,
                    Some(expected(METADATA_CREATE_IDEMPOTENCY)),
                )?;
                settling.verify_expected_root(name)?;
                for (key, value) in config {
                    effect_completion::config(&settling, &bound, key, value)?;
                }
                // Install the COMPLETE audited NIC as a local device on the
                // still-stopped VM: a local eth0 shadows the profile's device
                // wholesale (unlike init --device's merge or `override`), so
                // no inherited property can survive (R22-F2, same fix class
                // as the R20 repair path).
                let mut args: Vec<String> = vec![
                    "config".to_string(),
                    "device".to_string(),
                    "add".to_string(),
                    name.to_string(),
                    "eth0".to_string(),
                    "nic".to_string(),
                ];
                args.extend(plan.nic_device_args());
                let out = settling.run(&args, false)?;
                if out.exit_code != 0 {
                    return Err(host_cli_error("config device add", &out).into());
                }
                // Prove the effective devices before first start: exactly the
                // root disk plus the pinned sandbox-bridge NIC, regardless of
                // what the image or profiles asked for.
                settling.verify_instance_devices(name, plan)?;
                // Image unpack may consume most of an initial DNS lease.
                // Renew aging grants before the verified start, using the
                // same half-life threshold as the background scheduler.
                if !plan.policy_domains.is_empty() {
                    let policy = sandbox_protocol::EgressPolicy {
                        mode: sandbox_protocol::EgressMode::Allowlist,
                        domains: plan.policy_domains.clone(),
                        cidrs: plan.policy_cidrs.clone(),
                    };
                    let hash = plan.policy_hash.as_deref().ok_or_else(|| {
                        RuntimeError::new(
                            SandboxErrorCode::Internal,
                            "missing recorded egress policy",
                        )
                    })?;
                    let state = settling.load_dns_state(&plan.sandbox_id, hash);
                    if super::dns_refresh::refresh_due(
                        &plan.policy_domains,
                        state.as_ref(),
                        None,
                        settling.dns_clock.unix_now()?,
                    )
                    .is_some()
                    {
                        settling.refresh_dns_policy_locked(
                            &plan.sandbox_id,
                            &policy,
                            hash,
                            Duration::from_secs(30),
                            &|domain, limits| {
                                super::dns::resolve_policy_name_system(
                                    &settling,
                                    &plan.sandbox_id,
                                    domain,
                                    limits,
                                )
                            },
                        )?;
                    }
                }
                // Init leaves the VM stopped, even if its daemon operation
                // outlives a cancelled CLI. Start rechecks the revoked permit
                // and re-verifies the recorded network policy (C37 fence);
                // the launch-config audit runs at that same start boundary
                // (C37 R1), so retries and reconnects cannot skip it.
                #[cfg(test)]
                self.pause_create_for_test("before_start");
                // Start/readiness retain prompt revocation; only init/config
                // effects already issued above must finish before teardown.
                let mut launch = self.clone();
                launch.settle_create = false;
                launch
                    .start_bound(&bound, vm_size)
                    .map_err(crate::effect::PostIssueError::from_final_start)
            },
        )
    }

    /// Direct start always supplies an immutable original-root binding.
    pub fn start(
        &self,
        bound: &BoundInstance,
        vm_size: sandbox_protocol::VmSize,
        root: &crate::RootDisk,
    ) -> EffectOutcome<()> {
        self.with_root_disk(root)?.start_bound(bound, vm_size)
    }
    pub(super) fn start_bound(
        &self,
        bound: &BoundInstance,
        vm_size: sandbox_protocol::VmSize,
    ) -> EffectOutcome<()> {
        crate::resources::validate_vm_size(vm_size)?;
        let name = bound.name();
        pre::phase(
            |before| {
                // One wssp daemon per Incus server: no VM start of any kind
                // while another daemon's marker is live, checked here at
                // the start itself (not only at the operation's entry).
                crate::guard_probe::refuse_shared_incus_server(self.guard_probe.as_ref())?;
                pre::bound(&before, self, bound)?;
                pre::name(&before, name)?;
                // C37 R1: the launch-config audit runs at THIS boundary on
                // every start — an instance whose effective config carries
                // template/profile-injected keys is refused whether the
                // start comes from a fresh create, an existing-instance
                // retry, a reconnect resume, or a direct call.
                pre::launch_config(&before, self, name, vm_size)?;
                // C37: start is a verified-policy-only transition. The
                // readback against the persisted recorded policy runs
                // pre-issue on EVERY start, so no runtime entry point
                // (create, adoption, reconnect, or a direct call) can resume
                // an instance whose bridge/ACL/DNS enforcement is lost,
                // modified, or unverifiable.
                pre::verified_enforcement(&before, self, name)?;

                self.config_set(bound, "boot.autostart", "false")?;
                // And again after all configuration I/O, right before the
                // start: a conflict published while it ran refuses it.
                crate::guard_probe::refuse_shared_incus_server(self.guard_probe.as_ref())?;
                before.issue(|| self.run_effect(&["start", name], false))
            },
            |issued| effect_completion::running(self, bound, Some(&issued)),
        )
    }

    /// Close and reap every terminal of the bound sandbox (C51). Called
    /// AFTER each VM stop/delete effect, whatever its outcome, and never
    /// before it: the effect runs first on the caller's full runtime-permit
    /// budget, so no number of terminals can delay or preempt a stop/delete.
    /// An open reserves its session before binding, so it is either closed
    /// (or doomed) here or observes the stopped/absent VM. The intent is
    /// truthful: `confirmed` when the effect's outcome was confirmed,
    /// otherwise `LifecycleUnconfirmed` (closed conservatively).
    fn close_sandbox_terminals<T>(
        &self,
        bound: &BoundInstance,
        outcome: &EffectOutcome<T>,
        confirmed: crate::PtyCloseIntent,
    ) {
        let intent = match outcome {
            Ok(_) => confirmed,
            Err(_) => crate::PtyCloseIntent::LifecycleUnconfirmed,
        };
        self.pty_sessions
            .close_matching(Some(&bound.sandbox_id), intent);
    }

    pub fn stop_force(
        &self,
        bound: &BoundInstance,
    ) -> EffectOutcome<sandbox_protocol::SandboxLifecycleState> {
        let _priority = self.request_lifecycle_priority(&bound.sandbox_id);
        let outcome = self.stop_force_effect(bound);
        self.close_sandbox_terminals(bound, &outcome, crate::PtyCloseIntent::SandboxStopped);
        outcome
    }

    fn stop_force_effect(
        &self,
        bound: &BoundInstance,
    ) -> EffectOutcome<sandbox_protocol::SandboxLifecycleState> {
        let name = bound.name();
        pre::phase(
            |before| {
                pre::bound(&before, self, bound)?;
                pre::name(&before, name)?;

                before.issue(|| self.run_effect(&["stop", name, "--force"], false))
            },
            |issued| {
                let _ = issued;
                effect_completion::stopped_or_absent(self, bound)
            },
        )
    }

    /// Graceful stop (C55): `incus stop <name> --timeout <secs>` asks the
    /// guest to shut down and never forces; Incus fails the call when the
    /// guest is still running at the timeout. Completion is observed, exactly
    /// like the forced stop. The process wait is bounded a little past the
    /// guest timeout, and the caller's permit still bounds the whole call.
    pub fn stop_graceful(
        &self,
        bound: &BoundInstance,
        timeout: Duration,
    ) -> EffectOutcome<sandbox_protocol::SandboxLifecycleState> {
        let _priority = self.request_lifecycle_priority(&bound.sandbox_id);
        let outcome = self.stop_graceful_effect(bound, timeout);
        self.close_sandbox_terminals(bound, &outcome, crate::PtyCloseIntent::SandboxStopped);
        outcome
    }

    fn stop_graceful_effect(
        &self,
        bound: &BoundInstance,
        timeout: Duration,
    ) -> EffectOutcome<sandbox_protocol::SandboxLifecycleState> {
        let name = bound.name();
        let secs = timeout.as_secs().max(1);
        pre::phase(
            |before| {
                pre::bound(&before, self, bound)?;
                pre::name(&before, name)?;

                before.issue(|| {
                    self.run_timed_effect(
                        &["stop", name, "--timeout", &secs.to_string()],
                        false,
                        Duration::from_secs(secs + GRACEFUL_STOP_SLACK_SECS),
                    )
                })
            },
            |issued| {
                let _ = issued;
                effect_completion::stopped_or_absent(self, bound)
            },
        )
    }

    pub fn delete_force(&self, bound: &BoundInstance) -> EffectOutcome<()> {
        let _priority = self.request_lifecycle_priority(&bound.sandbox_id);
        let outcome = self.delete_force_effect(bound);
        self.close_sandbox_terminals(bound, &outcome, crate::PtyCloseIntent::SandboxDestroyed);
        outcome
    }

    fn delete_force_effect(&self, bound: &BoundInstance) -> EffectOutcome<()> {
        let name = bound.name();
        pre::phase(
            |before| {
                pre::bound(&before, self, bound)?;
                pre::name(&before, name)?;
                if let Some(root) = &self.expected_root {
                    pre::storage_pool(&before, self, &root.pool)?;
                }

                before.issue(|| {
                    let issued = self.run_effect(&["delete", name, "--force"], false);
                    match effect_completion::absent(self, name) {
                        Ok(proof) => Ok(proof),
                        Err(observation) => Err(issued.err().unwrap_or_else(|| observation.into())),
                    }
                })
            },
            |proof| {
                if let Some(root) = &self.expected_root {
                    self.prove_root_absent(root, name)?;
                }
                Ok(proof)
            },
        )
    }

    pub fn exec_argv(
        &self,
        bound: &BoundInstance,
        argv: &[String],
    ) -> Result<IncusCommandOutput, RuntimeError> {
        self.exec_argv_opts(bound, argv, None, None)
    }

    pub fn exec_argv_opts(
        &self,
        bound: &BoundInstance,
        argv: &[String],
        cwd: Option<&str>,
        timeout: Option<Duration>,
    ) -> Result<IncusCommandOutput, RuntimeError> {
        self.exec_argv_effect(bound, argv, cwd, timeout)
            .map_err(EffectError::into_error)
    }

    pub(super) fn exec_argv_effect(
        &self,
        bound: &BoundInstance,
        argv: &[String],
        cwd: Option<&str>,
        timeout: Option<Duration>,
    ) -> EffectResult<IncusCommandOutput> {
        self.exec_argv_effect_with_limit(bound, argv, cwd, timeout, None, false)
    }

    pub(super) fn exec_argv_effect_bounded(
        &self,
        bound: &BoundInstance,
        argv: &[String],
        timeout: Duration,
    ) -> EffectResult<IncusCommandOutput> {
        self.exec_argv_effect_with_limit(bound, argv, None, Some(timeout), Some(512), false)
    }

    /// The retire helper's runner. Exactly like
    /// [`Self::exec_argv_effect_bounded`] (bound, permit-fenced, captured and
    /// bounded output), but as guest root with `--user 0 --group 0 --cwd /`
    /// and no guest env. Not `with_root_exec` (D1 build steps only).
    pub(super) fn exec_root_helper_bounded(
        &self,
        bound: &BoundInstance,
        argv: &[String],
        timeout: Duration,
    ) -> EffectResult<IncusCommandOutput> {
        self.exec_argv_effect_with_limit(bound, argv, None, Some(timeout), Some(512), true)
    }

    fn exec_argv_effect_with_limit(
        &self,
        bound: &BoundInstance,
        argv: &[String],
        cwd: Option<&str>,
        timeout: Option<Duration>,
        output_limit: Option<usize>,
        root_helper: bool,
    ) -> EffectResult<IncusCommandOutput> {
        let name = bound.name();
        pre::phase(
            |before| {
                pre::bound(&before, self, bound)?;
                pre::name(&before, name)?;
                pre::guest(&before, &self.guest)?;
                if argv.is_empty() {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::ProtocolError,
                        "exec requires at least one argv entry",
                    )
                    .into());
                }
                if let Some(cwd) = cwd {
                    pre::path(&before, cwd, false)?;
                }
                let mut args = vec!["exec".to_string(), name.to_string(), "-T".to_string()];
                if root_helper {
                    // The declared identity still validates (as for every exec).
                    self.guest.validate()?;
                    args.extend(["--user", "0", "--group", "0", "--cwd", "/"].map(String::from));
                } else {
                    args.extend(self.guest_exec_args(cwd)?);
                }
                args.push("--".to_string());
                args.extend(argv.iter().cloned());

                before.issue(|| {
                    validate_incus_identifier(&self.project, "project")?;
                    let mut command = crate::host_child::command(
                        &self.binary,
                        crate::host_child::Environment::Incus,
                    );
                    command.args(["--project", &self.project]).args(&args);
                    // Never the daemon's stdin (C55-TB-1): an own-group helper
                    // reading an interactive TTY would stop on SIGTTIN, and
                    // `incus exec` would forward the operator's input.
                    command
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped());
                    pre::phase(
                        |before| before.issue(|| self.spawn_guest(bound, &mut command)),
                        |child| {
                            wait_process_with_limit(
                                child,
                                timeout.unwrap_or_else(|| self.host_call_timeout()),
                                self.host_permit(),
                                output_limit,
                            )
                            .map_err(crate::effect::PostIssueError::Unknown)
                        },
                    )
                    .map(map_output)
                })
            },
            Ok,
        )
    }

    pub fn kill_process_group(pid: u32) -> Result<(), RuntimeError> {
        Self::kill_process_group_cancellable(pid, None)
    }

    pub(super) fn kill_process_group_cancellable(
        pid: u32,
        permit: Option<&crate::RuntimePermit>,
    ) -> Result<(), RuntimeError> {
        let Some(group) = host_group_kill_arg(pid, own_process_group()) else {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("refusing to signal process group {pid}"),
            ));
        };
        let mut command =
            crate::host_child::command("kill", crate::host_child::Environment::PathOnly);
        command
            .args(["-KILL", "--", &group])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Ordinary tracked signals use their caller's permit; cleanup of an
        // already-owned local child uses None. Never hold a permit while waiting.
        let status = run_process_cancellable(command, Duration::from_secs(5), permit)
            .map_err(EffectError::into_error)?
            .status;
        if !status.success() && status.code() != Some(1) {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("kill -KILL {pid} failed with {status}"),
            ));
        }
        Ok(())
    }

    pub(super) fn verify_guest(
        &self,
        bound: &BoundInstance,
        architecture: Option<&str>,
    ) -> Result<(), RuntimeError> {
        self.verify_guest_identity(bound, architecture, true)
    }

    /// Readiness of the declared guest, per `mode`: `Standard` runs the
    /// identity script; `BuildBootstrap` (a raw upstream image that does not
    /// carry the declared identity yet) checks only the binding and the
    /// architecture, then the boot settle as the declared uid.
    pub(super) fn verify_guest_mode(
        &self,
        bound: &BoundInstance,
        architecture: Option<&str>,
        mode: crate::ReadinessMode,
    ) -> Result<(), RuntimeError> {
        match mode {
            crate::ReadinessMode::Standard => self.verify_guest(bound, architecture),
            crate::ReadinessMode::BuildBootstrap => {
                self.verify_guest_architecture(bound, architecture)?;
                match self.guest_boot_settle(bound, self.agent_timeout)? {
                    BootSettle::Settled => Ok(()),
                    BootSettle::Unsettled => Err(boot_unsettled()),
                }
            }
        }
    }

    /// The binding refresh and the architecture compare, nothing of the
    /// declared identity (bootstrap readiness, and the first half of every
    /// identity check).
    pub(super) fn verify_guest_architecture<'a>(
        &self,
        bound: &BoundInstance,
        architecture: Option<&'a str>,
    ) -> Result<&'a str, RuntimeError> {
        let name = bound.name();
        self.refresh_binding(bound)?;
        self.guest.validate()?;
        let architecture = architecture
            .filter(|a| !a.is_empty() && a.len() <= 64)
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::GuestUnavailable,
                    "missing or unsupported template architecture",
                )
                .with_readiness_reason(ReadinessFailureReason::Architecture)
            })?;
        let metadata = self.query_raw(&instance_query_url(name, &self.project)?)?;
        if metadata.get("architecture").and_then(|v| v.as_str()) != Some(architecture) {
            return Err(RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                "instance architecture differs from template",
            )
            .with_readiness_reason(ReadinessFailureReason::Architecture));
        }
        Ok(architecture)
    }

    /// Boot settle (bootstrap readiness): `systemctl is-system-running
    /// --wait` as the declared uid (never root), cwd `/`, bounded by `cap`.
    /// Exactly `running` or `degraded` (exit 0 or 1) is settled; any other
    /// answer, or an agent that went away mid-call (a restart), is
    /// `Unsettled`, which the readiness loop re-passes under its restart
    /// bound. Only the constant verdict is kept, never guest text.
    pub(super) fn guest_boot_settle(
        &self,
        bound: &BoundInstance,
        cap: Duration,
    ) -> Result<BootSettle, RuntimeError> {
        if self.exec_as_root {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "the boot settle never runs as guest root",
            ));
        }
        // Early in a boot the system bus may not be up yet: a non-root
        // `systemctl` then fails at once with no state. That is not a restart,
        // so it is retried within the cap (live 26.04 receipt); only an agent
        // that went away, or the cap, ends the pass as `Unsettled`.
        let deadline = Instant::now() + cap;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(BootSettle::Unsettled);
            }
            let out = self.bounded(remaining).exec_argv_effect_with_limit(
                bound,
                &GUEST_SETTLE_ARGV.map(String::from),
                Some("/"),
                Some(remaining),
                Some(256),
                false,
            );
            match out {
                Ok(out)
                    if matches!(out.exit_code, 0 | 1)
                        && matches!(out.stdout.as_str(), "running\n" | "degraded\n") =>
                {
                    return Ok(BootSettle::Settled);
                }
                // `systemctl` itself answered (exit 0/1) without a settled
                // state: retry. Any other exit (the exec was killed, the
                // agent went away under a reboot) re-passes and lets the
                // restart validation decide.
                Ok(out) if matches!(out.exit_code, 0 | 1) => {
                    let pause =
                        BOOT_SETTLE_RETRY.min(deadline.saturating_duration_since(Instant::now()));
                    if pause.is_zero() {
                        return Ok(BootSettle::Unsettled);
                    }
                    self.wait_readiness_poll(pause)?;
                }
                Ok(_) => return Ok(BootSettle::Unsettled),
                Err(error) => {
                    let error = error.into_error();
                    return if matches!(
                        error.code,
                        SandboxErrorCode::Timeout | SandboxErrorCode::SandboxNotRunning
                    ) {
                        Ok(BootSettle::Unsettled)
                    } else {
                        Err(error)
                    };
                }
            }
        }
    }

    pub(super) fn verify_guest_identity(
        &self,
        bound: &BoundInstance,
        architecture: Option<&str>,
        require_repo: bool,
    ) -> Result<(), RuntimeError> {
        let architecture = self.verify_guest_architecture(bound, architecture)?;
        let nonce = random_nonce()?;
        let out = self.exec_argv_opts(
            bound,
            &[
                "/bin/sh".into(),
                "-c".into(),
                GUEST_READY_SCRIPT.into(),
                "wssp-readiness".into(),
                nonce.clone(),
                self.guest.guest_uid.to_string(),
                self.guest.guest_gid.to_string(),
                architecture.into(),
                if require_repo { "required" } else { "optional" }.into(),
            ],
            // `/`, not HOME: the script itself reports an unusable HOME.
            Some("/"),
            Some(self.agent_timeout),
        )?;
        if out.exit_code != 0 || out.stdout != format!("WSSP_READY {nonce}\n") {
            return Err(RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                "declared guest user, HOME, shell, architecture or tooling unavailable",
            )
            .with_readiness_reason(readiness_script_reason(&out.stdout, &nonce)));
        }
        Ok(())
    }

    /// Best effort: `None` whenever the probe gives no exact record.
    pub(super) fn probe_guest_linger(&self, bound: &BoundInstance) -> Option<crate::GuestLinger> {
        let nonce = random_nonce().ok()?;
        let out = self
            .exec_argv_effect_bounded(
                bound,
                &[
                    "/bin/sh".into(),
                    "-c".into(),
                    GUEST_LINGER_SCRIPT.into(),
                    "wssp-linger".into(),
                    nonce.clone(),
                ],
                Duration::from_secs(10),
            )
            .ok()?;
        if out.exit_code != 0 {
            return None;
        }
        match out
            .stdout
            .strip_prefix(&format!("WSSP_LINGER {nonce} "))?
            .strip_suffix('\n')?
        {
            "blocked" => Some(crate::GuestLinger::Blocked),
            "allowed" => Some(crate::GuestLinger::Allowed),
            "enabled" => Some(crate::GuestLinger::Enabled),
            _ => None,
        }
    }

    /// The guest has an IPv4 default route (its DHCP lease), or the typed
    /// `guest_network_unavailable` once [`GUEST_NETWORK_TRIES`] seconds pass.
    /// `cap` bounds the whole check (the readiness pass's remaining budget).
    pub(super) fn verify_guest_network(
        &self,
        bound: &BoundInstance,
        cap: Duration,
    ) -> Result<(), RuntimeError> {
        let nonce = random_nonce()?;
        let out = self.exec_argv_opts(
            bound,
            &[
                "/bin/sh".into(),
                "-c".into(),
                GUEST_NETWORK_SCRIPT.into(),
                "wssp-network".into(),
                nonce.clone(),
                "/proc/net/route".into(),
                GUEST_NETWORK_TRIES.to_string(),
            ],
            Some("/"),
            Some(
                (self.agent_timeout + Duration::from_secs(u64::from(GUEST_NETWORK_TRIES))).min(cap),
            ),
        )?;
        if out.exit_code != 0 || out.stdout != format!("WSSP_NET {nonce}\n") {
            return Err(RuntimeError::new(
                SandboxErrorCode::GuestNetworkUnavailable,
                format!(
                    "guest_network_unavailable: the guest has no IPv4 default route after {GUEST_NETWORK_TRIES} s \
                     (no DHCP lease); a host firewall dropping `wsn-*` traffic is the usual cause, \
                     see `wssp guard status`"
                ),
            ));
        }
        Ok(())
    }

    pub(super) fn persisted_readiness(
        &self,
        bound: &BoundInstance,
    ) -> Result<ReadinessSpec, RuntimeError> {
        let name = bound.name();
        self.refresh_binding(bound)?;
        let metadata = self.query_raw(&instance_query_url(name, &self.project)?)?;
        let spec = metadata
            .get("config")
            .and_then(|v| v.get(METADATA_READINESS))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::GuestUnavailable,
                    "instance readiness metadata missing",
                )
            })?;
        serde_json::from_str(spec).map_err(|_| {
            RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                "invalid readiness metadata",
            )
        })
    }

    pub fn wait_for_agent(&self, bound: &BoundInstance) -> Result<(), RuntimeError> {
        self.wait_for_agent_inner(bound, false, &mut self.agent_wait())
    }

    /// A fresh readiness pass: one agent budget for all of its waits.
    pub(super) fn agent_wait(&self) -> AgentWait {
        AgentWait::new(self.agent_timeout, self.reboot_settle)
    }

    /// The readiness pass of `mode`. A community prep build VM is the first
    /// boot of a raw upstream image (cloud-init first run, one reboot, the
    /// boot settle) and gets at least [`BOOTSTRAP_AGENT_TIMEOUT`]: prod
    /// 26.04 builds took 157 s and failed `agent_timeout` at 205 s under the
    /// standard 120 s budget.
    pub(super) fn readiness_wait(&self, mode: crate::ReadinessMode) -> AgentWait {
        match mode {
            crate::ReadinessMode::BuildBootstrap => AgentWait::new(
                self.agent_timeout.max(BOOTSTRAP_AGENT_TIMEOUT),
                self.reboot_settle,
            ),
            crate::ReadinessMode::Standard => self.agent_wait(),
        }
    }

    pub(super) fn wait_for_agent_fenced(
        &self,
        bound: &BoundInstance,
        wait: &mut AgentWait,
    ) -> Result<(), RuntimeError> {
        self.wait_for_agent_inner(bound, true, wait)
    }

    fn wait_readiness_poll(&self, duration: Duration) -> Result<(), RuntimeError> {
        if let Some(permit) = &self.cancelled {
            permit.wait_for(duration)
        } else {
            thread::sleep(duration);
            Ok(())
        }
    }

    /// The guest kernel's boot id, read through the agent as the guest user
    /// (`/proc/sys/kernel/random/boot_id` is kernel-generated and read-only).
    /// `None` when it gives no exact record; the budget spent is
    /// `agent_timeout`.
    pub(super) fn guest_boot_id(
        &self,
        bound: &BoundInstance,
        wait: &AgentWait,
    ) -> Result<Option<String>, RuntimeError> {
        let remaining = wait.remaining();
        if remaining.is_zero() {
            return Err(wait.deadline_error(bound.name()));
        }
        let nonce = random_nonce()?;
        // cwd `/`: like every readiness exec, independent of HOME access.
        let out = self.bounded(remaining).exec_argv_effect_with_limit(
            bound,
            &[
                "/bin/sh".into(),
                "-c".into(),
                super::kvm::GUEST_BOOT_ID_SCRIPT.into(),
                "wssp-boot".into(),
                nonce.clone(),
            ],
            Some("/"),
            Some(remaining.min(Duration::from_secs(10))),
            Some(512),
            false,
        );
        match out {
            // A record that arrived after the deadline is not accepted.
            _ if wait.remaining().is_zero() => Err(wait.deadline_error(bound.name())),
            Ok(out) if out.exit_code == 0 => Ok(super::frames::parse_boot_record(
                &nonce,
                &out.stdout,
                &out.stderr,
            )),
            _ => Ok(None),
        }
    }

    /// Record the boot a readiness pass starts in (right after its agent wait).
    pub(super) fn record_pass_boot(
        &self,
        bound: &BoundInstance,
        wait: &mut AgentWait,
    ) -> Result<(), RuntimeError> {
        wait.boot = self.guest_boot_id(bound, wait)?;
        Ok(())
    }

    /// After a readiness pass, before its result is used: did the guest
    /// restart since its agent answered? Incus can reset a guest inside the
    /// SAME QEMU process (state stays Running, pid unchanged), so the signals
    /// are: the host state left Running, a new QEMU pid, or a new guest
    /// kernel boot id. Any non-Running observation invalidates the pass: a
    /// reboot phase (Error included) is a restart, any other state (Frozen, ...) is
    /// `vm_not_running`. An unreadable boot id (or host state) is
    /// `Unobserved`, never Stable. The budget spent before the observation
    /// is `agent_timeout`.
    pub(super) fn validate_pass(
        &self,
        bound: &BoundInstance,
        wait: &mut AgentWait,
    ) -> Result<PassValidation, RuntimeError> {
        let name = bound.name();
        let remaining = wait.remaining();
        if remaining.is_zero() {
            return Err(wait.deadline_error(name));
        }
        let state =
            match self.query_instance_state_timed(bound, remaining.min(self.host_call_timeout())) {
                Ok(state) => state,
                Err(_) if wait.remaining().is_zero() => return Err(wait.deadline_error(name)),
                Err(_) => return Ok(PassValidation::Unobserved),
            };
        if !state.is_running() {
            if !state.is_reboot_phase() {
                return Err(vm_not_running(
                    name,
                    NotRunningPath::ValidatePass,
                    Some(&state),
                    wait,
                ));
            }
            wait.restarted(name)?;
            wait.pid = None;
            wait.boot = None;
            wait.down_counted = true;
            return Ok(PassValidation::Restarted);
        }
        wait.last_running = Some(Instant::now());
        let pid_changed = matches!((wait.pid, state.pid), (Some(known), Some(pid)) if known != pid);
        if state.pid.is_some() {
            wait.pid = state.pid;
        }
        let boot = self.guest_boot_id(bound, wait)?;
        let boot_changed =
            matches!((&wait.boot, &boot), (Some(known), Some(boot)) if known != boot);
        if pid_changed || boot_changed {
            wait.restarted(name)?;
            wait.boot = None;
            return Ok(PassValidation::Restarted);
        }
        if wait.boot.is_none() || boot.is_none() {
            wait.boot = None;
            return Ok(PassValidation::Unobserved);
        }
        // Stable only inside the budget.
        if wait.remaining().is_zero() {
            return Err(wait.deadline_error(name));
        }
        Ok(PassValidation::Stable)
    }

    fn wait_for_agent_inner(
        &self,
        bound: &BoundInstance,
        fenced: bool,
        wait: &mut AgentWait,
    ) -> Result<(), RuntimeError> {
        let name = bound.name();
        let budget = wait.budget;
        // While the VM is out of Running after it was seen Running: since when.
        let mut down_since: Option<Instant> = None;
        // The last host state read (diagnostics of a `vm_not_running`).
        let mut last_state: Option<HostInstanceState> = None;
        loop {
            self.wait_readiness_poll(Duration::ZERO)?;
            let remaining = wait.remaining();
            if remaining.is_zero() {
                return Err(readiness_deadline_error(
                    name,
                    budget,
                    wait.saw_running_or_starting,
                ));
            }
            // Once the VM went down, every query and poll is also bounded by
            // the settle window: a stalled query never outlives it.
            let down_left = down_since.map(|since| wait.settle.saturating_sub(since.elapsed()));
            if down_left.is_some_and(|left| left.is_zero()) {
                return Err(vm_not_running(
                    name,
                    NotRunningPath::Settle,
                    last_state.as_ref(),
                    wait,
                ));
            }
            let call_timeout = remaining
                .min(self.host_call_timeout())
                .min(down_left.unwrap_or(Duration::MAX));
            let state = match self.query_instance_state_timed(bound, call_timeout) {
                Ok(state) => state,
                Err(err) if err.code == SandboxErrorCode::Timeout => {
                    let down_left =
                        down_since.map(|since| wait.settle.saturating_sub(since.elapsed()));
                    if down_left.is_some_and(|left| left.is_zero()) {
                        return Err(vm_not_running(
                            name,
                            NotRunningPath::Settle,
                            last_state.as_ref(),
                            wait,
                        ));
                    }
                    let remaining = wait.remaining();
                    if remaining.is_zero() {
                        return Err(readiness_deadline_error(
                            name,
                            budget,
                            wait.saw_running_or_starting,
                        ));
                    }
                    self.wait_readiness_poll(
                        remaining
                            .min(READINESS_POLL)
                            .min(down_left.unwrap_or(Duration::MAX)),
                    )?;
                    continue;
                }
                Err(err) => return Err(err),
            };
            last_state = Some(state.clone());
            if !state.is_running() {
                // Before the VM was ever seen Running, Stopped is a stopped VM
                // (the previous behaviour). After it, a reboot phase is a
                // guest restart: keep waiting, bounded by REBOOT_SETTLE, the
                // restart count and the budget. A non-boot state always fails.
                let tolerated =
                    state.is_starting() || (wait.saw_running && state.is_reboot_phase());
                if !tolerated {
                    let path = if wait.saw_running {
                        NotRunningPath::AgentWait
                    } else {
                        NotRunningPath::PreRunStop
                    };
                    return Err(vm_not_running(name, path, Some(&state), wait));
                }
                if wait.saw_running {
                    let since = match down_since {
                        Some(since) => since,
                        None => {
                            if !std::mem::take(&mut wait.down_counted) {
                                wait.restarted(name)?;
                            }
                            wait.pid = None;
                            *down_since.insert(Instant::now())
                        }
                    };
                    if since.elapsed() >= wait.settle {
                        return Err(vm_not_running(
                            name,
                            NotRunningPath::Settle,
                            Some(&state),
                            wait,
                        ));
                    }
                }
            }
            wait.saw_running_or_starting = true;
            if state.is_running() {
                wait.last_running = Some(Instant::now());
                wait.down_counted = false;
                if down_since.take().is_none() {
                    wait.observe_pid(name, &state)?;
                } else {
                    wait.pid = state.pid;
                }
                wait.saw_running = true;
                let remaining = wait.remaining();
                if remaining.is_zero() {
                    return Err(guest_unavailable_timeout(name, budget));
                }
                let probe_timeout = remaining.min(self.host_call_timeout());
                // cwd `/`: a declared uid that cannot enter HOME must reach
                // the identity check (`guest_user`), not wait out the budget.
                let prober = self.bounded(probe_timeout);
                let probe = || {
                    prober.exec_argv_opts(
                        bound,
                        &["true".to_string()],
                        Some("/"),
                        Some(probe_timeout),
                    )
                };
                let result = if fenced {
                    prober.with_verified_enforcement(&bound.sandbox_id, true, probe)
                } else {
                    probe()
                };
                match result {
                    Err(err) if err.is_enforcement_inconclusive() => return Err(err),
                    Ok(out) if out.exit_code == 0 => return Ok(()),
                    Ok(_) => {}
                    // The agent went away mid-probe (a restart): the next
                    // state observation decides.
                    Err(err)
                        if matches!(
                            err.code,
                            SandboxErrorCode::Timeout | SandboxErrorCode::SandboxNotRunning
                        ) => {}
                    Err(err) => return Err(err),
                }
            }
            let remaining = wait.remaining();
            if remaining.is_zero() {
                return Err(guest_unavailable_timeout(name, budget));
            }
            let down_left = down_since.map(|since| wait.settle.saturating_sub(since.elapsed()));
            self.wait_readiness_poll(
                remaining
                    .min(READINESS_POLL)
                    .min(down_left.unwrap_or(Duration::MAX)),
            )?;
        }
    }

    /// Daemon host totals. This does not inspect/provision the selected project.
    pub fn host_resources(&self) -> Result<crate::HostResources, RuntimeError> {
        let totals = crate::HostResources::from_daemon(self.query_raw("/1.0/resources")?)?;
        let meminfo = std::fs::read_to_string("/proc/meminfo").map_err(|_| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                "kernel memory total unavailable",
            )
        })?;
        totals.with_meminfo(&meminfo)
    }

    pub(crate) fn configured_vm_size(
        &self,
        name: &str,
    ) -> Result<sandbox_protocol::VmSize, RuntimeError> {
        let metadata = self.query_raw(&instance_query_url(name, &self.project)?)?;
        let config = metadata
            .get("expanded_config")
            .or_else(|| metadata.get("config"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::VmSizeMismatch,
                    "effective VM allocation is not auditable",
                )
            })?;
        crate::resources::configured_vm_size(config)
    }

    pub(super) fn query_raw(&self, path: &str) -> Result<serde_json::Value, RuntimeError> {
        self.query_raw_timed(path, self.host_call_timeout())
    }

    pub(super) fn query_raw_timed(
        &self,
        path: &str,
        timeout: Duration,
    ) -> Result<serde_json::Value, RuntimeError> {
        let out = self.read_bounded(&["query", "--raw", path], timeout, 8 * 1024 * 1024)?;
        let image_lookup = path.starts_with("/1.0/images/");
        match parse_query_envelope(&out) {
            QueryEnvelope::Error((404, _)) if image_lookup => {
                // Incus 7.5 includes the fingerprint in its diagnostic. The
                // structured status and image endpoint establish absence;
                // wording is not a protocol. A missing project also returns
                // 404 here, so prove the selected project exists first.
                self.verify_image_lookup_project(timeout)?;
                Err(image_not_found())
            }
            QueryEnvelope::Error(err) => Err(api_status_error(err)),
            QueryEnvelope::Sync(metadata) => Ok(metadata),
            QueryEnvelope::Unparseable
                if image_lookup && out.exit_code != 0 && cli_image_not_found(&out, path) =>
            {
                self.verify_image_lookup_project(timeout)?;
                Err(image_not_found())
            }
            QueryEnvelope::Unparseable => Err(host_cli_error("query", &out)),
        }
    }

    // A generic image 404 can mean that the selected project itself is absent.
    // Only report exact-image absence after a bounded read confirms the project.
    fn verify_image_lookup_project(&self, timeout: Duration) -> Result<(), RuntimeError> {
        self.query_raw_timed(&project_query_url(&self.project)?, timeout)
            .map(|_| ())
            .map_err(|error| {
                RuntimeError::new(
                    if error.code == SandboxErrorCode::AccessDenied {
                        SandboxErrorCode::AccessDenied
                    } else {
                        SandboxErrorCode::Internal
                    },
                    "incus image lookup failed",
                )
            })
    }

    pub fn list_instances(&self) -> Result<Vec<ListedInstance>, RuntimeError> {
        let out = self.run(&["list", "--format", "json"], false)?;
        if out.exit_code != 0 {
            return Err(host_cli_error("list", &out));
        }
        serde_json::from_str(&out.stdout).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("failed to parse incus list JSON: {err}"),
            )
        })
    }

    pub(super) fn host_permit(&self) -> Option<&crate::RuntimePermit> {
        self.cancelled
            .as_deref()
            .or(self.inspection_permit.as_deref())
    }
    pub(super) fn io_cancelled(&self) -> bool {
        self.host_children.is_closed()
            || self
                .cancelled
                .as_ref()
                .is_some_and(|permit| permit.is_cancelled())
            || self
                .inspection_permit
                .as_ref()
                .is_some_and(|permit| permit.is_cancelled())
    }

    pub fn shutdown_local_children(&self) -> Result<(), RuntimeError> {
        self.host_children.shutdown()
    }

    /// Local mutex waits have the same finite IO budget as daemon calls.
    /// In particular, recovery must yield to a later reconnect or shutdown.
    pub(super) fn lock_runtime<'a, T>(
        &self,
        lock: &'a std::sync::Mutex<T>,
    ) -> Result<std::sync::MutexGuard<'a, T>, RuntimeError> {
        let deadline = Instant::now() + self.agent_timeout;
        loop {
            if self.io_cancelled() || Instant::now() >= deadline {
                return Err(RuntimeError::new(
                    SandboxErrorCode::UnknownOutcome,
                    "runtime lock wait exceeded its budget or was cancelled",
                ));
            }
            match lock.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(std::sync::TryLockError::Poisoned(err)) => return Ok(err.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    thread::sleep(Duration::from_millis(10))
                }
            }
        }
    }

    fn host_call_timeout(&self) -> Duration {
        self.agent_timeout
    }

    /// Read-only CLI with deadline, cancellation, pipe bound and kill/reap on overflow.
    pub(super) fn read_bounded(
        &self,
        args: &[&str],
        timeout: Duration,
        cap: usize,
    ) -> Result<IncusCommandOutput, RuntimeError> {
        let mut command =
            crate::host_child::command(&self.binary, crate::host_child::Environment::Incus);
        if args.first() != Some(&"query") {
            validate_incus_identifier(&self.project, "project")?;
            command.args(["--project", &self.project]);
        }
        untranslated(&mut command);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        pre::phase(
            |before| {
                let guard = self.host_permit().map(|p| p.admit()).transpose()?;
                let child = self.host_children.spawn(before, &mut command);
                drop(guard);
                child
            },
            |(child, _owned)| {
                wait_process_with_limit(
                    child,
                    timeout.min(self.agent_timeout),
                    self.host_permit(),
                    Some(cap),
                )
                .map(map_output)
                .map_err(crate::effect::PostIssueError::Unknown)
            },
        )
        .map_err(EffectError::into_error)
    }

    pub(super) fn run<S: AsRef<str>>(
        &self,
        args: &[S],
        quiet: bool,
    ) -> Result<IncusCommandOutput, RuntimeError> {
        self.run_timed(args, quiet, self.host_call_timeout())
    }

    fn run_timed<S: AsRef<str>>(
        &self,
        args: &[S],
        quiet: bool,
        timeout: Duration,
    ) -> Result<IncusCommandOutput, RuntimeError> {
        self.run_timed_effect(args, quiet, timeout)
            .map_err(EffectError::into_error)
    }
    /// Caller-bounded variant of `run` (C36 r13): DNS allow mutations are
    /// bounded by the grant's remaining safe lifetime so a stalled
    /// addition is killed at its deadline instead of installing an
    /// already-expired destination. The timeout is additionally capped by
    /// the host call timeout, and deadline kills surface as
    /// `SandboxErrorCode::Timeout` from the supervised runner.
    pub(super) fn run_bounded<S: AsRef<str>>(
        &self,
        args: &[S],
        quiet: bool,
        timeout: Duration,
    ) -> Result<IncusCommandOutput, RuntimeError> {
        self.run_timed(args, quiet, timeout.min(self.host_call_timeout()))
    }
    fn run_effect<S: AsRef<str>>(
        &self,
        args: &[S],
        quiet: bool,
    ) -> EffectResult<IncusCommandOutput> {
        self.run_timed_effect(args, quiet, self.host_call_timeout())
    }
    fn run_timed_effect<S: AsRef<str>>(
        &self,
        args: &[S],
        quiet: bool,
        timeout: Duration,
    ) -> EffectResult<IncusCommandOutput> {
        // Incus CLI rule edits GET then PUT the whole ACL. The expiry watcher
        // deliberately bypasses the sandbox lock, so serialize ONLY each edit
        // with refresh edits to prevent lost allows/rejects. Never hold this
        // lock while taking lease/sandbox locks or waiting on another edit.
        let acl_turn = (args.first().map(AsRef::as_ref) == Some("network")
            && args.get(1).map(AsRef::as_ref) == Some("acl")
            && args.get(2).map(AsRef::as_ref) == Some("rule"))
        .then(|| {
            args.get(4)
                .map(|name| AclEditTurn::enqueue(&self.acl_edits, name.as_ref()))
        })
        .flatten();
        let deadline = Instant::now() + timeout;
        if let Some(turn) = &acl_turn {
            while !turn.ready() {
                if Instant::now() >= deadline || self.io_cancelled() {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::Timeout,
                        "ACL edit budget exhausted",
                    )
                    .into());
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        let mut command =
            crate::host_child::command(&self.binary, crate::host_child::Environment::Incus);
        if args.first().map(AsRef::as_ref) != Some("query") {
            validate_incus_identifier(&self.project, "project")?;
            command.arg("--project").arg(&self.project);
        }
        if quiet {
            command.arg("--quiet");
        }
        for arg in args {
            command.arg(arg.as_ref());
        }
        untranslated(&mut command);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command.stdin(Stdio::null());
        let output = run_process_cancellable_with_stdin(
            command,
            None,
            if acl_turn.is_some()
                && args.get(3).map(AsRef::as_ref) == Some("remove")
                && args.iter().any(|arg| {
                    arg.as_ref().starts_with("description=wssp-dns-quarantine-")
                        || arg
                            .as_ref()
                            .starts_with("description=wssp-dns-lease-quarantine-")
                })
            {
                // A stalled fence release must yield the lane to expiry
                // fencing. Grant withdrawals and additions keep their own
                // budgets so a slow daemon can finish enforcement. Pending
                // mutations remain journaled after either bound expires.
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(5))
            } else {
                deadline.saturating_duration_since(Instant::now())
            },
            self.host_permit(),
            self.settle_create,
            Some(&self.host_children),
        )?;
        Ok(map_output(output))
    }

    /// A finite FIFO turn; cancellation also removes a queued waiter.
    pub(super) fn acl_edit_turn(
        &self,
        name: &str,
        deadline: Instant,
    ) -> Result<AclEditTurn, RuntimeError> {
        let turn = AclEditTurn::enqueue(&self.acl_edits, name);
        while !turn.ready() {
            if Instant::now() >= deadline || self.io_cancelled() {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Timeout,
                    "ACL edit budget exhausted",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(turn)
    }

    /// Run with a request body on stdin (`incus query --data-file -`): argv
    /// is capped at MAX_ARG_STRLEN (128 KiB on 4 KiB-page Linux), so
    /// payloads like a fully populated `raw.dnsmasq` must travel over stdin,
    /// which has no such bound. Every caller supplies a deadline (C36 r17 F3):
    /// publication is bounded by
    /// the earliest working grant's deadline, never only by the host call
    /// timeout, so a stalled PATCH cannot run past an expiry.
    pub(super) fn run_with_stdin_timed<S: AsRef<str>>(
        &self,
        args: &[S],
        stdin_data: &[u8],
        quiet: bool,
        timeout: Duration,
    ) -> Result<IncusCommandOutput, RuntimeError> {
        let mut command =
            crate::host_child::command(&self.binary, crate::host_child::Environment::Incus);
        if args.first().map(AsRef::as_ref) != Some("query") {
            validate_incus_identifier(&self.project, "project")?;
            command.arg("--project").arg(&self.project);
        }
        if quiet {
            command.arg("--quiet");
        }
        for arg in args {
            command.arg(arg.as_ref());
        }
        untranslated(&mut command);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = run_process_cancellable_with_stdin(
            command,
            Some(stdin_data),
            timeout.min(self.host_call_timeout()),
            self.host_permit(),
            self.settle_create,
            Some(&self.host_children),
        )
        .map_err(EffectError::into_error)?;
        Ok(map_output(output))
    }

    /// `incus query -X PATCH <path>` with a JSON body; PATCH merges the
    /// given config keys (Incus API semantics), so publishing one key never
    /// touches the rest. See `query_patch_timed` for how the body travels.
    pub(super) fn query_patch(
        &self,
        path: &str,
        body: &str,
    ) -> Result<serde_json::Value, RuntimeError> {
        self.query_patch_timed(path, body, self.host_call_timeout())
    }

    /// Caller-bounded PATCH (C36 r17 F3).
    ///
    /// E-26: `incus query` has never read stdin for `-d @-` — every release
    /// from 6.0 through 7.5.1 json-decodes the `-d` value and otherwise sends
    /// it as a JSON string, so `@-` reached the daemon as the body `"@-"`
    /// (HTTP 400 "cannot unmarshal string into Go value of type
    /// api.NetworkPut"). The only stdin form is `--data-file -`, added in
    /// Incus 7.4.0. So the body goes on stdin via `--data-file -` first;
    /// a CLI older than 7.4 rejects the unknown flag during argument parsing,
    /// before it connects to the daemon (no request is sent), and the body
    /// is then retried inline as `-d <json>` when it fits
    /// `INLINE_QUERY_BODY_MAX`. A larger body on such a CLI fails closed.
    /// Both attempts share the one caller deadline.
    pub(super) fn query_patch_timed(
        &self,
        path: &str,
        body: &str,
        timeout: Duration,
    ) -> Result<serde_json::Value, RuntimeError> {
        self.query_body_timed("PATCH", path, body, &[], timeout)
    }

    pub(super) fn query_body_timed(
        &self,
        method: &str,
        path: &str,
        body: &str,
        headers: &[&str],
        timeout: Duration,
    ) -> Result<serde_json::Value, RuntimeError> {
        let started = Instant::now();
        use std::sync::atomic::Ordering;
        let mut args = vec!["query", "--raw", "-X", method];
        for header in headers {
            args.extend(["--header", header]);
        }
        let attempted = if self.query_body_mode.load(Ordering::Acquire) == 1 {
            None
        } else {
            Some(self.run_with_stdin_timed(
                &[args.as_slice(), &["--data-file", "-", path]].concat(),
                body.as_bytes(),
                false,
                timeout,
            )?)
        };
        let out = match attempted {
            Some(out) if !rejects_data_file_flag(&out) => {
                self.query_body_mode.store(2, Ordering::Release);
                out
            }
            _ => {
                self.query_body_mode.store(1, Ordering::Release);
                if body.len() > INLINE_QUERY_BODY_MAX {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::Internal,
                        format!(
                            "incus query {method} needs `--data-file` (Incus 7.4 or newer) for a \
                         {}-byte request body; this incus CLI only accepts an inline body \
                         of at most {INLINE_QUERY_BODY_MAX} bytes",
                            body.len()
                        ),
                    ));
                }
                let remaining = timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::Timeout,
                        format!("incus query {method} deadline elapsed before the inline retry"),
                    ));
                }
                self.run_bounded(
                    &[args.as_slice(), &["-d", body, path]].concat(),
                    false,
                    remaining,
                )?
            }
        };
        if !headers.is_empty() {
            if out.exit_code != 0 && out.stderr.contains("unknown flag: --header") {
                // Flag parsing fails before any daemon request. Retain the
                // established identity-specific writer on older supported CLIs.
                self.acl_update_mode.store(1, Ordering::Release);
                return Err(RuntimeError::new(
                    SandboxErrorCode::HostRuntimeUnsupported,
                    "incus CLI does not support conditional ACL updates",
                ));
            }
            self.acl_update_mode.store(2, Ordering::Release);
        }
        match parse_query_envelope(&out) {
            QueryEnvelope::Error(err) => Err(api_status_error(err)),
            QueryEnvelope::Sync(metadata) => Ok(metadata),
            QueryEnvelope::Unparseable => Err(host_cli_error("query", &out)),
        }
    }
}

/// Largest request body `query_patch_timed` passes inline (`-d <json>`) to an
/// incus CLI without `--data-file` (< 7.4). The kernel caps one argument at
/// MAX_ARG_STRLEN (32 pages: 128 KiB on 4 KiB-page Linux, never smaller) and
/// all of argv plus the environment at max(RLIMIT_STACK / 4, 128 KiB).
/// 96 KiB leaves 32 KiB for the remaining argv and the environment even at
/// that 128 KiB floor. DNS policies under ~1400 rendered records fit; the
/// record bound (~280 KiB) needs `--data-file`.
pub(super) const INLINE_QUERY_BODY_MAX: usize = 96 * 1024;

/// An incus CLI that predates `query --data-file` (added in 7.4.0) fails
/// flag parsing (cobra/pflag `unknown flag: --data-file`) before RunE, so
/// the request never reached the daemon and retrying inline is safe.
fn rejects_data_file_flag(out: &IncusCommandOutput) -> bool {
    out.exit_code != 0 && out.stderr.contains("unknown flag: --data-file")
}

/// HR-R5: the Incus CLI translates its messages from the caller's locale
/// (`LC_ALL`, then `LC_MESSAGES`/`LANG`). Outcome rules match its English
/// text (the `Error: ` prefix of a start refusal, the unknown-flag refusal of
/// `--data-file`), so every non-exec CLI run is pinned to the untranslated C
/// locale. A translated prefix would otherwise degrade a definite refusal to
/// UNKNOWN. `incus exec` spawns are left as they are: their outcomes come
/// from nonce-bound guest records, never from CLI message text.
fn untranslated(command: &mut Command) {
    command.env("LC_ALL", "C");
}

fn agent_timeout_from_env() -> Duration {
    let secs = std::env::var("WSSP_INCUS_AGENT_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_AGENT_TIMEOUT_SECS);
    Duration::from_secs(secs.max(1))
}

fn guest_unavailable_timeout(name: &str, timeout: Duration) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::GuestUnavailable,
        format!("incus VM `{name}` agent did not become ready within {timeout:?}"),
    )
    .with_readiness_reason(ReadinessFailureReason::AgentTimeout)
}

/// The readiness path that saw the VM out of Running.
#[derive(Debug, Clone, Copy)]
enum NotRunningPath {
    /// Stopped (or another non-start state) before Running was ever seen.
    PreRunStop,
    /// A non-boot state during the agent wait.
    AgentWait,
    /// Out of Running for the whole reboot settle window.
    Settle,
    /// A non-boot state when a pass was re-observed.
    ValidatePass,
}

impl NotRunningPath {
    fn as_str(self) -> &'static str {
        match self {
            Self::PreRunStop => "pre_run_stop",
            Self::AgentWait => "agent_wait",
            Self::Settle => "settle",
            Self::ValidatePass => "validate_pass",
        }
    }
}

/// A VM that is (or stayed) out of Running during readiness. It carries
/// host facts only (the readiness path, the last Incus status read, the time
/// since the VM was last seen Running) as a typed detail the daemon logs,
/// mirrored in the message. Never guest output.
fn vm_not_running(
    name: &str,
    path: NotRunningPath,
    state: Option<&HostInstanceState>,
    wait: &AgentWait,
) -> RuntimeError {
    let detail = crate::NotRunningDetail::new(
        path.as_str(),
        state.map(|state| (state.status.as_str(), state.status_code)),
        wait.last_running.map(|at| at.elapsed()),
    );
    RuntimeError::new(
        SandboxErrorCode::SandboxNotRunning,
        format!("incus instance `{name}` is not running ({detail})"),
    )
    .with_readiness_reason(ReadinessFailureReason::VmNotRunning)
    .with_not_running_detail(Some(detail))
}

fn readiness_deadline_error(
    name: &str,
    budget: Duration,
    saw_running_or_starting: bool,
) -> RuntimeError {
    if saw_running_or_starting {
        guest_unavailable_timeout(name, budget)
    } else {
        RuntimeError::new(
            SandboxErrorCode::Timeout,
            format!("incus query for `{name}` did not complete within {budget:?}"),
        )
    }
}

fn already_exists(out: &IncusCommandOutput) -> bool {
    out.stderr.to_ascii_lowercase().contains("already exists")
}

pub fn validate_env(env: &[(String, String)]) -> Result<(), RuntimeError> {
    sandbox_protocol::validate_env(env).map_err(|(code, message)| RuntimeError::new(code, message))
}

pub fn validate_incus_identifier(value: &str, what: &str) -> Result<(), RuntimeError> {
    let valid = (1..=63).contains(&value.len())
        && !value.starts_with('-')
        && !value.contains('/')
        && !value.contains('%')
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            format!("invalid incus {what} `{value}`"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_config_pair(key: &str, value: &str) -> Result<(), RuntimeError> {
    let key_ok = !key.is_empty()
        && !key.starts_with('-')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !key_ok || value.contains('\0') || value.contains('\n') {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            format!("invalid incus config pair `{key}`"),
        ));
    }
    Ok(())
}

pub(crate) fn refuse_root(path: &str) -> Result<(), RuntimeError> {
    if path == "/" {
        return Err(RuntimeError::new(
            SandboxErrorCode::PathRefused,
            "refusing to mutate the guest root path `/`",
        ));
    }
    Ok(())
}

fn instance_query_url(name: &str, project: &str) -> Result<String, RuntimeError> {
    validate_managed_instance_name(name)?;
    Ok(with_query_params(
        &format!("/1.0/instances/{}", percent_encode(name)),
        &[("project", project)],
    ))
}

fn image_query_url(image_ref: &str, project: &str) -> Result<String, RuntimeError> {
    validate_incus_identifier(project, "project")?;
    let encoded = if crate::is_incus_fingerprint(image_ref) {
        percent_encode(&crate::normalize_incus_fingerprint(image_ref)?)
    } else {
        percent_encode(image_ref)
    };
    Ok(with_query_params(
        &format!("/1.0/images/{encoded}"),
        &[("project", project)],
    ))
}

fn parse_image_metadata(
    metadata: &serde_json::Value,
    image_ref: &str,
) -> Result<crate::ResolvedHostImage, RuntimeError> {
    let fingerprint = metadata
        .get("fingerprint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("incus query JSON missing image fingerprint for `{image_ref}`"),
            )
        })?;
    let architecture = metadata
        .get("architecture")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("incus query JSON missing image architecture for `{image_ref}`"),
            )
        })?;
    Ok(crate::ResolvedHostImage {
        fingerprint: crate::image::fingerprint_from_incus(fingerprint)?,
        architecture: architecture.to_string(),
        size_bytes: metadata
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .filter(|size| *size > 0),
    })
}

fn project_query_url(name: &str) -> Result<String, RuntimeError> {
    validate_incus_identifier(name, "project")?;
    Ok(with_query_params(
        &format!("/1.0/projects/{}", percent_encode(name)),
        &[("project", "default")],
    ))
}

fn dedicated_project_sharing_error(project: &str) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::Internal,
        format!(
            "Incus project `{project}` must share profiles and images with the `default` project \
(features.profiles=false and features.images=false). Recreate it with \
`incus project create {project} --config features.profiles=false --config features.images=false`, \
or set WSSP_INCUS_PROJECT=default to use the default project directly."
        ),
    )
}

/// Whether a NUL-split QEMU argv names `instance`: an element after `-name`
/// whose first comma-separated field, after an optional `guest=` prefix, is
/// the instance name, or `<project>_<name>` in a non-default project.
pub(super) fn qemu_cmdline_names(cmdline: &[u8], instance: &str, project: &str) -> bool {
    let argv: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
    let prefixed = format!("{project}_{instance}");
    argv.windows(2).any(|pair| {
        pair[0] == b"-name"
            && std::str::from_utf8(pair[1]).is_ok_and(|value| {
                let first = value.split(',').next().unwrap_or_default();
                let first = first.strip_prefix("guest=").unwrap_or(first);
                first == instance || first == prefixed
            })
    })
}

/// Field 22 (`starttime`) of a `/proc/<pid>/stat` line, parsed after the
/// last `)` (the command name may contain spaces and parentheses).
pub(super) fn proc_stat_starttime(stat: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(stat).ok()?;
    let rest = &text[text.rfind(')')? + 1..];
    // After `)`: field 3 (state) is the first; starttime is field 22.
    let value = rest.split_ascii_whitespace().nth(22 - 3)?;
    value.parse().ok().filter(|ticks| *ticks > 0)
}

fn instance_state_query_url(name: &str, project: &str) -> Result<String, RuntimeError> {
    validate_managed_instance_name(name)?;
    Ok(with_query_params(
        &format!("/1.0/instances/{}/state", percent_encode(name)),
        &[("project", project)],
    ))
}

pub(super) fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub(super) fn with_query_params(path: &str, params: &[(&str, &str)]) -> String {
    let (base, existing) = match path.split_once('?') {
        Some((base, query)) => (base, query),
        None => (path, ""),
    };
    let mut parts: Vec<String> = if existing.is_empty() {
        Vec::new()
    } else {
        existing
            .split('&')
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect()
    };
    for (key, value) in params {
        let encoded_key = percent_encode(key);
        parts.retain(|part| {
            part.split_once('=')
                .map(|(name, _)| name != encoded_key)
                .unwrap_or(true)
        });
        parts.push(format!("{encoded_key}={}", percent_encode(value)));
    }
    if parts.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", parts.join("&"))
    }
}

pub fn sandbox_not_running(name: &str) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::SandboxNotRunning,
        format!("incus instance `{name}` is not running"),
    )
}

#[derive(Debug)]
pub(super) enum QueryEnvelope {
    Sync(serde_json::Value),
    Error((u64, String)),
    Unparseable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GuestStatus {
    Ok,
    NotFound,
    PermissionDenied,
    NotADirectory,
    NotAFile,
    NotEmpty,
    ProcessNotFound,
    /// The file-put commit fence was refused; the helper removed its staging file.
    Cancelled,
    OperationFailed,
}

/// Guest diagnostics are private data, including legacy helper output.
fn public_detail(_out: &IncusCommandOutput) -> String {
    "guest operation failed".into()
}

pub(super) fn random_nonce() -> Result<String, RuntimeError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|err| {
        RuntimeError::new(
            SandboxErrorCode::Internal,
            format!("failed to read OS CSPRNG: {err}"),
        )
    })?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(out)
}

pub(super) fn parse_guest_status(nonce: &str, out: &IncusCommandOutput) -> Option<GuestStatus> {
    let prefix = format!("WSSP_STATUS {nonce} ");
    for line in out.stderr.lines().chain(out.stdout.lines()) {
        let Some(code) = line.trim().strip_prefix(&prefix) else {
            continue;
        };
        return Some(match code.trim() {
            "ok" => GuestStatus::Ok,
            "not_found" => GuestStatus::NotFound,
            "guest_permission_denied" => GuestStatus::PermissionDenied,
            "not_a_directory" => GuestStatus::NotADirectory,
            "not_a_file" => GuestStatus::NotAFile,
            "not_empty" => GuestStatus::NotEmpty,
            "process_not_found" => GuestStatus::ProcessNotFound,
            "cancelled" => GuestStatus::Cancelled,
            "guest_operation_failed" => GuestStatus::OperationFailed,
            _ => GuestStatus::OperationFailed,
        });
    }
    None
}

pub(super) fn guest_status_error(_action: &str, _path: &str, status: GuestStatus) -> RuntimeError {
    let code = match status {
        GuestStatus::NotFound => SandboxErrorCode::FsNotFound,
        GuestStatus::PermissionDenied => SandboxErrorCode::GuestPermissionDenied,
        GuestStatus::NotADirectory => SandboxErrorCode::FsNotDirectory,
        GuestStatus::NotAFile => SandboxErrorCode::FsNotRegular,
        GuestStatus::NotEmpty => SandboxErrorCode::FsNotEmpty,
        GuestStatus::Cancelled => SandboxErrorCode::Cancelled,
        GuestStatus::OperationFailed | GuestStatus::Ok | GuestStatus::ProcessNotFound => {
            SandboxErrorCode::GuestOperationFailed
        }
    };
    if code.as_str().starts_with("fs_") {
        crate::metadata::fs_error(code)
    } else {
        RuntimeError::new(code, "guest operation failed")
    }
}

fn parse_json_value(text: &str) -> Option<serde_json::Value> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(value) = serde_json::from_str(trimmed) {
        return Some(value);
    }
    let idx = trimmed.find('{')?;
    serde_json::from_str(&trimmed[idx..]).ok()
}

pub(super) fn parse_query_envelope(out: &IncusCommandOutput) -> QueryEnvelope {
    for text in [&out.stdout, &out.stderr] {
        let Some(value) = parse_json_value(text) else {
            continue;
        };
        let error_code = value
            .get("error_code")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let kind = value.get("type").and_then(serde_json::Value::as_str);
        if kind == Some("error") || error_code >= 400 {
            let message = value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            return QueryEnvelope::Error((error_code.max(400), message));
        }
        if kind == Some("sync") || value.get("metadata").is_some() {
            return QueryEnvelope::Sync(value.get("metadata").cloned().unwrap_or(value));
        }
        return QueryEnvelope::Sync(value);
    }
    QueryEnvelope::Unparseable
}

// Some CLI versions render an API error as text. Only a complete not-found
// diagnostic from an image endpoint is absence evidence. Transport/readiness
// failures and instance 404s retain their different verdicts.
fn cli_image_not_found(out: &IncusCommandOutput, path: &str) -> bool {
    [
        "Error: not found",
        "Error: Image not found",
        "Error: Image alias not found",
    ]
    .iter()
    .any(|message| out.stderr.trim().eq_ignore_ascii_case(message))
        // CLI-only fallback for versions that discard the JSON envelope.
        // Match the complete image diagnostic, never a project/transport error.
        || out.stderr.trim().strip_prefix("Error: Image \"")
            .and_then(|message| message.strip_suffix("\" not found"))
            .is_some_and(|image| {
                let requested = path.split('?').next().unwrap_or_default()
                    .strip_prefix("/1.0/images/").unwrap_or_default();
                let requested = requested.strip_prefix("aliases/").unwrap_or(requested);
                !image.is_empty() && !image.contains(['\n', '\r', '"'])
                    && percent_encode(image) == requested
            })
}

#[cfg(test)]
mod quoted_image_tests {
    use super::*;
    #[test]
    fn quoted_cli_image_absence_is_bound_to_requested_ref() {
        let out = IncusCommandOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "Error: Image \"requested\" not found".into(),
        };
        assert!(cli_image_not_found(
            &out,
            "/1.0/images/requested?project=default"
        ));
        assert!(cli_image_not_found(
            &out,
            "/1.0/images/aliases/requested?project=default"
        ));
        assert!(!cli_image_not_found(
            &out,
            "/1.0/images/other?project=default"
        ));
        assert!(!cli_image_not_found(
            &out,
            "/1.0/images/aliases/other?project=default"
        ));
    }
}

fn image_not_found() -> RuntimeError {
    RuntimeError::new(SandboxErrorCode::NotFound, "incus image was not found")
}

fn api_status_error(err: (u64, String)) -> RuntimeError {
    let (code, message) = err;
    let detail = if message.is_empty() {
        format!("HTTP {code}")
    } else {
        message
    };
    match code {
        401 | 403 => RuntimeError::new(
            SandboxErrorCode::AccessDenied,
            format!("incus query permission denied: {detail}"),
        ),
        404 => RuntimeError::new(
            SandboxErrorCode::SandboxNotFound,
            format!("incus instance was not found during query: {detail}"),
        ),
        _ => RuntimeError::new(
            SandboxErrorCode::Internal,
            format!("incus query failed (HTTP {code}): {detail}"),
        ),
    }
}

fn parse_instance_metadata(
    metadata: &serde_json::Value,
    name: &str,
) -> Result<HostInstance, RuntimeError> {
    let status = metadata
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let status_code = metadata
        .get("status_code")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let inst_name = metadata
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(name)
        .to_string();
    if status.is_empty() && status_code == 0 {
        return Err(RuntimeError::new(
            SandboxErrorCode::Internal,
            format!("incus query JSON missing instance status for `{name}`"),
        ));
    }
    Ok(HostInstance {
        name: inst_name,
        status,
        status_code,
    })
}

fn parse_instance_state_metadata(
    metadata: &serde_json::Value,
    name: &str,
) -> Result<HostInstanceState, RuntimeError> {
    let status = metadata
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let status_code = metadata
        .get("status_code")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if status.is_empty() && status_code == 0 {
        return Err(RuntimeError::new(
            SandboxErrorCode::Internal,
            format!("incus query JSON missing instance state status for `{name}`"),
        ));
    }
    let pid = metadata
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .filter(|pid| *pid > 0);
    Ok(HostInstanceState {
        status,
        status_code,
        pid,
    })
}

pub(super) fn host_cli_error(action: &str, out: &IncusCommandOutput) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::Internal,
        format!("incus {action} failed: {}", public_detail(out)),
    )
}

#[cfg(test)]
pub(super) fn classify_coreutils_diagnostic(
    out: &IncusCommandOutput,
    tool: &str,
) -> Option<GuestStatus> {
    let mut matched: Option<&str> = None;
    for line in out.stderr.lines().map(str::trim) {
        if line.is_empty()
            || line.starts_with("WSSP_STATUS ")
            || line.starts_with("WSSP_PID ")
            || line.starts_with("WSSP_EXIT ")
        {
            continue;
        }
        let belongs = line
            .strip_prefix(tool)
            .is_some_and(|rest| rest.starts_with(": "));
        if !belongs {
            continue;
        }
        let strerror = parse_bound_tool_strerror(line, tool)?;
        if matched.is_some() {
            return None;
        }
        matched = Some(strerror);
    }
    matched.map(status_from_strerror)
}

#[cfg(test)]
fn status_from_strerror(strerror: &str) -> GuestStatus {
    match strerror {
        "No such file or directory" => GuestStatus::NotFound,
        "Permission denied" | "Operation not permitted" => GuestStatus::PermissionDenied,
        "Not a directory" => GuestStatus::NotADirectory,
        "Directory not empty" => GuestStatus::NotEmpty,
        _ => GuestStatus::OperationFailed,
    }
}

/// Strict GNU tool diagnostic line:
/// `<tool>: cannot <verb> <quoted-path> [to <quoted-path>]: <strerror>`
/// `<tool>: failed to <verb> <quoted-path>: <strerror>`
/// `<tool>: <quoted-path>: <strerror>` (findutils)
/// The quoted-path must parse fully under coreutils shell-escape quoting.
#[cfg(test)]
fn parse_gnu_tool_strerror(line: &str) -> Option<&str> {
    let (tool, rest) = line.split_once(": ")?;
    if !is_gnu_tool_name(tool) {
        return None;
    }
    parse_gnu_strerror_rest(rest)
}

#[cfg(test)]
fn is_gnu_tool_name(tool: &str) -> bool {
    !tool.is_empty()
        && tool
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && tool.chars().next().is_some_and(|c| c.is_ascii_lowercase())
}

#[cfg(test)]
fn parse_bound_tool_strerror<'a>(line: &'a str, tool: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(tool)?.strip_prefix(": ")?;
    parse_gnu_strerror_rest(rest)
}

#[cfg(test)]
fn parse_gnu_strerror_rest(rest: &str) -> Option<&str> {
    if rest.starts_with('\'') || rest.starts_with('"') || rest.starts_with("$'") {
        return finish_quoted_strerror(rest);
    }
    let rest = rest
        .strip_prefix("cannot ")
        .or_else(|| rest.strip_prefix("failed to "))?;
    let quote_at = rest.find(['\'', '"']).or_else(|| rest.find("$'"))?;
    let verb = rest[..quote_at].trim_end();
    if verb.is_empty() || !verb.chars().all(|c| c.is_ascii_lowercase() || c == ' ') {
        return None;
    }
    let (_, after_path) = parse_coreutils_quoted(&rest[quote_at..])?;
    if let Some(second) = after_path.strip_prefix(" to ") {
        return finish_quoted_strerror(second);
    }
    after_path.strip_prefix(": ")
}

#[cfg(test)]
fn finish_quoted_strerror(input: &str) -> Option<&str> {
    let (_, after) = parse_coreutils_quoted(input)?;
    after.strip_prefix(": ")
}

#[cfg(test)]
fn parse_coreutils_quoted(input: &str) -> Option<(String, &str)> {
    let mut decoded = String::new();
    let mut rest = input;
    let mut parsed_unit = false;
    loop {
        if rest.starts_with("$'") {
            let (chunk, next) = parse_ansi_c_quoted(rest)?;
            decoded.push_str(&chunk);
            rest = next;
            parsed_unit = true;
        } else if rest.starts_with('\'') {
            let (chunk, next) = parse_single_quoted(rest)?;
            decoded.push_str(&chunk);
            rest = next;
            parsed_unit = true;
        } else if rest.starts_with('"') {
            let (chunk, next) = parse_double_quoted(rest)?;
            decoded.push_str(&chunk);
            rest = next;
            parsed_unit = true;
        } else if rest.starts_with("\\'") {
            decoded.push('\'');
            rest = &rest[2..];
            parsed_unit = true;
        } else {
            break;
        }
    }
    if !parsed_unit {
        return None;
    }
    Some((decoded, rest))
}

#[cfg(test)]
fn parse_single_quoted(input: &str) -> Option<(String, &str)> {
    let rest = input.strip_prefix('\'')?;
    let end = rest.find('\'')?;
    Some((rest[..end].to_string(), &rest[end + 1..]))
}

#[cfg(test)]
fn parse_double_quoted(input: &str) -> Option<(String, &str)> {
    let rest = input.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.char_indices();
    while let Some((i, ch)) = chars.next() {
        match ch {
            '"' => return Some((out, &rest[i + 1..])),
            '\\' => {
                let (_, next) = chars.next()?;
                out.push(next);
            }
            _ => out.push(ch),
        }
    }
    None
}

#[cfg(test)]
fn parse_ansi_c_quoted(input: &str) -> Option<(String, &str)> {
    let rest = input.strip_prefix("$'")?;
    let mut out = String::new();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => {
                return Some((out, &rest[i + 1..]));
            }
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    return None;
                }
                match bytes[i] {
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'a' => out.push('\u{7}'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'v' => out.push('\u{b}'),
                    b'\\' => out.push('\\'),
                    b'\'' => out.push('\''),
                    b'"' => out.push('"'),
                    b'?' => out.push('?'),
                    b'x' => {
                        i += 1;
                        let (value, consumed) = parse_hex_escape(&bytes[i..])?;
                        out.push(char::from(value));
                        i += consumed;
                        continue;
                    }
                    b'0'..=b'7' => {
                        let (value, consumed) = parse_octal_escape(&bytes[i..]);
                        out.push(char::from(value));
                        i += consumed;
                        continue;
                    }
                    other => out.push(other as char),
                }
                i += 1;
            }
            _ => {
                let ch = rest[i..].chars().next()?;
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    None
}

#[cfg(test)]
fn parse_hex_escape(bytes: &[u8]) -> Option<(u8, usize)> {
    let mut value = 0u8;
    let mut consumed = 0;
    for &byte in bytes.iter().take(2) {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => break,
        };
        value = value.saturating_mul(16).saturating_add(digit);
        consumed += 1;
    }
    (consumed > 0).then_some((value, consumed))
}

#[cfg(test)]
fn parse_octal_escape(bytes: &[u8]) -> (u8, usize) {
    let mut value = 0u8;
    let mut consumed = 0;
    for &byte in bytes.iter().take(3) {
        if !byte.is_ascii_digit() || byte > b'7' {
            break;
        }
        value = value.saturating_mul(8).saturating_add(byte - b'0');
        consumed += 1;
    }
    (value, consumed.max(1))
}

#[cfg(test)]
fn error_line_proves_enoent(line: &str) -> bool {
    let Some(msg) = line.strip_prefix("Error: ") else {
        return false;
    };
    matches!(
        msg,
        "not found" | "file does not exist" | "no such file or directory"
    ) || sftp_proves_enoent(msg)
}

#[cfg(test)]
fn sftp_proves_enoent(msg: &str) -> bool {
    let Some(rest) = msg.strip_prefix("sftp: ") else {
        return false;
    };
    let Some(quoted) = rest.strip_prefix('"') else {
        return false;
    };
    let Some(end) = quoted.find('"') else {
        return false;
    };
    let inner = &quoted[..end];
    let after = quoted[end + 1..].trim();
    after == "(SSH_FX_NO_SUCH_FILE)"
        && inner
            .rsplit_once(": ")
            .is_some_and(|(_, strerror)| strerror.eq_ignore_ascii_case("no such file or directory"))
}

pub fn validate_guest_path(path: &str) -> Result<(), RuntimeError> {
    if !path.starts_with('/') || path.len() > 4096 || path.contains('\0') {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "guest path must be absolute and bounded",
        ));
    }
    if Path::new(path)
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "guest path must not contain parent traversal",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn guest_file_target(instance: &str, path: &str) -> Result<String, RuntimeError> {
    validate_managed_instance_name(instance)?;
    validate_guest_path(path)?;
    Ok(format!("{instance}{path}"))
}

#[cfg(test)]
fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

#[cfg(test)]
fn run_process(command: Command, timeout: Duration) -> Result<Output, RuntimeError> {
    run_process_cancellable(command, timeout, None).map_err(EffectError::into_error)
}
fn run_process_cancellable(
    mut command: Command,
    timeout: Duration,
    cancelled: Option<&crate::RuntimePermit>,
) -> EffectResult<Output> {
    // No request body: the helper never inherits the daemon's stdin
    // (C55-TB-1; it runs in its own, background, process group).
    command.stdin(Stdio::null());
    run_process_cancellable_with_stdin(command, None, timeout, cancelled, false, None)
}
/// `run_process_cancellable` with a stdin payload: request bodies of any
/// size never touch argv (Linux caps a single argument at MAX_ARG_STRLEN,
/// 128 KiB on 4 KiB-page hosts). The body is written by a CONCURRENT writer
/// thread while `wait_process` collects output under the deadline measured
/// from spawn: a child that stalls before reading stdin — or floods an
/// output pipe first — can never deadlock the write, and on timeout or
/// cancellation the kill-and-reap unblocks the writer (EPIPE) before it is
/// joined, so the sandbox lock the caller holds is never parked. A child
/// that exits without reading yields EPIPE, which is not an error here —
/// the exit status carries the outcome.
fn run_process_cancellable_with_stdin(
    mut command: Command,
    stdin_data: Option<&[u8]>,
    timeout: Duration,
    cancelled: Option<&crate::RuntimePermit>,
    settle: bool,
    children: Option<&HostChildren>,
) -> EffectResult<Output> {
    pre::phase(
        |before| {
            if cancelled.is_some_and(|c| c.is_cancelled()) {
                return Err(RuntimeError::new(
                    SandboxErrorCode::UnknownOutcome,
                    "runtime work preempted",
                )
                .into());
            }
            let spawn_guard = cancelled.map(|c| c.admit()).transpose()?;
            command.process_group(0);
            let spawned = match children {
                Some(children) => children
                    .spawn(before, &mut command)
                    .map(|issued| issued.map(|(child, owned)| (child, Some(owned)))),
                None => {
                    pre::spawn(before, &mut command).map(|issued| issued.map(|child| (child, None)))
                }
            };
            drop(spawn_guard);
            spawned
        },
        |(mut child, _owned)| {
            let writer = stdin_data.map(|data| {
                let mut stdin = child.stdin.take();
                let data = data.to_vec();
                let (written_tx, written_rx) = mpsc::channel();
                thread::spawn(move || {
                    use std::io::Write as _;
                    let written = match stdin.as_mut() {
                        Some(stdin) => stdin.write_all(&data),
                        None => Err(std::io::Error::other("incus stdin is unavailable")),
                    };
                    // Close so the child observes end-of-input.
                    drop(stdin);
                    let _ = written_tx.send(written);
                });
                written_rx
            });
            // Settlement ignores explicit revocation of already-issued work,
            // never a caller's cumulative deadline (including bounded DNS
            // observation and cleanup scopes cloned during create).
            let timeout = if settle {
                cancelled
                    .and_then(crate::RuntimePermit::remaining_time)
                    .map_or(timeout, |remaining| timeout.min(remaining))
            } else {
                timeout
            };
            let output = wait_process(child, timeout, if settle { None } else { cancelled })
                .map_err(crate::effect::PostIssueError::Unknown);
            if let Some(writer) = writer {
                match writer.recv_timeout(Duration::from_secs(1)) {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) if err.kind() == std::io::ErrorKind::BrokenPipe => {}
                    Ok(Err(err)) => {
                        return Err(crate::effect::PostIssueError::Unknown(
                            RuntimeError::new(
                                SandboxErrorCode::Internal,
                                format!("failed to write the incus request body to stdin: {err}"),
                            )
                            .into(),
                        ));
                    }
                    Err(_panicked) => {
                        return Err(crate::effect::PostIssueError::Unknown(
                            RuntimeError::new(
                                SandboxErrorCode::Internal,
                                "the incus stdin writer did not finish within its deadline",
                            )
                            .into(),
                        ));
                    }
                }
            }
            output
        },
    )
}

/// Fixed-verdict helpers never collect unbounded guest pipes. Each reader
/// stops at the first excess byte, then the owner kills and reaps transport.
fn bounded_output(
    mut child: std::process::Child,
    cap: usize,
    overflow: mpsc::Sender<()>,
) -> std::io::Result<Output> {
    use std::io::Read;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    thread::scope(|scope| {
        let read = move |pipe: Option<Box<dyn Read + Send>>,
                         overflow: mpsc::Sender<()>|
              -> std::io::Result<Vec<u8>> {
            let mut bytes = Vec::with_capacity(cap + 1);
            if let Some(pipe) = pipe {
                pipe.take((cap + 1) as u64).read_to_end(&mut bytes)?;
            }
            if bytes.len() > cap {
                let _ = overflow.send(());
            }
            Ok(bytes)
        };
        let stdout_overflow = overflow.clone();
        let out = scope.spawn(move || {
            read(
                stdout.map(|p| Box::new(p) as Box<dyn Read + Send>),
                stdout_overflow,
            )
        });
        let err = scope.spawn(move || {
            read(
                stderr.map(|p| Box::new(p) as Box<dyn Read + Send>),
                overflow,
            )
        });
        let status = child.wait()?;
        Ok(Output {
            status,
            stdout: out
                .join()
                .map_err(|_| std::io::Error::other("stdout reader failed"))??,
            stderr: err
                .join()
                .map_err(|_| std::io::Error::other("stderr reader failed"))??,
        })
    })
}

fn wait_process(
    child: std::process::Child,
    timeout: Duration,
    cancelled: Option<&crate::RuntimePermit>,
) -> Result<Output, crate::effect::Observation> {
    wait_process_with_limit(child, timeout, cancelled, None)
}
fn wait_process_with_limit(
    child: std::process::Child,
    timeout: Duration,
    cancelled: Option<&crate::RuntimePermit>,
    cap: Option<usize>,
) -> Result<Output, crate::effect::Observation> {
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    let (overflow_tx, overflow_rx) = mpsc::channel();
    thread::spawn(move || {
        let result = match cap {
            Some(cap) => bounded_output(child, cap, overflow_tx),
            None => child.wait_with_output(),
        };
        let _ = tx.send(result);
    });
    let deadline = Instant::now() + timeout;
    loop {
        if overflow_rx.try_recv().is_ok() {
            kill_process_group(pid);
            // This child is ours and has been killed; reap before returning,
            // bounded like the deadline path so a failed kill cannot hang a worker.
            let _ = rx.recv_timeout(Duration::from_secs(1));
            return Err(RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "helper output exceeds limit",
            )
            .into());
        }
        let preempted = cancelled.is_some_and(|c| c.is_cancelled());
        if preempted || Instant::now() >= deadline {
            if let Ok(result) = rx.try_recv() {
                return result.map_err(|e| {
                    crate::effect::Observation::from(RuntimeError::new(
                        SandboxErrorCode::UnknownOutcome,
                        format!("incus wait failed: {e}"),
                    ))
                });
            }
            kill_process_group(pid);
            let _ = rx.recv_timeout(Duration::from_secs(1));
            return Err(RuntimeError::new(
                if preempted {
                    SandboxErrorCode::UnknownOutcome
                } else {
                    SandboxErrorCode::Timeout
                },
                "incus command ended without a confirmed outcome",
            )
            .into());
        }
        match rx.recv_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(10)),
        ) {
            Ok(result) => {
                return result.map_err(|e| {
                    crate::effect::Observation::from(RuntimeError::new(
                        SandboxErrorCode::UnknownOutcome,
                        format!("incus wait failed: {e}"),
                    ))
                });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(
                    RuntimeError::new(SandboxErrorCode::UnknownOutcome, "incus wait lost").into(),
                );
            }
        }
    }
}

pub(super) fn kill_process_group(pid: u32) {
    let Some(group) = host_group_kill_arg(pid, own_process_group()) else {
        return;
    };
    // Its own process group with no terminal stdio, like every other host
    // helper (C55-TB-1): a Ctrl-C to the daemon's foreground group never
    // interrupts it, and as a background group it never touches the TTY.
    let _ = crate::host_child::command("kill", crate::host_child::Environment::PathOnly)
        .args(["-KILL", "--", &group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .status();
}

/// The `kill` argument for a HOST process-group kill of a child this daemon
/// spawned as a group leader (C55 kill scoping). Refused (`None`) for pid 0
/// (`-0` is the caller's own group), pid 1 (`-1` signals every process the
/// daemon may signal), the daemon itself, and the daemon's own process group:
/// closing a terminal or cancelling a command may only ever take down the
/// supervised child's group, never the daemon, the VM or unrelated processes.
pub(crate) fn host_group_kill_arg(pid: u32, own_group: Option<u32>) -> Option<String> {
    if pid <= 1 || pid == std::process::id() || own_group == Some(pid) {
        return None;
    }
    Some(format!("-{pid}"))
}

/// The process group of `pid` from `/proc/<pid>/stat` (field 5), read without
/// touching the process. `None` when unreadable.
pub(crate) fn process_group_of(pid: &str) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat_process_group(&stat)
}

/// Parse the process group out of one `/proc/<pid>/stat` line. `comm` may
/// contain spaces and `)`, so the fields after it start at the LAST `)`.
pub(crate) fn stat_process_group(stat: &str) -> Option<u32> {
    let (_, rest) = stat.rsplit_once(')')?;
    // state, ppid, pgrp, ...
    rest.split_whitespace().nth(2)?.parse().ok()
}

fn own_process_group() -> Option<u32> {
    process_group_of("self")
}

fn map_output(output: Output) -> IncusCommandOutput {
    IncusCommandOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code().unwrap_or(-1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// C55 kill scoping: the host group kill can never target init, every
    /// process (`-1`), the caller's own group (`-0`), the daemon itself or the
    /// daemon's own process group. Pure: no signal is sent by this test.
    #[test]
    fn c55_host_group_kill_never_targets_the_daemon_or_unrelated_processes() {
        let me = std::process::id();
        let own = own_process_group();
        assert!(own.is_some(), "the test process has a readable group");
        for pid in [0, 1, me] {
            assert_eq!(host_group_kill_arg(pid, own), None, "pid {pid}");
        }
        if let Some(group) = own {
            assert_eq!(host_group_kill_arg(group, own), None, "own group");
        }
        // A child's own group (pgid == pid of the setsid leader) is allowed.
        let child = me.wrapping_add(7919).max(2);
        assert_eq!(
            host_group_kill_arg(child, Some(child + 1)),
            Some(format!("-{child}"))
        );
        assert_eq!(
            stat_process_group("42 (a) b) c) S 7 42 42 0 -1"),
            Some(42),
            "comm with `)` and spaces"
        );
        assert_eq!(stat_process_group("garbage"), None);
    }

    fn out(stderr: &str, exit_code: i32) -> IncusCommandOutput {
        IncusCommandOutput {
            stdout: String::new(),
            stderr: stderr.to_string(),
            exit_code,
        }
    }

    #[test]
    fn query_urls_encode_project_and_merge_params() {
        assert_eq!(
            instance_query_url("wssp-sbx-1", "default").expect("url"),
            "/1.0/instances/wssp-sbx-1?project=default"
        );
        assert_eq!(
            instance_query_url("wssp-sbx-1", "custom").expect("url"),
            "/1.0/instances/wssp-sbx-1?project=custom"
        );
        assert_eq!(
            instance_query_url("wssp-sbx-1", "foo bar").expect("url"),
            "/1.0/instances/wssp-sbx-1?project=foo%20bar"
        );
        assert_eq!(
            project_query_url("wssp").expect("project url"),
            "/1.0/projects/wssp?project=default"
        );
        assert_eq!(
            instance_state_query_url("wssp-sbx-1", "default").expect("state url"),
            "/1.0/instances/wssp-sbx-1/state?project=default"
        );
        assert_eq!(
            with_query_params(
                "/1.0/instances/wssp-sbx-1/files",
                &[("path", "/x/permission denied"), ("project", "default")]
            ),
            "/1.0/instances/wssp-sbx-1/files?path=%2Fx%2Fpermission%20denied&project=default"
        );
    }

    #[test]
    fn malicious_instance_names_are_rejected_before_incus_argv() {
        let client = IncusClient::new("/nonexistent-wssp-incus", "wssp");
        let names = [
            "ubuntu",
            "-wssp-sbx-1",
            "wssp-sbx-/etc/passwd",
            "wssp-sbx-foo/bar",
            "wssp-sbx-foo%2Fbar",
            "wssp-sbx-foo%00",
            "default",
            "../wssp-sbx-1",
        ];
        let plan = crate::incus::network::test_plan("sbx-1");
        for name in names {
            let err = client
                .init_vm(
                    "images:ubuntu/24.04/cloud",
                    name,
                    &plan,
                    sandbox_protocol::VmSize::defaults().unwrap(),
                    &test_identity(),
                    &[],
                )
                .expect_err(name);
            assert_eq!(err.code, SandboxErrorCode::ProtocolError, "{name}");
            let err = client
                .bind_instance(
                    name,
                    "sbx",
                    &crate::CreateSandboxRequest::for_test("sbx", "key").template_digest,
                    None,
                )
                .unwrap_err();
            assert_eq!(err.code, SandboxErrorCode::ProtocolError);
            let err = guest_file_target(name, "/root/a").expect_err(name);
            assert_eq!(err.code, SandboxErrorCode::ProtocolError, "{name}");
            assert!(instance_query_url(name, "wssp").is_err(), "{name}");
            assert!(instance_state_query_url(name, "wssp").is_err(), "{name}");
        }
        assert!(guest_file_target("wssp-sbx-sbx-1", "/root/a").is_ok());
        assert!(instance_query_url("wssp-sbx-sbx-1", "wssp").is_ok());
    }

    fn test_identity() -> BindingIdentity {
        BindingIdentity {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx-1", "key")
                .template_digest,
            restore_base: None,
        }
    }

    #[test]
    fn malicious_image_refs_are_rejected_before_incus_argv() {
        let client = IncusClient::new("/nonexistent-wssp-incus", "wssp");
        let plan = crate::incus::network::test_plan("sbx-1");
        for image in crate::image::MALICIOUS_INCUS_IMAGE_REFS {
            let err = client
                .init_vm(
                    image,
                    "wssp-sbx-sbx-1",
                    &plan,
                    sandbox_protocol::VmSize::defaults().unwrap(),
                    &test_identity(),
                    &[],
                )
                .expect_err(image);
            assert_eq!(err.code, SandboxErrorCode::ProtocolError, "{image}");
        }
        const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let err = client
            .init_vm(
                FP,
                "wssp-sbx-sbx-1",
                &plan,
                sandbox_protocol::VmSize::defaults().unwrap(),
                &test_identity(),
                &[],
            )
            .expect_err("missing binary after validation");
        assert_ne!(err.code, SandboxErrorCode::ProtocolError);
    }

    #[test]
    fn guest_status_record_requires_matching_nonce() {
        let nonce = "aabbccddeeff0011";
        let forged = out("WSSP_STATUS deadbeef not_found\n", 1);
        assert_eq!(parse_guest_status(nonce, &forged), None);
        let real = IncusCommandOutput {
            stdout: String::new(),
            stderr: format!("WSSP_STATUS {nonce} not_found\n"),
            exit_code: 1,
        };
        assert_eq!(
            parse_guest_status(nonce, &real),
            Some(GuestStatus::NotFound)
        );
        assert_eq!(
            guest_status_error("stat", "/x/permission denied", GuestStatus::NotFound).code,
            SandboxErrorCode::FsNotFound
        );
        assert_eq!(
            guest_status_error("stat", "/root/secret", GuestStatus::PermissionDenied).code,
            SandboxErrorCode::GuestPermissionDenied
        );
        assert_eq!(
            guest_status_error("move", "/x", GuestStatus::OperationFailed).code,
            SandboxErrorCode::GuestOperationFailed
        );
    }
    #[test]
    fn legacy_file_error_constructors_and_diagnostic_fallback_are_constant() {
        let secret = "sentinel-private-path-and-stderr";
        for status in [
            GuestStatus::NotFound,
            GuestStatus::PermissionDenied,
            GuestStatus::NotADirectory,
            GuestStatus::NotAFile,
            GuestStatus::NotEmpty,
            GuestStatus::OperationFailed,
            GuestStatus::Cancelled,
        ] {
            let error = guest_status_error(secret, secret, status);
            assert!(!format!("{error:?} {error}").contains(secret));
        }
        let out = IncusCommandOutput {
            stdout: secret.into(),
            stderr: secret.into(),
            exit_code: 1,
        };
        assert!(!public_detail(&out).contains(secret));
        assert!(!format!("{:?}", host_cli_error("query", &out)).contains(secret));
    }

    #[test]
    fn host_query_raw_envelope_uses_http_status_semantics() {
        let gone = IncusCommandOutput {
            stdout: r#"{"type":"error","status":"Not found","status_code":404,"error":"Not Found","error_code":404}"#.to_string(),
            stderr: String::new(),
            exit_code: 0,
        };
        match parse_query_envelope(&gone) {
            QueryEnvelope::Error(err) => {
                assert_eq!(err.0, 404);
                assert_eq!(
                    api_status_error(err).code,
                    SandboxErrorCode::SandboxNotFound
                );
            }
            other => panic!("expected error envelope, got {other:?}"),
        }
        assert_eq!(
            api_status_error((403, "Forbidden".to_string())).code,
            SandboxErrorCode::AccessDenied
        );
        assert_eq!(
            api_status_error((500, "agent isn't currently running".to_string())).code,
            SandboxErrorCode::Internal
        );
        let guest_bytes = IncusCommandOutput {
            stdout: r#"{"type":"error","error_code":401,"error":"guest file bytes"}"#.to_string(),
            stderr: String::new(),
            exit_code: 0,
        };
        match parse_query_envelope(&guest_bytes) {
            QueryEnvelope::Error((401, _)) => {}
            other => panic!("parser still sees envelope-shaped bytes as error: {other:?}"),
        }
        let running = parse_instance_metadata(
            &serde_json::json!({"name":"wssp-sbx-1","status":"Running","status_code":103}),
            "wssp-sbx-1",
        )
        .expect("running");
        assert!(running.is_running());
        let stopped = parse_instance_metadata(
            &serde_json::json!({"name":"wssp-sbx-1","status":"Stopped","status_code":102}),
            "wssp-sbx-1",
        )
        .expect("stopped");
        assert!(stopped.is_stopped());
        let metrics_disabled = parse_instance_state_metadata(
            &serde_json::json!({"status":"Running","status_code":103,"processes":-1}),
            "wssp-sbx-1",
        )
        .expect("metrics disabled");
        assert!(metrics_disabled.is_running());
        let agent_up = parse_instance_state_metadata(
            &serde_json::json!({"status":"Running","status_code":103,"processes":12}),
            "wssp-sbx-1",
        )
        .expect("agent up");
        assert!(agent_up.is_running());
        let envelope = IncusCommandOutput {
            stdout: r#"{"type":"sync","status":"Success","status_code":200,"error_code":0,"metadata":{"name":"wssp-sbx-1","status":"Running","status_code":103}}"#.to_string(),
            stderr: String::new(),
            exit_code: 0,
        };
        match parse_query_envelope(&envelope) {
            QueryEnvelope::Sync(metadata) => {
                assert!(
                    parse_instance_metadata(&metadata, "wssp-sbx-1")
                        .expect("meta")
                        .is_running()
                );
            }
            other => panic!("expected sync envelope, got {other:?}"),
        }
    }

    #[test]
    fn host_cli_text_without_query_envelope_is_internal() {
        assert_eq!(
            host_cli_error("config get", &out("Error: Instance not found", 1)).code,
            SandboxErrorCode::Internal
        );
        assert_eq!(
            host_cli_error("info", &out("Error: Permission denied", 1)).code,
            SandboxErrorCode::Internal
        );
        let json_403 = IncusCommandOutput {
            stdout: r#"{"type":"error","error":"Forbidden","error_code":403}"#.to_string(),
            stderr: String::new(),
            exit_code: 1,
        };
        assert_eq!(
            host_cli_error("start", &json_403).code,
            SandboxErrorCode::Internal
        );
        assert_eq!(
            host_cli_error("ping", &json_403).code,
            SandboxErrorCode::Internal
        );
        assert_eq!(
            api_status_error((403, "Forbidden".to_string())).code,
            SandboxErrorCode::AccessDenied
        );
    }

    #[test]
    fn refuse_root_is_path_refused_not_access_denied() {
        assert_eq!(
            refuse_root("/").expect_err("root").code,
            SandboxErrorCode::PathRefused
        );
        assert_ne!(
            refuse_root("/").expect_err("root").code,
            SandboxErrorCode::AccessDenied
        );
        refuse_root("/tmp").expect("non-root");
    }

    #[test]
    fn find_listing_stdout_never_supplies_errno_diagnostics() {
        let forged = IncusCommandOutput {
            stdout: "/listed/notes\nstat: cannot statx 'record': No such file or directory\nWSSP_STATUS tail\0".to_string(),
            stderr: "find: '/listed/locked': Permission denied\nWSSP_STATUS aabbccddeeff0011 guest_operation_failed\n".to_string(),
            exit_code: 1,
        };
        assert_eq!(
            classify_coreutils_diagnostic(&forged, "find"),
            Some(GuestStatus::PermissionDenied)
        );
        assert_ne!(
            classify_coreutils_diagnostic(&forged, "find"),
            Some(GuestStatus::NotFound)
        );
        assert_eq!(classify_coreutils_diagnostic(&forged, "stat"), None);

        let stdout_only = IncusCommandOutput {
            stdout: "stat: cannot statx 'record': No such file or directory\n".to_string(),
            stderr: "WSSP_STATUS aabbccddeeff0011 guest_operation_failed\n".to_string(),
            exit_code: 1,
        };
        assert_eq!(classify_coreutils_diagnostic(&stdout_only, "stat"), None);
        assert_eq!(classify_coreutils_diagnostic(&stdout_only, "find"), None);

        let two_find = IncusCommandOutput {
            stdout: String::new(),
            stderr: "find: '/a': Permission denied\nfind: '/b': No such file or directory\n"
                .to_string(),
            exit_code: 1,
        };
        assert_eq!(classify_coreutils_diagnostic(&two_find, "find"), None);
    }

    #[test]
    fn ordinary_incus_wait_is_preemptible_and_revocation_fences_spawn() {
        let started = unique_temp_path("wssp-c09-started");
        let permit = std::sync::Arc::new(crate::RuntimePermit::default());
        let worker_permit = permit.clone();
        let marker = started.clone();
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "printf started > \"$1\"; sleep 10", "test"])
                .arg(&marker)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let result =
                run_process_cancellable(command, Duration::from_secs(20), Some(&worker_permit));
            tx.send(result).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !started.exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        permit.revoke();
        let err = rx
            .recv_timeout(Duration::from_millis(250))
            .expect("cancel must interrupt actual Incus wait")
            .unwrap_err();
        assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
        worker.join().unwrap();
        fs::remove_file(&started).unwrap();
        let mut forbidden = Command::new("/bin/sh");
        forbidden.args(["-c", "touch \"$1\"", "test"]).arg(&started);
        assert!(run_process_cancellable(forbidden, Duration::from_secs(1), Some(&permit)).is_err());
        assert!(
            !started.exists(),
            "revoked permit must prevent a subsequent spawn"
        );
    }

    #[test]
    fn census_deadline_and_shutdown_survive_recovery_clearing_the_operation_permit() {
        for revoke in [false, true] {
            let (mut client, log) = crate::incus::shim_tests::client_for_with_log("running");
            let started = log.parent().unwrap().join("census-child");
            crate::incus::shim_tests::install_executable(
                Path::new(&client.binary),
                &format!(
                    "#!/bin/sh\nprintf started > '{}'\nexec sleep 30\n",
                    started.display()
                ),
                0o700,
            );
            let permit = std::sync::Arc::new(crate::RuntimePermit::with_timeout(
                Duration::from_millis(200),
            ));
            client.inspection_permit = Some(permit.clone());
            // This is the recovery/pre-fence clone, independent of the
            // issuing operation but still inside the startup census.
            client.cancelled = None;
            let worker_client = client.clone();
            let (tx, rx) = mpsc::channel();
            let worker = thread::spawn(move || {
                let _ = tx.send(worker_client.run(&["version"], false));
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while !started.exists() {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            }
            if revoke {
                permit.revoke();
            }
            let outcome = rx.recv_timeout(Duration::from_secs(1));
            // Always clean up the owned fixture, including a failing mutation.
            client.shutdown_local_children().unwrap();
            worker.join().unwrap();
            let error = outcome
                .expect("census scope must interrupt recovery IO")
                .unwrap_err();
            assert_eq!(error.code, SandboxErrorCode::UnknownOutcome);
        }
    }

    #[test]
    fn final_shutdown_kills_permit_independent_children_and_closes_spawn_admission() {
        for settle in [false, true] {
            let (mut client, log) = crate::incus::shim_tests::client_for_with_log("running");
            let started = log.parent().unwrap().join("shutdown-child");
            crate::incus::shim_tests::install_executable(
                Path::new(&client.binary),
                &format!(
                    "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nexec sleep 30\n",
                    started.display()
                ),
                0o700,
            );
            client.cancelled = None;
            client.settle_create = settle;
            let worker_client = client.clone();
            let (tx, rx) = mpsc::channel();
            let worker = thread::spawn(move || {
                let _ = tx.send(worker_client.run(&["version"], false));
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while !started.exists() {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            }
            let pid = fs::read_to_string(&started).unwrap();
            client
                .shutdown_local_children()
                .expect("reap final-shutdown children");
            let out = rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
            assert_ne!(out.exit_code, 0);
            worker.join().unwrap();
            assert!(!Path::new(&format!("/proc/{pid}")).exists());
            fs::remove_file(&started).unwrap();
            assert!(client.run(&["version"], false).is_err());
            assert!(
                !started.exists(),
                "a clone cannot spawn after final shutdown"
            );
        }
    }

    #[test]
    fn run_process_keeps_a_child_that_exits_inside_the_final_poll() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 0.08; exit 0"]);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let output = run_process(command, Duration::from_millis(100)).expect("completed in budget");
        assert_eq!(output.status.code(), Some(0));
    }

    /// C55-R2-2 (C55-TB-1): a body-less host helper runs as its own
    /// process-group leader with /dev/null stdin, so a terminal Ctrl-C to the
    /// daemon's foreground group never reaches it and it never reads the TTY.
    /// Runs in a contained child that is not a group leader and whose stdin
    /// is a pipe, so neither property can hold by inheritance.
    #[test]
    fn run_process_helper_leads_its_own_group_with_null_stdin() {
        if super::super::shim_tests::contained_dir().is_none() {
            super::super::shim_tests::run_contained(
                "incus::client::tests::run_process_helper_leads_its_own_group_with_null_stdin",
                &std::env::temp_dir(),
            );
            return;
        }
        let me = std::process::id();
        let own = own_process_group().expect("own process group");
        assert_ne!(
            own, me,
            "precondition: the test child is not a group leader"
        );
        let stdin = std::fs::read_link("/proc/self/fd/0").expect("own stdin");
        assert_ne!(
            stdin,
            std::path::Path::new("/dev/null"),
            "precondition: the test child's stdin is not /dev/null"
        );
        let mut command = Command::new("/bin/sh");
        // pid, pgrp (field 5 of /proc/<pid>/stat, after the last `)`), stdin.
        command.args([
            "-c",
            "set -- $(sed 's/.*)//' /proc/$$/stat); echo \"$$ $3 $(readlink /proc/$$/fd/0)\"",
        ]);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let output = run_process(command, Duration::from_secs(5)).expect("helper ran");
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let parts: Vec<&str> = text.split_whitespace().collect();
        assert_eq!(parts.len(), 3, "{text:?}");
        assert_eq!(
            parts[0], parts[1],
            "helper must lead its own group: {text:?}"
        );
        assert_ne!(
            parts[1],
            own.to_string(),
            "helper must not share the daemon's group: {text:?}"
        );
        assert_eq!(parts[2], "/dev/null", "helper stdin: {text:?}");
    }

    #[test]
    fn run_process_times_out_a_hung_child_within_the_deadline() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 10"]);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let started = Instant::now();
        let err = run_process(command, Duration::from_millis(80)).expect_err("timeout");
        assert_eq!(err.code, SandboxErrorCode::Timeout);
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "hung child must be reaped near the deadline, got {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn nonce_is_128_bit_hex_from_csprng() {
        let first = random_nonce().expect("nonce");
        let second = random_nonce().expect("nonce");
        assert_eq!(first.len(), 32);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn coreutils_grammar_maps_only_proven_strerror() {
        assert_eq!(
            parse_gnu_tool_strerror("stat: cannot statx '/tmp/missing': No such file or directory"),
            Some("No such file or directory")
        );
        assert_eq!(
            parse_gnu_tool_strerror(
                "mkdir: cannot create directory '/tmp/ro/new': Permission denied"
            ),
            Some("Permission denied")
        );
        assert_eq!(
            parse_gnu_tool_strerror(
                "mv: cannot move '/a' to '/no-such-dir/b': No such file or directory"
            ),
            Some("No such file or directory")
        );
        assert_eq!(
            parse_gnu_tool_strerror("rmdir: failed to remove '/tmp/ne': Directory not empty"),
            Some("Directory not empty")
        );
        assert_eq!(
            parse_gnu_tool_strerror("find: '/tmp/hidden': Permission denied"),
            Some("Permission denied")
        );
        assert_eq!(
            parse_gnu_tool_strerror("stat: cannot statx '/tmp/long': File name too long"),
            Some("File name too long")
        );
        assert_eq!(
            status_from_strerror("File name too long"),
            GuestStatus::OperationFailed
        );
        assert_eq!(
            status_from_strerror("File exists"),
            GuestStatus::OperationFailed
        );
        assert_eq!(
            status_from_strerror("Too many levels of symbolic links"),
            GuestStatus::OperationFailed
        );
        assert!(
            parse_gnu_tool_strerror("mkdir: can't create directory '/x': File exists").is_none()
        );
        assert!(parse_gnu_tool_strerror("Error: permission denied").is_none());
        assert!(
            parse_gnu_tool_strerror("mv: '/tmp/src' and '/tmp/src' are the same file").is_none()
        );
        let newline =
            "stat: cannot statx '/tmp/parent'$'\\n''name/nope': No such file or directory";
        let (path, rest) =
            parse_coreutils_quoted(&newline["stat: cannot statx ".len()..]).expect("quoted");
        assert_eq!(path, "/tmp/parent\nname/nope");
        assert_eq!(rest, ": No such file or directory");
    }

    #[test]
    fn pull_enoent_requires_sftp_status_not_path_text() {
        assert!(error_line_proves_enoent("Error: not found"));
        assert!(error_line_proves_enoent(
            "Error: sftp: \"open /tmp/x: no such file or directory\" (SSH_FX_NO_SUCH_FILE)"
        ));
        assert!(!error_line_proves_enoent("Error: permission denied"));
        assert!(!error_line_proves_enoent(
            "Error: sftp: \"open /tmp/instance not found: too many levels of symbolic links\" (SSH_FX_FAILURE)"
        ));
        assert!(!error_line_proves_enoent(
            "Error: sftp: \"open /tmp/no such file or directory: too many levels of symbolic links\" (SSH_FX_FAILURE)"
        ));
        assert!(!error_line_proves_enoent(
            "Error: The instance's agent isn't currently running"
        ));
    }

    #[test]
    fn readable_script_reports_real_missing_and_dangling_paths_before_pull() {
        let dir = std::env::temp_dir().join(format!("wssp-readable-{}", random_nonce().unwrap()));
        fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("missing permission denied");
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(&missing, &dangling).unwrap();
        for path in [&missing, &dangling] {
            let out = run_wrapper(
                GUEST_READABLE_SCRIPT,
                "wssp-readable",
                &[path.to_str().unwrap()],
            );
            assert_ne!(out.exit_code, 0);
            assert_eq!(
                classify_coreutils_diagnostic(&out, "stat"),
                Some(GuestStatus::NotFound)
            );
            assert!(out.stdout.is_empty());
        }
        let readable = dir.join("readable");
        fs::write(&readable, b"data").unwrap();
        let out = run_wrapper(
            GUEST_READABLE_SCRIPT,
            "wssp-readable",
            &[readable.to_str().unwrap()],
        );
        assert_eq!(out.exit_code, 0);
        assert_eq!(
            out.stdout,
            "WSSP_READABLE 0123456789abcdef0123456789abcdef\n"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    fn run_wrapper(script: &str, helper: &str, args: &[&str]) -> IncusCommandOutput {
        let nonce = "0123456789abcdef0123456789abcdef";
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .arg(helper)
            .arg(nonce)
            .args(args)
            .output()
            .expect("run wrapper");
        IncusCommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(-1),
        }
    }

    fn helper_tool(helper: &str, args: &[&str]) -> &'static str {
        match helper {
            "wssp-stat" => "stat",
            "wssp-list" => "find",
            "wssp-mkdir" => "mkdir",
            "wssp-move" => "mv",
            "wssp-remove" => {
                if args.contains(&"rmdir") {
                    "rmdir"
                } else {
                    "rm"
                }
            }
            other => panic!("unknown helper {other}"),
        }
    }

    fn wrapper_status(out: &IncusCommandOutput, helper: &str, args: &[&str]) -> GuestStatus {
        let nonce = "0123456789abcdef0123456789abcdef";
        match parse_guest_status(nonce, out) {
            Some(GuestStatus::Ok) => GuestStatus::Ok,
            Some(_) => classify_coreutils_diagnostic(out, helper_tool(helper, args))
                .unwrap_or(GuestStatus::OperationFailed),
            None => panic!(
                "wrapper emitted no status (exit {}, stderr {})",
                out.exit_code, out.stderr
            ),
        }
    }

    struct Fixture {
        root: std::path::PathBuf,
        restore: Vec<(std::path::PathBuf, u32)>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            for (path, mode) in self.restore.drain(..).rev() {
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(mode));
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    impl Fixture {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let root =
                std::env::temp_dir().join(format!("wssp-wrapper-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&root).expect("fixture");
            Self {
                root,
                restore: Vec::new(),
            }
        }

        fn chmod(&mut self, path: &std::path::Path, mode: u32) {
            use std::os::unix::fs::PermissionsExt;
            let current = fs::metadata(path).expect("meta").permissions().mode();
            self.restore.push((path.to_path_buf(), current));
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
        }
    }

    fn assert_not_specific_wrong(status: GuestStatus, forbidden: GuestStatus, why: &str) {
        assert_ne!(status, forbidden, "{why}: got {status:?}");
    }

    #[test]
    fn wrappers_classify_c2_errno_table() {
        let mut fx = Fixture::new();
        let missing = fx.root.join("definitely-missing");
        let missing_args = [missing.to_str().unwrap()];
        let stat_missing = wrapper_status(
            &run_wrapper(GUEST_STAT_SCRIPT, "wssp-stat", &missing_args),
            "wssp-stat",
            &missing_args,
        );
        assert_eq!(stat_missing, GuestStatus::NotFound);

        let long_name = "a".repeat(256);
        let too_long = fx.root.join(&long_name);
        for (script, helper, args) in [
            (
                GUEST_STAT_SCRIPT,
                "wssp-stat",
                vec![too_long.to_str().unwrap().to_string()],
            ),
            (
                GUEST_LIST_SCRIPT,
                "wssp-list",
                vec![too_long.to_str().unwrap().to_string(), "1".to_string()],
            ),
            (
                GUEST_MOVE_SCRIPT,
                "wssp-move",
                vec![
                    too_long.to_str().unwrap().to_string(),
                    fx.root.join("dest").to_str().unwrap().to_string(),
                ],
            ),
            (
                GUEST_REMOVE_SCRIPT,
                "wssp-remove",
                vec![
                    too_long.to_str().unwrap().to_string(),
                    "rm".to_string(),
                    "--".to_string(),
                    too_long.to_str().unwrap().to_string(),
                ],
            ),
        ] {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let status = wrapper_status(&run_wrapper(script, helper, &args), helper, &args);
            assert_eq!(
                status,
                GuestStatus::OperationFailed,
                "{helper} ENAMETOOLONG got {status:?}"
            );
        }

        let exists = fx.root.join("exists-file");
        fs::write(&exists, b"f").expect("exists");
        let root = fx.root.clone();
        fx.chmod(&root, 0o555);
        let mkdir_args = [exists.to_str().unwrap()];
        let mkdir_exist = wrapper_status(
            &run_wrapper(GUEST_MKDIR_SCRIPT, "wssp-mkdir", &mkdir_args),
            "wssp-mkdir",
            &mkdir_args,
        );
        fx.chmod(&root, 0o755);
        assert_eq!(mkdir_exist, GuestStatus::OperationFailed);

        let src = fx.root.join("src-file");
        fs::write(&src, b"hi").expect("src");
        fx.chmod(&root, 0o555);
        let same_args = [src.to_str().unwrap(), src.to_str().unwrap()];
        let same = wrapper_status(
            &run_wrapper(GUEST_MOVE_SCRIPT, "wssp-move", &same_args),
            "wssp-move",
            &same_args,
        );
        fx.chmod(&root, 0o755);
        assert_eq!(same, GuestStatus::OperationFailed);

        let loop_link = fx.root.join("loop");
        std::os::unix::fs::symlink("loop", &loop_link).expect("symlink");
        let loop_path = loop_link.join("x");
        let eloop_args = [loop_path.to_str().unwrap()];
        let eloop = wrapper_status(
            &run_wrapper(GUEST_STAT_SCRIPT, "wssp-stat", &eloop_args),
            "wssp-stat",
            &eloop_args,
        );
        assert_eq!(eloop, GuestStatus::OperationFailed);

        let dest = fx.root.join("no-such-dir").join("dest");
        let mv_args = [src.to_str().unwrap(), dest.to_str().unwrap()];
        let mv_missing = wrapper_status(
            &run_wrapper(GUEST_MOVE_SCRIPT, "wssp-move", &mv_args),
            "wssp-move",
            &mv_args,
        );
        assert_not_specific_wrong(
            mv_missing,
            GuestStatus::PermissionDenied,
            "mv to missing dest parent",
        );

        let hidden = fx.root.join("hidden");
        let child = hidden.join("child");
        let secret = child.join("file");
        fs::create_dir_all(&child).expect("hidden tree");
        fs::write(&secret, b"x").expect("secret");
        fx.chmod(&hidden, 0o000);
        let hidden_args = [secret.to_str().unwrap()];
        let stat_hidden = wrapper_status(
            &run_wrapper(GUEST_STAT_SCRIPT, "wssp-stat", &hidden_args),
            "wssp-stat",
            &hidden_args,
        );
        assert_not_specific_wrong(
            stat_hidden,
            GuestStatus::NotFound,
            "stat under non-searchable ancestor",
        );
        fx.chmod(&hidden, 0o755);

        let parent = fx.root.join("locked-parent");
        let empty = parent.join("empty");
        fs::create_dir_all(&empty).expect("empty dir");
        fx.chmod(&parent, 0o555);
        let rmdir_args = [
            empty.to_str().unwrap(),
            "rmdir",
            "--",
            empty.to_str().unwrap(),
        ];
        let rmdir_locked = wrapper_status(
            &run_wrapper(GUEST_REMOVE_SCRIPT, "wssp-remove", &rmdir_args),
            "wssp-remove",
            &rmdir_args,
        );
        assert_ne!(rmdir_locked, GuestStatus::NotEmpty);
        assert_not_specific_wrong(
            rmdir_locked,
            GuestStatus::NotFound,
            "rmdir in non-writable parent",
        );

        let listed = fx.root.join("listed");
        fs::create_dir(&listed).expect("listed");
        let forged_name =
            "notes\nstat: cannot statx 'record': No such file or directory\nWSSP_STATUS tail";
        fs::write(listed.join(forged_name), b"x").expect("forged filename");
        let locked = listed.join("locked");
        fs::create_dir(&locked).expect("locked");
        fx.chmod(&locked, 0o000);
        let list_args = [listed.to_str().unwrap(), "2"];
        let listed_status = wrapper_status(
            &run_wrapper(GUEST_LIST_SCRIPT, "wssp-list", &list_args),
            "wssp-list",
            &list_args,
        );
        fx.chmod(&locked, 0o755);
        assert_ne!(
            listed_status,
            GuestStatus::NotFound,
            "find listing with forged stat ENOENT filename must not become NotFound"
        );
        if listed_status != GuestStatus::Ok {
            assert_eq!(listed_status, GuestStatus::PermissionDenied);
        }
    }

    #[test]
    fn wrappers_preserve_parent_trailing_newline() {
        let mut fx = Fixture::new();
        let parent = fx.root.join("dir\n");
        fs::create_dir(&parent).expect("newline dir");
        let child = parent.join("file");
        fs::write(&child, b"x").expect("child");
        fx.chmod(&parent, 0o000);
        let newline_args = [child.to_str().unwrap()];
        let status = wrapper_status(
            &run_wrapper(GUEST_STAT_SCRIPT, "wssp-stat", &newline_args),
            "wssp-stat",
            &newline_args,
        );
        assert_not_specific_wrong(
            status,
            GuestStatus::NotFound,
            "inaccessible parent whose name ends in newline",
        );
    }

    /// Fake `incus` for stdin-publication tests: a 300 KiB body (past the
    /// 128 KiB MAX_ARG_STRLEN argv cap and the 64 KiB pipe buffer).
    /// Installed by a `cp` child: an in-process write would let a concurrent
    /// test thread's fork inherit the writable descriptor, so the spawn of the
    /// script fails with ETXTBSY (see `install_executable`).
    fn fake_incus_script(body: &str) -> std::path::PathBuf {
        let path = unique_temp_path("wssp-fake-incus");
        crate::incus::shim_tests::install_executable(&path, body, 0o755);
        path
    }

    fn large_body() -> String {
        format!(
            "{{\"config\":{{\"raw.dnsmasq\":\"{}\"}}}}",
            "x".repeat(300 * 1024)
        )
    }

    #[test]
    fn concurrent_acl_cli_edits_cannot_overwrite_each_other() {
        let dir = probe_dir();
        let count = dir.join("count");
        fs::write(&count, "0").unwrap();
        // Model the CLI's GET -> PUT, with no daemon-side compare-and-swap.
        let script = fake_incus_script(&format!(
            "#!/bin/sh\nn=$(cat '{}')\nsleep 0.02\necho $((n+1)) > '{}'\n",
            count.display(),
            count.display()
        ));
        let client = IncusClient::new(script.to_str().unwrap(), "default");
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let client = &client;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..4 {
                        let out = client
                            .run_bounded(
                                &[
                                    "network",
                                    "acl",
                                    "rule",
                                    "add",
                                    "wsn-test",
                                    "egress",
                                    "action=reject",
                                ],
                                false,
                                Duration::from_secs(5),
                            )
                            .unwrap();
                        assert_eq!(out.exit_code, 0);
                    }
                });
            }
        });
        assert_eq!(fs::read_to_string(&count).unwrap().trim(), "16");
        fs::remove_file(script).unwrap();
    }

    #[test]
    fn stalled_acl_edit_yields_before_the_next_expiry_fence_budget() {
        let script = fake_incus_script("#!/bin/sh\nsleep 30\n");
        let client = IncusClient::new(script.to_str().unwrap(), "default");
        let started = Instant::now();
        let error = client
            .run_bounded(
                &[
                    "network",
                    "acl",
                    "rule",
                    "remove",
                    "wsn-test",
                    "egress",
                    "description=wssp-dns-lease-quarantine-g1-abcdef01",
                ],
                false,
                Duration::from_secs(20),
            )
            .unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::Timeout);
        assert!(started.elapsed() < Duration::from_secs(8));
        fs::remove_file(script).unwrap();
    }

    #[test]
    fn stdin_body_streams_while_the_child_writes_output_first() {
        // The child floods stderr BEFORE reading stdin: a stdin write that
        // ran before output collection would deadlock against the full
        // stderr pipe. The concurrent writer must stream the body while the
        // wait drains output, so this completes well under the deadline.
        let script = fake_incus_script(
            "#!/bin/sh\n\
             python3 -c 'import sys; sys.stderr.write(\"y\"*1048576); sys.stderr.flush()'\n\
             cat > /dev/null\n\
             printf '%s' '{\"type\":\"sync\",\"status_code\":200,\"error_code\":0,\"metadata\":{\"delivered\":true}}'\n",
        );
        let mut client = IncusClient::new(script.to_str().unwrap(), "default");
        client.agent_timeout = Duration::from_secs(15);
        let started = Instant::now();
        let meta = client
            .query_patch("/1.0/networks/wsn-test?project=default", &large_body())
            .expect("concurrent stdin + output collection");
        assert_eq!(meta.get("delivered").and_then(|v| v.as_bool()), Some(true));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "must not stall: {:?}",
            started.elapsed()
        );
        let _ = fs::remove_file(script);
    }

    #[test]
    fn unread_stdin_is_killed_at_the_deadline() {
        // The child never reads stdin and never exits on its own within the
        // test budget: the write can never complete, so the caller deadline
        // (measured from spawn) must kill and reap the child, unblocking
        // the writer (EPIPE) — the sandbox lock is not parked for 30s.
        let script = fake_incus_script("#!/bin/sh\nsleep 30\n");
        let mut client = IncusClient::new(script.to_str().unwrap(), "default");
        client.agent_timeout = Duration::from_millis(500);
        let started = Instant::now();
        let err = client
            .query_patch("/1.0/networks/wsn-test?project=default", &large_body())
            .expect_err("deadline must fire while stdin stays unread");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "killed at the deadline, not after the child: {:?}",
            started.elapsed()
        );
        assert_eq!(
            err.code,
            SandboxErrorCode::Timeout,
            "unconfirmed after the deadline: {err}"
        );
        let _ = fs::remove_file(script);
    }

    // ---- reviewer probes (incus7-query-r1) ----
    fn probe_dir() -> std::path::PathBuf {
        let d = unique_temp_path("wssp-probe");
        fs::create_dir_all(&d).unwrap();
        d
    }
    const OK_ENV: &str = "{\"type\":\"sync\",\"status_code\":200,\"error_code\":0,\"metadata\":{}}";

    #[test]
    fn unknown_flag_text_with_exit_zero_does_not_fall_back() {
        let d = probe_dir();
        let script = fake_incus_script(&format!(
            "#!/bin/sh\necho \"$*\" >> {log}\necho 'Error: unknown flag: --data-file' >&2\nexit 0\n",
            log = d.join("calls").display()
        ));
        let client = IncusClient::new(script.to_str().unwrap(), "default");
        let err = client
            .query_patch_timed("/1.0/networks/n", "{\"config\":{}}", Duration::from_secs(5))
            .expect_err("exit 0 with no envelope is unparseable");
        let calls = fs::read_to_string(d.join("calls")).unwrap();
        assert_eq!(calls.lines().count(), 1, "no retry: {calls}");
        eprintln!("PROBE A err={err}");
    }

    #[test]
    fn daemon_side_unknown_flag_text_after_apply_resends_same_body() {
        // A first attempt that "applied" and then failed with matching
        // stderr: the fallback re-sends the IDENTICAL body inline.
        let d = probe_dir();
        let script = fake_incus_script(&format!(
            "#!/bin/sh\necho \"$*\" >> {log}\ncase \"$*\" in *--data-file*) cat >> {applied}; echo 'Error: daemon said unknown flag: --data-file' >&2; exit 1;; esac\nprintf '%s' '{ok}'\n",
            log = d.join("calls").display(),
            applied = d.join("applied").display(),
            ok = OK_ENV
        ));
        let client = IncusClient::new(script.to_str().unwrap(), "default");
        let body = "{\"config\":{\"raw.dnsmasq\":\"a\"}}";
        client
            .query_patch_timed("/1.0/networks/n", body, Duration::from_secs(5))
            .expect("fallback succeeded");
        let calls = fs::read_to_string(d.join("calls")).unwrap();
        assert_eq!(calls.lines().count(), 2, "{calls}");
        assert_eq!(fs::read_to_string(d.join("applied")).unwrap(), body);
        assert!(calls.lines().nth(1).unwrap().contains(body), "{calls}");
        eprintln!("PROBE B calls={calls}");
    }

    #[test]
    fn shared_deadline_bounds_both_attempts() {
        let d = probe_dir();
        let script = fake_incus_script(&format!(
            "#!/bin/sh\necho \"$*\" >> {log}\ncase \"$*\" in *--data-file*) sleep 1; echo 'Error: unknown flag: --data-file' >&2; exit 1;; esac\nsleep 30\n",
            log = d.join("calls").display()
        ));
        let client = IncusClient::new(script.to_str().unwrap(), "default");
        let started = Instant::now();
        let err = client
            .query_patch_timed(
                "/1.0/networks/n",
                "{\"config\":{}}",
                Duration::from_millis(1800),
            )
            .expect_err("second attempt must be killed at the shared deadline");
        let el = started.elapsed();
        assert_eq!(err.code, SandboxErrorCode::Timeout, "{err}");
        assert!(el < Duration::from_millis(2600), "{el:?}");
        eprintln!("PROBE C elapsed={el:?} err={err}");
        // Deadline consumed entirely by the first attempt: no second spawn.
        let d2 = probe_dir();
        let script2 = fake_incus_script(&format!(
            "#!/bin/sh\necho \"$*\" >> {log}\nsleep 0.6; echo 'Error: unknown flag: --data-file' >&2; exit 1\n",
            log = d2.join("calls").display()
        ));
        let client2 = IncusClient::new(script2.to_str().unwrap(), "default");
        let err2 = client2
            .query_patch_timed(
                "/1.0/networks/n",
                "{\"config\":{}}",
                Duration::from_millis(500),
            )
            .expect_err("first attempt killed");
        assert_eq!(err2.code, SandboxErrorCode::Timeout, "{err2}");
        let calls2 = fs::read_to_string(d2.join("calls")).unwrap();
        assert_eq!(calls2.lines().count(), 1, "{calls2}");
    }

    #[test]
    fn inline_body_at_the_cap_spawns_and_arrives_intact() {
        let d = probe_dir();
        let script = fake_incus_script(&format!(
            "#!/bin/sh\ncase \"$*\" in *--data-file*) echo 'Error: unknown flag: --data-file' >&2; exit 1;; esac\nprintf '%s' \"$6\" > {got}\nprintf '%s' '{ok}'\n",
            got = d.join("got").display(),
            ok = OK_ENV
        ));
        let client = IncusClient::new(script.to_str().unwrap(), "default");
        let prefix = "{\"config\":{\"raw.dnsmasq\":\"";
        let suffix = "\"}}";
        let body = format!(
            "{prefix}{}{suffix}",
            "x".repeat(INLINE_QUERY_BODY_MAX - prefix.len() - suffix.len())
        );
        assert_eq!(body.len(), INLINE_QUERY_BODY_MAX);
        client
            .query_patch_timed("/1.0/networks/n", &body, Duration::from_secs(10))
            .expect("96 KiB inline argv spawns");
        assert_eq!(fs::read_to_string(d.join("got")).unwrap(), body);
        let over = format!("{body}x");
        let err = client
            .query_patch_timed("/1.0/networks/n", &over, Duration::from_secs(10))
            .expect_err("one byte over fails closed");
        assert_eq!(err.code, SandboxErrorCode::Internal);
        eprintln!("PROBE D over-err={err}");
    }
}

#[cfg(test)]
mod bounded_signal_output_tests {
    use super::*;
    #[test]
    fn signal_output_stops_at_513_bytes_and_kills_and_reaps_the_helper() {
        for redirect in ["", " >&2"] {
            let script = format!("printf '%0513d' 0{redirect}; sleep 30");
            let child = Command::new("/bin/sh")
                .args(["-c", &script])
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let pid = child.id();
            let started = Instant::now();
            let err = wait_process_with_limit(child, Duration::from_secs(10), None, Some(512))
                .unwrap_err();
            assert_eq!(
                EffectError::Unknown(err).code,
                SandboxErrorCode::UnknownOutcome
            );
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "must stop while reading, before deadline"
            );
            let live = Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(
                !live.success(),
                "helper must be killed and reaped before return"
            );
        }
        let child = Command::new("/bin/sh")
            .args(["-c", "printf '%0512d' 0 >&2"])
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let out = wait_process_with_limit(child, Duration::from_secs(2), None, Some(512)).unwrap();
        assert_eq!(out.stderr.len(), 512);
    }
}
