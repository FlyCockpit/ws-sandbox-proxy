use sandbox_protocol::{OperationState, SandboxErrorCode, SandboxLifecycleState};
use serde::{Deserialize, Serialize};

use crate::error::RuntimeError;

/// Incus instance-name prefix. Guest names are `{prefix}{sandbox_id}`.
pub const INCUS_INSTANCE_NAME_PREFIX: &str = "wssp-sbx-";

/// Default Incus instance name for a control-plane sandbox id (`wssp-sbx-<id>`).
pub fn default_incus_instance_name(sandbox_id: &str) -> String {
    format!("{INCUS_INSTANCE_NAME_PREFIX}{sandbox_id}")
}

/// Per-sandbox allocation evidence for local admission, never a wire DTO.
/// `Conflict` means an observed invalid/noncanonical config; `NoInstance` is
/// cleanup-only evidence with no VM; `Unobserved` retains a transient read error.
/// Consumers must distinguish these from an observed, validated allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfiguredSize {
    Configured(sandbox_protocol::VmSize),
    Conflict,
    NoInstance,
    Unobserved(RuntimeError),
}

/// Local runtime evidence, never a relay inventory DTO. A per-instance failure
/// does not discard the rest of the census.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryEntry {
    pub sandbox_id: String,
    pub state: SandboxLifecycleState,
    pub configured_size: ConfiguredSize,
}

/// Host-managed Incus instance names: `wssp-sbx-` + strict charset/length.
/// Rejects names that start with `-` or contain `/` or `%`.
pub fn validate_managed_instance_name(name: &str) -> Result<(), RuntimeError> {
    let rest = name.strip_prefix(INCUS_INSTANCE_NAME_PREFIX);
    let valid = rest.is_some_and(|rest| {
        (1..=54).contains(&rest.len())
            && name.len() <= 63
            && rest
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && rest
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && !rest.contains('/')
            && !name.contains('%')
            && !name.contains('/')
            && !name.starts_with('-')
    });
    if !valid {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            format!("invalid incus instance name `{name}`"),
        ));
    }
    Ok(())
}

/// The sandbox id a validated managed instance name encodes — the inverse of
/// [`default_incus_instance_name`]. Lifecycle fences that only hold an
/// instance name (e.g. the start fence, C37) derive the sandbox identity
/// here rather than trusting a caller-supplied id.
#[cfg(target_os = "linux")]
pub fn sandbox_id_from_instance_name(name: &str) -> Result<&str, RuntimeError> {
    validate_managed_instance_name(name)?;
    match name.strip_prefix(INCUS_INSTANCE_NAME_PREFIX) {
        Some(rest) => Ok(rest),
        None => Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            format!("invalid incus instance name `{name}`"),
        )),
    }
}

/// Derive the instance name from `sandbox_id`. A supplied name must match.
pub fn resolve_managed_instance_name(
    sandbox_id: &str,
    supplied: Option<&str>,
) -> Result<String, RuntimeError> {
    let derived = default_incus_instance_name(sandbox_id);
    validate_managed_instance_name(&derived)?;
    if let Some(supplied) = supplied {
        if supplied != derived {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                format!("incus instance name `{supplied}` does not match host-derived `{derived}`"),
            ));
        }
        validate_managed_instance_name(supplied)?;
    }
    Ok(derived)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestIdentity {
    pub guest_uid: u32,
    pub guest_gid: u32,
    pub guest_home: String,
    pub guest_shell: String,
}

impl GuestIdentity {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        let path_ok = |value: &str| {
            value.len() <= sandbox_protocol::RECEIPT_LIMITS.guest_path_bytes
                && value.starts_with('/')
                && value.len() > 1
                && !value.chars().any(char::is_control)
                && value
                    .split('/')
                    .skip(1)
                    .all(|p| !p.is_empty() && p != "." && p != "..")
        };
        if !(1..=sandbox_protocol::RECEIPT_LIMITS.guest_id_max).contains(&self.guest_uid)
            || !(1..=sandbox_protocol::RECEIPT_LIMITS.guest_id_max).contains(&self.guest_gid)
            || !path_ok(&self.guest_home)
            || !path_ok(&self.guest_shell)
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "invalid guest identity",
            ));
        }
        Ok(())
    }
}

impl Default for GuestIdentity {
    fn default() -> Self {
        Self {
            guest_uid: 1000,
            guest_gid: 1000,
            guest_home: "/home/user".to_string(),
            guest_shell: "/bin/bash".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxLiveProbeState {
    GuestReady,
    Stopped,
    ConfirmedAbsent,
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSandboxRequest {
    pub template_fingerprint: String,
    pub architecture: Option<String>,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub guest: GuestIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeSandboxResponse {
    pub state: SandboxLiveProbeState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSandboxRequest {
    /// Local receipt evidence, captured before recording this attempt's Effect.
    /// False for retries or when history cannot be proven. Never a wire field.
    pub first_attempt: bool,
    pub vm_size: sandbox_protocol::VmSize,
    pub lease: sandbox_protocol::HostLease,
    pub sandbox_id: String,
    pub instance_name: String,
    pub idempotency_key: String,
    /// Immutable Incus fingerprint stored as instance metadata.
    pub template_digest: String,
    pub incus_fingerprint: Option<String>,
    pub guest: GuestIdentity,
    pub architecture: Option<String>,
    /// Recorded egress policy and its canonical SHA-256 hash (M5, C34/C35).
    /// Both absent means deny-all; exactly one present fails closed.
    pub egress_policy: Option<sandbox_protocol::EgressPolicy>,
    pub egress_policy_hash: Option<String>,
    /// Node egress settings captured at materialization (§2.1): compiled
    /// into a fresh plan and snapshotted into its record. Never re-derived.
    pub egress_settings: crate::egress::EgressSettings,
    /// The daemon's early create check (§1.5): refused before any host IO.
    pub egress_admission: crate::egress::EgressAdmission,
    /// B12: this create is a TEMPLATE_BUILD VM; an allowlist-mode resolver
    /// then logs its queries to the runtime's in-memory reader so refused
    /// names become blocked-name hints. No other sandbox ever logs queries.
    pub refused_dns_hints: bool,
    /// Guest sudo for this create (from the journaled lease record): grant
    /// the drop-in, or remove it (and audit at create when `audit`).
    pub guest_privilege: GuestPrivilege,
    /// Which readiness this create's VM gets; persisted with its readiness
    /// spec. Only the daemon's build gate yields `BuildBootstrap`.
    pub readiness: ReadinessMode,
    /// A `sandbox.reconnect` restore boots this new root
    /// from the stored disk image instead of the template. The template tag
    /// stays `template_digest`; the base image is `restore.fingerprint`.
    pub restore: Option<RestoreLaunch>,
}

/// A restore's launch image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreLaunch {
    /// The worker-verified disk image, imported into staging only.
    pub fingerprint: String,
    /// `volatile.cloud-init.instance-id` of the stored copy, when known.
    pub cloud_init_instance_id: Option<String>,
}

/// How readiness decides a VM is READY. Persisted in the instance's
/// readiness spec at create (a pre-feature spec reads `Standard`), so
/// allocation recovery and probes after a daemon restart use the same mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessMode {
    /// The declared guest identity, HOME, shell, repo and tooling script.
    #[default]
    Standard,
    /// The community prep build VM of a raw upstream image, whose image
    /// identity is not yet the declared one: the same restart-tolerant pass,
    /// binding and architecture checks, but no identity script and no repo
    /// ensure; a boot settle (`systemctl is-system-running --wait` as the
    /// declared uid, cwd `/`) instead. Never on reconnect.
    BuildBootstrap,
}

/// What the daemon's fixed guest sudo helper does on a boot it drives.
/// Commands, files and terminals always run as the guest user either way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuestPrivilege {
    /// Effective `guestSudo`: install `/etc/sudoers.d/wssp-guest`
    /// (`#<uid> ALL=(ALL) NOPASSWD:ALL`) after the last guest restart and
    /// prove `sudo -n true` as the guest user. Persisted in the readiness
    /// spec for allocation recovery.
    pub sudo: bool,
    /// Create only, `sudo` off, no guest root possible and not a build VM:
    /// also run the hygiene audit for common static root grants (not a
    /// security control). Never persisted.
    pub audit: bool,
}

/// One QEMU process as the host saw it: `(pid, starttime)` from
/// `/proc/<pid>/stat`, read only after `/proc/<pid>/cmdline` named this
/// instance and the Incus pid read before and after agreed. A different
/// identity at retirement proves a new QEMU process (host evidence). The
/// converse does not hold: Incus may reset a guest inside the same process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QemuIdentity {
    pub pid: u64,
    pub start_ticks: u64,
}

impl CreateSandboxRequest {
    pub fn for_test(sandbox_id: &str, idempotency_key: &str) -> Self {
        const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        Self {
            first_attempt: true,
            vm_size: sandbox_protocol::VmSize {
                cpu_count: 1,
                memory_mi_b: 1024,
            },
            lease: sandbox_protocol::HostLease::for_test(),
            sandbox_id: sandbox_id.to_string(),
            instance_name: default_incus_instance_name(sandbox_id),
            idempotency_key: idempotency_key.to_string(),
            template_digest: FP.to_string(),
            incus_fingerprint: Some(FP.to_string()),
            guest: GuestIdentity::default(),
            architecture: Some("x86_64".to_string()),
            egress_policy: None,
            egress_policy_hash: None,
            egress_settings: crate::egress::EgressSettings::default(),
            egress_admission: crate::egress::EgressAdmission::PERMITTED,
            refused_dns_hints: false,
            guest_privilege: GuestPrivilege::default(),
            readiness: ReadinessMode::default(),
            restore: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSandboxResponse {
    pub sandbox: SandboxRecord,
    /// Allowlist grants the node's domain blocklist denied at
    /// materialization (§2.1, M19), bounded by [`bounded_denied_grants`].
    /// Reported in the create result as `egressDeniedGrants`.
    pub egress_denied_grants: Vec<String>,
    /// Whether the guest kernel delivers TERM/INT/HUP to a process group
    /// (Linux >= 6.9): the signal helper's own zero-signal probe, run once
    /// the guest was ready. `None` when it could not be observed; a signal
    /// call still checks at call time either way.
    pub guest_group_signals: Option<bool>,
    /// Whether the guest user can keep a user manager running past its
    /// commands (systemd linger): see [`GuestLinger`]. `None` when it could
    /// not be observed. Diagnostic only; never gates readiness.
    pub guest_linger: Option<GuestLinger>,
    /// Guest restarts readiness tolerated (an Ubuntu 26.04 first boot
    /// reboots once). The daemon logs a nonzero count.
    pub readiness_restarts: u32,
}

/// The guest user's systemd linger, observed once the guest was ready. A
/// lingering user manager can hold processes outside a command's scope, so
/// running-VM retirement keeps UNKNOWN receipts (fails safe) until the VM
/// stops or linger ends. Templates deny self-linger
/// (docs/operations/templates.md#deny-self-linger).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestLinger {
    /// Not enabled, and polkit does not authorize the guest user to enable it.
    Blocked,
    /// Not enabled, but the guest user may enable it without authentication.
    Allowed,
    /// Enabled for the guest user now.
    Enabled,
}
impl GuestLinger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Allowed => "allowed",
            Self::Enabled => "enabled",
        }
    }
}

/// Most denied grants a create result reports (the server's column bound).
pub const MAX_REPORTED_DENIED_GRANTS: usize = 128;
/// Their encoded budget inside the 32 KiB result (the result must never be
/// truncated: its `state` is the create's completion evidence).
pub const MAX_REPORTED_DENIED_GRANT_BYTES: usize = 8 * 1024;

/// Sorted, unique, at most [`MAX_REPORTED_DENIED_GRANTS`] names within
/// [`MAX_REPORTED_DENIED_GRANT_BYTES`] (JSON-encoded). Display data only: a
/// longer list is cut, never an error.
pub fn bounded_denied_grants(mut grants: Vec<String>) -> Vec<String> {
    grants.sort();
    grants.dedup();
    let mut bytes = 2;
    let mut out = Vec::new();
    for grant in grants {
        if out.len() == MAX_REPORTED_DENIED_GRANTS
            || bytes + grant.len() + 3 > MAX_REPORTED_DENIED_GRANT_BYTES
        {
            break;
        }
        bytes += grant.len() + 3;
        out.push(grant);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxRecord {
    pub sandbox_id: String,
    pub generation: u64,
    pub state: SandboxLifecycleState,
    pub idempotency_key: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RunCommandRequest {
    pub template_fingerprint: String,
    pub generation: u64,
    pub attempt: u64,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub argv: Vec<String>,
    pub script: Option<String>,
    pub cwd: Option<String>,
    pub timeout_ms: Option<u64>,
    pub env: Vec<(String, String)>,
    pub stdin: Option<Vec<u8>>,
    pub guest: GuestIdentity,
    /// D1: a template-build step, the only way a command runs as guest root.
    /// The node daemon sets it only for a dispatch whose journaled sandbox
    /// record carries a build id; `guest` stays the sandbox's declared
    /// (non-root) identity and is still validated.
    pub build_step: Option<BuildStep>,
}

/// How a template-build step runs (always as guest root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildStep {
    /// The request's own `argv`/`script` as guest root.
    Root,
    /// The fixed COPY helper ([`crate::build_copy_argv`]); the request
    /// carries no argv, script or env of its own.
    Copy(sandbox_protocol::BuildCopyV11),
}

impl std::fmt::Debug for RunCommandRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RunCommandRequest([REDACTED])")
    }
}

impl RunCommandRequest {
    /// Guest root (D1): only a template-build step.
    pub fn runs_as_root(&self) -> bool {
        self.build_step.is_some()
    }

    /// Shape checks shared by every runtime before any effect. A COPY step
    /// is validated as its typed body; everything else as a user command.
    pub(crate) fn validate_command_shape(&self) -> Result<(), RuntimeError> {
        self.guest.validate()?;
        sandbox_protocol::validate_command_timeout(self.timeout_ms)
            .map_err(|(code, message)| RuntimeError::new(code, message))?;
        if let Some(BuildStep::Copy(copy)) = &self.build_step {
            if !copy.is_valid()
                || !self.argv.is_empty()
                || self.script.is_some()
                || !self.env.is_empty()
                || self.stdin.is_some()
            {
                return Err(RuntimeError::new(
                    SandboxErrorCode::ProtocolError,
                    "invalid build copy step",
                ));
            }
            return Ok(());
        }
        sandbox_protocol::validate_command_run_spec(&self.command_spec())
            .map_err(|(code, message)| RuntimeError::new(code, message))?;
        if self.script.is_none() && self.argv.is_empty() {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "exec requires at least one argv entry",
            ));
        }
        Ok(())
    }

    pub(crate) fn command_spec(&self) -> sandbox_protocol::CommandRunSpec<'_> {
        sandbox_protocol::CommandRunSpec {
            // Runtime requests use an empty Vec for absent argv. Never hide a
            // supplied nonempty argv just because script is also present.
            argv: (!self.argv.is_empty() || self.script.is_none()).then_some(self.argv.as_slice()),
            script: self.script.as_deref(),
            cwd: self.cwd.as_deref(),
            env: Some(&self.env),
        }
    }
}

/// Shared 10.5 metadata DTO; stat and directory entries have identical bounds.
pub use sandbox_protocol::results::EntryInfo;
pub type GuestPathKind = sandbox_protocol::results::EntryType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListDirRequest {
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub path: String,
    pub depth: u32,
    pub limit: usize,
    pub generation: u64,
    pub continuation: Option<crate::DirectoryContinuation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDirResponse {
    pub path: String,
    pub depth: u32,
    pub items: Vec<EntryInfo>,
    pub continuation: Option<crate::DirectoryContinuation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatPathRequest {
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MkdirRequest {
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovePathRequest {
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub path: String,
    pub recursive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovePathRequest {
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MkdirResponse {
    pub created: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemovePathResponse {
    pub removed: bool,
}

/// Closed signal set (4b). SIGKILL is never delivered by the non-kill helper:
/// it routes to the command's single cancellation owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessSignal {
    Sigterm,
    Sigint,
    Sighup,
    Sigkill,
}

impl ProcessSignal {
    pub fn as_kill_arg(self) -> &'static str {
        match self {
            Self::Sigterm => "TERM",
            Self::Sigint => "INT",
            Self::Sighup => "HUP",
            Self::Sigkill => "KILL",
        }
    }

    /// Exact closed set; unknown names refuse before any effect. No
    /// normalization beyond the documented `SIG` prefix alias.
    pub fn parse(value: &str) -> Result<Self, RuntimeError> {
        match value {
            "SIGTERM" | "TERM" => Ok(Self::Sigterm),
            "SIGINT" | "INT" => Ok(Self::Sigint),
            "SIGHUP" | "HUP" => Ok(Self::Sighup),
            "SIGKILL" | "KILL" => Ok(Self::Sigkill),
            _ => Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "unsupported process signal",
            )),
        }
    }

    pub fn is_kill(self) -> bool {
        self == Self::Sigkill
    }
}

/// Host-local, guest-attested birth of one supervised command (4a). The
/// guest supplies pid/boot/ticks at the fixed start-record position; the host
/// clock supplies the time. Never carries the wrapper nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandBirth {
    pub pid: u32,
    pub boot_id: String,
    pub start_ticks: u64,
    /// Host clock (Unix milliseconds) when the host observed the record.
    pub started_at_ms: u64,
}

/// Bounded accepted-request description, derived only from the original
/// request (never the env frame, wrapper, script body or nonce).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandDescription {
    pub cmd: String,
    pub args: Vec<String>,
    pub args_truncated: bool,
    pub cwd: String,
}

/// Per-argument and aggregate bounds shared with `ProcessInfo::validate`.
const DESCRIPTION_ARG_UNITS: usize = 512;
const DESCRIPTION_ARGS_MAX: usize = 256;
const DESCRIPTION_ARGS_BYTES: usize = 4096;
const DESCRIPTION_MAX_BYTES: usize = 12288;

impl CommandDescription {
    /// Scripts expose no body: the description names the shell only and is
    /// marked truncated. Argv is kept in order until any bound would be
    /// exceeded; the remainder is dropped and `args_truncated` is set.
    pub fn from_request(request: &RunCommandRequest) -> Option<Self> {
        let fits = |value: &str| {
            value.encode_utf16().count() <= DESCRIPTION_ARG_UNITS && !value.contains('\0')
        };
        let cwd = request
            .cwd
            .clone()
            .unwrap_or_else(|| request.guest.guest_home.clone());
        if !cwd.starts_with('/') || cwd.len() > 4096 || cwd.contains('\0') {
            return None;
        }
        // A COPY step is described by its sources and destination, never by
        // the helper source.
        let copy_args: Vec<String>;
        let (cmd, rest, mut args_truncated): (String, &[String], bool) =
            if let Some(BuildStep::Copy(copy)) = &request.build_step {
                copy_args = copy.src.iter().chain([&copy.dest]).cloned().collect();
                ("wssp-build-copy".into(), &copy_args, false)
            } else if request.script.is_some() {
                ("/bin/bash".into(), &[], true)
            } else {
                let (cmd, rest) = request.argv.split_first()?;
                (cmd.clone(), rest, false)
            };
        if cmd.is_empty() || !fits(&cmd) {
            return None;
        }
        let mut args = Vec::new();
        let mut bytes = 2usize;
        for arg in rest {
            let encoded = serde_json::to_vec(arg).map_or(usize::MAX, |v| v.len()) + 1;
            if args.len() == DESCRIPTION_ARGS_MAX
                || !fits(arg)
                || bytes.saturating_add(encoded) > DESCRIPTION_ARGS_BYTES
            {
                args_truncated = true;
                break;
            }
            bytes += encoded;
            args.push(arg.clone());
        }
        let description = Self {
            cmd,
            args,
            args_truncated,
            cwd,
        };
        let total = serde_json::to_vec(&serde_json::json!({
            "cmd": description.cmd,
            "args": description.args,
            "argsTruncated": description.args_truncated,
            "cwd": description.cwd,
        }))
        .map_or(usize::MAX, |v| v.len());
        (total <= DESCRIPTION_MAX_BYTES).then_some(description)
    }
}

/// Full tracked target for a qualified signal (4b). The host revalidates
/// every field against its own active-map birth before any effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalTarget {
    pub target_operation_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub pid: u32,
}

/// The start a runtime bound for one guest-user command attempt (decision
/// 2): its public birth plus the host-known uid the launcher dropped to and
/// the effective budget (`0`: no budget). The daemon journals it once, so a
/// receipt from a mid-run restart can still be retired on a running VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandStart {
    pub birth: CommandBirth,
    pub uid: u32,
    pub budget_ms: u64,
    /// The host-read QEMU identity once the birth bound (R11); `None` when
    /// unreadable or on runtimes without one.
    pub qemu: Option<QemuIdentity>,
}

/// What the retire helper may do to the attempt's guest scope (decision 1).
/// A kill mode observes first and kills only a populated scope; only a due
/// command is ever killed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetireMode {
    /// Never signal anything.
    Observe,
    /// A cancel was requested or an interim stop is still unproven.
    KillCancel,
    /// Kill once the guest-monotonic time since the scope became active is
    /// past `budget_ms` plus [`RETIRE_DEADLINE_SLACK`].
    KillDeadline,
}
impl RetireMode {
    pub fn as_arg(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::KillCancel => "kill-cancel",
            Self::KillDeadline => "kill-deadline",
        }
    }
    pub fn kills(self) -> bool {
        self != Self::Observe
    }
}

/// The command an UNKNOWN `command.run` attempt may have left
/// behind, named by its journaled bound birth (leader pid, guest boot id,
/// start ticks) and its exact attempt, which derives its guest scope unit.
/// `uid` and `budget_ms` come only from the journaled start: without `uid`
/// the runtime never runs the scoped helper and keeps today's proofs (the VM
/// stopped or absent, or the guest rebooted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireCommandRequest {
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub birth: CommandBirth,
    pub generation: u64,
    pub attempt: u64,
    /// The uid the attempt's launcher dropped to (journaled), never the
    /// lease default.
    pub uid: Option<u32>,
    /// The attempt's effective budget in ms; `0` means none.
    pub budget_ms: u64,
    pub mode: RetireMode,
    /// The sandbox's lease has `guest_root`: guest-reported facts (scope
    /// verdicts, boot id) prove nothing. Only a stopped or absent VM or a
    /// changed QEMU identity retires; an unproven attempt is
    /// [`RetireObservation::Parked`]. A kill mode still runs the helper once
    /// for its effect, ignoring its verdict.
    pub host_proof_only: bool,
    /// The QEMU identity journaled at the attempt's start, when readable.
    pub qemu: Option<QemuIdentity>,
}

/// The kill-deadline slack past the budget: the spawn-to-banner allowance
/// (`HOST_SETUP_BUDGET`, 15 s) plus 5 s, so a due kill is never earlier
/// than the runtime's own deadline. Guest suspend does not count.
pub const RETIRE_DEADLINE_SLACK: std::time::Duration = std::time::Duration::from_secs(20);

/// One retirement observation that is not final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetireObservation {
    /// The attempt's work is proven gone.
    Gone(CommandGroupGone),
    /// The scope still runs. `not_due` is the time until a kill-deadline
    /// command becomes due; `None` means re-observe after a backoff.
    Running {
        not_due: Option<std::time::Duration>,
    },
    /// Host-proof-only (`guest_root`): the same QEMU process still runs, so
    /// nothing is provable from the host. Not timer-retried; rechecked from
    /// the host only (slowly) or re-armed by a lifecycle event.
    Parked,
}
impl RetireObservation {
    /// A constant label for logs: `gone`'s proof, `not_due` or `populated`.
    pub fn verdict(&self) -> &'static str {
        match self {
            Self::Parked => "parked",
            Self::Gone(proof) => proof.verdict(),
            Self::Running { not_due: Some(_) } => "not_due",
            Self::Running { not_due: None } => "populated",
        }
    }
}

/// Proof that nothing of one bound birth can still run: the runtime observed
/// the sandbox VM stopped or absent, or its guest booted again since the
/// birth (a different boot id), or the root retire helper proved the
/// attempt's root-owned scope gone (in a boot without an unscoped launch),
/// empty or killed, with no populated cgroup root of the guest uid. A
/// process group is never this proof. Only a runtime constructs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandGroupGone {
    birth: CommandBirth,
    verdict: &'static str,
}
impl CommandGroupGone {
    pub(crate) fn proven(birth: &CommandBirth) -> Self {
        Self::proven_by(birth, "gone")
    }
    /// `verdict` names the proof: a constant label, safe to log.
    pub(crate) fn proven_by(birth: &CommandBirth, verdict: &'static str) -> Self {
        Self {
            birth: birth.clone(),
            verdict,
        }
    }
    /// Which proof established it (`stopped`, `empty`, `killed`, ...).
    pub fn verdict(&self) -> &'static str {
        self.verdict
    }
    /// The bound birth this proof is about.
    pub fn birth(&self) -> &CommandBirth {
        &self.birth
    }
    /// Host evidence only (the VM stopped or absent, or a new QEMU process):
    /// the proofs a `guestRoot` sandbox's receipt may be deleted on. Every
    /// other verdict rests on guest-reported facts.
    pub fn host_proven(&self) -> bool {
        matches!(self.verdict, "vm_stopped" | "qemu_restarted")
    }
}

/// What a successful signal call established. Never "delivered to the user
/// command" from a wrapper-only syscall: group delivery is the sole success
/// scope for TERM/INT/HUP; SIGKILL only records a cancellation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalOutcome {
    ProcessGroup,
    CancelRequested,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestProcess {
    pub operation_id: String,
    pub pid: u32,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListProcessesRequest {
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListProcessesResponse {
    pub processes: Vec<GuestProcess>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalProcessRequest {
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub pid: u32,
    pub signal: ProcessSignal,
    /// Required for every effect. A naked legacy PID refuses pre-issue.
    pub target: Option<SignalTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteStdinRequest {
    pub operation_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub bytes: Vec<u8>,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRequest {
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub snapshot_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotResponse {
    pub snapshot_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSandboxRequest {
    pub sandbox_id: String,
    pub instance_name: String,
    pub dest_instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub snapshot_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSandboxResponse {
    pub dest_instance_name: String,
    pub snapshot_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFileRequest {
    /// Verified workload owner, used only for host staging accounting.
    pub sandbox_owner_id: String,
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFileResponse {
    pub path: String,
    pub bytes: crate::FileContent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteFileRequest {
    pub template_fingerprint: String,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub idempotency_key: String,
    pub path: String,
    pub bytes: crate::FileContent,
    pub guest: GuestIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteFileResponse {
    pub path: String,
    pub bytes_written: u64,
}

/// Settle an interrupted `file.put` attempt from guest evidence after a host
/// restart. The staging identity is derived from `(operation, generation,
/// attempt)`, so no host-side path or nonce needs to survive the crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverFilePutRequest {
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectSandboxRequest {
    pub vm_size: sandbox_protocol::VmSize,
    pub lease: sandbox_protocol::HostLease,
    pub template_fingerprint: String,
    pub architecture: Option<String>,
    pub guest: GuestIdentity,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
    /// Recorded egress policy and hash, re-applied immutably on relaunch.
    pub egress_policy: Option<sandbox_protocol::EgressPolicy>,
    pub egress_policy_hash: Option<String>,
    /// The daemon's cold-reconnect check (§1.5), applied against the
    /// RECORDED mode once the bound VM is known to be stopped.
    pub egress_admission: crate::egress::EgressAdmission,
    /// The journaled lease's `guest_sudo`: grant on every boot this
    /// reconnect drives, else remove the drop-in. Must equal the persisted
    /// readiness spec's (refused as `guest_check` otherwise).
    pub guest_sudo: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectSandboxResponse {
    pub sandbox: SandboxRecord,
    /// Whether the guest kernel delivers TERM/INT/HUP to a process group
    /// (Linux >= 6.9): the signal helper's own zero-signal probe, run once
    /// the guest was ready. `None` when it could not be observed; a signal
    /// call still checks at call time either way.
    pub guest_group_signals: Option<bool>,
    /// Whether the guest user can keep a user manager running past its
    /// commands (systemd linger): see [`GuestLinger`]. `None` when it could
    /// not be observed. Diagnostic only; never gates readiness.
    pub guest_linger: Option<GuestLinger>,
    /// Guest restarts readiness tolerated (an Ubuntu 26.04 first boot
    /// reboots once). The daemon logs a nonzero count.
    pub readiness_restarts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopSandboxRequest {
    pub template_fingerprint: String,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopSandboxResponse {
    pub sandbox: SandboxRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandStreamChunk {
    pub stream: CommandStream,
    pub sequence: u64,
    pub bytes: Vec<u8>,
    pub final_chunk: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRecord {
    pub operation_id: String,
    pub idempotency_key: String,
    pub state: OperationState,
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub guest_pid: Option<u32>,
    /// Public start identity, present only after the fixed-position start
    /// record. The legacy `guest_pid` banner remains cleanup-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth: Option<CommandBirth>,
    pub chunks: Vec<CommandStreamChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCommandResponse {
    pub command: CommandRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillSandboxRequest {
    pub template_fingerprint: String,
    pub sandbox_id: String,
    pub instance_name: String,
    pub operation_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillSandboxResponse {
    pub sandbox: SandboxRecord,
}

/// Lock only over local spawn (or FakeRuntime's immediate state mutation).
/// Revocation never waits for a daemon/guest response. Release admission
/// guards before revoking or closing this permit or any ancestor: revocation
/// waits for admitted spawn sections and would otherwise self-deadlock.
#[derive(Debug, Default)]
pub struct RuntimePermit {
    revoked: std::sync::Arc<std::sync::Mutex<bool>>,
    /// Every descendant spawn lock, held weakly so completed scopes are released.
    descendants: std::sync::Mutex<Vec<std::sync::Weak<std::sync::Mutex<bool>>>>,
    deadline: Option<std::time::Instant>,
    /// Test-only monotonic source, shared with logical fixture time.
    #[cfg(test)]
    test_clock: Option<std::sync::Arc<std::sync::Mutex<std::time::Instant>>>,
    /// Admission closed: no NEW work is admitted, but work already admitted
    /// is not preempted (`is_cancelled` stays false), so a bounded shutdown
    /// can wait for it before revoking.
    closed: std::sync::atomic::AtomicBool,
    /// A child permit is revoked whenever its parent is.
    parent: Option<std::sync::Arc<RuntimePermit>>,
}
impl RuntimePermit {
    pub fn with_timeout(timeout: std::time::Duration) -> Self {
        Self {
            deadline: Some(std::time::Instant::now() + timeout),
            ..Self::default()
        }
    }
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn with_test_clock(
        timeout: std::time::Duration,
        clock: std::sync::Arc<std::sync::Mutex<std::time::Instant>>,
    ) -> Self {
        let now = *clock.lock().unwrap();
        Self {
            deadline: Some(now + timeout),
            test_clock: Some(clock),
            ..Self::default()
        }
    }
    pub(crate) fn clock_now(&self) -> std::time::Instant {
        #[cfg(test)]
        if let Some(clock) = &self.test_clock {
            return *clock.lock().unwrap_or_else(|err| err.into_inner());
        }
        std::time::Instant::now()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn remaining_time(&self) -> Option<std::time::Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(self.clock_now()))
    }
    /// A child permit with its own deadline that is revoked whenever the
    /// parent is (explicit revocation propagates; the parent's deadline
    /// does not — the child carries its own).
    pub fn child(parent: std::sync::Arc<RuntimePermit>, timeout: std::time::Duration) -> Self {
        let permit = Self {
            deadline: Some(parent.clock_now() + timeout),
            #[cfg(test)]
            test_clock: parent.test_clock.clone(),
            parent: Some(parent),
            ..Self::default()
        };
        permit.register_descendant();
        permit
    }
    /// An independently revocable scope retaining its parent's deadline,
    /// explicit revocation and admission closure.
    #[cfg(target_os = "linux")]
    pub(crate) fn linked(parent: Option<std::sync::Arc<Self>>) -> Self {
        let permit = Self {
            deadline: parent.as_ref().and_then(|permit| permit.deadline),
            #[cfg(test)]
            test_clock: parent.as_ref().and_then(|permit| permit.test_clock.clone()),
            parent,
            ..Self::default()
        };
        permit.register_descendant();
        permit
    }
    fn register_descendant(&self) {
        let mut ancestor = self.parent.as_ref();
        while let Some(parent) = ancestor {
            let mut descendants = parent.descendants.lock().unwrap_or_else(|e| e.into_inner());
            descendants.retain(|child| child.strong_count() != 0);
            descendants.push(std::sync::Arc::downgrade(&self.revoked));
            ancestor = parent.parent.as_ref();
        }
    }
    /// Wait for every already-admitted descendant spawn section. Never hold
    /// an ancestor spawn lock while waiting: admission locks child then parent.
    /// Callers must release their own/descendant admission guard before calling
    /// `revoke` or `close` on an ancestor; doing so inside admission self-deadlocks.
    /// Runtime admission sections only spawn or mutate local state, never revoke.
    fn drain_descendants(&self) {
        let descendants: Vec<_> = {
            let mut descendants = self.descendants.lock().unwrap_or_else(|e| e.into_inner());
            descendants.retain(|child| child.strong_count() != 0);
            descendants
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .collect()
        };
        for child in descendants {
            drop(child.lock().unwrap_or_else(|e| e.into_inner()));
        }
    }
    /// Finish configuration of an already initialized, still-stopped VM.
    /// Revocation must prevent a launch, but cannot leave its disk with a
    /// half-installed NIC. Retain the exact cumulative deadline and clock.
    #[cfg(target_os = "linux")]
    pub(crate) fn settlement(&self) -> Self {
        Self {
            deadline: self.deadline,
            #[cfg(test)]
            test_clock: self.test_clock.clone(),
            ..Self::default()
        }
    }
    fn elapsed(&self) -> bool {
        self.deadline.is_some_and(|d| self.clock_now() >= d)
    }
    pub fn revoke(&self) {
        *self.revoked.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.drain_descendants();
    }
    /// Refuse every later `admit` without preempting admitted work. Taken
    /// under the spawn lock: once this returns, no spawn admitted before it
    /// is still mid-spawn and none can start after it.
    pub fn close(&self) {
        let guard = self.revoked.lock().unwrap_or_else(|e| e.into_inner());
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        drop(guard);
        self.drain_descendants();
    }
    pub fn is_closed(&self) -> bool {
        self.closed_chain() || self.is_cancelled()
    }
    /// Admission closed here or on any ancestor (C58 P3-1): a child permit
    /// never admits new work its parent has closed to.
    fn closed_chain(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.closed_chain())
    }
    /// Explicitly revoked (relay disconnect, shutdown, lease end) — as
    /// opposed to merely past its deadline.
    pub(crate) fn is_revoked(&self) -> bool {
        *self.revoked.lock().unwrap_or_else(|e| e.into_inner())
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.is_revoked())
    }
    /// Time left before the deadline (`None` = no deadline).
    pub(crate) fn remaining(&self) -> Option<std::time::Duration> {
        self.deadline
            .map(|d| d.saturating_duration_since(self.clock_now()))
    }
    pub fn is_cancelled(&self) -> bool {
        self.is_revoked() || self.elapsed()
    }
    /// Interrupt a readiness/poll wait on revocation without retaining spawn
    /// admission. A stop/kill can then acquire the sandbox's lifecycle slot.
    pub fn wait_for(&self, duration: std::time::Duration) -> Result<(), RuntimeError> {
        let until = std::time::Instant::now() + duration;
        loop {
            drop(self.admit()?);
            let remaining = until.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
        }
    }
    pub fn admit(&self) -> Result<std::sync::MutexGuard<'_, bool>, RuntimeError> {
        let guard = self.revoked.lock().unwrap_or_else(|e| e.into_inner());
        let parent_revoked = self
            .parent
            .as_ref()
            .is_some_and(|parent| parent.is_revoked());
        if *guard || parent_revoked || self.elapsed() || self.closed_chain() {
            return Err(RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "runtime work preempted",
            ));
        }
        Ok(guard)
    }
}

/// Lifecycle checkpoint around autonomous enforcement-loss destruction. The
/// caller captures lease authority BEFORE the drain starts: Prepare durably
/// closes that arm, Complete settles it only after VM AND network absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementLossStage {
    Prepare,
    Complete,
}

/// Lifecycle-owned authority captured before a readiness observation. Detection
/// may prepare, never complete: only a worker proving absence may complete.
pub trait EnforcementLossIntent: Send {
    /// IdempotencyConflict means the captured authority changed WITHOUT
    /// retaining intent. The detector must capture anew and reverify, never
    /// apply its old verdict to that new arm. Other failures retain the same
    /// arm's restrictive/retry intent but grant no destruction authority.
    fn prepare(&self) -> Result<(), RuntimeError>;
}

pub trait EnforcementLossLifecycle: Send + Sync + std::fmt::Debug {
    fn capture(&self, sandbox_id: &str) -> Box<dyn EnforcementLossIntent>;
}

/// Address-free diagnostics for one successfully committed sandbox refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRefreshReport {
    pub sandbox_id: String,
    pub domain_count: usize,
    /// Includes lease renewal even when address membership is unchanged.
    pub changed_grants: bool,
    /// Added plus removed domain/address pairs (renewals alone count as zero).
    pub changed_addresses: usize,
    pub added_addresses: usize,
    pub removed_addresses: usize,
    /// Next eligible refresh, including half-life scheduling and retry backoff.
    pub next_refresh_unix_secs: u64,
    /// Typed refresh warning: the pass completed WITHOUT publishing (e.g.
    /// `EgressRefusal::RefreshOverBudget`); the last-good rules stay.
    pub warning: Option<crate::EgressRefusal>,
}

pub trait SandboxRuntime: Send + Sync {
    /// The restore base the daemon's journaled lease
    /// record (or the server's `diskBaseFingerprint`) binds `sandbox_id` to.
    /// Every bind of that sandbox then requires the restored lineage. Never
    /// derived from instance config. Runtimes without binding ignore it.
    fn bind_restore_base(&self, _sandbox_id: &str, _restore_base: &str) {}
    /// Drop the restore base [`Self::bind_restore_base`] bound: a discard
    /// that bound a stale copy from the server's copy row (no lease record)
    /// releases the hint once it is done. Runtimes without binding ignore it.
    fn unbind_restore_base(&self, _sandbox_id: &str) {}
    /// Final daemon shutdown only. Stop admission and reap host-local helpers;
    /// daemon effects remain uncertain and their durable obligations survive.
    fn shutdown_local_children(&self) -> Result<(), RuntimeError> {
        Ok(())
    }

    /// CLI-logins proxy mode: whether this runtime gives every
    /// sandbox a host-side bridge gateway the guest can reach on the
    /// credential proxy port. `false` (the default) keeps the daemon's
    /// `proxy` credential capability off, so proxied logins are never placed
    /// here. The Incus runtime turns this on together with the gateway ACL
    /// allow rule, which lands on the egress branch's ACL compiler.
    fn supports_credential_proxy(&self) -> bool {
        false
    }

    /// The sandbox's recorded proxy endpoint: its bridge gateway IPv4 and
    /// the proxy port its create opened on the gateway ACL (the proxy's
    /// guest-facing listen address). The port is the one recorded for this
    /// sandbox, never the daemon's current configuration: a daemon restart
    /// re-binds where the guest's base URLs and ACL already point. `None`
    /// when the runtime has none for this sandbox; a proxied install then
    /// fails closed.
    fn credential_proxy_endpoint(&self, _sandbox_id: &str) -> Option<std::net::SocketAddrV4> {
        None
    }

    /// Preview tunnels: the pinned guest address and the declared ports of
    /// the sandbox's RECORDED plan, only when that plan carries the exact
    /// `wssp-tunnel-ingress` allow for them. The host's tunnel client dials
    /// only this; `None` refuses an apply.
    fn tunnel_target(&self, _sandbox_id: &str) -> Option<(std::net::Ipv4Addr, Vec<u16>)> {
        None
    }

    /// Preview tunnels: replace a tunnel sandbox's declared ports with this
    /// server-issued revision (`tunnel.ports`), atomically under the
    /// sandbox's lifecycle lock and the recorded plan's fences. `before_acl`
    /// is called with the ports the host's client may still forward, after
    /// the change is durably pending and before the ACL changes (the node
    /// daemon stops a client forwarding anything else there).
    fn update_tunnel_ports(
        &self,
        _sandbox_id: &str,
        revision: u64,
        _ports: &[u16],
        _before_acl: &dyn Fn(&[u16]),
    ) -> Result<crate::TunnelPortsUpdate, RuntimeError> {
        Ok(crate::TunnelPortsUpdate {
            outcome: sandbox_protocol::TunnelPortsOutcomeV11::Refused,
            revision,
        })
    }

    /// One bounded rotating policy-inspection pass. Call off the lease deadline
    /// path with lifecycle-owned active ids. Cleanup remains lifecycle-owned.
    fn reconcile_policies(&self, _sandbox_ids: &[String]) -> Result<(), RuntimeError> {
        Ok(())
    }

    /// One bounded DNS-grant refresh pass over lifecycle-owned active ids:
    /// re-resolve and re-arm the domain egress grants of every due, running,
    /// verified sandbox before they expire. Call off the lease deadline path,
    /// one pass at a time; `with_cancellation` bounds and aborts the pass
    /// (daemon shutdown). A failed or skipped refresh NEVER extends a grant:
    /// the armed expiry lease still fences it. Runtimes without domain
    /// grants do nothing.
    fn refresh_dns_grants(&self, _sandbox_ids: &[String]) -> Result<(), RuntimeError> {
        Ok(())
    }

    /// Like `refresh_dns_grants`, with one diagnostic per completed sandbox.
    /// Successful sandboxes are reported even if another sandbox fails the pass.
    fn refresh_dns_grants_observed(
        &self,
        sandbox_ids: &[String],
        _observe: &dyn Fn(&DnsRefreshReport),
    ) -> Result<(), RuntimeError> {
        self.refresh_dns_grants(sandbox_ids)
    }

    /// B12 blocked-name hints: whether this runtime's allowlist-mode resolver
    /// can report the names it refused (advertised as `egressRefusedHints`).
    /// Fail-closed default: no.
    fn refused_dns_hints_capability(&self) -> bool {
        false
    }

    /// B12 hook: drain `(sandbox_id, name)` pairs the allowlist-mode resolver
    /// refused since the last call (raw observations; the daemon validates,
    /// deduplicates, bounds and rate-limits them). Cheap and local: never
    /// daemon IO. Runtimes without the capability drain nothing.
    fn drain_refused_dns_names(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Cheap local health snapshot; never performs daemon IO on the socket reader.
    fn policy_reconciler_health(&self) -> sandbox_protocol::PolicyReconcilerHealth {
        sandbox_protocol::PolicyReconcilerHealth::default()
    }

    /// Installed before any host census, probe or operation. Runtime clones
    /// share this boundary, including independently permitted restrictive stops.
    fn set_enforcement_loss_lifecycle(
        &self,
        _lifecycle: std::sync::Arc<dyn EnforcementLossLifecycle>,
    ) {
    }

    /// Whether this runtime provably enforces recorded egress policies (M5,
    /// C35). Advertised as `egressPolicy` in the relay hello; fail-closed, so
    /// the default is "no". Callers map `Err` to `false`.
    fn egress_enforcement_capability(&self) -> Result<bool, RuntimeError> {
        Ok(false)
    }

    /// `egressOpen` (§2.5, static per daemon run): this runtime enforces
    /// recorded policies and the open-mode guest resolver has an upstream
    /// (configured `dns_upstreams`, or an IPv4 nameserver in the host
    /// resolv.conf). Guard health is deliberately NOT part of it: it is
    /// live and leased (`host.egress-state`), and a static bit measured at
    /// hello would turn a transient guard failure into a downgrade for the
    /// whole connection. Fail-closed default: no.
    fn egress_open_capability(
        &self,
        _settings: &crate::egress::EgressSettings,
    ) -> Result<bool, RuntimeError> {
        Ok(false)
    }

    /// The egress guard this runtime's start fence attests against (§2.0.5),
    /// for the daemon's heartbeat, deployment push and domain blocklist. The
    /// daemon and the fence share it so they never disagree about which
    /// guard they trust. `None`: this runtime has no guard.
    fn egress_guard_probe(&self) -> Option<std::sync::Arc<dyn crate::guard::probe::GuardProbe>> {
        None
    }

    /// One fresh egress-guard check (§2.0.5 `guard_ok`), the daemon's early
    /// create / cold-reconnect input. Never cached. Fail-closed default.
    fn egress_guard_check(&self) -> Result<(), RuntimeError> {
        Err(crate::EgressRefusal::GuardUnavailable.error("this runtime has no egress guard"))
    }

    /// Operator diagnosis for an unavailable egress capability: why this host
    /// cannot enforce recorded egress policies, and so cannot create
    /// sandboxes. Diagnostic text only, never an admission input: the
    /// capability itself stays `egress_enforcement_capability`. `None` when
    /// enforcement is available or the runtime has nothing specific to say.
    fn egress_enforcement_unavailable_reason(&self) -> Option<String> {
        None
    }

    /// C37 R3: drain durably recorded bound-enforcement losses — confirmed
    /// drift on positively bound VMs detected by ANY consumer (operation,
    /// receipt settle, census, probe). The drain re-verifies coherently
    /// (verified recovery retires; inconclusive evidence retains without action), refuses
    /// foreign instances, and tears confirmed-drift VMs down through the
    /// same write-ahead + tag-fenced path as a kill. Runtimes without
    /// enforcement drain nothing. Destruction MUST cross both caller-owned
    /// lifecycle checkpoints; a failed checkpoint retains the loss record.
    /// Prepare failure still invokes restrictive stopping, never deletion.
    fn drain_enforcement_losses(
        &self,
        _settle: &dyn Fn(&str, EnforcementLossStage) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    /// Authoritative managed-VM census. Unknown/non-stopped states consume live
    /// capacity. Failure must prevent host dispatch admission after restart.
    fn sandbox_inventory(&self) -> Result<Vec<RuntimeInventoryEntry>, RuntimeError> {
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "runtime has no authoritative inventory",
        ))
    }

    /// [`Self::sandbox_inventory`] that never waits on `busy` sandboxes: ones
    /// with in-flight (or relay-carried) work that may hold their lifecycle
    /// lock for a long time. Their network-cleanup drain is deferred to a
    /// later census, and a running busy VM is reported `Unreachable` (not
    /// vouched for, never a false Ready) instead of waiting to verify its
    /// enforcement. Every other sandbox is censused exactly as before.
    fn sandbox_inventory_skipping(
        &self,
        busy: &std::collections::HashSet<String>,
    ) -> Result<Vec<RuntimeInventoryEntry>, RuntimeError> {
        let _ = busy;
        self.sandbox_inventory()
    }

    /// Read-only daemon-host totals, independent of node-daemon process limits.
    fn host_resources(&self) -> Result<crate::HostResources, RuntimeError> {
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "runtime has no host resources query",
        ))
    }

    /// Read-only audited profile-root selection. Does not provision a project.
    fn default_storage_pool(&self) -> Result<String, RuntimeError> {
        Err(storage_unsupported())
    }

    /// Connect-only marker initialization. `expected` forbids recreating a bound marker.
    fn initialize_storage_pool(
        &self,
        _name: &str,
        _expected: Option<&crate::StoragePoolIdentity>,
    ) -> Result<crate::StoragePoolIdentity, RuntimeError> {
        Err(storage_unsupported())
    }
    /// Independent pool result: callers retain healthy siblings on failure.
    fn observe_storage_pool(
        &self,
        _pool: &crate::StoragePoolIdentity,
    ) -> Result<crate::StoragePoolObservation, RuntimeError> {
        Err(storage_unsupported())
    }
    fn storage_root_census(
        &self,
        _pool: &crate::StoragePoolIdentity,
    ) -> Result<crate::StorageRootCensus, RuntimeError> {
        Err(storage_unsupported())
    }
    fn storage_physical_usage(
        &self,
        _pool: &crate::StoragePoolIdentity,
        _charged_roots: &[String],
        _commitments_bytes: u64,
    ) -> Result<crate::PhysicalUsage, RuntimeError> {
        Err(storage_unsupported())
    }
    /// Exact healthy original-pool VM AND root absence; network cleanup is separate.
    fn prove_root_absent(
        &self,
        _root: &crate::RootDisk,
        _instance_name: &str,
    ) -> Result<crate::RootAbsenceProof, RuntimeError> {
        Err(storage_unsupported())
    }
    fn create_sandbox_on_storage(
        &self,
        _request: &CreateSandboxRequest,
        _root: &crate::RootDisk,
    ) -> crate::EffectOutcome<CreateSandboxResponse> {
        Err(storage_unsupported().into())
    }
    fn reconnect_sandbox_on_storage(
        &self,
        _request: &ReconnectSandboxRequest,
        _root: &crate::RootDisk,
    ) -> crate::EffectOutcome<ReconnectSandboxResponse> {
        Err(storage_unsupported().into())
    }
    fn kill_sandbox_on_storage(
        &self,
        _request: &KillSandboxRequest,
        _root: &crate::RootDisk,
    ) -> crate::EffectOutcome<KillSandboxResponse> {
        Err(storage_unsupported().into())
    }

    /// A worker-local adapter; cancellation never needs the ordinary IO lock.
    fn with_cancellation(
        &self,
        cancelled: std::sync::Arc<RuntimePermit>,
    ) -> Box<dyn SandboxRuntime>;
    /// Read-only, host-authoritative lifecycle reconciliation. Never starts a VM.
    fn query_sandbox(
        &self,
        sandbox_id: &str,
        create_key: Option<&str>,
        template_fingerprint: Option<&str>,
    ) -> Result<Option<SandboxLifecycleState>, RuntimeError>;

    /// Resolve an operator image ref against bounded host inventory (`incus query --raw`).
    fn resolve_image_ref(&self, image_ref: &str) -> Result<crate::ResolvedHostImage, RuntimeError> {
        let _ = image_ref;
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "runtime cannot resolve host image inventory",
        ))
    }

    /// Import a unified image tarball into the host image store; returns the
    /// daemon's fingerprint (`sha256:<hex>`). Never sets an alias.
    fn import_image(&self, path: &std::path::Path) -> Result<String, RuntimeError> {
        let _ = path;
        Err(image_unsupported())
    }

    /// Import an upstream split image (`<meta> <disk>`, community bases)
    /// into the host image store of this runtime's project. Both files are
    /// validated first ([`crate::validate_split_image`]); the daemon's
    /// fingerprint must equal `expected` (sha256 of meta then disk), or the
    /// imported image is deleted and the import refused. Never sets an alias.
    fn import_split_image(
        &self,
        meta: &std::path::Path,
        disk: &std::path::Path,
        expected: &str,
    ) -> Result<String, RuntimeError> {
        let _ = (meta, disk, expected);
        Err(image_unsupported())
    }

    /// Export an image into `dir`; returns the files written (one for a
    /// unified image, two for a split one).
    fn export_image(
        &self,
        fingerprint: &str,
        dir: &std::path::Path,
    ) -> Result<Vec<std::path::PathBuf>, RuntimeError> {
        let _ = (fingerprint, dir);
        Err(image_unsupported())
    }

    /// Delete an image the daemon imported. Callers check [`Self::image_protected`] first.
    fn delete_image(&self, fingerprint: &str) -> Result<(), RuntimeError> {
        let _ = fingerprint;
        Err(image_unsupported())
    }

    /// Every image fingerprint in the host image store (`sha256:<hex>`), as one
    /// bounded inventory read. Any error (including an inventory too large or
    /// an entry that does not parse) is never evidence of absence.
    fn list_image_fingerprints(&self) -> Result<std::collections::BTreeSet<String>, RuntimeError> {
        Err(image_unsupported())
    }

    /// An image the daemon must never evict: it has an alias, or it is the
    /// base image of any instance in any project.
    fn image_protected(&self, fingerprint: &str) -> Result<bool, RuntimeError> {
        let _ = fingerprint;
        Err(image_unsupported())
    }

    /// `incus publish <instance> --alias <alias>
    /// --compression zstd`, only while Incus reports the instance Stopped
    /// (`state_conflict` otherwise, `sandbox_not_found` when absent). The
    /// alias (`wssp-off-<offloadId>`) marks the image as an offload image:
    /// never a cache entry, never evicted by the cache.
    fn publish_stopped_instance(
        &self,
        instance_name: &str,
        alias: &str,
    ) -> Result<crate::PublishedDisk, RuntimeError> {
        let _ = (instance_name, alias);
        Err(image_unsupported())
    }

    /// The instance's `last_used_at` as Incus reports it ([unverified]
    /// field), compared only for equality; `None` when not reported.
    fn instance_last_used(&self, instance_name: &str) -> Result<Option<String>, RuntimeError> {
        let _ = instance_name;
        Err(image_unsupported())
    }

    /// The instance's `volatile.cloud-init.instance-id` ([unverified]).
    fn cloud_init_instance_id(&self, instance_name: &str) -> Result<Option<String>, RuntimeError> {
        let _ = instance_name;
        Err(image_unsupported())
    }

    /// Measured bytes of the instance's root volume (`disk.root.usage`,
    /// [unverified] for a stopped VM); `None` when not reported.
    fn instance_root_usage(&self, instance_name: &str) -> Result<Option<u64>, RuntimeError> {
        let _ = instance_name;
        Err(image_unsupported())
    }

    /// Every `wssp-off-*` alias of this runtime's image store, as one
    /// bounded read (an error is never evidence of absence).
    fn offload_aliases(&self) -> Result<Vec<crate::OffloadAlias>, RuntimeError> {
        Err(image_unsupported())
    }

    /// Whether Incus still runs (or has pending) an operation on the
    /// instance ([unverified] `GET /1.0/operations` resources).
    fn instance_operation_running(&self, instance_name: &str) -> Result<bool, RuntimeError> {
        let _ = instance_name;
        Err(image_unsupported())
    }

    /// Delete the orphan root
    /// volume of `instance_name` on `root.pool` (the copy row's
    /// `storagePoolName + storageMarker`, the census root identity). Refused
    /// while the instance exists; nothing to do when no such volume exists.
    /// The caller proves the absence afterwards (`prove_root_absent`).
    fn delete_orphan_root(
        &self,
        root: &crate::RootDisk,
        instance_name: &str,
    ) -> Result<(), RuntimeError> {
        let _ = (root, instance_name);
        Err(storage_unsupported())
    }

    /// Snapshot-to-template: copy, scrub and publish a sandbox's root as a
    /// new unified image. `progress` reports each phase as it starts.
    fn capture_template(
        &self,
        request: &crate::CaptureRequest,
        progress: &dyn Fn(crate::CapturePhase),
    ) -> Result<crate::CaptureOutcome, RuntimeError> {
        let _ = (request, progress);
        Err(image_unsupported())
    }

    /// Recovery after a daemon restart interrupted a capture: remove the
    /// capture's own disposable VM and source snapshot (both named from the
    /// operation ID). Never touches the sandbox or any image. Best effort.
    fn discard_capture(&self, sandbox_id: &str, operation_id: &str) -> Result<(), RuntimeError> {
        let _ = (sandbox_id, operation_id);
        Ok(())
    }

    /// Credential capture: pack the declared paths of the guest home into a
    /// bundle v1 (files only). Never follows a link; fails closed on limits.
    fn credential_pack(
        &self,
        request: &crate::CredentialPackRequest,
    ) -> Result<crate::CredentialPackOutcome, RuntimeError> {
        let _ = request;
        Err(credential_unsupported())
    }

    /// Credential install: clear every declared path (verified), then write
    /// the entries descriptor-relatively (temp file + rename).
    fn credential_restore(
        &self,
        request: &crate::CredentialRestoreRequest<'_>,
    ) -> Result<crate::CredentialRestoreOutcome, RuntimeError> {
        let _ = request;
        Err(credential_unsupported())
    }

    /// Credential scrub: unlink the paths (a link is unlinked, its target is
    /// never touched) and verify absence. A scrub that could not verify
    /// absence is `Ok` with `verified_absent: false`.
    fn credential_scrub(
        &self,
        request: &crate::CredentialScrubRequest,
    ) -> Result<crate::CredentialScrubOutcome, RuntimeError> {
        let _ = request;
        Err(credential_unsupported())
    }

    /// Stop guest-uid writers before a teardown pack (SIGTERM, grace, then
    /// SIGKILL under the cgroup v2 freezer). Root guest processes are never
    /// signalled; pack/scrub correctness never depends on this.
    fn credential_quiesce(
        &self,
        guest: &crate::CredentialGuest,
    ) -> Result<crate::CredentialQuiesceOutcome, RuntimeError> {
        let _ = guest;
        Err(credential_unsupported())
    }

    /// Pre-check: the guest can run the credential helper.
    fn credential_helper_present(
        &self,
        guest: &crate::CredentialGuest,
    ) -> Result<bool, RuntimeError> {
        let _ = guest;
        Err(credential_unsupported())
    }

    // VM existence is live-state evidence only; retained disks use prove_root_absent.
    /// Existence only: no image, ownership, readiness or policy validation may
    /// turn an existing instance into an absence proof. Errors remain ambiguous.
    fn sandbox_exists(&self, _sandbox_id: &str) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "runtime cannot prove instance absence",
        ))
    }

    /// Narrow host observation without readiness/image/policy checks. Only a
    /// positively stopped or absent VM returns false; transitional states may
    /// be running and errors remain ambiguous. Never mutates daemon state.
    fn sandbox_may_be_running(&self, _sandbox_id: &str) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "runtime cannot prove no running instance",
        ))
    }

    /// Graceful-first stop (C55 lease expiry): ask the guest to shut down and
    /// wait at most `timeout`. It never forces; a guest still running at the
    /// timeout is a failure, and the caller then falls back to the forced
    /// [`SandboxRuntime::stop_sandbox`]. Runtimes without a graceful path
    /// report `UNSUPPORTED_CAPABILITY` (no completion evidence), so callers
    /// always reach the forced fallback.
    fn stop_sandbox_graceful(
        &self,
        request: &StopSandboxRequest,
        timeout: std::time::Duration,
    ) -> crate::EffectOutcome<StopSandboxResponse> {
        let _ = (request, timeout);
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "runtime has no graceful stop",
        )
        .into())
    }

    fn run_command(&self, request: &RunCommandRequest) -> crate::EffectOutcome<RunCommandResponse>;

    /// Default for immediate runtimes; blocking runtimes override this entry.
    fn run_command_stream(
        &self,
        request: &RunCommandRequest,
        output: &crate::CommandOutput,
    ) -> crate::EffectOutcome<RunCommandResponse> {
        self.run_command(request).map(|done| {
            done.map(|response| {
                for chunk in &response.command.chunks {
                    output.push(chunk.stream, &chunk.bytes);
                }
                response
            })
        })
    }

    /// Whether this runtime implements [`SandboxRuntime::open_pty`] (C51).
    /// Fail-closed: runtimes without a PTY adapter report `false`.
    fn pty_capability(&self) -> bool {
        false
    }

    /// Open the single attachment to a guest terminal. The returned session
    /// is the only reader/writer/resizer (single-consumer by construction);
    /// the runtime retains close authority for stop/destroy/expiry/shutdown.
    /// Runtimes without a PTY adapter return `UNSUPPORTED_CAPABILITY`.
    fn open_pty(
        &self,
        request: &crate::OpenPtyRequest,
    ) -> Result<crate::PtySession, crate::PtyOpenFailure> {
        let _ = request;
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "Unsupported capability: terminal",
        )
        .into())
    }

    /// Close (terminate + reap) live terminal sessions of `sandbox_id`, or
    /// every session when `None`. Idempotent; returns how many it closed.
    fn close_pty_sessions(&self, sandbox_id: Option<&str>, intent: crate::PtyCloseIntent) -> usize {
        let _ = (sandbox_id, intent);
        0
    }

    /// Whether this runtime implements CLI channels (`pty` and `exec`,
    /// [`SandboxRuntime::open_channel`]). Fail-closed default.
    fn channel_capability(&self) -> bool {
        false
    }

    /// Spawn one channel process in its own guest scope (wssp-ssh). The
    /// spawn blocks (instance binding, host spawn) but carries no secret and
    /// starts no workload: the guest waits for the preamble the IO owner
    /// writes through the returned [`crate::ChannelIo`].
    fn spawn_channel(
        &self,
        request: &crate::SpawnChannelRequest,
    ) -> Result<crate::SpawnedChannel, crate::ChannelOpenFailure> {
        let _ = request;
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "Unsupported capability: channels",
        )
        .into())
    }

    /// Tombstone, kill and prove gone each listed channel scope of one
    /// sandbox (durable-registry sweep and retried uncertain kills). A
    /// positively stopped or absent instance proves every scope gone.
    fn kill_channel_scopes(
        &self,
        request: &crate::KillScopesRequest,
    ) -> Result<Vec<(String, crate::ScopeKill)>, RuntimeError> {
        let _ = request;
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "Unsupported capability: channels",
        ))
    }

    fn read_file(&self, request: &ReadFileRequest) -> Result<ReadFileResponse, RuntimeError>;

    fn write_file(&self, request: &WriteFileRequest) -> crate::EffectOutcome<WriteFileResponse>;

    /// Positive completion only when the guest destination holds exactly the
    /// requested bytes; a completed failure only when the attempt's staging
    /// file still existed (and is now removed, so it can never rename). All
    /// other observations stay unknown.
    fn recover_file_put(
        &self,
        request: &RecoverFilePutRequest,
    ) -> crate::EffectOutcome<WriteFileResponse> {
        let _ = request;
        Err(RuntimeError::new(
            SandboxErrorCode::UnknownOutcome,
            "runtime cannot recover interrupted file writes",
        )
        .into())
    }

    fn probe_sandbox(
        &self,
        request: &ProbeSandboxRequest,
    ) -> Result<ProbeSandboxResponse, RuntimeError>;

    fn stop_sandbox(
        &self,
        request: &StopSandboxRequest,
    ) -> crate::EffectOutcome<StopSandboxResponse>;

    fn list_dir(&self, request: &ListDirRequest) -> Result<ListDirResponse, RuntimeError>;

    fn stat_path(&self, request: &StatPathRequest) -> Result<EntryInfo, RuntimeError>;

    fn mkdir(&self, request: &MkdirRequest) -> crate::EffectOutcome<MkdirResponse>;

    fn remove_path(&self, request: &RemovePathRequest) -> crate::EffectOutcome<RemovePathResponse>;

    fn move_path(&self, request: &MovePathRequest) -> crate::EffectOutcome<EntryInfo>;

    fn cancel_operation(&self, operation_id: &str) -> crate::EffectOutcome<()>;

    fn list_processes(
        &self,
        request: &ListProcessesRequest,
    ) -> Result<ListProcessesResponse, RuntimeError>;

    fn signal_process(&self, request: &SignalProcessRequest)
    -> crate::EffectOutcome<SignalOutcome>;

    fn write_stdin(&self, request: &WriteStdinRequest) -> crate::EffectOutcome<()>;

    /// One retirement observation of an UNKNOWN command. `Gone`
    /// is a sound proof (VM stopped/absent, guest rebooted, or the scoped
    /// helper's proof); `Running` means the attempt's scope still runs (the
    /// caller may re-observe in the session); any doubt is an error and the
    /// caller keeps the receipt (and today's sandbox-level cleanup). A kill
    /// mode kills only a due command's whole scope, never anything else.
    /// The running VM's QEMU identity (see [`QemuIdentity`]); `None` when it
    /// cannot be read soundly (the safe direction: that arm cannot run).
    fn qemu_identity(&self, sandbox_id: &str) -> Option<QemuIdentity> {
        let _ = sandbox_id;
        None
    }

    fn retire_command_group(
        &self,
        request: &RetireCommandRequest,
    ) -> Result<RetireObservation, RuntimeError> {
        let _ = request;
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "runtime cannot retire a command process group",
        ))
    }

    fn create_snapshot(&self, request: &SnapshotRequest) -> crate::EffectOutcome<SnapshotResponse>;

    fn restore_snapshot(&self, request: &SnapshotRequest)
    -> crate::EffectOutcome<SnapshotResponse>;

    fn fork_sandbox(
        &self,
        request: &ForkSandboxRequest,
    ) -> crate::EffectOutcome<ForkSandboxResponse>;
}

#[cfg(test)]
mod description_tests {
    use super::*;

    fn request(argv: &[&str], script: Option<&str>) -> RunCommandRequest {
        RunCommandRequest {
            template_fingerprint: String::new(),
            generation: 1,
            attempt: 1,
            sandbox_id: "sbx".into(),
            instance_name: "wssp-sbx-sbx".into(),
            operation_id: "op".into(),
            idempotency_key: "op".into(),
            argv: argv.iter().map(|v| v.to_string()).collect(),
            script: script.map(str::to_string),
            cwd: None,
            timeout_ms: None,
            env: vec![("SECRET_NAME".into(), "sentinel-env-value".into())],
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        }
    }

    #[test]
    fn accepted_command_descriptions_match_typescript_fixture() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Input {
            argv: Vec<String>,
            script: Option<String>,
            cwd: Option<String>,
            guest_home: String,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Case {
            name: String,
            input: Input,
            expected: Option<serde_json::Value>,
        }
        let cases: Vec<Case> = serde_json::from_str(include_str!(
            "../../sandbox-protocol/fixtures/command_descriptions.json"
        ))
        .unwrap();
        for case in cases {
            let mut req = request(&[], None);
            req.argv = case.input.argv;
            req.script = case.input.script;
            req.cwd = case.input.cwd;
            req.guest.guest_home = case.input.guest_home;
            let actual = CommandDescription::from_request(&req).map(|d| {
                serde_json::json!({
                    "cmd": d.cmd, "args": d.args, "argsTruncated": d.args_truncated, "cwd": d.cwd,
                })
            });
            assert_eq!(actual, case.expected, "{}", case.name);
        }
    }

    #[test]
    fn descriptions_come_from_the_accepted_request_and_exclude_env_script_and_wrapper() {
        let described = CommandDescription::from_request(&request(&["echo", "a b"], None)).unwrap();
        assert_eq!(described.cmd, "echo");
        assert_eq!(described.args, ["a b"]);
        assert!(!described.args_truncated);
        assert_eq!(described.cwd, GuestIdentity::default().guest_home);
        let script =
            CommandDescription::from_request(&request(&[], Some("sentinel-script-body"))).unwrap();
        assert_eq!(script.cmd, "/bin/bash");
        assert!(script.args.is_empty() && script.args_truncated);
        for described in [described, script] {
            let text = format!("{described:?}");
            for secret in [
                "sentinel-env-value",
                "sentinel-script-body",
                "WSSP_",
                "setsid",
            ] {
                assert!(!text.contains(secret), "{secret}");
            }
        }
        let many: Vec<String> = (0..400).map(|i| format!("arg{i}")).collect();
        let refs: Vec<&str> = std::iter::once("cmd")
            .chain(many.iter().map(String::as_str))
            .collect();
        let bounded = CommandDescription::from_request(&request(&refs, None)).unwrap();
        assert!(bounded.args_truncated && bounded.args.len() <= 256);
        assert!(serde_json::to_vec(&bounded.args).unwrap().len() <= 4096);
        assert!(CommandDescription::from_request(&request(&[], None)).is_none());
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn d2_settlement_ignores_revocation_but_retains_the_exact_deadline() {
        let now = std::time::Instant::now();
        let clock = std::sync::Arc::new(std::sync::Mutex::new(now));
        let permit = super::RuntimePermit::with_test_clock(
            std::time::Duration::from_secs(10),
            clock.clone(),
        );
        *clock.lock().unwrap() = now + std::time::Duration::from_secs(8);
        permit.revoke();
        let settling = permit.settlement();
        assert!(permit.admit().is_err());
        assert!(settling.admit().is_ok());
        assert_eq!(
            settling.remaining(),
            Some(std::time::Duration::from_secs(2))
        );
        *clock.lock().unwrap() = now + std::time::Duration::from_secs(10);
        assert!(
            settling.admit().is_err(),
            "settlement restarted the cumulative deadline"
        );
    }

    #[test]
    fn a_child_permit_honours_its_parents_close_and_revocation() {
        let parent = std::sync::Arc::new(super::RuntimePermit::default());
        let child = super::RuntimePermit::child(parent.clone(), std::time::Duration::from_secs(60));
        assert!(child.admit().is_ok());
        parent.close();
        assert!(child.admit().is_err() && child.is_closed() && !child.is_cancelled());
        let parent = std::sync::Arc::new(super::RuntimePermit::default());
        let child = super::RuntimePermit::child(parent.clone(), std::time::Duration::from_secs(60));
        parent.revoke();
        assert!(child.admit().is_err() && child.is_cancelled());
    }

    #[test]
    fn ancestor_revocation_and_close_drain_child_and_grandchild_admission() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::time::{Duration, Instant};
        for grandchild in [false, true] {
            for close in [false, true] {
                let parent = Arc::new(super::RuntimePermit::default());
                let child = Arc::new(super::RuntimePermit::child(
                    parent.clone(),
                    Duration::from_secs(60),
                ));
                let descendant = if grandchild {
                    Arc::new(super::RuntimePermit::child(child, Duration::from_secs(60)))
                } else {
                    child
                };
                let admitted = Arc::new(Barrier::new(2));
                let release = Arc::new(Barrier::new(2));
                let (done_tx, done_rx) = mpsc::channel();
                std::thread::scope(|scope| {
                    scope.spawn(|| {
                        let _guard = descendant.admit().unwrap();
                        admitted.wait();
                        release.wait();
                    });
                    admitted.wait();
                    scope.spawn(|| {
                        if close {
                            parent.close();
                        } else {
                            parent.revoke();
                        }
                        done_tx.send(()).unwrap();
                    });
                    // The published flag proves revocation entered its drain;
                    // the barrier keeps admission live until explicitly released.
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while if close {
                        !parent.closed_chain()
                    } else {
                        !parent.is_revoked()
                    } {
                        if Instant::now() >= deadline {
                            break;
                        }
                        std::thread::yield_now();
                    }
                    let published = if close {
                        parent.closed_chain()
                    } else {
                        parent.is_revoked()
                    };
                    let premature = done_rx.try_recv();
                    // Release before asserting so a broken implementation
                    // fails the test without stranding a scoped thread.
                    release.wait();
                    if premature.is_err() {
                        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    assert!(published, "revocation did not publish its flag");
                    assert!(matches!(premature, Err(mpsc::TryRecvError::Empty)));
                });
                assert!(descendant.admit().is_err());
            }
        }
    }

    use super::*;

    /// Keep in lockstep with `packages/api/src/sandbox/incus-name.test.ts`.
    const FIXTURES: &[(&str, &str)] = &[
        ("sbx-1", "wssp-sbx-sbx-1"),
        ("sbx-2", "wssp-sbx-sbx-2"),
        ("sbx-3", "wssp-sbx-sbx-3"),
        (
            "ckabcdefghijklmnopqrstuv",
            "wssp-sbx-ckabcdefghijklmnopqrstuv",
        ),
    ];

    #[test]
    fn default_instance_names_match_product_prefix_fixtures() {
        assert_eq!(INCUS_INSTANCE_NAME_PREFIX, "wssp-sbx-");
        for (sandbox_id, instance_name) in FIXTURES {
            assert_eq!(default_incus_instance_name(sandbox_id), *instance_name);
            assert!(
                instance_name.starts_with(INCUS_INSTANCE_NAME_PREFIX),
                "{instance_name} must use the product prefix"
            );
            validate_managed_instance_name(instance_name).expect("fixture name");
        }
    }

    #[test]
    fn rejects_malicious_instance_names() {
        for name in [
            "-wssp-sbx-1",
            "wssp-sbx-/etc/passwd",
            "wssp-sbx-foo/bar",
            "wssp-sbx-foo%2Fbar",
            "wssp-sbx-foo%00",
            "default",
            "ubuntu",
            "wssp-sbx-",
            "wssp-sbx-.",
            "fc-sbx-1",
            "wssp-sbx- foo",
        ] {
            assert!(
                validate_managed_instance_name(name).is_err(),
                "expected reject for `{name}`"
            );
        }
        assert!(resolve_managed_instance_name("../etc/passwd", None).is_err());
        assert!(resolve_managed_instance_name("sbx-1", Some("ubuntu")).is_err());
        assert_eq!(
            resolve_managed_instance_name("sbx-1", Some("wssp-sbx-sbx-1")).expect("match"),
            "wssp-sbx-sbx-1"
        );
    }
}

fn storage_unsupported() -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::UnsupportedCapability,
        "runtime has no storage evidence",
    )
}

fn image_unsupported() -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::UnsupportedCapability,
        "runtime has no managed image store",
    )
}

fn credential_unsupported() -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::UnsupportedCapability,
        "runtime has no credential guest operations",
    )
}
