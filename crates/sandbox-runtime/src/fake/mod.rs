use crate::effect::PositiveEvidence;
mod channel;
mod credentials;
mod offload;
mod policy;
pub(crate) mod pty;
mod storage;
pub use channel::FakeChannelControl;
pub use offload::FakePublishCrash;
pub use policy::FakePolicyDrift;
pub use pty::FakePtyControl;
use std::collections::{HashMap, HashSet};

use sandbox_protocol::{OperationState, SandboxErrorCode, SandboxLifecycleState};

type GuestFileKey = (String, String);
type GuestFileMap = HashMap<GuestFileKey, crate::FileContent>;
type SnapshotStore = HashMap<GuestFileKey, GuestFileMap>;

use crate::error::RuntimeError;
use crate::r#trait::{
    CommandRecord, CommandStream, CommandStreamChunk, CreateSandboxRequest, CreateSandboxResponse,
    EntryInfo, ForkSandboxRequest, ForkSandboxResponse, GuestPathKind, KillSandboxRequest,
    KillSandboxResponse, ListDirRequest, ListDirResponse, ListProcessesRequest,
    ListProcessesResponse, MkdirRequest, MkdirResponse, MovePathRequest, ProbeSandboxRequest,
    ProbeSandboxResponse, ReadFileRequest, ReadFileResponse, ReconnectSandboxRequest,
    ReconnectSandboxResponse, RemovePathRequest, RemovePathResponse, RunCommandRequest,
    RunCommandResponse, SandboxLiveProbeState, SandboxRecord, SandboxRuntime, SignalProcessRequest,
    SnapshotRequest, SnapshotResponse, StatPathRequest, StopSandboxRequest, StopSandboxResponse,
    WriteFileRequest, WriteFileResponse, WriteStdinRequest,
};

const FAKE_FIRST_PID: u32 = 1000;

/// Ends a streamed command's signal-addressable window on every exit path.
struct FakeRunWindow(std::sync::Arc<std::sync::Mutex<FakeState>>, String);
impl Drop for FakeRunWindow {
    fn drop(&mut self) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .running
            .remove(&self.1);
    }
}
pub const FAKE_BOOT_ID: &str = "00000000-0000-4000-8000-000000000001";

/// The fake guest scope of one command attempt, as the root
/// retire helper would observe it (S4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeCommandScope {
    Absent,
    Empty,
    /// `killable: false` models a kill that never empties the scope.
    Populated {
        killable: bool,
    },
}

/// Cgroup roots owned by the guest uid (rule 8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FakeUidRoots {
    #[default]
    None,
    OneEmpty,
    OnePopulated,
    Two,
}

/// Retire-helper emulation state.
#[derive(Debug, Default)]
struct FakeScopes {
    /// Per operation id; an unset attempt has no scope (`Absent`).
    scopes: HashMap<String, FakeCommandScope>,
    /// Guest-monotonic time since each scope became active; unset fails the
    /// deadline gate (`populated`, no kill).
    active_for: HashMap<String, std::time::Duration>,
    /// `/run/wssp/unscoped` exists in the fake guest's boot.
    unscoped_marker: bool,
    uid_roots: FakeUidRoots,
    /// No `cgroup.kill` (Linux < 5.14).
    kill_unsupported: bool,
    /// No cgroup2 (`legacy`: today's arms).
    legacy: bool,
    /// Every whole-scope kill, in order: (operation, mode).
    kills: Vec<(String, crate::RetireMode)>,
}

fn fake_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

impl FakeState {
    /// The root retire helper's rules 4'-8 over the fake scope. `Ok(None)`
    /// is `unscoped`; `Err` is a final unproven verdict. A proof is
    /// returned as `Running`/`Gone` only after the uid-root check.
    fn scope_verdict(
        &mut self,
        request: &crate::RetireCommandRequest,
    ) -> Result<Option<crate::RetireObservation>, RuntimeError> {
        let final_verdict = |what: &str| {
            Err(RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                format!("command disappearance unproven: {what}"),
            ))
        };
        let scopes = &mut self.scopes;
        let scope = scopes
            .scopes
            .get(&request.operation_id)
            .copied()
            .unwrap_or(FakeCommandScope::Absent);
        match scope {
            FakeCommandScope::Absent if scopes.unscoped_marker => return Ok(None),
            FakeCommandScope::Absent | FakeCommandScope::Empty => {}
            FakeCommandScope::Populated { killable } => {
                if request.mode == crate::RetireMode::Observe {
                    return Ok(Some(crate::RetireObservation::Running { not_due: None }));
                }
                if request.mode == crate::RetireMode::KillDeadline {
                    if request.budget_ms == 0 {
                        return Ok(Some(crate::RetireObservation::Running { not_due: None }));
                    }
                    let Some(elapsed) = scopes.active_for.get(&request.operation_id) else {
                        return Ok(Some(crate::RetireObservation::Running { not_due: None }));
                    };
                    let due = std::time::Duration::from_millis(request.budget_ms)
                        + crate::RETIRE_DEADLINE_SLACK;
                    if *elapsed < due {
                        return Ok(Some(crate::RetireObservation::Running {
                            not_due: Some(due - *elapsed),
                        }));
                    }
                }
                if scopes.kill_unsupported {
                    return final_verdict("unsupported");
                }
                scopes
                    .kills
                    .push((request.operation_id.clone(), request.mode));
                if !killable {
                    return final_verdict("timeout");
                }
                scopes
                    .scopes
                    .insert(request.operation_id.clone(), FakeCommandScope::Absent);
            }
        }
        match scopes.uid_roots {
            FakeUidRoots::None | FakeUidRoots::OneEmpty => {}
            FakeUidRoots::OnePopulated => return final_verdict("uid_populated"),
            FakeUidRoots::Two => return final_verdict("unsupported"),
        }
        self.retired
            .push((request.operation_id.clone(), request.birth.clone()));
        Ok(Some(crate::RetireObservation::Gone(
            crate::CommandGroupGone::proven(&request.birth),
        )))
    }
}

#[derive(Debug, Default)]
struct FakeState {
    sandboxes: HashMap<String, SandboxRecord>,
    sandbox_sizes: HashMap<String, sandbox_protocol::VmSize>,
    /// B12: sandboxes whose create asked for blocked-name hints.
    refused_dns_hint_creates: HashSet<String>,
    /// Preview tunnels: the recorded (pinned address, declared ports).
    tunnel_targets: HashMap<String, (std::net::Ipv4Addr, Vec<u16>)>,
    /// Preview tunnels: the recorded declared-ports revision.
    tunnel_revisions: HashMap<String, u64>,
    storage_pools: HashMap<String, crate::StoragePoolIdentity>,
    unavailable_pools: HashSet<String>,
    root_disks: HashMap<String, crate::RootDisk>,
    create_idempotency: HashMap<String, String>,
    commands: HashMap<String, CommandRecord>,
    /// Deterministic guest PIDs for fake births; never reused within a state.
    next_pid: u32,
    /// Commands inside their streamed run window: (generation, attempt, birth).
    running: HashMap<String, (u64, u64, crate::CommandBirth)>,
    /// Conformance knob: a guest kernel without PIDFD_SIGNAL_PROCESS_GROUP
    /// (e.g. Ubuntu 24.04 GA 6.8).
    guest_lacks_group_signals: bool,
    /// Group deliveries observed (operation, signal); never wrapper-only.
    delivered: Vec<(String, crate::ProcessSignal)>,
    /// Commands proven gone (operation, bound birth), in order.
    retired: Vec<(String, crate::CommandBirth)>,
    /// Every `retire_command_group` call, proven or not.
    retire_attempts: usize,
    /// The root retire helper's view of command scopes.
    scopes: FakeScopes,
    files: GuestFileMap,
    dirs: HashMap<String, HashSet<String>>,
    snapshots: SnapshotStore,
    cancelled: HashSet<String>,
    image_aliases: HashMap<String, (String, String)>,
    images: HashMap<String, (String, crate::GuestIdentity, bool)>,
    /// Compressed sizes of images in the fake store (fingerprint -> bytes).
    image_sizes: HashMap<String, u64>,
    /// Unified tarball bytes of imported or published images.
    image_bytes: HashMap<String, Vec<u8>>,
    /// Fault injection: the image inventory read fails.
    image_inventory_fails: bool,
    /// Captures published so far (makes each capture's bytes distinct).
    captures: u32,
    /// `(sandbox_id, operation_id)` of every `discard_capture` call.
    discarded_captures: Vec<(String, String)>,
    /// Resolved login scrub targets of every `capture_template` call.
    capture_credential_scrubs: Vec<Vec<String>>,
    /// Fault injection: `discard_capture` cannot prove the leftovers gone.
    discard_capture_fails: bool,
    sandbox_images: HashMap<String, String>,
    /// The disk image a restored sandbox was launched from
    /// (the `user.flycockpit.restore_base` tag); its template stays in
    /// `sandbox_images`.
    restore_bases: HashMap<String, String>,
    /// The restore bases the daemon bound (`bind_restore_base`).
    bound_restore_bases: HashMap<String, String>,
    /// The persisted readiness spec per sandbox: architecture, declared
    /// guest and readiness mode (like Incus's `user.flycockpit.readiness`).
    sandbox_readiness: HashMap<String, (String, crate::GuestIdentity, crate::ReadinessMode)>,
    policy_drift: HashMap<String, FakePolicyDrift>,
    /// Recorded effective egress mode per sandbox (§3 FakeRuntime): the
    /// cold-reconnect check reads it, never the request.
    egress_modes: HashMap<String, sandbox_protocol::EgressMode>,
    /// Guest sudo (like Incus): the persisted spec's `sudo` per sandbox, every
    /// helper step `(sandbox, mode)` in order, and injected failures (the
    /// readiness reason a step of that mode fails with).
    spec_sudo: HashMap<String, bool>,
    guest_sudo_steps: Vec<(String, &'static str)>,
    guest_sudo_failures: HashMap<&'static str, sandbox_protocol::ReadinessFailureReason>,
    /// Split (upstream) imports so far.
    split_imports: usize,
    /// R11: each running fake VM's QEMU identity; a restart bumps it.
    qemu: HashMap<String, crate::QemuIdentity>,
    next_qemu_pid: u64,
    /// Disk offload (`fake/offload.rs`).
    offload: offload::FakeOffloadState,
    /// Test fault injection: sandboxes whose host network cleanup is still pending.
    network_cleanup_pending: HashSet<String>,
}

impl FakeState {
    /// The guest sudo step a boot runs (`check_readiness` in Incus): grant,
    /// revoke, or revoke plus the create-time audit.
    fn guest_sudo_step(
        &mut self,
        sandbox_id: &str,
        mode: &'static str,
        strict: bool,
    ) -> Result<(), RuntimeError> {
        self.guest_sudo_steps.push((sandbox_id.to_string(), mode));
        match self.guest_sudo_failures.get(mode).copied() {
            Some(reason) if strict || mode == "grant" => Err(RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                format!("readiness failed ({})", reason.as_str()),
            )
            .with_readiness_reason(reason)),
            _ => Ok(()),
        }
    }

    fn create_guest_sudo(&mut self, request: &CreateSandboxRequest) -> Result<(), RuntimeError> {
        let privilege = request.guest_privilege;
        let mode = if privilege.sudo {
            "grant"
        } else if privilege.audit {
            "revoke-audit"
        } else {
            "revoke"
        };
        self.guest_sudo_step(&request.sandbox_id, mode, true)
    }

    fn boot_qemu(&mut self, sandbox_id: &str) {
        self.next_qemu_pid += 1;
        let pid = 4000 + self.next_qemu_pid;
        self.qemu.insert(
            sandbox_id.to_string(),
            crate::QemuIdentity {
                pid,
                start_ticks: pid * 10,
            },
        );
        self.note_boot_for_offload(sandbox_id, pid);
    }

    fn create_sandbox(
        &mut self,
        request: &CreateSandboxRequest,
    ) -> Result<CreateSandboxResponse, RuntimeError> {
        request
            .lease
            .validate_now()
            .map_err(|message| RuntimeError::new(SandboxErrorCode::StateConflict, message))?;
        crate::resources::validate_vm_size(request.vm_size)?;
        request.guest.validate()?;
        // A restore launches the stored disk image; the
        // template binding stays the template digest.
        let (fp, launch) = match &request.restore {
            Some(restore) => (
                crate::normalize_incus_fingerprint(&request.template_digest)?,
                crate::require_restore_launch_fingerprint(
                    &restore.fingerprint,
                    &request.template_digest,
                )?,
            ),
            None => {
                let fp = crate::require_launch_fingerprint(
                    request.incus_fingerprint.as_deref(),
                    &request.template_digest,
                )?;
                (fp.clone(), fp)
            }
        };
        // Kill leaves historical keys behind. Only a surviving VM makes this
        // an existing-instance adoption, just like Incus's name lookup.
        if let Some(existing_id) = self
            .create_idempotency
            .get(&request.idempotency_key)
            .filter(|id| self.sandboxes.contains_key(*id))
        {
            let mut sandbox = self.sandboxes.get(existing_id).cloned().ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "idempotency index pointed at missing sandbox",
                )
            })?;
            if existing_id != &request.sandbox_id {
                return Err(RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "sandbox binding differs",
                ));
            }
            self.policy_binding(&request.sandbox_id)?;
            self.verify_binding(&request.sandbox_id, Some(&fp))?;
            if self.restore_bases.get(&request.sandbox_id)
                != request.restore.as_ref().map(|_| &launch)
            {
                return Err(RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "restore base binding differs",
                ));
            }
            self.verify_readiness(
                &launch,
                request.architecture.as_deref(),
                &request.guest,
                request.readiness,
            )?;
            self.verify_size(&request.sandbox_id, request.vm_size)?;
            self.existing_create_policy(
                &request.sandbox_id,
                sandbox.state == SandboxLifecycleState::Ready,
            )?;
            if sandbox.state != SandboxLifecycleState::Ready {
                self.boot_qemu(&request.sandbox_id);
            }
            self.create_guest_sudo(request)?;
            sandbox.state = SandboxLifecycleState::Ready;
            self.sandboxes
                .insert(sandbox.sandbox_id.clone(), sandbox.clone());
            return Ok(CreateSandboxResponse {
                sandbox,
                egress_denied_grants: fake_denied_grants(request),
                guest_group_signals: Some(!self.guest_lacks_group_signals),
                guest_linger: Some(crate::GuestLinger::Blocked),
                readiness_restarts: 0,
            });
        }

        if self.sandboxes.contains_key(&request.sandbox_id) {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                format!("sandbox id {} already exists", request.sandbox_id),
            ));
        }

        self.verify_readiness(
            &launch,
            request.architecture.as_deref(),
            &request.guest,
            request.readiness,
        )?;
        self.sandbox_sizes
            .insert(request.sandbox_id.clone(), request.vm_size);
        self.sandbox_images.insert(request.sandbox_id.clone(), fp);
        if request.restore.is_some() {
            self.restore_bases
                .insert(request.sandbox_id.clone(), launch);
        } else {
            self.restore_bases.remove(&request.sandbox_id);
        }
        self.sandbox_readiness.insert(
            request.sandbox_id.clone(),
            (
                request.architecture.clone().unwrap_or_default(),
                request.guest.clone(),
                request.readiness,
            ),
        );
        self.spec_sudo
            .insert(request.sandbox_id.clone(), request.guest_privilege.sudo);
        self.boot_qemu(&request.sandbox_id);
        self.create_guest_sudo(request)?;

        let sandbox = SandboxRecord {
            sandbox_id: request.sandbox_id.clone(),
            generation: 1,
            state: SandboxLifecycleState::Ready,
            idempotency_key: request.idempotency_key.clone(),
        };
        self.sandboxes
            .insert(request.sandbox_id.clone(), sandbox.clone());
        self.create_idempotency
            .insert(request.idempotency_key.clone(), request.sandbox_id.clone());
        Ok(CreateSandboxResponse {
            sandbox,
            egress_denied_grants: fake_denied_grants(request),
            guest_group_signals: Some(!self.guest_lacks_group_signals),
            guest_linger: Some(crate::GuestLinger::Blocked),
            readiness_restarts: 0,
        })
    }

    fn verify_size(
        &self,
        sandbox_id: &str,
        expected: sandbox_protocol::VmSize,
    ) -> Result<(), RuntimeError> {
        if self.sandbox_sizes.get(sandbox_id) != Some(&expected) {
            return Err(RuntimeError::new(
                SandboxErrorCode::VmSizeMismatch,
                "VM allocation differs",
            ));
        }
        Ok(())
    }

    fn verify_binding(
        &self,
        sandbox_id: &str,
        expected: Option<&str>,
    ) -> Result<&str, RuntimeError> {
        self.sandbox_images
            .get(sandbox_id)
            .filter(|fp| expected.is_none_or(|expected| expected == fp.as_str()))
            .map(String::as_str)
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "template binding differs",
                )
            })
    }

    /// Like Incus readiness: `Standard` requires the image's guest identity
    /// to equal the declared one; `BuildBootstrap` (a raw upstream image)
    /// checks only the image and its architecture.
    fn verify_readiness(
        &self,
        fp: &str,
        architecture: Option<&str>,
        guest: &crate::GuestIdentity,
        mode: crate::ReadinessMode,
    ) -> Result<(), RuntimeError> {
        guest.validate()?;
        let identity = |image: &crate::GuestIdentity| {
            mode == crate::ReadinessMode::BuildBootstrap || guest == image
        };
        if self.images.get(fp).is_some_and(|image| {
            architecture == Some(image.0.as_str()) && identity(&image.1) && image.2
        }) {
            Ok(())
        } else {
            Err(RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                "fake guest readiness failed",
            )
            .with_readiness_reason(sandbox_protocol::ReadinessFailureReason::GuestUser))
        }
    }

    fn kill_sandbox(
        &mut self,
        request: &KillSandboxRequest,
    ) -> Result<KillSandboxResponse, RuntimeError> {
        let sandbox = self
            .sandboxes
            .remove(&request.sandbox_id)
            .unwrap_or_else(|| SandboxRecord {
                sandbox_id: request.sandbox_id.clone(),
                generation: 1,
                state: SandboxLifecycleState::Deleted,
                idempotency_key: request.idempotency_key.clone(),
            });
        self.root_disks
            .remove(&crate::default_incus_instance_name(&request.sandbox_id));
        Ok(KillSandboxResponse {
            sandbox: SandboxRecord {
                sandbox_id: sandbox.sandbox_id,
                generation: sandbox.generation,
                state: SandboxLifecycleState::Deleted,
                idempotency_key: sandbox.idempotency_key,
            },
        })
    }

    fn run_command(
        &mut self,
        request: &RunCommandRequest,
        force_command_timeout: bool,
    ) -> Result<RunCommandResponse, RuntimeError> {
        self.require_live(&request.sandbox_id)?;
        let sandbox = self.sandboxes.get(&request.sandbox_id).ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::SandboxNotFound,
                format!("sandbox {} not found", request.sandbox_id),
            )
        })?;
        if sandbox.state != SandboxLifecycleState::Ready {
            return Err(RuntimeError::new(
                SandboxErrorCode::SandboxNotRunning,
                format!("sandbox {} is not running", request.sandbox_id),
            ));
        }

        if self.commands.contains_key(&request.operation_id) {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                format!("operation id {} already exists", request.operation_id),
            ));
        }

        if self.cancelled.contains(&request.operation_id) {
            return Err(RuntimeError::new(
                SandboxErrorCode::Cancelled,
                "command cancelled",
            ));
        }

        request.validate_command_shape()?;
        if force_command_timeout {
            return Err(RuntimeError::new(
                SandboxErrorCode::Timeout,
                "injected command timeout",
            ));
        }

        let joined = if let Some(crate::BuildStep::Copy(copy)) = &request.build_step {
            // The fixed COPY helper's validated arguments, not its source.
            let argv = crate::build_copy_argv(copy, &request.guest)?;
            format!("build-copy {}", argv.get(5..).unwrap_or_default().join(" "))
        } else if let Some(script) = &request.script {
            format!("script:{script}")
        } else {
            request.argv.join(" ")
        };
        // D1: a build-root step is observable as such; everything else keeps
        // the guest-user transcript unchanged.
        let joined = if request.runs_as_root() {
            format!("[root] {joined}")
        } else {
            joined
        };
        let env = request
            .env
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",");
        let stdout = if env.is_empty() {
            format!("exec:{joined}\n")
        } else {
            format!("exec:{joined};env:{env}\n")
        };
        let exit_code = if let Some(script) = &request.script {
            fake_script_exit_code(script)
        } else {
            fake_command_exit_code(&request.argv)
        };
        // Conformance with the supervised wrapper: identity is bound once at
        // start, from host clock time; FakeRuntime never reuses a PID.
        self.next_pid = self.next_pid.max(FAKE_FIRST_PID).saturating_add(1);
        let birth = crate::CommandBirth {
            pid: self.next_pid,
            boot_id: FAKE_BOOT_ID.to_string(),
            start_ticks: u64::from(self.next_pid),
            started_at_ms: fake_now_ms(),
        };
        let command = CommandRecord {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            state: OperationState::Succeeded,
            exit_code: Some(exit_code),
            guest_pid: None,
            birth: Some(birth),
            chunks: vec![CommandStreamChunk {
                stream: CommandStream::Stdout,
                sequence: 0,
                bytes: stdout.into_bytes(),
                final_chunk: true,
            }],
        };
        self.commands
            .insert(request.operation_id.clone(), command.clone());
        Ok(RunCommandResponse { command })
    }

    fn read_file(&mut self, request: &ReadFileRequest) -> Result<ReadFileResponse, RuntimeError> {
        crate::metadata::validate_file_path(&request.path)?;
        self.require_live(&request.sandbox_id)?;
        self.require_parent(&request.sandbox_id, &request.path)?;
        if self.is_dir(&request.sandbox_id, &request.path) {
            return Err(crate::metadata::fs_error(SandboxErrorCode::FsIsDirectory));
        }
        let stored = self
            .files
            .get(&(request.sandbox_id.clone(), request.path.clone()))
            .ok_or_else(|| crate::metadata::fs_error(SandboxErrorCode::FsNotFound))?;
        // Like a real guest read: a fresh, charged host capture of guest disk.
        let response = ReadFileResponse {
            path: request.path.clone(),
            bytes: stored.staged_copy(&request.sandbox_owner_id)?,
        };
        Ok(response)
    }

    fn write_file(
        &mut self,
        request: &WriteFileRequest,
    ) -> Result<WriteFileResponse, RuntimeError> {
        crate::metadata::validate_file_path(&request.path)?;
        self.require_live(&request.sandbox_id)?;
        if self.is_dir(&request.sandbox_id, &request.path) {
            return Err(crate::metadata::fs_error(SandboxErrorCode::FsIsDirectory));
        }
        let mut prefix = String::new();
        let parts: Vec<_> = request.path.split('/').filter(|p| !p.is_empty()).collect();
        for part in parts.iter().take(parts.len().saturating_sub(1)) {
            prefix.push('/');
            prefix.push_str(part);
            if self
                .files
                .contains_key(&(request.sandbox_id.clone(), prefix.clone()))
            {
                return Err(crate::metadata::fs_error(SandboxErrorCode::FsNotDirectory));
            }
        }
        // Simulated guest disk is not host transfer staging: persist an
        // uncharged copy so the transfer's slot is released when it drops.
        let stored = request.bytes.guest_disk_copy()?;
        self.ensure_parents(&request.sandbox_id, &request.path);
        self.files
            .insert((request.sandbox_id.clone(), request.path.clone()), stored);
        let response = WriteFileResponse {
            path: request.path.clone(),
            bytes_written: request.bytes.len() as u64,
        };
        Ok(response)
    }

    fn reconnect_sandbox(
        &mut self,
        request: &ReconnectSandboxRequest,
    ) -> Result<ReconnectSandboxResponse, RuntimeError> {
        request
            .lease
            .validate_now()
            .map_err(|message| RuntimeError::new(SandboxErrorCode::StateConflict, message))?;
        crate::resources::validate_vm_size(request.vm_size)?;
        self.policy_binding(&request.sandbox_id)?;
        let fp = self.verify_binding(&request.sandbox_id, Some(&request.template_fingerprint))?;
        // Never bootstrap on reconnect (like Incus).
        self.verify_readiness(
            fp,
            request.architecture.as_deref(),
            &request.guest,
            crate::ReadinessMode::Standard,
        )?;
        let sandbox = self.require_sandbox(&request.sandbox_id)?;
        self.verify_size(&request.sandbox_id, request.vm_size)?;
        self.policy_ready(
            &request.sandbox_id,
            sandbox.state == SandboxLifecycleState::Ready,
        )?;
        // Like Incus: the spec's sudo must equal the lease's.
        if self
            .spec_sudo
            .get(&request.sandbox_id)
            .copied()
            .unwrap_or(false)
            != request.guest_sudo
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                "guest sudo binding differs from the instance's readiness spec",
            )
            .with_readiness_reason(sandbox_protocol::ReadinessFailureReason::GuestCheck));
        }
        if sandbox.state != SandboxLifecycleState::Ready {
            self.boot_qemu(&request.sandbox_id);
        }
        self.guest_sudo_step(
            &request.sandbox_id,
            if request.guest_sudo {
                "grant"
            } else {
                "revoke"
            },
            false,
        )?;
        if let Some(record) = self.sandboxes.get_mut(&request.sandbox_id) {
            record.state = SandboxLifecycleState::Ready;
        }
        Ok(ReconnectSandboxResponse {
            sandbox: SandboxRecord {
                state: SandboxLifecycleState::Ready,
                ..sandbox
            },
            guest_group_signals: Some(!self.guest_lacks_group_signals),
            guest_linger: Some(crate::GuestLinger::Blocked),
            readiness_restarts: 0,
        })
    }

    fn stop_sandbox(
        &mut self,
        request: &StopSandboxRequest,
    ) -> Result<StopSandboxResponse, RuntimeError> {
        self.qemu.remove(&request.sandbox_id);
        let sandbox = if let Some(record) = self.sandboxes.get_mut(&request.sandbox_id) {
            record.state = SandboxLifecycleState::Stopped;
            record.clone()
        } else {
            SandboxRecord {
                sandbox_id: request.sandbox_id.clone(),
                generation: 1,
                state: SandboxLifecycleState::Absent,
                idempotency_key: request.idempotency_key.clone(),
            }
        };
        Ok(StopSandboxResponse { sandbox })
    }

    fn list_dir(&mut self, request: &ListDirRequest) -> Result<ListDirResponse, RuntimeError> {
        self.require_live(&request.sandbox_id)?;
        let root = request.validate_page()?;
        let stat = self.stat_path(&StatPathRequest {
            template_fingerprint: request.template_fingerprint.clone(),
            guest: request.guest.clone(),
            sandbox_id: request.sandbox_id.clone(),
            instance_name: request.instance_name.clone(),
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            path: root.clone(),
        })?;
        if stat.r#type != GuestPathKind::Dir {
            return Err(crate::metadata::fs_error(SandboxErrorCode::FsNotDirectory));
        }
        let files = self
            .files
            .iter()
            .filter(|((sandbox, path), _)| {
                sandbox == &request.sandbox_id
                    && crate::metadata::relative_key(&root, path, request.depth).is_some()
            })
            .map(|((_, path), bytes)| {
                fake_entry(
                    path,
                    GuestPathKind::File,
                    bytes.len() as u64,
                    &request.guest,
                )
            });
        let dirs = self
            .dirs
            .get(&request.sandbox_id)
            .into_iter()
            .flatten()
            .filter(|path| crate::metadata::relative_key(&root, path, request.depth).is_some())
            .map(|path| fake_entry(path, GuestPathKind::Dir, 0, &request.guest));
        crate::metadata::select_page(request, files.chain(dirs))
    }

    fn stat_path(&mut self, request: &StatPathRequest) -> Result<EntryInfo, RuntimeError> {
        self.require_live(&request.sandbox_id)?;
        let path = crate::canonical_metadata_path(&request.path, false)?;
        self.require_parent(&request.sandbox_id, &path)?;
        if let Some(bytes) = self.files.get(&(request.sandbox_id.clone(), path.clone())) {
            return Ok(fake_entry(
                &path,
                GuestPathKind::File,
                bytes.len() as u64,
                &request.guest,
            ));
        }
        if path == "/"
            || self
                .dirs
                .get(&request.sandbox_id)
                .is_some_and(|dirs| dirs.contains(&path))
        {
            return Ok(fake_entry(&path, GuestPathKind::Dir, 0, &request.guest));
        }
        Err(crate::metadata::fs_error(SandboxErrorCode::FsNotFound))
    }

    fn is_dir(&self, sandbox: &str, path: &str) -> bool {
        path == "/"
            || self
                .dirs
                .get(sandbox)
                .is_some_and(|dirs| dirs.contains(path))
    }
    fn has_children(&self, sandbox: &str, path: &str) -> bool {
        let prefix = format!("{path}/");
        self.files
            .keys()
            .any(|(s, p)| s == sandbox && p.starts_with(&prefix))
            || self
                .dirs
                .get(sandbox)
                .is_some_and(|dirs| dirs.iter().any(|p| p.starts_with(&prefix)))
    }
    fn require_directory(&self, sandbox: &str, path: &str) -> Result<(), RuntimeError> {
        let mut prefix = String::new();
        for part in path.split('/').filter(|p| !p.is_empty()) {
            prefix.push('/');
            prefix.push_str(part);
            if self.files.contains_key(&(sandbox.into(), prefix.clone())) {
                return Err(crate::metadata::fs_error(SandboxErrorCode::FsNotDirectory));
            }
            if !self.is_dir(sandbox, &prefix) {
                return Err(crate::metadata::fs_error(SandboxErrorCode::FsNotFound));
            }
        }
        Ok(())
    }
    fn require_parent(&self, sandbox: &str, path: &str) -> Result<(), RuntimeError> {
        let parent = path
            .rsplit_once('/')
            .map(|(p, _)| if p.is_empty() { "/" } else { p })
            .unwrap_or("/");
        self.require_directory(sandbox, parent)
    }
    fn mkdir(&mut self, request: &MkdirRequest) -> Result<MkdirResponse, RuntimeError> {
        self.require_live(&request.sandbox_id)?;
        let path = crate::canonical_metadata_path(&request.path, true)?;
        let mut prefix = String::new();
        let mut created = false;
        let mut created_any = false;
        for part in path.split('/').skip(1) {
            prefix.push('/');
            prefix.push_str(part);
            if self
                .files
                .contains_key(&(request.sandbox_id.clone(), prefix.clone()))
            {
                // B2-C-5: parents created before the failure are a partial
                // effect, exactly as the guest helper accounts for them.
                let error = crate::metadata::fs_error(if prefix == path {
                    SandboxErrorCode::FsAlreadyExists
                } else {
                    SandboxErrorCode::FsNotDirectory
                });
                return Err(if created_any {
                    error.filesystem(sandbox_protocol::results::FailureEffect::Partial)
                } else {
                    error
                });
            }
            created = self
                .dirs
                .entry(request.sandbox_id.clone())
                .or_default()
                .insert(prefix.clone());
            created_any |= created;
        }
        Ok(MkdirResponse { created })
    }
    fn remove_path(
        &mut self,
        request: &RemovePathRequest,
    ) -> Result<RemovePathResponse, RuntimeError> {
        self.require_live(&request.sandbox_id)?;
        let path = crate::canonical_metadata_path(&request.path, true)?;
        self.require_parent(&request.sandbox_id, &path)?;
        let file_key = (request.sandbox_id.clone(), path.clone());
        let is_dir = self.is_dir(&request.sandbox_id, &path);
        if !is_dir && !self.files.contains_key(&file_key) {
            return Err(crate::metadata::fs_error(SandboxErrorCode::FsNotFound));
        }
        if is_dir && !request.recursive && self.has_children(&request.sandbox_id, &path) {
            return Err(crate::metadata::fs_error(SandboxErrorCode::FsNotEmpty));
        }
        let prefix = format!("{path}/");
        self.files.retain(|(sandbox, p), _| {
            sandbox != &request.sandbox_id
                || (p != &path && !(request.recursive && p.starts_with(&prefix)))
        });
        if let Some(dirs) = self.dirs.get_mut(&request.sandbox_id) {
            dirs.retain(|p| p != &path && !(request.recursive && p.starts_with(&prefix)));
        }
        Ok(RemovePathResponse { removed: true })
    }
    fn move_path(&mut self, request: &MovePathRequest) -> Result<EntryInfo, RuntimeError> {
        self.require_live(&request.sandbox_id)?;
        let from = crate::canonical_metadata_path(&request.from, true)?;
        let to = crate::canonical_metadata_path(&request.to, true)?;
        let sandbox = &request.sandbox_id;
        self.require_parent(sandbox, &from)?;
        let source_file = self.files.get(&(sandbox.clone(), from.clone())).cloned();
        let source_dir = self.is_dir(sandbox, &from);
        if source_file.is_none() && !source_dir {
            return Err(crate::metadata::fs_error(SandboxErrorCode::FsNotFound));
        }
        let parent = to
            .rsplit_once('/')
            .map(|(p, _)| if p.is_empty() { "/" } else { p })
            .unwrap_or("/");
        self.require_directory(sandbox, parent)?;
        if from == to {
            return Ok(fake_entry(
                &to,
                if source_dir {
                    GuestPathKind::Dir
                } else {
                    GuestPathKind::File
                },
                source_file.as_ref().map_or(0, |b| b.len() as u64),
                &request.guest,
            ));
        }
        let destination_dir = self.is_dir(sandbox, &to);
        if !source_dir && destination_dir {
            return Err(crate::metadata::fs_error(SandboxErrorCode::FsIsDirectory));
        }
        if source_dir && self.files.contains_key(&(sandbox.clone(), to.clone())) {
            return Err(crate::metadata::fs_error(SandboxErrorCode::FsNotDirectory));
        }
        if destination_dir && self.has_children(sandbox, &to) {
            return Err(crate::metadata::fs_error(SandboxErrorCode::FsNotEmpty));
        }
        if source_dir && to.starts_with(&format!("{from}/")) {
            return Err(crate::metadata::fs_error(SandboxErrorCode::ProtocolError));
        }
        if let Some(bytes) = source_file {
            let size = bytes.len() as u64;
            self.files.remove(&(sandbox.clone(), from));
            self.files.insert((sandbox.clone(), to.clone()), bytes);
            return Ok(fake_entry(&to, GuestPathKind::File, size, &request.guest));
        }
        let prefix = format!("{from}/");
        let files: Vec<_> = self
            .files
            .iter()
            .filter(|((s, p), _)| s == sandbox && p.starts_with(&prefix))
            .map(|((_, p), b)| (p.clone(), b.clone()))
            .collect();
        for (old, bytes) in files {
            self.files.remove(&(sandbox.clone(), old.clone()));
            self.files.insert(
                (sandbox.clone(), format!("{to}{}", &old[from.len()..])),
                bytes,
            );
        }
        if let Some(dirs) = self.dirs.get_mut(sandbox) {
            let moved: Vec<_> = dirs
                .iter()
                .filter(|p| *p == &from || p.starts_with(&prefix))
                .cloned()
                .collect();
            for old in moved {
                dirs.remove(&old);
                dirs.insert(format!("{to}{}", &old[from.len()..]));
            }
        }
        Ok(fake_entry(&to, GuestPathKind::Dir, 0, &request.guest))
    }

    fn cancel_operation(&mut self, operation_id: &str) -> Result<(), RuntimeError> {
        self.cancelled.insert(operation_id.to_string());
        Ok(())
    }

    fn list_processes(
        &mut self,
        request: &ListProcessesRequest,
    ) -> Result<ListProcessesResponse, RuntimeError> {
        self.require_live(&request.sandbox_id)?;
        Ok(ListProcessesResponse {
            processes: Vec::new(),
        })
    }

    /// Same admission order as the Incus adapter: pid, full target, exact tracked identity, then kill→cancel owner or group-only
    /// delivery with a typed pre-effect refusal on unsupported guests.
    fn signal_process(
        &mut self,
        request: &SignalProcessRequest,
    ) -> Result<crate::SignalOutcome, RuntimeError> {
        if request.pid < 2 {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "process signal requires a tracked pid",
            ));
        }
        let target = request
            .target
            .as_ref()
            .filter(|target| target.pid == request.pid)
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::UnsupportedCapability,
                    "process signal requires a full tracked target",
                )
            })?;
        self.require_live(&request.sandbox_id)?;
        let not_found =
            || RuntimeError::new(SandboxErrorCode::ProcessNotFound, "process not found");
        let Some((generation, attempt, birth)) = self.running.get(&target.target_operation_id)
        else {
            return Err(RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "process outcome is unknown",
            ));
        };
        if (*generation, *attempt, birth.pid) != (target.generation, target.attempt, target.pid) {
            return Err(not_found());
        }
        if request.signal.is_kill() {
            self.cancelled.insert(target.target_operation_id.clone());
            return Ok(crate::SignalOutcome::CancelRequested);
        }
        if self.cancelled.contains(&target.target_operation_id) {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProcessCancelPending,
                "process cancellation is pending",
            ));
        }
        if self.guest_lacks_group_signals {
            return Err(RuntimeError::new(
                SandboxErrorCode::SignalUnsupportedOnGuest,
                "guest cannot deliver a group signal",
            ));
        }
        self.delivered
            .push((target.target_operation_id.clone(), request.signal));
        Ok(crate::SignalOutcome::ProcessGroup)
    }

    fn write_stdin(&mut self, _request: &WriteStdinRequest) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn create_snapshot(
        &mut self,
        request: &SnapshotRequest,
    ) -> Result<SnapshotResponse, RuntimeError> {
        self.require_sandbox(&request.sandbox_id)?;
        let snapshot = self
            .files
            .iter()
            .filter(|((sandbox, _), _)| sandbox == &request.sandbox_id)
            .map(|((_, path), bytes)| ((request.sandbox_id.clone(), path.clone()), bytes.clone()))
            .collect();
        self.snapshots.insert(
            (request.sandbox_id.clone(), request.snapshot_name.clone()),
            snapshot,
        );
        Ok(SnapshotResponse {
            snapshot_name: request.snapshot_name.clone(),
        })
    }

    fn restore_snapshot(
        &mut self,
        request: &SnapshotRequest,
    ) -> Result<SnapshotResponse, RuntimeError> {
        self.require_sandbox(&request.sandbox_id)?;
        let snapshot = self
            .snapshots
            .get(&(request.sandbox_id.clone(), request.snapshot_name.clone()))
            .cloned()
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::NotFound,
                    format!("snapshot `{}` was not found", request.snapshot_name),
                )
            })?;
        self.files
            .retain(|(sandbox, _), _| sandbox != &request.sandbox_id);
        self.files.extend(snapshot);
        Ok(SnapshotResponse {
            snapshot_name: request.snapshot_name.clone(),
        })
    }

    fn fork_sandbox(
        &mut self,
        request: &ForkSandboxRequest,
    ) -> Result<ForkSandboxResponse, RuntimeError> {
        self.require_sandbox(&request.sandbox_id)?;
        let snapshot = self
            .snapshots
            .get(&(request.sandbox_id.clone(), request.snapshot_name.clone()))
            .cloned()
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::NotFound,
                    format!("snapshot `{}` was not found", request.snapshot_name),
                )
            })?;
        for ((_, path), bytes) in snapshot {
            self.files
                .insert((request.dest_instance_name.clone(), path), bytes);
        }
        Ok(ForkSandboxResponse {
            dest_instance_name: request.dest_instance_name.clone(),
            snapshot_name: request.snapshot_name.clone(),
        })
    }
}

impl FakeState {
    fn require_sandbox(&self, sandbox_id: &str) -> Result<SandboxRecord, RuntimeError> {
        self.sandboxes.get(sandbox_id).cloned().ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::SandboxNotFound,
                format!("sandbox {sandbox_id} not found"),
            )
        })
    }

    /// The fake's `bind_instance` ownership check: a foreign-owned instance
    /// conflicts before any readiness verdict, whatever its power state.
    fn policy_binding(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        if self.policy_drift.get(sandbox_id) == Some(&FakePolicyDrift::Foreign) {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "fake instance is bound to a foreign owner",
            ));
        }
        Ok(())
    }

    /// THE fake bound-enforcement boundary shared by the readiness producers
    /// (reconnect, query, probe; existing-create adds its apply-time codes
    /// in `existing_create_policy`), mirroring production's
    /// `bind_instance` + `verify_bound_enforcement_locked`: verified passes;
    /// inconclusive keeps a retryable, non-cleanup code; confirmed drift is
    /// `GuestUnavailable` on a running instance and `IdempotencyConflict` on a
    /// stopped one. No producer may report Ready past a refusal.
    fn policy_ready(&self, sandbox_id: &str, running: bool) -> Result<(), RuntimeError> {
        self.policy_binding(sandbox_id)?;
        match self.policy_drift.get(sandbox_id) {
            None | Some(FakePolicyDrift::Foreign) => Ok(()),
            Some(FakePolicyDrift::Inconclusive) => Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "fake policy observation is inconclusive",
            )
            .enforcement_inconclusive()),
            Some(_) if running => Err(RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                "fake egress enforcement drifted on a running instance",
            )),
            Some(_) => Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "fake egress enforcement drifted on a stopped instance",
            )),
        }
    }

    /// A create retry over an EXISTING instance, mirroring production
    /// (kvm.rs create: `apply_sandbox_network`, then
    /// `ensure_instance_egress_device`, then start + readiness): bridge or ACL
    /// drift is `IdempotencyConflict` in any power state; a NIC off the plan
    /// is `IdempotencyConflict` on a running instance but is REPAIRED (and
    /// the instance then started) on a stopped one. Unlike reconnect, the
    /// create path never yields the cleanup-triggering `GuestUnavailable`.
    fn existing_create_policy(
        &mut self,
        sandbox_id: &str,
        running: bool,
    ) -> Result<(), RuntimeError> {
        match self.policy_drift.get(sandbox_id) {
            Some(FakePolicyDrift::Nic) if !running => {
                self.policy_drift.remove(sandbox_id);
                Ok(())
            }
            Some(FakePolicyDrift::Acl | FakePolicyDrift::Network | FakePolicyDrift::Nic) => {
                Err(RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "fake egress enforcement differs from the recorded plan",
                ))
            }
            _ => self.policy_ready(sandbox_id, running),
        }
    }

    fn require_live(&self, sandbox_id: &str) -> Result<SandboxRecord, RuntimeError> {
        if self.policy_drift.contains_key(sandbox_id) {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "fake policy is not verified",
            ));
        }
        let sandbox = self.require_sandbox(sandbox_id)?;
        if sandbox.state != SandboxLifecycleState::Ready {
            return Err(RuntimeError::new(
                SandboxErrorCode::SandboxNotRunning,
                format!("sandbox {sandbox_id} is not running"),
            ));
        }
        Ok(sandbox)
    }

    fn ensure_parents(&mut self, sandbox_id: &str, path: &str) {
        let mut current = path;
        while let Some((parent, _)) = current.rsplit_once('/') {
            if parent.is_empty() {
                break;
            }
            self.dirs
                .entry(sandbox_id.to_string())
                .or_default()
                .insert(parent.to_string());
            current = parent;
        }
    }
}

fn fake_script_exit_code(script: &str) -> i32 {
    if script.contains("exit 1") || script.contains("false") {
        1
    } else {
        0
    }
}

fn fake_command_exit_code(argv: &[String]) -> i32 {
    let first = argv.first().map(String::as_str).unwrap_or("");
    if first == "false"
        || first == "grep"
        || argv.iter().any(|arg| arg == "exit 1" || arg == "exit1")
    {
        1
    } else {
        0
    }
}

fn fake_entry(
    path: &str,
    kind: GuestPathKind,
    size: u64,
    guest: &crate::GuestIdentity,
) -> EntryInfo {
    let mode = if kind == GuestPathKind::Dir {
        0o755
    } else {
        0o644
    };
    EntryInfo {
        name: if path == "/" {
            "/"
        } else {
            path.rsplit('/').next().unwrap_or("")
        }
        .into(),
        path: path.into(),
        r#type: kind,
        size,
        mode,
        permissions: sandbox_protocol::results::mode_permissions(mode),
        uid: guest.guest_uid,
        gid: guest.guest_gid,
        owner: None,
        group: None,
        modified_time: None,
        symlink_target: None,
    }
}

#[derive(Debug, Default)]
struct FakeChannels {
    controls: HashMap<(String, String, String), FakeChannelControl>,
    kills: Vec<crate::KillScopesRequest>,
    present: HashSet<String>,
    /// The next spawns' launchers fail before the prompt (`true`: refused).
    fail_setup: Option<bool>,
    /// The next spawns fail before anything starts.
    fail_spawn: Option<SandboxErrorCode>,
    /// The next relay channels fail to connect this way.
    refuse_connect: Option<crate::RelayFailure>,
    next_pid: u32,
}

#[derive(Debug, Clone)]
pub struct FakeRuntime {
    policy: std::sync::Arc<std::sync::Mutex<policy::FakePolicy>>,
    policy_health: std::sync::Arc<std::sync::Mutex<sandbox_protocol::PolicyReconcilerHealth>>,
    state: std::sync::Arc<std::sync::Mutex<FakeState>>,
    command_delay: std::time::Duration,
    force_command_timeout: bool,
    command_clock: Option<std::sync::Arc<std::sync::Mutex<std::time::Instant>>>,
    lifecycle_hook: LifecycleHook,
    inventory_hook: LifecycleHook,
    query_hook: LifecycleHook,
    guest_io_hook: GuestIoHook,
    cancelled: Option<std::sync::Arc<crate::RuntimePermit>>,
    ptys: crate::pty::PtyRegistry,
    /// CLI channels: drivers keyed `(sandbox_id, connection_id, channel_id)`,
    /// plus every scope-kill request and the scopes a kill cannot prove gone.
    channels: std::sync::Arc<std::sync::Mutex<FakeChannels>>,
    /// Keyed like the registry: `(sandbox_id, session_id)`.
    pty_controls: std::sync::Arc<std::sync::Mutex<HashMap<(String, String), FakePtyControl>>>,
    /// Opt-in graceful stop (C55): off, the fake behaves like a runtime
    /// without one, so expiry always takes the forced fallback.
    graceful_stop: bool,
    /// Opt-in proven command cancel: a streamed command whose permit is
    /// cancelled mid-run completes CANCELLED (like the Incus supervisor's
    /// proven stop) instead of the default unproven UNKNOWN.
    proven_command_cancel: bool,
    /// DNS refresh passes the node daemon requested (daemon scheduler tests).
    dns_refresh: std::sync::Arc<std::sync::Mutex<FakeDnsRefresh>>,
    /// Policy sweep calls the node daemon made, in order (scheduler tests).
    policy_sweeps: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// Local-stack opt-in: advertise egress enforcement so a fake host can
    /// accept creates. Off by default; exists only on the fake runtime.
    advertise_egress_enforcement: bool,
    /// Synthetic egress guard (§2.0.6 "Fake runtime"): healthy unless a test
    /// says otherwise; shared by clones.
    guard: crate::guard::probe::FakeGuardProbe,
    /// The probe the create / cold-reconnect checks consult: `guard` unless
    /// a test installs another (e.g. a socket client of a fake guard).
    guard_probe: std::sync::Arc<dyn crate::guard::probe::GuardProbe>,
    /// Local-stack failure injection: while this file exists, every new
    /// create fails definitively before any state change.
    create_failure_switch: Option<std::path::PathBuf>,
    /// B12: `None` = no refused-name capability; otherwise the queued
    /// `(sandbox_id, name)` refusals a test injected.
    refused_dns_names: std::sync::Arc<RefusedQueue>,
    /// Credential guest homes, faults and holds (CLI logins C6a).
    credentials: std::sync::Arc<std::sync::Mutex<credentials::FakeCredentialState>>,
    stdin_hook: StdinHook,
    cancel_hook: LifecycleHook,
}

/// Observable record of `refresh_dns_grants` calls.
#[derive(Debug, Default)]
struct FakeDnsRefresh {
    passes: Vec<Vec<String>>,
    /// Each pass blocks this long (or until its permit is cancelled).
    hold: Option<std::time::Duration>,
    in_flight: usize,
    cancelled: usize,
}
impl Default for FakeRuntime {
    fn default() -> Self {
        let mut state = FakeState::default();
        let request = CreateSandboxRequest::for_test("default", "default");
        state.images.insert(
            request.template_digest,
            ("x86_64".into(), crate::GuestIdentity::default(), true),
        );
        let guard = crate::guard::probe::FakeGuardProbe::healthy();
        Self {
            policy: Default::default(),
            policy_health: Default::default(),
            state: std::sync::Arc::new(std::sync::Mutex::new(state)),
            command_delay: std::time::Duration::ZERO,
            force_command_timeout: false,
            command_clock: None,
            lifecycle_hook: LifecycleHook::default(),
            inventory_hook: LifecycleHook::default(),
            query_hook: LifecycleHook::default(),
            guest_io_hook: GuestIoHook::default(),
            cancelled: None,
            ptys: Default::default(),
            channels: Default::default(),
            pty_controls: Default::default(),
            graceful_stop: false,
            proven_command_cancel: false,
            dns_refresh: Default::default(),
            policy_sweeps: Default::default(),
            advertise_egress_enforcement: false,
            guard: guard.clone(),
            guard_probe: std::sync::Arc::new(guard),
            create_failure_switch: None,
            refused_dns_names: Default::default(),
            credentials: Default::default(),
            stdin_hook: StdinHook::default(),
            cancel_hook: LifecycleHook::default(),
        }
    }
}
type StdinCallback = dyn Fn(&WriteStdinRequest) -> Result<(), RuntimeError> + Send + Sync;
#[derive(Clone, Default)]
struct StdinHook(Option<std::sync::Arc<StdinCallback>>);
impl std::fmt::Debug for StdinHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StdinHook")
    }
}
type RefusedQueue = std::sync::Mutex<Option<Vec<(String, String)>>>;
fn lock_refused(queue: &RefusedQueue) -> std::sync::MutexGuard<'_, Option<Vec<(String, String)>>> {
    queue
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
type LifecycleCallback = dyn Fn(&str) -> Result<(), RuntimeError> + Send + Sync;
#[derive(Clone, Default)]
struct LifecycleHook(Option<std::sync::Arc<LifecycleCallback>>);
impl std::fmt::Debug for LifecycleHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LifecycleHook")
    }
}
/// One simulated guest-IO call, seen by [`FakeRuntime::with_guest_io_hook`].
pub struct FakeGuestIo<'a> {
    /// The dispatch kind this call serves (`file.list`, `process.signal`, ...).
    pub stage: &'a str,
    pub sandbox_id: &'a str,
    pub operation_id: &'a str,
    /// The caller's scoped permit, so a held call can observe revocation.
    pub permit: Option<&'a crate::RuntimePermit>,
}
type GuestIoCallback = dyn Fn(&FakeGuestIo<'_>) -> Result<(), RuntimeError> + Send + Sync;
#[derive(Clone, Default)]
struct GuestIoHook(Option<std::sync::Arc<GuestIoCallback>>);
impl std::fmt::Debug for GuestIoHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuestIoHook")
    }
}
impl FakeRuntime {
    /// B12: advertise blocked-name hints from this fake runtime.
    pub fn with_refused_dns_hints(self) -> Self {
        *lock_refused(&self.refused_dns_names) = Some(Vec::new());
        self
    }

    /// B12: whether `sandbox_id`'s create asked for blocked-name hints
    /// (`CreateSandboxRequest::refused_dns_hints`).
    pub fn created_with_refused_dns_hints(&self, sandbox_id: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .refused_dns_hint_creates
            .contains(sandbox_id)
    }

    /// B12: simulate the allowlist resolver refusing `name` for `sandbox_id`
    /// (ignored unless `with_refused_dns_hints`).
    pub fn push_refused_dns_name(&self, sandbox_id: &str, name: &str) {
        if let Some(queue) = lock_refused(&self.refused_dns_names).as_mut() {
            queue.push((sandbox_id.to_string(), name.to_string()));
        }
    }

    /// The synthetic egress guard (healthy by default); tests flip it to
    /// exercise the create, cold-reconnect and start-fence refusals.
    pub fn guard(&self) -> &crate::guard::probe::FakeGuardProbe {
        &self.guard
    }

    /// Replace the guard the create / cold-reconnect checks consult (the
    /// same hook as `IncusKvmRuntime::set_guard_probe`). `guard()` then no
    /// longer decides.
    pub fn set_guard_probe(&mut self, probe: std::sync::Arc<dyn crate::guard::probe::GuardProbe>) {
        self.guard_probe = probe;
    }

    /// The recorded effective egress mode of a sandbox, if it was created.
    pub fn recorded_egress_mode(&self, sandbox_id: &str) -> Option<sandbox_protocol::EgressMode> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .egress_modes
            .get(sandbox_id)
            .copied()
    }

    /// Advertise egress enforcement from this fake runtime so a local stack
    /// can exercise creates. The fake only records policies in memory; it
    /// enforces nothing. Never available on a real runtime.
    pub fn with_advertised_egress_enforcement(mut self, enabled: bool) -> Self {
        self.advertise_egress_enforcement = enabled;
        self
    }

    /// While `path` exists, every create of a new sandbox fails definitively
    /// (`INTERNAL`, nothing created), so a local stack can exercise the
    /// create-failure path by touching and removing one file.
    pub fn with_create_failure_switch(mut self, path: std::path::PathBuf) -> Self {
        self.create_failure_switch = Some(path);
        self
    }

    pub(super) fn injected_create_failure(&self) -> Option<RuntimeError> {
        let path = self.create_failure_switch.as_ref()?;
        // Any error other than a clean "absent" fails safe: inject the failure.
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            _ => Some(RuntimeError::new(
                SandboxErrorCode::Internal,
                "fake runtime: injected create failure",
            )),
        }
    }

    /// Deterministic timeout injection; independent of command spelling and budget.
    pub fn with_force_command_timeout(mut self, enabled: bool) -> Self {
        self.force_command_timeout = enabled;
        self
    }

    fn command_now(&self) -> std::time::Instant {
        if let Some(clock) = &self.command_clock {
            return *clock.lock().unwrap_or_else(|err| err.into_inner());
        }
        self.cancelled
            .as_ref()
            .map_or_else(std::time::Instant::now, |permit| permit.clock_now())
    }
    fn wait_command_delay(
        &self,
        request: &RunCommandRequest,
        started: std::time::Instant,
    ) -> crate::effect::EffectResult<()> {
        sandbox_protocol::validate_command_timeout(request.timeout_ms)
            .map_err(|(code, message)| RuntimeError::new(code, message))?;
        let timeout = match request.timeout_ms {
            Some(0) => None,
            Some(ms) => Some(std::time::Duration::from_millis(ms)),
            None => Some(std::time::Duration::from_secs(120)),
        };
        let deadline = started + self.command_delay;
        loop {
            self.check_cancelled()?;
            if self
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .cancelled
                .contains(&request.operation_id)
            {
                return Err(
                    RuntimeError::new(SandboxErrorCode::Cancelled, "command cancelled").into(),
                );
            }
            if timeout.is_some_and(|budget| {
                budget < self.command_delay
                    && self.command_now().saturating_duration_since(started) >= budget
            }) {
                // The fake clock proves a timeout; authority/cancel errors
                // above retain UNKNOWN rather than inventing completion proof.
                return Err(SimulatedFailure::completed(RuntimeError::new(
                    SandboxErrorCode::Timeout,
                    "command deadline exceeded",
                )));
            }
            if self.command_now() >= deadline {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    /// Make every `discard_capture` fail (leftovers not provably gone).
    pub fn set_discard_capture_fails(&self, fails: bool) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .discard_capture_fails = fails;
    }

    /// Resolved login scrub targets of every `capture_template` call, in order.
    pub fn capture_credential_scrubs(&self) -> Vec<Vec<String>> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .capture_credential_scrubs
            .clone()
    }

    /// Recovery cleanups requested for interrupted captures.
    pub fn discarded_captures(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .discarded_captures
            .clone()
    }

    /// Every policy sweep call so far, in order: `reconcile:<ids,>` for
    /// `reconcile_policies` and `drain` for `drain_enforcement_losses`.
    pub fn policy_sweep_calls(&self) -> Vec<String> {
        self.policy_sweeps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    /// Bounded: `--runtime fake` daemons sweep every 2 s for their lifetime.
    fn record_policy_sweep(&self, call: String) {
        let mut sweeps = self.policy_sweeps.lock().unwrap_or_else(|e| e.into_inner());
        if sweeps.len() >= 1024 {
            sweeps.drain(..512);
        }
        sweeps.push(call);
    }
    /// Every `refresh_dns_grants` pass so far, as the active ids it was given.
    pub fn dns_refresh_passes(&self) -> Vec<Vec<String>> {
        self.dns_refresh
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .passes
            .clone()
    }
    /// Make each refresh pass block for `hold`, returning early when the
    /// pass's cancellation permit is revoked.
    pub fn set_dns_refresh_hold(&self, hold: std::time::Duration) {
        self.dns_refresh
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .hold = Some(hold);
    }
    /// (passes currently running, passes that ended by cancellation).
    pub fn dns_refresh_activity(&self) -> (usize, usize) {
        let refresh = self.dns_refresh.lock().unwrap_or_else(|e| e.into_inner());
        (refresh.in_flight, refresh.cancelled)
    }
    /// Fault/barrier seam for deterministic host lifecycle tests; never used by Incus.
    pub fn with_lifecycle_hook(
        mut self,
        hook: impl Fn(&str) -> Result<(), RuntimeError> + Send + Sync + 'static,
    ) -> Self {
        self.lifecycle_hook = LifecycleHook(Some(std::sync::Arc::new(hook)));
        self
    }
    /// Barrier seam for targeted lifecycle observations; never used by Incus.
    pub fn with_query_hook(
        mut self,
        hook: impl Fn(&str) -> Result<(), RuntimeError> + Send + Sync + 'static,
    ) -> Self {
        self.query_hook = LifecycleHook(Some(std::sync::Arc::new(hook)));
        self
    }
    /// Barrier seam for a slow or failing host inventory; never used by Incus.
    pub fn with_inventory_hook(
        mut self,
        hook: impl Fn(&str) -> Result<(), RuntimeError> + Send + Sync + 'static,
    ) -> Self {
        self.inventory_hook = LifecycleHook(Some(std::sync::Arc::new(hook)));
        self
    }
    /// Barrier seam for slow guest IO (host pool tests); never used by Incus.
    /// It runs before the permit admission guard, so a held call never
    /// blocks revocation, and it sees the scoped permit to observe it.
    pub fn with_guest_io_hook(
        mut self,
        hook: impl Fn(&FakeGuestIo<'_>) -> Result<(), RuntimeError> + Send + Sync + 'static,
    ) -> Self {
        self.guest_io_hook = GuestIoHook(Some(std::sync::Arc::new(hook)));
        self
    }
    /// Models a durable cleanup record or leftover bridge/ACL for census tests.
    pub fn set_network_cleanup_pending(&self, sandbox_id: &str, pending: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if pending {
            state.network_cleanup_pending.insert(sandbox_id.into());
        } else {
            state.network_cleanup_pending.remove(sandbox_id);
        }
    }
    /// Barrier/observer seam for `write_stdin` control-lane tests; never used by Incus.
    pub fn with_stdin_hook(
        mut self,
        hook: impl Fn(&WriteStdinRequest) -> Result<(), RuntimeError> + Send + Sync + 'static,
    ) -> Self {
        self.stdin_hook = StdinHook(Some(std::sync::Arc::new(hook)));
        self
    }
    /// Barrier/observer seam for `cancel_operation` control-lane tests; never used by Incus.
    pub fn with_cancel_hook(
        mut self,
        hook: impl Fn(&str) -> Result<(), RuntimeError> + Send + Sync + 'static,
    ) -> Self {
        self.cancel_hook = LifecycleHook(Some(std::sync::Arc::new(hook)));
        self
    }
    fn guest_io(
        &self,
        stage: &str,
        sandbox_id: &str,
        operation_id: &str,
    ) -> Result<(), RuntimeError> {
        if let Some(hook) = &self.guest_io_hook.0 {
            hook(&FakeGuestIo {
                stage,
                sandbox_id,
                operation_id,
                permit: self.cancelled.as_deref(),
            })?;
        }
        Ok(())
    }
    /// Implement [`SandboxRuntime::stop_sandbox_graceful`] (C55). The
    /// lifecycle hook sees stage `stop_graceful`; an `Err` there is a guest
    /// that did not shut down within its timeout (the VM stays running).
    pub fn with_graceful_stop(mut self) -> Self {
        self.graceful_stop = true;
        self
    }
    /// See `proven_command_cancel`.
    pub fn with_proven_command_cancel(mut self) -> Self {
        self.proven_command_cancel = true;
        self
    }
    fn inventory_with_stage(
        &self,
        stage: &str,
    ) -> Result<Vec<crate::RuntimeInventoryEntry>, RuntimeError> {
        if let Some(hook) = &self.inventory_hook.0 {
            hook(stage)?;
        }
        self.check_cancelled()?;
        let state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        Ok(state
            .sandboxes
            .values()
            .map(|sandbox| crate::RuntimeInventoryEntry {
                sandbox_id: sandbox.sandbox_id.clone(),
                state: sandbox.state,
                configured_size: state
                    .sandbox_sizes
                    .get(&sandbox.sandbox_id)
                    .copied()
                    .map(crate::ConfiguredSize::Configured)
                    .unwrap_or(crate::ConfiguredSize::Conflict),
            })
            .collect())
    }
    fn lifecycle(&self, stage: &str) -> Result<(), RuntimeError> {
        if let Some(hook) = &self.lifecycle_hook.0 {
            hook(stage)?;
        }
        Ok(())
    }
    pub fn new() -> Self {
        Self::default()
    }

    /// Preview tunnels: record `sandbox_id`'s plan target (tests; a create
    /// with tunnel ports records `10.0.0.2` itself).
    pub fn set_tunnel_target(&self, sandbox_id: &str, target: std::net::Ipv4Addr, ports: Vec<u16>) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tunnel_targets
            .insert(sandbox_id.to_string(), (target, ports));
    }
    pub fn set_guest_group_signal_support(&self, supported: bool) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .guest_lacks_group_signals = !supported;
    }
    /// Stdout transcript of an executed command (`exec:[root] ...` for a
    /// build-root step), for daemon-level tests.
    pub fn command_stdout(&self, operation_id: &str) -> Option<String> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let record = state.commands.get(operation_id)?;
        let bytes: Vec<u8> = record
            .chunks
            .iter()
            .filter(|chunk| chunk.stream == CommandStream::Stdout)
            .flat_map(|chunk| chunk.bytes.iter().copied())
            .collect();
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
    /// The recorded lifecycle state of a fake sandbox, for daemon-level tests.
    pub fn lifecycle_state(&self, sandbox_id: &str) -> Option<SandboxLifecycleState> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sandboxes
            .get(sandbox_id)
            .map(|record| record.state)
    }
    /// Every `retire_command_group` call, proven or not.
    pub fn retire_attempts(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retire_attempts
    }
    /// Set the guest scope of `operation_id`'s attempt.
    pub fn set_command_scope(&self, operation_id: &str, scope: FakeCommandScope) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.scopes.scopes.insert(operation_id.into(), scope);
    }
    /// The guest-monotonic time since the scope became active.
    pub fn set_command_scope_active_for(&self, operation_id: &str, elapsed: std::time::Duration) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.scopes.active_for.insert(operation_id.into(), elapsed);
    }
    /// `/run/wssp/unscoped` in the fake guest's current boot.
    pub fn set_unscoped_marker(&self, present: bool) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scopes
            .unscoped_marker = present;
    }
    /// Cgroup roots owned by the guest uid.
    pub fn set_uid_roots(&self, roots: FakeUidRoots) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scopes
            .uid_roots = roots;
    }
    /// The fake guest kernel lacks `cgroup.kill`.
    pub fn set_scope_kill_unsupported(&self, unsupported: bool) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scopes
            .kill_unsupported = unsupported;
    }
    /// The fake guest has no cgroup2 (today's arms only).
    pub fn set_legacy_cgroups(&self, legacy: bool) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scopes
            .legacy = legacy;
    }
    /// Guest sudo: every helper step `(sandbox, mode)` in order (`grant`,
    /// `revoke` or `revoke-audit`).
    pub fn guest_sudo_steps(&self) -> Vec<(String, &'static str)> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .guest_sudo_steps
            .clone()
    }
    /// Guest sudo: steps of `mode` fail with `reason` (a create always; a
    /// later `revoke` never fails the boot, like Incus).
    pub fn fail_guest_sudo(
        &self,
        mode: &'static str,
        reason: sandbox_protocol::ReadinessFailureReason,
    ) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .guest_sudo_failures
            .insert(mode, reason);
    }
    /// R11: restart a running fake VM's QEMU process (a new identity).
    pub fn restart_qemu(&self, sandbox_id: &str) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .boot_qemu(sandbox_id);
    }
    /// Every whole-scope kill (operation, mode), in order.
    pub fn retire_kills(&self) -> Vec<(String, crate::RetireMode)> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scopes
            .kills
            .clone()
    }
    /// Every proven `retire_command_group` (operation, birth).
    pub fn retired_command_groups(&self) -> Vec<(String, crate::CommandBirth)> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retired
            .clone()
    }
    pub fn delivered_signals(&self) -> Vec<(String, crate::ProcessSignal)> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .delivered
            .clone()
    }
    /// Share logical command time with host lease fixtures, without waiting
    /// wall-clock minutes. Authority is still checked through the real permit.
    pub fn with_command_clock(
        mut self,
        clock: std::sync::Arc<std::sync::Mutex<std::time::Instant>>,
    ) -> Self {
        self.command_clock = Some(clock);
        self
    }
    pub fn with_command_delay(delay: std::time::Duration) -> Self {
        Self {
            command_delay: delay,
            ..Self::default()
        }
    }
    fn check_cancelled(&self) -> Result<(), RuntimeError> {
        if self.cancelled.as_ref().is_some_and(|c| c.is_cancelled()) {
            return Err(RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "runtime work preempted",
            ));
        }
        Ok(())
    }

    /// Driver handle for a fake channel opened by `open_channel` (tests).
    pub fn channel_control(
        &self,
        sandbox_id: &str,
        connection_id: &str,
        channel_id: &str,
    ) -> Option<FakeChannelControl> {
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .controls
            .get(&(
                sandbox_id.to_string(),
                connection_id.to_string(),
                channel_id.to_string(),
            ))
            .cloned()
    }

    /// Every `kill_channel_scopes` request so far (tests).
    pub fn channel_scope_kills(&self) -> Vec<crate::KillScopesRequest> {
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .kills
            .clone()
    }

    /// Kills of `unit` report `Present` until cleared (tests).
    pub fn set_channel_scope_present(&self, unit: &str, present: bool) {
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        if present {
            channels.present.insert(unit.to_string());
        } else {
            channels.present.remove(unit);
        }
    }

    /// The next channel launchers fail before their prompt (`Some(true)`:
    /// the guest has no usable scope) (tests).
    pub fn fail_channel_setup(&self, refused: Option<bool>) {
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fail_setup = refused;
    }

    /// The next relay channels (`tcp`/`unix`) fail to connect this way.
    pub fn refuse_channel_connect(&self, failure: Option<crate::RelayFailure>) {
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .refuse_connect = failure;
    }

    /// The next channel spawns fail before any process starts (tests).
    pub fn fail_channel_spawn(&self, code: Option<SandboxErrorCode>) {
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fail_spawn = code;
    }

    /// Driver handle for a fake terminal opened by `open_pty` (tests).
    pub fn pty_control(&self, sandbox_id: &str, session_id: &str) -> Option<FakePtyControl> {
        self.pty_controls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(sandbox_id.to_string(), session_id.to_string()))
            .cloned()
    }

    pub fn register_image(&self, alias: &str, fingerprint: &str, architecture: &str) {
        let fp = crate::normalize_incus_fingerprint(fingerprint).expect("test fingerprint");
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.images.insert(
            fp.clone(),
            (architecture.into(), crate::GuestIdentity::default(), true),
        );
        state
            .image_aliases
            .insert(alias.into(), (fp, architecture.into()));
    }
    /// Seed the fake image store with unified tarball bytes; returns its
    /// fingerprint. `aliased` images are operator images (never evictable).
    pub fn seed_image_bytes(&self, bytes: &[u8], architecture: &str, aliased: bool) -> String {
        let fp = format!("sha256:{}", sha256_hex(bytes));
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.images.insert(
            fp.clone(),
            (architecture.into(), crate::GuestIdentity::default(), true),
        );
        state.image_sizes.insert(fp.clone(), bytes.len() as u64);
        state.image_bytes.insert(fp.clone(), bytes.to_vec());
        if aliased {
            state.image_aliases.insert(
                format!("alias-{}", &fp[7..19]),
                (fp.clone(), architecture.into()),
            );
        }
        fp
    }
    /// Upstream split images imported so far (`import_split_image`).
    pub fn split_imports(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .split_imports
    }

    /// The disk image `sandbox_id` was restored from.
    pub fn restore_base(&self, sandbox_id: &str) -> Option<String> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.restore_bases.get(sandbox_id).cloned()
    }
    /// The restore base the daemon last bound for `sandbox_id`.
    pub fn bound_restore_base(&self, sandbox_id: &str) -> Option<String> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.bound_restore_bases.get(sandbox_id).cloned()
    }
    pub fn has_image(&self, fingerprint: &str) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.images.contains_key(fingerprint)
    }
    pub fn fail_image_inventory(&self, fails: bool) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .image_inventory_fails = fails;
    }
    pub fn set_image_guest(&self, fingerprint: &str, guest: crate::GuestIdentity, agent: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(image) = state.images.get_mut(fingerprint) {
            image.1 = guest;
            image.2 = agent;
        }
    }

    pub fn resolve_image_ref(&self, alias: &str) -> Result<crate::ResolvedHostImage, RuntimeError> {
        SandboxRuntime::resolve_image_ref(self, alias)
    }
}
/// Proof from the deterministic in-memory runtime, never from host/guest IO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedFailure(RuntimeError);
impl SimulatedFailure {
    pub(crate) fn error(&self) -> &RuntimeError {
        &self.0
    }
    fn completed(error: RuntimeError) -> crate::EffectError {
        crate::EffectError::Completed(crate::effect::CompletionFailure::Simulated(Self(error)))
    }
}

pub(crate) struct SimulatedCompletion<T>(T);
impl<T> PositiveEvidence for SimulatedCompletion<T> {
    type Value = T;
    fn value(self) -> T {
        self.0
    }
}
/// A raw upstream cloud image's identity (Ubuntu 26.04: `ubuntu` 1000:1001
/// at `/home/ubuntu`), never the declared target 1000:1000 at `/home/user`.
pub fn raw_upstream_identity() -> crate::GuestIdentity {
    crate::GuestIdentity {
        guest_uid: 1000,
        guest_gid: 1001,
        guest_home: "/home/ubuntu".into(),
        guest_shell: "/bin/bash".into(),
    }
}

fn simulated<T>(value: T) -> crate::Completed<T> {
    SimulatedCompletion(value).complete()
}

impl SandboxRuntime for FakeRuntime {
    fn tunnel_target(&self, sandbox_id: &str) -> Option<(std::net::Ipv4Addr, Vec<u16>)> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tunnel_targets
            .get(sandbox_id)
            .filter(|(_, ports)| !ports.is_empty())
            .cloned()
    }

    fn update_tunnel_ports(
        &self,
        sandbox_id: &str,
        revision: u64,
        ports: &[u16],
        before_acl: &dyn Fn(&[u16]),
    ) -> Result<crate::TunnelPortsUpdate, RuntimeError> {
        use sandbox_protocol::TunnelPortsOutcomeV11 as Outcome;
        let kept = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let Some((_, current)) = state.tunnel_targets.get(sandbox_id) else {
                return Ok(crate::TunnelPortsUpdate {
                    outcome: Outcome::Absent,
                    revision,
                });
            };
            let recorded = state.tunnel_revisions.get(sandbox_id).copied().unwrap_or(0);
            if revision <= recorded {
                return Ok(crate::TunnelPortsUpdate {
                    outcome: Outcome::Applied,
                    revision: recorded,
                });
            }
            current
                .iter()
                .copied()
                .filter(|port| ports.contains(port))
                .collect::<Vec<_>>()
        };
        before_acl(&kept);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, current)) = state.tunnel_targets.get_mut(sandbox_id) {
            *current = ports.to_vec();
        }
        state
            .tunnel_revisions
            .insert(sandbox_id.to_string(), revision);
        Ok(crate::TunnelPortsUpdate {
            outcome: Outcome::Applied,
            revision,
        })
    }

    fn bind_restore_base(&self, sandbox_id: &str, restore_base: &str) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bound_restore_bases
            .insert(sandbox_id.to_owned(), restore_base.to_owned());
    }
    fn unbind_restore_base(&self, sandbox_id: &str) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bound_restore_bases
            .remove(sandbox_id);
    }
    fn import_image(&self, path: &std::path::Path) -> Result<String, RuntimeError> {
        // Like the Incus runtime: no import while the server is shared.
        crate::guard::probe::refuse_shared_incus_server(self.guard_probe.as_ref())?;
        let bytes = std::fs::read(path)
            .map_err(|_| RuntimeError::new(SandboxErrorCode::Internal, "image file unreadable"))?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let fp = format!("sha256:{}", sha256_hex(&bytes));
        state.images.entry(fp.clone()).or_insert((
            "x86_64".into(),
            crate::GuestIdentity::default(),
            true,
        ));
        state.image_sizes.insert(fp.clone(), bytes.len() as u64);
        state.image_bytes.insert(fp.clone(), bytes);
        Ok(fp)
    }

    /// Like Incus: validated first, fingerprint sha256(meta || disk), compared
    /// with `expected` after the import (deleted on a mismatch). The image
    /// registers as a raw upstream image: its guest identity is `ubuntu`
    /// 1000:1001 at `/home/ubuntu`, never the declared target identity.
    fn import_split_image(
        &self,
        meta: &std::path::Path,
        disk: &std::path::Path,
        expected: &str,
    ) -> Result<String, RuntimeError> {
        crate::guard::probe::refuse_shared_incus_server(self.guard_probe.as_ref())?;
        crate::validate_split_image(meta, disk, crate::SPLIT_VIRTUAL_SIZE_MAX)?;
        let unreadable = || RuntimeError::new(SandboxErrorCode::Internal, "image file unreadable");
        let mut bytes = std::fs::read(meta).map_err(|_| unreadable())?;
        bytes.extend(std::fs::read(disk).map_err(|_| unreadable())?);
        let fp = format!("sha256:{}", sha256_hex(&bytes));
        if fp != expected {
            return Err(RuntimeError::new(
                SandboxErrorCode::ImageRejected,
                "image refused: imported_fingerprint_mismatch",
            ));
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.split_imports += 1;
        state
            .images
            .entry(fp.clone())
            .or_insert(("x86_64".into(), raw_upstream_identity(), true));
        state.image_sizes.insert(fp.clone(), bytes.len() as u64);
        state.image_bytes.insert(fp.clone(), bytes);
        Ok(fp)
    }

    fn export_image(
        &self,
        fingerprint: &str,
        dir: &std::path::Path,
    ) -> Result<Vec<std::path::PathBuf>, RuntimeError> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let bytes = state
            .image_bytes
            .get(fingerprint)
            .ok_or_else(|| RuntimeError::new(SandboxErrorCode::NotFound, "image not in store"))?;
        let path = dir.join(format!("{}.tar", &fingerprint[7..]));
        std::fs::write(&path, bytes)
            .map_err(|_| RuntimeError::new(SandboxErrorCode::Internal, "image export failed"))?;
        Ok(vec![path])
    }

    fn delete_image(&self, fingerprint: &str) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.images.remove(fingerprint);
        state.image_sizes.remove(fingerprint);
        state.image_bytes.remove(fingerprint);
        // Like Incus, deleting an image deletes its offload alias.
        state.image_aliases.retain(|alias, (fp, _)| {
            fp != fingerprint || !alias.starts_with(crate::OFFLOAD_ALIAS_PREFIX)
        });
        Ok(())
    }

    fn publish_stopped_instance(
        &self,
        instance_name: &str,
        alias: &str,
    ) -> Result<crate::PublishedDisk, RuntimeError> {
        self.fake_publish_stopped_instance(instance_name, alias)
    }

    fn instance_last_used(&self, instance_name: &str) -> Result<Option<String>, RuntimeError> {
        self.fake_instance_last_used(instance_name)
    }

    fn cloud_init_instance_id(&self, instance_name: &str) -> Result<Option<String>, RuntimeError> {
        self.fake_cloud_init_instance_id(instance_name)
    }

    fn instance_root_usage(&self, instance_name: &str) -> Result<Option<u64>, RuntimeError> {
        self.fake_instance_root_usage(instance_name)
    }

    fn offload_aliases(&self) -> Result<Vec<crate::OffloadAlias>, RuntimeError> {
        self.fake_offload_aliases()
    }

    fn instance_operation_running(&self, instance_name: &str) -> Result<bool, RuntimeError> {
        self.fake_instance_operation_running(instance_name)
    }

    fn delete_orphan_root(
        &self,
        root: &crate::RootDisk,
        instance_name: &str,
    ) -> Result<(), RuntimeError> {
        self.fake_delete_orphan_root(root, instance_name)
    }

    fn list_image_fingerprints(&self) -> Result<std::collections::BTreeSet<String>, RuntimeError> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.image_inventory_fails {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "fake image inventory unavailable",
            ));
        }
        Ok(state.images.keys().cloned().collect())
    }

    fn image_protected(&self, fingerprint: &str) -> Result<bool, RuntimeError> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Ok(state
            .image_aliases
            .values()
            .any(|(fp, _)| fp == fingerprint)
            || state.sandbox_images.values().any(|fp| fp == fingerprint))
    }

    fn discard_capture(&self, sandbox_id: &str, operation_id: &str) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .discarded_captures
            .push((sandbox_id.to_owned(), operation_id.to_owned()));
        if state.discard_capture_fails {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "capture_cleanup_pending: injected",
            ));
        }
        Ok(())
    }

    fn credential_pack(
        &self,
        request: &crate::CredentialPackRequest,
    ) -> Result<crate::CredentialPackOutcome, RuntimeError> {
        self.fake_credential_pack(request)
    }

    fn credential_restore(
        &self,
        request: &crate::CredentialRestoreRequest<'_>,
    ) -> Result<crate::CredentialRestoreOutcome, RuntimeError> {
        self.fake_credential_restore(request)
    }

    fn credential_scrub(
        &self,
        request: &crate::CredentialScrubRequest,
    ) -> Result<crate::CredentialScrubOutcome, RuntimeError> {
        self.fake_credential_scrub(request)
    }

    fn credential_quiesce(
        &self,
        guest: &crate::CredentialGuest,
    ) -> Result<crate::CredentialQuiesceOutcome, RuntimeError> {
        self.fake_credential_quiesce(guest)
    }

    fn credential_helper_present(
        &self,
        guest: &crate::CredentialGuest,
    ) -> Result<bool, RuntimeError> {
        self.fake_credential_helper_present(guest)
    }

    fn capture_template(
        &self,
        request: &crate::CaptureRequest,
        progress: &dyn Fn(crate::CapturePhase),
    ) -> Result<crate::CaptureOutcome, RuntimeError> {
        // Login paths fail closed before any effect, exactly as Incus does.
        let credentials =
            crate::credential_scrub_targets(&request.guest_home, &request.credential_scrub_paths)?;
        if !request.stopped {
            progress(crate::CapturePhase::Freezing);
            progress(crate::CapturePhase::Snapshotting);
        }
        progress(crate::CapturePhase::Copying);
        progress(crate::CapturePhase::Scrubbing);
        progress(crate::CapturePhase::Publishing);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let base = state
            .sandbox_images
            .get(&request.sandbox_id)
            .cloned()
            .ok_or_else(|| {
                RuntimeError::new(SandboxErrorCode::SandboxNotFound, "sandbox not found")
            })?;
        state.captures += 1;
        state.capture_credential_scrubs.push(credentials);
        let bytes = format!(
            "fake-capture:{}:{}:{}",
            request.sandbox_id, base, state.captures
        )
        .into_bytes();
        let fp = format!("sha256:{}", sha256_hex(&bytes));
        let architecture = state
            .images
            .get(&base)
            .map(|image| image.0.clone())
            .unwrap_or_else(|| "x86_64".into());
        state.images.insert(
            fp.clone(),
            (architecture.clone(), crate::GuestIdentity::default(), true),
        );
        state.image_sizes.insert(fp.clone(), bytes.len() as u64);
        let size_bytes = bytes.len() as u64;
        state.image_bytes.insert(fp.clone(), bytes);
        Ok(crate::CaptureOutcome {
            fingerprint: fp,
            size_bytes,
            architecture,
            symlinked_paths: Vec::new(),
        })
    }

    fn reconcile_policies(&self, ids: &[String]) -> Result<(), RuntimeError> {
        self.record_policy_sweep(format!("reconcile:{}", ids.join(",")));
        self.inspect_policies(ids)
    }
    fn refresh_dns_grants(&self, ids: &[String]) -> Result<(), RuntimeError> {
        let hold = {
            let mut refresh = self.dns_refresh.lock().unwrap_or_else(|e| e.into_inner());
            refresh.passes.push(ids.to_vec());
            refresh.in_flight += 1;
            refresh.hold
        };
        let mut cancelled = false;
        if let Some(hold) = hold {
            let until = std::time::Instant::now() + hold;
            while std::time::Instant::now() < until {
                if self.cancelled.as_ref().is_some_and(|c| c.is_cancelled()) {
                    cancelled = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        let mut refresh = self.dns_refresh.lock().unwrap_or_else(|e| e.into_inner());
        refresh.in_flight = refresh.in_flight.saturating_sub(1);
        if cancelled {
            refresh.cancelled += 1;
        }
        Ok(())
    }
    fn policy_reconciler_health(&self) -> sandbox_protocol::PolicyReconcilerHealth {
        self.policy_health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    fn set_enforcement_loss_lifecycle(
        &self,
        lifecycle: std::sync::Arc<dyn crate::EnforcementLossLifecycle>,
    ) {
        self.policy
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .lifecycle = Some(lifecycle);
    }
    fn drain_enforcement_losses(
        &self,
        settle: &dyn Fn(&str, crate::EnforcementLossStage) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.record_policy_sweep("drain".to_owned());
        self.drain_policy_losses(settle)
    }
    fn sandbox_inventory_skipping(
        &self,
        busy: &std::collections::HashSet<String>,
    ) -> Result<Vec<crate::RuntimeInventoryEntry>, RuntimeError> {
        // The hook sees which sandboxes the census must not wait on.
        let mut ids: Vec<&String> = busy.iter().collect();
        ids.sort();
        if ids.is_empty() {
            return self.inventory_with_stage("inventory");
        }
        let stage = format!(
            "inventory-skipping:{}",
            ids.iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        self.inventory_with_stage(&stage)
    }
    fn sandbox_inventory(&self) -> Result<Vec<crate::RuntimeInventoryEntry>, RuntimeError> {
        self.inventory_with_stage("inventory")
    }

    fn default_storage_pool(&self) -> Result<String, RuntimeError> {
        Ok("default".into())
    }
    fn initialize_storage_pool(
        &self,
        name: &str,
        expected: Option<&crate::StoragePoolIdentity>,
    ) -> Result<crate::StoragePoolIdentity, RuntimeError> {
        self.fake_initialize_storage_pool(name, expected)
    }
    fn observe_storage_pool(
        &self,
        pool: &crate::StoragePoolIdentity,
    ) -> Result<crate::StoragePoolObservation, RuntimeError> {
        self.fake_observe_storage_pool(pool)
    }
    fn storage_root_census(
        &self,
        pool: &crate::StoragePoolIdentity,
    ) -> Result<crate::StorageRootCensus, RuntimeError> {
        self.fake_storage_root_census(pool)
    }
    fn storage_physical_usage(
        &self,
        pool: &crate::StoragePoolIdentity,
        roots: &[String],
        _commitments: u64,
    ) -> Result<crate::PhysicalUsage, RuntimeError> {
        self.fake_observe_storage_pool(pool)?;
        if roots.len() > 10_000 {
            return Err(crate::storage::storage_error("too many charged roots"));
        }
        let mut seen = HashSet::new();
        for root in roots {
            crate::validate_managed_instance_name(root)?;
            if !seen.insert(root) {
                return Err(crate::storage::storage_error("duplicate charged root"));
            }
        }
        // Synthetic roots have no host physical allocation.
        Ok(crate::PhysicalUsage {
            charged_bytes: 0,
            trusted: false,
        })
    }
    fn prove_root_absent(
        &self,
        root: &crate::RootDisk,
        name: &str,
    ) -> Result<crate::RootAbsenceProof, RuntimeError> {
        self.fake_prove_root_absent(root, name)
    }
    fn prove_network_cleanup_complete(&self, sandbox_id: &str) -> Result<bool, RuntimeError> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        Ok(!self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .network_cleanup_pending
            .contains(sandbox_id))
    }
    fn create_sandbox_on_storage(
        &self,
        request: &CreateSandboxRequest,
        root: &crate::RootDisk,
    ) -> crate::EffectOutcome<CreateSandboxResponse> {
        self.fake_create_on_storage(request, root)
    }
    fn reconnect_sandbox_on_storage(
        &self,
        request: &ReconnectSandboxRequest,
        root: &crate::RootDisk,
    ) -> crate::EffectOutcome<ReconnectSandboxResponse> {
        self.fake_reconnect_on_storage(request, root)
    }
    fn kill_sandbox_on_storage(
        &self,
        request: &KillSandboxRequest,
        root: &crate::RootDisk,
    ) -> crate::EffectOutcome<KillSandboxResponse> {
        self.fake_kill_on_storage(request, root)
    }

    fn host_resources(&self) -> Result<crate::HostResources, RuntimeError> {
        crate::HostResources::new(8 * 1024 * 1024 * 1024, 4)
    }

    fn with_cancellation(
        &self,
        cancelled: std::sync::Arc<crate::RuntimePermit>,
    ) -> Box<dyn SandboxRuntime> {
        Box::new(Self {
            cancelled: Some(cancelled),
            ..self.clone()
        })
    }
    fn query_sandbox(
        &self,
        sandbox_id: &str,
        create_key: Option<&str>,
        template_fingerprint: Option<&str>,
    ) -> Result<Option<SandboxLifecycleState>, RuntimeError> {
        if let Some(hook) = &self.query_hook.0 {
            hook(sandbox_id)?;
        }
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(record) = state.sandboxes.get(sandbox_id) else {
            return Ok(None);
        };
        if create_key.is_some_and(|key| key != record.idempotency_key) {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "instance binding differs",
            ));
        }
        let fp = state.verify_binding(sandbox_id, template_fingerprint)?;
        // Like Incus `base_bound`'s hint arm: a bound restore base requires
        // the instance's restore base to be exactly that hint.
        if let Some(hint) = state.bound_restore_bases.get(sandbox_id)
            && state.restore_bases.get(sandbox_id) != Some(hint)
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "restore base binding differs",
            ));
        }
        state.policy_binding(sandbox_id)?;
        if record.state == SandboxLifecycleState::Ready {
            // Production verifies enforcement only on a running VM; a
            // stopped one reports Stopped without a policy verdict.
            state.policy_ready(sandbox_id, true)?;
            let (architecture, guest, mode) =
                state.sandbox_readiness.get(sandbox_id).ok_or_else(|| {
                    RuntimeError::new(
                        SandboxErrorCode::GuestUnavailable,
                        "readiness metadata missing",
                    )
                })?;
            state.verify_readiness(fp, Some(architecture), guest, *mode)?;
        }
        Ok(Some(record.state))
    }

    fn resolve_image_ref(&self, alias: &str) -> Result<crate::ResolvedHostImage, RuntimeError> {
        if crate::is_incus_fingerprint(alias) {
            let state = self.state.lock().map_err(|_| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "fake image inventory unavailable",
                )
            })?;
            return state
                .images
                .get(alias)
                .map(|(architecture, _, _)| crate::ResolvedHostImage {
                    fingerprint: alias.to_owned(),
                    architecture: architecture.clone(),
                    size_bytes: state.image_sizes.get(alias).copied(),
                })
                .ok_or_else(|| {
                    RuntimeError::new(SandboxErrorCode::NotFound, "image is not in host inventory")
                });
        }
        if !crate::is_incus_image_ref(alias) {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                format!("invalid image ref `{alias}`"),
            ));
        }
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .image_aliases
            .get(alias)
            .cloned()
            .map(|(fingerprint, architecture)| crate::ResolvedHostImage {
                fingerprint,
                architecture,
                size_bytes: None,
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::NotFound,
                    format!("image `{alias}` is not in host inventory"),
                )
            })
    }

    fn sandbox_exists(&self, sandbox_id: &str) -> Result<bool, RuntimeError> {
        if let Some(hook) = &self.inventory_hook.0 {
            hook("exists")?;
        }
        Ok(self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sandboxes
            .contains_key(sandbox_id))
    }

    fn qemu_identity(&self, sandbox_id: &str) -> Option<crate::QemuIdentity> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .qemu
            .get(sandbox_id)
            .copied()
    }
    fn sandbox_may_be_running(&self, sandbox_id: &str) -> Result<bool, RuntimeError> {
        if let Some(hook) = &self.inventory_hook.0 {
            hook("running")?;
        }
        Ok(self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sandboxes
            .get(sandbox_id)
            .is_some_and(|s| s.state != SandboxLifecycleState::Stopped))
    }

    fn run_command(&self, request: &RunCommandRequest) -> crate::EffectOutcome<RunCommandResponse> {
        sandbox_protocol::validate_command_timeout(request.timeout_ms)
            .map_err(|(code, message)| RuntimeError::new(code, message))?;
        let started = self.command_now();
        self.lifecycle("command-delay")?;
        self.wait_command_delay(request, started)?;
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .run_command(request, self.force_command_timeout)
            .map(simulated)
            .map_err(SimulatedFailure::completed)
    }
    fn run_command_stream(
        &self,
        request: &RunCommandRequest,
        output: &crate::CommandOutput,
    ) -> crate::EffectOutcome<RunCommandResponse> {
        let mut immediate = self.clone();
        immediate.command_delay = std::time::Duration::ZERO;
        let response = immediate.run_command(request)?;
        if let Some(birth) = &response.command.birth {
            if output.bind_start(birth) == crate::StartBinding::Bound && !request.runs_as_root() {
                // Like Incus: the bound start names the dropped-to uid and
                // the effective budget (the fake's default is 120 s).
                output.record_start(&crate::CommandStart {
                    birth: birth.clone(),
                    uid: request.guest.guest_uid,
                    budget_ms: request.timeout_ms.unwrap_or(120_000),
                    qemu: self.qemu_identity(&request.sandbox_id),
                });
            }
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .running
                .insert(
                    request.operation_id.clone(),
                    (request.generation, request.attempt, birth.clone()),
                );
        }
        let _window = FakeRunWindow(self.state.clone(), request.operation_id.clone());
        for chunk in &response.command.chunks {
            output.push(chunk.stream, &chunk.bytes);
        }
        let started = self.command_now();
        // Publication hooks may hold a command, but never restart its timer.
        self.lifecycle("command-output")?;
        match self.wait_command_delay(request, started) {
            Ok(()) => Ok(response),
            Err(_)
                if self.proven_command_cancel
                    && self.cancelled.as_ref().is_some_and(|c| c.is_cancelled()) =>
            {
                Ok(response.map(|mut response| {
                    response.command.state = OperationState::Cancelled;
                    response.command.exit_code = None;
                    response
                }))
            }
            Err(error) => Err(error),
        }
    }
    fn pty_capability(&self) -> bool {
        true
    }

    fn egress_enforcement_capability(&self) -> Result<bool, RuntimeError> {
        Ok(self.advertise_egress_enforcement)
    }

    fn refused_dns_hints_capability(&self) -> bool {
        lock_refused(&self.refused_dns_names).is_some()
    }

    fn drain_refused_dns_names(&self) -> Vec<(String, String)> {
        lock_refused(&self.refused_dns_names)
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }

    fn egress_open_capability(
        &self,
        _settings: &crate::egress::EgressSettings,
    ) -> Result<bool, RuntimeError> {
        Ok(self.advertise_egress_enforcement)
    }

    fn egress_guard_probe(&self) -> Option<std::sync::Arc<dyn crate::guard::probe::GuardProbe>> {
        Some(self.guard_probe.clone())
    }

    fn egress_guard_check(&self) -> Result<(), RuntimeError> {
        crate::guard::probe::check_guard(self.guard_probe.as_ref())
    }

    fn egress_enforcement_unavailable_reason(&self) -> Option<String> {
        if self.advertise_egress_enforcement {
            return None;
        }
        Some(
            "the fake runtime never enforces egress policies; run `wssp host run --runtime incus` on a host with incus 6.14 or later to create sandboxes"
                .to_string(),
        )
    }

    fn open_pty(
        &self,
        request: &crate::OpenPtyRequest,
    ) -> Result<crate::PtySession, crate::PtyOpenFailure> {
        let lifetime = request.validate()?;
        self.check_cancelled()?;
        let instance_name = crate::resolve_managed_instance_name(&request.sandbox_id, None)?;
        let reservation = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.require_live(&request.sandbox_id)?;
            state.verify_binding(&request.sandbox_id, Some(&request.template_fingerprint))?;
            // Reserve under the state lock: a concurrent stop/kill either
            // precedes this (open refused above) or dooms this reservation.
            self.ptys
                .reserve(&request.session_id, &request.sandbox_id)?
        };
        let (mut control, parts) =
            pty::fake_parts(instance_name, request.guest.clone(), request.size);
        control.set_env(request.env.clone());
        control.set_cwd(request.cwd.clone());
        let session = crate::PtySession::start(reservation, request.size, lifetime, parts)?;
        let mut controls = self.pty_controls.lock().unwrap_or_else(|e| e.into_inner());
        // Bounded: drivers of released sessions are dropped on the next open.
        controls.retain(|_, control| !control.released());
        controls.insert(
            (request.sandbox_id.clone(), request.session_id.clone()),
            control,
        );
        Ok(session)
    }

    fn close_pty_sessions(&self, sandbox_id: Option<&str>, intent: crate::PtyCloseIntent) -> usize {
        self.ptys.close_matching(sandbox_id, intent)
    }

    fn channel_capability(&self) -> bool {
        true
    }

    fn spawn_channel(
        &self,
        request: &crate::SpawnChannelRequest,
    ) -> Result<crate::SpawnedChannel, crate::ChannelOpenFailure> {
        request.validate()?;
        self.check_cancelled()?;
        {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.require_live(&request.sandbox_id)?;
            state.verify_binding(&request.sandbox_id, Some(&request.template_fingerprint))?;
        }
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(code) = channels.fail_spawn {
            return Err(RuntimeError::new(code, "channel setup failed").into());
        }
        channels.next_pid += 1;
        let (control, io, custody) = channel::open(channel::FakeOpen {
            mode: &request.mode,
            nonce: &request.nonce,
            argv: request.argv.clone(),
            login: request.login,
            cwd: request.cwd.clone(),
            pid: 2000 + channels.next_pid,
            fail_setup: channels.fail_setup,
            refuse: channels.refuse_connect,
        });
        channels.controls.insert(
            (
                request.sandbox_id.clone(),
                request.connection_id.clone(),
                request.channel_id.clone(),
            ),
            control,
        );
        // Bounded: drivers of ended channels are dropped beyond a cap.
        if channels.controls.len() > 4096 {
            channels
                .controls
                .retain(|_, control| control.ended().is_none());
        }
        Ok(crate::SpawnedChannel {
            io: Box::new(io),
            custody: Box::new(custody),
        })
    }

    fn kill_channel_scopes(
        &self,
        request: &crate::KillScopesRequest,
    ) -> Result<Vec<(String, crate::ScopeKill)>, RuntimeError> {
        for scope in &request.scopes {
            crate::validate_channel_scope_unit(&scope.unit)?;
        }
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        channels.kills.push(request.clone());
        Ok(request
            .scopes
            .iter()
            .map(|scope| {
                let kill = if channels.present.contains(&scope.unit) {
                    crate::ScopeKill::Present
                } else {
                    crate::ScopeKill::Gone
                };
                (scope.unit.clone(), kill)
            })
            .collect())
    }

    fn read_file(&self, request: &ReadFileRequest) -> Result<ReadFileResponse, RuntimeError> {
        self.guest_io("file.get", &request.sandbox_id, &request.operation_id)?;
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .read_file(request)
    }
    fn write_file(&self, request: &WriteFileRequest) -> crate::EffectOutcome<WriteFileResponse> {
        self.guest_io("file.put", &request.sandbox_id, &request.operation_id)?;
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .write_file(request)
            .map(simulated)
            .map_err(SimulatedFailure::completed)
    }
    /// Simulated guest writes are atomic: only matching bytes are evidence.
    fn recover_file_put(
        &self,
        request: &crate::RecoverFilePutRequest,
    ) -> crate::EffectOutcome<WriteFileResponse> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state
            .files
            .get(&(request.sandbox_id.clone(), request.path.clone()))
        {
            Some(stored)
                if stored.len() as u64 == request.size && stored.digest() == request.sha256 =>
            {
                Ok(simulated(WriteFileResponse {
                    path: request.path.clone(),
                    bytes_written: request.size,
                }))
            }
            _ => Err(RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "simulated guest does not hold the requested bytes",
            )
            .into()),
        }
    }
    fn probe_sandbox(
        &self,
        request: &ProbeSandboxRequest,
    ) -> Result<ProbeSandboxResponse, RuntimeError> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let probe_state = match state.sandboxes.get(&request.sandbox_id) {
            None => SandboxLiveProbeState::ConfirmedAbsent,
            Some(record) => {
                let fp = state
                    .verify_binding(&request.sandbox_id, Some(&request.template_fingerprint))?;
                state.policy_binding(&request.sandbox_id)?;
                if record.state == SandboxLifecycleState::Ready {
                    // A running instance is certified only through the
                    // boundary; its refusal propagates, as in production.
                    state.policy_ready(&request.sandbox_id, true)?;
                }
                if record.state == SandboxLifecycleState::Stopped {
                    SandboxLiveProbeState::Stopped
                } else if record.state == SandboxLifecycleState::Ready
                    && state
                        .verify_readiness(
                            fp,
                            request.architecture.as_deref(),
                            &request.guest,
                            state
                                .sandbox_readiness
                                .get(&request.sandbox_id)
                                .map(|(_, _, mode)| *mode)
                                .unwrap_or_default(),
                        )
                        .is_ok()
                {
                    SandboxLiveProbeState::GuestReady
                } else {
                    SandboxLiveProbeState::Unreachable
                }
            }
        };
        Ok(ProbeSandboxResponse { state: probe_state })
    }

    fn stop_sandbox(
        &self,
        request: &StopSandboxRequest,
    ) -> crate::EffectOutcome<StopSandboxResponse> {
        self.lifecycle("stop")?;
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        let stopped = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop_sandbox(request);
        self.ptys.close_matching(
            Some(&request.sandbox_id),
            crate::PtyCloseIntent::SandboxStopped,
        );
        stopped.map(simulated).map_err(SimulatedFailure::completed)
    }
    fn stop_sandbox_graceful(
        &self,
        request: &StopSandboxRequest,
        timeout: std::time::Duration,
    ) -> crate::EffectOutcome<StopSandboxResponse> {
        if !self.graceful_stop {
            let _ = timeout;
            return Err(RuntimeError::new(
                SandboxErrorCode::UnsupportedCapability,
                "runtime has no graceful stop",
            )
            .into());
        }
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        // A guest that ignores the shutdown keeps running: no state change.
        self.lifecycle("stop_graceful")?;
        let stopped = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop_sandbox(request);
        self.ptys.close_matching(
            Some(&request.sandbox_id),
            crate::PtyCloseIntent::SandboxStopped,
        );
        stopped.map(simulated).map_err(SimulatedFailure::completed)
    }
    fn list_dir(&self, request: &ListDirRequest) -> Result<ListDirResponse, RuntimeError> {
        self.guest_io("file.list", &request.sandbox_id, &request.operation_id)?;
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .list_dir(request)
    }
    fn stat_path(&self, request: &StatPathRequest) -> Result<EntryInfo, RuntimeError> {
        self.guest_io("file.stat", &request.sandbox_id, &request.operation_id)?;
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stat_path(request)
    }
    fn mkdir(&self, request: &MkdirRequest) -> crate::EffectOutcome<MkdirResponse> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mkdir(request)
            .map(simulated)
            .map_err(SimulatedFailure::completed)
    }
    fn remove_path(&self, request: &RemovePathRequest) -> crate::EffectOutcome<RemovePathResponse> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove_path(request)
            .map(simulated)
            .map_err(SimulatedFailure::completed)
    }
    fn move_path(&self, request: &MovePathRequest) -> crate::EffectOutcome<EntryInfo> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .move_path(request)
            .map(simulated)
            .map_err(SimulatedFailure::completed)
    }
    fn cancel_operation(&self, operation_id: &str) -> crate::EffectOutcome<()> {
        if let Some(hook) = &self.cancel_hook.0 {
            hook(operation_id).map_err(SimulatedFailure::completed)?;
        }
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel_operation(operation_id)
            .map(simulated)
            .map_err(SimulatedFailure::completed)
    }
    fn list_processes(
        &self,
        request: &ListProcessesRequest,
    ) -> Result<ListProcessesResponse, RuntimeError> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .list_processes(request)
    }
    fn signal_process(
        &self,
        request: &SignalProcessRequest,
    ) -> crate::EffectOutcome<crate::SignalOutcome> {
        // Match Incus: SIGKILL is local cancellation bookkeeping only.
        if !request.signal.is_kill() {
            self.guest_io("process.signal", &request.sandbox_id, &request.operation_id)?;
        }
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .signal_process(request)
            .map(simulated)
            .map_err(|error| {
                if error.code == SandboxErrorCode::UnknownOutcome {
                    error.into()
                } else {
                    SimulatedFailure::completed(error)
                }
            })
    }
    /// Like Incus: a stopped or absent fake VM proves the command
    /// gone. On a running one, a request with a journaled uid follows the
    /// root retire helper's rules over [`FakeCommandScope`] (marker, uid
    /// roots, deadline gate, `cgroup.kill`); `unscoped`/`legacy` and a
    /// request without a uid keep today's arm: the boot ([`FAKE_BOOT_ID`])
    /// differs from the birth's. Anything else is unproven. Every attempt is
    /// counted; the lifecycle hook (`retire`) injects an observation failure.
    fn retire_command_group(
        &self,
        request: &crate::RetireCommandRequest,
    ) -> Result<crate::RetireObservation, RuntimeError> {
        self.lifecycle("retire")?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.retire_attempts += 1;
        let unproven = || {
            RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "command disappearance unproven",
            )
        };
        let running = state
            .sandboxes
            .get(&request.sandbox_id)
            .is_some_and(|record| record.state != SandboxLifecycleState::Stopped);
        // R11 (like Incus): a different QEMU process proves the guest gone.
        let qemu_changed = running
            && request.qemu.is_some_and(|started| {
                state
                    .qemu
                    .get(&request.sandbox_id)
                    .is_some_and(|now| *now != started)
            });
        if running && !qemu_changed && request.host_proof_only {
            // I7: the guest-side verdict is ignored; a due kill still runs.
            if request.mode.kills() && request.uid.is_some() {
                let _ = state.scope_verdict(request);
            }
            return Ok(crate::RetireObservation::Parked);
        }
        let proven = if !running || qemu_changed {
            true
        } else if let Some(uid) = request.uid.filter(|_| !state.scopes.legacy) {
            if uid == 0 {
                return Err(unproven());
            }
            match state.scope_verdict(request)? {
                Some(observation) => return Ok(observation),
                // `unscoped`: today's arm below.
                None => request.birth.boot_id != FAKE_BOOT_ID,
            }
        } else {
            request.birth.boot_id != FAKE_BOOT_ID
        };
        if !proven {
            return Err(unproven());
        }
        state
            .retired
            .push((request.operation_id.clone(), request.birth.clone()));
        // Like Incus: name the host proofs, so a guest-root receipt is never
        // deleted on a guest-reported one.
        let verdict = if !running {
            "vm_stopped"
        } else if qemu_changed {
            "qemu_restarted"
        } else {
            "gone"
        };
        Ok(crate::RetireObservation::Gone(
            crate::CommandGroupGone::proven_by(&request.birth, verdict),
        ))
    }
    fn write_stdin(&self, request: &WriteStdinRequest) -> crate::EffectOutcome<()> {
        if let Some(hook) = &self.stdin_hook.0 {
            hook(request).map_err(SimulatedFailure::completed)?;
        }
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .write_stdin(request)
            .map(simulated)
            .map_err(SimulatedFailure::completed)
    }
    fn create_snapshot(&self, request: &SnapshotRequest) -> crate::EffectOutcome<SnapshotResponse> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create_snapshot(request)
            .map(simulated)
            .map_err(SimulatedFailure::completed)
    }
    fn restore_snapshot(
        &self,
        request: &SnapshotRequest,
    ) -> crate::EffectOutcome<SnapshotResponse> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .restore_snapshot(request)
            .map(simulated)
            .map_err(SimulatedFailure::completed)
    }
    fn fork_sandbox(
        &self,
        request: &ForkSandboxRequest,
    ) -> crate::EffectOutcome<ForkSandboxResponse> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fork_sandbox(request)
            .map(simulated)
            .map_err(SimulatedFailure::completed)
    }
}

impl FakeRuntime {
    /// Seed a hermetic VM on a real fake-pool binding for cross-crate test harnesses.
    #[cfg(test)]
    pub(crate) fn create_fixture(
        &self,
        request: &CreateSandboxRequest,
    ) -> crate::EffectOutcome<CreateSandboxResponse> {
        let root = self.fixture_root()?;
        self.create_sandbox_on_storage(request, &root)
    }
    #[cfg(test)]
    pub(crate) fn reconnect_fixture(
        &self,
        request: &ReconnectSandboxRequest,
    ) -> crate::EffectOutcome<ReconnectSandboxResponse> {
        let root = self.fixture_root()?;
        self.reconnect_sandbox_on_storage(request, &root)
    }
    #[cfg(test)]
    pub(crate) fn kill_fixture(
        &self,
        request: &KillSandboxRequest,
    ) -> crate::EffectOutcome<KillSandboxResponse> {
        let root = self.fixture_root()?;
        self.kill_sandbox_on_storage(request, &root)
    }
    pub fn fixture_root(&self) -> Result<crate::RootDisk, RuntimeError> {
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state
                .storage_pools
                .entry("default".into())
                .or_insert_with(|| crate::StoragePoolIdentity {
                    name: "default".into(),
                    storage_id: "a".repeat(32),
                });
        }
        Ok(crate::RootDisk {
            pool: self.initialize_storage_pool("default", None)?,
            disk_gi_b: sandbox_protocol::vm_size_limits()
                .map_err(|_| {
                    RuntimeError::new(
                        sandbox_protocol::SandboxErrorCode::Internal,
                        "invalid size policy",
                    )
                })?
                .disk_gi_b_default,
        })
    }
}

#[cfg(test)]
mod tests {
    /// The fake mirrors Incus — login paths are
    /// resolved against the guest home, and an invalid one fails the
    /// capture before any effect.
    #[test]
    fn capture_records_login_scrub_targets_and_refuses_invalid_ones_first() {
        let runtime = FakeRuntime::new();
        let create = CreateSandboxRequest::for_test("s", "create");
        runtime.create_fixture(&create).unwrap();
        let request = |paths: &[&str]| crate::CaptureRequest {
            sandbox_id: "s".into(),
            operation_id: "cap".into(),
            stopped: true,
            guest_home: "/home/user".into(),
            extra_scrub_paths: vec![],
            credential_scrub_paths: paths.iter().map(|p| (*p).to_owned()).collect(),
        };
        let refused = runtime
            .capture_template(&request(&[".netrc", "../escape"]), &|_| {})
            .unwrap_err();
        assert_eq!(refused.code, SandboxErrorCode::CaptureFailed);
        assert!(runtime.capture_credential_scrubs().is_empty());
        runtime
            .capture_template(&request(&[".netrc", ".config/tool"]), &|_| {})
            .unwrap();
        let staging = "[0-9a-f]".repeat(16);
        assert_eq!(
            runtime.capture_credential_scrubs(),
            [vec![
                format!("/home/user/.config/.wssp-cred-{staging}"),
                "/home/user/.config/tool".to_owned(),
                "/home/user/.netrc".to_owned(),
                format!("/home/user/.wssp-cred-{staging}"),
            ]]
        );
    }

    #[test]
    fn create_reports_the_grants_the_domain_blocklist_denied() {
        let runtime = FakeRuntime::new();
        let mut create = CreateSandboxRequest::for_test("s", "create");
        create.egress_policy = Some(sandbox_protocol::EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec!["api.bad.example".into(), "ok.example".into()],
            cidrs: Vec::new(),
        });
        create.egress_settings.domain_blocklist.names = vec!["bad.example".into()];
        let response = runtime.create_fixture(&create).unwrap().into_value();
        assert_eq!(response.egress_denied_grants, ["api.bad.example"]);

        let plain = runtime
            .create_fixture(&CreateSandboxRequest::for_test("t", "create-t"))
            .unwrap()
            .into_value();
        assert!(plain.egress_denied_grants.is_empty());
    }

    /// `egressOpen` is static (runtime + resolver support only): a guard that
    /// is unhealthy when it is measured must not freeze a downgrade for the
    /// whole connection. Guard health lives only in the live lease gate.
    #[test]
    fn open_capability_ignores_transient_guard_health() {
        let runtime = FakeRuntime::new().with_advertised_egress_enforcement(true);
        runtime.guard().set_healthy(false);
        assert!(runtime.egress_guard_check().is_err());
        assert!(
            runtime
                .egress_open_capability(&crate::egress::EgressSettings::default())
                .unwrap()
        );
        let plain = FakeRuntime::new();
        assert!(
            !plain
                .egress_open_capability(&crate::egress::EgressSettings::default())
                .unwrap()
        );
    }

    #[test]
    fn mkdir_that_created_parents_before_failing_reports_a_partial_effect() {
        let runtime = FakeRuntime::new();
        let create = CreateSandboxRequest::for_test("s", "create");
        runtime.create_fixture(&create).unwrap();
        // A file whose parent has no directory record: mkdir creates `/x`
        // before it meets the file at `/x/y`.
        runtime.state.lock().unwrap().files.insert(
            ("s".into(), "/x/y".into()),
            crate::FileContent::from_bytes(b"file").unwrap(),
        );
        let mkdir = |path: &str| {
            runtime.mkdir(&MkdirRequest {
                template_fingerprint: create.template_digest.clone(),
                guest: create.guest.clone(),
                sandbox_id: "s".into(),
                instance_name: "wssp-sbx-s".into(),
                operation_id: "mkdir".into(),
                idempotency_key: "mkdir".into(),
                path: path.into(),
            })
        };
        let error = mkdir("/x/y/z").unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::FsNotDirectory);
        assert_eq!(
            error.failure().unwrap().effect,
            sandbox_protocol::results::FailureEffect::Partial
        );
        // Nothing created before the failure stays a no-effect failure.
        let error = mkdir("/x/y/z").unwrap_err();
        assert_eq!(
            error.failure().unwrap().effect,
            sandbox_protocol::results::FailureEffect::None
        );
    }

    #[test]
    fn rich_file_model_has_bounded_pages_exact_mutations_and_revocation() {
        let runtime = FakeRuntime::new();
        let create = CreateSandboxRequest::for_test("s", "create");
        runtime.create_fixture(&create).unwrap();
        let mkdir = MkdirRequest {
            template_fingerprint: create.template_digest.clone(),
            guest: create.guest.clone(),
            sandbox_id: "s".into(),
            instance_name: "wssp-sbx-s".into(),
            operation_id: "mkdir".into(),
            idempotency_key: "mkdir".into(),
            path: "/tree".into(),
        };
        assert!(runtime.mkdir(&mkdir).unwrap().created);
        assert!(!runtime.mkdir(&mkdir).unwrap().created);
        let bytes = crate::FileContent::from_bytes(b"file").unwrap();
        for index in 0..205 {
            runtime
                .write_file(&WriteFileRequest {
                    template_fingerprint: create.template_digest.clone(),
                    guest: create.guest.clone(),
                    sandbox_id: "s".into(),
                    instance_name: "wssp-sbx-s".into(),
                    operation_id: "write".into(),
                    generation: 1,
                    attempt: 1,
                    idempotency_key: "write".into(),
                    path: format!("/tree/{index:04}{}", "é".repeat(90)),
                    bytes: bytes.clone(),
                })
                .unwrap();
        }
        let mut request = ListDirRequest {
            template_fingerprint: create.template_digest.clone(),
            guest: create.guest.clone(),
            sandbox_id: "s".into(),
            instance_name: "wssp-sbx-s".into(),
            operation_id: "list".into(),
            idempotency_key: "list".into(),
            path: "/tree".into(),
            depth: 1,
            limit: 100,
            generation: 1,
            continuation: None,
        };
        let mut count = 0;
        let mut pages = 0;
        loop {
            let page = runtime.list_dir(&request).unwrap();
            assert!(page.items.len() < 100);
            assert!(page.items.iter().all(EntryInfo::validate));
            count += page.items.len();
            pages += 1;
            request.continuation = page.continuation;
            if request.continuation.is_none() {
                break;
            }
        }
        assert_eq!(count, 205);
        assert!(pages >= 3);
        let move_request = MovePathRequest {
            template_fingerprint: create.template_digest.clone(),
            guest: create.guest.clone(),
            sandbox_id: "s".into(),
            instance_name: "wssp-sbx-s".into(),
            operation_id: "move".into(),
            idempotency_key: "move".into(),
            from: "/tree".into(),
            to: "/renamed".into(),
        };
        let moved = runtime.move_path(&move_request).unwrap();
        assert_eq!(moved.r#type, GuestPathKind::Dir);
        assert_eq!(moved.path, "/renamed");
        let remove = RemovePathRequest {
            template_fingerprint: create.template_digest.clone(),
            guest: create.guest.clone(),
            sandbox_id: "s".into(),
            instance_name: "wssp-sbx-s".into(),
            operation_id: "remove".into(),
            idempotency_key: "remove".into(),
            path: "/renamed".into(),
            recursive: false,
        };
        assert_eq!(
            runtime.remove_path(&remove).unwrap_err().code,
            SandboxErrorCode::FsNotEmpty
        );
        assert!(
            runtime
                .remove_path(&RemovePathRequest {
                    recursive: true,
                    ..remove.clone()
                })
                .unwrap()
                .removed
        );
        assert_eq!(
            runtime.remove_path(&remove).unwrap_err().code,
            SandboxErrorCode::FsNotFound
        );
        let permit = std::sync::Arc::new(crate::RuntimePermit::default());
        permit.revoke();
        assert!(runtime.with_cancellation(permit).mkdir(&mkdir).is_err());
        assert!(
            runtime.mkdir(&mkdir).unwrap().created,
            "revoked call must leave no directory"
        );
    }

    #[test]
    fn cached_fingerprint_survives_alias_move() {
        let runtime = super::FakeRuntime::default();
        let first = format!("sha256:{}", "a".repeat(64));
        let second = format!("sha256:{}", "b".repeat(64));
        runtime.register_image("base", &first, "x86_64");
        runtime.register_image("base", &second, "aarch64");
        assert_eq!(
            runtime
                .resolve_image_ref(&first)
                .expect("cached old artifact")
                .architecture,
            "x86_64"
        );
        assert_eq!(
            runtime
                .resolve_image_ref(&second)
                .expect("cached new artifact")
                .architecture,
            "aarch64"
        );
        assert_eq!(
            runtime
                .resolve_image_ref("base")
                .expect("moved alias")
                .fingerprint,
            second
        );
    }
    use super::*;

    /// C38-R2-5: every readiness producer (existing-create, reconnect, query,
    /// probe) goes through the one policy boundary. Healthy reports Ready; a
    /// running drift is GuestUnavailable (IdempotencyConflict for an
    /// existing-create retry, as production's apply refuses it first, G10R-2);
    /// inconclusive stays retryable; a foreign binding conflicts; a
    /// drift-STOPPED sandbox is never restored, except that a create retry
    /// repairs a stopped NIC and starts the VM.
    #[test]
    fn every_readiness_producer_shares_the_policy_boundary() {
        fn reconnect() -> ReconnectSandboxRequest {
            ReconnectSandboxRequest {
                vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                lease: sandbox_protocol::HostLease::for_test(),
                template_fingerprint: CreateSandboxRequest::for_test("sbx-1", "key")
                    .template_digest,
                architecture: Some("x86_64".into()),
                guest: Default::default(),
                sandbox_id: "sbx-1".into(),
                instance_name: "wssp-sbx-sbx-1".into(),
                operation_id: "op-re".into(),
                idempotency_key: "re-key".into(),
                egress_policy: None,
                egress_policy_hash: None,
                egress_admission: crate::egress::EgressAdmission::PERMITTED,
                guest_sudo: false,
            }
        }
        fn probe() -> ProbeSandboxRequest {
            ProbeSandboxRequest {
                template_fingerprint: CreateSandboxRequest::for_test("sbx-1", "key")
                    .template_digest,
                architecture: Some("x86_64".into()),
                sandbox_id: "sbx-1".into(),
                instance_name: "wssp-sbx-sbx-1".into(),
                operation_id: "op-probe".into(),
                idempotency_key: "probe-key".into(),
                guest: Default::default(),
            }
        }
        let create = CreateSandboxRequest::for_test("sbx-1", "key");
        let fp = create.template_digest.clone();
        type Codes = Option<(SandboxErrorCode, bool)>;
        let check = |label: &str, result: Result<(), RuntimeError>, want: Codes| match want {
            None => assert!(result.is_ok(), "{label}: {result:?}"),
            Some((code, inconclusive)) => {
                let err = result.expect_err(label);
                assert_eq!(err.code, code, "{label}: {err}");
                assert_eq!(err.is_enforcement_inconclusive(), inconclusive, "{label}");
            }
        };
        let unavailable = Some((SandboxErrorCode::GuestUnavailable, false));
        let conflict = Some((SandboxErrorCode::IdempotencyConflict, false));
        let inconclusive = Some((SandboxErrorCode::Internal, true));
        // (drift, readiness producers, existing-create retry) on a RUNNING VM.
        for (drift, want, create_want) in [
            (None, None, None),
            (Some(FakePolicyDrift::Acl), unavailable, conflict),
            (Some(FakePolicyDrift::Network), unavailable, conflict),
            (Some(FakePolicyDrift::Nic), unavailable, conflict),
            (
                Some(FakePolicyDrift::Inconclusive),
                inconclusive,
                inconclusive,
            ),
            (Some(FakePolicyDrift::Foreign), conflict, conflict),
        ] {
            let runtime = FakeRuntime::new();
            runtime.create_fixture(&create).expect("create");
            runtime.inject_policy_drift("sbx-1", drift);
            let label = format!("{drift:?}");
            check(
                &format!("{label} query"),
                runtime
                    .query_sandbox("sbx-1", Some("key"), Some(&fp))
                    .map(|state| assert_eq!(state, Some(SandboxLifecycleState::Ready))),
                want,
            );
            check(
                &format!("{label} probe"),
                runtime
                    .probe_sandbox(&probe())
                    .map(|r| assert_eq!(r.state, SandboxLiveProbeState::GuestReady)),
                want,
            );
            check(
                &format!("{label} reconnect"),
                runtime
                    .reconnect_fixture(&reconnect())
                    .map(|r| assert_eq!(r.sandbox.state, SandboxLifecycleState::Ready))
                    .map_err(crate::EffectError::into_error),
                want,
            );
            check(
                &format!("{label} existing create"),
                runtime
                    .create_fixture(&create)
                    .map(|r| assert_eq!(r.sandbox.state, SandboxLifecycleState::Ready))
                    .map_err(crate::EffectError::into_error),
                create_want,
            );
        }
        // A drift-STOPPED sandbox: query/probe report Stopped, and neither
        // reconnect nor an existing-create retry restores it to Ready.
        let runtime = FakeRuntime::new();
        runtime.create_fixture(&create).expect("create");
        runtime.inject_policy_drift("sbx-1", Some(FakePolicyDrift::Acl));
        runtime
            .reconcile_policies(&["sbx-1".into()])
            .expect("reconcile");
        let stopped = || runtime.state.lock().unwrap().sandboxes["sbx-1"].state;
        assert_eq!(stopped(), SandboxLifecycleState::Stopped);
        assert_eq!(
            runtime
                .query_sandbox("sbx-1", Some("key"), Some(&fp))
                .unwrap(),
            Some(SandboxLifecycleState::Stopped)
        );
        assert_eq!(
            runtime.probe_sandbox(&probe()).unwrap().state,
            SandboxLiveProbeState::Stopped
        );
        let err = runtime
            .reconnect_fixture(&reconnect())
            .map_err(crate::EffectError::into_error)
            .expect_err("reconnect refused");
        assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict, "{err}");
        let err = runtime
            .create_fixture(&create)
            .map_err(crate::EffectError::into_error)
            .expect_err("existing create refused");
        assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict, "{err}");
        assert_eq!(stopped(), SandboxLifecycleState::Stopped);
        // Healthy inverse: once verified, the same reconnect resumes it.
        runtime.inject_policy_drift("sbx-1", None);
        runtime.reconnect_fixture(&reconnect()).expect("reconnect");
        assert_eq!(stopped(), SandboxLifecycleState::Ready);
        // A create retry over a NIC-drift-STOPPED VM repairs the NIC and
        // starts it (production `ensure_instance_egress_device` + start).
        let nic = FakeRuntime::new();
        nic.create_fixture(&create).expect("create");
        nic.inject_policy_drift("sbx-1", Some(FakePolicyDrift::Nic));
        nic.reconcile_policies(&["sbx-1".into()])
            .expect("reconcile");
        assert_eq!(
            nic.state.lock().unwrap().sandboxes["sbx-1"].state,
            SandboxLifecycleState::Stopped
        );
        let started = nic
            .create_fixture(&create)
            .expect("stopped NIC is repaired");
        assert_eq!(started.sandbox.state, SandboxLifecycleState::Ready);
        assert_eq!(
            nic.query_sandbox("sbx-1", Some("key"), Some(&fp)).unwrap(),
            Some(SandboxLifecycleState::Ready),
            "the repaired NIC verifies"
        );
        // A foreign binding conflicts whatever the power state: a STOPPED
        // foreign instance is never reported Stopped as if it were ours.
        runtime
            .stop_sandbox(&StopSandboxRequest {
                template_fingerprint: fp.clone(),
                sandbox_id: "sbx-1".into(),
                instance_name: "wssp-sbx-sbx-1".into(),
                operation_id: "op-stop".into(),
                idempotency_key: "stop-key".into(),
            })
            .expect("stop");
        runtime.inject_policy_drift("sbx-1", Some(FakePolicyDrift::Foreign));
        assert_eq!(
            runtime
                .query_sandbox("sbx-1", Some("key"), Some(&fp))
                .unwrap_err()
                .code,
            SandboxErrorCode::IdempotencyConflict
        );
        assert_eq!(
            runtime.probe_sandbox(&probe()).unwrap_err().code,
            SandboxErrorCode::IdempotencyConflict
        );
    }

    #[test]
    fn egress_enforcement_is_advertised_only_on_opt_in() {
        let default = FakeRuntime::new();
        assert!(!default.egress_enforcement_capability().unwrap());
        assert!(default.egress_enforcement_unavailable_reason().is_some());
        let opted_in = FakeRuntime::new().with_advertised_egress_enforcement(true);
        assert!(opted_in.egress_enforcement_capability().unwrap());
        assert_eq!(opted_in.egress_enforcement_unavailable_reason(), None);
        // Cancellation-scoped clones keep the opt-in.
        let permit = std::sync::Arc::new(crate::RuntimePermit::default());
        let scoped = opted_in.with_cancellation(permit);
        assert!(scoped.egress_enforcement_capability().unwrap());
    }

    #[test]
    fn create_failure_switch_fails_new_creates_only_while_present() {
        let switch = std::env::temp_dir().join(format!(
            "wssp-fake-fail-create-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let runtime = FakeRuntime::new().with_create_failure_switch(switch.clone());
        let first = CreateSandboxRequest::for_test("sbx-1", "create-key-1");
        runtime
            .create_fixture(&first)
            .expect("create without switch");

        std::fs::write(&switch, b"").unwrap();
        let second = CreateSandboxRequest::for_test("sbx-2", "create-key-2");
        let error = runtime.create_fixture(&second).unwrap_err();
        // Definitive: nothing was created, so the operation simply failed.
        assert_eq!(error.state(), OperationState::Failed);
        assert_eq!(error.code, SandboxErrorCode::Internal);
        assert!(
            !runtime
                .state
                .lock()
                .unwrap()
                .sandboxes
                .contains_key("sbx-2")
        );
        // A retried create of an existing sandbox still adopts it.
        runtime.create_fixture(&first).expect("idempotent create");

        std::fs::remove_file(&switch).unwrap();
        runtime
            .create_fixture(&second)
            .expect("create after switch removed");
        assert_eq!(runtime.state.lock().unwrap().sandboxes.len(), 2);
    }

    #[test]
    fn create_sandbox_is_idempotent() {
        let runtime = FakeRuntime::new();
        let request = CreateSandboxRequest::for_test("sbx-1", "create-key");
        let first = runtime.create_fixture(&request).expect("create");
        let second = runtime.create_fixture(&request).expect("idempotent create");
        assert_eq!(first.sandbox, second.sandbox);
        assert_eq!(runtime.state.lock().unwrap().sandboxes.len(), 1);
    }

    #[test]
    fn direct_command_duplicate_requires_host_receipt() {
        let runtime = FakeRuntime::new();
        runtime
            .create_fixture(&CreateSandboxRequest::for_test("sbx-1", "create-key"))
            .expect("create");

        let request = RunCommandRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            generation: 1,
            attempt: 1,
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-1".to_string(),
            idempotency_key: "run-key".to_string(),
            argv: vec!["echo".to_string(), "hi".to_string()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: crate::GuestIdentity::default(),
            build_step: None,
        };
        let first = runtime.run_command(&request).expect("run");
        let second = runtime
            .run_command(&request)
            .expect_err("duplicate runtime invocation requires a host receipt");
        assert_eq!(second.code, SandboxErrorCode::IdempotencyConflict);
        assert_eq!(first.command.exit_code, Some(0));
        assert!(
            first
                .command
                .chunks
                .first()
                .expect("stdout chunk")
                .bytes
                .starts_with(b"exec:echo hi")
        );
    }

    /// G4: persisted fake guest files must not keep holding the host's four
    /// active staging slots; a fifth and sixth transfer still get admitted.
    #[test]
    fn stored_guest_files_do_not_hold_active_staging_quota() {
        let runtime = FakeRuntime::new();
        runtime
            .create_fixture(&CreateSandboxRequest::for_test("sbx-1", "create-key"))
            .expect("create");
        for index in 0..6 {
            let bytes = format!("file-{index}\0\u{ff}");
            runtime
                .write_file(&WriteFileRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "sbx-1".to_string(),
                    instance_name: "wssp-sbx-sbx-1".to_string(),
                    operation_id: format!("op-w{index}"),
                    generation: 1,
                    attempt: 1,
                    idempotency_key: format!("write-key-{index}"),
                    path: format!("/root/{index}.bin"),
                    bytes: crate::FileContent::from_bytes(bytes.as_bytes())
                        .expect("transfer capture admitted"),
                    guest: crate::GuestIdentity::default(),
                })
                .expect("write");
        }
        // Six stored files, and all four active slots are still available.
        let active: Vec<_> = (0..4)
            .map(|i| {
                crate::FileStaging::for_creator(1, &format!("creator-{i}"))
                    .expect("active slot free")
            })
            .collect();
        drop(active);
        for index in 0..6 {
            let read = runtime
                .read_file(&ReadFileRequest {
                    sandbox_owner_id: "owner".into(),
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    guest: Default::default(),
                    sandbox_id: "sbx-1".to_string(),
                    instance_name: "wssp-sbx-sbx-1".to_string(),
                    operation_id: format!("op-r{index}"),
                    idempotency_key: format!("read-key-{index}"),
                    path: format!("/root/{index}.bin"),
                })
                .expect("read");
            assert!(read.bytes.is_charged(), "a read is an active transfer");
            assert_eq!(
                read.bytes.read_chunk(0, 64).unwrap(),
                format!("file-{index}\0\u{ff}").as_bytes()
            );
        }
    }

    #[test]
    fn file_round_trip_and_reconnect() {
        let runtime = FakeRuntime::new();
        runtime
            .create_fixture(&CreateSandboxRequest::for_test("sbx-1", "create-key"))
            .expect("create");

        runtime
            .write_file(&WriteFileRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-w".to_string(),
                generation: 1,
                attempt: 1,
                idempotency_key: "write-key".to_string(),
                path: "/root/blob.bin".to_string(),
                bytes: crate::FileContent::from_bytes(b"abc\x00def\xff").expect("file capture"),
                guest: crate::GuestIdentity::default(),
            })
            .expect("write");
        let read = runtime
            .read_file(&ReadFileRequest {
                sandbox_owner_id: "owner".into(),
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-r".to_string(),
                idempotency_key: "read-key".to_string(),
                path: "/root/blob.bin".to_string(),
            })
            .expect("read");
        assert_eq!(
            read.bytes.read_chunk(0, crate::FILE_CHUNK_BYTES).unwrap(),
            b"abc\x00def\xff"
        );

        let stopped = runtime
            .stop_sandbox(&StopSandboxRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-s".to_string(),
                idempotency_key: "stop-key".to_string(),
            })
            .expect("stop");
        assert_eq!(stopped.sandbox.state, SandboxLifecycleState::Stopped);

        let reconnected = runtime
            .reconnect_fixture(&ReconnectSandboxRequest {
                vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                lease: sandbox_protocol::HostLease::for_test(),
                template_fingerprint: crate::CreateSandboxRequest::for_test("default", "default")
                    .template_digest,
                architecture: Some("x86_64".into()),
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-re".to_string(),
                idempotency_key: "re-key".to_string(),
                egress_policy: None,
                egress_policy_hash: None,
                egress_admission: crate::egress::EgressAdmission::PERMITTED,
                guest_sudo: false,
            })
            .expect("reconnect");
        assert_eq!(reconnected.sandbox.state, SandboxLifecycleState::Ready);
    }

    #[test]
    fn filesystem_env_and_snapshot_round_trip() {
        let runtime = FakeRuntime::new();
        runtime
            .create_fixture(&CreateSandboxRequest::for_test("sbx-1", "create-key"))
            .expect("create");

        runtime
            .mkdir(&MkdirRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-mk".to_string(),
                idempotency_key: "mk-key".to_string(),
                path: "/root/data".to_string(),
            })
            .expect("mkdir");
        runtime
            .write_file(&WriteFileRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-w".to_string(),
                generation: 1,
                attempt: 1,
                idempotency_key: "write-key".to_string(),
                path: "/root/data/a.txt".to_string(),
                bytes: crate::FileContent::from_bytes(b"before").expect("file capture"),
                guest: crate::GuestIdentity::default(),
            })
            .expect("write");
        let listed = runtime
            .list_dir(&ListDirRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-ls".to_string(),
                idempotency_key: "ls-key".to_string(),
                path: "/root".to_string(),
                depth: 2,
                limit: 100,
                generation: 1,
                continuation: None,
            })
            .expect("list");
        assert!(
            listed
                .items
                .iter()
                .any(|entry| entry.path == "/root/data" && entry.r#type == GuestPathKind::Dir)
        );
        assert!(
            listed
                .items
                .iter()
                .any(|entry| entry.path == "/root/data/a.txt")
        );

        runtime
            .create_snapshot(&SnapshotRequest {
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-snap".to_string(),
                idempotency_key: "snap-key".to_string(),
                snapshot_name: "base".to_string(),
            })
            .expect("snapshot");
        runtime
            .write_file(&WriteFileRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-w2".to_string(),
                generation: 1,
                attempt: 1,
                idempotency_key: "write-key-2".to_string(),
                path: "/root/data/a.txt".to_string(),
                bytes: crate::FileContent::from_bytes(b"after").expect("file capture"),
                guest: crate::GuestIdentity::default(),
            })
            .expect("overwrite");
        runtime
            .restore_snapshot(&SnapshotRequest {
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-restore".to_string(),
                idempotency_key: "restore-key".to_string(),
                snapshot_name: "base".to_string(),
            })
            .expect("restore");
        let restored = runtime
            .read_file(&ReadFileRequest {
                sandbox_owner_id: "owner".into(),
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-r".to_string(),
                idempotency_key: "read-key".to_string(),
                path: "/root/data/a.txt".to_string(),
            })
            .expect("read restored");
        assert_eq!(
            restored
                .bytes
                .read_chunk(0, crate::FILE_CHUNK_BYTES)
                .unwrap(),
            b"before"
        );

        runtime
            .move_path(&MovePathRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-mv".to_string(),
                idempotency_key: "mv-key".to_string(),
                from: "/root/data/a.txt".to_string(),
                to: "/root/data/b.txt".to_string(),
            })
            .expect("move");
        runtime
            .remove_path(&RemovePathRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-rm".to_string(),
                idempotency_key: "rm-key".to_string(),
                path: "/root/data".to_string(),
                recursive: true,
            })
            .expect("remove");
        assert!(
            runtime
                .stat_path(&StatPathRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    guest: Default::default(),
                    sandbox_id: "sbx-1".to_string(),
                    instance_name: "wssp-sbx-sbx-1".to_string(),
                    operation_id: "op-st".to_string(),
                    idempotency_key: "st-key".to_string(),
                    path: "/root/data".to_string(),
                })
                .is_err()
        );

        let ran = runtime
            .run_command(&RunCommandRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                generation: 1,
                attempt: 1,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-env".to_string(),
                idempotency_key: "env-key".to_string(),
                argv: vec!["env".to_string()],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: vec![("FOO".to_string(), "bar".to_string())],
                stdin: None,
                guest: crate::GuestIdentity::default(),
                build_step: None,
            })
            .expect("run env");
        let stdout = String::from_utf8_lossy(&ran.command.chunks[0].bytes);
        assert!(stdout.contains("FOO=bar"));

        runtime.cancel_operation("op-env").expect("cancel");
        assert!(runtime.state.lock().unwrap().cancelled.contains("op-env"));
    }

    fn seeded() -> FakeRuntime {
        let runtime = FakeRuntime::new();
        runtime
            .create_fixture(&CreateSandboxRequest::for_test("sbx-1", "create-key"))
            .expect("create");
        runtime
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn d20_fake_command_clock_positive_and_zero_obey_authority() {
        use std::sync::{Arc, Mutex, mpsc};
        for streamed in [false, true] {
            for timeout in [None, Some(0), Some(120_000)] {
                let mut runtime = seeded();
                runtime.command_delay = std::time::Duration::from_secs(600);
                let now = std::time::Instant::now();
                let clock = Arc::new(Mutex::new(now));
                let permit = Arc::new(crate::RuntimePermit::with_test_clock(
                    std::time::Duration::from_secs(900),
                    clock.clone(),
                ));
                runtime.cancelled = Some(permit.clone());
                let (ready, started) = mpsc::channel();
                let runtime = runtime.with_lifecycle_hook(move |stage| {
                    if stage
                        == if streamed {
                            "command-output"
                        } else {
                            "command-delay"
                        }
                    {
                        let _ = ready.send(());
                    }
                    Ok(())
                });
                let (done, result) = mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let request = RunCommandRequest {
                        template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                            .template_digest,
                        generation: 1,
                        attempt: 1,
                        sandbox_id: "sbx-1".into(),
                        instance_name: "wssp-sbx-sbx-1".into(),
                        operation_id: "clock".into(),
                        idempotency_key: "clock".into(),
                        argv: vec!["sleep".into(), "600".into()],
                        script: None,
                        cwd: None,
                        timeout_ms: timeout,
                        env: vec![],
                        stdin: None,
                        guest: crate::GuestIdentity::default(),
                        build_step: None,
                    };
                    let outcome = if streamed {
                        runtime.run_command_stream(&request, &crate::CommandOutput::default())
                    } else {
                        runtime.run_command(&request)
                    };
                    done.send(outcome).unwrap();
                });
                started
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap();
                *clock.lock().unwrap() = now + std::time::Duration::from_secs(121);
                let outcome = result.recv_timeout(std::time::Duration::from_millis(50));
                let timer_fired = outcome.is_ok();
                permit.revoke();
                let outcome = outcome.unwrap_or_else(|_| {
                    result
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap()
                });
                worker.join().unwrap();
                assert_eq!(timer_fired, timeout != Some(0));
                let error = outcome.unwrap_err();
                assert_eq!(
                    error.state(),
                    if timeout == Some(0) {
                        OperationState::UnknownOutcome
                    } else {
                        OperationState::Failed
                    }
                );
                assert_eq!(
                    error.code,
                    if timeout == Some(0) {
                        SandboxErrorCode::UnknownOutcome
                    } else {
                        SandboxErrorCode::Timeout
                    }
                );
            }
        }
    }

    #[test]
    fn command_zero_is_not_a_fake_timeout_even_for_sleep() {
        for timeout in [None, Some(0), Some(1), Some(120_000), Some(1_800_000)] {
            for script in [false, true] {
                let runtime = seeded();
                let request = RunCommandRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    generation: 1,
                    attempt: 1,
                    sandbox_id: "sbx-1".into(),
                    instance_name: "wssp-sbx-sbx-1".into(),
                    operation_id: "timer".into(),
                    idempotency_key: "timer".into(),
                    argv: if script {
                        vec![]
                    } else {
                        vec!["sleep".into(), "300".into()]
                    },
                    script: script.then(|| "sleep".into()),
                    cwd: None,
                    timeout_ms: timeout,
                    env: vec![],
                    stdin: None,
                    guest: crate::GuestIdentity::default(),
                    build_step: None,
                };
                assert!(runtime.run_command(&request).is_ok(), "wire={timeout:?}");
                let fault = seeded().with_force_command_timeout(true);
                assert_eq!(
                    fault.run_command(&request).unwrap_err().code,
                    SandboxErrorCode::Timeout
                );
                let mut invalid = request;
                invalid.timeout_ms = Some(1_800_001);
                assert_eq!(
                    seeded().run_command(&invalid).unwrap_err().code,
                    SandboxErrorCode::ProtocolError
                );
            }
        }
    }

    #[test]
    fn nonzero_exit_and_missing_path_leave_vm_ready_for_next_command() {
        let runtime = seeded();
        let failed = runtime
            .run_command(&RunCommandRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                generation: 1,
                attempt: 1,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-exit".to_string(),
                idempotency_key: "exit-key".to_string(),
                argv: vec!["false".to_string()],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: crate::GuestIdentity::default(),
                build_step: None,
            })
            .expect("exit 1 is a completed result");
        assert_eq!(failed.command.state, OperationState::Succeeded);
        assert_eq!(failed.command.exit_code, Some(1));
        assert_eq!(
            runtime.state.lock().unwrap().sandboxes["sbx-1"].state,
            SandboxLifecycleState::Ready
        );

        let grep = runtime
            .run_command(&RunCommandRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                generation: 1,
                attempt: 1,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-grep".to_string(),
                idempotency_key: "grep-key".to_string(),
                argv: vec!["grep".to_string(), "nope".to_string()],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: crate::GuestIdentity::default(),
                build_step: None,
            })
            .expect("grep no-match is a completed result");
        assert_eq!(grep.command.exit_code, Some(1));

        let missing = runtime
            .stat_path(&StatPathRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-stat".to_string(),
                idempotency_key: "stat-key".to_string(),
                path: "/no/such/path".to_string(),
            })
            .expect_err("missing path");
        assert_eq!(missing.code, SandboxErrorCode::FsNotFound);

        let read = runtime
            .read_file(&ReadFileRequest {
                sandbox_owner_id: "owner".into(),
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-read".to_string(),
                idempotency_key: "read-key".to_string(),
                path: "/no/such/file".to_string(),
            })
            .expect_err("missing file");
        assert_eq!(read.code, SandboxErrorCode::FsNotFound);

        let timed_out = runtime
            .clone()
            .with_force_command_timeout(true)
            .run_command(&RunCommandRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                generation: 1,
                attempt: 1,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-timeout".to_string(),
                idempotency_key: "timeout-key".to_string(),
                argv: vec!["sleep".to_string(), "30".to_string()],
                script: None,
                cwd: None,
                timeout_ms: Some(50),
                env: Vec::new(),
                stdin: None,
                guest: crate::GuestIdentity::default(),
                build_step: None,
            })
            .expect_err("timeout");
        assert_eq!(timed_out.code, SandboxErrorCode::Timeout);
        assert_eq!(
            runtime.state.lock().unwrap().sandboxes["sbx-1"].state,
            SandboxLifecycleState::Ready
        );

        let next = runtime
            .run_command(&RunCommandRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                generation: 1,
                attempt: 1,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-next".to_string(),
                idempotency_key: "next-key".to_string(),
                argv: vec!["echo".to_string(), "ok".to_string()],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: crate::GuestIdentity::default(),
                build_step: None,
            })
            .expect("next command after failures");
        assert_eq!(next.command.exit_code, Some(0));
        assert_eq!(
            runtime.state.lock().unwrap().sandboxes["sbx-1"].state,
            SandboxLifecycleState::Ready
        );
    }

    #[test]
    fn c15_script_mode_preserves_unicode_quotes_and_trailing_spaces() {
        let runtime = seeded();
        let script = format!(
            "printf 'capture\\n'; printf \"inj $(rm -rf /)\"; printf ' 世界  '\n{}",
            " ".repeat(40)
        );
        let ran = runtime
            .run_command(&RunCommandRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                generation: 1,
                attempt: 1,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-script".to_string(),
                idempotency_key: "script-key".to_string(),
                argv: Vec::new(),
                script: Some(script.clone()),
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: crate::GuestIdentity::default(),
                build_step: None,
            })
            .expect("script run");
        let stdout = String::from_utf8_lossy(&ran.command.chunks[0].bytes);
        assert_eq!(stdout, format!("exec:script:{script}\n"));
    }

    #[test]
    fn c15_runtime_modes_and_budget_cannot_be_bypassed() {
        let runtime = seeded();
        let mut request = RunCommandRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            generation: 1,
            attempt: 1,
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            operation_id: "op-mode".into(),
            idempotency_key: "mode".into(),
            argv: vec!["true".into()],
            script: Some("echo".into()),
            cwd: None,
            timeout_ms: None,
            env: vec![],
            stdin: None,
            guest: Default::default(),
            build_step: None,
        };
        assert_eq!(
            runtime.run_command(&request).unwrap_err().code,
            SandboxErrorCode::ProtocolError
        );
        request.argv.clear();
        request.script = Some("x".repeat(sandbox_protocol::command_payload_max_bytes()));
        assert_eq!(
            runtime.run_command(&request).unwrap_err().code,
            SandboxErrorCode::RequestTooLarge
        );
        request.script = Some("true".into());
        assert_eq!(
            runtime.run_command(&request).unwrap().command.exit_code,
            Some(0)
        );
    }

    #[test]
    fn c15_argv_preserves_empty_string_entry() {
        let runtime = seeded();
        let ran = runtime
            .run_command(&RunCommandRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                generation: 1,
                attempt: 1,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-empty-arg".to_string(),
                idempotency_key: "empty-arg-key".to_string(),
                argv: vec!["".to_string(), "echo".to_string()],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: crate::GuestIdentity::default(),
                build_step: None,
            })
            .expect("argv run");
        let stdout = String::from_utf8_lossy(&ran.command.chunks[0].bytes);
        assert_eq!(stdout, "exec: echo\n");
    }

    #[test]
    fn c15_detached_broker_command_does_not_block_the_next_fake_command() {
        let runtime = seeded();
        let _detached = runtime
            .run_command(&RunCommandRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                generation: 1,
                attempt: 1,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-detached".to_string(),
                idempotency_key: "detached-key".to_string(),
                argv: vec![
                    "wssp-broker".to_string(),
                    "sleep".to_string(),
                    "30".to_string(),
                ],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: crate::GuestIdentity::default(),
                build_step: None,
            })
            .expect("broker completes in fake runtime");
        let next = runtime
            .run_command(&RunCommandRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                generation: 1,
                attempt: 1,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-after-detached".to_string(),
                idempotency_key: "after-detached-key".to_string(),
                argv: vec!["echo".to_string(), "ok".to_string()],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: crate::GuestIdentity::default(),
                build_step: None,
            })
            .expect("next command");
        assert_eq!(next.command.exit_code, Some(0));
    }

    #[test]
    fn missing_vm_is_gone_not_missing_path() {
        let runtime = FakeRuntime::new();
        let gone = runtime
            .stat_path(&StatPathRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "missing".to_string(),
                instance_name: "wssp-sbx-missing".to_string(),
                operation_id: "op-stat".to_string(),
                idempotency_key: "stat-key".to_string(),
                path: "/root/a".to_string(),
            })
            .expect_err("gone");
        assert_eq!(gone.code, SandboxErrorCode::SandboxNotFound);

        let live = seeded();
        let path = live
            .stat_path(&StatPathRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-stat".to_string(),
                idempotency_key: "stat-key".to_string(),
                path: "/root/a".to_string(),
            })
            .expect_err("path");
        assert_eq!(path.code, SandboxErrorCode::FsNotFound);
    }

    #[test]
    fn stopped_guest_rejects_ordinary_work_without_lifecycle_change() {
        let runtime = seeded();
        runtime
            .stop_sandbox(&StopSandboxRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-stop".to_string(),
                idempotency_key: "stop-key".to_string(),
            })
            .expect("stop");
        let err = runtime
            .stat_path(&StatPathRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: "op-stat".to_string(),
                idempotency_key: "stat-stopped".to_string(),
                path: "/root/a".to_string(),
            })
            .expect_err("stopped");
        assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning);
        assert_eq!(
            runtime.state.lock().unwrap().sandboxes["sbx-1"].state,
            SandboxLifecycleState::Stopped
        );
    }

    #[test]
    fn refuse_root_is_path_refused_not_access_denied() {
        let runtime = seeded();
        let mkdir = runtime
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
            .expect_err("mkdir");
        assert_eq!(mkdir.code, SandboxErrorCode::PathRefused);
        assert_ne!(mkdir.code, SandboxErrorCode::AccessDenied);

        let remove = runtime
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
            .expect_err("remove");
        assert_eq!(remove.code, SandboxErrorCode::PathRefused);

        let move_from = runtime
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
            .expect_err("move");
        assert_eq!(move_from.code, SandboxErrorCode::PathRefused);
        assert_eq!(
            runtime.state.lock().unwrap().sandboxes["sbx-1"].state,
            SandboxLifecycleState::Ready
        );
    }
    #[test]
    fn absent_cleanup_is_completed_and_never_creates_a_record() {
        let runtime = FakeRuntime::new();
        for _ in 0..2 {
            let stop = runtime
                .stop_sandbox(&StopSandboxRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "absent".into(),
                    instance_name: "wssp-sbx-absent".into(),
                    operation_id: "stop".into(),
                    idempotency_key: "stop".into(),
                })
                .unwrap();
            assert_eq!(stop.sandbox.state, SandboxLifecycleState::Absent);
            let kill = runtime
                .kill_fixture(&KillSandboxRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "absent".into(),
                    instance_name: "wssp-sbx-absent".into(),
                    operation_id: "kill".into(),
                    idempotency_key: "kill".into(),
                })
                .unwrap();
            assert_eq!(kill.sandbox.state, SandboxLifecycleState::Deleted);
            assert_eq!(runtime.query_sandbox("absent", None, None).unwrap(), None);
        }
    }
}

#[cfg(test)]
mod vm_size_tests;

/// The fake applies the same M19 predicate as the Incus compiler to the
/// policy's grants, so fake stacks report denied grants too.
fn fake_denied_grants(request: &CreateSandboxRequest) -> Vec<String> {
    let Some(policy) = &request.egress_policy else {
        return Vec::new();
    };
    crate::bounded_denied_grants(
        policy
            .domains
            .iter()
            .filter(|domain| crate::egress::domain_denied(domain, &request.egress_settings))
            .cloned()
            .collect(),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(test)]
mod retire_tests;
