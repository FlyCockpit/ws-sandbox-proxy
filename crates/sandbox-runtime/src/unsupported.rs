use sandbox_protocol::SandboxErrorCode;

use crate::error::RuntimeError;
use crate::{
    CreateSandboxRequest, CreateSandboxResponse, EntryInfo, ForkSandboxRequest,
    ForkSandboxResponse, KillSandboxRequest, KillSandboxResponse, ListDirRequest, ListDirResponse,
    ListProcessesRequest, ListProcessesResponse, MkdirRequest, MkdirResponse, MovePathRequest,
    ReadFileRequest, ReadFileResponse, ReconnectSandboxRequest, ReconnectSandboxResponse,
    RemovePathRequest, RemovePathResponse, RunCommandRequest, RunCommandResponse, SandboxRuntime,
    SignalProcessRequest, SnapshotRequest, SnapshotResponse, StatPathRequest, StopSandboxRequest,
    StopSandboxResponse, WriteFileRequest, WriteFileResponse, WriteStdinRequest,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedRuntime;

impl UnsupportedRuntime {
    pub fn new() -> Self {
        Self
    }
}

impl SandboxRuntime for UnsupportedRuntime {
    fn initialize_storage_pool(
        &self,
        _: &str,
        _: Option<&crate::StoragePoolIdentity>,
    ) -> Result<crate::StoragePoolIdentity, RuntimeError> {
        Err(unsupported())
    }
    fn observe_storage_pool(
        &self,
        _: &crate::StoragePoolIdentity,
    ) -> Result<crate::StoragePoolObservation, RuntimeError> {
        Err(unsupported())
    }
    fn storage_root_census(
        &self,
        _: &crate::StoragePoolIdentity,
    ) -> Result<crate::StorageRootCensus, RuntimeError> {
        Err(unsupported())
    }
    fn storage_physical_usage(
        &self,
        _: &crate::StoragePoolIdentity,
        _: &[String],
        _: u64,
    ) -> Result<crate::PhysicalUsage, RuntimeError> {
        Err(unsupported())
    }
    fn prove_root_absent(
        &self,
        _: &crate::RootDisk,
        _: &str,
    ) -> Result<crate::RootAbsenceProof, RuntimeError> {
        Err(unsupported())
    }
    fn create_sandbox_on_storage(
        &self,
        request: &CreateSandboxRequest,
        _: &crate::RootDisk,
    ) -> crate::EffectOutcome<CreateSandboxResponse> {
        self.create_bound(request)
    }
    fn reconnect_sandbox_on_storage(
        &self,
        request: &ReconnectSandboxRequest,
        _: &crate::RootDisk,
    ) -> crate::EffectOutcome<ReconnectSandboxResponse> {
        self.reconnect_bound(request)
    }
    fn kill_sandbox_on_storage(
        &self,
        request: &KillSandboxRequest,
        _: &crate::RootDisk,
    ) -> crate::EffectOutcome<KillSandboxResponse> {
        self.kill_bound(request)
    }

    fn host_resources(&self) -> Result<crate::HostResources, RuntimeError> {
        Err(unsupported())
    }

    fn with_cancellation(
        &self,
        _: std::sync::Arc<crate::RuntimePermit>,
    ) -> Box<dyn SandboxRuntime> {
        Box::new(*self)
    }
    fn query_sandbox(
        &self,
        _: &str,
        _: Option<&str>,
        _template_fingerprint: Option<&str>,
    ) -> Result<Option<sandbox_protocol::SandboxLifecycleState>, RuntimeError> {
        Err(unsupported())
    }

    // No engine access means no evidence about VMs left by another runtime
    // or an earlier host process. Never turn an unsupported lookup into absence.
    fn sandbox_exists(&self, _: &str) -> Result<bool, RuntimeError> {
        Err(unsupported())
    }

    fn run_command(
        &self,
        _request: &RunCommandRequest,
    ) -> crate::EffectOutcome<RunCommandResponse> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn read_file(&self, _request: &ReadFileRequest) -> Result<ReadFileResponse, RuntimeError> {
        Err(unsupported())
    }

    fn open_pty(
        &self,
        _request: &crate::OpenPtyRequest,
    ) -> Result<crate::PtySession, crate::PtyOpenFailure> {
        Err(unsupported().into())
    }

    fn write_file(&self, _request: &WriteFileRequest) -> crate::EffectOutcome<WriteFileResponse> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn probe_sandbox(
        &self,
        _request: &crate::ProbeSandboxRequest,
    ) -> Result<crate::ProbeSandboxResponse, RuntimeError> {
        Err(unsupported())
    }

    fn stop_sandbox(
        &self,
        _request: &StopSandboxRequest,
    ) -> crate::EffectOutcome<StopSandboxResponse> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn list_dir(&self, _request: &ListDirRequest) -> Result<ListDirResponse, RuntimeError> {
        Err(unsupported())
    }

    fn stat_path(&self, _request: &StatPathRequest) -> Result<EntryInfo, RuntimeError> {
        Err(unsupported())
    }

    fn mkdir(&self, _request: &MkdirRequest) -> crate::EffectOutcome<MkdirResponse> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn remove_path(
        &self,
        _request: &RemovePathRequest,
    ) -> crate::EffectOutcome<RemovePathResponse> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn move_path(&self, _request: &MovePathRequest) -> crate::EffectOutcome<EntryInfo> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn cancel_operation(&self, _operation_id: &str) -> crate::EffectOutcome<()> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn list_processes(
        &self,
        _request: &ListProcessesRequest,
    ) -> Result<ListProcessesResponse, RuntimeError> {
        Err(unsupported())
    }

    fn signal_process(
        &self,
        _request: &SignalProcessRequest,
    ) -> crate::EffectOutcome<crate::SignalOutcome> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn write_stdin(&self, _request: &WriteStdinRequest) -> crate::EffectOutcome<()> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn create_snapshot(
        &self,
        _request: &SnapshotRequest,
    ) -> crate::EffectOutcome<SnapshotResponse> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn restore_snapshot(
        &self,
        _request: &SnapshotRequest,
    ) -> crate::EffectOutcome<SnapshotResponse> {
        Err(crate::before_issue::unsupported_runtime())
    }

    fn fork_sandbox(
        &self,
        _request: &ForkSandboxRequest,
    ) -> crate::EffectOutcome<ForkSandboxResponse> {
        Err(crate::before_issue::unsupported_runtime())
    }
}

fn unsupported() -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::HostRuntimeUnsupported,
        "sandbox host runtime is only available on Linux",
    )
}

impl UnsupportedRuntime {
    fn create_bound(
        &self,
        request: &CreateSandboxRequest,
    ) -> crate::EffectOutcome<CreateSandboxResponse> {
        let error = crate::before_issue::unsupported_runtime();
        Err(
            if crate::allocation_refusal_for_runtime(
                self,
                crate::AllocationKind::Create,
                request.first_attempt,
                &request.sandbox_id,
            ) == sandbox_protocol::OperationState::Failed
            {
                error
            } else {
                error.after_issue()
            },
        )
    }
    fn kill_bound(
        &self,
        _request: &KillSandboxRequest,
    ) -> crate::EffectOutcome<KillSandboxResponse> {
        Err(crate::before_issue::unsupported_runtime())
    }
    fn reconnect_bound(
        &self,
        _request: &ReconnectSandboxRequest,
    ) -> crate::EffectOutcome<ReconnectSandboxResponse> {
        // No journal or stopped/absent observation is available here. The
        // allocation classifier therefore retains uncertainty, as for create.
        Err(crate::before_issue::unsupported_runtime().for_create(false, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_host_runtime_unsupported() {
        let runtime = UnsupportedRuntime::new();
        let err = runtime
            .create_bound(&CreateSandboxRequest {
                refused_dns_hints: false,
                first_attempt: false,
                vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                lease: sandbox_protocol::HostLease::for_test(),
                sandbox_id: "sbx".to_string(),
                instance_name: "wssp-sbx-sbx".to_string(),
                idempotency_key: "key".to_string(),
                template_digest: "digest".to_string(),
                incus_fingerprint: None,
                guest: Default::default(),
                architecture: None,
                egress_policy: None,
                egress_policy_hash: None,
                egress_settings: crate::egress::EgressSettings::default(),
                egress_admission: crate::egress::EgressAdmission::PERMITTED,
                guest_privilege: Default::default(),
                readiness: Default::default(),
                restore: None,
            })
            .unwrap_err();
        assert_eq!(err.code, SandboxErrorCode::HostRuntimeUnsupported);
    }

    #[test]
    fn unsupported_create_cannot_prove_absence_even_on_first_attempt() {
        for first_attempt in [true, false] {
            let runtime = UnsupportedRuntime;
            assert!(runtime.sandbox_exists("sbx").is_err());
            assert!(runtime.sandbox_may_be_running("sbx").is_err());
            let mut request = CreateSandboxRequest::for_test("sbx", "create");
            request.first_attempt = first_attempt;
            let error = runtime.create_bound(&request).unwrap_err();
            assert_eq!(error.code, SandboxErrorCode::HostRuntimeUnsupported);
            assert_eq!(
                error.state(),
                sandbox_protocol::OperationState::UnknownOutcome
            );
        }
    }

    #[test]
    fn unsupported_reconnect_has_no_first_attempt_or_stopped_vm_proof() {
        let error = UnsupportedRuntime::new()
            .reconnect_bound(&ReconnectSandboxRequest {
                vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                lease: sandbox_protocol::HostLease::for_test(),
                template_fingerprint: "digest".into(),
                architecture: None,
                guest: Default::default(),
                sandbox_id: "sbx".into(),
                instance_name: "wssp-sbx-sbx".into(),
                operation_id: "reconnect".into(),
                idempotency_key: "reconnect".into(),
                egress_policy: None,
                egress_policy_hash: None,
                egress_admission: crate::egress::EgressAdmission::PERMITTED,
                guest_sudo: false,
            })
            .unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::HostRuntimeUnsupported);
        assert_eq!(
            error.state(),
            sandbox_protocol::OperationState::UnknownOutcome
        );
    }

    #[test]
    fn terminal_is_an_unsupported_capability_error_not_a_panic() {
        let runtime = UnsupportedRuntime::new();
        assert!(!runtime.pty_capability());
        let request = crate::OpenPtyRequest {
            template_fingerprint: "fp".into(),
            sandbox_id: "sbx".into(),
            session_id: "term-1".into(),
            guest: Default::default(),
            size: crate::PtySize::new(24, 80).unwrap(),
            max_duration: None,
            env: Vec::new(),
            cwd: None,
            setup_cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let err = runtime.open_pty(&request).unwrap_err();
        assert_eq!(err.code, SandboxErrorCode::HostRuntimeUnsupported);
        // Closing on a runtime without terminals is a no-op, not a panic.
        assert_eq!(
            runtime.close_pty_sessions(None, crate::PtyCloseIntent::Shutdown),
            0
        );
    }

    /// The trait default (any runtime without a PTY adapter) refuses with
    /// the stable capability error.
    #[test]
    fn trait_default_terminal_is_unsupported_capability() {
        struct NoPty;
        impl SandboxRuntime for NoPty {
            fn with_cancellation(
                &self,
                _: std::sync::Arc<crate::RuntimePermit>,
            ) -> Box<dyn SandboxRuntime> {
                Box::new(NoPty)
            }
            fn query_sandbox(
                &self,
                _: &str,
                _: Option<&str>,
                _: Option<&str>,
            ) -> Result<Option<sandbox_protocol::SandboxLifecycleState>, RuntimeError> {
                Err(unsupported())
            }
            fn create_sandbox_on_storage(
                &self,
                r: &CreateSandboxRequest,
                root: &crate::RootDisk,
            ) -> crate::EffectOutcome<CreateSandboxResponse> {
                UnsupportedRuntime.create_sandbox_on_storage(r, root)
            }
            fn kill_sandbox_on_storage(
                &self,
                r: &KillSandboxRequest,
                root: &crate::RootDisk,
            ) -> crate::EffectOutcome<KillSandboxResponse> {
                UnsupportedRuntime.kill_sandbox_on_storage(r, root)
            }
            fn run_command(
                &self,
                r: &RunCommandRequest,
            ) -> crate::EffectOutcome<RunCommandResponse> {
                UnsupportedRuntime.run_command(r)
            }
            fn read_file(&self, r: &ReadFileRequest) -> Result<ReadFileResponse, RuntimeError> {
                UnsupportedRuntime.read_file(r)
            }
            fn write_file(&self, r: &WriteFileRequest) -> crate::EffectOutcome<WriteFileResponse> {
                UnsupportedRuntime.write_file(r)
            }
            fn probe_sandbox(
                &self,
                r: &crate::ProbeSandboxRequest,
            ) -> Result<crate::ProbeSandboxResponse, RuntimeError> {
                UnsupportedRuntime.probe_sandbox(r)
            }
            fn reconnect_sandbox_on_storage(
                &self,
                r: &ReconnectSandboxRequest,
                root: &crate::RootDisk,
            ) -> crate::EffectOutcome<ReconnectSandboxResponse> {
                UnsupportedRuntime.reconnect_sandbox_on_storage(r, root)
            }
            fn stop_sandbox(
                &self,
                r: &StopSandboxRequest,
            ) -> crate::EffectOutcome<StopSandboxResponse> {
                UnsupportedRuntime.stop_sandbox(r)
            }
            fn list_dir(&self, r: &ListDirRequest) -> Result<ListDirResponse, RuntimeError> {
                UnsupportedRuntime.list_dir(r)
            }
            fn stat_path(&self, r: &StatPathRequest) -> Result<EntryInfo, RuntimeError> {
                UnsupportedRuntime.stat_path(r)
            }
            fn mkdir(&self, r: &MkdirRequest) -> crate::EffectOutcome<MkdirResponse> {
                UnsupportedRuntime.mkdir(r)
            }
            fn remove_path(
                &self,
                r: &RemovePathRequest,
            ) -> crate::EffectOutcome<RemovePathResponse> {
                UnsupportedRuntime.remove_path(r)
            }
            fn move_path(&self, r: &MovePathRequest) -> crate::EffectOutcome<EntryInfo> {
                UnsupportedRuntime.move_path(r)
            }
            fn cancel_operation(&self, id: &str) -> crate::EffectOutcome<()> {
                UnsupportedRuntime.cancel_operation(id)
            }
            fn list_processes(
                &self,
                r: &ListProcessesRequest,
            ) -> Result<ListProcessesResponse, RuntimeError> {
                UnsupportedRuntime.list_processes(r)
            }
            fn signal_process(
                &self,
                r: &SignalProcessRequest,
            ) -> crate::EffectOutcome<crate::SignalOutcome> {
                UnsupportedRuntime.signal_process(r)
            }
            fn write_stdin(&self, r: &WriteStdinRequest) -> crate::EffectOutcome<()> {
                UnsupportedRuntime.write_stdin(r)
            }
            fn create_snapshot(
                &self,
                r: &SnapshotRequest,
            ) -> crate::EffectOutcome<SnapshotResponse> {
                UnsupportedRuntime.create_snapshot(r)
            }
            fn restore_snapshot(
                &self,
                r: &SnapshotRequest,
            ) -> crate::EffectOutcome<SnapshotResponse> {
                UnsupportedRuntime.restore_snapshot(r)
            }
            fn fork_sandbox(
                &self,
                r: &ForkSandboxRequest,
            ) -> crate::EffectOutcome<ForkSandboxResponse> {
                UnsupportedRuntime.fork_sandbox(r)
            }
        }
        let request = crate::OpenPtyRequest {
            template_fingerprint: "fp".into(),
            sandbox_id: "sbx".into(),
            session_id: "term-1".into(),
            guest: Default::default(),
            size: crate::PtySize::new(24, 80).unwrap(),
            max_duration: None,
            env: Vec::new(),
            cwd: None,
            setup_cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        assert!(!NoPty.pty_capability());
        let err = NoPty.open_pty(&request).unwrap_err();
        assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
    }
}
