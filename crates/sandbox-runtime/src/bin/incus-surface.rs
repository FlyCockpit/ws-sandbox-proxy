//! Live Incus surface harness for the wssp node-daemon runtime.
//!
//! This drives the production [`sandbox_runtime::IncusKvmRuntime`] and
//! [`sandbox_runtime::IncusClient`] — the same types `wssp host run` uses —
//! plus a few raw `incus` probes for commands the wrapper does not expose
//! (`stop`, `project show`, `profile show`). It never deletes images.
//!
//! Linux only. Does not start automatically; CI compiles it but never runs it.
//!
//! ```sh
//! cargo run -p sandbox-runtime --bin incus-surface
//! cargo run -p sandbox-runtime --bin incus-surface -- cleanup <run-id>
//! ```
//!
//! Requires a host-local VM image with agent/tooling, UID/GID 1000,
//! writable `/home/user`, and `/bin/bash`. Image architecture is discovered.
//! Optional env: `WSSP_INCUS_IMAGE` (default local alias `wssp-base`),
//! `WSSP_INCUS_BINARY`, `WSSP_INCUS_PROJECT` (ignored; default project is used
//! for the lifecycle suite so we do not trash a configured host project).

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    match std::env::args().nth(1).as_deref() {
        Some("cleanup") => cleanup_only(std::env::args().nth(2).as_deref()),
        Some(other) if other != "test-all" => {
            eprintln!("usage: incus-surface [test-all|cleanup <run-id>]");
            2
        }
        _ => test_all(),
    }
}

#[cfg(not(target_os = "linux"))]
fn test_all() -> i32 {
    eprintln!("incus-surface: Linux-only (Incus/KVM host surface)");
    2
}

#[cfg(not(target_os = "linux"))]
fn cleanup_only(_run_id: Option<&str>) -> i32 {
    eprintln!("incus-surface: Linux-only (Incus/KVM host surface)");
    2
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::PathBuf;
    #[cfg(test)]
    use std::process::Command;
    use std::process::Output;
    use std::thread;
    use std::time::{Duration, Instant};

    use sandbox_protocol::{OperationState, SandboxErrorCode, SandboxLifecycleState};
    use sandbox_runtime::{
        BoundInstance, CreateSandboxRequest, ForkSandboxRequest, GuestIdentity, GuestPathKind,
        IncusClient, IncusConfig, IncusKvmRuntime, KillSandboxRequest, ListDirRequest,
        ListProcessesRequest, MkdirRequest, MovePathRequest, ProcessSignal, ReadFileRequest,
        ReconnectSandboxRequest, RemovePathRequest, RunCommandRequest, SandboxRuntime,
        SignalProcessRequest, SnapshotRequest, StatPathRequest, StopSandboxRequest,
        WriteFileRequest, WriteStdinRequest, default_incus_instance_name,
    };

    const IMAGE_DEFAULT: &str = "wssp-base";
    const PROJECT_PROBE_PREFIX: &str = "wssp-surface";
    const META_SANDBOX: &str = "user.flycockpit.sandbox_id";
    const META_KEY: &str = "user.flycockpit.create_idempotency_key";
    const META_TEMPLATE: &str = "user.flycockpit.template_digest";

    #[derive(Debug)]
    enum Outcome {
        Pass,
        Fail(String),
    }

    // This explicitly invoked surface harness retains the root selected by runtime().
    // It cannot enter a lifecycle effect without that pinned binding.
    trait SurfaceLifecycle {
        fn create_sandbox(
            &self,
            r: &CreateSandboxRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::CreateSandboxResponse>;
        fn reconnect_sandbox(
            &self,
            r: &ReconnectSandboxRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::ReconnectSandboxResponse>;
        fn kill_sandbox(
            &self,
            r: &KillSandboxRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::KillSandboxResponse>;
    }
    impl SurfaceLifecycle for IncusKvmRuntime {
        fn create_sandbox(
            &self,
            r: &CreateSandboxRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::CreateSandboxResponse> {
            self.create_sandbox_on_storage(
                r,
                self.root_disk().ok_or_else(|| {
                    sandbox_runtime::RuntimeError::new(
                        sandbox_protocol::SandboxErrorCode::VmSizeMismatch,
                        "surface root binding required",
                    )
                })?,
            )
        }
        fn reconnect_sandbox(
            &self,
            r: &ReconnectSandboxRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::ReconnectSandboxResponse> {
            self.reconnect_sandbox_on_storage(
                r,
                self.root_disk().ok_or_else(|| {
                    sandbox_runtime::RuntimeError::new(
                        sandbox_protocol::SandboxErrorCode::VmSizeMismatch,
                        "surface root binding required",
                    )
                })?,
            )
        }
        fn kill_sandbox(
            &self,
            r: &KillSandboxRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::KillSandboxResponse> {
            self.kill_sandbox_on_storage(
                r,
                self.root_disk().ok_or_else(|| {
                    sandbox_runtime::RuntimeError::new(
                        sandbox_protocol::SandboxErrorCode::VmSizeMismatch,
                        "surface root binding required",
                    )
                })?,
            )
        }
    }
    struct Report {
        cases: Vec<(&'static str, Outcome)>,
    }

    impl Report {
        fn new() -> Self {
            Self { cases: Vec::new() }
        }

        fn pass(&mut self, name: &'static str) {
            self.cases.push((name, Outcome::Pass));
        }

        fn fail(&mut self, name: &'static str, detail: impl Into<String>) {
            self.cases.push((name, Outcome::Fail(detail.into())));
        }

        fn check(&mut self, name: &'static str, ok: bool, detail: impl Into<String>) {
            if ok {
                self.pass(name);
            } else {
                self.fail(name, detail);
            }
        }

        fn print(&self) -> i32 {
            let mut failed = 0u32;
            println!("incus-surface results");
            for (name, outcome) in &self.cases {
                match outcome {
                    Outcome::Pass => println!("  PASS  {name}"),
                    Outcome::Fail(detail) => {
                        failed += 1;
                        println!("  FAIL  {name}");
                        println!("        {detail}");
                    }
                }
            }
            let passed = self.cases.len() as u32 - failed;
            println!(
                "{passed} passed, {failed} failed, {} total",
                self.cases.len()
            );
            i32::from(failed > 0)
        }
    }

    /// Effective uid from /proc (the surface harness targets Linux hosts).
    fn effective_uid() -> Result<u32, String> {
        let status = std::fs::read_to_string("/proc/self/status")
            .map_err(|err| format!("cannot read /proc/self/status: {err}"))?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| "cannot parse the effective uid from /proc/self/status".to_string())
    }

    /// The private parent for ALL surface state (run locks and state dirs):
    /// an owner-validated, mode-0700 directory that SURVIVES cleanup, so a
    /// different local user can never recreate a run's state dir and plant
    /// symlinks at the predictable journal temp names (R21-F1).
    /// `WSSP_SURFACE_ROOT` overrides the location (integration tests only).
    fn surface_root() -> Result<PathBuf, String> {
        if let Ok(custom) = std::env::var("WSSP_SURFACE_ROOT") {
            return validate_private_root(PathBuf::from(custom));
        }
        let uid = effective_uid()?;
        validate_private_root(std::env::temp_dir().join(format!("wssp-surface-root-{uid}")))
    }

    fn validate_private_root(root: PathBuf) -> Result<PathBuf, String> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        for _ in 0..2 {
            match std::fs::symlink_metadata(&root) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() || !meta.is_dir() {
                        return Err(format!(
                            "surface state root {} is a symlink or not a directory; refusing",
                            root.display()
                        ));
                    }
                    if meta.uid() != effective_uid()? {
                        return Err(format!(
                            "surface state root {} is owned by another user; refusing",
                            root.display()
                        ));
                    }
                    let mode = meta.permissions().mode() & 0o777;
                    if mode != 0o700 {
                        return Err(format!(
                            "surface state root {} must be mode 0700 (is {mode:o}); refusing",
                            root.display()
                        ));
                    }
                    return Ok(root);
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // Create 0700, then RE-VALIDATE: a racer's pre-created or
                    // symlinked root is caught by the second pass.
                    let _ = std::fs::DirBuilder::new().mode(0o700).create(&root);
                }
                Err(err) => {
                    return Err(format!(
                        "cannot inspect the surface state root {}: {err}",
                        root.display()
                    ));
                }
            }
        }
        Err(format!(
            "cannot establish a private surface state root {}",
            root.display()
        ))
    }

    struct Harness {
        binary: String,
        image: String,
        run_id: String,
        prefix: String,
        probe_project: String,
        /// This run's isolated host state dir (network cleanup journal,
        /// resolved plans, allocation lock): removed by `cleanup`.
        state_dir: std::path::PathBuf,
        /// Process-held exclusive lock for this run id, living OUTSIDE the
        /// state dir so the initial cleanup's directory removal never drops
        /// ownership while the harness is mid-run.
        run_lock: Option<std::fs::File>,
        /// Set only after this run proved the probe project absent.
        owns_probe_project: bool,
        report: Report,
    }

    impl Harness {
        /// Production constructor: the state dir is keyed by the RUN ID ONLY,
        /// so a later `incus-surface cleanup <run-id>` process reopens the
        /// SAME directory and consumes a retained journal. Concurrency is
        /// guarded by a process-held flock on a lock file OUTSIDE the state
        /// dir: the harness's initial cleanup removes the directory itself,
        /// and ownership must survive that for the entire run — a second
        /// claimant (another `cleanup <run-id>`) is refused while any process
        /// holds the lock, and a dead owner's claim is released by the
        /// kernel, so crash retention still works.
        fn claimed(run_id: String) -> Result<Self, String> {
            let root = surface_root()?;
            Self::claimed_under(&root, run_id)
        }

        /// `cleanup <run-id>`: the run id names the probe project, so the
        /// drain owns it (Incus still refuses a non-empty delete).
        fn claimed_for_cleanup(run_id: String) -> Result<Self, String> {
            let mut h = Self::claimed(run_id)?;
            h.owns_probe_project = true;
            Ok(h)
        }

        /// `test-all` owns the probe project only when it does not exist yet,
        /// so a run never deletes a project it did not create. False when it
        /// exists or cannot be checked.
        fn claim_probe_project(&mut self) -> bool {
            match self.raw(None, &["project", "show", &self.probe_project]) {
                Ok(out) if !out.status.success() => {
                    self.owns_probe_project = true;
                    true
                }
                _ => false,
            }
        }

        fn claimed_under(root: &std::path::Path, run_id: String) -> Result<Self, String> {
            let mut h = Self::new(run_id);
            let (dir, lock) = Self::claim_state_dir(root, &h.run_id)?;
            h.state_dir = dir;
            h.run_lock = Some(lock);
            Ok(h)
        }

        fn claim_state_dir(
            root: &std::path::Path,
            run_id: &str,
        ) -> Result<(PathBuf, std::fs::File), String> {
            let lock_path = root.join(format!("lock-{run_id}"));
            let mut lock = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&lock_path)
                .map_err(|err| {
                    format!("cannot open the run lock {}: {err}", lock_path.display())
                })?;
            match lock.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(format!(
                        "run {run_id} is owned by a live process; refusing to share its state"
                    ));
                }
                Err(err) => {
                    return Err(format!("cannot lock {}: {err}", lock_path.display()));
                }
            }
            use std::io::Write as _;
            lock.set_len(0)
                .and_then(|()| write!(lock, "{}", std::process::id()))
                .map_err(|err| format!("cannot annotate the run lock: {err}"))?;
            let dir = root.join(format!("state-{run_id}"));
            // Reject planted paths BEFORE create_dir_all would follow them:
            // a symlinked or foreign-owned state dir is never adopted.
            if let Ok(meta) = std::fs::symlink_metadata(&dir) {
                use std::os::unix::fs::MetadataExt;
                if meta.file_type().is_symlink()
                    || !meta.is_dir()
                    || meta.uid() != effective_uid().unwrap_or(u32::MAX)
                {
                    return Err(format!(
                        "run state dir {} is symlinked or foreign-owned; refusing",
                        dir.display()
                    ));
                }
            }
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .map_err(|err| format!("cannot create the state dir {}: {err}", dir.display()))?;
            Ok((dir, lock))
        }

        fn new(run_id: String) -> Self {
            let binary = std::env::var("WSSP_INCUS_BINARY").unwrap_or_else(|_| "incus".to_string());
            let image =
                std::env::var("WSSP_INCUS_IMAGE").unwrap_or_else(|_| IMAGE_DEFAULT.to_string());
            Self::with(binary, image, run_id)
        }

        fn with(binary: String, image: String, run_id: String) -> Self {
            // Placeholder ONLY: `claimed` replaces this with the canonical
            // run-id state dir. No directory is created here — an abandoned
            // pid-suffixed scratch dir would survive every invocation,
            // including a refused concurrent claim.
            let state_dir = std::env::temp_dir().join(format!(
                "wssp-surface-state-{run_id}-{}",
                std::process::id()
            ));
            Self {
                binary,
                image,
                prefix: format!("wssp-sbx-s{run_id}"),
                probe_project: format!("{PROJECT_PROBE_PREFIX}-{run_id}"),
                state_dir,
                run_id,
                run_lock: None,
                owns_probe_project: false,
                report: Report::new(),
            }
        }

        /// A runtime whose durable network state stays inside this run's
        /// scratch state dir.
        fn runtime(&self, project: &str) -> Result<IncusKvmRuntime, String> {
            let mut runtime = IncusKvmRuntime::new(IncusConfig {
                binary: self.binary.clone(),
                project: project.to_string(),
            })
            .map_err(|err| err.to_string())?;
            runtime.set_host_state_dir(self.state_dir.clone());
            if project != "default" {
                // The ephemeral-project probe path is not yet operator-qualified.
                // See docs/operations/host-isolation-qualification.md. Explicit
                // operator cleanup must leave the project empty for deletion.
                return Ok(runtime);
            }
            let (_, pool_name) = runtime
                .client()
                .profile_root_device(
                    sandbox_protocol::VmSize::defaults().map_err(|err| err.to_string())?,
                )
                .map_err(|err| err.to_string())?;
            // Explicitly invoked surface only: the marker is retained and is
            // never a sandbox root or a cleanup target.
            let pool = runtime
                .initialize_storage_pool(&pool_name, None)
                .map_err(|err| err.to_string())?;
            runtime
                .with_root_disk(&sandbox_runtime::RootDisk {
                    pool,
                    disk_gi_b: sandbox_protocol::vm_size_limits()
                        .map_err(|err| err.to_string())?
                        .disk_gi_b_default,
                })
                .map_err(|err| err.to_string())
        }

        fn instance(&self, suffix: &str) -> String {
            format!("{}-{}", self.prefix, suffix)
        }

        fn sandbox_id(&self, suffix: &str) -> String {
            self.instance(suffix)
                .trim_start_matches("wssp-sbx-")
                .to_string()
        }

        /// Force-deletes `<prefix>-<suffix>` only when its sandbox-id metadata is
        /// this run's id for that suffix; anything else is left alone.
        fn delete_owned(&self, project: &str, suffix: &str) -> Result<(), String> {
            let name = self.instance(suffix);
            // The ownership probe must not suppress errors: transport or
            // permission failure is not "unowned" (which would silently skip
            // — leak — this run's own VM).
            let owned = match self.raw(Some(project), &["config", "get", &name, META_SANDBOX]) {
                Ok(out) if out.status.success() => {
                    String::from_utf8_lossy(&out.stdout).trim() == self.sandbox_id(suffix)
                }
                Ok(out) if Self::is_not_found(&out, &Self::instance_not_found(&name, project)) => {
                    false
                }
                Ok(out) => {
                    return Err(format!(
                        "ownership probe {name}: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
                Err(err) => return Err(format!("ownership probe {name}: {err}")),
            };
            if owned {
                let out = self
                    .raw(Some(project), &["delete", &name, "--force"])
                    .map_err(|err| format!("delete {name} --force: {err}"))?;
                if !out.status.success() {
                    eprintln!(
                        "incus-surface cleanup: delete {name}: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                // Absence verification IS the failure propagation: any failed
                // or silently incomplete delete leaves the instance, which
                // this probe catches — and the network teardown below can
                // succeed without the VM referencing the managed bridge, so
                // command status alone would let the VM escape detection.
                // An unverifiable probe fails closed.
                let absent = Self::instance_not_found(&name, project);
                match self.raw(Some(project), &["config", "get", &name, META_SANDBOX]) {
                    Ok(probe) if Self::is_not_found(&probe, &absent) => {}
                    Ok(probe) if probe.status.success() => {
                        return Err(format!("instance {name} survived deletion"));
                    }
                    Ok(probe) => {
                        return Err(format!(
                            "cannot verify {name} absence: {}",
                            String::from_utf8_lossy(&probe.stderr).trim()
                        ));
                    }
                    Err(err) => {
                        return Err(format!("cannot verify {name} absence: {err}"));
                    }
                }
            }
            // The probe applies the bridge + ACL BEFORE the VM exists, so a
            // partially completed launch still leaves this run's network
            // resources behind. Remove them (tag- and project-fenced, never
            // another run's or project's objects) and verify absence.
            let mut client = self.client(project);
            client.set_host_state_dir(self.state_dir.clone());
            // Teardown failure is a RESULT, not a log line: the owned
            // bridge/ACL may remain, and the caller must keep the state
            // directory (the newly journaled obligation lives there) and
            // report failure.
            client
                .teardown_owned_sandbox_network(&self.sandbox_id(suffix))
                .map_err(|err| format!("network teardown for {}: {err}", self.sandbox_id(suffix)))
        }

        fn client(&self, project: &str) -> IncusClient {
            IncusClient::new(self.binary.clone(), project.to_string())
        }

        fn raw(&self, project: Option<&str>, args: &[&str]) -> Result<Output, String> {
            let mut cmd = sandbox_runtime::host_child_command(
                &self.binary,
                sandbox_runtime::HostChildEnvironment::Incus,
            );
            cmd.env("LC_ALL", "C");
            if let Some(project) = project {
                cmd.arg("--project").arg(project);
            }
            cmd.args(args);
            cmd.output().map_err(|err| format!("spawn incus: {err}"))
        }

        /// Absence evidence is ONLY the probed object's explicit not-found
        /// response, matched EXACTLY (real Incus 6.0, verified against the
        /// installed CLI):
        ///   `incus config get <vm> <key>` →
        ///     `Error: Failed to fetch instance "<vm>" in project "<p>": Instance not found`
        ///   `incus project show <p>` → `Error: Project not found`
        /// Any other output — daemon unreachable, permission denied, or an
        /// unrelated diagnostic that merely MENTIONS "not found" — is a
        /// failure, never proof of absence.
        fn is_not_found(out: &Output, expected: &str) -> bool {
            !out.status.success() && String::from_utf8_lossy(&out.stderr).trim() == expected
        }

        /// The exact not-found response for a `config get` on `name`.
        fn instance_not_found(name: &str, project: &str) -> String {
            format!(
                "Error: Failed to fetch instance \"{name}\" in project \"{project}\": Instance not found"
            )
        }

        fn raw_ok(&self, project: Option<&str>, args: &[&str]) -> Result<String, String> {
            let out = self.raw(project, args)?;
            if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            } else {
                Err(format!(
                    "incus {args:?} exit {}: {}",
                    out.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&out.stderr).trim()
                ))
            }
        }

        /// Returns 0 on success, 1 when any owned resource could not be
        /// torn down. While obligations remain, the state directory is
        /// PRESERVED: it holds the durable cleanup journal the drain needs
        /// (reconstruction deliberately excludes marked orphans).
        fn cleanup(&self) -> i32 {
            let mut failed = false;
            for suffix in ["a", "b", "fork"] {
                if let Err(err) = self.delete_owned("default", suffix) {
                    eprintln!("incus-surface cleanup: {err}");
                    failed = true;
                }
            }
            // Never delete images here: the probe project is created with
            // features.images=false, so its image list is the default project's
            // (including the harness's own base image).
            if self.owns_probe_project {
                if let Err(err) = self.delete_owned(&self.probe_project, "p") {
                    eprintln!("incus-surface cleanup: {err}");
                    failed = true;
                }
                // Incus refuses this while anything is left inside the project.
                match self.raw(None, &["project", "delete", &self.probe_project]) {
                    Ok(out) => {
                        if !out.status.success() {
                            eprintln!(
                                "incus-surface cleanup: project delete {}: {}",
                                self.probe_project,
                                String::from_utf8_lossy(&out.stderr).trim()
                            );
                        }
                        // Absence verification IS the failure propagation: a
                        // failed or silently incomplete delete leaves the
                        // project, which this probe catches; an unverifiable
                        // probe fails closed.
                        match self.raw(None, &["project", "show", &self.probe_project]) {
                            Ok(probe) if Self::is_not_found(&probe, "Error: Project not found") => {
                            }
                            Ok(probe) if !probe.status.success() => {
                                eprintln!(
                                    "incus-surface cleanup: cannot verify project {} absence: {}",
                                    self.probe_project,
                                    String::from_utf8_lossy(&probe.stderr).trim()
                                );
                                failed = true;
                            }
                            Ok(_) => {
                                eprintln!(
                                    "incus-surface cleanup: project {} survived deletion",
                                    self.probe_project
                                );
                                failed = true;
                            }
                            Err(err) => {
                                eprintln!(
                                    "incus-surface cleanup: cannot verify project {} absence: {err}",
                                    self.probe_project
                                );
                                failed = true;
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("incus-surface cleanup: project delete: {err}");
                        failed = true;
                    }
                }
            }
            if !failed && let Err(err) = std::fs::remove_dir_all(&self.state_dir) {
                eprintln!(
                    "incus-surface cleanup: cannot remove the state journal dir {}: {err}",
                    self.state_dir.display()
                );
                failed = true;
            }
            if failed { 1 } else { 0 }
        }
    }

    fn random_run_id() -> Result<String, String> {
        let mut bytes = [0u8; 6];
        getrandom::fill(&mut bytes).map_err(|err| format!("OS CSPRNG: {err}"))?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    fn valid_run_id(id: &str) -> bool {
        id.len() == 12 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    pub fn test_all() -> i32 {
        let run_id = match random_run_id() {
            Ok(id) => id,
            Err(err) => {
                eprintln!("incus-surface: {err}");
                return 2;
            }
        };
        let mut h = match Harness::claimed(run_id) {
            Ok(h) => h,
            Err(err) => {
                eprintln!("incus-surface: {err}");
                return 2;
            }
        };
        println!(
            "run id {} (manual cleanup: incus-surface cleanup {})",
            h.run_id, h.run_id
        );
        if !h.claim_probe_project() {
            eprintln!(
                "incus-surface: probe project `{}` exists or cannot be checked; refusing to run",
                h.probe_project
            );
            return 2;
        }
        let mut cleanup_failed = h.cleanup() != 0;
        run_preflight(&mut h);
        run_project_surface(&mut h);
        run_runtime_lifecycle(&mut h);
        run_error_paths(&mut h);
        run_naming(&mut h);
        cleanup_failed |= h.cleanup() != 0;
        let code = h.report.print();
        if cleanup_failed {
            eprintln!(
                "incus-surface: cleanup left obligations behind; the state journal is preserved for the drain"
            );
            1
        } else {
            code
        }
    }

    pub fn cleanup_only(run_id: Option<&str>) -> i32 {
        let Some(run_id) = run_id.filter(|id| valid_run_id(id)) else {
            eprintln!("usage: incus-surface cleanup <12-hex run id printed by test-all>");
            return 2;
        };
        let h = match Harness::claimed_for_cleanup(run_id.to_string()) {
            Ok(h) => h,
            Err(err) => {
                eprintln!("incus-surface cleanup: {err}");
                return 2;
            }
        };
        let code = h.cleanup();
        if code == 0 {
            println!(
                "cleaned `{}` and owned `{}-*` instances of run {run_id}",
                h.probe_project, h.prefix
            );
        } else {
            eprintln!(
                "incus-surface cleanup: one or more owned resources of run {run_id} could not be removed; the state journal is preserved for the drain"
            );
        }
        code
    }

    fn run_preflight(h: &mut Harness) {
        let client = h.client("default");
        match client.ping() {
            Ok(_) => h.report.pass("client.ping / incus version"),
            Err(err) => h
                .report
                .fail("client.ping / incus version", err.to_string()),
        }

        match client.ensure_project() {
            Ok(_) => h.report.pass("client.ensure_project default is a no-op"),
            Err(err) => h
                .report
                .fail("client.ensure_project default is a no-op", err.to_string()),
        }

        match client.list_instances() {
            Ok(rows) => h.report.check(
                "client.list_instances parses JSON",
                true,
                format!("{} existing instances", rows.len()),
            ),
            Err(err) => h
                .report
                .fail("client.list_instances parses JSON", err.to_string()),
        }

        match client.instance_exists("wssp-sbx-missing0") {
            Ok(false) => h.report.pass("client.instance_exists missing → false"),
            Ok(true) => h
                .report
                .fail("client.instance_exists missing → false", "reported true"),
            Err(err) => h
                .report
                .fail("client.instance_exists missing → false", err.to_string()),
        }

        match h.runtime("default") {
            Ok(runtime) => match runtime.count_managed_vms() {
                Ok(_) => h.report.pass("runtime.new + count_managed_vms"),
                Err(err) => h
                    .report
                    .fail("runtime.new + count_managed_vms", err.to_string()),
            },
            Err(err) => h
                .report
                .fail("runtime.new + count_managed_vms", err.to_string()),
        }
    }

    fn run_project_surface(h: &mut Harness) {
        match h.raw(Some(h.probe_project.as_str()), &["version"]) {
            Ok(out) if out.status.success() => {
                h.report.pass("incus --project <missing> version succeeds");
            }
            Ok(out) => h.report.fail(
                "incus --project <missing> version succeeds",
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ),
            Err(err) => h
                .report
                .fail("incus --project <missing> version succeeds", err),
        }

        match h.raw(
            Some(h.probe_project.as_str()),
            &["project", "list", "--format", "json"],
        ) {
            Ok(out) if out.status.success() => {
                h.report
                    .pass("incus --project <missing> project list succeeds");
            }
            Ok(out) => h.report.fail(
                "incus --project <missing> project list succeeds",
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ),
            Err(err) => h
                .report
                .fail("incus --project <missing> project list succeeds", err),
        }

        let client = h.client(&h.probe_project);
        match client.ensure_project() {
            Ok(_) => h
                .report
                .pass("client.ensure_project creates a missing project"),
            Err(err) => h.report.fail(
                "client.ensure_project creates a missing project",
                err.to_string(),
            ),
        }

        match client.ensure_project() {
            Ok(_) => h
                .report
                .pass("client.ensure_project is idempotent for an existing project"),
            Err(err) => h.report.fail(
                "client.ensure_project is idempotent for an existing project",
                err.to_string(),
            ),
        }

        match h.runtime(&h.probe_project.clone()) {
            Ok(_) => h.report.pass("runtime.new against a non-default project"),
            Err(err) => h
                .report
                .fail("runtime.new against a non-default project", err.to_string()),
        }

        match h.raw_ok(
            Some(h.probe_project.as_str()),
            &["profile", "show", "default"],
        ) {
            Ok(yaml) => {
                h.report.check(
                    "ensure_project adds a root disk and NIC to a new project",
                    yaml.contains("pool:") && yaml.contains("network:"),
                    yaml.trim().to_string(),
                );
            }
            Err(err) => h.report.fail(
                "ensure_project adds a root disk and NIC to a new project",
                err,
            ),
        }

        let probe_name = h.instance("p");
        match client.resolve_image_ref(&h.image).and_then(|image| {
            let runtime = h.runtime(&h.probe_project).map_err(|err| {
                sandbox_runtime::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::Internal,
                    err,
                )
            })?;
            runtime
                .create_sandbox(&CreateSandboxRequest {
                    refused_dns_hints: false,
                    first_attempt: false,
                    vm_size: sandbox_protocol::VmSize {
                        cpu_count: 1,
                        memory_mi_b: 1024,
                    },
                    lease: sandbox_protocol::HostLease::for_test(),
                    sandbox_id: h.sandbox_id("p"),
                    instance_name: probe_name.clone(),
                    idempotency_key: "surface-project".into(),
                    template_digest: image.fingerprint.clone(),
                    incus_fingerprint: Some(image.fingerprint.clone()),
                    architecture: Some(image.architecture.clone()),
                    guest: GuestIdentity::default(),
                    egress_policy: None,
                    egress_policy_hash: None,
                    egress_settings: sandbox_runtime::egress::EgressSettings::default(),
                    egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
                    guest_privilege: Default::default(),
                    readiness: Default::default(),
                    restore: None,
                })
                .map(|_| ())
                .map_err(sandbox_runtime::EffectError::into_error)
        }) {
            Ok(()) => h.report.pass("launch pinned VM image in ensured project"),
            Err(error) => h.report.fail(
                "launch pinned VM image in ensured project",
                error.to_string(),
            ),
        }

        let project = h.probe_project.clone();
        if let Err(err) = h.delete_owned(&project, "p") {
            h.report.fail("probe project instance teardown", err);
        }
    }

    fn run_runtime_lifecycle(h: &mut Harness) {
        let name = h.instance("a");
        let sandbox_id = h.sandbox_id("a");
        let key = format!("create-{sandbox_id}");
        let runtime = match h.runtime("default") {
            Ok(runtime) => runtime,
            Err(err) => {
                h.report
                    .fail("lifecycle: runtime.new default", err.to_string());
                return;
            }
        };

        let image = match runtime.resolve_image_ref(&h.image) {
            Ok(image) => image,
            Err(error) => {
                h.report
                    .fail("resolve host-local VM image", error.to_string());
                return;
            }
        };
        let created = runtime.create_sandbox(&CreateSandboxRequest {
            refused_dns_hints: false,
            first_attempt: false,
            vm_size: sandbox_protocol::VmSize {
                cpu_count: 1,
                memory_mi_b: 1024,
            },
            lease: sandbox_protocol::HostLease::for_test(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            idempotency_key: key.clone(),
            template_digest: image.fingerprint.clone(),
            incus_fingerprint: Some(image.fingerprint.clone()),
            guest: GuestIdentity::default(),
            architecture: Some(image.architecture.clone()),
            egress_policy: None,
            egress_policy_hash: None,
            egress_settings: sandbox_runtime::egress::EgressSettings::default(),
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_privilege: Default::default(),
            readiness: Default::default(),
            restore: None,
        });
        match created {
            Ok(resp) => {
                h.report.check(
                    "runtime.create_sandbox launches a VM and returns Ready",
                    resp.sandbox.state == SandboxLifecycleState::Ready,
                    format!("state={:?}", resp.sandbox.state),
                );
            }
            Err(err) => {
                h.report.fail(
                    "runtime.create_sandbox launches a VM and returns Ready",
                    err.to_string(),
                );
                return;
            }
        }

        let client = h.client("default");
        match client.instance_exists(&name) {
            Ok(true) => h.report.pass("client.instance_exists after create"),
            Ok(false) => h
                .report
                .fail("client.instance_exists after create", "missing"),
            Err(err) => h
                .report
                .fail("client.instance_exists after create", err.to_string()),
        }

        match client.list_instances() {
            Ok(rows) => {
                let found = rows.iter().find(|row| row.name == name);
                match found {
                    Some(row) => {
                        h.report.check(
                            "list marks the instance as virtual-machine",
                            row.instance_type == "virtual-machine",
                            format!("type={}", row.instance_type),
                        );
                        h.report.check(
                            "list reports Running after launch",
                            row.status.eq_ignore_ascii_case("running"),
                            format!("status={}", row.status),
                        );
                    }
                    None => {
                        h.report
                            .fail("list marks the instance as virtual-machine", "not listed");
                        h.report
                            .fail("list reports Running after launch", "not listed");
                    }
                }
            }
            Err(err) => {
                h.report.fail(
                    "list marks the instance as virtual-machine",
                    err.to_string(),
                );
                h.report
                    .fail("list reports Running after launch", err.to_string());
            }
        }

        match runtime.count_managed_vms() {
            Ok(count) => h.report.check(
                "count_managed_vms includes the created VM",
                count >= 1,
                format!("count={count}"),
            ),
            Err(err) => h
                .report
                .fail("count_managed_vms includes the created VM", err.to_string()),
        }

        let before_untag = runtime.count_managed_vms().unwrap_or(0);
        let _ = h.raw(Some("default"), &["config", "unset", &name, META_SANDBOX]);
        // The untagged VM no longer counts as a VM, but its owned bridge/ACL
        // are outstanding network evidence: the census re-journals the legacy
        // pair and reports the sandbox as Provisioning. Capacity is RETAINED
        // until teardown evidence completes — it must never be released early.
        match runtime.sandbox_inventory() {
            Ok(inventory) => {
                let retained = inventory.iter().any(|entry| {
                    entry.sandbox_id == sandbox_id
                        && entry.state == SandboxLifecycleState::Provisioning
                });
                h.report.check(
                    "untagged VM retains capacity while its networking is outstanding",
                    retained && inventory.len() as u32 == before_untag,
                    format!("before={before_untag} inventory={inventory:?}"),
                );
            }
            Err(err) => h.report.fail(
                "untagged VM retains capacity while its networking is outstanding",
                err.to_string(),
            ),
        }
        let _ = h.raw(
            Some("default"),
            &["config", "set", &name, META_SANDBOX, &sandbox_id],
        );

        let fingerprint = image.fingerprint.clone();
        let bound = match client.bind_instance(&name, &sandbox_id, &fingerprint, None) {
            Ok(bound) => bound,
            Err(err) => {
                h.report.fail("bind physical instance", err.to_string());
                return;
            }
        };
        assert_meta(
            h,
            &client,
            &bound,
            "metadata sandbox_id",
            META_SANDBOX,
            &sandbox_id,
        );
        assert_meta(
            h,
            &client,
            &bound,
            "metadata idempotency key",
            META_KEY,
            &key,
        );
        assert_meta(
            h,
            &client,
            &bound,
            "metadata template digest",
            META_TEMPLATE,
            &fingerprint,
        );

        let immediate = runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-immediate".to_string(),
            idempotency_key: "cmd-immediate".to_string(),
            argv: vec!["true".to_string()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        });
        match immediate {
            Ok(resp) if resp.command.exit_code == Some(0) => {
                h.report
                    .pass("run_command immediately after create (agent already ready)");
            }
            Ok(resp) => h.report.fail(
                "run_command immediately after create (guest agent race)",
                format!(
                    "create returns Ready while the guest agent is still booting; exec exit={:?}. wssp treats this as a failed command, not GuestUnavailable",
                    resp.command.exit_code
                ),
            ),
            Err(err) => h.report.fail(
                "run_command immediately after create (guest agent race)",
                format!("create returns Ready before the Incus VM agent is reachable: {err}"),
            ),
        }

        match wait_for_exec(&client, &bound, Duration::from_secs(120)) {
            Ok(elapsed) => h.report.check(
                "incus exec becomes ready after launch",
                true,
                format!("ready in {elapsed:?}"),
            ),
            Err(err) => {
                h.report.fail("incus exec becomes ready after launch", err);
                return;
            }
        }

        let echo = runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-echo".to_string(),
            idempotency_key: "cmd-echo".to_string(),
            argv: vec!["echo".to_string(), "wssp-surface".to_string()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        });
        match echo {
            Ok(resp) => {
                let stdout = stdout_text(&resp.command.chunks);
                h.report.check(
                    "run_command captures stdout from incus exec -T",
                    resp.command.exit_code == Some(0) && stdout.contains("wssp-surface"),
                    format!("exit={:?} stdout={stdout:?}", resp.command.exit_code),
                );
                h.report.check(
                    "run_command success maps to Succeeded",
                    resp.command.state == OperationState::Succeeded,
                    format!("state={:?}", resp.command.state),
                );
            }
            Err(err) => {
                h.report.fail(
                    "run_command captures stdout from incus exec -T",
                    err.to_string(),
                );
                h.report
                    .fail("run_command success maps to Succeeded", err.to_string());
            }
        }

        let fail_cmd = runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-fail".to_string(),
            idempotency_key: format!("cmd-fail-{}", std::process::id()),
            argv: vec!["/bin/sh".to_string(), "-c".to_string(), "false".to_string()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        });
        match fail_cmd {
            Ok(resp) => {
                h.report.check(
                    "run_command preserves a non-zero guest exit code",
                    resp.command.exit_code == Some(1),
                    format!("exit={:?}", resp.command.exit_code),
                );
                // A completed command is SUCCEEDED; its exit code carries the
                // guest result (only lifecycle/evidence failures are FAILED).
                h.report.check(
                    "run_command non-zero is a completed Succeeded record (not an API error)",
                    resp.command.state == OperationState::Succeeded,
                    format!("state={:?}", resp.command.state),
                );
            }
            Err(err) => {
                h.report.fail(
                    "run_command preserves a non-zero guest exit code",
                    err.to_string(),
                );
                h.report.fail(
                    "run_command non-zero is a completed Succeeded record (not an API error)",
                    err.to_string(),
                );
            }
        }

        match runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-stderr".to_string(),
            idempotency_key: "cmd-stderr".to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf err >&2".to_string(),
            ],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        }) {
            Ok(resp) => {
                let stderr = stderr_text(&resp.command.chunks);
                h.report.check(
                    "run_command captures stderr",
                    stderr.contains("err"),
                    format!("stderr={stderr:?}"),
                );
            }
            Err(err) => h
                .report
                .fail("run_command captures stderr", err.to_string()),
        }

        let first = runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-idemp".to_string(),
            idempotency_key: "cmd-idemp".to_string(),
            argv: vec!["echo".to_string(), "first".to_string()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        });
        let second = runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-idemp-2".to_string(),
            idempotency_key: "cmd-idemp".to_string(),
            argv: vec!["echo".to_string(), "second".to_string()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        });
        match (first, second) {
            (Ok(a), Ok(b)) => {
                let a_out = stdout_text(&a.command.chunks);
                let b_out = stdout_text(&b.command.chunks);
                // Command idempotency lives in the host journal (C09); the
                // runtime itself executes every call it is given.
                h.report.check(
                    "run_command has no runtime-level result cache (host journal owns receipts)",
                    a_out.contains("first") && b_out.contains("second"),
                    format!("first={a_out:?} second={b_out:?}"),
                );
            }
            (Err(err), _) | (_, Err(err)) => h.report.fail(
                "run_command has no runtime-level result cache (host journal owns receipts)",
                err.to_string(),
            ),
        }

        match runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-empty-live".to_string(),
            idempotency_key: "cmd-empty-live".to_string(),
            argv: Vec::new(),
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        }) {
            Err(err) if err.code == SandboxErrorCode::ProtocolError => {
                h.report
                    .pass("run_command with empty argv on a live VM is ProtocolError");
            }
            Ok(_) => h.report.fail(
                "run_command with empty argv on a live VM is ProtocolError",
                "succeeded",
            ),
            Err(err) => h.report.fail(
                "run_command with empty argv on a live VM is ProtocolError",
                format!("expected ProtocolError, got {err}"),
            ),
        }

        let cwd_cmd = runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-cwd".to_string(),
            idempotency_key: "cmd-cwd".to_string(),
            argv: vec!["pwd".to_string()],
            script: None,
            cwd: Some("/tmp".to_string()),
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        });
        match cwd_cmd {
            Ok(resp) => {
                let stdout = stdout_text(&resp.command.chunks);
                h.report.check(
                    "run_command honors cwd via incus exec --cwd",
                    resp.command.exit_code == Some(0) && stdout.contains("/tmp"),
                    format!("exit={:?} stdout={stdout:?}", resp.command.exit_code),
                );
            }
            Err(err) => h.report.fail(
                "run_command honors cwd via incus exec --cwd",
                err.to_string(),
            ),
        }

        let timed_out = runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-timeout".to_string(),
            idempotency_key: "cmd-timeout".to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "sleep 30".to_string(),
            ],
            script: None,
            cwd: None,
            timeout_ms: Some(1500),
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        });
        // E-19: the deadline stop is proven (the helper signalled the running
        // command and saw its group gone), so the outcome is a completed
        // FAILED with the stable `timeout` code. An unprovable stop would stay
        // UNKNOWN_OUTCOME (shim test `g3_e19_unproven_deadline_stop_stays_unknown`).
        const TIMEOUT_CHECK: &str =
            "run_command timeout_ms ends as a typed timeout (Failed, timeout)";
        match timed_out {
            Err(err)
                if err.code == SandboxErrorCode::Timeout
                    && err.state() == OperationState::Failed =>
            {
                h.report.pass(TIMEOUT_CHECK);
            }
            Ok(resp) => h.report.fail(
                TIMEOUT_CHECK,
                format!(
                    "exit={:?} stderr={:?}",
                    resp.command.exit_code,
                    stderr_text(&resp.command.chunks)
                ),
            ),
            Err(err) => h.report.fail(
                TIMEOUT_CHECK,
                format!("expected a Failed timeout, got {:?}: {err}", err.state()),
            ),
        }
        check_no_guest_sleep(
            h,
            &runtime,
            &image.fingerprint,
            &sandbox_id,
            &name,
            "op-timeout-check",
            "sleep 30",
            "timed-out guest command does not survive the deadline",
        );

        match runtime.write_file(&WriteFileRequest {
            template_fingerprint: image.fingerprint.clone(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-write".to_string(),
            generation: 1,
            attempt: 1,
            idempotency_key: "file-write".to_string(),
            path: "/home/user/wssp-nested/dir/hello.txt".to_string(),
            bytes: sandbox_runtime::FileContent::from_bytes(b"hello-wssp\n").expect("file capture"),
            guest: GuestIdentity::default(),
        }) {
            Ok(resp) => h.report.check(
                "write_file creates parent dirs via incus file push -p",
                resp.bytes_written == 11,
                format!("bytes_written={}", resp.bytes_written),
            ),
            Err(err) => h.report.fail(
                "write_file creates parent dirs via incus file push -p",
                err.to_string(),
            ),
        }

        match runtime.read_file(&ReadFileRequest {
            sandbox_owner_id: "owner".into(),
            template_fingerprint: image.fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-read".to_string(),
            idempotency_key: "file-read".to_string(),
            path: "/home/user/wssp-nested/dir/hello.txt".to_string(),
        }) {
            Ok(resp) => h.report.check(
                "read_file returns the pushed text bytes",
                resp.bytes
                    .read_chunk(0, sandbox_runtime::FILE_CHUNK_BYTES)
                    .unwrap_or_default()
                    == b"hello-wssp\n",
                format!(
                    "{:?}",
                    String::from_utf8_lossy(
                        &resp
                            .bytes
                            .read_chunk(0, sandbox_runtime::FILE_CHUNK_BYTES)
                            .unwrap_or_default()
                    )
                ),
            ),
            Err(err) => h
                .report
                .fail("read_file returns the pushed text bytes", err.to_string()),
        }

        let blob = b"abc\x00def\xff".to_vec();
        match runtime.write_file(&WriteFileRequest {
            template_fingerprint: image.fingerprint.clone(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-bin-w".to_string(),
            generation: 1,
            attempt: 1,
            idempotency_key: "file-bin-w".to_string(),
            path: "/home/user/wssp-nested/blob.bin".to_string(),
            bytes: sandbox_runtime::FileContent::from_bytes(&(blob.clone())).expect("file capture"),
            guest: GuestIdentity::default(),
        }) {
            Ok(_) => match runtime.read_file(&ReadFileRequest {
                sandbox_owner_id: "owner".into(),
                template_fingerprint: image.fingerprint.clone(),
                guest: Default::default(),
                sandbox_id: sandbox_id.clone(),
                instance_name: name.clone(),
                operation_id: "op-bin-r".to_string(),
                idempotency_key: "file-bin-r".to_string(),
                path: "/home/user/wssp-nested/blob.bin".to_string(),
            }) {
                Ok(resp) => h.report.check(
                    "read_file/write_file preserve NUL and high bytes",
                    resp.bytes
                        .read_chunk(0, sandbox_runtime::FILE_CHUNK_BYTES)
                        .unwrap_or_default()
                        == blob,
                    format!("len={}", resp.bytes.len()),
                ),
                Err(err) => h.report.fail(
                    "read_file/write_file preserve NUL and high bytes",
                    err.to_string(),
                ),
            },
            Err(err) => h.report.fail(
                "read_file/write_file preserve NUL and high bytes",
                err.to_string(),
            ),
        }

        match runtime.read_file(&ReadFileRequest {
            sandbox_owner_id: "owner".into(),
            template_fingerprint: image.fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-missing".to_string(),
            idempotency_key: "file-missing".to_string(),
            path: "/home/user/does-not-exist".to_string(),
        }) {
            Err(err) if err.code == SandboxErrorCode::NotFound => {
                h.report.pass("read_file of a missing path is NotFound");
            }
            Ok(_) => h
                .report
                .fail("read_file of a missing path is NotFound", "succeeded"),
            Err(err) => h.report.fail(
                "read_file of a missing path is NotFound",
                format!("expected NotFound, got {err}"),
            ),
        }

        match runtime.read_file(&ReadFileRequest {
            sandbox_owner_id: "owner".into(),
            template_fingerprint: image.fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-dir".to_string(),
            idempotency_key: "file-dir".to_string(),
            path: "/home/user/wssp-nested".to_string(),
        }) {
            Err(err)
                if err.code == SandboxErrorCode::ProtocolError
                    && !err.message.contains("WSSP_") =>
            {
                h.report.pass("read_file of a directory is not a file");
            }
            Ok(_) => h
                .report
                .fail("read_file of a directory is not a file", "succeeded"),
            Err(err) => h.report.fail(
                "read_file of a directory is not a file",
                format!("unexpected {err}"),
            ),
        }

        match runtime.write_file(&WriteFileRequest {
            template_fingerprint: image.fingerprint.clone(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-dotdot".to_string(),
            generation: 1,
            attempt: 1,
            idempotency_key: "file-dotdot".to_string(),
            path: "/home/user/../etc/passwd".to_string(),
            bytes: sandbox_runtime::FileContent::from_bytes(b"nope").expect("file capture"),
            guest: GuestIdentity::default(),
        }) {
            Err(err) if err.code == SandboxErrorCode::ProtocolError => {
                h.report.pass("write_file rejects `..` in the guest path");
            }
            Ok(_) => h
                .report
                .fail("write_file rejects `..` in the guest path", "succeeded"),
            Err(err) => h.report.fail(
                "write_file rejects `..` in the guest path",
                format!("expected ProtocolError, got {err}"),
            ),
        }

        match runtime.stop_sandbox(&StopSandboxRequest {
            template_fingerprint: image.fingerprint.clone(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-stop".to_string(),
            idempotency_key: "stop-1".to_string(),
        }) {
            Ok(resp) => h.report.check(
                "stop_sandbox force-stops and keeps the instance",
                resp.sandbox.state == SandboxLifecycleState::Stopped,
                format!("state={:?}", resp.sandbox.state),
            ),
            Err(err) => h.report.fail(
                "stop_sandbox force-stops and keeps the instance",
                err.to_string(),
            ),
        }

        match runtime.reconnect_sandbox(&ReconnectSandboxRequest {
            vm_size: sandbox_protocol::VmSize {
                cpu_count: 1,
                memory_mi_b: 1024,
            },
            lease: sandbox_protocol::HostLease::for_test(),
            template_fingerprint: image.fingerprint.clone(),
            architecture: Some(image.architecture.clone()),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-re".to_string(),
            idempotency_key: "re-1".to_string(),
            egress_policy: None,
            egress_policy_hash: None,
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        }) {
            Ok(resp) => h.report.check(
                "reconnect_sandbox starts a stopped VM and waits for the agent",
                resp.sandbox.state == SandboxLifecycleState::Ready,
                format!("state={:?}", resp.sandbox.state),
            ),
            Err(err) => h.report.fail(
                "reconnect_sandbox starts a stopped VM and waits for the agent",
                err.to_string(),
            ),
        }

        match runtime.read_file(&ReadFileRequest {
            sandbox_owner_id: "owner".into(),
            template_fingerprint: image.fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-persist".to_string(),
            idempotency_key: "file-persist".to_string(),
            path: "/home/user/wssp-nested/dir/hello.txt".to_string(),
        }) {
            Ok(resp) => h.report.check(
                "files under /home/user survive stop + reconnect",
                resp.bytes
                    .read_chunk(0, sandbox_runtime::FILE_CHUNK_BYTES)
                    .unwrap_or_default()
                    == b"hello-wssp\n",
                format!(
                    "{:?}",
                    String::from_utf8_lossy(
                        &resp
                            .bytes
                            .read_chunk(0, sandbox_runtime::FILE_CHUNK_BYTES)
                            .unwrap_or_default()
                    )
                ),
            ),
            Err(err) => h.report.fail(
                "files under /home/user survive stop + reconnect",
                err.to_string(),
            ),
        }

        match runtime.mkdir(&MkdirRequest {
            template_fingerprint: image.fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-mkdir".to_string(),
            idempotency_key: "mkdir-1".to_string(),
            path: "/home/user/wssp-fs/empty".to_string(),
        }) {
            Ok(_) => h.report.pass("mkdir creates nested directories"),
            Err(err) => h
                .report
                .fail("mkdir creates nested directories", err.to_string()),
        }

        match runtime.stat_path(&StatPathRequest {
            template_fingerprint: image.fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-stat".to_string(),
            idempotency_key: "stat-1".to_string(),
            path: "/home/user/wssp-nested/dir/hello.txt".to_string(),
        }) {
            Ok(stat) => h.report.check(
                "stat_path reports a regular file",
                stat.r#type == GuestPathKind::File && stat.size == 11,
                format!("kind={:?} size={}", stat.r#type, stat.size),
            ),
            Err(err) => h
                .report
                .fail("stat_path reports a regular file", err.to_string()),
        }

        match runtime.list_dir(&ListDirRequest {
            template_fingerprint: image.fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-list".to_string(),
            idempotency_key: "list-1".to_string(),
            path: "/home/user/wssp-nested".to_string(),
            depth: 8,
            limit: 100,
            generation: 1,
            continuation: None,
        }) {
            Ok(list) => {
                let paths: Vec<_> = list.items.iter().map(|e| e.path.as_str()).collect();
                h.report.check(
                    "list_dir returns nested files via find",
                    paths.iter().any(|p| p.ends_with("/hello.txt")),
                    format!("{paths:?}"),
                );
            }
            Err(err) => h
                .report
                .fail("list_dir returns nested files via find", err.to_string()),
        }

        match runtime.move_path(&MovePathRequest {
            template_fingerprint: image.fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-mv".to_string(),
            idempotency_key: "mv-1".to_string(),
            from: "/home/user/wssp-nested/dir/hello.txt".to_string(),
            to: "/home/user/wssp-fs/hello-moved.txt".to_string(),
        }) {
            Ok(_) => match runtime.read_file(&ReadFileRequest {
                sandbox_owner_id: "owner".into(),
                template_fingerprint: image.fingerprint.clone(),
                guest: Default::default(),
                sandbox_id: sandbox_id.clone(),
                instance_name: name.clone(),
                operation_id: "op-mv-read".to_string(),
                idempotency_key: "mv-read".to_string(),
                path: "/home/user/wssp-fs/hello-moved.txt".to_string(),
            }) {
                Ok(resp)
                    if resp
                        .bytes
                        .read_chunk(0, sandbox_runtime::FILE_CHUNK_BYTES)
                        .unwrap_or_default()
                        == b"hello-wssp\n" =>
                {
                    h.report.pass("move_path relocates a file")
                }
                Ok(resp) => h.report.fail(
                    "move_path relocates a file",
                    format!(
                        "{:?}",
                        String::from_utf8_lossy(
                            &resp
                                .bytes
                                .read_chunk(0, sandbox_runtime::FILE_CHUNK_BYTES)
                                .unwrap_or_default()
                        )
                    ),
                ),
                Err(err) => h.report.fail("move_path relocates a file", err.to_string()),
            },
            Err(err) => h.report.fail("move_path relocates a file", err.to_string()),
        }

        match runtime.remove_path(&RemovePathRequest {
            template_fingerprint: image.fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-rmdir".to_string(),
            idempotency_key: "rmdir-1".to_string(),
            path: "/home/user/wssp-fs/empty".to_string(),
            recursive: false,
        }) {
            Ok(_) => h.report.pass("remove_path rmdir on an empty directory"),
            Err(err) => h
                .report
                .fail("remove_path rmdir on an empty directory", err.to_string()),
        }

        match runtime.remove_path(&RemovePathRequest {
            template_fingerprint: image.fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-rmrf".to_string(),
            idempotency_key: "rmrf-1".to_string(),
            path: "/home/user/wssp-nested".to_string(),
            recursive: true,
        }) {
            Ok(_) => h.report.pass("remove_path recursive deletes a tree"),
            Err(err) => h
                .report
                .fail("remove_path recursive deletes a tree", err.to_string()),
        }

        match runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-env".to_string(),
            idempotency_key: "cmd-env".to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf %s \"$WSSP_ENV\"".to_string(),
            ],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: vec![("WSSP_ENV".to_string(), "from-host".to_string())],
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        }) {
            Ok(resp) => {
                let stdout = stdout_text(&resp.command.chunks);
                h.report.check(
                    "run_command passes env via incus exec --env",
                    stdout.contains("from-host"),
                    format!("stdout={stdout:?}"),
                );
            }
            Err(err) => h.report.fail(
                "run_command passes env via incus exec --env",
                err.to_string(),
            ),
        }

        match runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-pid".to_string(),
            idempotency_key: "cmd-pid".to_string(),
            argv: vec!["true".to_string()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        }) {
            Ok(resp) => {
                let stderr = stderr_text(&resp.command.chunks);
                h.report.check(
                    "run_command result includes the guest PID",
                    resp.command.guest_pid.is_some(),
                    format!("pid={:?} stderr={stderr:?}", resp.command.guest_pid),
                );
                h.report.check(
                    "pid banner is stripped from command stderr",
                    !stderr.contains("WSSP_PID"),
                    format!("stderr={stderr:?}"),
                );
            }
            Err(err) => h
                .report
                .fail("run_command result includes the guest PID", err.to_string()),
        }

        {
            let supervisor = runtime.exec_supervisor();
            let cancel_req = RunCommandRequest {
                template_fingerprint: image.fingerprint.clone(),
                generation: 1,
                attempt: 1,
                sandbox_id: sandbox_id.clone(),
                instance_name: name.clone(),
                operation_id: "op-cancel-sleep".to_string(),
                idempotency_key: "cmd-cancel".to_string(),
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "sleep 60; printf done".to_string(),
                ],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: GuestIdentity::default(),
                build_step: None,
            };
            let run_handle = supervisor.clone();
            let join = thread::spawn(move || {
                let bound = run_handle.bind(&cancel_req)?;
                run_handle.run(&bound, &cancel_req)
            });
            let waited = Instant::now();
            while waited.elapsed() < Duration::from_secs(5)
                && supervisor.active_guest_pid("op-cancel-sleep").is_none()
            {
                thread::sleep(Duration::from_millis(20));
            }
            match runtime.cancel_operation("op-cancel-sleep") {
                Ok(_) => h
                    .report
                    .pass("cancel_operation signals the guest process group"),
                Err(err) => h.report.fail(
                    "cancel_operation signals the guest process group",
                    err.to_string(),
                ),
            }
            // E-20: the command dies to the cancel's SIGTERM while running; the
            // wrapper's 143 frame after an attributed stop is the cancellation,
            // not a natural exit.
            const CANCEL_CHECK: &str = "TERM-cancelled run_command is Cancelled";
            match join.join() {
                Ok(Ok(resp)) => {
                    h.report.check(
                        CANCEL_CHECK,
                        resp.command.state == OperationState::Cancelled,
                        format!(
                            "state={:?} exit={:?}",
                            resp.command.state, resp.command.exit_code
                        ),
                    );
                    h.report.check(
                        "cancelled run_command reports the guest PID",
                        resp.command.guest_pid.is_some(),
                        format!("pid={:?}", resp.command.guest_pid),
                    );
                }
                Ok(Err(err)) => h.report.fail(CANCEL_CHECK, err.to_string()),
                Err(_) => h.report.fail(CANCEL_CHECK, "join panicked"),
            }
            match runtime.run_command(&RunCommandRequest {
                template_fingerprint: image.fingerprint.clone(),
                generation: 1,
                attempt: 1,
                sandbox_id: sandbox_id.clone(),
                instance_name: name.clone(),
                operation_id: "op-cancel-check".to_string(),
                idempotency_key: "cmd-cancel-check".to_string(),
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "pgrep -x sleep >/dev/null && echo live || echo dead".to_string(),
                ],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: GuestIdentity::default(),
                build_step: None,
            }) {
                Ok(resp) => {
                    let stdout = stdout_text(&resp.command.chunks);
                    h.report.check(
                        "guest sleep does not survive process-group cancel",
                        stdout.contains("dead"),
                        format!("stdout={stdout:?}"),
                    );
                }
                Err(err) => h.report.fail(
                    "guest sleep does not survive process-group cancel",
                    err.to_string(),
                ),
            }
        }

        {
            // A command that ignores SIGTERM is escalated to SIGKILL; with the
            // wrapper killed and the group gone, the result is CANCELLED.
            let supervisor = runtime.exec_supervisor();
            // WSSP_PID precedes the user shell's `trap`, so cancel only after the
            // command itself reports that TERM is ignored.
            let armed = format!("/tmp/wssp-term-armed-{}", h.run_id);
            let _ = client.exec_argv(&bound, &["rm".into(), "-f".into(), armed.clone()]);
            let cancel_req = RunCommandRequest {
                template_fingerprint: image.fingerprint.clone(),
                generation: 1,
                attempt: 1,
                sandbox_id: sandbox_id.clone(),
                instance_name: name.clone(),
                operation_id: "op-cancel-kill".to_string(),
                idempotency_key: "cmd-cancel-kill".to_string(),
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "trap '' TERM; : > \"$1\"; sleep 61".to_string(),
                    "wssp-term".to_string(),
                    armed.clone(),
                ],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: GuestIdentity::default(),
                build_step: None,
            };
            let run_handle = supervisor.clone();
            let join = thread::spawn(move || {
                let bound = run_handle.bind(&cancel_req)?;
                run_handle.run(&bound, &cancel_req)
            });
            let waited = Instant::now();
            let mut is_armed = false;
            while waited.elapsed() < Duration::from_secs(20) {
                is_armed = client
                    .exec_argv(&bound, &["test".into(), "-e".into(), armed.clone()])
                    .is_ok_and(|out| out.exit_code == 0);
                if is_armed {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            if !is_armed {
                h.report.fail(
                    "TERM-ignoring guest command armed its trap before cancel",
                    format!("no `{armed}` marker after {:?}", waited.elapsed()),
                );
            }
            let _ = runtime.cancel_operation("op-cancel-kill");
            match join.join() {
                Ok(Ok(resp)) => h.report.check(
                    "TERM-ignoring cancelled run_command escalates to Cancelled",
                    resp.command.state == OperationState::Cancelled,
                    format!(
                        "state={:?} exit={:?}",
                        resp.command.state, resp.command.exit_code
                    ),
                ),
                Ok(Err(err)) => h.report.fail(
                    "TERM-ignoring cancelled run_command escalates to Cancelled",
                    err.to_string(),
                ),
                Err(_) => h.report.fail(
                    "TERM-ignoring cancelled run_command escalates to Cancelled",
                    "join panicked",
                ),
            }
            check_no_guest_sleep(
                h,
                &runtime,
                &image.fingerprint,
                &sandbox_id,
                &name,
                "op-cancel-kill-check",
                "sleep 61",
                "TERM-ignoring guest command does not survive cancel",
            );
            let _ = client.exec_argv(&bound, &["rm".into(), "-f".into(), armed]);
        }

        {
            let supervisor = runtime.exec_supervisor();
            let sleep_req = RunCommandRequest {
                template_fingerprint: image.fingerprint.clone(),
                generation: 1,
                attempt: 1,
                sandbox_id: sandbox_id.clone(),
                instance_name: name.clone(),
                operation_id: "op-list-sleep".to_string(),
                idempotency_key: "cmd-list-sleep".to_string(),
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "sleep 60".to_string(),
                ],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: GuestIdentity::default(),
                build_step: None,
            };
            let run_handle = supervisor.clone();
            let join = thread::spawn(move || {
                let bound = run_handle.bind(&sleep_req)?;
                run_handle.run(&bound, &sleep_req)
            });
            let waited = Instant::now();
            while waited.elapsed() < Duration::from_secs(5)
                && supervisor.active_guest_pid("op-list-sleep").is_none()
            {
                thread::sleep(Duration::from_millis(20));
            }
            match runtime.list_processes(&ListProcessesRequest {
                sandbox_id: sandbox_id.clone(),
                instance_name: name.clone(),
                operation_id: "op-list".to_string(),
                idempotency_key: "list-1".to_string(),
            }) {
                Ok(list) => {
                    let found = list
                        .processes
                        .iter()
                        .find(|p| p.operation_id == "op-list-sleep");
                    h.report.check(
                        "list_processes includes started commands",
                        found.is_some_and(|p| p.argv.iter().any(|arg| arg.contains("sleep"))),
                        format!("processes={:?}", list.processes),
                    );
                    match found {
                        Some(process) => match runtime.signal_process(&SignalProcessRequest {
                            template_fingerprint: image.fingerprint.clone(),
                            guest: Default::default(),
                            sandbox_id: sandbox_id.clone(),
                            instance_name: name.clone(),
                            operation_id: "op-term".to_string(),
                            idempotency_key: "term-1".to_string(),
                            pid: process.pid,
                            signal: ProcessSignal::Sigterm,
                            target: Some(sandbox_runtime::SignalTarget {
                                target_operation_id: process.operation_id.clone(),
                                generation: 1,
                                attempt: 1,
                                pid: process.pid,
                            }),
                        }) {
                            Ok(_) => h
                                .report
                                .pass("signal_process SIGTERM targets the guest pid"),
                            other => h.report.fail(
                                "signal_process SIGTERM targets the guest pid",
                                format!("{:?}", other.map(|_| ()).map_err(|e| e.code)),
                            ),
                        },
                        None => h.report.fail(
                            "signal_process SIGTERM targets the guest pid",
                            "started sleep was not listed",
                        ),
                    }
                }
                Err(err) => h
                    .report
                    .fail("list_processes includes started commands", err.to_string()),
            }
            match join.join() {
                Ok(Ok(_)) => h.report.pass("SIGTERM completes the tracked run_command"),
                Ok(Err(err)) => h
                    .report
                    .fail("SIGTERM completes the tracked run_command", err.to_string()),
                Err(_) => h
                    .report
                    .fail("SIGTERM completes the tracked run_command", "join panicked"),
            }
        }

        {
            let supervisor = runtime.exec_supervisor();
            let sleep_req = RunCommandRequest {
                template_fingerprint: image.fingerprint.clone(),
                generation: 1,
                attempt: 1,
                sandbox_id: sandbox_id.clone(),
                instance_name: name.clone(),
                operation_id: "op-kill-sleep".to_string(),
                idempotency_key: "cmd-kill-sleep".to_string(),
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "sleep 60".to_string(),
                ],
                script: None,
                cwd: None,
                timeout_ms: None,
                env: Vec::new(),
                stdin: None,
                guest: GuestIdentity::default(),
                build_step: None,
            };
            let run_handle = supervisor.clone();
            let (kill_generation, kill_attempt) = (sleep_req.generation, sleep_req.attempt);
            let join = thread::spawn(move || {
                let bound = run_handle.bind(&sleep_req)?;
                run_handle.run(&bound, &sleep_req)
            });
            let waited = Instant::now();
            while waited.elapsed() < Duration::from_secs(5)
                && supervisor.active_guest_pid("op-kill-sleep").is_none()
            {
                thread::sleep(Duration::from_millis(20));
            }
            let pid = supervisor.active_guest_pid("op-kill-sleep");
            match pid {
                Some(pid) => match runtime.signal_process(&SignalProcessRequest {
                    template_fingerprint: image.fingerprint.clone(),
                    guest: Default::default(),
                    sandbox_id: sandbox_id.clone(),
                    instance_name: name.clone(),
                    operation_id: "op-kill".to_string(),
                    idempotency_key: "kill-1".to_string(),
                    pid,
                    signal: ProcessSignal::Sigkill,
                    target: Some(sandbox_runtime::SignalTarget {
                        target_operation_id: "op-kill-sleep".to_string(),
                        generation: kill_generation,
                        attempt: kill_attempt,
                        pid,
                    }),
                }) {
                    Ok(_) => h
                        .report
                        .pass("signal_process SIGKILL kills a tracked process group"),
                    Err(err) => h.report.fail(
                        "signal_process SIGKILL kills a tracked process group",
                        err.to_string(),
                    ),
                },
                None => h.report.fail(
                    "signal_process SIGKILL kills a tracked process group",
                    "guest pid never appeared",
                ),
            }
            // SIGKILL also kills the wrapper, so no exit frame exists and the
            // command can only settle as UNKNOWN_OUTCOME (C09 evidence rule).
            match join.join() {
                Ok(Err(err)) if err.code == SandboxErrorCode::UnknownOutcome => h
                    .report
                    .pass("SIGKILLed run_command settles UnknownOutcome (no exit frame)"),
                Ok(Ok(resp)) => h.report.fail(
                    "SIGKILLed run_command settles UnknownOutcome (no exit frame)",
                    format!(
                        "state={:?} exit={:?}",
                        resp.command.state, resp.command.exit_code
                    ),
                ),
                Ok(Err(err)) => h.report.fail(
                    "SIGKILLed run_command settles UnknownOutcome (no exit frame)",
                    err.to_string(),
                ),
                Err(_) => h.report.fail(
                    "SIGKILLed run_command settles UnknownOutcome (no exit frame)",
                    "join panicked",
                ),
            }
        }

        match runtime.run_command(&RunCommandRequest {
            template_fingerprint: image.fingerprint.clone(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-stdin".to_string(),
            idempotency_key: format!("cmd-stdin-cat-{}", std::process::id()),
            argv: vec!["/bin/sh".to_string(), "-c".to_string(), "cat".to_string()],
            script: None,
            cwd: None,
            timeout_ms: Some(10_000),
            env: Vec::new(),
            stdin: Some(b"hello-stdin\n".to_vec()),
            guest: GuestIdentity::default(),
            build_step: None,
        }) {
            Ok(resp) => {
                let stdout = stdout_text(&resp.command.chunks);
                h.report.check(
                    "run_command stdin is delivered to the guest",
                    stdout.contains("hello-stdin"),
                    format!("stdout={stdout:?}"),
                );
            }
            Err(err) => h.report.fail(
                "run_command stdin is delivered to the guest",
                err.to_string(),
            ),
        }

        {
            let supervisor = runtime.exec_supervisor();
            let cat_req = RunCommandRequest {
                template_fingerprint: image.fingerprint.clone(),
                generation: 1,
                attempt: 1,
                sandbox_id: sandbox_id.clone(),
                instance_name: name.clone(),
                operation_id: "op-stdin-live".to_string(),
                idempotency_key: format!("cmd-stdin-live-{}", std::process::id()),
                argv: vec!["/bin/sh".to_string(), "-c".to_string(), "cat".to_string()],
                script: None,
                cwd: None,
                timeout_ms: Some(10_000),
                env: Vec::new(),
                stdin: None,
                guest: GuestIdentity::default(),
                build_step: None,
            };
            match runtime.write_stdin(&WriteStdinRequest {
                operation_id: "op-stdin-live".to_string(),
                generation: 1,
                attempt: 1,
                bytes: b"live-stdin\n".to_vec(),
                eof: true,
            }) {
                Ok(_) => h
                    .report
                    .pass("write_stdin queues bytes for a starting command"),
                Err(err) => h.report.fail(
                    "write_stdin queues bytes for a starting command",
                    err.to_string(),
                ),
            }
            let run_handle = supervisor.clone();
            let join = thread::spawn(move || {
                let bound = run_handle.bind(&cat_req)?;
                run_handle.run(&bound, &cat_req)
            });
            match join.join() {
                Ok(Ok(resp)) => {
                    let stdout = stdout_text(&resp.command.chunks);
                    h.report.check(
                        "queued write_stdin is delivered when the command starts",
                        stdout.contains("live-stdin"),
                        format!("stdout={stdout:?} exit={:?}", resp.command.exit_code),
                    );
                }
                Ok(Err(err)) => h.report.fail(
                    "queued write_stdin is delivered when the command starts",
                    err.to_string(),
                ),
                Err(_) => h.report.fail(
                    "queued write_stdin is delivered when the command starts",
                    "join panicked",
                ),
            }
        }

        // C07: snapshot, restore and fork stay disabled fail-closed until
        // separately specified. Each entry point must refuse before any Incus
        // effect, so no snapshot or fork instance may appear.
        let snapshot = SnapshotRequest {
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-snap".to_string(),
            idempotency_key: "snap-1".to_string(),
            snapshot_name: "snap1".to_string(),
        };
        let unsupported = |result: Result<(), sandbox_runtime::EffectError>| match result {
            Err(err) if err.code == SandboxErrorCode::UnsupportedCapability => {
                (true, String::new())
            }
            Err(err) => (false, err.to_string()),
            Ok(()) => (false, "succeeded".to_string()),
        };
        let (ok, detail) = unsupported(runtime.create_snapshot(&snapshot).map(|_| ()));
        h.report
            .check("create_snapshot is UnsupportedCapability (C07)", ok, detail);
        let (ok, detail) = unsupported(runtime.restore_snapshot(&snapshot).map(|_| ()));
        h.report.check(
            "restore_snapshot is UnsupportedCapability (C07)",
            ok,
            detail,
        );
        let fork_name = h.instance("fork");
        let (ok, detail) = unsupported(
            runtime
                .fork_sandbox(&ForkSandboxRequest {
                    sandbox_id: sandbox_id.clone(),
                    instance_name: name.clone(),
                    dest_instance_name: fork_name.clone(),
                    operation_id: "op-fork".to_string(),
                    idempotency_key: "fork-1".to_string(),
                    snapshot_name: "snap1".to_string(),
                })
                .map(|_| ()),
        );
        h.report
            .check("fork_sandbox is UnsupportedCapability (C07)", ok, detail);
        let snapshots = h
            .raw_ok(
                Some("default"),
                &["snapshot", "list", &name, "--format", "csv"],
            )
            .unwrap_or_else(|err| err);
        h.report.check(
            "disabled snapshot entry points create no Incus snapshot",
            snapshots.trim().is_empty(),
            snapshots.trim().to_string(),
        );
        h.report.check(
            "disabled fork entry point creates no instance",
            matches!(client.instance_exists(&fork_name), Ok(false)),
            format!("{:?}", client.instance_exists(&fork_name)),
        );

        match runtime.create_sandbox(&CreateSandboxRequest {
            refused_dns_hints: false,
            first_attempt: false,
            vm_size: sandbox_protocol::VmSize {
                cpu_count: 1,
                memory_mi_b: 1024,
            },
            lease: sandbox_protocol::HostLease::for_test(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            idempotency_key: key.clone(),
            template_digest: image.fingerprint.clone(),
            incus_fingerprint: Some(image.fingerprint.clone()),
            guest: GuestIdentity::default(),
            architecture: Some(image.architecture.clone()),
            egress_policy: None,
            egress_policy_hash: None,
            egress_settings: sandbox_runtime::egress::EgressSettings::default(),
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_privilege: Default::default(),
            readiness: Default::default(),
            restore: None,
        }) {
            Ok(_) => h
                .report
                .pass("create_sandbox same name + same key is idempotent"),
            Err(err) => h.report.fail(
                "create_sandbox same name + same key is idempotent",
                err.to_string(),
            ),
        }

        match runtime.create_sandbox(&CreateSandboxRequest {
            refused_dns_hints: false,
            first_attempt: false,
            vm_size: sandbox_protocol::VmSize {
                cpu_count: 1,
                memory_mi_b: 1024,
            },
            lease: sandbox_protocol::HostLease::for_test(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            idempotency_key: "different-key".to_string(),
            template_digest: image.fingerprint.clone(),
            incus_fingerprint: Some(image.fingerprint.clone()),
            guest: GuestIdentity::default(),
            architecture: Some(image.architecture.clone()),
            egress_policy: None,
            egress_policy_hash: None,
            egress_settings: sandbox_runtime::egress::EgressSettings::default(),
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_privilege: Default::default(),
            readiness: Default::default(),
            restore: None,
        }) {
            Err(err) if err.code == SandboxErrorCode::IdempotencyConflict => {
                h.report
                    .pass("create_sandbox same name + different key is a conflict");
            }
            Ok(_) => h.report.fail(
                "create_sandbox same name + different key is a conflict",
                "succeeded",
            ),
            Err(err) => h.report.fail(
                "create_sandbox same name + different key is a conflict",
                err.to_string(),
            ),
        }

        match runtime.create_sandbox(&CreateSandboxRequest {
            refused_dns_hints: false,
            first_attempt: false,
            vm_size: sandbox_protocol::VmSize {
                cpu_count: 1,
                memory_mi_b: 1024,
            },
            lease: sandbox_protocol::HostLease::for_test(),
            sandbox_id: "other-sandbox".to_string(),
            instance_name: name.clone(),
            idempotency_key: "other-key".to_string(),
            template_digest: image.fingerprint.clone(),
            incus_fingerprint: Some(image.fingerprint.clone()),
            guest: GuestIdentity::default(),
            architecture: Some(image.architecture.clone()),
            egress_policy: None,
            egress_policy_hash: None,
            egress_settings: sandbox_runtime::egress::EgressSettings::default(),
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_privilege: Default::default(),
            readiness: Default::default(),
            restore: None,
        }) {
            Err(err) if err.code == SandboxErrorCode::IdempotencyConflict => {
                h.report
                    .pass("create_sandbox name already bound to another sandbox");
            }
            Ok(_) => h.report.fail(
                "create_sandbox name already bound to another sandbox",
                "succeeded",
            ),
            Err(err) => h.report.fail(
                "create_sandbox name already bound to another sandbox",
                format!("expected IdempotencyConflict, got {err}"),
            ),
        }

        match h.raw_ok(Some("default"), &["stop", &name, "--force"]) {
            Ok(_) => h
                .report
                .pass("incus stop --force (graceful stop timed out on cloud images)"),
            Err(err) => {
                h.report.fail("incus stop --force", err);
                return;
            }
        }

        match runtime.create_sandbox(&CreateSandboxRequest {
            refused_dns_hints: false,
            first_attempt: false,
            vm_size: sandbox_protocol::VmSize {
                cpu_count: 1,
                memory_mi_b: 1024,
            },
            lease: sandbox_protocol::HostLease::for_test(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            idempotency_key: key.clone(),
            template_digest: image.fingerprint.clone(),
            incus_fingerprint: Some(image.fingerprint.clone()),
            guest: GuestIdentity::default(),
            architecture: Some(image.architecture.clone()),
            egress_policy: None,
            egress_policy_hash: None,
            egress_settings: sandbox_runtime::egress::EgressSettings::default(),
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_privilege: Default::default(),
            readiness: Default::default(),
            restore: None,
        }) {
            Ok(_) => match client.list_instances() {
                Ok(rows) => {
                    let status = rows
                        .iter()
                        .find(|row| row.name == name)
                        .map(|row| row.status.as_str())
                        .unwrap_or("missing");
                    h.report.check(
                        "create_sandbox restarts a Stopped VM (maybe_start_stopped)",
                        status.eq_ignore_ascii_case("running"),
                        format!("status={status}"),
                    );
                }
                Err(err) => h.report.fail(
                    "create_sandbox restarts a Stopped VM (maybe_start_stopped)",
                    err.to_string(),
                ),
            },
            Err(err) => h.report.fail(
                "create_sandbox restarts a Stopped VM (maybe_start_stopped)",
                err.to_string(),
            ),
        }

        match wait_for_exec(&client, &bound, Duration::from_secs(120)) {
            Ok(elapsed) => h.report.check(
                "incus exec works after maybe_start_stopped",
                true,
                format!("ready in {elapsed:?}"),
            ),
            Err(err) => h
                .report
                .fail("incus exec works after maybe_start_stopped", err),
        }

        match runtime.kill_sandbox(&KillSandboxRequest {
            template_fingerprint: image.fingerprint.clone(),
            sandbox_id: sandbox_id.clone(),
            instance_name: name.clone(),
            operation_id: "op-kill".to_string(),
            idempotency_key: "kill-1".to_string(),
        }) {
            Ok(resp) => h.report.check(
                "runtime.kill_sandbox force-deletes a running VM",
                resp.sandbox.state == SandboxLifecycleState::Deleted,
                format!("state={:?}", resp.sandbox.state),
            ),
            Err(err) => h.report.fail(
                "runtime.kill_sandbox force-deletes a running VM",
                err.to_string(),
            ),
        }

        match client.instance_exists(&name) {
            Ok(false) => h.report.pass("instance is gone after kill"),
            Ok(true) => h.report.fail("instance is gone after kill", "still exists"),
            Err(err) => h
                .report
                .fail("instance is gone after kill", err.to_string()),
        }

        match runtime.kill_sandbox(&KillSandboxRequest {
            template_fingerprint: image.fingerprint.clone(),
            sandbox_id,
            instance_name: name,
            operation_id: "op-kill-2".to_string(),
            idempotency_key: "kill-2".to_string(),
        }) {
            Ok(_) => h
                .report
                .pass("kill_sandbox on an already-deleted instance is success"),
            Err(err) => h.report.fail(
                "kill_sandbox on an already-deleted instance is success",
                err.to_string(),
            ),
        }
    }

    fn run_error_paths(h: &mut Harness) {
        let runtime = match h.runtime("default") {
            Ok(runtime) => runtime,
            Err(err) => {
                h.report.fail("error paths: runtime.new", err.to_string());
                return;
            }
        };

        match runtime.run_command(&RunCommandRequest {
            template_fingerprint: String::new(),
            generation: 1,
            attempt: 1,
            sandbox_id: "missing0".to_string(),
            instance_name: "wssp-sbx-missing0".to_string(),
            operation_id: "op-miss".to_string(),
            idempotency_key: "cmd-miss".to_string(),
            argv: vec!["true".to_string()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        }) {
            Err(err) if err.code == SandboxErrorCode::SandboxNotFound => {
                h.report
                    .pass("run_command on a missing instance is SandboxNotFound");
            }
            Ok(_) => h.report.fail(
                "run_command on a missing instance is SandboxNotFound",
                "succeeded",
            ),
            Err(err) => h.report.fail(
                "run_command on a missing instance is SandboxNotFound",
                err.to_string(),
            ),
        }

        match runtime.run_command(&RunCommandRequest {
            template_fingerprint: String::new(),
            generation: 1,
            attempt: 1,
            sandbox_id: "missing0".to_string(),
            instance_name: "wssp-sbx-missing0".to_string(),
            operation_id: "op-empty".to_string(),
            idempotency_key: "cmd-empty".to_string(),
            argv: Vec::new(),
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        }) {
            Err(err) if err.code == SandboxErrorCode::ProtocolError => {
                h.report
                    .pass("empty argv is checked before instance_exists");
            }
            Err(err) if err.code == SandboxErrorCode::SandboxNotFound => {
                h.report.fail(
                    "empty argv is checked before instance_exists",
                    "instance_exists runs first, so a missing VM hides ProtocolError for empty argv",
                );
            }
            Ok(_) => h
                .report
                .fail("empty argv is checked before instance_exists", "succeeded"),
            Err(err) => h.report.fail(
                "empty argv is checked before instance_exists",
                format!("unexpected {err}"),
            ),
        }

        match runtime.create_sandbox(&CreateSandboxRequest {
            refused_dns_hints: false,
            first_attempt: false,
            vm_size: sandbox_protocol::VmSize {
                cpu_count: 1,
                memory_mi_b: 1024,
            },
            lease: sandbox_protocol::HostLease::for_test(),
            sandbox_id: h.sandbox_id("b"),
            instance_name: h.instance("b"),
            idempotency_key: "bad-image".to_string(),
            template_digest: "sha256:abc".to_string(),
            incus_fingerprint: None,
            guest: GuestIdentity::default(),
            architecture: Some("x86_64".into()),
            egress_policy: None,
            egress_policy_hash: None,
            egress_settings: sandbox_runtime::egress::EgressSettings::default(),
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_privilege: Default::default(),
            readiness: Default::default(),
            restore: None,
        }) {
            Err(err) => h.report.check(
                "create_sandbox with a digest-like image name fails (wssp template field)",
                err.to_string().contains("launch") || err.to_string().contains("image"),
                err.to_string(),
            ),
            Ok(_) => h.report.fail(
                "create_sandbox with a digest-like image name fails (wssp template field)",
                "sha256:abc launched; Incus accepted a digest as an image alias",
            ),
        }

        match runtime.create_sandbox(&CreateSandboxRequest {
            refused_dns_hints: false,
            first_attempt: false,
            vm_size: sandbox_protocol::VmSize {
                cpu_count: 1,
                memory_mi_b: 1024,
            },
            lease: sandbox_protocol::HostLease::for_test(),
            sandbox_id: h.sandbox_id("b"),
            instance_name: h.instance("b"),
            idempotency_key: "unknown-image".to_string(),
            template_digest: "unknown".to_string(),
            incus_fingerprint: None,
            guest: GuestIdentity::default(),
            architecture: Some("x86_64".into()),
            egress_policy: None,
            egress_policy_hash: None,
            egress_settings: sandbox_runtime::egress::EgressSettings::default(),
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_privilege: Default::default(),
            readiness: Default::default(),
            restore: None,
        }) {
            Err(_) => h
                .report
                .pass("create_sandbox with connect.rs fallback image `unknown` fails"),
            Ok(_) => h.report.fail(
                "create_sandbox with connect.rs fallback image `unknown` fails",
                "unexpected success",
            ),
        }

        // A failed local spawn is pre-issue evidence (C09), not a platform verdict.
        let missing_bin = IncusClient::new("/definitely/not/incus", "default");
        match missing_bin.ping() {
            Err(err) if err.code == SandboxErrorCode::HostEffectNotIssued => {
                h.report.pass("missing incus binary is HostEffectNotIssued");
            }
            Ok(_) => h.report.fail(
                "missing incus binary is HostEffectNotIssued",
                "ping succeeded",
            ),
            Err(err) => h.report.fail(
                "missing incus binary is HostEffectNotIssued",
                err.to_string(),
            ),
        }
    }

    fn run_naming(h: &mut Harness) {
        let id = "ckx1y2z3a4b5c6d7e8f9g0h1";
        let name = default_incus_instance_name(id);
        h.report.check(
            "default instance name is wssp-sbx-<id>",
            name == format!("wssp-sbx-{id}"),
            name.clone(),
        );
        h.report.check(
            "default instance name is a valid Incus hostname",
            is_valid_incus_name(&name),
            name,
        );
        let prisma_name = default_incus_instance_name("ckabcdefghijklmnopqrstuv");
        h.report.check(
            "Prisma cuid(2)-length name stays within 63 chars",
            prisma_name.len() <= 63 && is_valid_incus_name(&prisma_name),
            format!("{} chars: {prisma_name}", prisma_name.len()),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn check_no_guest_sleep(
        h: &mut Harness,
        runtime: &IncusKvmRuntime,
        fingerprint: &str,
        sandbox_id: &str,
        name: &str,
        operation_id: &str,
        cmdline: &str,
        case: &'static str,
    ) {
        match runtime.run_command(&RunCommandRequest {
            template_fingerprint: fingerprint.to_string(),
            generation: 1,
            attempt: 1,
            sandbox_id: sandbox_id.to_string(),
            instance_name: name.to_string(),
            operation_id: operation_id.to_string(),
            idempotency_key: operation_id.to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "command -v pgrep >/dev/null || exit 127; pgrep -fx \"$1\" >/dev/null; echo \"pgrep=$?\""
                    .to_string(),
                "wssp-check".to_string(),
                cmdline.to_string(),
            ],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        }) {
            Ok(resp) => {
                let stdout = stdout_text(&resp.command.chunks);
                // pgrep exits 1 only for "no match"; 0 is a survivor and any
                // other status (or a missing pgrep) is a broken probe.
                h.report.check(
                    case,
                    resp.command.state == OperationState::Succeeded
                        && resp.command.exit_code == Some(0)
                        && stdout.trim() == "pgrep=1",
                    format!(
                        "probe state={:?} exit={:?} stdout={stdout:?}",
                        resp.command.state, resp.command.exit_code
                    ),
                );
            }
            Err(err) => h.report.fail(case, format!("probe failed: {err}")),
        }
    }

    fn wait_for_exec(
        client: &IncusClient,
        name: &BoundInstance,
        budget: Duration,
    ) -> Result<Duration, String> {
        let started = Instant::now();
        loop {
            match client.exec_argv(name, &["true".to_string()]) {
                Ok(out) if out.exit_code == 0 => return Ok(started.elapsed()),
                Ok(out) => {
                    if started.elapsed() > budget {
                        return Err(format!(
                            "exec true still failing after {budget:?}: {}",
                            out.stderr.trim()
                        ));
                    }
                }
                Err(err) => {
                    if started.elapsed() > budget {
                        return Err(format!("exec never became ready: {err}"));
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    fn stdout_text(chunks: &[sandbox_runtime::CommandStreamChunk]) -> String {
        let bytes: Vec<u8> = chunks
            .iter()
            .filter(|c| c.stream == sandbox_runtime::CommandStream::Stdout)
            .flat_map(|c| c.bytes.clone())
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn stderr_text(chunks: &[sandbox_runtime::CommandStreamChunk]) -> String {
        let bytes: Vec<u8> = chunks
            .iter()
            .filter(|c| c.stream == sandbox_runtime::CommandStream::Stderr)
            .flat_map(|c| c.bytes.clone())
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn is_valid_incus_name(name: &str) -> bool {
        let bytes = name.as_bytes();
        (1..=63).contains(&bytes.len())
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
    }

    fn assert_meta(
        h: &mut Harness,
        client: &IncusClient,
        name: &BoundInstance,
        label: &'static str,
        key: &str,
        expected: &str,
    ) {
        match client.config_get(name, key) {
            Ok(Some(value)) if value == expected => h.report.pass(label),
            Ok(other) => h
                .report
                .fail(label, format!("got {other:?}, expected {expected}")),
            Err(err) => h.report.fail(label, err.to_string()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        const RUN: &str = "a1b2c3d4e5f6";

        #[test]
        fn diagnostic_child_scrubs_host_credentials() {
            const MARKER: &str = "WSSP_SCRUB_DIAGNOSTIC_TEST";
            if std::env::var_os(MARKER).is_none() {
                let out = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "linux::tests::diagnostic_child_scrubs_host_credentials",
                        "--exact",
                        "--nocapture",
                    ])
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", "/scrub-client-home")
                    .env("INCUS_DIR", "/scrub-client-dir")
                    .env("INCUS_SOCKET", "/scrub-client-socket")
                    .env("INCUS_CONF", "/scrub-client-conf")
                    .env("WSSP_HOST_TOKEN", "wssp_host_scrub_fixture")
                    .env("WSSP_DEVICE_TOKEN", "wssp_device_scrub_fixture")
                    .env("WORKLOAD_SECRET", "scrub-workload-fixture")
                    .env("LANG", "fr_FR.UTF-8")
                    .env("LC_ALL", "fr_FR.UTF-8")
                    .env(MARKER, "1")
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "{}\n{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
                return;
            }
            let (harness, dir) = shim_harness("env-scrub");
            install_executable(
                std::path::Path::new(&harness.binary),
                "#!/bin/sh\ncat /proc/$$/environ\n",
            );
            let out = harness.raw(None, &["version"]).unwrap();
            assert!(out.status.success());
            let entries: Vec<&str> = std::str::from_utf8(&out.stdout)
                .unwrap()
                .split('\0')
                .filter(|entry| !entry.is_empty())
                .collect();
            assert_eq!(entries.len(), 6, "diagnostic environment key count");
            for key in ["PATH", "HOME", "INCUS_DIR", "INCUS_SOCKET", "INCUS_CONF"] {
                let expected = format!("{key}={}", std::env::var(key).unwrap());
                assert!(entries.contains(&expected.as_str()), "missing {key}");
            }
            assert!(entries.contains(&"LC_ALL=C"));
            std::fs::remove_dir_all(dir).unwrap();
        }

        /// Installs an executable without this process ever holding a
        /// writable descriptor to it: a concurrent test thread's fork would
        /// inherit one written in-process, and our spawn of the script then
        /// fails with ETXTBSY. Only the `cp` child opens the target for
        /// writing (the library tests' `install_executable`).
        fn install_executable(path: &std::path::Path, contents: &str) {
            let mut staged = path.as_os_str().to_owned();
            staged.push(".src");
            let staged = std::path::PathBuf::from(staged);
            std::fs::write(&staged, contents).unwrap();
            let status = Command::new("cp").arg(&staged).arg(path).status().unwrap();
            assert!(status.success(), "cp {staged:?} -> {path:?}: {status}");
            std::fs::remove_file(&staged).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        /// Fake `incus` that logs every call. `-a` and `-p` carry this run's
        /// sandbox ids (VMs AND owned bridge/ACL pairs, modeling partially
        /// completed launches), `-b` is foreign with the same name, `-fork`
        /// is absent, and the image list advertises the shared base image.
        /// A fresh mode-0700 surface root for claim tests.
        fn private_root(tag: &str) -> std::path::PathBuf {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "wssp-surface-root-ut-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            dir
        }

        fn shim_harness(tag: &str) -> (Harness, std::path::PathBuf) {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "wssp-surface-cleanup-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let log = dir.join("calls");
            let shim = dir.join("incus");
            install_executable(
                &shim,
                &format!(
                    r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *"image list"*|*"image ls"*)
    echo '[{{"fingerprint":"7c6bf674d58d","aliases":[{{"name":"wssp-base"}}]}}]' ;;
  "query --raw /1.0/networks/"*|"query --raw /1.0/network-acls/"*)
    url=$3
    name=${{url##*/}}
    name=${{name%%\?*}}
    marker=$(cat '{dir}/net-'$name 2>/dev/null) || marker=""
    if [ -n "$marker" ]; then
      tag=${{marker%%|*}}
      proj=${{marker##*|}}
      printf '{{"type":"sync","status_code":200,"error_code":0,"metadata":{{"name":"%s","config":{{"user.wssp.sandbox_id":"%s","user.wssp.attempt":"s1","user.wssp.project":"%s"}}}}}}\n' "$name" "$tag" "$proj"
    else
      printf '{{"type":"error","status":"Not Found","status_code":404,"error_code":404,"error":"Not Found"}}\n'
    fi ;;
  *"network acl delete "*|*"network delete "*)
    if [ -f '{dir}/fail-net-delete' ]; then echo "Error: daemon busy" >&2; exit 1; fi
    rm -f '{dir}/'net-"${{*##* }}" ;;
  *"config get wssp-sbx-s{RUN}-a {META_SANDBOX}")
    if [ -f '{dir}/fail-probes' ]; then echo "Error: Forbidden" >&2; exit 1; fi
    if [ -f '{dir}/vm-a' ]; then echo "s{RUN}-a";
    elif [ -f '{dir}/fail-vm-probe-after-delete' ]; then echo "Error: Forbidden" >&2; exit 1;
    elif [ -f '{dir}/misleading-not-found' ]; then
      echo 'Error: cannot parse server response: field "config" not found' >&2; exit 1;
    else
      nf_name=$(printf '%s' "$*" | awk '{{print $(NF-1)}}')
      nf_proj=$(printf '%s' "$*" | awk '{{print $2}}')
      echo "Error: Failed to fetch instance \"$nf_name\" in project \"$nf_proj\": Instance not found" >&2; exit 1; fi ;;
  *"config get wssp-sbx-s{RUN}-p {META_SANDBOX}")
    if [ -f '{dir}/fail-probes' ]; then echo "Error: Forbidden" >&2; exit 1; fi
    if [ -f '{dir}/vm-p' ]; then echo "s{RUN}-p";
    elif [ -f '{dir}/fail-vm-probe-after-delete' ]; then echo "Error: Forbidden" >&2; exit 1;
    elif [ -f '{dir}/misleading-not-found' ]; then
      echo 'Error: cannot parse server response: field "config" not found' >&2; exit 1;
    else
      nf_name=$(printf '%s' "$*" | awk '{{print $(NF-1)}}')
      nf_proj=$(printf '%s' "$*" | awk '{{print $2}}')
      echo "Error: Failed to fetch instance \"$nf_name\" in project \"$nf_proj\": Instance not found" >&2; exit 1; fi ;;
  *" delete wssp-sbx-s{RUN}-a --force")
    if [ -f '{dir}/fail-vm-delete' ]; then echo "Error: daemon busy" >&2; exit 1; fi
    if [ -f '{dir}/silent-vm-survivor' ]; then exit 0; fi
    rm -f '{dir}/vm-a' ;;
  *" delete wssp-sbx-s{RUN}-p --force")
    if [ -f '{dir}/fail-vm-delete' ]; then echo "Error: daemon busy" >&2; exit 1; fi
    rm -f '{dir}/vm-p' ;;
  "project delete "*)
    if [ -f '{dir}/fail-project-delete' ]; then echo "Error: project is not empty" >&2; exit 1; fi
    if [ -f '{dir}/silent-project-survivor' ]; then exit 0; fi
    rm -f '{dir}/proj-exists' ;;
  "project show "*)
    if [ -f '{dir}/fail-probes' ]; then echo "Error: Forbidden" >&2; exit 1; fi
    if [ -f '{dir}/proj-exists' ]; then exit 0; fi
    if [ -f '{dir}/fail-project-probe' ]; then
      echo "Error: Get \"http://unix.socket/1.0\": dial unix: connect: connection refused" >&2; exit 1; fi
    echo "Error: Project not found" >&2; exit 1 ;;
  *"config get wssp-sbx-s{RUN}-b {META_SANDBOX}") echo "someone-elses-sandbox" ;;
  *"config get "*)
    nf_name=$(printf '%s' "$*" | awk '{{print $(NF-1)}}')
    nf_proj=$(printf '%s' "$*" | awk '{{print $2}}')
    echo "Error: Failed to fetch instance \"$nf_name\" in project \"$nf_proj\": Instance not found" >&2; exit 1 ;;
esac
exit 0
"#,
                    log = log.display(),
                    dir = dir.display()
                ),
            );
            // Owned bridge/ACL pairs for -a (default project) and -p (probe
            // project), foreign ones for -b, none for -fork: the harness must
            // remove exactly its own run's network resources.
            for marker in ["vm-a", "vm-p", "vm-b", "proj-exists"] {
                std::fs::write(dir.join(marker), "").unwrap();
            }
            let probe = format!("{PROJECT_PROBE_PREFIX}-{RUN}");
            for (suffix, owner, project) in [
                ("a", format!("s{RUN}-a"), "default".to_string()),
                ("p", format!("s{RUN}-p"), probe),
                (
                    "b",
                    "someone-elses-sandbox".to_string(),
                    "default".to_string(),
                ),
            ] {
                let (network, acl) = sandbox_runtime::sandbox_network_names(&owner);
                for name in [network, acl] {
                    std::fs::write(
                        dir.join(format!("net-{name}")),
                        format!("{owner}|{project}"),
                    )
                    .unwrap();
                }
                let _ = suffix;
            }
            let mut h = Harness::with(
                shim.to_string_lossy().into_owned(),
                IMAGE_DEFAULT.to_string(),
                RUN.to_string(),
            );
            // Isolate the harness state dir per test: it defaults to a
            // pid-keyed temp path, which parallel tests in one process would
            // share (one test's successful cleanup would remove another's
            // journal directory).
            h.state_dir = dir.join("state");
            std::fs::create_dir_all(&h.state_dir).unwrap();
            (h, dir)
        }

        fn owned_names(suffix: &str) -> (String, String) {
            sandbox_runtime::sandbox_network_names(&format!("s{RUN}-{suffix}"))
        }

        fn deletes(dir: &std::path::Path) -> Vec<String> {
            let calls = std::fs::read_to_string(dir.join("calls")).unwrap_or_default();
            for line in calls.lines() {
                // The probe project shares the default project's images, so any
                // image cleanup would delete host images the harness does not own.
                assert!(!line.split_whitespace().any(|w| w == "image"), "{line}");
            }
            calls
                .lines()
                .filter(|l| l.split_whitespace().any(|w| w == "delete"))
                .map(str::to_string)
                .collect()
        }

        #[test]
        fn cleanup_deletes_only_this_runs_instances_and_never_images() {
            let (mut h, dir) = shim_harness("owned");
            h.owns_probe_project = true;
            let (net_a, acl_a) = owned_names("a");
            let (net_p, acl_p) = owned_names("p");
            h.cleanup();
            assert_eq!(
                deletes(&dir),
                [
                    format!("--project default delete wssp-sbx-s{RUN}-a --force"),
                    format!("--project default network delete {net_a}"),
                    format!("--project default network acl delete {acl_a}"),
                    format!("--project wssp-surface-{RUN} delete wssp-sbx-s{RUN}-p --force"),
                    format!("--project wssp-surface-{RUN} network delete {net_p}"),
                    format!("--project wssp-surface-{RUN} network acl delete {acl_p}"),
                    format!("project delete wssp-surface-{RUN}"),
                ],
                "the foreign same-name `-b` VM, its bridge/ACL, and the absent `-fork` must be untouched"
            );
            // Verified removal: every owned resource's marker is gone.
            for name in [net_a, acl_a, net_p, acl_p] {
                assert!(!dir.join(format!("net-{name}")).exists(), "{name}");
            }
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn claims_leave_no_pid_scratch_directories() {
            // R20-F3: constructing the harness (even for a claim that is
            // REFUSED) must not abandon a pid-suffixed scratch directory;
            // only the canonical run-id dir may ever exist.
            let id = format!("{:012x}", std::process::id() as u64 * 16 + 9);
            let root = private_root("noscratch");
            let scratch = || -> Vec<std::path::PathBuf> {
                let prefix = format!("state-{id}-");
                std::fs::read_dir(&root)
                    .expect("root dir")
                    .filter_map(std::result::Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| {
                        path.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|name| name.starts_with(&prefix))
                    })
                    .collect()
            };
            // Successful claim: exactly the canonical dir, no scratch.
            let harness = Harness::claimed_under(&root, id.clone()).expect("claim");
            let extras = scratch();
            assert!(extras.is_empty(), "scratch dirs after claim: {extras:?}");
            // Refused claim (the lock is still held): no scratch either.
            let refused = Harness::claimed_under(&root, id.clone());
            assert!(refused.is_err(), "concurrent claim is refused");
            let extras = scratch();
            assert!(extras.is_empty(), "scratch dirs after refusal: {extras:?}");
            drop(harness);
            std::fs::remove_dir_all(&root).unwrap();
        }

        /// R21-F1: a symlink planted at the run's predictable state-dir path
        /// is REFUSED — never followed, never removed — and its target's
        /// bytes are untouched.
        #[test]
        fn planted_symlink_state_dir_is_refused_and_the_target_is_untouched() {
            let root = private_root("plink");
            let id = format!("{:012x}", std::process::id() as u64 * 16 + 11);
            let victim = root.join("victim.json");
            std::fs::write(&victim, b"precious").unwrap();
            let planted = root.join(format!("state-{id}"));
            std::os::unix::fs::symlink(&victim, &planted).unwrap();
            let err =
                Harness::claim_state_dir(&root, &id).expect_err("a planted symlink is refused");
            assert!(err.contains("refusing"), "{err}");
            assert_eq!(
                std::fs::read(&victim).unwrap(),
                b"precious",
                "the symlink target's bytes are untouched"
            );
            assert!(
                planted.symlink_metadata().unwrap().file_type().is_symlink(),
                "the planted symlink itself was not traversed or replaced"
            );
            std::fs::remove_dir_all(&root).unwrap();
        }

        /// R21-F1: the surface root must be an OWNED, mode-0700, plain
        /// directory; symlinked or permissive parents are refused, a missing
        /// one is created 0700.
        #[test]
        fn surface_root_must_be_an_owned_private_directory() {
            use std::os::unix::fs::PermissionsExt;
            let base = private_root("roots");
            // Symlinked root (even at an owned 0700 target) is refused.
            let target = base.join("real");
            std::fs::create_dir(&target).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
            let link = base.join("linkroot");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let err = validate_private_root(link).expect_err("symlinked root refused");
            assert!(err.contains("refusing"), "{err}");
            assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
            // Permissive mode is refused.
            let open = base.join("open");
            std::fs::create_dir(&open).unwrap();
            let err = validate_private_root(open).expect_err("0755 root refused");
            assert!(err.contains("0700"), "{err}");
            // Missing is created 0700.
            let fresh = base.join("fresh");
            let root = validate_private_root(fresh).expect("created");
            let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
            std::fs::remove_dir_all(&base).unwrap();
        }

        #[test]
        fn state_dir_is_reopenable_by_run_id_and_guarded() {
            // A later `cleanup <run-id>` process reopens the SAME state dir;
            // a SIMULTANEOUS claim is refused while the lock is held; a dead
            // owner's claim is released by the kernel.
            let id_a = format!("{:012x}", std::process::id() as u64 * 16);
            let root = private_root("reopen");
            let (dir, lock) = Harness::claim_state_dir(&root, &id_a).expect("first claim");
            assert_eq!(dir, root.join(format!("state-{id_a}")));
            let err =
                Harness::claim_state_dir(&root, &id_a).expect_err("simultaneous claim refused");
            assert!(err.contains("owned by a live process"), "{err}");
            // The lock file lives OUTSIDE the state dir: removing the dir
            // (the harness's initial cleanup) must not drop ownership.
            std::fs::remove_dir_all(&dir).unwrap();
            let err = Harness::claim_state_dir(&root, &id_a)
                .expect_err("claim still refused after the state dir is removed");
            assert!(err.contains("owned by a live process"), "{err}");
            // Releasing the lock (process exit in production) frees the run.
            // Bounded retry: a forked sibling test's child can hold the lock
            // file description until its exec (O_CLOEXEC) completes.
            drop(lock);
            let mut claimed = Harness::claim_state_dir(&root, &id_a);
            for _ in 0..200 {
                if claimed.is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
                claimed = Harness::claim_state_dir(&root, &id_a);
            }
            let (dir, lock) = claimed.expect("claim after release");
            assert_eq!(dir, root.join(format!("state-{id_a}")));
            drop(lock);
            std::fs::remove_dir_all(&root).unwrap();
        }

        #[test]
        fn cleanup_reports_failure_when_the_state_dir_cannot_be_removed() {
            let (mut h, dir) = shim_harness("owned");
            h.owns_probe_project = false;
            // Point the state dir at a regular FILE: the successful-teardown
            // journal removal fails and must be reported, never swallowed.
            let file = dir.join("a-file");
            std::fs::write(&file, "journal").unwrap();
            h.state_dir = file;
            assert_eq!(h.cleanup(), 1, "a journal removal failure is reported");
        }

        #[test]
        fn cleanup_leaves_a_probe_project_it_does_not_own_alone() {
            let (h, dir) = shim_harness("unowned");
            let (net_a, acl_a) = owned_names("a");
            h.cleanup();
            assert_eq!(
                deletes(&dir),
                [
                    format!("--project default delete wssp-sbx-s{RUN}-a --force"),
                    format!("--project default network delete {net_a}"),
                    format!("--project default network acl delete {acl_a}"),
                ]
            );
            std::fs::remove_dir_all(dir).unwrap();
        }

        /// R14-F1: a transient daemon deletion failure must surface as a
        /// COMMAND FAILURE and preserve the state directory holding the
        /// freshly journaled obligation — never print "cleaned" over an
        /// owned bridge/ACL whose recovery journal was just discarded.
        #[test]
        fn failed_cleanup_reports_failure_and_keeps_the_journal() {
            let (h, dir) = shim_harness("owned");
            let (net_a, _acl_a) = owned_names("a");
            // Pin the daemon delete to fail.
            std::fs::write(dir.join("fail-net-delete"), "").unwrap();
            assert_eq!(
                h.cleanup(),
                1,
                "cleanup reports failure when an owned resource remains"
            );
            assert!(
                dir.join(format!("net-{net_a}")).exists(),
                "the owned bridge is still on the daemon"
            );
            assert!(
                h.state_dir.exists(),
                "the state directory (journal) is preserved while obligations remain"
            );
            let (network, _acl) = sandbox_runtime::sandbox_network_names(&format!("s{RUN}-a"));
            let _ = network;
            let journal = h.state_dir.join("network-cleanups");
            assert!(
                std::fs::read_dir(&journal)
                    .map(|entries| entries.count() > 0)
                    .unwrap_or(false),
                "the durable cleanup obligation is journaled, not discarded"
            );
            // Recovery: unpin, and cleanup now succeeds and removes the dir.
            std::fs::remove_file(dir.join("fail-net-delete")).unwrap();
            assert_eq!(h.cleanup(), 0);
            assert!(!h.state_dir.exists(), "successful cleanup removes the dir");
            std::fs::remove_dir_all(dir).unwrap();
        }

        /// R15-F1: a failed VM deletion (even when the VM does not reference
        /// the managed bridge, so network teardown succeeds) and a failed
        /// probe-project deletion must each fail cleanup and retain state.
        #[test]
        fn failed_vm_and_project_deletion_fail_cleanup() {
            let (mut h, dir) = shim_harness("owned");
            h.owns_probe_project = true;
            std::fs::write(dir.join("fail-vm-delete"), "").unwrap();
            assert_eq!(h.cleanup(), 1, "a failed VM deletion fails cleanup");
            assert!(dir.join("vm-a").exists(), "the VM survives");
            assert!(h.state_dir.exists(), "state retained on failure");
            std::fs::remove_file(dir.join("fail-vm-delete")).unwrap();
            // Phase 1's project delete succeeded; re-create it so its failure
            // can be exercised.
            std::fs::write(dir.join("proj-exists"), "").unwrap();
            std::fs::write(dir.join("fail-project-delete"), "").unwrap();
            assert_eq!(
                h.cleanup(),
                1,
                "a failed project deletion fails cleanup even after teardown"
            );
            assert!(dir.join("proj-exists").exists());
            assert!(h.state_dir.exists(), "state retained on failure");
            std::fs::remove_file(dir.join("fail-project-delete")).unwrap();
            // Silent survivors: the delete reports success but keeps the
            // object — only the absence verification can catch it.
            std::fs::write(dir.join("vm-a"), "").unwrap();
            std::fs::write(dir.join("silent-vm-survivor"), "").unwrap();
            assert_eq!(h.cleanup(), 1, "a silently surviving VM fails cleanup");
            assert!(dir.join("vm-a").exists());
            std::fs::remove_file(dir.join("silent-vm-survivor")).unwrap();
            std::fs::write(dir.join("proj-exists"), "").unwrap();
            std::fs::write(dir.join("silent-project-survivor"), "").unwrap();
            assert_eq!(h.cleanup(), 1, "a silently surviving project fails cleanup");
            assert!(dir.join("proj-exists").exists());
            std::fs::remove_file(dir.join("silent-project-survivor")).unwrap();
            assert_eq!(h.cleanup(), 0);
            assert!(!h.state_dir.exists());
            std::fs::remove_dir_all(dir).unwrap();
        }

        /// R16-F1: a probe error is NOT absence evidence. Ownership-probe
        /// errors, and post-delete verify probes answered with anything but
        /// an explicit not-found (permission denied, daemon down), must fail
        /// cleanup and retain state — never report success over an
        /// unverified survivor.
        #[test]
        fn probe_errors_are_not_absence_evidence() {
            // VM side, no probe project involved.
            let (h, dir) = shim_harness("owned");
            // Ownership probe denied: the VM must not be silently skipped.
            std::fs::write(dir.join("fail-probes"), "").unwrap();
            assert_eq!(h.cleanup(), 1, "an ownership probe error fails cleanup");
            assert!(
                dir.join("vm-a").exists(),
                "a failed ownership probe never skips the VM silently"
            );
            assert!(h.state_dir.exists(), "state retained on probe failure");
            std::fs::remove_file(dir.join("fail-probes")).unwrap();
            // VM delete succeeds, but the verify probe errors (permission
            // denied): inconclusive absence must fail cleanup.
            std::fs::write(dir.join("fail-vm-probe-after-delete"), "").unwrap();
            assert_eq!(h.cleanup(), 1, "an inconclusive VM verify probe fails");
            assert!(!dir.join("vm-a").exists(), "the delete itself succeeded");
            assert!(h.state_dir.exists());
            std::fs::remove_file(dir.join("fail-vm-probe-after-delete")).unwrap();
            assert_eq!(h.cleanup(), 0);
            assert!(!h.state_dir.exists());
            std::fs::remove_dir_all(dir).unwrap();

            // Misleading diagnostics: an unrelated "not found" mention on the
            // verify probe is a FAILURE, not absence evidence — only the
            // exact `Instance not found` response for the probed object is.
            let (mut h, dir) = shim_harness("owned");
            h.owns_probe_project = false;
            std::fs::write(dir.join("misleading-not-found"), "").unwrap();
            assert_eq!(h.cleanup(), 1, "a misleading diagnostic is a failure");
            assert!(h.state_dir.exists());
            std::fs::remove_file(dir.join("misleading-not-found")).unwrap();
            assert_eq!(h.cleanup(), 0);
            assert!(!h.state_dir.exists());
            std::fs::remove_dir_all(dir).unwrap();

            // Project side: the delete succeeds but the daemon goes down for
            // `project show` — inconclusive absence fails cleanup.
            let (mut h, dir) = shim_harness("owned");
            h.owns_probe_project = true;
            std::fs::write(dir.join("fail-project-probe"), "").unwrap();
            assert_eq!(
                h.cleanup(),
                1,
                "a non-not-found project probe error fails cleanup"
            );
            assert!(
                !dir.join("proj-exists").exists(),
                "the project delete itself succeeded"
            );
            assert!(h.state_dir.exists(), "state retained on probe failure");
            std::fs::remove_file(dir.join("fail-project-probe")).unwrap();
            assert_eq!(h.cleanup(), 0);
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn run_ids_are_random_and_cleanup_rejects_malformed_ids() {
            let a = random_run_id().unwrap();
            assert!(valid_run_id(&a), "{a}");
            assert_ne!(a, random_run_id().unwrap());
            for bad in ["", "4242", "A1B2C3D4E5F6", "a1b2c3d4e5f6-", "../a1b2c3d4"] {
                assert!(!valid_run_id(bad), "{bad}");
            }
            assert_eq!(cleanup_only(None), 2);
            assert_eq!(cleanup_only(Some("4242")), 2);
        }
    }
}

#[cfg(target_os = "linux")]
fn test_all() -> i32 {
    linux::test_all()
}

#[cfg(target_os = "linux")]
fn cleanup_only(run_id: Option<&str>) -> i32 {
    linux::cleanup_only(run_id)
}
