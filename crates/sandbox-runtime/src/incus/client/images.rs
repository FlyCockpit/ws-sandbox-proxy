//! Managed image store and template capture through the `incus` CLI.
//!
//! Imports never set an alias (operator images keep theirs and are never
//! evicted); capture works on a disposable copy (`wssp-cap-*`) with no NIC, so
//! the live sandbox keeps running and keeps its credentials.

use super::*;
use std::io::{BufRead as _, BufReader, Write as _};

use crate::IMAGE_IO_TIMEOUT;
const CAPTURE_STEP_TIMEOUT: Duration = Duration::from_secs(600);
const FREEZE_READY_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(not(test))]
const CLEANUP_BACKOFF_START: Duration = Duration::from_secs(2);
#[cfg(not(test))]
const CLEANUP_BACKOFF_MAX: Duration = Duration::from_secs(300);
#[cfg(test)]
const CLEANUP_BACKOFF_START: Duration = Duration::from_millis(5);
#[cfg(test)]
const CLEANUP_BACKOFF_MAX: Duration = Duration::from_millis(20);

fn fingerprint_after(output: &str, marker: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (_, tail) = line.split_once(marker)?;
        let hex = tail.trim().trim_start_matches("sha256:");
        (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| format!("sha256:{}", hex.to_ascii_lowercase()))
    })
}

/// At most this many images in one inventory read; more is an error (the
/// caller must not act on a partial view).
const IMAGE_INVENTORY_MAX: usize = 8192;

/// `GET /1.0/images` answers image URLs (`/1.0/images/<hex>[?project=…]`);
/// each becomes the `sha256:<hex>` form the daemon journals. One entry that is
/// not a URL with a valid fingerprint fails the whole read.
fn parse_image_inventory(
    list: &serde_json::Value,
) -> Result<std::collections::BTreeSet<String>, RuntimeError> {
    let invalid = || {
        RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "image inventory entry is not an image URL",
        )
    };
    let entries = list.as_array().ok_or_else(invalid)?;
    if entries.len() > IMAGE_INVENTORY_MAX {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "image inventory exceeds its bound",
        ));
    }
    entries
        .iter()
        .map(|entry| {
            let url = entry.as_str().ok_or_else(invalid)?;
            let path = url.split_once('?').map_or(url, |(path, _)| path);
            let hex = path.strip_prefix("/1.0/images/").ok_or_else(invalid)?;
            crate::image::fingerprint_from_incus(hex).map_err(|_| invalid())
        })
        .collect()
}

fn require_success(out: &IncusCommandOutput, what: &str) -> Result<(), RuntimeError> {
    if out.exit_code == 0 {
        Ok(())
    } else {
        Err(host_cli_error(what, out))
    }
}

/// The whole boot settle of a capture VM, from `start` to a settled boot.
/// A fresh 26.04 instance reboots once during first boot, and a slow host
/// can take minutes to boot a 1-vCPU guest.
#[cfg(not(test))]
const CAPTURE_BOOT_TIMEOUT: Duration = Duration::from_secs(600);
#[cfg(test)]
const CAPTURE_BOOT_TIMEOUT: Duration = Duration::from_millis(1500);
/// One agent probe (`boot_id` read) of the capture VM.
const CAPTURE_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// One `systemctl is-system-running --wait` call.
const CAPTURE_SETTLE_CALL_TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(not(test))]
const CAPTURE_BOOT_POLL: Duration = Duration::from_secs(2);
#[cfg(test)]
const CAPTURE_BOOT_POLL: Duration = Duration::from_millis(5);

/// The scrub helper's first error for the host log, as fixed text only: an
/// allowlisted error class and the path only when it is exactly one of the
/// fixed manifest paths (`/etc/machine-id`, `<home>/.bash_history`, ...).
/// Never the helper's free text, a symlink target or a guest-chosen
/// descendant: a guest controls those (a link to `/run/<login value>` must
/// not reach a host log, CLI-logins rule).
fn scrub_failure_summary(stdout: &str, manifest_paths: &[String]) -> Option<String> {
    let report = serde_json::from_str::<serde_json::Value>(stdout.trim()).ok()?;
    let errors = report.get("errors")?.as_array()?;
    let first = errors.first()?;
    let path = first.get("path").and_then(|p| p.as_str()).unwrap_or("");
    let reason = first.get("error").and_then(|e| e.as_str()).unwrap_or("");
    let class = match reason {
        "Read-only file system" => "read_only_fs",
        "Permission denied" | "Operation not permitted" => "permission_denied",
        "No such file or directory" => "not_found",
        "replaced during scrub" => "replaced",
        "present after scrub" => "still_present",
        "not empty after scrub" | "missing after scrub" => "truncate_unverified",
        "a network device is attached" => "network_attached",
        _ if reason.starts_with("link target is protected") => "protected_link",
        _ if path == "<freeze>" => "freeze",
        _ => "other",
    };
    let shown = match path {
        "<freeze>" | "<network>" | "<mode>" => path,
        _ if !path.contains('*') && manifest_paths.iter().any(|p| p == path) => path,
        _ => "<path withheld>",
    };
    Some(format!(
        "{} scrub error(s), first: {class} at {shown}",
        errors.len().min(10_000)
    ))
}

impl IncusClient {
    /// The guest kernel's boot id through the agent (root, the capture VM
    /// has no wssp metadata to bind); `None` when the agent does not answer.
    fn capture_boot_id(&self, vm: &str, remaining: Duration) -> Option<String> {
        let out = self
            .image_run(
                &["exec", vm, "--", "cat", "/proc/sys/kernel/random/boot_id"],
                remaining.min(CAPTURE_PROBE_TIMEOUT),
            )
            .ok()?;
        let boot = out.stdout.trim();
        (out.exit_code == 0 && crate::incus::frames::valid_boot_id(boot.as_bytes()))
            .then(|| boot.to_owned())
    }

    /// Wait until the capture VM's boot has settled before the scrub: the
    /// agent answers, `systemctl is-system-running --wait` reports `running`
    /// or `degraded`, and the boot id is the same before and after. An
    /// agent that answers early in boot is not enough: until
    /// `systemd-machine-id-commit` runs, the emptied `/etc/machine-id` is a
    /// read-only transient bind mount and the scrub cannot truncate it (prod
    /// 26.04 capture on a busy host), and the first-boot reboot of a fresh
    /// 26.04 instance can still be ahead. A slow answer is retried until the
    /// budget ends.
    fn capture_vm_settle(&self, vm: &str) -> Result<(), RuntimeError> {
        let deadline = Instant::now() + CAPTURE_BOOT_TIMEOUT;
        let mut last = "agent never answered";
        loop {
            // A shutting-down daemon (closed host children) stops waiting.
            if self.io_cancelled() {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Cancelled,
                    "capture VM boot settle cancelled",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Timeout,
                    format!(
                        "capture VM boot did not settle within {}s: {last}",
                        CAPTURE_BOOT_TIMEOUT.as_secs()
                    ),
                ));
            }
            if let Some(before) = self.capture_boot_id(vm, remaining) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let settled = self.image_run(
                    &["exec", vm, "--", "systemctl", "is-system-running", "--wait"],
                    remaining.min(CAPTURE_SETTLE_CALL_TIMEOUT),
                );
                match settled {
                    Ok(out)
                        if matches!(out.exit_code, 0 | 1)
                            && matches!(out.stdout.trim(), "running" | "degraded") =>
                    {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if self.capture_boot_id(vm, remaining).as_deref() == Some(before.as_str()) {
                            return Ok(());
                        }
                        last = "guest restarted while its boot settled";
                    }
                    Ok(_) => last = "boot not settled",
                    Err(_) => last = "boot settle check did not answer",
                }
            }
            thread::sleep(
                CAPTURE_BOOT_POLL.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn image_run(
        &self,
        args: &[&str],
        timeout: Duration,
    ) -> Result<IncusCommandOutput, RuntimeError> {
        self.run_timed(args, false, timeout)
    }

    /// `incus image import <file>`: no alias, current project. The tarball
    /// is validated first (`validate_unified_image`): Incus itself accepts
    /// crafted backing files, links and device nodes, so nothing that is not
    /// exactly a wssp/Incus unified VM image ever reaches it.
    pub fn image_import(&self, path: &Path) -> Result<String, RuntimeError> {
        let file = path.to_str().ok_or_else(|| {
            RuntimeError::new(SandboxErrorCode::ProtocolError, "image path is not UTF-8")
        })?;
        crate::validate_unified_image(path)?;
        let out = self.image_run(&["image", "import", file], IMAGE_IO_TIMEOUT)?;
        require_success(&out, "image import")?;
        fingerprint_after(&out.stdout, "fingerprint:").ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "image import printed no fingerprint",
            )
        })
    }

    /// `incus image import <meta> <disk>` (an upstream split image,
    /// community bases) into this client's project (`--project`, whatever
    /// its `features.images`), no alias. Both files are validated first
    /// (`validate_split_image`), and the fingerprint Incus reports must equal
    /// `expected`; otherwise the imported image is deleted and the import is
    /// `image_rejected` (post-import compare, I3).
    pub fn image_import_split(
        &self,
        meta: &Path,
        disk: &Path,
        expected: &str,
    ) -> Result<String, RuntimeError> {
        let expected = crate::normalize_incus_fingerprint(expected)?;
        let utf8 = |path: &Path| {
            path.to_str().map(str::to_owned).ok_or_else(|| {
                RuntimeError::new(SandboxErrorCode::ProtocolError, "image path is not UTF-8")
            })
        };
        let (meta_file, disk_file) = (utf8(meta)?, utf8(disk)?);
        crate::validate_split_image(meta, disk, crate::SPLIT_VIRTUAL_SIZE_MAX)?;
        let out = self.image_run(
            &["image", "import", &meta_file, &disk_file],
            IMAGE_IO_TIMEOUT,
        )?;
        require_success(&out, "image import")?;
        let imported = fingerprint_after(&out.stdout, "fingerprint:").ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "image import printed no fingerprint",
            )
        })?;
        if imported != expected {
            let _ = self.image_delete(&imported);
            return Err(RuntimeError::new(
                SandboxErrorCode::ImageRejected,
                "image refused: imported_fingerprint_mismatch",
            ));
        }
        Ok(imported)
    }

    /// `incus image export <fp> <dir>/`: the files it wrote.
    pub fn image_export(
        &self,
        fingerprint: &str,
        dir: &Path,
    ) -> Result<Vec<std::path::PathBuf>, RuntimeError> {
        let fingerprint = crate::normalize_incus_fingerprint(fingerprint)?;
        let target = format!(
            "{}/",
            dir.to_str().ok_or_else(|| {
                RuntimeError::new(SandboxErrorCode::ProtocolError, "export path is not UTF-8")
            })?
        );
        let out = self.image_run(
            &["image", "export", &fingerprint[7..], &target],
            IMAGE_IO_TIMEOUT,
        )?;
        require_success(&out, "image export")?;
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .map_err(|_| {
                RuntimeError::new(SandboxErrorCode::Internal, "export directory unreadable")
            })?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        Ok(files)
    }

    pub fn image_delete(&self, fingerprint: &str) -> Result<(), RuntimeError> {
        let fingerprint = crate::normalize_incus_fingerprint(fingerprint)?;
        let out = self.image_run(
            &["image", "delete", &fingerprint[7..]],
            CAPTURE_STEP_TIMEOUT,
        )?;
        require_success(&out, "image delete")
    }

    /// `GET /1.0/images` of this client's project (the same project
    /// `resolve_image_ref`, import and delete use): one bounded read.
    pub fn image_fingerprints(&self) -> Result<std::collections::BTreeSet<String>, RuntimeError> {
        validate_incus_identifier(&self.project, "project")?;
        let list = self.query_raw(&with_query_params(
            "/1.0/images",
            &[("project", self.project.as_str())],
        ))?;
        parse_image_inventory(&list)
    }

    /// Aliased, or the `volatile.base_image` of any instance in any project.
    pub fn image_protected(&self, fingerprint: &str) -> Result<bool, RuntimeError> {
        let fingerprint = crate::normalize_incus_fingerprint(fingerprint)?;
        let image = self.query_raw(&image_query_url(&fingerprint[7..], &self.project)?)?;
        if image
            .get("aliases")
            .and_then(|a| a.as_array())
            .is_some_and(|a| !a.is_empty())
        {
            return Ok(true);
        }
        let instances = self.query_raw("/1.0/instances?all-projects=true&recursion=1")?;
        Ok(instances.as_array().is_some_and(|list| {
            list.iter().any(|instance| {
                instance
                    .get("config")
                    .and_then(|c| c.get("volatile.base_image"))
                    .and_then(|v| v.as_str())
                    .is_some_and(|base| base == &fingerprint[7..])
            })
        }))
    }

    /// Publish a stopped managed instance under its offload
    /// alias. The status is read first: anything but Stopped is refused
    /// before the CLI runs, so a running guest is never published.
    pub fn publish_stopped_instance(
        &self,
        instance: &str,
        alias: &str,
    ) -> Result<crate::PublishedDisk, RuntimeError> {
        validate_managed_instance_name(instance)?;
        crate::validate_offload_alias(alias)?;
        let host = self.query_instance_by_name(instance)?;
        if !host.is_stopped() {
            return Err(RuntimeError::new(
                SandboxErrorCode::StateConflict,
                "instance is not stopped",
            ));
        }
        let out = self.image_run(
            &[
                "publish",
                instance,
                "--alias",
                alias,
                "--compression",
                "zstd",
            ],
            IMAGE_IO_TIMEOUT,
        )?;
        require_success(&out, "publish")?;
        let fingerprint = fingerprint_after(&out.stdout, "fingerprint:").ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "publish printed no fingerprint",
            )
        })?;
        let resolved = self.resolve_image_ref(&fingerprint)?;
        Ok(crate::PublishedDisk {
            fingerprint: resolved.fingerprint,
            size_bytes: resolved.size_bytes,
        })
    }

    /// See `SandboxRuntime::delete_orphan_root`: `incus storage volume
    /// delete <pool> virtual-machine/<instance>` ([unverified]: the volume
    /// type path of a VM root), only with no instance of that name and only
    /// for a volume the pool's root census lists.
    pub fn delete_orphan_root(
        &self,
        root: &crate::RootDisk,
        instance: &str,
    ) -> Result<(), RuntimeError> {
        root.validate()?;
        validate_managed_instance_name(instance)?;
        self.observe_storage_pool(&root.pool)?;
        if self.instance_exists(instance)? {
            return Err(crate::storage::root_mismatch());
        }
        let census = self.storage_root_census(&root.pool)?;
        if !census.roots.iter().any(|r| r.instance_name == instance) {
            return Ok(());
        }
        let volume = format!("virtual-machine/{instance}");
        let out = self.image_run(
            &["storage", "volume", "delete", &root.pool.name, &volume],
            CAPTURE_STEP_TIMEOUT,
        )?;
        require_success(&out, "storage volume delete")
    }

    fn instance_document(&self, instance: &str) -> Result<serde_json::Value, RuntimeError> {
        self.query_raw(&instance_query_url(instance, &self.project)?)
    }

    /// See `SandboxRuntime::instance_last_used`.
    pub fn instance_last_used(&self, instance: &str) -> Result<Option<String>, RuntimeError> {
        crate::parse_last_used(&self.instance_document(instance)?)
    }

    /// See `SandboxRuntime::cloud_init_instance_id`.
    pub fn cloud_init_instance_id(&self, instance: &str) -> Result<Option<String>, RuntimeError> {
        crate::parse_cloud_init_instance_id(&self.instance_document(instance)?)
    }

    /// See `SandboxRuntime::instance_root_usage`.
    pub fn instance_root_usage(&self, instance: &str) -> Result<Option<u64>, RuntimeError> {
        validate_managed_instance_name(instance)?;
        let state = self.query_raw(&with_query_params(
            &format!("/1.0/instances/{}/state", percent_encode(instance)),
            &[("project", self.project.as_str())],
        ))?;
        crate::parse_root_usage(&state)
    }

    /// See `SandboxRuntime::offload_aliases`: this client's project only.
    pub fn offload_aliases(&self) -> Result<Vec<crate::OffloadAlias>, RuntimeError> {
        validate_incus_identifier(&self.project, "project")?;
        let list = self.query_raw(&with_query_params(
            "/1.0/images/aliases",
            &[("project", self.project.as_str()), ("recursion", "1")],
        ))?;
        crate::parse_offload_aliases(&list)
    }

    /// See `SandboxRuntime::instance_operation_running`.
    pub fn instance_operation_running(&self, instance: &str) -> Result<bool, RuntimeError> {
        validate_managed_instance_name(instance)?;
        validate_incus_identifier(&self.project, "project")?;
        let operations = self.query_raw(&with_query_params(
            "/1.0/operations",
            &[("project", self.project.as_str()), ("recursion", "1")],
        ))?;
        crate::parse_instance_operation_running(&operations, instance)
    }

    /// Freeze `/` in the guest with the fixed helper, run `work`, then thaw
    /// (stdin EOF). An already-frozen filesystem is left as it is (EBUSY).
    fn with_guest_frozen<T>(
        &self,
        instance: &str,
        work: impl FnOnce() -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        validate_incus_identifier(&self.project, "project")?;
        let mut command =
            crate::host_child::command(&self.binary, crate::host_child::Environment::Incus);
        command
            .args([
                "--project",
                &self.project,
                "exec",
                instance,
                "--user",
                "0",
                "--",
            ])
            .args(["python3", "-I", "-B", "-c", crate::FREEZE_HELPER]);
        untranslated(&mut command);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|_| {
            RuntimeError::new(SandboxErrorCode::Internal, "freeze helper did not start")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            RuntimeError::new(SandboxErrorCode::Internal, "freeze helper has no stdout")
        })?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let state = rx.recv_timeout(FREEZE_READY_TIMEOUT).unwrap_or_default();
        let frozen = state.trim() == "frozen";
        if !frozen && state.trim() != "busy" {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RuntimeError::new(
                SandboxErrorCode::GuestOperationFailed,
                "capture_freeze_failed: guest filesystem could not be frozen",
            ));
        }
        let result = work();
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(b"thaw\n");
        }
        let _ = child.wait();
        result
    }

    /// Whether an Incus object exists (`404` → absent); other errors are
    /// not evidence either way.
    fn capture_object_present(&self, path: &str) -> Result<bool, RuntimeError> {
        match self.query_raw(path) {
            Ok(_) => Ok(true),
            Err(err) if err.code == SandboxErrorCode::SandboxNotFound => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// One cleanup attempt, then proof of absence (P2-12): deletion errors
    /// are not trusted, the capture VM and the source snapshot must both be
    /// gone. `Err` means unresolved cleanup work remains.
    fn capture_cleanup(
        &self,
        sandbox: &str,
        vm: &str,
        snapshot: Option<&str>,
    ) -> Result<(), RuntimeError> {
        // VM first, then the snapshot (ZFS clone dependence).
        let _ = self.image_run(&["delete", vm, "--force"], CAPTURE_STEP_TIMEOUT);
        if let Some(snapshot) = snapshot {
            let _ = self.image_run(
                &["snapshot", "delete", sandbox, snapshot],
                CAPTURE_STEP_TIMEOUT,
            );
        }
        let project = percent_encode(&self.project);
        let vm_left = self.capture_object_present(&format!(
            "/1.0/instances/{}?project={project}",
            percent_encode(vm)
        ))?;
        let snapshot_left = match snapshot {
            Some(snapshot) => self.capture_object_present(&format!(
                "/1.0/instances/{}/snapshots/{}?project={project}",
                percent_encode(sandbox),
                percent_encode(snapshot)
            ))?,
            None => false,
        };
        if vm_left || snapshot_left {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "capture_cleanup_pending: capture VM or snapshot still present",
            ));
        }
        Ok(())
    }

    /// After a capture: retry the verified cleanup with backoff until it is
    /// proven. The operation (and with it the server's capture hold) stays
    /// open meanwhile; a daemon restart resumes through `discard_capture`.
    fn capture_cleanup_until_verified(&self, sandbox: &str, vm: &str, snapshot: Option<&str>) {
        let mut delay = CLEANUP_BACKOFF_START;
        while self.capture_cleanup(sandbox, vm, snapshot).is_err() {
            thread::sleep(delay);
            delay = (delay * 2).min(CLEANUP_BACKOFF_MAX);
        }
    }

    /// See `SandboxRuntime::discard_capture`: the snapshot delete is also
    /// attempted for a STOPPED capture (which made none); absence is fine,
    /// anything still present is an error (the receipt stays unresolved).
    pub fn discard_capture(
        &self,
        sandbox_id: &str,
        operation_id: &str,
    ) -> Result<(), RuntimeError> {
        let sandbox = crate::resolve_managed_instance_name(sandbox_id, None)?;
        let (vm, snapshot) = crate::capture_names(operation_id)?;
        validate_incus_identifier(&vm, "instance")?;
        self.capture_cleanup(&sandbox, &vm, Some(&snapshot))
    }

    /// See `SandboxRuntime::capture_template`.
    pub fn capture_template(
        &self,
        request: &crate::CaptureRequest,
        progress: &dyn Fn(crate::CapturePhase),
    ) -> Result<crate::CaptureOutcome, RuntimeError> {
        let sandbox = crate::resolve_managed_instance_name(&request.sandbox_id, None)?;
        let (vm, snapshot) = crate::capture_names(&request.operation_id)?;
        validate_incus_identifier(&vm, "instance")?;
        // Login paths fail closed before any effect.
        crate::credential_scrub_targets(&request.guest_home, &request.credential_scrub_paths)?;
        // A restart that left a half-built capture: start over cleanly, and
        // never build on leftovers that could not be removed.
        self.capture_cleanup(
            &sandbox,
            &vm,
            (!request.stopped).then_some(snapshot.as_str()),
        )?;
        let result = self.capture_steps(request, progress, &sandbox, &vm, &snapshot);
        self.capture_cleanup_until_verified(
            &sandbox,
            &vm,
            (!request.stopped).then_some(snapshot.as_str()),
        );
        result
    }

    fn capture_steps(
        &self,
        request: &crate::CaptureRequest,
        progress: &dyn Fn(crate::CapturePhase),
        sandbox: &str,
        vm: &str,
        snapshot: &str,
    ) -> Result<crate::CaptureOutcome, RuntimeError> {
        let source = if request.stopped {
            sandbox.to_owned()
        } else {
            progress(crate::CapturePhase::Freezing);
            self.with_guest_frozen(sandbox, || {
                progress(crate::CapturePhase::Snapshotting);
                let out = self.image_run(
                    &["snapshot", "create", sandbox, snapshot],
                    CAPTURE_STEP_TIMEOUT,
                )?;
                require_success(&out, "snapshot create")
            })?;
            format!("{sandbox}/{snapshot}")
        };
        progress(crate::CapturePhase::Copying);
        let out = self.image_run(
            &["copy", &source, vm, "--instance-only", "--no-profiles"],
            IMAGE_IO_TIMEOUT,
        )?;
        require_success(&out, "copy")?;
        // No network in the capture VM, a small fixed size, no wssp metadata.
        let instance = self.query_raw(&format!(
            "/1.0/instances/{}?project={}",
            percent_encode(vm),
            percent_encode(&self.project)
        ))?;
        if let Some(devices) = instance.get("devices").and_then(|d| d.as_object()) {
            for (name, device) in devices {
                if device.get("type").and_then(|t| t.as_str()) == Some("nic") {
                    validate_incus_identifier(name, "device")?;
                    let out = self.image_run(
                        &["config", "device", "remove", vm, name],
                        CAPTURE_STEP_TIMEOUT,
                    )?;
                    require_success(&out, "device remove")?;
                }
            }
        }
        if let Some(config) = instance.get("config").and_then(|c| c.as_object()) {
            for key in config.keys().filter(|k| k.starts_with("user.")) {
                let _ = self.image_run(&["config", "unset", vm, key], CAPTURE_STEP_TIMEOUT);
            }
        }
        for (key, value) in [("limits.cpu", "1"), ("limits.memory", "1024MiB")] {
            let out = self.image_run(&["config", "set", vm, key, value], CAPTURE_STEP_TIMEOUT)?;
            require_success(&out, "config set")?;
        }
        // One wssp daemon per Incus server: rechecked at the start itself;
        // the capture may have run for minutes since its entry check.
        crate::guard_probe::refuse_shared_incus_server(self.guard_probe.as_ref())?;
        let out = self.image_run(&["start", vm], CAPTURE_STEP_TIMEOUT)?;
        require_success(&out, "start")?;
        self.capture_vm_settle(vm)?;
        progress(crate::CapturePhase::Scrubbing);
        let manifest = crate::scrub_manifest()?;
        let (delete, truncate) =
            crate::scrub_paths(&manifest, &request.guest_home, &request.extra_scrub_paths);
        let credentials =
            crate::credential_scrub_targets(&request.guest_home, &request.credential_scrub_paths)?;
        let count = truncate.len().to_string();
        let mut args: Vec<&str> = vec![
            "exec",
            vm,
            "--user",
            "0",
            "--",
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            crate::SCRUB_HELPER,
            "freeze",
            &count,
        ];
        args.extend(truncate.iter().map(String::as_str));
        args.extend(delete.iter().map(String::as_str));
        if !credentials.is_empty() {
            args.push(crate::CREDENTIAL_SCRUB_SEPARATOR);
            args.extend(credentials.iter().map(String::as_str));
        }
        let out = self.image_run(&args, CAPTURE_STEP_TIMEOUT)?;
        if out.exit_code != 0 {
            let error = host_cli_error("scrub", &out);
            // Only the fixed manifest's own paths may be named (never the
            // request's extra or credential paths, never an expansion).
            let (fixed_delete, fixed_truncate) =
                crate::scrub_paths(&manifest, &request.guest_home, &[]);
            let fixed: Vec<String> = fixed_delete.into_iter().chain(fixed_truncate).collect();
            return Err(match scrub_failure_summary(&out.stdout, &fixed) {
                Some(summary) => {
                    RuntimeError::new(error.code, format!("{} ({summary})", error.message))
                }
                None => error,
            });
        }
        let symlinked_paths = serde_json::from_str::<serde_json::Value>(out.stdout.trim())
            .ok()
            .and_then(|v| v.get("symlinked").cloned())
            .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
            .unwrap_or_default();
        // The scrub left every guest task frozen by the cgroup v2 freezer,
        // PID 1 included, after scrubbing, syncing and verifying while
        // frozen (round-3 P1-1). Nothing thaws them: a clean shutdown would,
        // so the VM is powered off instead. Nothing else runs in the guest
        // after the verification (round-4 P1): a guest binary run by the
        // unfrozen agent (even `sync`) could undo what it proved.
        let out = self.image_run(&["stop", vm, "--force"], CAPTURE_STEP_TIMEOUT)?;
        require_success(&out, "stop")?;
        progress(crate::CapturePhase::Publishing);
        // And again before the publish writes the shared image store.
        crate::guard_probe::refuse_shared_incus_server(self.guard_probe.as_ref())?;
        let out = self.image_run(&["publish", vm, "--compression", "zstd"], IMAGE_IO_TIMEOUT)?;
        require_success(&out, "publish")?;
        let fingerprint = fingerprint_after(&out.stdout, "fingerprint:").ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "publish printed no fingerprint",
            )
        })?;
        let resolved = self.resolve_image_ref(&fingerprint)?;
        Ok(crate::CaptureOutcome {
            fingerprint: resolved.fingerprint,
            size_bytes: resolved.size_bytes.unwrap_or(0),
            architecture: resolved.architecture,
            symlinked_paths,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{IMAGE_INVENTORY_MAX, fingerprint_after, parse_image_inventory};

    #[test]
    fn image_inventory_yields_journal_fingerprints_and_fails_closed() {
        let hex = "ab".repeat(32);
        let other = "cd".repeat(32);
        let list = serde_json::json!([
            format!("/1.0/images/{hex}"),
            format!("/1.0/images/{other}?project=wssp"),
        ]);
        assert_eq!(
            parse_image_inventory(&list).expect("inventory"),
            [format!("sha256:{hex}"), format!("sha256:{other}")].into()
        );
        assert!(
            parse_image_inventory(&serde_json::json!([]))
                .expect("empty")
                .is_empty()
        );
        for bad in [
            serde_json::json!({}),
            serde_json::json!([format!("/1.0/images/{hex}"), 7]),
            serde_json::json!([format!("/1.0/instances/{hex}")]),
            serde_json::json!(["/1.0/images/xyz"]),
            serde_json::json!([format!("/1.0/images/{}", "AB".repeat(32))]),
        ] {
            assert!(parse_image_inventory(&bad).is_err(), "{bad}");
        }
        let huge = serde_json::Value::Array(vec![
            serde_json::json!(format!("/1.0/images/{hex}"));
            IMAGE_INVENTORY_MAX + 1
        ]);
        assert!(parse_image_inventory(&huge).is_err());
    }

    #[test]
    fn parses_import_and_publish_fingerprints() {
        let hex = "ab".repeat(32);
        assert_eq!(
            fingerprint_after(
                &format!("Image imported with fingerprint: {hex}\n"),
                "fingerprint:"
            ),
            Some(format!("sha256:{hex}"))
        );
        assert_eq!(
            fingerprint_after(
                &format!("Instance published with fingerprint: {hex}"),
                "fingerprint:"
            ),
            Some(format!("sha256:{hex}"))
        );
        assert_eq!(fingerprint_after("Image imported", "fingerprint:"), None);
        assert_eq!(fingerprint_after("fingerprint: xyz", "fingerprint:"), None);
    }
}
