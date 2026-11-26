//! Chunked guest IO. A put is ONE guest invocation whose rename is fenced by a
//! byte the host writes only while holding the current RuntimePermit.
use super::client::{BoundInstance, IncusClient, IncusCommandOutput};
use super::effect_completion;
use crate::before_issue::incus as pre;
use crate::{EffectOutcome, FILE_MAX_BYTES, FileContent, FileStaging, RuntimeError};
use sandbox_protocol::SandboxErrorCode;
use std::io::{BufRead, Read, Write};
use std::os::{fd::OwnedFd, unix::net::UnixStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(super) const HELPER: &str = include_str!("file-helper.py");
/// Upper bound for a refused fence to be confirmed by the guest helper.
const FENCE_REFUSAL_GRACE: Duration = Duration::from_secs(5);
fn error(_message: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::UnknownOutcome,
        "guest file IO did not complete",
    )
    .filesystem(sandbox_protocol::results::FailureEffect::Unknown)
}
/// Guest staging identity of one attempt: `.wssp-upload-<token>`. Derived, not
/// random, so recovery after a host crash addresses exactly this attempt.
pub(crate) fn transfer_token(operation_id: &str, generation: u64, attempt: u64) -> String {
    ring::digest::digest(
        &ring::digest::SHA256,
        format!("wssp-file-put\0{operation_id}\0{generation}\0{attempt}").as_bytes(),
    )
    .as_ref()
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect()
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fence {
    /// The helper has not asked, or the host has not answered yet.
    Pending,
    /// `C` was written while the permit was current; a rename may follow.
    Issued,
    /// A local write/flush failed after the attempt began. This cannot prove
    /// either that C was delivered or that no mutation was admitted.
    PossiblyIssued,
    /// EOF instead of `C`: the guest helper can only abort.
    Refused,
}
#[derive(Debug)]
pub(super) struct PutRun {
    pub fence: Fence,
    /// The local process group was killed (timeout, or revocation after the
    /// fence was issued, or refusal while payload was still streaming).
    pub interrupted: bool,
    pub output: IncusCommandOutput,
    pub body: Vec<u8>,
}
impl IncusClient {
    fn file_command(
        &self,
        bound: &BoundInstance,
        mode: &str,
        path: &str,
        token: &str,
        size: u64,
        digest: &str,
    ) -> Result<Command, RuntimeError> {
        self.refresh_binding(bound)?;
        if matches!(
            mode,
            "stat" | "list" | "mkdir" | "ensure-dir" | "remove" | "rename"
        ) {
            crate::canonical_metadata_path(
                path,
                matches!(mode, "mkdir" | "ensure-dir" | "remove" | "rename"),
            )?;
        } else {
            crate::metadata::validate_file_path(path)?;
        }
        let mut command =
            crate::host_child::command(&self.binary, crate::host_child::Environment::Incus);
        command.args(["--project", &self.project, "exec", bound.name(), "-T"]);
        command.args(self.guest_exec_args(None)?);
        // Isolated mode: the guest home is the writable cwd, and `-c` would
        // otherwise search it for imports. A guest-writable `hashlib.py` must
        // never turn a files-only grant into code execution.
        command.args([
            "--",
            "python3",
            "-I",
            "-c",
            HELPER,
            mode,
            path,
            token,
            &size.to_string(),
            digest,
        ]);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Ok(command)
    }
    /// Control-sized metadata has its own fixed memory bound. It must not
    /// consume the byte-transfer disk/slot quota (which may all be retained).
    fn metadata_io(
        &self,
        bound: &BoundInstance,
        mut command: Command,
    ) -> Result<(Vec<u8>, IncusCommandOutput), RuntimeError> {
        let mut child = self
            .spawn_guest(bound, &mut command)
            .map_err(crate::EffectError::into_error)?;
        let stdout = child.stdout.take().ok_or_else(|| error("missing stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| error("missing stderr"))?;
        let reader = std::thread::spawn(move || read_metadata(stdout));
        let diagnostics = std::thread::spawn(move || {
            let mut bytes = Vec::with_capacity(16 * 1024 + 1);
            stderr
                .take(16 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(error)?;
            String::from_utf8(bytes).map_err(|_| crate::metadata::invalid())
        });
        let deadline = Instant::now() + crate::metadata::observation_budgets(self.agent_timeout).0;
        let outcome = loop {
            if self.cancelled.as_ref().is_some_and(|p| p.is_cancelled())
                || Instant::now() >= deadline
            {
                break Err(error("metadata capture interrupted"));
            }
            match child.try_wait() {
                Ok(Some(status)) if reader.is_finished() && diagnostics.is_finished() => {
                    break Ok(status);
                }
                Ok(_) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break Err(error("metadata capture failed")),
            }
        };
        if outcome.is_err() {
            super::client::kill_process_group(child.id());
        }
        let _ = child.wait();
        // Join both readers on every outcome; inherited pipes are bounded by
        // the local process-group teardown and fixed observation deadline.
        let bytes = reader.join().map_err(|_| error("metadata reader failed"));
        let stderr = diagnostics
            .join()
            .map_err(|_| error("metadata diagnostics failed"));
        let status = outcome?;
        Ok((
            bytes??,
            IncusCommandOutput {
                stdout: String::new(),
                stderr: stderr??,
                exit_code: status.code().unwrap_or(-1),
            },
        ))
    }
    fn metadata_observe(
        &self,
        bound: &BoundInstance,
        mode: &str,
        path: &str,
        options: &serde_json::Value,
    ) -> Result<crate::metadata::GuestFileResult, RuntimeError> {
        let token = super::client::random_nonce()?;
        let token = format!("{token}{token}");
        let command = self.file_command(bound, mode, path, &token, 0, &options.to_string())?;
        let (bytes, out) = self.metadata_io(bound, command).map_err(read_only)?;
        if out.stderr != format!("WSSP_STATUS {token} ok\n") || out.exit_code != 0 {
            return Err(read_only(
                metadata_failure(&token, &out)
                    .unwrap_or_else(|| self.observation_plane_failure(bound)),
            ));
        }
        decode_metadata(&bytes)
    }
    pub fn guest_stat(
        &self,
        bound: &BoundInstance,
        path: &str,
    ) -> Result<crate::EntryInfo, RuntimeError> {
        let path = crate::canonical_metadata_path(path, false)?;
        let response = self.metadata_observe(bound, "stat", &path, &serde_json::json!({}))?;
        match response.result {
            sandbox_protocol::results::ResultBody::Stat { entry }
                if response.continuation.is_none() && entry.validate() && entry.path == path =>
            {
                Ok(entry)
            }
            _ => Err(crate::metadata::invalid()),
        }
    }
    pub fn guest_list_page(
        &self,
        bound: &BoundInstance,
        request: &crate::ListDirRequest,
    ) -> Result<crate::ListDirResponse, RuntimeError> {
        let root = request.validate_page()?;
        let budget = crate::metadata::observation_budgets(self.agent_timeout).1;
        let options = serde_json::json!({"depth": request.depth, "limit": request.limit, "generation": request.generation, "lastKey": request.continuation.as_ref().map(|c| &c.last_key), "budgetMs": budget.as_millis() as u64});
        let response = self.metadata_observe(bound, "list", &root, &options)?;
        match response.result {
            sandbox_protocol::results::ResultBody::List {
                path,
                depth,
                items,
                next_cursor: None,
                ..
            } => {
                let page = crate::ListDirResponse {
                    path,
                    depth,
                    items,
                    continuation: response.continuation,
                };
                crate::metadata::validate_page(request, &page)?;
                Ok(page)
            }
            _ => Err(crate::metadata::invalid()),
        }
    }
    fn metadata_mutation(
        &self,
        bound: &BoundInstance,
        mode: &str,
        path: &str,
        options: serde_json::Value,
    ) -> EffectOutcome<sandbox_protocol::results::ResultBody> {
        // B2-C-6: everything before the guest spawn is a definite refusal.
        let (path, token, command) = pre::phase(
            |before| {
                let path = pre::metadata_path(&before, path, true)?;
                if mode == "rename" {
                    pre::metadata_path(&before, options["destPath"].as_str().unwrap_or(""), true)?;
                }
                let token =
                    super::client::random_nonce().map_err(crate::before_issue::not_issued)?;
                let token = format!("{token}{token}");
                let command = self
                    .file_command(bound, mode, &path, &token, 0, &options.to_string())
                    .map_err(crate::before_issue::not_issued)?;
                before.issue(|| Ok((path, token, command)))
            },
            Ok,
        )?;
        let run = self.mutation_io(bound, command, None, &token)?;
        if let Some(refusal) = host_refusal(&token, &run) {
            return Err(refusal);
        }
        let proof = put_outcome(&token, &path, &run)?;
        // Parsing failure AFTER the fence/completion cannot turn into a safe
        // retry. Rename's metadata must come from this very helper invocation.
        let response =
            decode_metadata(&run.body).map_err(|_| error("invalid mutation response"))?;
        if response.continuation.is_some() {
            return Err(error("unexpected continuation").into());
        }
        let valid = match (&response.result, mode) {
            (sandbox_protocol::results::ResultBody::Mkdir { .. }, "mkdir" | "ensure-dir") => true,
            (sandbox_protocol::results::ResultBody::Remove { removed: true }, "remove") => true,
            (sandbox_protocol::results::ResultBody::Rename { entry }, "rename") => {
                entry.validate()
                    && options["destPath"]
                        .as_str()
                        .and_then(|p| crate::canonical_metadata_path(p, true).ok())
                        .is_some_and(|p| p == entry.path)
            }
            _ => false,
        };
        if !valid {
            return Err(error("invalid mutation metadata").into());
        }
        Ok(proof.map(|()| response.result))
    }
    pub fn guest_mkdir(
        &self,
        bound: &BoundInstance,
        path: &str,
    ) -> EffectOutcome<crate::MkdirResponse> {
        let proof = self.metadata_mutation(bound, "mkdir", path, serde_json::json!({}))?;
        let created = match &*proof {
            sandbox_protocol::results::ResultBody::Mkdir { created } => *created,
            _ => return Err(error("invalid mkdir response").into()),
        };
        Ok(proof.map(|_| crate::MkdirResponse { created }))
    }
    /// Readiness only: `$HOME/repo` is template layout, so this keeps
    /// `mkdir -p` follow semantics (B2-K-3) inside the same
    /// permit-fenced mutation executor. User-API mkdir never follows links.
    pub fn guest_ensure_directory(
        &self,
        bound: &BoundInstance,
        path: &str,
    ) -> EffectOutcome<crate::MkdirResponse> {
        let proof = self.metadata_mutation(bound, "ensure-dir", path, serde_json::json!({}))?;
        let created = match &*proof {
            sandbox_protocol::results::ResultBody::Mkdir { created } => *created,
            _ => return Err(error("invalid mkdir response").into()),
        };
        Ok(proof.map(|_| crate::MkdirResponse { created }))
    }
    pub fn guest_remove(
        &self,
        bound: &BoundInstance,
        path: &str,
        recursive: bool,
    ) -> EffectOutcome<crate::RemovePathResponse> {
        let proof = self.metadata_mutation(
            bound,
            "remove",
            path,
            serde_json::json!({"recursive":recursive}),
        )?;
        Ok(proof.map(|_| crate::RemovePathResponse { removed: true }))
    }
    pub fn guest_move(
        &self,
        bound: &BoundInstance,
        from: &str,
        to: &str,
    ) -> EffectOutcome<crate::EntryInfo> {
        let proof =
            self.metadata_mutation(bound, "rename", from, serde_json::json!({"destPath":to}))?;
        let entry = match &*proof {
            sandbox_protocol::results::ResultBody::Rename { entry } => entry.clone(),
            _ => return Err(error("invalid rename response").into()),
        };
        Ok(proof.map(|_| entry))
    }
    fn file_io(
        &self,
        bound: &BoundInstance,
        mut command: Command,
        limit: u64,
        input: Option<FileContent>,
        creator: &str,
    ) -> Result<(Option<FileContent>, IncusCommandOutput), RuntimeError> {
        let capture = (limit > 0)
            .then(|| FileStaging::for_creator(limit, creator))
            .transpose()?;
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = self
            .spawn_guest(bound, &mut command)
            .map_err(crate::EffectError::into_error)?;
        let input_worker = input.map(|content| {
            let stdin = child.stdin.take();
            std::thread::spawn(move || match stdin {
                Some(mut stdin) => std::io::copy(&mut content.reader(), &mut stdin)
                    .map(|_| ())
                    .map_err(error),
                None => Err(error("missing stdin")),
            })
        });
        let stdout = child.stdout.take().ok_or_else(|| error("missing stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| error("missing stderr"))?;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let result = if let Some(mut capture) = capture {
                std::io::copy(&mut stdout.take(limit + 1), &mut capture)
                    .map_err(error)
                    .and_then(|_| capture.seal(None))
                    .map(Some)
            } else {
                let mut byte = [0];
                match stdout.take(1).read(&mut byte) {
                    Ok(0) => Ok(None),
                    _ => Err(error("unexpected helper output")),
                }
            };
            let _ = tx.send(result);
        });
        let diagnostics = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.take(16 * 1024).read_to_end(&mut bytes);
            bytes
        });
        let deadline = Instant::now() + self.agent_timeout;
        let outcome = loop {
            if self.cancelled.as_ref().is_some_and(|p| p.is_cancelled())
                || Instant::now() >= deadline
            {
                break Err(error("cancelled or timed out"));
            }
            match child.try_wait() {
                Ok(Some(status)) if reader.is_finished() && diagnostics.is_finished() => {
                    break Ok(status);
                }
                Ok(Some(_)) => std::thread::sleep(Duration::from_millis(10)),
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => break Err(error(e)),
            }
        };
        // Kill the local process group also on leader exit; inherited pipes cannot
        // strand a reader. No runtime/authority lock is held across these waits.
        if outcome.is_err() {
            super::client::kill_process_group(child.id());
        }
        let _ = child.wait();
        let _ = reader.join();
        if let Some(worker) = input_worker {
            worker.join().map_err(|_| error("input reader failed"))??;
        }
        let stderr = diagnostics
            .join()
            .map_err(|_| error("stderr reader failed"))?;
        let status = outcome?;
        let bytes = rx.recv().map_err(error)??;
        Ok((
            bytes,
            IncusCommandOutput {
                stdout: String::new(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
                exit_code: status.code().unwrap_or(-1),
            },
        ))
    }
    /// Runs one fenced `put` helper. The fence byte is written only while an
    /// admission guard of the current RuntimePermit is held (a local pipe write
    /// of one byte, never a guest wait), so a revocation that wins the permit
    /// lock first leaves the helper nothing to do but remove its staging file.
    pub(super) fn put_io(
        &self,
        bound: &BoundInstance,
        command: Command,
        content: FileContent,
        token: &str,
    ) -> Result<PutRun, crate::EffectError> {
        self.mutation_io(bound, command, Some(content), token)
    }
    /// All metadata mutations and byte puts share the SAME commit admission.
    pub(super) fn mutation_io(
        &self,
        bound: &BoundInstance,
        mut command: Command,
        content: Option<FileContent>,
        token: &str,
    ) -> Result<PutRun, crate::EffectError> {
        let revoked = || self.cancelled.as_ref().is_some_and(|p| p.is_cancelled());
        // A socket supplies a safe std-only nonblocking writer. A hostile
        // guest can forge READY without draining stdin; C must NEVER block
        // while the permit guard is held. Framing remains the same byte stream.
        // Nothing has been spawned yet: a local failure here is a refusal.
        let (stdin, guest_stdin) =
            UnixStream::pair().map_err(|e| crate::before_issue::not_issued(error(e)))?;
        command
            .stdin(Stdio::from(OwnedFd::from(guest_stdin)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // B2-C-6: an admission refusal keeps its NotIssued evidence.
        let mut child = self.spawn_guest(bound, &mut command)?;
        // Command owns the parent copy of the guest socket endpoint. Close it
        // now, so terminating the child also wakes a blocked payload writer.
        drop(command);
        let stdout = child.stdout.take().ok_or_else(|| error("missing stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| error("missing stderr"))?;
        // The payload writer hands stdin back so only this owner can answer
        // the fence, and only after every payload byte was written. With no
        // payload the owner holds stdin from the start: no handoff can race
        // a refusal into an interrupted run.
        let (input_tx, input_rx) = std::sync::mpsc::sync_channel(1);
        let mut writer: Option<UnixStream> = None;
        let mut input_done = false;
        let input = match content {
            Some(content) => Some(std::thread::spawn(move || {
                let mut stdin = stdin;
                let written = std::io::copy(&mut content.reader(), &mut stdin).map(|_| stdin);
                let _ = input_tx.send(written);
            })),
            None => {
                writer = Some(stdin);
                input_done = true;
                None
            }
        };
        let expected = format!("WSSP_COMMIT_READY {token}\n");
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let output = std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = Vec::new();
            let _ = (&mut reader).take(256).read_until(b'\n', &mut line);
            let _ = ready_tx.send(line == expected.as_bytes());
            let mut rest = Vec::new();
            let _ = reader
                .take(crate::metadata::HOST_RESULT_MAX_BYTES as u64 + 1)
                .read_to_end(&mut rest);
            rest
        });
        let diagnostics = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.take(16 * 1024).read_to_end(&mut bytes);
            bytes
        });
        let deadline = Instant::now() + self.agent_timeout;
        let mut ready = false;
        let mut fence = Fence::Pending;
        let mut grace: Option<Instant> = None;
        let mut interrupted = false;
        let status = loop {
            if !input_done {
                match input_rx.try_recv() {
                    Ok(Ok(handle)) => {
                        writer = Some(handle);
                        input_done = true;
                    }
                    Ok(Err(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        input_done = true;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
            }
            if !ready {
                ready = ready_rx.try_recv().unwrap_or(false);
            }
            if fence == Fence::Pending && revoked() {
                fence = Fence::Refused;
            }
            if fence == Fence::Pending
                && ready
                && let Some(handle) = writer.as_mut()
            {
                #[cfg(test)]
                if let Some(hook) = &self.mutation_commit_hook {
                    (hook.0)();
                }
                fence = issue_commit(handle, self.cancelled.as_deref());
                drop(writer.take());
            }
            if fence == Fence::Refused && grace.is_none() {
                // EOF instead of the fence byte. Wait (bounded) for the helper's
                // own record that it removed the staging file.
                drop(writer.take());
                if !input_done {
                    interrupted = true;
                    break None;
                }
                grace = Some((Instant::now() + FENCE_REFUSAL_GRACE).min(deadline));
            }
            if (matches!(fence, Fence::Issued | Fence::PossiblyIssued) && revoked())
                || Instant::now() >= deadline
                || grace.is_some_and(|until| Instant::now() >= until)
            {
                interrupted = true;
                break None;
            }
            match child.try_wait() {
                Ok(Some(status)) if output.is_finished() && diagnostics.is_finished() => {
                    break Some(status);
                }
                Ok(_) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => {
                    interrupted = true;
                    break None;
                }
            }
        };
        drop(writer.take());
        if interrupted {
            super::client::kill_process_group(child.id());
        }
        let _ = child.wait();
        if let Some(input) = input {
            let _ = input.join();
        }
        let rest = output.join().unwrap_or_default();
        let stderr = diagnostics.join().unwrap_or_default();
        Ok(PutRun {
            fence,
            interrupted,
            output: IncusCommandOutput {
                stdout: String::new(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
                exit_code: status.and_then(|s| s.code()).unwrap_or(-1),
            },
            body: rest,
        })
    }
    /// Test/diagnostic entry with a random staging identity. Production writes
    /// use `IncusClient::file_put` with the attempt-derived token.
    pub fn file_push(
        &self,
        bound: &BoundInstance,
        path: &str,
        bytes: &FileContent,
    ) -> EffectOutcome<()> {
        let token = super::client::random_nonce()?;
        self.file_put(bound, path, bytes, &format!("{token}{token}"))
    }
    pub(crate) fn file_put(
        &self,
        bound: &BoundInstance,
        path: &str,
        bytes: &FileContent,
        token: &str,
    ) -> EffectOutcome<()> {
        // TQ-HOST1: an invalid destination is refused before any guest
        // invocation, so it is a definite NotIssued failure (FAILED), never
        // an uncertain post-issue observation like the IO below.
        pre::phase(
            |before| {
                pre::file_path(&before, path)?;
                before.issue(|| Ok(()))
            },
            Ok,
        )?;
        let command = self.file_command(
            bound,
            "put",
            path,
            token,
            bytes.len() as u64,
            bytes.digest(),
        )?;
        let run = self.put_io(bound, command, bytes.clone(), token)?;
        put_outcome(token, path, &run)
    }
    pub fn file_pull(
        &self,
        bound: &BoundInstance,
        path: &str,
    ) -> Result<FileContent, RuntimeError> {
        self.file_pull_for_creator(bound, path, "local")
    }
    pub(crate) fn file_pull_for_creator(
        &self,
        bound: &BoundInstance,
        path: &str,
        creator: &str,
    ) -> Result<FileContent, RuntimeError> {
        let token = super::client::random_nonce()?;
        let token = format!("{token}{token}");
        let command = self.file_command(bound, "read", path, &token, FILE_MAX_BYTES, "")?;
        let (bytes, out) = self
            .file_io(bound, command, FILE_MAX_BYTES, None, creator)
            .map_err(read_only)?;
        if out.stderr != format!("WSSP_STATUS {token} ok\n") || out.exit_code != 0 {
            return Err(read_only(
                metadata_failure(&token, &out)
                    .unwrap_or_else(|| self.observation_plane_failure(bound)),
            ));
        }
        bytes.ok_or_else(|| read_only(error("missing capture")))
    }
    /// Recovery never needs the lost host process: the staging name is derived
    /// from the attempt and removing it makes that attempt's rename impossible.
    pub(crate) fn recover_put(
        &self,
        bound: &BoundInstance,
        request: &crate::RecoverFilePutRequest,
    ) -> EffectOutcome<()> {
        crate::metadata::validate_file_path(&request.path)?;
        let token = transfer_token(&request.operation_id, request.generation, request.attempt);
        let out = self.exec_argv(
            bound,
            &[
                "python3".into(),
                // Isolated mode, as in `file_command`: never import from the
                // writable guest home during recovery either.
                "-I".into(),
                "-c".into(),
                HELPER.into(),
                "recover".into(),
                request.path.clone(),
                token.clone(),
                request.size.to_string(),
                request.sha256.clone(),
            ],
        )?;
        effect_completion::recovery_outcome(&token, &out, &request.path)
            .map_err(crate::EffectError::from)
    }
}

fn read_metadata(reader: impl Read) -> Result<Vec<u8>, RuntimeError> {
    let cap = crate::metadata::HOST_RESULT_MAX_BYTES;
    let mut bytes = Vec::with_capacity(cap + 1);
    reader
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() > cap {
        return Err(crate::metadata::invalid());
    }
    Ok(bytes)
}

fn issue_commit(writer: &mut UnixStream, permit: Option<&crate::RuntimePermit>) -> Fence {
    if writer.set_nonblocking(true).is_err() {
        return Fence::Refused;
    }
    let guard = match permit.map(|p| p.admit()).transpose() {
        Ok(guard) => guard,
        Err(_) => return Fence::Refused,
    };
    let written = writer.write_all(b"C").and_then(|()| writer.flush());
    drop(guard);
    match written {
        Ok(()) => Fence::Issued,
        Err(_) => Fence::PossiblyIssued,
    }
}

/// The helper's own failure record, a malformed one (`protocol_error`), or
/// `None` for plane loss, which the caller re-observes on the host (B2-K-2).
///
/// B2R2-C-4: plane loss includes a well-formed first record that the
/// transport then contradicted: a trailing line after it (`incus exec`'s own
/// `Error: ...`) or an exit status that disagrees with it (the agent dropped
/// after the helper wrote it). Only a record that is itself malformed, or one
/// that is not the first line, is `protocol_error`.
fn metadata_failure(token: &str, out: &IncusCommandOutput) -> Option<RuntimeError> {
    match effect_completion::file_status(token, out) {
        Some(effect_completion::FileStatus::Failed(failure)) => return Some(failure),
        Some(effect_completion::FileStatus::Ok) => return Some(crate::metadata::invalid()),
        None => {}
    }
    let prefix = format!("WSSP_STATUS {token} ");
    if !out.stderr.contains(prefix.trim_end()) {
        return None;
    }
    let first = out.stderr.split_inclusive('\n').next().unwrap_or_default();
    let alone = IncusCommandOutput {
        stdout: String::new(),
        stderr: first.to_owned(),
        exit_code: if first == format!("{prefix}ok\n") {
            0
        } else {
            1
        },
    };
    match effect_completion::file_status(token, &alone) {
        Some(_) => None,
        None => Some(crate::metadata::invalid()),
    }
}

/// B2-T-1: a read-only observation (stat, list, read) never changes the
/// guest filesystem, whatever effect a hostile guest record claims.
fn read_only(error: RuntimeError) -> RuntimeError {
    if error.failure().is_some() {
        error.filesystem(sandbox_protocol::results::FailureEffect::None)
    } else {
        error
    }
}

fn decode_metadata(bytes: &[u8]) -> Result<crate::metadata::GuestFileResult, RuntimeError> {
    if bytes.len() > crate::metadata::HOST_RESULT_MAX_BYTES {
        return Err(crate::metadata::invalid());
    }
    serde_json::from_slice(bytes).map_err(|_| crate::metadata::invalid())
}

/// B2-C-1: a fence the HOST refused (permit revoked or closed after spawn,
/// before `C`) is runtime work preemption, never the guest's own `cancelled`
/// and never a cleanup-authorizing guest failure. The helper's nonce-bound
/// `cancelled` record only confirms the refusal and its effect.
pub(super) fn host_refusal(token: &str, run: &PutRun) -> Option<crate::EffectError> {
    if run.fence != Fence::Refused || run.interrupted {
        return None;
    }
    effect_completion::preempted_refusal(token, &run.output).map(crate::EffectError::from)
}

/// Positive completion requires the issued fence and the helper's `ok` record.
/// A helper failure record is authored only before rename. Every interrupted
/// run after the fence, or without a record, is unknown — never success.
pub(super) fn put_outcome(token: &str, path: &str, run: &PutRun) -> EffectOutcome<()> {
    if run.interrupted && matches!(run.fence, Fence::Issued | Fence::PossiblyIssued) {
        return Err(error("interrupted after the commit fence was issued").into());
    }
    match effect_completion::helper_outcome(token, &run.output, "write", path) {
        Ok(done) if run.fence == Fence::Issued && !run.interrupted => Ok(done),
        Ok(_) => Err(error("helper reported success without an issued commit fence").into()),
        Err(failure) => Err(crate::EffectError::from(failure)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    /// Runs the real helper locally. `stdin` is written in full, then closed.
    fn helper(
        mode: &str,
        path: &std::path::Path,
        token: &str,
        size: usize,
        expected: &str,
        stdin: &[u8],
    ) -> std::process::Output {
        let mut child = Command::new("python3")
            .args([
                "-I",
                "-c",
                HELPER,
                mode,
                path.to_str().unwrap(),
                token,
                &size.to_string(),
                expected,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let _ = input.write_all(stdin);
        drop(input);
        child.wait_with_output().unwrap()
    }
    fn put(path: &std::path::Path, token: &str, bytes: &[u8], digest: &str, go: &[u8]) -> bool {
        helper(
            "put",
            path,
            token,
            bytes.len(),
            digest,
            &[bytes, go].concat(),
        )
        .status
        .success()
    }
    /// The helper's cwd is the writable guest home, and `python3 -c` would put
    /// it on `sys.path`. Isolated mode must ignore a hostile module shadow so a
    /// files-only grant cannot become code execution.
    #[test]
    fn helper_isolated_mode_ignores_guest_writable_module_shadows() {
        let dir = std::env::temp_dir().join(format!(
            "wssp-shadow-{}",
            super::super::client::random_nonce().unwrap()
        ));
        fs::create_dir(&dir).unwrap();
        let marker = dir.join("pwned");
        fs::write(
            dir.join("hashlib.py"),
            format!(
                "import pathlib\npathlib.Path({:?}).write_text('pwned')\n",
                marker.to_string_lossy()
            ),
        )
        .unwrap();
        let path = dir.join("target");
        let bytes = b"shadowed imports never run";
        let hash = FileContent::from_bytes(bytes).unwrap();
        let token = "c".repeat(64);
        for mode in ["put", "recover"] {
            let stdin: &[u8] = if mode == "put" {
                &[&bytes[..], b"C"].concat()
            } else {
                b""
            };
            let out = Command::new("python3")
                .args([
                    "-I",
                    "-c",
                    HELPER,
                    mode,
                    path.to_str().unwrap(),
                    &token,
                    &bytes.len().to_string(),
                    hash.digest(),
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .current_dir(&dir)
                .spawn()
                .and_then(|mut child| {
                    if let Some(mut pipe) = child.stdin.take() {
                        let _ = pipe.write_all(stdin);
                    }
                    child.wait_with_output()
                })
                .unwrap();
            assert!(
                out.status.success(),
                "{mode}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(!marker.exists(), "{mode}: guest module shadow executed");
        }
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn atomic_guest_helper_preserves_destination_on_bad_hash_and_rejects_path_attacks() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!(
            "wssp-helper-{}",
            super::super::client::random_nonce().unwrap()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("target");
        fs::write(&path, b"old").unwrap();
        let bytes = b"\0\xff\xfe\x80new";
        let hash = FileContent::from_bytes(bytes).unwrap();
        let token = "a".repeat(64);
        let temporary = dir.join(format!(".wssp-upload-{token}"));
        assert!(!put(&path, &token, bytes, &"0".repeat(64), b"C"));
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(!temporary.exists());
        // Short payload (EOF before the declared length) never renames.
        assert!(!put(&path, &token, &bytes[..3], hash.digest(), b""));
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(!temporary.exists());
        assert!(put(&path, &token, bytes, hash.digest(), b"C"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!temporary.exists());
        let link = dir.join("link");
        symlink(&path, &link).unwrap();
        assert!(!put(&link, &token, bytes, hash.digest(), b"C"));
        assert!(
            !helper("read", &link, &token, bytes.len(), "", b"")
                .status
                .success()
        );
        let nested = dir.join("nested");
        symlink(&dir, &nested).unwrap();
        assert!(!put(
            &nested.join("target"),
            &token,
            bytes,
            hash.digest(),
            b"C"
        ));
        assert!(!put(
            &dir.join("../escape"),
            &token,
            bytes,
            hash.digest(),
            b"C"
        ));
        assert!(
            !helper(
                "read",
                std::path::Path::new("/dev/null"),
                &token,
                bytes.len(),
                "",
                b""
            )
            .status
            .success()
        );
        let fifo = dir.join("fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            !helper("read", &fifo, &token, bytes.len(), "", b"")
                .status
                .success()
        );
        assert!(!put(&fifo, &token, bytes, hash.digest(), b"C"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::remove_dir_all(dir).unwrap();
    }
    /// G1 (guest side): without the host's fence byte the helper aborts,
    /// records `cancelled`, removes its staging file and leaves the destination.
    #[test]
    fn helper_never_renames_without_the_commit_fence_byte() {
        let dir = std::env::temp_dir().join(format!(
            "wssp-fence-{}",
            super::super::client::random_nonce().unwrap()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("target");
        fs::write(&path, b"old").unwrap();
        let bytes = b"\0new\xff";
        let hash = FileContent::from_bytes(bytes).unwrap();
        let token = "b".repeat(64);
        for go in [&b""[..], b"X"] {
            let out = helper(
                "put",
                &path,
                &token,
                bytes.len(),
                hash.digest(),
                &[&bytes[..], go].concat(),
            );
            assert!(!out.status.success());
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                format!("WSSP_COMMIT_READY {token}\n")
            );
            assert_eq!(
                String::from_utf8_lossy(&out.stderr),
                format!("WSSP_STATUS {token} cancelled none\n")
            );
            assert_eq!(fs::read(&path).unwrap(), b"old");
            assert!(!dir.join(format!(".wssp-upload-{token}")).exists());
        }
        fs::remove_dir_all(dir).unwrap();
    }
    /// G2: crash recovery settles an interrupted attempt from guest evidence.
    /// A surviving staging file proves no rename and is removed; a destination
    /// with exactly the requested bytes proves the commit; anything else stays
    /// unknown.
    #[test]
    fn recovery_removes_orphaned_staging_and_proves_committed_bytes() {
        let dir = std::env::temp_dir().join(format!(
            "wssp-recover-{}",
            super::super::client::random_nonce().unwrap()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("target");
        fs::write(&path, b"old").unwrap();
        let bytes = b"\0recovered\xff";
        let hash = FileContent::from_bytes(bytes).unwrap();
        let token = transfer_token("op-crash", 3, 2);
        let temporary = dir.join(format!(".wssp-upload-{token}"));
        let verdict = |out: std::process::Output| {
            assert!(out.status.success(), "{out:?}");
            assert_eq!(
                String::from_utf8_lossy(&out.stderr),
                format!("WSSP_STATUS {token} ok\n")
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        // Crash after staging, before the fence: the orphan is removed.
        fs::write(&temporary, bytes).unwrap();
        assert_eq!(
            verdict(helper(
                "recover",
                &path,
                &token,
                bytes.len(),
                hash.digest(),
                b""
            )),
            format!("WSSP_RECOVERED {token} not_committed\n")
        );
        assert!(!temporary.exists());
        assert_eq!(fs::read(&path).unwrap(), b"old");
        // No staging file and a destination with other bytes: unknown.
        assert_eq!(
            verdict(helper(
                "recover",
                &path,
                &token,
                bytes.len(),
                hash.digest(),
                b""
            )),
            format!("WSSP_RECOVERED {token} unknown\n")
        );
        // Crash after the rename: the destination proves the commit.
        assert!(put(&path, &token, bytes, hash.digest(), b"C"));
        assert_eq!(
            verdict(helper(
                "recover",
                &path,
                &token,
                bytes.len(),
                hash.digest(),
                b""
            )),
            format!("WSSP_RECOVERED {token} committed\n")
        );
        // Missing parent directory: no evidence either way.
        assert_eq!(
            verdict(helper(
                "recover",
                &dir.join("absent/target"),
                &token,
                bytes.len(),
                hash.digest(),
                b""
            )),
            format!("WSSP_RECOVERED {token} unknown\n")
        );
        let out = IncusCommandOutput {
            stdout: format!("WSSP_RECOVERED {token} not_committed\n"),
            stderr: format!("WSSP_STATUS {token} ok\n"),
            exit_code: 0,
        };
        let failed = crate::EffectError::from(
            effect_completion::recovery_outcome(&token, &out, "/target").unwrap_err(),
        );
        assert_eq!(failed.state(), sandbox_protocol::OperationState::Failed);
        assert_eq!(failed.code, SandboxErrorCode::Cancelled);
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn revoked_permit_prevents_commit_spawn_and_cancels_pending_file_io() {
        use std::sync::Arc;
        let marker = std::env::temp_dir().join(format!(
            "wssp-file-cancel-{}",
            super::super::client::random_nonce().unwrap()
        ));
        let permit = Arc::new(crate::RuntimePermit::default());
        let client = IncusClient {
            cancelled: Some(permit.clone()),
            agent_timeout: Duration::from_secs(2),
            ..IncusClient::new("unused", "default")
        };
        let path = marker.clone();
        let worker = std::thread::spawn(move || {
            let mut command = Command::new("sh");
            command
                .args(["-c", "printf ready > \"$1\"; sleep 60", "wssp-test"])
                .arg(&path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            client.file_io(&client.local_test_bound(), command, 0, None, "local")
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(marker.exists(), "real child must enter before cancellation");
        permit.revoke();
        assert!(worker.join().unwrap().is_err());
        std::fs::remove_file(&marker).unwrap();
        let client = IncusClient {
            cancelled: Some(permit),
            ..IncusClient::new("unused", "default")
        };
        let mut commit = Command::new("sh");
        commit
            .args(["-c", "printf committed > \"$1\"", "wssp-test"])
            .arg(&marker)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        assert!(
            client
                .file_io(&client.local_test_bound(), commit, 0, None, "local")
                .is_err()
        );
        assert!(
            !marker.exists(),
            "revoked generation must not issue a commit"
        );
    }
}

#[cfg(test)]
mod fence_tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;
    fn wait_for(path: &std::path::Path, contents: Option<&[u8]>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if fs::read(path).is_ok_and(|seen| contents.is_none_or(|want| seen == want)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("timed out waiting for {}", path.display());
    }
    fn scratch(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wssp-{label}-{}",
            super::super::client::random_nonce().unwrap()
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }
    /// G1: a revocation after spawn but before the fence prevents the guest
    /// rename. The real helper aborts on EOF, removes its staging file, and the
    /// outcome is a guest-recorded FAILED/cancelled — never success.
    #[test]
    fn revocation_before_the_fence_prevents_the_guest_rename() {
        let dir = scratch("fence-refused");
        let (target, marker, gate) = (dir.join("target"), dir.join("spawned"), dir.join("gate"));
        fs::write(&target, b"old").unwrap();
        let bytes = b"\0fresh\xff";
        let content = FileContent::from_bytes(bytes).unwrap();
        let token = transfer_token("op-fence", 4, 1);
        let helper = |marker: &std::path::Path, gate: &std::path::Path| {
            let mut command = Command::new("sh");
            command.args([
                "-c",
                "printf spawned > \"$1\"; while [ ! -e \"$2\" ]; do sleep 0.01; done; shift 2; exec \"$@\"",
                "wssp-test",
            ]);
            command.arg(marker).arg(gate).args([
                "python3",
                "-c",
                HELPER,
                "put",
                target.to_str().unwrap(),
                &token,
                &bytes.len().to_string(),
                content.digest(),
            ]);
            command
        };
        let permit = Arc::new(crate::RuntimePermit::default());
        let client = IncusClient {
            cancelled: Some(permit.clone()),
            agent_timeout: Duration::from_secs(20),
            ..IncusClient::new("unused", "default")
        };
        let worker = {
            let (command, content, token) =
                (helper(&marker, &gate), content.clone(), token.clone());
            std::thread::spawn(move || {
                client.put_io(&client.local_test_bound(), command, content, &token)
            })
        };
        wait_for(&marker, None);
        permit.revoke();
        fs::write(&gate, b"").unwrap();
        let run = worker.join().unwrap().unwrap();
        assert_eq!(run.fence, Fence::Refused);
        assert!(!run.interrupted, "the helper confirmed its own abort");
        let failed = put_outcome(&token, "/target", &run).unwrap_err();
        assert_eq!(failed.state(), sandbox_protocol::OperationState::Failed);
        assert_eq!(failed.code, SandboxErrorCode::Cancelled);
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(!dir.join(format!(".wssp-upload-{token}")).exists());
        // Positive control: the same helper with a current permit commits.
        let (marker, gate) = (dir.join("spawned-2"), dir.join("gate-2"));
        fs::write(&gate, b"").unwrap();
        let client = IncusClient {
            cancelled: Some(Arc::new(crate::RuntimePermit::default())),
            agent_timeout: Duration::from_secs(20),
            ..IncusClient::new("unused", "default")
        };
        let run = client
            .put_io(
                &client.local_test_bound(),
                helper(&marker, &gate),
                content,
                &token,
            )
            .unwrap();
        assert_eq!(run.fence, Fence::Issued);
        assert!(put_outcome(&token, "/target", &run).is_ok());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        fs::remove_dir_all(dir).unwrap();
    }
    /// G1: once the fence byte was issued, a later revocation cannot be
    /// reported as success; the run is interrupted and the outcome is unknown.
    #[test]
    fn revocation_after_the_fence_is_unknown_never_success() {
        let dir = scratch("fence-issued");
        let (go, gate) = (dir.join("go"), dir.join("gate"));
        let content = FileContent::from_bytes(b"payload").unwrap();
        let token = transfer_token("op-issued", 1, 1);
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "head -c 7 >/dev/null; printf 'WSSP_COMMIT_READY %s\\n' \"$1\"; head -c 1 > \"$2\"; \
                 while [ ! -e \"$3\" ]; do sleep 0.01; done; printf 'WSSP_STATUS %s ok\\n' \"$1\" >&2",
                "wssp-test",
                &token,
            ])
            .arg(&go)
            .arg(&gate);
        let permit = Arc::new(crate::RuntimePermit::default());
        let client = IncusClient {
            cancelled: Some(permit.clone()),
            agent_timeout: Duration::from_secs(20),
            ..IncusClient::new("unused", "default")
        };
        let worker = {
            let token = token.clone();
            std::thread::spawn(move || {
                client.put_io(&client.local_test_bound(), command, content, &token)
            })
        };
        wait_for(&go, Some(b"C"));
        permit.revoke();
        std::thread::sleep(Duration::from_millis(50));
        fs::write(&gate, b"").unwrap();
        let run = worker.join().unwrap().unwrap();
        assert_eq!(run.fence, Fence::Issued);
        assert!(run.interrupted);
        let unknown = put_outcome(&token, "/target", &run).unwrap_err();
        assert_eq!(
            unknown.state(),
            sandbox_protocol::OperationState::UnknownOutcome
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod metadata_boundary_tests {
    use super::*;
    #[test]
    fn hostile_metadata_is_capped_before_json_and_rejects_extra_fields() {
        assert!(decode_metadata(&vec![b' '; crate::metadata::HOST_RESULT_MAX_BYTES + 1]).is_err());
        let mut valid_oversize =
            br#"{"result":{"type":"file.mkdir","created":true},"continuation":null}"#.to_vec();
        valid_oversize.resize(crate::metadata::HOST_RESULT_MAX_BYTES + 1, b' ');
        assert!(decode_metadata(&valid_oversize).is_err());
        assert!(decode_metadata(br#"{"result":{"type":"file.mkdir","created":true},"continuation":null,"private":"sentinel"}"#).is_err());
        assert!(decode_metadata(b"\xff").is_err());
        let client = IncusClient::new("unused", "default");
        let mut command = Command::new("python3");
        command.args([
            "-I",
            "-c",
            "import sys; sys.stdout.buffer.write(b'x'*1000000)",
        ]);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        assert!(
            client
                .file_io(
                    &client.local_test_bound(),
                    command,
                    crate::metadata::HOST_RESULT_MAX_BYTES as u64,
                    None,
                    "local"
                )
                .is_err()
        );
    }
    #[test]
    fn metadata_capture_limits_reads_before_allocation_and_does_not_charge_transfer_slots() {
        struct Counted {
            consumed: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Read for Counted {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                let used = self.consumed.load(std::sync::atomic::Ordering::SeqCst);
                let count = bytes.len().min(1_000_000 - used);
                bytes[..count].fill(b' ');
                self.consumed
                    .fetch_add(count, std::sync::atomic::Ordering::SeqCst);
                Ok(count)
            }
        }
        let consumed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        assert!(
            read_metadata(Counted {
                consumed: consumed.clone()
            })
            .is_err()
        );
        assert_eq!(
            consumed.load(std::sync::atomic::Ordering::SeqCst),
            crate::metadata::HOST_RESULT_MAX_BYTES + 1
        );
        let _pinned: Vec<_> = (0..4)
            .map(|i| FileStaging::for_creator(16, &format!("creator-{i}")).unwrap())
            .collect();
        let client = IncusClient::new("unused", "default");
        let mut command = Command::new("python3");
        command
            .args(["-I", "-c", "print('{}', end='')"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (body, output) = client
            .metadata_io(&client.local_test_bound(), command)
            .unwrap();
        assert_eq!(output.exit_code, 0);
        assert_eq!(body, b"{}");
    }
    #[test]
    fn metadata_errors_never_retain_guest_diagnostics_and_need_exact_status() {
        let io_error = error("sentinel-path-stderr-or-parse-cause");
        assert!(!format!("{io_error:?} {io_error}").contains("sentinel"));
        let token = "a".repeat(64);
        for stderr in [
            format!("WSSP_STATUS {token} fs_not_found none\n"),
            format!("sentinel-path\nWSSP_STATUS {token} fs_not_found none\n"),
            "WSSP_STATUS wrong fs_not_found none\n".into(),
            "sentinel-private".into(),
        ] {
            let out = IncusCommandOutput {
                stdout: "sentinel-content".into(),
                stderr,
                exit_code: 1,
            };
            let Some(failure) = metadata_failure(&token, &out) else {
                // B2-K-2: no record for this token is plane loss, decided by
                // a host re-observation, never a guest-text protocol error.
                assert!(!out.stderr.contains(&format!("WSSP_STATUS {token}")));
                continue;
            };
            assert!(!format!("{failure:?} {failure}").contains("sentinel"));
            if out.stderr == format!("WSSP_STATUS {token} fs_not_found none\n") {
                assert_eq!(failure.code, SandboxErrorCode::FsNotFound);
            } else {
                assert_eq!(failure.code, SandboxErrorCode::ProtocolError);
            }
        }
    }
    /// B2R2-C-4: a valid record that the transport then contradicted is
    /// plane loss (`None`: the caller re-observes the VM); only a malformed
    /// record, or one that is not the first line, is `protocol_error`.
    #[test]
    fn a_contradicted_valid_record_is_plane_loss_and_a_malformed_one_is_not() {
        let token = "b".repeat(64);
        let drop = "Error: websocket: close 1006 (abnormal closure)\n";
        for (stderr, exit_code, plane_loss) in [
            (format!("WSSP_STATUS {token} ok\n"), 1, true),
            (format!("WSSP_STATUS {token} ok\n{drop}"), 1, true),
            (format!("WSSP_STATUS {token} ok\n{drop}"), 0, true),
            (
                format!("WSSP_STATUS {token} fs_not_found none\n{drop}"),
                1,
                true,
            ),
            (format!("WSSP_STATUS {token} fs_not_found none\n"), 0, true),
            (format!("WSSP_STATUS {token} ok"), 1, false),
            (format!("WSSP_STATUS {token} bogus\n"), 1, false),
            (
                format!("WSSP_STATUS {token} fs_not_found sideways\n{drop}"),
                1,
                false,
            ),
            (
                format!("WSSP_STATUS {token} unknown_outcome none\n"),
                1,
                false,
            ),
            (format!("{drop}WSSP_STATUS {token} ok\n"), 1, false),
        ] {
            let out = IncusCommandOutput {
                stdout: String::new(),
                stderr: stderr.clone(),
                exit_code,
            };
            match metadata_failure(&token, &out) {
                None => assert!(plane_loss, "{stderr:?} {exit_code}"),
                Some(failure) => {
                    assert!(!plane_loss, "{stderr:?} {exit_code}");
                    assert_eq!(failure.code, SandboxErrorCode::ProtocolError, "{stderr:?}");
                }
            }
        }
    }
    #[test]
    fn forged_ready_with_full_stdin_cannot_hold_the_permit_lock() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        loop {
            match writer.write(&[0; 8192]) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                other => panic!("unexpected socket fill: {other:?}"),
            }
        }
        loop {
            match writer.write(&[0]) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                other => panic!("unexpected socket fill: {other:?}"),
            }
        }
        writer.set_nonblocking(false).unwrap();
        let permit = std::sync::Arc::new(crate::RuntimePermit::default());
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = {
            let permit = permit.clone();
            std::thread::spawn(move || {
                let _ = tx.send(issue_commit(&mut writer, Some(&permit)));
            })
        };
        let result = rx.recv_timeout(Duration::from_secs(2));
        // Release a deliberately broken/blocking implementation before the
        // assertion, so a fault run fails without leaving a stuck test worker.
        drop(reader);
        worker.join().unwrap();
        assert!(
            result.is_ok(),
            "a guest-controlled full stdin blocked commit under the permit lock"
        );
        assert_eq!(result.unwrap(), Fence::PossiblyIssued);
        permit.revoke();
        let run = PutRun {
            fence: Fence::PossiblyIssued,
            interrupted: false,
            body: Vec::new(),
            output: IncusCommandOutput {
                stdout: String::new(),
                stderr: "WSSP_STATUS token ok\n".into(),
                exit_code: 0,
            },
        };
        assert_eq!(
            put_outcome("token", "/sentinel", &run).unwrap_err().state(),
            sandbox_protocol::OperationState::UnknownOutcome
        );
    }
    #[test]
    fn hostile_mutation_output_is_bounded_before_decoding_and_cannot_mint_completion() {
        let client = IncusClient::new("unused", "default");
        let token = "d".repeat(64);
        let mut command = Command::new("python3");
        command.args(["-I", "-c", "import sys; t=sys.argv[1]; print('WSSP_COMMIT_READY '+t, flush=True); sys.stdin.buffer.read(1); sys.stdout.buffer.write(b' '*1000000); sys.stdout.buffer.flush(); print('WSSP_STATUS '+t+' ok', file=sys.stderr, flush=True)", &token]);
        let run = client
            .mutation_io(&client.local_test_bound(), command, None, &token)
            .unwrap();
        assert!(run.body.len() <= crate::metadata::HOST_RESULT_MAX_BYTES + 1);
        assert!(decode_metadata(&run.body).is_err());
        assert_eq!(
            put_outcome(&token, "/sentinel", &run).unwrap_err().state(),
            sandbox_protocol::OperationState::UnknownOutcome
        );
    }
}
