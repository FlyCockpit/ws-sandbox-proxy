//! FakeRuntime credential guest operations: an in-memory guest home per
//! sandbox with the helper's semantics (pack never follows a link, restore
//! clears then writes, scrub unlinks links only), fault injection and a hold
//! hook that blocks an operation until the runtime permit is cancelled.

use std::collections::{BTreeMap, HashMap};

use login_definition::BundleFileKind;
use login_definition::paths::path_within;
use sandbox_protocol::SandboxErrorCode;
use zeroize::Zeroizing;

use crate::credentials::{self as cred, PackEntry};
use crate::{
    CredentialBytes, CredentialGuest, CredentialPackOutcome, CredentialPackRequest,
    CredentialQuiesceOutcome, CredentialRestoreOutcome, CredentialRestoreRequest,
    CredentialScrubOutcome, CredentialScrubRequest, RuntimeError,
};

/// One node of a fake guest home.
pub(crate) enum FakeNode {
    File { data: Zeroizing<Vec<u8>>, mode: u16 },
    Dir,
    Symlink,
    Fifo,
}

/// Per-runtime credential state (shared by clones like the rest of the fake).
#[derive(Default)]
pub(crate) struct FakeCredentialState {
    homes: HashMap<String, BTreeMap<String, FakeNode>>,
    faults: HashMap<String, usize>,
    holds: std::collections::HashSet<String>,
    quiesce: HashMap<String, (u32, u32)>,
    helper_missing: bool,
    calls: Vec<(String, String)>,
}

impl std::fmt::Debug for FakeCredentialState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Guest file contents are plaintext credentials: never printed.
        f.debug_struct("FakeCredentialState")
            .field("homes", &self.homes.len())
            .field("calls", &self.calls.len())
            .finish_non_exhaustive()
    }
}

const OPS: [&str; 5] = ["pack", "restore", "scrub", "quiesce", "probe"];

fn op_name(op: &str) -> &'static str {
    OPS.iter().find(|o| **o == op).copied().unwrap_or("pack")
}

impl super::FakeRuntime {
    fn credential_state(&self) -> std::sync::MutexGuard<'_, FakeCredentialState> {
        self.credentials.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Test hook: a regular file (parents created as directories).
    pub fn set_guest_file(&self, sandbox_id: &str, rel: &str, bytes: &[u8]) {
        let mut state = self.credential_state();
        let home = state.homes.entry(sandbox_id.to_owned()).or_default();
        ensure_parents(home, rel);
        home.insert(
            rel.to_owned(),
            FakeNode::File {
                data: Zeroizing::new(bytes.to_vec()),
                mode: 0o600,
            },
        );
    }

    /// Test hook: a symlink at `rel` (the target is recorded nowhere: a fake
    /// link has no reachable target, so following it is impossible).
    pub fn set_guest_symlink(&self, sandbox_id: &str, rel: &str, _target: &str) {
        let mut state = self.credential_state();
        let home = state.homes.entry(sandbox_id.to_owned()).or_default();
        ensure_parents(home, rel);
        remove_tree(home, rel);
        home.insert(rel.to_owned(), FakeNode::Symlink);
    }

    /// Test hook: a FIFO at `rel`.
    pub fn set_guest_fifo(&self, sandbox_id: &str, rel: &str) {
        let mut state = self.credential_state();
        let home = state.homes.entry(sandbox_id.to_owned()).or_default();
        ensure_parents(home, rel);
        home.insert(rel.to_owned(), FakeNode::Fifo);
    }

    /// Test hook: the bytes of a regular file, if one exists at `rel`.
    pub fn guest_file(&self, sandbox_id: &str, rel: &str) -> Option<Vec<u8>> {
        match self.credential_state().homes.get(sandbox_id)?.get(rel)? {
            FakeNode::File { data, .. } => Some(data.to_vec()),
            _ => None,
        }
    }

    /// Test hook: every path in the fake guest home, sorted.
    pub fn guest_paths(&self, sandbox_id: &str) -> Vec<String> {
        self.credential_state()
            .homes
            .get(sandbox_id)
            .map(|home| home.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Fault injection: the next `times` calls of `op` (`pack`, `restore`,
    /// `scrub`, `quiesce`, `probe`) fail with `GUEST_OPERATION_FAILED`.
    pub fn fail_credential_op(&self, op: &str, times: usize) {
        self.credential_state()
            .faults
            .insert(op_name(op).to_owned(), times);
    }

    /// Hold hook: every later call of `op` blocks until this runtime's
    /// cancellation permit fires (then fails `CANCELLED`) or the hold is
    /// released.
    pub fn hold_credential_op(&self, op: &str) {
        self.credential_state().holds.insert(op_name(op).to_owned());
    }

    pub fn release_credential_op(&self, op: &str) {
        self.credential_state().holds.remove(op_name(op));
    }

    /// Quiesce counts reported for `sandbox_id` (default zero).
    pub fn set_guest_quiesce(&self, sandbox_id: &str, terminated: u32, killed: u32) {
        self.credential_state()
            .quiesce
            .insert(sandbox_id.to_owned(), (terminated, killed));
    }

    pub fn set_credential_helper_present(&self, present: bool) {
        self.credential_state().helper_missing = !present;
    }

    /// `(op, sandbox_id)` of every credential call, in order (held and
    /// failed calls included).
    pub fn credential_calls(&self) -> Vec<(String, String)> {
        self.credential_state().calls.clone()
    }

    fn credential_enter(&self, op: &'static str, sandbox_id: &str) -> Result<(), RuntimeError> {
        {
            let mut state = self.credential_state();
            state.calls.push((op.to_owned(), sandbox_id.to_owned()));
            if let Some(left) = state.faults.get_mut(op)
                && *left > 0
            {
                *left -= 1;
                return Err(RuntimeError::new(
                    SandboxErrorCode::GuestOperationFailed,
                    format!("credential {op} failed: injected"),
                ));
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while self.credential_state().holds.contains(op) {
            if self.cancelled.as_ref().is_some_and(|p| p.is_cancelled()) {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Cancelled,
                    format!("credential {op} cancelled"),
                ));
            }
            if std::time::Instant::now() >= deadline {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Timeout,
                    format!("credential {op} timed out"),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(())
    }

    pub(super) fn fake_credential_pack(
        &self,
        request: &CredentialPackRequest,
    ) -> Result<CredentialPackOutcome, RuntimeError> {
        cred::validate_pack(request)?;
        self.credential_enter("pack", &request.guest.sandbox_id)?;
        let state = self.credential_state();
        let empty = BTreeMap::new();
        let home = state.homes.get(&request.guest.sandbox_id).unwrap_or(&empty);
        let excluded = |p: &str| request.paths.exclude.iter().any(|e| path_within(p, e));
        let mut entries: BTreeMap<String, PackEntry> = BTreeMap::new();
        let (mut links, mut special, mut data_total, mut path_total) = (0u32, 0u32, 0usize, 0usize);
        for root in request.paths.included() {
            if excluded(&root) {
                continue;
            }
            if ancestor_is_link(home, &root) {
                links += 1;
                continue;
            }
            for (path, node) in subtree(home, &root) {
                if excluded(path) || ancestor_is_link(home, path) && path != &root {
                    continue;
                }
                let (kind, mode, data) = match node {
                    FakeNode::Symlink => {
                        links += 1;
                        continue;
                    }
                    FakeNode::Fifo => {
                        special += 1;
                        continue;
                    }
                    FakeNode::Dir => (BundleFileKind::Dir, 0o700, Zeroizing::new(Vec::new())),
                    FakeNode::File { data, mode } => {
                        (BundleFileKind::File, *mode, Zeroizing::new(data.to_vec()))
                    }
                };
                if entries.contains_key(path) {
                    continue;
                }
                data_total += data.len();
                path_total += path.len();
                if data_total > request.max_bytes
                    || entries.len() >= login_definition::limits::BUNDLE_FILE_COUNT_MAX
                    || path_total > login_definition::limits::BUNDLE_PATH_TOTAL_MAX_BYTES
                    || path.split('/').count() > 32
                {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::GuestOperationFailed,
                        "credential pack failed: limit exceeded",
                    ));
                }
                entries.insert(
                    path.clone(),
                    PackEntry {
                        kind,
                        path: path.clone(),
                        mode,
                        data,
                    },
                );
            }
        }
        let mut list: Vec<PackEntry> = entries.into_values().collect();
        let bundle = cred::encode_files_bundle(&request.definition_digest, &mut list);
        Ok(CredentialPackOutcome {
            bundle: CredentialBytes::from_zeroizing(bundle),
            file_count: list.len() as u32,
            skipped_links: links,
            skipped_special: special,
        })
    }

    pub(super) fn fake_credential_restore(
        &self,
        request: &CredentialRestoreRequest<'_>,
    ) -> Result<CredentialRestoreOutcome, RuntimeError> {
        cred::validate_restore(request)?;
        self.credential_enter("restore", &request.guest.sandbox_id)?;
        let mut state = self.credential_state();
        let home = state
            .homes
            .entry(request.guest.sandbox_id.clone())
            .or_default();
        for path in request.declared.included() {
            if !ancestor_is_link(home, &path) {
                remove_tree(home, &path);
            }
        }
        let (mut files, mut dirs) = (0u32, 0u32);
        for file in &request.files {
            if ancestor_is_link(home, file.path) || ancestor_is_non_dir(home, file.path) {
                return Err(restore_refused(file.path, "parent is not a directory"));
            }
            dirs += ensure_parents(home, file.path);
            match (file.kind, home.get(file.path)) {
                (BundleFileKind::Dir, None) => {
                    home.insert(file.path.to_owned(), FakeNode::Dir);
                    dirs += 1;
                }
                (BundleFileKind::Dir, Some(FakeNode::Dir)) => {}
                (BundleFileKind::Dir, Some(_)) => {
                    return Err(restore_refused(file.path, "target is not a directory"));
                }
                (BundleFileKind::File, None | Some(FakeNode::File { .. })) => {
                    home.insert(
                        file.path.to_owned(),
                        FakeNode::File {
                            data: Zeroizing::new(file.data.to_vec()),
                            mode: login_definition::bundle::normalize_mode(file.kind, file.mode),
                        },
                    );
                    files += 1;
                }
                (BundleFileKind::File, Some(_)) => {
                    return Err(restore_refused(file.path, "target is not a regular file"));
                }
            }
        }
        Ok(CredentialRestoreOutcome {
            files_written: files,
            dirs_created: dirs,
        })
    }

    pub(super) fn fake_credential_scrub(
        &self,
        request: &CredentialScrubRequest,
    ) -> Result<CredentialScrubOutcome, RuntimeError> {
        cred::validate_scrub(request)?;
        self.credential_enter("scrub", &request.guest.sandbox_id)?;
        let mut state = self.credential_state();
        let home = state
            .homes
            .entry(request.guest.sandbox_id.clone())
            .or_default();
        let (mut removed, mut links) = (0u32, 0u32);
        for path in &request.paths {
            if ancestor_is_link(home, path) {
                continue;
            }
            let doomed: Vec<String> = subtree(home, path).map(|(p, _)| p.clone()).collect();
            for p in doomed {
                match home.remove(&p) {
                    Some(FakeNode::Symlink) => links += 1,
                    Some(_) => removed += 1,
                    None => {}
                }
            }
        }
        Ok(CredentialScrubOutcome {
            verified_absent: true,
            removed,
            links_unlinked: links,
            failed_paths: Vec::new(),
        })
    }

    pub(super) fn fake_credential_quiesce(
        &self,
        guest: &CredentialGuest,
    ) -> Result<CredentialQuiesceOutcome, RuntimeError> {
        cred::validate_quiesce(guest)?;
        self.credential_enter("quiesce", &guest.sandbox_id)?;
        let (terminated, killed) = self
            .credential_state()
            .quiesce
            .get(&guest.sandbox_id)
            .copied()
            .unwrap_or_default();
        Ok(CredentialQuiesceOutcome {
            terminated,
            killed,
            freezer: killed > 0,
        })
    }

    pub(super) fn fake_credential_helper_present(
        &self,
        guest: &CredentialGuest,
    ) -> Result<bool, RuntimeError> {
        cred::validate_guest(guest)?;
        self.credential_enter("probe", &guest.sandbox_id)?;
        Ok(!self.credential_state().helper_missing)
    }
}

fn restore_refused(path: &str, why: &str) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::GuestOperationFailed,
        format!("credential restore failed: {path}: {why}"),
    )
}

/// `rel` and everything below it (`a-x` sorts between `a` and `a/b`, so the
/// scan runs over the whole string prefix and filters by path).
fn subtree<'h>(
    home: &'h BTreeMap<String, FakeNode>,
    rel: &'h str,
) -> impl Iterator<Item = (&'h String, &'h FakeNode)> {
    home.range(rel.to_owned()..)
        .take_while(move |(p, _)| p.starts_with(rel))
        .filter(move |(p, _)| path_within(p, rel))
}

/// Proper ancestors of `rel`, shortest first.
fn ancestors(rel: &str) -> impl Iterator<Item = &str> {
    rel.match_indices('/').map(move |(i, _)| &rel[..i])
}

fn ancestor_is_link(home: &BTreeMap<String, FakeNode>, rel: &str) -> bool {
    ancestors(rel).any(|a| matches!(home.get(a), Some(FakeNode::Symlink)))
}

fn ancestor_is_non_dir(home: &BTreeMap<String, FakeNode>, rel: &str) -> bool {
    ancestors(rel).any(|a| matches!(home.get(a), Some(FakeNode::File { .. } | FakeNode::Fifo)))
}

/// Creates missing parent directories; returns how many were created.
fn ensure_parents(home: &mut BTreeMap<String, FakeNode>, rel: &str) -> u32 {
    let mut created = 0;
    for a in ancestors(rel).map(str::to_owned).collect::<Vec<_>>() {
        if let std::collections::btree_map::Entry::Vacant(slot) = home.entry(a) {
            slot.insert(FakeNode::Dir);
            created += 1;
        }
    }
    created
}

fn remove_tree(home: &mut BTreeMap<String, FakeNode>, rel: &str) {
    let doomed: Vec<String> = subtree(home, rel).map(|(p, _)| p.clone()).collect();
    for p in doomed {
        home.remove(&p);
    }
}
