//! S16r launch-branch inventory, Rust (offload plan §12 S16r, U3, U4).
//!
//! Every production line under `ROOTS` that contains one of `PATTERNS` (the
//! fixed-string S16r sweep) is listed in `INVENTORY`, keyed by file and trimmed
//! line text, with how it treats launch semantics. The test fails on an
//! unlisted hit and on a stale entry. This prevents drift only: invariant I18
//! is proven by the behavioural restore cells.
//!
//! Classes (the TS twin is `packages/api/src/sandbox/launch-branches.inventory.ts`):
//! - `Routed`: decides from the dispatch's launch mode / `restore` (§8.6).
//! - `Pending`: decides new-root versus retained-root from the dispatch kind
//!   alone; a restore is a `sandbox.reconnect` with `launchMode = new_root`, so
//!   C6c must route each one by launch mode and flip it to `Routed`.
//! - `CreateOnly`: CREATE-only by design (image fetch, builds, lease from READY,
//!   create-only test barriers); a restore never takes it.
//! - `Agnostic`: kind lists, or a branch that treats every launch alike.
//!
//! Test code (`*_tests.rs`, `tests.rs`, `test_support.rs`, `tests/`, and
//! `#[cfg(test)]` items) is outside the sweep.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Routed,
    Pending,
    CreateOnly,
    Agnostic,
}
use Class::{Agnostic, CreateOnly, Pending, Routed};

const ROOTS: &[&str] = &[
    "apps/cli/src",
    "crates/sandbox-runtime",
    "crates/sandbox-protocol",
];
const PATTERNS: &[&str] = &[
    "\"sandbox.reconnect\"",
    "\"sandbox.create\"",
    "AllocationKind::",
];

const CLI: &str = "apps/cli/src/sandbox_relay";

/// (file under `CLI` or a crate path, trimmed line, class).
const INVENTORY: &[(&str, &str, Class)] = &[
    (
        "authority.rs",
        r#"&& matches!(kind, "sandbox.create" | "sandbox.reconnect")"#,
        Agnostic,
    ),
    ("authority.rs", r#""sandbox.create""#, Agnostic),
    ("authority.rs", r#"| "sandbox.reconnect""#, Agnostic),
    (
        "build.rs",
        r#"if (bootstrap || upstream) && d.kind != "sandbox.create" {"#,
        CreateOnly,
    ),
    (
        "build.rs",
        r#""sandbox.create" if d.build.is_some() && d.guest_sudo.is_some() => Err(refused("#,
        CreateOnly,
    ),
    (
        "build.rs",
        r#""sandbox.create" if d.build.is_some() && !builds_enabled => Err(refused("#,
        CreateOnly,
    ),
    (
        "build.rs",
        r#""sandbox.reconnect" if record_build.is_some() => Err(refused("#,
        CreateOnly,
    ),
    (
        "connect.rs",
        r#""sandbox.create" | "sandbox.reconnect""#,
        Agnostic,
    ),
    (
        "connect.rs",
        r#"state: if matches!(kind, "sandbox.create" | "sandbox.reconnect") {"#,
        Agnostic,
    ),
    (
        "journal/leases.rs",
        r#"if matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect")"#,
        Agnostic,
    ),
    (
        "journal/leases.rs",
        r#"if d.kind == "sandbox.reconnect" {"#,
        Agnostic,
    ),
    (
        "journal/leases.rs",
        r#"if d.kind == "sandbox.reconnect""#,
        Agnostic,
    ),
    (
        "journal/leases.rs",
        r#"if lease.from_ready_ms.is_some() && d.kind != "sandbox.create" {"#,
        CreateOnly,
    ),
    (
        "journal/leases.rs",
        r#"Some(previous) if matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect") => {"#,
        Agnostic,
    ),
    (
        "journal/leases.rs",
        r#"let lifecycle = matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect");"#,
        Agnostic,
    ),
    (
        "journal/leases.rs",
        r#"&& matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect"))"#,
        Agnostic,
    ),
    (
        "journal/leases.rs",
        r#"&& matches!(r.kind.as_str(), "sandbox.create" | "sandbox.reconnect")"#,
        Agnostic,
    ),
    (
        "journal/leases.rs",
        r#"return (!matches!(kind, "sandbox.create" | "sandbox.reconnect")).then_some("no_lease");"#,
        Agnostic,
    ),
    (
        "journal/leases.rs",
        r#"if generation > row.generation && matches!(kind, "sandbox.create" | "sandbox.reconnect") {"#,
        Agnostic,
    ),
    (
        "journal/leases.rs",
        r#"let id = matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect")"#,
        Agnostic,
    ),
    (
        "journal.rs",
        r#""sandbox.create" | "sandbox.reconnect""#,
        Agnostic,
    ),
    // First-attempt lineage: a restore (reconnect + new root) scopes its
    // history to its own and later generations exactly like any reconnect,
    // matching the server's attestation (`sinceGeneration`, offload §8.6 U3).
    (
        "journal.rs",
        r#"|generation| receipt.kind != "sandbox.reconnect" || generation >= receipt.generation;"#,
        Agnostic,
    ),
    (
        "journal.rs",
        r#"let reconnect = receipt.kind == "sandbox.reconnect";"#,
        Agnostic,
    ),
    (
        "journal.rs",
        r#"&& matches!(r.kind.as_str(), "sandbox.create" | "sandbox.reconnect")"#,
        Agnostic,
    ),
    (
        "journal.rs",
        r#"sandbox_runtime::AllocationKind::from_launch(&self.kind, self.launch_mode)"#,
        Routed,
    ),
    (
        "journal/storage.rs",
        r#""sandbox.create" | "sandbox.reconnect""#,
        Agnostic,
    ),
    (
        "journal/storage.rs",
        r#"receipt.allocation_kind() == Some(sandbox_runtime::AllocationKind::Create),"#,
        Routed,
    ),
    (
        "journal/storage.rs",
        r#"if matches!(r.kind.as_str(), "sandbox.create" | "sandbox.reconnect")"#,
        Agnostic,
    ),
    (
        "live_admission.rs",
        r#""sandbox.create" | "sandbox.reconnect""#,
        Agnostic,
    ),
    (
        "live_admission.rs",
        r#"} else if d.kind != "sandbox.create" && d.restore.is_none() {"#,
        Routed,
    ),
    (
        "reconcile.rs",
        r#""sandbox.create" | "sandbox.reconnect""#,
        Agnostic,
    ),
    (
        "reconcile.rs",
        r#".unwrap_or(sandbox_runtime::AllocationKind::Create);"#,
        Routed,
    ),
    (
        "reconcile.rs",
        r#"(receipt.allocation_kind() == Some(sandbox_runtime::AllocationKind::Create))"#,
        Routed,
    ),
    (
        "reconcile.rs",
        r#"if row.lease.from_ready_ms.is_some() && receipt.kind == "sandbox.create" {"#,
        CreateOnly,
    ),
    (
        "supervisor.rs",
        r#"&& matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect") => journal"#,
        Agnostic,
    ),
    (
        "supervisor.rs",
        r#"("sandbox.reconnect" | "sandbox.kill", Some(offload)) => match offload"#,
        Agnostic,
    ),
    (
        "supervisor.rs",
        r#"("sandbox.create", Some(images)) if d.image.is_some() => images"#,
        CreateOnly,
    ),
    (
        "supervisor.rs",
        r#"("sandbox.create", None) if d.image.is_some() => Err(DispatchError {"#,
        CreateOnly,
    ),
    (
        "supervisor.rs",
        r#"("sandbox.reconnect", _) if d.restore.is_some() || d.expect_disk.is_some() => {"#,
        Routed,
    ),
    (
        "supervisor.rs",
        r#"if d.kind == "sandbox.create" || d.restore.is_some() =>"#,
        Routed,
    ),
    (
        "supervisor.rs",
        r#""sandbox.create" | "sandbox.reconnect" | "sandbox.lease.renew""#,
        Agnostic,
    ),
    (
        "supervisor.rs",
        r#"if d.kind == "sandbox.create" {"#,
        CreateOnly,
    ),
    (
        "supervisor.rs",
        r#"if matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect") =>"#,
        Agnostic,
    ),
    (
        "supervisor.rs",
        r#"if d.kind == "sandbox.create""#,
        CreateOnly,
    ),
    (
        "supervisor.rs",
        r#"let error = if matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect") {"#,
        Agnostic,
    ),
    (
        "supervisor.rs",
        r#"sandbox_runtime::AllocationKind::Create => runtime"#,
        Routed,
    ),
    (
        "supervisor.rs",
        r#"sandbox_runtime::AllocationKind::Reconnect => {"#,
        Routed,
    ),
    (
        "supervisor.rs",
        r#"let allocation = sandbox_runtime::AllocationKind::from_dispatch(dispatch);"#,
        Routed,
    ),
    ("supervisor.rs", r#""sandbox.create""#, Agnostic),
    ("supervisor.rs", r#"| "sandbox.reconnect""#, Agnostic),
    (
        "supervisor.rs",
        r#"if d.kind == "sandbox.reconnect" && d.restore.is_none() {"#,
        Routed,
    ),
    ("supervisor.rs", r#""sandbox.create" => {"#, CreateOnly),
    (
        "supervisor.rs",
        r#""sandbox.reconnect" if job.dispatch.restore.is_some() => {"#,
        Routed,
    ),
    ("supervisor.rs", r#""sandbox.reconnect" => {"#, Routed),
    ("supervisor.rs", r#"| "sandbox.create""#, Agnostic),
    (
        "terminal.rs",
        r#""sandbox.create" | "sandbox.reconnect" => dispatch.generation > *generation,"#,
        Agnostic,
    ),
    (
        "crates/sandbox-protocol/src/build.rs",
        r#"let create = d.kind == "sandbox.create";"#,
        CreateOnly,
    ),
    (
        "crates/sandbox-protocol/src/control.rs",
        r#""sandbox.create" | "sandbox.reconnect""#,
        Agnostic,
    ),
    (
        "crates/sandbox-protocol/src/credentials.rs",
        r#""sandbox.create","#,
        Agnostic,
    ),
    (
        "crates/sandbox-protocol/src/credentials.rs",
        r#""sandbox.reconnect","#,
        Agnostic,
    ),
    (
        "crates/sandbox-protocol/src/disk.rs",
        r#"let reconnect = d.kind == "sandbox.reconnect";"#,
        Routed,
    ),
    (
        "crates/sandbox-protocol/src/disk.rs",
        r#""sandbox.create" => mode == LaunchMode::NewRoot && d.restore.is_none(),"#,
        Routed,
    ),
    (
        "crates/sandbox-protocol/src/disk.rs",
        r#""sandbox.reconnect" => (mode == LaunchMode::NewRoot) == d.restore.is_some(),"#,
        Routed,
    ),
    (
        "crates/sandbox-protocol/src/dispatch.rs",
        r#""sandbox.create","#,
        Agnostic,
    ),
    (
        "crates/sandbox-protocol/src/dispatch.rs",
        r#""sandbox.reconnect","#,
        Agnostic,
    ),
    (
        "crates/sandbox-protocol/src/image.rs",
        r#""sandbox.create" => {"#,
        CreateOnly,
    ),
    (
        "crates/sandbox-protocol/src/image.rs",
        r#""sandbox.reconnect" => d.restore.is_some() && image.upstream.is_none(),"#,
        Routed,
    ),
    (
        "crates/sandbox-protocol/src/startup.rs",
        r#"matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect")"#,
        Agnostic,
    ),
    (
        "crates/sandbox-runtime/src/effect.rs",
        r#"("sandbox.create", _) => Some(Self::Create),"#,
        Routed,
    ),
    (
        "crates/sandbox-runtime/src/effect.rs",
        r#"("sandbox.reconnect", Some(sandbox_protocol::LaunchMode::NewRoot)) => {"#,
        Routed,
    ),
    (
        "crates/sandbox-runtime/src/effect.rs",
        r#"("sandbox.reconnect", _) => Some(Self::Reconnect),"#,
        Routed,
    ),
    (
        "crates/sandbox-runtime/src/effect.rs",
        r#"AllocationKind::Create => runtime.sandbox_exists(sandbox_id),"#,
        Routed,
    ),
    (
        "crates/sandbox-runtime/src/effect.rs",
        r#"AllocationKind::Reconnect => runtime.sandbox_may_be_running(sandbox_id),"#,
        Routed,
    ),
    (
        "crates/sandbox-runtime/src/incus/kvm.rs",
        r#"crate::AllocationKind::Create,"#,
        CreateOnly,
    ),
    (
        "crates/sandbox-runtime/src/reconcile.rs",
        r#"if matches!(kind, "sandbox.create" | "sandbox.reconnect")"#,
        Agnostic,
    ),
    (
        "crates/sandbox-runtime/src/reconcile.rs",
        r#""sandbox.create" | "sandbox.reconnect" | "sandbox.stop" | "sandbox.kill""#,
        Agnostic,
    ),
    (
        "crates/sandbox-runtime/src/reconcile.rs",
        r#"("sandbox.create" | "sandbox.reconnect", Some(SandboxLifecycleState::Ready)) => {"#,
        Agnostic,
    ),
    (
        "crates/sandbox-runtime/src/unsupported.rs",
        r#"crate::AllocationKind::Create,"#,
        CreateOnly,
    ),
];

/// C6c and C6d routed every `Pending` entry by launch mode; none is left.
const ROUTE_PENDING: usize = 0;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn inventory() -> BTreeMap<(String, String), Class> {
    let mut map = BTreeMap::new();
    for (file, line, class) in INVENTORY {
        let path = if file.starts_with("crates/") {
            (*file).to_owned()
        } else {
            format!("{CLI}/{file}")
        };
        let previous = map.insert((path, (*line).to_owned()), *class);
        assert!(
            previous.is_none(),
            "duplicate inventory entry {file} | {line}"
        );
    }
    map
}

fn in_sweep(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    path.ends_with(".rs")
        && !name.ends_with("_tests.rs")
        && name != "tests.rs"
        && name != "test_support.rs"
        && !path
            .split('/')
            .any(|part| part == "tests" || part == "target")
}

/// Code with string/char literals and line comments removed, for brace counts.
fn code_only(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                while let Some(n) = chars.next() {
                    if n == '\\' {
                        chars.next();
                    } else if n == '"' {
                        break;
                    }
                }
            }
            '\'' => {
                // A char literal ('x', '\n', '{'); a lifetime ('a) is left alone.
                let rest: String = chars.clone().take(3).collect();
                if let Some(escaped) = rest.strip_prefix('\\') {
                    if let Some(end) = escaped.find('\'') {
                        for _ in 0..end + 2 {
                            chars.next();
                        }
                    }
                } else if rest.chars().nth(1) == Some('\'') {
                    chars.next();
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'/') => break,
            _ => out.push(c),
        }
    }
    out
}

/// The production lines of a Rust source: `#[cfg(test)]` / `#[cfg(all(test, …))]`
/// items and `mod tests { … }` blocks are skipped by brace matching.
fn production_lines(text: &str) -> Vec<&str> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        let test_attr = trimmed.starts_with("#[")
            && (trimmed.contains("cfg(test") || trimmed.contains("cfg(all(test"));
        let tests_mod = trimmed.starts_with("mod tests {") || trimmed.starts_with("mod tests{");
        if !(test_attr || tests_mod) {
            out.push(lines[i]);
            i += 1;
            continue;
        }
        let mut j = i;
        if test_attr {
            j += 1;
            while j < lines.len() && lines[j].trim_start().starts_with("#[") {
                j += 1;
            }
        }
        let mut depth: i64 = 0;
        let mut opened = false;
        while j < lines.len() {
            let code = code_only(lines[j]);
            for c in code.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        opened = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if (opened && depth <= 0) || (!opened && code.trim_end().ends_with(';')) {
                break;
            }
            j += 1;
        }
        i = j + 1;
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn scan(files: &[(String, String)]) -> BTreeSet<(String, String)> {
    let mut hits = BTreeSet::new();
    for (path, text) in files {
        if !in_sweep(path) {
            continue;
        }
        for line in production_lines(text) {
            if PATTERNS.iter().any(|pattern| line.contains(pattern)) {
                hits.insert((path.clone(), line.trim().to_owned()));
            }
        }
    }
    hits
}

fn drift(
    hits: &BTreeSet<(String, String)>,
    inventory: &BTreeMap<(String, String), Class>,
) -> (Vec<String>, Vec<String>) {
    let unlisted = hits
        .iter()
        .filter(|hit| !inventory.contains_key(*hit))
        .map(|(file, line)| format!("{file} | {line}"))
        .collect();
    let stale = inventory
        .keys()
        .filter(|entry| !hits.contains(*entry))
        .map(|(file, line)| format!("{file} | {line}"))
        .collect();
    (unlisted, stale)
}

fn repo_files() -> Vec<(String, String)> {
    let root = repo_root();
    let mut paths = Vec::new();
    for dir in ROOTS {
        walk(&root.join(dir), &mut paths);
    }
    paths
        .into_iter()
        .filter_map(|path| {
            let relative = path
                .strip_prefix(&root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&path).ok()?;
            Some((relative, text))
        })
        .collect()
}

#[test]
fn lists_every_launch_branch_hit_and_no_stale_entry() {
    let (unlisted, stale) = drift(&scan(&repo_files()), &inventory());
    assert!(
        unlisted.is_empty() && stale.is_empty(),
        "unlisted: {unlisted:#?}\nstale: {stale:#?}"
    );
}

#[test]
fn canary_unrouted_create_branch_fails() {
    let mut files = repo_files();
    files.push((
        format!("{CLI}/canary.rs"),
        "fn new_root(kind: &str) -> bool {\n    kind == \"sandbox.create\"\n}\n".to_owned(),
    ));
    let (unlisted, stale) = drift(&scan(&files), &inventory());
    assert_eq!(
        unlisted,
        vec![format!("{CLI}/canary.rs | kind == \"sandbox.create\"")]
    );
    assert!(stale.is_empty());
}

#[test]
fn canary_stale_entry_and_test_code_is_outside_the_sweep() {
    let files = vec![
        (
            format!("{CLI}/x.rs"),
            "fn a() {}\n#[cfg(test)]\nmod t {\n    const K: &str = \"sandbox.create\";\n    fn b() { let _ = '{'; }\n}\n"
                .to_owned(),
        ),
        (format!("{CLI}/x_tests.rs"), "const K: &str = \"sandbox.create\";\n".to_owned()),
    ];
    let mut inventory = BTreeMap::new();
    inventory.insert(
        (format!("{CLI}/gone.rs"), "\"sandbox.create\"".to_owned()),
        CreateOnly,
    );
    let (unlisted, stale) = drift(&scan(&files), &inventory);
    assert!(unlisted.is_empty(), "{unlisted:?}");
    assert_eq!(stale, vec![format!("{CLI}/gone.rs | \"sandbox.create\"")]);
}

#[test]
fn route_pending_entries_are_counted_for_c6c() {
    let pending = INVENTORY
        .iter()
        .filter(|(_, _, class)| *class == Pending)
        .count();
    assert_eq!(pending, ROUTE_PENDING);
    assert!(INVENTORY.iter().any(|(_, _, class)| *class == Routed));
}
