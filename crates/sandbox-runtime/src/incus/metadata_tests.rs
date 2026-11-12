//! Real isolated helper, exclusively against generated temp directories.
use super::files::HELPER;
use crate::{DirectoryContinuation, ListDirRequest, ListDirResponse};
use sandbox_protocol::results::ResultBody;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wssp-metadata-{}",
            super::client::random_nonce().unwrap()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn helper(
    mode: &str,
    path: &Path,
    options: serde_json::Value,
    injection: &str,
) -> std::process::Output {
    let source = HELPER.replace("try:\n    run()", &format!("{injection}\ntry:\n    run()"));
    Command::new("python3")
        .args([
            "-I",
            "-c",
            &source,
            mode,
            path.to_str().unwrap(),
            &"a".repeat(64),
            "0",
            &options.to_string(),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}
fn success(out: std::process::Output) -> crate::metadata::GuestFileResult {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.len() <= crate::metadata::HOST_RESULT_MAX_BYTES);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!("WSSP_STATUS {} ok\n", "a".repeat(64))
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
fn failed(out: std::process::Output, code: &str) {
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!("WSSP_STATUS {} {code} none\n", "a".repeat(64))
    );
    assert!(out.stdout.is_empty());
}
fn entry(path: &Path) -> crate::EntryInfo {
    match success(helper("stat", path, serde_json::json!({}), "")).result {
        ResultBody::Stat { entry } => {
            assert!(entry.validate());
            entry
        }
        other => panic!("{other:?}"),
    }
}
fn request(
    root: &Path,
    depth: u32,
    limit: usize,
    continuation: Option<DirectoryContinuation>,
) -> ListDirRequest {
    ListDirRequest {
        path: root.to_str().unwrap().into(),
        depth,
        limit,
        generation: 7,
        continuation,
        template_fingerprint: String::new(),
        guest: Default::default(),
        sandbox_id: "s".into(),
        instance_name: "wssp-sbx-s".into(),
        operation_id: "o".into(),
        idempotency_key: "k".into(),
    }
}
fn page(request: &ListDirRequest, injection: &str) -> ListDirResponse {
    let response = success(helper(
        "list",
        Path::new(&request.path),
        serde_json::json!({"depth":request.depth,"limit":request.limit,"generation":request.generation,"lastKey":request.continuation.as_ref().map(|c| &c.last_key)}),
        injection,
    ));
    match response.result {
        ResultBody::List {
            path, depth, items, ..
        } => {
            let response = ListDirResponse {
                path,
                depth,
                items,
                continuation: response.continuation,
            };
            crate::metadata::validate_page(request, &response).unwrap();
            response
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn rich_metadata_preserves_root_links_other_mode_ownership_and_observed_names() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    let dir = Scratch::new();
    let file = dir.0.join(" space\n\t ");
    fs::write(&file, b"bytes").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o7754)).unwrap();
    failed(
        helper("stat", &file, serde_json::json!({}), ""),
        "protocol_error",
    );
    // Metadata INPUT rejects leading/trailing whitespace, but it must remain
    // representable as an observed directory entry.
    let observed = page(&request(&dir.0, 1, 100, None), "").items.remove(0);
    assert_eq!(observed.name, " space\n\t ");
    assert_eq!(observed.permissions, "rwsr-sr-T");
    assert_eq!(observed.mode, 0o7754);
    assert_eq!(observed.uid, fs::metadata(&file).unwrap().uid());
    assert_eq!(observed.gid, fs::metadata(&file).unwrap().gid());
    assert_eq!(observed.size, 5);
    assert!(observed.modified_time.is_some());
    assert!(observed.validate());
    let link = dir.0.join("dangling");
    symlink("missing target", &link).unwrap();
    assert_eq!(
        entry(&link).symlink_target.as_deref(),
        Some("missing target")
    );
    assert_eq!(
        entry(&link).r#type,
        sandbox_protocol::results::EntryType::Symlink
    );
    let fifo = dir.0.join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        entry(&fifo).r#type,
        sandbox_protocol::results::EntryType::Other
    );
    assert_eq!(entry(Path::new("/")).name, "/");
}

#[test]
fn directory_pages_are_byte_short_bounded_and_resume_after_emitted_key() {
    let dir = Scratch::new();
    for index in 0..205 {
        fs::write(dir.0.join(format!("{index:04}{}", "é".repeat(90))), b"x").unwrap();
    }
    let mut cursor = None;
    let mut observed = Vec::new();
    let mut pages = 0;
    loop {
        let response = page(&request(&dir.0, 1, 100, cursor), "");
        pages += 1;
        assert!(
            response.items.len() < 100,
            "byte cap must shorten this page"
        );
        observed.extend(response.items.iter().map(|e| e.name.clone()));
        cursor = response.continuation;
        if cursor.is_none() {
            break;
        }
        assert!(pages < 20);
    }
    assert!(pages >= 3);
    assert_eq!(observed.len(), 205);
    assert!(
        observed
            .windows(2)
            .all(|p| p[0].as_bytes() < p[1].as_bytes())
    );
}

#[test]
fn traversal_depth_and_no_follow_are_descriptor_relative() {
    use std::os::unix::fs::symlink;
    let dir = Scratch::new();
    let outside = Scratch::new();
    fs::write(outside.0.join("never-list"), b"secret").unwrap();
    symlink(&outside.0, dir.0.join("link")).unwrap();
    let mut nested = dir.0.clone();
    for _ in 0..9 {
        nested.push("nested");
        fs::create_dir(&nested).unwrap();
    }
    let shallow = page(&request(&dir.0, 1, 100, None), "");
    assert_eq!(shallow.items.len(), 2);
    let deep = page(&request(&dir.0, 8, 100, None), "");
    assert_eq!(deep.items.len(), 9);
    assert!(!deep.items.iter().any(|e| e.path.contains("never-list")));
    failed(
        helper(
            "stat",
            &dir.0.join("link/never-list"),
            serde_json::json!({}),
            "",
        ),
        "fs_symlink_refused",
    );
    failed(
        helper(
            "list",
            &dir.0.join("link"),
            serde_json::json!({"depth":1,"limit":100,"generation":7}),
            "",
        ),
        "fs_symlink_refused",
    );
    // Simulate an ancestor swapped into a symlink immediately before open.
    let swap = dir.0.join("swap");
    fs::create_dir(&swap).unwrap();
    let injection = format!(
        "original_open = os.open\ndef swapped(name, flags, *a, **kw):\n    if name == 'swap':\n        os.rmdir({swap:?})\n        os.symlink({outside:?}, {swap:?})\n    return original_open(name, flags, *a, **kw)\nos.open = swapped",
        swap = swap.to_str().unwrap(),
        outside = outside.0.to_str().unwrap()
    );
    failed(
        helper(
            "stat",
            &swap.join("never-list"),
            serde_json::json!({}),
            &injection,
        ),
        "fs_symlink_refused",
    );
}

#[test]
fn listing_heap_visit_time_and_entry_encoding_bounds_are_enforced() {
    use std::os::unix::ffi::OsStringExt;
    let dir = Scratch::new();
    for index in 0..120 {
        fs::write(dir.0.join(format!("file-{index:04}")), b"x").unwrap();
    }
    // Fail during traversal, not after collecting/sorting all entries.
    let instrument = "original_push = heapq.heappush\ndef bounded_push(heap, value):\n    assert len(heap) < 4, 'unbounded heap'\n    return original_push(heap, value)\nheapq.heappush = bounded_push\noriginal_sorted = sorted\ndef bounded_sort(values, *a, **kw):\n    assert len(values) <= 4, 'unbounded sort'\n    return original_sorted(values, *a, **kw)\nsorted = bounded_sort";
    assert_eq!(
        page(&request(&dir.0, 1, 3, None), instrument).items.len(),
        3
    );
    failed(
        helper(
            "list",
            &dir.0,
            serde_json::json!({"depth":1,"limit":3,"generation":7}),
            "original_scandir = os.scandir\nclass ManyEntries:\n    def __enter__(self):\n        with original_scandir(sys.argv[2]) as entries: self.child = next(entries)\n        return (self.child for _ in range(100001))\n    def __exit__(self, *args): pass\nos.scandir = lambda fd: ManyEntries()",
        ),
        "fs_listing_limit",
    );
    failed(
        helper(
            "list",
            &dir.0,
            serde_json::json!({"depth":1,"limit":100,"generation":7}),
            "VISIT_MAX = 100",
        ),
        "fs_listing_limit",
    );
    failed(
        helper(
            "list",
            &dir.0,
            serde_json::json!({"depth":1,"limit":100,"generation":7,"budgetMs":1}),
            "time.sleep(0.01)",
        ),
        "fs_listing_limit",
    );
    let invalid = dir.0.join(std::ffi::OsString::from_vec(vec![0xff]));
    fs::write(&invalid, b"x").unwrap();
    failed(
        helper(
            "list",
            &dir.0,
            serde_json::json!({"depth":1,"limit":100,"generation":7}),
            "",
        ),
        "fs_invalid_encoding",
    );
    fs::remove_file(&invalid).unwrap();
    failed(
        helper(
            "list",
            &dir.0,
            serde_json::json!({"depth":1,"limit":100,"generation":7}),
            "original_info = entry_info\ndef huge(*a):\n    value = original_info(*a)\n    value['symlinkTarget'] = 'x' * RESULT_BYTES\n    return value\nentry_info = huge",
        ),
        "fs_entry_too_large",
    );
    failed(
        helper(
            "stat",
            &dir.0,
            serde_json::json!({}),
            "original_stat = os.stat\nclass BadStat:\n    def __init__(self, st): self.st = st\n    def __getattr__(self, key): return 9007199254740992 if key == 'st_size' else getattr(self.st, key)\nos.stat = lambda *a, **kw: BadStat(original_stat(*a, **kw))",
        ),
        "fs_metadata_unrepresentable",
    );
}

#[test]
fn shared_limits_and_metadata_input_context_are_pinned() {
    let limits: sandbox_protocol::results::ResultLimits =
        serde_json::from_str(sandbox_protocol::results::RESULT_LIMITS_JSON).unwrap();
    assert_eq!(
        limits.host_result_max_bytes,
        crate::metadata::HOST_RESULT_MAX_BYTES
    );
    assert_eq!(limits.list_visit_max, crate::metadata::DIRECTORY_VISITS);
    assert_eq!(
        limits.observation_timeout_ms,
        crate::metadata::OBSERVATION_TIMEOUT.as_millis() as u64
    );
    for path in ["relative", "/a/../b", "/a\0b", "/a "] {
        assert!(crate::canonical_metadata_path(path, false).is_err());
    }
    assert_eq!(
        crate::canonical_metadata_path("//a/./b", false).unwrap(),
        "/a/b"
    );
    assert!(crate::canonical_metadata_path("//./", true).is_err());
    let dir = Scratch::new();
    let mut request = request(&dir.0, 1, 100, None);
    request.limit = 0;
    assert!(request.validate_page().is_err());
    request.limit = 101;
    assert!(request.validate_page().is_err());
}

/// B2-C-7: an entry removed or replaced between readdir and lstat/open is
/// missed by the live listing, not a failure of the whole page. The root
/// vanishing still fails.
#[test]
fn entries_vanishing_during_a_listing_are_skipped_but_a_missing_root_fails() {
    let dir = Scratch::new();
    for name in ["keep", "gone", "swapped"] {
        fs::create_dir(dir.0.join(name)).unwrap();
    }
    let race = format!(
        "original_info = entry_info\ndef racing_info(directory, name, path):\n    if name == 'gone':\n        os.rmdir(name, dir_fd=directory)\n    info = original_info(directory, name, path)\n    if name == 'swapped':\n        os.rmdir(name, dir_fd=directory)\n        open(os.path.join({root:?}, 'swapped'), 'w').close()\n    return info\nentry_info = racing_info",
        root = dir.0.to_str().unwrap()
    );
    let listed = page(&request(&dir.0, 2, 100, None), &race);
    let names: Vec<_> = listed.items.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["keep", "swapped"]);
    fs::remove_dir_all(&dir.0).unwrap();
    failed(
        helper(
            "list",
            &dir.0,
            serde_json::json!({"depth":1,"limit":100,"generation":7}),
            "",
        ),
        "fs_not_found",
    );
    fs::create_dir(&dir.0).unwrap();
}

/// B2-K-6: every helper bound is pinned to the shared limits JSON, as are
/// the host's own page constants. Drift fails here, not in a guest.
#[test]
fn helper_and_host_limits_are_pinned_to_the_shared_limits_json() {
    let limits: serde_json::Value =
        serde_json::from_str(sandbox_protocol::results::RESULT_LIMITS_JSON).unwrap();
    let pinned = |key: &str| limits[key].as_u64().unwrap();
    for (constant, key) in [
        ("RESULT_BYTES", "hostResultMaxBytes"),
        ("VISIT_MAX", "listVisitMax"),
        ("OBSERVATION_MS", "observationTimeoutMs"),
        ("LIST_LIMIT_MAX", "listMaxLimit"),
        ("DEPTH_MAX", "directoryDepthMax"),
    ] {
        let line = format!("\n{constant} = {}\n", pinned(key));
        assert!(
            HELPER.contains(&line),
            "helper {constant} drifted from {key}"
        );
    }
    assert_eq!(
        crate::metadata::DIRECTORY_LIMIT as u64,
        pinned("listMaxLimit")
    );
    assert_eq!(
        crate::metadata::DIRECTORY_LIMIT as u64,
        pinned("listDefaultLimit")
    );
    assert_eq!(
        crate::metadata::DIRECTORY_DEPTH as u64,
        pinned("directoryDepthMax")
    );
    assert_eq!(
        crate::metadata::DIRECTORY_VISITS as u64,
        pinned("listVisitMax")
    );
    assert_eq!(
        crate::metadata::HOST_RESULT_MAX_BYTES as u64,
        pinned("hostResultMaxBytes")
    );
    assert_eq!(
        crate::metadata::OBSERVATION_TIMEOUT.as_millis() as u64,
        pinned("observationTimeoutMs")
    );
    let wrapper = crate::metadata::HOST_RESULT_WRAPPER_BYTES;
    assert_eq!(wrapper, 1024);
    assert!(HELPER.contains(&format!("\nHOST_WRAPPER_BYTES = {wrapper}\n")));
    assert!(HELPER.contains("RESULT_BYTES - HOST_WRAPPER_BYTES"));
    // The helper's literals are used, not shadowed by inline numbers.
    assert!(HELPER.contains("1 <= depth <= DEPTH_MAX"));
    assert!(HELPER.contains("1 <= limit <= LIST_LIMIT_MAX"));
}

/// B2-K-5: one leading/trailing whitespace set across server, host and
/// helper, from the shared fixture the server's contract test also reads.
#[test]
fn path_whitespace_is_one_shared_set_for_host_and_helper() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../packages/config/src/sandbox-path-whitespace.json"
    ))
    .unwrap();
    let chars = |key: &str| -> Vec<char> {
        fixture[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| char::from_u32(c.as_u64().unwrap() as u32).unwrap())
            .collect()
    };
    let (whitespace, other) = (chars("whitespace"), chars("notWhitespace"));
    let mut sorted = crate::metadata::PATH_WHITESPACE.to_vec();
    sorted.sort();
    assert_eq!(sorted, whitespace);
    let codes: Vec<String> = whitespace.iter().map(|c| (*c as u32).to_string()).collect();
    assert!(HELPER.contains(&format!(
        "PATH_WHITESPACE = frozenset(chr(c) for c in ({}))",
        codes.join(", ")
    )));
    let dir = Scratch::new();
    for (ch, refused) in whitespace
        .iter()
        .map(|c| (*c, true))
        .chain(other.iter().map(|c| (*c, false)))
    {
        let path = format!("{}/missing{ch}", dir.0.display());
        assert_eq!(
            crate::canonical_metadata_path(&path, false).is_err(),
            refused,
            "host U+{:04X}",
            ch as u32
        );
        assert!(crate::canonical_metadata_path(&format!(" {path}"), false).is_err());
        let out = helper("stat", Path::new(&path), serde_json::json!({}), "");
        failed(
            out,
            if refused {
                "protocol_error"
            } else {
                "fs_not_found"
            },
        );
    }
}

#[test]
fn hostile_pages_cannot_change_context_escape_root_reorder_or_forge_metadata() {
    let dir = Scratch::new();
    for index in 0..4 {
        fs::write(dir.0.join(index.to_string()), b"x").unwrap();
    }
    let request = request(&dir.0, 1, 2, None);
    let valid = page(&request, "");
    let mut forged = valid.clone();
    forged.items.reverse();
    assert!(crate::metadata::validate_page(&request, &forged).is_err());
    let mut forged = valid.clone();
    forged.items[0].path = "/outside".into();
    assert!(crate::metadata::validate_page(&request, &forged).is_err());
    let mut forged = valid.clone();
    forged.items[0].permissions = "rwxrwxrwx".into();
    assert!(crate::metadata::validate_page(&request, &forged).is_err());
    let mut forged = valid.clone();
    forged.continuation.as_mut().unwrap().generation += 1;
    assert!(crate::metadata::validate_page(&request, &forged).is_err());
    let mut forged = valid;
    forged.continuation.as_mut().unwrap().last_key = "skipped".into();
    assert!(crate::metadata::validate_page(&request, &forged).is_err());
}
