//! Static qualification/default-gate exclusion guard. Never spawns a process.
use std::{
    fs,
    path::{Path, PathBuf},
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn files(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
            || path
                .file_name()
                .is_some_and(|name| name == "node_modules" || name == "target" || name == ".git")
        {
            continue;
        }
        if path.is_dir() {
            files(&path, extension, out);
        } else if path.extension().is_some_and(|v| v == extension) {
            out.push(path);
        }
    }
}

#[test]
fn hardware_qualification_is_a_non_executable_spec_excluded_from_default_targets() {
    let root = repo();
    let spec = root.join("docs/operations/host-isolation-qualification.md");
    let body = fs::read_to_string(&spec).unwrap();
    assert!(body.contains(
        "Automated tests do not execute these scenarios or establish live\nhardware isolation."
    ));
    for scenario in [
        "Approved/denied endpoints",
        "Shared-IP limitation",
        "DNS rebinding",
        "IPv6",
        "Lateral traffic",
        "Guest-root escape attempts",
    ] {
        assert!(body.contains(scenario), "missing {scenario}");
    }
    for manifest in [
        "Cargo.toml",
        "crates/sandbox-runtime/Cargo.toml",
        "apps/cli/Cargo.toml",
        "package.json",
        "apps/server/package.json",
        "apps/web/package.json",
    ] {
        let text = fs::read_to_string(root.join(manifest)).unwrap();
        assert!(
            !text.contains("host-isolation-qualification"),
            "spec must not be an executable target: {manifest}"
        );
    }
    assert_eq!(spec.extension().unwrap(), "md");
    assert!(
        !root
            .join("crates/sandbox-runtime/tests/host-isolation-qualification.rs")
            .exists()
    );
    assert!(
        !root
            .join("scripts/host-isolation-qualification.ts")
            .exists()
    );
}

#[test]
fn default_rust_tests_pin_shims_and_the_only_live_fixture_is_explicitly_ignored() {
    let root = repo();
    let live_path = root.join("apps/cli/src/sandbox_relay/expiry/tests.rs");
    let live = fs::read_to_string(&live_path).unwrap();
    let marker = "#[ignore = \"boots real Incus KVM VMs; opt in with WSSP_LIVE_INCUS=1\"]";
    assert_eq!(live.matches(marker).count(), 1);
    let start = live.find(marker).unwrap();
    let end = live[start + marker.len()..]
        .find("\n#[test]")
        .map_or(live.len(), |n| start + marker.len() + n);
    let ignored = &live[start..end];
    assert!(ignored.contains("fn expiry_live_incus_stop_destroy_and_restart_reconciliation()"));
    assert!(ignored.contains("std::env::var(\"WSSP_LIVE_INCUS\").as_deref() != Ok(\"1\")"));
    let mut sources = Vec::new();
    for dir in [
        "apps/cli/src",
        "apps/cli/tests",
        "crates/sandbox-runtime/src",
        "crates/sandbox-runtime/tests",
        "crates/sandbox-protocol/src",
    ] {
        files(&root.join(dir), "rs", &mut sources);
    }
    // Ban live executable/default-runtime entrypoints in reachable test bodies.
    // Production modules are inspected only from their inline test module.
    let banned = [
        ["Command::new(", "\"incus\")"].concat(),
        ["binary: ", "\"incus\"."].concat(),
        ["IncusConfig::", "from_env()"].concat(),
        ["default_", "runtime()"].concat(),
        ["build_runtime(HostRuntimeKind::", "IncusKvm)"].concat(),
        // C51: the PTY child is spawned through portable-pty, not Command.
        ["CommandBuilder::new(", "\"incus\")"].concat(),
        ["IncusClient::new(", "\"incus\""].concat(),
    ];
    for path in sources {
        if path.ends_with("no_live_incus.rs") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        let test_file = path.components().any(|p| p.as_os_str() == "tests")
            || path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with("_tests.rs");
        let mut tests = if test_file {
            source.clone()
        } else if let Some(start) = source.find("mod tests {") {
            source[start..].to_owned()
        } else {
            continue;
        };
        if path == live_path {
            tests.replace_range(start..end, "");
        }
        if path.ends_with("evidence_boundary_tests.rs") {
            // Pinned inert compile-fail source, never an executed runtime.
            // Any additional live selector still fails the scan below.
            let inert = "create_key: None, binary: \"incus\".into(), project: \"default\".into(),";
            assert_eq!(tests.matches(inert).count(), 1);
            assert!(tests.contains("\"--crate-type=lib\""));
            assert!(tests.contains("\"--emit=metadata\""));
            tests = tests.replace(inert, "compile-only bound-constructor probe");
        }
        for pattern in &banned {
            assert!(
                !tests.contains(pattern),
                "default tests may not select real Incus: {}: {pattern}",
                path.display()
            );
        }
    }
    let shim =
        fs::read_to_string(root.join("crates/sandbox-runtime/src/incus/shim_tests.rs")).unwrap();
    assert!(shim.contains("let (path, log) = write_shim(mode);"));
    assert!(shim.contains("binary: path.to_string_lossy().into_owned()"));
    assert!(shim.contains("install_executable(&path, &shim_script(mode, &log), 0o755);"));
    let cleanup =
        fs::read_to_string(root.join("crates/sandbox-runtime/tests/incus_surface_cleanup.rs"))
            .unwrap();
    assert!(cleanup.contains(".env(\"WSSP_INCUS_BINARY\", shim)"));
    // C51: PTY shim tests pin a temp-dir shim binary for every client.
    let pty = fs::read_to_string(root.join("crates/sandbox-runtime/src/incus/pty_shim_tests.rs"))
        .unwrap();
    assert_eq!(pty.matches("IncusClient::new(").count(), 1);
    assert!(pty.contains("super::shim_tests::install_executable(&binary, SHIM, 0o755);"));
    assert!(pty.contains(
        "let client = IncusClient::new(binary.to_string_lossy().into_owned(), \"default\");"
    ));
    assert!(pty.contains("assert!(Path::new(&client.binary).starts_with(std::env::temp_dir()));"));
    assert!(!pty.contains("IncusKvmRuntime::new("));
    // The production PTY spawn uses the configured client binary only.
    let spawn = fs::read_to_string(root.join("crates/sandbox-runtime/src/incus/pty.rs")).unwrap();
    assert!(spawn.contains("crate::host_child::incus_pty_command(&client.binary)"));
    assert!(spawn.contains("crate::host_child::command(&client.binary,"));
}

#[test]
fn typescript_wire_gate_overrides_incus_with_the_executable_fixture() {
    let root = repo();
    let relay = root.join("apps/server/src/sandbox-relay");
    // The shared daemon setup lives in `cancel-wire-fixtures.ts`; both
    // daemon gates (cancel-wire and relay-chaos) spawn through it.
    let fixtures = fs::read_to_string(relay.join("cancel-wire-fixtures.ts")).unwrap();
    assert!(fixtures.contains("WSSP_INCUS_BINARY: join(dir, \"incus\")"));
    assert!(fixtures.contains("const cancelIncusFixture"));
    // `incus` is a launcher that only imports the double, written beside it
    // (the module form caches its bytecode across the per-call processes).
    assert!(fixtures.contains("writeFile(join(dir, \"incus_double.py\"), cancelIncusFixture)"));
    assert!(fixtures.contains("writeFile(join(dir, \"incus\"), cancelIncusLauncher)"));
    let launcher = fixtures
        .split("const cancelIncusLauncher = `")
        .nth(1)
        .and_then(|rest| rest.split('`').next())
        .expect("launcher literal");
    assert_eq!(
        launcher.lines().filter(|l| !l.trim().is_empty()).count(),
        5,
        "the launcher only imports the double: {launcher}"
    );
    assert!(launcher.contains("sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))"));
    assert!(launcher.contains("import incus_double"));
    for gate in [
        "cancel-wire.contract.test.ts",
        "relay-chaos.contract.test.ts",
    ] {
        let source = fs::read_to_string(relay.join(gate)).unwrap();
        assert!(
            source.contains("from \"./cancel-wire-fixtures.js\""),
            "{gate} spawns its daemon through the shared incus shim"
        );
    }
    let mut tests = Vec::new();
    files(&root.join("apps"), "ts", &mut tests);
    for path in tests {
        if !path.to_string_lossy().contains(".test.") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        for method in ["spawn", "execFile", "exec", "spawnSync", "execFileSync"] {
            let pattern = format!("{method}(\"incus\"");
            assert!(
                !source.contains(&pattern),
                "no real Incus command in TS gates: {}",
                path.display()
            );
        }
    }
}

// All raw production builders belong to one audited construction boundary.
// Test modules/files are inventoried separately; no executable or kill exemption.
// The only other production sites are the two user-facing CLI programs below,
// pinned by exact line. They run for the person at their own terminal, never
// inside the daemon (`sandbox_relay`) or the runtime: `wssp ssh` `exec`s the
// user's own ssh, which needs the user's environment (SSH_AUTH_SOCK, TERM,
// HOME, ...), and `wssp ssh-config --install` asks `getent` for the passwd
// home, keeping only PATH. Do not add a daemon or runtime child here.
const USER_PROGRAMS: [(&str, &str); 2] = [
    (
        "apps/cli/src/commands/sandbox/ssh/config.rs",
        "let getent = std::process::Command::new(\"getent\")",
    ),
    (
        "apps/cli/src/commands/sandbox/ssh/mod.rs",
        "let mut command = std::process::Command::new(&ssh);",
    ),
];

#[test]
fn host_child_constructors_are_scrubbed() {
    let root = repo();
    let mut sources = Vec::new();
    for dir in ["crates", "apps/cli/src"] {
        files(&root.join(dir), "rs", &mut sources);
    }
    let constructors = ["Command", "CommandBuilder"].map(|name| format!("{name}::new("));
    let mut production = Vec::new();
    let mut test_only = Vec::new();
    let mut user_programs = Vec::new();
    for path in sources {
        let relative = path.strip_prefix(&root).unwrap();
        let source = fs::read_to_string(&path).unwrap();
        let test_file = relative.components().any(|p| p.as_os_str() == "tests")
            || relative
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with("_tests.rs")
            || relative.ends_with("test_support.rs")
            || relative.ends_with("tests.rs");
        // Inline tests in this workspace are trailing cfg(test) modules.
        // Reject a constructor outside those modules, including new files.
        let test_start = source
            .find("#[cfg(test)]\nmod tests {")
            .or_else(|| source.find("    #[cfg(test)]\n    mod tests {"))
            .or_else(|| source.find("#[cfg(all(test, unix))]\nmod tests {"))
            .unwrap_or(source.len());
        for (offset, _) in source.match_indices("::new(") {
            let line_start = source[..offset].rfind('\n').map_or(0, |n| n + 1);
            let line_end = source[offset..]
                .find('\n')
                .map_or(source.len(), |n| offset + n);
            let line = &source[line_start..line_end];
            if !constructors.iter().any(|needle| line.contains(needle)) {
                continue;
            }
            let site = format!(
                "{}:{}",
                relative.display(),
                source[..offset].lines().count()
            );
            if test_file || offset >= test_start {
                test_only.push(site);
            } else if USER_PROGRAMS
                .iter()
                .any(|&(file, text)| relative == Path::new(file) && line.trim() == text)
            {
                user_programs.push((
                    relative.to_str().unwrap().to_owned(),
                    line.trim().to_owned(),
                ));
            } else {
                assert_eq!(
                    relative,
                    Path::new("crates/sandbox-runtime/src/host_child.rs"),
                    "host child bypasses environment policy: {site}"
                );
                production.push(line.trim().to_string());
            }
        }
    }
    production.sort();
    assert_eq!(
        production,
        [
            "let mut builder = portable_pty::CommandBuilder::new(program);",
            "let mut command = Command::new(program);",
            "let mut command = portable_pty::CommandBuilder::new(\"/bin/sh\");",
        ],
        "only the three audited environment constructors may spawn host children"
    );
    assert!(!test_only.is_empty());
    user_programs.sort();
    assert_eq!(
        user_programs,
        USER_PROGRAMS.map(|(file, text)| (file.to_owned(), text.to_owned())),
        "each user-facing CLI program is pinned exactly once"
    );
    let getent = fs::read_to_string(root.join(USER_PROGRAMS[0].0)).unwrap();
    let getent = &getent[getent.find(USER_PROGRAMS[0].1).unwrap()..];
    let getent = &getent[..getent.find(".output()").unwrap()];
    assert!(getent.contains(".env_clear()"), "getent keeps only PATH");
    assert!(getent.contains(".envs(std::env::var_os(\"PATH\").map(|path| (\"PATH\", path)))"));
    let helper = fs::read_to_string(root.join("crates/sandbox-runtime/src/host_child.rs")).unwrap();
    assert!(helper.contains("command.env_clear().envs(inherited(policy))"));
    assert!(helper.contains("builder.env_clear()"));
    let terminal = helper
        .split("fn terminal_command_for(")
        .nth(1)
        .unwrap()
        .split("#[cfg(all(test,")
        .next()
        .unwrap();
    assert!(terminal.contains("command.env_clear()"));
    assert!(terminal.contains("command.arg(\"-i\")"));
    assert!(!terminal.contains("inherited("));
    assert!(helper.contains(r#"&["PATH", "HOME", "INCUS_DIR", "INCUS_SOCKET", "INCUS_CONF"]"#));
    assert!(helper.contains(r#"const PATH_ENV: &[&str] = &["PATH"]"#));
    let client =
        fs::read_to_string(root.join("crates/sandbox-runtime/src/incus/client.rs")).unwrap();
    assert!(client.contains(r#"command.env("LC_ALL", "C")"#));
    // Clearing at spawn/wait would erase the fixed locale applied after construction.
    assert!(!client.contains("env_clear("));
}

#[test]
fn executable_stdin_and_surface_fixtures_use_child_copy_installation() {
    let root = repo();
    let client =
        fs::read_to_string(root.join("crates/sandbox-runtime/src/incus/client.rs")).unwrap();
    let start = client.find("fn fake_incus_script(").unwrap();
    let end = client[start..].find("\n    fn large_body").unwrap() + start;
    assert!(client[start..end].contains("shim_tests::install_executable(&path, body, 0o755)"));
    assert!(!client[start..end].contains("fs::write("));
    let surface =
        fs::read_to_string(root.join("crates/sandbox-runtime/tests/incus_surface_cleanup.rs"))
            .unwrap();
    assert_eq!(surface.matches("install_executable(").count(), 2);
    assert!(surface.contains("Command::new(\"cp\").arg(&staged).arg(path).status()"));
    assert!(!surface.contains("fs::write(&shim"));
}
