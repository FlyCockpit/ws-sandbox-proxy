//! `wssp ssh-config` and the argv of `wssp ssh`, black-box: the generated
//! block and its ProxyCommand against hostile host names (through the real
//! OpenSSH client, the shells ssh hands the ProxyCommand to, and `--stdio`
//! itself), the binary path the block pins, the `--install` home check, the
//! host key across `wssp logout`, and the exact argv `wssp ssh` gives the
//! system ssh. The install itself (prompt races, Include detection, `ssh -G`
//! of the installed config) is covered by the unit tests in
//! `src/commands/sandbox/ssh/config.rs`, since ssh reads the account's home,
//! never a test's `$HOME`.
//!
//! A test that needs a missing client tool skips with a line saying why,
//! unless `WSSP_REQUIRE_SSH_TOOLS=1`, where it fails.
#![cfg(all(target_os = "linux", feature = "ssh"))]

use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[path = "../../../crates/sandbox-runtime/tests/support/managed_child.rs"]
mod managed_child;
use managed_child::ManagedChild;

const SECRET: &str = "wssp_sdk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const LIMIT: Duration = Duration::from_secs(60);

fn have(program: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Skip (with a line saying why) when a client tool is missing; fail
/// instead under `WSSP_REQUIRE_SSH_TOOLS=1`.
macro_rules! require {
    ($($program:expr),+) => {
        for program in [$($program),+] {
            if !have(program) {
                assert!(
                    std::env::var_os("WSSP_REQUIRE_SSH_TOOLS").is_none_or(|v| v != "1"),
                    "`{program}` is required (WSSP_REQUIRE_SSH_TOOLS=1)"
                );
                eprintln!("skipped: `{program}` is not installed");
                return;
            }
        }
    };
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The environment of a scratch wssp install under `root`.
fn wssp_env(command: &mut Command, root: &Path, server: &str) {
    command
        .env("HOME", root.join("home"))
        .env("WSSP_CONFIG_DIR", root.join("config"))
        .env("WSSP_DATA_DIR", root.join("data"))
        .env("WSSP_API_KEY", SECRET)
        .env("WSSP_SERVER", server)
        .env_remove("WSSP_USER_DIR")
        .env_remove("WSSP_CA_FILE")
        .env_remove("WSSP_LOG")
        .env_remove("RUST_LOG")
        .env_remove("SSH_AUTH_SOCK");
    for proxy in [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(proxy);
    }
}

fn wssp(root: &Path, server: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wssp"));
    wssp_env(&mut command, root, server);
    command
}

/// Run to completion (its process group killed after [`LIMIT`]), stdin
/// closed, through the shared child guard.
fn run(mut command: Command) -> Output {
    let child = ManagedChild::spawn(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap();
    let group = format!("-{}", child.id());
    let deadline = Instant::now() + LIMIT;
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if finished
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_err()
        {
            let _ = Command::new("kill").args(["-KILL", "--", &group]).status();
        }
    });
    let output = child.wait_with_output().unwrap();
    let _ = done.send(());
    watchdog.join().unwrap();
    output
}

/// A loopback listener that must never see a connection.
struct Untouched(TcpListener);

impl Untouched {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self(listener)
    }

    fn url(&self) -> String {
        format!("http://{}", self.0.local_addr().unwrap())
    }

    fn assert_untouched(&self, what: &str) {
        match self.0.accept() {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            other => panic!("{what}: the server saw a connection: {other:?}"),
        }
    }
}

/// `wssp ssh-config --json` under `root`.
fn report(root: &Path) -> serde_json::Value {
    let mut print = wssp(root, "http://127.0.0.1:9");
    print.args(["ssh-config", "--json"]);
    let output = run(print);
    assert!(output.status.success(), "{}", text(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn proxy_command_of(block: &str) -> String {
    block
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("ProxyCommand "))
        .unwrap()
        .to_owned()
}

/// An executable shell script at `path`.
fn script(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A recorder: writes its argv, NUL-terminated, to `$WSSP_TEST_ARGV`.
const RECORDER: &str = ": > \"$WSSP_TEST_ARGV\"\nfor a in \"$@\"; do printf '%s\\0' \"$a\" >> \"$WSSP_TEST_ARGV\"; done\n";

fn recorded(path: &Path) -> Vec<String> {
    let bytes = std::fs::read(path).unwrap();
    bytes
        .split(|b| *b == 0)
        .map(|arg| String::from_utf8(arg.to_vec()).unwrap())
        .collect::<Vec<_>>()
        .split_last()
        .map(|(last, rest)| {
            assert!(last.is_empty(), "unterminated argv");
            rest.to_vec()
        })
        .unwrap()
}

/// Host names that try to run `touch <marker>` through the ProxyCommand.
fn hostile(marker: &Path) -> Vec<String> {
    let m = marker.display();
    vec![
        format!("$(touch {m}).wssp"),
        format!("`touch {m}`.wssp"),
        format!("a;touch {m};.wssp"),
        format!("a\ntouch {m}\n.wssp"),
        format!("a && touch {m} && .wssp"),
        format!("a|touch {m}|.wssp"),
        "a b.wssp".to_owned(),
        format!("\"$(touch {m})\".wssp"),
        "$HOME.wssp".to_owned(),
        "-oProxyCommand=x.wssp".to_owned(),
    ]
}

// ------------------------------------------------------------ tests

#[test]
fn ssh_config_prints_the_block_and_keeps_the_host_key() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("home")).unwrap();
    let report = report(root.path());
    let block = report["config"].as_str().unwrap();
    assert!(block.starts_with("# Managed by wssp.\x20"));
    assert!(
        block.contains("\nHost *.wssp \"!*'*\" \"!*\\*\"\n"),
        "{block}"
    );
    assert!(
        block.contains(&format!(
            "ProxyCommand \"{}\" ssh --stdio '%n'\n",
            env!("CARGO_BIN_EXE_wssp")
        )),
        "{block}"
    );
    let known_hosts = PathBuf::from(report["knownHostsPath"].as_str().unwrap());
    let host_key = PathBuf::from(report["hostKeyPath"].as_str().unwrap());
    assert!(known_hosts.starts_with(root.path().join("data/user/ssh")));
    let entry = report["knownHostsEntry"].as_str().unwrap();
    assert!(entry.starts_with("wssp ssh-ed25519 "));
    assert_eq!(
        std::fs::read_to_string(&known_hosts).unwrap(),
        format!("{entry}\n")
    );
    // Nothing was installed without `--install`.
    assert!(!root.path().join("home/.ssh").exists());

    // A successful logout (local, then revoking at a server) removes the
    // login and keeps both host key files byte for byte.
    let files = |paths: &[&PathBuf]| -> Vec<Vec<u8>> {
        paths
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect()
    };
    let before = files(&[&host_key, &known_hosts]);
    let login = root.path().join("data/user/login.json");
    let save_login = |origin: &str| {
        let body = serde_json::json!({"origin":format!("{origin}/"),"keyId":"key-1","name":"laptop","secret":SECRET,"scopes":["sandboxes:connect"],"poolMode":"ALL_USABLE","poolIds":[],"ownSandboxesOnly":false,"expiresAt":null,"maxLiveSandboxes":null,"userEmail":"person@example.test","createdAt":"2026-11-18T00:00:00Z"});
        let staged = login.with_extension("fixture");
        std::fs::write(&staged, body.to_string()).unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&staged, &login).unwrap();
    };
    let logout = |args: &[&str]| {
        let mut command = wssp(root.path(), "http://127.0.0.1:9");
        command
            .env_remove("WSSP_API_KEY")
            .env_remove("WSSP_SERVER")
            .arg("logout")
            .args(args);
        run(command)
    };
    save_login("http://127.0.0.1:9");
    let output = logout(&["--local"]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(!login.exists());
    assert_eq!(files(&[&host_key, &known_hosts]), before);
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    server.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", server.local_addr().unwrap());
    let revoker = thread::spawn(move || {
        let deadline = Instant::now() + LIMIT;
        let mut stream = loop {
            match server.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "logout never called the server");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0_u8; 4096];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "request ended early");
            request.extend_from_slice(&buf[..n]);
        }
        let body = r#"{"id":"key-1","revoked":true}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        text(&request)
    });
    save_login(&origin);
    let output = logout(&["--json"]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(revoker.join().unwrap().starts_with("DELETE /v1/key "));
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["serverRevocation"], "revoked");
    assert!(!login.exists());
    assert_eq!(files(&[&host_key, &known_hosts]), before);

    // Rotation replaces the key.
    let mut rotate = wssp(root.path(), "http://127.0.0.1:9");
    rotate.args(["ssh-config", "--rotate-host-key", "--json"]);
    let output = run(rotate);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let rotated: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(rotated["knownHostsEntry"].as_str().unwrap(), entry);
    assert_eq!(rotated["hostKeyRotated"], true);
    assert_ne!(files(&[&host_key, &known_hosts]), before);
}

#[test]
fn install_refuses_without_a_prompt_or_in_a_home_ssh_does_not_read() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("home")).unwrap();
    // Without a terminal and without `--yes`: usage, nothing written.
    let mut install = wssp(root.path(), "http://127.0.0.1:9");
    install.args(["ssh-config", "--install"]);
    let account_home = Command::new("getent")
        .args(["passwd", &rustix::process::getuid().as_raw().to_string()])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| text(&output.stdout).split(':').nth(5).map(str::to_owned));
    let output = run(install);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    assert!(!root.path().join("home/.ssh").exists());
    // `$HOME` is the temporary one, not the account's: OpenSSH would never
    // read an install there, so `--install --yes` refuses and names both.
    let Some(account_home) = account_home else {
        eprintln!("skipped the home check: `getent passwd` does not know this user");
        return;
    };
    let mut install = wssp(root.path(), "http://127.0.0.1:9");
    install.args(["ssh-config", "--install", "--yes"]);
    let output = run(install);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("but ssh reads"), "{stderr}");
    assert!(
        stderr.contains(&format!("{account_home}/.ssh/config")),
        "{stderr}"
    );
    assert!(!root.path().join("home/.ssh").exists());
}

#[test]
fn the_block_names_the_invoked_binary_path() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("home")).unwrap();
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    // A version-manager style symlink: the block keeps the link, so an
    // upgrade behind it is picked up.
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_wssp"), bin.join("wssp")).unwrap();
    let block_via = |mut command: Command| {
        wssp_env(&mut command, root.path(), "http://127.0.0.1:9");
        command.args(["ssh-config", "--json"]);
        let output = run(command);
        assert!(output.status.success(), "{}", text(&output.stderr));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        proxy_command_of(report["config"].as_str().unwrap())
    };
    let linked = format!("\"{}\" ssh --stdio '%n'", bin.join("wssp").display());
    assert_eq!(block_via(Command::new(bin.join("wssp"))), linked);
    // Found on PATH by its bare name: the PATH entry.
    let mut bare = Command::new("wssp");
    bare.env("PATH", &bin);
    assert_eq!(block_via(bare), linked);
    // A relative invocation: the resolved binary.
    let mut relative = Command::new("./bin/wssp");
    relative.current_dir(root.path());
    let resolved = std::fs::canonicalize(env!("CARGO_BIN_EXE_wssp")).unwrap();
    assert_eq!(
        block_via(relative),
        format!("\"{}\" ssh --stdio '%n'", resolved.display())
    );
}

#[test]
fn hostile_host_names_never_reach_a_shell_or_the_network_through_stdio() {
    let root = tempfile::tempdir().unwrap();
    let server = Untouched::new();
    let marker = root.path().join("marker");
    for name in hostile(&marker) {
        let mut command = wssp(root.path(), &server.url());
        command.args(["ssh", "--stdio", &name]);
        let output = run(command);
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{name:?}: {stderr}");
        // A leading `-` is already refused by the argument parser.
        assert!(
            name.starts_with('-') || stderr.contains("invalid id"),
            "{name:?}: {stderr}"
        );
        server.assert_untouched(&name);
        assert!(!marker.exists(), "{name:?}");
    }
    // Refused before anything local either: no user directory was made.
    assert!(!root.path().join("data").exists());
}

#[test]
fn hostile_host_names_never_run_through_the_real_ssh() {
    require!("ssh");
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("home")).unwrap();
    let server = Untouched::new();
    let block = report(root.path())["config"].as_str().unwrap().to_owned();
    let config = root.path().join("block");
    std::fs::write(&config, &block).unwrap();
    let marker = root.path().join("marker");
    let mut names = hostile(&marker);
    names.push(format!("a'$(touch {})'.wssp", marker.display()));
    names.push(format!("a\\'$(touch {})\\'.wssp", marker.display()));
    for name in names {
        let mut ssh = Command::new("ssh");
        wssp_env(&mut ssh, root.path(), &server.url());
        ssh.arg("-F").arg(&config).args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=20",
            "--",
            &name,
            "true",
        ]);
        let output = run(ssh);
        assert!(!output.status.success(), "{name:?}");
        server.assert_untouched(&name);
        assert!(!marker.exists(), "{name:?}: {}", text(&output.stderr));
    }
}

/// What ssh does with the ProxyCommand: paste the name for `%n`, then
/// `$SHELL -c "exec <command>"`. Checked in every shell installed here
/// (independent of the OpenSSH version's own host name check), with the
/// binary replaced by a recorder.
#[test]
fn the_proxy_command_keeps_any_host_name_one_argument_in_every_shell() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("home")).unwrap();
    let block = report(root.path())["config"].as_str().unwrap().to_owned();
    let proxy = proxy_command_of(&block);
    let recorder = root.path().join("recorder/wssp");
    script(&recorder, RECORDER);
    let exe = format!("\"{}\"", env!("CARGO_BIN_EXE_wssp"));
    assert!(proxy.starts_with(&exe), "{proxy}");
    let proxy = proxy.replacen(&exe, &format!("\"{}\"", recorder.display()), 1);
    let marker = root.path().join("marker");
    let argv = root.path().join("argv");
    let shells: Vec<&str> = [
        "sh", "dash", "bash", "zsh", "ksh", "mksh", "fish", "tcsh", "csh",
    ]
    .into_iter()
    .filter(|shell| have(shell))
    .collect();
    assert!(shells.contains(&"sh"));
    eprintln!("shells: {shells:?}");
    let mut names = hostile(&marker);
    names.push("dev-box.wssp".to_owned());
    for shell in &shells {
        for name in &names {
            // Names holding `'` or `\` never match the block's `Host` line.
            assert!(!name.contains('\'') && !name.contains('\\'));
            let _ = std::fs::remove_file(&argv);
            let command = format!("exec {}", proxy.replace("%n", name));
            let mut run_it = Command::new(shell);
            run_it
                .arg("-c")
                .arg(&command)
                .env("WSSP_TEST_ARGV", &argv)
                .env("HOME", root.path().join("home"));
            let output = run(run_it);
            assert!(!marker.exists(), "{shell} {name:?}");
            if shell.ends_with("csh") && name.contains('\n') {
                // csh refuses a newline inside quotes: nothing runs.
                continue;
            }
            assert!(
                output.status.success(),
                "{shell} {name:?}: {}",
                text(&output.stderr)
            );
            assert_eq!(
                recorded(&argv),
                ["ssh", "--stdio", name.as_str()],
                "{shell} {name:?}"
            );
            assert!(!marker.exists(), "{shell} {name:?}");
        }
    }
}

/// The argv `wssp ssh` gives the system ssh, recorded by a PATH-selected
/// stand-in: every generated option as one `-o Keyword=value` pair before
/// the destination, then the user's arguments with their boundaries.
#[test]
fn wssp_ssh_passes_the_exact_argv() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("home")).unwrap();
    let report = report(root.path());
    let known_hosts = report["knownHostsPath"].as_str().unwrap().to_owned();
    let bin = root.path().join("bin");
    script(&bin.join("ssh"), RECORDER);
    let argv = root.path().join("argv");
    let mut command = wssp(root.path(), "http://127.0.0.1:9");
    command
        .env("PATH", &bin)
        .env("WSSP_TEST_ARGV", &argv)
        .args([
            "ssh",
            "dev-box",
            "--",
            "-t",
            "-o",
            "SendEnv=A B",
            "echo 'two words'",
            "",
        ]);
    let output = run(command);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let exe = env!("CARGO_BIN_EXE_wssp");
    let mut expected: Vec<String> = Vec::new();
    for option in [
        format!("ProxyCommand=\"{exe}\" ssh --stdio '%n'"),
        "User=wssp".to_owned(),
        "HostKeyAlias=wssp".to_owned(),
        format!("UserKnownHostsFile=\"{known_hosts}\""),
        "GlobalKnownHostsFile=/dev/null".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "HostKeyAlgorithms=ssh-ed25519".to_owned(),
        "CanonicalizeHostname=no".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        "IdentityFile=none".to_owned(),
        "ForwardAgent=no".to_owned(),
        "ForwardX11=no".to_owned(),
        "ServerAliveInterval=30".to_owned(),
    ] {
        expected.push("-o".to_owned());
        expected.push(option);
    }
    for arg in [
        "dev-box.wssp",
        "-t",
        "-o",
        "SendEnv=A B",
        "echo 'two words'",
        "",
    ] {
        expected.push(arg.to_owned());
    }
    assert_eq!(recorded(&argv), expected);
    // An id accepted as `<id>.wssp` too; anything else is refused first.
    let mut command = wssp(root.path(), "http://127.0.0.1:9");
    command
        .env("PATH", &bin)
        .env("WSSP_TEST_ARGV", &argv)
        .args(["ssh", "sbx_1.WSSP"]);
    let output = run(command);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(recorded(&argv).last().unwrap(), "sbx_1.wssp");
    let _ = std::fs::remove_file(&argv);
    let mut command = wssp(root.path(), "http://127.0.0.1:9");
    command
        .env("PATH", &bin)
        .env("WSSP_TEST_ARGV", &argv)
        .args(["ssh", "a;b"]);
    let output = run(command);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    assert!(!argv.exists());
}

/// The real ssh keeps the first value it reads, so a user's `-o` after the
/// generated ones cannot replace the ProxyCommand or loosen the host key
/// check. `-A`, `-X` and `-i` are flags the user chooses on purpose (the
/// endpoint refuses agent and X11 forwarding anyway, and offers a key only
/// to this local process).
#[test]
fn user_arguments_cannot_replace_the_generated_options() {
    require!("ssh");
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("home")).unwrap();
    let report = report(root.path());
    let known_hosts = report["knownHostsPath"].as_str().unwrap().to_owned();
    let effective = |user: &[&str]| {
        let mut command = wssp(root.path(), "http://127.0.0.1:9");
        command
            .args(["ssh", "dev-box", "--", "-F", "/dev/null", "-G"])
            .args(user);
        let output = run(command);
        assert!(output.status.success(), "{}", text(&output.stderr));
        text(&output.stdout)
    };
    let config = effective(&[
        "-o",
        "ProxyCommand=sh -c 'touch /tmp/never'",
        "-o",
        "User=root",
        "-o",
        "HostKeyAlias=other",
        "-o",
        "UserKnownHostsFile=/tmp/other",
        "-o",
        "GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "HostKeyAlgorithms=ssh-rsa",
        "-o",
        "CanonicalizeHostname=always",
        "-o",
        "IdentitiesOnly=no",
        "-o",
        "ForwardAgent=yes",
        "-o",
        "ForwardX11=yes",
    ]);
    for expected in [
        format!(
            "proxycommand \"{}\" ssh --stdio '%n'",
            env!("CARGO_BIN_EXE_wssp")
        ),
        "user wssp".to_owned(),
        "hostkeyalias wssp".to_owned(),
        format!("userknownhostsfile {known_hosts}"),
        "globalknownhostsfile /dev/null".to_owned(),
        "stricthostkeychecking true".to_owned(),
        "hostkeyalgorithms ssh-ed25519".to_owned(),
        "canonicalizehostname false".to_owned(),
        "identitiesonly yes".to_owned(),
        "identityfile none".to_owned(),
        "forwardagent no".to_owned(),
        "forwardx11 no".to_owned(),
        "serveraliveinterval 30".to_owned(),
    ] {
        assert!(
            config.lines().any(|line| line == expected),
            "{expected:?} missing in:\n{config}"
        );
    }
    // The documented on-purpose overrides.
    let config = effective(&["-A"]);
    assert!(
        config.lines().any(|line| line == "forwardagent yes"),
        "{config}"
    );
}

/// L4: `--stdio` that has to make the host key itself runs with another
/// wssp user directory than the ssh config names; it says so before the
/// session (ssh shows the line) and names the fix.
#[test]
fn stdio_names_the_fix_when_it_had_to_make_the_host_key() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("home")).unwrap();
    let stdio = || {
        // Nothing listens on port 9: the connect fails after the hint.
        let mut command = wssp(root.path(), "http://127.0.0.1:9");
        command.args(["ssh", "--stdio", "dev-box.wssp"]);
        run(command)
    };
    let output = stdio();
    let stderr = text(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("made a new ssh host key"), "{stderr}");
    assert!(stderr.contains("wssp ssh-config --install"), "{stderr}");
    let output = stdio();
    let stderr = text(&output.stderr);
    assert!(!stderr.contains("made a new ssh host key"), "{stderr}");
}
