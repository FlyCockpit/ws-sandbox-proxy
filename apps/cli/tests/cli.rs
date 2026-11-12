//! Black-box integration tests: run the built binary and assert on its
//! behavior (stdout, stderr, exit code). This is the highest-value test layer
//! for a CLI — it exercises argument parsing, dispatch, and output formatting
//! exactly as a user would.
//!
//! Tests use a throwaway config dir via `WSSP_CONFIG_DIR` so they never touch
//! the developer's real config.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

/// Build a `Command` for the binary with an isolated, empty config dir.
fn cli(config_dir: &std::path::Path) -> Command {
    let data_dir = config_dir.join("data");
    cli_with_data(config_dir, &data_dir)
}

fn cli_with_data(config_dir: &std::path::Path, data_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("wssp").expect("binary builds");
    cmd.env("WSSP_CONFIG_DIR", config_dir);
    cmd.env("WSSP_DATA_DIR", data_dir);
    // Never the machine's own egress guard: an empty stand-in for `/`.
    cmd.env("WSSP_TEST_GUARD_ROOT", config_dir.join("guard-root"));
    // Log-filter env vars from the developer's shell would override the flags
    // under test.
    cmd.env_remove("WSSP_LOG");
    cmd.env_remove("RUST_LOG");
    cmd
}

fn json_stdout(mut cmd: Command) -> Value {
    let stdout = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&stdout).expect("stdout is valid JSON")
}

#[test]
fn config_path_json_is_machine_readable() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = cli(tmp.path());
    cmd.args(["config", "--json", "path"]);
    let value = json_stdout(cmd);

    assert!(value["path"].as_str().is_some_and(|path| !path.is_empty()));
}

#[test]
fn config_show_json_is_machine_readable() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = cli(tmp.path());
    cmd.args(["config", "--json", "show"]);
    let value = json_stdout(cmd);

    assert!(value.is_object());
}

#[test]
fn config_init_json_reports_whether_it_created_the_file() {
    let tmp = tempfile::tempdir().unwrap();
    let mut first = cli(tmp.path());
    first.args(["config", "--json", "init"]);
    let first_value = json_stdout(first);

    let mut second = cli(tmp.path());
    second.args(["config", "--json", "init"]);
    let second_value = json_stdout(second);

    assert_eq!(first_value["created"], true);
    assert_eq!(second_value["created"], false);
    assert_eq!(first_value["path"], second_value["path"]);
}

#[test]
fn config_init_then_show() {
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path()).args(["config", "init"]).assert().success();
    let output = cli(tmp.path())
        .env("WSSP_RUNTIME", "fake")
        .args(["config", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = std::str::from_utf8(&output).unwrap();
    let _: toml::Value = toml::from_str(text).unwrap();
    assert!(text.contains("# runtime = \"fake\""));
    assert!(text.contains("WSSP_RUNTIME"));
}

#[test]
fn completions_generates_shell_script() {
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_wssp"));
}

#[test]
fn completions_for_each_shell_use_product_names() {
    let tmp = tempfile::tempdir().unwrap();
    for shell in ["bash", "zsh", "fish"] {
        let stdout = cli(tmp.path())
            .args(["completions", shell])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let text = String::from_utf8(stdout).expect("completions are utf-8");
        assert!(
            text.contains("wssp"),
            "{shell} completions must name the `wssp` binary"
        );
    }
}

#[test]
fn unknown_command_is_a_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    // clap exits 2 for usage errors.
    cli(tmp.path())
        .arg("definitely-not-a-command")
        .assert()
        .code(2);
}

#[test]
fn version_prints_package_version() {
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_commands() {
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: wssp"))
        .stdout(predicate::str::contains("Commands:"))
        .stdout(predicate::str::contains("config"))
        .stdout(predicate::str::contains("completions"))
        .stdout(predicate::str::contains("connect"))
        .stdout(predicate::str::contains("login"))
        .stdout(predicate::str::contains("logout"))
        .stdout(predicate::str::contains("token"));
}

#[test]
fn login_requires_slug_and_server_without_stdin() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = cli(tmp.path());
    cmd.args(["login", "--slug", "desk-01"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("server URL"));
}

#[test]
fn token_login_records_env_var_name_not_secret_value() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = cli(tmp.path());
    cmd.args(["token", "--json", "login", "WSSP_TEST_HOST_TOKEN"])
        .env(
            "WSSP_TEST_HOST_TOKEN",
            format!("wssp_host_{}", "B".repeat(43)),
        );
    let value = json_stdout(cmd);
    assert_eq!(value["hostTokenEnv"], "WSSP_TEST_HOST_TOKEN");
    let text = std::fs::read_to_string(tmp.path().join("config.toml")).unwrap();
    assert!(text.contains("WSSP_TEST_HOST_TOKEN"));
    assert!(!text.contains("wssp_host_secret"));
}

#[test]
fn global_log_flags_do_not_pollute_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .args(["--verbose", "--log-format", "json", "config", "path"])
        .assert()
        .success()
        .stdout(predicate::str::contains("config.toml"))
        .stdout(predicate::str::contains(r#""level":"DEBUG""#).not());
}

#[test]
fn quiet_conflicts_with_verbose() {
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .args(["--quiet", "--verbose", "config", "path"])
        .assert()
        .code(2);
}

#[test]
fn config_path_text_prints_path() {
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .args(["config", "path"])
        .assert()
        .success()
        .stdout(predicate::str::contains("config.toml"));
}

#[test]
fn config_show_text_prints_toml() {
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path()).args(["config", "show"]).assert().success();
}

#[test]
fn auth_command_help_matches_final_flags() {
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .args(["login", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--slug <SLUG>"));
    cli(tmp.path())
        .args(["connect", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--host-token-env"))
        .stdout(predicate::str::contains("required with a host token"))
        .stdout(predicate::str::contains("--token <").not());
    cli(tmp.path())
        .args(["logout", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--token").not())
        .stdout(predicate::str::contains("host token"));
}

#[test]
fn connect_command_concurrency_range_and_default() {
    use clap::Parser;
    use wssp::cli::{Cli, Command as CliCommand};
    for invalid in ["0", "257"] {
        let tmp = tempfile::tempdir().unwrap();
        cli(tmp.path())
            .args(["connect", "--max-concurrent-commands", invalid])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--max-concurrent-commands"));
    }
    for (args, expected) in [
        (vec!["wssp", "connect"], 16),
        (vec!["wssp", "connect", "--max-concurrent-commands", "1"], 1),
        (
            vec!["wssp", "connect", "--max-concurrent-commands", "256"],
            256,
        ),
    ] {
        let CliCommand::Connect(connect) = Cli::try_parse_from(args).unwrap().command else {
            panic!("connect args")
        };
        assert_eq!(connect.max_concurrent_commands, expected);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn config_show_detection_failure_is_successful_scalar_json_and_valid_toml() {
    let dir = tempfile::tempdir().unwrap();
    let config = "sandbox_memory_mib = 8192\nmax_sandbox_cpu_count = 4\n";
    std::fs::write(dir.path().join("config.toml"), config).unwrap();
    let mut json = cli(dir.path());
    json.env_remove("WSSP_RUNTIME")
        .env("WSSP_INCUS_BINARY", dir.path().join("absent-incus"))
        .args(["config", "show", "--json"]);
    let output = json.output().unwrap();
    assert!(
        output.status.success(),
        "config show must report detection failure successfully"
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["sandboxMemoryMib"], 8192);
    assert_eq!(value["maxSandboxCpuCount"], 4);
    assert_eq!(value["vmCapacity"]["runtime"], "incus");
    assert!(value["vmCapacity"]["detected"].is_null());
    assert!(value["vmCapacity"]["detectionError"].is_string());
    assert_eq!(value["vmCapacity"]["effective"]["memoryBudgetMiB"], 8192);
    let mut text = cli(dir.path());
    text.env_remove("WSSP_RUNTIME")
        .env("WSSP_INCUS_BINARY", dir.path().join("absent-incus"))
        .args(["config", "show"]);
    let output = text.assert().success().get_output().stdout.clone();
    let toml: toml::Value = toml::from_str(std::str::from_utf8(&output).unwrap()).unwrap();
    assert_eq!(toml["sandbox_memory_mib"].as_integer(), Some(8192));
    assert!(toml.get("vm_capacity").is_none());
    assert!(
        std::str::from_utf8(&output)
            .unwrap()
            .contains("# vm_capacity")
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("config.toml")).unwrap(),
        config
    );
}

#[test]
fn config_show_fake_reports_effective_capacity_without_new_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let mut json = cli(dir.path());
    json.env("WSSP_RUNTIME", "fake")
        .args(["config", "show", "--json"]);
    let value = json_stdout(json);
    assert_eq!(value["vmCapacity"]["runtime"], "fake");
    assert_eq!(value["vmCapacity"]["effective"]["memoryBudgetMiB"], 4096);
    assert_eq!(value["vmCapacity"]["effective"]["maxCpuCount"], 4);
    assert_eq!(value["vmCapacity"]["memorySource"], "detected");
    assert!(value["vmCapacity"]["detectionError"].is_null());
    let mut text = cli(dir.path());
    text.env("WSSP_RUNTIME", "fake").args(["config", "show"]);
    let output = text.assert().success().get_output().stdout.clone();
    let toml: toml::Value = toml::from_str(std::str::from_utf8(&output).unwrap()).unwrap();
    assert!(toml.get("vm_capacity").is_none());
    assert!(std::str::from_utf8(&output).unwrap().contains("4096"));
}

#[cfg(target_os = "linux")]
#[test]
fn config_show_daemon_totals_and_overrides_match_the_shared_resolver() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let shim = dir.path().join("incus");
    std::fs::write(&shim, "#!/bin/sh\n[ \"$1\" = query ] && [ \"$3\" = /1.0/resources ] || exit 1\nprintf '%s\\n' '{\"type\":\"sync\",\"status_code\":200,\"error_code\":0,\"metadata\":{\"memory\":{\"total\":17179869184},\"cpu\":{\"total\":8}}}'\n").unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut json = cli(dir.path());
    json.env_remove("WSSP_RUNTIME")
        .env("WSSP_INCUS_BINARY", &shim)
        .args(["config", "show", "--json"]);
    let value = json_stdout(json);
    assert_eq!(value["vmCapacity"]["derived"]["memoryBudgetMiB"], 12288);
    assert_eq!(value["vmCapacity"]["effective"]["memoryBudgetMiB"], 12288);
    assert_eq!(value["vmCapacity"]["detected"]["cpuThreads"], 8);
    assert!(value["vmCapacity"]["detectionError"].is_null());
}

/// One wssp daemon per Incus server, through the real binary: `connect`
/// refuses while another daemon's lease is live, before any other Incus
/// call; the test-only override is refused off loopback before Incus is
/// touched; `config show` reads Incus without ever claiming it.
#[cfg(target_os = "linux")]
#[test]
fn connect_refuses_an_incus_server_another_daemon_holds() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let shim = dir.path().join("incus");
    let log = dir.path().join("incus.log");
    std::fs::write(
        &shim,
        format!(
            r#"#!/usr/bin/python3 -I
import json, sys
args = sys.argv[1:]
open({log:?}, "a").write(" ".join(args) + "\n")
if args == ["query", "--raw", "/1.0/profiles?project=default&recursion=1"]:
    print(json.dumps({{"type": "sync", "status_code": 200, "error_code": 0, "metadata": [
        {{"name": "default", "config": {{}}, "devices": {{}}}},
        {{"name": "wssp-daemon-lease-3-0123456789abcdef", "config": {{
            "user.wssp.lease.identity": "0" * 32, "user.wssp.lease.claim": "c",
            "user.wssp.lease.host_id": "other-host", "user.wssp.lease.label": "other-label",
            "user.wssp.lease.machine": "box", "user.wssp.lease.pid": "77",
            "user.wssp.lease.expires_at": "99999999999"}}, "devices": {{}}}}]}}))
    sys.exit(0)
if args[:3] == ["query", "--raw", "/1.0/resources"]:
    print(json.dumps({{"type": "sync", "metadata": {{"memory": {{"total": 17179869184}}, "cpu": {{"total": 8}}}}}}))
    sys.exit(0)
sys.exit(1)
"#,
            log = log.to_str().unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let token = format!("{}{}", ["wssp", "host", ""].join("_"), "g".repeat(43));
    let connect = |server: &str, shared: Option<&str>| {
        let mut command = cli(dir.path());
        command
            .env("WSSP_INCUS_BINARY", &shim)
            .env_remove("WSSP_RUNTIME")
            .env_remove("WSSP_TEST_SHARED_INCUS")
            .env("WSSP_GUARD_TEST_HOST_TOKEN", &token)
            .args([
                "connect",
                "--runtime",
                "incus",
                "--host-token-env",
                "WSSP_GUARD_TEST_HOST_TOKEN",
                "--host-id",
                "this-host",
                "--server",
                server,
            ]);
        if let Some(value) = shared {
            command.env("WSSP_TEST_SHARED_INCUS", value);
        }
        command
            .timeout(std::time::Duration::from_secs(20))
            .output()
            .unwrap()
    };

    let output = connect("http://127.0.0.1:9", None);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(!stderr.contains(&token));
    for needle in [
        "another wssp daemon already drives this Incus server",
        "host `other-host` (label `other-label`, pid 77 on `box`)",
        "One wssp daemon per Incus server is supported",
        "Stop the other daemon",
        "wssp-daemon-lease-3-0123456789abcdef",
    ] {
        assert!(stderr.contains(needle), "{needle}: {stderr}");
    }
    // Refused before the runtime touched Incus (no project setup, no writes).
    let calls = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        calls,
        "query --raw /1.0/profiles?project=default&recursion=1\n"
    );

    std::fs::remove_file(&log).unwrap();
    let output = connect("https://wssp.example.com", Some("1"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("`WSSP_TEST_SHARED_INCUS` is a test-only override accepted only with a loopback control plane"),
        "{stderr}"
    );
    assert!(!log.exists(), "the refused override never reaches Incus");

    let mut show = cli(dir.path());
    show.env_remove("WSSP_RUNTIME")
        .env("WSSP_INCUS_BINARY", &shim)
        .args(["config", "show", "--json"]);
    json_stdout(show);
    let calls = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(!calls.contains("profiles"), "{calls}");
}

#[cfg(target_os = "linux")]
struct RelayHandshake;
#[cfg(target_os = "linux")]
impl tungstenite::handshake::server::Callback for RelayHandshake {
    fn on_request(
        self,
        request: &tungstenite::handshake::server::Request,
        mut response: tungstenite::handshake::server::Response,
    ) -> Result<
        tungstenite::handshake::server::Response,
        tungstenite::handshake::server::ErrorResponse,
    > {
        if let Some(protocol) = request.headers().get("Sec-WebSocket-Protocol") {
            response
                .headers_mut()
                .insert("Sec-WebSocket-Protocol", protocol.clone());
        }
        Ok(response)
    }
}

#[cfg(target_os = "linux")]
#[test]
fn connect_detection_failure_obeys_overrides_through_the_real_cli() {
    use std::{
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    for source in [
        "flags",
        "toml",
        "mixed",
        "oversized-detected",
        "reconnect-failure",
        "low-memory-flags",
        "low-memory-toml",
    ] {
        for (memory, cpu) in [(false, false), (true, false), (false, true), (true, true)] {
            if matches!(source, "oversized-detected" | "reconnect-failure") && (memory || cpu) {
                continue;
            }
            let retry_detection = source == "reconnect-failure";
            let oversized = source == "oversized-detected" || retry_detection;
            let low_memory = source.starts_with("low-memory");
            let flag_memory = source == "flags" || source == "low-memory-flags";
            let toml_cpu = source == "toml" || source == "low-memory-toml";
            let dir = tempfile::tempdir().unwrap();
            let shim = dir.path().join("incus");
            std::fs::write(&shim,r#"#!/usr/bin/env python3
import json,sys
args=sys.argv[1:]
if args[:1]==['--project']: args=args[2:]
if args[0]=='version': sys.exit(0)
if args[0]=='profile':
 print(json.dumps([{'name':'default','devices':{'root':{'type':'disk','path':'/','pool':'pool'},'eth0':{'type':'nic','network':'net'}}}]))
 sys.exit(0)
if args[0]=='list' or (args[0]=='network' and 'list' in args): print('[]'); sys.exit(0)
if args[0]=='query':
 if args[-1].startswith('/1.0/storage-pools/'):
  print(json.dumps({'type':'error','error_code':403,'error':'Forbidden'}));sys.exit(1)
 if args[-1].startswith('/1.0/projects/'):
  print(json.dumps({'type':'sync','metadata':{'name':'default','config':{}}}));sys.exit(0)
 if args[-1]=='/1.0/resources':
  from pathlib import Path
  if (Path(__file__).parent/'oversized').exists():
   print(json.dumps({'type':'sync','status_code':200,'error_code':0,'metadata':{'memory':{'total':32*1024*1024*1024*1024},'cpu':{'total':128}}}))
   sys.exit(0)
  if (Path(__file__).parent/'low-memory').exists():
   print(json.dumps({'type':'sync','status_code':200,'error_code':0,'metadata':{'memory':{'total':2*1024*1024*1024},'cpu':{'total':4}}}))
   sys.exit(0)
  sys.exit(1)
 print(json.dumps({'type':'sync','status_code':200,'error_code':0,'metadata':{'api_extensions':[]}}))
 sys.exit(0)
sys.exit(1)
"#).unwrap();
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
            if oversized {
                std::fs::write(dir.path().join("oversized"), "").unwrap();
            }
            if low_memory {
                std::fs::write(dir.path().join("low-memory"), "").unwrap();
            }
            let mut config = String::new();
            if memory && !flag_memory {
                config.push_str("sandbox_memory_mib = 4096\n");
            }
            if cpu && toml_cpu {
                config.push_str("max_sandbox_cpu_count = 4\n");
            }
            std::fs::write(dir.path().join("config.toml"), config).unwrap();
            if low_memory {
                let mut show = cli(dir.path());
                show.env("WSSP_INCUS_BINARY", &shim)
                    .env_remove("WSSP_RUNTIME")
                    .args(["config", "show", "--json"]);
                let view = json_stdout(show);
                assert_eq!(view["vmCapacity"]["detected"]["cpuThreads"], 4);
                assert_eq!(
                    view["vmCapacity"]["detected"]["memoryTotalBytes"],
                    2147483648_u64
                );
                assert!(view["vmCapacity"]["memoryError"].is_string());
                assert!(view["vmCapacity"]["detectionError"].is_null());
            }
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = if (memory && (cpu || low_memory)) || oversized {
                listener.set_nonblocking(true).unwrap();
                let resources_marker = dir.path().join("oversized");
                Some(std::thread::spawn(move || {
                    let mut reconnected = false;
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while Instant::now() < deadline {
                        if let Ok((stream, _)) = listener.accept() {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(5)))
                                .unwrap();
                            let mut ws = tungstenite::accept_hdr(stream, RelayHandshake).unwrap();
                            let Ok(hello) = ws.read() else {
                                return false;
                            };
                            let value: Value =
                                serde_json::from_str(hello.to_text().unwrap()).unwrap();
                            if retry_detection && !reconnected {
                                assert_eq!(value["type"], "hello");
                                std::fs::remove_file(&resources_marker).unwrap();
                                reconnected = true;
                                drop(ws);
                                continue;
                            }
                            if reconnected {
                                // A reconnect dials before re-observing the
                                // host (review r3 P2): its detection runs
                                // after hello.ok, before host.admission.
                                ws.send(tungstenite::Message::Text(
                                    include_str!(
                                        "../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
                                    )
                                    .into(),
                                ))
                                .unwrap();
                                while let Ok(frame) = ws.read() {
                                    if frame.to_text().is_ok_and(|t| t.contains("host.admission")) {
                                        break;
                                    }
                                }
                            }
                            // 4003 is the only server close that ends the
                            // daemon; any other close reconnects (P0-1).
                            ws.close(Some(tungstenite::protocol::CloseFrame {
                                code: tungstenite::protocol::frame::coding::CloseCode::Library(
                                    4003,
                                ),
                                reason: "credential_inactive".into(),
                            }))
                            .unwrap();
                            let _ = ws.read();
                            return value["type"] == "hello";
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    false
                }))
            } else {
                None
            };
            let token = format!("{}{}", ["wssp", "host", ""].join("_"), "a".repeat(43));
            let mut command = cli(dir.path());
            command
                .env("WSSP_INCUS_BINARY", &shim)
                .env("WSSP_INCUS_PROJECT", "default")
                // Capacity only: the shim models no Incus server lease.
                .env("WSSP_TEST_SHARED_INCUS", "1")
                .env_remove("WSSP_RUNTIME")
                .env("WSSP_B3_HOST_TOKEN", &token)
                .args([
                    "connect",
                    "--sandbox-vcpu-budget",
                    "8",
                    "--host-token-env",
                    "WSSP_B3_HOST_TOKEN",
                    "--host-id",
                    "host",
                    "--server",
                    &format!("http://{address}"),
                ]);
            if memory && flag_memory {
                command.args(["--sandbox-memory-mib", "4096"]);
            }
            if cpu && !toml_cpu {
                command.args(["--max-sandbox-cpu-count", "4"]);
            }
            let output = command.timeout(Duration::from_secs(8)).output().unwrap();
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(!diagnostic.contains(&token));
            if let Some(server) = server {
                assert!(
                    server.join().unwrap(),
                    "both overrides must reach relay startup ({source}): {diagnostic}"
                );
                // Ended by the test server's 4003 close (exit code 4).
                assert_eq!(output.status.code(), Some(4), "{diagnostic}");
                assert!(
                    diagnostic.contains("effective host capacity"),
                    "{diagnostic}"
                );
                let memory_source = if memory {
                    if flag_memory { "flag" } else { "toml" }
                } else if oversized {
                    "detected" // Kernel MemTotal caps the synthetic installed-RAM figure.
                } else {
                    "clamped"
                };
                if !low_memory {
                    assert!(
                        diagnostic.contains(&format!("memory_source=\"{memory_source}\"")),
                        "{diagnostic}"
                    );
                }
                if retry_detection {
                    assert!(
                        diagnostic.contains("reusing last good host capacity"),
                        "{diagnostic}"
                    );
                } else if oversized || low_memory {
                    assert!(
                        !diagnostic.contains("resource detection failed"),
                        "bare connect must clamp detected capacity"
                    );
                } else {
                    assert!(
                        diagnostic.contains("trusting both configured capacity overrides"),
                        "{diagnostic}"
                    );
                }
            } else {
                assert!(!output.status.success());
                assert_eq!(
                    diagnostic.contains("--sandbox-memory-mib"),
                    !memory,
                    "{diagnostic}"
                );
                assert_eq!(
                    diagnostic.contains("--max-sandbox-cpu-count"),
                    !cpu && !low_memory,
                    "{diagnostic}"
                );
            }
        }
    }
}

#[test]
fn systemd_execstart_keeps_capacity_overrides_optional() {
    let unit = include_str!("../examples/wssp-host.service");
    let exec = unit
        .lines()
        .find(|line| line.starts_with("ExecStart="))
        .unwrap();
    assert_eq!(exec, "ExecStart=%h/.local/bin/wssp connect --runtime incus");
}

#[test]
fn invalid_capacity_toml_is_a_keyed_diagnostic_in_show_and_error_elsewhere() {
    for key in ["sandbox_memory_mib", "max_sandbox_cpu_count"] {
        for value in [
            "-1",
            "1000",
            "4294967296",
            "18446744073709551616",
            "\"invalid\"",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let other_key = if key == "sandbox_memory_mib" {
                "max_sandbox_cpu_count = 4"
            } else {
                "sandbox_memory_mib = 2048"
            };
            let original = format!(
                "server_url = \"https://config.example\"\nhost_slug = \"preserved\"\n{key} = {value}\n{other_key}\n"
            );
            std::fs::write(dir.path().join("config.toml"), &original).unwrap();
            let mut show = cli(dir.path());
            show.env("WSSP_RUNTIME", "fake")
                .args(["config", "show", "--json"]);
            let view = json_stdout(show);
            assert_eq!(view["serverUrl"], "https://config.example");
            assert_eq!(view["hostSlug"], "preserved");
            assert_eq!(view["configErrors"].as_array().unwrap().len(), 1);
            let diagnostic = view["configErrors"][0].as_str().unwrap();
            assert!(diagnostic.contains(key));
            assert!(diagnostic.contains("config file"));
            assert!(!diagnostic.contains("--"));
            let mut show = cli(dir.path());
            show.env("WSSP_RUNTIME", "fake").args(["config", "show"]);
            let output = show.assert().success().get_output().stdout.clone();
            let text = std::str::from_utf8(&output).unwrap();
            let parsed: toml::Value = toml::from_str(text).unwrap();
            assert_eq!(
                parsed["server_url"].as_str(),
                Some("https://config.example")
            );
            assert_eq!(parsed["host_slug"].as_str(), Some("preserved"));
            let valid_key = if key == "sandbox_memory_mib" {
                "max_sandbox_cpu_count"
            } else {
                "sandbox_memory_mib"
            };
            assert!(parsed.get(valid_key).is_some());
            assert!(parsed.get(key).is_none());
            assert!(text.contains(&format!("# invalid config file value for `{key}`")));
            let mut connect = cli(dir.path());
            connect.env("WSSP_RUNTIME", "fake").args(["connect"]);
            let output = connect.assert().failure().get_output().stderr.clone();
            let diagnostic = std::str::from_utf8(&output).unwrap();
            assert!(diagnostic.contains(key), "{diagnostic}");
            assert!(diagnostic.contains("config file"), "{diagnostic}");
            assert!(!diagnostic.contains("--sandbox-memory-mib"));
            assert_eq!(
                std::fs::read_to_string(dir.path().join("config.toml")).unwrap(),
                original
            );
        }
    }
}

#[test]
fn config_errors_keep_locations_without_echoing_capacity_values() {
    for (body, location) in [
        (
            "sandbox_memory_mib = 18446744073709551616\nhost_slug = ",
            "line 2, column 13",
        ),
        (
            "sandbox_memory_mib = 1000\nhost_slug = 123",
            "line 2, column 13",
        ),
        ("# comment\nhost_slug = ", "line 2, column 13"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), body).unwrap();
        for args in [
            vec!["config", "show"],
            vec!["config", "show", "--json"],
            vec!["connect"],
            vec!["drain"],
        ] {
            let mut cmd = cli(dir.path());
            cmd.env("WSSP_RUNTIME", "fake").args(args);
            let output = cmd.assert().failure().get_output().stderr.clone();
            let diagnostic = std::str::from_utf8(&output).unwrap();
            assert!(diagnostic.contains(location), "{diagnostic}");
            assert!(!diagnostic.contains("18446744073709551616"));
            assert!(!diagnostic.contains("1000"));
        }
    }
}

#[test]
fn set_max_lease_validates_saves_and_warns_without_a_terminal_revision() {
    let tmp = tempfile::tempdir().unwrap();
    let mut command = cli(tmp.path());
    command.args(["config", "show", "--json"]);
    assert_eq!(json_stdout(command)["maxLease"], "24h");
    let assert = cli(tmp.path())
        .args(["config", "set-max-lease", "6h"])
        .assert()
        .success();
    let output = assert.get_output();
    assert!(String::from_utf8_lossy(&output.stdout).contains("`6h`"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("shortened"));
    let mut command = cli(tmp.path());
    command.args(["config", "set-max-lease", "unlimited", "--json"]);
    let saved = json_stdout(command);
    assert_eq!(saved["key"], "maxLease");
    assert_eq!(saved["value"], "unlimited");
    for invalid in ["4m", "25d", "6", "forever"] {
        cli(tmp.path())
            .args(["config", "set-max-lease", invalid])
            .assert()
            .failure();
    }
    let mut command = cli(tmp.path());
    command.args(["config", "show", "--json"]);
    let shown = json_stdout(command);
    assert_eq!(shown["maxLease"], "unlimited");
    assert_eq!(shown["hostTerminalPolicyRevision"], 0);
}

#[test]
fn carry_setters_validate_save_show_and_restore_defaults() {
    let tmp = tempfile::tempdir().unwrap();
    let mut command = cli(tmp.path());
    command.args(["config", "show", "--json"]);
    let shown = json_stdout(command);
    assert_eq!(shown["carryIntentWindow"], "10m");
    assert_eq!(shown["maxCarry"], "24h");
    let assert = cli(tmp.path())
        .args(["config", "set-carry-intent-window", "30m"])
        .assert()
        .success();
    assert!(String::from_utf8_lossy(&assert.get_output().stdout).contains("`30m`"));
    let mut command = cli(tmp.path());
    command.args(["config", "set-max-carry", "7d", "--json"]);
    let saved = json_stdout(command);
    assert_eq!(saved["key"], "maxCarry");
    assert_eq!(saved["value"], "7d");
    for (key, invalid) in [
        ("set-carry-intent-window", "30s"),
        ("set-carry-intent-window", "2d"),
        ("set-max-carry", "9m"),
        ("set-max-carry", "25d"),
        ("set-max-carry", "unlimited"),
    ] {
        cli(tmp.path())
            .args(["config", key, invalid])
            .assert()
            .failure();
    }
    let mut command = cli(tmp.path());
    command.args(["config", "show", "--json"]);
    let shown = json_stdout(command);
    assert_eq!(shown["carryIntentWindow"], "30m");
    assert_eq!(shown["maxCarry"], "7d");
    assert_eq!(shown["hostTerminalPolicyRevision"], 0);
    cli(tmp.path())
        .args(["config", "set-max-carry", "default"])
        .assert()
        .success();
    let mut command = cli(tmp.path());
    command.args(["config", "show", "--json"]);
    assert_eq!(json_stdout(command)["maxCarry"], "24h");
}

#[test]
fn builder_setters_save_and_show_without_a_terminal_revision() {
    let tmp = tempfile::tempdir().unwrap();
    let show = |path: &std::path::Path| {
        let mut command = cli(path);
        command.args(["config", "show"]);
        String::from_utf8(command.assert().success().get_output().stdout.clone()).unwrap()
    };
    assert!(!show(tmp.path()).contains("builder"));
    for (sub, value, key, saved) in [
        ("set-builder", "off", "builder", "false"),
        (
            "set-accept-foreign-builds",
            "on",
            "acceptForeignBuilds",
            "true",
        ),
    ] {
        let mut command = cli(tmp.path());
        command.args(["config", sub, value, "--json"]);
        let out = json_stdout(command);
        assert_eq!(out["key"], key);
        assert_eq!(out["value"], saved);
    }
    let text = show(tmp.path());
    assert!(text.contains("builder = false"), "{text}");
    assert!(text.contains("accept_foreign_builds = true"), "{text}");
    let mut command = cli(tmp.path());
    command.args(["config", "set-builder", "default", "--json"]);
    assert_eq!(json_stdout(command)["value"], "default");
    assert!(!show(tmp.path()).contains("builder ="));
    cli(tmp.path())
        .args(["config", "set-builder", "maybe"])
        .assert()
        .failure();
    let mut command = cli(tmp.path());
    command.args(["config", "show", "--json"]);
    assert_eq!(json_stdout(command)["hostTerminalPolicyRevision"], 0);
}

#[test]
fn host_terminal_setters_are_local_atomic_and_inspectable() {
    let tmp = tempfile::tempdir().unwrap();
    let mut command = cli(tmp.path());
    command.args(["config", "show", "--json"]);
    let initial = json_stdout(command);
    assert_eq!(initial["allowHostTerminal"], false);
    assert_eq!(initial["hostTerminalRequireTotp"], true);
    for (sub, value) in [
        ("set-host-terminal", "on"),
        ("set-host-terminal-totp", "optional"),
        ("set-host-terminal", "off"),
        ("set-host-terminal", "off"),
    ] {
        cli(tmp.path())
            .args(["config", sub, value])
            .assert()
            .success();
    }
    let mut command = cli(tmp.path());
    command.args(["config", "show", "--json"]);
    let saved = json_stdout(command);
    assert_eq!(saved["allowHostTerminal"], false);
    assert_eq!(saved["hostTerminalRequireTotp"], false);
    assert_eq!(saved["hostTerminalPolicyRevision"], 4);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(tmp.path().join("config.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let mut command = cli(tmp.path());
    command.args(["config", "set-host-terminal-totp", "required", "--json"]);
    assert_eq!(json_stdout(command)["key"], "hostTerminalRequireTotp");
    cli(tmp.path())
        .args(["connect", "--host-terminal", "off", "--help"])
        .assert()
        .success();
}

#[test]
fn egress_config_setters_persist_and_show_reports_effective_values_and_guard() {
    let tmp = tempfile::tempdir().unwrap();
    let shown = json_stdout({
        let mut cmd = cli(tmp.path());
        cmd.args(["config", "show", "--json"])
            .env("WSSP_RUNTIME", "fake");
        cmd
    });
    assert!(shown["openEgressForOthers"].is_null());
    assert_eq!(shown["egressBlockSmtp"], true);
    assert_eq!(shown["egressBlockExternalDns"], false);
    assert_eq!(shown["egressDnsUpstreams"], serde_json::json!([]));
    assert_eq!(shown["guard"]["installed"], false);
    assert_eq!(shown["guard"]["reason"], "guard_unreachable");

    for (args, key, value) in [
        (
            &["set-open-egress-for-others", "on"][..],
            "openEgressForOthers",
            "true",
        ),
        (
            &["set-egress-block-smtp", "off"][..],
            "egressBlockSmtp",
            "false",
        ),
        (
            &["set-egress-block-external-dns", "on"][..],
            "egressBlockExternalDns",
            "true",
        ),
        (
            &["set-egress-dns-upstreams", "1.1.1.1,9.9.9.9"][..],
            "egressDnsUpstreams",
            "1.1.1.1,9.9.9.9",
        ),
    ] {
        let mut cmd = cli(tmp.path());
        cmd.args(["config", "--json"]).args(args);
        let set = json_stdout(cmd);
        assert_eq!(set["key"], key);
        assert_eq!(set["value"], value);
    }
    let shown = json_stdout({
        let mut cmd = cli(tmp.path());
        cmd.args(["config", "show", "--json"])
            .env("WSSP_RUNTIME", "fake");
        cmd
    });
    assert_eq!(shown["openEgressForOthers"], true);
    assert_eq!(shown["egressBlockSmtp"], false);
    assert_eq!(shown["egressBlockExternalDns"], true);
    assert_eq!(
        shown["egressDnsUpstreams"],
        serde_json::json!(["1.1.1.1", "9.9.9.9"])
    );
    let text = cli(tmp.path())
        .env("WSSP_RUNTIME", "fake")
        .args(["config", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.contains("# egress_dns_upstreams = 1.1.1.1,9.9.9.9"),
        "{text}"
    );
    assert!(text.contains("guard install --daemon-user"), "{text}");
    toml::from_str::<toml::Value>(&text).expect("show output stays valid TOML");

    // Turning consent off warns about running foreign sandboxes.
    cli(tmp.path())
        .args(["config", "set-open-egress-for-others", "off"])
        .assert()
        .success()
        .stderr(predicate::str::contains("wssp drain"));
    // Clearing upstreams; invalid lists are refused and change nothing.
    cli(tmp.path())
        .args(["config", "set-egress-dns-upstreams", "--clear"])
        .assert()
        .success();
    for bad in [
        "0.0.0.0",
        "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5",
        "example.com",
    ] {
        cli(tmp.path())
            .args(["config", "set-egress-dns-upstreams", bad])
            .assert()
            .failure();
    }
    cli(tmp.path())
        .args(["config", "set-egress-dns-upstreams"])
        .assert()
        .failure();
    let shown = json_stdout({
        let mut cmd = cli(tmp.path());
        cmd.args(["config", "show", "--json"])
            .env("WSSP_RUNTIME", "fake");
        cmd
    });
    assert_eq!(shown["openEgressForOthers"], false);
    assert_eq!(shown["egressDnsUpstreams"], serde_json::json!([]));
}
