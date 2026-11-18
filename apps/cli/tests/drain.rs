//! Real binary with a bounded loopback HTTP fixture; no Incus or stdin.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

fn invoke(action: &str, status: u16, response: &str) -> (std::process::Output, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let response = response.to_owned();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            if let Ok((stream, _)) = listener.accept() {
                break stream;
            }
            assert!(
                Instant::now() < deadline,
                "CLI did not issue its drain request"
            );
            thread::sleep(Duration::from_millis(5));
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buf).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&buf[..read]);
            let text = String::from_utf8_lossy(&bytes);
            if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                let size: usize = headers
                    .lines()
                    .find_map(|line| {
                        line.to_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .unwrap()
                    .parse()
                    .unwrap();
                if body.len() >= size {
                    break;
                }
            }
        }
        write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nLocation: http://127.0.0.1:1/forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    let temp = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_wssp"))
        .arg("host")
        .args(action.split_whitespace())
        .args([
            "--server",
            &origin,
            "--host-id",
            "host-1",
            "--host-token-env",
            "WSSP_DRAIN_TEST_TOKEN",
            "--json",
        ])
        .env(
            "WSSP_DRAIN_TEST_TOKEN",
            format!("wssp_host_{}", "B".repeat(43)),
        )
        .env("WSSP_CONFIG_DIR", temp.path().join("config"))
        .env("WSSP_DATA_DIR", temp.path().join("data"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let request = handle
        .join()
        .unwrap_or_else(|_| panic!("CLI stderr: {}", String::from_utf8_lossy(&output.stderr)));
    (output, request)
}

#[test]
fn drain_and_undrain_send_host_authenticated_requests_and_report_counts() {
    for (command, draining) in [("drain", true), ("undrain", false)] {
        let body = serde_json::json!({"id":"host-1", "draining":draining, "liveSandboxCount":1, "drained":false, "offload":false});
        let (output, request) = invoke(command, 200, &body.to_string());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            body
        );
        assert!(request.starts_with("POST /api/sandbox-host/drain HTTP/1.1"));
        assert!(
            request
                .to_lowercase()
                .contains("authorization: bearer wssp_host_")
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(request.split_once("\r\n\r\n").unwrap().1)
                .unwrap(),
            serde_json::json!({"id":"host-1", "draining":draining, "offload":false})
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("wssp_host_"));
    }
}

#[test]
fn drain_offload_sends_the_switch_and_requires_it_echoed() {
    let body = serde_json::json!({"id":"host-1", "draining":true, "liveSandboxCount":0, "drained":true, "offload":true});
    let (output, request) = invoke("drain --offload", 200, &body.to_string());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request.split_once("\r\n\r\n").unwrap().1)
            .unwrap(),
        serde_json::json!({"id":"host-1", "draining":true, "offload":true})
    );
    // A server that did not record the switch is an invalid response.
    let (output, _) = invoke(
        "drain --offload",
        200,
        r#"{"id":"host-1","draining":true,"liveSandboxCount":0,"drained":true,"offload":false}"#,
    );
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn drain_http_failures_have_stable_exit_codes_and_never_follow_redirects() {
    for (status, exit) in [
        (401, 4),
        (403, 4),
        (404, 3),
        (409, 1),
        (429, 5),
        (503, 5),
        (302, 1),
    ] {
        let (output, _) = invoke("drain", status, "{}");
        assert_eq!(output.status.code(), Some(exit), "status {status}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn drain_rejects_inconsistent_success_and_wrong_host() {
    for body in [
        r#"{"id":"other","draining":true,"liveSandboxCount":0,"drained":true,"offload":false}"#,
        r#"{"id":"host-1","draining":true,"liveSandboxCount":1,"drained":true,"offload":false}"#,
    ] {
        let (output, _) = invoke("drain", 200, body);
        assert_eq!(output.status.code(), Some(1));
    }
}

#[test]
fn drain_usage_and_cleartext_remote_origin_fail_without_stdin() {
    let temp = tempfile::tempdir().unwrap();
    for (args, exit) in [
        (vec!["host", "drain", "--unknown"], 2),
        (
            vec![
                "host",
                "undrain",
                "--server",
                "http://remote.example.test",
                "--host-id",
                "h",
                "--host-token-env",
                "WSSP_DRAIN_TEST_TOKEN",
            ],
            1,
        ),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_wssp"))
            .args(args)
            .env("WSSP_CONFIG_DIR", temp.path().join("config"))
            .env("WSSP_DATA_DIR", temp.path().join("data"))
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit));
    }
}
