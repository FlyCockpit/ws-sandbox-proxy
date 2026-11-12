//! Security-critical: socket framing, authentication and bounds (M17).

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;

const DAEMON: u32 = 1000;

#[test]
fn requests_decode_strictly() {
    assert_eq!(
        decode_request(br#"{"op":"status"}"#),
        Ok(Request::Status {})
    );
    assert_eq!(
        decode_request(br#"{"op":"policy"}"#),
        Ok(Request::Policy {})
    );
    assert_eq!(
        decode_request(br#"{"op":"ceiling"}"#),
        Ok(Request::Ceiling {})
    );
    assert_eq!(
        decode_request(br#"{"op":"push_deployment","configured":false}"#),
        Ok(Request::PushDeployment {
            configured: false,
            entries: vec![]
        })
    );
    for bad in [
        &br#"{"op":"flush"}"#[..],
        br#"{"op":"status","extra":1}"#,
        br#"{"op":"push_deployment"}"#,
        b"not json",
    ] {
        assert!(decode_request(bad).is_err());
    }
}

#[test]
fn only_the_daemon_uid_may_push() {
    let push = Request::PushDeployment {
        configured: true,
        entries: vec![],
    };
    assert!(authorize(&push, Some(DAEMON), DAEMON).is_ok());
    for uid in [Some(0), Some(DAEMON + 1), None] {
        assert!(matches!(
            authorize(&push, uid, DAEMON).map_err(|r| *r),
            Err(Reply::Error {
                code: ErrorCode::Forbidden,
                ..
            })
        ));
    }
    for read in [Request::Status {}, Request::Policy {}, Request::Ceiling {}] {
        for uid in [Some(0), Some(DAEMON), Some(4242), None] {
            assert!(authorize(&read, uid, DAEMON).is_ok());
        }
    }
}

#[test]
fn reply_wire_shape() {
    let value = serde_json::to_value(Reply::Pushed {
        digest: "sha256:ab".into(),
        state: crate::guard::sources::SourceState::NotConfigured {
            digest: "sha256:ab".into(),
        },
    })
    .unwrap();
    assert_eq!(
        value,
        serde_json::json!({"result":"pushed","digest":"sha256:ab","state":{"state":"not_configured","digest":"sha256:ab"}})
    );
    let error = serde_json::to_value(Reply::Error {
        code: ErrorCode::InvalidSource,
        message: "m".into(),
        line: Some(3),
    })
    .unwrap();
    assert_eq!(
        error,
        serde_json::json!({"result":"error","code":"invalid_source","message":"m","line":3})
    );
}

#[test]
fn limiter_caps_concurrent_connections() {
    let limiter = ConnectionLimiter::new(MAX_CONNECTIONS);
    let permits: Vec<_> = (0..MAX_CONNECTIONS)
        .map(|_| limiter.try_acquire().unwrap())
        .collect();
    assert!(limiter.try_acquire().is_none());
    drop(permits);
    assert!(limiter.try_acquire().is_some());
}

/// Records every request it handles and the peer it was attributed to.
struct Recorder(Mutex<Vec<Request>>);

impl Handler for Recorder {
    fn handle(&self, request: Request) -> Reply {
        let reply = match &request {
            Request::PushDeployment { .. } => Reply::Pushed {
                digest: "sha256:00".into(),
                state: crate::guard::sources::SourceState::Unknown,
            },
            _ => Reply::error(ErrorCode::Internal, "recorded"),
        };
        if let Ok(mut log) = self.0.lock() {
            log.push(request);
        }
        reply
    }
}

fn exchange(peer_uid: Option<u32>, body: &[u8]) -> (Reply, Vec<Request>) {
    let (mut client, server) = UnixStream::pair().unwrap();
    let recorder = Recorder(Mutex::new(Vec::new()));
    let mut framed = (body.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(body);
    client.write_all(&framed).unwrap();
    serve_connection(server, peer_uid, ServerConfig::new(DAEMON), &recorder);
    let reply = read_frame(
        &mut client,
        MAX_FRAME_BYTES,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    (
        serde_json::from_slice(&reply).unwrap(),
        recorder.0.into_inner().unwrap(),
    )
}

#[test]
fn push_from_another_uid_never_reaches_the_handler() {
    let body = br#"{"op":"push_deployment","configured":true,"entries":["1.1.1.1"]}"#;
    let (reply, handled) = exchange(Some(DAEMON + 1), body);
    assert!(matches!(
        reply,
        Reply::Error {
            code: ErrorCode::Forbidden,
            ..
        }
    ));
    assert!(handled.is_empty());
    let (reply, handled) = exchange(Some(DAEMON), body);
    assert!(matches!(reply, Reply::Pushed { .. }));
    assert_eq!(handled.len(), 1);
}

#[test]
fn status_from_any_uid_is_answered() {
    let (_, handled) = exchange(Some(4242), br#"{"op":"status"}"#);
    assert_eq!(handled, [Request::Status {}]);
}

#[test]
fn oversize_frame_is_refused_before_reading_the_body() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
        .unwrap();
    let recorder = Recorder(Mutex::new(Vec::new()));
    serve_connection(server, Some(DAEMON), ServerConfig::new(DAEMON), &recorder);
    let reply: Reply = serde_json::from_slice(
        &read_frame(
            &mut client,
            MAX_FRAME_BYTES,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        reply,
        Reply::Error {
            code: ErrorCode::TooLarge,
            ..
        }
    ));
    assert!(recorder.0.into_inner().unwrap().is_empty());
}

#[test]
fn slow_client_times_out_on_the_total_deadline() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let config = ServerConfig {
        request_timeout: Duration::from_millis(400),
        ..ServerConfig::new(DAEMON)
    };
    let recorder = Arc::new(Recorder(Mutex::new(Vec::new())));
    let server_recorder = recorder.clone();
    let started = Instant::now();
    let worker = std::thread::spawn(move || {
        serve_connection(server, Some(DAEMON), config, server_recorder.as_ref());
    });
    // Trickle one byte at a time, each well within a per-read timeout.
    let body = br#"{"op":"status"}"#;
    let mut framed = (body.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(body);
    for byte in framed {
        if client.write_all(&[byte]).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        if started.elapsed() > Duration::from_secs(1) {
            break;
        }
    }
    worker.join().unwrap();
    assert!(started.elapsed() < Duration::from_millis(1500));
    assert!(recorder.0.lock().unwrap().is_empty());
}

fn temp_socket() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("wssp-guard-{}-{nanos}.sock", std::process::id()))
}

/// Handler that blocks until released, to hold connection slots open.
struct Gate {
    open: Mutex<bool>,
    cv: std::sync::Condvar,
    entered: AtomicUsize,
}

impl Handler for Gate {
    fn handle(&self, _request: Request) -> Reply {
        self.entered.fetch_add(1, Ordering::AcqRel);
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.cv.wait(open).unwrap();
        }
        Reply::error(ErrorCode::Internal, "released")
    }
}

#[test]
fn fifth_concurrent_connection_is_refused_busy() {
    let path = temp_socket();
    let listener = UnixListener::bind(&path).unwrap();
    let gate = Arc::new(Gate {
        open: Mutex::new(false),
        cv: std::sync::Condvar::new(),
        entered: AtomicUsize::new(0),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let server_gate: Arc<dyn Handler> = gate.clone();
    let server_stop = stop.clone();
    let server = std::thread::spawn(move || {
        let uid = |_: &UnixStream| Ok(DAEMON);
        let _ = serve(
            &listener,
            &uid,
            ServerConfig::new(DAEMON),
            server_gate,
            &server_stop,
        );
    });
    let send = |stream: &mut UnixStream| {
        let body = br#"{"op":"status"}"#;
        let mut framed = (body.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(body);
        stream.write_all(&framed).unwrap();
    };
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let mut stream = UnixStream::connect(&path).unwrap();
        send(&mut stream);
        held.push(stream);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while gate.entered.load(Ordering::Acquire) < MAX_CONNECTIONS {
        assert!(Instant::now() < deadline, "handlers never entered");
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut fifth = UnixStream::connect(&path).unwrap();
    let reply: Reply = serde_json::from_slice(
        &read_frame(
            &mut fifth,
            MAX_FRAME_BYTES,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        reply,
        Reply::Error {
            code: ErrorCode::Busy,
            ..
        }
    ));

    // Release, stop the accept loop (wake it with one last connection).
    *gate.open.lock().unwrap() = true;
    gate.cv.notify_all();
    for mut stream in held {
        let _ = read_frame(
            &mut stream,
            MAX_FRAME_BYTES,
            Instant::now() + Duration::from_secs(2),
        );
    }
    stop.store(true, Ordering::Release);
    drop(UnixStream::connect(&path));
    server.join().unwrap();
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn client_round_trip() {
    let path = temp_socket();
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let recorder = Recorder(Mutex::new(Vec::new()));
        serve_connection(stream, Some(DAEMON), ServerConfig::new(DAEMON), &recorder);
    });
    let reply = call(
        &path,
        &Request::PushDeployment {
            configured: false,
            entries: vec![],
        },
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(matches!(reply, Reply::Pushed { .. }));
    server.join().unwrap();
    std::fs::remove_file(&path).unwrap();
}
