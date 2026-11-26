//! Host channel tests: real `ChannelHost` + custodian threads +
//! journal + authority + registry over the FakeRuntime channel driver (no
//! Incus, no socket). The fake guest speaks the real in-band protocol
//! (PROMPT, preamble, secret-bound READY/EXIT); its IO never blocks. Time
//! jumps use the host's test clock (`ChannelHost::advance`).
use super::*;
use crate::sandbox_relay::journal::{HostJournal, TransportBindingV11, intent_from_dispatch};
use crate::sandbox_relay::test_support::FixtureRuntime;
use sandbox_protocol::parse_channel_frame;
use sandbox_runtime::{CreateSandboxRequest, FakeChannelControl, FakeRuntime};
use serde_json::json;
use std::collections::BTreeMap;

/// Test view of [`Outgoing`] without the box.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum Out {
    Text(DaemonControlMessage),
    Binary(Vec<u8>),
}
impl From<Outgoing> for Out {
    fn from(out: Outgoing) -> Self {
        match out {
            Outgoing::Text(message) => Out::Text(*message),
            Outgoing::Binary(bytes) => Out::Binary(bytes),
        }
    }
}
fn outs(out: Vec<Outgoing>) -> Vec<Out> {
    out.into_iter().map(Out::from).collect()
}

const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const CONN: &str = "conn-1";

struct Rig {
    dir: tempfile::TempDir,
    fake: FakeRuntime,
    journal: Arc<HostJournal>,
    slots: Arc<ChannelSlots>,
    registry: Arc<ChannelRegistry>,
    host: ChannelHost,
}

fn binding() -> TransportBindingV11 {
    TransportBindingV11 {
        server: "wss://relay.test/ws/sandbox-host".into(),
        host_owner_id: "owner-1".into(),
        host_id: "host-1".into(),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn dispatch(sandbox: &str, generation: u64, kind: &str, build: bool) -> OperationDispatch {
    dispatch_until(sandbox, generation, kind, build, now_ms() + 3_600_000)
}

fn dispatch_until(
    sandbox: &str,
    generation: u64,
    kind: &str,
    build: bool,
    deadline_unix_ms: u64,
) -> OperationDispatch {
    let owner = if sandbox == "sbx-2" {
        "owner-2"
    } else {
        "owner"
    };
    let op = format!("{}-{sandbox}-{generation}", kind.replace('.', "-"));
    let mut value = json!({"sandboxOwnerId": owner,
        "operationId": op, "sandboxId": sandbox, "kind": kind,
        "allocation": crate::sandbox_relay::test_support::allocation(),
        "generation": generation, "attempt": 1, "idempotencyKey": op,
        "bodyHash": "a".repeat(64), "incusFingerprint": FP, "templateDigest": FP,
        "lease": {"revision": generation, "deadlineUnixMs": deadline_unix_ms,
                  "action": "stop", "expiryPolicy": "retry-force-60s"},
        "guestUid": 1234, "guestGid": 2345, "guestHome": "/home/declared",
        "guestShell": "/bin/zsh",
    });
    if build {
        value["build"] = json!({"buildId": "build-1"});
    }
    serde_json::from_value(value).unwrap()
}

fn accept(journal: &HostJournal, d: &OperationDispatch) {
    journal
        .record_fixture_intent(&intent_from_dispatch(journal, &binding(), d))
        .unwrap();
    journal.accept_fixture_lease(d).unwrap();
}

fn rig() -> Rig {
    rig_until(now_ms() + 3_600_000)
}

/// A rig whose sandbox lease ends at `deadline_unix_ms`.
fn rig_until(deadline_unix_ms: u64) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let journal =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap());
    accept(
        &journal,
        &dispatch_until("sbx-1", 1, "sandbox.create", false, deadline_unix_ms),
    );
    // A second sandbox of another owner (`owner-2`) for the per-owner share.
    accept(
        &journal,
        &dispatch_until("sbx-2", 1, "sandbox.create", false, deadline_unix_ms),
    );
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    for sandbox in ["sbx-1", "sbx-2"] {
        fake.create_fixture(&CreateSandboxRequest::for_test(
            sandbox,
            &format!("sandbox-create-{sandbox}-1"),
        ))
        .unwrap();
    }
    let authority = HostAuthority::with_journal(journal.clone());
    let slots = Arc::new(ChannelSlots::default());
    let registry = Arc::new(ChannelRegistry::new(journal.clone()));
    let mut host = ChannelHost::new(
        slots.clone(),
        registry.clone(),
        Arc::new(fake.clone()),
        journal.clone(),
        authority,
        "host-1".into(),
    );
    host.enable(5, binding(), true);
    Rig {
        dir,
        fake,
        journal,
        slots,
        registry,
        host,
    }
}

fn fence(channel: &str) -> ChannelFence {
    ChannelFence {
        channel_id: channel.into(),
        connection_id: CONN.into(),
        host_id: "host-1".into(),
        epoch: 5,
        target: ChannelTarget::Sandbox {
            sandbox_id: "sbx-1".into(),
            generation: 1,
        },
    }
}

/// A channel of `sbx-2` (owner `owner-2`).
fn fence2(channel: &str) -> ChannelFence {
    ChannelFence {
        target: ChannelTarget::Sandbox {
            sandbox_id: "sbx-2".into(),
            generation: 1,
        },
        ..fence(channel)
    }
}

fn opened2(rig: &mut Rig, channel: &str) -> (ChannelFence, FakeChannelControl) {
    let fence = fence2(channel);
    assert!(open(rig, &fence, ChannelKind::Exec).is_empty());
    drive(rig, |o| ready(o).is_some());
    let control = rig
        .fake
        .channel_control("sbx-2", CONN, channel)
        .expect("channel opened");
    (fence, control)
}

fn unit(channel: &str) -> String {
    sandbox_runtime::channel_scope_unit(CONN, channel).unwrap()
}

fn open_message(fence: &ChannelFence, kind: ChannelKind) -> ServerControlMessage {
    ServerControlMessage::ChannelOpen {
        fence: fence.clone(),
        kind,
        argv: None,
        login: false,
        cwd: None,
        env: None,
        pty: (kind == ChannelKind::Pty).then(|| ChannelPtyParams {
            rows: 24,
            cols: 80,
            term: "xterm-256color".into(),
        }),
        port: None,
        path: None,
    }
}

fn open(rig: &mut Rig, fence: &ChannelFence, kind: ChannelKind) -> Vec<Out> {
    outs(rig.host.handle_control(open_message(fence, kind)).unwrap())
}

fn control(rig: &Rig, channel: &str) -> FakeChannelControl {
    rig.fake
        .channel_control("sbx-1", CONN, channel)
        .expect("channel opened")
}

/// Open and wait for `channel.ready`.
fn opened(rig: &mut Rig, channel: &str, kind: ChannelKind) -> (ChannelFence, FakeChannelControl) {
    let fence = fence(channel);
    assert!(open(rig, &fence, kind).is_empty());
    drive(rig, |o| ready(o).is_some());
    let control = control(rig, channel);
    (fence, control)
}

fn input(rig: &mut Rig, fence: &ChannelFence, seq: u64, bytes: &[u8]) {
    rig.host
        .handle_input(
            ChannelDataMetadata {
                r#type: ChannelDataKind::Data,
                fence: fence.clone(),
                stream: ChannelStream::Stdin,
                seq,
            },
            bytes.to_vec(),
        )
        .unwrap();
}

fn send(rig: &mut Rig, message: ServerControlMessage) -> Vec<Out> {
    outs(rig.host.handle_control(message).unwrap())
}

fn ack(rig: &mut Rig, fence: &ChannelFence, stream: ChannelStream, seq: u64) {
    assert!(
        send(
            rig,
            ServerControlMessage::ChannelAck {
                fence: fence.clone(),
                stream,
                seq,
            },
        )
        .is_empty()
    );
}

fn close(rig: &mut Rig, fence: &ChannelFence, intent: ChannelCloseIntent) {
    assert!(
        send(
            rig,
            ServerControlMessage::ChannelClose {
                fence: fence.clone(),
                intent,
            },
        )
        .is_empty()
    );
}

fn stdin_eof(rig: &mut Rig, fence: &ChannelFence, frames: u64) {
    assert!(
        send(
            rig,
            ServerControlMessage::ChannelEof {
                fence: fence.clone(),
                stream: ChannelStream::Stdin,
                frames,
            },
        )
        .is_empty()
    );
}

fn signal(rig: &mut Rig, fence: &ChannelFence, signal: ChannelSignal) -> Vec<Out> {
    send(
        rig,
        ServerControlMessage::ChannelSignal {
            fence: fence.clone(),
            signal,
        },
    )
}

/// Poll until `done` holds over everything collected so far (10 s hang
/// guard; tests normally finish in milliseconds).
fn drive(rig: &mut Rig, done: impl Fn(&[Out]) -> bool) -> Vec<Out> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut out = Vec::new();
    loop {
        out.extend(outs(rig.host.poll().unwrap()));
        if done(&out) {
            return out;
        }
        assert!(Instant::now() < deadline, "never reached: {out:?}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// Poll for a fixed time (for "nothing more happens" assertions).
fn settle(rig: &mut Rig, wait: Duration) -> Vec<Out> {
    let deadline = Instant::now() + wait;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        out.extend(outs(rig.host.poll().unwrap()));
        thread::sleep(Duration::from_millis(2));
    }
    out
}

/// Wait (bounded) until `done` holds, without polling the host.
fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "never reached: {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

fn ready(out: &[Out]) -> Option<Option<ChannelPtySize>> {
    out.iter().find_map(|o| match o {
        Out::Text(DaemonControlMessage::ChannelReady { pty, .. }) => Some(*pty),
        _ => None,
    })
}

#[derive(Debug, Clone, PartialEq)]
struct Exit {
    fence: ChannelFence,
    exit_code: Option<i32>,
    signal: Option<u8>,
    intent: Option<ChannelCloseIntent>,
    error: Option<ProtocolErrorDetail>,
    reaped: bool,
    frames: (u64, u64),
}

fn exits(out: &[Out]) -> Vec<Exit> {
    out.iter()
        .filter_map(|o| match o {
            Out::Text(DaemonControlMessage::ChannelExit {
                fence,
                exit_code,
                signal,
                intent,
                error,
                reaped,
                frames,
            }) => Some(Exit {
                fence: fence.clone(),
                exit_code: *exit_code,
                signal: *signal,
                intent: *intent,
                error: error.clone(),
                reaped: *reaped,
                frames: (frames.stdout, frames.stderr),
            }),
            _ => None,
        })
        .collect()
}
fn exit(out: &[Out]) -> Option<Exit> {
    exits(out).into_iter().next()
}
fn has_exit(out: &[Out]) -> bool {
    exit(out).is_some()
}
fn exit_index(out: &[Out]) -> usize {
    out.iter()
        .position(|o| matches!(o, Out::Text(DaemonControlMessage::ChannelExit { .. })))
        .unwrap()
}

/// A refusal (exit before ready): its error code.
fn refusal(out: &[Out]) -> sandbox_protocol::WireErrorCode {
    let exit = exit(out).unwrap_or_else(|| panic!("refusal expected: {out:?}"));
    assert!(exit.reaped);
    assert_eq!(exit.exit_code, None);
    assert_eq!(exit.signal, None);
    exit.error.expect("refusal carries an error").code
}

fn stdin_acks(out: &[Out]) -> Vec<u64> {
    out.iter()
        .filter_map(|o| match o {
            Out::Text(DaemonControlMessage::ChannelAck {
                stream: ChannelStream::Stdin,
                seq,
                ..
            }) => Some(*seq),
            _ => None,
        })
        .collect()
}

/// Decoded output data frames: `(stream, seq, body)` in order.
fn data(out: &[Out]) -> Vec<(ChannelStream, u64, Vec<u8>)> {
    out.iter()
        .filter_map(|o| match o {
            Out::Binary(frame) => {
                let (metadata, body) = parse_channel_frame(frame)
                    .expect("a channel frame")
                    .expect("a valid channel frame");
                Some((metadata.stream, metadata.seq, body))
            }
            _ => None,
        })
        .collect()
}

fn eofs(out: &[Out]) -> Vec<(ChannelStream, u64)> {
    out.iter()
        .filter_map(|o| match o {
            Out::Text(DaemonControlMessage::ChannelEof { stream, frames, .. }) => {
                Some((*stream, *frames))
            }
            _ => None,
        })
        .collect()
}

fn notices(out: &[Out]) -> Vec<ChannelNotice> {
    out.iter()
        .filter_map(|o| match o {
            Out::Text(DaemonControlMessage::ChannelError { code, .. }) => Some(*code),
            _ => None,
        })
        .collect()
}

fn registry_file(rig: &Rig, channel: &str) -> PathBuf {
    rig.journal
        .state_dir()
        .unwrap()
        .join(format!("{REGISTRY_PREFIX}{}", unit(channel)))
}

fn code(code: SandboxErrorCode) -> sandbox_protocol::WireErrorCode {
    code.into()
}

/// The custody closes a channel saw: `kill`, `hangup` or `finish`.
fn closes(control: &FakeChannelControl) -> Vec<&'static str> {
    control
        .closes()
        .iter()
        .map(|close| match close {
            ChannelClose::Kill { .. } => "kill",
            ChannelClose::Hangup(_) => "hangup",
            ChannelClose::Finish => "finish",
        })
        .collect()
}

// ------------------------------------------------------------------ pty ----

#[test]
fn pty_open_echo_ack_and_ctrl_d_exit() {
    let mut rig = rig();
    let fence = fence("ch-1");
    let mut env = BTreeMap::new();
    env.insert("LANG".to_string(), "C.UTF-8".to_string());
    let out = send(
        &mut rig,
        ServerControlMessage::ChannelOpen {
            fence: fence.clone(),
            kind: ChannelKind::Pty,
            argv: Some(vec!["/bin/bash".into(), "-i".into()]),
            login: true,
            cwd: Some("/work".into()),
            env: Some(env),
            pty: Some(ChannelPtyParams {
                rows: 30,
                cols: 100,
                term: "xterm-256color".into(),
            }),
            port: None,
            path: None,
        },
    );
    assert!(out.is_empty(), "{out:?}");
    let out = drive(&mut rig, |o| ready(o).is_some());
    assert_eq!(
        ready(&out),
        Some(Some(ChannelPtySize {
            rows: 30,
            cols: 100
        }))
    );
    match &out[0] {
        Out::Text(DaemonControlMessage::ChannelReady { fence: echoed, .. }) => {
            assert_eq!(echoed, &fence)
        }
        other => panic!("first frame must be ready: {other:?}"),
    }
    let control = control(&rig, "ch-1");
    assert!(control.is_pty());
    assert_eq!(
        control.argv(),
        Some(vec!["/bin/bash".to_string(), "-i".to_string()])
    );
    assert!(control.login());
    assert_eq!(control.cwd().as_deref(), Some("/work"));
    assert!(
        control
            .env()
            .unwrap()
            .contains(&("LANG".to_string(), "C.UTF-8".to_string()))
    );
    assert_eq!(control.sizes(), vec![PtySize::new(30, 100).unwrap()]);

    input(&mut rig, &fence, 0, b"hi");
    let out = drive(&mut rig, |o| {
        !stdin_acks(o).is_empty() && !data(o).is_empty()
    });
    assert_eq!(stdin_acks(&out), vec![0]);
    assert_eq!(data(&out), vec![(ChannelStream::Stdout, 0, b"hi".to_vec())]);
    ack(&mut rig, &fence, ChannelStream::Stdout, 0);

    input(&mut rig, &fence, 1, &[0x04]);
    let out = drive(&mut rig, has_exit);
    let exit = exit(&out).unwrap();
    assert_eq!(exit.fence, fence);
    assert_eq!(exit.exit_code, Some(0));
    assert_eq!(exit.signal, None);
    assert_eq!(exit.intent, None);
    assert_eq!(exit.error, None);
    assert!(exit.reaped);
    assert_eq!(exit.frames, (1, 0));
    assert_eq!(control.stdin(), b"hi\x04".to_vec());
    // A natural end finishes the host client and kills nothing.
    assert_eq!(closes(&control), vec!["finish"]);
    assert!(rig.fake.channel_scope_kills().is_empty());
    assert_eq!(rig.host.live_channels(), 0);
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
    assert!(!registry_file(&rig, "ch-1").exists());
}

#[test]
fn pty_resize_reaches_the_fake_and_exec_resize_is_a_state_conflict() {
    let mut rig = rig();
    let (pty, control) = opened(&mut rig, "ch-pty", ChannelKind::Pty);
    let out = send(
        &mut rig,
        ServerControlMessage::ChannelResize {
            fence: pty.clone(),
            rows: 40,
            cols: 120,
        },
    );
    assert!(out.is_empty());
    wait_until("resize applied", || control.sizes().len() == 2);
    assert_eq!(control.sizes()[1], PtySize::new(40, 120).unwrap());

    let (exec, _) = opened(&mut rig, "ch-exec", ChannelKind::Exec);
    let out = send(
        &mut rig,
        ServerControlMessage::ChannelResize {
            fence: exec,
            rows: 40,
            cols: 120,
        },
    );
    assert_eq!(notices(&out), vec![ChannelNotice::StateConflict]);
}

/// Client env (locale hints) never overrides the sandbox's own values; the
/// credential env the channel was opened with closes it (`revoked`) when
/// its login is freed.
#[test]
fn client_env_never_overrides_sandbox_env_and_a_freed_login_revokes() {
    let mut rig = rig();
    let dir = tempfile::tempdir().unwrap();
    let credentials =
        crate::sandbox_relay::credentials::service::CredentialService::start(dir.path(), "host-1")
            .unwrap();
    credentials.install_test_env("sbx-1", "lease-1", "LANG", b"sandbox-lang");
    rig.host.set_credentials(Some(credentials.clone()));
    let fence = fence("ch-1");
    let mut env = BTreeMap::new();
    env.insert("LANG".to_string(), "C.UTF-8".to_string());
    env.insert("COLORTERM".to_string(), "truecolor".to_string());
    let out = send(
        &mut rig,
        ServerControlMessage::ChannelOpen {
            fence: fence.clone(),
            kind: ChannelKind::Exec,
            argv: None,
            login: false,
            cwd: None,
            env: Some(env),
            pty: None,
            port: None,
            path: None,
        },
    );
    assert!(out.is_empty(), "{out:?}");
    drive(&mut rig, |o| ready(o).is_some());
    let control = control(&rig, "ch-1");
    let env = control.env().unwrap();
    let langs: Vec<_> = env.iter().filter(|(name, _)| name == "LANG").collect();
    assert_eq!(
        langs,
        vec![&("LANG".to_string(), "sandbox-lang".to_string())]
    );
    assert!(env.contains(&("COLORTERM".to_string(), "truecolor".to_string())));
    assert!(!has_exit(&settle(&mut rig, Duration::from_millis(50))));

    credentials.revoke_lease("lease-1");
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::Revoked)
    );
    assert_eq!(closes(&control), vec!["kill"]);
}

// ----------------------------------------------------------------- exec ----

#[test]
fn exec_scripted_output_eofs_then_exit() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.emit(ChannelOutput::Stdout, b"one");
    control.emit(ChannelOutput::Stderr, b"err");
    control.emit(ChannelOutput::Stdout, b"two");
    control.exit(ChannelExitStatus::Code(3));
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        data(&out),
        vec![
            (ChannelStream::Stdout, 0, b"one".to_vec()),
            (ChannelStream::Stderr, 0, b"err".to_vec()),
            (ChannelStream::Stdout, 1, b"two".to_vec()),
        ]
    );
    let eof_list = eofs(&out);
    assert!(
        eof_list.contains(&(ChannelStream::Stdout, 2)),
        "{eof_list:?}"
    );
    assert!(
        eof_list.contains(&(ChannelStream::Stderr, 1)),
        "{eof_list:?}"
    );
    // The exit is the last frame: after every data frame and eof.
    assert_eq!(exit_index(&out), out.len() - 1);
    let exit = exit(&out).unwrap();
    assert_eq!(exit.fence, fence);
    assert_eq!(exit.exit_code, Some(3));
    assert_eq!(exit.signal, None);
    assert_eq!(exit.frames, (2, 1));
    assert!(exit.reaped);
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
}

#[test]
fn exec_term_signal_reaches_the_process_and_the_exit_carries_it() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    assert!(signal(&mut rig, &fence, ChannelSignal::Term).is_empty());
    let out = drive(&mut rig, has_exit);
    assert_eq!(control.signals(), vec![ProcessSignal::Sigterm]);
    let exit = exit(&out).unwrap();
    assert_eq!(exit.signal, Some(15));
    assert_eq!(exit.exit_code, None);
    assert_eq!(exit.intent, None);
    assert_eq!(closes(&control), vec!["finish"]);
}

#[test]
fn exec_kill_signal_is_a_kill_close() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    assert!(signal(&mut rig, &fence, ChannelSignal::Kill).is_empty());
    let out = drive(&mut rig, has_exit);
    assert_eq!(closes(&control), vec!["kill"]);
    assert_eq!(exit(&out).unwrap().signal, Some(9));
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
}

#[test]
fn unsupported_group_signal_is_a_non_fatal_notice() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.set_signal_support(false);
    assert!(signal(&mut rig, &fence, ChannelSignal::Int).is_empty());
    let out = drive(&mut rig, |o| !notices(o).is_empty());
    assert_eq!(notices(&out), vec![ChannelNotice::UnsupportedSignal]);
    assert!(control.signals().is_empty());
    // The channel lives on.
    assert!(!has_exit(&settle(&mut rig, Duration::from_millis(50))));
    assert_eq!(rig.host.live_channels(), 1);
}

#[test]
fn signal_on_a_pty_is_refused_with_a_notice() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    let out = signal(&mut rig, &fence, ChannelSignal::Term);
    assert_eq!(notices(&out), vec![ChannelNotice::UnsupportedSignal]);
    assert!(control.signals().is_empty());
    assert!(!has_exit(&settle(&mut rig, Duration::from_millis(30))));
}

// --------------------------------------------------------------- credit ----

fn emit_n(control: &FakeChannelControl, stream: ChannelOutput, n: usize) {
    for i in 0..n {
        control.emit(stream, format!("frame-{i}").as_bytes());
    }
}

#[test]
fn pty_output_waits_for_credit() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    emit_n(&control, ChannelOutput::Stdout, 20);
    let mut out = drive(&mut rig, |o| data(o).len() >= 8);
    out.extend(settle(&mut rig, Duration::from_millis(150)));
    assert_eq!(data(&out).len(), 8, "the pty window is 8 frames");
    ack(&mut rig, &fence, ChannelStream::Stdout, 3);
    out.extend(drive(&mut rig, |o| data(o).len() >= 4));
    out.extend(settle(&mut rig, Duration::from_millis(100)));
    assert_eq!(data(&out).len(), 12);
    ack(&mut rig, &fence, ChannelStream::Stdout, 11);
    let rest = drive(&mut rig, |o| data(o).len() >= 8);
    out.extend(rest);
    let frames = data(&out);
    assert_eq!(frames.len(), 20);
    for (i, (stream, seq, body)) in frames.iter().enumerate() {
        assert_eq!(*stream, ChannelStream::Stdout);
        assert_eq!(*seq, i as u64);
        assert_eq!(body, format!("frame-{i}").as_bytes());
    }
}

#[test]
fn exec_output_window_is_32_frames_across_streams() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    emit_n(&control, ChannelOutput::Stdout, 30);
    emit_n(&control, ChannelOutput::Stderr, 10);
    let mut out = drive(&mut rig, |o| data(o).len() >= 32);
    out.extend(settle(&mut rig, Duration::from_millis(150)));
    assert_eq!(data(&out).len(), 32, "one window across both streams");
    for stream in [ChannelStream::Stdout, ChannelStream::Stderr] {
        if let Some(last) = data(&out)
            .iter()
            .filter(|(s, _, _)| *s == stream)
            .map(|(_, seq, _)| *seq)
            .max()
        {
            ack(&mut rig, &fence, stream, last);
        }
    }
    out.extend(drive(&mut rig, |o| data(o).len() >= 8));
    assert_eq!(data(&out).len(), 40);
    let seqs = |want: ChannelStream| -> Vec<u64> {
        data(&out)
            .into_iter()
            .filter(|(stream, _, _)| *stream == want)
            .map(|(_, seq, _)| seq)
            .collect()
    };
    assert_eq!(seqs(ChannelStream::Stderr), (0..10).collect::<Vec<_>>());
    assert_eq!(seqs(ChannelStream::Stdout), (0..30).collect::<Vec<_>>());
}

/// One runtime chunk larger than a pty frame splits into several frames; the
/// split never pushes the channel past its window.
#[test]
fn split_output_never_exceeds_the_window() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    emit_n(&control, ChannelOutput::Stdout, 7);
    let big = vec![b'z'; CHANNEL_PTY_DATA_MAX_BYTES + 100];
    control.emit(ChannelOutput::Stdout, &big);
    let mut out = drive(&mut rig, |o| data(o).len() >= 8);
    out.extend(settle(&mut rig, Duration::from_millis(150)));
    assert_eq!(data(&out).len(), 8, "a split chunk overran the window");
    ack(&mut rig, &fence, ChannelStream::Stdout, 0);
    out.extend(drive(&mut rig, |o| !data(o).is_empty()));
    let frames = data(&out);
    assert_eq!(frames.len(), 9);
    let tail: Vec<u8> = frames[7..]
        .iter()
        .flat_map(|(_, _, body)| body.clone())
        .collect();
    assert_eq!(tail, big);
    assert!(
        frames
            .iter()
            .all(|(_, _, body)| body.len() <= CHANNEL_PTY_DATA_MAX_BYTES)
    );
}

#[test]
fn ack_outside_the_window_is_a_protocol_violation() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    emit_n(&control, ChannelOutput::Stdout, 2);
    drive(&mut rig, |o| data(o).len() >= 2);
    ack(&mut rig, &fence, ChannelStream::Stdout, 5);
    let out = drive(&mut rig, has_exit);
    let first = exit(&out).unwrap();
    assert_eq!(first.intent, Some(ChannelCloseIntent::ProtocolViolation));
    assert_eq!(
        first.error.map(|e| e.code),
        Some(code(SandboxErrorCode::ProtocolError))
    );
    assert_eq!(closes(&control), vec!["kill"]);

    // An ack naming stdin is one too.
    let (fence, control) = opened(&mut rig, "ch-2", ChannelKind::Exec);
    ack(&mut rig, &fence, ChannelStream::Stdin, 0);
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::ProtocolViolation)
    );
    assert_eq!(closes(&control), vec!["kill"]);
}

// ---------------------------------------------------------------- input ----

#[test]
fn input_sequence_gap_is_a_protocol_violation() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    input(&mut rig, &fence, 1, b"skipped zero");
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::ProtocolViolation)
    );
    assert!(control.stdin().is_empty());
    assert_eq!(closes(&control), vec!["kill"]);
}

#[test]
fn duplicate_input_counts_violations_and_the_third_closes() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    input(&mut rig, &fence, 0, b"a");
    drive(&mut rig, |o| stdin_acks(o) == vec![0]);
    input(&mut rig, &fence, 0, b"a");
    input(&mut rig, &fence, 0, b"a");
    assert!(!has_exit(&settle(&mut rig, Duration::from_millis(50))));
    input(&mut rig, &fence, 0, b"a");
    let out = drive(&mut rig, has_exit);
    let exit = exit(&out).unwrap();
    assert_eq!(exit.intent, Some(ChannelCloseIntent::ProtocolViolation));
    assert_eq!(control.stdin(), b"a".to_vec(), "duplicates deliver nothing");
}

#[test]
fn input_beyond_the_window_is_refused() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    // No poll in between: none of the pump's acks has reached the server.
    for seq in 0..=CHANNEL_PTY_WINDOW_FRAMES {
        input(&mut rig, &fence, seq, b"x");
    }
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::ProtocolViolation)
    );
    assert!(control.stdin().len() <= CHANNEL_PTY_WINDOW_FRAMES as usize);
}

#[test]
fn stdin_eof_closes_stdin_after_every_frame() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    input(&mut rig, &fence, 0, b"one ");
    input(&mut rig, &fence, 1, b"two ");
    input(&mut rig, &fence, 2, b"three");
    stdin_eof(&mut rig, &fence, 3);
    let out = drive(&mut rig, has_exit);
    assert_eq!(control.stdin(), b"one two three".to_vec());
    assert!(control.stdin_closed());
    assert_eq!(stdin_acks(&out), vec![0, 1, 2]);
    let echoed: Vec<u8> = data(&out).into_iter().flat_map(|(_, _, b)| b).collect();
    assert_eq!(echoed, b"one two three".to_vec());
    assert!(eofs(&out).contains(&(ChannelStream::Stdout, 3)));
    assert!(eofs(&out).contains(&(ChannelStream::Stderr, 0)));
    let exit = exit(&out).unwrap();
    assert_eq!(exit.exit_code, Some(0));
    assert_eq!(exit.frames, (3, 0));
}

#[test]
fn stdin_eof_with_a_wrong_frame_count_is_a_violation() {
    let mut rig = rig();
    // Fewer frames than received.
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    input(&mut rig, &fence, 0, b"a");
    input(&mut rig, &fence, 1, b"b");
    stdin_eof(&mut rig, &fence, 1);
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::ProtocolViolation)
    );
    assert!(!control.stdin_closed());

    // More frames than received: on the ordered relay the rest is lost, and
    // input after an eof is refused, so stdin could never close.
    let (fence, control) = opened(&mut rig, "ch-2", ChannelKind::Exec);
    input(&mut rig, &fence, 0, b"a");
    stdin_eof(&mut rig, &fence, 2);
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::ProtocolViolation)
    );
    assert!(!control.stdin_closed());
}

// ---------------------------------------------------------------- fence ----

#[test]
fn foreign_opens_are_dropped_without_output() {
    let mut rig = rig();
    for foreign in [
        ChannelFence {
            epoch: 6,
            ..fence("ch-epoch")
        },
        ChannelFence {
            host_id: "host-2".into(),
            ..fence("ch-host")
        },
    ] {
        assert!(open(&mut rig, &foreign, ChannelKind::Pty).is_empty());
        assert!(
            rig.fake
                .channel_control("sbx-1", CONN, &foreign.channel_id)
                .is_none()
        );
    }
    assert!(settle(&mut rig, Duration::from_millis(30)).is_empty());
    assert_eq!(rig.host.live_channels(), 0);
    assert_eq!(rig.slots.live(), 0);
}

#[test]
fn fence_mismatch_on_a_live_channel_counts_violations() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    // Wrong epoch: nothing delivered.
    input(
        &mut rig,
        &ChannelFence {
            epoch: 6,
            ..fence.clone()
        },
        0,
        b"x",
    );
    // Wrong host.
    ack(
        &mut rig,
        &ChannelFence {
            host_id: "host-2".into(),
            ..fence.clone()
        },
        ChannelStream::Stdout,
        0,
    );
    assert!(!has_exit(&settle(&mut rig, Duration::from_millis(50))));
    assert!(control.stdin().is_empty());
    // Wrong target generation: the third violation closes.
    close(
        &mut rig,
        &ChannelFence {
            target: ChannelTarget::Sandbox {
                sandbox_id: "sbx-1".into(),
                generation: 2,
            },
            ..fence.clone()
        },
        ChannelCloseIntent::Client,
    );
    let out = drive(&mut rig, has_exit);
    let exit = exit(&out).unwrap();
    assert_eq!(exit.fence, fence);
    assert_eq!(exit.intent, Some(ChannelCloseIntent::ProtocolViolation));
    assert_eq!(closes(&control), vec!["kill"]);
    assert!(control.stdin().is_empty());
}

#[test]
fn frames_for_unknown_channels_are_ignored() {
    let mut rig = rig();
    let (_live, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    let unknown = fence("ch-unknown");
    input(&mut rig, &unknown, 0, b"x");
    ack(&mut rig, &unknown, ChannelStream::Stdout, 0);
    stdin_eof(&mut rig, &unknown, 0);
    close(&mut rig, &unknown, ChannelCloseIntent::Revoked);
    assert!(signal(&mut rig, &unknown, ChannelSignal::Term).is_empty());
    assert!(settle(&mut rig, Duration::from_millis(30)).is_empty());
    assert_eq!(rig.host.live_channels(), 1);
    assert!(control.closes().is_empty());
    assert!(control.stdin().is_empty());
}

#[test]
fn duplicate_opens_of_live_or_ended_ids_are_refused() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    // Live: refused silently, counted; the third closes the live channel.
    assert!(open(&mut rig, &fence, ChannelKind::Exec).is_empty());
    assert!(open(&mut rig, &fence, ChannelKind::Pty).is_empty());
    assert!(!has_exit(&settle(&mut rig, Duration::from_millis(30))));
    assert_eq!(rig.host.live_channels(), 1);
    assert_eq!(rig.slots.live(), 1);
    assert!(open(&mut rig, &fence, ChannelKind::Exec).is_empty());
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::ProtocolViolation)
    );
    assert_eq!(closes(&control), vec!["kill"]);
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
    // Tombstoned: refused, nothing opens.
    assert!(open(&mut rig, &fence, ChannelKind::Exec).is_empty());
    assert_eq!(rig.host.live_channels(), 0);
    assert_eq!(rig.slots.live(), 0);
    assert!(settle(&mut rig, Duration::from_millis(30)).is_empty());
}

// ---------------------------------------------------------------- close ----

#[test]
fn client_close_is_a_normal_close() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    let out = drive(&mut rig, has_exit);
    assert_eq!(closes(&control), vec!["hangup"]);
    let exit = exit(&out).unwrap();
    assert_eq!(exit.intent, Some(ChannelCloseIntent::Client));
    assert!(exit.reaped);
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
    assert!(!registry_file(&rig, "ch-1").exists());
}

#[test]
fn revoked_close_is_a_kill_close() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    let out = drive(&mut rig, has_exit);
    assert_eq!(closes(&control), vec!["kill"]);
    let exit = exit(&out).unwrap();
    assert_eq!(exit.intent, Some(ChannelCloseIntent::Revoked));
    assert_eq!(exit.signal, Some(9));
    assert!(exit.reaped);
}

#[test]
fn lifecycle_dispatches_kill_close_the_sandbox_channels() {
    let mut rig = rig();
    let (_a, a) = opened(&mut rig, "ch-a", ChannelKind::Exec);
    // Another sandbox's dispatch and a same-generation create touch nothing.
    rig.host
        .on_dispatch(&dispatch("sbx-other", 1, "sandbox.stop", false));
    rig.host
        .on_dispatch(&dispatch("sbx-1", 1, "sandbox.create", false));
    assert!(!has_exit(&settle(&mut rig, Duration::from_millis(30))));
    rig.host
        .on_dispatch(&dispatch("sbx-1", 1, "sandbox.stop", false));
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::SandboxStopped)
    );
    assert_eq!(closes(&a), vec!["kill"]);

    let (_b, b) = opened(&mut rig, "ch-b", ChannelKind::Pty);
    rig.host
        .on_dispatch(&dispatch("sbx-1", 2, "sandbox.reconnect", false));
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::Superseded)
    );
    assert_eq!(closes(&b), vec!["kill"]);
}

#[test]
fn relay_loss_kill_closes_every_channel() {
    let mut rig = rig();
    let (_a, a) = opened(&mut rig, "ch-a", ChannelKind::Pty);
    let (_b, b) = opened(&mut rig, "ch-b", ChannelKind::Exec);
    assert_eq!(rig.slots.live(), 2);
    let Rig {
        dir: _dir,
        slots,
        host,
        ..
    } = rig;
    drop(host);
    wait_until("both channels kill-closed", || {
        closes(&a) == vec!["kill"] && closes(&b) == vec!["kill"]
    });
    assert!(slots.wait_idle(Duration::from_secs(2)));
}

#[test]
fn shutdown_closes_every_channel_with_shutdown() {
    let mut rig = rig();
    let (_a, a) = opened(&mut rig, "ch-a", ChannelKind::Pty);
    let mut sent = Vec::new();
    rig.host
        .shutdown(Duration::from_secs(5), |frame| {
            sent.push(Out::from(frame));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        exit(&sent).unwrap().intent,
        Some(ChannelCloseIntent::Shutdown)
    );
    assert_eq!(closes(&a), vec!["kill"]);
    assert_eq!(rig.host.live_channels(), 0);
}

// ------------------------------------------------------------- refusals ----

#[test]
fn open_without_a_lease_is_sandbox_not_found() {
    let mut rig = rig();
    let fence = ChannelFence {
        target: ChannelTarget::Sandbox {
            sandbox_id: "sbx-none".into(),
            generation: 1,
        },
        ..fence("ch-1")
    };
    let out = open(&mut rig, &fence, ChannelKind::Pty);
    assert_eq!(refusal(&out), code(SandboxErrorCode::SandboxNotFound));
    assert_eq!(exit(&out).unwrap().fence, fence);
    assert!(rig.fake.channel_control("sbx-none", CONN, "ch-1").is_none());
    assert_eq!(rig.slots.live(), 0);
}

#[test]
fn open_for_another_generation_is_a_state_conflict() {
    let mut rig = rig();
    let fence = ChannelFence {
        target: ChannelTarget::Sandbox {
            sandbox_id: "sbx-1".into(),
            generation: 2,
        },
        ..fence("ch-1")
    };
    let out = open(&mut rig, &fence, ChannelKind::Exec);
    assert_eq!(refusal(&out), code(SandboxErrorCode::StateConflict));
    assert!(rig.fake.channel_control("sbx-1", CONN, "ch-1").is_none());
}

#[test]
fn build_sandboxes_never_open_a_channel() {
    let mut rig = rig();
    accept(&rig.journal, &dispatch("sbx-b", 1, "sandbox.create", true));
    rig.fake
        .create_fixture(&CreateSandboxRequest::for_test(
            "sbx-b",
            "sandbox-create-sbx-b-1",
        ))
        .unwrap();
    let fence = ChannelFence {
        target: ChannelTarget::Sandbox {
            sandbox_id: "sbx-b".into(),
            generation: 1,
        },
        ..fence("ch-build")
    };
    let out = open(&mut rig, &fence, ChannelKind::Pty);
    assert_eq!(refusal(&out), code(SandboxErrorCode::UnsupportedCapability));
    assert!(
        rig.fake
            .channel_control("sbx-b", CONN, "ch-build")
            .is_none()
    );
}

#[test]
fn invalid_kind_and_pty_combinations_are_refused() {
    let mut rig = rig();
    let fence = fence("ch-1");
    let out = send(
        &mut rig,
        ServerControlMessage::ChannelOpen {
            fence: fence.clone(),
            kind: ChannelKind::Pty,
            argv: None,
            login: false,
            cwd: None,
            env: None,
            pty: None,
            port: None,
            path: None,
        },
    );
    assert_eq!(refusal(&out), code(SandboxErrorCode::ProtocolError));
    assert_eq!(rig.slots.live(), 0);
}

#[test]
fn a_quiescing_daemon_refuses_new_opens() {
    let mut rig = rig();
    let (_live, live) = opened(&mut rig, "ch-live", ChannelKind::Exec);
    let state = Arc::new(crate::sandbox_relay::quiesce::QuiesceState::default());
    rig.host.set_quiesce(state.clone());
    state.enable();
    state.request();
    let out = open(&mut rig, &fence("ch-new"), ChannelKind::Pty);
    assert_eq!(refusal(&out), code(SandboxErrorCode::Disconnected));
    assert!(rig.fake.channel_control("sbx-1", CONN, "ch-new").is_none());
    // The live channel is not touched.
    assert!(!has_exit(&settle(&mut rig, Duration::from_millis(30))));
    assert!(live.closes().is_empty());
}

#[test]
fn channel_frames_before_negotiation_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let journal =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap());
    let fake = FakeRuntime::new();
    let mut host = ChannelHost::new(
        Arc::new(ChannelSlots::default()),
        Arc::new(ChannelRegistry::new(journal.clone())),
        Arc::new(fake),
        journal.clone(),
        HostAuthority::with_journal(journal),
        "host-1".into(),
    );
    let fence = fence("ch-1");
    assert!(
        host.handle_control(open_message(&fence, ChannelKind::Exec))
            .is_err()
    );
    let metadata = ChannelDataMetadata {
        r#type: ChannelDataKind::Data,
        fence: fence.clone(),
        stream: ChannelStream::Stdin,
        seq: 0,
    };
    assert!(host.handle_input(metadata.clone(), b"x".to_vec()).is_err());
    // `hello.ok` without the `channels` echo: still no channels.
    host.enable(5, binding(), false);
    assert!(
        host.handle_control(open_message(&fence, ChannelKind::Exec))
            .is_err()
    );
    assert!(host.handle_input(metadata, b"x".to_vec()).is_err());
    assert!(
        host.handle_control(ServerControlMessage::ChannelClose {
            fence,
            intent: ChannelCloseIntent::Client,
        })
        .is_err()
    );
    assert_eq!(host.live_channels(), 0);
}

#[test]
fn a_setup_failure_exits_with_an_error_and_forgets_the_channel() {
    let mut rig = rig();
    rig.fake.fail_channel_setup(Some(true));
    let fence = fence("ch-1");
    assert!(open(&mut rig, &fence, ChannelKind::Exec).is_empty());
    let out = drive(&mut rig, has_exit);
    assert!(ready(&out).is_none());
    assert!(data(&out).is_empty());
    assert_eq!(refusal(&out), code(SandboxErrorCode::UnsupportedCapability));
    let exit = exit(&out).unwrap();
    assert!(
        exit.error
            .unwrap()
            .message
            .starts_with("guest_scope_unavailable"),
    );
    assert_eq!(exit.frames, (0, 0));
    // The scope is kill-closed; the registry entry and slot are released.
    assert_eq!(closes(&control(&rig, "ch-1")), vec!["kill"]);
    assert_eq!(rig.host.live_channels(), 0);
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
    assert!(!registry_file(&rig, "ch-1").exists());
    // The next open works again.
    rig.fake.fail_channel_setup(None);
    opened(&mut rig, "ch-2", ChannelKind::Exec);
}

// ------------------------------------------------------------- capacity ----

#[test]
fn slots_cap_pty_channels_per_host() {
    let slots = Arc::new(ChannelSlots::default());
    let now = Instant::now();
    let mut held: Vec<SlotGuard> = (0..CHANNEL_MAX_PTY_CHANNELS_PER_HOST)
        .map(|i| {
            slots
                .try_acquire(true, &format!("creator-{}", i % 4), None, now)
                .unwrap()
        })
        .collect();
    assert_eq!(
        slots.try_acquire(true, "creator-9", None, now).unwrap_err(),
        SlotRefusal::HostCapacity
    );
    // Exec channels still fit.
    let exec = slots.try_acquire(false, "creator-9", None, now).unwrap();
    assert_eq!(slots.live(), CHANNEL_MAX_PTY_CHANNELS_PER_HOST + 1);
    held.pop();
    held.push(slots.try_acquire(true, "creator-9", None, now).unwrap());
    drop(exec);
    drop(held);
    assert_eq!(slots.live(), 0);
    assert!(slots.wait_idle(Duration::from_millis(10)));
}

#[test]
fn slots_cap_channels_per_creator() {
    let slots = Arc::new(ChannelSlots::default());
    let now = Instant::now();
    let held: Vec<SlotGuard> = (0..CHANNEL_MAX_CHANNELS_PER_GUEST_CREATOR)
        .map(|_| slots.try_acquire(false, "creator-a", None, now).unwrap())
        .collect();
    assert_eq!(
        slots
            .try_acquire(false, "creator-a", None, now)
            .unwrap_err(),
        SlotRefusal::HostCapacity
    );
    let other = slots.try_acquire(false, "creator-b", None, now).unwrap();
    drop(held);
    slots.try_acquire(false, "creator-a", None, now).unwrap();
    drop(other);
}

#[test]
fn slots_rate_limit_opens_per_creator_per_minute() {
    let slots = Arc::new(ChannelSlots::default());
    let now = Instant::now();
    for _ in 0..CHANNEL_OPENS_PER_MINUTE_PER_GUEST_CREATOR {
        drop(slots.try_acquire(false, "creator-a", None, now).unwrap());
    }
    assert_eq!(
        slots
            .try_acquire(false, "creator-a", None, now)
            .unwrap_err(),
        SlotRefusal::RateLimited
    );
    drop(slots.try_acquire(false, "creator-b", None, now).unwrap());
    let later = now + OPEN_RATE_WINDOW;
    drop(slots.try_acquire(false, "creator-a", None, later).unwrap());
}

#[test]
fn an_open_beyond_host_pty_capacity_is_refused() {
    let mut rig = rig();
    let held: Vec<SlotGuard> = (0..CHANNEL_MAX_PTY_CHANNELS_PER_HOST)
        .map(|_| {
            rig.slots
                .try_acquire(true, "someone", None, Instant::now())
                .unwrap()
        })
        .collect();
    let out = open(&mut rig, &fence("ch-1"), ChannelKind::Pty);
    assert_eq!(refusal(&out), code(SandboxErrorCode::RateLimited));
    assert!(rig.fake.channel_control("sbx-1", CONN, "ch-1").is_none());
    // An exec channel still opens.
    opened(&mut rig, "ch-2", ChannelKind::Exec);
    drop(held);
}

#[test]
fn a_settled_exit_releases_the_slot() {
    let mut rig = rig();
    let (fence, _control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    assert_eq!(rig.slots.live(), 1);
    stdin_eof(&mut rig, &fence, 0);
    let out = drive(&mut rig, has_exit);
    assert_eq!(exit(&out).unwrap().exit_code, Some(0));
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
}

/// An uncertain kill keeps the slot and the registry entry until a retried
/// scope kill proves the scope gone; then a bare second exit says so.
#[test]
fn an_uncertain_kill_keeps_capacity_until_the_scope_is_gone() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.make_kill_uncertain();
    rig.fake.set_channel_scope_present(&unit("ch-1"), true);
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    let mut out = drive(&mut rig, has_exit);
    let first = exit(&out).unwrap();
    assert_eq!(first.intent, Some(ChannelCloseIntent::Revoked));
    assert!(!first.reaped, "an unsettled end says so");
    assert_eq!((first.exit_code, first.signal), (None, None));
    let deadline = Instant::now() + Duration::from_secs(10);
    while rig.fake.channel_scope_kills().len() < 2 {
        assert!(Instant::now() < deadline, "the kill is never retried");
        out.extend(settle(&mut rig, Duration::from_millis(20)));
    }
    assert_eq!(exits(&out).len(), 1);
    assert_eq!(
        control.terminations(),
        0,
        "an unproven kill leaves the client and stdin"
    );
    assert_eq!(rig.slots.live(), 1);
    assert_eq!(rig.host.live_channels(), 1);
    assert!(registry_file(&rig, "ch-1").exists());
    let kills = rig.fake.channel_scope_kills();
    assert!(kills.len() >= 2, "the kill is retried: {kills:?}");
    assert!(kills.iter().all(|kill| {
        kill.sandbox_id == "sbx-1"
            && kill.template_fingerprint == FP
            && kill.guest.guest_uid == 1234
            && kill.scopes
                == vec![ChannelScopeRef {
                    unit: unit("ch-1"),
                    forget: false,
                }]
    }));
    // Same id while the scope is not settled: refused.
    assert!(open(&mut rig, &fence, ChannelKind::Exec).is_empty());

    rig.fake.set_channel_scope_present(&unit("ch-1"), false);
    out.extend(drive(&mut rig, has_exit));
    let all = exits(&out);
    assert_eq!(all.len(), 2, "{all:?}");
    let second = &all[1];
    assert!(second.reaped);
    assert_eq!(control.terminations(), 1, "ended only after the proof");
    assert_eq!(second.intent, None);
    assert_eq!(second.error, None);
    assert_eq!((second.exit_code, second.signal), (None, None));
    assert_eq!(rig.host.live_channels(), 0);
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
    assert!(!registry_file(&rig, "ch-1").exists());
}

// ------------------------------------------------------------- registry ----

#[test]
fn a_registry_entry_exists_while_the_channel_runs() {
    let mut rig = rig();
    let (fence, _control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    let path = registry_file(&rig, "ch-1");
    let entry = RegistryEntry::decode(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(entry.unit, unit("ch-1"));
    assert_eq!(entry.sandbox_id, "sbx-1");
    assert_eq!(entry.template_fingerprint, FP);
    assert_eq!(entry.guest.guest_uid, 1234);
    assert_eq!(entry.guest.guest_gid, 2345);
    assert_eq!(rig.registry.entries(), vec![entry]);
    input(&mut rig, &fence, 0, &[0x04]);
    drive(&mut rig, has_exit);
    // The custodian forgets it once the owner acknowledged the settled end.
    wait_until("entry forgotten", || !path.exists());
    assert!(rig.registry.entries().is_empty());
}

fn entry(sandbox: &str, channel: &str) -> RegistryEntry {
    RegistryEntry {
        unit: unit(channel),
        sandbox_id: sandbox.into(),
        template_fingerprint: FP.into(),
        guest: GuestIdentity {
            guest_uid: 1234,
            guest_gid: 2345,
            guest_home: "/home/declared".into(),
            guest_shell: "/bin/zsh".into(),
        },
    }
}

#[test]
fn the_sweep_kills_registered_scopes_and_forgets_the_gone_ones() {
    let rig = rig();
    let gone = entry("sbx-1", "a");
    let present = entry("sbx-1", "b");
    let other = entry("sbx-2", "c");
    for entry in [&gone, &present, &other] {
        rig.registry.record(entry).unwrap();
    }
    // An unreadable entry is skipped (and never handed to the runtime).
    let junk = rig
        .journal
        .state_dir()
        .unwrap()
        .join(format!("{REGISTRY_PREFIX}{}", unit("junk")));
    std::fs::write(&junk, b"not an entry").unwrap();
    rig.fake.set_channel_scope_present(&present.unit, true);
    sweep_registry(Arc::new(rig.fake.clone()), rig.registry.clone());
    wait_until("gone scopes forgotten", || {
        let units: Vec<String> = rig.registry.entries().into_iter().map(|e| e.unit).collect();
        units == vec![present.unit.clone()]
    });
    let kills = rig.fake.channel_scope_kills();
    let sbx1 = kills.iter().find(|k| k.sandbox_id == "sbx-1").unwrap();
    let mut units: Vec<&str> = sbx1.scopes.iter().map(|s| s.unit.as_str()).collect();
    units.sort_unstable();
    assert_eq!(units, vec![gone.unit.as_str(), present.unit.as_str()]);
    assert!(sbx1.scopes.iter().all(|s| !s.forget));
    assert_eq!(sbx1.template_fingerprint, FP);
    assert_eq!(sbx1.guest, gone.guest);
    let sbx2 = kills.iter().find(|k| k.sandbox_id == "sbx-2").unwrap();
    assert_eq!(sbx2.scopes.len(), 1);
    assert!(
        kills
            .iter()
            .all(|k| k.scopes.iter().all(|s| s.unit != unit("junk")))
    );
    // The present scope is retried until it is gone.
    rig.fake.set_channel_scope_present(&present.unit, false);
    wait_until("present scope forgotten", || {
        rig.registry.entries().is_empty()
    });
    assert!(junk.exists());
}

#[test]
fn registry_entries_round_trip_and_refuse_garbage() {
    let original = entry("sbx-1", "ch-1");
    let bytes = original.encode();
    assert_eq!(RegistryEntry::decode(&bytes), Some(original.clone()));

    let text = String::from_utf8(bytes).unwrap();
    let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    let with = |index: usize, value: &str| {
        let mut changed = lines.clone();
        changed[index] = value;
        format!("{}\n", changed.join("\n")).into_bytes()
    };
    let garbage: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"\n".to_vec(),
        vec![0xff, 0xfe, b'\n'],
        text.trim_end_matches('\n').as_bytes().to_vec(),
        format!("{text}extra\n").into_bytes(),
        with(0, "wssp-channel-scope-v0"),
        with(1, "wssp-sbx-1"),
        with(1, "wssp-chan-only.scope"),
        with(4, "not-a-uid"),
        with(4, "0"),
        with(5, "-1"),
        with(6, "relative/home"),
        with(7, "/bin/../sh"),
    ];
    for bytes in garbage {
        assert_eq!(
            RegistryEntry::decode(&bytes),
            None,
            "{:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

#[test]
fn the_registry_skips_an_entry_whose_name_and_unit_disagree() {
    let rig = rig();
    let path = rig
        .journal
        .state_dir()
        .unwrap()
        .join(format!("{REGISTRY_PREFIX}{}", unit("other")));
    std::fs::write(&path, entry("sbx-1", "ch-1").encode()).unwrap();
    assert!(rig.registry.entries().is_empty());
}

#[test]
fn a_kill_intent_during_a_slow_normal_close_kills_the_scope() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.set_normal_close_delay(Duration::from_millis(300));
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    wait_until("normal close started", || {
        closes(&control) == vec!["hangup"]
    });
    // A revoke lands while the hangup is still running.
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    let out = drive(&mut rig, has_exit);
    let exit = exit(&out).unwrap();
    assert_eq!(exit.intent, Some(ChannelCloseIntent::Revoked));
    let kills = rig.fake.channel_scope_kills();
    assert!(
        kills
            .iter()
            .any(|k| k.scopes.iter().any(|s| s.unit == unit("ch-1") && s.forget)),
        "the upgraded stop killed the scope: {kills:?}"
    );
}

#[test]
fn a_repeated_cumulative_ack_is_not_a_violation() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Pty);
    emit_n(&control, ChannelOutput::Stdout, 2);
    drive(&mut rig, |out| data(out).len() >= 2);
    ack(&mut rig, &fence, ChannelStream::Stdout, 1);
    ack(&mut rig, &fence, ChannelStream::Stdout, 1);
    ack(&mut rig, &fence, ChannelStream::Stdout, 0);
    let out = settle(&mut rig, Duration::from_millis(200));
    assert!(!has_exit(&out), "repeated acks never close: {out:?}");
    assert!(control.closes().is_empty());
}

#[test]
fn the_sweep_never_touches_entries_written_after_it_started() {
    let mut rig = rig();
    let leftover = entry("sbx-1", "old");
    rig.registry.record(&leftover).unwrap();
    rig.fake.set_channel_scope_present(&leftover.unit, true);
    sweep_registry(Arc::new(rig.fake.clone()), rig.registry.clone());
    wait_until("first sweep pass", || {
        !rig.fake.channel_scope_kills().is_empty()
    });
    // A channel of this process opens while the leftover is still retried.
    let (_fence, control) = opened(&mut rig, "ch-new", ChannelKind::Exec);
    std::thread::sleep(Duration::from_millis(400));
    let kills = rig.fake.channel_scope_kills();
    assert!(
        kills
            .iter()
            .all(|k| k.scopes.iter().all(|s| s.unit != unit("ch-new"))),
        "a live channel was swept: {kills:?}"
    );
    assert!(registry_file(&rig, "ch-new").exists());
    assert!(control.closes().is_empty());
    rig.fake.set_channel_scope_present(&leftover.unit, false);
}

#[test]
fn output_queued_before_a_close_decision_is_never_forwarded() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    emit_n(&control, ChannelOutput::Stdout, 3);
    // The output waits in the guest stream; no tick has read it.
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    let out = drive(&mut rig, has_exit);
    assert!(data(&out).is_empty(), "bytes after the decision: {out:?}");
    // Both output streams still end with an eof before the exit.
    let eofs = eofs(&out);
    assert_eq!(
        eofs,
        vec![(ChannelStream::Stdout, 0), (ChannelStream::Stderr, 0)]
    );
    assert!(exit_index(&out) > 0);
}

#[test]
fn an_explicit_close_ends_both_streams_with_eof_before_the_exit() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    emit_n(&control, ChannelOutput::Stderr, 1);
    let out = drive(&mut rig, |out| data(out).len() == 1);
    assert_eq!(data(&out)[0].0, ChannelStream::Stderr);
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        eofs(&out),
        vec![(ChannelStream::Stdout, 0), (ChannelStream::Stderr, 1)]
    );
}

#[test]
fn a_kill_signal_under_exhausted_credit_ends_at_once_without_more_output() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    // Fill the whole window (no acks), then queue more.
    emit_n(&control, ChannelOutput::Stdout, 40);
    let out = drive(&mut rig, |out| data(out).len() >= 32);
    assert_eq!(data(&out).len(), 32);
    let started = Instant::now();
    signal(&mut rig, &fence, ChannelSignal::Kill);
    let out = drive(&mut rig, has_exit);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(data(&out).is_empty(), "no output after the kill: {out:?}");
    assert_eq!(exit(&out).unwrap().signal, Some(9));
    assert_eq!(closes(&control), vec!["kill"]);
}

#[test]
fn a_revoke_after_an_unsettled_normal_close_still_kills_the_scope() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.make_unreaped();
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    let out = drive(&mut rig, has_exit);
    assert!(!exit(&out).unwrap().reaped, "unsettled end");
    assert!(registry_file(&rig, "ch-1").exists());
    // The relay drops (or the key is revoked) while the reap is pending.
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    wait_until("upgraded kill ran", || {
        rig.fake
            .channel_scope_kills()
            .iter()
            .any(|k| k.scopes.iter().any(|s| s.unit == unit("ch-1")))
    });
    control.reap();
    drive(&mut rig, |out| exits(out).iter().any(|e| e.reaped));
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
    assert!(!registry_file(&rig, "ch-1").exists());
}

#[test]
fn one_tick_forwards_a_bounded_number_of_data_frames_round_robin() {
    let mut rig = rig();
    let mut controls = Vec::new();
    for n in 0..3 {
        let (_fence, control) = opened(&mut rig, &format!("ch-{n}"), ChannelKind::Exec);
        controls.push(control);
    }
    for control in &controls {
        emit_n(control, ChannelOutput::Stdout, 20);
    }
    let first = outs(rig.host.poll().unwrap());
    assert_eq!(data(&first).len(), TICK_DATA_FRAMES);
    let out = drive(&mut rig, |out| data(out).len() >= 60 - TICK_DATA_FRAMES);
    assert_eq!(data(&first).len() + data(&out).len(), 60);
}

#[test]
fn unacknowledged_output_is_capped_per_owner_and_across_the_host() {
    let mut rig = rig();
    let mut controls = Vec::new();
    for n in 0..3 {
        controls.push(opened(&mut rig, &format!("a-{n}"), ChannelKind::Exec).1);
        controls.push(opened2(&mut rig, &format!("b-{n}")).1);
    }
    for control in &controls {
        emit_n(control, ChannelOutput::Stdout, 32);
    }
    let mut out = drive(&mut rig, |o| data(o).len() as u64 >= HOST_UNACKED_FRAMES);
    out.extend(settle(&mut rig, Duration::from_millis(100)));
    assert_eq!(data(&out).len() as u64, HOST_UNACKED_FRAMES);
    let per_owner = |sandbox: &str| {
        out.iter()
            .filter(|o| match o {
                Out::Binary(frame) => matches!(
                    &parse_channel_frame(frame).unwrap().unwrap().0.fence.target,
                    ChannelTarget::Sandbox { sandbox_id, .. } if sandbox_id == sandbox
                ),
                _ => false,
            })
            .count() as u64
    };
    assert_eq!(per_owner("sbx-1"), CREATOR_UNACKED_FRAMES);
    assert_eq!(per_owner("sbx-2"), CREATOR_UNACKED_FRAMES);
}

#[test]
fn kill_closes_never_wedge_behind_the_host_cap() {
    let mut rig = rig();
    let mut opened_channels = Vec::new();
    for n in 0..5 {
        let (fence, control) = opened(&mut rig, &format!("ch-{n}"), ChannelKind::Exec);
        opened_channels.push((fence, control));
    }
    for (_, control) in &opened_channels {
        emit_n(control, ChannelOutput::Stdout, 32);
    }
    let mut out = drive(&mut rig, |o| data(o).len() as u64 >= CREATOR_UNACKED_FRAMES);
    out.extend(settle(&mut rig, Duration::from_millis(100)));
    // The owner's share, plus at most each channel's reserved frame.
    let sent = data(&out).len() as u64;
    assert!(
        (CREATOR_UNACKED_FRAMES..=CREATOR_UNACKED_FRAMES + 5).contains(&sent),
        "{sent}"
    );
    // Kill closes of every channel while the host cap holds output back.
    for (fence, _) in &opened_channels {
        signal(&mut rig, fence, ChannelSignal::Kill);
    }
    let out = drive(&mut rig, |out| exits(out).len() == 5);
    assert!(data(&out).is_empty(), "no output after the kills: {out:?}");
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
}

#[test]
fn pty_output_is_never_starved_by_the_bulk_cap() {
    let mut rig = rig();
    let mut bulk = Vec::new();
    for n in 0..5 {
        bulk.push(opened(&mut rig, &format!("bulk-{n}"), ChannelKind::Exec).1);
    }
    for control in &bulk {
        emit_n(control, ChannelOutput::Stdout, 32);
    }
    drive(&mut rig, |o| data(o).len() as u64 >= CREATOR_UNACKED_FRAMES);
    let (_fence, shell) = opened(&mut rig, "shell", ChannelKind::Pty);
    emit_n(&shell, ChannelOutput::Stdout, 2);
    let out = drive(&mut rig, |out| data(out).len() >= 2);
    assert_eq!(data(&out).len(), 2);
}

#[test]
fn a_notice_flood_never_blocks_mandatory_events() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.set_signal_support(false);
    // More notices than fit next to the mandatory events, without a socket
    // tick taking them (within the control queue's own bound)…
    for _ in 0..40 {
        let _ = rig
            .host
            .handle_control(ServerControlMessage::ChannelSignal {
                fence: fence.clone(),
                signal: ChannelSignal::Term,
            });
    }
    std::thread::sleep(Duration::from_millis(200));
    // …and stdin still gets its ack, and a close still ends the channel.
    input(&mut rig, &fence, 0, b"x");
    let out = drive(&mut rig, |out| !stdin_acks(out).is_empty());
    assert_eq!(stdin_acks(&out), vec![0]);
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    drive(&mut rig, has_exit);
}

// ------------------------------------------- simplified-design findings ----

/// Open without driving: the channel is spawned (fake control exists) but
/// the owner has not handed the preamble over yet.
fn spawned(rig: &mut Rig, channel: &str, kind: ChannelKind) -> (ChannelFence, FakeChannelControl) {
    let fence = fence(channel);
    assert!(open(rig, &fence, kind).is_empty());
    wait_until("spawned", || {
        rig.fake.channel_control("sbx-1", CONN, channel).is_some()
    });
    let control = control(rig, channel);
    control.set_input_ready(false);
    (fence, control)
}

/// r4.2/r5.1/r6.2: a close before the go (the preamble's last byte) never
/// lets anything of the workload, or its env, reach the guest.
#[test]
fn a_close_before_the_preamble_starts_nothing_in_either_mode() {
    for kind in [ChannelKind::Exec, ChannelKind::Pty] {
        let mut rig = rig();
        let (fence, control) = spawned(&mut rig, "ch-1", kind);
        // PROMPT seen, but the host side is not ready for input yet.
        settle(&mut rig, Duration::from_millis(50));
        assert!(!control.started());
        close(&mut rig, &fence, ChannelCloseIntent::Revoked);
        control.set_input_ready(true);
        let out = drive(&mut rig, has_exit);
        assert!(
            !control.started(),
            "the workload started after the decision"
        );
        assert_eq!(
            control.partial_preamble(),
            0,
            "preamble bytes after the decision"
        );
        assert!(control.env().is_none());
        assert!(ready(&out).is_none());
        assert_eq!(closes(&control), vec!["kill"], "pre-READY closes kill");
        let exit = exit(&out).unwrap();
        assert_eq!(exit.intent, Some(ChannelCloseIntent::Revoked));
        assert!(rig.slots.wait_idle(Duration::from_secs(2)));
    }
}

/// A close decided while the custodian is still spawning: the spawned IO is
/// dropped unread, the preamble never goes, the scope is kill-closed.
#[test]
fn a_close_during_the_spawn_never_hands_the_preamble_over() {
    let mut rig = rig();
    let fence = fence("ch-1");
    assert!(open(&mut rig, &fence, ChannelKind::Exec).is_empty());
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    let out = drive(&mut rig, has_exit);
    assert!(ready(&out).is_none());
    if let Some(control) = rig.fake.channel_control("sbx-1", CONN, "ch-1") {
        assert!(!control.started());
        assert_eq!(closes(&control), vec!["kill"]);
    }
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
    assert!(!registry_file(&rig, "ch-1").exists());
}

/// The preamble goes only after PROMPT and once the host side is raw.
#[test]
fn the_preamble_waits_for_the_raw_host_tty() {
    let mut rig = rig();
    let (_fence, control) = spawned(&mut rig, "ch-1", ChannelKind::Pty);
    let out = settle(&mut rig, Duration::from_millis(100));
    assert!(ready(&out).is_none());
    assert!(!control.started());
    control.set_input_ready(true);
    drive(&mut rig, |o| ready(o).is_some());
    assert!(control.started());
}

/// r3.3/r4.3: the absolute deadline (an env-bearing channel's lease) also
/// bounds setup: past it the preamble is never handed over.
#[test]
fn the_admission_deadline_bounds_setup() {
    let mut rig = rig();
    let (_fence, control) = spawned(&mut rig, "ch-1", ChannelKind::Exec);
    settle(&mut rig, Duration::from_millis(30));
    rig.host.advance(sandbox_runtime::PTY_MAX_SESSION);
    control.set_input_ready(true);
    let out = drive(&mut rig, has_exit);
    assert!(!control.started());
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::Expired)
    );
    assert_eq!(closes(&control), vec!["kill"]);
}

/// The setup deadline: no READY within 30 s is a kill-closed timeout.
#[test]
fn a_setup_without_ready_times_out() {
    let mut rig = rig();
    let (_fence, control) = spawned(&mut rig, "ch-1", ChannelKind::Exec);
    settle(&mut rig, Duration::from_millis(30));
    rig.host.advance(SETUP_DEADLINE);
    let out = drive(&mut rig, has_exit);
    let exit = exit(&out).unwrap();
    assert_eq!(
        exit.error.map(|e| e.code),
        Some(code(SandboxErrorCode::Timeout))
    );
    assert!(!control.started());
    assert_eq!(closes(&control), vec!["kill"]);
}

/// r1.3: a silent workload's stdout EOF before READY is kept (stdout is not
/// read before READY) and reported after it.
#[test]
fn an_early_stdout_eof_waits_for_ready() {
    let mut rig = rig();
    let (fence, control) = spawned(&mut rig, "ch-1", ChannelKind::Exec);
    control.eof(ChannelOutput::Stdout);
    control.set_input_ready(true);
    let out = drive(&mut rig, |o| ready(o).is_some());
    assert!(eofs(&out).is_empty() || eofs(&out) == vec![(ChannelStream::Stdout, 0)]);
    control.exit(ChannelExitStatus::Code(0));
    let mut all = out;
    all.extend(drive(&mut rig, has_exit));
    assert!(eofs(&all).contains(&(ChannelStream::Stdout, 0)));
    let ready_at = all
        .iter()
        .position(|o| matches!(o, Out::Text(DaemonControlMessage::ChannelReady { .. })))
        .unwrap();
    let eof_at = all
        .iter()
        .position(|o| matches!(o, Out::Text(DaemonControlMessage::ChannelEof { .. })))
        .unwrap();
    assert!(ready_at < eof_at);
    assert_eq!(exit(&all).unwrap().exit_code, Some(0));
    assert_eq!(fence, exit(&all).unwrap().fence);
}

/// r1.4: READY and EXIT in one read of a fast pty command: ready, then a
/// natural exit with the status (never a setup failure).
#[test]
fn a_fast_pty_exit_in_the_ready_chunk_is_a_natural_end() {
    let mut rig = rig();
    let (_fence, control) = spawned(&mut rig, "ch-1", ChannelKind::Pty);
    settle(&mut rig, Duration::from_millis(30));
    control.set_input_ready(true);
    // One tick hands the preamble over (the fake queues READY); the exit
    // lands in the same stream before the next read.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !control.started() {
        assert!(Instant::now() < deadline, "preamble never handed over");
        assert!(ready(&outs(rig.host.poll().unwrap())).is_none());
    }
    control.exit(ChannelExitStatus::Code(0));
    // READY and EXIT arrive in one read: the owner handles every frame of a
    // chunk, not only the first.
    control.coalesce(ChannelOutput::Stdout);
    assert_eq!(control.queued(ChannelOutput::Stdout), 1);
    let out = drive(&mut rig, has_exit);
    assert!(ready(&out).is_some(), "{out:?}");
    let exit = exit(&out).unwrap();
    assert_eq!(exit.exit_code, Some(0));
    assert_eq!(exit.error, None);
    assert_eq!(closes(&control), vec!["finish"]);
}

/// r1.5/r2.4: a detached survivor that keeps writing (with an acknowledging
/// client) never extends the drain past 60 s after EXIT.
#[test]
fn a_writing_survivor_never_pins_an_exited_channel() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.exit_holding(ChannelExitStatus::Code(0));
    let mut out = Vec::new();
    for _ in 0..70 {
        control.emit(ChannelOutput::Stdout, b"survivor");
        let tick = outs(rig.host.poll().unwrap());
        for (stream, seq, _) in data(&tick) {
            ack(&mut rig, &fence, stream, seq);
        }
        out.extend(tick);
        if has_exit(&out) {
            break;
        }
        rig.host.advance(Duration::from_secs(1));
    }
    // The owner decided the natural end at the bound; the custodian's
    // answer (and the exit) follow asynchronously.
    wait_until("finish ordered", || closes(&control) == vec!["finish"]);
    if !has_exit(&out) {
        out.extend(drive(&mut rig, has_exit));
    }
    let exit = exit(&out).expect("the drain is bounded");
    assert_eq!(exit.exit_code, Some(0));
    assert!(
        rig.fake.channel_scope_kills().is_empty(),
        "survivors survive"
    );
}

/// A survivor that holds the pipes silent: 2 s after EXIT and proven idle.
#[test]
fn a_silent_survivor_ends_the_drain_after_two_seconds() {
    let mut rig = rig();
    let (_fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.exit_holding(ChannelExitStatus::Code(4));
    settle(&mut rig, Duration::from_millis(30));
    rig.host.advance(Duration::from_millis(1500));
    assert!(!has_exit(&settle(&mut rig, Duration::from_millis(30))));
    // Idle since the first empty read with credit; 2 s after EXIT it ends.
    rig.host.advance(Duration::from_millis(600));
    let out = drive(&mut rig, has_exit);
    assert_eq!(exit(&out).unwrap().exit_code, Some(4));
    assert_eq!(
        eofs(&out),
        vec![(ChannelStream::Stdout, 0), (ChannelStream::Stderr, 0)]
    );
}

/// r2.5/r3.1: a slow (but within-contract) client gets every byte of a
/// workload that exited: unread output is never "idle", so only the 60 s
/// cap could end the drain.
#[test]
fn a_slow_client_gets_every_byte_after_exit() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    emit_n(&control, ChannelOutput::Stdout, 50);
    control.exit(ChannelExitStatus::Code(0));
    let mut out = drive(&mut rig, |o| data(o).len() >= 32);
    // The client is slow: 10 s without an ack, well past the 2 s drain.
    for _ in 0..10 {
        rig.host.advance(Duration::from_secs(1));
        out.extend(settle(&mut rig, Duration::from_millis(5)));
    }
    assert!(!has_exit(&out), "back-pressured output ended the drain");
    ack(&mut rig, &fence, ChannelStream::Stdout, 31);
    out.extend(drive(&mut rig, has_exit));
    assert_eq!(data(&out).len(), 50);
    assert_eq!(exit(&out).unwrap().frames, (50, 0));
}

/// r3.2/r4.1: stdin admitted before a close decision but not yet handed over
/// is discarded; nothing reaches the guest after the decision.
#[test]
fn stdin_pending_at_a_close_decision_never_reaches_the_guest() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    input(&mut rig, &fence, 0, b"rm -rf");
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    let out = drive(&mut rig, has_exit);
    assert!(control.stdin().is_empty(), "stdin after the decision");
    assert!(stdin_acks(&out).is_empty());
    // With a slow signal in progress too.
    let (fence, control) = opened(&mut rig, "ch-2", ChannelKind::Exec);
    control.set_signal_delay(Duration::from_millis(200));
    assert!(signal(&mut rig, &fence, ChannelSignal::Term).is_empty());
    input(&mut rig, &fence, 0, b"x");
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    drive(&mut rig, has_exit);
    assert!(control.stdin().is_empty());
}

/// r5.2/r6.3: channels holding part-filled windows that keep the host cap
/// (both owners' shares) full are timed out; channels blocked only by the
/// cap then proceed.
#[test]
fn part_filled_windows_never_pin_the_host_cap() {
    let mut rig = rig();
    let mut holders = Vec::new();
    for n in 0..4 {
        holders.push(opened(&mut rig, &format!("hold-a{n}"), ChannelKind::Exec));
        holders.push(opened2(&mut rig, &format!("hold-b{n}")));
    }
    for (_, control) in &holders {
        emit_n(control, ChannelOutput::Stdout, 16);
    }
    let mut out = drive(&mut rig, |o| data(o).len() as u64 >= HOST_UNACKED_FRAMES);
    out.extend(settle(&mut rig, Duration::from_millis(50)));
    assert_eq!(data(&out).len() as u64, HOST_UNACKED_FRAMES);
    let (fence, healthy) = opened(&mut rig, "healthy", ChannelKind::Exec);
    emit_n(&healthy, ChannelOutput::Stdout, 3);
    // The full cap still leaves the newcomer its reserved frame: one at a
    // time, each after the previous one's ack (audit M1).
    for seq in 0..2 {
        let early = settle(&mut rig, Duration::from_millis(50));
        assert_eq!(data(&early).len(), 1, "{early:?}");
        assert_eq!(data(&early)[0].1, seq);
        ack(&mut rig, &fence, ChannelStream::Stdout, seq);
    }
    // Its third frame went out at once after the second ack: acknowledge
    // it too, so only the holders are 60 s unacknowledged.
    let early = drive(&mut rig, |o| !data(o).is_empty());
    assert_eq!(data(&early)[0].1, 2);
    ack(&mut rig, &fence, ChannelStream::Stdout, 2);
    rig.host.advance(STALL_TIMEOUT);
    emit_n(&healthy, ChannelOutput::Stdout, 2);
    let out = drive(&mut rig, |o| exits(o).len() >= 8 && !data(o).is_empty());
    assert!(
        exits(&out)
            .iter()
            .all(|e| e.intent == Some(ChannelCloseIntent::Backpressure))
    );
    let senders: Vec<ChannelFence> = out
        .iter()
        .filter_map(|o| match o {
            Out::Binary(frame) => parse_channel_frame(frame).map(|f| f.unwrap().0.fence),
            _ => None,
        })
        .collect();
    assert!(senders.iter().all(|f| *f == fence));
    assert!(exits(&out).iter().all(|e| e.fence != fence));
}

/// Promptly acknowledged output never stalls, a part-filled window
/// included; output unacknowledged for 60 s does, a full window or not.
#[test]
fn only_output_unacknowledged_for_sixty_seconds_stalls() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    let mut sent = 0;
    for _ in 0..4 {
        emit_n(&control, ChannelOutput::Stdout, 4);
        sent += 4;
        drive(&mut rig, |o| data(o).len() >= 4);
        rig.host.advance(STALL_TIMEOUT - Duration::from_secs(1));
        ack(&mut rig, &fence, ChannelStream::Stdout, sent - 1);
    }
    assert!(!has_exit(&settle(&mut rig, Duration::from_millis(30))));
    // One frame left unacknowledged: 60 s later the channel stalls.
    control.emit(ChannelOutput::Stdout, b"late");
    drive(&mut rig, |o| !data(o).is_empty());
    rig.host.advance(STALL_TIMEOUT);
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::Backpressure)
    );
}

/// Every close before READY is a kill close, a client close too.
#[test]
fn a_client_close_before_ready_still_kills() {
    let mut rig = rig();
    let (fence, control) = spawned(&mut rig, "ch-1", ChannelKind::Pty);
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    drive(&mut rig, has_exit);
    assert_eq!(closes(&control), vec!["kill"]);
}

/// r2.3 variant: a kill-class decision whose order crosses the normal
/// close's answer (already sent, not yet read) is never lost: the exit waits
/// for both answers and reports the proven kill.
#[test]
fn a_kill_upgrade_racing_the_normal_close_answer_is_never_lost() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    // The custodian answered the hangup; no tick has read the answer yet.
    wait_until("hangup answered", || control.ended().is_some());
    thread::sleep(Duration::from_millis(50));
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    let out = drive(&mut rig, |o| exits(o).iter().any(|e| e.reaped));
    let all = exits(&out);
    assert_eq!(all.len(), 1, "one exit, after both answers: {all:?}");
    assert_eq!(all[0].intent, Some(ChannelCloseIntent::Revoked));
    assert_eq!(
        all[0].signal,
        Some(9),
        "the exit reports the upgrade's proven kill"
    );
    assert!(
        rig.fake
            .channel_scope_kills()
            .iter()
            .any(|k| k.scopes.iter().any(|s| s.unit == unit("ch-1")))
    );
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
}

/// The custodian's own fixed rule: the owner vanished (relay loss) while a
/// normal close's end is unsettled: the scope is killed.
#[test]
fn relay_loss_during_an_unsettled_normal_close_kills_the_scope() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.make_unreaped();
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    drive(&mut rig, has_exit);
    let Rig {
        dir: _dir,
        fake,
        slots,
        host,
        ..
    } = rig;
    drop(host);
    wait_until("upgraded kill ran", || {
        fake.channel_scope_kills()
            .iter()
            .any(|k| k.scopes.iter().any(|s| s.unit == unit("ch-1")))
    });
    control.reap();
    assert!(slots.wait_idle(Duration::from_secs(5)));
}

#[test]
fn end_due_is_a_pure_function_of_the_drain_state() {
    let t0 = Instant::now();
    let exec = [ChannelOutput::Stdout, ChannelOutput::Stderr];
    let draining = Phase::Draining { exit_at: t0 };
    // Both eofs end at once (also while running: the wrapper died).
    assert!(end_due(
        draining,
        &exec,
        [true, true],
        [None, None],
        false,
        t0
    ));
    assert!(end_due(
        Phase::Running,
        &exec,
        [true, true],
        [None, None],
        false,
        t0
    ));
    assert!(!end_due(
        Phase::Starting,
        &exec,
        [true, true],
        [None, None],
        false,
        t0
    ));
    // Idle-proven streams end 2 s after EXIT, not before.
    let idle = [Some(t0), Some(t0)];
    assert!(!end_due(
        draining,
        &exec,
        [false, false],
        idle,
        false,
        t0 + Duration::from_millis(1900)
    ));
    assert!(end_due(
        draining,
        &exec,
        [false, false],
        idle,
        false,
        t0 + EXIT_DRAIN
    ));
    // Not proven idle: only the cap ends it.
    let busy = [None, Some(t0)];
    assert!(!end_due(
        draining,
        &exec,
        [false, false],
        busy,
        false,
        t0 + Duration::from_secs(59)
    ));
    assert!(end_due(
        draining,
        &exec,
        [false, false],
        busy,
        false,
        t0 + EXIT_DRAIN_MAX
    ));
    // Idle too recently.
    let recent = [Some(t0 + Duration::from_secs(3)), Some(t0)];
    assert!(!end_due(
        draining,
        &exec,
        [false, false],
        recent,
        false,
        t0 + Duration::from_secs(3)
    ));
    assert!(!end_due(
        Phase::Running,
        &exec,
        [false, true],
        idle,
        false,
        t0 + EXIT_DRAIN_MAX
    ));
    // A relay held by credit is not cut at the cap; once reads happen
    // again (not held) the cap applies, and an eof always ends it.
    let relay = [ChannelOutput::Stdout, ChannelOutput::Stderr];
    assert!(!end_due(
        draining,
        &relay,
        [false, false],
        [None, None],
        true,
        t0 + EXIT_DRAIN_MAX * 10
    ));
    assert!(end_due(
        draining,
        &relay,
        [false, false],
        [None, None],
        false,
        t0 + EXIT_DRAIN_MAX
    ));
    assert!(end_due(
        draining,
        &relay,
        [true, true],
        [None, None],
        true,
        t0
    ));
}

// ---------------------------------------------------------------- fuzz ----

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Per-channel trace checks over everything the host sent.
#[derive(Default)]
struct Trace {
    ready: bool,
    exited: bool,
    settled: bool,
    eof: [bool; 2],
    sent: [u64; 2],
    acked: [u64; 2],
    decided: bool,
    /// Data frames sent after the channel's close decision.
    after_decision: usize,
    stdin_at_decision: Option<usize>,
}

fn check(traces: &mut HashMap<String, Trace>, kinds: &HashMap<String, ChannelKind>, out: &[Out]) {
    for o in out {
        match o {
            Out::Binary(frame) => {
                let (meta, _) = parse_channel_frame(frame).unwrap().unwrap();
                let t = traces.entry(meta.fence.channel_id.clone()).or_default();
                assert!(t.ready, "data before ready");
                assert!(!t.exited, "data after exit");
                let i = (meta.stream == ChannelStream::Stderr) as usize;
                assert!(!t.eof[i], "data after eof");
                assert_eq!(meta.seq, t.sent[i], "sequence");
                t.sent[i] += 1;
                let unacked: u64 = (0..2).map(|s| t.sent[s] - t.acked[s]).sum();
                assert!(
                    unacked <= window(kinds[&meta.fence.channel_id]),
                    "window overrun"
                );
                if t.decided {
                    t.after_decision += 1;
                }
            }
            Out::Text(DaemonControlMessage::ChannelReady { fence, .. }) => {
                let t = traces.entry(fence.channel_id.clone()).or_default();
                assert!(!t.ready && !t.exited, "ready twice or after exit");
                t.ready = true;
            }
            Out::Text(DaemonControlMessage::ChannelEof {
                fence,
                stream,
                frames,
            }) => {
                let t = traces.entry(fence.channel_id.clone()).or_default();
                let i = (*stream == ChannelStream::Stderr) as usize;
                assert!(!t.exited && !t.eof[i], "eof twice or after exit");
                assert_eq!(*frames, t.sent[i]);
                t.eof[i] = true;
            }
            Out::Text(DaemonControlMessage::ChannelExit {
                fence,
                reaped,
                frames,
                ..
            }) => {
                let t = traces.entry(fence.channel_id.clone()).or_default();
                assert!(!t.settled, "exit after the settled exit");
                if t.exited {
                    assert!(*reaped, "only a bare settled exit may follow");
                } else if t.ready && kinds[&fence.channel_id] == ChannelKind::Exec {
                    assert!(t.eof[0] && t.eof[1], "eofs before exit");
                }
                assert_eq!((frames.stdout, frames.stderr), (t.sent[0], t.sent[1]));
                t.exited = true;
                t.settled = *reaped;
            }
            _ => {}
        }
    }
}

#[test]
fn seeded_interleavings_keep_the_trace_invariants() {
    for seed in 1..=24u64 {
        let mut rng = XorShift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut rig = rig();
        let mut traces: HashMap<String, Trace> = HashMap::new();
        let mut kinds: HashMap<String, ChannelKind> = HashMap::new();
        let mut live: Vec<(ChannelFence, FakeChannelControl, u64)> = Vec::new();
        for n in 0..(1 + rng.below(3)) {
            let kind = if rng.below(2) == 0 {
                ChannelKind::Exec
            } else {
                ChannelKind::Pty
            };
            let name = format!("f-{n}");
            kinds.insert(name.clone(), kind);
            let fence = fence(&name);
            assert!(open(&mut rig, &fence, kind).is_empty());
            wait_until("spawned", || {
                rig.fake.channel_control("sbx-1", CONN, &name).is_some()
            });
            let control = control(&rig, &name);
            if rng.below(3) == 0 {
                control.make_unreaped();
            }
            if rng.below(4) == 0 {
                control.make_kill_uncertain();
            }
            live.push((fence, control, 0));
        }
        for _step in 0..160 {
            let pick = rng.below(live.len() as u64) as usize;
            let (fence, control, next_in) = &mut live[pick];
            let name = fence.channel_id.clone();
            match rng.below(14) {
                0..=2 => {
                    let stream = if rng.below(3) == 0 {
                        ChannelOutput::Stderr
                    } else {
                        ChannelOutput::Stdout
                    };
                    let size = 1 + rng.below(40_000) as usize;
                    control.emit(stream, &vec![b'o'; size]);
                }
                3 => {
                    let t = traces.entry(name.clone()).or_default();
                    for (i, stream) in [ChannelStream::Stdout, ChannelStream::Stderr]
                        .into_iter()
                        .enumerate()
                    {
                        if t.sent[i] > t.acked[i] {
                            let seq = t.acked[i] + rng.below(t.sent[i] - t.acked[i]);
                            t.acked[i] = seq + 1;
                            let fence = fence.clone();
                            ack(&mut rig, &fence, stream, seq);
                        }
                    }
                }
                4 => {
                    let t = traces.entry(name.clone()).or_default();
                    if t.ready && !t.decided {
                        let fence = fence.clone();
                        let seq = *next_in;
                        *next_in += 1;
                        input(&mut rig, &fence, seq, b"in");
                    }
                }
                5 => {
                    if rng.below(2) == 0 {
                        control.exit(ChannelExitStatus::Code(rng.below(3) as i32));
                    } else {
                        control.exit_holding(ChannelExitStatus::Code(1));
                    }
                }
                6 => {
                    let intent = match rng.below(4) {
                        0 => ChannelCloseIntent::Client,
                        1 => ChannelCloseIntent::Revoked,
                        2 => ChannelCloseIntent::SandboxStopped,
                        _ => ChannelCloseIntent::Expired,
                    };
                    let fence = fence.clone();
                    let control = control.clone();
                    close(&mut rig, &fence, intent);
                    let t = traces.entry(name.clone()).or_default();
                    if !t.decided {
                        t.decided = true;
                        t.stdin_at_decision = Some(control.stdin().len());
                    }
                }
                7 => {
                    if kinds[&name] == ChannelKind::Exec {
                        let fence = fence.clone();
                        let _ = signal(&mut rig, &fence, ChannelSignal::Term);
                    }
                }
                8 => rig.host.advance(Duration::from_millis(rng.below(3_000))),
                9 => {
                    if rng.below(8) == 0 {
                        rig.host.advance(Duration::from_secs(61));
                    }
                }
                10 => control.reap(),
                11 => control.settle_kill(),
                _ => {}
            }
            let out = outs(rig.host.poll().unwrap());
            check(&mut traces, &kinds, &out);
            for (fence, control, _) in &live {
                let t = traces.entry(fence.channel_id.clone()).or_default();
                if let Some(at) = t.stdin_at_decision {
                    assert_eq!(
                        control.stdin().len(),
                        at,
                        "seed {seed}: stdin after the decision"
                    );
                }
                assert_eq!(t.after_decision, 0, "seed {seed}: data after the decision");
            }
        }
        // Everything ends and releases its capacity.
        for (fence, control, _) in &live {
            control.reap();
            control.settle_kill();
            let fence = fence.clone();
            close(&mut rig, &fence, ChannelCloseIntent::Shutdown);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while traces.values().filter(|t| t.settled).count() < live.len() {
            assert!(Instant::now() < deadline, "seed {seed}: never settled");
            let out = outs(rig.host.poll().unwrap());
            check(&mut traces, &kinds, &out);
            thread::sleep(Duration::from_millis(2));
        }
        assert!(rig.slots.wait_idle(Duration::from_secs(5)), "seed {seed}");
        assert_eq!(rig.host.live_channels(), 0, "seed {seed}");
    }
}

/// H1: stdin frames and the stdin eof that arrive after a
/// natural end was decided are dropped quietly, never a violation.
#[test]
fn stdin_after_a_natural_end_is_not_a_violation() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.set_normal_close_delay(Duration::from_millis(100));
    control.exit(ChannelExitStatus::Code(0));
    // Until the natural end is decided (both streams ended).
    let mut out = Vec::new();
    while !closes(&control).contains(&"finish") {
        out.extend(outs(rig.host.poll().unwrap()));
    }
    input(&mut rig, &fence, 0, b"late");
    stdin_eof(&mut rig, &fence, 1);
    out.extend(drive(&mut rig, has_exit));
    let exit = exit(&out).unwrap();
    assert_eq!(exit.exit_code, Some(0));
    assert_eq!(exit.intent, None);
    assert_eq!(exit.error, None);
    assert_eq!(closes(&control), vec!["finish"]);
    assert!(control.stdin().is_empty());
}

/// M1: a promptly acknowledging channel is never timed out, and
/// a trickle of single acks does not keep a holder alive.
#[test]
fn trickle_ackers_time_out_and_innocent_channels_never_do() {
    let mut rig = rig();
    let (fence, holder) = opened(&mut rig, "holder", ChannelKind::Exec);
    let (_innocent_fence, innocent) = opened2(&mut rig, "innocent");
    emit_n(&holder, ChannelOutput::Stdout, 32);
    innocent.emit(ChannelOutput::Stdout, b"a");
    innocent.emit(ChannelOutput::Stdout, b"b");
    let mut out = drive(&mut rig, |o| data(o).len() >= 34);
    // The innocent client acknowledges what it got at once.
    let innocent_fence = _innocent_fence.clone();
    ack(&mut rig, &innocent_fence, ChannelStream::Stdout, 1);
    for seq in 0..4 {
        // One frame per 30 s: not a quarter window per minute.
        ack(&mut rig, &fence, ChannelStream::Stdout, seq);
        out.extend(settle(&mut rig, Duration::from_millis(10)));
        rig.host.advance(STALL_TIMEOUT / 2);
        out.extend(settle(&mut rig, Duration::from_millis(10)));
        if has_exit(&out) {
            break;
        }
    }
    if !has_exit(&out) {
        out.extend(drive(&mut rig, has_exit));
    }
    let exits = exits(&out);
    assert_eq!(exits.len(), 1, "{exits:?}");
    assert_eq!(exits[0].fence, fence);
    assert_eq!(exits[0].intent, Some(ChannelCloseIntent::Backpressure));
    assert!(innocent.closes().is_empty());
}

/// A busy channel whose client acknowledges everything within the minute
/// never stalls, however long it runs.
#[test]
fn a_busy_channel_with_prompt_acks_never_stalls() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    emit_n(&control, ChannelOutput::Stdout, 200);
    let mut out = drive(&mut rig, |o| data(o).len() >= 32);
    for _ in 0..5 {
        rig.host.advance(STALL_TIMEOUT - Duration::from_secs(1));
        let last = data(&out).last().unwrap().1;
        ack(&mut rig, &fence, ChannelStream::Stdout, last);
        out.extend(drive(&mut rig, |o| !data(o).is_empty()));
    }
    assert!(!has_exit(&out));
    assert!(data(&out).len() > 64);
}

/// The custodian's fixed deadline rule, with the owner silent past it.
#[test]
fn the_custodian_kills_at_the_deadline_on_its_own() {
    // An env-bearing channel lives at most until its lease deadline.
    let mut rig = rig_until(now_ms() + 1_500);
    let dir = tempfile::tempdir().unwrap();
    let credentials =
        crate::sandbox_relay::credentials::service::CredentialService::start(dir.path(), "host-1")
            .unwrap();
    credentials.install_test_env("sbx-1", "lease-1", "TOKEN", b"x");
    rig.host.set_credentials(Some(credentials));
    let (_fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    // No tick: only the custodian can act.
    wait_until("custodian deadline kill", || {
        closes(&control) == vec!["kill"]
    });
    let out = drive(&mut rig, has_exit);
    let exit = exit(&out).unwrap();
    assert_eq!(exit.intent, Some(ChannelCloseIntent::Expired));
    assert_eq!(exit.signal, Some(9));
}

/// r1.1: many holders below any threshold cannot pin the cap: every
/// unacknowledged frame is due within 60 s.
#[test]
fn sub_quarter_holders_never_pin_the_cap() {
    let mut rig = rig();
    let mut holders = Vec::new();
    for n in 0..9 {
        holders.push(opened(&mut rig, &format!("small-{n}"), ChannelKind::Exec));
    }
    let (fence, waiting) = opened(&mut rig, "waiting", ChannelKind::Exec);
    for (_, control) in &holders {
        emit_n(control, ChannelOutput::Stdout, 7);
    }
    drive(&mut rig, |o| data(o).len() as u64 >= 63);
    emit_n(&waiting, ChannelOutput::Stdout, 3);
    // One slot of the owner's share is left: one frame, then nothing.
    let mut out = drive(&mut rig, |o| !data(o).is_empty());
    out.extend(settle(&mut rig, Duration::from_millis(30)));
    assert_eq!(data(&out).len(), 1, "the owner's share is full");
    // The waiting channel's client acknowledges promptly; each ack frees one
    // slot for it, none for anybody else.
    ack(&mut rig, &fence, ChannelStream::Stdout, 0);
    let out = drive(&mut rig, |o| !data(o).is_empty());
    ack(&mut rig, &fence, ChannelStream::Stdout, data(&out)[0].1);
    rig.host.advance(STALL_TIMEOUT);
    let out = drive(&mut rig, |o| exits(o).len() >= 9);
    assert!(
        exits(&out)
            .iter()
            .all(|e| e.intent == Some(ChannelCloseIntent::Backpressure) && e.fence != fence)
    );
    // The holders' credit is back: the owner's share takes more output.
    emit_n(&waiting, ChannelOutput::Stdout, 8);
    let out = drive(&mut rig, |o| data(o).len() >= 8);
    assert!(data(&out).len() >= 8, "credit came back");
}

/// r1.2: an authority loss seen in the same tick as a normal close's
/// (already queued) answer still kills the scope.
#[test]
fn a_revocation_racing_a_queued_normal_close_answer_still_kills() {
    let mut rig = rig();
    let dir = tempfile::tempdir().unwrap();
    let credentials =
        crate::sandbox_relay::credentials::service::CredentialService::start(dir.path(), "host-1")
            .unwrap();
    credentials.install_test_env("sbx-1", "lease-1", "TOKEN", b"x");
    rig.host.set_credentials(Some(credentials.clone()));
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    wait_until("hangup answered", || control.ended().is_some());
    // The answer is queued (sent right after the close returned).
    thread::sleep(Duration::from_millis(100));
    credentials.revoke_lease("lease-1");
    let out = drive(&mut rig, |o| exits(o).iter().any(|e| e.reaped));
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::Revoked)
    );
    assert!(
        rig.fake
            .channel_scope_kills()
            .iter()
            .any(|k| k.scopes.iter().any(|s| s.unit == unit("ch-1"))),
        "the revocation upgraded the normal close"
    );
}

/// r1.4: guest chatter before READY costs tick budget like output does.
#[test]
fn setup_chatter_is_bounded_per_tick() {
    let mut rig = rig();
    let (_fence, control) = spawned(&mut rig, "ch-1", ChannelKind::Pty);
    settle(&mut rig, Duration::from_millis(30));
    for _ in 0..100 {
        control.emit(ChannelOutput::Stdout, b"chatter");
    }
    let _ = rig.host.poll().unwrap();
    assert!(
        control.queued(ChannelOutput::Stdout) >= 100 - TICK_DATA_FRAMES,
        "one tick read {} chunks",
        100 - control.queued(ChannelOutput::Stdout)
    );
}

/// r1.5: a close never waits behind queued signals, only the running one.
#[test]
fn a_close_never_waits_behind_queued_signals() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.set_signal_support(false);
    control.set_signal_delay(Duration::from_millis(400));
    for _ in 0..4 {
        let _ = signal(&mut rig, &fence, ChannelSignal::Term);
    }
    thread::sleep(Duration::from_millis(50));
    let started = Instant::now();
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    wait_until("kill close", || closes(&control) == vec!["kill"]);
    assert!(
        started.elapsed() < Duration::from_millis(1200),
        "the kill waited behind queued signals: {:?}",
        started.elapsed()
    );
    drive(&mut rig, has_exit);
}

/// r1.6: a client that exits on its own after an unproven kill still gets
/// its post-proof termination (stdin release, writer unblock).
#[test]
fn a_post_proof_termination_runs_even_after_the_client_exited() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.make_kill_uncertain();
    rig.fake.set_channel_scope_present(&unit("ch-1"), true);
    close(&mut rig, &fence, ChannelCloseIntent::Revoked);
    let mut out = drive(&mut rig, has_exit);
    control.exit_client();
    out.extend(settle(&mut rig, Duration::from_millis(250)));
    rig.fake.set_channel_scope_present(&unit("ch-1"), false);
    out.extend(drive(&mut rig, |o| exits(o).iter().any(|e| e.reaped)));
    assert_eq!(control.terminations(), 1);
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
}

/// r1.8: opens that name a live channel with a wrong fence are violations.
#[test]
fn mismatched_opens_of_a_live_channel_count_as_violations() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    let foreign = ChannelFence {
        epoch: 6,
        ..fence.clone()
    };
    for _ in 0..3 {
        assert!(open(&mut rig, &foreign, ChannelKind::Exec).is_empty());
    }
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        exit(&out).unwrap().intent,
        Some(ChannelCloseIntent::ProtocolViolation)
    );
    assert_eq!(closes(&control), vec!["kill"]);
}

/// r2.2: an idle proof counts only for a stream found empty in this tick; a
/// stream the tick's budget could not reach keeps its queued output. Both
/// variants run (data on one stream, EOF on the other): whichever stream the
/// round robin reads first, one variant leaves the data stream unread.
#[test]
fn an_unread_stream_never_keeps_a_stale_idle_proof() {
    for (data_stream, eof_stream) in [
        (ChannelOutput::Stdout, ChannelOutput::Stderr),
        (ChannelOutput::Stderr, ChannelOutput::Stdout),
    ] {
        let mut rig = rig();
        let (_p1, p1) = opened(&mut rig, "p1", ChannelKind::Pty);
        let (_p2, p2) = opened(&mut rig, "p2", ChannelKind::Pty);
        let (_fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
        control.exit_holding(ChannelExitStatus::Code(0));
        // Draining, both streams proven idle now.
        settle(&mut rig, Duration::from_millis(30));
        // The pty channels (first in every tick) take 15 of the 16 reads.
        emit_n(&p1, ChannelOutput::Stdout, 8);
        emit_n(&p2, ChannelOutput::Stdout, 7);
        control.emit(data_stream, b"late");
        control.eof(eof_stream);
        rig.host.advance(EXIT_DRAIN + IDLE_PROOF);
        let first = outs(rig.host.poll().unwrap());
        assert!(!has_exit(&first), "a stale idle proof ended the drain");
        let mut out = first;
        out.extend(drive(&mut rig, |o| {
            exits(o).iter().any(|e| e.fence.channel_id == "ch-1")
        }));
        let late: Vec<u8> = out
            .iter()
            .filter_map(|o| match o {
                Out::Binary(frame) => {
                    let (meta, body) = parse_channel_frame(frame).unwrap().unwrap();
                    (meta.fence.channel_id == "ch-1").then_some(body)
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(late, b"late", "{data_stream:?}");
    }
}

/// r2.3: the absolute deadline also kills a normal close that is still
/// settling (owner rule).
#[test]
fn the_deadline_upgrades_an_unsettled_normal_close() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.make_unreaped();
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    let out = drive(&mut rig, has_exit);
    assert!(!exit(&out).unwrap().reaped);
    assert!(rig.fake.channel_scope_kills().is_empty());
    rig.host.advance(sandbox_runtime::PTY_MAX_SESSION);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !rig
        .fake
        .channel_scope_kills()
        .iter()
        .any(|k| k.scopes.iter().any(|s| s.unit == unit("ch-1")))
    {
        assert!(Instant::now() < deadline, "no deadline kill");
        let _ = rig.host.poll().unwrap();
        thread::sleep(Duration::from_millis(2));
    }
    control.reap();
    drive(&mut rig, |o| exits(o).iter().any(|e| e.reaped));
}

/// r2.3: the custodian's own deadline rule upgrades it too, with the owner
/// silent.
#[test]
fn the_custodian_deadline_upgrades_an_unsettled_normal_close() {
    let mut rig = rig_until(now_ms() + 1_000);
    let dir = tempfile::tempdir().unwrap();
    let credentials =
        crate::sandbox_relay::credentials::service::CredentialService::start(dir.path(), "host-1")
            .unwrap();
    credentials.install_test_env("sbx-1", "lease-1", "TOKEN", b"x");
    rig.host.set_credentials(Some(credentials));
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.make_unreaped();
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    drive(&mut rig, has_exit);
    // No tick from here on: only the custodian can act.
    wait_until("custodian deadline kill", || {
        rig.fake
            .channel_scope_kills()
            .iter()
            .any(|k| k.scopes.iter().any(|s| s.unit == unit("ch-1")))
    });
    control.reap();
    drive(&mut rig, |o| exits(o).iter().any(|e| e.reaped));
    assert!(rig.slots.wait_idle(Duration::from_secs(5)));
}

/// r3.1: a normal close still settling at the deadline is killed even when
/// its settled update is already queued for the owner.
#[test]
fn the_deadline_wins_over_a_queued_settlement() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.make_unreaped();
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    let out = drive(&mut rig, has_exit);
    assert!(!exit(&out).unwrap().reaped);
    // The client is reaped: the custodian queues the settled update; the
    // owner reads it only after its deadline passed.
    control.reap();
    thread::sleep(Duration::from_millis(300));
    rig.host.advance(sandbox_runtime::PTY_MAX_SESSION);
    let out = drive(&mut rig, |o| exits(o).iter().any(|e| e.reaped));
    assert!(!out.is_empty());
    assert!(
        rig.fake
            .channel_scope_kills()
            .iter()
            .any(|k| k.scopes.iter().any(|s| s.unit == unit("ch-1"))),
        "survivors outlived the deadline"
    );
}

/// r3.2: a channel id still settling from an earlier connection is never
/// admitted again (process-wide reservation), before or after its registry
/// entry exists.
#[test]
fn a_unit_still_settling_across_a_reconnect_is_never_admitted_twice() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.make_kill_uncertain();
    rig.fake.set_channel_scope_present(&unit("ch-1"), true);
    // Relay loss: the old custodian kills (unproven) and keeps settling.
    let Rig {
        dir,
        fake,
        journal,
        slots,
        registry,
        host,
    } = rig;
    drop(host);
    wait_until("old kill ran", || closes(&control) == vec!["kill"]);
    let mut host = ChannelHost::new(
        slots.clone(),
        registry.clone(),
        Arc::new(fake.clone()),
        journal.clone(),
        HostAuthority::with_journal(journal.clone()),
        "host-1".into(),
    );
    host.enable(6, binding(), true);
    let mut rig = Rig {
        dir,
        fake,
        journal,
        slots,
        registry,
        host,
    };
    let again = ChannelFence {
        epoch: 6,
        ..fence.clone()
    };
    let out = open(&mut rig, &again, ChannelKind::Exec);
    assert_eq!(refusal(&out), code(SandboxErrorCode::StateConflict));
    // Settled: the id is free again.
    rig.fake.set_channel_scope_present(&unit("ch-1"), false);
    assert!(rig.slots.wait_idle(Duration::from_secs(5)));
    assert!(open(&mut rig, &again, ChannelKind::Exec).is_empty());
    drive(&mut rig, |o| ready(o).is_some());
}

#[test]
fn slots_reserve_a_unit_until_the_slot_drops() {
    let slots = Arc::new(ChannelSlots::default());
    let now = Instant::now();
    let held = slots.try_acquire(false, "a", Some("u"), now).unwrap();
    assert_eq!(
        slots.try_acquire(false, "b", Some("u"), now).unwrap_err(),
        SlotRefusal::InUse
    );
    drop(slots.try_acquire(false, "a", Some("v"), now).unwrap());
    drop(held);
    drop(slots.try_acquire(false, "a", Some("u"), now).unwrap());
}

// ------------------------------- v3: crossings during a socket flush ----
//
// A tick only queues its frames; the socket writes follow once it has
// decided everything. Every former site where a blocking write separated a
// check from the action it guards is crossed here during the flush
// instead: a deadline or a revocation lands while a hooked write
// "blocks". What the tick decided
// before it stands; the next tick acts on the crossing before anything else.

/// Polls (bounded, r6.4) until a flush writes a frame matching `on`, then
/// runs `cross` right there, as if that write blocked across it. Every
/// write checks that the tick has finished deciding. Returns everything
/// these polls wrote.
fn cross_during_flush(
    rig: &mut Rig,
    mut on: impl FnMut(&Out) -> bool,
    mut cross: impl FnMut(),
) -> Vec<Out> {
    let ticking = rig.host.ticking_handle();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crossed = false;
    let mut out = Vec::new();
    while !crossed {
        assert!(
            Instant::now() < deadline,
            "the hooked write never happened: {out:?}"
        );
        rig.host
            .poll_with(&mut |frame| {
                assert!(
                    !ticking.load(std::sync::atomic::Ordering::SeqCst),
                    "a socket write inside the tick"
                );
                let frame = Out::from(frame);
                if !crossed && on(&frame) {
                    crossed = true;
                    cross();
                }
                out.push(frame);
                Ok(())
            })
            .unwrap();
        if !crossed {
            thread::sleep(Duration::from_millis(2));
        }
    }
    out
}

/// The crossing: the channels' absolute deadline passes.
fn past_the_deadline(rig: &Rig) -> impl FnMut() + use<> {
    let clock = rig.host.clock_handle();
    move || {
        clock.fetch_add(
            sandbox_runtime::PTY_MAX_SESSION.as_millis() as u64,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

/// A credential lease the channels opened from now on depend on.
fn leased(
    rig: &mut Rig,
) -> (
    tempfile::TempDir,
    crate::sandbox_relay::credentials::service::CredentialService,
) {
    let dir = tempfile::tempdir().unwrap();
    let credentials =
        crate::sandbox_relay::credentials::service::CredentialService::start(dir.path(), "host-1")
            .unwrap();
    credentials.install_test_env("sbx-1", "lease-1", "TOKEN", b"x");
    rig.host.set_credentials(Some(credentials.clone()));
    (dir, credentials)
}

/// The scope of `channel` was killed: by a kill close of its custody, or
/// by a scope kill (an upgrade of a settling normal close or natural end).
fn killed(rig: &Rig, channel: &str) -> bool {
    closes(&control(rig, channel)).contains(&"kill")
        || rig
            .fake
            .channel_scope_kills()
            .iter()
            .any(|k| k.scopes.iter().any(|s| s.unit == unit(channel)))
}

fn exit_of(out: &[Out], channel: &str) -> Option<Exit> {
    exits(out)
        .into_iter()
        .find(|e| e.fence.channel_id == channel)
}

fn is_ready_of(o: &Out, channel: &str) -> bool {
    matches!(o, Out::Text(DaemonControlMessage::ChannelReady { fence, .. }) if fence.channel_id == channel)
}

/// The bodies of `channel`'s output frames, in order.
fn bodies_of(out: &[Out], channel: &str) -> Vec<Vec<u8>> {
    out.iter()
        .filter_map(|o| match o {
            Out::Binary(frame) => {
                let (meta, body) = parse_channel_frame(frame).unwrap().unwrap();
                (meta.fence.channel_id == channel).then_some(body)
            }
            _ => None,
        })
        .collect()
}

/// A pty channel's output frame is being written when the crossing lands; a
/// starting exec channel handed its preamble over in that tick (the fake
/// guest queues READY). The next tick ends it before READY is read.
fn starting_across_a_flush(rig: &mut Rig, cross: impl FnMut()) -> Exit {
    let (_shell, shell) = opened(rig, "shell", ChannelKind::Pty);
    let (_fence, starting) = spawned(rig, "starting", ChannelKind::Exec);
    // PROMPT read (the frame stream is drained only once the IO is the
    // owner's), the host side not ready for input yet.
    let deadline = Instant::now() + Duration::from_secs(10);
    while starting.queued(ChannelOutput::Stderr) > 0 {
        assert!(Instant::now() < deadline, "PROMPT never read");
        let _ = rig.host.poll().unwrap();
        thread::sleep(Duration::from_millis(2));
    }
    let _ = rig.host.poll().unwrap();
    assert!(!starting.started());
    shell.emit(ChannelOutput::Stdout, b"output");
    starting.set_input_ready(true);
    let mut out = cross_during_flush(rig, |o| matches!(o, Out::Binary(_)), cross);
    assert!(
        starting.started(),
        "the go was decided in the hooked tick, before the crossing"
    );
    out.extend(drive(rig, |o| exit_of(o, "starting").is_some()));
    assert!(
        !out.iter().any(|o| is_ready_of(o, "starting")),
        "READY accepted after the crossing: {out:?}"
    );
    wait_until("starting killed", || killed(rig, "starting"));
    exit_of(&out, "starting").unwrap()
}

/// v2 r1.3: a revocation during an earlier write of the tick.
#[test]
fn a_revocation_during_a_flush_ends_a_starting_channel_before_ready() {
    let mut rig = rig();
    let (_dir, credentials) = leased(&mut rig);
    let exit = starting_across_a_flush(&mut rig, move || credentials.revoke_lease("lease-1"));
    assert_eq!(exit.intent, Some(ChannelCloseIntent::Revoked));
}

/// v2 r6.3: the setup deadline passes during an earlier write of the tick.
#[test]
fn a_setup_deadline_crossed_during_a_flush_refuses_a_late_ready() {
    let mut rig = rig();
    let clock = rig.host.clock_handle();
    let exit = starting_across_a_flush(&mut rig, move || {
        clock.fetch_add(
            SETUP_DEADLINE.as_millis() as u64,
            std::sync::atomic::Ordering::SeqCst,
        );
    });
    assert_eq!(exit.intent, None);
    assert_eq!(
        exit.error.map(|e| e.code),
        Some(code(SandboxErrorCode::Timeout))
    );
}

/// v2 r6.1: READY and workload data in one read; the `channel.ready` write
/// crosses the deadline. The data was decided with READY, before it; the
/// next tick kills, and nothing read after the crossing is sent.
#[test]
fn ready_and_data_written_across_the_deadline() {
    let mut rig = rig();
    let (_fence, control) = spawned(&mut rig, "ch-1", ChannelKind::Exec);
    settle(&mut rig, Duration::from_millis(30));
    control.set_input_ready(true);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !control.started() {
        assert!(Instant::now() < deadline, "preamble never handed over");
        assert!(ready(&outs(rig.host.poll().unwrap())).is_none());
    }
    // READY (queued by the fake guest) and data in one stderr read.
    control.emit(ChannelOutput::Stderr, b"early");
    control.coalesce(ChannelOutput::Stderr);
    assert_eq!(control.queued(ChannelOutput::Stderr), 1);
    let crossing = past_the_deadline(&rig);
    let mut out = cross_during_flush(&mut rig, |o| is_ready_of(o, "ch-1"), crossing);
    assert_eq!(bodies_of(&out, "ch-1"), vec![b"early".to_vec()], "{out:?}");
    control.emit(ChannelOutput::Stdout, b"late");
    out.extend(drive(&mut rig, |o| exit_of(o, "ch-1").is_some()));
    assert_eq!(bodies_of(&out, "ch-1"), vec![b"early".to_vec()], "{out:?}");
    assert_eq!(
        exit_of(&out, "ch-1").unwrap().intent,
        Some(ChannelCloseIntent::Expired)
    );
    wait_until("deadline kill", || killed(&rig, "ch-1"));
}

/// Stdin admitted but not yet handed over (the guest's stdin is
/// full) when a revocation lands during a flush is never handed over: the
/// next tick checks before it writes stdin.
#[test]
fn stdin_is_never_handed_over_after_a_flush_revocation() {
    let mut rig = rig();
    let (_dir, credentials) = leased(&mut rig);
    let (_shell, shell) = opened(&mut rig, "shell", ChannelKind::Pty);
    let (fence, exec) = opened(&mut rig, "exec", ChannelKind::Exec);
    // The workload stops reading: its stdin fills, then one more frame
    // stays admitted and unwritten.
    exec.hold_stdin(true);
    for seq in 0..32 {
        input(&mut rig, &fence, seq, b"x");
    }
    drive(&mut rig, |o| stdin_acks(o).len() == 32);
    input(&mut rig, &fence, 32, b"late");
    // The pty (first in the tick) writes output; the late frame is refused
    // by the full stdin in the same tick.
    shell.emit(ChannelOutput::Stdout, b"output");
    let mut out = cross_during_flush(
        &mut rig,
        |o| matches!(o, Out::Binary(_)),
        move || credentials.revoke_lease("lease-1"),
    );
    assert!(stdin_acks(&out).is_empty(), "{out:?}");
    // The workload reads again: the next tick could hand the frame over.
    exec.hold_stdin(false);
    assert_eq!(exec.stdin(), vec![b'x'; 32]);
    out.extend(drive(&mut rig, |o| exit_of(o, "exec").is_some()));
    assert_eq!(
        exec.stdin(),
        vec![b'x'; 32],
        "stdin handed over after the revocation"
    );
    assert_eq!(
        exit_of(&out, "exec").unwrap().intent,
        Some(ChannelCloseIntent::Revoked)
    );
}

/// A failed flush write ends the poll at once (the session ends with it);
/// the tick's decisions were all made before, and nothing more is written.
#[test]
fn a_failed_flush_write_ends_the_poll_after_the_tick_decided() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    let ticking = rig.host.ticking_handle();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut writes = 0;
    loop {
        assert!(Instant::now() < deadline, "nothing was ever written");
        let result = rig.host.poll_with(&mut |_frame| {
            assert!(!ticking.load(std::sync::atomic::Ordering::SeqCst));
            writes += 1;
            Err(anyhow::anyhow!("relay socket write failed"))
        });
        if writes > 0 {
            assert!(result.is_err());
            break;
        }
        result.unwrap();
        thread::sleep(Duration::from_millis(2));
    }
    // One write was tried (the first eof); the exit and the release were
    // decided in that tick all the same (a normal close's survivors are
    // meant to survive), so the custody is done.
    assert_eq!(writes, 1);
    assert!(rig.slots.wait_idle(Duration::from_secs(5)));
    assert_eq!(closes(&control), vec!["hangup"]);
    assert!(!killed(&rig, "ch-1"));
}

/// An unsettled normal close's exit write crosses the
/// deadline or a revocation while the settlement is queued: the next tick
/// sees the crossing before it consumes the settlement, so the scope is
/// killed and released only after the kill's answer.
fn a_settlement_after_a_flush_crossing_still_kills(revoke: bool) {
    let mut rig = rig();
    let lease = revoke.then(|| leased(&mut rig));
    let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
    control.make_unreaped();
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    let deadline = past_the_deadline(&rig);
    let mut crossing: Box<dyn FnMut()> = match &lease {
        Some((_, credentials)) => {
            let credentials = credentials.clone();
            Box::new(move || credentials.revoke_lease("lease-1"))
        }
        None => Box::new(deadline),
    };
    let settler = control.clone();
    let mut out = cross_during_flush(
        &mut rig,
        |o| exit_of(std::slice::from_ref(o), "ch-1").is_some_and(|e| !e.reaped),
        move || {
            crossing();
            // The client is reaped while the write "blocks": the settled
            // update is queued before the next tick.
            settler.reap();
        },
    );
    wait_until("settled update", || {
        control.ended().is_some_and(|e| e.reaped)
    });
    out.extend(drive(&mut rig, |o| exits(o).iter().any(|e| e.reaped)));
    assert!(killed(&rig, "ch-1"), "the crossing never upgraded: {out:?}");
    assert!(rig.slots.wait_idle(Duration::from_secs(5)));
}

#[test]
fn a_settlement_after_a_deadline_crossed_in_a_flush_still_kills() {
    a_settlement_after_a_flush_crossing_still_kills(false);
}

#[test]
fn a_settlement_after_a_revocation_in_a_flush_still_kills() {
    a_settlement_after_a_flush_crossing_still_kills(true);
}

/// v2 r5.1: a settled normal close's eof or exit write crosses the
/// deadline. The release (`Done`) was decided before it, in the tick that
/// consumed the settlement, so it stands: no kill, one settled exit.
#[test]
fn a_release_decided_before_a_flush_crossing_stands() {
    for on in [
        (|o: &Out| matches!(o, Out::Text(DaemonControlMessage::ChannelEof { .. })))
            as fn(&Out) -> bool,
        |o: &Out| matches!(o, Out::Text(DaemonControlMessage::ChannelExit { .. })),
    ] {
        let mut rig = rig();
        let (fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
        close(&mut rig, &fence, ChannelCloseIntent::Client);
        let crossing = past_the_deadline(&rig);
        let mut out = cross_during_flush(&mut rig, on, crossing);
        assert!(rig.slots.wait_idle(Duration::from_secs(5)), "{out:?}");
        out.extend(settle(&mut rig, Duration::from_millis(50)));
        let all = exits(&out);
        assert_eq!(all.len(), 1, "{out:?}");
        assert!(all[0].reaped);
        assert_eq!(all[0].intent, Some(ChannelCloseIntent::Client));
        assert_eq!(eofs(&out).len(), 2);
        assert!(exit_index(&out) > 1);
        assert_eq!(closes(&control), vec!["hangup"]);
        assert!(!killed(&rig, "ch-1"));
    }
}

/// v2 r6.2: the last output EOF write crosses the deadline or a revocation.
/// The natural end (`Finish`) was decided before it; the next tick upgrades
/// the still-settling end to a kill (contract: the deadline and authority
/// losses also kill a natural end that is still settling), and the
/// wrapper's status stands.
#[test]
fn a_natural_end_decided_before_a_flush_crossing_is_killed_next_tick() {
    for revoke in [false, true] {
        let mut rig = rig();
        let lease = revoke.then(|| leased(&mut rig));
        let (_fence, control) = opened(&mut rig, "ch-1", ChannelKind::Exec);
        control.make_unreaped();
        control.exit(ChannelExitStatus::Code(0));
        let deadline = past_the_deadline(&rig);
        let crossing: Box<dyn FnMut()> = match &lease {
            Some((_, credentials)) => {
                let credentials = credentials.clone();
                Box::new(move || credentials.revoke_lease("lease-1"))
            }
            None => Box::new(deadline),
        };
        let mut seen = 0;
        let mut out = cross_during_flush(
            &mut rig,
            |o| {
                seen += usize::from(matches!(
                    o,
                    Out::Text(DaemonControlMessage::ChannelEof { .. })
                ));
                seen == 2
            },
            crossing,
        );
        assert!(!has_exit(&out), "{out:?}");
        // The custodian runs the orders in turn: the finish (ordered in the
        // hooked tick), then the kill.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !(closes(&control).first() == Some(&"finish") && killed(&rig, "ch-1")) {
            assert!(Instant::now() < deadline, "no finish, then kill: {out:?}");
            out.extend(outs(rig.host.poll().unwrap()));
            thread::sleep(Duration::from_millis(2));
        }
        control.reap();
        out.extend(drive(&mut rig, |o| exits(o).iter().any(|e| e.reaped)));
        let exit = exit(&out).unwrap();
        assert_eq!(exit.exit_code, Some(0), "{out:?}");
        assert_eq!(
            exit.intent,
            Some(if revoke {
                ChannelCloseIntent::Revoked
            } else {
                ChannelCloseIntent::Expired
            })
        );
        assert!(killed(&rig, "ch-1"));
    }
}

/// By construction, the setup deadline passes while
/// another channel's authority lookup waits (on a journal or credential
/// lock) in the tick's gather phase. The tick's one clock read follows every
/// lookup, so a starting channel with READY waiting in its pipe is ended by
/// the setup rule, never moved to Running.
#[test]
fn a_setup_deadline_crossed_during_a_lookup_wait_refuses_ready() {
    let mut rig = rig();
    let (_shell, _shell_control) = opened(&mut rig, "shell", ChannelKind::Pty);
    let (_fence, starting) = spawned(&mut rig, "starting", ChannelKind::Exec);
    let deadline = Instant::now() + Duration::from_secs(10);
    while starting.queued(ChannelOutput::Stderr) > 0 {
        assert!(Instant::now() < deadline, "PROMPT never read");
        let _ = rig.host.poll().unwrap();
        thread::sleep(Duration::from_millis(2));
    }
    let _ = rig.host.poll().unwrap();
    // One tick hands the preamble over; the fake guest queues READY, read
    // only in the next tick.
    starting.set_input_ready(true);
    let mut out = outs(rig.host.poll().unwrap());
    assert!(starting.started());
    assert_eq!(starting.queued(ChannelOutput::Stderr), 1);
    // Next tick: the pty's lookup in the gather "waits" across the setup
    // deadline.
    let clock = rig.host.clock_handle();
    let mut shell_lookups = 0;
    rig.host
        .set_check_hook(Some(Box::new(move |fence: &ChannelFence| {
            if fence.channel_id == "shell" {
                shell_lookups += 1;
                if shell_lookups == 1 {
                    clock.fetch_add(
                        SETUP_DEADLINE.as_millis() as u64,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                }
            }
        })));
    out.extend(outs(rig.host.poll().unwrap()));
    rig.host.set_check_hook(None);
    out.extend(drive(&mut rig, |o| exit_of(o, "starting").is_some()));
    assert!(
        !out.iter().any(|o| is_ready_of(o, "starting")),
        "READY accepted past the setup deadline: {out:?}"
    );
    let exit = exit_of(&out, "starting").unwrap();
    assert_eq!(
        exit.error.map(|e| e.code),
        Some(code(SandboxErrorCode::Timeout))
    );
}

// ---------------------------------------------------------------- relay ----

fn relay_message(
    fence: &ChannelFence,
    port: Option<u16>,
    path: Option<&str>,
) -> ServerControlMessage {
    ServerControlMessage::ChannelOpen {
        fence: fence.clone(),
        kind: if path.is_some() {
            ChannelKind::Unix
        } else {
            ChannelKind::Tcp
        },
        argv: None,
        login: false,
        cwd: None,
        env: None,
        pty: None,
        port,
        path: path.map(str::to_string),
    }
}

/// Open a tcp relay to guest port 5432 and wait for `channel.ready`.
fn relay(rig: &mut Rig, channel: &str) -> (ChannelFence, FakeChannelControl) {
    let fence = fence(channel);
    assert!(send(rig, relay_message(&fence, Some(5432), None)).is_empty());
    let out = drive(rig, |o| ready(o).is_some());
    assert_eq!(ready(&out), Some(None), "a relay's ready has no size");
    (fence, control(rig, channel))
}

#[test]
fn the_node_offers_the_relay_kinds() {
    let rig = rig();
    assert_eq!(
        capability(rig.host.runtime.as_ref()).unwrap().kinds,
        vec![
            ChannelKind::Pty,
            ChannelKind::Exec,
            ChannelKind::Tcp,
            ChannelKind::Unix
        ]
    );
}

#[test]
fn a_tcp_relay_round_trips_and_half_closes_into_a_natural_end() {
    let mut rig = rig();
    // Login values are installed for the sandbox: a relay never gets them.
    let dir = tempfile::tempdir().unwrap();
    let credentials =
        crate::sandbox_relay::credentials::service::CredentialService::start(dir.path(), "host-1")
            .unwrap();
    credentials.install_test_env("sbx-1", "lease-1", "TOKEN", b"secret-value");
    rig.host.set_credentials(Some(credentials.clone()));
    let (fence, control) = relay(&mut rig, "ch-1");
    assert_eq!(
        control.env(),
        Some(Vec::new()),
        "a relay gets no environment"
    );
    input(&mut rig, &fence, 0, b"hello ");
    input(&mut rig, &fence, 1, b"guest");
    let out = drive(&mut rig, |o| data(o).len() == 2 && stdin_acks(o).len() == 2);
    assert_eq!(
        data(&out),
        vec![
            (ChannelStream::Stdout, 0, b"hello ".to_vec()),
            (ChannelStream::Stdout, 1, b"guest".to_vec()),
        ]
    );
    assert_eq!(control.stdin(), b"hello guest");
    stdin_eof(&mut rig, &fence, 2);
    let out = drive(&mut rig, has_exit);
    // The echo service closed too: its eof first, then the natural exit.
    assert_eq!(eofs(&out), vec![(ChannelStream::Stdout, 2)]);
    assert_eq!(exit_index(&out), out.len() - 1);
    let exit = exit(&out).unwrap();
    assert_eq!(
        (exit.exit_code, exit.intent, exit.error, exit.frames),
        (Some(0), None, None, (2, 0))
    );
    assert!(exit.reaped);
    assert_eq!(closes(&control), vec!["finish"]);
    // A revoked login never touches a relay that carries none.
    credentials.revoke_lease("lease-1");
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
}

#[test]
fn a_guest_write_shutdown_travels_while_input_still_flows() {
    let mut rig = rig();
    let (fence, control) = relay(&mut rig, "ch-1");
    control.set_echo(false);
    control.relay_emit(b"220 ready\r\n");
    control.relay_eof();
    let out = drive(&mut rig, |o| !eofs(o).is_empty());
    assert_eq!(
        data(&out),
        vec![(ChannelStream::Stdout, 0, b"220 ready\r\n".to_vec())]
    );
    assert_eq!(eofs(&out), vec![(ChannelStream::Stdout, 1)]);
    // The other direction is still open.
    input(&mut rig, &fence, 0, b"QUIT\r\n");
    let out = drive(&mut rig, |o| stdin_acks(o) == vec![0]);
    assert!(!has_exit(&out));
    assert_eq!(control.stdin(), b"QUIT\r\n");
    stdin_eof(&mut rig, &fence, 1);
    drive(&mut rig, |_| control.stdin_closed());
    control.relay_done();
    let out = drive(&mut rig, has_exit);
    assert!(eofs(&out).is_empty(), "one stdout eof only");
    assert_eq!(exit(&out).unwrap().exit_code, Some(0));
}

#[test]
fn a_relay_reset_ends_without_an_eof() {
    let mut rig = rig();
    let (fence, control) = relay(&mut rig, "ch-1");
    control.set_echo(false);
    control.relay_emit(b"partial");
    control.relay_reset();
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        data(&out),
        vec![(ChannelStream::Stdout, 0, b"partial".to_vec())]
    );
    assert!(eofs(&out).is_empty(), "a reset sends no eof: {out:?}");
    let exit = exit(&out).unwrap();
    assert_eq!(exit.fence, fence);
    assert_eq!((exit.exit_code, exit.intent), (Some(1), None));
    assert_eq!(exit.frames, (1, 0));
}

#[test]
fn a_relay_reset_after_the_guest_eof_is_reported_in_the_exit() {
    // The guest service shut its write side, then reset while input still
    // flowed: the helper's `R` after its `E` is read and the exit says 1.
    let mut rig = rig();
    let (fence, control) = relay(&mut rig, "ch-1");
    control.set_echo(false);
    control.relay_emit(b"220 bye\r\n");
    control.relay_eof();
    let out = drive(&mut rig, |o| !eofs(o).is_empty());
    assert_eq!(eofs(&out), vec![(ChannelStream::Stdout, 1)]);
    input(&mut rig, &fence, 0, b"MAIL FROM");
    let out = drive(&mut rig, |o| stdin_acks(o) == vec![0]);
    assert!(!has_exit(&out));
    control.relay_reset();
    let out = drive(&mut rig, has_exit);
    assert!(eofs(&out).is_empty(), "one stdout eof only: {out:?}");
    let exit = exit(&out).unwrap();
    assert_eq!(
        (exit.exit_code, exit.intent, exit.error, exit.frames),
        (Some(1), None, None, (1, 0)),
        "a reset, not a framing error and not a clean end"
    );
    assert_eq!(closes(&control), vec!["finish"]);
}

#[test]
fn an_eof_and_a_reset_in_one_read_send_the_eof_then_a_failed_exit() {
    let mut rig = rig();
    let (_fence, control) = relay(&mut rig, "ch-1");
    control.set_echo(false);
    control.relay_emit(b"bye");
    control.emit(ChannelOutput::Stdout, b"ER");
    control.coalesce(ChannelOutput::Stdout);
    // A helper that claims a clean end after its reset is still a reset.
    control.exit(ChannelExitStatus::Code(0));
    let out = drive(&mut rig, has_exit);
    assert_eq!(
        data(&out),
        vec![(ChannelStream::Stdout, 0, b"bye".to_vec())]
    );
    assert_eq!(eofs(&out), vec![(ChannelStream::Stdout, 1)]);
    let exit = exit(&out).unwrap();
    assert_eq!((exit.exit_code, exit.error), (Some(1), None));
}

#[test]
fn a_reset_read_after_the_eof_overrides_a_clean_exit_code() {
    // The `R` arrives in a later read than the `E`: stdout is still read
    // after the eof, so even a helper claiming exit 0 is reported as 1.
    let mut rig = rig();
    let (_fence, control) = relay(&mut rig, "ch-1");
    control.set_echo(false);
    control.relay_eof();
    let out = drive(&mut rig, |o| !eofs(o).is_empty());
    assert!(!has_exit(&out));
    control.emit(ChannelOutput::Stdout, b"R");
    control.exit(ChannelExitStatus::Code(0));
    let out = drive(&mut rig, has_exit);
    let exit = exit(&out).unwrap();
    assert_eq!((exit.exit_code, exit.error), (Some(1), None));
}

#[test]
fn a_relay_exit_zero_without_the_guest_eof_is_not_clean() {
    let mut rig = rig();
    let (_fence, control) = relay(&mut rig, "ch-1");
    control.set_echo(false);
    control.relay_emit(b"half");
    control.exit(ChannelExitStatus::Code(0));
    let out = drive(&mut rig, has_exit);
    assert!(eofs(&out).is_empty());
    assert_eq!(exit(&out).unwrap().exit_code, Some(1));
}

#[test]
fn a_refused_connect_exits_before_ready_without_a_kill() {
    for (failure, expected) in [
        (
            sandbox_runtime::RelayFailure::Refused,
            SandboxErrorCode::ConnectionRefused,
        ),
        (
            sandbox_runtime::RelayFailure::Denied,
            SandboxErrorCode::GuestPermissionDenied,
        ),
        (
            sandbox_runtime::RelayFailure::Failed,
            SandboxErrorCode::GuestOperationFailed,
        ),
    ] {
        let mut rig = rig();
        rig.fake.refuse_channel_connect(Some(failure));
        let fence = fence("ch-1");
        assert!(send(&mut rig, relay_message(&fence, Some(6000), None)).is_empty());
        let out = drive(&mut rig, has_exit);
        assert!(ready(&out).is_none(), "{out:?}");
        assert_eq!(refusal(&out), code(expected));
        // The secret-bound FAILED proves the helper ran inside its scope: a
        // normal finish, no scope kill and no tombstone left behind.
        let control = control(&rig, "ch-1");
        assert_eq!(closes(&control), vec!["finish"]);
        assert!(rig.fake.channel_scope_kills().is_empty());
        assert!(rig.slots.wait_idle(Duration::from_secs(2)));
        assert!(!registry_file(&rig, "ch-1").exists());
    }
}

#[test]
fn every_relay_close_is_a_kill_and_signals_and_resizes_are_refused() {
    let mut rig = rig();
    let (fence, control) = relay(&mut rig, "ch-1");
    assert_eq!(
        notices(&signal(&mut rig, &fence, ChannelSignal::Term)),
        vec![ChannelNotice::UnsupportedSignal]
    );
    let out = send(
        &mut rig,
        ServerControlMessage::ChannelResize {
            fence: fence.clone(),
            rows: 10,
            cols: 10,
        },
    );
    assert_eq!(notices(&out), vec![ChannelNotice::StateConflict]);
    // A client close is a reset: the relay's scope is killed, not hung up.
    close(&mut rig, &fence, ChannelCloseIntent::Client);
    let out = drive(&mut rig, has_exit);
    let exit = exit(&out).unwrap();
    assert_eq!(exit.intent, Some(ChannelCloseIntent::Client));
    assert_eq!(closes(&control), vec!["kill"]);
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
}

#[test]
fn a_unix_relay_reaches_its_path_and_the_target_is_the_only_parameter() {
    let mut rig = rig();
    let first = fence("ch-1");
    assert!(send(&mut rig, relay_message(&first, None, Some("/run/app.sock"))).is_empty());
    drive(&mut rig, |o| ready(o).is_some());
    let control = control(&rig, "ch-1");
    assert_eq!(control.argv(), None);
    assert!(!control.login());
    assert_eq!(control.cwd(), None);
    // Process fields on a relay (the wire refuses them too) never spawn.
    let bad = fence("ch-2");
    let out = send(
        &mut rig,
        ServerControlMessage::ChannelOpen {
            fence: bad.clone(),
            kind: ChannelKind::Tcp,
            argv: None,
            login: false,
            cwd: None,
            env: None,
            pty: None,
            port: None,
            path: Some("/run/app.sock".into()),
        },
    );
    assert_eq!(refusal(&out), code(SandboxErrorCode::ProtocolError));
    assert!(rig.fake.channel_control("sbx-1", CONN, "ch-2").is_none());
}

#[test]
fn relay_output_waits_for_credit_and_counts_against_the_bulk_caps() {
    let mut rig = rig();
    let (fence, control) = relay(&mut rig, "ch-1");
    control.set_echo(false);
    for i in 0..40 {
        control.relay_emit(format!("frame {i}").as_bytes());
    }
    let out = drive(&mut rig, |o| data(o).len() == 32);
    assert_eq!(data(&settle(&mut rig, Duration::from_millis(50))).len(), 0);
    assert_eq!(data(&out).len(), 32, "one bulk window");
    ack(&mut rig, &fence, ChannelStream::Stdout, 31);
    let out = drive(&mut rig, |o| data(o).len() == 8);
    assert_eq!(data(&out)[0].1, 32);
}

/// Audit M2: a completed relay stream (the helper exited) read by a slow
/// client is never cut at the 60 s drain cap while it waits only for
/// credit; every byte arrives, then the clean end.
#[test]
fn a_slow_reader_gets_a_completed_relay_stream_past_the_drain_cap() {
    let mut rig = rig();
    let (fence, control) = relay(&mut rig, "ch-1");
    control.set_echo(false);
    let mut expected = Vec::new();
    for i in 0..200 {
        let chunk = format!("frame {i};");
        expected.extend_from_slice(chunk.as_bytes());
        control.relay_emit(chunk.as_bytes());
    }
    control.relay_eof();
    control.relay_done();
    let mut all = drive(&mut rig, |o| data(o).len() >= 16);
    // A window per 20 s of node time: about 140 s after the EXIT, and no
    // frame is ever 60 s unacknowledged.
    let mut steps = 0;
    while !has_exit(&all) {
        steps += 1;
        assert!(steps < 200, "the stream never completed");
        rig.host.advance(Duration::from_secs(20));
        if let Some(last) = data(&all).last() {
            ack(&mut rig, &fence, ChannelStream::Stdout, last.1);
        }
        all.extend(drive(&mut rig, |o| !data(o).is_empty() || has_exit(o)));
    }
    assert!(steps >= 4, "the client was slower than the cap: {steps}");
    let got: Vec<u8> = data(&all)
        .into_iter()
        .flat_map(|(_, _, body)| body)
        .collect();
    assert_eq!(got, expected, "every byte, in order");
    assert_eq!(eofs(&all).len(), 1);
    let exit = exit(&all).unwrap();
    assert_eq!(
        (exit.exit_code, exit.intent, exit.error),
        (Some(0), None, None),
        "a clean end, not a cut stream"
    );
}

/// Audit M1 (node): relay channels whose clients stopped reading fill the
/// owner's share and the host cap; every other bulk channel still gets a
/// frame at a time (its reserve) instead of freezing until the stall rule.
#[test]
fn stalled_relays_never_freeze_the_other_bulk_channels() {
    let mut rig = rig();
    let mut stalled = Vec::new();
    for n in 0..2 {
        let (fence, control) = relay(&mut rig, &format!("stalled-{n}"));
        control.set_echo(false);
        stalled.push((fence, control));
    }
    for (n, (_, control)) in stalled.iter().enumerate() {
        for i in 0..40 {
            control.relay_emit(format!("{n}:{i}").as_bytes());
        }
    }
    let out = drive(&mut rig, |o| data(o).len() as u64 >= CREATOR_UNACKED_FRAMES);
    assert_eq!(data(&out).len() as u64, CREATOR_UNACKED_FRAMES);
    // The owner's share is full and nobody acknowledges it.
    let (fence, healthy) = relay(&mut rig, "healthy");
    healthy.set_echo(false);
    for i in 0..3 {
        healthy.relay_emit(format!("h{i}").as_bytes());
    }
    let senders = |out: &[Out]| -> Vec<(ChannelFence, u64)> {
        out.iter()
            .filter_map(|o| match o {
                Out::Binary(frame) => {
                    let (metadata, _) = parse_channel_frame(frame).unwrap().unwrap();
                    Some((metadata.fence, metadata.seq))
                }
                _ => None,
            })
            .collect()
    };
    // One frame at a time, each after the previous one's ack.
    for seq in 0..3 {
        let mut out = drive(&mut rig, |o| !data(o).is_empty());
        out.extend(settle(&mut rig, Duration::from_millis(30)));
        assert_eq!(senders(&out), vec![(fence.clone(), seq)], "{out:?}");
        ack(&mut rig, &fence, ChannelStream::Stdout, seq);
    }
    // The stalled ones got nothing more meanwhile.
    for (fence, _) in &stalled {
        assert!(
            senders(&settle(&mut rig, Duration::from_millis(30)))
                .iter()
                .all(|(f, _)| f != fence)
        );
    }
}
