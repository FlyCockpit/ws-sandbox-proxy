//! WP7 quiesce state machine: the pure step function, the per-connection
//! link (ack, fallback, the hello flag across a reconnect), the worker's
//! exit paths and the control file.

use super::*;
use std::sync::atomic::AtomicUsize;

const SECOND: Duration = Duration::from_secs(1);

fn timing() -> QuiesceTiming {
    QuiesceTiming::with_max(Duration::from_secs(600))
}

fn enabled() -> ShutdownSignal {
    let shutdown = ShutdownSignal::default();
    shutdown.quiesce().enable();
    shutdown
}

#[test]
fn without_an_ack_the_daemon_waits_thirty_seconds_then_falls_back() {
    let start = Instant::now();
    assert_eq!(timing().ack_wait, Duration::from_secs(30));
    // Still running work does not matter before the ack.
    assert!(matches!(
        next_step(start + 29 * SECOND, start, None, 3, timing()),
        Step::Wait(left) if left <= POLL
    ));
    assert_eq!(
        next_step(start + 30 * SECOND, start, None, 0, timing()),
        Step::Shutdown(QuiesceEnd::NoAck)
    );
}

#[test]
fn after_the_ack_it_waits_for_running_commands_then_restarts() {
    let start = Instant::now();
    let acked = start + SECOND;
    assert!(matches!(
        next_step(start + 5 * SECOND, start, Some(acked), 2, timing()),
        Step::Wait(_)
    ));
    // Nothing running, but a dispatch claimed before the hold may still be
    // on the wire: the drain is judged only after the settle.
    assert!(matches!(
        next_step(
            acked + Duration::from_millis(500),
            start,
            Some(acked),
            0,
            timing()
        ),
        Step::Wait(_)
    ));
    assert_eq!(
        next_step(acked + DRAIN_SETTLE, start, Some(acked), 0, timing()),
        Step::Shutdown(QuiesceEnd::Drained)
    );
}

#[test]
fn quiesce_max_caps_the_wait_from_the_request_and_reports_what_remains() {
    let start = Instant::now();
    let timing = QuiesceTiming::with_max(Duration::from_secs(600));
    assert_eq!(
        QuiesceTiming::with_max(Duration::from_secs(600)).max,
        Duration::from_secs(600)
    );
    assert!(matches!(
        next_step(start + 599 * SECOND, start, Some(start), 4, timing),
        Step::Wait(_)
    ));
    assert_eq!(
        next_step(start + 600 * SECOND, start, Some(start), 4, timing),
        Step::Shutdown(QuiesceEnd::Cap { remaining: 4 })
    );
}

#[test]
fn a_request_needs_the_handler_and_counts_once() {
    let state = QuiesceState::default();
    assert!(!state.request(), "no SIGUSR1 handler: nothing to quiesce");
    assert!(!state.quiescing());
    state.acknowledge();
    assert!(!state.acked(), "an ack without a request means nothing");
    state.enable();
    assert!(state.request());
    assert!(!state.request(), "a repeated SIGUSR1 is a no-op");
    assert!(state.quiescing());
}

#[test]
fn the_link_sends_host_quiesce_once_registered_and_counts_only_its_own_ack() {
    let shutdown = enabled();
    let mut link = QuiesceLink::new(&shutdown);
    assert!(QuiesceLink::capability(&shutdown));
    assert!(
        !link.hello_flag(),
        "not quiescing when this hello was built"
    );
    link.registered(&shutdown, true);
    assert!(link.poll(&shutdown, Some(7)).unwrap().is_none());
    shutdown.quiesce().request();
    // Not yet registered on this connection: nothing goes out.
    let mut unregistered = QuiesceLink::new(&shutdown);
    assert!(unregistered.poll(&shutdown, None).unwrap().is_none());
    let Some(DaemonControlMessage::HostQuiesce(frame)) = link.poll(&shutdown, Some(7)).unwrap()
    else {
        panic!("host.quiesce expected");
    };
    assert_eq!(
        frame,
        HostQuiesceV11 {
            connection_epoch: 7,
            sequence: 1
        }
    );
    assert!(
        link.poll(&shutdown, Some(7)).unwrap().is_none(),
        "sent once"
    );
    link.ack(&shutdown, 2);
    assert!(!shutdown.quiesce().acked(), "a foreign sequence is ignored");
    link.ack(&shutdown, 1);
    assert!(shutdown.quiesce().acked());
    assert!(!shutdown.requested());
}

#[test]
fn a_server_without_the_capability_gets_the_ordinary_shutdown_at_once() {
    let shutdown = enabled();
    shutdown.quiesce().request();
    let mut link = QuiesceLink::new(&shutdown);
    link.registered(&shutdown, false);
    assert!(link.poll(&shutdown, Some(1)).unwrap().is_none());
    assert!(shutdown.requested());
    assert!(!shutdown.quiesce().acked());
}

#[test]
fn a_reconnect_while_quiescing_says_so_and_its_registration_is_the_ack() {
    let shutdown = enabled();
    let mut first = QuiesceLink::new(&shutdown);
    first.registered(&shutdown, true);
    shutdown.quiesce().request();
    assert!(first.poll(&shutdown, Some(1)).unwrap().is_some());
    // The connection drops before the ack arrives: `first` is gone.
    let _ = first;
    let mut second = QuiesceLink::new(&shutdown);
    assert!(
        second.hello_flag(),
        "every reconnect hello carries quiescing"
    );
    assert!(!shutdown.quiesce().acked());
    second.registered(&shutdown, true);
    assert!(
        shutdown.quiesce().acked(),
        "the server holds from registration"
    );
    assert!(second.poll(&shutdown, Some(2)).unwrap().is_none());
    // And the next one still says so.
    assert!(QuiesceLink::new(&shutdown).hello_flag());
}

#[test]
fn a_daemon_that_cannot_quiesce_never_offers_or_sends_it() {
    let shutdown = ShutdownSignal::default();
    assert!(!QuiesceLink::capability(&shutdown));
    shutdown.quiesce().request();
    let mut link = QuiesceLink::new(&shutdown);
    assert!(!link.hello_flag());
    link.registered(&shutdown, true);
    assert!(link.poll(&shutdown, Some(1)).unwrap().is_none());
}

fn short(ack_wait: Duration, max: Duration) -> QuiesceTiming {
    QuiesceTiming {
        ack_wait,
        settle: Duration::from_millis(20),
        max,
    }
}

fn wait_for(shutdown: &ShutdownSignal, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if shutdown.requested() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    shutdown.requested()
}

#[test]
fn the_worker_restarts_once_running_commands_finish() {
    let shutdown = enabled();
    let running = Arc::new(AtomicUsize::new(2));
    let counter = running.clone();
    let _worker = QuiesceWorker::start(
        shutdown.clone(),
        short(Duration::from_secs(30), Duration::from_secs(60)),
        Box::new(move || counter.load(Ordering::SeqCst)),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert!(!shutdown.requested(), "nothing happens before a request");
    shutdown.quiesce().request();
    shutdown.quiesce().acknowledge();
    assert!(!wait_for(&shutdown, Duration::from_millis(300)));
    running.store(0, Ordering::SeqCst);
    assert!(wait_for(&shutdown, Duration::from_secs(5)));
}

#[test]
fn the_worker_falls_back_without_an_ack() {
    let shutdown = enabled();
    let _worker = QuiesceWorker::start(
        shutdown.clone(),
        short(Duration::from_millis(100), Duration::from_secs(60)),
        Box::new(|| 0),
    )
    .unwrap();
    let requested = Instant::now();
    shutdown.quiesce().request();
    assert!(wait_for(&shutdown, Duration::from_secs(5)));
    assert!(requested.elapsed() >= Duration::from_millis(100));
}

#[test]
fn the_worker_restarts_at_the_cap_with_commands_still_running() {
    let shutdown = enabled();
    let _worker = QuiesceWorker::start(
        shutdown.clone(),
        short(Duration::from_secs(30), Duration::from_millis(200)),
        Box::new(|| 1),
    )
    .unwrap();
    let requested = Instant::now();
    shutdown.quiesce().request();
    shutdown.quiesce().acknowledge();
    assert!(wait_for(&shutdown, Duration::from_secs(5)));
    assert!(requested.elapsed() >= Duration::from_millis(200));
}

#[test]
fn dropping_the_worker_stops_it_promptly_without_a_shutdown() {
    let shutdown = enabled();
    let worker = QuiesceWorker::start(shutdown.clone(), timing(), Box::new(|| 1)).unwrap();
    shutdown.quiesce().request();
    let dropped = Instant::now();
    drop(worker);
    assert!(dropped.elapsed() < Duration::from_secs(2));
    assert!(!shutdown.requested());
}

#[test]
fn start_time_is_field_22_even_with_parentheses_in_the_name() {
    let stat =
        "4242 (we ird) (x) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 3 0 987654 1000 10";
    assert_eq!(parse_start_time(stat), Some(987_654));
    assert_eq!(parse_start_time("4242 (short) S 1"), None);
    assert_eq!(parse_start_time("no parenthesis"), None);
    assert!(process_start_time(std::process::id()).is_some());
}

#[cfg(unix)]
#[test]
fn the_control_file_is_private_names_this_process_and_goes_at_exit() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let guard = ControlFileGuard::write(dir.path()).unwrap();
    let path = dir.path().join(CONTROL_FILE);
    let meta = std::fs::symlink_metadata(&path).unwrap();
    assert!(meta.is_file());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let file: ControlFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(file.pid, std::process::id());
    assert_eq!(Some(file.start_time), process_start_time(file.pid));
    assert_eq!(file.version, env!("CARGO_PKG_VERSION"));
    assert!(file.supports_quiesce());
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"startTime\""), "{text}");
    drop(guard);
    assert!(!path.exists());
}

#[test]
fn start_writes_nothing_unless_the_handler_is_registered() {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::config::Config::default();
    assert!(
        start(
            &ShutdownSignal::default(),
            dir.path(),
            &config,
            Box::new(|| 0)
        )
        .unwrap()
        .is_none()
    );
    assert!(!dir.path().join(CONTROL_FILE).exists());
    let shutdown = enabled();
    let quiesce = start(&shutdown, dir.path(), &config, Box::new(|| 0))
        .unwrap()
        .expect("enabled");
    assert!(dir.path().join(CONTROL_FILE).exists());
    drop(quiesce);
    assert!(!dir.path().join(CONTROL_FILE).exists());
}
