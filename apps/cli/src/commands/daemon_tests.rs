//! `wssp host daemon quiesce` decisions (WP7).

use super::*;
use crate::sandbox_relay::quiesce::QUIESCE_FEATURE;
use std::os::unix::fs::PermissionsExt;

fn control(pid: u32, start_time: u64) -> ControlFile {
    ControlFile {
        pid,
        start_time,
        version: "1.0.0".into(),
        features: vec![QUIESCE_FEATURE.into()],
    }
}

const MANAGED: Target = Target {
    pid: 4242,
    managed: true,
};
const MANUAL: Target = Target {
    pid: 4242,
    managed: false,
};

#[test]
fn a_verified_daemon_quiesces() {
    for target in [MANAGED, MANUAL] {
        assert_eq!(
            decide(target, Ok(Some(control(4242, 77))), Some(77), true),
            Decision::Quiesce(4242)
        );
    }
}

#[test]
fn an_older_daemon_without_a_control_file_restarts_with_sigterm() {
    let Decision::Terminate { pid, reason } = decide(MANAGED, Ok(None), Some(77), true) else {
        panic!("SIGTERM expected");
    };
    assert_eq!(pid, 4242);
    assert!(reason.contains("no daemon control file"), "{reason}");
}

#[test]
fn a_pid_mismatch_start_time_mismatch_or_missing_feature_never_gets_sigusr1() {
    let mut no_feature = control(4242, 77);
    no_feature.features = vec!["other".into()];
    for (file, live) in [
        (control(4243, 77), Some(77)),
        // A recycled pid: same number, another process.
        (control(4242, 77), Some(78)),
        // The process is gone.
        (control(4242, 77), None),
        (no_feature, Some(77)),
    ] {
        assert!(
            matches!(
                decide(MANAGED, Ok(Some(file.clone())), live, true),
                Decision::Terminate { pid: 4242, .. }
            ),
            "{file:?} {live:?}"
        );
        assert!(
            matches!(
                decide(MANUAL, Ok(Some(file)), live, true),
                Decision::Refuse(_)
            ),
            "a manual run never signals an unverified pid"
        );
    }
}

#[test]
fn an_unusable_control_file_restarts_a_managed_daemon_and_refuses_by_hand() {
    let reason = Err("`daemon.json` is a symlink; refused".to_string());
    assert!(matches!(
        decide(MANAGED, reason.clone(), Some(77), true),
        Decision::Terminate { .. }
    ));
    let Decision::Refuse(message) = decide(MANUAL, reason, Some(77), true) else {
        panic!("refusal expected");
    };
    assert!(message.contains("symlink"), "{message}");
    assert!(matches!(
        decide(MANUAL, Ok(None), Some(77), true),
        Decision::Refuse(_)
    ));
}

#[test]
fn the_target_is_mainpid_else_an_explicit_pid() {
    assert_eq!(target(Some("4242"), None), Ok(MANAGED));
    assert_eq!(target(Some("4242"), Some(4242)), Ok(MANAGED));
    assert!(target(Some("4242"), Some(5)).is_err());
    assert_eq!(target(None, Some(4242)), Ok(MANUAL));
    assert_eq!(target(Some(""), Some(4242)), Ok(MANUAL));
    let missing = target(None, None).unwrap_err();
    assert!(
        missing.contains("MAINPID") && missing.contains("--pid"),
        "{missing}"
    );
    for bad in ["0", "1", "-3", "abc"] {
        assert!(target(Some(bad), None).is_err(), "{bad}");
    }
}

fn write_private(path: &Path, file: &ControlFile) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec(file).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn read_control_refuses_symlinks_shared_modes_and_garbage() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.json");
    write_private(&real, &control(4242, 77));
    assert_eq!(read_control(&real), Ok(Some(control(4242, 77))));
    assert_eq!(read_control(&dir.path().join("absent.json")), Ok(None));

    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let error = read_control(&link).unwrap_err();
    assert!(error.contains("symlink"), "{error}");

    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = read_control(&real).unwrap_err();
    assert!(error.contains("readable by others"), "{error}");

    let garbage = dir.path().join("garbage.json");
    std::fs::write(&garbage, b"not json").unwrap();
    std::fs::set_permissions(&garbage, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_control(&garbage).is_err());

    let directory = dir.path().join("dir.json");
    std::fs::create_dir(&directory).unwrap();
    assert!(read_control(&directory).is_err());
}

#[test]
fn find_control_selects_the_file_naming_the_pid() {
    let relay = tempfile::tempdir().unwrap();
    assert_eq!(
        find_control(&relay.path().join("absent"), 1, None),
        Ok(None)
    );
    write_private(&relay.path().join("a").join(CONTROL_FILE), &control(100, 1));
    write_private(&relay.path().join("b").join(CONTROL_FILE), &control(200, 2));
    std::fs::create_dir_all(relay.path().join("c")).unwrap();
    assert_eq!(
        find_control(relay.path(), 200, Some(2)),
        Ok(Some(control(200, 2)))
    );
    assert_eq!(find_control(relay.path(), 300, None), Ok(None));
    // A symlinked control file is never followed, and is reported when no
    // usable file names the pid.
    let link_dir = relay.path().join("d");
    std::fs::create_dir_all(&link_dir).unwrap();
    std::os::unix::fs::symlink(
        relay.path().join("a").join(CONTROL_FILE),
        link_dir.join(CONTROL_FILE),
    )
    .unwrap();
    assert!(find_control(relay.path(), 100, Some(1)).is_ok_and(|f| f.is_some()));
    assert!(find_control(relay.path(), 300, None).is_err());
}

#[test]
fn without_a_pidfd_a_verified_daemon_is_restarted_never_sent_sigusr1() {
    let Decision::Terminate { reason, .. } =
        decide(MANAGED, Ok(Some(control(4242, 77))), Some(77), false)
    else {
        panic!("SIGTERM expected");
    };
    assert!(reason.contains("pidfd"), "{reason}");
    assert!(matches!(
        decide(MANUAL, Ok(Some(control(4242, 77))), Some(77), false),
        Decision::Refuse(_)
    ));
}

/// A crashed daemon's stale file naming a reused pid never
/// hides the live daemon's file, whatever the directory order.
#[test]
fn find_control_prefers_the_file_whose_start_time_matches() {
    for (stale_dir, live_dir) in [("a", "b"), ("b", "a")] {
        let relay = tempfile::tempdir().unwrap();
        write_private(
            &relay.path().join(stale_dir).join(CONTROL_FILE),
            &control(500, 10),
        );
        write_private(
            &relay.path().join(live_dir).join(CONTROL_FILE),
            &control(500, 20),
        );
        assert_eq!(
            find_control(relay.path(), 500, Some(20)),
            Ok(Some(control(500, 20)))
        );
        // No live match: a pid match is still reported (and then refused).
        assert_eq!(
            find_control(relay.path(), 500, Some(30)).map(|f| f.map(|f| f.pid)),
            Ok(Some(500))
        );
    }
}
