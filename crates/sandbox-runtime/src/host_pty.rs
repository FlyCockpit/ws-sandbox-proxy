//! Local host shell opener, separate from SandboxRuntime and guest admission.
use crate::{PtyOpenFailure, PtySession, PtySize, RuntimeError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Injected by relay tests. FakeRuntime never starts a real host shell.
pub trait HostPtyOpener: Send + Sync {
    fn open(
        &self,
        session_id: &str,
        size: PtySize,
        cancel: Arc<AtomicBool>,
    ) -> Result<PtySession, PtyOpenFailure>;
}

#[derive(Default)]
pub struct LocalHostPtyOpener {
    #[cfg(target_os = "linux")]
    registry: crate::pty::PtyRegistry,
}
impl HostPtyOpener for LocalHostPtyOpener {
    fn open(
        &self,
        session_id: &str,
        size: PtySize,
        cancel: Arc<AtomicBool>,
    ) -> Result<PtySession, PtyOpenFailure> {
        crate::validate_session_id(session_id)?;
        if cancel.load(Ordering::Acquire) {
            return Err(RuntimeError::new(
                sandbox_protocol::SandboxErrorCode::AccessDenied,
                "host terminal disabled",
            )
            .into());
        }
        #[cfg(target_os = "linux")]
        {
            let command = crate::host_child::terminal_command()?;
            let reservation = self.registry.reserve(session_id, "host")?;
            let pair = portable_pty::native_pty_system()
                .openpty(portable_pty::PtySize {
                    rows: size.rows(),
                    cols: size.cols(),
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|_| {
                    RuntimeError::new(
                        sandbox_protocol::SandboxErrorCode::Internal,
                        "host terminal allocation failed",
                    )
                })?;
            // The pump's cancellation flag is set by the socket policy gate before any new input.
            if cancel.load(Ordering::Acquire) {
                return Err(RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::AccessDenied,
                    "host terminal disabled",
                )
                .into());
            }
            // portable-pty creates a session/group and closes non-stdio descriptors.
            // Effective uid/gid/supplementary groups are unchanged.
            let child = pair.slave.spawn_command(command).map_err(|_| {
                RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::Internal,
                    "host terminal spawn failed",
                )
            })?;
            drop(pair.slave);
            crate::incus::pty::supervise_child(
                pair.master,
                child,
                reservation,
                size,
                std::time::Duration::from_millis(sandbox_protocol::TERMINAL_HOST_MAX_LIFETIME_MS),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = size;
            Err(RuntimeError::new(
                sandbox_protocol::SandboxErrorCode::UnsupportedCapability,
                "host terminal requires linux",
            )
            .into())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{PtyCloseIntent, PtyEvent, PtyTermination};
    /// Opens the local host shell while `sentinels` (descriptors of this test
    /// binary) are open here, and asserts the shell holds none of them, that it
    /// answers resize, uid, gid and groups, and that close is confirmed.
    ///
    /// The leak check compares what each of the shell's descriptors refers to
    /// with the sentinel file, never descriptor numbers: interactive dash
    /// (`/bin/sh -i`) keeps its own terminal on fd 10, so a sentinel that
    /// happened to get number 10 (other tests holding descriptors) used to
    /// read as a leak although nothing was inherited.
    fn assert_host_shell_holds_none_of(sentinels: &[std::fs::File]) {
        // A PTY open would move the descriptor baselines of the PTY shim tests.
        let _serial = crate::incus::pty_shim_tests::lock();
        let path = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let path = path.to_str().unwrap();
        assert!(!path.contains('\''), "{path}");
        assert!(!sentinels.is_empty());
        let opener = LocalHostPtyOpener::default();
        let mut session = opener
            .open(
                "local-host-test",
                PtySize::new(24, 80).unwrap(),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
        session.resize(PtySize::new(40, 100).unwrap()).unwrap();
        assert_eq!(session.size(), PtySize::new(40, 100).unwrap());
        // Octal escapes prevent terminal input echo from satisfying the marker.
        let command = format!(
            "for f in /proc/$$/fd/*; do [ \"$(readlink \"$f\")\" != '{path}' ] || printf '\\106D_LEAK %s\\n' \"$f\"; done; printf '\\1241_HOST_OK\\n'; id -u; id -g; id -G\n"
        );
        session.write_input(command.as_bytes()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut output = String::new();
        let groups = nix::unistd::getgroups()
            .unwrap()
            .iter()
            .map(|g| g.as_raw())
            .collect::<std::collections::HashSet<_>>();
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "local host shell did not answer"
            );
            if let Some(PtyEvent::Output(bytes)) = session
                .next_event(std::time::Duration::from_millis(20))
                .unwrap()
            {
                output.push_str(&String::from_utf8_lossy(&bytes));
            }
            let Some((_, result)) = output.split_once("T1_HOST_OK\r\n") else {
                continue;
            };
            let lines = result.lines().collect::<Vec<_>>();
            if lines.len() < 3 {
                continue;
            }
            if lines[0].trim() != nix::unistd::geteuid().as_raw().to_string()
                || lines[1].trim() != nix::unistd::getegid().as_raw().to_string()
            {
                continue;
            }
            let got = lines[2]
                .split_whitespace()
                .filter_map(|g| g.parse::<u32>().ok())
                .collect::<std::collections::HashSet<_>>();
            if groups.is_subset(&got) {
                break;
            }
        }
        assert!(
            !output.contains("FD_LEAK"),
            "non-stdio descriptor reached the shell: {output}"
        );
        assert!(matches!(
            session.close(PtyCloseIntent::Client),
            PtyTermination::Closed { reaped: true, .. }
        ));
        assert!(session.reap_confirmed());
    }

    #[test]
    fn local_host_pty_echo_resize_uid_groups_and_confirmed_close() {
        let sentinel = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        assert_host_shell_holds_none_of(&[sentinel]);
    }

    /// The same check while this process holds descriptors 3 through 12 (run
    /// alone they are all sentinels, so one of them is the number the shell
    /// uses for its own terminal); in the parallel suite the numbers are
    /// whatever is free, which the identity check does not depend on.
    #[test]
    fn local_host_pty_leak_check_holds_with_sentinels_on_the_shells_own_descriptor_numbers() {
        use std::os::fd::AsRawFd;
        let exe = std::env::current_exe().unwrap();
        let mut sentinels = Vec::new();
        while sentinels.len() < 64
            && sentinels
                .last()
                .is_none_or(|file: &std::fs::File| file.as_raw_fd() < 12)
        {
            sentinels.push(std::fs::File::open(&exe).unwrap());
        }
        assert_host_shell_holds_none_of(&sentinels);
    }

    /// An inheritable descriptor (`FD_CLOEXEC` cleared, as a library or an
    /// inherited descriptor could leave one) never reaches the host shell: the
    /// PTY spawn closes every descriptor above stdio. Positive control: a
    /// plain `sh` spawned by std, which closes nothing, sees the same sentinel
    /// through the same identity check.
    #[test]
    fn local_host_pty_closes_an_inheritable_descriptor() {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let path = exe.to_str().unwrap();
        assert!(!path.contains('\''), "{path}");
        let sentinel = std::fs::File::open(&exe).unwrap();
        fcntl(&sentinel, FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
        let control = crate::host_child::command("/bin/sh", crate::host_child::Environment::PathOnly)
            .arg("-c")
            .arg(format!(
                "for f in /proc/$$/fd/*; do [ \"$(readlink \"$f\")\" != '{path}' ] || echo FD_LEAK; done"
            ))
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&control.stdout).contains("FD_LEAK"),
            "the identity check must see an inherited descriptor: {control:?}"
        );
        assert_host_shell_holds_none_of(&[sentinel]);
    }
}
