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
    #[test]
    fn local_host_pty_echo_resize_uid_groups_and_confirmed_close() {
        use std::os::fd::AsRawFd;
        let sentinel = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
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
            "if [ -e /proc/$$/fd/{} ]; then printf '\\106D_LEAK\\n'; fi; printf '\\1241_HOST_OK\\n'; id -u; id -g; id -G\n",
            sentinel.as_raw_fd()
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
            "non-stdio descriptor reached the shell"
        );
        assert!(matches!(
            session.close(PtyCloseIntent::Client),
            PtyTermination::Closed { reaped: true, .. }
        ));
        assert!(session.reap_confirmed());
    }
}
