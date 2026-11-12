//! OS shutdown signals for `wssp connect` (C55, C52-TB-3).
//!
//! [`install`] registers SIGTERM and SIGINT with `signal-hook`'s iterator: a
//! process-wide handler (nothing is blocked, so every thread and every child
//! keeps its signal mask) feeds one dedicated watcher thread. The handler is
//! registered before `install` returns. `commands::connect::run` calls it
//! FIRST, before the relay, expiry, or PTY pump threads exist, so no relay
//! effect can start without the handler in place; a signal that lands before
//! that still takes the default action (the process dies with nothing
//! started).
//!
//! - The first signal raises the relay's [`ShutdownSignal`]: every terminal
//!   is closed with intent `shutdown` and reaped, the socket closes normally,
//!   and `run_connect` returns. The caller then ends the process with that
//!   same signal ([`terminate_by_signal`]), so a service manager sees death
//!   by SIGTERM (or SIGINT), not an exit status.
//! - A second signal during that shutdown ends the process at once, also by
//!   default-action emulation. So does [`SHUTDOWN_DEADLINE`] passing without
//!   the graceful path finishing (for example a runtime call that does not
//!   return; a relay handshake observes the request and is itself bounded,
//!   C55-L11). That is the documented forced path: PTY shells are not reaped (each setsid shell
//!   still gets SIGHUP when its master closes with the process).
//!
//! - WP7: on Linux SIGUSR1 (sent by `wssp daemon quiesce`, the service's
//!   reload) asks for a graceful *quiesce* first
//!   (`crate::sandbox_relay::quiesce`): it never takes the first-signal slot,
//!   so a later SIGTERM or SIGINT still starts (or a second one forces) the
//!   shutdown exactly as above. The quiesce ends in the same graceful
//!   shutdown, under the same deadline, and the process exits 0. The handler
//!   is registered here, before the daemon writes the control file that
//!   tells `wssp daemon quiesce` it may send SIGUSR1; without that file it
//!   sends SIGTERM under systemd, avoiding an unverified SIGUSR1.
//!
//! SIGINT from an interactive terminal reaches the whole foreground process
//! group. Every host helper child (`incus` effects, `incus exec`, `kill`) is
//! spawned as its own process-group leader (`process_group(0)`) and every
//! PTY child is a setsid leader, so a Ctrl-C reaches only the daemon and the
//! graceful path decides what to stop. SIGKILL cannot be caught; it remains
//! the one way to stop the daemon without closing its terminals.
//!
//! Windows has no binding: Ctrl-C ends the process at once, as before.

use crate::sandbox_relay::connect::ShutdownSignal;

#[cfg(unix)]
pub use imp::*;

#[cfg(unix)]
mod imp {
    use super::ShutdownSignal;
    use anyhow::{Context, Result};
    #[cfg(target_os = "linux")]
    use signal_hook::consts::SIGUSR1;
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::iterator::{Handle, Signals};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::thread::JoinHandle;
    use std::time::Duration;

    /// The graceful shutdown's outer bound. Its parts are bounded on their
    /// own (terminal drain 5 s, PTY reap wait 20 s, then the expiry worker's
    /// join: an in-flight graceful stop up to 16 s plus its forced stop up to
    /// 5 s); this only ends a shutdown that is stuck elsewhere. A service
    /// manager's stop timeout (systemd `TimeoutStopSec`) should exceed it.
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(60);

    /// What the watcher does with one delivered signal.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SignalAction {
        /// The first signal: start the graceful shutdown.
        Graceful,
        /// A later signal: end the process now with this signal.
        Exit(i32),
        /// WP7 SIGUSR1: quiesce, then shut down. Never takes the slot.
        Quiesce,
    }

    /// The signals `install` registers.
    fn handled() -> Vec<i32> {
        #[cfg_attr(
            not(target_os = "linux"),
            expect(unused_mut, reason = "Linux adds SIGUSR1")
        )]
        let mut signals = vec![SIGTERM, SIGINT];
        #[cfg(target_os = "linux")]
        signals.push(SIGUSR1);
        signals
    }

    fn is_quiesce(signal: i32) -> bool {
        #[cfg(target_os = "linux")]
        return signal == SIGUSR1;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = signal;
            false
        }
    }

    /// Record `signal` and decide what it means. The first shutdown signal
    /// wins the slot and requests the graceful shutdown; any later one exits.
    /// SIGUSR1 (quiesce) leaves the slot alone.
    pub fn receive(first: &AtomicI32, signal: i32) -> SignalAction {
        if is_quiesce(signal) {
            return SignalAction::Quiesce;
        }
        match first.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => SignalAction::Graceful,
            Err(_) => SignalAction::Exit(signal),
        }
    }

    /// The installed handlers. Dropping this unregisters them and joins the
    /// watcher, restoring the default actions.
    pub struct ShutdownSignals {
        first: Arc<AtomicI32>,
        handle: Handle,
        watcher: Option<JoinHandle<()>>,
    }

    /// Register SIGTERM and SIGINT (and on Linux SIGUSR1, WP7) and start the
    /// watcher thread. The handlers are in place when this returns; only
    /// then is quiescing enabled (so only then is the control file written).
    pub fn install(shutdown: &ShutdownSignal) -> Result<ShutdownSignals> {
        let mut signals = Signals::new(handled()).context("register shutdown signal handlers")?;
        let handle = signals.handle();
        let first = Arc::new(AtomicI32::new(0));
        let seen = first.clone();
        let watched = shutdown.clone();
        let watcher = std::thread::Builder::new()
            .name("wssp-shutdown-signals".into())
            .spawn(move || {
                for signal in signals.forever() {
                    match receive(&seen, signal) {
                        SignalAction::Graceful => {
                            tracing::info!(
                                signal,
                                "shutdown signal received; closing terminals and the relay"
                            );
                            watched.request();
                            start_deadline(signal);
                        }
                        SignalAction::Exit(signal) => {
                            tracing::warn!(signal, "second shutdown signal received; exiting now");
                            terminate_by_signal(signal);
                        }
                        SignalAction::Quiesce => {
                            if watched.quiesce().request() {
                                tracing::info!(
                                    "quiesce requested: finishing running commands, then restarting"
                                );
                                start_deadline_after_quiesce(watched.clone());
                            }
                        }
                    }
                }
            })
            .context("start the shutdown signal watcher")?;
        if handled().iter().copied().any(is_quiesce) {
            shutdown.quiesce().enable();
        }
        Ok(ShutdownSignals {
            first,
            handle,
            watcher: Some(watcher),
        })
    }

    /// Ends the process with `signal` if the graceful shutdown has not
    /// finished within [`SHUTDOWN_DEADLINE`]. Without a deadline thread the
    /// shutdown would be unbounded, so the process ends at once instead.
    fn start_deadline(signal: i32) {
        let spawned = std::thread::Builder::new()
            .name("wssp-shutdown-deadline".into())
            .spawn(move || run_deadline(signal));
        if spawned.is_err() {
            terminate_by_signal(signal);
        }
    }

    fn run_deadline(signal: i32) -> ! {
        let deadline = std::time::Instant::now() + SHUTDOWN_DEADLINE;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left);
        }
        tracing::warn!("graceful shutdown did not finish in time; exiting now");
        terminate_by_signal(signal)
    }

    /// WP7: the shutdown a quiesce ends in gets the same outer deadline,
    /// ending a stuck one by SIGTERM (the service manager restarts it).
    fn start_deadline_after_quiesce(shutdown: ShutdownSignal) {
        let spawned = std::thread::Builder::new()
            .name("wssp-quiesce-deadline".into())
            .spawn(move || {
                while !shutdown.requested() {
                    std::thread::sleep(Duration::from_millis(100));
                }
                run_deadline(SIGTERM)
            });
        if spawned.is_err() {
            tracing::warn!("could not bound the quiesce's shutdown");
        }
    }

    impl ShutdownSignals {
        /// The first shutdown signal received, if any.
        pub fn received(&self) -> Option<i32> {
            match self.first.load(Ordering::SeqCst) {
                0 => None,
                signal => Some(signal),
            }
        }
    }

    impl Drop for ShutdownSignals {
        fn drop(&mut self) {
            self.handle.close();
            if let Some(watcher) = self.watcher.take() {
                let _ = watcher.join();
            }
        }
    }

    /// End the process the way `signal` would have. `emulate_default_handler`
    /// puts the default action back in place of our handler, unblocks the
    /// signal and raises it. Exit status `128 + signal` is the fallback for a
    /// signal it does not know, and the answer as a PID namespace's init (a
    /// container's PID 1), where the kernel drops a default-action signal
    /// the process sends itself and the emulation would end in `abort`.
    pub fn terminate_by_signal(signal: i32) -> ! {
        if std::process::id() != 1 {
            let _ = signal_hook::low_level::emulate_default_handler(signal);
        }
        std::process::exit(128_i32.saturating_add(signal))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_first_signal_is_graceful_and_any_later_one_exits_with_its_own_signal() {
            let first = AtomicI32::new(0);
            assert_eq!(receive(&first, SIGTERM), SignalAction::Graceful);
            assert_eq!(first.load(Ordering::SeqCst), SIGTERM);
            assert_eq!(receive(&first, SIGINT), SignalAction::Exit(SIGINT));
            assert_eq!(receive(&first, SIGTERM), SignalAction::Exit(SIGTERM));
            // The recorded first signal never changes.
            assert_eq!(first.load(Ordering::SeqCst), SIGTERM);
        }

        /// WP7: SIGUSR1 never takes the first-signal slot, before or after
        /// a shutdown signal, so SIGTERM keeps its meaning during a quiesce.
        #[cfg(target_os = "linux")]
        #[test]
        fn sigusr1_quiesces_without_taking_the_first_signal_slot() {
            let first = AtomicI32::new(0);
            assert_eq!(receive(&first, SIGUSR1), SignalAction::Quiesce);
            assert_eq!(receive(&first, SIGUSR1), SignalAction::Quiesce);
            assert_eq!(first.load(Ordering::SeqCst), 0);
            assert_eq!(receive(&first, SIGTERM), SignalAction::Graceful);
            assert_eq!(receive(&first, SIGUSR1), SignalAction::Quiesce);
            assert_eq!(receive(&first, SIGINT), SignalAction::Exit(SIGINT));
            assert_eq!(first.load(Ordering::SeqCst), SIGTERM);
            assert!(handled().contains(&SIGUSR1));
        }
    }
}

/// No OS binding off Unix: the default console handling stays in place.
#[cfg(not(unix))]
pub struct ShutdownSignals;

#[cfg(not(unix))]
pub fn install(_shutdown: &ShutdownSignal) -> anyhow::Result<ShutdownSignals> {
    Ok(ShutdownSignals)
}

#[cfg(not(unix))]
impl ShutdownSignals {
    pub fn received(&self) -> Option<i32> {
        None
    }
}

#[cfg(not(unix))]
pub fn terminate_by_signal(signal: i32) -> ! {
    std::process::exit(128_i32.saturating_add(signal))
}
