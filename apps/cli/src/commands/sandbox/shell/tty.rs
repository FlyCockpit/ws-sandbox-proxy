//! The local terminal of `wssp sandbox shell`: tty detection, the window
//! size and raw mode with a guaranteed restore.
//!
//! Raw mode is restored when the [`RawMode`] guard drops (every return and
//! every unwinding panic) and by a panic hook (release builds abort on
//! panic, so no destructor runs there). Signals never kill the process while
//! the terminal is raw: the shell handles SIGINT, SIGTERM, SIGHUP and SIGQUIT itself
//! and returns through the guard. Only SIGKILL can leave a raw terminal
//! behind (`reset` repairs it).

#[cfg(target_os = "linux")]
mod imp {
    use std::sync::{Mutex, Once};

    use anyhow::{Context, Result};
    use rustix::termios::{self, OptionalActions, Termios};

    /// The terminal settings to restore; `Some` while raw.
    static SAVED: Mutex<Option<Termios>> = Mutex::new(None);
    static HOOK: Once = Once::new();

    pub fn stdin_is_tty() -> bool {
        termios::isatty(std::io::stdin())
    }

    pub fn stdout_is_tty() -> bool {
        termios::isatty(std::io::stdout())
    }

    /// `(rows, cols)` of the terminal on stdout (else stdin); `None` when
    /// unknown.
    pub fn size() -> Option<(u16, u16)> {
        let size = termios::tcgetwinsize(std::io::stdout())
            .or_else(|_| termios::tcgetwinsize(std::io::stdin()))
            .ok()?;
        (size.ws_row > 0 && size.ws_col > 0).then_some((size.ws_row, size.ws_col))
    }

    fn restore_from(saved: &mut Option<Termios>) {
        if let Some(settings) = saved.take() {
            let _ = termios::tcsetattr(std::io::stdin(), OptionalActions::Now, &settings);
        }
    }

    /// Restore the saved settings, if raw.
    pub fn restore() {
        let mut saved = SAVED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        restore_from(&mut saved);
    }

    /// Raw mode on stdin until the guard drops.
    pub struct RawMode(());

    impl RawMode {
        pub fn enter() -> Result<Self> {
            HOOK.call_once(|| {
                let previous = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |info| {
                    // Never wait on the lock here: the panic may hold it.
                    if let Ok(mut saved) = SAVED.try_lock() {
                        restore_from(&mut saved);
                    }
                    previous(info);
                }));
            });
            let stdin = std::io::stdin();
            let settings = termios::tcgetattr(&stdin).context("reading the terminal settings")?;
            let mut raw = settings.clone();
            raw.make_raw();
            let mut saved = SAVED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if saved.is_none() {
                *saved = Some(settings);
            }
            termios::tcsetattr(&stdin, OptionalActions::Now, &raw)
                .context("switching the terminal to raw mode")?;
            Ok(Self(()))
        }
    }

    impl Drop for RawMode {
        fn drop(&mut self) {
            restore();
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use anyhow::Result;

    pub fn stdin_is_tty() -> bool {
        false
    }

    pub fn stdout_is_tty() -> bool {
        false
    }

    pub fn size() -> Option<(u16, u16)> {
        None
    }

    pub struct RawMode(());

    impl RawMode {
        pub fn enter() -> Result<Self> {
            anyhow::bail!("interactive shells need Linux; pass `--no-tty`")
        }
    }
}

pub use imp::{RawMode, size, stdin_is_tty, stdout_is_tty};
