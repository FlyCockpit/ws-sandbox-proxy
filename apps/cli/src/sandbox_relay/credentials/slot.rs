//! Per-sandbox credential concurrency: `CredSandbox`.
//!
//! The `Mutex` guards in-memory transitions only and is never held across a
//! relay wait, bundle wait, upload or helper run. Exclusive guest access is
//! the `guest_slot` flag, set and cleared under that lock, with a `Condvar`
//! for waiters:
//!
//! - stop/kill wait ≤ 10 s, then cancel the holder through its permit
//!   (the runtime kills the helper child) and proceed;
//! - expiry waits ≤ 5 s inside its 20 s phase, then cancels the holder;
//! - checkpoint never waits (skips when busy);
//! - attach/free wait ≤ 10 s, then fail retryable.
//!
//! Enforcement loss is lock-free with respect to this mutex and condvar: it
//! sets the `revoked` flag and cancels the holder's permit through a separate
//! cell that serializes revocation with publishing a new holder.

use sandbox_runtime::RuntimePermit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub const TEARDOWN_SLOT_WAIT: Duration = Duration::from_secs(10);
pub const EXPIRY_SLOT_WAIT: Duration = Duration::from_secs(5);
pub const ATTACH_FREE_SLOT_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotUser {
    Install,
    Checkpoint,
    Teardown,
    Expiry,
    Attach,
    Free,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    /// Waited the allowed time (attach/free): retry later.
    Busy,
    /// The sandbox lost enforcement or its binding was revoked.
    Revoked,
    /// A preempted holder did not release within the caller's budget.
    HolderStuck,
}

#[derive(Debug, Default)]
struct SlotState {
    holder: Option<SlotUser>,
    /// Bumped on every acquisition; a guard only clears its own tenure.
    tenure: u64,
}

#[derive(Debug, Default)]
pub struct CredSandbox {
    state: Mutex<SlotState>,
    cond: Condvar,
    revoked: AtomicBool,
    holder_permit: Mutex<Option<Arc<RuntimePermit>>>,
}

#[derive(Debug)]
pub struct SlotGuard<'a> {
    owner: &'a CredSandbox,
    tenure: u64,
    pub user: SlotUser,
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.owner.lock_state();
        if state.tenure == self.tenure {
            state.holder = None;
            *self.owner.permit_cell() = None;
        }
        drop(state);
        self.owner.cond.notify_all();
    }
}

impl CredSandbox {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_state(&self) -> MutexGuard<'_, SlotState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn permit_cell(&self) -> MutexGuard<'_, Option<Arc<RuntimePermit>>> {
        self.holder_permit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::SeqCst)
    }

    /// Enforcement loss / revocation: never takes the state lock or waits on
    /// the condvar. The holder's helper is cancelled through its permit.
    pub fn revoke(&self) {
        let permit = {
            let cell = self.permit_cell();
            self.revoked.store(true, Ordering::SeqCst);
            cell.clone()
        };
        if let Some(permit) = permit {
            permit.revoke();
        }
        self.cond.notify_all();
    }

    /// Clears a revocation once the server has re-established authority.
    pub fn rearm(&self) {
        let _cell = self.permit_cell();
        self.revoked.store(false, Ordering::SeqCst);
    }

    pub fn holder(&self) -> Option<SlotUser> {
        self.lock_state().holder
    }

    fn take<'a>(
        &'a self,
        state: &mut MutexGuard<'_, SlotState>,
        user: SlotUser,
        permit: &Arc<RuntimePermit>,
        allow_revoked: bool,
    ) -> Result<SlotGuard<'a>, SlotError> {
        // Lock order is state → cell; revoke only needs the cell. The
        // revocation check and publication must be one cell transition.
        let mut cell = self.permit_cell();
        if !allow_revoked && self.is_revoked() {
            return Err(SlotError::Revoked);
        }
        state.tenure += 1;
        state.holder = Some(user);
        *cell = Some(Arc::clone(permit));
        Ok(SlotGuard {
            owner: self,
            tenure: state.tenure,
            user,
        })
    }

    /// Checkpoint: never waits.
    pub fn try_acquire(
        &self,
        user: SlotUser,
        permit: &Arc<RuntimePermit>,
    ) -> Result<SlotGuard<'_>, SlotError> {
        if self.is_revoked() {
            return Err(SlotError::Revoked);
        }
        let mut state = self.lock_state();
        if state.holder.is_some() {
            return Err(SlotError::Busy);
        }
        self.take(&mut state, user, permit, false)
    }

    /// Waits up to `wait` for the slot (attach/free/install).
    pub fn acquire(
        &self,
        user: SlotUser,
        wait: Duration,
        permit: &Arc<RuntimePermit>,
    ) -> Result<SlotGuard<'_>, SlotError> {
        let deadline = Instant::now() + wait;
        let mut state = self.lock_state();
        loop {
            if self.is_revoked() || permit.is_cancelled() {
                return Err(SlotError::Revoked);
            }
            if state.holder.is_none() {
                return self.take(&mut state, user, permit, false);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(SlotError::Busy);
            }
            state = self
                .cond
                .wait_timeout(state, (deadline - now).min(Duration::from_millis(50)))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    /// Stop/kill/expiry: wait up to `wait`, then cancel the holder through
    /// its permit and wait up to `release` for it to let go. Revocation does
    /// not stop a teardown (it still needs the slot to scrub or stop).
    pub fn acquire_preempting(
        &self,
        user: SlotUser,
        wait: Duration,
        release: Duration,
        permit: &Arc<RuntimePermit>,
    ) -> Result<SlotGuard<'_>, SlotError> {
        let deadline = Instant::now() + wait;
        let mut state = self.lock_state();
        loop {
            if state.holder.is_none() {
                return self.take(&mut state, user, permit, true);
            }
            let now = Instant::now();
            if now >= deadline {
                let holder = self.permit_cell().clone();
                if let Some(holder) = holder {
                    holder.revoke();
                }
                return self.wait_release(state, user, now + release, permit);
            }
            state = self
                .cond
                .wait_timeout(state, (deadline - now).min(Duration::from_millis(50)))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    fn wait_release<'a>(
        &'a self,
        mut state: MutexGuard<'_, SlotState>,
        user: SlotUser,
        deadline: Instant,
        permit: &Arc<RuntimePermit>,
    ) -> Result<SlotGuard<'a>, SlotError> {
        loop {
            if state.holder.is_none() {
                return self.take(&mut state, user, permit, true);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(SlotError::HolderStuck);
            }
            state = self
                .cond
                .wait_timeout(state, (deadline - now).min(Duration::from_millis(50)))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    /// Test hook: holds the state mutex (a stalled in-memory transition).
    #[cfg(test)]
    pub(crate) fn stall_state(&self) -> MutexGuard<'_, impl Sized> {
        self.lock_state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permit() -> Arc<RuntimePermit> {
        Arc::new(RuntimePermit::with_timeout(Duration::from_secs(60)))
    }

    #[test]
    fn checkpoint_never_waits_and_stop_preempts_it() {
        let slot = Arc::new(CredSandbox::new());
        let holder_permit = permit();
        let guard = slot
            .try_acquire(SlotUser::Checkpoint, &holder_permit)
            .unwrap();
        assert_eq!(
            slot.try_acquire(SlotUser::Checkpoint, &permit())
                .unwrap_err(),
            SlotError::Busy
        );
        // The "helper" releases as soon as its permit is cancelled.
        let worker = {
            let p = Arc::clone(&holder_permit);
            std::thread::spawn(move || {
                while !p.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
        };
        let s2 = Arc::clone(&slot);
        let stopper = std::thread::spawn(move || {
            s2.acquire_preempting(
                SlotUser::Teardown,
                Duration::from_millis(50),
                Duration::from_secs(5),
                &permit(),
            )
            .map(|g| g.user)
        });
        worker.join().unwrap();
        assert!(holder_permit.is_cancelled());
        drop(guard);
        assert_eq!(stopper.join().unwrap(), Ok(SlotUser::Teardown));
    }

    #[test]
    fn attach_and_free_fail_retryable_after_their_wait() {
        let slot = CredSandbox::new();
        let _held = slot.try_acquire(SlotUser::Teardown, &permit()).unwrap();
        let started = Instant::now();
        assert_eq!(
            slot.acquire(SlotUser::Attach, Duration::from_millis(80), &permit())
                .unwrap_err(),
            SlotError::Busy
        );
        assert!(started.elapsed() >= Duration::from_millis(80));
    }

    #[test]
    fn expiry_waits_then_cancels_and_reports_a_stuck_holder() {
        let slot = CredSandbox::new();
        let holder = permit();
        let _held = slot.try_acquire(SlotUser::Install, &holder).unwrap();
        // Holder never releases: the preemptor cancels it and gives up.
        assert_eq!(
            slot.acquire_preempting(
                SlotUser::Expiry,
                Duration::from_millis(20),
                Duration::from_millis(40),
                &permit(),
            )
            .unwrap_err(),
            SlotError::HolderStuck
        );
        assert!(holder.is_cancelled());
    }

    #[test]
    fn revocation_before_holder_publication_refuses_the_slot() {
        let slot = CredSandbox::new();
        let candidate = permit();
        // Simulate acquisition having passed its early revoked check, with
        // revoke winning the cell before take publishes the new permit.
        let mut state = slot.lock_state();
        assert!(!slot.is_revoked());
        slot.revoke();
        assert_eq!(
            slot.take(&mut state, SlotUser::Install, &candidate, false)
                .unwrap_err(),
            SlotError::Revoked
        );
        assert!(state.holder.is_none());
        assert!(slot.permit_cell().is_none());
        drop(state);
        // Teardown still needs to scrub after enforcement loss.
        assert!(
            slot.acquire_preempting(
                SlotUser::Teardown,
                Duration::ZERO,
                Duration::ZERO,
                &permit()
            )
            .is_ok()
        );
    }

    #[test]
    fn revocation_after_holder_publication_cancels_the_published_permit() {
        let slot = CredSandbox::new();
        let candidate = permit();
        let guard = slot.try_acquire(SlotUser::Install, &candidate).unwrap();
        assert!(!candidate.is_cancelled());
        slot.revoke();
        assert!(candidate.is_cancelled());
        drop(guard);
        assert_eq!(
            slot.try_acquire(SlotUser::Install, &permit()).unwrap_err(),
            SlotError::Revoked
        );
    }

    /// Enforcement loss completes while the state lock is held by a stalled
    /// hook: it never takes that lock or waits on the condvar.
    #[test]
    fn enforcement_loss_is_lock_free() {
        let slot = Arc::new(CredSandbox::new());
        let holder = permit();
        let guard = slot.try_acquire(SlotUser::Install, &holder).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let stalled = slot.stall_state();
        let s2 = Arc::clone(&slot);
        std::thread::spawn(move || {
            s2.revoke();
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(2))
            .expect("revoke must not wait on the stalled state lock");
        assert!(slot.is_revoked());
        assert!(holder.is_cancelled());
        drop(stalled);
        drop(guard);
        // New guest work is refused until re-armed.
        assert_eq!(
            slot.acquire(SlotUser::Attach, Duration::from_millis(10), &permit())
                .unwrap_err(),
            SlotError::Revoked
        );
        slot.rearm();
        assert!(slot.try_acquire(SlotUser::Checkpoint, &permit()).is_ok());
    }
}
