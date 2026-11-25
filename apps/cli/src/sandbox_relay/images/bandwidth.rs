//! Transfer pacing shared by image fetches and disk offload part loops: a
//! token bucket capped at a configured byte rate.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A token bucket with a one-part burst: each paced chunk starts no earlier
/// than the previous chunk's slot at `bytes_per_sec` has ended, so the
/// average rate never exceeds the cap.
#[derive(Debug)]
pub struct Bandwidth {
    bytes_per_sec: u64,
    next: Mutex<Option<Instant>>,
}

impl Bandwidth {
    /// `None` (unlimited) for `None`.
    pub fn new(bytes_per_sec: Option<u64>) -> Option<Arc<Self>> {
        bytes_per_sec.filter(|&rate| rate > 0).map(|rate| {
            Arc::new(Self {
                bytes_per_sec: rate,
                next: Mutex::new(None),
            })
        })
    }

    /// Reserve a slot for `bytes` at `now`; returns how long to wait first.
    fn reserve_at(&self, bytes: u64, now: Instant) -> Duration {
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        let start = next.map_or(now, |at| at.max(now));
        let slot = Duration::from_secs_f64(bytes as f64 / self.bytes_per_sec as f64);
        *next = Some(start + slot);
        start.saturating_duration_since(now)
    }

    /// Wait for `bytes`' slot; false when `stop` asked to end meanwhile.
    pub fn pace(&self, bytes: u64, stop: &dyn Fn() -> bool) -> bool {
        let until = Instant::now() + self.reserve_at(bytes, Instant::now());
        while Instant::now() < until {
            if stop() {
                return false;
            }
            std::thread::sleep(
                until
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(250)),
            );
        }
        !stop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_paces_to_the_cap_and_zero_is_unlimited() {
        assert!(Bandwidth::new(None).is_none());
        assert!(Bandwidth::new(Some(0)).is_none());
        let limit = Bandwidth::new(Some(1000)).unwrap();
        let now = Instant::now();
        // The first chunk goes at once; each later one waits for the previous
        // chunk's slot at 1000 B/s.
        assert_eq!(limit.reserve_at(500, now), Duration::ZERO);
        assert_eq!(limit.reserve_at(1000, now), Duration::from_millis(500));
        assert_eq!(limit.reserve_at(1, now), Duration::from_millis(1500));
        // Idle time is not banked beyond the slot already reserved.
        let later = now + Duration::from_secs(10);
        assert_eq!(limit.reserve_at(100, later), Duration::ZERO);
        // A stop ends the wait.
        let slow = Bandwidth::new(Some(1)).unwrap();
        assert!(slow.pace(1, &|| false));
        let started = Instant::now();
        assert!(!slow.pace(1, &|| true));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
