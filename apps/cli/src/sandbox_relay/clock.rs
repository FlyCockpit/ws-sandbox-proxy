//! Local elapsed time is the lower bound even when the wall clock rolls back.
use anyhow::Result;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub trait ClockSource: std::fmt::Debug + Send + Sync {
    fn sample(&self) -> Result<(u64, u64)>; // wall milliseconds, monotonic milliseconds
}
#[derive(Debug)]
struct SystemClock(Instant);
impl ClockSource for SystemClock {
    fn sample(&self) -> Result<(u64, u64)> {
        Ok((
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_millis()
                .try_into()?,
            self.0.elapsed().as_millis().try_into()?,
        ))
    }
}
#[derive(Debug)]
pub struct LeaseClock {
    source: Arc<dyn ClockSource>,
    last: Mutex<Option<(u64, u64)>>,
}
impl Default for LeaseClock {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock(Instant::now())))
    }
}
impl LeaseClock {
    pub fn new(source: Arc<dyn ClockSource>) -> Self {
        Self {
            source,
            last: Mutex::new(None),
        }
    }
    pub fn now_ms(&self) -> Result<u64> {
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        let (wall, mono) = self.source.sample()?;
        let now = last.map_or(wall, |(time, tick)| {
            wall.max(time.saturating_add(mono.saturating_sub(tick)))
        });
        *last = Some((now, mono));
        Ok(now)
    }
}
