//! Rate control for user-facing updates.
//!
//! Live views must never render per-packet updates. The engine aggregates internally and
//! emits a snapshot at most every `1 / hz` seconds, always emitting the first update so
//! a fresh panel is never left empty.

use std::time::{Duration, Instant};

/// Coalesces events down to a maximum emission rate.
#[derive(Debug)]
pub struct Throttle {
    interval: Duration,
    last_emit: Option<Instant>,
}

impl Throttle {
    /// Creates a throttle emitting at most once per `interval`.
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_emit: None,
        }
    }

    /// Creates a throttle from a frequency in hertz.
    ///
    /// A frequency of zero is clamped to 1 Hz so the UI still updates.
    #[must_use]
    pub fn from_hz(hz: u32) -> Self {
        let hz = hz.max(1);
        Self::new(Duration::from_millis(1_000 / u64::from(hz)))
    }

    /// Returns true when an update should be emitted now.
    pub fn should_emit(&mut self) -> bool {
        let now = Instant::now();
        match self.last_emit {
            None => {
                self.last_emit = Some(now);
                true
            }
            Some(last) if now.duration_since(last) >= self.interval => {
                self.last_emit = Some(now);
                true
            }
            Some(_) => false,
        }
    }

    /// Emits unconditionally and restarts the interval.
    pub fn force_emit(&mut self) {
        self.last_emit = Some(Instant::now());
    }

    /// Returns true when the interval has elapsed since the last emission.
    #[must_use]
    pub fn is_due(&self) -> bool {
        self.last_emit
            .is_none_or(|last| Instant::now().duration_since(last) >= self.interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_update_is_emitted_immediately() {
        let mut throttle = Throttle::new(Duration::from_millis(50));
        assert!(throttle.should_emit());
        assert!(!throttle.should_emit());
    }

    #[test]
    fn interval_zero_still_throttles() {
        let mut throttle = Throttle::new(Duration::ZERO);
        assert!(throttle.should_emit());
        assert!(throttle.should_emit());
    }

    #[test]
    fn hz_is_clamped_to_one() {
        let throttle = Throttle::from_hz(0);
        assert_eq!(throttle.interval, Duration::from_millis(1_000));
    }

    #[test]
    fn force_emit_restarts_the_window() {
        let mut throttle = Throttle::new(Duration::from_millis(500));
        assert!(throttle.should_emit());
        throttle.force_emit();
        assert!(!throttle.should_emit());
        assert!(!throttle.is_due());
    }
}
