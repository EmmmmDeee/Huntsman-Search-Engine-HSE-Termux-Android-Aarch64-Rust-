//! The wall clock as Unix time, read in one place. Every reading is measured from the Unix epoch,
//! and a clock that reads before the epoch gives 0 in every unit, so a timestamp is taken the same
//! way wherever it is recorded. `tests/architecture_boundaries.rs` holds the rest of the crate to
//! asking this module for the time.

use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

/// Whole seconds since the Unix epoch, or 0 when the clock reads before it.
#[must_use]
pub fn unix_now() -> u64 {
    since_epoch().map_or(0, |elapsed| elapsed.as_secs())
}

/// Whole milliseconds since the Unix epoch, saturating at `u64::MAX`, or 0 when the clock reads
/// before it.
#[must_use]
pub fn unix_now_millis() -> u64 {
    since_epoch().map_or(0, |elapsed| {
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
    })
}

/// Nanoseconds since the Unix epoch, or 0 when the clock reads before it.
#[must_use]
pub fn unix_now_nanos() -> u128 {
    since_epoch().map_or(0, |elapsed| elapsed.as_nanos())
}

/// The nanoseconds past the last whole second since the Unix epoch, or 0 when the clock reads
/// before it.
#[must_use]
pub fn unix_subsec_nanos() -> u32 {
    since_epoch().map_or(0, |elapsed| elapsed.subsec_nanos())
}

/// Whole seconds from the Unix epoch to `time`, or `None` when `time` is before it. For a time that
/// is not the reading now, such as a file's modification time.
#[must_use]
pub fn unix_secs_of(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

fn since_epoch() -> Result<Duration, SystemTimeError> {
    SystemTime::now().duration_since(UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_readings_agree_on_one_clock() {
        // Taken in order, so each later reading is at most a few seconds after the one before.
        let secs = unix_now();
        let millis = unix_now_millis();
        let nanos = unix_now_nanos();
        assert!(secs > 1_577_836_800, "{secs} is before 2020-01-01");
        assert!((secs * 1_000..=secs * 1_000 + 5_000).contains(&millis));
        let secs_in_nanos = u128::from(secs) * 1_000_000_000;
        assert!((secs_in_nanos..=secs_in_nanos + 5_000_000_000).contains(&nanos));
    }

    #[test]
    fn the_subsecond_part_is_below_one_second() {
        assert!(unix_subsec_nanos() < 1_000_000_000);
    }

    #[test]
    fn a_file_time_converts_to_whole_seconds_and_a_time_before_the_epoch_does_not() {
        assert_eq!(
            unix_secs_of(UNIX_EPOCH + Duration::from_millis(1_500)),
            Some(1)
        );
        assert_eq!(unix_secs_of(UNIX_EPOCH - Duration::from_secs(1)), None);
    }
}
