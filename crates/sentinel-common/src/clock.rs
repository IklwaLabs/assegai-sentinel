//! Time helpers and human-readable formatting.
//!
//! Sentinel stores timestamps as microseconds since the Unix epoch (`u64`), which is
//! compact, cheap to compare and serializes as a plain integer. Formatting is
//! implemented locally instead of pulling in a date-time crate: only UTC RFC 3339
//! rendering is needed for display and report metadata.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Microseconds since the Unix epoch, saturating at 0 if the clock predates it.
pub fn now_unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Seconds since the Unix epoch.
pub fn now_unix_secs() -> u64 {
    now_unix_micros() / 1_000_000
}

/// A process-lifetime monotonic instant, used for rate and interval maths.
pub fn now_monotonic() -> Instant {
    Instant::now()
}

/// Converts microseconds since the epoch into an RFC 3339 UTC timestamp.
///
/// Example: `1735689600000000` becomes `"2025-01-01T00:00:00.000Z"`.
#[must_use]
pub fn unix_micros_to_rfc3339(micros: u64) -> String {
    let secs = (micros / 1_000_000) as i64;
    let sub_millis = (micros % 1_000_000) / 1_000;

    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{sub_millis:03}Z")
}

/// Converts microseconds since the epoch into `HH:MM:SS` for dense timeline views.
#[must_use]
pub fn unix_micros_to_clock(micros: u64) -> String {
    let secs_of_day = ((micros / 1_000_000) as i64).rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60
    )
}

/// Civil date from a day count since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (y + i64::from(m <= 2), m as u32, d as u32)
}

/// Formats a byte count with a binary unit suffix and one decimal above 1 KiB.
///
/// Sentinel uses binary units (KiB/MiB/GiB) because that is what operating system
/// network statistics report, so displayed numbers stay consistent with the OS.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Formats a bits-per-second rate with a decimal suffix.
#[must_use]
pub fn format_bps(bits_per_second: f64) -> String {
    const UNITS: [&str; 5] = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
    if !bits_per_second.is_finite() || bits_per_second < 0.0 {
        return "0 bps".to_string();
    }
    let mut value = bits_per_second;
    let mut unit = 0usize;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} bps")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Formats a duration as a compact human string (`840s`, `5m 12s`, `2h 04m`).
#[must_use]
pub fn format_duration(seconds: u64) -> String {
    match seconds {
        s if s < 60 => format!("{s}s"),
        s if s < 3_600 => format!("{}m {:02}s", s / 60, s % 60),
        s if s < 86_400 => format!("{}h {:02}m", s / 3_600, (s % 3_600) / 60),
        s => format!("{}d {:02}h", s / 86_400, (s % 86_400) / 3_600),
    }
}

/// Saturating microsecond difference, guarding against clock jumps in either direction.
#[must_use]
pub fn elapsed_micros(from_us: u64, to_us: u64) -> u64 {
    to_us.saturating_sub(from_us)
}

/// Converts a [`Duration`] into whole seconds, rounding down.
#[must_use]
pub fn duration_secs(duration: Duration) -> u64 {
    duration.as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_epoch_instant() {
        assert_eq!(unix_micros_to_rfc3339(0), "1970-01-01T00:00:00.000Z");
        // 2025-01-01T00:00:00Z
        assert_eq!(
            unix_micros_to_rfc3339(1_735_689_600_000_000),
            "2025-01-01T00:00:00.000Z"
        );
        // 2024-02-29T12:34:56Z, leap day.
        assert_eq!(
            unix_micros_to_rfc3339(1_709_210_096_000_000),
            "2024-02-29T12:34:56.000Z"
        );
    }

    #[test]
    fn clock_time_wraps_after_midnight() {
        assert_eq!(unix_micros_to_clock(86_400_000_000), "00:00:00");
        assert_eq!(unix_micros_to_clock(3_661_000_000), "01:01:01");
    }

    #[test]
    fn byte_formatting_covers_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn rate_formatting_handles_garbage() {
        assert_eq!(format_bps(f64::NAN), "0 bps");
        assert_eq!(format_bps(-5.0), "0 bps");
        assert_eq!(format_bps(999.0), "999 bps");
        assert_eq!(format_bps(28_400_000.0), "28.4 Mbps");
    }

    #[test]
    fn duration_formatting_scales() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(312), "5m 12s");
        assert_eq!(format_duration(7_440), "2h 04m");
        assert_eq!(format_duration(90_000), "1d 01h");
    }

    #[test]
    fn elapsed_never_underflows() {
        assert_eq!(elapsed_micros(100, 50), 0);
        assert_eq!(elapsed_micros(50, 100), 50);
    }
}
