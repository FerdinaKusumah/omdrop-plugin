//! Wall-clock stamps in the advertisers' log format.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the epoch, as Python's `time.time()`.
pub fn epoch_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// `HH:MM:SSZ` in UTC for an epoch time (`time.strftime("%H:%M:%SZ", gmtime)`).
pub fn hms_utc(epoch: f64) -> String {
    let secs = (epoch.floor() as i64).rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn hms() {
        assert_eq!(super::hms_utc(1_760_000_000.999), "08:53:20Z");
        assert_eq!(super::hms_utc(0.0), "00:00:00Z");
    }
}
