//! The `Date` field of responses (RFC 9110 section 5.6.7, IMF-fixdate), made once a second.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static CACHE: Mutex<(u64, String)> = Mutex::new((u64::MAX, String::new()));

/// Now, as an IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub(crate) fn now() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if cache.0 != secs {
        *cache = (secs, format(secs));
    }
    cache.1.clone()
}

/// The IMF-fixdate of a time in seconds since 1970.
pub(crate) fn format(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{}, {d:02} {} {y:04} {:02}:{:02}:{:02} GMT", DAYS[(days % 7) as usize], MONTHS[(m - 1) as usize], rem / 3600, rem / 60 % 60, rem % 60)
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates_are_imf_fixdates() {
        assert_eq!(super::format(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(super::format(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(super::format(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(super::format(1_791_417_599), "Wed, 07 Oct 2026 23:59:59 GMT");
        assert_eq!(super::now().len(), 29);
    }
}
