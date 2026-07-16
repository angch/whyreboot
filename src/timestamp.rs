// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal timestamp replacing chrono::DateTime<Local>.
//! Stored as i64 (seconds since Unix epoch, UTC).
//!
//! Broken-down time is computed with pure-Rust civil-day algorithms (Hinnant's
//! algorithms, in both directions). UTC rendering is fully portable; local-time
//! rendering uses the platform timezone database — Win32 `FileTimeToLocalFileTime`
//! on Windows and libc `localtime_r` on Unix.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since Unix epoch (1970-01-01 00:00:00 UTC).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Timestamp(pub i64);

/// Broken-down calendar time (either UTC or local, depending on how it was built).
#[derive(Clone, Copy, Debug, Default)]
struct Civil { y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64 }

impl Timestamp {
    pub fn now() -> Self {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        Timestamp(d.as_secs() as i64)
    }

    pub fn from_system_time(st: SystemTime) -> Self {
        let d = st.duration_since(UNIX_EPOCH).unwrap_or_default();
        Timestamp(d.as_secs() as i64)
    }

    /// Parse an RFC-3339-ish timestamp: "YYYY-MM-DDTHH:MM:SS…" (assumed UTC).
    /// Accepts a space separator as well as `T`. Windows Event Log times are UTC.
    pub fn from_rfc3339(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() < 19 { return None; }
        let y   = p4(&b[0..4])?  as i64;
        let mo  = p2(&b[5..7])?  as i64;
        let d   = p2(&b[8..10])? as i64;
        let h   = p2(&b[11..13])? as i64;
        let min = p2(&b[14..16])? as i64;
        let s   = p2(&b[17..19])? as i64;
        Some(Timestamp(civil_to_unix(y, mo, d, h, min, s)))
    }

    /// Parse a macOS unified-log timestamp: `"YYYY-MM-DD HH:MM:SS.ffffff±HHMM"`
    /// (local time with an explicit UTC offset, as emitted by
    /// `log show --style ndjson`). The offset is applied to yield UTC.
    pub fn from_log_show(s: &str) -> Option<Self> {
        let base = Self::from_rfc3339(s)?; // parses the fixed-position date/time
        // Find the trailing ±HHMM offset (after the seconds/fraction).
        let tail = &s[19..];
        let sign_pos = tail.find(['+', '-'])?;
        let sign = if tail.as_bytes()[sign_pos] == b'+' { 1 } else { -1 };
        let digits = &tail[sign_pos + 1..];
        if digits.len() < 4 || !digits.as_bytes()[..4].iter().all(u8::is_ascii_digit) {
            return None;
        }
        let hh: i64 = digits[..2].parse().ok()?;
        let mm: i64 = digits[2..4].parse().ok()?;
        // Local = UTC + offset ⇒ UTC = parsed-as-if-UTC − offset.
        Some(Timestamp(base.0 - sign * (hh * 3600 + mm * 60)))
    }

    pub fn secs_since(self, earlier: Self) -> i64 { self.0 - earlier.0 }

    pub fn add_secs(self, s: i64) -> Self { Timestamp(self.0 + s) }

    /// Seconds elapsed since local-time midnight of the day this timestamp falls on.
    /// Used to compute local day boundaries ("today", "yesterday") without a
    /// timezone-math library: `self.add_secs(-self.secs_into_local_day())` is
    /// local midnight.
    pub fn secs_into_local_day(self) -> i64 {
        let c = local_civil(self);
        c.h * 3600 + c.mi * 60 + c.s
    }

    /// "YYYY-MM-DD HH:MM:SS" in local time.
    pub fn format_dt(self) -> String {
        let c = local_civil(self);
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", c.y, c.mo, c.d, c.h, c.mi, c.s)
    }

    /// "HH:MM:SS" in local time.
    pub fn format_t(self) -> String {
        let c = local_civil(self);
        format!("{:02}:{:02}:{:02}", c.h, c.mi, c.s)
    }

    /// RFC 3339 (UTC), for JSON output.
    pub fn to_rfc3339(self) -> String {
        let c = unix_to_civil(self.0);
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", c.y, c.mo, c.d, c.h, c.mi, c.s)
    }
}

// ── Local time (platform-specific) ──────────────────────────────────────────────

/// Windows: convert via `FileTimeToLocalFileTime` + `FileTimeToSystemTime`.
#[cfg(windows)]
fn local_civil(ts: Timestamp) -> Civil {
    use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows::Win32::Storage::FileSystem::FileTimeToLocalFileTime;
    use windows::Win32::System::Time::FileTimeToSystemTime;

    /// 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
    const FT_EPOCH: i64 = 11_644_473_600;
    let v = ((ts.0 + FT_EPOCH) * 10_000_000).max(0);
    let ft = FILETIME {
        dwLowDateTime:  (v & 0xFFFF_FFFF) as u32,
        dwHighDateTime: ((v >> 32) & 0xFFFF_FFFF) as u32,
    };
    unsafe {
        let mut lft = FILETIME::default();
        let mut st  = SYSTEMTIME::default();
        if FileTimeToLocalFileTime(&ft, &mut lft).is_err()
            || FileTimeToSystemTime(&lft, &mut st).is_err()
        {
            return unix_to_civil(ts.0);
        }
        Civil {
            y:  st.wYear   as i64, mo: st.wMonth  as i64, d:  st.wDay    as i64,
            h:  st.wHour   as i64, mi: st.wMinute as i64, s:  st.wSecond as i64,
        }
    }
}

/// Unix: convert via libc `localtime_r`, which consults the system timezone
/// database. Falls back to UTC if the conversion fails.
#[cfg(unix)]
fn local_civil(ts: Timestamp) -> Civil {
    // libc deprecates `time_t` on musl pending its move to 64-bit (already
    // 64-bit on x86_64). The `as` cast tracks whatever width the alias has,
    // so this is the future-proof form — just quiet the advisory lint.
    #[allow(deprecated)]
    let t = ts.0 as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::localtime_r(&t, &mut tm) };
    if r.is_null() { return unix_to_civil(ts.0); }
    Civil {
        y:  tm.tm_year as i64 + 1900, mo: tm.tm_mon as i64 + 1, d:  tm.tm_mday as i64,
        h:  tm.tm_hour as i64,        mi: tm.tm_min as i64,     s:  tm.tm_sec  as i64,
    }
}

/// Platforms with neither Win32 nor libc: fall back to UTC.
#[cfg(not(any(windows, unix)))]
fn local_civil(ts: Timestamp) -> Civil { unix_to_civil(ts.0) }

// ── Pure-Rust civil-day conversions (Hinnant) ───────────────────────────────────

fn p4(b: &[u8]) -> Option<u32> {
    b.iter().try_fold(0u32, |a, &c| {
        if c.is_ascii_digit() { Some(a * 10 + (c - b'0') as u32) } else { None }
    })
}

fn p2(b: &[u8]) -> Option<u32> { p4(b) }

/// Hinnant's civil-days algorithm: Gregorian date → Unix seconds (UTC).
fn civil_to_unix(y: i64, m: i64, d: i64, h: i64, min: i64, s: i64) -> i64 {
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) * 86_400 + h * 3600 + min * 60 + s
}

/// Inverse of `civil_to_unix`: Unix seconds (UTC) → broken-down UTC calendar time.
/// Hinnant's `civil_from_days`, extended to include the intra-day clock.
fn unix_to_civil(secs: i64) -> Civil {
    let days = secs.div_euclid(86_400);
    let rem  = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z   = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;                         // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y   = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);   // [0, 365]
    let mp  = (5 * doy + 2) / 153;                        // [0, 11]
    let d   = doy - (153 * mp + 2) / 5 + 1;              // [1, 31]
    let m   = if mp < 10 { mp + 3 } else { mp - 9 };     // [1, 12]

    Civil { y: if m <= 2 { y + 1 } else { y }, mo: m, d, h, mi, s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_round_trips() {
        let t = Timestamp(0);
        assert_eq!(t.to_rfc3339(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_date_parses_correctly() {
        // 2024-01-15T10:30:00Z → Unix 1705314600
        let t = Timestamp::from_rfc3339("2024-01-15T10:30:00.0000000Z").unwrap();
        assert_eq!(t.0, 1_705_314_600);
    }

    #[test]
    fn secs_since_symmetric() {
        let a = Timestamp(1000);
        let b = Timestamp(1100);
        assert_eq!(b.secs_since(a), 100);
        assert_eq!(a.secs_since(b), -100);
    }

    #[test]
    fn add_secs_roundtrip() {
        let t = Timestamp(5000);
        assert_eq!(t.add_secs(200).secs_since(t), 200);
    }

    #[test]
    fn from_log_show_parses_offsets() {
        // 2024-01-15T10:30:00Z reference point (Unix 1705314600).
        assert_eq!(Timestamp::from_log_show("2024-01-15 10:30:00.000000+0000"),
                   Some(Timestamp(1_705_314_600)));
        assert_eq!(Timestamp::from_log_show("2024-01-15 18:30:00.123456+0800"),
                   Some(Timestamp(1_705_314_600)));
        assert_eq!(Timestamp::from_log_show("2024-01-15 05:30:00.000000-0500"),
                   Some(Timestamp(1_705_314_600)));
        assert_eq!(Timestamp::from_log_show("garbage"), None);
        assert_eq!(Timestamp::from_log_show("2024-01-15 10:30:00"), None); // no offset
    }

    #[test]
    fn to_rfc3339_is_portable_utc() {
        // 2024-01-15T10:30:00Z → Unix 1705314600 (no platform APIs involved).
        assert_eq!(Timestamp(1_705_314_600).to_rfc3339(), "2024-01-15T10:30:00Z");
    }

    #[test]
    fn civil_roundtrip_over_many_dates() {
        // Every conversion Unix→civil→Unix must be lossless across a wide range.
        for &secs in &[
            0i64, 1, 86_399, 86_400, 951_782_400, /* 2000-02-29 leap */
            1_582_934_400, 1_705_314_600, 4_102_444_800, /* 2100-01-01 */
        ] {
            let c = unix_to_civil(secs);
            assert_eq!(civil_to_unix(c.y, c.mo, c.d, c.h, c.mi, c.s), secs, "secs={secs}");
        }
    }

    #[test]
    fn unix_to_civil_known_leap_day() {
        let c = unix_to_civil(951_782_400); // 2000-02-29T00:00:00Z
        assert_eq!((c.y, c.mo, c.d), (2000, 2, 29));
    }
}
