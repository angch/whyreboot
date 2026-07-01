// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal timestamp replacing chrono::DateTime<Local>.
//! Stored as i64 (seconds since Unix epoch, UTC); formatted in local time via Win32 APIs.

use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::Storage::FileSystem::FileTimeToLocalFileTime;
use windows::Win32::System::Time::FileTimeToSystemTime;

/// Seconds since Unix epoch (1970-01-01 00:00:00 UTC).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Timestamp(pub i64);

/// 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
const FT_EPOCH: i64 = 11_644_473_600;

impl Timestamp {
    pub fn now() -> Self {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        Timestamp(d.as_secs() as i64)
    }

    pub fn from_system_time(st: SystemTime) -> Self {
        let d = st.duration_since(UNIX_EPOCH).unwrap_or_default();
        Timestamp(d.as_secs() as i64)
    }

    /// Parse a Windows Event Log timestamp: "YYYY-MM-DDTHH:MM:SS…" (always UTC).
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

    pub fn secs_since(self, earlier: Self) -> i64 { self.0 - earlier.0 }

    pub fn add_secs(self, s: i64) -> Self { Timestamp(self.0 + s) }

    /// "YYYY-MM-DD HH:MM:SS" in local time.
    pub fn format_dt(self) -> String {
        let s = local_st(self);
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute, s.wSecond)
    }

    /// "HH:MM:SS" in local time.
    pub fn format_t(self) -> String {
        let s = local_st(self);
        format!("{:02}:{:02}:{:02}", s.wHour, s.wMinute, s.wSecond)
    }

    /// RFC 3339 (UTC), for JSON output.
    pub fn to_rfc3339(self) -> String {
        let s = utc_st(self);
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute, s.wSecond)
    }
}

fn to_ft(ts: Timestamp) -> FILETIME {
    let v = ts.0.saturating_add(FT_EPOCH).saturating_mul(10_000_000);
    let v = v.max(0);
    FILETIME {
        dwLowDateTime:  (v & 0xFFFF_FFFF) as u32,
        dwHighDateTime: ((v >> 32) & 0xFFFF_FFFF) as u32,
    }
}

fn local_st(ts: Timestamp) -> SYSTEMTIME {
    let ft = to_ft(ts);
    unsafe {
        let mut lft = FILETIME::default();
        let mut st  = SYSTEMTIME::default();
        let _ = FileTimeToLocalFileTime(&ft, &mut lft);
        let _ = FileTimeToSystemTime(&lft, &mut st);
        st
    }
}

fn utc_st(ts: Timestamp) -> SYSTEMTIME {
    let ft = to_ft(ts);
    unsafe {
        let mut st = SYSTEMTIME::default();
        let _ = FileTimeToSystemTime(&ft, &mut st);
        st
    }
}

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
}
