// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parsing of human time-range expressions into a concrete [`TimeWindow`].
//!
//! The window is the single source of truth for "analyze issues over this
//! duration": it is used both to bound the log query (e.g. `journalctl
//! --since @<start>`) and to render the report header. Keeping one resolved
//! `TimeWindow` — rather than passing free-text to each backend — means the
//! displayed range always matches the range actually scanned.
//!
//! Supported expressions (case-insensitive):
//! - relative durations: `"1 hour ago"`, `"30 minutes ago"`, `"2 days ago"`,
//!   and compact forms `"1h"`, `"30m"`, `"2d"`, `"90s"`, `"1w"`
//! - `"today"` / `"earlier today"` — since local midnight
//! - `"yesterday"` — the previous local calendar day
//! - `"all"` / `"any"` / `"forever"` — unbounded

use crate::timestamp::Timestamp;

/// A resolved, inclusive-ish time range. `None` bounds are open (unbounded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeWindow {
    pub start: Option<Timestamp>,
    pub end:   Option<Timestamp>,
}

impl TimeWindow {
    /// Fully open window (everything).
    pub fn all() -> Self { TimeWindow { start: None, end: None } }

    /// Window covering the last `secs` seconds up to `now`.
    pub fn last_secs(now: Timestamp, secs: i64) -> Self {
        TimeWindow { start: Some(now.add_secs(-secs)), end: None }
    }

    /// True if `t` falls within the window (open bounds always pass).
    pub fn contains(&self, t: Timestamp) -> bool {
        self.start.is_none_or(|s| t >= s) && self.end.is_none_or(|e| t <= e)
    }

    /// A short "since …" / "… → …" description for the report header.
    pub fn describe(&self) -> String {
        match (self.start, self.end) {
            (Some(s), None)    => format!("since {}", s.format_dt()),
            (Some(s), Some(e)) => format!("{} → {}", s.format_dt(), e.format_dt()),
            (None, Some(e))    => format!("up to {}", e.format_dt()),
            (None, None)       => "all available history".to_string(),
        }
    }
}

/// Parses a human time expression relative to `now`. Returns `None` if the text
/// is not understood, so the caller can report the error instead of silently
/// defaulting to a surprising range.
pub fn parse_window(expr: &str, now: Timestamp) -> Option<TimeWindow> {
    let e = expr.trim().to_lowercase();
    let e = e.trim();

    match e {
        "all" | "any" | "forever" | "everything" => return Some(TimeWindow::all()),
        "today" | "earlier today" | "so far today" => {
            let start = now.add_secs(-now.secs_into_local_day());
            return Some(TimeWindow { start: Some(start), end: None });
        }
        "yesterday" => {
            let today_midnight = now.add_secs(-now.secs_into_local_day());
            let start = today_midnight.add_secs(-86_400);
            return Some(TimeWindow { start: Some(start), end: Some(today_midnight) });
        }
        _ => {}
    }

    // Relative duration: "<n> <unit>[s] [ago]" or compact "<n><unit>".
    let secs = parse_duration_secs(e)?;
    Some(TimeWindow::last_secs(now, secs))
}

/// Parses a duration expression into seconds. Handles both worded forms
/// (`"2 hours ago"`, `"90 minutes"`) and compact forms (`"2h"`, `"90m"`).
fn parse_duration_secs(e: &str) -> Option<i64> {
    // Strip a trailing "ago" if present.
    let e = e.strip_suffix("ago").map(str::trim).unwrap_or(e);
    if e.is_empty() { return None; }

    // Split the leading numeric run from the unit (works for "2h" and "2 h").
    let digits_end = e.find(|c: char| !c.is_ascii_digit())?;
    if digits_end == 0 { return None; }
    let n: i64 = e[..digits_end].parse().ok()?;
    let unit = e[digits_end..].trim();

    let mult = match unit {
        "s" | "sec" | "secs" | "second" | "seconds"       => 1,
        "m" | "min" | "mins" | "minute" | "minutes"       => 60,
        "h" | "hr" | "hrs" | "hour" | "hours"             => 3_600,
        "d" | "day" | "days"                              => 86_400,
        "w" | "wk" | "week" | "weeks"                     => 604_800,
        _ => return None,
    };
    n.checked_mul(mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Timestamp = Timestamp(1_000_000_000);

    fn win(expr: &str) -> Option<TimeWindow> { parse_window(expr, NOW) }

    #[test]
    fn compact_durations() {
        assert_eq!(win("1h").unwrap().start, Some(Timestamp(1_000_000_000 - 3_600)));
        assert_eq!(win("30m").unwrap().start, Some(Timestamp(1_000_000_000 - 1_800)));
        assert_eq!(win("2d").unwrap().start, Some(Timestamp(1_000_000_000 - 172_800)));
        assert_eq!(win("90s").unwrap().start, Some(Timestamp(1_000_000_000 - 90)));
        assert_eq!(win("1w").unwrap().start, Some(Timestamp(1_000_000_000 - 604_800)));
    }

    #[test]
    fn worded_durations_with_ago() {
        assert_eq!(win("1 hour ago").unwrap().start, Some(Timestamp(1_000_000_000 - 3_600)));
        assert_eq!(win("2 hours ago").unwrap().start, Some(Timestamp(1_000_000_000 - 7_200)));
        assert_eq!(win("30 minutes ago").unwrap().start, Some(Timestamp(1_000_000_000 - 1_800)));
        assert_eq!(win("3 days ago").unwrap().start, Some(Timestamp(1_000_000_000 - 259_200)));
    }

    #[test]
    fn worded_durations_without_ago() {
        assert_eq!(win("45 minutes").unwrap().start, Some(Timestamp(1_000_000_000 - 2_700)));
    }

    #[test]
    fn case_insensitive_and_padded() {
        assert_eq!(win("  1 HOUR AGO  ").unwrap().start, Some(Timestamp(1_000_000_000 - 3_600)));
    }

    #[test]
    fn all_is_unbounded() {
        assert_eq!(win("all"), Some(TimeWindow::all()));
        assert_eq!(win("forever"), Some(TimeWindow::all()));
    }

    #[test]
    fn today_since_local_midnight_and_no_end() {
        let w = win("today").unwrap();
        assert!(w.start.is_some());
        assert!(w.end.is_none());
        // start is at or before now, and within the last 24h.
        let s = w.start.unwrap();
        assert!(s <= NOW && NOW.secs_since(s) < 86_400);
    }

    #[test]
    fn yesterday_is_a_bounded_day() {
        let w = win("yesterday").unwrap();
        let (s, e) = (w.start.unwrap(), w.end.unwrap());
        assert_eq!(e.secs_since(s), 86_400);
    }

    #[test]
    fn garbage_is_none() {
        assert!(win("").is_none());
        assert!(win("banana").is_none());
        assert!(win("h").is_none());
        assert!(win("5 lightyears").is_none());
    }

    #[test]
    fn contains_respects_bounds() {
        let w = TimeWindow { start: Some(Timestamp(100)), end: Some(Timestamp(200)) };
        assert!(!w.contains(Timestamp(99)));
        assert!(w.contains(Timestamp(100)));
        assert!(w.contains(Timestamp(150)));
        assert!(w.contains(Timestamp(200)));
        assert!(!w.contains(Timestamp(201)));
        assert!(TimeWindow::all().contains(Timestamp(0)));
    }
}
