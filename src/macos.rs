// SPDX-License-Identifier: MIT OR Apache-2.0
//! macOS log source: reads records from the unified log via `log show`.
//!
//! `log show --style ndjson` emits one JSON object per line (`eventMessage`,
//! `process`, `timestamp` with an explicit UTC offset), parsed by the shared
//! [`crate::jsonlog`] module into normalized [`LogLine`]s.
//!
//! Unlike journald there are no indexed field queries — `log show` always scans
//! its window — so volume is controlled with NSPredicate filters and by keeping
//! the time window tight (the CLI defaults to the last 24 hours; `--all` over a
//! long-lived install can take a while, which is inherent to `log show`).
//!
//! Provenance note: this backend has been compile- and unit-tested (fixtures in
//! the shared ndjson format) and builds in CI on macOS runners, but has **not**
//! been exercised against a live Mac during development.

use std::io;
use std::process::Command;

use crate::timewindow::TimeWindow;
use crate::types::LogLine;

/// NSPredicate limiting the scan to processes/messages the detectors understand.
/// Kept broad (superset) — the detectors classify precisely.
const PREDICATE: &str = "process == \"kernel\" \
OR process == \"ReportCrash\" \
OR process == \"softwareupdated\" \
OR process == \"osinstallersetupd\" \
OR eventMessage CONTAINS \"Previous shutdown cause\" \
OR eventMessage CONTAINS \"Sleep Wake failure\" \
OR eventMessage CONTAINS[c] \"panic\"";

/// Fetches unified-log records relevant to issue detection within `window`.
pub fn fetch_unified_log(window: &TimeWindow) -> io::Result<Vec<LogLine>> {
    let mut cmd = Command::new("log");
    cmd.args(["show", "--style", "ndjson", "--predicate", PREDICATE]);

    // `log show` accepts local-time "YYYY-MM-DD HH:MM:SS" for --start/--end;
    // Timestamp::format_dt renders exactly that in local time.
    let start;
    if let Some(s) = window.start {
        start = s.format_dt();
        cmd.args(["--start", &start]);
    }
    let end;
    if let Some(e) = window.end {
        end = e.format_dt();
        cmd.args(["--end", &end]);
    }

    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "log show failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(crate::jsonlog::parse_json_lines(&String::from_utf8_lossy(&out.stdout)))
}
