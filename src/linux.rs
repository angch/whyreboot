// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linux log source: reads records from the systemd journal via `journalctl`.
//!
//! `journalctl -o json` emits one flat JSON object per line, with all values as
//! JSON strings (binary fields become arrays, which we skip). We parse those into
//! normalized [`LogLine`]s for the platform-agnostic analyzers in [`crate::oom`].
//!
//! Two queries are issued and merged so both OOM killers are covered:
//! - `journalctl -k` — the kernel ring buffer (classic OOM killer)
//! - `journalctl -u systemd-oomd` — the userspace PSI-based killer
//!
//! For testing (and for analyzing captured logs), [`fetch_from_file`] reads the
//! same `-o json` line format from a file instead of invoking `journalctl`.

use std::io;
use std::process::Command;

use crate::timewindow::TimeWindow;
use crate::types::LogLine;

/// Fetches journal records relevant to issue detection within `window`, merging
/// the kernel stream, the systemd-oomd unit, and userspace/systemd issue lines.
///
/// **Performance:** every query matches only journald-*indexed* fields
/// (`_TRANSPORT`, `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `PRIORITY`) — never
/// `--grep`, which is an unindexed full-message scan that takes minutes over a
/// multi-gigabyte journal (the old `--all` never finished). Field matches use the
/// journal index, so `--all` returns in well under a second. The detectors then
/// classify precisely; the queries only need to be a superset of what matters.
pub fn fetch_journal(window: &TimeWindow) -> io::Result<Vec<LogLine>> {
    let mut lines = Vec::new();

    // Kernel ring buffer (`_TRANSPORT=kernel`), fetched UNFILTERED. Kernel lines
    // are sparse even in a huge journal, so this is cheap, and taking all of them
    // means a wording change in any kernel message can't silently drop an event.
    lines.append(&mut run_journalctl(&["-k"], window)?);

    // systemd-oomd unit (userspace OOM killer). Absent unit → empty, not an error.
    if let Ok(mut v) = run_journalctl(&["-u", "systemd-oomd"], window) {
        lines.append(&mut v);
    }

    // Service failures and coredumps. These come only from the `systemd` (PID 1 /
    // user manager) and `systemd-coredump` identifiers, and are always logged at
    // priority notice (5) or higher — while the tens of thousands of routine
    // unit start/stop lines are info (6). Intersecting the identifier and priority
    // indexes collapses ~90k lines to a few dozen in ~0.5s. Best-effort: a missing
    // identifier simply contributes nothing.
    let user = &["-p", "notice",
                 "SYSLOG_IDENTIFIER=systemd", "SYSLOG_IDENTIFIER=systemd-coredump"];
    if let Ok(mut v) = run_journalctl(user, window) {
        lines.append(&mut v);
    }

    // Graphical session: compositors and session managers, priority-gated because
    // gnome-shell/kwin chat a lot at info. Identifiers absent on servers/headless
    // boxes simply match nothing. (Best-effort, like the query above.)
    let graphical = &["-p", "notice",
                      "SYSLOG_IDENTIFIER=gnome-shell", "SYSLOG_IDENTIFIER=gnome-session-binary",
                      "SYSLOG_IDENTIFIER=kwin_wayland", "SYSLOG_IDENTIFIER=kwin_x11",
                      "SYSLOG_IDENTIFIER=plasmashell", "SYSLOG_IDENTIFIER=xdg-desktop-portal"];
    if let Ok(mut v) = run_journalctl(graphical, window) {
        lines.append(&mut v);
    }

    // X server logs arrive via gdm at info priority, so these two identifiers are
    // fetched unfiltered — their volume is modest (hundreds of lines per boot).
    let xorg = &["SYSLOG_IDENTIFIER=Xorg", "SYSLOG_IDENTIFIER=gdm-x-session",
                 "SYSLOG_IDENTIFIER=Xorg.bin"];
    if let Ok(mut v) = run_journalctl(xorg, window) {
        lines.append(&mut v);
    }

    dedup(&mut lines);
    Ok(lines)
}

/// Removes duplicate records (same timestamp and message) that can arise when a
/// line matches more than one query.
fn dedup(lines: &mut Vec<LogLine>) {
    let mut seen = std::collections::HashSet::new();
    lines.retain(|l| seen.insert((l.time.0, l.message.clone())));
}


/// Reads `journalctl -o json`-formatted lines from a file (test / offline seam).
/// Kept as a re-export so existing callers keep working; the implementation is
/// the shared, format-autodetecting parser in [`crate::jsonlog`].
pub use crate::jsonlog::fetch_from_file;

/// Runs `journalctl` with the given extra args plus JSON output and the window
/// bounds, returning parsed lines. `--output-fields` trims each record to the
/// four fields the detectors use, cutting journalctl's serialization and our
/// parsing cost (journald always also emits `__REALTIME_TIMESTAMP`).
fn run_journalctl(extra: &[&str], window: &TimeWindow) -> io::Result<Vec<LogLine>> {
    let mut cmd = Command::new("journalctl");
    cmd.args(extra);
    cmd.args(["-o", "json", "--no-pager",
              "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_TRANSPORT"]);

    // journalctl accepts `@<unix-seconds>` for absolute since/until.
    let since;
    if let Some(s) = window.start {
        since = format!("@{}", s.0);
        cmd.args(["--since", &since]);
    }
    let until;
    if let Some(e) = window.end {
        until = format!("@{}", e.0);
        cmd.args(["--until", &until]);
    }

    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "journalctl {:?} failed: {}",
            extra,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(crate::jsonlog::parse_json_lines(&String::from_utf8_lossy(&out.stdout)))
}
