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
use std::path::Path;
use std::process::Command;

use crate::timestamp::Timestamp;
use crate::timewindow::TimeWindow;
use crate::types::LogLine;

/// Markers for userspace / systemd issues, queried across the whole journal as a
/// `--grep` alternation. Unlike the kernel stream (which is small and fetched in
/// full), the general journal is large, so a filter is required here.
const USER_GREP: &str = "Failed with result|Main process exited|entered failed state|\
Start request repeated too quickly|Failed to start|dumped core|\
due to memory pressure|due to swap";

/// Fetches journal records relevant to issue detection within `window`, merging
/// the kernel stream, the systemd-oomd unit, and userspace/systemd issue lines.
pub fn fetch_journal(window: &TimeWindow) -> io::Result<Vec<LogLine>> {
    let mut lines = Vec::new();

    // Kernel ring buffer, fetched UNFILTERED within the window. Deliberately no
    // `--grep`: the detectors filter precisely, and a rejected/misparsed grep
    // pattern makes journalctl exit 0 with empty output — silently blinding the
    // correctness-critical kernel path (OOM, panic, disk errors). A windowed
    // `-k` is small, so fetching it all is cheap and cannot silently drop events.
    lines.append(&mut run_journalctl(&["-k"], window, None)?);

    // systemd-oomd unit (userspace OOM killer). Absent unit → empty, not an error.
    if let Ok(mut v) = run_journalctl(&["-u", "systemd-oomd"], window, None) {
        lines.append(&mut v);
    }

    // Userspace/systemd issues (service failures, coredumps) across the whole
    // journal. --grep is a necessary volume filter here; if the local journalctl
    // rejects it we retry unfiltered rather than silently drop these categories.
    match run_journalctl(&[], window, Some(USER_GREP)) {
        Ok(mut v) => lines.append(&mut v),
        Err(_)    => { let _ = run_journalctl(&[], window, None).map(|mut v| lines.append(&mut v)); }
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
pub fn fetch_from_file(path: &Path) -> io::Result<Vec<LogLine>> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_json_lines(&text))
}

/// Runs `journalctl` with the given extra args plus JSON output and the window
/// bounds, returning parsed lines. `grep` (if any) is passed as `--grep`.
fn run_journalctl(extra: &[&str], window: &TimeWindow, grep: Option<&str>) -> io::Result<Vec<LogLine>> {
    let mut cmd = Command::new("journalctl");
    cmd.args(extra);
    cmd.args(["-o", "json", "--no-pager"]);

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
    if let Some(g) = grep {
        cmd.args(["--grep", g]);
    }

    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "journalctl {:?} failed: {}",
            extra,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(parse_json_lines(&String::from_utf8_lossy(&out.stdout)))
}

/// Parses every non-empty line of `-o json` output into a [`LogLine`],
/// silently skipping lines that lack a usable message or timestamp.
fn parse_json_lines(text: &str) -> Vec<LogLine> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(line_to_log)
        .collect()
}

fn line_to_log(line: &str) -> Option<LogLine> {
    let fields = parse_flat_json(line);
    let get = |k: &str| fields.iter().find(|(f, _)| f == k).map(|(_, v)| v.as_str());

    let message = get("MESSAGE")?.to_string();
    // __REALTIME_TIMESTAMP is microseconds since the Unix epoch.
    let micros: i64 = get("__REALTIME_TIMESTAMP")?.parse().ok()?;
    Some(LogLine {
        time:       Timestamp(micros / 1_000_000),
        message,
        identifier: get("SYSLOG_IDENTIFIER").unwrap_or("").to_string(),
        transport:  get("_TRANSPORT").unwrap_or("").to_string(),
    })
}

/// Minimal parser for one line of journald `-o json`: a flat object whose values
/// are JSON strings, arrays, or bare literals. Returns the string-valued fields;
/// array/object values (e.g. binary MESSAGE blobs) are skipped. Nesting beyond
/// one level is not expected in journald output.
fn parse_flat_json(s: &str) -> Vec<(String, String)> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut out = Vec::new();

    // Skip to opening brace.
    while i < b.len() && b[i] != b'{' { i += 1; }
    if i < b.len() { i += 1; }

    loop {
        skip_ws(b, &mut i);
        if i >= b.len() || b[i] == b'}' { break; }
        if b[i] != b'"' { break; } // malformed key

        let Some(key) = parse_json_string(b, &mut i) else { break };
        skip_ws(b, &mut i);
        if i >= b.len() || b[i] != b':' { break; }
        i += 1;
        skip_ws(b, &mut i);
        if i >= b.len() { break; }

        match b[i] {
            b'"' => {
                if let Some(val) = parse_json_string(b, &mut i) {
                    out.push((key, val));
                }
            }
            b'[' => skip_balanced(b, &mut i, b'[', b']'),
            b'{' => skip_balanced(b, &mut i, b'{', b'}'),
            _ => {
                // Bare literal (number/true/false/null): capture verbatim.
                let start = i;
                while i < b.len() && b[i] != b',' && b[i] != b'}' { i += 1; }
                let val = s[start..i].trim().to_string();
                out.push((key, val));
            }
        }

        skip_ws(b, &mut i);
        if i < b.len() && b[i] == b',' { i += 1; }
    }
    out
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && (b[*i] as char).is_whitespace() { *i += 1; }
}

/// Parses a JSON string starting at `b[*i] == '"'`, advancing past the closing
/// quote. Decodes standard escapes and `\uXXXX` (BMP) sequences.
fn parse_json_string(b: &[u8], i: &mut usize) -> Option<String> {
    if *i >= b.len() || b[*i] != b'"' { return None; }
    *i += 1;
    let mut s = String::new();
    while *i < b.len() {
        let c = b[*i];
        *i += 1;
        match c {
            b'"' => return Some(s),
            b'\\' => {
                if *i >= b.len() { return None; }
                let e = b[*i];
                *i += 1;
                match e {
                    b'"'  => s.push('"'),
                    b'\\' => s.push('\\'),
                    b'/'  => s.push('/'),
                    b'n'  => s.push('\n'),
                    b't'  => s.push('\t'),
                    b'r'  => s.push('\r'),
                    b'b'  => s.push('\u{0008}'),
                    b'f'  => s.push('\u{000C}'),
                    b'u'  => {
                        if *i + 4 > b.len() { return None; }
                        let hex = std::str::from_utf8(&b[*i..*i + 4]).ok()?;
                        let cp = u32::from_str_radix(hex, 16).ok()?;
                        *i += 4;
                        s.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                    }
                    other => s.push(other as char),
                }
            }
            // Multi-byte UTF-8: copy the continuation bytes verbatim.
            0x80..=0xFF => {
                let start = *i - 1;
                while *i < b.len() && (b[*i] & 0xC0) == 0x80 { *i += 1; }
                if let Ok(chunk) = std::str::from_utf8(&b[start..*i]) {
                    s.push_str(chunk);
                }
            }
            _ => s.push(c as char),
        }
    }
    None // unterminated
}

/// Advances `*i` past a balanced `open`/`close` region, respecting JSON strings.
fn skip_balanced(b: &[u8], i: &mut usize, open: u8, close: u8) {
    let mut depth = 0i32;
    while *i < b.len() {
        match b[*i] {
            b'"' => { let _ = parse_json_string(b, i); continue; }
            c if c == open  => depth += 1,
            c if c == close => { depth -= 1; if depth == 0 { *i += 1; return; } }
            _ => {}
        }
        *i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_journalctl_json_line() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1700000000000000","_TRANSPORT":"kernel","MESSAGE":"Out of memory: Killed process 4242 (chrome) total-vm:1kB","PRIORITY":"3","SYSLOG_IDENTIFIER":"kernel"}"#;
        let ll = line_to_log(line).expect("parse");
        assert_eq!(ll.time, Timestamp(1_700_000_000));
        assert_eq!(ll.transport, "kernel");
        assert_eq!(ll.identifier, "kernel");
        assert!(ll.message.contains("chrome"));
    }

    #[test]
    fn skips_array_valued_fields() {
        // Binary MESSAGE arrives as an array; a plain field after it must still parse.
        let line = r#"{"MESSAGE":[72,105],"__REALTIME_TIMESTAMP":"1700000000000000","SYSLOG_IDENTIFIER":"kernel"}"#;
        // MESSAGE is an array → no MESSAGE field → line dropped (no usable message).
        assert!(line_to_log(line).is_none());
    }

    #[test]
    fn handles_escapes_in_message() {
        let line = r#"{"MESSAGE":"a \"quote\" and \\ and A","__REALTIME_TIMESTAMP":"1700000000000000"}"#;
        let ll = line_to_log(line).expect("parse");
        assert_eq!(ll.message, "a \"quote\" and \\ and A");
    }

    #[test]
    fn parse_flat_json_extracts_pairs() {
        let f = parse_flat_json(r#"{"a":"1","b":"two","c":[1,2],"d":"x"}"#);
        let get = |k: &str| f.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
        assert_eq!(get("a"), Some("1".into()));
        assert_eq!(get("b"), Some("two".into()));
        assert_eq!(get("c"), None); // array skipped
        assert_eq!(get("d"), Some("x".into()));
    }

    #[test]
    fn parse_multiple_lines_and_filters_blank() {
        let text = "\n{\"MESSAGE\":\"m1\",\"__REALTIME_TIMESTAMP\":\"1700000000000000\"}\n\n{\"MESSAGE\":\"m2\",\"__REALTIME_TIMESTAMP\":\"1700000001000000\"}\n";
        let v = parse_json_lines(text);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].message, "m1");
        assert_eq!(v[1].message, "m2");
    }
}
