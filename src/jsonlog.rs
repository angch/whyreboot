// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared JSON log-line parsing for the Linux (journald) and macOS (unified
//! log) backends — portable and unit-tested on every platform.
//!
//! Two newline-delimited JSON formats are understood, auto-detected per line:
//! - **journald** `journalctl -o json`: `MESSAGE`, `__REALTIME_TIMESTAMP`
//!   (microseconds since epoch), `SYSLOG_IDENTIFIER`, `_TRANSPORT`
//! - **macOS unified log** `log show --style ndjson`: `eventMessage`,
//!   `timestamp` (`"YYYY-MM-DD HH:MM:SS.ffffff+HHMM"`, local time with UTC
//!   offset), `process`, `subsystem`
//!
//! Both map onto the same normalized [`LogLine`]; macOS `process` becomes
//! `identifier` (so `process == "kernel"` satisfies the detectors' kernel
//! checks) and `subsystem` becomes `transport`.

use std::io;
use std::path::Path;

use crate::timestamp::Timestamp;
use crate::types::LogLine;

/// Reads a file of newline-delimited JSON records in either supported format
/// (test seam and offline analysis for both platforms).
pub fn fetch_from_file(path: &Path) -> io::Result<Vec<LogLine>> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_json_lines(&text))
}

/// Parses every non-empty line into a [`LogLine`], auto-detecting the format
/// and silently skipping lines that lack a usable message or timestamp.
pub fn parse_json_lines(text: &str) -> Vec<LogLine> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(line_to_log)
        .collect()
}

fn line_to_log(line: &str) -> Option<LogLine> {
    let fields = parse_flat_json(line);
    let get = |k: &str| fields.iter().find(|(f, _)| f == k).map(|(_, v)| v.as_str());

    if let Some(message) = get("MESSAGE") {
        // journald: __REALTIME_TIMESTAMP is microseconds since the Unix epoch.
        let micros: i64 = get("__REALTIME_TIMESTAMP")?.parse().ok()?;
        return Some(LogLine {
            time:       Timestamp(micros / 1_000_000),
            message:    message.to_string(),
            identifier: get("SYSLOG_IDENTIFIER").unwrap_or("").to_string(),
            transport:  get("_TRANSPORT").unwrap_or("").to_string(),
        });
    }

    if let Some(message) = get("eventMessage") {
        // macOS unified log (`log show --style ndjson`).
        let time = Timestamp::from_log_show(get("timestamp")?)?;
        return Some(LogLine {
            time,
            message:    message.to_string(),
            identifier: get("process").unwrap_or("").to_string(),
            transport:  get("subsystem").unwrap_or("").to_string(),
        });
    }

    None
}

/// Minimal parser for one line of flat-ish JSON: an object whose values are
/// JSON strings, arrays, objects, or bare literals. Returns the string-valued
/// and bare-literal fields; array/object values (journald binary blobs, macOS
/// `backtrace` objects) are skipped.
pub fn parse_flat_json(s: &str) -> Vec<(String, String)> {
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
    fn parses_macos_log_show_ndjson_line() {
        // Field shapes from `log show --style ndjson` (nested backtrace skipped).
        let line = r#"{"traceID":123,"eventMessage":"Previous shutdown cause: -61","eventType":"logEvent","backtrace":{"frames":[{"imageOffset":1}]},"subsystem":"","category":"","timestamp":"2024-01-15 10:30:00.123456+0000","process":"kernel","processID":0}"#;
        let ll = line_to_log(line).expect("parse");
        assert_eq!(ll.time, Timestamp(1_705_314_600));
        assert_eq!(ll.identifier, "kernel");
        assert!(ll.message.contains("shutdown cause"));
    }

    #[test]
    fn macos_timestamp_offset_respected() {
        // +0800: local 18:30 is 10:30 UTC.
        let line = r#"{"eventMessage":"x","timestamp":"2024-01-15 18:30:00.000000+0800","process":"kernel"}"#;
        let ll = line_to_log(line).expect("parse");
        assert_eq!(ll.time, Timestamp(1_705_314_600));
    }

    #[test]
    fn skips_array_valued_fields() {
        // Binary MESSAGE arrives as an array; the record is dropped (no usable message).
        let line = r#"{"MESSAGE":[72,105],"__REALTIME_TIMESTAMP":"1700000000000000","SYSLOG_IDENTIFIER":"kernel"}"#;
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
