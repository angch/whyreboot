// SPDX-License-Identifier: MIT OR Apache-2.0
//! Windows Event Log fetching: System channel, WER (Application channel), and minidump listing.

use std::ffi::c_void;
use std::path::PathBuf;
use windows::Win32::System::EventLog::*;
use crate::timestamp::Timestamp;
use crate::types::{EventRecord, WerRecord};
use crate::xml::parse_event;

/// Generic `EvtQuery` wrapper. Returns up to `limit` parsed events from the given
/// `channel` using the provided XPath `query_str`, newest first
/// (`EvtQueryReverseDirection`). Silently returns empty on query failure.
pub fn fetch_channel(channel: &[u16], query_str: &[u16], limit: usize) -> Vec<EventRecord> {
    let mut records = Vec::new();
    unsafe {
        let h_results = match EvtQuery(
            None,
            windows::core::PCWSTR(channel.as_ptr()),
            windows::core::PCWSTR(query_str.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        ) {
            Ok(h)  => h,
            Err(_) => return records,
        };

        let mut handles = [0isize; 16];
        'outer: loop {
            let mut returned = 0u32;
            if EvtNext(h_results, &mut handles, 5000, 0, &mut returned).is_err()
                || returned == 0
            {
                break;
            }
            for (i, &h) in handles[..returned as usize].iter().enumerate() {
                let h_ev = EVT_HANDLE(h);
                let mut needed = 0u32;
                let mut pc    = 0u32;
                let _ = EvtRender(None, h_ev, EvtRenderEventXml.0, 0, None, &mut needed, &mut pc);
                if needed > 0 {
                    let mut buf = vec![0u16; (needed as usize).div_ceil(2) + 1];
                    if EvtRender(
                        None,
                        h_ev,
                        EvtRenderEventXml.0,
                        needed,
                        Some(buf.as_mut_ptr() as *mut c_void),
                        &mut needed,
                        &mut pc,
                    )
                    .is_ok()
                    {
                        // `needed` is the byte count including the UTF-16 null
                        // terminator; strip it so the resulting String is clean.
                        let char_count = needed as usize / 2;
                        let end = if char_count > 0 && buf.get(char_count - 1) == Some(&0) {
                            char_count - 1
                        } else {
                            char_count
                        };
                        let xml = String::from_utf16_lossy(&buf[..end]);
                        if let Some(rec) = parse_event(&xml) {
                            records.push(rec);
                        }
                    }
                }
                let _ = EvtClose(h_ev);
                if records.len() >= limit {
                    // EvtNext already handed us the rest of this batch; close
                    // those handles too or they leak on early exit.
                    for &h_rest in &handles[i + 1..returned as usize] {
                        let _ = EvtClose(EVT_HANDLE(h_rest));
                    }
                    break 'outer;
                }
            }
        }
        let _ = EvtClose(h_results);
    }
    records
}

/// Fetches up to 300 shutdown/boot-related events from the System log.
/// Covers Event IDs: 12 (boot), 13 (shutdown), 41 (unexpected shutdown),
/// 109 (power button), 1074 (process-initiated shutdown), 1076 (shutdown reason),
/// 6006 (log stopped cleanly), 6008 (previous shutdown unexpected), 6009 (version),
/// 6013 (uptime).
pub fn fetch_system_events() -> Vec<EventRecord> {
    let ch: Vec<u16> = "System\0".encode_utf16().collect();
    let q: Vec<u16> =
        "*[System[(EventID=12 or EventID=13 or EventID=41 or EventID=109 \
          or EventID=1074 or EventID=1076 \
          or EventID=6006 or EventID=6008 or EventID=6009 or EventID=6013)]]\0"
            .encode_utf16()
            .collect();
    fetch_channel(&ch, &q, 300)
}

/// Maximum length kept for any single WER text field (see trust-boundary note below).
const MAX_WER_FIELD_LEN: usize = 4096;

/// Truncates `s` to at most `MAX_WER_FIELD_LEN` chars, on a char boundary.
fn clamp_field(s: &str) -> String {
    match s.char_indices().nth(MAX_WER_FIELD_LEN) {
        Some((byte_idx, _)) => s[..byte_idx].to_string(),
        None => s.to_string(),
    }
}

/// Fetches WER BugCheck records from the Application log (Event 1001).
/// Filters to records where the provider name contains "error reporting" or "wer"
/// and `EventName` is `"BlueScreen"` or `"BugCheck"` (both accepted defensively).
/// Parses `P1` as bare hex (no `0x` prefix) for the stop code.
/// Falls back through `Bucket` → `BucketId` → `HashedBucket` → `_0` for the bucket field.
///
/// Trust boundary: any unprivileged local process can write an Event 1001 to the
/// Application log via `ReportEvent` — these fields are not privileged. They are
/// only ever displayed (never opened or executed), and `annotate_wer_module`
/// additionally requires the stop code and time window to match a real Event 41
/// before using them, so a spoofed record can at worst mislabel the faulting
/// module in the diagnosis, not cause code execution or a file-system read.
/// Field lengths are still clamped defensively so a malicious record can't bloat
/// the displayed output.
pub fn fetch_wer_events() -> Vec<WerRecord> {
    let ch: Vec<u16> = "Application\0".encode_utf16().collect();
    let q: Vec<u16>  = "*[System[EventID=1001]]\0".encode_utf16().collect();

    fetch_channel(&ch, &q, 100)
        .into_iter()
        .filter_map(|ev| {
            let prov = ev.provider.to_lowercase();
            if !prov.contains("error reporting") && !prov.contains("wer") {
                return None;
            }
            let event_name = ev.get("EventName").unwrap_or("");
            if !event_name.eq_ignore_ascii_case("BlueScreen")
                && !event_name.eq_ignore_ascii_case("BugCheck")
            {
                return None;
            }
            let p1 = ev.get("P1")
                .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
                .unwrap_or(0);
            let bucket_id = ev.get("Bucket")
                .or_else(|| ev.get("BucketId"))
                .or_else(|| ev.get("HashedBucket"))
                .or_else(|| ev.get("_0"))
                .unwrap_or_default();
            let bucket_id = clamp_field(bucket_id);
            let minidump_path = ev.get("AttachedFiles").and_then(|s| {
                s.lines()
                    .map(|l| l.trim())
                    .find(|l| l.to_lowercase().ends_with(".dmp"))
                    .map(|l| PathBuf::from(clamp_field(l.trim_start_matches(r"\\?\"))))
            });
            Some(WerRecord { time_created: ev.time_created, p1, bucket_id, minidump_path })
        })
        .collect()
}

/// Lists `*.dmp` files in `%SystemRoot%\Minidump`, sorted newest first.
/// Returns an empty vec if the directory cannot be read (no admin rights, or dir absent).
pub fn list_minidumps() -> Vec<(Timestamp, PathBuf)> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let dir = PathBuf::from(sysroot).join("Minidump");
    let Ok(rd) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut v: Vec<(Timestamp, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("dmp"))
        })
        .filter_map(|e| {
            let mt = e.metadata().ok()?.modified().ok()?;
            Some((Timestamp::from_system_time(mt), e.path()))
        })
        .collect();
    v.sort_by_key(|b| std::cmp::Reverse(b.0));
    v
}
