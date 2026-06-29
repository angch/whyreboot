use std::ffi::c_void;
use std::path::PathBuf;
use chrono::{DateTime, Local};
use windows::Win32::System::EventLog::*;
use crate::types::{EventRecord, WerRecord};
use crate::xml::parse_event;

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
            for &h in &handles[..returned as usize] {
                let h_ev = EVT_HANDLE(h);
                let mut needed = 0u32;
                let mut pc    = 0u32;
                let _ = EvtRender(None, h_ev, EvtRenderEventXml.0, 0, None, &mut needed, &mut pc);
                if needed > 0 {
                    let mut buf = vec![0u16; (needed as usize + 1) / 2 + 1];
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
                        let xml = String::from_utf16_lossy(&buf[..needed as usize / 2]);
                        if let Some(rec) = parse_event(&xml) {
                            records.push(rec);
                        }
                    }
                }
                let _ = EvtClose(h_ev);
                if records.len() >= limit {
                    break 'outer;
                }
            }
        }
        let _ = EvtClose(h_results);
    }
    records
}

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
            let event_name = ev.data.get("EventName").map(|s| s.as_str()).unwrap_or("");
            if !event_name.eq_ignore_ascii_case("BlueScreen")
                && !event_name.eq_ignore_ascii_case("BugCheck")
            {
                return None;
            }
            let p1 = ev
                .data
                .get("P1")
                .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
                .unwrap_or(0);
            let bucket_id = ev
                .data
                .get("Bucket")
                .or_else(|| ev.data.get("BucketId"))
                .or_else(|| ev.data.get("HashedBucket"))
                .or_else(|| ev.data.get("_0"))
                .cloned()
                .unwrap_or_default();
            let minidump_path = ev.data.get("AttachedFiles").and_then(|s| {
                s.lines()
                    .map(|l| l.trim())
                    .find(|l| l.to_lowercase().ends_with(".dmp"))
                    .map(|l| PathBuf::from(l.trim_start_matches(r"\\?\")))
            });
            Some(WerRecord { time_created: ev.time_created, p1, bucket_id, minidump_path })
        })
        .collect()
}

pub fn list_minidumps() -> Vec<(DateTime<Local>, PathBuf)> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let dir = PathBuf::from(sysroot).join("Minidump");
    let Ok(rd) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut v: Vec<(DateTime<Local>, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map_or(false, |x| x.eq_ignore_ascii_case("dmp"))
        })
        .filter_map(|e| {
            let mt = e.metadata().ok()?.modified().ok()?;
            Some((DateTime::<Local>::from(mt), e.path()))
        })
        .collect();
    v.sort_by(|a, b| b.0.cmp(&a.0));
    v
}
