use chrono::{DateTime, Duration, Local};
use std::path::PathBuf;
use crate::types::{BootCycle, Cause, EventRecord, WerRecord};

// ── Lookup tables ─────────────────────────────────────────────────────────────

const STOP_CODES: &[(u64, &str)] = &[
    (0x00000001, "APC_INDEX_MISMATCH"),
    (0x00000019, "BAD_POOL_HEADER"),
    (0x0000001A, "MEMORY_MANAGEMENT"),
    (0x0000001E, "KMODE_EXCEPTION_NOT_HANDLED"),
    (0x00000023, "FAT_FILE_SYSTEM"),
    (0x00000024, "NTFS_FILE_SYSTEM"),
    (0x0000002E, "DATA_BUS_ERROR"),
    (0x0000003B, "SYSTEM_SERVICE_EXCEPTION"),
    (0x0000003F, "NO_MORE_SYSTEM_PTES"),
    (0x00000050, "PAGE_FAULT_IN_NONPAGED_AREA"),
    (0x00000051, "REGISTRY_ERROR"),
    (0x0000005A, "CRITICAL_SERVICE_FAILED"),
    (0x0000005C, "HAL_INITIALIZATION_FAILED"),
    (0x00000074, "BAD_SYSTEM_CONFIG_INFO"),
    (0x00000076, "PROCESS_HAS_LOCKED_PAGES"),
    (0x00000077, "KERNEL_STACK_INPAGE_ERROR"),
    (0x0000007A, "KERNEL_DATA_INPAGE_ERROR"),
    (0x0000007B, "INACCESSIBLE_BOOT_DEVICE"),
    (0x0000007E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"),
    (0x0000007F, "UNEXPECTED_KERNEL_MODE_TRAP"),
    (0x00000080, "NMI_HARDWARE_FAILURE"),
    (0x0000008E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED"),
    (0x0000009C, "MACHINE_CHECK_EXCEPTION"),
    (0x0000009F, "DRIVER_POWER_STATE_FAILURE"),
    (0x000000A0, "INTERNAL_POWER_ERROR"),
    (0x000000A5, "ACPI_BIOS_ERROR"),
    (0x000000BE, "ATTEMPTED_WRITE_TO_READONLY_MEMORY"),
    (0x000000C1, "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION"),
    (0x000000C2, "BAD_POOL_CALLER"),
    (0x000000C4, "DRIVER_VERIFIER_DETECTED_VIOLATION"),
    (0x000000C5, "DRIVER_CORRUPTED_EXPOOL"),
    (0x000000CA, "PNP_DETECTED_FATAL_ERROR"),
    (0x000000D1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL"),
    (0x000000D4, "SYSTEM_SCAN_AT_RAISED_IRQL_CAUGHT_IMPROPER_DRIVER_UNLOAD"),
    (0x000000EA, "THREAD_STUCK_IN_DEVICE_DRIVER"),
    (0x000000ED, "UNMOUNTABLE_BOOT_VOLUME"),
    (0x000000EF, "CRITICAL_PROCESS_DIED"),
    (0x000000F4, "CRITICAL_OBJECT_TERMINATION"),
    (0x000000FC, "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY"),
    (0x000000FE, "BUGCODE_USB_DRIVER"),
    (0x00000101, "CLOCK_WATCHDOG_TIMEOUT"),
    (0x00000102, "DPC_WATCHDOG_TIMEOUT"),
    (0x00000109, "CRITICAL_STRUCTURE_CORRUPTION"),
    (0x0000010D, "WDF_VIOLATION"),
    (0x0000010E, "VIDEO_MEMORY_MANAGEMENT_INTERNAL"),
    (0x00000113, "VIDEO_DXGKRNL_FATAL_ERROR"),
    (0x00000116, "VIDEO_TDR_FAILURE"),
    (0x00000117, "VIDEO_TDR_TIMEOUT_DETECTED"),
    (0x00000119, "VIDEO_SCHEDULER_INTERNAL_ERROR"),
    (0x0000019C, "WIN32K_POWER_WATCHDOG_TIMEOUT"),
    (0x00000124, "WHEA_UNCORRECTABLE_ERROR"),
    (0x00000125, "NMR_INVALID_STATE"),
    (0x00000127, "PAGE_NOT_ZERO"),
    (0x00000133, "DPC_WATCHDOG_VIOLATION"),
    (0x00000139, "KERNEL_SECURITY_CHECK_FAILURE"),
    (0x0000013A, "KERNEL_MODE_HEAP_CORRUPTION"),
    (0x00000141, "VIDEO_ENGINE_TIMEOUT_DETECTED"),
    (0x00000144, "BUGCODE_USB3_DRIVER"),
    (0x00000154, "UNEXPECTED_STORE_EXCEPTION"),
    (0x00000155, "OS_DATA_TAMPERING"),
    (0x00000160, "WIN32K_ATOMIC_CHECK_FAILURE"),
    (0x00000162, "KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE"),
    (0x00000164, "WIN32K_CRITICAL_FAILURE"),
    (0x00000187, "VIDEO_DWMINIT_TIMEOUT_FALLBACK_BDD"),
    (0x00000189, "BAD_OBJECT_HEADER"),
    (0x0000018B, "SECURE_KERNEL_ERROR"),
    (0x000001C4, "DRIVER_VERIFIER_DETECTED_VIOLATION_LIVEDUMP"),
    (0xC000021A, "STATUS_SYSTEM_PROCESS_TERMINATED"),
    (0xC0000005, "STATUS_ACCESS_VIOLATION"),
    (0xC0000142, "STATUS_DLL_INIT_FAILED"),
];

pub fn stop_name(code: u64) -> &'static str {
    STOP_CODES
        .iter()
        .find(|&&(c, _)| c == code)
        .map(|&(_, n)| n)
        .unwrap_or("(unknown)")
}

const REASON_CODES: &[(&str, &str)] = &[
    ("80020001", "OS: Upgrade/Reinstall (planned)"),
    ("80020002", "OS: Reconfiguration (planned) — typically Windows Update"),
    ("80020003", "Application: Maintenance (planned)"),
    ("80020004", "Application: Installation (planned)"),
    ("80020010", "Hardware: Maintenance (planned)"),
    ("80020011", "Hardware: Installation (planned)"),
    ("80020012", "Hardware: Upgrade (planned)"),
    ("80030001", "OS: Upgrade (unplanned)"),
    ("80030002", "OS: Reconfiguration (unplanned)"),
    ("80030003", "Application: Maintenance (unplanned)"),
    ("80030004", "Application: Unresponsive"),
    ("80030005", "Application: Unstable"),
    ("80030010", "Hardware: Maintenance (unplanned)"),
    ("80030011", "Hardware: Installation (unplanned)"),
    ("80040000", "Hardware failure (unplanned)"),
    ("80040001", "Hardware: Maintenance (unplanned)"),
    ("80040002", "Hardware: Installation (unplanned)"),
    ("80050001", "System failure: Stop error (BSOD)"),
    ("80050002", "System failure: Loss of power (unplanned)"),
    ("80050006", "Power supply failure (unplanned)"),
    ("00040000", "Other (unplanned)"),
    ("00050000", "Other (unplanned)"),
    ("00050001", "Other (planned)"),
    ("00050003", "Legacy API shutdown"),
];

pub fn decode_reason(code: &str) -> Option<&'static str> {
    let padded = format!(
        "{:0>8}",
        code.trim().trim_start_matches("0x").trim_start_matches("0X").to_lowercase()
    );
    REASON_CODES
        .iter()
        .find(|&&(c, _)| c == padded)
        .map(|&(_, d)| d)
}

pub fn hex_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if s.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
        u64::from_str_radix(s, 16).ok()
    } else {
        s.parse().ok()
    }
}

pub fn module_from_bucket(bucket: &str) -> Option<String> {
    let lower = bucket.to_lowercase();
    if let Some(bang) = bucket.find('!') {
        let before = &bucket[..bang];
        let start  = before.rfind('_').map(|i| i + 1).unwrap_or(0);
        let m = &before[start..];
        if !m.is_empty() { return Some(m.to_string()); }
    }
    if let Some(pos) = lower.find("_image_") {
        let rest = &bucket[pos + 7..];
        let end  = rest.find('_').unwrap_or(rest.len());
        let m = &rest[..end];
        if !m.is_empty() { return Some(m.to_string()); }
    }
    for token in bucket.split('_') {
        let tl = token.to_lowercase();
        if tl.ends_with(".sys") || tl.ends_with(".exe") || tl.ends_with(".dll") {
            return Some(token.to_string());
        }
    }
    None
}

// ── Analysis result ───────────────────────────────────────────────────────────

pub struct CycleAnalysis {
    pub cause:         Cause,
    pub confidence:    u8,
    pub shutdown_time: Option<DateTime<Local>>,
    pub evidence:      Vec<String>,
    pub timeline:      Vec<(DateTime<Local>, String)>,
}

// ── Event classifiers ─────────────────────────────────────────────────────────

fn bsod_evidence(stop_code: u64, params: [u64; 4]) -> Vec<String> {
    let mut ev = vec![format!("BSOD stop code: 0x{:08X} — {}", stop_code, stop_name(stop_code))];
    if stop_code == 0x9F {
        let meaning = match params[0] {
            1 => " (device object failed WaitForSingleObject during power transition)",
            2 => " (device object failed IRP_MN_SET_POWER for SystemPowerState)",
            3 => " (device object stalled during IRP_MN_SET_POWER; check P4)",
            4 => " (device object stalled powering down; check P4)",
            _ => "",
        };
        if !meaning.is_empty() {
            ev.push(format!("  0x9F P1=0x{:X}{}", params[0], meaning));
        }
    }
    for (i, &p) in params.iter().enumerate() {
        if p != 0 {
            ev.push(format!("  Parameter {}: 0x{:016X}", i + 1, p));
        }
    }
    ev
}

fn classify_event41(ev: &EventRecord, unexpected_flag: bool) -> (Cause, u8, Vec<String>) {
    let stop_code = ev.data.get("BugcheckCode").and_then(|s| hex_u64(s)).unwrap_or(0);
    let params = [
        ev.data.get("BugcheckParameter1").and_then(|s| hex_u64(s)).unwrap_or(0),
        ev.data.get("BugcheckParameter2").and_then(|s| hex_u64(s)).unwrap_or(0),
        ev.data.get("BugcheckParameter3").and_then(|s| hex_u64(s)).unwrap_or(0),
        ev.data.get("BugcheckParameter4").and_then(|s| hex_u64(s)).unwrap_or(0),
    ];
    let power_btn = ev
        .data
        .get("PowerButtonTimestamp")
        .and_then(|s| hex_u64(s))
        .map(|v| v != 0)
        .unwrap_or(false);

    if stop_code != 0 {
        let name     = stop_name(stop_code);
        let evidence = bsod_evidence(stop_code, params);
        (Cause::BlueScreen { stop_code, stop_name: name, params }, 95, evidence)
    } else if power_btn {
        (Cause::ForcedPowerOff, 82, vec!["Power button was held down (hard power-off)".into()])
    } else {
        let mut evidence = vec!["Event 41: system did not shut down cleanly".into()];
        if unexpected_flag {
            evidence.push("  Confirmed by Event 6008 at next startup".into());
        }
        (Cause::UnexpectedShutdown, 75, evidence)
    }
}

// Returns (cause, confidence, evidence, timeline_message).
fn classify_event1074(ev: &EventRecord) -> (Cause, u8, Vec<String>, String) {
    let process     = ev.data.get("param1").cloned().unwrap_or_default();
    let user        = ev.data.get("param3").cloned().unwrap_or_default();
    let reason_code = ev.data.get("param4").cloned().unwrap_or_default();
    let action_raw  = ev.data.get("param5").cloned().unwrap_or_default();
    let comment     = ev.data.get("param6").cloned().unwrap_or_default();

    let action = match action_raw.as_str() {
        "restart"              => "Restart",
        "power off"            => "Shutdown",
        s if !s.is_empty()     => s,
        _                      => "Shutdown/Restart",
    }
    .to_string();

    let mut evidence = vec![format!("Process: {}", process)];
    if !user.is_empty() { evidence.push(format!("User: {}", user)); }
    match decode_reason(&reason_code) {
        Some(desc) => evidence.push(format!("Reason: {} ({})", reason_code, desc)),
        None if !reason_code.is_empty() => evidence.push(format!("Reason code: {}", reason_code)),
        _ => {}
    }
    if !comment.is_empty() { evidence.push(format!("Comment: \"{}\"", comment)); }

    let timeline_msg = format!("{} initiated by {} (Event 1074)", action, process);

    let pl        = process.to_lowercase();
    let is_update = pl.contains("tiworker")
        || pl.contains("trustedinstaller")
        || pl.contains("wuauclt")
        || pl.contains("windowsupdate")
        || reason_code.trim().eq_ignore_ascii_case("0x80020002");
    let is_system = user.to_lowercase().contains("system")
        || user.to_lowercase().contains("authority");

    let (cause, confidence) = if is_update {
        (Cause::WindowsUpdate { process }, 92)
    } else if is_system {
        (Cause::SystemProcess { process, reason: reason_code, action }, 87)
    } else {
        (Cause::UserAction { user, action, comment }, 90)
    };

    (cause, confidence, evidence, timeline_msg)
}

// ── Core analysis ─────────────────────────────────────────────────────────────

pub fn analyze_slice(
    boot_time: Option<DateTime<Local>>,
    post_boot: &[EventRecord],
    pre_boot:  &[EventRecord],
) -> CycleAnalysis {
    let e41             = post_boot.iter().find(|e| e.event_id == 41);
    let unexpected_flag = post_boot.iter().any(|e| e.event_id == 6008);
    let e1074           = pre_boot.iter().find(|e| e.event_id == 1074);
    let e13             = pre_boot.iter().find(|e| e.event_id == 13);
    let e6006           = pre_boot.iter().find(|e| e.event_id == 6006);

    let shutdown_time = (e41.is_none())
        .then(|| e1074.or(e13).or(e6006).map(|e| e.time_created))
        .flatten();

    let mut timeline = Vec::new();
    if let Some(bt) = boot_time {
        timeline.push((bt, "System started (Event 12)".to_string()));
    }

    let (cause, confidence, evidence) = if let Some(ev) = e41 {
        timeline.push((
            ev.time_created,
            "Kernel-Power: logged at boot — previous session ended unexpectedly (Event 41)".into(),
        ));
        classify_event41(ev, unexpected_flag)
    } else if let Some(ev) = e1074 {
        let (cause, confidence, evidence, msg) = classify_event1074(ev);
        timeline.push((ev.time_created, msg));
        (cause, confidence, evidence)
    } else if unexpected_flag {
        (Cause::UnexpectedShutdown, 60, vec![
            "Event 6008: Windows logged that the previous shutdown was unexpected".into(),
            "No Kernel-Power Event 41 found — crash may have occurred before event was written".into(),
        ])
    } else if e13.is_some() || e6006.is_some() {
        let mut evidence = Vec::new();
        if let Some(e) = e13 {
            timeline.push((e.time_created, "OS shutdown (Event 13)".into()));
            evidence.push("Event 13: Clean OS shutdown recorded".into());
        }
        if let Some(e) = e6006 {
            timeline.push((e.time_created, "Event log stopped cleanly (Event 6006)".into()));
            evidence.push("Event 6006: Event log stopped cleanly".into());
        }
        (Cause::NormalShutdown, 60, evidence)
    } else {
        (Cause::Undetermined, 10, vec!["No conclusive shutdown events found in log window.".into()])
    };

    CycleAnalysis { cause, confidence, shutdown_time, evidence, timeline }
}

// ── Boot cycle extraction ─────────────────────────────────────────────────────

pub fn collect_boot_indices(events: &[EventRecord]) -> Vec<usize> {
    let general: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.event_id == 12 && e.provider.contains("General"))
        .map(|(i, _)| i)
        .collect();
    if !general.is_empty() { return general; }
    events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.event_id == 12)
        .map(|(i, _)| i)
        .collect()
}

pub fn extract_boot_cycles(
    events: &[EventRecord],
    wer:    &[WerRecord],
    dumps:  &[(DateTime<Local>, PathBuf)],
    limit:  usize,
) -> Vec<BootCycle> {
    let boot_idxs = collect_boot_indices(events);

    if boot_idxs.is_empty() {
        let a = analyze_slice(None, &[], events);
        return vec![BootCycle {
            index:          0,
            boot_time:      None,
            shutdown_time:  a.shutdown_time,
            cause:          a.cause,
            confidence:     a.confidence,
            evidence:       a.evidence,
            timeline:       a.timeline,
            wer_module:     None,
            minidumps:      Vec::new(),
            display_events: events.iter().take(20).cloned().collect(),
        }];
    }

    let n = if limit == 0 { boot_idxs.len() } else { limit.min(boot_idxs.len()) };

    let mut cycles: Vec<BootCycle> = (0..n)
        .map(|idx| {
            let bi         = boot_idxs[idx];
            let boot_time  = Some(events[bi].time_created);
            let post_start = if idx == 0 { 0 } else { boot_idxs[idx - 1] + 1 };
            let pre_end    = boot_idxs.get(idx + 1).copied().unwrap_or(events.len());
            let post_boot  = &events[post_start..bi];
            let pre_boot   = &events[bi + 1..pre_end];

            let a = analyze_slice(boot_time, post_boot, pre_boot);
            let display_events = events[post_start..pre_end].iter().take(20).cloned().collect();

            BootCycle {
                index:          idx,
                boot_time,
                shutdown_time:  a.shutdown_time,
                cause:          a.cause,
                confidence:     a.confidence,
                evidence:       a.evidence,
                timeline:       a.timeline,
                wer_module:     None,
                minidumps:      Vec::new(),
                display_events,
            }
        })
        .collect();

    annotate_with_wer_and_dumps(&mut cycles, wer, dumps);
    cycles
}

fn annotate_with_wer_and_dumps(
    cycles: &mut Vec<BootCycle>,
    wer:    &[WerRecord],
    dumps:  &[(DateTime<Local>, PathBuf)],
) {
    let boot_times: Vec<Option<DateTime<Local>>> = cycles.iter().map(|c| c.boot_time).collect();

    for idx in 0..cycles.len() {
        let boot_time    = boot_times[idx];
        let session_start = boot_times.get(idx + 1).copied().flatten();
        let wer_end       = if idx > 0 { boot_times[idx - 1] } else { None };

        annotate_minidumps(&mut cycles[idx], boot_time, session_start, dumps);
        annotate_wer_module(&mut cycles[idx], boot_time, wer_end, wer);
    }
}

fn annotate_minidumps(
    cycle:         &mut BootCycle,
    boot_time:     Option<DateTime<Local>>,
    session_start: Option<DateTime<Local>>,
    dumps:         &[(DateTime<Local>, PathBuf)],
) {
    let lower = session_start.unwrap_or_else(|| {
        boot_time.map(|t| t - Duration::days(30)).unwrap_or_else(Local::now)
    });
    let upper = boot_time.map(|t| t + Duration::minutes(10)).unwrap_or_else(Local::now);
    cycle.minidumps = dumps
        .iter()
        .filter(|(t, _)| *t >= lower && *t <= upper)
        .cloned()
        .collect();
}

fn annotate_wer_module(
    cycle:     &mut BootCycle,
    boot_time: Option<DateTime<Local>>,
    wer_end:   Option<DateTime<Local>>,
    wer:       &[WerRecord],
) {
    let Cause::BlueScreen { stop_code, .. } = &cycle.cause else { return };
    let sc    = *stop_code;
    let bt    = boot_time.unwrap_or_else(Local::now);
    let upper = wer_end.unwrap_or_else(Local::now);

    let Some(wr) = wer.iter().find(|w| w.p1 == sc && w.time_created >= bt && w.time_created <= upper)
    else { return };

    cycle.wer_module = module_from_bucket(&wr.bucket_id).or_else(|| {
        (!wr.bucket_id.is_empty()).then(|| format!("(bucket: {})", wr.bucket_id))
    });

    if cycle.minidumps.is_empty() {
        if let Some(ref p) = wr.minidump_path {
            cycle.minidumps = vec![(wr.time_created, p.clone())];
        }
    }
}
