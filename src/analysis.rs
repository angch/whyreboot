// SPDX-License-Identifier: MIT OR Apache-2.0
//! Boot cycle analysis: stop code tables, event classification, and WER/minidump annotation.

use std::path::PathBuf;
use crate::timestamp::Timestamp;
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

/// Returns the symbolic name for a bugcheck stop code, or `"(unknown)"`.
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

/// Looks up an Event 1074 reason code (accepts `0x` prefix, uppercase, short forms).
/// Returns `None` for codes not in the table.
pub fn decode_reason(code: &str) -> Option<&'static str> {
    let padded = format!(
        "{:0>8}",
        code.trim().to_lowercase().trim_start_matches("0x")
    );
    REASON_CODES
        .iter()
        .find(|&&(c, _)| c == padded)
        .map(|&(_, d)| d)
}

/// Parses a u64 from a decimal or `0x`-prefixed hex string.
/// Falls back to hex if the string contains a–f without a prefix.
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

/// Extracts the faulting module name from a WER fault bucket string.
/// Three patterns tried in order:
/// 1. `module!function` — take the token before `!` (after last `_`)
/// 2. `_IMAGE_module.sys` — take the token after `_image_`
/// 3. Any `_`-delimited token ending in `.sys`, `.exe`, or `.dll`
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

/// Intermediate result from `analyze_slice`, before WER/minidump annotation.
pub struct CycleAnalysis {
    pub cause:         Cause,
    pub confidence:    u8,
    pub shutdown_time: Option<Timestamp>,
    pub evidence:      Vec<String>,
    pub timeline:      Vec<(Timestamp, String)>,
}

// ── Event classifiers ─────────────────────────────────────────────────────────

/// Builds the evidence bullet list for a BSOD. For stop code 0x9F,
/// adds a human-readable decode of Parameter 1 (the failure mode).
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

/// Classifies an Event 41 (Kernel-Power: unexpected shutdown) into BlueScreen,
/// ForcedPowerOff, or UnexpectedShutdown based on `BugcheckCode` and `PowerButtonTimestamp`.
/// `unexpected_flag` is true if Event 6008 also appears in the same `post_boot` slice.
fn classify_event41(ev: &EventRecord, unexpected_flag: bool) -> (Cause, u8, Vec<String>) {
    let stop_code = ev.get("BugcheckCode").and_then(hex_u64).unwrap_or(0);
    let params = [
        ev.get("BugcheckParameter1").and_then(hex_u64).unwrap_or(0),
        ev.get("BugcheckParameter2").and_then(hex_u64).unwrap_or(0),
        ev.get("BugcheckParameter3").and_then(hex_u64).unwrap_or(0),
        ev.get("BugcheckParameter4").and_then(hex_u64).unwrap_or(0),
    ];
    let power_btn = ev.get("PowerButtonTimestamp")
        .and_then(hex_u64)
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

/// Classifies an Event 1074 (process-initiated shutdown) into WindowsUpdate,
/// SystemProcess, or UserAction based on process name, user, and reason code.
/// Returns `(cause, confidence, evidence, timeline_message)`.
fn classify_event1074(ev: &EventRecord) -> (Cause, u8, Vec<String>, String) {
    let process     = ev.get("param1").unwrap_or_default().to_owned();
    // param3 is the human-readable reason text (e.g. "Operating System: Upgrade
    // (Planned)"); the initiating user is param7. (Confirmed against a live
    // Event 1074 from User32 — the two are easy to mix up since both are strings.)
    let user        = ev.get("param7").unwrap_or_default().to_owned();
    let reason_code = ev.get("param4").unwrap_or_default().to_owned();
    let action_raw  = ev.get("param5").unwrap_or_default().to_owned();
    let comment     = ev.get("param6").unwrap_or_default().to_owned();

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
    // Normalize the reason code to bare hex (strip "0x"/"0X" if present) before
    // comparing, since Event 1074 param4 may arrive with or without the prefix.
    let rc_norm = reason_code.trim().to_lowercase();
    let rc_norm = rc_norm.trim_start_matches("0x");
    let is_update = pl.contains("tiworker")
        || pl.contains("trustedinstaller")
        || pl.contains("wuauclt")
        || pl.contains("windowsupdate")
        || pl.contains("usoclient")
        || pl.contains("mousocoreworker")
        || pl.contains("updateorchestrator")
        || rc_norm == "80020002";
    let ul = user.to_lowercase();
    let is_system = ul.contains("system") || ul.contains("authority");

    let (cause, confidence) = if is_update {
        (Cause::WindowsUpdate { process, old_version: None, new_version: None }, 92)
    } else if is_system {
        (Cause::SystemProcess { process, reason: reason_code, action }, 87)
    } else {
        (Cause::UserAction { user, action, comment }, 90)
    };

    (cause, confidence, evidence, timeline_msg)
}

/// Extracts a numeric "major.minor.build" string (e.g. `"10.0.26200"`) from an
/// Event 6009 startup version banner. Its `<Data>` fields are unnamed and keyed
/// `_0`.._4` by `xml_data`: `_0` is "major.minor." (e.g. `"10.00."`), `_1` is the
/// build number.
///
/// Returns `None` unless all three components parse as integers — the build field
/// is validated too, so a non-numeric banner (e.g. an older layout carrying
/// "Service Pack 0" in `_1`) yields `None` rather than a bogus "10.0.Service Pack 0".
fn os_version_from_6009(ev: &EventRecord) -> Option<String> {
    let major_minor = ev.get("_0")?.trim_matches('.');
    let build       = ev.get("_1")?.trim();
    if build.is_empty() || !build.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut parts = major_minor.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some(format!("{major}.{minor}.{build}"))
}


// ── Core analysis ─────────────────────────────────────────────────────────────

/// Applies the priority-ordered decision tree to classify one boot cycle.
/// `post_boot` contains events logged at the recovery boot about the prior session
/// (e.g. Event 41, 6008). `pre_boot` contains events logged during the prior session
/// (e.g. Event 1074, 13, 6006). See `HowItWorks.md` for the full decision tree.
pub fn analyze_slice(
    boot_time: Option<Timestamp>,
    post_boot: &[EventRecord],
    pre_boot:  &[EventRecord],
) -> CycleAnalysis {
    let e41             = post_boot.iter().find(|e| e.event_id == 41);
    let unexpected_flag = post_boot.iter().any(|e| e.event_id == 6008);
    let e1074           = pre_boot.iter().find(|e| e.event_id == 1074);
    let e13             = pre_boot.iter().find(|e| e.event_id == 13);
    let e6006           = pre_boot.iter().find(|e| e.event_id == 6006);

    let shutdown_time = if e41.is_none() {
        e1074.or(e13).or(e6006).map(|e| e.time_created)
    } else {
        None
    };

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
        // old_version/new_version are filled in later by `annotate_os_version`,
        // which scans the full (unsliced) event list — see its doc comment for why.
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

/// Returns indices of all Event 12 entries in the (newest-first) event list.
/// Prefers events from the `Microsoft-Windows-Kernel-General` provider; falls back
/// to any Event 12 if none found from that provider.
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

/// Slices the flat event list into per-boot cycles and classifies each one.
/// `limit` is the number of most-recent cycles to return (0 = all).
/// Falls back to treating the entire event set as a single cycle if no Event 12 is found.
/// After initial classification, annotates each cycle with WER module and minidump data.
pub fn extract_boot_cycles(
    events: &[EventRecord],
    wer:    &[WerRecord],
    dumps:  &[(Timestamp, PathBuf)],
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

    // Cycles are ordered newest-first, so idx+1 is the boot before this one and
    // idx-1 the boot after — the bounds `annotate_os_version` needs to confine
    // each version lookup to the correct session.
    let boot_times: Vec<Option<Timestamp>> = cycles.iter().map(|c| c.boot_time).collect();
    for idx in 0..cycles.len() {
        let prev_boot = boot_times.get(idx + 1).copied().flatten();
        let next_boot = if idx > 0 { boot_times[idx - 1] } else { None };
        annotate_os_version(&mut cycles[idx], events, prev_boot, next_boot);
    }
    annotate_with_wer_and_dumps(&mut cycles, wer, dumps);
    cycles
}

/// Returns the OS version from the first *parseable* Event 6009 in the half-open
/// time window `[lo, hi)` (either bound `None` = unbounded on that side).
/// `prefer_latest` selects the newest such banner; otherwise the oldest.
///
/// Scans by `TimeCreated`, not array position: classic `EventLog`-sourced IDs
/// like 6009 can be assigned an `EventRecordID` lower than concurrently-written
/// modern-provider events (observed live: a 6009 timestamped 15s after boot had
/// a lower RecordID than that same boot's own Event 12), so the newest-first
/// fetch order can't be trusted to place a banner on the expected side of an
/// Event 12 boundary. Falling through to the next parseable banner (rather than
/// parsing only the single extreme record) means one malformed 6009 doesn't
/// discard a perfectly good neighbor in range.
fn nearest_os_version(
    events:        &[EventRecord],
    lo:            Option<Timestamp>,
    hi:            Option<Timestamp>,
    prefer_latest: bool,
) -> Option<String> {
    let mut in_range: Vec<&EventRecord> = events.iter()
        .filter(|e| e.event_id == 6009)
        .filter(|e| lo.is_none_or(|l| e.time_created >= l))
        .filter(|e| hi.is_none_or(|h| e.time_created <  h))
        .collect();
    in_range.sort_by_key(|e| e.time_created);
    if prefer_latest {
        in_range.iter().rev().find_map(|e| os_version_from_6009(e))
    } else {
        in_range.iter().find_map(|e| os_version_from_6009(e))
    }
}

/// Fills in `old_version`/`new_version` for a `Cause::WindowsUpdate` cycle from
/// the Event 6009 version banners bracketing this boot.
///
/// Each lookup is confined to a single session so a neighbouring boot's banner
/// can never leak in:
/// - **old_version** — the newest banner in `[prev_boot, bt)`: the session that
///   was shut down to apply the update.
/// - **new_version** — the oldest banner in `[bt, next_boot)`: this boot's own.
///
/// Note this compares the build *at this specific boot*, not across an entire
/// update chain. Feature/cumulative updates often reboot several times and only
/// bump the build number on the final restart, so `old_version == new_version`
/// here does **not** prove no upgrade occurred — it only means the build hadn't
/// changed yet at this boot. `cause_detail` is careful not to overclaim on that.
fn annotate_os_version(
    cycle:     &mut BootCycle,
    events:    &[EventRecord],
    prev_boot: Option<Timestamp>,
    next_boot: Option<Timestamp>,
) {
    let Cause::WindowsUpdate { old_version, new_version, .. } = &mut cycle.cause else { return };
    let Some(bt) = cycle.boot_time else { return };
    *old_version = nearest_os_version(events, prev_boot, Some(bt), true);
    *new_version = nearest_os_version(events, Some(bt), next_boot, false);
}

/// Runs both annotation passes (minidumps then WER module) over all cycles.
fn annotate_with_wer_and_dumps(
    cycles: &mut [BootCycle],
    wer:    &[WerRecord],
    dumps:  &[(Timestamp, PathBuf)],
) {
    let boot_times: Vec<Option<Timestamp>> = cycles.iter().map(|c| c.boot_time).collect();

    for idx in 0..cycles.len() {
        let boot_time    = boot_times[idx];
        let session_start = boot_times.get(idx + 1).copied().flatten();
        let wer_end       = if idx > 0 { boot_times[idx - 1] } else { None };

        annotate_minidumps(&mut cycles[idx], boot_time, session_start, dumps);
        annotate_wer_module(&mut cycles[idx], boot_time, wer_end, wer);
    }
}

/// Matches filesystem minidumps to this cycle by modification time.
/// The window is `[session_start, boot_time + 10 min]`; the upper bound
/// accommodates WER processing delay after the recovery boot.
fn annotate_minidumps(
    cycle:         &mut BootCycle,
    boot_time:     Option<Timestamp>,
    session_start: Option<Timestamp>,
    dumps:         &[(Timestamp, PathBuf)],
) {
    let lower = session_start.unwrap_or_else(|| {
        boot_time.map(|t| t.add_secs(-30 * 86_400)).unwrap_or_else(Timestamp::now)
    });
    let upper = boot_time.map(|t| t.add_secs(10 * 60)).unwrap_or_else(Timestamp::now);
    cycle.minidumps = dumps
        .iter()
        .filter(|(t, _)| *t >= lower && *t <= upper)
        .cloned()
        .collect();
}

/// Matches a WER record to this cycle's BSOD by stop code and time window.
/// WER runs during the recovery boot, so the window is `[boot_time, wer_end]`
/// where `wer_end` is the start of the next boot (or now for the most recent cycle).
/// Also fills `minidumps` from `WerRecord.minidump_path` if the filesystem scan found nothing.
fn annotate_wer_module(
    cycle:     &mut BootCycle,
    boot_time: Option<Timestamp>,
    wer_end:   Option<Timestamp>,
    wer:       &[WerRecord],
) {
    let Cause::BlueScreen { stop_code, .. } = &cycle.cause else { return };
    let sc    = *stop_code;
    let bt    = boot_time.unwrap_or_else(Timestamp::now);
    let upper = wer_end.unwrap_or_else(Timestamp::now);

    let Some(wr) = wer.iter().find(|w| w.p1 == sc && w.time_created >= bt && w.time_created <= upper)
    else { return };

    cycle.wer_module = module_from_bucket(&wr.bucket_id).or_else(|| {
        (!wr.bucket_id.is_empty()).then(|| format!("(bucket: {})", wr.bucket_id))
    });

    if let (true, Some(p)) = (cycle.minidumps.is_empty(), &wr.minidump_path) {
        cycle.minidumps = vec![(wr.time_created, p.clone())];
    }
}

#[cfg(test)]
mod tests {
    use super::{
        hex_u64, stop_name, decode_reason, module_from_bucket,
        bsod_evidence, classify_event41, classify_event1074,
        analyze_slice, collect_boot_indices, extract_boot_cycles,
        annotate_os_version, os_version_from_6009,
    };
    use crate::timestamp::Timestamp;
    use crate::types::{BootCycle, Cause, EventRecord};

    fn make_event(event_id: u32, provider: &str, data: &[(&str, &str)]) -> EventRecord {
        make_event_at(event_id, provider, Timestamp::now(), data)
    }

    fn make_event_at(event_id: u32, provider: &str, time: Timestamp, data: &[(&str, &str)]) -> EventRecord {
        EventRecord {
            event_id,
            time_created: time,
            provider: provider.to_string(),
            data: data.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    // ── hex_u64 ───────────────────────────────────────────────────────────────

    #[test]
    fn hex_u64_0x_prefix_lowercase() {
        assert_eq!(hex_u64("0x9f"), Some(0x9f));
        assert_eq!(hex_u64("0x0000009f"), Some(0x9f));
    }

    #[test]
    fn hex_u64_0x_prefix_uppercase() {
        assert_eq!(hex_u64("0X9F"), Some(0x9f));
    }

    #[test]
    fn hex_u64_decimal() {
        assert_eq!(hex_u64("0"), Some(0));
        assert_eq!(hex_u64("159"), Some(159));
    }

    #[test]
    fn hex_u64_bare_hex_inferred() {
        // Contains a–f without prefix → parsed as hex.
        assert_eq!(hex_u64("9f"), Some(0x9f));
        assert_eq!(hex_u64("ff"), Some(0xff));
    }

    #[test]
    fn hex_u64_invalid() {
        assert_eq!(hex_u64(""), None);
        assert_eq!(hex_u64("xyz"), None);
        assert_eq!(hex_u64("0xgg"), None);
    }

    // ── stop_name ─────────────────────────────────────────────────────────────

    #[test]
    fn stop_name_known_codes() {
        assert_eq!(stop_name(0x9F),  "DRIVER_POWER_STATE_FAILURE");
        assert_eq!(stop_name(0x19C), "WIN32K_POWER_WATCHDOG_TIMEOUT");
        assert_eq!(stop_name(0xFE),  "BUGCODE_USB_DRIVER");
        assert_eq!(stop_name(0x144), "BUGCODE_USB3_DRIVER");
        assert_eq!(stop_name(0x50),  "PAGE_FAULT_IN_NONPAGED_AREA");
    }

    #[test]
    fn stop_name_unknown() {
        assert_eq!(stop_name(0xDEADBEEF), "(unknown)");
        assert_eq!(stop_name(0),          "(unknown)");
    }

    // ── decode_reason ─────────────────────────────────────────────────────────

    #[test]
    fn decode_reason_with_0x_prefix() {
        let r = decode_reason("0x80020002").expect("should be found");
        assert!(r.contains("Windows Update") || r.contains("Reconfiguration"));
    }

    #[test]
    fn decode_reason_without_prefix() {
        assert_eq!(decode_reason("80020002"), decode_reason("0x80020002"));
    }

    #[test]
    fn decode_reason_uppercase_x() {
        assert_eq!(decode_reason("0X80020002"), decode_reason("0x80020002"));
    }

    #[test]
    fn decode_reason_not_found() {
        assert!(decode_reason("DEADBEEF").is_none());
        assert!(decode_reason("00000000").is_none());
    }

    // ── module_from_bucket ────────────────────────────────────────────────────

    #[test]
    fn bucket_bang_pattern_with_prefix_tokens() {
        // Priority 1: token before '!' (after last '_')
        assert_eq!(
            module_from_bucket("0x9F_3_DXG_POWER_IRP_TIMEOUT_portcls!GetIrpDisposition"),
            Some("portcls".to_string())
        );
    }

    #[test]
    fn bucket_bang_pattern_simple() {
        assert_eq!(
            module_from_bucket("0x9F_3_usbccgp!WaitForSignal"),
            Some("usbccgp".to_string())
        );
    }

    #[test]
    fn bucket_image_pattern() {
        // Priority 2: token after '_IMAGE_'
        assert_eq!(
            module_from_bucket("0x9F_3_usbccgp_IMAGE_UsbHub3.sys"),
            Some("UsbHub3.sys".to_string())
        );
    }

    #[test]
    fn bucket_sys_token_fallback() {
        // Priority 3: token ending in .sys
        assert_eq!(module_from_bucket("0x50_ntoskrnl.exe"), Some("ntoskrnl.exe".to_string()));
        assert_eq!(module_from_bucket("CRASH_win32k.sys"),  Some("win32k.sys".to_string()));
    }

    #[test]
    fn bucket_dll_token_fallback() {
        assert_eq!(module_from_bucket("0x1E_some_lib.dll"), Some("lib.dll".to_string()));
    }

    #[test]
    fn bucket_no_match() {
        assert_eq!(module_from_bucket("0x9F_NOSYMBOLS"), None);
        assert_eq!(module_from_bucket(""), None);
    }

    #[test]
    fn bucket_bang_with_empty_module_falls_through() {
        // '_!function' → before='_', rfind('_')=0, m="" → falls through to .sys scan
        assert_eq!(module_from_bucket("_!func_ntoskrnl.exe"), Some("ntoskrnl.exe".to_string()));
    }

    // ── bsod_evidence ─────────────────────────────────────────────────────────

    #[test]
    fn bsod_evidence_0x9f_p1_decoded_for_values_1_to_4() {
        for p1 in 1u64..=4 {
            let ev = bsod_evidence(0x9F, [p1, 0, 0, 0]);
            // Must have stop code line + P1 decode line.
            assert!(ev.len() >= 2, "P1={p1} should produce a decode line");
            assert!(ev[0].contains("DRIVER_POWER_STATE_FAILURE"));
            assert!(ev.iter().any(|l| l.contains(&format!("P1=0x{p1:X}"))));
        }
    }

    #[test]
    fn bsod_evidence_0x9f_p1_zero_no_decode_line() {
        let ev = bsod_evidence(0x9F, [0, 0, 0, 0]);
        // All params zero → only the stop code line.
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn bsod_evidence_nonzero_params_appear() {
        let ev = bsod_evidence(0x50, [0, 0xDEAD, 0, 0xBEEF]);
        assert!(!ev.iter().any(|l| l.contains("Parameter 1")), "zero param 1 should be absent");
        assert!(ev.iter().any(|l| l.contains("Parameter 2")));
        assert!(!ev.iter().any(|l| l.contains("Parameter 3")), "zero param 3 should be absent");
        assert!(ev.iter().any(|l| l.contains("Parameter 4")));
    }

    // ── classify_event41 ──────────────────────────────────────────────────────

    #[test]
    fn ev41_bsod_stop_code_nonzero() {
        let ev = make_event(41, "Microsoft-Windows-Kernel-Power", &[
            ("BugcheckCode", "0x9f"),
            ("BugcheckParameter1", "3"),
            ("BugcheckParameter2", "0"),
            ("BugcheckParameter3", "0"),
            ("BugcheckParameter4", "0"),
            ("PowerButtonTimestamp", "0"),
        ]);
        let (cause, conf, _) = classify_event41(&ev, false);
        assert!(matches!(cause, Cause::BlueScreen { stop_code, .. } if stop_code == 0x9F));
        assert_eq!(conf, 95);
    }

    #[test]
    fn ev41_forced_power_off() {
        let ev = make_event(41, "Microsoft-Windows-Kernel-Power", &[
            ("BugcheckCode", "0"),
            ("PowerButtonTimestamp", "0x1234"),
        ]);
        let (cause, conf, _) = classify_event41(&ev, false);
        assert!(matches!(cause, Cause::ForcedPowerOff));
        assert_eq!(conf, 82);
    }

    #[test]
    fn ev41_unexpected_no_stop_code_no_power_btn() {
        let ev = make_event(41, "Microsoft-Windows-Kernel-Power", &[
            ("BugcheckCode", "0"),
            ("PowerButtonTimestamp", "0"),
        ]);
        let (cause, conf, _) = classify_event41(&ev, false);
        assert!(matches!(cause, Cause::UnexpectedShutdown));
        assert_eq!(conf, 75);
    }

    #[test]
    fn ev41_unexpected_with_6008_flag_adds_evidence() {
        let ev = make_event(41, "Microsoft-Windows-Kernel-Power", &[
            ("BugcheckCode", "0"),
            ("PowerButtonTimestamp", "0"),
        ]);
        let (cause, _, evidence) = classify_event41(&ev, true);
        assert!(matches!(cause, Cause::UnexpectedShutdown));
        assert!(evidence.iter().any(|e| e.contains("6008")));
    }

    // ── classify_event1074 ────────────────────────────────────────────────────

    #[test]
    fn ev1074_tiworker_is_windows_update() {
        let ev = make_event(1074, "User32", &[
            ("param1", r"C:\Windows\System32\TiWorker.exe"),
            ("param7", r"NT AUTHORITY\SYSTEM"),
            ("param4", "0x80020002"),
            ("param5", "restart"),
            ("param6", ""),
        ]);
        let (cause, conf, _, _) = classify_event1074(&ev);
        assert!(matches!(cause, Cause::WindowsUpdate { .. }));
        assert!(conf >= 90);
    }

    #[test]
    fn ev1074_reason_code_0x80020002_alone_triggers_update() {
        // Even when the process is not TiWorker, the reason code overrides.
        let ev = make_event(1074, "User32", &[
            ("param1", "SomeProcess.exe"),
            ("param7", r"DOMAIN\user"),
            ("param4", "0x80020002"),
            ("param5", "restart"),
            ("param6", ""),
        ]);
        let (cause, _, _, _) = classify_event1074(&ev);
        assert!(matches!(cause, Cause::WindowsUpdate { .. }));
    }

    #[test]
    fn ev1074_reason_code_without_0x_prefix_triggers_update() {
        // param4 "80020002" (no 0x prefix) must still classify as WindowsUpdate.
        let ev = make_event(1074, "User32", &[
            ("param1", "SomeProcess.exe"),
            ("param7", r"DOMAIN\user"),
            ("param4", "80020002"),
            ("param5", "restart"),
            ("param6", ""),
        ]);
        let (cause, _, _, _) = classify_event1074(&ev);
        assert!(matches!(cause, Cause::WindowsUpdate { .. }));
    }

    #[test]
    fn ev1074_system_user_is_system_process() {
        let ev = make_event(1074, "User32", &[
            ("param1", "svchost.exe"),
            ("param7", r"NT AUTHORITY\SYSTEM"),
            ("param4", "0x80040001"),
            ("param5", "power off"),
            ("param6", ""),
        ]);
        let (cause, _, _, _) = classify_event1074(&ev);
        assert!(matches!(cause, Cause::SystemProcess { .. }));
    }

    #[test]
    fn ev1074_normal_user_is_user_action() {
        let ev = make_event(1074, "User32", &[
            ("param1", "explorer.exe"),
            ("param7", r"DESKTOP-ABC\angch"),
            ("param4", "0x00040000"),
            ("param5", "restart"),
            ("param6", "testing reboot"),
        ]);
        let (cause, conf, evidence, _) = classify_event1074(&ev);
        assert!(matches!(cause, Cause::UserAction { .. }));
        assert!(conf >= 88);
        assert!(evidence.iter().any(|e| e.contains("angch")));
        assert!(evidence.iter().any(|e| e.contains("testing reboot")));
    }

    #[test]
    fn ev1074_action_normalised() {
        let ev = make_event(1074, "User32", &[
            ("param1", "p.exe"),
            ("param7", r"DOMAIN\bob"),
            ("param4", "0"),
            ("param5", "power off"),
            ("param6", ""),
        ]);
        let (_, _, _, msg) = classify_event1074(&ev);
        assert!(msg.contains("Shutdown"));
    }

    // ── analyze_slice (full decision tree) ────────────────────────────────────

    #[test]
    fn analyze_bsod_from_event41() {
        let post = [make_event(41, "Microsoft-Windows-Kernel-Power", &[
            ("BugcheckCode", "0x9f"),
            ("BugcheckParameter1", "3"),
            ("BugcheckParameter2", "0"),
            ("BugcheckParameter3", "0"),
            ("BugcheckParameter4", "0"),
            ("PowerButtonTimestamp", "0"),
        ])];
        let a = analyze_slice(None, &post, &[]);
        assert!(matches!(a.cause, Cause::BlueScreen { stop_code, .. } if stop_code == 0x9F));
        assert_eq!(a.confidence, 95);
        assert!(a.shutdown_time.is_none(), "crashes have no shutdown_time");
    }

    #[test]
    fn analyze_forced_poweroff_from_event41() {
        let post = [make_event(41, "Microsoft-Windows-Kernel-Power", &[
            ("BugcheckCode", "0"),
            ("PowerButtonTimestamp", "1"),
        ])];
        let a = analyze_slice(None, &post, &[]);
        assert!(matches!(a.cause, Cause::ForcedPowerOff));
    }

    #[test]
    fn analyze_windows_update_from_1074() {
        let pre = [make_event(1074, "User32", &[
            ("param1", "TiWorker.exe"),
            ("param7", "SYSTEM"),
            ("param4", "0x80020002"),
            ("param5", "restart"),
            ("param6", ""),
        ])];
        let a = analyze_slice(None, &[], &pre);
        assert!(matches!(a.cause, Cause::WindowsUpdate { .. }));
        assert!(a.shutdown_time.is_some(), "clean shutdowns record shutdown_time");
    }

    fn make_cycle(cause: Cause, boot_time: Option<Timestamp>) -> BootCycle {
        BootCycle {
            index: 0, boot_time, shutdown_time: None, cause, confidence: 0,
            evidence: Vec::new(), timeline: Vec::new(), wer_module: None,
            minidumps: Vec::new(), display_events: Vec::new(),
        }
    }

    #[test]
    fn annotate_os_version_finds_versions_on_each_side_of_boot() {
        let boot_time = Timestamp(1_705_314_600);
        let events = [
            make_event_at(6009, "EventLog", boot_time.add_secs(15),
                &[("_0", "10.00."), ("_1", "26100")]),
            make_event_at(6009, "EventLog", boot_time.add_secs(-90),
                &[("_0", "10.00."), ("_1", "25900")]),
        ];
        let mut cycle = make_cycle(
            Cause::WindowsUpdate { process: "TrustedInstaller.exe".into(), old_version: None, new_version: None },
            Some(boot_time),
        );
        annotate_os_version(&mut cycle, &events,
            Some(boot_time.add_secs(-300)), Some(boot_time.add_secs(300)));
        match cycle.cause {
            Cause::WindowsUpdate { old_version, new_version, .. } => {
                assert_eq!(old_version.as_deref(), Some("10.0.25900"));
                assert_eq!(new_version.as_deref(), Some("10.0.26100"));
            }
            other => panic!("expected WindowsUpdate, got {other:?}"),
        }
    }

    #[test]
    fn annotate_os_version_ignores_array_position_uses_timestamp_only() {
        // Regression: a boot's own 6009 can be assigned a lower EventRecordID
        // than events written around the same instant by modern providers (see
        // `annotate_os_version` doc comment), so it can end up anywhere in the
        // fetched event list relative to the Event 12 boundary. Deliberately put
        // the "new" (post-boot) banner earlier in the array than the "old" one
        // to confirm the lookup keys off TimeCreated, not array position.
        let boot_time = Timestamp(1_705_314_600);
        let events = [
            make_event_at(6009, "EventLog", boot_time.add_secs(15),
                &[("_0", "10.00."), ("_1", "26200")]),
            make_event_at(6009, "EventLog", boot_time.add_secs(-120),
                &[("_0", "10.00."), ("_1", "26100")]),
        ];
        let mut cycle = make_cycle(
            Cause::WindowsUpdate { process: "TrustedInstaller.exe".into(), old_version: None, new_version: None },
            Some(boot_time),
        );
        annotate_os_version(&mut cycle, &events,
            Some(boot_time.add_secs(-300)), Some(boot_time.add_secs(300)));
        match cycle.cause {
            Cause::WindowsUpdate { old_version, new_version, .. } => {
                assert_eq!(old_version.as_deref(), Some("10.0.26100"));
                assert_eq!(new_version.as_deref(), Some("10.0.26200"));
            }
            other => panic!("expected WindowsUpdate, got {other:?}"),
        }
    }

    #[test]
    fn annotate_os_version_no_op_for_non_windows_update_cause() {
        let mut cycle = make_cycle(Cause::NormalShutdown, Some(Timestamp(1_705_314_600)));
        annotate_os_version(&mut cycle, &[], None, None);
        assert!(matches!(cycle.cause, Cause::NormalShutdown));
    }

    #[test]
    fn annotate_os_version_no_op_without_boot_time() {
        let mut cycle = make_cycle(
            Cause::WindowsUpdate { process: "x".into(), old_version: None, new_version: None },
            None,
        );
        let events = [make_event_at(6009, "EventLog", Timestamp(1_705_314_600),
            &[("_0", "10.00."), ("_1", "26100")])];
        annotate_os_version(&mut cycle, &events, None, None);
        match cycle.cause {
            Cause::WindowsUpdate { old_version, new_version, .. } => {
                assert!(old_version.is_none() && new_version.is_none());
            }
            other => panic!("expected WindowsUpdate, got {other:?}"),
        }
    }

    #[test]
    fn annotate_os_version_bounds_new_version_to_this_boots_session() {
        // Regression (#1): this update cycle's OWN post-boot 6009 is missing. A
        // later, unrelated cycle's banner sits just past next_boot; it must NOT
        // be borrowed as this cycle's new_version, or we'd report a version from
        // a different reboot as if it were this update's result.
        let bt = Timestamp(1_705_314_600);
        let next_boot = bt.add_secs(3600);
        let events = [
            make_event_at(6009, "EventLog", bt.add_secs(-60),
                &[("_0", "10.00."), ("_1", "26100")]),
            // A different, later cycle's banner — outside [bt, next_boot).
            make_event_at(6009, "EventLog", next_boot.add_secs(15),
                &[("_0", "10.00."), ("_1", "26300")]),
        ];
        let mut cycle = make_cycle(
            Cause::WindowsUpdate { process: "TrustedInstaller.exe".into(), old_version: None, new_version: None },
            Some(bt),
        );
        annotate_os_version(&mut cycle, &events, Some(bt.add_secs(-300)), Some(next_boot));
        match cycle.cause {
            Cause::WindowsUpdate { old_version, new_version, .. } => {
                assert_eq!(old_version.as_deref(), Some("10.0.26100"));
                assert_eq!(new_version, None, "must not borrow a later cycle's banner");
            }
            other => panic!("expected WindowsUpdate, got {other:?}"),
        }
    }

    #[test]
    fn annotate_os_version_falls_back_past_unparseable_banner() {
        // Regression (A1): the newest in-range 6009 is malformed; a valid earlier
        // one still in range must be used rather than dropping old_version.
        let bt = Timestamp(1_705_314_600);
        let events = [
            make_event_at(6009, "EventLog", bt.add_secs(-30),
                &[("_0", "10.00."), ("_1", "Service Pack 0")]),
            make_event_at(6009, "EventLog", bt.add_secs(-120),
                &[("_0", "10.00."), ("_1", "19045")]),
        ];
        let mut cycle = make_cycle(
            Cause::WindowsUpdate { process: "TiWorker.exe".into(), old_version: None, new_version: None },
            Some(bt),
        );
        annotate_os_version(&mut cycle, &events, Some(bt.add_secs(-300)), None);
        match cycle.cause {
            Cause::WindowsUpdate { old_version, .. } =>
                assert_eq!(old_version.as_deref(), Some("10.0.19045")),
            other => panic!("expected WindowsUpdate, got {other:?}"),
        }
    }

    #[test]
    fn os_version_from_6009_rejects_non_numeric_build() {
        // Guards against "10.0.Service Pack 0"-style bogus version strings (#3).
        let good = make_event(6009, "EventLog", &[("_0", "10.00."), ("_1", "26200")]);
        assert_eq!(os_version_from_6009(&good).as_deref(), Some("10.0.26200"));
        let bad = make_event(6009, "EventLog", &[("_0", "10.00."), ("_1", "Service Pack 0")]);
        assert_eq!(os_version_from_6009(&bad), None);
        let empty = make_event(6009, "EventLog", &[("_0", "10.00."), ("_1", "")]);
        assert_eq!(os_version_from_6009(&empty), None);
    }

    #[test]
    fn ev1074_mousocoreworker_is_windows_update() {
        // Update Orchestrator worker restarts don't always carry the 0x80020002
        // reason code (this one is 0x80020010, "Service pack (Planned)") — the
        // process name alone must still be recognized as Windows Update.
        let ev = make_event(1074, "User32", &[
            ("param1", r"C:\WINDOWS\uus\AMD64\MoUsoCoreWorker.exe"),
            ("param7", r"NT AUTHORITY\SYSTEM"),
            ("param4", "0x80020010"),
            ("param5", "restart"),
            ("param6", ""),
        ]);
        let (cause, _, _, _) = classify_event1074(&ev);
        assert!(matches!(cause, Cause::WindowsUpdate { .. }));
    }

    #[test]
    fn analyze_unexpected_from_6008_only() {
        let post = [make_event(6008, "EventLog", &[])];
        let a = analyze_slice(None, &post, &[]);
        assert!(matches!(a.cause, Cause::UnexpectedShutdown));
        assert_eq!(a.confidence, 60);
    }

    #[test]
    fn analyze_normal_from_event13() {
        let pre = [make_event(13, "Microsoft-Windows-Kernel-General", &[])];
        let a = analyze_slice(None, &[], &pre);
        assert!(matches!(a.cause, Cause::NormalShutdown));
        assert!(a.shutdown_time.is_some());
    }

    #[test]
    fn analyze_normal_from_event6006() {
        let pre = [make_event(6006, "EventLog", &[])];
        let a = analyze_slice(None, &[], &pre);
        assert!(matches!(a.cause, Cause::NormalShutdown));
    }

    #[test]
    fn analyze_undetermined_when_no_events() {
        let a = analyze_slice(None, &[], &[]);
        assert!(matches!(a.cause, Cause::Undetermined));
        assert_eq!(a.confidence, 10);
    }

    #[test]
    fn analyze_event41_takes_priority_over_1074() {
        let post = [make_event(41, "Microsoft-Windows-Kernel-Power", &[
            ("BugcheckCode", "0x9f"),
            ("BugcheckParameter1", "3"),
            ("BugcheckParameter2", "0"),
            ("BugcheckParameter3", "0"),
            ("BugcheckParameter4", "0"),
            ("PowerButtonTimestamp", "0"),
        ])];
        let pre = [make_event(1074, "User32", &[
            ("param1", "TiWorker.exe"),
            ("param3", "SYSTEM"),
            ("param4", "0x80020002"),
            ("param5", "restart"),
            ("param6", ""),
        ])];
        let a = analyze_slice(None, &post, &pre);
        assert!(matches!(a.cause, Cause::BlueScreen { .. }), "Event 41 must win over Event 1074");
    }

    #[test]
    fn analyze_6008_without_41_is_lower_confidence_than_41() {
        let post_with_41 = [make_event(41, "Microsoft-Windows-Kernel-Power", &[
            ("BugcheckCode", "0"),
            ("PowerButtonTimestamp", "0"),
        ])];
        let post_6008_only = [make_event(6008, "EventLog", &[])];
        let a_41   = analyze_slice(None, &post_with_41,   &[]);
        let a_6008 = analyze_slice(None, &post_6008_only, &[]);
        assert!(a_41.confidence > a_6008.confidence);
    }

    // ── collect_boot_indices ──────────────────────────────────────────────────

    #[test]
    fn boot_indices_prefers_kernel_general_provider() {
        let events = vec![
            make_event(12, "Microsoft-Windows-Kernel-General", &[]), // idx 0 ✓
            make_event(41, "Microsoft-Windows-Kernel-Power",   &[]), // idx 1
            make_event(12, "SomeOtherProvider",                &[]), // idx 2 — not General
            make_event(12, "Microsoft-Windows-Kernel-General", &[]), // idx 3 ✓
        ];
        assert_eq!(collect_boot_indices(&events), vec![0, 3]);
    }

    #[test]
    fn boot_indices_falls_back_to_any_event12() {
        let events = vec![
            make_event(41, "Kernel-Power",  &[]),
            make_event(12, "SomeProvider",  &[]), // idx 1
            make_event(41, "Kernel-Power",  &[]),
            make_event(12, "OtherProvider", &[]), // idx 3
        ];
        assert_eq!(collect_boot_indices(&events), vec![1, 3]);
    }

    #[test]
    fn boot_indices_empty_when_no_event12() {
        let events = vec![make_event(41, "Kernel-Power", &[])];
        assert!(collect_boot_indices(&events).is_empty());
    }

    // ── extract_boot_cycles ───────────────────────────────────────────────────

    #[test]
    fn extract_empty_events_returns_one_undetermined_cycle() {
        let cycles = extract_boot_cycles(&[], &[], &[], 1);
        assert_eq!(cycles.len(), 1);
        assert!(matches!(cycles[0].cause, Cause::Undetermined));
        assert_eq!(cycles[0].index, 0);
    }

    #[test]
    fn extract_limit_restricts_count() {
        // events: [ev41, Event12, Event13, Event12, Event13] → 2 boot cycles
        let events = vec![
            make_event(41, "Kernel-Power", &[("BugcheckCode","0"),("PowerButtonTimestamp","0")]),
            make_event(12, "Microsoft-Windows-Kernel-General", &[]),
            make_event(13, "Microsoft-Windows-Kernel-General", &[]),
            make_event(12, "Microsoft-Windows-Kernel-General", &[]),
            make_event(13, "Microsoft-Windows-Kernel-General", &[]),
        ];
        assert_eq!(extract_boot_cycles(&events, &[], &[], 1).len(), 1);
        assert_eq!(extract_boot_cycles(&events, &[], &[], 0).len(), 2); // 0 = all
    }

    #[test]
    fn extract_bsod_cycle_identified() {
        // post_boot of cycle 0 = [ev41], pre_boot = [ev13]
        let events = vec![
            make_event(41, "Microsoft-Windows-Kernel-Power", &[
                ("BugcheckCode", "0x9f"),
                ("BugcheckParameter1", "3"),
                ("BugcheckParameter2", "0"),
                ("BugcheckParameter3", "0"),
                ("BugcheckParameter4", "0"),
                ("PowerButtonTimestamp", "0"),
            ]),
            make_event(12, "Microsoft-Windows-Kernel-General", &[]),
            make_event(13, "Microsoft-Windows-Kernel-General", &[]),
        ];
        let cycles = extract_boot_cycles(&events, &[], &[], 1);
        assert_eq!(cycles.len(), 1);
        assert!(matches!(&cycles[0].cause, Cause::BlueScreen { stop_code, .. } if *stop_code == 0x9F));
    }

    #[test]
    fn extract_two_boots_assigns_correct_indices() {
        let events = vec![
            make_event(12, "Microsoft-Windows-Kernel-General", &[]), // idx 0: current boot
            make_event(13, "Microsoft-Windows-Kernel-General", &[]), // pre_boot of cycle 0
            make_event(12, "Microsoft-Windows-Kernel-General", &[]), // idx 2: previous boot
            make_event(13, "Microsoft-Windows-Kernel-General", &[]), // pre_boot of cycle 1
        ];
        let cycles = extract_boot_cycles(&events, &[], &[], 0);
        assert_eq!(cycles.len(), 2);
        assert_eq!(cycles[0].index, 0);
        assert_eq!(cycles[1].index, 1);
        assert!(matches!(cycles[0].cause, Cause::NormalShutdown));
        assert!(matches!(cycles[1].cause, Cause::NormalShutdown));
    }
}
