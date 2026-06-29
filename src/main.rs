use chrono::{DateTime, Duration, Local};
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::PathBuf;
use windows::Win32::System::EventLog::*;

// ── CLI ───────────────────────────────────────────────────────────────────────

struct Args {
    history: usize, // 0 = all cycles
    json:    bool,
    color:   bool,
}

fn parse_args() -> Args {
    let mut args = Args { history: 1, json: false, color: true };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--json"        => args.json = true,
            "--no-color"    => args.color = false,
            "--all"         => args.history = 0,
            "--help" | "-h" => print_help(),
            "--history" => {
                i += 1;
                if let Some(n) = argv.get(i).and_then(|s| s.parse().ok()) {
                    args.history = n;
                }
            }
            _ => {}
        }
        i += 1;
    }
    args
}

fn print_help() -> ! {
    println!("whyreboot — diagnose why Windows last rebooted");
    println!();
    println!("USAGE: whyreboot [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --history N   Show last N boot cycles (default: 1)");
    println!("  --all         Show all boot cycles in the log");
    println!("  --json        Output JSON instead of text");
    println!("  --no-color    Disable ANSI color output");
    println!("  --help, -h    Show this help");
    std::process::exit(0);
}

// ── Color ─────────────────────────────────────────────────────────────────────

struct Pal {
    crash: &'static str,
    warn:  &'static str,
    ok:    &'static str,
    info:  &'static str,
    bold:  &'static str,
    dim:   &'static str,
    reset: &'static str,
}

const NO_COLOR: Pal = Pal { crash: "", warn: "", ok: "", info: "", bold: "", dim: "", reset: "" };

const COLORS: Pal = Pal {
    crash: "\x1b[1;31m",
    warn:  "\x1b[1;33m",
    ok:    "\x1b[1;32m",
    info:  "\x1b[36m",
    bold:  "\x1b[1m",
    dim:   "\x1b[2m",
    reset: "\x1b[0m",
};

fn enable_ansi_color() -> bool {
    use windows::Win32::System::Console::*;
    const VTP: u32 = 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
    unsafe {
        let h = match GetStdHandle(STD_OUTPUT_HANDLE) {
            Ok(h) => h,
            Err(_) => return false,
        };
        if h.is_invalid() { return false; }
        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(h, &mut mode).is_err() { return false; }
        SetConsoleMode(h, CONSOLE_MODE(mode.0 | VTP)).is_ok()
    }
}

// ── Data structures ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct EventRecord {
    event_id:     u32,
    time_created: DateTime<Local>,
    provider:     String,
    data:         HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct WerRecord {
    time_created:  DateTime<Local>,
    p1:            u64,          // bugcheck stop code
    bucket_id:     String,       // WER fault bucket string
    minidump_path: Option<PathBuf>, // from AttachedFiles field
}

#[allow(dead_code)]
struct AudioPowerInfo {
    instance:     String,    // e.g. "0005"
    name:         String,    // e.g. "Realtek Audio"
    allow_idle_d3: Option<u32>, // AllowIdleIrpInD3: None=absent, 0=safe, 1+=risky
    enhanced_pm:  Option<u32>, // EnhancedPowerManagementEnabled
}

#[derive(Debug)]
enum Cause {
    BlueScreen { stop_code: u64, stop_name: &'static str, params: [u64; 4] },
    ForcedPowerOff,
    UnexpectedShutdown,
    WindowsUpdate { process: String },
    UserAction  { user: String, action: String, comment: String },
    SystemProcess { process: String, reason: String, action: String },
    NormalShutdown,
    Undetermined,
}

struct BootCycle {
    index:          usize,
    boot_time:      Option<DateTime<Local>>,
    shutdown_time:  Option<DateTime<Local>>,
    cause:          Cause,
    confidence:     u8,
    evidence:       Vec<String>,
    timeline:       Vec<(DateTime<Local>, String)>,
    wer_module:     Option<String>,
    minidumps:      Vec<(DateTime<Local>, PathBuf)>,
    display_events: Vec<EventRecord>,
}

// ── XML helpers ───────────────────────────────────────────────────────────────

fn xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let start = xml.find(&format!("<{}", tag))?;
    let region_end = xml[start..].find('>')?;
    let region = &xml[start..start + region_end];
    for (open, close) in [("='", '\''), ("=\"", '"')] {
        let search = format!("{}{}", attr, open);
        if let Some(pos) = region.find(&search) {
            let vs = pos + search.len();
            if let Some(ve) = region[vs..].find(close) {
                return Some(region[vs..vs + ve].to_string());
            }
        }
    }
    None
}

fn xml_elem(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)?;
    Some(xml[s..s + e].trim().to_string())
}

fn xml_data(xml: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut cursor = 0;
    let mut anon = 0usize;
    while let Some(rel) = xml[cursor..].find("<Data") {
        let abs = cursor + rel;
        let rest = &xml[abs..];
        let name = xml_attr(rest, "Data", "Name");
        if let Some(gt) = rest.find('>') {
            if rest.get(gt.saturating_sub(1)..gt) == Some("/") {
                cursor = abs + gt + 1;
                continue;
            }
            let cs = gt + 1;
            if let Some(end) = rest[cs..].find("</Data>") {
                let value = rest[cs..cs + end].trim().to_string();
                let key = name.unwrap_or_else(|| {
                    let k = format!("_{}", anon);
                    anon += 1;
                    k
                });
                map.insert(key, value);
                cursor = abs + cs + end + 7;
            } else {
                cursor = abs + 1;
            }
        } else {
            cursor = abs + 1;
        }
    }
    map
}

fn parse_event(xml: &str) -> Option<EventRecord> {
    let event_id: u32 = xml_elem(xml, "EventID")?.parse().ok()?;
    let time_str = xml_attr(xml, "TimeCreated", "SystemTime")?;
    let time_created = DateTime::parse_from_rfc3339(&time_str).ok()?.with_timezone(&Local);
    let provider = xml_attr(xml, "Provider", "Name").unwrap_or_default();
    let data = xml_data(xml);
    Some(EventRecord { event_id, time_created, provider, data })
}

// ── Event fetching ────────────────────────────────────────────────────────────

fn fetch_channel(channel: &[u16], query_str: &[u16], limit: usize) -> Vec<EventRecord> {
    let mut records = Vec::new();
    unsafe {
        let h_results = match EvtQuery(
            None,
            windows::core::PCWSTR(channel.as_ptr()),
            windows::core::PCWSTR(query_str.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        ) {
            Ok(h) => h,
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
                let mut pc = 0u32;
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

fn fetch_system_events() -> Vec<EventRecord> {
    // Build query as owned u16 array (for interior nul safety)
    let ch: Vec<u16> = "System\0".encode_utf16().collect();
    let q: Vec<u16> =
        "*[System[(EventID=12 or EventID=13 or EventID=41 or EventID=109 \
          or EventID=1074 or EventID=1076 \
          or EventID=6006 or EventID=6008 or EventID=6009 or EventID=6013)]]\0"
            .encode_utf16()
            .collect();
    fetch_channel(&ch, &q, 300)
}

fn fetch_wer_events() -> Vec<WerRecord> {
    let ch: Vec<u16> = "Application\0".encode_utf16().collect();
    let q: Vec<u16> =
        "*[System[EventID=1001]]\0"
            .encode_utf16()
            .collect();

    let raw = fetch_channel(&ch, &q, 100);
    raw.into_iter().filter_map(|ev| {
        // Only Windows Error Reporting BlueScreen/BugCheck events
        let prov = ev.provider.to_lowercase();
        if !prov.contains("error reporting") && !prov.contains("wer") {
            return None;
        }
        // WER uses "BlueScreen" (not "BugCheck") for kernel crashes
        let event_name = ev.data.get("EventName").map(|s| s.as_str()).unwrap_or("");
        let is_crash = event_name.eq_ignore_ascii_case("BlueScreen")
            || event_name.eq_ignore_ascii_case("BugCheck");
        if !is_crash {
            return None;
        }
        // WER P1 is the stop code as bare hex without "0x" (e.g. "9f" for 0x0000009F)
        let p1 = ev.data.get("P1")
            .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
            .unwrap_or(0);
        // Bucket field is literally named "Bucket" in WER XML (not BucketId)
        let bucket_id = ev.data.get("Bucket")
            .or_else(|| ev.data.get("BucketId"))
            .or_else(|| ev.data.get("HashedBucket"))
            .or_else(|| ev.data.get("_0"))
            .cloned()
            .unwrap_or_default();
        // Extract minidump path from AttachedFiles (lines ending in .dmp)
        let minidump_path = ev.data.get("AttachedFiles").and_then(|s| {
            s.lines()
                .map(|l| l.trim())
                .find(|l| l.to_lowercase().ends_with(".dmp"))
                .map(|l| {
                    // Strip \\?\ UNC prefix if present
                    let clean = l.trim_start_matches(r"\\?\");
                    PathBuf::from(clean)
                })
        });
        Some(WerRecord { time_created: ev.time_created, p1, bucket_id, minidump_path })
    }).collect()
}

fn list_minidumps() -> Vec<(DateTime<Local>, PathBuf)> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let dir = PathBuf::from(sysroot).join("Minidump");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut v: Vec<(DateTime<Local>, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension()
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

// ── Device power settings ─────────────────────────────────────────────────────

fn reg_read_dword(hk: windows::Win32::System::Registry::HKEY, name: &str) -> Option<u32> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};
    let w: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut val = 0u32;
    let mut sz  = 4u32;
    let mut tp  = REG_VALUE_TYPE(0);
    let ok = unsafe {
        RegQueryValueExW(
            hk,
            windows::core::PCWSTR(w.as_ptr()),
            None,
            Some(&mut tp),
            Some(&mut val as *mut u32 as *mut u8),
            Some(&mut sz),
        ).ok().is_ok()
    };
    if ok && tp.0 == 4 /* REG_DWORD */ { Some(val) } else { None }
}

fn reg_read_string(hk: windows::Win32::System::Registry::HKEY, name: &str) -> Option<String> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};
    let w: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut sz = 0u32;
    let mut tp = REG_VALUE_TYPE(0);
    // First call: get required buffer size
    unsafe {
        let _ = RegQueryValueExW(hk, windows::core::PCWSTR(w.as_ptr()), None, Some(&mut tp), None, Some(&mut sz));
    }
    if sz < 2 { return None; }
    let mut buf = vec![0u8; sz as usize + 2];
    let ok = unsafe {
        RegQueryValueExW(
            hk,
            windows::core::PCWSTR(w.as_ptr()),
            None,
            Some(&mut tp),
            Some(buf.as_mut_ptr()),
            Some(&mut sz),
        ).ok().is_ok()
    };
    if ok && (tp.0 == 1 || tp.0 == 2) /* REG_SZ / REG_EXPAND_SZ */ {
        let chars = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u16, sz as usize / 2) };
        let s = String::from_utf16_lossy(chars);
        let trimmed = s.trim_end_matches('\0');
        if !trimmed.is_empty() { Some(trimmed.to_string()) } else { None }
    } else {
        None
    }
}

fn check_audio_power_settings() -> Vec<AudioPowerInfo> {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegCloseKey, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    const BASE: &str = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}";
    let mut results = Vec::new();
    unsafe {
        let base_w: Vec<u16> = BASE.encode_utf16().chain([0]).collect();
        let mut hk_base = HKEY(std::ptr::null_mut());
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, windows::core::PCWSTR(base_w.as_ptr()), None, KEY_READ, &mut hk_base).ok().is_err() {
            return results;
        }
        for i in 0..=20u32 {
            let inst = format!("{:04}", i);
            let path = format!("{}\\{}", BASE, inst);
            let path_w: Vec<u16> = path.encode_utf16().chain([0]).collect();
            let mut hk = HKEY(std::ptr::null_mut());
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, windows::core::PCWSTR(path_w.as_ptr()), None, KEY_READ, &mut hk).ok().is_err() {
                continue;
            }
            let name = match reg_read_string(hk, "DriverDesc").or_else(|| reg_read_string(hk, "FriendlyName")) {
                Some(n) if !n.is_empty() => n,
                _ => { let _ = RegCloseKey(hk); continue; }
            };
            let allow_idle_d3 = reg_read_dword(hk, "AllowIdleIrpInD3");
            let enhanced_pm   = reg_read_dword(hk, "EnhancedPowerManagementEnabled");
            let _ = RegCloseKey(hk);
            results.push(AudioPowerInfo { instance: inst, name, allow_idle_d3, enhanced_pm });
        }
        let _ = RegCloseKey(hk_base);
    }
    results
}

// ── Analysis ──────────────────────────────────────────────────────────────────

fn hex_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if s.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
        // Bare hex without 0x prefix (e.g. "9f" from WER events)
        u64::from_str_radix(s, 16).ok()
    } else {
        s.parse().ok()
    }
}

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
    (0x0000019C, "WIN32K_POWER_WATCHDOG_TIMEOUT"),
    (0x00000119, "VIDEO_SCHEDULER_INTERNAL_ERROR"),
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

fn stop_name(code: u64) -> &'static str {
    STOP_CODES
        .iter()
        .find(|&&(c, _)| c == code)
        .map(|&(_, n)| n)
        .unwrap_or("(unknown)")
}

// Full SHTDN_REASON_* decode table (reason code stored as 8 hex digits)
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

fn decode_reason(code: &str) -> Option<&'static str> {
    let k = code
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_lowercase();
    // Pad to 8 hex digits
    let padded = format!("{:0>8}", k);
    REASON_CODES
        .iter()
        .find(|&&(c, _)| c == padded)
        .map(|&(_, d)| d)
}

// Extract driver/module name from WER bucket ID string.
// Examples:
//   "0x9F_3_DXG_POWER_IRP_TIMEOUT_portcls!GetIrpDisposition"  → "portcls"
//   "0x9F_3_usbccgp!WaitForSignal"                            → "usbccgp"
//   "0x9F_3_DXG_POWER_IRP_TIMEOUT_IMAGE_pci.sys"              → "pci.sys"
//   "0x9F_3_usbccgp_IMAGE_UsbHub3.sys"                        → "UsbHub3.sys"
fn module_from_bucket(bucket: &str) -> Option<String> {
    let lower = bucket.to_lowercase();
    // Pattern: "module!function" — the module is before the bang
    if let Some(bang) = bucket.find('!') {
        // Walk back from ! to the preceding _
        let before = &bucket[..bang];
        let start = before.rfind('_').map(|i| i + 1).unwrap_or(0);
        let m = &before[start..];
        if !m.is_empty() {
            return Some(m.to_string());
        }
    }
    // Pattern: "_IMAGE_module.sys" or "_image_module.sys"
    if let Some(pos) = lower.find("_image_") {
        let rest = &bucket[pos + 7..];
        let end = rest.find('_').unwrap_or(rest.len());
        let m = &rest[..end];
        if !m.is_empty() {
            return Some(m.to_string());
        }
    }
    // Fallback: look for tokens ending with a known driver extension
    for token in bucket.split('_') {
        let tl = token.to_lowercase();
        if tl.ends_with(".sys") || tl.ends_with(".exe") || tl.ends_with(".dll") {
            return Some(token.to_string());
        }
    }
    None
}

// Core per-cycle analysis. Returns (cause, confidence, shutdown_time, evidence, timeline).
fn analyze_slice(
    boot_time: Option<DateTime<Local>>,
    post_boot: &[EventRecord],
    pre_boot:  &[EventRecord],
) -> (Cause, u8, Option<DateTime<Local>>, Vec<String>, Vec<(DateTime<Local>, String)>) {
    let e41            = post_boot.iter().find(|e| e.event_id == 41);
    let unexpected_flag = post_boot.iter().any(|e| e.event_id == 6008);
    let e1074          = pre_boot.iter().find(|e| e.event_id == 1074);
    let e13            = pre_boot.iter().find(|e| e.event_id == 13);
    let e6006          = pre_boot.iter().find(|e| e.event_id == 6006);

    // shutdown_time is only meaningful for clean shutdowns
    let shutdown_time = if e41.is_none() {
        e1074.or(e13).or(e6006).map(|e| e.time_created)
    } else {
        None
    };

    let mut evidence = Vec::new();
    let mut timeline = Vec::new();

    if let Some(bt) = boot_time {
        timeline.push((bt, "System started (Event 12)".to_string()));
    }

    let (cause, confidence): (Cause, u8) = if let Some(ev) = e41 {
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

        timeline.push((
            ev.time_created,
            "Kernel-Power: logged at boot — previous session ended unexpectedly (Event 41)".into(),
        ));

        if stop_code != 0 {
            let name = stop_name(stop_code);
            evidence.push(format!("BSOD stop code: 0x{:08X} — {}", stop_code, name));
            // Annotate 0x9F param 1 meaning
            if stop_code == 0x9F {
                let p1_meaning = match params[0] {
                    1 => " (device object failed WaitForSingleObject during power transition)",
                    2 => " (device object failed IRP_MN_SET_POWER for SystemPowerState)",
                    3 => " (device object stalled during IRP_MN_SET_POWER; check P4)",
                    4 => " (device object stalled powering down; check P4)",
                    _ => "",
                };
                if !p1_meaning.is_empty() {
                    evidence.push(format!(
                        "  0x9F P1=0x{:X}{}", params[0], p1_meaning
                    ));
                }
            }
            for (i, &p) in params.iter().enumerate() {
                if p != 0 {
                    evidence.push(format!("  Parameter {}: 0x{:016X}", i + 1, p));
                }
            }
            (Cause::BlueScreen { stop_code, stop_name: name, params }, 95)
        } else if power_btn {
            evidence.push("Power button was held down (hard power-off)".into());
            (Cause::ForcedPowerOff, 82)
        } else {
            evidence.push("Event 41: system did not shut down cleanly".into());
            if unexpected_flag {
                evidence.push("  Confirmed by Event 6008 at next startup".into());
            }
            (Cause::UnexpectedShutdown, 75)
        }
    } else if let Some(ev) = e1074 {
        let process     = ev.data.get("param1").cloned().unwrap_or_default();
        let user        = ev.data.get("param3").cloned().unwrap_or_default();
        let reason_code = ev.data.get("param4").cloned().unwrap_or_default();
        let action_raw  = ev.data.get("param5").cloned().unwrap_or_default();
        let comment     = ev.data.get("param6").cloned().unwrap_or_default();

        let action = match action_raw.as_str() {
            "restart"   => "Restart",
            "power off" => "Shutdown",
            s if !s.is_empty() => s,
            _ => "Shutdown/Restart",
        }
        .to_string();

        timeline.push((
            ev.time_created,
            format!("{} initiated by {} (Event 1074)", action, process),
        ));

        evidence.push(format!("Process: {}", process));
        if !user.is_empty() {
            evidence.push(format!("User: {}", user));
        }
        if let Some(desc) = decode_reason(&reason_code) {
            evidence.push(format!("Reason: {} ({})", reason_code, desc));
        } else if !reason_code.is_empty() {
            evidence.push(format!("Reason code: {}", reason_code));
        }
        if !comment.is_empty() {
            evidence.push(format!("Comment: \"{}\"", comment));
        }

        let pl = process.to_lowercase();
        let is_update = pl.contains("tiworker")
            || pl.contains("trustedinstaller")
            || pl.contains("wuauclt")
            || pl.contains("windowsupdate")
            || reason_code.trim().eq_ignore_ascii_case("0x80020002");

        if is_update {
            (Cause::WindowsUpdate { process }, 92)
        } else if user.to_lowercase().contains("system")
            || user.to_lowercase().contains("authority")
        {
            (Cause::SystemProcess { process, reason: reason_code, action }, 87)
        } else {
            (Cause::UserAction { user, action, comment }, 90)
        }
    } else if unexpected_flag {
        evidence
            .push("Event 6008: Windows logged that the previous shutdown was unexpected".into());
        evidence.push(
            "No Kernel-Power Event 41 found — crash may have occurred before event was written"
                .into(),
        );
        (Cause::UnexpectedShutdown, 60)
    } else if e13.is_some() || e6006.is_some() {
        if let Some(ev) = e13 {
            timeline.push((ev.time_created, "OS shutdown (Event 13)".into()));
            evidence.push("Event 13: Clean OS shutdown recorded".into());
        }
        if let Some(ev) = e6006 {
            timeline.push((
                ev.time_created,
                "Event log stopped cleanly (Event 6006)".into(),
            ));
            evidence.push("Event 6006: Event log stopped cleanly".into());
        }
        (Cause::NormalShutdown, 60)
    } else {
        evidence.push("No conclusive shutdown events found in log window.".into());
        (Cause::Undetermined, 10)
    };

    (cause, confidence, shutdown_time, evidence, timeline)
}

fn collect_boot_indices(events: &[EventRecord]) -> Vec<usize> {
    // Prefer Kernel-General Event 12 (earliest in boot sequence)
    let general: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.event_id == 12 && e.provider.contains("General"))
        .map(|(i, _)| i)
        .collect();
    if !general.is_empty() {
        return general;
    }
    // Fallback: any Event 12
    events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.event_id == 12)
        .map(|(i, _)| i)
        .collect()
}

fn extract_boot_cycles(
    events: &[EventRecord],
    wer: &[WerRecord],
    dumps: &[(DateTime<Local>, PathBuf)],
    limit: usize,
) -> Vec<BootCycle> {
    let boot_idxs = collect_boot_indices(events);

    // If no boot markers found, analyze all events as one cycle
    if boot_idxs.is_empty() {
        let (cause, conf, shutdown_time, evidence, timeline) =
            analyze_slice(None, &[], events);
        return vec![BootCycle {
            index:          0,
            boot_time:      None,
            shutdown_time,
            cause,
            confidence:     conf,
            evidence,
            timeline,
            wer_module:     None,
            minidumps:      Vec::new(),
            display_events: events.iter().take(20).cloned().collect(),
        }];
    }

    let n = if limit == 0 {
        boot_idxs.len()
    } else {
        limit.min(boot_idxs.len())
    };

    let mut cycles: Vec<BootCycle> = (0..n)
        .map(|idx| {
            let bi = boot_idxs[idx];
            let boot_time = Some(events[bi].time_created);

            // post_boot: newer events logged at this boot's startup (lower indices)
            let post_start = if idx == 0 { 0 } else { boot_idxs[idx - 1] + 1 };
            let post_boot = &events[post_start..bi];

            // pre_boot: older events from the session that preceded this boot
            let pre_end = if idx + 1 < boot_idxs.len() {
                boot_idxs[idx + 1]
            } else {
                events.len()
            };
            let pre_boot = &events[bi + 1..pre_end];

            let (cause, conf, shutdown_time, evidence, timeline) =
                analyze_slice(boot_time, post_boot, pre_boot);

            let display_events: Vec<EventRecord> =
                events[post_start..pre_end].iter().take(20).cloned().collect();

            BootCycle {
                index:     idx,
                boot_time,
                shutdown_time,
                cause,
                confidence: conf,
                evidence,
                timeline,
                wer_module: None,
                minidumps:  Vec::new(),
                display_events,
            }
        })
        .collect();

    // Collect boot times for annotation pass (avoids borrow conflicts)
    let boot_times: Vec<Option<DateTime<Local>>> =
        cycles.iter().map(|c| c.boot_time).collect();

    // Annotate cycles with WER faulting module and minidump files
    for idx in 0..cycles.len() {
        let boot_time = boot_times[idx];
        // Previous cycle (higher index = older boot) gives us the start of the crashed session
        let crashed_session_start = if idx + 1 < boot_times.len() {
            boot_times[idx + 1]
        } else {
            None
        };
        // WER processes the crash during the NEXT boot's session (lower idx = newer)
        let wer_session_end = if idx > 0 { boot_times[idx - 1] } else { None };

        // 1. Match filesystem minidumps (crash time is just before this boot)
        let dump_lower = crashed_session_start.unwrap_or_else(|| {
            boot_time
                .map(|t| t - Duration::days(30))
                .unwrap_or_else(Local::now)
        });
        let dump_upper = boot_time
            .map(|t| t + Duration::minutes(10))
            .unwrap_or_else(Local::now);
        cycles[idx].minidumps = dumps
            .iter()
            .filter(|(t, _)| *t >= dump_lower && *t <= dump_upper)
            .cloned()
            .collect();

        // 2. Match WER BugCheck event; supplement minidumps from WER AttachedFiles
        if let Cause::BlueScreen { stop_code, .. } = &cycles[idx].cause {
            let sc = *stop_code;
            let bt = boot_time.unwrap_or_else(Local::now);
            let upper = wer_session_end.unwrap_or_else(Local::now);
            let wer_match = wer.iter().find(|w| {
                w.p1 == sc && w.time_created >= bt && w.time_created <= upper
            });
            if let Some(wr) = wer_match {
                let m = module_from_bucket(&wr.bucket_id);
                cycles[idx].wer_module = m.or_else(|| {
                    if !wr.bucket_id.is_empty() {
                        Some(format!("(bucket: {})", &wr.bucket_id))
                    } else {
                        None
                    }
                });
                // Supplement with minidump path from WER if filesystem found nothing
                if cycles[idx].minidumps.is_empty() {
                    if let Some(ref p) = wr.minidump_path {
                        cycles[idx].minidumps = vec![(wr.time_created, p.clone())];
                    }
                }
            }
        }
    }

    cycles
}

// ── Display helpers ───────────────────────────────────────────────────────────

fn fmt_secs(s: i64) -> String {
    let s = s.max(0);
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
    }
}

fn short_provider(p: &str) -> &str {
    p.rfind('-').map(|i| &p[i + 1..]).unwrap_or(p)
}

fn event_summary(ev: &EventRecord) -> String {
    let d = &ev.data;
    match ev.event_id {
        12   => "System started".into(),
        13   => "System shutdown initiated".into(),
        41   => format!(
            "Unexpected shutdown — BugCheck={}",
            d.get("BugcheckCode").map(|s| s.as_str()).unwrap_or("?")
        ),
        109  => "Kernel power button transition".into(),
        1074 => format!(
            "{} by {}",
            d.get("param5").map(|s| s.as_str()).unwrap_or("action"),
            d.get("param3").map(|s| s.as_str()).unwrap_or("?")
        ),
        1076 => "Shutdown reason documented".into(),
        6006 => "Event log stopped cleanly (shutdown)".into(),
        6008 => "Previous shutdown was unexpected".into(),
        6009 => "Startup: Windows version info".into(),
        6013 => d
            .get("param1")
            .and_then(|s| s.parse::<i64>().ok())
            .map(|s| format!("System uptime: {}", fmt_secs(s)))
            .unwrap_or_else(|| "System uptime".into()),
        id   => format!("Event {}", id),
    }
}

fn cause_pal<'p>(cause: &Cause, pal: &'p Pal) -> &'p str {
    match cause {
        Cause::BlueScreen { .. } | Cause::ForcedPowerOff | Cause::UnexpectedShutdown => {
            pal.crash
        }
        Cause::Undetermined => pal.warn,
        _ => pal.ok,
    }
}

fn cause_label(cause: &Cause) -> &'static str {
    match cause {
        Cause::BlueScreen { .. }      => "BLUE SCREEN OF DEATH (BSOD)",
        Cause::ForcedPowerOff         => "FORCED POWER-OFF",
        Cause::UnexpectedShutdown     => "UNEXPECTED / UNCLEAN SHUTDOWN",
        Cause::WindowsUpdate { .. }   => "WINDOWS UPDATE",
        Cause::UserAction { .. }      => "USER-INITIATED",
        Cause::SystemProcess { .. }   => "SYSTEM / SOFTWARE RESTART",
        Cause::NormalShutdown         => "NORMAL SHUTDOWN",
        Cause::Undetermined           => "UNDETERMINED",
    }
}

fn cause_detail(cause: &Cause) -> String {
    match cause {
        Cause::BlueScreen { stop_code, stop_name, .. } => {
            format!("Stop code 0x{:08X} — {}", stop_code, stop_name)
        }
        Cause::ForcedPowerOff => {
            "Power button held down or power cable pulled".into()
        }
        Cause::UnexpectedShutdown => {
            "System did not shut down cleanly (crash or power loss)".into()
        }
        Cause::WindowsUpdate { process } => {
            format!(
                "Restart to apply updates ({})",
                process.split('\\').last().unwrap_or(process)
            )
        }
        Cause::UserAction { user, action, .. } => format!("{} by {}", action, user),
        Cause::SystemProcess { process, action, .. } => {
            format!("{} by {}", action, process.split('\\').last().unwrap_or(process))
        }
        Cause::NormalShutdown => {
            "System shut down cleanly; no specific initiator recorded".into()
        }
        Cause::Undetermined => {
            "Insufficient event log data to determine cause".into()
        }
    }
}

// ── Explanation ───────────────────────────────────────────────────────────────

fn generate_explanation(
    cause:  &Cause,
    module: &Option<String>,
    audio:  &[AudioPowerInfo],
) -> Vec<String> {
    let mut out = Vec::new();
    let Cause::BlueScreen { stop_code, params, .. } = cause else { return out };

    match *stop_code {
        0x0000009F => {
            let m = module.as_deref().unwrap_or("(unknown driver)");
            let m_low = m.to_lowercase();
            let p1 = params[0];

            let is_audio = m_low.contains("portcls") || m_low.contains("audio") || m_low.contains("hdaud");
            let is_usb   = m_low.contains("usbccgp") || m_low.contains("usbhub") || m_low.contains("usb");

            out.push(format!(
                "DRIVER_POWER_STATE_FAILURE: {} failed to complete a power state", m
            ));
            out.push("transition in time. Windows was going to sleep, hibernating, or".to_string());
            out.push("shutting down when the driver stalled and never responded.".to_string());

            if p1 == 3 {
                out.push(String::new());
                out.push(format!(
                    "P1=3: the OS sent an IRP_MN_SET_POWER request to {} but the driver", m
                ));
                out.push("object did not complete it before the watchdog expired.".to_string());
            }

            out.push(String::new());
            out.push("Recommended actions:".to_string());

            if is_audio {
                // Check if any audio device has the risky default setting
                let all_safe = !audio.is_empty() && audio.iter().all(|d| d.allow_idle_d3 == Some(0));
                let none_set = audio.iter().all(|d| d.allow_idle_d3.is_none());

                if all_safe {
                    out.push("  [OK] AllowIdleIrpInD3=0 is already set for all audio devices.".to_string());
                    out.push("  1. The driver itself may be buggy — update your audio driver.".to_string());
                    out.push("  2. Update BIOS/UEFI firmware.".to_string());
                } else {
                    if none_set {
                        out.push("  1. Disable audio idle D3 power entry (most effective fix):".to_string());
                        out.push("     For each entry below, create DWORD value AllowIdleIrpInD3=0 in:".to_string());
                        out.push(format!("     HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e96c-e325-11ce-bfc1-08002be10318}}\\<inst>"));
                    } else {
                        out.push("  1. Some audio devices still have AllowIdleIrpInD3 unset (see below).".to_string());
                        out.push("     Set AllowIdleIrpInD3=0 (DWORD) for all audio class instances.".to_string());
                    }
                    out.push("  2. Alternatively, via Device Manager:".to_string());
                    out.push("     Sound, video and game controllers → [audio device] → Properties".to_string());
                    out.push("     → Power Management → uncheck \"Allow the computer to turn off".to_string());
                    out.push("     this device to save power\" (if tab is visible)".to_string());
                    out.push("  3. Update your audio driver (Realtek/Intel HD Audio).".to_string());
                    out.push("  4. Check for a BIOS update — AMD platform power management bugs".to_string());
                    out.push("     can manifest as portcls stalls.".to_string());
                }
            } else if is_usb {
                out.push("  1. Disable USB selective suspend:".to_string());
                out.push("     Control Panel → Power Options → Change plan settings".to_string());
                out.push("     → Change advanced power settings → USB settings".to_string());
                out.push("     → USB selective suspend setting → Disabled".to_string());
                out.push("  2. Disconnect USB devices before sleep/shutdown as a workaround.".to_string());
                out.push("  3. Update chipset/USB drivers.".to_string());
            } else {
                out.push(format!("  1. Update the {} driver.", m));
                out.push("  2. Check Device Manager for a Power Management tab on this device.".to_string());
                out.push("  3. Update BIOS/UEFI firmware.".to_string());
            }
        }

        0x0000019C => {
            let m = module.as_deref().unwrap_or("(unknown driver)");
            out.push("WIN32K_POWER_WATCHDOG_TIMEOUT: the display subsystem failed to respond".to_string());
            out.push(format!("during a power transition. {} timed out waking the GPU from sleep.", m));
            out.push(String::new());
            out.push("Recommended actions:".to_string());
            out.push("  1. Update GPU driver (NVIDIA/AMD) — this is the most common fix.".to_string());
            out.push("  2. Disable Fast Startup:".to_string());
            out.push("     Control Panel → Power Options → Choose what the power buttons do".to_string());
            out.push("     → uncheck \"Turn on fast startup (recommended)\"".to_string());
            out.push("  3. Install pending Windows updates — Microsoft patches dxgkrnl watchdog".to_string());
            out.push("     issues via cumulative updates.".to_string());
            out.push("  4. In NVIDIA/AMD control panel: set power management mode to".to_string());
            out.push("     \"Prefer maximum performance\" (disables aggressive GPU idle).".to_string());
        }

        0x000000FE | 0x00000144 => {
            out.push("BUGCODE_USB_DRIVER: a USB driver triggered a fatal error.".to_string());
            out.push(String::new());
            out.push("Recommended actions:".to_string());
            out.push("  1. Disconnect USB devices and test if crashes stop.".to_string());
            out.push("  2. Update chipset/USB 3 drivers.".to_string());
            out.push("  3. Disable USB selective suspend (Power Options → USB settings).".to_string());
        }

        _ => {}
    }
    out
}

// ── Text output ───────────────────────────────────────────────────────────────

fn print_cycle(cycle: &BootCycle, pal: &Pal, total: usize, audio: &[AudioPowerInfo]) {
    let w = 74usize;
    let line = "─".repeat(w);
    let dline = "═".repeat(w);

    println!();
    if total > 1 {
        let label = if cycle.index == 0 {
            format!(
                " Boot Cycle {} of {} — most recent ",
                total - cycle.index,
                total
            )
        } else {
            format!(" Boot Cycle {} of {} ", total - cycle.index, total)
        };
        let pad = w.saturating_sub(label.len());
        let lpad = pad / 2;
        let rpad = pad - lpad;
        println!("{}{}{}{}{}{}",
            pal.bold,
            "═".repeat(lpad),
            label,
            "═".repeat(rpad),
            pal.reset,
            "",
        );
    } else {
        println!("{}{}{}",
            pal.bold,
            dline,
            pal.reset,
        );
    }

    if let Some(bt) = cycle.boot_time {
        let ago = Local::now().signed_duration_since(bt);
        let ago_s = if ago.num_days() >= 2 {
            format!("{} days ago", ago.num_days())
        } else if ago.num_hours() >= 2 {
            format!("{} hours ago", ago.num_hours())
        } else {
            format!("{} minutes ago", ago.num_minutes())
        };
        println!("  {}Last boot:{} {}  ({})",
            pal.bold, pal.reset,
            bt.format("%Y-%m-%d %H:%M:%S"),
            ago_s,
        );
    } else {
        println!("  {}Boot time:{} (unknown — no Event 12 in log window)", pal.bold, pal.reset);
    }

    if let (Some(sd), Some(bt)) = (cycle.shutdown_time, cycle.boot_time) {
        let offline = bt.signed_duration_since(sd).num_seconds();
        println!("  {}Offline:{}   {} → {}  ({})",
            pal.bold, pal.reset,
            sd.format("%H:%M:%S"),
            bt.format("%H:%M:%S"),
            fmt_secs(offline),
        );
    }

    println!();

    let color = cause_pal(&cycle.cause, pal);
    println!("  {}VERDICT:{}    {}{}{} ({}% confidence)",
        pal.bold, pal.reset,
        color,
        cause_label(&cycle.cause),
        pal.reset,
        cycle.confidence,
    );
    println!("              {}", cause_detail(&cycle.cause));

    if let Some(ref m) = cycle.wer_module {
        println!("  {}Module:{}     {} {}[from WER Event 1001]{}",
            pal.bold, pal.reset,
            m,
            pal.info,
            pal.reset,
        );
    }

    if !cycle.evidence.is_empty() {
        println!();
        println!("  {}Evidence:{}",  pal.bold, pal.reset);
        for line_str in &cycle.evidence {
            println!("    • {}", line_str);
        }
    }

    if cycle.timeline.len() > 1 {
        let mut tl = cycle.timeline.clone();
        tl.sort_by_key(|(t, _)| *t);
        println!();
        println!("  {}Timeline:{}", pal.bold, pal.reset);
        for (t, msg) in &tl {
            println!("    {}{}{}  {}", pal.dim, t.format("%Y-%m-%d %H:%M:%S"), pal.reset, msg);
        }
    }

    if !cycle.minidumps.is_empty() {
        println!();
        println!("  {}Minidumps:{}", pal.bold, pal.reset);
        for (t, p) in &cycle.minidumps {
            println!("    {}{}{}  {}", pal.dim, t.format("%Y-%m-%d %H:%M:%S"), pal.reset,
                p.display());
        }
    }

    // Device power settings (shown when crash is power-related and audio data is available)
    let module_low = cycle.wer_module.as_deref().unwrap_or("").to_lowercase();
    let is_power_crash = matches!(&cycle.cause, Cause::BlueScreen { stop_code, .. }
        if *stop_code == 0x9F || *stop_code == 0x19C || *stop_code == 0xFE || *stop_code == 0x144);
    let is_audio_crash = is_power_crash && (
        module_low.contains("portcls") || module_low.contains("audio") || module_low.contains("hdaud")
    );
    if is_audio_crash && !audio.is_empty() {
        println!();
        println!("  {}Device Power Settings (audio class):{}", pal.bold, pal.reset);
        for dev in audio {
            let (status_color, status_text) = match dev.allow_idle_d3 {
                Some(0) => (pal.ok,   "AllowIdleIrpInD3=0  [safe — D3 idle disabled]"),
                Some(_) => (pal.crash,"AllowIdleIrpInD3=1  [RISKY — D3 idle enabled]"),
                None    => (pal.warn, "AllowIdleIrpInD3: not set [driver default — risky]"),
            };
            println!("    [{}] {:<32}  {}{}{}", dev.instance, dev.name, status_color, status_text, pal.reset);
        }
    }

    // Explanation and remediation
    let explanation = generate_explanation(&cycle.cause, &cycle.wer_module, audio);
    if !explanation.is_empty() {
        println!();
        println!("  {}Explanation:{}", pal.bold, pal.reset);
        for ln in &explanation {
            if ln.is_empty() {
                println!();
            } else {
                println!("    {}", ln);
            }
        }
    }

    if !cycle.display_events.is_empty() {
        println!();
        println!("{}", line);
        println!(
            "{:<20} {:>6}  {:<26}  {}",
            "Time", "Event", "Provider", "Summary"
        );
        println!("{}", line);
        for ev in &cycle.display_events {
            println!(
                "{:<20} {:>6}  {:<26.26}  {}",
                ev.time_created.format("%Y-%m-%d %H:%M:%S"),
                ev.event_id,
                short_provider(&ev.provider),
                event_summary(ev),
            );
        }
        println!("{}", line);
    }
}

// ── JSON output ───────────────────────────────────────────────────────────────

fn json_str(s: &str) -> String {
    let escaped = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{}\"", escaped)
}

fn print_json(cycles: &[BootCycle]) {
    let now = Local::now().to_rfc3339();
    println!("{{");
    println!("  \"generated\": {},", json_str(&now));
    println!("  \"cycle_count\": {},", cycles.len());
    println!("  \"cycles\": [");
    for (ci, cycle) in cycles.iter().enumerate() {
        println!("    {{");
        println!("      \"index\": {},", cycle.index);
        if let Some(bt) = cycle.boot_time {
            println!("      \"boot_time\": {},", json_str(&bt.to_rfc3339()));
        } else {
            println!("      \"boot_time\": null,");
        }
        if let Some(sd) = cycle.shutdown_time {
            println!("      \"shutdown_time\": {},", json_str(&sd.to_rfc3339()));
        } else {
            println!("      \"shutdown_time\": null,");
        }
        println!("      \"confidence\": {},", cycle.confidence);

        // Cause
        let (kind, extra) = match &cycle.cause {
            Cause::BlueScreen { stop_code, stop_name, params } => (
                "BlueScreen",
                format!(
                    "\"stop_code\": \"0x{:08X}\", \"stop_name\": {}, \"params\": [\"{:#x}\",\"{:#x}\",\"{:#x}\",\"{:#x}\"],",
                    stop_code, json_str(stop_name),
                    params[0], params[1], params[2], params[3]
                ),
            ),
            Cause::WindowsUpdate { process } => (
                "WindowsUpdate",
                format!("\"process\": {},", json_str(process)),
            ),
            Cause::UserAction { user, action, comment } => (
                "UserAction",
                format!(
                    "\"user\": {}, \"action\": {}, \"comment\": {},",
                    json_str(user), json_str(action), json_str(comment)
                ),
            ),
            Cause::SystemProcess { process, reason, action } => (
                "SystemProcess",
                format!(
                    "\"process\": {}, \"reason\": {}, \"action\": {},",
                    json_str(process), json_str(reason), json_str(action)
                ),
            ),
            other => (cause_label(other), String::new()),
        };
        println!("      \"cause\": {},", json_str(kind));
        if !extra.is_empty() {
            for line_str in extra.lines() {
                println!("      {}", line_str);
            }
        }

        if let Some(ref m) = cycle.wer_module {
            println!("      \"faulting_module\": {},", json_str(m));
        } else {
            println!("      \"faulting_module\": null,");
        }

        // Evidence
        print!("      \"evidence\": [");
        for (i, e) in cycle.evidence.iter().enumerate() {
            if i > 0 { print!(", "); }
            print!("{}", json_str(e));
        }
        println!("],");

        // Minidumps
        print!("      \"minidumps\": [");
        for (i, (_, p)) in cycle.minidumps.iter().enumerate() {
            if i > 0 { print!(", "); }
            print!("{}", json_str(&p.to_string_lossy()));
        }
        println!("]");

        if ci + 1 < cycles.len() {
            println!("    }},");
        } else {
            println!("    }}");
        }
    }
    println!("  ]");
    println!("}}");
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args = parse_args();
    let pal = if args.color && enable_ansi_color() {
        &COLORS
    } else {
        &NO_COLOR
    };

    eprintln!("Scanning Windows Event Log for shutdown/reboot events…");

    let sys_events  = fetch_system_events();
    let wer_events  = fetch_wer_events();
    let dumps       = list_minidumps();
    let audio_power = check_audio_power_settings();

    if sys_events.is_empty() {
        eprintln!("No events found. Try running as Administrator.");
        std::process::exit(1);
    }

    if !wer_events.is_empty() {
        eprintln!("  Found {} WER BugCheck event(s).", wer_events.len());
    }
    if !dumps.is_empty() {
        eprintln!("  Found {} minidump file(s).", dumps.len());
    }
    if !audio_power.is_empty() {
        eprintln!("  Checked {} audio device power setting(s).", audio_power.len());
    }

    let cycles = extract_boot_cycles(&sys_events, &wer_events, &dumps, args.history);

    eprintln!("  Analyzed {} boot cycle(s).\n", cycles.len());

    if args.json {
        print_json(&cycles);
    } else {
        // Print oldest to newest so the most recent result is at the bottom
        for cycle in cycles.iter().rev() {
            print_cycle(cycle, pal, cycles.len(), &audio_power);
        }
        println!();
    }
}
