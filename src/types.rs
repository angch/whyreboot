// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::timestamp::Timestamp;
use std::path::PathBuf;

/// Parsed representation of a single Windows Event Log record.
/// `data` holds all `<Data Name="…">value</Data>` fields from the XML;
/// unnamed fields are keyed `_0`, `_1`, etc.
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub event_id:     u32,
    pub time_created: Timestamp,
    pub provider:     String,
    pub data:         Vec<(String, String)>,
}

impl EventRecord {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.data.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// One Windows Error Reporting BugCheck record (Application log, Event 1001).
/// `p1` is the bugcheck stop code — WER stores it as bare lowercase hex in the
/// `P1` field (e.g. `"9f"`), parsed to u64 here.
/// `bucket_id` is the WER fault bucket string and typically encodes the faulting
/// module; see `module_from_bucket` in analysis.rs.
#[derive(Debug, Clone)]
pub struct WerRecord {
    pub time_created:  Timestamp,
    pub p1:            u64,
    pub bucket_id:     String,
    pub minidump_path: Option<PathBuf>,
}

/// Power management configuration for one audio device class instance,
/// read from the Windows registry.
/// `allow_idle_d3`: `None` = value absent (driver default, typically risky);
/// `Some(0)` = safe; `Some(1)` = driver may enter D3 on idle (risky for portcls).
#[allow(dead_code)]
pub struct AudioPowerInfo {
    pub instance:      String,    // zero-padded 4-digit instance number, e.g. "0005"
    pub name:          String,    // DriverDesc or FriendlyName
    pub allow_idle_d3: Option<u32>,
    pub enhanced_pm:   Option<u32>,
}

/// Why this boot cycle ended.
/// Variants are ordered by detection priority in `analyze_slice`.
#[derive(Debug)]
pub enum Cause {
    /// Kernel bugcheck (BSOD). `params` are BugcheckParameter1–4 from Event 41.
    BlueScreen { stop_code: u64, stop_name: &'static str, params: [u64; 4] },
    /// Power button held — Event 41 present with non-zero `PowerButtonTimestamp`.
    ForcedPowerOff,
    /// Event 41 with no stop code, or Event 6008 without Event 41.
    UnexpectedShutdown,
    /// Event 1074 from TiWorker / TrustedInstaller, or reason code 0x80020002.
    WindowsUpdate  { process: String },
    /// Event 1074 from an interactive user account.
    UserAction     { user: String, action: String, comment: String },
    /// Event 1074 from NT AUTHORITY\SYSTEM or similar.
    SystemProcess  { process: String, reason: String, action: String },
    /// Event 13 or 6006 found, no crash indicators.
    NormalShutdown,
    /// No conclusive events found in the log window.
    Undetermined,
}

/// One boot session, from Event 12 to the next Event 12 (or end of log).
/// `shutdown_time` is `None` for crashes — only the recovery boot timestamp is
/// known, not the moment of the crash itself.
/// `wer_module` and `minidumps` are filled by the annotation pass after
/// initial classification.
pub struct BootCycle {
    pub index:          usize,
    pub boot_time:      Option<Timestamp>,
    pub shutdown_time:  Option<Timestamp>,
    pub cause:          Cause,
    pub confidence:     u8,
    pub evidence:       Vec<String>,
    pub timeline:       Vec<(Timestamp, String)>,
    pub wer_module:     Option<String>,
    pub minidumps:      Vec<(Timestamp, PathBuf)>,
    pub display_events: Vec<EventRecord>,
}
