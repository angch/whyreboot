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
    /// Event 1074 from TiWorker / TrustedInstaller / the Update Orchestrator, or
    /// reason code 0x80020002. `old_version`/`new_version` are "major.minor.build"
    /// strings read from the Event 6009 banner logged just after each boot
    /// (before and after this restart, respectively) — `None` if not found in
    /// the scanned log window.
    WindowsUpdate  { process: String, old_version: Option<String>, new_version: Option<String> },
    /// Event 1074 from an interactive user account.
    UserAction     { user: String, action: String, comment: String },
    /// Event 1074 from NT AUTHORITY\SYSTEM or similar.
    SystemProcess  { process: String, reason: String, action: String },
    /// Event 13 or 6006 found, no crash indicators.
    NormalShutdown,
    /// No conclusive events found in the log window.
    Undetermined,
}

// ── Generic, platform-agnostic findings ─────────────────────────────────────────

/// A normalized log record, independent of the source (journald, dmesg, file, …).
/// Detectors in [`crate::detect`] consume these and emit [`Finding`]s.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub time:       Timestamp,
    pub message:    String,
    /// syslog identifier, e.g. `"kernel"` or `"systemd-oomd"` (may be empty).
    pub identifier: String,
    /// journald `_TRANSPORT`, e.g. `"kernel"` (may be empty).
    pub transport:  String,
}

/// Severity of a detected issue. Ordered least-to-most severe so `Ord` can rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    /// Short uppercase label for text output.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info     => "INFO",
            Severity::Warning  => "WARNING",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// A single detected system issue, independent of platform or log source.
///
/// This is the generic replacement for the Windows-specific [`BootCycle`] model:
/// analyzers (OOM, and future detectors) scan a normalized log stream over a
/// [`crate::timewindow::TimeWindow`] and emit one `Finding` per issue. Unlike a
/// boot cycle, a finding need not correspond to a reboot.
#[derive(Debug, Clone)]
pub struct Finding {
    /// When the issue occurred.
    pub time:     Timestamp,
    pub severity: Severity,
    /// Coarse category slug, e.g. `"OOM"`.
    pub category: String,
    /// One-line human-readable headline.
    pub title:    String,
    /// Supporting detail bullets (raw log excerpts, extracted fields, advice).
    pub evidence: Vec<String>,
    /// Where it came from, e.g. `"journald:kernel"` or `"systemd-oomd"`.
    pub source:   String,
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
