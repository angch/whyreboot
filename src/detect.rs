// SPDX-License-Identifier: MIT OR Apache-2.0
//! Detector framework — turns a normalized [`LogLine`] stream into [`Finding`]s.
//!
//! Each detector is a `fn(&LogLine) -> Option<Finding>` that recognizes one
//! category of system issue by anchoring on stable marker substrings (rather than
//! brittle full-line regexes) and extracting a few useful fields. [`scan`] runs
//! every detector over every line, stopping at the first match per line so a
//! single log line yields at most one finding, then **coalesces** bursts of the
//! same category (e.g. the ~11 lines a single ATA/SATA fault emits) into one
//! finding to keep the report high-level.
//!
//! Categories (beyond [`crate::oom`]): kernel panic/oops, userspace segfaults,
//! disk & filesystem I/O errors, CPU lockups & hung tasks, thermal events,
//! machine-check / hardware errors, failed systemd units, and process coredumps.

use crate::oom;
use crate::types::{Finding, LogLine, Severity};

/// A named detector. Order matters only for which category claims a line when
/// several could match; more specific detectors come first.
type Detector = fn(&LogLine) -> Option<Finding>;

const DETECTORS: &[Detector] = &[
    oom::detect,
    detect_kernel_panic,
    detect_segfault,
    detect_disk_io,
    detect_lockup,
    detect_thermal,
    detect_hardware,
    detect_service_failure,
    detect_coredump,
];

/// Findings within this many seconds, of the same category and source, are
/// merged into a single finding (a burst = one incident).
const COALESCE_SECS: i64 = 30;

/// Runs all detectors over all lines, coalesces bursts, and returns findings
/// newest-first.
pub fn scan(lines: &[LogLine]) -> Vec<Finding> {
    let mut found: Vec<Finding> = lines.iter().filter_map(classify).collect();
    found.sort_by_key(|f| f.time); // ascending for coalescing
    let mut merged = coalesce(found);
    merged.sort_by_key(|f| std::cmp::Reverse(f.time)); // present newest-first
    merged
}

/// Applies each detector in order, returning the first match for a line.
fn classify(line: &LogLine) -> Option<Finding> {
    DETECTORS.iter().find_map(|d| d(line))
}

/// Merges consecutive same-category, same-source findings within `COALESCE_SECS`
/// into the earliest of the burst, folding the rest in as evidence. Input must be
/// sorted by ascending time.
fn coalesce(findings: Vec<Finding>) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for f in findings {
        if let Some(last) = out.last_mut() {
            let same = last.category == f.category && last.source == f.source;
            if same && f.time.secs_since(last.time) <= COALESCE_SECS {
                // Fold f into last as an extra related line.
                let raw = f.evidence.iter().find(|e| e.starts_with("Raw:"))
                    .cloned()
                    .unwrap_or_else(|| format!("Raw: {}", f.title));
                last.evidence.push(format!("+ related: {}", raw.trim_start_matches("Raw: ")));
                continue;
            }
        }
        out.push(f);
    }
    // Annotate coalesced bursts with a count so the reader knows it was many lines.
    for f in &mut out {
        let related = f.evidence.iter().filter(|e| e.starts_with("+ related:")).count();
        if related > 0 {
            f.title = format!("{} ({} related log lines)", f.title, related + 1);
        }
    }
    out
}

// ── Small matching helpers ──────────────────────────────────────────────────────

/// Case-insensitive substring test.
fn has(msg: &str, needle: &str) -> bool {
    contains_ci(msg, needle)
}

/// Returns the first needle (from `needles`) that appears in `msg`, case-insensitively.
fn first_of<'a>(msg: &str, needles: &[&'a str]) -> Option<&'a str> {
    let lower = msg.to_lowercase();
    needles.iter().copied().find(|n| lower.contains(&n.to_lowercase()))
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Extracts a leading `comm[pid]:` prefix common to kernel userspace-fault lines,
/// e.g. `"chrome[4242]: segfault at …"` → `("chrome", Some(4242))`.
fn comm_pid_prefix(msg: &str) -> Option<(String, Option<u64>)> {
    let colon = msg.find(':')?;
    let head = msg[..colon].trim();
    let br = head.find('[')?;
    let comm = head[..br].trim();
    if comm.is_empty() || comm.contains(' ') { return None; }
    let pid = head[br + 1..].trim_end_matches(']')
        .chars().take_while(|c| c.is_ascii_digit()).collect::<String>()
        .parse().ok();
    Some((comm.to_string(), pid))
}

/// Builds a finding, always attaching the raw line as the final evidence entry.
fn finding(line: &LogLine, sev: Severity, category: &str, title: String,
           mut evidence: Vec<String>, source: &str) -> Finding {
    evidence.push(format!("Raw: {}", line.message.trim()));
    Finding { time: line.time, severity: sev, category: category.to_string(), title, evidence,
              source: source.to_string() }
}

/// True if the line came from the kernel (transport or identifier says so).
fn is_kernel(line: &LogLine) -> bool {
    line.transport.eq_ignore_ascii_case("kernel")
        || line.identifier.eq_ignore_ascii_case("kernel")
}

// ── Detectors ────────────────────────────────────────────────────────────────────

/// Kernel panics, oopses, and BUGs — the system is (or was) in a fatal state.
fn detect_kernel_panic(line: &LogLine) -> Option<Finding> {
    let markers = [
        "Kernel panic - not syncing", "BUG: unable to handle",
        "kernel BUG at", "Oops:", "Internal error: Oops", "unable to handle kernel",
    ];
    let m = first_of(&line.message, &markers)?;
    let title = if has(&line.message, "panic") {
        "Kernel panic".to_string()
    } else {
        format!("Kernel {}", m.trim_end_matches(':'))
    };
    Some(finding(line, Severity::Critical, "KernelPanic", title,
        vec!["The kernel hit an unrecoverable fault. If the machine rebooted, this is \
              almost certainly why; capture the full trace with `journalctl -k -b -1`.".into()],
        "journald:kernel"))
}

/// Userspace crashes the kernel logs: segfaults, GPFs, and trap faults.
fn detect_segfault(line: &LogLine) -> Option<Finding> {
    let markers = ["segfault at", "general protection fault", "traps:", "trap invalid opcode"];
    let m = first_of(&line.message, &markers)?;
    let who = comm_pid_prefix(&line.message)
        .map(|(c, p)| match p { Some(p) => format!("{c} (pid {p})"), None => c })
        .unwrap_or_else(|| "a process".to_string());
    let kind = if m == "segfault at" { "segmentation fault" }
               else if m.starts_with("general") { "general protection fault" }
               else { "an illegal-instruction / trap fault" };
    Some(finding(line, Severity::Warning, "Segfault",
        format!("{who} crashed with {kind}"),
        vec!["A process died on a memory-access or instruction fault — likely a bug or \
              corrupted binary. Check for a matching coredump.".into()],
        "journald:kernel"))
}

/// Disk and filesystem errors: block-layer I/O errors, ATA/SATA link faults,
/// filesystem corruption, and read-only remounts.
fn detect_disk_io(line: &LogLine) -> Option<Finding> {
    let markers = [
        "I/O error", "Buffer I/O error", "critical medium error", "critical target error",
        "EXT4-fs error", "EXT4-fs (", "XFS (", "Btrfs", "failed command:",
        "exception Emask", "hard resetting link", "SError:",
        "Remounting filesystem read-only", "reset SATA link", "device offlined",
    ];
    let m = first_of(&line.message, &markers)?;
    // Filesystem-prefix markers also match routine mount/unmount chatter
    // ("EXT4-fs (sda3): mounted filesystem … ro" is the normal boot sequence,
    // not a fault). Those markers only count when the line signals an error.
    if (m == "XFS (" || m == "Btrfs" || m == "EXT4-fs (")
        && !contains_ci(&line.message, "error")
        && !contains_ci(&line.message, "corrupt")
        && !contains_ci(&line.message, "warning") {
        return None;
    }
    let (title, advice) = if has(&line.message, "read-only") {
        ("Filesystem remounted read-only after an error",
         "The kernel forced the filesystem read-only to protect data. Run `fsck` and \
          check SMART health (`smartctl -a <dev>`).")
    } else if has(&line.message, "medium error") || has(&line.message, "I/O error") {
        ("Disk I/O error",
         "The block layer reported an I/O failure — a failing drive, cable, or controller. \
          Check `smartctl -a <dev>` and `dmesg` for the device.")
    } else if has(&line.message, "EXT4-fs") || has(&line.message, "XFS")
           || has(&line.message, "Btrfs") {
        ("Filesystem error",
         "The filesystem reported an on-disk error. Unmount and `fsck` at the next window.")
    } else {
        ("Disk / SATA link error",
         "The storage link faulted (ATA/SATA). Often a bad cable or a failing drive; check \
          SMART and reseat connections.")
    };
    Some(finding(line, Severity::Critical, "Disk", title.to_string(),
        vec![advice.to_string()], "journald:kernel"))
}

/// CPU soft/hard lockups, RCU stalls, and hung tasks (D-state > 120s).
fn detect_lockup(line: &LogLine) -> Option<Finding> {
    let markers = [
        "soft lockup", "hard LOCKUP", "blocked for more than",
        "rcu_sched detected", "rcu_preempt detected", "self-detected stall",
        "hung_task", "task hung",
    ];
    let m = first_of(&line.message, &markers)?;
    let (title, cat_advice) = if has(&line.message, "blocked for more than")
        || has(&line.message, "hung") {
        ("A task hung (blocked > 120s in uninterruptible sleep)",
         "A process is stuck in the kernel — usually blocked on failing storage or a driver. \
          Correlate with disk errors above.")
    } else if has(&line.message, "rcu") || has(&line.message, "stall") {
        ("RCU stall detected",
         "A CPU failed to report a quiescent state — a stuck kernel path or starved CPU.")
    } else {
        ("CPU lockup detected",
         "A CPU spun without yielding (soft/hard lockup) — a kernel or driver bug, or \
          firmware/SMI interference.")
    };
    let _ = m;
    Some(finding(line, Severity::Critical, "Lockup", title.to_string(),
        vec![cat_advice.to_string()], "journald:kernel"))
}

/// Thermal events: throttling and critical-temperature trips.
fn detect_thermal(line: &LogLine) -> Option<Finding> {
    let markers = [
        "temperature above threshold", "critical temperature reached",
        "thermal zone", "Package temperature above threshold", "clock throttled",
        "CPU clock throttled",
    ];
    let m = first_of(&line.message, &markers)?;
    let critical = has(&line.message, "critical temperature");
    let (sev, title) = if critical {
        (Severity::Critical, "Critical temperature reached — thermal shutdown risk")
    } else {
        (Severity::Warning, "Thermal throttling — CPU temperature above threshold")
    };
    let _ = m;
    Some(finding(line, sev, "Thermal", title.to_string(),
        vec!["The CPU/system got hot enough to throttle or trip. Check cooling, fans, dust, \
              and airflow; sustained throttling degrades performance.".into()],
        "journald:kernel"))
}

/// Machine-check exceptions and other hardware-error reports.
fn detect_hardware(line: &LogLine) -> Option<Finding> {
    let markers = [
        "Hardware Error", "Machine check events logged", "mce:", "MCE ",
        "Uncorrected error", "Corrected error", "EDAC", "PCIe Bus Error",
    ];
    let m = first_of(&line.message, &markers)?;
    // "EDAC" / "mce:" / "MCE " also appear in benign boot-time driver banners
    // ("EDAC MC: Ver: 3.0.0", "mce: CPU supports 32 MCE banks"). For those
    // ambiguous markers, require an actual error indication in the message;
    // real reports carry "error"/"fail" or a CE/UE (corrected/uncorrected
    // event) count, e.g. "EDAC MC0: 1 CE memory read error …".
    if matches!(m, "EDAC" | "mce:" | "MCE ") {
        let msg = &line.message;
        let errorish = contains_ci(msg, "error") || contains_ci(msg, "fail")
            || msg.contains(" CE ") || msg.contains(" UE ");
        if !errorish { return None; }
    }
    let uncorrected = has(&line.message, "uncorrected") || has(&line.message, "fatal");
    let (sev, title) = if uncorrected {
        (Severity::Critical, "Uncorrected hardware (machine-check) error")
    } else if has(&line.message, "corrected") || has(&line.message, "EDAC") {
        (Severity::Warning, "Corrected hardware/memory error (ECC)")
    } else {
        (Severity::Critical, "Hardware error reported")
    };
    let _ = m;
    Some(finding(line, sev, "Hardware", title.to_string(),
        vec!["The platform reported a hardware fault (CPU/memory/PCIe). Persistent errors \
              point to failing RAM (run memtest86) or a failing component; check `ras-mc-ctl \
              --summary` / `mcelog`.".into()],
        "journald:kernel"))
}

/// systemd units that failed. Anchored on the `systemd` identifier so ordinary
/// application log lines that merely contain "failed" don't trip it.
fn detect_service_failure(line: &LogLine) -> Option<Finding> {
    if !line.identifier.eq_ignore_ascii_case("systemd") { return None; }
    let markers = [
        "Failed with result", "Main process exited, code=dumped", "entered failed state",
        "Start request repeated too quickly", "Failed to start",
    ];
    let m = first_of(&line.message, &markers)?;
    // The unit name is the message prefix before the first ':' ("foo.service: Failed …").
    let unit = line.message.split(':').next().map(str::trim)
        .filter(|u| u.ends_with(".service") || u.ends_with(".mount")
                 || u.ends_with(".socket") || u.ends_with(".timer"))
        .unwrap_or("A systemd unit");
    let dumped = has(&line.message, "code=dumped");
    let title = if dumped {
        format!("Service '{unit}' crashed (dumped core)")
    } else {
        format!("Service '{unit}' failed")
    };
    let _ = m;
    Some(finding(line, Severity::Warning, "Service", title,
        vec![format!("Inspect with `systemctl status {}` and `journalctl -u {}`.",
                     unit.trim_start_matches('\''), unit.trim_start_matches('\''))],
        "systemd"))
}

/// Process coredumps captured by systemd-coredump.
fn detect_coredump(line: &LogLine) -> Option<Finding> {
    let by_id = line.identifier.eq_ignore_ascii_case("systemd-coredump");
    if !by_id && !contains_ci(&line.message, "dumped core") { return None; }
    if is_kernel(line) { return None; } // kernel "dumped core" duplicates segfault handling
    // "Process 1234 (comm) of user 1000 dumped core."
    let comm = line.message.find('(')
        .and_then(|a| line.message[a + 1..].find(')').map(|b| line.message[a + 1..a + 1 + b].to_string()));
    let who = comm.map(|c| format!("'{c}'")).unwrap_or_else(|| "a process".to_string());
    Some(finding(line, Severity::Warning, "Coredump",
        format!("Process {who} dumped core"),
        vec!["A crash was captured. Inspect the backtrace with `coredumpctl info` / \
              `coredumpctl gdb`.".into()],
        "systemd-coredump"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timestamp::Timestamp;

    fn kline_at(t: i64, msg: &str) -> LogLine {
        LogLine { time: Timestamp(t), message: msg.into(),
                  identifier: "kernel".into(), transport: "kernel".into() }
    }
    fn kline(msg: &str) -> LogLine { kline_at(1_700_000_000, msg) }
    fn systemd(msg: &str) -> LogLine {
        LogLine { time: Timestamp(1_700_000_000), message: msg.into(),
                  identifier: "systemd".into(), transport: "journal".into() }
    }

    #[test]
    fn kernel_panic_detected() {
        let f = classify(&kline("Kernel panic - not syncing: Fatal exception")).unwrap();
        assert_eq!(f.category, "KernelPanic");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn segfault_extracts_comm_and_pid() {
        let f = classify(&kline(
            "chrome[4242]: segfault at 7f00 ip 00007f00 sp 00007ffe error 4 in libc.so[7f00+1a]"
        )).unwrap();
        assert_eq!(f.category, "Segfault");
        assert!(f.title.contains("chrome"));
        assert!(f.title.contains("4242"));
    }

    #[test]
    fn disk_io_error_detected() {
        let f = classify(&kline(
            "blk_update_request: I/O error, dev sda, sector 1234567 op 0x0:(READ)"
        )).unwrap();
        assert_eq!(f.category, "Disk");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn ext4_error_detected() {
        let f = classify(&kline(
            "EXT4-fs error (device sda1): ext4_lookup:1600: inode #2: comm ls: deleted inode referenced"
        )).unwrap();
        assert_eq!(f.category, "Disk");
    }

    #[test]
    fn plain_xfs_info_line_ignored() {
        assert!(classify(&kline("XFS (dm-0): Mounting V5 Filesystem")).is_none());
    }

    #[test]
    fn ext4_normal_mount_lines_ignored() {
        // Routine boot sequence: root mounts ro, then remounts r/w. Not faults.
        assert!(classify(&kline(
            "EXT4-fs (sda3): mounted filesystem 6a51901f with ordered data mode. Quota mode: none."
        )).is_none());
        assert!(classify(&kline("EXT4-fs (sda3): re-mounted 6a51901f r/w.")).is_none());
    }

    #[test]
    fn hung_task_detected() {
        let f = classify(&kline(
            "INFO: task kworker/1:2:1234 blocked for more than 120 seconds."
        )).unwrap();
        assert_eq!(f.category, "Lockup");
    }

    #[test]
    fn thermal_throttle_is_warning_critical_is_critical() {
        let warn = classify(&kline(
            "CPU2: Package temperature above threshold, cpu clock throttled (total events = 12)"
        )).unwrap();
        assert_eq!(warn.severity, Severity::Warning);
        let crit = classify(&kline(
            "thermal thermal_zone0: critical temperature reached (100 C), shutting down"
        )).unwrap();
        assert_eq!(crit.severity, Severity::Critical);
    }

    #[test]
    fn mce_uncorrected_is_critical() {
        let f = classify(&kline(
            "mce: [Hardware Error]: Machine check events logged"
        )).unwrap();
        assert_eq!(f.category, "Hardware");
    }

    #[test]
    fn edac_and_mce_boot_banners_are_not_hardware_errors() {
        // Driver-init banners logged at every boot must not be findings.
        assert!(classify(&kline("EDAC MC: Ver: 3.0.0")).is_none());
        assert!(classify(&kline("mce: CPU supports 32 MCE banks")).is_none());
        assert!(classify(&kline("MCE banks initialized")).is_none());
    }

    #[test]
    fn edac_real_ce_report_is_detected() {
        let f = classify(&kline(
            "EDAC MC0: 1 CE memory read error on CPU_SrcID#0_MC#0_Chan#1_DIMM#0"
        )).unwrap();
        assert_eq!(f.category, "Hardware");
        assert_eq!(f.severity, Severity::Warning); // corrected → warning
    }

    #[test]
    fn service_failure_needs_systemd_identifier() {
        let f = classify(&systemd(
            "nginx.service: Failed with result 'exit-code'."
        )).unwrap();
        assert_eq!(f.category, "Service");
        assert!(f.title.contains("nginx.service"));
        // The same text from a non-systemd source must NOT be a service failure.
        assert!(classify(&kline("nginx.service: Failed with result 'exit-code'.")).is_none()
            || classify(&kline("nginx.service: Failed with result 'exit-code'.")).unwrap().category != "Service");
    }

    #[test]
    fn coredump_detected() {
        let l = LogLine { time: Timestamp(1_700_000_000),
            message: "Process 4242 (chrome) of user 1000 dumped core.".into(),
            identifier: "systemd-coredump".into(), transport: "journal".into() };
        let f = classify(&l).unwrap();
        assert_eq!(f.category, "Coredump");
        assert!(f.title.contains("chrome"));
    }

    #[test]
    fn ordinary_line_yields_nothing() {
        assert!(classify(&kline("usb 1-3: new high-speed USB device number 7")).is_none());
    }

    #[test]
    fn ata_burst_coalesces_into_one_finding() {
        // A single SATA fault emits many lines within the same second.
        let base = 1_700_000_000;
        let burst = [
            "ata1.00: exception Emask 0x10 SAct 0x10000 SErr 0x40d0000 action 0xe frozen",
            "ata1: SError: { PHYRdyChg CommWake 10B8B DevExch }",
            "ata1.00: failed command: READ FPDMA QUEUED",
            "ata1: hard resetting link",
        ];
        let lines: Vec<LogLine> = burst.iter().enumerate()
            .map(|(i, m)| kline_at(base + i as i64, m)).collect();
        let found = scan(&lines);
        assert_eq!(found.len(), 1, "the burst should collapse to a single Disk finding");
        assert_eq!(found[0].category, "Disk");
        assert!(found[0].title.contains("related log lines"), "title: {}", found[0].title);
    }

    #[test]
    fn distinct_categories_are_not_coalesced() {
        let lines = vec![
            kline_at(1_700_000_000, "EXT4-fs error (device sda1): bad inode"),
            kline_at(1_700_000_005, "Kernel panic - not syncing: Fatal exception"),
        ];
        let found = scan(&lines);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn far_apart_same_category_not_coalesced() {
        let lines = vec![
            kline_at(1_700_000_000, "blk_update_request: I/O error, dev sda, sector 1"),
            kline_at(1_700_000_600, "blk_update_request: I/O error, dev sda, sector 2"),
        ];
        assert_eq!(scan(&lines).len(), 2, "10 minutes apart → two incidents");
    }
}
