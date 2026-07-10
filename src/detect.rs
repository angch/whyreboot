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
//! machine-check / hardware errors, failed systemd units, process coredumps,
//! GPU hangs/resets (amdgpu, i915, nouveau, NVIDIA NVRM), and display-session
//! failures (Wayland compositor loss, X server crashes).
//!
//! After coalescing, [`scan`] runs a **correlation pass**: a GPU incident is
//! cross-annotated with the segfaults/coredumps/session failures that follow it,
//! and a compositor crash is cross-annotated with the client apps that lost
//! their connection — so cascades read as one story, not scattered findings.
//!
//! # Provenance of marker strings
//!
//! Every detector below carries a `Provenance:` note with one of three levels,
//! so readers know how battle-tested each pattern is:
//!
//! - **verified-live** — matched real events in a live journal on a real
//!   machine during development (strongest).
//! - **third-party logs** — marker strings copied verbatim from real captured
//!   logs in public incident reports (bug trackers, forums); realistic, but
//!   never reproduced against a live incident by us.
//! - **canonical format** — taken from kernel/systemd source or documentation;
//!   the format is authoritative but the detector has only ever seen
//!   fixture data, not a live incident.
//!
//! Anything not verified-live should be treated as **untested in the wild**:
//! wording drift across kernel versions may cause misses (never crashes — a
//! miss just means no finding). Negative baselines (benign boot banners) ARE
//! verified-live on this project's dev machines.

use crate::oom;
use crate::types::{Finding, LogLine, Severity};

/// A named detector. Order matters only for which category claims a line when
/// several could match; more specific detectors come first.
type Detector = fn(&LogLine) -> Option<Finding>;

const DETECTORS: &[Detector] = &[
    oom::detect,
    detect_kernel_panic,
    detect_gpu,
    detect_segfault,
    detect_disk_io,
    detect_lockup,
    detect_thermal,
    detect_hardware,
    detect_service_failure,
    detect_coredump,
    detect_session,
];

/// Findings within this many seconds, of the same category and source, are
/// merged into a single finding (a burst = one incident).
const COALESCE_SECS: i64 = 30;

/// Findings within this many seconds of a GPU incident or compositor crash are
/// considered part of the same cascade and cross-annotated.
const CORRELATE_SECS: i64 = 120;

/// Runs all detectors over all lines, coalesces bursts, correlates cascades,
/// and returns findings newest-first.
pub fn scan(lines: &[LogLine]) -> Vec<Finding> {
    let mut found: Vec<Finding> = lines.iter().filter_map(classify).collect();
    found.sort_by_key(|f| f.time); // ascending for coalescing
    let mut merged = coalesce(found);
    correlate(&mut merged);
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

/// Compositor / display-server process names whose crash takes down every
/// graphical client attached to them.
const COMPOSITORS: &[&str] = &[
    "gnome-shell", "kwin_wayland", "kwin_x11", "mutter", "plasmashell",
    "Xorg", "Xwayland", "weston", "sway", "hyprland", "labwc",
];

/// Cross-annotates cascade relationships between findings (any order in the
/// slice; time proximity decides):
///
/// 1. **GPU incident → casualties.** Segfaults, coredumps, session failures,
///    lockups, and service failures within [`CORRELATE_SECS`] of a GPU finding
///    are marked as likely consequences, and the GPU finding lists them.
/// 2. **Compositor crash → orphaned clients.** A segfault/coredump whose title
///    names a compositor is linked with `Session` connection-loss findings in
///    the same window.
fn correlate(findings: &mut [Finding]) {
    let n = findings.len();
    // (target index, note to append) — collected first, applied after, so we
    // never annotate based on already-annotated state.
    let mut notes: Vec<(usize, String)> = Vec::new();

    let near = |a: &Finding, b: &Finding| a.time.secs_since(b.time).abs() <= CORRELATE_SECS;
    let is_crash_of_compositor = |f: &Finding| {
        matches!(f.category.as_str(), "Segfault" | "Coredump")
            && COMPOSITORS.iter().any(|c| f.title.contains(c))
    };

    for i in 0..n {
        match findings[i].category.as_str() {
            "GPU" => {
                for j in 0..n {
                    if i == j || !near(&findings[i], &findings[j]) { continue; }
                    if matches!(findings[j].category.as_str(),
                        "Segfault" | "Coredump" | "Session" | "Service" | "Lockup")
                    {
                        notes.push((i, format!(
                            "Correlated: {} at {} — likely a casualty of this GPU incident.",
                            findings[j].title, findings[j].time.format_t())));
                        notes.push((j, format!(
                            "Correlated: GPU incident at {} ({}) — this failure likely \
                             follows the GPU hang/reset.",
                            findings[i].time.format_t(), findings[i].title)));
                    }
                }
            }
            "Session" => {
                for j in 0..n {
                    if i == j || !near(&findings[i], &findings[j]) { continue; }
                    if is_crash_of_compositor(&findings[j]) {
                        notes.push((i, format!(
                            "Correlated: {} at {} — the compositor/display server died, \
                             which explains the lost connection.",
                            findings[j].title, findings[j].time.format_t())));
                        notes.push((j, format!(
                            "Correlated: {} at {} — graphical clients lost their \
                             compositor connection when this process crashed.",
                            findings[i].title, findings[i].time.format_t())));
                    }
                }
            }
            _ => {}
        }
    }

    notes.sort_by_key(|(idx, _)| *idx);
    notes.dedup();
    for (idx, note) in notes {
        findings[idx].evidence.push(note);
    }
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
///
/// Provenance: **canonical format** (kernel `panic()` / oops wording) — fixture
/// tested only; no live panic reproduced during development.
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

/// GPU hangs, resets, and fatal driver errors (amdgpu, i915, nouveau, NVIDIA).
/// Kernel-only. Marker strings verified against real reports:
/// - amdgpu: `*ERROR* ring gfx_0.0.0 timeout`, `GPU reset begin!`,
///   `GPU reset succeeded`, `VRAM is lost due to GPU reset!`, `soft recovered`
/// - i915:   `GPU HANG: ecode …, in app [pid]`, `Resetting … for stopped heartbeat`
/// - NVIDIA: `NVRM: Xid (PCI:…): 79, GPU has fallen off the bus`
/// - generic DRM: `[drm:…] *ERROR* … flip_done timed out`
/// - Strix Halo–era amdgpu MES/queue resets (verified against a real gfx1151
///   incident report): `Starting gfx_0.0.0 ring reset`, `Ring gfx_0.0.0 reset
///   failed`, `MES failed to respond to msg=RESET`, `failed to reset legacy
///   queue`, `*ERROR* failed to halt cp gfx`, `[drm] device wedged`, and the
///   culprit line `Process <comm> pid <n> thread <comm:cs0> pid <n>`
///
/// Benign init banners (`[drm] Initialized …`, `fbcon: …`) must not match —
/// every marker here encodes an error, not a subsystem name.
///
/// Provenance: **third-party logs / UNTESTED LIVE** — every marker is copied
/// verbatim from public incident reports (Ubuntu/Arch bug trackers, NVIDIA
/// forums, a Framework Strix Halo gfx1151 thread), but no GPU hang has been
/// reproduced against this detector on live hardware. The benign-banner
/// negative baseline IS verified-live (this dev VM's journal).
fn detect_gpu(line: &LogLine) -> Option<Finding> {
    if !is_kernel(line) { return None; }
    let msg = &line.message;
    let markers = [
        "GPU HANG", "GPU hang", "GPU reset", "gpu reset",
        "stopped heartbeat", "NVRM: Xid", "fallen off the bus",
        "VRAM is lost", "ring gfx", "ring sdma", "ring comp",
        "flip_done timed out", "GPU recovery", "amdgpu_job_timedout",
        "GPU lockup", "failed to initialize the GPU",
        "ring reset", "MES failed", "failed to halt cp",
        "legacy queue", "device wedged", "IB test failed",
        "*ERROR*",
    ];
    let m = match first_of(msg, &markers) {
        Some(m) => m,
        None => {
            // amdgpu's culprit line carries no error word of its own:
            // "Process slack pid 17365 thread slack:cs0 pid 17389"
            let t = msg.trim();
            if t.starts_with("Process ") && t.contains(" pid ") && t.contains(" thread ") {
                "Process"
            } else {
                return None;
            }
        }
    };
    // "ring …" markers also appear in benign topology prints; require a fault word.
    if m.starts_with("ring")
        && !(contains_ci(msg, "timeout") || contains_ci(msg, "timed out")
             || contains_ci(msg, "error") || contains_ci(msg, "hang")
             || contains_ci(msg, "fail") || contains_ci(msg, "reset")) {
        return None;
    }
    // "legacy queue" only signals a fault when the operation on it failed.
    if m == "legacy queue" && !contains_ci(msg, "fail") { return None; }

    let driver = ["amdgpu", "i915", "nouveau", "radeon"].iter()
        .find(|d| contains_ci(msg, d)).copied()
        .or_else(|| msg.contains("NVRM").then_some("nvidia"))
        .unwrap_or("drm");

    // "*ERROR*" is drm-style logging, but only attribute it to the GPU when the
    // line carries GPU context — otherwise unrelated subsystems using the same
    // convention would land here.
    if m == "*ERROR*" && !msg.contains("[drm") && driver == "drm" { return None; }

    // Culprit extraction. i915 inlines it ("GPU HANG: ecode …, in kwin_wayland
    // [1155]"); amdgpu logs a separate "Process slack pid 17365 thread slack:cs0
    // pid 17389" line right after the ring timeout (it coalesces into the burst).
    let culprit = msg.find(", in ").map(|p| {
        let rest = &msg[p + 5..];
        rest[..rest.find('[').unwrap_or(rest.len())].trim().to_string()
    }).or_else(|| {
        msg.trim().strip_prefix("Process ").and_then(|rest| {
            rest.contains(" pid ").then(|| {
                rest[..rest.find(" pid ").unwrap()].trim().to_string()
            })
        })
    }).filter(|c| !c.is_empty());

    let soft = contains_ci(msg, "soft recovered") || contains_ci(msg, "flip_done")
        || is_app_level_xid(msg);
    let (sev, what) = if contains_ci(msg, "fallen off the bus") {
        (Severity::Critical, "GPU has fallen off the bus (device unreachable)".to_string())
    } else if soft {
        (Severity::Warning, format!("GPU fault ({driver}) — recovered/soft"))
    } else {
        (Severity::Critical, format!("GPU hang / reset ({driver})"))
    };

    let mut evidence = Vec::new();
    if let Some(c) = &culprit {
        evidence.push(format!("Workload at fault (per driver): {c}"));
    }
    evidence.push(match sev {
        Severity::Critical =>
            "The GPU stopped responding and the driver attempted a reset — the session \
             may freeze or crash. Update GPU drivers/firmware (and BIOS); if recurring, \
             check thermals and power delivery, and test with another kernel."
                .to_string(),
        _ =>
            "The GPU driver recovered from a fault without a full reset. Occasional \
             events can be an app bug; frequent ones point to a driver regression."
                .to_string(),
    });
    Some(finding(line, sev, "GPU", what, evidence, "journald:kernel"))
}

/// NVIDIA Xid codes that indicate an application-level fault (kernel/driver and
/// GPU stay healthy): 13 graphics exception, 31 MMU fault, 43 app error, 45 preempt.
fn is_app_level_xid(msg: &str) -> bool {
    let Some(p) = msg.find("NVRM: Xid") else { return false };
    // "NVRM: Xid (PCI:0000:01:00): 79, GPU has fallen off the bus"
    let rest = &msg[p..];
    let after_paren = rest.find("):").map(|i| &rest[i + 2..]).unwrap_or(rest);
    let code: String = after_paren.trim_start().chars()
        .take_while(|c| c.is_ascii_digit()).collect();
    matches!(code.as_str(), "13" | "31" | "43" | "45")
}

/// Userspace crashes the kernel logs: segfaults, GPFs, and trap faults.
///
/// Provenance: **canonical format** (kernel `show_signal_msg()` wording is
/// stable across many kernel versions) — fixture tested; no live segfault
/// event observed during development.
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
///
/// Provenance: mixed. The ATA/SATA burst markers are **third-party logs**
/// (verbatim from a real captured SATA fault); block/filesystem error markers
/// are **canonical format**. The EXT4 benign-mount negative baseline is
/// **verified-live** (this dev VM's boot sequence). No live disk fault
/// reproduced during development.
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
///
/// Provenance: **canonical format** (watchdog/hung_task/RCU wording from kernel
/// source) — fixture tested only; untested against a live lockup.
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
///
/// Provenance: **canonical format** (intel thermal / thermal_zone wording) —
/// fixture tested only; untested against a live thermal event.
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
///
/// Provenance: **canonical format** (mce/EDAC/AER wording) — fixture tested;
/// the EDAC boot-banner negative baseline is **verified-live** (this dev VM).
/// No live hardware error reproduced during development.
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
///
/// Provenance: **verified-live** — matched real `Failed with result
/// 'exit-code'` events (iperf3, openipmi, snap units) in this dev machine's
/// journal during development.
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
///
/// Provenance: **canonical format** (systemd-coredump's fixed message) —
/// fixture tested only; no live coredump observed during development.
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

/// Display-session failures: Wayland clients losing their compositor, GNOME
/// session components dying, and X server fatal errors. Message shapes verified
/// against real reports:
/// - clients: `Lost connection to Wayland compositor.`,
///   `The Wayland connection broke. Did the compositor die?`,
///   `Error 71 (Protocol error) dispatching to Wayland display.`
/// - gnome-session-binary: `Unrecoverable failure in required component X.desktop`
/// - Xorg: `(EE) Segmentation fault at address …`, `(EE) Fatal server error:`,
///   `(EE) Server terminated with error (1)`
///
/// Provenance: **third-party logs / UNTESTED LIVE** — all marker strings are
/// verbatim from public reports (GNOME/mutter GitLab, Mozilla bugzilla, Arch
/// forums, KDE bugs); this dev VM has no graphical session, so none have been
/// reproduced live.
fn detect_session(line: &LogLine) -> Option<Finding> {
    if is_kernel(line) { return None; }
    let msg = &line.message;

    // X server fatal errors — the "(EE)" prefix plus a fatal phrase.
    if msg.contains("(EE)")
        && (msg.contains("Segmentation fault at address")
            || msg.contains("Fatal server error")
            || msg.contains("Server terminated with error")
            || msg.contains("Caught signal"))
    {
        return Some(finding(line, Severity::Critical, "Session",
            "X server (Xorg) crashed".to_string(),
            vec!["The X display server hit a fatal error — the whole graphical session \
                  died with it. Check /var/log/Xorg.0.log.old and the GPU driver; the \
                  (EE) Backtrace lines name the faulting module.".into()],
            "journald:x11"));
    }

    // GNOME session component failure.
    if line.identifier.eq_ignore_ascii_case("gnome-session-binary")
        && contains_ci(msg, "Unrecoverable failure in required component")
    {
        let comp = msg.rsplit(' ').next().unwrap_or("a component").trim_end_matches('.');
        return Some(finding(line, Severity::Warning, "Session",
            format!("GNOME session lost required component {comp}"),
            vec!["A core part of the GNOME session (often the gnome-shell compositor) \
                  failed. Look for a matching coredump/segfault just before this.".into()],
            "gnome-session"));
    }

    // Wayland clients reporting their compositor vanished.
    let lost = ["Lost connection to Wayland compositor",
                "The Wayland connection broke",
                "Error 71 (Protocol error) dispatching to Wayland display",
                "Wayland compositor died"];
    if first_of(msg, &lost).is_some() {
        let who = if line.identifier.is_empty() { "An app".to_string() }
                  else { format!("'{}'", line.identifier) };
        return Some(finding(line, Severity::Warning, "Session",
            format!("{who} lost its Wayland compositor connection"),
            vec!["The Wayland compositor (gnome-shell / kwin_wayland / …) went away — \
                  usually because it crashed, killing every client attached to it. \
                  Check for a compositor coredump/segfault at the same moment.".into()],
            "journald:wayland"));
    }

    None
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

    // ── GPU ───────────────────────────────────────────────────────────────────

    #[test]
    fn amdgpu_ring_timeout_is_critical_gpu() {
        let f = classify(&kline(
            "[drm:amdgpu_job_timedout [amdgpu]] *ERROR* ring gfx_0.0.0 timeout, \
             signaled seq=633, emitted seq=635"
        )).unwrap();
        assert_eq!(f.category, "GPU");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.title.contains("amdgpu"));
    }

    #[test]
    fn amdgpu_reset_and_vram_lost_detected() {
        assert_eq!(classify(&kline("amdgpu 0000:0c:00.0: amdgpu: GPU reset begin!"))
            .unwrap().category, "GPU");
        assert_eq!(classify(&kline("[drm] VRAM is lost due to GPU reset!"))
            .unwrap().category, "GPU");
    }

    #[test]
    fn amdgpu_soft_recovery_is_warning() {
        let f = classify(&kline(
            "[drm] ring gfx_0.0.0 timeout, but soft recovered"
        )).unwrap();
        assert_eq!(f.category, "GPU");
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn i915_gpu_hang_extracts_culprit() {
        let f = classify(&kline(
            "i915 0000:00:02.0: [drm] GPU HANG: ecode 9:1:85dffffa, in kwin_wayland [1155]"
        )).unwrap();
        assert_eq!(f.category, "GPU");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.evidence.iter().any(|e| e.contains("kwin_wayland")), "{:?}", f.evidence);
    }

    #[test]
    fn i915_heartbeat_reset_detected() {
        let f = classify(&kline(
            "i915 0000:00:02.0: [drm] Resetting rcs0 for stopped heartbeat on rcs0"
        )).unwrap();
        assert_eq!(f.category, "GPU");
    }

    #[test]
    fn nvidia_xid_79_fallen_off_bus_is_critical() {
        let f = classify(&kline(
            "NVRM: Xid (PCI:0000:01:00): 79, pid=1234, GPU has fallen off the bus."
        )).unwrap();
        assert_eq!(f.category, "GPU");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.title.contains("fallen off the bus"));
    }

    #[test]
    fn nvidia_xid_13_app_level_is_warning() {
        let f = classify(&kline(
            "NVRM: Xid (PCI:0000:01:00): 13, pid=4242, Graphics Exception: ESR 0x404490=0x80000000"
        )).unwrap();
        assert_eq!(f.category, "GPU");
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn strix_halo_mes_ring_reset_burst_is_one_gpu_finding() {
        // Verbatim sequence from a real Strix Halo (gfx1151) incident report:
        // Slack under mundane GL load trips a gfx ring timeout; MES reset fails,
        // MODE2 GPU reset recovers. Must collapse to ONE GPU finding naming slack.
        let base = 1_700_000_000;
        let burst = [
            "ring gfx_0.0.0 timeout, signaled seq=17436214, emitted seq=17436217",
            "Process slack pid 17365 thread slack:cs0 pid 17389",
            "Starting gfx_0.0.0 ring reset",
            "MES failed to respond to msg=RESET",
            "failed to reset legacy queue",
            "reset via MES failed and try pipe reset -110",
            "Ring gfx_0.0.0 reset failed",
            "GPU reset begin!. Source: 1",
            "MES failed to respond to msg=REMOVE_QUEUE",
            "failed to unmap legacy queue",
            "[drm:gfx_v11_0_cp_gfx_enable.isra.0 [amdgpu]] *ERROR* failed to halt cp gfx",
            "GPU reset succeeded, trying to resume",
            "GPU reset(1) succeeded!",
            "[drm] device wedged, but recovered through reset",
        ];
        // Every line must classify as GPU (none dropped, none misfiled).
        for msg in burst {
            let f = classify(&kline(msg));
            assert_eq!(f.as_ref().map(|f| f.category.as_str()), Some("GPU"),
                "line not detected as GPU: {msg}");
        }
        let lines: Vec<LogLine> = burst.iter().enumerate()
            .map(|(i, m)| kline_at(base + i as i64, m)).collect();
        let found = scan(&lines);
        assert_eq!(found.len(), 1, "burst must coalesce to one finding");
        assert_eq!(found[0].severity, Severity::Critical);
        assert!(found[0].evidence.iter().any(|e| e.contains("slack")),
            "culprit 'slack' should surface: {:?}", found[0].evidence);
    }

    #[test]
    fn non_drm_error_convention_not_gpu() {
        // "*ERROR*" without any drm/GPU context must not be attributed to the GPU.
        assert!(classify(&kline("some_subsys: *ERROR* widget calibration failed"))
            .is_none());
    }

    #[test]
    fn drm_init_banners_are_not_gpu_findings() {
        // Benign boot lines observed verbatim in this machine's journal.
        for msg in [
            "[drm] Initialized bochs-drm 1.0.0 20130925 for 0000:00:02.0 on minor 0",
            "ACPI: bus type drm_connector registered",
            "fbcon: bochs-drmdrmfb (fb0) is primary device",
            "[drm] Found bochs VGA, ID 0xb0c5.",
            "workqueue: drm_fb_helper_damage_work hogged CPU for >13333us 4 times",
        ] {
            assert!(classify(&kline(msg)).is_none(), "false positive on: {msg}");
        }
    }

    // ── Session ───────────────────────────────────────────────────────────────

    fn user_line(ident: &str, msg: &str) -> LogLine {
        LogLine { time: Timestamp(1_700_000_000), message: msg.into(),
                  identifier: ident.into(), transport: "journal".into() }
    }

    #[test]
    fn xorg_fatal_ee_is_critical_session() {
        let f = classify(&user_line("Xorg",
            "(EE) Fatal server error: (EE) Caught signal 11 (Segmentation fault). Server aborting"
        )).unwrap();
        assert_eq!(f.category, "Session");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn xorg_nonfatal_ee_line_ignored() {
        assert!(classify(&user_line("Xorg",
            "(EE) AIGLX: reverting to software rendering")).is_none());
    }

    #[test]
    fn gnome_session_component_failure() {
        let f = classify(&user_line("gnome-session-binary",
            "Unrecoverable failure in required component org.gnome.Shell.desktop"
        )).unwrap();
        assert_eq!(f.category, "Session");
        assert!(f.title.contains("org.gnome.Shell.desktop"));
    }

    #[test]
    fn wayland_client_lost_compositor() {
        let f = classify(&user_line("firefox",
            "Lost connection to Wayland compositor.")).unwrap();
        assert_eq!(f.category, "Session");
        assert!(f.title.contains("firefox"));
        let g = classify(&user_line("gimp",
            "Gdk-Message: 10:11:12.000: Error 71 (Protocol error) dispatching to Wayland display."
        )).unwrap();
        assert_eq!(g.category, "Session");
    }

    // ── Correlation ───────────────────────────────────────────────────────────

    #[test]
    fn gpu_incident_correlates_with_following_crashes() {
        let base = 1_700_000_000;
        let lines = vec![
            kline_at(base, "[drm:amdgpu_job_timedout [amdgpu]] *ERROR* ring gfx_0.0.0 \
                            timeout, signaled seq=633, emitted seq=635"),
            kline_at(base + 40,
                "gnome-shell[1500]: segfault at 0 ip 00007f00 sp 00007ffe error 4 in \
                 libmutter.so[7f00+1a000]"),
            LogLine { time: Timestamp(base + 55),
                message: "Lost connection to Wayland compositor.".into(),
                identifier: "firefox".into(), transport: "journal".into() },
        ];
        let found = scan(&lines);
        assert_eq!(found.len(), 3);
        let gpu = found.iter().find(|f| f.category == "GPU").unwrap();
        let seg = found.iter().find(|f| f.category == "Segfault").unwrap();
        let ses = found.iter().find(|f| f.category == "Session").unwrap();
        assert!(gpu.evidence.iter().any(|e| e.contains("casualty")), "{:?}", gpu.evidence);
        assert!(seg.evidence.iter().any(|e| e.contains("GPU incident")), "{:?}", seg.evidence);
        // The session loss is correlated both to the GPU incident and to the
        // compositor (gnome-shell) segfault.
        assert!(ses.evidence.iter().any(|e| e.contains("GPU incident")), "{:?}", ses.evidence);
        assert!(ses.evidence.iter().any(|e| e.contains("compositor")), "{:?}", ses.evidence);
    }

    #[test]
    fn distant_crash_not_correlated_with_gpu() {
        let base = 1_700_000_000;
        let lines = vec![
            kline_at(base, "amdgpu 0000:0c:00.0: amdgpu: GPU reset begin!"),
            kline_at(base + 3600,
                "chrome[4242]: segfault at 7f00 ip 00007f00 sp 00007ffe error 4 in libc.so[7f00+1a]"),
        ];
        let found = scan(&lines);
        let seg = found.iter().find(|f| f.category == "Segfault").unwrap();
        assert!(!seg.evidence.iter().any(|e| e.contains("GPU incident")));
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
