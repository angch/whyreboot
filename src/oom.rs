// SPDX-License-Identifier: MIT OR Apache-2.0
//! Out-of-memory (OOM) detection — pure, platform-agnostic log analysis.
//!
//! Consumes a normalized stream of [`LogLine`]s (produced by a platform backend
//! such as [`crate::linux`]) and emits one [`Finding`] per OOM kill. Two distinct
//! killers are recognized on modern Linux:
//!
//! 1. **Kernel OOM killer** (`mm/oom_kill.c`) — logged to the kernel ring buffer.
//!    The decisive line is `"Out of memory: Killed process <pid> (<comm>) …"`
//!    (older kernels: `"Killed process …"` / `"Kill process …"`), optionally
//!    accompanied by RSS accounting fields.
//! 2. **systemd-oomd** — a userspace, PSI-pressure-based killer common on modern
//!    Ubuntu. It logs `"Killed <cgroup> due to memory pressure …"` under the
//!    `systemd-oomd` syslog identifier. Kernel-only scanning misses these.
//!
//! Matching anchors on stable marker substrings and extracts fields tolerantly,
//! rather than pinning a brittle full-line format.
//!
//! Provenance (see `detect.rs` module docs for the levels): **canonical
//! format** — the kernel wording comes from `mm/oom_kill.c` and the
//! systemd-oomd wording from its source/documentation. Parsing was exercised
//! against a real `journalctl -o json` capture with the OOM message spliced
//! in, but **no live OOM kill has been reproduced** against this detector
//! during development.

use crate::types::{Finding, LogLine, Severity};

/// Classifies a single line as an OOM kill, if it is one. Entry point used by
/// the [`crate::detect`] framework.
pub fn detect(line: &LogLine) -> Option<Finding> {
    if is_oomd(line) {
        detect_systemd_oomd(line)
    } else {
        detect_kernel_oom(line)
    }
}

fn is_oomd(line: &LogLine) -> bool {
    line.identifier.eq_ignore_ascii_case("systemd-oomd")
}

// ── Kernel OOM killer ────────────────────────────────────────────────────────

/// Detects the kernel OOM killer's decisive "Killed process" line and extracts
/// the victim pid, process name, and RSS if present.
fn detect_kernel_oom(line: &LogLine) -> Option<Finding> {
    let msg = &line.message;
    let marker = find_ci(msg, "killed process").or_else(|| find_ci(msg, "kill process"))?;
    let after = &msg[marker..];

    let pid  = first_number(after);
    let comm = between(after, '(', ')');

    let victim = match (&comm, pid) {
        (Some(c), Some(p)) => format!("process '{c}' (pid {p})"),
        (Some(c), None)    => format!("process '{c}'"),
        (None, Some(p))    => format!("process pid {p}"),
        (None, None)       => "a process".to_string(),
    };

    let mut evidence = Vec::new();
    if let Some(rss) = extract_field_kb(msg, "anon-rss:") {
        evidence.push(format!("Victim anonymous RSS: {}", human_kb(rss)));
    }
    if let Some(vm) = extract_field_kb(msg, "total-vm:") {
        evidence.push(format!("Victim total virtual memory: {}", human_kb(vm)));
    }
    if let Some(adj) = extract_after(msg, "oom_score_adj:") {
        evidence.push(format!("oom_score_adj: {adj}"));
    }
    evidence.push(format!("Raw: {}", msg.trim()));
    evidence.push(
        "The kernel ran out of memory and killed the highest-scoring process to \
         reclaim RAM. Check for a memory leak or an under-provisioned machine/cgroup."
            .to_string(),
    );

    Some(Finding {
        time:     line.time,
        severity: Severity::Critical,
        category: "OOM".to_string(),
        title:    format!("Kernel OOM killer terminated {victim}"),
        evidence,
        source:   "journald:kernel".to_string(),
    })
}

// ── systemd-oomd ──────────────────────────────────────────────────────────────

/// Detects systemd-oomd kills. Message form:
/// `"Killed <cgroup> due to <reason> …"`.
fn detect_systemd_oomd(line: &LogLine) -> Option<Finding> {
    let msg = &line.message;
    let marker = find_ci(msg, "killed ")?;
    // Everything after "Killed " up to " due to" is the cgroup path.
    let rest = &msg[marker + "killed ".len()..];
    let due  = find_ci(rest, "due to")?;
    let cgroup = rest[..due].trim().trim_end_matches(',').trim();
    let reason = rest[due..].trim();

    let mut evidence = Vec::new();
    if !reason.is_empty() {
        evidence.push(format!("Reason: {reason}"));
    }
    evidence.push(format!("Raw: {}", msg.trim()));
    evidence.push(
        "systemd-oomd killed this control group in userspace based on memory-pressure \
         (PSI) thresholds — the kernel OOM killer may not have fired. Review the unit's \
         MemoryHigh/MemoryMax limits and its actual usage."
            .to_string(),
    );

    let cg = if cgroup.is_empty() { "a control group".to_string() } else { format!("'{cgroup}'") };

    Some(Finding {
        time:     line.time,
        severity: Severity::Critical,
        category: "OOM".to_string(),
        title:    format!("systemd-oomd killed {cg} under memory pressure"),
        evidence,
        source:   "systemd-oomd".to_string(),
    })
}

// ── String extraction helpers ──────────────────────────────────────────────────

/// ASCII-case-insensitive substring search returning a byte offset into
/// `haystack`. All needles here are ASCII, so the matched span is ASCII and the
/// returned offset is always a valid char boundary — safe to slice `haystack`
/// with, even when the message contains multibyte UTF-8 elsewhere.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    if n.is_empty() || h.len() < n.len() { return None; }
    (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// First run of ASCII digits in `s`, parsed as u64.
fn first_number(s: &str) -> Option<u64> {
    let start = s.find(|c: char| c.is_ascii_digit())?;
    let end = s[start..].find(|c: char| !c.is_ascii_digit()).map_or(s.len(), |i| start + i);
    s[start..end].parse().ok()
}

/// Substring between the first `open` and the next `close`.
fn between(s: &str, open: char, close: char) -> Option<String> {
    let a = s.find(open)? + open.len_utf8();
    let b = s[a..].find(close)? + a;
    Some(s[a..b].to_string())
}

/// Text immediately following `key`, up to the next whitespace or comma.
fn extract_after(s: &str, key: &str) -> Option<String> {
    let pos = s.find(key)? + key.len();
    let rest = s[pos..].trim_start();
    let end = rest.find(|c: char| c.is_whitespace() || c == ',').unwrap_or(rest.len());
    let v = &rest[..end];
    (!v.is_empty()).then(|| v.to_string())
}

/// Parses a `"<key><N>kB"` field (e.g. `"anon-rss:12345kB"`) into kilobytes.
fn extract_field_kb(s: &str, key: &str) -> Option<u64> {
    let v = extract_after(s, key)?;
    let digits: String = v.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Formats a kilobyte count as a human-readable size.
fn human_kb(kb: u64) -> String {
    if kb >= 1024 * 1024 { format!("{:.1} GB", kb as f64 / (1024.0 * 1024.0)) }
    else if kb >= 1024   { format!("{:.1} MB", kb as f64 / 1024.0) }
    else                 { format!("{kb} kB") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timestamp::Timestamp;

    fn kline(msg: &str) -> LogLine {
        LogLine { time: Timestamp(1_700_000_000), message: msg.to_string(),
                  identifier: "kernel".into(), transport: "kernel".into() }
    }
    fn oomd_line(msg: &str) -> LogLine {
        LogLine { time: Timestamp(1_700_000_100), message: msg.to_string(),
                  identifier: "systemd-oomd".into(), transport: "journal".into() }
    }

    #[test]
    fn modern_kernel_kill_extracts_pid_and_comm() {
        let l = kline(
            "Out of memory: Killed process 4242 (chrome) total-vm:9999000kB, \
             anon-rss:512000kB, file-rss:0kB, shmem-rss:0kB, UID:1000 \
             pgtables:2048kB oom_score_adj:300");
        let f = detect(&l).expect("should detect");
        assert_eq!(f.category, "OOM");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.source, "journald:kernel");
        assert!(f.title.contains("chrome"), "title: {}", f.title);
        assert!(f.title.contains("4242"));
        assert!(f.evidence.iter().any(|e| e.contains("MB") || e.contains("GB")));
        assert!(f.evidence.iter().any(|e| e.contains("oom_score_adj: 300")));
    }

    #[test]
    fn older_kernel_kill_without_oom_prefix() {
        let l = kline("Killed process 111 (mysqld) total-vm:200000kB, anon-rss:150000kB");
        let f = detect(&l).expect("should detect");
        assert!(f.title.contains("mysqld"));
        assert!(f.title.contains("111"));
    }

    #[test]
    fn kernel_kill_process_variant() {
        let l = kline("Out of memory: Kill process 999 (python3) score 42 or sacrifice child");
        let f = detect(&l).expect("should detect");
        assert!(f.title.contains("python3"));
        assert!(f.title.contains("999"));
    }

    #[test]
    fn invoked_oom_killer_line_is_not_a_kill() {
        // The dump header is context, not the decisive kill line.
        assert!(detect(&kline(
            "chrome invoked oom-killer: gfp_mask=0x140dca(GFP_HIGHUSER_MOVABLE), order=0"
        )).is_none());
    }

    #[test]
    fn ordinary_kernel_line_ignored() {
        assert!(detect(&kline("usb 1-1: new high-speed USB device number 5")).is_none());
    }

    #[test]
    fn systemd_oomd_memory_pressure_kill() {
        let l = oomd_line(
            "Killed /user.slice/user-1000.slice/user@1000.service/app.slice/app-foo.service \
             due to memory pressure for /user.slice/user-1000.slice/user@1000.service being \
             60.13% > 50.00% for > 20s");
        let f = detect(&l).expect("should detect");
        assert_eq!(f.source, "systemd-oomd");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.title.contains("app-foo.service"), "title: {}", f.title);
        assert!(f.evidence.iter().any(|e| e.contains("memory pressure")));
    }

    #[test]
    fn systemd_oomd_swap_kill() {
        let l = oomd_line(
            "Killed /user.slice/app.slice/leaky.service due to swap used (2000000) / total \
             (2097148) being more than 90.00%");
        let f = detect(&l).expect("should detect");
        assert!(f.title.contains("leaky.service"));
        assert!(f.evidence.iter().any(|e| e.to_lowercase().contains("swap")));
    }

    #[test]
    fn detect_selects_only_oom_lines() {
        let lines = vec![
            kline("Out of memory: Killed process 1 (a) anon-rss:1000kB"),
            oomd_line("Killed /x.service due to memory pressure for /x being 99% > 50% for > 5s"),
            kline("nothing to see here"),
        ];
        let found: Vec<_> = lines.iter().filter_map(detect).collect();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].source, "journald:kernel");
        assert_eq!(found[1].source, "systemd-oomd");
    }

    #[test]
    fn human_kb_scales() {
        assert_eq!(human_kb(512), "512 kB");
        assert_eq!(human_kb(2048), "2.0 MB");
        assert_eq!(human_kb(2 * 1024 * 1024), "2.0 GB");
    }
}
