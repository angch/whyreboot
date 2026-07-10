// SPDX-License-Identifier: MIT OR Apache-2.0
//! Text and JSON output.
//!
//! Two report styles share this module:
//! - **Findings** (portable): generic [`Finding`] issues over a time window —
//!   the Linux/OOM path, and the general model going forward.
//! - **Boot cycles** (`cfg(windows)`): the Windows-specific reboot diagnosis.

use crate::color::Pal;
use whyreboot::timestamp::Timestamp;
use whyreboot::timewindow::TimeWindow;
use whyreboot::types::{Finding, Severity};

#[cfg(windows)]
use whyreboot::format::{
    cause_label, cause_detail, fmt_secs, short_provider, event_summary, generate_explanation,
};
#[cfg(windows)]
use whyreboot::types::{AudioPowerInfo, BootCycle, Cause};

// ── Finding output (portable) ───────────────────────────────────────────────────

fn severity_color(sev: Severity, pal: &Pal) -> &str {
    match sev {
        Severity::Critical => pal.crash,
        Severity::Warning  => pal.warn,
        Severity::Info     => pal.info,
    }
}

/// Prints the findings report: a header describing the scanned window, then one
/// block per finding (newest first), or a clean-bill-of-health line if none.
pub fn print_findings(findings: &[Finding], pal: &Pal, window: &TimeWindow, scanned: usize) {
    let w = 74usize;
    println!();
    println!("{}{}{}", pal.bold, "═".repeat(w), pal.reset);
    println!("  {}System Issue Report{} — {}", pal.bold, pal.reset, window.describe());
    println!("  Scanned {} log record(s); found {}{}{} issue(s).",
        scanned,
        if findings.is_empty() { pal.ok } else { pal.crash },
        findings.len(), pal.reset);
    println!("{}{}{}", pal.bold, "═".repeat(w), pal.reset);

    if findings.is_empty() {
        println!();
        println!("  {}No issues detected in this window.{}", pal.ok, pal.reset);
        println!();
        return;
    }

    for f in findings {
        let color = severity_color(f.severity, pal);
        println!();
        println!("  {}[{}]{} {}{}{}  {}{}{}",
            color, f.severity.label(), pal.reset,
            pal.bold, f.category, pal.reset,
            pal.dim, f.time.format_dt(), pal.reset);
        println!("  {}{}{}", pal.bold, f.title, pal.reset);
        println!("  {}source: {}{}", pal.dim, f.source, pal.reset);
        for e in &f.evidence {
            println!("    • {}", e);
        }
    }
    println!();
}

/// Outputs findings as hand-built JSON (no serde dependency), mirroring the
/// boot-cycle JSON shape.
pub fn print_findings_json(findings: &[Finding], window: &TimeWindow, scanned: usize) {
    println!("{{");
    println!("  \"generated\": {},", json_str(&Timestamp::now().to_rfc3339()));
    match window.start {
        Some(s) => println!("  \"window_start\": {},", json_str(&s.to_rfc3339())),
        None    => println!("  \"window_start\": null,"),
    }
    match window.end {
        Some(e) => println!("  \"window_end\": {},", json_str(&e.to_rfc3339())),
        None    => println!("  \"window_end\": null,"),
    }
    println!("  \"scanned\": {},", scanned);
    println!("  \"issue_count\": {},", findings.len());
    println!("  \"issues\": [");
    for (i, f) in findings.iter().enumerate() {
        println!("    {{");
        println!("      \"time\": {},", json_str(&f.time.to_rfc3339()));
        println!("      \"severity\": {},", json_str(f.severity.label()));
        println!("      \"category\": {},", json_str(&f.category));
        println!("      \"title\": {},", json_str(&f.title));
        println!("      \"source\": {},", json_str(&f.source));
        print!("      \"evidence\": [");
        for (j, e) in f.evidence.iter().enumerate() {
            if j > 0 { print!(", "); }
            print!("{}", json_str(e));
        }
        println!("]");
        if i + 1 < findings.len() { println!("    }},"); } else { println!("    }}"); }
    }
    println!("  ]");
    println!("}}");
}

// ── Cause color ───────────────────────────────────────────────────────────────

#[cfg(windows)]
fn cause_color<'p>(cause: &Cause, pal: &'p Pal) -> &'p str {
    match cause {
        Cause::BlueScreen { .. } | Cause::ForcedPowerOff | Cause::UnexpectedShutdown => pal.crash,
        Cause::Undetermined => pal.warn,
        _ => pal.ok,
    }
}

// ── Cycle printing ────────────────────────────────────────────────────────────

/// Prints all sections for one boot cycle to stdout in order:
/// header → boot times → verdict → evidence → timeline → minidumps →
/// device power settings → explanation → event table.
#[cfg(windows)]
pub fn print_cycle(cycle: &BootCycle, pal: &Pal, total: usize, audio: &[AudioPowerInfo]) {
    let w     = 74usize;
    let line  = "─".repeat(w);
    let dline = "═".repeat(w);

    println!();
    print_cycle_header(cycle, pal, total, &dline);
    print_boot_times(cycle, pal);
    print_verdict(cycle, pal);
    print_evidence(cycle, pal);
    print_timeline(cycle, pal);
    print_minidumps(cycle, pal);
    print_device_power(cycle, pal, audio);
    print_explanation(cycle, pal, audio);
    print_event_table(cycle, &line);
}

/// Prints the cycle separator line with centered "Boot Cycle N of M" label.
#[cfg(windows)]
fn print_cycle_header(cycle: &BootCycle, pal: &Pal, total: usize, dline: &str) {
    let w = 74usize;
    if total > 1 {
        let label = if cycle.index == 0 {
            format!(" Boot Cycle {} of {} — most recent ", total - cycle.index, total)
        } else {
            format!(" Boot Cycle {} of {} ", total - cycle.index, total)
        };
        let pad  = w.saturating_sub(label.len());
        let lpad = pad / 2;
        let rpad = pad - lpad;
        println!("{}{}{}{}{}",
            pal.bold, "═".repeat(lpad), label, "═".repeat(rpad), pal.reset);
    } else {
        println!("{}{}{}", pal.bold, dline, pal.reset);
    }
}

#[cfg(windows)]
fn print_boot_times(cycle: &BootCycle, pal: &Pal) {
    if let Some(bt) = cycle.boot_time {
        let ago_s = secs_to_ago(Timestamp::now().secs_since(bt));
        println!("  {}Last boot:{} {}  ({})", pal.bold, pal.reset, bt.format_dt(), ago_s);
    } else {
        println!("  {}Boot time:{} (unknown — no Event 12 in log window)", pal.bold, pal.reset);
    }

    if let (Some(sd), Some(bt)) = (cycle.shutdown_time, cycle.boot_time) {
        let offline = bt.secs_since(sd);
        if offline >= 0 {
            println!("  {}Offline:{}   {} → {}  ({})",
                pal.bold, pal.reset,
                sd.format_t(), bt.format_t(), fmt_secs(offline));
        }
    }
}

#[cfg(windows)]
fn secs_to_ago(secs: i64) -> String {
    let s = secs.max(0);
    if s >= 2 * 86_400       { format!("{} days ago",    s / 86_400) }
    else if s >= 2 * 3_600   { format!("{} hours ago",   s / 3_600)  }
    else                      { format!("{} minutes ago", s / 60)     }
}

#[cfg(windows)]
fn print_verdict(cycle: &BootCycle, pal: &Pal) {
    println!();
    let color = cause_color(&cycle.cause, pal);
    println!("  {}VERDICT:{}    {}{}{} ({}% confidence)",
        pal.bold, pal.reset, color, cause_label(&cycle.cause), pal.reset, cycle.confidence);
    println!("              {}", cause_detail(&cycle.cause));

    if let Some(ref m) = cycle.wer_module {
        println!("  {}Module:{}     {} {}[from WER Event 1001]{}",
            pal.bold, pal.reset, m, pal.info, pal.reset);
    }
}

#[cfg(windows)]
fn print_evidence(cycle: &BootCycle, pal: &Pal) {
    if cycle.evidence.is_empty() { return; }
    println!();
    println!("  {}Evidence:{}", pal.bold, pal.reset);
    for line in &cycle.evidence {
        println!("    • {}", line);
    }
}

#[cfg(windows)]
fn print_timeline(cycle: &BootCycle, pal: &Pal) {
    if cycle.timeline.len() <= 1 { return; }
    let mut idxs: Vec<usize> = (0..cycle.timeline.len()).collect();
    idxs.sort_by_key(|&i| cycle.timeline[i].0);
    println!();
    println!("  {}Timeline:{}", pal.bold, pal.reset);
    for i in idxs {
        let (t, msg) = &cycle.timeline[i];
        println!("    {}{}{}  {}", pal.dim, t.format_dt(), pal.reset, msg);
    }
}

#[cfg(windows)]
fn print_minidumps(cycle: &BootCycle, pal: &Pal) {
    if cycle.minidumps.is_empty() { return; }
    println!();
    println!("  {}Minidumps:{}", pal.bold, pal.reset);
    for (t, p) in &cycle.minidumps {
        println!("    {}{}{}  {}", pal.dim, t.format_dt(), pal.reset, p.display());
    }
}

/// Prints audio class registry power state — only for power-related BSODs
/// where the faulting module is audio-related (`portcls`, `audio`, `hdaud`).
#[cfg(windows)]
fn print_device_power(cycle: &BootCycle, pal: &Pal, audio: &[AudioPowerInfo]) {
    let module_low = cycle.wer_module.as_deref().unwrap_or("").to_lowercase();
    let is_power_crash = matches!(&cycle.cause, Cause::BlueScreen { stop_code, .. }
        if *stop_code == 0x9F || *stop_code == 0x19C || *stop_code == 0xFE || *stop_code == 0x144);
    let is_audio_crash = is_power_crash
        && (module_low.contains("portcls") || module_low.contains("audio") || module_low.contains("hdaud"));

    if !is_audio_crash || audio.is_empty() { return; }

    println!();
    println!("  {}Device Power Settings (audio class):{}", pal.bold, pal.reset);
    for dev in audio {
        let (color, text) = match dev.allow_idle_d3 {
            Some(0) => (pal.ok,    "AllowIdleIrpInD3=0  [safe — D3 idle disabled]"),
            Some(_) => (pal.crash, "AllowIdleIrpInD3=1  [RISKY — D3 idle enabled]"),
            None    => (pal.warn,  "AllowIdleIrpInD3: not set [driver default — risky]"),
        };
        println!("    [{}] {:<32}  {}{}{}", dev.instance, dev.name, color, text, pal.reset);
    }
}

#[cfg(windows)]
fn print_explanation(cycle: &BootCycle, pal: &Pal, audio: &[AudioPowerInfo]) {
    let lines = generate_explanation(&cycle.cause, &cycle.wer_module, audio);
    if lines.is_empty() { return; }
    println!();
    println!("  {}Explanation:{}", pal.bold, pal.reset);
    for ln in &lines {
        if ln.is_empty() { println!(); } else { println!("    {}", ln); }
    }
}

#[cfg(windows)]
fn print_event_table(cycle: &BootCycle, line: &str) {
    if cycle.display_events.is_empty() { return; }
    println!();
    println!("{}", line);
    println!("{:<20} {:>6}  {:<26}  {}", "Time", "Event", "Provider", "Summary");
    println!("{}", line);
    for ev in &cycle.display_events {
        println!(
            "{:<20} {:>6}  {:<26.26}  {}",
            ev.time_created.format_dt(),
            ev.event_id,
            short_provider(&ev.provider),
            event_summary(ev),
        );
    }
    println!("{}", line);
}

// ── JSON output ───────────────────────────────────────────────────────────────

/// Escapes a string for JSON output: backslash, quote, the standard short
/// escapes (`\n`, `\r`, `\t`), and any other ASCII control character (0x00-0x1F)
/// via `\u00XX` so the output is valid JSON even with unexpected control bytes.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"'  => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Outputs all boot cycles as hand-built JSON to stdout (no serde dependency).
#[cfg(windows)]
pub fn print_json(cycles: &[BootCycle]) {
    let now = Timestamp::now().to_rfc3339();
    println!("{{");
    println!("  \"generated\": {},", json_str(&now));
    println!("  \"cycle_count\": {},", cycles.len());
    println!("  \"cycles\": [");
    for (ci, cycle) in cycles.iter().enumerate() {
        println!("    {{");
        println!("      \"index\": {},", cycle.index);
        match cycle.boot_time {
            Some(bt) => println!("      \"boot_time\": {},", json_str(&bt.to_rfc3339())),
            None     => println!("      \"boot_time\": null,"),
        }
        match cycle.shutdown_time {
            Some(sd) => println!("      \"shutdown_time\": {},", json_str(&sd.to_rfc3339())),
            None     => println!("      \"shutdown_time\": null,"),
        }
        println!("      \"confidence\": {},", cycle.confidence);

        let (kind, extra) = cause_json(&cycle.cause);
        println!("      \"cause\": {},", json_str(kind));
        for line in extra.lines() { println!("      {}", line); }

        match &cycle.wer_module {
            Some(m) => println!("      \"faulting_module\": {},", json_str(m)),
            None    => println!("      \"faulting_module\": null,"),
        }

        print!("      \"evidence\": [");
        for (i, e) in cycle.evidence.iter().enumerate() {
            if i > 0 { print!(", "); }
            print!("{}", json_str(e));
        }
        println!("],");

        print!("      \"minidumps\": [");
        for (i, (_, p)) in cycle.minidumps.iter().enumerate() {
            if i > 0 { print!(", "); }
            print!("{}", json_str(&p.to_string_lossy()));
        }
        println!("]");

        if ci + 1 < cycles.len() { println!("    }},"); } else { println!("    }}"); }
    }
    println!("  ]");
    println!("}}");
}

/// Returns `(kind_string, extra_json_fields)` for a `Cause` variant.
/// `extra_json_fields` is a fragment of pre-formatted JSON (with trailing comma).
#[cfg(windows)]
fn cause_json(cause: &Cause) -> (&'static str, String) {
    match cause {
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
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_str_escapes_backslash_and_quote() {
        assert_eq!(super::json_str(r#"C:\path"quoted""#), r#""C:\\path\"quoted\"""#);
    }

    #[test]
    fn json_str_escapes_newline_and_tab() {
        assert_eq!(super::json_str("a\nb\tc"), r#""a\nb\tc""#);
    }

    #[test]
    fn json_str_plain_string() {
        assert_eq!(super::json_str("hello"), r#""hello""#);
    }
}
