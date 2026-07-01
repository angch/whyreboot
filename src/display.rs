// SPDX-License-Identifier: MIT OR Apache-2.0
//! Text and JSON output for boot cycles, including explanations and remediation advice.

use crate::color::Pal;
use whyreboot::format::{
    audio_power_status_text, cause_label, cause_detail, event_row, event_table_header,
    fmt_secs, generate_explanation, is_audio_power_crash, relative_ago,
};
use whyreboot::timestamp::Timestamp;
use whyreboot::types::{AudioPowerInfo, BootCycle, Cause};

// ── Cause color ───────────────────────────────────────────────────────────────

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
fn print_cycle_header(cycle: &BootCycle, pal: &Pal, total: usize, dline: &str) {
    let w = 74usize;
    if total > 1 {
        let label = if cycle.index == 0 {
            format!(" Boot Cycle {} of {} — most recent ", total - cycle.index, total)
        } else {
            format!(" Boot Cycle {} of {} ", total - cycle.index, total)
        };
        // Pad by char count, not byte length — the em dash is 3 bytes but 1 column.
        let pad  = w.saturating_sub(label.chars().count());
        let lpad = pad / 2;
        let rpad = pad - lpad;
        println!("{}{}{}{}{}",
            pal.bold, "═".repeat(lpad), label, "═".repeat(rpad), pal.reset);
    } else {
        println!("{}{}{}", pal.bold, dline, pal.reset);
    }
}

fn print_boot_times(cycle: &BootCycle, pal: &Pal) {
    if let Some(bt) = cycle.boot_time {
        let ago_s = relative_ago(Timestamp::now().secs_since(bt));
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

fn print_evidence(cycle: &BootCycle, pal: &Pal) {
    if cycle.evidence.is_empty() { return; }
    println!();
    println!("  {}Evidence:{}", pal.bold, pal.reset);
    for line in &cycle.evidence {
        println!("    • {}", line);
    }
}

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
fn print_device_power(cycle: &BootCycle, pal: &Pal, audio: &[AudioPowerInfo]) {
    if !is_audio_power_crash(&cycle.cause, &cycle.wer_module) || audio.is_empty() { return; }

    println!();
    println!("  {}Device Power Settings (audio class):{}", pal.bold, pal.reset);
    for dev in audio {
        let color = match dev.allow_idle_d3 {
            Some(0) => pal.ok,
            Some(_) => pal.crash,
            None    => pal.warn,
        };
        let text = audio_power_status_text(dev.allow_idle_d3);
        println!("    [{}] {:<32}  {}{}{}", dev.instance, dev.name, color, text, pal.reset);
    }
}

fn print_explanation(cycle: &BootCycle, pal: &Pal, audio: &[AudioPowerInfo]) {
    let lines = generate_explanation(&cycle.cause, &cycle.wer_module, audio);
    if lines.is_empty() { return; }
    println!();
    println!("  {}Explanation:{}", pal.bold, pal.reset);
    for ln in &lines {
        if ln.is_empty() { println!(); } else { println!("    {}", ln); }
    }
}

fn print_event_table(cycle: &BootCycle, line: &str) {
    if cycle.display_events.is_empty() { return; }
    println!();
    println!("{}", line);
    println!("{}", event_table_header());
    println!("{}", line);
    for ev in &cycle.display_events {
        println!("{}", event_row(ev));
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
