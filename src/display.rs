// SPDX-License-Identifier: MIT OR Apache-2.0
//! Text and JSON output.
//!
//! Two report styles share this module:
//! - **Findings** (portable): generic [`Finding`] issues over a time window —
//!   the Linux/OOM path, and the general model going forward.
//! - **Boot cycles** (`cfg(windows)`): the Windows-specific reboot diagnosis.

use crate::color::Pal;
use whyreboot::timestamp::Timestamp;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use whyreboot::timewindow::TimeWindow;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use whyreboot::types::{Finding, Severity};

#[cfg(windows)]
use whyreboot::format::{
    audio_power_status_text, cause_detail, cause_label, event_row, event_table_header, fmt_secs,
    generate_explanation, is_audio_power_crash, relative_ago,
};
#[cfg(windows)]
use whyreboot::types::{AudioPowerInfo, BootCycle, Cause};

// ── Finding output (portable) ───────────────────────────────────────────────────

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn severity_color(sev: Severity, pal: &Pal) -> &str {
    match sev {
        Severity::Critical => pal.crash,
        Severity::Warning => pal.warn,
        Severity::Info => pal.info,
    }
}

/// Prints the findings report: a header describing the scanned window, then one
/// block per finding (newest first), or a clean-bill-of-health line if none.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn print_findings(findings: &[Finding], pal: &Pal, window: &TimeWindow, scanned: usize) {
    let w = 74usize;
    println!();
    println!("{}{}{}", pal.bold, "═".repeat(w), pal.reset);
    println!(
        "  {}System Issue Report{} — {}",
        pal.bold,
        pal.reset,
        window.describe()
    );
    println!(
        "  Scanned {} log record(s); found {}{}{} issue(s).",
        scanned,
        if findings.is_empty() {
            pal.ok
        } else {
            pal.crash
        },
        findings.len(),
        pal.reset
    );
    println!("{}{}{}", pal.bold, "═".repeat(w), pal.reset);

    if findings.is_empty() {
        println!();
        println!(
            "  {}No issues detected in this window.{}",
            pal.ok, pal.reset
        );
        println!();
        return;
    }

    for f in findings {
        let color = severity_color(f.severity, pal);
        println!();
        println!(
            "  {}[{}]{} {}{}{}  {}{}{}",
            color,
            f.severity.label(),
            pal.reset,
            pal.bold,
            f.category,
            pal.reset,
            pal.dim,
            f.time.format_dt(),
            pal.reset
        );
        println!("  {}{}{}", pal.bold, f.title, pal.reset);
        println!("  {}source: {}{}", pal.dim, f.source, pal.reset);
        for e in f.detail_lines() {
            println!("    • {}", e);
        }
    }
    println!();
}

/// Outputs findings as hand-built JSON (no serde dependency), mirroring the
/// boot-cycle JSON shape.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn print_findings_json(findings: &[Finding], window: &TimeWindow, scanned: usize) {
    println!(
        "{}",
        findings_json(findings, window, scanned, Timestamp::now())
    );
}

/// Renders the findings JSON document. Split from the `println!` wrapper and
/// given an explicit `generated` timestamp so the exact output can be asserted
/// in tests — printing straight to stdout left this shape uncovered.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn findings_json(
    findings: &[Finding],
    window: &TimeWindow,
    scanned: usize,
    generated: Timestamp,
) -> String {
    let mut o = String::new();
    o.push_str("{\n");
    push_field(&mut o, "  ", "schema_version", &SCHEMA_VERSION.to_string());
    push_field(
        &mut o,
        "  ",
        "generated",
        &json_str(&generated.to_rfc3339()),
    );
    push_field(&mut o, "  ", "window_start", &json_time(window.start));
    push_field(&mut o, "  ", "window_end", &json_time(window.end));
    push_field(&mut o, "  ", "scanned", &scanned.to_string());
    push_field(&mut o, "  ", "issue_count", &findings.len().to_string());
    o.push_str("  \"issues\": [\n");
    for (i, f) in findings.iter().enumerate() {
        o.push_str("    {\n");
        push_field(&mut o, "      ", "time", &json_str(&f.time.to_rfc3339()));
        push_field(&mut o, "      ", "severity", &json_str(f.severity.label()));
        push_field(&mut o, "      ", "category", &json_str(&f.category));
        push_field(&mut o, "      ", "title", &json_str(&f.title));
        push_field(&mut o, "      ", "source", &json_str(&f.source));
        o.push_str("      \"evidence\": ");
        push_array(&mut o, &f.evidence);
        o.push_str(",\n");
        push_field(&mut o, "      ", "raw", &json_str(&f.raw));
        o.push_str("      \"related\": ");
        push_array(&mut o, &f.related);
        o.push_str(",\n");
        o.push_str("      \"correlations\": ");
        push_array(&mut o, &f.correlations);
        o.push('\n');
        o.push_str(if i + 1 < findings.len() {
            "    },\n"
        } else {
            "    }\n"
        });
    }
    o.push_str("  ]\n}");
    o
}

// ── Cause color ───────────────────────────────────────────────────────────────

#[cfg(windows)]
fn cause_color<'p>(cause: &Cause, pal: &'p Pal) -> &'p str {
    use whyreboot::format::CauseSeverity;
    match whyreboot::format::cause_severity(cause) {
        CauseSeverity::Crash => pal.crash,
        CauseSeverity::Warn => pal.warn,
        CauseSeverity::Ok => pal.ok,
    }
}

// ── Cycle printing ────────────────────────────────────────────────────────────

/// Prints all sections for one boot cycle to stdout in order:
/// header → boot times → verdict → evidence → timeline → minidumps →
/// device power settings → explanation → event table.
#[cfg(windows)]
pub fn print_cycle(cycle: &BootCycle, pal: &Pal, total: usize, audio: &[AudioPowerInfo]) {
    let w = 74usize;
    let line = "─".repeat(w);
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
            format!(
                " Boot Cycle {} of {} — most recent ",
                total - cycle.index,
                total
            )
        } else {
            format!(" Boot Cycle {} of {} ", total - cycle.index, total)
        };
        // Pad by char count, not byte length — the em dash is 3 bytes but 1 column.
        let pad = w.saturating_sub(label.chars().count());
        let lpad = pad / 2;
        let rpad = pad - lpad;
        println!(
            "{}{}{}{}{}",
            pal.bold,
            "═".repeat(lpad),
            label,
            "═".repeat(rpad),
            pal.reset
        );
    } else {
        println!("{}{}{}", pal.bold, dline, pal.reset);
    }
}

#[cfg(windows)]
fn print_boot_times(cycle: &BootCycle, pal: &Pal) {
    if let Some(bt) = cycle.boot_time {
        let ago_s = relative_ago(Timestamp::now().secs_since(bt));
        println!(
            "  {}Last boot:{} {}  ({})",
            pal.bold,
            pal.reset,
            bt.format_dt(),
            ago_s
        );
    } else {
        println!(
            "  {}Boot time:{} (unknown — no Event 12 in log window)",
            pal.bold, pal.reset
        );
    }

    if let (Some(sd), Some(bt)) = (cycle.shutdown_time, cycle.boot_time) {
        let offline = bt.secs_since(sd);
        if offline >= 0 {
            println!(
                "  {}Offline:{}   {} → {}  ({})",
                pal.bold,
                pal.reset,
                sd.format_t(),
                bt.format_t(),
                fmt_secs(offline)
            );
        }
    }
}

#[cfg(windows)]
fn print_verdict(cycle: &BootCycle, pal: &Pal) {
    println!();
    let color = cause_color(&cycle.cause, pal);
    println!(
        "  {}VERDICT:{}    {}{}{} ({}% confidence)",
        pal.bold,
        pal.reset,
        color,
        cause_label(&cycle.cause),
        pal.reset,
        cycle.confidence
    );
    println!("              {}", cause_detail(&cycle.cause));

    if let Some(ref m) = cycle.wer_module {
        println!(
            "  {}Module:{}     {} {}[from WER Event 1001]{}",
            pal.bold, pal.reset, m, pal.info, pal.reset
        );
    }
}

#[cfg(windows)]
fn print_evidence(cycle: &BootCycle, pal: &Pal) {
    if cycle.evidence.is_empty() {
        return;
    }
    println!();
    println!("  {}Evidence:{}", pal.bold, pal.reset);
    for line in &cycle.evidence {
        println!("    • {}", line);
    }
}

#[cfg(windows)]
fn print_timeline(cycle: &BootCycle, pal: &Pal) {
    if cycle.timeline.len() <= 1 {
        return;
    }
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
    if cycle.minidumps.is_empty() {
        return;
    }
    println!();
    println!("  {}Minidumps:{}", pal.bold, pal.reset);
    for (t, p) in &cycle.minidumps {
        println!(
            "    {}{}{}  {}",
            pal.dim,
            t.format_dt(),
            pal.reset,
            p.display()
        );
    }
}

/// Prints audio class registry power state — only for power-related BSODs
/// where the faulting module is audio-related (`portcls`, `audio`, `hdaud`).
#[cfg(windows)]
fn print_device_power(cycle: &BootCycle, pal: &Pal, audio: &[AudioPowerInfo]) {
    if !is_audio_power_crash(&cycle.cause, &cycle.wer_module) || audio.is_empty() {
        return;
    }

    println!();
    println!(
        "  {}Device Power Settings (audio class):{}",
        pal.bold, pal.reset
    );
    for dev in audio {
        let color = match dev.allow_idle_d3 {
            Some(0) => pal.ok,
            Some(_) => pal.crash,
            None => pal.warn,
        };
        let text = audio_power_status_text(dev.allow_idle_d3);
        println!(
            "    [{}] {:<32}  {}{}{}",
            dev.instance, dev.name, color, text, pal.reset
        );
    }
}

#[cfg(windows)]
fn print_explanation(cycle: &BootCycle, pal: &Pal, audio: &[AudioPowerInfo]) {
    let lines = generate_explanation(&cycle.cause, &cycle.wer_module, audio);
    if lines.is_empty() {
        return;
    }
    println!();
    println!("  {}Explanation:{}", pal.bold, pal.reset);
    for ln in &lines {
        if ln.is_empty() {
            println!();
        } else {
            println!("    {}", ln);
        }
    }
}

#[cfg(windows)]
fn print_event_table(cycle: &BootCycle, line: &str) {
    if cycle.display_events.is_empty() {
        return;
    }
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
/// Version of the JSON documents emitted by `--json`. Bump on any breaking
/// change to either shape (renamed/removed field, changed type) so consumers can
/// refuse output they don't understand; additive fields don't require a bump.
const SCHEMA_VERSION: u32 = 1;

/// Appends `"key": value,\n` at `indent`. `value` must already be valid JSON
/// (use `json_str` for strings, `json_time` for optional timestamps).
fn push_field(out: &mut String, indent: &str, key: &str, value: &str) {
    out.push_str(indent);
    out.push('"');
    out.push_str(key);
    out.push_str("\": ");
    out.push_str(value);
    out.push_str(",\n");
}

/// An optional timestamp as an RFC3339 string, or JSON `null`.
fn json_time(t: Option<Timestamp>) -> String {
    t.map_or_else(|| "null".to_string(), |t| json_str(&t.to_rfc3339()))
}

/// Appends a JSON array of escaped strings, e.g. `["a", "b"]`.
fn push_array(out: &mut String, items: &[String]) {
    out.push('[');
    for (i, e) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&json_str(e));
    }
    out.push(']');
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
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
    println!("{}", cycles_json(cycles, Timestamp::now()));
}

/// Renders the boot-cycle JSON document. Split from the `println!` wrapper and
/// given an explicit `generated` timestamp so tests can assert the exact shape.
#[cfg(windows)]
fn cycles_json(cycles: &[BootCycle], generated: Timestamp) -> String {
    let mut o = String::new();
    o.push_str("{\n");
    push_field(&mut o, "  ", "schema_version", &SCHEMA_VERSION.to_string());
    push_field(
        &mut o,
        "  ",
        "generated",
        &json_str(&generated.to_rfc3339()),
    );
    push_field(&mut o, "  ", "cycle_count", &cycles.len().to_string());
    o.push_str("  \"cycles\": [\n");
    for (ci, cycle) in cycles.iter().enumerate() {
        o.push_str("    {\n");
        push_field(&mut o, "      ", "index", &cycle.index.to_string());
        push_field(&mut o, "      ", "boot_time", &json_time(cycle.boot_time));
        push_field(
            &mut o,
            "      ",
            "shutdown_time",
            &json_time(cycle.shutdown_time),
        );
        push_field(
            &mut o,
            "      ",
            "confidence",
            &cycle.confidence.to_string(),
        );

        let (kind, extra) = cause_json(&cycle.cause);
        push_field(&mut o, "      ", "cause", &json_str(kind));
        for line in extra.lines() {
            o.push_str("      ");
            o.push_str(line);
            o.push('\n');
        }

        push_field(
            &mut o,
            "      ",
            "faulting_module",
            &cycle
                .wer_module
                .as_deref()
                .map_or_else(|| "null".to_string(), json_str),
        );

        o.push_str("      \"evidence\": ");
        push_array(&mut o, &cycle.evidence);
        o.push_str(",\n");

        let dumps: Vec<String> = cycle
            .minidumps
            .iter()
            .map(|(_, p)| p.to_string_lossy().into_owned())
            .collect();
        o.push_str("      \"minidumps\": ");
        push_array(&mut o, &dumps);
        o.push('\n');

        o.push_str(if ci + 1 < cycles.len() {
            "    },\n"
        } else {
            "    }\n"
        });
    }
    o.push_str("  ]\n}");
    o
}

/// Returns `(kind_string, extra_json_fields)` for a `Cause` variant.
/// `extra_json_fields` is a fragment of pre-formatted JSON (with trailing comma).
#[cfg(windows)]
fn cause_json(cause: &Cause) -> (&'static str, String) {
    match cause {
        Cause::BlueScreen {
            stop_code,
            stop_name,
            params,
        } => (
            "BlueScreen",
            format!(
                "\"stop_code\": \"0x{:08X}\", \"stop_name\": {}, \"params\": [\"{:#x}\",\"{:#x}\",\"{:#x}\",\"{:#x}\"],",
                stop_code,
                json_str(stop_name),
                params[0],
                params[1],
                params[2],
                params[3]
            ),
        ),
        Cause::WindowsUpdate {
            process,
            old_version,
            new_version,
        } => (
            "WindowsUpdate",
            format!(
                "\"process\": {}, \"old_version\": {}, \"new_version\": {},",
                json_str(process),
                old_version
                    .as_deref()
                    .map(json_str)
                    .unwrap_or_else(|| "null".to_string()),
                new_version
                    .as_deref()
                    .map(json_str)
                    .unwrap_or_else(|| "null".to_string()),
            ),
        ),
        Cause::UserAction {
            user,
            action,
            comment,
        } => (
            "UserAction",
            format!(
                "\"user\": {}, \"action\": {}, \"comment\": {},",
                json_str(user),
                json_str(action),
                json_str(comment)
            ),
        ),
        Cause::SystemProcess {
            process,
            reason,
            action,
        } => (
            "SystemProcess",
            format!(
                "\"process\": {}, \"reason\": {}, \"action\": {},",
                json_str(process),
                json_str(reason),
                json_str(action)
            ),
        ),
        other => (cause_label(other), String::new()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_str_escapes_backslash_and_quote() {
        assert_eq!(
            super::json_str(r#"C:\path"quoted""#),
            r#""C:\\path\"quoted\"""#
        );
    }

    #[test]
    fn json_str_escapes_newline_and_tab() {
        assert_eq!(super::json_str("a\nb\tc"), r#""a\nb\tc""#);
    }

    #[test]
    fn json_str_plain_string() {
        assert_eq!(super::json_str("hello"), r#""hello""#);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod findings_doc {
        use whyreboot::timestamp::Timestamp;
        use whyreboot::timewindow::TimeWindow;
        use whyreboot::types::{Finding, Severity};

        const GEN: Timestamp = Timestamp(1_700_000_000);

        fn finding(title: &str) -> Finding {
            Finding {
                time: Timestamp(1_699_999_000),
                severity: Severity::Critical,
                category: "OOM".to_string(),
                title: title.to_string(),
                evidence: vec!["first".to_string(), "second \"quoted\"".to_string()],
                raw: "Out of memory: Killed process 1 (a)".to_string(),
                related: Vec::new(),
                correlations: Vec::new(),
                source: "journald:kernel".to_string(),
            }
        }

        fn render(findings: &[Finding]) -> String {
            super::super::findings_json(findings, &TimeWindow::all(), 42, GEN)
        }

        #[test]
        fn empty_document_shape() {
            let doc = render(&[]);
            assert_eq!(
                doc,
                concat!(
                    "{\n",
                    "  \"schema_version\": 1,\n",
                    "  \"generated\": \"2023-11-14T22:13:20Z\",\n",
                    "  \"window_start\": null,\n",
                    "  \"window_end\": null,\n",
                    "  \"scanned\": 42,\n",
                    "  \"issue_count\": 0,\n",
                    "  \"issues\": [\n",
                    "  ]\n",
                    "}"
                ),
                "unexpected document:\n{doc}"
            );
        }

        #[test]
        fn issue_fields_and_escaping() {
            let doc = render(&[finding("kernel OOM")]);
            assert!(doc.contains("\"title\": \"kernel OOM\""), "{doc}");
            assert!(doc.contains("\"severity\": \"CRITICAL\""), "{doc}");
            assert!(doc.contains("\"category\": \"OOM\""), "{doc}");
            assert!(doc.contains("\"source\": \"journald:kernel\""), "{doc}");
            assert!(doc.contains("\"time\": \"2023-11-14T21:56:40Z\""), "{doc}");
            // Evidence strings are escaped inside the array.
            assert!(
                doc.contains(r#""evidence": ["first", "second \"quoted\""]"#),
                "{doc}"
            );
        }

        /// The separator logic is the classic hand-rolled-JSON bug: a trailing
        /// comma after the last element is invalid JSON.
        #[test]
        fn no_trailing_comma_between_issues() {
            let doc = render(&[finding("one"), finding("two")]);
            assert!(doc.contains("    },\n    {\n"), "missing separator:\n{doc}");
            assert!(!doc.contains("},\n  ]"), "trailing comma:\n{doc}");
            assert_eq!(doc.matches("\"title\"").count(), 2);
        }

        #[test]
        fn window_bounds_are_rendered_when_set() {
            let w = TimeWindow {
                start: Some(Timestamp(1_699_990_000)),
                end: Some(Timestamp(1_699_999_999)),
            };
            let doc = super::super::findings_json(&[], &w, 0, GEN);
            assert!(
                doc.contains("\"window_start\": \"2023-11-14T19:26:40Z\""),
                "{doc}"
            );
            assert!(
                doc.contains("\"window_end\": \"2023-11-14T22:13:19Z\""),
                "{doc}"
            );
        }
    }
}
