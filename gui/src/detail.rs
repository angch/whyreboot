// SPDX-License-Identifier: MIT OR Apache-2.0
//! Builds the right-pane detail text for one boot cycle. Pure string formatting —
//! no Win32 calls — mirroring the CLI's `display.rs` for the same data.

use whyreboot::format::{
    audio_power_status_text, cause_detail, cause_label, event_row, event_table_header,
    fmt_secs, generate_explanation, is_audio_power_crash, relative_ago,
};
use whyreboot::timestamp::Timestamp;
use whyreboot::types::{AudioPowerInfo, BootCycle};

pub fn format_cycle_detail(c: &BootCycle, audio: &[AudioPowerInfo]) -> String {
    let mut s = String::new();

    // ── Boot times ────────────────────────────────────────────────────────────
    let bt_str = c.boot_time
        .map(|t| t.format_dt())
        .unwrap_or_else(|| "(unknown — no Event 12 found)".into());
    s += &format!("Boot time:   {}\r\n", bt_str);

    if let Some(t) = c.boot_time {
        let ago = relative_ago(Timestamp::now().secs_since(t));
        s += &format!("             ({})\r\n", ago);
    }

    if let Some((sd, bt)) = c.shutdown_time.zip(c.boot_time) {
        let secs = bt.secs_since(sd);
        if secs >= 0 {
            s += &format!("Offline:     {}  \u{2192}  {}  ({})\r\n",
                sd.format_t(), bt.format_t(), fmt_secs(secs));
        }
    }

    s += "\r\n";

    // ── Verdict ───────────────────────────────────────────────────────────────
    s += &format!("VERDICT:     {}  ({}% confidence)\r\n", cause_label(&c.cause), c.confidence);
    s += &format!("             {}\r\n", cause_detail(&c.cause));
    if let Some(m) = &c.wer_module {
        s += &format!("Module:      {}  [from WER Event 1001]\r\n", m);
    }

    // ── Evidence ──────────────────────────────────────────────────────────────
    if !c.evidence.is_empty() {
        s += "\r\nEvidence:\r\n";
        for e in &c.evidence {
            s += &format!("  \u{2022} {}\r\n", e);
        }
    }

    // ── Timeline ──────────────────────────────────────────────────────────────
    if c.timeline.len() > 1 {
        let mut idxs: Vec<usize> = (0..c.timeline.len()).collect();
        idxs.sort_by_key(|&i| c.timeline[i].0);
        s += "\r\nTimeline:\r\n";
        for i in idxs {
            let (t, msg) = &c.timeline[i];
            s += &format!("  {}  {}\r\n", t.format_dt(), msg);
        }
    }

    // ── Minidumps ─────────────────────────────────────────────────────────────
    if !c.minidumps.is_empty() {
        s += "\r\nMinidumps:\r\n";
        for (t, p) in &c.minidumps {
            s += &format!("  {}  {}\r\n", t.format_dt(), p.display());
        }
    }

    // ── Device Power Settings (conditional: audio power-crash only) ───────────
    if is_audio_power_crash(&c.cause, &c.wer_module) && !audio.is_empty() {
        s += "\r\nDevice Power Settings (audio class):\r\n";
        for dev in audio {
            let status = audio_power_status_text(dev.allow_idle_d3);
            s += &format!("  [{}] {:<32}  {}\r\n", dev.instance, dev.name, status);
        }
    }

    // ── Explanation / remediation ─────────────────────────────────────────────
    let explanation = generate_explanation(&c.cause, &c.wer_module, audio);
    if !explanation.is_empty() {
        s += "\r\nExplanation:\r\n";
        for ln in &explanation {
            if ln.is_empty() { s += "\r\n"; } else { s += &format!("  {}\r\n", ln); }
        }
    }

    // ── Raw event table ───────────────────────────────────────────────────────
    if !c.display_events.is_empty() {
        let line = "\u{2500}".repeat(69);
        s += &format!("\r\n{}\r\n", line);
        s += &format!("{}\r\n", event_table_header());
        s += &format!("{}\r\n", line);
        for ev in &c.display_events {
            s += &format!("{}\r\n", event_row(ev));
        }
        s += &format!("{}\r\n", line);
    }

    s
}
