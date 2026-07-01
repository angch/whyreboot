// SPDX-License-Identifier: MIT OR Apache-2.0
//! Builds the right-pane detail text for one boot cycle. Pure string formatting —
//! no Win32 calls — mirroring the CLI's `display.rs` for the same data.

use whyreboot::format::{cause_detail, cause_label, event_summary, fmt_secs, generate_explanation, short_provider};
use whyreboot::timestamp::Timestamp;
use whyreboot::types::{AudioPowerInfo, BootCycle, Cause};

pub fn format_cycle_detail(c: &BootCycle, audio: &[AudioPowerInfo]) -> String {
    let mut s = String::new();

    // ── Boot times ────────────────────────────────────────────────────────────
    let bt_str = c.boot_time
        .map(|t| t.format_dt())
        .unwrap_or_else(|| "(unknown — no Event 12 found)".into());
    s += &format!("Boot time:   {}\r\n", bt_str);

    if let Some(t) = c.boot_time {
        let secs = Timestamp::now().secs_since(t).max(0);
        let ago = if secs < 120        { format!("{secs} seconds ago") }
            else if secs < 7200        { format!("{} minutes ago", secs / 60) }
            else if secs < 172_800     { format!("{} hours ago",   secs / 3600) }
            else                       { format!("{} days ago",    secs / 86400) };
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
    let module_low = c.wer_module.as_deref().unwrap_or("").to_lowercase();
    let is_power_crash = matches!(&c.cause, Cause::BlueScreen { stop_code, .. }
        if *stop_code == 0x9F || *stop_code == 0x19C || *stop_code == 0xFE || *stop_code == 0x144);
    let is_audio_crash = is_power_crash
        && (module_low.contains("portcls") || module_low.contains("audio") || module_low.contains("hdaud"));
    if is_audio_crash && !audio.is_empty() {
        s += "\r\nDevice Power Settings (audio class):\r\n";
        for dev in audio {
            let status = match dev.allow_idle_d3 {
                Some(0) => "AllowIdleIrpInD3=0  [safe — D3 idle disabled]",
                Some(_) => "AllowIdleIrpInD3=1  [RISKY — D3 idle enabled]",
                None    => "AllowIdleIrpInD3: not set [driver default — risky]",
            };
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
        s += &format!("{:<20} {:>6}  {:<26}  Summary\r\n", "Time", "Event", "Provider");
        s += &format!("{}\r\n", line);
        for ev in &c.display_events {
            s += &format!(
                "{:<20} {:>6}  {:<26.26}  {}\r\n",
                ev.time_created.format_dt(),
                ev.event_id,
                short_provider(&ev.provider),
                event_summary(ev),
            );
        }
        s += &format!("{}\r\n", line);
    }

    s
}
