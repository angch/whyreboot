//! Text and JSON output for boot cycles, including explanations and remediation advice.

use chrono::Local;
use crate::color::Pal;
use crate::types::{AudioPowerInfo, BootCycle, Cause, EventRecord};

// ── Cause labelling ───────────────────────────────────────────────────────────

/// Short all-caps label for the verdict line, e.g. `"BLUE SCREEN OF DEATH (BSOD)"`.
pub fn cause_label(cause: &Cause) -> &'static str {
    match cause {
        Cause::BlueScreen { .. }    => "BLUE SCREEN OF DEATH (BSOD)",
        Cause::ForcedPowerOff       => "FORCED POWER-OFF",
        Cause::UnexpectedShutdown   => "UNEXPECTED / UNCLEAN SHUTDOWN",
        Cause::WindowsUpdate { .. } => "WINDOWS UPDATE",
        Cause::UserAction { .. }    => "USER-INITIATED",
        Cause::SystemProcess { .. } => "SYSTEM / SOFTWARE RESTART",
        Cause::NormalShutdown       => "NORMAL SHUTDOWN",
        Cause::Undetermined         => "UNDETERMINED",
    }
}

/// One-line detail sentence printed under the verdict, e.g. stop code and name for BSODs.
pub fn cause_detail(cause: &Cause) -> String {
    match cause {
        Cause::BlueScreen { stop_code, stop_name, .. } =>
            format!("Stop code 0x{:08X} — {}", stop_code, stop_name),
        Cause::ForcedPowerOff =>
            "Power button held down or power cable pulled".into(),
        Cause::UnexpectedShutdown =>
            "System did not shut down cleanly (crash or power loss)".into(),
        Cause::WindowsUpdate { process } =>
            format!("Restart to apply updates ({})", process.split('\\').last().unwrap_or(process)),
        Cause::UserAction { user, action, .. } =>
            format!("{} by {}", action, user),
        Cause::SystemProcess { process, action, .. } =>
            format!("{} by {}", action, process.split('\\').last().unwrap_or(process)),
        Cause::NormalShutdown =>
            "System shut down cleanly; no specific initiator recorded".into(),
        Cause::Undetermined =>
            "Insufficient event log data to determine cause".into(),
    }
}

/// Maps a cause to the appropriate palette color (crash=red, undetermined=yellow, else=green).
fn cause_color<'p>(cause: &Cause, pal: &'p Pal) -> &'p str {
    match cause {
        Cause::BlueScreen { .. } | Cause::ForcedPowerOff | Cause::UnexpectedShutdown => pal.crash,
        Cause::Undetermined => pal.warn,
        _ => pal.ok,
    }
}

// ── Formatting helpers ────────────────────────────────────────────────────────

/// Formats a duration in seconds as `Xs`, `Xm YYs`, or `Xh YYm`.
pub fn fmt_secs(s: i64) -> String {
    let s = s.max(0);
    if s < 60        { format!("{}s", s) }
    else if s < 3600 { format!("{}m {:02}s", s / 60, s % 60) }
    else             { format!("{}h {:02}m", s / 3600, (s % 3600) / 60) }
}

/// Returns the last `-`-delimited component of a provider name for compact table display.
fn short_provider(p: &str) -> &str {
    p.rfind('-').map(|i| &p[i + 1..]).unwrap_or(p)
}

/// Short human-readable summary for a raw event row in the event table.
fn event_summary(ev: &EventRecord) -> String {
    let d = &ev.data;
    match ev.event_id {
        12   => "System started".into(),
        13   => "System shutdown initiated".into(),
        41   => format!(
            "Unexpected shutdown — BugCheck={}",
            d.get("BugcheckCode").map(|s| s.as_str()).unwrap_or("?")
        ),
        109  => "Kernel power button transition".into(),
        1074 => format!(
            "{} by {}",
            d.get("param5").map(|s| s.as_str()).unwrap_or("action"),
            d.get("param3").map(|s| s.as_str()).unwrap_or("?")
        ),
        1076 => "Shutdown reason documented".into(),
        6006 => "Event log stopped cleanly (shutdown)".into(),
        6008 => "Previous shutdown was unexpected".into(),
        6009 => "Startup: Windows version info".into(),
        6013 => d
            .get("param1")
            .and_then(|s| s.parse::<i64>().ok())
            .map(|s| format!("System uptime: {}", fmt_secs(s)))
            .unwrap_or_else(|| "System uptime".into()),
        id   => format!("Event {}", id),
    }
}

// ── Explanation ───────────────────────────────────────────────────────────────

/// Generates plain-English diagnosis and numbered remediation steps for known BSOD patterns.
/// Returns an empty vec for non-BSOD causes or stop codes without a known handler.
/// Dispatches by stop code: 0x9F → driver power failure, 0x19C → Win32k watchdog,
/// 0xFE / 0x144 → USB driver bugcheck.
pub fn generate_explanation(
    cause:  &Cause,
    module: &Option<String>,
    audio:  &[AudioPowerInfo],
) -> Vec<String> {
    let mut out = Vec::new();
    let Cause::BlueScreen { stop_code, params, .. } = cause else { return out };

    match *stop_code {
        0x0000009F => explain_driver_power_failure(module, params[0], audio, &mut out),
        0x0000019C => explain_win32k_power_watchdog(module, &mut out),
        0x000000FE | 0x00000144 => {
            out.push("BUGCODE_USB_DRIVER: a USB driver triggered a fatal error.".into());
            out.push(String::new());
            out.push("Recommended actions:".into());
            out.push("  1. Disconnect USB devices and test if crashes stop.".into());
            out.push("  2. Update chipset/USB 3 drivers.".into());
            out.push("  3. Disable USB selective suspend (Power Options → USB settings).".into());
        }
        _ => {}
    }
    out
}

/// Explanation handler for stop code 0x9F (DRIVER_POWER_STATE_FAILURE).
/// Branches on whether the faulting module is audio, USB, or other.
fn explain_driver_power_failure(
    module: &Option<String>,
    p1:     u64,
    audio:  &[AudioPowerInfo],
    out:    &mut Vec<String>,
) {
    let m     = module.as_deref().unwrap_or("(unknown driver)");
    let m_low = m.to_lowercase();
    let is_audio = m_low.contains("portcls") || m_low.contains("audio") || m_low.contains("hdaud");
    let is_usb   = m_low.contains("usbccgp") || m_low.contains("usbhub") || m_low.contains("usb");

    out.push(format!("DRIVER_POWER_STATE_FAILURE: {} failed to complete a power state", m));
    out.push("transition in time. Windows was going to sleep, hibernating, or".into());
    out.push("shutting down when the driver stalled and never responded.".into());

    if p1 == 3 {
        out.push(String::new());
        out.push(format!("P1=3: the OS sent an IRP_MN_SET_POWER request to {} but the driver", m));
        out.push("object did not complete it before the watchdog expired.".into());
    }

    out.push(String::new());
    out.push("Recommended actions:".into());

    if is_audio {
        explain_audio_fix(audio, out);
    } else if is_usb {
        out.push("  1. Disable USB selective suspend:".into());
        out.push("     Control Panel → Power Options → Change plan settings".into());
        out.push("     → Change advanced power settings → USB settings".into());
        out.push("     → USB selective suspend setting → Disabled".into());
        out.push("  2. Disconnect USB devices before sleep/shutdown as a workaround.".into());
        out.push("  3. Update chipset/USB drivers.".into());
    } else {
        out.push(format!("  1. Update the {} driver.", m));
        out.push("  2. Check Device Manager for a Power Management tab on this device.".into());
        out.push("  3. Update BIOS/UEFI firmware.".into());
    }
}

/// Adds audio-specific remediation steps, incorporating the actual registry state.
/// If all devices already have `AllowIdleIrpInD3=0`, pivots to "update driver/BIOS".
fn explain_audio_fix(audio: &[AudioPowerInfo], out: &mut Vec<String>) {
    let all_safe = !audio.is_empty() && audio.iter().all(|d| d.allow_idle_d3 == Some(0));

    if all_safe {
        out.push("  [OK] AllowIdleIrpInD3=0 is already set for all audio devices.".into());
        out.push("  1. The driver itself may be buggy — update your audio driver.".into());
        out.push("  2. Update BIOS/UEFI firmware.".into());
        return;
    }

    let none_set = audio.iter().all(|d| d.allow_idle_d3.is_none());
    if none_set {
        out.push("  1. Disable audio idle D3 power entry (most effective fix):".into());
        out.push("     For each audio instance below, create DWORD AllowIdleIrpInD3=0 in:".into());
        out.push("     HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96c-e325-11ce-bfc1-08002be10318}\\<inst>".into());
    } else {
        out.push("  1. Some audio devices still have AllowIdleIrpInD3 unset (see below).".into());
        out.push("     Set AllowIdleIrpInD3=0 (DWORD) for all audio class instances.".into());
    }
    out.push("  2. Alternatively, via Device Manager:".into());
    out.push("     Sound, video and game controllers → [audio device] → Properties".into());
    out.push("     → Power Management → uncheck \"Allow the computer to turn off".into());
    out.push("     this device to save power\" (if tab is visible)".into());
    out.push("  3. Update your audio driver (Realtek/Intel HD Audio).".into());
    out.push("  4. Check for a BIOS update — AMD platform power management bugs".into());
    out.push("     can manifest as portcls stalls.".into());
}

/// Explanation handler for stop code 0x19C (WIN32K_POWER_WATCHDOG_TIMEOUT).
/// Typically a GPU driver failing to wake during a power transition.
fn explain_win32k_power_watchdog(module: &Option<String>, out: &mut Vec<String>) {
    let m = module.as_deref().unwrap_or("(unknown driver)");
    out.push("WIN32K_POWER_WATCHDOG_TIMEOUT: the display subsystem failed to respond".into());
    out.push(format!("during a power transition. {} timed out waking the GPU from sleep.", m));
    out.push(String::new());
    out.push("Recommended actions:".into());
    out.push("  1. Update GPU driver (NVIDIA/AMD) — this is the most common fix.".into());
    out.push("  2. Disable Fast Startup:".into());
    out.push("     Control Panel → Power Options → Choose what the power buttons do".into());
    out.push("     → uncheck \"Turn on fast startup (recommended)\"".into());
    out.push("  3. Install pending Windows updates — Microsoft patches dxgkrnl watchdog".into());
    out.push("     issues via cumulative updates.".into());
    out.push("  4. In NVIDIA/AMD control panel: set power management mode to".into());
    out.push("     \"Prefer maximum performance\" (disables aggressive GPU idle).".into());
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
        let pad  = w.saturating_sub(label.len());
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
        let ago = Local::now().signed_duration_since(bt);
        let ago_s = if ago.num_days() >= 2 {
            format!("{} days ago", ago.num_days())
        } else if ago.num_hours() >= 2 {
            format!("{} hours ago", ago.num_hours())
        } else {
            format!("{} minutes ago", ago.num_minutes())
        };
        println!("  {}Last boot:{} {}  ({})", pal.bold, pal.reset, bt.format("%Y-%m-%d %H:%M:%S"), ago_s);
    } else {
        println!("  {}Boot time:{} (unknown — no Event 12 in log window)", pal.bold, pal.reset);
    }

    if let (Some(sd), Some(bt)) = (cycle.shutdown_time, cycle.boot_time) {
        let offline = bt.signed_duration_since(sd).num_seconds();
        println!("  {}Offline:{}   {} → {}  ({})",
            pal.bold, pal.reset,
            sd.format("%H:%M:%S"), bt.format("%H:%M:%S"), fmt_secs(offline));
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
    let mut tl = cycle.timeline.clone();
    tl.sort_by_key(|(t, _)| *t);
    println!();
    println!("  {}Timeline:{}", pal.bold, pal.reset);
    for (t, msg) in &tl {
        println!("    {}{}{}  {}", pal.dim, t.format("%Y-%m-%d %H:%M:%S"), pal.reset, msg);
    }
}

fn print_minidumps(cycle: &BootCycle, pal: &Pal) {
    if cycle.minidumps.is_empty() { return; }
    println!();
    println!("  {}Minidumps:{}", pal.bold, pal.reset);
    for (t, p) in &cycle.minidumps {
        println!("    {}{}{}  {}", pal.dim, t.format("%Y-%m-%d %H:%M:%S"), pal.reset, p.display());
    }
}

/// Prints audio class registry power state — only for power-related BSODs
/// where the faulting module is audio-related (`portcls`, `audio`, `hdaud`).
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
    println!("{:<20} {:>6}  {:<26}  {}", "Time", "Event", "Provider", "Summary");
    println!("{}", line);
    for ev in &cycle.display_events {
        println!(
            "{:<20} {:>6}  {:<26.26}  {}",
            ev.time_created.format("%Y-%m-%d %H:%M:%S"),
            ev.event_id,
            short_provider(&ev.provider),
            event_summary(ev),
        );
    }
    println!("{}", line);
}

// ── JSON output ───────────────────────────────────────────────────────────────

/// Escapes a string for JSON output (backslash, quote, newlines, tabs).
fn json_str(s: &str) -> String {
    format!("\"{}\"",
        s.replace('\\', "\\\\")
         .replace('"',  "\\\"")
         .replace('\n', "\\n")
         .replace('\r', "\\r")
         .replace('\t', "\\t"))
}

/// Outputs all boot cycles as hand-built JSON to stdout (no serde dependency).
pub fn print_json(cycles: &[BootCycle]) {
    let now = Local::now().to_rfc3339();
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
