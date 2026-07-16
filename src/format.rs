// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure formatting utilities — shared between the CLI binary and the GUI crate.

use crate::types::{AudioPowerInfo, Cause, EventRecord};

// ── Cause labelling ───────────────────────────────────────────────────────────

/// Short all-caps verdict label.
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

/// One-line human-readable detail sentence for the verdict.
pub fn cause_detail(cause: &Cause) -> String {
    match cause {
        Cause::BlueScreen { stop_code, stop_name, .. } =>
            format!("Stop code 0x{:08X} — {}", stop_code, stop_name),
        Cause::ForcedPowerOff =>
            "Power button held down or power cable pulled".into(),
        Cause::UnexpectedShutdown =>
            "System did not shut down cleanly (crash or power loss)".into(),
        Cause::WindowsUpdate { process, old_version, new_version } => {
            let base = format!("Restart to apply updates ({})",
                process.split('\\').next_back().unwrap_or(process));
            match (old_version, new_version) {
                (Some(o), Some(n)) if o != n =>
                    format!("{base} — {} → {}", win_product(o), win_product(n)),
                // Same build before and after this boot. Update chains often
                // reboot several times and only bump the build on the final
                // restart, so this does not prove no upgrade — just that the
                // build hadn't changed yet at this boot. Don't overclaim.
                (Some(_), Some(n)) =>
                    format!("{base} — running {}", win_product(n)),
                (None, Some(n)) =>
                    format!("{base} — now running {} (prior version not in log window)", win_product(n)),
                (Some(o), None) =>
                    format!("{base} — was running {}", win_product(o)),
                (None, None) => base,
            }
        }
        Cause::UserAction { user, action, .. } =>
            format!("{} by {}", action, user),
        Cause::SystemProcess { process, action, .. } =>
            format!("{} by {}", action,
                process.split('\\').next_back().unwrap_or(process)),
        Cause::NormalShutdown =>
            "System shut down cleanly; no specific initiator recorded".into(),
        Cause::Undetermined =>
            "Insufficient event log data to determine cause".into(),
    }
}

/// Maps an OS version string `"major.minor.build"` to a friendly product name.
///
/// Windows 11 shares NT version `10.0` with Windows 10 — only the build number
/// distinguishes them (Windows 11 starts at build 22000). Surfacing the raw NT
/// version as "Windows 10.0.26200" reads as "Windows 10" to a user actually on
/// Windows 11, so map the build to the marketing name and keep the build for
/// precision. Anything outside the known Win10/11 build ranges falls back to the
/// raw NT version rather than guessing.
pub fn win_product(version: &str) -> String {
    match version.rsplit('.').next().and_then(|b| b.parse::<u32>().ok()) {
        Some(b) if b >= 22_000                  => format!("Windows 11 (build {b})"),
        Some(b) if (10_240..22_000).contains(&b) => format!("Windows 10 (build {b})"),
        _                                        => format!("Windows {version}"),
    }
}

// ── Duration formatting ───────────────────────────────────────────────────────

/// Formats a duration in seconds as `Xs`, `Xm YYs`, or `Xh YYm`.
pub fn fmt_secs(s: i64) -> String {
    let s = s.max(0);
    if s < 60        { format!("{}s", s) }
    else if s < 3600 { format!("{}m {:02}s", s / 60, s % 60) }
    else             { format!("{}h {:02}m", s / 3600, (s % 3600) / 60) }
}

/// Formats a past duration in seconds as a coarse "N units ago" phrase:
/// seconds (<2m), minutes (<2h), hours (<2d), or days.
pub fn relative_ago(secs: i64) -> String {
    let s = secs.max(0);
    if s < 120          { format!("{s} seconds ago") }
    else if s < 7_200   { format!("{} minutes ago", s / 60) }
    else if s < 172_800 { format!("{} hours ago",   s / 3_600) }
    else                { format!("{} days ago",    s / 86_400) }
}

// ── Audio power-crash classification ──────────────────────────────────────────

/// True if `cause` is a known power-transition BSOD (0x9F, 0x19C, 0xFE, 0x144)
/// and `wer_module` names an audio driver (`portcls`, `audio`, `hdaud`).
pub fn is_audio_power_crash(cause: &Cause, wer_module: &Option<String>) -> bool {
    let is_power_crash = matches!(cause, Cause::BlueScreen { stop_code, .. }
        if *stop_code == 0x9F || *stop_code == 0x19C || *stop_code == 0xFE || *stop_code == 0x144);
    if !is_power_crash { return false; }
    let module_low = wer_module.as_deref().unwrap_or("").to_lowercase();
    module_low.contains("portcls") || module_low.contains("audio") || module_low.contains("hdaud")
}

/// Human-readable status text for one audio device's `AllowIdleIrpInD3` registry
/// value: `Some(0)` is safe, `Some(_)` is risky, `None` is unset (driver default).
pub fn audio_power_status_text(allow_idle_d3: Option<u32>) -> &'static str {
    match allow_idle_d3 {
        Some(0) => "AllowIdleIrpInD3=0  [safe — D3 idle disabled]",
        Some(_) => "AllowIdleIrpInD3=1  [RISKY — D3 idle enabled]",
        None    => "AllowIdleIrpInD3: not set [driver default — risky]",
    }
}

// ── Event helpers ─────────────────────────────────────────────────────────────

/// Returns the last `-`-delimited component of a provider name for compact display.
pub fn short_provider(p: &str) -> &str {
    p.rfind('-').map(|i| &p[i + 1..]).unwrap_or(p)
}

/// Header row for the raw event table (pair with `event_row` for each entry).
pub fn event_table_header() -> String {
    format!("{:<20} {:>6}  {:<26}  Summary", "Time", "Event", "Provider")
}

/// One formatted row of the raw event table: time, event ID, short provider, summary.
pub fn event_row(ev: &EventRecord) -> String {
    format!(
        "{:<20} {:>6}  {:<26.26}  {}",
        ev.time_created.format_dt(),
        ev.event_id,
        short_provider(&ev.provider),
        event_summary(ev),
    )
}

/// Short human-readable summary for a raw event row in the event table.
pub fn event_summary(ev: &EventRecord) -> String {
    match ev.event_id {
        12   => "System started".into(),
        13   => "System shutdown initiated".into(),
        19   => ev.get("updateTitle")
            .map(|t| format!("Update installed: {}", t))
            .unwrap_or_else(|| "Windows Update installed".into()),
        41   => format!(
            "Unexpected shutdown — BugCheck={}",
            ev.get("BugcheckCode").unwrap_or("?")
        ),
        109  => "Kernel power button transition".into(),
        1074 => format!(
            "{} by {}",
            ev.get("param5").unwrap_or("action"),
            ev.get("param7").unwrap_or("?")
        ),
        1076 => "Shutdown reason documented".into(),
        7045 => format!(
            "Service/driver installed: {}",
            ev.get("ServiceName").unwrap_or("?")
        ),
        6006 => "Event log stopped cleanly (shutdown)".into(),
        6008 => "Previous shutdown was unexpected".into(),
        6009 => "Startup: Windows version info".into(),
        6013 => ev.get("param1")
            .and_then(|s| s.parse::<i64>().ok())
            .map(|s| format!("System uptime: {}", fmt_secs(s)))
            .unwrap_or_else(|| "System uptime".into()),
        id   => format!("Event {}", id),
    }
}

// ── Explanation / remediation ─────────────────────────────────────────────────

/// Generates plain-English diagnosis and numbered remediation steps for known
/// BSOD stop codes. Returns an empty vec for non-BSOD causes or unknown codes.
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

fn explain_driver_power_failure(
    module: &Option<String>,
    p1:     u64,
    audio:  &[AudioPowerInfo],
    out:    &mut Vec<String>,
) {
    let m     = module.as_deref().unwrap_or("(unknown driver)");
    let m_low = m.to_lowercase();
    let is_audio = m_low.contains("portcls") || m_low.contains("audio")
                || m_low.contains("hdaud");
    let is_usb   = m_low.contains("usbccgp") || m_low.contains("usbhub")
                || m_low.contains("usb");

    out.push(format!(
        "DRIVER_POWER_STATE_FAILURE: {} failed to complete a power state", m));
    out.push("transition in time. Windows was going to sleep, hibernating, or".into());
    out.push("shutting down when the driver stalled and never responded.".into());

    if p1 == 3 {
        out.push(String::new());
        out.push(format!(
            "P1=3: the OS sent an IRP_MN_SET_POWER request to {} but the driver", m));
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
        out.push("     HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\".into());
        out.push("     {4d36e96c-e325-11ce-bfc1-08002be10318}\\<instance>".into());
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

fn explain_win32k_power_watchdog(module: &Option<String>, out: &mut Vec<String>) {
    let m = module.as_deref().unwrap_or("(unknown driver)");
    out.push(
        "WIN32K_POWER_WATCHDOG_TIMEOUT: the display subsystem failed to respond".into());
    out.push(format!(
        "during a power transition. {} timed out waking the GPU from sleep.", m));
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AudioPowerInfo, Cause};

    fn audio(allow_idle_d3: Option<u32>) -> AudioPowerInfo {
        AudioPowerInfo {
            instance: "0000".into(), name: "Test Audio".into(),
            allow_idle_d3, enhanced_pm: None,
        }
    }

    // ── fmt_secs ──────────────────────────────────────────────────────────────

    #[test]
    fn fmt_secs_seconds_range() {
        assert_eq!(fmt_secs(0),  "0s");
        assert_eq!(fmt_secs(30), "30s");
        assert_eq!(fmt_secs(59), "59s");
    }

    #[test]
    fn fmt_secs_minutes_range() {
        assert_eq!(fmt_secs(60),   "1m 00s");
        assert_eq!(fmt_secs(90),   "1m 30s");
        assert_eq!(fmt_secs(3599), "59m 59s");
    }

    #[test]
    fn fmt_secs_hours_range() {
        assert_eq!(fmt_secs(3600), "1h 00m");
        assert_eq!(fmt_secs(3661), "1h 01m");
        assert_eq!(fmt_secs(7200), "2h 00m");
    }

    #[test]
    fn fmt_secs_negative_clamped_to_zero() {
        assert_eq!(fmt_secs(-100), "0s");
    }

    // ── relative_ago ──────────────────────────────────────────────────────────

    #[test]
    fn relative_ago_seconds_range() {
        assert_eq!(relative_ago(0),   "0 seconds ago");
        assert_eq!(relative_ago(119), "119 seconds ago");
    }

    #[test]
    fn relative_ago_minutes_range() {
        assert_eq!(relative_ago(120),  "2 minutes ago");
        assert_eq!(relative_ago(7199), "119 minutes ago");
    }

    #[test]
    fn relative_ago_hours_range() {
        assert_eq!(relative_ago(7200),   "2 hours ago");
        assert_eq!(relative_ago(172_799), "47 hours ago");
    }

    #[test]
    fn relative_ago_days_range() {
        assert_eq!(relative_ago(172_800), "2 days ago");
        assert_eq!(relative_ago(864_000), "10 days ago");
    }

    #[test]
    fn relative_ago_negative_clamped_to_zero() {
        assert_eq!(relative_ago(-100), "0 seconds ago");
    }

    // ── is_audio_power_crash ──────────────────────────────────────────────────

    #[test]
    fn audio_power_crash_true_for_portcls_0x9f() {
        let c = Cause::BlueScreen { stop_code: 0x9F, stop_name: "X", params: [0; 4] };
        assert!(is_audio_power_crash(&c, &Some("portcls".into())));
    }

    #[test]
    fn audio_power_crash_false_for_non_power_stop_code() {
        let c = Cause::BlueScreen { stop_code: 0x50, stop_name: "X", params: [0; 4] };
        assert!(!is_audio_power_crash(&c, &Some("portcls".into())));
    }

    #[test]
    fn audio_power_crash_false_for_non_audio_module() {
        let c = Cause::BlueScreen { stop_code: 0x9F, stop_name: "X", params: [0; 4] };
        assert!(!is_audio_power_crash(&c, &Some("usbccgp".into())));
    }

    #[test]
    fn audio_power_crash_false_for_non_bsod() {
        assert!(!is_audio_power_crash(&Cause::NormalShutdown, &Some("portcls".into())));
    }

    // ── audio_power_status_text ───────────────────────────────────────────────

    #[test]
    fn audio_power_status_text_variants() {
        assert!(audio_power_status_text(Some(0)).contains("safe"));
        assert!(audio_power_status_text(Some(1)).contains("RISKY"));
        assert!(audio_power_status_text(None).contains("not set"));
    }

    // ── event_table_header / event_row ────────────────────────────────────────

    #[test]
    fn event_table_header_has_expected_columns() {
        let h = event_table_header();
        assert!(h.contains("Time") && h.contains("Event") && h.contains("Provider") && h.contains("Summary"));
    }

    #[test]
    fn event_row_contains_provider_and_summary() {
        let ev = EventRecord {
            event_id: 12,
            time_created: crate::timestamp::Timestamp(0),
            provider: "Microsoft-Windows-Kernel-General".into(),
            data: vec![],
        };
        let row = event_row(&ev);
        assert!(row.contains("General"));
        assert!(row.contains("System started"));
    }

    // ── cause_label ───────────────────────────────────────────────────────────

    #[test]
    fn cause_label_all_variants() {
        let bsod = Cause::BlueScreen { stop_code: 0x9F, stop_name: "X", params: [0;4] };
        assert!(cause_label(&bsod).contains("BLUE SCREEN"));
        assert!(cause_label(&Cause::ForcedPowerOff).contains("FORCED"));
        assert!(cause_label(&Cause::UnexpectedShutdown).contains("UNEXPECTED"));
        assert!(cause_label(&Cause::WindowsUpdate {
            process: "x".into(), old_version: None, new_version: None })
            .contains("WINDOWS UPDATE"));
        assert!(cause_label(&Cause::UserAction {
            user: "u".into(), action: "a".into(), comment: "c".into() })
            .contains("USER"));
        assert!(cause_label(&Cause::SystemProcess {
            process: "p".into(), reason: "r".into(), action: "a".into() })
            .contains("SYSTEM"));
        assert!(cause_label(&Cause::NormalShutdown).contains("NORMAL"));
        assert!(cause_label(&Cause::Undetermined).contains("UNDETERMINED"));
    }

    // ── cause_detail ──────────────────────────────────────────────────────────

    #[test]
    fn cause_detail_bsod_contains_hex_and_name() {
        let c = Cause::BlueScreen {
            stop_code: 0x9F, stop_name: "DRIVER_POWER_STATE_FAILURE", params: [0;4] };
        let d = cause_detail(&c);
        assert!(d.contains("0x0000009F"));
        assert!(d.contains("DRIVER_POWER_STATE_FAILURE"));
    }

    #[test]
    fn cause_detail_windows_update_uses_last_path_component() {
        let c = Cause::WindowsUpdate {
            process: r"C:\Windows\TiWorker.exe".into(), old_version: None, new_version: None };
        let d = cause_detail(&c);
        assert!(d.contains("TiWorker.exe"));
        assert!(!d.contains(r"C:\Windows\"));
    }

    #[test]
    fn cause_detail_windows_update_shows_version_change() {
        // A real Win10→Win11 feature upgrade: both report NT 10.0, only the
        // build distinguishes them, so the friendly product names must differ.
        let c = Cause::WindowsUpdate {
            process: r"C:\Windows\TiWorker.exe".into(),
            old_version: Some("10.0.19045".into()),
            new_version: Some("10.0.26100".into()),
        };
        let d = cause_detail(&c);
        assert!(d.contains("Windows 10"));
        assert!(d.contains("Windows 11"));
        assert!(d.contains("19045"));
        assert!(d.contains("26100"));
        assert!(d.contains("→"));
    }

    #[test]
    fn cause_detail_windows_update_same_build_no_arrow_no_upgrade_claim() {
        let c = Cause::WindowsUpdate {
            process: r"C:\Windows\TiWorker.exe".into(),
            old_version: Some("10.0.26200".into()),
            new_version: Some("10.0.26200".into()),
        };
        let d = cause_detail(&c);
        assert!(d.contains("26200"));
        assert!(!d.contains("→"));
        // Must not assert a revision/upgrade the data can't confirm.
        assert!(!d.to_lowercase().contains("revision"));
    }

    #[test]
    fn win_product_maps_build_to_marketing_name() {
        assert!(win_product("10.0.26200").contains("Windows 11"));
        assert!(win_product("10.0.26200").contains("26200"));
        assert!(win_product("10.0.22000").contains("Windows 11"));
        assert!(win_product("10.0.19045").contains("Windows 10"));
        assert!(win_product("10.0.10240").contains("Windows 10"));
        // Pre-Win10 build (Windows 7 SP1 = NT 6.1.7601): fall back to raw NT version.
        assert_eq!(win_product("6.1.7601"), "Windows 6.1.7601");
        // Unparseable build: fall back to raw string.
        assert_eq!(win_product("garbage"), "Windows garbage");
    }

    #[test]
    fn cause_detail_user_action() {
        let c = Cause::UserAction {
            user: "angch".into(), action: "Restart".into(), comment: "".into() };
        let d = cause_detail(&c);
        assert!(d.contains("angch") && d.contains("Restart"));
    }

    #[test]
    fn cause_detail_system_process() {
        let c = Cause::SystemProcess {
            process: "svchost.exe".into(), reason: "r".into(), action: "Shutdown".into() };
        let d = cause_detail(&c);
        assert!(d.contains("svchost.exe") && d.contains("Shutdown"));
    }

    // ── generate_explanation ──────────────────────────────────────────────────

    #[test]
    fn explanation_non_bsod_returns_empty() {
        assert!(generate_explanation(&Cause::NormalShutdown,   &None, &[]).is_empty());
        assert!(generate_explanation(&Cause::UnexpectedShutdown, &None, &[]).is_empty());
        assert!(generate_explanation(&Cause::Undetermined,     &None, &[]).is_empty());
    }

    #[test]
    fn explanation_unknown_stop_code_returns_empty() {
        let cause = Cause::BlueScreen {
            stop_code: 0x50, stop_name: "PAGE_FAULT", params: [0;4] };
        assert!(generate_explanation(&cause, &None, &[]).is_empty());
    }

    #[test]
    fn explanation_0x9f_audio_portcls_suggests_allow_idle_d3() {
        let cause = Cause::BlueScreen {
            stop_code: 0x9F, stop_name: "DRIVER_POWER_STATE_FAILURE", params: [3,0,0,0] };
        let exp = generate_explanation(&cause, &Some("portcls".into()), &[]);
        assert!(!exp.is_empty());
        assert!(exp.iter().any(|l| l.contains("AllowIdleIrpInD3")));
    }

    #[test]
    fn explanation_0x9f_audio_all_safe_says_ok() {
        let cause = Cause::BlueScreen {
            stop_code: 0x9F, stop_name: "DRIVER_POWER_STATE_FAILURE", params: [3,0,0,0] };
        let devs  = vec![audio(Some(0)), audio(Some(0))];
        let exp   = generate_explanation(&cause, &Some("portcls".into()), &devs);
        assert!(exp.iter().any(|l| l.contains("[OK]")));
    }

    #[test]
    fn explanation_0x9f_audio_partial_safe_mentions_unset() {
        let cause = Cause::BlueScreen {
            stop_code: 0x9F, stop_name: "DRIVER_POWER_STATE_FAILURE", params: [3,0,0,0] };
        let devs  = vec![audio(Some(0)), audio(None)];
        let exp   = generate_explanation(&cause, &Some("portcls".into()), &devs);
        assert!(exp.iter().any(|l| l.contains("still have")));
    }

    #[test]
    fn explanation_0x9f_usb_module_mentions_usb() {
        let cause = Cause::BlueScreen {
            stop_code: 0x9F, stop_name: "DRIVER_POWER_STATE_FAILURE", params: [3,0,0,0] };
        let exp   = generate_explanation(&cause, &Some("usbccgp".into()), &[]);
        assert!(exp.iter().any(|l| l.to_lowercase().contains("usb")));
        assert!(!exp.iter().any(|l| l.contains("AllowIdleIrpInD3")));
    }

    #[test]
    fn explanation_0x9f_other_driver_generic_advice() {
        let cause = Cause::BlueScreen {
            stop_code: 0x9F, stop_name: "DRIVER_POWER_STATE_FAILURE", params: [3,0,0,0] };
        let exp   = generate_explanation(&cause, &Some("somedrv".into()), &[]);
        assert!(exp.iter().any(|l| l.contains("somedrv")));
    }

    #[test]
    fn explanation_0x19c_mentions_gpu_or_display() {
        let cause = Cause::BlueScreen {
            stop_code: 0x19C, stop_name: "WIN32K_POWER_WATCHDOG_TIMEOUT", params: [0;4] };
        let exp   = generate_explanation(&cause, &Some("dxgkrnl".into()), &[]);
        assert!(!exp.is_empty());
        assert!(exp.iter().any(|l|
            l.contains("GPU") || l.to_lowercase().contains("display")
            || l.contains("watchdog")));
    }

    #[test]
    fn explanation_0xfe_is_usb_bugcheck() {
        let cause = Cause::BlueScreen {
            stop_code: 0xFE, stop_name: "BUGCODE_USB_DRIVER", params: [0;4] };
        let exp = generate_explanation(&cause, &None, &[]);
        assert!(exp.iter().any(|l| l.to_lowercase().contains("usb")));
    }

    #[test]
    fn explanation_0x144_is_usb3_bugcheck() {
        let cause = Cause::BlueScreen {
            stop_code: 0x144, stop_name: "BUGCODE_USB3_DRIVER", params: [0;4] };
        let exp = generate_explanation(&cause, &None, &[]);
        assert!(exp.iter().any(|l| l.to_lowercase().contains("usb")));
    }
}
