// SPDX-License-Identifier: MIT OR Apache-2.0
//! (Re)loading analysis data: the live Event Log fetch (also used at startup)
//! and offline replay of a captured event-log XML — the GUI equivalent of the
//! CLI's `--from-file`. Both end by repopulating the Boot History panel in
//! place, so neither needs to recreate any window.
#![allow(unsafe_op_in_unsafe_fn)]

use whyreboot::analysis::{extract_boot_cycles, wer_from_event};
use whyreboot::events::{fetch_system_events, fetch_wer_events, list_minidumps};
use whyreboot::registry::check_audio_power_settings;
use whyreboot::xml::parse_event_log;

use crate::panels::refresh_boot_history;
use crate::state;

/// Re-scans the live Windows Event Log / registry, exactly like a fresh launch.
/// Used both at startup and by the "Refresh" menu command.
pub unsafe fn reload_live() {
    let sys = fetch_system_events();
    let wer = fetch_wer_events();
    let dumps = list_minidumps();
    let audio = check_audio_power_settings();
    state::set_cycles(extract_boot_cycles(&sys, &wer, &dumps, 0));
    state::set_audio(audio);
    refresh_boot_history();
}

/// Replays a captured event-log XML file (`wevtutil qe System /f:xml`, or
/// `Get-WinEvent | %{ $_.ToXml() }`) through the same portable analysis the
/// live path uses. Mirrors the CLI's `--from-file`: minidumps and registry
/// audio-power state are machine-local, so they're empty for a replay.
///
/// Returns `Err` with a user-facing message on read failure or an empty/
/// unparseable capture, matching the CLI's `--from-file` diagnostics.
pub unsafe fn reload_from_file(path: &std::path::Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Couldn't read {}:\n{e}", path.display()))?;
    let events = parse_event_log(&text);
    if events.is_empty() {
        return Err(format!(
            "No <Event> records parsed from {}.",
            path.display()
        ));
    }
    let wer = events.iter().filter_map(wer_from_event).collect::<Vec<_>>();
    state::set_cycles(extract_boot_cycles(&events, &wer, &[], 0));
    state::set_audio(Vec::new());
    refresh_boot_history();
    Ok(())
}
