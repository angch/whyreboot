// SPDX-License-Identifier: MIT OR Apache-2.0
#![windows_subsystem = "windows"]

mod app;
mod detail;
mod panels;
mod state;
mod win32;

use whyreboot::analysis::extract_boot_cycles;
use whyreboot::events::{fetch_system_events, fetch_wer_events, list_minidumps};
use whyreboot::registry::check_audio_power_settings;

fn main() {
    let sys   = fetch_system_events();
    let wer   = fetch_wer_events();
    let dumps = list_minidumps();
    let audio = check_audio_power_settings();
    state::CYCLES.set(extract_boot_cycles(&sys, &wer, &dumps, 0)).ok();
    state::AUDIO.set(audio).ok();

    unsafe { app::run_ui() };
}
