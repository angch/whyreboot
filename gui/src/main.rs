// SPDX-License-Identifier: MIT OR Apache-2.0
#![windows_subsystem = "windows"]

mod app;
mod detail;
mod fetch;
mod panels;
mod state;
mod win32;

fn main() {
    // The window doesn't exist yet, so this just seeds `state`; `run_ui`
    // populates the ListView from it once the panel is built.
    unsafe { fetch::reload_live() };
    unsafe { app::run_ui() };
}
