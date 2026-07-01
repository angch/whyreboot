// SPDX-License-Identifier: MIT OR Apache-2.0
//! Process-wide analysis results and window-handle state shared across modules.

use std::cell::Cell;
use std::sync::OnceLock;

use whyreboot::types::{AudioPowerInfo, BootCycle};

// ── Layout ────────────────────────────────────────────────────────────────────

pub const WIN_W: i32 = 860;
pub const WIN_H: i32 = 500;
pub const LV_W:  i32 = 252;   // left-pane ListView width
pub const PAD:   i32 = 4;     // gap between panes / edge margins

// ── Analysis data ─────────────────────────────────────────────────────────────

pub static CYCLES: OnceLock<Vec<BootCycle>>      = OnceLock::new();
pub static AUDIO:  OnceLock<Vec<AudioPowerInfo>> = OnceLock::new();

// ── Window handles ────────────────────────────────────────────────────────────
// Raw HWNDs stored as `isize` since HWND isn't Send/Sync; these are only ever
// touched from the single GUI thread that owns the message loop.

thread_local! {
    pub static TAB_H:    Cell<isize>      = const { Cell::new(0) };
    pub static LV_H:     Cell<isize>      = const { Cell::new(0) };
    pub static DETAIL_H: Cell<isize>      = const { Cell::new(0) };
    pub static PANELS:   Cell<[isize; 2]> = const { Cell::new([0; 2]) };
}
