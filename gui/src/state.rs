// SPDX-License-Identifier: MIT OR Apache-2.0
//! Process-wide analysis results and window-handle state shared across modules.

use std::cell::{Cell, RefCell};

use whyreboot::types::{AudioPowerInfo, BootCycle};

// ── Layout ────────────────────────────────────────────────────────────────────

pub const WIN_W: i32 = 860;
pub const WIN_H: i32 = 500;
pub const LV_W: i32 = 252; // left-pane ListView width
pub const PAD: i32 = 4; // gap between panes / edge margins

// ── Analysis data ─────────────────────────────────────────────────────────────
// `RefCell`, not `OnceLock`: unlike the original one-shot startup fetch, "Refresh"
// and "Open Capture…" both need to replace this data after the window is already
// showing. The whole GUI runs on a single thread (the message-loop thread), so a
// plain `RefCell` is enough — no locking needed, same as the `Cell`s below.
thread_local! {
    static CYCLES: RefCell<Vec<BootCycle>> = const { RefCell::new(Vec::new()) };
    static AUDIO: RefCell<Vec<AudioPowerInfo>> = const { RefCell::new(Vec::new()) };
}

/// Replaces the current boot-cycle set (live fetch or a replayed capture).
pub fn set_cycles(v: Vec<BootCycle>) {
    CYCLES.with(|c| *c.borrow_mut() = v);
}

/// Replaces the current audio power-setting snapshot. Empty for a replayed
/// capture — registry state is machine-local, not part of the capture file.
pub fn set_audio(v: Vec<AudioPowerInfo>) {
    AUDIO.with(|c| *c.borrow_mut() = v);
}

/// Runs `f` with a borrow of the current cycles. Kept as a callback (rather than
/// returning a guard) so callers can't accidentally hold the borrow across a
/// `set_cycles` call.
pub fn with_cycles<R>(f: impl FnOnce(&[BootCycle]) -> R) -> R {
    CYCLES.with(|c| f(&c.borrow()))
}

/// Runs `f` with a borrow of the current audio power settings.
pub fn with_audio<R>(f: impl FnOnce(&[AudioPowerInfo]) -> R) -> R {
    AUDIO.with(|c| f(&c.borrow()))
}

// ── Window handles ────────────────────────────────────────────────────────────
// Raw HWNDs stored as `isize` since HWND isn't Send/Sync; these are only ever
// touched from the single GUI thread that owns the message loop.

thread_local! {
    pub static PANEL_H:  Cell<isize>      = const { Cell::new(0) };
    pub static LV_H:     Cell<isize>      = const { Cell::new(0) };
    pub static DETAIL_H: Cell<isize>      = const { Cell::new(0) };
}
