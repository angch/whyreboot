// SPDX-License-Identifier: MIT OR Apache-2.0
//! Core library for whyreboot — a cross-platform system-issue diagnostic tool.
//!
//! Originally a Windows "why did it reboot" tool, now generalized to detect
//! system issues over an arbitrary time window on both Windows and Linux — some
//! of which (e.g. OOM kills) never end in a reboot at all.
//!
//! ## Layout
//! Portable core (compiles and is unit-tested on every platform):
//! - [`types`]   — shared data model, including the platform-agnostic [`types::Finding`]
//! - [`timestamp`] — Unix-epoch timestamp with portable UTC / platform local rendering
//! - [`timewindow`] — parse "1 hour ago" / "today" / "2h" into a concrete window
//! - [`oom`]     — pure log-line → [`types::Finding`] OOM detectors
//! - [`analysis`], [`format`], [`xml`] — Windows boot-cycle analysis logic
//!
//! Platform backends (gated by `cfg`):
//! - [`events`], [`registry`] — Windows Event Log & registry (`cfg(windows)`)
//! - [`linux`] — journald log source via `journalctl` (`cfg(target_os = "linux")`)
//!
//! The CLI binary (`src/main.rs`) and the GUI crate (`gui/`) both depend on this.

pub mod analysis;
pub mod detect;
pub mod format;
pub mod oom;
pub mod timestamp;
pub mod timewindow;
pub mod types;
pub mod xml;

// Windows Event Log & registry backend.
#[cfg(windows)]
pub mod events;
#[cfg(windows)]
pub mod registry;

// Linux journald backend.
#[cfg(target_os = "linux")]
pub mod linux;
