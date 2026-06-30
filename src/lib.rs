// SPDX-License-Identifier: MIT OR Apache-2.0
//! Core library for whyreboot — types, event fetching, analysis, and registry helpers.
//! The CLI binary (`src/main.rs`) and the GUI crate (`gui/`) both depend on this.
pub mod analysis;
pub mod events;
pub mod registry;
pub mod types;
pub mod xml;
