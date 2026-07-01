// SPDX-License-Identifier: MIT OR Apache-2.0
//! Small Win32 handle helpers, plus glue for APIs not yet in the `windows` crate.
#![allow(unsafe_op_in_unsafe_fn)]

use windows::core::PWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::HGDIOBJ;
use windows::Win32::UI::Controls::NMHDR;
use windows::Win32::UI::WindowsAndMessaging::{HMENU, SendMessageW, WM_SETFONT};

// ── Win32 constants not yet in windows 0.62 ───────────────────────────────────

// LVN_FIRST - 58 (Unicode variant)
pub const LVN_GETINFOTIPW_CODE: u32 = 0xFFFF_FF62;

// Per-item tooltip data sent with LVN_GETINFOTIPW
#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
pub struct NMLVGETINFOTIPW {
    pub hdr:      NMHDR,
    pub dw_flags: u32,
    pub psz_text: PWSTR,
    pub cch_max:  i32,
    pub item:     i32,
    pub sub_item: i32,
    pub l_param:  LPARAM,
}

// ── Handle helpers ────────────────────────────────────────────────────────────

pub fn wstr(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }

pub fn hinstance(m: HMODULE) -> HINSTANCE { HINSTANCE(m.0) }

pub fn hmenu_id(id: usize) -> Option<HMENU> {
    Some(HMENU(id as *mut std::ffi::c_void))
}

pub fn as_hwnd(v: isize) -> HWND { HWND(v as *mut std::ffi::c_void) }

pub unsafe fn apply_font(hwnd: HWND, font: HGDIOBJ) {
    SendMessageW(hwnd, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
}
