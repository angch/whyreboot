// SPDX-License-Identifier: MIT OR Apache-2.0
//! Small Win32 handle helpers, plus glue for APIs not yet in the `windows` crate.
#![allow(unsafe_op_in_unsafe_fn)]

use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::HGDIOBJ;
use windows::Win32::UI::Controls::Dialogs::*;
use windows::Win32::UI::Controls::NMHDR;
use windows::Win32::UI::WindowsAndMessaging::{HMENU, SendMessageW, WM_SETFONT};
use windows::core::{PCWSTR, PWSTR, w};

// ── Win32 constants not yet in windows 0.62 ───────────────────────────────────

// LVN_FIRST - 58 (Unicode variant)
pub const LVN_GETINFOTIPW_CODE: u32 = 0xFFFF_FF62;

// Per-item tooltip data sent with LVN_GETINFOTIPW
#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
pub struct NMLVGETINFOTIPW {
    pub hdr: NMHDR,
    pub dw_flags: u32,
    pub psz_text: PWSTR,
    pub cch_max: i32,
    pub item: i32,
    pub sub_item: i32,
    pub l_param: LPARAM,
}

// ── Handle helpers ────────────────────────────────────────────────────────────

pub fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub fn hinstance(m: HMODULE) -> HINSTANCE {
    HINSTANCE(m.0)
}

pub fn hmenu_id(id: usize) -> Option<HMENU> {
    Some(HMENU(id as *mut std::ffi::c_void))
}

pub fn as_hwnd(v: isize) -> HWND {
    HWND(v as *mut std::ffi::c_void)
}

pub unsafe fn apply_font(hwnd: HWND, font: HGDIOBJ) {
    SendMessageW(
        hwnd,
        WM_SETFONT,
        Some(WPARAM(font.0 as usize)),
        Some(LPARAM(1)),
    );
}

/// Packs an 8-bit-per-channel color into a `COLORREF`'s `0x00BBGGRR` layout.
pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

/// Shows the standard "Open" common dialog filtered to event-log capture
/// files, mirroring the CLI's `--from-file`. Returns `None` if the user
/// cancelled.
pub unsafe fn open_capture_dialog(owner: HWND) -> Option<std::path::PathBuf> {
    let mut buf = [0u16; 4096];
    let filter = wstr("Event Log Capture (*.xml;*.txt)\0*.xml;*.txt\0All Files (*.*)\0*.*\0\0");
    let mut ofn = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner,
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(buf.as_mut_ptr()),
        nMaxFile: buf.len() as u32,
        lpstrTitle: w!("Open Event Log Capture"),
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER,
        ..Default::default()
    };
    if GetOpenFileNameW(&mut ofn).as_bool() {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(std::path::PathBuf::from(String::from_utf16_lossy(
            &buf[..len],
        )))
    } else {
        None
    }
}
