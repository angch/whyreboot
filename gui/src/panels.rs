// SPDX-License-Identifier: MIT OR Apache-2.0
//! Panel window procedure and the two tab panels: Boot History (ListView + detail
//! EDIT) and About.
#![allow(unsafe_op_in_unsafe_fn)]

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::WindowsAndMessaging::*;

use whyreboot::types::Cause;

use crate::detail::format_cycle_detail;
use crate::state::{AUDIO, CYCLES, DETAIL_H, LV_H, LV_W, PAD, PANELS};
use crate::win32::{apply_font, as_hwnd, hmenu_id, wstr};

// ── Panel window procedure ────────────────────────────────────────────────────

pub unsafe extern "system" fn panel_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_ERASEBKGND => {
            let hdc = HDC(wp.0 as *mut _);
            let mut rc = RECT::default();
            let _ = GetClientRect(hwnd, &mut rc);
            FillRect(hdc, &rc, GetSysColorBrush(COLOR_3DFACE));
            LRESULT(1)
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let hdc = HDC(wp.0 as *mut _);
            SetBkColor(hdc, COLORREF(GetSysColor(COLOR_3DFACE)));
            SetTextColor(hdc, COLORREF(GetSysColor(COLOR_WINDOWTEXT)));
            LRESULT(GetSysColorBrush(COLOR_3DFACE).0 as isize)
        }
        WM_CTLCOLOREDIT => {
            let hdc = HDC(wp.0 as *mut _);
            SetBkColor(hdc, COLORREF(GetSysColor(COLOR_WINDOW)));
            SetTextColor(hdc, COLORREF(GetSysColor(COLOR_WINDOWTEXT)));
            LRESULT(GetSysColorBrush(COLOR_WINDOW).0 as isize)
        }
        // Forward child notifications to the main window so wnd_proc sees them.
        WM_NOTIFY => {
            if let Ok(parent) = GetParent(hwnd) {
                return SendMessageW(parent, WM_NOTIFY, Some(wp), Some(lp));
            }
            DefWindowProcW(hwnd, msg, wp, lp)
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

// ── Update detail pane from cycle index ───────────────────────────────────────

pub unsafe fn update_detail(idx: usize) {
    let detail = DETAIL_H.with(|t| as_hwnd(t.get()));
    if detail.0.is_null() { return; }
    let cycles = CYCLES.get().map(|v| v.as_slice()).unwrap_or(&[]);
    let audio  = AUDIO.get().map(|v| v.as_slice()).unwrap_or(&[]);
    let text = cycles.get(idx)
        .map(|c| format_cycle_detail(c, audio))
        .unwrap_or_default();
    let txt = wstr(&text);
    let _ = SetWindowTextW(detail, PCWSTR(txt.as_ptr()));
}

// ── Build boot-history panel (two-pane) ──────────────────────────────────────

pub unsafe fn build_boot_history(parent: HWND, rc: RECT, hi: HINSTANCE, font: HGDIOBJ) -> HWND {
    let pw = rc.right  - rc.left;
    let ph = rc.bottom - rc.top;

    let panel = CreateWindowExW(
        WINDOW_EX_STYLE(0), w!("WRPanel"), w!(""),
        WS_CHILD | WS_VISIBLE,
        rc.left, rc.top, pw, ph,
        Some(parent), None, Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()));

    // ── Left: ListView ────────────────────────────────────────────────────────
    let lv = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_LISTVIEWW, w!(""),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL
            | WINDOW_STYLE(LVS_REPORT | LVS_SINGLESEL
                         | LVS_NOSORTHEADER | LVS_SHOWSELALWAYS),
        PAD, PAD, LV_W, ph - PAD * 2,
        Some(panel), hmenu_id(300), Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()));
    apply_font(lv, font);

    // Full-row select + info-tip tooltips
    let ex_style = LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP;
    SendMessageW(lv, LVM_SETEXTENDEDLISTVIEWSTYLE,
        Some(WPARAM(ex_style as usize)),
        Some(LPARAM(ex_style as isize)));

    LV_H.with(|t| t.set(lv.0 as isize));

    let col_defs: &[(&str, i32)] = &[
        ("#",           26),
        ("Date / Time", 118),
        ("Cause",       100),
    ];
    for (i, (name, cx)) in col_defs.iter().enumerate() {
        let mut txt = wstr(name);
        let mut col = LVCOLUMNW {
            mask:     LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM,
            cx:       *cx,
            iSubItem: i as i32,
            pszText:  PWSTR(txt.as_mut_ptr()),
            ..Default::default()
        };
        SendMessageW(lv, LVM_INSERTCOLUMNW,
            Some(WPARAM(i)), Some(LPARAM(&mut col as *mut _ as isize)));
    }

    let cycles = CYCLES.get().map(|v| v.as_slice()).unwrap_or(&[]);
    for (row, c) in cycles.iter().enumerate() {
        let mut num_w = wstr(&format!("{}", c.index + 1));
        let date_str = c.boot_time
            .map(|t| t.format_dt())
            .unwrap_or_else(|| "?".into());
        let mut date_w = wstr(&date_str);
        let cause_str = match &c.cause {
            Cause::BlueScreen { .. }    => "BSOD",
            Cause::ForcedPowerOff       => "Forced off",
            Cause::UnexpectedShutdown   => "Unexpected",
            Cause::WindowsUpdate { .. } => "Update",
            Cause::UserAction { .. }    => "User",
            Cause::SystemProcess { .. } => "System",
            Cause::NormalShutdown       => "Normal",
            Cause::Undetermined         => "?",
        };
        let mut cause_w = wstr(cause_str);

        let mut item = LVITEMW {
            mask:     LVIF_TEXT,
            iItem:    row as i32,
            iSubItem: 0,
            pszText:  PWSTR(num_w.as_mut_ptr()),
            ..Default::default()
        };
        SendMessageW(lv, LVM_INSERTITEMW,
            Some(WPARAM(0)), Some(LPARAM(&mut item as *mut _ as isize)));

        for (col, txt) in [(1, &mut date_w), (2, &mut cause_w)] {
            item.iSubItem = col;
            item.pszText  = PWSTR(txt.as_mut_ptr());
            SendMessageW(lv, LVM_SETITEMW,
                Some(WPARAM(0)), Some(LPARAM(&mut item as *mut _ as isize)));
        }
    }

    // ── Right: detail EDIT ────────────────────────────────────────────────────
    let ex = LV_W + PAD * 2;
    let ew = pw - ex - PAD;
    let detail = CreateWindowExW(
        WS_EX_CLIENTEDGE, w!("EDIT"), w!(""),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL
            | WINDOW_STYLE(ES_MULTILINE as u32 | ES_READONLY as u32 | ES_AUTOVSCROLL as u32),
        ex, PAD, ew, ph - PAD * 2,
        Some(panel), hmenu_id(301), Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()));
    apply_font(detail, font);
    DETAIL_H.with(|t| t.set(detail.0 as isize));

    // Select first row and populate detail
    if !cycles.is_empty() {
        let mut state = LVITEMW {
            stateMask: LVIS_SELECTED,
            state:     LVIS_SELECTED,
            ..Default::default()
        };
        SendMessageW(lv, LVM_SETITEMSTATE,
            Some(WPARAM(0)), Some(LPARAM(&mut state as *mut _ as isize)));
        update_detail(0);
    } else {
        let empty = wstr("No boot cycles found.\r\nTry running as Administrator.");
        let _ = SetWindowTextW(detail, PCWSTR(empty.as_ptr()));
    }

    panel
}

// ── Build about panel ─────────────────────────────────────────────────────────

pub unsafe fn build_about(parent: HWND, rc: RECT, hi: HINSTANCE, font: HGDIOBJ) -> HWND {
    let pw = rc.right  - rc.left;
    let ph = rc.bottom - rc.top;

    let panel = CreateWindowExW(
        WINDOW_EX_STYLE(0), w!("WRPanel"), w!(""),
        WS_CHILD,
        rc.left, rc.top, pw, ph,
        Some(parent), None, Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()));

    let about = wstr(concat!(
        "whyreboot  v0.1.0\r\n",
        "Windows boot cause analyzer\r\n\r\n",
        "Reads the Windows Event Log (System channel) and Windows Error\r\n",
        "Reporting to diagnose why the machine last shut down or crashed.\r\n\r\n",
        "Data sources:\r\n",
        "  \u{2022} System Event Log  \u{2014}  Event IDs 12, 13, 41, 1074, 6006, 6008\r\n",
        "  \u{2022} WER Event 1001    \u{2014}  faulting driver from Bucket field\r\n",
        "  \u{2022} C:\\Windows\\Minidump  \u{2014}  crash dump files (needs admin)\r\n",
        "  \u{2022} Registry audio class  \u{2014}  AllowIdleIrpInD3 power settings\r\n\r\n",
        "Licensed under MIT OR Apache-2.0\r\n",
        "https://github.com/angch/whyreboot",
    ));
    let hw = CreateWindowExW(
        WINDOW_EX_STYLE(0), w!("STATIC"),
        PCWSTR(about.as_ptr()),
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(0),
        16, 16, pw - 32, ph - 32,
        Some(panel), hmenu_id(400), Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()));
    apply_font(hw, font);

    panel
}

// ── Tab switching ─────────────────────────────────────────────────────────────

pub unsafe fn switch_tab(idx: usize) {
    let panels = PANELS.with(|p| p.get());
    for (i, &raw) in panels.iter().enumerate() {
        let _ = ShowWindow(as_hwnd(raw), if i == idx { SW_SHOW } else { SW_HIDE });
    }
}
