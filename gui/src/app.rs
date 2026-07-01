// SPDX-License-Identifier: MIT OR Apache-2.0
//! Main window: creation, message dispatch, layout on resize, and the message loop.
#![allow(unsafe_op_in_unsafe_fn)]

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::WindowsAndMessaging::*;

use whyreboot::format::relative_ago;
use whyreboot::timestamp::Timestamp;

use crate::panels::{build_about, build_boot_history, panel_proc, switch_tab, update_detail};
use crate::state::{CYCLES, DETAIL_H, LV_H, LV_W, PAD, PANELS, TAB_H, WIN_H, WIN_W};
use crate::win32::{apply_font, as_hwnd, hinstance, hmenu_id, wstr, NMLVGETINFOTIPW, LVN_GETINFOTIPW_CODE};

// ── Main window procedure ─────────────────────────────────────────────────────

pub unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            let hi   = hinstance(GetModuleHandleW(PCWSTR(std::ptr::null())).unwrap_or_default());
            let font = GetStockObject(DEFAULT_GUI_FONT);

            let tab = CreateWindowExW(
                WINDOW_EX_STYLE(0), WC_TABCONTROLW, w!(""),
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                0, 0, WIN_W, WIN_H,
                Some(hwnd), hmenu_id(1000), Some(hi), None,
            ).unwrap_or(HWND(std::ptr::null_mut()));
            apply_font(tab, font);
            TAB_H.with(|t| t.set(tab.0 as isize));

            for (i, name) in ["Boot History", "About"].iter().enumerate() {
                let mut txt = wstr(name);
                let mut ti = TCITEMW {
                    mask:    TCIF_TEXT,
                    pszText: PWSTR(txt.as_mut_ptr()),
                    ..Default::default()
                };
                SendMessageW(tab, TCM_INSERTITEMW,
                    Some(WPARAM(i)), Some(LPARAM(&mut ti as *mut _ as isize)));
            }

            let mut rc = RECT { left: 2, top: 2, right: WIN_W - 2, bottom: WIN_H - 2 };
            SendMessageW(tab, TCM_ADJUSTRECT,
                Some(WPARAM(0)), Some(LPARAM(&mut rc as *mut _ as isize)));

            let p0 = build_boot_history(hwnd, rc, hi, font);
            let p1 = build_about(hwnd, rc, hi, font);
            PANELS.with(|p| p.set([p0.0 as isize, p1.0 as isize]));

            SetWindowPos(tab, Some(HWND_TOP), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE).ok();
            switch_tab(0);
            LRESULT(0)
        }
        WM_NOTIFY => {
            if lp.0 == 0 {
                return DefWindowProcW(hwnd, msg, wp, lp);
            }
            let hdr  = &*(lp.0 as *const NMHDR);
            let tab  = TAB_H.with(|t| as_hwnd(t.get()));
            let lv   = LV_H.with(|t| as_hwnd(t.get()));

            if hdr.hwndFrom == tab && hdr.code == TCN_SELCHANGE {
                let sel = SendMessageW(tab, TCM_GETCURSEL,
                    Some(WPARAM(0)), Some(LPARAM(0))).0 as usize;
                switch_tab(sel);
            } else if hdr.hwndFrom == lv && hdr.code == LVN_ITEMCHANGED {
                let nmlv = &*(lp.0 as *const NMLISTVIEW);
                // Only act when a row becomes selected (not deselected)
                if nmlv.uChanged.0 & LVIF_STATE.0 != 0
                    && nmlv.uNewState & LVIS_SELECTED.0 != 0
                {
                    update_detail(nmlv.iItem as usize);
                }
            } else if hdr.hwndFrom == lv && hdr.code == LVN_GETINFOTIPW_CODE {
                let tip = &mut *(lp.0 as *mut NMLVGETINFOTIPW);
                if tip.item >= 0 && !tip.psz_text.0.is_null() && tip.cch_max > 0 {
                    let cycles = CYCLES.get().map(|v| v.as_slice()).unwrap_or(&[]);
                    if let Some(t) = cycles.get(tip.item as usize).and_then(|c| c.boot_time) {
                        let ago = relative_ago(Timestamp::now().secs_since(t));
                        let encoded: Vec<u16> = ago.encode_utf16().collect();
                        let max = (tip.cch_max as usize).saturating_sub(1);
                        let len = encoded.len().min(max);
                        for (i, &ch) in encoded[..len].iter().enumerate() {
                            *tip.psz_text.0.add(i) = ch;
                        }
                        *tip.psz_text.0.add(len) = 0;
                    }
                }
            }
            LRESULT(0)
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let hdc = HDC(wp.0 as *mut _);
            SetBkColor(hdc, COLORREF(GetSysColor(COLOR_3DFACE)));
            SetTextColor(hdc, COLORREF(GetSysColor(COLOR_WINDOWTEXT)));
            LRESULT(GetSysColorBrush(COLOR_3DFACE).0 as isize)
        }
        WM_SIZE => {
            // Skip minimized — nothing to lay out.
            if wp.0 == 1 { return LRESULT(0); }
            let cw = (lp.0 & 0xFFFF) as i32;
            let ch = (lp.0 >> 16 & 0xFFFF) as i32;
            let tab = TAB_H.with(|t| as_hwnd(t.get()));

            // Stretch tab control to fill the client area.
            SetWindowPos(tab, None, 0, 0, cw, ch,
                SWP_NOZORDER | SWP_NOACTIVATE).ok();

            // Ask the tab control for the usable inner rect.
            let mut rc = RECT { left: 2, top: 2, right: cw - 2, bottom: ch - 2 };
            SendMessageW(tab, TCM_ADJUSTRECT,
                Some(WPARAM(0)), Some(LPARAM(&mut rc as *mut _ as isize)));
            let pw = rc.right  - rc.left;
            let ph = rc.bottom - rc.top;

            // Resize both panels to the new inner rect.
            let panels = PANELS.with(|p| p.get());
            for &raw in &panels {
                SetWindowPos(as_hwnd(raw), None, rc.left, rc.top, pw, ph,
                    SWP_NOZORDER | SWP_NOACTIVATE).ok();
            }

            // Resize ListView (left, fixed width) and EDIT (right, fills rest).
            let lv     = LV_H.with(|t| as_hwnd(t.get()));
            let detail = DETAIL_H.with(|t| as_hwnd(t.get()));
            SetWindowPos(lv, None, PAD, PAD, LV_W, ph - PAD * 2,
                SWP_NOZORDER | SWP_NOACTIVATE).ok();
            let ex = LV_W + PAD * 2;
            SetWindowPos(detail, None, ex, PAD, pw - ex - PAD, ph - PAD * 2,
                SWP_NOZORDER | SWP_NOACTIVATE).ok();

            // Resize the About panel's static text child.
            if let Ok(child) = GetWindow(as_hwnd(panels[1]), GW_CHILD) {
                SetWindowPos(child, None, 16, 16, pw - 32, ph - 32,
                    SWP_NOZORDER | SWP_NOACTIVATE).ok();
            }

            LRESULT(0)
        }
        WM_DESTROY => { PostQuitMessage(0); LRESULT(0) }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

// ── Message loop ──────────────────────────────────────────────────────────────

pub unsafe fn run_ui() {
    let hi = hinstance(GetModuleHandleW(PCWSTR(std::ptr::null())).unwrap_or_default());

    let icc = INITCOMMONCONTROLSEX {
        dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC:  ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES,
    };
    let _ = InitCommonControlsEx(&icc);

    let panel_wc = WNDCLASSW {
        lpfnWndProc:   Some(panel_proc),
        hInstance:     hi,
        hbrBackground: GetSysColorBrush(COLOR_3DFACE),
        lpszClassName: w!("WRPanel"),
        ..Default::default()
    };
    RegisterClassW(&panel_wc);

    let wc = WNDCLASSW {
        style:         CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc:   Some(wnd_proc),
        hInstance:     hi,
        hbrBackground: GetSysColorBrush(COLOR_3DFACE),
        hCursor:       LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
        lpszClassName: w!("WhyReboot"),
        ..Default::default()
    };
    RegisterClassW(&wc);

    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_SIZEBOX | WS_MAXIMIZEBOX;
    let mut rc = RECT { left: 0, top: 0, right: WIN_W, bottom: WIN_H };
    AdjustWindowRect(&mut rc, style, false).ok();

    let main = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        w!("WhyReboot"),
        w!("whyreboot \u{2014} Boot Cause Analyzer"),
        style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        None, None, Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()));

    let _ = ShowWindow(main, SW_SHOWNORMAL);
    let _ = UpdateWindow(main);

    let mut msg = MSG::default();
    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
