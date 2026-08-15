// SPDX-License-Identifier: MIT OR Apache-2.0
//! Main window: creation, message dispatch, layout on resize, and the message loop.
#![allow(unsafe_op_in_unsafe_fn)]

use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::Input::KeyboardAndMouse::VK_F5;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{PCWSTR, w};

use whyreboot::format::{CauseSeverity, cause_severity, relative_ago};
use whyreboot::timestamp::Timestamp;

use crate::fetch;
use crate::panels::{ABOUT_TEXT, build_boot_history, panel_proc, update_detail};
use crate::state::{self, DETAIL_H, LV_H, LV_W, PAD, PANEL_H, WIN_H, WIN_W};
use crate::win32::{
    LVN_GETINFOTIPW_CODE, NMLVGETINFOTIPW, as_hwnd, hinstance, open_capture_dialog, rgb, wstr,
};

// ── Menu command IDs ──────────────────────────────────────────────────────────

pub const ID_REFRESH: usize = 1001;
pub const ID_OPEN_CAPTURE: usize = 1002;
pub const ID_ABOUT: usize = 1003;
pub const ID_EXIT: usize = 1004;

// ── Main window procedure ─────────────────────────────────────────────────────

pub unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            let hi = hinstance(GetModuleHandleW(PCWSTR(std::ptr::null())).unwrap_or_default());
            let font = GetStockObject(DEFAULT_GUI_FONT);

            build_menu(hwnd);

            let mut client = RECT::default();
            let _ = GetClientRect(hwnd, &mut client);
            let rc = panel_rect(client.right, client.bottom);
            let panel = build_boot_history(hwnd, rc, hi, font);
            PANEL_H.with(|p| p.set(panel.0 as isize));

            LRESULT(0)
        }
        WM_COMMAND => {
            match wp.0 & 0xFFFF {
                ID_REFRESH => fetch::reload_live(),
                ID_OPEN_CAPTURE => {
                    if let Some(path) = open_capture_dialog(hwnd)
                        && let Err(e) = fetch::reload_from_file(&path)
                    {
                        let msg = wstr(&e);
                        MessageBoxW(
                            Some(hwnd),
                            PCWSTR(msg.as_ptr()),
                            w!("whyreboot"),
                            MB_ICONERROR,
                        );
                    }
                }
                ID_ABOUT => {
                    let msg = wstr(ABOUT_TEXT);
                    MessageBoxW(
                        Some(hwnd),
                        PCWSTR(msg.as_ptr()),
                        w!("About whyreboot"),
                        MB_ICONINFORMATION,
                    );
                }
                ID_EXIT => {
                    let _ = DestroyWindow(hwnd);
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_NOTIFY => {
            if lp.0 == 0 {
                return DefWindowProcW(hwnd, msg, wp, lp);
            }
            let hdr = &*(lp.0 as *const NMHDR);
            let lv = LV_H.with(|t| as_hwnd(t.get()));

            if hdr.hwndFrom == lv && hdr.code == LVN_ITEMCHANGED {
                let nmlv = &*(lp.0 as *const NMLISTVIEW);
                // Only act when a row becomes selected (not deselected)
                if nmlv.uChanged.0 & LVIF_STATE.0 != 0 && nmlv.uNewState & LVIS_SELECTED.0 != 0 {
                    update_detail(nmlv.iItem as usize);
                }
            } else if hdr.hwndFrom == lv && hdr.code == LVN_GETINFOTIPW_CODE {
                let tip = &mut *(lp.0 as *mut NMLVGETINFOTIPW);
                if tip.item >= 0 && !tip.psz_text.0.is_null() && tip.cch_max > 0 {
                    let ago = state::with_cycles(|cycles| {
                        cycles
                            .get(tip.item as usize)
                            .and_then(|c| c.boot_time)
                            .map(|t| relative_ago(Timestamp::now().secs_since(t)))
                    });
                    if let Some(ago) = ago {
                        let encoded: Vec<u16> = ago.encode_utf16().collect();
                        let max = (tip.cch_max as usize).saturating_sub(1);
                        let len = encoded.len().min(max);
                        for (i, &ch) in encoded[..len].iter().enumerate() {
                            *tip.psz_text.0.add(i) = ch;
                        }
                        *tip.psz_text.0.add(len) = 0;
                    }
                }
            } else if hdr.hwndFrom == lv && hdr.code == NM_CUSTOMDRAW {
                return list_view_custom_draw(lp);
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
            if wp.0 == 1 {
                return LRESULT(0);
            }
            let cw = (lp.0 & 0xFFFF) as i32;
            let ch = (lp.0 >> 16 & 0xFFFF) as i32;

            // The Boot History panel fills the whole client area (minus a
            // small margin) — there's no tab control competing for the space
            // anymore. `panel_rect` is shared with WM_CREATE so the two can't
            // drift out of sync (they used to: WM_CREATE built the panel flush
            // against the edges while WM_SIZE always inset by 2px, causing a
            // visible jump the first time the window was resized).
            let rc = panel_rect(cw, ch);
            let pw = rc.right - rc.left;
            let ph = rc.bottom - rc.top;

            let panel = PANEL_H.with(|p| as_hwnd(p.get()));
            SetWindowPos(
                panel,
                None,
                rc.left,
                rc.top,
                pw,
                ph,
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
            .ok();

            // Resize ListView (left, fixed width) and EDIT (right, fills rest).
            let lv = LV_H.with(|t| as_hwnd(t.get()));
            let detail = DETAIL_H.with(|t| as_hwnd(t.get()));
            SetWindowPos(
                lv,
                None,
                PAD,
                PAD,
                LV_W,
                ph - PAD * 2,
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
            .ok();
            let ex = LV_W + PAD * 2;
            SetWindowPos(
                detail,
                None,
                ex,
                PAD,
                pw - ex - PAD,
                ph - PAD * 2,
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
            .ok();

            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

/// The Boot History panel's rect within the client area: a small margin so
/// child controls don't touch the window frame.
fn panel_rect(cw: i32, ch: i32) -> RECT {
    RECT {
        left: 2,
        top: 2,
        right: cw - 2,
        bottom: ch - 2,
    }
}

/// Builds the "File" menu: Refresh (re-scan the live event log), Open
/// Capture… (replay a `--from-file`-style XML capture), About, and Exit.
unsafe fn build_menu(hwnd: HWND) {
    let Ok(menu) = CreateMenu() else { return };
    if let Ok(file_menu) = CreatePopupMenu() {
        let _ = AppendMenuW(file_menu, MF_STRING, ID_REFRESH, w!("&Refresh\tF5"));
        let _ = AppendMenuW(
            file_menu,
            MF_STRING,
            ID_OPEN_CAPTURE,
            w!("&Open Capture...\tCtrl+O"),
        );
        let _ = AppendMenuW(file_menu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(file_menu, MF_STRING, ID_ABOUT, w!("&About whyreboot"));
        let _ = AppendMenuW(file_menu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(file_menu, MF_STRING, ID_EXIT, w!("E&xit"));
        let _ = AppendMenuW(menu, MF_POPUP, file_menu.0 as usize, w!("&File"));
    }
    let _ = SetMenu(hwnd, Some(menu));
}

/// Colors each Boot History row's text by the cycle's [`CauseSeverity`] —
/// the GUI equivalent of the CLI's ANSI-colored verdict line.
unsafe fn list_view_custom_draw(lp: LPARAM) -> LRESULT {
    let cd = &mut *(lp.0 as *mut NMLVCUSTOMDRAW);
    if cd.nmcd.dwDrawStage == CDDS_PREPAINT {
        return LRESULT(CDRF_NOTIFYITEMDRAW as isize);
    }
    if cd.nmcd.dwDrawStage == CDDS_ITEMPREPAINT {
        let idx = cd.nmcd.dwItemSpec;
        let sev = state::with_cycles(|cycles| cycles.get(idx).map(|c| cause_severity(&c.cause)));
        if let Some(sev) = sev {
            cd.clrText = COLORREF(match sev {
                CauseSeverity::Crash => rgb(180, 0, 0),
                CauseSeverity::Warn => rgb(150, 95, 0),
                CauseSeverity::Ok => GetSysColor(COLOR_WINDOWTEXT),
            });
        }
        return LRESULT(CDRF_NEWFONT as isize);
    }
    LRESULT(CDRF_DODEFAULT as isize)
}

// ── Message loop ──────────────────────────────────────────────────────────────

pub unsafe fn run_ui() {
    let hi = hinstance(GetModuleHandleW(PCWSTR(std::ptr::null())).unwrap_or_default());

    let icc = INITCOMMONCONTROLSEX {
        dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC: ICC_LISTVIEW_CLASSES,
    };
    let _ = InitCommonControlsEx(&icc);

    let panel_wc = WNDCLASSW {
        lpfnWndProc: Some(panel_proc),
        hInstance: hi,
        hbrBackground: GetSysColorBrush(COLOR_3DFACE),
        lpszClassName: w!("WRPanel"),
        ..Default::default()
    };
    RegisterClassW(&panel_wc);

    let wc = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wnd_proc),
        hInstance: hi,
        hbrBackground: GetSysColorBrush(COLOR_3DFACE),
        hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
        lpszClassName: w!("WhyReboot"),
        ..Default::default()
    };
    RegisterClassW(&wc);

    let style =
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_SIZEBOX | WS_MAXIMIZEBOX;
    let mut rc = RECT {
        left: 0,
        top: 0,
        right: WIN_W,
        bottom: WIN_H,
    };
    // `true`: a menu bar is added in WM_CREATE, so its height must be budgeted
    // into the window rect too, or the client area would come up short by
    // exactly one menu row.
    AdjustWindowRect(&mut rc, style, true).ok();

    let main = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        w!("WhyReboot"),
        w!("whyreboot \u{2014} Boot Cause Analyzer"),
        style,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        rc.right - rc.left,
        rc.bottom - rc.top,
        None,
        None,
        Some(hi),
        None,
    )
    .unwrap_or(HWND(std::ptr::null_mut()));

    let _ = ShowWindow(main, SW_SHOWNORMAL);
    let _ = UpdateWindow(main);

    // F5 = Refresh, Ctrl+O = Open Capture — mirrors the menu, works regardless
    // of which child control has focus.
    let accels = [
        ACCEL {
            fVirt: FVIRTKEY,
            key: VK_F5.0,
            cmd: ID_REFRESH as u16,
        },
        ACCEL {
            fVirt: FVIRTKEY | FCONTROL,
            key: b'O' as u16,
            cmd: ID_OPEN_CAPTURE as u16,
        },
    ];
    let haccel = CreateAcceleratorTableW(&accels).unwrap_or_default();

    let mut msg = MSG::default();
    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
        if TranslateAcceleratorW(main, haccel, &msg) != 0 {
            continue;
        }
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    let _ = DestroyAcceleratorTable(haccel);
}
