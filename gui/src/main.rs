// SPDX-License-Identifier: MIT OR Apache-2.0
#![windows_subsystem = "windows"]
#![allow(unsafe_op_in_unsafe_fn)]

use std::cell::Cell;
use std::sync::OnceLock;

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::WindowsAndMessaging::*;

use whyreboot::{
    analysis::extract_boot_cycles,
    events::{fetch_system_events, fetch_wer_events, list_minidumps},
    registry::check_audio_power_settings,
    types::{AudioPowerInfo, BootCycle, Cause},
};

// ── Analysis results ──────────────────────────────────────────────────────────

static CYCLES: OnceLock<Vec<BootCycle>>      = OnceLock::new();
static AUDIO:  OnceLock<Vec<AudioPowerInfo>> = OnceLock::new();

// ── Layout constants ──────────────────────────────────────────────────────────

const WIN_W: i32 = 620;
const WIN_H: i32 = 500;
const LX: i32 = 14;   // label column x inside a group
const VX: i32 = 140;  // value column x
const VW: i32 = 430;  // value column width
const RH: i32 = 18;   // row height
const RY: i32 = 20;   // first row y inside a group box

// ── Helpers ───────────────────────────────────────────────────────────────────

fn wstr(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }

// Safe wrapper: convert HMODULE → HINSTANCE (same representation in Win32)
fn hinstance(m: HMODULE) -> HINSTANCE { HINSTANCE(m.0) }

fn hmenu_id(id: usize) -> Option<HMENU> {
    Some(HMENU(id as *mut std::ffi::c_void))
}

// ── Control creation helpers ──────────────────────────────────────────────────

unsafe fn make_window(
    ex:     WINDOW_EX_STYLE,
    class:  PCWSTR,
    text:   &[u16],
    style:  WINDOW_STYLE,
    x: i32, y: i32, w: i32, h: i32,
    parent: HWND,
    id:     usize,
    hi:     HINSTANCE,
) -> HWND {
    CreateWindowExW(
        ex, class, PCWSTR(text.as_ptr()),
        WS_CHILD | WS_VISIBLE | style,
        x, y, w, h,
        Some(parent), hmenu_id(id), Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()))
}

unsafe fn groupbox(caption: &str, x: i32, y: i32, bw: i32, bh: i32,
                   parent: HWND, id: usize, hi: HINSTANCE) -> HWND {
    let txt = wstr(caption);
    make_window(WINDOW_EX_STYLE(0), w!("BUTTON"), &txt,
                WINDOW_STYLE(BS_GROUPBOX as u32),
                x, y, bw, bh, parent, id, hi)
}

unsafe fn label(text: &str, x: i32, y: i32, parent: HWND, id: usize, hi: HINSTANCE) {
    let txt = wstr(text);
    make_window(WINDOW_EX_STYLE(0), w!("STATIC"), &txt,
                WINDOW_STYLE(0), // SS_LEFT = 0
                x, y, 120, RH, parent, id, hi);
}

unsafe fn value(text: &str, x: i32, y: i32, vw: i32,
                parent: HWND, id: usize, hi: HINSTANCE) -> HWND {
    let txt = wstr(text);
    make_window(WINDOW_EX_STYLE(0), w!("STATIC"), &txt,
                WINDOW_STYLE(0),
                x, y, vw, RH, parent, id, hi)
}

// ── Panel window procedure ────────────────────────────────────────────────────

unsafe extern "system" fn panel_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
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
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

// ── Panel builders ────────────────────────────────────────────────────────────

unsafe fn build_summary(parent: HWND, rc: RECT, hi: HINSTANCE) -> HWND {
    let pw = rc.right  - rc.left;
    let ph = rc.bottom - rc.top;
    let panel = CreateWindowExW(
        WINDOW_EX_STYLE(0), w!("WRPanel"), w!(""),
        WS_CHILD | WS_VISIBLE,
        rc.left, rc.top, pw, ph,
        Some(parent), None, Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()));

    let cycles = CYCLES.get().map(|v| v.as_slice()).unwrap_or(&[]);
    let cycle  = cycles.first();
    let gw = pw - 16;

    // ── Last Boot ─────────────────────────────────────────────────────────────
    groupbox("Last Boot", 8, 4, gw, 78, panel, 200, hi);

    let bt_text = cycle.and_then(|c| c.boot_time)
        .map(|t| format!("{}", t.format("%Y-%m-%d %H:%M:%S")))
        .unwrap_or_else(|| "(no Event 12 in log)".into());
    let ago_text = cycle.and_then(|c| c.boot_time).map(|t| {
        let s = chrono::Local::now().signed_duration_since(t).num_seconds().max(0);
        if s < 120        { format!("{s} seconds ago") }
        else if s < 7200  { format!("{} minutes ago", s / 60) }
        else if s < 172800 { format!("{} hours ago", s / 3600) }
        else              { format!("{} days ago", s / 86400) }
    }).unwrap_or_default();
    let off_text = match cycle.and_then(|c| c.shutdown_time.zip(c.boot_time)) {
        Some((sd, bt)) => {
            let s = bt.signed_duration_since(sd).num_seconds();
            if s < 0      { "(clock skew)".into() }
            else if s < 60 { format!("{s}s") }
            else if s < 3600 { format!("{}m {:02}s", s/60, s%60) }
            else           { format!("{}h {:02}m", s/3600, (s%3600)/60) }
        }
        None => "(unknown — crash or no data)".into(),
    };

    label("Boot time",  LX,      RY,       panel, 201, hi);
    value(&bt_text,     VX,      RY,  VW,  panel, 202, hi);
    label("Time ago",   LX,      RY+RH,    panel, 203, hi);
    value(&ago_text,    VX,      RY+RH, VW, panel, 204, hi);
    label("Offline",    LX,      RY+RH*2,  panel, 205, hi);
    value(&off_text,    VX,      RY+RH*2, VW, panel, 206, hi);

    // ── Verdict ───────────────────────────────────────────────────────────────
    groupbox("Verdict", 8, 88, gw, 122, panel, 210, hi);

    let cause_s = cycle.map(|c| match &c.cause {
        Cause::BlueScreen { .. }    => "BLUE SCREEN OF DEATH (BSOD)",
        Cause::ForcedPowerOff       => "FORCED POWER-OFF",
        Cause::UnexpectedShutdown   => "UNEXPECTED / UNCLEAN SHUTDOWN",
        Cause::WindowsUpdate { .. } => "WINDOWS UPDATE RESTART",
        Cause::UserAction { .. }    => "USER-INITIATED SHUTDOWN",
        Cause::SystemProcess { .. } => "SYSTEM / SOFTWARE RESTART",
        Cause::NormalShutdown       => "NORMAL SHUTDOWN",
        Cause::Undetermined         => "UNDETERMINED",
    }).unwrap_or("(no data)");
    let detail_s = cycle.map(|c| match &c.cause {
        Cause::BlueScreen { stop_code, stop_name, .. } =>
            format!("0x{:08X}  —  {}", stop_code, stop_name),
        Cause::WindowsUpdate { process } =>
            format!("via {}", process.split('\\').last().unwrap_or(process)),
        Cause::UserAction { user, action, .. } => format!("{} by {}", action, user),
        Cause::SystemProcess { process, action, .. } =>
            format!("{} by {}", action, process.split('\\').last().unwrap_or(process)),
        _ => String::new(),
    }).unwrap_or_default();
    let module_s  = cycle.and_then(|c| c.wer_module.as_deref()).unwrap_or("—").to_string();
    let conf_s    = cycle.map(|c| format!("{}%", c.confidence)).unwrap_or_default();

    label("Cause",       LX, RY,       panel, 211, hi);
    value(cause_s,       VX, RY,  VW,  panel, 212, hi);
    label("Detail",      LX, RY+RH,    panel, 213, hi);
    value(&detail_s,     VX, RY+RH, VW, panel, 214, hi);
    label("Module",      LX, RY+RH*2,  panel, 215, hi);
    value(&module_s,     VX, RY+RH*2, VW, panel, 216, hi);
    label("Confidence",  LX, RY+RH*3,  panel, 217, hi);
    value(&conf_s,       VX, RY+RH*3, VW, panel, 218, hi);

    // ── Evidence ──────────────────────────────────────────────────────────────
    let ey = 216;
    let eh = ph - ey - 8;
    groupbox("Evidence", 8, ey, gw, eh, panel, 220, hi);

    let evid = cycle.map(|c| {
        if c.evidence.is_empty() { "(none)".into() }
        else { c.evidence.iter().map(|e| format!("• {e}")).collect::<Vec<_>>().join("\r\n") }
    }).unwrap_or_else(|| {
        "No boot cycles found.\r\nTry running as Administrator.".into()
    });
    let evid_w = wstr(&evid);

    CreateWindowExW(
        WS_EX_CLIENTEDGE, w!("EDIT"),
        PCWSTR(evid_w.as_ptr()),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL
            | WINDOW_STYLE(ES_MULTILINE as u32 | ES_READONLY as u32 | ES_AUTOVSCROLL as u32),
        8 + LX, ey + RY, gw - LX - 14, eh - RY - 8,
        Some(panel), hmenu_id(221), Some(hi), None,
    ).ok();

    panel
}

unsafe fn build_history(parent: HWND, rc: RECT, hi: HINSTANCE) -> HWND {
    let pw = rc.right  - rc.left;
    let ph = rc.bottom - rc.top;
    let panel = CreateWindowExW(
        WINDOW_EX_STYLE(0), w!("WRPanel"), w!(""),
        WS_CHILD,
        rc.left, rc.top, pw, ph,
        Some(parent), None, Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()));

    let lv = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_LISTVIEWW, w!(""),
        WS_CHILD | WS_VISIBLE
            | WINDOW_STYLE(LVS_REPORT as u32 | LVS_SINGLESEL as u32 | LVS_NOSORTHEADER as u32),
        4, 4, pw - 8, ph - 8,
        Some(panel), hmenu_id(300), Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()));

    let cols: &[(&str, i32)] = &[
        ("#",           36),
        ("Boot time",  155),
        ("Cause",      190),
        ("Stop code",   94),
        ("Confidence",  84),
    ];
    for (i, (name, cx)) in cols.iter().enumerate() {
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
        let mut num_w  = wstr(&format!("{}", c.index + 1));
        let bt_str = c.boot_time
            .map(|t| format!("{}", t.format("%Y-%m-%d %H:%M")))
            .unwrap_or_else(|| "(unknown)".into());
        let mut bt_w   = wstr(&bt_str);
        let cause_str  = match &c.cause {
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
        let stop_str = match &c.cause {
            Cause::BlueScreen { stop_code, .. } => format!("0x{:08X}", stop_code),
            _ => String::new(),
        };
        let mut stop_w  = wstr(&stop_str);
        let mut conf_w  = wstr(&format!("{}%", c.confidence));

        let mut item = LVITEMW {
            mask:     LVIF_TEXT,
            iItem:    row as i32,
            iSubItem: 0,
            pszText:  PWSTR(num_w.as_mut_ptr()),
            ..Default::default()
        };
        SendMessageW(lv, LVM_INSERTITEMW,
            Some(WPARAM(0)), Some(LPARAM(&mut item as *mut _ as isize)));

        for (col, txt) in [(1, &mut bt_w), (2, &mut cause_w),
                           (3, &mut stop_w), (4, &mut conf_w)] {
            item.iSubItem = col;
            item.pszText  = PWSTR(txt.as_mut_ptr());
            SendMessageW(lv, LVM_SETITEMW,
                Some(WPARAM(0)), Some(LPARAM(&mut item as *mut _ as isize)));
        }
    }
    panel
}

unsafe fn build_about(parent: HWND, rc: RECT, hi: HINSTANCE) -> HWND {
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
    CreateWindowExW(
        WINDOW_EX_STYLE(0), w!("STATIC"),
        PCWSTR(about.as_ptr()),
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(0),
        16, 16, pw - 32, ph - 32,
        Some(panel), hmenu_id(400), Some(hi), None,
    ).ok();

    panel
}

// ── Main window ───────────────────────────────────────────────────────────────

thread_local! {
    static TAB_H:  Cell<isize>      = const { Cell::new(0) };
    static PANELS: Cell<[isize; 3]> = const { Cell::new([0; 3]) };
}

fn as_hwnd(v: isize) -> HWND { HWND(v as *mut std::ffi::c_void) }

unsafe fn switch_tab(idx: usize) {
    let panels = PANELS.with(|p| p.get());
    for (i, &raw) in panels.iter().enumerate() {
        let _ = ShowWindow(as_hwnd(raw), if i == idx { SW_SHOW } else { SW_HIDE });
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            let hi = hinstance(GetModuleHandleW(PCWSTR(std::ptr::null())).unwrap_or_default());

            let tab = CreateWindowExW(
                WINDOW_EX_STYLE(0), WC_TABCONTROLW, w!(""),
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                0, 0, WIN_W, WIN_H,
                Some(hwnd), hmenu_id(1000), Some(hi), None,
            ).unwrap_or(HWND(std::ptr::null_mut()));
            TAB_H.with(|t| t.set(tab.0 as isize));

            for (i, name) in ["Summary", "History", "About"].iter().enumerate() {
                let mut txt = wstr(name);
                let mut ti = TCITEMW {
                    mask:    TCIF_TEXT,
                    pszText: PWSTR(txt.as_mut_ptr()),
                    ..Default::default()
                };
                SendMessageW(tab, TCM_INSERTITEMW,
                    Some(WPARAM(i)), Some(LPARAM(&mut ti as *mut _ as isize)));
            }

            // Content rect
            let mut rc = RECT { left: 2, top: 2, right: WIN_W - 2, bottom: WIN_H - 2 };
            SendMessageW(tab, TCM_ADJUSTRECT,
                Some(WPARAM(0)), Some(LPARAM(&mut rc as *mut _ as isize)));

            let p0 = build_summary(hwnd, rc, hi);
            let p1 = build_history(hwnd, rc, hi);
            let p2 = build_about  (hwnd, rc, hi);
            PANELS.with(|p| p.set([p0.0 as isize, p1.0 as isize, p2.0 as isize]));

            // Tab control must be Z-order top so its frame draws over the panels
            SetWindowPos(tab, Some(HWND_TOP), 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE).ok();

            switch_tab(0);
            LRESULT(0)
        }
        WM_NOTIFY => {
            let hdr = &*(lp.0 as *const NMHDR);
            let tab = TAB_H.with(|t| as_hwnd(t.get()));
            if hdr.hwndFrom == tab && hdr.code == TCN_SELCHANGE as u32 {
                let sel = SendMessageW(tab, TCM_GETCURSEL,
                    Some(WPARAM(0)), Some(LPARAM(0))).0 as usize;
                switch_tab(sel);
            }
            LRESULT(0)
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let hdc = HDC(wp.0 as *mut _);
            SetBkColor(hdc, COLORREF(GetSysColor(COLOR_3DFACE)));
            SetTextColor(hdc, COLORREF(GetSysColor(COLOR_WINDOWTEXT)));
            LRESULT(GetSysColorBrush(COLOR_3DFACE).0 as isize)
        }
        WM_DESTROY => { PostQuitMessage(0); LRESULT(0) }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let sys   = fetch_system_events();
    let wer   = fetch_wer_events();
    let dumps = list_minidumps();
    let audio = check_audio_power_settings();
    CYCLES.set(extract_boot_cycles(&sys, &wer, &dumps, 0)).ok();
    AUDIO.set(audio).ok();

    unsafe { run_ui() };
}

unsafe fn run_ui() {
    let hi_mod = GetModuleHandleW(PCWSTR(std::ptr::null())).unwrap_or_default();
    let hi     = hinstance(hi_mod);

    let icc = INITCOMMONCONTROLSEX {
        dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC:  ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES,
    };
    let _ = InitCommonControlsEx(&icc);

    // Panel class — handles background painting for tab pages
    let panel_wc = WNDCLASSW {
        lpfnWndProc:   Some(panel_proc),
        hInstance:     hi,
        hbrBackground: GetSysColorBrush(COLOR_3DFACE),
        lpszClassName: w!("WRPanel"),
        ..Default::default()
    };
    RegisterClassW(&panel_wc);

    // Main window class
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

    // Compute outer window size from desired client area
    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
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
