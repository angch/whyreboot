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

// ── Analysis data ─────────────────────────────────────────────────────────────

static CYCLES: OnceLock<Vec<BootCycle>>      = OnceLock::new();
static AUDIO:  OnceLock<Vec<AudioPowerInfo>> = OnceLock::new();

// ── Layout ────────────────────────────────────────────────────────────────────

const WIN_W:  i32 = 660;
const WIN_H:  i32 = 500;
const LV_W:   i32 = 210;   // left-pane ListView width
const PAD:    i32 = 4;      // gap between panes / edge margins

// ── Helpers ───────────────────────────────────────────────────────────────────

fn wstr(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }

fn hinstance(m: HMODULE) -> HINSTANCE { HINSTANCE(m.0) }

fn hmenu_id(id: usize) -> Option<HMENU> {
    Some(HMENU(id as *mut std::ffi::c_void))
}

fn as_hwnd(v: isize) -> HWND { HWND(v as *mut std::ffi::c_void) }

unsafe fn apply_font(hwnd: HWND, font: HGDIOBJ) {
    SendMessageW(hwnd, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
}


// ── Format cycle detail (right pane) ─────────────────────────────────────────

fn format_cycle_detail(c: &BootCycle) -> String {
    let mut s = String::new();

    // Boot time
    let bt_str = c.boot_time
        .map(|t| format!("{}", t.format("%Y-%m-%d  %H:%M:%S")))
        .unwrap_or_else(|| "(unknown — no Event 12 found)".into());
    s += &format!("Boot time:   {}\r\n", bt_str);

    if let Some(t) = c.boot_time {
        let secs = chrono::Local::now().signed_duration_since(t).num_seconds().max(0);
        let ago = if secs < 120        { format!("{secs} seconds ago") }
            else if secs < 7200        { format!("{} minutes ago", secs / 60) }
            else if secs < 172_800     { format!("{} hours ago",   secs / 3600) }
            else                       { format!("{} days ago",    secs / 86400) };
        s += &format!("             ({})\r\n", ago);
    }

    // Offline duration
    match c.shutdown_time.zip(c.boot_time) {
        Some((sd, bt)) => {
            let secs = bt.signed_duration_since(sd).num_seconds();
            let off = if secs < 0      { "(clock skew)".into() }
                else if secs < 60      { format!("{secs}s") }
                else if secs < 3600    { format!("{}m {:02}s", secs / 60, secs % 60) }
                else                   { format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60) };
            s += &format!("Offline:     {}\r\n", off);
        }
        None => { s += "Offline:     (unknown)\r\n"; }
    }

    s += "\r\n";

    // Cause
    let cause = match &c.cause {
        Cause::BlueScreen { .. }    => "BLUE SCREEN OF DEATH (BSOD)",
        Cause::ForcedPowerOff       => "FORCED POWER-OFF",
        Cause::UnexpectedShutdown   => "UNEXPECTED / UNCLEAN SHUTDOWN",
        Cause::WindowsUpdate { .. } => "WINDOWS UPDATE RESTART",
        Cause::UserAction { .. }    => "USER-INITIATED SHUTDOWN",
        Cause::SystemProcess { .. } => "SYSTEM / SOFTWARE RESTART",
        Cause::NormalShutdown       => "NORMAL SHUTDOWN",
        Cause::Undetermined         => "UNDETERMINED",
    };
    s += &format!("Cause:       {}\r\n", cause);

    let detail = match &c.cause {
        Cause::BlueScreen { stop_code, stop_name, .. } =>
            format!("0x{:08X}  {}", stop_code, stop_name),
        Cause::WindowsUpdate { process } =>
            format!("via {}", process.split('\\').last().unwrap_or(process)),
        Cause::UserAction { user, action, .. } =>
            format!("{} (user: {})", action, user),
        Cause::SystemProcess { process, action, .. } =>
            format!("{} by {}", action, process.split('\\').last().unwrap_or(process)),
        _ => String::new(),
    };
    if !detail.is_empty() {
        s += &format!("             {}\r\n", detail);
    }

    if let Some(m) = &c.wer_module {
        s += &format!("Module:      {}\r\n", m);
    }

    s += &format!("Confidence:  {}%\r\n", c.confidence);

    if !c.evidence.is_empty() {
        s += "\r\nEvidence:\r\n";
        for e in &c.evidence {
            s += &format!("  \u{2022} {}\r\n", e);
        }
    }

    s
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

// ── Thread-local handles ──────────────────────────────────────────────────────

thread_local! {
    static TAB_H:    Cell<isize>      = const { Cell::new(0) };
    static LV_H:     Cell<isize>      = const { Cell::new(0) };
    static DETAIL_H: Cell<isize>      = const { Cell::new(0) };
    static PANELS:   Cell<[isize; 2]> = const { Cell::new([0; 2]) };
}

// ── Update detail pane from cycle index ───────────────────────────────────────

unsafe fn update_detail(idx: usize) {
    let detail = DETAIL_H.with(|t| as_hwnd(t.get()));
    if detail.0.is_null() { return; }
    let cycles = CYCLES.get().map(|v| v.as_slice()).unwrap_or(&[]);
    let text = cycles.get(idx).map(format_cycle_detail).unwrap_or_default();
    let txt = wstr(&text);
    let _ = SetWindowTextW(detail, PCWSTR(txt.as_ptr()));
}

// ── Build boot-history panel (two-pane) ──────────────────────────────────────

unsafe fn build_boot_history(parent: HWND, rc: RECT, hi: HINSTANCE, font: HGDIOBJ) -> HWND {
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
            | WINDOW_STYLE(LVS_REPORT as u32 | LVS_SINGLESEL as u32
                         | LVS_NOSORTHEADER as u32 | LVS_SHOWSELALWAYS as u32),
        PAD, PAD, LV_W, ph - PAD * 2,
        Some(panel), hmenu_id(300), Some(hi), None,
    ).unwrap_or(HWND(std::ptr::null_mut()));
    apply_font(lv, font);

    // Full-row select extended style
    SendMessageW(lv, LVM_SETEXTENDEDLISTVIEWSTYLE,
        Some(WPARAM(LVS_EX_FULLROWSELECT as usize)),
        Some(LPARAM(LVS_EX_FULLROWSELECT as isize)));

    LV_H.with(|t| t.set(lv.0 as isize));

    let col_defs: &[(&str, i32)] = &[
        ("#",      28),
        ("Date",   88),
        ("Cause",  80),
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
            .map(|t| format!("{}", t.format("%Y-%m-%d")))
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

unsafe fn build_about(parent: HWND, rc: RECT, hi: HINSTANCE, font: HGDIOBJ) -> HWND {
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

unsafe fn switch_tab(idx: usize) {
    let panels = PANELS.with(|p| p.get());
    for (i, &raw) in panels.iter().enumerate() {
        let _ = ShowWindow(as_hwnd(raw), if i == idx { SW_SHOW } else { SW_HIDE });
    }
}

// ── Main window procedure ─────────────────────────────────────────────────────

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
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
            let hdr  = &*(lp.0 as *const NMHDR);
            let tab  = TAB_H.with(|t| as_hwnd(t.get()));
            let lv   = LV_H.with(|t| as_hwnd(t.get()));

            if hdr.hwndFrom == tab && hdr.code == TCN_SELCHANGE as u32 {
                let sel = SendMessageW(tab, TCM_GETCURSEL,
                    Some(WPARAM(0)), Some(LPARAM(0))).0 as usize;
                switch_tab(sel);
            } else if hdr.hwndFrom == lv && hdr.code == LVN_ITEMCHANGED as u32 {
                let nmlv = &*(lp.0 as *const NMLISTVIEW);
                // Only act when a row becomes selected (not deselected)
                if nmlv.uChanged.0 & LVIF_STATE.0 != 0
                    && nmlv.uNewState & LVIS_SELECTED.0 != 0
                {
                    update_detail(nmlv.iItem as usize);
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
