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
    format::{cause_detail, cause_label, event_summary, fmt_secs, generate_explanation, short_provider},
    registry::check_audio_power_settings,
    timestamp::Timestamp,
    types::{AudioPowerInfo, BootCycle, Cause},
};

// ── Analysis data ─────────────────────────────────────────────────────────────

static CYCLES: OnceLock<Vec<BootCycle>>      = OnceLock::new();
static AUDIO:  OnceLock<Vec<AudioPowerInfo>> = OnceLock::new();

// ── Win32 constants not yet in windows 0.62 ───────────────────────────────────

// LVN_FIRST - 58 (Unicode variant)
const LVN_GETINFOTIPW_CODE: u32 = 0xFFFF_FF62;

// Per-item tooltip data sent with LVN_GETINFOTIPW
#[repr(C)]
struct NMLVGETINFOTIPW {
    hdr:        NMHDR,
    dw_flags:   u32,
    psz_text:   PWSTR,
    cch_max:    i32,
    item:       i32,
    sub_item:   i32,
    l_param:    LPARAM,
}

// ── Layout ────────────────────────────────────────────────────────────────────

const WIN_W:  i32 = 860;
const WIN_H:  i32 = 500;
const LV_W:   i32 = 252;   // left-pane ListView width
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

fn format_cycle_detail(c: &BootCycle, audio: &[AudioPowerInfo]) -> String {
    let mut s = String::new();

    // ── Boot times ────────────────────────────────────────────────────────────
    let bt_str = c.boot_time
        .map(|t| t.format_dt())
        .unwrap_or_else(|| "(unknown — no Event 12 found)".into());
    s += &format!("Boot time:   {}\r\n", bt_str);

    if let Some(t) = c.boot_time {
        let secs = Timestamp::now().secs_since(t).max(0);
        let ago = if secs < 120        { format!("{secs} seconds ago") }
            else if secs < 7200        { format!("{} minutes ago", secs / 60) }
            else if secs < 172_800     { format!("{} hours ago",   secs / 3600) }
            else                       { format!("{} days ago",    secs / 86400) };
        s += &format!("             ({})\r\n", ago);
    }

    if let Some((sd, bt)) = c.shutdown_time.zip(c.boot_time) {
        let secs = bt.secs_since(sd);
        if secs >= 0 {
            s += &format!("Offline:     {}  \u{2192}  {}  ({})\r\n",
                sd.format_t(), bt.format_t(), fmt_secs(secs));
        }
    }

    s += "\r\n";

    // ── Verdict ───────────────────────────────────────────────────────────────
    s += &format!("VERDICT:     {}  ({}% confidence)\r\n", cause_label(&c.cause), c.confidence);
    s += &format!("             {}\r\n", cause_detail(&c.cause));
    if let Some(m) = &c.wer_module {
        s += &format!("Module:      {}  [from WER Event 1001]\r\n", m);
    }

    // ── Evidence ──────────────────────────────────────────────────────────────
    if !c.evidence.is_empty() {
        s += "\r\nEvidence:\r\n";
        for e in &c.evidence {
            s += &format!("  \u{2022} {}\r\n", e);
        }
    }

    // ── Timeline ──────────────────────────────────────────────────────────────
    if c.timeline.len() > 1 {
        let mut idxs: Vec<usize> = (0..c.timeline.len()).collect();
        idxs.sort_by_key(|&i| c.timeline[i].0);
        s += "\r\nTimeline:\r\n";
        for i in idxs {
            let (t, msg) = &c.timeline[i];
            s += &format!("  {}  {}\r\n", t.format_dt(), msg);
        }
    }

    // ── Minidumps ─────────────────────────────────────────────────────────────
    if !c.minidumps.is_empty() {
        s += "\r\nMinidumps:\r\n";
        for (t, p) in &c.minidumps {
            s += &format!("  {}  {}\r\n", t.format_dt(), p.display());
        }
    }

    // ── Device Power Settings (conditional: audio power-crash only) ───────────
    let module_low = c.wer_module.as_deref().unwrap_or("").to_lowercase();
    let is_power_crash = matches!(&c.cause, Cause::BlueScreen { stop_code, .. }
        if *stop_code == 0x9F || *stop_code == 0x19C || *stop_code == 0xFE || *stop_code == 0x144);
    let is_audio_crash = is_power_crash
        && (module_low.contains("portcls") || module_low.contains("audio") || module_low.contains("hdaud"));
    if is_audio_crash && !audio.is_empty() {
        s += "\r\nDevice Power Settings (audio class):\r\n";
        for dev in audio {
            let status = match dev.allow_idle_d3 {
                Some(0) => "AllowIdleIrpInD3=0  [safe — D3 idle disabled]",
                Some(_) => "AllowIdleIrpInD3=1  [RISKY — D3 idle enabled]",
                None    => "AllowIdleIrpInD3: not set [driver default — risky]",
            };
            s += &format!("  [{}] {:<32}  {}\r\n", dev.instance, dev.name, status);
        }
    }

    // ── Explanation / remediation ─────────────────────────────────────────────
    let explanation = generate_explanation(&c.cause, &c.wer_module, audio);
    if !explanation.is_empty() {
        s += "\r\nExplanation:\r\n";
        for ln in &explanation {
            if ln.is_empty() { s += "\r\n"; } else { s += &format!("  {}\r\n", ln); }
        }
    }

    // ── Raw event table ───────────────────────────────────────────────────────
    if !c.display_events.is_empty() {
        let line = "\u{2500}".repeat(69);
        s += &format!("\r\n{}\r\n", line);
        s += &format!("{:<20} {:>6}  {:<26}  {}\r\n", "Time", "Event", "Provider", "Summary");
        s += &format!("{}\r\n", line);
        for ev in &c.display_events {
            s += &format!(
                "{:<20} {:>6}  {:<26.26}  {}\r\n",
                ev.time_created.format_dt(),
                ev.event_id,
                short_provider(&ev.provider),
                event_summary(ev),
            );
        }
        s += &format!("{}\r\n", line);
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
    let audio  = AUDIO.get().map(|v| v.as_slice()).unwrap_or(&[]);
    let text = cycles.get(idx)
        .map(|c| format_cycle_detail(c, audio))
        .unwrap_or_default();
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
            if lp.0 == 0 {
                return DefWindowProcW(hwnd, msg, wp, lp);
            }
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
            } else if hdr.hwndFrom == lv && hdr.code == LVN_GETINFOTIPW_CODE {
                let tip = &mut *(lp.0 as *mut NMLVGETINFOTIPW);
                if tip.item >= 0 && !tip.psz_text.0.is_null() && tip.cch_max > 0 {
                    let cycles = CYCLES.get().map(|v| v.as_slice()).unwrap_or(&[]);
                    if let Some(c) = cycles.get(tip.item as usize) {
                        if let Some(t) = c.boot_time {
                            let secs = Timestamp::now().secs_since(t).max(0);
                            let ago = if secs < 120       { format!("{secs} seconds ago") }
                                else if secs < 7200       { format!("{} minutes ago", secs / 60) }
                                else if secs < 172_800    { format!("{} hours ago",   secs / 3600) }
                                else                      { format!("{} days ago",    secs / 86400) };
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
