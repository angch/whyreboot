pub struct Pal {
    pub crash: &'static str,
    pub warn:  &'static str,
    pub ok:    &'static str,
    pub info:  &'static str,
    pub bold:  &'static str,
    pub dim:   &'static str,
    pub reset: &'static str,
}

pub const NO_COLOR: Pal = Pal {
    crash: "", warn: "", ok: "", info: "", bold: "", dim: "", reset: "",
};

pub const COLORS: Pal = Pal {
    crash: "\x1b[1;31m",
    warn:  "\x1b[1;33m",
    ok:    "\x1b[1;32m",
    info:  "\x1b[36m",
    bold:  "\x1b[1m",
    dim:   "\x1b[2m",
    reset: "\x1b[0m",
};

pub fn enable_ansi_color() -> bool {
    use windows::Win32::System::Console::*;
    const VTP: u32 = 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
    unsafe {
        let h = match GetStdHandle(STD_OUTPUT_HANDLE) {
            Ok(h)  => h,
            Err(_) => return false,
        };
        if h.is_invalid() { return false; }
        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(h, &mut mode).is_err() { return false; }
        SetConsoleMode(h, CONSOLE_MODE(mode.0 | VTP)).is_ok()
    }
}
