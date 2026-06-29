//! Windows registry helpers and audio device power settings check.
//!
//! The audio device class GUID `{4d36e96c-e325-11ce-bfc1-08002be10318}` is a fixed
//! Microsoft-assigned identifier for "Sound, video and game controllers" (the Media
//! device class). It has been stable since Windows 98 and covers all audio devices:
//! HD Audio, USB audio, Bluetooth audio, etc.

use crate::types::AudioPowerInfo;

/// Reads a `REG_DWORD` value from an open registry key. Returns `None` if the
/// value is absent, the wrong type, or the query fails.
fn reg_read_dword(hk: windows::Win32::System::Registry::HKEY, name: &str) -> Option<u32> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};
    let w: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut val = 0u32;
    let mut sz  = 4u32;
    let mut tp  = REG_VALUE_TYPE(0);
    let ok = unsafe {
        RegQueryValueExW(
            hk,
            windows::core::PCWSTR(w.as_ptr()),
            None,
            Some(&mut tp),
            Some(&mut val as *mut u32 as *mut u8),
            Some(&mut sz),
        )
        .ok()
        .is_ok()
    };
    if ok && tp.0 == 4 { Some(val) } else { None }
}

/// Reads a `REG_SZ` or `REG_EXPAND_SZ` value from an open registry key.
/// Uses a two-pass query: size probe then read. Returns `None` if absent or empty.
fn reg_read_string(hk: windows::Win32::System::Registry::HKEY, name: &str) -> Option<String> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};
    let w: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut sz = 0u32;
    let mut tp = REG_VALUE_TYPE(0);
    unsafe {
        let _ = RegQueryValueExW(
            hk,
            windows::core::PCWSTR(w.as_ptr()),
            None,
            Some(&mut tp),
            None,
            Some(&mut sz),
        );
    }
    // sz=2 is just a null terminator (empty string); skip that too.
    if sz <= 2 { return None; }
    let mut buf = vec![0u8; sz as usize + 2];
    let ok = unsafe {
        RegQueryValueExW(
            hk,
            windows::core::PCWSTR(w.as_ptr()),
            None,
            Some(&mut tp),
            Some(buf.as_mut_ptr()),
            Some(&mut sz),
        )
        .ok()
        .is_ok()
    };
    if ok && (tp.0 == 1 || tp.0 == 2) {
        let chars = unsafe {
            std::slice::from_raw_parts(buf.as_ptr() as *const u16, sz as usize / 2)
        };
        let trimmed = String::from_utf16_lossy(chars);
        let trimmed = trimmed.trim_end_matches('\0');
        if !trimmed.is_empty() { Some(trimmed.to_string()) } else { None }
    } else {
        None
    }
}

/// Reads power management registry values for all audio class instances (0000–0020).
/// Skips entries that have neither `DriverDesc` nor `FriendlyName` (not real devices).
/// Returns one `AudioPowerInfo` per found instance with `AllowIdleIrpInD3` and
/// `EnhancedPowerManagementEnabled` values (`None` = registry value absent).
pub fn check_audio_power_settings() -> Vec<AudioPowerInfo> {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegCloseKey, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    const BASE: &str = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}";
    let mut results = Vec::new();
    unsafe {
        let base_w: Vec<u16> = BASE.encode_utf16().chain([0]).collect();
        let mut hk_base = HKEY(std::ptr::null_mut());
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(base_w.as_ptr()),
            None,
            KEY_READ,
            &mut hk_base,
        )
        .ok()
        .is_err()
        {
            return results;
        }

        for i in 0..=20u32 {
            let inst   = format!("{:04}", i);
            let path   = format!("{}\\{}", BASE, inst);
            let path_w: Vec<u16> = path.encode_utf16().chain([0]).collect();
            let mut hk = HKEY(std::ptr::null_mut());
            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                windows::core::PCWSTR(path_w.as_ptr()),
                None,
                KEY_READ,
                &mut hk,
            )
            .ok()
            .is_err()
            {
                continue;
            }

            let name = match reg_read_string(hk, "DriverDesc")
                .or_else(|| reg_read_string(hk, "FriendlyName"))
            {
                Some(n) if !n.is_empty() => n,
                _ => { let _ = RegCloseKey(hk); continue; }
            };

            let allow_idle_d3 = reg_read_dword(hk, "AllowIdleIrpInD3");
            let enhanced_pm   = reg_read_dword(hk, "EnhancedPowerManagementEnabled");
            let _ = RegCloseKey(hk);
            results.push(AudioPowerInfo { instance: inst, name, allow_idle_d3, enhanced_pm });
        }

        let _ = RegCloseKey(hk_base);
    }
    results
}
