// SPDX-License-Identifier: MIT OR Apache-2.0
//! Windows lookup tables: bugcheck stop codes and Event 1074 shutdown reason
//! codes, with their lookup functions.
//!
//! Split out from `analysis.rs` so the decision logic there reads without
//! scrolling past ~120 lines of pure data. Both tables are `&'static` slices
//! searched linearly — they are small, and a map would cost more code size than
//! the scan saves.

const STOP_CODES: &[(u64, &str)] = &[
    (0x00000001, "APC_INDEX_MISMATCH"),
    (0x00000019, "BAD_POOL_HEADER"),
    (0x0000001A, "MEMORY_MANAGEMENT"),
    (0x0000001E, "KMODE_EXCEPTION_NOT_HANDLED"),
    (0x00000023, "FAT_FILE_SYSTEM"),
    (0x00000024, "NTFS_FILE_SYSTEM"),
    (0x0000002E, "DATA_BUS_ERROR"),
    (0x0000003B, "SYSTEM_SERVICE_EXCEPTION"),
    (0x0000003F, "NO_MORE_SYSTEM_PTES"),
    (0x00000050, "PAGE_FAULT_IN_NONPAGED_AREA"),
    (0x00000051, "REGISTRY_ERROR"),
    (0x0000005A, "CRITICAL_SERVICE_FAILED"),
    (0x0000005C, "HAL_INITIALIZATION_FAILED"),
    (0x00000074, "BAD_SYSTEM_CONFIG_INFO"),
    (0x00000076, "PROCESS_HAS_LOCKED_PAGES"),
    (0x00000077, "KERNEL_STACK_INPAGE_ERROR"),
    (0x0000007A, "KERNEL_DATA_INPAGE_ERROR"),
    (0x0000007B, "INACCESSIBLE_BOOT_DEVICE"),
    (0x0000007E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"),
    (0x0000007F, "UNEXPECTED_KERNEL_MODE_TRAP"),
    (0x00000080, "NMI_HARDWARE_FAILURE"),
    (0x0000008E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED"),
    (0x0000009C, "MACHINE_CHECK_EXCEPTION"),
    (0x0000009F, "DRIVER_POWER_STATE_FAILURE"),
    (0x000000A0, "INTERNAL_POWER_ERROR"),
    (0x000000A5, "ACPI_BIOS_ERROR"),
    (0x000000BE, "ATTEMPTED_WRITE_TO_READONLY_MEMORY"),
    (0x000000C1, "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION"),
    (0x000000C2, "BAD_POOL_CALLER"),
    (0x000000C4, "DRIVER_VERIFIER_DETECTED_VIOLATION"),
    (0x000000C5, "DRIVER_CORRUPTED_EXPOOL"),
    (0x000000CA, "PNP_DETECTED_FATAL_ERROR"),
    (0x000000D1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL"),
    (
        0x000000D4,
        "SYSTEM_SCAN_AT_RAISED_IRQL_CAUGHT_IMPROPER_DRIVER_UNLOAD",
    ),
    (0x000000EA, "THREAD_STUCK_IN_DEVICE_DRIVER"),
    (0x000000ED, "UNMOUNTABLE_BOOT_VOLUME"),
    (0x000000EF, "CRITICAL_PROCESS_DIED"),
    (0x000000F4, "CRITICAL_OBJECT_TERMINATION"),
    (0x000000FC, "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY"),
    (0x000000FE, "BUGCODE_USB_DRIVER"),
    (0x00000101, "CLOCK_WATCHDOG_TIMEOUT"),
    (0x00000102, "DPC_WATCHDOG_TIMEOUT"),
    (0x00000109, "CRITICAL_STRUCTURE_CORRUPTION"),
    (0x0000010D, "WDF_VIOLATION"),
    (0x0000010E, "VIDEO_MEMORY_MANAGEMENT_INTERNAL"),
    (0x00000113, "VIDEO_DXGKRNL_FATAL_ERROR"),
    (0x00000116, "VIDEO_TDR_FAILURE"),
    (0x00000117, "VIDEO_TDR_TIMEOUT_DETECTED"),
    (0x00000119, "VIDEO_SCHEDULER_INTERNAL_ERROR"),
    (0x0000019C, "WIN32K_POWER_WATCHDOG_TIMEOUT"),
    (0x00000124, "WHEA_UNCORRECTABLE_ERROR"),
    (0x00000125, "NMR_INVALID_STATE"),
    (0x00000127, "PAGE_NOT_ZERO"),
    (0x00000133, "DPC_WATCHDOG_VIOLATION"),
    (0x00000139, "KERNEL_SECURITY_CHECK_FAILURE"),
    (0x0000013A, "KERNEL_MODE_HEAP_CORRUPTION"),
    (0x00000141, "VIDEO_ENGINE_TIMEOUT_DETECTED"),
    (0x00000144, "BUGCODE_USB3_DRIVER"),
    (0x00000154, "UNEXPECTED_STORE_EXCEPTION"),
    (0x00000155, "OS_DATA_TAMPERING"),
    (0x00000160, "WIN32K_ATOMIC_CHECK_FAILURE"),
    (0x00000162, "KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE"),
    (0x00000164, "WIN32K_CRITICAL_FAILURE"),
    (0x00000187, "VIDEO_DWMINIT_TIMEOUT_FALLBACK_BDD"),
    (0x00000189, "BAD_OBJECT_HEADER"),
    (0x0000018B, "SECURE_KERNEL_ERROR"),
    (0x000001C4, "DRIVER_VERIFIER_DETECTED_VIOLATION_LIVEDUMP"),
    (0xC000021A, "STATUS_SYSTEM_PROCESS_TERMINATED"),
    (0xC0000005, "STATUS_ACCESS_VIOLATION"),
    (0xC0000142, "STATUS_DLL_INIT_FAILED"),
];

/// Returns the symbolic name for a bugcheck stop code, or `"(unknown)"`.
pub fn stop_name(code: u64) -> &'static str {
    STOP_CODES
        .iter()
        .find(|&&(c, _)| c == code)
        .map(|&(_, n)| n)
        .unwrap_or("(unknown)")
}

const REASON_CODES: &[(&str, &str)] = &[
    ("80020001", "OS: Upgrade/Reinstall (planned)"),
    (
        "80020002",
        "OS: Reconfiguration (planned) — typically Windows Update",
    ),
    ("80020003", "Application: Maintenance (planned)"),
    ("80020004", "Application: Installation (planned)"),
    ("80020010", "Hardware: Maintenance (planned)"),
    ("80020011", "Hardware: Installation (planned)"),
    ("80020012", "Hardware: Upgrade (planned)"),
    ("80030001", "OS: Upgrade (unplanned)"),
    ("80030002", "OS: Reconfiguration (unplanned)"),
    ("80030003", "Application: Maintenance (unplanned)"),
    ("80030004", "Application: Unresponsive"),
    ("80030005", "Application: Unstable"),
    ("80030010", "Hardware: Maintenance (unplanned)"),
    ("80030011", "Hardware: Installation (unplanned)"),
    ("80040000", "Hardware failure (unplanned)"),
    ("80040001", "Hardware: Maintenance (unplanned)"),
    ("80040002", "Hardware: Installation (unplanned)"),
    ("80050001", "System failure: Stop error (BSOD)"),
    ("80050002", "System failure: Loss of power (unplanned)"),
    ("80050006", "Power supply failure (unplanned)"),
    ("00040000", "Other (unplanned)"),
    ("00050000", "Other (unplanned)"),
    ("00050001", "Other (planned)"),
    ("00050003", "Legacy API shutdown"),
];

/// Looks up an Event 1074 reason code (accepts `0x` prefix, uppercase, short forms).
/// Returns `None` for codes not in the table.
pub fn decode_reason(code: &str) -> Option<&'static str> {
    let padded = format!(
        "{:0>8}",
        code.trim().to_lowercase().trim_start_matches("0x")
    );
    REASON_CODES
        .iter()
        .find(|&&(c, _)| c == padded)
        .map(|&(_, d)| d)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── stop_name ─────────────────────────────────────────────────────────────

    #[test]
    fn stop_name_known_codes() {
        assert_eq!(stop_name(0x9F), "DRIVER_POWER_STATE_FAILURE");
        assert_eq!(stop_name(0x19C), "WIN32K_POWER_WATCHDOG_TIMEOUT");
        assert_eq!(stop_name(0xFE), "BUGCODE_USB_DRIVER");
        assert_eq!(stop_name(0x144), "BUGCODE_USB3_DRIVER");
        assert_eq!(stop_name(0x50), "PAGE_FAULT_IN_NONPAGED_AREA");
    }

    #[test]
    fn stop_name_unknown() {
        assert_eq!(stop_name(0xDEADBEEF), "(unknown)");
        assert_eq!(stop_name(0), "(unknown)");
    }

    // ── decode_reason ─────────────────────────────────────────────────────────

    #[test]
    fn decode_reason_with_0x_prefix() {
        let r = decode_reason("0x80020002").expect("should be found");
        assert!(r.contains("Windows Update") || r.contains("Reconfiguration"));
    }

    #[test]
    fn decode_reason_without_prefix() {
        assert_eq!(decode_reason("80020002"), decode_reason("0x80020002"));
    }

    #[test]
    fn decode_reason_uppercase_x() {
        assert_eq!(decode_reason("0X80020002"), decode_reason("0x80020002"));
    }

    #[test]
    fn decode_reason_not_found() {
        assert!(decode_reason("DEADBEEF").is_none());
        assert!(decode_reason("00000000").is_none());
    }
}
