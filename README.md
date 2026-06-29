# whyreboot

A command-line tool for Windows that reads the Event Log and tells you *why* your machine last rebooted — crash, forced power-off, update restart, or clean shutdown — and which driver is likely to blame.

```
Scanning Windows Event Log for shutdown/reboot events…
  Found 3 WER BugCheck event(s).
  Found 2 minidump file(s).
  Checked 2 audio device power setting(s).
  Analyzed 1 boot cycle(s).

══════════════════ Boot Cycle 1 of 1 — most recent ══════════════════
  Last boot:   2026-06-28 03:17:44  (21 hours ago)
  Offline:     03:17:01 → 03:17:44  (43s)

  VERDICT:    BLUE SCREEN OF DEATH (BSOD) (95% confidence)
              Stop code 0x0000009F — DRIVER_POWER_STATE_FAILURE
  Module:     portcls [from WER Event 1001]

  Evidence:
    • BugCheck stop code: 0x0000009F (DRIVER_POWER_STATE_FAILURE)
    • P1=3: device object stalled on IRP_MN_SET_POWER (check P4 for device object)
    • Event 6008 confirms previous shutdown was unexpected

  Minidumps:
    2026-06-28 03:17:38  C:\Windows\Minidump\062826-9234-01.dmp

  Device Power Settings (audio):
    Realtek High Definition Audio  AllowIdleIrpInD3=absent (risky default)

  DRIVER_POWER_STATE_FAILURE: portcls failed to complete a power state
  transition in time. Windows was going to sleep, hibernating, or
  shutting down when the driver stalled and never responded.

  Recommended actions:
    1. Set AllowIdleIrpInD3=0 for your audio device:
       regedit → HKLM\SYSTEM\CurrentControlSet\Control\Class\
       {4d36e96c-e325-11ce-bfc1-08002be10318}\0000
       Add DWORD value: AllowIdleIrpInD3 = 0
    2. Update audio drivers (Realtek/Intel HD Audio site or Windows Update).
    3. Update BIOS/UEFI firmware.
```

## Requirements

- Windows 10 or 11
- Rust toolchain (stable, edition 2024)
- No admin rights needed for Event Log or WER data
- Admin rights needed only for reading `C:\Windows\Minidump\` directly (the tool falls back to WER-reported paths without admin)

## Build

```powershell
cargo build --release
```

The binary lands at `target\release\whyreboot.exe`. Copy it anywhere on your `PATH`.

## Usage

```
whyreboot [OPTIONS]

OPTIONS:
  --history N   Show last N boot cycles (default: 1)
  --all         Show all boot cycles in the log
  --json        Output JSON instead of text
  --no-color    Disable ANSI color output
  --help, -h    Show this help
```

**Examples**

```powershell
# Most recent boot cycle only (default)
whyreboot

# Last 5 boot cycles
whyreboot --history 5

# Everything in the log
whyreboot --all

# JSON for scripting
whyreboot --all --json | jq '.cycles[].cause'
```

## What it detects

| Verdict | How |
|---|---|
| Blue Screen (BSOD) | Event 41 with non-zero bugcheck code; faulting driver from WER Event 1001 |
| Forced power-off | Event 41 with non-zero `PowerButtonTimestamp` |
| Unexpected shutdown | Event 41 with no stop code, or Event 6008 alone |
| Windows Update | Event 1074 from TiWorker/TrustedInstaller, or reason code `0x80020002` |
| System/software restart | Event 1074 from SYSTEM or NT AUTHORITY |
| User-initiated | Event 1074 from an interactive user account |
| Normal shutdown | Event 13 (shutdown initiated) or Event 6006 (event log stopped cleanly) |
| Undetermined | Not enough events in the log |

## How it works

See [HowItWorks.md](HowItWorks.md) for a detailed walkthrough of the 8-step pipeline: event fetching, boot-boundary detection, per-cycle slicing, cause classification, WER correlation, minidump matching, registry checks, and explanation generation.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
