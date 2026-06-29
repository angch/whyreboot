# TODO

## High priority

- [x] **Query Application channel for Event 1001 (WER BugCheck)**
  Implemented. Queries Application channel for EventID=1001 from Windows Error Reporting.
  Extracts faulting module from the `Bucket` data field (e.g., `portcls`, `usbccgp`, `dxgkrnl`).
  Also extracts minidump path from the `AttachedFiles` field.
  Key finding: WER uses `EventName=BlueScreen` (not "BugCheck"), and P1 is bare hex (no 0x prefix).

- [x] **Show full reboot history, not just the most recent**
  Implemented. Use `--all` to show all boot cycles, `--history N` for last N.
  Correctly handles multiple Kernel-General Event 12 boundaries.

## Medium priority

- [x] **Identify the faulting driver for DRIVER_POWER_STATE_FAILURE**
  Done via WER Event 1001 BucketId field. Recurring pattern:
  - Jun 21: `dxgkrnl` (0x19C WIN32K_POWER_WATCHDOG_TIMEOUT) → DirectX Graphics Kernel
  - Jun 24: `usbccgp` (0x9F) → USB Class Generic Parent
  - Jun 28: `portcls` (0x9F) → Port Class audio driver kernel
  The `portcls` / audio driver failure during power transitions is the likely culprit
  (also seen on Jun 14 and Jun 18 per WER history).

- [x] **Handle truncated / missing boot event**
  If no Kernel-General Event 12 found, falls back to analyzing all events as a single
  cycle with boot_time=None.

- [x] **Expand stop-code table**
  Expanded from 17 to ~70 entries. Added 0x19C (WIN32K_POWER_WATCHDOG_TIMEOUT) and
  many other common codes.

- [x] **Decode reason codes for Event 1074 more completely**
  Expanded REASON_CODES from 6 to 24 entries covering the full SHTDN_REASON_* set.

## Low priority / nice to have

- [ ] **Release build + install script**
  `cargo build --release` then copy `target\release\whyreboot.exe` to
  `C:\Users\angch\.local\bin\` (already on PATH).

- [x] **Color output**
  ANSI color via Win32 `SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING)`.
  Red=crash, yellow=undetermined, green=clean. Use `--no-color` to disable.

- [x] **`--history N` flag**
  Implemented. `--history N` shows last N cycles, `--all` shows all.

- [x] **`--json` flag**
  Implemented. Outputs JSON with all cycle fields including faulting module and minidump paths.

- [x] **Check minidump directory**
  Done. First tries `C:\Windows\Minidump\` via filesystem (may require admin).
  Falls back to minidump paths extracted from WER Event 1001 `AttachedFiles` field
  (works without admin).

## Remaining action items for the hardware issue

Based on the evidence gathered:
- `portcls` (audio kernel driver) appears in most BSODs — try disabling audio device power
  management in Device Manager → audio adapter → Power Management → uncheck "Allow the
  computer to turn off this device to save power"
- Also check for Realtek/Intel HD Audio driver updates
- `dxgkrnl` crash (Jun 21) = graphics driver power issue — update GPU driver if not current
- `usbccgp` crash (Jun 24) = USB device stalled on power transition — disconnect USB devices
  before sleep/shutdown as a workaround
