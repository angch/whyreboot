# TODO

## Open

### `/var/log/*` fallback for non-systemd hosts
When `journalctl` is absent or unreadable, fall back to reading classic log files
(`/var/log/kern.log`, `/var/log/syslog`, `/var/log/messages`, `dmesg`), including
`.gz`-rotated files. Parse each syslog line ("`Mon DD HH:MM:SS host ident[pid]: msg`")
into a `LogLine` and run the existing detectors unchanged — only the source adapter
is new. Note syslog timestamps lack a year and are local time, so infer the year
from the window and convert to `Timestamp`.

### Validate internet-sourced detectors on live incidents
GPU, Session, and most kernel-fault detectors are built from third-party
incident reports / canonical formats and have **never seen a live incident**
(see the provenance table in HowItWorks.md and `Provenance:` notes in
detect.rs). When a real GPU hang / compositor crash / OOM happens on real
hardware: capture `journalctl -o json` around it, replay with `--from-file`,
fix any misses, and upgrade the detector's provenance note to verified-live.

### Other next steps
- More detectors: filesystem-full (`No space left`), network link flaps, watchdog
  reboots, `systemd-coredump` truncation, apparmor/SELinux denials, USB resets.
- Optional `--category <name>` filter and severity threshold (`--min-severity`).
- Correlate related findings (segfault ↔ coredump ↔ service failure for one pid).
- Wire the resolved `TimeWindow` into the Windows path too (currently `--history N`).

## Done — cross-platform generalization (2026-07)

- Made the crate build/test on Linux: `windows` dep target-gated, Win32 modules
  behind `#[cfg(windows)]`, GUI excluded via `default-members`.
- Portable `Timestamp` (pure-Rust UTC; local time via libc `localtime_r` on unix).
- `TimeWindow` parser ("1 hour ago" / "today" / "2h" / "all").
- Generic `Finding`/`Severity` model + detector framework (`detect.rs`) with burst
  coalescing; Linux journal source (`linux.rs`, `journalctl -o json`).
- Detectors: OOM (kernel + systemd-oomd), kernel panic, segfault, disk/I-O,
  lockup/hung-task, thermal, hardware/MCE, service failure, coredump.
- Perf: `whyreboot --all` went from never-finishing (unindexed whole-journal
  `--grep` over 2.3 GB) to ~0.5 s by querying only journald-indexed fields
  (`_TRANSPORT`, `SYSLOG_IDENTIFIER`, `PRIORITY`) + `--output-fields`.
- Release: fully static Linux binary (x86_64 musl, static-pie, ~520 KB;
  UPX → ~215 KB) built, tested, and published by the GitHub Actions release
  workflow as `whyreboot-cli-x86_64-linux`. If UPX ever trips AV false
  positives, ship the uncompressed musl binary alongside.
- GPU + Wayland/X11 session detection with cascade correlation: GPU
  hangs/resets (amdgpu incl. MES-era Strix Halo sequences, i915, NVIDIA Xid),
  compositor-loss and Xorg fatals; a correlation pass links a GPU incident to
  the segfaults/coredumps/session losses that follow, and a compositor crash
  to the clients it orphaned.

## Hardware investigation notes

Based on the evidence gathered so far:

- `portcls` (audio kernel driver) appears in most BSODs — disable audio device power
  management: Device Manager → audio adapter → Power Management → uncheck
  "Allow the computer to turn off this device to save power"
- Also check for Realtek/Intel HD Audio driver updates
- `dxgkrnl` crash (Jun 21) = graphics driver power issue — update GPU driver if not current
- `usbccgp` crash (Jun 24) = USB device stalled on power transition — disconnect USB
  devices before sleep/shutdown as a workaround
