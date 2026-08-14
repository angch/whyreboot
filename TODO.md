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



### Drop nightly from the release job when `-Zbuild-std` stabilizes
The Linux release artifact is built on nightly purely to rebuild std without its
`backtrace` feature (216 KB → 125 KB compressed; the machinery can't symbolize
anything anyway because the profile sets `strip = true`). The job falls back to a
stable build if nightly breaks. When build-std is stable, delete the nightly
toolchain step and the fallback, and build with stable directly.

### Other next steps
- More detectors: filesystem-full (`No space left`), network link flaps, watchdog
  reboots, `systemd-coredump` truncation, apparmor/SELinux denials, USB resets.
- Optional `--category <name>` filter and severity threshold (`--min-severity`).
  Cheaper now that `Finding` has typed fields — filter before render, and the
  JSON `schema_version` is in place to describe any shape change.
- Correlate related findings (segfault ↔ coredump ↔ service failure for one pid).
- Wire the resolved `TimeWindow` into the Windows path too (currently `--history N`).
- Extend `tests/fixtures/windows_events.xml` as Windows analysis changes — it is
  the only coverage of that path that runs off Windows.

## Done — maintainability + CI pass (2026-08)

- Shrunk the macOS artifact from ~780 KB to ~555 KB (universal binary) by implementing a nightly `-Zbuild-std` build pipeline with stable fallback in `.github/workflows/release.yml`, similar to Linux.
- Added a robust smoke test to the macOS release job that replays `tests/fixtures/oom.jsonl` and asserts exit 10.
- Ran `whyreboot --all` on a live macOS machine and confirmed the kernel-log detectors scan successfully and report 0 false positives on a healthy system.
- Installed cross-compilation targets (`x86_64-apple-darwin` and `x86_64-pc-windows-gnu`) to ensure we can verify clippy cleanliness across all targets.
- rustfmt across the tree, enforced by a `fmt` job in `.github/workflows/ci.yml`
  and a gate on the release workflow; `.git-blame-ignore-revs` hides the reformat.
- Clippy clean on all three cfg paths (linux host, `x86_64-pc-windows-gnu` for the
  Win32 + GUI code, `x86_64-apple-darwin` for `macos.rs`). A plain Linux clippy run
  covers barely half the codebase — cross-check all three.
- `CycleBounds` derives each cycle's prev/next boot once; the WER/minidump pass
  used to re-derive the same pair under different names.
- `Finding` evidence is typed (`raw` / `related` / `correlations`) instead of
  string-prefix encoded; `tables.rs` holds the stop-code and reason-code tables.
- JSON emitters are pure `String`-returning functions with `schema_version: 1`,
  and their exact shape is asserted in tests.
- `--exit-code` (exit 10 on a critical finding or crash reboot) for cron/monitoring;
  arg parsing now errors on bad/missing values and unknown flags instead of
  silently analyzing a different window; `parse_argv` is unit-tested.
- `--from-file` replays a Windows event-log XML capture through the real analysis,
  so the Windows path finally has end-to-end coverage that runs on Linux CI.

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
- macOS backend: unified-log scan (`log show --style ndjson`) reusing the whole
  findings pipeline — unsafe shutdowns (Previous shutdown cause code table),
  XNU/watchdog panics, sleep/wake failures, ReportCrash app crashes, update
  reboots. Shared ndjson parser (`jsonlog.rs`) auto-detects journald vs
  log-show format, so `--from-file` and Linux CI cover the macOS path; release
  workflow builds/tests a universal (arm64+x86_64) binary on macOS runners.
  Untested on a live Mac — validate and upgrade provenance when one is handy.
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
