# whyreboot

A single-binary command-line tool that diagnoses system issues from the OS logs.

- **Windows:** reads the Event Log and tells you *why* your machine last rebooted — crash, forced power-off, update restart, or clean shutdown — and which driver is likely to blame.
- **Linux:** scans the systemd journal for logged system issues over a time window you choose (`"1 hour ago"`, `"today"`, `"2h"`, …) — starting with **out-of-memory (OOM) kills** and covering kernel panics, segfaults, disk/I-O errors, CPU lockups, thermal trips, hardware (machine-check) errors, failed systemd units, and coredumps. These issues need not have caused a reboot at all.
- **macOS:** scans the unified log (`log show`) over the same time windows for **unsafe shutdowns** (`Previous shutdown cause` codes: power loss, watchdog-forced restarts, thermal/battery trips), kernel panics (including WindowServer watchdog panics), sleep/wake failures, app crashes captured by ReportCrash, and **reboots for software updates** — so an unexplained restart can be told apart from an expected one.

The two platforms share one core: a normalized log stream feeds pluggable detectors that emit findings, rendered as the same text/JSON report.

## Linux quick start

```console
$ whyreboot "1 hour ago"          # issues in the last hour
$ whyreboot today                 # since local midnight
$ whyreboot --since "2 days ago"  # explicit range
$ whyreboot --all --json          # everything, as JSON

Scanning system logs for issues (since 2026-07-09 13:00:00)…
  Scanned 42 record(s); found 1 issue(s).

  [CRITICAL] OOM  2026-07-09 13:22:41
  Kernel OOM killer terminated process 'chrome' (pid 4242)
  source: journald:kernel
    • Victim anonymous RSS: 2.4 GB
    • The kernel ran out of memory and killed the highest-scoring process…
```

Reads the journal via `journalctl` (no root needed if you're in the `systemd-journal` or `adm` group). Use `--from-file <f>` to analyze captured `journalctl -o json` output offline.

## macOS quick start

Same CLI, reading the unified log via `log show` (macOS 10.12+, no root needed):

```console
$ whyreboot "1 hour ago"        # issues in the last hour
$ whyreboot today               # since local midnight
$ whyreboot --json 2d           # last two days, as JSON
```

Note: `log show` scans (it has no field indexes like journald), so wide windows like `--all` can take a while on a long-lived install — prefer bounded ranges. `--from-file` accepts captured `log show --style ndjson` output.

## Windows

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

- Rust toolchain (stable, edition 2024)
- **Windows:** 10 or 11. No admin rights for Event Log/WER data; admin only for reading `C:\Windows\Minidump\` directly (falls back to WER-reported paths without admin).
- **Linux:** systemd with `journalctl` on `PATH`. No root if you're in the `systemd-journal` or `adm` group.

## Build

```console
$ cargo build --release
```

The core binary lands at `target/release/whyreboot`. The Windows GUI (`whyreboot-gui`) is Windows-only; a bare `cargo build` skips it, so the workspace builds on Linux too.

### Fully static Linux binary

```console
$ rustup target add x86_64-unknown-linux-musl
$ cargo build --release --target x86_64-unknown-linux-musl
```

No `musl-tools` or C cross-toolchain needed — the crate has no C dependencies and Rust ships a prebuilt musl libc. The result is a static-pie binary (~520 KB) that runs on any x86-64 Linux regardless of glibc version; `upx --best --lzma` shrinks it to ~215 KB with no measurable startup cost. Release binaries built this way (and UPX-compressed) are published by the GitHub Actions release workflow alongside the Windows ones.

## Usage

```
whyreboot [OPTIONS] [TIME-RANGE]

TIME-RANGE (Linux):
  A duration or phrase: "1 hour ago", "30 minutes ago", "2h", "today",
  "yesterday", or "all". Defaults to the last 24 hours.

OPTIONS:
  --since <expr>   Time range to analyze (aliases: --for, --window)
  --all            Analyze all available history
  --history N      [Windows] show last N boot cycles (default: 1)
  --from-file <f>  [Linux] read journalctl -o json records from a file
  --json           Output JSON instead of text
  --no-color       Disable ANSI color output
  --help, -h       Show this help
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

### Linux (journal issue scan)

| Category | Signals matched |
|---|---|
| OOM | kernel `Out of memory: Killed process …` / `oom-kill:`; `systemd-oomd` memory-pressure & swap kills |
| Kernel panic | `Kernel panic - not syncing`, `BUG: unable to handle`, `Oops:`, `kernel BUG at` |
| Segfault | `segfault at …`, `general protection fault`, `traps:` (extracts `comm[pid]`) |
| Disk / filesystem | `I/O error`, `Buffer I/O error`, `critical medium error`, `EXT4-fs error`, XFS/Btrfs errors, ATA/SATA `exception Emask` / `failed command` / `hard resetting link`, read-only remounts |
| CPU lockup / hung task | `soft lockup`, `hard LOCKUP`, `blocked for more than … seconds`, RCU stalls |
| Thermal | `temperature above threshold`, `critical temperature reached`, clock throttling |
| Hardware (MCE) | `Hardware Error`, `Machine check events logged`, `mce:`, EDAC, `PCIe Bus Error` |
| Service failure | `systemd` unit `Failed with result`, `Main process exited, code=dumped`, `entered failed state` |
| Coredump | `systemd-coredump` `Process … dumped core` |
| GPU hang / reset † | amdgpu `ring … timeout` / `GPU reset begin!` / `VRAM is lost`, i915 `GPU HANG: ecode …` / `stopped heartbeat`, NVIDIA `NVRM: Xid` (app-level codes 13/31/43/45 → warning; `fallen off the bus` → critical), DRM `flip_done timed out` |
| Wayland / X11 session † | clients' `Lost connection to Wayland compositor` / `Error 71 … dispatching to Wayland display`, `gnome-session` `Unrecoverable failure in required component`, Xorg `(EE) Fatal server error` / `(EE) Segmentation fault` |

### macOS (unified log scan) †

| Category | Signals matched |
|---|---|
| Unsafe shutdown | kernel `Previous shutdown cause: N` with a decoded cause table — power loss (0), hard power-off (3), watchdog-forced restart (-61/-62), thermal (-3/-81/-95), battery (-74/-103), disk corruption (-60), … clean shutdowns (5) are not reported |
| Kernel panic | `panic(cpu N caller …)`, incl. `userspace watchdog timeout: no successful checkins from <process>` (names the hung process, classically WindowServer) |
| Sleep/wake failure | `Sleep Wake failure in EFI` |
| App crash | ReportCrash `Saved crash report for App[pid] … .ips` |
| Update reboot | `softwareupdated`/OSInstaller restart activity — expected reboots, listed to distinguish them from unexplained ones |

† Marker strings sourced verbatim from public incident reports / platform documentation but **not yet reproduced against a live incident** — see the provenance table in [HowItWorks.md](HowItWorks.md). A wording mismatch means a silent miss, never a wrong verdict; capture misses with `journalctl -o json` (Linux) or `log show --style ndjson` (macOS) and replay via `--from-file`.

A burst of related lines from one incident (e.g. the ~10 lines a SATA fault emits) is coalesced into a single finding, and a **correlation pass** links cascades: a GPU hang lists the segfaults/coredumps/session losses that followed it, and a compositor crash is linked to every client that lost its connection. Adding a category is one detector function in `src/detect.rs`.

### Windows (reboot diagnosis)

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

See [HowItWorks.md](HowItWorks.md). The **Windows** path runs an 8-step pipeline: event fetching, boot-boundary detection, per-cycle slicing, cause classification, WER correlation, minidump matching, registry checks, and explanation generation. The **Linux** path resolves the time window, pulls matching records from `journalctl -o json`, runs the detector framework over the normalized log stream, coalesces bursts, and renders findings.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
