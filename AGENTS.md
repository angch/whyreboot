# AGENTS.md — whyreboot

Guidance for agentic coders working in this repository. Read this before touching anything.

---

## What this is

`whyreboot` is a single-binary **cross-platform** Rust CLI that diagnoses system issues from OS logs.

- **Windows:** diagnoses why the machine last rebooted, querying the Windows Event Log (System channel) and Windows Error Reporting (Application channel) for crash causes, faulting drivers, and power-management misconfigurations. This is the original tool; its logic is unchanged.
- **Linux:** scans the systemd journal (`journalctl`) over a time window for logged system issues — OOM kills, kernel panics, segfaults, disk/I-O errors, lockups, thermal trips, hardware/MCE errors, failed units, coredumps — emitting generic `Finding`s. Issues need not have caused a reboot.

The two platforms share a portable core (data model, timestamp, analysis logic) and diverge only in the log-source backend and the top-level report style. `cfg(windows)` / `cfg(target_os = "linux")` gate the backends; a bare `cargo build`/`cargo test` builds the core crate on any platform (the Win32 GUI is excluded via `default-members`).

**Windows binary:** `C:\Users\angch\.local\bin\whyreboot.exe` (on PATH)  
**Build (Windows):** `cargo build --release && copy target\release\whyreboot.exe C:\Users\angch\.local\bin\`  
**Build/test (Linux):** `cargo build` / `cargo test` (skips the Windows-only GUI).  
**No admin/root required** for most data — Windows System channel is readable by standard users (`C:\Windows\Minidump` needs admin, falls back to WER AttachedFiles); Linux `journalctl` is readable by the `systemd-journal`/`adm` groups.

---

## Cross-platform architecture (read this first)

```
Portable core (compiles + unit-tested on every platform):
  types.rs      — data model: EventRecord/BootCycle/Cause (Windows) AND
                  the generic Finding/Severity/LogLine (both)
  timestamp.rs  — i64 Unix-epoch Timestamp; portable UTC formatting (pure-Rust
                  Hinnant civil-day algos), local time via Win32 OR libc localtime_r
  timewindow.rs — parse "1 hour ago" / "today" / "2h" → concrete TimeWindow
  detect.rs     — detector framework: fn(&LogLine)->Option<Finding>, runs all,
                  coalesces bursts; the Linux issue taxonomy lives here
  oom.rs        — OOM detectors (kernel oom-killer + systemd-oomd)
  analysis.rs/format.rs/xml.rs — Windows boot-cycle logic (pure; still tested on Linux)

Windows backend  (#[cfg(windows)]):        events.rs, registry.rs
Linux backend    (#[cfg(target_os="linux")]): linux.rs (journalctl -o json source)
Binary (main.rs): cfg-dispatch — run_windows() vs run_linux()
display.rs (binary module): print_findings[_json] (portable) + print_cycle/print_json (#[cfg(windows)])
```

**Adding a Linux detector:** write one `fn(&LogLine) -> Option<Finding>` in `detect.rs` and add it to the `DETECTORS` array. Kernel-log categories need nothing more — `fetch_journal` pulls `-k` **unfiltered** within the window, so any kernel line reaches the detectors. A *userspace/systemd* category (non-kernel) must be reachable by one of the **indexed** queries in `fetch_journal` — currently `SYSLOG_IDENTIFIER=systemd`/`systemd-coredump` at priority ≥ notice. If your source is a different identifier or logs below notice, add an indexed query for it (see the perf note below). Add a fixture line to `tests/fixtures/`. Nothing else changes — display/JSON/CLI already handle arbitrary findings.

**False positives — gate bare subsystem markers:** driver-init banners logged at every boot contain subsystem names without any error (`EDAC MC: Ver: 3.0.0`, `mce: CPU supports 32 MCE banks`, `EXT4-fs (sda3): mounted filesystem … ro`). A detector marker that is a bare name/prefix must require an error indication in the same message (`error`/`fail`/`corrupt`/`warning` or ` CE `/` UE `); see `detect_hardware`/`detect_disk_io`. Before adding a marker, check what that subsystem logs at boot (`journalctl -k -b | grep -i <name>`), and vet with `whyreboot --all` on a healthy machine — the kernel side should report nothing.

**Performance — never `--grep`:** `fetch_journal` matches only journald-*indexed* fields (`_TRANSPORT`, `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `PRIORITY`) and uses `--output-fields` to trim records. `--grep` is an unindexed full-message scan: on this machine's 2.3 GB journal it never finished for `--all`; the indexed queries return in ~0.5 s. Do **not** reintroduce `--grep` to widen coverage — add an indexed query instead, and let the detectors filter precisely.

**Timestamp gotcha:** only `now`/arithmetic/`from_rfc3339`/`to_rfc3339` are portable. Local-time rendering (`format_dt`/`format_t`) is platform-specific (Win32 vs libc). chrono was deliberately removed (commit 97f106b); do not reintroduce it — libc `localtime_r` covers local time at near-zero weight.

**Testing the Linux path:** detectors and the journal JSON parser are pure and unit-tested. End-to-end coverage runs fixtures through `fetch_from_file` → `detect::scan` (`tests/oom_e2e.rs`, fixtures in `tests/fixtures/*.jsonl` — one `journalctl -o json` object per line). The `--from-file` flag is the injectable seam; use it to analyze captured journals offline too.

---

## Repository layout

```
src/main.rs        — CLI args + cfg-dispatched entry (run_windows / run_linux)
src/types.rs       — shared structs/enums: Windows (EventRecord/BootCycle/Cause)
                     + generic (Finding/Severity/LogLine)
src/timestamp.rs   — portable Timestamp; UTC pure-Rust, local via Win32/libc
src/timewindow.rs  — parse human time ranges → TimeWindow  [portable]
src/detect.rs      — detector framework + Linux issue taxonomy  [portable]
src/oom.rs         — OOM detectors (kernel + systemd-oomd)  [portable]
src/xml.rs         — hand-rolled XML parsing (no external dep)  [portable]
src/analysis.rs    — boot cycle analysis, lookup tables, WER correlation  [portable]
src/format.rs      — cause labels, explanations, formatting  [portable]
src/color.rs       — ANSI palette; enable via Win32 VTP / unix isatty
src/events.rs      — System + WER event fetching, minidump listing  [cfg(windows)]
src/registry.rs    — registry helpers + audio power settings check  [cfg(windows)]
src/linux.rs       — journalctl -o json source + flat-JSON parser  [cfg(linux)]
src/display.rs     — findings output (portable) + boot-cycle output (cfg(windows))
tests/oom_e2e.rs   — end-to-end: fixture → detect::scan
tests/fixtures/    — journalctl -o json sample lines (oom.jsonl, mixed.jsonl)
Cargo.toml         — windows dep is target-gated; libc for unix; default-members=["."]
HowItWorks.md      — full narrative of the analysis pipeline and decision logic
TODO.md            — feature tracking
HANDOFF.md         — early session notes (mostly superseded by this file)
```

**Keep `HowItWorks.md` in sync** when modifying the analysis decision tree (`analyze_slice`, `classify_event41`, `classify_event1074`), the WER/minidump correlation windows, the device power check logic, or the explanation patterns in `generate_explanation`. The doc describes the exact logic, not just the concept.

---

## Architecture

### Data flow

```
fetch_system_events()  → Vec<EventRecord>   (System channel: boot/shutdown events)
fetch_wer_events()     → Vec<WerRecord>     (Application channel: WER BugCheck Event 1001)
list_minidumps()       → Vec<(DateTime, PathBuf)>   (C:\Windows\Minidump, admin-only)
check_audio_power_settings() → Vec<AudioPowerInfo>  (Registry: audio class power config)
        ↓
extract_boot_cycles()  → Vec<BootCycle>
        ↓
print_cycle() / print_json()
```

### Event ordering

`EvtQueryReverseDirection` returns events **newest first** (index 0 = most recent).  
`collect_boot_indices()` finds all Kernel-General Event 12 positions.

For boot cycle N (index 0 = current boot):
- `boot_idx = boot_idxs[N]`
- `post_boot = events[post_start..boot_idx]` — events logged **at this boot** (lower indices than the boot marker), which report the fate of the *previous* session
- `pre_boot = events[boot_idx+1..pre_end]` — events logged *during* the previous session before it ended

**Critical:** Event 41 (Kernel-Power unexpected shutdown) and Event 6008 are logged at the *next* boot to report the previous crash. They appear in `post_boot`. Events 13, 6006, 1074 (clean shutdowns) are logged during the shutdown itself — they appear in `pre_boot`.

### WER-to-cycle matching

WER (Windows Error Reporting) processes crash dumps during the boot *after* the crash. So for a BSOD in cycle N:
- WER events appear with `time_created >= boot_times[N]` (the boot after the crash)
- Match by `w.p1 == stop_code` (WER P1 field = bugcheck stop code)

---

## Windows API details

### Event Log (windows feature: `Win32_System_EventLog`)

Key functions used: `EvtQuery`, `EvtNext`, `EvtRender(EvtRenderEventXml)`, `EvtClose`  
`EVT_HANDLE` is treated as `isize` (it's `#[repr(transparent)]` over isize).  
Batch size: 16 handles per `EvtNext` call.

### WER Event 1001 XML — critical field names (discovered by inspecting raw XML)

These are non-obvious and were discovered by running `$ev.ToXml()` in PowerShell:

| Field purpose | Correct XML field name | Wrong names to avoid |
|---|---|---|
| Crash type | `EventName` = `"BlueScreen"` | NOT `"BugCheck"` |
| Stop code (hex, no 0x) | `P1` e.g. `"9f"` | P1 is bare hex, not decimal |
| Fault bucket string | `Bucket` | NOT `BucketId`, NOT `HashedBucket` |
| Minidump path | `AttachedFiles` (first line ending `.dmp`) | — |

**P1 parsing:** `u64::from_str_radix(s.trim(), 16)` — NOT `hex_u64()` which requires `0x` prefix.

**Bucket examples:**
- `0x9F_3_DXG_POWER_IRP_TIMEOUT_portcls!GetIrpDisposition` → module `portcls`
- `0x9F_3_usbccgp!WaitForSignal` → module `usbccgp`
- `0x9F_3_usbccgp_IMAGE_UsbHub3.sys` → module `UsbHub3.sys`

**Module extraction priority** (in `module_from_bucket()`):
1. `module!function` pattern — extract the token before `!` (after last `_`)
2. `_IMAGE_module.sys` pattern — extract after `_image_`
3. Fallback: tokens ending in `.sys`/`.exe`/`.dll`

**Minidump path:** Strip `\\?\` UNC prefix with `trim_start_matches(r"\\?\")`.

### Registry (windows feature: `Win32_System_Registry`)

`RegOpenKeyExW` in windows 0.62: the `uloptions` parameter is `Option<u32>` — pass `None`, not `0`.  
`RegQueryValueExW` and `RegOpenKeyExW` return `WIN32_ERROR`; call `.ok().is_ok()` to convert to `bool`.  
In Rust 2024 edition: unsafe calls inside `unsafe fn` still require `unsafe {}` blocks.

### Console color (windows feature: `Win32_System_Console`)

`ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004`  
Must call `SetConsoleMode(stdout_handle, existing_mode | 0x0004)` to enable ANSI escapes.

---

## This machine's crash history (as of 2026-06-29)

Recurring `DRIVER_POWER_STATE_FAILURE` (0x9F) BSODs:

| Date | Stop code | Module (from WER) | P1 meaning |
|---|---|---|---|
| Jun 14, 2026 | 0x9F | `portcls` | P1=3: stalled on IRP_MN_SET_POWER |
| Jun 18, 2026 | 0x9F | `portcls` | P1=3 |
| Jun 21, 2026 | 0x19C | `dxgkrnl` | WIN32K_POWER_WATCHDOG_TIMEOUT |
| Jun 24, 2026 | 0x9F | `usbccgp` | USB Generic Parent stalled |
| Jun 28, 2026 | 0x9F | `portcls` | P1=3, most recent crash |

**Root cause hypothesis:** The Realtek/Intel HD Audio driver (`portcls.sys` / `RTKVHD64.sys`) fails during system sleep/shutdown power transitions. The audio controller is being put into D3 (deepest sleep) but `portcls` stalls responding to the `IRP_MN_SET_POWER` request.

**Registry check result:** `AllowIdleIrpInD3` is **absent** for all 11 audio class instances — none have disabled idle D3 entry. This is the risky driver-default configuration.

**Fix:** Set `AllowIdleIrpInD3=0` (DWORD) for each audio class instance:
```powershell
$base = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}"
0..10 | ForEach-Object {
    $key = "$base\$('{0:D4}' -f $_)"
    if (Test-Path $key) { Set-ItemProperty $key -Name AllowIdleIrpInD3 -Value 0 -Type DWord }
}
```

**Realtek device instance:** `HDAUDIO\FUNC_01&VEN_10EC&DEV_0295&SUBSYS_10280A6E&REV_1000\5&5C8DBF4&0&0001`  
**Driver:** `RTKVHD64.sys` version 6.0.9433.1 (2022-11-01) — outdated, update recommended  
**Audio class GUID:** `{4d36e96c-e325-11ce-bfc1-08002be10318}`  
**Note:** `DEVPKEY_Device_PowerData` shows `NoDisplayInUI` flag set — Power Management tab may not appear in Device Manager for this device.

---

## Key data structures

```rust
struct EventRecord { event_id, time_created, provider, data: HashMap<String,String> }
struct WerRecord { time_created, p1: u64, bucket_id: String, minidump_path: Option<PathBuf> }
struct AudioPowerInfo { instance, name, allow_idle_d3: Option<u32>, enhanced_pm: Option<u32> }

enum Cause {
    BlueScreen { stop_code: u64, stop_name: &'static str, params: [u64; 4] },
    ForcedPowerOff, UnexpectedShutdown,
    WindowsUpdate { process }, UserAction { user, action, comment },
    SystemProcess { process, reason, action },
    NormalShutdown, Undetermined,
}

struct BootCycle {
    index, boot_time, shutdown_time, cause, confidence: u8,
    evidence: Vec<String>, timeline: Vec<(DateTime, String)>,
    wer_module: Option<String>, minidumps: Vec<(DateTime, PathBuf)>,
    display_events: Vec<EventRecord>,
}
```

---

## Output sections (text mode)

Each `BootCycle` prints:
1. **Header** — boot time, offline duration
2. **VERDICT** — cause label + detail + confidence
3. **Module** — faulting driver (from WER), if available
4. **Evidence** — bullet list
5. **Timeline** — sorted events
6. **Minidumps** — paths (filesystem or from WER AttachedFiles)
7. **Device Power Settings** — audio class registry state (shown only for power-related BSODs with audio module)
8. **Explanation** — plain-English diagnosis + remediation steps (shown for known stop code + module combos: 0x9F, 0x19C, 0xFE/0x144)
9. **Event table** — raw event log rows

---

## CLI flags

```
--history N     show last N boot cycles (default: 1)
--all           show all cycles in the log
--json          JSON output
--no-color      disable ANSI color
--help / -h
```

---

## Known pitfalls and constraints

- **No XML dep:** XML parsing is hand-rolled (`xml_attr`, `xml_elem`, `xml_data`). Don't add `serde-xml` or similar.
- **Edition 2024:** `unsafe fn` bodies require explicit `unsafe {}` blocks around unsafe calls — the compiler warns without them and will error in future editions.
- **`EvtQueryReverseDirection`:** The constant is accessed as `.0` on the bitflag enum. Combined with `EvtQueryChannelPath.0` using bitwise OR on the raw `u32`.
- **WER filter:** Must accept `EventName == "BlueScreen"` OR `"BugCheck"` — real events use `BlueScreen` but accept both defensively.
- **Minidump annotation ordering:** Set filesystem minidumps first, then supplement from WER AttachedFiles only if filesystem found nothing. Reversing this order causes WER paths to be overwritten by empty filesystem results.
- **Cycle 0 = current (most recent) boot.** Print order is reversed (`cycles.iter().rev()`) so most recent appears last in terminal output.
- **`check_audio_power_settings()` iterates instances 0000–0020.** Skips any instance where `DriverDesc` and `FriendlyName` are both absent (not a real device entry).
