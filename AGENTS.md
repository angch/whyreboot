# AGENTS.md — whyreboot

Guidance for agentic coders working in this repository. Read this before touching anything.

---

## What this is

`whyreboot` is a single-binary **cross-platform** Rust CLI that diagnoses system issues from OS logs.

- **Windows:** diagnoses why the machine last rebooted, querying the Windows Event Log (System channel) and Windows Error Reporting (Application channel) for crash causes, faulting drivers, and power-management misconfigurations. This is the original tool; its logic is unchanged.
- **Linux:** scans the systemd journal (`journalctl`) over a time window for logged system issues — OOM kills, kernel panics, segfaults, disk/I-O errors, lockups, thermal trips, hardware/MCE errors, failed units, coredumps — emitting generic `Finding`s. Issues need not have caused a reboot.
- **macOS:** same findings pipeline over the unified log (`log show --style ndjson`): unsafe shutdowns (`Previous shutdown cause` code table), XNU panics (incl. WindowServer watchdog), sleep/wake failures, ReportCrash app crashes, update reboots. Backend in `macos.rs`; detectors are portable and fixture-tested on Linux CI; the release workflow builds/tests a universal binary on macOS runners. No live Mac was used in development — provenance is third-party.

The two platforms share a portable core (data model, timestamp, analysis logic) and diverge only in the log-source backend and the top-level report style. `cfg(windows)` / `cfg(target_os = "linux")` gate the backends; a bare `cargo build`/`cargo test` builds the core crate on any platform (the Win32 GUI is excluded via `default-members`).

**Windows binary:** `C:\Users\angch\.local\bin\whyreboot.exe` (on PATH)  
**Build (Windows):** `cargo build --release && copy target\release\whyreboot.exe C:\Users\angch\.local\bin\`  
**Build/test (Linux):** `cargo build` / `cargo test` (skips the Windows-only GUI).  
**Static Linux release:** `cargo build --release --target x86_64-unknown-linux-musl` — no `musl-tools`/C toolchain needed (no C deps; rust-std ships musl libc). Produces a static binary (~528 KB; UPX → ~216 KB, no startup cost). **The release workflow builds the shipped artifact on nightly with `-Zbuild-std` instead (~301 KB, UPX → ~125 KB) — see "Binary size" below.** A plain stable build is still correct, just larger. The release workflow builds/tests/uploads this as `whyreboot-cli-x86_64-linux`; its `file`/`ldd` step asserts the binary really is static, so don't add a crate with a C build dependency without updating that job.  
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

**Provenance discipline:** every detector in `detect.rs` carries a `Provenance:` doc note — `verified-live` (matched a real event in a live journal), `third-party logs` (markers verbatim from public incident reports, never reproduced live), or `canonical format` (from kernel/systemd source/docs, fixture-tested only). When adding or editing a detector, set this honestly; when a real incident validates a pattern, upgrade the note. The user-facing summary lives in HowItWorks.md ("Marker provenance").

**False positives — gate bare subsystem markers:** driver-init banners logged at every boot contain subsystem names without any error (`EDAC MC: Ver: 3.0.0`, `mce: CPU supports 32 MCE banks`, `EXT4-fs (sda3): mounted filesystem … ro`). A detector marker that is a bare name/prefix must require an error indication in the same message (`error`/`fail`/`corrupt`/`warning` or ` CE `/` UE `); see `detect_hardware`/`detect_disk_io`. Before adding a marker, check what that subsystem logs at boot (`journalctl -k -b | grep -i <name>`), and vet with `whyreboot --all` on a healthy machine — the kernel side should report nothing.

**Acronym markers: case-sensitive only.** Found live on a real Mac: case-insensitive `EDAC` matched inside macOS's literal `<IPv4-redacted>` privacy token ("red-edac-ted") in kernel tcp_connection_summary lines, and `so_error: 0` satisfied the error gate → bogus ECC finding. The kernel logs `EDAC`/`MCE` uppercase, `mce:` lowercase — match acronyms with plain `str::contains`, never `first_of`/`contains_ci`.

**Performance — never `--grep`:** `fetch_journal` matches only journald-*indexed* fields (`_TRANSPORT`, `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `PRIORITY`) and uses `--output-fields` to trim records. `--grep` is an unindexed full-message scan: on this machine's 2.3 GB journal it never finished for `--all`; the indexed queries return in ~0.5 s. Do **not** reintroduce `--grep` to widen coverage — add an indexed query instead, and let the detectors filter precisely.

**Timestamp gotcha:** only `now`/arithmetic/`from_rfc3339`/`to_rfc3339` are portable. Local-time rendering (`format_dt`/`format_t`) is platform-specific (Win32 vs libc). chrono was deliberately removed (commit 97f106b); do not reintroduce it — libc `localtime_r` covers local time at near-zero weight.

**Testing the Linux path:** detectors and the journal JSON parser are pure and unit-tested. End-to-end coverage runs fixtures through `fetch_from_file` → `detect::scan` (`tests/oom_e2e.rs`, fixtures in `tests/fixtures/*.jsonl` — one `journalctl -o json` object per line). The `--from-file` flag is the injectable seam; use it to analyze captured journals offline too.

**Testing the Windows path without Windows:** `--from-file` also accepts an event-log XML capture (`wevtutil qe System /f:xml`, or `Get-WinEvent | %{ $_.ToXml() }`), parsed by the portable `xml::parse_event_log`. `tests/windows_replay.rs` drives a captured BSOD through `extract_boot_cycles` and asserts the verdict, the faulting module, and the driver-install correlation — and it runs on Linux/macOS CI. Only the live `EvtQuery` fetch is Windows-only, so **any change to the Windows analysis should be covered by extending that fixture**, not deferred until someone is at a Windows box.

**`Finding` evidence is typed, not prefix-encoded.** `evidence` holds the detector's own bullets; the triggering line is `raw`, coalesced burst siblings are `related`, and the correlation pass writes `correlations`. These used to share one `Vec<String>` distinguished by `"Raw: "` / `"+ related: "` prefixes that later passes re-parsed. Don't reintroduce that: a detector bullet that happened to start with those words corrupted burst counting. `Finding::detail_lines()` flattens them in display order when you need the old view.

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
src/xml.rs         — hand-rolled XML parsing + `parse_event_log` capture replay  [portable]
src/analysis.rs    — boot cycle analysis, WER mapping/correlation  [portable]
src/tables.rs      — bugcheck stop codes + Event 1074 reason codes  [portable]
src/format.rs      — cause labels, explanations, formatting  [portable]
src/color.rs       — ANSI palette; enable via Win32 VTP / unix isatty
src/events.rs      — System + WER event fetching, minidump listing  [cfg(windows)]
src/registry.rs    — registry helpers + audio power settings check  [cfg(windows)]
src/jsonlog.rs     — shared ndjson parser: journald + macOS log-show formats  [portable]
src/linux.rs       — journalctl -o json source (indexed queries)  [cfg(linux)]
src/macos.rs       — macOS `log show --style ndjson` source  [cfg(macos)]
src/display.rs     — findings output (portable) + boot-cycle output (cfg(windows))
tests/oom_e2e.rs   — end-to-end: fixture → detect::scan
tests/windows_replay.rs — end-to-end: event-XML capture → extract_boot_cycles
tests/fixtures/    — journalctl -o json sample lines (oom.jsonl, mixed.jsonl)
                     + windows_events.xml (event-log capture)
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
--since <expr>  time range to analyze (aliases: --for, --window)
--all           analyze all available history
--exit-code     exit 10 if a critical issue (or crash reboot) was found
--history N     [Windows] show last N boot cycles (default: 1)
--from-file <f> replay a capture: journald/log-show ndjson, or Windows event XML
--json          JSON output
--no-color      disable ANSI color
--help / -h
```

**Exit codes:** `0` success, `1` operational failure (no logs readable / empty capture), `2` usage error, `10` issues found with `--exit-code`. Keep them distinct — a monitoring script needs to tell "scan worked, found a crash" from "scan failed". Argument parsing **errors** on a bad or missing value rather than falling back silently (`--history abc`, a valueless `--since`, unknown `--flags`); `parse_argv` is pure and unit-tested in `main.rs`.

**JSON output carries `schema_version`** (currently `1`) as the first field of both documents. Bump it on any breaking change — renamed/removed field or changed type; purely additive fields don't need one. Both emitters are pure functions returning a `String` (`findings_json` / `cycles_json`), with the `print_*` wrappers only adding `println!`, so the exact shape is asserted in tests.

---

## Code formatting — non-negotiable

**Every commit must be `rustfmt`-clean.** Run `cargo fmt` before committing and verify with:

```
cargo fmt --check    # must exit 0 and print nothing
```

The whole tree was normalized in one pass (v0.5.0); do not reintroduce hand-formatting. In particular, **no gofmt-style column alignment** — rustfmt collapses these and will fight you forever:

```rust
// WRONG — hand-aligned, rustfmt will rewrite it
Finding { time:     line.time,
          severity: Severity::Critical, }
let pid  = first_number(after);
let comm = between(after, '(', ')');

// RIGHT — let rustfmt decide
Finding { time: line.time, severity: Severity::Critical }
let pid = first_number(after);
let comm = between(after, '(', ')');
```

The same applies to manually packed multi-argument calls (the Win32 `CreateWindowExW` calls in `gui/`) and aligned `match` arms — write it however, then run `cargo fmt` and commit what it produces.

There is no `rustfmt.toml`; default rustfmt settings are the standard. If you genuinely need to preserve a hand layout (e.g. a table-like `const` array), use a targeted `#[rustfmt::skip]` on that item and say why in a comment — never disable formatting repo-wide.

Note `cargo fmt` covers the workspace including `gui/`, which is excluded from `default-members` for build/test — so `cargo fmt --all --check` on Linux still checks the Windows-only GUI sources.

**This is enforced in CI**, not just documented: the `fmt` job in `.github/workflows/ci.yml` runs on every push to `main` and every PR, and `.github/workflows/release.yml` has a `fmt` gate that all three build jobs depend on — an unformatted tree fails the tag build before any binary is produced.

The one-shot reformat commit is listed in `.git-blame-ignore-revs` so it doesn't pollute history. Run this once per clone to make local blame skip it (GitHub's blame view honours the file automatically):

```
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

---

## Binary size

The shipped Linux artifact is a static musl binary, UPX-compressed by the release workflow. `.cargo/config.toml` adds `-C relocation-model=static` for that target (non-PIE; see the file for the ASLR trade-off). The release profile is otherwise fully size-tuned already — `opt-level="z"`, fat LTO, `codegen-units=1`, `strip`, `panic="abort"` — so there is nothing left to win there.

Measured composition (`nm -S -C` on an unstripped build, grouped by symbol origin):

| | bytes | |
|---|---:|---|
| panic backtrace + unwinder (gimli, addr2line, miniz_oxide, rustc_demangle, libunwind) | 218,826 | 40% |
| rest of std/core/alloc/musl | 167,044 | 31% |
| **whyreboot's own code** | **34,964** | 6% |

**Our code is 6% of the binary**, so micro-optimizing it is not where the size is. Two rules that do matter:

- **Don't format floats.** A single `{:.1}` on an `f64` links all of `core::fmt::float` plus musl's `fmt_fp`/`printf_core` — **16 KB**, measured, for one decimal place. `oom::one_decimal` does it with integer math. Check whether integers will do before adding any float formatting.
- **Watch monomorphization over `Finding`.** It is a large struct; each distinct `sort_by_key` closure instantiates its own copy of the sort (~1.5 KB). `detect::scan` deliberately keeps two — see the comment there for why `reverse()` is not a valid substitute.

### The 40%: panic machinery, and what it's worth

`strip = true` means that machinery **cannot symbolize anything**. A real panic in the shipped binary prints:

```
thread 'main' panicked at src/main.rs:4:21:
index out of bounds: the len is 3 but the index is 99
stack backtrace:
   0:           0x412ffa - <unknown>
   1:           0x406804 - <unknown>
```

218 KB to print hex addresses. Rebuilding std without its `backtrace` feature removes it and keeps the part that is actually diagnostic (message + file:line). Measured on this machine, all three verified by forcing a real panic:

| build | raw | UPX | on panic |
|---|---:|---:|---|
| **stable, as shipped** | 528,464 | 215,952 | message + `<unknown>` frames |
| build-std, no `backtrace` feature | 300,808 | 124,720 | message + file:line, no frames |
| build-std + `panic=immediate-abort` | 181,920 | 84,328 | **nothing** — silent abort |

`immediate-abort` is the smallest and the wrong trade for a diagnostic tool: a bug becomes an unexplained `SIGILL` with no message and no way for a user to report it usefully.

**The middle row is what ships.** The `build-linux` release job builds it on nightly:

```
rustup toolchain install nightly --component rust-src
rustup target add x86_64-unknown-linux-musl --toolchain nightly   # self-contained CRT + libunwind.a
cargo +nightly build --release --target x86_64-unknown-linux-musl \
  -Zbuild-std=std,panic_abort -Zbuild-std-features=
```

Notes for anyone touching that job:

- **Don't set `RUSTFLAGS`** in the workflow. It would override `.cargo/config.toml`, and the non-PIE flag lives there.
- `-Zbuild-std-features=` (empty) is the load-bearing part: it drops std's default features, `backtrace` among them. Without it you rebuild std and save nothing.
- Tests run on `+stable`; the nightly std swap doesn't change this crate's logic, and building std from source for the test profile too would only cost minutes.
- The job **falls back to a stable build** if the nightly one fails, so a nightly regression can't block a release — it just ships the larger binary with a warning annotation.
- The cache key is separate (`-cargo-buildstd-`) because that `target/` holds a from-source std.
- `musl-tools` is only needed if you link with `musl-gcc` instead of the self-contained CRT. Without the nightly musl target installed, point at the stable toolchain's copy: `-C linker=musl-gcc -C link-self-contained=no -C link-arg=-L$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained`.

**Revert to a plain stable build once `build-std` stabilizes** — that is the only reason nightly is in the release path.

---

## Known pitfalls and constraints

- **No XML dep:** XML parsing is hand-rolled (`xml_attr`, `xml_elem`, `xml_data`). Don't add `serde-xml` or similar.
- **Edition 2024:** `unsafe fn` bodies require explicit `unsafe {}` blocks around unsafe calls — the compiler warns without them and will error in future editions.
- **`EvtQueryReverseDirection`:** The constant is accessed as `.0` on the bitflag enum. Combined with `EvtQueryChannelPath.0` using bitwise OR on the raw `u32`.
- **WER filter:** Must accept `EventName == "BlueScreen"` OR `"BugCheck"` — real events use `BlueScreen` but accept both defensively.
- **Minidump annotation ordering:** Set filesystem minidumps first, then supplement from WER AttachedFiles only if filesystem found nothing. Reversing this order causes WER paths to be overwritten by empty filesystem results.
- **Cycle 0 = current (most recent) boot.** Print order is reversed (`cycles.iter().rev()`) so most recent appears last in terminal output.
- **`check_audio_power_settings()` iterates instances 0000–0020.** Skips any instance where `DriverDesc` and `FriendlyName` are both absent (not a real device entry).
