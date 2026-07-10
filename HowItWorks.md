# How whyreboot Works

whyreboot turns raw OS logs into a plain-English verdict. On **Windows** it explains why the machine last rebooted; on **Linux** it scans the systemd journal over a time window for logged system issues. This document walks through each pipeline. Keep it in sync with the source when logic changes.

The two share a portable core (`types.rs`, `timestamp.rs`, `timewindow.rs`, `detect.rs`, `oom.rs`, `analysis.rs`, `format.rs`); they differ in the log-source backend (`events.rs`/`registry.rs` on Windows, `linux.rs` on Linux) and the top-level report (`print_cycle` vs `print_findings`). See [the Linux section](#linux-journal-issue-scanning) below; the Windows pipeline follows.

---

## The pipeline at a glance

```
 Windows Event Log (System)      ──► fetch_system_events()
 Windows Error Reporting (App)   ──► fetch_wer_events()
 C:\Windows\Minidump\            ──► list_minidumps()
 Registry (audio class)          ──► check_audio_power_settings()
                                              │
                                              ▼
                                    extract_boot_cycles()
                                    ┌─────────────────────┐
                                    │  for each cycle:    │
                                    │  analyze_slice()    │
                                    │  annotate WER       │
                                    │  annotate dumps     │
                                    └─────────────────────┘
                                              │
                                              ▼
                                    print_cycle() / print_json()
```

---

## Step 1 — Fetch events

### System log (`fetch_system_events`)

Calls `EvtQuery` with `EvtQueryReverseDirection` so events arrive **newest first** (index 0 = most recent). Pulls up to 300 events matching these IDs:

| ID | Provider | What it means |
|---|---|---|
| 12 | Kernel-General | System started — one per boot |
| 13 | Kernel-General | OS shutdown initiated |
| 41 | Kernel-Power | Unexpected shutdown — written at the *next* boot |
| 109 | Kernel-Power | Power button state transition |
| 1074 | User32 | Process-initiated shutdown or restart |
| 1076 | User32 | Shutdown reason documented |
| 6006 | EventLog | Event log stopped cleanly |
| 6008 | EventLog | Previous shutdown was unexpected |
| 6009 | EventLog | Windows version at startup |
| 6013 | EventLog | System uptime in seconds |

> **Important timing note:** Event 41 and Event 6008 are *retrospective* — Windows logs them at the start of the recovery boot to describe what happened in the *previous* session. Events 1074, 13, and 6006 are *prospective* — logged during the shutdown itself.

### Windows Error Reporting (`fetch_wer_events`)

Queries Event ID 1001 from the Application log, filtered to WER provider records where `EventName == "BlueScreen"`. These appear after every BSOD, once WER has finished processing the crash dump during the recovery boot.

Three fields matter:

| Field | Used for | Gotcha |
|---|---|---|
| `P1` | Stop code | Bare hex without `0x` — e.g. `"9f"`, not `"0x0000009F"` |
| `Bucket` | Faulting driver name | Called `Bucket`, not `BucketId` |
| `AttachedFiles` | Minidump path | First `.dmp` line; strip leading `\\?\` |

---

## Step 2 — Find boot boundaries

`collect_boot_indices` scans the flat event list (newest-first) for Event 12 from `Microsoft-Windows-Kernel-General`. Each occurrence marks the start of a boot session. If none are found, it falls back to any Event 12.

The result is a list of indices into the event array, e.g. `[0, 15, 31, 47]`, one per boot, newest first.

---

## Step 3 — Slice events into boot cycles

For boot cycle N (0 = current boot, 1 = previous, …):

```
events (newest → oldest):
 [0 ··· boot_idxs[N] ·················· boot_idxs[N+1] ··· ]
         ^ Event 12 (this boot)          ^ Event 12 (prior boot)

         |←── post_boot ──→|←──── pre_boot ────→|
```

- **`post_boot`** — events between the prior boot marker and this boot marker. These are retrospective: crash reports logged *at startup* about the previous session (Event 41, Event 6008).
- **`pre_boot`** — events after this boot marker up to the next older boot marker. These are prospective: logged *during* the previous session (Event 1074, Event 13, Event 6006).

This two-bucket split is the key insight that lets the tool correctly associate crash evidence with the session that actually crashed.

---

## Step 4 — Classify each cycle

`analyze_slice` applies a priority-ordered decision tree. The **first matching condition wins.**

```
 1.  Event 41 in post_boot?
     ├─ BugcheckCode ≠ 0              →  BLUE SCREEN  (95%)
     ├─ PowerButtonTimestamp ≠ 0      →  FORCED POWER-OFF  (82%)
     └─ neither                       →  UNEXPECTED SHUTDOWN  (75%)
          + Event 6008 also present?  →  (same verdict, evidence noted)

 2.  Event 1074 in pre_boot?
     ├─ process = TiWorker / TrustedInstaller / wuauclt
     │   OR reason code = 0x80020002  →  WINDOWS UPDATE  (92%)
     ├─ user contains "SYSTEM" / "NT AUTHORITY"
     │                                →  SYSTEM PROCESS  (87%)
     └─ otherwise                     →  USER ACTION  (90%)

 3.  Event 6008 in post_boot (no Event 41)?
     →  UNEXPECTED SHUTDOWN  (60%)

 4.  Event 13 or Event 6006 in pre_boot?
     →  NORMAL SHUTDOWN  (60%)

 5.  Nothing matched
     →  UNDETERMINED  (10%)
```

### Confidence values

| Cause | Confidence | Why |
|---|---|---|
| Blue Screen | 95% | Non-zero bugcheck code is unambiguous |
| Windows Update | 92% | TiWorker + reason `0x80020002` is definitive |
| User Action | 90% | Event 1074 from an interactive user is reliable |
| System Process | 87% | Event 1074 from SYSTEM; less specific process |
| Forced Power-Off | 82% | `PowerButtonTimestamp` heuristic; occasionally wrong |
| Unexpected Shutdown (Event 41) | 75% | Event 41 without a stop code |
| Normal Shutdown | 60% | Event 13/6006 only; no 1074 explanation |
| Unexpected Shutdown (Event 6008 only) | 60% | Weaker evidence — no Event 41 |
| Undetermined | 10% | Insufficient log data |

### Blue screen detail

For stop code `0x9F` (DRIVER_POWER_STATE_FAILURE), Parameter 1 narrows the failure mode:

| P1 | Meaning |
|---|---|
| 1 | Device failed `WaitForSingleObject` during power transition |
| 2 | Device failed `IRP_MN_SET_POWER` for system power state |
| 3 | Device stalled on `IRP_MN_SET_POWER` — check P4 for the device object |
| 4 | Device stalled powering down — check P4 |

### Shutdown time

`shutdown_time` is recorded only for clean shutdowns (no Event 41 present). It comes from whichever of Event 1074, Event 13, or Event 6006 appears first. For crashes the shutdown time is unknown — only the recovery boot time is known.

---

## Step 5 — Correlate WER data

WER processes the crash dump during the boot *after* the crash, so a BSOD from session N produces a WER event during session N+1. The tool matches WER records to cycles using a time window and stop code:

```
 WER record matches cycle N when:
   w.time >= boot_time[N]        (WER runs after the recovery boot starts)
   w.time <= boot_time[N-1]      (or "now" for the most recent crash)
   w.p1   == stop_code           (P1 field = bugcheck code)
```

The faulting module is extracted from the WER `Bucket` string. Three patterns are tried in order:

1. **`module!function`** — e.g. `0x9F_3_DXG_POWER_IRP_TIMEOUT_portcls!GetIrpDisposition`
   → take the token before `!`, then the last `_`-delimited segment → `portcls`

2. **`_IMAGE_module.sys`** — e.g. `0x9F_3_usbccgp_IMAGE_UsbHub3.sys`
   → find `_image_`, take the token that follows → `UsbHub3.sys`

3. **Token ending in `.sys` / `.dll` / `.exe`** — fallback scan across all `_`-delimited tokens

---

## Step 6 — Match minidumps

Two sources, tried in order:

1. **Filesystem** (`C:\Windows\Minidump\*.dmp`): matches dump files whose modification time falls within `[session_start, boot_time + 10 min]`. Requires admin rights; returns nothing otherwise.

2. **WER `AttachedFiles`**: the WER Event 1001 record includes the full dump path in its data. Used as fallback when the filesystem scan returns nothing (no admin required).

---

## Step 7 — Check audio device power settings

Reads `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}` — the Windows-assigned GUID for the audio device class (stable since Windows 98). Iterates instances `0000`–`0020` and reads two registry values per device:

| Value | Meaning |
|---|---|
| `AllowIdleIrpInD3 = 0` | Safe — D3 idle IRPs are disabled |
| `AllowIdleIrpInD3 = 1` | Risky — driver may stall on power transition |
| `AllowIdleIrpInD3` absent | Risky — driver uses its own (often unsafe) default |
| `EnhancedPowerManagementEnabled` | Supplementary power management flag |

This check is shown only for power-related BSODs (stop codes 0x9F, 0x19C, 0xFE, 0x144) when the faulting module is audio-related (`portcls`, `audio`, `hdaud`).

---

## Step 8 — Generate explanation

When the cause is a BSOD with a recognised stop code, `generate_explanation` pattern-matches on stop code and module name to produce plain-English text and numbered remediation steps:

| Stop code | Module | Topic |
|---|---|---|
| `0x9F` | `portcls`, `audio`, `hdaud` | Audio driver power transition failure; suggests `AllowIdleIrpInD3=0` |
| `0x9F` | `usbccgp`, `usbhub`, `usb` | USB device power transition failure; suggests disabling selective suspend |
| `0x9F` | other | Generic driver power failure |
| `0x19C` | any | Win32k power watchdog timeout (usually a GPU driver issue) |
| `0xFE`, `0x144` | any | USB driver bugcheck |

The actual registry state from Step 7 is woven in: if all audio devices already have `AllowIdleIrpInD3=0`, the explanation says so and suggests updating the driver or BIOS instead.

---

## Output format

**Text mode** prints each boot cycle in this order:

1. Header with boot time and "N of M"
2. Last boot timestamp + offline duration (clean shutdowns only)
3. **Verdict** — cause, detail, confidence %, faulting module
4. **Evidence** — bullet points from the matching events
5. **Timeline** — key event timestamps, sorted chronologically
6. **Minidumps** — file paths if found
7. **Device Power Settings** — audio registry state (power BSODs with audio module only)
8. **Explanation** — diagnosis and numbered steps (known stop code patterns only)
9. Raw event table — timestamp, ID, provider, summary

Cycles print oldest-first so the most recent result appears at the bottom of the terminal.

**JSON mode** (`--json`) outputs a single object with `generated`, `cycle_count`, and a `cycles` array. Each cycle includes `index`, `boot_time`, `shutdown_time`, `confidence`, `cause`, `stop_code`, `params`, `faulting_module`, `evidence`, and `minidumps`.

---

## Known limitations

| Limitation | Detail |
|---|---|
| Log rollover | The System log has a default size cap. Older cycles may not appear on systems that crash frequently or rarely reboot. The tool degrades gracefully: if no Event 12 is found it treats all events as one cycle with `boot_time = None`. |
| Admin rights | Not required for Event Log or WER. Required only for direct minidump filesystem access; WER-reported paths work without it. |
| Event 41 timing | Windows writes Event 41 at the start of the recovery boot, not at crash time. The exact moment of the crash is unlogged. |
| Event 6008 without Event 41 | Rare — can happen if the kernel crashed before it had time to write Event 41. Classified as Unexpected Shutdown at 60% confidence. |
| WER latency | WER processes dumps asynchronously. A very fast reboot after a crash may not have a WER event yet. |
| Multiple crashes between boots | Not common, but the tool would only see the most recent boot boundary. The minidump directory may contain multiple files from that window. |

---

# Linux — journal issue scanning

On Linux, `whyreboot` does not diagnose a single reboot; it reports **every logged system issue in a time window**, many of which never cause a reboot (an OOM kill, a failed service, a corrected ECC error). The pipeline:

```
 Time expression ("1 hour ago")  ──► parse_window()  ──► TimeWindow { start, end }
                                              │
 journalctl -o json (kernel -k,               ▼
   systemd-oomd unit, service/coredump  ──► fetch_journal()  ──► Vec<LogLine>
   greps)   [or --from-file <f>]                │
                                              ▼
                                    detect::scan()
                                    ┌───────────────────────────┐
                                    │ for each LogLine:         │
                                    │   first matching detector │  fn(&LogLine)->Option<Finding>
                                    │ coalesce() bursts         │
                                    └───────────────────────────┘
                                              │
                                              ▼
                                    print_findings() / print_findings_json()
```

## Step 1 — Resolve the time window (`timewindow.rs`)

The user's phrase becomes one concrete `TimeWindow` — the single source of truth used both to bound the journal query and to render the header. Supported: relative durations (`"1 hour ago"`, `"30 minutes ago"`, `"2h"`, `"90s"`, `"1w"`), `"today"`/`"earlier today"` (since local midnight), `"yesterday"` (bounded prior day), and `"all"`. Local day boundaries are computed with `Timestamp::secs_into_local_day()` (no timezone-math library). Default when no range is given: last 24 hours. Unrecognized text is rejected (exit 2), not silently defaulted.

## Step 2 — Fetch journal records (`linux.rs`)

Three `journalctl -o json` queries are issued and merged, each bounded by `--since @<unix>` / `--until @<unix>`:

1. `journalctl -k` — the kernel stream, fetched **unfiltered**. Deliberately no `--grep`: a rejected or misparsed grep pattern makes journalctl exit 0 with empty stdout, which would silently blind the correctness-critical kernel path (OOM, panic, disk errors). A windowed `-k` is small, so fetching it whole is cheap and the detectors filter precisely.
2. `journalctl -u systemd-oomd` — the userspace OOM killer's own unit.
3. A `--grep` over the whole journal for userspace/systemd markers (`Failed with result`, `dumped core`, memory-pressure kills…) — a filter is needed here because the general journal is large; falls back to unfiltered if `--grep` is rejected.

Results are de-duplicated by `(time, message)`. Each JSON line is parsed by a minimal hand-rolled flat-object parser (no serde) that extracts the string-valued fields; `MESSAGE` and `__REALTIME_TIMESTAMP` (microseconds) are required, `SYSLOG_IDENTIFIER` and `_TRANSPORT` are optional. Binary/array-valued fields are skipped. `--from-file` reads the same line format from disk (test seam + offline analysis).

## Step 3 — Detect (`detect.rs`, `oom.rs`)

Each detector is `fn(&LogLine) -> Option<Finding>`. `classify()` runs them in order and takes the **first** match, so one line yields at most one finding. Detectors anchor on stable marker substrings (not brittle full-line regexes) and extract a few fields tolerantly. Categories: `OOM`, `KernelPanic`, `Segfault`, `Disk`, `Lockup`, `Thermal`, `Hardware`, `Service`, `Coredump`. Severity is `Critical` (system stability threatened) or `Warning` (single process/service).

OOM specifics (`oom.rs`): the kernel detector keys on `Killed process <pid> (<comm>)` (also older `Kill process`), extracting pid, comm, and `anon-rss:`/`total-vm:`/`oom_score_adj:`; the `invoked oom-killer:`/`oom-kill:` context lines are deliberately **not** counted, so a single kill = one finding. The systemd-oomd detector (identifier `systemd-oomd`) parses `Killed <cgroup> due to <reason>`.

## Step 4 — Coalesce bursts (`coalesce()`)

A single incident often emits many lines (a SATA fault logs ~10). Consecutive findings of the **same category and source** within `COALESCE_SECS` (30s) are merged into the earliest, folding the rest in as `+ related:` evidence and appending `(N related log lines)` to the title. This keeps the report high-level. Distinct categories, and same-category events far apart in time, stay separate.

## Step 5 — Window-filter and render

Findings are filtered by `TimeWindow::contains` (belt-and-suspenders with journalctl's own `--since`, and the only filter for `--from-file`) and printed newest-first. Text output: a header (`System Issue Report — <window>`, scanned/found counts), then per finding a severity-colored `[LEVEL] CATEGORY time` line, title, `source:`, and evidence bullets; a clean-bill line when none. **JSON mode** emits `{ generated, window_start, window_end, scanned, issue_count, issues: [{ time, severity, category, title, source, evidence }] }`.

## Adding a category

1. Write a detector `fn(&LogLine) -> Option<Finding>` in `detect.rs` and add it to `DETECTORS`.
2. Kernel-log categories need nothing else (the `-k` stream is fetched unfiltered). A userspace/systemd category must add its marker substrings to `USER_GREP` in `linux.rs` so the general-journal query fetches those lines.
3. Add a fixture line to `tests/fixtures/` and an assertion in `tests/oom_e2e.rs`.

## Known limitations (Linux)

| Limitation | Detail |
|---|---|
| Requires journalctl | The journal is read via `journalctl`; systems using only classic `/var/log/*` files (no systemd journal) aren't yet supported. `--from-file` accepts captured `-o json` output. |
| Permissions | Kernel and most messages need membership in `systemd-journal`/`adm`. Without it, queries may return nothing rather than erroring. |
| Marker-based matching | Detection keys on known substrings; kernel wording changes across versions and unusual formats may be missed. Prefer adding markers over tightening to full-line formats. |
| Non-persistent journal | If `Storage=volatile`, history is lost on reboot, so ranges spanning a reboot may be truncated. |
