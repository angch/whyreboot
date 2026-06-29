# How whyreboot Works

This document traces how the tool goes from raw Windows Event Log data to a diagnosis. Keep it in sync with the source when logic changes.

---

## Overview

Every time Windows shuts down or crashes, it writes structured records to the Windows Event Log. whyreboot reads those records, identifies boot boundaries, groups events into per-boot cycles, and classifies each cycle's shutdown cause by applying a priority-ordered decision tree.

```
Windows Event Log (System channel)
  └─ fetch_system_events()  →  Vec<EventRecord>   (newest-first)
Windows Error Reporting (Application channel)
  └─ fetch_wer_events()     →  Vec<WerRecord>      (crash detail + faulting driver)
C:\Windows\Minidump\
  └─ list_minidumps()       →  Vec<(time, path)>
HKLM registry (audio class)
  └─ check_audio_power_settings() → Vec<AudioPowerInfo>
           │
           ▼
    extract_boot_cycles()
           │
     ┌─────┴──────┐
     │ per cycle  │
     │ analyze_   │
     │ slice()    │
     └────────────┘
           │
    print_cycle() / print_json()
```

---

## Step 1 — Fetching events

### System channel (`src/events.rs: fetch_system_events`)

Uses the Win32 `EvtQuery` API with `EvtQueryReverseDirection` so events arrive **newest first** (index 0 = most recent). Fetches up to 300 events matching these IDs from the `System` log:

| Event ID | Provider | Meaning |
|---|---|---|
| 12 | Microsoft-Windows-Kernel-General | System started — logged at every boot |
| 13 | Microsoft-Windows-Kernel-General | OS shutdown initiated — logged during orderly shutdown |
| 41 | Microsoft-Windows-Kernel-Power | Unexpected shutdown — logged at the *next* boot to report the previous session |
| 109 | Microsoft-Windows-Kernel-Power | Power button state transition |
| 1074 | User32 | Process-initiated shutdown or restart |
| 1076 | User32 | Shutdown reason documented by user |
| 6006 | EventLog | Event log service stopped cleanly |
| 6008 | EventLog | Event log reports previous shutdown was unexpected |
| 6009 | EventLog | Windows version recorded at startup |
| 6013 | EventLog | System uptime in seconds |

### Application channel (`src/events.rs: fetch_wer_events`)

Queries Event ID 1001 from the `Application` log, then filters to Windows Error Reporting (WER) provider events where `EventName == "BlueScreen"` (the actual field value Windows uses — not "BugCheck"). These appear after every BSOD, during the next session, once WER has finished processing the crash dump.

Fields extracted from WER XML:

| XML field | Maps to | Note |
|---|---|---|
| `P1` | stop code (hex) | Bare hex without `0x` prefix, e.g. `"9f"` |
| `Bucket` | fault bucket string | Contains faulting driver name; NOT named `BucketId` |
| `AttachedFiles` | minidump path | First line ending in `.dmp`; strip leading `\\?\` |

---

## Step 2 — Finding boot boundaries (`src/analysis.rs: collect_boot_indices`)

Event 12 from provider `Microsoft-Windows-Kernel-General` marks the start of every boot session. `collect_boot_indices` scans all events (which are newest-first) and returns the indices of every Event 12 from that provider. If none are found it falls back to any Event 12.

Result: a list of indices, e.g. `[0, 15, 31, 47]` — each pointing to a boot marker, newest first.

---

## Step 3 — Slicing events into boot cycles (`src/analysis.rs: extract_boot_cycles`)

For boot cycle N (index 0 = current boot, index 1 = previous, etc.):

```
events array (newest → oldest):
 [0 ......... boot_idxs[0] ........... boot_idxs[1] ........... boot_idxs[2] ...]
              ^ Event 12 (boot N)      ^ Event 12 (boot N-1)
  |<-post_boot->|                      |
                |<----pre_boot---->|
```

- **`post_boot`**: events between the previous boot marker and this boot marker (indices `boot_idxs[N-1]+1 .. boot_idxs[N]`). These were logged *at* the current boot's startup and contain retrospective reports about the previous session (Event 41, Event 6008).
- **`pre_boot`**: events after this boot marker up to the next boot marker (`boot_idxs[N]+1 .. boot_idxs[N+1]`). These were logged *during* the previous session while it was running (Event 1074, Event 13, Event 6006).

**Key insight**: Event 41 ("unexpected shutdown") and Event 6008 ("previous shutdown was unexpected") are retrospective — Windows writes them at the start of the *next* boot, not at crash time. They live in `post_boot`. Events 1074/13/6006 are prospective — written during the shutdown itself — and live in `pre_boot`.

---

## Step 4 — Classifying each cycle (`src/analysis.rs: analyze_slice`)

`analyze_slice` applies a priority-ordered decision tree. The first matching condition wins.

### Decision tree

```
1. Event 41 in post_boot?
   ├─ BugcheckCode != 0  →  BLUE SCREEN (95% confidence)
   ├─ PowerButtonTimestamp != 0  →  FORCED POWER-OFF (82%)
   └─ otherwise  →  UNEXPECTED SHUTDOWN (75%)
        └─ also Event 6008?  →  still UNEXPECTED, note confirms it

2. Event 1074 in pre_boot?
   ├─ process is TiWorker / TrustedInstaller / wuauclt  →  WINDOWS UPDATE (92%)
   ├─ process is TrustedInstaller / wuauclt
   │   OR reason code == 0x80020002  →  WINDOWS UPDATE (92%)
   ├─ user contains "SYSTEM" or "NT AUTHORITY"  →  SYSTEM PROCESS (87%)
   └─ otherwise  →  USER ACTION (90%)

3. Event 6008 in post_boot (but no Event 41)?
   →  UNEXPECTED SHUTDOWN (60%)
      (crash happened before Event 41 could be written)

4. Event 13 or Event 6006 in pre_boot?
   →  NORMAL SHUTDOWN (60%)

5. None of the above
   →  UNDETERMINED (10%)
```

### Confidence values

| Cause | Confidence | Reason |
|---|---|---|
| BlueScreen | 95% | Event 41 with non-zero stop code is unambiguous |
| WindowsUpdate | 92% | TiWorker + reason 0x80020002 is definitive |
| UserAction | 90% | Event 1074 from interactive user is reliable |
| SystemProcess | 87% | Event 1074 from SYSTEM, less specific |
| ForcedPowerOff | 82% | PowerButtonTimestamp heuristic, sometimes incorrect |
| UnexpectedShutdown (with 41) | 75% | Event 41 present but no stop code |
| NormalShutdown | 60% | Event 13/6006 only; no 1074 explanation |
| UnexpectedShutdown (6008 only) | 60% | 6008 without 41 is weaker evidence |
| Undetermined | 10% | Insufficient data |

### Blue screen detail (`src/analysis.rs: classify_event41 + bsod_evidence`)

For stop code 0x9F (`DRIVER_POWER_STATE_FAILURE`), Parameter 1 is decoded:

| P1 value | Meaning |
|---|---|
| 1 | Device object failed WaitForSingleObject during power transition |
| 2 | Device object failed IRP_MN_SET_POWER for SystemPowerState |
| 3 | Device object stalled during IRP_MN_SET_POWER (check P4 for the device object) |
| 4 | Device object stalled powering down (check P4) |

### Shutdown time

`shutdown_time` is only recorded for clean shutdowns (no Event 41). It is taken from the earliest of Event 1074, Event 13, or Event 6006. When Event 41 is present the time of the crash is unknown — only the time of the subsequent boot is known.

---

## Step 5 — WER correlation (`src/analysis.rs: annotate_wer_module`)

WER processes the crash dump during the boot *after* the crash. So a BSOD in session N gets a WER event during session N+1. The correlation window is:

```
time >= boot_times[N]          (WER can't run before the recovery boot starts)
time <= boot_times[N-1]        (or "now" if this is the most recent crash)
w.p1 == stop_code              (P1 field matches the bugcheck stop code)
```

The faulting module name is extracted from the WER `Bucket` string using three patterns, tried in order:

1. **`module!function`** — e.g. `0x9F_3_DXG_POWER_IRP_TIMEOUT_portcls!GetIrpDisposition` → `portcls`
   - Take everything before `!`, then take the substring after the last `_`
2. **`_IMAGE_module.sys`** — e.g. `0x9F_3_usbccgp_IMAGE_UsbHub3.sys` → `UsbHub3.sys`
   - Find `_image_`, take the token after it up to the next `_`
3. **Token ending in `.sys`/`.dll`/`.exe`** — fallback scan of `_`-delimited tokens

---

## Step 6 — Minidump correlation (`src/analysis.rs: annotate_minidumps`)

Two sources, tried in order:

1. **Filesystem** (`C:\Windows\Minidump\*.dmp`): matches dump files whose modification time falls between the start of the crashed session and 10 minutes after the recovery boot. Requires admin; returns nothing otherwise.
2. **WER `AttachedFiles`**: the WER Event 1001 record contains the full path to the processed dump in its `AttachedFiles` data field. Used as fallback if the filesystem scan returned nothing (no admin required).

---

## Step 7 — Device power settings check (`src/registry.rs`)

Reads `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}` (the Windows audio device class) and iterates instances `0000`–`0020`. For each instance with a `DriverDesc` value, reads:

| Registry value | Type | Meaning |
|---|---|---|
| `AllowIdleIrpInD3` | DWORD | `0` = safe (D3 idle disabled); `1` = risky; absent = driver default (risky for portcls) |
| `EnhancedPowerManagementEnabled` | DWORD | Supplementary power management flag |

This check is displayed only when the current crash is a power-related BSOD (stop codes 0x9F, 0x19C, 0xFE, 0x144) with an audio-related faulting module (`portcls`, `audio`, `hdaud`).

---

## Step 8 — Explanation generation (`src/display.rs: generate_explanation`)

Triggered when the cause is a BSOD with a known stop code. Pattern-matches on stop code × module name to produce plain-English text and remediation steps:

| Stop code | Module pattern | Explanation topic |
|---|---|---|
| `0x9F` | `portcls`, `audio`, `hdaud` | Audio driver power transition failure; suggests `AllowIdleIrpInD3=0` fix |
| `0x9F` | `usbccgp`, `usbhub`, `usb` | USB device power transition failure; suggests disabling selective suspend |
| `0x9F` | other | Generic driver power failure |
| `0x19C` | any | Win32k power watchdog timeout (usually GPU driver) |
| `0xFE`, `0x144` | any | USB driver bugcheck |

For the audio path, the actual registry state (from Step 7) is incorporated: if all devices already have `AllowIdleIrpInD3=0`, the explanation says so and pivots to "update driver / BIOS" as the next step.

---

## Output format

### Text mode

Each boot cycle prints in order:
1. Cycle header with boot time and "N of M"
2. Last boot timestamp + offline duration (clean shutdowns only)
3. **VERDICT** — cause label, detail, confidence %, faulting module
4. **Evidence** — bullet points from the matching events
5. **Timeline** — sorted list of key event timestamps
6. **Minidumps** — paths if found
7. **Device Power Settings** — audio registry state (power BSODs with audio module only)
8. **Explanation** — plain-English diagnosis + numbered remediation steps (known patterns only)
9. Raw event table — time, event ID, provider, summary

Cycles print oldest-first so the most recent result is at the bottom of the terminal.

### JSON mode (`--json`)

Outputs a JSON object with `generated`, `cycle_count`, and a `cycles` array. Each cycle has `index`, `boot_time`, `shutdown_time`, `confidence`, `cause`, `stop_code` (BSODs), `params`, `faulting_module`, `evidence`, `minidumps`.

---

## Limitations and edge cases

- **Log rollover**: the System log has a default size limit. On systems that haven't rebooted recently or crash frequently, older boot cycles may not appear at all. The tool degrades gracefully: if no Event 12 is found, the entire event set is treated as a single cycle with `boot_time = None`.
- **Admin rights**: not required for Event Log or WER reading. Required for `C:\Windows\Minidump` filesystem access (WER fallback covers this case).
- **Event 41 timing**: Windows writes Event 41 at the beginning of the recovery boot, not at crash time. The crash itself is unlogged — only the subsequent boot timestamp is known.
- **Event 6008 without Event 41**: can occur if the kernel crashed before it had time to write Event 41 (rare). Classified as `UnexpectedShutdown` at 60% confidence.
- **WER timing**: WER processes dumps asynchronously in the background. A very quick reboot after a crash may not have a corresponding WER event yet.
- **Multiple crashes between boots**: not common, but if it happened the tool would only see the most recent boot boundary. The minidump directory may have multiple files from that period.
