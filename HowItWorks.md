# How whyreboot Works

whyreboot turns raw OS logs into a plain-English verdict. On **Windows** it explains why the machine last rebooted; on **Linux** it scans the systemd journal over a time window for logged system issues; on **macOS** it scans the unified log the same way (unsafe shutdowns, panics, sleep/wake failures, app crashes, update reboots). This document walks through each pipeline. Keep it in sync with the source when logic changes.

All platforms share a portable core (`types.rs`, `timestamp.rs`, `timewindow.rs`, `detect.rs`, `oom.rs`, `jsonlog.rs`, `analysis.rs`, `format.rs`); they differ in the log-source backend (`events.rs`/`registry.rs` on Windows, `linux.rs` on Linux, `macos.rs` on macOS) and the top-level report (`print_cycle` vs `print_findings`). See [the Linux section](#linux-journal-issue-scanning) and [the macOS section](#macos-unified-log-scanning) below; the Windows pipeline follows.

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

Calls `EvtQuery` with `EvtQueryReverseDirection` so events arrive **newest first** (index 0 = most recent). Pulls up to 500 events matching these IDs:

| ID | Provider | What it means |
|---|---|---|
| 12 | Kernel-General | System started — one per boot |
| 13 | Kernel-General | OS shutdown initiated |
| 19 | WindowsUpdateClient | Update install succeeded — title embeds the KB (reboot-cause correlation) |
| 41 | Kernel-Power | Unexpected shutdown — written at the *next* boot |
| 109 | Kernel-Power | Power button state transition |
| 1074 | User32 | Process-initiated shutdown or restart |
| 1076 | User32 | Shutdown reason documented |
| 7045 | Service Control Manager | A service/driver was installed (bugcheck-cause correlation) |
| 6006 | EventLog | Event log stopped cleanly |
| 6008 | EventLog | Previous shutdown was unexpected |
| 6009 | EventLog | Windows version at startup |
| 6013 | EventLog | System uptime in seconds |

> **Reboot-cause correlation (Events 19 and 7045):** These don't classify a reboot; they explain it, following Microsoft's [*Troubleshoot unexpected reboots using system event logs*](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs). For a **Windows Update** cycle, `annotate_update_installs` names the update(s) from Event 19 installed in the shut-down session plus a one-hour post-boot grace (deliberately *not* out to the next boot, so a day of unrelated Store/Defender updates isn't swept in); frequent Defender "Security Intelligence" definition updates are de-prioritized. For a **BSOD** cycle, `annotate_service_installs` lists any driver/service installed *during the session that crashed* (Event 7045) as a prime suspect — the classic "new driver → bugcheck" lead — flagging kernel-mode drivers and `.sys` images specifically.

> **Important timing note:** Event 41 and Event 6008 are *retrospective* — Windows logs them at the start of the recovery boot to describe what happened in the *previous* session. Events 1074, 13, and 6006 are *prospective* — logged during the shutdown itself.

> **XML parsing gotcha:** Classic providers (`User32`, `EventLog` — i.e. Events 1074, 6006, 6008, 6009, 6013) render the ID as `<EventID Qualifiers='32768'>1074</EventID>`, with an attribute, whereas modern ETW providers emit a bare `<EventID>12</EventID>`. `xml_elem` must therefore match the opening tag allowing for attributes; an exact-`<EventID>`-literal match silently drops every legacy-provider event — which previously made update reboots (Event 1074) invisible and caused them to fall through to the weaker Event 13 "normal shutdown" verdict. Relatedly, these classic events' `EventRecordID`s are **not** reliably ordered against modern-provider records written at the same instant, so time-sensitive lookups compare `TimeCreated` rather than trusting array position.

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
     ├─ process = TiWorker / TrustedInstaller / wuauclt / usoclient
     │   / MoUsoCoreWorker / UpdateOrchestrator
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

### Event 1074 field layout

`classify_event1074` reads the `<Data>` insertion strings by name. The order is easy to get wrong because several are free-form text:

| Field | Meaning |
|---|---|
| `param1` | Initiating process (full path) |
| `param2` | Computer name |
| `param3` | Reason **text** (e.g. "Operating System: Upgrade (Planned)") |
| `param4` | Reason **code** (hex, e.g. `0x80020002`) |
| `param5` | Shutdown type (`restart` / `power off`) |
| `param6` | Comment |
| `param7` | **Initiating user** (e.g. `NT AUTHORITY\SYSTEM`) |

The user is `param7`, *not* `param3` — `param3` is the human-readable reason string. Reading the user from `param3` (an earlier bug) put the reason text into the user field and broke the SYSTEM-vs-interactive-user branch.

### Windows Update OS version

For a `WINDOWS UPDATE` cycle, `annotate_os_version` records the OS build on each side of the reboot from the Event 6009 startup banner (`_0` = "major.minor.", `_1` = build; both must be numeric or the banner is ignored):

- **`old_version`** — newest 6009 in `[prev_boot, boot_time)` (the session shut down to update).
- **`new_version`** — oldest 6009 in `[bt, next_boot)` (this boot's own banner).

Each lookup is bounded to a single session so a neighbouring boot's banner can't leak in, and it falls through to the next *parseable* 6009 rather than trusting a single record. Because 6009 carries only `major.minor.build` (no UBR/revision), and update chains often reboot several times before the build changes, `old_version == new_version` does **not** prove no upgrade occurred — the render layer (`cause_detail` → `win_product`) therefore maps the build to a marketing name (build ≥ 22000 ⇒ Windows 11) and avoids claiming a version change it can't observe.

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

**JSON mode** (`--json`) outputs a single object with `generated`, `cycle_count`, and a `cycles` array. Each cycle includes `index`, `boot_time`, `shutdown_time`, `confidence`, `cause`, `stop_code`, `params`, `faulting_module`, `evidence`, and `minidumps`. A `WindowsUpdate` cause additionally carries `process` and the raw `old_version` / `new_version` build strings (`"major.minor.build"`, or `null` when not found in the log window).

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

1. `journalctl -k` — the kernel stream (`_TRANSPORT=kernel`), fetched **unfiltered**. Kernel lines are sparse even in a multi-GB journal, so taking all of them is cheap and means a wording change in any kernel message can't silently drop an event; the detectors filter precisely.
2. `journalctl -u systemd-oomd` — the userspace OOM killer's own unit.
3. `journalctl -p notice SYSLOG_IDENTIFIER=systemd SYSLOG_IDENTIFIER=systemd-coredump` — service failures and coredumps. These come only from those two identifiers and are always logged at priority notice (5) or above, so intersecting the identifier and priority **indexes** returns a few dozen lines instead of the tens of thousands of routine unit start/stop lines.
4. `journalctl -p notice SYSLOG_IDENTIFIER=gnome-shell … kwin_wayland … plasmashell … xdg-desktop-portal …` — graphical compositors/session managers, priority-gated because they chat heavily at info. Absent identifiers (servers, headless) match nothing.
5. `journalctl SYSLOG_IDENTIFIER=Xorg SYSLOG_IDENTIFIER=gdm-x-session …` — the X server logs via gdm at info priority, so these low-volume identifiers are fetched unfiltered.

**All queries use indexed fields only — never `--grep`.** `--grep` is an unindexed full-message scan; over this machine's 2.3 GB journal it made `--all` never finish. The indexed queries plus `--output-fields` (trimming each record to the four fields the detectors read) bring `--all` down to ~0.5 s. The queries only need to be a *superset* of what matters — the detectors do the precise classification.

Results are de-duplicated by `(time, message)`. Each JSON line is parsed by a minimal hand-rolled flat-object parser (no serde) that extracts the string-valued fields; `MESSAGE` and `__REALTIME_TIMESTAMP` (microseconds) are required, `SYSLOG_IDENTIFIER` and `_TRANSPORT` are optional. Binary/array-valued fields are skipped. `--from-file` reads the same line format from disk (test seam + offline analysis).

## Step 3 — Detect (`detect.rs`, `oom.rs`)

Each detector is `fn(&LogLine) -> Option<Finding>`. `classify()` runs them in order and takes the **first** match, so one line yields at most one finding. Detectors anchor on stable marker substrings (not brittle full-line regexes) and extract a few fields tolerantly. Categories: `OOM`, `KernelPanic`, `GPU`, `Segfault`, `Disk`, `Lockup`, `Thermal`, `Hardware`, `Service`, `Coredump`, `Session`. Severity is `Critical` (system stability threatened) or `Warning` (single process/service).

GPU specifics (`detect_gpu`, kernel-only): amdgpu ring timeouts / `GPU reset begin!` / `VRAM is lost`, i915 `GPU HANG: ecode …, in <app> [pid]` (the culprit workload is extracted) / stopped-heartbeat resets, NVIDIA `NVRM: Xid` (codes 13/31/43/45 are app-level → Warning; `fallen off the bus` and other codes → Critical), and DRM `flip_done timed out`. Modern-amdgpu (MES-era, e.g. Strix Halo gfx1151) reset sequences are covered too — `Starting … ring reset`, `Ring … reset failed`, `MES failed to respond to msg=…`, `failed to reset/unmap legacy queue`, `*ERROR* failed to halt cp gfx` (the `*ERROR*` marker requires drm/GPU context in the line), `[drm] device wedged` — plus amdgpu's separate culprit line `Process <comm> pid <n> thread …`, which coalesces into the burst and names the workload. `ring …` markers additionally require a fault word (`timeout`/`error`/`hang`/`fail`/`reset`) so topology prints don't match.

Session specifics (`detect_session`, userspace-only): Wayland clients reporting `Lost connection to Wayland compositor` / `The Wayland connection broke` / `Error 71 (Protocol error) dispatching to Wayland display`; `gnome-session-binary`'s `Unrecoverable failure in required component <x>`; and Xorg fatals (`(EE)` plus `Fatal server error` / `Segmentation fault at address` / `Server terminated with error` / `Caught signal`). Non-fatal `(EE)` lines are ignored.

### Marker provenance — how battle-tested is each detector?

Three levels (each detector's doc comment in `detect.rs` carries its level):

- **verified-live** — matched real events in a live journal during development.
- **third-party logs** — markers copied verbatim from real captured logs in public incident reports; realistic, but never reproduced live by us.
- **canonical format** — from kernel/systemd source or docs; only ever exercised on fixtures.

| Category | Provenance | Notes |
|---|---|---|
| Service | **verified-live** | real `Failed with result` events on the dev machine |
| OOM | canonical format | kernel `mm/oom_kill.c` + systemd-oomd wording; splice-tested through a real journalctl capture, no live OOM reproduced |
| Disk | third-party logs + canonical | ATA burst verbatim from a real captured SATA fault; EXT4 benign baseline verified-live |
| GPU | **third-party logs — untested live** | verbatim from Ubuntu/Arch/NVIDIA/Framework reports (incl. Strix Halo gfx1151) |
| Session | **third-party logs — untested live** | verbatim from GNOME GitLab / Mozilla / KDE / Arch reports; dev VM has no graphical session |
| KernelPanic, Segfault, Lockup, Thermal, Hardware, Coredump | canonical format | fixture-tested only; benign EDAC/boot-banner baselines verified-live |
| ShutdownCause, SleepWake, Crash, UpdateRestart (macOS) | **third-party logs — untested live** | formats from public reports/documentation; the fetch/parse backend IS verified-live on a real Mac (which also surfaced and fixed the `<IPv4-redacted>`→EDAC false positive), but no real shutdown/panic/crash incident has been matched yet |

A miss (wording drift on some kernel/driver version) silently yields no finding — it never misclassifies or crashes. If you hit a real incident that these patterns miss, capture it with `journalctl -o json > incident.jsonl` and replay with `--from-file`; extending the markers is a one-function change.

**Guarding against boot-banner false positives.** Several subsystem names appear in benign driver-init banners logged at *every* boot, not just in error reports — observed live on this machine:

| Line (logged at boot) | Naïve marker that matched | Why it's benign |
|---|---|---|
| `EDAC MC: Ver: 3.0.0` | `EDAC` | EDAC driver version banner |
| `mce: CPU supports 32 MCE banks` | `mce:` | MCE capability announcement |
| `EXT4-fs (sda3): mounted filesystem … ro` → `re-mounted … r/w` | `EXT4-fs (` | Normal root-mount sequence (ro first, then r/w) |

Rule: a marker that is a bare subsystem name/prefix (`EDAC`, `mce:`, `MCE `, `EXT4-fs (`, `XFS (`, `Btrfs`) must be **gated on an error indication** in the same message (`error`/`fail`/`corrupt`/`warning`, or an ` CE `/` UE ` event count). Unambiguous markers (`Hardware Error`, `EXT4-fs error`, `Kernel panic`, …) match directly. When adding a detector, check what the subsystem logs at boot (`journalctl -k -b | grep -i <name>`) before trusting a bare name. A quick way to vet the whole taxonomy: run `whyreboot --all` on a healthy machine — ideally it should report nothing from the kernel side.

**Acronym markers must be case-sensitive** (found live on a real Mac): case-insensitive `EDAC` matches inside ordinary words — macOS kernel `tcp_connection_summary` lines contain the literal privacy token `<IPv4-redacted>`, and "red**edac**ted" contains "edac"; the same line's `so_error: 0` then satisfied the error gate, producing a bogus "Corrected hardware/memory error (ECC)" finding. The kernel always logs `EDAC`/`MCE` uppercase and `mce:` lowercase, so those markers now match exactly (`str::contains`, not the case-insensitive helper). Prefer case-sensitive matching for any short acronym marker.

OOM specifics (`oom.rs`): the kernel detector keys on `Killed process <pid> (<comm>)` (also older `Kill process`), extracting pid, comm, and `anon-rss:`/`total-vm:`/`oom_score_adj:`; the `invoked oom-killer:`/`oom-kill:` context lines are deliberately **not** counted, so a single kill = one finding. The systemd-oomd detector (identifier `systemd-oomd`) parses `Killed <cgroup> due to <reason>`.

## Step 4 — Coalesce bursts (`coalesce()`) and correlate cascades (`correlate()`)

A single incident often emits many lines (a SATA fault logs ~10). Consecutive findings of the **same category and source** within `COALESCE_SECS` (30s) are merged into the earliest, folding the rest in as `+ related:` evidence and appending `(N related log lines)` to the title. This keeps the report high-level. Distinct categories, and same-category events far apart in time, stay separate.

After coalescing, `correlate()` cross-annotates cascade relationships within `CORRELATE_SECS` (120s):

1. **GPU incident → casualties.** Segfault/Coredump/Session/Service/Lockup findings near a `GPU` finding are marked "likely follows the GPU hang/reset", and the GPU finding lists each casualty. A GPU hang that takes down the compositor and its apps reads as one story.
2. **Compositor crash → orphaned clients.** A Segfault/Coredump whose title names a compositor or display server (`gnome-shell`, `kwin_wayland`, `mutter`, `Xorg`, `Xwayland`, `sway`, …) is linked with the `Session` connection-loss findings around it.

Annotations are appended to `evidence` on **both** sides of each link, so whichever finding the reader looks at first points at the rest of the cascade.

## Step 5 — Window-filter and render

Findings are filtered by `TimeWindow::contains` (belt-and-suspenders with journalctl's own `--since`, and the only filter for `--from-file`) and printed newest-first. Text output: a header (`System Issue Report — <window>`, scanned/found counts), then per finding a severity-colored `[LEVEL] CATEGORY time` line, title, `source:`, and evidence bullets; a clean-bill line when none. **JSON mode** emits `{ generated, window_start, window_end, scanned, issue_count, issues: [{ time, severity, category, title, source, evidence }] }`.

## Adding a category

1. Write a detector `fn(&LogLine) -> Option<Finding>` in `detect.rs` and add it to `DETECTORS`.
2. Kernel-log categories need nothing else (the `-k` stream is fetched unfiltered). A userspace/systemd category must be reachable by an **indexed** query in `fetch_journal` (by `SYSLOG_IDENTIFIER`/`_SYSTEMD_UNIT`/`PRIORITY`) — add one if your source isn't already covered. Never use `--grep` (see the performance note above).
3. Add a fixture line to `tests/fixtures/` and an assertion in `tests/oom_e2e.rs`.

## Known limitations (Linux)

| Limitation | Detail |
|---|---|
| Requires journalctl | The journal is read via `journalctl`; systems using only classic `/var/log/*` files (no systemd journal) aren't yet supported. `--from-file` accepts captured `-o json` output. |
| Permissions | Kernel and most messages need membership in `systemd-journal`/`adm`. Without it, queries may return nothing rather than erroring. |
| Marker-based matching | Detection keys on known substrings; kernel wording changes across versions and unusual formats may be missed. Prefer adding markers over tightening to full-line formats. |
| Non-persistent journal | If `Storage=volatile`, history is lost on reboot, so ranges spanning a reboot may be truncated. |
| App-side Wayland-loss lines | Arbitrary apps log `Lost connection to Wayland compositor` under their own identifier at info priority, which the indexed live queries don't fetch (we can't enumerate every app). The compositor's own crash *is* fetched (coredump/segfault/session queries), so the incident is still reported; the client lines are picked up in `--from-file` captures. |

---

# macOS — unified log scanning

The macOS path reuses the entire Linux findings pipeline — same `TimeWindow`, same detector framework and correlation pass, same report — with one different fetch backend (`macos.rs`) and a second input format handled by the shared parser (`jsonlog.rs`).

## Fetch (`macos.rs`)

One `log show --style ndjson` invocation, bounded by `--start`/`--end` (local-time `YYYY-MM-DD HH:MM:SS`, rendered by `Timestamp::format_dt`) and filtered with an NSPredicate over `process` (kernel, ReportCrash, softwareupdated, osinstallersetupd) plus `eventMessage CONTAINS` fallbacks for shutdown-cause / sleep-wake / panic strings. Unlike journald, the unified log has **no indexed field queries** — `log show` scans its window regardless — so keep windows bounded; `--all` on a long-lived install is inherently slow (this is `log show`, not us).

Each ndjson record maps onto the shared `LogLine`: `eventMessage` → message, `process` → identifier (so kernel lines satisfy the detectors' kernel checks), `subsystem` → transport. The `timestamp` field is local time with an explicit UTC offset (`2026-07-10 08:00:05.123456+0800`), parsed offset-correctly by `Timestamp::from_log_show`.

## macOS detectors (in the same `DETECTORS` list)

| Category | Trigger | Severity |
|---|---|---|
| `ShutdownCause` | kernel `Previous shutdown cause: N`, logged at the boot **after** the event. Decoded: 0 power loss, 3 hard power-off, -60 disk corruption, -61/-62 watchdog restart, -3/-71/-74/-81/-95 thermal/battery, -103 battery low, -128 unknown; unlisted codes still flagged. Cause 5 (clean) is deliberately **not** reported. | Critical / Warning by code |
| `KernelPanic` | XNU `panic(cpu N caller …)`; `userspace watchdog timeout: no successful checkins from <proc>` extracts the hung process (classically WindowServer) | Critical |
| `SleepWake` | `Sleep Wake failure` | Critical |
| `Crash` | ReportCrash identifier + `Saved crash report for App[pid] …` (app name extracted) | Warning |
| `UpdateRestart` | softwareupdated/osinstallersetupd identifier + restart/install markers — expected reboots, reported at Info so unexplained restarts can be told apart from updates | Info |

These detectors live in the portable `detect.rs`, so the macOS fixtures (`tests/fixtures/macos.jsonl`) are exercised on Linux CI as well; a journald stream never contains these markers, so they cost nothing cross-platform.

## Known limitations (macOS)

| Limitation | Detail |
|---|---|
| No field indexes | `log show` scans its whole window; wide ranges are slow by nature. Default window is 24h. |
| Provenance | All macOS markers are third-party/documentation-sourced and **untested against a live Mac** (development happened on Linux; CI smoke-runs the binary against the macOS runner's live unified log). See the provenance table above. |
| Log retention | The unified log typically retains days–weeks; `--all` cannot see past its retention. |
| Update-restart wording | softwareupdated log phrasing churns across macOS releases more than the other categories; expect to extend markers. |
