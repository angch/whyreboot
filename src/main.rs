// SPDX-License-Identifier: MIT OR Apache-2.0
//! whyreboot — cross-platform system-issue diagnostics.
//!
//! On Windows it diagnoses why the machine last rebooted (Event Log / WER).
//! On Linux it scans the systemd journal for logged system issues over a time
//! window — starting with out-of-memory (OOM) kills, which need not have caused
//! a reboot at all.

mod color;
mod display;

use color::{COLORS, NO_COLOR, enable_ansi_color};

// ── CLI ───────────────────────────────────────────────────────────────────────

/// Parsed command-line options (superset across platforms; each backend uses the
/// subset that applies to it).
// `Debug` is test-only on purpose: the release binary never formats `Args`, and
// deriving it unconditionally emits formatting code this size-sensitive binary
// doesn't need.
#[cfg_attr(test, derive(Debug))]
struct Args {
    /// Windows: number of boot cycles to show (default 1; 0 = all).
    history: usize,
    json: bool,
    color: bool,
    /// Time-range expression, e.g. "1 hour ago" / "today" / "2h" (Linux).
    window: Option<String>,
    /// Analyze all available history regardless of window.
    all: bool,
    /// Read journalctl `-o json` records from this file instead of the live
    /// journal (Linux; used for testing and offline analysis).
    from_file: Option<std::path::PathBuf>,
    /// Exit with [`EXIT_ISSUES_FOUND`] if anything critical was reported, so the
    /// tool can gate a cron job or monitoring check.
    exit_code: bool,
}

/// Exit status for `--exit-code` when a critical issue (or a crash reboot) was
/// found. Distinct from 1 (operational failure) and 2 (usage error) so a script
/// can tell "the scan worked and found something bad" from "the scan failed".
const EXIT_ISSUES_FOUND: i32 = 10;

/// Parses `std::env::args`. Recognized flags are consumed; any remaining bare
/// words are joined into the time-range expression, so `whyreboot 1 hour ago`
/// works as well as `whyreboot --since "1 hour ago"`.
fn parse_args() -> Args {
    match parse_argv(std::env::args().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => print_help(),
        Err(e) => {
            eprintln!("whyreboot: {e}");
            eprintln!("Try 'whyreboot --help' for usage.");
            std::process::exit(2);
        }
    }
}

/// Pure argument parsing, split out from `parse_args` so it is testable.
/// `Ok(None)` means "help was requested"; `Err` carries a user-facing message.
///
/// A bad value is an **error**, never a silent fallback: `--history abc` and a
/// valueless `--since` used to be ignored, so the tool quietly analyzed a
/// different window than the one asked for. An unknown `--flag` is rejected too,
/// rather than being swept into the time-range expression.
fn parse_argv(argv: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut args = Args {
        history: 1,
        json: false,
        color: true,
        window: None,
        all: false,
        from_file: None,
        exit_code: false,
    };
    let argv: Vec<String> = argv.collect();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    // Consumes the value that follows flag `name`, or reports it missing.
    fn value(argv: &[String], i: usize, name: &str) -> Result<String, String> {
        argv.get(i + 1)
            .filter(|v| !v.starts_with("--"))
            .cloned()
            .ok_or_else(|| format!("{name} needs a value"))
    }
    while i < argv.len() {
        match argv[i].as_str() {
            "--json" => args.json = true,
            "--no-color" => args.color = false,
            "--all" => args.all = true,
            "--exit-code" => args.exit_code = true,
            "--help" | "-h" => return Ok(None),
            "--history" => {
                let v = value(&argv, i, "--history")?;
                args.history = v
                    .parse::<usize>()
                    .map_err(|_| format!("--history needs a number, got '{v}'"))?;
                i += 1;
            }
            "--since" | "--for" | "--window" => {
                args.window = Some(value(&argv, i, argv[i].as_str())?);
                i += 1;
            }
            "--from-file" => {
                args.from_file = Some(value(&argv, i, "--from-file")?.into());
                i += 1;
            }
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("unknown option '{other}'"));
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }
    if args.window.is_none() && !positional.is_empty() {
        args.window = Some(positional.join(" "));
    } else if args.window.is_some() && !positional.is_empty() {
        return Err(format!(
            "unexpected argument '{}' after a time range was already given",
            positional.join(" ")
        ));
    }
    Ok(Some(args))
}

/// One `print!` of one literal rather than ~20 `println!` calls: each call site
/// emits its own `format_args` setup, which is pure weight in a binary this
/// size-sensitive. The exit code is interpolated so the text can't drift from
/// [`EXIT_ISSUES_FOUND`].
fn print_help() -> ! {
    print!(
        "\
whyreboot — diagnose system issues (reboots on Windows; OOM and more on Linux)

USAGE: whyreboot [OPTIONS] [TIME-RANGE]

TIME-RANGE (Linux/macOS):
  A duration or phrase: \"1 hour ago\", \"30 minutes ago\", \"2h\", \"today\",
  \"yesterday\", or \"all\". Defaults to the last 24 hours.

OPTIONS:
  --since <expr>  Time range to analyze (alias: --for, --window)
  --all           Analyze all available history
  --exit-code     Exit {EXIT_ISSUES_FOUND} if a critical issue (or crash reboot) was found
  --history N     [Windows] show last N boot cycles (default: 1)
  --from-file <f> Replay a capture instead of reading live logs:
                  journalctl -o json / log show ndjson, or on Windows
                  `wevtutil qe System /f:xml` event XML
  --json          Output JSON instead of text
  --no-color      Disable ANSI color output
  --help, -h      Show this help

EXIT CODES:
  0 ok   1 could not read logs   2 usage error   {EXIT_ISSUES_FOUND} issues found (--exit-code)
"
    );
    std::process::exit(0);
}

// ── Entry point ─────────────────────────────────────────────────────────────────

fn main() {
    let args = parse_args();
    let pal = if args.color && enable_ansi_color() {
        &COLORS
    } else {
        &NO_COLOR
    };

    #[cfg(windows)]
    run_windows(&args, pal);

    #[cfg(target_os = "linux")]
    run_issue_scan(
        &args,
        pal,
        whyreboot::linux::fetch_journal,
        "Ensure `journalctl` is available and readable (try the systemd-journal or adm group).",
    );

    #[cfg(target_os = "macos")]
    run_issue_scan(
        &args,
        pal,
        whyreboot::macos::fetch_unified_log,
        "Ensure the `log` command is available (macOS 10.12+).",
    );

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (&args, pal);
        eprintln!("whyreboot: this platform is not supported yet.");
        std::process::exit(1);
    }
}

// ── Linux / macOS: issue scanning ───────────────────────────────────────────────

/// Shared unix issue-scan flow: resolve the time window, pull records from the
/// platform log source (or a `--from-file` capture in either supported format),
/// run the detectors, filter, and render.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_issue_scan(
    args: &Args,
    pal: &color::Pal,
    fetch: fn(
        &whyreboot::timewindow::TimeWindow,
    ) -> std::io::Result<Vec<whyreboot::types::LogLine>>,
    fetch_hint: &str,
) {
    use whyreboot::detect::scan;
    use whyreboot::jsonlog::fetch_from_file;
    use whyreboot::timestamp::Timestamp;
    use whyreboot::timewindow::{TimeWindow, parse_window};

    let now = Timestamp::now();

    // Resolve the time window. When reading a fixture file with no explicit
    // range, analyze the whole file rather than the (now-relative) 24h default.
    let window = if args.all {
        TimeWindow::all()
    } else if let Some(expr) = &args.window {
        match parse_window(expr, now) {
            Some(w) => w,
            None => {
                eprintln!("whyreboot: could not understand time range '{expr}'.");
                eprintln!("Try: \"1 hour ago\", \"30 minutes ago\", \"2h\", \"today\", \"all\".");
                std::process::exit(2);
            }
        }
    } else if args.from_file.is_some() {
        TimeWindow::all()
    } else {
        TimeWindow::last_secs(now, 24 * 3600)
    };

    eprintln!("Scanning system logs for issues ({})…", window.describe());

    let lines = match &args.from_file {
        Some(p) => fetch_from_file(p),
        None => fetch(&window),
    };
    let lines = match lines {
        Ok(l) => l,
        Err(e) => {
            eprintln!("whyreboot: failed to read logs: {e}");
            eprintln!("{fetch_hint}");
            std::process::exit(1);
        }
    };

    // Detect, then window-filter (belt-and-suspenders alongside the source's own
    // time bounds, and the only filter for --from-file).
    let findings: Vec<_> = scan(&lines)
        .into_iter()
        .filter(|f| window.contains(f.time))
        .collect();

    eprintln!(
        "  Scanned {} record(s); found {} issue(s).\n",
        lines.len(),
        findings.len()
    );

    if args.json {
        display::print_findings_json(&findings, &window, lines.len());
    } else {
        display::print_findings(&findings, pal, &window, lines.len());
    }

    if args.exit_code
        && findings
            .iter()
            .any(|f| f.severity == whyreboot::types::Severity::Critical)
    {
        std::process::exit(EXIT_ISSUES_FOUND);
    }
}

// ── Windows: reboot diagnosis ──────────────────────────────────────────────────

#[cfg(windows)]
fn run_windows(args: &Args, pal: &color::Pal) {
    use whyreboot::analysis::{extract_boot_cycles, wer_from_event};
    use whyreboot::events::{fetch_system_events, fetch_wer_events, list_minidumps};
    use whyreboot::registry::check_audio_power_settings;
    use whyreboot::xml::parse_event_log;

    // Offline replay of a captured event log, mirroring `--from-file` on the
    // unix backends. Both channels can live in one capture: WER records are
    // recognized by content, not by which file they came from. Minidumps and
    // registry state are machine-local, so they are simply absent in a replay.
    let (sys_events, wer_events, dumps, audio_power) = match &args.from_file {
        Some(p) => {
            eprintln!("Replaying captured event log from {}…", p.display());
            let text = std::fs::read_to_string(p).unwrap_or_else(|e| {
                eprintln!("whyreboot: failed to read {}: {e}", p.display());
                std::process::exit(1);
            });
            let events = parse_event_log(&text);
            let wer = events.iter().filter_map(wer_from_event).collect();
            (events, wer, Vec::new(), Vec::new())
        }
        None => {
            eprintln!("Scanning Windows Event Log for shutdown/reboot events…");
            (
                fetch_system_events(),
                fetch_wer_events(),
                list_minidumps(),
                check_audio_power_settings(),
            )
        }
    };

    if sys_events.is_empty() {
        if args.from_file.is_some() {
            eprintln!("No <Event> records parsed from the capture.");
        } else {
            eprintln!("No events found. Try running as Administrator.");
        }
        std::process::exit(1);
    }
    if !wer_events.is_empty() {
        eprintln!("  Found {} WER BugCheck event(s).", wer_events.len());
    }
    if !dumps.is_empty() {
        eprintln!("  Found {} minidump file(s).", dumps.len());
    }
    if !audio_power.is_empty() {
        eprintln!(
            "  Checked {} audio device power setting(s).",
            audio_power.len()
        );
    }

    let cycles = extract_boot_cycles(&sys_events, &wer_events, &dumps, args.history);
    eprintln!("  Analyzed {} boot cycle(s).\n", cycles.len());

    if args.json {
        display::print_json(&cycles);
    } else {
        for cycle in cycles.iter().rev() {
            display::print_cycle(cycle, pal, cycles.len(), &audio_power);
        }
        println!();
    }

    // Cycle 0 is the most recent boot: gate on how *this* machine last went
    // down, not on any older crash still inside the log window.
    if args.exit_code
        && cycles.first().is_some_and(|c| {
            matches!(
                c.cause,
                whyreboot::types::Cause::BlueScreen { .. }
                    | whyreboot::types::Cause::ForcedPowerOff
                    | whyreboot::types::Cause::UnexpectedShutdown
            )
        })
    {
        std::process::exit(EXIT_ISSUES_FOUND);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_argv;

    fn parse(args: &[&str]) -> Result<Option<super::Args>, String> {
        parse_argv(args.iter().map(|s| s.to_string()))
    }

    fn ok(args: &[&str]) -> super::Args {
        parse(args)
            .expect("should parse")
            .expect("should not be --help")
    }

    #[test]
    fn defaults() {
        let a = ok(&[]);
        assert_eq!(a.history, 1);
        assert!(!a.json && a.color && !a.all && !a.exit_code);
        assert!(a.window.is_none() && a.from_file.is_none());
    }

    #[test]
    fn boolean_flags() {
        let a = ok(&["--json", "--no-color", "--all", "--exit-code"]);
        assert!(a.json && !a.color && a.all && a.exit_code);
    }

    #[test]
    fn help_is_reported_separately_from_an_error() {
        assert!(parse(&["--help"]).expect("help is not an error").is_none());
        assert!(parse(&["-h"]).expect("help is not an error").is_none());
    }

    #[test]
    fn bare_words_join_into_a_time_range() {
        assert_eq!(
            ok(&["1", "hour", "ago"]).window.as_deref(),
            Some("1 hour ago")
        );
    }

    #[test]
    fn since_and_its_aliases_take_a_value() {
        for flag in ["--since", "--for", "--window"] {
            assert_eq!(ok(&[flag, "2h"]).window.as_deref(), Some("2h"), "{flag}");
        }
    }

    #[test]
    fn history_parses_a_number() {
        assert_eq!(ok(&["--history", "5"]).history, 5);
        assert_eq!(ok(&["--history", "0"]).history, 0); // 0 = all cycles
    }

    // ── Input that used to be swallowed silently ──────────────────────────────

    #[test]
    fn history_with_a_non_number_is_an_error() {
        let e = parse(&["--history", "abc"]).expect_err("must not be ignored");
        assert!(e.contains("--history") && e.contains("abc"), "{e}");
    }

    #[test]
    fn flag_without_its_value_is_an_error() {
        for flag in ["--since", "--history", "--from-file"] {
            let e = parse(&[flag]).expect_err("must not be ignored");
            assert!(e.contains(flag), "{flag}: {e}");
        }
    }

    #[test]
    fn flag_followed_by_another_flag_is_a_missing_value() {
        let e = parse(&["--since", "--json"]).expect_err("must not consume the next flag");
        assert!(e.contains("--since"), "{e}");
    }

    #[test]
    fn unknown_option_is_rejected_not_treated_as_a_time_range() {
        let e = parse(&["--verbose"]).expect_err("must not be a time range");
        assert!(
            e.contains("unknown option") && e.contains("--verbose"),
            "{e}"
        );
    }

    #[test]
    fn from_file_takes_a_path() {
        assert_eq!(
            ok(&["--from-file", "cap.jsonl"]).from_file.as_deref(),
            Some(std::path::Path::new("cap.jsonl"))
        );
    }
}
