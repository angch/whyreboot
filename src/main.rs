// SPDX-License-Identifier: MIT OR Apache-2.0
//! whyreboot — cross-platform system-issue diagnostics.
//!
//! On Windows it diagnoses why the machine last rebooted (Event Log / WER).
//! On Linux it scans the systemd journal for logged system issues over a time
//! window — starting with out-of-memory (OOM) kills, which need not have caused
//! a reboot at all.

mod color;
mod display;

use color::{enable_ansi_color, COLORS, NO_COLOR};

// ── CLI ───────────────────────────────────────────────────────────────────────

/// Parsed command-line options (superset across platforms; each backend uses the
/// subset that applies to it).
struct Args {
    /// Windows: number of boot cycles to show (default 1; 0 = all).
    history:   usize,
    json:      bool,
    color:     bool,
    /// Time-range expression, e.g. "1 hour ago" / "today" / "2h" (Linux).
    window:    Option<String>,
    /// Analyze all available history regardless of window.
    all:       bool,
    /// Read journalctl `-o json` records from this file instead of the live
    /// journal (Linux; used for testing and offline analysis).
    from_file: Option<std::path::PathBuf>,
}

/// Parses `std::env::args`. Recognized flags are consumed; any remaining bare
/// words are joined into the time-range expression, so `whyreboot 1 hour ago`
/// works as well as `whyreboot --since "1 hour ago"`.
fn parse_args() -> Args {
    let mut args = Args {
        history: 1, json: false, color: true,
        window: None, all: false, from_file: None,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--json"        => args.json  = true,
            "--no-color"    => args.color = false,
            "--all"         => args.all   = true,
            "--help" | "-h" => print_help(),
            "--history" => {
                i += 1;
                if let Some(n) = argv.get(i).and_then(|s| s.parse::<usize>().ok()) {
                    args.history = n;
                }
            }
            "--since" | "--for" | "--window" => {
                i += 1;
                if let Some(v) = argv.get(i) { args.window = Some(v.clone()); }
            }
            "--from-file" => {
                i += 1;
                if let Some(v) = argv.get(i) { args.from_file = Some(v.into()); }
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }
    if args.window.is_none() && !positional.is_empty() {
        args.window = Some(positional.join(" "));
    }
    args
}

fn print_help() -> ! {
    println!("whyreboot — diagnose system issues (reboots on Windows; OOM and more on Linux)");
    println!();
    println!("USAGE: whyreboot [OPTIONS] [TIME-RANGE]");
    println!();
    println!("TIME-RANGE (Linux):");
    println!("  A duration or phrase: \"1 hour ago\", \"30 minutes ago\", \"2h\", \"today\",");
    println!("  \"yesterday\", or \"all\". Defaults to the last 24 hours.");
    println!();
    println!("OPTIONS:");
    println!("  --since <expr>  Time range to analyze (alias: --for, --window)");
    println!("  --all           Analyze all available history");
    println!("  --history N     [Windows] show last N boot cycles (default: 1)");
    println!("  --from-file <f> [Linux] read journalctl -o json records from a file");
    println!("  --json          Output JSON instead of text");
    println!("  --no-color      Disable ANSI color output");
    println!("  --help, -h      Show this help");
    std::process::exit(0);
}

// ── Entry point ─────────────────────────────────────────────────────────────────

fn main() {
    let args = parse_args();
    let pal  = if args.color && enable_ansi_color() { &COLORS } else { &NO_COLOR };

    #[cfg(windows)]
    run_windows(&args, pal);

    #[cfg(target_os = "linux")]
    run_linux(&args, pal);

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (&args, pal);
        eprintln!("whyreboot: this platform is not supported yet.");
        std::process::exit(1);
    }
}

// ── Linux: issue scanning ────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn run_linux(args: &Args, pal: &color::Pal) {
    use whyreboot::detect::scan;
    use whyreboot::linux::{fetch_from_file, fetch_journal};
    use whyreboot::timestamp::Timestamp;
    use whyreboot::timewindow::{parse_window, TimeWindow};

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
        None    => fetch_journal(&window),
    };
    let lines = match lines {
        Ok(l) => l,
        Err(e) => {
            eprintln!("whyreboot: failed to read logs: {e}");
            eprintln!("Ensure `journalctl` is available and readable (try the systemd-journal or adm group).");
            std::process::exit(1);
        }
    };

    // Detect, then window-filter (belt-and-suspenders alongside journalctl's own
    // --since/--until, and the only filter for --from-file).
    let findings: Vec<_> = scan(&lines)
        .into_iter()
        .filter(|f| window.contains(f.time))
        .collect();

    eprintln!("  Scanned {} record(s); found {} issue(s).\n", lines.len(), findings.len());

    if args.json {
        display::print_findings_json(&findings, &window, lines.len());
    } else {
        display::print_findings(&findings, pal, &window, lines.len());
    }
}

// ── Windows: reboot diagnosis ──────────────────────────────────────────────────

#[cfg(windows)]
fn run_windows(args: &Args, pal: &color::Pal) {
    use whyreboot::analysis::extract_boot_cycles;
    use whyreboot::events::{fetch_system_events, fetch_wer_events, list_minidumps};
    use whyreboot::registry::check_audio_power_settings;

    eprintln!("Scanning Windows Event Log for shutdown/reboot events…");

    let sys_events  = fetch_system_events();
    let wer_events  = fetch_wer_events();
    let dumps       = list_minidumps();
    let audio_power = check_audio_power_settings();

    if sys_events.is_empty() {
        eprintln!("No events found. Try running as Administrator.");
        std::process::exit(1);
    }
    if !wer_events.is_empty() {
        eprintln!("  Found {} WER BugCheck event(s).", wer_events.len());
    }
    if !dumps.is_empty() {
        eprintln!("  Found {} minidump file(s).", dumps.len());
    }
    if !audio_power.is_empty() {
        eprintln!("  Checked {} audio device power setting(s).", audio_power.len());
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
}
