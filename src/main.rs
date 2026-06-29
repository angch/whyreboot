mod analysis;
mod color;
mod display;
mod events;
mod registry;
mod types;
mod xml;

use color::{enable_ansi_color, COLORS, NO_COLOR};
use display::{print_cycle, print_json};
use events::{fetch_system_events, fetch_wer_events, list_minidumps};
use registry::check_audio_power_settings;
use analysis::extract_boot_cycles;

// ── CLI ───────────────────────────────────────────────────────────────────────

/// Parsed command-line options.
struct Args {
    history: usize,
    json:    bool,
    color:   bool,
}

/// Parses `std::env::args` into `Args`. Unknown flags are silently ignored.
fn parse_args() -> Args {
    let mut args = Args { history: 1, json: false, color: true };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--json"        => args.json  = true,
            "--no-color"    => args.color = false,
            "--all"         => args.history = 0,
            "--help" | "-h" => print_help(),
            "--history" => {
                i += 1;
                if let Some(n) = argv.get(i).and_then(|s| s.parse::<usize>().ok()) {
                    args.history = n;
                }
            }
            _ => {}
        }
        i += 1;
    }
    args
}

fn print_help() -> ! {
    println!("whyreboot — diagnose why Windows last rebooted");
    println!();
    println!("USAGE: whyreboot [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --history N   Show last N boot cycles (default: 1)");
    println!("  --all         Show all boot cycles in the log");
    println!("  --json        Output JSON instead of text");
    println!("  --no-color    Disable ANSI color output");
    println!("  --help, -h    Show this help");
    std::process::exit(0);
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args = parse_args();
    let pal  = if args.color && enable_ansi_color() { &COLORS } else { &NO_COLOR };

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
        print_json(&cycles);
    } else {
        for cycle in cycles.iter().rev() {
            print_cycle(cycle, pal, cycles.len(), &audio_power);
        }
        println!();
    }
}
