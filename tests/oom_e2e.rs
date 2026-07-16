// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end test of the OOM path: fixture file → parse → detect → window filter.
//! Exercises the same code the Linux CLI runs (minus the journalctl invocation),
//! proving field extraction lines up with real journalctl `-o json` output.

use whyreboot::detect::scan;
use whyreboot::jsonlog::fetch_from_file;
use whyreboot::timestamp::Timestamp;
use whyreboot::timewindow::TimeWindow;

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

#[test]
fn detects_kernel_and_oomd_kills_from_fixture() {
    let lines = fetch_from_file(&fixture("oom.jsonl")).expect("read fixture");
    // 6 records in the fixture, all parsed.
    assert_eq!(lines.len(), 6, "all journal lines should parse");

    let findings: Vec<_> = scan(&lines).into_iter().filter(|f| f.category == "OOM").collect();
    assert_eq!(findings.len(), 2, "one kernel kill + one systemd-oomd kill");

    // Newest first: the systemd-oomd kill (20:01) precedes the kernel kill (20:00).
    assert_eq!(findings[0].source, "systemd-oomd");
    assert!(findings[0].title.contains("Builder.service"));

    let kernel = &findings[1];
    assert_eq!(kernel.source, "journald:kernel");
    assert!(kernel.title.contains("chrome"));
    assert!(kernel.title.contains("4242"));
    assert!(kernel.evidence.iter().any(|e| e.contains("2.4 GB")));

    // The "invoked oom-killer" and "oom-kill:" context lines must NOT create
    // extra findings (no double counting for a single kill).
    assert!(findings.iter().all(|f| f.category == "OOM"));
}

#[test]
fn detects_mixed_categories_and_coalesces_ata_burst() {
    let lines = fetch_from_file(&fixture("mixed.jsonl")).expect("read fixture");
    let findings = scan(&lines);

    // Expect one finding per distinct incident: the 10-line ATA burst collapses
    // to a single Disk finding, plus segfault, coredump, service failure, panic.
    let cats: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
    assert!(cats.contains(&"Disk"),      "categories: {cats:?}");
    assert!(cats.contains(&"Segfault"),  "categories: {cats:?}");
    assert!(cats.contains(&"Coredump"),  "categories: {cats:?}");
    assert!(cats.contains(&"Service"),   "categories: {cats:?}");
    assert!(cats.contains(&"KernelPanic"), "categories: {cats:?}");

    // The ATA burst must be exactly one Disk finding, not ten.
    assert_eq!(findings.iter().filter(|f| f.category == "Disk").count(), 1);
    let disk = findings.iter().find(|f| f.category == "Disk").unwrap();
    assert!(disk.title.contains("related log lines"), "title: {}", disk.title);
}

#[test]
fn gpu_cascade_detected_and_correlated() {
    let lines = fetch_from_file(&fixture("gpu.jsonl")).expect("read fixture");
    let findings = scan(&lines);

    let cats: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
    assert!(cats.contains(&"GPU"),      "categories: {cats:?}");
    assert!(cats.contains(&"Segfault"), "categories: {cats:?}");
    assert!(cats.contains(&"Coredump"), "categories: {cats:?}");
    assert!(cats.contains(&"Session"),  "categories: {cats:?}");

    // The GPU HANG + heartbeat-reset burst coalesces into one GPU finding.
    assert_eq!(findings.iter().filter(|f| f.category == "GPU").count(), 1);
    let gpu = findings.iter().find(|f| f.category == "GPU").unwrap();
    assert!(gpu.evidence.iter().any(|e| e.contains("gnome-shell")),
        "culprit workload should be extracted: {:?}", gpu.evidence);

    // Correlation: the GPU incident lists its casualties, and the session-loss
    // finding points back at both the GPU incident and the compositor crash.
    assert!(gpu.evidence.iter().any(|e| e.contains("casualty")), "{:?}", gpu.evidence);
    let ses = findings.iter().find(|f| f.category == "Session").unwrap();
    assert!(ses.evidence.iter().any(|e| e.contains("GPU incident")), "{:?}", ses.evidence);

    // The trailing benign "[drm] Initialized i915" boot banner must not match.
    assert!(!findings.iter().any(|f| f.title.contains("Initialized")));

    // The two client connection-loss lines (firefox + nautilus, 0.3s apart)
    // coalesce with the gnome-session failure into Session finding(s), never
    // one finding per app per line spamming the report.
    assert!(findings.len() <= 5, "expected a compact report, got: {cats:?}");
}

#[test]
fn macos_ndjson_fixture_detects_shutdown_panic_crash_and_update() {
    // macOS `log show --style ndjson` format, parsed by the same shared code —
    // this runs on every platform, so the macOS path is regression-tested on Linux CI.
    let lines = fetch_from_file(&fixture("macos.jsonl")).expect("read fixture");
    assert_eq!(lines.len(), 8, "all ndjson lines should parse");

    let findings = scan(&lines);
    let cats: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
    assert!(cats.contains(&"ShutdownCause"),  "categories: {cats:?}");
    assert!(cats.contains(&"KernelPanic"),    "categories: {cats:?}");
    assert!(cats.contains(&"Crash"),          "categories: {cats:?}");
    assert!(cats.contains(&"SleepWake"),      "categories: {cats:?}");
    assert!(cats.contains(&"UpdateRestart"),  "categories: {cats:?}");

    // Clean shutdown (cause 5) and the benign Thunderbolt line yield nothing:
    // exactly one ShutdownCause finding (the -61 watchdog).
    assert_eq!(findings.iter().filter(|f| f.category == "ShutdownCause").count(), 1);

    // Live-Mac regression: the kernel tcp_connection_summary line (with its
    // literal "<IPv4-redacted>" and "so_error: 0") must yield NO finding.
    assert!(!findings.iter().any(|f| f.category == "Hardware"),
        "redacted tcp summary must not be a Hardware finding");

    // The watchdog panic names WindowServer, and the shutdown cause is Critical.
    let panic = findings.iter().find(|f| f.category == "KernelPanic").unwrap();
    assert!(panic.title.contains("WindowServer"));
    let sc = findings.iter().find(|f| f.category == "ShutdownCause").unwrap();
    assert!(sc.title.contains("-61"));

    // Timestamps parsed with offset: the -61 line is 2026-07-10T08:00:05Z.
    assert_eq!(sc.time.to_rfc3339(), "2026-07-10T08:00:05Z");
}

#[test]
fn window_filter_excludes_out_of_range_findings() {
    let lines = fetch_from_file(&fixture("oom.jsonl")).expect("read fixture");
    let all = scan(&lines);

    // A window ending before every fixture event yields nothing.
    let empty = TimeWindow { start: None, end: Some(Timestamp(1_000_000_000)) };
    assert_eq!(all.iter().filter(|f| empty.contains(f.time)).count(), 0);

    // A window covering the fixture's day yields both.
    let day = TimeWindow {
        start: Some(Timestamp(1_783_598_000)),
        end:   Some(Timestamp(1_783_599_000)),
    };
    assert_eq!(all.iter().filter(|f| day.contains(f.time)).count(), 2);
}
