// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end replay of a captured Windows event log through the boot-cycle
//! analysis — the coverage the Windows path could not otherwise have.
//!
//! `--from-file` feeds a `wevtutil qe System /f:xml` capture to exactly this
//! pipeline. Everything here (XML parsing, WER mapping, cycle extraction,
//! classification) is portable, so these run on Linux and macOS CI too; only the
//! live `EvtQuery` fetch is Windows-only.

use whyreboot::analysis::{extract_boot_cycles, wer_from_event};
use whyreboot::types::Cause;
use whyreboot::xml::parse_event_log;

const CAPTURE: &str = include_str!("fixtures/windows_events.xml");

const WER_1001: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
 <System><Provider Name='Windows Error Reporting'/><EventID Qualifiers='0'>1001</EventID>
  <TimeCreated SystemTime='2026-06-28T08:02:00.000000000Z'/></System>
 <EventData>
  <Data Name='EventName'>BlueScreen</Data>
  <Data Name='P1'>9f</Data>
  <Data Name='Bucket'>0x9F_3_DXG_POWER_IRP_TIMEOUT_portcls!GetIrpDisposition</Data>
  <Data Name='AttachedFiles'>\\?\C:\Windows\Minidump\062826-9203-01.dmp</Data>
 </EventData>
</Event>"#;

#[test]
fn capture_parses_into_records() {
    let events = parse_event_log(CAPTURE);
    let ids: Vec<u32> = events.iter().map(|e| e.event_id).collect();
    assert_eq!(ids, vec![41, 6008, 12, 6009, 7045, 12], "ids: {ids:?}");
    // Attributes on the opening tag (legacy providers) must not defeat the
    // element scan, and `<EventID>` must not be mistaken for a document start.
    assert_eq!(events[1].provider, "EventLog");
}

#[test]
fn bsod_cycle_is_classified_from_a_capture() {
    let events = parse_event_log(CAPTURE);
    let cycles = extract_boot_cycles(&events, &[], &[], 0);
    assert_eq!(cycles.len(), 2, "two Event 12 boots in the capture");

    // Cycle 0 is the recovery boot; its Event 41 reports the previous session's
    // bugcheck, so the verdict belongs to that cycle.
    let Cause::BlueScreen {
        stop_code,
        stop_name,
        params,
    } = cycles[0].cause
    else {
        panic!("expected a BlueScreen verdict, got {:?}", cycles[0].cause);
    };
    assert_eq!(stop_code, 0x9F);
    assert_eq!(stop_name, "DRIVER_POWER_STATE_FAILURE");
    assert_eq!(params[0], 3, "P1=3 → stalled on IRP_MN_SET_POWER");
    assert!(
        cycles[0].confidence >= 80,
        "confidence: {}",
        cycles[0].confidence
    );
}

#[test]
fn driver_installed_before_the_crash_is_flagged() {
    let events = parse_event_log(CAPTURE);
    let cycles = extract_boot_cycles(&events, &[], &[], 0);
    // The 7045 sits in the session that crashed (between the two boots).
    assert!(
        cycles[0]
            .evidence
            .iter()
            .any(|e| e.contains("RTKVHD64") && e.contains("Driver")),
        "evidence: {:?}",
        cycles[0].evidence
    );
}

#[test]
fn wer_record_supplies_the_faulting_module_and_minidump() {
    let wer: Vec<_> = parse_event_log(WER_1001)
        .iter()
        .filter_map(wer_from_event)
        .collect();
    assert_eq!(wer.len(), 1, "the 1001 record should map to a WerRecord");
    assert_eq!(wer[0].p1, 0x9F, "P1 is bare hex, not decimal");

    let events = parse_event_log(CAPTURE);
    let cycles = extract_boot_cycles(&events, &wer, &[], 0);
    assert_eq!(cycles[0].wer_module.as_deref(), Some("portcls"));
    // The `\\?\` UNC prefix is stripped from the attached dump path.
    let dumps: Vec<String> = cycles[0]
        .minidumps
        .iter()
        .map(|(_, p)| p.to_string_lossy().into_owned())
        .collect();
    assert_eq!(dumps, vec![r"C:\Windows\Minidump\062826-9203-01.dmp"]);
}

#[test]
fn garbage_input_yields_no_records_rather_than_panicking() {
    assert!(parse_event_log("").is_empty());
    assert!(parse_event_log("not xml at all").is_empty());
    assert!(parse_event_log("<Event><System><EventID>abc</EventID></System></Event>").is_empty());
    // Unterminated document: stop cleanly instead of looping or slicing past the end.
    assert!(parse_event_log("<Event xmlns='x'><System><EventID>41</EventID>").is_empty());
}
