// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal XML extraction for Windows Event Log records.
//! `EvtRender(EvtRenderEventXml)` produces well-structured output, so a
//! full parser is unnecessary — string scanning is sufficient and avoids
//! adding an XML dependency.

use crate::timestamp::Timestamp;
use crate::types::EventRecord;

/// True if `c` terminates an XML tag *name*, so that a search for tag `Data`
/// matches `<Data>`, `<Data …>`, and `<Data/>` but never a longer name like
/// `<DataObject>`.
fn is_tag_boundary(c: char) -> bool {
    c == '>' || c == '/' || c.is_ascii_whitespace()
}

/// Given a slice starting at the `<` of an opening tag, returns the byte offset
/// of the `>` that closes it, skipping any `>` that appears inside a single- or
/// double-quoted attribute value. Returns `None` for an unterminated tag.
///
/// Scanning bytes is UTF-8-safe here: `'`, `"`, and `>` are ASCII, and a UTF-8
/// continuation byte never collides with an ASCII byte, so the returned index
/// always falls on a char boundary.
fn find_tag_end(s: &str) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (i, b) in s.bytes().enumerate() {
        match quote {
            Some(q) if b == q       => quote = None,
            Some(_)                 => {}
            None if b == b'\'' || b == b'"' => quote = Some(b),
            None if b == b'>'       => return Some(i),
            None                    => {}
        }
    }
    None
}

/// Extracts an attribute value from the first occurrence of `<tag … attr='…'>`.
/// Handles both single- and double-quoted attribute values.
/// Requires the character immediately after the tag name to be a tag boundary
/// (space, `>`, `/`) to avoid matching longer tag names such as `<DataObject>`
/// when searching for `<Data>`.
pub fn xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_prefix = format!("<{}", tag);
    // A single forward sweep over all occurrences of `tag_prefix`, rather than
    // restarting the search one byte later on each boundary-check failure —
    // the latter is O(n^2) on adversarial input with many false-positive matches.
    for (start, _) in xml.match_indices(&tag_prefix) {
        let after = start + tag_prefix.len();
        if !xml[after..].starts_with(is_tag_boundary) { continue; }
        let Some(region_end) = find_tag_end(&xml[start..]) else { continue };
        let region = &xml[start..start + region_end];
        for (open, close) in [("='", '\''), ("=\"", '"')] {
            let search = format!("{}{}", attr, open);
            if let Some(pos) = region.find(&search) {
                let vs = pos + search.len();
                if let Some(ve) = region[vs..].find(close) {
                    return Some(region[vs..vs + ve].to_string());
                }
            }
        }
        return None;
    }
    None
}

/// Extracts the trimmed text content of `<tag …>…</tag>` (first occurrence only).
/// Tolerates attributes on the opening tag (e.g. `<EventID Qualifiers='32768'>1074</EventID>`,
/// as emitted for events from legacy providers like `User32` and `EventLog`) — matching
/// only a bare `<tag>` would miss these entirely. Self-closing `<tag/>` has no
/// content and is skipped.
pub fn xml_elem(xml: &str, tag: &str) -> Option<String> {
    let tag_prefix = format!("<{}", tag);
    let close = format!("</{}>", tag);
    for (start, _) in xml.match_indices(&tag_prefix) {
        let after = start + tag_prefix.len();
        if !xml[after..].starts_with(is_tag_boundary) { continue; }
        let Some(end) = find_tag_end(&xml[start..]) else { continue };
        if xml[start..start + end].ends_with('/') { continue; } // self-closing: no content
        let s = start + end + 1;
        let Some(e) = xml[s..].find(&close) else { continue };
        return Some(xml[s..s + e].trim().to_string());
    }
    None
}

/// Collects all `<Data Name="key">value</Data>` pairs from an event XML fragment.
/// Fields without a `Name` attribute are assigned anonymous keys `_0`, `_1`, etc.
/// Self-closing `<Data … />` elements are skipped (empty values).
pub fn xml_data(xml: &str) -> Vec<(String, String)> {
    let mut map  = Vec::new();
    let mut anon = 0usize;
    // Single forward sweep over all "<Data" occurrences (see `xml_attr` for why
    // this replaces a restart-by-one-byte loop). `resume_from` skips matches that
    // fall inside a region already consumed by a previously parsed element.
    let mut resume_from = 0usize;
    for (abs, _) in xml.match_indices("<Data") {
        if abs < resume_from { continue; }
        let rest = &xml[abs..];
        // Guard against matching <DataSomethingElse> when we want only <Data …>.
        if !rest["<Data".len()..].starts_with(is_tag_boundary) {
            continue;
        }
        let name = xml_attr(rest, "Data", "Name");
        let Some(gt) = find_tag_end(rest) else { continue };
        if rest[..gt].ends_with('/') {
            resume_from = abs + gt + 1;
            continue;
        }
        let cs = gt + 1;
        let Some(end) = rest[cs..].find("</Data>") else { continue };
        let value = rest[cs..cs + end].trim().to_string();
        let key = name.unwrap_or_else(|| {
            let k = format!("_{}", anon);
            anon += 1;
            k
        });
        map.push((key, value));
        resume_from = abs + cs + end + 7;
    }
    map
}

/// Parses a complete event XML string produced by `EvtRender` into an `EventRecord`.
/// Returns `None` if the minimum required fields (EventID, SystemTime) are absent.
pub fn parse_event(xml: &str) -> Option<EventRecord> {
    let event_id: u32 = xml_elem(xml, "EventID")?.parse().ok()?;
    let time_str      = xml_attr(xml, "TimeCreated", "SystemTime")?;
    let time_created  = Timestamp::from_rfc3339(&time_str)?;
    let provider      = xml_attr(xml, "Provider", "Name").unwrap_or_default();
    let data          = xml_data(xml);
    Some(EventRecord { event_id, time_created, provider, data })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Realistic EvtRender output for an Event 41 (unexpected shutdown with BSOD).
    // BugcheckCode 159 == 0x9F. SelfEmpty tests self-closing element skipping.
    const EV41_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
 <System>
  <Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/>
  <EventID>41</EventID>
  <TimeCreated SystemTime='2026-06-29T10:00:00.000000000Z'/>
 </System>
 <EventData>
  <Data Name='BugcheckCode'>159</Data>
  <Data Name='BugcheckParameter1'>3</Data>
  <Data Name='SelfEmpty'/>
 </EventData>
</Event>"#;

    // ── xml_attr ──────────────────────────────────────────────────────────────

    #[test]
    fn attr_single_quote() {
        assert_eq!(
            xml_attr("<Provider Name='Kernel-Power'>", "Provider", "Name"),
            Some("Kernel-Power".to_string())
        );
    }

    #[test]
    fn attr_double_quote() {
        assert_eq!(
            xml_attr(r#"<TimeCreated SystemTime="2026-06-29T10:00:00Z"/>"#, "TimeCreated", "SystemTime"),
            Some("2026-06-29T10:00:00Z".to_string())
        );
    }

    #[test]
    fn attr_missing_tag() {
        assert_eq!(xml_attr("<Provider Name='foo'>", "System", "Name"), None);
    }

    #[test]
    fn attr_missing_attr() {
        assert_eq!(xml_attr("<Provider Name='foo'>", "Provider", "Guid"), None);
    }

    #[test]
    fn attr_first_occurrence_only() {
        // Two Provider tags — only the first is matched.
        let xml = "<Provider Name='first'/><Provider Name='second'/>";
        assert_eq!(xml_attr(xml, "Provider", "Name"), Some("first".to_string()));
    }

    #[test]
    fn attr_skips_longer_tag_name() {
        // <SystemTime> must not be matched when searching for <System>.
        let xml = r#"<SystemTime attr='wrong'/><System Name='right'/>"#;
        assert_eq!(xml_attr(xml, "System", "Name"), Some("right".to_string()));
    }

    #[test]
    fn attr_ignores_gt_inside_quoted_value() {
        // A '>' inside an earlier attribute value must not be mistaken for the
        // end of the opening tag, or a later attribute becomes unreachable.
        let xml = r#"<Provider Name='a>b' Guid='xyz'/>"#;
        assert_eq!(xml_attr(xml, "Provider", "Guid"), Some("xyz".to_string()));
        assert_eq!(xml_attr(xml, "Provider", "Name"), Some("a>b".to_string()));
    }

    // ── xml_elem ─────────────────────────────────────────────────────────────

    #[test]
    fn elem_basic() {
        assert_eq!(xml_elem("<EventID>41</EventID>", "EventID"), Some("41".to_string()));
    }

    #[test]
    fn elem_trims_whitespace() {
        assert_eq!(xml_elem("<EventID>  41  </EventID>", "EventID"), Some("41".to_string()));
    }

    #[test]
    fn elem_missing() {
        assert_eq!(xml_elem("<EventID>41</EventID>", "Level"), None);
    }

    #[test]
    fn elem_first_occurrence_only() {
        let xml = "<EventID>41</EventID><EventID>42</EventID>";
        assert_eq!(xml_elem(xml, "EventID"), Some("41".to_string()));
    }

    #[test]
    fn elem_tolerates_attributes_on_opening_tag() {
        // Legacy providers (User32, EventLog) emit `<EventID Qualifiers='32768'>1074</EventID>`.
        assert_eq!(
            xml_elem("<EventID Qualifiers='32768'>1074</EventID>", "EventID"),
            Some("1074".to_string())
        );
    }

    #[test]
    fn elem_skips_longer_tag_name() {
        // <EventIDFoo> must not be matched when searching for <EventID>.
        let xml = "<EventIDFoo>99</EventIDFoo><EventID>41</EventID>";
        assert_eq!(xml_elem(xml, "EventID"), Some("41".to_string()));
    }

    #[test]
    fn elem_self_closing_has_no_content() {
        // A self-closing tag carries no text; don't fall through to a later
        // element's close tag and return garbage.
        assert_eq!(xml_elem("<EventID/>", "EventID"), None);
        // ...but a real element after a self-closing one is still found.
        let xml = "<EventID/><EventID>41</EventID>";
        assert_eq!(xml_elem(xml, "EventID"), Some("41".to_string()));
    }

    // ── xml_data ─────────────────────────────────────────────────────────────

    fn dget<'a>(m: &'a [(String, String)], key: &str) -> Option<&'a str> {
        m.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn data_named_fields() {
        let xml = r#"<Data Name="BugcheckCode">159</Data><Data Name="BugcheckParameter1">3</Data>"#;
        let m = xml_data(xml);
        assert_eq!(dget(&m, "BugcheckCode"), Some("159"));
        assert_eq!(dget(&m, "BugcheckParameter1"), Some("3"));
    }

    #[test]
    fn data_anonymous_fields_keyed_sequentially() {
        let xml = "<Data>first</Data><Data>second</Data>";
        let m = xml_data(xml);
        assert_eq!(dget(&m, "_0"), Some("first"));
        assert_eq!(dget(&m, "_1"), Some("second"));
    }

    #[test]
    fn data_self_closing_skipped() {
        let xml = r#"<Data Name="Empty"/><Data Name="Real">value</Data>"#;
        let m = xml_data(xml);
        assert!(dget(&m, "Empty").is_none());
        assert_eq!(dget(&m, "Real"), Some("value"));
    }

    #[test]
    fn data_empty_input() {
        assert!(xml_data("").is_empty());
    }

    #[test]
    fn data_trims_content_whitespace() {
        let xml = r#"<Data Name="K">  hello  </Data>"#;
        let m = xml_data(xml);
        assert_eq!(dget(&m, "K"), Some("hello"));
    }

    #[test]
    fn data_skips_longer_tag_name() {
        // <DataProvider> must not be matched as <Data>.
        let xml = r#"<DataProvider Name="wrong"/><Data Name="right">val</Data>"#;
        let m = xml_data(xml);
        assert!(dget(&m, "wrong").is_none(), "longer tag name must not be matched");
        assert_eq!(dget(&m, "right"), Some("val"));
    }

    // ── parse_event ───────────────────────────────────────────────────────────

    #[test]
    fn parse_event_valid() {
        let rec = parse_event(EV41_XML).expect("should parse valid event");
        assert_eq!(rec.event_id, 41);
        assert_eq!(rec.provider, "Microsoft-Windows-Kernel-Power");
        assert_eq!(rec.get("BugcheckCode"), Some("159"));
        // Self-closing Data element must be absent.
        assert!(rec.get("SelfEmpty").is_none());
    }

    #[test]
    fn parse_event_missing_event_id() {
        let xml = r#"<Event><System><TimeCreated SystemTime='2026-06-29T10:00:00Z'/></System></Event>"#;
        assert!(parse_event(xml).is_none());
    }

    #[test]
    fn parse_event_non_numeric_event_id() {
        let xml = r#"<Event><System><EventID>abc</EventID><TimeCreated SystemTime='2026-06-29T10:00:00Z'/></System></Event>"#;
        assert!(parse_event(xml).is_none());
    }

    #[test]
    fn parse_event_missing_time() {
        let xml = r#"<Event><System><EventID>12</EventID></System></Event>"#;
        assert!(parse_event(xml).is_none());
    }

    #[test]
    fn parse_event_invalid_time_format() {
        let xml = r#"<Event><System><EventID>12</EventID><TimeCreated SystemTime='not-a-date'/></System></Event>"#;
        assert!(parse_event(xml).is_none());
    }

    #[test]
    fn parse_event_missing_provider_returns_empty_string() {
        let xml = r#"<Event><System><EventID>6008</EventID><TimeCreated SystemTime='2026-06-29T10:00:00Z'/></System></Event>"#;
        let rec = parse_event(xml).expect("should parse without provider");
        assert_eq!(rec.event_id, 6008);
        assert_eq!(rec.provider, "");
    }
}
