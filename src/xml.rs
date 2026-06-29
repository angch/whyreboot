// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal XML extraction for Windows Event Log records.
//! `EvtRender(EvtRenderEventXml)` produces well-structured output, so a
//! full parser is unnecessary — string scanning is sufficient and avoids
//! adding an XML dependency.

use std::collections::HashMap;
use chrono::{DateTime, Local};
use crate::types::EventRecord;

/// Extracts an attribute value from the first occurrence of `<tag … attr='…'>`.
/// Handles both single- and double-quoted attribute values.
/// Requires the character immediately after the tag name to be a word boundary
/// (space, `>`, `/`) to avoid matching longer tag names such as `<DataObject>`
/// when searching for `<Data>`.
pub fn xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_prefix = format!("<{}", tag);
    let mut from = 0;
    loop {
        let start = xml[from..].find(&tag_prefix).map(|i| from + i)?;
        let after = start + tag_prefix.len();
        if xml[after..].starts_with(|c: char| c == '>' || c == '/' || c.is_ascii_whitespace()) {
            let region_end = xml[start..].find('>')?;
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
        from = start + 1;
    }
}

/// Extracts the trimmed text content of `<tag>…</tag>` (first occurrence only).
pub fn xml_elem(xml: &str, tag: &str) -> Option<String> {
    let open  = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)?;
    Some(xml[s..s + e].trim().to_string())
}

/// Collects all `<Data Name="key">value</Data>` pairs from an event XML fragment.
/// Fields without a `Name` attribute are assigned anonymous keys `_0`, `_1`, etc.
/// Self-closing `<Data … />` elements are skipped (empty values).
pub fn xml_data(xml: &str) -> HashMap<String, String> {
    let mut map    = HashMap::new();
    let mut cursor = 0;
    let mut anon   = 0usize;
    while let Some(rel) = xml[cursor..].find("<Data") {
        let abs  = cursor + rel;
        let rest = &xml[abs..];
        // Guard against matching <DataSomethingElse> when we want only <Data …>.
        if !rest[5..].starts_with(|c: char| c == '>' || c == '/' || c.is_ascii_whitespace()) {
            cursor = abs + 1;
            continue;
        }
        let name = xml_attr(rest, "Data", "Name");
        if let Some(gt) = rest.find('>') {
            if rest[..gt].ends_with('/') {
                cursor = abs + gt + 1;
                continue;
            }
            let cs = gt + 1;
            if let Some(end) = rest[cs..].find("</Data>") {
                let value = rest[cs..cs + end].trim().to_string();
                let key = name.unwrap_or_else(|| {
                    let k = format!("_{}", anon);
                    anon += 1;
                    k
                });
                map.insert(key, value);
                cursor = abs + cs + end + 7;
            } else {
                cursor = abs + 1;
            }
        } else {
            cursor = abs + 1;
        }
    }
    map
}

/// Parses a complete event XML string produced by `EvtRender` into an `EventRecord`.
/// Returns `None` if the minimum required fields (EventID, SystemTime) are absent.
pub fn parse_event(xml: &str) -> Option<EventRecord> {
    let event_id: u32 = xml_elem(xml, "EventID")?.parse().ok()?;
    let time_str      = xml_attr(xml, "TimeCreated", "SystemTime")?;
    let time_created  = DateTime::parse_from_rfc3339(&time_str).ok()?.with_timezone(&Local);
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

    // ── xml_data ─────────────────────────────────────────────────────────────

    #[test]
    fn data_named_fields() {
        let xml = r#"<Data Name="BugcheckCode">159</Data><Data Name="BugcheckParameter1">3</Data>"#;
        let m = xml_data(xml);
        assert_eq!(m.get("BugcheckCode"), Some(&"159".to_string()));
        assert_eq!(m.get("BugcheckParameter1"), Some(&"3".to_string()));
    }

    #[test]
    fn data_anonymous_fields_keyed_sequentially() {
        let xml = "<Data>first</Data><Data>second</Data>";
        let m = xml_data(xml);
        assert_eq!(m.get("_0"), Some(&"first".to_string()));
        assert_eq!(m.get("_1"), Some(&"second".to_string()));
    }

    #[test]
    fn data_self_closing_skipped() {
        let xml = r#"<Data Name="Empty"/><Data Name="Real">value</Data>"#;
        let m = xml_data(xml);
        assert!(!m.contains_key("Empty"));
        assert_eq!(m.get("Real"), Some(&"value".to_string()));
    }

    #[test]
    fn data_empty_input() {
        assert!(xml_data("").is_empty());
    }

    #[test]
    fn data_trims_content_whitespace() {
        let xml = r#"<Data Name="K">  hello  </Data>"#;
        let m = xml_data(xml);
        assert_eq!(m.get("K"), Some(&"hello".to_string()));
    }

    #[test]
    fn data_skips_longer_tag_name() {
        // <DataProvider> must not be matched as <Data>.
        let xml = r#"<DataProvider Name="wrong"/><Data Name="right">val</Data>"#;
        let m = xml_data(xml);
        assert!(!m.contains_key("wrong"), "longer tag name must not be matched");
        assert_eq!(m.get("right"), Some(&"val".to_string()));
    }

    // ── parse_event ───────────────────────────────────────────────────────────

    #[test]
    fn parse_event_valid() {
        let rec = parse_event(EV41_XML).expect("should parse valid event");
        assert_eq!(rec.event_id, 41);
        assert_eq!(rec.provider, "Microsoft-Windows-Kernel-Power");
        assert_eq!(rec.data.get("BugcheckCode"), Some(&"159".to_string()));
        // Self-closing Data element must be absent.
        assert!(!rec.data.contains_key("SelfEmpty"));
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
