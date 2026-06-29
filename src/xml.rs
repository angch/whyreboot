use std::collections::HashMap;
use chrono::{DateTime, Local};
use crate::types::EventRecord;

pub fn xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let start = xml.find(&format!("<{}", tag))?;
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
    None
}

pub fn xml_elem(xml: &str, tag: &str) -> Option<String> {
    let open  = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)?;
    Some(xml[s..s + e].trim().to_string())
}

pub fn xml_data(xml: &str) -> HashMap<String, String> {
    let mut map   = HashMap::new();
    let mut cursor = 0;
    let mut anon  = 0usize;
    while let Some(rel) = xml[cursor..].find("<Data") {
        let abs  = cursor + rel;
        let rest = &xml[abs..];
        let name = xml_attr(rest, "Data", "Name");
        if let Some(gt) = rest.find('>') {
            if rest.get(gt.saturating_sub(1)..gt) == Some("/") {
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

pub fn parse_event(xml: &str) -> Option<EventRecord> {
    let event_id: u32 = xml_elem(xml, "EventID")?.parse().ok()?;
    let time_str      = xml_attr(xml, "TimeCreated", "SystemTime")?;
    let time_created  = DateTime::parse_from_rfc3339(&time_str).ok()?.with_timezone(&Local);
    let provider      = xml_attr(xml, "Provider", "Name").unwrap_or_default();
    let data          = xml_data(xml);
    Some(EventRecord { event_id, time_created, provider, data })
}
