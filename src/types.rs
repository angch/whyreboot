use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub event_id:     u32,
    pub time_created: DateTime<Local>,
    pub provider:     String,
    pub data:         HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct WerRecord {
    pub time_created:  DateTime<Local>,
    pub p1:            u64,
    pub bucket_id:     String,
    pub minidump_path: Option<PathBuf>,
}

#[allow(dead_code)]
pub struct AudioPowerInfo {
    pub instance:      String,
    pub name:          String,
    pub allow_idle_d3: Option<u32>,
    pub enhanced_pm:   Option<u32>,
}

#[derive(Debug)]
pub enum Cause {
    BlueScreen { stop_code: u64, stop_name: &'static str, params: [u64; 4] },
    ForcedPowerOff,
    UnexpectedShutdown,
    WindowsUpdate  { process: String },
    UserAction     { user: String, action: String, comment: String },
    SystemProcess  { process: String, reason: String, action: String },
    NormalShutdown,
    Undetermined,
}

pub struct BootCycle {
    pub index:          usize,
    pub boot_time:      Option<DateTime<Local>>,
    pub shutdown_time:  Option<DateTime<Local>>,
    pub cause:          Cause,
    pub confidence:     u8,
    pub evidence:       Vec<String>,
    pub timeline:       Vec<(DateTime<Local>, String)>,
    pub wer_module:     Option<String>,
    pub minidumps:      Vec<(DateTime<Local>, PathBuf)>,
    pub display_events: Vec<EventRecord>,
}
