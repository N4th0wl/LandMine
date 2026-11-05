use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::Severity;

/// Jenis event dalam lifecycle sebuah proses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Proses yang sudah berjalan saat LandMine pertama kali melakukan scan.
    ProcessSnapshot,
    /// Proses baru yang muncul setelah scan awal.
    ProcessStarted,
    /// Terjadi eskalasi hak akses / privilege pada proses yang sedang berjalan.
    ProcessElevated,
    /// Proses mencurigakan (>= Medium) yang sudah keluar.
    ProcessTerminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcEvent {
    pub ts_utc: DateTime<Utc>,
    pub event_type: EventType,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub parent_name: Option<String>,
    pub exe_path: Option<String>,
    pub original_filename: Option<String>,
    pub command_line: Option<String>,
    pub sha256: Option<String>,
    pub is_elevated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_destinations: Vec<String>,
    pub flags: Vec<String>,
    pub matched_rules: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub flags: Vec<String>,
    pub matched_rules: Vec<String>,
    pub severity: Severity,
}
