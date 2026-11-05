//! Stateful lifecycle tracking (roadmap 3.1): setiap proses hanya dinilai &
//! dicatat sekali saat pertama terlihat, bukan di setiap siklus polling.
//! Mendukung deduplikasi, deteksi eskalasi hak akses (ProcessElevated),
//! dan emisi event saat proses berakhir (ProcessTerminated).

use std::collections::{HashMap, HashSet};

use crate::models::{EventType, ProcEvent, Severity};
use chrono::Utc;

/// Identitas unik proses. PID saja tidak cukup karena OS memakai ulang PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcKey {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Debug, Clone)]
struct TrackedProcess {
    is_elevated: bool,
    event: Option<ProcEvent>,
}

#[derive(Debug, Default)]
pub struct LifecycleTracker {
    known: HashMap<ProcKey, TrackedProcess>,
}

impl LifecycleTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_known(&self, key: &ProcKey) -> bool {
        self.known.contains_key(key)
    }

    pub fn track(&mut self, key: ProcKey, is_elevated: bool, started: Option<ProcEvent>) {
        self.known.insert(
            key,
            TrackedProcess {
                is_elevated,
                event: started,
            },
        );
    }

    /// Memeriksa apakah terjadi eskalasi hak akses (dari non-elevated menjadi elevated).
    /// Mengembalikan event `ProcessElevated` jika terjadi eskalasi baru.
    pub fn check_elevation(
        &mut self,
        key: &ProcKey,
        currently_elevated: bool,
    ) -> Option<ProcEvent> {
        if let Some(entry) = self.known.get_mut(key) {
            if !entry.is_elevated && currently_elevated {
                entry.is_elevated = true;
                if let Some(ref mut evt) = entry.event {
                    evt.is_elevated = true;
                    let mut elevated_evt = evt.clone();
                    elevated_evt.ts_utc = Utc::now();
                    elevated_evt.event_type = EventType::ProcessElevated;
                    elevated_evt.flags.push("process_elevated".to_string());
                    if elevated_evt.severity < Severity::High {
                        elevated_evt.severity = Severity::High;
                    }
                    return Some(elevated_evt);
                } else {
                    // Buat event minimal untuk proses non-suspicious yang mengalami eskalasi
                    return Some(ProcEvent {
                        ts_utc: Utc::now(),
                        event_type: EventType::ProcessElevated,
                        pid: key.pid,
                        ppid: None,
                        name: "elevated_process".to_string(),
                        parent_name: None,
                        exe_path: None,
                        original_filename: None,
                        command_line: None,
                        sha256: None,
                        is_elevated: true,
                        network_destinations: Vec::new(),
                        flags: vec!["process_elevated".to_string()],
                        matched_rules: Vec::new(),
                        severity: Severity::High,
                    });
                }
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.known.len()
    }

    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }

    /// Menghapus proses yang sudah tidak hidup dan mengembalikan event awal dari
    /// proses mencurigakan yang berakhir.
    pub fn reap(&mut self, alive: &HashSet<ProcKey>) -> Vec<ProcEvent> {
        let mut terminated = Vec::new();
        self.known.retain(|key, tracked| {
            if alive.contains(key) {
                return true;
            }
            if let Some(evt) = tracked.event.take() {
                terminated.push(evt);
            }
            false
        });
        terminated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn key(pid: u32) -> ProcKey {
        ProcKey {
            pid,
            start_time: 100,
        }
    }

    fn event(pid: u32) -> ProcEvent {
        ProcEvent {
            ts_utc: Utc::now(),
            event_type: EventType::ProcessStarted,
            pid,
            ppid: None,
            name: "x.exe".into(),
            parent_name: None,
            exe_path: None,
            original_filename: None,
            command_line: None,
            sha256: None,
            is_elevated: false,
            network_destinations: vec![],
            flags: vec![],
            matched_rules: vec![],
            severity: Severity::High,
        }
    }

    #[test]
    fn tracks_and_recognizes_known_processes() {
        let mut t = LifecycleTracker::new();
        assert!(!t.is_known(&key(1)));
        t.track(key(1), false, None);
        assert!(t.is_known(&key(1)));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn detects_process_elevation() {
        let mut t = LifecycleTracker::new();
        t.track(key(1), false, Some(event(1)));

        // Tetap non-elevated -> None
        assert!(t.check_elevation(&key(1), false).is_none());

        // Berubah jadi elevated -> Emits ProcessElevated
        let elevated = t.check_elevation(&key(1), true).unwrap();
        assert_eq!(elevated.event_type, EventType::ProcessElevated);
        assert!(elevated.is_elevated);
        assert!(elevated.flags.contains(&"process_elevated".to_string()));

        // Polling berikutnya (sudah elevated) -> Tidak emit lagi
        assert!(t.check_elevation(&key(1), true).is_none());
    }

    #[test]
    fn reap_returns_only_suspicious_terminated() {
        let mut t = LifecycleTracker::new();
        t.track(key(1), false, Some(event(1)));
        t.track(key(2), false, None);
        t.track(key(3), false, Some(event(3)));

        let alive: HashSet<ProcKey> = [key(3)].into_iter().collect();
        let gone = t.reap(&alive);

        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].pid, 1);
        assert_eq!(t.len(), 1);
        assert!(t.is_known(&key(3)));
    }
}
