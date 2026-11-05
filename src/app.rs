//! Orkestrasi satu siklus monitoring: collect -> deduplikasi -> detect -> enrich -> response.

use anyhow::Result;
use chrono::Utc;
use std::{collections::HashSet, path::PathBuf};

use crate::{
    collector::ProcessCollector,
    detector::{EvalContext, RuleEngine},
    enrich::{scan_binary_patterns, HashCache, HashDb},
    models::{EventType, ProcEvent, ProcSnapshot, Severity},
    platform::{self, DefenseAction},
    state::{LifecycleTracker, ProcKey},
};

#[derive(Debug, Clone, Default)]
pub struct DefenseOptions {
    pub suspend_on_high: bool,
    pub kill_on_critical: bool,
    pub quarantine_dir: Option<PathBuf>,
}

pub struct Monitor {
    collector: ProcessCollector,
    engine: RuleEngine,
    tracker: LifecycleTracker,
    hashes: HashCache,
    hash_db: HashDb,
    defense: DefenseOptions,
    baseline_done: bool,
}

impl Monitor {
    pub fn new(engine: RuleEngine) -> Self {
        Self {
            collector: ProcessCollector::new(),
            engine,
            tracker: LifecycleTracker::new(),
            hashes: HashCache::new(),
            hash_db: HashDb::new(),
            defense: DefenseOptions::default(),
            baseline_done: false,
        }
    }

    pub fn with_hash_db(mut self, db: HashDb) -> Self {
        self.hash_db = db;
        self
    }

    pub fn with_defense(mut self, defense: DefenseOptions) -> Self {
        self.defense = defense;
        self
    }

    /// Menjalankan satu siklus dan mengembalikan event yang baru:
    /// - Proses yang pertama kali terlihat (`process_snapshot` / `process_started`)
    /// - Proses yang mengalami eskalasi hak akses (`process_elevated`)
    /// - Proses mencurigakan yang berakhir (`process_terminated`)
    pub fn tick(&mut self) -> Result<Vec<ProcEvent>> {
        let snapshot = self.collector.collect()?;
        let event_type = if self.baseline_done {
            EventType::ProcessStarted
        } else {
            EventType::ProcessSnapshot
        };
        self.baseline_done = true;

        let mut events = Vec::new();
        let mut alive: HashSet<ProcKey> = HashSet::with_capacity(snapshot.len());

        for p in &snapshot {
            let key = ProcKey {
                pid: p.pid,
                start_time: p.start_time,
            };
            alive.insert(key);

            // Jika proses sudah pernah dilihat, periksa apakah ada eskalasi hak akses (ProcessElevated)
            if self.tracker.is_known(&key) {
                if let Some(elevated_evt) = self.tracker.check_elevation(&key, p.is_elevated) {
                    events.push(elevated_evt);
                }
                continue;
            }

            let evt = self.analyze(p, event_type);

            // Active Defense & Response jika diaktifkan pengguna
            self.apply_active_defense(&evt);

            let remembered = (evt.severity >= Severity::Medium).then(|| evt.clone());
            self.tracker.track(key, p.is_elevated, remembered);
            events.push(evt);
        }

        for mut evt in self.tracker.reap(&alive) {
            evt.ts_utc = Utc::now();
            evt.event_type = EventType::ProcessTerminated;
            events.push(evt);
        }

        Ok(events)
    }

    fn analyze(&mut self, p: &ProcSnapshot, event_type: EventType) -> ProcEvent {
        let exe_str = p.exe_path_string();

        // 1. Hitung hash jika proses berpotensi mencurigakan atau nama LOLBin
        let sha256 = p
            .exe_path
            .as_deref()
            .and_then(|path| self.hashes.hash(path));

        // 2. Cocokkan ke database malware hash
        let is_known_malware = sha256
            .as_deref()
            .map(|h| self.hash_db.contains(h))
            .unwrap_or(false);

        // 3. Scan pattern/packer (YARA-lite) jika ada exe_path
        let suspicious_pattern = p
            .exe_path
            .as_deref()
            .map(|path| !scan_binary_patterns(path).is_empty())
            .unwrap_or(false);

        // 4. Jalankan Rule Engine evaluasi komprehensif
        let det = self.engine.evaluate(&EvalContext {
            name: &p.name,
            exe_path: exe_str.as_deref(),
            original_filename: p.original_filename.as_deref(),
            command_line: p.command_line.as_deref(),
            parent_name: p.parent_name.as_deref(),
            is_signed: p.is_signed,
            has_public_network: p.has_public_network,
            is_known_malware,
            suspicious_pattern,
        });

        let network_destinations = p
            .network_connections
            .iter()
            .map(|s| s.to_string())
            .collect();

        ProcEvent {
            ts_utc: Utc::now(),
            event_type,
            pid: p.pid,
            ppid: p.ppid,
            name: p.name.clone(),
            parent_name: p.parent_name.clone(),
            exe_path: exe_str,
            original_filename: p.original_filename.clone(),
            command_line: p.command_line.clone(),
            sha256,
            is_elevated: p.is_elevated,
            network_destinations,
            flags: det.flags,
            matched_rules: det.matched_rules,
            severity: det.severity,
        }
    }

    fn apply_active_defense(&self, evt: &ProcEvent) {
        if evt.severity == Severity::Critical && self.defense.kill_on_critical {
            if let Some(ref dump_dir) = self.defense.quarantine_dir {
                match platform::dump_and_kill_process(evt.pid, &evt.name, dump_dir) {
                    Ok(DefenseAction::DumpedAndTerminated) => {
                        eprintln!(
                            "[DEFENSE] Quarantined & terminated critical process PID {} ({})",
                            evt.pid, evt.name
                        );
                    }
                    Ok(DefenseAction::SkippedFailsafe) => {
                        eprintln!(
                            "[DEFENSE] Skipped termination for protected process PID {} ({})",
                            evt.pid, evt.name
                        );
                    }
                    Err(e) => eprintln!(
                        "[DEFENSE-ERR] Failed to quarantine process PID {}: {}",
                        evt.pid, e
                    ),
                    _ => {}
                }
            } else {
                match platform::kill_process(evt.pid, &evt.name) {
                    Ok(DefenseAction::Terminated) => {
                        eprintln!(
                            "[DEFENSE] Terminated critical process PID {} ({})",
                            evt.pid, evt.name
                        );
                    }
                    Ok(DefenseAction::SkippedFailsafe) => {
                        eprintln!(
                            "[DEFENSE] Skipped termination for protected process PID {} ({})",
                            evt.pid, evt.name
                        );
                    }
                    Err(e) => eprintln!(
                        "[DEFENSE-ERR] Failed to terminate process PID {}: {}",
                        evt.pid, e
                    ),
                    _ => {}
                }
            }
        } else if evt.severity >= Severity::High && self.defense.suspend_on_high {
            match platform::suspend_process(evt.pid, &evt.name) {
                Ok(DefenseAction::Suspended) => {
                    eprintln!(
                        "[DEFENSE] Suspended high-severity process PID {} ({})",
                        evt.pid, evt.name
                    );
                }
                Ok(DefenseAction::SkippedFailsafe) => {
                    eprintln!(
                        "[DEFENSE] Skipped suspension for protected process PID {} ({})",
                        evt.pid, evt.name
                    );
                }
                Err(e) => eprintln!(
                    "[DEFENSE-ERR] Failed to suspend process PID {}: {}",
                    evt.pid, e
                ),
                _ => {}
            }
        }
    }
}
