use anyhow::Result;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::models::ProcSnapshot;
use crate::platform::{self, pe_version, SignatureStatus};

/// Pengumpul snapshot proses. Instance `System` dipertahankan antar-poll
/// (tidak dialokasikan ulang tiap siklus) dan hasil pembacaan PE VersionInfo
/// serta digital signature di-cache per path executable.
pub struct ProcessCollector {
    sys: System,
    pe_cache: HashMap<PathBuf, Option<String>>,
    sig_cache: HashMap<PathBuf, bool>,
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessCollector {
    pub fn new() -> Self {
        Self {
            sys: System::new(),
            pe_cache: HashMap::new(),
            sig_cache: HashMap::new(),
        }
    }

    pub fn collect(&mut self) -> Result<Vec<ProcSnapshot>> {
        let kind = ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_cmd(UpdateKind::OnlyIfNotSet);
        self.sys
            .refresh_processes_specifics(ProcessesToUpdate::All, true, kind);

        // Ambil pemetaan PID -> Koneksi Jaringan aktif (TCP)
        let network_map = platform::get_tcp_connections_by_pid();

        let mut out = Vec::with_capacity(self.sys.processes().len());

        for (pid, proc_) in self.sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = proc_.name().to_string_lossy().into_owned();

            // Primary source dari sysinfo. Falls back to the Windows API jika:
            // crate cannot read the path (e.g. for SYSTEM / other-user processes).
            let exe_path: Option<PathBuf> = proc_
                .exe()
                .map(|p| p.to_path_buf())
                .or_else(|| platform::query_image_path(pid_u32));

            // Extract OriginalFilename from PE VersionInfo resource.
            // This survives file renames and is the key to detecting renamed LOLBins.
            let original_filename = exe_path
                .as_deref()
                .and_then(|p| original_filename_cached(&mut self.pe_cache, p));

            // Verifikasi digital signature (Authenticode) dengan caching
            let is_signed = exe_path
                .as_deref()
                .map(|p| signature_verified_cached(&mut self.sig_cache, p));

            let cmd = proc_.cmd();
            let command_line = if cmd.is_empty() {
                None
            } else {
                Some(
                    cmd.iter()
                        .map(|s| s.to_string_lossy())
                        .collect::<Vec<_>>()
                        .join(" "),
                )
            };

            // Parent hanya dipercaya jika lahir lebih dulu dari child; kalau tidak,
            // PID parent kemungkinan sudah dipakai ulang oleh proses lain.
            let ppid = proc_.parent();
            let parent = ppid
                .and_then(|pp| self.sys.process(pp))
                .filter(|pp| pp.start_time() <= proc_.start_time());
            let parent_name = parent.map(|p| p.name().to_string_lossy().into_owned());

            // Korelasi jaringan untuk PID ini
            let net_info = network_map.get(&pid_u32);
            let network_connections = net_info
                .map(|ni| ni.connections.clone())
                .unwrap_or_default();
            let has_public_network = net_info.map(|ni| ni.has_public_connection).unwrap_or(false);

            let is_elevated = platform::is_process_elevated(pid_u32);

            out.push(ProcSnapshot {
                pid: pid_u32,
                ppid: ppid.map(|p| p.as_u32()),
                start_time: proc_.start_time(),
                name,
                exe_path,
                original_filename,
                command_line,
                parent_name,
                is_elevated,
                is_signed,
                network_connections,
                has_public_network,
            });
        }

        Ok(out)
    }
}

fn original_filename_cached(
    cache: &mut HashMap<PathBuf, Option<String>>,
    path: &Path,
) -> Option<String> {
    if let Some(hit) = cache.get(path) {
        return hit.clone();
    }
    let value = pe_version::read_pe_metadata(path).and_then(|m| m.original_filename);
    cache.insert(path.to_path_buf(), value.clone());
    value
}

fn signature_verified_cached(cache: &mut HashMap<PathBuf, bool>, path: &Path) -> bool {
    if let Some(&hit) = cache.get(path) {
        return hit;
    }
    let valid = platform::verify_signature(path) == SignatureStatus::Valid;
    cache.insert(path.to_path_buf(), valid);
    valid
}
