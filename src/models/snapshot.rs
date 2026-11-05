use std::{net::SocketAddr, path::PathBuf};

/// Data mentah satu proses yang dikumpulkan oleh collector.
#[derive(Debug, Clone)]
pub struct ProcSnapshot {
    pub pid: u32,
    pub ppid: Option<u32>,
    /// Epoch detik saat proses dimulai. Bersama `pid` membentuk identitas unik
    /// proses (PID bisa dipakai ulang oleh OS).
    pub start_time: u64,
    pub name: String,
    pub exe_path: Option<PathBuf>,
    // The OriginalFilename field from the PE VersionInfo resource.
    // Survives file renames — used to detect renamed LOLBins.
    pub original_filename: Option<String>,
    pub command_line: Option<String>,
    pub parent_name: Option<String>,
    pub is_elevated: bool,
    pub is_signed: Option<bool>,
    pub network_connections: Vec<SocketAddr>,
    pub has_public_network: bool,
}

impl ProcSnapshot {
    pub fn exe_path_string(&self) -> Option<String> {
        self.exe_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
    }
}
