//! Nama flag deteksi. Dipusatkan di satu tempat agar tidak ada "magic string"
//! yang tersebar di engine, test, dan dokumentasi.

pub const LOLBIN_PROCESS: &str = "lolbin_process";
pub const LOLBIN_RECON: &str = "lolbin_recon";
pub const LOLBIN_MASQUERADE: &str = "lolbin_masquerade";
pub const RENAMED_BINARY: &str = "renamed_binary";

pub const EXEC_FROM_PREFIX: &str = "exec_from_";
pub const EXEC_FROM_TEMP: &str = "exec_from_temp";
pub const EXEC_FROM_DOWNLOADS: &str = "exec_from_downloads";
pub const EXEC_FROM_APPDATA: &str = "exec_from_appdata";

pub const NO_EXE_PATH: &str = "no_exe_path";
pub const ALLOWLISTED_NAME: &str = "allowlisted_name";

pub const SUSPICIOUS_PARENT_SPAWN: &str = "suspicious_parent_spawn";
pub const OFFICE_SPAWNS_SCRIPT_ENGINE: &str = "office_spawns_script_engine";
pub const WEBSERVER_SPAWNS_SHELL: &str = "webserver_spawns_shell";
pub const BROWSER_SPAWNS_TEMP_EXE: &str = "browser_spawns_temp_exe";

pub const CMDLINE_OBFUSCATION: &str = "cmdline_obfuscation";
pub const CMDLINE_DOWNLOAD_CRADLE: &str = "cmdline_download_cradle";
pub const CMDLINE_TAMPERING: &str = "cmdline_tampering";

// Sinyal baru sesuai Roadmap LandMine
pub const UNSIGNED_SYSTEM_BINARY: &str = "unsigned_system_binary";
pub const LOLBIN_NETWORK_BEACON: &str = "lolbin_network_beacon";
pub const NETWORK_OUTBOUND_PUBLIC: &str = "network_outbound_public";
pub const KNOWN_MALWARE_HASH: &str = "known_malware_hash";
pub const SUSPICIOUS_PATTERN: &str = "suspicious_packer_or_pattern";
pub const PROCESS_ELEVATED: &str = "process_elevated";

/// Prefix flag untuk custom rule dari file TOML, mis. `rule:lolbin_certutil_download`.
pub const RULE_PREFIX: &str = "rule:";
