use clap::Parser;

use crate::{logger::ConsoleFormat, models::Severity};

#[derive(Parser, Debug)]
#[command(
    name = "landmine",
    version,
    about = "LandMine — Living-off-the-Land Process Activity Monitor & Threat Detector"
)]
pub struct Args {
    /// Jalankan satu snapshot lalu keluar
    #[arg(long)]
    pub once: bool,

    /// Jeda antar polling (detik)
    #[arg(long, default_value_t = 5)]
    pub interval: u64,

    /// Path file log JSONL
    #[arg(long, default_value = "logs/landmine.jsonl")]
    pub out: String,

    /// File allowlist nama proses tepercaya (satu per baris)
    #[arg(long, default_value = "rules/allowlist.txt")]
    pub allowlist: String,

    /// File custom detection rules (TOML)
    #[arg(long, default_value = "rules/detection_rules.toml")]
    pub rules: String,

    /// File database malware hash (satu SHA-256 per baris)
    #[arg(long, default_value = "rules/malware_hashes.txt")]
    pub hash_db: String,

    /// Format output console (pretty | jsonl)
    #[arg(long, value_enum, default_value_t = ConsoleFormat::Pretty)]
    pub format: ConsoleFormat,

    /// Severity minimum yang ditulis ke file log (low|medium|high|critical)
    #[arg(long, default_value_t = Severity::Low)]
    pub min_severity: Severity,

    /// Ukuran maksimum file log sebelum dirotasi, dalam MB (0 = tanpa rotasi)
    #[arg(long, default_value_t = 50)]
    pub max_size_mb: u64,

    /// Jumlah file backup log yang disimpan
    #[arg(long, default_value_t = 5)]
    pub max_backups: u32,

    /// Tulis event severity Medium+ ke Windows Event Log (Application)
    #[arg(long)]
    pub winevent: bool,

    /// Active Defense: Tangguhkan eksekusi proses jika severity High atau Critical
    #[arg(long)]
    pub suspend_on_high: bool,

    /// Active Defense: Hentikan paksa proses jika severity Critical
    #[arg(long)]
    pub kill_on_critical: bool,

    /// Active Defense: Direktori untuk menyimpan memory mini-dump sebelum proses dimatikan
    #[arg(long)]
    pub dump_quarantine: Option<String>,

    /// Matikan warna pada --format pretty
    #[arg(long)]
    pub no_color: bool,
}
