//! Enrichment: data tambahan atas proses yang terdeteksi (Hash, Threat Intel, YARA/Pattern).

pub mod hash;
pub mod hashdb;
pub mod patterns;

pub use hash::{hash_file_sha256, HashCache};
pub use hashdb::HashDb;
pub use patterns::{scan_binary_patterns, PatternMatch};
