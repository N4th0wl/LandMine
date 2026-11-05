//! Fast in-memory malware hash database (Roadmap 4.1).
//! Memuat kumpulan hash SHA-256 malware (mis. dari abuse.ch / MalwareBazaar / NIST NSRL).

use anyhow::Result;
use std::{collections::HashSet, fs, path::Path};

#[derive(Debug, Clone, Default)]
pub struct HashDb {
    hashes: HashSet<String>,
}

impl HashDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, hash: &str) {
        let trimmed = hash.trim().to_ascii_lowercase();
        if trimmed.len() == 64 {
            self.hashes.insert(trimmed);
        }
    }

    pub fn contains(&self, hash: &str) -> bool {
        let trimmed = hash.trim().to_ascii_lowercase();
        self.hashes.contains(&trimmed)
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let mut db = Self::new();
        if !path_ref.exists() {
            return Ok(db);
        }

        let content = fs::read_to_string(path_ref)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Dukung format "hash", atau "hash,description", atau "hash;..."
            let hash_part = line.split([',', ';', ' ']).next().unwrap_or("").trim();
            if hash_part.len() == 64 {
                db.insert(hash_part);
            }
        }
        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_contains() {
        let mut db = HashDb::new();
        let test_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        db.insert(test_hash);
        assert!(db.contains(test_hash));
        assert!(db.contains(&test_hash.to_uppercase()));
        assert!(!db.contains("0000000000000000000000000000000000000000000000000000000000000000"));
    }
}
