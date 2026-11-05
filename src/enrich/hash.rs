use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::SystemTime,
};

/// Cache hash per file. Banyak proses sering berasal dari satu binary yang sama
/// (mis. puluhan `chrome.exe`), jadi cukup di-hash sekali. Entri divalidasi
/// dengan ukuran + waktu modifikasi sehingga file yang berubah di-hash ulang.
#[derive(Debug, Default)]
pub struct HashCache {
    entries: HashMap<PathBuf, (FileStamp, Option<String>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

impl HashCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mengembalikan hash SHA-256 file, atau `None` jika file tidak bisa dibaca.
    pub fn hash(&mut self, path: &Path) -> Option<String> {
        let meta = fs::metadata(path).ok()?;
        let stamp = FileStamp {
            len: meta.len(),
            modified: meta.modified().ok(),
        };

        if let Some((cached_stamp, value)) = self.entries.get(path) {
            if *cached_stamp == stamp {
                return value.clone();
            }
        }

        let value = hash_file_sha256(path).ok();
        self.entries
            .insert(path.to_path_buf(), (stamp, value.clone()));
        value
    }
}

/// SHA-256 file dalam format hex lowercase (dibaca streaming per 64 KiB).
pub fn hash_file_sha256<P: AsRef<Path>>(path: P) -> Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 64];

    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hashes_known_vector() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap();
        assert_eq!(
            hash_file_sha256(f.path()).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(hash_file_sha256("this/file/does/not/exist.bin").is_err());
    }

    #[test]
    fn cache_returns_same_hash_and_invalidates_on_change() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap();
        f.flush().unwrap();

        let mut cache = HashCache::new();
        let first = cache.hash(f.path()).unwrap();
        assert_eq!(cache.hash(f.path()).unwrap(), first);

        // Ukuran berubah => stamp berbeda => hash dihitung ulang.
        f.write_all(b"def").unwrap();
        f.flush().unwrap();
        assert_ne!(cache.hash(f.path()).unwrap(), first);
    }

    #[test]
    fn cache_returns_none_for_missing_file() {
        let mut cache = HashCache::new();
        assert!(cache.hash(Path::new("no/such/file.exe")).is_none());
    }
}
