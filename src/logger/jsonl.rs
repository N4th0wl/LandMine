use anyhow::{Context, Result};
use std::{
    fs::{self, create_dir_all, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

/// Penulis JSONL append-only dengan rotasi berdasarkan ukuran:
/// `log.jsonl` -> `log.jsonl.1` -> ... -> `log.jsonl.<max_backups>`.
pub struct RotatingWriter {
    path: PathBuf,
    max_bytes: u64,
    max_backups: u32,
    file: Option<BufWriter<File>>,
    size: u64,
}

impl RotatingWriter {
    /// `max_bytes == 0` menonaktifkan rotasi.
    pub fn open<P: AsRef<Path>>(path: P, max_bytes: u64, max_backups: u32) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        let (file, size) = open_append(&path)?;
        Ok(Self {
            path,
            max_bytes,
            max_backups,
            file: Some(file),
            size,
        })
    }

    pub fn write_line(&mut self, line: &str) -> Result<()> {
        let incoming = line.len() as u64 + 1;
        if self.max_bytes > 0 && self.size > 0 && self.size + incoming > self.max_bytes {
            self.rotate()?;
        }
        let file = self.file.as_mut().context("log file is not open")?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        self.size += incoming;
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }

    fn backup_path(&self, index: u32) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{index}"));
        PathBuf::from(name)
    }

    fn rotate(&mut self) -> Result<()> {
        // Handle harus ditutup dulu; Windows tidak mengizinkan rename file terbuka.
        if let Some(mut f) = self.file.take() {
            f.flush()?;
        }

        if self.max_backups == 0 {
            fs::remove_file(&self.path)?;
        } else {
            let oldest = self.backup_path(self.max_backups);
            if oldest.exists() {
                fs::remove_file(&oldest)?;
            }
            for i in (1..self.max_backups).rev() {
                let from = self.backup_path(i);
                if from.exists() {
                    fs::rename(&from, self.backup_path(i + 1))?;
                }
            }
            fs::rename(&self.path, self.backup_path(1))?;
        }

        let (file, size) = open_append(&self.path)?;
        self.file = Some(file);
        self.size = size;
        Ok(())
    }
}

fn open_append(path: &Path) -> Result<(BufWriter<File>, u64)> {
    let f = OpenOptions::new().create(true).append(true).open(path)?;
    let size = f.metadata()?.len();
    Ok((BufWriter::new(f), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs").join("a.jsonl");
        let mut w = RotatingWriter::open(&path, 0, 3).unwrap();
        w.write_line("one").unwrap();
        w.write_line("two").unwrap();
        w.flush().unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "one\ntwo\n");
    }

    #[test]
    fn rotates_when_size_exceeded_and_prunes_backups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.jsonl");
        // Setiap baris "xxxx\n" = 5 byte; batas 10 byte => 2 baris per file.
        let mut w = RotatingWriter::open(&path, 10, 2).unwrap();
        for i in 0..8 {
            w.write_line(&format!("{i:04}")).unwrap();
        }
        w.flush().unwrap();

        assert!(path.exists());
        assert!(dir.path().join("a.jsonl.1").exists());
        assert!(dir.path().join("a.jsonl.2").exists());
        assert!(!dir.path().join("a.jsonl.3").exists());
        // File aktif berisi baris terbaru.
        assert!(fs::read_to_string(&path).unwrap().contains("0007"));
    }

    #[test]
    fn reopening_continues_existing_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.jsonl");
        {
            let mut w = RotatingWriter::open(&path, 0, 1).unwrap();
            w.write_line("abcd").unwrap();
            w.flush().unwrap();
        }
        let w = RotatingWriter::open(&path, 0, 1).unwrap();
        assert_eq!(w.size, 5);
    }
}
