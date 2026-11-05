//! Scanning pattern biner ringan (YARA-lite / Roadmap 4.2).
//! Memeriksa header dan byte executable untuk packer mencurigakan (UPX),
//! indikator C2 beacon, atau embedded shellcode loaders.

use std::{fs::File, io::Read, path::Path};

pub struct PatternMatch {
    pub tag: &'static str,
    pub description: &'static str,
}

const SIGNATURES: &[(&[u8], &str, &str)] = &[
    (b"UPX0", "packer_upx", "UPX packed executable section UPX0"),
    (b"UPX1", "packer_upx", "UPX packed executable section UPX1"),
    (b"UPX!", "packer_upx", "UPX packed executable header"),
    (
        b"ReflectiveLoader",
        "reflective_dll_injection",
        "Reflective DLL injection export name",
    ),
    (
        b"beacon.x64.dll",
        "c2_beacon",
        "CobaltStrike / C2 beacon x64 artifact",
    ),
    (
        b"beacon.dll",
        "c2_beacon",
        "CobaltStrike / C2 beacon x86 artifact",
    ),
    (
        b"mimikatz",
        "credential_dumper",
        "Mimikatz credential dumping signature",
    ),
    (
        b"sekurlsa::logonpasswords",
        "credential_dumper",
        "Sekurlsa credential dump command signature",
    ),
];

/// Memindai file executable (sampai 1 MB pertama) untuk pattern mencurigakan.
pub fn scan_binary_patterns<P: AsRef<Path>>(path: P) -> Vec<PatternMatch> {
    let mut matches = Vec::new();
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return matches,
    };

    // Baca header hingga 1 MB (cukup untuk header PE, section table, dan payload awal)
    let mut buffer = vec![0u8; 1024 * 1024];
    let bytes_read = match file.read(&mut buffer) {
        Ok(n) => n,
        Err(_) => return matches,
    };
    let data = &buffer[..bytes_read];

    for &(needle, tag, desc) in SIGNATURES {
        if contains_subslice(data, needle) && !matches.iter().any(|m: &PatternMatch| m.tag == tag) {
            matches.push(PatternMatch {
                tag,
                description: desc,
            });
        }
    }

    matches
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_upx_signature() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"MZ......This program cannot be run in DOS mode. UPX0...UPX1...")
            .unwrap();
        f.flush().unwrap();

        let res = scan_binary_patterns(f.path());
        assert!(res.iter().any(|m| m.tag == "packer_upx"));
    }

    #[test]
    fn clean_binary_has_no_matches() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"MZ......Just a harmless hello world binary")
            .unwrap();
        f.flush().unwrap();

        let res = scan_binary_patterns(f.path());
        assert!(res.is_empty());
    }
}
