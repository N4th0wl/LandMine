// Normalize a PE OriginalFilename for comparison.
// Windows PE VersionInfo sering pakai suffix .MUI atau .dll untuk binary
// yang sebenarnya exe, jadi kita harus normalize dulu sebelum compare.
//   "PowerShell.EXE.MUI" → "powershell.exe"
//   "CTFMON.EXE.MUI"     → "ctfmon.exe"
//   "Copilot.dll"        → "copilot.dll" (tetap, bukan rename sebenarnya)
//   "svchost.exe.mui"    → "svchost.exe"
pub fn normalize_original_filename(orig: &str) -> String {
    let s = orig.trim().to_lowercase();
    // Strip trailing .mui (resource-only naming convention)
    if let Some(base) = s.strip_suffix(".mui") {
        base.to_string()
    } else {
        s
    }
}

// Determine whether a binary has been renamed by comparing its current
// file-system name to the OriginalFilename from its PE VersionInfo.
// Returns `true` when the two names are present AND different (case-insensitive).
//
// Handles common Windows PE conventions:
//  - .MUI suffix (e.g. "PowerShell.EXE.MUI" is NOT a rename of powershell.exe)
//  - .dll vs .exe mismatch in Electron/MSIX apps (e.g. "Copilot.dll" is NOT
//    a rename of Copilot.exe — same stem = not suspicious)
pub fn is_renamed(actual_name: &str, original_filename: Option<&str>) -> bool {
    match original_filename {
        Some(orig) => {
            let normalized = normalize_original_filename(orig);
            if normalized.is_empty() {
                return false;
            }
            let actual_lc = actual_name.to_lowercase();

            // Exact match after normalization artinya not renamed
            if normalized == actual_lc {
                return false;
            }

            // Same stem, different extension (.exe vs .dll) -> not renamed
            // Ini sering terjadi di Electron/MSIX apps
            let stem_actual = actual_lc
                .rsplit_once('.')
                .map(|(s, _)| s)
                .unwrap_or(&actual_lc);
            let stem_orig = normalized
                .rsplit_once('.')
                .map(|(s, _)| s)
                .unwrap_or(&normalized);
            if stem_actual == stem_orig {
                return false;
            }

            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mui_suffix_is_stripped() {
        assert_eq!(
            normalize_original_filename("PowerShell.EXE.MUI"),
            "powershell.exe"
        );
    }

    #[test]
    fn same_name_is_not_renamed() {
        assert!(!is_renamed("powershell.exe", Some("PowerShell.EXE.MUI")));
    }

    #[test]
    fn same_stem_different_extension_is_not_renamed() {
        assert!(!is_renamed("Copilot.exe", Some("Copilot.dll")));
    }

    #[test]
    fn different_name_is_renamed() {
        assert!(is_renamed("update.exe", Some("powershell.exe")));
    }

    #[test]
    fn missing_original_filename_is_not_renamed() {
        assert!(!is_renamed("update.exe", None));
    }
}
