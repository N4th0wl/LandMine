use super::flags;

/// Flag berbasis lokasi executable. Input harus sudah lowercase.
pub fn path_flags(path_lc: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    if path_lc.is_empty() {
        return out;
    }
    if path_lc.contains("\\appdata\\local\\temp\\") || path_lc.contains("\\windows\\temp\\") {
        out.push(flags::EXEC_FROM_TEMP);
    }
    if path_lc.contains("\\downloads\\") {
        out.push(flags::EXEC_FROM_DOWNLOADS);
    }
    // AppData\Local\Programs\ itu standard install directory untuk user-level
    // apps (Discord, VS Code, Opera, dsb). Jangan flag ini sebagai suspicious.
    // Yang kita flag hanya direct execution dari AppData yang bukan Programs.
    let is_appdata =
        path_lc.contains("\\appdata\\roaming\\") || path_lc.contains("\\appdata\\local\\");
    let is_programs = path_lc.contains("\\appdata\\local\\programs\\");
    if is_appdata && !is_programs {
        out.push(flags::EXEC_FROM_APPDATA);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_path_is_flagged() {
        let f = path_flags("c:\\users\\x\\appdata\\local\\temp\\a.exe");
        assert!(f.contains(&flags::EXEC_FROM_TEMP));
    }

    #[test]
    fn programs_dir_is_not_appdata_flagged() {
        let f = path_flags("c:\\users\\x\\appdata\\local\\programs\\app\\app.exe");
        assert!(f.is_empty());
    }

    #[test]
    fn empty_path_has_no_flags() {
        assert!(path_flags("").is_empty());
    }
}
