//! Analisis rantai eksekusi parent -> child (roadmap 1.2).

use super::{builtin, flags};

/// Mengembalikan flag lineage anomali. Jika tidak kosong, elemen pertama selalu
/// `suspicious_parent_spawn` diikuti flag spesifik yang menjelaskan pola.
/// Semua input harus lowercase.
pub fn check(parent_lc: &str, child_lc: &str, child_from_temp: bool) -> Vec<&'static str> {
    let mut specific = Vec::new();

    if builtin::OFFICE_APPS.contains(&parent_lc) && builtin::SCRIPT_ENGINES.contains(&child_lc) {
        specific.push(flags::OFFICE_SPAWNS_SCRIPT_ENGINE);
    }
    if builtin::WEB_SERVERS.contains(&parent_lc) && builtin::SHELLS.contains(&child_lc) {
        specific.push(flags::WEBSERVER_SPAWNS_SHELL);
    }
    if builtin::BROWSERS.contains(&parent_lc) && child_from_temp {
        specific.push(flags::BROWSER_SPAWNS_TEMP_EXE);
    }

    if specific.is_empty() {
        return specific;
    }
    let mut out = vec![flags::SUSPICIOUS_PARENT_SPAWN];
    out.extend(specific);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn office_spawning_shell_is_flagged() {
        let f = check("winword.exe", "powershell.exe", false);
        assert_eq!(f[0], flags::SUSPICIOUS_PARENT_SPAWN);
        assert!(f.contains(&flags::OFFICE_SPAWNS_SCRIPT_ENGINE));
    }

    #[test]
    fn webserver_spawning_cmd_is_flagged() {
        let f = check("w3wp.exe", "cmd.exe", false);
        assert!(f.contains(&flags::WEBSERVER_SPAWNS_SHELL));
    }

    #[test]
    fn browser_spawning_temp_exe_is_flagged() {
        assert!(!check("chrome.exe", "setup.exe", true).is_empty());
        assert!(check("chrome.exe", "setup.exe", false).is_empty());
    }

    #[test]
    fn explorer_spawning_cmd_is_clean() {
        assert!(check("explorer.exe", "cmd.exe", false).is_empty());
    }
}
