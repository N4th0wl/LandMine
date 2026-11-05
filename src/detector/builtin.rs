//! Database bawaan: LOLBin, relasi parent-child, dan proses sistem yang wajar
//! tidak punya path. Semua nama dalam huruf kecil.

/// LOLBin kelas eksekusi / scripting / compile. Alone = Medium.
// Well-known Living-off-the-Land Binaries.
// Checked against BOTH the actual process name AND the PE OriginalFilename.
pub const LOLBINS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    // Compilation / execution (.NET bypass)
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "csc.exe",
    "vbc.exe",
    // Scripting & proxy execution
    "hh.exe",
    "cmstp.exe",
    "xwizard.exe",
    "control.exe",
    "pcalua.exe",
];

/// LOLBin kelas recon / persistence. Sering dipakai tool legitimate, jadi alone
/// hanya `Low`; naik severity bila digabung path/parent/cmdline mencurigakan.
pub const RECON_LOLBINS: &[&str] = &[
    "schtasks.exe",
    "nltest.exe",
    "whoami.exe",
    "net.exe",
    "net1.exe",
    "qwinsta.exe",
];

pub const CRITICAL_SYSTEM_BINARIES: &[&str] = &[
    "svchost.exe",
    "explorer.exe",
    "services.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "dllhost.exe",
    "sihost.exe",
    "conhost.exe",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LolbinClass {
    Execution,
    Recon,
}

pub fn lolbin_class(name_lc: &str) -> Option<LolbinClass> {
    if LOLBINS.contains(&name_lc) {
        Some(LolbinClass::Execution)
    } else if RECON_LOLBINS.contains(&name_lc) {
        Some(LolbinClass::Recon)
    } else {
        None
    }
}

pub fn is_expected_signed(name_lc: &str, path_lc: &str) -> bool {
    CRITICAL_SYSTEM_BINARIES.contains(&name_lc)
        || LOLBINS.contains(&name_lc)
        || RECON_LOLBINS.contains(&name_lc)
        || path_lc.contains(r"\windows\system32\")
        || path_lc.contains(r"\windows\syswow64\")
}

pub const OFFICE_APPS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "mspub.exe",
];

pub const WEB_SERVERS: &[&str] = &["w3wp.exe", "httpd.exe", "nginx.exe", "sqlservr.exe"];

pub const BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"];

/// Script engine yang tidak wajar di-spawn oleh aplikasi Office.
pub const SCRIPT_ENGINES: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
];

/// Command shell yang tidak wajar di-spawn oleh web server / database.
pub const SHELLS: &[&str] = &["cmd.exe", "powershell.exe", "pwsh.exe"];

/// Proses sistem yang memang tidak punya exe path yang bisa dibaca.
pub const KNOWN_SYSTEM_NO_PATH: &[&str] = &[
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "system",
    "registry",
    "system idle process",
    "memory compression",
    "secure system",
];
