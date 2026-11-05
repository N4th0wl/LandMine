//! Banner dan CLI UI untuk LandMine.
//! Menampilkan logo ASCII art, ringkasan konfigurasi aktif, dan petunjuk penggunaan (usage).

use crate::cli::Args;
use crate::platform;

pub const BANNER_ASCII: &str = r"
  _                _      _               
 | |   __ _ _ _  _| |_ __(_)_ _  ___      
 | |__/ _` | ' \/ _ | '  \ | ' \/ -_)     
 |____\__,_|_||_\___|_|_|_|_|_||_\___|     
  [!] L I G H T W E I G H T   E D R [!]        
═════════════════════════════════════════════";

pub fn render_banner(args: &Args, rule_count: usize, hash_count: usize, color: bool) -> String {
    let is_admin = platform::is_elevated();

    let (c_bold, c_cyan, c_red, c_yellow, c_green, c_dim, c_reset) = if color {
        (
            "\x1b[1m",
            "\x1b[1;36m",
            "\x1b[1;31m",
            "\x1b[1;33m",
            "\x1b[1;32m",
            "\x1b[2m",
            "\x1b[0m",
        )
    } else {
        ("", "", "", "", "", "", "")
    };

    let mode_str = if args.once {
        "Single Snapshot (--once)"
    } else {
        "Continuous Monitoring"
    };

    let priv_str = if is_admin {
        format!("{c_green}Administrator (Full System Visibility){c_reset}")
    } else {
        format!("{c_yellow}Standard User (Limited - run as Admin for full visibility){c_reset}")
    };

    let defense_str = match (args.suspend_on_high, args.kill_on_critical) {
        (true, true) => format!("{c_red}ACTIVE (Suspend High + Kill Critical){c_reset}"),
        (true, false) => format!("{c_yellow}ACTIVE (Suspend High only){c_reset}"),
        (false, true) => format!("{c_red}ACTIVE (Kill Critical only){c_reset}"),
        (false, false) => format!("{c_dim}Disabled (Detection & Logging only){c_reset}"),
    };

    let winevent_str = if args.winevent {
        format!("{c_green}Enabled (Application Event Log){c_reset}")
    } else {
        format!("{c_dim}Disabled{c_reset}")
    };

    let interval_desc = if args.once {
        String::new()
    } else {
        format!(" (poll every {}s)", args.interval)
    };

    let mut out = String::new();

    // ASCII Art Logo
    if color {
        out.push_str(&format!(
            "{c_cyan}\n  _                _      _               \n | |   __ _ _ _  _| |_ __(_)_ _  ___      \n | |__/ _` | ' \\/ _ | '  \\ | ' \\/ -_)     \n |____\\__,_|_||_\\___|_|_|_|_|_||_\\___|     \n  {c_red}[!]{c_yellow} L I G H T W E I G H T   E D R {c_red}[!]{c_cyan}        \n═════════════════════════════════════════════{c_reset}\n"
        ));
    } else {
        out.push_str(BANNER_ASCII);
        out.push('\n');
    }

    // Active Engine Profile
    out.push_str(&format!("\n{c_bold}  [ ENGINE PROFILE ]{c_reset}\n"));
    out.push_str(&format!("  • Mode         : {mode_str}{interval_desc}\n"));
    out.push_str(&format!("  • Privilege    : {priv_str}\n"));
    out.push_str(&format!("  • Log File     : {}\n", args.out));
    out.push_str(&format!(
        "  • Engine Rules : {} custom rule(s) loaded (Sigma-lite)\n",
        rule_count
    ));
    out.push_str(&format!(
        "  • Threat Intel : {} malware hash(es) loaded\n",
        hash_count
    ));
    out.push_str(&format!("  • Defense      : {defense_str}\n"));
    out.push_str(&format!("  • WinEvent Log : {winevent_str}\n"));

    // Usage & Quick Commands
    out.push_str(&format!("\n{c_bold}  [ CLI USAGE & EXAMPLES ]{c_reset}\n"));
    out.push_str(&format!(
        "  {c_cyan}landmine.exe --format pretty{c_reset}              Real-time colored terminal alerts\n"
    ));
    out.push_str(&format!(
        "  {c_cyan}landmine.exe --once{c_reset}                       Single-shot baseline audit and exit\n"
    ));
    out.push_str(&format!(
        "  {c_cyan}landmine.exe --winevent{c_reset}                   Forward Medium+ alerts to Windows Event Log\n"
    ));
    out.push_str(&format!(
        "  {c_cyan}landmine.exe --suspend-on-high{c_reset}            Pause execution of suspicious processes\n"
    ));
    out.push_str(&format!(
        "  {c_cyan}landmine.exe --kill-on-critical{c_reset}           Instantly terminate confirmed malicious attacks\n"
    ));
    out.push_str(&format!(
        "  {c_cyan}landmine.exe --dump-quarantine <DIR>{c_reset}      Capture memory minidump before killing\n"
    ));
    out.push_str(&format!(
        "\n{c_dim}  Press [Ctrl + C] to stop monitoring.{c_reset}\n"
    ));
    out.push_str(&format!(
        "{c_cyan}═════════════════════════════════════════════════════════════════════════════{c_reset}\n"
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn banner_contains_logo_text() {
        let args = Args::parse_from(["landmine"]);
        let s = render_banner(&args, 41, 14, false);
        assert!(s.contains("L I G H T W E I G H T   E D R"));
        assert!(s.contains("ENGINE PROFILE"));
        assert!(s.contains("CLI USAGE & EXAMPLES"));
        assert!(s.contains("landmine.exe --format pretty"));
    }

    #[test]
    fn banner_with_color_has_ansi_escapes() {
        let args = Args::parse_from(["landmine"]);
        let s = render_banner(&args, 41, 14, true);
        assert!(s.contains("\x1b["));
    }
}
