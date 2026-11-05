use clap::ValueEnum;

use crate::models::{EventType, ProcEvent, Severity};

/// Format output untuk console (file log selalu JSONL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ConsoleFormat {
    /// Satu objek JSON per baris, siap di-pipe ke `jq` / SIEM.
    Jsonl,
    /// Ringkas, berwarna, nyaman dibaca saat investigasi.
    Pretty,
}

pub fn render(evt: &ProcEvent, format: ConsoleFormat, color: bool) -> String {
    match format {
        ConsoleFormat::Jsonl => serde_json::to_string(evt).unwrap_or_default(),
        ConsoleFormat::Pretty => render_pretty(evt, color),
    }
}

pub fn render_pretty(evt: &ProcEvent, color: bool) -> String {
    let ts = evt.ts_utc.format("%H:%M:%S");
    let (label, badge_code, border_code) = match evt.severity {
        Severity::Low => ("LOW ", "36", "36"),             // Cyan
        Severity::Medium => ("MED ", "33", "33"),          // Yellow
        Severity::High => ("HIGH", "31", "31"),            // Red
        Severity::Critical => ("CRIT", "1;97;41", "1;31"), // White on Red / Bold Red
    };

    let (c_badge_on, c_badge_off, c_border, c_bold, c_dim, c_reset) = if color {
        (
            format!("\x1b[{badge_code}m"),
            "\x1b[0m",
            format!("\x1b[{border_code}m"),
            "\x1b[1m",
            "\x1b[2m",
            "\x1b[0m",
        )
    } else {
        (String::new(), "", String::new(), "", "", "")
    };

    let kind = match evt.event_type {
        EventType::ProcessSnapshot => "SNAPSHOT",
        EventType::ProcessStarted => "STARTED",
        EventType::ProcessElevated => "ELEVATED",
        EventType::ProcessTerminated => "EXITED",
    };

    let primary_title = if !evt.matched_rules.is_empty() {
        evt.matched_rules.join(", ")
    } else if let Some(first_flag) = evt.flags.first() {
        first_flag.clone()
    } else {
        evt.name.clone()
    };

    let mut out = String::new();

    // Header bar
    out.push_str(&format!(
        "{c_dim}[{ts}]{c_reset} {c_border}┌──{c_reset} {c_badge_on} {label} {c_badge_off} {c_bold}{kind:<8}{c_reset} {c_border}──{c_reset} {c_bold}{primary_title}{c_reset}\n"
    ));

    // Process & Lineage
    let proc_line = if let Some(p) = &evt.parent_name {
        let ppid_str = evt
            .ppid
            .map(|id| format!(", PPID: {id}"))
            .unwrap_or_default();
        format!("{} <- {p} (PID: {}{ppid_str})", evt.name, evt.pid)
    } else {
        format!("{} (PID: {})", evt.name, evt.pid)
    };
    out.push_str(&format!(
        "           {c_border}│{c_reset}  {c_bold}Process{c_reset} : {proc_line}\n"
    ));

    // Exe Path & Original Filename
    if let Some(path) = &evt.exe_path {
        let orig_str = if let Some(orig) = &evt.original_filename {
            if orig.to_lowercase() != evt.name.to_lowercase() {
                format!("  {c_dim}[PE Original: {orig}]{c_reset}")
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        out.push_str(&format!(
            "           {c_border}│{c_reset}  {c_bold}Path{c_reset}    : {}{orig_str}\n",
            path
        ));
    }

    // Command Line
    if let Some(cmd) = &evt.command_line {
        out.push_str(&format!(
            "           {c_border}│{c_reset}  {c_bold}Command{c_reset} : {}\n",
            truncate(cmd, 160)
        ));
    }

    // Network Destinations
    if !evt.network_destinations.is_empty() {
        out.push_str(&format!(
            "           {c_border}│{c_reset}  {c_bold}Network{c_reset} : {}\n",
            evt.network_destinations.join(", ")
        ));
    }

    // SHA-256
    if let Some(hash) = &evt.sha256 {
        out.push_str(&format!(
            "           {c_border}│{c_reset}  {c_bold}SHA-256{c_reset} : {hash}\n"
        ));
    }

    // Flags
    if !evt.flags.is_empty() {
        out.push_str(&format!(
            "           {c_border}│{c_reset}  {c_bold}Flags{c_reset}   : [{}]\n",
            evt.flags.join(", ")
        ));
    }

    // Footer
    out.push_str(&format!(
        "           {c_border}└────────────────────────────────────────────────────────────────────────────{c_reset}"
    ));

    out
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample() -> ProcEvent {
        ProcEvent {
            ts_utc: Utc::now(),
            event_type: EventType::ProcessStarted,
            pid: 42,
            ppid: Some(1),
            name: "powershell.exe".into(),
            parent_name: Some("winword.exe".into()),
            exe_path: None,
            original_filename: None,
            command_line: Some("powershell -enc AAAA".into()),
            is_elevated: false,
            network_destinations: vec![],
            sha256: None,
            flags: vec!["cmdline_obfuscation".into()],
            matched_rules: vec![],
            severity: Severity::High,
        }
    }

    #[test]
    fn pretty_without_color_has_no_escape_codes() {
        let s = render_pretty(&sample(), false);
        assert!(!s.contains('\x1b'));
        assert!(s.contains("powershell.exe <- winword.exe"));
        assert!(s.contains("cmdline_obfuscation"));
    }

    #[test]
    fn pretty_with_color_has_escape_codes() {
        assert!(render_pretty(&sample(), true).contains("\x1b[31m"));
    }

    #[test]
    fn jsonl_roundtrips() {
        let s = render(&sample(), ConsoleFormat::Jsonl, false);
        let back: ProcEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.pid, 42);
    }

    #[test]
    fn truncate_adds_ellipsis() {
        assert_eq!(truncate("abcdef", 3), "abc…");
        assert_eq!(truncate("abc", 3), "abc");
    }
}
