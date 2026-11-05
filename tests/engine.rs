use landmine::{
    detector::{custom_rules, flags, EvalContext, RuleEngine},
    models::Severity,
};
use std::collections::HashSet;

fn ctx<'a>(name: &'a str, path: Option<&'a str>) -> EvalContext<'a> {
    EvalContext::simple(name, path)
}

fn engine() -> RuleEngine {
    RuleEngine::default()
}

#[test]
fn benign_process_is_low() {
    let r = engine().evaluate(&ctx(
        "notepad.exe",
        Some(r"C:\Windows\System32\notepad.exe"),
    ));
    assert_eq!(r.severity, Severity::Low);
    assert!(r.flags.is_empty());
}

#[test]
fn lolbin_alone_is_medium() {
    let r = engine().evaluate(&ctx("cmd.exe", Some(r"C:\Windows\System32\cmd.exe")));
    assert_eq!(r.severity, Severity::Medium);
    assert!(r.flags.contains(&flags::LOLBIN_PROCESS.to_string()));
}

#[test]
fn recon_lolbin_alone_is_low_but_high_from_temp() {
    let r = engine().evaluate(&ctx("whoami.exe", Some(r"C:\Windows\System32\whoami.exe")));
    assert_eq!(r.severity, Severity::Low);

    let r = engine().evaluate(&ctx(
        "whoami.exe",
        Some(r"C:\Users\x\AppData\Local\Temp\whoami.exe"),
    ));
    assert_eq!(r.severity, Severity::High);
}

#[test]
fn lolbin_from_temp_is_high() {
    let r = engine().evaluate(&ctx(
        "powershell.exe",
        Some(r"C:\Users\x\AppData\Local\Temp\powershell.exe"),
    ));
    assert_eq!(r.severity, Severity::High);
    assert!(r.flags.contains(&flags::EXEC_FROM_TEMP.to_string()));
}

#[test]
fn renamed_lolbin_is_masquerade_high() {
    let mut c = ctx("update.exe", Some(r"C:\ProgramData\update.exe"));
    c.original_filename = Some("PowerShell.EXE");
    let r = engine().evaluate(&c);
    assert_eq!(r.severity, Severity::High);
    assert!(r.flags.contains(&flags::LOLBIN_MASQUERADE.to_string()));
}

#[test]
fn office_spawning_encoded_powershell_is_critical() {
    let mut c = ctx(
        "powershell.exe",
        Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    );
    c.parent_name = Some("WINWORD.EXE");
    c.command_line = Some("powershell.exe -nop -enc ZQBjAGgAbwA=");
    let r = engine().evaluate(&c);
    assert_eq!(r.severity, Severity::Critical);
    assert!(r
        .flags
        .contains(&flags::SUSPICIOUS_PARENT_SPAWN.to_string()));
    assert!(r.flags.contains(&flags::CMDLINE_OBFUSCATION.to_string()));
}

#[test]
fn explorer_launching_cmd_is_not_escalated() {
    let mut c = ctx("cmd.exe", Some(r"C:\Windows\System32\cmd.exe"));
    c.parent_name = Some("explorer.exe");
    c.command_line = Some("cmd.exe");
    assert_eq!(engine().evaluate(&c).severity, Severity::Medium);
}

#[test]
fn non_lolbin_with_tampering_cmdline_is_high() {
    let mut c = ctx("vssadmin.exe", Some(r"C:\Windows\System32\vssadmin.exe"));
    c.command_line = Some("vssadmin delete shadows /all /quiet");
    let r = engine().evaluate(&c);
    assert_eq!(r.severity, Severity::High);
    assert!(r.flags.contains(&flags::CMDLINE_TAMPERING.to_string()));
}

#[test]
fn unsigned_system_binary_is_flagged_high() {
    let mut c = ctx("svchost.exe", Some(r"C:\Windows\System32\svchost.exe"));
    c.is_signed = Some(false);
    let r = engine().evaluate(&c);
    assert!(r.severity >= Severity::High);
    assert!(r.flags.contains(&flags::UNSIGNED_SYSTEM_BINARY.to_string()));
}

#[test]
fn lolbin_network_beacon_is_flagged() {
    let mut c = ctx("certutil.exe", Some(r"C:\Windows\System32\certutil.exe"));
    c.has_public_network = true;
    let r = engine().evaluate(&c);
    assert_eq!(r.severity, Severity::High);
    assert!(r.flags.contains(&flags::LOLBIN_NETWORK_BEACON.to_string()));
    assert!(r
        .flags
        .contains(&flags::NETWORK_OUTBOUND_PUBLIC.to_string()));
}

#[test]
fn known_malware_hash_is_critical() {
    let mut c = ctx("random.exe", Some(r"C:\Users\Public\random.exe"));
    c.is_known_malware = true;
    let r = engine().evaluate(&c);
    assert_eq!(r.severity, Severity::Critical);
    assert!(r.flags.contains(&flags::KNOWN_MALWARE_HASH.to_string()));
}

#[test]
fn suspicious_packer_pattern_is_high() {
    let mut c = ctx("packed.exe", Some(r"C:\Users\user\Downloads\packed.exe"));
    c.suspicious_pattern = true;
    let r = engine().evaluate(&c);
    assert!(r.severity >= Severity::High);
    assert!(r.flags.contains(&flags::SUSPICIOUS_PATTERN.to_string()));
}

#[test]
fn allowlist_suppresses_name_based_flags() {
    let allow: HashSet<String> = ["cmd.exe".to_string()].into_iter().collect();
    let e = RuleEngine::new(allow, vec![]);
    let r = e.evaluate(&ctx("cmd.exe", Some(r"C:\Windows\System32\cmd.exe")));
    assert_eq!(r.severity, Severity::Low);
    assert_eq!(r.flags, vec![flags::ALLOWLISTED_NAME.to_string()]);
}

#[test]
fn allowlist_does_not_hide_renamed_or_malicious_cmdline() {
    let allow: HashSet<String> = ["powershell.exe".to_string()].into_iter().collect();
    let e = RuleEngine::new(allow, vec![]);

    let mut c = ctx(
        "powershell.exe",
        Some(r"C:\Windows\System32\powershell.exe"),
    );
    c.command_line = Some("powershell -enc AAAA");
    assert!(e.evaluate(&c).severity >= Severity::High);

    let mut renamed = ctx("powershell.exe", Some(r"C:\Temp\powershell.exe"));
    renamed.original_filename = Some("evil.exe");
    assert!(e.evaluate(&renamed).severity >= Severity::Medium);
}

#[test]
fn missing_path_is_flagged_except_for_known_system_processes() {
    let r = engine().evaluate(&ctx("mystery.exe", None));
    assert!(r.flags.contains(&flags::NO_EXE_PATH.to_string()));
    // flag tidak boleh muncul dua kali
    assert_eq!(
        r.flags.iter().filter(|f| *f == flags::NO_EXE_PATH).count(),
        1
    );

    let r = engine().evaluate(&ctx("lsass.exe", None));
    assert!(r.flags.is_empty());
}

#[test]
fn custom_rule_raises_severity_and_records_id() {
    let rules = custom_rules::parse_rules(
        r#"
        [[rules]]
        id = "public_profile"
        severity = "Critical"
        [rules.conditions]
        path_contains = ['\users\public\']
        "#,
    )
    .unwrap();
    let e = RuleEngine::default().with_custom_rules(rules);
    let r = e.evaluate(&ctx("tool.exe", Some(r"C:\Users\Public\tool.exe")));
    assert_eq!(r.severity, Severity::Critical);
    assert_eq!(r.matched_rules, vec!["public_profile".to_string()]);
    assert!(r.flags.contains(&"rule:public_profile".to_string()));
}

#[test]
fn bundled_rules_file_is_valid() {
    let rules = custom_rules::load_rules("rules/detection_rules.toml").unwrap();
    assert!(!rules.is_empty());
}
