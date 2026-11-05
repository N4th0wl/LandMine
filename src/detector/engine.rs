use std::{collections::HashSet, fs, path::Path};

use super::{
    builtin::{self, LolbinClass},
    cmdline,
    custom_rules::{CustomRule, MatchContext},
    filename, flags, lineage, path,
};
use crate::models::{DetectionResult, Severity};

/// Data proses yang dibutuhkan engine untuk menilai satu proses.
#[derive(Debug, Clone, Copy)]
pub struct EvalContext<'a> {
    pub name: &'a str,
    pub exe_path: Option<&'a str>,
    pub original_filename: Option<&'a str>,
    pub command_line: Option<&'a str>,
    pub parent_name: Option<&'a str>,
    pub is_signed: Option<bool>,
    pub has_public_network: bool,
    pub is_known_malware: bool,
    pub suspicious_pattern: bool,
}

impl<'a> EvalContext<'a> {
    /// Konstruktor helper untuk unit test dasar
    pub fn simple(name: &'a str, exe_path: Option<&'a str>) -> Self {
        Self {
            name,
            exe_path,
            original_filename: None,
            command_line: None,
            parent_name: None,
            is_signed: None,
            has_public_network: false,
            is_known_malware: false,
            suspicious_pattern: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleEngine {
    allowlisted_names: HashSet<String>,
    custom_rules: Vec<CustomRule>,
}

impl RuleEngine {
    pub fn new(allowlisted_names: HashSet<String>, custom_rules: Vec<CustomRule>) -> Self {
        Self {
            allowlisted_names,
            custom_rules,
        }
    }

    /// Muat allowlist (satu nama per baris, `#` = komentar). File yang hilang
    /// diperlakukan sebagai allowlist kosong.
    pub fn load_allowlist<P: AsRef<Path>>(path: P) -> HashSet<String> {
        let mut set = HashSet::new();
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                set.insert(t.to_lowercase());
            }
        }
        set
    }

    pub fn from_allowlist_file<P: AsRef<Path>>(path: P) -> Self {
        Self::new(Self::load_allowlist(path), Vec::new())
    }

    pub fn with_custom_rules(mut self, rules: Vec<CustomRule>) -> Self {
        self.custom_rules = rules;
        self
    }

    pub fn custom_rule_count(&self) -> usize {
        self.custom_rules.len()
    }

    /// Menilai satu proses: mengumpulkan flag lalu mengklasifikasikan severity.
    pub fn evaluate(&self, ctx: &EvalContext<'_>) -> DetectionResult {
        let name_lc = ctx.name.to_lowercase();
        let path_lc = ctx.exe_path.unwrap_or("").to_lowercase();
        let parent_lc = ctx.parent_name.map(str::to_lowercase);
        let cmd_lc = ctx.command_line.unwrap_or("").to_lowercase();
        // Pakai normalize supaya .MUI suffix di-strip sebelum compare
        let orig_normalized = ctx
            .original_filename
            .map(filename::normalize_original_filename);
        let renamed = filename::is_renamed(&name_lc, orig_normalized.as_deref());

        let path_flags = path::path_flags(&path_lc);
        let from_temp = path_flags.contains(&flags::EXEC_FROM_TEMP);
        let cmdline_flags = ctx
            .command_line
            .map(|c| cmdline::analyze(&name_lc, c))
            .unwrap_or_default();
        let lineage_flags = parent_lc
            .as_deref()
            .map(|p| lineage::check(p, &name_lc, from_temp))
            .unwrap_or_default();

        let match_ctx = MatchContext {
            name_lc: &name_lc,
            parent_lc: parent_lc.as_deref(),
            path_lc: &path_lc,
            cmd_lc: &cmd_lc,
        };
        let matched: Vec<&CustomRule> = self
            .custom_rules
            .iter()
            .filter(|r| r.matches(&match_ctx))
            .collect();

        // Allowlist short-circuit
        // Only trust the allowlist when the binary has NOT been renamed and no
        // behavioural indicator (cmdline / lineage / custom rule / malware / unsigned) fired.
        let allowlisted = self.allowlisted_names.contains(&name_lc);
        if allowlisted
            && !renamed
            && cmdline_flags.is_empty()
            && lineage_flags.is_empty()
            && matched.is_empty()
            && !ctx.is_known_malware
            && !ctx.has_public_network
        {
            return DetectionResult {
                flags: vec![flags::ALLOWLISTED_NAME.to_string()],
                matched_rules: Vec::new(),
                severity: Severity::Low,
            };
        }

        let mut out: Vec<String> = Vec::new();

        // Kalau ketemu missing exe_path
        if ctx.exe_path.is_none() && !builtin::KNOWN_SYSTEM_NO_PATH.contains(&name_lc.as_str()) {
            out.push(flags::NO_EXE_PATH.to_string());
        }

        out.extend(path_flags.iter().map(|f| f.to_string()));

        // LOLBin detection: by actual name OR by OriginalFilename
        let by_name = builtin::lolbin_class(&name_lc);
        let by_orig = orig_normalized.as_deref().and_then(builtin::lolbin_class);
        let is_lolbin = by_name.is_some() || by_orig.is_some();

        match by_name.or(by_orig) {
            Some(LolbinClass::Execution) => out.push(flags::LOLBIN_PROCESS.to_string()),
            Some(LolbinClass::Recon) => out.push(flags::LOLBIN_RECON.to_string()),
            None => {}
        }

        if renamed {
            out.push(flags::RENAMED_BINARY.to_string());
        }

        // If a LOLBin was detected only through the OriginalFilename
        // (meaning the file was renamed to evade name-based detection),
        // flag the masquerade explicitly.
        if by_name.is_none() && by_orig.is_some() && renamed {
            out.push(flags::LOLBIN_MASQUERADE.to_string());
        }

        // Authenticode digital signature check:
        // Binary sistem Windows atau LOLBin yang tidak bertandatangan digital sah
        if builtin::is_expected_signed(&name_lc, &path_lc) && ctx.is_signed == Some(false) {
            out.push(flags::UNSIGNED_SYSTEM_BINARY.to_string());
        }

        // Network connection correlation
        if ctx.has_public_network {
            out.push(flags::NETWORK_OUTBOUND_PUBLIC.to_string());
            if is_lolbin {
                out.push(flags::LOLBIN_NETWORK_BEACON.to_string());
            }
        }

        // Threat Intel / Malware Hash & Pattern matching
        if ctx.is_known_malware {
            out.push(flags::KNOWN_MALWARE_HASH.to_string());
        }
        if ctx.suspicious_pattern {
            out.push(flags::SUSPICIOUS_PATTERN.to_string());
        }

        out.extend(cmdline_flags.iter().map(|f| f.to_string()));
        out.extend(lineage_flags.iter().map(|f| f.to_string()));
        out.extend(
            matched
                .iter()
                .map(|r| format!("{}{}", flags::RULE_PREFIX, r.id)),
        );
        if allowlisted {
            out.push(flags::ALLOWLISTED_NAME.to_string());
        }

        let rule_severity = matched.iter().map(|r| r.severity).max();
        let severity = classify(&out, rule_severity);

        DetectionResult {
            flags: out,
            matched_rules: matched.iter().map(|r| r.id.clone()).collect(),
            severity,
        }
    }
}

// severity classification
fn classify(flags_out: &[String], rule_severity: Option<Severity>) -> Severity {
    let has = |f: &str| flags_out.iter().any(|x| x == f);

    let has_exec_from = flags_out
        .iter()
        .any(|f| f.starts_with(flags::EXEC_FROM_PREFIX));
    let has_lolbin = has(flags::LOLBIN_PROCESS) || has(flags::LOLBIN_RECON);
    let has_masquerade = has(flags::LOLBIN_MASQUERADE);
    let has_renamed = has(flags::RENAMED_BINARY);
    let has_cmdline = has(flags::CMDLINE_OBFUSCATION)
        || has(flags::CMDLINE_DOWNLOAD_CRADLE)
        || has(flags::CMDLINE_TAMPERING);
    let has_spawn = has(flags::SUSPICIOUS_PARENT_SPAWN);
    let from_temp = has(flags::EXEC_FROM_TEMP);
    let unsigned_system = has(flags::UNSIGNED_SYSTEM_BINARY);
    let is_beacon = has(flags::LOLBIN_NETWORK_BEACON);
    let is_known_malware = has(flags::KNOWN_MALWARE_HASH);

    let base = if is_known_malware {
        Severity::Critical
    } else if (has_spawn && (has_cmdline || from_temp || has_masquerade))
        || (unsigned_system && (has_masquerade || from_temp))
        || (is_beacon && (has_cmdline || from_temp))
    {
        // Rantai eksekusi anomali / impersonasi sistem tak bertanda tangan / C2 beaconing
        Severity::Critical
    } else if has_masquerade
        || has_spawn
        || has_cmdline
        || unsigned_system
        || is_beacon
        || has(flags::SUSPICIOUS_PATTERN)
        || (has_lolbin && (has_exec_from || has_renamed))
    {
        Severity::High
    } else if has_exec_from
        || has(flags::LOLBIN_PROCESS)
        || has_renamed
        || has(flags::NETWORK_OUTBOUND_PUBLIC)
    {
        Severity::Medium
    } else {
        Severity::Low
    };

    rule_severity.map_or(base, |r| base.max(r))
}
