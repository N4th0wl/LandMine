//! Custom detection rules (Sigma-lite) yang dimuat dari file TOML sehingga
//! analis bisa menambah deteksi tanpa recompile (roadmap 2.2).
//!
//! Semantik kondisi: seluruh kondisi yang terisi harus terpenuhi (AND).
//! Di dalam satu list berlaku OR, kecuali `command_line_contains` (semua
//! substring harus ada) -- gunakan `command_line_contains_any` untuk OR.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};

use crate::models::Severity;

#[derive(Debug, Clone, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rules: Vec<CustomRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomRule {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub severity: Severity,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub conditions: Conditions,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Conditions {
    #[serde(default)]
    pub process_name: Vec<String>,
    #[serde(default)]
    pub parent_name: Vec<String>,
    #[serde(default)]
    pub path_contains: Vec<String>,
    #[serde(default)]
    pub command_line_contains: Vec<String>,
    #[serde(default)]
    pub command_line_contains_any: Vec<String>,
}

impl Conditions {
    fn is_empty(&self) -> bool {
        self.process_name.is_empty()
            && self.parent_name.is_empty()
            && self.path_contains.is_empty()
            && self.command_line_contains.is_empty()
            && self.command_line_contains_any.is_empty()
    }

    fn lowercase(&mut self) {
        for list in [
            &mut self.process_name,
            &mut self.parent_name,
            &mut self.path_contains,
            &mut self.command_line_contains,
            &mut self.command_line_contains_any,
        ] {
            for item in list.iter_mut() {
                *item = item.to_lowercase();
            }
        }
    }
}

/// Konteks pencocokan; semua string sudah lowercase.
pub struct MatchContext<'a> {
    pub name_lc: &'a str,
    pub parent_lc: Option<&'a str>,
    pub path_lc: &'a str,
    pub cmd_lc: &'a str,
}

impl CustomRule {
    pub fn matches(&self, c: &MatchContext<'_>) -> bool {
        let k = &self.conditions;

        if !k.process_name.is_empty() && !k.process_name.iter().any(|n| n == c.name_lc) {
            return false;
        }
        if !k.parent_name.is_empty()
            && !c
                .parent_lc
                .is_some_and(|p| k.parent_name.iter().any(|n| n == p))
        {
            return false;
        }
        if !k.path_contains.is_empty()
            && !k
                .path_contains
                .iter()
                .any(|n| c.path_lc.contains(n.as_str()))
        {
            return false;
        }
        if !k.command_line_contains.is_empty()
            && !k
                .command_line_contains
                .iter()
                .all(|n| c.cmd_lc.contains(n.as_str()))
        {
            return false;
        }
        if !k.command_line_contains_any.is_empty()
            && !k
                .command_line_contains_any
                .iter()
                .any(|n| c.cmd_lc.contains(n.as_str()))
        {
            return false;
        }
        true
    }
}

/// Parse isi file TOML menjadi daftar rule yang sudah dinormalisasi.
pub fn parse_rules(toml_src: &str) -> Result<Vec<CustomRule>> {
    let file: RuleFile = toml::from_str(toml_src).context("invalid detection rules TOML")?;
    let mut rules = file.rules;
    for rule in &mut rules {
        if rule.id.trim().is_empty() {
            bail!("a detection rule is missing its `id`");
        }
        if rule.conditions.is_empty() {
            // Rule tanpa kondisi akan cocok dengan SEMUA proses.
            bail!("rule '{}' has no conditions", rule.id);
        }
        rule.conditions.lowercase();
    }
    Ok(rules)
}

pub fn load_rules<P: AsRef<Path>>(path: P) -> Result<Vec<CustomRule>> {
    let path = path.as_ref();
    let src = fs::read_to_string(path)
        .with_context(|| format!("cannot read rules file {}", path.display()))?;
    parse_rules(&src).with_context(|| format!("while loading {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        [[rules]]
        id = "certutil_download"
        severity = "High"
        tags = ["mitre.t1105"]
        [rules.conditions]
        process_name = ["CertUtil.exe"]
        command_line_contains = ["-urlcache", "-split"]
    "#;

    fn ctx<'a>(name: &'a str, cmd: &'a str) -> MatchContext<'a> {
        MatchContext {
            name_lc: name,
            parent_lc: None,
            path_lc: "",
            cmd_lc: cmd,
        }
    }

    #[test]
    fn parses_and_normalizes_case() {
        let rules = parse_rules(SAMPLE).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].conditions.process_name, vec!["certutil.exe"]);
        assert_eq!(rules[0].severity, Severity::High);
    }

    #[test]
    fn command_line_contains_requires_all() {
        let rules = parse_rules(SAMPLE).unwrap();
        assert!(rules[0].matches(&ctx("certutil.exe", "certutil -urlcache -split -f x")));
        assert!(!rules[0].matches(&ctx("certutil.exe", "certutil -urlcache x")));
        assert!(!rules[0].matches(&ctx("cmd.exe", "-urlcache -split")));
    }

    #[test]
    fn rule_without_conditions_is_rejected() {
        let src = "[[rules]]\nid = \"bad\"\nseverity = \"Low\"\n";
        assert!(parse_rules(src).is_err());
    }

    #[test]
    fn parent_condition_requires_known_parent() {
        let src = r#"
            [[rules]]
            id = "p"
            severity = "Critical"
            [rules.conditions]
            parent_name = ["winword.exe"]
        "#;
        let rules = parse_rules(src).unwrap();
        assert!(!rules[0].matches(&ctx("cmd.exe", "")));
        let mut c = ctx("cmd.exe", "");
        c.parent_lc = Some("winword.exe");
        assert!(rules[0].matches(&c));
    }
}
