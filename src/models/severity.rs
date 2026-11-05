use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Tingkat keparahan sebuah deteksi. Urutan varian = urutan prioritas
/// (`Low < Medium < High < Critical`), sehingga bisa dibandingkan langsung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!(
                "invalid severity '{s}' (expected: low, medium, high, critical)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_follows_priority() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn parses_case_insensitively() {
        assert_eq!("HIGH".parse::<Severity>(), Ok(Severity::High));
        assert_eq!(" low ".parse::<Severity>(), Ok(Severity::Low));
        assert!("urgent".parse::<Severity>().is_err());
    }
}
