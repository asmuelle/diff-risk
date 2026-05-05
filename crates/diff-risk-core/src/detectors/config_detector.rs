//! Config-file-driven custom detector.
//!
//! Reads patterns from `.cargo-vibe.toml` (section `[diff_risk.detectors]`)
//! or a standalone `detectors.toml` file, compiling them into regex-based
//! detectors that run alongside the built-in ones.
//!
//! ## TOML format
//!
//! ```toml
//! [[diff_risk.detectors]]
//! name = "my-company-auth"
//! category = "auth_gate"
//! severity = "critical"
//! pattern = '\.verify_permission\s*\('
//! message = "Permission verification was changed or removed"
//!
//! [[diff_risk.detectors]]
//! name = "sql-raw-query"
//! category = "concurrency"
//! severity = "high"
//! pattern = '\.execute\s*\('
//! message = "Raw SQL execution — ensure parameterized queries"
//! ```

use regex::Regex;
use serde::Deserialize;
use std::path::Path;

use crate::detectors::Detector;
use crate::diff::Diff;
use crate::report::{Finding, RiskCategory, Severity};

/// A single custom detection rule read from config.
#[derive(Debug, Clone, Deserialize)]
pub struct DetectorRule {
    /// Unique identifier for this rule.
    pub name: String,
    /// Risk category: "api_contract", "async_boundary", "serde_drift", "auth_gate", "concurrency", "other"
    #[serde(default = "default_category")]
    pub category: String,
    /// Severity: "low", "medium", "high", "critical"
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Regex pattern to match against added and removed lines.
    pub pattern: String,
    /// Human-readable message when the pattern matches. Use `{line}` as
    /// a placeholder for the matched line content (truncated to 120 chars).
    #[serde(default = "default_message")]
    pub message: String,
    /// If true, also scan removed lines (default: true).
    #[serde(default = "default_true")]
    pub scan_removed: bool,
    /// If true, only scan added lines (default: false — scans both).
    #[serde(default = "default_false")]
    pub added_only: bool,
}

fn default_category() -> String { "other".to_string() }
fn default_severity() -> String { "medium".to_string() }
fn default_message() -> String { "Custom pattern matched: {line}".to_string() }
fn default_true() -> bool { true }
fn default_false() -> bool { false }

/// Wrapper for TOML deserialization of detector rules.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DetectorsConfig {
    /// Custom detector rules to apply during analysis.
    #[serde(default)]
    pub detectors: Vec<DetectorRule>,
}

/// A compiled custom rule ready for execution.
#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    category: RiskCategory,
    severity: Severity,
    pattern: Regex,
    message_template: String,
    scan_removed: bool,
    added_only: bool,
}

/// Config-file-driven detector that loads custom patterns.
#[derive(Debug, Clone)]
pub struct ConfigDetector {
    name: &'static str,
    rules: Vec<CompiledRule>,
}

impl ConfigDetector {
    /// Create a detector from custom rules defined in TOML config.
    ///
    /// # Errors
    /// Returns a string error for invalid regex patterns or unknown severity/category values.
    pub fn from_rules(rules: Vec<DetectorRule>) -> Result<Self, String> {
        let compiled: Result<Vec<CompiledRule>, String> = rules.into_iter().map(|rule| {
            let pattern = Regex::new(&rule.pattern)
                .map_err(|e| format!("invalid regex in rule '{}': {e}", rule.name))?;
            let severity = parse_severity(&rule.severity)?;
            let category = parse_category(&rule.category)?;
            Ok(CompiledRule {
                name: rule.name,
                category,
                severity,
                pattern,
                message_template: rule.message,
                scan_removed: rule.scan_removed,
                added_only: rule.added_only,
            })
        }).collect();
        Ok(Self {
            name: "config-detector",
            rules: compiled?,
        })
    }

    /// Load and create detectors from a `.cargo-vibe.toml` file.
    pub fn from_vibe_config(root: &Path) -> Option<Self> {
        let config_path = find_config_file(root)?;
        let contents = std::fs::read_to_string(&config_path).ok()?;
        Self::from_toml_str(&contents)
    }

    /// Parse TOML config string into detectors.
    fn from_toml_str(toml_str: &str) -> Option<Self> {
        // Try parsing the full vibe config first, then fall back to bare detectors
        #[derive(Deserialize)]
        struct VibeConfig {
            diff_risk: Option<DiffRiskSection>,
        }
        #[derive(Deserialize)]
        struct DiffRiskSection {
            #[serde(default)]
            detectors: Vec<DetectorRule>,
        }

        // Try full vibe config
        if let Ok(config) = toml::from_str::<VibeConfig>(toml_str) {
            if let Some(section) = config.diff_risk {
                if !section.detectors.is_empty() {
                    return ConfigDetector::from_rules(section.detectors).ok();
                }
            }
        }

        // Try bare detectors format
        if let Ok(rules) = toml::from_str::<DetectorsConfig>(toml_str) {
            if !rules.detectors.is_empty() {
                return ConfigDetector::from_rules(rules.detectors).ok();
            }
        }

        None
    }
}

fn find_config_file(root: &Path) -> Option<std::path::PathBuf> {
    let candidates = [
        root.join(".cargo-vibe.toml"),
        root.join("detectors.toml"),
    ];
    for path in &candidates {
        if path.exists() {
            return Some(path.clone());
        }
    }
    None
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.to_lowercase().as_str() {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(format!("unknown severity '{other}' — use low, medium, high, or critical")),
    }
}

fn parse_category(s: &str) -> Result<RiskCategory, String> {
    match s.to_lowercase().as_str() {
        "api_contract" => Ok(RiskCategory::ApiContract),
        "async_boundary" => Ok(RiskCategory::AsyncBoundary),
        "serde_drift" => Ok(RiskCategory::SerdeDrift),
        "auth_gate" => Ok(RiskCategory::AuthGate),
        "concurrency" => Ok(RiskCategory::Concurrency),
        "other" => Ok(RiskCategory::Other),
        other => Err(format!("unknown category '{other}' — use api_contract, async_boundary, serde_drift, auth_gate, concurrency, or other")),
    }
}

impl Detector for ConfigDetector {
    fn name(&self) -> &'static str {
        self.name
    }

    fn detect(&self, diff: &Diff) -> Vec<Finding> {
        let mut findings = Vec::new();

        for hunk in &diff.hunks {
            for rule in &self.rules {
                // Scan added lines
                for added in &hunk.added {
                    if rule.pattern.is_match(&added.text) {
                        let msg = rule.message_template.replace("{line}", &truncate(&added.text, 120));
                        findings.push(Finding {
                            category: rule.category,
                            severity: rule.severity,
                            file: hunk.path.clone(),
                            line: Some(added.line),
                            message: format!("{}: {msg}", rule.name),
                        });
                    }
                }

                // Scan removed lines
                if rule.scan_removed && !rule.added_only {
                    for removed in &hunk.removed {
                        if rule.pattern.is_match(removed) {
                            let msg = rule.message_template.replace("{line}", &truncate(removed, 120));
                            findings.push(Finding {
                                category: rule.category,
                                severity: rule.severity,
                                file: hunk.path.clone(),
                                line: None, // No line number for removed lines
                                message: format!("{} (removed): {msg}", rule.name),
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}

fn truncate(s: &str, max: usize) -> String {
    let trimmed = s.trim();
    if trimmed.chars().count() <= max {
        trimmed.to_string()
    } else {
        let cut: String = trimmed.chars().take(max).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::parse_unified_diff;

    #[test]
    fn parses_detectors_from_toml() {
        let toml = r#"
[[detectors]]
name = "sql-raw-query"
category = "concurrency"
severity = "high"
pattern = '\.execute\s*\('
message = "Raw SQL execution found"
"#;
        let detector = ConfigDetector::from_toml_str(toml).unwrap();
        assert_eq!(detector.rules.len(), 1);
        assert_eq!(detector.rules[0].name, "sql-raw-query");
        assert_eq!(detector.rules[0].severity, Severity::High);
    }

    #[test]
    fn parses_from_vibe_config_format() {
        let toml = r#"
[diff_risk]
threshold = 8.0

[[diff_risk.detectors]]
name = "company-secret"
category = "auth_gate"
severity = "critical"
pattern = 'SECRET_KEY'
message = "Secret key detected"
"#;
        let detector = ConfigDetector::from_toml_str(toml).unwrap();
        assert_eq!(detector.rules.len(), 1);
        assert_eq!(detector.rules[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_matching_pattern_in_diff() {
        let toml = r#"
[[detectors]]
name = "test-detector"
category = "other"
severity = "high"
pattern = 'dangerous_function\('
"#;
        let detector = ConfigDetector::from_toml_str(toml).unwrap();

        let diff_str = "\
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 pub fn foo() {
+    dangerous_function(42);
}
";
        let diff = parse_unified_diff(diff_str).unwrap();
        let findings = detector.detect(&diff);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("test-detector"));
    }

    #[test]
    fn also_scans_removed_lines_by_default() {
        let toml = r#"
[[detectors]]
name = "removal-detector"
category = "api_contract"
severity = "critical"
pattern = 'pub fn removed_func'
"#;
        let detector = ConfigDetector::from_toml_str(toml).unwrap();

        let diff_str = "\
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
-pub fn removed_func() {}
+pub fn new_func() {}
";
        let diff = parse_unified_diff(diff_str).unwrap();
        let findings = detector.detect(&diff);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("removed"));
    }

    #[test]
    fn added_only_skips_removed_lines() {
        let toml = r#"
[[detectors]]
name = "added-only-detector"
category = "other"
severity = "medium"
pattern = 'pub fn'
added_only = true
scan_removed = false
"#;
        let detector = ConfigDetector::from_toml_str(toml).unwrap();

        let diff_str = "\
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
-pub fn old() {}
+pub fn new() {}
";
        let diff = parse_unified_diff(diff_str).unwrap();
        let findings = detector.detect(&diff);
        // Only the added line should match
        assert_eq!(findings.len(), 1);
    }
}
