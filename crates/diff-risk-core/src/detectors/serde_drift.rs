//! Serde & schema-drift detector (Risk Matrix category C).
//!
//! Flags changes to serde attribute syntax that break wire-format
//! compatibility with other services or stored data:
//!
//! * Adding or removing `#[derive(Serialize)]` / `#[derive(Deserialize)]`
//!   — type enters or leaves the wire format → Medium.
//! * Changing `#[serde(rename = …)]` or `#[serde(rename_all = …)]` —
//!   field name on the wire changes → High.
//! * Changing `#[serde(skip…)]` — field disappears from or reappears in
//!   the wire format → High.
//! * Changing `#[serde(tag …)]` / `#[serde(untagged)]` /
//!   `#[serde(content …)]` / `#[serde(flatten)]` — the enum or nested
//!   struct wire shape changes fundamentally → Critical.
//! * Changing `#[serde(default …)]` — affects deserialization of older
//!   payloads → Medium.
//!
//! Regex-only: we detect *attribute* changes, not renamed struct
//! fields without attributes. A field rename without a `#[serde(rename
//! = …)]` to preserve the old name is the canonical silent wire break
//! that requires AST + paired-line analysis — tracked for a follow-up
//! `syn`-based pass.

use regex::Regex;
use std::sync::OnceLock;

use crate::detectors::Detector;
use crate::diff::Diff;
use crate::report::{Finding, RiskCategory, Severity};

/// Regex-based serde attribute drift detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct SerdeDriftDetector;

impl SerdeDriftDetector {
    /// Construct a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

fn derive_serde_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `#[derive(..., Serialize | Deserialize, ...)]` — order-insensitive.
    RE.get_or_init(|| {
        Regex::new(r"#\[\s*derive\s*\([^\]]*\b(?:Serialize|Deserialize)\b[^\]]*\)\s*\]")
            .expect("derive regex")
    })
}

fn serde_rename_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `#[serde(rename = "...")]` or `#[serde(rename_all = "...")]`.
    RE.get_or_init(|| {
        Regex::new(r"#\[\s*serde\s*\([^\]]*\brename(?:_all)?\s*=").expect("serde rename regex")
    })
}

fn serde_skip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `#[serde(skip)]`, `#[serde(skip_serializing)]`,
    // `#[serde(skip_deserializing)]`, `#[serde(skip_serializing_if = …)]`.
    RE.get_or_init(|| Regex::new(r"#\[\s*serde\s*\([^\]]*\bskip").expect("serde skip regex"))
}

fn serde_wire_shape_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Enum / nested wire-shape attributes — changing any of these is
    // a breaking schema rearrangement.
    RE.get_or_init(|| {
        Regex::new(r"#\[\s*serde\s*\([^\]]*\b(?:tag|untagged|content|flatten)\b")
            .expect("serde wire shape regex")
    })
}

fn serde_default_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"#\[\s*serde\s*\([^\]]*\bdefault\b").expect("serde default regex")
    })
}

impl Detector for SerdeDriftDetector {
    fn name(&self) -> &'static str {
        "serde-drift"
    }

    fn detect(&self, diff: &Diff) -> Vec<Finding> {
        let mut findings = Vec::new();
        for hunk in &diff.hunks {
            for added in &hunk.added {
                findings.extend(scan_line(
                    &hunk.path,
                    Some(added.line),
                    &added.text,
                    "added",
                ));
            }
            for removed in &hunk.removed {
                findings.extend(scan_line(&hunk.path, None, removed, "removed"));
            }
        }
        findings
    }
}

fn scan_line(path: &str, line: Option<u32>, text: &str, verb: &'static str) -> Vec<Finding> {
    let mut out = Vec::new();

    // Wire-shape attributes are the most severe — check first, and
    // don't double-count against the more generic rename/skip rules
    // when `#[serde(tag = "…", rename_all = "…")]` shows up together.
    if serde_wire_shape_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::SerdeDrift,
            severity: Severity::Critical,
            file: path.to_string(),
            line,
            message: format!(
                "serde wire-shape attribute {verb} (tag/untagged/content/flatten): {}",
                truncate(text, 120)
            ),
        });
        return out;
    }

    if serde_rename_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::SerdeDrift,
            severity: Severity::High,
            file: path.to_string(),
            line,
            message: format!(
                "serde rename attribute {verb} — field name on the wire changes: {}",
                truncate(text, 120)
            ),
        });
        return out;
    }

    if serde_skip_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::SerdeDrift,
            severity: Severity::High,
            file: path.to_string(),
            line,
            message: format!(
                "serde skip attribute {verb} — field enters/leaves wire format: {}",
                truncate(text, 120)
            ),
        });
        return out;
    }

    if serde_default_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::SerdeDrift,
            severity: Severity::Medium,
            file: path.to_string(),
            line,
            message: format!(
                "serde default attribute {verb} — affects older-payload deserialization: {}",
                truncate(text, 120)
            ),
        });
        return out;
    }

    if derive_serde_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::SerdeDrift,
            severity: Severity::Medium,
            file: path.to_string(),
            line,
            message: format!(
                "serde derive {verb} — type enters/leaves the wire format: {}",
                truncate(text, 120)
            ),
        });
    }

    out
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

    fn run(diff_text: &str) -> Vec<Finding> {
        let diff = parse_unified_diff(diff_text).expect("valid diff");
        SerdeDriftDetector::new().detect(&diff)
    }

    #[test]
    fn added_derive_serialize_is_medium() {
        let diff = "\
--- a/src/dto.rs
+++ b/src/dto.rs
@@ -1,1 +1,2 @@
 pub mod types;
+#[derive(Debug, Serialize, Deserialize)]
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium && f.message.contains("serde derive")),
            "derive(Serialize) must fire Medium, got {findings:?}"
        );
    }

    #[test]
    fn rename_attribute_is_high() {
        let diff = "\
--- a/src/dto.rs
+++ b/src/dto.rs
@@ -1,1 +1,2 @@
 pub mod types;
+    #[serde(rename = \"user_id\")]
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.message.contains("serde rename")),
            "rename attribute must fire High, got {findings:?}"
        );
    }

    #[test]
    fn removed_rename_attribute_fires() {
        let diff = "\
--- a/src/dto.rs
+++ b/src/dto.rs
@@ -1,3 +1,2 @@
 pub struct User {
-    #[serde(rename = \"user_id\")]
     pub id: u64,
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("serde rename") && f.message.contains("removed")),
            "removed rename must fire, got {findings:?}"
        );
    }

    #[test]
    fn rename_all_attribute_fires() {
        let diff = "\
--- a/src/dto.rs
+++ b/src/dto.rs
@@ -1,1 +1,2 @@
 pub mod types;
+#[serde(rename_all = \"camelCase\")]
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.message.contains("serde rename")),
            "rename_all must fire High, got {findings:?}"
        );
    }

    #[test]
    fn skip_attribute_is_high() {
        let diff = "\
--- a/src/dto.rs
+++ b/src/dto.rs
@@ -1,1 +1,2 @@
 pub mod types;
+    #[serde(skip_serializing)]
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.message.contains("serde skip")),
            "skip must fire High, got {findings:?}"
        );
    }

    #[test]
    fn tag_wire_shape_is_critical() {
        let diff = "\
--- a/src/dto.rs
+++ b/src/dto.rs
@@ -1,1 +1,2 @@
 pub mod types;
+#[serde(tag = \"type\", content = \"data\")]
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.message.contains("serde wire-shape")),
            "tag/content must fire Critical, got {findings:?}"
        );
    }

    #[test]
    fn untagged_wire_shape_is_critical() {
        let diff = "\
--- a/src/dto.rs
+++ b/src/dto.rs
@@ -1,1 +1,2 @@
 pub mod types;
+#[serde(untagged)]
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.message.contains("serde wire-shape")),
            "untagged must fire Critical, got {findings:?}"
        );
    }

    #[test]
    fn flatten_wire_shape_is_critical() {
        let diff = "\
--- a/src/dto.rs
+++ b/src/dto.rs
@@ -1,1 +1,2 @@
 pub mod types;
+    #[serde(flatten)]
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.message.contains("serde wire-shape")),
            "flatten must fire Critical, got {findings:?}"
        );
    }

    #[test]
    fn default_attribute_is_medium() {
        let diff = "\
--- a/src/dto.rs
+++ b/src/dto.rs
@@ -1,1 +1,2 @@
 pub mod types;
+    #[serde(default)]
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium && f.message.contains("serde default")),
            "default must fire Medium, got {findings:?}"
        );
    }

    #[test]
    fn derive_without_serde_is_silent() {
        let diff = "\
--- a/src/dto.rs
+++ b/src/dto.rs
@@ -1,1 +1,2 @@
 pub mod types;
+#[derive(Debug, Clone, PartialEq)]
";
        assert!(
            run(diff).is_empty(),
            "derives that don't include Serialize/Deserialize must not fire"
        );
    }

    #[test]
    fn non_serde_diff_is_silent() {
        let diff = "\
--- a/src/math.rs
+++ b/src/math.rs
@@ -1,1 +1,2 @@
 pub fn add(a: i32, b: i32) -> i32 {
+    a + b
 }
";
        assert!(run(diff).is_empty());
    }
}
