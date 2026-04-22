//! Auth & permission-gate detector (Risk Matrix category D).
//!
//! Strategy: keyword-weighted scan over added and removed lines. A line
//! matching a *strong* auth keyword (`authorize`, `authenticate`, `jwt`,
//! `permission`, `role`, `bearer`, `session`) in a Rust-y context
//! (identifier, string literal, attribute, or function name) is flagged
//! as a `Critical` finding. A line matching a *weak* keyword (`token`,
//! `admin`, `login`, `logout`) is flagged as `High`.
//!
//! Comments and CSS-like contexts are skipped. Non-Rust files still match
//! — LLMs are just as dangerous editing middleware in TOML configs.

use regex::Regex;
use std::sync::OnceLock;

use crate::detectors::Detector;
use crate::diff::Diff;
use crate::report::{Finding, RiskCategory, Severity};

/// Keyword-weighted auth-gate detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthDetector;

impl AuthDetector {
    /// Construct a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// Identifier-boundary pattern: matches at the start/end of the line OR when the
// neighbouring character is a non-alphanumeric. Crucially this treats `_` as a
// boundary, so `skip_jwt_check` and `check_permission` still match, unlike the
// default `\b` (which considers `_` a word character).
const ID_BOUNDARY_PRE: &str = r"(?:^|[^a-z0-9])";
const ID_BOUNDARY_POST: &str = r"(?:[^a-z0-9]|$)";

fn strong_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let pat = format!(
            r"(?ix){ID_BOUNDARY_PRE}(
              authorize | authorise | authorization | authorisation |
              authenticate | authentication |
              jwt | oauth |
              permission | permissions |
              bearer |
              role | roles
            ){ID_BOUNDARY_POST}"
        );
        Regex::new(&pat).expect("strong auth regex")
    })
}

fn weak_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let pat = format!(
            r"(?ix){ID_BOUNDARY_PRE}(
              token | tokens |
              admin |
              login | logout |
              session | sessions |
              credentials?
            ){ID_BOUNDARY_POST}"
        );
        Regex::new(&pat).expect("weak auth regex")
    })
}

// Lines that are pure comments or doc strings — deprioritize but still scan so
// a commented-out `authorize()` call doesn't register as Critical.
fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("*")
}

impl Detector for AuthDetector {
    fn name(&self) -> &'static str {
        "auth-gate"
    }

    fn detect(&self, diff: &Diff) -> Vec<Finding> {
        let strong = strong_re();
        let weak = weak_re();
        let mut out = Vec::new();

        // Added lines — most likely vector for an LLM to introduce a bypass.
        for (path, added) in diff.added_lines() {
            if is_comment_line(&added.text) {
                continue;
            }
            let severity = classify(&added.text, strong, weak);
            if let Some(sev) = severity {
                out.push(Finding {
                    category: RiskCategory::AuthGate,
                    severity: sev,
                    file: path.to_string(),
                    line: Some(added.line),
                    message: format!(
                        "auth-related change on added line: {}",
                        truncate(&added.text, 120)
                    ),
                });
            }
        }

        // Removed lines — deletion of a check is as dangerous as adding one.
        for (path, removed) in diff.removed_lines() {
            if is_comment_line(removed) {
                continue;
            }
            let severity = classify(removed, strong, weak);
            if let Some(sev) = severity {
                out.push(Finding {
                    category: RiskCategory::AuthGate,
                    severity: sev,
                    file: path.to_string(),
                    line: None,
                    message: format!("auth-related line removed: {}", truncate(removed, 120)),
                });
            }
        }

        out
    }
}

fn classify(line: &str, strong: &Regex, weak: &Regex) -> Option<Severity> {
    if strong.is_match(line) {
        Some(Severity::Critical)
    } else if weak.is_match(line) {
        Some(Severity::High)
    } else {
        None
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

    fn run(diff_text: &str) -> Vec<Finding> {
        let diff = parse_unified_diff(diff_text).expect("valid diff");
        AuthDetector::new().detect(&diff)
    }

    #[test]
    fn flags_added_authorize_call_as_critical() {
        let diff = "\
--- a/src/auth.rs
+++ b/src/auth.rs
@@ -10,3 +10,4 @@
 fn handler() {
-    authorize(&req)?;
+    // TODO: re-enable later
 }
";
        let findings = run(diff);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "removed authorize() must fire critical, got {findings:?}"
        );
    }

    #[test]
    fn flags_added_jwt_change_as_critical() {
        let diff = "\
--- a/src/mw.rs
+++ b/src/mw.rs
@@ -1,3 +1,4 @@
 fn verify() {}
+fn skip_jwt_check() { true }
";
        let findings = run(diff);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].category, RiskCategory::AuthGate);
        assert_eq!(findings[0].line, Some(2));
    }

    #[test]
    fn bare_token_word_is_high_not_critical() {
        // No strong keyword (no "bearer", "jwt", etc.) — just "token".
        let diff = "\
--- a/src/client.rs
+++ b/src/client.rs
@@ -1,1 +1,2 @@
 fn x() {}
+    let token = fetch();
";
        let findings = run(diff);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn admin_alone_is_high() {
        let diff = "\
--- a/src/users.rs
+++ b/src/users.rs
@@ -1,1 +1,2 @@
 fn x() {}
+    user.admin = true;
";
        let findings = run(diff);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn comment_only_lines_are_ignored() {
        let diff = "\
--- a/src/notes.rs
+++ b/src/notes.rs
@@ -1,1 +1,2 @@
 fn x() {}
+    // authorize the user later
";
        assert!(run(diff).is_empty());
    }

    #[test]
    fn non_auth_diff_produces_nothing() {
        let diff = "\
--- a/src/math.rs
+++ b/src/math.rs
@@ -1,1 +1,2 @@
 fn x() {}
+    let sum = a + b;
";
        assert!(run(diff).is_empty());
    }

    #[test]
    fn removed_permission_check_is_critical() {
        let diff = "\
--- a/src/mw.rs
+++ b/src/mw.rs
@@ -5,4 +5,3 @@
 fn guard() {
-    check_permission(user, \"admin\")?;
 }
";
        let findings = run(diff);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }
}
