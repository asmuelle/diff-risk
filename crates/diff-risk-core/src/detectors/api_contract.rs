//! API-contract detector (Risk Matrix category A).
//!
//! Flags changes to the public surface of a Rust crate — any added or
//! removed `pub` declaration that changes what downstream crates can
//! see. Regex-only, so:
//!
//! * a rename like `pub fn foo` → `pub fn bar` emits **two** findings
//!   (one per side). That's accurate: to the parser, both sides are
//!   public-surface changes.
//! * a pure visibility flip (`pub fn f` → `fn f`) emits one finding on
//!   the removed side. The added plain-`fn` line won't match.
//! * Restricted visibilities (`pub(crate)`, `pub(super)`, `pub(in …)`)
//!   are intentionally excluded — the `\bpub\s+` anchor requires
//!   whitespace after `pub`, and `pub(crate)` has `(` instead.
//!
//! Severity tiers:
//!
//! * `pub trait` — Critical (every impl downstream needs to change).
//! * `pub struct` / `enum` / `union` / `type` / `const` / `static` /
//!   `mod` — High (type or value in the public namespace).
//! * `pub fn` — Medium (common enough that treating every one as High
//!   would drown out real risks).
//! * `pub use` — Medium (re-export surface change).

use regex::Regex;
use std::sync::OnceLock;

use crate::detectors::Detector;
use crate::diff::Diff;
use crate::report::{Finding, RiskCategory, Severity};

/// Regex-based public-API surface detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct ApiContractDetector;

impl ApiContractDetector {
    /// Construct a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

fn pub_trait_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `pub trait Name` / `pub unsafe trait Name`.
    RE.get_or_init(|| Regex::new(r"\bpub\s+(?:unsafe\s+)?trait\s+\w+").expect("pub trait regex"))
}

fn pub_type_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `pub struct|enum|union|type|const|static|mod Name`.
    RE.get_or_init(|| {
        Regex::new(r"\bpub\s+(?:struct|enum|union|type|const|static|mod)\s+\w+")
            .expect("pub type regex")
    })
}

fn pub_fn_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `pub fn` with optional modifier keywords and optional
    // `extern "C"`-style ABI string.
    RE.get_or_init(|| {
        Regex::new(r#"\bpub\s+(?:(?:async|const|unsafe|extern(?:\s+"[^"]+")?)\s+)*fn\s+\w+"#)
            .expect("pub fn regex")
    })
}

fn pub_use_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bpub\s+use\s+").expect("pub use regex"))
}

impl Detector for ApiContractDetector {
    fn name(&self) -> &'static str {
        "api-contract"
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

    // Order matters: match the most specific rules first so a `pub
    // trait` line fires Critical rather than also tripping a looser
    // rule.
    if pub_trait_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::ApiContract,
            severity: Severity::Critical,
            file: path.to_string(),
            line,
            message: format!("public trait {verb}: {}", truncate(text, 120)),
        });
        return out;
    }

    if pub_type_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::ApiContract,
            severity: Severity::High,
            file: path.to_string(),
            line,
            message: format!("public type or item {verb}: {}", truncate(text, 120)),
        });
        return out;
    }

    if pub_fn_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::ApiContract,
            severity: Severity::Medium,
            file: path.to_string(),
            line,
            message: format!("public fn signature {verb}: {}", truncate(text, 120)),
        });
        return out;
    }

    if pub_use_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::ApiContract,
            severity: Severity::Medium,
            file: path.to_string(),
            line,
            message: format!("public re-export {verb}: {}", truncate(text, 120)),
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
        ApiContractDetector::new().detect(&diff)
    }

    #[test]
    fn added_pub_fn_is_medium() {
        let diff = "\
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 pub mod internal;
+pub fn parse(input: &str) -> Result<(), ()> { Ok(()) }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium && f.message.contains("public fn")),
            "added pub fn must fire Medium, got {findings:?}"
        );
    }

    #[test]
    fn pub_fn_signature_change_fires_twice() {
        let diff = "\
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,3 @@
 pub mod types;
-pub fn find_user(id: u32) -> Option<User> { None }
+pub fn find_user(id: u64) -> Option<User> { None }
";
        let findings = run(diff);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.message.contains("public fn"))
                .count(),
            2,
            "rename/signature change should emit one finding per side, got {findings:?}"
        );
    }

    #[test]
    fn pub_crate_fn_is_not_flagged() {
        let diff = "\
--- a/src/util.rs
+++ b/src/util.rs
@@ -1,1 +1,2 @@
 pub mod inner;
+pub(crate) fn helper() {}
";
        assert!(
            run(diff).is_empty(),
            "pub(crate) fn must not be treated as public API"
        );
    }

    #[test]
    fn pub_struct_is_high() {
        let diff = "\
--- a/src/model.rs
+++ b/src/model.rs
@@ -1,1 +1,2 @@
 pub mod types;
+pub struct Config { pub port: u16 }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.message.contains("public type")),
            "pub struct must fire High, got {findings:?}"
        );
    }

    #[test]
    fn pub_trait_is_critical() {
        let diff = "\
--- a/src/traits.rs
+++ b/src/traits.rs
@@ -1,1 +1,2 @@
 pub mod impls;
+pub trait Handler { fn handle(&self); }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.message.contains("public trait")),
            "pub trait must fire Critical, got {findings:?}"
        );
    }

    #[test]
    fn pub_unsafe_trait_is_critical() {
        let diff = "\
--- a/src/traits.rs
+++ b/src/traits.rs
@@ -1,1 +1,2 @@
 pub mod impls;
+pub unsafe trait Raw { unsafe fn get(&self); }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.message.contains("public trait")),
            "pub unsafe trait must fire Critical, got {findings:?}"
        );
    }

    #[test]
    fn pub_use_is_medium() {
        let diff = "\
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 pub mod internal;
+pub use internal::Config;
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium && f.message.contains("public re-export")),
            "pub use must fire Medium, got {findings:?}"
        );
    }

    #[test]
    fn removed_pub_fn_is_flagged() {
        let diff = "\
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,2 +1,1 @@
 pub mod internal;
-pub fn deprecated_helper() {}
";
        let findings = run(diff);
        assert!(
            findings.iter().any(|f| f.message.contains("removed")),
            "removed pub fn must be flagged, got {findings:?}"
        );
    }

    #[test]
    fn identifier_containing_pub_is_not_flagged() {
        let diff = "\
--- a/src/mod.rs
+++ b/src/mod.rs
@@ -1,1 +1,2 @@
 pub mod inner;
+let _republish_count = 0;
";
        let findings = run(diff);
        // `pub mod inner` is context (not added/removed), so shouldn't
        // fire. The added line contains `republish` which contains
        // `pub` only as a substring.
        assert!(
            findings.is_empty(),
            "identifier containing `pub` substring must not fire, got {findings:?}"
        );
    }

    #[test]
    fn pub_extern_c_fn_is_medium() {
        let diff = "\
--- a/src/ffi.rs
+++ b/src/ffi.rs
@@ -1,1 +1,2 @@
 pub mod bindings;
+pub extern \"C\" fn ffi_entry() {}
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium && f.message.contains("public fn")),
            "pub extern \"C\" fn must fire Medium, got {findings:?}"
        );
    }

    #[test]
    fn non_api_diff_is_silent() {
        let diff = "\
--- a/src/math.rs
+++ b/src/math.rs
@@ -1,2 +1,3 @@
 fn add(a: i32, b: i32) -> i32 {
+    a + b
 }
";
        assert!(run(diff).is_empty());
    }
}
