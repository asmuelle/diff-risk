//! Concurrency & memory-safety detector (Risk Matrix category E).
//!
//! Flags patterns in added lines that raise memory-safety or
//! concurrency-hazard risk when an LLM rewrites Rust:
//!
//! * **`unsafe` block / `fn` / `impl` / `trait`** — Critical.
//! * **`mem::transmute`** — Critical.
//! * **`*_unchecked` methods** (`get_unchecked`, `from_utf8_unchecked`, …) —
//!   High.
//! * **Synchronisation-primitive types** — `Mutex`, `RwLock`, `Atomic*`,
//!   `Cell`, `RefCell`, `UnsafeCell` introduced in type position — High.
//! * **Raw pointers** (`*const T` / `*mut T`) in type position — High.
//! * **Lock acquisition calls** (`.lock()`, `.try_lock()`) — Medium.
//!
//! Detection is regex-only, so precision is bounded. A paired change
//! like `Mutex<T>` → `RwLock<T>` emits one finding (on the added
//! `RwLock<`) rather than trying to correlate sides; that's fine for a
//! warning signal. Future AST-level work can dedupe and catch cases
//! the keyword rules miss (macro expansion, type-alias laundering).

use regex::Regex;
use std::sync::OnceLock;

use crate::detectors::Detector;
use crate::detectors::brace_depth;
use crate::diff::{AddedLine, Diff};
use crate::report::{Finding, RiskCategory, Severity};

/// Regex-based concurrency & memory-safety detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConcurrencyDetector;

impl ConcurrencyDetector {
    /// Construct a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

fn unsafe_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `unsafe` keyword followed by a block, fn, impl, or trait. The
    // word-boundary around `unsafe` keeps us from firing on identifiers
    // that merely contain the substring (e.g. `unsafely_named`).
    RE.get_or_init(|| Regex::new(r"\bunsafe\b\s*(?:(?:fn|impl|trait)\b|\{)").expect("unsafe regex"))
}

fn transmute_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\btransmute\b").expect("transmute regex"))
}

fn unchecked_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Methods whose names end in `_unchecked` — by convention, any such
    // method carries an invariant the caller must uphold.
    RE.get_or_init(|| Regex::new(r"\b\w+_unchecked\b").expect("unchecked regex"))
}

fn sync_primitive_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Primitive type used as a generic container — e.g. `Mutex<T>`,
    // `AtomicU32`. Requires `<` to distinguish type-position use from
    // bare identifiers in comments or imports.
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:Mutex|RwLock|AtomicBool|AtomicU(?:8|16|32|64|size)|AtomicI(?:8|16|32|64|size)|AtomicPtr|UnsafeCell|RefCell|Cell)\s*<",
        )
        .expect("sync primitive regex")
    })
}

fn raw_pointer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `*const T` / `*mut T`. `*` immediately adjacent to the keyword
    // (Rust syntax); trailing `\s` avoids matching identifiers like
    // `*const_name` in arithmetic.
    RE.get_or_init(|| Regex::new(r"\*(?:const|mut)\s").expect("raw pointer regex"))
}

fn lock_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `.lock(` / `.try_lock(` — generic enough to fire on `parking_lot`
    // and `tokio::sync::Mutex` as well as `std::sync::Mutex`.
    RE.get_or_init(|| Regex::new(r"\.\s*(?:lock|try_lock)\s*\(").expect("lock regex"))
}

impl Detector for ConcurrencyDetector {
    fn name(&self) -> &'static str {
        "concurrency"
    }

    fn detect(&self, diff: &Diff) -> Vec<Finding> {
        let mut findings = Vec::new();
        for hunk in &diff.hunks {
            // Check for multi-line unsafe blocks first
            let added_pairs: Vec<(u32, String)> = hunk
                .added
                .iter()
                .map(|a| (a.line, a.text.clone()))
                .collect();
            let has_multi_line = brace_depth::has_multi_line_unsafe(&added_pairs);
            
            for added in &hunk.added {
                let text = &added.text;
                let is_unsafe_line = unsafe_re().is_match(text);
                if is_unsafe_line || (has_multi_line && text.trim() == "{") {
                    // Avoid double-firing when both single-line and multi-line match
                    if is_unsafe_line || !findings.iter().any(|f: &Finding| {
                        f.line == Some(added.line)
                            && f.file == hunk.path
                            && f.message.contains("unsafe code")
                    }) {
                        let msg = if has_multi_line && !is_unsafe_line {
                            format!("unsafe block continued from previous line: {}", truncate(text, 120))
                        } else {
                            format!("unsafe code introduced: {}", truncate(text, 120))
                        };
                        findings.push(Finding {
                            category: RiskCategory::Concurrency,
                            severity: Severity::Critical,
                            file: hunk.path.clone(),
                            line: Some(added.line),
                            message: msg,
                        });
                    }
                }
                findings.extend(scan_added_line(&hunk.path, added));
            }
        }
        findings
    }
}

fn scan_added_line(path: &str, added: &AddedLine) -> Vec<Finding> {
    let mut out = Vec::new();
    let text = &added.text;

    if transmute_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::Concurrency,
            severity: Severity::Critical,
            file: path.to_string(),
            line: Some(added.line),
            message: format!(
                "transmute introduced — bypasses the type system: {}",
                truncate(text, 120)
            ),
        });
    }

    if unchecked_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::Concurrency,
            severity: Severity::High,
            file: path.to_string(),
            line: Some(added.line),
            message: format!(
                "`*_unchecked` method added — caller carries the invariant: {}",
                truncate(text, 120)
            ),
        });
    }

    if sync_primitive_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::Concurrency,
            severity: Severity::High,
            file: path.to_string(),
            line: Some(added.line),
            message: format!(
                "synchronisation primitive type added or changed: {}",
                truncate(text, 120)
            ),
        });
    }

    if raw_pointer_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::Concurrency,
            severity: Severity::High,
            file: path.to_string(),
            line: Some(added.line),
            message: format!("raw pointer introduced: {}", truncate(text, 120)),
        });
    }

    if lock_call_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::Concurrency,
            severity: Severity::Medium,
            file: path.to_string(),
            line: Some(added.line),
            message: format!("lock acquisition added: {}", truncate(text, 120)),
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
        ConcurrencyDetector::new().detect(&diff)
    }

    #[test]
    fn unsafe_block_is_critical() {
        let diff = "\
--- a/src/raw.rs
+++ b/src/raw.rs
@@ -1,2 +1,4 @@
 pub fn peek(p: *const u8) -> u8 {
+    unsafe {
+        *p
+    }
 }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.message.contains("unsafe code")),
            "unsafe block must fire Critical, got {findings:?}"
        );
    }

    #[test]
    fn unsafe_fn_is_critical() {
        let diff = "\
--- a/src/raw.rs
+++ b/src/raw.rs
@@ -1,1 +1,2 @@
 pub mod module;
+pub unsafe fn dangerous() {}
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.message.contains("unsafe code")),
            "unsafe fn must fire Critical, got {findings:?}"
        );
    }

    #[test]
    fn identifier_containing_unsafe_is_not_flagged() {
        let diff = "\
--- a/src/mod.rs
+++ b/src/mod.rs
@@ -1,1 +1,2 @@
 pub mod handlers;
+pub fn unsafely_named_helper() {}
";
        assert!(
            run(diff).iter().all(|f| !f.message.contains("unsafe code")),
            "identifier with `unsafe` substring must not trip the unsafe rule"
        );
    }

    #[test]
    fn transmute_is_critical() {
        let diff = "\
--- a/src/cast.rs
+++ b/src/cast.rs
@@ -1,3 +1,4 @@
 pub fn cast(x: u32) -> f32 {
+    unsafe { std::mem::transmute(x) }
 }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.message.contains("transmute")),
            "transmute must fire Critical, got {findings:?}"
        );
    }

    #[test]
    fn unchecked_method_is_high() {
        let diff = "\
--- a/src/slice.rs
+++ b/src/slice.rs
@@ -1,2 +1,3 @@
 pub fn first(xs: &[u32]) -> u32 {
+    unsafe { *xs.get_unchecked(0) }
 }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.message.contains("_unchecked")),
            "get_unchecked must fire High, got {findings:?}"
        );
    }

    #[test]
    fn sync_primitive_added_is_high() {
        let diff = "\
--- a/src/state.rs
+++ b/src/state.rs
@@ -1,2 +1,3 @@
 pub struct State {
+    pub inner: std::sync::Mutex<Vec<u8>>,
 }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High
                    && f.message.contains("synchronisation primitive")),
            "Mutex<…> added must fire High, got {findings:?}"
        );
    }

    #[test]
    fn mutex_to_rwlock_swap_fires_on_added_side() {
        let diff = "\
--- a/src/state.rs
+++ b/src/state.rs
@@ -1,3 +1,3 @@
 pub struct State {
-    pub inner: std::sync::Mutex<Vec<u8>>,
+    pub inner: std::sync::RwLock<Vec<u8>>,
 }
";
        let findings = run(diff);
        let primitive_hits = findings
            .iter()
            .filter(|f| f.message.contains("synchronisation primitive"))
            .count();
        assert_eq!(
            primitive_hits, 1,
            "Mutex→RwLock swap should emit one primitive finding on the added line, got {findings:?}"
        );
    }

    #[test]
    fn user_type_with_mutex_in_name_is_silent() {
        let diff = "\
--- a/src/mod.rs
+++ b/src/mod.rs
@@ -1,1 +1,2 @@
 pub mod state;
+pub type MyMutexLike<T> = Wrapper<T>;
";
        assert!(
            run(diff)
                .iter()
                .all(|f| !f.message.contains("synchronisation primitive")),
            "user types with Mutex-like names must not trigger the sync primitive rule"
        );
    }

    #[test]
    fn raw_pointer_type_is_high() {
        let diff = "\
--- a/src/ffi.rs
+++ b/src/ffi.rs
@@ -1,1 +1,2 @@
 pub mod bindings;
+pub fn peek(p: *const u8) -> u8 { 0 }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.message.contains("raw pointer")),
            "raw pointer must fire High, got {findings:?}"
        );
    }

    #[test]
    fn multiplication_expression_is_not_a_raw_pointer() {
        let diff = "\
--- a/src/math.rs
+++ b/src/math.rs
@@ -1,2 +1,3 @@
 pub fn double(x: u32, c: u32) -> u32 {
+    x * const_factor(c)
 }
";
        assert!(
            run(diff).iter().all(|f| !f.message.contains("raw pointer")),
            "arithmetic with `*` must not trip raw pointer rule"
        );
    }

    #[test]
    fn lock_call_is_medium() {
        let diff = "\
--- a/src/state.rs
+++ b/src/state.rs
@@ -3,2 +3,3 @@ impl State {
     pub fn mutate(&self) {
+        let _guard = self.inner.lock().unwrap();
     }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium && f.message.contains("lock acquisition")),
            ".lock() call must fire Medium, got {findings:?}"
        );
    }

    #[test]
    fn non_concurrency_diff_is_silent() {
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
