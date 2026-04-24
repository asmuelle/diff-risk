//! Async-boundary detector (Risk Matrix category B).
//!
//! Flags the most common ways an LLM silently introduces a deadlock or
//! an executor-starvation bug in async Rust:
//!
//! * **`.await` inside a loop** — still the #1 "AI shipped a quadratic
//!   roundtrip" pattern. Detected with a per-hunk indentation walk over
//!   the added lines; false positives are possible when diff context is
//!   missing but the precision/recall trade-off is acceptable for a
//!   warning signal.
//! * **`block_on` / `block_in_place`** — synchronously blocking the
//!   executor.
//! * **`std::thread::sleep`** — almost always wrong in async code.
//! * **`async fn` signature changes** — adding or removing `async` from
//!   a function changes every caller's await-point topology.
//!
//! Future (AST-level) work will catch `impl Future for …`, `Poll::Ready`
//! hand-rolls, and `tokio::spawn` misuse.

use regex::Regex;
use std::sync::OnceLock;

use crate::detectors::Detector;
use crate::diff::{AddedLine, Diff};
use crate::report::{Finding, RiskCategory, Severity};

/// Keyword + indentation-tracking async-boundary detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct AsyncBoundaryDetector;

impl AsyncBoundaryDetector {
    /// Construct a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

fn loop_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Matches a loop header anchored to the line's first non-whitespace token.
    // We intentionally do *not* match bare `loop` inside an expression because
    // that's far rarer than the statement-level pattern we care about.
    RE.get_or_init(|| Regex::new(r"^\s*(for\s+|while\s+|loop\s*\{)").expect("loop header regex"))
}

fn block_on_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(block_on|block_in_place)\s*\(").expect("block_on regex"))
}

fn thread_sleep_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `std::thread::sleep`, `thread::sleep`, or bare `sleep(` (from a `use` import).
    // The bare form is too ambiguous without AST, so we require `thread::sleep` here.
    RE.get_or_init(|| Regex::new(r"\bthread::sleep\b").expect("thread::sleep regex"))
}

fn async_fn_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\basync\s+fn\b").expect("async fn regex"))
}

impl Detector for AsyncBoundaryDetector {
    fn name(&self) -> &'static str {
        "async-boundary"
    }

    fn detect(&self, diff: &Diff) -> Vec<Finding> {
        let mut findings = Vec::new();

        for hunk in &diff.hunks {
            findings.extend(await_in_loop(&hunk.path, &hunk.added));

            for added in &hunk.added {
                findings.extend(scan_added_line(&hunk.path, added));
            }

            for removed in &hunk.removed {
                if async_fn_re().is_match(removed) {
                    findings.push(Finding {
                        category: RiskCategory::AsyncBoundary,
                        severity: Severity::Medium,
                        file: hunk.path.clone(),
                        line: None,
                        message: format!(
                            "async fn removed or converted to sync: {}",
                            truncate(removed, 120)
                        ),
                    });
                }
            }
        }

        findings
    }
}

fn scan_added_line(path: &str, added: &AddedLine) -> Vec<Finding> {
    let mut out = Vec::new();
    let text = &added.text;

    if block_on_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::AsyncBoundary,
            severity: Severity::High,
            file: path.to_string(),
            line: Some(added.line),
            message: format!("executor-blocking call introduced: {}", truncate(text, 120)),
        });
    }

    if thread_sleep_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::AsyncBoundary,
            severity: Severity::High,
            file: path.to_string(),
            line: Some(added.line),
            message: format!(
                "`thread::sleep` added — blocks the executor if called from an async task: {}",
                truncate(text, 120)
            ),
        });
    }

    if async_fn_re().is_match(text) {
        out.push(Finding {
            category: RiskCategory::AsyncBoundary,
            severity: Severity::Medium,
            file: path.to_string(),
            line: Some(added.line),
            message: format!(
                "async fn signature added or changed: {}",
                truncate(text, 120)
            ),
        });
    }

    out
}

/// Indentation-tracking walk over a hunk's added lines that flags any
/// `.await` appearing inside a still-open loop introduced earlier in the
/// same added block.
fn await_in_loop(path: &str, added: &[AddedLine]) -> Vec<Finding> {
    let mut stack: Vec<usize> = Vec::new();
    let mut findings = Vec::new();

    for line in added {
        let indent = leading_ws(&line.text);

        // Pop any loops we've de-indented out of.
        while let Some(&top) = stack.last() {
            if indent <= top {
                stack.pop();
            } else {
                break;
            }
        }

        let is_loop = loop_header_re().is_match(&line.text);
        let has_await = line.text.contains(".await");

        // If `.await` lands while at least one loop header is still open above us,
        // that's the canonical "await inside a loop" smell.
        if has_await && !stack.is_empty() && !is_loop {
            findings.push(Finding {
                category: RiskCategory::AsyncBoundary,
                severity: Severity::High,
                file: path.to_string(),
                line: Some(line.line),
                message: format!(
                    "`.await` inside a loop — risks serialised round-trips: {}",
                    truncate(&line.text, 120)
                ),
            });
        }

        if is_loop {
            stack.push(indent);
        }
    }

    findings
}

fn leading_ws(s: &str) -> usize {
    s.chars().take_while(|c| c.is_whitespace()).count()
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
        AsyncBoundaryDetector::new().detect(&diff)
    }

    #[test]
    fn await_inside_for_loop_is_high() {
        let diff = "\
--- a/src/work.rs
+++ b/src/work.rs
@@ -1,3 +1,6 @@
 pub async fn go(items: Vec<Id>) {
+    for id in items {
+        fetch(id).await;
+    }
 }
";
        let findings = run(diff);
        assert!(
            findings.iter().any(
                |f| f.severity == Severity::High && f.message.contains(".await` inside a loop")
            ),
            "expected await-in-loop hit, got {findings:?}"
        );
    }

    #[test]
    fn await_outside_loop_is_not_flagged() {
        let diff = "\
--- a/src/work.rs
+++ b/src/work.rs
@@ -1,2 +1,3 @@
 pub async fn go() {
+    fetch().await;
 }
";
        let findings = run(diff);
        assert!(
            !findings.iter().any(|f| f.message.contains("inside a loop")),
            "plain .await must not trigger the loop rule, got {findings:?}"
        );
    }

    #[test]
    fn block_on_added_is_high() {
        let diff = "\
--- a/src/runner.rs
+++ b/src/runner.rs
@@ -3,3 +3,4 @@ pub fn run(rt: &Runtime) {
     let task = build();
+    rt.block_on(task);
 }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.message.contains("executor-blocking")),
            "block_on must fire High, got {findings:?}"
        );
    }

    #[test]
    fn thread_sleep_added_is_high() {
        let diff = "\
--- a/src/net.rs
+++ b/src/net.rs
@@ -1,2 +1,3 @@
 pub async fn poll_once() {
+    std::thread::sleep(std::time::Duration::from_millis(50));
 }
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.message.contains("thread::sleep")),
            "thread::sleep must fire High, got {findings:?}"
        );
    }

    #[test]
    fn new_async_fn_is_medium() {
        let diff = "\
--- a/src/api.rs
+++ b/src/api.rs
@@ -1,1 +1,2 @@
 pub mod handlers;
+pub async fn refresh() {}
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium
                    && f.message.contains("async fn signature")),
            "async fn added should fire Medium, got {findings:?}"
        );
    }

    #[test]
    fn async_converted_to_sync_is_medium() {
        let diff = "\
--- a/src/api.rs
+++ b/src/api.rs
@@ -1,3 +1,3 @@
-pub async fn refresh() {}
+pub fn refresh() {}
";
        let findings = run(diff);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium
                    && f.message.contains("removed or converted")),
            "async→sync must fire Medium, got {findings:?}"
        );
    }

    #[test]
    fn non_async_diff_is_silent() {
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
