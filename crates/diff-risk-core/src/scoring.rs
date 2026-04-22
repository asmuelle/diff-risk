//! Scoring function — turns a flat list of findings into a 0.0–10.0 score.
//!
//! The rule is deliberately simple and auditable: sum severity weights,
//! apply a diminishing-returns curve, and clamp to `[0.0, 10.0]`.

use crate::report::Finding;

/// Maximum score the scorer can output.
pub const MAX_SCORE: f32 = 10.0;

/// Score a list of findings.
///
/// Empty list → `0.0`. A single `Critical` finding already lands above the
/// `--threshold 7` gate described in the README. Additional findings push
/// the score up with diminishing returns so that ten medium issues don't
/// outrank one critical.
#[must_use]
pub fn score_findings(findings: &[Finding]) -> f32 {
    if findings.is_empty() {
        return 0.0;
    }

    let total_weight: f32 = findings.iter().map(|f| f.severity.weight()).sum();
    let max_severity_weight = findings
        .iter()
        .map(|f| f.severity.weight())
        .fold(0.0_f32, f32::max);

    // Diminishing-returns curve: max-severity floor + saturating bonus.
    // floor = weight of the worst finding (keeps "one Critical" visible).
    // bonus = scaled log of total weight for pile-up of lesser findings.
    let bonus = (1.0 + total_weight - max_severity_weight).ln().max(0.0);
    let raw = max_severity_weight + bonus;

    raw.clamp(0.0, MAX_SCORE)
}

/// Convenience: does this report's score meet or exceed `threshold`?
#[must_use]
pub fn exceeds(score: f32, threshold: f32) -> bool {
    score >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Finding, RiskCategory, Severity};

    fn finding(sev: Severity) -> Finding {
        Finding {
            category: RiskCategory::Other,
            severity: sev,
            file: "x.rs".to_string(),
            line: Some(1),
            message: "test".to_string(),
        }
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(score_findings(&[]), 0.0);
    }

    #[test]
    fn single_critical_exceeds_threshold_seven() {
        let s = score_findings(&[finding(Severity::Critical)]);
        assert!(s >= 7.0, "critical must exceed threshold 7, got {s}");
    }

    #[test]
    fn single_low_below_threshold_seven() {
        let s = score_findings(&[finding(Severity::Low)]);
        assert!(s < 7.0, "single low must be below threshold 7, got {s}");
    }

    #[test]
    fn one_critical_beats_many_mediums() {
        let crit = score_findings(&[finding(Severity::Critical)]);
        let mediums = score_findings(&[
            finding(Severity::Medium),
            finding(Severity::Medium),
            finding(Severity::Medium),
        ]);
        assert!(crit > mediums);
    }

    #[test]
    fn score_clamped_to_max() {
        let flood: Vec<Finding> = (0..50).map(|_| finding(Severity::Critical)).collect();
        assert!(score_findings(&flood) <= MAX_SCORE);
    }

    #[test]
    fn more_findings_never_lowers_score() {
        let one = score_findings(&[finding(Severity::High)]);
        let two = score_findings(&[finding(Severity::High), finding(Severity::Low)]);
        assert!(two >= one);
    }
}
