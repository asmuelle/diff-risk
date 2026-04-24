//! Core risk-scoring engine for `diff-risk`.
//!
//! Parses unified diffs, runs a pipeline of [`Detector`]s against the
//! changed regions, and aggregates findings into a [`RiskReport`] with
//! an overall 0.0–10.0 score.
//!
//! The CLI front-end lives in the `diff-risk-cli` crate; this crate is
//! deliberately I/O-free so it can be embedded in editors, pre-commit
//! hooks, and CI tooling.

pub mod detectors;
pub mod diff;
pub mod report;
pub mod scoring;

pub use detectors::{
    api_contract::ApiContractDetector, async_boundary::AsyncBoundaryDetector, auth::AuthDetector,
    concurrency::ConcurrencyDetector, serde_drift::SerdeDriftDetector, Detector,
};
pub use diff::{parse_unified_diff, ChangedHunk, Diff, DiffError};
pub use report::{Finding, RiskCategory, RiskReport, Severity};
pub use scoring::score_findings;

/// Run the default detector suite against a parsed [`Diff`] and return a [`RiskReport`].
#[must_use]
pub fn analyze(diff: &Diff) -> RiskReport {
    analyze_with(diff, &default_detectors())
}

/// Run an explicit set of detectors against a parsed [`Diff`].
#[must_use]
pub fn analyze_with(diff: &Diff, detectors: &[Box<dyn Detector>]) -> RiskReport {
    let mut findings = Vec::new();
    for detector in detectors {
        findings.extend(detector.detect(diff));
    }
    let score = score_findings(&findings);
    RiskReport { findings, score }
}

/// The detector suite applied by [`analyze`].
#[must_use]
pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(ApiContractDetector::new()),
        Box::new(AsyncBoundaryDetector::new()),
        Box::new(AuthDetector::new()),
        Box::new(ConcurrencyDetector::new()),
        Box::new(SerdeDriftDetector::new()),
    ]
}
