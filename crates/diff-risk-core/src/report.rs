//! Output types: [`Finding`], [`RiskReport`], and supporting enums.

use serde::{Deserialize, Serialize};

/// Categories of semantic risk, as enumerated in the `diff-risk` specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    /// A. Public API contract changes (signatures, visibility, return types).
    ApiContract,
    /// B. Async boundary changes (`.await`, `spawn`, `block_on`, blocking calls).
    AsyncBoundary,
    /// C. Serde / schema drift (renamed fields, changed field types).
    SerdeDrift,
    /// D. Auth & permission gate modifications.
    AuthGate,
    /// E. Concurrency and memory-safety primitives (`Mutex`, `RwLock`, `Arc`, `unsafe`).
    Concurrency,
    /// Everything else — low-risk logic or cosmetic changes.
    Other,
}

impl RiskCategory {
    /// Human-readable display name matching the README headings.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ApiContract => "API Contract Change",
            Self::AsyncBoundary => "Async Boundary Change",
            Self::SerdeDrift => "Serde Schema Drift",
            Self::AuthGate => "Auth / Permission Gate",
            Self::Concurrency => "Concurrency / Memory Safety",
            Self::Other => "Other",
        }
    }
}

/// Severity of an individual finding.
///
/// Maps to the scoring weights applied in [`crate::scoring::score_findings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Cosmetic or low-risk change.
    Low,
    /// Requires a closer look but unlikely to be dangerous alone.
    Medium,
    /// High-risk change — likely to surprise or break things.
    High,
    /// Security- or safety-critical change.
    Critical,
}

impl Severity {
    /// Numeric weight used by [`crate::scoring::score_findings`].
    #[must_use]
    pub fn weight(self) -> f32 {
        match self {
            Self::Low => 1.0,
            Self::Medium => 3.0,
            Self::High => 6.0,
            Self::Critical => 9.0,
        }
    }

    /// Short emoji marker for human-readable output.
    #[must_use]
    pub fn marker(self) -> &'static str {
        match self {
            Self::Low => "✅",
            Self::Medium => "🟡",
            Self::High => "⚠️",
            Self::Critical => "🚨",
        }
    }
}

/// A single detector hit against a specific file/line region.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Category this finding belongs to.
    pub category: RiskCategory,
    /// Severity assigned by the detector.
    pub severity: Severity,
    /// File path, as reported in the diff header.
    pub file: String,
    /// 1-based line number in the new file, or `None` for whole-file findings.
    pub line: Option<u32>,
    /// Short human-readable explanation.
    pub message: String,
}

/// Aggregated output of an analysis run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskReport {
    /// All findings, in detector-defined order.
    pub findings: Vec<Finding>,
    /// Overall risk score on a 0.0–10.0 scale.
    pub score: f32,
}

impl RiskReport {
    /// Return findings filtered to a single category.
    #[must_use]
    pub fn findings_for(&self, category: RiskCategory) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.category == category)
            .collect()
    }

    /// Highest severity observed in the report, if any findings exist.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}
