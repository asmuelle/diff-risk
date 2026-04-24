//! Detector plug-ins. Each detector inspects a [`Diff`] and emits
//! [`Finding`](crate::report::Finding)s.
//!
//! The trait is object-safe and intentionally small — one method,
//! one input, one output — so new detectors (async-boundary, serde-drift,
//! etc.) can be slotted in without touching existing code.

use crate::diff::Diff;
use crate::report::Finding;

pub mod async_boundary;
pub mod auth;
pub mod concurrency;

/// A detector inspects a parsed diff and produces zero or more findings.
pub trait Detector: Send + Sync {
    /// Short stable identifier (e.g. `"auth-gate"`), used in logs and --explain output.
    fn name(&self) -> &'static str;

    /// Inspect `diff` and return any findings this detector produces.
    fn detect(&self, diff: &Diff) -> Vec<Finding>;
}
