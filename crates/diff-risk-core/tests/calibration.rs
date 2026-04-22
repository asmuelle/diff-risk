//! Calibration corpus — §2.4 in the spec.
//!
//! Each fixture is a real-looking unified diff with a hand-labeled
//! expected score range. These tests are what make scoring tunable
//! rather than vibes: the scorer can evolve as long as the corpus
//! stays satisfied.
//!
//! Fixtures live in `tests/fixtures/` and are paired with this
//! `expectations` table. Keep the table small and meaningful —
//! a bloated corpus with noisy expectations is worse than none.

use std::path::Path;

use diff_risk_core::{analyze, parse_unified_diff};

struct Expectation {
    fixture: &'static str,
    min_score: f32,
    max_score: f32,
    expect_findings: usize,
    note: &'static str,
}

const EXPECTATIONS: &[Expectation] = &[
    Expectation {
        fixture: "low_risk_refactor.diff",
        min_score: 0.0,
        max_score: 1.0,
        expect_findings: 0,
        note: "pure string-concat refactor — must not trip auth detector",
    },
    Expectation {
        fixture: "auth_bypass_deletion.diff",
        min_score: 7.0,
        max_score: 10.0,
        expect_findings: 1,
        note: "deleted permission check — must land above --threshold 7",
    },
    Expectation {
        fixture: "jwt_middleware_added.diff",
        min_score: 7.0,
        max_score: 10.0,
        expect_findings: 1,
        note: "new JWT handler must fire critical",
    },
    Expectation {
        fixture: "token_leak_log.diff",
        min_score: 5.0,
        max_score: 10.0,
        expect_findings: 1,
        note: "logging a bearer token — critical-ish",
    },
];

#[test]
fn calibration_corpus_matches_expectations() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");

    let mut failures: Vec<String> = Vec::new();

    for exp in EXPECTATIONS {
        let path = fixtures_dir.join(exp.fixture);
        let input = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let diff =
            parse_unified_diff(&input).unwrap_or_else(|e| panic!("parse {}: {e}", exp.fixture));
        let report = analyze(&diff);

        if report.findings.len() != exp.expect_findings {
            failures.push(format!(
                "{}: expected {} finding(s), got {} — {}",
                exp.fixture,
                exp.expect_findings,
                report.findings.len(),
                exp.note,
            ));
        }
        if report.score < exp.min_score || report.score > exp.max_score {
            failures.push(format!(
                "{}: score {:.2} outside [{:.2}, {:.2}] — {}",
                exp.fixture, report.score, exp.min_score, exp.max_score, exp.note,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "calibration regressions:\n  - {}",
        failures.join("\n  - ")
    );
}
