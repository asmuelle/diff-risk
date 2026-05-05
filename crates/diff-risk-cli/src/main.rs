//! `diff-risk` CLI front-end.
//!
//! Reads a unified diff from stdin (or, with `--commit`, will eventually
//! shell out to git), runs the core detectors, and prints a
//! human-readable risk report. Exits non-zero when `--threshold` is set
//! and the score meets or exceeds it — designed for CI gating.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use diff_risk_core::{
    analyze_with, default_detectors, parse_unified_diff, scoring::exceeds, ConfigDetector,
    Detector, Finding, RiskReport, Severity,
};

/// Semantic risk scoring for Rust diffs.
#[derive(Debug, Parser)]
#[command(name = "diff-risk", version, about, long_about = None)]
struct Cli {
    /// Score a specific commit (not yet implemented — reads stdin for now).
    #[arg(long, value_name = "SHA")]
    commit: Option<String>,

    /// Exit non-zero if the risk score meets or exceeds this threshold.
    #[arg(long, value_name = "SCORE")]
    threshold: Option<f32>,

    /// Suppress the human-readable report — print the score only.
    #[arg(long)]
    quiet: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(exit) => exit,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    if cli.commit.is_some() {
        anyhow::bail!("--commit is not implemented yet; pipe a unified diff on stdin");
    }

    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read diff from stdin")?;

    let diff = parse_unified_diff(&input).context("failed to parse unified diff")?;
    let detectors = detectors_for_root(&std::env::current_dir().context("failed to read cwd")?)?;
    let report = analyze_with(&diff, &detectors);

    if cli.quiet {
        println!("{:.1}", report.score);
    } else {
        print_report(&report);
    }

    if let Some(threshold) = cli.threshold {
        if exceeds(report.score, threshold) {
            return Ok(ExitCode::from(1));
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn detectors_for_root(root: &Path) -> Result<Vec<Box<dyn Detector>>> {
    let mut detectors = default_detectors();
    if let Some(config_detector) = load_config_detector(root)? {
        detectors.push(Box::new(config_detector));
    }
    Ok(detectors)
}

fn load_config_detector(root: &Path) -> Result<Option<ConfigDetector>> {
    for path in detector_config_candidates(root) {
        if !path.exists() {
            continue;
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        match ConfigDetector::from_toml_str(&contents)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?
        {
            Some(detector) => return Ok(Some(detector)),
            None => continue,
        }
    }
    Ok(None)
}

fn detector_config_candidates(root: &Path) -> [PathBuf; 2] {
    [root.join(".cargo-vibe.toml"), root.join("detectors.toml")]
}

fn print_report(report: &RiskReport) {
    let banner_severity = report.max_severity().unwrap_or(Severity::Low);
    println!(
        "{} DIFF RISK ASSESSMENT: [SCORE: {:.1}/10.0 — {}]",
        banner_severity.marker(),
        report.score,
        severity_label(banner_severity),
    );

    if report.findings.is_empty() {
        println!();
        println!("  No risky patterns detected.");
        return;
    }

    println!();
    for finding in &report.findings {
        print_finding(finding);
    }
}

fn print_finding(f: &Finding) {
    let location = match f.line {
        Some(n) => format!("{}:{n}", f.file),
        None => f.file.clone(),
    };
    println!(
        "  {} {}: {} — {}",
        f.severity.marker(),
        f.category.label(),
        location,
        f.message,
    );
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Low => "LOW RISK",
        Severity::Medium => "MEDIUM RISK",
        Severity::High => "HIGH RISK",
        Severity::Critical => "CRITICAL RISK",
    }
}
