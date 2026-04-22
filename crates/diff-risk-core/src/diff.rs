//! Minimal unified-diff parser.
//!
//! Intentionally hand-rolled to keep dependency surface tiny. Handles
//! the subset of unified-diff output produced by `git diff` and `diff -u`
//! that the detectors need:
//!
//! * `diff --git a/... b/...` or `--- a/... / +++ b/...` file headers
//! * `@@ -old_start,old_count +new_start,new_count @@` hunk headers
//! * `+` / `-` / ` ` body lines
//!
//! It is **not** a general patch applier. Line numbers on changed lines
//! are tracked relative to the new file for high-precision reporting.

use thiserror::Error;

/// A single changed hunk within a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedHunk {
    /// File path (as reported in the `+++ b/...` header, `b/` stripped).
    pub path: String,
    /// Added lines together with their 1-based line number in the new file.
    pub added: Vec<AddedLine>,
    /// Raw text of removed lines (line numbers in old file are not currently tracked).
    pub removed: Vec<String>,
}

/// An added line with its line number in the new file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedLine {
    /// 1-based line number in the new file.
    pub line: u32,
    /// Raw line content, without the leading `+`.
    pub text: String,
}

/// A parsed unified diff.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Diff {
    /// All hunks across all files.
    pub hunks: Vec<ChangedHunk>,
}

impl Diff {
    /// Iterate over all added lines across all hunks, paired with their file path.
    pub fn added_lines(&self) -> impl Iterator<Item = (&str, &AddedLine)> {
        self.hunks
            .iter()
            .flat_map(|h| h.added.iter().map(move |a| (h.path.as_str(), a)))
    }

    /// Iterate over all removed lines across all hunks, paired with their file path.
    pub fn removed_lines(&self) -> impl Iterator<Item = (&str, &str)> {
        self.hunks
            .iter()
            .flat_map(|h| h.removed.iter().map(move |r| (h.path.as_str(), r.as_str())))
    }
}

/// Errors returned by [`parse_unified_diff`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiffError {
    /// A hunk header (`@@ ... @@`) could not be parsed.
    #[error("malformed hunk header: {0}")]
    BadHunkHeader(String),
    /// A body line appeared before any `+++` file header.
    #[error("body line before file header: {0}")]
    OrphanBody(String),
}

/// Parse a unified diff into a [`Diff`].
///
/// # Errors
/// Returns [`DiffError`] if a hunk header is malformed or body content
/// appears before a file header.
pub fn parse_unified_diff(input: &str) -> Result<Diff, DiffError> {
    let mut diff = Diff::default();
    let mut current_path: Option<String> = None;
    let mut current_hunk: Option<ChangedHunk> = None;
    let mut new_line_cursor: u32 = 0;

    for line in input.lines() {
        if let Some(rest) = line.strip_prefix("+++ ") {
            flush_hunk(&mut diff, &mut current_hunk);
            current_path = Some(strip_diff_prefix(rest).to_string());
            continue;
        }

        if line.starts_with("--- ") || line.starts_with("diff --git ") || line.starts_with("index ")
        {
            continue;
        }

        if let Some(rest) = line.strip_prefix("@@ ") {
            flush_hunk(&mut diff, &mut current_hunk);
            let Some(path) = current_path.clone() else {
                return Err(DiffError::OrphanBody(line.to_string()));
            };
            new_line_cursor = parse_hunk_header(rest)?;
            current_hunk = Some(ChangedHunk {
                path,
                added: Vec::new(),
                removed: Vec::new(),
            });
            continue;
        }

        // Body lines.
        let Some(hunk) = current_hunk.as_mut() else {
            // Silently skip pre-hunk noise (binary file notices, mode bits).
            continue;
        };

        if let Some(added) = line.strip_prefix('+') {
            hunk.added.push(AddedLine {
                line: new_line_cursor,
                text: added.to_string(),
            });
            new_line_cursor += 1;
        } else if let Some(removed) = line.strip_prefix('-') {
            hunk.removed.push(removed.to_string());
        } else if let Some(_ctx) = line.strip_prefix(' ') {
            new_line_cursor += 1;
        }
        // `\ No newline at end of file` and empty lines are ignored.
    }

    flush_hunk(&mut diff, &mut current_hunk);
    Ok(diff)
}

fn flush_hunk(diff: &mut Diff, current: &mut Option<ChangedHunk>) {
    if let Some(h) = current.take() {
        if !h.added.is_empty() || !h.removed.is_empty() {
            diff.hunks.push(h);
        }
    }
}

fn strip_diff_prefix(header: &str) -> &str {
    // "+++ b/src/foo.rs\tTAB..." → "src/foo.rs"
    let path = header.split('\t').next().unwrap_or(header).trim();
    path.strip_prefix("b/").unwrap_or(path)
}

fn parse_hunk_header(rest: &str) -> Result<u32, DiffError> {
    // rest looks like: "-1,3 +4,7 @@ optional-section"
    let body = rest
        .split_once("@@")
        .map_or(rest, |(before, _)| before)
        .trim();

    for part in body.split_whitespace() {
        if let Some(new_part) = part.strip_prefix('+') {
            let start = new_part
                .split(',')
                .next()
                .ok_or_else(|| DiffError::BadHunkHeader(rest.to_string()))?;
            return start
                .parse::<u32>()
                .map_err(|_| DiffError::BadHunkHeader(rest.to_string()));
        }
    }
    Err(DiffError::BadHunkHeader(rest.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = "\
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 fn a() {}
-fn b() {}
+fn b_renamed() {}
+fn c() {}
";

    #[test]
    fn parses_file_path_without_prefix() {
        let d = parse_unified_diff(SIMPLE).unwrap();
        assert_eq!(d.hunks.len(), 1);
        assert_eq!(d.hunks[0].path, "src/lib.rs");
    }

    #[test]
    fn tracks_added_line_numbers_in_new_file() {
        let d = parse_unified_diff(SIMPLE).unwrap();
        let added = &d.hunks[0].added;
        assert_eq!(added.len(), 2);
        // Hunk starts at new line 1, context bumps cursor to 2, then two + lines at 2 and 3.
        assert_eq!(added[0].line, 2);
        assert_eq!(added[0].text, "fn b_renamed() {}");
        assert_eq!(added[1].line, 3);
    }

    #[test]
    fn collects_removed_lines() {
        let d = parse_unified_diff(SIMPLE).unwrap();
        assert_eq!(d.hunks[0].removed, vec!["fn b() {}".to_string()]);
    }

    #[test]
    fn single_line_hunk_header_is_accepted() {
        let input = "\
--- a/foo.rs
+++ b/foo.rs
@@ -1 +1 @@
-old
+new
";
        let d = parse_unified_diff(input).unwrap();
        assert_eq!(d.hunks[0].added[0].line, 1);
        assert_eq!(d.hunks[0].removed, vec!["old".to_string()]);
    }

    #[test]
    fn malformed_hunk_header_is_reported() {
        let input = "\
+++ b/foo.rs
@@ not-a-header @@
+x
";
        assert!(matches!(
            parse_unified_diff(input),
            Err(DiffError::BadHunkHeader(_))
        ));
    }

    #[test]
    fn empty_diff_is_ok() {
        let d = parse_unified_diff("").unwrap();
        assert!(d.hunks.is_empty());
    }

    #[test]
    fn multi_file_diff() {
        let input = "\
--- a/a.rs
+++ b/a.rs
@@ -1 +1 @@
-a1
+a2
--- a/b.rs
+++ b/b.rs
@@ -1 +1 @@
-b1
+b2
";
        let d = parse_unified_diff(input).unwrap();
        assert_eq!(d.hunks.len(), 2);
        assert_eq!(d.hunks[0].path, "a.rs");
        assert_eq!(d.hunks[1].path, "b.rs");
    }
}
