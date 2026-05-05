//! Brace-depth tracking for multi-line pattern matching.
//!
//! Helps detectors identify constructs that span multiple lines,
//! such as `unsafe { ... }` blocks where `unsafe` and `{` are on
//! different lines.

use crate::diff::Diff;

/// Track brace depth across consecutive added lines in a file hunk.
/// Returns the depth after each line: `Vec<(AddedLine, depth_at_end)>`.
pub fn brace_depth_per_added_line(diff: &Diff) -> Vec<(&str, Vec<(u32, usize)>)> {
    diff.hunks.iter().map(|hunk| {
        let mut depth = 0usize;
        let depths: Vec<(u32, usize)> = hunk.added.iter().map(|added| {
            for ch in added.text.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            (added.line, depth)
        }).collect();
        (hunk.path.as_str(), depths)
    }).collect()
}

/// Check if an `unsafe` keyword appears in a line and is followed by
/// a `{` either on the same line or on a subsequent line within the
/// same hunk, considering brace depth.
///
/// Returns true if multi-line unsafe is detected on any added line.
pub fn has_multi_line_unsafe(added_lines: &[(u32, String)]) -> bool {
    let mut pending_unsafe = false;
    for (_line, text) in added_lines {
        let trimmed = text.trim();
        
        if trimmed == "unsafe" {
            pending_unsafe = true;
            continue;
        }
        
        if pending_unsafe {
            if trimmed.starts_with('{') || trimmed.contains("unsafe {") {
                return true;
            }
            // Reset if we find any non-whitespace, non-comment content
            // that isn't a brace
            if !trimmed.is_empty() && !trimmed.starts_with("//") {
                pending_unsafe = false;
            }
        }
        
        // Also catch same-line `unsafe {`
        if trimmed.contains("unsafe {") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_line_unsafe_detected() {
        let lines = vec![
            (1u32, "unsafe".to_string()),
            (2u32, "{".to_string()),
            (3u32, "    *ptr".to_string()),
            (4u32, "}".to_string()),
        ];
        assert!(has_multi_line_unsafe(&lines));
    }

    #[test]
    fn single_line_unsafe_detected() {
        let lines = vec![
            (1u32, "unsafe { *ptr }".to_string()),
        ];
        assert!(has_multi_line_unsafe(&lines));
    }

    #[test]
    fn no_unsafe_not_detected() {
        let lines = vec![
            (1u32, "let x = 1;".to_string()),
            (2u32, "let y = 2;".to_string()),
        ];
        assert!(!has_multi_line_unsafe(&lines));
    }

    #[test]
    fn unsafe_in_comment_not_detected() {
        let lines = vec![
            (1u32, "unsafe".to_string()),
            (2u32, "// this is a comment, not a brace".to_string()),
            (3u32, "let x = 1;".to_string()),
        ];
        assert!(!has_multi_line_unsafe(&lines));
    }
}
