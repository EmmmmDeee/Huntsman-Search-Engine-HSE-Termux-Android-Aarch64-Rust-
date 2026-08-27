//! Architecture invariant tests — compile-time and runtime checks that
//! the module boundaries and contracts hold.

use std::fs;
use std::path::Path;

fn scan_for_violations(dir: &Path, patterns: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    scan_dir(dir, patterns, &mut violations);
    violations
}

fn scan_dir(dir: &Path, patterns: &[&str], violations: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, patterns, violations);
        } else if path.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        } else if path.extension().is_some_and(|e| e == "rs") {
            let raw = fs::read_to_string(&path).unwrap();
            let scanned = production_source(&raw);
            let raw_lines: Vec<&str> = raw.lines().collect();
            for (i, line) in scanned.lines().enumerate() {
                let trimmed = line.trim();
                if patterns.iter().any(|p| trimmed.contains(p)) {
                    let shown = raw_lines.get(i).map_or(trimmed, |l| l.trim());
                    violations.push(format!("{}:{}: {}", path.display(), i + 1, shown));
                }
            }
        }
    }
}
