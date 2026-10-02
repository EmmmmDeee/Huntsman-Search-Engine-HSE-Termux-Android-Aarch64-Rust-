//! Repository architectural invariants compiled from repeated maintenance rules.
//!
//! This is deliberately source/configuration inspection, complementary to the
//! runtime module-graph audit. A failure to inspect a protected surface is a
//! violation, never a vacuous pass.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Invariantized,
    Automated,
    Procedural,
    Blocked,
    Superseded,
    Obsolete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantStatus {
    Satisfied,
    Violated,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InvariantReport {
    pub id: &'static str,
    pub protected_property: &'static str,
    pub failure_class: &'static str,
    pub enforcement_boundary: &'static str,
    pub disposition: Disposition,
    pub status: InvariantStatus,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepositoryInvariantAudit {
    pub root: PathBuf,
    pub reports: Vec<InvariantReport>,
}

impl RepositoryInvariantAudit {
    #[must_use]
    pub fn has_violations(&self) -> bool {
        self.reports
            .iter()
            .any(|report| report.status == InvariantStatus::Violated)
    }

    #[must_use]
    pub fn has_blockers(&self) -> bool {
        self.reports
            .iter()
            .any(|report| report.status == InvariantStatus::Blocked)
    }
}

fn read_required(root: &Path, relative: &str) -> Result<String, String> {
    let path = root.join(relative);
    fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))
}

fn quoted_assignment(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|raw| {
        let line = raw.split('#').next().unwrap_or("").trim();
        let (left, right) = line.split_once('=')?;
        if left.trim() != key {
            return None;
        }
        let value = right.trim();
        (value.len() >= 2 && value.starts_with('"') && value.ends_with('"'))
            .then(|| value[1..value.len() - 1].to_owned())
    })
}

fn numeric_toolchain_values(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let value = line.trim().strip_prefix("toolchain:")?.trim();
            let value = value.trim_matches('"').trim_matches('\'');
            value
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_digit())
                .then(|| value.to_owned())
        })
        .collect()
}

fn report_failure(
    id: &'static str,
    property: &'static str,
    class: &'static str,
    boundary: &'static str,
    disposition: Disposition,
    error: String,
) -> InvariantReport {
    InvariantReport {
        id,
        protected_property: property,
        failure_class: class,
        enforcement_boundary: boundary,
        disposition,
        status: InvariantStatus::Violated,
        evidence: vec![error],
    }
}

fn auto_update_policy(root: &Path) -> InvariantReport {
    const ID: &str = "INV-AUTOUPDATE-001";
    const PROPERTY: &str = "auto-update ownership policy has one executable authority";
    const CLASS: &str = "runtime/test mirrored predicates can diverge";
    const BOUNDARY: &str = "Rust function";

    let Ok(source) = read_required(root, "src/cli/update.rs") else {
        return report_failure(
            ID,
            PROPERTY,
            CLASS,
            BOUNDARY,
            Disposition::Invariantized,
            "src/cli/update.rs is unreadable".into(),
        );
    };

    let count = source
        .matches("fn skips_auto_update(command: &Command) -> bool")
        .count();
    let obsolete_reminder = source.contains("Mirrors the skip predicate");

    InvariantReport {
        id: ID,
        protected_property: PROPERTY,
        failure_class: CLASS,
        enforcement_boundary: BOUNDARY,
        disposition: Disposition::Invariantized,
        status: if count == 1 && !obsolete_reminder {
            InvariantStatus::Satisfied
        } else {
            InvariantStatus::Violated
        },
        evidence: vec![
            format!("executable policy definitions: {count}"),
            format!("obsolete mirror reminder present: {obsolete_reminder}"),
        ],
    }
}

fn rust_toolchain(root: &Path) -> InvariantReport {
    const ID: &str = "INV-RUSTPIN-001";
    const PROPERTY: &str = "normal CI and Docker use a project-compatible Rust release";
    const CLASS: &str = "copied toolchain literals drift from repository authority";
    const BOUNDARY: &str = "rust-toolchain.toml + Rust architecture audit";

    let toolchain = match read_required(root, "rust-toolchain.toml") {
        Ok(value) => value,
        Err(error) => {
            return report_failure(
                ID,
                PROPERTY,
                CLASS,
                BOUNDARY,
                Disposition::Automated,
                error,
            );
        }
    };
    let cargo = match read_required(root, "Cargo.toml") {
        Ok(value) => value,
        Err(error) => {
            return report_failure(
                ID,
                PROPERTY,
                CLASS,
                BOUNDARY,
                Disposition::Automated,
                error,
            );
        }
    };
    let Some(project) = quoted_assignment(&toolchain, "channel") else {
        return report_failure(
            ID,
            PROPERTY,
            CLASS,
            BOUNDARY,
            Disposition::Automated,
            "rust-toolchain.toml has no quoted channel assignment".into(),
        );
    };
    let Some(msrv) = quoted_assignment(&cargo, "rust-version") else {
        return report_failure(
            ID,
            PROPERTY,
            CLASS,
            BOUNDARY,
            Disposition::Automated,
            "Cargo.toml has no quoted rust-version assignment".into(),
        );
    };

    let workflows = root.join(".github/workflows");
    let entries = match fs::read_dir(&workflows) {
        Ok(entries) => entries,
        Err(error) => {
            return report_failure(
                ID,
                PROPERTY,
                CLASS,
                BOUNDARY,
                Disposition::Automated,
                format!("{}: {error}", workflows.display()),
            );
        }
    };

    let mut workflow_count = 0_usize;
    let mut invalid = Vec::new();
    let mut numeric_count = 0_usize;

    for entry in entries.flatten() {
        let path = entry.path();
        if !matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        workflow_count += 1;
        let Ok(text) = fs::read_to_string(&path) else {
            invalid.push(format!("unreadable workflow {}", path.display()));
            continue;
        };
        for value in numeric_toolchain_values(&text) {
            numeric_count += 1;
            let filename = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("<non-utf8>");
            let legitimate_msrv = filename == "ci.yml" && value == msrv;
            if value != project && !legitimate_msrv {
                invalid.push(format!("{filename}: numeric toolchain {value}"));
            }
        }
    }

    if workflow_count == 0 {
        invalid.push("no workflow files discovered (non-vacuity failure)".into());
    }
    if numeric_count == 0 {
        invalid.push("no numeric toolchain declarations discovered (non-vacuity failure)".into());
    }

    match read_required(root, "Dockerfile") {
        Ok(docker) => {
            let builder = docker
                .lines()
                .map(str::trim)
                .find(|line| line.starts_with("FROM rust:") && line.contains(" AS builder"));
            match builder {
                Some(line) => {
                    let tag = line
                        .trim_start_matches("FROM rust:")
                        .split_whitespace()
                        .next()
                        .unwrap_or("");
                    let version = tag.split('-').next().unwrap_or(tag);
                    if version != project {
                        invalid.push(format!(
                            "Docker builder Rust {version} != project channel {project}"
                        ));
                    }
                }
                None => invalid.push("Docker Rust builder line not found".into()),
            }
        }
        Err(error) => invalid.push(error),
    }

    InvariantReport {
        id: ID,
        protected_property: PROPERTY,
        failure_class: CLASS,
        enforcement_boundary: BOUNDARY,
        disposition: Disposition::Automated,
        status: if invalid.is_empty() {
            InvariantStatus::Satisfied
        } else {
            InvariantStatus::Violated
        },
        evidence: if invalid.is_empty() {
            vec![
                format!("project channel: {project}"),
                format!("declared MSRV: {msrv}"),
                format!("workflow files inspected: {workflow_count}"),
                format!("numeric toolchain declarations inspected: {numeric_count}"),
            ]
        } else {
            invalid
        },
    }
}

/// Run all repository invariants against `root`.
#[must_use]
pub fn audit_repository(root: &Path) -> RepositoryInvariantAudit {
    RepositoryInvariantAudit {
        root: root.to_path_buf(),
        reports: vec![auto_update_policy(root), rust_toolchain(root)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_toolchain_detector_catches_stale_fixture() {
        assert_eq!(
            numeric_toolchain_values("with:\n  toolchain: 1.97.1\n"),
            vec!["1.97.1".to_owned()]
        );
    }

    #[test]
    fn quoted_assignment_ignores_comments() {
        assert_eq!(
            quoted_assignment(
                "[toolchain]\nchannel = \"1.98.0\" # authoritative\n",
                "channel"
            ),
            Some("1.98.0".into())
        );
    }
}
