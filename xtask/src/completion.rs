//! Deterministic, evidence-limited repository inventory and dependency-ordered work register.
//! Engineering tooling only: no network, credentials, source edits or runtime dependencies.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path};
use std::process::ExitCode;

use serde_json::Value;

use crate::error::{self, Error, Result};
use crate::proc::{git_stdout, repository_root};

const USAGE: &str = "usage: cargo run --locked -p xtask -- completion [print|write|check]
  print   show the current full Markdown register on stdout (default)
  write   regenerate target/completion/IMPLEMENTATION_REGISTER.md
  check   compare that generated file with current tracked inputs";

const OUTPUT: &str = "target/completion/IMPLEMENTATION_REGISTER.md";
const TASKS: &str = "docs/completion/tasks.json";

#[derive(Debug)]
struct Task {
    id: String,
    path: String,
    priority: u8,
    state: String,
    objective: String,
    evidence: String,
    implementation: String,
    verification: String,
    dependencies: Vec<String>,
}

#[derive(Default)]
struct Tree {
    children: BTreeMap<String, Tree>,
    label: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let mode = match args {
        [] => "print",
        [one] if matches!(one.as_str(), "print" | "write" | "check") => one,
        _ => return error::usage(USAGE),
    };
    let root = repository_root();
    let result = generate(&root).and_then(|report| match mode {
        "print" => {
            print!("{report}");
            Ok(())
        }
        "write" => write_report(&root, &report),
        "check" => {
            let file = root.join(OUTPUT);
            let existing = fs::read_to_string(&file).map_err(|source| Error::Io {
                path: file.clone(),
                source,
            })?;
            if existing == report {
                println!("completion: PASS ({OUTPUT} matches the current inputs)");
                Ok(())
            } else {
                Err(Error::Refused(format!(
                    "{OUTPUT} differs from tracked inputs; run completion write"
                )))
            }
        }
        _ => unreachable!(),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => error::report("xtask completion", &problem),
    }
}

fn write_report(root: &Path, report: &str) -> Result<()> {
    let path = root.join(OUTPUT);
    if fs::read_to_string(&path).is_ok_and(|before| before == report) {
        println!("completion: unchanged ({OUTPUT})");
        return Ok(());
    }
    let parent = path.parent().expect("OUTPUT has a parent");
    fs::create_dir_all(parent).map_err(|source| Error::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let temporary = path.with_extension("md.tmp");
    fs::write(&temporary, report).map_err(|source| Error::Io {
        path: temporary.clone(),
        source,
    })?;
    fs::rename(&temporary, &path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    println!("completion: wrote {OUTPUT}");
    Ok(())
}

fn generate(root: &Path) -> Result<String> {
    let raw = git_stdout(root, &["ls-files", "-z", "--cached"])?;
    let mut files = BTreeSet::new();
    for bytes in raw.split(|byte| *byte == 0).filter(|item| !item.is_empty()) {
        let path = std::str::from_utf8(bytes)
            .map_err(|_| Error::Invalid("tracked path is not UTF-8".to_owned()))?;
        validate_path(path)?;
        files.insert(path.to_owned());
    }
    if files.is_empty() {
        return Err(Error::Refused("git index contains no tracked files".to_owned()));
    }
    let tasks = read_tasks(root)?;
    let ordered = order_tasks(&tasks)?;

    let mut tree = Tree::default();
    for path in &files {
        tree.add(path, "[E]".to_owned());
    }
    for task in &tasks {
        let label = if files.contains(&task.path) {
            format!("[E:{}]", task.state)
        } else {
            format!("[P:{}]", task.state)
        };
        tree.add(&task.path, label);
    }

    let sha = String::from_utf8(git_stdout(root, &["rev-parse", "HEAD"])?)
        .map_err(|_| Error::Invalid("commit SHA is not UTF-8".to_owned()))?;
    let mut report = String::new();
    let fence = char::from(96).to_string().repeat(3);
    report.push_str("# Huntsman — adaptive implementation register\n\n");
    report.push_str("GENERATED EVIDENCE INVENTORY — NOT A CLAIM OF IMPLEMENTATION COMPLETENESS.\n\n");
    let _ = writeln!(
        report,
        "Source: local Git index at HEAD {}, generated from {} and tracked paths.",
        sha.trim(),
        TASKS
    );
    let _ = writeln!(
        report,
        "Tracked files: {}. Registered implementation tasks: {}.\n",
        files.len(),
        tasks.len()
    );
    report.push_str("Target: safe Rust 2024, Android AArch64, rootless Termux; CLI, engine, HTTP API and loopback web UI remain compatible.\n\n");
    report.push_str(
        "## Read before acting\n\n\
         1. Read AGENTS.md, Cargo.toml, xtask/src/main.rs, src/lib.rs, the affected files and their callers, tests and configuration.\n\
         2. Treat [E] as present in the Git index, NOT as compiled, reachable, safe or verified. [P] means a registered path absent from the index.\n\
         3. Extra states on a path come from the reviewed task register; REVIEW is a request to inspect, not a defect claim.\n\
         4. No classification can establish an unwired or incompatible module without actual source and test evidence.\n\
         5. Before modifying a path, verify the currently checked-out revision; preserve its public contracts and all unrelated files.\n\
         6. Execute tasks only after their dependencies and preconditions; validate with the existing xtask gate and Android/Web UI acceptance.\n\
         7. Amend docs/completion/tasks.json with observed evidence, status and acceptance tests, then regenerate this register.\n\
         8. Prefer incremental, reversible changes. Do not invent tests, API keys, provider outcomes, performance figures or a successful merge.\n\n",
    );
    report.push_str("## Complete hierarchical Git-index inventory\n\n");
    report.push_str(&fence);
    report.push_str("text\nHuntsman/\n");
    tree.append(&mut report, "");
    report.push_str(&fence);
    report.push_str("\n\n");
    report.push_str("## Dependency-ordered implementation queue\n\n");
    report.push_str(
        "P0 = foundational or critical verification; P1 = integration; P2 = improvement; P3 = optional. \
         Priority breaks ties only among dependency-ready tasks. No task status is inferred from a filename.\n\n",
    );
    for (sequence, index) in ordered.iter().enumerate() {
        let task = &tasks[*index];
        let _ = writeln!(
            report,
            "### {}. P{} — {} [{}]\n",
            sequence + 1,
            task.priority,
            escape_md(&task.id),
            escape_md(&task.state)
        );
        let _ = writeln!(
            report,
            "- File: {} ({})",
            escape_md(&task.path),
            if files.contains(&task.path) {
                "present in Git index"
            } else {
                "not present in Git index; proposal only"
            }
        );
        let _ = writeln!(
            report,
            "- Dependencies: {}",
            if task.dependencies.is_empty() {
                "none".to_owned()
            } else {
                task.dependencies.join(", ")
            }
        );
        let _ = writeln!(report, "- Objective: {}", escape_md(&task.objective));
        let _ = writeln!(report, "- Evidence/uncertainty: {}", escape_md(&task.evidence));
        let _ = writeln!(report, "- Implement: {}", escape_md(&task.implementation));
        let _ = writeln!(report, "- Verify: {}\n", escape_md(&task.verification));
    }
    report.push_str(
        "## Completion and continuity gates\n\n\
         - Every tracked path must remain represented, including non-overlapping files and files not selected for modification.\n\
         - Existing code must not be called unwired, incompatible, broken, obsolete or verified without specific evidence.\n\
         - Each implemented change must name changed paths, affected interface contracts, regressions checked and real command outcomes.\n\
         - Check cargo fmt, the applicable xtask gate, Android aarch64 build and actual handset/web acceptance when access permits.\n\
         - Record unexecuted validation as BLOCKED/UNKNOWN, not PASS; preserve traceability to a commit and test artifact.\n\
         - Re-run completion write on new commits or task revisions. CI also produces a fresh Markdown artifact; no autonomous source edits occur.\n\
         - Completion is reached only when acceptance criteria are demonstrated and no higher-value feasible action remains; no process can guarantee absolute design perfection.\n",
    );
    Ok(report)
}

impl Tree {
    fn add(&mut self, path: &str, label: String) {
        let mut node = self;
        for segment in path.split('/') {
            node = node.children.entry(segment.to_owned()).or_default();
        }
        if let Some(existing) = &mut node.label {
            if existing != &label && label != "[E]" {
                if existing == "[E]" {
                    *existing = label;
                } else {
                    // One file may have independent review tasks. Preserve both states.
                    let new = label.trim_start_matches("[E:").trim_start_matches("[P:").trim_end_matches(']');
                    if !existing.contains(new) {
                        existing.insert_str(existing.len() - 1, &format!(",{new}"));
                    }
                }
            }
        } else {
            node.label = Some(label);
        }
    }

    fn append(&self, output: &mut String, prefix: &str) {
        for (index, (name, child)) in self.children.iter().enumerate() {
            let last = index + 1 == self.children.len();
            let connector = if last { "└── " } else { "├── " };
            let suffix = if child.label.is_some() { "" } else { "/" };
            let label = child.label.as_deref().unwrap_or("");
            let separator = if label.is_empty() { "" } else { " " };
            let _ = writeln!(
                output,
                "{prefix}{connector}{name}{suffix}{separator}{label}"
            );
            let mut next = prefix.to_owned();
            next.push_str(if last { "    " } else { "│   " });
            child.append(output, &next);
        }
    }
}

fn read_tasks(root: &Path) -> Result<Vec<Task>> {
    let path = root.join(TASKS);
    let input = fs::read_to_string(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    let value: Value = serde_json::from_str(&input)
        .map_err(|problem| Error::Invalid(format!("{TASKS}: {problem}")))?;
    if value["schema"] != "huntsman.completion/1" {
        return Err(Error::Invalid(format!("{TASKS}: unknown schema")));
    }
    let list = value["implementations"]
        .as_array()
        .ok_or_else(|| Error::Invalid(format!("{TASKS}: implementations must be an array")))?;
    let mut tasks = Vec::new();
    let mut ids = BTreeSet::new();
    for row in list {
        let id = required(row, "id")?;
        if !ids.insert(id.clone()) {
            return Err(Error::Invalid(format!("duplicate task id: {id}")));
        }
        let path = required(row, "path")?;
        validate_path(&path)?;
        let priority = match required(row, "priority")?.as_str() {
            "P0" => 0,
            "P1" => 1,
            "P2" => 2,
            "P3" => 3,
            bad => return Err(Error::Invalid(format!("{id}: unsupported priority {bad}"))),
        };
        let state = required(row, "state")?;
        if !matches!(
            state.as_str(),
            "REVIEW" | "UNWIRED" | "INCOMPATIBLE" | "INCOMPLETE" |
                "MISSING" | "PROPOSED" | "BLOCKED" | "VERIFIED"
        ) {
            return Err(Error::Invalid(format!("{id}: unsupported state {state}")));
        }
        let depends = row["depends_on"]
            .as_array()
            .ok_or_else(|| Error::Invalid(format!("{id}: depends_on must be an array")))?;
        let mut dependencies = Vec::new();
        for dep in depends {
            let Some(name) = dep.as_str() else {
                return Err(Error::Invalid(format!("{id}: non-string dependency")));
            };
            if dependencies.iter().any(|item| item == name) {
                return Err(Error::Invalid(format!("{id}: duplicate dependency {name}")));
            }
            dependencies.push(name.to_owned());
        }
        tasks.push(Task {
            id,
            path,
            priority,
            state,
            objective: required(row, "objective")?,
            evidence: required(row, "evidence")?,
            implementation: required(row, "implementation")?,
            verification: required(row, "verification")?,
            dependencies,
        });
    }
    Ok(tasks)
}

fn required(row: &Value, name: &str) -> Result<String> {
    let value = row[name]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::Invalid(format!("task: missing or empty {name}")))?;
    if value.contains('\n') || value.contains('\r') {
        return Err(Error::Invalid(format!("task: {name} cannot contain newlines")));
    }
    Ok(value.to_owned())
}

fn validate_path(path: &str) -> Result<()> {
    let valid = !path.is_empty()
        && !path.contains('\n')
        && !path.contains('\r')
        && !path.contains('\\')
        && !Path::new(path).is_absolute()
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)));
    if !valid {
        return Err(Error::Invalid(format!("unsafe repository-relative path: {path:?}")));
    }
    Ok(())
}

fn order_tasks(tasks: &[Task]) -> Result<Vec<usize>> {
    let ids: BTreeSet<&str> = tasks.iter().map(|task| task.id.as_str()).collect();
    for task in tasks {
        for dependency in &task.dependencies {
            if !ids.contains(dependency.as_str()) {
                return Err(Error::Invalid(format!(
                    "{}: unknown dependency {dependency}",
                    task.id
                )));
            }
        }
    }
    let mut done = BTreeSet::new();
    let mut output = Vec::new();
    while done.len() < tasks.len() {
        let next = tasks
            .iter()
            .enumerate()
            .filter(|(_, task)| {
                !done.contains(task.id.as_str())
                    && task
                        .dependencies
                        .iter()
                        .all(|dep| done.contains(dep.as_str()))
            })
            .min_by_key(|(_, task)| (task.priority, task.id.as_str()));
        let Some((index, task)) = next else {
            return Err(Error::Invalid(
                "dependency cycle in completion tasks".to_owned(),
            ));
        };
        done.insert(task.id.as_str());
        output.push(index);
    }
    Ok(output)
}

fn escape_md(value: &str) -> String {
    value.replace('|', "\\|").replace('<', "&lt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependencies_override_simple_priority() {
        let make = |id: &str, priority, dependencies: Vec<&str>| Task {
            id: id.to_owned(),
            path: format!("src/{id}.rs"),
            priority,
            state: "REVIEW".to_owned(),
            objective: "inspect".to_owned(),
            evidence: "not yet checked".to_owned(),
            implementation: "review".to_owned(),
            verification: "test".to_owned(),
            dependencies: dependencies.into_iter().map(str::to_owned).collect(),
        };
        let tasks = vec![
            make("consumer", 0, vec!["foundation"]),
            make("independent", 1, vec![]),
            make("foundation", 2, vec![]),
        ];
        assert_eq!(order_tasks(&tasks).unwrap(), [1, 2, 0]);
    }

    #[test]
    fn unsafe_paths_refused() {
        for path in ["../x", "/etc/passwd", "a\\b", "a\nb", "."] {
            assert!(validate_path(path).is_err(), "{path}");
        }
        assert!(validate_path("src/source_registry.rs").is_ok());
    }

    #[test]
    fn tree_keeps_unrelated_paths_and_correct_connectors() {
        let mut tree = Tree::default();
        tree.add("src/b.rs", "[E]".to_owned());
        tree.add("src/a.rs", "[E:REVIEW]".to_owned());
        tree.add("docs/proposed.md", "[P:PROPOSED]".to_owned());
        let mut out = String::new();
        tree.append(&mut out, "");
        assert!(out.contains("├── docs/\n│   └── proposed.md [P:PROPOSED]"));
        assert!(out.contains("└── src/\n    ├── a.rs [E:REVIEW]\n    └── b.rs [E]"));
    }
}
