//! Read-only implementation handoff. Git objects, not worktree reads, own provenance.
mod queue;
mod wiring;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::error::{self, Error, Result};
use crate::proc::repository_root;

const USAGE: &str = "usage: cargo run --locked -p xtask -- roadmap [markdown|json|check]

Reads the committed docs/implementation/queue.json and complete Git tree at HEAD.
Dirty edits are not inventoried. Outputs a snapshot, never a test/deployment receipt.
No queue command is executed and no source file is changed.";
const MAX_METADATA: usize = 16 * 1024 * 1024;
const MAX_SOURCE: usize = 2 * 1024 * 1024;
const MAX_QUEUE: usize = 1024 * 1024;
const QUEUE_PATH: &str = "docs/implementation/queue.json";

pub(super) struct Entry {
    path: String,
    oid: String,
    bytes: u64,
    kind: &'static str,
}

#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let mode = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["markdown"] => "markdown",
        ["json"] => "json",
        ["check"] => "check",
        ["--help" | "-h"] => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => return error::usage(USAGE),
    };
    match snapshot(&repository_root()) {
        Ok(report) => {
            match mode {
                "json" => println!("{report}"),
                "check" => {
                    println!("roadmap: PASS snapshot and queue structure; verification not run")
                }
                _ => print!("{}", markdown(&report)),
            }
            ExitCode::SUCCESS
        }
        Err(problem) => {
            eprintln!("roadmap: {}", problem.to_string().escape_debug());
            ExitCode::from(if matches!(problem, Error::Invalid(_)) {
                error::EX_USAGE
            } else {
                error::EX_REFUSED
            })
        }
    }
}

fn snapshot(root: &Path) -> Result<Value> {
    // Older Git can silently ignore the no-lazy-fetch environment control.
    let version = git_text(root, &["--version"])?;
    let compatible = version
        .split_whitespace()
        .nth(2)
        .and_then(|v| {
            let mut parts = v.split('.');
            Some((
                parts.next()?.parse::<u32>().ok()?,
                parts.next()?.parse::<u32>().ok()?,
            ))
        })
        .is_some_and(|v| v >= (2, 43));
    if !compatible {
        return Err(Error::Invalid(
            "read-only roadmap requires Git 2.43 or newer".into(),
        ));
    }
    let commit = git_text(root, &["rev-parse", "HEAD"])?;
    let tree = git_text(root, &["rev-parse", &format!("{commit}^{{tree}}")])?;
    let entries = entries(&git(root, &["ls-tree", "-rlz", "--full-tree", &commit])?)?;
    let known: BTreeSet<String> = entries.iter().map(|e| e.path.clone()).collect();
    let mut blobs = Blobs::open(root)?;
    let queue_entry = entries
        .iter()
        .find(|e| e.path == QUEUE_PATH && e.kind == "file")
        .ok_or_else(|| Error::Invalid(format!("{QUEUE_PATH} must be a committed regular file")))?;
    let authored = blobs.read(queue_entry, MAX_QUEUE)?;
    let (tasks, shared) = queue::tasks(&authored, &known)?;
    let completion_register = register(&entries, &mut blobs, &tasks, &known)?;
    let (wiring, limitations) = wiring::scan(&entries, &mut blobs)?;
    let mut identical: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut files = Vec::with_capacity(entries.len());
    for e in &entries {
        if e.kind == "file" {
            identical.entry(&e.oid).or_default().push(&e.path);
        }
        files.push(json!({
            "path": e.path, "object": e.oid, "bytes": e.bytes, "kind": e.kind,
            "state": "committed", "wiring": wiring.get(&e.path).map_or("not_assessed", String::as_str),
            "compatibility": "not_assessed",
        }));
    }
    let duplicates: Vec<Value> = identical
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(oid, paths)| json!({"object": oid, "paths": paths, "action": "review_only"}))
        .collect();
    let clean = git(root, &["status", "--porcelain", "--untracked-files=all"])?.is_empty();
    let observed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Refused(format!("invalid clock: {e}")))?
        .as_secs();
    Ok(json!({
        "schema": "huntsman.implementation-map", "scope": "committed_tree",
        "commit": commit, "tree": tree, "observed_at_unix": observed,
        "working_tree_clean": clean, "verification": "not_run",
        "files": files, "duplicate_groups": duplicates,
        "tasks": tasks, "shared_edit_paths": shared, "limitations": limitations,
        "completion_register": completion_register,
    }))
}

/// Preserve the existing broad register as authored intent. Detailed tasks reference it;
/// the immutable view never creates a competing completion state or omits unmapped work.
fn register(
    entries: &[Entry],
    blobs: &mut Blobs,
    tasks: &[Value],
    known: &BTreeSet<String>,
) -> Result<Value> {
    let path = "docs/completion/tasks.json";
    let input = entries.iter().find(|e| e.path == path && e.kind == "file");
    let Some(input) = input else {
        if tasks.iter().any(|t| t.get("register_tasks").is_some()) {
            return Err(Error::Invalid(
                "register_tasks needs committed docs/completion/tasks.json".into(),
            ));
        }
        return Ok(Value::Null);
    };
    let value: Value = serde_json::from_slice(&blobs.read(input, MAX_QUEUE)?)
        .map_err(|e| Error::Invalid(format!("completion register JSON: {e}")))?;
    if value["schema"] != "huntsman.completion/1" {
        return Err(Error::Invalid(
            "unsupported completion register schema".into(),
        ));
    }
    let rows = value["implementations"]
        .as_array()
        .ok_or_else(|| Error::Invalid("completion register needs implementations array".into()))?;
    let mut definitions = BTreeMap::new();
    for row in rows {
        let id = row["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Invalid("completion register needs nonempty IDs".into()))?;
        for field in ["path", "state", "objective"] {
            if row[field].as_str().is_none_or(|s| s.is_empty()) {
                return Err(Error::Invalid(format!("completion register needs {field}")));
            }
        }
        if !safe_path(row["path"].as_str().unwrap_or_default())
            || definitions.insert(id, row).is_some()
        {
            return Err(Error::Invalid(
                "unsafe path or duplicate ID in completion register".into(),
            ));
        }
    }
    let mut mappings: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    for task in tasks {
        let Some(ids) = task.get("register_tasks") else {
            continue;
        };
        let ids = ids
            .as_array()
            .ok_or_else(|| Error::Invalid("register_tasks needs an array".into()))?;
        let mut seen = BTreeSet::new();
        for id in ids {
            let id = id
                .as_str()
                .ok_or_else(|| Error::Invalid("register_tasks needs text IDs".into()))?;
            if !definitions.contains_key(id) || !seen.insert(id) {
                return Err(Error::Invalid(format!(
                    "unknown or repeated completion task {id:?}"
                )));
            }
            mappings.entry(id).or_default().push(&task["id"]);
        }
    }
    let rows: Vec<Value> = definitions.into_iter().map(|(id, definition)| json!({
        "id": id, "path": definition["path"], "declared_state": definition["state"],
        "path_exists": definition["path"].as_str().is_some_and(|p| known.contains(p)),
        "implementation_tasks": mappings.remove(id).unwrap_or_default(), "definition": definition,
    })).collect();
    Ok(
        json!({"source": path, "scope": "declared_intent_not_verification",
        "mapping_semantics": "partial coverage only; detailed dependencies govern execution, broad prerequisites govern broad task completion",
        "tasks": rows}),
    )
}

fn entries(bytes: &[u8]) -> Result<Vec<Entry>> {
    let mut result = Vec::new();
    let mut paths = BTreeSet::new();
    for raw in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let text = std::str::from_utf8(raw).map_err(|_| {
            Error::Invalid("non-UTF-8 Git path; inventory refused without aliasing paths".into())
        })?;
        let (header, path) = text
            .split_once('\t')
            .ok_or_else(|| Error::Invalid("malformed Git tree entry".into()))?;
        if !safe_path(path) || !paths.insert(path.to_owned()) {
            return Err(Error::Invalid("unsafe or repeated Git tree path".into()));
        }
        let fields: Vec<&str> = header.split_whitespace().collect();
        let [mode, object_type, oid, size] = fields.as_slice() else {
            return Err(Error::Invalid("malformed Git tree metadata".into()));
        };
        let kind = match (*mode, *object_type) {
            ("100644" | "100755", "blob") => "file",
            ("120000", "blob") => "symlink",
            ("160000", "commit") => "submodule",
            _ => return Err(Error::Invalid("unsupported Git tree object".into())),
        };
        let bytes = if kind == "submodule" {
            0
        } else {
            size.parse().map_err(|_| Error::Invalid("missing local Git blob or invalid length; explicitly materialize required objects before read-only generation".into()))?
        };
        result.push(Entry {
            path: path.to_owned(),
            oid: (*oid).to_owned(),
            bytes,
            kind,
        });
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

/// POSIX paths are deliberate: Git paths always use '/', including on Termux.
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.contains('\0')
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    String::from_utf8(git(root, args)?)
        .map(|s| s.trim().to_owned())
        .map_err(|_| Error::Invalid("Git metadata is not UTF-8".into()))
}

/// Bound capture before allocation, and reap the child on every failure path.
fn git_command(root: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("--no-replace-objects")
        .arg("--no-optional-locks")
        .args(["-c", "core.fsmonitor=false"])
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .current_dir(root);
    command
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let shown = format!("git {}", args.join(" "));
    let mut child = git_command(root)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| Error::Command {
            shown: shown.clone(),
            reason: e.to_string(),
        })?;
    let mut bytes = Vec::new();
    let capture = child
        .stdout
        .take()
        .ok_or_else(|| Error::Refused("missing Git stdout".into()))
        .and_then(|out| {
            out.take((MAX_METADATA + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|e| Error::Command {
                    shown: shown.clone(),
                    reason: e.to_string(),
                })
        });
    if capture.is_err() || bytes.len() > MAX_METADATA {
        let _ = child.kill();
        let _ = child.wait();
        capture?;
        return Err(Error::Invalid(
            "Git metadata exceeds the 16 MiB budget".into(),
        ));
    }
    let status = child.wait().map_err(|e| Error::Command {
        shown: shown.clone(),
        reason: e.to_string(),
    })?;
    if !status.success() {
        return Err(Error::Command {
            shown,
            reason: format!("exited with {status}"),
        });
    }
    Ok(bytes)
}

/// Interleave one request and response, avoiding pipe deadlocks and process-per-file costs.
struct Blobs {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<std::process::ChildStdout>,
}

impl Blobs {
    fn open(root: &Path) -> Result<Self> {
        let mut child = git_command(root)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::Command {
                shown: "git cat-file --batch".into(),
                reason: e.to_string(),
            })?;
        let input = child.stdin.take();
        let output = child
            .stdout
            .take()
            .ok_or_else(|| Error::Refused("missing blob stdout".into()))?;
        Ok(Self {
            child,
            input,
            output: BufReader::new(output),
        })
    }

    fn read(&mut self, entry: &Entry, budget: usize) -> Result<Vec<u8>> {
        if entry.kind != "file" || entry.bytes > budget as u64 {
            return Err(Error::Invalid(format!(
                "{} exceeds its {budget}-byte regular-file budget",
                entry.path
            )));
        }
        let io_error = |e: std::io::Error| Error::Command {
            shown: "git cat-file --batch".into(),
            reason: e.to_string(),
        };
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| Error::Refused("blob input closed".into()))?;
        writeln!(input, "{}", entry.oid).map_err(io_error)?;
        input.flush().map_err(io_error)?;
        let mut header = Vec::new();
        (&mut self.output)
            .take(256)
            .read_until(b'\n', &mut header)
            .map_err(io_error)?;
        let expected = format!("{} blob {}\n", entry.oid, entry.bytes);
        if header != expected.as_bytes() {
            return Err(Error::Invalid(format!(
                "{}: inconsistent Git blob metadata",
                entry.path
            )));
        }
        let size = usize::try_from(entry.bytes)
            .map_err(|_| Error::Invalid("blob size exceeds address space".into()))?;
        let mut body = vec![0; size];
        self.output.read_exact(&mut body).map_err(io_error)?;
        let mut newline = [0];
        self.output.read_exact(&mut newline).map_err(io_error)?;
        if newline != *b"\n" {
            return Err(Error::Invalid("malformed blob delimiter".into()));
        }
        Ok(body)
    }
}

impl Drop for Blobs {
    fn drop(&mut self) {
        drop(self.input.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Code spans contain JSON-escaped text: control characters and Markdown cannot add nodes.
fn literal(text: &str) -> String {
    let encoded = json!(text)
        .to_string()
        .replace('`', "\\u0060")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e");
    format!("`{encoded}`")
}

fn markdown(report: &Value) -> String {
    let mut text = String::from("# Huntsman adaptive implementation map\n\n");
    let _ = writeln!(
        text,
        "Commit: {}. Tree: {}. Observed Unix time: {}.\n",
        literal(report["commit"].as_str().unwrap_or_default()),
        literal(report["tree"].as_str().unwrap_or_default()),
        report["observed_at_unix"]
    );
    let _ = writeln!(
        text,
        "Working tree clean: {}. Scope: **committed tree**. Verification: **not run**.\n",
        report["working_tree_clean"]
    );
    text.push_str("Uncommitted files and edits are excluded. Stage and commit a coherent change before refreshing.\n\nRead `docs/implementation/README.md` before implementing. Tasks are proposals; declarations are syntactic hints; compatibility requires the specified tests and platform receipts. Duplicate content is review-only.\n\n## Ordered implementation queue\n\n");
    for task in report["tasks"].as_array().into_iter().flatten() {
        let _ = writeln!(
            text,
            "### {} — {}\n",
            literal(task["id"].as_str().unwrap_or_default()),
            literal(task["title"].as_str().unwrap_or_default())
        );
        let _ = writeln!(
            text,
            "Priority: P{}. Readiness: {}. Dependencies: {}. Verification: not run.\n",
            task["priority"],
            literal(task["readiness"].as_str().unwrap_or_default()),
            task["depends_on"]
        );
        for (field, label) in [
            ("evidence", "Evidence"),
            ("interfaces", "Integration contracts"),
            ("files", "File operations"),
            ("acceptance", "Acceptance commands"),
            ("path_issues", "Path review"),
        ] {
            let Some(rows) = task[field].as_array().filter(|rows| !rows.is_empty()) else {
                continue;
            };
            let _ = writeln!(text, "{label}:\n");
            for row in rows {
                let value = row.as_str().map_or_else(|| row.to_string(), str::to_owned);
                let _ = writeln!(text, "- {}", literal(&value));
            }
            text.push('\n');
        }
        for (field, label) in [
            ("done_when", "Complete only when"),
            ("rollback", "Rollback"),
        ] {
            let _ = writeln!(
                text,
                "{label}: {}.\n",
                literal(task[field].as_str().unwrap_or_default())
            );
        }
    }
    if let Some(rows) = report["completion_register"]["tasks"].as_array() {
        text.push_str("## Existing completion register and task crosswalk\n\nThe broad capability/status authority remains docs/completion/tasks.json. These are authored states, not new verification results. Links represent partial coverage, not task or dependency equivalence. Detailed dependencies govern repair execution; broad prerequisites and full acceptance criteria govern broad task closure. An offline detail passing does not close a broad handset-gated task. Avoid duplicate implementation where coverage overlaps. Unmapped and missing-path intentions remain visible.\n\n");
        for row in rows {
            let _ = writeln!(
                text,
                "### Register {}\n",
                literal(row["id"].as_str().unwrap_or_default())
            );
            let _ = writeln!(
                text,
                "Declared state: {}. Path: {}. Committed path exists: {}. Implementation tasks: {}.\n",
                literal(row["declared_state"].as_str().unwrap_or_default()),
                literal(row["path"].as_str().unwrap_or_default()),
                row["path_exists"],
                literal(&row["implementation_tasks"].to_string())
            );
            let _ = writeln!(
                text,
                "Broad priority: {}. Broad completion prerequisites: {}.\n",
                literal(&row["definition"]["priority"].to_string()),
                literal(&row["definition"]["depends_on"].to_string())
            );
            for field in ["objective", "evidence", "implementation", "verification"] {
                if let Some(value) = row["definition"][field].as_str() {
                    let _ = writeln!(text, "{field}: {}.\n", literal(value));
                }
            }
        }
    }
    text.push_str("## Shared edit paths\n\nSerialise tasks touching these files or reconcile them in isolated branches before integration.\n\n");
    for row in report["shared_edit_paths"].as_array().into_iter().flatten() {
        let _ = writeln!(
            text,
            "- {}: {}",
            literal(row["path"].as_str().unwrap_or_default()),
            literal(&row["tasks"].to_string())
        );
    }
    text.push_str("\n## Complete committed file tree\n\nEach leaf appears once; directory nodes are structural. All compatibility labels are not_assessed.\n\n");
    let mut directories = BTreeSet::new();
    for file in report["files"].as_array().into_iter().flatten() {
        let path = file["path"].as_str().unwrap_or_default();
        let parts: Vec<&str> = path.split('/').collect();
        for depth in 0..parts.len().saturating_sub(1) {
            let directory = parts[..=depth].join("/");
            if directories.insert(directory) {
                let _ = writeln!(text, "{}- {}/", "  ".repeat(depth), literal(parts[depth]));
            }
        }
        let _ = writeln!(
            text,
            "{}- {} — {}; {}; {} bytes",
            "  ".repeat(parts.len().saturating_sub(1)),
            literal(parts.last().copied().unwrap_or_default()),
            file["kind"].as_str().unwrap_or_default(),
            file["wiring"].as_str().unwrap_or_default(),
            file["bytes"]
        );
    }
    text.push_str("\n## Exact duplicate committed blobs\n\nNo deletion is proposed. Directive mirrors, fixtures and licenses can be intentional.\n\n");
    for row in report["duplicate_groups"].as_array().into_iter().flatten() {
        let _ = writeln!(
            text,
            "- {}: {}",
            literal(row["object"].as_str().unwrap_or_default()),
            literal(&row["paths"].to_string())
        );
    }
    text.push_str("\n## Uncertainty and scope\n\n");
    for row in report["limitations"].as_array().into_iter().flatten() {
        let _ = writeln!(text, "- {}", literal(row.as_str().unwrap_or_default()));
    }
    text
}
