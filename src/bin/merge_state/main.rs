//! `merge-state` — resolve an `.agent/state.json` merge conflict between two
//! concurrent loop sessions.
//!
//! Two automated sessions run the five-slot loop on separate branches and
//! both write this file, so it conflicts on essentially every merge from
//! main. The resolution is always the same shape, so it is scripted rather
//! than redone by hand each time — a hand-merge of a large JSON file is
//! exactly where a record silently loses an entry.
//!
//! main's copy is the canonical record and always wins on the keys it owns:
//! it advances the cycle counter, the slot lists and the shared
//! defect/rejection registers. This branch's contributions are re-applied on
//! top, under keys main does not use, so neither side is overwritten and the
//! provenance stays explicit.
//!
//! Usage, mid-conflict:
//!
//! ```text
//! git show :2:.agent/state.json > /tmp/ours.json     # this branch
//! git show :3:.agent/state.json > /tmp/theirs.json   # origin/main
//! cargo run --bin merge-state -- /tmp/ours.json /tmp/theirs.json [BRANCH]
//! git add .agent/state.json
//! ```
//!
//! BRANCH defaults to the branch this helper shipped on; pass it explicitly
//! when a different session reuses the resolver so the provenance keys match
//! its work.
//!
//! Note on JSON key ordering: unlike the original Python (which loaded with
//! `object_pairs_hook=OrderedDict` and so preserved main's key order
//! byte-for-byte), this port uses `serde_json`'s default `Map` and emits
//! object keys in a fixed (not necessarily original) order. That's a
//! deliberate, scoped trade-off — enabling `serde_json`'s `preserve_order`
//! feature would change `serde_json::Value`'s iteration order project-wide,
//! for a benefit (matching historical key order in a rarely-hand-read state
//! file) that has no functional effect on any consumer of this file.

use std::collections::HashSet;
use std::path::Path;
use std::process::ExitCode;

use serde_json::{Map, Value};

/// The branch this helper originally shipped on; used as the default when
/// the caller does not name one. Overridable as the optional third CLI
/// argument so a different concurrent session can reuse the resolver without
/// editing the binary.
const DEFAULT_BRANCH: &str = "claude/huntsman-price-analysis-ewy20t";

const USAGE: &str = "usage: merge-state OURS.json THEIRS.json [BRANCH]";

/// Appended to `$comment` on every run (after dropping any previous copy —
/// see [`merge`]), so re-running is idempotent instead of appending a
/// duplicate note each time.
const CONCURRENCY_NOTE: &[&str] = &[
    "",
    "CONCURRENCY: two automated sessions ran this loop at the same time on",
    "separate branches and both wrote this file, with different schemas and",
    "overlapping slot numbers. They are merged as a union, not reconciled into",
    "one sequence — the cycle_N_slots lists are the other session's run, and",
    "`concurrent_session_runs` is this branch's. A future cycle should pick ONE",
    "shape before adding to either, or every merge from main will conflict here.",
    "The resolution is scripted: src/bin/merge_state/main.rs (cargo run --bin merge-state).",
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    }
    let branch = args.get(3).map_or(DEFAULT_BRANCH, String::as_str);
    match run(Path::new(&args[1]), Path::new(&args[2]), branch) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("merge-state: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(ours_path: &Path, theirs_path: &Path, branch: &str) -> Result<(), String> {
    let ours = load_object(ours_path)?;
    let theirs = load_object(theirs_path)?;
    let merged = merge(&ours, theirs, branch)?;

    let mut text = serde_json::to_string_pretty(&merged)
        .map_err(|e| format!("serialising merged state: {e}"))?;
    text.push('\n');
    std::fs::write(".agent/state.json", &text)
        .map_err(|e| format!("writing .agent/state.json: {e}"))?;

    println!("cycle_count: {}", field_display(&merged, "cycle_count"));
    println!(
        "rejected_candidates: {}",
        array_len(&merged, "rejected_candidates")
    );
    println!("open_defects: {}", defect_ids_repr(&merged, "open_defects"));
    println!("incidents: {}", array_len(&merged, "incidents"));
    println!(
        "concurrent_session_runs: {}",
        array_len(&merged, "concurrent_session_runs")
    );
    Ok(())
}

fn load_object(path: &Path) -> Result<Map<String, Value>, String> {
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|e| format!("parsing {}: {e}", path.display()))?;
    match value {
        Value::Object(map) => Ok(map),
        other => Err(format!(
            "{}: expected a JSON object at the top level, found {other}",
            path.display()
        )),
    }
}

/// main's copy (`theirs`) is the base; re-apply this branch's (`ours`)
/// additions on top of it.
fn merge(
    ours: &Map<String, Value>,
    mut theirs: Map<String, Value>,
    branch: &str,
) -> Result<Value, String> {
    // Drop any previously appended note in full — it runs from its marker
    // line to the end of the list, so matching only the marker would leave
    // the tail behind and each re-run would append a duplicate.
    let mut base_comment = string_array(&theirs, "$comment")?;
    let marker = base_comment
        .iter()
        .position(|c| c.contains("CONCURRENCY:"))
        .unwrap_or(base_comment.len());
    base_comment.truncate(marker);
    while base_comment.last().is_some_and(|s| s.trim().is_empty()) {
        base_comment.pop();
    }
    base_comment.extend(CONCURRENCY_NOTE.iter().map(|s| (*s).to_string()));
    theirs.insert(
        "$comment".to_string(),
        Value::Array(base_comment.into_iter().map(Value::String).collect()),
    );

    // Keys main does not use: carried across verbatim from this branch.
    for key in ["concurrent_session_runs", "incidents"] {
        if let Some(v) = ours.get(key) {
            theirs.insert(key.to_string(), v.clone());
        }
    }

    // Annotate the shared rejection both sessions reached independently.
    if let Some(rejected) = theirs.get_mut("rejected_candidates") {
        let arr = rejected
            .as_array_mut()
            .ok_or_else(|| "`rejected_candidates` is not an array".to_string())?;
        for c in arr.iter_mut() {
            let is_shared_rejection =
                candidate_of(c, "rejected_candidates")?.starts_with("Add test coverage to the 8");
            if is_shared_rejection {
                c.as_object_mut()
                    .expect("candidate_of succeeded above, so c is a JSON object")
                    .insert(
                        "corroboration".to_string(),
                        Value::String(corroboration(branch)),
                    );
            }
        }
    }

    // This branch's rejections, keyed so re-running is idempotent.
    let seen: HashSet<String> = theirs
        .get("rejected_candidates")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("candidate").and_then(Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if let Some(ours_rejected) = ours.get("rejected_candidates").and_then(Value::as_array) {
        for c in ours_rejected {
            let candidate = candidate_of(c, "rejected_candidates (ours)")?;
            let source_branch = c.get("source_branch").and_then(Value::as_str);
            if source_branch == Some(branch) && !seen.contains(candidate) {
                theirs
                    .get_mut("rejected_candidates")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| {
                        "main's state.json has no `rejected_candidates` array to append to"
                            .to_string()
                    })?
                    .push(c.clone());
            }
        }
    }

    // This branch's defects, keyed the same way. Deliberately no
    // `source_branch` check here (unlike rejections above) — only the "PA-"
    // id prefix gates inclusion, matching the original script exactly.
    let ids: HashSet<String> = theirs
        .get("open_defects")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|d| d.get("id").and_then(Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if let Some(ours_defects) = ours.get("open_defects").and_then(Value::as_array) {
        for d in ours_defects {
            let id = id_of(d, "open_defects (ours)")?;
            if id.starts_with("PA-") && !ids.contains(id) {
                theirs
                    .get_mut("open_defects")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| {
                        "main's state.json has no `open_defects` array to append to".to_string()
                    })?
                    .push(d.clone());
            }
        }
    }

    Ok(Value::Object(theirs))
}

/// The shared-rejection annotation, tagged with the resolving branch.
fn corroboration(branch: &str) -> String {
    format!(
        "Reached independently by the session on {branch}, which measured the inline tests those 8 modules already carried: bluesky_user 15, codeberg_user 9, devto 7, gitlab_user 8, lobsters 8, mastodon_user 8, stackoverflow_user 11, url_extract 5 — 71 tests, not zero. Two detectors, same artefact, same conclusion. Note the layout count is three, not two: include!(\"tests.rs\") 191 files, `mod tests;` 107, tests inline in mod.rs ~129 — and every_src_file_is_wired_into_the_module_tree accepts all of them."
    )
}

/// `obj[key]` as a `Vec<String>`, defaulting to empty when the key is
/// absent — mirrors Python's `out.get(key, [])` read side.
fn string_array(obj: &Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    match obj.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("`{key}` entry is not a string: {v}"))
            })
            .collect(),
        Some(other) => Err(format!("`{key}` is not an array: {other}")),
    }
}

/// `entry["candidate"]` as a string, or a clear error — mirrors Python's
/// direct `c["candidate"]` indexing, which raises if the entry isn't an
/// object with a string `candidate` field.
fn candidate_of<'a>(entry: &'a Value, list_name: &str) -> Result<&'a str, String> {
    entry
        .get("candidate")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!("an entry in `{list_name}` has no string \"candidate\" field: {entry}")
        })
}

/// `entry["id"]` as a string, or a clear error — mirrors Python's direct
/// `d["id"]` indexing.
fn id_of<'a>(entry: &'a Value, list_name: &str) -> Result<&'a str, String> {
    entry
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("an entry in `{list_name}` has no string \"id\" field: {entry}"))
}

/// Renders like Python's `str()` on the same JSON-decoded value, for the
/// summary lines printed at the end of a run: `None` for missing/null, a
/// string unquoted, a bool capitalised, anything else via its JSON text.
fn field_display(obj: &Value, key: &str) -> String {
    match obj.get(key) {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => (if *b { "True" } else { "False" }).to_string(),
        Some(other) => other.to_string(),
    }
}

fn array_len(obj: &Value, key: &str) -> usize {
    obj.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

/// Renders like Python's `print(..., [d["id"] for d in ...])` — a Python
/// list-repr of the ids, e.g. `['OD-1', 'OD-2']`.
fn defect_ids_repr(obj: &Value, key: &str) -> String {
    let ids: Vec<String> = obj
        .get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|d| format!("'{}'", d.get("id").and_then(Value::as_str).unwrap_or("?")))
                .collect()
        })
        .unwrap_or_default();
    format!("[{}]", ids.join(", "))
}

#[cfg(test)]
mod tests {
    include!("main_tests.rs");
}
