//! Validate authored intent; never execute commands or infer completed work.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::error::{Error, Result};

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|s| !s.trim().is_empty() && s.len() <= 16_384)
        .ok_or_else(|| {
            invalid(format!(
                "queue field {key} needs nonempty text, at most 16 KiB"
            ))
        })
}

fn strings<'a>(value: &'a Value, key: &str, allow_empty: bool) -> Result<Vec<&'a str>> {
    let rows = value[key]
        .as_array()
        .filter(|rows| allow_empty || !rows.is_empty())
        .ok_or_else(|| invalid(format!("queue field {key} needs an array")))?;
    let mut result = Vec::new();
    for row in rows {
        result.push(
            row.as_str()
                .filter(|s| !s.trim().is_empty() && s.len() <= 16_384)
                .ok_or_else(|| invalid(format!("queue field {key} contains invalid text")))?,
        );
    }
    Ok(result)
}

pub(super) fn tasks(bytes: &[u8], known: &BTreeSet<String>) -> Result<(Vec<Value>, Vec<Value>)> {
    let authored: Value =
        serde_json::from_slice(bytes).map_err(|e| invalid(format!("queue JSON: {e}")))?;
    if authored["schema"] != "huntsman.implementation-queue" {
        return Err(invalid("unsupported implementation queue schema"));
    }
    let rows = authored["tasks"]
        .as_array()
        .ok_or_else(|| invalid("queue needs tasks array"))?;
    let mut pending = BTreeMap::new();
    let mut shared: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        let id = text(row, "id")?;
        if id.len() > 80
            || !id.starts_with(|c: char| c.is_ascii_lowercase())
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(invalid(format!("invalid task identifier {id:?}")));
        }
        if row["priority"].as_u64().is_none_or(|p| p > 3) {
            return Err(invalid(format!("{id}: priority must be 0..3")));
        }
        for field in ["title", "done_when", "rollback"] {
            text(row, field)?;
        }
        for field in ["evidence", "interfaces", "acceptance"] {
            strings(row, field, false)?;
        }
        let dependencies = strings(row, "depends_on", true)?;
        if dependencies.iter().copied().collect::<BTreeSet<_>>().len() != dependencies.len() {
            return Err(invalid(format!("{id}: repeated dependency")));
        }
        let files = row["files"]
            .as_array()
            .filter(|rows| !rows.is_empty())
            .ok_or_else(|| invalid(format!("{id}: files array is empty")))?;
        let mut touched = BTreeSet::new();
        let mut issues = Vec::new();
        for file in files {
            let path = text(file, "path")?;
            let action = text(file, "action")?;
            if !super::safe_path(path) || !touched.insert(path) {
                return Err(invalid(format!(
                    "{id}: unsafe or repeated task path {path:?}"
                )));
            }
            let exists = known.contains(path);
            match action {
                "modify" | "inspect" if !exists => {
                    issues.push(format!("missing {action} target: {path}"))
                }
                "create" if exists => issues.push(format!("create target already exists: {path}")),
                "modify" | "inspect" | "create" => {}
                _ => return Err(invalid(format!("{id}: unknown file action {action:?}"))),
            }
            if action != "inspect" {
                shared
                    .entry(path.to_owned())
                    .or_default()
                    .push(id.to_owned());
            }
        }
        let mut task = row.clone();
        task["verification"] = "not_run".into();
        task["path_issues"] = json!(issues);
        task["readiness"] = if !issues.is_empty() {
            "needs_path_review"
        } else if dependencies.is_empty() {
            "ready_for_execution"
        } else {
            "awaits_dependencies"
        }
        .into();
        if pending.insert(id.to_owned(), task).is_some() {
            return Err(invalid(format!("duplicate task ID: {id}")));
        }
    }
    for (id, task) in &pending {
        for dependency in strings(task, "depends_on", true)? {
            if !pending.contains_key(dependency) {
                return Err(invalid(format!("{id}: unknown dependency {dependency}")));
            }
        }
    }
    let mut ordered = Vec::new();
    let mut seen = BTreeSet::new();
    while !pending.is_empty() {
        let next = pending
            .iter()
            .filter(|(_, t)| {
                t["depends_on"].as_array().is_some_and(|ds| {
                    ds.iter()
                        .all(|d| d.as_str().is_some_and(|id| seen.contains(id)))
                })
            })
            .min_by_key(|(id, t)| (t["priority"].as_u64(), (*id).clone()))
            .map(|(id, _)| id.clone())
            .ok_or_else(|| invalid("implementation queue dependency cycle"))?;
        let mut task = pending
            .remove(&next)
            .ok_or_else(|| invalid("queue changed during ordering"))?;
        task["execution_order"] = (ordered.len() + 1).into();
        ordered.push(task);
        seen.insert(next);
    }
    let shared = shared
        .into_iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|(path, ids)| json!({"path": path, "tasks": ids, "policy": "serialise_or_reconcile"}))
        .collect();
    Ok((ordered, shared))
}
