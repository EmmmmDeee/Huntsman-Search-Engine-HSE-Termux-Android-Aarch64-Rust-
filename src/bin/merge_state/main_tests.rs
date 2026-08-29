use super::*;
use serde_json::json;

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        other => panic!("expected object, got {other}"),
    }
}

/// Golden value captured directly from the original Python `corroboration()`
/// (`python3 -c 'import .agent.merge_state as m; print(m.corroboration("test-branch"))'`)
/// — pins the exact wording, since this text is written verbatim into the
/// persisted `.agent/state.json`.
#[test]
fn corroboration_matches_python_golden_value() {
    let expected = "Reached independently by the session on test-branch, which measured the \
inline tests those 8 modules already carried: bluesky_user 15, codeberg_user 9, devto 7, \
gitlab_user 8, lobsters 8, mastodon_user 8, stackoverflow_user 11, url_extract 5 — 71 tests, \
not zero. Two detectors, same artefact, same conclusion. Note the layout count is three, not \
two: include!(\"tests.rs\") 191 files, `mod tests;` 107, tests inline in mod.rs ~129 — and \
every_src_file_is_wired_into_the_module_tree accepts all of them.";
    assert_eq!(corroboration("test-branch"), expected);
}

/// End-to-end scenario mirroring a real conflict: a duplicate shared
/// rejection gets annotated, a same-branch rejection is carried and a
/// different-branch one is not, a "PA-"-prefixed defect is carried and both
/// a wrong-prefix and an already-present-id defect are not, the old
/// CONCURRENCY note is replaced (not duplicated), and unrelated keys from
/// `ours` (`incidents`, `concurrent_session_runs`) are carried verbatim.
#[test]
fn merge_matches_real_conflict_shape() {
    let branch = "claude/huntsman-price-analysis-ewy20t";
    let theirs = obj(json!({
        "$comment": [
            "top-level notes.",
            "",
            "CONCURRENCY: stale note from a previous resolution",
            "second line of the stale note"
        ],
        "cycle_count": 12,
        "rejected_candidates": [
            {"candidate": "Add test coverage to the 8 src/modules/* directories with no tests.rs",
             "reason": "not a gap", "cycle": 1},
            {"candidate": "Switch DbWriter to a bounded channel",
             "reason": "deliberate", "cycle": 3, "source_branch": "claude/some-other-branch"}
        ],
        "open_defects": [
            {"id": "OD-1", "summary": "unbounded channel", "status": "OPEN"}
        ]
    }));
    let ours = obj(json!({
        "rejected_candidates": [
            {"candidate": "Add test coverage to the 8 src/modules/* directories with no tests.rs",
             "reason": "found independently", "cycle": 1, "source_branch": branch},
            {"candidate": "New rejection from this branch",
             "reason": "some reason", "cycle": 9, "source_branch": branch},
            {"candidate": "Rejection from a different branch, must not be carried",
             "reason": "some reason", "cycle": 9, "source_branch": "claude/unrelated-branch"}
        ],
        "open_defects": [
            {"id": "PA-1", "summary": "new defect", "status": "OPEN"},
            {"id": "OD-1", "summary": "duplicate id, must not be re-added", "status": "OPEN"},
            {"id": "XX-9", "summary": "wrong prefix, must not be carried", "status": "OPEN"}
        ],
        "concurrent_session_runs": [{"branch": branch, "cycles": 9}],
        "incidents": [{"what": "a scheduler hiccup", "cycle": 4}]
    }));

    let merged = merge(&ours, theirs, branch).unwrap();

    // Old CONCURRENCY note fully replaced, not duplicated or appended-to.
    // comment[1] is the fresh CONCURRENCY_NOTE's own leading blank separator
    // line, not the stale note's blank line (which was truncated away).
    let comment = merged["$comment"].as_array().unwrap();
    assert_eq!(comment[0], "top-level notes.");
    assert_eq!(comment[1], "");
    assert_eq!(
        comment[2],
        "CONCURRENCY: two automated sessions ran this loop at the same time on"
    );
    assert!(
        !comment
            .iter()
            .any(|c| c.as_str() == Some("second line of the stale note"))
    );
    assert_eq!(
        comment
            .iter()
            .filter(|c| c.as_str().unwrap_or_default().contains("CONCURRENCY:"))
            .count(),
        1
    );

    // main's own field untouched.
    assert_eq!(merged["cycle_count"], 12);

    // Shared rejection annotated with fresh corroboration, regardless of `ours`.
    let rejected = merged["rejected_candidates"].as_array().unwrap();
    let shared = rejected
        .iter()
        .find(|c| {
            c["candidate"]
                == "Add test coverage to the 8 src/modules/* directories with no tests.rs"
        })
        .unwrap();
    assert_eq!(shared["corroboration"], corroboration(branch));

    // Exactly the same-branch new rejection was carried; the other-branch one was not.
    assert!(
        rejected
            .iter()
            .any(|c| c["candidate"] == "New rejection from this branch")
    );
    assert!(
        !rejected
            .iter()
            .any(|c| c["candidate"] == "Rejection from a different branch, must not be carried")
    );
    // main's own pre-existing, unrelated rejection survives untouched.
    assert!(
        rejected
            .iter()
            .any(|c| c["candidate"] == "Switch DbWriter to a bounded channel")
    );
    assert_eq!(rejected.len(), 3);

    // Defects: PA- prefix carried, duplicate id and wrong prefix both excluded.
    let defects = merged["open_defects"].as_array().unwrap();
    let ids: Vec<&str> = defects.iter().map(|d| d["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["OD-1", "PA-1"]);

    // Keys main doesn't use, carried verbatim from `ours`.
    assert_eq!(
        merged["incidents"],
        json!([{"what": "a scheduler hiccup", "cycle": 4}])
    );
    assert_eq!(
        merged["concurrent_session_runs"],
        json!([{"branch": branch, "cycles": 9}])
    );
}

/// No pre-existing CONCURRENCY marker: the note is simply appended once,
/// nothing truncated.
#[test]
fn merge_appends_note_when_no_marker_present() {
    let branch = "some-branch";
    let theirs = obj(json!({"$comment": ["plain note, no marker"]}));
    let ours = obj(json!({}));
    let merged = merge(&ours, theirs, branch).unwrap();
    let comment = merged["$comment"].as_array().unwrap();
    assert_eq!(comment[0], "plain note, no marker");
    assert_eq!(comment[1], "");
    assert_eq!(
        comment[2],
        "CONCURRENCY: two automated sessions ran this loop at the same time on"
    );
}

/// Re-running merge on its own prior output must not duplicate a rejection
/// or defect that was already carried over — the idempotency the tool's
/// docs promise for a repeated invocation.
#[test]
fn merge_is_idempotent_across_two_runs() {
    let branch = "claude/huntsman-price-analysis-ewy20t";
    let theirs = obj(json!({"rejected_candidates": [], "open_defects": []}));
    let ours = obj(json!({
        "rejected_candidates": [
            {"candidate": "X", "reason": "r", "source_branch": branch}
        ],
        "open_defects": [
            {"id": "PA-1", "summary": "s", "status": "OPEN"}
        ]
    }));
    let once = merge(&ours, theirs, branch).unwrap();
    let twice = merge(&ours, obj(once.clone()), branch).unwrap();
    assert_eq!(once, twice);
    assert_eq!(twice["rejected_candidates"].as_array().unwrap().len(), 1);
    assert_eq!(twice["open_defects"].as_array().unwrap().len(), 1);
}

/// Mirrors the original script's implicit assumption that main's state
/// already has a `rejected_candidates` array before appending to it — surfaced
/// as a clear error instead of Python's `KeyError` traceback.
#[test]
fn merge_errors_when_theirs_has_no_rejected_candidates_array_to_append_to() {
    let branch = "b";
    let theirs = obj(json!({})); // no `rejected_candidates` key at all
    let ours = obj(json!({
        "rejected_candidates": [{"candidate": "X", "source_branch": branch}]
    }));
    let err = merge(&ours, theirs, branch).unwrap_err();
    assert!(err.contains("rejected_candidates"), "got: {err}");
}

/// An entry missing the required `id`/`candidate` field is a clear error,
/// not a silent skip — mirrors Python's `KeyError` on direct indexing.
#[test]
fn merge_errors_on_malformed_defect_entry() {
    let branch = "b";
    let theirs = obj(json!({"open_defects": []}));
    let ours = obj(json!({"open_defects": [{"summary": "no id field"}]}));
    let err = merge(&ours, theirs, branch).unwrap_err();
    assert!(err.contains("\"id\""), "got: {err}");
}
