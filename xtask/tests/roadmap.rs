//! Real Git fixtures protect immutable provenance, complete inventory and safe planning.
mod common;

use common::Repo;
use serde_json::{Value, json};
use std::process::{Command, Output};

fn task(id: &str, priority: u8, dependencies: &[&str]) -> Value {
    json!({
        "id": id, "priority": priority, "title": format!("Implement {id}"),
        "depends_on": dependencies,
        "evidence": ["Fixture evidence, not a production defect"],
        "interfaces": ["Preserve the public interface"],
        "files": [{"path": "src/lib.rs", "action": "modify"}],
        "acceptance": ["cargo test --locked"],
        "done_when": "A successful exact-revision test receipt exists",
        "rollback": "Revert only this change; preserve operator state"
    })
}

fn queue(tasks: Vec<Value>) -> String {
    json!({"schema": "huntsman.implementation-queue", "tasks": tasks}).to_string()
}

fn fixture(extra: &[(&str, &str)]) -> Repo {
    let repo = Repo::with_files("roadmap", extra);
    repo.write(
        "docs/implementation/queue.json",
        &queue(vec![task("first", 1, &[])]),
    );
    repo.git(&["add", "docs/implementation/queue.json"]);
    repo.git(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "commit",
        "-qm",
        "queue",
    ]);
    repo
}

fn run(repo: &Repo, mode: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["roadmap", mode])
        .current_dir(repo.root())
        .env("CARGO_MANIFEST_DIR", repo.root().join("xtask"))
        .output()
        .expect("xtask runs")
}

fn report(repo: &Repo) -> Value {
    let out = run(repo, "json");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("JSON report")
}

fn file<'a>(report: &'a Value, path: &str) -> &'a Value {
    report["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == path)
        .expect("file in inventory")
}

#[test]
fn inventories_every_committed_path_once_and_does_not_invent_verification() {
    let repo = fixture(&[
        ("asset.bin", "binary\0asset"),
        ("duplicate.txt", "same"),
        ("other.txt", "same"),
    ]);
    let value = report(&repo);
    let count = repo
        .git(&["ls-tree", "-rz", "HEAD"])
        .stdout
        .iter()
        .filter(|b| **b == 0)
        .count();
    let files = value["files"].as_array().unwrap();
    assert_eq!(files.len(), count);
    let paths: std::collections::BTreeSet<_> =
        files.iter().map(|r| r["path"].as_str().unwrap()).collect();
    assert_eq!(paths.len(), count);
    assert_eq!(value["commit"], repo.rev("HEAD"));
    assert_eq!(value["verification"], "not_run");
    assert_eq!(value["scope"], "committed_tree");
    assert!(
        value["duplicate_groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["paths"] == json!(["duplicate.txt", "other.txt"]))
    );
    assert_eq!(file(&value, "asset.bin")["bytes"], 12);
}

#[test]
fn dirty_files_do_not_change_the_committed_snapshot_or_expose_their_contents() {
    let repo = fixture(&[]);
    repo.write("src/lib.rs", "a secret uncommitted value");
    repo.write("new-untracked-file", "another secret");
    let value = report(&repo);
    assert_eq!(value["working_tree_clean"], false);
    assert_eq!(file(&value, "src/lib.rs")["bytes"], 14);
    assert!(!value.to_string().contains("secret"));
    assert!(
        !value["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["path"] == "new-untracked-file")
    );
}

#[test]
fn resolves_literal_inclusions_but_never_treats_a_comment_as_wiring() {
    let repo = fixture(&[
        (
            "src/lib.rs",
            "mod wired;\nmod inline { mod child; }\n#[path=\"odd/place.rs\"] mod odd;\ninclude!(\"extra.rs\");\n// mod orphan;\n",
        ),
        ("src/wired.rs", "pub fn x() {}"),
        ("src/inline/child.rs", "pub fn y() {}"),
        ("src/odd/place.rs", "pub fn z() {}"),
        ("src/extra.rs", "pub fn e() {}"),
        ("src/orphan.rs", "pub fn o() {}"),
    ]);
    let value = report(&repo);
    for path in [
        "src/wired.rs",
        "src/inline/child.rs",
        "src/odd/place.rs",
        "src/extra.rs",
    ] {
        assert_eq!(file(&value, path)["wiring"], "declared_reachable", "{path}");
    }
    assert_eq!(
        file(&value, "src/orphan.rs")["wiring"],
        "unlinked_candidate"
    );
    assert_eq!(
        file(&value, "src/orphan.rs")["compatibility"],
        "not_assessed"
    );
}

#[test]
fn unsupported_macros_are_explicit_uncertainty_and_not_dead_code_proof() {
    let repo = fixture(&[
        ("src/lib.rs", "include!(concat!(\"part\", \"s.rs\"));"),
        ("src/parts.rs", "pub fn p() {}"),
    ]);
    let value = report(&repo);
    assert!(
        value["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains("src/lib.rs"))
    );
    assert_eq!(file(&value, "src/parts.rs")["wiring"], "unlinked_candidate");
}

#[test]
fn orders_dependencies_before_priority_and_exposes_shared_edits() {
    let mut repo = fixture(&[]);
    repo.write(
        "docs/implementation/queue.json",
        &queue(vec![
            task("dependent", 0, &["base"]),
            task("base", 3, &[]),
            task("independent", 1, &[]),
        ]),
    );
    repo.commit_all("ordered tasks");
    let value = report(&repo);
    let order: Vec<_> = value["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert_eq!(order, ["independent", "base", "dependent"]);
    assert_eq!(value["shared_edit_paths"][0]["path"], "src/lib.rs");
    assert_eq!(value["tasks"][2]["readiness"], "awaits_dependencies");
}

#[test]
fn flags_missing_and_already_created_paths_without_silently_retargeting() {
    let mut repo = fixture(&[]);
    let mut t = task("drift", 1, &[]);
    t["files"] = json!([{"path":"src/gone.rs", "action":"modify"}, {"path":"src/lib.rs", "action":"create"}]);
    repo.write("docs/implementation/queue.json", &queue(vec![t]));
    repo.commit_all("path drift");
    let value = report(&repo);
    assert_eq!(value["tasks"][0]["readiness"], "needs_path_review");
    assert_eq!(
        value["tasks"][0]["path_issues"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn refuses_duplicate_ids_cycles_dangling_dependencies_and_unsafe_paths() {
    let mut repo = fixture(&[]);
    let mut unsafe_task = task("unsafe", 1, &[]);
    unsafe_task["files"][0]["path"] = "../outside".into();
    for tasks in [
        vec![task("same", 1, &[]), task("same", 2, &[])],
        vec![task("a", 1, &["b"]), task("b", 1, &["a"])],
        vec![task("a", 1, &["missing"])],
        vec![unsafe_task],
    ] {
        repo.write("docs/implementation/queue.json", &queue(tasks));
        repo.commit_all("invalid plan");
        let out = run(&repo, "check");
        assert_eq!(out.status.code(), Some(64), "{out:?}");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn renders_control_characters_safely_and_never_follows_a_symlink() {
    let mut repo = fixture(&[("odd\nname\tfile", "payload")]);
    repo.symlink("/definitely-outside/a-secret", "src/link.rs");
    repo.commit_all("symlink");
    let value = report(&repo);
    assert_eq!(file(&value, "src/link.rs")["kind"], "symlink");
    let out = run(&repo, "markdown");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("odd\\nname\\tfile"));
    assert!(!text.contains("/definitely-outside"));
    assert!(!text.contains("odd\nname\tfile"));
}

#[test]
fn generation_is_read_only_even_when_acceptance_contains_a_shell_command() {
    let mut repo = fixture(&[]);
    let mut t = task("do-not-execute", 1, &[]);
    t["acceptance"] = json!(["touch forbidden-side-effect"]);
    repo.write("docs/implementation/queue.json", &queue(vec![t]));
    repo.commit_all("instruction text");
    let before = repo
        .git(&["status", "--porcelain", "--untracked-files=all"])
        .stdout;
    assert!(run(&repo, "check").status.success());
    assert!(run(&repo, "markdown").status.success());
    assert_eq!(
        repo.git(&["status", "--porcelain", "--untracked-files=all"])
            .stdout,
        before
    );
    assert!(!repo.root().join("forbidden-side-effect").exists());
}

#[test]
fn replacement_objects_cannot_change_the_recorded_commit_contents() {
    let mut repo = fixture(&[]);
    let original = repo.rev("HEAD");
    let original_tree = repo.rev("HEAD^{tree}");
    repo.write("replacement-only", "not present in the original commit");
    repo.commit_all("replacement");
    let replacement = repo.rev("HEAD");
    repo.git(&["reset", "--hard", &original]);
    repo.git(&["replace", &original, &replacement]);
    let value = report(&repo);
    assert_eq!(value["commit"], original);
    assert_eq!(value["tree"], original_tree);
    assert!(
        !value["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["path"] == "replacement-only")
    );
}

#[test]
fn a_git_fsmonitor_hook_is_not_executed_during_read_only_generation() {
    use std::os::unix::fs::PermissionsExt;
    let mut repo = fixture(&[]);
    repo.write(
        "monitor.sh",
        "#!/bin/sh\nprintf executed > forbidden-monitor-effect\nprintf 'token\\0'\n",
    );
    std::fs::set_permissions(
        repo.root().join("monitor.sh"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    repo.commit_all("monitor fixture");
    repo.git(&[
        "config",
        "core.fsmonitor",
        repo.root().join("monitor.sh").to_str().unwrap(),
    ]);
    assert!(run(&repo, "check").status.success());
    assert!(!repo.root().join("forbidden-monitor-effect").exists());
}

#[test]
fn module_context_survives_path_attributes_and_literal_code_inclusion() {
    let repo = fixture(&[
        (
            "src/lib.rs",
            "#[path=\"odd/place.rs\"] mod other;\ninclude!(\"parts.rs\");\n#[path=\"../shared.rs\"] mod shared;",
        ),
        ("src/odd/place.rs", "mod child;"),
        ("src/odd/child.rs", "pub fn correct() {}"),
        ("src/odd/place/child.rs", "pub fn wrong_context() {}"),
        ("src/parts.rs", "mod child;"),
        ("src/child.rs", "pub fn correct() {}"),
        ("src/parts/child.rs", "pub fn wrong_context() {}"),
        ("shared.rs", "#[path=\"src/shared_child.rs\"] mod child;"),
        ("src/shared_child.rs", "pub fn correct() {}"),
    ]);
    let value = report(&repo);
    for path in ["src/odd/child.rs", "src/child.rs", "src/shared_child.rs"] {
        assert_eq!(file(&value, path)["wiring"], "declared_reachable", "{path}");
    }
    for path in ["src/odd/place/child.rs", "src/parts/child.rs"] {
        assert_eq!(file(&value, path)["wiring"], "unlinked_candidate", "{path}");
    }
}

#[test]
fn a_partial_clone_is_refused_without_hydrating_remote_objects() {
    use std::os::unix::fs::PermissionsExt;
    let repo = fixture(&[]);
    repo.git(&["config", "uploadpack.allowFilter", "true"]);
    let client = repo.root().join("partial-client");
    let clone = Command::new("git")
        .args(["clone", "--filter=blob:none", "--no-checkout"])
        .arg(format!("file://{}", repo.root().display()))
        .arg(&client)
        .output()
        .unwrap();
    assert!(clone.status.success(), "{clone:?}");
    let marker = repo.root().join("forbidden-fetch-effect");
    let hook = repo.root().join("upload-pack.sh");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\ntouch '{}'\nexec git-upload-pack \"$@\"\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = Command::new("git")
        .args(["config", "remote.origin.uploadpack"])
        .arg(&hook)
        .current_dir(&client)
        .status()
        .unwrap();
    assert!(config.success());
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["roadmap", "check"])
        .current_dir(&client)
        .env("CARGO_MANIFEST_DIR", client.join("xtask"))
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "missing blobs must not be fetched: {out:?}"
    );
    assert!(!marker.exists(), "a remote helper was executed");
}

#[test]
fn budget_errors_cannot_emit_terminal_controls_or_forge_an_extra_line() {
    let mut repo = fixture(&[(
        "src/lib.rs",
        "#[path=\"huge\\u{1b}[31m\\nroadmap: PASS.rs\"] mod huge;",
    )]);
    repo.write(
        "src/huge\u{1b}[31m\nroadmap: PASS.rs",
        &" ".repeat(2 * 1024 * 1024 + 1),
    );
    repo.commit_all("oversized source");
    let out = run(&repo, "check");
    assert_eq!(out.status.code(), Some(64), "{out:?}");
    assert!(!out.stderr.contains(&0x1b));
    assert_eq!(out.stderr.iter().filter(|b| **b == b'\n').count(), 1);
    assert!(String::from_utf8_lossy(&out.stderr).contains("budget"));
}

#[test]
fn preserves_the_existing_register_and_maps_details_without_claiming_completion() {
    let mut repo = fixture(&[]);
    let mut t = task("detail", 1, &[]);
    t["register_tasks"] = json!(["existing"]);
    repo.write("docs/implementation/queue.json", &queue(vec![t]));
    repo.write("docs/completion/tasks.json", &json!({"schema":"huntsman.completion/1", "implementations":[
        {"id":"existing","path":"src/lib.rs","state":"REVIEW","objective":"Existing broad contract"},
        {"id":"unmapped","path":"src/not-present.rs","state":"PROPOSED","objective":"Keep this separate intent visible"}
    ]}).to_string());
    repo.commit_all("existing register");
    let value = report(&repo);
    assert_eq!(
        value["completion_register"]["tasks"][0]["implementation_tasks"],
        json!(["detail"])
    );
    assert_eq!(
        value["completion_register"]["tasks"][0]["declared_state"],
        "REVIEW"
    );
    assert_eq!(
        value["completion_register"]["tasks"][1]["path_exists"],
        false
    );
    assert_eq!(
        value["completion_register"]["tasks"][1]["implementation_tasks"],
        json!([])
    );
    assert_eq!(value["tasks"][0]["verification"], "not_run");
}

#[test]
fn refuses_a_crosswalk_to_an_unknown_existing_register_task() {
    let mut repo = fixture(&[]);
    let mut t = task("detail", 1, &[]);
    t["register_tasks"] = json!(["typo"]);
    repo.write("docs/implementation/queue.json", &queue(vec![t]));
    repo.write(
        "docs/completion/tasks.json",
        r#"{"schema":"huntsman.completion/1","implementations":[]}"#,
    );
    repo.commit_all("dangling crosswalk");
    assert_eq!(run(&repo, "check").status.code(), Some(64));
}
