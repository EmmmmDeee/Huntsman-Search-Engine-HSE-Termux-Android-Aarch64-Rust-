//! The issue-fix path guard, `xtask issue-fix guard BASE`. Each case of the shell self-check
//! (scripts/issue-fix/self-check.sh) that covers the guard is a test here, named after the case's
//! label. The cases that the shell wrote as `expect_refusal` also check the refusal text. The
//! cases that have no shell counterpart pin the rules that syn and the token scan decide, and the
//! behaviour changes that go with them.

mod common;

use std::process::Output;

use common::{Repo, Scratch, xtask};

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The shell's `expect pass`: the guard accepts the change.
fn assert_passes(repo: &Repo) {
    let output = repo.guard();
    assert!(
        output.status.success(),
        "the guard refused the change: {}",
        stderr(&output)
    );
}

/// The shell's `expect fail`: the guard refuses the change with status 1.
fn assert_refused(repo: &Repo) {
    let output = repo.guard();
    assert_eq!(
        output.status.code(),
        Some(1),
        "the guard accepted the change: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// The shell's `expect_refusal`: the guard refuses the change, under the header the shell
/// printed, and lists TEXT.
fn assert_refused_for(repo: &Repo, text: &str) {
    let output = repo.guard();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let header = format!(
        "check-protected: refused changes against {}:\n",
        repo.base()
    );
    assert!(
        stderr(&output).starts_with(&header),
        "the refusal header differs: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains(text),
        "refused, but not for {text:?}: {}",
        stderr(&output)
    );
}

// Cases of the shell self-check: `expect pass` and `expect fail`.

#[test]
fn edit_under_src() {
    let repo = Repo::new("edit-under-src");
    repo.append("src/lib.rs", "pub fn b() {}\n");
    assert_passes(&repo);
}

#[test]
fn new_test_file_untracked() {
    let repo = Repo::new("new-test-file-untracked");
    repo.write("tests/issue_fix_1.rs", "#[test]\nfn t() {}\n");
    assert_passes(&repo);
}

#[test]
fn new_test_file_staged() {
    let repo = Repo::new("new-test-file-staged");
    repo.write("tests/issue_fix_1.rs", "#[test]\nfn t() {}\n");
    repo.add("tests/issue_fix_1.rs");
    assert_passes(&repo);
}

#[test]
fn new_untracked_file_under_src() {
    let repo = Repo::new("new-untracked-file-under-src");
    repo.write("src/new.rs", "pub fn b() {}\n");
    assert_passes(&repo);
}

#[test]
fn new_test_module_in_a_new_file() {
    let repo = Repo::new("new-test-module-in-a-new-file");
    repo.write("src/extra.rs", "pub fn b() {}\n");
    repo.append("src/lib.rs", "\n#[cfg(test)]\nmod extra;\n");
    assert_passes(&repo);
}

#[test]
fn rename_within_src() {
    let repo = Repo::new("rename-within-src");
    repo.rename("src/lib.rs", "src/core.rs");
    assert_passes(&repo);
}

#[test]
fn delete_a_src_file_without_test_code() {
    let repo = Repo::new("delete-a-src-file-without-test-code");
    repo.remove("src/lib.rs");
    assert_passes(&repo);
}

#[test]
fn edit_src_above_a_test_module() {
    let repo = Repo::new("edit-src-above-a-test-module");
    repo.set_line("src/tested.rs", 2, "    1 + 0");
    assert_passes(&repo);
}

#[test]
fn edit_a_module_declarations_file_above_the_declaration() {
    let repo = Repo::new("edit-a-module-declarations-file-above-the-declaration");
    repo.set_line("src/parent.rs", 2, "    9");
    assert_passes(&repo);
}

#[test]
fn edit_the_body_of_a_file_that_has_tests() {
    let repo = Repo::new("edit-the-body-of-a-file-that-has-tests");
    repo.set_line("src/normal.rs", 2, "    60");
    assert_passes(&repo);
}

#[test]
fn edit_inside_a_test_module() {
    let repo = Repo::new("edit-inside-a-test-module");
    repo.replace(
        "src/tested.rs",
        "assert_eq!(super::c(), 1);",
        "assert!(true);",
    );
    assert_refused(&repo);
}

#[test]
fn append_after_a_test_module() {
    let repo = Repo::new("append-after-a-test-module");
    repo.append("src/tested.rs", "pub fn d() {}\n");
    assert_refused(&repo);
}

#[test]
fn delete_a_src_file_that_holds_tests() {
    let repo = Repo::new("delete-a-src-file-that-holds-tests");
    repo.remove("src/tested.rs");
    assert_refused(&repo);
}

#[test]
fn rename_a_src_file_that_holds_tests() {
    let repo = Repo::new("rename-a-src-file-that-holds-tests");
    repo.rename("src/tested.rs", "src/moved.rs");
    assert_refused(&repo);
}

#[test]
fn untracked_symbolic_link_under_src() {
    let repo = Repo::new("untracked-symbolic-link-under-src");
    repo.symlink("../Cargo.toml", "src/link.rs");
    assert_refused(&repo);
}

#[test]
fn staged_symbolic_link_under_src() {
    let repo = Repo::new("staged-symbolic-link-under-src");
    repo.symlink("../Cargo.toml", "src/link.rs");
    repo.add("src/link.rs");
    assert_refused(&repo);
}

#[test]
fn untracked_symbolic_link_under_tests() {
    let repo = Repo::new("untracked-symbolic-link-under-tests");
    repo.symlink("../Cargo.toml", "tests/link.rs");
    assert_refused(&repo);
}

#[test]
fn edit_an_existing_test() {
    let repo = Repo::new("edit-an-existing-test");
    repo.write("tests/existing.rs", "use fixture::a; // weaker\n");
    assert_refused(&repo);
}

#[test]
fn delete_an_existing_test() {
    let repo = Repo::new("delete-an-existing-test");
    repo.remove("tests/existing.rs");
    assert_refused(&repo);
}

#[test]
fn rename_an_existing_test() {
    let repo = Repo::new("rename-an-existing-test");
    repo.rename("tests/existing.rs", "tests/renamed.rs");
    assert_refused(&repo);
}

#[test]
fn edit_cargo_toml() {
    let repo = Repo::new("edit-cargo-toml");
    repo.write("Cargo.toml", "[package]\nname = \"x\"\n");
    assert_refused(&repo);
}

#[test]
fn edit_a_workflow() {
    let repo = Repo::new("edit-a-workflow");
    repo.write(".github/workflows/ci.yml", "name: weaker\n");
    assert_refused(&repo);
}

#[test]
fn add_a_workflow() {
    let repo = Repo::new("add-a-workflow");
    repo.write(".github/workflows/extra.yml", "name: extra\n");
    assert_refused(&repo);
}

#[test]
fn edit_the_repair_gate() {
    let repo = Repo::new("edit-the-repair-gate");
    repo.write("xtask/src/gate.rs", "fn main() { return; }\n");
    assert_refused(&repo);
}

#[test]
fn edit_a_file_named_tests_rs_above_its_first_test() {
    let repo = Repo::new("edit-a-file-named-tests-rs-above-its-first-test");
    repo.write("src/tests.rs", "pub fn t() -> u8 {\n    2\n}\n");
    assert_refused(&repo);
}

#[test]
fn delete_a_file_named_tests_rs() {
    let repo = Repo::new("delete-a-file-named-tests-rs");
    repo.remove("src/tests.rs");
    assert_refused(&repo);
}

#[test]
fn edit_a_helper_above_the_first_test_of_a_module_loaded_from_test_code() {
    let repo = Repo::new("edit-a-helper-above-the-first-test-of-a-module-loaded-from-test-code");
    repo.set_line("src/parent/helpers.rs", 2, "    9");
    assert_refused(&repo);
}

#[test]
fn delete_a_module_loaded_from_test_code() {
    let repo = Repo::new("delete-a-module-loaded-from-test-code");
    repo.remove("src/parent/helpers.rs");
    assert_refused(&repo);
}

#[test]
fn edit_a_file_loaded_by_path_from_test_code() {
    let repo = Repo::new("edit-a-file-loaded-by-path-from-test-code");
    repo.set_line("src/odd_dir/check.rs", 3, "    assert_eq!(super::o(), 9);");
    assert_refused(&repo);
}

#[test]
fn edit_a_file_that_opens_with_cfg_test() {
    let repo = Repo::new("edit-a-file-that-opens-with-cfg-test");
    repo.replace("src/inner.rs", "4, 4", "4, 5");
    assert_refused(&repo);
}

#[test]
fn edit_the_first_line_of_a_file_that_opens_with_cfg_test() {
    let repo = Repo::new("edit-the-first-line-of-a-file-that-opens-with-cfg-test");
    repo.set_line("src/inner.rs", 1, "#![cfg(test)] // edited");
    assert_refused(&repo);
}

#[test]
fn edit_a_test_marked_with_a_space_after_the_hash() {
    let repo = Repo::new("edit-a-test-marked-with-a-space-after-the-hash");
    repo.replace("src/spaced.rs", "s(), 2", "s(), 9");
    assert_refused(&repo);
}

#[test]
fn delete_a_test_marked_with_a_space_after_the_hash() {
    let repo = Repo::new("delete-a-test-marked-with-a-space-after-the-hash");
    repo.write("src/spaced.rs", "pub fn s() -> u8 {\n    2\n}\n");
    assert_refused(&repo);
}

#[test]
fn edit_a_test_in_a_file_with_a_nul_byte_above_it() {
    let repo = Repo::new("edit-a-test-in-a-file-with-a-nul-byte-above-it");
    repo.replace("src/nul.rs", "assert_eq!(n(), 3);", "assert!(true);");
    assert_refused(&repo);
}

#[test]
fn hide_a_test_edit_behind_a_src_gitattributes_diff() {
    let repo = Repo::new("hide-a-test-edit-behind-a-src-gitattributes-diff");
    repo.write("src/.gitattributes", "*.rs -diff\n");
    repo.replace("src/attr.rs", "assert_eq!(at(), 5);", "assert!(true);");
    assert_refused(&repo);
}

#[test]
fn edit_the_test_of_a_normal_file() {
    let repo = Repo::new("edit-the-test-of-a-normal-file");
    repo.replace("src/normal.rs", "nm(), 6", "nm(), 7");
    assert_refused(&repo);
}

#[test]
fn insert_a_cfg_attribute_above_a_test_marker() {
    let repo = Repo::new("insert-a-cfg-attribute-above-a-test-marker");
    repo.insert_after("src/tested.rs", 4, "#[cfg(any())]");
    assert_refused(&repo);
}

#[test]
fn insert_a_macro_rules_above_a_test_marker() {
    let repo = Repo::new("insert-a-macro-rules-above-a-test-marker");
    repo.insert_after(
        "src/tested.rs",
        4,
        "macro_rules! assert_eq { ($a:expr, $b:expr) => {} }",
    );
    assert_refused(&repo);
}

#[test]
fn insert_an_import_alias_above_a_test_marker() {
    let repo = Repo::new("insert-an-import-alias-above-a-test-marker");
    repo.insert_after("src/tested.rs", 4, "use std::fmt::Write as _;");
    assert_refused(&repo);
}

#[test]
fn add_a_macro_use_module_that_carries_a_macro_shadow() {
    let repo = Repo::new("add-a-macro-use-module-that-carries-a-macro-shadow");
    repo.write(
        "src/shadow.rs",
        "macro_rules! assert_eq { ($a:expr, $b:expr) => {} }\n",
    );
    repo.append("src/lib.rs", "#[macro_use]\nmod shadow;\n");
    assert_refused(&repo);
}

#[test]
fn add_a_path_module_to_a_file_with_no_tests() {
    let repo = Repo::new("add-a-path-module-to-a-file-with-no-tests");
    repo.append(
        "src/lib.rs",
        "#[path = \"odd_dir/check.rs\"]\nmod odd_plain;\n",
    );
    assert_refused(&repo);
}

#[test]
fn add_an_import_alias_to_a_file_with_no_tests() {
    let repo = Repo::new("add-an-import-alias-to-a-file-with-no-tests");
    repo.append("src/lib.rs", "use std::fmt::Write as _;\n");
    assert_passes(&repo);
}

// Cases of the shell self-check: `expect_refusal`, with the reason that the guard must print.

#[test]
fn refused_for_edit_inside_a_test_module() {
    let repo = Repo::new("refused-for-edit-inside-a-test-module");
    repo.replace(
        "src/tested.rs",
        "assert_eq!(super::c(), 1);",
        "assert!(true);",
    );
    assert_refused_for(&repo, "M src/tested.rs");
}

#[test]
fn refused_for_append_after_a_test_module() {
    let repo = Repo::new("refused-for-append-after-a-test-module");
    repo.append("src/tested.rs", "pub fn d() {}\n");
    assert_refused_for(&repo, "M src/tested.rs");
}

#[test]
fn refused_for_delete_a_src_file_that_holds_tests() {
    let repo = Repo::new("refused-for-delete-a-src-file-that-holds-tests");
    repo.remove("src/tested.rs");
    assert_refused_for(&repo, "D src/tested.rs");
}

#[test]
fn refused_for_rename_a_src_file_that_holds_tests() {
    let repo = Repo::new("refused-for-rename-a-src-file-that-holds-tests");
    repo.rename("src/tested.rs", "src/moved.rs");
    assert_refused_for(&repo, "src/tested.rs -> src/moved.rs");
}

#[test]
fn refused_for_untracked_symbolic_link_under_src() {
    let repo = Repo::new("refused-for-untracked-symbolic-link-under-src");
    repo.symlink("../Cargo.toml", "src/link.rs");
    assert_refused_for(&repo, "(symbolic link)");
}

#[test]
fn refused_for_staged_symbolic_link_under_src() {
    let repo = Repo::new("refused-for-staged-symbolic-link-under-src");
    repo.symlink("../Cargo.toml", "src/link.rs");
    repo.add("src/link.rs");
    assert_refused_for(&repo, "link or submodule (mode 120000)");
}

#[test]
fn refused_for_edit_an_existing_test() {
    let repo = Repo::new("refused-for-edit-an-existing-test");
    repo.write("tests/existing.rs", "use fixture::a; // weaker\n");
    assert_refused_for(&repo, "M tests/existing.rs");
}

#[test]
fn refused_for_hide_a_test_edit_behind_diff() {
    let repo = Repo::new("refused-for-hide-a-test-edit-behind-diff");
    repo.write("src/.gitattributes", "*.rs -diff\n");
    repo.replace("src/attr.rs", "assert_eq!(at(), 5);", "assert!(true);");
    assert_refused_for(&repo, "M src/attr.rs");
}

#[test]
fn refused_for_edit_a_test_in_a_file_with_a_nul_byte_above_it() {
    let repo = Repo::new("refused-for-edit-a-test-in-a-file-with-a-nul-byte-above-it");
    repo.replace("src/nul.rs", "assert_eq!(n(), 3);", "assert!(true);");
    assert_refused_for(&repo, "M src/nul.rs");
}

#[test]
fn refused_for_edit_a_helper_in_a_module_loaded_from_test_code() {
    let repo = Repo::new("refused-for-edit-a-helper-in-a-module-loaded-from-test-code");
    repo.set_line("src/parent/helpers.rs", 2, "    9");
    assert_refused_for(&repo, "M src/parent/helpers.rs");
}

// The base commit is not a commit, and the usage.

#[test]
fn an_unknown_base_is_refused() {
    let repo = Repo::new("an-unknown-base-is-refused");
    let output = xtask(repo.root(), &["issue-fix", "guard", "not-a-real-commit"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("is not a commit"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_missing_base_is_a_usage_error() {
    let repo = Repo::new("a-missing-base-is-a-usage-error");
    assert_eq!(
        xtask(repo.root(), &["issue-fix", "guard"]).status.code(),
        Some(64)
    );
    assert_eq!(
        xtask(repo.root(), &["issue-fix", "guard", ""])
            .status
            .code(),
        Some(64)
    );
    assert_eq!(
        xtask(repo.root(), &["issue-fix", "guard", repo.base(), "extra"])
            .status
            .code(),
        Some(64)
    );
}

#[test]
fn an_unchanged_tree_passes_and_says_so() {
    let repo = Repo::new("an-unchanged-tree-passes-and-says-so");
    let output = repo.guard();
    assert!(output.status.success(), "{}", stderr(&output));
    let expected = format!("check-protected: ok against {}\n", repo.base());
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
}

// The filter and the program that the agent's repository names must not run during the guard.

#[test]
fn a_filter_named_by_gitattributes_does_not_run_during_the_guard() {
    let repo = Repo::new("a-filter-named-by-gitattributes-does-not-run-during-the-guard");
    let scratch = Scratch::new("filter-guard");
    let marker = scratch.path().join("filter-ran");
    let filter = format!("touch '{}'; cat", marker.display());
    // The control: a plain git add runs the filter, so the check below proves something.
    repo.git(&["config", "filter.evil.clean", &filter]);
    repo.write("src/.gitattributes", "*.rs filter=evil\n");
    repo.write("src/lib.rs", "pub fn a() {}\npub fn b() {}\n");
    repo.git(&["add", "src/lib.rs"]);
    assert!(marker.exists(), "the control did not run the filter");
    std::fs::remove_file(&marker).expect("the marker must be removed");
    repo.reset();
    repo.write("src/.gitattributes", "*.rs filter=evil\n");
    repo.write("src/lib.rs", "pub fn a() {}\npub fn b() {}\n");
    assert_passes(&repo);
    assert!(!marker.exists(), "a filter ran during the guard");
}

#[test]
fn a_filter_in_info_attributes_and_a_fsmonitor_program_do_not_run_during_the_guard() {
    let repo = Repo::new("a-filter-in-info-attributes-and-a-fsmonitor-program-do-not-run");
    let scratch = Scratch::new("info-guard");
    let info_marker = scratch.path().join("info-filter-ran");
    let fsmon_marker = scratch.path().join("fsmon-ran");
    let fsmon_script = scratch.path().join("fsmon.sh");
    let fsmon_text = format!("#!/bin/sh\ntouch {}\nexit 0\n", fsmon_marker.display());
    std::fs::write(&fsmon_script, fsmon_text).expect("the program must be written");
    set_executable(&fsmon_script);
    let filter = format!("touch '{}'; echo REPLACED", info_marker.display());
    let fsmon = fsmon_script.display().to_string();
    let info_attributes = repo.root().join(".git/info/attributes");

    // The control for the attributes file: a plain git add runs the filter it names.
    repo.git(&["config", "filter.evil.clean", &filter]);
    std::fs::write(&info_attributes, "*.rs filter=evil\n").expect("attributes must be written");
    repo.write("src/lib.rs", "pub fn a() {}\npub fn b() {}\n");
    repo.git(&["add", "src/lib.rs"]);
    assert!(info_marker.exists(), "the control did not run the filter");
    std::fs::remove_file(&info_marker).expect("the marker must be removed");
    std::fs::remove_file(&info_attributes).expect("attributes must be removed");
    repo.git(&["config", "--unset", "filter.evil.clean"]);
    repo.reset();

    // The control for the program: git status runs the core.fsmonitor program.
    repo.git(&["config", "core.fsmonitor", &fsmon]);
    repo.git_status(&["status", "--porcelain"]);
    assert!(
        fsmon_marker.exists(),
        "the control did not run core.fsmonitor"
    );
    std::fs::remove_file(&fsmon_marker).expect("the marker must be removed");
    repo.git(&["config", "--unset", "core.fsmonitor"]);

    repo.reset();
    repo.git(&["config", "filter.evil.clean", &filter]);
    repo.git(&["config", "core.fsmonitor", &fsmon]);
    std::fs::write(&info_attributes, "*.rs filter=evil\n").expect("attributes must be written");
    repo.write("src/lib.rs", "pub fn a() {}\npub fn b() {}\n");
    assert_passes(&repo);
    assert!(
        !info_marker.exists() && !fsmon_marker.exists(),
        "a program in the agent's repository ran during the guard"
    );
}

#[cfg(unix)]
fn set_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)
        .expect("the program must exist")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("the program must be made executable");
}

// Behaviour that the syntax tree decides, and that the shell guard decided with lines.

#[test]
fn a_spaced_macro_rules_above_a_test_marker_is_refused() {
    let repo = Repo::new("a-spaced-macro-rules-above-a-test-marker-is-refused");
    repo.insert_after(
        "src/tested.rs",
        4,
        "macro_rules ! assert_eq { ($a:expr, $b:expr) => {} }",
    );
    assert_refused_for(&repo, "M src/tested.rs");
}

#[test]
fn a_comment_that_names_macro_rules_is_not_a_macro() {
    let repo = Repo::new("a-comment-that-names-macro-rules-is-not-a-macro");
    repo.append("src/lib.rs", "// macro_rules! is not used here\n");
    assert_passes(&repo);
}

#[test]
fn a_marker_inside_a_string_literal_does_not_start_test_code() {
    let repo = Repo::with_files(
        "a-marker-inside-a-string-literal-does-not-start-test-code",
        &[(
            "src/lit.rs",
            "pub fn l() -> &'static str {\n    \"\n#[test]\n\"\n}\n",
        )],
    );
    repo.set_line("src/lit.rs", 5, "} ");
    assert_passes(&repo);
}

#[test]
fn a_module_nested_in_an_inline_test_module_protects_the_file_it_loads() {
    let repo = Repo::with_files(
        "a-module-nested-in-an-inline-test-module-protects-the-file-it-loads",
        &[
            (
                "src/nested.rs",
                "pub fn q() -> u8 {\n    1\n}\n\n#[cfg(test)]\nmod inner {\n    mod deep;\n}\n",
            ),
            (
                "src/nested/inner/deep.rs",
                "fn d() -> bool {\n    true\n}\n",
            ),
        ],
    );
    repo.replace("src/nested/inner/deep.rs", "true", "false");
    assert_refused_for(&repo, "M src/nested/inner/deep.rs");
}

#[test]
fn a_module_declared_by_a_test_file_is_test_code() {
    let repo = Repo::with_files(
        "a-module-declared-by-a-test-file-is-test-code",
        &[
            ("src/foo_tests.rs", "mod bar;\n"),
            ("src/foo_tests/bar.rs", "fn b() -> bool {\n    true\n}\n"),
        ],
    );
    repo.replace("src/foo_tests/bar.rs", "true", "false");
    assert_refused_for(&repo, "M src/foo_tests/bar.rs");
}

#[test]
fn a_file_that_test_code_includes_is_test_code() {
    let repo = Repo::with_files(
        "a-file-that-test-code-includes-is-test-code",
        &[
            (
                "src/inc.rs",
                "pub fn i() -> u8 {\n    1\n}\n\n#[cfg(test)]\ninclude!(\"parts.rs\");\n",
            ),
            ("src/parts.rs", "fn part() -> bool {\n    true\n}\n"),
        ],
    );
    repo.replace("src/parts.rs", "true", "false");
    assert_refused_for(&repo, "M src/parts.rs");
}

#[test]
fn an_include_that_test_code_cannot_name_refuses_every_src_change() {
    let repo = Repo::with_files(
        "an-include-that-test-code-cannot-name-refuses-every-src-change",
        &[(
            "src/inc2.rs",
            "pub fn j() -> u8 {\n    1\n}\n\n#[cfg(test)]\ninclude!(concat!(\"a\", \"b.rs\"));\n",
        )],
    );
    repo.append("src/lib.rs", "pub fn b() {}\n");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn a_base_file_that_does_not_parse_refuses_the_change() {
    let repo = Repo::with_files(
        "a-base-file-that-does-not-parse-refuses-the-change",
        &[("src/broken.rs", "fn (\n")],
    );
    repo.append("src/lib.rs", "pub fn b() {}\n");
    let output = repo.guard();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("cannot parse src/broken.rs"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("refused changes"),
        "a base that does not parse is an error, not a listing: {}",
        stderr(&output)
    );
}

#[test]
fn a_new_src_file_that_does_not_parse_is_refused() {
    let repo = Repo::new("a-new-src-file-that-does-not-parse-is-refused");
    repo.write("src/bad.rs", "fn (\n");
    assert_refused_for(&repo, "?? src/bad.rs");
}

#[test]
fn a_binary_file_under_src_is_not_parsed() {
    let repo = Repo::new("a-binary-file-under-src-is-not-parsed");
    repo.write_bytes("src/data.bin", &[0xff, 0x00, 0x7f, b'\n', 0xfe]);
    assert_passes(&repo);
}

#[test]
fn a_non_rust_file_under_src_that_adds_a_macro_line_is_refused() {
    let repo = Repo::new("a-non-rust-file-under-src-that-adds-a-macro-line-is-refused");
    repo.write("src/data.txt", "macro_rules! x\n");
    assert_refused_for(&repo, "?? src/data.txt");
}

#[test]
fn a_file_named_for_tests_is_test_code() {
    let repo = Repo::with_files(
        "a-file-named-for-tests-is-test-code",
        &[
            ("src/foo_tests.rs", "pub fn f() -> u8 {\n    1\n}\n"),
            ("src/foo_test.rs", "pub fn g() -> u8 {\n    1\n}\n"),
        ],
    );
    repo.set_line("src/foo_tests.rs", 2, "    2");
    assert_refused_for(&repo, "M src/foo_tests.rs");
    repo.reset();
    repo.set_line("src/foo_test.rs", 2, "    2");
    assert_refused_for(&repo, "M src/foo_test.rs");
}

#[test]
fn a_file_under_a_tests_directory_is_test_code() {
    let repo = Repo::with_files(
        "a-file-under-a-tests-directory-is-test-code",
        &[("src/tests/unit.rs", "pub fn u() -> u8 {\n    1\n}\n")],
    );
    repo.set_line("src/tests/unit.rs", 2, "    2");
    assert_refused_for(&repo, "M src/tests/unit.rs");
}

#[test]
fn a_test_attribute_with_a_path_starts_test_code() {
    let repo = Repo::with_files(
        "a-test-attribute-with-a-path-starts-test-code",
        &[(
            "src/asyncs.rs",
            "pub fn z() -> u8 {\n    1\n}\n\n#[tokio::test]\nasync fn t() {\n    assert!(true);\n}\n",
        )],
    );
    repo.replace("src/asyncs.rs", "assert!(true);", "assert!(false || true);");
    assert_refused_for(&repo, "M src/asyncs.rs");
}

#[test]
fn a_test_attribute_named_rstest_or_test_case_starts_test_code() {
    let repo = Repo::with_files(
        "a-test-attribute-named-rstest-or-test-case-starts-test-code",
        &[(
            "src/cases.rs",
            "pub fn r() -> u8 {\n    1\n}\n\n#[rstest]\nfn t() {\n    assert!(true);\n}\n",
        )],
    );
    repo.replace("src/cases.rs", "assert!(true);", "assert!(false || true);");
    assert_refused_for(&repo, "M src/cases.rs");
}

#[test]
fn a_test_marker_inside_a_macro_body_starts_test_code() {
    let repo = Repo::with_files(
        "a-test-marker-inside-a-macro-body-starts-test-code",
        &[(
            "src/mac.rs",
            "pub fn m() -> u8 {\n    1\n}\n\nmacro_rules! mk {\n    () => {\n        #[test]\n        fn x() {}\n    };\n}\n",
        )],
    );
    repo.replace("src/mac.rs", "fn x() {}", "fn x() { }");
    assert_refused_for(&repo, "M src/mac.rs");
}

#[test]
fn a_macro_export_added_to_a_file_is_refused() {
    let repo = Repo::new("a-macro-export-added-to-a-file-is-refused");
    repo.append(
        "src/lib.rs",
        "#[macro_export]\nmacro_rules! m { () => {} }\n",
    );
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn an_include_added_to_a_file_is_refused() {
    let repo = Repo::new("an-include-added-to-a-file-is-refused");
    repo.append("src/lib.rs", "include!(\"other.rs\");\n");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn an_extern_crate_added_to_a_file_with_tests_is_refused() {
    let repo = Repo::new("an-extern-crate-added-to-a-file-with-tests-is-refused");
    repo.insert_after("src/tested.rs", 4, "extern crate core;");
    assert_refused_for(&repo, "M src/tested.rs");
}

#[test]
fn a_cfg_attribute_inside_a_macro_added_above_a_marker_is_refused() {
    let repo = Repo::new("a-cfg-attribute-inside-a-macro-added-above-a-marker-is-refused");
    repo.insert_after("src/tested.rs", 4, "m! { #[cfg(any())] }");
    assert_refused_for(&repo, "M src/tested.rs");
}

#[test]
fn a_path_attribute_that_leaves_src_protects_every_file_under_src() {
    let repo = Repo::with_files(
        "a-path-attribute-that-leaves-src-protects-every-file-under-src",
        &[(
            "src/esc.rs",
            "pub fn e() -> u8 {\n    1\n}\n\n#[cfg(test)]\n#[path = \"../outside.rs\"]\nmod out;\n",
        )],
    );
    repo.append("src/lib.rs", "pub fn b() {}\n");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn a_submodule_entry_is_refused() {
    let repo = Repo::new("a-submodule-entry-is-refused");
    // A nested repository that git adds as a gitlink, which is a submodule entry (mode 160000).
    let nested = repo.root().join("sub");
    std::fs::create_dir_all(&nested).expect("the nested directory must be created");
    for args in [
        vec!["init", "-q"],
        vec![
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "nested",
        ],
    ] {
        let output = std::process::Command::new("git")
            .args(&args)
            .current_dir(&nested)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git must run");
        assert!(output.status.success(), "{}", stderr(&output));
    }
    repo.add("sub");
    assert_refused_for(&repo, "link or submodule (mode 160000)");
}

#[test]
fn a_file_replaced_by_a_symbolic_link_is_refused() {
    let repo = Repo::new("a-file-replaced-by-a-symbolic-link-is-refused");
    repo.remove("src/lib.rs");
    repo.symlink("tested.rs", "src/lib.rs");
    repo.add("src/lib.rs");
    assert_refused_for(
        &repo,
        "link or submodule (mode 120000) in the diff: src/lib.rs",
    );
}

#[test]
fn a_path_that_is_not_utf8_refuses_the_listing() {
    use std::os::unix::ffi::OsStrExt;
    let repo = Repo::new("a-path-that-is-not-utf8-refuses-the-listing");
    let name = std::ffi::OsStr::from_bytes(b"tests/bad-\xff.rs");
    std::fs::write(repo.root().join(name), "#[test]\nfn t() {}\n")
        .expect("the file must be written");
    let output = repo.guard();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("not UTF-8"), "{}", stderr(&output));
}

// The defects that the review of the port found. Each test is named after its finding, and fails
// on the commit before the fix. The tests after them pin the rules that the fix adds.

#[test]
fn a_test_attribute_inserted_above_a_base_test_is_refused() {
    let repo = Repo::with_files(
        "a-test-attribute-inserted-above-a-base-test-is-refused",
        &[(
            "src/ignored.rs",
            "pub fn a() -> i32 {\n    1\n}\n\n#[test]\nfn t() {\n    assert_eq!(a(), 1);\n}\n",
        )],
    );
    repo.insert_after("src/ignored.rs", 4, "#[ignore]");
    assert_refused_for(&repo, "M src/ignored.rs");
}

#[test]
fn a_should_panic_attribute_inserted_above_a_base_test_is_refused() {
    let repo = Repo::with_files(
        "a-should-panic-attribute-inserted-above-a-base-test-is-refused",
        &[(
            "src/failing.rs",
            "pub fn a() -> i32 {\n    1\n}\n\n#[test]\nfn t() {\n    assert_eq!(a(), 2);\n}\n",
        )],
    );
    repo.insert_after("src/failing.rs", 4, "#[should_panic]");
    assert_refused_for(&repo, "M src/failing.rs");
}

#[test]
fn test_code_in_a_non_rs_file_that_a_non_test_include_loads_is_refused() {
    let repo = Repo::with_files(
        "test-code-in-a-non-rs-file-that-a-non-test-include-loads-is-refused",
        &[
            (
                "src/lib.rs",
                "include!(\"data.inc\");\npub fn a() -> u8 {\n    1\n}\n",
            ),
            (
                "src/data.inc",
                "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(super::a(), 1);\n    }\n}\n",
            ),
        ],
    );
    repo.replace(
        "src/data.inc",
        "assert_eq!(super::a(), 1);",
        "assert_eq!(super::a(), 2);",
    );
    assert_refused_for(&repo, "M src/data.inc");
}

#[test]
fn a_module_declared_inside_a_macro_invocation_protects_the_file_it_loads() {
    let repo = Repo::with_files(
        "a-module-declared-inside-a-macro-invocation-protects-the-file-it-loads",
        &[
            (
                "src/lib.rs",
                "macro_rules! passthru { ($($t:tt)*) => { $($t)* }; }\npub fn a() -> i32 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(super::a(), 1);\n    }\n}\n\npassthru! {\n    #[cfg(test)]\n    mod helper;\n}\n",
            ),
            ("src/helper.rs", "pub fn expected() -> i32 {\n    1\n}\n"),
        ],
    );
    repo.set_line("src/helper.rs", 2, "    2");
    assert_refused_for(&repo, "M src/helper.rs");
}

#[test]
fn a_deletion_that_activates_a_commented_macro_shadow_above_a_test_is_refused() {
    let repo = Repo::with_files(
        "a-deletion-that-activates-a-commented-macro-shadow-above-a-test-is-refused",
        &[(
            "src/lib.rs",
            "/*\nmacro_rules! assert_eq {\n    ($l:expr, $r:expr) => { let _ = ($l, $r); };\n}\n*/\n\npub fn a() -> i32 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(super::a(), 1);\n    }\n}\n",
        )],
    );
    repo.write(
        "src/lib.rs",
        "macro_rules! assert_eq {\n    ($l:expr, $r:expr) => { let _ = ($l, $r); };\n}\n\npub fn a() -> i32 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(super::a(), 1);\n    }\n}\n",
    );
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn an_untracked_nested_repository_under_tests_is_refused() {
    let repo = Repo::new("an-untracked-nested-repository-under-tests-is-refused");
    nested_repository(&repo.root().join("tests/nested"));
    assert_refused_for(&repo, "?? tests/nested/ (nested repository)");
}

#[test]
fn a_test_inside_a_block_comment_is_test_code() {
    let repo = Repo::with_files(
        "a-test-inside-a-block-comment-is-test-code",
        &[(
            "src/commented.rs",
            "pub fn a() -> i32 {\n    1\n}\n\n/*\n#[test]\nfn t() {\n    assert_eq!(super::a(), 1);\n}\n*/\n",
        )],
    );
    repo.write(
        "src/commented.rs",
        "pub fn a() -> i32 {\n    1\n}\n\n#[test]\nfn t() {\n    assert_eq!(super::a(), 2);\n}\n",
    );
    assert_refused_for(&repo, "M src/commented.rs");
}

#[test]
fn a_raw_identifier_module_protects_the_file_without_the_raw_prefix() {
    let repo = Repo::with_files(
        "a-raw-identifier-module-protects-the-file-without-the-raw-prefix",
        &[
            (
                "src/lib.rs",
                "pub fn a() -> i32 {\n    1\n}\n\n#[cfg(test)]\nmod r#type;\n",
            ),
            ("src/type.rs", "pub fn helper() -> i32 {\n    1\n}\n"),
        ],
    );
    repo.set_line("src/type.rs", 2, "    2");
    assert_refused_for(&repo, "M src/type.rs");
}

#[test]
fn an_edit_inside_an_existing_macro_definition_above_a_marker_is_refused() {
    let repo = Repo::with_files(
        "an-edit-inside-an-existing-macro-definition-above-a-marker-is-refused",
        &[(
            "src/lib.rs",
            "macro_rules! helper {\n    ($x:expr) => {\n        $x\n    };\n}\n\npub fn a() -> i32 {\n    helper!(1)\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(super::a(), 1);\n    }\n}\n",
        )],
    );
    repo.replace("src/lib.rs", "        $x\n", "        $x + 0\n");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn a_deletion_inside_an_existing_macro_definition_above_a_marker_is_refused() {
    let repo = Repo::with_files(
        "a-deletion-inside-an-existing-macro-definition-above-a-marker-is-refused",
        &[(
            "src/lib.rs",
            "macro_rules! helper {\n    ($x:expr) => {\n        $x\n    };\n}\n\npub fn a() -> i32 {\n    helper!(1)\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(super::a(), 1);\n    }\n}\n",
        )],
    );
    repo.replace("src/lib.rs", "        $x\n", "");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn a_removed_macro_definition_above_a_test_is_allowed() {
    let repo = Repo::with_files(
        "a-removed-macro-definition-above-a-test-is-allowed",
        &[(
            "src/lib.rs",
            "macro_rules! helper {\n    ($x:expr) => {\n        $x\n    };\n}\n\npub fn a() -> i32 {\n    helper!(1)\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(super::a(), 1);\n    }\n}\n",
        )],
    );
    repo.replace(
        "src/lib.rs",
        "macro_rules! helper {\n    ($x:expr) => {\n        $x\n    };\n}\n\n",
        "",
    );
    assert_passes(&repo);
}

#[test]
fn a_line_added_directly_above_a_test_marker_is_refused() {
    let repo = Repo::new("a-line-added-directly-above-a-test-marker-is-refused");
    repo.insert_after("src/tested.rs", 4, "pub fn d() {}");
    assert_refused_for(&repo, "M src/tested.rs");
}

#[test]
fn a_line_added_above_the_blank_line_above_a_test_marker_is_allowed() {
    let repo = Repo::new("a-line-added-above-the-blank-line-above-a-test-marker-is-allowed");
    repo.insert_after("src/tested.rs", 3, "pub fn d() {}");
    assert_passes(&repo);
}

#[test]
fn an_attribute_above_a_test_attribute_is_part_of_the_test() {
    let repo = Repo::with_files(
        "an-attribute-above-a-test-attribute-is-part-of-the-test",
        &[(
            "src/attrs.rs",
            "pub fn x() -> u8 {\n    1\n}\n\n#[allow(unused)]\n#[test]\nfn t() {\n    assert_eq!(x(), 1);\n}\n",
        )],
    );
    repo.set_line("src/attrs.rs", 5, "#[allow(dead_code)]");
    assert_refused_for(&repo, "M src/attrs.rs");
}

#[test]
fn a_test_marker_mentioned_in_a_line_comment_does_not_start_test_code() {
    let repo = Repo::with_files(
        "a-test-marker-mentioned-in-a-line-comment-does-not-start-test-code",
        &[(
            "src/notes.rs",
            "pub fn x() -> u8 {\n    1\n}\n\n// see #[test] above\n/// Mark each case with `#[test]`.\npub fn y() -> u8 {\n    2\n}\n",
        )],
    );
    repo.set_line("src/notes.rs", 8, "    3");
    assert_passes(&repo);
}

#[test]
fn a_commented_out_test_in_line_comments_is_test_code() {
    let repo = Repo::with_files(
        "a-commented-out-test-in-line-comments-is-test-code",
        &[(
            "src/commented_line.rs",
            "pub fn a() -> i32 {\n    1\n}\n\n// #[test]\n// fn t() {\n//     assert_eq!(a(), 1);\n// }\n",
        )],
    );
    repo.set_line("src/commented_line.rs", 7, "//     assert_eq!(a(), 2);");
    assert_refused_for(&repo, "M src/commented_line.rs");
}

#[test]
fn a_commented_out_module_declaration_in_test_code_refuses_every_src_change() {
    let repo = Repo::with_files(
        "a-commented-out-module-declaration-in-test-code-refuses-every-src-change",
        &[(
            "src/lib.rs",
            "pub fn a() -> u8 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(super::a(), 1);\n    }\n}\n// mod helper;\n",
        )],
    );
    repo.set_line("src/lib.rs", 2, "    3");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn an_import_alias_added_to_a_non_rust_file_with_test_code_is_refused() {
    let repo = Repo::with_files(
        "an-import-alias-added-to-a-non-rust-file-with-test-code-is-refused",
        &[(
            "src/notes.txt",
            "pub fn q() -> u8 {\n    1\n}\n\n#[cfg(test)]\nfn t() {}\n",
        )],
    );
    repo.insert_after("src/notes.txt", 0, "use std::fmt::Write as _;");
    assert_refused_for(&repo, "M src/notes.txt");
}

#[test]
fn a_module_declared_by_a_file_that_a_non_test_include_compiles_refuses_every_src_change() {
    let repo = Repo::with_files(
        "a-module-declared-by-a-file-that-a-non-test-include-compiles-refuses-every-src-change",
        &[
            ("src/inc.rs", "include!(\"parts.rs\");\n"),
            ("src/parts.rs", "mod helper;\n"),
            ("src/helper.rs", "pub fn h() -> u8 {\n    1\n}\n"),
        ],
    );
    repo.append("src/lib.rs", "pub fn b() {}\n");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn an_include_outside_test_code_that_cannot_be_named_refuses_every_src_change() {
    let repo = Repo::with_files(
        "an-include-outside-test-code-that-cannot-be-named-refuses-every-src-change",
        &[("src/inc2.rs", "include!(concat!(\"a\", \"b.rs\"));\n")],
    );
    repo.append("src/lib.rs", "pub fn b() {}\n");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn a_module_declaration_in_a_block_comment_of_test_code_refuses_every_src_change() {
    let repo = Repo::with_files(
        "a-module-declaration-in-a-block-comment-of-test-code-refuses-every-src-change",
        &[(
            "src/lib.rs",
            "pub fn a() -> u8 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(super::a(), 1);\n    }\n}\n/*\nmod helper;\n*/\n",
        )],
    );
    repo.set_line("src/lib.rs", 2, "    3");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn a_submodule_under_src_in_the_base_does_not_refuse_a_change_to_another_file() {
    let mut repo = Repo::new("a-submodule-under-src-in-the-base-does-not-refuse-a-change");
    // A submodule that is not checked out is an empty directory of the working tree. It has to
    // exist before `git add -A`, which would otherwise stage the submodule as deleted.
    std::fs::create_dir_all(repo.root().join("src/sub")).expect("the directory must be created");
    let head = repo.rev("HEAD");
    repo.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{head},src/sub"),
    ]);
    repo.commit_all("a submodule under src");
    repo.append("src/lib.rs", "pub fn b() {}\n");
    assert_passes(&repo);
}

#[test]
fn an_attribute_above_a_test_across_a_blank_line_is_refused() {
    // The blank line does not end the run of attributes, so #[ignore] becomes part of the test.
    let repo = Repo::with_files(
        "an-attribute-above-a-test-across-a-blank-line-is-refused",
        &[(
            "src/lib.rs",
            "pub fn c() -> u8 {\n    1\n}\n\n#[test]\nfn c_is_one() {\n    assert_eq!(c(), 1);\n}\n",
        )],
    );
    repo.insert_after("src/lib.rs", 3, "#[ignore]");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn a_block_comment_opened_above_the_tests_and_closed_after_them_is_refused() {
    // The `*/` in the last line comment closes the block comment that starts above the tests, so
    // the test is commented out and the file has no test left.
    let repo = Repo::with_files(
        "a-block-comment-opened-above-the-tests-and-closed-after-them-is-refused",
        &[(
            "src/lib.rs",
            "pub fn c() -> u8 {\n    1\n}\n\n#[test]\nfn c_is_one() {\n    assert_eq!(c(), 1);\n}\n// done */\n",
        )],
    );
    repo.insert_after("src/lib.rs", 0, "/*");
    assert_refused_for(&repo, "M src/lib.rs");
}

#[test]
fn a_non_rust_file_nested_too_deep_is_refused_with_a_message_not_an_abort() {
    let repo = Repo::with_files(
        "a-non-rust-file-nested-too-deep-is-refused-with-a-message-not-an-abort",
        &[("src/data.txt", "x\n")],
    );
    repo.write("src/data.txt", &"(".repeat(30_000));
    let output = repo.guard();
    assert_eq!(
        output.status.code(),
        Some(1),
        "the guard must refuse the change with status 1, not abort: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("brackets nest more than 128 levels deep"),
        "the refusal must say why: {}",
        stderr(&output)
    );
}

#[test]
fn a_rust_file_nested_too_deep_is_refused_with_a_message_not_an_abort() {
    let repo = Repo::new("a-rust-file-nested-too-deep-is-refused-with-a-message-not-an-abort");
    // A valid item, so that the syntax tree is built and recurses to the full depth.
    let deep = format!(
        "pub const DEEP: u8 = {}1{};\n",
        "(".repeat(2_000),
        ")".repeat(2_000)
    );
    repo.insert_after("src/tested.rs", 0, &deep);
    let output = repo.guard();
    assert_eq!(
        output.status.code(),
        Some(1),
        "the guard must refuse the change, not abort: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("brackets nest more than 128 levels deep"),
        "the refusal must say why: {}",
        stderr(&output)
    );
}

/// Creates a git repository of its own in DIR, with one empty commit, as a directory of a working
/// tree that holds it.
fn nested_repository(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).expect("the nested directory must be created");
    for args in [
        vec!["init", "-q"],
        vec![
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "nested",
        ],
    ] {
        let output = std::process::Command::new("git")
            .args(&args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git must run");
        assert!(output.status.success(), "{}", stderr(&output));
    }
}
