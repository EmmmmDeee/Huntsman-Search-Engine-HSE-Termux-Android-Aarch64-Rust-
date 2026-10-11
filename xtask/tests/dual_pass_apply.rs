//! Behaviour of `xtask dual-pass apply`, run as the binary. Each test names the behaviour of
//! `scripts/dual-pass/apply_change.py`, or of its self-check, that it pins. The expected output
//! lines are byte for byte what the original printed, except where a test says it is a change.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

/// The result of one run: the status, and the standard output, which is the one JSON line.
#[derive(Debug)]
struct Run {
    code: Option<i32>,
    stdout: String,
}

/// A fresh directory for one test, with a `src` directory, under the Cargo target temporary
/// directory. No test writes to the system temporary directory.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("dual-pass-apply-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src")).expect("the scratch directory must be created");
    dir
}

/// Runs `xtask dual-pass apply` in DIR with INPUT on standard input. PATH, when given, replaces
/// the search path of the run.
fn run_with(dir: &Path, input: impl AsRef<[u8]>, path: Option<&str>) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
    command
        .args(["dual-pass", "apply"])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let mut child = command.spawn().expect("xtask must start");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(input.as_ref())
        .expect("the change must be written");
    drop(stdin);
    let output = child.wait_with_output().expect("xtask must finish");
    Run {
        code: output.status.code(),
        stdout: String::from_utf8(output.stdout).expect("the output is UTF-8"),
    }
}

fn run(dir: &Path, input: impl AsRef<[u8]>) -> Run {
    run_with(dir, input, None)
}

/// A `replace_fn` op for NAME in PATH with BODY.
fn op(path: &str, name: &str, body: &str) -> Value {
    json!({"kind": "replace_fn", "path": path, "name": name, "body": body})
}

/// A change with the declared targets ALLOWED, the diff DIFF, and the ops OPS.
fn change(allowed: &[&str], diff: &str, ops: Vec<Value>) -> String {
    json!({"allowed": allowed, "diff": diff, "ops": ops}).to_string()
}

fn write(dir: &Path, rel: &str, bytes: &[u8]) {
    fs::write(dir.join(rel), bytes).expect("the fixture must be written");
}

fn read(dir: &Path, rel: &str) -> Vec<u8> {
    fs::read(dir.join(rel)).expect("the fixture must be readable")
}

/// The names of the entries directly in DIR.
fn entries(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .expect("the directory must be readable")
        .map(|entry| {
            entry
                .expect("an entry must be readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

const ANSWER_0: &str = "pub fn answer() -> i32 {\n    0\n}\n";
const ANSWER_7: &str = "pub fn answer() -> i32 {\n    7\n}\n";
const LABEL_LINE: &str = "pub const LABEL: &str = \"h\u{e9}llo \u{2713} \u{65e5}\u{672c}\";\n";

// The ast fallback: the diff misses, so the named function is replaced instead.

#[test]
fn ast_fallback_replaces_the_named_function_when_git_apply_misses() {
    let dir = scratch("ast-fallback");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let diff = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-not the file\n+nope\n";
    let input = change(
        &["src/lib.rs"],
        diff,
        vec![op("src/lib.rs", "answer", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"applied\": \"function-replace\", \"ops\": 1}\n"
    );
    assert_eq!(read(&dir, "src/lib.rs"), ANSWER_7.as_bytes());
}

#[test]
fn git_apply_accepts_a_matching_diff_and_the_ops_do_not_run() {
    let dir = scratch("git-apply");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let diff = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,3 +1,3 @@\n pub fn answer() -> i32 {\n-    0\n+    7\n }\n";
    // The op names a function that does not exist. Had it run, the change would be refused.
    let input = change(
        &["src/lib.rs"],
        diff,
        vec![op("src/lib.rs", "missing", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(out.stdout, "{\"applied\": \"git-apply\"}\n");
    assert_eq!(read(&dir, "src/lib.rs"), ANSWER_7.as_bytes());
}

#[test]
fn the_patch_file_is_removed_after_git_apply_accepts_or_refuses() {
    let dir = scratch("patch-removed");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let refused = change(
        &["src/lib.rs"],
        "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-x\n+y\n",
        vec![op("src/lib.rs", "answer", ANSWER_7)],
    );
    assert_eq!(run(&dir, &refused).code, Some(0));
    let accepted = change(
        &["src/lib.rs"],
        "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,3 +1,3 @@\n pub fn answer() -> i32 {\n-    7\n+    0\n }\n",
        vec![],
    );
    assert_eq!(run(&dir, &accepted).code, Some(0));
    let left: Vec<String> = entries(&dir)
        .into_iter()
        .filter(|name| name.starts_with(".dual-pass"))
        .collect();
    assert!(left.is_empty(), "patch files were left behind: {left:?}");
}

#[test]
fn a_git_that_cannot_start_is_an_error_and_leaves_no_patch_file() {
    let dir = scratch("git-missing");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "--- a/src/lib.rs\n+++ b/src/lib.rs\n",
        vec![op("src/lib.rs", "answer", ANSWER_7)],
    );
    let out = run_with(&dir, &input, Some(""));
    assert_eq!(out.code, Some(1), "{out:?}");
    assert!(out.stdout.contains("could not start"), "{}", out.stdout);
    assert_eq!(read(&dir, "src/lib.rs"), ANSWER_0.as_bytes());
    assert!(
        entries(&dir)
            .iter()
            .all(|name| !name.starts_with(".dual-pass")),
        "a patch file was left behind"
    );
}

// The function replace on the grammar: byte spans, whole names, line endings, ambiguity.

#[test]
fn non_ascii_text_above_the_function_does_not_move_the_edit() {
    let dir = scratch("non-ascii");
    let source = format!(
        "{LABEL_LINE}\npub fn answer_more() -> i32 {{\n    9\n}}\n\npub fn answer() -> i32 {{\n    0\n}}\n"
    );
    write(&dir, "src/unicode.rs", source.as_bytes());
    let input = change(
        &["src/unicode.rs"],
        "",
        vec![op("src/unicode.rs", "answer", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"applied\": \"function-replace\", \"ops\": 1}\n"
    );
    let expected = format!("{LABEL_LINE}\npub fn answer_more() -> i32 {{\n    9\n}}\n\n{ANSWER_7}");
    assert_eq!(read(&dir, "src/unicode.rs"), expected.as_bytes());
}

#[test]
fn a_second_identical_replace_changes_nothing() {
    let dir = scratch("idempotent");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op("src/lib.rs", "answer", ANSWER_7)],
    );
    assert_eq!(run(&dir, &input).code, Some(0));
    let once = read(&dir, "src/lib.rs");
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(read(&dir, "src/lib.rs"), once);
    assert_eq!(once, ANSWER_7.as_bytes());
}

#[test]
fn a_name_that_is_a_prefix_of_another_matches_only_itself() {
    let dir = scratch("prefix-name");
    let source = "pub fn answer() -> i32 {\n    0\n}\n\npub fn answer_more() -> i32 {\n    9\n}\n";
    write(&dir, "src/lib.rs", source.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op(
            "src/lib.rs",
            "answer_more",
            "pub fn answer_more() -> i32 {\n    8\n}\n",
        )],
    );
    assert_eq!(run(&dir, &input).code, Some(0));
    let expected =
        "pub fn answer() -> i32 {\n    0\n}\n\npub fn answer_more() -> i32 {\n    8\n}\n";
    assert_eq!(read(&dir, "src/lib.rs"), expected.as_bytes());
}

#[test]
fn crlf_file_keeps_the_bytes_outside_the_function() {
    let dir = scratch("crlf");
    write(
        &dir,
        "src/crlf.rs",
        b"pub const X: u8 = 1;\r\n\r\npub fn answer() -> i32 {\r\n    0\r\n}\r\n",
    );
    let input = change(
        &["src/crlf.rs"],
        "",
        vec![op("src/crlf.rs", "answer", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(
        read(&dir, "src/crlf.rs"),
        b"pub const X: u8 = 1;\r\n\r\npub fn answer() -> i32 {\n    7\n}\r\n"
    );
}

#[test]
fn a_name_matching_two_functions_is_refused_and_the_file_is_untouched() {
    let dir = scratch("ambiguous");
    let source = "struct A;\nimpl A {\n    pub fn new() -> A {\n        A\n    }\n}\nstruct B;\nimpl B {\n    pub fn new() -> B {\n        B\n    }\n}\n";
    write(&dir, "src/impls.rs", source.as_bytes());
    let input = change(
        &["src/impls.rs"],
        "",
        vec![op("src/impls.rs", "new", "pub fn new() -> A {\n    A\n}\n")],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"function new matches 2 functions in src/impls.rs; name one\"}\n"
    );
    assert_eq!(read(&dir, "src/impls.rs"), source.as_bytes());
}

#[test]
fn a_missing_function_is_refused() {
    let dir = scratch("missing-fn");
    write(&dir, "src/unicode.rs", LABEL_LINE.as_bytes());
    let input = change(
        &["src/unicode.rs"],
        "",
        vec![op("src/unicode.rs", "absent", "pub fn absent() {}\n")],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"function absent not found in src/unicode.rs\"}\n"
    );
    assert_eq!(read(&dir, "src/unicode.rs"), LABEL_LINE.as_bytes());
}

#[test]
fn attributes_and_doc_comments_above_the_function_are_kept() {
    let dir = scratch("attributes");
    let source = "/// Answers.\n#[inline]\n#[must_use]\npub fn answer() -> i32 {\n    0\n}\n";
    write(&dir, "src/lib.rs", source.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op("src/lib.rs", "answer", ANSWER_7)],
    );
    assert_eq!(run(&dir, &input).code, Some(0));
    let expected = "/// Answers.\n#[inline]\n#[must_use]\npub fn answer() -> i32 {\n    7\n}\n";
    assert_eq!(read(&dir, "src/lib.rs"), expected.as_bytes());
}

#[test]
fn a_trait_declaration_without_a_body_and_a_default_method_are_both_replaced() {
    let dir = scratch("trait");
    let source = "pub trait Shape {\n    fn area(&self) -> f64;\n    fn name(&self) -> String {\n        String::new()\n    }\n}\n";
    write(&dir, "src/lib.rs", source.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "",
        vec![
            op(
                "src/lib.rs",
                "area",
                "fn area(&self) -> f64 {\n        0.0\n    }\n",
            ),
            op(
                "src/lib.rs",
                "name",
                "fn name(&self) -> String {\n        String::from(\"x\")\n    }\n",
            ),
        ],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"applied\": \"function-replace\", \"ops\": 2}\n"
    );
    let expected = "pub trait Shape {\n    fn area(&self) -> f64 {\n        0.0\n    }\n    fn name(&self) -> String {\n        String::from(\"x\")\n    }\n}\n";
    assert_eq!(read(&dir, "src/lib.rs"), expected.as_bytes());
}

#[test]
fn a_method_in_an_impl_block_is_replaced_and_its_indent_is_kept() {
    let dir = scratch("impl-method");
    write(
        &dir,
        "src/lib.rs",
        b"struct A;\n\nimpl A {\n    pub fn get(&self) -> u8 {\n        1\n    }\n}\n",
    );
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op(
            "src/lib.rs",
            "get",
            "pub fn get(&self) -> u8 {\n        2\n    }\n",
        )],
    );
    assert_eq!(run(&dir, &input).code, Some(0));
    assert_eq!(
        read(&dir, "src/lib.rs"),
        b"struct A;\n\nimpl A {\n    pub fn get(&self) -> u8 {\n        2\n    }\n}\n"
    );
}

#[test]
fn the_span_starts_at_the_first_qualifier_not_at_fn() {
    let dir = scratch("qualifiers");
    write(
        &dir,
        "src/a.rs",
        b"pub(crate) const unsafe fn answer() -> i32 {\n    0\n}\n",
    );
    write(
        &dir,
        "src/b.rs",
        b"unsafe extern \"C\" fn answer() -> i32 {\n    0\n}\n",
    );
    let input = change(
        &["src/a.rs", "src/b.rs"],
        "",
        vec![
            op(
                "src/a.rs",
                "answer",
                "pub(crate) const unsafe fn answer() -> i32 {\n    7\n}\n",
            ),
            op(
                "src/b.rs",
                "answer",
                "unsafe extern \"C\" fn answer() -> i32 {\n    7\n}\n",
            ),
        ],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(
        read(&dir, "src/a.rs"),
        b"pub(crate) const unsafe fn answer() -> i32 {\n    7\n}\n"
    );
    assert_eq!(
        read(&dir, "src/b.rs"),
        b"unsafe extern \"C\" fn answer() -> i32 {\n    7\n}\n"
    );
}

#[test]
fn a_function_nested_inside_another_is_matched() {
    let dir = scratch("nested");
    write(
        &dir,
        "src/lib.rs",
        b"pub fn outer() -> i32 {\n    fn inner() -> i32 {\n        1\n    }\n    inner()\n}\n",
    );
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op(
            "src/lib.rs",
            "inner",
            "fn inner() -> i32 {\n        2\n    }\n",
        )],
    );
    assert_eq!(run(&dir, &input).code, Some(0));
    assert_eq!(
        read(&dir, "src/lib.rs"),
        b"pub fn outer() -> i32 {\n    fn inner() -> i32 {\n        2\n    }\n    inner()\n}\n"
    );
}

#[test]
fn a_declaration_in_an_extern_block_is_matched() {
    let dir = scratch("extern-block");
    write(
        &dir,
        "src/lib.rs",
        b"extern \"C\" {\n    fn answer() -> i32;\n}\n",
    );
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op("src/lib.rs", "answer", "fn answer() -> u8;")],
    );
    assert_eq!(run(&dir, &input).code, Some(0));
    assert_eq!(
        read(&dir, "src/lib.rs"),
        b"extern \"C\" {\n    fn answer() -> u8;\n}\n"
    );
}

#[test]
fn a_column_after_non_ascii_text_on_the_same_line_counts_characters() {
    let dir = scratch("same-line");
    let source =
        "pub const S: &str = \"\u{65e5}\u{672c}\u{8a9e}\"; pub fn answer() -> i32 {\n    0\n}\n";
    write(&dir, "src/lib.rs", source.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op("src/lib.rs", "answer", ANSWER_7)],
    );
    assert_eq!(run(&dir, &input).code, Some(0));
    let expected = format!("pub const S: &str = \"\u{65e5}\u{672c}\u{8a9e}\"; {ANSWER_7}");
    assert_eq!(read(&dir, "src/lib.rs"), expected.as_bytes());
}

#[test]
fn a_byte_order_mark_or_a_shebang_does_not_shift_the_span() {
    let dir = scratch("bom-shebang");
    write(
        &dir,
        "src/bom.rs",
        "\u{feff}pub fn answer() -> i32 {\n    0\n}\n".as_bytes(),
    );
    write(
        &dir,
        "src/shebang.rs",
        b"#!/usr/bin/env run\npub fn answer() -> i32 {\n    0\n}\n",
    );
    let input = change(
        &["src/bom.rs", "src/shebang.rs"],
        "",
        vec![
            op("src/bom.rs", "answer", ANSWER_7),
            op("src/shebang.rs", "answer", ANSWER_7),
        ],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(
        read(&dir, "src/bom.rs"),
        "\u{feff}pub fn answer() -> i32 {\n    7\n}\n".as_bytes()
    );
    assert_eq!(
        read(&dir, "src/shebang.rs"),
        b"#!/usr/bin/env run\npub fn answer() -> i32 {\n    7\n}\n"
    );
}

#[test]
fn a_file_that_does_not_parse_is_refused_and_untouched() {
    let dir = scratch("unparsable");
    let source = "pub fn answer() -> i32 {\n    0\n}\npub fn broken( {\n";
    write(&dir, "src/lib.rs", source.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op("src/lib.rs", "answer", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert!(
        out.stdout
            .starts_with("{\"error\": \"src/lib.rs does not parse as Rust: "),
        "{}",
        out.stdout
    );
    assert_eq!(read(&dir, "src/lib.rs"), source.as_bytes());
}

#[test]
fn a_file_that_is_not_utf8_is_refused_and_untouched() {
    let dir = scratch("not-utf8");
    let bytes = b"pub fn answer() -> i32 {\n    0\n}\n\xff\n";
    write(&dir, "src/lib.rs", bytes);
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op("src/lib.rs", "answer", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"src/lib.rs is not UTF-8 text\"}\n"
    );
    assert_eq!(read(&dir, "src/lib.rs"), bytes);
}

#[test]
fn trailing_separator_controls_of_the_body_are_stripped_as_python_strips_them() {
    let dir = scratch("rstrip");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op(
            "src/lib.rs",
            "answer",
            "pub fn answer() -> i32 {\n    7\n}\n\u{1c}",
        )],
    );
    assert_eq!(run(&dir, &input).code, Some(0));
    assert_eq!(read(&dir, "src/lib.rs"), ANSWER_7.as_bytes());
}

// The checks before the ops: the diff's paths, then the op's path, then its file.

#[test]
fn a_diff_outside_the_declared_targets_lists_the_sorted_paths_and_runs_no_op() {
    let dir = scratch("escapes");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let diff = "--- a/z.rs\n+++ b/z.rs\n--- a/\u{e9}.rs\n+++ b/\u{e9}.rs\n";
    let input = change(
        &["src/lib.rs"],
        diff,
        vec![op("src/lib.rs", "answer", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"diff escapes declared targets\", \"paths\": [\"z.rs\", \"\\u00e9.rs\"]}\n"
    );
    assert_eq!(read(&dir, "src/lib.rs"), ANSWER_0.as_bytes());
}

#[test]
fn a_diff_header_that_cannot_be_read_is_refused() {
    let dir = scratch("unreadable-header");
    let input = change(
        &["my file.rs"],
        "diff --git a/my file.rs b/my file.rs\n",
        vec![],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"cannot read the paths in: diff --git a/my file.rs b/my file.rs\"}\n"
    );
}

#[test]
fn an_op_path_is_compared_after_pathlib_normalization() {
    let dir = scratch("normalized");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op("./src//lib.rs", "answer", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(read(&dir, "src/lib.rs"), ANSWER_7.as_bytes());
}

#[test]
fn an_op_path_outside_the_declared_targets_names_the_normalized_path() {
    let dir = scratch("op-escape");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "",
        vec![op("./other.rs", "answer", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"op escapes declared targets: other.rs\"}\n"
    );
}

#[test]
fn a_declared_target_that_is_not_a_file_is_refused() {
    let dir = scratch("missing-file");
    let input = change(
        &["src/gone.rs"],
        "",
        vec![op("src/gone.rs", "answer", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(out.stdout, "{\"error\": \"missing src/gone.rs\"}\n");
}

#[test]
fn an_unsupported_op_kind_is_named_as_the_original_named_it() {
    let dir = scratch("kinds");
    let named = json!({"allowed": ["src/lib.rs"], "diff": "", "ops": [{"kind": "replace_struct", "path": "src/lib.rs", "name": "a", "body": "b"}]});
    let out = run(&dir, named.to_string());
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"unsupported op replace_struct\"}\n"
    );
    let unnamed = json!({"allowed": ["src/lib.rs"], "diff": "", "ops": [{"path": "src/lib.rs"}]});
    let out = run(&dir, unnamed.to_string());
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(out.stdout, "{\"error\": \"unsupported op None\"}\n");
}

#[test]
fn ops_run_in_order_and_an_edit_before_a_failure_is_kept() {
    let dir = scratch("in-order");
    let source = "pub fn a() -> i32 {\n    0\n}\npub fn b() -> i32 {\n    0\n}\n";
    write(&dir, "src/lib.rs", source.as_bytes());
    let input = change(
        &["src/lib.rs"],
        "",
        vec![
            op("src/lib.rs", "a", "pub fn a() -> i32 {\n    1\n}\n"),
            op("src/lib.rs", "nope", "pub fn nope() {}\n"),
            op("src/lib.rs", "b", "pub fn b() -> i32 {\n    2\n}\n"),
        ],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"function nope not found in src/lib.rs\"}\n"
    );
    let expected = "pub fn a() -> i32 {\n    1\n}\npub fn b() -> i32 {\n    0\n}\n";
    assert_eq!(read(&dir, "src/lib.rs"), expected.as_bytes());
}

#[test]
fn a_change_with_no_applicable_diff_and_no_ops_is_refused() {
    let dir = scratch("nothing");
    for input in [
        "{}",
        "",
        "{\"allowed\": null, \"diff\": null, \"ops\": null}",
    ] {
        let out = run(&dir, input);
        assert_eq!(out.code, Some(1), "{out:?}");
        assert_eq!(
            out.stdout,
            "{\"error\": \"neither git apply nor function replace applied\"}\n"
        );
    }
}

#[test]
fn malformed_input_is_refused_with_a_json_line_and_the_status_one() {
    let dir = scratch("malformed");
    let cases = [
        ("{", "{\"error\": \"the change is not JSON: "),
        ("[]", "{\"error\": \"the change must be a JSON object\"}\n"),
        (
            "{\"allowed\": [1]}",
            "{\"error\": \"allowed must hold only strings\"}\n",
        ),
        (
            "{\"allowed\": \"src/lib.rs\"}",
            "{\"error\": \"allowed must be a list\"}\n",
        ),
        ("{\"diff\": 5}", "{\"error\": \"diff must be a string\"}\n"),
        ("{\"ops\": false}", "{\"error\": \"ops must be a list\"}\n"),
        (
            "{\"ops\": [\"x\"]}",
            "{\"error\": \"an op must be a JSON object\"}\n",
        ),
    ];
    for (input, want) in cases {
        let out = run(&dir, input);
        assert_eq!(out.code, Some(1), "{input}: {out:?}");
        assert!(out.stdout.starts_with(want), "{input}: {}", out.stdout);
    }
}

#[test]
fn an_extra_argument_is_a_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["dual-pass", "apply", "extra"])
        .stdin(Stdio::null())
        .output()
        .expect("xtask must run");
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn non_utf8_input_is_refused_with_status_one() {
    let dir = scratch("non-utf8-input");
    let out = run(&dir, vec![0xff_u8, b'{']);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert!(
        out.stdout
            .starts_with("{\"error\": \"cannot read the change: "),
        "{}",
        out.stdout
    );
}

#[test]
fn an_op_missing_a_text_field_is_refused() {
    let dir = scratch("op-fields");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let cases = [
        (
            json!({"kind": "replace_fn", "path": "src/lib.rs", "body": "x"}),
            "{\"error\": \"an op needs a text \\\"name\\\"\"}\n",
        ),
        (
            json!({"kind": "replace_fn", "path": "src/lib.rs", "name": "answer", "body": 7}),
            "{\"error\": \"an op needs a text \\\"body\\\"\"}\n",
        ),
        (
            json!({"kind": "replace_fn", "name": "answer", "body": "x"}),
            "{\"error\": \"an op needs a text \\\"path\\\"\"}\n",
        ),
    ];
    for (bad, want) in cases {
        let input = change(&["src/lib.rs"], "", vec![bad]);
        let out = run(&dir, &input);
        assert_eq!(out.code, Some(1), "{out:?}");
        assert_eq!(out.stdout, want);
    }
    assert_eq!(read(&dir, "src/lib.rs"), ANSWER_0.as_bytes());
}

#[test]
fn a_declared_target_that_is_a_directory_is_missing() {
    let dir = scratch("directory-target");
    let input = change(&["src"], "", vec![op("src", "answer", ANSWER_7)]);
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(out.stdout, "{\"error\": \"missing src\"}\n");
}

#[test]
fn an_allowed_entry_is_compared_raw_not_normalized() {
    let dir = scratch("raw-allowed");
    write(&dir, "src/g.rs", ANSWER_0.as_bytes());
    let input = change(
        &["./src/g.rs"],
        "",
        vec![op("./src/g.rs", "answer", ANSWER_7)],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"op escapes declared targets: src/g.rs\"}\n"
    );
    assert_eq!(read(&dir, "src/g.rs"), ANSWER_0.as_bytes());
}

#[test]
fn a_rename_out_of_the_declared_targets_is_refused() {
    let dir = scratch("rename-out");
    write(&dir, "src/lib.rs", ANSWER_0.as_bytes());
    let diff = "diff --git a/src/lib.rs b/other.rs\nsimilarity index 100%\nrename from src/lib.rs\nrename to other.rs\n";
    let out = run(&dir, change(&["src/lib.rs"], diff, vec![]));
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"diff escapes declared targets\", \"paths\": [\"other.rs\", \"src/lib.rs\"]}\n"
    );
}

#[test]
fn a_generic_async_restricted_or_specialised_function_is_matched() {
    let dir = scratch("shapes");
    write(
        &dir,
        "src/generic.rs",
        b"pub fn answer<T: Clone>(x: T) -> T\nwhere\n    T: Clone,\n{\n    x\n}\n",
    );
    write(
        &dir,
        "src/async.rs",
        b"pub async fn answer() -> i32 {\n    0\n}\n",
    );
    write(
        &dir,
        "src/restricted.rs",
        b"pub(in crate::m) fn answer() -> i32 {\n    0\n}\n",
    );
    write(
        &dir,
        "src/special.rs",
        b"struct A;\nimpl A {\n    pub default fn answer() -> i32 {\n        0\n    }\n}\n",
    );
    let input = change(
        &[
            "src/generic.rs",
            "src/async.rs",
            "src/restricted.rs",
            "src/special.rs",
        ],
        "",
        vec![
            op(
                "src/generic.rs",
                "answer",
                "pub fn answer<T: Clone>(x: T) -> T {\n    x.clone()\n}\n",
            ),
            op(
                "src/async.rs",
                "answer",
                "pub async fn answer() -> i32 {\n    7\n}\n",
            ),
            op(
                "src/restricted.rs",
                "answer",
                "pub(in crate::m) fn answer() -> i32 {\n    7\n}\n",
            ),
            op(
                "src/special.rs",
                "answer",
                "pub default fn answer() -> i32 {\n        7\n    }\n",
            ),
        ],
    );
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"applied\": \"function-replace\", \"ops\": 4}\n"
    );
    assert_eq!(
        read(&dir, "src/generic.rs"),
        b"pub fn answer<T: Clone>(x: T) -> T {\n    x.clone()\n}\n"
    );
    assert_eq!(
        read(&dir, "src/async.rs"),
        b"pub async fn answer() -> i32 {\n    7\n}\n"
    );
    assert_eq!(
        read(&dir, "src/restricted.rs"),
        b"pub(in crate::m) fn answer() -> i32 {\n    7\n}\n"
    );
    assert_eq!(
        read(&dir, "src/special.rs"),
        b"struct A;\nimpl A {\n    pub default fn answer() -> i32 {\n        7\n    }\n}\n"
    );
}

#[test]
fn a_function_inside_a_macro_definition_is_not_matched() {
    let dir = scratch("macro-body");
    let source = "macro_rules! m {\n    () => {\n        fn answer() -> i32 {\n            0\n        }\n    };\n}\n";
    write(&dir, "src/g.rs", source.as_bytes());
    let input = change(&["src/g.rs"], "", vec![op("src/g.rs", "answer", ANSWER_7)]);
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"function answer not found in src/g.rs\"}\n"
    );
    assert_eq!(read(&dir, "src/g.rs"), source.as_bytes());
}

#[test]
fn a_raw_identifier_is_matched_by_its_raw_name_only() {
    let dir = scratch("raw-ident");
    write(&dir, "src/g.rs", b"pub fn r#type() -> i32 {\n    0\n}\n");
    let plain = change(
        &["src/g.rs"],
        "",
        vec![op(
            "src/g.rs",
            "type",
            "pub fn r#type() -> i32 {\n    7\n}\n",
        )],
    );
    let out = run(&dir, &plain);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"function type not found in src/g.rs\"}\n"
    );
    let raw = change(
        &["src/g.rs"],
        "",
        vec![op(
            "src/g.rs",
            "r#type",
            "pub fn r#type() -> i32 {\n    7\n}\n",
        )],
    );
    let out = run(&dir, &raw);
    assert_eq!(out.code, Some(0), "{out:?}");
    assert_eq!(
        read(&dir, "src/g.rs"),
        b"pub fn r#type() -> i32 {\n    7\n}\n"
    );
}

#[test]
fn a_nested_function_with_the_same_name_is_ambiguous() {
    let dir = scratch("nested-same");
    let source = "pub fn answer() -> i32 {\n    fn answer() -> i32 {\n        1\n    }\n    0\n}\n";
    write(&dir, "src/g.rs", source.as_bytes());
    let input = change(&["src/g.rs"], "", vec![op("src/g.rs", "answer", ANSWER_7)]);
    let out = run(&dir, &input);
    assert_eq!(out.code, Some(1), "{out:?}");
    assert_eq!(
        out.stdout,
        "{\"error\": \"function answer matches 2 functions in src/g.rs; name one\"}\n"
    );
    assert_eq!(read(&dir, "src/g.rs"), source.as_bytes());
}

#[test]
fn an_empty_body_removes_the_function() {
    let dir = scratch("empty-body");
    write(
        &dir,
        "src/g.rs",
        b"pub fn a() {}\npub fn answer() -> i32 {\n    0\n}\n",
    );
    let input = change(&["src/g.rs"], "", vec![op("src/g.rs", "answer", "")]);
    assert_eq!(run(&dir, &input).code, Some(0));
    assert_eq!(read(&dir, "src/g.rs"), b"pub fn a() {}\n\n");
}

#[test]
fn the_body_is_inserted_as_given_except_its_trailing_whitespace() {
    let dir = scratch("body-whitespace");
    write(&dir, "src/g.rs", ANSWER_0.as_bytes());
    let body = "\n\npub fn answer() -> i32 {\n    7\n}\n\n";
    let input = change(&["src/g.rs"], "", vec![op("src/g.rs", "answer", body)]);
    assert_eq!(run(&dir, &input).code, Some(0));
    assert_eq!(
        read(&dir, "src/g.rs"),
        b"\n\npub fn answer() -> i32 {\n    7\n}\n"
    );
}
