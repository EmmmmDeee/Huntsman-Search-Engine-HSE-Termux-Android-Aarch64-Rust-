//! Applies one dual-pass change, as `scripts/dual-pass/apply_change.py` did: a unified diff
//! through `git apply`, or else named Rust functions replaced in place.
//!
//! The input is one JSON object on standard input, generated from the plan. Its `allowed` list
//! names the paths a change may touch: every path a diff names must be on it, and every op's
//! path must be on it. A diff that `git apply` accepts is applied, and the ops are not run.
//! Otherwise the ops run in order. A function replace edits only the bytes of the function the
//! syntax tree places, so the rest of the file, its line endings, and its non-ASCII text are kept.
//!
//! The output is one JSON line, written the way Python's `json.dumps` wrote it, so the report
//! the runner keeps reads the same. The status is 0 only when the change was applied.
//!
//! The function replace uses `syn`, which is strict: a file that does not parse is refused. The
//! original used tree-sitter, which tolerates syntax errors and could edit a broken function.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use proc_macro2::{LineColumn, Span};
use serde_json::{Map, Value};
use syn::visit::{self, Visit};
use syn::{ForeignItemFn, ImplItemFn, ItemFn, Signature, TraitItemFn, Visibility};

use crate::dual_pass::patch_paths::touched_paths;
use crate::error::{self, Error, Result};

const USAGE: &str = "usage: xtask dual-pass apply < CHANGE.json";

/// The message for a diff that names a path outside the declared targets.
const ESCAPE_MESSAGE: &str = "diff escapes declared targets";

/// `dual-pass apply`: reads one change on standard input and prints one JSON line for it. The
/// line says how the change was applied, or why it was refused, and the status is 0 only when
/// it was applied. The command takes no arguments, so an extra one is a usage error.
pub fn run(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        return error::usage(USAGE);
    }
    let mut input = String::new();
    let outcome = match std::io::stdin().read_to_string(&mut input) {
        Ok(_) => apply(&input),
        Err(source) => {
            Outcome::Refused(Error::Invalid(format!("cannot read the change: {source}")))
        }
    };
    println!("{}", outcome.line());
    if outcome.applied() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(error::EX_REFUSED)
    }
}

/// What one run of `apply` did. Every variant prints exactly one JSON line.
enum Outcome {
    /// `git apply` accepted the diff, so the ops did not run.
    GitApply,
    /// Every op replaced its function, and OPS counts them.
    FunctionReplace { ops: usize },
    /// The diff names paths outside the declared targets, sorted.
    Escapes(BTreeSet<String>),
    /// The change was refused, or failed, for the reason the error gives.
    Refused(Error),
}

impl Outcome {
    fn applied(&self) -> bool {
        matches!(self, Self::GitApply | Self::FunctionReplace { .. })
    }

    fn line(&self) -> String {
        match self {
            Self::GitApply => "{\"applied\": \"git-apply\"}".to_owned(),
            Self::FunctionReplace { ops } => {
                format!("{{\"applied\": \"function-replace\", \"ops\": {ops}}}")
            }
            Self::Escapes(paths) => {
                let listed: Vec<String> = paths.iter().map(|path| json_string(path)).collect();
                format!(
                    "{{\"error\": {}, \"paths\": [{}]}}",
                    json_string(ESCAPE_MESSAGE),
                    listed.join(", ")
                )
            }
            Self::Refused(problem) => {
                format!("{{\"error\": {}}}", json_string(&problem.to_string()))
            }
        }
    }
}

/// Runs the change in INPUT. Every failure becomes a refusal outcome, so the printed line always
/// says what happened and the status follows from it.
fn apply(input: &str) -> Outcome {
    match change(input) {
        Ok(outcome) => outcome,
        Err(problem) => Outcome::Refused(problem),
    }
}

/// The checks, in the order the original made them: the diff's paths, then `git apply`, then the
/// ops one at a time. A malformed field is refused when it is reached, so the ops before it run,
/// as they did in the original.
fn change(input: &str) -> Result<Outcome> {
    let payload = payload(input)?;
    let allowed = string_list(payload.get("allowed"), "allowed")?;
    let diff = diff_text(payload.get("diff"))?;
    let touched = touched_paths(diff)?;
    if touched.iter().any(|path| !allowed.contains(path)) {
        return Ok(Outcome::Escapes(touched));
    }
    if !diff.is_empty() && git_apply(diff)? {
        return Ok(Outcome::GitApply);
    }
    let mut ops = 0;
    for op in op_list(payload.get("ops"))? {
        replace_op(op, &allowed)?;
        ops += 1;
    }
    if ops == 0 {
        return Err(Error::Refused(
            "neither git apply nor function replace applied".to_owned(),
        ));
    }
    Ok(Outcome::FunctionReplace { ops })
}

/// The change's top-level object. Empty input is an empty change, as the original read it.
fn payload(input: &str) -> Result<Map<String, Value>> {
    if input.is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_str(input) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Error::Invalid(
            "the change must be a JSON object".to_owned(),
        )),
        Err(source) => Err(Error::Invalid(format!("the change is not JSON: {source}"))),
    }
}

/// The strings of an optional list field. A missing or null field is empty, which is what the
/// original's `or []` made of it. Any other value is malformed.
fn string_list(value: Option<&Value>, field: &str) -> Result<BTreeSet<String>> {
    match value {
        None | Some(Value::Null) => Ok(BTreeSet::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Error::Invalid(format!("{field} must hold only strings")))
            })
            .collect(),
        Some(_) => Err(Error::Invalid(format!("{field} must be a list"))),
    }
}

/// The diff text. A missing or null diff is empty, as the original had it.
fn diff_text(value: Option<&Value>) -> Result<&str> {
    match value {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(Error::Invalid("diff must be a string".to_owned())),
    }
}

/// The ops list. A missing or null list is empty. Any other value is malformed.
fn op_list(value: Option<&Value>) -> Result<&[Value]> {
    match value {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(Error::Invalid("ops must be a list".to_owned())),
    }
}

/// Runs one op. Its kind must be `replace_fn`, and its path must be a declared target that is a
/// file. The checks run in the original's order, and each one stops the op before the next.
fn replace_op(op: &Value, allowed: &BTreeSet<String>) -> Result<()> {
    let Some(fields) = op.as_object() else {
        return Err(Error::Invalid("an op must be a JSON object".to_owned()));
    };
    let kind = fields.get("kind");
    if kind.and_then(Value::as_str) != Some("replace_fn") {
        return Err(Error::Refused(format!(
            "unsupported op {}",
            python_text(kind)
        )));
    }
    let path = posix_path(text_field(fields, "path")?);
    if !allowed.contains(&path) {
        return Err(Error::Refused(format!(
            "op escapes declared targets: {path}"
        )));
    }
    let target = PathBuf::from(&path);
    if !target.is_file() {
        return Err(Error::Refused(format!("missing {path}")));
    }
    let name = text_field(fields, "name")?;
    let body = text_field(fields, "body")?;
    replace_fn(&target, name, body)
}

/// A string field of an op. A missing or non-string field is malformed.
fn text_field<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Invalid(format!("an op needs a text \"{key}\"")))
}

/// Replaces the one function NAME in the file at PATH with BODY.
///
/// The file is read and written as bytes. The span comes from byte offsets the syntax tree gives,
/// so non-ASCII text above the function cannot move the edit. The body loses its trailing
/// whitespace and nothing is added after it: the text after the function, its line ending
/// included, is kept, so a second identical replace changes nothing.
fn replace_fn(path: &Path, name: &str, body: &str) -> Result<()> {
    let raw = fs::read(path).map_err(|source| io(path, source))?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| Error::Refused(format!("{} is not UTF-8 text", path.display())))?;
    let spans = function_spans(path, text, name)?;
    let (start, end) = match spans.as_slice() {
        [] => {
            return Err(Error::Refused(format!(
                "function {name} not found in {}",
                path.display()
            )));
        }
        [only] => *only,
        many => {
            return Err(Error::Refused(format!(
                "function {name} matches {} functions in {}; name one",
                many.len(),
                path.display()
            )));
        }
    };
    let replaced = splice(&raw, start, end, python_rstrip(body).as_bytes()).ok_or_else(|| {
        Error::Invalid(format!(
            "the function {name} lies outside {}",
            path.display()
        ))
    })?;
    fs::write(path, replaced).map_err(|source| io(path, source))
}

/// The bytes of RAW with START..END replaced by NEW, or None when the range is not inside RAW.
/// Both sides are taken with `get`, so a bad range is an error rather than a panic.
fn splice(raw: &[u8], start: usize, end: usize, new: &[u8]) -> Option<Vec<u8>> {
    let before = raw.get(..start)?;
    let after = raw.get(end..)?;
    let mut out = Vec::with_capacity(before.len() + new.len() + after.len());
    out.extend_from_slice(before);
    out.extend_from_slice(new);
    out.extend_from_slice(after);
    Some(out)
}

/// The byte spans of every function named NAME in TEXT, in file order. A file that does not
/// parse is refused.
fn function_spans(path: &Path, text: &str, name: &str) -> Result<Vec<(usize, usize)>> {
    let file = syn::parse_file(text).map_err(|source| {
        Error::Refused(format!(
            "{} does not parse as Rust: {source}",
            path.display()
        ))
    })?;
    // syn parses what follows a byte order mark and a shebang line, and proc-macro2 positions
    // count from there. The skipped bytes are added back to every offset.
    let bom = if text.starts_with('\u{feff}') {
        '\u{feff}'.len_utf8()
    } else {
        0
    };
    let shebang = file.shebang.as_ref().map_or(0, String::len);
    let prefix = bom + shebang;
    let body = text.get(prefix..).ok_or_else(|| {
        Error::Refused(format!("cannot place the functions in {}", path.display()))
    })?;
    let mut finder = Finder {
        name,
        found: Vec::new(),
    };
    finder.visit_file(&file);
    let starts = line_starts(body);
    let mut spans = Vec::with_capacity(finder.found.len());
    for found in &finder.found {
        match (
            byte_offset(body, &starts, found.start),
            byte_offset(body, &starts, found.end),
        ) {
            (Some(start), Some(end)) => spans.push((prefix + start, prefix + end)),
            _ => {
                return Err(Error::Refused(format!(
                    "cannot place the function {name} in {}",
                    path.display()
                )));
            }
        }
    }
    spans.sort_unstable();
    Ok(spans)
}

/// A function the visitor found, by its first and last token positions.
struct Candidate {
    start: LineColumn,
    end: LineColumn,
}

/// Collects every function named NAME. A function is a free fn, an associated fn in an impl, a
/// trait method with or without a default body, or a declaration in an extern block. Nested items
/// are visited too, so a function inside another function's body counts.
struct Finder<'a> {
    name: &'a str,
    found: Vec<Candidate>,
}

impl Finder<'_> {
    fn note(
        &mut self,
        sig: &Signature,
        vis: Option<&Visibility>,
        default: Option<Span>,
        end: Span,
    ) {
        if sig.ident == self.name {
            let start = head(sig, vis, default);
            self.found.push(Candidate {
                start,
                end: end.end(),
            });
        }
    }
}

impl<'ast> Visit<'ast> for Finder<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.note(
            &node.sig,
            Some(&node.vis),
            None,
            node.block.brace_token.span.close(),
        );
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let default = node.defaultness.as_ref().map(|token| token.span);
        self.note(
            &node.sig,
            Some(&node.vis),
            default,
            node.block.brace_token.span.close(),
        );
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        let end = match (&node.default, &node.semi_token) {
            (Some(body), _) => Some(body.brace_token.span.close()),
            (None, Some(semi)) => Some(semi_span(semi)),
            (None, None) => None,
        };
        if let Some(end) = end {
            self.note(&node.sig, None, None, end);
        }
        visit::visit_trait_item_fn(self, node);
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast ForeignItemFn) {
        self.note(
            &node.sig,
            Some(&node.vis),
            None,
            semi_span(&node.semi_token),
        );
        visit::visit_foreign_item_fn(self, node);
    }
}

/// The span of a `;`. syn stores a punctuation token's span as a one-element array.
fn semi_span(semi: &syn::token::Semi) -> Span {
    let [span] = semi.spans;
    span
}

/// Where a function's first token is: its visibility or a qualifier, whichever comes first, or
/// the `fn` keyword when it has none. Attributes and doc comments come before this and are not
/// part of the function.
fn head(sig: &Signature, vis: Option<&Visibility>, default: Option<Span>) -> LineColumn {
    let visibility = match vis {
        Some(Visibility::Public(token)) => Some(token.span),
        Some(Visibility::Restricted(restricted)) => Some(restricted.pub_token.span),
        Some(Visibility::Inherited) | None => None,
    };
    let qualifiers = [
        visibility,
        default,
        sig.constness.as_ref().map(|token| token.span),
        sig.asyncness.as_ref().map(|token| token.span),
        sig.unsafety.as_ref().map(|token| token.span),
        sig.abi.as_ref().map(|abi| abi.extern_token.span),
    ];
    qualifiers
        .into_iter()
        .flatten()
        .map(|span| span.start())
        .fold(sig.fn_token.span.start(), std::cmp::min)
}

/// The byte offset at which each line of TEXT starts. Line 1 starts at 0, and each LF starts the
/// next line, which is how proc-macro2 counts lines.
fn line_starts(text: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(text.match_indices('\n').map(|(index, _)| index + 1))
        .collect()
}

/// The byte offset of AT in TEXT. Lines are 1-based, and a column counts characters from the
/// start of its line, as proc-macro2 reports them. Characters are walked one at a time, so the
/// offset never falls inside a multi-byte character.
fn byte_offset(text: &str, starts: &[usize], at: LineColumn) -> Option<usize> {
    let line_start = *starts.get(at.line.checked_sub(1)?)?;
    let mut offset = line_start;
    let mut rest = text.get(line_start..)?.chars();
    for _ in 0..at.column {
        offset += rest.next()?.len_utf8();
    }
    Some(offset)
}

/// Runs `git apply` on DIFF through a patch file in the working directory. Returns whether git
/// accepted the patch. A refusal by git is `false`, so the caller can try the ops, while a git
/// that cannot start is an error. Once the file exists it is removed on every path, and it is
/// created with `create_new`, so a name clash is an error and never an overwrite.
fn git_apply(diff: &str) -> Result<bool> {
    let path = patch_path();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| io(&path, source))?;
    let mut text = diff.to_owned();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let written = file.write_all(text.as_bytes());
    drop(file);
    let verdict = written
        .map_err(|source| io(&path, source))
        .and_then(|()| run_git_apply(&path));
    let removed = fs::remove_file(&path).map_err(|source| io(&path, source));
    let accepted = verdict?;
    removed?;
    Ok(accepted)
}

/// `git apply --whitespace=nowarn --recount PATH`, with its output captured. Returns whether git
/// exited with status 0.
fn run_git_apply(path: &Path) -> Result<bool> {
    let output = Command::new("git")
        .args(["apply", "--whitespace=nowarn", "--recount"])
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|source| Error::Command {
            shown: format!("git apply --whitespace=nowarn --recount {}", path.display()),
            reason: format!("could not start: {source}"),
        })?;
    Ok(output.status.success())
}

/// A patch file name in the working directory, unique to this process and moment.
fn patch_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |age| age.as_nanos());
    PathBuf::from(format!(".dual-pass-{}-{nanos}.patch", std::process::id()))
}

/// An I/O failure on PATH.
fn io(path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// TEXT as Python's `json.dumps` writes a string: in double quotes, with printable ASCII as it is
/// and every other character escaped. A character above U+FFFF is written as a surrogate pair, so
/// the line is ASCII whatever a path or a message holds.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut units = [0_u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

/// The text Python's `str()` gives for a value of the input, which the original's messages
/// printed. A missing or null value is `None`, and a boolean is `True` or `False`. Other values
/// are printed as JSON, which differs from Python for lists and objects.
fn python_text(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_owned(),
        Some(Value::Bool(true)) => "True".to_owned(),
        Some(Value::Bool(false)) => "False".to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

/// TEXT without its trailing whitespace, as Python's `str.rstrip()` takes it. Python counts the
/// ASCII separators U+001C to U+001F as whitespace, and Rust's `char::is_whitespace` does not.
fn python_rstrip(text: &str) -> &str {
    text.trim_end_matches(|ch: char| ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch))
}

/// The path as Python's `pathlib` writes it, which is how the original compared and printed a
/// declared path. Repeated separators, `.` components, and a trailing separator are dropped, and
/// an empty path is `.`. A leading `//` is kept, as pathlib keeps it, and `..` is not resolved.
fn posix_path(text: &str) -> String {
    let root = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else if text.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = text
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let joined = parts.join("/");
    if root.is_empty() && joined.is_empty() {
        ".".to_owned()
    } else {
        format!("{root}{joined}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rstrip_drops_the_separators_python_drops() {
        assert_eq!(python_rstrip("fn a() {}\n\t \u{1c}\u{a0}"), "fn a() {}");
        assert_eq!(python_rstrip("\u{200b}x\u{200b}"), "\u{200b}x\u{200b}");
        assert_eq!(python_rstrip("pub\u{2028}\u{85}\u{2029}"), "pub");
    }

    #[test]
    fn posix_path_matches_pathlib() {
        assert_eq!(posix_path("./src//lib.rs"), "src/lib.rs");
        assert_eq!(posix_path("src/lib.rs/"), "src/lib.rs");
        assert_eq!(posix_path("src/./lib.rs"), "src/lib.rs");
        assert_eq!(posix_path("src/../lib.rs"), "src/../lib.rs");
        assert_eq!(posix_path(""), ".");
        assert_eq!(posix_path("./"), ".");
        assert_eq!(posix_path("/"), "/");
        assert_eq!(posix_path("///a"), "/a");
        assert_eq!(posix_path("//a"), "//a");
    }

    #[test]
    fn json_string_matches_python_dumps() {
        assert_eq!(json_string("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(
            json_string("\n\r\t\u{8}\u{c}\u{1}"),
            r#""\n\r\t\b\f\u0001""#
        );
        assert_eq!(json_string("\u{7f}\u{e9}"), "\"\\u007f\\u00e9\"");
        assert_eq!(json_string("\u{1f600}"), "\"\\ud83d\\ude00\"");
    }

    #[test]
    fn byte_offset_counts_characters_on_each_line() {
        let text = "é = 1;\n日本 fn a() {}\n";
        let starts = line_starts(text);
        let at = LineColumn { line: 2, column: 3 };
        let offset = byte_offset(text, &starts, at).expect("line 2 has column 3");
        assert_eq!(text.get(offset..), Some("fn a() {}\n"));
        let end = LineColumn {
            line: 2,
            column: 12,
        };
        assert_eq!(byte_offset(text, &starts, end), Some(text.len() - 1));
        assert_eq!(
            byte_offset(text, &starts, LineColumn { line: 9, column: 0 }),
            None
        );
    }
}
