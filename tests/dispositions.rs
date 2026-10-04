//! `docs/DISPOSITIONS.md` claims to account for the legacy monolith. This test recomputes
//! that accounting from `legacy/`, so a row for a file that does not exist, or a stale
//! "Not yet dispositioned" count, fails the build. It also recomputes the crate's module
//! tree from `src/lib.rs` and `src/main.rs`, so a row that says code was rebuilt into a
//! `src/` file outside that tree, or any `src/` file outside it, fails too. A `mod` gated
//! by a `cfg` other than `cfg(test)`, or moved with `path`, fails rather than counting.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const UNLISTED_HEADING: &str = "## Not yet dispositioned";

fn monolith() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("legacy/hse-monolith-v1.41.0")
}

fn doc() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/DISPOSITIONS.md")).unwrap()
}

/// First cell of every table row, without backticks or annotations.
fn first_cells(markdown: &str) -> impl Iterator<Item = (&str, &str)> {
    markdown.lines().filter_map(|line| {
        let row = line.strip_prefix("| ")?;
        if row.starts_with("---") {
            return None;
        }
        let cell = row.split(" |").next()?.trim();
        let path = cell.split(' ').next()?.trim_matches('`');
        Some((path, cell))
    })
}

fn files_under(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, base, out);
        } else {
            let rel = path.strip_prefix(base).unwrap().to_string_lossy();
            out.insert(rel.replace('\\', "/"));
        }
    }
}

fn legacy_src() -> BTreeSet<String> {
    let src = monolith().join("src");
    let mut files = BTreeSet::new();
    files_under(&src, &src, &mut files);
    files
}

/// Legacy paths (relative to the monolith's `src/`) listed in the per-area sections.
fn listed(doc: &str) -> BTreeSet<String> {
    let body = &doc[..doc.find(UNLISTED_HEADING).expect("unlisted section")];
    first_cells(body)
        .filter(|(_, cell)| !cell.contains("(current owner)"))
        .map(|(path, _)| path.strip_prefix("src/").unwrap_or(path).to_owned())
        .filter(|path| path.contains('/') || Path::new(path).extension().is_some())
        .collect()
}

fn area(path: &str) -> &str {
    path.split_once('/').map_or("(root)", |(top, _)| top)
}

/// The `Not yet dispositioned` table as area → (unlisted, total).
fn unlisted_table(doc: &str) -> BTreeMap<String, (usize, usize)> {
    let section = &doc[doc.find(UNLISTED_HEADING).expect("unlisted section")..];
    section
        .lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line
                .strip_prefix("| ")?
                .split(" |")
                .map(|c| c.trim().trim_start_matches("| ").trim())
                .collect();
            let unlisted = cells.get(1)?.parse().ok()?;
            let total = cells.get(2)?.parse().ok()?;
            let label = cells[0];
            let key = if label.starts_with("crate root") {
                "(root)".to_owned()
            } else {
                let path = label.split('`').nth(1)?;
                path.trim_start_matches("src/")
                    .trim_end_matches('/')
                    .to_owned()
            };
            Some((key, (unlisted, total)))
        })
        .collect()
}

#[test]
fn every_listed_legacy_row_exists() {
    let doc = doc();
    let src = legacy_src();
    let missing: Vec<String> = listed(&doc)
        .into_iter()
        .filter(|path| !src.contains(path) && !monolith().join(path).is_file())
        .collect();
    assert!(
        missing.is_empty(),
        "rows name absent legacy files: {missing:?}"
    );
}

#[test]
fn unlisted_counts_match_legacy() {
    let doc = doc();
    let listed = listed(&doc);
    let mut want: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for path in legacy_src() {
        let slot = want.entry(area(&path).to_owned()).or_default();
        slot.1 += 1;
        if !listed.contains(&path) {
            slot.0 += 1;
        }
    }
    want.retain(|_, (unlisted, _)| *unlisted > 0);
    assert_eq!(unlisted_table(&doc), want);

    let unlisted: usize = want.values().map(|v| v.0).sum();
    let total = legacy_src().len();
    let sentence = format!("({unlisted} of {total})");
    assert!(
        doc.contains(&sentence),
        "DISPOSITIONS should state {sentence}"
    );
}

/// Decisions that claim the code now lives in a current `src/` file.
const CLAIMS: [&str; 4] = ["REBUILT", "REIMPLEMENT", "MERGED", "PARTIAL"];

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// `text` with comments and string/char literals blanked to spaces (newlines kept), so a
/// `mod` line inside `/* … */`, `//` or a (raw) string literal is not taken as code.
fn strip_non_code(text: &str) -> String {
    let src: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let blank = |out: &mut String, chunk: &[char]| {
        out.extend(chunk.iter().map(|&c| if c == '\n' { '\n' } else { ' ' }));
    };
    let mut i = 0;
    while i < src.len() {
        let rest = &src[i..];
        let is_ident = |at: usize| src[at].is_alphanumeric() || src[at] == '_';
        // `r` starts a raw string unless it ends an identifier; `br`/`cr` prefixes count too.
        let ident_before = i > 0
            && is_ident(i - 1)
            && !(matches!(src[i - 1], 'b' | 'c') && (i < 2 || !is_ident(i - 2)));
        let end = if rest.starts_with(&['/', '/']) {
            rest.iter().position(|&c| c == '\n').unwrap_or(rest.len())
        } else if rest.starts_with(&['/', '*']) {
            let (mut depth, mut j) = (0_usize, 0);
            while j < rest.len() {
                if rest[j..].starts_with(&['/', '*']) {
                    depth += 1;
                    j += 2;
                } else if rest[j..].starts_with(&['*', '/']) {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            j
        } else if rest[0] == 'r' && !ident_before && raw_string_len(rest).is_some() {
            raw_string_len(rest).unwrap()
        } else if rest[0] == '"' {
            let mut j = 1;
            while j < rest.len() && rest[j] != '"' {
                j += if rest[j] == '\\' { 2 } else { 1 };
            }
            (j + 1).min(rest.len())
        } else if rest[0] == '\'' && rest.get(1) == Some(&'\\') {
            rest.iter()
                .skip(2)
                .position(|&c| c == '\'')
                .map_or(rest.len(), |p| p + 3)
        } else if rest[0] == '\'' && rest.get(2) == Some(&'\'') {
            3
        } else {
            out.push(rest[0]);
            i += 1;
            continue;
        };
        blank(&mut out, &rest[..end]);
        i += end;
    }
    out
}

/// Length of the raw string literal (`r"…"`, `r#"…"#`, …) at the start of `rest`, if any.
fn raw_string_len(rest: &[char]) -> Option<usize> {
    let hashes = rest[1..].iter().take_while(|&&c| c == '#').count();
    if rest.get(1 + hashes) != Some(&'"') {
        return None;
    }
    let body = 2 + hashes;
    let close: Vec<char> = std::iter::once('"')
        .chain(std::iter::repeat_n('#', hashes))
        .collect();
    let found = (body..rest.len()).find(|&j| rest[j..].starts_with(&close));
    Some(found.map_or(rest.len(), |j| j + close.len()))
}

/// Non-test `cfg` attributes allowed on a `mod` item, as (file, attribute text).
/// Empty: nothing in the tree is conditionally compiled except under `cfg(test)`.
const CFG_ALLOWLIST: &[(&str, &str)] = &[];

/// What one source file declares.
#[derive(Debug)]
struct Scan {
    /// Out-of-line children as crate-relative stems: `src/a` is `src/a.rs` or `src/a/mod.rs`.
    children: Vec<String>,
    /// Declarations this check cannot prove are compiled. Each one fails the guards.
    problems: Vec<String>,
}

/// Identifiers and single punctuation characters of already-stripped code.
fn tokens(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    for c in code.chars() {
        if c.is_alphanumeric() || c == '_' {
            word.push(c);
            continue;
        }
        if !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        if !c.is_whitespace() {
            out.push(c.to_string());
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// Index just past the bracket group that opens at `toks[open]`.
fn group_end(toks: &[String], open: usize) -> usize {
    let mut depth = 0_usize;
    for (at, tok) in toks.iter().enumerate().skip(open) {
        match tok.as_str() {
            "[" | "(" | "{" => depth += 1,
            "]" | ")" | "}" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return at + 1;
                }
            }
            _ => {}
        }
    }
    toks.len()
}

/// Why an attribute stops this check proving a module is compiled, if it does.
/// `cfg(test)` is fine because `cargo test` compiles it; everything else that can
/// compile a module out (`cfg`, `cfg_attr(…, cfg(…))`) or move it (`path`,
/// `cfg_attr(…, path = …)`) fails closed unless it is in `CFG_ALLOWLIST`.
fn attribute_problem(file: &str, attr: &[String]) -> Option<String> {
    let text = attr.concat();
    let name = attr.first().map_or("", String::as_str);
    let mentions = |ident: &str| attr.iter().any(|tok| tok == ident);
    if name == "path" || (name == "cfg_attr" && mentions("path")) {
        return Some(format!(
            "{file}: `#[{text}]` relocates a module; this check does not resolve `path`"
        ));
    }
    let gates = (name == "cfg" && text != "cfg(test)") || (name == "cfg_attr" && mentions("cfg"));
    if gates && !CFG_ALLOWLIST.contains(&(file, text.as_str())) {
        return Some(format!(
            "{file}: `#[{text}]` can compile a module out; add it to CFG_ALLOWLIST or drop it"
        ));
    }
    None
}

/// Module declarations in one file (`file` is crate-relative). Handles any visibility
/// (`pub`, `pub(crate)`, `pub(super)`, `pub(in …)`, any spacing), several items per line,
/// attributes on the same or earlier lines, and out-of-line children of inline modules.
/// Comments and literals are blanked first. Inner `#![…]` attributes are checked for the
/// enclosing module.
fn scan(file: &str, text: &str) -> Scan {
    let toks = tokens(&strip_non_code(text));
    let base = child_dir(file);
    let mut scan = Scan {
        children: Vec::new(),
        problems: Vec::new(),
    };
    // One entry per open `{`: the inline module's name, or `None` for any other block.
    let mut scopes: Vec<Option<String>> = Vec::new();
    let mut attrs: Vec<Vec<String>> = Vec::new();
    let tok_at = |at: usize| toks.get(at).map_or("", String::as_str);
    let mut i = 0;
    while i < toks.len() {
        let inner = tok_at(i + 1) == "!" && tok_at(i + 2) == "[";
        if tok_at(i) == "#" && (tok_at(i + 1) == "[" || inner) {
            let open = if inner { i + 2 } else { i + 1 };
            let end = group_end(&toks, open);
            let body = toks[open + 1..end.saturating_sub(1).max(open + 1)].to_vec();
            if inner {
                scan.problems.extend(attribute_problem(file, &body));
            } else {
                attrs.push(body);
            }
            i = end;
            continue;
        }
        match tok_at(i) {
            "pub" => {
                i += 1;
                if tok_at(i) == "(" {
                    i = group_end(&toks, i);
                }
                continue;
            }
            "mod" => {
                let name = tok_at(i + 1).to_owned();
                for attr in attrs.drain(..) {
                    if let Some(problem) = attribute_problem(file, &attr) {
                        scan.problems.push(format!("{problem} (on `mod {name}`)"));
                    }
                }
                match tok_at(i + 2) {
                    ";" => {
                        let mut stem = base.clone();
                        for inline in scopes.iter().flatten() {
                            stem = format!("{stem}/{inline}");
                        }
                        scan.children.push(format!("{stem}/{name}"));
                    }
                    "{" => scopes.push(Some(name)),
                    _ => scan
                        .problems
                        .push(format!("{file}: unrecognised declaration `mod {name}`")),
                }
                i += 3;
                continue;
            }
            "{" => scopes.push(None),
            "}" => {
                scopes.pop();
            }
            _ => {}
        }
        attrs.clear();
        i += 1;
    }
    scan
}

/// Directory that holds the children of `file` (a path relative to the crate root).
fn child_dir(file: &str) -> String {
    let (dir, name) = file.rsplit_once('/').unwrap();
    match name {
        "lib.rs" | "main.rs" | "mod.rs" => dir.to_owned(),
        _ => format!("{dir}/{}", name.trim_end_matches(".rs")),
    }
}

/// The module tree reached from both crate roots (every `src/` file `cargo test`
/// compiles), plus every declaration the scan could not prove compiled.
fn module_tree() -> (BTreeSet<String>, Vec<String>) {
    let root = crate_root();
    let mut seen = BTreeSet::new();
    let mut problems = Vec::new();
    let mut queue = vec!["src/lib.rs".to_owned(), "src/main.rs".to_owned()];
    while let Some(file) = queue.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let text = fs::read_to_string(root.join(&file)).unwrap();
        let mut scan = scan(&file, &text);
        problems.append(&mut scan.problems);
        for stem in scan.children {
            let found = [format!("{stem}.rs"), format!("{stem}/mod.rs")]
                .into_iter()
                .find(|path| root.join(path).is_file());
            match found {
                Some(path) => queue.push(path),
                None => problems.push(format!("{file}: no file backs module `{stem}`")),
            }
        }
    }
    (seen, problems)
}

/// Every `src/` file `cargo test` compiles. Fails, naming them, on declarations the
/// scan cannot prove compiled.
fn compiled_sources() -> BTreeSet<String> {
    let (compiled, problems) = module_tree();
    assert!(
        problems.is_empty(),
        "module declarations this check cannot prove are compiled: {problems:?}"
    );
    compiled
}

fn is_rust(path: &str) -> bool {
    Path::new(path).extension().is_some_and(|ext| ext == "rs")
}

/// `src/…/*.rs` paths named in `cell`.
fn src_paths(cell: &str) -> Vec<String> {
    cell.match_indices("src/")
        .filter(|(at, _)| {
            at.checked_sub(1)
                .is_none_or(|i| !cell.as_bytes()[i].is_ascii_alphanumeric())
        })
        .map(|(at, _)| {
            cell[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '/' | '.'))
                .collect::<String>()
        })
        .filter(|path| is_rust(path))
        .collect()
}

/// Current `src/` files that the per-area sections say hold rebuilt code: every path
/// outside the legacy (first) column of a claiming row, and every bullet that starts
/// with a backticked `src/` path.
fn claimed_targets(doc: &str) -> BTreeSet<String> {
    let body = &doc[..doc.find(UNLISTED_HEADING).expect("unlisted section")];
    let mut out = BTreeSet::new();
    for line in body.lines() {
        if let Some(row) = line.strip_prefix("| ") {
            let cells: Vec<&str> = row.split(" |").map(str::trim).collect();
            let claims = cells
                .iter()
                .skip(1)
                .any(|cell| CLAIMS.iter().any(|claim| cell.starts_with(claim)));
            if claims {
                out.extend(cells.iter().skip(1).flat_map(|cell| src_paths(cell)));
            }
        } else if let Some(item) = line.strip_prefix("- `src/") {
            out.extend(src_paths(&format!("src/{item}")).into_iter().take(1));
        }
    }
    out
}

fn uncompiled(claimed: &BTreeSet<String>, compiled: &BTreeSet<String>) -> Vec<String> {
    claimed.difference(compiled).cloned().collect()
}

#[test]
fn every_rebuilt_target_is_compiled() {
    let claimed = claimed_targets(&doc());
    assert!(
        claimed.contains("src/diamond.rs") && claimed.contains("src/dmarc.rs"),
        "claim parser found too little: {claimed:?}"
    );
    let missing = uncompiled(&claimed, &compiled_sources());
    assert!(
        missing.is_empty(),
        "DISPOSITIONS claims code lives in files outside the compiled module tree: {missing:?}"
    );
}

#[test]
fn every_src_file_is_compiled() {
    let root = crate_root();
    let mut files = BTreeSet::new();
    files_under(&root.join("src"), root, &mut files);
    files.retain(|path| is_rust(path));
    let missing = uncompiled(&files, &compiled_sources());
    assert!(
        missing.is_empty(),
        "src files outside the compiled module tree are never built or tested: {missing:?}"
    );
}

#[test]
fn claim_check_flags_an_uncompiled_target() {
    let doc = format!(
        "| `src/core/x.rs` | 1 | REBUILT | `src/x.rs`, `src/y/mod.rs` tests | why |\n\
         | `src/core/z.rs` | 1 | PENDING | `src/z.rs` | not yet |\n\
         - `src/w.rs`\n{UNLISTED_HEADING}\n- `src/after.rs`\n"
    );
    let claimed = claimed_targets(&doc);
    let want: BTreeSet<String> = ["src/w.rs", "src/x.rs", "src/y/mod.rs"]
        .map(str::to_owned)
        .into();
    assert_eq!(claimed, want);
    let compiled: BTreeSet<String> = ["src/x.rs".to_owned()].into();
    assert_eq!(
        uncompiled(&claimed, &compiled),
        ["src/w.rs", "src/y/mod.rs"]
    );
}

#[test]
fn module_tree_follows_mod_rs_and_nested_files() {
    let compiled = compiled_sources();
    for path in [
        "src/lib.rs",
        "src/main.rs",
        "src/hibp/mod.rs",
        "src/hibp/tests.rs",
        "src/eval/stats.rs",
    ] {
        assert!(compiled.contains(path), "{path} missing from {compiled:?}");
    }
    assert_eq!(child_dir("src/lib.rs"), "src");
    assert_eq!(child_dir("src/hibp/mod.rs"), "src/hibp");
    assert_eq!(child_dir("src/geo.rs"), "src/geo");
}

/// Children of `text` as if it were `file`, asserting the scan raised no problem.
fn children(file: &str, text: &str) -> Vec<String> {
    let scan = scan(file, text);
    assert!(scan.problems.is_empty(), "{text:?}: {:?}", scan.problems);
    scan.children
}

#[test]
fn scan_ignores_comments_and_literals() {
    let hidden = concat!(
        "/* outer /* nested */\npub mod gone;\n*/\n",
        "// mod line_comment;\n",
        "const S: &str = \"\nmod in_string;\n\";\n",
        "const R: &str = r#\"\nmod in_raw;\n\"#;\n",
        "const B: &[u8] = br\"\\\";\npub mod after_byte_raw;\nconst T: &str = \"x\";\n",
        "const C: &core::ffi::CStr = cr\"\\\";\npub mod after_c_raw;\nconst U: &str = \"x\";\n",
        "const Q: char = '\"';\nfn f<'a>(_: &'a str) {}\n",
        "#[doc = \"mod in_doc;\"]\npub mod kept;\n",
    );
    assert_eq!(
        children("src/lib.rs", hidden),
        ["src/after_byte_raw", "src/after_c_raw", "src/kept"]
    );
}

/// Forms from review 5395609494 that used to be misread as uncompiled, or panicked.
#[test]
fn scan_reads_every_valid_declaration_form() {
    let cases: [(&str, &str, &[&str]); 9] = [
        (
            "src/lib.rs",
            "pub mod a;\npub(crate) mod b;\n    mod c;\n",
            &["src/a", "src/b", "src/c"],
        ),
        ("src/lib.rs", "#[cfg(test)] mod hidden;\n", &["src/hidden"]),
        (
            "src/lib.rs",
            "#[cfg(test)]\n#[allow(dead_code)]\nmod tests;\n",
            &["src/tests"],
        ),
        ("src/lib.rs", "mod a; mod b;\n", &["src/a", "src/b"]),
        (
            "src/lib.rs",
            "pub  mod x;\npub(crate)  mod y;\npub( super )  mod z;\npub(in crate::q) mod w;\n",
            &["src/x", "src/y", "src/z", "src/w"],
        ),
        (
            "src/lib.rs",
            "pub mod zzinline {\n    pub mod deep;\n    fn f() { let _ = 1; }\n}\nmod after;\n",
            &["src/zzinline/deep", "src/after"],
        ),
        (
            "src/geo.rs",
            "mod inner { mod deeper { mod leaf; } }\n",
            &["src/geo/inner/deeper/leaf"],
        ),
        (
            "src/lib.rs",
            "#[cfg(unix)]\nfn f() {}\nmod plain;\n",
            &["src/plain"],
        ),
        (
            "src/lib.rs",
            "#![deny(unsafe_code)]\n#![allow(clippy::all)]\npub mod top;\n",
            &["src/top"],
        ),
    ];
    for (file, text, want) in cases {
        assert_eq!(children(file, text), want, "{text:?}");
    }
}

/// Forms from review 5395609494 that used to pass although rustc may never compile
/// the module, or compiles a different file. Each must fail and name the declaration.
#[test]
fn scan_fails_closed_on_cfg_and_path() {
    let cases = [
        (
            "#[cfg(any())]\npub mod zzdead;\n",
            "`#[cfg(any())]`",
            "mod zzdead",
        ),
        ("#[cfg(not(test))] mod n;\n", "`#[cfg(not(test))]`", "mod n"),
        (
            "#[cfg(unix)]\n#[doc = \"d\"]\nmod u;\n",
            "`#[cfg(unix)]`",
            "mod u",
        ),
        (
            "#[cfg_attr(all(), cfg(any()))]\nmod g;\n",
            "cfg_attr",
            "mod g",
        ),
        (
            "#[cfg_attr(all(), path = \"elsewhere.rs\")]\nmod p;\n",
            "cfg_attr",
            "mod p",
        ),
        ("#[path = \"x.rs\"]\nmod p;\n", "`#[path=]`", "mod p"),
        (
            "#[doc = \"d\"] #[path = \"x.rs\"] pub mod p;\n",
            "`#[path=]`",
            "mod p",
        ),
        (
            "mod outer {\n    #[path = \"x.rs\"]\n    mod p;\n}\n",
            "`#[path=]`",
            "mod p",
        ),
        ("#![cfg(any())]\nmod m;\n", "`#[cfg(any())]`", "src/lib.rs"),
    ];
    for (text, attr, decl) in cases {
        let scan = scan("src/lib.rs", text);
        assert!(
            scan.problems
                .iter()
                .any(|p| p.starts_with("src/lib.rs:") && p.contains(attr) && p.contains(decl)),
            "{text:?} was not reported: {scan:?}"
        );
    }
}
