//! `ARCHITECTURE.md` makes claims about the module tree and the capability table. This
//! test recomputes them from `src/`, so any of these fails the build:
//! - a compiled module missing from the map, mapped twice, placed in an unknown layer, or
//!   moved from its pinned layer;
//! - a "Not compiled" entry that `src/lib.rs` does compile, or that does not exist;
//! - a `crate::` dependency on a higher layer that the map does not list as an exception,
//!   or a stated cycle or exception that the code does not have;
//! - a capability row removed, renamed or renumbered, an unknown status or acceptance
//!   criterion, or a stale status count;
//! - a section out of order.
//!
//! Text inside HTML comments is ignored, because GitHub does not render it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const SECTIONS: [&str; 12] = [
    "OBJECTIVE",
    "CAPABILITIES",
    "ARCHITECTURE",
    "BOUNDARIES",
    "CONTRACTS",
    "INVARIANTS",
    "DATA",
    "EXECUTION",
    "FAILURE MODEL",
    "VERIFICATION",
    "MIGRATION POLICY",
    "ORDERED BACKLOG",
];

/// Module-map rows, in order. A module's layer is its index here.
const LAYERS: [&str; 8] = [
    "L0 primitives",
    "L1 evidence core",
    "L2 network boundary",
    "L3 normalisation",
    "L4 source clients",
    "L5 entity model and analysis",
    "L6 GEOINT and RF",
    "L7 records and outputs",
];

/// Layer of every module the map placed when this test was written, by [`LAYERS`] index.
/// A module that is still compiled must stay in its pinned layer: moving one is a design
/// change, made here and in the map together. A new module needs no pin; the dependency
/// checks place it.
const PINNED_LAYERS: [&str; 8] = [
    "error sha256 json timefmt union_find tags xml uid stage event fsio signals place geohash redact termination circuit oui_ieee oui radar",
    "evidence_ancestry confidence identity_resolution resolve eval",
    "classify source_outcome egress credential_origin http keys fetch fetch_cli deadline",
    "textnorm canonical validation domains address_au postcode_au au_id breach spf dmarc tlsrpt",
    "ckan mediawiki atproto dns hibp service_defs key_health scraper_health recon",
    "entity identity relation graph coref correlator cross_scan dependency module attack attack_catalog exposure profiles leads timeline community diff path pivot intelligence classifier classify_module lineage assurance benchmark coverage diamond gap metrics roi trust",
    "geo geometry rf geoint",
    "ledger session store stix navigator search gexf snake_graph",
];
const BINARY_ROW: &str = "Binary";
/// Optional last row: files in `src/` that `src/lib.rs` does not declare.
const NOT_COMPILED_ROW: &str = "Not compiled (G8)";

const STATUSES: [&str; 3] = ["REIMPLEMENTED", "PARTIAL", "NOT YET REBUILT"];
/// Acceptance criteria codes, in the order a row lists them.
const CRITERIA: [&str; 4] = ["D", "N", "L", "S"];

/// Capability names by row number (index + 1). Restoration only: a row may be added after
/// the last one, but none may be dropped, renamed or renumbered without editing this list.
const PINNED_ROWS: [&str; 23] = [
    "Person lookup by email",
    "Person lookup by username",
    "Person lookup by phone",
    "AU people registers by name",
    "HIBP breach lookup",
    "stolen.tax breach search",
    "Domain recon (crt.sh, DNS, SPF, DMARC)",
    "Unified, recursive and batch scan",
    "Identity resolution on collected evidence",
    "Response cache and source pacing",
    "Saved results, export, diff",
    "Offline utilities: `geo`, `geohash`, `coarsen`, `id`",
    "Guarded fetch and outcome classification: `fetch`, `classify`",
    "Key management",
    "Web meta-search",
    "Entity extraction from text",
    "Web UI and HTTP API",
    "Radio and device sensing",
    "ATT&CK and assurance reports",
    "Diagnostics and self-test",
    "Module catalogue and config",
    "Self-update and release",
    "Remaining subcommands",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn doc() -> String {
    rendered(&fs::read_to_string(root().join("ARCHITECTURE.md")).unwrap())
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ── Markdown ───────────────────────────────────────────────────────────────────────────

/// `markdown` without `<!-- … -->` comments.
fn rendered(markdown: &str) -> String {
    let mut out = String::new();
    let mut rest = markdown;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        let end = rest[start..]
            .find("-->")
            .map_or(rest.len(), |e| start + e + 3);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// `## ` headings in document order.
fn headings(markdown: &str) -> Vec<&str> {
    markdown
        .lines()
        .filter_map(|l| l.strip_prefix("## "))
        .map(str::trim)
        .collect()
}

/// Body of the `## NAME` section, up to the next `## ` heading.
fn section<'a>(markdown: &'a str, name: &str) -> &'a str {
    let start = markdown
        .find(&format!("\n## {name}\n"))
        .unwrap_or_else(|| panic!("no `## {name}` section"))
        + name.len()
        + 5;
    let rest = &markdown[start..];
    &rest[..rest.find("\n## ").unwrap_or(rest.len())]
}

/// Cells of every table body row (header and separator rows excluded). Every row must
/// have both outer pipes and as many cells as the header, so no row renders in GitHub
/// while being skipped here.
fn table_rows(body: &str) -> Vec<Vec<&str>> {
    let mut rows: Vec<Vec<&str>> = Vec::new();
    for line in body.lines().map(str::trim).filter(|l| l.starts_with('|')) {
        let inner = line[1..]
            .strip_suffix('|')
            .unwrap_or_else(|| panic!("table row without a closing `|`: {line}"));
        let cells: Vec<&str> = inner.split('|').map(str::trim).collect();
        if let Some(header) = rows.first() {
            assert_eq!(
                cells.len(),
                header.len(),
                "table row has {} cells, header has {}: {line}",
                cells.len(),
                header.len()
            );
        }
        rows.push(cells);
    }
    rows.retain(|cells| !cells[0].starts_with("---"));
    if !rows.is_empty() {
        rows.remove(0);
    }
    rows
}

/// The text between each pair of backticks.
fn backticked(text: &str) -> Vec<&str> {
    text.split('`').skip(1).step_by(2).collect()
}

fn is_ident(s: &str) -> bool {
    s.chars()
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// The ARCHITECTURE module map.
#[derive(Debug, Default)]
struct ModuleMap {
    /// Module name to layer index into [`LAYERS`].
    layer: BTreeMap<String, usize>,
    binary: Vec<String>,
    binary_role: String,
    not_compiled: Vec<String>,
}

fn module_map(markdown: &str) -> ModuleMap {
    let mut map = ModuleMap::default();
    let mut labels = Vec::new();
    let mut seen = BTreeSet::new();
    for cells in table_rows(section(markdown, "ARCHITECTURE")) {
        let label = cells[0];
        let names: Vec<String> = cells[1]
            .split(',')
            .map(|entry| {
                let entry = entry.trim();
                entry
                    .strip_prefix('`')
                    .and_then(|n| n.strip_suffix('`'))
                    .filter(|n| is_ident(n))
                    .unwrap_or_else(|| {
                        panic!("map row `{label}`: {entry:?} is not a backticked module name")
                    })
                    .to_owned()
            })
            .collect();
        for name in &names {
            assert!(seen.insert(name.clone()), "map lists `{name}` twice");
        }
        if let Some(index) = LAYERS.iter().position(|l| *l == label) {
            for name in names {
                map.layer.insert(name, index);
            }
        } else if label == BINARY_ROW {
            map.binary = names;
            cells[2].clone_into(&mut map.binary_role);
        } else if label == NOT_COMPILED_ROW {
            map.not_compiled = names;
        } else {
            panic!("module map row {label:?} is not a known layer");
        }
        labels.push(label);
    }
    let mut expected: Vec<&str> = LAYERS.to_vec();
    expected.push(BINARY_ROW);
    if labels.last() == Some(&NOT_COMPILED_ROW) {
        expected.push(NOT_COMPILED_ROW);
    }
    assert_eq!(
        labels, expected,
        "module map rows are missing, repeated or out of order"
    );
    map
}

/// The value of the single `- LABEL: …` bullet in `body`.
fn stated<'a>(body: &'a str, label: &str) -> &'a str {
    let prefix = format!("- {label}: ");
    let found: Vec<&str> = body
        .lines()
        .filter_map(|l| l.strip_prefix(prefix.as_str()))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "ARCHITECTURE needs exactly one `{prefix}…` line"
    );
    found[0]
}

/// `` `a` (L3) → `b` (L4); … `` or `none.` as (from, to) pairs.
fn stated_edges(value: &str) -> BTreeSet<(String, String)> {
    if value == "none." {
        return BTreeSet::new();
    }
    let value = value.strip_suffix('.').expect("list ends with `.`");
    value
        .split("; ")
        .map(|edge| match backticked(edge)[..] {
            [from, to] if edge.contains(" → ") => (from.to_owned(), to.to_owned()),
            _ => panic!("upward edge {edge:?} is not `` `from` (Ln) → `to` (Lm) ``"),
        })
        .collect()
}

/// `` `a`–`b`–`c` (L3); … `` as module sets, each checked to sit in the stated layer.
fn stated_cycles(value: &str, map: &ModuleMap) -> BTreeSet<BTreeSet<String>> {
    if value == "none." {
        return BTreeSet::new();
    }
    let value = value.strip_suffix('.').expect("list ends with `.`");
    value
        .split("; ")
        .map(|cycle| {
            let names: BTreeSet<String> =
                backticked(cycle).into_iter().map(str::to_owned).collect();
            let layer = cycle
                .rsplit_once(" (L")
                .and_then(|(_, l)| l.strip_suffix(')'))
                .and_then(|l| l.parse::<usize>().ok())
                .unwrap_or_else(|| panic!("cycle {cycle:?} does not end with its layer `(Ln)`"));
            for name in &names {
                assert_eq!(
                    map.layer.get(name),
                    Some(&layer),
                    "cycle member `{name}` is not in L{layer}"
                );
            }
            names
        })
        .collect()
}

// ── Rust source ────────────────────────────────────────────────────────────────────────

/// `text` with comments and string/char literals blanked to spaces (newlines kept), so a
/// `mod` line or `crate::` path inside `/* … */`, `//` or a (raw) string is not code.
/// Same scanner as `tests/dispositions.rs` on #675 (`bd363d0d`).
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
        // `r` starts a raw string unless it ends an identifier; `br` (byte raw) counts too.
        let ident_before =
            i > 0 && is_ident(i - 1) && !(src[i - 1] == 'b' && (i < 2 || !is_ident(i - 2)));
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

/// Identifiers, `::`, and single punctuation characters.
fn tokens(code: &str) -> Vec<String> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c.is_alphanumeric() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
        } else if c == ':' && chars.get(i + 1) == Some(&':') {
            out.push("::".to_owned());
            i += 2;
        } else {
            out.push(c.to_string());
            i += 1;
        }
    }
    out
}

fn tok(toks: &[String], i: usize) -> &str {
    toks.get(i).map_or("", String::as_str)
}

/// Index just past the bracket group opened at `open`.
fn skip_group(toks: &[String], open: usize) -> usize {
    let mut depth = 0_usize;
    for (i, t) in toks.iter().enumerate().skip(open) {
        match t.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced brackets from token {open}")
}

const CFG_TEST: [&str; 7] = ["#", "[", "cfg", "(", "test", ")", "]"];

/// `toks` with every item under `#[cfg(test)]` removed, plus the names of out-of-line
/// `#[cfg(test)] mod x;` declarations it removed.
fn without_test_items(toks: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut out, mut test_mods) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < toks.len() {
        if !toks[i..].iter().map(String::as_str).take(7).eq(CFG_TEST) {
            out.push(toks[i].clone());
            i += 1;
            continue;
        }
        i += CFG_TEST.len();
        while tok(toks, i) == "#" && tok(toks, i + 1) == "[" {
            i = skip_group(toks, i + 1);
        }
        let start = i;
        let mut depth = 0_usize;
        loop {
            match tok(toks, i) {
                "" => panic!("unterminated #[cfg(test)] item"),
                "(" | "[" => depth += 1,
                ")" | "]" => depth -= 1,
                ";" | "," if depth == 0 => {
                    i += 1;
                    break;
                }
                "}" if depth == 0 => break,
                "{" if depth == 0 => {
                    i = skip_group(toks, i);
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        let item = &toks[start..i];
        if let Some(p) = item.iter().position(|t| t == "mod") {
            if item.len() == p + 3 && item[p + 2] == ";" {
                test_mods.push(item[p + 1].clone());
            }
        }
    }
    (out, test_mods)
}

/// What one source file declares and references, outside `#[cfg(test)]`.
#[derive(Debug, Default, PartialEq)]
struct Scan {
    /// Out-of-line `mod x;` at file level.
    mods: Vec<String>,
    /// Out-of-line `#[cfg(test)] mod x;`.
    test_mods: Vec<String>,
    /// First segment of every path that starts at the crate root (`krate::` or enough
    /// `super::`), including each item of a `krate::{…}` group.
    roots: Vec<String>,
}

/// Scan a file `level` modules below the crate root. `krate` is the root path keyword:
/// `crate` inside the library, `huntsman_recon` from the binary.
fn scan(code: &str, level: usize, krate: &str) -> Scan {
    let (toks, test_mods) = without_test_items(&tokens(&strip_non_code(code)));
    let mut scan = Scan {
        test_mods,
        ..Scan::default()
    };
    let heads = |at: usize| -> Vec<String> {
        if tok(&toks, at) != "{" {
            return vec![tok(&toks, at).to_owned()];
        }
        let (end, mut depth, mut out) = (skip_group(&toks, at), 0_usize, Vec::new());
        for i in at..end {
            match tok(&toks, i) {
                "{" | "(" | "[" => {
                    depth += 1;
                    if depth == 1 {
                        out.push(tok(&toks, i + 1).to_owned());
                    }
                }
                "}" | ")" | "]" => depth -= 1,
                "," if depth == 1 => out.push(tok(&toks, i + 1).to_owned()),
                _ => {}
            }
        }
        out.retain(|h| h != "}");
        out
    };
    let mut depth = 0_usize;
    let mut inline: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let after_path = i > 0 && tok(&toks, i - 1) == "::";
        match tok(&toks, i) {
            "{" => depth += 1,
            "}" => {
                if inline.last() == Some(&depth) {
                    inline.pop();
                }
                depth -= 1;
            }
            "mod" if is_ident(tok(&toks, i + 1)) && tok(&toks, i + 2) == ";" => {
                assert!(
                    depth == 0,
                    "out-of-line `mod` inside a block is not supported"
                );
                scan.mods.push(tok(&toks, i + 1).to_owned());
            }
            "mod" if is_ident(tok(&toks, i + 1)) && tok(&toks, i + 2) == "{" => {
                inline.push(depth + 1);
            }
            t if t == krate && !after_path && tok(&toks, i + 1) == "::" => {
                scan.roots.extend(heads(i + 2));
            }
            "super" if !after_path && tok(&toks, i + 1) == "::" => {
                let (mut n, mut j) = (0, i);
                while tok(&toks, j) == "super" && tok(&toks, j + 1) == "::" {
                    n += 1;
                    j += 2;
                }
                let here = level + inline.len();
                assert!(n <= here, "`super::` path escapes the crate root");
                if n == here {
                    scan.roots.extend(heads(j));
                }
                i = j;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    scan
}

/// The file `mod name;` in `parent` loads.
fn child_file(parent: &Path, name: &str) -> PathBuf {
    let base = match parent.file_name().and_then(|n| n.to_str()) {
        Some("mod.rs" | "lib.rs" | "main.rs") => parent.parent().unwrap().to_path_buf(),
        _ => parent.with_extension(""),
    };
    let flat = base.join(format!("{name}.rs"));
    let nested = base.join(name).join("mod.rs");
    match (flat.is_file(), nested.is_file()) {
        (true, false) => flat,
        (false, true) => nested,
        _ => panic!("`mod {name};` in {} has no single file", parent.display()),
    }
}

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path, out: &mut BTreeSet<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.insert(path);
        }
    }
}

/// The compiled crate as the test sees it.
#[derive(Debug, Default)]
struct Tree {
    /// Modules declared in `src/lib.rs`.
    lib_mods: BTreeSet<String>,
    /// Crate-root items the library re-exports (`pub use m::{X, …}`), to their module.
    reexports: BTreeMap<String, String>,
    /// Top-level module to the top-level modules its non-test code names.
    deps: BTreeMap<String, BTreeSet<String>>,
    /// Library modules the binary names.
    main_deps: BTreeSet<String>,
    /// Files reached through `mod` declarations, test-only ones included.
    reached: BTreeSet<PathBuf>,
}

impl Tree {
    fn load() -> Self {
        let src = root().join("src");
        let lib_path = src.join("lib.rs");
        let lib_code = read(&lib_path);
        let lib = scan(&lib_code, 0, "crate");
        let mut tree = Tree {
            lib_mods: lib.mods.iter().cloned().collect(),
            reexports: reexports(&lib_code),
            ..Tree::default()
        };
        tree.reached.insert(lib_path.clone());
        tree.mark_test_only(&lib_path, &lib.test_mods);
        for module in lib.mods.clone() {
            let mut roots = Vec::new();
            tree.walk(&child_file(&lib_path, &module), 1, "crate", &mut roots);
            let deps = tree.resolve(&roots, &module);
            tree.deps.insert(module, deps);
        }
        let main_path = src.join("main.rs");
        let mut roots = Vec::new();
        tree.walk(&main_path, 0, "huntsman_recon", &mut roots);
        tree.main_deps = tree.resolve(&roots, "main");
        let investigate_path = src.join("bin/investigate.rs");
        let mut investigate_roots = Vec::new();
        tree.walk(
            &investigate_path,
            0,
            "huntsman_recon",
            &mut investigate_roots,
        );
        tree.main_deps
            .extend(tree.resolve(&investigate_roots, "investigate"));
        tree
    }

    fn walk(&mut self, file: &Path, level: usize, krate: &str, roots: &mut Vec<String>) {
        assert!(
            self.reached.insert(file.to_path_buf()),
            "{} loaded twice",
            file.display()
        );
        let found = scan(&read(file), level, krate);
        roots.extend(found.roots);
        self.mark_test_only(file, &found.test_mods);
        for name in found.mods {
            self.walk(&child_file(file, &name), level + 1, krate, roots);
        }
    }

    /// Test-only files are reached but not scanned for dependencies.
    fn mark_test_only(&mut self, parent: &Path, names: &[String]) {
        for name in names {
            let file = child_file(parent, name);
            let dir = if file.ends_with("mod.rs") {
                file.parent().unwrap().to_path_buf()
            } else {
                file.with_extension("")
            };
            self.reached.insert(file);
            if dir.is_dir() {
                rust_files(&dir, &mut self.reached);
            }
        }
    }

    /// Top-level modules named by root-path heads, `from` itself excluded.
    fn resolve(&self, heads: &[String], from: &str) -> BTreeSet<String> {
        heads
            .iter()
            .map(|head| {
                if self.lib_mods.contains(head) {
                    head.clone()
                } else {
                    self.reexports.get(head).cloned().unwrap_or_else(|| {
                        panic!("`{from}` names crate-root item `{head}`, which is no module or re-export")
                    })
                }
            })
            .filter(|m| m != from)
            .collect()
    }
}

/// `pub use m::{A, B};` / `pub use m::A;` in `src/lib.rs`, as item name to module.
fn reexports(lib: &str) -> BTreeMap<String, String> {
    let (toks, _) = without_test_items(&tokens(&strip_non_code(lib)));
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < toks.len() {
        if tok(&toks, i) == "pub" && tok(&toks, i + 1) == "use" {
            let module = tok(&toks, i + 2).to_owned();
            let mut j = i + 3;
            while tok(&toks, j) != ";" {
                let t = tok(&toks, j);
                if is_ident(t) && !matches!(t, "self" | "as") {
                    out.insert(t.to_owned(), module.clone());
                }
                j += 1;
            }
            i = j;
        }
        i += 1;
    }
    out
}

/// Sets of two or more modules that all reach each other.
fn cycles(deps: &BTreeMap<String, BTreeSet<String>>) -> BTreeSet<BTreeSet<String>> {
    let reach = |from: &String| {
        let mut seen = BTreeSet::new();
        let mut todo = vec![from.clone()];
        while let Some(m) = todo.pop() {
            for d in deps.get(&m).into_iter().flatten() {
                if seen.insert(d.clone()) {
                    todo.push(d.clone());
                }
            }
        }
        seen
    };
    let reachable: BTreeMap<&String, BTreeSet<String>> =
        deps.keys().map(|m| (m, reach(m))).collect();
    reachable
        .iter()
        .filter(|(m, r)| r.contains(**m))
        .map(|(m, r)| {
            r.iter()
                .filter(|o| reachable[o].contains(*m))
                .cloned()
                .collect::<BTreeSet<String>>()
        })
        .filter(|c| c.len() > 1)
        .collect()
}

/// `L0, L1 and L2`.
fn layer_list(layers: &BTreeSet<usize>) -> String {
    let names: Vec<String> = layers.iter().map(|l| format!("L{l}")).collect();
    match names.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

// ── Capabilities ───────────────────────────────────────────────────────────────────────

/// Status of a CAPABILITIES row and whether it is a regression. The cell is `STATUS`,
/// `STATUS. REGRESSION` or `STATUS. REGRESSION: note`.
fn parse_status(cell: &str) -> (&'static str, bool) {
    let status = STATUSES
        .iter()
        .copied()
        .find(|s| cell.starts_with(s))
        .unwrap_or_else(|| panic!("unknown status {cell:?}"));
    let rest = &cell[status.len()..];
    let regression = match rest {
        "" => false,
        ". REGRESSION" => true,
        _ if rest.starts_with(". REGRESSION: ") => true,
        _ => panic!("status {cell:?} is not `STATUS[. REGRESSION[: note]]`"),
    };
    assert!(
        !(regression && status == "REIMPLEMENTED"),
        "a REIMPLEMENTED row cannot be a regression: {cell:?}"
    );
    (status, regression)
}

/// Acceptance criteria codes of a row: `D, N[, L[ (qualifier)]][, S][. note]`.
fn parse_criteria(cell: &str) -> Vec<&str> {
    let codes = cell.split_once(". ").map_or(cell, |(codes, _)| codes);
    let found: Vec<&str> = codes
        .split(", ")
        .map(|item| {
            let code = match item.split_once(" (") {
                Some((code, qualifier)) if qualifier.len() > 1 && qualifier.ends_with(')') => code,
                Some(_) => panic!("criterion {item:?} has a malformed qualifier"),
                None => item,
            };
            CRITERIA
                .iter()
                .copied()
                .find(|c| *c == code)
                .unwrap_or_else(|| panic!("unknown acceptance criterion {item:?} in {cell:?}"))
        })
        .collect();
    let order: Vec<usize> = found
        .iter()
        .map(|c| CRITERIA.iter().position(|k| k == c).unwrap())
        .collect();
    assert!(
        order.windows(2).all(|w| w[0] < w[1]),
        "criteria {cell:?} are repeated or out of D, N, L, S order"
    );
    assert!(
        found.starts_with(&["D", "N"]),
        "criteria {cell:?} lack D and N"
    );
    found
}

// ── Tests ──────────────────────────────────────────────────────────────────────────────

#[test]
fn sections_appear_in_order() {
    assert_eq!(headings(&doc()), SECTIONS);
}

#[test]
fn module_map_matches_the_compiled_tree() {
    let map = module_map(&doc());
    let tree = Tree::load();
    assert!(
        tree.lib_mods.len() > 50,
        "lib.rs parse failed: {:?}",
        tree.lib_mods
    );

    let mapped: BTreeSet<String> = map.layer.keys().cloned().collect();
    let unmapped: Vec<&String> = tree.lib_mods.difference(&mapped).collect();
    assert!(
        unmapped.is_empty(),
        "compiled modules missing from the layer rows: {unmapped:?}"
    );
    let uncompiled: Vec<&String> = mapped.difference(&tree.lib_mods).collect();
    assert!(
        uncompiled.is_empty(),
        "layer rows name modules src/lib.rs does not declare: {uncompiled:?}"
    );
    assert_eq!(
        map.binary,
        ["main", "investigate"],
        "the Binary row must name every executable entry point"
    );

    let src = root().join("src");
    for name in &map.not_compiled {
        assert!(
            !tree.lib_mods.contains(name),
            "`{name}` is listed as not compiled, but src/lib.rs declares it"
        );
        let file = src.join(format!("{name}.rs"));
        assert!(
            file.is_file(),
            "`{name}` is listed as not compiled, but {} does not exist",
            file.display()
        );
        assert!(
            !tree.reached.contains(&file),
            "`{name}` is listed as not compiled, but a `mod` loads it"
        );
    }

    let mut all = BTreeSet::new();
    rust_files(&src, &mut all);
    let listed: BTreeSet<PathBuf> = map
        .not_compiled
        .iter()
        .map(|n| src.join(format!("{n}.rs")))
        .collect();
    let stray: Vec<String> = all
        .iter()
        .filter(|f| !tree.reached.contains(*f) && !listed.contains(*f))
        .map(|f| f.strip_prefix(root()).unwrap().display().to_string())
        .collect();
    assert!(
        stray.is_empty(),
        "files neither compiled nor in the Not compiled row: {stray:?}"
    );
}

#[test]
fn layer_placement_is_pinned() {
    let map = module_map(&doc());
    let tree = Tree::load();
    for (pinned, names) in PINNED_LAYERS.iter().enumerate() {
        for name in names.split_whitespace() {
            if !tree.lib_mods.contains(name) {
                continue;
            }
            let layer = map.layer.get(name).copied();
            assert_eq!(
                layer,
                Some(pinned),
                "`{name}` is pinned to {}; the map puts it in {:?} (move it in PINNED_LAYERS too if that is intended)",
                LAYERS[pinned],
                layer.map(|l| LAYERS[l])
            );
        }
    }
}

#[test]
fn dependencies_match_the_stated_layering() {
    let doc = doc();
    let body = section(&doc, "ARCHITECTURE");
    let map = module_map(&doc);
    let tree = Tree::load();

    let upward: BTreeSet<(String, String)> = tree
        .deps
        .iter()
        .flat_map(|(from, deps)| deps.iter().map(move |to| (from.clone(), to.clone())))
        .filter(|(from, to)| map.layer[to] > map.layer[from])
        .collect();
    assert_eq!(
        upward,
        stated_edges(stated(body, "Upward edges")),
        "the `- Upward edges:` line does not match the code (computed, then stated)"
    );
    assert_eq!(
        cycles(&tree.deps),
        stated_cycles(stated(body, "Dependency cycles"), &map),
        "the `- Dependency cycles:` line does not match the code (computed, then stated)"
    );

    let used: BTreeSet<usize> = tree.main_deps.iter().map(|m| map.layer[m]).collect();
    let unused: BTreeSet<usize> = (0..LAYERS.len()).filter(|l| !used.contains(l)).collect();
    let mut claim = format!("calls {} directly", layer_list(&used));
    if !unused.is_empty() {
        claim = format!("{claim}, never {}", layer_list(&unused));
    }
    assert!(
        map.binary_role.contains(&claim),
        "the Binary row should say: {claim}"
    );
}

#[test]
fn capability_rows_are_pinned_and_counted() {
    let doc = doc();
    let body = section(&doc, "CAPABILITIES");
    let rows = table_rows(body);
    assert!(
        rows.len() >= PINNED_ROWS.len(),
        "capability rows were removed: {} of {}",
        rows.len(),
        PINNED_ROWS.len()
    );
    let mut counts: BTreeMap<&str, usize> = STATUSES.iter().map(|s| (*s, 0)).collect();
    let mut regressions = 0;
    for (index, cells) in rows.iter().enumerate() {
        let number = (index + 1).to_string();
        assert_eq!(
            cells[0], number,
            "capability rows must be numbered 1, 2, 3, … with no gap or repeat"
        );
        if let Some(name) = PINNED_ROWS.get(index) {
            assert_eq!(
                cells[1], *name,
                "row {number} was renamed, dropped or moved"
            );
        }
        let (status, regression) = parse_status(cells[3]);
        *counts.get_mut(status).unwrap() += 1;
        regressions += usize::from(regression);
        parse_criteria(cells[5]);
    }
    let claim = format!(
        "Status counts: {} ({regressions} of {} rows are regressions).",
        STATUSES
            .iter()
            .map(|s| format!("{s} {}", counts[s]))
            .collect::<Vec<_>>()
            .join(", "),
        rows.len()
    );
    assert!(
        body.lines().any(|l| l == claim),
        "CAPABILITIES should have the line: {claim}"
    );
}

#[test]
fn binary_entrypoint_is_a_thin_composition_root() {
    let main = read(&root().join("src/main.rs"));
    assert!(
        main.contains("mod cli;"),
        "main must delegate to the CLI composition layer"
    );
    assert!(
        main.contains("cli::run("),
        "main must delegate process arguments"
    );
    assert!(
        !main.contains("huntsman_recon::"),
        "business/library dependencies belong below src/cli/, not in src/main.rs"
    );
    assert!(
        main.lines().count() <= 16,
        "src/main.rs regrew into a front controller ({} lines)",
        main.lines().count()
    );
}

#[test]
fn cli_adapters_declare_dependencies_explicitly() {
    let cli = root().join("src/cli");
    let dispatch = read(&cli.join("mod.rs"));
    assert!(
        !dispatch.contains("huntsman_recon::"),
        "src/cli/mod.rs must remain a process router, not a library dependency hub"
    );

    for entry in fs::read_dir(&cli).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let source = read(&path);
        assert!(
            !source.contains("use super::*;"),
            "{} hides adapter coupling behind a parent wildcard import",
            path.display()
        );
        assert!(
            !source.contains("clippy::wildcard_imports"),
            "{} suppresses the explicit-dependency rule",
            path.display()
        );
    }
}

#[test]
fn lookup_adapter_is_a_small_facade() {
    let lookup = read(&root().join("src/cli/lookup.rs"));
    for child in ["mod discovery;", "mod profiles;", "mod scan;"] {
        assert!(lookup.contains(child), "lookup facade is missing {child}");
    }
    assert!(
        !lookup.contains("huntsman_recon::"),
        "lookup facade must not own domain/library dependencies"
    );
    assert!(
        lookup.lines().count() <= 24,
        "src/cli/lookup.rs regrew into a mixed-concern adapter ({} lines)",
        lookup.lines().count()
    );
}

#[test]
fn current_document_does_not_mark_reachable_commands_absent() {
    let markdown = doc();
    let dispatch = read(&root().join("src/cli/mod.rs"));
    let mut commands = BTreeSet::new();
    for line in dispatch.lines() {
        let Some(rest) = line.split_once("Some(\"").map(|(_, rest)| rest) else {
            continue;
        };
        let Some((command, tail)) = rest.split_once("\")") else {
            continue;
        };
        if tail.contains("=>") {
            commands.insert(command.to_owned());
        }
    }
    assert!(commands.contains("serve"), "command extraction lost serve");
    assert!(commands.contains("recon"), "command extraction lost recon");

    for command in commands {
        for stale in [
            format!("`{command}` remains absent"),
            format!("`{command}` exits 64"),
            format!("`{command}` has no caller"),
        ] {
            assert!(
                !markdown.contains(&stale),
                "ARCHITECTURE contradicts reachable command {command:?}: {stale:?}"
            );
        }
    }
}

#[test]
fn parsers_hold_on_known_inputs() {
    let md = "# T\n\n## A\n\n| L | Modules | R |\n| --- | --- | --- |\n| L0 | `x`, `y_z` | r `q` |\n\n## B\ntext\n";
    assert_eq!(headings(md), ["A", "B"]);
    assert_eq!(section(md, "B"), "text\n");
    assert_eq!(
        table_rows(section(md, "A")),
        [vec!["L0", "`x`, `y_z`", "r `q`"]]
    );
    assert_eq!(rendered("a<!-- b\nc -->d"), "ad");
    assert!(
        std::panic::catch_unwind(|| table_rows("| a | b |\n| --- | --- |\n| 1 | 2\n")).is_err()
    );
    assert!(
        std::panic::catch_unwind(|| table_rows("| a | b |\n| --- | --- |\n| 1 | 2 | 3 |\n"))
            .is_err()
    );

    // Declarations: any visibility, attributes on the same line, trailing comments; not
    // in comments, strings or `#[cfg(test)]` items.
    let lib = concat!(
        "pub mod a;\npub(crate) mod b; // c\n#[cfg(unix)] pub mod c;\nmod d {\n}\n",
        "/* pub mod ghost; */\nconst S: &str = \"\nmod in_string;\n\";\n",
        "#[cfg(test)]\nmod tests;\n",
    );
    let found = scan(lib, 0, "crate");
    assert_eq!(found.mods, ["a", "b", "c"]);
    assert_eq!(found.test_mods, ["tests"]);

    // Root paths: `use`, `pub use`, groups, inline paths, `super::` that reaches the root.
    let code = concat!(
        "use crate::{a::X, b::{Y, Z}, c};\npub use crate::d;\nfn f() { crate::e::g(); }\n",
        "use super::h;\npub(crate) fn k() {}\n// crate::ghost\n",
        "#[cfg(test)]\nmod tests { use crate::only_test; }\n",
        "mod inner { use super::same_file; use super::super::up; }\n",
    );
    assert_eq!(
        scan(code, 1, "crate").roots,
        ["a", "b", "c", "d", "e", "h", "up"]
    );
    assert_eq!(
        scan("use super::x;\n", 2, "crate").roots,
        Vec::<String>::new()
    );
    assert_eq!(
        scan("use huntsman_recon::{p, q::R};\n", 0, "huntsman_recon").roots,
        ["p", "q"]
    );

    let deps: BTreeMap<String, BTreeSet<String>> = [("a", "b"), ("b", "a"), ("c", "a")]
        .iter()
        .map(|(f, t)| (f.to_string(), BTreeSet::from([t.to_string()])))
        .collect();
    assert_eq!(
        cycles(&deps),
        BTreeSet::from([BTreeSet::from(["a".to_owned(), "b".to_owned()])])
    );
    assert_eq!(layer_list(&BTreeSet::from([0, 2, 5])), "L0, L2 and L5");

    assert_eq!(parse_status("PARTIAL. REGRESSION: x"), ("PARTIAL", true));
    assert_eq!(parse_status("REIMPLEMENTED"), ("REIMPLEMENTED", false));
    assert_eq!(
        parse_criteria("D, N, L (operator key), S. note"),
        ["D", "N", "L", "S"]
    );
    for bad in [
        "D, Nonsense",
        "D",
        "N, D",
        "D, N, N",
        "D, N, X. note",
        "D, N, L (x",
    ] {
        assert!(
            std::panic::catch_unwind(|| parse_criteria(bad)).is_err(),
            "{bad} accepted"
        );
    }
    for bad in [
        "PARTIALLY",
        "PARTIAL REGRESSION",
        "REIMPLEMENTED. REGRESSION",
        "DONE",
    ] {
        assert!(
            std::panic::catch_unwind(|| parse_status(bad)).is_err(),
            "{bad} accepted"
        );
    }
}
