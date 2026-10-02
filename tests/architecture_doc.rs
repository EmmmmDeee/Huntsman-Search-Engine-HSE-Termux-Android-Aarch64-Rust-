//! `ARCHITECTURE.md` claims a module map and a capability table. This test recomputes
//! both from the tree, so a module that is renamed, added or removed without the map
//! changing, a section out of order, or a stale status count fails the build.

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

const STATUSES: [&str; 3] = ["REIMPLEMENTED", "PARTIAL", "NOT YET REBUILT"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn doc() -> String {
    fs::read_to_string(root().join("ARCHITECTURE.md")).unwrap()
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

/// Cells of every table body row (header and separator rows excluded).
fn table_rows(body: &str) -> Vec<Vec<&str>> {
    let mut rows: Vec<Vec<&str>> = body
        .lines()
        .filter_map(|l| l.strip_prefix('|')?.strip_suffix('|'))
        .map(|l| l.split('|').map(str::trim).collect())
        .collect();
    rows.retain(|cells: &Vec<&str>| !cells[0].starts_with("---"));
    if !rows.is_empty() {
        rows.remove(0);
    }
    rows
}

/// Backticked names in the second column of the ARCHITECTURE module map.
fn mapped_modules(markdown: &str) -> Vec<String> {
    table_rows(section(markdown, "ARCHITECTURE"))
        .iter()
        .flat_map(|cells| cells.get(1).copied().unwrap_or("").split(','))
        .filter_map(|name| {
            let name = name.trim();
            Some(name.strip_prefix('`')?.strip_suffix('`')?.to_owned())
        })
        .collect()
}

/// Top-level modules declared in `src/lib.rs`.
fn declared_modules(lib: &str) -> BTreeSet<String> {
    lib.lines()
        .map(str::trim)
        .filter_map(|l| {
            l.strip_prefix("pub mod ")
                .or_else(|| l.strip_prefix("mod "))
        })
        .filter_map(|l| l.strip_suffix(';'))
        .map(str::to_owned)
        .collect()
}

fn exists_in_src(name: &str) -> bool {
    let src = root().join("src");
    src.join(format!("{name}.rs")).is_file() || src.join(name).join("mod.rs").is_file()
}

#[test]
fn sections_appear_in_order() {
    assert_eq!(headings(&doc()), SECTIONS);
}

#[test]
fn every_mapped_module_exists_in_src() {
    let mapped = mapped_modules(&doc());
    assert!(mapped.len() > 50, "module map looks empty: {mapped:?}");
    let missing: Vec<&String> = mapped.iter().filter(|m| !exists_in_src(m)).collect();
    assert!(missing.is_empty(), "map names absent modules: {missing:?}");
    let mut seen = BTreeSet::new();
    let twice: Vec<&String> = mapped.iter().filter(|m| !seen.insert(*m)).collect();
    assert!(twice.is_empty(), "map lists modules twice: {twice:?}");
}

#[test]
fn every_src_module_is_mapped() {
    let lib = fs::read_to_string(root().join("src/lib.rs")).unwrap();
    let declared = declared_modules(&lib);
    assert!(declared.len() > 50, "lib.rs parse failed: {declared:?}");
    let mapped: BTreeSet<String> = mapped_modules(&doc()).into_iter().collect();
    let unmapped: Vec<&String> = declared.difference(&mapped).collect();
    assert!(
        unmapped.is_empty(),
        "src/lib.rs modules missing from ARCHITECTURE.md: {unmapped:?}"
    );
    assert!(mapped.contains("main"), "binary `main` is not in the map");
    for entry in fs::read_dir(root().join("src")).unwrap() {
        let path = entry.unwrap().path();
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        let is_module =
            path.extension().is_some_and(|e| e == "rs") || path.join("mod.rs").is_file();
        if is_module && stem != "lib" {
            assert!(
                mapped.contains(&stem),
                "{} is not in the module map",
                Path::new("src").join(path.file_name().unwrap()).display()
            );
        }
    }
}

#[test]
fn status_counts_match_the_capability_table() {
    let doc = doc();
    let body = section(&doc, "CAPABILITIES");
    let mut counts: BTreeMap<&str, usize> = STATUSES.iter().map(|s| (*s, 0)).collect();
    let mut regressions = 0;
    let rows = table_rows(body);
    for cells in &rows {
        let status = cells.get(3).copied().unwrap_or("");
        let found: Vec<&str> = STATUSES
            .iter()
            .copied()
            .filter(|s| status.starts_with(s))
            .collect();
        assert_eq!(found.len(), 1, "row {cells:?} has no single status");
        *counts.get_mut(found[0]).unwrap() += 1;
        regressions += usize::from(status.contains("REGRESSION"));
        let criteria = cells.last().copied().unwrap_or("");
        assert!(
            criteria.starts_with("D, N"),
            "row {} lacks the D and N acceptance criteria",
            cells[0]
        );
    }
    let claim = format!(
        "Status counts: REIMPLEMENTED {}, PARTIAL {}, NOT YET REBUILT {} ({regressions} of {} rows are regressions).",
        counts["REIMPLEMENTED"],
        counts["PARTIAL"],
        counts["NOT YET REBUILT"],
        rows.len()
    );
    assert!(body.contains(&claim), "CAPABILITIES should state: {claim}");
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
    assert_eq!(
        declared_modules("pub mod a;\nmod b;\npub use a::X;\n"),
        BTreeSet::from(["a".to_owned(), "b".to_owned()])
    );
}
