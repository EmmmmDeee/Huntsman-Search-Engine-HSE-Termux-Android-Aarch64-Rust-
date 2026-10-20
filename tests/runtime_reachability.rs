use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/fixtures.rs"]
mod fixtures;

#[allow(dead_code)]
#[path = "support/rust_code.rs"]
mod rust_code;
use rust_code::{strip_non_code, tok, tokens};

const ALLOWED: [&str; 5] = ["runtime", "adapter", "exporter", "leaf", "diagnostic"];
const REQUIRED_RUNTIME: [&str; 21] = [
    "analysis",
    "collection",
    "community",
    "coref",
    "correlator",
    "coverage",
    "cross_scan",
    "dependency",
    "entity",
    "evidence_ancestry",
    "gap",
    "graph",
    "intelligence",
    "metrics",
    "module",
    "pipeline",
    "pivot",
    "planner",
    "relation",
    "roi",
    "runtime",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn compiled_modules() -> BTreeSet<String> {
    fs::read_to_string(root().join("src/lib.rs"))
        .expect("src/lib.rs")
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("pub mod ")
                .and_then(|name| name.strip_suffix(';'))
                .map(str::to_string)
        })
        .collect()
}

fn dispositions() -> BTreeMap<String, String> {
    let text = fixtures::text("runtime_module_dispositions.tsv");
    let mut out = BTreeMap::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(
            fields.len(),
            3,
            "line {} must have three TSV fields",
            line_number + 1
        );
        let module = fields[0].trim();
        let class = fields[1].trim();
        let rationale = fields[2].trim();
        assert!(
            !module.is_empty(),
            "line {} has empty module",
            line_number + 1
        );
        assert!(ALLOWED.contains(&class), "{module}: unknown class {class}");
        assert!(!rationale.is_empty(), "{module}: missing rationale");
        assert!(
            out.insert(module.to_string(), class.to_string()).is_none(),
            "module {module} classified more than once"
        );
    }
    out
}

#[test]
fn every_compiled_module_has_exactly_one_runtime_disposition() {
    let compiled = compiled_modules();
    let classified = dispositions().into_keys().collect::<BTreeSet<_>>();
    assert_eq!(classified, compiled);
}

#[test]
fn integration_spine_modules_are_runtime_reachable_by_policy() {
    let dispositions = dispositions();
    for module in REQUIRED_RUNTIME {
        assert_eq!(
            dispositions.get(module).map(String::as_str),
            Some("runtime"),
            "{module} must remain part of the runtime spine"
        );
    }
}

/// The spine runs from the one shipped binary, so the prebuilt release reaches it too.
#[test]
fn the_shipped_binary_runs_the_spine() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["plan", "example.com"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("termination="));
}

/// The referrer of a file that is not part of a library module: the binary (`src/main.rs`,
/// `src/cli/`), `src/lib.rs`, an integration test, an example or xtask.
const ROOT: &str = "the binary, lib.rs, tests, examples or xtask";

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The top-level library module a file belongs to: `src/m.rs` and everything under `src/m/`
/// belong to `m`. Every other file is a [`ROOT`].
fn owner(relative: &Path) -> String {
    let mut parts = relative.iter().map(|part| part.to_str().unwrap());
    if parts.next() != Some("src") {
        return ROOT.to_owned();
    }
    match parts.next().map(|name| name.trim_end_matches(".rs")) {
        None | Some("lib" | "main" | "cli") => ROOT.to_owned(),
        Some(module) => module.to_owned(),
    }
}

/// The first identifier of each item in the brace group that opens at `open`, so `m` and `n`
/// in `{m::{self, A}, n}`.
fn group_heads(toks: &[String], open: usize) -> Vec<String> {
    let mut heads = Vec::new();
    let mut depth = 0_usize;
    for i in open..toks.len() {
        match tok(toks, i) {
            "{" | "(" | "[" => {
                depth += 1;
                if depth == 1 {
                    heads.push(tok(toks, i + 1).to_owned());
                }
            }
            "}" | ")" | "]" => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            "," if depth == 1 => heads.push(tok(toks, i + 1).to_owned()),
            _ => {}
        }
    }
    heads.retain(|head| head != "}");
    heads
}

/// The top-level modules the code names from the crate root: `x` in `crate::x`,
/// `huntsman_recon::x` and each head of a `crate::{x, y::{Z}}` group, `pub use` included.
/// Comments (so doctests) and string literals are not code. Outside the library `crate` is
/// the test, example or xtask crate itself, so only `huntsman_recon` counts there.
fn named_modules(code: &str, in_library: bool) -> BTreeSet<String> {
    let toks = tokens(&strip_non_code(code));
    let mut named = BTreeSet::new();
    for i in 0..toks.len() {
        let root = match tok(&toks, i) {
            "huntsman_recon" => true,
            "crate" => in_library,
            _ => false,
        };
        let after_path = i > 0 && tok(&toks, i - 1) == "::";
        if !root || after_path || tok(&toks, i + 1) != "::" {
            continue;
        }
        if tok(&toks, i + 2) == "{" {
            named.extend(group_heads(&toks, i + 2));
        } else {
            named.insert(tok(&toks, i + 2).to_owned());
        }
    }
    named
}

/// A module outside the runtime spine stays only while something reaches it. It is reached
/// when a [`ROOT`] file, a runtime module or a module one of those reaches names it by a
/// `crate::m` or `huntsman_recon::m` path from outside its own files. A module that only its
/// own doctests name, or that only other unreached modules name, is dead.
#[test]
fn every_module_outside_the_spine_is_reached() {
    let root = root();
    let mut files = Vec::new();
    for dir in ["src", "tests", "examples", "xtask"] {
        rust_files(&root.join(dir), &mut files);
    }
    let mut referrers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for file in &files {
        let relative = file.strip_prefix(&root).unwrap();
        let from = owner(relative);
        let code = fs::read_to_string(file).unwrap();
        for name in named_modules(&code, relative.starts_with("src")) {
            if name != from {
                referrers.entry(name).or_default().insert(from.clone());
            }
        }
    }

    let dispositions = dispositions();
    let mut reached: BTreeSet<String> = dispositions
        .iter()
        .filter(|(_, class)| *class == "runtime")
        .map(|(module, _)| module.clone())
        .collect();
    reached.insert(ROOT.to_owned());
    let mut todo: Vec<String> = reached.iter().cloned().collect();
    while let Some(from) = todo.pop() {
        for (name, named_by) in &referrers {
            if named_by.contains(&from) && reached.insert(name.clone()) {
                todo.push(name.clone());
            }
        }
    }

    let unreached: Vec<String> = dispositions
        .keys()
        .filter(|module| !reached.contains(*module))
        .map(|module| match referrers.get(module) {
            None => format!("{module}: nothing outside src/{module} names it"),
            Some(named_by) => format!(
                "{module}: named only by {}, which nothing reaches",
                named_by.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
        })
        .collect();
    assert!(
        unreached.is_empty(),
        "modules nothing reaches (remove them, or add the caller):\n  {}",
        unreached.join("\n  ")
    );
}
