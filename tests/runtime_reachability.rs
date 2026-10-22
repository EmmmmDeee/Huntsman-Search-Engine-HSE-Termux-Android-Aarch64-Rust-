use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/fixtures.rs"]
mod fixtures;

#[allow(dead_code)]
#[path = "support/rust_code.rs"]
mod rust_code;
use rust_code::{strip_non_code, tok, tokens, without_test_items};

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

/// The referrer of a shipped file that is not part of a library module: the binary
/// (`src/main.rs`, `src/cli/`), `src/lib.rs` or xtask.
const ROOT: &str = "the binary, lib.rs or xtask";

/// The referrer of an integration test or an example. A module that only it reaches, directly or
/// through other modules only it reaches, ships without a caller, so it must be `diagnostic`.
const TEST_ROOT: &str = "tests or examples";

/// Modules that nothing shipped reaches and that are not `diagnostic`, kept until their owner
/// decides to wire them into the binary or delete them: module, owner, why it is kept. The list
/// only shrinks: an entry for a module that is gone, shipped or a tested `diagnostic` fails the
/// test.
const PENDING_OWNER_DECISION: [(&str, &str, &str); 6] = [
    (
        "claim_coverage",
        "JEFF DEAN, RALF JUNG",
        "shadow-mode claim kernel: negative-evidence admission only tests/claim_coverage.rs runs",
    ),
    (
        "claim_policy",
        "JEFF DEAN, RALF JUNG",
        "shadow-mode claim kernel: verification policy only the claim and proof tests run",
    ),
    (
        "proof",
        "JEFF DEAN, RALF JUNG",
        "shadow-mode claim kernel: proof environments only the kernel and its tests name",
    ),
    (
        "shadow_assessment",
        "JEFF DEAN, RALF JUNG",
        "shadow-mode claim kernel: assessment reporting only tests/shadow_assessment.rs runs",
    ),
    (
        "resolve",
        "JEFF DEAN, RALF JUNG",
        "L1 automatic_clusters, named only by tests/person_resolution_homonym_live_capture.rs",
    ),
    (
        "radar",
        "JEFF DEAN",
        "sweep and Bluetooth tracking nothing names; wire it into `radar` or delete it",
    ),
];

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

/// The files of the out-of-line `#[cfg(test)] mod name;` that `parent` declares: `name.rs` in
/// `parent`'s module directory, and every file under `name/`.
fn test_module_files(parent: &Path, name: &str, out: &mut Vec<PathBuf>) {
    let base = match parent.file_name().and_then(|n| n.to_str()) {
        Some("mod.rs" | "lib.rs" | "main.rs") => parent.parent().unwrap().to_path_buf(),
        _ => parent.with_extension(""),
    };
    out.push(base.join(format!("{name}.rs")));
    let dir = base.join(name);
    if dir.is_dir() {
        rust_files(&dir, out);
    }
}

/// The top-level library module a file belongs to: `src/m.rs` and everything under `src/m/`
/// belong to `m`. The binary, `src/lib.rs` and xtask are [`ROOT`]; tests and examples are
/// [`TEST_ROOT`].
fn owner(relative: &Path) -> String {
    let mut parts = relative.iter().map(|part| part.to_str().unwrap());
    match parts.next() {
        Some("src") => {}
        Some("tests" | "examples") => return TEST_ROOT.to_owned(),
        _ => return ROOT.to_owned(),
    }
    match parts.next().map(|name| name.trim_end_matches(".rs")) {
        None | Some("lib" | "main" | "cli") => ROOT.to_owned(),
        Some(module) => module.to_owned(),
    }
}

/// The index of the first identifier of each item in the brace group that opens at `open`, so
/// those of `m` and `n` in `{m::{self, A}, n}`.
fn group_heads(toks: &[String], open: usize) -> Vec<usize> {
    let mut heads = Vec::new();
    let mut depth = 0_usize;
    for i in open..toks.len() {
        match tok(toks, i) {
            "{" | "(" | "[" => {
                depth += 1;
                if depth == 1 {
                    heads.push(i + 1);
                }
            }
            "}" | ")" | "]" => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            "," if depth == 1 => heads.push(i + 1),
            _ => {}
        }
    }
    heads.retain(|&head| tok(toks, head) != "}");
    heads
}

/// Whether the `use` at `at` is public at some visibility: `pub use` or `pub(…) use`.
fn is_pub_use(toks: &[String], at: usize) -> bool {
    let Some(mut before) = at.checked_sub(1) else {
        return false;
    };
    if tok(toks, before) == ")" {
        match (0..before).rev().find(|&b| tok(toks, b) == "(") {
            Some(open) if open > 0 => before = open - 1,
            _ => return false,
        }
    }
    tok(toks, before) == "pub"
}

/// The top-level modules `toks` names from the crate root: `x` in `crate::x`,
/// `huntsman_recon::x` and each head of a `crate::{x, y::{Z}}` group. A `pub use` of a whole
/// module (`pub use crate::m;`, `pub use crate::{m, n as o};`) only hands the module on, so it
/// names nothing; a `pub use` of items in one (`pub use crate::m::{A, B};`) names `m`. Outside
/// the library `crate` is the test, example or xtask crate itself, so only `huntsman_recon`
/// counts there.
fn named_modules(toks: &[String], in_library: bool) -> BTreeSet<String> {
    let mut named = BTreeSet::new();
    let mut in_pub_use = false;
    for i in 0..toks.len() {
        let root = match tok(toks, i) {
            "use" => {
                in_pub_use = is_pub_use(toks, i);
                false
            }
            ";" => {
                in_pub_use = false;
                false
            }
            "huntsman_recon" => true,
            "crate" => in_library,
            _ => false,
        };
        let after_path = i > 0 && tok(toks, i - 1) == "::";
        if !root || after_path || tok(toks, i + 1) != "::" {
            continue;
        }
        let heads = if tok(toks, i + 2) == "{" {
            group_heads(toks, i + 2)
        } else {
            vec![i + 2]
        };
        for head in heads {
            let whole_module = tok(toks, head + 1) != "::";
            if !(in_pub_use && whole_module) {
                named.insert(tok(toks, head).to_owned());
            }
        }
    }
    named
}

/// `text` as the gate reads it: comments (so doctests) and string literals are not code, and
/// outside tests and examples neither are `#[cfg(test)]` items. Also returns the names of the
/// out-of-line `#[cfg(test)] mod x;` declarations it removed.
fn gate_tokens(text: &str, from: &str) -> (Vec<String>, Vec<String>) {
    let toks = tokens(&strip_non_code(text));
    if from == TEST_ROOT {
        (toks, Vec::new())
    } else {
        without_test_items(&toks)
    }
}

/// Every module `seeds` reach: a module is reached when a reached referrer names it.
fn reached_from(
    seeds: &[String],
    referrers: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut reached: BTreeSet<String> = seeds.iter().cloned().collect();
    let mut todo = seeds.to_vec();
    while let Some(from) = todo.pop() {
        for (name, named_by) in referrers {
            if named_by.contains(&from) && reached.insert(name.clone()) {
                todo.push(name.clone());
            }
        }
    }
    reached
}

#[test]
fn whole_module_reexports_and_test_items_name_nothing() {
    let code = concat!(
        "pub use crate::whole;\npub(crate) use crate::{grouped, renamed as other};\n",
        "pub use crate::items::{A, B};\npub use crate::{nested::{self, C}, item::D};\n",
        "use crate::imported;\nfn f() { crate::called::g(); }\n",
        "use huntsman_recon::{shipped, also::E};\n",
    );
    let toks = tokens(code);
    assert_eq!(
        named_modules(&toks, true),
        [
            "also", "called", "imported", "item", "items", "nested", "shipped"
        ]
        .map(String::from)
        .into()
    );
    assert_eq!(
        named_modules(&toks, false),
        ["also", "shipped"].map(String::from).into()
    );

    let tested = "fn f() { crate::kept::g(); }\n#[cfg(test)]\nmod tests { use crate::only; }\n";
    assert_eq!(
        named_modules(&gate_tokens(tested, "m").0, true),
        ["kept"].map(String::from).into()
    );
    assert_eq!(
        named_modules(&gate_tokens(tested, TEST_ROOT).0, true),
        ["kept", "only"].map(String::from).into()
    );
}

/// A module outside the runtime spine stays only while something shipped reaches it. It is
/// reached when a [`ROOT`] file, a runtime module or a module one of those reaches names it by
/// a `crate::m` or `huntsman_recon::m` path from outside its own files. `#[cfg(test)]` code and
/// a `pub use` that hands a whole module on name nothing. A module that only [`TEST_ROOT`]
/// reaches, directly or through modules only it reaches, must be `diagnostic` or wait in
/// [`PENDING_OWNER_DECISION`]. A module that only its own doctests name, or that only other
/// unreached modules name, is dead.
#[test]
fn every_module_outside_the_spine_is_reached() {
    let root = root();
    let mut files = Vec::new();
    for dir in ["src", "tests", "examples", "xtask"] {
        rust_files(&root.join(dir), &mut files);
    }
    let mut scanned = Vec::new();
    let mut test_files = Vec::new();
    for file in &files {
        let relative = file.strip_prefix(&root).unwrap();
        let from = owner(relative);
        let (toks, test_mods) = gate_tokens(&fs::read_to_string(file).unwrap(), &from);
        for name in test_mods {
            test_module_files(file, &name, &mut test_files);
        }
        scanned.push((file, relative.starts_with("src"), from, toks));
    }
    let mut referrers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (file, in_library, from, toks) in &scanned {
        if test_files.contains(file) {
            continue;
        }
        for name in named_modules(toks, *in_library) {
            if name != *from {
                referrers.entry(name).or_default().insert(from.clone());
            }
        }
    }

    let dispositions = dispositions();
    let mut seeds: Vec<String> = dispositions
        .iter()
        .filter(|(_, class)| *class == "runtime")
        .map(|(module, _)| module.clone())
        .collect();
    seeds.push(ROOT.to_owned());
    let shipped = reached_from(&seeds, &referrers);
    let tested = reached_from(&[TEST_ROOT.to_owned()], &referrers);
    let named_by = |module: &str| {
        referrers
            .get(module)
            .map(|by| by.iter().cloned().collect::<Vec<_>>().join(", "))
    };
    let pending = |module: &str| PENDING_OWNER_DECISION.iter().any(|entry| entry.0 == module);

    let mut failures = Vec::new();
    for (module, class) in &dispositions {
        let diagnostic = class == "diagnostic" && tested.contains(module);
        if shipped.contains(module) || diagnostic || pending(module) {
            continue;
        }
        failures.push(match named_by(module) {
            None => format!("{module}: nothing outside src/{module} names it"),
            Some(by) if tested.contains(module) => format!(
                "{module}: only {TEST_ROOT} reach it (named by {by}); a {class} module needs a \
                 shipped caller, or the diagnostic class"
            ),
            Some(by) => format!("{module}: named only by {by}, which nothing reaches"),
        });
    }
    for (module, owner, _) in PENDING_OWNER_DECISION {
        let stale = match dispositions.get(module).map(String::as_str) {
            None => Some("is not compiled"),
            Some(_) if shipped.contains(module) => Some("is reached by shipped code"),
            Some("diagnostic") if tested.contains(module) => Some("is a tested diagnostic"),
            Some(_) => None,
        };
        if let Some(why) = stale {
            failures.push(format!(
                "{module}: waits on {owner} but {why}; drop its PENDING_OWNER_DECISION entry"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "modules nothing shipped reaches (remove them, or add the caller):\n  {}",
        failures.join("\n  ")
    );
}
