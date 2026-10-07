use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_rs(dir: &Path, out: &mut BTreeSet<PathBuf>) {
    let mut entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.insert(path);
        }
    }
}

fn strip_leading_attributes(mut line: &str) -> &str {
    loop {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("#[") {
            return trimmed;
        }
        let Some(end) = trimmed.find(']') else {
            return trimmed;
        };
        line = &trimmed[end + 1..];
    }
}

fn declared_file_modules(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in source.lines() {
        let code = raw.split_once("//").map_or(raw, |(code, _)| code);
        let line = strip_leading_attributes(code);
        if line.is_empty() || line.starts_with("/*") || line.starts_with('*') {
            continue;
        }
        let Some((before_semicolon, after)) = line.split_once(';') else {
            continue;
        };
        if !after.trim().is_empty() {
            continue;
        }
        let mut tokens = before_semicolon.split_whitespace().collect::<Vec<_>>();
        let Some(mod_index) = tokens.iter().position(|token| *token == "mod") else {
            continue;
        };
        if mod_index > 1 {
            continue;
        }
        if mod_index == 1 && !tokens[0].starts_with("pub") {
            continue;
        }
        if tokens.len() != mod_index + 2 {
            continue;
        }
        let name = tokens.pop().expect("module name");
        if name
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            out.push(name.to_string());
        }
    }
    out
}

fn module_base(file: &Path) -> PathBuf {
    let parent = file.parent().expect("source parent");
    let stem = file
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if matches!(stem, "lib" | "main" | "mod") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    }
}

fn resolve_child(parent: &Path, name: &str) -> PathBuf {
    let base = module_base(parent);
    let flat = base.join(format!("{name}.rs"));
    let nested = base.join(name).join("mod.rs");
    match (flat.is_file(), nested.is_file()) {
        (true, false) => flat,
        (false, true) => nested,
        (true, true) => panic!(
            "ambiguous Rust module {name}: both {} and {} exist",
            flat.display(),
            nested.display()
        ),
        (false, false) => panic!(
            "{} declares file module {name}, but neither {} nor {} exists",
            parent.display(),
            flat.display(),
            nested.display()
        ),
    }
}

fn module_graph_sources() -> BTreeSet<PathBuf> {
    let src = root().join("src");
    let mut roots = vec![src.join("lib.rs"), src.join("main.rs")];
    let bin = src.join("bin");
    if bin.is_dir() {
        let mut bins = fs::read_dir(&bin)
            .expect("src/bin")
            .map(|entry| entry.expect("bin entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
            .collect::<Vec<_>>();
        bins.sort();
        roots.extend(bins);
    }

    let mut seen = BTreeSet::new();
    let mut pending = roots;
    while let Some(file) = pending.pop() {
        if !file.is_file() || !seen.insert(file.clone()) {
            continue;
        }
        let source = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
        for name in declared_file_modules(&source) {
            pending.push(resolve_child(&file, &name));
        }
    }
    seen
}

#[test]
fn every_rust_source_file_is_reachable_from_a_crate_root() {
    let src = root().join("src");
    let mut all = BTreeSet::new();
    collect_rs(&src, &mut all);
    let reachable = module_graph_sources();
    let orphaned = all.difference(&reachable).collect::<Vec<_>>();
    assert!(
        orphaned.is_empty(),
        "orphan Rust source files are not compiled by any crate root: {orphaned:#?}"
    );
}

#[test]
fn production_source_contains_no_explicit_unfinished_constructs() {
    let src = root().join("src");
    let mut files = BTreeSet::new();
    collect_rs(&src, &mut files);

    let forbidden_compact = [
        "todo!(",
        "unimplemented!(",
        "panic!(\"todo",
        "panic!(\"notimplemented",
        "compile_error!(\"todo",
        "#[allow(dead_code)]",
        "#[allow(unused)]",
    ];

    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert!(
            !source.trim().is_empty(),
            "{} is an empty Rust source file",
            path.display()
        );
        let compact = source
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        for needle in forbidden_compact {
            if compact.contains(needle) {
                violations.push(format!("{} contains {needle}", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "explicit unfinished/dead-code constructs are forbidden in production source:\n{}",
        violations.join("\n")
    );
}
