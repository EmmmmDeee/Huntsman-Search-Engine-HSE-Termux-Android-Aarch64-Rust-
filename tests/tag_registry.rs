//! `src/tags.rs` is the one registry of shared entity tags. A tag call that spells a registered
//! tag as a string literal is a second authority for it, which a rename would miss, and a
//! constant nothing uses is a tag no entity can carry.

use std::fs;
use std::path::{Path, PathBuf};

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

/// `(NAME, "value")` for every `pub const NAME: &str = "value";` in `src/tags.rs`.
fn registry(root: &Path) -> Vec<(String, String)> {
    fs::read_to_string(root.join("src/tags.rs"))
        .unwrap()
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("pub const ")?;
            let (name, value) = rest.split_once(": &str = \"")?;
            Some((name.to_owned(), value.strip_suffix("\";")?.to_owned()))
        })
        .collect()
}

#[test]
fn shared_tags_are_named_by_their_constants_and_every_constant_is_used() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tags = registry(&root);
    assert!(tags.len() > 20, "{tags:?}");
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let sources: Vec<(PathBuf, String)> = files
        .into_iter()
        .filter(|path| !path.ends_with("src/tags.rs"))
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            (path, text)
        })
        .collect();

    let mut literals = Vec::new();
    for (path, text) in &sources {
        for (number, line) in text.lines().enumerate() {
            for (name, value) in &tags {
                for call in [".tag(\"", "has_tag(\""] {
                    if line.contains(&format!("{call}{value}\")")) {
                        literals.push(format!(
                            "{}:{}: \"{value}\" is tags::{name}",
                            path.strip_prefix(&root).unwrap().display(),
                            number + 1
                        ));
                    }
                }
            }
        }
    }
    assert!(
        literals.is_empty(),
        "registered tags written as literals:\n{}",
        literals.join("\n")
    );

    let unused: Vec<&str> = tags
        .iter()
        .filter(|(name, _)| {
            !sources.iter().any(|(_, text)| {
                text.match_indices(name.as_str()).any(|(at, _)| {
                    let before = text[..at].chars().next_back();
                    let after = text[at + name.len()..].chars().next();
                    !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                        && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
                })
            })
        })
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(unused.is_empty(), "tag constants nothing uses: {unused:?}");
}
