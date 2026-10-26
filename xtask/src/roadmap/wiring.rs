//! Context-preserving inclusion hints; compilation and runtime liveness remain unverified.
use super::{Blobs, Entry, MAX_SOURCE};
use crate::error::{Error, Result};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use syn::visit::{self, Visit};

fn root(path: &str) -> bool {
    if matches!(
        path,
        "src/lib.rs"
            | "src/main.rs"
            | "xtask/src/lib.rs"
            | "xtask/src/main.rs"
            | "build.rs"
            | "xtask/build.rs"
    ) {
        return true;
    }
    [
        "src/bin/",
        "xtask/src/bin/",
        "tests/",
        "xtask/tests/",
        "examples/",
        "xtask/examples/",
    ]
    .iter()
    .any(|prefix| {
        path.strip_prefix(prefix).is_some_and(|tail| {
            tail.ends_with(".rs") && !tail.contains('/')
                || tail.split('/').count() == 2 && tail.ends_with("/main.rs")
        })
    })
}
fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}
fn join(base: &str, relative: &str) -> Option<String> {
    if relative.starts_with('/') || relative.contains('\\') {
        return None;
    }
    let full = format!("{base}/{relative}");
    let mut parts = Vec::new();
    for part in full.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    let path = parts.join("/");
    super::safe_path(&path).then_some(path)
}
/// None marks an embedded asset. Code loads retain the declaring module directory.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Load {
    path: String,
    module_dir: Option<String>,
}

pub(super) fn scan(
    entries: &[Entry],
    blobs: &mut Blobs,
) -> Result<(BTreeMap<String, String>, Vec<String>)> {
    let known: BTreeMap<&str, &Entry> = entries
        .iter()
        .filter(|e| e.kind == "file")
        .map(|e| (e.path.as_str(), e))
        .collect();
    let mut limitations = BTreeSet::from([
        "Declaration reachability is syntactic across cfg branches, not compiled or runtime reachability; unlinked candidates are not proven dead code.".to_owned(),
        "Conventional Cargo roots are recognised; explicit manifest targets, custom workspaces, macro expansion and generated code require compiler/architecture review.".to_owned(),
        "Compatibility, provider access, legacy parity, Android execution and performance are not assessed by this generator. Run the task acceptance commands and record exact-revision receipts.".to_owned(),
        "Inventory covers the committed Git tree; uncommitted and ignored files, symlink targets and submodule contents are not read.".to_owned(),
    ]);
    let mut pending: VecDeque<Load> = entries
        .iter()
        .filter(|e| e.kind == "file" && root(&e.path))
        .map(|e| Load {
            path: e.path.clone(),
            module_dir: Some(parent(&e.path).to_owned()),
        })
        .collect();
    let mut contexts = BTreeSet::new();
    let mut reached = BTreeSet::new();
    while let Some(load) = pending.pop_front() {
        if !contexts.insert(load.clone()) {
            continue;
        }
        if contexts.len() > 100_000 {
            return Err(Error::Invalid(
                "inclusion graph exceeds 100000 contexts".into(),
            ));
        }
        reached.insert(load.path.clone());
        let Some(module_dir) = load.module_dir else {
            continue;
        };
        let entry = known
            .get(load.path.as_str())
            .ok_or_else(|| Error::Invalid("inclusion target disappeared".into()))?;
        let bytes = blobs.read(entry, MAX_SOURCE)?;
        let parsed = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| syn::parse_file(text).ok());
        let Some(parsed) = parsed else {
            limitations.insert(format!(
                "{}: Rust syntax could not be analysed; inspect fixture/generated/custom syntax",
                load.path
            ));
            continue;
        };
        let mut collector = Inclusion {
            file: &load.path,
            module_dir,
            inline: 0,
            known: &known,
            loads: Vec::new(),
            limitations: &mut limitations,
        };
        collector.visit_file(&parsed);
        pending.extend(collector.loads);
    }
    let result = entries
        .iter()
        .filter(|e| e.kind == "file")
        .map(|e| {
            let status = if root(&e.path) {
                "entrypoint"
            } else if reached.contains(&e.path) {
                "declared_reachable"
            } else if e.path.ends_with(".rs") {
                "unlinked_candidate"
            } else {
                "not_assessed"
            };
            (e.path.clone(), status.to_owned())
        })
        .collect();
    Ok((result, limitations.into_iter().collect()))
}
struct Inclusion<'a> {
    file: &'a str,
    module_dir: String,
    inline: usize,
    known: &'a BTreeMap<&'a str, &'a Entry>,
    loads: Vec<Load>,
    limitations: &'a mut BTreeSet<String>,
}
impl Inclusion<'_> {
    fn uncertain(&mut self, reason: &str) {
        self.limitations.insert(format!("{}: {reason}", self.file));
    }
    fn record(&mut self, path: Option<String>, module_dir: Option<String>) {
        match path {
            Some(path) if self.known.contains_key(path.as_str()) => {
                self.loads.push(Load { path, module_dir })
            }
            _ => self
                .uncertain("literal inclusion is missing, outside the tree, or not a regular file"),
        }
    }
}
impl<'ast> Visit<'ast> for Inclusion<'_> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        let explicit = module
            .attrs
            .iter()
            .find(|attr| attr.path().is_ident("path"));
        if module
            .attrs
            .iter()
            .any(|attr| attr.path().is_ident("cfg_attr"))
        {
            self.uncertain("cfg_attr module attributes are not evaluated");
        }
        if let Some((_, items)) = &module.content {
            if explicit.is_some() {
                self.uncertain("inline #[path] module directory needs compiler review");
                return;
            }
            let outer = self.module_dir.clone();
            self.module_dir = format!("{outer}/{}", module.ident);
            self.inline += 1;
            for item in items {
                self.visit_item(item);
            }
            self.inline -= 1;
            self.module_dir = outer;
        } else if let Some(attr) = explicit {
            let syn::Meta::NameValue(value) = &attr.meta else {
                self.uncertain("unsupported path attribute");
                return;
            };
            let syn::Expr::Lit(literal) = &value.value else {
                self.uncertain("nonliteral path attribute");
                return;
            };
            let syn::Lit::Str(path) = &literal.lit else {
                self.uncertain("nonstring path attribute");
                return;
            };
            let base = if self.inline == 0 {
                parent(self.file)
            } else {
                &self.module_dir
            };
            let path = join(base, &path.value());
            let directory = path.as_deref().map(parent).map(str::to_owned);
            self.record(path, directory);
        } else {
            let direct = join(&self.module_dir, &format!("{}.rs", module.ident));
            let nested = join(&self.module_dir, &format!("{}/mod.rs", module.ident));
            let existing: Vec<_> = [direct, nested]
                .into_iter()
                .flatten()
                .filter(|p| self.known.contains_key(p.as_str()))
                .collect();
            if existing.len() != 1 {
                self.uncertain("module declaration has missing or ambiguous conventional targets");
            }
            let directory = join(&self.module_dir, &module.ident.to_string());
            for path in existing {
                self.record(Some(path), directory.clone());
            }
        }
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(segment) = mac.path.segments.last() {
            let name = segment.ident.to_string();
            if matches!(name.as_str(), "include" | "include_str" | "include_bytes") {
                if let Ok(path) = syn::parse2::<syn::LitStr>(mac.tokens.clone()) {
                    let directory = (name == "include").then(|| self.module_dir.clone());
                    self.record(join(parent(self.file), &path.value()), directory);
                } else {
                    self.uncertain("nonliteral include macro requires expansion review");
                }
            }
        }
        visit::visit_macro(self, mac);
    }
}
