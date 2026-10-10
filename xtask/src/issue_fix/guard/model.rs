//! The test code of the base commit. Every file under src/ at BASE is read: a Rust file with syn,
//! and any other file as text. A file is wholly test code when its name says so, when it sits under
//! a tests/ directory, when it has an inner `#![cfg(test)]`, or when test code loads it. A module
//! declaration is test code from the first test marker of its file on, or everywhere in a file that
//! is wholly test code. Test code loads the files of its module declarations and of its include!
//! calls, and those files are test code too, so the loading is repeated until it adds nothing. An
//! include! call compiles its file, whatever its position, so a file that an include! names is read
//! for its test markers. Its module declarations resolve as the including module's would, which the
//! guard does not model, so a compiled file with module declarations makes every file test code.

use std::collections::{BTreeMap, BTreeSet};

use super::git;
use super::syntax::{self, FileFacts, ModDecl, PathAttr};
use crate::error::{Error, Result};

/// The test code of one base commit.
pub struct Model {
    base: String,
    /// The files under src/ at BASE, and the files that an include! call names, read for their
    /// facts.
    files: BTreeMap<String, FileFacts>,
    /// Files that test code loads, by their path. A file in this set is wholly test code.
    loaded: BTreeSet<String>,
    /// Directories whose files test code loads. Every file under one is wholly test code.
    dirs: BTreeSet<String>,
    /// Files that a path attribute loads. Their own module declarations resolve in their
    /// directory, as a crate root's do.
    path_loaded: BTreeSet<String>,
    /// Files that an include! call names, in any position, so that the build compiles them.
    included: BTreeSet<String>,
    /// Set when test code loads a path that the guard cannot follow. Then every file under src/
    /// is wholly test code.
    everything: bool,
}

/// One fact that a test declaration or an include! call adds to the model.
enum Protect {
    /// A path that the guard cannot follow.
    Everything,
    /// A file that test code loads by name.
    File(String),
    /// A file that a path attribute loads.
    PathFile(String),
    /// A file that an include! call names. The call is test code when TEST is set, and then the
    /// file is test code too.
    Included { file: String, test: bool },
    /// A directory that test code loads from.
    Dir(String),
}

impl Model {
    /// Reads the files under src/ at BASE and works out the test code. A Rust file that does not
    /// parse is an error, which refuses the change: the guard cannot tell what that file loads.
    pub fn load(base: &str) -> Result<Self> {
        let mut model = Self {
            base: base.to_owned(),
            files: BTreeMap::new(),
            loaded: BTreeSet::new(),
            dirs: BTreeSet::new(),
            path_loaded: BTreeSet::new(),
            included: BTreeSet::new(),
            everything: false,
        };
        for path in git::src_paths(base)? {
            model.read(&path)?;
        }
        model.expand()?;
        Ok(model)
    }

    /// The first line of test code in PATH at BASE, or 0 when it has none or is not a file that the
    /// model reads.
    pub fn start(&self, path: &str) -> usize {
        self.files.get(path).map_or(0, |facts| facts.start)
    }

    /// The texts of the constructs of PATH at BASE that the guard compares with the working tree:
    /// the scope constructs, and the cfg constructs when the file has test code.
    pub fn constructs(&self, path: &str) -> Vec<&str> {
        self.files
            .get(path)
            .map_or_else(Vec::new, |facts| facts.construct_texts(facts.start > 0))
    }

    /// True when PATH at BASE is wholly test code.
    pub fn is_test_file(&self, path: &str) -> bool {
        self.everything
            || is_test_name(path)
            || path.contains("/tests/")
            || self.loaded.contains(path)
            || self.dirs.iter().any(|dir| path.starts_with(dir.as_str()))
            || self
                .files
                .get(path)
                .is_some_and(|facts| facts.inner_cfg_test)
    }

    /// Reads PATH at BASE, unless it is read already. A file that is absent at BASE is not read,
    /// and neither is a file that is not UTF-8, which cannot be compiled. A Rust file is read with
    /// its syntax tree, and any other file as text. The return value says whether this call read
    /// it.
    fn read(&mut self, path: &str) -> Result<bool> {
        if self.files.contains_key(path) {
            return Ok(false);
        }
        let Some(bytes) = git::blob(&self.base, path)? else {
            return Ok(false);
        };
        let rust = path.ends_with(".rs");
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) if rust => {
                return Err(Error::Refused(format!(
                    "cannot parse {path} at {}: not UTF-8",
                    self.base
                )));
            }
            Err(_) => return Ok(false),
        };
        let facts = if rust {
            syntax::read(&text).map_err(|reason| {
                Error::Refused(format!("cannot parse {path} at {}: {reason}", self.base))
            })?
        } else {
            syntax::read_text(&text)
        };
        self.files.insert(path.to_owned(), facts);
        Ok(true)
    }

    /// Adds every test-code fact until a pass adds nothing new.
    fn expand(&mut self) -> Result<()> {
        loop {
            let mut wanted = Vec::new();
            for (path, facts) in &self.files {
                let wholly = self.is_test_file(path);
                let test_at = |line: usize| wholly || (facts.start > 0 && line >= facts.start);
                for decl in &facts.mods {
                    if test_at(decl.line) {
                        self.decl_targets(path, decl, &mut wanted);
                    }
                }
                for include in &facts.includes {
                    let test = test_at(include.line);
                    self.include_target(path, include.path.as_deref(), test, &mut wanted);
                }
                // A module declaration that the syntax tree does not give loads a file that the
                // guard cannot name. In test code of a Rust file, that refuses the change. In a
                // file that the build compiles, every module declaration does the same, as an
                // included file's declarations resolve as the including module's would.
                let unnamed_test = facts.unfollowed_mods.iter().any(|&line| test_at(line));
                let declares = !facts.mods.is_empty() || !facts.unfollowed_mods.is_empty();
                let compiled = self.included.contains(path);
                if (unnamed_test && path.ends_with(".rs")) || (compiled && declares) {
                    wanted.push(Protect::Everything);
                }
            }
            let mut grew = false;
            for protect in wanted {
                grew |= self.apply(protect)?;
            }
            if !grew {
                return Ok(());
            }
        }
    }

    /// Applies one fact to the model. The return value says whether the model grew.
    fn apply(&mut self, protect: Protect) -> Result<bool> {
        match protect {
            Protect::Everything => Ok(!std::mem::replace(&mut self.everything, true)),
            Protect::File(file) => self.load_file(file),
            Protect::PathFile(file) => {
                let grew_path = self.path_loaded.insert(file.clone());
                let grew_dir = self.dirs.insert(format!("{}/", dir_of(&file)));
                let grew_file = self.load_file(file)?;
                Ok(grew_path || grew_dir || grew_file)
            }
            Protect::Included { file, test } => {
                let grew_included = self.included.insert(file.clone());
                let grew_file = if test {
                    self.load_file(file)?
                } else {
                    self.read(&file)?
                };
                Ok(grew_included || grew_file)
            }
            Protect::Dir(dir) => Ok(self.dirs.insert(dir)),
        }
    }

    /// Marks FILE as test code, and reads it. The return value says whether anything new was
    /// marked or read.
    fn load_file(&mut self, file: String) -> Result<bool> {
        let fresh = self.loaded.insert(file.clone());
        let read = self.read(&file)?;
        Ok(fresh || read)
    }

    /// The facts that module declaration DECL in PATH adds, when the declaration is test code.
    fn decl_targets(&self, path: &str, decl: &ModDecl, out: &mut Vec<Protect>) {
        if decl.unsupported_nesting {
            out.push(Protect::Everything);
            return;
        }
        let inline = decl.inline.join("/");
        match &decl.path {
            PathAttr::Unsupported => out.push(Protect::Everything),
            PathAttr::Literal(file) => {
                let bases = if decl.inline.is_empty() {
                    vec![dir_of(path).to_owned()]
                } else {
                    self.nested_dirs(path, &inline)
                };
                for base in bases {
                    match relative_target(&base, file) {
                        Some(target) => out.push(Protect::PathFile(target)),
                        None => out.push(Protect::Everything),
                    }
                }
            }
            PathAttr::None => {
                let bases = if decl.inline.is_empty() {
                    self.children_dirs(path)
                } else {
                    self.nested_dirs(path, &inline)
                };
                for base in bases {
                    let own = join(&base, &decl.name);
                    out.push(Protect::File(format!("{own}.rs")));
                    out.push(Protect::File(join(&own, "mod.rs")));
                    out.push(Protect::Dir(format!("{own}/")));
                }
            }
        }
    }

    /// The facts that include! call FILE in PATH adds. A call in test code (TEST) makes its file
    /// test code, and every call compiles its file. A call that names no file, or a file that
    /// cannot be named, protects every file.
    fn include_target(&self, path: &str, file: Option<&str>, test: bool, out: &mut Vec<Protect>) {
        let Some(file) = file else {
            out.push(Protect::Everything);
            return;
        };
        match relative_target(dir_of(path), file) {
            Some(target) if target.starts_with("src/") => {
                out.push(Protect::Included { file: target, test });
            }
            Some(_) => {}
            None => out.push(Protect::Everything),
        }
    }

    /// The directories that the modules declared in PATH load from, when PATH is read as a
    /// module of its own. A crate root, a mod.rs file, and a file that a path attribute loads
    /// load from their own directory. Another file loads from a directory named after itself,
    /// and a file that is loaded both ways is covered by both.
    fn children_dirs(&self, path: &str) -> Vec<String> {
        let dir = dir_of(path);
        if is_mod_rs(path) {
            return vec![dir.to_owned()];
        }
        let own = join(dir, stem_of(path));
        if self.path_loaded.contains(path) {
            vec![dir.to_owned(), own]
        } else {
            vec![own]
        }
    }

    /// The directories of the modules declared inside inline modules INLINE in PATH.
    fn nested_dirs(&self, path: &str, inline: &str) -> Vec<String> {
        self.children_dirs(path)
            .into_iter()
            .map(|dir| join(&dir, inline))
            .collect()
    }
}

/// True when PATH is a test file by its name: `tests.rs`, `test.rs`, or a name that ends in
/// `_tests.rs` or `_test.rs`.
fn is_test_name(path: &str) -> bool {
    let name = file_name(path);
    name == "tests.rs"
        || name == "test.rs"
        || name.ends_with("_tests.rs")
        || name.ends_with("_test.rs")
}

/// True when PATH is a module root or a mod.rs file: a file whose modules load from its own
/// directory. The crate roots are lib.rs and main.rs under src/, and the binaries under src/bin.
fn is_mod_rs(path: &str) -> bool {
    file_name(path) == "mod.rs"
        || path == "src/lib.rs"
        || path == "src/main.rs"
        || dir_of(path) == "src/bin"
}

/// The last component of PATH.
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The directory of PATH, without its trailing slash, or the empty string for a top-level file.
fn dir_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// The name of PATH without its `.rs` extension.
fn stem_of(path: &str) -> &str {
    let name = file_name(path);
    name.strip_suffix(".rs").unwrap_or(name)
}

/// DIR and NAME joined with one slash. An empty side is dropped.
fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else if name.is_empty() {
        dir.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// The path that REL names from DIR, with its `.` and empty parts removed. A path that is
/// absolute, or that climbs out with `..`, has no such path: None.
fn relative_target(dir: &str, rel: &str) -> Option<String> {
    if rel.starts_with('/') || rel.split('/').any(|part| part == "..") {
        return None;
    }
    let joined = join(dir, rel);
    let parts: Vec<&str> = joined
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    Some(parts.join("/"))
}
