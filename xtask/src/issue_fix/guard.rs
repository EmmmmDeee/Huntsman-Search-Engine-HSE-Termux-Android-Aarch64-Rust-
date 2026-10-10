//! The path guard: refuses a change that the issue-fix agent may not make. It reads the working
//! tree against BASE, the commit the run started from, and applies the rules of the shell guard
//! it replaces (scripts/issue-fix/check-protected.sh), whose header lists them, and the stricter
//! rules that docs/ISSUE_FIX.md lists for the port. Test code is decided from the files at BASE,
//! with the token stream and syn (see `model` and `syntax`).
//!
//! The guard runs from the trusted xtask that the workflow builds from BASE before the model
//! runs. It reads the checkout as data and never runs anything the checkout names: every git
//! command runs with the overrides in `git`, and the repository's .git/info/attributes is removed
//! before the first command that reads attributes.

pub(super) mod git;
mod model;
mod syntax;

use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;

use model::Model;

use crate::error::{self, EX_REFUSED, Error, Result};

const USAGE: &str = "usage: xtask issue-fix guard BASE";

/// `issue-fix guard BASE`: exits 0 and prints that the change is ok against BASE, or prints each
/// refused change on its own line and exits 1. A failure to read the change exits 1 too.
pub fn run(args: &[String]) -> ExitCode {
    let [base] = args else {
        return error::usage(USAGE);
    };
    if base.is_empty() {
        return error::usage(USAGE);
    }
    match check(base) {
        Ok(refused) if refused.is_empty() => {
            println!("check-protected: ok against {base}");
            ExitCode::SUCCESS
        }
        Ok(refused) => {
            eprintln!("check-protected: refused changes against {base}:");
            for line in &refused {
                eprintln!("  {line}");
            }
            ExitCode::from(EX_REFUSED)
        }
        Err(problem) => {
            eprintln!("check-protected: {problem}; refusing");
            ExitCode::from(EX_REFUSED)
        }
    }
}

/// The refused changes against BASE, as the lines the guard prints. A failure is an error.
fn check(base: &str) -> Result<Vec<String>> {
    git::detach_attributes()?;
    if !git::is_commit(base) {
        return Err(Error::Refused(format!("{base} is not a commit")));
    }
    let changes = parse_raw(&git::raw_diff(base)?)
        .ok_or_else(|| Error::Refused(format!("malformed diff output against {base}")))?;
    let guard = Guard {
        base,
        model: Model::load(base)?,
    };
    let mut refused = Vec::new();
    for change in &changes {
        guard.check_change(change, &mut refused)?;
    }
    for path in git::untracked()? {
        if is_symlink(&path) {
            refused.push(format!("?? {path} (symbolic link)"));
        } else if is_nested_repository(&path) {
            // git lists a directory that holds a repository of its own with a trailing slash.
            // Added, it becomes a submodule entry, which the guard refuses.
            refused.push(format!("?? {path} (nested repository)"));
        } else if !guard.allowed('A', &path)? {
            refused.push(format!("?? {path}"));
        }
    }
    Ok(refused)
}

/// One entry of the raw diff: a change to one path, or a rename or copy from FIRST to SECOND.
#[derive(Debug)]
struct Change {
    src_mode: String,
    dst_mode: String,
    status: String,
    first: String,
    second: Option<String>,
}

/// Reads the NUL-separated raw diff. Each entry is `:SRC_MODE DST_MODE SRC_SHA DST_SHA STATUS`
/// and one path, or two for a rename or copy. None when the output does not have that shape.
fn parse_raw(bytes: &[u8]) -> Option<Vec<Change>> {
    let mut fields = bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty());
    let mut changes = Vec::new();
    while let Some(meta) = fields.next() {
        let meta = utf8(meta)?.strip_prefix(':')?;
        let parts: Vec<&str> = meta.split_whitespace().collect();
        let [src_mode, dst_mode, _, _, status] = parts.as_slice() else {
            return None;
        };
        let first = utf8(fields.next()?)?.to_owned();
        let second = if status.starts_with(['R', 'C']) {
            Some(utf8(fields.next()?)?.to_owned())
        } else {
            None
        };
        changes.push(Change {
            src_mode: (*src_mode).to_owned(),
            dst_mode: (*dst_mode).to_owned(),
            status: (*status).to_owned(),
            first,
            second,
        });
    }
    Some(changes)
}

fn utf8(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok()
}

/// One hunk of a -U0 diff: the old lines that it replaces and the new lines that replace them.
#[derive(Clone, Copy, Debug)]
struct Hunk {
    old_first: usize,
    old_count: usize,
    new_first: usize,
    new_count: usize,
}

impl Hunk {
    /// The last old line that the hunk replaces. A hunk that replaces no line ends at the line
    /// before it, which is the line the hunk sits after.
    fn old_last(self) -> usize {
        if self.old_count == 0 {
            self.old_first
        } else {
            self.old_first + self.old_count - 1
        }
    }
}

/// Reads the hunks of a -U0 diff. None when a hunk header does not have the usual shape.
fn parse_hunks(bytes: &[u8]) -> Option<Vec<Hunk>> {
    utf8(bytes)?
        .lines()
        .filter(|line| line.starts_with("@@ "))
        .map(parse_hunk)
        .collect()
}

/// Reads one hunk header, `@@ -OLD +NEW @@`, where a range is `FIRST` or `FIRST,COUNT`.
fn parse_hunk(line: &str) -> Option<Hunk> {
    let mut fields = line.split_whitespace().skip(1);
    let (old_first, old_count) = range(fields.next()?, '-')?;
    let (new_first, new_count) = range(fields.next()?, '+')?;
    Some(Hunk {
        old_first,
        old_count,
        new_first,
        new_count,
    })
}

/// Reads one range of a hunk header: SIGN followed by FIRST, or FIRST,COUNT. A count that is
/// missing is 1.
fn range(field: &str, sign: char) -> Option<(usize, usize)> {
    let body = field.strip_prefix(sign)?;
    match body.split_once(',') {
        Some((first, count)) => Some((first.parse().ok()?, count.parse().ok()?)),
        None => Some((body.parse().ok()?, 1)),
    }
}

/// The lines of the working tree that a change adds. A new file has every line added.
enum Added {
    Every,
    Lines(BTreeSet<usize>),
}

impl Added {
    /// The lines that the hunks add, in the working tree.
    fn from_hunks(hunks: &[Hunk]) -> Self {
        let mut lines = BTreeSet::new();
        for hunk in hunks {
            lines.extend(hunk.new_first..hunk.new_first + hunk.new_count);
        }
        Self::Lines(lines)
    }

    /// True when a line of FIRST..=LAST is added.
    fn touches(&self, first: usize, last: usize) -> bool {
        match self {
            Self::Every => true,
            Self::Lines(lines) => lines.range(first..=last).next().is_some(),
        }
    }
}

/// The checks of one run, against one base commit.
struct Guard<'a> {
    base: &'a str,
    model: Model,
}

impl Guard<'_> {
    /// Appends to REFUSED the lines that the change in CHANGE refuses.
    fn check_change(&self, change: &Change, refused: &mut Vec<String>) -> Result<()> {
        for mode in [&change.src_mode, &change.dst_mode] {
            if mode == "120000" || mode == "160000" {
                refused.push(format!(
                    "link or submodule (mode {mode}) in the diff: {}",
                    change.first
                ));
            }
        }
        let letter = change.status.chars().next().unwrap_or('?');
        match (letter, change.second.as_deref()) {
            ('R', Some(second)) => {
                let pair = format!("{} {} -> {second}", change.status, change.first);
                if !self.allowed('D', &change.first)? {
                    refused.push(pair.clone());
                }
                if !self.allowed('A', second)? {
                    refused.push(pair);
                }
            }
            ('C', Some(second)) => {
                if !self.allowed('A', second)? {
                    refused.push(format!("{} {} -> {second}", change.status, change.first));
                }
            }
            _ => {
                if !self.allowed(letter, &change.first)? {
                    refused.push(format!("{} {}", change.status, change.first));
                }
            }
        }
        Ok(())
    }

    /// True when a change of kind LETTER (A added, M modified, D deleted) to PATH is allowed.
    fn allowed(&self, letter: char, path: &str) -> Result<bool> {
        if path.starts_with("src/") {
            return match letter {
                'A' => Ok(!self.scope_refused(path, &Added::Every, 0)?),
                'M' => self.modified_allowed(path),
                'D' => Ok(!self.model.is_test_file(path) && self.model.start(path) == 0),
                _ => Ok(false),
            };
        }
        Ok(path.starts_with("tests/") && letter == 'A')
    }

    /// True when a modification of PATH is allowed: it is not test code, it leaves the test code
    /// of the base alone, it adds no line that reaches code beyond its own, and it keeps every
    /// construct of the base that reaches code beyond its own lines.
    fn modified_allowed(&self, path: &str) -> Result<bool> {
        if self.model.is_test_file(path) {
            return Ok(false);
        }
        let Some(hunks) = git::hunks(self.base, path).and_then(|bytes| parse_hunks(&bytes)) else {
            return Ok(false);
        };
        let start = self.model.start(path);
        // The test code starts at the first attribute of its run, so a change that reaches the line
        // above that attribute can add one to the test, and it is refused.
        if start > 0 && hunks.iter().any(|hunk| hunk.old_last() + 1 >= start) {
            return Ok(false);
        }
        let added = Added::from_hunks(&hunks);
        if self.scope_refused(path, &added, start)? {
            return Ok(false);
        }
        self.constructs_kept(path, start)
    }

    /// True when the lines that PATH adds (every line, for a new file) reach beyond their own
    /// lines. A macro definition, a path, macro_use or macro_export attribute, and an include!
    /// call reach beyond. In a file with test code at the base (START > 0), a cfg attribute, an
    /// extern crate item, and an import alias reach beyond too. A file that cannot be read or
    /// parsed refuses the change.
    fn scope_refused(&self, path: &str, added: &Added, start: usize) -> Result<bool> {
        let Ok(bytes) = std::fs::read(path) else {
            return Ok(true);
        };
        if !path.ends_with(".rs") {
            let text = String::from_utf8_lossy(&bytes);
            if text_reaches(&text, added) {
                return Ok(true);
            }
            return Ok(start > 0
                && syntax::read_text(&text)
                    .cfg_constructs
                    .iter()
                    .any(|construct| added.touches(construct.first, construct.last)));
        }
        let Ok(text) = String::from_utf8(bytes) else {
            return Ok(true);
        };
        let Ok(facts) = syntax::read(&text) else {
            return Ok(true);
        };
        if facts
            .scope_constructs
            .iter()
            .any(|construct| added.touches(construct.first, construct.last))
        {
            return Ok(true);
        }
        Ok(start > 0
            && facts
                .cfg_constructs
                .iter()
                .any(|construct| added.touches(construct.first, construct.last)))
    }

    /// True when the working-tree PATH keeps every construct of BASE that the guard compares: the
    /// scope constructs, and the cfg constructs when BASE has test code. A construct that the
    /// working tree has and BASE does not is live now, which an edit can do with no added line,
    /// such as deleting the delimiters of a comment around a macro definition. A file that does
    /// not read as text cannot be compiled, so it activates nothing.
    fn constructs_kept(&self, path: &str, start: usize) -> Result<bool> {
        let Ok(bytes) = std::fs::read(path) else {
            return Ok(false);
        };
        let now = syntax::read_text(&String::from_utf8_lossy(&bytes));
        let now_texts = now.construct_texts(start > 0);
        Ok(contained(&now_texts, &self.model.constructs(path)))
    }
}

/// True when every text of NOW is in BEFORE, each one as often as it occurs in BEFORE.
fn contained(now: &[&str], before: &[&str]) -> bool {
    let mut left: BTreeMap<&str, usize> = BTreeMap::new();
    for text in before {
        *left.entry(text).or_default() += 1;
    }
    now.iter().all(|text| match left.get_mut(text) {
        Some(count) if *count > 0 => {
            *count -= 1;
            true
        }
        _ => false,
    })
}

/// True when an added line of a non-Rust file has a construct that reaches beyond its own line.
/// These are the patterns of the shell guard, matched as text, since such a file is not parsed.
fn text_reaches(text: &str, added: &Added) -> bool {
    text.lines().enumerate().any(|(index, line)| {
        added.touches(index + 1, index + 1)
            && (line.contains("macro_rules!")
                || line.contains("macro_use")
                || line.contains("macro_export")
                || line.contains("include!")
                || has_path_attribute(line))
    })
}

/// True when LINE opens a path attribute: `#[path` or `#![path`, with spaces allowed after the
/// bracket.
fn has_path_attribute(line: &str) -> bool {
    line.match_indices('#').any(|(at, _)| {
        line.get(at + 1..)
            .map(|rest| rest.strip_prefix('!').unwrap_or(rest))
            .and_then(|rest| rest.strip_prefix('['))
            .is_some_and(|rest| rest.trim_start().starts_with("path"))
    })
}

/// True when PATH is a symbolic link in the working tree. A path that cannot be read is not.
fn is_symlink(path: &str) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// True when PATH is a directory of the working tree, which git lists with a trailing slash when
/// the directory holds a repository of its own.
fn is_nested_repository(path: &str) -> bool {
    path.ends_with('/') || std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}
