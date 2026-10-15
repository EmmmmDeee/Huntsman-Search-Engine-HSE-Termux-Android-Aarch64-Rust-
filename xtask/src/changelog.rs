//! Changelog fragments. A change adds one file under `changelog.d/` instead of a line in
//! `CHANGELOG.md`, so two pull requests never edit the same lines and a merge never conflicts on
//! the changelog. A fragment is named `<slug>.<section>.md`: the slug is lowercase letters,
//! digits and hyphens (the topic or branch), the section is one of Keep a Changelog's (`added`,
//! `changed`, `deprecated`, `removed`, `fixed`, `security`), and the body is one or more Markdown
//! bullets (`- text`, continued by lines indented two spaces). `check` validates every fragment
//! and runs in every gate mode. `assemble` moves the bullets to the top of their section under
//! `## [Unreleased]`, creates a section the block lacks in Keep a Changelog's order, and deletes
//! the fragments; it is how a version heading is cut. `render` prints what `assemble` would
//! write and touches no file.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::error::{self, Error, Result};
use crate::proc::repository_root;

const USAGE: &str =
    "usage: cargo run --locked -p xtask -- changelog <check|assemble|render> [--root DIR]";
/// The fragments directory, relative to the repository root.
pub const DIR: &str = "changelog.d";
/// The changelog, relative to the repository root.
const FILE: &str = "CHANGELOG.md";
/// The heading the fragments are assembled under.
const UNRELEASED: &str = "## [Unreleased]";
/// Keep a Changelog's sections in its order. A fragment's file name ends in one of them.
const SECTIONS: [&str; 6] = [
    "added",
    "changed",
    "deprecated",
    "removed",
    "fixed",
    "security",
];

#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let (command, root) = match parse(args) {
        Ok(parsed) => parsed,
        Err(problem) => return error::report("xtask changelog", &problem),
    };
    let outcome = match command {
        "check" => check(&root).map(|count| println!("xtask changelog: {count} fragment(s) valid")),
        "assemble" => assemble(&root),
        "render" => render(&root).map(|text| print!("{text}")),
        _ => return error::usage(USAGE),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => error::report("xtask changelog", &problem),
    }
}

fn parse(args: &[String]) -> Result<(&str, PathBuf)> {
    match args {
        [command] => Ok((command, repository_root())),
        [command, flag, dir] if flag == "--root" => Ok((command, PathBuf::from(dir))),
        _ => Err(Error::Invalid(USAGE.to_owned())),
    }
}

/// One fragment: its file, its section's index in [`SECTIONS`], and its bullet lines.
struct Fragment {
    path: PathBuf,
    section: usize,
    body: String,
}

/// Validates every fragment and the changelog's heading; returns how many fragments there are.
/// Every gate mode runs this, so a malformed fragment never reaches `main`.
pub fn check(root: &Path) -> Result<usize> {
    let count = fragments(root)?.len();
    changelog(root)?;
    Ok(count)
}

/// The changelog with every fragment assembled under `[Unreleased]`, without writing.
fn render(root: &Path) -> Result<String> {
    let found = fragments(root)?;
    let lines = changelog(root)?;
    Ok(assembled(&lines, &found))
}

/// Writes the assembled changelog and deletes the fragments. No fragments: nothing changes.
fn assemble(root: &Path) -> Result<()> {
    let found = fragments(root)?;
    let lines = changelog(root)?;
    if found.is_empty() {
        println!("xtask changelog: no fragments to assemble");
        return Ok(());
    }
    let path = root.join(FILE);
    fs::write(&path, assembled(&lines, &found)).map_err(|source| Error::Io { path, source })?;
    for fragment in &found {
        fs::remove_file(&fragment.path).map_err(|source| Error::Io {
            path: fragment.path.clone(),
            source,
        })?;
    }
    println!(
        "xtask changelog: assembled {} fragment(s) into {FILE}",
        found.len()
    );
    Ok(())
}

/// Every fragment under [`DIR`] in file-name order, each validated. A missing directory holds
/// none. `README.md` describes the convention and is not a fragment.
fn fragments(root: &Path) -> Result<Vec<Fragment>> {
    let dir = root.join(DIR);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let io = |source| Error::Io {
        path: dir.clone(),
        source,
    };
    let mut names = fs::read_dir(&dir)
        .map_err(io)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(io)?;
    names.sort();
    names
        .iter()
        .filter(|name| *name != "README.md")
        .map(|name| fragment(&dir.join(name)))
        .collect()
}

fn fragment(path: &Path) -> Result<Fragment> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let Some(section) = section_of(name) else {
        return Err(Error::Refused(format!(
            "{}: a fragment is named <slug>.<section>.md, with a slug of lowercase letters, \
             digits and hyphens and a section among {}",
            path.display(),
            SECTIONS.join(", ")
        )));
    };
    let body = fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if let Some(problem) = body_problem(&body) {
        return Err(Error::Refused(format!("{}: {problem}", path.display())));
    }
    Ok(Fragment {
        path: path.to_path_buf(),
        section,
        body,
    })
}

/// The index in [`SECTIONS`] of the section a fragment's file name ends in, when the name is
/// well formed.
fn section_of(name: &str) -> Option<usize> {
    let (slug, section) = name.strip_suffix(".md")?.rsplit_once('.')?;
    let slug_ok = !slug.is_empty()
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !slug_ok {
        return None;
    }
    SECTIONS.iter().position(|known| *known == section)
}

/// Why BODY is not a fragment body, when it is not: one or more Markdown bullets, each `- `
/// followed by text and continued by lines indented two spaces, ending in a newline.
fn body_problem(body: &str) -> Option<&'static str> {
    if body.trim().is_empty() {
        return Some("the fragment is empty");
    }
    if !body.ends_with('\n') {
        return Some("the fragment does not end in a newline");
    }
    let mut bullets = 0usize;
    for line in body.lines() {
        if let Some(text) = line.strip_prefix("- ") {
            if text.trim().is_empty() {
                return Some("a bullet has no text");
            }
            bullets += 1;
        } else if line.starts_with("  ") {
            if bullets == 0 {
                return Some("the fragment must start with a bullet");
            }
        } else if !line.is_empty() {
            return Some("every line is a bullet (`- text`) or a continuation indented two spaces");
        }
    }
    (bullets == 0).then_some("the fragment holds no bullet")
}

/// The changelog's lines; refused without the `[Unreleased]` heading to assemble under.
fn changelog(root: &Path) -> Result<Vec<String>> {
    let path = root.join(FILE);
    let text = fs::read_to_string(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    if !text.lines().any(|line| line.trim_end() == UNRELEASED) {
        return Err(Error::Refused(format!(
            "{}: no `{UNRELEASED}` heading to assemble under",
            path.display()
        )));
    }
    Ok(text.lines().map(str::to_owned).collect())
}

/// `### Added` for `added`.
fn heading(section: usize) -> String {
    let name = SECTIONS[section];
    let mut chars = name.chars();
    let first = chars
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or_default();
    format!("### {first}{}", chars.as_str())
}

/// The index in [`SECTIONS`] of the section LINE is the heading of, if it is one.
fn section_index(line: &str) -> Option<usize> {
    let title = line.trim_end().strip_prefix("### ")?.to_ascii_lowercase();
    SECTIONS.iter().position(|known| *known == title)
}

/// LINES with every fragment's bullets at the top of its section under `[Unreleased]`, in
/// file-name order. A section the block lacks is created in Keep a Changelog's order. Lines
/// outside the `[Unreleased]` block are untouched. The result ends in one newline.
fn assembled(lines: &[String], found: &[Fragment]) -> String {
    let mut by_section: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for fragment in found {
        by_section
            .entry(fragment.section)
            .or_default()
            .extend(fragment.body.lines().map(str::to_owned));
    }
    let mut out = lines.to_vec();
    for (section, bullets) in by_section {
        insert(&mut out, section, &bullets);
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}

/// Inserts BULLETS at the top of SECTION in the `[Unreleased]` block of OUT, creating the
/// section (heading, blank line, bullets, blank line) before the first existing section that
/// follows it in Keep a Changelog's order, or at the end of the block.
fn insert(out: &mut Vec<String>, section: usize, bullets: &[String]) {
    let Some(start) = out.iter().position(|line| line.trim_end() == UNRELEASED) else {
        return;
    };
    let block_end = out[start + 1..]
        .iter()
        .position(|line| line.starts_with("## "))
        .map_or(out.len(), |offset| start + 1 + offset);
    let title = heading(section);
    let existing = out[start..block_end]
        .iter()
        .position(|line| line.trim_end() == title)
        .map(|offset| start + offset);
    let (at, mut lines) = match existing {
        Some(heading_at) => {
            let mut at = heading_at + 1;
            if out.get(at).is_some_and(|line| line.trim().is_empty()) {
                at += 1;
            } else {
                out.insert(at, String::new());
                at += 1;
            }
            (at, bullets.to_vec())
        }
        None => {
            let later = out[start..block_end]
                .iter()
                .position(|line| section_index(line).is_some_and(|index| index > section))
                .map_or(block_end, |offset| start + offset);
            let mut lines = vec![title, String::new()];
            lines.extend_from_slice(bullets);
            if later < out.len() {
                lines.push(String::new());
            }
            (later, lines)
        }
    };
    if existing.is_none() && !out[..at].last().is_some_and(|line| line.is_empty()) {
        lines.insert(0, String::new());
    }
    for (offset, line) in lines.into_iter().enumerate() {
        out.insert(at + offset, line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_needs_a_lowercase_slug_and_a_known_section() {
        assert_eq!(section_of("fetch-cache.changed.md"), Some(1));
        assert_eq!(section_of("x9.security.md"), Some(5));
        for bad in [
            "Fetch.changed.md",
            "fetch.unknown.md",
            "fetch.md",
            ".changed.md",
            "fetch.changed.txt",
            "fetch_cache.changed.md",
        ] {
            assert_eq!(section_of(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_body_is_bullets_with_indented_continuations() {
        assert_eq!(body_problem("- One.\n"), None);
        assert_eq!(body_problem("- One.\n  more.\n\n- Two.\n"), None);
        assert!(body_problem("").is_some());
        assert!(body_problem("- One.").is_some());
        assert!(body_problem("- \n").is_some());
        assert!(body_problem("One.\n").is_some());
        assert!(body_problem("  continued.\n- One.\n").is_some());
        assert!(body_problem("\n\n").is_some());
    }

    #[test]
    fn headings_follow_keep_a_changelog() {
        assert_eq!(heading(0), "### Added");
        assert_eq!(heading(5), "### Security");
        assert_eq!(section_index("### Changed "), Some(1));
        assert_eq!(section_index("## [Unreleased]"), None);
    }
}
