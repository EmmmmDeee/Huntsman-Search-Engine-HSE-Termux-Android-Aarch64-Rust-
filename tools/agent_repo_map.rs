//! Dependency-free repository symbol mapper for Android-controlled coding agents.
//! Build: rustc --edition=2024 tools/agent_repo_map.rs -o /tmp/agent-repo-map
//! Usage: /tmp/agent-repo-map . [query words...]
//! This is a lexical navigation aid, not a Rust parser or call graph.

use std::{env, fs, io::{self, Read}, path::{Path, PathBuf}};

const MAX_FILE_BYTES: u64 = 1_000_000;
const MAX_FILES: usize = 20_000;
const MAX_SYMBOLS: usize = 2_000;
const MAX_RESULTS: usize = 60;
const MAX_DIRS: usize = 20_000;
const MAX_DIR_ENTRIES: usize = 20_000;
const MAX_DEPTH: usize = 64;

fn is_symbol(line: &str) -> bool {
    let s = line.trim_start();
    ["pub fn ", "pub(crate) fn ", "fn ", "pub struct ", "struct ",
     "pub enum ", "enum ", "pub trait ", "trait ", "impl ", "pub type ",
     "type ", "pub mod ", "mod "].iter().any(|p| s.starts_with(p))
}
fn allowed_dir(name: &str) -> bool {
    !matches!(name, ".git" | "target" | "node_modules" | ".venv" | ".idea" | "vendor")
}
fn require_room(count: usize, limit: usize, kind: &str) -> io::Result<()> {
    if count >= limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            format!("{kind} limit exceeded ({limit})")));
    }
    Ok(())
}
fn collect(dir: &Path, out: &mut Vec<PathBuf>, visited: &mut usize, depth: usize) -> io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "directory depth limit exceeded"));
    }
    require_room(*visited, MAX_DIRS, "directory")?;
    *visited += 1;
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        require_room(entries.len(), MAX_DIR_ENTRIES, "directory entry")?;
        entries.push(entry?);
    }
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let ty = e.file_type()?;
        if ty.is_symlink() { continue; }
        if ty.is_dir() {
            if allowed_dir(&e.file_name().to_string_lossy()) {
                collect(&e.path(), out, visited, depth + 1)?;
            }
        } else if ty.is_file() && e.path().extension().is_some_and(|x| x == "rs")
            && e.metadata()?.len() <= MAX_FILE_BYTES {
            require_room(out.len(), MAX_FILES, "Rust file")?;
            out.push(e.path());
        }
    }
    Ok(())
}
fn score(path: &str, lines: &[(usize, String)], terms: &[String]) -> usize {
    if terms.is_empty() { return 1; }
    let p = path.to_ascii_lowercase();
    let body = lines.iter().map(|(_, s)| s.to_ascii_lowercase()).collect::<Vec<_>>().join(" ");
    terms.iter().map(|t| if p.contains(t) { 12 } else if body.contains(t) { 3 } else { 0 }).sum()
}
// Keep only the results that can be emitted: retaining every matched file could
// otherwise accumulate millions of source symbols on a memory-limited phone.
fn keep_best(matches: &mut Vec<(usize, String, Vec<(usize, String)>)>, rank: usize,
             path: String, symbols: Vec<(usize, String)>) {
    matches.push((rank, path, symbols));
    matches.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    matches.truncate(MAX_RESULTS);
}
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let root = Path::new(args.get(1).map(String::as_str).unwrap_or(".")).canonicalize()?;
    let terms: Vec<String> = args.iter().skip(2).map(|s| s.to_ascii_lowercase()).collect();
    let mut paths = Vec::new();
    let mut visited = 0;
    collect(&root, &mut paths, &mut visited, 0)?;
    let mut matches = Vec::new();
    for path in paths.iter() {
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "Rust source exceeded file size limit during read"));
        }
        let Ok(src) = String::from_utf8(bytes) else { continue };
        let symbols: Vec<(usize, String)> = src.lines().enumerate()
            .filter(|(_, s)| is_symbol(s))
            .take(MAX_SYMBOLS)
            .map(|(n, s)| (n + 1, s.trim().chars().take(180).collect()))
            .collect();
        let relative = path.strip_prefix(&root).unwrap_or(path).to_string_lossy().replace('\\', "/");
        let rank = score(&relative, &symbols, &terms);
        if rank > 0 { keep_best(&mut matches, rank, relative, symbols); }
    }
    println!("# Repository symbol map (lexical; not a dependency graph)\n# Rust files inspected: {}\n# Query: {}\n", paths.len(), terms.join(" "));
    for (rank, path, symbols) in matches.iter() {
        println!("## {} [relevance={}]", path, rank);
        for (line, text) in symbols.iter().take(35) { println!("{}: {}", line, text); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn symbols_and_non_symbols() {
        assert!(is_symbol("  pub(crate) fn resolve() {}"));
        assert!(is_symbol("impl Thing {"));
        assert!(!is_symbol("let x = 3;"));
        assert!(!is_symbol("// fn fake()"));
    }
    #[test] fn rankings() {
        let s = vec![(1, "fn correlate()".to_string())];
        assert_eq!(score("src/correlator.rs", &s, &["correlat".into()]), 12);
        assert_eq!(score("src/other.rs", &s, &["correlat".into()]), 3);
    }
    #[test] fn budgets_fail_closed() {
        assert!(require_room(0, 1, "item").is_ok());
        assert_eq!(require_room(1, 1, "item").unwrap_err().kind(), io::ErrorKind::InvalidData);
        let mut paths = Vec::new();
        let mut visited = 0;
        assert_eq!(collect(Path::new("."), &mut paths, &mut visited, MAX_DEPTH + 1)
            .unwrap_err().kind(), io::ErrorKind::InvalidData);
        visited = MAX_DIRS;
        assert_eq!(collect(Path::new("."), &mut paths, &mut visited, 0)
            .unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
    #[test] fn results_are_bounded_and_deterministic() {
        let mut matches = Vec::new();
        for i in (0..MAX_RESULTS + 200).rev() {
            keep_best(&mut matches, 1, format!("src/{i:04}.rs"),
                      vec![(1, "fn demo() {}".to_string())]);
            assert!(matches.len() <= MAX_RESULTS);
        }
        assert_eq!(matches.len(), MAX_RESULTS);
        assert_eq!(matches.first().unwrap().1, "src/0000.rs");
        assert_eq!(matches.last().unwrap().1, format!("src/{:04}.rs", MAX_RESULTS - 1));
        keep_best(&mut matches, 10, "src/high.rs".to_string(), Vec::new());
        assert_eq!(matches.first().unwrap().1, "src/high.rs");
    }
    #[test] fn exclusions() {
        assert!(!allowed_dir(".git"));
        assert!(!allowed_dir("target"));
        assert!(allowed_dir("src"));
    }
}
