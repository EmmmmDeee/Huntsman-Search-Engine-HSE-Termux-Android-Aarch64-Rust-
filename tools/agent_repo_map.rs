//! Dependency-free repository symbol mapper for Android-controlled coding agents.
//! Build: rustc --edition=2024 tools/agent_repo_map.rs -o /tmp/agent-repo-map
//! Usage: /tmp/agent-repo-map . [query words...]
//! This is a lexical navigation aid, not a Rust parser or call graph.

use std::{env, fs, io, path::{Path, PathBuf}};

const MAX_FILE_BYTES: u64 = 1_000_000;
const MAX_FILES: usize = 20_000;
const MAX_SYMBOLS: usize = 2_000;

fn is_symbol(line: &str) -> bool {
    let s = line.trim_start();
    ["pub fn ", "pub(crate) fn ", "fn ", "pub struct ", "struct ",
     "pub enum ", "enum ", "pub trait ", "trait ", "impl ", "pub type ",
     "type ", "pub mod ", "mod "].iter().any(|p| s.starts_with(p))
}
fn allowed_dir(name: &str) -> bool {
    !matches!(name, ".git" | "target" | "node_modules" | ".venv" | ".idea" | "vendor")
}
fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    if out.len() >= MAX_FILES { return Ok(()); }
    let mut entries = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        if out.len() >= MAX_FILES { break; }
        let ty = e.file_type()?;
        if ty.is_symlink() { continue; }
        if ty.is_dir() {
            if allowed_dir(&e.file_name().to_string_lossy()) { collect(&e.path(), out)?; }
        } else if ty.is_file() && e.path().extension().is_some_and(|x| x == "rs")
            && e.metadata()?.len() <= MAX_FILE_BYTES {
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
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let root = Path::new(args.get(1).map(String::as_str).unwrap_or(".")).canonicalize()?;
    let terms: Vec<String> = args.iter().skip(2).map(|s| s.to_ascii_lowercase()).collect();
    let mut paths = Vec::new();
    collect(&root, &mut paths)?;
    let mut matches = Vec::new();
    for path in paths.iter() {
        let bytes = fs::read(path)?;
        let Ok(src) = String::from_utf8(bytes) else { continue };
        let symbols: Vec<(usize, String)> = src.lines().enumerate()
            .filter(|(_, s)| is_symbol(s))
            .take(MAX_SYMBOLS)
            .map(|(n, s)| (n + 1, s.trim().chars().take(180).collect()))
            .collect();
        let relative = path.strip_prefix(&root).unwrap_or(path).to_string_lossy().replace('\\', "/");
        let rank = score(&relative, &symbols, &terms);
        if rank > 0 { matches.push((rank, relative, symbols)); }
    }
    matches.sort_by(|a,b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    println!("# Repository symbol map (lexical; not a dependency graph)\n# Rust files inspected: {}\n# Query: {}\n", paths.len(), terms.join(" "));
    for (rank, path, symbols) in matches.iter().take(60) {
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
    #[test] fn exclusions() {
        assert!(!allowed_dir(".git"));
        assert!(!allowed_dir("target"));
        assert!(allowed_dir("src"));
    }
}
