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

#[derive(Default)]
struct Coverage {
    oversized: usize,
    non_utf8: usize,
    symbol_truncated: usize,
    matched: usize,
    inspected: usize,
    displayed_symbols_truncated: usize,
    omitted_paths: Vec<String>,
}

fn is_symbol(line: &str) -> bool {
    let s = line.trim_start();
    ["pub fn ", "pub(crate) fn ", "pub(super) fn ", "fn ", "pub async fn ", "async fn ",
     "pub(crate) async fn ", "pub(super) async fn ", "pub const fn ", "const fn ",
     "pub(crate) const fn ", "pub(super) const fn ", "pub unsafe fn ", "unsafe fn ",
     "pub(crate) unsafe fn ", "pub(super) unsafe fn ", "pub extern ", "extern ",
     "pub struct ", "struct ",
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
fn collect(dir: &Path, out: &mut Vec<PathBuf>, visited: &mut usize, depth: usize, coverage: &mut Coverage) -> io::Result<()> {
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
                collect(&e.path(), out, visited, depth + 1, coverage)?;
            }
        } else if ty.is_file() && e.path().extension().is_some_and(|x| x == "rs") { 
            if e.metadata()?.len() > MAX_FILE_BYTES {
                coverage.oversized += 1;
                coverage.omitted_paths.push(e.path().display().to_string());
                continue;
            }
            require_room(out.len(), MAX_FILES, "Rust file")?;
            out.push(e.path());
        }
    }
    Ok(())
}
fn score(path: &str, source: &str, terms: &[String]) -> usize {
    if terms.is_empty() { return 1; }
    let path_lower = path.to_ascii_lowercase();
    let source_lower = source.to_ascii_lowercase();
    terms.iter().map(|term| {
        if path_lower.contains(term) { 12 }
        else if source_lower.contains(term) { 3 }
        else { 0 }
    }).sum()
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
    let mut coverage = Coverage::default();
    collect(&root, &mut paths, &mut visited, 0, &mut coverage)?;
    let mut matches = Vec::new();
    for path in paths.iter() {
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "Rust source exceeded file size limit during read"));
        }
        let Ok(src) = String::from_utf8(bytes) else {
            coverage.non_utf8 += 1;
            coverage.omitted_paths.push(path.display().to_string());
            continue;
        };
        coverage.inspected += 1;
        let relative = path.strip_prefix(&root).unwrap_or(path).to_string_lossy().replace('\\', "/");
        let rank = score(&relative, &src, &terms);
        if rank == 0 { continue; }
        let mut symbol_count = 0;
        let mut symbols = Vec::new();
        for (line_number, line) in src.lines().enumerate() {
            if !is_symbol(line) { continue; }
            symbol_count += 1;
            if symbols.len() < MAX_SYMBOLS {
                symbols.push((line_number + 1, line.trim().chars().take(180).collect()));
            }
        }
        if symbol_count > MAX_SYMBOLS { coverage.symbol_truncated += 1; }
        if rank > 0 {
            coverage.matched += 1;
            keep_best(&mut matches, rank, relative, symbols);
        }
    }
    coverage.displayed_symbols_truncated = matches.iter().filter(|(_, _, symbols)| symbols.len() > 35).count();
    println!("# Repository symbol map (lexical; not a dependency graph)\n# Rust files inspected: {}\n# Query: {}\n# Coverage: oversized={} non_utf8={} symbol_truncated={} result_limit={} matched={} returned={} results_truncated={} inspected={} matched_files_with_hidden_symbols={}\n", paths.len(), terms.join(" "), coverage.oversized, coverage.non_utf8, coverage.symbol_truncated, MAX_RESULTS, coverage.matched, matches.len(), coverage.matched > matches.len(), coverage.inspected, coverage.displayed_symbols_truncated);
    coverage.omitted_paths.sort();
    for omitted in &coverage.omitted_paths {
        let relative = Path::new(omitted).strip_prefix(&root).unwrap_or(Path::new(omitted));
        eprintln!("# Omitted Rust file: {}", relative.display());
    }
    for (rank, path, symbols) in matches.iter() {
        println!("## {} [relevance={}]", path, rank);
        for (line, text) in symbols.iter().take(35) { println!("{}: {}", line, text); }
        if symbols.len() > 35 { println!("# {} additional symbols not displayed", symbols.len() - 35); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn symbols_and_non_symbols() {
        assert!(is_symbol("  pub(crate) fn resolve() {}"));
        assert!(is_symbol("impl Thing {"));
        assert!(is_symbol("pub async fn fetch() {}"));
        assert!(is_symbol("const fn limit() -> usize { 2 }"));
        assert!(is_symbol("pub(crate) unsafe fn probe() {}"));
        assert!(is_symbol("pub(super) fn helper() {}"));
        assert!(!is_symbol("let x = 3;"));
        assert!(!is_symbol("// fn fake()"));
    }
    #[test] fn full_body_terms_are_not_symbol_only() {
        let source = "fn unrelated() {}\nlet evidence_marker = 1;";
        assert_eq!(score("src/other.rs", source, &["evidence_marker".into()]), 3);
    }
    #[test] fn rankings() {
        let source = "fn correlate() {}";
        assert_eq!(score("src/correlator.rs", source, &["correlat".into()]), 12);
        assert_eq!(score("src/other.rs", source, &["correlat".into()]), 3);
        assert_eq!(score("src/other.rs", source, &[]), 1);
    }
    #[test] fn budgets_fail_closed() {
        assert!(require_room(0, 1, "item").is_ok());
        assert_eq!(require_room(1, 1, "item").unwrap_err().kind(), io::ErrorKind::InvalidData);
        let mut paths = Vec::new();
        let mut visited = 0;
        assert_eq!(collect(Path::new("."), &mut paths, &mut visited, MAX_DEPTH + 1, &mut Coverage::default())
            .unwrap_err().kind(), io::ErrorKind::InvalidData);
        visited = MAX_DIRS;
        assert_eq!(collect(Path::new("."), &mut paths, &mut visited, 0, &mut Coverage::default())
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
    #[test] fn full_source_ranking_is_case_insensitive() {
        assert_eq!(score("src/other.rs", "let Evidence_Marker = 1;", &["evidence_marker".into()]), 3);
        assert_eq!(score("src/EVIDENCE.rs", "let evidence_marker = 1;", &["evidence".into()]), 12);
        assert_eq!(score("src/other.rs", "let evidence_marker = 1;", &["absent".into()]), 0);
    }
    #[test] fn exclusions() {
        assert!(!allowed_dir(".git"));
        assert!(!allowed_dir("target"));
        assert!(allowed_dir("src"));
    }
}
