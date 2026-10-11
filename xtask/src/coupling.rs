//! Coupling analysis: which source files form clusters. A unit is a top-level module, a
//! directory module, or a bin target. A unit refers to another when one of its files names it
//! through a `crate::` or `huntsman_recon::` path, read from the syntax tree, so grouped imports
//! and expression paths count. `#[cfg(test)] mod` blocks are skipped, and `mod name;` counts only
//! in the bin root, where it declares a unit. Integration tests sit outside the graph and only add
//! incoming references, which separates test-only units from unreferenced ones. Communities
//! maximise modularity by local moves with fixed restarts. Co-change is the Jaccard index over the
//! commits that touched a pair of units, read from git history.

#![allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use syn::visit::{self, Visit};

use crate::error::{self, Error, Result};
use crate::proc::{git_stdout, repository_root};

const USAGE: &str = "usage: cargo run --locked -p xtask -- coupling";
/// Restarts of the modularity search: the first from singletons, the rest from shuffled orders.
const RESTARTS: u64 = 60;
/// Commits that touch more units than this are formatting or rename sweeps, which say nothing
/// about coupling.
const MAX_UNITS_PER_COMMIT: usize = 25;
/// A pair must change together in at least this many commits to be reported.
const MIN_CO_CHANGES: usize = 2;
/// Rows that each report section prints.
const ROWS: usize = 15;
/// The first segments of paths that name a unit: the library crate and the binary's own name.
const ROOTS: [&str; 2] = ["crate", "huntsman_recon"];

#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        return error::usage(USAGE);
    }
    match analyse(&repository_root()) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(problem) => error::report("xtask coupling", &problem),
    }
}

fn analyse(root: &Path) -> Result<String> {
    let model = Model::build(root)?;
    let (labels, quality) = best_partition(&model.weights, &model.degree, model.total_degree());
    let groups = group_members(&model.names, &labels);
    let log = git_stdout(
        root,
        &[
            "log",
            "--name-only",
            "--pretty=format:__C__",
            "--",
            "src",
            "tests",
        ],
    )?;
    let commits = parse_commits(&String::from_utf8_lossy(&log));
    let cochange = cochange_scores(&commits);
    Ok(render(
        &model,
        &groups,
        &labels,
        quality,
        commits.len(),
        &cochange,
    ))
}

/// The coupling graph over production units, sorted by name.
struct Model {
    names: Vec<String>,
    index: BTreeMap<String, usize>,
    /// Undirected reference counts: files in either unit that name the other.
    weights: Vec<Vec<f64>>,
    degree: Vec<f64>,
    lines: Vec<usize>,
    paths: Vec<String>,
    /// Whether some other production unit names this one.
    referenced_by_production: Vec<bool>,
    /// How many integration-test files name this unit.
    referenced_by_tests: Vec<usize>,
}

impl Model {
    fn build(root: &Path) -> Result<Self> {
        let mut files = Vec::new();
        collect_rs(&root.join("src"), &mut files)?;
        collect_rs(&root.join("tests"), &mut files)?;

        let mut facts: BTreeMap<String, (usize, String)> = BTreeMap::new();
        let mut referencing: Vec<(String, BTreeSet<String>)> = Vec::new();
        for file in &files {
            let rel = relative(root, file);
            let Some(unit) = unit_of(&rel) else { continue };
            let text = read(file)?;
            let refs = references_of(&text, rel == "src/main.rs")
                .map_err(|problem| Error::Invalid(format!("{rel}: {problem}")))?;
            if !unit.starts_with("test:") {
                let fact = facts
                    .entry(unit.clone())
                    .or_insert_with(|| (0, path_of(&rel)));
                fact.0 += text.lines().count();
            }
            referencing.push((unit, refs));
        }

        let names: Vec<String> = facts.keys().cloned().collect();
        let index: BTreeMap<String, usize> = names
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, name)| (name, i))
            .collect();
        let size = names.len();
        let mut directed = vec![vec![0.0_f64; size]; size];
        let mut referenced_by_production = vec![false; size];
        let mut referenced_by_tests = vec![0_usize; size];
        for (unit, refs) in &referencing {
            for target in refs {
                let Some(&to) = index.get(target) else {
                    continue;
                };
                if unit.starts_with("test:") {
                    referenced_by_tests[to] += 1;
                } else if let Some(&from) = index.get(unit) {
                    if from != to {
                        directed[from][to] += 1.0;
                        referenced_by_production[to] = true;
                    }
                }
            }
        }
        let weights: Vec<Vec<f64>> = directed
            .iter()
            .enumerate()
            .map(|(i, row)| {
                row.iter()
                    .enumerate()
                    .map(|(j, cell)| cell + directed[j][i])
                    .collect()
            })
            .collect();
        let degree: Vec<f64> = weights.iter().map(|row| row.iter().sum()).collect();
        let lines = names.iter().map(|name| facts[name].0).collect();
        let paths = names.iter().map(|name| facts[name].1.clone()).collect();
        Ok(Self {
            names,
            index,
            weights,
            degree,
            lines,
            paths,
            referenced_by_production,
            referenced_by_tests,
        })
    }

    fn total_degree(&self) -> f64 {
        self.degree.iter().sum()
    }

    fn edge_count(&self) -> usize {
        self.weights
            .iter()
            .enumerate()
            .map(|(i, row)| {
                row.iter()
                    .skip(i + 1)
                    .filter(|weight| **weight > 0.0)
                    .count()
            })
            .sum()
    }

    /// Weight inside the members, each edge once, and weight leaving them.
    fn cut(&self, members: &[usize]) -> (f64, f64) {
        let inside: BTreeSet<usize> = members.iter().copied().collect();
        let (mut internal, mut boundary) = (0.0_f64, 0.0_f64);
        for &i in members {
            for (j, weight) in self.weights[i].iter().enumerate() {
                if *weight > 0.0 {
                    if inside.contains(&j) {
                        internal += weight;
                    } else {
                        boundary += weight;
                    }
                }
            }
        }
        (internal / 2.0, boundary)
    }
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let read = fs::read_dir(dir).map_err(|source| Error::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut entries = Vec::new();
    for entry in read {
        let entry = entry.map_err(|source| Error::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        entries.push(entry.path());
    }
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rs(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn relative(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The unit a repository file belongs to. The library root only declares modules, so it has none.
fn unit_of(rel: &str) -> Option<String> {
    let parts: Vec<&str> = rel.split('/').collect();
    match parts.as_slice() {
        ["src", "lib.rs"] => None,
        ["src", "main.rs"] => Some("bin:main".to_string()),
        ["src", "bin", file] => Some(format!("bin:{}", file.trim_end_matches(".rs"))),
        ["src", file] => Some(file.trim_end_matches(".rs").to_string()),
        ["src", dir, ..] => Some((*dir).to_string()),
        ["tests", file] => Some(format!("test:{}", file.trim_end_matches(".rs"))),
        _ => None,
    }
}

/// The path a unit's code lives at: its file, or the directory of a directory module.
fn path_of(rel: &str) -> String {
    let parts: Vec<&str> = rel.split('/').collect();
    match parts.as_slice() {
        ["src", dir, _, ..] if *dir != "bin" => format!("src/{dir}/"),
        _ => rel.to_string(),
    }
}

/// The names of the top-level units a file refers to through a root path.
fn references_of(
    text: &str,
    top_level_declarations: bool,
) -> std::result::Result<BTreeSet<String>, syn::Error> {
    let file = syn::parse_file(text)?;
    let mut found = References {
        names: BTreeSet::new(),
        top_level_declarations,
    };
    found.visit_file(&file);
    Ok(found.names)
}

struct References {
    names: BTreeSet<String>,
    top_level_declarations: bool,
}

impl References {
    fn record(&mut self, name: &str) {
        if name != "self" {
            self.names.insert(name.to_string());
        }
    }

    /// The use tree below a root segment: the first name of each branch names a unit.
    fn below_root(&mut self, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Name(name) => self.record(&name.ident.to_string()),
            syn::UseTree::Rename(rename) => self.record(&rename.ident.to_string()),
            syn::UseTree::Path(path) => self.record(&path.ident.to_string()),
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.below_root(item);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }

    /// Finds the root segments at any depth of a use tree.
    fn use_tree(&mut self, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(path) if ROOTS.iter().any(|root| path.ident == *root) => {
                self.below_root(&path.tree);
            }
            syn::UseTree::Path(path) => self.use_tree(&path.tree),
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.use_tree(item);
                }
            }
            syn::UseTree::Name(_) | syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for References {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        if self.top_level_declarations && node.content.is_none() {
            self.record(&node.ident.to_string());
        }
        visit::visit_item_mod(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        self.use_tree(&node.tree);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        let mut segments = node.segments.iter();
        if let (Some(root), Some(unit)) = (segments.next(), segments.next()) {
            if ROOTS.iter().any(|name| root.ident == *name) {
                self.record(&unit.ident.to_string());
            }
        }
        visit::visit_path(self, node);
    }
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Ident>()
                .is_ok_and(|ident| ident == "test")
    })
}

fn next_random(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state >> 33
}

/// Local moves to a fixed point: each unit joins the neighbouring community that raises
/// modularity most, and stays put unless a move is a strict improvement.
fn local_moves(weights: &[Vec<f64>], degree: &[f64], total: f64, order: &[usize]) -> Vec<usize> {
    let mut labels: Vec<usize> = (0..degree.len()).collect();
    let mut tot: Vec<f64> = degree.to_vec();
    let mut moved = true;
    while moved {
        moved = false;
        for &i in order {
            let home = labels[i];
            tot[home] -= degree[i];
            let mut link: BTreeMap<usize, f64> = BTreeMap::new();
            link.insert(home, 0.0);
            for (j, weight) in weights[i].iter().enumerate() {
                if j != i && *weight > 0.0 {
                    *link.entry(labels[j]).or_insert(0.0) += weight;
                }
            }
            let mut best = home;
            let mut best_gain =
                link.get(&home).copied().unwrap_or(0.0) - tot[home] * degree[i] / total;
            for (&candidate, &inside) in &link {
                let gain = inside - tot[candidate] * degree[i] / total;
                if gain > best_gain + 1e-12 {
                    best = candidate;
                    best_gain = gain;
                }
            }
            tot[best] += degree[i];
            if best != home {
                labels[i] = best;
                moved = true;
            }
        }
    }
    labels
}

fn modularity(weights: &[Vec<f64>], degree: &[f64], total: f64, labels: &[usize]) -> f64 {
    let mut q = 0.0;
    for (i, row) in weights.iter().enumerate() {
        for (j, weight) in row.iter().enumerate() {
            if labels[i] == labels[j] {
                q += weight - degree[i] * degree[j] / total;
            }
        }
    }
    q / total
}

/// The community labels with the highest modularity over `RESTARTS` local-move runs, and that
/// modularity. The first run starts from singletons and the rest from shuffled orders, so the
/// result is deterministic.
fn best_partition(weights: &[Vec<f64>], degree: &[f64], total: f64) -> (Vec<usize>, f64) {
    let size = degree.len();
    let singletons: Vec<usize> = (0..size).collect();
    if total <= 0.0 {
        return (singletons, 0.0);
    }
    let mut best: (Vec<usize>, f64) = (singletons, f64::NEG_INFINITY);
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    for restart in 0..RESTARTS {
        let mut order: Vec<usize> = (0..size).collect();
        if restart > 0 {
            for i in (1..size).rev() {
                let j = (next_random(&mut state) as usize) % (i + 1);
                order.swap(i, j);
            }
        }
        let labels = local_moves(weights, degree, total, &order);
        let q = modularity(weights, degree, total, &labels);
        if q > best.1 + 1e-12 {
            best = (labels, q);
        }
    }
    best
}

/// The members of each community, largest first. Ties sort by the first member's name.
fn group_members(names: &[String], labels: &[usize]) -> Vec<Vec<usize>> {
    let mut by_label: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, label) in labels.iter().enumerate() {
        by_label.entry(*label).or_default().push(i);
    }
    let mut groups: Vec<Vec<usize>> = by_label.into_values().collect();
    groups.sort_by(|a, b| {
        b.len()
            .cmp(&a.len())
            .then_with(|| names[a[0]].cmp(&names[b[0]]))
    });
    groups
}

/// The production units of each commit, from `git log --name-only` in `__C__` format.
fn parse_commits(log: &str) -> Vec<BTreeSet<String>> {
    let mut commits = Vec::new();
    let mut current: Option<BTreeSet<String>> = None;
    for line in log.lines().map(str::trim) {
        if line == "__C__" {
            commits.extend(current.take());
            current = Some(BTreeSet::new());
        } else if let (Some(set), Some(unit)) = (current.as_mut(), unit_of(line)) {
            if !unit.starts_with("test:") {
                set.insert(unit);
            }
        }
    }
    commits.extend(current);
    commits
}

struct CoChange {
    jaccard: f64,
    co: usize,
    a: String,
    b: String,
}

/// The Jaccard index of each unit pair that changed together at least `MIN_CO_CHANGES` times:
/// commits touching both, over commits touching either. Commits that touch too many units are
/// skipped.
fn cochange_scores(commits: &[BTreeSet<String>]) -> Vec<CoChange> {
    let mut touched: BTreeMap<String, usize> = BTreeMap::new();
    let mut together: BTreeMap<(String, String), usize> = BTreeMap::new();
    for commit in commits
        .iter()
        .filter(|commit| (2..=MAX_UNITS_PER_COMMIT).contains(&commit.len()))
    {
        for unit in commit {
            *touched.entry(unit.clone()).or_insert(0) += 1;
        }
        let units: Vec<&String> = commit.iter().collect();
        for (offset, left) in units.iter().enumerate() {
            for right in &units[offset + 1..] {
                *together
                    .entry(((*left).clone(), (*right).clone()))
                    .or_insert(0) += 1;
            }
        }
    }
    let mut scored: Vec<CoChange> = together
        .into_iter()
        .filter(|(_, co)| *co >= MIN_CO_CHANGES)
        .map(|((a, b), co)| {
            let union = touched[&a] + touched[&b] - co;
            CoChange {
                jaccard: co as f64 / union as f64,
                co,
                a,
                b,
            }
        })
        .collect();
    scored.sort_by(|x, y| {
        y.jaccard
            .total_cmp(&x.jaccard)
            .then_with(|| y.co.cmp(&x.co))
            .then_with(|| x.a.cmp(&y.a))
    });
    scored
}

fn render(
    model: &Model,
    groups: &[Vec<usize>],
    labels: &[usize],
    quality: f64,
    commits: usize,
    cochange: &[CoChange],
) -> String {
    let mut out = String::new();
    render_communities(&mut out, model, groups, quality);
    render_bridges(&mut out, model, labels);
    render_hubs(&mut out, model);
    render_classes(&mut out, model);
    render_cochange(&mut out, model, commits, cochange);
    out
}

fn render_communities(out: &mut String, model: &Model, groups: &[Vec<usize>], quality: f64) {
    let _ = writeln!(
        out,
        "== communities by modularity: {} units, {} coupled pairs, Q = {quality:.3}, {} communities ==",
        model.names.len(),
        model.edge_count(),
        groups.len()
    );
    for (rank, members) in groups.iter().enumerate() {
        let (internal, boundary) = model.cut(members);
        let lines: usize = members.iter().map(|&i| model.lines[i]).sum();
        let _ = writeln!(
            out,
            "C{:02}: {} units, {lines} lines, internal {internal:.0}, boundary {boundary:.0}",
            rank + 1,
            members.len()
        );
        let mut paths: Vec<&str> = members.iter().map(|&i| model.paths[i].as_str()).collect();
        paths.sort_unstable();
        paths.dedup();
        let _ = writeln!(out, "     {}", paths.join(" "));
    }
}

fn render_bridges(out: &mut String, model: &Model, labels: &[usize]) {
    let _ = writeln!(
        out,
        "== bridge units: share of their coupling that leaves their community (coupling >= 3) =="
    );
    let mut rows: Vec<(usize, f64, usize)> = Vec::new();
    for (i, degree) in model.degree.iter().enumerate() {
        if *degree < 3.0 {
            continue;
        }
        let mut external = 0.0_f64;
        let mut foreign: BTreeSet<usize> = BTreeSet::new();
        for (j, weight) in model.weights[i].iter().enumerate() {
            if *weight > 0.0 && labels[j] != labels[i] {
                external += weight;
                foreign.insert(labels[j]);
            }
        }
        rows.push((i, external / degree, foreign.len()));
    }
    rows.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then_with(|| model.names[a.0].cmp(&model.names[b.0]))
    });
    for (i, share, foreign) in rows.iter().take(ROWS) {
        let _ = writeln!(
            out,
            "  {:<22} coupling {:>4.0}  external {:>4.0}%  foreign communities {foreign}",
            model.names[*i],
            model.degree[*i],
            share * 100.0
        );
    }
}

fn render_hubs(out: &mut String, model: &Model) {
    let mut order: Vec<usize> = (0..model.names.len()).collect();
    order.sort_by(|a, b| {
        model.degree[*b]
            .total_cmp(&model.degree[*a])
            .then_with(|| model.names[*a].cmp(&model.names[*b]))
    });
    let _ = writeln!(out, "== hubs: most coupled units ==");
    for &i in order.iter().take(ROWS) {
        let _ = writeln!(
            out,
            "  {:<22} coupling {:>4.0}  lines {:>5}  {}",
            model.names[i], model.degree[i], model.lines[i], model.paths[i]
        );
    }
}

fn render_classes(out: &mut String, model: &Model) {
    let mut unreferenced = Vec::new();
    let mut test_only = Vec::new();
    for (i, name) in model.names.iter().enumerate() {
        if name.starts_with("bin:") || model.referenced_by_production[i] {
            continue;
        }
        if model.referenced_by_tests[i] == 0 {
            unreferenced.push(model.paths[i].as_str());
        } else {
            test_only.push(model.paths[i].as_str());
        }
    }
    let _ = writeln!(
        out,
        "== unreferenced units ({}): {} ==",
        unreferenced.len(),
        unreferenced.join(" ")
    );
    let _ = writeln!(
        out,
        "== test-only units ({}): {} ==",
        test_only.len(),
        test_only.join(" ")
    );
}

fn render_cochange(out: &mut String, model: &Model, commits: usize, cochange: &[CoChange]) {
    let _ = writeln!(
        out,
        "== co-change over {commits} commits (Jaccard; * = no import edge between the pair) =="
    );
    for pair in cochange.iter().take(ROWS) {
        let linked = match (model.index.get(&pair.a), model.index.get(&pair.b)) {
            (Some(&i), Some(&j)) => model.weights[i][j] > 0.0,
            _ => false,
        };
        let marker = if linked { " " } else { "*" };
        let _ = writeln!(
            out,
            "  {:.2} co={:<3} {marker}{} <-> {}",
            pair.jaccard, pair.co, pair.a, pair.b
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[test]
    fn files_map_to_units_and_the_library_root_is_not_a_unit() {
        assert_eq!(unit_of("src/cli/mod.rs").as_deref(), Some("cli"));
        assert_eq!(unit_of("src/fetch.rs").as_deref(), Some("fetch"));
        assert_eq!(
            unit_of("src/bin/investigate.rs").as_deref(),
            Some("bin:investigate")
        );
        assert_eq!(unit_of("src/main.rs").as_deref(), Some("bin:main"));
        assert_eq!(unit_of("src/lib.rs"), None);
        assert_eq!(unit_of("tests/readme.rs").as_deref(), Some("test:readme"));
    }

    #[test]
    fn paths_name_the_file_or_the_directory_of_a_module() {
        assert_eq!(path_of("src/cli/mod.rs"), "src/cli/");
        assert_eq!(path_of("src/correlator/rules.rs"), "src/correlator/");
        assert_eq!(path_of("src/fetch.rs"), "src/fetch.rs");
        assert_eq!(path_of("src/bin/investigate.rs"), "src/bin/investigate.rs");
    }

    #[test]
    fn grouped_imports_and_expression_paths_name_top_level_units() {
        let text = "use crate::{fetch::{FetchOptions, Fetched}, geohash, self};\n\
                    use huntsman_recon::exit::EX_USAGE;\n\
                    fn f() { let _ = crate::place::AddressComponents::default(); }\n";
        let found = references_of(text, false).expect("the sample parses");
        assert_eq!(found, set(&["exit", "fetch", "geohash", "place"]));
    }

    #[test]
    fn comments_and_test_modules_are_not_references_but_bin_declarations_are() {
        let text = "// use crate::commented;\n\
                    mod declared;\n\
                    #[cfg(test)]\n\
                    mod tests { use crate::only_in_tests; }\n";
        let library = references_of(text, false).expect("the sample parses");
        assert_eq!(library, BTreeSet::new());
        let binary = references_of(text, true).expect("the sample parses");
        assert_eq!(binary, set(&["declared"]));
    }

    #[test]
    fn modularity_separates_two_dense_groups_joined_by_a_thin_bridge() {
        // Units 0-3 and 4-7 are two cliques; a single 0.1 edge joins them.
        let mut weights = vec![vec![0.0_f64; 8]; 8];
        for (i, row) in weights.iter_mut().enumerate() {
            for (j, cell) in row.iter_mut().enumerate() {
                if i != j && i / 4 == j / 4 {
                    *cell = 1.0;
                }
            }
        }
        weights[3][4] = 0.1;
        weights[4][3] = 0.1;
        let degree: Vec<f64> = weights.iter().map(|row| row.iter().sum()).collect();
        let total: f64 = degree.iter().sum();
        let (labels, quality) = best_partition(&weights, &degree, total);
        assert_eq!(labels[0], labels[3]);
        assert_eq!(labels[4], labels[7]);
        assert_ne!(labels[0], labels[4]);
        assert!(quality > 0.3, "{quality}");
    }

    #[test]
    fn git_history_splits_into_commits_of_production_units() {
        let log =
            "__C__\n\nsrc/cli/mod.rs\nsrc/fetch.rs\ntests/readme.rs\n\n__C__\n\nsrc/fetch.rs\n";
        assert_eq!(
            parse_commits(log),
            vec![set(&["cli", "fetch"]), set(&["fetch"])]
        );
    }
}
