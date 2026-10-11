//! The boundaries `ARCHITECTURE.md` states for production code, checked on the token stream of
//! every file under `src/`. Comments, literals and `#[cfg(test)]` items are not production code,
//! so they are not checked. The process boundary is the binary's adapters (`src/cli`, `src/bin`,
//! `src/main.rs`): it alone reads the process environment and its arguments, writes to the
//! terminal, or ends the process. Library code takes those as values.

#[allow(dead_code)]
#[path = "support/rust_code.rs"]
mod rust_code;

use rust_code::{strip_non_code, tokens, without_test_items};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The binary's adapters: the one place a process reads its environment or arguments, prints, or
/// ends.
const PROCESS_BOUNDARY: [&str; 3] = ["src/cli", "src/bin", "src/main.rs"];
/// The one library module that reads the environment. Its accessors are the configuration surface.
const ENVIRONMENT_READER: [&str; 1] = ["src/environment.rs"];
/// The modules that own a socket: the outbound transport and the inbound listener.
const SOCKET_OWNERS: [&str; 2] = ["src/http.rs", "src/web_server.rs"];

/// Functions of `std::env` that read the environment or the process arguments.
const ENV_READS: [&str; 6] = ["var", "var_os", "vars", "vars_os", "args", "args_os"];
/// Names that open a connection or resolve a host. Address values such as `IpAddr` open nothing and
/// are not named here.
const SOCKET_NAMES: [&str; 5] = [
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "ureq",
    "ToSocketAddrs",
];
/// Macros that write to standard output or standard error.
const PRINT_MACROS: [&str; 5] = ["println", "eprintln", "print", "eprint", "dbg"];

/// One production source file: its path relative to the crate root, and its text.
struct Source {
    path: String,
    text: String,
}

/// Every source file under `src/`, relative to the crate root.
fn all_sources() -> Vec<Source> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect(&root.join("src"), &mut files);
    files.sort();
    files
        .into_iter()
        .map(|file| Source {
            path: normal(file.strip_prefix(root).expect("under the crate root")),
            text: fs::read_to_string(&file).expect("readable source"),
        })
        .collect()
}

/// The source files that compile outside `cfg(test)`: every file under `src/` but the out-of-line
/// test modules (`#[cfg(test)] mod tests;`) and the files they name.
fn production_sources() -> Vec<Source> {
    let all = all_sources();
    let test_only = test_only_files(&all);
    all.into_iter()
        .filter(|source| !test_only.contains(&source.path))
        .collect()
}

/// The files only a `#[cfg(test)]` declaration compiles. For `#[cfg(test)] mod x;` in a file, the
/// module is `x.rs` or `x/mod.rs` in the file's module directory: the directory holding `lib.rs`,
/// `main.rs` or `mod.rs`, and otherwise the directory named after the file.
fn test_only_files(sources: &[Source]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for source in sources {
        let (_, declared) = without_test_items(&tokens(&strip_non_code(&source.text)));
        if declared.is_empty() {
            continue;
        }
        let path = Path::new(&source.path);
        let dir = match path.file_name().and_then(|name| name.to_str()) {
            Some("lib.rs" | "main.rs" | "mod.rs") => path.parent().unwrap_or(Path::new("")).into(),
            _ => path.with_extension(""),
        };
        for name in declared {
            found.insert(normal(&dir.join(format!("{name}.rs"))));
            found.insert(normal(&dir.join(&name).join("mod.rs")));
        }
    }
    found
}

fn normal(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Whether `path` is `entry`, or a file under the directory `entry`.
fn under(path: &str, entry: &str) -> bool {
    path == entry || path.starts_with(&format!("{entry}/"))
}

/// The production code of `text` as tokens: no comments, no literals, no `#[cfg(test)]` items.
fn production_tokens(text: &str) -> Vec<String> {
    without_test_items(&tokens(&strip_non_code(text))).0
}

/// Whether the tokens read the environment or the process arguments. A grouped import from
/// `std::env` (`use std::env::{var}`) counts too, since the names it brings in are read later.
fn reads_environment(toks: &[String]) -> bool {
    toks.windows(3).any(|w| {
        w[0] == "env" && w[1] == "::" && (ENV_READS.contains(&w[2].as_str()) || w[2] == "{")
    })
}

/// Whether the tokens name a type that opens a connection or resolves a host.
fn opens_socket(toks: &[String]) -> bool {
    toks.iter().any(|t| SOCKET_NAMES.contains(&t.as_str()))
}

/// Whether the tokens invoke a macro that writes to the terminal.
fn prints(toks: &[String]) -> bool {
    toks.windows(2)
        .any(|w| PRINT_MACROS.contains(&w[0].as_str()) && w[1] == "!")
}

/// Whether the tokens end the process.
fn ends_process(toks: &[String]) -> bool {
    toks.windows(3)
        .any(|w| w[0] == "process" && w[1] == "::" && w[2] == "exit")
}

/// The production files outside `allowed` whose code matches `matches`.
fn offenders(allowed: &[&str], matches: fn(&[String]) -> bool) -> Vec<String> {
    production_sources()
        .into_iter()
        .filter(|source| !allowed.iter().any(|entry| under(&source.path, entry)))
        .filter(|source| matches(&production_tokens(&source.text)))
        .map(|source| source.path)
        .collect()
}

#[test]
fn only_the_environment_module_reads_the_environment_outside_the_process_boundary() {
    let allowed = [&PROCESS_BOUNDARY[..], &ENVIRONMENT_READER[..]].concat();
    let found = offenders(&allowed, reads_environment);
    assert!(
        found.is_empty(),
        "library code reads the environment or process arguments outside `src/environment.rs`: {found:?}"
    );
}

#[test]
fn only_the_transport_and_the_listener_own_a_socket() {
    let found = offenders(&SOCKET_OWNERS, opens_socket);
    assert!(
        found.is_empty(),
        "a production module outside the transport and the listener names a socket: {found:?}"
    );
}

#[test]
fn library_code_never_writes_to_the_terminal() {
    let found = offenders(&PROCESS_BOUNDARY, prints);
    assert!(
        found.is_empty(),
        "library code prints; output belongs to the process boundary: {found:?}"
    );
}

#[test]
fn library_code_never_ends_the_process() {
    let found = offenders(&PROCESS_BOUNDARY, ends_process);
    assert!(
        found.is_empty(),
        "library code ends the process; only the process boundary may: {found:?}"
    );
}

/// A scanner that finds nothing would pass every rule above, so every name a rule forbids is also
/// checked on a sample, and the forms it must ignore (comments, literals, test items) too.
#[test]
fn the_scanner_sees_each_forbidden_form_and_ignores_the_rest() {
    let code = production_tokens;
    for name in ENV_READS {
        assert!(
            reads_environment(&code(&format!("use std::env::{name};"))),
            "{name}"
        );
    }
    for name in SOCKET_NAMES {
        assert!(opens_socket(&code(&format!("use net::{name};"))), "{name}");
    }
    for name in PRINT_MACROS {
        assert!(
            prints(&code(&format!("fn f() {{ {name}!(\"x\"); }}"))),
            "{name}"
        );
    }
    assert!(reads_environment(&code("fn f() { std::env::var(\"X\"); }")));
    assert!(reads_environment(&code(
        "use std::env; fn f() { env::var_os(\"X\"); }"
    )));
    assert!(reads_environment(&code("use std::env::var;")));
    assert!(reads_environment(&code("use std::env::{var};")));
    assert!(reads_environment(&code("fn f() { std::env::args(); }")));
    assert!(!reads_environment(&code(
        "// std::env::var(\"X\") in a comment"
    )));
    assert!(!reads_environment(&code(
        "fn f() { let s = \"std::env::var\"; }"
    )));
    assert!(!reads_environment(&code(
        "#[cfg(test)] mod tests { fn f() { std::env::var(\"X\"); } }"
    )));
    assert!(!reads_environment(&code(
        "fn f() { crate::environment::home(); }"
    )));

    assert!(opens_socket(&code("use std::net::TcpStream;")));
    assert!(opens_socket(&code("fn f() { let _ = ureq::get(\"u\"); }")));
    assert!(!opens_socket(&code("// TcpStream in a comment")));

    assert!(prints(&code("fn f() { println!(\"hi\"); }")));
    assert!(prints(&code("fn f() { eprint!(\"hi\"); }")));
    assert!(!prints(&code("fn f() { let s = \"println!\"; }")));
    assert!(!prints(&code("fn f() { format!(\"{}\", 1); }")));

    assert!(ends_process(&code("fn f() { std::process::exit(2); }")));
    assert!(!ends_process(&code("fn f() { let exit = 2; }")));
}
