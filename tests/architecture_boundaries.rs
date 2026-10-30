//! The boundaries `ARCHITECTURE.md` states for production code, checked on the token stream of
//! every file under `src/`. Comments, literals and `#[cfg(test)]` items are not production code,
//! so they are not checked. The process boundary is the binary's adapters (`src/cli`, `src/bin`,
//! `src/main.rs`): it alone reads the process environment and its arguments, writes to the
//! terminal, or ends the process. Library code takes those as values.

#[allow(dead_code)]
#[path = "support/rust_code.rs"]
mod rust_code;

use rust_code::{code_with_string_literals, strip_non_code, tokens, without_test_items};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The binary's adapters: the one place a process reads its environment or arguments, prints, or
/// ends.
const PROCESS_BOUNDARY: [&str; 3] = ["src/cli", "src/bin", "src/main.rs"];
/// The one library module that reads the environment. Its accessors are the configuration surface.
const ENVIRONMENT_READER: [&str; 1] = ["src/environment.rs"];
/// The modules that own a socket: the outbound transport, the inbound listener, and the
/// listener's loopback health probe that `doctor` runs, and the standalone `MetaScan`
/// loopback listener.
const SOCKET_OWNERS: [&str; 4] = [
    "src/http.rs",
    "src/web_server.rs",
    "src/serve_probe.rs",
    "src/bin/meta_scan/web.rs",
];

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
/// The suffixes a credential slot name ends in: a key, a token, a secret, an id or a user name.
const CREDENTIAL_SUFFIXES: [&str; 5] = ["_KEY", "_TOKEN", "_SECRET", "_ID", "_USER"];
/// The one module that names a credential slot. Other production code refers to its constants.
const SLOT_OWNER: [&str; 1] = ["src/environment.rs"];
/// The module that builds an outcome from its fields, and `fetch.rs`, which refines an outcome it
/// already holds with struct-update syntax.
const OUTCOME_OWNERS: [&str; 2] = ["src/source_outcome.rs", "src/fetch.rs"];
/// The one module that measures time from the Unix epoch. Every other production module asks it for
/// the time, so each timestamp is taken the same way.
const CLOCK_READER: [&str; 1] = ["src/clock.rs"];

/// The lookups that end from their source rows through `source_outcome::SourceReach`, and the
/// indicator legs below them. Each reads how far its sources got from the rows they recorded, so
/// none names a typed refusal (`LegError::Refused`, `LegError::Transport`) or reads the
/// `is_transport_failure` predicate at the call site, and none keeps a `refused`/`unanswered`/
/// `no_response`/`network` side channel of type `Option<String>` beside those rows.
const REFUSAL_ROUTED: [&str; 13] = [
    "src/ip_cli.rs",
    "src/ip_cli",
    "src/netblock_cli.rs",
    "src/netblock_cli",
    "src/asn_cli.rs",
    "src/domain_cli.rs",
    "src/domain_cli",
    "src/email_cli.rs",
    "src/username_cli.rs",
    "src/exposure_cli.rs",
    "src/network_cli.rs",
    "src/network_cli",
    "src/indicator_legs.rs",
];
/// The side-channel field and parameter names a refusal-routed lookup must not keep beside its
/// rows: the row's kind is the one authority `SourceReach` reads.
const REASON_CHANNEL_NAMES: [&str; 4] = ["refused", "unanswered", "no_response", "network"];

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

/// The text of each string literal in `text` that is production code, in source order.
fn production_string_literals(text: &str) -> Vec<String> {
    let (code, literals) = code_with_string_literals(text);
    without_test_items(&tokens(&code))
        .0
        .iter()
        .filter_map(|token| {
            let index = token.strip_prefix("__str")?.parse::<usize>().ok()?;
            literals.get(index).cloned()
        })
        .collect()
}

/// Whether a string literal names a credential: a `HUNTSMAN_` name with a credential suffix, or one
/// of the two names outside that prefix, the standard `HIBP_API_KEY` and the `serve` token.
fn names_a_credential_slot(literal: &str) -> bool {
    matches!(literal, "HIBP_API_KEY" | "HSE_AUTH_TOKEN")
        || (literal.starts_with("HUNTSMAN_")
            && CREDENTIAL_SUFFIXES
                .iter()
                .any(|suffix| literal.ends_with(suffix)))
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

/// Whether the tokens read keys from the environment alone (`Keys::from_env`) or load the HIBP key
/// without the lookup keys' slot (`default_chain(None)`). Either leaves a key set only in
/// `~/.huntsman.env` unused, though `credential-status` reports it as set.
fn reads_keys_without_the_default_file(toks: &[String]) -> bool {
    toks.windows(3)
        .any(|w| w[0] == "Keys" && w[1] == "::" && w[2] == "from_env")
        || toks
            .windows(3)
            .any(|w| w[0] == "default_chain" && w[1] == "(" && w[2] == "None")
}

#[test]
fn every_lookup_reads_keys_from_the_default_file_too() {
    let found = offenders(&["src/keys.rs"], reads_keys_without_the_default_file);
    assert!(
        found.is_empty(),
        "production code reads keys from the environment only; use `Keys::for_lookup` \
         (the binary's `lookup_keys`) so a key in ~/.huntsman.env is used: {found:?}"
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

/// Whether the tokens name the Unix epoch, which a wall-clock reading is measured from.
fn measures_from_the_unix_epoch(toks: &[String]) -> bool {
    toks.iter().any(|t| t == "UNIX_EPOCH")
}

#[test]
fn only_the_clock_module_measures_time_from_the_unix_epoch() {
    let found = offenders(&CLOCK_READER, measures_from_the_unix_epoch);
    assert!(
        found.is_empty(),
        "production code measures Unix time outside `src/clock.rs`; ask `clock` for the time: {found:?}"
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

/// Whether the tokens put a secret on a request themselves: a `header(..)` or
/// `append_query_param(..)` call whose arguments read a secret with `expose`.
fn attaches_a_secret(toks: &[String]) -> bool {
    toks.windows(2).enumerate().any(|(start, w)| {
        (w[0] == "header" || w[0] == "append_query_param")
            && w[1] == "("
            && call_reads_a_secret(&toks[start + 1..])
    })
}

/// Whether the call whose `(` begins `toks` reads `expose` before its matching `)`.
fn call_reads_a_secret(toks: &[String]) -> bool {
    let mut depth = 0usize;
    for token in toks {
        match token.as_str() {
            "(" => depth += 1,
            ")" => {
                depth -= 1;
                if depth == 0 {
                    return false;
                }
            }
            "expose" => return true,
            _ => {}
        }
    }
    false
}

/// The one module that puts a secret on a request: `fetch::Credential`, which sends it only to
/// the origin it is bound to, strips it from every other hop and scrubs it from diagnostics.
const SECRET_ATTACHER: [&str; 1] = ["src/fetch.rs"];

#[test]
fn only_the_fetch_credential_puts_a_secret_on_a_request() {
    let found = offenders(&SECRET_ATTACHER, attaches_a_secret);
    assert!(
        found.is_empty(),
        "production code sets a key on a request itself; pass a `fetch::Credential` built from \
         an `AuthenticationAuthority` to `fetch` instead: {found:?}"
    );
}

#[test]
fn the_secret_rule_sees_a_header_or_query_key_and_nothing_else() {
    let reads = |code: &str| attaches_a_secret(&production_tokens(code));
    assert!(reads(
        "fn f() { req.header(\"hibp-api-key\", key.expose()); }"
    ));
    assert!(reads(
        "fn f() { req.header(NAME, format!(\"Bearer {}\", s.expose())); }"
    ));
    assert!(reads(
        "fn f() { append_query_param(&url, \"key\", secret.expose()); }"
    ));
    assert!(!reads(
        "fn f() { req.header(\"Accept\", \"application/json\"); let n = key.expose().len(); }"
    ));
    assert!(!reads(
        "#[cfg(test)] mod tests { fn f() { req.header(\"k\", key.expose()); } }"
    ));
}

#[test]
fn library_code_never_ends_the_process() {
    let found = offenders(&PROCESS_BOUNDARY, ends_process);
    assert!(
        found.is_empty(),
        "library code ends the process; only the process boundary may: {found:?}"
    );
}

#[test]
fn only_the_environment_module_names_a_credential_slot() {
    let found: Vec<String> = production_sources()
        .into_iter()
        .filter(|source| !SLOT_OWNER.iter().any(|entry| under(&source.path, entry)))
        .filter(|source| {
            production_string_literals(&source.text)
                .iter()
                .any(|literal| names_a_credential_slot(literal))
        })
        .map(|source| source.path)
        .collect();
    assert!(
        found.is_empty(),
        "production code writes a credential slot as a string literal; name it in \
         `src/environment.rs` and refer to the constant: {found:?}"
    );
}

/// The formats of the two rows a report gives an entity, as the literals read in the source: the
/// entity itself (kind, value, confidence, tags) and the evidence behind it (source, summary).
const REPORT_ROWS: [&str; 2] = ["{}\\t{}\\t{:.2}\\t{}", "evidence\\t{}\\t{}"];
/// The one module that formats them, and so the one place that makes their values safe to print.
const REPORT_OWNER: [&str; 1] = ["src/lookup_report.rs"];

/// The production files outside `owners` that hold a string literal equal to `needle`.
fn literal_offenders(owners: &[&str], needle: &str) -> Vec<String> {
    production_sources()
        .into_iter()
        .filter(|source| !owners.iter().any(|entry| under(&source.path, entry)))
        .filter(|source| {
            production_string_literals(&source.text)
                .iter()
                .any(|literal| literal == needle)
        })
        .map(|source| source.path)
        .collect()
}

#[test]
fn only_the_lookup_report_formats_an_entity_or_evidence_row() {
    for row in REPORT_ROWS {
        let found = literal_offenders(&REPORT_OWNER, row);
        assert!(
            found.is_empty(),
            "a second module formats the report row `{row}`; call `lookup_report::entity_row` or \
             `lookup_report::evidence_row`, which neutralise third-party text, instead: {found:?}"
        );
    }
}

#[test]
fn the_report_row_rule_sees_each_row_and_ignores_comments() {
    for row in REPORT_ROWS {
        let code = format!("fn f() {{ writeln!(out, \"{row}\", a, b); }}");
        assert!(
            production_string_literals(&code)
                .iter()
                .any(|literal| literal == row),
            "{row}"
        );
        let commented = format!("// \"{row}\"\nfn f() {{}}");
        assert!(
            !production_string_literals(&commented)
                .iter()
                .any(|literal| literal == row),
            "{row}"
        );
    }
}

/// Whether the tokens build a `SourceExecutionOutcome` with a struct literal. The type name followed
/// by a brace is a literal, unless the brace follows `impl`, `struct` or `for`, or the `>` of a
/// return type (`->` is two tokens).
fn builds_an_outcome_literal(toks: &[String]) -> bool {
    toks.windows(2).enumerate().any(|(index, pair)| {
        pair[0] == "SourceExecutionOutcome"
            && pair[1] == "{"
            && !(index > 0 && matches!(toks[index - 1].as_str(), "impl" | "struct" | "for" | ">"))
    })
}

#[test]
fn only_the_outcome_module_builds_an_outcome_literal() {
    let found = offenders(&OUTCOME_OWNERS, builds_an_outcome_literal);
    assert!(
        found.is_empty(),
        "production code builds a SourceExecutionOutcome with a struct literal; call one of its \
         constructors in `src/source_outcome.rs` instead: {found:?}"
    );
}

#[test]
fn the_outcome_literal_rule_sees_a_literal_and_ignores_declarations() {
    let literal = production_tokens("fn f() { let o = SourceExecutionOutcome { module: m }; }");
    assert!(builds_an_outcome_literal(&literal));
    for declaration in [
        "impl SourceExecutionOutcome { fn g() {} }",
        "struct SourceExecutionOutcome { module: String }",
        "impl Trait for SourceExecutionOutcome { }",
        "fn f() -> SourceExecutionOutcome { todo() }",
    ] {
        assert!(
            !builds_an_outcome_literal(&production_tokens(declaration)),
            "{declaration}"
        );
    }
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
    assert!(measures_from_the_unix_epoch(&code(
        "fn f() { SystemTime::now().duration_since(std::time::UNIX_EPOCH); }"
    )));
    assert!(!measures_from_the_unix_epoch(&code(
        "// SystemTime::now().duration_since(UNIX_EPOCH) in a comment"
    )));
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

    assert_eq!(
        production_string_literals("const K: &str = \"HUNTSMAN_SHODAN_KEY\";"),
        ["HUNTSMAN_SHODAN_KEY"]
    );
    assert_eq!(
        production_string_literals("// const K: &str = \"HUNTSMAN_SHODAN_KEY\";"),
        Vec::<String>::new()
    );
    assert_eq!(
        production_string_literals(
            "#[cfg(test)] mod t { const K: &str = \"HUNTSMAN_SHODAN_KEY\"; }"
        ),
        Vec::<String>::new()
    );
    for name in [
        "HUNTSMAN_SHODAN_KEY",
        "HUNTSMAN_GITHUB_TOKEN",
        "HUNTSMAN_CENSYS_ID",
        "HUNTSMAN_WIGLE_USER",
        "HUNTSMAN_CENSYS_SECRET",
        "HIBP_API_KEY",
        "HSE_AUTH_TOKEN",
    ] {
        assert!(names_a_credential_slot(name), "{name}");
    }
    for text in [
        "HUNTSMAN_DATA_DIR",
        "HUNTSMAN_SHODAN_KEY is set in the environment",
        "HUNTSMAN_SHODAN_KEY_ENV",
    ] {
        assert!(!names_a_credential_slot(text), "{text}");
    }
}

/// The production files under `scoped` whose tokens `matches`, the mirror of [`offenders`] for a
/// rule that holds only within a set of files rather than everywhere outside one.
fn scoped_offenders(scoped: &[&str], matches: fn(&[String]) -> bool) -> Vec<String> {
    production_sources()
        .into_iter()
        .filter(|source| scoped.iter().any(|entry| under(&source.path, entry)))
        .filter(|source| matches(&production_tokens(&source.text)))
        .map(|source| source.path)
        .collect()
}

/// Whether the tokens name a typed refusal (`LegError::Refused` or `LegError::Transport`) or read
/// the `is_transport_failure` predicate — the forms a lookup would use to route a refusal or a
/// no-response beside its rows instead of reading the rows themselves.
fn routes_a_refusal(toks: &[String]) -> bool {
    toks.windows(3).any(|w| {
        w[0] == "LegError" && w[1] == "::" && matches!(w[2].as_str(), "Refused" | "Transport")
    }) || toks.iter().any(|t| t == "is_transport_failure")
}

#[test]
fn lookups_never_route_refusals_beside_their_rows() {
    let found = scoped_offenders(&REFUSAL_ROUTED, routes_a_refusal);
    assert!(
        found.is_empty(),
        "a refusal-routed lookup names LegError::Refused/Transport or reads is_transport_failure \
         at the call site; end from the rows through source_outcome::SourceReach instead: {found:?}"
    );
}

#[test]
fn the_refusal_route_rule_sees_each_forbidden_form_and_ignores_the_rest() {
    let code = production_tokens;
    assert!(routes_a_refusal(&code(
        "fn f() { if let LegError::Refused(m) = e {} }"
    )));
    assert!(routes_a_refusal(&code(
        "fn f() { if let crate::api_leg::LegError::Transport(k) = e {} }"
    )));
    assert!(routes_a_refusal(&code(
        "fn f() { if o.kind.is_transport_failure() {} }"
    )));
    // Reading the rows through SourceReach is the allowed form.
    assert!(!routes_a_refusal(&code(
        "fn f() { SourceReach::of(&report.outcomes).unanswered(lead); }"
    )));
    assert!(!routes_a_refusal(&code(
        "// LegError::Refused in a comment"
    )));
    assert!(!routes_a_refusal(&code(
        "fn f() { let s = \"is_transport_failure\"; }"
    )));
    assert!(!routes_a_refusal(&code(
        "#[cfg(test)] mod t { fn f() { let _ = o.kind.is_transport_failure(); } }"
    )));
}

/// Whether `rest` begins with `Option<String>`, optionally behind a `&mut`: the type of a reason
/// side channel kept beside a lookup's rows.
fn is_optional_string(rest: &[String]) -> bool {
    let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
    let core: &[&str] = match rest.as_slice() {
        ["&", "mut", tail @ ..] => tail,
        other => other,
    };
    matches!(core, ["Option", "<", "String", ">", ..])
}

/// Whether the tokens declare a field or parameter named for a reason side channel
/// ([`REASON_CHANNEL_NAMES`]) of type `Option<String>` or `&mut Option<String>`.
fn keeps_a_reason_channel(toks: &[String]) -> bool {
    toks.iter().enumerate().any(|(i, t)| {
        REASON_CHANNEL_NAMES.contains(&t.as_str())
            && toks.get(i + 1).is_some_and(|c| c == ":")
            && is_optional_string(&toks[i + 2..])
    })
}

#[test]
fn lookups_keep_no_reason_channel() {
    let found = scoped_offenders(&REFUSAL_ROUTED, keeps_a_reason_channel);
    assert!(
        found.is_empty(),
        "a refusal-routed lookup keeps a refused/unanswered/no_response/network reason channel of \
         type Option<String>; the row's kind is the one authority, read by SourceReach: {found:?}"
    );
}

#[test]
fn the_reason_channel_rule_sees_each_channel_and_ignores_the_rest() {
    let code = production_tokens;
    for name in REASON_CHANNEL_NAMES {
        assert!(
            keeps_a_reason_channel(&code(&format!("struct S {{ {name}: Option<String> }}"))),
            "{name} field"
        );
        assert!(
            keeps_a_reason_channel(&code(&format!("fn f({name}: &mut Option<String>) {{}}"))),
            "{name} parameter"
        );
    }
    // A channel of another type, a local, a comment, or a test item is not a reason channel.
    assert!(!keeps_a_reason_channel(&code(
        "struct S { network: Option<IpAddr> }"
    )));
    assert!(!keeps_a_reason_channel(&code(
        "struct S { outcomes: Vec<SourceExecutionOutcome> }"
    )));
    assert!(!keeps_a_reason_channel(&code(
        "fn f() { let network = String::new(); }"
    )));
    assert!(!keeps_a_reason_channel(&code(
        "// network: Option<String> in a comment"
    )));
    assert!(!keeps_a_reason_channel(&code(
        "#[cfg(test)] mod t { struct S { network: Option<String> } }"
    )));
}

/// The `WiGLE` collector reads the network selector grammar from `network_selector`, never from
/// `scan_route`: collection does not depend on scan routing (`docs/ARCHITECTURE.md`, Stage 6).
#[test]
fn the_wigle_collector_does_not_depend_on_scan_routing() {
    let found: Vec<String> = production_sources()
        .into_iter()
        .filter(|source| source.path == "src/wigle.rs" || under(&source.path, "src/wigle"))
        .filter(|source| {
            production_tokens(&source.text)
                .iter()
                .any(|t| t == "scan_route")
        })
        .map(|source| source.path)
        .collect();
    assert!(found.is_empty(), "wigle names scan_route: {found:?}");
}
