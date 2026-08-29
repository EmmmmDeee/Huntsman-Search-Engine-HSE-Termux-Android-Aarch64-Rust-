// Included via `mod tests { include!("pack_tests.rs"); }` in pack.rs, so
// `super::*` is the pack module (private items included).
use super::*;

/// A unique, pre-cleaned temp directory for a test that unpacks to disk.
fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "hse-mono-test-{}-{:?}-{tag}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// The core guarantee: pack a diverse set of files (text with and without a
/// trailing newline, an empty file, CRLF text, NUL-binary, invalid-UTF-8
/// binary, and — adversarially — a text file whose own content contains a line
/// that looks like a `### sha256` metablock key) and reconstruct every one
/// byte-for-byte. `write_file` also re-verifies each record's SHA, so this
/// exercises the digest path too.
#[test]
fn round_trip_reconstructs_bytes_exactly() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("src/util/a.rs", b"fn a() {}\n".to_vec()),
        ("src/core/mod.rs", b"// no trailing newline".to_vec()),
        ("README.md", b"# T\n\nbody\n".to_vec()),
        ("empty.txt", Vec::new()),
        ("crlf.txt", b"a\r\nb\r\n".to_vec()),
        ("assets/blob.bin", vec![0u8, 1, 2, 3, 250, 255]),
        ("assets/invalid.dat", vec![0xff, 0xfe, 0xfd, 0x00]),
        // Content that mimics a metablock key must NOT confuse the parser: a
        // payload's lines are consumed positionally (between BEGIN/END), never
        // rescanned for `### ...`.
        ("tricky.md", b"### sha256   : deadbeefdeadbeef\nreal content\n".to_vec()),
    ];
    let entries: Vec<Entry> =
        cases.iter().map(|(p, d)| Entry::new(p.to_string(), d.clone())).collect();
    let total = entries.len();
    let mut mono = String::new();
    for (i, e) in entries.iter().enumerate() {
        mono.push_str(&body_record(e, i + 1, total));
    }

    let dir = tmp_dir("roundtrip");
    let restored = unpack(&mono, &dir).expect("unpack must succeed and SHAs must match");
    assert_eq!(restored.len(), cases.len(), "restored file count");
    for (p, d) in &cases {
        let got = std::fs::read(dir.join(p)).unwrap_or_else(|_| panic!("missing restored file {p}"));
        assert_eq!(&got, d, "byte mismatch for {p}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn classify_layer_assigns_expected_ranks() {
    assert_eq!(classify_layer("Cargo.toml"), (0, "build"));
    assert_eq!(classify_layer(".cargo/config.toml"), (0, "build"));
    assert_eq!(classify_layer("src/util/foo.rs").0, 1);
    assert_eq!(classify_layer("src/core/mod.rs").0, 2);
    assert_eq!(classify_layer("src/storage/db.rs").0, 3);
    assert_eq!(classify_layer("src/modules/x/mod.rs").0, 4);
    assert_eq!(classify_layer("src/api/routes.rs").0, 5);
    assert_eq!(classify_layer("src/cli/mod.rs").0, 6);
    assert_eq!(classify_layer("src/lib.rs"), (9, "crate-root"));
    assert_eq!(classify_layer("src/web/js/main.js").0, 10);
    assert_eq!(classify_layer("tests/architecture.rs").0, 12);
    assert_eq!(classify_layer("scripts/gate.sh").0, 14);
    assert_eq!(classify_layer("README.md"), (18, "docs"));
    // A per-module build.rs stays WITH its module (rank 4), not foundation.
    assert_eq!(classify_layer("src/modules/photon/build.rs").0, 4);
    // The crate-root build.rs IS foundation.
    assert_eq!(classify_layer("build.rs"), (0, "build"));
}

#[test]
fn sort_orders_mod_first_then_files_then_subdirs() {
    let mut paths = vec![
        "src/core/foo/sub/mod.rs",
        "src/core/foo/bar.rs",
        "src/core/foo/mod.rs",
        "src/core/mod.rs",
    ];
    paths.sort_by_key(|p| sort_key(p));
    assert_eq!(
        paths,
        vec![
            "src/core/mod.rs",       // parent module file first
            "src/core/foo/mod.rs",   // child dir's own mod.rs
            "src/core/foo/bar.rs",   // then other files in that dir
            "src/core/foo/sub/mod.rs", // then deeper sub-dirs
        ]
    );
}

#[test]
fn sort_respects_layer_rank_then_explicit_order() {
    // Cargo.toml (explicit 0) before Cargo.lock (explicit 1), both rank 0;
    // a util file (rank 1) after both.
    let mut paths = vec!["src/util/x.rs", "Cargo.lock", "Cargo.toml"];
    paths.sort_by_key(|p| sort_key(p));
    assert_eq!(paths, vec!["Cargo.toml", "Cargo.lock", "src/util/x.rs"]);
}

#[test]
fn is_binary_detects_nul_and_invalid_utf8() {
    assert!(!is_binary(b"plain text\n"));
    assert!(!is_binary(b""));
    assert!(!is_binary("héllo — utf8".as_bytes()));
    assert!(is_binary(&[0u8, 1, 2]));
    assert!(is_binary(&[0xff, 0xfe]));
}

#[test]
fn number_formatting_matches_python() {
    assert_eq!(commas(0), "0");
    assert_eq!(commas(999), "999");
    assert_eq!(commas(1000), "1,000");
    assert_eq!(commas(1_234_567), "1,234,567");
    assert_eq!(commas_f1(1.0), "1.0");
    assert_eq!(commas_f1(1234.56), "1,234.6");
    assert_eq!(human(0), "0 B");
    assert_eq!(human(512), "512 B");
    assert_eq!(human(1024), "1.0 KiB");
    assert_eq!(human(1536), "1.5 KiB");
    assert_eq!(human(1_048_576), "1.0 MiB");
}

#[test]
fn sanitize_remote_strips_credentials_and_proxy() {
    // A plain https URL: scheme dropped, `.git` trimmed — the host is kept
    // (this mirrors the Python original; it only fully slugifies the proxy
    // form below, which is the one that leaks a `local_proxy@host` prefix).
    assert_eq!(
        sanitize_remote("https://github.com/owner/repo.git"),
        "github.com/owner/repo"
    );
    // The sandbox proxy form — credentials + host + `/git/` all stripped to
    // the bare `owner/repo` slug, so no proxy host is baked into the artifact.
    assert_eq!(
        sanitize_remote("http://local_proxy@127.0.0.1:8080/git/owner/repo"),
        "owner/repo"
    );
    assert_eq!(sanitize_remote(""), "(unknown)");
}

#[test]
fn lang_for_maps_extensions() {
    assert_eq!(lang_for("a/b.rs", false), "rust");
    assert_eq!(lang_for("x.toml", false), "toml");
    assert_eq!(lang_for("Cargo.lock", false), "toml");
    assert_eq!(lang_for(".gitignore", false), "gitignore");
    assert_eq!(lang_for("x.unknownext", false), "text");
    assert_eq!(lang_for("anything.rs", true), "binary");
}
