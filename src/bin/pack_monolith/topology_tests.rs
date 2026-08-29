use super::*;

#[test]
fn classify_layer_matches_expected_ranks() {
    let cases: &[(&str, u32, &str)] = &[
        ("Cargo.toml", 0, "build"),
        (".cargo/config.toml", 0, "build"),
        ("src/util/dns.rs", 1, "util"),
        ("src/core/entity/mod.rs", 2, "core"),
        ("src/storage/mod.rs", 3, "storage"),
        ("src/modules/whois/mod.rs", 4, "modules"),
        ("src/api/mod.rs", 5, "api"),
        ("src/cli/config.rs", 6, "cli"),
        ("src/audit/mod.rs", 7, "audit"),
        ("src/selftest/mod.rs", 8, "selftest"),
        ("src/lib.rs", 9, "crate-root"),
        ("src/main.rs", 9, "crate-root"),
        ("src/web/spa.html", 10, "web"),
        ("src/app/runtime.rs", 11, "src-other"),
        ("tests/architecture.rs", 12, "tests"),
        ("benches/scan_throughput.rs", 13, "benches"),
        ("scripts/gate.sh", 14, "scripts"),
        (".github/workflows/ci.yml", 15, "ci"),
        ("proptest-regressions/foo.txt", 16, "proptest"),
        (".claude/settings.json", 17, "meta"),
        ("README.md", 18, "docs"),
    ];
    for &(path, rank, label) in cases {
        assert_eq!(classify_layer(path), (rank, label), "path: {path}");
    }
}

/// A per-module `build.rs` belongs WITH its module, not the foundation layer
/// — only the crate-root build files (via `EXPLICIT_ORDER`) count as "build".
#[test]
fn per_module_build_rs_stays_with_its_module() {
    assert_eq!(
        classify_layer("src/modules/photon/build.rs"),
        (4, "modules")
    );
}

#[test]
fn module_token_key_puts_mod_rs_before_siblings_and_files_before_subdirs() {
    // mod.rs sorts before another file at the same level.
    assert!(module_token_key("src/core/mod.rs") < module_token_key("src/core/entity.rs"));
    // A file directly in a directory sorts before that directory's own
    // subdirectories, regardless of name — the load-bearing property this
    // key exists for (parent module before child modules).
    assert!(module_token_key("src/core/mod.rs") < module_token_key("src/core/entity/mod.rs"));
    assert!(module_token_key("src/core/aaa_file.rs") < module_token_key("src/core/aaa_dir/mod.rs"));
    // Two plain files sort alphabetically.
    assert!(module_token_key("src/core/a.rs") < module_token_key("src/core/b.rs"));
}

#[test]
fn sort_key_orders_a_representative_path_set_correctly() {
    let mut paths = vec![
        "src/lib.rs".to_string(),
        "src/core/entity/tests.rs".to_string(),
        "Cargo.toml".to_string(),
        "src/util/dns.rs".to_string(),
        "src/core/mod.rs".to_string(),
        "src/core/entity/mod.rs".to_string(),
        "tests/architecture.rs".to_string(),
        "docs/TROUBLESHOOTING.md".to_string(),
    ];
    paths.sort_by_key(|p| sort_key(p));
    assert_eq!(
        paths,
        vec![
            "Cargo.toml",
            "src/util/dns.rs",
            "src/core/mod.rs",
            "src/core/entity/mod.rs",
            "src/core/entity/tests.rs",
            "src/lib.rs",
            "tests/architecture.rs",
            "docs/TROUBLESHOOTING.md",
        ]
    );
}

#[test]
fn category_note_flags_vendor_lockfile_proptest_der_and_web() {
    assert_eq!(
        category_note("src/web/vendor/d3.js"),
        "vendored third-party asset (not HSE-authored)"
    );
    assert_eq!(category_note("Cargo.lock"), "generated dependency lockfile");
    assert_eq!(
        category_note("proptest-regressions/foo.txt"),
        "generated property-test regression seeds"
    );
    assert_eq!(
        category_note("src/modules/tls/cert.der"),
        "binary test fixture (DER certificate)"
    );
    assert_eq!(
        category_note("src/web/js/main.js"),
        "hand-rolled SPA front-end asset"
    );
    assert_eq!(category_note("src/lib.rs"), "");
}
