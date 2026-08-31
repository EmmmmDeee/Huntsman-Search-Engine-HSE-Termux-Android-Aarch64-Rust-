#[test]
fn skiptrace_focus_maps_to_the_right_real_modules() {
    // The `skiptrace` profile restricts dispatch by category. This guard pins
    // that the focus resolves to a healthy, correct set of REAL modules — so a
    // future category change (or a regression of the hudsonrock/au_unclaimed
    // categorisations) can't silently gut or pollute debtor-location scans.
    use huntsman_search_engine::core::module::ModuleCategory;
    use huntsman_search_engine::core::profiles::SKIPTRACE_CATEGORIES;

    let modules = huntsman_search_engine::modules::registry();
    let category_of = |name: &str| -> Option<ModuleCategory> {
        modules
            .iter()
            .find(|m| m.name() == name)
            .map(|m| m.category())
    };
    let in_focus = |name: &str| -> bool {
        category_of(name).is_some_and(|c| SKIPTRACE_CATEGORIES.contains(&c))
    };

    // Every focused category must be populated — an empty category would mean
    // the focus silently narrows the scan with nothing to show for it.
    for cat in SKIPTRACE_CATEGORIES {
        assert!(
            modules.iter().any(|m| m.category() == *cat),
            "skiptrace focus category {cat:?} maps to no registered module"
        );
    }

    // The core person-locators MUST be in focus (incl. hudsonrock → Breach).
    for name in [
        "employer_pivot",  // People — where they work / ability to pay
        "au_unclaimed",    // Corporate — name → government register + address (incl. QLD)
        "geocode",         // Geo — address → coordinates
        "geo_intel",       // Geo
        "phone_intl",      // Phone — contactability + country
        "social_probe",    // Social — owned accounts / aliases
        "username_search", // Social — cross-platform handle hunt
        "opencorporates",  // Corporate — directorships / assets
        "abn_lookup",      // Corporate — AU business / assets
        "search_engines",  // Search — open-web address/phone/associate scrape
        "dehashed",        // Breach — leaked phone/address/credentials
        "hudsonrock",      // Breach — stealer-log intel
        "email_parse",     // Email — identity bridge
    ] {
        assert!(
            in_focus(name),
            "skip-trace needs `{name}` ({:?}) in the category focus",
            category_of(name)
        );
    }

    // Pure-noise-for-people modules MUST be excluded — running them on a debtor
    // search is wasted budget.
    for name in [
        "shodan",         // Infrastructure
        "censys",         // Infrastructure
        "threatfox",      // Threat
        "urlhaus",        // Threat
        "device_sensors", // Sensor (the operator's own device)
        "portscan",       // Infrastructure
    ] {
        assert!(
            !in_focus(name),
            "skip-trace must NOT spend budget on `{name}` ({:?})",
            category_of(name)
        );
    }
}

#[test]
fn non_passive_modules_budget_above_default() {
    let default = huntsman_search_engine::MODULE_TIMEOUT_MS;
    let modules = huntsman_search_engine::modules::registry();
    let under_budget: Vec<(&str, u64)> = modules
        .iter()
        .filter(|m| !m.is_passive())
        .map(|m| (m.name(), m.max_timeout_ms()))
        .filter(|(_, budget)| *budget <= default)
        .collect();
    assert!(
        under_budget.is_empty(),
        "non-passive modules must override max_timeout_ms() above the {default}ms \
         default or the engine kills them mid-request; offenders: {under_budget:?}"
    );
}

#[test]
fn architecture_constants() {
    assert_eq!(huntsman_search_engine::MODULE_TIMEOUT_MS, 3000);
    assert_eq!(huntsman_search_engine::WORKER_THREADS, 2);
    assert_eq!(huntsman_search_engine::DEFAULT_BIND, "127.0.0.1:8080");
}

/// Recursively collect `.rs` file paths under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// True iff `s` is at least `n` characters, entirely ASCII hex digits, and
/// contains at least one decimal digit — the last clause excludes purely
/// alphabetic hex-alphabet strings (e.g. a stray word like "deedbead" would
/// pass `is_ascii_hexdigit` alone) while still matching real deployed keys,
/// which are effectively random over 0-9a-f.
fn hexish(s: &str, n: usize) -> bool {
    s.len() >= n && s.chars().all(|c| c.is_ascii_hexdigit()) && s.chars().any(char::is_numeric)
}

/// True iff `lit` matches one of the two provider-key shapes this project has
/// actually leaked and could plausibly paste back: SeekNow (`seek-` + 48 hex)
/// or a WiGLE API name (`AID` + 32 hex). A generic "long hex run" rule is
/// deliberately NOT used here — this codebase is full of legitimate MD5/SHA/
/// UUID fixtures — the `secret-scan` workflow's entropy rules cover the
/// general case. Shared by [`no_provider_credential_is_embedded_in_source`]
/// and [`no_provider_credential_is_embedded_in_narrative_files`].
fn looks_like_provider_key(lit: &str) -> bool {
    lit.strip_prefix("seek-").is_some_and(|r| hexish(r, 32))
        || lit.strip_prefix("AID").is_some_and(|r| hexish(r, 24))
}

/// No provider credential may be embedded in the source tree.
///
/// This repository is public and every released binary is downloadable, so a
/// credential compiled into the build is a credential disclosed to everyone.
/// Earlier revisions shipped live OathNet / HIBP / WiGLE / SeekNow keys as
/// "zero-config defaults"; they were removed, revoked, and replaced by a
/// required-key contract (`ModuleContext::key` → `Error::MissingKey` → a "needs
/// key" skip). This test is what stops one being added back.
///
/// It is a coarse, deliberately conservative net — CI's dedicated secret scanner
/// (`.github/workflows/secret-scan.yml`) is the thorough one — but it runs in
/// the normal `cargo test` gate, so a re-embedded key fails locally and in every
/// PR rather than only in a scheduled job.
///
/// The shape check ([`looks_like_provider_key`]) is shared with
/// [`no_provider_credential_is_embedded_in_narrative_files`] below, which
/// applies the identical check outside `src/` — the file-scope, not the
/// shape, is what differs between the two.
#[test]
fn no_provider_credential_is_embedded_in_source() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs_files(&root.join("src"), &mut files);

    // A credential-named constant bound to a long literal is the exact shape the
    // removed defaults had (`const HIBP_DEFAULT_KEY: &str = "…"`). Env-var NAMES
    // and URLs share those constant names legitimately, so both are excluded.
    let credential_const = |line: &str| -> bool {
        let Some((decl, rest)) = line.split_once(": &str =") else {
            return false;
        };
        let decl = decl.trim();
        if !(decl.starts_with("const ")
            || decl.starts_with("pub const ")
            || decl.contains("static "))
        {
            return false;
        }
        let name = decl.rsplit(' ').next().unwrap_or_default();
        if !["_KEY", "_TOKEN", "_SECRET", "_USER", "_GUID", "_ID"]
            .iter()
            .any(|s| name.ends_with(s))
        {
            return false;
        }
        let Some(value) = rest.split('"').nth(1) else {
            return false;
        };
        value.len() >= 16
            && !value.starts_with("HUNTSMAN_")
            && !value.starts_with("http")
            && !value.contains(' ')
    };

    let mut offenders = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        // Test fixtures legitimately carry synthetic keys in each provider's real
        // shape — that is how HSE's credential-DETECTION engine is tested.
        if rel.contains("tests.rs") || rel.contains("/tests/") || rel.contains("testdata") {
            continue;
        }
        let content = fs::read_to_string(&path).unwrap();
        for (n, line) in content.lines().enumerate() {
            if credential_const(line) {
                offenders.push(format!("{rel}:{} (credential-named const)", n + 1));
            }
        }
        // `util::keys::constants` holds SHA-256 digests of the retired
        // credentials so upgrades can purge them; digests are one-way, and
        // `util::keys::tests::no_credential_is_embedded_in_the_build` asserts
        // every entry there is a 64-char hex digest and never a plaintext key.
        if rel.ends_with("util/keys/constants.rs") {
            continue;
        }
        for lit in content.split('"').skip(1).step_by(2) {
            if looks_like_provider_key(lit) {
                offenders.push(format!("{rel} (provider-key literal)"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "credential-shaped literal(s) in source — this build must ship NO provider \
         credentials; require the operator's own key via `ctx.key(...)` instead: {offenders:?}"
    );
}

/// No provider credential may be pasted into a narrative/bookkeeping file
/// outside `src/`. `no_provider_credential_is_embedded_in_source` above only
/// scans `.rs` files under `src/` — a live-shaped SeekNow key leaked into
/// `.agent/state.json` for 17 days specifically because that file is neither
/// (see `docs/CREDENTIAL_AUDIT_2026-08-27.md`). Two new `gitleaks` rules
/// closed the detection gap at the repo-scanning layer; this is the same
/// SHAPE check ([`looks_like_provider_key`]) made a `cargo test`-gated, always
/// -local complement, per that audit's own follow-up recommendation.
///
/// Deliberately an explicit small file list, not a tree-walk over everything
/// outside `src/`: `Cargo.lock`, vendored test fixtures, and the rest of the
/// non-`src/` tree are not free-text narrative and would only add
/// false-positive risk (fixture hashes, lockfile checksums) with no real
/// leak-surface benefit. Add a path here the day a new narrative/bookkeeping
/// file joins `.agent/state.json`, rather than widening the scope generally.
#[test]
fn no_provider_credential_is_embedded_in_narrative_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    const NARRATIVE_FILES: &[&str] = &[".agent/state.json"];

    let mut offenders = Vec::new();
    for rel in NARRATIVE_FILES {
        let content = fs::read_to_string(root.join(rel))
            .unwrap_or_else(|e| panic!("narrative file {rel} must be readable: {e}"));
        for lit in content.split('"').skip(1).step_by(2) {
            if looks_like_provider_key(lit) {
                offenders.push(format!("{rel} (provider-key-shaped literal)"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "credential-shaped literal(s) in a narrative file — rotate the credential \
         immediately and see docs/CREDENTIAL_AUDIT_2026-08-27.md for the response \
         playbook: {offenders:?}"
    );
}

/// Guards against the silent-key-mismatch bug class: a key documented in the
/// provisioning template under a name no module actually reads, so the operator
/// sets it and gets nothing. Every key in `env_template.txt` must be genuinely
/// READ somewhere in `src/` (an `_ENV` const, a `ctx.key`/`key_opt` call, or a
/// direct `env::var` read), or be explicitly listed as reserved.
///
/// Deliberately does NOT count mere `service_defs()` registration as
/// consumption (a `ServiceDef` only drives `hse doctor`'s validation probe and
/// the Settings UI, and can exist with zero consuming modules): that was
/// exactly the loophole that let `HUNTSMAN_BREACHDIR_KEY`,
/// `HUNTSMAN_BINARYEDGE_KEY`, `HUNTSMAN_C99_KEY`, `HUNTSMAN_FULLHUNT_KEY`,
/// `HUNTSMAN_PULSEDIVE_KEY`, and `HUNTSMAN_PASSIVETOTAL_KEY` go orphaned
/// (registered, documented, and even accepted by `hse doctor` — yet spent by
/// no scan) before each finally grew a real consuming module. Nor does it
/// count a bare textual mention anywhere in `src/` (a doc comment, another
/// constant's value, `service_defs.rs`'s own registration literal): every one
/// of those six keys was already textually present in `src/` the whole time
/// they were orphaned, so that weaker bar would have let them straight
/// through.
#[test]
fn env_template_keys_are_all_consumed() {
    use std::collections::HashSet;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Documented but currently a no-op for the operator. Each MUST be marked
    // `[RESERVED]` in the template; setting any of them has no runtime effect.
    // Usually because no consuming module has shipped yet — except
    // `HUNTSMAN_PROXYCURL_KEY`, whose module *did* ship and consume it, but the
    // vendor permanently sunset the API (2026-08-26): `proxycurl::process` now
    // short-circuits unconditionally without reading the key, so it is exactly
    // as inert to an operator as the "not yet wired" entries below.
    const NOT_YET_WIRED: &[&str] = &[
        "HUNTSMAN_MALSHARE_KEY",
        "HUNTSMAN_PHISHTANK_KEY",
        "HUNTSMAN_XPOSEDORNOT_KEY",
        "HUNTSMAN_HUDSONROCK_KEY",
        "HUNTSMAN_MACADDRESS_KEY",
        "HUNTSMAN_IPINFO_KEY",
        "HUNTSMAN_MAXMIND_KEY",
        "HUNTSMAN_PROXYCURL_KEY",
    ];

    // 1. Keys declared in the provisioning template.
    let template = fs::read_to_string(root.join("src/cli/env_template.txt")).unwrap();
    let declared: Vec<String> = template
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("HUNTSMAN_"))
        .filter_map(|l| l.split('=').next())
        .map(|k| k.trim().to_string())
        .collect();
    assert!(!declared.is_empty(), "no keys parsed from env template");

    // 2. Keys genuinely read somewhere in source. `collect_key_env_consts`
    //    (the `_ENV`-const / `key`/`key_opt` forms) stays scoped to `src/` here
    //    rather than `src/modules` — this test cares about ANY consumer, not
    //    just OSINT-provider modules. `collect_raw_huntsman_env_reads` (below,
    //    shared with `modules_never_read_credentials_via_raw_env`) adds the one
    //    further form real config-knob reads use (`env::var(...)` bypassing
    //    `ModuleContext` entirely) that the other collector intentionally
    //    excludes (see its own doc comment) — called over all of `src/` here
    //    rather than that test's `src/modules`-only scope, for the same
    //    any-consumer-counts reason as the line above.
    let mut consumed: HashSet<String> = HashSet::new();
    collect_key_env_consts(&root.join("src"), &mut consumed);
    collect_raw_huntsman_env_reads(&root.join("src"), &mut consumed);

    let reserved: HashSet<&str> = NOT_YET_WIRED.iter().copied().collect();

    // Every documented key must be consumed/registered, or explicitly reserved.
    let orphans: Vec<&String> = declared
        .iter()
        .filter(|k| !consumed.contains(k.as_str()) && !reserved.contains(k.as_str()))
        .collect();
    assert!(
        orphans.is_empty(),
        "env template documents keys no module reads (silent no-op for the operator): {orphans:?}"
    );

    // The reserved allowlist must not rot: each entry must still be in the template.
    let declared_set: HashSet<&str> = declared.iter().map(String::as_str).collect();
    let stale: Vec<&str> = NOT_YET_WIRED
        .iter()
        .copied()
        .filter(|k| !declared_set.contains(k))
        .collect();
    assert!(
        stale.is_empty(),
        "NOT_YET_WIRED lists keys absent from the template (remove them): {stale:?}"
    );
}

/// Inserts the `HUNTSMAN_*` string literal whose opening `"` sits at
/// `open_quote`, if that is what the literal actually holds. Shared by both
/// detection forms in [`collect_key_env_consts`] so they extract identically.
fn push_huntsman_literal(
    line: &str,
    open_quote: usize,
    out: &mut std::collections::HashSet<String>,
) {
    let rest = &line[open_quote + 1..];
    if !rest.starts_with("HUNTSMAN_") {
        return;
    }
    if let Some(end) = rest.find('"') {
        out.insert(rest[..end].to_string());
    }
}

/// Collects every `HUNTSMAN_*` env var a module under `dir` genuinely READS, in
/// all three forms the codebase actually uses:
///
/// 1. the `const ..._ENV: &str = "HUNTSMAN_..."` naming convention (`const
///    KEY_ENV: &str = "HUNTSMAN_SHODAN_KEY"`, `const OTX_KEY_ENV: &str =
///    "HUNTSMAN_ALIENVAULT_KEY"`, …);
/// 2. an **inline** read that names the var at the call site —
///    `ctx.key_opt("HUNTSMAN_GITHUB_TOKEN")` / `ctx.key("HUNTSMAN_…")`; and
/// 3. the var name passed as a positional literal to the shared
///    `util::http::fetch_keyed_json` helper (`fetch_keyed_json(ctx, SRC, &url,
///    "HUNTSMAN_VIRUSTOTAL_KEY", "x-apikey")`), which reads the key itself
///    rather than making the caller do it — used as-is (not through a `_ENV`
///    const) by `virustotal`, `abuseipdb`, and `auspost`.
///
/// Form 2 was previously invisible here: the scan hard-required `const ` AND
/// `ENV` on the line, so a module reading its key inline was silently exempt
/// from the documentation guard below. That blind spot let a real, poolable,
/// `service_defs`-registered credential (`HUNTSMAN_GITHUB_TOKEN`, read by
/// `github_user`/`github_code_search`/`github_commits`) go missing from both
/// `KNOWN_KEYS` and `env_template.txt` — invisible to the Settings grid, to
/// `hse provision`, and to `hse doctor`'s acquisition ranking. Form 3 closed
/// the same class of blind spot for `virustotal`/`abuseipdb`'s keys once this
/// collector started being asked (by `env_template_keys_are_all_consumed`) to
/// prove consumption instead of accepting mere `service_defs()` registration.
///
/// Deliberately narrower than a plain textual search for the identifier: a
/// mention only counts here when it is bound to an `_ENV` const or passed
/// directly to a key read, which is the precise "a module genuinely reads
/// this env var" signal — the inverse of what `env_template_keys_are_all_consumed`
/// guards. Also deliberately excludes a bare `env::var("HUNTSMAN_...")` read
/// (see [`collect_raw_huntsman_env_reads`]): that form is how config knobs
/// bypass `ModuleContext` entirely, and this collector's own caller
/// (`key_gated_modules_are_documented_everywhere_an_operator_would_look`)
/// requires every var it finds to appear in `KNOWN_KEYS` — correct for a
/// pooled provider credential, wrong for a tuning knob like
/// `HUNTSMAN_SEARCH_PROXY` that was never meant to appear in the Settings-page
/// API-key grid.
fn collect_key_env_consts(dir: &Path, out: &mut std::collections::HashSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_key_env_consts(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let content = fs::read_to_string(&path).unwrap();
            for line in content.lines() {
                // 1. `const ..._ENV: &str = "HUNTSMAN_..."`.
                if line.contains("const ")
                    && line.contains("ENV")
                    && let Some(q) = line.find("\"HUNTSMAN_")
                {
                    push_huntsman_literal(line, q, out);
                }
                // 2. `…key_opt("HUNTSMAN_…")` / `…key("HUNTSMAN_…")`. `key(`
                //    cannot alias `key_opt(` (the char after `key` is `_`), and
                //    every index below lands on an ASCII pattern boundary, so
                //    the slicing is char-boundary safe.
                for pat in ["key_opt(", "key("] {
                    let mut from = 0;
                    while let Some(i) = line[from..].find(pat) {
                        let after = from + i + pat.len();
                        if line[after..].starts_with('"') {
                            push_huntsman_literal(line, after, out);
                        }
                        from = after;
                    }
                }
            }
            // 3. `fetch_keyed_json(ctx, SRC, &url, "HUNTSMAN_...", "header")` —
            //    sometimes `fetch_keyed_json::<SomeResponse>(...)` when the
            //    return type can't be inferred, so this matches the bare
            //    function name rather than requiring an immediately-following
            //    `(`. Scanned across the whole file rather than line-by-line
            //    since a real call commonly wraps its arguments across several
            //    lines; the search window after each call site is bounded so
            //    an unrelated later literal can't be mistaken for its argument.
            let mut from = 0;
            while let Some(i) = content[from..].find("fetch_keyed_json") {
                let call_start = from + i;
                let mut window_end = (call_start + 400).min(content.len());
                while !content.is_char_boundary(window_end) {
                    window_end -= 1;
                }
                if let Some(q) = content[call_start..window_end].find("\"HUNTSMAN_") {
                    push_huntsman_literal(&content[call_start..], q, out);
                }
                from = call_start + "fetch_keyed_json".len();
            }
        }
    }
}

/// Guards the FOUR independent places a key-gated module's env var must be
/// documented for an operator to ever discover it — `env_template.txt` (the
/// `hse provision` template), `util::keys::constants::KNOWN_KEYS` (drives the
/// Settings-page paste grid), `install.sh`'s own hand-maintained
/// `~/.huntsman.env` heredoc (what a fresh `curl | bash` install writes), and
/// the repo-root `.env.example` (the browsable provider catalogue `AUTONOMY.md`
/// and `OSINT_API_REFERENCE.md` both point operators at) — all stay in sync
/// with the modules that actually exist.
///
/// This is the inverse direction of `env_template_keys_are_all_consumed`
/// (documented ⇒ consumed) and closes the gap that let a real drift ship: a
/// `const ...ENV: &str = "HUNTSMAN_NIAMONX_KEY"` in a live, registered module
/// with NO test catching that `KNOWN_KEYS` (so the Settings UI could never
/// surface it) or `env_template.txt` never mentioned it — discovered via a
/// four-way audit of the actual embedded-vs-shipped provisioning templates
/// after `src/cli/provision/env_template.txt` turned out to be a silently
/// stale `include_str!` shadow copy of the real, tested `src/cli/env_template.txt`.
#[test]
fn key_gated_modules_are_documented_everywhere_an_operator_would_look() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut consumed = std::collections::HashSet::new();
    collect_key_env_consts(&root.join("src/modules"), &mut consumed);
    assert!(
        consumed.len() > 30,
        "sanity: expected 30+ KEY_ENV-style consts across src/modules, found {}",
        consumed.len()
    );

    // 1. env_template.txt (the file `hse provision` embeds — see the
    //    `include_str!` in src/cli/provision/mod.rs, which must point HERE).
    let template = fs::read_to_string(root.join("src/cli/env_template.txt")).unwrap();
    let template_keys: std::collections::HashSet<&str> = template
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("HUNTSMAN_"))
        .filter_map(|l| l.split('=').next())
        .map(str::trim)
        .collect();
    let missing_from_template: Vec<&String> = consumed
        .iter()
        .filter(|k| !template_keys.contains(k.as_str()))
        .collect();
    assert!(
        missing_from_template.is_empty(),
        "module(s) read a key env_template.txt never mentions (hse provision \
         can't offer it): {missing_from_template:?}"
    );

    // 2. util::keys::constants::KNOWN_KEYS (drives the Settings-page grid).
    let known: std::collections::HashSet<&str> = huntsman_search_engine::util::keys::KNOWN_KEYS
        .iter()
        .copied()
        .collect();
    let missing_from_known_keys: Vec<&String> = consumed
        .iter()
        .filter(|k| !known.contains(k.as_str()))
        .collect();
    assert!(
        missing_from_known_keys.is_empty(),
        "module(s) read a key KNOWN_KEYS omits (Settings UI can never surface \
         it): {missing_from_known_keys:?}"
    );

    // 3. install.sh must configure the fresh `~/.huntsman.env` through the ONE
    //    canonical source. It previously carried a second, hand-maintained copy
    //    of the key list in a `cat > "$KEYS_PATH" <<'TEMPLATE'` heredoc that
    //    could (and did) drift from env_template.txt; that duplicate was removed
    //    in favour of delegating to `hse provision --env-only --discover`, which
    //    embeds env_template.txt (proven complete in step 1). So completeness for
    //    a fresh `curl | bash` install now flows through that single source, and
    //    the guard here is that the delegation is present — not that a rival
    //    template exists to fall behind.
    let install_sh = fs::read_to_string(root.join("install.sh")).unwrap();
    assert!(
        !install_sh.contains("cat > \"$KEYS_PATH\" <<'TEMPLATE'"),
        "install.sh reintroduced a hand-maintained keys heredoc — that is a second \
         template that will drift from env_template.txt. Configure keys by \
         delegating to `hse provision` (the single canonical source) instead."
    );
    assert!(
        install_sh.contains("provision --env-only --discover"),
        "install.sh must configure ~/.huntsman.env by delegating to \
         `hse provision --env-only --discover` (the single canonical env-template \
         source), so a fresh install offers every key with autonomous discovery \
         and no drift-prone second list"
    );

    // 4. The repo-root `.env.example` — the browsable provider catalogue
    //    (signup links, free-tier notes, key formats) that `docs/AUTONOMY.md`
    //    and `docs/OSINT_API_REFERENCE.md` both send operators to. It was the
    //    one provisioning surface with NO guard at all, and had already drifted:
    //    `HUNTSMAN_ALIENVAULT_KEY` was consumed by `ip_reputation`, listed in
    //    `KNOWN_KEYS` AND in `env_template.txt`, yet missing here.
    //
    //    Deliberately FORWARD-ONLY (consumed ⇒ documented). The reverse
    //    direction is NOT asserted, because `.env.example` legitimately carries
    //    entries that are not module-read credentials: tuning knobs
    //    (`HUNTSMAN_DNS_RESOLVERS`, `HUNTSMAN_EMAIL_DOMAINS`,
    //    `HUNTSMAN_SEARCH_PROXY`, `HUNTSMAN_SEEKNOW_BASE`,
    //    `HUNTSMAN_SEEKNOW_SCAN_CAP`) plus reserved keys for not-yet-wired
    //    providers. Asserting documented ⇒ consumed would fail on every one of
    //    those and pressure a future contributor to DELETE real operator
    //    documentation just to stay green.
    let env_example = fs::read_to_string(root.join(".env.example")).unwrap();
    let example_keys: std::collections::HashSet<&str> = env_example
        .lines()
        .map(str::trim)
        // Entries are commented-out placeholders (`# HUNTSMAN_X=value`), so the
        // leading `#` is stripped before matching.
        .map(|l| l.trim_start_matches('#').trim())
        .filter(|l| l.starts_with("HUNTSMAN_"))
        // `split_once('=')` (not `split('=').next()`, which never fails) so an
        // `=` is REQUIRED: a bare `# HUNTSMAN_X` mention with no placeholder
        // would otherwise count as "documented" while giving the operator
        // nothing to fill in, letting a real drift pass the guard.
        .filter_map(|l| l.split_once('=').map(|(name, _)| name))
        .map(str::trim)
        .collect();
    let mut missing_from_example: Vec<&String> = consumed
        .iter()
        .filter(|k| !example_keys.contains(k.as_str()))
        .collect();
    // `consumed` is a HashSet, so sort for a stable, reproducible failure
    // message when more than one key is missing.
    missing_from_example.sort();
    assert!(
        missing_from_example.is_empty(),
        "module(s) read a key the repo-root .env.example never documents (an \
         operator browsing the provider catalogue can't discover it): \
         {missing_from_example:?}"
    );
}

#[test]
fn every_declared_module_is_registered() {
    // A `pub mod foo;` in src/modules/mod.rs that implements `Module` but is
    // never pushed into `registry()` compiles cleanly, is invisible to clippy
    // (unused pub item in a lib), and silently never runs — exactly how
    // `pwned_passwords` was dead at runtime. Assert every declared module mod
    // is instantiated somewhere in the registry body.
    let src = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/modules/mod.rs"))
        .expect("src/modules/mod.rs must exist");

    let declared: Vec<String> = src
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("pub mod ")
                .and_then(|r| r.strip_suffix(';'))
                .map(|n| n.trim().to_string())
        })
        .collect();

    // The `Arc::new(...)` instantiations live in the `MODULE_REGISTRY` static
    // (built once, then cloned by `registry()` on every call — see its doc
    // comment), so anchor on whichever of the two appears first in the file
    // rather than only `fn registry(`.
    let anchor = ["static MODULE_REGISTRY", "fn registry("]
        .iter()
        .filter_map(|marker| src.find(marker))
        .min()
        .unwrap_or(0);
    let body = &src[anchor..];

    let missing: Vec<&String> = declared
        .iter()
        .filter(|name| !body.contains(&format!("{name}::")))
        .collect();

    assert!(
        missing.is_empty(),
        "module mods declared in src/modules/mod.rs but never registered in \
         registry() (dead at runtime): {missing:?}"
    );
}

#[test]
fn all_target_kinds_lists_every_enum_variant() {
    // DRIFT GUARD. `ALL_TARGET_KINDS` is the SOLE source the dispatch-index
    // builder and the `consumes()` default-probe iterate, so a `TargetKind`
    // variant absent from it is DEAD at runtime — no seed of that kind ever
    // dispatches to any module. This is exactly how WiGLE's `Ssid` SSID-search
    // path was silently unreachable. The arm-less `match` below is a compile-time
    // tripwire: adding a new `TargetKind` variant fails to compile here until the
    // author handles it (and the comment tells them to add it to BOTH `EVERY` and
    // `ALL_TARGET_KINDS`); the runtime assertions then prove the array actually
    // contains every variant and carries no extra/duplicate.
    use huntsman_search_engine::core::dependency::ALL_TARGET_KINDS;
    use huntsman_search_engine::core::scan::TargetKind;

    const EVERY: &[TargetKind] = &[
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Phone,
        TargetKind::FullName,
        TargetKind::IpAddress,
        TargetKind::Domain,
        TargetKind::Url,
        TargetKind::Asn,
        TargetKind::Cidr,
        TargetKind::Coordinates,
        TargetKind::Address,
        TargetKind::Organisation,
        TargetKind::AbnAcn,
        TargetKind::MacAddress,
        TargetKind::ApiKey,
        TargetKind::CryptoAddress,
        TargetKind::DeviceId,
        TargetKind::Ssid,
        TargetKind::TrackingId,
    ];

    // Compile-time tripwire: NO `_` arm, so a new enum variant breaks this match
    // until it is wired in.
    for &k in EVERY {
        match k {
            TargetKind::Email
            | TargetKind::Username
            | TargetKind::Phone
            | TargetKind::FullName
            | TargetKind::IpAddress
            | TargetKind::Domain
            | TargetKind::Url
            | TargetKind::Asn
            | TargetKind::Cidr
            | TargetKind::Coordinates
            | TargetKind::Address
            | TargetKind::Organisation
            | TargetKind::AbnAcn
            | TargetKind::MacAddress
            | TargetKind::ApiKey
            | TargetKind::CryptoAddress
            | TargetKind::DeviceId
            | TargetKind::Ssid
            | TargetKind::TrackingId => {}
        }
    }

    for &k in EVERY {
        assert!(
            ALL_TARGET_KINDS.contains(&k),
            "{k:?} is absent from ALL_TARGET_KINDS — it would be DEAD at runtime \
             (no seed of that kind dispatches to any module)"
        );
    }
    assert_eq!(
        EVERY.len(),
        ALL_TARGET_KINDS.len(),
        "ALL_TARGET_KINDS carries an extra or duplicate TargetKind"
    );
}

#[test]
fn wigle_is_reachable_from_an_ssid_seed() {
    // End-to-end proof that the Ssid wiring is live: an `Ssid` target must
    // dispatch to `wigle` (its sole consumer). Guards the runtime path the
    // drift-guard above protects structurally.
    use huntsman_search_engine::core::dependency::ModuleGraph;
    use huntsman_search_engine::core::scan::TargetKind;
    let modules = huntsman_search_engine::modules::registry();
    let graph = ModuleGraph::build(&modules);
    let ssid_consumers: Vec<&str> = graph
        .modules_for(TargetKind::Ssid)
        .iter()
        .map(|&i| modules[i].name())
        .collect();
    assert!(
        ssid_consumers.contains(&"wigle"),
        "an Ssid seed must reach wigle; dispatchers for Ssid = {ssid_consumers:?}"
    );
}

/// Concatenated source of the correlator unit-test files used by the
/// meta-guard (`every_dispatched_correlation_rule_has_a_firing_test`).
///
/// `tests.rs` itself `include!`s fragments from a `tests/` subdirectory (split
/// purely for reliable transmission through this repo's push tooling — see
/// `tests.rs`'s own doc comment), so those fragments are read and concatenated
/// too; otherwise a rule whose sole firing test lives in a fragment would look
/// untested to this scanner even though it compiles into the same test binary.
fn correlator_tests_source() -> String {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/correlator");
    let mut out = fs::read_to_string(base.join("tests.rs")).unwrap_or_default();
    if let Ok(rd) = fs::read_dir(base.join("tests")) {
        let mut parts: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        parts.sort(); // deterministic concatenation order
        for p in parts {
            if p.extension().is_some_and(|e| e == "rs") {
                out.push('\n');
                out.push_str(&fs::read_to_string(&p).unwrap_or_default());
            }
        }
    }
    out.push('\n');
    out.push_str(&fs::read_to_string(base.join("rules/tests.rs")).unwrap_or_default());
    out
}

/// True iff `line` contains `len(), N` where N is a positive decimal integer.
fn has_nonzero_len_assert(line: &str) -> bool {
    let Some(pos) = line.find("len(), ") else {
        return false;
    };
    let after = line[pos + "len(), ".len()..].trim_start();
    let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<usize>().unwrap_or(0) > 0
}

/// Collects every `HUNTSMAN_*` env var a module reads via a RAW
/// `std::env::var(...)` call — i.e. bypassing the [`ModuleContext`] key
/// accessors. Line-based like [`collect_key_env_consts`]: `env::var(` matches
/// both `std::env::var(` and a `use std::env` shorthand, and never
/// `env::var_os(` (the char after `var` is `_`, not `(`). Only literal-argument
/// reads are seen — the one shape the two sanctioned reads actually use — which
/// is the same best-effort structural signal every scanner in this file relies
/// on.
///
/// Two callers, two different directory scopes: [`modules_never_read_credentials_via_raw_env`]
/// below passes `src/modules` (its "no module bypasses the accessor"
/// invariant only concerns modules); [`env_template_keys_are_all_consumed`]
/// passes all of `src/` (a config knob consumed outside `src/modules` still
/// needs to count as "this template key is genuinely read somewhere").
fn collect_raw_huntsman_env_reads(dir: &Path, out: &mut std::collections::HashSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_raw_huntsman_env_reads(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let content = fs::read_to_string(&path).unwrap();
            for line in content.lines() {
                let mut from = 0;
                while let Some(i) = line[from..].find("env::var(") {
                    let after = from + i + "env::var(".len();
                    if line[after..].starts_with('"') {
                        push_huntsman_literal(line, after, out);
                    }
                    from = after;
                }
            }
        }
    }
}

/// A module must never read a `HUNTSMAN_*` credential via a raw
/// `std::env::var(...)` call: that bypasses [`ModuleContext::key`] /
/// [`ModuleContext::key_opt`], which are the single chokepoint applying
/// `util::keys::resolve_key`'s "what counts as a configured credential"
/// filter (absent / blank / an unedited `insert_..._here` provisioning
/// placeholder all resolve to "unconfigured"). A credential read raw would
/// forward an unedited template placeholder to the provider verbatim — a
/// confused-deputy request against a stranger's account (the IL-2 class the
/// `key_opt` chokepoint exists to close). This is the source-structural half
/// of that guarantee: the `key_opt` unit tests prove the accessor filters;
/// this proves no module sidesteps the accessor.
///
/// The two sanctioned raw reads are NON-credential tuning knobs (no
/// `_KEY`/`_TOKEN`/`_SECRET` suffix), allow-listed with justification.
/// A credential MUST NOT be added here — route it through the accessors so the
/// filter applies. The allow-list is anti-rot-checked so a knob that stops
/// being read is removed rather than lingering as a phantom exemption.
#[test]
fn modules_never_read_credentials_via_raw_env() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Sanctioned raw `env::var("HUNTSMAN_…")` reads in src/modules — both are
    // non-credential tuning knobs deliberately read inline rather than threaded
    // through `ModuleContext`:
    //   * HUNTSMAN_SEARCH_PROXY  — abn_lookup's per-request proxy override.
    //   * HUNTSMAN_EMAIL_DOMAINS — name_intel's permutation domain list.
    const ALLOWED_RAW_ENV: &[&str] = &["HUNTSMAN_SEARCH_PROXY", "HUNTSMAN_EMAIL_DOMAINS"];

    let mut raw = std::collections::HashSet::new();
    collect_raw_huntsman_env_reads(&root.join("src/modules"), &mut raw);

    let allowed: std::collections::HashSet<&str> = ALLOWED_RAW_ENV.iter().copied().collect();
    let mut offenders: Vec<&str> = raw
        .iter()
        .map(String::as_str)
        .filter(|v| !allowed.contains(v))
        .collect();
    offenders.sort_unstable();
    assert!(
        offenders.is_empty(),
        "module(s) read a HUNTSMAN_* env var via raw std::env::var, bypassing the \
         ModuleContext key/key_opt accessors (and thus util::keys::resolve_key's \
         placeholder/blank filter). Route it through ctx.key/ctx.key_opt; or, ONLY \
         for a genuinely non-credential tuning knob, add it to ALLOWED_RAW_ENV with \
         justification: {offenders:?}"
    );

    // Anti-rot: every allow-listed knob must still actually be read, else it is
    // a stale exemption to delete (mirrors NOT_YET_WIRED's own staleness check).
    let stale: Vec<&str> = ALLOWED_RAW_ENV
        .iter()
        .copied()
        .filter(|k| !raw.contains(*k))
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWED_RAW_ENV lists env vars no module reads any more (remove them): {stale:?}"
    );
}
