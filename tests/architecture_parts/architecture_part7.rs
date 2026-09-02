/// Parse a file-module declaration `mod NAME;` of any visibility, returning
/// `NAME`. Inline `mod NAME { … }` blocks (no trailing `;`) and every other line
/// yield `None`.
fn parse_file_mod_decl(line: &str) -> Option<String> {
    let mut l = line.trim();
    if l.starts_with("//") {
        return None;
    }
    // Strip a leading visibility: `pub`, optionally followed by `(…)`.
    if let Some(rest) = l.strip_prefix("pub") {
        l = rest.trim_start();
        if let Some(after) = l.strip_prefix('(') {
            l = after.split_once(')').map_or("", |(_, r)| r).trim_start();
        }
    }
    // Take the identifier up to the terminating `;`. Requiring a `;` (rather
    // than end-of-line) tolerates a trailing `// comment` — `mod archive; // …`
    // is common here — while still rejecting an inline `mod X { … }` block,
    // which has no `;`.
    let after_mod = l.strip_prefix("mod ")?.trim_start();
    let name = after_mod[..after_mod.find(';')?].trim();
    if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Some(name.to_string())
    } else {
        None
    }
}

/// 100% file relevance: every `.rs` file under `src/` must be wired into the
/// crate — declared `mod <name>;` (a directory through its `mod.rs`, a leaf
/// through `<name>.rs`) or pulled in via `include!("…")`.
///
/// Cargo compiles only files reachable from `lib.rs`/`main.rs` through the module
/// tree and SILENTLY ignores an orphan `.rs`: no compile error, no clippy
/// warning. A stranded file — a half-finished module, a stale copy, an un-wired
/// new file — therefore reads as live code while being dead weight. This makes
/// such a file a test failure, so what exists on disk is always what compiles.
///
/// (The repo uses no `#[path = "…"]` attributes; a file reached only that way
/// would surface here as a false orphan, correctly flagging that this check must
/// then learn about `#[path]`.)
#[test]
fn every_src_file_is_wired_into_the_module_tree() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);

    // Declared and included targets are tracked by resolved, canonicalized path
    // (not by bare module name): a `mod name;` in one directory must not make an
    // unrelated `name.rs`/`name/mod.rs` elsewhere in the tree read as reachable.
    let mut declared: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();
    let mut included: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap();
        let dir = f.parent().unwrap();
        let fname = f.file_name().unwrap().to_string_lossy();
        // Rust's own resolution rule: a `mod.rs`/`lib.rs`/`main.rs` declares its
        // children as siblings in its own directory, but a *leaf* `name.rs`
        // declares its children under a `name/` subdirectory of its own dir —
        // e.g. `hse-core/src/coords.rs`'s `mod tests;` resolves to
        // `hse-core/src/coords/tests.rs`, not `hse-core/src/tests.rs`.
        let mod_base = if matches!(&*fname, "mod.rs" | "lib.rs" | "main.rs") {
            dir.to_path_buf()
        } else {
            dir.join(f.file_stem().unwrap())
        };
        for line in text.lines() {
            if let Some(name) = parse_file_mod_decl(line) {
                for candidate in [
                    mod_base.join(format!("{name}.rs")),
                    mod_base.join(&name).join("mod.rs"),
                ] {
                    if let Ok(p) = candidate.canonicalize() {
                        declared.insert(p);
                    }
                }
            }
            if let Some((_, after)) = line.trim().split_once("include!(\"")
                && let Some((rel, _)) = after.split_once('"')
                && let Ok(p) = dir.join(rel).canonicalize()
            {
                included.insert(p);
            }
        }
    }

    let mut orphans = Vec::new();
    for f in &files {
        let fname = f.file_name().unwrap().to_string_lossy().into_owned();
        // Crate roots are reachable by definition, not via a `mod` declaration.
        if fname == "main.rs" || fname == "lib.rs" {
            continue;
        }
        let canonical = f.canonicalize().ok();
        let reachable = canonical.as_ref().is_some_and(|c| declared.contains(c));
        let via_include = canonical.as_ref().is_some_and(|c| included.contains(c));
        if !reachable && !via_include {
            orphans.push(f.strip_prefix(&src).unwrap_or(f).display().to_string());
        }
    }
    orphans.sort();

    assert!(
        orphans.is_empty(),
        "orphan src file(s): present on disk but not `mod`-linked or `include!`d, \
         so cargo never compiles them — 100% file relevance is broken:\n  {}",
        orphans.join("\n  ")
    );
}

/// Every `docs/*.md` path cited from Rust source must actually exist.
///
/// A comment pointing at a document that was never written — or was renamed and
/// left behind — is a fabricated source: it presents a claim as having external
/// backing that cannot be read. Worse, an assertion message telling a maintainer
/// to "update `docs/<name>.md`" sends them after a file that isn't there. (That
/// placeholder is deliberately not a resolvable path — this guard scans its own
/// source too, and caught the literal example the first time it ran.) Both had
/// accumulated here: 24 citations across 9 non-existent documents, including one
/// failure message instructing the reader to reconcile a missing audit doc.
///
/// The repository's own doctrine is that the running software is the source of
/// truth for reference material (`hse --help`, `hse modules`), and that
/// invariants are enforced by the guards in this file rather than by prose. This
/// test makes that mechanical: cite a document, and it has to exist.
///
/// Scoped to `.rs` files deliberately: a planning document may legitimately
/// list documents it intends to create (marked e.g. `— NEW`), which is a
/// forward reference, not a broken citation — only `.rs` sources make a claim
/// that the cited doc already backs them.
#[test]
fn every_docs_path_cited_from_rust_source_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    // EVERY Rust source tree in the repository, not just the crate's own two:
    // `benches/` and `build.rs` are compiled by `cargo check --all-targets`, and
    // the fuzz targets are a separate crate that is still this repository's
    // code. Scanning only `src`/`tests` would let a citation rot in any of them
    // while the guard reported all-clear.
    for dir in ["src", "tests", "benches", "fuzz/fuzz_targets"] {
        let path = root.join(dir);
        if path.is_dir() {
            collect_rs_files(&path, &mut files);
        }
    }
    let build_rs = root.join("build.rs");
    if build_rs.is_file() {
        files.push(build_rs);
    }
    assert!(
        files.len() > 100,
        "expected to scan the whole Rust source tree; found only {} file(s) — \
         the walk is broken, and a guard that scans nothing passes vacuously",
        files.len()
    );

    let mut dangling: Vec<String> = Vec::new();
    for file in &files {
        // A file that cannot be read is a failure, not a skip. Silently
        // continuing here would let an unreadable source hide its citations and
        // still report a pass.
        let text = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("cannot read {} for citation scan: {e}", file.display()));
        for (lineno, line) in text.lines().enumerate() {
            let mut rest = line;
            while let Some(at) = rest.find("docs/") {
                // A `docs/…` sitting inside an http(s) URL belongs to someone
                // else's repository (e.g. npm's `REGISTRY-API.md`) and must not
                // be resolved against this checkout. Quotes, backticks and
                // brackets are token boundaries too — a URL written
                // `` `https://…/docs/X.md` `` or `"https://…/docs/X.md"` would
                // otherwise be misread as a local citation and fail the build.
                let preceding = &rest[..at];
                let in_url = preceding
                    .rsplit(|c: char| {
                        c.is_whitespace() || matches!(c, '(' | '<' | '`' | '"' | '\'' | '[')
                    })
                    .next()
                    .is_some_and(|tok| tok.starts_with("http"));

                let tail = &rest[at..];
                let end = tail
                    .find(|c: char| {
                        !(c.is_ascii_alphanumeric() || c == '/' || c == '.' || c == '_' || c == '-')
                    })
                    .unwrap_or(tail.len());
                let cited = &tail[..end];

                if !in_url && cited.ends_with(".md") && !root.join(cited).exists() {
                    dangling.push(format!(
                        "{}:{} cites {cited}",
                        file.strip_prefix(root).unwrap_or(file).display(),
                        lineno + 1,
                    ));
                }
                rest = &tail[end.max(1)..];
            }
        }
    }

    assert!(
        dangling.is_empty(),
        "Rust source cites {} document(s) that do not exist — a citation with no \
         readable source. Point at the real enforcement site (a guard in \
         tests/architecture.rs, `hse --help`, `hse modules`) or drop the \
         reference; do NOT author a document to satisfy the citation:\n  {}",
        dangling.len(),
        dangling.join("\n  ")
    );
}

/// Every `f64` clap argument must declare a `value_parser`.
///
/// `f64::from_str` accepts `nan` and `inf`, and clap's stock `f64` parser takes
/// them verbatim. A NaN threshold makes every `>=`/`<` comparison against it
/// false, so a filter built on one silently inverts or disables itself — the
/// silent-under-reporting failure this crate treats as its cardinal sin. An
/// out-of-range finite value (`--min-confidence 5.0`) is just as bad in the
/// other direction: it is accepted, unsatisfiable, and reported as success.
///
/// This shipped once already. `hse ingest --min-confidence nan` exited 0 having
/// emitted an empty deliverable, and the fix added a `value_parser` to that ONE
/// flag while seven others kept clap's stock parser — `scan`/`live`
/// `--min-confidence`, `--min-expand-confidence` and `--min-marginal-yield`, and
/// `keys prune --min-success-rate`. Fixing one instance of a class and leaving
/// its siblings is what this guard exists to prevent.
///
/// The library layer coerces non-finite values defensively
/// (`ScanOptions::effective_*`), but silently: the operator's flag is discarded
/// with no message. Validation belongs at the argument boundary, where it can
/// still be a usage error before any work is done.
#[test]
fn every_f64_cli_argument_declares_a_value_parser() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs_files(&root.join("src/cli"), &mut files);
    assert!(
        !files.is_empty(),
        "no CLI sources found — the walk is broken and this guard would pass vacuously"
    );

    let mut unguarded: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for file in &files {
        let text = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("cannot read {} for f64-arg scan: {e}", file.display()));
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // A clap field declaration: `name: f64,` or `name: Option<f64>,`.
            if !(t.ends_with(": f64,") || t.ends_with(": Option<f64>,")) {
                continue;
            }
            // Walk back over the doc comments to the nearest `#[arg(...)]`. A
            // field with no `#[arg]` at all is a plain struct field, not a CLI
            // argument, and is none of this guard's business.
            let mut attr: Option<String> = None;
            for back in (0..i).rev() {
                let p = lines[back].trim();
                if p.starts_with("#[arg(") {
                    // The attribute may wrap across lines; join until the field.
                    attr = Some(lines[back..i].join(" "));
                    break;
                }
                if !(p.starts_with("///")
                    || p.starts_with("//")
                    || p.starts_with('#')
                    || p.is_empty())
                {
                    break;
                }
            }
            let Some(attr) = attr else { continue };
            checked += 1;
            if !attr.contains("value_parser") {
                unguarded.push(format!(
                    "{}:{} {}",
                    file.strip_prefix(root).unwrap_or(file).display(),
                    i + 1,
                    t
                ));
            }
        }
    }

    assert!(
        checked >= 8,
        "expected to find the known f64 CLI arguments; found only {checked} — the \
         scan is broken and this guard would pass vacuously"
    );
    assert!(
        unguarded.is_empty(),
        "{} f64 CLI argument(s) use clap's stock parser, which accepts `nan` and \
         `inf` and enforces no range. Add `value_parser = confidence_floor` (a \
         0.0-1.0 probability) or `value_parser = non_negative_rate` (a \
         non-negative rate):\n  {}",
        unguarded.len(),
        unguarded.join("\n  ")
    );
}

/// A non-2xx response must never be folded into a module's empty result.
///
/// `if !resp.status().is_success() { return Ok(empty) }` reports a 403 scraper block,
/// a 429 throttle and a 5xx outage as the same answer as a genuine miss. For a
/// registry lookup that empty result is not "nothing to report" — it is a negative
/// claim about a named subject ("not a registered practitioner", "holds no licence")
/// that an analyst will act on. `util::http::ok_or_absent` is the fail-closed form:
/// it takes the statuses that genuinely mean absence for that endpoint and turns
/// every other non-2xx into a typed `Err` the operator can see.
///
/// This guard exists because the raw pattern was independently written in eleven
/// modules before it was caught.
#[test]
fn modules_do_not_collapse_a_non_2xx_into_an_empty_result() {
    // `exif_geo` fetches an arbitrary, scraper-discovered image URL that almost
    // certainly serves no EXIF. That resembles the speculative-probe carve-out
    // `util::http::fetch_json_probe` documents, where a refusal and a miss really are
    // the same negative — but unlike the probe helpers it makes no such claim in a
    // doc comment. Left as-is pending a maintainer decision rather than changed on a
    // guess; listed here so the exemption is visible instead of silently unscanned.
    //
    // `github_commits` degrades a non-2xx GitHub *search* to an empty result by
    // an explicit, reasoned decision recorded at the call site ("best-effort and
    // free: a 403/429 means rate-limited, not a scan error"), and it still feeds
    // the status to the key pool via `note_keyed_error` so a dead token is never
    // silent. Whether that carve-out should also cover 5xx is a maintainer call,
    // not an unambiguous defect — listed so the exemption is visible instead of
    // being hidden by a matcher that simply could not see it.
    const EXEMPT: &[&str] = &["exif_geo", "github_commits"];

    let mut violations = Vec::new();
    let mut scanned = 0usize;
    let mut stack = vec![Path::new("src/modules").to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs")
                || path.file_name().is_some_and(|n| n == "tests.rs")
                || EXEMPT.iter().any(|m| path.to_string_lossy().contains(m))
            {
                continue;
            }
            let raw = fs::read_to_string(&path).unwrap();
            let scanned_src = production_source(&raw);
            let lines: Vec<&str> = scanned_src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if !(trimmed.starts_with("if !") && trimmed.contains("status().is_success()")) {
                    continue;
                }
                scanned += 1;
                // The collapse is the `return Ok(..)` anywhere in the guarded
                // block; a `return Err(..)` or a propagating `?` is correct.
                //
                // Scan the WHOLE block by brace depth rather than a fixed
                // two-line window. The window is why this lint could not see
                // `reddit_user`, whose guard logged the status across four lines
                // before folding a 403 into `Ok(None)` on the fifth — the exact
                // defect this test exists to catch, sitting in-tree and green.
                // A bounded walk costs nothing and cannot be defeated by an
                // intervening comment or log line.
                let mut depth = 0i32;
                let mut body = String::new();
                for line in &lines[i..lines.len().min(i + 40)] {
                    body.push_str(line);
                    depth += line.matches('{').count() as i32;
                    depth -= line.matches('}').count() as i32;
                    if depth <= 0 && !body.is_empty() {
                        break;
                    }
                }
                if body.contains("return Ok(") {
                    violations.push(format!("{}:{}", path.display(), i + 1));
                }
            }
        }
    }

    assert!(
        scanned >= 20,
        "expected to scan the known `is_success()` guards; found only {scanned} — the \
         scan is broken and this test would pass vacuously"
    );
    assert!(
        violations.is_empty(),
        "{} module(s) fold a non-2xx response into an empty result, so a refusal is \
         reported as a negative finding about the subject. Use \
         `util::http::ok_or_absent(SRC, resp, &[<codes that mean absence>])`:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

// ── Provider capability + economics descriptor (REQ-PROVIDER-001/002) ──────
//
// `derive_default_provider_descriptor`'s pure derivation logic and the
// `unknown_cost_paid_provider_blocked` gate have their own unit coverage in
// `src/core/module/provider_tests.rs` against a local stub module — `core`
// must stay module-agnostic (`core_does_not_import_modules`, elsewhere in
// this file), so the REGISTRY-WIDE completeness/consistency checks below
// (which need the real 188-module `crate::modules::registry()`) live here
// instead, as an integration test outside `src/core/`.

#[test]
fn every_registered_module_has_an_internally_consistent_provider_descriptor() {
    use huntsman_search_engine::core::module::{AccessClass, CachePolicy, CostModel, EscalationBand};

    let mods = huntsman_search_engine::modules::registry();
    assert!(mods.len() > 100, "sanity: registry should hold ~188 modules");
    for m in &mods {
        let d = m.provider_descriptor();
        assert_eq!(d.module_id, m.name());
        assert_eq!(d.provider_id, m.name());
        assert_eq!(
            d.supported_seed_types,
            m.consumes(),
            "{}: supported_seed_types must equal consumes()",
            d.module_id
        );

        // access_class <-> requires_key must agree in both directions.
        match d.access_class {
            AccessClass::Keyless => assert!(
                !d.requires_key,
                "{}: Keyless access_class must not require a key",
                d.module_id
            ),
            AccessClass::FreeAccount
            | AccessClass::FreeQuota
            | AccessClass::Paid
            | AccessClass::Enterprise => assert!(
                d.requires_key,
                "{}: {:?} access_class must require a key",
                d.module_id, d.access_class
            ),
        }

        // A Free cost model can never carry a per-request price — there is
        // nothing to price.
        if d.cost_model == CostModel::Free {
            assert!(
                d.cost_per_request.is_none(),
                "{}: Free cost_model must not carry a cost_per_request",
                d.module_id
            );
            assert_eq!(d.access_class, AccessClass::Keyless);
        }

        // L0Local is reserved for genuinely passive (no-network) modules.
        if d.escalation_band == EscalationBand::L0Local {
            assert!(
                m.is_passive(),
                "{}: L0Local escalation band must only apply to a passive module",
                d.module_id
            );
        }
        // The inverse also holds: every passive module is L0Local (the
        // derivation checks `is_passive` before anything else).
        if m.is_passive() {
            assert_eq!(
                d.escalation_band,
                EscalationBand::L0Local,
                "{}: a passive module's escalation band must be L0Local",
                d.module_id
            );
        }

        // Cross-correlation-gated modules must land in the specialist band.
        if m.is_high_value_only() || m.requires_geo_corroboration() {
            assert_eq!(
                d.escalation_band,
                EscalationBand::L4Specialist,
                "{}: a cross-correlation-gated module must be L4Specialist",
                d.module_id
            );
        }

        // cache_policy must mirror cache_ttl_secs() exactly.
        match d.cache_policy {
            CachePolicy::Disabled => assert_eq!(m.cache_ttl_secs(), 0, "{}", d.module_id),
            CachePolicy::TtlSeconds(secs) => {
                assert_eq!(secs, m.cache_ttl_secs(), "{}", d.module_id);
            }
        }

        // The four [0,1] priors must actually be in range.
        for (name, v) in [
            ("provenance_quality_prior", d.provenance_quality_prior),
            ("uniqueness_prior", d.uniqueness_prior),
            ("reliability_prior", d.reliability_prior),
            ("optionality_prior", d.optionality_prior),
        ] {
            assert!(
                (0.0..=1.0).contains(&v),
                "{}: {name} must be in [0,1], got {v}",
                d.module_id
            );
        }
    }
}

#[test]
fn the_six_overridden_providers_have_their_expected_provider_descriptors() {
    use huntsman_search_engine::core::module::{AccessClass, CostModel, EscalationBand};

    let mods = huntsman_search_engine::modules::registry();
    let get = |name: &str| {
        mods.iter()
            .find(|m| m.name() == name)
            .unwrap_or_else(|| panic!("module {name} not in registry"))
            .provider_descriptor()
    };

    let oathnet = get("oathnet_pro");
    assert_eq!(oathnet.escalation_band, EscalationBand::L4Specialist);
    assert_eq!(oathnet.cost_model, CostModel::Unknown);
    assert_eq!(oathnet.quota_unit, Some("lookup"));

    let wigle = get("wigle");
    assert_eq!(wigle.access_class, AccessClass::FreeQuota);
    assert_eq!(wigle.escalation_band, EscalationBand::L4Specialist);
    assert_eq!(wigle.quota_unit, Some("query"));

    let see_know = get("see_know");
    assert_eq!(see_know.access_class, AccessClass::Enterprise);
    assert_eq!(see_know.escalation_band, EscalationBand::L5Enterprise);
    assert_eq!(see_know.cost_model, CostModel::Estimated);
    assert_eq!(see_know.quota_unit, Some("credit"));

    let osintcat = get("osintcat");
    assert_eq!(osintcat.access_class, AccessClass::Paid);
    assert_eq!(osintcat.cost_model, CostModel::Exact);

    // The two evidence-based quality-prior overrides — `0.5` is the neutral
    // default every un-overridden module's `provenance_quality_prior` carries.
    const NEUTRAL_PRIOR: f64 = 0.5;
    let hudsonrock = get("hudsonrock");
    assert!(hudsonrock.provenance_quality_prior > NEUTRAL_PRIOR);
    let comb = get("comb_search");
    assert!(comb.provenance_quality_prior < NEUTRAL_PRIOR);
}
