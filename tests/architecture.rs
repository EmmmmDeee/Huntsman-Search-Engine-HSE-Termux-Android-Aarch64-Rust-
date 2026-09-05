//! Architecture invariant tests — compile-time and runtime checks that
//! the module boundaries and contracts hold.

use std::fs;
use std::path::Path;

fn scan_for_violations(dir: &Path, patterns: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    scan_dir(dir, patterns, &mut violations);
    violations
}

fn scan_dir(dir: &Path, patterns: &[&str], violations: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, patterns, violations);
        } else if path.file_name().is_some_and(|n| n == "tests.rs")
            // A `tests/` directory component catches the same test code when
            // `tests.rs` splits its content into `tests/partNN.rs` fragments
            // via `include!` (done purely to keep each file small enough for
            // reliable transmission through this repo's push tooling) — those
            // fragments are entirely test code too, just as a file literally
            // named `tests.rs` is.
            || path.components().any(|c| c.as_os_str() == "tests")
        {
            // A dedicated `tests.rs` submodule file is entirely test code — it's
            // declared `#[cfg(test)] mod tests;` in its parent, so the gating
            // `#[cfg(test)]` marker isn't inside the file for the line-scanner to
            // see. Test code is allowed to reach into `util`, so skip it whole,
            // exactly as the inline-`#[cfg(test)]`-module case already is.
            continue;
        } else if path.extension().is_some_and(|e| e == "rs") {
            let raw = fs::read_to_string(&path).unwrap();
            // This used to latch `in_test = true` on the first `#[cfg(test)]`
            // and never reset, so everything below it went unscanned. With
            // `#[cfg(test)] mod tests;` declared at the top of most files here,
            // that hid 43,478 of the 205,361 lines in `src/` — 21% — from the
            // layering invariants. `production_source` drops the attributed
            // ITEM instead, and blanks comment and literal content so a path
            // merely named in prose is not read as an import. Line numbers
            // survive the transform, so the report still points at real source.
            let scanned = production_source(&raw);
            let raw_lines: Vec<&str> = raw.lines().collect();
            for (i, line) in scanned.lines().enumerate() {
                let trimmed = line.trim();
                if patterns.iter().any(|p| trimmed.contains(p)) {
                    // Show the original line — the scanned copy has its literals
                    // blanked and would print a confusing half-empty statement.
                    let shown = raw_lines.get(i).map_or(trimmed, |l| l.trim());
                    violations.push(format!("{}:{}: {}", path.display(), i + 1, shown));
                }
            }
        }
    }
}

#[test]
fn core_does_not_import_storage_directly() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let v = scan_for_violations(&dir, &["storage::Store", "crate::storage"]);
    assert!(
        v.is_empty(),
        "core/ must not import storage/ directly — use StoragePort.\nViolations:\n{}",
        v.join("\n")
    );
}

/// The LLM integration stays removed.
///
/// `core_does_not_import_ai` used to guard the LAYERING around `src/ai` — that
/// core never imported the opt-in Ollama surface. With that surface deleted the
/// old test could only pass vacuously, so it is replaced by the guard that
/// actually has teeth now: nothing in the tree reaches an inference engine at
/// all.
///
/// The integration was removed on the maintainer's instruction after it broke
/// real installs (its `df -Pm` storage probe killed the whole installer under
/// `set -euo pipefail`). Paired with
/// `runtime_carries_no_ai_ml_inference_dependency`, which guards the dependency
/// graph: this guards the source tree, the binary list and the CLI surface.
#[test]
fn no_llm_inference_integration_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !root.join("src/ai").exists(),
        "src/ai (the Ollama client) was removed — reintroducing a runtime LLM \
         integration needs a deliberate decision, not a quiet re-add"
    );
    assert!(
        !root.join("src/bin/hse_ai_daemon").exists(),
        "the hse-ai-daemon binary was removed"
    );
    assert!(
        !root.join("scripts/finetune").exists(),
        "scripts/finetune (the model-training tooling for the removed analysis \
         prompt) was removed with the integration it trained for"
    );
    let cargo = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml");
    assert!(
        !cargo.contains("hse-ai-daemon"),
        "Cargo.toml must not declare the removed hse-ai-daemon binary"
    );
    // The operator-facing surface, too: no `hse analyze`, no feature toggle, and
    // no installer bootstrap that pulls a model onto the device.
    let cli = fs::read_to_string(root.join("src/cli/command.rs")).expect("command.rs");
    assert!(
        !cli.contains("Analyze {"),
        "the `hse analyze` subcommand was removed with its backend"
    );
    let install = fs::read_to_string(root.join("install.sh")).expect("install.sh");
    for needle in ["ollama", "Ollama", "hse-ai", "HSE_WITH_AI"] {
        assert!(
            !install.contains(needle),
            "install.sh must not reference `{needle}` — the Ollama bootstrap is gone"
        );
    }
    // The whole live tree, not just the four surfaces above. The first version
    // of this lock checked exactly those and passed while `scripts/finetune/`
    // (the model-training tooling, importing the deleted analysis module by
    // path), a default-only `scans_pending_analysis` on `StoragePort`, and
    // comments in CI and two tests still described the client as present.
    // History may name the integration — the ledger, the changelog, dated
    // audit records — but live code, tooling, CI and operator docs may not.
    let leftovers = removed_integration_references(root);
    assert!(
        leftovers.is_empty(),
        "live references to the removed LLM integration (a re-add needs a \
         deliberate decision; a leftover needs deleting):\n{}",
        leftovers.join("\n")
    );
}

/// Identifiers a re-add of the removed integration would bring back, or that
/// its tooling used. `scan_analysis` is matched as a whole identifier below so
/// the unrelated SPA test `..._per_scan_analysis_endpoints` does not trip it.
const REMOVED_INTEGRATION_IDENTIFIERS: &[&str] = &[
    "src/ai/",
    "src/ai`",
    "hse_ai_daemon",
    "hse-ai-daemon",
    "ai_daemon",
    "scans_pending_analysis",
    "hse analyze",
    "OSINT_MODEL_FINE_TUNING",
    "scripts/finetune",
    "finetune",
    "Modelfile",
];

/// Roots an operator, a contributor, CI or the installer actually reads.
/// `run/`, `CHANGELOG.md` and the dated records under `docs/` are history
/// and deliberately outside the scan.
const LIVE_ROOTS: &[&str] = &[
    "src",
    "tests",
    "scripts",
    ".github",
    "docs",
    "install.sh",
    "Cargo.toml",
    "README.md",
];

fn removed_integration_references(root: &Path) -> Vec<String> {
    let mut hits = Vec::new();
    for r in LIVE_ROOTS {
        walk_live_text(&root.join(r), root, &mut hits);
    }
    hits.sort();
    hits
}

fn is_historical_record(rel: &str) -> bool {
    rel == "docs/REQUIREMENTS_LEDGER.md" || rel.starts_with("docs/audit/") || rel.contains("_2026-")
}

fn walk_live_text(path: &Path, root: &Path, hits: &mut Vec<String>) {
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            walk_live_text(&entry.unwrap().path(), root, hits);
        }
        return;
    }
    let rel = path
        .strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    // This file names the identifiers in order to forbid them.
    if rel == "tests/architecture.rs" || is_historical_record(&rel) {
        return;
    }
    // A file NAMED for the integration is a re-add whatever it contains —
    // falsification showed a re-created `scripts/finetune/` with clean
    // contents slipping past a contents-only scan.
    if REMOVED_INTEGRATION_IDENTIFIERS
        .iter()
        .any(|n| rel.contains(n))
    {
        hits.push(format!("{rel}: path names the removed integration"));
        return;
    }
    // Non-UTF-8 (binary) files cannot carry a source reference.
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    // The crate-name denylist in `runtime_carries_no_ai_ml_inference_dependency`
    // legitimately lists `ollama` in order to forbid it as a dependency.
    let is_crate_denylist = rel == "tests/architecture_parts/architecture_part4.rs";
    for (i, line) in text.lines().enumerate() {
        let ident = REMOVED_INTEGRATION_IDENTIFIERS
            .iter()
            .any(|n| line.contains(n))
            || contains_identifier(line, "scan_analysis");
        let ollama = !is_crate_denylist && line.to_ascii_lowercase().contains("ollama");
        if ident || ollama {
            hits.push(format!("{rel}:{}: {}", i + 1, line.trim()));
        }
    }
}

/// `ident` present as a whole identifier: not preceded or followed by an
/// identifier character.
fn contains_identifier(line: &str, ident: &str) -> bool {
    let bytes = line.as_bytes();
    let is_ident_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut from = 0;
    while let Some(pos) = line[from..].find(ident) {
        let start = from + pos;
        let end = start + ident.len();
        let before_ok = start == 0 || !is_ident_char(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident_char(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

#[test]
fn api_does_not_import_storage_directly() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api");
    let v = scan_for_violations(&dir, &["crate::storage", "storage::store"]);
    assert!(
        v.is_empty(),
        "api/ must not import storage/ directly — use StoragePort.\nViolations:\n{}",
        v.join("\n")
    );
}

#[test]
fn api_does_not_import_cli() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api");
    let v = scan_for_violations(&dir, &["crate::cli", "use crate::cli"]);
    assert!(
        v.is_empty(),
        "api/ must not import the CLI presentation layer; move shared use cases to app/.\n\
         Violations:\n{}",
        v.join("\n")
    );
}

#[test]
fn app_does_not_import_cli() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/app");
    let v = scan_for_violations(&dir, &["crate::cli", "use crate::cli"]);
    assert!(
        v.is_empty(),
        "app/ owns shared use cases and must not depend on CLI presentation.\nViolations:\n{}",
        v.join("\n")
    );
}

#[test]
fn app_does_not_import_api() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/app");
    let v = scan_for_violations(&dir, &["crate::api", "use crate::api"]);
    assert!(
        v.is_empty(),
        "app/ owns shared use cases and must not depend on the API presentation layer — \
         move shared rendering/business logic into app/ and have api/ call into it.\nViolations:\n{}",
        v.join("\n")
    );
}

#[test]
fn application_layer_owns_runtime_composition() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let runtime = fs::read_to_string(root.join("src/app/runtime.rs")).unwrap();
    for required in [
        "Store::open(",
        // The composition constructor. It gained the host parameter when
        // `core` stopped reaching into `util` directly; app is the one layer
        // permitted to name both sides, which is why the wiring lives here.
        "ScanEngine::with_runtime_and_host(",
        "registry()",
        "module_runtime()",
        // Pin the REAL host too. Without this the engine would silently fall
        // back to `NoopEngineHost` — no egress pool refresh, no module-health
        // quarantine — and every test would still pass.
        "UtilEngineHost",
    ] {
        assert!(
            runtime.contains(required),
            "src/app/runtime.rs must own shared runtime composition token {required:?}"
        );
    }

    for layer in ["src/cli", "src/api"] {
        let v = scan_for_violations(
            &root.join(layer),
            &[
                "fn build_runtime(",
                "ScanEngine::new(",
                "ScanEngine::with_module_runtime(",
                "ScanEngine::with_runtime_and_host(",
                "Store::open(",
                "crate::storage",
            ],
        );
        assert!(
            v.is_empty(),
            "{layer} must consume app/ use cases rather than construct Store or ScanEngine.\n\
             Violations:\n{}",
            v.join("\n")
        );
    }
}

#[test]
fn modules_do_not_import_engine_or_storage() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/modules");
    let v = scan_for_violations(&dir, &["crate::core::engine", "crate::storage"]);
    assert!(
        v.is_empty(),
        "modules/ must not import engine/ or storage/.\nViolations:\n{}",
        v.join("\n")
    );
}

#[test]
fn util_does_not_import_upper_layers() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/util");
    let v = scan_for_violations(
        &dir,
        &[
            "crate::api",
            "crate::cli",
            "crate::modules",
            "crate::selftest",
            "crate::storage",
        ],
    );
    assert!(
        v.is_empty(),
        "util/ must not import upper application layers.\nViolations:\n{}",
        v.join("\n")
    );
}

#[test]
fn core_does_not_import_util_directly() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let v = scan_for_violations(&dir, &["crate::util"]);
    let allowed: Vec<String> = v
        .into_iter()
        .filter(|line| {
            !line.contains("util::key_pool")
                && !line.contains("util::key_roi")
                && !line.contains("util::geohash")
                // Pure, offline computational geometry (convex hull, geometric
                // median, …) — the geo correlation rules' location estimators.
                // Same justification as `util::geohash`: no I/O, no deps.
                && !line.contains("util::geometry")
                // Pure, offline CIDR containment (overflow-safe bitmask maths on
                // std `Ipv4Addr`/`Ipv6Addr`; no I/O, no deps) — same leaf
                // category as `util::geometry`. AU-112 uses it to test whether a
                // discovered IP falls inside a discovered announced network block.
                // Scoped to the two CIDR types actually used (confirmed: `core`
                // imports nothing else from `util::spf` on either branch) rather
                // than the whole module, so the guard stays precise if
                // `util::spf` ever grows a non-pure item.
                && !line.contains("util::spf::Ipv4Cidr")
                && !line.contains("util::spf::Ipv6Cidr")
                // Pure, offline, dependency-free IEEE OUI classifier (a const
                // vendor table + a U/L-bit test on the first octet; no I/O, no
                // deps) — same leaf category as `util::spf`/`util::abn`. AU-122
                // uses it to separate a trackable universally-administered MAC
                // from a randomized privacy address in a radar/WiGLE sweep, the
                // same classifier the WiGLE emit path already applies so the two
                // never disagree on which addresses are real hardware.
                && !line.contains("util::oui")
                // Pure, offline, dependency-free generic/default-SSID classifier
                // (two curated const string tables + one cached aho-corasick
                // pass over a lowercased copy; no I/O, no state, no upward
                // deps) — the same leaf category as `util::oui` directly above,
                // and its exact counterpart: `oui` answers "is this BSSID real
                // hardware?", `wifi` answers "is this network name a vendor
                // default?". The autonomous seeding gate
                // (`core::engine::ranking::is_autonomous_seed_candidate`) uses
                // it so a `NETGEAR` heard in passing can never seed a scan. It
                // lives in `util` rather than in `core` precisely so it is the
                // SAME implementation the WiGLE module applies before spending
                // a request, and the two can never drift. Scoped to the single
                // function rather than the whole module so the guard stays
                // precise if `util::wifi` ever grows a non-pure item.
                && !line.contains("util::wifi::is_generic_ssid")
                // Pure, offline look-alike/typosquat comparison for domain
                // labels (homoglyph skeleton fold + Levenshtein; no I/O, no
                // deps, no Unicode tables) — same leaf category as
                // `util::oui`/`util::abn`. AU-118 uses it to flag a phishing /
                // brand-impersonation domain standing up beside the genuine one.
                && !line.contains("util::confusable")
                // Pure, offline canonical-identity-form helpers (Gmail dot/
                // `+tag` mailbox folding, the shared generational-suffix
                // list; no I/O, no deps) — same leaf category as
                // `util::confusable`/`util::abn`. `core::resolve` calls this
                // instead of keeping its own copy so its merge-suggestion
                // pass and `modules::email_canonical`'s enrichment pass can
                // never silently disagree on what counts as one mailbox.
                && !line.contains("util::canonical")
                // Pure, offline URL tracking-param denylist + predicate (no
                // I/O, no deps) — same leaf category as `util::canonical`
                // immediately above. `core::entity`'s `Url` UID normaliser
                // calls this instead of keeping its own copy so it can never
                // silently drift from `modules::search_engines`'s SERP-dedup
                // key, which strips the same params for the same reason.
                && !line.contains("util::url_util::is_tracking_param_key")
                && !line.contains("util::preflight")
                && !line.contains("util::keys::signup_hint")
                && !line.contains("util::oathnet::reset_budget")
                && !line.contains("util::see_know::set_scan_cap_override")
                // Pure task-local setter (no I/O): the foreign-key scan-scope
                // ambient. The engine wraps each scan + each spawned dispatch task in
                // `found_keys::with_scan` so the per-response key scanner attributes a
                // discovered key to the right `scan_id` under concurrent `serve`
                // scans (PROBLEM_TREE T2.11). reset/drain still go through the module
                // hook (they bridge to `core::entity`); only the pure scope is here.
                && !line.contains("util::found_keys::with_scan")
                // Pure task-local ambient (no I/O): the regional-search
                // scan-scope, the same shape/justification as
                // `found_keys::with_scan` immediately above. The engine wraps
                // each scan + each spawned dispatch task in `with_regional` so
                // `search_engines::regional_enabled()` reads the setting of
                // the scan actually executing on the calling task, never a
                // concurrently-running sibling's (PROBLEM_TREE T2.11).
                // `regional_enabled` itself is read directly at the dispatch
                // spawn site to capture the value before re-scoping it inside
                // the spawned task.
                && !line.contains("util::regional::with_regional")
                && !line.contains("util::regional::regional_enabled")
                // Pure task-local ambient (no I/O): the per-scan quota-budget
                // scope, the same shape/justification as `found_keys::with_scan`
                // / `regional::with_regional` above. The engine wraps each scan +
                // each spawned dispatch task in this so `QuotaBudget`'s scan-
                // scoped state (see_know / oathnet_pro / wigle's shared per-scan
                // caps, cap overrides, and exhausted latches) is isolated per
                // `scan_id` instead of a single process-wide counter that any
                // concurrent `hse serve` scan starting could silently reset for
                // every sibling scan (the same PROBLEM_TREE T2.11 class of bug).
                // `cleanup_scan_budgets` still goes through the `ModuleRuntime`
                // hook; only the pure scope-setter is here.
                && !line.contains("util::budget::with_scan")
                // Pure, offline, dependency-free UTC time-of-day formatter
                // (`HH:MM:SS` via Howard Hinnant civil-from-days — no date crate,
                // no I/O, no state; total and deterministic) — the same leaf
                // category as `util::geohash`/`util::geometry`. `core::event`'s
                // `Event::to_log_line` is the single canonical definition of the
                // structured JSON log line shared by every surface (events.log,
                // the debug bundle, `hse live`, the web Scan-Log), so it stamps
                // each event's `time` field through this one formatter rather than
                // re-deriving the time-of-day maths in `core` (which would
                // duplicate a `util` responsibility). Scoped to the single
                // function actually used so the guard stays precise.
                && !line.contains("util::timefmt::hms_utc")
                // Persistent capability toggles (universal toggleability): the
                // engine's module gate reads `module.<name>` on/off.
                && !line.contains("util::settings::get_bool")
                // Pure, dependency-free ABN/ACN checksums — used by
                // `TargetKind::detect` to tell a registry number from a phone
                // number in the unified-scan auto-detector.
                && !line.contains("util::abn::is_valid_abn")
                && !line.contains("util::abn::is_valid_acn")
                // Pure, dependency-free company-ACN extractor (no state, no I/O),
                // same leaf category as the ABN/ACN checksums above. AU-089 uses
                // it to fold a company ABN onto its embedded ACN so an ABN and
                // its derived ACN count as one company in the corporate-network
                // rule.
                && !line.contains("util::abn::derive_acn")
                // Pure, dependency-free address locality dedup key — same leaf
                // category as the ABN checksums: no state, no I/O. The engine's
                // finalise step uses it to collapse postcode-variant Address
                // entities (e.g. "X, NSW" / "X, NSW 2582") into one.
                && !line.contains("util::address_au::locality_key")
                // Pure, dependency-free AU state/territory resolver (abbrev /
                // full name / postcode → canonical code). Same leaf category as
                // `locality_key`: no state, no I/O. AU-056 uses it to derive the
                // jurisdiction an Address asserts, to cross-check it against the
                // `au-state:` tag a Coordinates entity carries.
                && !line.contains("util::address_au::state_code")
                // Pure, dependency-free AU fixed-line area-code → geographic
                // region/state resolver (no I/O), same leaf category as
                // `state_code`. AU-085 uses it to derive the jurisdiction a
                // landline's area code physically implies, to cross-check it
                // against the subject's address/coordinate state.
                && !line.contains("util::address_au::au_phone_region")
                // Pure, dependency-free AU phone line-type classifier (mobile /
                // geographic / VoIP / business-service; no I/O), same leaf
                // category as `au_phone_region`. AU-102 uses it to profile every
                // number the subject carries into a contactability/premises/
                // organisational picture; the type is portability-proof.
                && !line.contains("util::address_au::au_phone_line_type")
                && !line.contains("util::address_au::AuLineType")
                // Pure, dependency-free AU phone E.164 normaliser (no I/O), same
                // leaf category as `au_phone_region`. AU-102 uses it to dedup the
                // subject's numbers by canonical form before profiling them.
                && !line.contains("util::address_au::normalise_phone")
                // Pure, dependency-free AU network-operator brand recogniser (no
                // I/O): an isp/org/as string → the Australian ISP/AARNet it names.
                // Same leaf category as `state_code`. AU-097 attributes the
                // network; AU-098 uses it as a domestic-connection corroboration.
                && !line.contains("util::address_au::au_network_operator")
                && !line.contains("util::address_au::AuNetworkKind")
                // Pure, dependency-free coordinate -> AU state/territory
                // bounding-box classifier (no I/O). AU-056 uses it to derive a
                // coordinate's jurisdiction when the `au-state:` tag is absent
                // (most fixes — only three builders tag), so the cross-check
                // works for coordinates from any module.
                && !line.contains("util::geo::au_state_for_coords")
                // Pure, dependency-free AU bounding-box membership test (no I/O),
                // same leaf category as `au_state_for_coords`. AU-059 uses it to
                // restrict the cross-seed geo-synergy fix to Australian
                // coordinates when the `au-state:`/`country:AU` tag is absent.
                && !line.contains("util::geo::is_in_australia")
                // Pure, dependency-free offline reverse geocoder (coordinate →
                // nearest AU population centre, by haversine over a curated
                // anchor set; no I/O), same leaf category as `au_state_for_coords`.
                // AU-099 uses it to label a bare coordinate with a human locality.
                && !line.contains("util::geo::nearest_au_locality")
                // Pure, dependency-free great-circle distance (haversine; no I/O,
                // no deps), same leaf category as `nearest_au_locality`. The
                // multi-source location-corroboration scorer
                // (`au_location_corroboration`) uses it to cluster AU location
                // signals that agree on one locality.
                && !line.contains("util::geo::haversine_km")
                // Pure, dependency-free offline coordinate parser (no I/O, no
                // network), same leaf category as `geohash`/`geometry`. The
                // target auto-detector (`core::scan`) uses it to recognise
                // self-evident coordinate notations (DMS, geo: URI, Plus Code),
                // and entity normalisation (`core::entity`) to canonicalise them
                // to the one decimal "lat,lon" shape the geo pipeline speaks.
                && !line.contains("util::geo::coords::parse")
                // Pure, dependency-free digit-only normaliser — the same leaf
                // category as the ABN checksums above; `core::scan` uses it in
                // the target auto-detector to strip separators from a candidate
                // phone/registry number. No state, no I/O, no upward deps.
                && !line.contains("util::str_util::ascii_digits")
                // Pure, dependency-free offline city→coordinate lookup table
                // (no I/O, no network). The engine's address_to_coords_pass uses
                // it to convert Address entities into Coordinates for geo correlation.
                && !line.contains("util::city_coords::city_coords")
                // Pure, dependency-free offline AU-locality exact-match lookup
                // (no I/O, no network), same leaf category as `city_coords`
                // immediately above — it reuses the identical `CITIES` table,
                // just as an exact-phrase membership test rather than a
                // free-text address geocoder. AU-058 uses it to disambiguate a
                // multi-word suburb (Gold Coast, Sunshine Coast, Alice
                // Springs, …) embedded in a ratemyagent.com.au URL slug, where
                // hyphen-splitting alone can't tell an elastic agent-name
                // prefix from a multi-word suburb.
                && !line.contains("util::city_coords::is_tabulated_au_city")
                // Pure, dependency-free offline surname-distinctiveness heuristic
                // (a small embedded common-surname set; no state, no I/O), same leaf
                // category as `address_au::locality_key`. `core::leads` uses it to
                // treat a shared rare surname as corroborating and a shared common
                // one with caution, so the family signal is weighted by how
                // distinctive the name actually is.
                && !line.contains("util::surnames::is_common")
                && !line.contains("util::surnames::surname_of")
                // Pure, dependency-free offline SIM-anonymity classifier (a curated
                // carrier→tier table; no state, no I/O), same leaf category as
                // `surnames`/`address_au`. AU-068 reads the tier from a phone's tag
                // (via `tier_for_tag` / `ANONYMITY_TAGS`) to surface a likely burner
                // SIM, weighting how much attribution a phone-based link deserves.
                && !line.contains("util::sim_anonymity")
                // Pure, dependency-free offline breach-source → sector classifier
                // (a curated brand/category table + string parse; no state, no
                // I/O, no upward deps), same leaf category as `sim_anonymity` /
                // `surnames`. The engine's admission pass (`tag_breach_sector`)
                // uses it to stamp every breach finding with its source's sector
                // (`sector:real-estate`, …), so a hit is filterable by sector at
                // one chokepoint regardless of which pool surfaced it.
                && !line.contains("util::breach_sector")
                // Pure, dependency-free offline domain utilities (no state, no
                // I/O, no network): the proxy-registrant allowlist check
                // (`is_proxy_registrant`) and the public-suffix-based
                // registrable-domain extractor (`registrable_domain`). Used by
                // `core::relation::builders` (derive_co_ownership) and
                // `core::correlator::rules::org` (AU-109/AU-110) to collapse
                // same-site subdomains and exclude privacy-proxy registrants.
                && !line.contains("util::domains::is_proxy_registrant")
                && !line.contains("util::domains::registrable_domain")
                // Pure, dependency-free whole-label suffix predicate (no I/O),
                // same leaf category. `core::data_broker::broker_for_host` uses
                // it to match a host to its data-broker site (the canonical home
                // of the `host == d || subdomain-of d` idiom).
                && !line.contains("util::domains::is_or_subdomain_of")
                // Pure, dependency-free freemail-domain membership test (a small
                // embedded list; no I/O), same leaf category as the other
                // `util::domains` predicates. AU-100 uses it to exclude personal
                // webmail when inferring an employer from a work-email domain.
                && !line.contains("util::domains::is_freemail")
                // Pure, dependency-free `.au` second-level-domain registrant
                // classifier (no I/O), same leaf category as `state_code`. AU-100
                // uses it to type the subject's organisational email domain.
                && !line.contains("util::address_au::au_domain_registrant")
                // Pure, dependency-free Australian BSB → financial-institution
                // resolver (a curated AusPayNet prefix table; no state, no I/O),
                // same leaf category as `state_code`. AU-104 uses it to name the
                // bank behind an exposed BSB in breach/stealer data.
                && !line.contains("util::bsb::bsb_institution")
                // Pure, dependency-free OFFLINE hash intelligence (no state, no
                // I/O, no network, no GPU — Termux-safe), same leaf category as
                // `bsb` / `sim_anonymity`: the common-password denylist
                // (`is_common_password`), the offline digest table
                // (`digests_of` / `is_common_collision`). AU-105 (credential
                // reuse) uses them to bridge a leaked plaintext to the SAME
                // password leaked as a hash without admitting a common-password
                // collision as a link.
                && !line.contains("util::hashcat::is_common_password")
                && !line.contains("util::hashcat::digests_of")
                && !line.contains("util::hashcat::is_common_collision")
                // Pure, dependency-free disjoint-set / union-find primitive (a
                // flat parent `Vec<usize>` with path-halving; no state, no I/O,
                // no deps), same leaf category as `util::geometry`. The
                // credential-reuse (AU-121) and shared-infrastructure (AU-116)
                // closure rules use it to compute connected components over
                // handle/infra graphs; it is the single source of truth those
                // rules and the diagnostics/relation clusterers all delegate to.
                && !line.contains("util::union_find")
                // Pure, IO-free recursive query generator + its value types (no
                // network, no key, no state — `generate` is a deterministic
                // `(kind, value, opts) -> Vec<BatchQuery>`), same leaf category
                // as `util::union_find`. `core::breach_sweep` compiles the final
                // bulk breach plan with it. Deliberately scoped to
                // `oathnet_batch`: the OathNet *client* (`util::oathnet` —
                // budget state, key resolution, `async fn search`) stays out of
                // `core`, which is why the field→TargetKind mapping the sweep
                // needs lives on `BatchQuery::target_kind` rather than being
                // reached for as `util::oathnet::FIELD_*`.
                && !line.contains("util::oathnet_batch")
                // Pure, IO-free key-resolution POLICY: `resolve_key` is a
                // deterministic `Option<&str> -> Option<&str>` deciding what
                // counts as a configured credential (absent / blank / an
                // unedited `insert_..._here` template placeholder all read as
                // unconfigured). No state, no I/O, no network — the same leaf
                // category as `util::union_find`.
                //
                // `ModuleContext::key` must apply exactly this rule, because it
                // is the gate every keyed module goes through since the embedded
                // provider credentials were removed: a slot that fails it yields
                // `Error::MissingKey` and a clean "needs key" skip instead of a
                // request authenticated with "" or a placeholder string.
                // Duplicating the rule in `core` is what would actually be
                // dangerous — the two copies could disagree about what
                // "configured" means.
                //
                // Deliberately scoped to the pure resolver: the STATEFUL half of
                // `util::keys` (env-file `load`/`write_keys`, the compromised-key
                // purge, the key pool) stays out of `core`, exactly as
                // `util::oathnet_batch` is allowed while the `util::oathnet`
                // client is not.
                && !line.contains("util::keys::resolve_key")
        })
        .collect();

    // The revealed backlog is EMPTY and the scaffolding that froze it is gone.
    //
    // Un-blinding `scan_dir` (#355) surfaced four real violations here, all in
    // `core/engine/mod.rs`: three `util::egress` calls and one
    // `util::scraper_health` import. They were frozen in a shrink-only list
    // rather than allow-listed, because docs/AUTONOMY_CHARTER.md's INV-3 is
    // explicit that a tripped invariant is a design decision to raise, not
    // silence ("No deleted assertion, no new `#[allow]`/`#[ignore]` ... unless
    // replaced by a strictly stronger check in the same commit").
    //
    // They were then resolved properly: `core::engine_host::EngineHost` is the
    // contract, `util::engine_host::UtilEngineHost` implements it, and
    // `app::runtime` injects it — the same `util → core` direction
    // `storage::Store` already uses for `StoragePort`. With nothing left to
    // record, this is a plain assertion again.
    assert!(
        allowed.is_empty(),
        "core/ must not import util/ (except the allow-listed pure/leaf helpers above).\nViolations:\n{}",
        allowed.join("\n")
    );
}

#[test]
fn core_does_not_import_modules() {
    // core is module-agnostic: the application layer injects the implementation
    // of core's `ModuleRuntime` contract; core never names `crate::modules`.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let v = scan_for_violations(&dir, &["crate::modules"]);
    assert!(
        v.is_empty(),
        "core/ must not import modules/ — invert via `core::module_runtime`.\nViolations:\n{}",
        v.join("\n")
    );
}

#[test]
fn module_runtime_has_no_process_global_installation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let contract = fs::read_to_string(root.join("src/core/module_runtime.rs")).unwrap();
    for forbidden in ["OnceLock", "static HOOKS", "fn install("] {
        assert!(
            !contract.contains(forbidden),
            "ModuleRuntime must be injected per engine, not installed globally: {forbidden}"
        );
    }
    let registry = fs::read_to_string(root.join("src/modules/mod.rs")).unwrap();
    assert!(
        !registry.contains("install_core_hooks"),
        "module registry construction must remain free of process-global side effects"
    );
}

#[test]
fn storage_port_is_object_safe() {
    use huntsman_search_engine::core::StoragePort;
    fn _assert_object_safety(_: &dyn StoragePort) {}
}

#[test]
fn all_modules_have_descriptions() {
    let modules = huntsman_search_engine::modules::registry();
    assert!(!modules.is_empty());
    let missing: Vec<_> = modules
        .iter()
        .filter(|m| m.description().trim().is_empty())
        .map(|m| m.name())
        .collect();
    assert!(
        missing.is_empty(),
        "modules with no description: {missing:?}"
    );
}

#[test]
fn module_registry_count_is_stable() {
    // Coarse scale floor, complementing the exact count pinned by
    // `readme_module_overview_count_matches_registry`. The old `>= 75` bound sat
    // so far below the real registry (~168) that it could not catch an accidental
    // drop of dozens of modules — a mass-removal that also edited the README to
    // match would slip past the exact guard, and this floor is the second barrier.
    // Kept a floor (not an exact count) so routine single-module churn does not
    // touch this test; only a large regression trips it.
    let modules = huntsman_search_engine::modules::registry();
    assert!(
        modules.len() >= 150,
        "expected >=150 modules, got {} — a large registry drop; if intentional, \
         lower this floor deliberately",
        modules.len()
    );
}

#[test]
fn module_names_are_unique() {
    // Module names are the primary key of the runtime: `MODULE_TECHNIQUES` keys a
    // HashMap on `m.name()` (src/modules/mod.rs), and `find(|m| m.name() == ..)`
    // is used pervasively for per-module lookup. Two modules sharing a name would
    // silently collapse in the index (one entry wins, the other's techniques and
    // dispatch attribution vanish) with no other test failing. This pins the
    // uniqueness that the rest of the system already assumes.
    use std::collections::BTreeMap;
    let modules = huntsman_search_engine::modules::registry();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for m in &modules {
        *counts.entry(m.name()).or_default() += 1;
    }
    let dupes: Vec<(&&str, &usize)> = counts.iter().filter(|(_, n)| **n > 1).collect();
    assert!(
        dupes.is_empty(),
        "duplicate module name(s) in the registry — names must be unique: {dupes:?}"
    );
}

// Split into part files under architecture_parts/ (not directly in tests/, so
// Cargo doesn't auto-discover them as separate test binaries) purely to keep
// each file small enough for reliable transmission through the push tooling
// used in this repo's environment — `include!` splices them back into this
// same module scope at compile time, so this is byte-for-byte the same test
// suite as one file; behavior, test names, and results are unaffected.
include!("architecture_parts/architecture_part2.rs");
include!("architecture_parts/architecture_part3.rs");
include!("architecture_parts/architecture_part4.rs");
include!("architecture_parts/architecture_part5.rs");
include!("architecture_parts/architecture_part6.rs");
include!("architecture_parts/architecture_part7.rs");
