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
        } else if path.file_name().is_some_and(|n| n == "tests.rs") {
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

/// `core_does_not_import_ai` — half of the `Runtime AI-independence` invariant
/// (`src/lib.rs`): `ai/` depends on `core/`, never the reverse, so the
/// deterministic scan engine, module dispatch, correlator, and storage port can
/// never come to depend — even transitively — on the optional, opt-in AI-daemon
/// surface. Paired with `runtime_carries_no_ai_ml_inference_dependency` below,
/// which guards the dependency graph itself; this guards the layering that keeps
/// the exception (`src/ai/`) from spreading into the part of the codebase that
/// must stay reproducible with no AI available.
#[test]
fn core_does_not_import_ai() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let v = scan_for_violations(&dir, &["crate::ai", "use crate::ai"]);
    assert!(
        v.is_empty(),
        "core/ must not import ai/ — the deterministic scan/correlation pipeline \
         (BFS engine, module dispatch, correlator, storage port, exports) stays \
         fully AI-independent and reproducible with no AI available; the optional \
         AI-analysis daemon depends on core, never the reverse.\nViolations:\n{}",
        v.join("\n")
    );
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

/// Every non-passive (network-reaching) module must declare a
/// `max_timeout_ms()` strictly greater than the default `MODULE_TIMEOUT_MS`
/// (3s). The engine wraps each `process()` in a `tokio::time::timeout` at
/// this budget; with no client-level total timeout, a module left at the 3s
/// default is killed before a slow-but-connected response can return,
/// surfacing a spurious engine "timeout" and silently yielding nothing.
///
/// Several modules (abn_lookup, disposable_check, mylnikov, sunrise_sunset,
/// and the ip/breach lookups) shipped exactly this defect. This guard makes
/// the whole class a CI failure rather than a silent runtime no-op. Passive
/// modules (local sensors, pure computation) legitimately keep the default
/// and are exempt.
#[test]
fn every_module_maps_to_valid_attack_reconnaissance_techniques() {
    // Every registered module declares the MITRE ATT&CK Reconnaissance technique
    // IDs its collection implements (defaulted from category, overridden where
    // the category is too coarse). This guard pins that across ALL modules:
    //   1. every declared ID is a real catalogue entry (no typo / stale ID);
    //   2. the active scanner maps to Active Scanning, not passive DB search;
    //   3. the catalogue's coverage spans the core OSINT-collection techniques,
    //      so the ATT&CK alignment is substantive rather than vacuous.
    use huntsman_search_engine::core::attack;
    let modules = huntsman_search_engine::modules::registry();

    let mut covered = std::collections::BTreeSet::new();
    for m in &modules {
        // Systematic enrichment: EVERY collection module must declare at least
        // one ATT&CK Reconnaissance technique, so none silently contributes
        // nothing to the per-scan coverage report. A new module added without a
        // mapping (its category defaulting to `Other` → empty) fails here.
        assert!(
            !m.attack_techniques().is_empty(),
            "module `{}` has no ATT&CK Reconnaissance technique — add a category \
             mapping or an attack_techniques() override",
            m.name()
        );
        for id in m.attack_techniques() {
            let tech = attack::technique(id).unwrap_or_else(|| {
                panic!(
                    "module `{}` claims ATT&CK technique `{id}` absent from the catalogue",
                    m.name()
                )
            });
            // The declared technique must belong to the Reconnaissance tactic
            // (TA0043) — the one tactic HSE claims. `coverage()` and the Navigator
            // export iterate `reconnaissance()` only, so a catalogued-but-non-recon
            // override (e.g. an Impact or Collection technique) passes the
            // membership check above yet is silently dropped from every coverage
            // report. Pin the whole-registry override surface to the tactic the
            // category defaults are already constrained to.
            assert!(
                tech.tactics.contains(&"reconnaissance"),
                "module `{}` claims ATT&CK technique `{id}` ({}) outside the \
                 Reconnaissance tactic — coverage() would silently drop it; \
                 map to a TA0043 technique or correct the override",
                m.name(),
                tech.tactics.join("+"),
            );
            covered.insert(*id);
        }
    }

    // The active scanner is the deliberate per-module override away from its
    // (passive) category default.
    let portscan = modules
        .iter()
        .find(|m| m.name() == "portscan")
        .expect("portscan registered");
    assert!(
        portscan.attack_techniques().contains(&"T1595.001"),
        "portscan must map to Active Scanning (T1595.001), got {:?}",
        portscan.attack_techniques()
    );

    // Coverage must span the backbone Reconnaissance techniques — if any of
    // these is uncovered, a whole class of collection has silently dropped out.
    for id in [
        "T1589.001", // Credentials (breach)
        "T1589.002", // Email Addresses
        "T1590.002", // DNS
        "T1591.001", // Physical Locations (geo)
        "T1593.001", // Social Media
        "T1593.002", // Search Engines
        "T1596.002", // WHOIS
    ] {
        assert!(
            covered.contains(id),
            "no module covers ATT&CK Reconnaissance technique {id} — collection gap"
        );
    }
}

#[test]
fn attack_overrides_attribute_collection_modules_precisely() {
    // Modules whose coarse category default mis- or over-attributed their ATT&CK
    // Reconnaissance technique now declare the precise one. This pins the
    // intended attribution (and guards against a regression to the category
    // default) so the per-scan coverage report is accurate.
    let modules = huntsman_search_engine::modules::registry();
    let techniques = |name: &str| -> Vec<&'static str> {
        modules
            .iter()
            .find(|m| m.name() == name)
            .map(|m| m.attack_techniques().to_vec())
            .unwrap_or_default()
    };

    // Code repositories — NOT social media (T1593.001). `crates_io` and
    // `npm_author` are pure package-registry lookups with no Person/
    // Organisation/Address collection, so Code Repositories alone is precise
    // for them.
    for name in ["crates_io", "npm_author"] {
        assert_eq!(
            techniques(name),
            vec!["T1593.003"],
            "{name} → Code Repositories"
        );
        assert!(
            !techniques(name).contains(&"T1593.001"),
            "{name} must no longer claim Social Media"
        );
    }
    // `github_user` is also Code Repositories rather than Social Media for its
    // Username discovery, but — unlike its two package-registry siblings
    // above — it additionally collects a real name (Person), published/gist/
    // commit emails, company/org membership (Organisation), a location
    // (Address/Coordinates), and published SSH keys (Credential), so its
    // precise set is a superset of the bare Code Repositories technique.
    assert_eq!(
        techniques("github_user"),
        vec![
            "T1589.001",
            "T1589.002",
            "T1589.003",
            "T1591.001",
            "T1591.002",
            "T1593.003",
        ],
        "github_user → Code Repositories plus every technique its Person/Email/\
         Organisation/Address/Coordinates/Credential collection actually performs"
    );
    assert!(
        !techniques("github_user").contains(&"T1593.001"),
        "github_user must no longer claim Social Media"
    );
    // DnsRecon family — each its specific technique, not the whole bundle.
    assert_eq!(techniques("crtsh"), vec!["T1596.003"]); // Digital Certificates
    assert_eq!(techniques("cert_intel"), vec!["T1596.003"]);
    assert_eq!(techniques("whois"), vec!["T1596.002"]); // WHOIS
    assert_eq!(techniques("rdap_domain"), vec!["T1596.002"]);
    // dns_intel resolves live records (DNS, T1590.002) AND brute-forces
    // subdomains from a common-name wordlist (Active Scanning: Wordlist Scanning,
    // T1595.003) — two techniques for its two behaviours, not just passive DNS.
    assert_eq!(techniques("dns_intel"), vec!["T1590.002", "T1595.003"]);
    assert!(
        techniques("dns_intel").contains(&"T1595.003"),
        "dns_intel's dictionary subdomain brute-force is Wordlist Scanning"
    );
    assert_eq!(techniques("securitytrails"), vec!["T1596.001"]); // Passive DNS
    assert_eq!(techniques("hackertarget"), vec!["T1590.002", "T1596.001"]);
    // opencellid searches a cell-tower geolocation DATABASE (Search Open Technical
    // Databases → Physical Locations); it makes no DNS query, so it must NOT claim
    // DNS/Passive DNS (T1596.001) — there is no cell-database sub-technique, so the
    // honest mapping stops at the T1596 parent.
    assert_eq!(techniques("opencellid"), vec!["T1591.001", "T1596"]);
    assert!(
        !techniques("opencellid").contains(&"T1596.001"),
        "opencellid queries a cell-tower database, not DNS"
    );
    // Active vulnerability probe (dangling-CNAME takeover) → Active Scanning:
    // Vulnerability Scanning (T1595.002), NOT the passive Domain Properties the
    // DnsRecon default would inherit. It touches the target to prove an
    // exploitable misconfiguration, exactly the case the override exists for.
    assert_eq!(techniques("subdomain_takeover"), vec!["T1595.002"]);
    assert!(
        !techniques("subdomain_takeover").contains(&"T1590.001"),
        "subdomain_takeover actively scans for a takeover vulnerability, it does \
         not passively gather domain properties"
    );
    // WAF/CDN fingerprinting → Network Security Appliances + CDNs (not the Web default).
    assert_eq!(techniques("waf_detect"), vec!["T1590.006", "T1596.004"]);

    // Corporate registries geocode the registered business address to
    // coordinates, so they also Determine Physical Locations (T1591.001) — which
    // the Corporate default (Business Relationships + Identify Roles) omits. The
    // three that surface no officer/role drop the inherited T1591.004; only
    // opencorporates, which lists officers, keeps it.
    for name in ["abn_lookup", "acnc_charities", "gleif_lei"] {
        assert_eq!(
            techniques(name),
            vec!["T1591.001", "T1591.002"],
            "{name} → Physical Locations + Business Relationships (no roles)"
        );
        assert!(
            !techniques(name).contains(&"T1591.004"),
            "{name} surfaces no officer/role; must not claim Identify Roles"
        );
    }
    assert_eq!(
        techniques("opencorporates"),
        vec!["T1591.001", "T1591.002", "T1591.004"],
        "opencorporates lists officers → also Identify Roles",
    );

    // IP geolocation modules (Geo or Infrastructure category) all emit
    // Coordinates + Address (T1591.001 Physical Locations) and an ISP/Organisation
    // entity (T1591.002 Business Relationships) alongside ASN info (T1590.005).
    // The Geo default (T1591.001 only) and Infrastructure default (T1590.005 +
    // T1596.005 Scan Databases) both under-claim; all five declare the precise
    // triple instead — none are scan databases, all are passive geolocation APIs.
    for name in ["ip_geo", "ip2location", "ip_whois_geo", "ipinfo", "ipquery"] {
        assert_eq!(
            techniques(name),
            vec!["T1590.005", "T1591.001", "T1591.002"],
            "{name} → IP Addresses + Physical Locations + Business Relationships"
        );
        assert!(
            !techniques(name).contains(&"T1596.005"),
            "{name} is a passive geolocation API, not a scan database (T1596.005)"
        );
    }

    // Scan-database Infrastructure modules that also geocode hosts:
    // Shodan is a genuine scan db (T1596.005) + IP info (T1590.005) but also
    // maps country→Address (T1591.001) and ASN→Organisation (T1591.002).
    assert_eq!(
        techniques("shodan"),
        vec!["T1590.005", "T1591.001", "T1591.002", "T1596.005"],
        "shodan → scan-db + IP info + physical location + org"
    );
    // Censys likewise: scan db (T1596.005) + IP info (T1590.005) + datacenter
    // coordinates and city as physical location (T1591.001) + the ASN operator
    // as an Organisation (T1591.002 Business Relationships).
    assert_eq!(
        techniques("censys"),
        vec!["T1590.005", "T1596.005", "T1591.001", "T1591.002"],
        "censys → scan-db + IP info + physical location + org"
    );

    // ip_whois_geo is a passive geolocation API identical in surface to the
    // geo-5 above: IP address info + physical location + ISP/operator org.
    assert_eq!(
        techniques("ip_whois_geo"),
        vec!["T1590.005", "T1591.001", "T1591.002"],
        "ip_whois_geo → IP Addresses + Physical Locations + Business Relationships"
    );
    assert!(
        !techniques("ip_whois_geo").contains(&"T1596.005"),
        "ip_whois_geo is a passive geo API, not a scan database (T1596.005)"
    );

    // Keybase: Social category but profiles include a user-declared location
    // string → Physical Locations (T1591.001) alongside Social Media (T1593.001)
    // and Employee Names (T1589.003).
    assert_eq!(
        techniques("keybase"),
        vec!["T1591.001", "T1593.001", "T1589.003"],
        "keybase → Physical Locations + Social Media + Employee Names"
    );

    // NumVerify: Phone category, maps carrier country to a geocodable Address
    // → T1591.001 Physical Locations alongside the base T1589 phone identity.
    assert_eq!(
        techniques("numverify"),
        vec!["T1589", "T1591.001"],
        "numverify → Gather Victim Identity Info (Phone) + Physical Locations"
    );

    // AbuseIPDB: Infrastructure (scan database T1596.005 + IP info T1590.005)
    // but also identifies the ISP as an Organisation → T1591.002 Business
    // Relationships, which the Infrastructure default omits.
    assert_eq!(
        techniques("abuseipdb"),
        vec!["T1590.005", "T1591.002", "T1596.005"],
        "abuseipdb → IP Addresses + Business Relationships + Scan Databases"
    );

    // GreyNoise: same surface as AbuseIPDB — scan-db + IP info + ISP org.
    assert_eq!(
        techniques("greynoise"),
        vec!["T1590.005", "T1591.002", "T1596.005"],
        "greynoise → IP Addresses + Business Relationships + Scan Databases"
    );

    // ip_reputation (AlienVault OTX + Tor): threat intel vendor (T1597.001)
    // rather than passive scan database (T1596.005). Also emits ISP/adversary
    // Organisation (T1591.002) alongside IP info (T1590.005).
    assert_eq!(
        techniques("ip_reputation"),
        vec!["T1590.005", "T1591.002", "T1597.001"],
        "ip_reputation → IP Addresses + Business Relationships + Threat Intel Vendors"
    );
    assert!(
        !techniques("ip_reputation").contains(&"T1596.005"),
        "ip_reputation uses OTX (threat intel vendor T1597.001), not a scan database"
    );

    // Gravatar: People category, but profile location → T1591.001 Physical
    // Locations. T1591.004 (Identify Roles) dropped — Gravatar profiles carry
    // no role information.
    assert_eq!(
        techniques("gravatar"),
        vec!["T1591.001", "T1589.003"],
        "gravatar → Physical Locations + Employee Names (no roles)"
    );
    assert!(
        !techniques("gravatar").contains(&"T1591.004"),
        "gravatar surfaces no role/job info; must not claim Identify Roles"
    );

    // netblock: pure offline CIDR expansion — no scan database → drops T1596.005.
    assert_eq!(
        techniques("netblock"),
        vec!["T1590.005"],
        "netblock → IP Addresses only (no scan database queried)"
    );
    assert!(
        !techniques("netblock").contains(&"T1596.005"),
        "netblock is a pure CIDR math expansion, not a scan database"
    );

    // urlscan: scan database (T1596.005) + IP info (T1590.005) + hosting country
    // → Address entity → T1591.001 Physical Locations (missing from default).
    assert_eq!(
        techniques("urlscan"),
        vec!["T1590.005", "T1591.001", "T1596.005"],
        "urlscan → IP Addresses + Physical Locations + Scan Databases"
    );

    // IntelX: Breach category covers Credentials (T1589.001) and Email
    // Addresses (T1589.002), but the module also emits real-name Person
    // entities → T1589.003 Employee Names must be declared explicitly.
    // Unlike DeHashed below, IntelX re-emits the scanned target as its own
    // entity rather than extracting child entities from record content (its
    // own doc comment: "does not extract child entities — see the
    // no-document-bodies invariant"), so it does not run the shared
    // `breach_rich` pass and does not need that pass's broader technique set.
    assert_eq!(
        techniques("intelx"),
        vec!["T1589.001", "T1589.002", "T1589.003", "T1597.002"],
        "intelx → Credentials + Email Addresses + Employee Names + Purchase Technical Data"
    );
    assert!(
        techniques("intelx").contains(&"T1589.003"),
        "intelx emits Person entities; must claim Employee Names (T1589.003)"
    );

    // DeHashed: Breach category covers Credentials + Email Addresses, but the
    // module's own per-record extractor plus the shared `breach_rich`
    // "maximum raw data" pass it runs (see `dehashed/build.rs`'s call site)
    // together mint Person, IP, Address/Coordinates, Organisation, host
    // fingerprints (MAC/device id), and social-media handles — the full
    // breach-pool surface `see_know`/`oathnet_pro` declare for running the
    // identical shared extractor, not just credentials/email/name.
    assert_eq!(
        techniques("dehashed"),
        vec![
            "T1589.001",
            "T1589.002",
            "T1589.003",
            "T1590.005",
            "T1591.001",
            "T1591.002",
            "T1592",
            "T1593.001",
            "T1597.002",
        ],
        "dehashed → the full shared breach_rich surface, from a purchased data feed"
    );

    // WiGLE: Geo category (T1591.001 Physical Locations) but also surfaces
    // the cellular carrier / WiFi network operator as an Organisation →
    // T1591.002 Business Relationships.
    assert_eq!(
        techniques("wigle"),
        vec!["T1591.001", "T1591.002"],
        "wigle → Physical Locations + Business Relationships (carrier/operator)"
    );

    // ip_registry: queries RDAP (T1596.002 WHOIS) + BGPView (T1590.005 IP Addresses).
    // Emits abuse-contact emails (T1589.002) and ASN operator org (T1591.002).
    // T1596.005 (Scan Databases) does not apply to registration/routing databases.
    assert_eq!(
        techniques("ip_registry"),
        vec!["T1589.002", "T1590.005", "T1591.002", "T1596.002"],
        "ip_registry → Email Addresses + IP Addresses + Business Relationships + WHOIS"
    );
    assert!(
        !techniques("ip_registry").contains(&"T1596.005"),
        "ip_registry queries RDAP/BGPView — not a scan database (T1596.005)"
    );

    // exif_geo: Geo category (T1591.001) but EXIF Author field → Person entity
    // → T1589.003 Employee Names, which the Geo default omits.
    assert_eq!(
        techniques("exif_geo"),
        vec!["T1589.003", "T1591.001"],
        "exif_geo → Employee Names (EXIF author) + Physical Locations (GPS)"
    );

    // search_engines: Search category (T1593.002) but SERP scraping surfaces
    // emails, real names, addresses, and organisations — all techniques absent
    // from the narrow Search category default.
    assert_eq!(
        techniques("search_engines"),
        vec![
            "T1589.002",
            "T1589.003",
            "T1591.001",
            "T1591.002",
            "T1593.002"
        ],
        "search_engines → Email + Employee Names + Physical Locations + Business Relationships + Search Engines"
    );

    // pgp: People default (T1589.003 + T1591.004 Identify Roles) but PGP keys
    // carry no role info — only real name (T1589.003) and email (T1589.002).
    assert_eq!(
        techniques("pgp"),
        vec!["T1589.002", "T1589.003"],
        "pgp → Email Addresses + Employee Names (no role data)"
    );
    assert!(
        !techniques("pgp").contains(&"T1591.004"),
        "pgp profiles carry no role/job info; must not claim Identify Roles"
    );

    // hacker_news: Social default (T1593.001 Social Media + T1589.003 Employee Names)
    // but HN profiles carry no real-name Person entity → T1589.003 over-claimed.
    // Bio emails → T1589.002 Email Addresses must be declared.
    assert_eq!(
        techniques("hacker_news"),
        vec!["T1589.002", "T1593.001"],
        "hacker_news → Email Addresses + Social Media (no real-name Person)"
    );
    assert!(
        !techniques("hacker_news").contains(&"T1589.003"),
        "hacker_news emits no Person entity; must not claim Employee Names"
    );

    // hudsonrock: Breach default (T1589.001 + T1589.002). Stealer logs also
    // capture the victim device IP → T1590.005 IP Addresses must be declared.
    assert_eq!(
        techniques("hudsonrock"),
        vec!["T1589.001", "T1589.002", "T1590.005"],
        "hudsonrock → Credentials + Email Addresses + IP Addresses (stealer device IP)"
    );

    // wifi_intel: Geo default (T1591.001 Physical Locations) but also enumerates
    // WiFi AP MAC addresses → T1592 Host Information (hardware identification).
    assert_eq!(
        techniques("wifi_intel"),
        vec!["T1591.001", "T1592"],
        "wifi_intel → Physical Locations + Host Information (AP MAC addresses)"
    );

    // cell_intel: Sensor default (T1592 Host Information) but primarily determines
    // the device's physical location from cell-tower triangulation → T1591.001.
    assert_eq!(
        techniques("cell_intel"),
        vec!["T1591.001", "T1592"],
        "cell_intel → Physical Locations (triangulated) + Host Information"
    );

    // reddit_user: same profile as hacker_news — Social default over-claims
    // T1589.003 (no Person entity emitted); adds T1589.002 for bio emails.
    assert_eq!(
        techniques("reddit_user"),
        vec!["T1589.002", "T1593.001"],
        "reddit_user → Email Addresses + Social Media (no real-name Person)"
    );
    assert!(
        !techniques("reddit_user").contains(&"T1589.003"),
        "reddit_user emits no Person entity; must not claim Employee Names"
    );

    // username_search: enumerates handle PRESENCE across 300+ sites, emitting a
    // profile Url + the confirmed Username and never a real-name Person — so the
    // Social default's T1589.003 (Employee Names) is over-claimed, the same fix
    // as hacker_news / reddit_user. It has no bio-email path, so T1593.001
    // (Social Media search) is its single precise technique.
    assert_eq!(
        techniques("username_search"),
        vec!["T1593.001"],
        "username_search → Social Media search only (handle presence, no Person)"
    );
    assert!(
        !techniques("username_search").contains(&"T1589.003"),
        "username_search resolves no name; must not claim Employee Names"
    );

    // Name-less Social-category modules: they search a platform for a handle (or,
    // for the offline decoders, derive account metadata from an ID) and emit only
    // Username/Url/Email — never a real-name Person — so the Social default's
    // T1589.003 (Employee Names) is over-claimed, the same fix as
    // hacker_news / reddit_user / nostr / username_search.
    for name in ["streaming_probe", "gaming_profile", "discord_snowflake"] {
        assert_eq!(
            techniques(name),
            vec!["T1593.001"],
            "{name} → Social Media only (no Person emitted)"
        );
        assert!(
            !techniques(name).contains(&"T1589.003"),
            "{name} emits no Person; must not claim Employee Names"
        );
    }
    // fediverse also emits profile emails → T1589.002 (like nostr).
    assert_eq!(
        techniques("fediverse"),
        vec!["T1589.002", "T1593.001"],
        "fediverse → Email Addresses + Social Media (no Person)"
    );
    assert!(
        !techniques("fediverse").contains(&"T1589.003"),
        "fediverse emits no Person; must not claim Employee Names"
    );
    // structured_id is an OFFLINE structured-ID decoder, not a social search: its
    // signal is the generating machine's MAC embedded in a UUIDv1 → host hardware
    // (T1592.001), so it drops BOTH the inherited social-presence techniques.
    assert_eq!(
        techniques("structured_id"),
        vec!["T1592.001"],
        "structured_id → Host Hardware (UUIDv1 node MAC), not social media"
    );
    assert!(
        !techniques("structured_id").contains(&"T1589.003")
            && !techniques("structured_id").contains(&"T1593.001"),
        "structured_id neither resolves a name nor searches social media"
    );

    // epieos: People default drops over-claimed T1591.004 (no roles); adds
    // T1589.002 for the email seed and T1591.001 for location Address.
    assert_eq!(
        techniques("epieos"),
        vec!["T1589.002", "T1589.003", "T1591.001"],
        "epieos → Email Addresses + Employee Names + Physical Locations"
    );
    assert!(
        !techniques("epieos").contains(&"T1591.004"),
        "epieos carries no role/job data; must not claim Identify Roles"
    );

    // local_net: Sensor default (T1592) adds T1590.005 for IpAddress enumeration.
    assert_eq!(
        techniques("local_net"),
        vec!["T1590.005", "T1592"],
        "local_net → IP Addresses (local network sweep) + Host Information (MAC)"
    );

    // leakix: existing override adds T1590.005 for the exposed-service IpAddress.
    assert_eq!(
        techniques("leakix"),
        vec!["T1589.001", "T1589.002", "T1590.005", "T1596.005"],
        "leakix → Credentials + Email Addresses + IP Addresses + Scan Databases"
    );

    // ipqs: existing override adds T1589 + T1589.002 for Phone and Email scoring.
    assert_eq!(
        techniques("ipqs"),
        vec!["T1589", "T1589.002", "T1590.005", "T1596.005", "T1597.001"],
        "ipqs → Victim Identity (Phone) + Email Addresses + IP Addresses + Scan Databases + Threat Intel Vendors"
    );

    // criminal_ip: override adds T1591.002 for the ASN operator Organisation and
    // T1591.001 for the whois city/region/lat-lon → Address/Coordinates.
    assert_eq!(
        techniques("criminal_ip"),
        vec![
            "T1590.005",
            "T1591.001",
            "T1591.002",
            "T1596.005",
            "T1597.001"
        ],
        "criminal_ip → IP Addresses + Physical Locations + Business Relationships + Scan Databases + Threat Intel Vendors"
    );

    // device_sensors: Sensor default (T1592 Host Information) but GPS coordinates
    // also Determine Physical Locations (T1591.001) and the device IP is
    // T1590.005 IP Addresses — both omitted from the Sensor default.
    assert_eq!(
        techniques("device_sensors"),
        vec!["T1590.005", "T1591.001", "T1592"],
        "device_sensors → IP Addresses + Physical Locations + Host Information"
    );

    // Every overridden ID is still a real catalogue entry (no typos).
    for name in [
        "github_user",
        "crtsh",
        "whois",
        "dns_intel",
        "securitytrails",
        "hackertarget",
        "subdomain_takeover",
        "ip_geo",
        "ip2location",
        "ip_whois_geo",
        "keybase",
        "numverify",
        "abuseipdb",
        "greynoise",
        "ip_reputation",
        "gravatar",
        "netblock",
        "urlscan",
        "dehashed",
        "intelx",
        "wigle",
        "ip_registry",
        "exif_geo",
        "search_engines",
        "pgp",
        "hacker_news",
        "hudsonrock",
        "wifi_intel",
        "cell_intel",
        "reddit_user",
        "epieos",
        "local_net",
        "leakix",
        "ipqs",
        "criminal_ip",
        "device_sensors",
    ] {
        for id in techniques(name) {
            assert!(
                huntsman_search_engine::core::attack::technique(id).is_some(),
                "{name} → unknown technique {id}"
            );
        }
    }
}

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

/// Walk `dir` recursively and collect every `HUNTSMAN_*` identifier literal
/// that appears in a `.rs` source file (i.e. every key a module could read).
fn collect_env_literals(dir: &Path, out: &mut std::collections::HashSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_env_literals(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let content = fs::read_to_string(&path).unwrap();
            for (idx, _) in content.match_indices("HUNTSMAN_") {
                let tail = &content[idx..];
                let end = tail
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(tail.len());
                out.insert(tail[..end].to_string());
            }
        }
    }
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
#[test]
fn no_provider_credential_is_embedded_in_source() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs_files(&root.join("src"), &mut files);

    let hexish = |s: &str, n: usize| {
        s.len() >= n && s.chars().all(|c| c.is_ascii_hexdigit()) && s.chars().any(char::is_numeric)
    };
    // The two provider formats this project actually leaked and could plausibly
    // paste back: SeekNow (`seek-` + 48 hex) and a WiGLE API name (`AID` + 32
    // hex). A generic "long hex run" rule is deliberately NOT used here — this
    // codebase is full of legitimate MD5/SHA/UUID fixtures — the `secret-scan`
    // workflow's entropy rules cover the general case.
    let looks_like_provider_key = |lit: &str| -> bool {
        lit.strip_prefix("seek-").is_some_and(|r| hexish(r, 32))
            || lit.strip_prefix("AID").is_some_and(|r| hexish(r, 24))
    };

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
        if !['_KEY", "_TOKEN", "_SECRET", "_USER", "_GUID", "_ID'].iter().any(|s| name.ends_with(s)) {
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
