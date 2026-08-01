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
            let content = fs::read_to_string(&path).unwrap();
            let mut in_test = false;
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed == "#[cfg(test)]" {
                    in_test = true;
                    continue;
                }
                if in_test {
                    continue;
                }
                if trimmed.starts_with("//") {
                    continue;
                }
                if patterns.iter().any(|p| trimmed.contains(p)) {
                    violations.push(format!("{}:{}: {}", path.display(), i + 1, trimmed));
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
fn application_layer_owns_runtime_composition() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let runtime = fs::read_to_string(root.join("src/app/runtime.rs")).unwrap();
    for required in [
        "Store::open(",
        "ScanEngine::with_module_runtime(",
        "registry()",
        "module_runtime()",
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
                // Pure, offline look-alike/typosquat comparison for domain
                // labels (homoglyph skeleton fold + Levenshtein; no I/O, no
                // deps, no Unicode tables) — same leaf category as
                // `util::oui`/`util::abn`. AU-118 uses it to flag a phishing /
                // brand-impersonation domain standing up beside the genuine one.
                && !line.contains("util::confusable")
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
        })
        .collect();
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
    let modules = huntsman_search_engine::modules::registry();
    assert!(
        modules.len() >= 75,
        "expected >=75 modules, got {}",
        modules.len()
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
            assert!(
                attack::technique(id).is_some(),
                "module `{}` claims ATT&CK technique `{id}` absent from the catalogue",
                m.name()
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

/// Every embedded default key must have a SINGLE source of truth in
/// `util::keys` — modules reference the `*_DEFAULT_KEY` constants rather than
/// re-declaring the literal. A re-hardcoded copy elsewhere could silently drift
/// from the canonical value (the "which key is actually current?" bug). This
/// asserts each embedded literal appears only in `src/util/keys.rs`.
#[test]
fn embedded_default_keys_have_a_single_source_of_truth() {
    use huntsman_search_engine::util::keys;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let values = [
        keys::OATHNET_DEFAULT_KEY,
        keys::HIBP_DEFAULT_KEY,
        keys::WIGLE_DEFAULT_USER,
        keys::WIGLE_DEFAULT_TOKEN,
        keys::SEEKNOW_DEFAULT_KEY,
        keys::SEEKNOW_SUPERSEDED_KEY,
    ];

    let mut files = Vec::new();
    collect_rs_files(&root.join("src"), &mut files);

    let mut offenders = Vec::new();
    for path in files {
        // The single source of truth — the literals legitimately live here
        // (flat file or directory module's constants submodule).
        if path.ends_with("util/keys.rs") || path.ends_with("util/keys/constants.rs") {
            continue;
        }
        let content = fs::read_to_string(&path).unwrap();
        if values.iter().any(|v| content.contains(v)) {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "embedded key literals must live only in util::keys.rs (reference the \
         *_DEFAULT_KEY constants, don't re-hardcode them): {offenders:?}"
    );
}

/// Guards against the silent-key-mismatch bug class: a key documented in the
/// provisioning template under a name no module actually reads, so the operator
/// sets it and gets nothing. Every key in `env_template.txt` must be consumed in
/// `src/` (or registered as a service def), or be explicitly listed as reserved.
#[test]
fn env_template_keys_are_all_consumed() {
    use std::collections::HashSet;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Documented but not yet wired to a consuming module. Each MUST be marked
    // `[RESERVED]` in the template; setting it has no runtime effect (yet).
    const NOT_YET_WIRED: &[&str] = &[
        "HUNTSMAN_MALSHARE_KEY",
        "HUNTSMAN_PHISHTANK_KEY",
        "HUNTSMAN_XPOSEDORNOT_KEY",
        "HUNTSMAN_HUDSONROCK_KEY",
        "HUNTSMAN_MACADDRESS_KEY",
        "HUNTSMAN_IPINFO_KEY",
        "HUNTSMAN_MAXMIND_KEY",
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

    // 2. Keys actually read in source, plus the registered service registry.
    let mut consumed: HashSet<String> = HashSet::new();
    collect_env_literals(&root.join("src"), &mut consumed);
    for d in huntsman_search_engine::util::service_defs::service_defs() {
        consumed.insert(d.env_var.to_string());
    }

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

/// Collects every `HUNTSMAN_*` literal bound to a `const ..._ENV: &str = "..."`
/// declaration under `dir` — the project-wide convention every key-gated
/// module uses to name the env var it reads (`const KEY_ENV: &str =
/// "HUNTSMAN_SHODAN_KEY"`, `const OTX_KEY_ENV: &str =
/// "HUNTSMAN_ALIENVAULT_KEY"`, etc). Deliberately narrower than
/// `collect_env_literals` (which also matches prose/doc-comment mentions): this
/// is the precise "a module genuinely reads this env var" signal used to catch
/// keys that are consumed but undocumented in a template — the inverse of what
/// `env_template_keys_are_all_consumed` already guards.
fn collect_key_env_consts(dir: &Path, out: &mut std::collections::HashSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_key_env_consts(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let content = fs::read_to_string(&path).unwrap();
            for line in content.lines() {
                if !line.contains("const ") || !line.contains("ENV") {
                    continue;
                }
                if let Some(start) = line.find("\"HUNTSMAN_") {
                    let rest = &line[start + 1..];
                    if let Some(end) = rest.find('"') {
                        out.insert(rest[..end].to_string());
                    }
                }
            }
        }
    }
}

/// Guards the THREE independent places a key-gated module's env var must be
/// documented for an operator to ever discover it — `env_template.txt` (the
/// `hse provision` template), `util::keys::constants::KNOWN_KEYS` (drives the
/// Settings-page paste grid), and `install.sh`'s own hand-maintained
/// `~/.huntsman.env` heredoc (what a fresh `curl | bash` install writes) — all
/// stay in sync with the modules that actually exist.
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
fn correlator_tests_source() -> String {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/correlator");
    let a = fs::read_to_string(base.join("tests.rs")).unwrap_or_default();
    let b = fs::read_to_string(base.join("rules/tests.rs")).unwrap_or_default();
    format!("{a}\n{b}")
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

/// Concatenated source of every correlation-rule file. The rules live in a
/// `rules/` module split into thematic families (breach/identity/infra/geo/org/
/// crypto) plus `mod.rs`; the rule-wiring and rule-id guards scan the union, so
/// they keep working regardless of how the rules are partitioned across files.
fn correlator_rules_source() -> String {
    // Recurse into subdirectories (`geo/`, `identity/`, `location/`) — a flat
    // `fs::read_dir` would silently skip them (a directory has no `.rs`
    // extension, so the filter drops it entirely), leaving ~46 rules across 3
    // whole subdirectories unscanned by every guard built on this helper
    // (`every_defined_correlation_rule_is_dispatched`,
    // `correlation_rule_ids_match_their_function_number`,
    // `no_two_correlation_rule_functions_share_a_number`). A dead or
    // mis-numbered rule confined to one of those subdirectories would compile,
    // dispatch, and fire while every one of those safety nets stayed silent.
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && p.file_name().is_some_and(|n| n != "tests.rs")
            {
                out.push(p);
            }
        }
    }

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/correlator/rules");
    let mut files = Vec::new();
    walk(&dir, &mut files);
    files.sort(); // deterministic concatenation order

    let mut out = String::new();
    for p in files {
        let text = fs::read_to_string(&p).expect("rule file readable");
        // Truncate at the file's own `#[cfg(test)]` boundary (always at file
        // end by this codebase's convention — see `geo/mod.rs`/`location/mod.rs`
        // for the inline form). Without this, a trailing test module's
        // `assert_eq!(.., "AU-NNN")` for one rule reads as a SUBSEQUENT
        // emission of whichever rule function was declared last in the file,
        // producing a false `correlation_rule_ids_match_their_function_number`
        // mismatch the moment the file under scan has more than one rule and
        // an inline (not split-out) test module.
        let code = text.split("#[cfg(test)]").next().unwrap_or(&text);
        out.push_str(code);
        out.push('\n');
    }
    out
}

/// Every correlation rule defined in the `rules/` module must be wired into a
/// dispatch array in `mod.rs` (`RULES` or `RELATION_RULES`). A `rule_au_*` fn
/// that is never added to an array compiles cleanly (it's referenced by the
/// glob `use rules::*;`, so it isn't even a dead-code warning) and silently
/// never fires — the analyst simply never sees that correlation, with no error
/// anywhere. This is the correlator analog of `every_declared_module_is_registered`
/// (the same failure mode that left `pwned_passwords` dead at runtime).
#[test]
fn every_defined_correlation_rule_is_dispatched() {
    let rules_src = correlator_rules_source();
    let mod_src = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/core/correlator/mod.rs"
    ))
    .expect("correlator mod.rs must exist");

    // Defined: the identifier after `fn ` on any line declaring a `rule_au_*`.
    let defined: Vec<String> = rules_src
        .lines()
        .filter_map(|l| {
            let at = l.find("fn rule_au_")?;
            l[at + "fn ".len()..]
                .split('(')
                .next()
                .map(|name| name.trim().to_string())
        })
        .collect();

    // Dispatched: the leading identifier on each array-element line — every
    // `rule_au_*` occurrence in mod.rs lives in `RULES`/`RELATION_RULES`, one
    // per line (`    rule_au_001_multi_breach,`). Taking the identifier prefix
    // is robust against a trailing comma or comment.
    let dispatched: std::collections::HashSet<String> = mod_src
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("rule_au_"))
        .map(|l| {
            l.chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .collect();

    assert!(
        !defined.is_empty() && !dispatched.is_empty(),
        "parse failure: defined={} dispatched={}",
        defined.len(),
        dispatched.len()
    );

    let orphans: Vec<&String> = defined
        .iter()
        .filter(|name| !dispatched.contains(*name))
        .collect();

    assert!(
        orphans.is_empty(),
        "correlation rules defined in rules.rs but never added to RULES or \
         RELATION_RULES in mod.rs (they compile but silently never fire): {orphans:?}"
    );
}

/// Each `rule_au_NNN_*` function must emit the matching `"AU-NNN"` rule_id. A
/// copy-pasted rule that keeps the source rule's id (e.g. `rule_au_037` emitting
/// `"AU-036"`) compiles and fires, but mis-attributes the correlation — and the
/// id is the dedup/ranking key, so two rules sharing one id collide silently.
/// The `"AU-NNN"` string literal is the emission marker (verified never to appear
/// quoted in a comment); both emission forms — `rule_id: "AU-NNN".into()` and
/// `Correlation::new("AU-NNN", …)` — are covered.
#[test]
fn correlation_rule_ids_match_their_function_number() {
    let src = correlator_rules_source();

    // Digit run starting at byte `from` in `s` (empty if none).
    fn digits_at(s: &str, from: usize) -> &str {
        let bytes = s.as_bytes();
        let end = (from..bytes.len())
            .find(|&i| !bytes[i].is_ascii_digit())
            .unwrap_or(bytes.len());
        &s[from..end]
    }

    let mut current: Option<&str> = None;
    let mut mismatches: Vec<String> = Vec::new();

    for line in src.lines() {
        if let Some(i) = line.find("fn rule_au_") {
            let n = digits_at(line, i + "fn rule_au_".len());
            if !n.is_empty() {
                current = Some(n);
            }
        }
        // Every quoted `"AU-NNN"` on the line is a rule_id emission.
        let mut from = 0;
        while let Some(rel) = line[from..].find("\"AU-") {
            let at = from + rel + "\"AU-".len();
            let n = digits_at(line, at);
            from = at + n.len();
            if n.is_empty() {
                continue;
            }
            // Compare numerically so id zero-padding need not match the function
            // name's (`rule_au_031` ↔ `"AU-031"`, and would still pass `"AU-31"`).
            match current {
                Some(fnum) if fnum.parse::<u32>().ok() == n.parse::<u32>().ok() => {}
                Some(fnum) => mismatches.push(format!("fn rule_au_{fnum} emits \"AU-{n}\"")),
                None => {
                    mismatches.push(format!("\"AU-{n}\" emitted outside any rule_au_* function"));
                }
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "correlation rule_id does not match its function number (copy-paste \
         mis-attribution / colliding dedup key): {mismatches:?}"
    );
}

/// No two DIFFERENT rule functions may claim the same `AU-NNN` number.
///
/// [`correlation_rule_ids_match_their_function_number`] only checks that a
/// function's OWN emitted id matches ITS OWN number — it has no notion of any
/// OTHER function, so two independently-written, independently-dispatched,
/// independently-tested rules (e.g. `rule_au_076_email_username_localpart_bridge`
/// in `identity/account.rs` and the former `rule_au_076_shared_registrant` in
/// `org.rs`) can each individually satisfy it while silently colliding on one
/// `rule_id`. That id is the dedup/supersede key `storage::upsert_correlation`
/// queries on (`WHERE scan_id = ?1 AND rule_id = ?2`), so a collision makes two
/// semantically unrelated findings overwrite/merge into one, corrupting
/// whichever fires second. This exact collision shipped once — a missed
/// renumbering from a 2026-06-25 `origin/main` merge that unioned two
/// independently-numbered rule sets (see `docs/SOLUTION_TREE.md`) — and was
/// only caught by a dedicated audit, not by the test suite. This closes that
/// gap permanently: a number is collected with EVERY distinct
/// `rule_au_<NNN>_<name>` function that declares it, and fails if any number
/// has more than one distinct owner.
#[test]
fn no_two_correlation_rule_functions_share_a_number() {
    let src = correlator_rules_source();
    let mut owners: std::collections::BTreeMap<u32, Vec<String>> =
        std::collections::BTreeMap::new();

    for line in src.lines() {
        let Some(i) = line.find("fn rule_au_") else {
            continue;
        };
        let after = &line[i + "fn rule_au_".len()..];
        let digit_end = after
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after.len());
        if digit_end == 0 {
            continue;
        }
        let Ok(n) = after[..digit_end].parse::<u32>() else {
            continue;
        };
        let name_start = i + "fn ".len();
        let name_end = line[name_start..]
            .find('(')
            .map_or(line.len(), |p| name_start + p);
        let full_name = line[name_start..name_end].trim().to_string();
        let names = owners.entry(n).or_default();
        if !names.contains(&full_name) {
            names.push(full_name);
        }
    }

    let collisions: Vec<String> = owners
        .into_iter()
        .filter(|(_, names)| names.len() > 1)
        .map(|(n, names)| format!("AU-{n:03}: {names:?}"))
        .collect();

    assert!(
        collisions.is_empty(),
        "two different rule functions claim the same AU-NNN number — they will \
         collide on storage's (scan_id, rule_id) dedup/supersede key and corrupt \
         each other's findings; assign the newer rule an unused number: \
         {collisions:?}"
    );
}

/// Every HTTP response body read in `src/modules` and `src/core` must go
/// through a CAPPED reader (`util::http::{read_text, read_json_text,
/// fetch_json*, read_body_capped}`), never a raw `reqwest::Response::text()`.
///
/// The raw call buffers the WHOLE body in RAM with no upper bound before the
/// caller ever inspects it — exactly the OOM-on-Termux pattern
/// `util::http::fetch`'s `JSON_BODY_CAP` (32 MiB) and its capped helpers exist
/// to close off. One module (`pypi_user`'s XML-RPC step) called the raw method
/// directly and went unnoticed until a dedicated audit found it: every OTHER
/// body read in the tree had already been migrated to a capped helper, so the
/// established convention gave no compile-time or test signal that this one
/// call site had been missed. This closes that gap permanently: the raw
/// method is only legitimate inside `util::http` itself, where it backs the
/// capped wrappers.
#[test]
fn no_module_reads_an_http_body_without_a_size_cap() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for sub in ["modules", "core"] {
        let mut files = Vec::new();
        walk(&root.join(sub), &mut files);
        files.sort();
        for p in files {
            let text = fs::read_to_string(&p).expect("source file readable");
            for (i, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue; // doc/explanatory comments may mention the pattern
                }
                if line.contains(".text().await") {
                    offenders.push(format!("{}:{}", p.display(), i + 1));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "raw, uncapped reqwest::Response::text().await outside util::http — \
         use util::http::read_text / read_json_text / fetch_json* instead, or \
         read_body_capped for a non-erroring truncated read: {offenders:?}"
    );
}

/// The README's headline module count is hand-maintained and had drifted
/// (stated as "60+", "63" and "89" across files while the registry held 89).
/// Tie the authoritative "## Module Overview (N modules" figure to the live
/// registry so it can't silently rot again — the same no-silent-drift guard as
/// `modules_md_lists_every_registered_module` and the engine-count test
/// (FTA finding E10.1).
#[test]
fn readme_module_overview_count_matches_registry() {
    let readme = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("README.md must exist");
    let n = huntsman_search_engine::modules::registry().len();
    let needle = format!("## Module Overview ({n} modules");
    assert!(
        readme.contains(&needle),
        "README '## Module Overview (N modules ...)' must cite the live registry \
         size ({n}); update README.md after adding/removing a module"
    );

    // The heading's free/key-gated SPLIT is also authoritative and was previously
    // unguarded — so it silently drifted (headline said "128 free, 34 paid" while
    // the registry held a different split, and later edits compounded it). Tie the
    // full split to the live cost() of every registered module so it can't rot
    // again — the same no-silent-drift guard as the total above. (The per-category
    // "highlight" subtotals lower down are a deliberately CURATED subset, not the
    // registry total, so they are intentionally not checked here.)
    use huntsman_search_engine::core::module::ModuleCost;
    let registry = huntsman_search_engine::modules::registry();
    let (mut free, mut key_gated_paid) = (0usize, 0usize);
    for m in &registry {
        match m.cost() {
            ModuleCost::Free => free += 1,
            ModuleCost::KeyGated | ModuleCost::Paid => key_gated_paid += 1,
        }
    }
    let split =
        format!("## Module Overview ({n} modules — {free} free, {key_gated_paid} key-gated/paid)");
    assert!(
        readme.contains(&split),
        "README module-overview headline must cite the live free/key-gated split \
         ({split:?}); update README.md after adding/removing a module or changing \
         a module's cost()"
    );

    // The heading check alone proved insufficient: the intro blurb and the
    // `hse modules` usage comment each carry their own hand-written count and
    // both rotted to a stale figure while the heading stayed correct. Sweep
    // EVERY "<digits> modules" mention in the README against the registry.
    let stale: Vec<&str> = readme
        .lines()
        .filter(|line| {
            let mut rest = *line;
            while let Some(pos) = rest.find(" modules") {
                let prefix = &rest[..pos];
                let digits: String = prefix
                    .chars()
                    .rev()
                    .take_while(char::is_ascii_digit)
                    .collect();
                if !digits.is_empty() {
                    let count: usize = digits.chars().rev().collect::<String>().parse().unwrap();
                    // Only headline totals can match the registry; sub-counts
                    // ("81 free", …) are smaller and skipped via a floor.
                    if count > n / 2 && count != n {
                        return true;
                    }
                }
                rest = &rest[pos + " modules".len()..];
            }
            false
        })
        .collect();
    assert!(
        stale.is_empty(),
        "README cites a stale module total (registry holds {n}): {stale:?}"
    );
}

/// The README's "Deterministic correlator: N rules (E entity + R graph-aware
/// relation)" line is hand-maintained prose and had already drifted once
/// (stated 108 while the registry held 109, immediately after a rule was
/// added and only `docs/ARCHITECTURE_AUDIT.md` was reconciled). Tie it to
/// [`huntsman_search_engine::core::correlator::rule_counts`] so it can't
/// silently rot again — the same no-silent-drift guard as
/// `readme_module_overview_count_matches_registry`.
#[test]
fn readme_correlator_rule_count_matches_registry() {
    let readme = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("README.md must exist");
    let (entity, relation) = huntsman_search_engine::core::correlator::rule_counts();
    let total = entity + relation;
    let needle = format!(
        "Deterministic correlator: {total} rules ({entity} entity + {relation} graph-aware relation)"
    );
    assert!(
        readme.contains(&needle),
        "README must cite the live correlator rule split ({needle:?}); update \
         README.md (and docs/ARCHITECTURE_AUDIT.md) after adding/removing a rule"
    );
}

/// Runtime AI-independence guard (the `RUNTIME_INDEPENDENCE` charter): the
/// compiled binary must carry NO AI / ML / LLM / cloud-inference / vector /
/// embedding dependency, so every runtime capability is deterministic Rust that
/// reproduces identically on Termux aarch64 (no root), Linux and CI with no AI
/// available. AI is a development-time accelerator only. This turns the principle
/// into a mechanical CI check — adding e.g. `candle`, `onnxruntime`, an LLM SDK,
/// `tokenizers`, or `qdrant-client` fails here. External OSINT *data* APIs
/// (registries, breach corpora, geocoders) are data sources, not AI services,
/// and are deliberately unaffected. See `docs/RUNTIME_INDEPENDENCE.md`.
#[test]
fn runtime_carries_no_ai_ml_inference_dependency() {
    let lock = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
        .expect("Cargo.lock must exist");

    // Substrings unambiguous enough that no non-AI crate name contains them.
    const DENY_SUBSTR: &[&str] = &[
        "candle-",
        "onnx",
        "openai",
        "anthropic",
        "huggingface",
        "hf-hub",
        "tokenizers",
        "tiktoken",
        "fastembed",
        "text-embeddings",
        "qdrant",
        "pinecone",
        "weaviate",
        "milvus",
        "chromadb",
        "ollama",
        "llama",
        "langchain",
        "llm-chain",
        "rust-bert",
        "instant-distance",
        "tensorflow",
        "torch-sys",
    ];
    // Exact crate names too short/common to match safely as substrings.
    const DENY_EXACT: &[&str] = &[
        "tch",
        "burn",
        "tract",
        "ort",
        "rten",
        "llm",
        "lance",
        "lancedb",
        "hnsw",
        "usearch",
        "faiss",
        "dfdx",
        "smartcore",
        "linfa",
        "genai",
        "kalosm",
        "rig-core",
        "mistralai",
        "mistral-rs",
    ];

    let offenders: Vec<&str> = lock
        .lines()
        .filter_map(|l| {
            l.strip_prefix("name = \"")
                .and_then(|s| s.strip_suffix('"'))
        })
        .filter(|name| DENY_SUBSTR.iter().any(|d| name.contains(d)) || DENY_EXACT.contains(name))
        .collect();

    assert!(
        offenders.is_empty(),
        "RUNTIME_INDEPENDENCE violation — AI/ML/inference crate(s) entered the \
         dependency tree: {offenders:?}. HSE's runtime must stay deterministic \
         Rust with no AI / LLM / vector / embedding dependency (AI is a \
         development-time accelerator only). See docs/RUNTIME_INDEPENDENCE.md."
    );
}

/// Every coarse IP/WiFi-geolocation provider must gate its emitted coordinates
/// on `is_plausible_provider_coord`, not the precise `is_valid_coords`.
///
/// These sources resolve to a city/region centroid and emit a sub-degree
/// null-island *jitter band* (`0.005,0.005`-style "no fix" placeholder) when
/// they have no location. `is_valid_coords` rejects only exact `0,0`, so gating
/// a coarse provider on it lets that placeholder through as a high-confidence
/// `geoint` fix that poisons the AU-014/AU-017 geo-cluster correlator —
/// precisely the drift that slipped into `ip_whois_geo` until it was corrected.
/// Pin the categorization here so a new (or edited) coarse provider can't
/// silently pick the wrong validator.
#[test]
fn coarse_ip_geo_providers_use_the_provider_coord_gate() {
    const COARSE_PROVIDERS: &[&str] = &[
        "ip_geo",
        "ipinfo",
        "ip2location",
        "ipquery",
        "ip_whois_geo",
        "wigle",
    ];
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/modules");
    let mut offenders = Vec::new();
    for provider in COARSE_PROVIDERS {
        // Modules may be a flat file (`{provider}.rs`) or a directory module
        // (`{provider}/mod.rs`). For directory modules we concatenate all
        // non-test source files so the gate check covers the whole module.
        let flat = root.join(format!("{provider}.rs"));
        let dir = root.join(provider);
        let src = if flat.exists() {
            fs::read_to_string(&flat)
                .unwrap_or_else(|_| panic!("coarse provider {provider} missing at {flat:?}"))
        } else if dir.is_dir() {
            // Concatenate the module's PRODUCTION source. Read in a deterministic
            // (sorted) order and strip each file's own `mod tests` section BEFORE
            // concatenating: for a multi-file module whose gate call lives outside
            // `mod.rs` (e.g. wigle's is in `emit.rs`), a `mod.rs` concatenated
            // ahead of it would otherwise be truncated away by the later
            // `split("mod tests")`, making this guard pass or fail on
            // `fs::read_dir` order alone — green locally yet red in CI.
            let mut paths: Vec<_> = fs::read_dir(&dir)
                .unwrap_or_else(|_| panic!("cannot read dir {dir:?}"))
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
                .collect();
            paths.sort();
            let mut combined = String::new();
            for p in paths {
                // `tests.rs` is pure unit-test code — never part of the gate.
                if p.file_name().and_then(|n| n.to_str()) == Some("tests.rs") {
                    continue;
                }
                if let Ok(s) = fs::read_to_string(&p) {
                    // Drop this file's own `#[cfg(test)] mod tests` tail so a
                    // `use is_valid_coords` in a unit test can't satisfy the gate.
                    combined.push_str(s.split("mod tests").next().unwrap_or(&s));
                    combined.push('\n');
                }
            }
            combined
        } else {
            panic!("coarse provider {provider} missing at {flat:?}");
        };
        // Flat-file modules keep their test tail here (directory modules were
        // already stripped per-file above; this is a no-op for them).
        let prod = src.split("mod tests").next().unwrap_or(&src);
        // The gate is satisfied either by calling `is_plausible_provider_coord`
        // directly OR by building the entity through `coarse_provider_coords`,
        // which applies that exact gate internally (ipinfo/ip2location/
        // ipquery were consolidated onto the helper).
        let gated =
            prod.contains("is_plausible_provider_coord") || prod.contains("coarse_provider_coords");
        if !gated {
            offenders.push(*provider);
        }
    }
    assert!(
        offenders.is_empty(),
        "coarse IP/WiFi-geo provider(s) {offenders:?} do not gate coordinates on \
         is_plausible_provider_coord / coarse_provider_coords — a null-island placeholder could become a \
         false geoint fix. Use crate::util::geo::is_plausible_provider_coord."
    );
}

/// CONVENTIONS.md §2 — hubs declare, never house. Outside `#[cfg(test)]`
/// code, a module body belongs in its own file: `pub mod name;` in the hub,
/// code in `name.rs`. This pin turns the convention into a mechanical check
/// (the same treatment the AI-independence charter got), so the consistency
/// bought by extracting every inline module from core/mod.rs and util/mod.rs
/// can't erode one "harmless exception" at a time. The only permitted inline
/// bodies are trivial wrappers that would be NOISE as files, allow-listed
/// here by (path-suffix, module-name) so adding one is a reviewed decision.
#[test]
fn no_inline_module_bodies_outside_allowed_exceptions() {
    // (path suffix, module name) → why it is legitimately inline.
    const ALLOWED: &[(&str, &str)] = &[
        // 3-line include! wrapper for the build.rs-generated source manifest.
        ("src/lib.rs", "source_manifest"),
        // 5-line path-constants shim local to the oathnet util.
        ("src/util/oathnet.rs", "paths"),
    ];

    fn visit(dir: &Path, offenders: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, offenders);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs")
                || path.file_name().is_some_and(|n| n == "tests.rs")
            {
                continue;
            }
            let content = fs::read_to_string(&path).unwrap();
            let rel = path.display().to_string().replace('\\', "/");
            // Once the first `#[cfg(test)]` appears, the rest of the file is
            // test scaffolding by this tree's layout convention (test modules
            // come last) — same simplification the layering scanner uses.
            let mut in_test = false;
            for (i, line) in content.lines().enumerate() {
                let t = line.trim();
                if t == "#[cfg(test)]" {
                    in_test = true;
                }
                if in_test || !t.ends_with('{') {
                    continue;
                }
                let rest = ["pub(crate) mod ", "pub(super) mod ", "pub mod ", "mod "]
                    .iter()
                    .find_map(|p| t.strip_prefix(p));
                let Some(rest) = rest else { continue };
                let Some(name) = rest.strip_suffix('{').map(str::trim) else {
                    continue;
                };
                if name == "tests"
                    || ALLOWED
                        .iter()
                        .any(|(suf, m)| rel.ends_with(suf) && *m == name)
                {
                    continue;
                }
                offenders.push(format!("{rel}:{}: inline `mod {name}`", i + 1));
            }
        }
    }

    let mut offenders = Vec::new();
    visit(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut offenders,
    );
    assert!(
        offenders.is_empty(),
        "inline module bodies outside the allow-list (CONVENTIONS.md §2 — \
         move the body to its own file, or allow-list a trivial wrapper \
         with a justification): {offenders:#?}"
    );
}

/// Every rule wired into RULES or RELATION_RULES must have at least one
/// positive firing test in the correlator test suite. A dispatched rule with
/// no firing test compiles, is called on every scan, but silently produces no
/// correlation even when its trigger condition is met — indistinguishable from
/// a correctly-absent result. Two detection modes are accepted:
///
/// - **Direct**: the rule function name appears in the corpus, AND within ±15
///   lines there is a `len(), N` assertion where N > 0 (the canonical
///   positive-result form used throughout the correlator test suite).
/// - **Indirect**: the quoted `"AU-NNN"` rule-id appears on a line that also
///   contains `assert`/`.unwrap()`/`.expect()`/`contains(` (covers rules
///   verified through `correlate_entities()` or `Correlator::run()` rather
///   than a direct function call).
#[test]
fn every_dispatched_correlation_rule_has_a_firing_test() {
    let mod_src = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/core/correlator/mod.rs"
    ))
    .expect("correlator/mod.rs must exist");

    let corpus = correlator_tests_source();
    let corpus_lines: Vec<&str> = corpus.lines().collect();

    // Extract dispatched rule function names from the RULES / RELATION_RULES
    // arrays: each element is a bare identifier on its own indented line.
    let dispatched: Vec<String> = mod_src
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("rule_au_"))
        .map(|l| {
            l.chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect()
        })
        .collect();

    assert!(
        !dispatched.is_empty(),
        "parse failure: no dispatched rules found"
    );

    let missing: Vec<&str> = dispatched
        .iter()
        .filter(|rule| {
            // (a) Direct: function name in corpus, positive len assertion nearby.
            let direct = corpus_lines.iter().enumerate().any(|(i, line)| {
                if !line.contains(rule.as_str()) {
                    return false;
                }
                let start = i.saturating_sub(15);
                let end = (i + 15).min(corpus_lines.len());
                corpus_lines[start..end]
                    .iter()
                    .any(|ctx| has_nonzero_len_assert(ctx))
            });
            if direct {
                return false;
            }
            // (b) Indirect: quoted "AU-NNN" id on a line with an assertion form.
            let id_str = rule
                .strip_prefix("rule_au_")
                .and_then(|r| r.split('_').next())
                .and_then(|n| n.parse::<u32>().ok())
                .map(|n| format!("\"AU-{n:03}\""));
            let indirect = id_str.as_deref().is_some_and(|id| {
                corpus_lines.iter().any(|l| {
                    l.contains(id)
                        && (l.contains("assert")
                            || l.contains(".unwrap()")
                            || l.contains(".expect(")
                            || l.contains("contains("))
                })
            });
            !indirect
        })
        .map(String::as_str)
        .collect();

    assert!(
        missing.is_empty(),
        "dispatched correlation rule(s) with no positive firing fixture in the \
         test suite — add a test that calls the rule function directly (or \
         exercises it via correlate_entities/Correlator::run) and asserts at \
         least one correlation is produced: {missing:?}"
    );
}

#[test]
fn every_literal_constructed_entity_kind_is_declared_in_produces() {
    // FORWARD producer-graph accuracy — the dual of smoke.rs's
    // `every_declared_produced_pivot_has_a_consumer`. A module that mints an
    // entity via a literal `Entity::new(EntityKind::X, …)` must declare `X` in
    // `produces()`, so the capability map and consumer-matching can never
    // silently under-represent what the module actually emits. This locks in the
    // produces()-accuracy audit (crtsh / oathnet_pro / see_know et al.).
    //
    // SOUND, not complete — by construction it raises only true positives:
    //   * It inspects only LITERAL constructions. A module that builds entities
    //     with a *variable* kind (wigle / search_engines classify at runtime, the
    //     core `classifier` extracts dynamically) is not checked here — a miss,
    //     never a false alarm.
    //   * The terminal catch-all `EntityKind::Other(_)` is excluded: it is
    //     non-pivotable (`TargetKind::from_entity_kind` → None) and by universal
    //     convention declared by no module — exactly like the Credential/Password
    //     terminals the reverse guard special-cases.
    // Coverage floors keep it from rotting into a vacuous pass.
    use huntsman_search_engine::core::entity::EntityKind;
    use huntsman_search_engine::modules::registry;

    // PascalCase variant identifier for a declared kind, e.g. `IpAddress`; for the
    // tuple variant `Other(String)` the leading `Other` before `(`.
    fn variant_name(k: &EntityKind) -> String {
        let dbg = format!("{k:?}");
        match dbg.split_once('(') {
            Some((head, _)) => head.to_string(),
            None => dbg,
        }
    }

    // Every `Entity::new( EntityKind::<Ident>` variant token in one source file,
    // tolerating whitespace/newlines between `new(` and the kind path.
    fn constructed_kinds(src: &str) -> Vec<String> {
        const NEEDLE: &str = "Entity::new(";
        let mut out = Vec::new();
        let mut rest = src;
        while let Some(p) = rest.find(NEEDLE) {
            rest = &rest[p + NEEDLE.len()..];
            if let Some(tail) = rest.trim_start().strip_prefix("EntityKind::") {
                let ident: String = tail
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !ident.is_empty() {
                    out.push(ident);
                }
            }
        }
        out
    }

    fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && p.file_name().is_some_and(|n| n != "tests.rs")
            {
                out.push(p);
            }
        }
    }

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src/modules");
    let mut scanned_modules = 0usize;
    let mut kinds_checked = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for m in registry() {
        let name = m.name();
        let declared: std::collections::HashSet<String> =
            m.produces().iter().map(variant_name).collect();

        // name → src/modules/<name>/ (dir) or src/modules/<name>.rs (file).
        // Core-hosted modules (e.g. the universal `classifier`) live outside this
        // tree and build dynamically — no literal constructions to check, so they
        // are skipped; the coverage floor below stops that from going vacuous.
        let dir = Path::new(root).join(name);
        let file = Path::new(root).join(format!("{name}.rs"));
        let mut files = Vec::new();
        if dir.is_dir() {
            rs_files(&dir, &mut files);
        } else if file.is_file() {
            files.push(file);
        } else {
            continue;
        }
        scanned_modules += 1;

        for path in files {
            let Ok(src) = fs::read_to_string(&path) else {
                continue;
            };
            for ident in constructed_kinds(&src) {
                if ident == "Other" {
                    continue; // terminal catch-all, never declared by convention
                }
                kinds_checked += 1;
                if !declared.contains(&ident) {
                    let v = format!(
                        "{name} constructs EntityKind::{ident} (literal Entity::new) but \
                         does not declare it in produces()  [{}]",
                        path.display()
                    );
                    if !violations.contains(&v) {
                        violations.push(v);
                    }
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "module(s) mint (via literal Entity::new) an EntityKind absent from \
         produces() — add it to the module's produces() so the capability graph \
         reflects what it emits:\n  {}",
        violations.join("\n  ")
    );
    // Floors: the source audit mapped 160 modules and ~450 distinct literal
    // EntityKind constructions. Keep generous lower bounds so a refactor that
    // breaks the name→file map or the scanner can't make this guard pass vacuously.
    assert!(
        scanned_modules >= 120,
        "expected to map most modules to source, only mapped {scanned_modules}"
    );
    assert!(
        kinds_checked >= 300,
        "expected many literal EntityKind constructions, saw {kinds_checked}"
    );
}

#[test]
fn every_checked_feature_flag_is_registered() {
    // Toggle contract (checked ⊆ registered): a `"feature.X"` switch read
    // anywhere OUTSIDE the settings module must name a key registered in
    // FEATURE_TOGGLES — otherwise the operator can never see or control it (the
    // web/CLI toggle catalogue, `hse config`, and the write guard all gate on
    // `is_feature_key`/FEATURE_TOGGLES). Sound by construction: it scans string
    // literals only, and skips `src/util/settings` (the registry + the named
    // constants live there, so their literals are registration, not usage). The
    // reverse direction (no registered toggle is dead) is covered by the read
    // sites every FEATURE_TOGGLES key carries plus
    // `feature_toggles_length_matches_registration`.
    use huntsman_search_engine::util::settings::is_feature_key;

    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.ends_with("util/settings") {
                    continue; // the registry + const defs — literals here are registration
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && p.file_name().is_some_and(|n| n != "tests.rs")
            {
                out.push(p);
            }
        }
    }

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut files = Vec::new();
    walk(Path::new(root), &mut files);

    const NEEDLE: &str = "\"feature.";
    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for path in &files {
        let Ok(src) = fs::read_to_string(path) else {
            continue;
        };
        let mut rest = src.as_str();
        while let Some(p) = rest.find(NEEDLE) {
            rest = &rest[p + 1..]; // step past the opening quote
            let key: String = rest.chars().take_while(|c| *c != '"').collect();
            // Only well-formed `feature.<ident>` keys (ignore a bare prefix).
            if key.len() > "feature.".len()
                && key[8..].chars().all(|c| c.is_ascii_lowercase() || c == '_')
            {
                checked += 1;
                if !is_feature_key(&key) {
                    let v = format!("{key} [{}]", path.display());
                    if !violations.contains(&v) {
                        violations.push(v);
                    }
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "feature flag(s) read via a \"feature.*\" literal but NOT registered in \
         FEATURE_TOGGLES — the operator can't toggle them; register each:\n  {}",
        violations.join("\n  ")
    );
    // Floor: the codebase checks several literal feature flags (regional, recall,
    // auto_update, update_notify, …); a refactor that breaks the scan can't make
    // this guard vacuously pass.
    assert!(
        checked >= 3,
        "expected several literal feature.* checks outside settings, saw {checked}"
    );
}

// ── Canonical entity classifier convergence tests ─────────────────────────────
// Phase 1, item 1: `core::classifier` owns the canonical embedded-entity locators;
// `util::entity_extractor` re-uses them. These tests assert that the re-exported
// patterns are identical to the canonical ones and that classification is
// deterministic.

use huntsman_search_engine::core::classifier as core_classifier;
use huntsman_search_engine::util::entity_extractor::EntityKind;
use huntsman_search_engine::util::entity_extractor::classifier::EntityClassifier;
use huntsman_search_engine::util::entity_extractor::patterns;

#[test]
fn entity_extractor_reuses_core_patterns() {
    // The patterns re-exported by `util::entity_extractor::patterns` must be the
    // *same* `Regex` instances as the canonical `core::classifier` patterns.
    assert!(std::ptr::addr_eq(
        &*patterns::EMAIL_PATTERN,
        &*core_classifier::EMAIL_RE
    ));
    assert!(std::ptr::addr_eq(
        &*patterns::IPV4_PATTERN,
        &*core_classifier::IPV4_RE
    ));
    assert!(std::ptr::addr_eq(
        &*patterns::DOMAIN_PATTERN,
        &*core_classifier::DOMAIN_RE
    ));
    assert!(std::ptr::addr_eq(
        &*patterns::URL_PATTERN,
        &*core_classifier::URL_RE
    ));
}

#[test]
fn core_and_extractor_classifiers_agree_on_canonical_values() {
    let classifier = EntityClassifier::new().expect("should succeed");

    let cases: &[(&str, EntityKind)] = &[
        ("test@example.com", EntityKind::Email),
        ("https://example.com/path", EntityKind::Url),
        ("192.168.1.1", EntityKind::Ipv4),
        ("example.com", EntityKind::Domain),
    ];

    for (value, expected) in cases {
        assert_eq!(
            classifier.classify(value, None),
            *expected,
            "classifier mismatch for {value}"
        );
        let core = core_classifier::classify(value);
        assert_eq!(
            core.value, *value,
            "core classifier must preserve the raw value"
        );
        assert!(
            core.confidence > 0.0,
            "core classifier must assign non-zero confidence to {value}"
        );
    }
}

#[test]
fn core_extract_is_deterministic() {
    let text = "Contact: alice@example.com or https://example.com and 8.8.8.8. \
                Also example.org and @handle.";
    let first = core_classifier::extract(text);
    let second = core_classifier::extract(text);
    assert_eq!(
        first, second,
        "core::classifier::extract must be deterministic for the same input"
    );
    // Smoke-check that the canonical locators actually found the expected entities.
    assert!(
        first
            .iter()
            .any(|c| c.kind == huntsman_search_engine::core::entity::EntityKind::Email),
        "expected an email entity"
    );
    assert!(
        first
            .iter()
            .any(|c| c.kind == huntsman_search_engine::core::entity::EntityKind::Url),
        "expected a URL entity"
    );
    assert!(
        first
            .iter()
            .any(|c| c.kind == huntsman_search_engine::core::entity::EntityKind::IpAddress),
        "expected an IP entity"
    );
}
