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
fn core_does_not_import_util_directly() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let v = scan_for_violations(&dir, &["crate::util"]);
    let allowed: Vec<String> = v
        .into_iter()
        .filter(|line| {
            !line.contains("util::proxy::ProxyPool")
                && !line.contains("util::key_pool")
                && !line.contains("util::key_roi")
                && !line.contains("util::geohash")
                // Pure, offline computational geometry (convex hull, geometric
                // median, …) — the geo correlation rules' location estimators.
                // Same justification as `util::geohash`: no I/O, no deps.
                && !line.contains("util::geometry")
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
                // Persistent capability toggles (universal toggleability): the
                // engine's module gate reads `module.<name>` on/off.
                && !line.contains("util::settings::get_bool")
                // Pure, dependency-free ABN/ACN checksums — used by
                // `TargetKind::detect` to tell a registry number from a phone
                // number in the unified-scan auto-detector.
                && !line.contains("util::abn::is_valid_abn")
                && !line.contains("util::abn::is_valid_acn")
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
                // Pure, dependency-free digit-only normaliser — the same leaf
                // category as the ABN checksums above; `core::scan` uses it in
                // the target auto-detector to strip separators from a candidate
                // phone/registry number. No state, no I/O, no upward deps.
                && !line.contains("util::str_util::ascii_digits")
                // Pure, dependency-free offline city→coordinate lookup table
                // (no I/O, no network). The engine's address_to_coords_pass uses
                // it to convert Address entities into Coordinates for geo correlation.
                && !line.contains("util::city_coords::city_coords")
                // Pure, dependency-free email classifier (role local-part + a
                // static CDN/registrar/proxy mail-domain set; no I/O, no deps) —
                // same leaf category as `address_au::state_code`. AU-061 uses it
                // to exclude privacy-proxy / registrar registrant mailboxes
                // (`abuse@godaddy.com`, `*@whoisguard.com`) from shared-registrant
                // co-ownership, so a shared proxy can't mass-link unrelated domains.
                && !line.contains("util::domains::is_infrastructure_email")
                // Pure, dependency-free eTLD+1 reducer (label split + a static
                // multi-label-suffix table; no I/O) — same leaf category as
                // `is_infrastructure_email`. AU-062 uses it to require ≥2 DISTINCT
                // registrable domains on a shared IP, so a single site's own
                // subdomains (co-residence) don't read as cross-site co-ownership.
                && !line.contains("util::domains::registrable_domain")
                // Pure privacy-proxy / WHOIS-redaction guard (marker table +
                // `is_infrastructure_email`; no I/O). Extracted from AU-061's
                // local definition into util so `core::relation::builders::
                // derive_co_ownership` (R13) can share the exclusion logic
                // without duplicating it: one definition, two callers, no drift.
                && !line.contains("util::domains::is_proxy_registrant")
        })
        .collect();
    assert!(
        allowed.is_empty(),
        "core/ must not import util/ (except proxy::ProxyPool on ModuleContext).\nViolations:\n{}",
        allowed.join("\n")
    );
}

#[test]
fn core_does_not_import_modules() {
    // core is module-agnostic: the engine drives modules through the registry
    // and the `core::hooks` function-pointer registry, never the reverse
    // (PROBLEM_TREE T1.4). The one legal `modules → core` hook edge is the
    // install in `modules::registry`; `core` itself names no `crate::modules`.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let v = scan_for_violations(&dir, &["crate::modules"]);
    assert!(
        v.is_empty(),
        "core/ must not import modules/ — invert via `core::hooks`.\nViolations:\n{}",
        v.join("\n")
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
/// Every registered module must appear in `docs/MODULES.md`. The catalogue
/// section there is generated from `hse modules --json`, but nothing stops a
/// future contributor adding a module and forgetting to regenerate it — the
/// doc had drifted to describe only 31 of 85 modules (and listed ~11 that no
/// longer existed) before this guard. A missing module name here fails CI,
/// keeping the operator-facing catalogue honest.
#[test]
fn modules_md_lists_every_registered_module() {
    let doc = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/MODULES.md"))
        .expect("docs/MODULES.md must exist");
    let modules = huntsman_search_engine::modules::registry();
    let missing: Vec<&str> = modules
        .iter()
        .map(|m| m.name())
        .filter(|name| {
            // Match the `\`name\`` form used in the generated table so a
            // substring of another name can't accidentally satisfy it.
            !doc.contains(&format!("`{name}`"))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "modules missing from docs/MODULES.md (regenerate the catalogue from \
         `hse modules --json`): {missing:?}"
    );
}

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

    // Code repositories — NOT social media (T1593.001).
    for name in ["github_user", "crates_io", "npm_author"] {
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
    // DnsRecon family — each its specific technique, not the whole bundle.
    assert_eq!(techniques("crtsh"), vec!["T1596.003"]); // Digital Certificates
    assert_eq!(techniques("cert_intel"), vec!["T1596.003"]);
    assert_eq!(techniques("whois"), vec!["T1596.002"]); // WHOIS
    assert_eq!(techniques("rdap_domain"), vec!["T1596.002"]);
    assert_eq!(techniques("dns_intel"), vec!["T1590.002"]); // DNS
    assert_eq!(techniques("securitytrails"), vec!["T1596.001"]); // Passive DNS
    assert_eq!(techniques("hackertarget"), vec!["T1590.002", "T1596.001"]);
    assert_eq!(techniques("subdomain_takeover"), vec!["T1590.001"]); // Domain Properties
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
    // coordinates and city as physical location (T1591.001).
    assert_eq!(
        techniques("censys"),
        vec!["T1590.005", "T1596.005", "T1591.001"],
        "censys → scan-db + IP info + physical location"
    );

    // ipapi is a passive geolocation API identical in surface to the geo-5 above:
    // IP address info + physical location + ISP/operator organisation.
    assert_eq!(
        techniques("ipapi"),
        vec!["T1590.005", "T1591.001", "T1591.002"],
        "ipapi → IP Addresses + Physical Locations + Business Relationships"
    );
    assert!(
        !techniques("ipapi").contains(&"T1596.005"),
        "ipapi is a passive geo API, not a scan database (T1596.005)"
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

    // DeHashed + IntelX: Breach category covers Credentials (T1589.001) and
    // Email Addresses (T1589.002) but both modules also emit real-name Person
    // entities → T1589.003 Employee Names must be declared explicitly.
    for name in ["dehashed", "intelx"] {
        assert_eq!(
            techniques(name),
            vec!["T1589.001", "T1589.002", "T1589.003"],
            "{name} → Credentials + Email Addresses + Employee Names"
        );
        assert!(
            techniques(name).contains(&"T1589.003"),
            "{name} emits Person entities; must claim Employee Names (T1589.003)"
        );
    }

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

    // criminal_ip: existing override adds T1591.002 for ASN operator Organisation.
    assert_eq!(
        techniques("criminal_ip"),
        vec!["T1590.005", "T1591.002", "T1596.005", "T1597.001"],
        "criminal_ip → IP Addresses + Business Relationships + Scan Databases + Threat Intel Vendors"
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
        "ipapi",
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
    // future category change (or a regression of the hudsonrock/qld_unclaimed
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

    // The core person-locators MUST be in focus (incl. the two whose categories
    // were corrected: hudsonrock → Breach, qld_unclaimed → People).
    for name in [
        "employer_pivot",  // People — where they work / ability to pay
        "qld_unclaimed",   // People — name → government register + address
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
        "HUNTSMAN_ALIENVAULT_KEY",
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

    let body = src.split_once("fn registry(").map_or("", |(_, b)| b);

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
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/correlator/rules");
    let mut out = String::new();
    let mut files: Vec<_> = fs::read_dir(&dir)
        .expect("correlator/rules/ must exist")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort(); // deterministic concatenation order
    for p in files {
        out.push_str(&fs::read_to_string(&p).expect("rule file readable"));
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
        "ipapi",
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
        // which applies that exact gate internally (ipinfo/ipapi/ip2location/
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
