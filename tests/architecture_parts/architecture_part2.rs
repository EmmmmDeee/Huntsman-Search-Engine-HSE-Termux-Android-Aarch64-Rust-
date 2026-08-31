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
    // Locations, owner-published emails → T1589.002, employer Organisation →
    // T1591.002. T1591.004 (Identify Roles) dropped — Gravatar profiles carry
    // no role information.
    assert_eq!(
        techniques("gravatar"),
        vec!["T1591.001", "T1589.002", "T1589.003", "T1591.002"],
        "gravatar → Physical Locations + Email Addresses + Employee Names + Business Relationships (no roles)"
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
    // T1591.002 Business Relationships, and queries its own crowdsourced
    // open WiFi/cell/Bluetooth database → T1596 Search Open Technical
    // Databases (the same mechanism mylnikov/opencellid claim it for).
    assert_eq!(
        techniques("wigle"),
        vec!["T1591.001", "T1591.002", "T1596"],
        "wigle → Physical Locations + Business Relationships (carrier/operator) + Open Technical Databases"
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
    // → T1589.003 Employee Names, which the Geo default omits. Also emits a
    // DeviceId (camera hardware serial) → T1592.001 Hardware, the same
    // mapping signal_radar uses for a device hardware identifier.
    assert_eq!(
        techniques("exif_geo"),
        vec!["T1589.003", "T1591.001", "T1592.001"],
        "exif_geo → Employee Names (EXIF author) + Physical Locations (GPS) + Hardware (camera serial)"
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
    // WiFi AP MAC addresses → T1592 Host Information (hardware identification),
    // and its WiGLE-detail lookup phase queries the same crowdsourced open
    // WiFi/cell database the sibling wigle/mylnikov/opencellid modules claim
    // T1596 for.
    assert_eq!(
        techniques("wifi_intel"),
        vec!["T1591.001", "T1592", "T1596"],
        "wifi_intel → Physical Locations + Host Information (AP MAC addresses) + Open Technical Databases"
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

    // ipqs: existing override adds T1589 + T1589.002 for Phone and Email scoring,
    // and T1591.002 for the ISP/organization/carrier Organisation pivot.
    assert_eq!(
        techniques("ipqs"),
        vec![
            "T1589",
            "T1589.002",
            "T1590.005",
            "T1591.002",
            "T1596.005",
            "T1597.001"
        ],
        "ipqs → Victim Identity (Phone) + Email Addresses + IP Addresses + \
         Business Relationships (ISP/org) + Scan Databases + Threat Intel Vendors"
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
