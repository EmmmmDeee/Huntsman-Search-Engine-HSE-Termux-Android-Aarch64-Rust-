use super::*;

struct StubModule;

impl ModuleSpec for StubModule {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn priority(&self) -> u8 {
        42
    }

    fn consumes(&self) -> Vec<&'static str> {
        vec!["domain"]
    }

    fn produces(&self) -> Vec<&'static str> {
        vec!["subdomain"]
    }
}

#[test]
fn reachable_catalog_is_unique_and_nonempty() {
    let modules = reachable_modules();
    assert!(!modules.is_empty());
    for (index, module) in modules.iter().enumerate() {
        assert!(!module.name.is_empty());
        assert!(!module.command.is_empty());
        if module.network && module.category != ModuleCategory::Other {
            assert!(
                !module.attack_techniques.is_empty(),
                "network collector {} has no explicit ATT&CK mapping",
                module.name
            );
        }
        for id in module.attack_techniques {
            let technique = crate::attack::technique(id)
                .unwrap_or_else(|| panic!("{} maps to unknown ATT&CK id {id}", module.name));
            assert!(
                technique.tactics.contains(&"reconnaissance"),
                "{} maps outside Reconnaissance: {id}",
                module.name
            );
        }
        assert!(
            !modules[..index]
                .iter()
                .any(|prior| prior.name == module.name),
            "duplicate reachable module {}",
            module.name
        );
    }
}

#[test]
fn reachable_catalog_exposes_expected_collection_categories() {
    let modules = reachable_modules();
    let category = |name: &str| {
        modules
            .iter()
            .find(|module| module.name == name)
            .map(|module| module.category)
    };
    assert_eq!(category("web_query"), Some(ModuleCategory::Search));
    assert_eq!(category("hibp"), Some(ModuleCategory::Breach));
    assert_eq!(category("crtsh"), Some(ModuleCategory::DnsRecon));
    assert_eq!(category("github_user"), Some(ModuleCategory::Social));
    assert_eq!(category("email_parse"), Some(ModuleCategory::Other));

    let techniques = |name: &str| {
        modules
            .iter()
            .find(|module| module.name == name)
            .map(|module| module.attack_techniques)
    };
    assert_eq!(techniques("github_user"), Some(&["T1593.003"][..]));
    assert_eq!(techniques("crtsh"), Some(&["T1596.003"][..]));
    assert_eq!(techniques("dns"), Some(&["T1590.001"][..]));
    assert_eq!(techniques("web_server"), Some(&[][..]));
}

#[test]
fn every_source_a_lookup_records_is_a_reachable_module() {
    // The label each lookup leg records its outcome and evidence under. A leg missing from
    // the catalogue is absent from `modules`, `sf -M`, the web UI and the ATT&CK coverage.
    let named = [
        crate::internetdb::SOURCE,
        crate::ripestat::SOURCE,
        crate::greynoise::SOURCE,
        crate::abuseipdb::SOURCE,
        crate::virustotal::SOURCE,
        crate::hunter::SOURCE,
        crate::numverify::SOURCE,
        crate::phone_intl::SOURCE,
        crate::phone_intl::AU_SOURCE,
        crate::phone_intl::NANP_SOURCE,
        crate::phone_intl::AE_SOURCE,
        crate::gravatar::SRC,
        crate::duolingo::SRC,
        crate::openpgp_keys::SRC,
        crate::github_user::SRC,
        crate::npm_author::SRC,
        crate::crates_io::SRC,
        crate::hacker_news::SRC,
        crate::lobsters::SRC,
        crate::chess_com::SRC,
        crate::lichess::SRC,
        crate::docker_hub_user::SRC,
        crate::codeberg_user::SRC,
        crate::devto_user::SRC,
        crate::huggingface_user::SRC,
        crate::codewars_user::SRC,
        crate::bluesky_user::SRC,
        crate::mastodon_user::SRC,
        crate::keybase::SRC,
        crate::blockchain::SOURCE,
        crate::base_rpc::SOURCE,
        crate::eth_rpc::SOURCE,
        crate::solana_rpc::SOURCE,
        crate::itunes::SOURCE,
        crate::hibp::ACCOUNT_SOURCE,
        crate::stolen_tax::SOURCE,
        crate::oathnet::SOURCE,
        crate::dehashed::COLLECTOR_ID,
        crate::oui::SOURCE,
        crate::wigle::SOURCE,
        crate::wigle::BLUETOOTH_SOURCE,
        crate::asic_orgs::SRC,
        crate::abn_lookup::SOURCE,
    ];
    let registry = crate::indicator_legs::SOURCES
        .iter()
        .map(|source| source.api.source);
    let missing: Vec<&str> = named
        .into_iter()
        .chain(registry)
        .filter(|label| {
            !reachable_modules()
                .iter()
                .any(|module| module.name == *label)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "lookup legs missing from the module catalogue: {missing:?}"
    );
}

#[test]
fn serde_forms_are_the_pinned_wire_names() {
    for (cost, name) in [
        (ModuleCost::Free, "free"),
        (ModuleCost::KeyGated, "key_gated"),
        (ModuleCost::Paid, "paid"),
    ] {
        let json = serde_json::to_string(&cost).expect("json");
        assert_eq!(json.trim_matches('"'), name);
    }
    let json = serde_json::to_string(&ModuleCategory::DnsRecon).expect("json");
    assert_eq!(json.trim_matches('"'), "dns_recon");
}

#[test]
fn default_info_and_descriptor_are_consistent() {
    let info = StubModule.info();
    assert_eq!(info.name, "stub");
    assert_eq!(info.priority, 42);
    assert_eq!(info.cost, ModuleCost::Free);
    assert_eq!(info.category, ModuleCategory::Other);
    assert_eq!(info.provider.access_class, AccessClass::Keyless);
    assert_eq!(
        info.provider.rate_limit_policy,
        RateLimitPolicy::SharedHostCircuitBreaker
    );
    assert_eq!(info.provider.supported_seed_types, vec!["domain"]);
}

#[test]
fn cost_parser_is_strict_and_unknown_gate_is_conservative() {
    assert_eq!(parse_cost_per_request("0.0025"), Some(0.0025));
    assert_eq!(parse_cost_per_request("-1"), None);
    assert_eq!(parse_cost_per_request("NaN"), None);

    let mut descriptor = derive_default_provider_descriptor(&StubModule);
    descriptor.access_class = AccessClass::Paid;
    descriptor.cost_model = CostModel::Unknown;
    assert!(unknown_cost_paid_provider_blocked(
        &descriptor,
        Some(10.0),
        false
    ));
    assert!(!unknown_cost_paid_provider_blocked(
        &descriptor,
        Some(10.0),
        true
    ));
    assert!(!unknown_cost_paid_provider_blocked(
        &descriptor,
        None,
        false
    ));
}

#[test]
fn env_cost_is_none_when_unset() {
    assert_eq!(
        env_cost_per_request("definitely_missing_provider_xyz"),
        None
    );
}

#[test]
fn every_module_names_its_access_in_one_spelling() {
    // A module that needs the operator's key says `operator_key`, the one spelling the use
    // cases and the key reports read: a second word for it would escape both.
    for module in REACHABLE_MODULES {
        assert!(
            matches!(
                module.access,
                "keyless" | "operator_key" | "offline" | "local" | "local_sensor" | "mixed"
            ),
            "{}: {}",
            module.name,
            module.access
        );
    }
}

#[test]
fn use_cases_choose_modules_by_category() {
    let all = Selection::all();
    assert!(use_case_selection("all", &all).is_all());
    for module in REACHABLE_MODULES {
        assert!(use_case_runs("all", module), "{}", module.name);
    }
    // Passive: every source but the keyed breach ones, so no paid service is told the target.
    let passive = use_case_selection("passive", &all);
    for skipped in [
        "hibp",
        "hibp_account",
        "dehashed",
        "oathnet",
        "stolen_tax",
        "seeknow",
    ] {
        assert!(!passive.runs(skipped), "passive leaves out {skipped}");
    }
    for module in REACHABLE_MODULES {
        let keyed_breach =
            module.category == ModuleCategory::Breach && module.access == "operator_key";
        assert_eq!(passive.runs(module.name), !keyed_breach, "{}", module.name);
    }
    assert!(passive.runs("xposed_or_not") && passive.runs("rdap") && passive.runs("spamhaus"));
    // Footprint: what the target exposes, without the threat, blocklist and reputation sources.
    let footprint = use_case_selection("footprint", &all);
    for runs in [
        "rdap",
        "internetdb",
        "gravatar",
        "github_user",
        "hibp",
        "asic_persons",
    ] {
        assert!(footprint.runs(runs), "footprint runs {runs}");
    }
    for skipped in ["spamhaus", "virustotal", "shodan", "abuseipdb"] {
        assert!(!footprint.runs(skipped), "footprint leaves out {skipped}");
    }
    // Investigate: the threat sources with the basic footprint, without social, search, people
    // and corporate expansion.
    let investigate = use_case_selection("investigate", &all);
    for runs in [
        "spamhaus",
        "virustotal",
        "rdap",
        "internetdb",
        "hibp",
        "oathnet",
    ] {
        assert!(investigate.runs(runs), "investigate runs {runs}");
    }
    for skipped in [
        "gravatar",
        "github_user",
        "asic_persons",
        "asic_director",
        "web_query",
    ] {
        assert!(
            !investigate.runs(skipped),
            "investigate leaves out {skipped}"
        );
    }
    // A use case keeps the chosen modules to its own and never adds one.
    let chosen = Selection::only(["spamhaus", "rdap"]);
    let kept = use_case_selection("footprint", &chosen);
    assert!(kept.runs("rdap") && !kept.runs("spamhaus") && !kept.runs("mnemonic"));
    assert_eq!(use_case_selection("all", &chosen), chosen);
}

/// Spiderfoot's `sfp_commoncrawl` (Common Crawl index URLs for a domain) and
/// `sfp_openstreetmap` (Nominatim geocoding of an address) choose the Huntsman modules that do
/// that same work, and only those, so a Spiderfoot module list naming them still scans.
#[test]
fn spiderfoot_commoncrawl_and_openstreetmap_choose_their_rebuilt_modules() {
    for (spiderfoot, module) in [
        ("sfp_commoncrawl", "common_crawl"),
        ("SFP_OpenStreetMap", "nominatim"),
    ] {
        let chosen = selection(&[spiderfoot.to_owned()])
            .unwrap_or_else(|why| panic!("{spiderfoot} is unknown: {why}"));
        assert_eq!(chosen, Selection::only([module]), "{spiderfoot}");
    }
}
