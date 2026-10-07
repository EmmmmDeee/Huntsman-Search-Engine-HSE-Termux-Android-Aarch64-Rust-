//! Pure module metadata and provider economics descriptors.

use serde::{Deserialize, Serialize};

pub use crate::dependency::{ModuleCategory, ModuleCost, ModuleMeta};

pub const PROVIDER_COST_ENV_PREFIX: &str = "HSE_PROVIDER_COST_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessClass {
    Keyless,
    FreeAccount,
    FreeQuota,
    Paid,
    Enterprise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationBand {
    L0Local,
    L1FreePublic,
    L2FreeQuota,
    L3Microcost,
    L4Specialist,
    L5Enterprise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostModel {
    Free,
    Exact,
    Estimated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveUsePolicy {
    Unrestricted,
    OncePerTargetPerScan,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    Disabled,
    TtlSeconds(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitPolicy {
    None,
    SharedHostCircuitBreaker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalDepthClass {
    Live,
    RollingWindow,
    DeepArchive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub provider_id: &'static str,
    pub module_id: &'static str,
    pub source_class: ModuleCategory,
    pub supported_seed_types: Vec<&'static str>,
    pub access_class: AccessClass,
    pub escalation_band: EscalationBand,
    pub requires_key: bool,
    pub recursive_use_policy: RecursiveUsePolicy,
    pub cache_policy: CachePolicy,
    pub rate_limit_policy: RateLimitPolicy,
    pub cost_model: CostModel,
    pub cost_per_request: Option<f64>,
    pub quota_unit: Option<&'static str>,
    pub historical_depth_class: HistoricalDepthClass,
    pub provenance_quality_prior: f64,
    pub uniqueness_prior: f64,
    pub reliability_prior: f64,
    pub optionality_prior: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ModuleInfo {
    pub name: &'static str,
    pub priority: u8,
    pub cost: ModuleCost,
    pub passive: bool,
    pub description: &'static str,
    pub category: ModuleCategory,
    pub consumes: Vec<&'static str>,
    pub produces: Vec<&'static str>,
    pub provider: ProviderDescriptor,
}

pub trait ModuleSpec {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u8;

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn passive(&self) -> bool {
        false
    }

    fn description(&self) -> &'static str {
        ""
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Other
    }

    fn consumes(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn produces(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn high_value_only(&self) -> bool {
        false
    }

    fn requires_geo_corroboration(&self) -> bool {
        false
    }

    fn cache_ttl_secs(&self) -> u64 {
        0
    }

    fn provider_descriptor(&self) -> ProviderDescriptor {
        derive_default_provider_descriptor(self)
    }

    fn info(&self) -> ModuleInfo {
        ModuleInfo {
            name: self.name(),
            priority: self.priority(),
            cost: self.cost(),
            passive: self.passive(),
            description: self.description(),
            category: self.category(),
            consumes: self.consumes(),
            produces: self.produces(),
            provider: self.provider_descriptor(),
        }
    }
}

#[must_use]
pub fn derive_default_provider_descriptor<M: ModuleSpec + ?Sized>(
    module: &M,
) -> ProviderDescriptor {
    let cost = module.cost();
    let passive = module.passive();
    let escalates = module.high_value_only() || module.requires_geo_corroboration();
    let access_class = match cost {
        ModuleCost::Free => AccessClass::Keyless,
        ModuleCost::KeyGated => AccessClass::FreeAccount,
        ModuleCost::Metered => AccessClass::FreeQuota,
        ModuleCost::Paid | ModuleCost::Unknown => AccessClass::Paid,
    };
    let escalation_band = if passive {
        EscalationBand::L0Local
    } else if escalates {
        EscalationBand::L4Specialist
    } else {
        match cost {
            ModuleCost::Free => EscalationBand::L1FreePublic,
            ModuleCost::KeyGated => EscalationBand::L2FreeQuota,
            ModuleCost::Metered | ModuleCost::Paid | ModuleCost::Unknown => {
                EscalationBand::L3Microcost
            }
        }
    };
    ProviderDescriptor {
        provider_id: module.name(),
        module_id: module.name(),
        source_class: module.category(),
        supported_seed_types: module.consumes(),
        access_class,
        escalation_band,
        requires_key: cost != ModuleCost::Free,
        recursive_use_policy: if cost == ModuleCost::Free {
            RecursiveUsePolicy::Unrestricted
        } else {
            RecursiveUsePolicy::OncePerTargetPerScan
        },
        cache_policy: match module.cache_ttl_secs() {
            0 => CachePolicy::Disabled,
            seconds => CachePolicy::TtlSeconds(seconds),
        },
        rate_limit_policy: if passive {
            RateLimitPolicy::None
        } else {
            RateLimitPolicy::SharedHostCircuitBreaker
        },
        cost_model: match cost {
            ModuleCost::Free => CostModel::Free,
            ModuleCost::Metered => CostModel::Estimated,
            ModuleCost::KeyGated | ModuleCost::Paid | ModuleCost::Unknown => CostModel::Unknown,
        },
        cost_per_request: env_cost_per_request(module.name()),
        quota_unit: None,
        historical_depth_class: if module.category() == ModuleCategory::Breach {
            HistoricalDepthClass::DeepArchive
        } else {
            HistoricalDepthClass::Live
        },
        provenance_quality_prior: 0.5,
        uniqueness_prior: 0.5,
        reliability_prior: 0.5,
        optionality_prior: if module.produces().is_empty() {
            0.0
        } else {
            0.5
        },
    }
}

#[must_use]
pub fn parse_cost_per_request(raw: &str) -> Option<f64> {
    let parsed = raw.trim().parse::<f64>().ok()?;
    (parsed.is_finite() && parsed >= 0.0).then_some(parsed)
}

#[must_use]
pub fn env_cost_per_request(provider_id: &str) -> Option<f64> {
    let env_var = format!(
        "{PROVIDER_COST_ENV_PREFIX}{}",
        provider_id.trim().to_ascii_uppercase()
    );
    std::env::var(env_var)
        .ok()
        .and_then(|value| parse_cost_per_request(&value))
}

#[must_use]
pub fn unknown_cost_paid_provider_blocked(
    descriptor: &ProviderDescriptor,
    budget_usd: Option<f64>,
    allow_unknown_cost: bool,
) -> bool {
    budget_usd.is_some()
        && !allow_unknown_cost
        && matches!(
            descriptor.access_class,
            AccessClass::Paid | AccessClass::Enterprise
        )
        && descriptor.cost_model == CostModel::Unknown
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReachableModule {
    pub name: &'static str,
    pub command: &'static str,
    pub access: &'static str,
    pub network: bool,
    pub category: ModuleCategory,
    pub attack_techniques: &'static [&'static str],
    pub description: &'static str,
}

const REACHABLE_MODULES: &[ReachableModule] = &[
    ReachableModule {
        name: "source_registry",
        command: "sources QUERY",
        access: "offline",
        network: false,
        category: ModuleCategory::Other,
        attack_techniques: &[],
        description: "curated lead-only source routing",
    },
    ReachableModule {
        name: "domain_lifecycle",
        command: "domain-lifecycle analyze INPUT --as-of TIME",
        access: "offline",
        network: false,
        category: ModuleCategory::Other,
        attack_techniques: &[],
        description: "conservative comparison of imported domain observations",
    },
    ReachableModule {
        name: "sf_compat",
        command: "sf [-M|-T|-V] | -s TARGET [options]",
        access: "mixed",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &[],
        description: "SpiderFoot-compatible front end over rebuilt lookup paths",
    },
    ReachableModule {
        name: "classify_module",
        command: "investigate TEXT... | --file FILE",
        access: "offline",
        network: false,
        category: ModuleCategory::Other,
        attack_techniques: &[],
        description: "bounded offline entity extraction from local text",
    },
    ReachableModule {
        name: "local_search",
        command: "search QUERY [DIR]",
        access: "offline",
        network: false,
        category: ModuleCategory::Other,
        attack_techniques: &[],
        description: "bounded local text search",
    },
    ReachableModule {
        name: "web_query",
        command: "query QUERY...",
        access: "keyless",
        network: true,
        category: ModuleCategory::Search,
        attack_techniques: &["T1593.002"],
        description: "bounded Bing, Brave, and Mojeek meta-search",
    },
    ReachableModule {
        name: "web_server",
        command: "serve [--bind ADDR]",
        access: "local",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &[],
        description: "embedded Web UI and read-only JSON API",
    },
    ReachableModule {
        name: "asic_persons",
        command: "people NAME",
        access: "keyless",
        network: true,
        category: ModuleCategory::People,
        attack_techniques: &["T1591.004"],
        description: "ASIC people register lookup",
    },
    ReachableModule {
        name: "asic_director",
        command: "people NAME",
        access: "keyless",
        network: true,
        category: ModuleCategory::Corporate,
        attack_techniques: &["T1591.002", "T1591.004"],
        description: "ASIC director register lookup",
    },
    ReachableModule {
        name: "au_people",
        command: "people NAME",
        access: "keyless",
        network: true,
        category: ModuleCategory::People,
        attack_techniques: &["T1589.003"],
        description: "Australian public people-source lookup",
    },
    ReachableModule {
        name: "au_electoral",
        command: "people NAME",
        access: "keyless",
        network: true,
        category: ModuleCategory::People,
        attack_techniques: &["T1589.003"],
        description: "Australian public electoral-source lookup",
    },
    ReachableModule {
        name: "email_parse",
        command: "email ADDR",
        access: "offline",
        network: false,
        category: ModuleCategory::Other,
        attack_techniques: &[],
        description: "deterministic email canonicalisation and pivots",
    },
    ReachableModule {
        name: "gravatar",
        command: "email ADDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public Gravatar profile lookup",
    },
    ReachableModule {
        name: "username_variants",
        command: "username HANDLE",
        access: "offline",
        network: false,
        category: ModuleCategory::Other,
        attack_techniques: &[],
        description: "bounded deterministic username variants",
    },
    ReachableModule {
        name: "github_user",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.003"],
        description: "public GitHub profile lookup",
    },
    ReachableModule {
        name: "bluesky_user",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public Bluesky profile lookup",
    },
    ReachableModule {
        name: "phone_intl",
        command: "phone NUMBER",
        access: "offline",
        network: false,
        category: ModuleCategory::Phone,
        attack_techniques: &[],
        description: "E.164 and international dialling-prefix classification",
    },
    ReachableModule {
        name: "phone_au",
        command: "phone NUMBER",
        access: "offline",
        network: false,
        category: ModuleCategory::Phone,
        attack_techniques: &[],
        description: "Australian numbering-plan classification",
    },
    ReachableModule {
        name: "hibp",
        command: "hibp SUBCOMMAND",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Breach,
        attack_techniques: &["T1589.001", "T1589.002"],
        description: "explicit HIBP/Pwned Passwords lookup",
    },
    ReachableModule {
        name: "crtsh",
        command: "recon crtsh TARGET",
        access: "keyless",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1596.003"],
        description: "certificate-transparency lookup",
    },
    ReachableModule {
        name: "dns",
        command: "recon dns TARGET",
        access: "keyless",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1590.001"],
        description: "DNS and mail-policy lookup",
    },
    ReachableModule {
        name: "stolen_tax",
        command: "recon stolen-tax QUERY",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Breach,
        attack_techniques: &["T1589.001", "T1589.002"],
        description: "explicit stolen.tax lookup",
    },
    ReachableModule {
        name: "seeknow",
        command: "seeknow SUBCOMMAND",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Breach,
        attack_techniques: &["T1589.001", "T1589.002"],
        description: "explicit See-Know lookup",
    },
];

#[must_use]
pub const fn reachable_modules() -> &'static [ReachableModule] {
    REACHABLE_MODULES
}

#[cfg(test)]
mod tests {
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
    fn string_forms_match_serde() {
        for cost in [ModuleCost::Free, ModuleCost::KeyGated, ModuleCost::Paid] {
            let json = serde_json::to_string(&cost).expect("json");
            assert_eq!(json.trim_matches('"'), cost.as_str());
        }
        assert_eq!(ModuleCategory::DnsRecon.as_str(), "dns_recon");
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
}
