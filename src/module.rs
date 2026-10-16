//! Pure module metadata and provider economics descriptors.

use serde::{Deserialize, Serialize};

pub use crate::dependency::{ModuleCategory, ModuleCost, ModuleMeta};
use crate::environment;
pub use crate::environment::PROVIDER_COST_ENV_PREFIX;
use crate::module_selection::Selection;

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
    environment::provider_cost_per_request(provider_id)
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
        command: "sf [-M|-T|-V] | -C SCAN_ID | -s TARGET [options]",
        access: "mixed",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &[],
        description: "SpiderFoot-compatible sf.py front end over saved scans",
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
        command: "serve [--bind ADDR] [--history DIR]",
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
        name: "duolingo",
        command: "email ADDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "Duolingo account registered to an email",
    },
    ReachableModule {
        name: "openpgp_keys",
        command: "email ADDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &["T1589.002"],
        description: "verified OpenPGP key identities for an email (keys.openpgp.org)",
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
        name: "numverify",
        command: "phone NUMBER",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Phone,
        attack_techniques: &["T1589"],
        description: "Numverify carrier, line type and location (free key)",
    },
    ReachableModule {
        name: "tellows",
        command: "phone NUMBER",
        access: "keyless",
        network: true,
        category: ModuleCategory::Phone,
        attack_techniques: &["T1589"],
        description: "Tellows community reputation score for a phone number",
    },
    ReachableModule {
        name: "usacallerlookup",
        command: "phone NUMBER",
        access: "keyless",
        network: true,
        category: ModuleCategory::Phone,
        attack_techniques: &["T1589"],
        description: "USACallerLookup NANPA carrier, location and FTC complaint profile",
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
        name: "domain_cli",
        command: "domain DOMAIN | scan -k domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1590.001", "T1596.003"],
        description: "combined crt.sh and DNS domain recon front-end",
    },
    ReachableModule {
        name: "virustotal",
        command: "domain DOMAIN | ip ADDRESS",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596"],
        description: "VirusTotal engine verdicts for a domain or address (free key)",
    },
    ReachableModule {
        name: "hunter",
        command: "domain DOMAIN | email ADDR",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Email,
        attack_techniques: &["T1589.002"],
        description: "Hunter.io addresses published for a domain and address verification (free key)",
    },
    ReachableModule {
        name: "ip_cli",
        command: "ip ADDRESS | scan -k ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1590.005", "T1596.005"],
        description: "combined public IP address front-end",
    },
    ReachableModule {
        name: "netblock_cli",
        command: "netblock CIDR | scan -k netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1590.004", "T1590.005"],
        description: "combined public address-block front-end: registration, routing and the PTR names of its addresses",
    },
    ReachableModule {
        name: "asn_cli",
        command: "asn AS-NUMBER | scan -k asn AS-NUMBER",
        access: "keyless",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1590.004", "T1590.005"],
        description: "combined AS front-end: registration, holder, every announced prefix and BGP neighbour",
    },
    ReachableModule {
        name: "internetdb",
        command: "ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1596.005"],
        description: "Shodan InternetDB open ports, hostnames, CPEs and CVEs",
    },
    ReachableModule {
        name: "ripestat",
        command: "ip ADDRESS | netblock CIDR | asn AS-NUMBER",
        access: "keyless",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1590.004", "T1590.005"],
        description: "RIPEstat covering prefix and origin AS of an address or a block, and an AS's holder, announced prefixes and BGP neighbours",
    },
    ReachableModule {
        name: "greynoise",
        command: "ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "GreyNoise Community internet-scanner status (optional free key)",
    },
    ReachableModule {
        name: "spamhaus",
        command: "ip ADDRESS | domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Spamhaus ZEN address and DBL domain blocklists over the system resolver",
    },
    ReachableModule {
        name: "spamcop",
        command: "ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "SpamCop address blocklist over the system resolver",
    },
    ReachableModule {
        name: "uceprotect",
        command: "ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "UCEPROTECT levels 1, 2 and 3 address blocklists over the system resolver",
    },
    ReachableModule {
        name: "dronebl",
        command: "ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "DroneBL address blocklist (drones, proxies, botnets) over the system resolver",
    },
    ReachableModule {
        name: "sorbs",
        command: "ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "SORBS address blocklist over the system resolver",
    },
    ReachableModule {
        name: "surbl",
        command: "ip ADDRESS | domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "SURBL multi address and domain blocklist over the system resolver",
    },
    ReachableModule {
        name: "adguard_dns",
        command: "domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "AdGuard DNS default and family filters over DNS-over-HTTPS",
    },
    ReachableModule {
        name: "cleanbrowsing",
        command: "domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "CleanBrowsing security, adult and family filters over DNS-over-HTTPS",
    },
    ReachableModule {
        name: "cloudflaredns",
        command: "domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Cloudflare 1.1.1.1 for Families malware and family filters over DNS-over-HTTPS",
    },
    ReachableModule {
        name: "comodo",
        command: "domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Comodo Secure DNS filter over UDP",
    },
    ReachableModule {
        name: "dns_for_family",
        command: "domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "DNS for Family filter over UDP to its own servers",
    },
    ReachableModule {
        name: "opendns",
        command: "domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "OpenDNS FamilyShield botnet, malware, phishing and adult categories over DNS-over-HTTPS",
    },
    ReachableModule {
        name: "quad9",
        command: "domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Quad9 threat-blocking resolver over UDP to its own servers",
    },
    ReachableModule {
        name: "yandexdns",
        command: "domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Yandex DNS family filter (infected and adult) over UDP to its own servers",
    },
    ReachableModule {
        name: "abusech",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "abuse.ch Feodo Tracker botnet C2 addresses and URLhaus recent malware URLs, downloaded and kept on the device",
    },
    ReachableModule {
        name: "alienvaultiprep",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "AlienVault IP reputation list of malicious and scanning hosts, downloaded and kept on the device",
    },
    ReachableModule {
        name: "blocklistde",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "blocklist.de addresses reported for attacks in the last 48 hours, downloaded and kept on the device",
    },
    ReachableModule {
        name: "botvrij",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "botvrij.eu malicious domain list, downloaded and kept on the device",
    },
    ReachableModule {
        name: "cinsscore",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "CINS Army list of addresses with poor reputation, downloaded and kept on the device",
    },
    ReachableModule {
        name: "cleantalk",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "CleanTalk's list of HTTP spammers from the last seven days, downloaded and kept on the device",
    },
    ReachableModule {
        name: "coinblocker",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "CoinBlocker cryptomining host list, downloaded and kept on the device",
    },
    ReachableModule {
        name: "cybercrimetracker",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "CyberCrime-Tracker.net botnet panel URLs, downloaded and kept on the device",
    },
    ReachableModule {
        name: "emergingthreats",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Emerging Threats compromised-address list, downloaded and kept on the device",
    },
    ReachableModule {
        name: "greensnow",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "GreenSnow attacking-address list, downloaded and kept on the device",
    },
    ReachableModule {
        name: "openphish",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "OpenPhish phishing URL feed, downloaded and kept on the device",
    },
    ReachableModule {
        name: "phishtank",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "PhishTank verified online phishing URLs, downloaded and kept on the device",
    },
    ReachableModule {
        name: "stevenblack_hosts",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Steven Black unified hosts blocklist (adware and malware hosts), downloaded and kept on the device",
    },
    ReachableModule {
        name: "torexits",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Tor exit relays from Onionoo with their relay records, downloaded and kept on the device",
    },
    ReachableModule {
        name: "voipbl",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "VoIPBL VoIP-abuse address blocks, downloaded and kept on the device",
    },
    ReachableModule {
        name: "vxvault",
        command: "ip ADDRESS | domain DOMAIN | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "VXVault malware download URLs, downloaded and kept on the device",
    },
    ReachableModule {
        name: "abuseipdb",
        command: "ip ADDRESS",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "AbuseIPDB community abuse reports (free key)",
    },
    ReachableModule {
        name: "shodan",
        command: "ip ADDRESS | domain DOMAIN",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Shodan host services and DNS records (key; DNS spends a query credit)",
    },
    ReachableModule {
        name: "pulsedive",
        command: "ip ADDRESS | domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Pulsedive threat risk, feeds and seen technologies (optional free key)",
    },
    ReachableModule {
        name: "leakix",
        command: "ip ADDRESS | domain DOMAIN",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "LeakIX exposed services and data leaks (free key)",
    },
    ReachableModule {
        name: "threatfox",
        command: "ip ADDRESS | domain DOMAIN",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "abuse.ch ThreatFox IOCs naming the indicator (free key)",
    },
    ReachableModule {
        name: "ipqs",
        command: "ip ADDRESS | email ADDR | phone NUMBER",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "IPQualityScore fraud score for an address, email or phone number (free key)",
    },
    ReachableModule {
        name: "whoxy",
        command: "domain DOMAIN | email ADDR",
        access: "operator_key",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1596.002"],
        description: "Whoxy live WHOIS record and reverse WHOIS by email (pay-as-you-go key)",
    },
    ReachableModule {
        name: "netlas",
        command: "ip ADDRESS | domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Netlas scan data, DNS, IOC listings and subdomains (optional free key)",
    },
    ReachableModule {
        name: "otx",
        command: "ip ADDRESS | domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "AlienVault OTX pulses, malware families and adversaries (optional free key)",
    },
    ReachableModule {
        name: "urlscan",
        command: "ip ADDRESS | domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "urlscan.io public page scans, verdicts and co-hosted pages (optional free key)",
    },
    ReachableModule {
        name: "ipinfo",
        command: "ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1590.005"],
        description: "IPinfo hostname, origin AS and city-level location (optional free token)",
    },
    ReachableModule {
        name: "robtex",
        command: "ip ADDRESS | domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1590.002", "T1590.005"],
        description: "Robtex BGP route, origin AS and passive DNS names and records",
    },
    ReachableModule {
        name: "hackertarget",
        command: "ip ADDRESS | domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1590.002", "T1596.001"],
        description: "HackerTarget hosts under a domain and domains on an address (optional key)",
    },
    ReachableModule {
        name: "stopforumspam",
        command: "email ADDR | ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1589.002"],
        description: "StopForumSpam spam-report count, last report and Tor-exit flag",
    },
    ReachableModule {
        name: "isc",
        command: "ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Internet Storm Center (DShield) reports, threat feeds and SSH and web honeypot activity of an address",
    },
    ReachableModule {
        name: "maltiverse",
        command: "domain DOMAIN | ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Maltiverse classification, every blacklist entry, threat flags, place and resolutions",
    },
    ReachableModule {
        name: "phishstats",
        command: "ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "PhishStats phishing URLs reported on an address, each with every field",
    },
    ReachableModule {
        name: "xposed_or_not",
        command: "email ADDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Breach,
        attack_techniques: &["T1589.002"],
        description: "XposedOrNot names of public breaches that included the address",
    },
    ReachableModule {
        name: "kickbox",
        command: "email ADDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::Email,
        attack_techniques: &["T1589.002"],
        description: "Kickbox Open disposable-mail check on the address's domain",
    },
    ReachableModule {
        name: "urlhaus",
        command: "ip ADDRESS | domain DOMAIN",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "abuse.ch URLhaus malware URLs hosted on the indicator (free key)",
    },
    ReachableModule {
        name: "securitytrails",
        command: "domain DOMAIN",
        access: "operator_key",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1596.001"],
        description: "SecurityTrails recorded subdomains (free key)",
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
        name: "certspotter",
        command: "domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1596.003"],
        description: "Cert Spotter: every certificate logged for a domain and its subdomains, in full (optional free key)",
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
        name: "dnsresolve",
        command: "domain DOMAIN | ip ADDRESS | netblock CIDR",
        access: "keyless",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1590.002"],
        description: "A and AAAA records of every subdomain a domain lookup finds, PTR records of an address and of every address in a block of at most 256",
    },
    ReachableModule {
        name: "rdap",
        command: "domain DOMAIN | ip ADDRESS | netblock CIDR | asn AS-NUMBER",
        access: "keyless",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1596.002"],
        description: "RDAP registration of a domain, an address's network, a block or an AS number, from the registry the IANA bootstrap names",
    },
    ReachableModule {
        name: "mnemonic",
        command: "domain DOMAIN | ip ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1596.001"],
        description: "Mnemonic passive DNS: every record seen for a domain or an address, with when, how often and its TTL; names, addresses and co-hosted sites",
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
    ReachableModule {
        name: "dehashed",
        command: "dehashed search (--email|--username|--domain) --purpose PURPOSE",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Breach,
        attack_techniques: &["T1589.001", "T1589.002"],
        description: "explicit DeHashed exact-match search with a declared purpose",
    },
    ReachableModule {
        name: "oathnet",
        command: "exposure EMAIL|USERNAME | email ADDR | username HANDLE",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Breach,
        attack_techniques: &["T1589.001", "T1589.002"],
        description: "OathNet breach and stealer-log search of an email address or username: incidents, exposed fields and pivots",
    },
    ReachableModule {
        name: "wigle",
        command: "network BSSID|LAT,LON|SSID",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Geo,
        attack_techniques: &["T1590"],
        description: "WiGLE WiFi and Bluetooth sightings of a BSSID, an SSID or around a coordinate",
    },
    ReachableModule {
        name: "oui",
        command: "network BSSID",
        access: "offline",
        network: false,
        category: ModuleCategory::Sensor,
        attack_techniques: &[],
        description: "the IEEE vendor assignment of a BSSID's OUI",
    },
];

#[must_use]
pub const fn reachable_modules() -> &'static [ReachableModule] {
    REACHABLE_MODULES
}

/// The Spiderfoot module names a Huntsman module does the work of, beside `sfp_<module>`.
/// **Pure.**
#[must_use]
pub fn spiderfoot_names(module: &str) -> Vec<String> {
    let extra: &[&str] = match module {
        "crtsh" => &["sfp_crt"],
        "dns" => &["sfp_dnsresolve", "sfp_dnsraw"],
        "internetdb" => &["sfp_shodan"],
        "otx" => &["sfp_alienvault"],
        "hibp" | "hibp_account" => &["sfp_haveibeenpwned"],
        "ipqs" => &["sfp_ipqualityscore"],
        "ripestat" => &["sfp_ripe"],
        "urlhaus" | "threatfox" => &["sfp_abusech"],
        "github_user" => &["sfp_github"],
        "openpgp_keys" => &["sfp_pgp"],
        "whoxy" | "rdap" => &["sfp_whois"],
        "kickbox" => &["sfp_debounce"],
        "greynoise" => &["sfp_greynoise_community"],
        "hostdomain" => &["sfp_dnsresolve"],
        _ => &[],
    };
    let mut names = vec![module.to_owned(), format!("sfp_{module}")];
    names.extend(extra.iter().map(|name| (*name).to_owned()));
    names
}

/// The module an outcome or evidence label belongs to, by the name a scan chooses it by: HIBP's
/// account search is `hibp`, `WiGLE`'s Bluetooth search `wigle`, and a module's part
/// (`asic_persons.banned`) the module. **Pure.**
#[must_use]
pub fn module_of(label: &str) -> &str {
    match label {
        "hibp_account" => "hibp",
        "wigle_bluetooth" => "wigle",
        _ => label.split_once('.').map_or(label, |(module, _)| module),
    }
}

/// The selection a scan's chosen `names` make. Each name is a module [`reachable_modules`] lists,
/// or a Spiderfoot module (`sfp_spamhaus`, `sfp_dnsresolve`) standing for every module that does
/// its work, in any case. No name chooses every module.
///
/// # Errors
/// Every name that is neither, in the order given.
pub fn selection(names: &[String]) -> Result<Selection, String> {
    let names: Vec<String> = names
        .iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    if names.is_empty() {
        return Ok(Selection::all());
    }
    let mut chosen = Vec::new();
    let mut unknown = Vec::new();
    for name in &names {
        let modules: Vec<&str> = REACHABLE_MODULES
            .iter()
            .map(|module| module.name)
            .filter(|module| module == name || spiderfoot_names(module).iter().any(|sf| sf == name))
            .collect();
        if modules.is_empty() {
            unknown.push(name.as_str());
        }
        chosen.extend(modules);
    }
    if unknown.is_empty() {
        Ok(Selection::only(chosen))
    } else {
        Err(format!(
            "no module is named {}; /api/modules and the New Scan page list them, and a \
             Spiderfoot name (sfp_...) stands for the modules that do its work",
            unknown.join(", ")
        ))
    }
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
