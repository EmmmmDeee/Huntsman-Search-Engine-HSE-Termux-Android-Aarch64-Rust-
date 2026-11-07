//! Pure module metadata and provider economics descriptors.

use serde::{Deserialize, Serialize};

pub use crate::dependency::{ModuleCategory, ModuleCost};
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
        name: "exa",
        command: "query --exa QUERY...",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Search,
        attack_techniques: &["T1593.002"],
        description: "explicit opt-in Exa search leads (5 results maximum; API credits)",
    },
    ReachableModule {
        name: "web_query",
        command: "query QUERY...",
        access: "keyless",
        network: true,
        category: ModuleCategory::Search,
        attack_techniques: &["T1593.002"],
        description: "bounded Bing, Brave, and Mojeek meta-search; --all asks 13 keyless engines in one budget",
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
        name: "acnc",
        command: "people NAME",
        access: "keyless",
        network: true,
        category: ModuleCategory::Corporate,
        attack_techniques: &["T1591.002"],
        description: "ACNC charity register lookup",
    },
    ReachableModule {
        name: "sec_edgar",
        command: "people NAME",
        access: "keyless",
        network: true,
        category: ModuleCategory::Corporate,
        attack_techniques: &["T1591.002", "T1591.004"],
        description: "SEC EDGAR filer lookup",
    },
    ReachableModule {
        name: "sanctions",
        command: "people NAME",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1593"],
        description: "OFAC SDN, UN Security Council and EU sanctions listings that name every word of the person's name, matched on the device",
    },
    ReachableModule {
        name: "icij_offshore",
        command: "people NAME",
        access: "keyless",
        network: true,
        category: ModuleCategory::Corporate,
        attack_techniques: &["T1591.002"],
        description: "ICIJ Offshore Leaks nodes that name every word of the person's name",
    },
    ReachableModule {
        name: "fbi_wanted",
        command: "people NAME | public-osint notices QUERY",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1593"],
        description: "FBI wanted notices that name every word of the person's name",
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
        name: "github_repos",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.003"],
        description: "bounded public GitHub repository footprint; self-declared metadata is not identity proof",
    },
    ReachableModule {
        name: "gitlab_user",
        command: "username HANDLE | scan -k username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.003"],
        description: "exact public GitLab.com user profile via GitLab Users API; no inferred cross-platform attribution",
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
        name: "npm_author",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.003"],
        description: "public npm registry author packages and the maintainer's own published contact",
    },
    ReachableModule {
        name: "crates_io",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.003"],
        description: "public crates.io account, its GitHub profile and its published crates' repository links",
    },
    ReachableModule {
        name: "docker_hub_user",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.003"],
        description: "public Docker Hub account, its profile, website and published image repository count",
    },
    ReachableModule {
        name: "codeberg_user",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.003"],
        description: "public Codeberg (Forgejo) account, its profile, self-declared name, website and public e-mail",
    },
    ReachableModule {
        name: "devto_user",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public DEV Community account, its profile, website and self-declared GitHub and X/Twitter handles",
    },
    ReachableModule {
        name: "huggingface_user",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.003"],
        description: "public Hugging Face account, its profile, self-declared name, published-work counts and public organisation memberships",
    },
    ReachableModule {
        name: "codewars_user",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public Codewars account, its profile, self-declared name, honor, rank and clan",
    },
    ReachableModule {
        name: "hacker_news",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public Hacker News account, its profile and any links self-published in its bio",
    },
    ReachableModule {
        name: "lobsters",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public Lobsters account, its profile and the GitHub handle it self-declares as a cross-platform lead",
    },
    ReachableModule {
        name: "chess_com",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public Chess.com player account, its profile, title, country, join and last-seen times, and the display name and Twitch channel it self-declares as candidate leads",
    },
    ReachableModule {
        name: "lichess",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public Lichess account, its profile, title, creation and last-seen times, game count, and the real name and links it self-declares as candidate leads",
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
        name: "mastodon_user",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public Mastodon account lookup on mastodon.social",
    },
    ReachableModule {
        name: "tiktok_public_contact",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public TikTok profile bio contact candidates, never private registration emails",
    },
    ReachableModule {
        name: "telegram",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001", "T1589.002"],
        description: "public Telegram channel, group, bot or profile page; unowned and private handles stay inconclusive",
    },
    ReachableModule {
        name: "keybase",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "public Keybase identity: cryptographically proven linked accounts, websites and PGP key",
    },
    ReachableModule {
        name: "wikipedia",
        command: "username HANDLE",
        access: "keyless",
        network: true,
        category: ModuleCategory::Social,
        attack_techniques: &["T1593.001"],
        description: "recent public Wikipedia page edits attributed to a handle, keyless (MediaWiki usercontribs)",
    },
    ReachableModule {
        name: "base_rpc",
        command: "crypto base:0xADDRESS | scan -k crypto base:0xADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &["T1596"],
        description: "read-only Base mainnet wallet balances, outgoing nonce, and contract-code presence at finalized block tag via public JSON-RPC; no identity attribution",
    },
    ReachableModule {
        name: "eth_rpc",
        command: "crypto eth:0xADDRESS | scan -k crypto eth:0xADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &["T1596"],
        description: "read-only Ethereum mainnet wallet balances, outgoing nonce, and contract-code presence at finalized block tag via public JSON-RPC; no identity attribution",
    },
    ReachableModule {
        name: "solana_rpc",
        command: "crypto sol:ADDRESS | scan -k crypto sol:ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &["T1596"],
        description: "read-only Solana mainnet-beta account state at finalized commitment via public JSON-RPC once the genesis hash confirms the cluster: exact lamports, owner program and account class, an SPL token account's owner, delegate and close authority, a mint's supply and mint and freeze authorities, a multisig's signers, and the newest transactions naming it that the node retains; no identity attribution",
    },
    ReachableModule {
        name: "blockchain",
        command: "crypto BITCOIN-ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &["T1596"],
        description: "public Bitcoin address balance and lifetime totals from blockchain.info",
    },
    ReachableModule {
        name: "apple_itunes",
        command: "itunes KEYWORD",
        access: "keyless",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &["T1593"],
        description: "public App Store apps for one keyword, with seller and bundle, from Apple's iTunes Search API",
    },
    ReachableModule {
        name: "wikidata",
        command: "wikidata QUERY | scan -k people NAME",
        access: "keyless",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &["T1591"],
        description: "public Wikidata item for a query, its full structured record, and website, coordinate and external-identifier pivots, from Wikidata's keyless search and REST APIs",
    },
    ReachableModule {
        name: "abn_lookup",
        command: "company ABN|ACN",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &["T1591"],
        description: "Australian Business Register record for an ABN or ACN: entity name and type, ABN status, GST registration, state and postcode and business names, from the ABR's JSON web service with the operator's free GUID",
    },
    ReachableModule {
        name: "asic_orgs",
        command: "company NAME|ACN|ABN",
        access: "keyless",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &["T1591"],
        description: "ASIC registered companies, business names and banned or disqualified organisations for a name, ACN or ABN, with each record's numbers, status and dates, from data.gov.au's keyless CKAN datastore",
    },
    ReachableModule {
        name: "gleif_lei",
        command: "gleif LEI|NAME",
        access: "keyless",
        network: true,
        category: ModuleCategory::Other,
        attack_techniques: &["T1591"],
        description: "public GLEIF legal-entity record for an LEI or name: the registered organisation, its legal and headquarters addresses, and an Australian entity's checksum-validated ACN, from GLEIF's keyless public API",
    },
    ReachableModule {
        name: "nominatim",
        command: "geocode PLACE|LAT,LON",
        access: "keyless",
        network: true,
        category: ModuleCategory::Geo,
        attack_techniques: &["T1591.001"],
        description: "forward and reverse geocoding from OpenStreetMap's Nominatim: a place or address to its coordinates and full address, or a point to the address there",
    },
    ReachableModule {
        name: "stac",
        command: "geocode LAT,LON | scan -k geocode LAT,LON",
        access: "keyless",
        network: true,
        category: ModuleCategory::Geo,
        attack_techniques: &["T1591.001"],
        description: "satellite-imagery catalogue: the Sentinel-2 and Landsat scenes Earth Search STAC lists over a point in the last 90 days, with acquisition time, cloud cover and footprint; no imagery downloaded",
    },
    ReachableModule {
        name: "opensky",
        command: "geocode LAT,LON | scan -k geocode LAT,LON",
        access: "keyless",
        network: true,
        category: ModuleCategory::Geo,
        attack_techniques: &["T1591.001"],
        description: "public aircraft observations: the transponders OpenSky Network receivers last reported within half a degree of a point, nearest first, with callsign, position time, altitude, speed and squawk; an airframe, not anyone aboard",
    },
    ReachableModule {
        name: "qld_traffic_cameras",
        command: "traffic-cameras [--district NAME] [--locality NAME] [--limit N] [--reconcile]",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Geo,
        attack_techniques: &["T1591.001"],
        description: "Queensland's published traffic-camera catalogue, read once: each camera's location, direction and JPEG address, never the image; --reconcile compares it with TMR's state-road GIS layer by camera ID",
    },
    ReachableModule {
        name: "exif",
        command: "exif IMAGE-FILE",
        access: "keyless",
        network: false,
        category: ModuleCategory::Geo,
        attack_techniques: &["T1591.001"],
        description: "GPS coordinates and camera/device metadata read from a local image's EXIF, keyless and offline",
    },
    ReachableModule {
        name: "docmeta",
        command: "docmeta FILE",
        access: "keyless",
        network: false,
        category: ModuleCategory::Geo,
        // Authors are employee names, creator tools and history agents are the software in use,
        // and an embedded GPS position is a physical location.
        attack_techniques: &["T1589.003", "T1591.001", "T1592.002"],
        description: "author, creator tool, edit history, timestamps, document IDs, values a PDF edit superseded and embedded GPS read from a local file's XMP packets and PDF /Info dictionary, keyless and offline",
    },
    // The reverse-image providers: each receives the operator's whole image, so each runs only
    // when the operator names it, never from a scan or a lookup.
    ReachableModule {
        name: "google_vision",
        command: "reverse-image IMAGE-FILE --live --provider google_vision",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Search,
        attack_techniques: &["T1593.002"],
        description: "Google Cloud Vision web detection of one local image the operator uploads: pages and images in Google's index holding the same or a similar picture, as leads",
    },
    ReachableModule {
        name: "lenso",
        command: "reverse-image IMAGE-FILE --live --provider lenso",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Search,
        attack_techniques: &["T1593.002"],
        description: "Lenso duplicate-image search of one local image the operator uploads: copies of the picture in Lenso's index and the pages holding them, as leads",
    },
    ReachableModule {
        name: "saucenao",
        command: "reverse-image IMAGE-FILE --live --provider saucenao",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Search,
        attack_techniques: &["T1593.002"],
        description: "SauceNAO image-index search of one local image the operator uploads: matching artwork and its source pages in SauceNAO's indexes, as leads",
    },
    ReachableModule {
        name: crate::phone_intl::SOURCE,
        command: "phone NUMBER",
        access: "offline",
        network: false,
        category: ModuleCategory::Phone,
        attack_techniques: &[],
        description: "E.164 and international dialling-prefix classification",
    },
    ReachableModule {
        name: crate::phone_intl::AU_SOURCE,
        command: "phone NUMBER",
        access: "offline",
        network: false,
        category: ModuleCategory::Phone,
        attack_techniques: &[],
        description: "Australian numbering-plan classification",
    },
    ReachableModule {
        name: crate::phone_intl::NANP_SOURCE,
        command: "phone NUMBER",
        access: "offline",
        network: false,
        category: ModuleCategory::Phone,
        attack_techniques: &[],
        description: "North American Numbering Plan reading of a +1 number: plan validity, local and international forms, line class, the area code's country and the 555-01XX fiction block",
    },
    ReachableModule {
        name: crate::phone_intl::AE_SOURCE,
        command: "phone NUMBER",
        access: "offline",
        network: false,
        category: ModuleCategory::Phone,
        attack_techniques: &[],
        description: "United Arab Emirates numbering-plan reading of a +971 number: fixed line, mobile or service range, local and international forms, and a fixed line's area and emirates (Dubai is 04); no operator or address is inferred",
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
        name: "hudsonrock",
        command: "domain DOMAIN | email ADDRESS",
        access: "keyless",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1589.002"],
        description: "Hudson Rock Cavalier infostealer intelligence (keyless): domain-level aggregates and one address's infostealer records as non-credential breach metadata",
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
        name: "peeringdb",
        command: "asn AS-NUMBER | scan -k asn AS-NUMBER",
        access: "keyless",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1590.004", "T1590.005"],
        description: "PeeringDB operator profile, website and public Internet-exchange peering addresses for an AS",
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
        description: "SORBS address blocklist, which has shut down: never asked, its row says so",
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
        description: "abuse.ch Feodo Tracker botnet C2 addresses, downloaded and kept on the device",
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
        description: "Shodan host with every service banner, CVE and TLS detail, and DNS records (key; DNS spends a query credit)",
    },
    ReachableModule {
        name: "censys",
        command: "ip ADDRESS",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Threat,
        attack_techniques: &["T1596.005"],
        description: "Censys Platform v3 host ports, network, DNS and location (free-plan PAT)",
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
        name: "ipinfo_lite",
        command: "ip ADDRESS",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1590.005"],
        description: "IPinfo Lite country and origin AS for an address, with bogon and anycast flags (free IPinfo token)",
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
        name: "submd",
        command: "domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1590.001"],
        description: "sub.md passive subdomain enumeration (CT + pDNS + X.509)",
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
        name: "opencellid",
        command: "network cell:MCC:MNC:AREA:CELL",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Infrastructure,
        attack_techniques: &["T1590.005"],
        description: "OpenCelliD cell tower position (keyed)",
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
        description: "Internet Storm Center (DShield) reports, threat feeds and SSH and web honeypot activity of an IPv4 address",
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
        name: "wayback_cdx",
        command: "domain DOMAIN | scan -k domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1593.002"],
        description: "bounded Internet Archive CDX capture metadata, historical URL and subdomain pivots, and the contacts up to 3 archived pages published",
    },
    ReachableModule {
        name: "common_crawl",
        command: "domain DOMAIN | scan -k domain DOMAIN",
        access: "keyless",
        network: true,
        category: ModuleCategory::DnsRecon,
        attack_techniques: &["T1593.002"],
        description: "newest Common Crawl index: bounded historical URL and subdomain pivots, and the contacts up to 3 crawled pages published, read by WARC byte range",
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
        command: "recon stolen-tax QUERY | exposure ADDR",
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
        command: "dehashed search (--email|--username|--domain) --purpose PURPOSE | exposure ADDR",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Breach,
        attack_techniques: &["T1589.001", "T1589.002"],
        description: "explicit DeHashed exact-match search with a declared purpose",
    },
    ReachableModule {
        name: "hibp_account",
        command: "exposure ADDR",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Breach,
        attack_techniques: &["T1589.001", "T1589.002"],
        description: "HIBP breaches that list an email address (key)",
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
        name: "wifi_radar",
        command: "radar wifi [--json] [--file TERMUX_SCAN_JSON]",
        access: "local_sensor",
        network: false,
        category: ModuleCategory::Sensor,
        attack_techniques: &[],
        description: "Termux:API Android OS-cached WiFi scan observations; cache age disclosed, no active scan",
    },
    ReachableModule {
        name: "mitm_guard",
        command: "mitm audit [--file WIFI_JSON_OR_WIGLE_JSONL] [--baseline TRUSTED_JSON] [--json]",
        access: "local_sensor",
        network: false,
        category: ModuleCategory::Sensor,
        attack_techniques: &[],
        description: "passive Wi-Fi MITM/evil-twin advisory, operator-verified BSSID/security baseline and mitigation instructions; not a confirmed intrusion detector",
    },
    ReachableModule {
        name: "cell_radar",
        command: "radar cells [--json] [--file TERMUX_CELL_JSON]",
        access: "local_sensor",
        network: false,
        category: ModuleCategory::Sensor,
        attack_techniques: &[],
        description: "Termux:API Android OS-cached GSM/WCDMA/LTE/NR/CDMA identities; no claimed UTC, age or device location",
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
    ReachableModule {
        name: "wigle_bluetooth",
        command: "network BSSID|LAT,LON",
        access: "operator_key",
        network: true,
        category: ModuleCategory::Geo,
        attack_techniques: &["T1590"],
        description: "WiGLE Bluetooth sightings of a device address or around a coordinate",
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
        "common_crawl" => &["sfp_commoncrawl"],
        "nominatim" => &["sfp_openstreetmap"],
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
    let module = label.split_once('.').map_or(label, |(module, _)| module);
    match module {
        "hibp_account" => "hibp",
        "wigle_bluetooth" => "wigle",
        _ => module,
    }
}

/// Whether a New Scan use case runs `module`, as Spiderfoot's use-case flags choose modules. `all`
/// runs every module. `footprint` learns what the target exposes and leaves out the threat,
/// blocklist and reputation sources. `investigate` suspects the target: the threat sources with the
/// basic footprint (names and addresses, infrastructure, breach exposure, the target's own data),
/// without the social, search, web, people and corporate sources that widen a footprint.
/// `passive` asks no keyed breach source (HIBP, `DeHashed`, `OathNet`, stolen.tax, `SeekNow`): no
/// paid service is told an address, handle, name or number the scan looks up, in any lookup, and no
/// quota is spent on one; every other source runs, keyless breach exposure included. A use case is
/// a module set, so every lookup's legs honour it through the scan's [`Selection`]. **Pure.**
#[must_use]
pub fn use_case_runs(usecase: &str, module: &ReachableModule) -> bool {
    match usecase {
        "footprint" => module.category != ModuleCategory::Threat,
        "investigate" => !matches!(
            module.category,
            ModuleCategory::Social
                | ModuleCategory::Search
                | ModuleCategory::Web
                | ModuleCategory::People
                | ModuleCategory::Corporate
        ),
        "passive" => {
            !(module.category == ModuleCategory::Breach && module.access == "operator_key")
        }
        _ => true,
    }
}

/// The selection a scan runs: the modules `chosen` names, kept to the ones `usecase` runs. A use
/// case that runs every module keeps `chosen` as it is, so a scan that chose no module still runs
/// every one; a use case never adds a module `chosen` left out. **Pure.**
#[must_use]
pub fn use_case_selection(usecase: &str, chosen: &Selection) -> Selection {
    if REACHABLE_MODULES
        .iter()
        .all(|module| use_case_runs(usecase, module))
    {
        return chosen.clone();
    }
    Selection::only(
        REACHABLE_MODULES
            .iter()
            .filter(|module| use_case_runs(usecase, module) && chosen.runs(module.name))
            .map(|module| module.name),
    )
}

/// The selection a scan's chosen `names` make. Each name is a module [`reachable_modules`] lists,
/// a label a Sources table shows for one (`hibp_account`, `wigle_bluetooth`, see [`module_of`]),
/// or a Spiderfoot module (`sfp_spamhaus`, `sfp_dnsresolve`) standing for every module that does
/// its work, in any case. No name chooses every module. A retired module's name, which a scan
/// saved before its source was retired may hold, chooses nothing.
///
/// # Errors
/// Every name that is none of those, in the order given.
pub fn selection(names: &[String]) -> Result<Selection, String> {
    /// Modules retired with the source they read (`CoinBlocker`'s list is no longer public): a
    /// saved scan or a Spiderfoot module list that names one still runs, without it.
    const RETIRED: [&str; 1] = ["coinblocker"];
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
        let wanted = module_of(name);
        let modules: Vec<&str> = REACHABLE_MODULES
            .iter()
            .map(|module| module.name)
            .filter(|module| {
                *module == wanted || spiderfoot_names(module).iter().any(|sf| sf == name)
            })
            .collect();
        let retired = RETIRED.iter().any(|module| {
            *module == wanted || spiderfoot_names(module).iter().any(|sf| sf == name)
        });
        if modules.is_empty() && !retired {
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
mod tests;
