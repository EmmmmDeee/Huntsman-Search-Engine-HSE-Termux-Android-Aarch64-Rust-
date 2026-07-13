//! Canonical entity tag string constants. One definition so a tag a
//! module emits and a correlator rule matches on can't drift in spelling.

pub const BREACH: &str = "breach";
pub const STEALER_LOG: &str = "stealer-log";
pub const WEB: &str = "web";
pub const CRAWLED: &str = "crawled";
pub const SUBDOMAIN: &str = "subdomain";
pub const EXTERNAL: &str = "external";
pub const WEB_SCRAPED: &str = "web-scraped";
pub const CT_LOG: &str = "ct-log";
pub const PTR: &str = "ptr";
pub const HIGH_EXPOSURE: &str = "high-exposure";
pub const PASTE_EXPOSED: &str = "paste-exposed";
pub const PASSWORD_AT_RISK: &str = "password-at-risk";
pub const MULTI_DEVICE: &str = "multi-device";
pub const MISSING_SECURITY_HEADERS: &str = "missing-security-headers";

// Geolocation
pub const GEOINT: &str = "geoint";
pub const GEOLOCATION_LEAD: &str = "geolocation-lead";
pub const COARSE: &str = "coarse";
/// Datacenter / CDN / cloud-host location, not a residence. Carried by
/// coordinates that geolocate a hosting IP (e.g. a Cloudflare edge), so the
/// area-of-operation rule (AU-052) can exclude them from a person's footprint.
pub const HOSTING: &str = "hosting";
/// Shared / third-party **platform infrastructure** — cloud-storage buckets,
/// datacenter/CDN hosting endpoints, and third-party analytics IDs. Not
/// subject-owned, so the default report ([`crate::api::scan_export`]) suppresses
/// it (restorable via `--include-infra` / `--output full`) and the location
/// rules keep it out of the subject's physical footprint. Stamped by the
/// `tag_platform_infra` enrichment pass in [`crate::core::engine`].
pub const PLATFORM_INFRA: &str = "platform-infra";
/// A WHOIS/RDAP **registrant** location — the domain owner's filing or privacy
/// address (often a registrar's privacy service), not the scan subject's home.
/// Carried by the address/coordinates a WHOIS record yields so the geo rules
/// can keep it out of the subject's physical footprint (see
/// `is_infrastructure_geo`, AU-018/026/030).
pub const REGISTRANT: &str = "registrant";

// Device / local
pub const WIFI_AP: &str = "wifi-ap";
pub const CELL_TOWER: &str = "cell-tower";
pub const LOCAL_ARP: &str = "local-arp";
pub const LOCAL_INTERFACE: &str = "local-interface";

// Reputation / threat
pub const THREAT_INTEL: &str = "threat-intel";
pub const MALICIOUS: &str = "malicious";
pub const TOR_EXIT: &str = "tor-exit";
pub const PROXY: &str = "proxy";
pub const VPN: &str = "vpn";
pub const VULNERABLE: &str = "vulnerable";

// Identity
pub const SOCIAL_PROFILE: &str = "social-profile";
pub const CANDIDATE: &str = "candidate";

// Discovery method
pub const SEARCH_DISCOVERED: &str = "search-discovered";
pub const BREACH_DERIVED: &str = "breach-derived";
/// Entity injected from the persistent store at scan start — prior-scan
/// knowledge recalled so the local database acts as a source, not just a sink.
pub const RECALLED: &str = "recalled";
