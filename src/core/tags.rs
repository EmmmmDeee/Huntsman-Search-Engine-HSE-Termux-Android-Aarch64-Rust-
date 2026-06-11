//! Canonical entity tag string constants. One definition so a tag a
//! module emits and a correlator rule matches on can't drift in spelling.

pub const BREACH: &str = "breach";
pub const STEALER_LOG: &str = "stealer-log";
/// Subject data observed on a darknet/Tor source (a distinct, higher-severity
/// exposure than a public leak — it implies active circulation on criminal
/// marketplaces/forums). Emitted by sources that classify by origin (e.g.
/// IntelX `darknet.*` buckets) so the correlator can group darknet exposure.
pub const DARKNET: &str = "darknet";
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

// Australia-specific geolocation. The `au-state:` / `au-lga:` / `au-carrier:`
// families are namespaced: the PREFIX constants are the single source the
// emitters (`util::geo`, the geo modules) and the correlator's `strip_prefix`
// matchers share, and the full-value constants are the exact strings the
// correlator matches by `has_tag`. Defining them here — not as literals
// scattered across the geo modules — is the same anti-drift guarantee this
// module gives every other tag: an emitter and a rule cannot disagree on
// spelling or casing (`au-state:QLD` vs `au-state:Qld` would silently break
// AU-056/AU-059/AU-060).
pub const AU_RELEVANT: &str = "au-relevant";
/// South-East Queensland sub-state signal (Brisbane / Logan / Gold Coast / …).
pub const AU_SE_QLD: &str = "au-se-qld";

/// Namespace prefix for state/territory tags; pair with a code, e.g. `QLD`.
pub const AU_STATE_PREFIX: &str = "au-state:";
pub const AU_STATE_QLD: &str = "au-state:QLD";
pub const AU_STATE_NSW: &str = "au-state:NSW";
pub const AU_STATE_VIC: &str = "au-state:VIC";
pub const AU_STATE_WA: &str = "au-state:WA";
pub const AU_STATE_SA: &str = "au-state:SA";
pub const AU_STATE_TAS: &str = "au-state:TAS";
pub const AU_STATE_NT: &str = "au-state:NT";
pub const AU_STATE_ACT: &str = "au-state:ACT";

/// Namespace prefix for local-government-area tags; pair with a lowercased,
/// hyphenated LGA slug, e.g. `logan-city`.
pub const AU_LGA_PREFIX: &str = "au-lga:";
pub const AU_LGA_LOGAN_CITY: &str = "au-lga:logan-city";

/// Namespace prefix for mobile-carrier tags; pair with a carrier slug.
pub const AU_CARRIER_PREFIX: &str = "au-carrier:";
pub const AU_CARRIER_OPTUS: &str = "au-carrier:optus";
pub const AU_CARRIER_TELSTRA: &str = "au-carrier:telstra";
pub const AU_CARRIER_VODAFONE: &str = "au-carrier:vodafone";

/// The canonical `au-state:<CODE>` tag for a state/territory code (`"QLD"`),
/// or `None` for an unrecognised code. One mapping so every module that turns a
/// resolved state code into a tag produces the identical string. Callers that
/// must tag an unknown code can fall back to [`AU_STATE_PREFIX`] + the code.
#[must_use]
pub fn au_state_tag(code: &str) -> Option<&'static str> {
    Some(match code {
        "QLD" => AU_STATE_QLD,
        "NSW" => AU_STATE_NSW,
        "VIC" => AU_STATE_VIC,
        "WA" => AU_STATE_WA,
        "SA" => AU_STATE_SA,
        "TAS" => AU_STATE_TAS,
        "NT" => AU_STATE_NT,
        "ACT" => AU_STATE_ACT,
        _ => return None,
    })
}

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
pub const DERIVED: &str = "derived";
pub const SOCIAL_PROFILE: &str = "social-profile";
pub const CANDIDATE: &str = "candidate";

// Discovery method
pub const SEARCH_DISCOVERED: &str = "search-discovered";
pub const BREACH_DERIVED: &str = "breach-derived";
