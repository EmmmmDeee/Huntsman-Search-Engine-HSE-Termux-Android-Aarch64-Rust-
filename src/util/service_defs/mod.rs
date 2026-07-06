use serde::{Deserialize, Serialize};

/// Static metadata for one keyed external provider — the single registry the
/// key-management surface (validation probes, the key pool, ROI accounting) reads
/// so a provider's env var, test endpoint, key placement and rate-limit window are
/// declared in exactly one place and can't drift between consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDef {
    /// Canonical lowercase service name (the lookup key for [`find_service`]).
    pub name: &'static str,
    /// Environment variable that supplies this service's API key.
    pub env_var: &'static str,
    /// Coarse grouping (`breach`, `infra`, `geo`, …) for reporting/ROI rollups.
    pub category: &'static str,
    /// A cheap endpoint a key-validation probe can hit to check the key works.
    pub test_url: &'static str,
    /// Where the key goes on a request (query param vs header) — see [`KeyPlacement`].
    pub key_header: KeyPlacement,
    /// Seconds to back off after a rate-limit response from this service.
    pub rate_limit_reset_secs: u64,
}

/// The rate-limit back-off window (seconds) for `service`, or a conservative
/// `3600` default when the name is not a registered provider ([`find_service`]).
#[must_use]
pub fn rate_limit_reset(service: &str) -> u64 {
    find_service(service).map_or(3600, |d| d.rate_limit_reset_secs)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPlacement {
    QueryParam(&'static str),
    Header(&'static str),
    BasicAuth,
    BearerAuth,
}

static SERVICE_DEFS: &[ServiceDef] = &[
    ServiceDef {
        name: "shodan",
        env_var: "HUNTSMAN_SHODAN_KEY",
        category: "infrastructure",
        test_url: "https://api.shodan.io/api-info?key=",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 300,
    },
    ServiceDef {
        name: "intelx",
        env_var: "HUNTSMAN_INTELX_KEY",
        category: "breach",
        test_url: "https://2.intelx.io/authenticate/info",
        key_header: KeyPlacement::Header("x-key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "securitytrails",
        env_var: "HUNTSMAN_SECTRAILS_KEY",
        category: "infrastructure",
        test_url: "https://api.securitytrails.com/v1/account/usage",
        key_header: KeyPlacement::Header("APIKEY"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "leakix",
        env_var: "HUNTSMAN_LEAKIX_KEY",
        category: "breach",
        test_url: "https://leakix.net/api/subdomains/example.com",
        key_header: KeyPlacement::Header("api-key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "ipqs",
        env_var: "HUNTSMAN_IPQS_KEY",
        category: "threat_intel",
        test_url: "https://ipqualityscore.com/api/json/account/",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "numverify",
        env_var: "HUNTSMAN_NUMVERIFY_KEY",
        category: "identity",
        test_url: "https://apilayer.net/api/validate?number=14158586273&access_key=",
        key_header: KeyPlacement::QueryParam("access_key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "criminal_ip",
        env_var: "HUNTSMAN_CRIMINALIP_KEY",
        category: "threat_intel",
        test_url: "https://api.criminalip.io/v1/user/me",
        key_header: KeyPlacement::Header("x-api-key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "virustotal",
        env_var: "HUNTSMAN_VIRUSTOTAL_KEY",
        category: "threat_intel",
        test_url: "https://www.virustotal.com/api/v3/urls",
        key_header: KeyPlacement::Header("x-apikey"),
        rate_limit_reset_secs: 15,
    },
    ServiceDef {
        name: "wigle",
        env_var: "HUNTSMAN_WIGLE_TOKEN",
        category: "geoint",
        test_url: "https://api.wigle.net/api/v2/profile/user",
        key_header: KeyPlacement::Header("Authorization"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "hunter",
        env_var: "HUNTSMAN_HUNTER_KEY",
        category: "identity",
        test_url: "https://api.hunter.io/v2/account?api_key=",
        key_header: KeyPlacement::QueryParam("api_key"),
        rate_limit_reset_secs: 4,
    },
    ServiceDef {
        name: "hibp",
        env_var: "HUNTSMAN_HIBP_KEY",
        category: "breach",
        test_url: "https://haveibeenpwned.com/api/v3/breaches",
        key_header: KeyPlacement::Header("hibp-api-key"),
        rate_limit_reset_secs: 6,
    },
    // NOTE: DeHashed is intentionally absent. Its v2 API is POST-only
    // (`POST /v2/search` with a `Dehashed-Api-Key` header), which the
    // GET-based key validator here cannot probe without spending a paid
    // search credit — and the legacy v1 `GET /search` URL it used now 404s.
    // The `dehashed` module reads HUNTSMAN_DEHASHED_KEY from the env directly,
    // so a validator def would only ever mis-report a valid key as invalid.
    ServiceDef {
        name: "threatfox",
        env_var: "HUNTSMAN_THREATFOX_KEY",
        category: "threat_intel",
        test_url: "https://threatfox-api.abuse.ch/api/v1/",
        key_header: KeyPlacement::Header("API-KEY"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "passivetotal",
        env_var: "HUNTSMAN_PASSIVETOTAL_KEY",
        category: "infrastructure",
        test_url: "https://api.passivetotal.org/v2/account/quota",
        key_header: KeyPlacement::BasicAuth,
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "onyphe",
        env_var: "HUNTSMAN_ONYPHE_KEY",
        category: "infrastructure",
        test_url: "https://www.onyphe.io/api/v2/simple/whois/best/8.8.8.8",
        key_header: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "zoomeye",
        env_var: "HUNTSMAN_ZOOMEYE_KEY",
        category: "infrastructure",
        test_url: "https://api.zoomeye.org/resources-info",
        key_header: KeyPlacement::Header("API-KEY"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "fofa",
        env_var: "HUNTSMAN_FOFA_KEY",
        category: "infrastructure",
        test_url: "https://fofa.info/api/v1/info/my",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "netlas",
        env_var: "HUNTSMAN_NETLAS_KEY",
        category: "infrastructure",
        test_url: "https://app.netlas.io/api/users/current/",
        // netlas authenticates with an `X-API-Key` header (see modules/netlas/mod.rs
        // and api_key_probe) — a `BearerAuth` probe would 401 a valid key and
        // mis-report it invalid.
        key_header: KeyPlacement::Header("X-API-Key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "pulsedive",
        env_var: "HUNTSMAN_PULSEDIVE_KEY",
        category: "threat_intel",
        test_url: "https://pulsedive.com/api/info.php?indicator=pulsedive.com&key=",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 30,
    },
    ServiceDef {
        name: "builtwith",
        env_var: "HUNTSMAN_BUILTWITH_KEY",
        category: "infrastructure",
        test_url: "https://api.builtwith.com/usagev2/api.json?KEY=",
        key_header: KeyPlacement::QueryParam("KEY"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "emailrep",
        env_var: "HUNTSMAN_EMAILREP_KEY",
        category: "identity",
        test_url: "https://emailrep.io/test@example.com",
        key_header: KeyPlacement::Header("Key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "whoisxml",
        env_var: "HUNTSMAN_WHOISXML_KEY",
        category: "infrastructure",
        test_url: "https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=example.com&outputFormat=JSON&apiKey=",
        key_header: KeyPlacement::QueryParam("apiKey"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "breachdirectory",
        env_var: "HUNTSMAN_BREACHDIR_KEY",
        category: "breach",
        test_url: "https://breachdirectory.p.rapidapi.com/?func=auto&term=test@example.com",
        key_header: KeyPlacement::Header("X-RapidAPI-Key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "c99",
        env_var: "HUNTSMAN_C99_KEY",
        category: "infrastructure",
        test_url: "https://api.c99.nl/",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "greynoise",
        env_var: "HUNTSMAN_GREYNOISE_KEY",
        category: "threat_intel",
        test_url: "https://api.greynoise.io/v3/community/8.8.8.8",
        key_header: KeyPlacement::Header("key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "urlscan",
        env_var: "HUNTSMAN_URLSCAN_KEY",
        category: "threat_intel",
        test_url: "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1",
        key_header: KeyPlacement::Header("API-Key"),
        rate_limit_reset_secs: 5,
    },
    ServiceDef {
        name: "censys",
        env_var: "HUNTSMAN_CENSYS_ID",
        category: "infrastructure",
        test_url: "https://search.censys.io/api/v2/hosts/1.1.1.1",
        key_header: KeyPlacement::BasicAuth,
        rate_limit_reset_secs: 3,
    },
    ServiceDef {
        name: "censys_secret",
        env_var: "HUNTSMAN_CENSYS_SECRET",
        category: "infrastructure",
        test_url: "https://search.censys.io/api/v2/hosts/1.1.1.1",
        key_header: KeyPlacement::BasicAuth,
        rate_limit_reset_secs: 3,
    },
    // (DeHashed v2 is key-only; the former `dehashed_user` account-email def
    // is obsolete — see the note where the `dehashed` def used to live.)
    ServiceDef {
        name: "binaryedge",
        env_var: "HUNTSMAN_BINARYEDGE_KEY",
        category: "infrastructure",
        test_url: "https://api.binaryedge.io/v2/user/subscription",
        key_header: KeyPlacement::Header("X-Key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "abuseipdb",
        env_var: "HUNTSMAN_ABUSEIPDB_KEY",
        category: "threat_intel",
        test_url: "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1",
        key_header: KeyPlacement::Header("Key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "fullhunt",
        env_var: "HUNTSMAN_FULLHUNT_KEY",
        category: "infrastructure",
        test_url: "https://fullhunt.io/api/v1/auth/status",
        key_header: KeyPlacement::Header("X-API-KEY"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "abr",
        env_var: "HUNTSMAN_ABR_GUID",
        category: "identity",
        test_url: "https://abr.business.gov.au/json/AbnDetails.aspx?abn=51824753556&callback=cb&guid=",
        key_header: KeyPlacement::QueryParam("guid"),
        rate_limit_reset_secs: 5,
    },
    ServiceDef {
        name: "wigle_user",
        env_var: "HUNTSMAN_WIGLE_USER",
        category: "geoint",
        test_url: "https://api.wigle.net/api/v2/profile/user",
        key_header: KeyPlacement::Header("Authorization"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "opencellid",
        env_var: "HUNTSMAN_OPENCELLID_KEY",
        category: "geoint",
        test_url: "https://opencellid.org/cell/get?key=",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 60,
    },
    ServiceDef {
        name: "seon",
        env_var: "HUNTSMAN_SEON_KEY",
        category: "identity",
        test_url: "https://api.seon.io/SeonRestService/email-api/v3",
        key_header: KeyPlacement::Header("X-API-KEY"),
        rate_limit_reset_secs: 18,
    },
    ServiceDef {
        name: "epieos",
        env_var: "HUNTSMAN_EPIEOS_KEY",
        category: "identity",
        test_url: "https://api.epieos.com/api/v1/email",
        key_header: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 36,
    },
    ServiceDef {
        name: "proxycurl",
        env_var: "HUNTSMAN_PROXYCURL_KEY",
        category: "identity",
        test_url: "https://nubela.co/proxycurl/api/v2/linkedin",
        key_header: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 12,
    },
    ServiceDef {
        name: "opencorporates",
        env_var: "HUNTSMAN_OPENCORP_KEY",
        category: "identity",
        test_url: "https://api.opencorporates.com/v0.4/companies/search?q=test",
        key_header: KeyPlacement::QueryParam("api_token"),
        rate_limit_reset_secs: 60,
    },
    // SeekNow (see-know.eu) — direct OathNet competitor with 5000 daily
    // lookups on premiumhq tier. Auth: `X-API-Key: <key>` — the server REJECTS
    // `Authorization: Bearer` with "Missing API key. Use X-API-Key" (see
    // see_know/client.rs, which authenticates with AuthScheme::XApiKey), so the
    // validation probe must send the same header or it mis-reports a valid key
    // as invalid. /credits is a free introspection endpoint for validation.
    ServiceDef {
        name: "see_know",
        env_var: "HUNTSMAN_SEEKNOW_KEY",
        category: "breach",
        test_url: "https://see-know.eu/api/v1/credits",
        key_header: KeyPlacement::Header("X-API-Key"),
        rate_limit_reset_secs: 17,
    },
    // Exa AI neural search — semantic web search for entity discovery.
    // x-api-key header. POST endpoint, but the GET /search?q=test path
    // returns a usage stub that confirms key validity.
    ServiceDef {
        name: "exa",
        env_var: "HUNTSMAN_EXA_KEY",
        category: "search",
        test_url: "https://api.exa.ai/search",
        key_header: KeyPlacement::Header("x-api-key"),
        rate_limit_reset_secs: 5,
    },
];

/// The full static registry of keyed-provider definitions — the canonical list
/// every key-management consumer iterates.
#[must_use]
pub fn service_defs() -> &'static [ServiceDef] {
    SERVICE_DEFS
}

/// Look up a provider's [`ServiceDef`] by name, case-insensitively, or `None` when
/// it is not a registered keyed provider.
#[must_use]
pub fn find_service(name: &str) -> Option<&'static ServiceDef> {
    let lower = name.to_lowercase();
    SERVICE_DEFS.iter().find(|s| s.name == lower)
}

/// True if `service` is a recognised keyed provider whose key the engine's
/// key-cascade can actually **reuse** — i.e. it appears in [`service_defs`], so
/// `hot_inject_keys` (which iterates `service_defs`) will pull a pooled key for
/// it on a later round.
///
/// This is the gate for what may enter the rotation **pool**. A discovered
/// secret for any *other* "service" — the `generic_hex` catch-all, `jwt_token`,
/// a `crypto_*` wallet tag, a foreign consumer login — is still surfaced as an
/// `ApiKey` entity (the intel), but must NOT be pooled: nothing ever injects it,
/// so pooling only grows `key_pool.json` without bound. A live run accumulated
/// **8668** `generic_hex` blobs → a 4 MB pool that overflowed the web pool view.
#[must_use]
pub fn is_poolable_service(service: &str) -> bool {
    find_service(service).is_some()
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
