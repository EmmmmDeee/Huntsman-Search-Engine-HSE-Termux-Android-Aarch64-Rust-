use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Parses a probe's JSON response into `(label, value)` evidence pairs —
/// see [`ServiceDef::probe_parser`].
pub type ProbeParser = fn(&Value) -> Vec<(String, String)>;

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
    /// For services `api_key_probe` can enrich with live account metadata
    /// (plan, credits, quota) beyond a bare pass/fail validation — parses
    /// the probe response into `(label, value)` evidence pairs. `None` for
    /// definitions that exist purely for pool validation/rotation. Not
    /// serializable (a function pointer), so skipped on both directions —
    /// `ServiceDef` is (de)serialized only where its data fields matter.
    #[serde(skip)]
    pub probe_parser: Option<ProbeParser>,
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
    /// A header carrying a custom scheme prefix directly followed by the key
    /// (header name, prefix) — e.g. OpenSanctions' `Authorization: ApiKey
    /// <key>`. Distinct from `BearerAuth`, which is hardcoded to the literal
    /// `bearer` scheme and can't express a different prefix word.
    HeaderPrefixed(&'static str, &'static str),
}

static SERVICE_DEFS: &[ServiceDef] = &[
    ServiceDef {
        name: "shodan",
        env_var: "HUNTSMAN_SHODAN_KEY",
        category: "infrastructure",
        test_url: "https://api.shodan.io/api-info?key=",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 300,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(p) = v.get("plan").and_then(|v| v.as_str()) {
                out.push(("plan".into(), p.to_string()));
            }
            if let Some(c) = v.get("query_credits").and_then(serde_json::Value::as_u64) {
                out.push(("query_credits".into(), c.to_string()));
            }
            if let Some(c) = v.get("scan_credits").and_then(serde_json::Value::as_u64) {
                out.push(("scan_credits".into(), c.to_string()));
            }
            out
        }),
    },
    ServiceDef {
        name: "intelx",
        env_var: "HUNTSMAN_INTELX_KEY",
        category: "breach",
        test_url: "https://2.intelx.io/authenticate/info",
        key_header: KeyPlacement::Header("x-key"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(n) = v.get("Name").and_then(|v| v.as_str()) {
                out.push(("account_name".into(), n.to_string()));
            }
            if let Some(c) = v.get("CreditBalance").and_then(serde_json::Value::as_i64) {
                out.push(("credit_balance".into(), c.to_string()));
            }
            if let Some(p) = v.get("MaxCredits").and_then(serde_json::Value::as_i64) {
                out.push(("max_credits".into(), p.to_string()));
            }
            out
        }),
    },
    ServiceDef {
        name: "securitytrails",
        env_var: "HUNTSMAN_SECTRAILS_KEY",
        category: "infrastructure",
        test_url: "https://api.securitytrails.com/v1/ping",
        key_header: KeyPlacement::Header("APIKEY"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if v.get("success").and_then(serde_json::Value::as_bool) == Some(true) {
                out.push(("status".into(), "authenticated".into()));
            }
            out
        }),
    },
    ServiceDef {
        name: "leakix",
        env_var: "HUNTSMAN_LEAKIX_KEY",
        category: "breach",
        test_url: "https://leakix.net/api/subdomains/example.com",
        key_header: KeyPlacement::Header("api-key"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|_v| vec![("status".into(), "authenticated".into())]),
    },
    ServiceDef {
        name: "ipqs",
        env_var: "HUNTSMAN_IPQS_KEY",
        category: "threat_intel",
        test_url: "https://ipqualityscore.com/api/json/account/",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(c) = v.get("credits").and_then(serde_json::Value::as_u64) {
                out.push(("credits".into(), c.to_string()));
            }
            if let Some(p) = v.get("plan").and_then(|v| v.as_str()) {
                out.push(("plan".into(), p.to_string()));
            }
            out
        }),
    },
    ServiceDef {
        name: "numverify",
        env_var: "HUNTSMAN_NUMVERIFY_KEY",
        category: "identity",
        test_url: "https://apilayer.net/api/validate?number=14158586273&access_key=",
        key_header: KeyPlacement::QueryParam("access_key"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if v.get("valid").and_then(serde_json::Value::as_bool) == Some(true) {
                out.push(("status".into(), "authenticated".into()));
            }
            out
        }),
    },
    ServiceDef {
        name: "criminal_ip",
        env_var: "HUNTSMAN_CRIMINALIP_KEY",
        category: "threat_intel",
        test_url: "https://api.criminalip.io/v1/user/me",
        key_header: KeyPlacement::Header("x-api-key"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(data) = v.get("data")
                && let Some(p) = data.get("plan").and_then(|v| v.as_str())
            {
                out.push(("plan".into(), p.to_string()));
            }
            out
        }),
    },
    ServiceDef {
        name: "virustotal",
        env_var: "HUNTSMAN_VIRUSTOTAL_KEY",
        category: "threat_intel",
        test_url: "https://www.virustotal.com/api/v3/users/me",
        key_header: KeyPlacement::Header("x-apikey"),
        rate_limit_reset_secs: 15,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(data) = v.get("data").and_then(|d| d.get("attributes")) {
                if let Some(q) = data.get("quotas")
                    && let Some(api) = q.get("api_requests_daily")
                    && let Some(allowed) = api.get("allowed").and_then(serde_json::Value::as_u64)
                {
                    out.push(("daily_quota".into(), allowed.to_string()));
                }
                if let Some(p) = data.get("privileges") {
                    out.push(("privileges".into(), format!("{p}")));
                }
            }
            out
        }),
    },
    // KNOWN LIMITATION: WiGLE actually authenticates with HTTP Basic Auth
    // over a username:token PAIR (see modules/wigle/fetch.rs/account.rs's
    // real `.basic_auth(user, Some(token))` calls) — a single-value
    // `ApiKey` credential can't represent that, so this def (and the
    // `censys`/`censys_secret` pair below, which has the same two-part
    // shape) validates only the bare token via a plain `Authorization`
    // header, which a real WiGLE key will always fail. Pre-existing in
    // both tables this def was merged from; a real fix needs a paired-
    // credential `KeyPlacement` variant, deliberately out of scope here.
    ServiceDef {
        name: "wigle",
        env_var: "HUNTSMAN_WIGLE_TOKEN",
        category: "geoint",
        test_url: "https://api.wigle.net/api/v2/profile/user",
        key_header: KeyPlacement::Header("Authorization"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(u) = v.get("userid").and_then(|v| v.as_str()) {
                out.push(("userid".into(), u.to_string()));
            }
            out
        }),
    },
    ServiceDef {
        name: "hunter",
        env_var: "HUNTSMAN_HUNTER_KEY",
        category: "identity",
        test_url: "https://api.hunter.io/v2/account?api_key=",
        key_header: KeyPlacement::QueryParam("api_key"),
        rate_limit_reset_secs: 4,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(data) = v.get("data") {
                if let Some(p) = data.get("plan_name").and_then(|v| v.as_str()) {
                    out.push(("plan".into(), p.to_string()));
                }
                if let Some(r) = data.get("requests")
                    && let Some(avail) = r
                        .get("searches")
                        .and_then(|s| s.get("available"))
                        .and_then(serde_json::Value::as_u64)
                {
                    out.push(("searches_available".into(), avail.to_string()));
                }
            }
            out
        }),
    },
    ServiceDef {
        name: "hibp",
        env_var: "HUNTSMAN_HIBP_KEY",
        category: "breach",
        test_url: "https://haveibeenpwned.com/api/v3/breaches",
        key_header: KeyPlacement::Header("hibp-api-key"),
        rate_limit_reset_secs: 6,
        probe_parser: Some(|_v| vec![("status".into(), "authenticated".into())]),
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
        probe_parser: None,
    },
    ServiceDef {
        name: "passivetotal",
        env_var: "HUNTSMAN_PASSIVETOTAL_KEY",
        category: "infrastructure",
        test_url: "https://api.passivetotal.org/v2/account/quota",
        key_header: KeyPlacement::BasicAuth,
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(u) = v
                .get("user")
                .and_then(|u| u.get("owner"))
                .and_then(|v| v.as_str())
            {
                out.push(("owner".into(), u.to_string()));
            }
            out
        }),
    },
    ServiceDef {
        name: "onyphe",
        env_var: "HUNTSMAN_ONYPHE_KEY",
        category: "infrastructure",
        test_url: "https://www.onyphe.io/api/v2/simple/whois/best/8.8.8.8",
        key_header: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if v.get("count").is_some() {
                out.push(("status".into(), "authenticated".into()));
            }
            out
        }),
    },
    ServiceDef {
        name: "zoomeye",
        env_var: "HUNTSMAN_ZOOMEYE_KEY",
        category: "infrastructure",
        test_url: "https://api.zoomeye.org/resources-info",
        key_header: KeyPlacement::Header("API-KEY"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(p) = v.get("plan").and_then(|v| v.as_str()) {
                out.push(("plan".into(), p.to_string()));
            }
            if let Some(c) = v
                .get("resources")
                .and_then(|r| r.get("search"))
                .and_then(serde_json::Value::as_u64)
            {
                out.push(("search_credits".into(), c.to_string()));
            }
            out
        }),
    },
    ServiceDef {
        name: "fofa",
        env_var: "HUNTSMAN_FOFA_KEY",
        category: "infrastructure",
        test_url: "https://fofa.info/api/v1/info/my",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
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
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if v.get("email").is_some() {
                out.push(("status".into(), "authenticated".into()));
            }
            out
        }),
    },
    ServiceDef {
        name: "pulsedive",
        env_var: "HUNTSMAN_PULSEDIVE_KEY",
        category: "threat_intel",
        test_url: "https://pulsedive.com/api/info.php?indicator=pulsedive.com&key=",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 30,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if v.get("indicator").is_some() {
                out.push(("status".into(), "authenticated".into()));
            }
            out
        }),
    },
    ServiceDef {
        name: "builtwith",
        env_var: "HUNTSMAN_BUILTWITH_KEY",
        category: "infrastructure",
        test_url: "https://api.builtwith.com/usagev2/api.json?KEY=",
        key_header: KeyPlacement::QueryParam("KEY"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    ServiceDef {
        name: "emailrep",
        env_var: "HUNTSMAN_EMAILREP_KEY",
        category: "identity",
        test_url: "https://emailrep.io/test@example.com",
        key_header: KeyPlacement::Header("Key"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if v.get("reputation").is_some() {
                out.push(("status".into(), "authenticated".into()));
            }
            out
        }),
    },
    ServiceDef {
        name: "whoisxml",
        env_var: "HUNTSMAN_WHOISXML_KEY",
        category: "infrastructure",
        test_url: "https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=example.com&outputFormat=JSON&apiKey=",
        key_header: KeyPlacement::QueryParam("apiKey"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    ServiceDef {
        name: "breachdirectory",
        env_var: "HUNTSMAN_BREACHDIR_KEY",
        category: "breach",
        test_url: "https://breachdirectory.p.rapidapi.com/?func=auto&term=test@example.com",
        key_header: KeyPlacement::Header("X-RapidAPI-Key"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    ServiceDef {
        name: "c99",
        env_var: "HUNTSMAN_C99_KEY",
        category: "infrastructure",
        test_url: "https://api.c99.nl/",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    ServiceDef {
        name: "greynoise",
        env_var: "HUNTSMAN_GREYNOISE_KEY",
        category: "threat_intel",
        test_url: "https://api.greynoise.io/v3/ip/8.8.8.8",
        key_header: KeyPlacement::Header("key"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if v.get("ip").is_some() && v.get("seen").is_some() {
                out.push(("status".into(), "authenticated".into()));
                if let Some(c) = v.get("classification").and_then(|v| v.as_str()) {
                    out.push(("classification".into(), c.to_string()));
                }
            }
            out
        }),
    },
    ServiceDef {
        name: "urlscan",
        env_var: "HUNTSMAN_URLSCAN_KEY",
        category: "threat_intel",
        test_url: "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1",
        key_header: KeyPlacement::Header("API-Key"),
        rate_limit_reset_secs: 5,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if v.get("results").is_some() {
                out.push(("status".into(), "authenticated".into()));
            }
            out
        }),
    },
    ServiceDef {
        name: "censys",
        env_var: "HUNTSMAN_CENSYS_ID",
        category: "infrastructure",
        test_url: "https://search.censys.io/api/v2/hosts/1.1.1.1",
        key_header: KeyPlacement::BasicAuth,
        rate_limit_reset_secs: 3,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(ip) = v.get("ip").and_then(|v| v.as_str()) {
                out.push(("status".into(), "authenticated".into()));
                out.push(("test_ip".into(), ip.to_string()));
            }
            out
        }),
    },
    ServiceDef {
        name: "censys_secret",
        env_var: "HUNTSMAN_CENSYS_SECRET",
        category: "infrastructure",
        test_url: "https://search.censys.io/api/v2/hosts/1.1.1.1",
        key_header: KeyPlacement::BasicAuth,
        rate_limit_reset_secs: 3,
        probe_parser: None,
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
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(p) = v
                .get("subscription")
                .and_then(|s| s.get("name"))
                .and_then(|v| v.as_str())
            {
                out.push(("plan".into(), p.to_string()));
            }
            if let Some(c) = v.get("requests_left").and_then(serde_json::Value::as_u64) {
                out.push(("requests_left".into(), c.to_string()));
            }
            out
        }),
    },
    ServiceDef {
        name: "abuseipdb",
        env_var: "HUNTSMAN_ABUSEIPDB_KEY",
        category: "threat_intel",
        test_url: "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1",
        key_header: KeyPlacement::Header("Key"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if v.get("data").is_some() {
                out.push(("status".into(), "authenticated".into()));
            }
            out
        }),
    },
    ServiceDef {
        name: "fullhunt",
        env_var: "HUNTSMAN_FULLHUNT_KEY",
        category: "infrastructure",
        test_url: "https://fullhunt.io/api/v1/auth/status",
        key_header: KeyPlacement::Header("X-API-KEY"),
        rate_limit_reset_secs: 60,
        probe_parser: Some(|v| {
            let mut out = Vec::new();
            if let Some(u) = v
                .get("user")
                .and_then(|u| u.get("plan"))
                .and_then(|v| v.as_str())
            {
                out.push(("plan".into(), u.to_string()));
            }
            if let Some(c) = v
                .get("user")
                .and_then(|u| u.get("credits"))
                .and_then(|u| u.get("remaining"))
                .and_then(serde_json::Value::as_u64)
            {
                out.push(("credits_remaining".into(), c.to_string()));
            }
            out
        }),
    },
    ServiceDef {
        name: "abr",
        env_var: "HUNTSMAN_ABR_GUID",
        category: "identity",
        test_url: "https://abr.business.gov.au/json/AbnDetails.aspx?abn=51824753556&callback=cb&guid=",
        key_header: KeyPlacement::QueryParam("guid"),
        rate_limit_reset_secs: 5,
        probe_parser: None,
    },
    ServiceDef {
        name: "wigle_user",
        env_var: "HUNTSMAN_WIGLE_USER",
        category: "geoint",
        test_url: "https://api.wigle.net/api/v2/profile/user",
        key_header: KeyPlacement::Header("Authorization"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    ServiceDef {
        name: "opencellid",
        env_var: "HUNTSMAN_OPENCELLID_KEY",
        category: "geoint",
        test_url: "https://opencellid.org/cell/get?key=",
        key_header: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    ServiceDef {
        name: "seon",
        env_var: "HUNTSMAN_SEON_KEY",
        category: "identity",
        test_url: "https://api.seon.io/SeonRestService/email-api/v3",
        key_header: KeyPlacement::Header("X-API-KEY"),
        rate_limit_reset_secs: 18,
        probe_parser: None,
    },
    ServiceDef {
        name: "epieos",
        env_var: "HUNTSMAN_EPIEOS_KEY",
        category: "identity",
        test_url: "https://api.epieos.com/api/v1/email",
        key_header: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 36,
        probe_parser: None,
    },
    ServiceDef {
        name: "proxycurl",
        env_var: "HUNTSMAN_PROXYCURL_KEY",
        category: "identity",
        test_url: "https://nubela.co/proxycurl/api/v2/linkedin",
        key_header: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 12,
        probe_parser: None,
    },
    ServiceDef {
        name: "opencorporates",
        env_var: "HUNTSMAN_OPENCORP_KEY",
        category: "identity",
        test_url: "https://api.opencorporates.com/v0.4/companies/search?q=test",
        key_header: KeyPlacement::QueryParam("api_token"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    // OpenSanctions — sanctions/PEP/watchlist screening (OFAC, UN, EU, DFAT
    // AU, 400+ sources). /statements is free to call (no quota charge) but
    // still requires a valid key, so it validates without spending a paid
    // /match query.
    ServiceDef {
        name: "opensanctions",
        env_var: "HUNTSMAN_OPENSANCTIONS_KEY",
        category: "identity",
        test_url: "https://api.opensanctions.org/statements",
        key_header: KeyPlacement::HeaderPrefixed("Authorization", "ApiKey "),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    // SeekNow (see-know.ru — the live domain as of 2026-08; the legacy
    // see-know.icu host is dead, verified returning HTTP 502) — direct OathNet
    // competitor. Auth: `X-API-Key: <key>` — the server answers a keyless probe
    // with "Missing API key. Use X-API-Key: seek-…" and a bad key with 401
    // `invalid_api_key` "Invalid API key" (verified live against see-know.ru; see
    // see_know/client.rs, which authenticates with AuthScheme::XApiKey). The
    // validation probe must send that header or it mis-reports a valid key as
    // invalid. /credits is a free introspection endpoint (200 with credits JSON
    // for a valid key, 401 for a bad one). `.ru` matches `client::base_url()`'s
    // primary domain (promoted 2026-07-29; `.xyz`/`.eu`/`.icu` remain fallback
    // there) so a validated key is probed against the same host the live
    // search calls actually hit.
    ServiceDef {
        name: "see_know",
        env_var: "HUNTSMAN_SEEKNOW_KEY",
        category: "breach",
        test_url: "https://see-know.ru/api/v1/credits",
        key_header: KeyPlacement::Header("X-API-Key"),
        rate_limit_reset_secs: 17,
        probe_parser: None,
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
        probe_parser: None,
    },
    // The following nine were confirmed live (module code + a real 2026-07-14
    // GET probe against each host from this environment) to be genuine
    // per-service API keys with ZERO key-pool integration: never poolable
    // (`is_poolable_service` gates on this registry), invisible on the
    // operator's key-health dashboard, and the documented
    // `HUNTSMAN_X_KEY=a,b,c` multi-key convention silently breaking (the CSV
    // split in `util/keys/io.rs` only runs for a registered `env_var`, so an
    // operator following that convention here would send the literal
    // comma-joined string as one broken credential). `github_user`/
    // `github_code_search`/`github_commits`/`urlhaus` additionally needed a
    // module-side fix (they swallowed 401/403/429 without ever calling
    // `ctx.report_key_exhausted`); `trove_au`/`fullcontact`/`domainsdb`/
    // `niamonx`/`osintcat` already reported correctly — for those five,
    // registration alone turns their existing (previously no-op) reports into
    // real pool state.
    ServiceDef {
        name: "github",
        env_var: "HUNTSMAN_GITHUB_TOKEN",
        category: "identity",
        // GitHub's documented "get the authenticated user" endpoint — 200 for
        // a valid token, 401 for an invalid/expired one, zero side effects.
        test_url: "https://api.github.com/user",
        key_header: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    // abuse.ch's URLhaus. Confirmed live (2026-07-14, real requests from this
    // environment against `modules/urlhaus/mod.rs`'s own base URL): no
    // `Auth-Key` header → 401; a present-but-wrong `Auth-Key` → 404 (its real
    // endpoints are POST-only, so this GET path doesn't cleanly echo the
    // auth verdict a valid key would get). Either way the probe lands
    // `Indeterminate`, never a false `Invalid` — the same safe trade-off
    // `dehashed`'s omission note above documents for a POST-only API.
    // abuse.ch's 2024 auth rollout unified URLhaus/ThreatFox/MalwareBazaar
    // under one Auth-Key, which is why `urlhaus`'s own code falls back to
    // `HUNTSMAN_THREATFOX_KEY` when no dedicated key is set — registered here
    // as its own service so a *dedicated* URLhaus key still pools/rotates
    // independently.
    ServiceDef {
        name: "urlhaus",
        env_var: "HUNTSMAN_ABUSECH_KEY",
        category: "threat_intel",
        test_url: "https://urlhaus-api.abuse.ch/v1/",
        key_header: KeyPlacement::Header("Auth-Key"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    ServiceDef {
        name: "hlrlookups",
        env_var: "HUNTSMAN_HLR_KEY",
        category: "identity",
        // hlrlookups.com has no keyless account-status endpoint; the real
        // lookup endpoint requires an MSISDN, so the probe uses a NANP
        // fictional-use reserved number (+1-555-01xx, ITU/NANPA-reserved for
        // testing — never a real subscriber) purely to exercise the auth
        // header, not to look anyone up.
        test_url: "https://api.hlrlookups.com/api/lookup?msisdn=%2B15555550100",
        key_header: KeyPlacement::QueryParam("api_key"),
        rate_limit_reset_secs: 300,
        probe_parser: None,
    },
    ServiceDef {
        name: "opencnam",
        env_var: "HUNTSMAN_OPENCNAM_KEY",
        category: "identity",
        // Same reserved-number rationale as `hlrlookups` above. OpenCNAM's
        // API additionally requires a (non-secret, hardcoded) `account_sid` —
        // `modules/hlr_cnam/mod.rs` always sends `account_sid=huntsman`, so the
        // probe mirrors that exact pairing.
        test_url: "https://api.opencnam.com/v2/phone/+15555550100?account_sid=huntsman",
        key_header: KeyPlacement::QueryParam("auth_token"),
        rate_limit_reset_secs: 300,
        probe_parser: None,
    },
    ServiceDef {
        name: "trove_au",
        env_var: "HUNTSMAN_TROVE_KEY",
        category: "identity",
        // The module's own real endpoint (National Library of Australia
        // newspaper search), minimised to `n=1` — a genuine, cheap live query.
        test_url: "https://api.trove.nla.gov.au/v3/result?q=test&zone=newspaper&encoding=json&n=1&reclevel=brief",
        key_header: KeyPlacement::Header("X-API-KEY"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    ServiceDef {
        name: "fullcontact",
        env_var: "HUNTSMAN_FULLCONTACT_KEY",
        category: "identity",
        // FullContact's enrichment endpoint is POST-only (`modules/fullcontact/
        // mod.rs`), so — same reasoning as `urlhaus`/`dehashed` above — a
        // GET-based probe safely lands `Indeterminate` rather than a false
        // `Invalid`; it still confirms the pool integration (rotation,
        // dashboard visibility, real `report_key_exhausted` effect) works.
        test_url: "https://api.fullcontact.com/v3/person.enrich",
        key_header: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 300,
        probe_parser: None,
    },
    ServiceDef {
        name: "domainsdb",
        env_var: "HUNTSMAN_DOMAINSDB_KEY",
        category: "infrastructure",
        // Confirmed live (2026-07-14): domainsdb.info's search endpoint does
        // NOT actually verify a bearer token's authenticity — it 401s with NO
        // `Authorization` header at all, but accepts ANY non-empty bearer
        // value and returns a normal 200 (empty result set for a garbage
        // token, same shape as a real zero-match search). A `domain=`-bearing
        // test_url would therefore make the probe read a garbage key as
        // `Valid` — a false positive, worse than the safe `Indeterminate`
        // the POST-only services above accept. Omitting the required
        // `domain` param sidesteps that: auth-presence is still checked
        // first (no header → 401), but any present token then hits this
        // param-validation 400 before the (unreliable) key check would ever
        // matter — so this probe can only land `Indeterminate`, never a
        // false `Valid` or a false `Invalid`. domainsdb.info made the key
        // mandatory in 2025 (T2.48); the module's own doc comment ("free, no
        // key") is now stale, corrected here.
        test_url: "https://api.domainsdb.info/v1/domains/search?zone=com&limit=1",
        key_header: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    ServiceDef {
        name: "niamonx",
        env_var: "HUNTSMAN_NIAMONX_KEY",
        category: "breach",
        // NiamonX's PBS v1 search is POST-only (`modules/niamonx/mod.rs`'s own
        // `BASE`) — same safe `Indeterminate`-only trade-off as `urlhaus`/
        // `fullcontact`.
        test_url: "https://dash.niamonx.io/api/v2/breaches_search",
        key_header: KeyPlacement::Header("X-API-Key"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    // OSINTCat (osintcat.net) — aggregated breach/footprint lookups. The free
    // `GET /api/user` account endpoint the `osintcat` module already uses as its
    // own credit preflight (with the `x-api-key` header, checked before every
    // paid call — see `modules/osintcat/mod.rs`'s own module doc) doubles as a
    // cheap validation probe. Deliberately NOT `/api/email-osint`: that is the
    // module's PAID deep-search endpoint, so using it here would spend a real
    // credit on every key-validation probe.
    ServiceDef {
        name: "osintcat",
        env_var: "HUNTSMAN_OSINTCAT_KEY",
        category: "breach",
        test_url: "https://www.osintcat.net/api/user",
        key_header: KeyPlacement::Header("x-api-key"),
        rate_limit_reset_secs: 60,
        probe_parser: None,
    },
    ServiceDef {
        name: "abusech",
        env_var: "HUNTSMAN_ABUSECH_KEY",
        category: "threat_intel",
        test_url: "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        key_header: KeyPlacement::Header("Auth-Key"),
        rate_limit_reset_secs: 120,
        probe_parser: None,
    },
    // Intentionally NOT registered (same reasoning as DeHashed above): `niamonx`
    // (POST `/breaches_search`, `X-API-Key` header) and `fullcontact` (POST
    // `/v3/person.enrich`, `Authorization: Bearer`) are POST-only, so the
    // GET-based validator here would spend a request and/or mis-report a valid
    // key as invalid. Their modules read HUNTSMAN_{NIAMONX,FULLCONTACT}_KEY from
    // the env directly; those keys are still surfaced in the Settings grid via
    // `KNOWN_KEYS`. Pooling/rotation is forgone for them until a POST-aware
    // validation path exists.
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
