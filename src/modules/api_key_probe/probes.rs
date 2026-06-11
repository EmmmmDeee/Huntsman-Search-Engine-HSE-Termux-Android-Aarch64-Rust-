use serde_json::Value;

type UrlBuilderFn = fn(&str) -> (String, Vec<(&'static str, String)>);

pub(super) struct Probe {
    pub(super) service: &'static str,
    pub(super) category: &'static str,
    pub(super) env_var: &'static str,
    pub(super) url_builder: UrlBuilderFn,
    pub(super) parse_info: fn(&Value) -> Vec<(String, String)>,
}

pub(super) fn probes() -> Vec<Probe> {
    vec![
        Probe {
            service: "shodan",
            category: "infrastructure",
            env_var: "HUNTSMAN_SHODAN_KEY",
            url_builder: |key| (format!("https://api.shodan.io/api-info?key={key}"), vec![]),
            parse_info: |v| {
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
            },
        },
        Probe {
            service: "virustotal",
            category: "threat_intel",
            env_var: "HUNTSMAN_VIRUSTOTAL_KEY",
            url_builder: |_key| {
                (
                    "https://www.virustotal.com/api/v3/users/me".into(),
                    vec![("x-apikey", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(data) = v.get("data").and_then(|d| d.get("attributes")) {
                    if let Some(q) = data.get("quotas")
                        && let Some(api) = q.get("api_requests_daily")
                        && let Some(allowed) =
                            api.get("allowed").and_then(serde_json::Value::as_u64)
                    {
                        out.push(("daily_quota".into(), allowed.to_string()));
                    }
                    if let Some(p) = data.get("privileges") {
                        out.push(("privileges".into(), format!("{p}")));
                    }
                }
                out
            },
        },
        Probe {
            service: "intelx",
            category: "breach",
            env_var: "HUNTSMAN_INTELX_KEY",
            url_builder: |_key| {
                (
                    "https://2.intelx.io/authenticate/info".into(),
                    vec![("x-key", String::new())],
                )
            },
            parse_info: |v| {
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
            },
        },
        Probe {
            service: "securitytrails",
            category: "infrastructure",
            env_var: "HUNTSMAN_SECTRAILS_KEY",
            url_builder: |_key| {
                (
                    "https://api.securitytrails.com/v1/ping".into(),
                    vec![("APIKEY", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("success").and_then(serde_json::Value::as_bool) == Some(true) {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "hunter",
            category: "identity",
            env_var: "HUNTSMAN_HUNTER_KEY",
            url_builder: |key| {
                (
                    format!("https://api.hunter.io/v2/account?api_key={key}"),
                    vec![],
                )
            },
            parse_info: |v| {
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
            },
        },
        Probe {
            service: "leakix",
            category: "breach",
            env_var: "HUNTSMAN_LEAKIX_KEY",
            url_builder: |_key| {
                (
                    "https://leakix.net/api/subdomains/example.com".into(),
                    vec![("api-key", String::new())],
                )
            },
            parse_info: |_v| vec![("status".into(), "authenticated".into())],
        },
        Probe {
            service: "ipqs",
            category: "threat_intel",
            env_var: "HUNTSMAN_IPQS_KEY",
            url_builder: |key| {
                (
                    format!("https://ipqualityscore.com/api/json/account/{key}"),
                    vec![],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(c) = v.get("credits").and_then(serde_json::Value::as_u64) {
                    out.push(("credits".into(), c.to_string()));
                }
                if let Some(p) = v.get("plan").and_then(|v| v.as_str()) {
                    out.push(("plan".into(), p.to_string()));
                }
                out
            },
        },
        Probe {
            service: "criminal_ip",
            category: "threat_intel",
            env_var: "HUNTSMAN_CRIMINALIP_KEY",
            url_builder: |_key| {
                (
                    "https://api.criminalip.io/v1/user/me".into(),
                    vec![("x-api-key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(data) = v.get("data")
                    && let Some(p) = data.get("plan").and_then(|v| v.as_str())
                {
                    out.push(("plan".into(), p.to_string()));
                }
                out
            },
        },
        Probe {
            service: "numverify",
            category: "identity",
            env_var: "HUNTSMAN_NUMVERIFY_KEY",
            url_builder: |key| {
                (
                    format!(
                        "https://apilayer.net/api/validate?number=14158586273&access_key={key}"
                    ),
                    vec![],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("valid").and_then(serde_json::Value::as_bool) == Some(true) {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "wigle",
            category: "geoint",
            env_var: "HUNTSMAN_WIGLE_TOKEN",
            url_builder: |_key| {
                (
                    "https://api.wigle.net/api/v2/profile/user".into(),
                    vec![("Authorization", "Basic".to_string())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(u) = v.get("userid").and_then(|v| v.as_str()) {
                    out.push(("userid".into(), u.to_string()));
                }
                out
            },
        },
        Probe {
            service: "hibp",
            category: "breach",
            env_var: "HUNTSMAN_HIBP_KEY",
            url_builder: |_key| {
                (
                    "https://haveibeenpwned.com/api/v3/breaches".into(),
                    vec![("hibp-api-key", String::new())],
                )
            },
            parse_info: |_v| vec![("status".into(), "authenticated".into())],
        },
        Probe {
            service: "abuseipdb",
            category: "threat_intel",
            env_var: "HUNTSMAN_ABUSEIPDB_KEY",
            url_builder: |_key| {
                (
                    "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1"
                        .into(),
                    vec![("Key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("data").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "censys",
            category: "infrastructure",
            env_var: "HUNTSMAN_CENSYS_KEY",
            url_builder: |_key| {
                // Censys uses HTTP Basic Auth with API_ID:API_SECRET
                // The key value should be "id:secret" format
                (
                    "https://search.censys.io/api/v2/hosts/1.1.1.1".into(),
                    vec![("_basic_auth", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(ip) = v.get("ip").and_then(|v| v.as_str()) {
                    out.push(("status".into(), "authenticated".into()));
                    out.push(("test_ip".into(), ip.to_string()));
                }
                out
            },
        },
        Probe {
            service: "binaryedge",
            category: "infrastructure",
            env_var: "HUNTSMAN_BINARYEDGE_KEY",
            url_builder: |_key| {
                (
                    "https://api.binaryedge.io/v2/user/subscription".into(),
                    vec![("X-Key", String::new())],
                )
            },
            parse_info: |v| {
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
            },
        },
        Probe {
            service: "greynoise",
            category: "threat_intel",
            env_var: "HUNTSMAN_GREYNOISE_KEY",
            url_builder: |_key| {
                // Use the paid v3 IP endpoint — community endpoint works
                // without auth and would cause false positives
                (
                    "https://api.greynoise.io/v3/ip/8.8.8.8".into(),
                    vec![("key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("ip").is_some() && v.get("seen").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                    if let Some(c) = v.get("classification").and_then(|v| v.as_str()) {
                        out.push(("classification".into(), c.to_string()));
                    }
                }
                out
            },
        },
        Probe {
            service: "fullhunt",
            category: "infrastructure",
            env_var: "HUNTSMAN_FULLHUNT_KEY",
            url_builder: |_key| {
                (
                    "https://fullhunt.io/api/v1/auth/status".into(),
                    vec![("X-API-KEY", String::new())],
                )
            },
            parse_info: |v| {
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
            },
        },
        Probe {
            service: "urlscan",
            category: "threat_intel",
            env_var: "HUNTSMAN_URLSCAN_KEY",
            url_builder: |_key| {
                (
                    "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1".into(),
                    vec![("API-Key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("results").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "passivetotal",
            category: "infrastructure",
            env_var: "HUNTSMAN_PASSIVETOTAL_KEY",
            url_builder: |_key| {
                (
                    "https://api.passivetotal.org/v2/account/quota".into(),
                    vec![("_basic_auth", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(u) = v
                    .get("user")
                    .and_then(|u| u.get("owner"))
                    .and_then(|v| v.as_str())
                {
                    out.push(("owner".into(), u.to_string()));
                }
                out
            },
        },
        Probe {
            service: "onyphe",
            category: "infrastructure",
            env_var: "HUNTSMAN_ONYPHE_KEY",
            url_builder: |_key| {
                (
                    "https://www.onyphe.io/api/v2/simple/whois/best/8.8.8.8".into(),
                    vec![("Authorization", "bearer".to_string())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("count").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "zoomeye",
            category: "infrastructure",
            env_var: "HUNTSMAN_ZOOMEYE_KEY",
            url_builder: |_key| {
                (
                    "https://api.zoomeye.org/resources-info".into(),
                    vec![("API-KEY", String::new())],
                )
            },
            parse_info: |v| {
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
            },
        },
        Probe {
            service: "netlas",
            category: "infrastructure",
            env_var: "HUNTSMAN_NETLAS_KEY",
            url_builder: |_key| {
                (
                    "https://app.netlas.io/api/users/current/".into(),
                    vec![("X-API-Key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("email").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "pulsedive",
            category: "threat_intel",
            env_var: "HUNTSMAN_PULSEDIVE_KEY",
            url_builder: |key| {
                (
                    format!("https://pulsedive.com/api/info.php?indicator=pulsedive.com&key={key}"),
                    vec![],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("indicator").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "emailrep",
            category: "identity",
            env_var: "HUNTSMAN_EMAILREP_KEY",
            url_builder: |_key| {
                (
                    "https://emailrep.io/test@example.com".into(),
                    vec![("Key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("reputation").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
    ]
}

/// The subject's brand/service domain for a validated key, for the pivot
/// `Domain` entity the probe emits. Single source of truth (complete for every
/// `probes()` entry — enforced by `every_probe_has_a_service_domain`).
///
/// This is deliberately NOT derived from the probe URL: several services are
/// validated through an unrelated API host (numverify → `apilayer.net`,
/// passivetotal → `api.passivetotal.org`), so URL-host derivation would pivot
/// into the wrong estate.
pub(super) fn service_domain(service: &str) -> Option<&'static str> {
    Some(match service {
        "shodan" => "shodan.io",
        "virustotal" => "virustotal.com",
        "intelx" => "intelx.io",
        "securitytrails" => "securitytrails.com",
        "hunter" => "hunter.io",
        "leakix" => "leakix.net",
        "ipqs" => "ipqualityscore.com",
        "criminal_ip" => "criminalip.io",
        "numverify" => "numverify.com",
        "wigle" => "wigle.net",
        "hibp" => "haveibeenpwned.com",
        "abuseipdb" => "abuseipdb.com",
        "censys" => "censys.io",
        "binaryedge" => "binaryedge.io",
        "greynoise" => "greynoise.io",
        "fullhunt" => "fullhunt.io",
        "urlscan" => "urlscan.io",
        "passivetotal" => "passivetotal.org",
        "onyphe" => "onyphe.io",
        "zoomeye" => "zoomeye.org",
        "netlas" => "netlas.io",
        "pulsedive" => "pulsedive.com",
        "emailrep" => "emailrep.io",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_probe_has_a_service_domain() {
        // The pivot Domain emission depends on this mapping being complete; a
        // new probe added without a domain here would silently lose its DNS/IP/
        // geo expansion pivot.
        for probe in probes() {
            assert!(
                service_domain(probe.service).is_some(),
                "{} has no service_domain mapping — add it so the probe still \
                 emits a pivot Domain entity",
                probe.service
            );
        }
    }

    #[test]
    fn service_domains_are_bare_registrable_hosts() {
        // No scheme, no path, no port — a clean domain the DNS/IP pipeline can
        // resolve. (Guards a typo like "https://shodan.io" or "shodan.io/api".)
        for probe in probes() {
            if let Some(d) = service_domain(probe.service) {
                assert!(
                    !d.contains("://") && !d.contains('/') && !d.contains(':'),
                    "{} domain {d:?} is not a bare host",
                    probe.service
                );
                assert!(d.contains('.'), "{} domain {d:?} has no TLD", probe.service);
            }
        }
    }

    #[test]
    fn unknown_service_has_no_domain() {
        assert_eq!(service_domain("not_a_real_service"), None);
    }
}
