//! Keyed-provider registry and probe planning.

use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Method, Request, Response, Transport, append_query_param};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPlacement {
    QueryParam(&'static str),
    Header(&'static str),
    BearerAuth,
    HeaderPrefixed(&'static str, &'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDef {
    pub name: &'static str,
    pub env_var: &'static str,
    pub category: &'static str,
    pub test_url: &'static str,
    pub probe_method: Method,
    pub key_placement: KeyPlacement,
    pub rate_limit_reset_secs: u64,
    pub probe_body: Option<&'static [u8]>,
    pub success_indicates_valid_key: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    Valid,
    Rejected,
    RateLimited,
    Indeterminate,
}

impl ProbeVerdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Rejected => "rejected",
            Self::RateLimited => "rate_limited",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub verdict: ProbeVerdict,
    pub evidence: Vec<(String, String)>,
    pub response: Response,
}

const SERVICE_DEFS: &[ServiceDef] = &[
    ServiceDef {
        name: "shodan",
        env_var: crate::environment::SHODAN_KEY_ENV,
        category: "infrastructure",
        test_url: "https://api.shodan.io/api-info",
        probe_method: Method::Get,
        key_placement: KeyPlacement::QueryParam("key"),
        rate_limit_reset_secs: 300,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "intelx",
        env_var: crate::environment::INTELX_KEY_ENV,
        category: "breach",
        test_url: "https://2.intelx.io/authenticate/info",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("x-key"),
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "securitytrails",
        env_var: crate::environment::SECTRAILS_KEY_ENV,
        category: "infrastructure",
        test_url: "https://api.securitytrails.com/v1/ping",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("APIKEY"),
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "onyphe",
        env_var: crate::environment::ONYPHE_KEY_ENV,
        category: "threat_intel",
        test_url: "https://www.onyphe.io/api/v2/summary/ip/8.8.8.8",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("apikey"),
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "certspotter",
        env_var: crate::environment::CERTSPOTTER_KEY_ENV,
        category: "infrastructure",
        test_url: "https://api.certspotter.com/v1/issuances?domain=example.com",
        probe_method: Method::Get,
        key_placement: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "netlas",
        env_var: crate::environment::NETLAS_KEY_ENV,
        category: "infrastructure",
        test_url: "https://app.netlas.io/api/responses/",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("X-API-Key"),
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "hunter",
        env_var: crate::environment::HUNTER_KEY_ENV,
        category: "identity",
        test_url: "https://api.hunter.io/v2/account",
        probe_method: Method::Get,
        key_placement: KeyPlacement::QueryParam("api_key"),
        rate_limit_reset_secs: 4,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "seeknow",
        env_var: crate::seeknow::KEY_SLOT,
        category: "breach",
        // The free key check in docs/SEEKNOW_CONTRACT.md, on the origin the client uses.
        test_url: "https://see-know.ru/api/v1/credits",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("X-API-Key"),
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "threatfox",
        env_var: crate::environment::THREATFOX_KEY_ENV,
        category: "threat_intel",
        test_url: "https://threatfox-api.abuse.ch/api/v1/",
        probe_method: Method::Post,
        key_placement: KeyPlacement::Header("Auth-Key"),
        rate_limit_reset_secs: 60,
        probe_body: Some(br#"{"query":"get_iocs","limit":1}"#),
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "numverify",
        env_var: crate::environment::NUMVERIFY_KEY_ENV,
        category: "identity",
        test_url: "https://api.apilayer.com/number_verification/validate?number=15555550100",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("apikey"),
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "criminal_ip",
        env_var: crate::environment::CRIMINALIP_KEY_ENV,
        category: "threat_intel",
        test_url: "https://api.criminalip.io/v1/user/me",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("x-api-key"),
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "virustotal",
        env_var: crate::environment::VIRUSTOTAL_KEY_ENV,
        category: "threat_intel",
        test_url: "https://www.virustotal.com/api/v3/users/me",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("x-apikey"),
        rate_limit_reset_secs: 15,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "github",
        env_var: crate::environment::GITHUB_TOKEN_ENV,
        category: "identity",
        test_url: "https://api.github.com/user",
        probe_method: Method::Get,
        key_placement: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "urlhaus",
        env_var: crate::environment::ABUSECH_KEY_ENV,
        category: "threat_intel",
        test_url: "https://urlhaus-api.abuse.ch/v1/",
        probe_method: Method::Post,
        key_placement: KeyPlacement::Header("Auth-Key"),
        rate_limit_reset_secs: 60,
        probe_body: Some(br#"{"query":"get_recent"}"#),
        success_indicates_valid_key: false,
    },
    ServiceDef {
        name: "hlrlookups",
        env_var: crate::environment::HLR_KEY_ENV,
        category: "identity",
        test_url: "https://api.hlrlookups.com/api/lookup?msisdn=%2B15555550100",
        probe_method: Method::Get,
        key_placement: KeyPlacement::QueryParam("api_key"),
        rate_limit_reset_secs: 300,
        probe_body: None,
        success_indicates_valid_key: false,
    },
    ServiceDef {
        name: "opencnam",
        env_var: crate::environment::OPENCNAM_KEY_ENV,
        category: "identity",
        test_url: "https://api.opencnam.com/v2/phone/+15555550100?account_sid=huntsman",
        probe_method: Method::Get,
        key_placement: KeyPlacement::QueryParam("auth_token"),
        rate_limit_reset_secs: 300,
        probe_body: None,
        success_indicates_valid_key: false,
    },
    ServiceDef {
        name: "trove_au",
        env_var: crate::environment::TROVE_KEY_ENV,
        category: "identity",
        test_url: "https://api.trove.nla.gov.au/v3/result?q=test&zone=newspaper&encoding=json&n=1&reclevel=brief",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("X-API-KEY"),
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "dehashed",
        env_var: crate::environment::DEHASHED_KEY_ENV,
        category: "breach",
        test_url: "https://api.dehashed.com/v2/search",
        probe_method: Method::Post,
        key_placement: KeyPlacement::Header("Dehashed-Api-Key"),
        rate_limit_reset_secs: 60,
        probe_body: Some(br#"{"query":"email:test@example.com","size":1}"#),
        success_indicates_valid_key: false,
    },
    ServiceDef {
        name: "fullcontact",
        env_var: crate::environment::FULLCONTACT_KEY_ENV,
        category: "identity",
        test_url: "https://api.fullcontact.com/v3/person.enrich",
        probe_method: Method::Post,
        key_placement: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 300,
        probe_body: Some(br#"{"email":"test@example.com"}"#),
        success_indicates_valid_key: false,
    },
    ServiceDef {
        name: "domainsdb",
        env_var: crate::environment::DOMAINSDB_KEY_ENV,
        category: "infrastructure",
        test_url: "https://api.domainsdb.info/v1/domains/search?zone=com&limit=1",
        probe_method: Method::Get,
        key_placement: KeyPlacement::BearerAuth,
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: false,
    },
    ServiceDef {
        name: "niamonx",
        env_var: crate::environment::NIAMONX_KEY_ENV,
        category: "breach",
        test_url: "https://dash.niamonx.io/api/v2/breaches_search",
        probe_method: Method::Post,
        key_placement: KeyPlacement::Header("X-API-Key"),
        rate_limit_reset_secs: 60,
        probe_body: Some(br#"{"query":"test@example.com"}"#),
        success_indicates_valid_key: false,
    },
    ServiceDef {
        name: "hibp",
        env_var: crate::environment::HUNTSMAN_HIBP_KEY_ENV,
        category: "breach",
        test_url: "https://haveibeenpwned.com/api/v3/subscription/status",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("hibp-api-key"),
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "osintcat",
        env_var: crate::environment::OSINTCAT_KEY_ENV,
        category: "breach",
        test_url: "https://www.osintcat.net/api/email-osint?query=test%40example.com",
        probe_method: Method::Get,
        key_placement: KeyPlacement::Header("x-api-key"),
        rate_limit_reset_secs: 60,
        probe_body: None,
        success_indicates_valid_key: true,
    },
];

#[must_use]
pub fn service_defs() -> &'static [ServiceDef] {
    SERVICE_DEFS
}

#[must_use]
pub fn find_service(name: &str) -> Option<&'static ServiceDef> {
    let lower = name.trim().to_ascii_lowercase();
    SERVICE_DEFS.iter().find(|service| service.name == lower)
}

#[must_use]
pub fn service_for_env(env_var: &str) -> Option<&'static ServiceDef> {
    SERVICE_DEFS
        .iter()
        .find(|service| service.env_var.eq_ignore_ascii_case(env_var))
}

#[must_use]
pub fn is_poolable_service(service: &str) -> bool {
    find_service(service).is_some()
}

#[must_use]
pub fn rate_limit_reset(service: &str) -> u64 {
    find_service(service).map_or(3_600, |service| service.rate_limit_reset_secs)
}

#[must_use]
pub fn looks_like_auth_failure_text(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    [
        "api key not found",
        "invalid api key",
        "invalid authorization",
        "invalid credentials",
        "authentication failed",
        "authentication_failed",
        "no user found for the api key",
        "api key format",
        "missing api key",
        "invalid token",
        "forbidden",
    ]
    .iter()
    .any(|phrase| lower.contains(phrase))
}

#[must_use]
pub fn body_rejects_key(service: &str, body: &serde_json::Value) -> bool {
    match service {
        "criminal_ip" => matches!(
            body.get("status").and_then(serde_json::Value::as_i64),
            Some(401 | 402 | 429)
        ),
        _ => false,
    }
}

#[must_use]
pub fn build_probe_request(service: &ServiceDef, key: &str) -> Request {
    let mut request = match service.probe_method {
        Method::Get => Request::get(service.test_url),
        Method::Head => Request {
            method: Method::Head,
            ..Request::get(service.test_url)
        },
        Method::Post => Request::post(
            service.test_url,
            service.probe_body.unwrap_or_default().to_vec(),
        ),
    };
    match &service.key_placement {
        KeyPlacement::QueryParam(name) => {
            request.url = append_query_param(&request.url, name, key);
        }
        KeyPlacement::Header(name) => {
            request = request.header(*name, key);
        }
        KeyPlacement::BearerAuth => {
            request = request.header("Authorization", format!("Bearer {key}"));
        }
        KeyPlacement::HeaderPrefixed(name, prefix) => {
            request = request.header(*name, format!("{prefix} {key}"));
        }
    }
    if service.name == "hibp" {
        request = request.header("User-Agent", crate::hibp::client::USER_AGENT);
    }
    if matches!(service.probe_method, Method::Post) && !request.body.is_empty() {
        request = request.header("Content-Type", "application/json");
    }
    request
}

#[must_use]
pub fn classify_probe_response(service: &ServiceDef, response: &Response) -> ProbeVerdict {
    if response.status == 429 {
        return ProbeVerdict::RateLimited;
    }
    if matches!(response.status, 401 | 403) {
        return ProbeVerdict::Rejected;
    }
    if response.status == 400 && looks_like_auth_failure_text(&response.text()) {
        return ProbeVerdict::Rejected;
    }
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) {
        if body_rejects_key(service.name, &json) {
            return ProbeVerdict::Rejected;
        }
    }
    if (200..300).contains(&response.status) {
        if service.success_indicates_valid_key {
            ProbeVerdict::Valid
        } else {
            ProbeVerdict::Indeterminate
        }
    } else {
        ProbeVerdict::Indeterminate
    }
}

#[must_use]
pub fn extract_probe_evidence(service: &str, response: &Response) -> Vec<(String, String)> {
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&response.body) else {
        return Vec::new();
    };
    match service {
        "shodan" => {
            let mut out = Vec::new();
            if let Some(plan) = body.get("plan").and_then(serde_json::Value::as_str) {
                out.push(("plan".to_string(), plan.to_string()));
            }
            if let Some(credits) = body
                .get("query_credits")
                .and_then(serde_json::Value::as_u64)
            {
                out.push(("query_credits".to_string(), credits.to_string()));
            }
            out
        }
        "intelx" => {
            let mut out = Vec::new();
            if let Some(name) = body.get("Name").and_then(serde_json::Value::as_str) {
                out.push(("account_name".to_string(), name.to_string()));
            }
            if let Some(balance) = body
                .get("CreditBalance")
                .and_then(serde_json::Value::as_i64)
            {
                out.push(("credit_balance".to_string(), balance.to_string()));
            }
            out
        }
        "virustotal" => {
            let mut out = Vec::new();
            if let Some(allowed) = body
                .get("data")
                .and_then(|value| value.get("attributes"))
                .and_then(|value| value.get("quotas"))
                .and_then(|value| value.get("api_requests_daily"))
                .and_then(|value| value.get("allowed"))
                .and_then(serde_json::Value::as_u64)
            {
                out.push(("daily_quota".to_string(), allowed.to_string()));
            }
            out
        }
        "hibp" => {
            let mut out = Vec::new();
            if let Some(name) = body
                .get("SubscriptionName")
                .and_then(serde_json::Value::as_str)
            {
                out.push(("subscription_name".to_string(), name.to_string()));
            }
            if let Some(rpm) = body.get("Rpm").and_then(serde_json::Value::as_u64) {
                out.push(("rpm".to_string(), rpm.to_string()));
            }
            for (field, label) in [
                ("IncludesStealerLogs", "includes_stealer_logs"),
                ("IncludesKAnon", "includes_k_anon"),
            ] {
                if let Some(enabled) = body.get(field).and_then(serde_json::Value::as_bool) {
                    out.push((label.to_string(), enabled.to_string()));
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

/// # Errors
///
/// Returns [`crate::http::TransportFailure`] when the request could not obtain an
/// HTTP response. Returns [`crate::Error::Invalid`] when the named service is not
/// present in the registry.
pub fn probe_service<T: Transport + ?Sized>(
    transport: &T,
    service_name: &str,
    key: &str,
) -> Result<ProbeResult, Error> {
    let service = find_service(service_name)
        .ok_or_else(|| Error::Invalid(format!("unknown service: {service_name}")))?;
    let request = build_probe_request(service, key);
    let fetched = fetch(
        transport,
        request,
        None,
        &FetchOptions::default(),
        service.name,
        0,
    )?;
    let response = fetched.response.ok_or_else(|| {
        Error::Network(
            fetched
                .outcome
                .detail
                .unwrap_or_else(|| format!("{:?}", fetched.outcome.kind)),
        )
    })?;
    let verdict = classify_probe_response(service, &response);
    let evidence = extract_probe_evidence(service.name, &response);
    Ok(ProbeResult {
        verdict,
        evidence,
        response,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::http::TransportFailure;

    struct FakeTransport {
        response: Response,
        seen: RefCell<Vec<Request>>,
    }

    impl Transport for FakeTransport {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.clone());
            Ok(self.response.clone())
        }
    }

    #[test]
    fn service_lookup_and_poolability_are_case_insensitive() {
        assert!(find_service("SHODAN").is_some());
        assert!(service_for_env("huntsman_shodan_key").is_some());
        assert!(is_poolable_service("github"));
        assert!(!is_poolable_service("generic_hex"));
        assert_eq!(rate_limit_reset("virustotal"), 15);
        assert_eq!(rate_limit_reset("missing-service"), 3_600);
    }

    #[test]
    fn seeknow_is_probed_on_the_client_origin_and_slot() {
        let seeknow = find_service("seeknow").expect("seeknow is a registered service");
        assert_eq!(seeknow.env_var, crate::seeknow::KEY_SLOT);
        assert_eq!(
            seeknow.test_url,
            format!("{}/credits", crate::seeknow::API_BASE)
        );
        assert_eq!(seeknow.probe_method, Method::Get);
        assert_eq!(
            service_for_env(crate::seeknow::KEY_SLOT).map(|service| service.name),
            Some("seeknow")
        );
    }

    #[test]
    fn builds_probe_requests_with_correct_auth_placement() {
        let github = find_service("github").expect("github");
        let github_request = build_probe_request(github, "test-key");
        assert_eq!(
            github_request.header_value("authorization"),
            Some("Bearer test-key")
        );

        let seeknow = find_service("seeknow").expect("seeknow");
        let seeknow_request = build_probe_request(seeknow, "test-key");
        assert_eq!(seeknow_request.header_value("x-api-key"), Some("test-key"));

        let opencnam = find_service("opencnam").expect("opencnam");
        let opencnam_request = build_probe_request(opencnam, "test-key");
        assert!(opencnam_request.url.contains("auth_token=test-key"));
        assert!(opencnam_request.url.contains("account_sid=huntsman"));

        let threatfox = find_service("threatfox").expect("threatfox");
        let threatfox_request = build_probe_request(threatfox, "test-key");
        assert_eq!(threatfox_request.method, Method::Post);
        assert_eq!(
            threatfox_request.body,
            br#"{"query":"get_iocs","limit":1}"#.to_vec()
        );
    }

    #[test]
    fn classifies_probe_responses_conservatively() {
        let shodan = find_service("shodan").expect("shodan");
        assert_eq!(
            classify_probe_response(
                shodan,
                &Response {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                    truncated: false,
                }
            ),
            ProbeVerdict::Valid
        );
        assert_eq!(
            classify_probe_response(
                shodan,
                &Response {
                    status: 429,
                    headers: Vec::new(),
                    body: Vec::new(),
                    truncated: false,
                }
            ),
            ProbeVerdict::RateLimited
        );
        let dehashed = find_service("dehashed").expect("dehashed");
        assert_eq!(
            classify_probe_response(
                dehashed,
                &Response {
                    status: 200,
                    headers: Vec::new(),
                    body: br#"{"ok":true}"#.to_vec(),
                    truncated: false,
                }
            ),
            ProbeVerdict::Indeterminate
        );
    }

    #[test]
    fn extracts_probe_evidence_from_known_shapes() {
        let shodan = Response {
            status: 200,
            headers: Vec::new(),
            body: br#"{"plan":"dev","query_credits":42}"#.to_vec(),
            truncated: false,
        };
        assert_eq!(
            extract_probe_evidence("shodan", &shodan),
            vec![
                ("plan".to_string(), "dev".to_string()),
                ("query_credits".to_string(), "42".to_string())
            ]
        );
    }

    #[test]
    fn probe_service_uses_transport_with_shared_types() {
        let fake = FakeTransport {
            response: Response {
                status: 200,
                headers: Vec::new(),
                body: br#"{"plan":"dev"}"#.to_vec(),
                truncated: false,
            },
            seen: RefCell::new(Vec::new()),
        };
        let result = probe_service(&fake, "shodan", "test-key").expect("probe");
        assert_eq!(result.verdict, ProbeVerdict::Valid);
        assert_eq!(fake.seen.borrow().len(), 1);
        assert!(fake.seen.borrow()[0].url.contains("key=test-key"));
    }
}
