//! Keyed-provider registry and probe planning.

use crate::api_leg::KeyPlace;
use crate::credential_origin::AuthenticationAuthority;
use crate::error::Error;
use crate::fetch::{Credential, FetchOptions, fetch};
use crate::http::{Method, Request, Response, Transport};
use crate::keys::Secret;
use crate::source_outcome::{SourceOutcomeKind, classify_fetch};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDef {
    pub name: &'static str,
    pub env_var: &'static str,
    pub test_url: &'static str,
    pub probe_method: Method,
    pub key_placement: KeyPlace,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub verdict: ProbeVerdict,
    pub evidence: Vec<(String, String)>,
}

const SERVICE_DEFS: &[ServiceDef] = &[
    ServiceDef {
        name: "shodan",
        env_var: crate::environment::SHODAN_KEY_ENV,
        test_url: "https://api.shodan.io/api-info",
        probe_method: Method::Get,
        key_placement: KeyPlace::Query("key"),
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "securitytrails",
        env_var: crate::environment::SECTRAILS_KEY_ENV,
        test_url: "https://api.securitytrails.com/v1/ping",
        probe_method: Method::Get,
        key_placement: KeyPlace::Header("APIKEY"),
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "certspotter",
        env_var: crate::environment::CERTSPOTTER_KEY_ENV,
        test_url: "https://api.certspotter.com/v1/issuances?domain=example.com",
        probe_method: Method::Get,
        key_placement: KeyPlace::Bearer,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "netlas",
        env_var: crate::environment::NETLAS_KEY_ENV,
        test_url: "https://app.netlas.io/api/responses/",
        probe_method: Method::Get,
        key_placement: KeyPlace::Header("X-API-Key"),
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "hunter",
        env_var: crate::environment::HUNTER_KEY_ENV,
        test_url: "https://api.hunter.io/v2/account",
        probe_method: Method::Get,
        key_placement: KeyPlace::Header("X-API-KEY"),
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "seeknow",
        env_var: crate::seeknow::KEY_SLOT,
        // The free key check in docs/SEEKNOW_CONTRACT.md, on the origin the client uses.
        test_url: "https://see-know.ru/api/v1/credits",
        probe_method: Method::Get,
        key_placement: KeyPlace::Header("X-API-Key"),
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "threatfox",
        env_var: crate::environment::THREATFOX_KEY_ENV,
        test_url: "https://threatfox-api.abuse.ch/api/v1/",
        probe_method: Method::Post,
        key_placement: KeyPlace::Header("Auth-Key"),
        probe_body: Some(br#"{"query":"get_iocs","limit":1}"#),
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "numverify",
        env_var: crate::environment::NUMVERIFY_KEY_ENV,
        test_url: "https://api.apilayer.com/number_verification/validate?number=15555550100",
        probe_method: Method::Get,
        key_placement: KeyPlace::Header("apikey"),
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "virustotal",
        env_var: crate::environment::VIRUSTOTAL_KEY_ENV,
        test_url: "https://www.virustotal.com/api/v3/users/me",
        probe_method: Method::Get,
        key_placement: KeyPlace::Header("x-apikey"),
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "github",
        env_var: crate::environment::GITHUB_TOKEN_ENV,
        test_url: "https://api.github.com/user",
        probe_method: Method::Get,
        key_placement: KeyPlace::Bearer,
        probe_body: None,
        success_indicates_valid_key: true,
    },
    ServiceDef {
        name: "urlhaus",
        env_var: crate::environment::ABUSECH_KEY_ENV,
        test_url: "https://urlhaus-api.abuse.ch/v1/",
        probe_method: Method::Post,
        key_placement: KeyPlace::Header("Auth-Key"),
        probe_body: Some(br#"{"query":"get_recent"}"#),
        success_indicates_valid_key: false,
    },
    ServiceDef {
        name: "dehashed",
        env_var: crate::environment::DEHASHED_KEY_ENV,
        test_url: "https://api.dehashed.com/v2/search",
        probe_method: Method::Post,
        key_placement: KeyPlace::Header("Dehashed-Api-Key"),
        probe_body: Some(br#"{"query":"email:test@example.com","size":1}"#),
        success_indicates_valid_key: false,
    },
    ServiceDef {
        name: "hibp",
        env_var: crate::environment::HUNTSMAN_HIBP_KEY_ENV,
        test_url: "https://haveibeenpwned.com/api/v3/subscription/status",
        probe_method: Method::Get,
        key_placement: KeyPlace::Header("hibp-api-key"),
        probe_body: None,
        success_indicates_valid_key: true,
    },
];

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

/// The probe request without its key: [`probe_service`] adds the key as the request is sent,
/// through a [`Credential`] bound to the `test_url`'s origin.
#[must_use]
pub fn build_probe_request(service: &ServiceDef) -> Request {
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
    // A challenge page is a wall at any status (see `classify_fetch`): the key was never checked.
    if classify_fetch(response.status, &response.text_view()) == SourceOutcomeKind::BotWaf {
        return ProbeVerdict::Indeterminate;
    }
    if matches!(response.status, 401 | 403) {
        return ProbeVerdict::Rejected;
    }
    if response.status == 400 && looks_like_auth_failure_text(&response.text()) {
        return ProbeVerdict::Rejected;
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

/// Send `secret` to the service's `test_url` as its `key_placement` says, through a
/// [`Credential`] bound to that URL's origin, with redirects not followed: a 3xx with a usable
/// `Location` is the answer, which [`classify_probe_response`] reads as indeterminate.
///
/// # Errors
///
/// Returns [`crate::Error::Network`] when the request obtains no HTTP response, is refused by
/// the egress policy, or gets a 3xx whose `Location` does not resolve to an http(s) URL with a
/// host; `credential-status --probe` prints each as `probe=unavailable`. Returns
/// [`crate::Error::Invalid`] when the named service is not present in the registry.
pub fn probe_service<T: Transport + ?Sized>(
    transport: &T,
    service_name: &str,
    secret: &Secret,
) -> Result<ProbeResult, Error> {
    let service = find_service(service_name)
        .ok_or_else(|| Error::Invalid(format!("unknown service: {service_name}")))?;
    let now = crate::clock::unix_now();
    let authority = AuthenticationAuthority::configured_slot(service.name, service.env_var, now)?;
    let style = service.key_placement.auth_style();
    let credential = Credential::new(authority, secret.clone(), style)?;
    let fetched = fetch(
        transport,
        build_probe_request(service),
        Some(&credential),
        &FetchOptions::no_redirects(),
        service.name,
        now,
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
    Ok(ProbeResult { verdict, evidence })
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

    fn answering(status: u16, body: &str) -> FakeTransport {
        FakeTransport {
            response: Response {
                status,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
                truncated: false,
            },
            seen: RefCell::new(Vec::new()),
        }
    }

    fn test_key() -> Secret {
        Secret::new("test-key").expect("a configured value")
    }

    /// A Cloudflare interstitial, as HIBP's edge serves it.
    const CHALLENGE_PAGE: &str = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cloudflare <script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1\"></script></body></html>";

    #[test]
    fn service_lookup_is_case_insensitive() {
        assert!(find_service("SHODAN").is_some());
        assert!(service_for_env("huntsman_shodan_key").is_some());
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
        let sent = |service: &str| {
            let fake = answering(200, "{}");
            probe_service(&fake, service, &test_key()).expect("probe");
            let seen = fake.seen.borrow();
            assert_eq!(seen.len(), 1, "{service}");
            seen[0].clone()
        };

        let github_request = sent("github");
        assert_eq!(
            github_request.header_value("authorization"),
            Some("Bearer test-key")
        );

        let seeknow_request = sent("seeknow");
        assert_eq!(seeknow_request.header_value("x-api-key"), Some("test-key"));

        let hunter_request = sent("hunter");
        assert_eq!(hunter_request.header_value("x-api-key"), Some("test-key"));
        assert!(
            !hunter_request.url.contains("test-key"),
            "{}",
            hunter_request.url
        );

        let threatfox_request = sent("threatfox");
        assert_eq!(threatfox_request.method, Method::Post);
        assert_eq!(threatfox_request.header_value("auth-key"), Some("test-key"));
        assert_eq!(
            threatfox_request.header_value("content-type"),
            Some("application/json")
        );
        assert_eq!(
            threatfox_request.body,
            br#"{"query":"get_iocs","limit":1}"#.to_vec()
        );
    }

    #[test]
    fn every_probe_row_matches_its_client() {
        // Each keyed client declares its slot, origin and key placement in its `API`; the probe
        // must send the key where the lookup sends it, on the origin the lookup uses.
        for (source, slot, api) in [
            (
                crate::shodan::SOURCE,
                crate::shodan::KEY_SLOT,
                crate::shodan::API,
            ),
            (
                crate::securitytrails::SOURCE,
                crate::securitytrails::KEY_SLOT,
                crate::securitytrails::API,
            ),
            (
                crate::netlas::SOURCE,
                crate::netlas::KEY_SLOT,
                crate::netlas::API,
            ),
            (
                crate::numverify::SOURCE,
                crate::numverify::KEY_SLOT,
                crate::numverify::API,
            ),
            (
                crate::threatfox::SOURCE,
                crate::threatfox::KEY_SLOT,
                crate::threatfox::API,
            ),
            (
                crate::urlhaus::SOURCE,
                crate::urlhaus::KEY_SLOT,
                crate::urlhaus::API,
            ),
            (
                crate::virustotal::SOURCE,
                crate::virustotal::KEY_SLOT,
                crate::virustotal::API,
            ),
            (
                crate::hunter::SOURCE,
                crate::hunter::KEY_SLOT,
                crate::hunter::API,
            ),
            (
                crate::certspotter::SOURCE,
                crate::certspotter::KEY_SLOT,
                crate::certspotter::API,
            ),
        ] {
            let service = find_service(source).unwrap_or_else(|| panic!("{source} registered"));
            let key = api.key.unwrap_or_else(|| panic!("{source} is keyed"));
            assert_eq!(service.env_var, slot, "{source}");
            assert_eq!(service.key_placement, key.place, "{source}");
            assert_eq!(
                crate::http::origin_of(service.test_url).as_deref(),
                Some(api.origin),
                "{source}"
            );
        }
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
    fn a_key_the_provider_refuses_is_rejected() {
        // Only a challenge page keeps a 401, a 403 or a 400 that names an auth failure from
        // counting as a rejection; a 400 about anything else says nothing about the key.
        let hibp = find_service("hibp").expect("hibp");
        for (status, body, verdict) in [
            (
                401,
                r#"{"statusCode":401,"message":"Access denied due to invalid hibp-api-key."}"#,
                ProbeVerdict::Rejected,
            ),
            (403, "forbidden: key revoked", ProbeVerdict::Rejected),
            (400, "Invalid API key", ProbeVerdict::Rejected),
            (400, "query is malformed", ProbeVerdict::Indeterminate),
        ] {
            let response = Response {
                status,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
                truncated: false,
            };
            assert_eq!(
                classify_probe_response(hibp, &response),
                verdict,
                "HTTP {status} {body}"
            );
        }
    }

    #[test]
    fn a_challenge_page_is_indeterminate_at_any_status() {
        // An edge's interstitial never reached the provider, so it says nothing about the key:
        // served with 403 it is not a rejection, served with 200 it is not a valid key.
        let hibp = find_service("hibp").expect("hibp");
        for status in [403, 200] {
            let page = Response {
                status,
                headers: Vec::new(),
                body: CHALLENGE_PAGE.as_bytes().to_vec(),
                truncated: false,
            };
            assert_eq!(
                classify_probe_response(hibp, &page),
                ProbeVerdict::Indeterminate,
                "HTTP {status}"
            );
        }
        // 429 still comes first, as in `classify_fetch`.
        let throttled = Response {
            status: 429,
            headers: Vec::new(),
            body: CHALLENGE_PAGE.as_bytes().to_vec(),
            truncated: false,
        };
        assert_eq!(
            classify_probe_response(hibp, &throttled),
            ProbeVerdict::RateLimited
        );
    }

    #[test]
    fn probe_service_does_not_follow_a_redirect() {
        // The provider's own answer decides: a 302 to a page that answers 200 is not a valid key.
        struct Redirecting {
            seen: RefCell<Vec<Request>>,
        }
        impl Transport for Redirecting {
            fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
                let first = self.seen.borrow().is_empty();
                self.seen.borrow_mut().push(request.clone());
                Ok(if first {
                    Response {
                        status: 302,
                        headers: vec![("Location".into(), "/login".into())],
                        body: Vec::new(),
                        truncated: false,
                    }
                } else {
                    Response {
                        status: 200,
                        headers: Vec::new(),
                        body: br#"{"plan":"dev"}"#.to_vec(),
                        truncated: false,
                    }
                })
            }
        }
        let fake = Redirecting {
            seen: RefCell::new(Vec::new()),
        };
        let result = probe_service(&fake, "shodan", &test_key()).expect("probe");
        assert_eq!(result.verdict, ProbeVerdict::Indeterminate);
        assert!(result.evidence.is_empty(), "{:?}", result.evidence);
        assert_eq!(fake.seen.borrow().len(), 1, "the redirect is not followed");
    }

    #[test]
    fn a_redirect_to_an_unusable_location_is_no_answer() {
        // A 3xx whose `Location` does not resolve to an http(s) URL with a host is not followed —
        // the target is never fetched — but the 3xx response was received, so it is the answer,
        // read like any other redirect: not a recognizable probe answer, hence indeterminate, not
        // an error that would read as "nothing reached the network".
        let fake = FakeTransport {
            response: Response {
                status: 302,
                headers: vec![("Location".into(), "mailto:ops@example.com".into())],
                body: Vec::new(),
                truncated: false,
            },
            seen: RefCell::new(Vec::new()),
        };
        let result = probe_service(&fake, "shodan", &test_key()).expect("probe");
        assert_eq!(result.verdict, ProbeVerdict::Indeterminate);
        assert_eq!(fake.seen.borrow().len(), 1, "the redirect is not followed");
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
        let fake = answering(200, r#"{"plan":"dev"}"#);
        let result = probe_service(&fake, "shodan", &test_key()).expect("probe");
        assert_eq!(result.verdict, ProbeVerdict::Valid);
        assert_eq!(fake.seen.borrow().len(), 1);
        assert!(fake.seen.borrow()[0].url.contains("key=test-key"));
    }
}
