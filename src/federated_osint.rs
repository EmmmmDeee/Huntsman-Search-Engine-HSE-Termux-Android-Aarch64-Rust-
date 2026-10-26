//! Independent, read-only OSINT federation for indexed X links and Base account state.
//!
//! No borrowed backend access, shared provider credentials or transaction signing.
//! A search result is a discovery lead, not corroboration of a claim or identity.

use serde::Serialize;
use serde_json::{Value, json};

use crate::error::Error;
use crate::fetch::{Credential, FetchOptions, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, append_query_param, parse_http_uri};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::web_query::{self, SearchHit};

pub const BASE_PUBLIC_RPC: &str = "https://mainnet.base.org";
pub const BASE_ALCHEMY_RPC: &str = "https://base-mainnet.g.alchemy.com/v2";
pub const BASE_ALCHEMY_ORIGIN: &str = "https://base-mainnet.g.alchemy.com:443";
pub const ALCHEMY_KEY_SLOT: &str = "HUNTSMAN_ALCHEMY_KEY";
pub const X_API_URL: &str = "https://api.x.com/2/tweets/search/recent";
pub const X_API_ORIGIN: &str = "https://api.x.com:443";
pub const X_BEARER_SLOT: &str = "HUNTSMAN_X_BEARER_TOKEN";
const BASE_CHAIN_ID: u64 = 8453;
const BASE_MODULE: &str = "base_rpc";

/// URLs are discovery leads only. The indexed mode does not access Grok/X's private index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XDiscoveryReport {
    pub source: &'static str,
    pub evidence_role: &'static str,
    pub observed_at_unix: u64,
    pub hits: Vec<SearchHit>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

fn checked_query(query: &str) -> Result<&str, Error> {
    let query = query.trim();
    if query.is_empty() || query.len() > 460 || query.chars().any(char::is_control) {
        return Err(Error::invalid(
            "X query must be 1..460 bytes without control characters",
        ));
    }
    Ok(query)
}

/// Public site-index search with no API key, credit consumption, or inference about ownership.
///
/// # Errors
/// Invalid query or prohibited outbound request.
pub fn search_indexed_x<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    now_unix: u64,
) -> Result<XDiscoveryReport, Error> {
    let query = checked_query(query)?;
    let indexed = web_query::search(transport, &format!("site:x.com {query}"), now_unix)?;
    let mut outcomes = indexed.outcomes;
    let mut hits = Vec::new();
    for hit in indexed.hits {
        if is_public_x_url(&hit.url) && !hits.iter().any(|prior: &SearchHit| prior.url == hit.url) {
            hits.push(hit);
        }
    }
    // Legacy links can still be indexed under twitter.com. Search only when
    // the first pass yielded no X links and at least one index was reachable.
    if hits.is_empty() && outcomes.iter().any(|o| o.kind.is_accepted()) {
        let legacy = web_query::search(transport, &format!("site:twitter.com {query}"), now_unix)?;
        for hit in legacy.hits {
            if is_public_x_url(&hit.url)
                && !hits.iter().any(|prior: &SearchHit| prior.url == hit.url)
            {
                hits.push(hit);
            }
        }
        outcomes.extend(legacy.outcomes);
    }
    Ok(XDiscoveryReport {
        source: "public_web_indexes",
        evidence_role: "unverified_discovery_lead",
        observed_at_unix: now_unix,
        hits,
        outcomes,
    })
}

fn is_public_x_url(url: &str) -> bool {
    let Ok(uri) = parse_http_uri(url) else {
        return false;
    };
    uri.scheme_str() == Some("https")
        && matches!(
            uri.host().map(str::to_ascii_lowercase).as_deref(),
            Some("x.com" | "www.x.com" | "twitter.com" | "www.twitter.com" | "mobile.twitter.com")
        )
}

/// An explicitly operator-authorized official X API search. Uses one bounded recent-search
/// page (at most ten posts); there is no implicit paid API escalation from indexed search.
///
/// # Errors
/// Invalid query or prohibited outbound request.
pub fn search_official_x<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    query: &str,
    now_unix: u64,
) -> Result<XDiscoveryReport, Error> {
    let query = checked_query(query)?;
    let url = append_query_param(X_API_URL, "query", query);
    let url = append_query_param(&url, "max_results", "10");
    let fetched = fetch(
        transport,
        Request::get(url).header("accept", "application/json"),
        Some(credential),
        &FetchOptions::no_redirects().paced(),
        "x_recent_search",
        now_unix,
    )?;
    let mut report = XDiscoveryReport {
        source: "official_x_recent_search",
        evidence_role: "public_post_link_lead_not_verified_attribution",
        observed_at_unix: now_unix,
        hits: Vec::new(),
        outcomes: Vec::new(),
    };
    let decoded = whole_response(&fetched, "X API").and_then(|response| {
        answer(&fetched, "X API")?;
        decode_json::<Value>(response, "x_recent_search", now_unix, "X API")
    });
    let value = match decoded {
        Ok(value) => value,
        Err(outcome) => {
            report.outcomes.push(outcome);
            return Ok(report);
        }
    };
    let has_errors = value
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|e| !e.is_empty());
    let mut invalid_posts = false;
    if let Some(data) = value.get("data").and_then(Value::as_array) {
        for post in data.iter().take(10) {
            if let Some(id) = post.get("id").and_then(Value::as_str).filter(|id| {
                !id.is_empty() && id.len() <= 24 && id.bytes().all(|b| b.is_ascii_digit())
            }) {
                report.hits.push(SearchHit {
                    engine: "official_x_recent_search".to_owned(),
                    url: format!("https://x.com/i/web/status/{id}"),
                });
            } else {
                invalid_posts = true;
            }
        }
    }
    let malformed = invalid_posts
        || value.get("data").is_some_and(|d| !d.is_array())
        || (value
            .get("data")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
            && report.hits.is_empty());
    let result_count = value
        .get("meta")
        .and_then(|v| v.get("result_count"))
        .and_then(Value::as_u64);
    let outcome = if has_errors {
        SourceExecutionOutcome::failed(
            "x_recent_search",
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(200),
            "X API returned errors; any links are partial leads",
        )
    } else if malformed || (report.hits.is_empty() && result_count.is_some_and(|n| n > 0)) {
        SourceExecutionOutcome::failed(
            "x_recent_search",
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(200),
            "X API returned inconsistent or malformed result data",
        )
    } else if report.hits.is_empty() {
        SourceExecutionOutcome::valid_zero("x_recent_search", now_unix).with_http_status(200)
    } else {
        SourceExecutionOutcome::success("x_recent_search", now_unix, report.hits.len())
            .with_http_status(200)
    };
    report.outcomes.push(outcome);
    Ok(report)
}

/// Exact Base mainnet balance. Never attributes a wallet to a person and never signs anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaseBalanceReport {
    pub address: String,
    pub chain: &'static str,
    pub chain_id: Option<u64>,
    pub provider: &'static str,
    pub observed_at_unix: u64,
    pub balance_wei: Option<String>,
    pub balance_eth: Option<String>,
    pub block_height: Option<u64>,
    pub block_tag: String,
    pub evidence_role: &'static str,
    pub outcome: SourceExecutionOutcome,
}

fn valid_evm_address(address: &str) -> bool {
    address.len() == 42
        && address.starts_with("0x")
        && address.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
}

/// Inspect Base using its keyless public endpoint, or operator-owned Alchemy credentials.
/// Alchemy credentials must be a bearer token origin-bound to `BASE_ALCHEMY_ORIGIN`; callers
/// should use Huntsman's `Credential` constructor rather than adding headers manually.
/// A bad Alchemy response is surfaced, not silently retried on an unrelated endpoint.
///
/// # Errors
/// Invalid wallet address or outbound policy refusal.
pub fn base_balance<T: Transport + ?Sized>(
    transport: &T,
    address: &str,
    alchemy: Option<&Credential>,
    now_unix: u64,
) -> Result<BaseBalanceReport, Error> {
    if !valid_evm_address(address) {
        return Err(Error::invalid_value(
            "expected 0x-prefixed, 20-byte hexadecimal EVM address",
        ));
    }
    let (provider, endpoint) = if alchemy.is_some() {
        ("alchemy_operator_key", BASE_ALCHEMY_RPC)
    } else {
        ("base_public_rpc", BASE_PUBLIC_RPC)
    };
    let mut report = BaseBalanceReport {
        address: address.to_ascii_lowercase(),
        chain: "base_mainnet",
        chain_id: None,
        provider,
        observed_at_unix: now_unix,
        balance_wei: None,
        balance_eth: None,
        block_height: None,
        block_tag: "latest".to_owned(),
        evidence_role: "onchain_observation_not_wallet_ownership_attribution",
        outcome: SourceExecutionOutcome::failed(
            BASE_MODULE,
            now_unix,
            SourceOutcomeKind::Inconclusive,
            None,
            "RPC not checked",
        ),
    };
    let Some(chain_hex) = rpc_read(
        transport,
        endpoint,
        alchemy,
        "eth_chainId",
        json!([]),
        now_unix,
        &mut report,
    )?
    else {
        return Ok(report);
    };
    let Some(chain_id) = parse_quantity(&chain_hex).and_then(|n| n.parse::<u64>().ok()) else {
        report.outcome = schema_drift(now_unix, "invalid RPC chain ID");
        return Ok(report);
    };
    report.chain_id = Some(chain_id);
    if chain_id != BASE_CHAIN_ID {
        report.outcome = schema_drift(now_unix, "RPC chain ID is not Base mainnet");
        return Ok(report);
    }
    // Pin the observation to a numbered block, not a moving 'latest' head.
    let Some(height_hex) = rpc_read(
        transport,
        endpoint,
        alchemy,
        "eth_blockNumber",
        json!([]),
        now_unix,
        &mut report,
    )?
    else {
        return Ok(report);
    };
    let Some(height) = parse_quantity(&height_hex).and_then(|n| n.parse::<u64>().ok()) else {
        report.outcome = schema_drift(now_unix, "RPC block height is invalid");
        return Ok(report);
    };
    report.block_height = Some(height);
    report.block_tag = height_hex;
    let block_tag = report.block_tag.clone();
    let Some(balance_hex) = rpc_read(
        transport,
        endpoint,
        alchemy,
        "eth_getBalance",
        json!([report.address.as_str(), block_tag]),
        now_unix,
        &mut report,
    )?
    else {
        return Ok(report);
    };
    let Some(wei) = parse_quantity(&balance_hex) else {
        report.outcome = schema_drift(now_unix, "invalid RPC balance quantity");
        return Ok(report);
    };
    report.balance_eth = Some(wei_to_eth(&wei));
    report.balance_wei = Some(wei);
    report.outcome =
        SourceExecutionOutcome::success(BASE_MODULE, now_unix, 1).with_http_status(200);
    Ok(report)
}

fn schema_drift(now: u64, reason: &'static str) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(
        BASE_MODULE,
        now,
        SourceOutcomeKind::SchemaDrift,
        Some(200),
        reason,
    )
}

fn rpc_read<T: Transport + ?Sized>(
    transport: &T,
    endpoint: &str,
    credential: Option<&Credential>,
    method: &'static str,
    params: Value,
    now: u64,
    report: &mut BaseBalanceReport,
) -> Result<Option<String>, Error> {
    let body = json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params});
    let request = Request::post(endpoint, body.to_string().into_bytes())
        .header("accept", "application/json")
        .header("content-type", "application/json");
    let fetched = fetch(
        transport,
        request,
        credential,
        &FetchOptions::no_redirects().paced(),
        BASE_MODULE,
        now,
    )?;
    let decoded = whole_response(&fetched, "Base RPC").and_then(|response| {
        answer(&fetched, "Base RPC")?;
        decode_json::<Value>(response, BASE_MODULE, now, "Base RPC")
    });
    let value = match decoded {
        Ok(value) => value,
        Err(outcome) => {
            report.outcome = outcome;
            return Ok(None);
        }
    };
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || value.get("id").and_then(Value::as_u64) != Some(1)
        || value.get("error").is_some()
    {
        report.outcome = schema_drift(now, "RPC error or invalid envelope");
        return Ok(None);
    }
    let Some(result) = value.get("result").and_then(Value::as_str) else {
        report.outcome = schema_drift(now, "RPC result missing");
        return Ok(None);
    };
    Ok(Some(result.to_owned()))
}

/// Exact uint256 to decimal without floating point; refuses noncanonical quantities.
fn parse_quantity(raw: &str) -> Option<String> {
    let digits = raw.strip_prefix("0x")?;
    if digits.is_empty()
        || digits.len() > 64
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let mut decimal = vec![0_u8];
    for digit in digits.bytes() {
        let digit = digit.to_ascii_lowercase();
        let mut carry = if digit.is_ascii_digit() {
            digit - b'0'
        } else {
            digit - b'a' + 10
        };
        for cell in &mut decimal {
            let n = u16::from(*cell) * 16 + u16::from(carry);
            *cell = (n % 10) as u8;
            carry = (n / 10) as u8;
        }
        while carry != 0 {
            decimal.push(carry % 10);
            carry /= 10;
        }
    }
    Some(
        decimal
            .iter()
            .rev()
            .map(|n| char::from(b'0' + *n))
            .collect(),
    )
}

fn wei_to_eth(wei: &str) -> String {
    let mut padded = wei.to_owned();
    if padded.len() <= 18 {
        padded.insert_str(0, &"0".repeat(19 - padded.len()));
    }
    let split = padded.len() - 18;
    let fraction = padded[split..].trim_end_matches('0');
    if fraction.is_empty() {
        padded[..split].to_owned()
    } else {
        format!("{}.{}", &padded[..split], fraction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Response, TransportFailure};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        responses: Mutex<Vec<Response>>,
        requests: Mutex<Vec<Request>>,
    }

    impl Fake {
        fn new(bodies: &[&str]) -> Self {
            Self {
                responses: Mutex::new(
                    bodies
                        .iter()
                        .rev()
                        .map(|body| Response {
                            status: 200,
                            headers: vec![(
                                "content-type".to_owned(),
                                "application/json".to_owned(),
                            )],
                            body: body.as_bytes().to_vec(),
                            truncated: false,
                        })
                        .collect(),
                ),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            Ok(self
                .responses
                .lock()
                .expect("responses")
                .pop()
                .expect("request exceeds fixture"))
        }
    }

    #[test]
    fn quantities_remain_exact() {
        assert_eq!(parse_quantity("0x0").as_deref(), Some("0"));
        assert_eq!(
            parse_quantity("0xde0b6b3a7640000").as_deref(),
            Some("1000000000000000000")
        );
        assert_eq!(wei_to_eth("1000000000000000000"), "1");
        assert_eq!(wei_to_eth("1"), "0.000000000000000001");
        assert!(parse_quantity("0x00").is_none());
        assert!(parse_quantity("0x-1").is_none());
        assert!(parse_quantity(&format!("0x{}", "f".repeat(65))).is_none());
    }

    #[test]
    fn verified_base_chain_before_balance() {
        let fake = Fake::new(&[
            r#"{"jsonrpc":"2.0","id":1,"result":"0x2105"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x123"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}"#,
        ]);
        let report = base_balance(
            &fake,
            "0x0000000000000000000000000000000000000001",
            None,
            100,
        )
        .expect("read");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(report.balance_eth.as_deref(), Some("1"));
        assert_eq!(report.chain_id, Some(8453));
        assert_eq!(report.block_height, Some(291));
        assert_eq!(report.block_tag, "0x123");
        let requests = fake.requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert!(String::from_utf8_lossy(&requests[2].body).contains("0x123"));
        assert!(
            requests
                .iter()
                .all(|request| request.url == BASE_PUBLIC_RPC)
        );
    }

    #[test]
    fn wrong_chain_never_queries_balance() {
        let fake = Fake::new(&[r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#]);
        let report = base_balance(
            &fake,
            "0x0000000000000000000000000000000000000001",
            None,
            100,
        )
        .expect("read");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
        assert_eq!(fake.requests.lock().expect("requests").len(), 1);
    }

    #[test]
    fn official_x_uses_pinned_auth_and_filters_invalid_post_identifiers() {
        use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
        use crate::fetch::AuthStyle;
        use crate::keys::Secret;
        let fake = Fake::new(&[
            r#"{"data":[{"id":"123456789"},{"id":"123/evil"}],"meta":{"result_count":2}}"#,
        ]);
        let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
            provider_id: "official_x_recent_search".to_owned(),
            credential_slot: X_BEARER_SLOT.to_owned(),
            approved_at_unix: 100,
            approval_provenance: "operator-owned fixture".to_owned(),
        })
        .expect("approved");
        let credential = Credential::new(
            authority,
            Secret::new("owned-fixture-secret-abcdef123456").expect("fixture"),
            AuthStyle::Bearer,
        )
        .expect("credential")
        .only_for_origin(X_API_ORIGIN);
        let report = search_official_x(&fake, &credential, "sample", 100).expect("search");
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].url, "https://x.com/i/web/status/123456789");
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
        let requests = fake.requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].header_value("authorization"),
            Some("Bearer owned-fixture-secret-abcdef123456")
        );
        assert!(!format!("{:?}", requests[0]).contains("owned-fixture-secret-abcdef123456"));
        assert!(requests[0].url.starts_with(X_API_URL));
    }

    #[test]
    fn malformed_rpc_envelope_never_reaches_balance() {
        let fake = Fake::new(&[r#"{"jsonrpc":"2.0","id":2,"result":"0x2105"}"#]);
        let report = base_balance(
            &fake,
            "0x0000000000000000000000000000000000000001",
            None,
            100,
        )
        .expect("read");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
        assert_eq!(fake.requests.lock().expect("requests").len(), 1);
    }

    #[test]
    fn reject_invalid_wallet_and_spoofed_social_host_without_io() {
        let fake = Fake::default();
        assert!(base_balance(&fake, "0xabc", None, 100).is_err());
        assert!(is_public_x_url("https://x.com/u/status/1"));
        assert!(!is_public_x_url("https://x.com.attacker.example/status/1"));
        assert!(!is_public_x_url("http://x.com/u/status/1"));
        assert!(search_indexed_x(&fake, "a\nb", 100).is_err());
        assert!(fake.requests.lock().expect("requests").is_empty());
    }
}
