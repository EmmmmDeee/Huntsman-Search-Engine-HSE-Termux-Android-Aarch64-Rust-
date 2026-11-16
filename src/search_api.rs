//! Explicit search API calls. Returned URLs are ranked discovery leads.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::api_leg::{self, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_url;
use crate::environment::{
    BRAVE_KEY_ENV, OPENALEX_KEY_ENV, SERPAPI_KEY_ENV, TAVILY_KEY_ENV, TROVE_KEY_ENV,
};
use crate::http::{
    Transport, append_query_param, percent_encode_component, percent_encode_unreserved,
};
use crate::keys::Keys;
use crate::value_syntax::percent_decode_strict;

pub const MAX_RESULTS: usize = 5;
pub const MAX_QUERY_BYTES: usize = 512;

/// Bound the explicit provider response below the shared client's general-purpose body limit.
#[must_use]
pub fn transport_config() -> crate::http::TransportConfig {
    crate::http::TransportConfig {
        max_body: 512 * 1024,
        ..api_leg::transport_config()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchApi {
    Exa,
    Brave,
    Tavily,
    SerpGoogle,
    SerpBing,
    SerpYahoo,
    SerpYandex,
    Trove,
    OpenAlex,
    OpenAlexPublic,
    Crossref,
}

impl SearchApi {
    pub const ALL: [Self; 11] = [
        Self::Exa,
        Self::Brave,
        Self::Tavily,
        Self::SerpGoogle,
        Self::SerpBing,
        Self::SerpYahoo,
        Self::SerpYandex,
        Self::Trove,
        Self::OpenAlex,
        Self::OpenAlexPublic,
        Self::Crossref,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exa => "exa",
            Self::Brave => "brave",
            Self::Tavily => "tavily",
            Self::SerpGoogle => "serpapi-google",
            Self::SerpBing => "serpapi-bing",
            Self::SerpYahoo => "serpapi-yahoo",
            Self::SerpYandex => "serpapi-yandex",
            Self::Trove => "trove",
            Self::OpenAlex => "openalex",
            Self::OpenAlexPublic => "openalex-public",
            Self::Crossref => "crossref",
        }
    }

    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|api| api.name() == name)
    }

    const fn serp_engine(self) -> (&'static str, &'static str) {
        match self {
            Self::SerpGoogle => ("google", "q"),
            Self::SerpBing => ("bing", "q"),
            Self::SerpYahoo => ("yahoo", "p"),
            Self::SerpYandex => ("yandex", "text"),
            _ => unreachable!(),
        }
    }

    pub(crate) const fn api(self) -> Api {
        let (source, provider, origin, slot, place) = match self {
            Self::Exa => return crate::exa::API,
            Self::OpenAlexPublic => {
                return Api {
                    key: None,
                    ..Self::OpenAlex.api()
                };
            }
            Self::Crossref => {
                return Api {
                    source: "crossref",
                    provider: "crossref.org",
                    origin: "https://api.crossref.org:443",
                    key: None,
                };
            }
            Self::Brave => (
                "brave_api",
                "brave.com",
                "https://api.search.brave.com:443",
                BRAVE_KEY_ENV,
                KeyPlace::Header("X-Subscription-Token"),
            ),
            Self::Tavily => (
                "tavily",
                "tavily.com",
                "https://api.tavily.com:443",
                TAVILY_KEY_ENV,
                KeyPlace::Bearer,
            ),
            Self::Trove => (
                "trove_api",
                "trove.nla.gov.au",
                "https://api.trove.nla.gov.au:443",
                TROVE_KEY_ENV,
                KeyPlace::Header("X-API-KEY"),
            ),
            Self::OpenAlex => (
                "openalex",
                "openalex.org",
                "https://api.openalex.org:443",
                OPENALEX_KEY_ENV,
                KeyPlace::Query("api_key"),
            ),
            _ => (
                "serpapi",
                "serpapi.com",
                "https://serpapi.com:443",
                SERPAPI_KEY_ENV,
                KeyPlace::Query("api_key"),
            ),
        };
        Api {
            source,
            provider,
            origin,
            key: Some(KeyUse {
                slot,
                place,
                required: true,
            }),
        }
    }

    /// Whether this route uses an operator credential.
    #[must_use]
    pub const fn requires_key(self) -> bool {
        self.api().key.is_some()
    }

    /// Check the selected provider's input bounds before any request.
    ///
    /// # Errors
    /// Returns a refusal for blank, oversized or control-bearing queries.
    pub fn check_query(self, query: &str) -> Result<&str, LegError> {
        if !crate::textnorm::is_bounded_text(query, MAX_QUERY_BYTES)
            || (self == Self::SerpYandex && query.trim().chars().count() > 400)
        {
            return Err(LegError::Refused(format!(
                "search query must contain 1–{MAX_QUERY_BYTES} bytes without controls (Yandex: at most 400 characters)"
            )));
        }
        Ok(query.trim())
    }

    /// Run one query with the existing guarded client and return at most five unique leads.
    ///
    /// # Errors
    /// Returns a typed error for an invalid query, missing key, unavailable provider or invalid
    /// response. The query is sent to the selected API only.
    pub fn search<T: Transport + ?Sized>(
        self,
        transport: &T,
        keys: &Keys,
        query: &str,
        now_unix: u64,
    ) -> Result<Vec<String>, LegError> {
        let query = self.check_query(query)?;
        let api = self.api();
        let answer = match self {
            Self::Exa => api_leg::post_json(
                transport,
                &api,
                keys,
                crate::exa::URL,
                &json!({"query": query, "type": "lite", "numResults": MAX_RESULTS}),
                now_unix,
            ),
            Self::Brave => api_leg::get(
                transport,
                &api,
                keys,
                &append_query_param(
                    "https://api.search.brave.com/res/v1/web/search?count=5&result_filter=web",
                    "q",
                    query,
                ),
                now_unix,
            ),
            Self::Tavily => api_leg::post_json(
                transport,
                &api,
                keys,
                "https://api.tavily.com/search",
                &json!({
                    "query": query, "search_depth": "basic", "max_results": MAX_RESULTS,
                    "auto_parameters": false, "include_answer": false,
                    "include_raw_content": false, "include_images": false
                }),
                now_unix,
            ),
            Self::Trove => api_leg::get(
                transport, &api, keys,
                &append_query_param(
                    "https://api.trove.nla.gov.au/v3/result?category=newspaper&encoding=json&reclevel=brief&n=5",
                    "q", query,
                ), now_unix,
            ),
            Self::OpenAlex | Self::OpenAlexPublic => api_leg::get(
                transport, &api, keys,
                &append_query_param(
                    "https://api.openalex.org/works?select=id&per_page=5",
                    "search", query,
                ), now_unix,
            ),
            Self::Crossref => api_leg::get(
                transport, &api, keys,
                &append_query_param("https://api.crossref.org/works?rows=5&select=DOI", "query", query),
                now_unix,
            ),
            _ => {
                let (engine, parameter) = self.serp_engine();
                let url = format!("https://serpapi.com/search.json?engine={engine}");
                api_leg::get(
                    transport,
                    &api,
                    keys,
                    &append_query_param(&url, parameter, query),
                    now_unix,
                )
            }
        }?
        .body_or_unexpected()?;
        let secret = api.key.and_then(|key| keys.provider_key(key.slot));
        self.decode(
            &answer,
            Some(query),
            secret.as_ref().map(crate::keys::Secret::expose),
        )
    }

    pub(crate) fn decode(
        self,
        body: &[u8],
        query: Option<&str>,
        secret: Option<&str>,
    ) -> Result<Vec<String>, LegError> {
        let payload: Value = api_leg::decode(body)?;
        let Some(rows) = self.result_rows(&payload, query)? else {
            return Ok(Vec::new());
        };
        let url_field = match self {
            Self::Trove => "troveUrl",
            Self::OpenAlex | Self::OpenAlexPublic => "id",
            Self::Crossref => "DOI",
            Self::Exa | Self::Brave | Self::Tavily => "url",
            _ => "link",
        };
        if url_field != "link" && rows.len() > MAX_RESULTS {
            return Err(malformed());
        }
        let mut seen = BTreeSet::new();
        let mut hits = Vec::new();
        for row in rows {
            let raw = row
                .get(url_field)
                .and_then(Value::as_str)
                .ok_or_else(malformed)?;
            let valid_scoped_id = |prefix| {
                raw.strip_prefix(prefix).is_some_and(|id| {
                    !id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit())
                })
            };
            match self {
                Self::Trove if !valid_scoped_id("https://trove.nla.gov.au/ndp/del/article/") => {
                    return Err(malformed());
                }
                Self::OpenAlex | Self::OpenAlexPublic
                    if !valid_scoped_id("https://openalex.org/W") =>
                {
                    return Err(malformed());
                }
                _ => {}
            }
            let url = if self == Self::Crossref {
                doi_url(raw)
            } else {
                result_url(raw, secret)
            }
            .ok_or_else(malformed)?;
            if seen.insert(url.clone()) {
                hits.push(url);
                if hits.len() == MAX_RESULTS {
                    break;
                }
            }
        }
        Ok(hits)
    }
    // A successful envelope with an explicitly empty result can have no row array.
    fn result_rows<'a>(
        self,
        payload: &'a Value,
        query: Option<&str>,
    ) -> Result<Option<&'a [Value]>, LegError> {
        let verify_query = |actual: Option<&str>| {
            if let Some(expected) = query {
                api_leg::bound_to_query(actual, "search query", |value| value == expected)?;
            }
            Ok::<(), LegError>(())
        };
        let rows = match self {
            Self::Exa => payload.get("results"),
            Self::Brave => {
                verify_query(payload.pointer("/query/original").and_then(Value::as_str))?;
                if payload.get("type").and_then(Value::as_str) != Some("search") {
                    return Err(malformed());
                }
                match payload.get("web") {
                    None | Some(Value::Null) if payload.get("error").is_none() => return Ok(None),
                    Some(web) => web.get("results"),
                    None => return Err(malformed()),
                }
            }
            Self::Tavily => {
                verify_query(payload.get("query").and_then(Value::as_str))?;
                payload.get("results")
            }
            Self::Trove => {
                verify_query(payload.get("query").and_then(Value::as_str))?;
                return trove_rows(payload);
            }
            Self::OpenAlex | Self::OpenAlexPublic => {
                return counted_rows(
                    payload,
                    payload.pointer("/meta/count"),
                    payload.get("results"),
                    false,
                );
            }
            Self::Crossref => {
                if payload.get("status").and_then(Value::as_str) != Some("ok")
                    || payload.get("message-type").and_then(Value::as_str) != Some("work-list")
                {
                    return Err(malformed());
                }
                return counted_rows(
                    payload,
                    payload.pointer("/message/total-results"),
                    payload.pointer("/message/items"),
                    false,
                );
            }
            _ => {
                let (engine, parameter) = self.serp_engine();
                if payload
                    .pointer("/search_metadata/status")
                    .and_then(Value::as_str)
                    != Some("Success")
                {
                    return Err(malformed());
                }
                let parameters = &payload["search_parameters"];
                if parameters.get("engine").and_then(Value::as_str) != Some(engine) {
                    return Err(LegError::Decode(
                        "search API returned another engine".into(),
                    ));
                }
                verify_query(parameters.get(parameter).and_then(Value::as_str))?;
                let rows = payload.get("organic_results");
                let reported_empty = payload
                    .pointer("/search_information/organic_results_state")
                    .and_then(Value::as_str)
                    .is_some_and(|state| state.eq_ignore_ascii_case("fully empty"));
                let empty_message = payload.get("error").is_none_or(|error| {
                    error.as_str().is_some_and(|message| {
                        message.split_once(' ').is_some_and(|(service, text)| {
                            service.trim_end_matches('!').eq_ignore_ascii_case(engine)
                                && text == "hasn't returned any results for this query."
                        })
                    })
                });
                if rows.is_none() && reported_empty && empty_message {
                    return Ok(None);
                }
                rows
            }
        };
        if payload.get("error").is_some() {
            return Err(malformed());
        }
        rows.and_then(Value::as_array)
            .map(|rows| Some(rows.as_slice()))
            .ok_or_else(malformed)
    }
}

fn malformed() -> LegError {
    LegError::Decode("search API response has an unexpected shape".into())
}

fn trove_rows(payload: &Value) -> Result<Option<&[Value]>, LegError> {
    let [category] = payload
        .get("category")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(malformed)?
    else {
        return Err(malformed());
    };
    if category.get("code").and_then(Value::as_str) != Some("newspaper") {
        return Err(malformed());
    }
    let records = category.get("records").ok_or_else(malformed)?;
    counted_rows(payload, records.get("total"), records.get("article"), true)
}

fn counted_rows<'a>(
    payload: &Value,
    count: Option<&Value>,
    rows: Option<&'a Value>,
    allow_omitted_zero: bool,
) -> Result<Option<&'a [Value]>, LegError> {
    if payload.get("error").is_some() {
        return Err(malformed());
    }
    let count = count.and_then(Value::as_u64).ok_or_else(malformed)?;
    if rows.is_none() && count == 0 && allow_omitted_zero {
        return Ok(None);
    }
    let rows = rows.and_then(Value::as_array).ok_or_else(malformed)?;
    if (count == 0) != rows.is_empty() || rows.len() as u64 > count {
        return Err(malformed());
    }
    Ok(Some(rows))
}

fn doi_url(doi: &str) -> Option<String> {
    let (prefix, suffix) = doi.split_once('/')?;
    let registrant = prefix.strip_prefix("10.")?;
    if registrant.is_empty()
        || !registrant
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        || suffix.is_empty()
        || suffix.split('/').any(|part| matches!(part, "." | ".."))
        || !crate::textnorm::is_bounded_text(doi, 512)
        || doi.chars().any(char::is_whitespace)
    {
        return None;
    }
    let encoded = suffix
        .to_ascii_lowercase()
        .split('/')
        .map(percent_encode_unreserved)
        .collect::<Vec<_>>()
        .join("/");
    Some(format!("https://doi.org/{prefix}/{encoded}"))
}

fn result_url(raw: &str, secret: Option<&str>) -> Option<String> {
    if !crate::textnorm::is_bounded_text(raw, 4096)
        || raw.chars().any(|c| c.is_whitespace() || c == '\\')
    {
        return None;
    }
    let url = canonical_url(raw)?;
    let host = crate::circuit::host_of(&url)?;
    if (host.parse().map_or_else(
        |_| {
            !host
                .rsplit_once('.')
                .is_some_and(|(_, tld)| crate::value_syntax::is_iana_tld(tld))
        },
        |ip| !crate::egress::is_public_ip(ip),
    )) || secret.is_some_and(|key| {
        [raw, &url].into_iter().any(|value| {
            value.contains(key)
                || value.contains(&percent_encode_component(key))
                || value.contains(&percent_encode_unreserved(key))
                || percent_decode_strict(value).is_some_and(|decoded| decoded.contains(key))
        })
    }) {
        return None;
    }
    Some(url)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::http::{Request, Response, TransportFailure};

    const QUERY: &str = "public data & maps";
    const TOKEN: &str = "fixture+search-token";
    const URL: &str = "https://example.com/record";

    struct Mock {
        response: Response,
        requests: Mutex<Vec<Request>>,
    }

    impl Mock {
        fn new(status: u16, body: &Value) -> Self {
            Self {
                response: Response {
                    status,
                    headers: vec![("content-type".into(), "application/json".into())],
                    body: body.to_string().into_bytes(),
                    truncated: false,
                },
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for Mock {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.requests.lock().unwrap().push(request.clone());
            Ok(self.response.clone())
        }
    }

    fn keys(api: SearchApi) -> Keys {
        let slot = api.api().key.unwrap().slot;
        Keys::parse(&format!("{slot}={TOKEN}\n")).unwrap()
    }

    fn serp(engine: &str, parameter: &str, rows: &Value) -> Value {
        json!({
            "search_metadata": {"status":"Success"},
            "search_parameters": {"engine":engine, (parameter):QUERY},
            "organic_results": rows
        })
    }

    #[test]
    fn keyed_selectors_require_their_own_key_and_all_reject_invalid_queries() {
        for api in SearchApi::ALL {
            assert_eq!(SearchApi::named(api.name()), Some(api));
            let mock = Mock::new(200, &json!({}));
            if api.api().key.is_some() {
                assert!(matches!(
                    api.search(&mock, &Keys::default(), QUERY, 1),
                    Err(LegError::MissingKey(_))
                ));
            }
            assert!(matches!(
                api.search(&mock, &Keys::default(), "bad\nquery", 1),
                Err(LegError::Refused(_))
            ));
            assert!(mock.requests.lock().unwrap().is_empty());
        }
        assert!(SearchApi::named("https://example.org").is_none());
    }

    #[test]
    fn search_requests_are_origin_bound_and_use_provider_specific_contracts() {
        let brave = SearchApi::Brave;
        let mock = Mock::new(
            200,
            &json!({"type":"search","query":{"original":QUERY},"web":{"results":[{"url":URL}]}}),
        );
        assert_eq!(brave.search(&mock, &keys(brave), QUERY, 1).unwrap(), [URL]);
        let calls = mock.requests.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].header_value("X-Subscription-Token"), Some(TOKEN));
        assert_eq!(
            calls[0].url,
            "https://api.search.brave.com/res/v1/web/search?count=5&result_filter=web&q=public+data+%26+maps"
        );

        let tavily = SearchApi::Tavily;
        let mock = Mock::new(200, &json!({"query":QUERY,"results":[{"url":URL}]}));
        assert_eq!(
            tavily.search(&mock, &keys(tavily), QUERY, 1).unwrap(),
            [URL]
        );
        let calls = mock.requests.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].url, "https://api.tavily.com/search");
        assert_eq!(
            calls[0].header_value("Authorization").unwrap(),
            format!("Bearer {TOKEN}")
        );
        let request: Value = serde_json::from_slice(&calls[0].body).unwrap();
        assert_eq!(
            request,
            json!({
                "query":QUERY, "search_depth":"basic", "max_results":5,
                "auto_parameters":false, "include_answer":false,
                "include_raw_content":false, "include_images":false,
            })
        );

        for (api, engine, param) in [
            (SearchApi::SerpGoogle, "google", "q"),
            (SearchApi::SerpBing, "bing", "q"),
            (SearchApi::SerpYahoo, "yahoo", "p"),
            (SearchApi::SerpYandex, "yandex", "text"),
        ] {
            let mock = Mock::new(200, &serp(engine, param, &json!([{"link":URL}])));
            assert_eq!(api.search(&mock, &keys(api), QUERY, 1).unwrap(), [URL]);
            let calls = mock.requests.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(
                calls[0].url,
                format!(
                    "https://serpapi.com/search.json?engine={engine}&{param}=public+data+%26+maps&api_key=fixture%2Bsearch-token"
                )
            );
            assert!(calls[0].header_value("Authorization").is_none());
        }
    }

    #[test]
    fn specialist_searches_return_only_the_requested_record_kind() {
        let trove = SearchApi::Trove;
        let article = "https://trove.nla.gov.au/ndp/del/article/152471373";
        let body = json!({"query":QUERY,"category":[{"code":"newspaper","records":{
            "total":76,"article":[{"id":"152471373","troveUrl":article}],
            "next":"https://evil.example.com/?key=fixture%2Bsearch-token"
        }}]});
        let mock = Mock::new(200, &body);
        assert_eq!(
            trove.search(&mock, &keys(trove), QUERY, 1).unwrap(),
            [article]
        );
        let calls = mock.requests.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0]
                .url
                .starts_with("https://api.trove.nla.gov.au/v3/result?category=newspaper")
        );
        assert_eq!(calls[0].header_value("X-API-KEY"), Some(TOKEN));

        let openalex = SearchApi::OpenAlex;
        let work = "https://openalex.org/W123";
        let mock = Mock::new(200, &json!({"meta":{"count":7},"results":[{"id":work}]}));
        assert_eq!(
            openalex.search(&mock, &keys(openalex), QUERY, 1).unwrap(),
            [work]
        );
        let calls = mock.requests.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].url,
            "https://api.openalex.org/works?select=id&per_page=5&search=public+data+%26+maps&api_key=fixture%2Bsearch-token"
        );
    }

    #[test]
    fn keyless_research_uses_no_stored_credential() {
        let configured = keys(SearchApi::OpenAlex);
        let mock = Mock::new(
            200,
            &json!({"meta":{"count":1},"results":[{"id":"https://openalex.org/W123"}]}),
        );
        assert_eq!(
            SearchApi::OpenAlexPublic
                .search(&mock, &configured, QUERY, 1)
                .unwrap(),
            ["https://openalex.org/W123"]
        );
        let calls = mock.requests.lock().unwrap();
        assert_eq!(
            calls[0].url,
            "https://api.openalex.org/works?select=id&per_page=5&search=public+data+%26+maps"
        );
        assert!(calls[0].header_value("Authorization").is_none());

        let mock = Mock::new(
            200,
            &json!({
                "status":"ok","message-type":"work-list","message":{
                    "total-results":2,"items":[{"DOI":"10.1234/B%?#"},{"DOI":"10.1234/b%?#"}]
                }
            }),
        );
        assert_eq!(
            SearchApi::Crossref
                .search(&mock, &configured, QUERY, 1)
                .unwrap(),
            ["https://doi.org/10.1234/b%25%3F%23"]
        );
        let calls = mock.requests.lock().unwrap();
        assert_eq!(
            calls[0].url,
            "https://api.crossref.org/works?rows=5&select=DOI&query=public+data+%26+maps"
        );
    }

    #[test]
    fn valid_zeros_and_provider_errors_are_distinct() {
        let google = SearchApi::SerpGoogle;
        let zero = json!({
            "search_metadata":{"status":"Success"},
            "search_parameters":{"engine":"google","q":QUERY},
            "search_information":{"organic_results_state":"Fully empty"},
            "error":"Google hasn't returned any results for this query."
        });
        let read = |api, body: &Value| {
            let mock = Mock::new(200, body);
            SearchApi::search(api, &mock, &keys(api), QUERY, 1)
        };
        assert!(read(google, &zero).unwrap().is_empty());
        let mut contradiction = zero.clone();
        contradiction["error"] = json!("Gateway unavailable");
        assert!(read(google, &contradiction).is_err());
        let mut mismatched = zero;
        mismatched["search_parameters"]["q"] = json!("wrong");
        assert!(read(google, &mismatched).is_err());
        assert!(read(google, &serp("bing", "q", &json!([]))).is_err());
        assert!(read(google, &json!({"organic_results":[]})).is_err());
        assert!(
            read(
                SearchApi::Brave,
                &json!({"type":"error","query":{"original":QUERY}})
            )
            .is_err()
        );
        assert!(read(SearchApi::Tavily, &json!({"query":"wrong","results":[]})).is_err());
        assert!(
            read(SearchApi::Tavily, &json!({"query":QUERY,"results":[]}))
                .unwrap()
                .is_empty()
        );
        assert!(
            read(
                SearchApi::OpenAlex,
                &json!({"meta":{"count":1},"results":[]})
            )
            .is_err()
        );
        assert!(
            read(
                SearchApi::OpenAlex,
                &json!({"meta":{"count":0},"results":[]})
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            read(
                SearchApi::Trove,
                &json!({"query":QUERY,"category":[{"code":"newspaper","records":{"total":0}}]})
            )
            .unwrap()
            .is_empty()
        );
        for status in [302, 401, 403, 404, 429, 503] {
            let mut mock = Mock::new(status, &json!({"query":QUERY,"results":[]}));
            mock.response
                .headers
                .push(("Location".into(), "https://example.org/redirect".into()));
            assert!(
                SearchApi::Tavily
                    .search(&mock, &keys(SearchApi::Tavily), QUERY, 1)
                    .is_err()
            );
            assert_eq!(mock.requests.lock().unwrap().len(), 1);
        }
    }

    #[test]
    fn ranking_deduplicates_and_never_exposes_an_echoed_key_or_private_url() {
        let api = SearchApi::SerpGoogle;
        let mut rows = vec![json!({"link":"https://example.com/a#fragment"})];
        rows.extend(
            (b'a'..=b'g').map(
                |letter| json!({"link":format!("https://example.com/{}", char::from(letter))}),
            ),
        );
        let mock = Mock::new(200, &serp("google", "q", &Value::Array(rows)));
        assert_eq!(
            api.search(&mock, &keys(api), QUERY, 1).unwrap(),
            ["a", "b", "c", "d", "e"].map(|path| format!("https://example.com/{path}"))
        );
        for bad in [
            "http://127.0.0.1/path",
            "https://localhost/path",
            "https://person:password@example.com",
            "https://example.com/path?value=fixture%2bsearch-token",
        ] {
            let mock = Mock::new(200, &serp("google", "q", &json!([{"link":bad}])));
            let err = api.search(&mock, &keys(api), QUERY, 1).unwrap_err();
            assert!(!err.to_string().contains("fixture"));
        }
    }
}
