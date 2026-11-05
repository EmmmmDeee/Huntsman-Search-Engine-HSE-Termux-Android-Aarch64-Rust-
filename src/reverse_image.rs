//! Bounded, explicit reverse-image web search. These providers search their own indexes, not
//! the whole internet. A visually similar image is never evidence of a person's identity.
//! No provider is contacted unless the operator asks for --live and has configured its key.
//!
//! Each provider is an [`Api`] leg ([`crate::api_leg`]): its key comes only from its operator
//! slot, goes only to the provider's own origin, is added to the request only as it is sent and
//! is scrubbed from every diagnostic. Google Cloud Vision takes the key in the `X-goog-api-key`
//! header, Lenso as a bearer token and `SauceNAO` as the `api_key` query parameter, never inside
//! the uploaded form.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Value, json};

use crate::api_leg::{self, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::keys::Keys;
use crate::sha256::{hex32, sha256};

/// Cap memory use for image bytes, Base64 encoding, request building and downstream providers.
pub const MAX_REVERSE_IMAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_MATCHES: usize = 80;

/// The source label of Google Cloud Vision web detection.
pub const GOOGLE_VISION_SOURCE: &str = "google_vision";
/// The source label of Lenso's duplicate-image search.
pub const LENSO_SOURCE: &str = "lenso";
/// The source label of `SauceNAO`'s image-index search.
pub const SAUCENAO_SOURCE: &str = "saucenao";

/// Google Cloud Vision `images:annotate`, asked for web detection only.
const GOOGLE_VISION_URL: &str = "https://vision.googleapis.com/v1/images:annotate";
/// Lenso's category search, asked for duplicates.
const LENSO_URL: &str = "https://api.lenso.ai/search";
/// `SauceNAO`'s search over every index (`db=999`), answering in JSON (`output_type=2`). The key is
/// not part of it: it is added as the `api_key` parameter as the request is sent.
const SAUCENAO_URL: &str = "https://saucenao.com/search.php?output_type=2&numres=10&db=999";

/// Google Cloud Vision takes an API key in the `X-goog-api-key` header, the placement Google's
/// API-key documentation gives first; its `key` query parameter would put the key in a URL.
pub const GOOGLE_VISION: Api = Api {
    source: GOOGLE_VISION_SOURCE,
    provider: "vision.googleapis.com",
    origin: "https://vision.googleapis.com:443",
    key: Some(KeyUse {
        slot: crate::environment::GOOGLE_VISION_KEY_ENV,
        place: KeyPlace::Header("X-goog-api-key"),
        required: true,
    }),
};

/// Lenso takes its access token as `Authorization: Bearer`, as its API documentation gives it.
pub const LENSO: Api = Api {
    source: LENSO_SOURCE,
    provider: "lenso.ai",
    origin: "https://api.lenso.ai:443",
    key: Some(KeyUse {
        slot: crate::environment::LENSO_KEY_ENV,
        place: KeyPlace::Bearer,
        required: true,
    }),
};

/// `SauceNAO` takes its key as the `api_key` query parameter of `search.php`, as `SauceNAO`'s own
/// example client sends it beside a multipart file upload. The uploaded form never holds it.
pub const SAUCENAO: Api = Api {
    source: SAUCENAO_SOURCE,
    provider: "saucenao.com",
    origin: "https://saucenao.com:443",
    key: Some(KeyUse {
        slot: crate::environment::SAUCENAO_KEY_ENV,
        place: KeyPlace::Query("api_key"),
        required: true,
    }),
};

/// The providers, as `--provider` names them.
const PROVIDERS: [&Api; 3] = [&GOOGLE_VISION, &LENSO, &SAUCENAO];

#[derive(Debug, Clone, Serialize)]
pub struct ImageMatch {
    pub provider: String,
    pub match_type: String,
    pub source_url: Option<String>,
    pub image_url: Option<String>,
    /// A provider-defined similarity value; never an identity probability.
    pub provider_score: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct ProviderStatus {
    pub provider: &'static str,
    pub state: &'static str,
    pub detail: String,
    pub results: usize,
}

#[derive(Debug, Serialize)]
pub struct ImageReport {
    pub image_sha256: String,
    pub bytes: usize,
    pub live_requested: bool,
    pub observed_at_unix: u64,
    /// Matching image URLs returned independently by at least two provider indexes.
    /// Same URL across providers does not by itself establish a real-world identity.
    pub shared_image_urls: Vec<String>,
    pub truncated: bool,
    pub statuses: Vec<ProviderStatus>,
    pub matches: Vec<ImageMatch>,
}

fn is_image(bytes: &[u8]) -> bool {
    (bytes.len() >= 3 && bytes.starts_with(&[0xff, 0xd8, 0xff]))
        || bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || (bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP")
        || bytes.starts_with(b"GIF87a")
        || bytes.starts_with(b"GIF89a")
}

fn web_url(value: &str) -> Option<String> {
    if value.len() > 2048
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\' || byte == b' ')
    {
        return None;
    }
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))?
        .split(['/', '?', '#'])
        .next()?;
    if authority.is_empty() || authority.contains('@') || authority.starts_with(':') {
        return None;
    }
    crate::http::parse_http_uri(value).ok()?;
    Some(value.to_owned())
}

fn insert(
    matches: &mut Vec<ImageMatch>,
    provider: &str,
    kind: &str,
    source: Option<&str>,
    image: Option<&str>,
    score: Option<f64>,
) {
    if matches.len() > MAX_MATCHES {
        return;
    }
    let source_url = source.and_then(web_url);
    let image_url = image.and_then(web_url);
    if source_url.is_none() && image_url.is_none() {
        return;
    }
    matches.push(ImageMatch {
        provider: provider.to_owned(),
        match_type: kind.to_owned(),
        source_url,
        image_url,
        provider_score: score.filter(|v| v.is_finite()),
    });
}

fn parse_google(value: &Value) -> Result<Vec<ImageMatch>, &'static str> {
    let first = value
        .get("responses")
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .ok_or("google response is missing responses[0]")?;
    if first.get("error").is_some() {
        return Err("google reported a request error");
    }
    let data = first
        .get("webDetection")
        .and_then(Value::as_object)
        .ok_or("google response is missing webDetection")?;
    let mut matches = Vec::new();
    for (field, kind) in [
        ("fullMatchingImages", "full_image"),
        ("partialMatchingImages", "partial_image"),
        ("visuallySimilarImages", "visually_similar"),
    ] {
        if let Some(items) = data.get(field).and_then(Value::as_array) {
            for item in items {
                insert(
                    &mut matches,
                    "google_vision",
                    kind,
                    None,
                    item.get("url").and_then(Value::as_str),
                    None,
                );
            }
        }
    }
    if let Some(pages) = data
        .get("pagesWithMatchingImages")
        .and_then(Value::as_array)
    {
        for page in pages {
            let source = page.get("url").and_then(Value::as_str);
            insert(
                &mut matches,
                "google_vision",
                "page_with_match",
                source,
                None,
                page.get("score").and_then(Value::as_f64),
            );
            for (field, kind) in [
                ("fullMatchingImages", "full_image_on_page"),
                ("partialMatchingImages", "partial_image_on_page"),
            ] {
                if let Some(items) = page.get(field).and_then(Value::as_array) {
                    for item in items {
                        insert(
                            &mut matches,
                            "google_vision",
                            kind,
                            source,
                            item.get("url").and_then(Value::as_str),
                            None,
                        );
                    }
                }
            }
        }
    }
    Ok(matches)
}

fn parse_lenso(value: &Value) -> Result<Vec<ImageMatch>, &'static str> {
    let rows = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or("lenso response is missing results array")?;
    let mut matches = Vec::new();
    for row in rows {
        let score = row.get("confidenceScore").and_then(Value::as_f64);
        if let Some(urls) = row.get("urlList").and_then(Value::as_array) {
            for item in urls {
                insert(
                    &mut matches,
                    "lenso",
                    "provider_duplicate",
                    item.get("sourceUrl").and_then(Value::as_str),
                    item.get("imageUrl").and_then(Value::as_str),
                    score,
                );
            }
        }
    }
    Ok(matches)
}

fn parse_saucenao(value: &Value) -> Result<Vec<ImageMatch>, &'static str> {
    let header = value
        .get("header")
        .and_then(Value::as_object)
        .ok_or("SauceNAO response is missing header")?;
    if header.get("status").and_then(Value::as_i64) != Some(0) {
        return Err("SauceNAO returned a non-success status");
    }
    let rows = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or("SauceNAO response is missing results array")?;
    let mut matches = Vec::new();
    for row in rows {
        let score = row.pointer("/header/similarity").and_then(|v| {
            v.as_str()
                .and_then(|s| s.parse::<f64>().ok())
                .or_else(|| v.as_f64())
        });
        let source = row
            .pointer("/data/ext_urls/0")
            .and_then(Value::as_str)
            .or_else(|| row.pointer("/data/source").and_then(Value::as_str));
        insert(
            &mut matches,
            "saucenao",
            "provider_similar",
            source,
            row.pointer("/header/thumbnail").and_then(Value::as_str),
            score,
        );
    }
    Ok(matches)
}

/// The image as the one `file` part of a multipart form, under a boundary drawn from the image's
/// own digest, which its bytes do not hold. No other field is sent: the options are in
/// [`SAUCENAO_URL`], and the key is added to it as the request is sent.
fn multipart_upload(image: &[u8]) -> Result<(String, Vec<u8>), LegError> {
    let boundary = format!("huntsman-{}", &hex32(&sha256(image))[..32]);
    if image
        .windows(boundary.len())
        .any(|window| window == boundary.as_bytes())
    {
        return Err(LegError::Refused(
            "the image holds its own multipart boundary".into(),
        ));
    }
    let mut body = Vec::with_capacity(image.len() + 256);
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"image\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(image);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok((format!("multipart/form-data; boundary={boundary}"), body))
}

/// One provider's search for `image`, through its [`Api`] leg. Redirects are not followed, a
/// challenge page or a refusal is an error, and an answer that is not the provider's documented
/// shape is an error, never an empty search.
fn perform<T: Transport + ?Sized>(
    transport: &T,
    api: &Api,
    image: &[u8],
    keys: &Keys,
    now: u64,
) -> Result<Vec<ImageMatch>, LegError> {
    let answer = match api.source {
        GOOGLE_VISION_SOURCE => {
            let request = json!({"requests": [{"image": {"content": crate::base64::standard(image)},
                "features": [{"type": "WEB_DETECTION", "maxResults": 20}]}]});
            api_leg::post_json(transport, api, keys, GOOGLE_VISION_URL, &request, now)?
        }
        LENSO_SOURCE => {
            let request = json!({"image": crate::base64::standard(image), "category": "duplicates",
                "sortType": "QUALITY_DESCENDING", "page": 1});
            api_leg::post_json(transport, api, keys, LENSO_URL, &request, now)?
        }
        _ => {
            let (content_type, body) = multipart_upload(image)?;
            api_leg::post_body(transport, api, keys, SAUCENAO_URL, &content_type, body, now)?
        }
    };
    let json: Value = api_leg::decode(&answer.body_or_unexpected()?)?;
    match api.source {
        GOOGLE_VISION_SOURCE => parse_google(&json),
        LENSO_SOURCE => parse_lenso(&json),
        _ => parse_saucenao(&json),
    }
    .map_err(|reason| LegError::Decode(reason.to_owned()))
}

/// The same search, optionally restricted to one provider. This avoids unintentionally
/// spending credits with all configured providers. Other providers are not contacted.
///
/// # Errors
/// An unknown provider or invalid image is rejected before network activity.
pub fn search_selected<T: Transport + ?Sized>(
    transport: &T,
    image: &[u8],
    keys: &Keys,
    now: u64,
    live: bool,
    selected: Option<&str>,
) -> Result<ImageReport, &'static str> {
    if selected.is_some_and(|name| !PROVIDERS.iter().any(|api| api.source == name)) {
        return Err("unknown reverse-image provider");
    }
    if image.is_empty() || image.len() > MAX_REVERSE_IMAGE_BYTES || !is_image(image) {
        return Err("expected a JPEG, PNG, GIF or WebP image of 1 byte to 4 MiB");
    }
    let mut report = ImageReport {
        image_sha256: hex32(&sha256(image)),
        bytes: image.len(),
        live_requested: live,
        observed_at_unix: now,
        shared_image_urls: Vec::new(),
        truncated: false,
        statuses: Vec::new(),
        matches: Vec::new(),
    };
    for api in PROVIDERS {
        let name = api.source;
        if selected.is_some_and(|chosen| chosen != name) {
            continue;
        }
        let status = if !live {
            ProviderStatus {
                provider: name,
                state: "not_requested",
                detail: "offline only (pass --live to send image to providers)".into(),
                results: 0,
            }
        } else if api.wanted(keys) {
            match perform(transport, api, image, keys, now) {
                Ok(mut matches) => {
                    let count = matches.len();
                    report.matches.append(&mut matches);
                    ProviderStatus {
                        provider: name,
                        state: "completed",
                        detail: "response parsed; matches are not proof of identity".into(),
                        results: count,
                    }
                }
                Err(error) => ProviderStatus {
                    provider: name,
                    state: "failed",
                    detail: error.to_string(),
                    results: 0,
                },
            }
        } else {
            ProviderStatus {
                provider: name,
                state: "unconfigured",
                detail: api.key.map_or_else(String::new, |key| {
                    format!("set {} in the private credentials file", key.slot)
                }),
                results: 0,
            }
        };
        report.statuses.push(status);
    }
    let mut seen = BTreeSet::new();
    report.matches.retain(|m| {
        seen.insert((
            m.provider.clone(),
            m.match_type.clone(),
            m.source_url.clone(),
            m.image_url.clone(),
        ))
    });
    report.truncated = report.matches.len() > MAX_MATCHES;
    report.matches.truncate(MAX_MATCHES);
    let mut sources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for item in &report.matches {
        if let Some(url) = item.image_url.as_ref() {
            sources
                .entry(url.clone())
                .or_default()
                .insert(item.provider.clone());
        }
    }
    report.shared_image_urls = sources
        .into_iter()
        .filter_map(|(url, providers)| (providers.len() > 1).then_some(url))
        .collect();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Request;

    #[test]
    fn parser_google_uses_actual_image_matches_not_web_entities() {
        let v = json!({"responses":[{"webDetection":{
            "webEntities":[{"description":"person"}],
            "fullMatchingImages":[{"url":"https://images.example/a.jpg"}],
            "pagesWithMatchingImages":[{"url":"https://pages.example/p",
                "partialMatchingImages":[{"url":"https://images.example/crop.jpg"}]}]}}]});
        let results = parse_google(&v).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().any(|m| m.match_type == "full_image"));
        assert!(
            results
                .iter()
                .any(|m| m.source_url.as_deref() == Some("https://pages.example/p"))
        );
    }

    #[test]
    fn parser_lenso_exposes_link_and_provider_score() {
        let v = json!({"results":[{"confidenceScore":92.0,"urlList":[
            {"sourceUrl":"https://source.example/p","imageUrl":"https://img.example/a"}]}]});
        let result = parse_lenso(&v).unwrap();
        assert_eq!(result[0].provider_score, Some(92.0));
        assert_eq!(
            result[0].source_url.as_deref(),
            Some("https://source.example/p")
        );
    }

    #[test]
    fn parser_saucenao_refuses_provider_status_errors() {
        assert!(parse_saucenao(&json!({"header":{"status":-2},"results":[]})).is_err());
        let result = parse_saucenao(&json!({"header":{"status":0},"results":[
            {"header":{"similarity":"93.4","thumbnail":"https://img.example/t"},
             "data":{"ext_urls":["https://source.example/a"]}}]}))
        .unwrap();
        assert_eq!(result[0].provider_score, Some(93.4));
    }

    struct NoNetwork;
    impl Transport for NoNetwork {
        fn send(
            &self,
            _: &Request,
        ) -> Result<crate::http::Response, crate::http::TransportFailure> {
            panic!("offline image search must not access the network");
        }
    }

    #[test]
    fn offline_search_never_contacts_providers_or_misreports_zero_matches() {
        let image = b"\xff\xd8\xff\xd9";
        let keys = Keys::parse("").unwrap();
        let report = search_selected(&NoNetwork, image, &keys, 1, false, None).unwrap();
        assert_eq!(report.image_sha256.len(), 64);
        assert!(report.matches.is_empty());
        assert!(report.statuses.iter().all(|s| s.state == "not_requested"));
    }

    #[test]
    fn live_without_keys_is_unconfigured_not_empty_and_does_not_call_network() {
        let report = search_selected(
            &NoNetwork,
            b"GIF89a",
            &Keys::parse("").unwrap(),
            1,
            true,
            None,
        )
        .unwrap();
        assert!(report.statuses.iter().all(|s| s.state == "unconfigured"));
        assert!(report.matches.is_empty());
    }

    #[test]
    fn malformed_and_oversized_input_rejected_before_network() {
        let keys = Keys::parse("").unwrap();
        assert!(search_selected(&NoNetwork, b"not image", &keys, 1, true, None).is_err());
        assert!(
            search_selected(
                &NoNetwork,
                &vec![0xff; MAX_REVERSE_IMAGE_BYTES + 1],
                &keys,
                1,
                true,
                None
            )
            .is_err()
        );
    }
    struct ScriptedTransport {
        requests: std::sync::Mutex<Vec<Request>>,
        body: Vec<u8>,
    }

    impl Transport for ScriptedTransport {
        fn send(
            &self,
            request: &Request,
        ) -> Result<crate::http::Response, crate::http::TransportFailure> {
            self.requests.lock().unwrap().push(request.clone());
            Ok(crate::http::Response {
                status: 200,
                headers: Vec::new(),
                body: self.body.clone(),
                truncated: false,
            })
        }
    }

    #[test]
    fn one_provider_is_called_once_and_its_key_is_not_in_the_url_or_debug() {
        let network = ScriptedTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            body: serde_json::to_vec(&json!({"responses":[{"webDetection":{
                "fullMatchingImages":[{"url":"https://example.org/picture.jpg"}]}}]}))
            .unwrap(),
        };
        let keys = Keys::parse(&format!(
            "{}=testing_provider_secret_123",
            crate::environment::GOOGLE_VISION_KEY_ENV
        ))
        .unwrap();
        let report =
            search_selected(&network, b"GIF89a", &keys, 123, true, Some("google_vision")).unwrap();
        assert_eq!(report.observed_at_unix, 123);
        assert_eq!(report.statuses.len(), 1);
        assert_eq!(report.statuses[0].state, "completed");
        assert_eq!(report.matches.len(), 1);
        let requests = network.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, crate::http::Method::Post);
        assert_eq!(
            request.url,
            "https://vision.googleapis.com/v1/images:annotate"
        );
        assert_eq!(
            request.header_value("X-goog-api-key"),
            Some("testing_provider_secret_123")
        );
        assert!(!format!("{request:?}").contains("testing_provider_secret_123"));
        let payload: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            payload
                .pointer("/requests/0/features/0/type")
                .and_then(Value::as_str),
            Some("WEB_DETECTION")
        );
    }

    #[test]
    fn saucenao_key_is_only_the_api_key_parameter_added_as_the_request_is_sent() {
        let network = ScriptedTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            body: serde_json::to_vec(&json!({"header":{"status":0},"results":[]})).unwrap(),
        };
        let secret = "testing_sauce_secret_123";
        let keys = Keys::parse(&format!(
            "{}={secret}",
            crate::environment::SAUCENAO_KEY_ENV
        ))
        .unwrap();
        let report =
            search_selected(&network, b"GIF89a", &keys, 123, true, Some("saucenao")).unwrap();
        assert_eq!(report.statuses.len(), 1);
        assert_eq!(report.statuses[0].state, "completed");
        let requests = network.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        // The URL the code builds holds no key; fetch adds it as `api_key` as it sends.
        assert!(!SAUCENAO_URL.contains(secret));
        assert_eq!(requests[0].url, format!("{SAUCENAO_URL}&api_key={secret}"));
        assert!(
            !requests[0]
                .body
                .windows(secret.len())
                .any(|part| part == secret.as_bytes()),
            "the key is in the uploaded form"
        );
        assert!(!requests[0].body.windows(7).any(|part| part == b"api_key"));
        assert!(requests[0].headers.iter().all(|(_, v)| !v.contains(secret)));
        assert!(!format!("{:?}", requests[0]).contains(secret));
        let content_type = requests[0].header_value("content-type").unwrap();
        let boundary = content_type
            .strip_prefix("multipart/form-data; boundary=")
            .unwrap();
        assert!(
            requests[0]
                .body
                .starts_with(format!("--{boundary}\r\n").as_bytes())
        );
        assert!(
            requests[0]
                .body
                .ends_with(format!("\r\n--{boundary}--\r\n").as_bytes())
        );
    }

    #[test]
    fn lenso_token_is_a_bearer_header_bound_to_its_origin() {
        let network = ScriptedTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            body: serde_json::to_vec(&json!({"results":[]})).unwrap(),
        };
        let secret = "testing_lenso_secret_123";
        let keys = Keys::parse(&format!("{}={secret}", crate::environment::LENSO_KEY_ENV)).unwrap();
        let report = search_selected(&network, b"GIF89a", &keys, 123, true, Some("lenso")).unwrap();
        assert_eq!(report.statuses[0].state, "completed");
        let requests = network.requests.lock().unwrap();
        assert_eq!(requests[0].url, LENSO_URL);
        assert_eq!(
            requests[0].header_value("authorization"),
            Some(format!("Bearer {secret}").as_str())
        );
        assert!(!format!("{:?}", requests[0]).contains(secret));
    }

    #[test]
    fn invalid_provider_and_private_embedded_urls_are_refused() {
        let keys = Keys::parse("").unwrap();
        assert!(search_selected(&NoNetwork, b"GIF89a", &keys, 1, true, Some("other")).is_err());
        assert!(web_url("https://user:password@example.org/a").is_none());
        assert!(web_url("https://example.org/space here").is_none());
        assert!(web_url("javascript:alert(1)").is_none());
        assert_eq!(
            web_url("https://example.org/x?a=1"),
            Some("https://example.org/x?a=1".into())
        );
    }

    #[test]
    fn malformed_provider_json_does_not_look_like_a_negative_result() {
        let network = ScriptedTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            body: serde_json::to_vec(&json!({"notResults": []})).unwrap(),
        };
        let keys = Keys::parse(&format!(
            "{}=testing_lenso_secret_123",
            crate::environment::LENSO_KEY_ENV
        ))
        .unwrap();
        let result = search_selected(&network, b"GIF89a", &keys, 123, true, Some("lenso")).unwrap();
        assert_eq!(result.statuses[0].state, "failed");
        assert!(result.matches.is_empty());
    }
}
