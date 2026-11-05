//! Opt-in reverse-image search of one local image by the one provider the operator names.
//!
//! Offline by default: [`fingerprint`] hashes the file and sends nothing, so no search runs and
//! the report holds no matches, rather than zero matches. [`search_one`] uploads the whole image
//! to the one provider the operator named with `--live --provider NAME`, Google Cloud Vision web
//! detection, Lenso or `SauceNAO`, and to no other: nothing fans out to every configured provider.
//! Each provider searches its own index, not the whole internet, and a visually similar image is
//! never evidence of a person's identity.
//!
//! Each provider is an [`Api`] leg ([`crate::api_leg`]): its key comes only from its operator
//! slot, goes only to the provider's own origin, is added to the request only as it is sent and
//! is scrubbed from every diagnostic. Google Cloud Vision takes the key in the `X-goog-api-key`
//! header, Lenso as a bearer token and `SauceNAO` as the `api_key` query parameter, never inside
//! the uploaded form.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Value, json};

use crate::api_leg::{self, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::keys::Keys;
use crate::sha256::{hex32, sha256};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

/// The largest image read and uploaded. It bounds the memory the Base64 and multipart copies of
/// an upload take.
pub const MAX_REVERSE_IMAGE_BYTES: usize = 4 * 1024 * 1024;
/// The most matches one report keeps; a provider that returned more distinct ones is marked
/// truncated.
pub const MAX_MATCHES: usize = 80;

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

/// Every provider, in the order `--provider` lists them.
pub const PROVIDERS: [&Api; 3] = [&GOOGLE_VISION, &LENSO, &SAUCENAO];

/// The provider `--provider` names by its source label, or `None` for any other name. **Pure.**
#[must_use]
pub fn provider(name: &str) -> Option<&'static Api> {
    PROVIDERS.into_iter().find(|api| api.source == name)
}

/// An image container the command reads, by its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Jpeg,
    Png,
    WebP,
    Gif,
}

impl Format {
    /// The container `image` starts as, or `None` for anything else. **Pure.**
    fn of(image: &[u8]) -> Option<Self> {
        if image.starts_with(&[0xFF, 0xD8, 0xFF]) {
            Some(Self::Jpeg)
        } else if image.starts_with(crate::exif::PNG_SIGNATURE) {
            Some(Self::Png)
        } else if image.starts_with(b"RIFF") && image.get(8..12) == Some(b"WEBP") {
            Some(Self::WebP)
        } else if image.starts_with(b"GIF87a") || image.starts_with(b"GIF89a") {
            Some(Self::Gif)
        } else {
            None
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Jpeg => "JPEG",
            Self::Png => "PNG",
            Self::WebP => "WebP",
            Self::Gif => "GIF",
        }
    }
}

/// One match a provider returned: a page holding the picture, the picture's own address, or both.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImageMatch {
    /// The provider's own kind of match, such as `full_image` or `visually_similar`.
    pub match_type: &'static str,
    pub source_url: Option<String>,
    pub image_url: Option<String>,
    /// A provider-defined similarity value; never an identity probability.
    pub provider_score: Option<f64>,
}

/// Whether a search ran: what a report says first, so an offline run or a missing key is never
/// read as a search that found nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Search {
    /// Nothing was sent: no provider was named, its key is not configured, or the request was
    /// refused before sending.
    NotRun,
    /// The image was sent and no answer could be read: not a negative result.
    Failed,
    /// The provider answered. `matches` holds what it returned from its own index, which may be
    /// nothing.
    Completed,
}

/// One `reverse-image` run.
#[derive(Debug, Serialize)]
pub struct ImageReport {
    /// SHA-256 of the file as read.
    pub file_sha256: String,
    pub file_bytes: usize,
    /// The container the file's first bytes name: JPEG, PNG, WebP or GIF.
    pub format: &'static str,
    /// The one provider the operator named; `None` offline.
    pub provider: Option<&'static str>,
    pub search: Search,
    /// How the provider's request ended; `None` offline.
    pub outcome: Option<SourceExecutionOutcome>,
    pub observed_at_unix: u64,
    /// What the provider returned when the search completed; `None` when no search ran or it
    /// failed, so an absent list is never read as no matches.
    pub matches: Option<Vec<ImageMatch>>,
    /// Whether the provider returned more distinct matches than the [`MAX_MATCHES`] kept.
    pub truncated: bool,
}

/// The offline report: the file's SHA-256, size and format. No provider is asked and nothing is
/// sent, so the report says no search ran and holds no matches.
///
/// # Errors
/// An empty file, one over [`MAX_REVERSE_IMAGE_BYTES`], or one that is not a JPEG, PNG, WebP or
/// GIF image.
pub fn fingerprint(image: &[u8], now_unix: u64) -> Result<ImageReport, &'static str> {
    if image.is_empty() || image.len() > MAX_REVERSE_IMAGE_BYTES {
        return Err("the image must be 1 byte to 4 MiB");
    }
    let format = Format::of(image).ok_or("not a JPEG, PNG, WebP or GIF image")?;
    Ok(ImageReport {
        file_sha256: hex32(&sha256(image)),
        file_bytes: image.len(),
        format: format.name(),
        provider: None,
        search: Search::NotRun,
        outcome: None,
        observed_at_unix: now_unix,
        matches: None,
        truncated: false,
    })
}

/// One live search: `image` uploaded to the one provider `name` names, with its key from `keys`,
/// and to no other provider. A provider whose key is not configured is asked nothing. A refusal,
/// a failure and an answer that is not the provider's documented shape are reported as such,
/// never as no matches.
///
/// # Errors
/// An unknown provider name, or an image [`fingerprint`] refuses, before any request.
pub fn search_one<T: Transport + ?Sized>(
    transport: &T,
    image: &[u8],
    keys: &Keys,
    name: &str,
    now_unix: u64,
) -> Result<ImageReport, &'static str> {
    let api = provider(name).ok_or("unknown reverse-image provider")?;
    let mut report = fingerprint(image, now_unix)?;
    report.provider = Some(api.source);
    let (search, outcome) = if api.wanted(keys) {
        match perform(transport, api, image, keys, now_unix) {
            Ok(found) => {
                let outcome = if found.kept.is_empty() {
                    SourceExecutionOutcome::valid_zero(api.source, now_unix)
                } else {
                    SourceExecutionOutcome::success(api.source, now_unix, found.kept.len())
                };
                report.truncated = found.truncated;
                report.matches = Some(found.kept);
                (Search::Completed, outcome)
            }
            // Nothing left the device: the guarded path refused the request before sending.
            Err(error @ (LegError::Refused(_) | LegError::MissingKey(_))) => {
                (Search::NotRun, error.outcome(api, now_unix))
            }
            Err(error) => (Search::Failed, error.outcome(api, now_unix)),
        }
    } else {
        let slot = api.key.map_or("", |key| key.slot);
        (
            Search::NotRun,
            LegError::MissingKey(slot).outcome(api, now_unix),
        )
    };
    report.search = search;
    report.outcome = Some(outcome);
    Ok(report)
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
) -> Result<Collected, LegError> {
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

/// The distinct matches of one answer, in the provider's order, at most [`MAX_MATCHES`], and
/// whether more distinct ones were left out.
#[derive(Debug, Default)]
struct Collected {
    kept: Vec<ImageMatch>,
    seen: BTreeSet<(&'static str, Option<String>, Option<String>)>,
    truncated: bool,
}

impl Collected {
    /// Keeps one match that names at least one web address, unless the same one is kept already.
    fn push(
        &mut self,
        match_type: &'static str,
        source: Option<&str>,
        image: Option<&str>,
        score: Option<f64>,
    ) {
        let source_url = source.and_then(web_url);
        let image_url = image.and_then(web_url);
        if source_url.is_none() && image_url.is_none() {
            return;
        }
        if !self
            .seen
            .insert((match_type, source_url.clone(), image_url.clone()))
        {
            return;
        }
        if self.kept.len() == MAX_MATCHES {
            self.truncated = true;
            return;
        }
        self.kept.push(ImageMatch {
            match_type,
            source_url,
            image_url,
            provider_score: score.filter(|value| value.is_finite()),
        });
    }
}

/// `value` when it is a plain `http` or `https` address to keep: ASCII, at most 2 KiB, no
/// credentials, spaces, backslashes or control characters, and one the HTTP layer parses.
/// **Pure.**
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

/// What a per-image `error` in a Google Cloud Vision answer means, by its `google.rpc.Code`, at
/// the HTTP 200 the batch answer came with. **Pure.**
fn google_error(error: &Value) -> LegError {
    let kind = match error.get("code").and_then(Value::as_i64) {
        // PERMISSION_DENIED, RESOURCE_EXHAUSTED, UNAUTHENTICATED.
        Some(7) => SourceOutcomeKind::EntitlementDenied,
        Some(8) => SourceOutcomeKind::QuotaExhausted,
        Some(16) => SourceOutcomeKind::AuthRejected,
        // DEADLINE_EXCEEDED, INTERNAL, UNAVAILABLE.
        Some(4 | 13 | 14) => SourceOutcomeKind::Upstream5xx,
        // INVALID_ARGUMENT and any other code: the image or the request was refused.
        _ => SourceOutcomeKind::Upstream4xx,
    };
    LegError::NotAnAnswer(kind, 200)
}

fn parse_google(value: &Value) -> Result<Collected, LegError> {
    let first = value
        .get("responses")
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .ok_or_else(|| LegError::Decode("Google Vision answer names no responses[0]".into()))?;
    if let Some(error) = first.get("error") {
        return Err(google_error(error));
    }
    let data = first
        .get("webDetection")
        .and_then(Value::as_object)
        .ok_or_else(|| LegError::Decode("Google Vision answer has no webDetection".into()))?;
    let mut found = Collected::default();
    for (field, kind) in [
        ("fullMatchingImages", "full_image"),
        ("partialMatchingImages", "partial_image"),
        ("visuallySimilarImages", "visually_similar"),
    ] {
        for item in data
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            found.push(kind, None, item.get("url").and_then(Value::as_str), None);
        }
    }
    let pages = data
        .get("pagesWithMatchingImages")
        .and_then(Value::as_array);
    for page in pages.into_iter().flatten() {
        let source = page.get("url").and_then(Value::as_str);
        let score = page.get("score").and_then(Value::as_f64);
        found.push("page_with_match", source, None, score);
        for (field, kind) in [
            ("fullMatchingImages", "full_image_on_page"),
            ("partialMatchingImages", "partial_image_on_page"),
        ] {
            for item in page
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                found.push(kind, source, item.get("url").and_then(Value::as_str), None);
            }
        }
    }
    Ok(found)
}

fn parse_lenso(value: &Value) -> Result<Collected, LegError> {
    let rows = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| LegError::Decode("Lenso answer has no results array".into()))?;
    let mut found = Collected::default();
    for row in rows {
        let score = row.get("confidenceScore").and_then(Value::as_f64);
        for item in row
            .get("urlList")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            found.push(
                "provider_duplicate",
                item.get("sourceUrl").and_then(Value::as_str),
                item.get("imageUrl").and_then(Value::as_str),
                score,
            );
        }
    }
    Ok(found)
}

/// A whole number written as a JSON number or as a string of digits, as `SauceNAO` writes its
/// header fields. **Pure.**
fn integer(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

/// `SauceNAO`'s answer, read as its own example client reads it: a `user_id` above zero is its API
/// answering (otherwise its ordinary site took over), status 0 is a search every index answered,
/// a positive status is one or more of its indexes failing and a negative one a refused image or
/// request. Only a status-0 answer is read for matches.
fn parse_saucenao(value: &Value) -> Result<Collected, LegError> {
    let header = value
        .get("header")
        .and_then(Value::as_object)
        .ok_or_else(|| LegError::Decode("SauceNAO answer has no header".into()))?;
    if integer(header.get("user_id")).is_none_or(|user| user <= 0) {
        return Err(LegError::Decode(
            "SauceNAO answered without its API (no user_id)".into(),
        ));
    }
    match integer(header.get("status")) {
        Some(0) => {}
        Some(status) if status > 0 => {
            return Err(LegError::NotAnAnswer(SourceOutcomeKind::Upstream5xx, 200));
        }
        Some(_) => return Err(LegError::NotAnAnswer(SourceOutcomeKind::Upstream4xx, 200)),
        None => return Err(LegError::Decode("SauceNAO answer has no status".into())),
    }
    let rows = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| LegError::Decode("SauceNAO answer has no results array".into()))?;
    let mut found = Collected::default();
    for row in rows {
        let score = row.pointer("/header/similarity").and_then(|value| {
            value
                .as_str()
                .and_then(|text| text.parse::<f64>().ok())
                .or_else(|| value.as_f64())
        });
        let source = row
            .pointer("/data/ext_urls/0")
            .and_then(Value::as_str)
            .or_else(|| row.pointer("/data/source").and_then(Value::as_str));
        found.push(
            "provider_similar",
            source,
            row.pointer("/header/thumbnail").and_then(Value::as_str),
            score,
        );
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::http::{Method, Request, Response, TransportFailure};

    /// A transport that must never be used.
    struct NoNetwork;

    impl Transport for NoNetwork {
        fn send(&self, _: &Request) -> Result<Response, TransportFailure> {
            panic!("this search must not access the network");
        }
    }

    /// Answers every request with one `200` body and records each request.
    struct Scripted {
        requests: Mutex<Vec<Request>>,
        body: Vec<u8>,
    }

    impl Scripted {
        fn new(body: &Value) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                body: serde_json::to_vec(body).unwrap(),
            }
        }

        fn sent(&self) -> Vec<Request> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Transport for Scripted {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.requests.lock().unwrap().push(request.clone());
            Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: self.body.clone(),
                truncated: false,
            })
        }
    }

    const IMAGE: &[u8] = b"GIF89a\x01\x00\x01\x00";

    fn keys_with(slot: &str, secret: &str) -> Keys {
        Keys::parse(&format!("{slot}={secret}")).unwrap()
    }

    /// A key in every provider's slot, so a search that asked the wrong one would be seen.
    fn every_key() -> Keys {
        Keys::parse(&format!(
            "{}=google_secret_123\n{}=lenso_secret_123\n{}=sauce_secret_123\n",
            crate::environment::GOOGLE_VISION_KEY_ENV,
            crate::environment::LENSO_KEY_ENV,
            crate::environment::SAUCENAO_KEY_ENV,
        ))
        .unwrap()
    }

    fn sauce_answer(status: i64, results: &Value) -> Value {
        json!({"header": {"user_id": "4242", "status": status}, "results": results})
    }

    #[test]
    fn parser_google_uses_actual_image_matches_not_web_entities() {
        let v = json!({"responses":[{"webDetection":{
            "webEntities":[{"description":"person"}],
            "fullMatchingImages":[{"url":"https://images.example/a.jpg"}],
            "pagesWithMatchingImages":[{"url":"https://pages.example/p",
                "partialMatchingImages":[{"url":"https://images.example/crop.jpg"}]}]}}]});
        let results = parse_google(&v).unwrap().kept;
        assert_eq!(results.len(), 3);
        assert!(results.iter().any(|m| m.match_type == "full_image"));
        assert!(
            results
                .iter()
                .any(|m| m.source_url.as_deref() == Some("https://pages.example/p"))
        );
    }

    #[test]
    fn a_google_error_for_the_image_is_typed_by_its_code_never_an_empty_search() {
        for (code, kind) in [
            (8, SourceOutcomeKind::QuotaExhausted),
            (7, SourceOutcomeKind::EntitlementDenied),
            (16, SourceOutcomeKind::AuthRejected),
            (14, SourceOutcomeKind::Upstream5xx),
            (3, SourceOutcomeKind::Upstream4xx),
        ] {
            let answer = json!({"responses":[{"error":{"code":code,"message":"refused"}}]});
            assert_eq!(
                parse_google(&answer).unwrap_err(),
                LegError::NotAnAnswer(kind, 200)
            );
        }
        assert!(parse_google(&json!({"responses":[{}]})).is_err());
    }

    #[test]
    fn parser_lenso_exposes_link_and_provider_score() {
        let v = json!({"results":[{"confidenceScore":92.0,"urlList":[
            {"sourceUrl":"https://source.example/p","imageUrl":"https://img.example/a"}]}]});
        let result = parse_lenso(&v).unwrap().kept;
        assert_eq!(result[0].provider_score, Some(92.0));
        assert_eq!(
            result[0].source_url.as_deref(),
            Some("https://source.example/p")
        );
    }

    #[test]
    fn parser_saucenao_reads_only_a_status_zero_answer_from_its_api() {
        assert_eq!(
            parse_saucenao(&sauce_answer(-2, &json!([]))).unwrap_err(),
            LegError::NotAnAnswer(SourceOutcomeKind::Upstream4xx, 200)
        );
        assert_eq!(
            parse_saucenao(&sauce_answer(3, &json!([]))).unwrap_err(),
            LegError::NotAnAnswer(SourceOutcomeKind::Upstream5xx, 200)
        );
        let site = json!({"header":{"user_id":"0","status":0},"results":[]});
        assert!(matches!(parse_saucenao(&site), Err(LegError::Decode(_))));
        let result = parse_saucenao(&sauce_answer(
            0,
            &json!([{"header":{"similarity":"93.4","thumbnail":"https://img.example/t"},
                     "data":{"ext_urls":["https://source.example/a"]}}]),
        ))
        .unwrap()
        .kept;
        assert_eq!(result[0].provider_score, Some(93.4));
        assert_eq!(
            result[0].source_url.as_deref(),
            Some("https://source.example/a")
        );
    }

    #[test]
    fn offline_says_no_search_ran_and_holds_no_matches_rather_than_zero() {
        let report = fingerprint(IMAGE, 7).unwrap();
        assert_eq!(report.file_sha256, hex32(&sha256(IMAGE)));
        assert_eq!(report.file_bytes, IMAGE.len());
        assert_eq!(report.format, "GIF");
        assert_eq!(report.search, Search::NotRun);
        assert_eq!(report.provider, None);
        assert!(report.outcome.is_none());
        assert!(
            report.matches.is_none(),
            "offline must not read as no matches"
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["search"], "not_run");
        assert_eq!(json["matches"], Value::Null);
    }

    #[test]
    fn malformed_oversized_and_unknown_input_is_refused_before_any_request() {
        let keys = every_key();
        assert!(search_one(&NoNetwork, b"not image", &keys, LENSO_SOURCE, 1).is_err());
        let oversized = vec![0xFF; MAX_REVERSE_IMAGE_BYTES + 1];
        assert!(search_one(&NoNetwork, &oversized, &keys, LENSO_SOURCE, 1).is_err());
        assert!(search_one(&NoNetwork, b"", &keys, LENSO_SOURCE, 1).is_err());
        assert!(search_one(&NoNetwork, IMAGE, &keys, "other", 1).is_err());
        assert!(search_one(&NoNetwork, IMAGE, &keys, "", 1).is_err());
    }

    #[test]
    fn a_provider_without_a_key_is_asked_nothing_and_named_with_its_slot() {
        for api in PROVIDERS {
            let report = search_one(&NoNetwork, IMAGE, &Keys::default(), api.source, 1).unwrap();
            assert_eq!(report.search, Search::NotRun, "{}", api.source);
            assert!(report.matches.is_none());
            let outcome = report.outcome.unwrap();
            assert_eq!(outcome.kind, SourceOutcomeKind::NotConfigured);
            let slot = api.key.unwrap().slot;
            assert!(outcome.reason().contains(slot), "{}", outcome.reason());
        }
    }

    #[test]
    fn only_the_named_provider_receives_the_image_once() {
        for (api, answer) in [
            (
                &GOOGLE_VISION,
                json!({"responses":[{"webDetection":{"fullMatchingImages":[]}}]}),
            ),
            (&LENSO, json!({"results":[]})),
            (&SAUCENAO, sauce_answer(0, &json!([]))),
        ] {
            let network = Scripted::new(&answer);
            let report = search_one(&network, IMAGE, &every_key(), api.source, 9).unwrap();
            assert_eq!(report.provider, Some(api.source));
            assert_eq!(report.search, Search::Completed, "{}", api.source);
            assert_eq!(report.matches, Some(Vec::new()));
            assert_eq!(
                report.outcome.map(|outcome| outcome.kind),
                Some(SourceOutcomeKind::ValidZero),
                "a completed search that found nothing is a valid zero"
            );
            let sent = network.sent();
            assert_eq!(sent.len(), 1, "{}", api.source);
            assert_eq!(sent[0].method, Method::Post);
            assert_eq!(
                crate::http::origin_of(&sent[0].url).as_deref(),
                Some(api.origin),
                "{} sent elsewhere",
                api.source
            );
            // No other provider's key travelled with it.
            let carried = format!("{} {:?}", sent[0].url, sent[0].headers);
            for other in ["google", "lenso", "sauce"] {
                if api.source.starts_with(other) {
                    continue;
                }
                assert!(
                    !carried.contains(&format!("{other}_secret_123")),
                    "{carried}"
                );
            }
        }
    }

    #[test]
    fn google_key_is_the_header_and_not_in_the_url_or_debug() {
        let network = Scripted::new(&json!({"responses":[{"webDetection":{
            "fullMatchingImages":[{"url":"https://example.org/picture.jpg"}]}}]}));
        let secret = "testing_provider_secret_123";
        let keys = keys_with(crate::environment::GOOGLE_VISION_KEY_ENV, secret);
        let report = search_one(&network, IMAGE, &keys, GOOGLE_VISION_SOURCE, 123).unwrap();
        assert_eq!(report.observed_at_unix, 123);
        assert_eq!(report.search, Search::Completed);
        assert_eq!(report.matches.as_ref().map(Vec::len), Some(1));
        assert_eq!(
            report.outcome.as_ref().map(|outcome| outcome.kind),
            Some(SourceOutcomeKind::Success)
        );
        let sent = network.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].url, GOOGLE_VISION_URL);
        assert_eq!(sent[0].header_value("X-goog-api-key"), Some(secret));
        assert!(!format!("{:?}", sent[0]).contains(secret));
        let payload: Value = serde_json::from_slice(&sent[0].body).unwrap();
        assert_eq!(
            payload
                .pointer("/requests/0/features/0/type")
                .and_then(Value::as_str),
            Some("WEB_DETECTION")
        );
    }

    #[test]
    fn saucenao_key_is_only_the_api_key_parameter_added_as_the_request_is_sent() {
        let network = Scripted::new(&sauce_answer(0, &json!([])));
        let secret = "testing_sauce_secret_123";
        let keys = keys_with(crate::environment::SAUCENAO_KEY_ENV, secret);
        let report = search_one(&network, IMAGE, &keys, SAUCENAO_SOURCE, 123).unwrap();
        assert_eq!(report.search, Search::Completed);
        let sent = network.sent();
        assert_eq!(sent.len(), 1);
        // The URL the code builds holds no key; fetch adds it as `api_key` as it sends.
        assert!(!SAUCENAO_URL.contains(secret));
        assert_eq!(sent[0].url, format!("{SAUCENAO_URL}&api_key={secret}"));
        let body = &sent[0].body;
        assert!(
            !body
                .windows(secret.len())
                .any(|part| part == secret.as_bytes()),
            "the key is in the uploaded form"
        );
        assert!(!body.windows(7).any(|part| part == b"api_key"));
        assert!(sent[0].headers.iter().all(|(_, v)| !v.contains(secret)));
        assert!(!format!("{:?}", sent[0]).contains(secret));
        let content_type = sent[0].header_value("content-type").unwrap();
        let boundary = content_type
            .strip_prefix("multipart/form-data; boundary=")
            .unwrap();
        assert!(body.starts_with(format!("--{boundary}\r\n").as_bytes()));
        assert!(body.ends_with(format!("\r\n--{boundary}--\r\n").as_bytes()));
        assert!(body.windows(IMAGE.len()).any(|part| part == IMAGE));
    }

    #[test]
    fn lenso_token_is_a_bearer_header_bound_to_its_origin() {
        let network = Scripted::new(&json!({"results":[]}));
        let secret = "testing_lenso_secret_123";
        let keys = keys_with(crate::environment::LENSO_KEY_ENV, secret);
        let report = search_one(&network, IMAGE, &keys, LENSO_SOURCE, 123).unwrap();
        assert_eq!(report.search, Search::Completed);
        let sent = network.sent();
        assert_eq!(sent[0].url, LENSO_URL);
        assert_eq!(
            sent[0].header_value("authorization"),
            Some(format!("Bearer {secret}").as_str())
        );
        assert!(!format!("{:?}", sent[0]).contains(secret));
    }

    #[test]
    fn malformed_provider_json_is_a_failed_search_not_a_negative_result() {
        let network = Scripted::new(&json!({"notResults": []}));
        let report = search_one(&network, IMAGE, &every_key(), LENSO_SOURCE, 123).unwrap();
        assert_eq!(report.search, Search::Failed);
        assert!(report.matches.is_none());
        assert!(!report.outcome.unwrap().kind.is_accepted());
    }

    #[test]
    fn matches_are_distinct_and_truncation_counts_only_distinct_matches_left_out() {
        let mut found = Collected::default();
        for _ in 0..3 {
            found.push("full_image", None, Some("https://img.example/same"), None);
        }
        assert_eq!(found.kept.len(), 1);
        for n in 1..MAX_MATCHES {
            let url = format!("https://img.example/{n}");
            found.push("full_image", None, Some(&url), None);
        }
        assert_eq!(found.kept.len(), MAX_MATCHES);
        assert!(
            !found.truncated,
            "a repeat of a kept match is no truncation"
        );
        found.push("full_image", None, Some("https://img.example/same"), None);
        assert!(!found.truncated);
        found.push("full_image", None, Some("https://img.example/new"), None);
        assert!(found.truncated);
        assert_eq!(found.kept.len(), MAX_MATCHES);
    }

    #[test]
    fn private_embedded_and_malformed_urls_are_not_kept() {
        assert!(web_url("https://user:password@example.org/a").is_none());
        assert!(web_url("https://example.org/space here").is_none());
        assert!(web_url("javascript:alert(1)").is_none());
        assert!(web_url("https://example.org/\u{1b}[2J").is_none());
        assert_eq!(
            web_url("https://example.org/x?a=1"),
            Some("https://example.org/x?a=1".into())
        );
    }
}
