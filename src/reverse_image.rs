//! Bounded, explicit reverse-image web search. These providers search their own indexes, not
//! the whole internet. A visually similar image is never evidence of a person's identity.
//! No provider is contacted unless the operator asks for --live and has configured its key.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::credential_origin::AuthenticationAuthority;
use crate::fetch::{AuthStyle, Credential, FetchOptions, fetch};
use crate::http::{Request, Transport};
use crate::keys::{Keys, Secret};
use crate::sha256::{hex32, sha256};

/// Cap memory use for image bytes, Base64 encoding, request building and downstream providers.
pub const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_MATCHES: usize = 80;
const PROVIDERS: [(&str, &str); 3] = [
    ("google_vision", "HSE_GOOGLE_VISION_API_KEY"),
    ("lenso", "HSE_LENSO_API_KEY"),
    ("saucenao", "HSE_SAUCENAO_API_KEY"),
];

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
    (value.len() <= 2048 && (value.starts_with("https://") || value.starts_with("http://")))
        .then(|| value.to_owned())
}

fn insert(
    matches: &mut Vec<ImageMatch>,
    provider: &str,
    kind: &str,
    source: Option<&str>,
    image: Option<&str>,
    score: Option<f64>,
) {
    if matches.len() >= MAX_MATCHES {
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
    let first = value.get("responses").and_then(Value::as_array)
        .and_then(|list| list.first()).ok_or("google response is missing responses[0]")?;
    if first.get("error").is_some() {
        return Err("google reported a request error");
    }
    let data = first.get("webDetection").and_then(Value::as_object)
        .ok_or("google response is missing webDetection")?;
    let mut matches = Vec::new();
    for (field, kind) in [
        ("fullMatchingImages", "full_image"),
        ("partialMatchingImages", "partial_image"),
        ("visuallySimilarImages", "visually_similar"),
    ] {
        if let Some(items) = data.get(field).and_then(Value::as_array) {
            for item in items {
                insert(&mut matches, "google_vision", kind, None,
                    item.get("url").and_then(Value::as_str), None);
            }
        }
    }
    if let Some(pages) = data.get("pagesWithMatchingImages").and_then(Value::as_array) {
        for page in pages {
            let source = page.get("url").and_then(Value::as_str);
            insert(&mut matches, "google_vision", "page_with_match", source, None,
                page.get("score").and_then(Value::as_f64));
            for (field, kind) in [("fullMatchingImages", "full_image_on_page"),
                                   ("partialMatchingImages", "partial_image_on_page")] {
                if let Some(items) = page.get(field).and_then(Value::as_array) {
                    for item in items {
                        insert(&mut matches, "google_vision", kind, source,
                            item.get("url").and_then(Value::as_str), None);
                    }
                }
            }
        }
    }
    Ok(matches)
}

fn parse_lenso(value: &Value) -> Result<Vec<ImageMatch>, &'static str> {
    let rows = value.get("results").and_then(Value::as_array)
        .ok_or("lenso response is missing results array")?;
    let mut matches = Vec::new();
    for row in rows {
        let score = row.get("confidenceScore").and_then(Value::as_f64);
        if let Some(urls) = row.get("urlList").and_then(Value::as_array) {
            for item in urls {
                insert(&mut matches, "lenso", "provider_duplicate",
                    item.get("sourceUrl").and_then(Value::as_str),
                    item.get("imageUrl").and_then(Value::as_str), score);
            }
        }
    }
    Ok(matches)
}

fn parse_saucenao(value: &Value) -> Result<Vec<ImageMatch>, &'static str> {
    let header = value.get("header").and_then(Value::as_object)
        .ok_or("SauceNAO response is missing header")?;
    if header.get("status").and_then(Value::as_i64) != Some(0) {
        return Err("SauceNAO returned a non-success status");
    }
    let rows = value.get("results").and_then(Value::as_array)
        .ok_or("SauceNAO response is missing results array")?;
    let mut matches = Vec::new();
    for row in rows {
        let score = row.pointer("/header/similarity")
            .and_then(|v| v.as_str().and_then(|s| s.parse::<f64>().ok())
                .or_else(|| v.as_f64()));
        let source = row.pointer("/data/ext_urls/0").and_then(Value::as_str)
            .or_else(|| row.pointer("/data/source").and_then(Value::as_str));
        insert(&mut matches, "saucenao", "provider_similar", source,
            row.pointer("/header/thumbnail").and_then(Value::as_str), score);
    }
    Ok(matches)
}

fn multipart_body(image: &[u8], secret: &Secret, boundary: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(image.len() + 1024);
    for (name, value) in [("api_key", secret.expose()), ("output_type", "2"),
                          ("db", "999"), ("numres", "10")] {
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes());
    }
    body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"image.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
    body.extend_from_slice(image);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

fn sauce_request(image: &[u8], secret: &Secret) -> Request {
    let mut boundary = "HSE_Image_Boundary_A".to_owned();
    while image.windows(boundary.len()).any(|window| window == boundary.as_bytes()) {
        boundary.push('Z');
    }
    Request::post("https://saucenao.com/search.php",
                  multipart_body(image, secret, &boundary))
        .header("Content-Type", format!("multipart/form-data; boundary={boundary}"))
}

fn perform<T: Transport + ?Sized>(
    transport: &T,
    name: &'static str,
    slot: &'static str,
    image: &[u8],
    secret: &Secret,
    now: u64,
) -> Result<Vec<ImageMatch>, String> {
    let b64 = crate::base64::standard(image);
    let (request, credential) = match name {
        "google_vision" => {
            let body = json!({"requests": [{"image": {"content": b64},
                "features": [{"type": "WEB_DETECTION", "maxResults": 20}]}]});
            let request = Request::post("https://vision.googleapis.com/v1/images:annotate",
                serde_json::to_vec(&body).map_err(|_| "could not encode request")?)
                .header("Content-Type", "application/json");
            let authority = AuthenticationAuthority::configured_slot(name, slot, now)
                .map_err(|_| "credential authority invalid")?;
            let cred = Credential::new(authority, secret.clone(),
                AuthStyle::Header("X-goog-api-key".into()))
                .map_err(|_| "credential invalid")?
                .only_for_origin("https://vision.googleapis.com:443");
            (request, Some(cred))
        }
        "lenso" => {
            let body = json!({"image": b64, "category": "duplicates",
                "sortType": "QUALITY_DESCENDING", "page": 1});
            let request = Request::post("https://api.lenso.ai/search",
                serde_json::to_vec(&body).map_err(|_| "could not encode request")?)
                .header("Content-Type", "application/json");
            let authority = AuthenticationAuthority::configured_slot(name, slot, now)
                .map_err(|_| "credential authority invalid")?;
            let cred = Credential::new(authority, secret.clone(), AuthStyle::Bearer)
                .map_err(|_| "credential invalid")?
                .only_for_origin("https://api.lenso.ai:443");
            (request, Some(cred))
        }
        "saucenao" => (sauce_request(image, secret), None),
        _ => return Err("unknown provider".into()),
    };
    // Never follow redirects for image uploads or credentials, including SauceNAO's body secret.
    let fetched = fetch(transport, request.with_timeout(Duration::from_secs(30)),
        credential.as_ref(), &FetchOptions::no_redirects(), name, now)
        .map_err(|_| "network policy or request refused")?;
    let response = fetched.response.ok_or_else(|| format!("transport: {}",
        fetched.outcome.kind.as_str()))?;
    if response.truncated {
        return Err("provider response truncated".into());
    }
    if response.status != 200 {
        return Err(format!("HTTP {}", response.status));
    }
    let json: Value = serde_json::from_slice(&response.body)
        .map_err(|_| "provider response is not valid JSON")?;
    match name {
        "google_vision" => parse_google(&json),
        "lenso" => parse_lenso(&json),
        "saucenao" => parse_saucenao(&json),
        _ => Err("unknown provider"),
    }.map_err(str::to_owned)
}

/// Compute the immutable input hash offline, then optionally query all three configured
/// providers. Absent credentials are skipped; a failure is not an empty search result.
/// No external provider search is performed unless `live` is explicitly true.
///
/// # Errors
/// Rejects empty, oversized or unrecognised image bytes without making a network request.
pub fn search<T: Transport + ?Sized>(
    transport: &T, image: &[u8], keys: &Keys, now: u64, live: bool,
) -> Result<ImageReport, &'static str> {
    if image.is_empty() || image.len() > MAX_IMAGE_BYTES || !is_image(image) {
        return Err("expected a JPEG, PNG, GIF or WebP image of 1 byte to 4 MiB");
    }
    let mut report = ImageReport {
        image_sha256: hex32(&sha256(image)),
        bytes: image.len(),
        live_requested: live,
        statuses: Vec::new(),
        matches: Vec::new(),
    };
    for (name, slot) in PROVIDERS {
        let status = if !live {
            ProviderStatus {provider: name, state: "not_requested",
                detail: "offline only (pass --live to send image to providers)".into(), results: 0}
        } else if let Some(secret) = keys.get(slot) {
            match perform(transport, name, slot, image, &secret, now) {
                Ok(mut matches) => {
                    let count = matches.len();
                    report.matches.append(&mut matches);
                    ProviderStatus {provider: name, state: "completed",
                        detail: "response parsed; matches are not proof of identity".into(),
                        results: count}
                }
                Err(message) => ProviderStatus {provider: name, state: "failed",
                    detail: message, results: 0},
            }
        } else {
            ProviderStatus {provider: name, state: "unconfigured",
                detail: format!("set {slot} in the private credentials file"),
                results: 0}
        };
        report.statuses.push(status);
    }
    let mut seen = BTreeSet::new();
    report.matches.retain(|m| seen.insert((m.provider.clone(), m.match_type.clone(),
        m.source_url.clone(), m.image_url.clone())));
    report.matches.truncate(MAX_MATCHES);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(results.iter().any(|m| m.source_url.as_deref() == Some("https://pages.example/p")));
    }

    #[test]
    fn parser_lenso_exposes_link_and_provider_score() {
        let v = json!({"results":[{"confidenceScore":92.0,"urlList":[
            {"sourceUrl":"https://source.example/p","imageUrl":"https://img.example/a"}]}]});
        let result = parse_lenso(&v).unwrap();
        assert_eq!(result[0].provider_score, Some(92.0));
        assert_eq!(result[0].source_url.as_deref(), Some("https://source.example/p"));
    }

    #[test]
    fn parser_saucenao_refuses_provider_status_errors() {
        assert!(parse_saucenao(&json!({"header":{"status":-2},"results":[]})).is_err());
        let result = parse_saucenao(&json!({"header":{"status":0},"results":[
            {"header":{"similarity":"93.4","thumbnail":"https://img.example/t"},
             "data":{"ext_urls":["https://source.example/a"]}}]})).unwrap();
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
        let report = search(&NoNetwork, image, &keys, 1, false).unwrap();
        assert_eq!(report.image_sha256.len(), 64);
        assert!(report.matches.is_empty());
        assert!(report.statuses.iter().all(|s| s.state == "not_requested"));
    }

    #[test]
    fn live_without_keys_is_unconfigured_not_empty_and_does_not_call_network() {
        let report = search(&NoNetwork, b"GIF89a", &Keys::parse("").unwrap(), 1, true).unwrap();
        assert!(report.statuses.iter().all(|s| s.state == "unconfigured"));
        assert!(report.matches.is_empty());
    }

    #[test]
    fn malformed_and_oversized_input_rejected_before_network() {
        let keys = Keys::parse("").unwrap();
        assert!(search(&NoNetwork, b"not image", &keys, 1, true).is_err());
        assert!(search(&NoNetwork, &vec![0xff; MAX_IMAGE_BYTES + 1], &keys, 1, true).is_err());
    }
}
