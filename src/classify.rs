//! Fetch outcome classifier. A challenge page is Blocked, never a result, never an outage.
//! 429 beats a vendor string. JSON that merely quotes a vendor path is not a wall.
//! Tables preserved from the 98c77fd floor. No live fetch.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FetchOutcome {
    Parsed,
    RateLimited { status: u16, detail: String },
    Blocked { status: u16, detail: String },
    Failed { detail: String },
}

impl FetchOutcome {
    #[must_use]
    pub fn is_wall(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    #[must_use]
    pub fn is_throttle(&self) -> bool {
        matches!(self, Self::RateLimited { .. })
    }

    #[must_use]
    pub fn is_result(&self) -> bool {
        matches!(self, Self::Parsed)
    }
}

const OPENERS: &[&str] = &["<!doctype html", "<html", "<head", "<body"];

const VENDOR: &[&str] = &[
    "challenges.cloudflare.com",
    "/cdn-cgi/challenge-platform/h/",
    "cf-chl-",
    "/recaptcha/api",
    "g-recaptcha",
    "grecaptcha",
    "/sorry/index",
    "hcaptcha.com",
    "h-captcha",
    "captcha-delivery.com",
    "datadome",
    "perimeterx",
    "px-captcha",
    "_pxhd",
    "funcaptcha",
    "arkoselabs",
    "smartcaptcha",
    "showcaptcha",
    "anomaly-modal",
    "httpservice/retry",
    "perfdrive.com",
    "shieldsquare",
    "radware captcha",
];

const PHRASES: &[&[&str]] = &[
    &["just a moment", "cloudflare"],
    &["attention required", "cloudflare"],
    &["checking your browser", "cloudflare"],
    &["unusual traffic", "network"],
    &["before you continue", "consent"],
    &["request unsuccessful", "incapsula"],
    &["are not a robot"],
    &["verify you are human"],
    &["sending automated queries"],
    &["enable javascript and cookies to continue"],
    &["access to this page has been denied"],
    &["your request has been blocked", "reference number"],
    &["blocked by network security"],
    &["enable javascript to view the page content", "support id"],
    &["the requested url was rejected", "support id"],
];

#[must_use]
pub fn looks_like_document(body: &str) -> bool {
    let head = body.trim_start().as_bytes();
    OPENERS.iter().any(|opener| {
        head.get(..opener.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(opener.as_bytes()))
    })
}

#[must_use]
pub fn challenge_signature_present(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    VENDOR.iter().any(|n| lower.contains(n))
        || PHRASES
            .iter()
            .any(|set| set.iter().all(|t| lower.contains(t)))
}

#[must_use]
pub fn is_json_body(body: &str) -> bool {
    let t = body.trim_start();
    t.starts_with('{') || t.starts_with('[')
}

/// Wall only when a signature is present and the body is not a JSON document
/// that merely quotes a vendor path.
#[must_use]
pub fn is_challenge(body: &str) -> bool {
    challenge_signature_present(body) && (!is_json_body(body) || looks_like_document(body))
}

/// Largest saved document that can be an interstitial page. Interstitials are short, so a longer
/// document that carries a vendor string or a phrase is a page that mentions one.
pub const SAVED_CHALLENGE_MAX_BYTES: usize = 32 * 1024;

/// Whether a saved operator document is a challenge page. Only a short HTML document with a
/// signature qualifies. Markdown, prose and long pages that quote a vendor or a phrase are kept.
/// Fetched responses still use [`classify_response`] with no size bound: a challenge missed there
/// would read as an absent result.
#[must_use]
pub fn is_saved_challenge(body: &str) -> bool {
    body.len() <= SAVED_CHALLENGE_MAX_BYTES
        && looks_like_document(body)
        && challenge_signature_present(body)
}

#[must_use]
pub fn classify_response(status: u16, body: &str) -> FetchOutcome {
    if status == 429 {
        return FetchOutcome::RateLimited {
            status,
            detail: snippet(body),
        };
    }
    if is_challenge(body) {
        return FetchOutcome::Blocked {
            status,
            detail: snippet(body),
        };
    }
    if !(200..300).contains(&status) {
        return FetchOutcome::Failed {
            detail: format!("HTTP {status}: {}", snippet(body)),
        };
    }
    FetchOutcome::Parsed
}

fn snippet(body: &str) -> String {
    let trimmed = body.trim();
    let end = trimmed
        .char_indices()
        .nth(180)
        .map_or(trimmed.len(), |(i, _)| i);
    trimmed[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_beats_vendor_and_json_quote_is_not_a_wall() {
        let limited = classify_response(429, "challenges.cloudflare.com");
        assert!(limited.is_throttle());
        assert!(!limited.is_wall());
        let quoted = classify_response(200, r#"{"url":"https://challenges.cloudflare.com/x"}"#);
        assert!(quoted.is_result());
        let wall = classify_response(200, "<html>just a moment cloudflare</html>");
        assert!(wall.is_wall());
        assert!(!wall.is_result());
        let down = classify_response(503, "origin unavailable");
        assert!(matches!(down, FetchOutcome::Failed { .. }));
    }

    #[test]
    fn multibyte_body_never_panics_the_opener_check() {
        for body in [
            r#"{"éé":"datadome"}"#,
            "[ééééééé datadome",
            "ééééééé datadome",
            r#"{"名前名前":"datadome"}"#,
        ] {
            let _ = classify_response(200, body);
            let _ = is_challenge(body);
        }
        assert!(!looks_like_document("é<html>"));
        assert!(looks_like_document("  <!DOCTYPE HTML><p>"));
    }

    #[test]
    fn saved_challenge_must_be_a_short_html_document() {
        assert!(is_saved_challenge("<html>just a moment cloudflare</html>"));
        assert!(is_saved_challenge("  <!DOCTYPE html><p>datadome</p>"));
        // Markdown and prose that quote a challenge are documents.
        assert!(!is_saved_challenge(
            "# Notes\n\n`<html>just a moment cloudflare</html>`\n"
        ));
        assert!(!is_saved_challenge("DataDome blocked the request"));
        // Structured data that quotes a vendor path is not a page.
        assert!(!is_saved_challenge(
            r#"{"url":"https://challenges.cloudflare.com/x"}"#
        ));
        // A long page with a captcha widget is not an interstitial.
        let long = format!(
            "<html>{}<script src=\"https://www.google.com/recaptcha/api.js\"></script>",
            "x".repeat(SAVED_CHALLENGE_MAX_BYTES)
        );
        assert!(!is_saved_challenge(&long));
    }

    #[test]
    fn reddit_block_opens_as_a_document() {
        assert!(looks_like_document(
            "<body class=theme-beta>blocked by network security"
        ));
        assert!(is_challenge(
            "<body class=theme-beta>blocked by network security"
        ));
    }
}
