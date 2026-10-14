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

/// Markers that appear only on a challenge or block page: the vendor's challenge endpoint,
/// its interstitial script or its block page. A body carrying one is an interstitial.
const INTERSTITIAL: &[&str] = &[
    "challenges.cloudflare.com",
    "/cdn-cgi/challenge-platform/h/",
    "cf-chl-",
    "/sorry/index",
    "captcha-delivery.com",
    "px-captcha",
    "showcaptcha",
    "anomaly-modal",
    "httpservice/retry",
    "radware captcha",
];

/// Markers of a bot-management sensor or a CAPTCHA widget. A protected site serves its sensor
/// script on every page and a login or sign-up form embeds a widget, so on a successful
/// response these say nothing about whether the page is content; on a refusal they name the
/// vendor that refused.
const SENSOR: &[&str] = &[
    "/recaptcha/api",
    "g-recaptcha",
    "grecaptcha",
    "hcaptcha.com",
    "h-captcha",
    "datadome",
    "perimeterx",
    "_pxhd",
    "funcaptcha",
    "arkoselabs",
    "smartcaptcha",
    "perfdrive.com",
    "shieldsquare",
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

/// Whether `body` carries any challenge marker: an interstitial marker, a sensor or widget
/// marker, or a phrase. This is the right question for a refused response (403, 429, 503) and
/// for an endpoint that never serves pages; for a successful response use
/// [`is_served_challenge`], since content pages carry sensor and widget markers too.
#[must_use]
pub fn challenge_signature_present(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    INTERSTITIAL.iter().any(|n| lower.contains(n))
        || SENSOR.iter().any(|n| lower.contains(n))
        || phrase_present(&lower)
}

fn phrase_present(lower: &str) -> bool {
    PHRASES
        .iter()
        .any(|set| set.iter().all(|t| lower.contains(t)))
}

#[must_use]
pub fn is_json_body(body: &str) -> bool {
    let t = body.trim_start();
    t.starts_with('{') || t.starts_with('[')
}

/// Wall only when a signature is present and the body is not a JSON document
/// that merely quotes a vendor path. Status-blind: right for a refused response or for an
/// endpoint that only ever answers JSON (DNS over HTTPS, crt.sh), where any page is a wall.
/// For a response that may be content, use [`is_challenge_at`].
#[must_use]
pub fn is_challenge(body: &str) -> bool {
    challenge_signature_present(body) && (!is_json_body(body) || looks_like_document(body))
}

/// Largest body that can be a challenge interstitial. Interstitials are a few KiB; a longer
/// body that carries a marker is a page that mentions, embeds or serves one.
pub const CHALLENGE_MAX_BYTES: usize = 32 * 1024;

/// Whether a successful response is a challenge page: a short body with an interstitial
/// marker or a challenge phrase. A content page served with 200 carries its site's sensor
/// script and, on a login or sign-up form, a CAPTCHA widget, so those markers alone do not
/// make it a wall: counting them did drop the page as a wall and, after five such pages, opened
/// the host's circuit breaker for a minute. A body over [`CHALLENGE_MAX_BYTES`] is never a
/// served challenge and is not scanned, so a large page costs no lowercase copy.
#[must_use]
pub fn is_served_challenge(body: &str) -> bool {
    if body.len() > CHALLENGE_MAX_BYTES || (is_json_body(body) && !looks_like_document(body)) {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    INTERSTITIAL.iter().any(|n| lower.contains(n)) || phrase_present(&lower)
}

/// Whether a response is a challenge page, given its status. A refusal (anything outside
/// 2xx) is a wall on any signature, as [`is_challenge`] says; a success is a wall only when
/// the body is itself an interstitial, as [`is_served_challenge`] says.
#[must_use]
pub fn is_challenge_at(status: u16, body: &str) -> bool {
    if (200..300).contains(&status) {
        is_served_challenge(body)
    } else {
        is_challenge(body)
    }
}

/// Largest saved document that can be an interstitial page: the same bound as a served one.
pub const SAVED_CHALLENGE_MAX_BYTES: usize = CHALLENGE_MAX_BYTES;

/// Whether a saved operator document is a challenge page. Only a short HTML document with a
/// signature qualifies. Markdown, prose and long pages that quote a vendor or a phrase are kept.
/// A fetched response goes through [`classify_response`], which applies the same bound to a
/// success and none to a refusal.
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
    if is_challenge_at(status, body) {
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

    /// A login page carries its CAPTCHA widget and a protected site its sensor script on every
    /// page, so served with 200 they are content; the same bodies on a refusal are the wall.
    #[test]
    fn a_served_page_with_a_widget_or_sensor_is_content_and_a_refused_one_is_a_wall() {
        let login = format!(
            "<!doctype html><html><head><script src=\"https://www.google.com/recaptcha/api.js\"></script></head><body>{}<div class=\"g-recaptcha\" data-sitekey=\"x\"></div></body></html>",
            "<p>Jane Doe, Sydney</p>".repeat(50)
        );
        let sensored = "<html><head><script src=\"https://js.datadome.co/tags.js\"></script></head><body>datadome<h1>Jane Doe</h1></body></html>";
        for body in [login.as_str(), sensored] {
            assert!(!is_served_challenge(body), "{}", &body[..40]);
            assert!(!is_challenge_at(200, body), "{}", &body[..40]);
            assert!(classify_response(200, body).is_result(), "{}", &body[..40]);
            for status in [403, 503] {
                assert!(is_challenge_at(status, body), "{status}");
                assert!(classify_response(status, body).is_wall(), "{status}");
            }
        }
    }

    #[test]
    fn a_served_interstitial_is_a_wall() {
        for body in [
            "<html><title>Just a moment...</title>Cloudflare</html>",
            "<html><script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\"></script></html>",
            "<html><div id=\"px-captcha\"></div></html>",
            "<html><body>Please verify you are human</body></html>",
            "Our systems have detected unusual traffic from your computer network.",
        ] {
            assert!(is_served_challenge(body), "{body}");
            assert!(is_challenge_at(200, body), "{body}");
            assert!(classify_response(200, body).is_wall(), "{body}");
        }
    }

    /// Interstitials are a few KiB. A longer successful body with a marker is a page about,
    /// or embedding, a challenge, and is not even scanned; a refusal that long is still a wall.
    #[test]
    fn a_long_body_is_never_a_served_challenge() {
        let long = format!(
            "<html>{}challenges.cloudflare.com</html>",
            "x".repeat(CHALLENGE_MAX_BYTES)
        );
        assert!(!is_served_challenge(&long));
        assert!(classify_response(200, &long).is_result());
        assert!(classify_response(403, &long).is_wall());
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
