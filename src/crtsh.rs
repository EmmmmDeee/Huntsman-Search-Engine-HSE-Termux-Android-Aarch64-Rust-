//! crt.sh Certificate Transparency search on the guarded fetch layer.
//!
//! Ported from M D's `src/modules/crtsh` (lost local commit 764ce8e, restored on the
//! old tree as `1dfb5c9d`). Free and keyless: `GET https://crt.sh/?q=…&output=json`.
//! SAN names become `Domain` entities (subdomains of the seed's apex are boosted and
//! tagged), SAN addresses become `Email` entities, and a non-public issuing CA becomes
//! an `Organisation`. Nothing is capped: every distinct name is a pivot.
//!
//! crt.sh is slow and flaps: healthy JSON was measured at ~5–11 s, so requests get a
//! 30 s timeout, and HTTP 502 / 503 / 429 are retried a bounded number of times with a
//! fixed pause, unless the body is a challenge page. Every other outcome
//! (transport failure, challenge page at any status, 404, 500, a truncated or
//! malformed 2xx body) fails once, typed.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, TransportConfig, append_query_param};
use crate::recon::ReconTargetKind;
use crate::source_outcome::SourceOutcomeKind;
use crate::tags;

const SRC: &str = "crtsh";
const ENDPOINT: &str = "https://crt.sh/";

/// Per-request timeout. Healthy CT JSON from crt.sh lands in ~5–11 s; 8 s timed
/// out live while the same request still returned a full array seconds later.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Body cap for one CT answer. A popular apex returns several MiB of JSON; a
/// larger body is reported as truncated, never parsed as a partial answer.
pub const MAX_BODY: usize = 16 * 1024 * 1024;

/// Attempts (first try included) for a crt.sh gateway flap.
const TRANSIENT_ATTEMPTS: u32 = 3;
/// Fixed pause between transient retries. The overload clears in seconds; this is
/// not a paid rate-limit client, so exponential backoff is the wrong shape.
const TRANSIENT_PAUSE: Duration = Duration::from_secs(2);

/// Shortest SAN email surfaced (`a@b.c`).
const MIN_EMAIL_LEN: usize = 5;

// Confidence tiers carried over from the monolith's `core::confidence`.
const LOW_MEDIUM: f64 = 0.45;
const MEDIUM_HIGH: f64 = 0.55;
const HIGH_PLUS: f64 = 0.70;
const VERY_HIGH: f64 = 0.75;

/// Issuer organisations of well-known public CAs; they add no OSINT signal.
const PUBLIC_CA_ORG_PREFIXES: &[&str] = &[
    "let's encrypt",
    "letsencrypt",
    "digicert",
    "sectigo",
    "comodo",
    "globalsign",
    "identrust",
    "entrust",
    "godaddy",
    "thawte",
    "geotrust",
    "rapidssl",
    "network solutions",
    "amazon",
    "cloudflare",
    "microsoft",
    "google trust services",
    "google",
    "apple",
    "buypass",
    "zerossl",
    "ssl.com",
    "actalis",
    "certum",
    "swisssign",
    "d-trust",
    "trustwave",
    "baltimore cybertrust",
    "cybertrust",
    "verisign",
    "symantec",
    "norton",
];

/// Why a crt.sh lookup produced no answer. Never carries a response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CrtShError {
    /// Refused before sending: bad URL or the egress policy.
    #[error("crtsh: request refused: {0}")]
    Refused(String),
    /// No HTTP response (DNS, connect, TLS, timeout).
    #[error("crtsh: no response ({0:?})")]
    NoResponse(SourceOutcomeKind),
    /// A non-success HTTP status, after the retry budget where it applies.
    #[error("crtsh: HTTP {status} after {attempts} attempt(s)")]
    Status { status: u16, attempts: u32 },
    /// A 2xx that is not a CT answer (challenge page, redirect).
    #[error("crtsh: response is not a CT answer ({0:?})")]
    NotAnAnswer(SourceOutcomeKind),
    /// The body hit [`MAX_BODY`]; a partial array is not evidence.
    #[error("crtsh: response exceeds the body limit")]
    Truncated,
    /// The body is not the documented JSON array.
    #[error("crtsh: could not decode response: {0}")]
    Decode(String),
}

/// One crt.sh certificate row. Only the fields used for entities are declared.
#[derive(Debug, Default, Deserialize)]
struct CrtEntry {
    #[serde(default)]
    common_name: Option<String>,
    #[serde(default)]
    name_value: Option<String>,
    #[serde(default)]
    issuer_name: Option<String>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    serial_number: Option<String>,
}

/// What one lookup returned.
#[derive(Debug, Clone, PartialEq)]
pub struct CrtShReport {
    /// The crt.sh `q` value, or `None` for a seed kind crt.sh cannot key on.
    pub query: Option<String>,
    /// Every distinct entity, confidence-descending.
    pub entities: Vec<Entity>,
    /// Requests sent (0 when there was no query).
    pub attempts: u32,
}

/// Transport settings for crt.sh: the 30 s timeout and the CT body cap.
#[must_use]
pub fn transport_config() -> TransportConfig {
    TransportConfig {
        timeout: TIMEOUT,
        max_body: MAX_BODY,
        ..TransportConfig::default()
    }
}

/// Query crt.sh for `seed` and build entities. A seed kind with no crt.sh query
/// (`Username`) returns an empty report without a request.
///
/// # Errors
/// [`CrtShError`] when crt.sh gave no usable answer.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    kind: ReconTargetKind,
    seed: &str,
    scan_id: &str,
) -> Result<CrtShReport, CrtShError> {
    lookup_with_pause(transport, kind, seed, scan_id, &std::thread::sleep)
}

fn lookup_with_pause<T: Transport + ?Sized>(
    transport: &T,
    kind: ReconTargetKind,
    seed: &str,
    scan_id: &str,
    pause: &dyn Fn(Duration),
) -> Result<CrtShReport, CrtShError> {
    let Some(query) = build_query(kind, seed) else {
        return Ok(CrtShReport {
            query: None,
            entities: Vec::new(),
            attempts: 0,
        });
    };
    let url = append_query_param(&append_query_param(ENDPOINT, "q", &query), "output", "json");
    let (entries, attempts): (Vec<CrtEntry>, u32) =
        fetch_crt_json_with_transient_retry(transport, &url, pause)?;
    let base = apex_base(kind, seed);
    Ok(CrtShReport {
        query: Some(query),
        entities: build_entities(&entries, &base, scan_id),
        attempts,
    })
}

/// True only for the crt.sh gateway-flap class. **Pure.**
const fn is_transient_crt_status(status: u16) -> bool {
    matches!(status, 429 | 502 | 503)
}

/// One guarded GET with a bounded retry for crt.sh's transient gateway flaps:
/// at most [`TRANSIENT_ATTEMPTS`] attempts, [`TRANSIENT_PAUSE`] apart, and only for
/// [`is_transient_crt_status`] with a body that is not a challenge page (as in the
/// monolith, a bot challenge is never retried). The last failure is returned
/// unchanged.
fn fetch_crt_json_with_transient_retry<T, D>(
    transport: &T,
    url: &str,
    pause: &dyn Fn(Duration),
) -> Result<(D, u32), CrtShError>
where
    T: Transport + ?Sized,
    D: DeserializeOwned,
{
    let mut attempt = 1;
    loop {
        let fetched = fetch(
            transport,
            Request::get(url).header("Accept", "application/json"),
            None,
            &FetchOptions { max_redirects: 0 },
            SRC,
            0,
        )
        .map_err(|e| CrtShError::Refused(e.to_string()))?;
        let Some(response) = fetched.response else {
            return Err(CrtShError::NoResponse(fetched.outcome.kind));
        };
        // A challenge page is a wall at any status, 429/502/503 included, and is
        // never retried. The body is inspected directly: the shared classifier
        // labels every 429 `RateLimited` before it looks for a challenge.
        if crate::classify::is_challenge(&response.text()) {
            return Err(CrtShError::NotAnAnswer(SourceOutcomeKind::BotWaf));
        }
        if !(200..300).contains(&response.status) {
            if attempt < TRANSIENT_ATTEMPTS && is_transient_crt_status(response.status) {
                attempt += 1;
                pause(TRANSIENT_PAUSE);
                continue;
            }
            return Err(CrtShError::Status {
                status: response.status,
                attempts: attempt,
            });
        }
        if fetched.outcome.kind != SourceOutcomeKind::Inconclusive {
            return Err(CrtShError::NotAnAnswer(fetched.outcome.kind));
        }
        if response.truncated {
            return Err(CrtShError::Truncated);
        }
        let parsed = crate::http::parse_json_body(&response)
            .map_err(|e| CrtShError::Decode(e.to_string()))?;
        return Ok((parsed, attempt));
    }
}

/// The crt.sh `q` for a seed: a `%.domain` wildcard for a domain, the address for
/// an email, the host's wildcard for a URL. **Pure.**
fn build_query(kind: ReconTargetKind, value: &str) -> Option<String> {
    match kind {
        ReconTargetKind::Domain => Some(format!("%.{}", value.trim())),
        ReconTargetKind::Email => Some(value.trim().to_owned()),
        ReconTargetKind::Url => crate::domains::host_from_url(value).map(|h| format!("%.{h}")),
        ReconTargetKind::Username => None,
    }
}

/// The apex discovered names are classified against: the host of a URL, the domain
/// part of an email, the value itself for a domain. Keying on the raw URL or address
/// made every discovered subdomain look external. **Pure.**
fn apex_base(kind: ReconTargetKind, value: &str) -> String {
    match kind {
        ReconTargetKind::Url => {
            crate::domains::host_from_url(value).unwrap_or_else(|| value.to_owned())
        }
        ReconTargetKind::Email => value
            .rsplit_once('@')
            .map_or_else(|| value.to_owned(), |(_, domain)| domain.to_owned()),
        ReconTargetKind::Domain | ReconTargetKind::Username => value.to_owned(),
    }
}

/// Issuer, validity window and (when present) the serial, an attribution pivot.
/// Issuer and validity are always stamped, empty when absent. **Pure.**
fn cert_evidence(entry: &CrtEntry, summary: &str, scan_id: &str) -> Evidence {
    let mut ev = Evidence::new(EvidenceProvenance::for_scan(SRC, scan_id), summary)
        .with_attr("issuer", entry.issuer_name.as_deref().unwrap_or(""))
        .with_attr("not_before", entry.not_before.as_deref().unwrap_or(""))
        .with_attr("not_after", entry.not_after.as_deref().unwrap_or(""));
    if let Some(serial) = entry.serial_number.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("cert_serial", serial);
    }
    ev
}

/// First non-empty `O=` value of an X.509 distinguished name. **Pure.**
fn parse_dn_org(dn: &str) -> Option<&str> {
    dn.split(',')
        .filter_map(|segment| segment.trim().strip_prefix("O="))
        .map(str::trim)
        .find(|org| !org.is_empty())
}

/// A well-known public CA, matched case-insensitively by prefix. **Pure.**
fn is_public_ca(org: &str) -> bool {
    let lower = org.to_lowercase();
    PUBLIC_CA_ORG_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// CT rows → deduplicated Domain / Email / Organisation entities, every one kept,
/// confidence-descending then uid. Wildcards are skipped, role mailboxes are not
/// surfaced, and the apex is never its own subdomain. **Pure.**
fn build_entities(entries: &[CrtEntry], domain_base: &str, scan_id: &str) -> Vec<Entity> {
    let base = domain_base.trim().to_lowercase();
    let mut seen_domains = BTreeSet::new();
    let mut seen_emails = BTreeSet::new();
    let mut seen_issuers = BTreeSet::new();
    let mut out = Vec::new();

    for entry in entries {
        let names = entry
            .name_value
            .as_deref()
            .unwrap_or("")
            .split('\n')
            .chain(entry.common_name.as_deref());
        for raw in names {
            let name = raw.trim().to_lowercase();
            if name.is_empty() || name.starts_with('*') {
                continue;
            }
            if crate::canonical::canonical_email(&name).is_some() {
                if name.len() < MIN_EMAIL_LEN
                    || crate::domains::is_infrastructure_email(&name)
                    || !seen_emails.insert(name.clone())
                {
                    continue;
                }
                let mut e = Entity::new(EntityKind::Email, &name, HIGH_PLUS, scan_id);
                e.tag(tags::CT_LOG);
                e.add_evidence(cert_evidence(entry, "Email in certificate SAN", scan_id));
                out.push(e);
            } else if name.contains('.') {
                // Dedup and classify on the canonical host (`www.` stripped), the
                // same identity the monolith's entity normaliser gave a Domain, so
                // `www.example.com` and `example.com` are one name, and the
                // dot-boundary check keeps `evilexample.com` external.
                let (canonical, is_sub) = crate::domains::classify_domain_candidate(&name, &base);
                if !seen_domains.insert(canonical.clone()) {
                    continue;
                }
                let conf = if is_sub { VERY_HIGH } else { LOW_MEDIUM };
                let mut e = Entity::new(EntityKind::Domain, &canonical, conf, scan_id);
                // The spelling the certificate carried, as the monolith kept it.
                e.raw_value = name;
                e.tag(tags::CT_LOG);
                if is_sub {
                    e.tag(tags::SUBDOMAIN);
                }
                e.add_evidence(cert_evidence(
                    entry,
                    "Certificate Transparency log",
                    scan_id,
                ));
                out.push(e);
            }
        }
    }

    // A non-public issuing CA reveals custom or enterprise PKI: every domain it
    // signed shares an operator. Once per distinct `O=`.
    for entry in entries {
        let Some(dn) = entry.issuer_name.as_deref() else {
            continue;
        };
        let Some(org) = parse_dn_org(dn) else {
            continue;
        };
        if is_public_ca(org) || !seen_issuers.insert(org.to_lowercase()) {
            continue;
        }
        let mut o = Entity::new(EntityKind::Organisation, org, MEDIUM_HIGH, scan_id);
        o.tag(tags::CT_LOG);
        o.tag("certificate-issuer");
        o.tag(tags::DERIVED);
        o.add_evidence(
            cert_evidence(
                entry,
                &format!("Certificate issuer organisation: {org}"),
                scan_id,
            )
            .with_attr("issuer_dn", dn)
            .with_attr("signed_domain", domain_base),
        );
        out.push(o);
    }

    out.sort_by(|a, b| {
        b.confidence
            .total_cmp(&a.confidence)
            .then_with(|| a.uid.cmp(&b.uid))
    });
    out
}

#[cfg(test)]
mod differential;
#[cfg(test)]
mod tests;
