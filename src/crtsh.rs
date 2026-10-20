//! crt.sh Certificate Transparency search on the guarded fetch layer.
//!
//! Ported from M D's `src/modules/crtsh` (lost local commit 764ce8e, restored on the
//! old tree as `1dfb5c9d`). Free and keyless: `GET https://crt.sh/?q=…&output=json`.
//! SAN names become `Domain` entities (subdomains of the seed's apex are boosted and
//! tagged), SAN addresses become `Email` entities, and a non-public issuing CA becomes
//! an `Organisation`. Nothing is capped: every distinct name is a pivot, and its evidence
//! covers every certificate that names it: each crt.sh id (the whole certificate is
//! `https://crt.sh/?id=…`), serial, issuer and issuing CA id, how many there are, the
//! earliest start and latest end of validity, and when the first and newest were logged.
//!
//! crt.sh is slow and flaps: healthy JSON was measured at ~5–11 s, so requests get a
//! 30 s timeout. HTTP 502 / 503 / 429 keep their bounded retry budget; one transient
//! transport failure (connect, TTFB timeout, or body timeout) is also retried once with
//! the same fixed pause. Challenge pages, DNS/TLS failures, 404/500, truncated or
//! malformed 2xx bodies still fail once, typed.

use std::collections::{HashMap, HashSet};
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
/// One retry for a transient no-response transport failure.
const TRANSIENT_TRANSPORT_RETRIES: u32 = 1;
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
    // SSL.com issues under its legal name.
    "ssl corporation",
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

/// One crt.sh certificate row.
#[derive(Debug, Default, Deserialize)]
struct CrtEntry {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    issuer_ca_id: Option<u64>,
    #[serde(default)]
    entry_timestamp: Option<String>,
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

/// True only for no-response failures that are plausibly transient at crt.sh.
const fn is_transient_crt_transport(kind: SourceOutcomeKind) -> bool {
    matches!(
        kind,
        SourceOutcomeKind::ConnectFailure
            | SourceOutcomeKind::TtfbTimeout
            | SourceOutcomeKind::BodyTimeout
    )
}

/// One guarded GET with bounded retries for crt.sh's transient gateway and transport flaps.
/// HTTP [`is_transient_crt_status`] responses keep [`TRANSIENT_ATTEMPTS`] as their own
/// budget. A transient connect/TTFB/body failure gets one retry. All retries pause for
/// [`TRANSIENT_PAUSE`]. Bot challenges are never retried.
fn fetch_crt_json_with_transient_retry<T, D>(
    transport: &T,
    url: &str,
    pause: &dyn Fn(Duration),
) -> Result<(D, u32), CrtShError>
where
    T: Transport + ?Sized,
    D: DeserializeOwned,
{
    let mut attempts = 0;
    let mut status_retries = 0;
    let mut transport_retries = 0;
    loop {
        attempts += 1;
        let fetched = fetch(
            transport,
            Request::get(url).header("Accept", "application/json"),
            None,
            &FetchOptions::no_redirects(),
            SRC,
            0,
        )
        .map_err(|e| CrtShError::Refused(e.to_string()))?;
        let Some(response) = fetched.response else {
            let kind = fetched.outcome.kind;
            if transport_retries < TRANSIENT_TRANSPORT_RETRIES && is_transient_crt_transport(kind) {
                transport_retries += 1;
                pause(TRANSIENT_PAUSE);
                continue;
            }
            return Err(CrtShError::NoResponse(kind));
        };
        // A challenge page is a wall at any status, 429/502/503 included, and is
        // never retried. The body is inspected directly: the shared classifier
        // labels every 429 `RateLimited` before it looks for a challenge.
        if crate::classify::is_challenge(&response.text_view()) {
            return Err(CrtShError::NotAnAnswer(SourceOutcomeKind::BotWaf));
        }
        if !(200..300).contains(&response.status) {
            if status_retries + 1 < TRANSIENT_ATTEMPTS && is_transient_crt_status(response.status) {
                status_retries += 1;
                pause(TRANSIENT_PAUSE);
                continue;
            }
            return Err(CrtShError::Status {
                status: response.status,
                attempts,
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
        return Ok((parsed, attempts));
    }
}

/// The crt.sh `q` for a seed: a `%.domain` wildcard for a domain, the address for
/// an email, the host's wildcard for a URL. **Pure.**
fn build_query(kind: ReconTargetKind, value: &str) -> Option<String> {
    match kind {
        // The same canonical apex `build_entities` classifies against: a
        // mixed-case, `www.` or root-dotted seed otherwise queried a literal
        // crt.sh never matches.
        ReconTargetKind::Domain => {
            let host = crate::domains::canonical_domain_host(value)
                .unwrap_or_else(|| value.trim().trim_end_matches('.').to_ascii_lowercase());
            Some(format!("%.{host}"))
        }
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

/// Values in the order first given, each once. **Pure.**
#[derive(Default)]
struct Distinct {
    values: Vec<String>,
    seen: HashSet<String>,
}

impl Distinct {
    fn push(&mut self, value: Option<String>) {
        if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
            if self.seen.insert(value.clone()) {
                self.values.push(value);
            }
        }
    }
}

/// The earliest and latest of some times crt.sh writes in one ISO 8601 form, so the text
/// orders as the time. **Pure.**
fn span<'a>(times: impl Iterator<Item = Option<&'a str>>) -> (Option<&'a str>, Option<&'a str>) {
    let times: Vec<&str> = times.flatten().filter(|t| !t.is_empty()).collect();
    (times.iter().copied().min(), times.iter().copied().max())
}

/// [`cert_evidence`] of the first certificate that names an entity, and across every one that
/// names it: each crt.sh id, serial, issuer and issuing CA id, the common names, how many
/// certificates there are, the earliest start and latest end of validity, and when the first
/// and newest were logged. Issuer names hold commas, so they are joined with `; `, the
/// separator [`Evidence::attr_values`] splits on. **Pure.**
fn certificates_evidence(certs: &[&CrtEntry], summary: &str, scan_id: &str) -> Evidence {
    let Some(first) = certs.first() else {
        return cert_evidence(&CrtEntry::default(), summary, scan_id);
    };
    let (mut ids, mut serials, mut issuers, mut ca_ids, mut common) = (
        Distinct::default(),
        Distinct::default(),
        Distinct::default(),
        Distinct::default(),
        Distinct::default(),
    );
    for cert in certs {
        ids.push(cert.id.map(|id| id.to_string()));
        serials.push(cert.serial_number.clone());
        issuers.push(cert.issuer_name.clone());
        ca_ids.push(cert.issuer_ca_id.map(|id| id.to_string()));
        common.push(cert.common_name.as_deref().map(str::to_lowercase));
    }
    let count = if ids.values.is_empty() {
        certs.len()
    } else {
        ids.values.len()
    };
    let (first_start, _) = span(certs.iter().map(|c| c.not_before.as_deref()));
    let (_, last_end) = span(certs.iter().map(|c| c.not_after.as_deref()));
    let (first_logged, last_logged) = span(certs.iter().map(|c| c.entry_timestamp.as_deref()));
    let mut ev =
        cert_evidence(first, summary, scan_id).with_attr("certificates", count.to_string());
    for (key, values, separator) in [
        ("cert_ids", &ids.values, ","),
        ("cert_serials", &serials.values, ","),
        ("issuers", &issuers.values, "; "),
        ("issuer_ca_ids", &ca_ids.values, ","),
        ("common_names", &common.values, ","),
    ] {
        if !values.is_empty() {
            ev = ev.with_attr(key, values.join(separator));
        }
    }
    for (key, value) in [
        ("first_not_before", first_start),
        ("last_not_after", last_end),
        ("first_logged", first_logged),
        ("last_logged", last_logged),
    ] {
        if let Some(value) = value {
            ev = ev.with_attr(key, value);
        }
    }
    ev
}

/// First non-empty `O=` value of an X.509 distinguished name. **Pure.**
fn parse_dn_org(dn: &str) -> Option<String> {
    dn_attributes(dn)
        .into_iter()
        .find(|(key, value)| key == "O" && !value.is_empty())
        .map(|(_, value)| value)
}

/// The `KEY=value` pairs of a distinguished name in its one-line form, as crt.sh prints it
/// (`C=US, O="CLOUDFLARE, INC.", CN=…`), each value unquoted and unescaped. A comma or `+`
/// separates attributes only outside double quotes and when not escaped with a backslash, so
/// an organisation such as `"Example, Inc."` stays whole. **Pure.**
fn dn_attributes(dn: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let (mut key, mut value) = (String::new(), String::new());
    let (mut in_value, mut quoted) = (false, false);
    let mut chars = dn.chars();
    while let Some(c) = chars.next() {
        let literal = match c {
            '\\' => chars.next(),
            '"' => {
                quoted = !quoted;
                None
            }
            ',' | '+' if !quoted => {
                push_attribute(&mut pairs, &mut key, &mut value);
                in_value = false;
                None
            }
            '=' if !in_value => {
                in_value = true;
                None
            }
            c => Some(c),
        };
        if let Some(c) = literal {
            if in_value { &mut value } else { &mut key }.push(c);
        }
    }
    push_attribute(&mut pairs, &mut key, &mut value);
    pairs
}

fn push_attribute(pairs: &mut Vec<(String, String)>, key: &mut String, value: &mut String) {
    let name = key.trim();
    if !name.is_empty() {
        pairs.push((name.to_owned(), value.trim().to_owned()));
    }
    key.clear();
    value.clear();
}

/// A well-known public CA, matched case-insensitively by prefix. **Pure.**
fn is_public_ca(org: &str) -> bool {
    let lower = org.to_lowercase();
    PUBLIC_CA_ORG_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Every name a certificate row lists: its SAN lines and its common name. **Pure.**
fn names_of(entry: &CrtEntry) -> impl Iterator<Item = &str> {
    entry
        .name_value
        .as_deref()
        .unwrap_or("")
        .split('\n')
        .chain(entry.common_name.as_deref())
}

/// One entity of the lookup and every certificate that names it.
struct Named<'a> {
    entity: Entity,
    summary: String,
    certs: Vec<&'a CrtEntry>,
}

impl<'a> Named<'a> {
    fn new(entity: Entity, summary: impl Into<String>) -> Self {
        Self {
            entity,
            summary: summary.into(),
            certs: Vec::new(),
        }
    }

    /// Count `entry` once, however many of its names lead here.
    fn named_by(&mut self, entry: &'a CrtEntry) {
        if !self
            .certs
            .last()
            .is_some_and(|last| std::ptr::eq(*last, entry))
        {
            self.certs.push(entry);
        }
    }
}

/// The entity a certificate name stands for, keyed by its identity, or `None` for a name
/// that is not surfaced: a wildcard, a role mailbox, a too-short address or a bare label.
/// **Pure.**
fn name_entity(name: &str, base: &str, scan_id: &str) -> Option<(String, Named<'static>)> {
    if name.is_empty() || name.starts_with('*') {
        return None;
    }
    if crate::canonical::canonical_email(name).is_some() {
        if name.len() < MIN_EMAIL_LEN || crate::domains::is_infrastructure_email(name) {
            return None;
        }
        let mut e = Entity::new(EntityKind::Email, name, HIGH_PLUS, scan_id);
        e.tag(tags::CT_LOG);
        return Some((
            format!("email {name}"),
            Named::new(e, "Email in certificate SAN"),
        ));
    }
    if !name.contains('.') {
        return None;
    }
    // Dedup and classify on the canonical host (`www.` stripped), the same identity the
    // monolith's entity normaliser gave a Domain, so `www.example.com` and `example.com` are
    // one name, and the dot-boundary check keeps `evilexample.com` external.
    let (canonical, is_sub) = crate::domains::classify_domain_candidate(name, base);
    let conf = if is_sub { VERY_HIGH } else { LOW_MEDIUM };
    let mut e = Entity::new(EntityKind::Domain, &canonical, conf, scan_id);
    // The spelling the certificate carried, as the monolith kept it.
    name.clone_into(&mut e.raw_value);
    e.tag(tags::CT_LOG);
    if is_sub {
        e.tag(tags::SUBDOMAIN);
    }
    Some((
        format!("domain {canonical}"),
        Named::new(e, "Certificate Transparency log"),
    ))
}

/// CT rows → deduplicated Domain / Email / Organisation entities, every one kept,
/// confidence-descending then uid. Wildcards are skipped, role mailboxes are not
/// surfaced, and the apex is never its own subdomain. Each entity's evidence covers every
/// certificate that names it ([`certificates_evidence`]). **Pure.**
fn build_entities(entries: &[CrtEntry], domain_base: &str, scan_id: &str) -> Vec<Entity> {
    let base = domain_base.trim().to_lowercase();
    let mut named: Vec<Named<'_>> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();

    for entry in entries {
        for raw in names_of(entry) {
            let name = raw.trim().to_lowercase();
            let Some((key, fresh)) = name_entity(&name, &base, scan_id) else {
                continue;
            };
            let at = *index.entry(key).or_insert_with(|| {
                named.push(fresh);
                named.len() - 1
            });
            named[at].named_by(entry);
        }
    }

    // A non-public issuing CA reveals custom or enterprise PKI: every domain it
    // signed shares an operator. Once per distinct `O=`.
    let mut signed: Vec<(String, Vec<&CrtEntry>)> = Vec::new();
    let mut seen_issuers: HashMap<String, usize> = HashMap::new();
    for entry in entries {
        let Some(org) = entry.issuer_name.as_deref().and_then(parse_dn_org) else {
            continue;
        };
        if is_public_ca(&org) {
            continue;
        }
        let at = *seen_issuers.entry(org.to_lowercase()).or_insert_with(|| {
            signed.push((org, Vec::new()));
            signed.len() - 1
        });
        signed[at].1.push(entry);
    }

    let mut out: Vec<Entity> = named
        .into_iter()
        .map(
            |Named {
                 mut entity,
                 summary,
                 certs,
             }| {
                entity.add_evidence(certificates_evidence(&certs, &summary, scan_id));
                entity
            },
        )
        .collect();
    for (org, certs) in signed {
        let mut o = Entity::new(EntityKind::Organisation, org.as_str(), MEDIUM_HIGH, scan_id);
        o.tag(tags::CT_LOG);
        o.tag("certificate-issuer");
        o.tag(tags::DERIVED);
        let dn = certs
            .first()
            .and_then(|c| c.issuer_name.as_deref())
            .unwrap_or_default();
        let mut signed_names = Distinct::default();
        for cert in &certs {
            for name in names_of(cert) {
                signed_names.push(Some(name.trim().to_lowercase()));
            }
        }
        let mut ev = certificates_evidence(
            &certs,
            &format!("Certificate issuer organisation: {org}"),
            scan_id,
        )
        .with_attr("issuer_dn", dn)
        .with_attr("signed_domain", domain_base);
        if !signed_names.values.is_empty() {
            ev = ev.with_attr("signed_names", signed_names.values.join(","));
        }
        o.add_evidence(ev);
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
#[cfg(test)]
mod transport_retry_tests;
