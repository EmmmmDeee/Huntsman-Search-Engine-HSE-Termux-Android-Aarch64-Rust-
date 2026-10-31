//! Cert Spotter (SSLMate): every unexpired certificate the certificate transparency logs hold
//! for a domain and its subdomains, as Spiderfoot's `sfp_certspotter` reads them, without its key
//! requirement.
//!
//! One page is `GET https://api.certspotter.com/v1/issuances?domain=D&include_subdomains=true`
//! with `match_wildcards`, every `expand` the API offers and, after the first, `after=ID` of the
//! page's last issuance. Cert Spotter answers without a key at a low rate; with
//! `HUNTSMAN_CERTSPOTTER_KEY` set the key goes as a bearer token and the limit is the account's.
//! Pages are read until one comes back empty, for at most [`MAX_PAGES`], Spiderfoot's `max_pages`.
//! A lookup that stops at that bound, or at a rate limit or failure part way, keeps every
//! certificate it read, and its row says where it stopped.
//!
//! Each certificate is one record on the queried domain: Cert Spotter's own fields (its id, the
//! certificate, TBS and key hashes, the issuer, the validity window, revocation and the CA's
//! problem-reporting address, every name) and, read from the certificate itself (see
//! [`crate::x509`]), its serial, subject, key and signature algorithms and the certificate as PEM.
//! In a saved scan these are the domain's `SSL_CERTIFICATE_RAW`, `SSL_CERTIFICATE_ISSUED`,
//! `SSL_CERTIFICATE_ISSUER` and `SSL_CERTIFICATE_EXPIRING` or `_EXPIRED`. Every name a
//! certificate covers is a domain entity (a wildcard as the name under it) listing the
//! certificates that name it, as `sfp_certspotter` reports each host. Beyond Spiderfoot, an
//! organisation a certificate's subject names (an OV or EV certificate) is an entity with its
//! place and registration, and every email address and IP address in a certificate is one too.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::{canonical_domain, canonical_email, canonical_ip};
use crate::domains::is_proper_subdomain_of;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::http::{Transport, append_query_param};
use crate::keys::Keys;
use crate::source_outcome::SourceExecutionOutcome;
use crate::tags;
use crate::x509;

pub const SOURCE: &str = "certspotter";
pub const KEY_SLOT: &str = crate::environment::CERTSPOTTER_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "sslmate.com",
    origin: "https://api.certspotter.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Bearer,
        required: false,
    }),
};
const ENDPOINT: &str = "https://api.certspotter.com/v1/issuances";
/// Every field the issuances endpoint can add to an issuance.
const EXPANSIONS: [&str; 5] = [
    "dns_names",
    "issuer",
    "revocation",
    "problem_reporting",
    "cert_der",
];

/// Pages read for one domain, Spiderfoot's `max_pages`; the row says when more were left.
pub const MAX_PAGES: usize = 20;

/// The queried domain and the organisation a certificate's subject names: the CA checked both.
const SEED_CONFIDENCE: f64 = 0.90;
/// A name under the domain, in a certificate logged for it.
const SUBDOMAIN_CONFIDENCE: f64 = 0.75;
/// An address or another domain a certificate for the domain also covers.
const COVERED_CONFIDENCE: f64 = 0.55;

#[derive(Debug, Clone, Default, Deserialize)]
struct Issuance {
    id: String,
    #[serde(default)]
    tbs_sha256: Option<String>,
    #[serde(default)]
    cert_sha256: Option<String>,
    #[serde(default)]
    dns_names: Vec<String>,
    #[serde(default)]
    pubkey_sha256: Option<String>,
    #[serde(default)]
    issuer: Option<Issuer>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    revoked: Option<bool>,
    #[serde(default)]
    revocation: Option<Revocation>,
    #[serde(default)]
    problem_reporting: Option<String>,
    #[serde(default)]
    cert_der: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Issuer {
    #[serde(default)]
    friendly_name: Option<String>,
    #[serde(default)]
    pubkey_sha256: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Revocation {
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    reason: Option<serde_json::Value>,
    #[serde(default)]
    checked_at: Option<String>,
}

/// What one lookup found and its row.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// The URL of the page of issuances for `domain` after issuance `after`. **Pure.**
#[must_use]
pub fn issuances_url(domain: &str, after: Option<&str>) -> String {
    let mut url = append_query_param(ENDPOINT, "domain", domain);
    url = append_query_param(&url, "include_subdomains", "true");
    url = append_query_param(&url, "match_wildcards", "true");
    for expansion in EXPANSIONS {
        url = append_query_param(&url, "expand", expansion);
    }
    match after {
        Some(id) => append_query_param(&url, "after", id),
        None => url,
    }
}

/// Every certificate logged for `domain` and its subdomains, read page by page.
#[must_use]
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    domain: &str,
    scan_id: &str,
    now_unix: u64,
) -> Report {
    let mut issuances = Vec::new();
    let mut pages = 0;
    let mut stopped: Option<LegError> = None;
    let mut exhausted = false;
    while pages < MAX_PAGES {
        let after = issuances
            .last()
            .map(|issuance: &Issuance| issuance.id.as_str());
        let url = issuances_url(domain, after);
        let page = match api_leg::get(transport, &API, keys, &url, now_unix) {
            Ok(Answer::Body(body)) => api_leg::decode::<Vec<Issuance>>(&body),
            // Cert Spotter answers a domain with no certificates `[]` at 200, and `sfp_certspotter`
            // reads any status but 200 and 429 as an error: a 404 is no empty page.
            Ok(Answer::NotFound(_)) => Err(LegError::Unexpected(404)),
            Err(error) => Err(error),
        };
        match page {
            Ok(page) if page.is_empty() => {
                exhausted = true;
                break;
            }
            Ok(page) => {
                pages += 1;
                issuances.extend(page);
            }
            Err(error) => {
                stopped = Some(error);
                break;
            }
        }
    }
    let entities = entities(&issuances, domain, scan_id);
    let outcome = match stopped {
        Some(error) if issuances.is_empty() => error.outcome(&API, now_unix),
        _ if issuances.is_empty() => {
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(200)
        }
        stopped => {
            let mut detail = format!("{} certificates on {pages} pages", issuances.len());
            let last = issuances.last().map_or("", |issuance| issuance.id.as_str());
            match stopped {
                Some(error) => {
                    let _ = write!(detail, "; stopped after issuance {last}: {error}");
                }
                None if !exhausted => {
                    let _ = write!(
                        detail,
                        "; stopped at {MAX_PAGES} pages, later issuances follow {last}"
                    );
                }
                None => {}
            }
            SourceExecutionOutcome::success(SOURCE, now_unix, issuances.len())
                .with_http_status(200)
                .with_detail(detail)
        }
    };
    Report { entities, outcome }
}

/// The certificate records, names, organisations and addresses of `issuances`. **Pure.**
fn entities(issuances: &[Issuance], domain: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut found = Found::default();
    for issuance in issuances {
        let cert = issuance
            .cert_der
            .as_deref()
            .and_then(crate::base64::decode_standard)
            .map(|der| (x509::parse(&der), der));
        let label = issuance
            .cert_sha256
            .clone()
            .unwrap_or_else(|| format!("issuance {}", issuance.id));
        let record = certificate_record(issuance, cert.as_ref(), &label, domain, scan_id);
        push_entity(
            &mut out,
            EntityKind::Domain,
            domain,
            SEED_CONFIDENCE,
            scan_id,
            record,
            &[tags::CT_LOG],
        );
        let parsed = cert.as_ref().and_then(|(parsed, _)| parsed.as_ref().ok());
        found.note(issuance, parsed, &label);
    }
    found.push_into(&mut out, domain, scan_id);
    out
}

/// One certificate as a record on the queried domain. **Pure.**
fn certificate_record(
    issuance: &Issuance,
    cert: Option<&(Result<x509::Certificate, x509::X509Error>, Vec<u8>)>,
    label: &str,
    domain: &str,
    scan_id: &str,
) -> Evidence {
    let issuer = issuance.issuer.clone().unwrap_or_default();
    let parsed = cert.and_then(|(parsed, _)| parsed.as_ref().ok());
    let issuer_line = parsed.map(x509::Certificate::issuer_line);
    let not_before = issuance
        .not_before
        .clone()
        .or_else(|| parsed.and_then(|c| c.not_before.clone()));
    let not_after = issuance
        .not_after
        .clone()
        .or_else(|| parsed.and_then(|c| c.not_after.clone()));
    let mut summary = format!("Certificate {label} logged for {domain}");
    if let Some(name) = issuer.friendly_name.as_deref().or(issuer.name.as_deref()) {
        let _ = write!(summary, ", issued by {name}");
    }
    if let (Some(start), Some(end)) = (&not_before, &not_after) {
        let _ = write!(summary, ", valid {start} to {end}");
    }
    let revocation = issuance.revocation.clone().unwrap_or_default();
    let reason = revocation.reason.as_ref().and_then(|reason| match reason {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        other => Some(other.to_string()),
    });
    let mut record = Evidence::new(EvidenceProvenance::for_scan(SOURCE, scan_id), summary)
        .with_attr("certspotter_id", issuance.id.as_str())
        .with_optional_attrs([
            ("cert_sha256", issuance.cert_sha256.as_deref()),
            ("tbs_sha256", issuance.tbs_sha256.as_deref()),
            ("pubkey_sha256", issuance.pubkey_sha256.as_deref()),
            ("issuer", issuer.name.as_deref().or(issuer_line.as_deref())),
            ("issuer_friendly_name", issuer.friendly_name.as_deref()),
            ("issuer_pubkey_sha256", issuer.pubkey_sha256.as_deref()),
            ("not_before", not_before.as_deref()),
            ("not_after", not_after.as_deref()),
            ("revocation_time", revocation.time.as_deref()),
            ("revocation_reason", reason.as_deref()),
            ("revocation_checked_at", revocation.checked_at.as_deref()),
            ("problem_reporting", issuance.problem_reporting.as_deref()),
        ]);
    if let Some(revoked) = issuance.revoked {
        record = record.with_attr("revoked", revoked.to_string());
    }
    if !issuance.dns_names.is_empty() {
        record = record.with_attr("dns_names", issuance.dns_names.join(", "));
    }
    match cert {
        Some((parsed, der)) => described(record, parsed.as_ref(), der),
        None => match issuance.cert_der.as_deref() {
            Some(text) => record
                .with_attr("cert_der", text)
                .with_attr("certificate_error", "not base64"),
            None => record,
        },
    }
}

/// What the certificate itself says, on its record, and the certificate as PEM. **Pure.**
fn described(
    record: Evidence,
    parsed: Result<&x509::Certificate, &x509::X509Error>,
    der: &[u8],
) -> Evidence {
    let record = record.with_attr("certificate", x509::pem(der));
    let cert = match parsed {
        Ok(cert) => cert,
        Err(error) => return record.with_attr("certificate_error", error.to_string()),
    };
    let mut record = record
        .with_attr("subject", cert.subject_line())
        .with_attr("cert_serial", cert.serial.as_str())
        .with_attr("signature_algorithm", cert.signature_algorithm.as_str())
        .with_attr("public_key", cert.public_key.as_str());
    for (key, values) in [
        ("san_emails", &cert.emails),
        ("san_ips", &cert.ip_addresses),
        ("san_uris", &cert.uris),
    ] {
        if !values.is_empty() {
            record = record.with_attr(key, values.join(", "));
        }
    }
    if cert.is_ca {
        record = record.with_attr("ca", "true");
    }
    if cert.precertificate {
        record = record.with_attr("precertificate", "true");
    }
    record
}

/// An organisation's subject, as the first certificate naming it has it, and every certificate
/// naming it.
type Holder = (Vec<(String, String)>, Vec<String>);

/// Names, organisations and addresses across the certificates, each with every certificate that
/// names it.
#[derive(Default)]
struct Found {
    /// Each canonical name: the spelling first seen and the certificates naming it.
    names: BTreeMap<String, (String, Vec<String>)>,
    /// Each organisation, keyed lower-case: its subject and the certificates naming it.
    organisations: BTreeMap<String, Holder>,
    emails: BTreeMap<String, Vec<String>>,
    addresses: BTreeMap<String, Vec<String>>,
}

impl Found {
    fn note(&mut self, issuance: &Issuance, cert: Option<&x509::Certificate>, label: &str) {
        let label = label.to_owned();
        let mut names: Vec<&str> = issuance.dns_names.iter().map(String::as_str).collect();
        if let Some(cert) = cert {
            names.extend(cert.dns_names.iter().map(String::as_str));
        }
        for name in names {
            let bare = name.trim().trim_start_matches("*.");
            if let Some(canonical) = canonical_domain(bare) {
                let entry = self
                    .names
                    .entry(canonical)
                    .or_insert_with(|| (name.trim().to_owned(), Vec::new()));
                push_once(&mut entry.1, &label);
            }
        }
        let Some(cert) = cert else {
            return;
        };
        if let Some(organisation) = cert.subject_value("O") {
            let entry = self
                .organisations
                .entry(organisation.to_lowercase())
                .or_insert_with(|| (cert.subject.clone(), Vec::new()));
            push_once(&mut entry.1, &label);
        }
        let subject_email = cert.subject_value("emailAddress");
        for email in cert.emails.iter().map(String::as_str).chain(subject_email) {
            if let Some(email) = canonical_email(email) {
                push_once(self.emails.entry(email).or_default(), &label);
            }
        }
        for address in &cert.ip_addresses {
            if let Some(address) = canonical_ip(address) {
                push_once(self.addresses.entry(address).or_default(), &label);
            }
        }
    }

    fn push_into(self, out: &mut Vec<Entity>, domain: &str, scan_id: &str) {
        let evidence = |summary: String, certificates: &[String]| {
            Evidence::new(EvidenceProvenance::for_scan(SOURCE, scan_id), summary)
                .with_attr("certificates", certificates.join("; "))
        };
        for (name, (spelling, certificates)) in self.names {
            if name == domain {
                continue;
            }
            let under = is_proper_subdomain_of(&name, domain);
            let mut seen = evidence(
                format!("Named in certificates logged for {domain}"),
                &certificates,
            );
            if spelling.starts_with("*.") {
                seen = seen.with_attr("wildcard", spelling.as_str());
            }
            let mut entity = Entity::new(
                EntityKind::Domain,
                &name,
                if under {
                    SUBDOMAIN_CONFIDENCE
                } else {
                    COVERED_CONFIDENCE
                },
                scan_id,
            );
            entity.raw_value = spelling;
            entity.tag(tags::CT_LOG);
            if under {
                entity.tag(tags::SUBDOMAIN);
            }
            entity.add_evidence(seen);
            out.push(entity);
        }
        for (subject, certificates) in self.organisations.into_values() {
            out.push(organisation(&subject, &certificates, domain, scan_id));
        }
        for (email, certificates) in self.emails {
            let seen = evidence(
                format!("In certificates logged for {domain}"),
                &certificates,
            );
            push_entity(
                out,
                EntityKind::Email,
                &email,
                COVERED_CONFIDENCE,
                scan_id,
                seen,
                &[tags::CT_LOG],
            );
        }
        for (address, certificates) in self.addresses {
            let seen = evidence(
                format!("In certificates logged for {domain}"),
                &certificates,
            );
            push_entity(
                out,
                EntityKind::IpAddress,
                &address,
                COVERED_CONFIDENCE,
                scan_id,
                seen,
                &[tags::CT_LOG],
            );
        }
    }
}

/// The organisation a certificate subject names, with the place and registration the CA checked.
/// **Pure.**
fn organisation(
    subject: &[(String, String)],
    certificates: &[String],
    domain: &str,
    scan_id: &str,
) -> Entity {
    let value = |name: &str| x509::attribute(subject, name);
    let extended = value("jurisdictionC").is_some() || value("businessCategory").is_some();
    let validation = if extended { "extended" } else { "organisation" };
    let name = value("O").unwrap_or_default();
    let seen = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!("Holder of certificates for {domain}, {validation} validation"),
    )
    .with_attr("domain", domain)
    .with_attr("validation", validation)
    .with_attr("certificate_subject", x509::one_line(subject))
    .with_attr("certificates", certificates.join("; "))
    .with_optional_attrs([
        ("unit", value("OU")),
        ("street", value("street")),
        ("city", value("L")),
        ("region", value("ST")),
        ("postal_code", value("postalCode")),
        ("country", value("C")),
        ("registration_number", value("serialNumber")),
        ("organization_identifier", value("organizationIdentifier")),
        ("business_category", value("businessCategory")),
        ("jurisdiction_locality", value("jurisdictionL")),
        ("jurisdiction_region", value("jurisdictionST")),
        ("jurisdiction_country", value("jurisdictionC")),
    ]);
    let mut entity = Entity::new(EntityKind::Organisation, name, SEED_CONFIDENCE, scan_id);
    entity.tag(tags::CT_LOG);
    entity.tag("certificate-subject");
    entity.add_evidence(seen);
    entity
}

fn push_once(list: &mut Vec<String>, label: &str) {
    if !list.iter().any(|seen| seen == label) {
        list.push(label.to_owned());
    }
}

#[cfg(test)]
mod tests;
