//! `security.txt` (RFC 9116) — a domain's *published* security contacts.
//!
//! Free, keyless, single fetch. RFC 9116 standardises a machine-readable file at
//! `https://<domain>/.well-known/security.txt` (with a legacy root fallback)
//! where an organisation publishes how to reach its security team: `Contact:`
//! (email / phone / web form), `Encryption:` (a PGP key location), plus
//! `Canonical`, `Policy`, `Acknowledgments`, and `Hiring` URLs. It is a
//! high-signal, authoritative source of **contact intelligence an organisation
//! deliberately published about itself** — exactly the identity/contact pivots a
//! domain scan wants, and one no other HSE module collects.
//!
//! The parse ([`parse_security_txt`]) is a pure function over the file body, so
//! the field → entity mapping is unit-tested without a live fetch; `process`
//! owns only URL construction, the `.well-known`→root fallback, and transport.

use std::collections::HashSet;

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, read_body_capped};

const SRC: &str = "security_txt";

/// A security.txt is tiny (RFC 9116 files are a handful of lines); 64 KB is a
/// generous cap that still refuses a mis-served binary/HTML blob.
const BODY_CAP: usize = 64 * 1024;

pub struct SecurityTxt;

#[async_trait]
impl Module for SecurityTxt {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "RFC 9116 security.txt recon — extracts a domain's published security contacts (email, phone, PGP key, policy URLs)"
    }
    fn priority(&self) -> u8 {
        36
    }
    fn max_timeout_ms(&self) -> u64 {
        // Up to two small GETs (.well-known, then the root fallback).
        8_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // T1594 Search Victim-Owned Websites — security.txt is a file on the
        // victim's OWN site. T1589.002 Email Addresses — it harvests published
        // contact email addresses. Superset of the Web default ["T1594", ...].
        &["T1594", "T1589.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Email, EntityKind::Phone, EntityKind::Url];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let host = match target.kind {
            TargetKind::Url => crate::util::url_util::host_only(&target.value).to_lowercase(),
            _ => target.value.trim().to_lowercase(),
        };
        if host.is_empty() {
            return Ok(ModuleResult::new());
        }

        // RFC 9116 §3: the canonical location is `/.well-known/security.txt`; the
        // bare-root path is the pre-standard legacy location, tried second.
        let candidates = [
            format!("https://{host}/.well-known/security.txt"),
            format!("https://{host}/security.txt"),
        ];

        for url in &candidates {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let Ok(resp) = ctx.http.get(url).send_tagged(SRC).await else {
                continue;
            };
            if !resp.status().is_success() {
                continue;
            }
            let Some(body) = read_body_capped(resp, BODY_CAP).await else {
                continue;
            };
            // Many sites answer a missing file with a 200 HTML error page; require
            // a real `Contact:` field (the one mandatory RFC 9116 field) before
            // trusting the body, so an HTML 200 never mints bogus entities.
            if !looks_like_security_txt(&body) {
                continue;
            }
            let entities = parse_security_txt(&body, url, &ctx.scan_id);
            if !entities.is_empty() {
                let mut result = ModuleResult::with_capacity(entities.len());
                result.extend(entities);
                return Ok(result);
            }
        }

        Ok(ModuleResult::new())
    }
}

/// True when `body` carries at least one `Contact:` field — the single mandatory
/// RFC 9116 field. Guards against a 200-OK HTML "not found" page masquerading as
/// a security.txt.
fn looks_like_security_txt(body: &str) -> bool {
    body.lines().any(|line| {
        // `get(..8)` is byte-boundary-safe: `None` for a short line or a slice
        // that would split a multibyte char, so a UTF-8 line never panics here.
        line.trim_start()
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("contact:"))
    })
}

/// Map a security.txt file body to its published-contact entities. **Pure** (no
/// network/IO). Parses RFC 9116 `Field: value` lines (case-insensitive field
/// names; `#` comments and blank lines skipped), de-duplicates, and emits:
///
/// * `Contact:` → an `Email` (`mailto:` or a bare address), `Phone` (`tel:`), or
///   `Url` (a web contact form) — the highest-value fields.
/// * `Encryption:` → a `Url` tagged `pgp` (the PGP key location).
/// * `Canonical` / `Policy` / `Acknowledgments` / `Hiring` → a `Url`.
fn parse_security_txt(body: &str, source_url: &str, scan_id: &str) -> Vec<Entity> {
    let mut out: Vec<Entity> = Vec::new();
    let mut seen: HashSet<(u8, String)> = HashSet::new();

    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let field = field.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match field.as_str() {
            "contact" => push_contact(&mut out, &mut seen, value, source_url, scan_id),
            "encryption" => {
                push_url(
                    &mut out,
                    &mut seen,
                    value,
                    "encryption",
                    source_url,
                    scan_id,
                    true,
                );
            }
            "canonical" | "policy" | "acknowledgments" | "acknowledgements" | "hiring" => {
                push_url(
                    &mut out, &mut seen, value, &field, source_url, scan_id, false,
                );
            }
            _ => {}
        }
    }
    out
}

/// Emit the entity for one `Contact:` value — `mailto:` / bare address → `Email`,
/// `tel:` → `Phone`, an `http(s)` URL → `Url`.
fn push_contact(
    out: &mut Vec<Entity>,
    seen: &mut HashSet<(u8, String)>,
    value: &str,
    source_url: &str,
    scan_id: &str,
) {
    if let Some(mail) = value.strip_prefix("mailto:").or_else(|| {
        // A bare `Contact: name@example.com` (no scheme) is common though not
        // strictly conformant; accept it when it is unambiguously an address.
        (value.contains('@') && !value.contains(' ') && !value.contains('/')).then_some(value)
    }) {
        let mail = mail.trim();
        if mail.contains('@') && seen.insert((0, mail.to_ascii_lowercase())) {
            let mut e = Entity::new(EntityKind::Email, mail, confidence::HIGH_PLUS, scan_id);
            tag_contact(&mut e);
            e.add_evidence(contact_evidence("email", mail, source_url));
            out.push(e);
        }
    } else if let Some(tel) = value.strip_prefix("tel:") {
        let tel = tel.trim();
        if !tel.is_empty() && seen.insert((1, tel.to_string())) {
            let mut e = Entity::new(EntityKind::Phone, tel, confidence::HIGH, scan_id);
            tag_contact(&mut e);
            e.add_evidence(contact_evidence("phone", tel, source_url));
            out.push(e);
        }
    } else if is_http_url(value) && seen.insert((2, value.to_string())) {
        let mut e = Entity::new(EntityKind::Url, value, confidence::MEDIUM_HIGH, scan_id);
        tag_contact(&mut e);
        e.add_evidence(contact_evidence("web", value, source_url));
        out.push(e);
    }
}

/// Emit a `Url` entity for a URL-valued field (`Encryption`, `Canonical`, …).
fn push_url(
    out: &mut Vec<Entity>,
    seen: &mut HashSet<(u8, String)>,
    value: &str,
    field: &str,
    source_url: &str,
    scan_id: &str,
    is_pgp: bool,
) {
    // Encryption may also point at a PGP key by `openpgp4fpr:` or a bare address;
    // only a real web URL becomes a Url entity (fingerprints carry no location).
    if !is_http_url(value) || !seen.insert((2, value.to_string())) {
        return;
    }
    let mut e = Entity::new(EntityKind::Url, value, confidence::MEDIUM_HIGH, scan_id);
    e.tag("security-txt");
    e.tag(crate::core::tags::SEARCH_DISCOVERED);
    if is_pgp {
        e.tag("pgp");
    }
    e.add_evidence(
        Evidence::new(
            SRC,
            format!("security.txt `{field}` URL published at {source_url}"),
        )
        .with_attr("field", field)
        .with_attr("source", source_url),
    );
    out.push(e);
}

fn tag_contact(e: &mut Entity) {
    e.tag("security-txt");
    e.tag("security-contact");
    e.tag(crate::core::tags::SEARCH_DISCOVERED);
}

fn contact_evidence(kind: &str, value: &str, source_url: &str) -> Evidence {
    Evidence::new(
        SRC,
        format!("Published security {kind} contact `{value}` (RFC 9116 security.txt)"),
    )
    .with_attr("field", "contact")
    .with_attr("contact_type", kind)
    .with_attr("source", source_url)
}

/// True for an `http://` or `https://` URL (ASCII, case-insensitive scheme).
fn is_http_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://")
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
