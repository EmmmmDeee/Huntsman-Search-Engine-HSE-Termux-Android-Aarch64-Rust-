//! `security.txt` harvester (RFC 9116) — published-contact OSINT.
//!
//! Endpoints: `GET https://{domain}/.well-known/security.txt` (canonical
//! location), falling back to `/security.txt`.
//!
//! Organisations that publish a `security.txt` hand you a curated list of their
//! security-team **contacts** (emails / phones / forms), **PGP keys**, and
//! policy / hiring / disclosure URLs — published, authoritative identity and
//! infrastructure leads. The harvested contact emails become fresh Email
//! targets, expanding the footprint into the people behind the domain. (The
//! crawler only *probes* this path for config leaks; nothing parsed its fields
//! into entities until now.)
//!
//! Defensive: the file is read streamed-and-capped, and every line is treated
//! as untrusted `Field: value` input.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "security_txt";

/// `security.txt` is meant to be small; cap defensively against a hostile host.
const MAX_BODY: usize = 64 * 1024;

/// Parse RFC 9116 `Field: value` lines — case-insensitive field, `#` comments
/// and blanks skipped, split on the first colon so `mailto:` URIs survive.
fn parse_fields(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter_map(|line| {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let (k, v) = l.split_once(':')?;
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            if k.is_empty() || v.is_empty() {
                return None;
            }
            Some((k, v.to_string()))
        })
        .collect()
}

fn url_entity(url: &str, tag: &str, domain: &str, scan_id: &str, conf: f64) -> Entity {
    let mut e = Entity::new(EntityKind::Url, url, conf, scan_id);
    e.tag("security-txt");
    e.tag(tag);
    e.add_evidence(
        Evidence::new(SRC, format!("security.txt {tag} for {domain}"))
            .with_attr("source_domain", domain),
    );
    e
}

fn contact_email(addr: &str, domain: &str, scan_id: &str, conf: f64) -> Entity {
    let mut e = Entity::new(EntityKind::Email, addr, conf, scan_id);
    e.tag("security-contact");
    e.tag("security-txt");
    e.add_evidence(
        Evidence::new(SRC, format!("security.txt contact for {domain}"))
            .with_attr("source_domain", domain),
    );
    e
}

/// Extract entities from a `security.txt` body. Pure — unit-tested offline.
fn entities_from_security_txt(body: &str, domain: &str, scan_id: &str) -> Vec<Entity> {
    let fields = parse_fields(body);
    let mut out = Vec::new();
    let mut contacts = 0u32;

    for (field, value) in &fields {
        match field.as_str() {
            "contact" => {
                if let Some(mail) = value.strip_prefix("mailto:").map(str::trim) {
                    if mail.contains('@') {
                        out.push(contact_email(mail, domain, scan_id, 0.78));
                        contacts += 1;
                    }
                } else if let Some(tel) = value.strip_prefix("tel:").map(str::trim) {
                    let mut e = Entity::new(EntityKind::Phone, tel, 0.68, scan_id);
                    e.tag("security-contact");
                    e.tag("security-txt");
                    e.add_evidence(
                        Evidence::new(SRC, format!("security.txt phone contact for {domain}"))
                            .with_attr("source_domain", domain),
                    );
                    out.push(e);
                    contacts += 1;
                } else if value.starts_with("http") {
                    out.push(url_entity(value, "security-contact", domain, scan_id, 0.62));
                    contacts += 1;
                } else if value.contains('@') {
                    out.push(contact_email(value, domain, scan_id, 0.72));
                    contacts += 1;
                }
            }
            "encryption" if value.starts_with("http") => {
                out.push(url_entity(value, "pgp-key", domain, scan_id, 0.58));
            }
            "policy" | "acknowledgments" | "acknowledgements" | "hiring" | "canonical" | "csaf"
                if value.starts_with("http") =>
            {
                out.push(url_entity(
                    value,
                    &format!("security-{field}"),
                    domain,
                    scan_id,
                    0.55,
                ));
            }
            _ => {}
        }
    }

    // Only anchor (and thus claim "publishes security.txt") if it actually
    // parsed as one — a stray 200 of unrelated text yields nothing.
    if out.is_empty() {
        return out;
    }
    let mut anchor = Entity::new(EntityKind::Domain, domain, 0.70, scan_id);
    anchor.tag("publishes-security-txt");
    anchor.add_evidence(
        Evidence::new(
            SRC,
            format!("Publishes a security.txt ({contacts} contact(s))"),
        )
        .with_attr("source_domain", domain)
        .with_attr("contacts", contacts.to_string()),
    );
    out.push(anchor);
    out
}

pub struct SecurityTxt;

#[async_trait]
impl Module for SecurityTxt {
    fn name(&self) -> &'static str {
        "security_txt"
    }

    fn description(&self) -> &'static str {
        "Harvest RFC 9116 security.txt — published security contacts, PGP keys, and policy URLs"
    }

    fn priority(&self) -> u8 {
        96
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Url,
            EntityKind::Domain,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = match target.kind {
            TargetKind::Url => {
                crate::util::url_util::host_from_url(&target.value).unwrap_or_default()
            }
            TargetKind::Domain => target.value.trim().to_lowercase(),
            _ => return Ok(ModuleResult::new()),
        };
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        // Canonical location first, then the legacy root path.
        let mut body = crate::util::http::fetch_text_capped(
            &ctx.http,
            &format!("https://{domain}/.well-known/security.txt"),
            MAX_BODY,
        )
        .await;
        if body.is_none() {
            body = crate::util::http::fetch_text_capped(
                &ctx.http,
                &format!("https://{domain}/security.txt"),
                MAX_BODY,
            )
            .await;
        }
        let Some(body) = body else {
            return Ok(ModuleResult::new());
        };
        crate::util::http::scan_for_api_keys(&body);

        let mut result = ModuleResult::new();
        for e in entities_from_security_txt(&body, &domain, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# Our security policy
Contact: mailto:security@acme.example
Contact: tel:+1-201-555-0123
Contact: https://acme.example/report
Encryption: https://acme.example/pgp-key.txt
Policy: https://acme.example/security-policy
Hiring: https://acme.example/jobs
Acknowledgments: https://acme.example/thanks
Expires: 2030-01-01T00:00:00.000Z
Preferred-Languages: en, fr
";

    #[test]
    fn accepts_domain_and_url() {
        let m = SecurityTxt;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "acme.example")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://acme.example/")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn parses_rfc9116_fields_skipping_comments_and_blanks() {
        let fields = parse_fields(SAMPLE);
        // Comment + Expires + Preferred-Languages present; we only key off the
        // contact/url fields downstream, but parsing must retain them all.
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "contact" && v == "mailto:security@acme.example")
        );
        assert!(fields.iter().any(|(k, _)| k == "expires"));
        assert!(!fields.iter().any(|(_, v)| v.starts_with('#')));
    }

    #[test]
    fn extracts_contacts_keys_and_policy_urls() {
        let ents = entities_from_security_txt(SAMPLE, "acme.example", "s");
        let has = |k: EntityKind, needle: &str| {
            ents.iter().any(|e| e.kind == k && e.value.contains(needle))
        };
        assert!(has(EntityKind::Email, "security@acme.example"));
        // A Phone entity is emitted from the `tel:` contact (its value is
        // re-normalised, so don't assert the exact dashed form).
        assert!(ents.iter().any(|e| e.kind == EntityKind::Phone));
        assert!(has(EntityKind::Url, "acme.example/report"));
        assert!(has(EntityKind::Url, "pgp-key.txt"));
        assert!(has(EntityKind::Url, "security-policy"));
        // Domain anchor records that the org publishes a security.txt.
        assert!(ents.iter().any(|e| e.kind == EntityKind::Domain
            && e.value == "acme.example"
            && e.has_tag("publishes-security-txt")));

        let pgp = ents
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value.contains("pgp-key"))
            .unwrap();
        assert!(pgp.has_tag("pgp-key"));
    }

    #[test]
    fn unrelated_body_yields_no_entities() {
        // A 200 that isn't a security.txt (e.g. an HTML 404 page) must not be
        // mistaken for one.
        assert!(
            entities_from_security_txt("<html><body>Not found</body></html>", "x.com", "s")
                .is_empty()
        );
    }
}
