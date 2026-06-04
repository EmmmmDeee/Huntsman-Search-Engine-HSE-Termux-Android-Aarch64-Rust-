//! crt.sh — free Certificate Transparency log search.
//!
//! Endpoint: `GET https://crt.sh/?q={target}&output=json`
//! Auth: None — completely free, no API key required.
//!
//! Returns certificates issued for a domain, revealing subdomains,
//! email addresses in SANs, and issuer organizations. Invaluable for
//! subdomain discovery and certificate timeline analysis.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::urlencode;

const SRC: &str = "crtsh";

#[derive(Deserialize)]
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

pub struct CrtSh;

#[async_trait]
impl Module for CrtSh {
    fn name(&self) -> &'static str {
        "crtsh"
    }

    fn description(&self) -> &'static str {
        "Certificate Transparency log search via crt.sh (free, no key)"
    }

    fn priority(&self) -> u8 {
        29
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::Email | TargetKind::Url
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::Email,
            EntityKind::Organisation,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = match target.kind {
            TargetKind::Domain => format!("%.{}", target.value.trim()),
            TargetKind::Email => target.value.trim().to_string(),
            TargetKind::Url => match crate::util::url_util::host_from_url(&target.value) {
                Some(h) => format!("%.{h}"),
                None => return Ok(ModuleResult::new()),
            },
            _ => return Ok(ModuleResult::new()),
        };

        let url = format!("https://crt.sh/?q={}&output=json", urlencode(&query));

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(SRC, format!("HTTP {status}")));
        }

        let entries: Vec<CrtEntry> = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        if ctx.cancel.is_cancelled() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        for e in build_entities(&entries, &target.value, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

/// Trimmed, non-empty view of an optional string field.
fn nonempty(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// One evidence record for a certificate, carrying its issuer + validity window
/// and — recovered from the previously-discarded field — the `cert_serial`. A
/// serial shared across two domains means they are literally on the *same*
/// certificate, a strong same-operator link the old code dropped. **Pure**.
fn cert_evidence(summary: &str, entry: &CrtEntry) -> Evidence {
    let mut ev = Evidence::new(SRC, summary.to_string());
    if let Some(v) = nonempty(&entry.issuer_name) {
        ev = ev.with_attr("issuer", v);
    }
    if let Some(v) = nonempty(&entry.not_before) {
        ev = ev.with_attr("not_before", v);
    }
    if let Some(v) = nonempty(&entry.not_after) {
        ev = ev.with_attr("not_after", v);
    }
    if let Some(v) = nonempty(&entry.serial_number) {
        ev = ev.with_attr("cert_serial", v);
    }
    ev
}

/// Extract `Domain` (subdomain-classified) and SAN `Email` entities from a set
/// of Certificate Transparency entries. **Pure** (no IO) so the classification,
/// dedup, confidence-sort, and 200-cap are unit-tested. A name ending in
/// `.{domain_base}` (or equal to it) is a subdomain (0.75 + `subdomain` tag);
/// any other dotted name is a weaker related domain (0.45). Wildcards are skipped.
fn build_entities(entries: &[CrtEntry], domain_base: &str, scan_id: &str) -> Vec<Entity> {
    let mut result: Vec<Entity> = Vec::new();
    let mut seen_domains: HashSet<String> = HashSet::new();
    let mut seen_emails: HashSet<String> = HashSet::new();

    for entry in entries {
        let names = entry
            .name_value
            .as_deref()
            .unwrap_or("")
            .split('\n')
            .chain(entry.common_name.as_deref());

        for raw_name in names {
            let name = raw_name.trim().to_lowercase();
            if name.is_empty() || name.starts_with('*') {
                continue;
            }

            if name.contains('@') {
                if seen_emails.insert(name.clone()) && name.len() >= 5 {
                    let mut e = Entity::new(EntityKind::Email, &name, 0.70, scan_id);
                    e.tag(tags::CT_LOG);
                    e.add_evidence(cert_evidence("Email in certificate SAN", entry));
                    result.push(e);
                }
            } else if name.contains('.') && seen_domains.insert(name.clone()) {
                let is_sub = name.ends_with(&format!(".{domain_base}")) || name == domain_base;
                let conf = if is_sub { 0.75 } else { 0.45 };
                let mut e = Entity::new(EntityKind::Domain, &name, conf, scan_id);
                e.tag(tags::CT_LOG);
                if is_sub {
                    e.tag(tags::SUBDOMAIN);
                }
                e.add_evidence(cert_evidence("Certificate Transparency log", entry));
                result.push(e);
            }
        }
    }

    result.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    result.truncate(200);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_and_email() {
        let m = CrtSh;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::Email, "a@x.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "u")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            CrtSh.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn description_non_empty() {
        assert!(!CrtSh.description().is_empty());
    }

    #[test]
    fn crt_entry_deser() {
        let json = r#"[{"common_name":"www.example.com","name_value":"www.example.com\nexample.com","issuer_name":"Let's Encrypt","not_before":"2024-01-01","not_after":"2024-04-01","serial_number":"abc123"}]"#;
        let entries: Vec<CrtEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].common_name.as_deref(), Some("www.example.com"));
        assert!(
            entries[0]
                .name_value
                .as_deref()
                .unwrap()
                .contains("example.com")
        );
    }

    fn parse(json: &str) -> Vec<CrtEntry> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn build_classifies_subdomains_recovers_serial_and_issuer() {
        let entries = parse(
            r#"[{"common_name":"shop.acme.com",
                 "name_value":"shop.acme.com\nmail.acme.com\nother.net",
                 "issuer_name":"Let's Encrypt","not_before":"2024-01-01",
                 "not_after":"2024-04-01","serial_number":"DEADBEEF"}]"#,
        );
        let v = build_entities(&entries, "acme.com", "s");
        let sub = v.iter().find(|e| e.value == "mail.acme.com").unwrap();
        assert!(sub.has_tag(tags::SUBDOMAIN) && sub.has_tag(tags::CT_LOG));
        assert!((sub.confidence - 0.75).abs() < 1e-9);
        // A name outside the base domain is a weaker related domain, not a subdomain.
        let unrelated = v.iter().find(|e| e.value == "other.net").unwrap();
        assert!(!unrelated.has_tag(tags::SUBDOMAIN));
        assert!((unrelated.confidence - 0.45).abs() < 1e-9);
        // Recovered cert serial + issuer/validity surfaced on the evidence.
        let a = &sub.evidence[0].attributes;
        assert_eq!(a.get("cert_serial").map(String::as_str), Some("DEADBEEF"));
        assert_eq!(a.get("issuer").map(String::as_str), Some("Let's Encrypt"));
        assert_eq!(a.get("not_after").map(String::as_str), Some("2024-04-01"));
    }

    #[test]
    fn build_extracts_san_email() {
        let entries = parse(r#"[{"name_value":"admin@acme.com","serial_number":"AA11"}]"#);
        let v = build_entities(&entries, "acme.com", "s");
        let email = v.iter().find(|e| e.kind == EntityKind::Email).unwrap();
        assert_eq!(email.value, "admin@acme.com");
        assert!(email.has_tag(tags::CT_LOG));
        assert!((email.confidence - 0.70).abs() < 1e-9);
        assert_eq!(
            email.evidence[0]
                .attributes
                .get("cert_serial")
                .map(String::as_str),
            Some("AA11")
        );
    }

    #[test]
    fn build_skips_wildcards_dedups_and_sorts_by_confidence() {
        let entries = parse(
            r#"[{"name_value":"*.acme.com\nunrelated.net\nsub.acme.com"},
                {"name_value":"sub.acme.com"}]"#,
        );
        let v = build_entities(&entries, "acme.com", "s");
        let doms: Vec<&str> = v
            .iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .map(|e| e.value.as_str())
            .collect();
        assert!(!doms.iter().any(|d| d.starts_with('*')), "wildcard skipped");
        assert_eq!(
            doms.iter().filter(|d| **d == "sub.acme.com").count(),
            1,
            "name deduped across entries"
        );
        // Subdomain (0.75) sorts ahead of the unrelated domain (0.45).
        assert_eq!(v.first().unwrap().value, "sub.acme.com");
    }
}
