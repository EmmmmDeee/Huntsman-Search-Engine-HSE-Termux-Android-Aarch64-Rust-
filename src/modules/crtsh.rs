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

/// Shortest SAN email we'll surface (`a@b.c` is 5 chars).
const MIN_EMAIL_LEN: usize = 5;
/// Cap on entities returned from one CT search — a popular apex can have tens of
/// thousands of certs; the highest-confidence 200 are plenty to pivot on.
const MAX_ENTITIES: usize = 200;

/// Build the crt.sh query for a target, or `None` for a kind/URL we can't key on.
/// **Pure**: a `Domain` becomes a `%.domain` wildcard subdomain search, an
/// `Email` is searched verbatim, and a `Url` is reduced to its host first.
fn build_query(kind: TargetKind, value: &str) -> Option<String> {
    match kind {
        TargetKind::Domain => Some(format!("%.{}", value.trim())),
        TargetKind::Email => Some(value.trim().to_string()),
        TargetKind::Url => crate::util::url_util::host_from_url(value).map(|h| format!("%.{h}")),
        _ => None,
    }
}

/// Map crt.sh certificate entries to deduplicated Domain/Email entities.
/// **Pure** (no network/IO): splits each cert's SAN list + common name, skips
/// wildcards, classifies a name as a subdomain of `domain_base` (case-folded) for
/// a confidence boost, dedups across the whole response, then returns the
/// highest-confidence [`MAX_ENTITIES`].
fn build_entities(entries: &[CrtEntry], domain_base: &str, scan_id: &str) -> Vec<Entity> {
    let base = domain_base.trim().to_lowercase();
    let mut out: Vec<Entity> = Vec::new();
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
                if name.len() >= MIN_EMAIL_LEN && seen_emails.insert(name.clone()) {
                    let mut e = Entity::new(EntityKind::Email, &name, 0.70, scan_id);
                    e.tag(tags::CT_LOG);
                    e.add_evidence(
                        Evidence::new(SRC, "Email in certificate SAN".to_string())
                            .with_attr("issuer", entry.issuer_name.as_deref().unwrap_or(""))
                            .with_attr("not_before", entry.not_before.as_deref().unwrap_or("")),
                    );
                    out.push(e);
                }
            } else if name.contains('.') && seen_domains.insert(name.clone()) {
                let is_sub = name == base || name.ends_with(&format!(".{base}"));
                let conf = if is_sub { 0.75 } else { 0.45 };
                let mut e = Entity::new(EntityKind::Domain, &name, conf, scan_id);
                e.tag(tags::CT_LOG);
                if is_sub {
                    e.tag(tags::SUBDOMAIN);
                }
                e.add_evidence(
                    Evidence::new(SRC, "Certificate Transparency log".to_string())
                        .with_attr("issuer", entry.issuer_name.as_deref().unwrap_or(""))
                        .with_attr("not_before", entry.not_before.as_deref().unwrap_or(""))
                        .with_attr("not_after", entry.not_after.as_deref().unwrap_or("")),
                );
                out.push(e);
            }
        }
    }

    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out.truncate(MAX_ENTITIES);
    out
}

#[derive(Deserialize)]
#[allow(dead_code)]
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
        let Some(query) = build_query(target.kind, &target.value) else {
            return Ok(ModuleResult::new());
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

        let mut result = ModuleResult::new();
        result.entities = build_entities(&entries, &target.value, &ctx.scan_id);
        Ok(result)
    }
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

    #[test]
    fn build_query_shapes_each_kind() {
        assert_eq!(
            build_query(TargetKind::Domain, " example.com "),
            Some("%.example.com".into())
        );
        assert_eq!(
            build_query(TargetKind::Email, " a@b.com "),
            Some("a@b.com".into())
        );
        assert_eq!(
            build_query(TargetKind::Url, "https://sub.example.com/path"),
            Some("%.sub.example.com".into())
        );
        assert_eq!(build_query(TargetKind::Username, "u"), None);
    }

    fn entries(json: &str) -> Vec<CrtEntry> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn classifies_subdomains_dedups_and_skips_wildcards() {
        let e = entries(
            r#"[
              {"name_value":"api.example.com\n*.example.com\napi.example.com","common_name":"api.example.com","issuer_name":"Let's Encrypt","not_before":"2024-01-01","not_after":"2024-04-01"},
              {"name_value":"unrelated.org","common_name":"unrelated.org"}
            ]"#,
        );
        let out = build_entities(&e, "example.com", "s");
        let by_val = |v: &str| out.iter().find(|x| x.value == v).cloned();

        // api.example.com repeats across SANs + common_name → deduped to one.
        assert_eq!(
            out.iter().filter(|x| x.value == "api.example.com").count(),
            1
        );
        // Wildcard *.example.com skipped.
        assert!(by_val("*.example.com").is_none());

        // Subdomain → high confidence + subdomain tag.
        let api = by_val("api.example.com").unwrap();
        assert!((api.confidence - 0.75).abs() < 1e-9);
        assert!(api.has_tag(tags::CT_LOG) && api.has_tag(tags::SUBDOMAIN));
        assert_eq!(
            api.evidence[0].attributes.get("issuer").map(String::as_str),
            Some("Let's Encrypt")
        );

        // Unrelated domain → lower confidence, no subdomain tag.
        let other = by_val("unrelated.org").unwrap();
        assert!((other.confidence - 0.45).abs() < 1e-9);
        assert!(!other.has_tag(tags::SUBDOMAIN));
    }

    #[test]
    fn subdomain_match_is_case_insensitive_against_base() {
        // Mixed-case target base must still classify the SAN as a subdomain.
        let e = entries(r#"[{"name_value":"api.example.com"}]"#);
        let out = build_entities(&e, "Example.COM", "s");
        let api = out.iter().find(|x| x.value == "api.example.com").unwrap();
        assert!((api.confidence - 0.75).abs() < 1e-9);
        assert!(api.has_tag(tags::SUBDOMAIN));
    }

    #[test]
    fn surfaces_san_emails_above_min_length() {
        let e = entries(
            r#"[{"name_value":"admin@example.com\na@b","issuer_name":"CA","not_before":"2024-01-01"}]"#,
        );
        let out = build_entities(&e, "example.com", "s");
        let email = out.iter().find(|x| x.kind == EntityKind::Email);
        let email = email.unwrap();
        assert_eq!(email.value, "admin@example.com");
        assert!((email.confidence - 0.70).abs() < 1e-9);
        assert!(email.has_tag(tags::CT_LOG));
        // "a@b" is below MIN_EMAIL_LEN → not surfaced.
        assert!(!out.iter().any(|x| x.value == "a@b"));
    }

    #[test]
    fn results_are_capped_highest_confidence_first() {
        // Build > MAX_ENTITIES distinct unrelated domains (conf 0.45) plus one
        // subdomain (0.75); the cap must keep the subdomain (sorted first).
        let mut sans: Vec<String> = (0..MAX_ENTITIES + 50)
            .map(|i| format!("host{i}.other-{i}.net"))
            .collect();
        sans.push("keep.example.com".to_string());
        let json = format!(r#"[{{"name_value":"{}"}}]"#, sans.join("\\n"));
        let out = build_entities(&entries(&json), "example.com", "s");
        assert_eq!(out.len(), MAX_ENTITIES);
        assert_eq!(out[0].value, "keep.example.com"); // highest confidence first
        assert!(out.windows(2).all(|w| w[0].confidence >= w[1].confidence));
    }
}
