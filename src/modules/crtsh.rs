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
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::urlencode;

const SRC: &str = "crtsh";

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
        matches!(t.kind, TargetKind::Domain | TargetKind::Email | TargetKind::Url)
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

        let url = format!(
            "https://crt.sh/?q={}&output=json",
            urlencode(&query)
        );

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
        let mut seen_domains: HashSet<String> = HashSet::new();
        let mut seen_emails: HashSet<String> = HashSet::new();
        let domain_base = target.value.trim().to_lowercase();

        for entry in &entries {
            if ctx.cancel.is_cancelled() {
                break;
            }

            let names = entry
                .name_value
                .as_deref()
                .unwrap_or("")
                .split('\n')
                .chain(entry.common_name.as_deref().into_iter());

            for raw_name in names {
                let name = raw_name.trim().to_lowercase();
                if name.is_empty() || name.starts_with('*') {
                    continue;
                }

                if name.contains('@') {
                    if seen_emails.insert(name.clone()) && name.len() >= 5 {
                        let mut e =
                            Entity::new(EntityKind::Email, &name, 0.70, &ctx.scan_id);
                        e.tag(tags::CT_LOG);
                        e.add_evidence(
                            Evidence::new(
                                SRC,
                                format!("Email in certificate SAN"),
                            )
                            .with_attr("issuer", entry.issuer_name.as_deref().unwrap_or(""))
                            .with_attr(
                                "not_before",
                                entry.not_before.as_deref().unwrap_or(""),
                            ),
                        );
                        result.push(e);
                    }
                } else if name.contains('.') && seen_domains.insert(name.clone()) {
                    let is_sub = name.ends_with(&format!(".{domain_base}"))
                        || name == domain_base;
                    let conf = if is_sub { 0.75 } else { 0.45 };
                    let mut e =
                        Entity::new(EntityKind::Domain, &name, conf, &ctx.scan_id);
                    e.tag(tags::CT_LOG);
                    if is_sub {
                        e.tag(tags::SUBDOMAIN);
                    }
                    e.add_evidence(
                        Evidence::new(SRC, format!("Certificate Transparency log"))
                            .with_attr(
                                "issuer",
                                entry.issuer_name.as_deref().unwrap_or(""),
                            )
                            .with_attr(
                                "not_before",
                                entry.not_before.as_deref().unwrap_or(""),
                            )
                            .with_attr(
                                "not_after",
                                entry.not_after.as_deref().unwrap_or(""),
                            ),
                    );
                    result.push(e);
                }
            }
        }

        result
            .entities
            .sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        if result.entities.len() > 200 {
            result.entities.truncate(200);
        }

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
        assert!(matches!(CrtSh.cost(), crate::core::module::ModuleCost::Free));
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
        assert!(entries[0].name_value.as_deref().unwrap().contains("example.com"));
    }
}
