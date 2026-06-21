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
use crate::util::http::RequestBuilderExt;
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

/// Shared evidence for a CT-log entity (a SAN `Email` or a discovered `Domain`):
/// the issuing CA, the validity window (`not_before`/`not_after`), and — recovered
/// here — the certificate **serial**, an infrastructure-attribution pivot (the
/// same serial seen across hosts links their certificates / operator). Issuer and
/// validity are always stamped (empty when absent, preserving the prior shape);
/// the serial is added only when present. **Pure.**
fn cert_evidence(entry: &CrtEntry, summary: &str) -> Evidence {
    let mut ev = Evidence::new(SRC, summary.to_string())
        .with_attr("issuer", entry.issuer_name.as_deref().unwrap_or(""))
        .with_attr("not_before", entry.not_before.as_deref().unwrap_or(""))
        .with_attr("not_after", entry.not_after.as_deref().unwrap_or(""));
    if let Some(serial) = entry.serial_number.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("cert_serial", serial);
    }
    ev
}

/// Map crt.sh certificate entries to deduplicated Domain/Email entities.
/// **Pure** (no network/IO): splits each cert's SAN list + common name, skips
/// wildcards, classifies a name as a subdomain of `domain_base` (case-folded) for
/// a confidence boost, dedups across the whole response, then returns the
/// highest-confidence [`MAX_ENTITIES`].
fn build_entities(entries: &[CrtEntry], domain_base: &str, scan_id: &str) -> Vec<Entity> {
    let base = domain_base.trim().to_lowercase();
    // Pre-compute the `.base` subdomain suffix once instead of re-formatting it
    // for every name across every certificate.
    let dot_base = format!(".{base}");
    let mut seen_domains: HashSet<String> = HashSet::new();
    let mut seen_emails: HashSet<String> = HashSet::new();

    let mut out: Vec<Entity> = entries
        .iter()
        .flat_map(|entry| {
            entry
                .name_value
                .as_deref()
                .unwrap_or("")
                .split('\n')
                .chain(entry.common_name.as_deref())
                .map(move |raw_name| (entry, raw_name))
        })
        .filter_map(|(entry, raw_name)| {
            let name = raw_name.trim().to_lowercase();
            if name.is_empty() || name.starts_with('*') {
                return None;
            }
            if name.contains('@') {
                if name.len() < MIN_EMAIL_LEN || !seen_emails.insert(name.clone()) {
                    return None;
                }
                let mut e = Entity::new(EntityKind::Email, &name, 0.70, scan_id);
                e.tag(tags::CT_LOG);
                e.add_evidence(cert_evidence(entry, "Email in certificate SAN"));
                Some(e)
            } else if name.contains('.') && seen_domains.insert(name.clone()) {
                let is_sub = name == base || name.ends_with(&dot_base);
                let conf = if is_sub { 0.75 } else { 0.45 };
                let mut e = Entity::new(EntityKind::Domain, &name, conf, scan_id);
                e.tag(tags::CT_LOG);
                if is_sub {
                    e.tag(tags::SUBDOMAIN);
                }
                e.add_evidence(cert_evidence(entry, "Certificate Transparency log"));
                Some(e)
            } else {
                None
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out.truncate(MAX_ENTITIES);
    out
}

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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Certificate Transparency — ATT&CK Digital Certificates (T1596.003).
        &["T1596.003"]
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
        // Live scan: 62 transport errors (connection refused/TLS) from DC IPs —
        // these fail fast (<1 s). 8 s is enough for a healthy JSON response
        // and cuts the concurrency-slot ceiling by 7 s vs the old 15 s.
        8_000
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
            .send_tagged(SRC)
            .await?;

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
    include!("tests.rs");
}
