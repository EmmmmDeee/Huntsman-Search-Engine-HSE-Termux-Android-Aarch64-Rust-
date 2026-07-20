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
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::urlencode;

const SRC: &str = "crtsh";

/// Shortest SAN email we'll surface (`a@b.c` is 5 chars).
const MIN_EMAIL_LEN: usize = 5;

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

/// Well-known public CAs whose organisation names add no OSINT signal.
/// Any issuer `O=` value that is a case-insensitive prefix/equal match against
/// one of these is suppressed from the Organisation entity list.
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

/// Extract the `O=` value from an X.509 Distinguished Name string such as
/// `"C=US, O=Let's Encrypt, CN=E5"`.  Returns `None` when no O= field is
/// present or the value is empty. `pub(crate)` so the sibling `certspotter`
/// Certificate-Transparency module reuses the identical issuer-org parsing
/// rather than re-deriving it.
pub(crate) fn parse_dn_org(dn: &str) -> Option<&str> {
    for segment in dn.split(',') {
        let seg = segment.trim();
        if let Some(rest) = seg.strip_prefix("O=") {
            let org = rest.trim();
            if !org.is_empty() {
                return Some(org);
            }
        }
    }
    None
}

/// True when `org` is a well-known public CA whose name adds no OSINT signal.
/// `pub(crate)` so `certspotter` shares the identical suppression list.
pub(crate) fn is_public_ca(org: &str) -> bool {
    let lower = org.to_lowercase();
    PUBLIC_CA_ORG_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Map crt.sh certificate entries to deduplicated Domain/Email/Organisation
/// entities.  **Pure** (no network/IO): splits each cert's SAN list + common
/// name, skips wildcards, classifies a name as a subdomain of `domain_base`
/// (case-folded) for a confidence boost, dedups across the whole response, then
/// returns EVERY distinct entity, confidence-descending (uid-tie-broken). No
/// per-module cap: each subdomain/email/org is a real BFS pivot and the frontier
/// budget is the engine's, not this leaf module's.
///
/// Organisation entities are emitted for non-public issuing CAs only — these
/// signal enterprise or custom PKI infrastructure and are a high-value
/// attribution pivot.
fn build_entities(entries: &[CrtEntry], domain_base: &str, scan_id: &str) -> Vec<Entity> {
    let base = domain_base.trim().to_lowercase();
    let mut seen_domains: HashSet<String> = HashSet::new();
    let mut seen_emails: HashSet<String> = HashSet::new();
    let mut seen_issuers: HashSet<String> = HashSet::new();

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
            if crate::util::extract::looks_like_email(&name) {
                if name.len() < MIN_EMAIL_LEN || !seen_emails.insert(name.clone()) {
                    return None;
                }
                let mut e = Entity::new(EntityKind::Email, &name, 0.70, scan_id);
                e.tag(tags::CT_LOG);
                e.add_evidence(cert_evidence(entry, "Email in certificate SAN"));
                Some(e)
            } else if name.contains('.') && seen_domains.insert(name.clone()) {
                let is_sub = crate::util::domains::is_or_subdomain_of(&name, &base);
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

    // Non-public issuing CA organisations — emitted once per unique O= value.
    // A custom or enterprise CA in the CT log reveals internal PKI and is a
    // strong attribution pivot: all domains signed by the same private CA
    // share an operator.
    out.extend(entries.iter().filter_map(|entry| {
        let dn = entry.issuer_name.as_deref()?;
        let org = parse_dn_org(dn)?;
        if is_public_ca(org) {
            return None;
        }
        let key = org.to_lowercase();
        if !seen_issuers.insert(key) {
            return None;
        }
        let mut o = Entity::new(EntityKind::Organisation, org, 0.55, scan_id);
        o.tag(tags::CT_LOG);
        o.tag("certificate-issuer");
        o.tag("derived");
        o.add_evidence(
            cert_evidence(entry, &format!("Certificate issuer organisation: {org}"))
                .with_attr("issuer_dn", dn)
                .with_attr("signed_domain", domain_base),
        );
        Some(o)
    }));

    // Confidence-descending, uid-ascending as a total, deterministic tie-break.
    // NO truncation: every discovered subdomain / SAN email / enterprise-CA org is
    // a real BFS expansion pivot, and the frontier budget is owned by the engine
    // (max depth / frontier cap), not this leaf module — the same reasoning the
    // netlas cert path documents. A prior `.take(10)` on issuers and a
    // `truncate(200)` here silently dropped genuine pivots (subdomains a popular
    // apex's CT history exposes, custom-PKI attribution orgs) with the total count
    // surfaced nowhere. Ordering via the shared host-recon helper.
    crate::util::recon::sort_by_confidence_desc(&mut out);
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
        // `Organisation` is the non-public issuing CA mined from the certificate
        // (build_entities); it was emitted but undeclared, hiding a corporate
        // pivot edge from the producer graph.
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

        // Route through the shared `fetch_json`: crt.sh always answers 200 with a
        // JSON array, matching fetch_json's error-on-non-2xx contract. On a reqwest
        // transport failure, `fetch_json_inner` automatically retries via the
        // system curl binary using the OS OpenSSL/CA store rather than rustls's
        // bundled webpki-roots — recovering the exact TLS/connect failure class the
        // module's telemetry documents on Termux/DC IPs, plus gaining the shared
        // circuit breaker. crtsh was the one keyless subdomain source excluded from
        // this Termux-friendly escape hatch every other fetch_json module has.
        let entries: Vec<CrtEntry> = crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;

        let mut result = ModuleResult::new();
        result.entities = build_entities(&entries, &target.value, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
