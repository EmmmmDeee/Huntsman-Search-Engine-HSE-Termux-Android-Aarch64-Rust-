//! Cert Spotter — free Certificate Transparency issuance search (SSLMate).
//!
//! Endpoint:
//!   `GET https://api.certspotter.com/v1/issuances
//!        ?domain={host}&include_subdomains=true&expand=dns_names&expand=issuer`
//! Auth: None — the anonymous tier is free and key-less (rate-limited; a 429
//! simply surfaces as a module error and the engine moves on, exactly like any
//! other transient free-source failure).
//!
//! This is the deliberate COMPANION to [`crate::modules::crtsh`], not a
//! duplicate: no single Certificate-Transparency aggregator has complete log
//! coverage, so offensive subdomain enumeration standardly queries several
//! (subfinder / amass / assetfinder all do). crt.sh reads its own monitored-log
//! database; Cert Spotter runs an independent monitor with different freshness
//! and back-fill, so each routinely surfaces hostnames the other misses — running
//! both maximises the attack-surface recall from one apex seed. The issuer-org
//! parsing and public-CA suppression are shared with `crtsh` (single source of
//! truth) rather than re-encoded here.

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
use crate::modules::crtsh::{is_public_ca, parse_dn_org};
use crate::util::http::urlencode;

const SRC: &str = "certspotter";

/// One issuance object from the `v1/issuances` array, expanded with `dns_names`
/// and `issuer`. Every field is optional so a partial/renamed response degrades
/// to fewer entities rather than a hard deserialize error.
#[derive(Deserialize)]
struct Issuance {
    #[serde(default)]
    dns_names: Vec<String>,
    #[serde(default)]
    issuer: Option<Issuer>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    /// The certificate's SHA-256 — an infrastructure-attribution pivot: the same
    /// cert fingerprint seen across hosts links their certificates / operator
    /// (the Cert Spotter analogue of crt.sh's `serial_number`).
    #[serde(default)]
    cert_sha256: Option<String>,
}

#[derive(Deserialize)]
struct Issuer {
    /// The issuer Distinguished Name, e.g. `"C=US, O=Let's Encrypt, CN=R3"`.
    #[serde(default)]
    name: Option<String>,
}

/// Shared evidence for a CT issuance-derived entity: the issuing CA DN, the
/// validity window, and — when present — the certificate SHA-256 fingerprint
/// pivot. **Pure.**
fn cert_evidence(entry: &Issuance, summary: &str) -> Evidence {
    let issuer = entry
        .issuer
        .as_ref()
        .and_then(|i| i.name.as_deref())
        .unwrap_or("");
    let mut ev = Evidence::new(SRC, summary.to_string())
        .with_attr("issuer", issuer)
        .with_attr("not_before", entry.not_before.as_deref().unwrap_or(""))
        .with_attr("not_after", entry.not_after.as_deref().unwrap_or(""));
    if let Some(fp) = entry.cert_sha256.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("cert_sha256", fp);
    }
    ev
}

/// Map Cert Spotter issuances to deduplicated `Domain` / `Organisation`
/// entities. **Pure** (no network/IO): flattens each issuance's `dns_names`,
/// skips wildcards, classifies a name as a subdomain of `domain_base`
/// (case-folded) for a confidence boost, dedups across the whole response, and
/// mines the non-public issuing CA as a high-value attribution pivot. Returns
/// EVERY distinct entity, confidence-descending (uid-tie-broken) — no per-module
/// cap, because each subdomain / enterprise-CA org is a real BFS pivot and the
/// frontier budget is the engine's, not this leaf module's (mirrors `crtsh`).
fn build_entities(entries: &[Issuance], domain_base: &str, scan_id: &str) -> Vec<Entity> {
    let base = domain_base.trim().trim_end_matches('.').to_lowercase();
    let mut seen_domains: HashSet<String> = HashSet::new();
    let mut seen_issuers: HashSet<String> = HashSet::new();

    let mut out: Vec<Entity> = entries
        .iter()
        .flat_map(|entry| entry.dns_names.iter().map(move |name| (entry, name)))
        .filter_map(|(entry, raw_name)| {
            let name = raw_name.trim().trim_end_matches('.').to_lowercase();
            // Skip blanks, wildcards (`*.example.com` — not a resolvable host),
            // and anything that isn't a dotted hostname.
            if name.is_empty() || name.starts_with('*') || !name.contains('.') {
                return None;
            }
            if !seen_domains.insert(name.clone()) {
                return None;
            }
            let is_sub = crate::util::domains::is_or_subdomain_of(&name, &base);
            let conf = if is_sub { 0.75 } else { 0.45 };
            let mut e = Entity::new(EntityKind::Domain, &name, conf, scan_id);
            e.tag(tags::CT_LOG);
            if is_sub {
                e.tag(tags::SUBDOMAIN);
            }
            e.add_evidence(cert_evidence(
                entry,
                "Certificate Transparency issuance (Cert Spotter)",
            ));
            Some(e)
        })
        .collect();

    // Non-public issuing-CA organisations — one per unique O= value. A custom /
    // enterprise CA in the CT log reveals internal PKI and is a strong operator
    // attribution pivot (identical policy to `crtsh`, via the shared helpers).
    out.extend(entries.iter().filter_map(|entry| {
        let dn = entry.issuer.as_ref()?.name.as_deref()?;
        let org = parse_dn_org(dn)?;
        if is_public_ca(org) {
            return None;
        }
        if !seen_issuers.insert(org.to_lowercase()) {
            return None;
        }
        let mut o = Entity::new(EntityKind::Organisation, org, 0.55, scan_id);
        o.tag(tags::CT_LOG);
        o.tag("certificate-issuer");
        o.tag("derived");
        o.add_evidence(
            cert_evidence(entry, &format!("Certificate issuer organisation: {org}"))
                .with_attr("issuer_dn", dn)
                .with_attr("signed_domain", &base),
        );
        Some(o)
    }));

    // Deterministic confidence-descending emission order (shared with the other
    // host-recon collectors). No truncation.
    crate::util::recon::sort_by_confidence_desc(&mut out);
    out
}

pub struct CertSpotter;

#[async_trait]
impl Module for CertSpotter {
    fn name(&self) -> &'static str {
        "certspotter"
    }

    fn description(&self) -> &'static str {
        "Certificate Transparency issuance search via Cert Spotter (free, no key)"
    }

    fn priority(&self) -> u8 {
        // One below `crtsh` (29): the two CT sources run back-to-back, and the
        // engine's per-target dedup means whichever surfaces a subdomain first
        // wins — order is immaterial to the union, but a stable priority keeps
        // dispatch deterministic.
        28
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Search Open Technical Databases: Digital Certificates (T1596.003).
        &["T1596.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::Organisation];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Cert Spotter's issuance query over a busy apex can be slower than
        // crt.sh; 10 s leaves headroom for a healthy JSON response while still
        // failing a dead/rate-limited endpoint well within a scan round.
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(host) = crate::util::recon::host_key(target.kind, &target.value) else {
            return Ok(ModuleResult::new());
        };

        // `include_subdomains=true` widens the query from the apex to every
        // sub-name; the two `expand` params inline the dns_names + issuer so a
        // single request yields full detail (unexpanded, they are bare refs).
        let url = format!(
            "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names&expand=issuer",
            urlencode(&host)
        );

        // Shared `fetch_json`: Cert Spotter answers 200 with a JSON array, matching
        // fetch_json's error-on-non-2xx contract, and inherits the curl/OpenSSL
        // fallback + circuit breaker every keyless source uses on Termux/DC IPs.
        let entries: Vec<Issuance> = crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;

        let mut result = ModuleResult::new();
        result.entities = build_entities(&entries, &host, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
