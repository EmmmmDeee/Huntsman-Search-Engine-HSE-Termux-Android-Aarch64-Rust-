//! SecurityTrails subdomain enumeration + reverse IP lookup. Key-gated; free tier 50 q/mo.
//!
//! Domain path: `GET https://api.securitytrails.com/v1/domain/{domain}/subdomains`
//! IP path:     `GET https://api.securitytrails.com/v1/ips/list?ipAddresses={ip}` (associated domains)
//! Auth:        `APIKEY` request header
//!
//! Both response→entity mappings are pure ([`build_subdomain_entity`],
//! [`build_associated_entity`]) so they are unit-tested without a live key.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const KEY_ENV: &str = "HUNTSMAN_SECTRAILS_KEY";
const SRC: &str = "securitytrails";

#[derive(Deserialize)]
struct SubdomainResp {
    #[serde(default)]
    subdomains: Vec<String>,
    #[serde(default)]
    subdomain_count: Option<u64>,
}

#[derive(Deserialize)]
struct AssociatedResp {
    #[serde(default)]
    records: Vec<AssociatedRecord>,
    /// SecurityTrails' reported total of domains associated with the IP. Often
    /// larger than `records.len()` (the API pages), so it is the honest measure
    /// of how shared the host is. `None` when the field is absent — fall back to
    /// the number of records actually returned, never a fabricated total.
    #[serde(default)]
    record_count: Option<u64>,
}

#[derive(Deserialize)]
struct AssociatedRecord {
    #[serde(default)]
    hostname: Option<String>,
}

/// Cap on associated-domain records turned into ENTITIES from one reverse-IP
/// lookup. Unlike a domain's own subdomains, reverse-IP neighbours on a shared
/// host / CDN are mostly unrelated co-tenants — not the subject's data — so
/// minting thousands of them as first-class pivots would flood expansion with
/// noise. The cap bounds only the entity fan-out; the FULL associated-domain
/// **count** is never hidden — it is surfaced on every emitted entity as the
/// `total_associated` evidence attribute (mirroring the subdomain path's
/// `total_subdomains`), so an analyst always sees how shared the host is even
/// when only the first records become entities.
const MAX_REVERSE_RECORDS: usize = 30;

/// Build the `Domain` entity for one enumerated subdomain label under `domain`.
/// **Pure** (no network/IO). `total_str` is the parent's reported subdomain
/// count, carried as evidence context. Returns `None` for a blank label.
fn build_subdomain_entity(
    domain: &str,
    sub: &str,
    total_str: &str,
    scan_id: &str,
) -> Option<Entity> {
    let sub = sub.trim();
    if sub.is_empty() {
        return None;
    }
    let host = format!("{sub}.{domain}");
    let mut e = Entity::new(EntityKind::Domain, &host, confidence::EXPERT, scan_id);
    e.tag("subdomain");
    e.tag("securitytrails");
    e.add_evidence(
        Evidence::new(SRC, format!("Subdomain of {domain} per SecurityTrails"))
            .with_attr("parent_domain", domain)
            .with_attr("total_subdomains", total_str),
    );
    Some(e)
}

/// Build the `Domain` entity for one reverse-IP associated record. **Pure** (no
/// network/IO): trims a trailing dot and rejects anything that is not a usable
/// hostname — blank, a bare IP literal (the PTR pointing back at the IP itself),
/// or a single label with no dot. Returns `None` for a rejected record.
/// `total_str` is the IP's full associated-domain count, carried as evidence so
/// the cap on entity fan-out never hides how shared the host is.
fn build_associated_entity(
    ip: &str,
    hostname: Option<&str>,
    total_str: &str,
    scan_id: &str,
) -> Option<Entity> {
    let hostname = hostname?.trim().trim_end_matches('.');
    if hostname.is_empty()
        || hostname.parse::<std::net::IpAddr>().is_ok()
        || !hostname.contains('.')
    {
        return None;
    }
    let mut e = Entity::new(
        EntityKind::Domain,
        hostname,
        confidence::CORROBORATED,
        scan_id,
    );
    e.tag("securitytrails");
    e.tag("reverse-ip");
    e.add_evidence(
        Evidence::new(
            SRC,
            format!("Domain associated with {ip} per SecurityTrails"),
        )
        .with_attr("ip", ip)
        .with_attr("total_associated", total_str),
    );
    Some(e)
}

/// Map a reverse-IP response's records to `Domain` entities. **Pure** (no
/// network/IO) so the cap + count-surfacing is unit-tested without a live key.
/// The entity fan-out is capped at [`MAX_REVERSE_RECORDS`] (co-tenant flood
/// guard), but the honest total — SecurityTrails' `record_count` when present,
/// else the number of records returned — is threaded onto every entity, so the
/// aggregate signal ("this IP has N associated domains") is never dropped.
fn associated_entities(
    records: &[AssociatedRecord],
    record_count: Option<u64>,
    ip: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let total = record_count.unwrap_or(records.len() as u64);
    let total_str = total.to_string();
    records
        .iter()
        .take(MAX_REVERSE_RECORDS)
        .filter_map(|record| {
            build_associated_entity(ip, record.hostname.as_deref(), &total_str, scan_id)
        })
        .collect()
}

pub struct SecurityTrails;

#[async_trait]
impl Module for SecurityTrails {
    fn name(&self) -> &'static str {
        "securitytrails"
    }
    fn description(&self) -> &'static str {
        "SecurityTrails recon — enumerates subdomains and pivots via reverse IP lookup"
    }
    fn priority(&self) -> u8 {
        45
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Historical/passive DNS database — ATT&CK DNS/Passive DNS (T1596.001).
        &["T1596.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;

        match target.kind {
            TargetKind::Domain => self.subdomain_search(target, key, ctx).await,
            TargetKind::IpAddress => self.reverse_ip(target, key, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

impl SecurityTrails {
    async fn subdomain_search(
        &self,
        target: &Target,
        key: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let domain = target.value.trim().trim_end_matches('.').to_lowercase();
        if domain.is_empty() || domain.contains('/') {
            return Ok(ModuleResult::new());
        }
        let url = format!("https://api.securitytrails.com/v1/domain/{domain}/subdomains");
        // A 404 here is a genuine failure (the subdomains endpoint answers a
        // real domain with 200 + an empty array, never a 404), so `absent_statuses`
        // stays empty — unchanged from before this was migrated to `keyed_cascade`.
        let Some(body): Option<SubdomainResp> = self.fetch_keyed(key, &url, &[], ctx).await? else {
            return Ok(ModuleResult::new());
        };

        let total = body.subdomain_count.unwrap_or(body.subdomains.len() as u64);
        let total_str = total.to_string();
        let mut result = ModuleResult::with_capacity(body.subdomains.len());
        result.extend(
            body.subdomains
                .iter()
                .filter_map(|sub| build_subdomain_entity(&domain, sub, &total_str, &ctx.scan_id)),
        );
        Ok(result)
    }

    async fn reverse_ip(
        &self,
        target: &Target,
        key: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://api.securitytrails.com/v1/ips/list?ipAddresses={}",
            crate::util::http::urlencode(ip),
        );
        // A 404 means no associated domains for this IP — a clean absence, not
        // an error (unlike `subdomain_search`'s endpoint; see `fetch_keyed`'s doc).
        let Some(body): Option<AssociatedResp> = self.fetch_keyed(key, &url, &[404], ctx).await?
        else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.extend(associated_entities(
            &body.records,
            body.record_count,
            ip,
            &ctx.scan_id,
        ));
        Ok(result)
    }

    /// Fetch and decode one SecurityTrails endpoint through the shared cascade
    /// primitive (T2: keyed-API consolidation) — the retry/rotate/cancel loop
    /// this used to hand-roll is now identical to what onyphe/threatfox/9+
    /// other keyed modules share; only the request shape (`APIKEY` header,
    /// GET) and the decode stay module-specific.
    ///
    /// `absent_statuses` differs by caller because the two SecurityTrails
    /// endpoints disagree on what a 404 means: [`Self::subdomain_search`]
    /// passes `&[]` (a subdomains 404 is a genuine failure, unchanged from
    /// before), while [`Self::reverse_ip`] passes `&[404]` (no associated
    /// domains for this IP is a clean absence, not an error) — see each
    /// caller's own comment.
    async fn fetch_keyed<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        url: &str,
        absent_statuses: &[u16],
        ctx: &ModuleContext,
    ) -> Result<Option<T>> {
        let Some(resp) = crate::util::http::keyed_cascade(ctx, SRC, key, absent_statuses, |k| {
            ctx.http
                .get(url)
                .header("APIKEY", k)
                .header("Accept", "application/json")
        })
        .await?
        else {
            return Ok(None);
        };
        // Capped decode (32 MiB) — a raw `resp.json()` would buffer an
        // unbounded body on the low-RAM Termux target.
        Ok(Some(crate::util::http::json_decode(SRC, resp).await?))
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
