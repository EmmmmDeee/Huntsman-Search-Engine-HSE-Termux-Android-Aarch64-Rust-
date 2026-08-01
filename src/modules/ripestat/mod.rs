//! RIPEstat enrichment — free, no-credential authoritative IP/ASN intelligence.
//!
//! RIPE NCC's public data API (`stat.ripe.net/data/<endpoint>/data.json`) is
//! keyless, fair-use, and authoritative. This module wires the highest-value
//! endpoints for OSINT:
//!
//!   * `network-info`         IP  → announcing ASN(s) + covering prefix
//!   * `as-overview`          ASN → holder (the org that operates the network)
//!   * `announced-prefixes`   ASN → every prefix the ASN announces (scannable CIDRs)
//!   * `abuse-contact-finder` IP/ASN → the registered **abuse-contact email**
//!
//! The abuse contact is the standout: it turns an IP or ASN into an *email*, a
//! genuine infrastructure → identity edge no other module produces. It is an
//! org-level contact (tagged `abuse-contact`, modest confidence), not the
//! subject's personal address, but it feeds the email pipeline and corroborates
//! the network's operator. Two small JSON GETs; Termux-friendly.

use async_trait::async_trait;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json, urlencode};

const SRC: &str = "ripestat";

pub struct RipeStat;

/// RIPEstat envelope: `{ "status": "ok", "data": { … } }`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct StatResp<T> {
    data: T,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetworkInfo {
    asns: Vec<String>,
    prefix: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AsOverview {
    holder: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AbuseContact {
    abuse_contacts: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AnnouncedPrefixes {
    prefixes: Vec<AnnouncedPrefix>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AnnouncedPrefix {
    prefix: Option<String>,
}

#[async_trait]
impl Module for RipeStat {
    fn name(&self) -> &'static str {
        "ripestat"
    }

    fn description(&self) -> &'static str {
        "RIPEstat IP/ASN recon — resolves ASN, network holder, and abuse-contact email (free)"
    }

    fn priority(&self) -> u8 {
        107
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Asn)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // RIPEstat resolves the registered abuse-contact email (T1589.002
        // Email Addresses) and the network-holder organisation (T1591.002
        // Business Relationships) beyond plain T1590.005 IP Addresses.
        // T1596.005 (Scan Databases) does NOT apply: every endpoint used here
        // (network-info, as-overview, announced-prefixes, abuse-contact-finder)
        // is RIR registration/routing data, not a port-scan corpus — the same
        // exclusion ip_registry's own override comment already establishes for
        // this exact class of source.
        &["T1590.005", "T1589.002", "T1591.002"]
    }

    fn max_timeout_ms(&self) -> u64 {
        // Two sequential JSON GETs; budget for a slow mobile link.
        14_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Asn,
            EntityKind::Cidr,
            EntityKind::Organisation,
            EntityKind::Email,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let resource = target.value.trim();

        match target.kind {
            TargetKind::IpAddress => {
                if let Some(ni) = stat::<NetworkInfo>(ctx, "network-info", resource).await {
                    result.entities.extend(build_asns(&ni, &ctx.scan_id));
                }
            }
            TargetKind::Asn => {
                if let Some(ao) = stat::<AsOverview>(ctx, "as-overview", resource).await {
                    result.entities.extend(build_org(&ao, &ctx.scan_id));
                }
                // The prefixes the ASN actually announces — each a scannable
                // CIDR the graph can expand into constituent host IPs, the same
                // way `network-info`'s covering prefix is surfaced for an IP.
                if let Some(ap) =
                    stat::<AnnouncedPrefixes>(ctx, "announced-prefixes", resource).await
                {
                    result
                        .entities
                        .extend(build_announced_prefixes(&ap, &ctx.scan_id));
                }
            }
            _ => return Ok(result),
        }

        if let Some(ac) = stat::<AbuseContact>(ctx, "abuse-contact-finder", resource).await {
            result
                .entities
                .extend(build_abuse(&ac.abuse_contacts, &ctx.scan_id));
        }
        Ok(result)
    }
}

/// Fetch + unwrap a RIPEstat endpoint's `data` object. `None` on any transport
/// or parse failure — best-effort, never fatal.
async fn stat<T: DeserializeOwned + Default>(
    ctx: &ModuleContext,
    endpoint: &str,
    resource: &str,
) -> Option<T> {
    let url = format!(
        "https://stat.ripe.net/data/{endpoint}/data.json?resource={}",
        urlencode(resource)
    );
    fetch_json::<StatResp<T>>(&ctx.http, SRC, &url)
        .await
        .ok()
        .map(|r| r.data)
}

/// ASN entities (`AS<n>`) + covering `Cidr` entity, from `network-info`.
fn build_asns(ni: &NetworkInfo, scan_id: &str) -> Vec<Entity> {
    let mut out: Vec<Entity> = ni
        .asns
        .iter()
        .filter(|a| a.chars().all(|c| c.is_ascii_digit()) && !a.is_empty())
        .map(|a| {
            let mut e = Entity::new(
                EntityKind::Asn,
                format!("AS{a}"),
                confidence::VERY_HIGH,
                scan_id,
            );
            e.tag(SRC);
            let mut ev = Evidence::new(SRC, "Announcing ASN (RIPEstat network-info)");
            if let Some(p) = &ni.prefix {
                ev = ev.with_attr("prefix", p);
            }
            e.add_evidence(ev);
            e
        })
        .collect();
    // The covering network prefix is a scannable CIDR — emit it so the graph
    // can expand into constituent host IPs via the scan engine.
    if let Some(prefix) = ni
        .prefix
        .as_deref()
        .map(str::trim)
        .filter(|p| p.contains('/'))
    {
        let mut ce = Entity::new(EntityKind::Cidr, prefix, confidence::HIGH_PLUS, scan_id);
        ce.tag(SRC);
        ce.tag("network-prefix");
        let mut ev = Evidence::new(SRC, "Covering prefix (RIPEstat network-info)");
        // Stamp the announcing ASN — matching `bgpview`'s Cidr evidence, which
        // already carries `asn`/`name` — so the prefix's origin network is on
        // record even without a consuming attribution rule. Only when the
        // origin is unambiguous (a single announcing ASN); a multi-origin
        // (MOAS) prefix has no one owner to assert, so it stays unattributed
        // rather than fabricating a single holder.
        let mut origins = ni
            .asns
            .iter()
            .filter(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()));
        if let Some(asn) = origins.next()
            && origins.next().is_none()
        {
            ev = ev.with_attr("asn", asn.as_str());
        }
        ce.add_evidence(ev);
        out.push(ce);
    }
    out
}

/// The network holder organisation, from `as-overview`.
fn build_org(ao: &AsOverview, scan_id: &str) -> Option<Entity> {
    let holder = ao
        .holder
        .as_deref()
        .map(str::trim)
        .filter(|h| h.len() >= 2)?;
    let mut e = Entity::new(
        EntityKind::Organisation,
        holder,
        confidence::HIGH_PLUS,
        scan_id,
    );
    e.tag(SRC);
    e.tag("network-holder");
    e.add_evidence(Evidence::new(SRC, "Network holder (RIPEstat as-overview)"));
    Some(e)
}

/// Announced prefixes for an ASN → scannable `Cidr` entities. **Pure.**
/// Deduplicated and emitted in a deterministic (sorted) order so the output
/// never leaks the API's array ordering. Only well-formed `/`-bearing prefixes
/// are kept — a malformed entry is dropped rather than becoming a junk CIDR.
fn build_announced_prefixes(ap: &AnnouncedPrefixes, scan_id: &str) -> Vec<Entity> {
    let prefixes: std::collections::BTreeSet<&str> = ap
        .prefixes
        .iter()
        .filter_map(|p| p.prefix.as_deref())
        .map(str::trim)
        .filter(|p| p.contains('/'))
        .collect();
    prefixes
        .into_iter()
        .map(|prefix| {
            let mut e = Entity::new(EntityKind::Cidr, prefix, 0.70, scan_id);
            e.tag(SRC);
            e.tag("network-prefix");
            e.add_evidence(Evidence::new(
                SRC,
                "Announced prefix (RIPEstat announced-prefixes)",
            ));
            e
        })
        .collect()
}

/// Abuse-contact emails — an org-level infrastructure→identity edge, tagged so
/// it's never mistaken for the subject's personal address.
fn build_abuse(contacts: &[String], scan_id: &str) -> Vec<Entity> {
    contacts
        .iter()
        .map(|c| c.trim())
        .filter(|c| crate::util::extract::looks_like_email(c))
        // A network abuse desk on a CDN/cloud/registrar provider (the common
        // case — `abuse@cloudflare.com`) is infrastructure, never the subject;
        // suppress it so it can't pollute the identity cluster.
        .filter(|c| !crate::util::domains::is_infrastructure_email(c))
        .map(|c| {
            let mut e = Entity::new(EntityKind::Email, c, confidence::MEDIUM, scan_id);
            e.tag(SRC);
            e.tag("abuse-contact");
            e.add_evidence(Evidence::new(SRC, "Registered abuse contact (RIPEstat)"));
            e
        })
        .collect()
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
