//! PeeringDB — ASN → network-operator attribution (keyless).
//!
//! Queries the free PeeringDB API (no key) for the `net` record behind an ASN:
//! the operating organisation's name, public website, IRR AS-SET, and network
//! profile (type / scope / peering policy, announced-prefix counts). It answers
//! the question `bgpview`/`ripestat` don't — *who runs this ASN?* — turning a
//! bare `AS13335` into a **named operator** and a **pivotable website**, so an
//! ASN discovered deep in an infrastructure sweep resolves to a real
//! organisation the corporate / people rules can pick up.
//!
//! Endpoint: `https://www.peeringdb.com/api/net?asn={n}` (public, keyless).
//! PeeringDB answers an unknown ASN with `200 {"data":[]}` — a clean "no such
//! network", which maps to zero findings rather than an error. The response →
//! entity mapping lives in the pure [`net_entities`] so it is unit-tested
//! without a live API; `process` owns only URL construction and transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::str_util::{nonempty, parse_asn};

const SRC: &str = "peeringdb";

pub struct PeeringDb;

#[async_trait]
impl Module for PeeringDb {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "PeeringDB recon — names the network operator behind an ASN (organisation, website, IRR AS-SET, network profile)"
    }
    fn priority(&self) -> u8 {
        34
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Asn)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Organisation, EntityKind::Url];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        // Normalise `AS13335` / `as13335` / `13335` → `13335`; reject junk.
        let Some(asn) = parse_asn(&target.value) else {
            return Ok(result);
        };
        let url = format!("https://www.peeringdb.com/api/net?asn={asn}");
        let resp: NetResponse = crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;
        for net in &resp.data {
            result.extend(net_entities(net, asn, &ctx.scan_id));
        }
        Ok(result)
    }
}

/// Entities for one PeeringDB `net` record: the operating `Organisation` (with
/// its full network profile as evidence) and, when the record lists one, the
/// operator's public `Url` (website) as a pivotable entity. An `Organisation`
/// is emitted only when the record actually names one — a `net` row with no
/// `name` yields nothing rather than an empty-named entity.
fn net_entities(net: &Net, asn: u64, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();

    if let Some(name) = nonempty(&net.name) {
        let mut e = Entity::new(
            EntityKind::Organisation,
            name,
            confidence::HIGH_PLUSPLUS,
            scan_id,
        );
        e.tag("peeringdb");
        e.tag("network-operator");
        let mut ev = Evidence::new(SRC, format!("AS{asn} operated by {name} (PeeringDB)"))
            .with_attr("asn", asn.to_string());
        if let Some(aka) = nonempty(&net.aka) {
            ev = ev.with_attr("aka", aka);
        }
        if let Some(set) = nonempty(&net.irr_as_set) {
            ev = ev.with_attr("irr_as_set", set);
        }
        if let Some(t) = nonempty(&net.info_type) {
            ev = ev.with_attr("network_type", t);
        }
        if let Some(scope) = nonempty(&net.info_scope) {
            ev = ev.with_attr("network_scope", scope);
        }
        if let Some(policy) = nonempty(&net.policy_general) {
            ev = ev.with_attr("peering_policy", policy);
        }
        // 0 is PeeringDB's "unset"; only surface a real announced-prefix count.
        if let Some(n) = net.info_prefixes4.filter(|n| *n > 0) {
            ev = ev.with_attr("announced_prefixes_v4", n.to_string());
        }
        if let Some(n) = net.info_prefixes6.filter(|n| *n > 0) {
            ev = ev.with_attr("announced_prefixes_v6", n.to_string());
        }
        if let Some(w) = nonempty(&net.website) {
            ev = ev.with_attr("website", w);
        }
        e.add_evidence(ev);
        out.push(e);
    }

    // The operator's public website — a pivotable Url. Only a syntactically
    // plausible http(s) URL is emitted, so a stray non-URL string in the field
    // never becomes a bogus entity.
    if let Some(website) = nonempty(&net.website)
        && (website.starts_with("http://") || website.starts_with("https://"))
    {
        let mut u = Entity::new(EntityKind::Url, website, confidence::HIGH, scan_id);
        u.tag("peeringdb");
        u.tag("operator-website");
        u.add_evidence(Evidence::new(
            SRC,
            format!("Operator website for AS{asn} (PeeringDB)"),
        ));
        out.push(u);
    }

    out
}

#[derive(Deserialize)]
struct NetResponse {
    #[serde(default)]
    data: Vec<Net>,
}

/// The subset of PeeringDB's `net` object HSE consumes. Every field is optional
/// so a sparse record (PeeringDB rows vary widely in completeness) still
/// deserialises — a missing field simply yields no evidence attribute.
#[derive(Deserialize)]
struct Net {
    name: Option<String>,
    aka: Option<String>,
    website: Option<String>,
    irr_as_set: Option<String>,
    info_type: Option<String>,
    info_scope: Option<String>,
    policy_general: Option<String>,
    info_prefixes4: Option<u64>,
    info_prefixes6: Option<u64>,
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
