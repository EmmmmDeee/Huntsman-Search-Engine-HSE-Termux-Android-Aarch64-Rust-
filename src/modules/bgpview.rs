//! BGPView ASN lookup. Free, no key, 1 req/sec public rate limit.
//!
//! Endpoint: `https://api.bgpview.io/asn/{asn}` — returns the AS's
//! holder name, country, RIR, and contact addresses. Closes the
//! `TargetKind::Asn` coverage gap (zero modules accepted ASN inputs
//! before this).
//!
//! Also accepts an `IpAddress` target and reverse-maps it to the
//! announcing ASN via `/ip/{ip}` — emits one Asn entity tagged
//! `announcing` so an IP scan picks up its network operator.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

pub struct BgpView;

#[derive(Deserialize)]
struct AsnResp {
    data: Option<AsnData>,
    status: String,
}

#[derive(Deserialize)]
struct AsnData {
    name: Option<String>,
    description_short: Option<String>,
    country_code: Option<String>,
    rir_allocation: Option<RirInfo>,
    email_contacts: Option<Vec<String>>,
    abuse_contacts: Option<Vec<String>>,
    website: Option<String>,
}

#[derive(Deserialize)]
struct RirInfo {
    rir_name: Option<String>,
    date_allocated: Option<String>,
}

#[derive(Deserialize)]
struct IpResp {
    data: Option<IpData>,
    status: String,
}

#[derive(Deserialize)]
struct IpData {
    prefixes: Option<Vec<PrefixInfo>>,
}

#[derive(Deserialize)]
struct PrefixInfo {
    prefix: Option<String>,
    asn: Option<AsnRef>,
}

#[derive(Deserialize)]
struct AsnRef {
    asn: Option<u64>,
    name: Option<String>,
    description: Option<String>,
    country_code: Option<String>,
}

#[async_trait]
impl Module for BgpView {
    fn name(&self) -> &'static str {
        "bgpview"
    }

    fn priority(&self) -> u8 {
        25
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Asn | TargetKind::IpAddress)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::Asn => lookup_asn(target, ctx).await,
            TargetKind::IpAddress => lookup_ip(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

async fn lookup_asn(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let raw = target.value.trim().to_uppercase();
    // Accept both "AS15169" and "15169".
    let digits = raw.trim_start_matches("AS").trim();
    let asn: u64 = match digits.parse() {
        Ok(n) => n,
        Err(_) => return Ok(ModuleResult::new()),
    };

    let url = format!("https://api.bgpview.io/asn/{asn}");
    let Some(body): Option<AsnResp> = fetch_json_or_404(&ctx.http, "bgpview", &url).await? else {
        return Ok(ModuleResult::new());
    };

    if body.status != "ok" {
        return Ok(ModuleResult::new());
    }
    let Some(data) = body.data else {
        return Ok(ModuleResult::new());
    };

    let mut result = ModuleResult::new();
    let mut entity = Entity::new(EntityKind::Asn, format!("AS{asn}"), 0.92, &ctx.scan_id);
    entity.tag("registered");

    let mut ev = Evidence::new("bgpview", format!("ASN AS{asn} registry record"))
        .with_attr("asn_number", asn.to_string());
    if let Some(n) = data.name.as_deref() {
        ev = ev.with_attr("handle", n);
    }
    if let Some(d) = data.description_short.as_deref() {
        ev = ev.with_attr("name", d);
    }
    if let Some(c) = data.country_code.as_deref() {
        ev = ev.with_attr("country", c);
    }
    if let Some(rir) = &data.rir_allocation {
        if let Some(n) = rir.rir_name.as_deref() {
            ev = ev.with_attr("rir", n);
        }
        if let Some(d) = rir.date_allocated.as_deref() {
            ev = ev.with_attr("allocated", d);
        }
    }
    if let Some(w) = data.website.as_deref()
        && !w.is_empty()
    {
        ev = ev.with_attr("website", w);
    }
    entity.add_evidence(ev);
    result.push(entity);

    // Surface contact emails as discrete Email entities — they're real
    // identity signals (the AS holder's abuse / NOC mailbox).
    for email in data
        .email_contacts
        .into_iter()
        .flatten()
        .chain(data.abuse_contacts.into_iter().flatten())
    {
        if !email.contains('@') {
            continue;
        }
        let mut e = Entity::new(EntityKind::Email, &email, 0.78, &ctx.scan_id);
        e.tag("asn-contact");
        e.add_evidence(
            Evidence::new("bgpview", format!("Contact for AS{asn}"))
                .with_attr("source", "bgpview")
                .with_attr("asn", asn.to_string()),
        );
        result.push(e);
    }

    // If the AS has a website, emit it as a Url entity.
    if let Some(w) = data
        .website
        .as_deref()
        .filter(|w| w.starts_with("http://") || w.starts_with("https://"))
    {
        let mut u = Entity::new(EntityKind::Url, w, 0.75, &ctx.scan_id);
        u.tag("asn-website");
        u.add_evidence(
            Evidence::new("bgpview", format!("Website of AS{asn}"))
                .with_attr("asn", asn.to_string()),
        );
        result.push(u);
    }

    Ok(result)
}

async fn lookup_ip(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let ip = target.value.trim();
    if ip.is_empty() {
        return Ok(ModuleResult::new());
    }
    let url = format!("https://api.bgpview.io/ip/{ip}");
    let Some(body): Option<IpResp> = fetch_json_or_404(&ctx.http, "bgpview", &url).await? else {
        return Ok(ModuleResult::new());
    };
    if body.status != "ok" {
        return Ok(ModuleResult::new());
    }
    let Some(data) = body.data else {
        return Ok(ModuleResult::new());
    };

    let mut result = ModuleResult::new();
    // Take only the most-specific (first) prefix announcement — bgpview
    // returns them ordered by length descending.
    if let Some(prefix) = data.prefixes.into_iter().flatten().next()
        && let Some(asn_ref) = prefix.asn
        && let Some(asn_num) = asn_ref.asn
    {
        let mut e = Entity::new(EntityKind::Asn, format!("AS{asn_num}"), 0.88, &ctx.scan_id);
        e.tag("announcing");
        let mut ev = Evidence::new("bgpview", format!("ASN announcing {ip}"))
            .with_attr("asn_number", asn_num.to_string());
        if let Some(p) = prefix.prefix.as_deref() {
            ev = ev.with_attr("prefix", p);
        }
        if let Some(n) = asn_ref.name.as_deref() {
            ev = ev.with_attr("handle", n);
        }
        if let Some(d) = asn_ref.description.as_deref() {
            ev = ev.with_attr("name", d);
        }
        if let Some(c) = asn_ref.country_code.as_deref() {
            ev = ev.with_attr("country", c);
        }
        e.add_evidence(ev);
        result.push(e);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_asn_and_ip() {
        let m = BgpView;
        assert!(m.accepts(&Target::new(TargetKind::Asn, "AS15169")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }
}
