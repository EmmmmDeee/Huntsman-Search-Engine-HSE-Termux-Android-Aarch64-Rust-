//! Merged IP registration + ASN module: RDAP (Registry Data Access
//! Protocol) allocation records **and** BGPView ASN / prefix lookups.
//!
//! For `IpAddress` targets both RDAP and BGPView are queried
//! concurrently. For `Asn` targets only BGPView is used.
//!
//! RDAP endpoint: `https://rdap.arin.net/registry/ip/{ip}` (ARIN
//! redirects to the matching RIR when necessary; `reqwest` follows
//! redirects transparently).
//!
//! BGPView endpoints:
//!   - `https://api.bgpview.io/asn/{asn}` (ASN registry record)
//!   - `https://api.bgpview.io/ip/{ip}`   (IP-to-ASN reverse mapping)
//!
//! Both APIs are free, keyless, and rate-limited to ~1 req/s.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

mod types;

#[cfg(test)]
mod tests;

use types::{AsnResp, IpResp, RdapResp};

const SRC: &str = "ip_registry";

pub struct IpRegistry;

#[async_trait]
impl Module for IpRegistry {
    fn name(&self) -> &'static str {
        "ip_registry"
    }

    fn description(&self) -> &'static str {
        "IP registration and ASN data via RDAP and BGPView"
    }

    fn priority(&self) -> u8 {
        23
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Asn)
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // ip_registry queries RDAP (the standardised WHOIS replacement, T1596.002)
        // and BGPView (IP/ASN intelligence, T1590.005). It emits abuse-contact
        // Email entities (T1589.002) and the ASN operator as a Business
        // Relationship (T1591.002). T1596.005 (Scan Databases) does not apply —
        // RDAP and BGPView are registration/routing databases, not port-scan corpora.
        &["T1589.002", "T1590.005", "T1591.002", "T1596.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Asn,
            EntityKind::Email,
            EntityKind::Url,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::IpAddress => process_ip(target, ctx).await,
            TargetKind::Asn => bgp_lookup_asn(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

async fn process_ip(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let ip = target.value.trim();
    let (rdap_res, bgp_res) = tokio::join!(rdap_lookup_ip(ip, ctx), bgp_lookup_ip(ip, ctx),);
    let mut result = rdap_res?;
    result.extend(bgp_res?.entities);
    Ok(result)
}

async fn rdap_lookup_ip(ip: &str, ctx: &ModuleContext) -> Result<ModuleResult> {
    let url = format!("https://rdap.arin.net/registry/ip/{ip}");
    let Some(body): Option<RdapResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };

    let cidr = body
        .cidr0_cidrs
        .iter()
        .find_map(|c| {
            let p = c.v4prefix.as_deref().or(c.v6prefix.as_deref())?;
            Some(match c.length {
                Some(l) => format!("{p}/{l}"),
                None => p.to_string(),
            })
        })
        .or_else(
            || match (body.start_address.as_deref(), body.end_address.as_deref()) {
                (Some(s), Some(e)) => Some(format!("{s} – {e}")),
                _ => None,
            },
        );

    let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.90, &ctx.scan_id);
    entity.tag("rdap");
    if let Some(c) = body.country.as_deref() {
        entity.tag(format!("country:{}", c.to_uppercase()));
    }

    let ev = [
        ("handle", body.handle.as_deref()),
        ("name", body.name.as_deref()),
        ("country", body.country.as_deref()),
        ("prefix", cidr.as_deref()),
        ("ip_version", body.ip_version.as_deref()),
        ("parent_handle", body.parent_handle.as_deref()),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v)))
    .fold(
        Evidence::new(SRC, format!("RDAP allocation record for {ip}")),
        |ev, (key, v)| ev.with_attr(key, v),
    );
    let ev = body
        .events
        .iter()
        .fold(ev, |ev, evt| match evt.date.as_deref() {
            Some(d) => ev.with_attr(format!("event:{}", evt.action.replace(' ', "_")), d),
            None => ev,
        });
    entity.add_evidence(ev);

    let mut result = ModuleResult::new();
    result.push(entity);
    Ok(result)
}

async fn bgp_lookup_ip(ip: &str, ctx: &ModuleContext) -> Result<ModuleResult> {
    let url = format!("https://api.bgpview.io/ip/{ip}");
    let Some(body): Option<IpResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };
    if body.status != "ok" {
        return Ok(ModuleResult::new());
    }
    let Some(data) = body.data else {
        return Ok(ModuleResult::new());
    };

    let mut result = ModuleResult::new();
    if let Some(prefix) = data.prefixes.into_iter().flatten().next()
        && let Some(asn_ref) = prefix.asn
        && let Some(asn_num) = asn_ref.asn
    {
        let asn_num_str = asn_num.to_string();
        let mut e = Entity::new(EntityKind::Asn, format!("AS{asn_num}"), 0.88, &ctx.scan_id);
        e.tag("announcing");
        let mut ev = Evidence::new(SRC, format!("ASN announcing {ip}"))
            .with_attr("asn_number", &asn_num_str);
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

async fn bgp_lookup_asn(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let raw = target.value.trim().to_uppercase();
    let digits = raw.trim_start_matches("AS").trim();
    let Ok(asn) = digits.parse::<u64>() else {
        return Ok(ModuleResult::new());
    };

    let url = format!("https://api.bgpview.io/asn/{asn}");
    let Some(body): Option<AsnResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };
    if body.status != "ok" {
        return Ok(ModuleResult::new());
    }
    let Some(data) = body.data else {
        return Ok(ModuleResult::new());
    };

    let mut result = ModuleResult::new();
    let asn_label = format!("AS{asn}");
    let asn_str = asn.to_string();
    let mut entity = Entity::new(EntityKind::Asn, &asn_label, 0.92, &ctx.scan_id);
    entity.tag("registered");

    let mut ev = Evidence::new(SRC, format!("ASN {asn_label} registry record"))
        .with_attr("asn_number", &asn_str);
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

    result.extend(contact_emails(
        data.email_contacts,
        "admin",
        &asn_label,
        &asn_str,
        &ctx.scan_id,
    ));
    result.extend(contact_emails(
        data.abuse_contacts,
        "abuse",
        &asn_label,
        &asn_str,
        &ctx.scan_id,
    ));

    if let Some(w) = data
        .website
        .as_deref()
        .filter(|w| w.starts_with("http://") || w.starts_with("https://"))
    {
        let mut u = Entity::new(EntityKind::Url, w, 0.75, &ctx.scan_id);
        u.tag("asn-website");
        u.add_evidence(
            Evidence::new(SRC, format!("Website of {asn_label}")).with_attr("asn", &asn_str),
        );
        result.push(u);
    }

    Ok(result)
}

/// Build `Email` entities for an ASN's contact list. Pure (no network).
fn contact_emails(
    emails: Option<Vec<String>>,
    role: &'static str,
    asn_label: &str,
    asn_str: &str,
    scan_id: &str,
) -> Vec<Entity> {
    emails
        .into_iter()
        .flatten()
        .filter(|email| email.contains('@'))
        .map(|email| {
            let mut e = Entity::new(EntityKind::Email, &email, 0.78, scan_id);
            e.tag("asn-contact");
            e.tag(format!("role:{role}"));
            e.add_evidence(
                Evidence::new(SRC, format!("Contact for {asn_label}"))
                    .with_attr("source", "bgpview")
                    .with_attr("asn", asn_str)
                    .with_attr("contact_role", role),
            );
            e
        })
        .collect()
}
