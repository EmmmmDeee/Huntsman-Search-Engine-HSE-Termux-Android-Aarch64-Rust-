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
//!
//! Each network fn is a thin transport shell over a **pure** `build_*`
//! function that owns the record→entity mapping, so the extraction logic is
//! unit-tested directly off JSON fixtures with no network.

use async_trait::async_trait;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

mod types;

#[cfg(test)]
mod tests;

use types::{AsnResp, IpResp, RdapContact, RdapResp};

const SRC: &str = "ip_registry";

pub struct IpRegistry;

#[async_trait]
impl Module for IpRegistry {
    fn name(&self) -> &'static str {
        "ip_registry"
    }

    fn description(&self) -> &'static str {
        "IP registration recon — resolves registration and ASN data via RDAP and BGPView"
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
            EntityKind::Organisation,
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

// ── Transport (network) ─────────────────────────────────────────────────────

async fn process_ip(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let ip = target.value.trim();
    let (rdap_res, bgp_res) = tokio::join!(rdap_lookup_ip(ip, ctx), bgp_lookup_ip(ip, ctx));
    // Merge partial successes: RDAP and BGPView are independent sources, so one
    // failing must not discard the other's already-fetched result. The old
    // `rdap_res?` / `bgp_res?` propagated either error and reported total module
    // failure, losing the good half. Only error when BOTH sources fail.
    let mut result = ModuleResult::new();
    let mut rdap_err = None;
    match rdap_res {
        Ok(r) => result.extend(r.entities),
        Err(e) => {
            tracing::debug!(source = SRC, ip, error = %e, "ip_registry: RDAP lookup failed");
            rdap_err = Some(e);
        }
    }
    match bgp_res {
        Ok(b) => result.extend(b.entities),
        Err(e) => {
            tracing::debug!(source = SRC, ip, error = %e, "ip_registry: BGPView lookup failed");
            if let Some(rerr) = rdap_err {
                // Both sources failed — surface a real error so the circuit breaker
                // still registers the outage (matches the old `?`-propagation).
                return Err(rerr);
            }
        }
    }
    Ok(result)
}

async fn rdap_lookup_ip(ip: &str, ctx: &ModuleContext) -> Result<ModuleResult> {
    let url = format!("https://rdap.arin.net/registry/ip/{ip}");
    let Some(body): Option<RdapResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };
    let mut result = ModuleResult::new();
    result.entities = build_rdap_entities(&body, ip, &ctx.scan_id);
    Ok(result)
}

async fn bgp_lookup_ip(ip: &str, ctx: &ModuleContext) -> Result<ModuleResult> {
    let url = format!("https://api.bgpview.io/ip/{ip}");
    let Some(body): Option<IpResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };
    let mut result = ModuleResult::new();
    result.entities = build_bgp_ip_entities(&body, ip, &ctx.scan_id);
    Ok(result)
}

async fn bgp_lookup_asn(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let Some(asn) = crate::util::str_util::parse_asn(&target.value) else {
        return Ok(ModuleResult::new());
    };

    let url = format!("https://api.bgpview.io/asn/{asn}");
    let Some(body): Option<AsnResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };
    let mut result = ModuleResult::new();
    result.entities = build_asn_entities(&body, asn, &ctx.scan_id);
    Ok(result)
}

// ── Pure builders (record → entities, no I/O) ────────────────────────────────

/// Build entities from an RDAP IP record. **Pure.** Always emits the
/// `IpAddress` allocation entity (RDAP returning a record at all means the block
/// is allocated): the CIDR derivation (explicit prefix, else the start–end
/// range), the `country:` tag, and the registration/event evidence all live
/// here. Additionally mines the nested contact tree for the registrant
/// `Organisation` (the network operator holding the block) and the abuse-desk
/// `Email` — parity with the `whois` RDAP-over-HTTPS fallback and with the
/// BGPView abuse/admin contacts this module already surfaces for ASN targets.
fn build_rdap_entities(body: &RdapResp, ip: &str, scan_id: &str) -> Vec<Entity> {
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

    let mut entity = Entity::new(EntityKind::IpAddress, ip, confidence::VERY_HIGH_PLUS, scan_id);
    entity.tag("rdap");
    if let Some(c) = body.country.as_deref().filter(|c| !c.is_empty()) {
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
    .filter_map(|(key, value)| value.filter(|v| !v.is_empty()).map(|v| (key, v)))
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

    let mut out = vec![entity];
    // Registrant organisation — the network operator that holds the block, a
    // high-value attribution pivot (blocks held by the same operator cluster).
    if let Some(org) = build_registrant_org(&body.entities, ip, scan_id) {
        out.push(org);
    }
    // Abuse-desk email — an operational role contact, never GDPR-redacted for
    // IP allocations. Mirrors the BGPView `abuse_contacts` surfaced for ASNs.
    if let Some(email) = build_abuse_email(&body.entities, ip, scan_id) {
        out.push(email);
    }
    out
}

/// Walk the RDAP contact tree (contacts nest — a registrant entity carries its
/// own abuse/technical children) and return the first entity whose `roles`
/// include `role`. **Pure.** Mirrors `whois::find_ip_entity`.
fn find_contact<'a>(contacts: &'a [RdapContact], role: &str) -> Option<&'a RdapContact> {
    for c in contacts {
        if c.roles.iter().any(|r| r == role) {
            return Some(c);
        }
        if let Some(found) = find_contact(&c.entities, role) {
            return Some(found);
        }
    }
    None
}

/// Build the registrant `Organisation` from the RDAP contact tree. **Pure.**
/// `None` unless a registrant-role contact carries a usable vCard `fn`/`org`.
/// Gated on vCard `kind`: IP blocks are allocated to network operators, but a
/// rare `individual`-kind registrant is a natural person and is skipped so their
/// name never surfaces as an organisation.
fn build_registrant_org(contacts: &[RdapContact], ip: &str, scan_id: &str) -> Option<Entity> {
    let vc = find_contact(contacts, "registrant")?.vcard_array.as_ref()?;
    if crate::modules::whois::vcard_field(vc, "kind")
        .is_some_and(|k| k.eq_ignore_ascii_case("individual"))
    {
        return None;
    }
    let name = crate::modules::whois::vcard_field(vc, "fn")
        .or_else(|| crate::modules::whois::vcard_field(vc, "org"))
        .map(|s| s.trim().to_string())
        .filter(|s| s.len() >= 3)?;

    let mut oe = Entity::new(EntityKind::Organisation, &name, 0.72, scan_id);
    oe.tag("rdap");
    oe.tag("ip-registrant");
    oe.add_evidence(
        Evidence::new(SRC, format!("RDAP network registrant for {ip}")).with_attr("ip", ip),
    );
    Some(oe)
}

/// Build the abuse-desk `Email` from the RDAP contact tree. **Pure.** `None`
/// unless an abuse-role contact carries a vCard `email` that parses as an
/// address. Tagged `role:abuse`, matching the BGPView contact convention.
fn build_abuse_email(contacts: &[RdapContact], ip: &str, scan_id: &str) -> Option<Entity> {
    let vc = find_contact(contacts, "abuse")?.vcard_array.as_ref()?;
    let email = crate::modules::whois::vcard_field(vc, "email")?;
    let email = email.trim();
    if !crate::util::extract::looks_like_email(email) {
        return None;
    }
    let mut ee = Entity::new(EntityKind::Email, email, 0.78, scan_id);
    ee.tag("rdap-contact");
    ee.tag("role:abuse");
    ee.add_evidence(
        Evidence::new(SRC, format!("RDAP abuse contact for {ip}"))
            .with_attr("source", "rdap")
            .with_attr("ip", ip)
            .with_attr("contact_role", "abuse"),
    );
    Some(ee)
}

/// Build the announcing-`Asn` entity for an IP from a BGPView `ip` record.
/// **Pure.** Empty unless the response is `ok` and the leading (most-specific)
/// prefix carries an ASN — mirroring BGPView's prefix ordering.
fn build_bgp_ip_entities(body: &IpResp, ip: &str, scan_id: &str) -> Vec<Entity> {
    if body.status != "ok" {
        return Vec::new();
    }
    let Some(data) = body.data.as_ref() else {
        return Vec::new();
    };
    let Some(prefix) = data.prefixes.iter().flatten().next() else {
        return Vec::new();
    };
    let Some(asn_ref) = prefix.asn.as_ref() else {
        return Vec::new();
    };
    let Some(asn_num) = asn_ref.asn else {
        return Vec::new();
    };

    let asn_num_str = asn_num.to_string();
    let mut e = Entity::new(EntityKind::Asn, format!("AS{asn_num}"), confidence::EXPERT, scan_id);
    e.tag("announcing");
    let mut ev =
        Evidence::new(SRC, format!("ASN announcing {ip}")).with_attr("asn_number", &asn_num_str);
    if let Some(p) = prefix.prefix.as_deref().filter(|p| !p.is_empty()) {
        ev = ev.with_attr("prefix", p);
    }
    if let Some(n) = asn_ref.name.as_deref().filter(|n| !n.is_empty()) {
        ev = ev.with_attr("handle", n);
    }
    if let Some(d) = asn_ref.description.as_deref().filter(|d| !d.is_empty()) {
        ev = ev.with_attr("name", d);
    }
    if let Some(c) = asn_ref.country_code.as_deref().filter(|c| !c.is_empty()) {
        ev = ev.with_attr("country", c);
    }
    e.add_evidence(ev);
    vec![e]
}

/// Build the registry `Asn` entity, its contact `Email`s, and the operator
/// `Url` from a BGPView `asn` record. **Pure.** Empty unless the response is
/// `ok` with data.
fn build_asn_entities(body: &AsnResp, asn: u64, scan_id: &str) -> Vec<Entity> {
    if body.status != "ok" {
        return Vec::new();
    }
    let Some(data) = body.data.as_ref() else {
        return Vec::new();
    };

    let asn_label = format!("AS{asn}");
    let asn_str = asn.to_string();
    let mut result = Vec::new();

    let mut entity = Entity::new(EntityKind::Asn, &asn_label, 0.92, scan_id);
    entity.tag("registered");
    let mut ev = Evidence::new(SRC, format!("ASN {asn_label} registry record"))
        .with_attr("asn_number", &asn_str);
    if let Some(n) = data.name.as_deref().filter(|n| !n.is_empty()) {
        ev = ev.with_attr("handle", n);
    }
    if let Some(d) = data.description_short.as_deref().filter(|d| !d.is_empty()) {
        ev = ev.with_attr("name", d);
    }
    if let Some(c) = data.country_code.as_deref().filter(|c| !c.is_empty()) {
        ev = ev.with_attr("country", c);
    }
    if let Some(rir) = &data.rir_allocation {
        if let Some(n) = rir.rir_name.as_deref().filter(|n| !n.is_empty()) {
            ev = ev.with_attr("rir", n);
        }
        if let Some(d) = rir.date_allocated.as_deref().filter(|d| !d.is_empty()) {
            ev = ev.with_attr("allocated", d);
        }
    }
    if let Some(w) = data.website.as_deref().filter(|w| !w.is_empty()) {
        ev = ev.with_attr("website", w);
    }
    entity.add_evidence(ev);
    result.push(entity);

    // Operator organisation — the entity that holds the ASN, a high-value
    // attribution pivot (ASNs/blocks held by the same operator cluster).
    // Mirrors `build_registrant_org`'s RDAP promotion, sourced from BGPView
    // instead: prefer the full legible name, fall back to the registry handle.
    let operator_name = data
        .description_short
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| data.name.as_deref().filter(|s| !s.trim().is_empty()));
    if let Some(name) = operator_name {
        let mut oe = Entity::new(EntityKind::Organisation, name, confidence::HIGH_PLUS, scan_id);
        oe.tag("bgpview");
        oe.tag("asn-operator");
        oe.add_evidence(
            Evidence::new(SRC, format!("Operator of {asn_label}")).with_attr("asn", &asn_str),
        );
        result.push(oe);
    }

    result.extend(contact_emails(
        data.email_contacts.as_deref(),
        "admin",
        &asn_label,
        &asn_str,
        scan_id,
    ));
    result.extend(contact_emails(
        data.abuse_contacts.as_deref(),
        "abuse",
        &asn_label,
        &asn_str,
        scan_id,
    ));

    if let Some(w) = data
        .website
        .as_deref()
        .filter(|w| w.starts_with("http://") || w.starts_with("https://"))
    {
        let mut u = Entity::new(EntityKind::Url, w, confidence::VERY_HIGH, scan_id);
        u.tag("asn-website");
        u.add_evidence(
            Evidence::new(SRC, format!("Website of {asn_label}")).with_attr("asn", &asn_str),
        );
        result.push(u);
    }

    result
}

/// Build `Email` entities for an ASN's contact list. Pure (no network).
/// Non-email strings (no `@`) are skipped; each address is tagged with its
/// contact `role` (admin/abuse).
fn contact_emails(
    emails: Option<&[String]>,
    role: &'static str,
    asn_label: &str,
    asn_str: &str,
    scan_id: &str,
) -> Vec<Entity> {
    emails
        .unwrap_or_default()
        .iter()
        .filter(|email| crate::util::extract::looks_like_email(email))
        .map(|email| {
            let mut e = Entity::new(EntityKind::Email, email.as_str(), 0.78, scan_id);
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
