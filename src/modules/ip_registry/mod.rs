//! IP and ASN registration records over RDAP (Registry Data Access
//! Protocol, the standardised WHOIS replacement).
//!
//! For `IpAddress` targets: `https://rdap.arin.net/registry/ip/{ip}` — the
//! allocation record (block, country, events, registrant, abuse desk).
//! For `Asn` targets: `https://rdap.arin.net/registry/autnum/{asn}` — the
//! autnum record (handle, name, status, events, registrant organisation,
//! abuse / technical / administrative contacts). ARIN's RDAP root redirects to
//! the authoritative RIR for a resource it does not hold (`AS3320` →
//! `rdap.db.ripe.net`); `reqwest` follows the redirect transparently.
//!
//! The ASN path used to query BGPView's `api.bgpview.io/asn/{n}` (and the IP
//! path its `/ip/{ip}` twin). That host no longer resolves — the weekly live
//! sweep read the `bgpview` canary "unreachable" on every run and every ASN
//! target hard-errored — so the BGPView half was retired: the announcing-ASN /
//! covering-prefix pivots an IP used to get from it are `ripestat`'s
//! (`network-info`), and the ASN registry record is RDAP's, the same corpus
//! the IP path already reads (`docs/PROVIDER_SWEEP_BACKLOG.md` #25,
//! `docs/REQUIREMENTS_LEDGER.md` REQ-BGP-001).
//!
//! Both endpoints are free and keyless. Each network fn is a thin transport
//! shell over a **pure** `build_*` function that owns the record→entity
//! mapping, so the extraction logic is unit-tested directly off JSON fixtures
//! (captured from the live RIRs) with no network.
use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

mod types;

#[cfg(test)]
mod tests;

use types::{AutnumResp, RdapContact, RdapResp};

const SRC: &str = "ip_registry";

/// ARIN's RDAP root. ARIN serves its own resources directly and answers a
/// resource held by another RIR with a redirect to that RIR's RDAP service, so
/// one base covers every allocation and every ASN.
const RDAP_BASE: &str = "https://rdap.arin.net/registry";

pub struct IpRegistry;

#[async_trait]
impl Module for IpRegistry {
    fn name(&self) -> &'static str {
        "ip_registry"
    }

    fn description(&self) -> &'static str {
        "IP / ASN registration recon — RDAP allocation and autnum records via ARIN's bootstrap, redirected to the authoritative RIR"
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
        // for IP allocations and ASN registrations (T1590.005). It emits
        // abuse-contact Email entities (T1589.002) and the ASN operator as a
        // Business Relationship (T1591.002). T1596.005 (Scan Databases) does not
        // apply — RDAP is a registration database, not a port-scan corpus.
        &["T1589.002", "T1590.005", "T1591.002", "T1596.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Asn,
            EntityKind::Email,
            EntityKind::Organisation,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::IpAddress => {
                rdap_lookup_ip(&ctx.http, RDAP_BASE, target.value.trim(), &ctx.scan_id).await
            }
            TargetKind::Asn => {
                // Normalise `AS13335` / `as13335` / `13335` → `13335`; reject junk.
                let Some(asn) = crate::util::str_util::parse_asn(&target.value) else {
                    return Ok(ModuleResult::new());
                };
                rdap_lookup_asn(&ctx.http, RDAP_BASE, asn, &ctx.scan_id).await
            }
            _ => Ok(ModuleResult::new()),
        }
    }
}

// ── Transport (network) ─────────────────────────────────────────────────────

/// The IP allocation record. RDAP's 404 is "no such allocation" — the one
/// clean negative; any other non-2xx, a transport failure or an unreadable
/// body is the module's error.
async fn rdap_lookup_ip(
    client: &reqwest::Client,
    rdap_base: &str,
    ip: &str,
    scan_id: &str,
) -> Result<ModuleResult> {
    let url = format!("{rdap_base}/ip/{ip}");
    let Some(body): Option<RdapResp> = fetch_json_or_404(client, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };
    let mut result = ModuleResult::new();
    result.entities = build_rdap_entities(&body, ip, scan_id);
    Ok(result)
}

/// The ASN registration record. RDAP's 404 is "no such autnum" (an unassigned
/// or reserved number) — the one clean negative; any other non-2xx, a
/// transport failure or an unreadable body is the module's error.
async fn rdap_lookup_asn(
    client: &reqwest::Client,
    rdap_base: &str,
    asn: u64,
    scan_id: &str,
) -> Result<ModuleResult> {
    let url = format!("{rdap_base}/autnum/{asn}");
    let Some(body): Option<AutnumResp> = fetch_json_or_404(client, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };
    let mut result = ModuleResult::new();
    result.entities = build_autnum_entities(&body, asn, scan_id);
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
/// autnum contacts this module surfaces for ASN targets.
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

    let mut entity = Entity::new(
        EntityKind::IpAddress,
        ip,
        confidence::VERY_HIGH_PLUS,
        scan_id,
    );
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
    // IP allocations. Mirrors the abuse contact surfaced for ASNs.
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

    let mut oe = Entity::new(
        EntityKind::Organisation,
        &name,
        confidence::ATTRIBUTED,
        scan_id,
    );
    oe.tag("rdap");
    oe.tag("ip-registrant");
    oe.add_evidence(
        Evidence::new(SRC, format!("RDAP network registrant for {ip}")).with_attr("ip", ip),
    );
    Some(oe)
}

/// Build the abuse-desk `Email` from the RDAP contact tree. **Pure.** `None`
/// unless an abuse-role contact carries a vCard `email` that parses as an
/// address. Tagged `role:abuse`, matching the ASN contact convention.
fn build_abuse_email(contacts: &[RdapContact], ip: &str, scan_id: &str) -> Option<Entity> {
    let vc = find_contact(contacts, "abuse")?.vcard_array.as_ref()?;
    let email = crate::modules::whois::vcard_field(vc, "email")?;
    let email = email.trim();
    // An RDAP abuse contact resolves to a registrar/provider desk by
    // construction, but it is still free-text-sourced — a role-local-part or
    // provider-domain address (hostmaster@, dns@cloudflare.com) is
    // infrastructure contact, never the subject's own mail. Same gate
    // whois/dns_intel already apply to their own abuse/admin contacts.
    if !crate::util::extract::looks_like_email(email)
        || crate::util::domains::is_infrastructure_email(email)
    {
        return None;
    }
    let mut ee = Entity::new(EntityKind::Email, email, confidence::STRONG, scan_id);
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

/// Build entities from an RDAP `autnum` record. **Pure.** Always emits the
/// `Asn` registry entity (RDAP returning the object at all means the number is
/// registered) carrying handle, name, status, the registry that answered and
/// every dated event; adds the registrant `Organisation` (the operator holding
/// the ASN — a high-value attribution pivot, as ASNs and blocks held by one
/// operator cluster) and the contact `Email`s (abuse, administrative,
/// technical) that pass the same role-local-part / provider-domain gate every
/// registry contact in this crate passes.
fn build_autnum_entities(body: &AutnumResp, asn: u64, scan_id: &str) -> Vec<Entity> {
    let asn_label = format!("AS{asn}");
    let asn_str = asn.to_string();

    let mut entity = Entity::new(
        EntityKind::Asn,
        &asn_label,
        confidence::AUTHORITATIVE,
        scan_id,
    );
    entity.tag("registered");
    entity.tag("rdap");
    let range = match (body.start_autnum, body.end_autnum) {
        (Some(a), Some(b)) if a != b => Some(format!("AS{a}-AS{b}")),
        _ => None,
    };
    let status = (!body.status.is_empty()).then(|| body.status.join(","));
    let ev = [
        ("asn_number", Some(asn_str.as_str())),
        ("handle", body.handle.as_deref()),
        ("name", body.name.as_deref()),
        ("status", status.as_deref()),
        ("range", range.as_deref()),
        ("registry", body.port43.as_deref()),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.filter(|v| !v.is_empty()).map(|v| (key, v)))
    .fold(
        Evidence::new(SRC, format!("RDAP registry record for {asn_label}")),
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
    if let Some(org) = build_asn_operator(&body.entities, &asn_label, &asn_str, scan_id) {
        out.push(org);
    }
    out.extend(build_asn_contacts(
        &body.entities,
        &asn_label,
        &asn_str,
        scan_id,
    ));
    out
}

/// Every contact in the tree (contacts nest) whose `roles` include `role`, in
/// document order. **Pure.**
fn contacts_with_role<'a>(contacts: &'a [RdapContact], role: &str, out: &mut Vec<&'a RdapContact>) {
    for c in contacts {
        if c.roles.iter().any(|r| r == role) {
            out.push(c);
        }
        contacts_with_role(&c.entities, role, out);
    }
}

/// The operator `Organisation` from an autnum's registrant contacts. **Pure.**
/// RIPE lists several `registrant`-role entities on one autnum — the
/// organisation, but also the maintainer and routing-registry handles, which
/// carry vCard `kind: individual` and a `fn` that is just the handle
/// (`DTAG-RR`, `RIPE-NCC-END-MNT`). Only a registrant whose vCard says
/// `kind: org` is the operator; an `individual` registrant is never minted as
/// an organisation, mirroring [`build_registrant_org`]'s rule for allocations.
fn build_asn_operator(
    contacts: &[RdapContact],
    asn_label: &str,
    asn_str: &str,
    scan_id: &str,
) -> Option<Entity> {
    let mut registrants = Vec::new();
    contacts_with_role(contacts, "registrant", &mut registrants);
    let name = registrants.iter().find_map(|c| {
        let vc = c.vcard_array.as_ref()?;
        if !crate::modules::whois::vcard_field(vc, "kind")
            .is_some_and(|k| k.eq_ignore_ascii_case("org"))
        {
            return None;
        }
        crate::modules::whois::vcard_field(vc, "fn")
            .or_else(|| crate::modules::whois::vcard_field(vc, "org"))
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() >= 3)
    })?;
    let mut oe = Entity::new(
        EntityKind::Organisation,
        &name,
        confidence::HIGH_PLUS,
        scan_id,
    );
    oe.tag("rdap");
    oe.tag("asn-operator");
    oe.add_evidence(
        Evidence::new(SRC, format!("Operator of {asn_label} (RDAP registrant)"))
            .with_attr("asn", asn_str),
    );
    Some(oe)
}

/// The abuse / administrative / technical contact `Email`s of an autnum, each
/// tagged with its role, deduplicated by address, through the same gate every
/// registry contact passes: a role local-part (`abuse@`, `noc@`) or a
/// provider-domain address is infrastructure contact, never the subject's own
/// mail. **Pure.**
fn build_asn_contacts(
    contacts: &[RdapContact],
    asn_label: &str,
    asn_str: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (role, tag) in [
        ("abuse", "abuse"),
        ("administrative", "admin"),
        ("technical", "technical"),
    ] {
        let mut matches = Vec::new();
        contacts_with_role(contacts, role, &mut matches);
        for c in matches {
            let Some(vc) = c.vcard_array.as_ref() else {
                continue;
            };
            let Some(email) = crate::modules::whois::vcard_field(vc, "email") else {
                continue;
            };
            let email = email.trim().to_ascii_lowercase();
            if !crate::util::extract::looks_like_email(&email)
                || crate::util::domains::is_infrastructure_email(&email)
                || !seen.insert(email.clone())
            {
                continue;
            }
            let mut e = Entity::new(EntityKind::Email, &email, confidence::STRONG, scan_id);
            e.tag("asn-contact");
            e.tag(format!("role:{tag}"));
            e.add_evidence(
                Evidence::new(SRC, format!("RDAP {role} contact for {asn_label}"))
                    .with_attr("source", "rdap")
                    .with_attr("asn", asn_str)
                    .with_attr("contact_role", tag),
            );
            out.push(e);
        }
    }
    out
}
