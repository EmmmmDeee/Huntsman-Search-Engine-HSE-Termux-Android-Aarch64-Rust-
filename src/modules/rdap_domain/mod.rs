//! RDAP — Registration Data Access Protocol for domains. Free, no key.
//!
//! Endpoint: `https://rdap.org/domain/{domain}`
//!
//! Complements `whois` with structured registry data: status flags,
//! events (registration / expiration / last-changed), nameservers,
//! nameserver glue-record IP addresses, and contact roles. The rdap.org
//! redirector resolves the right
//! bootstrap registry for any TLD, so we don't need to maintain our
//! own bootstrap table.
//!
//! Per project invariants we surface contact role names (`registrant`,
//! `administrative`, etc.) but never raw contact PII (email/phone/postal).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;
use crate::util::str_util::slugify;

#[derive(Deserialize)]
struct RdapResp {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    status: Vec<String>,
    #[serde(default)]
    events: Vec<Event>,
    #[serde(default)]
    entities: Vec<EntityRef>,
    #[serde(default)]
    nameservers: Vec<Nameserver>,
    #[serde(default, rename = "secureDNS")]
    secure_dns: Option<SecureDns>,
}

#[derive(Deserialize)]
struct Event {
    #[serde(default, rename = "eventAction")]
    action: Option<String>,
    #[serde(default, rename = "eventDate")]
    date: Option<String>,
}

#[derive(Deserialize)]
struct EntityRef {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default, rename = "vcardArray")]
    vcard_array: Option<serde_json::Value>,
    #[serde(default, rename = "publicIds")]
    public_ids: Vec<PublicId>,
}

/// One RDAP `publicIds` entry. For the registrar entity this carries the
/// `{"type":"IANA Registrar ID","identifier":"1910"}` pair — the canonical,
/// numerically-stable registrar identifier (survives registrar rebrands), and
/// public registry data rather than contact PII.
#[derive(Deserialize)]
struct PublicId {
    #[serde(default, rename = "type")]
    id_type: Option<String>,
    #[serde(default)]
    identifier: Option<String>,
}

#[derive(Deserialize)]
struct IpAddresses {
    #[serde(default)]
    v4: Vec<String>,
    #[serde(default)]
    v6: Vec<String>,
}

#[derive(Deserialize)]
struct Nameserver {
    #[serde(default, rename = "ldhName")]
    name: Option<String>,
    #[serde(default, rename = "ipAddresses")]
    ip_addresses: Option<IpAddresses>,
}

#[derive(Deserialize)]
struct SecureDns {
    #[serde(default, rename = "delegationSigned")]
    delegation_signed: Option<bool>,
}

const SRC: &str = "rdap_domain";

/// One Domain entity per nameserver complements whois `whois-ns`. Cap at the
/// first 16; heavyweight TLDs / anycast registries can list many NS plus glue
/// records and we don't want one module call to fan out into hundreds.
const MAX_NS: usize = 16;

/// Extract the registrar's *public* identity from the RDAP `entities` list:
/// the organisation name (vCard `fn`) and the IANA Registrar ID (`publicIds`).
///
/// Returns `(registrar_name, iana_id)`, either side `None` when absent.
///
/// Both are public registry data — the registrar of record and its IANA number
/// — **not** contact PII, so surfacing them respects the module's no-PII
/// invariant. Extraction is gated strictly to the `registrar` role: a
/// registrar-role vCard `fn` is always a company name, whereas a
/// registrant/admin/tech vCard `fn` can be a natural person's name, which must
/// never be surfaced. Reuses the shared `whois::vcard_field` parser (one
/// definition, no drift). **Pure** (no network/IO).
fn registrar_identity(body: &RdapResp) -> (Option<String>, Option<String>) {
    let Some(reg) = body
        .entities
        .iter()
        .find(|e| e.roles.iter().any(|r| r == "registrar"))
    else {
        return (None, None);
    };
    let name = reg
        .vcard_array
        .as_ref()
        .and_then(|vc| crate::modules::whois::vcard_field(vc, "fn"))
        .map(|s| s.trim().to_string())
        .filter(|s| s.len() >= 3);
    let iana = reg
        .public_ids
        .iter()
        .find(|p| {
            p.id_type
                .as_deref()
                .is_some_and(|t| t.to_ascii_lowercase().contains("iana registrar"))
        })
        .and_then(|p| p.identifier.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    (name, iana)
}

/// Build a registrar `Organisation` entity from the RDAP record — the
/// registrar of record for the domain, a strong attribution/clustering pivot
/// (domains held by the same owner routinely share a registrar). Carries the
/// IANA Registrar ID as evidence when present. **Pure** (no network/IO);
/// returns `None` when no usable registrar name is available.
fn build_registrar_entity(
    domain: &str,
    name: &str,
    iana: Option<&str>,
    scan_id: &str,
) -> Option<Entity> {
    let name = name.trim();
    if name.len() < 3 {
        return None;
    }
    let mut oe = Entity::new(EntityKind::Organisation, name, 0.72, scan_id);
    oe.tag("rdap");
    oe.tag("registrar");
    let mut ev = Evidence::new(SRC, format!("Registrar of record for {domain}"));
    if let Some(id) = iana {
        ev = ev.with_attr("iana_registrar_id", id);
    }
    oe.add_evidence(ev);
    Some(oe)
}

/// Build the primary `Domain` entity from an RDAP record. **Pure** (no
/// network/IO): slugifies the status phrases into `status:` tags, groups event
/// dates by action into `event_<action>` attributes (RDAP can repeat an action,
/// e.g. successive `transfer` events), surfaces the deduplicated contact *role*
/// names (never raw PII), the registrar of record + its IANA ID, the DNSSEC
/// delegation state, and the nameserver list.
fn build_domain_entity(domain: &str, body: &RdapResp, scan_id: &str) -> Entity {
    use std::collections::{BTreeMap, BTreeSet};

    let mut entity = Entity::new(EntityKind::Domain, domain, 0.88, scan_id);
    entity.tag("rdap");
    let mut ev = Evidence::new(SRC, format!("RDAP record for {domain}"));

    if let Some(h) = body.handle.as_deref() {
        ev = ev.with_attr("handle", h);
    }
    if !body.status.is_empty() {
        ev = ev.with_attr("status", body.status.join(","));
        // RDAP status values are human phrases ("client transfer prohibited");
        // slugify so tags match the whitespace-free convention.
        body.status
            .iter()
            .for_each(|s| entity.tag(format!("status:{}", slugify(s))));
    }
    // RDAP commonly carries multiple events with the same action (e.g. two
    // `transfer` events from successive registrar moves). Group dates by action.
    let mut events_by_action: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for e in &body.events {
        if let (Some(action), Some(date)) = (e.action.as_deref(), e.date.as_deref()) {
            events_by_action.entry(action).or_default().push(date);
        }
    }
    for (action, dates) in events_by_action {
        // Slugify the action so attr keys stay whitespace-free (RDAP
        // eventAction values like "last changed" contain spaces).
        ev = ev.with_attr(format!("event_{}", slugify(action)), dates.join(","));
    }
    let roles: BTreeSet<&str> = body
        .entities
        .iter()
        .flat_map(|e| e.roles.iter().map(String::as_str))
        .collect();
    if !roles.is_empty() {
        ev = ev.with_attr(
            "contact_roles",
            roles
                .into_iter()
                .enumerate()
                .fold(String::new(), |mut acc, (i, s)| {
                    if i > 0 {
                        acc.push(',');
                    }
                    acc.push_str(s);
                    acc
                }),
        );
    }
    if let Some(sd) = &body.secure_dns
        && let Some(signed) = sd.delegation_signed
    {
        entity.tag(if signed {
            "dnssec:signed"
        } else {
            "dnssec:unsigned"
        });
        ev = ev.with_attr("dnssec_signed", signed.to_string());
    }
    // Registrar of record — public registry identity (never contact PII). The
    // IANA ID additionally becomes a `registrar-id:<n>` tag so the correlator
    // can cluster same-registrar domains without parsing evidence text.
    let (registrar_name, registrar_iana) = registrar_identity(body);
    if let Some(name) = &registrar_name {
        ev = ev.with_attr("registrar", name);
    }
    if let Some(iana) = &registrar_iana {
        ev = ev.with_attr("registrar_iana_id", iana);
        entity.tag(format!("registrar-id:{iana}"));
    }
    let ns_names: Vec<&str> = body
        .nameservers
        .iter()
        .filter_map(|n| n.name.as_deref())
        .collect();
    if !ns_names.is_empty() {
        ev = ev.with_attr("nameservers", ns_names.join(","));
    }
    entity.add_evidence(ev);
    entity
}

/// Build `IpAddress` entities from RDAP nameserver glue-record `ipAddresses`. **Pure** (no network/IO).
fn build_ns_ip_entities(domain: &str, ns: &Nameserver, scan_id: &str) -> Vec<Entity> {
    let Some(ips) = &ns.ip_addresses else {
        return Vec::new();
    };
    let ns_name = ns.name.as_deref().unwrap_or(domain);
    ips.v4
        .iter()
        .chain(ips.v6.iter())
        .filter(|ip| !ip.trim().is_empty())
        .filter_map(|ip| {
            let addr: std::net::IpAddr = ip.trim().parse().ok()?;
            let mut e = Entity::new(EntityKind::IpAddress, addr.to_string(), 0.80, scan_id);
            e.tag("rdap-ns-glue");
            e.add_evidence(
                Evidence::new(SRC, format!("RDAP nameserver glue for {domain}"))
                    .with_attr("nameserver", ns_name),
            );
            Some(e)
        })
        .collect()
}

/// Build a `Domain` entity for one RDAP nameserver. **Pure** (no network/IO).
/// `Entity::new` normalises the domain (trim, lowercase, strip trailing dot), so
/// we only reject a blank/whitespace name here. Returns `None` for a blank name.
fn build_ns_entity(domain: &str, name: &str, scan_id: &str) -> Option<Entity> {
    if name.trim().is_empty() {
        return None;
    }
    let mut ns = Entity::new(EntityKind::Domain, name, 0.80, scan_id);
    ns.tag("rdap-ns");
    ns.tag("ns");
    ns.add_evidence(
        Evidence::new(SRC, format!("RDAP nameserver for {domain}")).with_attr("parent", domain),
    );
    Some(ns)
}

/// The registrable domain (eTLD+1) to query RDAP with, derived from a Domain or
/// Url target. Returns `None` when the value yields no usable host (empty, or a
/// URL with no host).
///
/// RDAP only resolves *registered* domains, not arbitrary hostnames:
/// `rdap.org/domain/www.peekyou.com` errors/404s where `peekyou.com` succeeds.
/// Reducing any subdomain (`www.`, `m.`, a host pulled from a URL) to its
/// registrable base keeps a `www.`-prefixed Domain entity from wasting the
/// lookup on a guaranteed 404. **Pure.**
fn query_domain(target: &Target) -> Option<String> {
    let host = match target.kind {
        TargetKind::Url => crate::util::url_util::host_from_url(&target.value)?,
        _ => target.value.trim().to_string(),
    };
    if host.is_empty() {
        return None;
    }
    Some(crate::util::domains::registrable_domain(&host).unwrap_or(host))
}

pub struct RdapDomain;

#[async_trait]
impl Module for RdapDomain {
    fn name(&self) -> &'static str {
        "rdap_domain"
    }

    fn description(&self) -> &'static str {
        "RDAP registry recon — pulls a domain's authoritative registration record from registry data"
    }

    fn priority(&self) -> u8 {
        // One step below whois (32) so whois — the canonical record
        // holder — runs first; rdap fills structured gaps after.
        // (Engine sorts highest-priority-first.)
        31
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn max_timeout_ms(&self) -> u64 {
        // RDAP servers (IANA bootstrap + registrar endpoints) respond within
        // 4-6 s on healthy paths; 8 s provides margin and cuts the ceiling
        // from 15 s, freeing concurrency slots faster.
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // RDAP registration data — ATT&CK WHOIS (T1596.002).
        &["T1596.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::IpAddress,
            EntityKind::Organisation,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(domain) = query_domain(target) else {
            return Ok(ModuleResult::new());
        };
        let domain = domain.as_str();

        // urlencode the path segment defensively: TargetKind::Domain
        // values are already DNS-label-shape per validation, but
        // encoding makes us robust to upstream changes and consistent
        // with the rest of the module set.
        let url = format!("https://rdap.org/domain/{}", urlencode(domain));
        // ctx.http carries a 3 s default timeout (MODULE_TIMEOUT_MS),
        // shorter than this module's declared 15 s budget; an explicit
        // per-request timeout matches the budget we publish.
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/rdap+json")
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
            .send_tagged(SRC)
            .await?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(crate::util::http::http_status_error(SRC, resp).await);
        }

        let body: RdapResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut result = ModuleResult::new();
        result.push(build_domain_entity(domain, &body, &ctx.scan_id));

        // Registrar of record → Organisation entity (parity with the `whois`
        // module, which already emits this). A domain scan previously kept only
        // the registrar *role* name ("registrar") but dropped WHICH registrar —
        // losing a high-value attribution pivot the API hands over for free.
        let (registrar_name, registrar_iana) = registrar_identity(&body);
        if let Some(name) = &registrar_name
            && let Some(oe) =
                build_registrar_entity(domain, name, registrar_iana.as_deref(), &ctx.scan_id)
        {
            result.push(oe);
        }

        result.extend(
            body.nameservers
                .iter()
                .take(MAX_NS)
                .filter_map(|n| build_ns_entity(domain, n.name.as_deref()?, &ctx.scan_id)),
        );
        result.extend(
            body.nameservers
                .iter()
                .take(MAX_NS)
                .flat_map(|n| build_ns_ip_entities(domain, n, &ctx.scan_id)),
        );

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
