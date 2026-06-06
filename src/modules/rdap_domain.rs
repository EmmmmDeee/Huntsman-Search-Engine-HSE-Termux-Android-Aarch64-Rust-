//! RDAP — Registration Data Access Protocol for domains. Free, no key.
//!
//! Endpoint: `https://rdap.org/domain/{domain}`
//!
//! Complements `whois` with structured registry data: status flags,
//! events (registration / expiration / last-changed), nameservers,
//! and contact roles. The rdap.org redirector resolves the right
//! bootstrap registry for any TLD, so we don't need to maintain our
//! own bootstrap table.
//!
//! Per project invariants we surface contact role names (`registrant`,
//! `administrative`, etc.) but never raw contact PII (email/phone/postal).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, urlencode};

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
}

#[derive(Deserialize)]
struct Nameserver {
    #[serde(default, rename = "ldhName")]
    name: Option<String>,
}

#[derive(Deserialize)]
struct SecureDns {
    #[serde(default, rename = "delegationSigned")]
    delegation_signed: Option<bool>,
}

/// Replace each run of ASCII whitespace with a single `-` so RDAP's
/// human-readable status phrases ("client transfer prohibited") fit
/// the project's whitespace-free tag convention.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for ch in s.chars() {
        if ch.is_ascii_whitespace() {
            if !prev_dash {
                out.push('-');
                prev_dash = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        }
    }
    out
}

const SRC: &str = "rdap_domain";

/// One Domain entity per nameserver complements whois `whois-ns`. Cap at the
/// first 16; heavyweight TLDs / anycast registries can list many NS plus glue
/// records and we don't want one module call to fan out into hundreds.
const MAX_NS: usize = 16;

/// Build the primary `Domain` entity from an RDAP record. **Pure** (no
/// network/IO): slugifies the status phrases into `status:` tags, groups event
/// dates by action into `event_<action>` attributes (RDAP can repeat an action,
/// e.g. successive `transfer` events), surfaces the deduplicated contact *role*
/// names (never raw PII), the DNSSEC delegation state, and the nameserver list.
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
        for s in &body.status {
            // RDAP status values are human phrases ("client transfer
            // prohibited"); slugify so tags match the whitespace-free convention.
            entity.tag(format!("status:{}", slugify(s)));
        }
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
            roles.into_iter().collect::<Vec<_>>().join(","),
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

pub struct RdapDomain;

#[async_trait]
impl Module for RdapDomain {
    fn name(&self) -> &'static str {
        "rdap_domain"
    }

    fn description(&self) -> &'static str {
        "RDAP registry record lookup for domain registration data"
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
        15_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = match target.kind {
            TargetKind::Url => match crate::util::url_util::host_from_url(&target.value) {
                Some(h) => h,
                None => return Ok(ModuleResult::new()),
            },
            _ => target.value.trim().to_string(),
        };
        let domain = domain.as_str();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

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
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: RdapResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let mut result = ModuleResult::new();
        result.push(build_domain_entity(domain, &body, &ctx.scan_id));

        for n in body.nameservers.iter().take(MAX_NS) {
            let Some(name) = n.name.as_deref() else {
                continue;
            };
            if let Some(ns) = build_ns_entity(domain, name, &ctx.scan_id) {
                result.push(ns);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_domain() {
        let m = RdapDomain;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn priority_runs_after_whois() {
        // Whois (priority 32) is the canonical record holder; rdap fills
        // structured gaps after. Engine sorts highest-first.
        assert!(RdapDomain.priority() < 32);
    }

    #[test]
    fn slugify_collapses_whitespace_and_lowercases() {
        assert_eq!(
            slugify("client transfer prohibited"),
            "client-transfer-prohibited"
        );
        assert_eq!(slugify("Active"), "active");
        assert_eq!(slugify("a  b   c"), "a-b-c");
        assert_eq!(slugify("no-spaces"), "no-spaces");
        assert_eq!(slugify(""), "");
    }

    fn resp(json: &str) -> RdapResp {
        serde_json::from_str(json).unwrap()
    }

    fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn domain_entity_slugs_status_groups_events_and_surfaces_roles() {
        let body = resp(
            r#"{
              "handle":"D-123",
              "status":["client transfer prohibited","active"],
              "events":[
                {"eventAction":"registration","eventDate":"1997-09-15"},
                {"eventAction":"transfer","eventDate":"2005-01-01"},
                {"eventAction":"transfer","eventDate":"2019-03-03"},
                {"eventAction":"last changed","eventDate":"2024-08-01"}
              ],
              "entities":[{"roles":["registrant","technical"]},{"roles":["registrant"]}],
              "nameservers":[{"ldhName":"ns1.example.com"},{"ldhName":"ns2.example.com"}],
              "secureDNS":{"delegationSigned":true}
            }"#,
        );
        let e = build_domain_entity("example.com", &body, "s");
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("rdap"));
        // Status phrases slugified into tags.
        assert!(e.has_tag("status:client-transfer-prohibited") && e.has_tag("status:active"));
        assert_eq!(attr(&e, "handle"), Some("D-123"));
        // Repeated `transfer` action → both dates grouped under one attr.
        assert_eq!(attr(&e, "event_transfer"), Some("2005-01-01,2019-03-03"));
        assert_eq!(attr(&e, "event_registration"), Some("1997-09-15"));
        // Slugified multi-word action key.
        assert_eq!(attr(&e, "event_last-changed"), Some("2024-08-01"));
        // Roles deduplicated + sorted; raw PII never present.
        assert_eq!(attr(&e, "contact_roles"), Some("registrant,technical"));
        // DNSSEC.
        assert!(e.has_tag("dnssec:signed"));
        assert_eq!(attr(&e, "dnssec_signed"), Some("true"));
        assert_eq!(
            attr(&e, "nameservers"),
            Some("ns1.example.com,ns2.example.com")
        );
    }

    #[test]
    fn unsigned_dnssec_and_empty_record_degrade_cleanly() {
        let signed = build_domain_entity(
            "x.com",
            &resp(r#"{"secureDNS":{"delegationSigned":false}}"#),
            "s",
        );
        assert!(signed.has_tag("dnssec:unsigned"));

        // Bare record: only the base tag + summary, every optional attr omitted.
        let bare = build_domain_entity("x.com", &resp("{}"), "s");
        assert!(bare.has_tag("rdap"));
        assert_eq!(attr(&bare, "handle"), None);
        assert_eq!(attr(&bare, "status"), None);
        assert_eq!(attr(&bare, "contact_roles"), None);
        assert_eq!(attr(&bare, "nameservers"), None);
    }

    #[test]
    fn ns_entity_tags_and_rejects_blank() {
        let ns = build_ns_entity("example.com", "NS1.Example.COM.", "s").unwrap();
        assert_eq!(ns.kind, EntityKind::Domain);
        // Entity::new normalises domains (lowercase, strip trailing dot).
        assert_eq!(ns.value, "ns1.example.com");
        assert!(ns.has_tag("rdap-ns") && ns.has_tag("ns"));
        assert_eq!(attr(&ns, "parent"), Some("example.com"));
        // Blank / whitespace name → no entity.
        assert!(build_ns_entity("example.com", "   ", "s").is_none());
    }
}
