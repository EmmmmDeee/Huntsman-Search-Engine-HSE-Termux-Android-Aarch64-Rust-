//! auDA RDAP — structured, keyless registration data for **.au domains**.
//!
//! Ported from the sibling `Huntsman-` repository during consolidation. The
//! parsing judgement — which `auData_eligibility` fields become which entity
//! kind, the registrar/abuse-contact vCard extraction, and the confidence
//! calibration — is the part worth carrying over verbatim; the trait wrapper
//! is rewritten against this crate's `Module` contract (`accepts`/`process`/
//! `produces`), which the source repository's simpler `is_enabled`/`execute`
//! shape has no equivalent of.
//!
//! Since 2019 auDA (the .au registry) publishes RDAP (RFC 9083 — the modern,
//! JSON, IETF-standard replacement for free-text WHOIS) at
//! `https://rdap.cctld.au/rdap/domain/{name}`, no key or rate-limit account
//! required. Unlike generic gTLD RDAP, which redacts registrant identity
//! behind GDPR-style privacy, .au's registrant *eligibility* rules require the
//! registry to disclose WHO qualifies a domain for registration — that
//! disclosure lands in the `auData_eligibility` extension, so this is one of
//! the few registries where the registrant organisation/trademark holder is
//! visible without a key. This module is intentionally .au-scoped: it
//! short-circuits on any other TLD rather than issuing a wasted
//! (and always-404) request. It complements, rather than duplicates,
//! `rdap_domain` (generic RDAP via the `rdap.org` bootstrap redirector):
//! `rdap_domain` never sees `auData_eligibility` because it queries a
//! different (non-.au-specific) endpoint.
//!
//! Endpoint verified live in the source repository: `GET
//! https://rdap.cctld.au/rdap/domain/google.com.au` → 200 with
//! `auData_eligibility`, `nameservers`, `entities` (registrar + nested abuse
//! contact, as vCard); an unregistered .au domain → 404 (routed through the
//! shared `fetch_json_or_404` "no data" path).
//!
//! # Deliberate deviations from the source module (disclosed, not silent)
//!
//! * **ABN recognition is upgraded from a length check to a checksum
//!   validation.** The source treated any 11-digit `eligibility id` as an ABN;
//!   this crate already ships [`crate::util::abn::is_valid_abn`] (the ATO
//!   mod-89 checksum), which every other AU module here uses to recognise an
//!   ABN, so an 11-digit-but-checksum-invalid value now falls through to the
//!   generic eligibility-metadata entity instead of minting a bogus `AbnAcn`.
//! * **The query domain is reduced to its registrable form (eTLD+1)** via
//!   [`crate::util::domains::registrable_domain`] before the TLD check and the
//!   request, exactly as the sibling `rdap_domain` module does and for the
//!   same reason: a `shop.example.com.au` target would otherwise 404 against
//!   this endpoint, which only resolves registered domains. The source module
//!   queried the raw target value verbatim.
//! * **Nameservers are capped** at [`MAX_NAMESERVERS`], matching the
//!   discipline `rdap_domain::MAX_NS` already applies for the same registry
//!   fan-out reason. The source module had no cap.
//!
//! # A quirk preserved, not fixed
//!
//! The registrar/abuse-contact walk below requires the *outer* RDAP entity to
//! carry its own `vcardArray` before its nested `entities` (where an "abuse"
//! contact lives) are even inspected — see the comment at the loop. This is
//! how the source module was written; nothing in its comments suggests it was
//! deliberate rather than an oversight, but per the porting brief this port
//! preserves the source's actual behaviour rather than silently changing it.
//! Flagged here and in `self_check_notes` for the integration pass to judge.

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "au_rdap";

/// `EntityKind::Other` discriminant for an auDA eligibility disclosure field
/// that is not a recognised ABN — `eligibility type`/`eligibility name`, or an
/// `eligibility id` that fails the ABN checksum (e.g. a trademark number).
/// Owns a `String`, so (like `plc_directory`'s `DID_KIND`/`ROTATION_KEY_KIND`)
/// it cannot appear in the `const` slice `produces()` returns.
const ELIGIBILITY_KIND: &str = "au_eligibility";

/// Cap on nameserver `Domain` entities emitted per lookup. Matches
/// `rdap_domain::MAX_NS`'s discipline: a real `.au` domain has a handful, but
/// nothing here bounds a pathological/anycast registry response otherwise.
const MAX_NAMESERVERS: usize = 16;

#[derive(Debug, Deserialize, Default)]
struct RdapEligibilityItem {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RdapNameserver {
    #[serde(default, rename = "ldhName")]
    ldh_name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RdapEntity {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default, rename = "vcardArray")]
    vcard_array: Option<Value>,
    /// Nested entities — e.g. the registrar's "abuse" contact is a child of
    /// the "registrar" entity.
    #[serde(default)]
    entities: Vec<RdapEntity>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RdapResponse {
    #[serde(default)]
    entities: Vec<RdapEntity>,
    #[serde(default)]
    nameservers: Vec<RdapNameserver>,
    #[serde(default, rename = "auData_eligibility")]
    au_data_eligibility: Vec<RdapEligibilityItem>,
}

/// Append `e` to `out` unless an entity with the same identity (`uid` — hash
/// of kind + normalised value) has already been emitted this call. Mirrors
/// the source module's `common::push_deduped`, keyed on the engine's own
/// identity derivation rather than a hand-rolled `(kind, value)` pair.
fn push_unique(out: &mut Vec<Entity>, seen: &mut HashSet<String>, e: Entity) {
    if seen.insert(e.uid.clone()) {
        out.push(e);
    }
}

/// Pure projection of an auDA RDAP response into engine entities. Unit
/// testable with no network. `domain` is the queried domain, folded into
/// evidence text for auditability; it plays no role in entity identity.
pub(super) fn build_entities(resp: &RdapResponse, domain: &str, scan_id: &str) -> Vec<Entity> {
    let mut out: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // auData_eligibility: the disclosure that makes .au RDAP unusual — see the
    // module doc. Each item is a free-form (name, value) pair; only the three
    // names the registry actually emits are recognised, everything else is
    // ignored rather than guessed at.
    for item in &resp.au_data_eligibility {
        let (Some(name), Some(value)) = (item.name.as_deref(), item.value.as_deref()) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match name.to_ascii_lowercase().as_str() {
            "registrant name" => {
                let mut e = Entity::new(
                    EntityKind::Organisation,
                    value,
                    confidence::HIGH_PLUSPLUS,
                    scan_id,
                );
                e.tag("au_rdap");
                e.tag("registrant");
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("auDA-disclosed registrant of {domain}: {value}"),
                    )
                    .with_attr("eligibility_field", "registrant name"),
                );
                push_unique(&mut out, &mut seen, e);
            }
            "eligibility id" => {
                if crate::util::abn::is_valid_abn(value) {
                    let digits = crate::util::str_util::ascii_digits(value);
                    let mut e =
                        Entity::new(EntityKind::AbnAcn, &digits, confidence::VERY_HIGH, scan_id);
                    e.tag("au_rdap");
                    e.tag("abn");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("ABN disclosed via auDA eligibility for {domain}"),
                        )
                        .with_attr("eligibility_field", "eligibility id"),
                    );
                    push_unique(&mut out, &mut seen, e);
                } else {
                    // Not a checksum-valid ABN — still real registry data (most
                    // often a trademark number), so it is surfaced as a
                    // catch-all `Other` node rather than silently dropped.
                    let mut e = Entity::new(
                        EntityKind::Other(ELIGIBILITY_KIND.to_string()),
                        value,
                        confidence::MEDIUM_HIGH,
                        scan_id,
                    );
                    e.tag("au_rdap");
                    e.tag("eligibility");
                    e.add_evidence(
                        Evidence::new(SRC, format!("auDA eligibility id for {domain}: {value}"))
                            .with_attr("eligibility_field", "eligibility id"),
                    );
                    push_unique(&mut out, &mut seen, e);
                }
            }
            "eligibility type" | "eligibility name" => {
                let field = name.to_ascii_lowercase();
                let mut e = Entity::new(
                    EntityKind::Other(ELIGIBILITY_KIND.to_string()),
                    value,
                    confidence::MEDIUM_HIGH,
                    scan_id,
                );
                e.tag("au_rdap");
                e.tag("eligibility");
                e.add_evidence(
                    Evidence::new(SRC, format!("auDA {field} for {domain}: {value}"))
                        .with_attr("eligibility_field", &field),
                );
                push_unique(&mut out, &mut seen, e);
            }
            _ => {}
        }
    }

    // Registrar identity + its nested abuse contact.
    //
    // QUIRK PRESERVED FROM THE SOURCE (see module docs): the `let Some(vcard)
    // = &entity.vcard_array else { continue };` below skips the WHOLE outer
    // entity — including its `entities` children — whenever the entity itself
    // carries no vCard, even if a nested "abuse" child has its own vCard. A
    // registrar entity with no vCard of its own but a vCard-bearing abuse
    // child would therefore contribute nothing here, exactly as in the source.
    for entity in &resp.entities {
        let Some(vcard) = &entity.vcard_array else {
            continue;
        };
        // Both the Organisation below AND the nested abuse-contact loop are
        // scoped to a CONFIRMED registrar-role entity — an RDAP response can
        // list several top-level entities with other roles (technical,
        // administrative, billing, reseller, noc, ...), and this loop's own
        // nested-child search used to run for any of them that happened to
        // carry a vCard, regardless of role. An abuse email nested under a
        // non-registrar entity was then emitted with evidence text
        // unconditionally asserting "Registrar abuse contact for {domain}" —
        // a role never actually checked.
        if !entity.roles.iter().any(|r| r == "registrar") {
            continue;
        }
        if let Some(org) = crate::modules::whois::vcard_field(vcard, "fn") {
            let mut e = Entity::new(
                EntityKind::Organisation,
                &org,
                confidence::HIGH_PLUS,
                scan_id,
            );
            e.tag("au_rdap");
            e.tag("registrar");
            e.add_evidence(Evidence::new(
                SRC,
                format!("Registrar of record for {domain}: {org}"),
            ));
            push_unique(&mut out, &mut seen, e);
        }

        for child in &entity.entities {
            if !child.roles.iter().any(|r| r == "abuse") {
                continue;
            }
            let Some(child_vcard) = &child.vcard_array else {
                continue;
            };
            // The abuse desk is the registrar's own automation mailbox, not
            // the subject's — emitting it as a plain, un-gated Email entity
            // is the same leakage class #351 removed from cert_intel/crtsh/
            // ip_registry/doh_resolver (and this file's own sibling
            // `whois::find_ip_entity` already gates the identical RIR-abuse
            // shape). Several real AU registrar domains are even already in
            // `is_infrastructure_email`'s own tables (INFRA_PROVIDER_ROOTS + INFRA_MAIL_ONLY).
            if let Some(email) = crate::modules::whois::vcard_field(child_vcard, "email")
                && !crate::util::domains::is_infrastructure_email(&email)
            {
                let mut e = Entity::new(EntityKind::Email, &email, confidence::HIGH, scan_id);
                e.tag("au_rdap");
                e.tag("abuse-contact");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Registrar abuse contact for {domain}"),
                ));
                push_unique(&mut out, &mut seen, e);
            }
        }
    }

    // Nameservers — a direct, authoritative registry fact.
    for ns in resp.nameservers.iter().take(MAX_NAMESERVERS) {
        let Some(name) = ns.ldh_name.as_deref() else {
            continue;
        };
        if name.trim().is_empty() {
            continue;
        }
        let mut e = Entity::new(EntityKind::Domain, name, confidence::VERY_HIGH, scan_id);
        e.tag("au_rdap");
        e.tag("nameserver");
        e.add_evidence(Evidence::new(SRC, format!("Nameserver for {domain}")));
        push_unique(&mut out, &mut seen, e);
    }

    out
}

/// The registrable domain (eTLD+1) to query auDA RDAP with. `TargetKind::Domain`
/// values can carry a subdomain (`shop.example.com.au`); RDAP only resolves the
/// registered name, so reducing first avoids a guaranteed 404 — the same
/// reasoning `rdap_domain::query_domain` applies. **Pure.**
fn query_domain(target: &Target) -> Option<String> {
    let raw = target.value.trim();
    if raw.is_empty() {
        return None;
    }
    Some(crate::util::domains::registrable_domain(raw).unwrap_or_else(|| raw.to_string()))
}

/// auDA RDAP domain registration lookup — see the module docs for the
/// `auData_eligibility` disclosure this module exists to surface, and the
/// deliberate deviations from the ported source.
pub struct AuRdap;

#[async_trait]
impl Module for AuRdap {
    fn name(&self) -> &'static str {
        "au_rdap"
    }

    fn description(&self) -> &'static str {
        "auDA RDAP recon (.au domains, keyless) — the registrant identity .au eligibility rules require the registry to disclose, plus registrar, abuse contact, and nameservers"
    }

    fn priority(&self) -> u8 {
        // One above `whois` (32) and `rdap_domain` (31), the two other
        // domain-registration-record modules: for a .au domain this source
        // discloses registrant identity via `auData_eligibility` that neither
        // generic module can see (they never reach auDA's own endpoint), so it
        // is worth dispatching first when it applies. Free/keyless, so it sits
        // in the DnsRecon free band rather than the KeyGated AU government
        // band (110-118) `abn_lookup`/`acnc_charities` occupy.
        33
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // RDAP registration data — ATT&CK WHOIS (T1596.002), same as the
        // sibling `rdap_domain` module.
        &["T1596.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Also emits `Other("au_eligibility")` for non-ABN eligibility
        // disclosures, which cannot appear in a `const` slice (it owns a
        // `String`) — see `ELIGIBILITY_KIND`.
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Email,
            EntityKind::Domain,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // One request against a single well-known RDAP host. Matches
        // `rdap_domain`'s budget and reasoning: healthy RDAP responses land in
        // 4-6 s, 8 s leaves margin without holding a concurrency slot long.
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(domain) = query_domain(target) else {
            return Ok(ModuleResult::new());
        };

        // .au-scoped: any other TLD 404s against this registry's RDAP server,
        // so skip the wasted request rather than let it silently contribute
        // nothing (matches the source module's short-circuit).
        if !domain.to_ascii_lowercase().ends_with(".au") {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://rdap.cctld.au/rdap/domain/{}", urlencode(&domain));
        let data: Option<RdapResponse> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let Some(data) = data else {
            // 404 = domain not registered (or not found) — the common case,
            // not an error.
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(&data, &domain, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
