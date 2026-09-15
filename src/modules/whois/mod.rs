//! Raw whois protocol (TCP port 43). Free, no key, no root.
//!
//! Most TLDs delegate via referral — we ask IANA which server is
//! authoritative, follow that one hop, then parse the authoritative answer
//! for registrar / dates / registrant contacts (domains) or the allocation's
//! operator / country / abuse contact (addresses). The parser is line-prefix
//! based, robust across the half-dozen mostly-but-not-quite-RFC-3912 dialects
//! in the wild.
//!
//! ## What is — and is not — evidence about the target
//!
//! IANA's bootstrap answer describes the **TLD** (`domain: COM`, `created:
//! 1985-01-01`, the thirteen `nserver:` gTLD servers, `status: ACTIVE`) or the
//! **/8** an address sits in (`inetnum: 8.0.0.0 - 8.255.255.255`, `status:
//! LEGACY`) — never the target. It is consumed for exactly one thing, the
//! referral (`refer:` / `whois:`), and never reaches the parser. This module
//! used to fall back to parsing it whenever the referral hop failed (a
//! timeout, a refused connection, an unresolvable host) or whenever IANA
//! listed no WHOIS server at all (`.vn`'s registry publishes none): every
//! `.vn` domain, and any domain whose registry was momentarily unreachable,
//! came back "registered 1985-01-01 / 1994-04-14, status ACTIVE" with the
//! TLD's root servers minted as `whois-ns` Domain entities at CORROBORATED
//! confidence — fabricated registration data at HIGH_PLUSPLUS_PLUS, fed to the
//! timeline as a `Registered` event and to the expansion loop as pivots.
//!
//! Now each outcome is reported as what it is:
//! * the authoritative server did not answer / could not be resolved →
//!   `Error::Module` — the registry did not say "no record", it said nothing
//!   (a coverage `Failed`, not a clean negative);
//! * IANA lists no WHOIS server for the registry → a typed
//!   [`SkipClass::NotApplicable`] skip (`Error::skipped`) — port-43 WHOIS
//!   structurally cannot speak about that namespace; `rdap_domain` is the
//!   registry-data path;
//! * the registry refused the query for load (`WHOIS LIMIT EXCEEDED`, DENIC's
//!   `access control limit reached`) → `Error::RateLimited`;
//! * the registry answered with a record → entities;
//! * the registry answered "no match" → an empty result, the one genuine
//!   clean negative.
//!
//! ## Address (RIR) records
//!
//! An RIR answers an address query with an allocation record, not a domain
//! record: `NetRange`/`NetName`/`OrgName`/`Country`/`OrgAbuseEmail` at ARIN,
//! `inetnum`/`netname`/`org-name`/`country`/`abuse-mailbox` in RPSL
//! (RIPE/APNIC/AFRINIC), `inetnum`/`owner` at LACNIC. These are judged on
//! their own signals: the previous domain-only "actionable data" gate
//! (registrar/created/nameservers/status) read every ARIN allocation — all
//! of North America — as "no data", while the HTTPS RDAP fallback for the
//! same address yielded the operator, country and abuse contact. ARIN also
//! returns every enclosing allocation, least specific first, so the parse is
//! anchored on the MOST specific block (`parse::most_specific_network_record`)
//! rather than attributing the parent carrier's operator to the address. An
//! RPSL `org:` line is an organisation HANDLE (`ORG-RIEN1-RIPE`), never a
//! name — the name is `org-name:` — and the `person:`/`role:` objects an RIR
//! returns are the network's technical contacts, never the subject, so an
//! address record mints no Person entity.
//!
//! ## Proxy-environment fallback
//!
//! TCP port 43 is not routable through an HTTPS proxy. When `HTTPS_PROXY` or
//! `https_proxy` is set the module detects this at dispatch time:
//! - **Domain targets** — skip cleanly; `rdap_domain` covers RDAP over HTTPS.
//! - **IP targets** — fall back to `https://rdap.org/ip/{addr}` which routes to
//!   the authoritative RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC) and returns the
//!   same org / country / abuse-contact data that TCP WHOIS would have provided.

mod client;
mod parse;

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    event::SkipClass,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

use client::{Transport, find_referral};
use parse::{WhoisFields, field, parse_whois};

const SRC: &str = "whois";
const IANA_WHOIS: &str = "whois.iana.org:43";
pub(super) const QUERY_TIMEOUT_MS: u64 = 4000;

// ── Proxy-environment detection ────────────────────────────────────────────

/// True when the process is running behind an HTTPS proxy. In that environment
/// TCP port 43 (raw WHOIS) is not reachable, so domain targets skip and IP
/// targets fall back to RDAP-over-HTTPS.
fn behind_proxy() -> bool {
    std::env::var_os("HTTPS_PROXY").is_some() || std::env::var_os("https_proxy").is_some()
}

// ── RDAP-over-HTTPS fallback for IP targets ────────────────────────────────

#[derive(Deserialize)]
struct RdapIpResp {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    entities: Vec<RdapIpEntity>,
}

#[derive(Deserialize)]
struct RdapIpEntity {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default, rename = "vcardArray")]
    vcard_array: Option<serde_json::Value>,
    #[serde(default)]
    entities: Vec<RdapIpEntity>,
}

/// Extract the value of a named vCard property from a `vcardArray` JSON value.
/// `vcardArray = ["vcard", [[name, params, type, value], ...]]`
pub(crate) fn vcard_field(vcard: &serde_json::Value, prop: &str) -> Option<String> {
    let items = vcard.as_array()?.get(1)?.as_array()?;
    items.iter().find_map(|item| {
        let arr = item.as_array()?;
        (arr.first()?.as_str()? == prop).then(|| arr.get(3)?.as_str().map(str::to_string))?
    })
}

/// The real registrant-location parts (state, then country) for the Address
/// geo-hint — each dropped if it is empty or a whois privacy-proxy placeholder.
/// Uses the SAME single-sourced [`crate::core::validation::is_whois_privacy_placeholder`]
/// guard the registrant name/org paths apply, rather than a narrow inline
/// `redacted`/`privacy` substring check that let masked values like "Data
/// Protected", "Withheld", or ".au statutory masking" through as a fake Address.
/// **Pure** — unit-tested directly.
pub(super) fn registrant_location_parts<'a>(
    state: Option<&'a str>,
    country: &'a str,
) -> Vec<&'a str> {
    [state, Some(country)]
        .into_iter()
        .flatten()
        .filter(|p| !p.is_empty() && !crate::core::validation::is_whois_privacy_placeholder(p))
        .collect()
}

/// True when a WHOIS contact email is usable as a standalone `Email` pivot —
/// neither an infrastructure/role mailbox (`abuse@`, `dns@`, `hostmaster@`,
/// or one on a CDN/registrar/cloud provider's own domain, e.g.
/// `abuse@cloudflare.com`) nor a dedicated privacy-proxy forwarding address
/// (WhoisGuard, Domains By Proxy, PrivacyProtect, Withheld for Privacy, ...)
/// a registrar stamps into the contact fields when GDPR/privacy protection
/// is on but the registry still emits a real (non-placeholder-TEXT) address.
/// Either is the registrar/provider's desk, never the subject — emitting one
/// as a `confidence::STRONG` Email entity made it a breach-checked,
/// identity-clustered, expandable target (a real scan merged
/// `dns@cloudflare.com`/`abuse@cloudflare.com` into the subject's identity).
/// The address is still preserved in the parent domain's evidence attrs; it
/// just must not become standalone PII. **Pure** — unit-tested directly.
pub(super) fn is_usable_contact_email(addr: &str) -> bool {
    !crate::util::domains::is_infrastructure_email(addr)
        && !crate::core::validation::is_whois_privacy_placeholder(addr)
}

/// Walk `entities` recursively, returning the first one whose `roles` list
/// contains `role`.
fn find_ip_entity<'a>(entities: &'a [RdapIpEntity], role: &str) -> Option<&'a RdapIpEntity> {
    for e in entities {
        if e.roles.iter().any(|r| r == role) {
            return Some(e);
        }
        if let Some(found) = find_ip_entity(&e.entities, role) {
            return Some(found);
        }
    }
    None
}

/// Registrant org name from the RDAP contact tree: vCard `fn`, falling back
/// to vCard `org` — mirrors `ip_registry::build_registrant_org`'s exact
/// chain over the identical RDAP shape, so the two RDAP-consuming modules
/// can't drift back apart. Gated on vCard `kind`: IP blocks are allocated to
/// network operators, but a rare `individual`-kind registrant is a natural
/// person, and their name must never surface as an Organisation. **Pure** —
/// unit-tested directly.
fn registrant_org_name(entities: &[RdapIpEntity]) -> Option<String> {
    let vc = find_ip_entity(entities, "registrant")?
        .vcard_array
        .as_ref()?;
    if vcard_field(vc, "kind").is_some_and(|k| k.eq_ignore_ascii_case("individual")) {
        return None;
    }
    vcard_field(vc, "fn")
        .or_else(|| vcard_field(vc, "org"))
        .filter(|s| !s.is_empty())
}

/// RDAP-over-HTTPS fallback for IP targets when TCP/43 is unavailable.
///
/// `https://rdap.org/ip/{ip}` bootstraps to the authoritative RIR (ARIN /
/// RIPE / APNIC / LACNIC / AFRINIC) and returns the same org / country /
/// abuse-contact data that raw WHOIS would have provided.
async fn rdap_ip_fallback(ip: &str, ctx: &ModuleContext) -> Result<ModuleResult> {
    let url = format!("https://rdap.org/ip/{}", crate::util::http::urlencode(ip));
    let resp = ctx
        .http
        .get(&url)
        .header("Accept", "application/rdap+json")
        .timeout(std::time::Duration::from_secs(10))
        .send_tagged(SRC)
        .await?;

    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(ModuleResult::new());
    }
    if !status.is_success() {
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }

    let body: RdapIpResp = crate::util::http::json_decode(SRC, resp).await?;

    let mut result = ModuleResult::new();
    let net_name = body.name.as_deref().unwrap_or("").trim().to_string();
    let country = body.country.as_deref().unwrap_or("").trim().to_string();

    let org_name = registrant_org_name(&body.entities);

    if let Some(org) = &org_name {
        let org = org.trim();
        if org.len() >= 3 {
            let mut ev = Evidence::new(SRC, format!("RDAP network registrant for {ip}"))
                .with_attr("source", "rdap-fallback")
                .with_attr("ip", ip);
            if !net_name.is_empty() {
                ev = ev.with_attr("net_name", net_name.as_str());
            }
            if !country.is_empty() {
                ev = ev.with_attr("country", country.as_str());
            }
            let mut oe = Entity::new(
                EntityKind::Organisation,
                org,
                confidence::ATTRIBUTED,
                &ctx.scan_id,
            );
            oe.tag("whois");
            oe.tag("rdap-fallback");
            oe.tag("ip-registrant");
            oe.add_evidence(ev);
            result.push(oe);
        }
    }

    // A CDN/anycast edge IP's RDAP network-block registration describes the
    // PROVIDER's registered country, not the subject's — the same class
    // `untrusted_ip_geo_reason` exists to catch (the org/abuse-contact data
    // above is unaffected: an operator attribution, not a geo claim).
    if !country.is_empty() && crate::core::validation::untrusted_ip_geo_reason(ip).is_none() {
        let mut ae = Entity::new(
            EntityKind::Address,
            &country,
            confidence::MEDIUM,
            &ctx.scan_id,
        );
        ae.tag("whois");
        ae.tag("rdap-fallback");
        ae.tag("geoint");
        ae.add_evidence(
            Evidence::new(SRC, format!("RDAP country for {ip}"))
                .with_attr("source", "rdap-fallback")
                .with_attr("ip", ip),
        );
        result.push(ae);
    }

    // Abuse contact email — the RIR abuse role is never GDPR-redacted for IPs.
    if let Some(email) = find_ip_entity(&body.entities, "abuse")
        .and_then(|e| e.vcard_array.as_ref())
        .and_then(|vc| vcard_field(vc, "email"))
        .filter(|e| e.contains('@'))
        .filter(|e| !crate::util::domains::is_infrastructure_email(e))
    {
        let mut ee = Entity::new(
            EntityKind::Email,
            &email,
            confidence::ATTRIBUTED,
            &ctx.scan_id,
        );
        ee.tag("whois-abuse");
        ee.tag("rdap-fallback");
        ee.add_evidence(
            Evidence::new(SRC, format!("RDAP abuse contact for {ip}"))
                .with_attr("source", "rdap-fallback")
                .with_attr("ip", ip),
        );
        result.push(ee);
    }

    Ok(result)
}

pub struct Whois;

#[async_trait]
impl Module for Whois {
    fn name(&self) -> &'static str {
        "whois"
    }

    fn description(&self) -> &'static str {
        "WHOIS recon — harvests registration data and extracts registrant contacts from the raw record"
    }

    fn priority(&self) -> u8 {
        32
    }

    /// IANA query + one referral follow-up, each capped at
    /// `QUERY_TIMEOUT_MS = 4000`. Worst case 2 × 4 s = 8 s; round up
    /// to give the response read some headroom past connect timeout.
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::IpAddress | TargetKind::Url
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // WHOIS registration data — ATT&CK WHOIS (T1596.002).
        &["T1596.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // IpAddress: `target.to_entity(...)` (dynamically kinded) re-emits
        // an IpAddress target itself when the WHOIS/RDAP response carries
        // enough to be worth reporting (registrar/created/nameservers/
        // status) — RIPE-style inetnum/inet6num objects commonly do.
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::IpAddress,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // When running behind an HTTPS proxy, TCP port 43 is not routable.
        // IP targets fall back to RDAP-over-HTTPS for the same org/country/abuse
        // data. Domain targets are reported as a typed `Unavailable` skip —
        // this host cannot reach the registry over port 43, so WHOIS was NOT
        // consulted; that is a coverage gap the operator can see (rdap_domain
        // carries the registry data over HTTPS), never the clean "no
        // registration data" an empty result would have recorded.
        if behind_proxy() {
            // Decided on the looked-up value — a URL whose host is an address
            // (`http://8.8.8.8/…`) takes the address path like a bare address.
            let q = query_value(target)?;
            return if q.parse::<std::net::IpAddr>().is_ok() {
                rdap_ip_fallback(&q, ctx).await
            } else {
                Err(Error::skipped(
                    SkipClass::Unavailable,
                    "TCP/43 WHOIS is not routable through the configured HTTPS proxy — \
                     domain WHOIS was not attempted (rdap_domain carries the registry \
                     data over HTTPS)",
                ))
            };
        }
        lookup(&client::Tcp, target, &ctx.scan_id).await
    }
}

/// The value sent down the wire for `target`: a URL's host (an IPv6 literal
/// without its `[…]` brackets, so it classifies and queries as an address),
/// otherwise the value itself. A URL with no host has nothing to look up.
///
/// Every operator-facing message this module builds names THIS value, never
/// the raw target: a URL's path, query or userinfo (`?token=…`, `user:pw@`)
/// is not the WHOIS subject and must not reach a persisted skip reason or
/// error string.
fn query_value(target: &Target) -> Result<String> {
    match target.kind {
        TargetKind::Url => {
            let host = crate::util::url_util::host_only(&target.value);
            let host = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(host);
            if host.is_empty() {
                return Err(Error::skipped(
                    SkipClass::NotApplicable,
                    "URL target has no host to look up — nothing to send to a WHOIS server",
                ));
            }
            Ok(host.to_string())
        }
        _ => Ok(target.value.clone()),
    }
}

/// The ONLY thing taken from IANA's bootstrap answer: the authoritative
/// server it refers `q` to. The rest of that answer describes the TLD or the
/// /8, not the target, and must never be parsed as the target's record (see
/// the module docs). No referral — IANA's `whois:` line is blank for a
/// registry that publishes no WHOIS server, `.vn` among them — is a typed
/// `NotApplicable` skip: port-43 WHOIS structurally cannot say anything about
/// that namespace, which is not "no registration record". **Pure** — tested
/// against the live IANA records for `COM`, `VN` and `8.8.8.8`.
fn bootstrap_referral(iana_answer: &str, q: &str) -> Result<String> {
    if let Some(server) = find_referral(iana_answer) {
        return Ok(server);
    }
    // No referral. That is "the registry publishes no WHOIS server" ONLY when
    // IANA actually answered with the registry's object; a refusal or an
    // unrecognised body must not be laundered into a harmless structural skip.
    if let Some(notice) = parse::rate_limit_notice(iana_answer) {
        return Err(Error::RateLimited(format!(
            "[{SRC}] IANA WHOIS bootstrap ({IANA_WHOIS}) refused the query for {q}: {notice}"
        )));
    }
    match parse::iana_bootstrap_shape(iana_answer) {
        parse::IanaShape::RegistryObject => Err(Error::skipped(
            SkipClass::NotApplicable,
            format!(
                "IANA lists no WHOIS server for the registry of {q} — port-43 WHOIS \
                 cannot say anything about it (this is not \"no registration \
                 record\"); rdap_domain carries the registry data over HTTPS"
            ),
        )),
        parse::IanaShape::NoObject => Err(Error::skipped(
            SkipClass::NotApplicable,
            format!(
                "IANA knows no registry for {q} (its bootstrap answer returned 0 \
                 objects) — port-43 WHOIS cannot say anything about it (this is not \
                 \"no registration record\")"
            ),
        )),
        parse::IanaShape::Unrecognised => Err(Error::module(
            SRC,
            format!(
                "IANA WHOIS bootstrap ({IANA_WHOIS}) answered {q} with neither a referral \
                 nor a registry object ({} bytes) — unrecognised reply, not \"no \
                 registration record\"",
                iana_answer.len()
            ),
        )),
    }
}

/// The whole lookup — bootstrap, referral, authoritative query, parse — over
/// an injected [`Transport`], so the decision chain runs offline in tests
/// against canned wire text. `process` runs it over [`client::Tcp`].
async fn lookup(transport: &dyn Transport, target: &Target, scan_id: &str) -> Result<ModuleResult> {
    let q = query_value(target)?;
    // 1) Ask IANA who's authoritative for this name. The answer is consumed by
    //    `bootstrap_referral` alone — deliberately never bound to a name the
    //    parser could be handed.
    let server = bootstrap_referral(
        &transport.bootstrap(&q).await.map_err(|e| {
            Error::module(
                SRC,
                format!(
                    "IANA WHOIS bootstrap ({IANA_WHOIS}) did not answer for {q}: {e} — \
                     not \"no registration record\""
                ),
            )
        })?,
        &q,
    )?;
    // 2) Query the authoritative server. Its silence is a failure of the
    //    lookup, reported as such — never papered over with another record.
    let response = transport.authoritative(&server, &q).await.map_err(|e| {
        Error::module(
            SRC,
            format!(
                "authoritative WHOIS server {server} for {q} {e} — not \"no \
                 registration record\""
            ),
        )
    })?;

    crate::util::http::scan_for_api_keys_with_source(&response, "whois");

    build_result(target, &q, &server, &response, scan_id)
}

/// Turn the authoritative server's answer for `target` (looked up as `q`) into
/// entities. **Pure** (no I/O): the parse, the "did the registry actually say
/// anything" gate (per record kind — an address record has no
/// registrar/nameservers), the load-refusal check, and the entity mapping,
/// all unit-tested against real registry answers.
fn build_result(
    target: &Target,
    q: &str,
    server: &str,
    response: &str,
    scan_id: &str,
) -> Result<ModuleResult> {
    // An address record is what an RIR answers for an address — whether the
    // target IS the address or is a URL whose host is one (`http://8.8.8.8/`).
    let is_ip = target.kind == TargetKind::IpAddress || q.parse::<std::net::IpAddr>().is_ok();
    // An RIR answer can carry every enclosing allocation; only the most
    // specific one describes the address (see `most_specific_network_record`).
    let record = if is_ip {
        parse::most_specific_network_record(response)
    } else {
        response
    };

    // 3) Parse the response into the fields we surface.
    let WhoisFields {
        registrar,
        registrar_iana,
        registrar_url,
        updated,
        created,
        expires,
        registrant_email,
        registrant_org,
        registrant_country,
        registrant_state,
        admin_email,
        admin_name,
        admin_org,
        tech_email,
        tech_name,
        tech_org,
        abuse_email,
        nameservers,
        statuses,
        dnssec,
        phones,
        net_name,
        net_range,
        cidr,
        net_type,
        descr,
    } = parse_whois(record);

    // Did the registry say anything about this target? A domain record
    // carries a registrar / creation date / nameservers / status; an address
    // record carries an allocation (net name / range), its operator, country
    // or abuse contact. Judged per kind — the domain-only gate read every
    // ARIN allocation as "no data".
    // A "no record" reply can itself carry a status line — DENIC answers an
    // unregistered name with `Status: free` — so a status alone is a record
    // only when the reply does not also say there is nothing there.
    let no_match = parse::no_match_notice(response).is_some();
    let actionable = if is_ip {
        net_name.is_some()
            || net_range.is_some()
            || registrant_org.is_some()
            || registrant_country.is_some()
            || abuse_email.is_some()
    } else {
        registrar.is_some()
            || created.is_some()
            || !nameservers.is_empty()
            || (!statuses.is_empty() && !no_match)
    };
    if !actionable {
        // A server that refused the query for load answered "not now", not
        // "no record" — surface it as the typed rate-limit so the breaker
        // backs off and coverage records a failure, never a clean negative.
        if let Some(notice) = parse::rate_limit_notice(response) {
            return Err(Error::RateLimited(format!(
                "[{SRC}] {server} refused the query for {q}: {notice}"
            )));
        }
        // The registry answered and holds nothing for this target — a reply
        // that SAYS so ("No match for …", "NOT FOUND", RIPE's ERROR:101 …).
        // The one genuine clean negative.
        if no_match {
            return Ok(ModuleResult::new());
        }
        // Anything else — an empty reply, a banner, a dialect the parser does
        // not know, an error we have no marker for — is a reply this module
        // could not read, and coverage must record it as a failure, never as
        // "checked, nothing there".
        return Err(Error::module(
            SRC,
            format!(
                "authoritative WHOIS server {server} answered {q} with neither a record \
                 nor a \"no match\" reply ({} bytes) — unrecognised reply, not \"no \
                 registration record\"",
                response.len()
            ),
        ));
    }

    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS_PLUS, scan_id);

    // Status flags become tags so the SPA can highlight them. These
    // are the most operationally interesting: lock states, hold flags,
    // pending transfers, etc.
    for status in &statuses {
        let lower = status.to_lowercase();
        for flag in [
            "clienttransferprohibited",
            "clientdeleteprohibited",
            "clientholdprohibited",
            "clientupdateprohibited",
            "servertransferprohibited",
            "serverdeleteprohibited",
            "serverholdprohibited",
            "serverupdateprohibited",
            "redemptionperiod",
            "pendingdelete",
            "pendingtransfer",
            "addperiod",
            "autorenewperiod",
            "ok",
        ] {
            if lower.contains(flag) {
                entity.tag(format!("status:{flag}"));
            }
        }
    }
    if let Some(d) = &dnssec
        && d.to_lowercase().contains("unsigned")
    {
        entity.tag("dnssec:unsigned");
    }
    if let Some(d) = &dnssec
        && d.to_lowercase().contains("signed")
    {
        entity.tag("dnssec:signed");
    }

    // Parsed here (not only at the Person-emission site below) so the
    // registrant/admin/tech NAMES fold into the domain's own evidence attrs —
    // those attrs are what `core::relation::derive_registration` matches a
    // registrant Person against to build the Domain→Person `RegisteredBy`
    // edge. A redacted name folds harmlessly: no Person entity is emitted for
    // it, so it can never form an edge.
    //
    // Domain records only: on an address record `person:` is the RIR's
    // technical/admin contact object for the NETWORK (an ISP engineer, a
    // registry employee), never the subject — an RIR record names no
    // registrant person.
    let registrant_name = (!is_ip)
        .then(|| {
            field(
                record,
                &["Registrant Name:", "Registrant Person:", "person:"],
            )
        })
        .flatten();
    let ev = [
        ("whois_server", Some(server.to_string())),
        ("registrar", registrar.clone()),
        ("registrar_iana_id", registrar_iana.clone()),
        ("registrar_url", registrar_url.clone()),
        ("created", created.clone()),
        ("updated", updated.clone()),
        ("expires", expires.clone()),
        (
            "name_servers",
            (!nameservers.is_empty()).then(|| nameservers.join(", ")),
        ),
        (
            "statuses",
            (!statuses.is_empty()).then(|| statuses.join(", ")),
        ),
        ("dnssec", dnssec.clone()),
        ("net_name", net_name.clone()),
        ("net_range", net_range.clone()),
        ("cidr", cidr.clone()),
        ("net_type", net_type.clone()),
        ("descr", descr.clone()),
        ("registrant_org", registrant_org.clone()),
        ("registrant_name", registrant_name.clone()),
        ("admin_name", admin_name.clone()),
        ("tech_name", tech_name.clone()),
        ("registrant_country", registrant_country.clone()),
        ("registrant_state", registrant_state.clone()),
        ("registrant_email", registrant_email.clone()),
        ("admin_email", admin_email.clone()),
        ("tech_email", tech_email.clone()),
        ("abuse_email", abuse_email.clone()),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v)))
    .fold(
        Evidence::new(SRC, format!("WHOIS for {}", target.value)),
        |ev, (key, v)| ev.with_attr(key, v),
    );

    entity.add_evidence(ev);

    let mut result = ModuleResult::new();
    result.push(entity);

    // Surface contact emails as discrete Email entities so they fan
    // out as scan targets in autonomous-expansion mode.
    // A WHOIS contact that is an infrastructure mailbox — a role address
    // (`abuse@`, `dns@`, `hostmaster@`) or a mailbox on a CDN/registrar/cloud
    // provider (`abuse@cloudflare.com`) — is the registrar/provider's desk,
    // NEVER the subject. Emitting it as a confidence::STRONG Email entity made it a
    // breach-checked, identity-clustered, expandable target (a real scan
    // merged `dns@cloudflare.com` / `abuse@cloudflare.com` into the subject's
    // identity). The address is still preserved in the parent domain's
    // evidence attrs above; it just must not become standalone PII.
    result.extend(
        [
            (&registrant_email, "registrant"),
            (&admin_email, "admin"),
            (&tech_email, "tech"),
            (&abuse_email, "abuse"),
        ]
        .into_iter()
        .filter_map(|(email, role)| {
            let addr = email.as_deref()?;
            if !is_usable_contact_email(addr) {
                return None;
            }
            let mut e = Entity::new(EntityKind::Email, addr, confidence::STRONG, scan_id);
            e.tag(format!("whois-{role}"));
            e.add_evidence(
                Evidence::new(SRC, format!("WHOIS {role} contact for {}", target.value))
                    .with_attr("role", role)
                    .with_attr("parent_target", target.value.as_str()),
            );
            Some(e)
        }),
    );

    // Registrant organisation → Organisation entity. For an address this is
    // the allocation's operator (tagged `ip-registrant`, like the RDAP path),
    // not a domain registrant.
    if let Some(org) = &registrant_org {
        let org = org.trim();
        if org.len() >= 3 && !crate::core::validation::is_whois_privacy_placeholder(org) {
            let mut oe = Entity::new(
                EntityKind::Organisation,
                org,
                confidence::ATTRIBUTED,
                scan_id,
            );
            oe.tag("whois");
            if is_ip {
                oe.tag("ip-registrant");
            } else {
                oe.tag(crate::core::tags::REGISTRANT);
            }
            oe.add_evidence(
                Evidence::new(SRC, format!("WHOIS registrant for {}", target.value))
                    .with_attr("parent_target", target.value.as_str()),
            );
            result.push(oe);
        }
    }

    // Registrant name → Person entity (when not redacted). `registrant_name`
    // is parsed above so it can also fold into the domain evidence.
    if let Some(name) = &registrant_name {
        let name = name.trim();
        if name.len() >= 4
            && name.contains(' ')
            && !crate::core::validation::is_whois_privacy_placeholder(name)
        {
            let mut pe = Entity::new(EntityKind::Person, name, confidence::ATTRIBUTED, scan_id);
            pe.tag("whois");
            pe.tag(crate::core::tags::REGISTRANT);
            pe.add_evidence(
                Evidence::new(SRC, format!("WHOIS registrant for {}", target.value))
                    .with_attr("parent_target", target.value.as_str()),
            );
            result.push(pe);
        }
    }

    // Registrant address → Address entity (when available and not a
    // privacy-proxy placeholder — via the SAME shared guard the registrant
    // name/org paths above use, not a narrow redacted/privacy substring test).
    //
    // For an IpAddress target this same field also carries the RIR
    // allocation record's `country:`/`state:` RPSL attributes — a CDN/
    // anycast edge IP's own registration describes the PROVIDER's
    // registered address, not the subject's, exactly the class
    // `untrusted_ip_geo_reason` exists to catch (the same policy
    // `ip_whois_geo`/`geo_intel`/`ipinfo`/`ip2location`/`ipquery`/`netlas`
    // already apply). A Domain target's registrant address is unaffected
    // — it has nothing to do with IP geolocation trust.
    let geo_trusted = !is_ip || crate::core::validation::untrusted_ip_geo_reason(q).is_none();
    if geo_trusted && let Some(country) = &registrant_country {
        let parts = registrant_location_parts(registrant_state.as_deref(), country);
        if !parts.is_empty() && parts.iter().any(|p| p.len() >= 2) {
            let addr = parts.join(", ");
            let mut ae = Entity::new(EntityKind::Address, &addr, confidence::MEDIUM, scan_id);
            ae.tag("whois");
            ae.tag(crate::core::tags::REGISTRANT);
            ae.tag("geoint");
            ae.add_evidence(
                Evidence::new(SRC, format!("Registrant location for {}", target.value))
                    .with_attr("parent_target", target.value.as_str()),
            );
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&addr) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(
                    EntityKind::Coordinates,
                    &coord_val,
                    confidence::LOW,
                    scan_id,
                );
                c.tag("whois");
                c.tag("addr-derived");
                c.tag("geoint");
                c.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Geocode of registrant address for {}", target.value),
                    )
                    .with_attr("parent_target", target.value.as_str()),
                );
                result.push(c);
            }
            result.push(ae);
        }
    }

    // Admin and tech contact names / organisations — same redaction filter
    // as the registrant block above (the shared, complete privacy-proxy guard).
    // Domain records only: an RIR record's contacts are the network's staff.
    let is_redacted = crate::core::validation::is_whois_privacy_placeholder;
    if !is_ip {
        for (name_opt, role) in [(&admin_name, "admin"), (&tech_name, "tech")] {
            if let Some(name) = name_opt
                .as_deref()
                .map(str::trim)
                .filter(|n| n.len() >= 4 && n.contains(' ') && !is_redacted(n))
            {
                let mut pe = Entity::new(EntityKind::Person, name, confidence::HIGH, scan_id);
                pe.tag("whois");
                pe.tag(role);
                pe.add_evidence(
                    Evidence::new(SRC, format!("WHOIS {} contact for {}", role, target.value))
                        .with_attr("role", role)
                        .with_attr("parent_target", target.value.as_str()),
                );
                result.push(pe);
            }
        }
        for (org_opt, role) in [(&admin_org, "admin"), (&tech_org, "tech")] {
            if let Some(org) = org_opt
                .as_deref()
                .map(str::trim)
                .filter(|o| o.len() >= 3 && !is_redacted(o))
            {
                let mut oe =
                    Entity::new(EntityKind::Organisation, org, confidence::NOTABLE, scan_id);
                oe.tag("whois");
                oe.tag(role);
                oe.add_evidence(
                    Evidence::new(SRC, format!("WHOIS {} org for {}", role, target.value))
                        .with_attr("role", role)
                        .with_attr("parent_target", target.value.as_str()),
                );
                result.push(oe);
            }
        }
    }

    // Contact phone numbers — redacted values are already excluded in
    // parse_whois; each surviving number is in E.164 `+<digits>` form.
    for phone in &phones {
        let mut pe = Entity::new(EntityKind::Phone, phone, confidence::HIGH_PLUS, scan_id);
        pe.tag("whois");
        pe.add_evidence(
            Evidence::new(SRC, format!("WHOIS contact phone for {}", target.value))
                .with_attr("parent_target", target.value.as_str()),
        );
        result.push(pe);
    }

    // Surface nameservers as Domain entities too so DNS chaining
    // picks them up at depth>=1. Values are already host-only (glue
    // stripped, shape-checked) — see `parse::clean_nameserver`.
    result.extend(nameservers.iter().filter_map(|ns| {
        let host = ns.trim_end_matches('.').to_lowercase();
        if host.is_empty() {
            return None;
        }
        let mut e = Entity::new(EntityKind::Domain, &host, confidence::CORROBORATED, scan_id);
        e.tag("whois-ns");
        e.add_evidence(
            Evidence::new(SRC, format!("Nameserver for {}", target.value))
                .with_attr("parent_target", target.value.as_str()),
        );
        Some(e)
    }));

    Ok(result)
}
