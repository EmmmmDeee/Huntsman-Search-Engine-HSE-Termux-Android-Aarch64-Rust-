//! Australian property and land title register searches.
//!
//! Queries publicly-accessible property and land title portals to find
//! registered ownership records for a full-name seed. Property title
//! registration is compulsory in Australia; ownership records are public
//! and freely searchable through state portals and their data services.
//!
//! Sources (all free, keyless):
//!   * NSW Spatial — `https://maps.six.nsw.gov.au/` (owner name search via
//!     ELVIS cadastral API — free, no key required for basic lookups)
//!   * VIC MapShare — `https://mapshare.vic.gov.au/` (parcel/owner search)
//!   * QLD Globe — `https://qldglobe.information.qld.gov.au/` (lot/plan owner)
//!   * data.gov.au Geocoded National Address File (GNAF) — suburb/postcode
//!     from lot/plan references, open-data, no key required
//!
//! **Live status (2026-07-14):** all three legacy endpoints this module
//! targets are currently confirmed dead — real, non-proxy-blocked live
//! requests to each (root domain reachable, specific path gone) return:
//! NSW's `/services/public/Property_Name_Address` → `404` (re-confirmed
//! 2026-08-04: `maps.six.nsw.gov.au/` now `308`-redirects wholesale to
//! `portal.spatial.nsw.gov.au/explorer/index.html`, the client-rendered "SDT
//! Explorer" SPA — the whole legacy domain was retired, not just this one
//! path; the same "legacy static endpoint retired for a client-rendered app"
//! pattern already confirmed for `au_electoral`'s AEC leg and `metager`. The
//! SPA's actual data API was not identified — that needs a browser-devtools
//! network trace, not a plain HTTP probe, and is the concrete next step);
//! VIC's `/mapsharevic/ows` WFS endpoint → `404` (IIS "File or directory not
//! found", root MapShareVic app itself still live at `200`); QLD's
//! `/environment/land/title/searching/owners` → `404` (qld.gov.au's own
//! "Page not found" template). No replacement endpoint identified yet for
//! any of the three — named as this module's next candidate work. Until a
//! replacement is found, `process()` distinguishes "every portal is down"
//! (a real `Error::module` failure, surfaced to the operator and to the
//! T2.7 scraper-health signal) from "a portal responded but had no match for
//! this name" (the ordinary, honest empty success) — see `leg_failure` in this
//! module.
//!
//! That failure message names which of the two possible causes actually
//! occurred. A dead endpoint and an unreachable host both end a run with no
//! data, but they call for opposite operator responses — the first is this
//! module's problem, the second is the device's — and on a Termux handset
//! (lost mobile data, captive portal, dropped VPN) the second is routine.
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (property address + suburb)
//!   * T1589.003 — Employee Names (confirms legal registered name)
//!
//! Note: this module does NOT claim T1591.002 (Business Relationships). Every
//! `PropertyRecord::owner_name` is always just the queried `full_name` echoed
//! back — there is no co-owner, trust, or company extraction here, so a
//! "business relationships" claim would be phantom.
//!
//! Confidence model — a title register outranks a directory or electoral
//! roll (per the sourcing note above):
//!   * Owner name matched with suburb + state + a corroborating postcode
//!     extracted nearby: 0.74 — one notch above `au_electoral`'s own
//!     suburb-match tier (`confidence::ATTRIBUTED`, 0.72), since the extra
//!     extracted field is itself weak corroboration of a genuine structured
//!     record rather than an isolated name/suburb coincidence.
//!   * Owner name matched with suburb + state only (no postcode found
//!     nearby): `confidence::NOTABLE` (0.62) — the base title-register tier,
//!     below `ATTRIBUTED` since it lacks that corroborating field.
//!   * Coordinates from suburb centroid: confidence::MEDIUM_PLUS (derived, not raw)
//!
//! Orthogonal to `au_electoral` (electoral roll), `au_people` (residential
//! directories), `abn_lookup` (business register), `asic_director` (company
//! directors) — property ownership is a distinct legal record class.

mod parse;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, read_body_capped_or_fail};

use parse::{
    SRC, parse_nsw_response, parse_qld_response, parse_vic_response, record_to_entities,
    split_name, surname,
};

pub struct AuProperty;

// ─── Module impl ──────────────────────────────────────────────────────────

#[async_trait]
impl Module for AuProperty {
    fn name(&self) -> &'static str {
        "au_property"
    }

    fn description(&self) -> &'static str {
        "Australian property & land-title recon — pivots a full-name seed to registered ownership records (suburb/state/postcode) across the NSW, VIC, and QLD public cadastral portals"
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::FullName
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[EntityKind::Address, EntityKind::Coordinates]
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003"]
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn priority(&self) -> u8 {
        84
    }

    fn max_timeout_ms(&self) -> u64 {
        // Three sequential state portal requests, each ~3–5 s.
        18_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        if full_name.is_empty() {
            return Ok(ModuleResult::new());
        }

        let (first, last) = split_name(full_name);
        if last.is_empty() {
            return Ok(ModuleResult::new());
        }
        let sname = surname(full_name);
        let encoded_full = crate::util::http::urlencode(full_name);
        let encoded_sname = crate::util::http::urlencode(sname);

        let mut all_entities: Vec<Entity> = Vec::new();
        // How each leg resolved. Not a single `any_leg_ok: bool`: that could not
        // tell "the endpoint answered with an error status" from "nothing
        // answered", and the failure message asserted the former either way.
        let mut tally = LegTally::default();

        // Legs run in order and stop at the first that yields anything — the
        // portals are alternatives, not a fan-out. Each is a URL, an Accept
        // header, and a parser; `run_leg` owns the request and the outcome
        // classification so all three agree on what a failure was.
        let legs: [(String, &str, fn(&str, &str) -> Vec<parse::PropertyRecord>); 3] = [
            // NSW Spatial / ELVIS cadastral — surname + given name query.
            (
                format!(
                    "https://maps.six.nsw.gov.au/services/public/Property_Name_Address?surname={}&givenname={}&maxRows=10",
                    crate::util::http::urlencode(last),
                    crate::util::http::urlencode(first),
                ),
                "application/json,text/html",
                parse_nsw_response as fn(&str, &str) -> Vec<parse::PropertyRecord>,
            ),
            // VIC MapShare — parcel/owner WFS query.
            (
                format!(
                    "https://mapshare.vic.gov.au/mapsharevic/ows?service=WFS&version=1.0.0\
                     &request=GetFeature&typeName=CADASTRE:PARCEL&outputFormat=application/json\
                     &CQL_FILTER=OWNER_NAME+LIKE+%27{encoded_sname}%25%27&maxFeatures=10"
                ),
                "application/json,text/html",
                parse_vic_response as fn(&str, &str) -> Vec<parse::PropertyRecord>,
            ),
            // QLD Globe / titles — owner search.
            (
                format!(
                    "https://www.qld.gov.au/environment/land/title/searching/owners?owner={encoded_full}"
                ),
                "text/html,application/xhtml+xml",
                parse_qld_response as fn(&str, &str) -> Vec<parse::PropertyRecord>,
            ),
        ];

        for (url, accept, parse_fn) in &legs {
            if !all_entities.is_empty() {
                break;
            }
            tally.record(run_leg(ctx, url, accept, full_name, *parse_fn, &mut all_entities).await);
        }

        // Dedup by (kind, value) — different portals may agree on the same suburb.
        crate::core::entity::dedup_merge_entities(&mut all_entities);

        if let Some(msg) = leg_failure(tally) {
            return Err(Error::module(SRC, msg));
        }

        let mut result = ModuleResult::new();
        result.entities = all_entities;
        Ok(result)
    }
}

/// What one portal leg actually did.
///
/// The distinction a single `any_leg_ok: bool` erased: it was false both when a
/// response arrived carrying a non-success status and when no response arrived
/// at all, so the failure message asserted the former while the latter was
/// equally likely — routine on this module's target platform, where a handset
/// loses mobile data, sits behind a captive portal, or drops a VPN mid-scan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LegOutcome {
    /// The portal itself answered 2xx and the whole body was read: the
    /// register was consulted, and whatever the parser found (or did not) is
    /// its answer.
    Ok,
    /// A response arrived, carrying a non-success status.
    HttpError,
    /// The request was redirected off the portal's host and a *different* site
    /// answered 2xx — the retired legacy domain forwarding wholesale to a
    /// client-rendered app (NSW's `maps.six.nsw.gov.au` → `portal.spatial.nsw.gov.au`
    /// SPA, observed 2026-08-04). That page is not the register: parsing it
    /// yields nothing for anyone, which before this read as "register
    /// consulted, no records for this name" (`docs/PROVIDER_SWEEP_BACKLOG.md`
    /// #3). Counted as a dead endpoint, like `HttpError`.
    Migrated,
    /// No response arrived, or the body could not be read to the end: DNS,
    /// connect, TLS, timeout, or a mid-body transport failure. The last used to
    /// be tallied `Ok` with an empty body (`docs/PROVIDER_SWEEP_BACKLOG.md` #4).
    Unreachable,
}

/// How the attempted legs resolved.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct LegTally {
    ok: u8,
    http_error: u8,
    migrated: u8,
    unreachable: u8,
}

impl LegTally {
    fn record(&mut self, outcome: LegOutcome) {
        let slot = match outcome {
            LegOutcome::Ok => &mut self.ok,
            LegOutcome::HttpError => &mut self.http_error,
            LegOutcome::Migrated => &mut self.migrated,
            LegOutcome::Unreachable => &mut self.unreachable,
        };
        *slot = slot.saturating_add(1);
    }
}

/// The hard failure `process()` should surface, or `None` when the run was an
/// honest empty success.
///
/// Any leg answering 2xx means the registers were genuinely consulted, so an
/// empty result is a real "no records for this name" — never an error, whatever
/// the other legs did. Otherwise the message states **what was actually
/// observed**, because the two failure causes call for opposite operator
/// responses: a dead endpoint is this module's problem, an unreachable host is
/// the device's.
///
/// This replaces `all_legs_unreachable(any_leg_http_ok, found_any_entity)`,
/// whose second parameter was dead: entities were only ever appended inside a
/// leg's own `is_success()` branch, so `found_any_entity` implied
/// `any_leg_http_ok` and could never change the result. Its doc and a unit test
/// both presented `(false, true)` as a meaningful case, which was drift-prone in
/// the dangerous direction — a future caller could trust a guard that does not
/// guard. `tally.ok > 0` now expresses that condition directly and truthfully.
///
/// Pure and network-free, so it is unit-testable without a live server.
#[must_use]
fn leg_failure(tally: LegTally) -> Option<String> {
    if tally.ok > 0 {
        return None;
    }
    // A leg that redirected off the portal's host is a dead endpoint like a
    // non-success status: the register never answered, something else did.
    let dead = tally.http_error.saturating_add(tally.migrated);
    let attempted = u16::from(dead) + u16::from(tally.unreachable);
    if attempted == 0 {
        // No leg ran at all (the caller short-circuited); nothing to report on.
        return None;
    }
    Some(match (dead, tally.unreachable) {
        (0, _) => format!(
            "none of the {attempted} property-register endpoints (NSW ELVIS, VIC MapShare WFS, \
             QLD titles search) could be reached — the requests failed before any reply \
             (DNS, connect, TLS, or timeout). That is a connectivity failure on this device, \
             NOT evidence about the registers and NOT \"no property records for this name\"."
        ),
        (_, 0) => format!(
            "all {attempted} property-register endpoints (NSW ELVIS, VIC MapShare WFS, QLD \
             titles search) returned a non-success HTTP status or redirected away to another \
             host — likely retired/migrated legacy URLs (see this module's doc comment), not \
             \"no property records for this name\""
        ),
        (dead, unreachable) => format!(
            "no property-register endpoint answered: {dead} returned a non-success HTTP \
             status or redirected away to another host (likely retired/migrated legacy URLs \
             — see this module's doc comment) and {unreachable} could not be reached at all \
             (DNS, connect, TLS, or timeout). Mixed causes, so this is not evidence of \"no \
             property records for this name\"."
        ),
    })
}

/// Run one portal leg: request, classify the outcome, and on a 2xx parse the
/// body into entities appended to `out`.
///
/// One definition so the three legs cannot drift in how they classify a failure
/// — they were three verbatim copies of `if let Ok(resp) = … && resp.status()
/// .is_success()`, whose discarded `Err` arm is exactly what collapsed
/// "unreachable" into "non-success status".
async fn run_leg(
    ctx: &ModuleContext,
    url: &str,
    accept: &str,
    full_name: &str,
    parse: fn(&str, &str) -> Vec<parse::PropertyRecord>,
    out: &mut Vec<Entity>,
) -> LegOutcome {
    let Ok(resp) = ctx
        .http
        .get(url)
        .header("Accept", accept)
        .header("User-Agent", crate::util::http::UA_BROWSER)
        .send_tagged(SRC)
        .await
    else {
        return LegOutcome::Unreachable;
    };
    if !resp.status().is_success() {
        return LegOutcome::HttpError;
    }
    // A 2xx that arrived from a different host than the one asked is not the
    // register answering: the legacy domain forwarded the request wholesale to
    // some other app (NSW's SPA), whose page says nothing about this name.
    if landed_off_host(url, resp.url()) {
        tracing::debug!(
            source = SRC,
            requested = %crate::util::http::redact_credentials(url),
            landed = %resp.url(),
            "au_property: leg redirected off the portal's host — retired endpoint, not an answer"
        );
        return LegOutcome::Migrated;
    }
    // Fail closed on a body that cannot be read to the end: a mid-body
    // transport failure is a transport failure, not an empty register page.
    let Ok(body) = read_body_capped_or_fail(SRC, resp, 1_000_000).await else {
        return LegOutcome::Unreachable;
    };
    out.extend(
        parse(&body, full_name)
            .iter()
            .flat_map(|rec| record_to_entities(rec, &ctx.scan_id)),
    );
    LegOutcome::Ok
}

/// True when the response's final URL (after redirects) sits on a different
/// host than the URL that was requested. A same-host redirect (http → https,
/// a trailing-slash canonicalisation) is the portal answering; a cross-host one
/// is the portal handing the request to some other site. Pure.
fn landed_off_host(requested: &str, landed: &url::Url) -> bool {
    let requested_host = url::Url::parse(requested)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
    let landed_host = landed.host_str().map(str::to_ascii_lowercase);
    match (requested_host, landed_host) {
        (Some(r), Some(l)) => r != l,
        // Cannot tell — do not invent a migration.
        _ => false,
    }
}
