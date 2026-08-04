//! State electoral roll lookups (NSW, VIC, QLD).
//!
//! Queries the state electoral commission pages to confirm enrolment and
//! extract the electoral division (which maps to a suburb/postcode range).
//! Electoral roll enrolment in Australia is compulsory, so this is a
//! high-confidence residential-address signal orthogonal to business
//! registers, unclaimed-money records, and people-finder directories.
//!
//! Sources (all free, keyless, public HTML):
//!   * NSW Electoral Commission — `https://check.elections.nsw.gov.au/`
//!   * VEC (Victoria) — `https://check.vec.vic.gov.au/`
//!   * ECQ (Queensland) — `https://enrol.ecq.qld.gov.au/check`
//!
//! No national/AEC leg: the AEC retired the `NameSearch.aspx` name-based
//! lookup this module used to query — live-confirmed (2026-07-13) via two
//! real `GET electorate.aec.gov.au/NameSearch.aspx?surname=…&firstname=…`
//! calls, a nonsense name and a real enrolled public figure, both returning
//! the *identical* generic `"Temporarily Unavailable / System Problem"`
//! error page rather than a query-specific result. The AEC's current
//! "Check your enrolment" tool (`check.aec.gov.au`) confirmed this isn't
//! transient: it now runs an address-based multi-step lookup (postcode →
//! suburb → street, via `?handler=…` RPC calls) with no name-search
//! capability at all — a different input shape (`Address`, not `FullName`)
//! this module doesn't take, so repointing to it is a distinct future
//! capability, not a same-shape endpoint repair. Removed the dead dispatch
//! (it never returned a result and was silently swallowed) rather than
//! leave every `FullName` scan pay its request/timeout cost for nothing.
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (electoral division → suburb)
//!   * T1589.003 — Employee Names (confirms legal registered name)
//!
//! Confidence model:
//!   * Confirmed enrolment with division + suburb: 0.72 (electoral roll is
//!     compulsory and address-verified; higher than directory sources)
//!   * Division only (no suburb resolved): 0.58
//!   * Address from division centroid lookup: confidence::HIGH (derived, not raw)
//!
//! The module is AU-restricted: it only accepts `FullName` targets and only
//! emits when the division geography maps inside Australia.

mod division_map;
mod entity;
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
use crate::util::http::{RequestBuilderExt, read_body_capped};

pub(crate) use entity::build_electoral_entities;
pub(crate) use parse::extract_division;

pub(super) const SRC: &str = "au_electoral";

pub struct AuElectoral;

// ─── Outcome of one commission lookup ─────────────────────────────────────

/// What a single electoral-commission leg established.
///
/// Carries no payload on purpose: the entities go straight into the result, and
/// this records only whether the registry *spoke*. That is precisely the
/// distinction the old code threw away — each leg was a single
/// `if let Ok(resp) = … && let Some(body) = … && let Some(div) = …` chain, so a
/// transport failure, an unreadable reply and a page naming no division all
/// landed on the same "no entities" branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RollOutcome {
    /// The commission answered and its page was read. Whether it named a
    /// division or not, this IS a statement about enrolment in that state, and
    /// an empty result from it is a genuine negative.
    Answered,
    /// Nothing was established — the request failed, or the reply could not be
    /// read. **Not** a statement about enrolment.
    Unreachable,
}

/// True when NO commission answered: every leg failed to reach or read a
/// registry, so the module established nothing about enrolment at all.
///
/// This matters more here than for a typical source. Enrolment is *compulsory*
/// in Australia — the module header leans on exactly that to call this a
/// "high-confidence residential-address signal" — so "au_electoral returned
/// nothing" reads to an analyst as *not on any roll*, a strong negative claim
/// about a person. When all three registries were simply down, nothing
/// whatsoever supports that claim.
///
/// Pure, so the decision that turns a scan into a `ModuleError` is unit-testable
/// without three live state-government endpoints. Deliberately requires ALL
/// outcomes to be unreachable: one commission answering, even with no division,
/// proves the lookup path works and the empties are real negatives.
///
/// An empty slice is NOT unreachable — no legs ran (cancellation, or an empty
/// name), which is its own condition and must not be reported as an outage.
pub(super) fn rolls_wholly_unreachable(outcomes: &[RollOutcome]) -> bool {
    !outcomes.is_empty() && outcomes.iter().all(|o| *o == RollOutcome::Unreachable)
}

/// Query one electoral commission, returning what it established and any
/// entities its page yielded.
///
/// Known limit, stated rather than papered over: a page that is read but names
/// no division is reported as [`RollOutcome::Answered`] with no entities. That
/// is right for a genuine "not on this roll", but a changed page layout or an
/// interstitial block page would also land there and read as a real negative.
/// Separating those needs a positive "no match found" marker per commission,
/// which needs live samples of each state's negative-result page — a distinct
/// unit, and one that must not be guessed at.
async fn query_roll(url: &str, full_name: &str, ctx: &ModuleContext) -> (RollOutcome, Vec<Entity>) {
    let Ok(resp) = ctx
        .http
        .get(url)
        .header("Accept", "text/html,application/xhtml+xml")
        .header("User-Agent", crate::util::http::UA_BROWSER)
        .send_tagged(SRC)
        .await
    else {
        return (RollOutcome::Unreachable, Vec::new());
    };
    let Some(body) = read_body_capped(resp, 1_000_000).await else {
        // The commission responded but we could not read the reply, so nothing
        // about enrolment was established. Not a negative.
        return (RollOutcome::Unreachable, Vec::new());
    };
    match extract_division(&body) {
        Some((div, suburb)) => (
            RollOutcome::Answered,
            build_electoral_entities(&div, suburb.as_deref(), full_name, &ctx.scan_id),
        ),
        None => (RollOutcome::Answered, Vec::new()),
    }
}

// ─── Module impl ──────────────────────────────────────────────────────────

#[async_trait]
impl Module for AuElectoral {
    fn name(&self) -> &'static str {
        "au_electoral"
    }

    fn description(&self) -> &'static str {
        "AEC and state electoral-commission recon — confirms residential electoral division (suburb/state) for an AU full-name seed via enrolment lookups"
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
        85
    }

    fn max_timeout_ms(&self) -> u64 {
        // Three sequential EC lookups (NSW → VIC → ECQ), each ~3–5 s.
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        if full_name.is_empty() {
            return Ok(ModuleResult::new());
        }

        let encoded = crate::util::http::urlencode(full_name);
        let mut all_entities: Vec<Entity> = Vec::new();
        let mut outcomes: Vec<RollOutcome> = Vec::new();

        // No AEC national leg: `electorate.aec.gov.au/NameSearch.aspx` no
        // longer performs a name search (see the module doc comment) — every
        // call returned the identical generic error page, live-confirmed
        // against both a nonsense name and a real enrolled public figure.
        let legs = [
            format!("https://check.elections.nsw.gov.au/search?name={encoded}"),
            format!("https://check.vec.vic.gov.au/search?name={encoded}"),
            format!("https://enrol.ecq.qld.gov.au/check?name={encoded}"),
        ];

        for url in &legs {
            // First hit wins — unchanged. A leg that answered with a division
            // stops the remaining lookups, exactly as the three `if
            // all_entities.is_empty()` guards did before.
            if !all_entities.is_empty() {
                break;
            }
            let (outcome, entities) = query_roll(url, full_name, ctx).await;
            all_entities.extend(entities);
            outcomes.push(outcome);
        }

        // Every commission we tried failed to answer, so nothing was
        // established. Returning an empty success here would render as "not on
        // the NSW, VIC or QLD roll" — and because enrolment is compulsory, that
        // reads as a finding about the person rather than about the network.
        //
        // Gated on cancellation: an operator stopping the scan (or the
        // wall-time watchdog firing) leaves the in-flight legs unreachable, and
        // reporting that as "no electoral commission answered" would blame the
        // registries for our own stop. The zero-leg case is already excluded
        // inside `rolls_wholly_unreachable`; this covers partial-then-cancelled.
        if !ctx.cancel.is_cancelled() && rolls_wholly_unreachable(&outcomes) {
            return Err(Error::module(
                SRC,
                format!(
                    "no electoral commission answered for {full_name}: all {} lookups \
                     (NSW, VIC, QLD) failed to respond or returned a reply that could \
                     not be read. Enrolment is compulsory in Australia, so an empty \
                     result would read as 'not enrolled' — which nothing established.",
                    outcomes.len()
                ),
            ));
        }

        let mut result = ModuleResult::new();
        result.entities = all_entities;
        Ok(result)
    }
}
