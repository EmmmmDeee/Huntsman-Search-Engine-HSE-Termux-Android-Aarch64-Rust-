//! What routing says about the announced prefix covering a resource, built one way for every
//! lookup that reads `RIPEstat`'s prefix overview (`ip ADDRESS`, `netblock CIDR`).
//!
//! Two keyless `RIPEstat` reads follow the overview when the covering prefix is announced:
//! - the RPKI route-origin validation state of the prefix for each of its first
//!   [`ripestat::MAX_RPKI_ORIGINS`] public origin AS numbers ([`rpki_states`], [`with_rpki`]);
//! - the prefix's routing history, of which every origin AS other than the current ones that RIS
//!   peers saw announcing a prefix that touches the resource is listed ([`routing_history`],
//!   [`history_record`]).
//!
//! An invalid RPKI state or a past origin is a lead, never a finding: each record says a
//! misconfiguration, a transfer, an anycast or multi-homed operator, a leak or a hijack fits it,
//! and that it proves none of them. A read that failed says it failed; it is never shown as an
//! unknown state or an empty history.

use crate::api_leg::LegError;
use crate::entity::Evidence;
use crate::http::Transport;
use crate::ripestat::{self, OriginHistory, Routing, RoutingHistory, Rpki};
use crate::tags;

/// Each current origin's RPKI state, keyed by AS number.
pub type RpkiStates = Vec<(u32, Result<Rpki, LegError>)>;

/// The covering prefix, when it is announced: there is nothing to validate or trace otherwise.
fn announced(routing: &Routing) -> Option<&str> {
    routing.prefix.as_deref().filter(|_| routing.announced)
}

/// The RPKI state of the announced covering prefix for each of its first
/// [`ripestat::MAX_RPKI_ORIGINS`] public origin AS numbers: one request each.
#[must_use]
pub fn rpki_states<T: Transport + ?Sized>(
    transport: &T,
    routing: &Routing,
    now_unix: u64,
) -> RpkiStates {
    let Some(prefix) = announced(routing) else {
        return Vec::new();
    };
    routing
        .public_origins()
        .take(ripestat::MAX_RPKI_ORIGINS)
        .map(|origin| {
            (
                origin.asn,
                ripestat::rpki_validation(transport, origin.asn, prefix, now_unix),
            )
        })
        .collect()
}

/// The routing history of the announced covering prefix, keeping the announcements whose prefix
/// `touches` the resource: one request. `None` when there is no announcement to ask about.
#[must_use]
pub fn routing_history<T: Transport + ?Sized>(
    transport: &T,
    routing: &Routing,
    touches: impl Fn(&str) -> bool,
    now_unix: u64,
) -> Option<Result<RoutingHistory, LegError>> {
    let prefix = announced(routing)?;
    Some(ripestat::routing_history(
        transport, prefix, touches, now_unix,
    ))
}

/// `evidence` on origin `asn` with its RPKI state, and, when the state contradicts a published
/// ROA, the record `record` makes for the resource. A failed check is said to have failed.
#[must_use]
pub fn with_rpki(
    evidence: Evidence,
    asn: u32,
    routing: &Routing,
    rpki: &RpkiStates,
    record: impl Fn(String) -> Evidence,
) -> (Evidence, Option<Evidence>) {
    let Some(state) = rpki
        .iter()
        .find(|(origin, _)| *origin == asn)
        .map(|(_, state)| state)
    else {
        return (evidence, None);
    };
    let state = match state {
        Ok(state) => state,
        // A failed check is not an unknown state.
        Err(error) => {
            return (
                evidence.with_attr("rpki_check", format!("failed: {error}")),
                None,
            );
        }
    };
    let mut evidence = evidence
        .with_attr("rpki_state", state.state.as_str())
        .with_attr("rpki_meaning", state.state.meaning())
        .with_optional_attrs([("rpki_validator", state.validator.as_deref())]);
    if !state.roas.is_empty() {
        evidence = evidence.with_attr("rpki_roas", state.roas_text());
    }
    let invalid = state.state.is_invalid().then(|| {
        record(format!(
            "RPKI {}: AS{asn} announcing {} contradicts a published ROA",
            state.state.as_str(),
            routing.prefix.as_deref().unwrap_or_default()
        ))
        .with_attr("asn", format!("AS{asn}"))
        .with_attr("rpki_state", state.state.as_str())
        .with_attr("rpki_meaning", state.state.meaning())
        .with_attr("rpki_roas", state.roas_text())
    });
    (evidence, invalid)
}

/// Who else announced the covering prefix, as the record `record` makes for the resource, with
/// the tag it carries when there were other origins: every origin AS other than the current
/// ones, most recently seen first, at most [`ripestat::MAX_PAST_ORIGINS`] listed. `touching`
/// says how an announced prefix relates to the resource (`containing the address`).
#[must_use]
pub fn history_record(
    routing: &Routing,
    history: &Result<RoutingHistory, LegError>,
    touching: &str,
    record: impl Fn(String) -> Evidence,
) -> (Evidence, Option<&'static str>) {
    let prefix = routing.prefix.as_deref().unwrap_or_default();
    let history = match history {
        Ok(history) => history,
        Err(error) => {
            let evidence = record(format!("Routing history of {prefix} not read"))
                .with_attr("routing_history_check", format!("failed: {error}"));
            return (evidence, None);
        }
    };
    let past: Vec<&OriginHistory> = history
        .origins
        .iter()
        .filter(|origin| !routing.origins.iter().any(|now| now.asn == origin.asn))
        .collect();
    let base = |summary: String| {
        record(summary)
            .with_attr("prefix", prefix)
            .with_attr(
                "routing_history_min_peers",
                ripestat::ROUTING_MIN_PEERS.to_string(),
            )
            .with_attr("past_origin_count", past.len().to_string())
            .with_optional_attrs([("routing_history_window", history.window.as_deref())])
    };
    let Some(latest) = past.first() else {
        let evidence = base(format!(
            "Routing history of {prefix}: no origin AS but the current one seen announcing it by {} or more RIS peers",
            ripestat::ROUTING_MIN_PEERS
        ));
        return (evidence, None);
    };
    let listed: Vec<String> = past
        .iter()
        .take(ripestat::MAX_PAST_ORIGINS)
        .map(|origin| origin.line())
        .collect();
    let evidence = base(format!(
        "Routing history of {prefix}: {} other origin AS number(s) announced a prefix {touching}, most recently AS{} until {}; a transfer, an anycast or multi-homed operator, a leak or a hijack, not proof of any",
        past.len(),
        latest.asn,
        latest.last_seen
    ))
    .with_attr("past_origins_listed", listed.len().to_string());
    // One value per origin, so each is its own attribute value.
    let evidence = listed.iter().fold(evidence, |evidence, line| {
        evidence.with_attr("past_origins", line)
    });
    (evidence, Some(tags::PREFIX_ORIGIN_HISTORY))
}
