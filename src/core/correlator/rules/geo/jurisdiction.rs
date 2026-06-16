//! GEOINT correlation rules — country/region/state inference family.
//!
//! Reconciles the AU state/territory asserted by a `Coordinates` fix against the
//! one parsed from an `Address`/postcode (AU-056), and infers a suburb-level
//! workplace locality from professional-profile URL slugs (AU-058). See
//! `super::super` (rules/mod.rs) for the shared helpers; all reach them via
//! `use super::*` → `geo/mod.rs` → `use super::*` → `rules/mod.rs`.

use super::*;

/// The AU state/territory a confirmed `Coordinates` entity asserts. Prefers the
/// `au-state:XX` tag the geo builders attach, but falls back to deriving the
/// state straight from the lat/long via [`crate::util::geo::au_state_for_coords`]
/// when the tag is absent — a coordinate enters the graph from many modules
/// (`geo_normalize`, `search_engines`, `exif_geo`, …), only three of which tag
/// it, so a tag-only read silently dropped most real fixes (seen on a live
/// scan: a Brisbane coordinate from `geo_normalize` carried no tag and the
/// jurisdiction cross-check never fired). Only confirmed fixes (≥0.50) count, so
/// an off-region candidate can't assert a jurisdiction.
fn coord_state(e: &Entity) -> Option<&'static str> {
    if e.kind != EntityKind::Coordinates || e.confidence < 0.50 {
        return None;
    }
    const AU_STATES: [&str; 8] = ["ACT", "NSW", "NT", "QLD", "SA", "TAS", "VIC", "WA"];
    if let Some(state) = e
        .tags
        .iter()
        .find_map(|t| t.strip_prefix("au-state:"))
        .and_then(|code| AU_STATES.into_iter().find(|s| *s == code))
    {
        return Some(state);
    }
    crate::util::geohash::parse_coords(&e.value)
        .and_then(|(lat, lon)| crate::util::geo::au_state_for_coords(lat, lon))
}

/// AU-056 — Jurisdiction cross-check (coordinate state vs address state).
///
/// The synergy lever for the new offline state attribution: a subject's
/// location is asserted independently by two signal classes — a `Coordinates`
/// fix (tagged `au-state:` from its lat/long) and an `Address`/postcode (whose
/// state is parsed by [`crate::util::address_au::state_code`]). This rule
/// reconciles them:
///
/// * **Agreement** — both classes name the *same* state → a corroboration that
///   raises confidence in the location at jurisdiction grain (High when each
///   side speaks with one voice, Medium when one side is mixed).
/// * **Conflict** — the two classes name *disjoint* states (coordinates say
///   QLD, every address says VIC) → a Medium anomaly worth surfacing: travel, a
///   secondary base, or planted/stale data.
///
/// Requires at least one state from *each* class; a scan with only coordinates,
/// or only addresses, yields nothing (there is nothing to cross-check). Pure
/// over the confirmed entity set.
pub(in crate::core::correlator) fn rule_au_056_jurisdiction_cross_check(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};

    // state -> contributing uids, for each signal class.
    let mut coord_states: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut addr_states: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

    for e in entities {
        if let Some(state) = coord_state(e) {
            coord_states.entry(state).or_default().push(e.uid.clone());
        } else if e.kind == EntityKind::Address
            && e.confidence >= 0.50
            && let Some(state) = crate::util::address_au::state_code(&e.value)
        {
            addr_states.entry(state).or_default().push(e.uid.clone());
        }
    }

    if coord_states.is_empty() || addr_states.is_empty() {
        return Vec::new();
    }

    let coord_set: BTreeSet<&'static str> = coord_states.keys().copied().collect();
    let addr_set: BTreeSet<&'static str> = addr_states.keys().copied().collect();
    let shared: Vec<&'static str> = coord_set.intersection(&addr_set).copied().collect();

    let mut uids: Vec<String> = coord_states
        .values()
        .chain(addr_states.values())
        .flatten()
        .cloned()
        .collect();
    uids.sort_unstable();
    uids.dedup();

    let correlation = if let Some(&state) = shared.first() {
        // Agreement. High only when neither class is internally split AND the
        // shared state is the *only* state either class names.
        let unanimous = coord_set.len() == 1 && addr_set.len() == 1;
        let severity = if unanimous {
            Severity::High
        } else {
            Severity::Medium
        };
        Correlation::new(
            "AU-056",
            "Jurisdiction corroborated (coordinate + address)",
            severity,
            format!(
                "Coordinate fix(es) and address/postcode(s) independently place the subject in \
                 {state} — location corroborated at state grain{}",
                if unanimous {
                    String::new()
                } else {
                    format!(
                        " (coordinates: {}; addresses: {})",
                        join_slash(coord_set.iter().copied()),
                        join_slash(addr_set.iter().copied()),
                    )
                }
            ),
            uids,
            scan_id,
            ts,
        )
    } else {
        Correlation::new(
            "AU-056",
            "Jurisdiction conflict (coordinate vs address)",
            Severity::Medium,
            format!(
                "Coordinate fix(es) place the subject in {} but address/postcode(s) say {} — \
                 travel, a secondary base, or planted/stale data",
                join_slash(coord_set.iter().copied()),
                join_slash(addr_set.iter().copied()),
            ),
            uids,
            scan_id,
            ts,
        )
    };

    vec![correlation]
}

/// AU-058 — Professional profile geographic signal (T1591.002).
///
/// AU real estate agent profile URLs embed a suburb-level workplace location in
/// the URL slug — no live HTTP fetch required. ratemyagent.com.au slugs follow
/// `/real-estate-agent/<name>-<suburb>-<id>/`; the suburb token is extracted and
/// surfaced as a geographic signal aligned with MITRE T1591.002 (Business
/// Relationships — physical location inferred from professional context).
pub(in crate::core::correlator) fn rule_au_058_professional_profile_geo(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const PROF_HOSTS: &[&str] = &["ratemyagent.com.au", "homely.com.au", "soho.com.au"];

    let mut out = Vec::new();

    for e in entities_of_kind(entities, EntityKind::Url) {
        if e.confidence < 0.45 {
            continue;
        }
        let url_lower = e.value.to_lowercase();
        let Some(host) = PROF_HOSTS.iter().find(|h| url_lower.contains(*h)) else {
            continue;
        };

        let suburb = if host.contains("ratemyagent") {
            extract_ratemyagent_suburb(&e.value)
        } else {
            None
        };

        let Some(suburb) = suburb else {
            continue;
        };

        out.push(Correlation::new(
            "AU-058",
            "Professional profile geographic signal",
            Severity::Medium,
            format!(
                "Real estate agent profile at {host} indicates subject operates in \
                 '{suburb}' — MITRE T1591.002 (Business Relationships)"
            ),
            vec![e.uid.clone()],
            scan_id,
            ts,
        ));
    }

    out
}

/// Extract the suburb token from a ratemyagent.com.au agent URL slug.
///
/// Pattern: `/real-estate-agent/<name>-<suburb>-<id>/`
/// The trailing ID is stripped; the preceding token is the suburb.
fn extract_ratemyagent_suburb(url: &str) -> Option<String> {
    let path_start = url.find("/real-estate-agent/")?;
    let slug_area = &url[path_start + "/real-estate-agent/".len()..];
    let slug = slug_area
        .trim_end_matches('/')
        .split('?')
        .next()
        .unwrap_or(slug_area);
    let parts: Vec<&str> = slug.split('-').collect();
    if parts.len() < 4 {
        return None;
    }
    let id = *parts.last()?;
    if !id.chars().all(|c| c.is_ascii_alphanumeric()) || id.len() < 2 {
        return None;
    }
    let suburb = parts[parts.len() - 2];
    if suburb.len() >= 4 && suburb.chars().all(|c| c.is_ascii_alphabetic()) {
        Some(suburb.to_string())
    } else {
        None
    }
}
