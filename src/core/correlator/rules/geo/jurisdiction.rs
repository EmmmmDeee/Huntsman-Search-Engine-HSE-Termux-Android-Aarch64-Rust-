use super::*;

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
        if let Some(state) = super::coord_state(e) {
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
                        coord_set.iter().copied().enumerate().fold(
                            String::new(),
                            |mut acc, (i, s)| {
                                if i > 0 {
                                    acc.push('/');
                                }
                                acc.push_str(s);
                                acc
                            },
                        ),
                        addr_set.iter().copied().enumerate().fold(
                            String::new(),
                            |mut acc, (i, s)| {
                                if i > 0 {
                                    acc.push('/');
                                }
                                acc.push_str(s);
                                acc
                            },
                        ),
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
                coord_set
                    .iter()
                    .copied()
                    .enumerate()
                    .fold(String::new(), |mut acc, (i, s)| {
                        if i > 0 {
                            acc.push('/');
                        }
                        acc.push_str(s);
                        acc
                    },),
                addr_set
                    .iter()
                    .copied()
                    .enumerate()
                    .fold(String::new(), |mut acc, (i, s)| {
                        if i > 0 {
                            acc.push('/');
                        }
                        acc.push_str(s);
                        acc
                    },),
            ),
            uids,
            scan_id,
            ts,
        )
    };

    vec![correlation]
}

/// Join an iterator of state/region codes with `/` for a description string.
fn join_slash<'a>(it: impl Iterator<Item = &'a str>) -> String {
    it.enumerate().fold(String::new(), |mut acc, (i, s)| {
        if i > 0 {
            acc.push('/');
        }
        acc.push_str(s);
        acc
    })
}

/// AU-085 — Phone-region jurisdiction cross-check (fixed-line area code vs
/// address / coordinate state).
///
/// The AU numbering plan places a fixed-line phone in one of four geographic
/// regions by its area code (02 → NSW/ACT, 03 → VIC/TAS, 07 → QLD, 08 →
/// SA/WA/NT), and a geographic number cannot port across regions — so the area
/// code physically locates the line. This rule treats that as a *third*,
/// independent jurisdiction signal, alongside the coordinate + address classes
/// AU-056 reconciles, and cross-checks it against where the subject's
/// addresses/coordinates place them:
///
/// * **Corroboration** — a known address/coordinate state lies within the phone
///   region's state set (a 02 line + a NSW address) → the fixed line and the
///   residence agree at state grain.
/// * **Conflict** — the subject has known location states but *none* lies in the
///   phone region's set (a 03/VIC-TAS line, every address in WA) → the landline
///   disagrees with the residence: a business/holiday line, a relocation, or
///   mixed identities — worth surfacing.
///
/// Only AU *geographic* phones contribute (mobiles / freephone have no region).
/// Requires ≥1 phone region AND ≥1 location state, else there is nothing to
/// check. The region is derived from the phone *value* (via
/// [`crate::util::address_au::au_phone_region`]), so it fires on any AU Phone
/// entity — imported numbers too, not only `phone_au`-tagged ones. Pure.
pub(in crate::core::correlator) fn rule_au_085_phone_region_jurisdiction(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};

    // The union of state codes implied by every AU geographic phone, the region
    // names they name, and the phone uids — the phone jurisdiction class.
    let mut phone_states: BTreeSet<&'static str> = BTreeSet::new();
    let mut regions: BTreeSet<&'static str> = BTreeSet::new();
    let mut phone_uids: Vec<String> = Vec::new();
    // The location jurisdiction class: address + coordinate states → uids.
    let mut loc_states: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

    for e in entities {
        if e.kind == EntityKind::Phone
            && e.confidence >= 0.50
            && let Some((_slug, name, states)) = crate::util::address_au::au_phone_region(&e.value)
        {
            regions.insert(name);
            phone_states.extend(states.iter().copied());
            phone_uids.push(e.uid.clone());
        } else if let Some(state) = super::coord_state(e) {
            loc_states.entry(state).or_default().push(e.uid.clone());
        } else if e.kind == EntityKind::Address
            && e.confidence >= 0.50
            && let Some(state) = crate::util::address_au::state_code(&e.value)
        {
            loc_states.entry(state).or_default().push(e.uid.clone());
        }
    }

    if phone_states.is_empty() || loc_states.is_empty() {
        return Vec::new();
    }

    let loc_set: BTreeSet<&'static str> = loc_states.keys().copied().collect();
    let shared: Vec<&'static str> = phone_states.intersection(&loc_set).copied().collect();
    let region_list = join_slash(regions.iter().copied());

    let correlation = if !shared.is_empty() {
        // Agreement: attach the phone uids + the uids of the matching states.
        let mut uids = phone_uids.clone();
        for s in &shared {
            if let Some(v) = loc_states.get(s) {
                uids.extend(v.iter().cloned());
            }
        }
        uids.sort_unstable();
        uids.dedup();
        Correlation::new(
            "AU-085",
            "Phone region corroborates location",
            Severity::Medium,
            format!(
                "An AU fixed-line area code ({region_list} region) and the subject's \
                 address/coordinate jurisdiction independently agree on {} — location \
                 corroborated at state grain",
                join_slash(shared.iter().copied()),
            ),
            uids,
            scan_id,
            ts,
        )
    } else {
        // Conflict: every known location state is outside the phone region.
        let mut uids = phone_uids.clone();
        uids.extend(loc_states.values().flatten().cloned());
        uids.sort_unstable();
        uids.dedup();
        Correlation::new(
            "AU-085",
            "Phone region conflicts with location",
            Severity::Medium,
            format!(
                "An AU fixed-line area code ({region_list} region, states {}) but every known \
                 address/coordinate places the subject in {} — a business/holiday line, a \
                 relocation, or mixed identities",
                join_slash(phone_states.iter().copied()),
                join_slash(loc_set.iter().copied()),
            ),
            uids,
            scan_id,
            ts,
        )
    };

    vec![correlation]
}
