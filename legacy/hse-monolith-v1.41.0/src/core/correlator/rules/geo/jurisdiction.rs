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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::{BTreeMap, BTreeSet};

    // state -> contributing uids, for each signal class.
    let mut coord_states: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut addr_states: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

    for e in entities {
        if let Some(state) = super::coord_state(e) {
            coord_states.entry(state).or_default().push(e.uid.clone());
        } else if e.kind == EntityKind::Address
            && e.confidence >= 0.50
            // A hosting / WHOIS-registrant datacentre address is the host's
            // location, not the SUBJECT's, so it must not vote a jurisdiction —
            // excluding it here mirrors the coordinate side (`coord_state`) and
            // the sibling AU-018/026/030 address rollups. Without this a datacentre
            // "Sydney NSW" manufactured a false AU-056 agreement (or conflict)
            // against the subject's real interstate address.
            && !is_infrastructure_geo(e)
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
            // Same infrastructure-geo exclusion as AU-056: a hosting/registrant
            // datacentre address is not the subject's jurisdiction, so it must not
            // corroborate (or contradict) the phone region.
            && !is_infrastructure_geo(e)
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

/// Pluralising suffix for a count — `""` for one, `"s"` otherwise.
fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// AU-102 — Phone line-type intelligence (contactability, premises &
/// organisational ties).
///
/// Every AU phone the subject carries encodes a network/contactability class in
/// its leading digits (the ACMA Numbering Plan), and that *type* is
/// portability-proof — only the carrier ports, never the type. Where AU-085
/// reads only the *geographic* class (an area-code region), this profiles
/// *every* class the subject's numbers fall into, turning the phone set into a
/// people + network picture:
///
/// * a **geographic fixed line** (02/03/07/08) physically anchors a dwelling or
///   premises to its area-code region — a location signal;
/// * a **personal mobile** (04) is a direct-contact and SMS/2FA pivot, the line
///   most tightly bound to one individual; two or more is itself a signal;
/// * a **business/service line** (1300/1800/13/190x) ties the subject to an
///   organisation rather than a person — a people→business bridge.
///
/// Fires only when the set carries something beyond a single lone mobile (a
/// premises line, a business/service line, or ≥2 mobiles), so a bare mobile —
/// which the `Phone` entity already speaks for — never manufactures noise.
/// Medium when a premises or organisational line is present; Low for a
/// multiple-mobile-only profile. Phones are deduped by their canonical E.164
/// form, so the same number from two modules counts once. Derived from the
/// value itself (via [`crate::util::address_au::au_phone_line_type`]), so it
/// fires on any AU `Phone` entity. Pure over the confirmed set.
pub(in crate::core::correlator) fn rule_au_102_phone_line_type_profile(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use crate::util::address_au::AuLineType;
    use crate::util::address_au::au_phone_line_type;
    use crate::util::address_au::au_phone_region;
    use crate::util::address_au::normalise_phone;
    use std::collections::{BTreeMap, BTreeSet};

    // Dedup by canonical value so one number imported twice is counted once.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut mobiles: Vec<String> = Vec::new();
    let mut voip: Vec<String> = Vec::new();
    let mut geo_uids: Vec<String> = Vec::new();
    let mut geo_regions: BTreeSet<&'static str> = BTreeSet::new();
    // Business/service line human label -> contributing phone uids.
    let mut biz: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

    for e in entities {
        if e.kind != EntityKind::Phone || e.confidence < 0.50 {
            continue;
        }
        let Some((lt, _label)) = au_phone_line_type(&e.value) else {
            continue;
        };
        let key = normalise_phone(&e.value).unwrap_or_else(|| e.value.clone());
        if !seen.insert(key) {
            continue;
        }
        match lt {
            AuLineType::Mobile => mobiles.push(e.uid.clone()),
            AuLineType::Voip => voip.push(e.uid.clone()),
            AuLineType::GeographicFixed => {
                geo_uids.push(e.uid.clone());
                if let Some((_slug, name, _states)) = au_phone_region(&e.value) {
                    geo_regions.insert(name);
                }
            }
            AuLineType::Freephone => biz
                .entry("freephone (1800)")
                .or_default()
                .push(e.uid.clone()),
            AuLineType::LocalRate => biz
                .entry("local-rate (13/1300)")
                .or_default()
                .push(e.uid.clone()),
            AuLineType::Premium => biz
                .entry("premium-rate (190x)")
                .or_default()
                .push(e.uid.clone()),
        }
    }

    let has_premises = !geo_uids.is_empty();
    let has_business = !biz.is_empty();
    // A single lone mobile is left to the bare Phone entity; only a richer
    // profile (premises, business/service, or multiple mobiles) is a finding.
    if !has_premises && !has_business && mobiles.len() < 2 {
        return Vec::new();
    }

    let mut segs: Vec<String> = Vec::new();
    if !mobiles.is_empty() {
        segs.push(format!(
            "{} personal mobile{}",
            mobiles.len(),
            plural(mobiles.len())
        ));
    }
    if has_premises {
        let region_note = if geo_regions.is_empty() {
            String::new()
        } else {
            format!(
                " (premises-anchored to {})",
                join_slash(geo_regions.iter().copied())
            )
        };
        segs.push(format!(
            "{} geographic fixed line{}{region_note}",
            geo_uids.len(),
            plural(geo_uids.len())
        ));
    }
    if !voip.is_empty() {
        segs.push(format!("{} VoIP line{}", voip.len(), plural(voip.len())));
    }
    for (label, uids) in &biz {
        segs.push(format!(
            "{} {label} business/service line{}",
            uids.len(),
            plural(uids.len())
        ));
    }

    let mut notes: Vec<&str> = Vec::new();
    if has_premises {
        notes.push("the fixed line physically anchors a premises to its area-code region");
    }
    if has_business {
        notes.push("the business/service line ties the subject to an organisation");
    }
    if mobiles.len() >= 2 {
        notes.push("multiple personal mobiles indicate more than one handset/number");
    }

    let severity = if has_premises || has_business {
        Severity::Medium
    } else {
        Severity::Low
    };

    // All contributing phone uids, deduplicated and ordered.
    let mut uids: Vec<String> = Vec::new();
    uids.extend(mobiles);
    uids.extend(voip);
    uids.extend(geo_uids);
    for v in biz.values() {
        uids.extend(v.iter().cloned());
    }
    uids.sort_unstable();
    uids.dedup();

    vec![Correlation::new(
        "AU-102",
        "Phone line-type profile",
        severity,
        format!(
            "Phone line-type profile: {}. {}.",
            segs.join("; "),
            notes.join("; ")
        ),
        uids,
        scan_id,
        ts,
    )]
}
