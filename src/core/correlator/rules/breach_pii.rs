//! AU correlation rules — breach/stealer PII intelligence.
//!
//! These rules mine the structured fields that breach, stealer-log and other
//! leak modules store as **evidence attributes** on the subject's confirmed
//! entities — the data already collected, just not yet surfaced as findings:
//!
//! * [`rule_au_073_subject_date_of_birth`] — the subject's date of birth,
//!   corroborated across sources (the core identifier that disambiguates
//!   same-name people — the namesake failure class).
//! * [`rule_au_074_au_government_id_exposure`] — exposure of an Australian
//!   government identifier (TFN / Medicare / Centrelink CRN / driver licence /
//!   passport), the most serious identity-theft signal, validated by
//!   format + checksum.
//! * [`rule_au_075_named_associate`] — a named relative/associate carried in a
//!   breach or stealer record (spouse, next-of-kin, emergency contact, the
//!   stealer-log owner), linking real people to the subject.
//! * [`rule_au_090_au_jurisdiction`] — the subject's Australian state/territory
//!   asserted by a breach `state` / state-of-issue field (the Optus/Medibank
//!   licence + address dumps carry it), resolved to a canonical AU jurisdiction
//!   and cross-checked for agreement vs conflict — a people-centric geo anchor
//!   that complements the entity-level cross-checks (AU-056/085).
//! * [`rule_au_091_au_postcode_locality`] — the subject's residential postcode
//!   mined from a breach `postcode` field, resolved offline to its state and a
//!   gazetteer coordinate — a locality anchor finer than AU-090's state grain.
//! * [`rule_au_092_breach_locality_footprint_crosscheck`] — cross-checks the
//!   state implied by the breach `state`/`postcode` fields (AU-090/091) against
//!   the geolocated coordinate/address footprint: agreement corroborates
//!   residency, disjoint states flag stale data / a move / a namesake.
//! * [`rule_au_093_au_address_from_breach`] — assembles the subject's suburb (or
//!   full residential address) from the co-located street/suburb/state/postcode
//!   fields of one breach record, offline-geocoded — the dwelling-grade locator
//!   the single-field AU-090/091 rules can't reach.
//!
//! All run on the confirmed (candidate-filtered, quarantine-excluded)
//! view, so breach co-occurrence strangers never leak in. See `super`
//! (rules/mod.rs) for the shared helpers.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// The corroboration bucket a breach-PII rule accumulates per distinct value:
/// the distinct evidence `sources` that assert it and the entity `uids` carrying
/// it, both ordered sets for deterministic output.
type SourcesAndUids = (BTreeSet<String>, BTreeSet<String>);

/// Scan every entity's evidence for attributes whose key matches (ASCII
/// case-insensitively) any of `keys`, yielding `(value, source, uid)` per hit.
/// Accumulated multi-values (the `"a; b"` form the evidence store produces on a
/// repeated key) are split so each underlying value is seen individually.
fn scan_evidence<'a>(entities: &'a [Entity], keys: &[&str]) -> Vec<(String, &'a str, &'a str)> {
    let mut out = Vec::new();
    for e in entities {
        for ev in &e.evidence {
            for (k, v) in &ev.attributes {
                if keys.iter().any(|key| k.eq_ignore_ascii_case(key)) {
                    for part in v.split("; ") {
                        let part = part.trim();
                        if !part.is_empty() {
                            out.push((part.to_string(), ev.source.as_str(), e.uid.as_str()));
                        }
                    }
                }
            }
        }
    }
    out
}

// ── AU-073 — Subject date of birth ───────────────────────────────────────────

const DOB_KEYS: &[&str] = &[
    "date_of_birth",
    "dob",
    "birthdate",
    "birth_date",
    "dateofbirth",
    "birthday",
    "born",
];

/// Normalise a breach DOB to a canonical `YYYY-MM-DD` when it carries an ISO date
/// (the dominant breach format, including ISO date-times like
/// `1980-11-08T00:00:00`); otherwise return the trimmed value verbatim (a
/// non-ISO form like `08/11/1980` is left as-is rather than guess DD-vs-MM).
fn normalise_dob(raw: &str) -> Option<String> {
    let s = raw.trim();
    let b = s.as_bytes();
    if s.len() >= 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
    {
        return Some(s[..10].to_string());
    }
    (!s.is_empty()).then(|| s.to_string())
}

/// AU-073 — the subject's date of birth, corroborated across sources.
///
/// DOB is the single strongest disambiguator between same-name people, yet it
/// sits unused in breach `date_of_birth` fields. This surfaces each distinct DOB
/// with the number of INDEPENDENT sources that assert it: two or more agreeing
/// sources is a Verified-grade identity anchor (High); a single source is a lead
/// (Medium). Conflicting DOBs each emit their own finding, so a namesake's DOB
/// is visible as the minority claim rather than silently averaged in.
pub(in crate::core::correlator) fn rule_au_073_subject_date_of_birth(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // dob → (distinct sources, uids), both ordered for determinism.
    let mut by_dob: BTreeMap<String, SourcesAndUids> = BTreeMap::new();
    for (raw, source, uid) in scan_evidence(entities, DOB_KEYS) {
        let Some(dob) = normalise_dob(&raw) else {
            continue;
        };
        let entry = by_dob.entry(dob).or_default();
        entry.0.insert(source.to_string());
        entry.1.insert(uid.to_string());
    }

    by_dob
        .into_iter()
        .map(|(dob, (sources, uids))| {
            let n = sources.len();
            let severity = if n >= 2 {
                Severity::High
            } else {
                Severity::Medium
            };
            Correlation {
                rule_id: "AU-073".into(),
                rule_name: "Subject date of birth".into(),
                severity,
                description: format!(
                    "Subject date of birth {dob} — asserted by {n} independent source(s) \
                     ({}); the strongest disambiguator from same-name namesakes",
                    sources.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                entity_uids: uids.into_iter().collect(),
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

// ── AU-074 — Australian government-ID exposure ───────────────────────────────

/// Australian Tax File Number — 9 digits, weighted mod-11 checksum.
fn is_valid_tfn(value: &str) -> bool {
    let d: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() != 9 {
        return false;
    }
    const W: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum: u32 = d.iter().zip(W).map(|(x, w)| x * w).sum();
    sum.is_multiple_of(11)
}

/// Medicare card number — 10 digits, first digit 2-6, 9th digit is the
/// weighted mod-10 check of the first eight (the 10th is the issue number).
fn is_valid_medicare(value: &str) -> bool {
    let d: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() < 10 || !(2..=6).contains(&d[0]) {
        return false;
    }
    const W: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
    let sum: u32 = d[..8].iter().zip(W).map(|(x, w)| x * w).sum();
    sum % 10 == d[8]
}

/// Mask all but the last three characters of a sensitive value for the finding
/// text — the full value stays in the entity's evidence (operator full-fidelity).
fn mask_tail(value: &str) -> String {
    let digits: String = value.chars().filter(char::is_ascii_alphanumeric).collect();
    let n = digits.len();
    if n <= 3 {
        return "***".to_string();
    }
    format!("{}{}", "*".repeat(n - 3), &digits[n - 3..])
}

/// One Australian government-ID class: the evidence keys it appears under, a
/// human label, and an optional structural validator.
struct GovId {
    keys: &'static [&'static str],
    label: &'static str,
    validate: Option<fn(&str) -> bool>,
}

const GOV_IDS: &[GovId] = &[
    GovId {
        keys: &["tfn", "tax_file_number", "taxfilenumber", "tax_file_no"],
        label: "Tax File Number",
        validate: Some(is_valid_tfn),
    },
    GovId {
        keys: &["medicare", "medicare_number", "medicare_no", "medicarecard"],
        label: "Medicare number",
        validate: Some(is_valid_medicare),
    },
    GovId {
        keys: &[
            "crn",
            "centrelink",
            "centrelink_crn",
            "customer_reference_number",
        ],
        label: "Centrelink CRN",
        validate: None,
    },
    GovId {
        keys: &[
            "drivers_licence",
            "driver_licence",
            "drivers_license",
            "driver_license",
            "licence_number",
            "license_number",
            "dl_number",
        ],
        label: "driver licence",
        validate: None,
    },
    GovId {
        keys: &["passport", "passport_number", "passport_no"],
        label: "passport number",
        validate: None,
    },
];

/// AU-074 — exposure of an Australian government identifier in breach/stealer
/// data.
///
/// The most serious identity-theft signal for a person: a leaked TFN, Medicare,
/// Centrelink CRN, driver licence, or passport (the Optus/Medibank exposure
/// class). Detection is by the breach FIELD KEY (robust — the dump literally
/// names the field `tfn`/`medicare`/…), confirmed by a format/checksum where one
/// is defined, so a mislabelled number can't fabricate a CRITICAL finding. The
/// value is masked in the finding text; the full value remains in the entity's
/// evidence under the operator full-fidelity policy.
pub(in crate::core::correlator) fn rule_au_074_au_government_id_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for gid in GOV_IDS {
        // (masked value, sources, uids) per distinct underlying value.
        let mut found: BTreeMap<String, SourcesAndUids> = BTreeMap::new();
        for (raw, source, uid) in scan_evidence(entities, gid.keys) {
            if gid.validate.is_some_and(|v| !v(&raw)) {
                continue; // key matched but the value fails its checksum/format
            }
            let entry = found.entry(raw).or_default();
            entry.0.insert(source.to_string());
            entry.1.insert(uid.to_string());
        }
        for (raw, (sources, uids)) in found {
            out.push(Correlation {
                rule_id: "AU-074".into(),
                rule_name: "Australian government-ID exposure".into(),
                severity: Severity::Critical,
                description: format!(
                    "Subject's {} ({}) exposed in {} breach source(s) — critical \
                     identity-theft risk; verify and advise the subject",
                    gid.label,
                    mask_tail(&raw),
                    sources.len()
                ),
                entity_uids: uids.into_iter().collect(),
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }
    out
}

// ── AU-075 — Named associate from a breach/stealer record ────────────────────

/// Relationship evidence keys mapped to the relationship they assert.
const ASSOCIATE_KEYS: &[(&str, &str)] = &[
    ("spouse", "spouse"),
    ("partner", "partner"),
    ("husband", "spouse"),
    ("wife", "spouse"),
    ("next_of_kin", "next of kin"),
    ("nextofkin", "next of kin"),
    ("emergency_contact", "emergency contact"),
    ("emergency_contact_name", "emergency contact"),
    ("father", "father"),
    ("mother", "mother"),
    ("parent", "parent"),
    ("guardian", "guardian"),
    ("dependent", "dependent"),
    ("relationship", "relation"),
    ("owner_name", "stealer-log owner"),
];

/// AU-075 — a named relative/associate carried in a breach or stealer record.
///
/// Breach and stealer dumps often carry an explicit related person — a spouse,
/// next-of-kin, emergency contact, or (for a stealer log) the machine OWNER
/// whose accounts these are. This surfaces those named links to the subject —
/// genuine relationship intelligence that the geo/surname family rules
/// (AU-049/051/061) can't reach because the tie is stated, not inferred.
pub(in crate::core::correlator) fn rule_au_075_named_associate(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // (name, relationship) → (sources, uids).
    let mut assoc: BTreeMap<(String, &'static str), SourcesAndUids> = BTreeMap::new();
    for &(key, relation) in ASSOCIATE_KEYS {
        for (raw, source, uid) in scan_evidence(entities, &[key]) {
            // A plausible person name: at least two letters, contains a letter,
            // not a lone token like "self"/"n/a".
            let name = raw.trim();
            let lower = name.to_ascii_lowercase();
            if name.chars().filter(|c| c.is_alphabetic()).count() < 2
                || matches!(lower.as_str(), "self" | "n/a" | "na" | "none" | "unknown")
            {
                continue;
            }
            let entry = assoc.entry((name.to_string(), relation)).or_default();
            entry.0.insert(source.to_string());
            entry.1.insert(uid.to_string());
        }
    }

    assoc
        .into_iter()
        .map(|((name, relation), (sources, uids))| Correlation {
            rule_id: "AU-075".into(),
            rule_name: "Named associate from breach record".into(),
            severity: Severity::Medium,
            description: format!(
                "Subject linked to '{name}' ({relation}) in {} breach/stealer record(s) — \
                 a stated relationship, not a geo/surname inference",
                sources.len()
            ),
            entity_uids: uids.into_iter().collect(),
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

// ── AU-090 — Australian jurisdiction from a breach/record state field ─────────

/// Breach/record evidence keys that assert an Australian state or territory —
/// either the subject's residential state or the issuing state of a state-issued
/// identity document (driver licence, proof-of-age card). Deliberately specific:
/// the bare ambiguous keys (`region`, `area`) are excluded, and every value is
/// re-resolved through [`crate::util::address_au::state_code`], which only
/// returns a code for a genuine AU state/abbreviation/postcode — so a non-AU
/// `state` field (a US "California", a status flag) yields nothing rather than a
/// false jurisdiction.
const JURISDICTION_KEYS: &[&str] = &[
    "state",
    "state_territory",
    "address_state",
    "state_of_residence",
    "residential_state",
    "state_of_issue",
    "stateofissue",
    "issuing_state",
    "issue_state",
    "licence_state",
    "license_state",
    "dl_state",
    "card_state",
];

/// AU-090 — the subject's Australian state/territory, asserted by a breach record.
///
/// AU breach and identity-document dumps (the Optus/Medibank licence + address
/// class) carry an explicit `state` / state-of-issue field that sits unused
/// alongside the licence number AU-074 already surfaces. This resolves each such
/// field to a canonical AU jurisdiction and emits it as a people-centric geo
/// anchor: two or more independent sources naming the same state is a
/// Verified-grade residency signal (High); a single source is a lead (Medium).
///
/// Each distinct state emits its own finding, so a recent interstate move — or a
/// merged same-name namesake — shows up as a *second* jurisdiction claim rather
/// than being silently averaged away. This complements the entity-level
/// jurisdiction cross-checks (AU-056 coordinate-vs-address, AU-085 phone-region)
/// by mining the structured field directly, reaching state assertions that never
/// became an `Address` entity. Runs on the confirmed view.
pub(in crate::core::correlator) fn rule_au_090_au_jurisdiction(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // canonical AU state code → (distinct sources, uids), ordered for determinism.
    let mut by_state: BTreeMap<&'static str, SourcesAndUids> = BTreeMap::new();
    for (raw, source, uid) in scan_evidence(entities, JURISDICTION_KEYS) {
        let Some(state) = crate::util::address_au::state_code(&raw) else {
            continue; // not a recognisable Australian state/territory
        };
        let entry = by_state.entry(state).or_default();
        entry.0.insert(source.to_string());
        entry.1.insert(uid.to_string());
    }

    let multi = by_state.len() > 1;
    by_state
        .into_iter()
        .map(|(state, (sources, uids))| {
            let n = sources.len();
            let severity = if n >= 2 {
                Severity::High
            } else {
                Severity::Medium
            };
            let note = if multi {
                " (one of multiple state claims — interstate move or same-name namesake)"
            } else {
                ""
            };
            Correlation {
                rule_id: "AU-090".into(),
                rule_name: "Australian jurisdiction from breach record".into(),
                severity,
                description: format!(
                    "Subject's Australian jurisdiction {state} — asserted by {n} breach \
                     record source(s) ({}){note}; a residency/issuing-state geo anchor \
                     that cross-checks the address/coordinate footprint",
                    sources.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                entity_uids: uids.into_iter().collect(),
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

// ── AU-091 — Australian residential locality from a breach postcode field ─────

/// Breach/record evidence keys that carry the subject's postal code. The US
/// `zip*` keys are excluded — a 5-digit US zip never matches the 4-digit AU
/// gate below anyway, and dropping them keeps the intent AU-specific.
const POSTCODE_KEYS: &[&str] = &[
    "postcode",
    "post_code",
    "postal_code",
    "postalcode",
    "postcode_au",
    "pcode",
];

/// The first 4-digit run in `raw` that resolves to an *assigned* Australian
/// postcode, with the state/territory it falls in. A 4-digit token is required
/// (a 5-digit US zip is skipped) and it must land in a real AU postcode range
/// (via [`crate::util::address_au::state_code`]), so incidental 4-digit noise —
/// a year, a unit count — yields nothing. Pure.
fn au_postcode_and_state(raw: &str) -> Option<(String, &'static str)> {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let run = &raw[start..i];
            if run.len() == 4
                && let Some(state) = crate::util::address_au::state_code(run)
            {
                return Some((run.to_string(), state));
            }
        } else {
            i += 1;
        }
    }
    None
}

/// AU-091 — the subject's Australian residential locality, mined from a breach
/// `postcode` field and resolved offline.
///
/// A postcode is the finest free residential locator in the breach-field family:
/// where AU-090 surfaces the state, this surfaces the postcode *within* it —
/// resolved to its state and an offline gazetteer coordinate
/// ([`crate::util::city_coords::city_coords`], whole-AU-postcode-space, no
/// network) so the analyst gets a mappable point, not just a number. Two or more
/// independent sources naming the same postcode is a Verified-grade locality
/// anchor (High); a single source is a lead (Medium). Each distinct postcode
/// emits its own finding, so a second residence — or a same-name namesake — is
/// visible as a separate claim rather than averaged away.
///
/// Complements AU-090 (state grain) and the entity-level geo rules by reaching
/// the raw `postcode` attribute directly, including the records whose postcode
/// never became an `Address` entity. Runs on the confirmed view.
///
/// (AU postcodes overlap New Zealand's 4-digit range; consistent with the rest
/// of the AU-focused engine, a 4-digit `postcode` in an assigned AU range is
/// read as Australian.)
pub(in crate::core::correlator) fn rule_au_091_au_postcode_locality(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // postcode → (state, distinct sources, uids).
    let mut by_pc: BTreeMap<String, (&'static str, BTreeSet<String>, BTreeSet<String>)> =
        BTreeMap::new();
    for (raw, source, uid) in scan_evidence(entities, POSTCODE_KEYS) {
        let Some((pc, state)) = au_postcode_and_state(&raw) else {
            continue;
        };
        let entry = by_pc
            .entry(pc)
            .or_insert_with(|| (state, BTreeSet::new(), BTreeSet::new()));
        entry.1.insert(source.to_string());
        entry.2.insert(uid.to_string());
    }

    let multi = by_pc.len() > 1;
    by_pc
        .into_iter()
        .map(|(pc, (state, sources, uids))| {
            let n = sources.len();
            let severity = if n >= 2 {
                Severity::High
            } else {
                Severity::Medium
            };
            let coord = crate::util::city_coords::city_coords(&pc)
                .map(|(lat, lon)| format!(" ≈ {lat:.3},{lon:.3} (offline)"))
                .unwrap_or_default();
            let note = if multi {
                " (one of multiple postcode claims — second residence or same-name namesake)"
            } else {
                ""
            };
            Correlation {
                rule_id: "AU-091".into(),
                rule_name: "Australian postcode locality".into(),
                severity,
                description: format!(
                    "Subject's Australian postcode {pc} ({state}){coord} — asserted by {n} \
                     breach record source(s) ({}){note}; a residential locality anchor finer \
                     than the state",
                    sources.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                entity_uids: uids.into_iter().collect(),
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

// ── AU-092 — Breach locality vs geolocated footprint cross-check ──────────────

/// The state(s) the breach `state` / state-of-issue and `postcode` fields imply
/// for the subject — the AU-090 + AU-091 signal, reduced to a `state → uids`
/// map. Pure over the evidence attributes.
fn breach_field_states(entities: &[Entity]) -> BTreeMap<&'static str, BTreeSet<String>> {
    let mut states: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    for (raw, _source, uid) in scan_evidence(entities, JURISDICTION_KEYS) {
        if let Some(state) = crate::util::address_au::state_code(&raw) {
            states.entry(state).or_default().insert(uid.to_string());
        }
    }
    for (raw, _source, uid) in scan_evidence(entities, POSTCODE_KEYS) {
        if let Some((_pc, state)) = au_postcode_and_state(&raw) {
            states.entry(state).or_default().insert(uid.to_string());
        }
    }
    states
}

/// The state(s) the **geolocated footprint** asserts: a `Coordinates` entity's
/// state (its `au-state:` tag, else its lat/long via [`super::geo::coord_state`])
/// and a confident `Address` entity's parsed state. `state → uids`.
fn footprint_states(entities: &[Entity]) -> BTreeMap<&'static str, BTreeSet<String>> {
    let mut states: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    for e in entities {
        if let Some(state) = super::geo::coord_state(e) {
            states.entry(state).or_default().insert(e.uid.clone());
        } else if e.kind == EntityKind::Address
            && e.confidence >= 0.50
            && let Some(state) = crate::util::address_au::state_code(&e.value)
        {
            states.entry(state).or_default().insert(e.uid.clone());
        }
    }
    states
}

/// Render a state set as a `/`-joined string for a finding (`"NSW/VIC"`).
fn join_states(set: &BTreeSet<&'static str>) -> String {
    set.iter().copied().collect::<Vec<_>>().join("/")
}

/// AU-092 — does the locality the breach record *states* match where the subject
/// is *geolocated*?
///
/// AU-090/091 read the subject's state/postcode straight out of breach fields;
/// the geo layer independently places the subject by coordinate and address.
/// This cross-checks the two — the breach-field analogue of AU-056
/// (coordinate-vs-address):
///
/// * **Agreement** — a breach-stated state and the geolocated footprint name the
///   *same* state → residency corroborated across two independent signal classes
///   (High when each side speaks with one voice, Medium when one is mixed).
/// * **Conflict** — the breach fields say one state, the footprint says a
///   disjoint one → a Medium anomaly: stale breach data, a relocation, or a
///   same-name namesake merged into the graph.
///
/// Requires at least one state from *each* side; a scan with only breach fields,
/// or only a geo footprint, yields nothing. Pure over the confirmed entity set.
pub(in crate::core::correlator) fn rule_au_092_breach_locality_footprint_crosscheck(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let breach = breach_field_states(entities);
    if breach.is_empty() {
        return Vec::new();
    }
    let footprint = footprint_states(entities);
    if footprint.is_empty() {
        return Vec::new();
    }

    let bset: BTreeSet<&'static str> = breach.keys().copied().collect();
    let fset: BTreeSet<&'static str> = footprint.keys().copied().collect();
    let shared: Vec<&'static str> = bset.intersection(&fset).copied().collect();

    let mut uids: BTreeSet<String> = BTreeSet::new();
    for s in breach.values().chain(footprint.values()) {
        uids.extend(s.iter().cloned());
    }
    let uids: Vec<String> = uids.into_iter().collect();

    let correlation = if let Some(&state) = shared.first() {
        let unanimous = bset.len() == 1 && fset.len() == 1;
        let severity = if unanimous {
            Severity::High
        } else {
            Severity::Medium
        };
        Correlation {
            rule_id: "AU-092".into(),
            rule_name: "Breach locality corroborated by footprint".into(),
            severity,
            description: format!(
                "Breach-record locality and the geolocated footprint independently place the \
                 subject in {state} — residency corroborated across breach fields and geo signals{}",
                if unanimous {
                    String::new()
                } else {
                    format!(
                        " (breach: {}; footprint: {})",
                        join_states(&bset),
                        join_states(&fset)
                    )
                }
            ),
            entity_uids: uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        }
    } else {
        Correlation {
            rule_id: "AU-092".into(),
            rule_name: "Breach locality conflicts with footprint".into(),
            severity: Severity::Medium,
            description: format!(
                "Breach records place the subject in {} but the geolocated footprint is {} — \
                 stale breach data, a relocation, or a same-name namesake",
                join_states(&bset),
                join_states(&fset)
            ),
            entity_uids: uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        }
    };
    vec![correlation]
}

// ── AU-093 — Australian suburb / residential address assembled from a record ──

/// Breach/record keys naming the locality (suburb/city). `city` is included but
/// only ever assembled together with a co-located AU state/postcode in the same
/// record, so a non-AU city never fires this on its own.
const SUBURB_KEYS: &[&str] = &["suburb", "locality", "town", "suburb_town", "city"];

/// Breach/record keys naming the street line of a residential address — the
/// component that lifts a suburb-grade locality to a dwelling-grade one.
const STREET_KEYS: &[&str] = &[
    "street",
    "street_address",
    "streetaddress",
    "street_name",
    "address_line_1",
    "addressline1",
    "address1",
    "residential_address",
    "home_address",
];

/// First non-empty attribute value whose key matches (ASCII case-insensitively)
/// any of `keys`, within a single evidence record. Trimmed.
fn record_attr<'a>(attrs: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    attrs.iter().find_map(|(k, v)| {
        if keys.iter().any(|key| k.eq_ignore_ascii_case(key)) {
            let t = v.trim();
            (!t.is_empty()).then_some(t)
        } else {
            None
        }
    })
}

/// AU-093 — the subject's Australian suburb (or full residential address),
/// assembled from the co-located fields of a single breach record.
///
/// AU-090/091 surface the state and postcode in isolation; this adds the
/// component they ignore — the **suburb/city name** — and, when the record also
/// carries a street line, assembles a full **dwelling-grade** address. Because
/// the parts are taken from the *same* evidence record they describe one place,
/// not a merge of two. The result is resolved to an offline gazetteer coordinate
/// ([`crate::util::city_coords::city_coords`], no network) so it lands on a map.
///
/// * **Street present** → a residential address (High — the highest-value free
///   people-locator there is).
/// * **Suburb only** → a suburb-level locality (Medium — still far finer than the
///   bare state/postcode of AU-090/091).
///
/// Each distinct assembled address emits once, with its corroborating sources.
/// A suburb is required (so this never merely restates AU-090/091), together
/// with a state or postcode from the same record. Runs on the confirmed view.
/// (Per the AU-091 note, a 4-digit postcode in an assigned AU range is read as
/// Australian; the suburb requirement further constrains the match.)
pub(in crate::core::correlator) fn rule_au_093_au_address_from_breach(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // assembled address → (has_street, distinct sources, uids).
    let mut by_addr: BTreeMap<String, (bool, BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for e in entities {
        for ev in &e.evidence {
            let attrs = &ev.attributes;
            let Some(suburb) =
                record_attr(attrs, SUBURB_KEYS).filter(|s| s.chars().any(char::is_alphabetic))
            else {
                continue;
            };
            // State: an explicit state field wins; else derive it from a postcode.
            let pc = record_attr(attrs, POSTCODE_KEYS).and_then(au_postcode_and_state);
            let Some(state) = record_attr(attrs, JURISDICTION_KEYS)
                .and_then(crate::util::address_au::state_code)
                .or(pc.as_ref().map(|(_, s)| *s))
            else {
                continue;
            };
            let street =
                record_attr(attrs, STREET_KEYS).filter(|s| s.chars().any(char::is_alphabetic));

            let mut parts: Vec<String> = Vec::new();
            if let Some(st) = street {
                parts.push(st.to_string());
            }
            parts.push(suburb.to_string());
            parts.push(match pc.as_ref() {
                Some((p, _)) => format!("{state} {p}"),
                None => state.to_string(),
            });
            let addr = parts.join(", ");

            let entry = by_addr
                .entry(addr)
                .or_insert_with(|| (false, BTreeSet::new(), BTreeSet::new()));
            entry.0 |= street.is_some();
            entry.1.insert(ev.source.clone());
            entry.2.insert(e.uid.clone());
        }
    }

    by_addr
        .into_iter()
        .map(|(addr, (has_street, sources, uids))| {
            let coord = crate::util::city_coords::city_coords(&addr)
                .map(|(lat, lon)| format!(" ≈ {lat:.3},{lon:.3} (offline)"))
                .unwrap_or_default();
            let (name, severity, grade) = if has_street {
                (
                    "Australian residential address from breach record",
                    Severity::High,
                    "a dwelling-grade locator",
                )
            } else {
                (
                    "Australian suburb locality from breach record",
                    Severity::Medium,
                    "a suburb-level locality, finer than the bare state/postcode",
                )
            };
            Correlation {
                rule_id: "AU-093".into(),
                rule_name: name.into(),
                severity,
                description: format!(
                    "Subject's Australian locality {addr}{coord} — assembled from {} breach \
                     record source(s) ({}); {grade}",
                    sources.len(),
                    sources.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                entity_uids: uids.into_iter().collect(),
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}
