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
