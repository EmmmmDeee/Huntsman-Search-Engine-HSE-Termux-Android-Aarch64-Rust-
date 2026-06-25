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
//!
//! All three run on the confirmed (candidate-filtered, quarantine-excluded)
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
