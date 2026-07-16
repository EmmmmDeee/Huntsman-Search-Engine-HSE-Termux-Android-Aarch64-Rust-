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
//! * [`rule_au_098_residency_consensus`] — fuses every independent state-grain
//!   location class (coordinate, address, breach record, phone area code) into a
//!   single jurisdiction verdict, scored by cross-class agreement — the
//!   gold-standard, corroborated geolocation finding.
//! * [`rule_au_101_identity_resolution`] — the people-centric analogue of
//!   AU-098: fuses every independent identity facet class (name, email, phone,
//!   username, address, business id, DOB, government ID) into a single
//!   resolution-breadth verdict, the gold-standard subject-resolution finding.
//! * [`rule_au_104_bank_account_exposure`] — resolves an exposed Australian BSB
//!   to its financial institution (the AusPayNet allocation), escalating to a
//!   full account-credential finding when a bank account number co-occurs — a
//!   people-centric financial-attribution signal for almost every AU adult.
//! * [`rule_au_105_credential_reuse`] — the same secret reused across two or more
//!   distinct breaches: the subject's credential-stuffing / account-takeover
//!   surface, surfaced without ever echoing the secret value.
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

/// Genuine breach / stealer-log evidence sources: the collection modules that
/// import **leaked** records carrying structured PII (name, DOB, address,
/// gov-ID, credentials). A breach-PII rule MUST consult this before counting an
/// evidence record's `source` as a "breach record source" or labelling a value
/// breach-sourced.
///
/// The geo and AU-registry *enrichment* passes attach the SAME
/// `state`/`postcode`/`suburb`/`city`/`street` attributes these rules key on — a
/// reverse geocode (`geocode` / `photon`), and registry enrichers such as
/// `au_property` / `au_electoral` / `abn_lookup` / `au_people` — so without this
/// gate a reverse-geocoded or registry-sourced locality was assembled and
/// mislabelled, e.g. a live phone scan produced "assembled from 1 breach record
/// source(s) (geocode)" for a bare AU mobile. Allow-list (default-deny) so a
/// newly added enrichment source can never leak in.
///
/// Delegates to the canonical provider-family taxonomy ([`super::source_family`],
/// which substring-matches the breach/stealer/leak corpora — `hibp`, `dehashed`,
/// `oathnet*`, `xposed*`, `leakcheck`, `leakix`, `snusbase`, `intelx`, `pwned*`,
/// `hudsonrock`, and any `*breach*` / `*stealer*` source) so this predicate can
/// never drift from the rest of the correlator — with ONE correction:
/// `source_family` files `see_know` (SeekNow, a rich breach source) under
/// `"presence"` (its name matches a presence needle first), so it is added back
/// explicitly, or real SeekNow breach localities/addresses would silently
/// vanish. Every non-breach enricher that leaks the same attributes — `geocode`,
/// `photon`, `search_engines`, and the AU registries (`au_property`,
/// `au_electoral`, `abn_lookup`, `au_people`) — is classified non-breach by
/// `source_family` and so is correctly rejected. Pure.
fn is_breach_source(name: &str) -> bool {
    super::source_family(name) == "breach"
        || name.eq_ignore_ascii_case("see_know")
        || name.eq_ignore_ascii_case("see-know")
}

// ── AU-073 — Subject date of birth ───────────────────────────────────────────

/// The canonical DOB evidence-attribute-key vocabulary — also the single
/// source `core::exposure`'s sensitive-disclosure scan uses (see that
/// module's doc comment), so a spelling added here is instantly visible to
/// both consumers instead of silently undercounting one of them.
pub(crate) const DOB_KEYS: &[&str] = &[
    "date_of_birth",
    "dob",
    "birthdate",
    "birth_date",
    "dateofbirth",
    "birthday",
    "born",
    // OathNet renders its `Date Birth` field as `date_birth`; SeekNow/IntelVault
    // also emit `date_birth` — a major breach source that the older key list missed.
    "date_birth",
    "datebirth",
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

/// Derive a person's whole-year age from a canonical `YYYY-MM-DD` date of birth
/// as of `now_unix` (Unix seconds), or `None` for an unparseable / non-ISO date or
/// a future DOB. Dependency-free (no `chrono`): converts the calendar DOB to a day
/// count via Howard Hinnant's `days_from_civil`, then divides the elapsed seconds
/// by the mean Gregorian year (365.2425 d) — exact to the year for any plausible
/// DOB. Age is the single most stable people-centric identity attribute (it
/// disambiguates same-name namesakes and dates a footprint), yet a bare `YYYY-MM-DD`
/// leaves it implicit; this makes it explicit. Pure.
pub(in crate::core::correlator) fn age_from_dob(dob: &str, now_unix: u64) -> Option<u32> {
    let b = dob.as_bytes();
    // Require a strict ASCII `YYYY-MM-DD` head before slicing. The dash + length
    // check alone let a value whose "digits" were actually multibyte UTF-8 — a
    // breach DOB such as `1980-11-€X`, where `€` is three bytes at indices 8..11 —
    // reach `dob[8..10]`, which then sliced through the middle of the char and
    // panicked (the correlator runs outside the engine's per-module catch_unwind,
    // so that crashed the whole scan). Validating each digit run on the raw bytes
    // keeps every str-slice below on an ASCII char boundary AND in range
    // (`dob.len() >= 10` guarantees byte indices 0..10 exist).
    if dob.len() < 10
        || b[4] != b'-'
        || b[7] != b'-'
        || !b[0..4].iter().all(u8::is_ascii_digit)
        || !b[5..7].iter().all(u8::is_ascii_digit)
        || !b[8..10].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let y: i64 = dob[0..4].parse().ok()?;
    let m: i64 = dob[5..7].parse().ok()?;
    let d: i64 = dob[8..10].parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // days_from_civil (Hinnant): days since the Unix epoch (1970-01-01).
    let yy = y - i64::from(m <= 2);
    let era = (if yy >= 0 { yy } else { yy - 399 }) / 400;
    let yoe = yy - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let dob_unix = days * 86_400;
    let now = i64::try_from(now_unix).ok()?;
    if now < dob_unix {
        return None; // a future DOB is not a real age
    }
    // Mean Gregorian year in seconds (365.2425 days) — exact to the whole year.
    u32::try_from((now - dob_unix) / 31_556_952).ok()
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
        // Only a genuine breach/stealer record is a "breach record source" for a
        // DOB (see `is_breach_source`).
        if !is_breach_source(source) {
            continue;
        }
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
                    "Subject date of birth {dob}{} — asserted by {n} independent source(s) \
                     ({}); the strongest disambiguator from same-name namesakes",
                    age_from_dob(&dob, ts).map_or(String::new(), |age| format!(" (age {age})")),
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
pub(crate) struct GovId {
    pub(crate) keys: &'static [&'static str],
    label: &'static str,
    validate: Option<fn(&str) -> bool>,
}

/// The canonical AU government-ID evidence-attribute-key vocabulary, grouped
/// by ID class (needed here for AU-074's per-class masking/labelling).
/// `core::exposure`'s sensitive-disclosure scan flattens this to a plain
/// "was any gov-ID key present" check (see that module's doc comment) rather
/// than keeping its own separate, narrower copy — the drift that left it
/// silently undercounting breach records naming e.g. `tax_file_number`
/// instead of the bare `tfn` this list's first entry alone used to cover.
pub(crate) const GOV_IDS: &[GovId] = &[
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
            // A government ID is a "breach record" disclosure only from a genuine
            // breach/stealer source (see `is_breach_source`).
            if !is_breach_source(source) {
                continue;
            }
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
            // Only a genuine breach/stealer record names an associate; a
            // search/crawl "parent" (a DOMAIN parent, e.g. "wikipedia.org")
            // otherwise mislabels an unrelated site as a breached relative (see
            // `is_breach_source`).
            if !is_breach_source(source) {
                continue;
            }
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
        // Only a genuine breach/stealer record may be counted as a "breach
        // record source" — a geocode/registry enricher carries the same `state`
        // attribute but is not a leaked record (see `is_breach_source`).
        if !is_breach_source(source) {
            continue;
        }
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
        // Same gate as AU-090: a geocode/registry `postcode` attribute is not a
        // breach record and must not be counted as one (see `is_breach_source`).
        if !is_breach_source(source) {
            continue;
        }
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
    // Only genuine breach/stealer records form the "breach record" location
    // class (AU-092's crosscheck side, AU-098's consensus vote). A geocode /
    // registry `state`/`postcode` attribute is already represented by the
    // coordinate/address class and must not double-vote here as breach (see
    // `is_breach_source`).
    for (raw, source, uid) in scan_evidence(entities, JURISDICTION_KEYS) {
        if !is_breach_source(source) {
            continue;
        }
        if let Some(state) = crate::util::address_au::state_code(&raw) {
            states.entry(state).or_default().insert(uid.to_string());
        }
    }
    for (raw, source, uid) in scan_evidence(entities, POSTCODE_KEYS) {
        if !is_breach_source(source) {
            continue;
        }
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
            // THE PROVEN DEFECT: a reverse-geocode record (`geocode`/`photon`)
            // or a registry enricher carries the same suburb/state/postcode
            // attributes as a real leaked address record. Skip the whole record
            // unless it is a genuine breach source, so a geocoded suburb is never
            // assembled and reported as a "dwelling-grade" breach address (see
            // `is_breach_source`).
            if !is_breach_source(&ev.source) {
                continue;
            }
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

// ── AU-098 — Multi-source residency consensus (jurisdiction verdict) ──────────

/// AU-098 — the authoritative, multi-source verdict on where the subject lives.
///
/// The individual geo rules each speak for one signal class — AU-056 reconciles a
/// coordinate against an address, AU-085 a phone region, AU-090/091 the breach
/// `state`/`postcode` fields, AU-092 breach-vs-footprint. This rule fuses **all**
/// of the independent state-grain signal classes into a single jurisdiction
/// verdict and scores it by how many classes agree — the cross-corroboration an
/// investigator would do by hand, made explicit:
///
/// * **Coordinate** — every `Coordinates` fix's state ([`super::geo::coord_state`]).
/// * **Address** — every confident `Address`'s parsed state.
/// * **Breach record** — the `state`/`postcode` fields (the AU-090/091 signal).
/// * **Phone area code** — the state(s) a geographic AU fixed line spans
///   ([`crate::util::address_au::au_phone_region`]).
///
/// The consensus state is the one the most classes support; a tie or a dissenting
/// minority is surfaced, never hidden. Three or more independent classes agreeing
/// is a Verified-grade residency (High); two is strong (Medium). One class alone
/// never fires here — the single-signal rules already cover it. When a
/// consensus-state coordinate is present the verdict is sharpened from state to
/// **locality** via the offline reverse geocoder (AU-099) — "QLD, near Brisbane"
/// — and an IP/ASN on an Australian ISP (AU-097's signal) is appended as a
/// domestic-connection corroboration, distinguishing genuine AU residency from a
/// VPN/foreign exit. This is the gold-standard geolocation finding: a
/// jurisdiction asserted by independent corroboration, confidence shown.
pub(in crate::core::correlator) fn rule_au_098_residency_consensus(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    type StateMap = BTreeMap<&'static str, BTreeSet<String>>;

    // Coordinate class.
    let mut coord: StateMap = BTreeMap::new();
    // Address class.
    let mut addr: StateMap = BTreeMap::new();
    // Phone-area-code class (a geographic line can span 1-3 states).
    let mut phone: StateMap = BTreeMap::new();
    for e in entities {
        if let Some(state) = super::geo::coord_state(e) {
            coord.entry(state).or_default().insert(e.uid.clone());
        } else if e.kind == EntityKind::Address
            && e.confidence >= 0.50
            && let Some(state) = crate::util::address_au::state_code(&e.value)
        {
            addr.entry(state).or_default().insert(e.uid.clone());
        } else if e.kind == EntityKind::Phone
            && let Some((_, _, states)) = crate::util::address_au::au_phone_region(&e.value)
        {
            for s in states {
                phone.entry(s).or_default().insert(e.uid.clone());
            }
        }
    }
    // Breach-record class (state + postcode fields).
    let breach: StateMap = breach_field_states(entities);

    let classes: [(&str, &StateMap); 4] = [
        ("coordinate", &coord),
        ("address", &addr),
        ("breach record", &breach),
        ("phone area code", &phone),
    ];
    let active_classes = classes.iter().filter(|(_, m)| !m.is_empty()).count();

    // state -> the labels of the classes that support it.
    let mut support: BTreeMap<&'static str, Vec<&'static str>> = BTreeMap::new();
    for (label, map) in &classes {
        for state in map.keys() {
            support.entry(state).or_default().push(label);
        }
    }

    // Consensus = the state the most classes support. Deterministic tie-break by
    // the BTreeMap's key order (state code).
    let Some((&consensus, agreeing)) = support
        .iter()
        .max_by(|a, b| a.1.len().cmp(&b.1.len()).then(b.0.cmp(a.0)))
    else {
        return Vec::new();
    };
    let n = agreeing.len();
    if n < 2 {
        return Vec::new(); // a single class is the single-signal rules' job
    }

    // Dissenting minority states (supported by a class, but not the consensus).
    let minority: Vec<&str> = support
        .keys()
        .copied()
        .filter(|s| *s != consensus)
        .collect();

    // Contributing entity uids: every class's entities that named the consensus.
    let mut uids: BTreeSet<String> = BTreeSet::new();
    for (_, map) in &classes {
        if let Some(set) = map.get(consensus) {
            uids.extend(set.iter().cloned());
        }
    }

    let severity = if n >= 3 {
        Severity::High
    } else {
        Severity::Medium
    };
    let dissent = if minority.is_empty() {
        " no dissenting signal".to_string()
    } else {
        format!(" dissenting minority: {}", minority.join("/"))
    };

    // Sharpen the verdict from state grain to a locality: the nearest AU
    // population centre to whichever consensus-state coordinate fix is closest to
    // an anchor (offline reverse geocode). Turns "QLD" into "QLD, near Brisbane".
    let locality_note = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Coordinates && super::geo::coord_state(e) == Some(consensus)
        })
        .filter_map(|e| {
            crate::util::geohash::parse_coords(&e.value)
                .and_then(|(lat, lon)| crate::util::geo::nearest_au_locality(lat, lon))
        })
        .min_by(|a, b| a.2.total_cmp(&b.2))
        .map(|(name, _, km)| format!(", near {name} (≈{km:.0} km)"))
        .unwrap_or_default();

    // Network-layer corroboration (AU-097's signal): an IP/ASN on an Australian
    // ISP confirms a real *domestic* connection — distinguishing genuine AU
    // residency from a VPN / foreign exit node that the state signals can't see;
    // AARNet additionally flags an academic/research user. Country-grain, so it
    // corroborates the AU-ness of the verdict, it does not vote on the state.
    let network_note = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::IpAddress | EntityKind::Asn))
        .find_map(|e| super::au_network_of(e))
        .map(|(name, kind)| match kind {
            crate::util::address_au::AuNetworkKind::Academic => {
                format!("; network on {name} (academic/research) confirms an AU connection")
            }
            crate::util::address_au::AuNetworkKind::Consumer => {
                format!("; network on an Australian ISP ({name}) confirms a domestic connection")
            }
        })
        .unwrap_or_default();

    vec![Correlation::new(
        "AU-098",
        "Multi-source residency consensus",
        severity,
        format!(
            "Residency consensus: {consensus}{locality_note} — {n} of {active_classes} independent \
             location signal classes agree ({});{dissent}{network_note}. A cross-corroborated \
             jurisdiction verdict.",
            agreeing.join(", ")
        ),
        uids.into_iter().collect(),
        scan_id,
        ts,
    )]
}

// ── AU-101 — Identity resolution (attribute breadth) ─────────────────────────

/// AU-101 — identity-resolution breadth: how many distinct CLASSES of identity
/// attribute are pinned to the subject.
///
/// The people-centric analogue of AU-098's residency consensus. Where AU-098
/// fuses the *location* signals into one jurisdiction verdict, this fuses the
/// *identity* signals into one resolution verdict — the breadth of the subject's
/// confirmed footprint across independent attribute facets. It is deliberately a
/// BREADTH measure (how many distinct kinds of identifier are nailed down),
/// distinct from the DEPTH-corroboration of AU-002/003/088 (how many sources
/// agree on one value): a subject with a name, an email, a phone, an address and
/// a DOB is *resolved* even if each rests on a single source.
///
/// The eight facet classes, each counted at most once:
/// legal name (a `Person` at confidence ≥ 0.50), email, phone, username, physical
/// address, business identifier (`AbnAcn`), date of birth (a valid breach DOB
/// field), and a government ID (a breach gov-ID field passing its validator).
/// `n < 4` is left to the single-facet rules; `n == 4` is a Medium resolution;
/// `n ≥ 5` is a High-confidence, cross-facet identity fix — Interpol-grade
/// subject resolution from the data already collected.
pub(in crate::core::correlator) fn rule_au_101_identity_resolution(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Each facet class -> the entity uids that establish it, so the finding can
    // point at the contributing entities and the class is counted at most once.
    let mut facets: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();

    for e in entities {
        let label = match e.kind {
            EntityKind::Person if e.confidence >= 0.50 => "legal name",
            EntityKind::Email => "email",
            EntityKind::Phone => "phone",
            EntityKind::Username => "username",
            EntityKind::Address if e.confidence >= 0.50 => "physical address",
            EntityKind::AbnAcn => "business identifier",
            _ => continue,
        };
        facets.entry(label).or_default().insert(e.uid.clone());
    }

    // Date of birth: a breach DOB field whose value normalises (the AU-073
    // detector), counted as one facet regardless of how many records carry it.
    for (raw, _src, uid) in scan_evidence(entities, DOB_KEYS) {
        if normalise_dob(&raw).is_some() {
            facets
                .entry("date of birth")
                .or_default()
                .insert(uid.to_string());
        }
    }

    // Government ID: any breach gov-ID field passing its validator (the AU-074
    // detector), counted as a single "government ID" facet across all classes.
    for gid in GOV_IDS {
        for (raw, _src, uid) in scan_evidence(entities, gid.keys) {
            if gid.validate.is_none_or(|v| v(&raw)) {
                facets
                    .entry("government ID")
                    .or_default()
                    .insert(uid.to_string());
            }
        }
    }

    // Phone / email facets from breach evidence ATTRIBUTES, not only first-class
    // entities: a breach record often carries the subject's phone or email in an
    // attribute that never became its own `Phone`/`Email` entity (a secondary
    // field, or one the importer kept only as evidence), yet it is a genuinely
    // resolved facet of the subject. Each class is a `BTreeSet` keyed by the
    // facet label, so a subject who has BOTH a Phone entity and a phone attribute
    // still counts "phone" exactly once — no double-count, n stays honest.
    const PHONE_ATTR_KEYS: &[&str] = &["phone", "phone_number", "mobile", "cell"];
    for (raw, _src, uid) in scan_evidence(entities, PHONE_ATTR_KEYS) {
        // The same validity gate the phone rules use: ≥8 digits and not a single
        // repeated digit (a placeholder like 0000000000).
        let digits: Vec<char> = raw.chars().filter(char::is_ascii_digit).collect();
        if digits.len() >= 8 && !digits.iter().all(|c| *c == digits[0]) {
            facets.entry("phone").or_default().insert(uid.to_string());
        }
    }
    const EMAIL_ATTR_KEYS: &[&str] = &["email", "email_address", "mail"];
    for (raw, _src, uid) in scan_evidence(entities, EMAIL_ATTR_KEYS) {
        if raw.contains('@') && raw.split('@').nth(1).is_some_and(|d| d.contains('.')) {
            facets.entry("email").or_default().insert(uid.to_string());
        }
    }

    let n = facets.len();
    if n < 4 {
        return Vec::new(); // a thin footprint is the single-facet rules' job
    }

    let severity = if n >= 5 {
        Severity::High
    } else {
        Severity::Medium
    };

    let mut uids: BTreeSet<String> = BTreeSet::new();
    for set in facets.values() {
        uids.extend(set.iter().cloned());
    }
    let classes: Vec<&str> = facets.keys().copied().collect();

    vec![Correlation::new(
        "AU-101",
        "Identity resolution breadth",
        severity,
        format!(
            "Subject resolved across {n} independent identity facets ({}) — a cross-facet \
             identity fix measuring the breadth of the confirmed footprint, distinct from the \
             single-value corroboration of AU-002/003/088.",
            classes.join(", ")
        ),
        uids.into_iter().collect(),
        scan_id,
        ts,
    )]
}

// ── AU-104 — Australian bank account / institution exposure ───────────────────

/// Breach field keys that carry a Bank-State-Branch code.
const BSB_KEYS: &[&str] = &["bsb", "bank_state_branch", "bsb_number", "bank_bsb"];

/// Breach field keys that carry a bank account number (co-occurrence escalates a
/// BSB exposure to a full, directly-abusable account credential). Also the
/// canonical bank-account-number vocabulary `core::exposure`'s Financial
/// component single-sources for its "bank_account" concept (see that module's
/// doc comment) — `card_number`/`iban` have no equivalent here and stay as
/// `exposure`'s own literals; only the bank-account-number spellings overlap.
pub(crate) const BANK_ACCOUNT_KEYS: &[&str] = &[
    "account_number",
    "bank_account",
    "account_no",
    "acct_number",
    "acct_no",
];

/// AU-104 — exposure of an Australian bank account, resolved to its institution.
///
/// A BSB is the 6-digit code prefixing every Australian bank account; its
/// leading digits name the account-holding institution (the AusPayNet
/// allocation). This mines the `bsb`/`bank_state_branch` fields breach and
/// stealer records carry, resolves each to its bank via
/// [`crate::util::bsb::bsb_institution`], and surfaces the financial-institution
/// attribution — a people-centric signal that applies to almost every Australian
/// adult. When a bank account NUMBER co-occurs in the same data, the BSB+number
/// pair is a full, directly-abusable account credential (mandate-fraud /
/// identity-theft grade), so the finding escalates from Medium to High. Only
/// BSBs that resolve to a known institution are surfaced (accuracy over
/// coverage), so the named bank is reliable.
pub(in crate::core::correlator) fn rule_au_104_bank_account_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // institution -> (distinct sources, uids).
    let mut by_bank: BTreeMap<&'static str, SourcesAndUids> = BTreeMap::new();
    for (raw, source, uid) in scan_evidence(entities, BSB_KEYS) {
        // A BSB/account exposure counts only from a genuine breach/stealer
        // source (see `is_breach_source`).
        if !is_breach_source(source) {
            continue;
        }
        if let Some(bank) = crate::util::bsb::bsb_institution(&raw) {
            let entry = by_bank.entry(bank).or_default();
            entry.0.insert(source.to_string());
            entry.1.insert(uid.to_string());
        }
    }
    if by_bank.is_empty() {
        return Vec::new();
    }

    // A bank account number co-occurring with the BSB is the difference between
    // "we know their bank" and "we hold their account credential".
    let has_account = !scan_evidence(entities, BANK_ACCOUNT_KEYS).is_empty();

    by_bank
        .into_iter()
        .map(|(bank, (sources, uids))| {
            let n = sources.len();
            let (severity, exposure) = if has_account {
                (
                    Severity::High,
                    "with an account number — a full, directly-abusable bank-account credential",
                )
            } else {
                (
                    Severity::Medium,
                    "BSB only — financial-institution attribution",
                )
            };
            Correlation::new(
                "AU-104",
                "Australian bank account exposure",
                severity,
                format!(
                    "Subject banks with {bank} — an Australian BSB exposed across {n} source(s) \
                     ({}); {exposure}.",
                    sources.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                uids.into_iter().collect(),
                scan_id,
                ts,
            )
        })
        .collect()
}

/// Breach evidence keys carrying a reusable secret, split by representation: a
/// plaintext `password` is directly stuffable, a `password_hash`/`hash` only
/// proves reuse (it must be cracked first).
const PLAINTEXT_PW_KEYS: &[&str] = &["password"];
// `hashed_password` is DeHashed's v2 spelling; `password_hash` is OathNet/SeekNow's.
// Reading both lets the SAME digest from two providers group as one reuse signal.
const HASH_PW_KEYS: &[&str] = &["password_hash", "hashed_password", "hash"];

/// AU-105 — Credential reuse across breaches.
///
/// The same secret appearing in two or more DISTINCT breach databases proves the
/// subject reuses credentials, so one cracked password opens every account — the
/// credential-stuffing / account-takeover surface, and one of the most actionable
/// people-centric findings for a breach-exposed subject (the majority of them).
///
/// The finding NEVER echoes the secret value — only the breach names and the reuse
/// count — so the report stays safe to share. Hashes are grouped case-insensitively
/// (the same hash is dumped upper- and lower-case across sources) and kept in a
/// namespace separate from case-sensitive plaintext, so the two never conflate. A
/// value containing `@` (a mis-stored email) is skipped, as is a hash whose
/// plaintext is a known COMMON password ([`crate::util::hashcat::is_common_collision`]) —
/// the same `md5("password")` recurs for unrelated people, so it is a collision,
/// not a reuse link. Plaintext reuse is High
/// (immediately exploitable); hash reuse is Medium. Runs on the confirmed view, so
/// a co-occurrence stranger's reused password never fires it. Deterministic.
pub(in crate::core::correlator) fn rule_au_105_credential_reuse(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // grouping key (`p:`/`h:` namespaced) -> (plaintext?, distinct breaches, uids).
    let mut by_secret: BTreeMap<String, (bool, BTreeSet<String>, BTreeSet<String>)> =
        BTreeMap::new();
    // Bridge from each UNCOMMON plaintext's candidate digests back to the plaintext,
    // so a leaked HASH of that same password (in another breach) unifies with the
    // plaintext group: cross-representation reuse. Offline — only the plaintexts
    // already in hand are hashed, never a brute force (MITRE T1110.002, dictionary).
    let mut digest_bridge: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // The breach a record came from — the unit reuse is measured across. Read
    // the breach-name attr across the spellings the providers actually stamp:
    // `dbname` (OathNet/stealer), `breach`, and `source_db` — the key the
    // `see_know` extractor renames a record's raw `source` breach-name field to
    // (so it can't clobber the provenance `source` attr). Without `source_db`,
    // every SeekNow breach collapsed to the bare module name `see_know`, so a
    // genuine password reused across two SeekNow breaches counted as ONE and
    // AU-105 stayed silent — an under-count that suppressed the most actionable
    // people-centric finding on a primary paid breach source.
    let breach_of = |ev: &crate::core::entity::Evidence| -> String {
        ev.attributes
            .get("dbname")
            .or_else(|| ev.attributes.get("breach"))
            .or_else(|| ev.attributes.get("source_db"))
            .map_or(ev.source.as_str(), String::as_str)
            .to_string()
    };

    // Pass 1 — plaintext secrets, and the digest bridge for the uncommon ones.
    for e in entities {
        for ev in &e.evidence {
            // A reused secret spans a "breach" only via a genuine breach/stealer
            // record — one from an allow-listed source, or one carrying an
            // explicit breach-db name attribute (see `is_breach_source`). This
            // stops a non-breach source's stray password attribute from being
            // counted as a distinct breach.
            if !is_breach_source(&ev.source)
                && !["dbname", "breach", "source_db"]
                    .iter()
                    .any(|k| ev.attributes.contains_key(*k))
            {
                continue;
            }
            let breach = breach_of(ev);
            for k in PLAINTEXT_PW_KEYS {
                if let Some(v) = ev.attributes.get(*k) {
                    let s = v.trim();
                    if s.len() >= 4 && !s.contains('@') {
                        let entry = by_secret.entry(format!("p:{s}")).or_insert((
                            true,
                            BTreeSet::new(),
                            BTreeSet::new(),
                        ));
                        entry.1.insert(breach.clone());
                        entry.2.insert(e.uid.clone());
                        // A COMMON password is shared by unrelated people, so its
                        // digests must not bridge (that would be a collision link).
                        if !crate::util::hashcat::is_common_password(s) {
                            for d in crate::util::hashcat::digests_of(s) {
                                digest_bridge.entry(d).or_insert_with(|| s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Pass 2 — hashes. A hash that equals a candidate digest of a known plaintext
    // unifies with that plaintext's group (cross-representation reuse); otherwise a
    // non-common hash groups by its own value, and a common-password hash is a
    // collision and is skipped (offline `crack_common`).
    for e in entities {
        for ev in &e.evidence {
            // A reused secret spans a "breach" only via a genuine breach/stealer
            // record — one from an allow-listed source, or one carrying an
            // explicit breach-db name attribute (see `is_breach_source`). This
            // stops a non-breach source's stray password attribute from being
            // counted as a distinct breach.
            if !is_breach_source(&ev.source)
                && !["dbname", "breach", "source_db"]
                    .iter()
                    .any(|k| ev.attributes.contains_key(*k))
            {
                continue;
            }
            let breach = breach_of(ev);
            for k in HASH_PW_KEYS {
                if let Some(v) = ev.attributes.get(*k) {
                    let s = v.trim();
                    if s.len() < 8 || s.contains('@') {
                        continue;
                    }
                    let lower = s.to_lowercase();
                    let hex_len = lower.bytes().take_while(u8::is_ascii_hexdigit).count();
                    let bridged = matches!(hex_len, 32 | 40 | 64 | 128)
                        .then(|| digest_bridge.get(&lower[..hex_len]))
                        .flatten();
                    if let Some(plaintext) = bridged {
                        let entry = by_secret.entry(format!("p:{plaintext}")).or_insert((
                            true,
                            BTreeSet::new(),
                            BTreeSet::new(),
                        ));
                        entry.1.insert(breach.clone());
                        entry.2.insert(e.uid.clone());
                    } else if !crate::util::hashcat::is_common_collision(s) {
                        let entry = by_secret.entry(format!("h:{lower}")).or_insert((
                            false,
                            BTreeSet::new(),
                            BTreeSet::new(),
                        ));
                        entry.1.insert(breach.clone());
                        entry.2.insert(e.uid.clone());
                    }
                }
            }
        }
    }

    by_secret
        .into_values()
        .filter(|(_, breaches, _)| breaches.len() >= 2)
        .map(|(plaintext, breaches, uids)| {
            let n = breaches.len();
            let (kind, severity) = if plaintext {
                ("password", Severity::High)
            } else {
                ("password hash", Severity::Medium)
            };
            Correlation::new(
                "AU-105",
                "Credential reuse across breaches",
                severity,
                format!(
                    "A {kind} is reused across {n} distinct breaches ({}) — the subject reuses \
                     credentials, so one cracked secret opens every account (the credential-stuffing \
                     / account-takeover surface). MITRE T1110.004",
                    breaches.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                uids.into_iter().collect(),
                scan_id,
                ts,
            )
        })
        .collect()
}
