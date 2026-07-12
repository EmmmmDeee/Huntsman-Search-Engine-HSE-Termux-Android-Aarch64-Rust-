//! Target **Exposure Index** — a single, explainable `0–100` rollup of how
//! exposed a subject is, aggregated from signals HSE already computes: breach
//! corpus presence, sensitive-PII disclosure, identifier spread, and the
//! correlator's own severities.
//!
//! Competitors surface risk *per finding* (SpiderFoot flags each data element);
//! this is the calibrated **composite** an operator — or an executive summary —
//! reads first, with a fully transparent per-component breakdown so it is never a
//! black-box number. "Don't reinvent the wheel, better it": every input here is
//! already produced elsewhere in the engine; this only *aggregates* it.
//!
//! Pure and deterministic. It reads the CONFIRMED entity set (candidate-quarantined
//! entities — not yet tied to the subject — are excluded) plus the correlations,
//! and derives counts-based, scan/merge-order-independent component scores. It is
//! `core`-only (entity + correlator types) and imports no modules, so the
//! architecture guards stay green.

use std::collections::BTreeSet;

use crate::core::correlator::{Correlation, Severity};
use crate::core::entity::{Entity, EntityKind};

#[cfg(test)]
mod tests;

/// Minimum effective confidence for a finding to count toward exposure. Exposure
/// is a statement about what is GENUINELY known, so bare single-source speculation
/// — chiefly the `name_intel` / `username_variants` permutation guesses (~0.3–0.45)
/// a name scan emits by the dozen — must not inflate it. A real scan of a name
/// surfaced "40 identifiers" of which all but a handful were such guesses; this
/// floor (solidly within the Probable tier) keeps the corroborated findings and
/// drops the speculation. Candidate-quarantined entities are below it regardless.
const EXPOSURE_CONF_FLOOR: f64 = 0.5;

/// Per-component ceilings. They sum to 100 — the index maximum.
const MAX_BREACH: u8 = 35;
const MAX_SENSITIVE: u8 = 30;
const MAX_IDENTIFIERS: u8 = 20;
const MAX_CORRELATION: u8 = 15;

/// Evidence-attribute keys that mark a sensitive disclosure. `DOB_KEYS` and the
/// government-ID keys are single-sourced from `core::correlator::rules::breach_pii`
/// (AU-073/AU-074's own canonical vocabularies) rather than kept as a separate
/// copy — the previous local copies had drifted to a narrower subset (5 of 22
/// government-ID spellings; 3 of 9 DOB spellings), silently undercounting the
/// exposure score for a breach record naming e.g. `tax_file_number` or
/// `date_birth` (OathNet/SeekNow's own DOB field name — a major breach source)
/// instead of the one spelling each list used to know about.
use crate::core::correlator::rules::breach_pii::{DOB_KEYS, GOV_IDS};
const FINANCIAL_KEYS: &[&str] = &["iban", "bank_account", "card_number"];

/// Qualitative band for the headline number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExposureBand {
    Minimal,
    Low,
    Moderate,
    High,
    Critical,
}

impl ExposureBand {
    fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Self::Minimal,
            20..=39 => Self::Low,
            40..=59 => Self::Moderate,
            60..=79 => Self::High,
            _ => Self::Critical,
        }
    }

    /// Upper-case label for terminal/report rendering.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Minimal => "MINIMAL",
            Self::Low => "LOW",
            Self::Moderate => "MODERATE",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// One transparent contributor to the index — its earned points, its ceiling, and
/// a human reason. The breakdown is the point: the operator sees *why* the number
/// is what it is. Serialize-only: the index is computed from entities +
/// correlations on demand, never deserialized back (the `name` is a static label).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExposureComponent {
    pub name: &'static str,
    pub score: u8,
    pub max: u8,
    pub detail: String,
}

/// The composite exposure assessment for one subject.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExposureIndex {
    /// `0..=100`.
    pub score: u8,
    pub band: ExposureBand,
    pub components: Vec<ExposureComponent>,
}

impl ExposureIndex {
    /// One-line headline, e.g. `"Exposure 72/100 [HIGH]"`.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!("Exposure {}/100 [{}]", self.score, self.band.label())
    }
}

/// Assess subject exposure from the CONFIRMED entities + the scan's correlations.
///
/// Candidate-quarantined entities (`tags::CANDIDATE`) and bare speculation below
/// [`EXPOSURE_CONF_FLOOR`] are excluded — exposure is a statement about what is
/// genuinely tied to the *subject*, not about how many guesses the engine emitted.
#[must_use]
pub fn assess(entities: &[Entity], correlations: &[Correlation]) -> ExposureIndex {
    let confirmed: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            !e.has_tag(crate::core::tags::CANDIDATE) && e.c_effective() >= EXPOSURE_CONF_FLOOR
        })
        .collect();

    let components = vec![
        breach_component(&confirmed),
        sensitive_component(&confirmed),
        identifier_component(&confirmed),
        correlation_component(correlations),
    ];

    // Each component is already capped at its ceiling and the ceilings sum to 100,
    // so the total can never exceed 100 — no clamp needed, but fold defensively.
    let score = components
        .iter()
        .fold(0u16, |acc, c| acc + u16::from(c.score))
        .min(100) as u8;

    ExposureIndex {
        score,
        band: ExposureBand::from_score(score),
        components,
    }
}

/// Breach corpus breadth: distinct named breach/stealer databases the subject
/// appears in (12 pts each, capped). More corpora ⇒ wider, longer-lived exposure.
fn breach_component(confirmed: &[&Entity]) -> ExposureComponent {
    // A breach-corpus name reaches us under one of several evidence keys. A
    // per-record co-occurrence row stamps `dbname`, but the SUBJECT's own
    // aggregate hit stamps `top_dbnames` (oathnet_pro) or `breaches`
    // (xposed_or_not) — each a comma-separated list of corpus names. Reading only
    // `dbname` scored a confirmed subject breach as zero: in a real scan the
    // subject's TLDRtech appearance — asserted by BOTH oathnet_pro (`top_dbnames`)
    // and xposed_or_not (`breaches`) — was missed because neither uses `dbname`,
    // while the only `dbname`-bearing rows were non-subject candidates (already
    // excluded from `confirmed`). Read every corpus key, splitting the lists.
    const CORPUS_KEYS: &[&str] = &["dbname", "top_dbnames", "breaches"];
    let mut dbs: BTreeSet<String> = BTreeSet::new();
    for e in confirmed {
        if !(e.has_tag(crate::core::tags::BREACH) || e.has_tag(crate::core::tags::STEALER_LOG)) {
            continue;
        }
        for ev in &e.evidence {
            for key in CORPUS_KEYS {
                let Some(raw) = ev.attributes.get(*key) else {
                    continue;
                };
                for name in raw.split(',') {
                    // Fold to an alphanumeric-only lowercase key so the one corpus
                    // written two ways ("tldr.tech" vs "TLDRtech") counts once.
                    let norm: String = name
                        .chars()
                        .filter(|c| c.is_alphanumeric())
                        .flat_map(char::to_lowercase)
                        .collect();
                    if !norm.is_empty() && norm != "unknown" {
                        dbs.insert(norm);
                    }
                }
            }
        }
    }
    let n = dbs.len();
    let score = n.saturating_mul(12).min(MAX_BREACH as usize) as u8;
    let detail = if n == 0 {
        "no named breach corpus appearances".to_string()
    } else {
        format!(
            "{n} distinct breach corpus{}",
            if n == 1 { "" } else { "es" }
        )
    };
    ExposureComponent {
        name: "Breach exposure",
        score,
        max: MAX_BREACH,
        detail,
    }
}

/// Sensitive-disclosure flags: each category present scores once (a government ID
/// is the gravest, then a cleartext credential, then DOB, then financial).
fn sensitive_component(confirmed: &[&Entity]) -> ExposureComponent {
    let (mut gov, mut dob, mut fin, mut secret) = (false, false, false, false);
    for e in confirmed {
        if matches!(e.kind, EntityKind::Password | EntityKind::Credential) {
            secret = true;
        }
        for ev in &e.evidence {
            for k in ev.attributes.keys() {
                let kl = k.to_ascii_lowercase();
                gov |= GOV_IDS.iter().any(|g| g.keys.contains(&kl.as_str()));
                dob |= DOB_KEYS.contains(&kl.as_str());
                fin |= FINANCIAL_KEYS.contains(&kl.as_str());
            }
        }
    }
    let mut score = 0usize;
    let mut parts: Vec<&str> = Vec::new();
    if gov {
        score += 15;
        parts.push("government ID");
    }
    if secret {
        score += 8;
        parts.push("cleartext credential");
    }
    if dob {
        score += 7;
        parts.push("date of birth");
    }
    if fin {
        score += 5;
        parts.push("financial");
    }
    let score = score.min(MAX_SENSITIVE as usize) as u8;
    let detail = if parts.is_empty() {
        "no sensitive identifiers disclosed".to_string()
    } else {
        format!("disclosed: {}", parts.join(", "))
    };
    ExposureComponent {
        name: "Sensitive PII",
        score,
        max: MAX_SENSITIVE,
        detail,
    }
}

/// Identifier surface: distinct confirmed contactable identifiers tied to the
/// subject (email / phone / username / postal address) — a broader reachable
/// footprint is greater exposure. 4 pts each, capped.
fn identifier_component(confirmed: &[&Entity]) -> ExposureComponent {
    // `(kind-tag, lowercased value)` so two spellings of one handle don't
    // double-count and the set is order-independent.
    let mut ids: BTreeSet<(u8, String)> = BTreeSet::new();
    for e in confirmed {
        let tag = match e.kind {
            EntityKind::Email => 0u8,
            EntityKind::Phone => 1,
            EntityKind::Username => 2,
            EntityKind::Address => 3,
            _ => continue,
        };
        ids.insert((tag, e.value.to_lowercase()));
    }
    let n = ids.len();
    let score = n.saturating_mul(4).min(MAX_IDENTIFIERS as usize) as u8;
    let detail = format!(
        "{n} distinct identifier{} (email/phone/username/address)",
        if n == 1 { "" } else { "s" }
    );
    ExposureComponent {
        name: "Identifier surface",
        score,
        max: MAX_IDENTIFIERS,
        detail,
    }
}

/// Correlation severity: the engine's own verdicts. Critical 5 pts, High 2 pts,
/// capped — Low/Medium do not move the exposure needle.
fn correlation_component(correlations: &[Correlation]) -> ExposureComponent {
    let (mut crit, mut high) = (0usize, 0usize);
    for c in correlations {
        match c.severity {
            Severity::Critical => crit += 1,
            Severity::High => high += 1,
            _ => {}
        }
    }
    let score =
        (crit.saturating_mul(5) + high.saturating_mul(2)).min(MAX_CORRELATION as usize) as u8;
    let detail = format!("{crit} critical, {high} high correlation(s)");
    ExposureComponent {
        name: "Correlation severity",
        score,
        max: MAX_CORRELATION,
        detail,
    }
}
