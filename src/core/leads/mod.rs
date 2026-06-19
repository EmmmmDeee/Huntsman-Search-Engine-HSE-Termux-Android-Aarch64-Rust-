//! `core::leads` — proactive next-best-action recommendations.
//!
//! Discovery → connection ([`crate::core::relation`]) → synthesis
//! ([`crate::core::network`]) → **action**. This closes the loop: it ranks the
//! identities a scan surfaced but did NOT pivot on — most importantly the
//! family/associate connections the engine deliberately keeps below the
//! expansion floor (so a scan doesn't auto-fan-out across a whole family tree) —
//! and turns each into a one-click "scan this next" lead for the analyst.
//!
//! It builds directly on the network synthesis (no second graph traversal):
//! every lead is one of the subject's connections, re-scored for *pivot value*
//! (how much a fresh scan of it would yield) and annotated with *why* it matters
//! and whether it is still untapped. Pure over `(entities, relations, floor)`, so
//! it is deterministic and unit-testable; `GET /api/v1/scans/{id}/leads` and the
//! web UI's Leads tab render it directly. Bounded for a low-RAM Termux device.

use serde::Serialize;

use crate::core::entity::Entity;
use crate::core::network::{self, ConnectionGroup};
use crate::core::relation::Relation;

/// Maximum leads returned — a focused, actionable shortlist, not a second entity
/// dump. Ranked, so the cap keeps the highest-value pivots.
const LEAD_CAP: usize = 25;

/// Score multiplier applied to a `geo-discordant` lead — a shared-surname person a
/// whole region from the subject ([`crate::core::geo_family::NAMESAKE_GEO_KM`]), so
/// a likely namesake. Halved (not dropped): a far relative can still be genuine, so
/// it sinks below the local family yet stays on the list for the analyst to judge.
const NAMESAKE_PENALTY: f64 = 0.5;

/// Multiplier for a bare family lead that shares only a COMMON surname (and isn't
/// geo-confirmed) — "another Smith" is weak evidence, so it's discounted and the
/// analyst is told to corroborate it independently ([`crate::util::surnames`]).
const COMMON_SURNAME_FACTOR: f64 = 0.6;

/// Multiplier for a family lead that shares a DISTINCTIVE surname — a shared rare
/// name (Diegmann, Bamford) is itself corroborating, so it earns a small lift,
/// which is what surfaces a rare-surname subject's real kin above the noise.
const RARE_SURNAME_FACTOR: f64 = 1.15;

/// A recommended next investigation step: an entity worth pivoting on, why, and
/// the scan that would pursue it.
#[derive(Debug, Clone, Serialize)]
pub struct Lead {
    pub uid: String,
    pub value: String,
    /// The entity kind (display form).
    pub kind: String,
    /// The `TargetKind` to seed a follow-up scan with (the web UI POSTs this).
    pub target_kind: &'static str,
    /// The recommended action — currently always a fresh focused scan.
    pub action: &'static str,
    /// A short, grounded justification ("A relative of the subject · not yet
    /// investigated").
    pub reason: String,
    /// Pivot-value score (higher = investigate sooner). Opaque ranking number.
    pub score: f64,
    /// Far-end entity tier (`VERIFIED` / `PROBABLE` / `CANDIDATE`).
    pub classification: String,
    /// An INDEPENDENT second signal corroborates this lead — a geo-corroborated
    /// relative (shared surname AND the subject's confirmed area) or a high-tier
    /// new person. The reliable pivots, so the UI badges them and they rank first.
    pub confirmed: bool,
    /// A likely NAMESAKE — a shared-surname person a whole region from the subject
    /// (`geo-discordant`). Demoted in the ranking and flagged for the UI so the
    /// analyst can tell the genuine local family from interstate look-alikes.
    pub discordant: bool,
    /// The network group this lead came from (`people` / `identifiers` / …).
    pub group: &'static str,
}

/// Base pivot value by entity kind — how widely a fresh scan of it tends to fan
/// out (mirrors the engine's seed-yield ordering: identities richest, infra
/// thinner). `None` ⇒ not independently pivotable, so never a lead.
fn pivot(kind: &str) -> Option<(&'static str, f64)> {
    match kind {
        "person" => Some(("full_name", 1.0)),
        "email" => Some(("email", 0.9)),
        "username" => Some(("username", 0.7)),
        "phone" => Some(("phone", 0.55)),
        "domain" => Some(("domain", 0.5)),
        "ip_address" => Some(("ip_address", 0.35)),
        _ => None,
    }
}

/// Per-group lead weight: a *new* person or persona is fresh territory to map,
/// while an identifier the subject already owns is confirmation more than
/// expansion — so people/aliases lead, owned identifiers and infra trail.
fn group_weight(group: &str) -> f64 {
    match group {
        "people" => 1.0,
        "aliases" => 0.85,
        "identifiers" => 0.6,
        "locations" => 0.4,
        _ => 0.5,
    }
}

/// Composite pivot score: kind value × group weight × node trust × link strength,
/// then lifted by two INDEPENDENT bonuses —
/// * **novelty** (`+0.6` when still untapped: below the expansion floor, or a
///   shared-surname relative the engine deliberately held back, so the engine did
///   not pivot it — exactly the lead a human should pick up), and
/// * **confirmation** (a second, independent signal vouches the connection is real
///   — see [`confirmation_boost`]).
///
/// The trust term floors at 0.4 so a low-confidence-but-novel relative still ranks,
/// not zero. A geo-corroborated relative earns BOTH bonuses (novel *and*
/// confirmed), so every scan's reliably-linked family surfaces as its top one-tap
/// pivots — the previous binary "untapped ⇒ ×1.6" instead penalised exactly those
/// relatives the moment geo-corroboration lifted them over the floor. A
/// `discordant` lead (a likely namesake a region away) is finally scaled by
/// [`NAMESAKE_PENALTY`] so it sinks below the genuine local family.
fn score(
    kind_value: f64,
    group_weight: f64,
    entity_conf: f64,
    edge_conf: f64,
    untapped: bool,
    confirmation: f64,
    discordant: bool,
) -> f64 {
    let base = kind_value * group_weight * (0.4 + 0.6 * entity_conf) * (0.5 + 0.5 * edge_conf);
    let novelty = if untapped { 0.6 } else { 0.0 };
    let raw = base * (1.0 + novelty + confirmation);
    if discordant {
        raw * NAMESAKE_PENALTY
    } else {
        raw
    }
}

/// Reliability bonus for a lead, layered on top of novelty: how strongly an
/// INDEPENDENT second signal confirms the connection is real and worth pivoting.
///
/// A `geo-corroborated` relative — shared surname AND the subject's own confirmed
/// area, two independent free signals agreeing offline
/// ([`crate::core::geo_family`]) — is the most reliable pivot a free scan can
/// produce, so it leads. A high-tier *new* person or persona is corroborated, but
/// by a single angle, so it earns less. Owned identifiers, locations and
/// infrastructure get nothing here: a verified value the subject already owns is
/// confirmation, not a fresh lead, and must not outrank a new person on its own
/// reliability.
fn confirmation_boost(group: &str, classification: &str, tags: &[String]) -> f64 {
    if tags.iter().any(|t| t == "geo-corroborated") {
        return 0.8;
    }
    if matches!(group, "people" | "aliases") {
        match classification {
            "VERIFIED" => 0.45,
            "PROBABLE" => 0.20,
            _ => 0.0,
        }
    } else {
        0.0
    }
}

/// Surname-distinctiveness multiplier for a *family* lead. A `family-candidate`
/// shares the subject's surname by construction, so how distinctive that surname is
/// says how much the bare match is worth: a rare surname is itself corroborating (a
/// small lift), a common one is weak and wants a second angle (a discount). A
/// geo-corroborated relative is already confirmed by location, so geo dominates and
/// the name is not second-guessed; non-family leads are unaffected
/// ([`crate::util::surnames`]).
fn surname_factor(value: &str, tags: &[String]) -> f64 {
    let family = tags.iter().any(|t| t == "family-candidate");
    let geo_confirmed = tags.iter().any(|t| t == "geo-corroborated");
    if !family || geo_confirmed {
        return 1.0;
    }
    match crate::util::surnames::surname_of(value) {
        Some(s) if crate::util::surnames::is_common(&s) => COMMON_SURNAME_FACTOR,
        Some(_) => RARE_SURNAME_FACTOR,
        None => 1.0,
    }
}

/// A grounded, human reason for the lead, from its group, label, value, exposure
/// tags and untapped status.
fn reason(group: &str, label: &str, value: &str, tags: &[String], untapped: bool) -> String {
    let head = match group {
        "people" if label == "relative" => "A relative of the subject",
        "people" => "An associate of the subject",
        "identifiers" => "An identifier the subject owns",
        "aliases" => "An alias of the subject's persona",
        "locations" => "A place tied to the subject",
        _ => "Connected to the subject's network",
    };
    let mut r = head.to_string();
    if tags
        .iter()
        .any(|t| t == "breach" || t == "stealer-log" || t == "breach-derived")
    {
        r.push_str(" · exposed in a breach");
    }
    // Geo first (the strongest free family signal), else fall back to surname
    // distinctiveness: a bare common-surname match is the weakest family lead.
    if tags.iter().any(|t| t == "geo-corroborated") {
        r.push_str(" · confirmed in the subject's area");
    } else if tags.iter().any(|t| t == "geo-discordant") {
        r.push_str(" · different region — possible namesake");
    } else if tags.iter().any(|t| t == "family-candidate")
        && crate::util::surnames::surname_of(value)
            .is_some_and(|s| crate::util::surnames::is_common(&s))
    {
        r.push_str(" · common surname — corroborate independently");
    }
    if untapped {
        r.push_str(" · not yet investigated");
    }
    r
}

/// Rank the scan's untapped pivots into a focused, actionable shortlist.
///
/// `expansion_floor` is the scan's `min_expand_confidence`; a connection below it
/// was not auto-pivoted by the engine, so it earns the untapped boost. Pure and
/// deterministic: leads are ranked by score, ties broken by value, capped at
/// [`LEAD_CAP`].
#[must_use]
pub fn recommend(entities: &[Entity], relations: &[Relation], expansion_floor: f64) -> Vec<Lead> {
    let net = network::synthesize(entities, relations);
    let mut leads: Vec<Lead> = net
        .groups
        .iter()
        .flat_map(|group: &ConnectionGroup| {
            group.items.iter().filter_map(move |conn| {
                let (target_kind, kind_value) = pivot(&conn.kind)?;
                // Untapped = the engine did not pivot it: below the expansion
                // floor, OR a shared-surname `family-candidate` (the engine
                // deliberately holds the surname cluster below the floor so a scan
                // doesn't fan out across a whole family tree). Geo-corroboration may
                // lift such a relative's confidence over the floor at finalise, but
                // it was still never auto-expanded — so it stays a one-tap lead.
                let untapped = conn.entity_confidence < expansion_floor
                    || conn.tags.iter().any(|t| t == "family-candidate");
                // A flagged namesake is the opposite of confirmed, so it earns no
                // reliability bonus (even if its tier alone would have) and takes
                // the ranking penalty instead.
                let discordant = conn.tags.iter().any(|t| t == "geo-discordant");
                let confirmation = if discordant {
                    0.0
                } else {
                    confirmation_boost(group.key, &conn.classification, &conn.tags)
                };
                Some(Lead {
                    uid: conn.uid.clone(),
                    value: conn.value.clone(),
                    kind: conn.kind.clone(),
                    target_kind,
                    action: "scan",
                    reason: reason(group.key, &conn.label, &conn.value, &conn.tags, untapped),
                    score: score(
                        kind_value,
                        group_weight(group.key),
                        conn.entity_confidence,
                        conn.edge_confidence,
                        untapped,
                        confirmation,
                        discordant,
                    ) * surname_factor(&conn.value, &conn.tags),
                    classification: conn.classification.clone(),
                    confirmed: confirmation > 0.0,
                    discordant,
                    group: group.key,
                })
            })
        })
        .collect();

    leads.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.value.cmp(&b.value))
    });
    leads.truncate(LEAD_CAP);
    leads
}

#[cfg(test)]
mod tests;
