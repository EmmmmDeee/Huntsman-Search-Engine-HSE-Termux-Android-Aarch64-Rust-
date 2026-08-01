//! `core::leads` — proactive next-best-action recommendations.
//!
//! Discovery → connection ([`crate::core::relation`]) → synthesis
//! ([`crate::core::network`]) → **action**. This closes the loop: it ranks the
//! identities a scan surfaced but did NOT pivot on — most importantly the
//! family/associate connections the engine deliberately keeps below the
//! expansion floor (so a scan doesn't auto-fan-out across a whole family tree) —
//! and turns each into a one-click "scan this next" lead for the analyst.
//!
//! It builds directly on the network synthesis: every lead is one of the subject's
//! connections, re-scored for *pivot value* (how much a fresh scan of it would
//! yield) and annotated with *why* it matters and whether it is still untapped. The
//! score fuses several independent signals — kind/group base value, node trust and
//! link strength, novelty, cross-scan history, and the **graph's own structure**:
//! a lead that is a bridging pivot (high betweenness / a cut vertex, from
//! [`crate::core::pivot`]) is, by the exact reasoning that module is built on, the
//! highest-reach next scan, so its structural centrality lifts it. That is the
//! synergy — the connectivity analysis feeding straight back into which recursion
//! to run next. Pure over `(entities, relations, floor)`, so it is deterministic
//! and unit-testable; `GET /api/v1/scans/{id}/leads` and the web UI's Leads tab
//! render it directly. Bounded for a low-RAM Termux device.

use serde::Serialize;

use crate::core::entity::Entity;
use crate::core::network::{self, ConnectionGroup};
use crate::core::pivot;
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

/// Pivot-score lift when a lead is a CROSS-INVESTIGATION BRIDGE — the same value
/// independently surfaced in an EARLIER scan in the local intelligence database (the
/// history flywheel). Graded by the strength of the prior tie, strongest wins: an
/// explicit prior RELATIONSHIP (`cross-scan-relation`) is the richest signal, a prior
/// CO-OCCURRENCE (`cross-scan-cooccurrence`) is next, and bare RECURRENCE
/// (`cross-scan`) is the weakest. Historical corroboration is independent of every
/// within-scan signal, so it lifts priority: a value two investigations already
/// touched is a higher-yield pivot than a fresh one — accumulated intelligence
/// driving prioritisation, not just annotation.
const HISTORY_RELATION_BOOST: f64 = 0.5;
const HISTORY_COOCCURRENCE_BOOST: f64 = 0.3;
const HISTORY_RECURRENCE_BOOST: f64 = 0.15;

/// Pivot-score lift per unit of a lead's **betweenness centrality** — the fraction
/// of the graph's shortest paths that route THROUGH it ([`crate::core::pivot`]).
/// This is the synergy that closes the loop back onto the graph's own structure: a
/// lead that is also a bridging intermediary is, by the exact reasoning the pivot
/// module is built on, the highest-yield next scan — expanding it reaches the most
/// of the footprint for the least work. Betweenness is normalised to `[0, 1]`, so
/// this is the maximum lift a pure bridge earns; a pendant leaf (betweenness 0, the
/// shape of most leads) earns nothing here and its ranking is unchanged.
const STRUCT_BRIDGE_WEIGHT: f64 = 0.4;

/// Additional flat lift when a lead is a **cut vertex** (articulation point) — its
/// removal would fragment the graph, so it single-handedly holds a cluster onto the
/// subject's footprint. The exact binary complement to the continuous betweenness
/// term, from the same shared pivot analysis; a lead can be a cut vertex at modest
/// betweenness (a lone bridge to a pendant cluster), so the two are summed, not
/// merged.
const STRUCT_CUT_VERTEX_BONUS: f64 = 0.2;

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
    /// A CROSS-INVESTIGATION BRIDGE — the same value independently surfaced in an
    /// earlier scan (the history flywheel: recurrence, co-occurrence, or a recalled
    /// prior relationship). Earns a [`history_boost`] in the ranking and lets the UI
    /// badge a lead that connects two investigations.
    pub bridged: bool,
    /// This lead is a **structural pivot** — a high-betweenness bridge and/or a cut
    /// vertex in the scan's relationship graph ([`crate::core::pivot`]). Earns a
    /// [`structural_boost`] in the ranking, and lets the UI badge the lead whose
    /// expansion would reach the most of the footprint. Distinct from `confirmed`
    /// (reliability) and `bridged` (cross-scan history): this is pure graph
    /// structure — how central the node is to connectivity, regardless of trust.
    pub structural: bool,
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
        // An organisation the subject is affiliated with (a company they direct,
        // an employer) is a rich, scannable seed: re-scanning it surfaces the
        // other officers, the corporate family and the registered offices — the
        // person → company → wider-network pivot the affiliation edges enable.
        // Weighted like a domain (a container to expand), above the ABN that
        // merely re-identifies it.
        "organisation" => Some(("organisation", 0.5)),
        "abn_acn" => Some(("abn_acn", 0.45)),
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
        // An affiliation is fresh territory to map (a whole organisation's
        // network sits behind it) but one step removed from the subject
        // themselves, so it ranks below owned identifiers and above bare places.
        "affiliations" => 0.55,
        "locations" => 0.4,
        _ => 0.5,
    }
}

/// Composite pivot score: kind value × group weight × node trust × link strength,
/// then lifted by **novelty** (`+0.6` when still untapped: below the expansion
/// floor, or a shared-surname relative the engine deliberately held back, so it was
/// never auto-pivoted — exactly the lead a human should pick up) and an additive
/// corroboration **bonus**: the caller's [`confirmation_boost`] (an independent
/// within-scan signal vouches the connection) PLUS its [`history_boost`] (the lead
/// bridges an earlier investigation, so accumulated cross-scan intelligence lifts
/// its priority). The two arrive pre-summed because the score only sums them — the
/// caller keeps them apart to set the `confirmed` / `bridged` flags.
///
/// The trust term floors at 0.4 so a low-confidence-but-novel relative still ranks,
/// not zero. A geo-corroborated relative earns novelty AND a confirmation bonus, so
/// every scan's reliably-linked family surfaces as its top one-tap pivots — the
/// previous binary "untapped ⇒ ×1.6" instead penalised exactly those relatives the
/// moment geo-corroboration lifted them over the floor. A `discordant` lead (a
/// likely namesake a region away) is finally scaled by [`NAMESAKE_PENALTY`] so it
/// sinks below the genuine local family.
fn score(
    kind_value: f64,
    group_weight: f64,
    entity_conf: f64,
    edge_conf: f64,
    untapped: bool,
    bonus: f64,
    discordant: bool,
) -> f64 {
    let base = kind_value * group_weight * (0.4 + 0.6 * entity_conf) * (0.5 + 0.5 * edge_conf);
    let novelty = if untapped { 0.6 } else { 0.0 };
    let raw = base * (1.0 + novelty + bonus);
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

/// Cross-investigation history lift for a lead, from the STRONGEST history-flywheel
/// tag it carries ([`HISTORY_RELATION_BOOST`] / [`HISTORY_COOCCURRENCE_BOOST`] /
/// [`HISTORY_RECURRENCE_BOOST`]). The three tags nest in strength — a recalled
/// relationship implies the value also recurred — so the MAX applicable boost is
/// taken, never summed. Zero when the lead bridges no prior scan. This is what makes
/// the ranking data-driven on accumulated intelligence: history informs
/// prioritisation, not just the reason text.
fn history_boost(tags: &[String]) -> f64 {
    if tags.iter().any(|t| t == "cross-scan-relation") {
        HISTORY_RELATION_BOOST
    } else if tags.iter().any(|t| t == "cross-scan-cooccurrence") {
        HISTORY_COOCCURRENCE_BOOST
    } else if tags.iter().any(|t| t == "cross-scan") {
        HISTORY_RECURRENCE_BOOST
    } else {
        0.0
    }
}

/// Structural-centrality lift for a lead, from its node in the scan's relationship
/// graph ([`crate::core::pivot::detect`]). Sums the continuous bridge term
/// ([`STRUCT_BRIDGE_WEIGHT`] × betweenness) and the flat cut-vertex term
/// ([`STRUCT_CUT_VERTEX_BONUS`]) — the same fragility pair the pivot module reports,
/// here repurposed as *pivot-yield*: a lead many paths route through, or whose loss
/// would fragment the footprint, is the objectively highest-reach next scan. `None`
/// (a pendant leaf, or a node absent from the index) contributes zero, so the
/// overwhelming majority of leads — direct pendants of the subject — rank exactly
/// as before; the term only lifts a lead that genuinely bridges the graph.
///
/// Takes the `(betweenness, is_cut_vertex)` signal from
/// [`pivot::structural_index`] — the un-truncated per-node index — NOT
/// [`pivot::detect`], whose top-`PIVOT_CAP` cut would silently zero the signal for
/// a real bridge that ranked just outside the shortlist on a large graph.
fn structural_boost(signal: Option<&(f64, bool)>) -> f64 {
    match signal {
        Some(&(betweenness, is_cut_vertex)) => {
            STRUCT_BRIDGE_WEIGHT * betweenness
                + if is_cut_vertex {
                    STRUCT_CUT_VERTEX_BONUS
                } else {
                    0.0
                }
        }
        None => 0.0,
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
fn reason(
    group: &str,
    label: &str,
    value: &str,
    tags: &[String],
    untapped: bool,
    structural: bool,
) -> String {
    let head = match group {
        "people" if label == "relative" => "A relative of the subject",
        "people" => "An associate of the subject",
        "identifiers" => "An identifier the subject owns",
        "aliases" => "An alias of the subject's persona",
        "affiliations" => "An organisation the subject is affiliated with",
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
    // The cross-scan bridge (the history flywheel): this value links to an earlier
    // investigation — annotated by the STRONGEST prior tie so the analyst sees HOW it
    // bridges (a recalled relationship beats a co-occurrence beats bare recurrence).
    if tags.iter().any(|t| t == "cross-scan-relation") {
        r.push_str(" · linked to it in a prior scan");
    } else if tags.iter().any(|t| t == "cross-scan-cooccurrence") {
        r.push_str(" · seen with it in a prior scan");
    } else if tags.iter().any(|t| t == "cross-scan") {
        r.push_str(" · also in a prior scan");
    }
    // The graph-structure signal (independent of every trust/history signal above):
    // this lead bridges the footprint, so expanding it reaches the most for the least.
    if structural {
        r.push_str(" · a bridging pivot in the graph");
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

    // Structural centrality of the SAME graph the leads live in: the synergy that
    // lets the graph's own shape prioritise the next recursion. Uses the un-truncated
    // `structural_index` (every node's betweenness + cut-vertex), NOT `detect` — a
    // genuine bridge that ranks outside `detect`'s top PIVOT_CAP must still lift its
    // lead, and a lead absent from the index is a pendant/minor node that takes the
    // zero path in `structural_boost`.
    let structural_index = pivot::structural_index(entities, relations);
    // Borrowed into the per-group closures below (they are `move`, so capture the
    // reference, not the map itself — one shared read across every group).
    let structural_index = &structural_index;

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
                // Accumulated cross-scan intelligence lifts a lead's priority,
                // independent of every within-scan signal (the history flywheel).
                let history = history_boost(&conn.tags);
                // Graph structure lifts it again, independent of trust and history:
                // a lead that bridges the footprint is the highest-reach next scan.
                let structural = structural_boost(structural_index.get(conn.uid.as_str()));
                let is_structural = structural > 0.0;
                Some(Lead {
                    uid: conn.uid.clone(),
                    value: conn.value.clone(),
                    kind: conn.kind.clone(),
                    target_kind,
                    action: "scan",
                    reason: reason(
                        group.key,
                        &conn.label,
                        &conn.value,
                        &conn.tags,
                        untapped,
                        is_structural,
                    ),
                    score: score(
                        kind_value,
                        group_weight(group.key),
                        conn.entity_confidence,
                        conn.edge_confidence,
                        untapped,
                        confirmation + history + structural,
                        discordant,
                    ) * surname_factor(&conn.value, &conn.tags),
                    classification: conn.classification.clone(),
                    confirmed: confirmation > 0.0,
                    discordant,
                    bridged: history > 0.0,
                    structural: is_structural,
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
