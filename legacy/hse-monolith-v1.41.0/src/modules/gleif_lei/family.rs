//! Corporate-family edges from GLEIF Level 2 — and stating honestly what they
//! do and do not mean.
//!
//! Level 1 answers "who is this legal entity". Level 2 answers "who consolidates
//! it, and what does it consolidate" — the relationship records (RR-CDF) GLEIF
//! publishes alongside the LEI index, free and keyless, and which this module
//! previously discarded entirely.
//!
//! Pure: no network, no IO, no global state. [`super::level2`] does the fetching.

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
};

use super::helpers::non_empty;
use super::types::GleifRecord;
use super::{ORG_EXACT, SRC};

/// Confidence for an entity reached through a corporate-family edge.
///
/// Deliberately BELOW [`ORG_EXACT`], and the reason is the seed, not the edge.
/// The edge itself is about as good as corporate data gets: reported by the
/// entity under a regulatory obligation, validated by its managing LOU, and
/// published by GLEIF. What is weaker is the *chain to the operator's subject* —
/// a relative is reached only via a name match on the seed, so if that match
/// picked the wrong "Acme Holdings", the entire family is wrong with it. One
/// inferential hop out from the seed must therefore grade below the seed.
///
/// Kept ABOVE `confidence::MEDIUM` (the noisy-OR expansion floor) on purpose: a
/// corporate parent is exactly the kind of entity the scan should go on to
/// enrich, and burying it below the floor would make the walk decorative.
pub(super) const KIN_CONFIDENCE: f64 = confidence::HIGH_PLUS;
// Compile-time pins on both halves of that argument, so a later tune of either
// constant cannot silently invert the relationship it depends on.
const _: () = assert!(KIN_CONFIDENCE < ORG_EXACT);
const _: () = assert!(KIN_CONFIDENCE > confidence::MEDIUM);

/// The caveat that governs every finding in this file, recorded on each of them.
///
/// This is the single most important sentence in the module. GLEIF Level 2 is a
/// **high-precision, low-recall** ownership source: the edges it publishes are
/// real, but it only ever publishes *accounting-consolidation* edges, and only
/// where the entity reported one. Vast numbers of genuine ownership links are
/// absent because the parent files a reporting exception instead
/// (`NON_CONSOLIDATING`, `NO_LEI`, `BINDING_LEGAL_COMMITMENTS`, …).
///
/// So an operator must never read "no parent returned" as "independent", and
/// must never read "parent returned" as "owns more than 50%". Both readings are
/// wrong, and both are the kind of wrong that produces a confident false
/// finding, so the disclaimer travels with the data rather than living only in
/// documentation the operator may never see.
const COVERAGE_CAVEAT: &str = "GLEIF Level 2 records ACCOUNTING-CONSOLIDATION relationships only: \
     an edge exists where the parent prepares consolidated financial statements including this \
     entity. It is NOT a statement of any ownership percentage, and the ABSENCE of an edge is NOT \
     evidence of independence — entities may instead file a reporting exception. Corroborate; \
     never treat as a negative finding.";

/// Which Level-2 edge a relative was reached by.
///
/// All three are separately reported RR-CDF relationships, not derived by this
/// module, so they are graded alike; what differs is what each one *means*, and
/// that difference is carried in tags and evidence rather than in a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kinship {
    /// The entity that directly consolidates the seed.
    DirectParent,
    /// The top of the seed's consolidation tree.
    UltimateParent,
    /// An entity the seed directly consolidates.
    DirectChild,
}

impl Kinship {
    /// The GLEIF/JSON:API relationship path segment this edge is fetched from.
    pub(super) const fn path(self) -> &'static str {
        match self {
            Self::DirectParent => "direct-parent",
            Self::UltimateParent => "ultimate-parent",
            Self::DirectChild => "direct-children",
        }
    }

    /// The tag downstream rules and reports filter on.
    const fn tag(self) -> &'static str {
        match self {
            Self::DirectParent => "corporate-parent",
            Self::UltimateParent => "ultimate-parent",
            Self::DirectChild => "corporate-subsidiary",
        }
    }

    /// GLEIF's own RR-CDF relationship type, quoted rather than paraphrased so
    /// the evidence stays checkable against the source record.
    const fn rr_type(self) -> &'static str {
        match self {
            Self::DirectParent | Self::DirectChild => "IS_DIRECTLY_CONSOLIDATED_BY",
            Self::UltimateParent => "IS_ULTIMATELY_CONSOLIDATED_BY",
        }
    }

    /// A human phrasing of the edge, oriented from the seed. Note the direction
    /// flips for a child: the *relative* consolidates nothing, the seed does.
    fn summary(self, relative: &str, seed: &str) -> String {
        match self {
            Self::DirectParent => {
                format!("{relative} directly consolidates {seed} (GLEIF Level 2)")
            }
            Self::UltimateParent => {
                format!("{relative} is the ultimate parent of {seed} (GLEIF Level 2)")
            }
            Self::DirectChild => {
                format!("{seed} directly consolidates {relative} (GLEIF Level 2)")
            }
        }
    }
}

/// Map one GLEIF record reached over a Level-2 edge to an `Organisation`.
///
/// Returns `None` for a record with no usable legal name — a nameless relative
/// is not a finding, and inventing a placeholder for it would be fabrication.
///
/// The seed's LEI and name ride in evidence on every relative, so the edge is
/// reconstructable from the entity alone: the graph records which organisation
/// this was reached *through*, not merely that it was reached.
pub(super) fn build_relative(
    rec: &GleifRecord,
    seed_lei: &str,
    seed_name: &str,
    kin: Kinship,
    scan_id: &str,
) -> Option<Entity> {
    let attrs = rec.attributes.as_ref()?;
    let entity = attrs.entity.as_ref()?;
    let name = non_empty(entity.legal_name.as_ref().and_then(|n| n.name.clone()))?;
    let lei = attrs.lei.clone().unwrap_or_default();

    let mut e = Entity::new(EntityKind::Organisation, &name, KIN_CONFIDENCE, scan_id);
    e.tag(SRC);
    e.tag("gleif");
    e.tag("lei");
    e.tag("corporate-family");
    e.tag(kin.tag());
    if let Some(j) = entity.jurisdiction.as_deref() {
        e.tag(format!("country:{j}"));
    }
    // Same status handling as the Level-1 transform, so a dissolved subsidiary
    // is graded consistently however it was reached.
    match entity
        .status
        .as_deref()
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("ACTIVE") => e.tag("active"),
        Some("INACTIVE" | "ANNULLED") => {
            e.tag("inactive");
            e.confidence = confidence::derived_from(e.confidence);
        }
        _ => {}
    }

    let mut ev = Evidence::new(SRC, kin.summary(&name, seed_name))
        .with_attr("register", "GLEIF Global LEI Index (Level 2 / RR-CDF)")
        .with_attr("relationship", kin.rr_type())
        .with_attr("relationship_role", kin.tag())
        .with_attr("via_org", seed_name)
        .with_attr("coverage", COVERAGE_CAVEAT);
    if !lei.is_empty() {
        ev = ev.with_attr("lei", &lei);
    }
    if !seed_lei.is_empty() {
        ev = ev.with_attr("via_lei", seed_lei);
    }
    if let Some(j) = entity.jurisdiction.as_deref() {
        ev = ev.with_attr("jurisdiction", j);
    }
    if let Some(s) = entity.status.as_deref() {
        ev = ev.with_attr("entity_status", s);
    }
    if let Some(r) = entity.registered_as.as_deref() {
        ev = ev.with_attr("registered_as", r);
    }
    e.add_evidence(ev);
    Some(e)
}

/// Whether a record is the *same legal entity* as the direct parent already
/// emitted for this seed.
///
/// In a two-level group the direct parent IS the ultimate parent, and GLEIF
/// answers both links with the same record. Emitting it twice would double-count
/// one organisation as two findings and inflate the apparent size of the family,
/// so the caller adds the second role to the existing entity instead.
///
/// Compared by LEI rather than by name: the LEI is the identifier the registry
/// guarantees to be unique, whereas two distinct entities in a group routinely
/// carry near-identical legal names.
pub(super) fn is_same_entity(rec: &GleifRecord, direct_lei: Option<&str>) -> bool {
    let lei = rec.attributes.as_ref().and_then(|a| a.lei.as_deref());
    matches!((lei, direct_lei), (Some(a), Some(b)) if a == b)
}

/// Note on the emitted set of children when GLEIF reports more than were taken.
///
/// A bounded walk is unavoidable — a large banking group consolidates hundreds
/// of subsidiaries and this module runs under one timeout on a phone — but a
/// bounded walk that says nothing is indistinguishable from a complete one, and
/// an operator reading "12 subsidiaries" must be able to tell that from "12 of
/// 480". The true total therefore rides in evidence on every child, not only in
/// a log line the report never sees.
pub(super) fn note_child_coverage(e: &mut Entity, emitted: usize, total: u64) {
    if let Some(ev) = e.evidence.first_mut() {
        ev.attributes
            .insert("subsidiaries_emitted".to_string(), emitted.to_string());
        ev.attributes
            .insert("subsidiaries_total".to_string(), total.to_string());
        if total > emitted as u64 {
            ev.attributes.insert(
                "subsidiaries_truncated".to_string(),
                format!(
                    "GLEIF reports {total} direct subsidiaries; {emitted} are in this scan. The \
                     remainder were NOT retrieved — re-run against the parent's LEI to enumerate \
                     them."
                ),
            );
        }
    }
}
