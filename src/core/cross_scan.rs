//! Cross-scan entity category: browse the history bridges as one search facet.
//!
//! The finalise passes in [`crate::core::engine`] tag entities that recur across
//! investigations (`cross-scan`, `cross-scan-cooccurrence`, `cross-scan-relation`,
//! `cross-scan-alias`). Those tags are the detection half; this module is the
//! presentation half, assembling them into a single ranked category an operator
//! can open and expand scan by scan.
//!
//! It also owns the kind-compatibility table used by the cross-kind alias probe,
//! so the notion of "these two kinds can denote one identifier" has one definition.
//!
//! # Two degrees of bridge
//!
//! A **direct** bridge ([`BridgedEntity`]) is an identifier present in *this*
//! scan that an earlier scan also recorded. A **transitive** link
//! ([`TransitiveLink`]) is an identifier this scan never saw, reached by walking
//! *through* a direct bridge into the earlier scan that shares it. The two are
//! kept in separate collections and are never merged: a transitive link is a
//! LEAD, not a finding about this subject, and it carries the full chain
//! (`via_uids` / `via_scan_ids`) so a reader can audit exactly how it was
//! reached rather than being asked to trust it.
//!
//! The walk is the recursion this module needs, adapted the same way
//! [`crate::core::engine`]'s expansion adapts it: an explicit frontier instead
//! of call-stack recursion, because the scan graph is arbitrary, cyclic, and
//! operator-supplied — a self-call would recurse until the stack died on a
//! history that loops. Every hop is budget-checked, and every entity and scan is
//! entered into a visited set before it can be traversed again.

use std::collections::HashSet;

use crate::core::entity::{Entity, EntityKind};
use crate::core::error::Result;
use crate::core::port::StoragePort;

/// Tag marking an entity bridged to history by value under a *different* kind.
pub const ALIAS_TAG: &str = "cross-scan-alias";

/// Hops from this scan the transitive walk will take. Degree 1 is the direct
/// bridge itself; degree 2 is "shared a prior scan with one of our bridges";
/// degree 3 is one hop further out.
///
/// Three is where the chain stops being auditable by a human reader: by then the
/// claim is "an identifier that shared a scan with an identifier that shared a
/// scan with something we saw", and each extra hop multiplies the chance that
/// one link in it was coincidence.
pub const MAX_BRIDGE_DEGREE: usize = 3;

/// Prior scans the walk will open, across all degrees. This is the real cost
/// bound: each one is an `entities_for_scan` load, and the walk runs inside a
/// request handler.
pub const MAX_TRANSITIVE_SCANS: usize = 12;

/// Links the walk will return. Excess is reported as `dropped_over_cap`, never
/// dropped in silence.
pub const MAX_TRANSITIVE_LINKS: usize = 200;

/// Confidence floor for an identifier to be walked through.
///
/// A direct bridge earns its place from the finalise passes' own gating. A
/// transitive link has no such backing — it is being asserted purely because two
/// scans share a value — so a shaky identifier must not become the joint that
/// connects two investigations.
pub const MIN_LINK_CONFIDENCE: f64 = 0.5;

/// Prior-scan count past which an identifier is a *hub* and is reported but not
/// traversed through.
///
/// An identifier in many investigations is usually shared infrastructure or the
/// operator's own recurring fixture, not a link between the subjects of those
/// investigations. Walking through it would connect every scan to every other —
/// the classic way a link graph fabricates relationships — so a hub terminates
/// the path. It is still reported, flagged `hub`, because "this identifier is
/// everywhere" is itself worth knowing.
pub const MAX_HUB_DEGREE: usize = 8;

/// How strongly an entity is bridged to earlier investigations.
///
/// Ordered weakest to strongest; mirrors the ladder `core::leads::history_boost`
/// scores, so the category ranks the way lead recommendation already does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BridgeTier {
    /// Same value under a compatible but different kind — heuristic.
    KindAlias,
    /// The identical identifier was recorded in an earlier scan.
    Recurrence,
    /// The identifier shared an earlier scan with a partner seen here too.
    Cooccurrence,
    /// An earlier scan recorded a typed relation between this and a current peer.
    Relation,
}

impl BridgeTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KindAlias => "kind_alias",
            Self::Recurrence => "recurrence",
            Self::Cooccurrence => "cooccurrence",
            Self::Relation => "relation",
        }
    }

    /// Strongest tier the entity's tags evidence, if any.
    pub fn strongest(entity: &Entity) -> Option<Self> {
        if entity.has_tag("cross-scan-relation") {
            Some(Self::Relation)
        } else if entity.has_tag("cross-scan-cooccurrence") {
            Some(Self::Cooccurrence)
        } else if entity.has_tag("cross-scan") {
            Some(Self::Recurrence)
        } else if entity.has_tag(ALIAS_TAG) {
            Some(Self::KindAlias)
        } else {
            None
        }
    }
}

/// One bridged entity, with the earlier scans it can be expanded into.
#[derive(Debug, Clone)]
pub struct BridgedEntity {
    pub uid: String,
    pub value: String,
    pub kind: EntityKind,
    pub confidence: f64,
    pub tier: BridgeTier,
    /// True when the entity bridges three or more distinct investigations.
    pub hub: bool,
    /// Earlier scans that also recorded this entity, ascending. Empty when the
    /// store could not answer — never a claim that no earlier scan exists.
    pub prior_scan_ids: Vec<String>,
}

/// An identifier THIS SCAN NEVER SAW, reached by walking through a direct
/// bridge into an earlier investigation that shares it.
///
/// Deliberately a separate type from [`BridgedEntity`]. A direct bridge says
/// "this scan and an earlier one both recorded this identifier". A transitive
/// link says only "an earlier scan that shares an identifier with this one also
/// recorded *that*" — which is a lead to check, not an attribute of this
/// subject. Collapsing the two would be exactly the fabrication the codebase
/// forbids, so the chain travels with the link.
#[derive(Debug, Clone)]
pub struct TransitiveLink {
    pub uid: String,
    pub value: String,
    pub kind: EntityKind,
    /// Confidence as recorded in the scan it was reached from — NOT a claim
    /// about this scan's subject.
    pub confidence: f64,
    /// Hops from this scan. 2 = shared a prior scan with one of our direct
    /// bridges; 3 = one further hop out.
    pub degree: usize,
    /// The identifiers walked through to get here, nearest-first. `via_uids[0]`
    /// is always a direct bridge of this scan.
    pub via_uids: Vec<String>,
    /// The scans walked through, positionally paired with `via_uids`.
    pub via_scan_ids: Vec<String>,
    /// Scans recording this identifier that are not already on the path.
    pub prior_scan_ids: Vec<String>,
    /// Present in more than [`MAX_HUB_DEGREE`] investigations, so it is shared
    /// infrastructure rather than a link between their subjects. Reported, but
    /// the walk stops here.
    pub hub: bool,
}

/// The transitive walk's result, including everything it declined to do.
#[derive(Debug, Clone, Default)]
pub struct TransitiveClosure {
    /// Links found, ranked nearest and best-evidenced first.
    pub links: Vec<TransitiveLink>,
    /// Prior scans actually opened.
    pub scans_visited: usize,
    /// Store lookups that errored during the walk. A short closure with a
    /// non-zero count here is incomplete, not empty.
    pub lookups_failed: usize,
    /// Links derived but not returned because [`MAX_TRANSITIVE_LINKS`] was hit.
    pub dropped_over_cap: usize,
    /// Prior scans the walk could not open because [`MAX_TRANSITIVE_SCANS`] was
    /// spent. Non-zero means unexplored history remains.
    pub scans_over_budget: usize,
    /// Identifiers reported but not traversed through because they are hubs.
    pub hubs_not_traversed: usize,
}

/// The cross-scan category for one scan: every history bridge, ranked.
#[derive(Debug, Clone)]
pub struct CrossScanCategory {
    pub scan_id: String,
    pub entities: Vec<BridgedEntity>,
    /// Bridged entities whose prior-scan lookup failed, so `prior_scan_ids` is
    /// empty for a reason other than "no history". Surfaced, never hidden.
    pub lookups_failed: usize,
    /// Second- and third-degree links, populated by
    /// [`CrossScanCategory::expand_transitively`]. Empty until it is called —
    /// the walk costs store queries, so assembling the category never runs it
    /// implicitly.
    pub transitive: TransitiveClosure,
}

impl CrossScanCategory {
    /// Bridges at or above `tier`, preserving rank order.
    pub fn at_least(&self, tier: BridgeTier) -> Vec<&BridgedEntity> {
        self.entities.iter().filter(|e| e.tier >= tier).collect()
    }

    /// Distinct earlier scans reachable from this scan's bridges.
    pub fn prior_scans(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .entities
            .iter()
            .flat_map(|e| e.prior_scan_ids.iter().cloned())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Walk the history graph outward from this scan's direct bridges and fill
    /// in [`Self::transitive`].
    ///
    /// Separate from assembly because it costs store queries. Idempotent: a
    /// second call recomputes from the same direct bridges rather than
    /// compounding, so a caller cannot accidentally inflate the closure by
    /// invoking it twice.
    pub fn expand_transitively(&mut self, store: &dyn StoragePort) {
        self.transitive = transitive_closure(store, &self.scan_id, &self.entities);
    }
}

/// Walk outward from `direct` through the scans that share those identifiers.
///
/// # Shape of the walk
///
/// Breadth-first over an explicit frontier of `(scan, path)`, one degree at a
/// time — the cycle-safe adaptation of recursion this graph requires (see the
/// module docs). Every scan and every identifier is recorded in a visited set
/// before it can be expanded, so a history that loops back terminates instead of
/// revisiting; every hop is checked against the scan and link budgets, and
/// whatever the budgets refuse is COUNTED into the returned closure rather than
/// disappearing.
///
/// # What it refuses to walk through
///
/// * identifiers of a kind that cannot denote a person or account
///   ([`is_bridgeable_kind`]) — an IP or a coordinate is context, and joining two
///   investigations on shared context invents a relationship between their
///   subjects;
/// * quarantined candidates ([`crate::core::tags::CANDIDATE`]) — an entity the
///   engine itself declines to attribute to its own subject cannot be the joint
///   that attributes two subjects to each other. Unconditional, with no opt-in:
///   unlike a display filter this is a correctness rule, and it also means no
///   caller of this function can leak a quarantined value out of a scan the
///   requester was reading past;
/// * identifiers below [`MIN_LINK_CONFIDENCE`];
/// * hubs (over [`MAX_HUB_DEGREE`] investigations), which are reported and then
///   terminate their path.
#[must_use]
pub fn transitive_closure(
    store: &dyn StoragePort,
    scan_id: &str,
    direct: &[BridgedEntity],
) -> TransitiveClosure {
    let mut closure = TransitiveClosure::default();

    // Visited sets seeded with everything already accounted for: this scan and
    // its prior scans are not new history, and this scan's own identifiers are
    // direct bridges, not transitive links.
    let mut seen_scans: HashSet<String> = HashSet::new();
    seen_scans.insert(scan_id.to_string());
    let mut seen_entities: HashSet<String> = direct.iter().map(|b| b.uid.clone()).collect();

    // Degree-1 frontier: each direct bridge's prior scans, carrying the bridge
    // it was reached through as the first element of the path.
    let mut frontier: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    for bridge in direct {
        for prior in &bridge.prior_scan_ids {
            if seen_scans.insert(prior.clone()) {
                frontier.push((prior.clone(), vec![bridge.uid.clone()], vec![prior.clone()]));
            }
        }
    }
    // Deterministic order in, deterministic truncation out.
    frontier.sort_by(|a, b| a.0.cmp(&b.0));

    for degree in 2..=MAX_BRIDGE_DEGREE {
        if frontier.is_empty() {
            break;
        }
        let mut next: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();

        for (prior_scan, via_uids, via_scan_ids) in frontier {
            if closure.scans_visited >= MAX_TRANSITIVE_SCANS {
                closure.scans_over_budget += 1;
                continue;
            }
            let entities = match store.entities_for_scan(&prior_scan) {
                Ok(e) => e,
                Err(_) => {
                    closure.lookups_failed += 1;
                    continue;
                }
            };
            closure.scans_visited += 1;

            let mut entities = entities;
            entities.sort_by(|a, b| a.uid.cmp(&b.uid));

            for entity in &entities {
                if seen_entities.contains(&entity.uid)
                    || !is_bridgeable_kind(&entity.kind)
                    || entity.has_tag(crate::core::tags::CANDIDATE)
                    || entity.confidence < MIN_LINK_CONFIDENCE
                {
                    continue;
                }

                let onward = match store.scan_ids_for_entity(&entity.uid) {
                    Ok(ids) => ids,
                    Err(_) => {
                        closure.lookups_failed += 1;
                        continue;
                    }
                };
                // Total investigations this identifier appears in decides
                // hub-ness; the ones NOT already on our path are what makes it
                // a lead worth reporting at all.
                let hub = onward.len() > MAX_HUB_DEGREE;
                let fresh: Vec<String> = {
                    let mut v: Vec<String> = onward
                        .into_iter()
                        .filter(|id| !seen_scans.contains(id))
                        .collect();
                    v.sort_unstable();
                    v.dedup();
                    v
                };
                if fresh.is_empty() {
                    // Reaches no investigation we have not already accounted
                    // for, so it adds no history — not a link, just a member of
                    // a scan we already opened.
                    continue;
                }

                seen_entities.insert(entity.uid.clone());
                if closure.links.len() >= MAX_TRANSITIVE_LINKS {
                    closure.dropped_over_cap += 1;
                    continue;
                }

                let mut link_via_uids = via_uids.clone();
                link_via_uids.push(entity.uid.clone());
                closure.links.push(TransitiveLink {
                    uid: entity.uid.clone(),
                    value: entity.value.clone(),
                    kind: entity.kind.clone(),
                    confidence: entity.confidence,
                    degree,
                    via_uids: via_uids.clone(),
                    via_scan_ids: via_scan_ids.clone(),
                    prior_scan_ids: fresh.clone(),
                    hub,
                });

                if hub {
                    // Reported above, but the path stops: walking on through a
                    // hub connects every investigation to every other.
                    closure.hubs_not_traversed += 1;
                    continue;
                }
                if degree < MAX_BRIDGE_DEGREE {
                    for onward_scan in fresh {
                        if seen_scans.insert(onward_scan.clone()) {
                            let mut scans = via_scan_ids.clone();
                            scans.push(onward_scan.clone());
                            next.push((onward_scan, link_via_uids.clone(), scans));
                        }
                    }
                }
            }
        }

        next.sort_by(|a, b| a.0.cmp(&b.0));
        frontier = next;
    }

    // Nearest first, then best-evidenced, then widest reach — a total order, so
    // the ranking is reproducible for the same store.
    closure.links.sort_by(|a, b| {
        a.degree
            .cmp(&b.degree)
            .then(a.hub.cmp(&b.hub))
            .then(b.prior_scan_ids.len().cmp(&a.prior_scan_ids.len()))
            .then(
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then_with(|| a.uid.cmp(&b.uid))
    });
    closure
}

/// Kinds that can denote a person or an account, and so can legitimately join
/// two investigations.
///
/// The exclusions are the point. An IP address, a coordinate, a URL, an
/// organisation or a bare domain is *context*: many unrelated people share a
/// CDN edge, a suburb, a news article, or an employer. Bridging on those would
/// wire every investigation that touched the same infrastructure into one graph
/// and present it as a finding. Only identifiers a subject actually possesses
/// are walked.
#[must_use]
pub fn is_bridgeable_kind(kind: &EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::Email
            | EntityKind::Username
            | EntityKind::Phone
            | EntityKind::Person
            | EntityKind::CryptoAddress
            | EntityKind::DeviceId
            | EntityKind::ApiKey
    )
}

/// Assemble the cross-scan category for `scan_id`.
///
/// Ranked strongest tier first, then by confidence, then by uid so the ordering is
/// total and stable. Per-entity prior-scan lookups are indexed point queries; the
/// set they run over is already bounded by the finalise passes that write the tags.
pub fn category_for_scan(store: &dyn StoragePort, scan_id: &str) -> Result<CrossScanCategory> {
    let entities = store.entities_for_scan(scan_id)?;
    Ok(category_from_entities(store, scan_id, &entities))
}

/// Assemble the category from entities the caller has already loaded.
///
/// Split out from [`category_for_scan`] so a caller that must filter the entity
/// set first — the API, which applies the candidate quarantine before anything
/// reads the entities — controls the load. A quarantined entity gated out here is
/// then absent from the category, rather than being loaded past the gate.
#[must_use]
pub fn category_from_entities(
    store: &dyn StoragePort,
    scan_id: &str,
    entities: &[Entity],
) -> CrossScanCategory {
    let mut category = CrossScanCategory {
        scan_id: scan_id.to_string(),
        entities: Vec::new(),
        lookups_failed: 0,
        // Empty until `expand_transitively` is called — building the direct
        // bridges must stay a cheap, single-pass operation for callers that
        // only need degree 1.
        transitive: TransitiveClosure::default(),
    };

    for entity in entities {
        let Some(tier) = BridgeTier::strongest(entity) else {
            continue;
        };

        let prior_scan_ids = match store.scan_ids_for_entity(&entity.uid) {
            Ok(ids) => {
                let mut ids: Vec<String> = ids.into_iter().filter(|id| id != scan_id).collect();
                ids.sort_unstable();
                ids
            }
            Err(_) => {
                category.lookups_failed += 1;
                Vec::new()
            }
        };

        category.entities.push(BridgedEntity {
            uid: entity.uid.clone(),
            value: entity.value.clone(),
            kind: entity.kind.clone(),
            confidence: entity.confidence,
            hub: entity.has_tag("hub-entity") || entity.has_tag("hub-cooccurrence"),
            tier,
            prior_scan_ids,
        });
    }

    category.entities.sort_by(|a, b| {
        b.tier
            .cmp(&a.tier)
            .then(
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then_with(|| a.uid.cmp(&b.uid))
    });

    category
}

/// Handle values a cross-kind history probe should look for, given an entity.
///
/// Only Email → Username. Normalisation is kind-specific, so no two kinds ever
/// share a normalised value by accident — an Email value always contains `@` and
/// so can never equal a Username value. The one real bridge is an address's
/// local-part, which is routinely the handle the same person registers elsewhere;
/// AU-076 already makes that link *within* a scan, and this is its history-facing
/// counterpart.
///
/// Returns the raw local-part first, then its separator-stripped canonical form
/// when that differs — stored usernames keep their punctuation, so both spellings
/// must be probed to recall `j.doe` from a scan that saw `jdoe`.
#[must_use]
pub fn alias_handles(entity: &Entity) -> Vec<String> {
    if entity.kind != EntityKind::Email {
        return Vec::new();
    }
    // Local-part minus any Gmail-style `+tag` suffix, matching AU-076.
    let local = entity.value.split('@').next().unwrap_or_default();
    let base = local.split('+').next().unwrap_or_default();
    if !crate::core::correlator::is_anchorable_handle(base) {
        return Vec::new();
    }

    let canonical = crate::core::entity::canonical_handle(base);
    if canonical == base {
        vec![base.to_string()]
    } else {
        vec![base.to_string(), canonical]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;

    fn entity(kind: EntityKind, value: &str, tags: &[&str]) -> Entity {
        let mut e = Entity::new(kind, value, confidence::HIGH, "scan-1");
        for t in tags {
            e.tag(*t);
        }
        e
    }

    #[test]
    fn alias_handles_uses_the_email_local_part() {
        let e = entity(EntityKind::Email, "jordanmeyers@example.com", &[]);
        assert_eq!(alias_handles(&e), vec!["jordanmeyers".to_string()]);
    }

    #[test]
    fn alias_handles_probes_both_spellings_when_punctuated() {
        let e = entity(EntityKind::Email, "jordan.meyers@example.com", &[]);
        assert_eq!(
            alias_handles(&e),
            vec!["jordan.meyers".to_string(), "jordanmeyers".to_string()]
        );
    }

    #[test]
    fn alias_handles_strips_plus_tag() {
        let e = entity(EntityKind::Email, "jordanmeyers+shopping@example.com", &[]);
        assert_eq!(alias_handles(&e), vec!["jordanmeyers".to_string()]);
    }

    #[test]
    fn alias_handles_rejects_role_and_short_local_parts() {
        for value in ["admin@example.com", "jd@example.com", "info@example.com"] {
            assert!(
                alias_handles(&entity(EntityKind::Email, value, &[])).is_empty(),
                "{value} should not be an identity anchor"
            );
        }
    }

    #[test]
    fn only_emails_have_cross_kind_aliases() {
        // Kind-specific normalisation means no other kind can share a value.
        assert!(alias_handles(&entity(EntityKind::Username, "jdoe", &[])).is_empty());
        assert!(alias_handles(&entity(EntityKind::Person, "Jordan Meyers", &[])).is_empty());
    }

    #[test]
    fn strongest_tier_wins_over_weaker_tags() {
        let e = entity(
            EntityKind::Email,
            "a@example.com",
            &["cross-scan", ALIAS_TAG, "cross-scan-relation"],
        );
        assert_eq!(BridgeTier::strongest(&e), Some(BridgeTier::Relation));
    }

    #[test]
    fn untagged_entity_is_not_in_the_category() {
        let e = entity(EntityKind::Email, "a@example.com", &[]);
        assert_eq!(BridgeTier::strongest(&e), None);
    }

    #[test]
    fn alias_is_the_weakest_tier() {
        assert!(BridgeTier::KindAlias < BridgeTier::Recurrence);
        assert!(BridgeTier::Recurrence < BridgeTier::Cooccurrence);
        assert!(BridgeTier::Cooccurrence < BridgeTier::Relation);
    }

    #[test]
    fn category_ranks_by_tier_and_excludes_unbridged() {
        let store = crate::core::test_support::InMemoryStore::new();
        let alias = entity(EntityKind::Username, "jdoe", &[ALIAS_TAG]);
        let relation = entity(EntityKind::Email, "j@example.com", &["cross-scan-relation"]);
        let plain = entity(EntityKind::Email, "nobody@example.com", &[]);
        for e in [&alias, &relation, &plain] {
            store.upsert_entity(e).expect("should succeed");
        }

        let category = category_for_scan(&store, "scan-1").expect("category");

        assert_eq!(category.entities.len(), 2);
        assert_eq!(category.entities[0].tier, BridgeTier::Relation);
        assert_eq!(category.entities[1].tier, BridgeTier::KindAlias);
        assert_eq!(category.at_least(BridgeTier::Cooccurrence).len(), 1);
    }

    // ── Transitive closure ──────────────────────────────────────────────
    //
    // The walk is the load-bearing new capability: it turns "this identifier
    // recurs" into "this identifier reaches THAT investigation, by this exact
    // path". Every test below pins one of the two halves that make it honest —
    // what it will walk through, and what it refuses to — because both failure
    // modes are silent: too permissive and it fabricates links between unrelated
    // subjects, too eager and it hides how much history it never opened.

    use crate::core::test_support::InMemoryStore;

    /// Record `value` as observed by every scan in `scans`, at `confidence`.
    /// Returns the shared uid — the same identifier across all of them, which is
    /// exactly what makes it a bridge.
    fn observe(
        store: &InMemoryStore,
        kind: EntityKind,
        value: &str,
        conf: f64,
        scans: &[&str],
    ) -> String {
        let mut uid = String::new();
        for s in scans {
            let e = Entity::new(kind.clone(), value, conf, *s);
            uid = e.uid.clone();
            store.upsert_entity(&e).expect("should succeed");
        }
        uid
    }

    /// Build the direct-bridge list the walk starts from, the way the engine's
    /// finalise passes would: tagged `cross-scan`, so the category picks it up.
    fn direct_bridges(store: &InMemoryStore, scan_id: &str) -> Vec<BridgedEntity> {
        category_for_scan(store, scan_id)
            .expect("category")
            .entities
    }

    #[test]
    fn a_degree_two_link_carries_the_whole_path_that_reached_it() {
        let store = InMemoryStore::new();
        // scan-1 (ours) and scan-2 both saw this email → a direct bridge.
        let bridge_uid = observe(
            &store,
            EntityKind::Email,
            "jordan@corp.test",
            0.9,
            &["scan-1", "scan-2"],
        );
        store
            .upsert_entity(&entity(
                EntityKind::Email,
                "jordan@corp.test",
                &["cross-scan"],
            ))
            .expect("should succeed");
        // scan-2 also saw a username that scan-3 saw — reachable only THROUGH
        // the bridge, and never seen by scan-1.
        let link_uid = observe(
            &store,
            EntityKind::Username,
            "jmeyers",
            0.8,
            &["scan-2", "scan-3"],
        );

        let closure = transitive_closure(&store, "scan-1", &direct_bridges(&store, "scan-1"));

        assert_eq!(
            closure.links.len(),
            1,
            "exactly the one reachable identifier"
        );
        let link = &closure.links[0];
        assert_eq!(link.uid, link_uid);
        assert_eq!(link.value, "jmeyers");
        assert_eq!(link.degree, 2);
        // The chain is auditable end to end: through OUR bridge, via scan-2.
        assert_eq!(link.via_uids, vec![bridge_uid]);
        assert_eq!(link.via_scan_ids, vec!["scan-2".to_string()]);
        // And it names the investigation it opens up, which is the whole point.
        assert_eq!(link.prior_scan_ids, vec!["scan-3".to_string()]);
        // Two scans opened: scan-2 at degree 2, then scan-3 — which the link
        // pointed at, and which the walk follows and finds nothing new in. It
        // reports the scans it OPENED, not the links it happened to get from
        // them; a cost bound that only counted productive loads would understate
        // what the walk actually charged the caller.
        assert_eq!(closure.scans_visited, 2);
        assert_eq!(closure.lookups_failed, 0);
        assert_eq!(closure.dropped_over_cap, 0);
    }

    #[test]
    fn the_walk_reaches_degree_three_and_stops() {
        let store = InMemoryStore::new();
        observe(
            &store,
            EntityKind::Email,
            "jordan@corp.test",
            0.9,
            &["scan-1", "scan-2"],
        );
        store
            .upsert_entity(&entity(
                EntityKind::Email,
                "jordan@corp.test",
                &["cross-scan"],
            ))
            .expect("should succeed");
        // A chain one hop longer than the walk is allowed to follow:
        //   scan-2 →(jmeyers)→ scan-3 →(+61400111222)→ scan-4 →(deep)→ scan-5
        observe(
            &store,
            EntityKind::Username,
            "jmeyers",
            0.8,
            &["scan-2", "scan-3"],
        );
        observe(
            &store,
            EntityKind::Phone,
            "+61400111222",
            0.8,
            &["scan-3", "scan-4"],
        );
        observe(
            &store,
            EntityKind::Username,
            "deep",
            0.8,
            &["scan-4", "scan-5"],
        );

        let closure = transitive_closure(&store, "scan-1", &direct_bridges(&store, "scan-1"));

        let by_value: Vec<(&str, usize)> = closure
            .links
            .iter()
            .map(|l| (l.value.as_str(), l.degree))
            .collect();
        assert_eq!(
            by_value,
            vec![("jmeyers", 2), ("+61400111222", 3)],
            "degree 2 and 3 are reached; the degree-4 identifier is not"
        );
        // The degree-3 link's chain names both hops that got there.
        let deep = &closure.links[1];
        assert_eq!(
            deep.via_scan_ids,
            vec!["scan-2".to_string(), "scan-3".to_string()]
        );
        assert_eq!(deep.via_uids.len(), 2, "our bridge, then the degree-2 link");
    }

    #[test]
    fn shared_context_is_never_a_bridge() {
        // The fabrication this gate exists to prevent: two unrelated
        // investigations both touching Cloudflare, a capital city, or a news
        // site must NOT become one graph.
        let store = InMemoryStore::new();
        observe(
            &store,
            EntityKind::Email,
            "jordan@corp.test",
            0.9,
            &["scan-1", "scan-2"],
        );
        store
            .upsert_entity(&entity(
                EntityKind::Email,
                "jordan@corp.test",
                &["cross-scan"],
            ))
            .expect("should succeed");
        for (kind, value) in [
            (EntityKind::IpAddress, "104.20.37.187"),
            (EntityKind::Domain, "cloudflare.com"),
            (EntityKind::Url, "https://news.test/article"),
            (EntityKind::Organisation, "Telstra"),
        ] {
            assert!(
                !is_bridgeable_kind(&kind),
                "{value} is context, not identity"
            );
            observe(&store, kind, value, 0.95, &["scan-2", "scan-9"]);
        }

        let closure = transitive_closure(&store, "scan-1", &direct_bridges(&store, "scan-1"));

        assert!(
            closure.links.is_empty(),
            "shared infrastructure must not link two investigations: {:?}",
            closure.links.iter().map(|l| &l.value).collect::<Vec<_>>()
        );
        // It still OPENED scan-2 — the refusal is per-identifier, not a failure
        // to look.
        assert_eq!(closure.scans_visited, 1);
    }

    #[test]
    fn a_quarantined_candidate_is_never_a_link() {
        // A candidate is an entity the engine declines to attribute to its OWN
        // subject. Using it to attribute two subjects to each other would be
        // strictly worse — and the API reads other scans through this walk, so
        // a leak here escapes the candidate gate entirely.
        let store = InMemoryStore::new();
        observe(
            &store,
            EntityKind::Email,
            "jordan@corp.test",
            0.9,
            &["scan-1", "scan-2"],
        );
        store
            .upsert_entity(&entity(
                EntityKind::Email,
                "jordan@corp.test",
                &["cross-scan"],
            ))
            .expect("should succeed");
        for scan in ["scan-2", "scan-3"] {
            let mut c = Entity::new(
                EntityKind::Email,
                "stranger@breach.test",
                confidence::VERY_HIGH_PLUS,
                scan,
            );
            c.tag(crate::core::tags::CANDIDATE);
            store.upsert_entity(&c).expect("should succeed");
        }

        let closure = transitive_closure(&store, "scan-1", &direct_bridges(&store, "scan-1"));

        assert!(
            closure.links.is_empty(),
            "a quarantined value must not escape through the walk: {:?}",
            closure.links.iter().map(|l| &l.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_shaky_identifier_is_not_walked_through() {
        let store = InMemoryStore::new();
        observe(
            &store,
            EntityKind::Email,
            "jordan@corp.test",
            0.9,
            &["scan-1", "scan-2"],
        );
        store
            .upsert_entity(&entity(
                EntityKind::Email,
                "jordan@corp.test",
                &["cross-scan"],
            ))
            .expect("should succeed");
        observe(
            &store,
            EntityKind::Username,
            "maybe",
            MIN_LINK_CONFIDENCE - 0.01,
            &["scan-2", "scan-3"],
        );
        observe(
            &store,
            EntityKind::Username,
            "solid",
            MIN_LINK_CONFIDENCE,
            &["scan-2", "scan-4"],
        );

        let closure = transitive_closure(&store, "scan-1", &direct_bridges(&store, "scan-1"));

        let values: Vec<&str> = closure.links.iter().map(|l| l.value.as_str()).collect();
        assert_eq!(values, vec!["solid"], "the floor is inclusive and it bites");
    }

    #[test]
    fn a_hub_is_reported_but_terminates_its_path() {
        let store = InMemoryStore::new();
        observe(
            &store,
            EntityKind::Email,
            "jordan@corp.test",
            0.9,
            &["scan-1", "scan-2"],
        );
        store
            .upsert_entity(&entity(
                EntityKind::Email,
                "jordan@corp.test",
                &["cross-scan"],
            ))
            .expect("should succeed");
        // An identifier in far more investigations than MAX_HUB_DEGREE — the
        // operator's own recurring fixture, not a link between subjects.
        let hub_scans: Vec<String> = (0..MAX_HUB_DEGREE + 3)
            .map(|i| format!("hub-{i:02}"))
            .collect();
        let mut scans: Vec<&str> = vec!["scan-2"];
        scans.extend(hub_scans.iter().map(String::as_str));
        observe(
            &store,
            EntityKind::Username,
            "support",
            confidence::VERY_HIGH_PLUS,
            &scans,
        );
        // Something reachable ONLY by walking on through the hub.
        observe(
            &store,
            EntityKind::Username,
            "behind-the-hub",
            0.9,
            &["hub-00", "scan-7"],
        );

        let closure = transitive_closure(&store, "scan-1", &direct_bridges(&store, "scan-1"));

        let hub_link = closure
            .links
            .iter()
            .find(|l| l.value == "support")
            .expect("the hub is still reported — 'this is everywhere' is worth knowing");
        assert!(hub_link.hub);
        assert_eq!(closure.hubs_not_traversed, 1);
        assert!(
            closure.links.iter().all(|l| l.value != "behind-the-hub"),
            "walking through a hub would wire every investigation to every other"
        );
    }

    #[test]
    fn a_history_that_loops_back_terminates() {
        let store = InMemoryStore::new();
        // scan-1 ⇄ scan-2 ⇄ scan-3, with every identifier shared by every scan:
        // a fully cyclic history, the case a naive self-call would recurse on
        // until the stack died.
        for value in ["a@corp.test", "b@corp.test", "c@corp.test"] {
            observe(
                &store,
                EntityKind::Email,
                value,
                0.9,
                &["scan-1", "scan-2", "scan-3"],
            );
            store
                .upsert_entity(&entity(EntityKind::Email, value, &["cross-scan"]))
                .expect("should succeed");
        }

        let closure = transitive_closure(&store, "scan-1", &direct_bridges(&store, "scan-1"));

        // Every identifier is already a direct bridge and every scan is already
        // on the path, so there is no new history — and, crucially, the call
        // returned.
        assert!(closure.links.is_empty());
        assert!(closure.scans_visited <= MAX_TRANSITIVE_SCANS);
    }

    #[test]
    fn exhausting_the_scan_budget_is_counted_not_hidden() {
        let store = InMemoryStore::new();
        // One direct bridge shared with far more prior scans than the walk may
        // open, each holding its own onward identifier.
        let mut bridge_scans: Vec<String> = vec!["scan-1".to_string()];
        for i in 0..MAX_TRANSITIVE_SCANS + 5 {
            bridge_scans.push(format!("prior-{i:02}"));
        }
        let refs: Vec<&str> = bridge_scans.iter().map(String::as_str).collect();
        observe(
            &store,
            EntityKind::Email,
            "jordan@corp.test",
            confidence::VERY_HIGH_PLUS,
            &refs,
        );
        store
            .upsert_entity(&entity(
                EntityKind::Email,
                "jordan@corp.test",
                &["cross-scan"],
            ))
            .expect("should succeed");
        for i in 0..MAX_TRANSITIVE_SCANS + 5 {
            observe(
                &store,
                EntityKind::Username,
                &format!("user-{i:02}"),
                0.9,
                &[&format!("prior-{i:02}"), &format!("far-{i:02}")],
            );
        }

        let closure = transitive_closure(&store, "scan-1", &direct_bridges(&store, "scan-1"));

        assert_eq!(closure.scans_visited, MAX_TRANSITIVE_SCANS);
        assert_eq!(
            closure.links.len(),
            MAX_TRANSITIVE_SCANS,
            "one per opened scan"
        );
        assert_eq!(
            closure.scans_over_budget,
            5 + MAX_TRANSITIVE_SCANS,
            "unopened history is REPORTED — the 5 degree-1 priors the budget \
             refused, PLUS the 12 degree-2 scans the links it did find pointed \
             at. A short closure with this at 0 means 'there is no more \
             history', and it must never say that falsely"
        );
    }

    #[test]
    fn expand_transitively_is_idempotent() {
        let store = InMemoryStore::new();
        observe(
            &store,
            EntityKind::Email,
            "jordan@corp.test",
            0.9,
            &["scan-1", "scan-2"],
        );
        store
            .upsert_entity(&entity(
                EntityKind::Email,
                "jordan@corp.test",
                &["cross-scan"],
            ))
            .expect("should succeed");
        observe(
            &store,
            EntityKind::Username,
            "jmeyers",
            0.8,
            &["scan-2", "scan-3"],
        );

        let mut category = category_for_scan(&store, "scan-1").expect("category");
        assert!(
            category.transitive.links.is_empty(),
            "not walked implicitly"
        );

        category.expand_transitively(&store);
        let first: Vec<String> = category
            .transitive
            .links
            .iter()
            .map(|l| l.uid.clone())
            .collect();
        assert_eq!(first.len(), 1);

        category.expand_transitively(&store);
        let second: Vec<String> = category
            .transitive
            .links
            .iter()
            .map(|l| l.uid.clone())
            .collect();
        assert_eq!(first, second, "a second call recomputes, never compounds");
    }

    #[test]
    fn a_scan_with_no_bridges_walks_nowhere() {
        let store = InMemoryStore::new();
        store
            .upsert_entity(&entity(EntityKind::Email, "lonely@corp.test", &[]))
            .expect("should succeed");

        let closure = transitive_closure(&store, "scan-1", &direct_bridges(&store, "scan-1"));

        assert!(closure.links.is_empty());
        assert_eq!(closure.scans_visited, 0);
        assert_eq!(closure.scans_over_budget, 0);
    }
}
