use std::cell::{Ref, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_handle;
use crate::entity::Entity;
use crate::relation::{self, PairPathways, Relation};
use crate::tags;

mod rules;

pub use rules::{
    date_diff_days, rule_au_001_multi_breach, rule_au_002_identity_cluster,
    rule_au_003_high_corroboration, rule_au_019_temporal_breach_cluster,
    rule_au_021_api_key_exposure, rule_au_060_transitive_identity_closure,
    rule_au_062_multipath_corroboration, rule_au_063_corroboration_gap,
    rule_au_070_connection_broker, rule_au_071_robust_identity_cluster,
    rule_au_109_shared_registrant, rule_au_110_shared_hosting_ip, rule_geo_bssid_ip, source_family,
    tagged_matching_sources, text_mentions_ip,
};

/// The entities and relations one rule pass reads, with indexes built on first use. The indexes
/// are ordered by key, so a rule that walks them (pairing every entity with every other, say)
/// emits the same result in the same order on every run: a hash map's order is seeded per map,
/// and the same scan correlated twice used to disagree.
pub struct RuleContext<'a> {
    entities: &'a [Entity],
    relations: &'a [Relation],
    by_uid: RefCell<Option<BTreeMap<&'a str, &'a Entity>>>,
    by_canonical_handle: RefCell<Option<BTreeMap<String, Vec<&'a Entity>>>>,
    pathways: RefCell<Option<Vec<PairPathways<'a>>>>,
    clusters: RefCell<Option<Vec<Vec<String>>>>,
}

impl<'a> RuleContext<'a> {
    #[must_use]
    pub fn new(entities: &'a [Entity], relations: &'a [Relation]) -> Self {
        Self {
            entities,
            relations,
            by_uid: RefCell::new(None),
            by_canonical_handle: RefCell::new(None),
            pathways: RefCell::new(None),
            clusters: RefCell::new(None),
        }
    }

    #[must_use]
    pub fn entities(&self) -> &'a [Entity] {
        self.entities
    }

    #[must_use]
    pub fn relations(&self) -> &'a [Relation] {
        self.relations
    }

    pub fn by_uid(&self) -> Ref<'_, BTreeMap<&'a str, &'a Entity>> {
        if self.by_uid.borrow().is_none() {
            *self.by_uid.borrow_mut() = Some(
                self.entities
                    .iter()
                    .map(|entity| (entity.uid.as_str(), entity))
                    .collect(),
            );
        }
        Ref::map(self.by_uid.borrow(), |map| {
            map.as_ref().expect("cache initialised")
        })
    }

    pub fn by_canonical_handle(&self) -> Ref<'_, BTreeMap<String, Vec<&'a Entity>>> {
        if self.by_canonical_handle.borrow().is_none() {
            let mut map = BTreeMap::<String, Vec<&Entity>>::new();
            for entity in self.entities {
                if let Some(handle) = canonical_handle(&entity.value) {
                    map.entry(handle).or_default().push(entity);
                }
            }
            *self.by_canonical_handle.borrow_mut() = Some(map);
        }
        Ref::map(self.by_canonical_handle.borrow(), |map| {
            map.as_ref().expect("cache initialised")
        })
    }

    /// The identity pathways between every two entities, each pair counted in full (see
    /// [`relation::pairwise_disjoint_pathways`]), with the positions of [`Self::by_uid`]'s
    /// keys. AU-062 and AU-063 both read them, so a pass counts them once.
    pub fn pathways(&self) -> Ref<'_, Vec<PairPathways<'a>>> {
        if self.pathways.borrow().is_none() {
            let uids = self.by_uid().keys().copied().collect::<Vec<_>>();
            let pathways = relation::pairwise_disjoint_pathways(&uids, self.relations, usize::MAX);
            *self.pathways.borrow_mut() = Some(pathways);
        }
        Ref::map(self.pathways.borrow(), |pathways| {
            pathways.as_ref().expect("cache initialised")
        })
    }

    /// The identity clusters (see [`relation::resolve_identity_clusters`]), found once: AU-060
    /// and AU-071 both read them.
    pub fn identity_clusters(&self) -> Ref<'_, Vec<Vec<String>>> {
        if self.clusters.borrow().is_none() {
            let clusters = relation::resolve_identity_clusters(self.relations);
            *self.clusters.borrow_mut() = Some(clusters);
        }
        Ref::map(self.clusters.borrow(), |clusters| {
            clusters.as_ref().expect("cache initialised")
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn as_canonical(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    #[must_use]
    pub const fn weight(self) -> f64 {
        match self {
            Self::Low => 1.0,
            Self::Medium => 2.0,
            Self::High => 3.0,
            Self::Critical => 4.0,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_canonical())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Correlation {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub entity_uids: Vec<String>,
    pub scan_id: String,
    pub ts: u64,
    #[serde(default)]
    pub rank: f64,
}

impl Correlation {
    #[must_use]
    pub fn new(
        rule_id: &str,
        rule_name: &str,
        severity: Severity,
        description: impl Into<String>,
        entity_uids: Vec<String>,
        scan_id: &str,
        ts: u64,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            severity,
            description: description.into(),
            entity_uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        }
    }
}

pub trait Rule: Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn description(&self) -> &'static str;
    fn run(&self, context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation>;
}

struct FnRule {
    id: &'static str,
    name: &'static str,
    severity: Severity,
    description: &'static str,
    runner: fn(&RuleContext<'_>, &str, u64) -> Vec<Correlation>,
}

impl Rule for FnRule {
    fn id(&self) -> &'static str {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn description(&self) -> &'static str {
        self.description
    }

    fn run(&self, context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation> {
        (self.runner)(context, scan_id, now)
    }
}

static AU_001: FnRule = FnRule {
    id: "AU-001",
    name: "multi_breach",
    severity: Severity::High,
    description: "Two or more identity entities appear in breach data.",
    runner: rule_au_001_multi_breach,
};
static AU_002: FnRule = FnRule {
    id: "AU-002",
    name: "identity_cluster",
    severity: Severity::Critical,
    description: "Identities of at least two kinds (email, username, phone, name) that plausibly belong to one person. Not counted: a handle any record of which was guessed from an address, a name every record of which was, a role mailbox other than the operator's own, and a contact a registration record publishes as a group or an organisation, or as an abuse desk it does not call an individual, that no other source observed. More of a kind than one person holds is no cluster.",
    runner: rule_au_002_identity_cluster,
};
static AU_003: FnRule = FnRule {
    id: "AU-003",
    name: "high_corroboration",
    severity: Severity::Medium,
    description: "An entity that two or more independent sources corroborate with high confidence.",
    runner: rule_au_003_high_corroboration,
};
static AU_019: FnRule = FnRule {
    id: "AU-019",
    name: "temporal_breach_cluster",
    severity: Severity::High,
    description: "Three or more breached entities whose first breaches fall within one 30-day window.",
    runner: rule_au_019_temporal_breach_cluster,
};
static AU_021: FnRule = FnRule {
    id: "AU-021",
    name: "api_key_exposure",
    severity: Severity::Critical,
    description: "An API key found exposed.",
    runner: rule_au_021_api_key_exposure,
};
static AU_060: FnRule = FnRule {
    id: "AU-060",
    name: "transitive_identity_closure",
    severity: Severity::High,
    description: "Three or more entities joined by identity-binding relations.",
    runner: rule_au_060_transitive_identity_closure,
};
static AU_062: FnRule = FnRule {
    id: "AU-062",
    name: "multipath_corroboration",
    severity: Severity::High,
    description: "Two entities linked by two or more independent pathways.",
    runner: rule_au_062_multipath_corroboration,
};
static AU_063: FnRule = FnRule {
    id: "AU-063",
    name: "corroboration_gap",
    severity: Severity::Low,
    description: "Entities joined by one identity pathway that the count found; corroborating it would firm up the link.",
    runner: rule_au_063_corroboration_gap,
};
static AU_070: FnRule = FnRule {
    id: "AU-070",
    name: "connection_broker",
    severity: Severity::Medium,
    description: "An entity that brokers two or more of the strongest identity paths between others.",
    runner: rule_au_070_connection_broker,
};
static AU_071: FnRule = FnRule {
    id: "AU-071",
    name: "robust_identity_cluster",
    severity: Severity::High,
    description: "An identity cluster of four or more entities held together by more than one kind of identity relation and more than one piece of evidence.",
    runner: rule_au_071_robust_identity_cluster,
};
static AU_109: FnRule = FnRule {
    id: "AU-109",
    name: "shared_registrant",
    severity: Severity::Medium,
    description: "Two or more assets registered or operated by one registrant.",
    runner: rule_au_109_shared_registrant,
};
static AU_110: FnRule = FnRule {
    id: "AU-110",
    name: "shared_hosting_ip",
    severity: Severity::Medium,
    description: "Two or more domains resolving to one hosting IP address.",
    runner: rule_au_110_shared_hosting_ip,
};

static REGISTRY: [&dyn Rule; 12] = [
    &AU_001, &AU_002, &AU_003, &AU_019, &AU_021, &AU_060, &AU_062, &AU_063, &AU_070, &AU_071,
    &AU_109, &AU_110,
];

/// Every rule, in the order a pass runs them. [`evaluate_rules`] is the only caller, so every
/// correlation comes from one pass over one rule input.
fn registry() -> &'static [&'static dyn Rule] {
    &REGISTRY
}

/// One of Huntsman's own correlation rules, as a rule list shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub description: &'static str,
}

/// Every rule [`evaluate_rules`] runs, in the order it runs them.
#[must_use]
pub fn rule_catalog() -> Vec<RuleInfo> {
    registry()
        .iter()
        .map(|rule| RuleInfo {
            id: rule.id(),
            name: rule.name(),
            severity: rule.severity(),
            description: rule.description(),
        })
        .collect()
}

pub fn rank_and_sort(correlations: &mut [Correlation], entities: &[Entity]) {
    let ceff = entities
        .iter()
        .map(|entity| (entity.uid.clone(), entity.c_effective()))
        .collect::<HashMap<_, _>>();
    for correlation in correlations.iter_mut() {
        let max_child = correlation
            .entity_uids
            .iter()
            .filter_map(|uid| ceff.get(uid).copied())
            .fold(0.0_f64, f64::max);
        correlation.rank = correlation.severity.weight() * max_child;
    }
    correlations.sort_by(|left, right| {
        right
            .rank
            .partial_cmp(&left.rank)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(right.severity.cmp(&left.severity))
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.entity_uids.cmp(&right.entity_uids))
    });
}

#[must_use]
pub fn confirmed_only(entities: &[Entity]) -> Vec<Entity> {
    entities
        .iter()
        .filter(|entity| !entity.has_tag(tags::CANDIDATE))
        .cloned()
        .collect()
}

/// The relations a rule pass reads: those [`relation::derive_all`] infers from the confirmed
/// entities and those `observed`, kept only where both ends are confirmed entities, each
/// `(from, to, kind)` once at its highest confidence.
///
/// A relation through a candidate, or to a uid the scan holds no entity for, is not read: a rule
/// would name that entity, or link two confirmed entities through it, and neither was confirmed.
fn rule_relations(confirmed: &[Entity], observed: &[Relation], scan_id: &str) -> Vec<Relation> {
    let members = confirmed
        .iter()
        .map(|entity| entity.uid.as_str())
        .collect::<HashSet<_>>();
    let joins_members = |relation: &Relation| {
        members.contains(relation.from_uid.as_str()) && members.contains(relation.to_uid.as_str())
    };
    let relations = relation::derive_all(confirmed, scan_id)
        .into_iter()
        .filter(|relation| joins_members(relation))
        .chain(
            observed
                .iter()
                .filter(|relation| joins_members(relation))
                .cloned(),
        )
        .collect();
    relation::collapse_duplicates_max_confidence(relations)
}

/// Run every rule once over one scan's entities. The analysis behind `plan` and the web UI, and
/// `correlate` on a saved scan, all correlate here, so the same entities give the same
/// correlations whichever path they take.
///
/// Candidates are dropped first. The rules then read the confirmed entities and the relations
/// between them (see [`rule_relations`]); `observed` carries relations a collector recorded,
/// such as those stored with a saved scan. Every correlation is stamped with the scan's latest
/// observation, not the wall clock, so correlating the same scan again gives identical output.
#[must_use]
pub fn evaluate_rules(
    entities: &[Entity],
    observed: &[Relation],
    scan_id: &str,
) -> Vec<Correlation> {
    let confirmed = confirmed_only(entities);
    let relations = rule_relations(&confirmed, observed, scan_id);
    let context = RuleContext::new(&confirmed, &relations);
    let now = entities
        .iter()
        .map(|entity| entity.observed_at_unix)
        .max()
        .unwrap_or(0);
    let mut out = Vec::new();
    for rule in registry() {
        out.extend(rule.run(&context, scan_id, now));
    }
    rank_and_sort(&mut out, &confirmed);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
    use crate::relation::RelationKind;

    fn evidence(source: &str, summary: &str) -> Evidence {
        Evidence::new(EvidenceProvenance::new(source), summary)
    }

    fn ent(kind: EntityKind, value: &str, conf: f64, src: &str, candidate: bool) -> Entity {
        let mut entity = Entity::new(kind, value, conf, "scan");
        entity.add_evidence(evidence(src, "x"));
        if candidate {
            entity.tag(tags::CANDIDATE);
        }
        entity
    }

    #[test]
    fn the_rule_catalog_names_and_describes_every_rule_once() {
        let catalog = rule_catalog();
        assert_eq!(catalog.len(), REGISTRY.len());
        let ids: std::collections::BTreeSet<&str> = catalog.iter().map(|rule| rule.id).collect();
        assert_eq!(ids.len(), catalog.len());
        assert!(
            catalog
                .iter()
                .all(|rule| !rule.name.is_empty() && rule.description.ends_with('.'))
        );
    }

    #[test]
    fn rule_context_by_uid_indexes_every_entity_and_caches() {
        let entities = vec![
            ent(EntityKind::Email, "a@example.com", 0.9, "src-a", false),
            ent(EntityKind::Username, "alice", 0.8, "src-b", false),
            ent(EntityKind::Domain, "example.com", 0.7, "src-c", false),
        ];
        let ctx = RuleContext::new(&entities, &[]);
        let by_uid = ctx.by_uid();
        assert_eq!(by_uid.len(), entities.len());
        for entity in &entities {
            let got = by_uid.get(entity.uid.as_str()).unwrap();
            assert_eq!(got.uid, entity.uid);
        }
        drop(by_uid);
        assert_eq!(ctx.by_uid().len(), entities.len());
    }

    #[test]
    fn temporal_breach_cluster_survives_non_ascii_breach_date() {
        let mk = |value: &str, date: &str| {
            let mut entity = Entity::new(EntityKind::Email, value, 0.8, "scan");
            entity.tag(tags::BREACH);
            entity.add_evidence(evidence("hibp", "breach").with_attr("breach_date", date));
            entity
        };
        let entities = vec![
            mk("a@x.com", "2024-01-0€9"),
            mk("b@x.com", "2024-01-15"),
            mk("c@x.com", "2024-02-10"),
        ];
        let _ = rule_au_019_temporal_breach_cluster(&RuleContext::new(&entities, &[]), "scan", 0);
    }

    #[test]
    fn temporal_breach_cluster_window_is_anchored_not_rolling() {
        let mk = |value: &str, date: &str| {
            let mut entity = Entity::new(EntityKind::Email, value, 0.8, "scan");
            entity.tag(tags::BREACH);
            entity.add_evidence(evidence("hibp", "breach").with_attr("breach_date", date));
            entity
        };
        let tight = vec![
            mk("a@x.com", "2024-01-01"),
            mk("b@x.com", "2024-01-10"),
            mk("c@x.com", "2024-01-20"),
        ];
        let result = rule_au_019_temporal_breach_cluster(&RuleContext::new(&tight, &[]), "scan", 0);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].entity_uids.len(), 3);
        let chained = vec![
            mk("a@x.com", "2024-01-01"),
            mk("b@x.com", "2024-01-30"),
            mk("c@x.com", "2024-02-28"),
            mk("d@x.com", "2024-03-30"),
        ];
        let chained_result =
            rule_au_019_temporal_breach_cluster(&RuleContext::new(&chained, &[]), "scan", 0);
        assert!(chained_result.is_empty(), "{chained_result:?}");
    }

    #[test]
    fn candidates_are_excluded_from_correlation() {
        let mut entities = vec![
            ent(EntityKind::Email, "me@real.com", 0.85, "oathnet_pro", false),
            ent(EntityKind::Username, "me", 0.7, "oathnet_pro", false),
            ent(EntityKind::Phone, "15551112222", 0.7, "oathnet_pro", false),
        ];
        for i in 0..40 {
            entities.push(ent(
                EntityKind::Email,
                &format!("stranger{i}@bank.com"),
                0.25,
                "oathnet_pro",
                true,
            ));
        }
        let firings = evaluate_rules(&entities, &[], "scan");
        let candidate_uids = entities
            .iter()
            .filter(|entity| entity.has_tag(tags::CANDIDATE))
            .map(|entity| entity.uid.as_str())
            .collect::<std::collections::HashSet<_>>();
        for correlation in &firings {
            for uid in &correlation.entity_uids {
                assert!(!candidate_uids.contains(uid.as_str()));
            }
        }
        let au002 = firings
            .iter()
            .find(|correlation| correlation.rule_id == "AU-002")
            .unwrap();
        assert!(au002.description.contains("1 email(s)"));
    }

    #[test]
    fn au002_refuses_to_fuse_an_implausible_identity_dump() {
        let mut big = vec![
            ent(EntityKind::Username, "u", 0.7, "s", false),
            ent(EntityKind::Phone, "15551112222", 0.7, "s", false),
        ];
        for i in 0..30 {
            big.push(ent(
                EntityKind::Email,
                &format!("e{i}@x.com"),
                0.7,
                "s",
                false,
            ));
        }
        let findings = rule_au_002_identity_cluster(&RuleContext::new(&big, &[]), "scan", 0);
        assert!(findings.is_empty(), "{findings:?}");
        let small = vec![
            ent(EntityKind::Email, "me@x.com", 0.85, "s", false),
            ent(EntityKind::Username, "me", 0.7, "s", false),
            ent(EntityKind::Phone, "15551112222", 0.7, "s", false),
        ];
        assert_eq!(
            rule_au_002_identity_cluster(&RuleContext::new(&small, &[]), "scan", 0).len(),
            1
        );
        let weak = vec![
            ent(EntityKind::Email, "me@x.com", 0.3, "s", false),
            ent(EntityKind::Username, "me", 0.3, "s", false),
            ent(EntityKind::Phone, "15551112222", 0.3, "s", false),
        ];
        let findings = rule_au_002_identity_cluster(&RuleContext::new(&weak, &[]), "scan", 0);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn au002_does_not_count_a_username_inferred_from_the_email() {
        // The email's local part, derived as a username (inferred), plus a public profile found
        // under that name. The profile is observed, but the name still adds no identity.
        let email = ent(EntityKind::Email, "me@x.com", 0.99, "seed", false);
        let mut username = Entity::new(EntityKind::Username, "me", 0.65, "scan");
        username.add_evidence(evidence("email_parse", "derived from me@x.com").inferred());
        username.add_evidence(evidence("gravatar", "public profile"));
        let entities = vec![email, username];
        let findings = rule_au_002_identity_cluster(&RuleContext::new(&entities, &[]), "scan", 0);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn au002_still_counts_an_observed_username_beside_the_email() {
        let email = ent(EntityKind::Email, "me@x.com", 0.99, "seed", false);
        let username = ent(EntityKind::Username, "me", 0.65, "gravatar", false);
        let entities = vec![email, username];
        let findings = rule_au_002_identity_cluster(&RuleContext::new(&entities, &[]), "scan", 0);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].description.contains("1 username(s)"));
    }

    /// A person guessed from an e-mail's local part is no identity beside the address: a corporate
    /// `first.last@` alone is no identity cluster.
    #[test]
    fn au002_does_not_count_a_person_inferred_from_the_email() {
        let email = ent(
            EntityKind::Email,
            "jane.doe@acme.example",
            0.99,
            "seed",
            false,
        );
        let mut person = Entity::new(EntityKind::Person, "Jane Doe", 0.55, "scan");
        person
            .add_evidence(evidence("email_parse", "derived from jane.doe@acme.example").inferred());
        let entities = vec![email, person];
        let findings = rule_au_002_identity_cluster(&RuleContext::new(&entities, &[]), "scan", 0);
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// A name a source tied to the address observed is an identity, though the analysis also
    /// derived it from the address: a key server's "Jane Doe" for `jane.doe@` is the mailbox's.
    #[test]
    fn au002_counts_a_name_a_source_observed_for_the_address() {
        let email = ent(
            EntityKind::Email,
            "jane.doe@acme.example",
            0.99,
            "seed",
            false,
        );
        let mut person = Entity::new(EntityKind::Person, "Jane Doe", 0.65, "scan");
        person
            .add_evidence(evidence("email_parse", "derived from jane.doe@acme.example").inferred());
        person.add_evidence(evidence(
            "openpgp_keys",
            "uid of the key for jane.doe@acme.example",
        ));
        let entities = vec![email, person];
        let findings = rule_au_002_identity_cluster(&RuleContext::new(&entities, &[]), "scan", 0);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].description.contains("1 person(s)"));
    }

    /// The mailbox or telephone of one of a registration record's contacts, as the RDAP legs
    /// record it: its roles and, when the record gives one, its jCard kind.
    fn registration_contact(
        kind: EntityKind,
        value: &str,
        roles: &str,
        jcard: Option<&str>,
    ) -> Entity {
        let tag = if roles.split(", ").any(|role| role == "abuse") {
            tags::ABUSE_CONTACT
        } else {
            tags::WHOIS_CONTACT
        };
        let mut entity = Entity::new(kind, value, 0.85, "scan");
        entity.add_evidence(
            evidence(
                crate::rdap::SOURCE,
                &format!("contact ({roles}) in the registration"),
            )
            .with_attr("role", roles)
            .with_optional_attrs([("contact_kind", jcard)]),
        );
        entity.tag(tag);
        entity
    }

    /// A registration record's contacts that name a function (an abuse desk, a role or an
    /// organisation's mailbox, its switchboard) are no identity cluster, also once a crawl has
    /// looked them up; a contact the record publishes as an individual, or without a kind, is a
    /// person's, and so is one another source also observed.
    #[test]
    fn au002_does_not_count_a_registration_records_role_contacts() {
        let fires = |entities: &[Entity]| {
            rule_au_002_identity_cluster(&RuleContext::new(entities, &[]), "scan", 0).len()
        };
        let role = registration_contact;
        // An operator's role mailbox at its own domain, and its abuse desk's telephone.
        let mut registry = vec![
            role(
                EntityKind::Email,
                "rir@smallisp.example",
                "administrative, technical",
                Some("group"),
            ),
            role(EntityKind::Phone, "+16503198930", "abuse", None),
        ];
        assert_eq!(fires(&registry), 0, "{registry:?}");
        assert!(
            evaluate_rules(&registry, &[], "scan")
                .iter()
                .all(|correlation| correlation.rule_id != "AU-002")
        );
        // A crawl looked both up: the telephone's numbering plan and the lookup's echo of the
        // mailbox observe no one.
        registry[0].add_evidence(evidence("seed", "email selector the lookup was asked"));
        registry[1].add_evidence(evidence("phone_intl", "international number"));
        assert_eq!(fires(&registry), 0, "{registry:?}");

        // An individual's contact, or one with no kind, which a jCard reads as an individual.
        for jcard in [Some("individual"), None] {
            let person = vec![
                role(
                    EntityKind::Email,
                    "jsmith@smallco.example",
                    "registrant",
                    jcard,
                ),
                role(EntityKind::Phone, "+61412345678", "registrant", jcard),
            ];
            assert_eq!(fires(&person), 1, "{jcard:?}");
        }
        // An abuse desk the record calls an individual is a person's contact too.
        let desk = vec![
            role(
                EntityKind::Email,
                "jsmith@smallco.example",
                "abuse",
                Some("individual"),
            ),
            role(
                EntityKind::Phone,
                "+61412345678",
                "abuse",
                Some("individual"),
            ),
        ];
        assert_eq!(fires(&desk), 1);

        // A registration contact another source also observed counts.
        let seen = |kind: EntityKind, value: &str| {
            let mut entity = role(kind, value, "technical", Some("group"));
            entity.add_evidence(evidence("hibp", "breach record"));
            entity
        };
        let corroborated = vec![
            seen(EntityKind::Email, "jane@acme.example"),
            seen(EntityKind::Phone, "+61412345678"),
        ];
        assert_eq!(fires(&corroborated), 1);
    }

    /// A role mailbox names a function wherever it was found, unless the operator asked about it;
    /// a person's mailbox at a provider's own domain is a person's.
    #[test]
    fn au002_does_not_count_a_role_mailbox_but_the_operators_own() {
        let fires = |entities: &[Entity]| {
            rule_au_002_identity_cluster(&RuleContext::new(entities, &[]), "scan", 0).len()
        };
        let phone = || ent(EntityKind::Phone, "+61412345678", 0.85, "hibp", false);
        let found = vec![
            ent(
                EntityKind::Email,
                "hostmaster@acme.example",
                0.85,
                "crtsh",
                false,
            ),
            phone(),
        ];
        assert_eq!(fires(&found), 0);
        let mut asked = Entity::new(EntityKind::Email, "hello@janedoe.example", 0.99, "scan");
        asked.add_evidence(Evidence::new(
            EvidenceProvenance::new("seed"),
            "email selector the lookup was asked",
        ));
        assert_eq!(fires(&[asked, phone()]), 1);
        let staff = ent(
            EntityKind::Email,
            "jane.doe@google.com",
            0.85,
            "hibp",
            false,
        );
        assert_eq!(fires(&[staff, phone()]), 1);
    }

    /// Too many identities of a kind to be one person is judged by every identity observed, so
    /// a page listing seven mailboxes is no person's, however few of them are a person's own.
    #[test]
    fn au002_judges_a_dump_by_every_identity_observed() {
        let mut page: Vec<Entity> = ["info", "sales", "support", "accounts"]
            .iter()
            .map(|local| {
                ent(
                    EntityKind::Email,
                    &format!("{local}@acme.example"),
                    0.6,
                    "wayback_cdx",
                    false,
                )
            })
            .collect();
        for local in ["jane", "bob", "alice"] {
            page.push(ent(
                EntityKind::Email,
                &format!("{local}@acme.example"),
                0.6,
                "wayback_cdx",
                false,
            ));
        }
        page.push(ent(
            EntityKind::Phone,
            "+61290000000",
            0.6,
            "wayback_cdx",
            false,
        ));
        let findings = rule_au_002_identity_cluster(&RuleContext::new(&page, &[]), "scan", 0);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn every_breach_module_is_a_breach_source() {
        // The module catalogue's `Breach` category and the correlator's breach family must agree,
        // or a breach module's hits never count toward `multi_breach`.
        let breach_modules = crate::module::reachable_modules()
            .iter()
            .filter(|module| module.category == crate::dependency::ModuleCategory::Breach)
            .collect::<Vec<_>>();
        assert!(breach_modules.len() >= 3, "{breach_modules:?}");
        for module in breach_modules {
            assert_eq!(source_family(module.name), "breach", "{}", module.name);
        }
    }

    #[test]
    fn helper_behaviour_matches_legacy_oracles() {
        assert!(text_mentions_ip("seen at 1.2.3.4: Brisbane", "1.2.3.4"));
        assert!(text_mentions_ip("via [2001:db8::1]:443", "2001:db8::1"));
        assert!(!text_mentions_ip("host 1.2.3.45 responded", "1.2.3.4"));
        assert!(!text_mentions_ip("aé1", "é"));
        assert_eq!(source_family("ip2location"), "infra");
        assert_eq!(source_family("hibp"), "breach");
        assert_eq!(source_family("seeknow"), "breach");
        assert_eq!(source_family("see_know"), "breach");
        assert_eq!(source_family("github_user"), "code");
        assert_eq!(date_diff_days("2024-06-15", "2024-06-15"), 0);
        assert!(crate::relation::is_generic_handle("support"));
        assert!(!crate::relation::is_generic_handle("adalovelace"));
    }

    #[test]
    fn run_ranks_by_severity_times_max_child_ceff() {
        let mut weak_key = Entity::new(EntityKind::ApiKey, "AKIAWEAK", 0.20, "scan");
        weak_key.add_evidence(evidence("key_harvest", "found once"));
        let mut strong_email = Entity::new(EntityKind::Email, "a@b.com", 0.95, "scan");
        for source in ["hibp", "dehashed", "search_engines"] {
            strong_email.add_evidence(evidence(source, "seen"));
        }
        let results = evaluate_rules(&[weak_key, strong_email], &[], "scan");
        assert_eq!(results[0].rule_id, "AU-003");
        assert!(
            results
                .iter()
                .any(|correlation| correlation.rule_id == "AU-021")
        );
    }

    #[test]
    fn relation_rules_cover_core_graph_patterns() {
        let entities = vec![
            ent(EntityKind::Email, "a@example.com", 0.9, "hibp", false),
            ent(EntityKind::Username, "alice", 0.8, "github_user", false),
            ent(EntityKind::Phone, "15551112222", 0.8, "name_intel", false),
            ent(EntityKind::Domain, "a.example.com", 0.8, "whois", false),
            ent(EntityKind::Domain, "b.example.com", 0.8, "whois", false),
            ent(EntityKind::IpAddress, "1.2.3.4", 0.8, "dns_intel", false),
        ];
        let relations = vec![
            Relation::new(
                &entities[0].uid,
                &entities[1].uid,
                RelationKind::AliasOf,
                0.8,
                "scan",
            ),
            Relation::new(
                &entities[1].uid,
                &entities[2].uid,
                RelationKind::IdentifiedBy,
                0.8,
                "scan",
            ),
            Relation::new(
                &entities[0].uid,
                &entities[2].uid,
                RelationKind::SameIdentity,
                0.7,
                "scan",
            ),
            Relation::new(
                &entities[3].uid,
                &entities[5].uid,
                RelationKind::ResolvesTo,
                0.8,
                "scan",
            ),
            Relation::new(
                &entities[4].uid,
                &entities[5].uid,
                RelationKind::ResolvesTo,
                0.8,
                "scan",
            ),
            Relation::new(
                &entities[3].uid,
                &entities[1].uid,
                RelationKind::RegisteredBy,
                0.8,
                "scan",
            ),
            Relation::new(
                &entities[4].uid,
                &entities[1].uid,
                RelationKind::RegisteredBy,
                0.8,
                "scan",
            ),
        ];
        let results = evaluate_rules(&entities, &relations, "scan");
        assert!(
            results
                .iter()
                .any(|correlation| correlation.rule_id == "AU-060")
        );
        assert!(
            results
                .iter()
                .any(|correlation| correlation.rule_id == "AU-062")
        );
        assert!(
            results
                .iter()
                .any(|correlation| correlation.rule_id == "AU-109")
        );
        assert!(
            results
                .iter()
                .any(|correlation| correlation.rule_id == "AU-110")
        );
    }

    /// The rule context walks its entities in uid order, so a rule that pairs them emits the same
    /// pairs, in the same order, every time. Six aliases in a chain give AU-063 all fifteen pairs:
    /// over a hash map every pair came out ascending only one run in 720, and the same entities
    /// correlated twice disagreed.
    #[test]
    fn correlating_the_same_entities_twice_gives_the_same_ordered_pairs() {
        let entities: Vec<Entity> = (0..6)
            .map(|n| {
                ent(
                    EntityKind::Username,
                    &format!("member{n}"),
                    0.9,
                    "src",
                    false,
                )
            })
            .collect();
        let relations: Vec<Relation> = entities
            .windows(2)
            .map(|pair| {
                Relation::new(
                    &pair[0].uid,
                    &pair[1].uid,
                    RelationKind::AliasOf,
                    0.8,
                    "scan",
                )
            })
            .collect();
        let first = evaluate_rules(&entities, &relations, "scan");
        let pairs: Vec<&Correlation> = first
            .iter()
            .filter(|correlation| correlation.rule_id == "AU-063")
            .collect();
        assert_eq!(pairs.len(), 15, "{first:?}");
        for correlation in &pairs {
            assert!(
                correlation
                    .entity_uids
                    .windows(2)
                    .all(|uids| uids[0] < uids[1]),
                "{correlation:?}"
            );
        }
        for _ in 0..8 {
            assert_eq!(evaluate_rules(&entities, &relations, "scan"), first);
        }
    }

    /// The rules read only relations between confirmed entities. A candidate is an unconfirmed
    /// guess, dropped before the rules run, and a uid the scan holds no entity for is unknown, so
    /// a link through either asserts nothing. Here three confirmed entities that share nothing
    /// are each linked to a candidate handle and to an unknown uid. Before, both joined the
    /// confirmed entities' identity cluster (AU-060, AU-071), brokered their strongest paths
    /// (AU-070), and gave every two of them two independent pathways (AU-062).
    #[test]
    fn identity_links_run_only_through_confirmed_entities() {
        let confirmed = [
            ent(EntityKind::Email, "ann@mail.example", 0.9, "hibp", false),
            ent(EntityKind::Username, "bob", 0.9, "github_user", false),
            ent(EntityKind::Phone, "15551112222", 0.9, "name_intel", false),
        ];
        let candidate = ent(EntityKind::Username, "guess", 0.9, "username_cli", true);
        let unknown = "uid-of-no-entity";
        let mut relations = Vec::new();
        for entity in &confirmed {
            relations.push(Relation::new(
                &entity.uid,
                &candidate.uid,
                RelationKind::AliasOf,
                0.9,
                "scan",
            ));
            relations.push(Relation::new(
                unknown,
                &entity.uid,
                RelationKind::IdentifiedBy,
                0.8,
                "scan",
            ));
        }
        let mut entities = confirmed.to_vec();
        entities.push(candidate.clone());

        let correlations = evaluate_rules(&entities, &relations, "scan");
        for correlation in &correlations {
            for uid in &correlation.entity_uids {
                assert!(
                    confirmed.iter().any(|entity| &entity.uid == uid),
                    "{} names {uid}, which is not a confirmed entity: {correlation:?}",
                    correlation.rule_id
                );
            }
        }
        let identity_rules = ["AU-060", "AU-062", "AU-063", "AU-070", "AU-071"];
        assert!(
            correlations
                .iter()
                .all(|correlation| !identity_rules.contains(&correlation.rule_id.as_str())),
            "no two confirmed entities are linked: {correlations:?}"
        );
    }

    /// Six addresses with one handle are aliases of each other, every link resting on that
    /// handle. They form one cluster (AU-060) with one gap (AU-063): the handle is the one
    /// pathway found between each pair. Before, each other address counted as an independent
    /// pathway, so all fifteen pairs raised a High AU-062 alert claiming five independent
    /// pathways, and none had a gap.
    #[test]
    fn a_handle_shared_by_many_addresses_is_one_pathway_and_one_gap() {
        let entities = (0..6)
            .map(|n| {
                ent(
                    EntityKind::Email,
                    &format!("jsmith.alpha@site{n}.example"),
                    0.9,
                    "dehashed",
                    false,
                )
            })
            .collect::<Vec<_>>();
        let mut uids = entities
            .iter()
            .map(|entity| entity.uid.clone())
            .collect::<Vec<_>>();
        uids.sort();
        let correlations = evaluate_rules(&entities, &[], "scan");
        let fired = |rule: &str| {
            correlations
                .iter()
                .filter(|correlation| correlation.rule_id == rule)
                .collect::<Vec<_>>()
        };
        assert!(fired("AU-062").is_empty(), "{correlations:?}");
        let clusters = fired("AU-060");
        assert_eq!(clusters.len(), 1, "{correlations:?}");
        assert_eq!(clusters[0].entity_uids, uids);
        let gaps = fired("AU-063");
        assert_eq!(gaps.len(), 1, "{correlations:?}");
        assert_eq!(gaps[0].entity_uids, uids);
        assert_eq!(
            gaps[0].description,
            "15 pairs among these 6 entities each have one identity pathway found, which rests on a shared handle"
        );
    }

    /// Two addresses with one handle are one pair joined by one pathway, the handle. Nothing else
    /// connects them, so the count is exact, and the gap says only what the search found.
    #[test]
    fn two_addresses_with_one_handle_gap_says_what_was_found() {
        let entities = (0..2)
            .map(|site| {
                ent(
                    EntityKind::Email,
                    &format!("jsmith.alpha@site{site}.example"),
                    0.9,
                    "dehashed",
                    false,
                )
            })
            .collect::<Vec<_>>();
        let gaps = evaluate_rules(&entities, &[], "scan")
            .into_iter()
            .filter(|correlation| correlation.rule_id == "AU-063")
            .map(|correlation| correlation.description)
            .collect::<Vec<_>>();
        assert_eq!(
            gaps,
            ["one identity pathway found connects the pair; the search found no second"]
        );
    }

    /// Evidence that rests on something other than the shared handle still corroborates. A
    /// breach record naming one owner for two of four addresses with one handle gives the owner
    /// with each of the two a second pathway (AU-062), and the two addresses also share a
    /// password hash, so they have three: the handle, the owner and the secret. The other five
    /// pairs of addresses remain one gap; the owner's single pathways to the other two addresses
    /// run through the record as well as the handle, so each is a gap of its own.
    #[test]
    fn evidence_beside_a_shared_handle_still_corroborates() {
        let address = |site: usize, owner: bool| {
            let mut entity = ent(
                EntityKind::Email,
                &format!("jsmith.alpha@site{site}.example"),
                0.9,
                "dehashed",
                false,
            );
            if owner {
                entity.add_evidence(
                    evidence("dehashed", "row")
                        .with_attr("owner", "Jane Roe")
                        .with_attr("password_hash", "5f4dcc3b5aa765d61d8327deb882cf99"),
                );
            }
            entity
        };
        let owner = ent(EntityKind::Person, "Jane Roe", 0.9, "dehashed", false);
        let entities = vec![
            address(0, true),
            address(1, true),
            address(2, false),
            address(3, false),
            owner.clone(),
        ];
        let pair = |left: &Entity, right: &Entity| {
            let mut uids = vec![left.uid.clone(), right.uid.clone()];
            uids.sort();
            uids
        };
        let correlations = evaluate_rules(&entities, &[], "scan");
        let mut corroborated = correlations
            .iter()
            .filter(|correlation| correlation.rule_id == "AU-062")
            .map(|correlation| {
                (
                    correlation.entity_uids.clone(),
                    correlation.description.as_str(),
                )
            })
            .collect::<Vec<_>>();
        corroborated.sort();
        let two = "2 independent pathways corroborate the link";
        let mut expected = vec![
            (
                pair(&entities[0], &entities[1]),
                "3 independent pathways corroborate the link",
            ),
            (pair(&owner, &entities[0]), two),
            (pair(&owner, &entities[1]), two),
        ];
        expected.sort();
        assert_eq!(corroborated, expected, "{correlations:?}");

        let mut gaps = correlations
            .iter()
            .filter(|correlation| correlation.rule_id == "AU-063")
            .map(|correlation| {
                (
                    correlation.entity_uids.clone(),
                    correlation.description.as_str(),
                )
            })
            .collect::<Vec<_>>();
        gaps.sort();
        let mut addresses = entities[..4]
            .iter()
            .map(|entity| entity.uid.clone())
            .collect::<Vec<_>>();
        addresses.sort();
        let single = "one identity pathway found connects the pair; the search found no second";
        let mut expected = vec![
            (
                addresses,
                "5 pairs among these 4 entities each have one identity pathway found, which rests on a shared handle",
            ),
            (pair(&owner, &entities[2]), single),
            (pair(&owner, &entities[3]), single),
        ];
        expected.sort();
        assert_eq!(gaps, expected, "{correlations:?}");
    }

    /// Four addresses with one handle and a person whose name is that handle are one identity
    /// cluster, joined by aliases and by identifiers: two kinds of relation that both rest on
    /// the handle. That is one piece of evidence, so the cluster is not robust (AU-071), and its
    /// one corroboration gap (AU-063) stands. An owner that a breach record names for one of the
    /// addresses is evidence of its own, and with it the cluster is robust.
    #[test]
    fn a_cluster_only_a_shared_handle_holds_is_not_robust() {
        let mut entities = (0..4)
            .map(|site| {
                ent(
                    EntityKind::Email,
                    &format!("jsmith.alpha@site{site}.example"),
                    0.9,
                    "dehashed",
                    false,
                )
            })
            .collect::<Vec<_>>();
        entities.push(ent(
            EntityKind::Person,
            "Jsmith Alpha",
            0.9,
            "dehashed",
            false,
        ));
        let fired = |entities: &[Entity], rule: &str| {
            evaluate_rules(entities, &[], "scan")
                .into_iter()
                .filter(|correlation| correlation.rule_id == rule)
                .map(|correlation| (correlation.entity_uids.len(), correlation.description))
                .collect::<Vec<_>>()
        };
        assert_eq!(fired(&entities, "AU-071"), []);
        assert_eq!(fired(&entities, "AU-060").len(), 1);
        assert_eq!(
            fired(&entities, "AU-063"),
            [(
                5,
                "10 pairs among these 5 entities each have one identity pathway found, which rests on a shared handle".to_owned()
            )]
        );

        entities[0].add_evidence(evidence("dehashed", "row").with_attr("owner", "Jane Roe"));
        entities.push(ent(EntityKind::Person, "Jane Roe", 0.9, "dehashed", false));
        assert_eq!(
            fired(&entities, "AU-071"),
            [(
                6,
                "6 entities connected by 2 kinds of identity relation resting on 2 independent \
                 pieces of evidence"
                    .to_owned()
            )]
        );
    }

    /// Four addresses that three same-as assertions join are one identity, by one kind of
    /// identity relation. An association between two of them says nothing about whether they are
    /// one identity, so it does not make the cluster robust (AU-071); an alias does.
    #[test]
    fn only_identity_relations_make_a_cluster_robust() {
        let entities = [
            "ann@a.example",
            "bob@b.example",
            "cat@c.example",
            "dan@d.example",
        ]
        .map(|value| ent(EntityKind::Email, value, 0.9, "dehashed", false));
        let uid = |n: usize| entities[n].uid.as_str();
        let mut relations = vec![
            Relation::new(uid(0), uid(1), RelationKind::SameAs, 0.8, "scan"),
            Relation::new(uid(1), uid(2), RelationKind::SameAs, 0.8, "scan"),
            Relation::new(uid(2), uid(3), RelationKind::SameAs, 0.8, "scan"),
            Relation::new(uid(0), uid(3), RelationKind::AssociatedWith, 0.8, "scan"),
        ];
        let robust = |relations: &[Relation]| {
            evaluate_rules(&entities, relations, "scan")
                .into_iter()
                .filter(|correlation| correlation.rule_id == "AU-071")
                .map(|correlation| correlation.description)
                .collect::<Vec<_>>()
        };
        assert_eq!(robust(&relations), Vec::<String>::new());
        relations.push(Relation::new(
            uid(0),
            uid(2),
            RelationKind::AliasOf,
            0.8,
            "scan",
        ));
        assert_eq!(
            robust(&relations),
            [
                "4 entities connected by 2 kinds of identity relation resting on 4 independent \
              pieces of evidence"
            ]
        );
    }

    /// A correlation is stamped with the scan's latest observation, not the wall clock, so
    /// correlating the same scan again, now or a year later, gives identical output.
    #[test]
    fn correlations_are_stamped_with_the_scans_latest_observation() {
        let mut early = ent(EntityKind::Email, "a@example.com", 0.95, "hibp", false);
        for source in ["dehashed", "search_engines"] {
            early.add_evidence(evidence(source, "seen"));
        }
        early.observed_at_unix = 1_000;
        let mut late = ent(EntityKind::Username, "zed", 0.9, "github_user", false);
        late.observed_at_unix = 2_000;
        let correlations = evaluate_rules(&[early, late], &[], "scan");
        assert!(!correlations.is_empty(), "AU-003 fires on the email");
        for correlation in &correlations {
            assert_eq!(correlation.ts, 2_000, "{correlation:?}");
        }
    }
}
