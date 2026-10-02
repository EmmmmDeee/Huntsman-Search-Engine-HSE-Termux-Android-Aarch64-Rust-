use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_handle;
use crate::entity::{Entity, EntityKind};
use crate::relation::{
    Relation, RelationKind, connection_brokers, disjoint_pathways, resolve_identity_clusters,
};
use crate::tags;
use crate::timefmt::parse_timestamp;

pub struct RuleContext<'a> {
    entities: &'a [Entity],
    relations: &'a [Relation],
    by_uid: RefCell<Option<HashMap<&'a str, &'a Entity>>>,
    by_canonical_handle: RefCell<Option<HashMap<String, Vec<&'a Entity>>>>,
}

impl<'a> RuleContext<'a> {
    #[must_use]
    pub fn new(entities: &'a [Entity], relations: &'a [Relation]) -> Self {
        Self {
            entities,
            relations,
            by_uid: RefCell::new(None),
            by_canonical_handle: RefCell::new(None),
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

    pub fn by_uid(&self) -> std::cell::Ref<'_, HashMap<&'a str, &'a Entity>> {
        if self.by_uid.borrow().is_none() {
            *self.by_uid.borrow_mut() = Some(
                self.entities
                    .iter()
                    .map(|entity| (entity.uid.as_str(), entity))
                    .collect(),
            );
        }
        std::cell::Ref::map(self.by_uid.borrow(), |map| {
            map.as_ref().expect("cache initialised")
        })
    }

    pub fn by_canonical_handle(&self) -> std::cell::Ref<'_, HashMap<String, Vec<&'a Entity>>> {
        if self.by_canonical_handle.borrow().is_none() {
            let mut map = HashMap::<String, Vec<&Entity>>::new();
            for entity in self.entities {
                if let Some(handle) = canonical_handle(&entity.value) {
                    map.entry(handle).or_default().push(entity);
                }
            }
            *self.by_canonical_handle.borrow_mut() = Some(map);
        }
        std::cell::Ref::map(self.by_canonical_handle.borrow(), |map| {
            map.as_ref().expect("cache initialised")
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
    fn run(&self, context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation>;
}

struct FnRule {
    id: &'static str,
    name: &'static str,
    severity: Severity,
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

    fn run(&self, context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation> {
        (self.runner)(context, scan_id, now)
    }
}

static AU_001: FnRule = FnRule {
    id: "AU-001",
    name: "multi_breach",
    severity: Severity::High,
    runner: rule_au_001_multi_breach,
};
static AU_002: FnRule = FnRule {
    id: "AU-002",
    name: "identity_cluster",
    severity: Severity::Critical,
    runner: rule_au_002_identity_cluster,
};
static AU_003: FnRule = FnRule {
    id: "AU-003",
    name: "high_corroboration",
    severity: Severity::Medium,
    runner: rule_au_003_high_corroboration,
};
static AU_019: FnRule = FnRule {
    id: "AU-019",
    name: "temporal_breach_cluster",
    severity: Severity::High,
    runner: rule_au_019_temporal_breach_cluster,
};
static AU_021: FnRule = FnRule {
    id: "AU-021",
    name: "api_key_exposure",
    severity: Severity::Critical,
    runner: rule_au_021_api_key_exposure,
};
static AU_060: FnRule = FnRule {
    id: "AU-060",
    name: "transitive_identity_closure",
    severity: Severity::High,
    runner: rule_au_060_transitive_identity_closure,
};
static AU_062: FnRule = FnRule {
    id: "AU-062",
    name: "multipath_corroboration",
    severity: Severity::High,
    runner: rule_au_062_multipath_corroboration,
};
static AU_063: FnRule = FnRule {
    id: "AU-063",
    name: "corroboration_gap",
    severity: Severity::Low,
    runner: rule_au_063_corroboration_gap,
};
static AU_070: FnRule = FnRule {
    id: "AU-070",
    name: "connection_broker",
    severity: Severity::Medium,
    runner: rule_au_070_connection_broker,
};
static AU_071: FnRule = FnRule {
    id: "AU-071",
    name: "robust_identity_cluster",
    severity: Severity::High,
    runner: rule_au_071_robust_identity_cluster,
};
static AU_109: FnRule = FnRule {
    id: "AU-109",
    name: "shared_registrant",
    severity: Severity::Medium,
    runner: rule_au_109_shared_registrant,
};
static AU_110: FnRule = FnRule {
    id: "AU-110",
    name: "shared_hosting_ip",
    severity: Severity::Medium,
    runner: rule_au_110_shared_hosting_ip,
};

static REGISTRY: [&dyn Rule; 12] = [
    &AU_001, &AU_002, &AU_003, &AU_019, &AU_021, &AU_060, &AU_062, &AU_063, &AU_070, &AU_071,
    &AU_109, &AU_110,
];

#[must_use]
pub fn registry() -> &'static [&'static dyn Rule] {
    &REGISTRY
}

pub struct Correlator;

impl Correlator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn run_on(
        &self,
        entities: &[Entity],
        relations: &[Relation],
        scan_id: &str,
    ) -> Vec<Correlation> {
        evaluate_rules(entities, relations, scan_id)
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
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

#[must_use]
pub fn evaluate_rules(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
) -> Vec<Correlation> {
    let confirmed = confirmed_only(entities);
    let context = RuleContext::new(&confirmed, relations);
    let now = crate::entity::unix_now();
    let mut out = Vec::new();
    for rule in registry() {
        out.extend(rule.run(&context, scan_id, now));
    }
    rank_and_sort(&mut out, &confirmed);
    out
}

#[must_use]
pub fn correlate_entities(entities: &[Entity], scan_id: &str) -> Vec<Correlation> {
    evaluate_rules(entities, &[], scan_id)
}

#[must_use]
pub fn text_mentions_ip(text: &str, ip: &str) -> bool {
    if ip.is_empty() || !ip.is_ascii() {
        return false;
    }
    let haystack = text.to_ascii_lowercase();
    let needle = ip.to_ascii_lowercase();
    let extends = if needle.contains(':') {
        |byte: u8| byte.is_ascii_hexdigit() || byte == b':'
    } else {
        |byte: u8| byte.is_ascii_digit() || byte == b'.'
    };
    haystack.match_indices(&needle).any(|(index, _)| {
        let before_ok = index == 0 || !extends(haystack.as_bytes()[index - 1]);
        let after_index = index + needle.len();
        let after_ok = after_index == haystack.len() || !extends(haystack.as_bytes()[after_index]);
        before_ok && after_ok
    })
}

#[must_use]
pub fn source_family(source: &str) -> &'static str {
    let source = source.trim().to_ascii_lowercase();
    match source.as_str() {
        "comb_search" | "dehashed" | "hibp" | "hudsonrock" | "intelx" | "leakcheck_public"
        | "leakix" | "niamonx" | "osintcat" | "psbdmp" | "pwned_passwords" | "xposed_or_not"
        | "oathnet_pro" | "see_know" => "breach",
        "github_user" | "npm_author" | "crates_io" => "code",
        "reddit_user" | "hacker_news" => "forum",
        "social_probe" | "gravatar" => "social",
        "username_search" | "epieos" => "presence",
        "search_engines" | "google" | "exa_search" => "search",
        "smtp_vrfy" | "emailrep" => "email_intel",
        "proxycurl" | "name_intel" | "fullcontact" | "contact_enrich" | "gleif_lei"
        | "asic_director" | "au_electoral" | "au_people" | "ahpra" | "acnc_charities" => {
            "identity_registry"
        }
        "shodan" | "dns_intel" | "ip_geo" | "geocode" | "ip_whois_geo" | "ip2location"
        | "mylnikov" | "abuseipdb" | "bgpview" | "criminal_ip" | "ipqs" | "netblock" | "netlas"
        | "onyphe" | "portscan" | "ripestat" | "securitytrails" | "zoomeye" | "domainsdb" => {
            "infra"
        }
        _ if source.contains("github") || source.contains("npm") => "code",
        _ if source.contains("forum") || source.contains("reddit") => "forum",
        _ if source.contains("search") => "search",
        _ if source.contains("mail") || source.contains("smtp") => "email_intel",
        _ if source.contains("dns") || source.contains("geo") || source.contains("ip") => "infra",
        _ => "other",
    }
}

#[must_use]
pub fn date_diff_days(left: &str, right: &str) -> i64 {
    match (parse_timestamp(left), parse_timestamp(right)) {
        (Some(left), Some(right)) => ((left - right).abs()) / 86_400,
        _ => i64::MAX,
    }
}

#[must_use]
pub fn tagged_matching_sources(entity: &Entity, tag: &str) -> BTreeSet<String> {
    if !entity.has_tag(tag) {
        return BTreeSet::new();
    }
    entity
        .evidence
        .iter()
        .map(|evidence| source_family(&evidence.provenance.source).to_owned())
        .filter(|family| family != "other")
        .collect()
}

fn breach_sources(entity: &Entity) -> BTreeSet<String> {
    entity
        .evidence
        .iter()
        .filter(|evidence| {
            is_breach_source(&evidence.provenance.source) || entity.has_tag(tags::BREACH)
        })
        .map(|evidence| evidence.provenance.source.clone())
        .collect()
}

fn is_breach_source(source: &str) -> bool {
    source_family(source) == "breach"
}

fn identity_entities(entities: &[Entity]) -> Vec<&Entity> {
    entities
        .iter()
        .filter(|entity| {
            matches!(
                entity.kind,
                EntityKind::Email | EntityKind::Username | EntityKind::Phone | EntityKind::Person
            )
        })
        .collect()
}

fn dates_for_breach(entity: &Entity) -> Vec<i64> {
    entity
        .evidence
        .iter()
        .flat_map(|evidence| evidence.attr_values("breach_date"))
        .filter_map(parse_timestamp)
        .collect()
}

pub fn rule_au_001_multi_breach(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let breached = identity_entities(context.entities())
        .into_iter()
        .filter(|entity| !breach_sources(entity).is_empty())
        .collect::<Vec<_>>();
    let families = breached
        .iter()
        .flat_map(|entity| {
            entity
                .evidence
                .iter()
                .map(|evidence| source_family(&evidence.provenance.source))
        })
        .collect::<BTreeSet<_>>();
    if breached.len() >= 2 && families.contains("breach") {
        return vec![Correlation::new(
            "AU-001",
            "multi_breach",
            Severity::High,
            format!(
                "{} breached identity entities across {} family/families",
                breached.len(),
                families.len()
            ),
            breached
                .into_iter()
                .map(|entity| entity.uid.clone())
                .collect(),
            scan_id,
            now,
        )];
    }
    Vec::new()
}

pub fn rule_au_002_identity_cluster(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let identities = identity_entities(context.entities())
        .into_iter()
        .filter(|entity| entity.confidence >= 0.5)
        .collect::<Vec<_>>();
    let emails = identities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Email)
        .count();
    let usernames = identities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Username)
        .count();
    let phones = identities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Phone)
        .count();
    let people = identities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person)
        .count();
    let active_kinds = [emails, usernames, phones, people]
        .into_iter()
        .filter(|count| *count > 0)
        .count();
    if active_kinds < 2 || emails > 6 || usernames > 8 || phones > 4 || identities.len() > 12 {
        return Vec::new();
    }
    if identities.len() < 2 {
        return Vec::new();
    }
    vec![Correlation::new(
        "AU-002",
        "identity_cluster",
        Severity::Critical,
        format!(
            "{emails} email(s), {usernames} username(s), {phones} phone(s), {people} person(s)"
        ),
        identities
            .into_iter()
            .map(|entity| entity.uid.clone())
            .collect(),
        scan_id,
        now,
    )]
}

pub fn rule_au_003_high_corroboration(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    context
        .entities()
        .iter()
        .filter(|entity| entity.corroborating_sources().len() >= 2 && entity.c_effective() >= 0.75)
        .map(|entity| {
            Correlation::new(
                "AU-003",
                "high_corroboration",
                Severity::Medium,
                format!(
                    "{} corroborating source(s) for {}",
                    entity.corroborating_sources().len(),
                    entity.kind.as_str()
                ),
                vec![entity.uid.clone()],
                scan_id,
                now,
            )
        })
        .collect()
}

pub fn rule_au_019_temporal_breach_cluster(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let mut dated = context
        .entities()
        .iter()
        .filter_map(|entity| {
            let mut dates = dates_for_breach(entity);
            dates.sort_unstable();
            dates.first().copied().map(|date| (date, entity))
        })
        .collect::<Vec<_>>();
    dated.sort_by_key(|(date, _)| *date);
    let mut best = Vec::<String>::new();
    for start in 0..dated.len() {
        let start_date = dated[start].0;
        let cluster = dated[start..]
            .iter()
            .take_while(|(date, _)| (*date - start_date) <= 30 * 86_400)
            .map(|(_, entity)| entity.uid.clone())
            .collect::<Vec<_>>();
        if cluster.len() > best.len() {
            best = cluster;
        }
    }
    if best.len() >= 3 {
        return vec![Correlation::new(
            "AU-019",
            "temporal_breach_cluster",
            Severity::High,
            format!(
                "{} breach entities fall within one 30-day anchored window",
                best.len()
            ),
            best,
            scan_id,
            now,
        )];
    }
    Vec::new()
}

pub fn rule_au_021_api_key_exposure(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    context
        .entities()
        .iter()
        .filter(|entity| entity.kind == EntityKind::ApiKey)
        .map(|entity| {
            let family_count = entity
                .evidence
                .iter()
                .map(|evidence| source_family(&evidence.provenance.source))
                .filter(|family| *family != "other")
                .collect::<BTreeSet<_>>()
                .len();
            Correlation::new(
                "AU-021",
                "api_key_exposure",
                Severity::Critical,
                format!("api key exposed via {family_count} source family/families"),
                vec![entity.uid.clone()],
                scan_id,
                now,
            )
        })
        .collect()
}

pub fn rule_au_060_transitive_identity_closure(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    resolve_identity_clusters(context.relations())
        .into_iter()
        .filter(|cluster| cluster.len() >= 3)
        .map(|cluster| {
            Correlation::new(
                "AU-060",
                "transitive_identity_closure",
                Severity::High,
                format!(
                    "{} entities joined by identity-binding relations",
                    cluster.len()
                ),
                cluster,
                scan_id,
                now,
            )
        })
        .collect()
}

pub fn rule_au_062_multipath_corroboration(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    let ids = context.by_uid().keys().copied().collect::<Vec<_>>();
    for left in 0..ids.len() {
        for right in left + 1..ids.len() {
            let pathways = disjoint_pathways(ids[left], ids[right], context.relations());
            if pathways >= 2 {
                out.push(Correlation::new(
                    "AU-062",
                    "multipath_corroboration",
                    Severity::High,
                    format!("{pathways} independent pathways corroborate the link"),
                    vec![ids[left].to_owned(), ids[right].to_owned()],
                    scan_id,
                    now,
                ));
            }
        }
    }
    out
}

pub fn rule_au_063_corroboration_gap(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    let ids = context.by_uid().keys().copied().collect::<Vec<_>>();
    for left in 0..ids.len() {
        for right in left + 1..ids.len() {
            if disjoint_pathways(ids[left], ids[right], context.relations()) == 1 {
                out.push(Correlation::new(
                    "AU-063",
                    "corroboration_gap",
                    Severity::Low,
                    "only one identity pathway currently connects the pair",
                    vec![ids[left].to_owned(), ids[right].to_owned()],
                    scan_id,
                    now,
                ));
            }
        }
    }
    out
}

pub fn rule_au_070_connection_broker(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    connection_brokers(context.relations())
        .into_iter()
        .filter(|(_, score)| *score >= 2)
        .map(|(uid, score)| {
            Correlation::new(
                "AU-070",
                "connection_broker",
                Severity::Medium,
                format!("brokered {score} strongest identity paths"),
                vec![uid],
                scan_id,
                now,
            )
        })
        .collect()
}

pub fn rule_au_071_robust_identity_cluster(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    resolve_identity_clusters(context.relations())
        .into_iter()
        .filter(|cluster| cluster.len() >= 4)
        .filter_map(|cluster| {
            let kinds = context
                .relations()
                .iter()
                .filter(|relation| {
                    cluster.contains(&relation.from_uid) && cluster.contains(&relation.to_uid)
                })
                .map(|relation| relation.kind)
                .collect::<BTreeSet<_>>();
            (kinds.len() >= 2).then(|| {
                Correlation::new(
                    "AU-071",
                    "robust_identity_cluster",
                    Severity::High,
                    format!(
                        "{} entities connected by {} distinct relation kinds",
                        cluster.len(),
                        kinds.len()
                    ),
                    cluster,
                    scan_id,
                    now,
                )
            })
        })
        .collect()
}

pub fn rule_au_109_shared_registrant(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let mut by_target = BTreeMap::<String, Vec<String>>::new();
    for relation in context.relations().iter().filter(|relation| {
        matches!(
            relation.kind,
            RelationKind::RegisteredBy | RelationKind::SameOperator
        )
    }) {
        by_target
            .entry(relation.to_uid.clone())
            .or_default()
            .push(relation.from_uid.clone());
    }
    by_target
        .into_iter()
        .filter_map(|(target, mut sources)| {
            sources.sort();
            sources.dedup();
            (sources.len() >= 2).then(|| {
                let mut entity_uids = sources;
                entity_uids.push(target);
                Correlation::new(
                    "AU-109",
                    "shared_registrant",
                    Severity::Medium,
                    "multiple assets share one registrant/operator",
                    entity_uids,
                    scan_id,
                    now,
                )
            })
        })
        .collect()
}

pub fn rule_au_110_shared_hosting_ip(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let mut by_ip = BTreeMap::<String, Vec<String>>::new();
    for relation in context
        .relations()
        .iter()
        .filter(|relation| relation.kind == RelationKind::ResolvesTo)
    {
        by_ip
            .entry(relation.to_uid.clone())
            .or_default()
            .push(relation.from_uid.clone());
    }
    by_ip
        .into_iter()
        .filter_map(|(ip, mut domains)| {
            domains.sort();
            domains.dedup();
            (domains.len() >= 2).then(|| {
                let mut entity_uids = domains;
                entity_uids.push(ip);
                Correlation::new(
                    "AU-110",
                    "shared_hosting_ip",
                    Severity::Medium,
                    "multiple domains resolve to one hosting IP",
                    entity_uids,
                    scan_id,
                    now,
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Evidence, EvidenceProvenance};

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
    fn helper_behaviour_matches_legacy_oracles() {
        assert!(text_mentions_ip("seen at 1.2.3.4: Brisbane", "1.2.3.4"));
        assert!(text_mentions_ip("via [2001:db8::1]:443", "2001:db8::1"));
        assert!(!text_mentions_ip("host 1.2.3.45 responded", "1.2.3.4"));
        assert!(!text_mentions_ip("aé1", "é"));
        assert_eq!(source_family("ip2location"), "infra");
        assert_eq!(source_family("hibp"), "breach");
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
}
