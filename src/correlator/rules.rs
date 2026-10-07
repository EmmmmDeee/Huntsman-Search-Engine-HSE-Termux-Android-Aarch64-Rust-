use std::collections::{BTreeMap, BTreeSet};

use crate::entity::{Entity, EntityKind};
use crate::relation::{
    RelationKind, connection_brokers, disjoint_pathways, resolve_identity_clusters,
};
use crate::tags;
use crate::timefmt::parse_timestamp;

use super::{Correlation, RuleContext, Severity};

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
