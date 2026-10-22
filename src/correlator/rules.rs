use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::entity::{Entity, EntityKind};
use crate::relation::{PairPathways, RelationKind, basis_kind, connection_brokers};
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
    // `seeknow` is the live SeekNow collector id. `see_know` is the id the legacy 7dca720 build
    // wrote, and its consensus fixture still uses it.
    match source.as_str() {
        "comb_search" | "dehashed" | "hibp" | "hibp_account" | "hudsonrock" | "intelx"
        | "leakcheck_public" | "leakix" | "niamonx" | "osintcat" | "psbdmp" | "pwned_passwords"
        | "xposed_or_not" | "oathnet" | "oathnet_pro" | "seeknow" | "see_know" | "stolen_tax" => {
            "breach"
        }
        "github_user" | "npm_author" | "crates_io" => "code",
        "wigle" | "wigle_bluetooth" | "oui" => "rf",
        "reddit_user" | "hacker_news" => "forum",
        "social_probe" | "gravatar" | "duolingo" => "social",
        "username_search" | "epieos" => "presence",
        "search_engines" | "google" | "exa_search" => "search",
        "smtp_vrfy" | "emailrep" | "openpgp_keys" | "hunter" | "kickbox" => "email_intel",
        "proxycurl" | "name_intel" | "fullcontact" | "contact_enrich" | "gleif_lei"
        | "asic_director" | "au_electoral" | "au_people" | "ahpra" | "acnc_charities" => {
            "identity_registry"
        }
        "shodan" | "dns_intel" | "ip_geo" | "geocode" | "ip_whois_geo" | "ip2location"
        | "mylnikov" | "abuseipdb" | "bgpview" | "criminal_ip" | "ipqs" | "netblock" | "netlas"
        | "onyphe" | "portscan" | "ripestat" | "securitytrails" | "zoomeye" | "domainsdb"
        | "internetdb" | "greynoise" | "virustotal" | "pulsedive" | "threatfox" | "urlhaus"
        | "whoxy" | "otx" | "urlscan" | "ipinfo" | "robtex" | "hackertarget" | "stopforumspam"
        | "isc" | "maltiverse" | "phishstats" => "infra",
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

/// A username the analysis inferred, such as one derived from an email's local part. It adds no
/// identity beyond the address it came from, so the identity-cluster rule does not count it.
fn is_inferred_username(entity: &Entity) -> bool {
    entity.kind == EntityKind::Username
        && entity.evidence.iter().any(|evidence| evidence.is_inferred)
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
        .filter(|entity| !is_inferred_username(entity))
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
    context
        .identity_clusters()
        .iter()
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
                cluster.clone(),
                scan_id,
                now,
            )
        })
        .collect()
}

/// The uids of the entities a rule pass reads, in the context's ascending uid order, so that the
/// pairwise rules pair them the same way round, and in the same order, on every run. The
/// positions in [`RuleContext::pathways`] index this list.
fn ordered_uids<'a>(context: &RuleContext<'a>) -> Vec<&'a str> {
    context.by_uid().keys().copied().collect()
}

pub fn rule_au_062_multipath_corroboration(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let ids = ordered_uids(context);
    context
        .pathways()
        .iter()
        .filter(|pair| pair.count >= 2)
        .map(|pair| {
            Correlation::new(
                "AU-062",
                "multipath_corroboration",
                Severity::High,
                format!("{} independent pathways corroborate the link", pair.count),
                vec![ids[pair.left].to_owned(), ids[pair.right].to_owned()],
                scan_id,
                now,
            )
        })
        .collect()
}

/// A gap for each pair whose count finds one identity pathway and no second. The count takes the
/// strongest pathway first, so a second pathway it misses is not ruled out. When that pathway rests
/// entirely on one shared basis, such as a handle that many addresses share, the pairs whose one
/// pathway rests on it are one gap, reported once for every entity in them: one handle on 96 sites
/// leaves 4,560 such pairs, and closing the gap means corroborating the handle, not each pair.
pub fn rule_au_063_corroboration_gap(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let ids = ordered_uids(context);
    let gap = |description: String, uids: Vec<String>| {
        Correlation::new(
            "AU-063",
            "corroboration_gap",
            Severity::Low,
            description,
            uids,
            scan_id,
            now,
        )
    };
    let pair_gap = |pair: &PairPathways<'_>| {
        gap(
            "one identity pathway found connects the pair; a second may exist that the search did not take"
                .to_owned(),
            vec![ids[pair.left].to_owned(), ids[pair.right].to_owned()],
        )
    };
    let mut out = Vec::new();
    let mut shared = BTreeMap::<&str, Vec<PairPathways<'_>>>::new();
    for pair in context.pathways().iter().filter(|pair| pair.count == 1) {
        match pair.basis {
            Some(basis) => shared.entry(basis).or_default().push(*pair),
            None => out.push(pair_gap(pair)),
        }
    }
    for (basis, pairs) in shared {
        if let [pair] = pairs.as_slice() {
            out.push(pair_gap(pair));
            continue;
        }
        let members = pairs
            .iter()
            .flat_map(|pair| [pair.left, pair.right])
            .collect::<BTreeSet<_>>();
        out.push(gap(
            format!(
                "{} pairs among these {} entities each have one identity pathway found, which rests on a shared {}",
                pairs.len(),
                members.len(),
                basis_kind(basis)
            ),
            members
                .into_iter()
                .map(|position| ids[position].to_owned())
                .collect(),
        ));
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

/// An identity cluster of four or more entities held together by more than one kind of identity
/// relation and more than one piece of evidence. Only relations that bind identity count: an
/// association between two members says nothing about whether they are one identity. Relations
/// that rest on one thing (see [`crate::relation::Relation::rests_on`]), such as the aliases
/// and the name match that one shared handle implies, are one piece of evidence whatever their
/// kinds, so a cluster that only a shared handle holds together is not robust; its
/// corroboration gap (AU-063) says so.
pub fn rule_au_071_robust_identity_cluster(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let clusters = context.identity_clusters();
    let mut cluster_of = HashMap::<&str, usize>::new();
    for (number, cluster) in clusters.iter().enumerate() {
        if cluster.len() >= 4 {
            cluster_of.extend(cluster.iter().map(|uid| (uid.as_str(), number)));
        }
    }
    let mut kinds = vec![BTreeSet::new(); clusters.len()];
    let mut bases = vec![HashSet::new(); clusters.len()];
    // A relation that binds identity joins two members of one cluster, so its first end places it.
    for relation in context.relations() {
        if let Some(&number) = cluster_of
            .get(relation.from_uid.as_str())
            .filter(|_| relation.kind.binds_identity())
        {
            kinds[number].insert(relation.kind);
            bases[number].insert(relation.rests_on());
        }
    }
    clusters
        .iter()
        .zip(kinds.iter().zip(&bases))
        .filter(|(_, (kinds, bases))| kinds.len() >= 2 && bases.len() >= 2)
        .map(|(cluster, (kinds, bases))| {
            Correlation::new(
                "AU-071",
                "robust_identity_cluster",
                Severity::High,
                format!(
                    "{} entities connected by {} kinds of identity relation resting on {} \
                     independent pieces of evidence",
                    cluster.len(),
                    kinds.len(),
                    bases.len()
                ),
                cluster.clone(),
                scan_id,
                now,
            )
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

/// BSSID position within this distance of an IP geolocation is a finding.
const GEO_DELTA_DEGREES: f64 = 0.002;

/// Parse "lat,lon" into coordinates. **Pure.**
fn parse_position(text: &str) -> Option<(f64, f64)> {
    let (lat, lon) = text.split_once(',')?;
    let lat: f64 = lat.trim().parse().ok()?;
    let lon: f64 = lon.trim().parse().ok()?;
    (lat.is_finite() && lon.is_finite()).then_some((lat, lon))
}

/// Distance in degrees between two positions. **Pure.**
fn delta_degrees(a: (f64, f64), b: (f64, f64)) -> f64 {
    let dlat = a.0 - b.0;
    let dlon = a.1 - b.1;
    (dlat * dlat + dlon * dlon).sqrt()
}

/// BSSID position within `GEO_DELTA_DEGREES` of an IP geolocation.
#[must_use]
pub fn rule_geo_bssid_ip(ctx: &RuleContext<'_>) -> Vec<Correlation> {
    let mut out = Vec::new();
    let bssids: Vec<_> = ctx
        .entities()
        .iter()
        .filter(|e| e.kind == EntityKind::MacAddress)
        .filter_map(|e| {
            e.evidence.iter().find_map(|ev| {
                ev.attr_values("position")
                    .next()
                    .and_then(parse_position)
                    .map(|pos| (e, pos))
            })
        })
        .collect();
    let ips: Vec<_> = ctx
        .entities()
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .filter_map(|e| {
            e.evidence.iter().find_map(|ev| {
                ev.attr_values("loc")
                    .next()
                    .and_then(parse_position)
                    .map(|pos| (e, pos))
            })
        })
        .collect();
    for (bssid, bpos) in &bssids {
        for (ip, ipos) in &ips {
            let d = delta_degrees(*bpos, *ipos);
            if d <= GEO_DELTA_DEGREES {
                out.push(Correlation::new(
                    "geo_bssid_ip",
                    "BSSID near IP geolocation",
                    Severity::Medium,
                    format!("BSSID {} within {:.4}° of IP {}", bssid.value, d, ip.value),
                    vec![bssid.uid.clone(), ip.uid.clone()],
                    bssid.scan_id.as_str(),
                    0,
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Evidence, EvidenceProvenance};

    #[test]
    fn hibp_breaches_from_exposure_are_breach_evidence() {
        // `exposure` records each HIBP breach that lists an address as that address, tagged
        // `breach`, with evidence under `exposure_cli::SOURCE`.
        let breached = |address: &str| {
            let mut entity = Entity::new(EntityKind::Email, address, 0.9, "scan");
            entity.tag(tags::BREACH);
            entity.add_evidence(Evidence::new(
                EvidenceProvenance::new(crate::exposure_cli::SOURCE),
                "Address listed in HIBP breach Adobe",
            ));
            entity
        };
        let entities = [breached("ada@example.com"), breached("ada.l@example.com")];
        let found = rule_au_001_multi_breach(&RuleContext::new(&entities, &[]), "scan", 0);
        assert_eq!(
            found.iter().map(|c| c.rule_id.as_str()).collect::<Vec<_>>(),
            ["AU-001"]
        );
        assert_eq!(
            tagged_matching_sources(&entities[0], tags::BREACH),
            BTreeSet::from(["breach".to_owned()])
        );
    }
}
