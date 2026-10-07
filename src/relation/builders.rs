use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Instant;

use crate::canonical::{
    canonical_coordinates, canonical_domain_host, canonical_handle, canonical_url,
};
use crate::entity::{Entity, EntityKind, normalise};
use crate::geohash::haversine_km;
use crate::tags;

use super::affiliation::{
    derive_asset_operator, derive_corporate_control, derive_employment, derive_membership,
    derive_officership, derive_org_identity,
};
use super::social_extract::derive_profile_links;
use super::types::{Relation, RelationKind, domain_key, is_identity_kind};

const COLLOCATION_RADIUS_KM: f64 = 1.0;
const SHARED_SELECTOR_MAX_GROUP: usize = 8;

fn endpoint_confidence(left: &Entity, right: &Entity) -> f64 {
    left.confidence.min(right.confidence)
}

fn entity_attr_values<'a>(entity: &'a Entity, keys: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    for evidence in &entity.evidence {
        for key in keys {
            out.extend(evidence.attr_values(key));
        }
    }
    out
}

fn normalised_attr_values(entity: &Entity, keys: &[&str], kind: &EntityKind) -> BTreeSet<String> {
    entity_attr_values(entity, keys)
        .into_iter()
        .map(|value| normalise(kind, value))
        .filter(|value| !value.is_empty())
        .collect()
}

fn canonical_pair<'a>(left: &'a Entity, right: &'a Entity) -> (&'a Entity, &'a Entity) {
    if left.uid <= right.uid {
        (left, right)
    } else {
        (right, left)
    }
}

fn push_edge(
    edges: &mut Vec<Relation>,
    from_uid: &str,
    to_uid: &str,
    kind: RelationKind,
    confidence: f64,
    scan_id: &str,
) {
    if from_uid == to_uid {
        return;
    }
    edges.push(Relation::new(from_uid, to_uid, kind, confidence, scan_id));
}

fn parse_coords(raw: &str) -> Option<(f64, f64)> {
    let canonical = canonical_coordinates(raw)?;
    let (lat, lon) = canonical.split_once(',')?;
    Some((lat.parse().ok()?, lon.parse().ok()?))
}

fn url_host(url: &str) -> Option<String> {
    let canonical = canonical_url(url)?;
    let (_, rest) = canonical.split_once("://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    canonical_domain_host(authority).map(|host| domain_key(&host))
}

fn extract_email_localpart(value: &str) -> Option<&str> {
    value.split_once('@').map(|(local, _)| local)
}

fn is_numeric_handle(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit())
}

#[must_use]
pub fn is_generic_handle(value: &str) -> bool {
    let canonical = canonical_handle(value)
        .or_else(|| extract_email_localpart(value).and_then(canonical_handle))
        .unwrap_or_else(|| value.trim().to_ascii_lowercase());
    matches!(
        canonical.as_str(),
        "admin"
            | "contact"
            | "hello"
            | "help"
            | "info"
            | "mail"
            | "noreply"
            | "office"
            | "postmaster"
            | "sales"
            | "security"
            | "support"
            | "team"
            | "webmaster"
    ) || canonical.is_empty()
        || is_numeric_handle(&canonical)
}

fn persona_key(entity: &Entity) -> Option<String> {
    match entity.kind {
        EntityKind::Email => extract_email_localpart(&entity.value).and_then(canonical_handle),
        EntityKind::Username => canonical_handle(&entity.value),
        _ => None,
    }
    .filter(|key| !is_generic_handle(key))
}

fn person_key(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn person_fingerprints(value: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let full = person_key(value);
    if !full.is_empty() {
        out.insert(full);
    }
    let parts = value
        .split_whitespace()
        .map(person_key)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if let (Some(first), Some(last)) = (parts.first(), parts.last()) {
        out.insert(format!(
            "{}{}",
            first.chars().next().unwrap_or_default(),
            last
        ));
        out.insert(format!("{first}{last}"));
    }
    out
}

fn coreference_key(entity: &Entity) -> Option<String> {
    match entity.kind {
        EntityKind::Person => {
            let key = person_key(&entity.value);
            (!key.is_empty()).then_some(key)
        }
        EntityKind::Email | EntityKind::Username => persona_key(entity),
        _ => None,
    }
}

fn collapse_duplicates_max_confidence(relations: Vec<Relation>) -> Vec<Relation> {
    let mut out: Vec<Relation> = Vec::new();
    let mut seen = BTreeMap::<(String, String, RelationKind), usize>::new();
    for relation in relations {
        let key = (
            relation.from_uid.clone(),
            relation.to_uid.clone(),
            relation.kind,
        );
        if let Some(index) = seen.get(&key).copied() {
            if relation.confidence > out[index].confidence {
                out[index].confidence = relation.confidence;
            }
        } else {
            seen.insert(key, out.len());
            out.push(relation);
        }
    }
    out
}

#[must_use]
pub fn derive_structural(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut edges = Vec::new();
    let mut domains = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Domain)
        .map(|entity| (entity.value.clone(), entity))
        .collect::<HashMap<_, _>>();
    for entity in entities {
        match entity.kind {
            EntityKind::Domain => {
                let labels = entity.value.split('.').collect::<Vec<_>>();
                for index in 1..=labels.len().saturating_sub(1) {
                    let parent = labels[index..].join(".");
                    if let Some(parent_entity) = domains.get(parent.as_str()) {
                        push_edge(
                            &mut edges,
                            &entity.uid,
                            &parent_entity.uid,
                            RelationKind::SubdomainOf,
                            endpoint_confidence(entity, parent_entity),
                            scan_id,
                        );
                        break;
                    }
                }
            }
            EntityKind::Email => {
                if let Some((_, domain)) = entity.value.split_once('@') {
                    if let Some(domain_entity) = domains.get(domain_key(domain).as_str()) {
                        push_edge(
                            &mut edges,
                            &entity.uid,
                            &domain_entity.uid,
                            RelationKind::BelongsToDomain,
                            endpoint_confidence(entity, domain_entity),
                            scan_id,
                        );
                    }
                }
            }
            EntityKind::Url => {
                if let Some(host) = url_host(&entity.value) {
                    if let Some(domain_entity) = domains.get(host.as_str()) {
                        push_edge(
                            &mut edges,
                            &entity.uid,
                            &domain_entity.uid,
                            RelationKind::HostedOn,
                            endpoint_confidence(entity, domain_entity),
                            scan_id,
                        );
                    }
                }
            }
            _ => {}
        }
    }
    domains.clear();
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_colocation(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let coords = entities
        .iter()
        .filter_map(|entity| {
            (entity.kind == EntityKind::Coordinates)
                .then(|| parse_coords(&entity.value).map(|point| (entity, point)))
                .flatten()
        })
        .collect::<Vec<_>>();
    let mut edges = Vec::new();
    for left in 0..coords.len() {
        for right in left + 1..coords.len() {
            let (left_entity, (left_lat, left_lon)) = coords[left];
            let (right_entity, (right_lat, right_lon)) = coords[right];
            if haversine_km(left_lat, left_lon, right_lat, right_lon) <= COLLOCATION_RADIUS_KM {
                let (from, to) = canonical_pair(left_entity, right_entity);
                push_edge(
                    &mut edges,
                    &from.uid,
                    &to.uid,
                    RelationKind::CoLocatedWith,
                    endpoint_confidence(from, to),
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

fn summary_ip_tokens(summary: &str) -> impl Iterator<Item = &str> {
    summary.split_whitespace().map(|token| {
        token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != ':')
    })
}

#[must_use]
pub fn derive_resolution(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let ip_map = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::IpAddress)
        .map(|entity| (entity.value.clone(), entity))
        .collect::<HashMap<_, _>>();
    let mut edges = Vec::new();
    for domain in entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Domain)
    {
        let mut ips = BTreeSet::new();
        for evidence in &domain.evidence {
            for key in ["ip", "ipv4", "ipv6", "a", "aaaa", "resolved_ip"] {
                ips.extend(evidence.attr_values(key).map(str::to_owned));
            }
            ips.extend(summary_ip_tokens(&evidence.summary).map(str::to_owned));
        }
        for ip in ips {
            if let Some(target) = ip_map.get(ip.as_str()) {
                push_edge(
                    &mut edges,
                    &domain.uid,
                    &target.uid,
                    RelationKind::ResolvesTo,
                    endpoint_confidence(domain, target),
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_registration(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let orgs = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Organisation)
        .map(|entity| (entity.value.clone(), entity))
        .collect::<HashMap<_, _>>();
    let emails = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Email)
        .map(|entity| (entity.value.clone(), entity))
        .collect::<HashMap<_, _>>();
    let people = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person)
        .map(|entity| (entity.value.clone(), entity))
        .collect::<HashMap<_, _>>();
    let mut edges = Vec::new();
    for domain in entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Domain)
    {
        let mut targets = BTreeSet::<String>::new();
        for evidence in &domain.evidence {
            for value in evidence
                .attr_values("registrant_org")
                .chain(evidence.attr_values("admin_org"))
            {
                let key = normalise(&EntityKind::Organisation, value);
                if let Some(target) = orgs.get(key.as_str()) {
                    if targets.insert(target.uid.clone()) {
                        push_edge(
                            &mut edges,
                            &domain.uid,
                            &target.uid,
                            RelationKind::RegisteredBy,
                            endpoint_confidence(domain, target),
                            scan_id,
                        );
                    }
                }
            }
            for value in evidence
                .attr_values("registrant_email")
                .chain(evidence.attr_values("admin_email"))
            {
                let key = normalise(&EntityKind::Email, value);
                if let Some(target) = emails.get(key.as_str()) {
                    if targets.insert(target.uid.clone()) {
                        push_edge(
                            &mut edges,
                            &domain.uid,
                            &target.uid,
                            RelationKind::RegisteredBy,
                            endpoint_confidence(domain, target),
                            scan_id,
                        );
                    }
                }
            }
            for value in evidence
                .attr_values("registrant_name")
                .chain(evidence.attr_values("admin_name"))
            {
                let key = normalise(&EntityKind::Person, value);
                if let Some(target) = people.get(key.as_str()) {
                    if targets.insert(target.uid.clone()) {
                        push_edge(
                            &mut edges,
                            &domain.uid,
                            &target.uid,
                            RelationKind::RegisteredBy,
                            endpoint_confidence(domain, target),
                            scan_id,
                        );
                    }
                }
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_name_lineage(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let people = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person)
        .map(|entity| (entity.value.clone(), entity))
        .collect::<HashMap<_, _>>();
    let mut edges = Vec::new();
    for entity in entities
        .iter()
        .filter(|entity| entity.has_tag(tags::NAME_DERIVED))
    {
        if !matches!(entity.kind, EntityKind::Email | EntityKind::Username) {
            continue;
        }
        let names = normalised_attr_values(entity, &["source_name", "owner"], &EntityKind::Person);
        for name in names {
            if let Some(person) = people.get(name.as_str()) {
                push_edge(
                    &mut edges,
                    &entity.uid,
                    &person.uid,
                    RelationKind::DerivedFrom,
                    endpoint_confidence(entity, person),
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_handles(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut groups = BTreeMap::<String, Vec<&Entity>>::new();
    for entity in entities {
        if let Some(key) = persona_key(entity) {
            groups.entry(key).or_default().push(entity);
        }
    }
    let mut edges = Vec::new();
    for group in groups.into_values() {
        for left in 0..group.len() {
            for right in left + 1..group.len() {
                let (from, to) = canonical_pair(group[left], group[right]);
                push_edge(
                    &mut edges,
                    &from.uid,
                    &to.uid,
                    RelationKind::AliasOf,
                    endpoint_confidence(from, to),
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

fn secret_fingerprints(entity: &Entity) -> BTreeSet<String> {
    entity
        .evidence
        .iter()
        .flat_map(|evidence| {
            [
                "password_hash",
                "credential_hash",
                "secret_fingerprint",
                "shared_secret",
            ]
            .into_iter()
            .flat_map(move |key| evidence.attr_values(key))
        })
        .map(str::trim)
        .filter(|value| value.len() >= 16)
        .map(str::to_ascii_lowercase)
        .collect()
}

#[must_use]
pub fn derive_reused_secret_link(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut groups = BTreeMap::<String, Vec<&Entity>>::new();
    for entity in entities
        .iter()
        .filter(|entity| is_identity_kind(&entity.kind))
    {
        for fingerprint in secret_fingerprints(entity) {
            groups.entry(fingerprint).or_default().push(entity);
        }
    }
    let mut edges = Vec::new();
    for group in groups.into_values() {
        for left in 0..group.len() {
            for right in left + 1..group.len() {
                let (from, to) = canonical_pair(group[left], group[right]);
                push_edge(
                    &mut edges,
                    &from.uid,
                    &to.uid,
                    RelationKind::SharesSecretWith,
                    endpoint_confidence(from, to) * 0.8,
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_identity_ownership(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let subjects = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person && entity.has_tag("subject"))
        .collect::<Vec<_>>();
    let mut edges = Vec::new();
    for person in entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person)
    {
        let person_name = normalise(&EntityKind::Person, &person.value);
        let person_fingerprints = person_fingerprints(&person.value);
        for identity in entities.iter().filter(|entity| {
            matches!(entity.kind, EntityKind::Email | EntityKind::Username)
                && entity.uid != person.uid
        }) {
            let named = normalised_attr_values(
                identity,
                &["owner", "source_name", "person"],
                &EntityKind::Person,
            )
            .contains(&person_name);
            if named {
                push_edge(
                    &mut edges,
                    &person.uid,
                    &identity.uid,
                    RelationKind::IdentifiedBy,
                    endpoint_confidence(person, identity),
                    scan_id,
                );
                continue;
            }
            if subjects.iter().any(|subject| subject.uid == person.uid) {
                let Some(key) = persona_key(identity) else {
                    continue;
                };
                if person_fingerprints.contains(&key) {
                    push_edge(
                        &mut edges,
                        &person.uid,
                        &identity.uid,
                        RelationKind::IdentifiedBy,
                        endpoint_confidence(person, identity) * 0.7,
                        scan_id,
                    );
                }
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_residency(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let people = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person)
        .map(|entity| (entity.value.clone(), entity))
        .collect::<HashMap<_, _>>();
    let mut edges = Vec::new();
    for place in entities
        .iter()
        .filter(|entity| matches!(entity.kind, EntityKind::Address | EntityKind::Coordinates))
    {
        for owner in normalised_attr_values(
            place,
            &["owner", "resident", "occupant"],
            &EntityKind::Person,
        ) {
            if let Some(person) = people.get(owner.as_str()) {
                push_edge(
                    &mut edges,
                    &person.uid,
                    &place.uid,
                    RelationKind::LocatedAt,
                    endpoint_confidence(person, place),
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_kinship(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let people = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person)
        .collect::<Vec<_>>();
    let mut groups = BTreeMap::<String, Vec<&Entity>>::new();
    for person in &people {
        let parts = person.value.split_whitespace().collect::<Vec<_>>();
        if let Some(surname) = parts.last() {
            let surname = surname.to_ascii_lowercase();
            if surname.len() >= 4
                && !matches!(surname.as_str(), "smith" | "johnson" | "williams" | "jones")
            {
                groups.entry(surname).or_default().push(person);
            }
        }
    }
    let mut edges = Vec::new();
    for group in groups.into_values() {
        for left in 0..group.len() {
            for right in left + 1..group.len() {
                let (from, to) = canonical_pair(group[left], group[right]);
                push_edge(
                    &mut edges,
                    &from.uid,
                    &to.uid,
                    RelationKind::AssociatedWith,
                    endpoint_confidence(from, to) * 0.7,
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_regional_kinship(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let towns = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Address)
        .collect::<Vec<_>>();
    if towns.is_empty() {
        return Vec::new();
    }
    derive_kinship(entities, scan_id)
}

#[must_use]
pub fn derive_declared_associations(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let by_name = entities
        .iter()
        .map(|entity| {
            let kind = match entity.kind {
                EntityKind::Person => EntityKind::Person,
                EntityKind::Organisation => EntityKind::Organisation,
                _ => EntityKind::Other,
            };
            (normalise(&kind, &entity.value), entity)
        })
        .collect::<HashMap<_, _>>();
    let mut edges = Vec::new();
    for entity in entities {
        for value in entity_attr_values(entity, &["associated_with", "related_to", "co_owner"]) {
            let kind = if entity.kind == EntityKind::Organisation {
                EntityKind::Organisation
            } else {
                EntityKind::Person
            };
            let key = normalise(&kind, value);
            if let Some(target) = by_name.get(key.as_str()) {
                let (from, to) = canonical_pair(entity, target);
                push_edge(
                    &mut edges,
                    &from.uid,
                    &to.uid,
                    RelationKind::AssociatedWith,
                    endpoint_confidence(from, to),
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_co_residence(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let people = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person)
        .collect::<Vec<_>>();
    let mut homes = BTreeMap::<String, Vec<&Entity>>::new();
    for person in people {
        for value in entity_attr_values(person, &["address", "home_address", "residence"]) {
            homes
                .entry(normalise(&EntityKind::Address, value))
                .or_default()
                .push(person);
        }
    }
    let mut edges = Vec::new();
    for residents in homes.into_values() {
        if residents.len() > 6 {
            continue;
        }
        for left in 0..residents.len() {
            for right in left + 1..residents.len() {
                let (from, to) = canonical_pair(residents[left], residents[right]);
                push_edge(
                    &mut edges,
                    &from.uid,
                    &to.uid,
                    RelationKind::AssociatedWith,
                    endpoint_confidence(from, to) * 0.8,
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_co_mention(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut docs = BTreeMap::<String, Vec<&Entity>>::new();
    for person in entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person)
    {
        for url in entity_attr_values(person, &["source_url", "url", "document"]) {
            docs.entry(url.to_ascii_lowercase())
                .or_default()
                .push(person);
        }
    }
    let mut edges = Vec::new();
    for mentioned in docs.into_values() {
        if !(2..=6).contains(&mentioned.len()) {
            continue;
        }
        let mut unique = mentioned;
        unique.sort_by(|left, right| left.uid.cmp(&right.uid));
        unique.dedup_by(|left, right| left.uid == right.uid);
        for left in 0..unique.len() {
            for right in left + 1..unique.len() {
                push_edge(
                    &mut edges,
                    &unique[left].uid,
                    &unique[right].uid,
                    RelationKind::AssociatedWith,
                    endpoint_confidence(unique[left], unique[right]) * 0.6,
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

fn selector_values(entity: &Entity) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for key in [
        "registrant_org",
        "registrant_email",
        "tracking_id",
        "tracking_pixel",
        "fingerprint",
        "ad_id",
    ] {
        let values = entity_attr_values(entity, &[key])
            .into_iter()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<BTreeSet<_>>();
        if !values.is_empty() {
            out.insert(key.to_owned(), values);
        }
    }
    out
}

fn is_privacy_proxy(value: &str) -> bool {
    ["whoisguard", "privacy", "proxy", "domains by proxy"]
        .iter()
        .any(|needle| value.contains(needle))
}

#[must_use]
pub fn derive_shared_selector(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut buckets = BTreeMap::<(String, String), Vec<&Entity>>::new();
    for entity in entities {
        for (key, values) in selector_values(entity) {
            for value in values {
                if value.len() < 3 || is_privacy_proxy(&value) {
                    continue;
                }
                buckets
                    .entry((key.clone(), value))
                    .or_default()
                    .push(entity);
            }
        }
    }
    let mut edges = Vec::new();
    for ((key, _), group) in buckets {
        if !(2..=SHARED_SELECTOR_MAX_GROUP).contains(&group.len()) {
            continue;
        }
        let kind = if key == "registrant_org" || key == "registrant_email" {
            RelationKind::SameOperator
        } else {
            RelationKind::AssociatedWith
        };
        for left in 0..group.len() {
            for right in left + 1..group.len() {
                let (from, to) = canonical_pair(group[left], group[right]);
                push_edge(
                    &mut edges,
                    &from.uid,
                    &to.uid,
                    kind,
                    endpoint_confidence(from, to),
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_canonical_identities(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut buckets = BTreeMap::<(EntityKind, String), Vec<&Entity>>::new();
    for entity in entities {
        match entity.kind {
            EntityKind::Email | EntityKind::Domain | EntityKind::Username => {
                buckets
                    .entry((entity.kind.clone(), entity.value.clone()))
                    .or_default()
                    .push(entity);
            }
            _ => {}
        }
    }
    let mut edges = Vec::new();
    for ((_kind, _value), group) in buckets {
        for left in 0..group.len() {
            for right in left + 1..group.len() {
                let (from, to) = canonical_pair(group[left], group[right]);
                push_edge(
                    &mut edges,
                    &from.uid,
                    &to.uid,
                    RelationKind::SameAs,
                    endpoint_confidence(from, to),
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

#[must_use]
pub fn derive_coreferences(
    entities: &[Entity],
    existing: &[Relation],
    scan_id: &str,
) -> Vec<Relation> {
    let existing_keys = existing
        .iter()
        .map(|relation| {
            (
                relation.from_uid.clone(),
                relation.to_uid.clone(),
                relation.kind,
            )
        })
        .collect::<HashSet<_>>();
    let mut buckets = BTreeMap::<String, Vec<&Entity>>::new();
    for entity in entities {
        if let Some(key) = coreference_key(entity) {
            buckets.entry(key).or_default().push(entity);
        }
    }
    let mut edges = Vec::new();
    for group in buckets.into_values() {
        for left in 0..group.len() {
            for right in left + 1..group.len() {
                let kind = match (&group[left].kind, &group[right].kind) {
                    (EntityKind::Person, EntityKind::Person) => continue,
                    (EntityKind::Person, _) | (_, EntityKind::Person) => RelationKind::IdentifiedBy,
                    _ => RelationKind::AliasOf,
                };
                let (from_uid, to_uid) = if kind == RelationKind::IdentifiedBy {
                    if group[left].kind == EntityKind::Person {
                        (group[left].uid.clone(), group[right].uid.clone())
                    } else {
                        (group[right].uid.clone(), group[left].uid.clone())
                    }
                } else {
                    let (from, to) = canonical_pair(group[left], group[right]);
                    (from.uid.clone(), to.uid.clone())
                };
                let key = (from_uid.clone(), to_uid.clone(), kind);
                if existing_keys.contains(&key) {
                    continue;
                }
                push_edge(
                    &mut edges,
                    &from_uid,
                    &to_uid,
                    kind,
                    endpoint_confidence(group[left], group[right]) * 0.85,
                    scan_id,
                );
            }
        }
    }
    collapse_duplicates_max_confidence(edges)
}

fn derive_co_ownership(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    derive_shared_selector(entities, scan_id)
        .into_iter()
        .filter(|relation| relation.kind == RelationKind::SameOperator)
        .collect()
}

#[must_use]
pub fn derive_all(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    derive_all_within_budget(entities, scan_id, None)
}

#[must_use]
pub fn derive_all_within_budget(
    entities: &[Entity],
    scan_id: &str,
    deadline: Option<Instant>,
) -> Vec<Relation> {
    type RelationPass = fn(&[Entity], &str) -> Vec<Relation>;
    let passes: &[RelationPass] = &[
        derive_structural,
        derive_colocation,
        derive_resolution,
        derive_registration,
        derive_name_lineage,
        derive_co_ownership,
        derive_handles,
        derive_reused_secret_link,
        derive_identity_ownership,
        derive_residency,
        derive_kinship,
        derive_regional_kinship,
        derive_declared_associations,
        derive_co_residence,
        derive_co_mention,
        derive_shared_selector,
        derive_canonical_identities,
        derive_profile_links,
        derive_officership,
        derive_employment,
        derive_membership,
        derive_corporate_control,
        derive_asset_operator,
        derive_org_identity,
    ];
    let mut out = Vec::new();
    let mut existing = Vec::new();
    for pass in passes {
        if deadline.is_some_and(|limit| Instant::now() >= limit) {
            break;
        }
        let mut relations = pass(entities, scan_id);
        if std::ptr::fn_addr_eq(
            *pass,
            derive_canonical_identities as fn(&[Entity], &str) -> Vec<Relation>,
        ) {
            relations.extend(derive_coreferences(entities, &existing, scan_id));
        }
        existing.extend(relations.clone());
        out.extend(relations);
    }
    collapse_duplicates_max_confidence(out)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::entity::{Evidence, EvidenceProvenance};

    fn evidence(source: &str, summary: &str) -> Evidence {
        Evidence::new(EvidenceProvenance::new(source), summary)
    }

    fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
        Entity::new(kind, value, conf, "rel-scan")
    }

    #[test]
    fn name_lineage_links_derived_handles_to_the_subject_person() {
        let person = ent(EntityKind::Person, "Jane Smith", 0.6);
        let mut uname = ent(EntityKind::Username, "jsmith", 0.38);
        uname.tag(tags::NAME_DERIVED);
        uname
            .add_evidence(evidence("name_intel", "derived").with_attr("source_name", "Jane Smith"));
        let mut email = ent(EntityKind::Email, "jane.smith@gmail.com", 0.30);
        email.tag(tags::NAME_DERIVED);
        email.add_evidence(
            evidence("name_intel", "permuted").with_attr("source_name", "jane smith"),
        );
        let rels = derive_name_lineage(&[person.clone(), uname.clone(), email.clone()], "s");
        assert_eq!(rels.len(), 2);
        assert!(
            rels.iter()
                .all(|relation| relation.kind == RelationKind::DerivedFrom)
        );
        assert!(rels.iter().all(|relation| relation.to_uid == person.uid));
    }

    #[test]
    fn subdomain_email_and_url_edges_are_derived() {
        let domain = ent(EntityKind::Domain, "example.com", 0.9);
        let sub = ent(EntityKind::Domain, "a.b.example.com", 0.8);
        let email = ent(EntityKind::Email, "user@example.com", 0.7);
        let url = ent(EntityKind::Url, "https://www.example.com/login", 0.6);
        let rels = derive_structural(
            &[domain.clone(), sub.clone(), email.clone(), url.clone()],
            "s",
        );
        assert!(
            rels.iter()
                .any(|relation| relation.kind == RelationKind::SubdomainOf
                    && relation.from_uid == sub.uid
                    && relation.to_uid == domain.uid)
        );
        assert!(
            rels.iter()
                .any(|relation| relation.kind == RelationKind::BelongsToDomain
                    && relation.from_uid == email.uid
                    && relation.to_uid == domain.uid)
        );
        assert!(
            rels.iter()
                .any(|relation| relation.kind == RelationKind::HostedOn
                    && relation.from_uid == url.uid
                    && relation.to_uid == domain.uid)
        );
    }

    #[test]
    fn resolution_and_registration_link_present_entities_only() {
        let mut domain = ent(EntityKind::Domain, "example.com", 0.92);
        domain.add_evidence(
            evidence("dns_intel", "A 1.2.3.4")
                .with_attr("a", "1.2.3.4")
                .with_attr("registrant_org", "Example Org LLC")
                .with_attr("registrant_email", "admin@example.com"),
        );
        let ip = ent(EntityKind::IpAddress, "1.2.3.4", 0.8);
        let org = ent(EntityKind::Organisation, "Example Org LLC", 0.72);
        let email = ent(EntityKind::Email, "admin@example.com", 0.78);
        let rels = derive_all(
            &[domain.clone(), ip.clone(), org.clone(), email.clone()],
            "s",
        );
        assert!(
            rels.iter()
                .any(|relation| relation.kind == RelationKind::ResolvesTo
                    && relation.to_uid == ip.uid)
        );
        assert!(
            rels.iter()
                .any(|relation| relation.kind == RelationKind::RegisteredBy
                    && relation.to_uid == org.uid)
        );
        assert!(
            rels.iter()
                .any(|relation| relation.kind == RelationKind::RegisteredBy
                    && relation.to_uid == email.uid)
        );
    }

    #[test]
    fn handles_alias_and_identity_ownership_respect_subject_gate() {
        let mut subject = ent(EntityKind::Person, "Kyle Diegmann", 0.9);
        subject.tag("subject");
        let mut owned = ent(EntityKind::Email, "k.d@acme.com", 0.6);
        owned.add_evidence(evidence("breach", "dump").with_attr("owner", "Kyle Diegmann"));
        let fp = ent(EntityKind::Username, "kdiegmann", 0.5);
        let rels = derive_identity_ownership(&[subject.clone(), owned.clone(), fp.clone()], "s");
        assert_eq!(rels.len(), 2);
        assert!(
            rels.iter()
                .all(|relation| relation.kind == RelationKind::IdentifiedBy)
        );
        assert!(rels.iter().all(|relation| relation.from_uid == subject.uid));
        let alias = derive_handles(
            &[
                ent(EntityKind::Email, "jsmith@gmail.com", 0.7),
                ent(EntityKind::Email, "jsmith@outlook.com", 0.6),
                ent(EntityKind::Username, "jsmith", 0.5),
            ],
            "s",
        );
        assert_eq!(alias.len(), 3);
    }

    #[test]
    fn coreference_promotion_is_additive_only() {
        let user = ent(EntityKind::Username, "johnsmith", 0.8);
        let email = ent(EntityKind::Email, "johnsmith@gmail.com", 0.8);
        let person = ent(EntityKind::Person, "John Smith", 0.8);
        let fresh = derive_coreferences(&[user.clone(), email.clone(), person.clone()], &[], "s");
        assert!(
            fresh
                .iter()
                .any(|relation| relation.kind == RelationKind::AliasOf)
        );
        assert!(
            fresh
                .iter()
                .any(|relation| relation.kind == RelationKind::IdentifiedBy)
        );
        let alias = fresh
            .iter()
            .find(|relation| relation.kind == RelationKind::AliasOf)
            .unwrap();
        let prior = vec![Relation::new(
            &alias.from_uid,
            &alias.to_uid,
            RelationKind::AliasOf,
            0.95,
            "s",
        )];
        let after = derive_coreferences(&[user, email], &prior, "s");
        assert!(after.is_empty(), "{after:?}");
    }

    #[test]
    fn derive_all_within_budget_stops_starting_new_passes_past_deadline() {
        let domain = ent(EntityKind::Domain, "example.com", 0.9);
        let deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("subtracting one millisecond from now is always valid");
        let rels = derive_all_within_budget(&[domain], "s", Some(deadline));
        assert!(rels.is_empty(), "{rels:?}");
    }

    #[test]
    fn duplicate_edges_keep_max_confidence() {
        let relations = vec![
            Relation::new("a", "b", RelationKind::AliasOf, 0.2, "s"),
            Relation::new("a", "b", RelationKind::AliasOf, 0.9, "s"),
        ];
        let collapsed = collapse_duplicates_max_confidence(relations);
        assert_eq!(collapsed.len(), 1);
        assert!((collapsed[0].confidence - 0.9).abs() < f64::EPSILON);
    }
}
