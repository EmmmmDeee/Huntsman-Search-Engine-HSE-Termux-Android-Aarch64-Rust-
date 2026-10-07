use std::collections::{BTreeSet, HashMap};

use crate::canonical::{canonical_coordinates, canonical_domain_host, canonical_url};
use crate::entity::{Entity, EntityKind, normalise};
use crate::geohash::haversine_km;

use super::{
    Relation, RelationKind, canonical_pair, collapse_duplicates_max_confidence, domain_key,
    endpoint_confidence, push_edge,
};

const COLLOCATION_RADIUS_KM: f64 = 1.0;

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
