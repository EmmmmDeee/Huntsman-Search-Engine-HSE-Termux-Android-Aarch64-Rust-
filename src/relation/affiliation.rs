use std::collections::HashMap;

use crate::entity::{Entity, EntityKind, normalise};

use super::types::{Relation, RelationKind};

fn endpoint_confidence(left: &Entity, right: &Entity) -> f64 {
    left.confidence.min(right.confidence)
}

fn push_named_links(
    out: &mut Vec<Relation>,
    entities: &[Entity],
    source_kind: &EntityKind,
    target_kind: &EntityKind,
    attrs: &[&str],
    relation_kind: RelationKind,
    scan_id: &str,
) {
    let targets = entities
        .iter()
        .filter(|entity| &entity.kind == target_kind)
        .map(|entity| (entity.value.clone(), entity))
        .collect::<HashMap<_, _>>();
    for source in entities.iter().filter(|entity| &entity.kind == source_kind) {
        for evidence in &source.evidence {
            for attr in attrs {
                for value in evidence.attr_values(attr) {
                    let key = normalise(target_kind, value);
                    if let Some(target) = targets.get(key.as_str()) {
                        out.push(Relation::new(
                            &source.uid,
                            &target.uid,
                            relation_kind,
                            endpoint_confidence(source, target),
                            scan_id,
                        ));
                    }
                }
            }
        }
    }
}

#[must_use]
pub fn derive_officership(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut out = Vec::new();
    push_named_links(
        &mut out,
        entities,
        &EntityKind::Person,
        &EntityKind::Organisation,
        &["officer_of", "director_of"],
        RelationKind::OfficerOf,
        scan_id,
    );
    out
}

#[must_use]
pub fn derive_employment(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut out = Vec::new();
    push_named_links(
        &mut out,
        entities,
        &EntityKind::Person,
        &EntityKind::Organisation,
        &["employer", "works_for"],
        RelationKind::EmployedBy,
        scan_id,
    );
    out
}

#[must_use]
pub fn derive_membership(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut out = Vec::new();
    push_named_links(
        &mut out,
        entities,
        &EntityKind::Person,
        &EntityKind::Organisation,
        &["member_of", "affiliated_with"],
        RelationKind::MemberOf,
        scan_id,
    );
    out
}

#[must_use]
pub fn derive_corporate_control(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut out = Vec::new();
    push_named_links(
        &mut out,
        entities,
        &EntityKind::Organisation,
        &EntityKind::Organisation,
        &["controls", "controlled_by", "parent_org"],
        RelationKind::ControlledBy,
        scan_id,
    );
    out
}

#[must_use]
pub fn derive_asset_operator(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut out = Vec::new();
    let operators = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Organisation)
        .map(|entity| (entity.value.clone(), entity))
        .collect::<HashMap<_, _>>();
    for asset in entities.iter().filter(|entity| {
        matches!(
            entity.kind,
            EntityKind::Domain | EntityKind::Url | EntityKind::IpAddress | EntityKind::DeviceId
        )
    }) {
        for evidence in &asset.evidence {
            for value in evidence
                .attr_values("operator")
                .chain(evidence.attr_values("owner_org"))
            {
                let key = normalise(&EntityKind::Organisation, value);
                if let Some(operator) = operators.get(key.as_str()) {
                    out.push(Relation::new(
                        &asset.uid,
                        &operator.uid,
                        RelationKind::OperatedBy,
                        endpoint_confidence(asset, operator),
                        scan_id,
                    ));
                }
            }
        }
    }
    out
}

#[must_use]
pub fn derive_org_identity(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut out = Vec::new();
    let orgs = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Organisation)
        .map(|entity| (entity.value.clone(), entity))
        .collect::<HashMap<_, _>>();
    for entity in entities
        .iter()
        .filter(|entity| matches!(entity.kind, EntityKind::Email | EntityKind::Domain))
    {
        for evidence in &entity.evidence {
            for value in evidence
                .attr_values("organisation")
                .chain(evidence.attr_values("org"))
            {
                let key = normalise(&EntityKind::Organisation, value);
                if let Some(org) = orgs.get(key.as_str()) {
                    out.push(Relation::new(
                        &entity.uid,
                        &org.uid,
                        RelationKind::SameOperator,
                        endpoint_confidence(entity, org) * 0.8,
                        scan_id,
                    ));
                }
            }
        }
    }
    out
}
