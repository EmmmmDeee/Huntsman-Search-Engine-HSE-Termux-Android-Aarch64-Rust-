use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::entity::{Entity, EntityKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiamondVertex {
    Adversary,
    Capability,
    Infrastructure,
    Victim,
}

impl DiamondVertex {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Adversary => "adversary",
            Self::Capability => "capability",
            Self::Infrastructure => "infrastructure",
            Self::Victim => "victim",
        }
    }
}

impl std::fmt::Display for DiamondVertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub trait ClassifyDiamondVertex {
    #[must_use]
    fn diamond_vertex(&self) -> DiamondVertex;
}

impl ClassifyDiamondVertex for EntityKind {
    fn diamond_vertex(&self) -> DiamondVertex {
        match self {
            Self::Person
            | Self::Email
            | Self::Phone
            | Self::Username
            | Self::Organisation
            | Self::AbnAcn => DiamondVertex::Victim,
            Self::Credential | Self::ApiKey => DiamondVertex::Capability,
            Self::IpAddress
            | Self::Domain
            | Self::Url
            | Self::Asn
            | Self::Address
            | Self::Coordinates
            | Self::MacAddress
            | Self::DeviceId
            | Self::Ssid
            | Self::TrackingId
            | Self::CryptoAddress
            | Self::Document
            | Self::Other => DiamondVertex::Infrastructure,
        }
    }
}

impl ClassifyDiamondVertex for Entity {
    fn diamond_vertex(&self) -> DiamondVertex {
        self.kind.diamond_vertex()
    }
}

#[must_use]
pub fn partition_by_vertex(entities: &[Entity]) -> BTreeMap<DiamondVertex, Vec<&Entity>> {
    let mut out = BTreeMap::new();
    for entity in entities {
        out.entry(entity.diamond_vertex())
            .or_insert_with(Vec::new)
            .push(entity);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(kind: EntityKind) -> Entity {
        Entity::new(kind, "v", 0.5, "s")
    }

    #[test]
    fn kinds_map_to_expected_vertices() {
        for kind in [
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Username,
            EntityKind::Organisation,
            EntityKind::AbnAcn,
        ] {
            assert_eq!(kind.diamond_vertex(), DiamondVertex::Victim);
        }
        for kind in [EntityKind::Credential, EntityKind::ApiKey] {
            assert_eq!(kind.diamond_vertex(), DiamondVertex::Capability);
        }
        for kind in [
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::Asn,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::MacAddress,
            EntityKind::DeviceId,
            EntityKind::Ssid,
            EntityKind::TrackingId,
            EntityKind::CryptoAddress,
            EntityKind::Document,
            EntityKind::Other,
        ] {
            assert_eq!(kind.diamond_vertex(), DiamondVertex::Infrastructure);
        }
    }

    #[test]
    fn classifier_never_emits_adversary() {
        for kind in [
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Credential,
            EntityKind::IpAddress,
            EntityKind::CryptoAddress,
            EntityKind::Other,
        ] {
            assert_ne!(kind.diamond_vertex(), DiamondVertex::Adversary);
        }
    }

    #[test]
    fn partition_groups_in_input_order() {
        let entities = [
            ent(EntityKind::Person),
            ent(EntityKind::Domain),
            ent(EntityKind::Email),
            ent(EntityKind::Credential),
        ];
        let grouped = partition_by_vertex(&entities);
        assert_eq!(grouped[&DiamondVertex::Victim].len(), 2);
        assert_eq!(grouped[&DiamondVertex::Infrastructure].len(), 1);
        assert_eq!(grouped[&DiamondVertex::Capability].len(), 1);
        assert!(!grouped.contains_key(&DiamondVertex::Adversary));
    }
}
