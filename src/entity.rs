//! Entity, evidence, and relation-ready model.
//!
//! Every evidence item carries mandatory provenance, so graph, timeline,
//! exposure, and identity logic all rest on the same traceable record shape.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::canonical::{
    canonical_coordinates, canonical_domain, canonical_email, canonical_handle, canonical_name,
    canonical_phone, canonical_provenance_family, canonical_url, canonical_whitespace,
};
use crate::confidence::{
    Classification, VerificationMethod, depth_decayed, effective, effective_from_ancestry,
};
use crate::evidence_ancestry::{AncestryError, EvidenceAncestryGraph, EvidenceNodeId};
use crate::sha256::{hex32, sha256};
use crate::tags;

static SCAN_COUNTER: AtomicU64 = AtomicU64::new(0);

#[must_use]
pub fn scan_id(kind: &str, value: &str) -> String {
    let counter = SCAN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0u128, |duration| duration.as_nanos());
    let material = format!("huntsman-scan-id-v1\0{kind}\0{value}\0{now}\0{counter}");
    hex32(&sha256(material.as_bytes()))
}

pub const CANDIDATE_CONF: f64 = 0.25;
pub const RECALL_SOURCE: &str = "recall";
pub const CROSS_SCAN_SOURCE: &str = "cross_scan_history";
pub const CONSENSUS_SOURCE: &str = "breach_consensus";
pub const MULTIPATH_CORROBORATION_SOURCE: &str = "multipath_corroboration";
pub const CROSS_SCAN_CORROBORATION_SOURCE: &str = "cross_scan_corroboration";
pub const GEO_CORROBORATION_SOURCE: &str = "geo_corroboration";
pub const ENRICHMENT_ONLY_SOURCES: &[&str] = &[
    "breach_timezone",
    "discord_snowflake",
    "email_canonical",
    "email_header_geo",
    "email_locale",
    "email_parse",
    "geo_domain_classifier",
    "geo_normalize",
    "name_intel",
    "payid",
    "phone_au",
    "phone_geo",
    "phone_intl",
    "seed",
    "structured_id",
    "url_extract",
    "username_variants",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Person,
    Organisation,
    Email,
    Phone,
    Username,
    Domain,
    Url,
    IpAddress,
    Coordinates,
    Address,
    Credential,
    Document,
    CryptoAddress,
    DeviceId,
    Ssid,
    TrackingId,
    AbnAcn,
    ApiKey,
    MacAddress,
    Asn,
    Other,
}

impl EntityKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Organisation => "organisation",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Username => "username",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::IpAddress => "ip_address",
            Self::Coordinates => "coordinates",
            Self::Address => "address",
            Self::Credential => "credential",
            Self::Document => "document",
            Self::CryptoAddress => "crypto_address",
            Self::DeviceId => "device_id",
            Self::Ssid => "ssid",
            Self::TrackingId => "tracking_id",
            Self::AbnAcn => "abn_acn",
            Self::ApiKey => "api_key",
            Self::MacAddress => "mac_address",
            Self::Asn => "asn",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceProvenance {
    pub source: String,
    /// Canonical family of `source`, as stored. Loaded from saved data, so its value is
    /// not trusted for counting: [`Self::corroboration_key`] derives the key from
    /// `source` and reads only whether this field is empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_family: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<String>,
    pub recorded_at_unix: u64,
}

impl EvidenceProvenance {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        let source = source.into();
        Self {
            source_family: canonical_provenance_family(&source),
            source,
            scan_id: None,
            recorded_at_unix: unix_now(),
        }
    }

    #[must_use]
    pub fn for_scan(source: impl Into<String>, scan_id: impl Into<String>) -> Self {
        let mut provenance = Self::new(source);
        provenance.scan_id = Some(scan_id.into());
        provenance
    }

    /// The family this record corroborates under, derived from `source`.
    ///
    /// The stored `source_family` value is never used as the key. It is deserialized
    /// from saved data (`#[serde(default)]`) and `Entity::add_evidence` only fills it
    /// when empty, so trusting it would let a tampered saved record give two rows from
    /// one collector two families and inflate `Entity::source_count`. A record with a
    /// stored family counts under `canonical_provenance_family(source)`, the same
    /// derivation as the lineage registry gate, which is what an honest record stores.
    ///
    /// A record with no stored family keeps counting under its raw `source`, as on
    /// main and in legacy 7dca720 (which counts raw sources). Canonicalising that case
    /// too would make `HIBP` and `hibp` one source, a count change that legacy does
    /// not make; it is not adopted here (see docs/LINEAGE.md).
    #[must_use]
    pub fn corroboration_key(&self) -> String {
        if self.source_family.is_empty() {
            self.source.clone()
        } else {
            canonical_provenance_family(&self.source)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub provenance: EvidenceProvenance,
    pub summary: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationMethod>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_inferred: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ancestry_node: Option<EvidenceNodeId>,
}

impl Evidence {
    #[must_use]
    pub fn new(provenance: EvidenceProvenance, summary: impl Into<String>) -> Self {
        Self {
            provenance,
            summary: summary.into(),
            attributes: BTreeMap::new(),
            verification: None,
            is_inferred: false,
            ancestry_node: None,
        }
    }

    #[must_use]
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let value = value.into();
        match self.attributes.get_mut(&key) {
            Some(existing) => {
                if !existing.split("; ").any(|seen| seen == value) {
                    existing.push_str("; ");
                    existing.push_str(&value);
                }
            }
            None => {
                self.attributes.insert(key, value);
            }
        }
        self
    }

    #[must_use]
    pub fn with_optional_attrs<'a>(
        mut self,
        attrs: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
    ) -> Self {
        for (key, value) in attrs {
            if let Some(value) = value.map(str::trim).filter(|s| !s.is_empty()) {
                self = self.with_attr(key, value);
            }
        }
        self
    }

    pub fn attr_values<'a>(&'a self, key: &str) -> impl Iterator<Item = &'a str> + 'a {
        self.attributes
            .get(key)
            .into_iter()
            .flat_map(|value| value.split("; "))
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    #[must_use]
    pub fn with_verification(mut self, verification: VerificationMethod) -> Self {
        self.verification = Some(verification);
        self
    }

    #[must_use]
    pub fn inferred(mut self) -> Self {
        self.is_inferred = true;
        self
    }

    #[must_use]
    pub fn with_ancestry(mut self, node_id: impl Into<EvidenceNodeId>) -> Self {
        self.ancestry_node = Some(node_id.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    pub uid: String,
    pub kind: EntityKind,
    pub value: String,
    pub raw_value: String,
    pub confidence: f64,
    pub corroboration: u32,
    pub observed_at_unix: u64,
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub scan_id: String,
    #[serde(default)]
    pub generation: u32,
}

pub fn merge_by_uid(entities: &mut Vec<Entity>) {
    let mut positions = HashMap::<String, usize>::with_capacity(entities.len());
    let mut merged = Vec::with_capacity(entities.len());
    for entity in entities.drain(..) {
        if let Some(&index) = positions.get(&entity.uid) {
            merged[index].absorb(entity);
        } else {
            positions.insert(entity.uid.clone(), merged.len());
            merged.push(entity);
        }
    }
    *entities = merged;
}

impl Entity {
    #[must_use]
    pub fn new(
        kind: EntityKind,
        value: impl Into<String>,
        confidence: f64,
        scan_id: impl Into<String>,
    ) -> Self {
        let raw_value = value.into();
        let value = normalise(&kind, &raw_value);
        Self {
            uid: derive_uid(&kind, &value),
            kind,
            value,
            raw_value,
            confidence: unit(confidence),
            corroboration: 1,
            observed_at_unix: unix_now(),
            evidence: Vec::new(),
            tags: Vec::new(),
            scan_id: scan_id.into(),
            generation: 0,
        }
    }

    #[must_use]
    pub fn builder(
        kind: EntityKind,
        value: impl Into<String>,
        confidence: f64,
        scan_id: impl Into<String>,
    ) -> EntityBuilder {
        EntityBuilder {
            entity: Self::new(kind, value, confidence, scan_id),
        }
    }

    #[must_use]
    pub fn source_count(&self) -> u32 {
        let derived = self.has_tag(tags::DERIVED);
        let mut real = BTreeSet::new();
        let mut promo = BTreeSet::new();
        for evidence in &self.evidence {
            let key = evidence.provenance.corroboration_key();
            if is_non_corroborating_source(&key) {
                continue;
            }
            if is_promotion_source(&key) {
                promo.insert(key);
            } else {
                real.insert(key);
            }
        }
        let grounded = real.len() >= if derived { 2 } else { 1 };
        let distinct = real.len() + if grounded { promo.len() } else { 0 };
        if distinct > 0 {
            u32::try_from(distinct).unwrap_or(u32::MAX)
        } else {
            self.corroboration.max(1)
        }
    }

    #[must_use]
    pub fn c_effective(&self) -> f64 {
        effective(self.confidence, self.source_count())
    }

    /// # Errors
    /// Returns ancestry validation errors when support nodes are missing or cyclic.
    pub fn c_effective_from_ancestry(
        &self,
        graph: &EvidenceAncestryGraph,
    ) -> Result<f64, AncestryError> {
        let support: Vec<EvidenceNodeId> = self
            .evidence
            .iter()
            .filter_map(|evidence| evidence.ancestry_node.clone())
            .collect();
        if support.is_empty() {
            Ok(self.c_effective())
        } else {
            effective_from_ancestry(self.confidence, graph, &support)
        }
    }

    #[must_use]
    pub fn c_effective_depth_decayed(&self, base: f64) -> Option<f64> {
        depth_decayed(self.c_effective(), base, self.generation)
    }

    #[must_use]
    pub fn classify(&self) -> Classification {
        Classification::from_effective(self.c_effective())
    }

    pub fn add_evidence(&mut self, mut evidence: Evidence) {
        if evidence.provenance.scan_id.is_none() && !self.scan_id.is_empty() {
            evidence.provenance.scan_id = Some(self.scan_id.clone());
        }
        if evidence.provenance.source_family.is_empty() {
            evidence.provenance.source_family =
                canonical_provenance_family(&evidence.provenance.source);
        }
        self.evidence.push(evidence);
    }

    pub fn tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !self.tags.iter().any(|seen| seen == &tag) {
            self.tags.push(tag);
        }
    }

    pub fn demote_to_candidate(&mut self) {
        self.confidence = self.confidence.min(CANDIDATE_CONF);
        self.tag(tags::CANDIDATE);
    }

    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|seen| seen == tag)
    }

    #[must_use]
    pub fn evidence_sources(&self) -> BTreeSet<String> {
        self.evidence
            .iter()
            .map(|evidence| evidence.provenance.source.clone())
            .collect()
    }

    #[must_use]
    pub fn corroborating_sources(&self) -> BTreeSet<String> {
        self.evidence
            .iter()
            .map(|evidence| evidence.provenance.corroboration_key())
            .filter(|source| !is_non_corroborating_source(source))
            .collect()
    }

    pub fn absorb(&mut self, other: Self) {
        if self.uid != other.uid {
            return;
        }
        self.confidence = self.confidence.max(other.confidence);
        self.corroboration = self.corroboration.saturating_add(other.corroboration);
        self.observed_at_unix = self.observed_at_unix.min(other.observed_at_unix);
        self.generation = self.generation.min(other.generation);
        for tag in other.tags {
            self.tag(tag);
        }
        for evidence in other.evidence {
            if let Some(existing) = self
                .evidence
                .iter_mut()
                .find(|current| same_evidence_identity(current, &evidence))
            {
                merge_evidence(existing, evidence);
            } else {
                self.evidence.push(evidence);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityBuilder {
    entity: Entity,
}

impl EntityBuilder {
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.entity.tag(tag);
        self
    }

    #[must_use]
    pub fn tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for tag in tags {
            self.entity.tag(tag);
        }
        self
    }

    #[must_use]
    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.entity.add_evidence(evidence);
        self
    }

    #[must_use]
    pub fn build(self) -> Entity {
        self.entity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRef {
    pub uid: String,
    pub kind: EntityKind,
    pub value: String,
}

impl From<&Entity> for EntityRef {
    fn from(entity: &Entity) -> Self {
        Self {
            uid: entity.uid.clone(),
            kind: entity.kind.clone(),
            value: entity.value.clone(),
        }
    }
}

#[must_use]
pub fn derive_uid(kind: &EntityKind, normalised_value: &str) -> String {
    let material = format!("{}:{normalised_value}", kind.as_str());
    hex32(&sha256(material.as_bytes()))
}

#[must_use]
pub fn normalise(kind: &EntityKind, value: &str) -> String {
    match kind {
        EntityKind::Email => {
            canonical_email(value).unwrap_or_else(|| value.trim().to_ascii_lowercase())
        }
        EntityKind::Username => {
            canonical_handle(value).unwrap_or_else(|| value.trim().to_ascii_lowercase())
        }
        EntityKind::Domain => canonical_domain(value)
            .unwrap_or_else(|| value.trim().trim_matches('.').to_ascii_lowercase()),
        EntityKind::Url => canonical_url(value).unwrap_or_else(|| value.trim().to_owned()),
        EntityKind::Phone => canonical_phone(value).unwrap_or_else(|| value.trim().to_owned()),
        EntityKind::Coordinates => {
            canonical_coordinates(value).unwrap_or_else(|| canonical_whitespace(value))
        }
        EntityKind::Person | EntityKind::Organisation | EntityKind::Address => {
            canonical_name(value)
        }
        EntityKind::IpAddress | EntityKind::Credential | EntityKind::Document => {
            value.trim().to_owned()
        }
        EntityKind::CryptoAddress
        | EntityKind::DeviceId
        | EntityKind::Ssid
        | EntityKind::TrackingId
        | EntityKind::AbnAcn
        | EntityKind::ApiKey
        | EntityKind::MacAddress
        | EntityKind::Asn
        | EntityKind::Other => canonical_whitespace(value),
    }
}

#[must_use]
pub fn evidence_sources(entities: &[Entity]) -> BTreeSet<String> {
    entities
        .iter()
        .flat_map(Entity::evidence_sources)
        .collect::<BTreeSet<_>>()
}

#[must_use]
pub fn is_enrichment_source(source: &str) -> bool {
    ENRICHMENT_ONLY_SOURCES.contains(&source)
}

#[must_use]
pub fn is_promotion_source(source: &str) -> bool {
    matches!(
        source,
        MULTIPATH_CORROBORATION_SOURCE | CROSS_SCAN_CORROBORATION_SOURCE | GEO_CORROBORATION_SOURCE
    )
}

#[must_use]
pub fn is_non_corroborating_source(source: &str) -> bool {
    is_enrichment_source(source)
        || matches!(source, RECALL_SOURCE | CROSS_SCAN_SOURCE | CONSENSUS_SOURCE)
}

#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn unit(x: f64) -> f64 {
    if x.is_finite() {
        x.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

fn same_evidence_identity(left: &Evidence, right: &Evidence) -> bool {
    left.provenance.source == right.provenance.source && left.summary == right.summary
}

fn merge_evidence(existing: &mut Evidence, incoming: Evidence) {
    for (key, value) in incoming.attributes {
        match existing.attributes.get_mut(&key) {
            Some(current) if current != &value => {
                let mut merged = current
                    .split("; ")
                    .map(ToOwned::to_owned)
                    .collect::<BTreeSet<_>>();
                merged.extend(value.split("; ").map(ToOwned::to_owned));
                *current = merged.into_iter().collect::<Vec<_>>().join("; ");
            }
            Some(_) => {}
            None => {
                existing.attributes.insert(key, value);
            }
        }
    }
    if existing.verification.is_none() {
        existing.verification = incoming.verification;
    }
    existing.is_inferred |= incoming.is_inferred;
    if existing.ancestry_node.is_none() {
        existing.ancestry_node = incoming.ancestry_node;
    }
}

impl fmt::Display for Entity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}) C={:.3} C_eff={:.3} corr={} → {}",
            self.kind,
            self.value,
            self.uid.get(..8).unwrap_or(&self.uid),
            self.confidence,
            self.c_effective(),
            self.corroboration,
            self.classify()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(source: &str, summary: &str) -> Evidence {
        Evidence::new(EvidenceProvenance::for_scan(source, "scan-1"), summary)
    }

    #[test]
    fn uid_is_deterministic() {
        let a = Entity::new(EntityKind::Email, "Ada@Example.com", 0.6, "scan");
        let b = Entity::new(EntityKind::Email, "ada@example.com", 0.6, "scan");
        assert_eq!(a.uid, b.uid);
    }

    #[test]
    fn builder_matches_hand_rolled_entity() {
        let mut hand = Entity::new(EntityKind::Domain, "Example.COM", 0.83, "scan-1");
        hand.tag("archived");
        hand.tag("web");
        hand.add_evidence(
            evidence("wayback", "3 snapshots")
                .with_attr("snapshot_count", "3")
                .with_attr("first_seen", "2020"),
        );
        let built = Entity::builder(EntityKind::Domain, "Example.COM", 0.83, "scan-1")
            .tag("archived")
            .tag("web")
            .evidence(
                evidence("wayback", "3 snapshots")
                    .with_attr("snapshot_count", "3")
                    .with_attr("first_seen", "2020"),
            )
            .build();
        assert_eq!(built.uid, hand.uid);
        assert_eq!(built.tags, hand.tags);
        assert_eq!(built.evidence, hand.evidence);
    }

    #[test]
    fn provenance_is_mandatory_and_scan_id_backfills() {
        let mut entity = Entity::new(EntityKind::Email, "a@b.com", 0.5, "scan-x");
        let evidence = Evidence::new(EvidenceProvenance::new("hibp"), "breach row");
        entity.add_evidence(evidence);
        assert_eq!(entity.evidence[0].provenance.source, "hibp");
        assert_eq!(
            entity.evidence[0].provenance.scan_id.as_deref(),
            Some("scan-x")
        );
    }

    #[test]
    fn enrichment_and_recall_do_not_count_as_corroboration() {
        let mut entity = Entity::new(EntityKind::Address, "Austin, Texas", 0.45, "s");
        entity.tag(tags::DERIVED);
        entity.add_evidence(evidence("search_engines", "recycled snippet"));
        entity.add_evidence(evidence("geo_normalize", "parsed"));
        entity.add_evidence(evidence(RECALL_SOURCE, "recalled"));
        assert_eq!(entity.evidence_sources().len(), 3);
        assert_eq!(entity.source_count(), 1);
    }

    #[test]
    fn demote_to_candidate_is_idempotent() {
        let mut entity = Entity::new(EntityKind::Email, "stranger@example.com", 0.7, "s");
        entity.demote_to_candidate();
        entity.demote_to_candidate();
        assert_eq!(entity.classify(), Classification::Candidate);
        assert_eq!(
            entity
                .tags
                .iter()
                .filter(|tag| *tag == tags::CANDIDATE)
                .count(),
            1
        );
    }

    #[test]
    fn absorb_merges_evidence_attributes_and_confidence() {
        let mut left = Entity::builder(EntityKind::Email, "a@b.com", 0.4, "s1")
            .evidence(evidence("hibp", "breach").with_attr("site", "forum-a"))
            .build();
        let right = Entity::builder(EntityKind::Email, "A@B.COM", 0.8, "s2")
            .evidence(evidence("hibp", "breach").with_attr("site", "forum-b"))
            .tag(tags::BREACH)
            .build();
        left.absorb(right);
        assert!((left.confidence - 0.8).abs() < f64::EPSILON);
        assert!(left.has_tag(tags::BREACH));
        assert_eq!(
            left.evidence[0].attributes.get("site").map(String::as_str),
            Some("forum-a; forum-b")
        );
    }
}
