//! Entity, evidence, and relation-ready model.
//!
//! Every evidence item carries mandatory provenance, so graph, timeline,
//! exposure, and identity logic all rest on the same traceable record shape.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::canonical::{
    canonical_coordinates, canonical_domain, canonical_email, canonical_handle, canonical_name,
    canonical_phone, canonical_provenance_family, canonical_url, canonical_whitespace,
};
use crate::clock;
use crate::confidence::{Classification, VerificationMethod, effective};
use crate::evidence_ancestry::EvidenceNodeId;
use crate::sha256::{hex32, sha256};
use crate::tags;

static SCAN_COUNTER: AtomicU64 = AtomicU64::new(0);

#[must_use]
pub fn scan_id(kind: &str, value: &str) -> String {
    let counter = SCAN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = clock::unix_now_nanos();
    let material = format!("huntsman-scan-id-v1\0{kind}\0{value}\0{now}\0{counter}");
    hex32(&sha256(material.as_bytes()))
}

pub const CANDIDATE_CONF: f64 = 0.25;
/// The `evidence_role` an operator's seed carries: the query the scan was given, not a source's
/// finding about it.
pub const SEED_EVIDENCE_ROLE: &str = "seed_not_external_verification";
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
    "oui",
    "payid",
    "phone_au",
    "phone_geo",
    "phone_intl",
    "phone_nanp",
    "registry_policy",
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
    /// An address block in CIDR form, written as its first address and prefix length.
    Netblock,
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
            Self::Netblock => "netblock",
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
            recorded_at_unix: clock::unix_now(),
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
    /// The provenance of every other observation merged into this record, in merge order. Two
    /// records of one source saying the same thing about one entity merge into one, and this keeps
    /// the scan and time of each observation the first record alone would have hidden.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merged_provenance: Vec<EvidenceProvenance>,
}

/// What joins the values of an attribute that holds several: [`Evidence::with_attr`] joins a
/// repeated key's values with it and [`Evidence::attr_values`] lists them by it.
const VALUE_SEPARATOR: &str = "; ";

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
            merged_provenance: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let value = value.into();
        match self.attributes.get_mut(&key) {
            Some(existing) => {
                if !holds_whole(existing, &value) {
                    existing.push_str(VALUE_SEPARATOR);
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
            .flat_map(|value| value.split(VALUE_SEPARATOR))
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// Whether this evidence is the operator's own seed rather than a source's finding.
    #[must_use]
    pub fn is_operator_seed(&self) -> bool {
        matches!(self.provenance.source.as_str(), "operator_input" | "seed")
            || self
                .attr_values("evidence_role")
                .any(|value| value == SEED_EVIDENCE_ROLE)
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
    /// Every spelling sources observed a username under, with the highest confidence each was
    /// observed at, once merges brought more than its own `raw_value`. A username's identity key
    /// folds case and separators, so `pg_smith` and `PGSmith` are one entity, while a platform
    /// that keeps separators sees two handles. Another case of a kept spelling raises that
    /// spelling's confidence instead of adding one. Empty means the `raw_value` alone, at the
    /// entity's confidence, when a source observed it ([`Entity::observed_spellings`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spellings: BTreeMap<String, f64>,
}

pub fn merge_by_uid(entities: &mut Vec<Entity>) {
    let mut positions = HashMap::<String, usize>::with_capacity(entities.len());
    let mut merged: Vec<Entity> = Vec::with_capacity(entities.len());
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

/// Adds one entity observed with `evidence` and the given tags. Entities that end up with the same
/// uid are folded together by [`merge_by_uid`].
pub fn push_entity(
    entities: &mut Vec<Entity>,
    kind: EntityKind,
    value: &str,
    confidence: f64,
    scan_id: &str,
    evidence: Evidence,
    tags: &[&str],
) {
    let mut entity = Entity::new(kind, value, confidence, scan_id);
    for tag in tags {
        entity.tag(*tag);
    }
    entity.add_evidence(evidence);
    entities.push(entity);
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
            observed_at_unix: clock::unix_now(),
            evidence: Vec::new(),
            tags: Vec::new(),
            scan_id: scan_id.into(),
            generation: 0,
            spellings: BTreeMap::new(),
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
        } else if !self.evidence.is_empty() && self.corroborating_sources().is_empty() {
            // Only enrichment or recall evidence: one observation, however many entities derived
            // from the same input were merged into this one.
            1
        } else {
            // No evidence: the number of times the entity was seen.
            self.corroboration.max(1)
        }
    }

    #[must_use]
    pub fn c_effective(&self) -> f64 {
        effective(self.confidence, self.source_count())
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

    /// Whether every record of this entity is a reading made offline from another value, by a
    /// source that observes no one ([`is_enrichment_source`]): a handle guessed from an address's
    /// local part, a name read off it, a handle's variants. Such an entity restates the value it
    /// was read from, so it binds no identity. A record any other source made, a profile's own
    /// published address included, is an observation. The operator's own selector
    /// ([`Evidence::is_operator_seed`]) is no reading of another value either: the `seed` source
    /// corroborates nothing, but the value it records is the one the lookup was asked about.
    #[must_use]
    pub fn is_offline_reading(&self) -> bool {
        !self.evidence.is_empty()
            && self.evidence.iter().all(|evidence| {
                !evidence.is_operator_seed()
                    && is_enrichment_source(&evidence.provenance.corroboration_key())
            })
    }

    #[must_use]
    pub fn corroborating_sources(&self) -> BTreeSet<String> {
        self.evidence
            .iter()
            .map(|evidence| evidence.provenance.corroboration_key())
            .filter(|source| !is_non_corroborating_source(source))
            .collect()
    }

    /// Whether a source observed this entity, rather than only guessing it from another value
    /// (an e-mail's local part, a username's variants) or being asked it: some record is neither
    /// inferred nor an operator's seed ([`Evidence::is_operator_seed`], the query a lookup was
    /// given, which every lookup a crawl dispatches echoes back), or it has no record to say
    /// otherwise. **Pure.**
    #[must_use]
    pub fn is_observed(&self) -> bool {
        self.evidence.is_empty()
            || self
                .evidence
                .iter()
                .any(|evidence| !evidence.is_inferred && !evidence.is_operator_seed())
    }

    /// Every spelling a source observed this username under, with the highest confidence each was
    /// observed at: the ones merges kept ([`Self::spellings`]), else its own `raw_value` at its
    /// confidence when a source observed it. A guess observed nothing, and other kinds have none.
    #[must_use]
    pub fn observed_spellings(&self) -> BTreeMap<String, f64> {
        if !self.spellings.is_empty() {
            return self.spellings.clone();
        }
        let mut spellings = BTreeMap::new();
        if self.kind == EntityKind::Username && self.is_observed() {
            spellings.insert(spelling_of(&self.raw_value), self.confidence);
        }
        spellings
    }

    pub fn absorb(&mut self, other: Self) {
        if self.uid != other.uid {
            return;
        }
        // Each spelling a source observed the handle under is kept, as `raw_value` alone cannot
        // hold them, so a merge never loses a handle a source reported.
        let spellings = (self.kind == EntityKind::Username).then(|| {
            let mut spellings = self.observed_spellings();
            for (spelling, confidence) in other.observed_spellings() {
                let route = crate::canonical::handle_route_key(&spelling);
                match spellings
                    .iter_mut()
                    .find(|(kept, _)| crate::canonical::handle_route_key(kept) == route)
                {
                    Some((_, kept)) => *kept = kept.max(confidence),
                    None => {
                        spellings.insert(spelling, confidence);
                    }
                }
            }
            spellings
        });
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
        if let Some(spellings) = spellings {
            // Kept only when it says more than the entity's own spelling at its confidence.
            self.spellings = BTreeMap::new();
            if spellings != self.observed_spellings() {
                self.spellings = spellings;
            }
        }
    }
}

/// A handle as a source wrote it, without surrounding space or its leading `@`s.
fn spelling_of(raw: &str) -> String {
    raw.trim().trim_start_matches('@').to_owned()
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
        // A Solana address is base58 without a checksum: two spellings that differ only in case
        // are two different keys, so its case is part of its identity.
        EntityKind::CryptoAddress if value.trim().starts_with(crate::canonical::SOLANA_PREFIX) => {
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
        EntityKind::Netblock => crate::netblock::Netblock::parse(value)
            .map_or_else(|| canonical_whitespace(value), |block| block.to_string()),
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

/// A structured provider answer must be kept as one document. JSON strings may contain
/// the separator used by legacy attribute-list merges, so splitting a document corrupts it.
fn is_json_document(value: &str) -> bool {
    matches!(value.trim_start().as_bytes().first(), Some(b'{' | b'['))
        && serde_json::from_str::<serde::de::IgnoredAny>(value).is_ok()
}

fn same_evidence_identity(left: &Evidence, right: &Evidence) -> bool {
    if left.provenance.source != right.provenance.source || left.summary != right.summary {
        return false;
    }
    // Changed structured documents describe distinct source observations, even when the
    // summary repeats. Keep both provenance-bearing records instead of splicing raw answers
    // together or dropping the older document. Equal documents still coalesce as before.
    !left.attributes.iter().any(|(key, previous)| {
        right.attributes.get(key).is_some_and(|incoming| {
            previous != incoming
                && (key.starts_with("raw_")
                    || is_json_document(previous)
                    || is_json_document(incoming))
        })
    })
}

/// Whether the attribute value `held` already holds `value` whole: as all of it, or as a run of
/// its values that the separator bounds at both ends. **Pure.**
fn holds_whole(held: &str, value: &str) -> bool {
    held == value
        || held
            .strip_prefix(value)
            .is_some_and(|rest| rest.starts_with(VALUE_SEPARATOR))
        || held
            .strip_suffix(value)
            .is_some_and(|rest| rest.ends_with(VALUE_SEPARATOR))
        || held.contains(&format!("{VALUE_SEPARATOR}{value}{VALUE_SEPARATOR}"))
}

/// Folds `incoming` into the attribute value `held` so that it holds both whole, `held`'s values
/// first. A `held` that already holds `incoming` is kept, and an `incoming` that holds `held`
/// replaces it. Where `incoming` begins with values `held` ends with, those are written once;
/// otherwise the two are joined. Nothing is split apart, reordered or dropped, so a value with the
/// separator in its own text survives any number of merges byte for byte.
fn fold_value(held: &mut String, incoming: String) {
    if holds_whole(held, &incoming) {
        return;
    }
    if holds_whole(&incoming, held) {
        *held = incoming;
        return;
    }
    let rest = incoming
        .rmatch_indices(VALUE_SEPARATOR)
        .find(|&(at, _)| {
            held.strip_suffix(&incoming[..at])
                .is_some_and(|before| before.ends_with(VALUE_SEPARATOR))
        })
        .map_or(incoming.as_str(), |(at, _)| {
            &incoming[at + VALUE_SEPARATOR.len()..]
        });
    held.push_str(VALUE_SEPARATOR);
    held.push_str(rest);
}

/// Folds `incoming` into `existing`, one observation ([`same_evidence_identity`]). Every value either
/// record holds is kept whole, in the order it was observed ([`fold_value`]).
fn merge_evidence(existing: &mut Evidence, incoming: Evidence) {
    for (key, value) in incoming.attributes {
        match existing.attributes.get_mut(&key) {
            Some(held) => fold_value(held, value),
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
    keep_observations(existing, incoming.provenance, incoming.merged_provenance);
}

/// Keeps every observation a merge brings in: the incoming record's own provenance, then any it
/// already carried from its merges. An observation the record already holds is not kept twice.
fn keep_observations(
    existing: &mut Evidence,
    incoming: EvidenceProvenance,
    earlier: Vec<EvidenceProvenance>,
) {
    for observation in std::iter::once(incoming).chain(earlier) {
        if observation != existing.provenance && !existing.merged_provenance.contains(&observation)
        {
            existing.merged_provenance.push(observation);
        }
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

    /// A record of one scan that a later scan re-finds merges into one record. The later scan's
    /// observation must survive in the saved entity, not vanish with the merge.
    #[test]
    fn a_merged_observation_keeps_its_scan_and_time() {
        let first = Evidence::new(
            EvidenceProvenance {
                recorded_at_unix: 100,
                ..EvidenceProvenance::for_scan("hunter", "scan-1")
            },
            "domain seen",
        );
        let mut entity = Entity::new(EntityKind::Domain, "example.com", 0.6, "scan-1");
        entity.add_evidence(first);
        let mut later = Entity::new(EntityKind::Domain, "example.com", 0.6, "scan-2");
        later.add_evidence(Evidence::new(
            EvidenceProvenance {
                recorded_at_unix: 200,
                ..EvidenceProvenance::for_scan("hunter", "scan-2")
            },
            "domain seen",
        ));
        entity.absorb(later);

        assert_eq!(entity.evidence.len(), 1);
        assert_eq!(
            entity.evidence[0].provenance.scan_id.as_deref(),
            Some("scan-1")
        );
        assert_eq!(entity.evidence[0].provenance.recorded_at_unix, 100);
        let saved = serde_json::to_string(&entity).unwrap();
        assert!(
            saved.contains("scan-2"),
            "the second observation was dropped: {saved}"
        );
    }

    /// An observation is kept once however often it merges, and a record that already holds
    /// merged observations passes all of them on when it is merged into another.
    #[test]
    fn observations_are_kept_once_and_pass_on_through_a_later_merge() {
        let observed = |scan: &str, at: u64| {
            Evidence::new(
                EvidenceProvenance {
                    recorded_at_unix: at,
                    ..EvidenceProvenance::for_scan("hunter", scan)
                },
                "domain seen",
            )
        };
        let entity = |scan: &str, at: u64| {
            let mut entity = Entity::new(EntityKind::Domain, "example.com", 0.6, scan);
            entity.add_evidence(observed(scan, at));
            entity
        };

        let mut first = entity("scan-1", 100);
        first.absorb(entity("scan-2", 200));
        first.absorb(entity("scan-2", 200));
        assert_eq!(first.evidence[0].merged_provenance.len(), 1);

        let mut newest = entity("scan-9", 900);
        newest.absorb(first);
        let record = &newest.evidence[0];
        assert_eq!(record.provenance.scan_id.as_deref(), Some("scan-9"));
        let kept: Vec<_> = record
            .merged_provenance
            .iter()
            .filter_map(|observation| observation.scan_id.as_deref())
            .collect();
        assert_eq!(kept, ["scan-1", "scan-2"]);
    }

    /// A record with no merges keeps its saved form exactly, and a saved record from before the
    /// field existed still loads.
    #[test]
    fn a_record_without_merges_keeps_its_saved_form() {
        let record = evidence("hunter", "domain seen");
        let saved = serde_json::to_value(&record).unwrap();
        assert!(saved.get("merged_provenance").is_none(), "{saved}");
        let restored: Evidence = serde_json::from_value(saved).unwrap();
        assert!(restored.merged_provenance.is_empty());
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
        hand.tag(crate::tags::WEB);
        hand.add_evidence(
            evidence("wayback", "3 snapshots")
                .with_attr("snapshot_count", "3")
                .with_attr("first_seen", "2020"),
        );
        let built = Entity::builder(EntityKind::Domain, "Example.COM", 0.83, "scan-1")
            .tag("archived")
            .tag(crate::tags::WEB)
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
    fn a_solana_address_keeps_its_case_in_its_identity() {
        // Base58 without a checksum: one letter's case changed is another key.
        let upper = Entity::new(
            EntityKind::CryptoAddress,
            "sol:3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3",
            0.7,
            "s",
        );
        let lower = Entity::new(
            EntityKind::CryptoAddress,
            "sol:3jF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3",
            0.7,
            "s",
        );
        assert_ne!(upper.uid, lower.uid);
        assert_eq!(
            upper.value,
            "sol:3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3"
        );
        // Hex has no case, so an EVM selector still folds to one identity.
        let mixed = Entity::new(
            EntityKind::CryptoAddress,
            "eth:0xABCDEF0000000000000000000000000000000000",
            0.7,
            "s",
        );
        let folded = Entity::new(
            EntityKind::CryptoAddress,
            "eth:0xabcdef0000000000000000000000000000000000",
            0.7,
            "s",
        );
        assert_eq!(mixed.uid, folded.uid);
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
    fn a_merge_keeps_every_spelling_a_source_observed_a_handle_under() {
        let handle = |value: &str, source: &str, confidence: f64, inferred: bool| {
            let mut entity = Entity::new(EntityKind::Username, value, confidence, "s");
            // One source and summary for every spelling, as Gravatar writes its handles, so the
            // records fold into one: the spellings are kept on the entity, not on a record.
            let record = evidence(source, "public profile");
            entity.add_evidence(if inferred { record.inferred() } else { record });
            entity
        };
        let spellings = |entity: &Entity| -> Vec<(String, f64)> {
            entity.observed_spellings().into_iter().collect()
        };
        // An unmerged handle is its own spelling, and keeps no map.
        let mut handle_a = handle("pg_smith", "gravatar", 0.9, false);
        assert_eq!(spellings(&handle_a), [("pg_smith".to_owned(), 0.9)]);
        assert!(handle_a.spellings.is_empty());
        // Another spelling of one identity is kept beside it, at its own confidence, and the
        // entity keeps its own `raw_value`.
        handle_a.absorb(handle("PGSmith", "gravatar", 0.6, false));
        assert_eq!(handle_a.evidence.len(), 1, "the records fold");
        assert_eq!(handle_a.raw_value, "pg_smith");
        assert_eq!(
            spellings(&handle_a),
            [("PGSmith".to_owned(), 0.6), ("pg_smith".to_owned(), 0.9)]
        );
        // Another case of a kept spelling raises its confidence instead of adding one.
        handle_a.absorb(handle("pgsmith", "keybase", 0.8, false));
        assert_eq!(
            spellings(&handle_a),
            [("PGSmith".to_owned(), 0.8), ("pg_smith".to_owned(), 0.9)]
        );
        // A guess observed nothing: merged with an observation, only the observation is kept,
        // and the entity keeps the guess's `raw_value`.
        let mut guess = handle("pg_smith", "email_parse", 0.7, true);
        assert!(spellings(&guess).is_empty());
        guess.absorb(handle("PG_Smith", "gravatar", 0.65, false));
        assert_eq!(guess.raw_value, "pg_smith");
        assert_eq!(spellings(&guess), [("PG_Smith".to_owned(), 0.65)]);
        let mut guesses = handle("pg.smith", "email_parse", 0.7, true);
        guesses.absorb(handle("pgsmith", "username_variants", 0.7, true));
        assert!(spellings(&guesses).is_empty() && guesses.spellings.is_empty());
        // A merge that adds nothing but case keeps no map.
        let mut cased = handle("pg_smith", "hacker_news", 0.8, false);
        cased.absorb(handle("PG_Smith", "github_user", 0.9, false));
        assert!(cased.spellings.is_empty());
        assert_eq!(spellings(&cased), [("pg_smith".to_owned(), 0.9)]);
        // A lookup's seed is the query it was given, not an observation: echoed back by the lookup
        // a crawl dispatched for a guess, it observes nothing, and echoed for an observed spelling,
        // it does not raise the confidence that spelling was observed at.
        let asked = |value: &str| {
            let mut entity = Entity::new(EntityKind::Username, value, 0.99, "s");
            entity.tag("seed");
            entity.add_evidence(evidence("seed", "username selector the lookup was asked"));
            entity
        };
        assert!(spellings(&asked("pgsmith")).is_empty());
        let mut echoed_guess = handle("pg-smith", "email_parse", 0.7, true);
        echoed_guess.absorb(asked("pgsmith"));
        assert!(spellings(&echoed_guess).is_empty() && echoed_guess.spellings.is_empty());
        let mut echoed_observation = handle("PG_Smith", "gravatar", 0.65, false);
        echoed_observation.absorb(asked("pg_smith"));
        assert_eq!(
            spellings(&echoed_observation),
            [("PG_Smith".to_owned(), 0.65)]
        );
        // Other kinds have no spellings.
        let mut mail = Entity::new(EntityKind::Email, "Pg.Smith@example.com", 0.8, "s");
        mail.add_evidence(evidence("gravatar", "profile"));
        mail.absorb(Entity::new(
            EntityKind::Email,
            "pg.smith@example.com",
            0.8,
            "s",
        ));
        assert!(mail.observed_spellings().is_empty() && mail.spellings.is_empty());
    }

    #[test]
    fn guesses_derived_from_one_input_are_one_observation_however_many_merge() {
        // Four spellings of one username, each a guess from the same email address. They share a
        // uid, so they merge, and the merge must not read as four sources agreeing.
        let guess = |value: &str| {
            let mut entity = Entity::new(EntityKind::Username, value, 0.7, "s");
            entity.tag(tags::DERIVED);
            entity.add_evidence(evidence(
                "email_parse",
                "derived from jane.doe@acme.example",
            ));
            entity
        };
        let mut merged = vec![
            guess("jane.doe"),
            guess("janedoe"),
            guess("jane_doe"),
            guess("jane-doe"),
        ];
        merge_by_uid(&mut merged);
        assert_eq!(merged.len(), 1, "the four spellings share a uid");
        let entity = &merged[0];
        assert_eq!(entity.corroboration, 4, "the merge counter is unchanged");
        assert_eq!(entity.source_count(), 1);
        assert!(
            (entity.c_effective() - 0.7).abs() < 1e-9,
            "{}",
            entity.c_effective()
        );
        assert_eq!(entity.classify(), Classification::Probable);
    }

    #[test]
    fn ungrounded_promotion_evidence_keeps_the_merge_count_as_before() {
        // A promotion source corroborates only with grounded evidence. Without it, the merge count
        // decides, as it did before the enrichment-only case was narrowed out of this fallback.
        let promoted = || {
            let mut entity = Entity::new(EntityKind::Email, "a@b.com", 0.6, "s");
            entity.add_evidence(evidence(MULTIPATH_CORROBORATION_SOURCE, "seen twice"));
            entity
        };
        let mut merged = vec![promoted(), promoted()];
        merge_by_uid(&mut merged);
        assert_eq!(merged[0].corroboration, 2);
        assert_eq!(merged[0].source_count(), 2);
    }

    #[test]
    fn an_entity_without_evidence_keeps_the_number_of_times_it_was_seen() {
        let mut seen = Entity::new(EntityKind::Email, "a@b.com", 0.5, "s");
        seen.absorb(Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"));
        seen.absorb(Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"));
        assert!(seen.evidence.is_empty());
        assert_eq!(seen.source_count(), 3);
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

    /// A fold holds both values whole, the held value's first, and writes once the values where
    /// one continues the other. A value is only ever matched whole, never by a piece of its text.
    #[test]
    fn a_fold_holds_both_values_whole() {
        let fold = |held: &str, incoming: &str| {
            let mut held = held.to_owned();
            fold_value(&mut held, incoming.to_owned());
            held
        };
        assert_eq!(fold("a; b; c", "b"), "a; b; c");
        assert_eq!(fold("a; b; c", "b; c"), "a; b; c");
        assert_eq!(fold("b", "a; b; c"), "a; b; c");
        assert_eq!(fold("a; b", "b; c"), "a; b; c");
        assert_eq!(fold("a; b; c", "b; c; d"), "a; b; c; d");
        assert_eq!(fold("x; b", "b; x"), "x; b; x");
        assert_eq!(fold("ab", "b"), "ab; b");
        assert_eq!(fold("a; b", "ab; c"), "a; b; ab; c");
        assert_eq!(fold("a; bc", "c"), "a; bc; c");
    }
}
