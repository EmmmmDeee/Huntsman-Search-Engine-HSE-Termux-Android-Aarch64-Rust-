//! Convert entity-extractor output → HSE `core::entity::Entity`, ready to
//! persist as a scan.
//!
//! Two commands turn free text into structured entities via
//! `util::entity_extractor` — `hse ingest` (document text) and `hse
//! investigate` (a natural-language prompt) — and both need the identical
//! kind-mapping and evidence-chain construction to feed `app::persist`. Single
//! source here so the two can never map an extractor kind to a different core
//! kind, or drop an evidence field, from each other.

use crate::core::entity::{Entity, EntityKind as CoreEntityKind, Evidence};
use crate::util::entity_extractor::{EntityKind as ExtractorEntityKind, ExtractedEntity};

/// Map extractor `EntityKind` to core `EntityKind`.
pub(crate) fn map_entity_kind(kind: &ExtractorEntityKind) -> CoreEntityKind {
    match kind {
        ExtractorEntityKind::Email => CoreEntityKind::Email,
        ExtractorEntityKind::Phone => CoreEntityKind::Phone,
        ExtractorEntityKind::Ipv4 | ExtractorEntityKind::Ipv6 => CoreEntityKind::IpAddress,
        ExtractorEntityKind::Domain => CoreEntityKind::Domain,
        ExtractorEntityKind::Url => CoreEntityKind::Url,
        ExtractorEntityKind::Hash => CoreEntityKind::Other("hash".to_string()),
        ExtractorEntityKind::Username => CoreEntityKind::Username,
        ExtractorEntityKind::Person => CoreEntityKind::Person,
        ExtractorEntityKind::Organization => CoreEntityKind::Organisation,
        ExtractorEntityKind::SocialHandle => CoreEntityKind::Username, // map to username for scanning
        ExtractorEntityKind::IpRange => CoreEntityKind::Cidr,
        ExtractorEntityKind::Port => CoreEntityKind::Other("port".to_string()),
        ExtractorEntityKind::Identifier => CoreEntityKind::DeviceId,
        ExtractorEntityKind::Coordinates => CoreEntityKind::Coordinates,
        ExtractorEntityKind::Unknown(s) => CoreEntityKind::Other(s.clone()),
    }
}

/// Convert an extracted entity to an HSE `Entity` ready for the scan pipeline.
///
/// `evidence_source` is the free-form provenance label recorded verbatim as
/// this entity's [`Evidence::source`] and named in its description — e.g.
/// `"ingest:notes.txt"` or `"investigate:who owns example.com"`. Every caller
/// composes its own so the recorded provenance is always truthful about which
/// command actually produced the entity — this function never guesses or
/// defaults it (evidence is EVIDENCE; mislabelling where an entity came from
/// is the fabrication this crate treats as its cardinal sin). `origin_tag` is
/// the tag applied for downstream filtering/audit (e.g.
/// `"document-ingestion"`, `"investigate-query"`): both mark the entity as
/// text-extracted rather than module-fetched, but distinguish which pathway
/// did the extracting.
pub(crate) fn extracted_to_hse_entity(
    extracted: &ExtractedEntity,
    scan_id: impl Into<String>,
    evidence_source: &str,
    origin_tag: &str,
) -> Entity {
    let scan_id = scan_id.into();
    let core_kind = map_entity_kind(&extracted.kind);

    // Create HSE entity with extracted confidence
    let mut entity = Entity::new(core_kind, &extracted.value, extracted.confidence, &scan_id);

    // Build evidence with full extraction metadata
    let mut evidence = Evidence::new(
        evidence_source.to_string(),
        format!(
            "Entity extracted from {evidence_source} via pattern: {}",
            extracted.source_pattern
        ),
    );

    // Add extraction details as attributes
    evidence = evidence
        .with_attr("source_pattern", &extracted.source_pattern)
        .with_attr("kind", extracted.kind.to_str())
        .with_attr("extraction_confidence", extracted.confidence.to_string());

    // Add context if available
    if let Some(ctx) = &extracted.context {
        evidence = evidence.with_attr("context", ctx);
    }

    // Add boost reason if available
    if let Some(reason) = &extracted.boost_reason {
        evidence = evidence.with_attr("confidence_boost_reason", reason);
    }

    entity.add_evidence(evidence);

    // Tag with the caller's origin (filtering/audit) plus an origin-agnostic
    // confidence bucket.
    entity.tag(origin_tag);
    entity.tag(format!("confidence-{:.0}", extracted.confidence * 100.0));

    entity
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::entity_extractor::EntityKind;

    #[test]
    fn test_kind_mapping_email() {
        let kind = map_entity_kind(&EntityKind::Email);
        assert_eq!(kind, CoreEntityKind::Email);
    }

    #[test]
    fn test_kind_mapping_ipv4_to_ipaddress() {
        let kind = map_entity_kind(&EntityKind::Ipv4);
        assert_eq!(kind, CoreEntityKind::IpAddress);
    }

    #[test]
    fn map_entity_kind_pins_every_extractor_variant() {
        // The extraction→core contract: each extractor kind maps to a fixed core
        // kind. Only Email/Ipv4 were covered before, leaving the non-obvious
        // mappings (SocialHandle→Username, Identifier→DeviceId, Port/Hash→Other)
        // and the Ipv6 arm free to drift silently. Pin all fifteen so a remap is
        // a test failure, not a surprise in the scan graph.
        use CoreEntityKind as C;
        use EntityKind as E;
        let cases: [(E, C); 16] = [
            (E::Email, C::Email),
            (E::Phone, C::Phone),
            (E::Ipv4, C::IpAddress),
            (E::Ipv6, C::IpAddress),
            (E::Domain, C::Domain),
            (E::Url, C::Url),
            (E::Hash, C::Other("hash".to_string())),
            (E::Username, C::Username),
            (E::Person, C::Person),
            (E::Organization, C::Organisation),
            (E::SocialHandle, C::Username),
            (E::IpRange, C::Cidr),
            (E::Port, C::Other("port".to_string())),
            (E::Identifier, C::DeviceId),
            (E::Coordinates, C::Coordinates),
            (
                E::Unknown("custom-kind".to_string()),
                C::Other("custom-kind".to_string()),
            ),
        ];
        for (ext, expected) in cases {
            assert_eq!(
                map_entity_kind(&ext),
                expected,
                "mapping drifted for {ext:?}"
            );
        }
    }

    #[test]
    fn exif_coordinates_entity_converts_to_core_coordinates() {
        // The `hse ingest --extract-geolocation` path mints a Coordinates
        // ExtractedEntity from an EXIF GPS fix; it must reach the scan pipeline as
        // a core Coordinates entity whose value the geo layer can parse.
        let extracted = ExtractedEntity {
            kind: EntityKind::Coordinates,
            value: "-27.476611,153.016611".to_string(),
            confidence: 0.9,
            context: Some("EXIF GPS (exif_gps); camera Apple iPhone".to_string()),
            source_pattern: "exif_gps".to_string(),
            boost_reason: None,
        };
        let entity = extracted_to_hse_entity(
            &extracted,
            "scan-1",
            "ingest:photo.jpg",
            "document-ingestion",
        );
        assert_eq!(entity.kind, CoreEntityKind::Coordinates);
        assert_eq!(entity.value, "-27.476611,153.016611");
        assert!(
            crate::util::geohash::parse_coords(&entity.value).is_some(),
            "the geo layer must be able to parse the emitted value"
        );
    }

    #[test]
    fn ipv6_entity_converts_to_core_ipaddress() {
        // Guards the extractor's Ipv6 kind end-to-end: an IPv6 in the source
        // text must reach the scan pipeline as an IpAddress with its canonical
        // value preserved.
        let extracted = ExtractedEntity {
            kind: EntityKind::Ipv6,
            value: "2001:db8::1".to_string(),
            confidence: 0.88,
            context: None,
            source_pattern: "ipv6_rfc4291".to_string(),
            boost_reason: Some("Valid IPv6 address (std-parsed)".to_string()),
        };
        let entity =
            extracted_to_hse_entity(&extracted, "scan-1", "ingest:doc.txt", "document-ingestion");
        assert_eq!(entity.kind, CoreEntityKind::IpAddress);
        assert_eq!(entity.value, "2001:db8::1");
    }

    #[test]
    fn test_extracted_entity_conversion() {
        let extracted = ExtractedEntity {
            kind: EntityKind::Email,
            value: "test@example.com".to_string(),
            confidence: 0.85,
            context: Some("Contact john.doe@example.com".to_string()),
            source_pattern: "email_rfc5322".to_string(),
            boost_reason: Some("RFC 5322 compliant format".to_string()),
        };

        let entity = extracted_to_hse_entity(
            &extracted,
            "scan-123",
            "ingest:test.txt",
            "document-ingestion",
        );

        assert_eq!(entity.kind, CoreEntityKind::Email);
        assert_eq!(entity.value, "test@example.com");
        assert_eq!(entity.confidence, 0.85);
        assert_eq!(entity.scan_id, "scan-123");
        assert!(entity.tags.contains(&"document-ingestion".to_string()));
        assert!(!entity.evidence.is_empty());

        let first_evidence = &entity.evidence[0];
        assert!(first_evidence.source.contains("ingest:"));
        assert!(first_evidence.attributes.contains_key("source_pattern"));
        assert_eq!(
            first_evidence.attributes.get("source_pattern"),
            Some(&"email_rfc5322".to_string())
        );
    }

    #[test]
    fn origin_tag_and_evidence_source_are_caller_controlled() {
        // The whole point of parameterising origin_tag/evidence_source: two
        // different callers (ingest, investigate) must be able to record
        // truthful, DIFFERENT provenance for entities that otherwise go
        // through an identical conversion. Prove both are threaded through
        // unmodified rather than defaulted or hardcoded.
        let extracted = ExtractedEntity {
            kind: EntityKind::Domain,
            value: "example.com".to_string(),
            confidence: 0.7,
            context: None,
            source_pattern: "domain_generic".to_string(),
            boost_reason: None,
        };
        let entity = extracted_to_hse_entity(
            &extracted,
            "scan-x",
            "investigate:who owns example.com",
            "investigate-query",
        );
        assert!(entity.tags.contains(&"investigate-query".to_string()));
        assert!(!entity.tags.contains(&"document-ingestion".to_string()));
        assert!(
            entity
                .evidence
                .iter()
                .any(|e| e.source == "investigate:who owns example.com")
        );
    }
}
