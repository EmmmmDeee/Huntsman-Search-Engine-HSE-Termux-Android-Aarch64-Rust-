//! Convert extracted entities → HSE core::entity::Entity for auto-scan pipeline.

use crate::core::entity::{Entity, EntityKind as CoreEntityKind, Evidence};
use crate::util::entity_extractor::{EntityKind as ExtractorEntityKind, ExtractedEntity};

/// Map extractor EntityKind to core EntityKind.
pub fn map_entity_kind(kind: &ExtractorEntityKind) -> CoreEntityKind {
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
        ExtractorEntityKind::Unknown(s) => CoreEntityKind::Other(s.clone()),
    }
}

/// Convert an extracted entity to an HSE Entity ready for the scan pipeline.
///
/// # Parameters
/// - `extracted`: The entity from the ingest pipeline
/// - `scan_id`: The scan ID to associate this entity with
/// - `document_source`: Name of the document/file (e.g., "license.png", "scan.pdf")
///
/// # Returns
/// An HSE Entity with:
/// - Kind mapped to HSE's taxonomy
/// - Base confidence from extraction
/// - Evidence chain including source pattern, context, and extraction metadata
/// - Tags marking the entity as document-ingested
pub fn extracted_to_hse_entity(
    extracted: &ExtractedEntity,
    scan_id: impl Into<String>,
    document_source: &str,
) -> Entity {
    let scan_id = scan_id.into();
    let core_kind = map_entity_kind(&extracted.kind);

    // Create HSE entity with extracted confidence
    let mut entity = Entity::new(core_kind, &extracted.value, extracted.confidence, &scan_id);

    // Build evidence with full extraction metadata
    let mut evidence = Evidence::new(
        format!("ingest:{document_source}"),
        format!(
            "Entity extracted from {} via pattern: {}",
            document_source, extracted.source_pattern
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

    // Tag as document-ingested for filtering/audit
    entity.tag("document-ingestion");
    entity.tag(format!(
        "ingest:confidence-{:.0}",
        extracted.confidence * 100.0
    ));

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
    fn test_extracted_entity_conversion() {
        let extracted = ExtractedEntity {
            kind: EntityKind::Email,
            value: "test@example.com".to_string(),
            confidence: 0.85,
            context: Some("Contact john.doe@example.com".to_string()),
            source_pattern: "email_rfc5322".to_string(),
            boost_reason: Some("RFC 5322 compliant format".to_string()),
        };

        let entity = extracted_to_hse_entity(&extracted, "scan-123", "test.txt");

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
}
