//! Privacy-preserving, read-only adapter from Rhinser fixture inspections to
//! Huntsman's canonical entity/evidence model. This represents *submitted
//! report records*, never devices, cards, people, transactions or verified scans.
//!
//! A syntactically valid capture is not a sensor attestation. Event records
//! deliberately remain candidates and cannot imply ownership or proximity.

use serde::Serialize;
use serde_json::Value;

use crate::entity::{
    CANDIDATE_CONF, Entity, EntityKind, Evidence, EvidenceProvenance, SEED_EVIDENCE_ROLE,
};
use crate::rhinser_native::NativeCaptureReport;
use crate::sha256::{hex32, sha256};
use crate::tags;

/// Offline import preview. No persistence, graph edges or remote requests.
#[derive(Debug, Serialize)]
pub struct RhinserEntityImport {
    pub source: &'static str,
    pub evidence_role: &'static str,
    pub claimed_capture_unix_ms: u64,
    pub device_attested: bool,
    pub radio_access: bool,
    pub relationships_inferred: bool,
    pub entities: Vec<Entity>,
}

fn add_safe_metadata(mut evidence: Evidence, value: &Value, kind: &str) -> Evidence {
    // Allow-list only metadata produced by the bounded inspection functions.
    // Never copy raw frames, NFC tag values, identifiers, owner names or URLs.
    let fields: &[&str] = match kind {
        "ndef" => &["byte_count", "records", "total_payload_bytes"],
        "apdu" => &[
            "byte_count",
            "data_bytes",
            "instruction",
            "class",
            "sw1",
            "sw2",
        ],
        "tlv" => &["byte_count", "fields", "constructed_fields"],
        "bluetooth" => &["transport", "signal_class", "bonded", "address_class"],
        _ => &[],
    };
    let source = if kind == "bluetooth" {
        value
    } else {
        value.get("inspection").unwrap_or(&Value::Null)
    };
    for &field in fields {
        let Some(raw) = source.get(field) else {
            continue;
        };
        let output = match raw {
            Value::String(text) => text.clone(),
            Value::Number(_) | Value::Bool(_) => raw.to_string(),
            _ => continue,
        };
        evidence = evidence.with_attr(field, output);
    }
    evidence
}

/// Convert an already validated fixture report into canonical *event-record*
/// entities. Repeated identical sanitized reports produce stable event IDs.
///
/// Event identifiers refer to inspection records, not unique hardware. No
/// `PaymentCard`, `Person`, `MacAddress` or real `DeviceId` is manufactured.
/// A signature or corroborated source would require a separate gated pathway.
///
/// # Errors
/// Refuses unexpected observation kinds or failed serialization.
pub fn to_hse_entities(report: &NativeCaptureReport) -> Result<RhinserEntityImport, String> {
    if report.evidence_role != "operator_submitted_unverified"
        || report.device_attested
        || report.radio_access
        || report.transport_verified
    {
        return Err("only unverified offline Rhinser reports can be mapped".to_owned());
    }
    let sanitized = serde_json::to_vec(report)
        .map_err(|_| "Rhinser inspection serialization failed".to_owned())?;
    let scan_id = format!("rhinser-fixture:{}", hex32(&sha256(&sanitized)));
    let mut entities = Vec::with_capacity(report.observations.len());
    for (index, observation) in report.observations.iter().enumerate() {
        let metadata = serde_json::to_value(observation)
            .map_err(|_| "Rhinser observation serialization failed".to_owned())?;
        let kind = metadata
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| "Rhinser observation kind missing".to_owned())?;
        if !matches!(kind, "ndef" | "apdu" | "tlv" | "bluetooth") {
            return Err("unsupported Rhinser observation kind".to_owned());
        }

        let value = format!("{scan_id}:event:{index}");
        let mut entity = Entity::new(EntityKind::Other, value, CANDIDATE_CONF, &scan_id);
        entity.tag(tags::CANDIDATE);
        entity.tag(tags::DERIVED);
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan("operator_input", &scan_id),
            "Offline inspection of operator-supplied Rhinser data; sensor authenticity unverified",
        )
        .with_attr("evidence_role", SEED_EVIDENCE_ROLE)
        .with_attr("rhinser_event_kind", kind)
        .with_attr("event_index", index.to_string())
        .with_attr(
            "claimed_capture_unix_ms",
            report.captured_unix_ms_claim.to_string(),
        )
        .with_attr("device_attested", "false")
        .with_attr("radio_access", "false");
        entity.add_evidence(add_safe_metadata(evidence, &metadata, kind));
        entities.push(entity);
    }
    Ok(RhinserEntityImport {
        source: "rhinser_native",
        evidence_role: "operator_submitted_unverified",
        claimed_capture_unix_ms: report.captured_unix_ms_claim,
        device_attested: false,
        radio_access: false,
        relationships_inferred: false,
        entities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rhinser_native::inspect_capture_json;

    #[test]
    fn produces_unverified_candidates_without_exposing_private_frame_contents() {
        let fixture = br#"{"schema_version":1,"captured_unix_ms":1730000000000,"operator_consented":true,"events":[{"kind":"ndef","hex":"D101055402656E4869"},{"kind":"apdu","hex":"00A40400023F00"},{"kind":"bluetooth","transport":"ble","rssi_dbm":-66,"bonded":false,"randomized_address":true}]}"#;
        let native = inspect_capture_json(fixture).unwrap();
        let output = to_hse_entities(&native).unwrap();
        assert_eq!(output.entities.len(), 3);
        assert!(!output.relationships_inferred);
        assert!(!output.device_attested);
        assert!(!output.radio_access);
        assert_eq!(output.entities[0].confidence, CANDIDATE_CONF);
        assert!(
            output
                .entities
                .iter()
                .all(|item| item.kind == EntityKind::Other)
        );
        assert!(
            output
                .entities
                .iter()
                .all(|item| item.has_tag(tags::CANDIDATE))
        );
        assert!(
            output
                .entities
                .iter()
                .all(|item| item.has_tag(tags::DERIVED))
        );
        assert!(
            output
                .entities
                .iter()
                .all(|item| item.evidence[0].is_operator_seed())
        );
        let serialized = serde_json::to_string(&output).unwrap();
        for forbidden in [
            "D101055402656E4869",
            "00A40400023F00",
            "pan_full",
            "cardholder_name",
            "owns",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "unexpected raw/private field: {forbidden}"
            );
        }
        assert_eq!(
            output.entities[0].uid,
            to_hse_entities(&inspect_capture_json(fixture).unwrap())
                .unwrap()
                .entities[0]
                .uid
        );
        assert_ne!(output.entities[0].uid, output.entities[1].uid);
    }

    #[test]
    fn does_not_accept_unconsented_fixture_as_an_entity() {
        let fixture = br#"{"schema_version":1,"captured_unix_ms":1,"operator_consented":false,"events":[{"kind":"bluetooth","transport":"ble","rssi_dbm":-66,"bonded":false,"randomized_address":true}]}"#;
        assert!(inspect_capture_json(fixture).is_err());
    }
}
