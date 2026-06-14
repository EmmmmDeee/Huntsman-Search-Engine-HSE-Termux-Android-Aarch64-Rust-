use super::*;
use crate::core::scan::Target;

// ── Deserialisation ──────────────────────────────────────────────────────────

#[test]
fn deserialize_neighbours_response() {
    let json = r#"{
        "status": "ok",
        "data": {
            "resource": "13335",
            "neighbours": [
                {"asn": 1299, "type": "left"},
                {"asn": 2914, "type": "right"}
            ]
        }
    }"#;
    let r: NeighboursResp = serde_json::from_str(json).unwrap();
    assert_eq!(r.data.neighbours.len(), 2);
    assert_eq!(r.data.neighbours[0].asn, 1299);
    assert_eq!(r.data.neighbours[0].peer_type, "left");
    assert_eq!(r.data.neighbours[1].asn, 2914);
}

#[test]
fn deserialize_empty_neighbours() {
    let json = r#"{"status":"ok","data":{"neighbours":[]}}"#;
    let r: NeighboursResp = serde_json::from_str(json).unwrap();
    assert!(r.data.neighbours.is_empty());
}

#[test]
fn deserialize_missing_data_defaults() {
    let json = r#"{"status":"ok"}"#;
    let r: NeighboursResp = serde_json::from_str(json).unwrap();
    assert!(r.data.neighbours.is_empty());
}

// ── Entity mapping ───────────────────────────────────────────────────────────

#[test]
fn peer_entities_emit_asn_entities_with_tags() {
    let data: NeighboursData = serde_json::from_str(
        r#"{"neighbours":[{"asn":1299,"type":"left"},{"asn":6939,"type":"right"}]}"#,
    )
    .unwrap();
    let es = peer_entities(&data, "13335", "scan-1");
    assert_eq!(es.len(), 2);
    assert!(es.iter().all(|e| e.kind == EntityKind::Asn));
    assert_eq!(es[0].value, "AS1299");
    assert!(es[0].has_tag("asn_peers"));
    assert!(es[0].has_tag("bgp-peer:left"));
    let ev = &es[0].evidence[0];
    assert_eq!(ev.attributes.get("origin_asn").map(String::as_str), Some("13335"));
    assert_eq!(ev.attributes.get("peer_type").map(String::as_str), Some("left"));
    assert_eq!(es[1].value, "AS6939");
    assert!(es[1].has_tag("bgp-peer:right"));
}

#[test]
fn peer_entities_empty_data_yields_nothing() {
    let data = NeighboursData::default();
    assert!(peer_entities(&data, "13335", "s").is_empty());
}

#[test]
fn peer_entities_respect_cap() {
    let neighbours: Vec<_> = (1u64..=60)
        .map(|i| Neighbour {
            asn: i,
            peer_type: "left".to_string(),
        })
        .collect();
    let data = NeighboursData { neighbours };
    assert_eq!(peer_entities(&data, "1", "s").len(), MAX_PEERS);
}

// ── Module metadata ──────────────────────────────────────────────────────────

#[tokio::test]
async fn module_metadata() {
    let m = AsnPeers;
    assert!(m.accepts(&Target::new(TargetKind::Asn, "AS13335")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.is_passive());
    assert_eq!(m.name(), "asn_peers");
    assert!(!m.attack_techniques().is_empty());
}
