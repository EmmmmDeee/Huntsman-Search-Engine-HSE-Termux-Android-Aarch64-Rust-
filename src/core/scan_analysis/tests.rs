use super::{AnalysisFinding, ScanAnalysis};

fn sample() -> ScanAnalysis {
    ScanAnalysis {
        scan_id: "abc123".into(),
        model: "qwen2.5:7b".into(),
        created_at: 1_700_000_000,
        summary: "Two exposed accounts found.".into(),
        findings: vec![AnalysisFinding {
            description: "Reused handle across two breached services.".into(),
            severity: 62,
        }],
    }
}

#[test]
fn round_trips_through_json() {
    let original = sample();
    let json = serde_json::to_string(&original).expect("serialize");
    let restored: ScanAnalysis = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.scan_id, original.scan_id);
    assert_eq!(restored.model, original.model);
    assert_eq!(restored.created_at, original.created_at);
    assert_eq!(restored.summary, original.summary);
    assert_eq!(restored.findings.len(), 1);
    assert_eq!(restored.findings[0].severity, 62);
}

#[test]
fn empty_findings_round_trip() {
    let mut analysis = sample();
    analysis.findings.clear();
    let json = serde_json::to_string(&analysis).expect("serialize");
    let restored: ScanAnalysis = serde_json::from_str(&json).expect("deserialize");
    assert!(restored.findings.is_empty());
}
