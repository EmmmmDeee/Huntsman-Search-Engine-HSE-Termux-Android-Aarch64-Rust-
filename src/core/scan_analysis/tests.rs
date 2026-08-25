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
            evidence: vec!["uid-1".into(), "uid-2".into()],
            remediation: "Change the reused password and enable 2FA on both accounts.".into(),
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
fn round_trips_evidence_and_remediation() {
    let original = sample();
    let json = serde_json::to_string(&original).expect("serialize");
    let restored: ScanAnalysis = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.findings[0].evidence, original.findings[0].evidence);
    assert_eq!(
        restored.findings[0].remediation,
        original.findings[0].remediation
    );
}

#[test]
fn an_analysis_persisted_before_grounding_existed_still_deserialises() {
    // `scan_analysis.data_json` is a JSON blob, so rows written by an older
    // build carry no `evidence`/`remediation`. Reading one must yield an
    // analysis whose findings are visibly ungrounded (empty evidence), NOT a
    // failed read of the whole record.
    let legacy = r#"{"scan_id":"old","model":"qwen2.5:7b","created_at":1,
        "summary":"s","findings":[{"description":"d","severity":50}]}"#;
    let restored: ScanAnalysis = serde_json::from_str(legacy).expect("legacy row must still read");
    assert_eq!(restored.findings.len(), 1);
    assert!(
        restored.findings[0].evidence.is_empty(),
        "a pre-grounding finding must read back as ungrounded rather than fabricating citations"
    );
    assert!(restored.findings[0].remediation.is_empty());
}

#[test]
fn empty_findings_round_trip() {
    let mut analysis = sample();
    analysis.findings.clear();
    let json = serde_json::to_string(&analysis).expect("serialize");
    let restored: ScanAnalysis = serde_json::from_str(&json).expect("deserialize");
    assert!(restored.findings.is_empty());
}
