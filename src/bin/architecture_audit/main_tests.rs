use super::*;
use serde_json::json;

/// Cross-validated against the original Python script on this exact fixture
/// (`--from-dir`, both text and `--json` output byte-for-byte / structurally
/// identical, key order aside — see the module doc comment). Deliberately
/// sized so `ModG` reaches exactly 1 of 8 modules (12.5%), landing on the
/// one case where Python's round-half-to-even and Rust's default
/// round-half-away-from-zero disagree.
fn fixture_graph() -> Value {
    json!({
        "terminal_kinds": ["k3"],
        "edges": [
            {"module": "ModA", "category": "OSINT", "consumes": [], "pivots_to": ["k1"]},
            {"module": "ModB", "category": "OSINT", "consumes": ["k1"], "pivots_to": ["k2"]},
            {"module": "ModC", "category": "OSINT", "consumes": ["k1"], "pivots_to": ["k2"]},
            {"module": "ModD", "category": "OSINT", "consumes": [], "pivots_to": ["k3"]},
            {"module": "ModE", "category": "OSINT", "consumes": ["email"], "pivots_to": ["k5"]},
            {"module": "ModF", "category": "OSINT", "consumes": ["k99"], "pivots_to": []},
            {"module": "ModG", "category": "OSINT", "consumes": ["k2"], "pivots_to": ["k4"]},
            {"module": "ModH", "category": "OSINT", "consumes": ["k4"], "pivots_to": []}
        ]
    })
}

fn fixture_modules() -> Vec<Value> {
    serde_json::from_value(json!([
        {"name": "ModA", "category": "OSINT", "cost": "free", "passive": false},
        {"name": "ModB", "category": "OSINT", "cost": "free", "passive": true},
        {"name": "ModC", "category": "OSINT", "cost": "paid", "passive": false},
        {"name": "ModD", "category": "NETINT", "cost": "free", "passive": false},
        {"name": "ModE", "category": "OSINT", "cost": "free", "passive": true},
        {"name": "ModF", "category": "OSINT", "cost": "paid", "passive": false},
        {"name": "ModG", "category": "NETINT", "cost": "free", "passive": true},
        {"name": "ModH", "category": "OSINT", "cost": "free", "passive": false}
    ]))
    .unwrap()
}

#[test]
fn audit_matches_python_golden_report() {
    let rep = audit(&fixture_modules(), &fixture_graph()).unwrap();

    assert_eq!(rep.module_count, 8);
    assert_eq!(rep.kind_count, 7); // k1..k5, k99, email
    assert_eq!(rep.terminal_kinds, vec!["k3"]);

    assert_eq!(
        rep.inventory,
        BTreeMap::from([
            ("category:NETINT".to_string(), 2),
            ("category:OSINT".to_string(), 6),
            ("cost:free".to_string(), 6),
            ("cost:paid".to_string(), 2),
            ("passive".to_string(), 3),
        ])
    );

    // k3 is terminal, so it's excluded from orphan_kinds despite having no consumer.
    assert_eq!(
        rep.orphan_kinds,
        BTreeMap::from([("k5".to_string(), vec!["ModE".to_string()])])
    );
    // "email" is a seed kind, so it's excluded from ungrounded_kinds.
    assert_eq!(
        rep.ungrounded_kinds,
        BTreeMap::from([("k99".to_string(), vec!["ModF".to_string()])])
    );

    assert_eq!(rep.sole_producer_count, 4);
    assert_eq!(
        rep.sole_producers,
        BTreeMap::from([
            ("k1".to_string(), "ModA".to_string()),
            ("k3".to_string(), "ModD".to_string()),
            ("k4".to_string(), "ModG".to_string()),
            ("k5".to_string(), "ModE".to_string()),
        ])
    );

    assert_eq!(
        rep.duplicate_capabilities,
        BTreeMap::from([(
            "OSINT: k1 -> k2".to_string(),
            vec!["ModB".to_string(), "ModC".to_string()]
        )])
    );

    // Descending by reach; ties broken by original edges order (stable
    // sort) — ModB before ModC, then the zero-reach group in D, E, F, H
    // order. ModG's 12.5% rounds to 12 (round-half-to-even), not 13.
    let got: Vec<(&str, usize, i64)> = rep
        .fanout_hotspots
        .iter()
        .map(|h| (h.module.as_str(), h.reaches, h.pct))
        .collect();
    assert_eq!(
        got,
        vec![
            ("ModA", 4, 50),
            ("ModB", 2, 25),
            ("ModC", 2, 25),
            ("ModG", 1, 12),
            ("ModD", 0, 0),
            ("ModE", 0, 0),
            ("ModF", 0, 0),
            ("ModH", 0, 0),
        ]
    );
}

#[test]
fn render_matches_python_golden_text() {
    let rep = audit(&fixture_modules(), &fixture_graph()).unwrap();
    let expected = "\
HSE architecture audit
============================================================
modules: 8   entity kinds in graph: 7
terminal kinds (no TargetKind, always a leaf): k3

inventory:
  category:NETINT          2
  category:OSINT           6
  cost:free                6
  cost:paid                2
  passive                  3

orphan kinds (produced, never consumed): 1
  k5                 produced by: ModE

ungrounded kinds (consumed, never produced, not a seed): 1
  k99                consumed by: ModF

sole producers (single point of failure for a kind): 4
  k1                 only from: ModA
  k3                 only from: ModD
  k4                 only from: ModG
  k5                 only from: ModE

duplicate capability signatures: 1
  ModB, ModC
      OSINT: k1 -> k2

blast radius (modules reachable downstream):
  ModA                      4 modules  (50% of graph)
  ModB                      2 modules  (25% of graph)
  ModC                      2 modules  (25% of graph)
  ModG                      1 modules  (12% of graph)
  ModD                      0 modules  (0% of graph)
  ModE                      0 modules  (0% of graph)
  ModF                      0 modules  (0% of graph)
  ModH                      0 modules  (0% of graph)";
    assert_eq!(render(&rep), expected);
}

#[test]
fn build_rejects_a_graph_that_predates_pivots_to() {
    let edges = vec![json!({"module": "ModX", "consumes": []})];
    let err = build(&edges).unwrap_err();
    assert!(err.contains("predates `pivots_to`"), "got: {err}");
}

#[test]
fn py_display_matches_python_str_semantics() {
    assert_eq!(py_display(None), "None");
    assert_eq!(py_display(Some(&Value::Null)), "None");
    assert_eq!(py_display(Some(&json!("free"))), "free");
    assert_eq!(py_display(Some(&json!(true))), "True");
    assert_eq!(py_display(Some(&json!(false))), "False");
    assert_eq!(py_display(Some(&json!(3))), "3");
}

#[test]
fn is_truthy_matches_python_truthiness() {
    assert!(!is_truthy(None));
    assert!(!is_truthy(Some(&Value::Null)));
    assert!(!is_truthy(Some(&json!(false))));
    assert!(!is_truthy(Some(&json!(0))));
    assert!(!is_truthy(Some(&json!(""))));
    assert!(!is_truthy(Some(&json!([]))));
    assert!(is_truthy(Some(&json!(true))));
    assert!(is_truthy(Some(&json!(1))));
    assert!(is_truthy(Some(&json!("x"))));
    assert!(is_truthy(Some(&json!(["x"]))));
}
