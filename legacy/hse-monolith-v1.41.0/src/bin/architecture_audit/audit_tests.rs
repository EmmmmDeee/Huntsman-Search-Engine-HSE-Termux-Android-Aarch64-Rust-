use super::*;

fn edge(module: &str, category: &str, consumes: &[&str], pivots_to: &[&str]) -> Edge {
    Edge {
        module: module.to_string(),
        category: Some(category.to_string()),
        consumes: consumes.iter().map(ToString::to_string).collect(),
        pivots_to: Some(pivots_to.iter().map(ToString::to_string).collect()),
    }
}

fn graph(edges: Vec<Edge>, terminal_kinds: &[&str]) -> Graph {
    Graph {
        edges,
        terminal_kinds: terminal_kinds.iter().map(ToString::to_string).collect(),
    }
}

fn module_info(category: &str, cost: &str, passive: bool) -> ModuleInfo {
    ModuleInfo {
        category: Some(category.to_string()),
        cost: Some(cost.to_string()),
        passive,
    }
}

#[test]
fn seed_kinds_matches_the_ported_pythons_nineteen_entries() {
    // The Python original hand-copied exactly these 19 strings as
    // `SEED_KINDS`. Pinning the count here means a future `TargetKind`
    // variant is *noticed* (the count changes) even though `seed_kinds()`
    // itself never needs hand-editing — the point of deriving it.
    let seeds = seed_kinds();
    assert_eq!(seeds.len(), 19, "seed count drifted from the ported baseline: {seeds:?}");
    for expected in [
        "email",
        "username",
        "phone",
        "full_name",
        "domain",
        "ip_address",
        "url",
        "coordinates",
        "mac_address",
        "organisation",
        "address",
        "asn",
        "cidr",
        "crypto_address",
        "abn_acn",
        "api_key",
        "device_id",
        "ssid",
        "tracking_id",
    ] {
        assert!(seeds.contains(expected), "missing seed kind: {expected}");
    }
}

#[test]
fn modules_payload_accepts_the_wrapped_live_endpoint_shape() {
    let raw = r#"{"modules": [{"category": "social", "cost": "free", "passive": false}], "count": 1}"#;
    let payload: ModulesPayload = serde_json::from_str(raw).expect("wrapped shape parses");
    assert_eq!(payload.into_modules().len(), 1);
}

#[test]
fn modules_payload_accepts_a_bare_array_for_from_dir_captures() {
    let raw = r#"[{"category": "social", "cost": "free", "passive": true}]"#;
    let payload: ModulesPayload = serde_json::from_str(raw).expect("bare array shape parses");
    let modules = payload.into_modules();
    assert_eq!(modules.len(), 1);
    assert!(modules[0].passive);
}

#[test]
fn missing_pivots_to_is_a_refusal_not_a_silent_wrong_join() {
    // A graph predating `pivots_to` must be rejected outright — joining on
    // `produces` instead crosses two vocabularies and silently undercounts
    // edges, exactly the mistake the Python original's own docstring
    // confesses making on its first run.
    let bad = Edge {
        module: "m".to_string(),
        category: None,
        consumes: vec![],
        pivots_to: None,
    };
    let err = build_index(&[bad]).expect_err("must refuse a pre-pivots_to graph");
    assert!(err.contains("pivots_to"), "error should name the real cause: {err}");
    assert!(err.contains("Rebuild"), "error should say what to do: {err}");
}

#[test]
fn orphan_kind_excludes_terminal_kinds() {
    // `credential` is produced but consumed by nobody and IS terminal (no
    // TargetKind by design) -> must not appear in orphan_kinds.
    // `only_produced` is produced, consumed by nobody, NOT terminal -> a
    // genuine orphan.
    let g = graph(
        vec![edge("producer", "code", &[], &["credential", "only_produced"])],
        &["credential"],
    );
    let rep = audit(&[], &g).expect("valid graph");
    assert!(!rep.orphan_kinds.contains_key("credential"));
    assert!(rep.orphan_kinds.contains_key("only_produced"));
    assert_eq!(rep.orphan_kinds["only_produced"], vec!["producer".to_string()]);
}

#[test]
fn ungrounded_kind_excludes_seed_kinds() {
    // `email` is consumed but never produced, and IS a legitimate seed kind
    // -> excluded. `mystery` is consumed, never produced, NOT a seed -> a
    // genuine defect.
    let g = graph(
        vec![edge("consumer", "code", &["email", "mystery"], &[])],
        &[],
    );
    let rep = audit(&[], &g).expect("valid graph");
    assert!(!rep.ungrounded_kinds.contains_key("email"));
    assert!(rep.ungrounded_kinds.contains_key("mystery"));
}

#[test]
fn sole_producer_is_reported_only_for_single_source_kinds() {
    let g = graph(
        vec![
            edge("a", "code", &[], &["shared"]),
            edge("b", "code", &[], &["shared"]),
            edge("c", "code", &[], &["unique"]),
        ],
        &[],
    );
    let rep = audit(&[], &g).expect("valid graph");
    assert!(!rep.sole_producers.contains_key("shared"), "produced by two modules");
    assert_eq!(rep.sole_producers.get("unique"), Some(&"c".to_string()));
    assert_eq!(rep.sole_producer_count, rep.sole_producers.len());
}

#[test]
fn duplicate_capability_groups_identical_signatures_and_sorts_members() {
    let g = graph(
        vec![
            edge("zeta", "code", &["email"], &["username"]),
            edge("alpha", "code", &["email"], &["username"]),
            edge("solo", "social", &["email"], &["username"]),
        ],
        &[],
    );
    let rep = audit(&[], &g).expect("valid graph");
    assert_eq!(rep.duplicate_capabilities.len(), 1, "only the 'code' pair shares a signature");
    let (label, members) = &rep.duplicate_capabilities[0];
    assert_eq!(label, "code: email -> username");
    // Members are sorted even though `zeta` was inserted before `alpha`.
    assert_eq!(members, &vec!["alpha".to_string(), "zeta".to_string()]);
}

#[test]
fn duplicate_capability_label_uses_dash_for_empty_consumes_or_pivots() {
    let g = graph(
        vec![
            edge("a", "passive", &[], &[]),
            edge("b", "passive", &[], &[]),
        ],
        &[],
    );
    let rep = audit(&[], &g).expect("valid graph");
    assert_eq!(rep.duplicate_capabilities[0].0, "passive: - -> -");
}

#[test]
fn duplicate_capability_order_is_first_appearance_not_alphabetical() {
    // "zzz" category sorts after "aaa" alphabetically but appears FIRST in
    // the edge list — the Python original's dict preserves insertion order,
    // which is first-appearance order, not sorted order.
    let g = graph(
        vec![
            edge("a1", "zzz", &[], &[]),
            edge("a2", "zzz", &[], &[]),
            edge("b1", "aaa", &[], &["x"]),
            edge("b2", "aaa", &[], &["x"]),
        ],
        &[],
    );
    let rep = audit(&[], &g).expect("valid graph");
    assert_eq!(rep.duplicate_capabilities.len(), 2);
    assert!(
        rep.duplicate_capabilities[0].0.starts_with("zzz"),
        "the zzz signature appeared first in the edge list and must stay first: {:?}",
        rep.duplicate_capabilities
    );
}

#[test]
fn fanout_hotspot_reachability_follows_pivots_to_transitively() {
    // a -> b -> c: a's blast radius is {b, c}, b's is {c}, c's is {}.
    let g = graph(
        vec![
            edge("a", "code", &[], &["k_ab"]),
            edge("b", "code", &["k_ab"], &["k_bc"]),
            edge("c", "code", &["k_bc"], &[]),
        ],
        &[],
    );
    let rep = audit(&[], &g).expect("valid graph");
    let by_module: std::collections::HashMap<&str, usize> =
        rep.fanout_hotspots.iter().map(|h| (h.module.as_str(), h.reaches)).collect();
    assert_eq!(by_module["a"], 2);
    assert_eq!(by_module["b"], 1);
    assert_eq!(by_module["c"], 0);
}

#[test]
fn fanout_hotspot_reachability_terminates_on_a_cycle() {
    // a -> b -> a: must not infinite-loop, and neither reaches itself.
    let g = graph(
        vec![
            edge("a", "code", &["k_ba"], &["k_ab"]),
            edge("b", "code", &["k_ab"], &["k_ba"]),
        ],
        &[],
    );
    let rep = audit(&[], &g).expect("valid graph (terminates)");
    let by_module: std::collections::HashMap<&str, usize> =
        rep.fanout_hotspots.iter().map(|h| (h.module.as_str(), h.reaches)).collect();
    assert_eq!(by_module["a"], 1, "a reaches only b, not itself");
    assert_eq!(by_module["b"], 1, "b reaches only a, not itself");
}

#[test]
fn fanout_hotspots_truncates_to_twelve_highest_reach() {
    let edges: Vec<Edge> = (0..20)
        .map(|i| edge(&format!("m{i}"), "code", &[], &[format!("k{i}").leak()]))
        .collect();
    let g = graph(edges, &[]);
    let rep = audit(&[], &g).expect("valid graph");
    assert_eq!(rep.fanout_hotspots.len(), 12, "must cap at 12 like the Python original");
}

#[test]
fn fanout_hotspots_tie_break_keeps_first_appearance_order() {
    // All three reach 0 modules (no shared kinds) -> a tie. The Python
    // original's `sorted()` is stable, so ties preserve `by_name`'s
    // iteration order = first-appearance-in-edges order.
    let g = graph(
        vec![
            edge("first", "code", &[], &[]),
            edge("second", "code", &[], &[]),
            edge("third", "code", &[], &[]),
        ],
        &[],
    );
    let rep = audit(&[], &g).expect("valid graph");
    let order: Vec<&str> = rep.fanout_hotspots.iter().map(|h| h.module.as_str()).collect();
    assert_eq!(order, vec!["first", "second", "third"]);
}

#[test]
fn python_round_percent_matches_bankers_rounding_on_known_ties() {
    // round(12.5) == 12 (nearest even); round(37.5) == 38 (nearest even).
    assert_eq!(python_round_percent(1, 8), 12);
    assert_eq!(python_round_percent(3, 8), 38);
    // A clean non-tie case as a sanity check.
    assert_eq!(python_round_percent(1, 4), 25);
    assert_eq!(python_round_percent(0, 0), 0, "max(total, 1) guards divide-by-zero");
}

#[test]
fn inventory_counts_category_cost_and_passive_from_modules_not_edges() {
    let modules = vec![
        module_info("social", "free", false),
        module_info("social", "paid", true),
        module_info("code", "free", false),
    ];
    let rep = audit(&modules, &graph(vec![], &[])).expect("valid empty graph");
    assert_eq!(rep.inventory["category:social"], 2);
    assert_eq!(rep.inventory["category:code"], 1);
    assert_eq!(rep.inventory["cost:free"], 2);
    assert_eq!(rep.inventory["cost:paid"], 1);
    assert_eq!(rep.inventory["passive"], 1);
}

#[test]
fn inventory_renders_none_literal_for_a_missing_category_matching_python_fstring() {
    // Python's `f"category:{m.get('category')}"` renders a missing/null
    // category as the literal string "category:None" (Python's `str(None)`),
    // not an empty or omitted key.
    let m = ModuleInfo { category: None, cost: None, passive: false };
    let rep = audit(&[m], &graph(vec![], &[])).expect("valid empty graph");
    assert_eq!(rep.inventory.get("category:None"), Some(&1));
    assert_eq!(rep.inventory.get("cost:None"), Some(&1));
}

#[test]
fn kind_count_is_the_union_of_produced_and_consumed_kinds() {
    let g = graph(
        vec![edge("a", "code", &["only_consumed"], &["only_produced", "shared"])],
        &[],
    );
    let rep = audit(&[], &g).expect("valid graph");
    // only_produced, shared, only_consumed = 3 distinct kinds, even though
    // "shared" only appears on the produced side here.
    assert_eq!(rep.kind_count, 3);
}

#[test]
fn render_matches_the_pythons_exact_padding_widths() {
    // Build the expected lines with the SAME width specifiers `render()`
    // uses, rather than hand-counted literal spaces — a hand count is
    // exactly the class of mistake that bit this port's own byte-layout test
    // in the sibling `gen_oui` port (an arithmetic slip, not a logic bug).
    let g = graph(vec![edge("solo_producer", "code", &[], &["only_kind"])], &[]);
    let rep = audit(&[], &g).expect("valid graph");
    let text = render(&rep);

    let expected_sole_producer_line = format!("  {:<18} only from: solo_producer", "only_kind");
    assert!(
        text.contains(&expected_sole_producer_line),
        "unexpected sole-producer line — want {expected_sole_producer_line:?} in:\n{text}"
    );

    let expected_fanout_line = format!("  {:<22} {:>4} modules  (0% of graph)", "solo_producer", 0);
    assert!(
        text.contains(&expected_fanout_line),
        "unexpected fanout line — want {expected_fanout_line:?} in:\n{text}"
    );
}

#[test]
fn report_json_round_trips_field_order_matches_declaration() {
    // Not a byte-identity claim (see main.rs's doc comment on
    // serde_json::to_string_pretty vs Python's json.dumps) — just that the
    // struct's declared field order, which IS what drives serialisation
    // order, matches the Python original's dict insertion order.
    let g = graph(vec![edge("a", "code", &[], &["k"])], &[]);
    let rep = audit(&[], &g).expect("valid graph");
    let json = serde_json::to_string(&rep).expect("serialises");
    let expected_order = [
        "module_count",
        "terminal_kinds",
        "kind_count",
        "inventory",
        "orphan_kinds",
        "ungrounded_kinds",
        "sole_producer_count",
        "sole_producers",
        "duplicate_capabilities",
        "fanout_hotspots",
    ];
    let mut last_pos = 0;
    for key in expected_order {
        let needle = format!("\"{key}\":");
        let pos = json.find(&needle).unwrap_or_else(|| panic!("missing key {key} in {json}"));
        assert!(pos >= last_pos, "key {key} out of declared order in {json}");
        last_pos = pos;
    }
}
