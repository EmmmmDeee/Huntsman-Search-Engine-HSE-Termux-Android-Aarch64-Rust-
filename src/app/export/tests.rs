use super::dossier::join_or_dash;
use super::renderers::{
    IssueInputs, KeyPoolSummary, SEV_CRITICAL, SEV_WARNING, SystemDebugInputs, build_scan_report,
    detect_issues, entities_to_csv, extract_au_location_fix, render_csv, render_debug_bundle,
    render_full, render_gexf, render_json, render_report, render_system_debug_bundle,
};
use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};
use crate::storage::Store;

#[test]
fn exports_never_brand_a_non_complete_scan_as_complete() {
    // An export of an aborted / failed / still-running scan holds only what was
    // found before the stop. Labelling it "complete" tells the operator that a
    // missing finding is a real negative, when it may simply be work that never
    // ran — the one claim an evidentiary artifact must never make falsely.
    // Both the dossier and the debug bundle must agree, since they are the two
    // artifacts an operator hands on as the record of a scan.
    for (status, id, dossier_tag, bundle_tag) in [
        (
            ScanStatus::Aborted,
            "scan-st-aborted",
            "partial, aborted, unredacted",
            "partial aborted scan snapshot",
        ),
        (
            ScanStatus::Failed,
            "scan-st-failed",
            "partial, failed, unredacted",
            "partial failed scan snapshot",
        ),
        (
            ScanStatus::Running,
            "scan-st-running",
            "partial, live, unredacted",
            "partial live scan snapshot",
        ),
        (
            ScanStatus::Complete,
            "scan-st-complete",
            "complete, unredacted",
            "complete scan snapshot",
        ),
    ] {
        let dir = tempfile::tempdir().expect("should succeed");
        let db = dir.path().join(format!("{id}.db"));
        let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");
        let target = Target::new(TargetKind::FullName, "Jordan Avery");
        let mut scan = Scan::new(id, target);
        scan.status = status;
        store.upsert_scan(&scan).expect("should succeed");

        let dossier = render_full(&store, id).expect("should succeed");
        assert!(
            dossier.contains(&format!("HUNTSMAN FULL DOSSIER — {dossier_tag}")),
            "{status:?} dossier must be labelled {dossier_tag:?}"
        );
        let bundle = render_debug_bundle(&store, id).expect("should succeed");
        assert!(
            bundle.contains(&format!("=== HUNTSMAN DEBUG BUNDLE — {bundle_tag} ===")),
            "{status:?} bundle must be labelled {bundle_tag:?}"
        );
        if status != ScanStatus::Complete {
            assert!(
                !dossier.contains("HUNTSMAN FULL DOSSIER — complete, unredacted"),
                "{status:?} dossier must not also claim completeness"
            );
            assert!(
                !bundle.contains("=== HUNTSMAN DEBUG BUNDLE — complete scan snapshot ==="),
                "{status:?} bundle must not also claim completeness"
            );
        }
    }
}

#[test]
fn render_json_kind_is_a_uniform_string_including_for_other_variant() {
    // Regression (critical audit): render_json called serde_json::to_value(e)
    // directly on the whole Entity. serde's default externally-tagged
    // representation renders EntityKind's 20 unit variants as a bare string
    // ("email") but the Other(String) catch-all as a nested object
    // ({"other":"iban"}) -- so the exported `kind` field's JSON TYPE silently
    // switched depending on which kind an entity happened to be. Other is not
    // an edge case: it's the real representation for IBANs, AT-Proto DIDs,
    // nostr keys, app-link identifiers, and more. Any consumer treating
    // `kind` as always-a-string (jq -r '.[].kind', a typed deserializer)
    // broke on exactly those entities while working for the other 20 kinds.
    // CSV/GEXF sidestep this by using e.kind.to_string() (the Display impl,
    // always a plain string) -- JSON was the sole outlier renderer.
    use crate::core::entity::{Entity, EntityKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("kind_test.db");
    let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");
    let target = Target::new(TargetKind::Email, "seed@example.com");
    let scan = Scan::new("scan-kind", target);
    store.upsert_scan(&scan).expect("should succeed");
    let ordinary = Entity::new(EntityKind::Email, "seed@example.com", 0.9, "scan-kind");
    let other = Entity::new(
        EntityKind::Other("iban".into()),
        "GB33BUKB20201555555555",
        0.8,
        "scan-kind",
    );
    store
        .upsert_entities_batch(&[ordinary, other])
        .expect("should succeed");

    let body = render_json(&store, "scan-kind", false).expect("should succeed");
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&body).expect("valid json");
    for entity in &parsed {
        assert!(
            entity["kind"].is_string(),
            "every entity's `kind` field must be a plain JSON string, got: {entity}"
        );
    }
    let iban_kind = parsed
        .iter()
        .find(|e| e["value"] == "GB33BUKB20201555555555")
        .expect("the Other-kind entity is present")["kind"]
        .as_str()
        .expect("kind is a string")
        .to_string();
    assert_eq!(iban_kind, "other:iban");
}

#[test]
fn render_full_dumps_every_field_and_provenance() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("full_test.db");
    let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");

    let target = Target::new(TargetKind::Email, "vanamill@hotmail.com");
    let scan = Scan::new("scan-full", target);
    store.upsert_scan(&scan).expect("should succeed");

    // A password entity carrying full provenance + a raw source field.
    let mut e = Entity::new(EntityKind::Password, "thelord", 0.75, "scan-full");
    e.tag("breach");
    e.add_evidence(
        Evidence::new("see_know", "SeekNow record from Snusbase")
            .with_attr("provider", "see-know")
            .with_attr("api_key_origin", "see-know:seek-62650f9a…0fd0a4")
            .with_attr("via_endpoint", "search")
            .with_attr("source", "Snusbase")
            .with_attr("username", "3toadsloth"),
    );
    // An Email whose raw source spelling (mixed-case) DIVERGES from the
    // normalised `value` — exercises the "nothing omitted" promise for the
    // entity's own top-level `raw_value`/`observed_at`/`uid` fields, which the
    // Password fixture above (a passthrough-normalise kind) can't.
    let mut mixed = Entity::new(EntityKind::Email, "TestUser@Example.COM", 0.6, "scan-full");
    mixed.observed_at = 1_700_000_000;
    store
        .upsert_entities_batch(&[e, mixed])
        .expect("should succeed");

    let out = render_full(&store, "scan-full").expect("should succeed");
    // Header + provenance roll-up.
    assert!(out.contains("HUNTSMAN FULL DOSSIER"));
    assert!(out.contains("providers      : see-know"));
    assert!(out.contains("api key origins: see-know:seek-62650f9a…0fd0a4"));
    assert!(out.contains("sources/sites  : Snusbase"));
    // The entity, its value, and EVERY evidence attribute verbatim.
    assert!(out.contains("password = thelord"));
    assert!(out.contains("api_key_origin = see-know:seek-62650f9a…0fd0a4"));
    assert!(out.contains("via_endpoint = search"));
    assert!(out.contains("username = 3toadsloth"));
    // "Nothing omitted": the entity's own top-level fields must all appear —
    // the normalised value, its DIVERGENT raw spelling, and the observed_at
    // timestamp (raw + compact-UTC), none of which render_full carried before.
    assert!(
        out.contains("email = testuser@example.com"),
        "normalised value"
    );
    assert!(
        out.contains("raw_value=TestUser@Example.COM"),
        "divergent raw_value must be surfaced verbatim: {out}"
    );
    assert!(
        out.contains("observed_at=1700000000"),
        "raw observed_at timestamp must appear"
    );
    assert!(
        out.contains("20231114T221320Z"),
        "observed_at must also render as a compact-UTC string"
    );
    assert!(out.contains("uid="), "the SHA-256 uid must appear");
    // Exposure Index headline + breakdown mirror the live dossier — the on-disk
    // full dossier opens with the same operator-facing verdict.
    assert!(out.contains("── EXPOSURE INDEX ──"));
    assert!(out.contains("Exposure "));
}

#[test]
fn render_full_carries_generation_and_every_per_evidence_qualifier() {
    // Regression guard for the "every field, fully unredacted" contract: the
    // ENTITIES section previously dropped the entity's `generation` (pivot
    // distance from the seed, which the web Browse pane already showed) and
    // three per-evidence fields — `recorded_at`, `is_inferred`, and
    // `verification` — so an INFERRED derivation rendered identically to a
    // direct observation and an account attribution gave no basis.
    use crate::core::entity::{Entity, EntityKind, Evidence, VerificationMethod};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("qualifiers_test.db");
    let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");

    let target = Target::new(TargetKind::Username, "jmally");
    let scan = Scan::new("scan-qual", target);
    store.upsert_scan(&scan).expect("should succeed");

    let mut e = Entity::new(EntityKind::Person, "James Mally", 0.6, "scan-qual");
    // Two pivots out from the seed — must not read as operator input.
    e.generation = 2;
    let mut inferred = Evidence::new("name_intel", "Name permuted from username")
        .with_verification(VerificationMethod::Unverified)
        .with_inferred(true);
    inferred.recorded_at = 1_700_000_000;
    e.add_evidence(inferred);
    store.upsert_entities_batch(&[e]).expect("should succeed");

    let out = render_full(&store, "scan-qual").expect("should succeed");
    assert!(
        out.contains("generation=2"),
        "entity generation (hops from seed) must be surfaced: {out}"
    );
    assert!(
        out.contains("(inferred)"),
        "an inferred derivation must be marked, not read as an observation: {out}"
    );
    assert!(
        out.contains("verification = Unverified"),
        "the account-attribution basis must be surfaced: {out}"
    );
    assert!(
        out.contains("recorded_at = 1700000000"),
        "each evidence record's own timestamp must appear: {out}"
    );
    assert!(
        out.contains("20231114T221320Z"),
        "recorded_at must also render as a compact-UTC string: {out}"
    );
    // `name_intel` is an enrichment-only source, so it must ALSO still carry the
    // pre-existing non-corroborating marker — the new qualifiers append to it
    // rather than displace it.
    assert!(
        out.contains("(non-corroborating"),
        "the non-corroborating marker must survive alongside the new qualifiers: {out}"
    );
}

#[test]
fn render_full_resolves_relation_labels_and_reports_all_module_counts() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::relation::{Relation, RelationKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("full_rel.db");
    let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");

    let mut scan = Scan::new("scan-fr", Target::new(TargetKind::FullName, "Jordan Avery"));
    scan.modules_run = 12;
    scan.modules_timed_out = 3;
    scan.modules_skipped = 1;
    scan.modules_cached = 2;
    store.upsert_scan(&scan).expect("should succeed");

    let email = Entity::new(EntityKind::Email, "jordan@real.com", 0.85, "scan-fr");
    let user = Entity::new(EntityKind::Username, "jordanavery", 0.80, "scan-fr");
    store
        .upsert_entities_batch(&[email.clone(), user.clone()])
        .expect("should succeed");
    store
        .upsert_relation(&Relation::new(
            &email.uid,
            &user.uid,
            RelationKind::AliasOf,
            0.8,
            "scan-fr",
        ))
        .expect("should succeed");

    let out = render_full(&store, "scan-fr").expect("should succeed");
    // Relation endpoints resolve to `value (kind)`, not opaque hex→hex.
    assert!(out.contains("── RELATIONS ──"));
    assert!(
        out.contains("jordan@real.com (email)"),
        "from-endpoint must resolve to value (kind): {out}"
    );
    assert!(
        out.contains("jordanavery (username)"),
        "to-endpoint must resolve to value (kind)"
    );
    // Full module accounting, including the timed-out/skipped/cached counts.
    assert!(
        out.contains("modules    :"),
        "header must carry module accounting"
    );
    assert!(
        out.contains("3 timed out"),
        "timed-out count must be disclosed"
    );
    assert!(out.contains("1 skipped"));
    assert!(out.contains("2 cached"));
}

#[test]
fn render_full_explains_the_gap_between_corroboration_and_source_count() {
    // Regression: `corroboration` (a raw per-module magnitude) and
    // `source_count` (the distinct-source count that actually drives c_eff)
    // can diverge, and a reader of the debug bundle / full dossier had no way
    // to tell from the text alone — the two numbers look interchangeable
    // sitting next to each other. When they diverge, an explanatory note and
    // per-evidence markers must make the real driver of c_eff explicit.
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("source_count_test.db");
    let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");

    let target = Target::new(TargetKind::Address, "1 Example St");
    let scan = Scan::new("scan-sc", target);
    store.upsert_scan(&scan).expect("should succeed");

    let mut e = Entity::new(EntityKind::Address, "1 Example St", 0.82, "scan-sc");
    e.corroboration = 8;
    e.add_evidence(Evidence::new("oathnet_pro", "Breach on ebay.com"));
    e.add_evidence(Evidence::new(
        "geo_normalize",
        "Address parse + normalization",
    ));
    store.upsert_entities_batch(&[e]).expect("should succeed");

    let out = render_full(&store, "scan-sc").expect("should succeed");
    assert!(
        out.contains("corroboration=8") && out.contains("source_count=1"),
        "both counters must be visible and distinct: {out}"
    );
    assert!(
        out.contains("note: c_eff is driven by source_count="),
        "the divergence must be explained inline, not left for the reader to guess: {out}"
    );
    assert!(
        out.contains("[geo_normalize] Address parse + normalization  (non-corroborating"),
        "the non-corroborating evidence source must be marked as such: {out}"
    );
    assert!(
        !out.contains("[oathnet_pro] Breach on ebay.com  (non-corroborating"),
        "a genuinely corroborating source must NOT be marked non-corroborating: {out}"
    );
}

#[test]
fn structured_exports_quarantine_candidates_but_full_retains_them() {
    // H1: the CSV/JSON/GEXF exports used to ship the quarantined `candidate`
    // rows (non-subject breach co-occurrence strangers) even though the
    // self-audit promised they were "excluded from export". The structured
    // exports now default to the subject's confirmed footprint, while the
    // nothing-hidden `full` bundle still retains everything for transparency.
    use crate::core::entity::{Entity, EntityKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("quarantine_test.db");
    let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");

    let target = Target::new(TargetKind::Email, "subject@example-real.com");
    let scan = Scan::new("scan-q", target);
    store.upsert_scan(&scan).expect("should succeed");

    let confirmed = Entity::new(EntityKind::Email, "subject@example-real.com", 0.8, "scan-q");
    let mut stranger = Entity::new(EntityKind::Person, "Random Stranger", 0.25, "scan-q");
    stranger.demote_to_candidate(); // tags `candidate`
    store
        .upsert_entities_batch(&[confirmed, stranger])
        .expect("should succeed");

    for body in [
        render_csv(&store, "scan-q", false).expect("should succeed"),
        render_json(&store, "scan-q", false).expect("should succeed"),
        render_gexf(&store, "scan-q", false).expect("should succeed"),
    ] {
        assert!(
            body.contains("subject@example-real.com"),
            "the confirmed subject entity is exported"
        );
        assert!(
            !body.contains("Random Stranger"),
            "the quarantined candidate must NOT appear in a structured export"
        );
    }

    // The full (nothing-hidden) bundle still carries the quarantined row.
    let full = render_full(&store, "scan-q").expect("should succeed");
    assert!(
        full.contains("Random Stranger"),
        "the full bundle retains quarantined rows for transparency"
    );
}

#[test]
fn debug_bundle_includes_dossier_sequence_and_audit() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::event::{Event, EventKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("debug_test.db");
    let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");

    let target = Target::new(TargetKind::Email, "isaac@example-real.com");
    let scan = Scan::new("scan-dbg", target);
    store.upsert_scan(&scan).expect("should succeed");
    store
        .upsert_entities_batch(&[Entity::new(
            EntityKind::Email,
            "isaac@example-real.com",
            0.8,
            "scan-dbg",
        )])
        .expect("should succeed");
    // A recorded sequence including an exclusion (so the audit ledger fires).
    store
        .insert_event(&Event::new(
            "scan-dbg",
            EventKind::ModuleStart {
                module: "hibp".into(),
            },
        ))
        .expect("should succeed");
    store
        .insert_event(&Event::new(
            "scan-dbg",
            EventKind::EntityExcluded {
                kind: "username".into(),
                value: "stranger".into(),
                reason: "identity_mismatch".into(),
            },
        ))
        .expect("should succeed");

    let out = render_debug_bundle(&store, "scan-dbg").expect("should succeed");
    // The pillars are all present in the single artifact.
    assert!(out.contains("HUNTSMAN DEBUG BUNDLE"));
    // Environment fingerprint (secret-free) frames the run.
    assert!(out.contains("── ENVIRONMENT"));
    assert!(out.contains("hse_version :"));
    assert!(out.contains("keys_present:"));
    // The full module-file roster is present — every module-file the binary
    // carries is accounted for, named, even if it never dispatched here.
    assert!(out.contains("modules     :"));
    assert!(
        out.contains("hibp"),
        "ENVIRONMENT module roster must name every registered module"
    );
    // The source-file manifest incorporates EVERY file, not just modules.
    assert!(out.contains("── SOURCE FILES"));
    assert!(out.contains("src/lib.rs"));
    assert!(out.contains("src/app/export/mod.rs"));
    assert!(out.contains("HUNTSMAN FULL DOSSIER")); // §1 embeds render_full
    assert!(out.contains("── EXPOSURE INDEX")); // §1 headline mirrors live dossier
    assert!(out.contains("── CORRELATIONS")); // §2
    assert!(out.contains("SCAN SEQUENCE")); // §3 header (plain ASCII, no box glyphs)
    assert!(out.contains("\"kind\":\"module_start\"")); // events as structured JSON lines
    assert!(out.contains("\"module\":\"hibp\"")); // module_start rendered in the sequence
    assert!(out.contains("\"kind\":\"entity_excluded\"")); // exclusion event present
    assert!(out.contains("\"reason\":\"identity_mismatch\"")); // …with its reason preserved
    assert!(out.contains("── SELF-AUDIT")); // §4
    assert!(out.contains("score      :"));
    assert!(out.contains("exclusions : identity_mismatch×1")); // ledger folded in
}

#[test]
fn event_log_renders_a_readable_aligned_timeline() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::event::{Event, EventKind};
    use crate::core::tags::CANDIDATE;

    let mut cand = Entity::new(EntityKind::Password, "hunter2", 0.25, "s");
    cand.tag(CANDIDATE);
    let evs = vec![
        Event::new(
            "s",
            EventKind::ScanStart {
                target_kind: "username".into(),
                target_value: "alameddine".into(),
            },
        ),
        Event::new(
            "s",
            EventKind::ModuleStart {
                module: "dehashed".into(),
            },
        ),
        Event::new(
            "s",
            EventKind::ModuleDone {
                module: "dehashed".into(),
                found: 0,
            },
        ),
        Event::new(
            "s",
            EventKind::ModuleSkipped {
                module: "psbdmp".into(),
                reason: "capability-quarantined".into(),
                class: Some(crate::core::event::SkipClass::Unavailable),
            },
        ),
        Event::new(
            "s",
            EventKind::EntityFound {
                entity: Entity::new(EntityKind::Email, "a@b.com", 0.90, "s"),
            },
        ),
        Event::new("s", EventKind::EntityFound { entity: cand }),
        Event::new(
            "s",
            EventKind::EntityExcluded {
                kind: "username".into(),
                value: "stranger".into(),
                reason: "identity_mismatch".into(),
            },
        ),
        Event::new(
            "s",
            EventKind::ScanComplete {
                scan_id: "s".into(),
                entity_count: 2,
                status: crate::core::scan::ScanStatus::Complete,
            },
        ),
    ];
    let out = crate::app::export::render_event_log(&evs);

    // Structured JSON lines: one parseable JSON object per event, in order, with
    // no decorative header, histogram, box-drawing, or status glyphs.
    assert!(
        !out.contains('●')
            && !out.contains('▶')
            && !out.contains('✔')
            && !out.contains('⊘')
            && !out.contains('─'),
        "the structured log must carry no status/box glyphs, got:\n{out}"
    );
    let lines: Vec<serde_json::Value> = out
        .lines()
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("line is not JSON: {l:?} — {e}"))
        })
        .collect();
    assert_eq!(lines.len(), 8, "one JSON object per event");

    // Every object leads with time/level/kind.
    for (v, ev) in lines.iter().zip(&evs) {
        assert!(v["time"].is_string());
        assert_eq!(v["level"], "info");
        assert_eq!(v["kind"], ev.kind.event_type_str());
    }

    // scan_start carries the target.
    assert_eq!(lines[0]["kind"], "scan_start");
    assert_eq!(lines[0]["target_kind"], "username");
    assert_eq!(lines[0]["target_value"], "alameddine");
    // module_start / module_done / module_skipped keep their concise fields.
    assert_eq!(lines[1]["module"], "dehashed");
    assert_eq!(lines[2]["found"], 0);
    assert_eq!(lines[3]["reason"], "capability-quarantined");
    // entity_found reduces the Entity to a handful of fields; the candidate flag
    // is a boolean, not prose.
    assert_eq!(lines[4]["entity_kind"], "email");
    assert_eq!(lines[4]["value"], "a@b.com");
    assert_eq!(lines[4]["confidence"], 0.9);
    assert_eq!(lines[4]["candidate"], false);
    assert_eq!(lines[5]["candidate"], true);
    // entity_excluded renames its `kind` to `entity_kind` so it never collides
    // with the line's top-level `kind`, and preserves the reason.
    assert_eq!(lines[6]["kind"], "entity_excluded");
    assert_eq!(lines[6]["entity_kind"], "username");
    assert_eq!(lines[6]["value"], "stranger");
    assert_eq!(lines[6]["reason"], "identity_mismatch");
    // scan_complete reports status + entity count as data.
    assert_eq!(lines[7]["kind"], "scan_complete");
    assert_eq!(lines[7]["status"], "complete");
    assert_eq!(lines[7]["entities"], 2);

    println!("\n===== render_event_log sample =====\n{out}=====");
}

#[test]
fn debug_bundle_correlation_histogram_surfaces_a_dominant_rule() {
    use crate::core::correlator::{Correlation, Severity};
    use crate::core::entity::{Entity, EntityKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("debug_histo.db");
    let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");

    let scan = Scan::new("scan-histo", Target::new(TargetKind::Email, "x@y.com"));
    store.upsert_scan(&scan).expect("should succeed");
    store
        .upsert_entities_batch(&[Entity::new(EntityKind::Email, "x@y.com", 0.8, "scan-histo")])
        .expect("should succeed");
    // Three AU-099 hits and one AU-076 hit — AU-099 dominates the histogram.
    for i in 0..3 {
        store
            .upsert_correlation(&Correlation::new(
                "AU-099",
                "Coordinate reverse-geocode",
                Severity::Medium,
                format!("fix {i}"),
                vec![format!("u{i}")],
                "scan-histo",
                0,
            ))
            .expect("should succeed");
    }
    store
        .upsert_correlation(&Correlation::new(
            "AU-076",
            "Email-username local-part identity bridge",
            Severity::High,
            "bridge".to_string(),
            vec!["u9".to_string()],
            "scan-histo",
            0,
        ))
        .expect("should succeed");

    let out = render_debug_bundle(&store, "scan-histo").expect("should succeed");
    assert!(
        out.contains("rule histogram"),
        "the debug bundle must include a correlation rule histogram"
    );
    // The dominant rule (3 of 4 = 75%) is rendered with its share.
    assert!(
        out.contains("AU-099") && out.contains("75.0%"),
        "the histogram must show the dominant rule's share: {out}"
    );
    // Histogram is frequency-ordered: AU-099 (3) appears before AU-076 (1).
    let hi = out.find("rule histogram").expect("should succeed");
    let tail = &out[hi..];
    assert!(
        tail.find("AU-099").expect("should succeed") < tail.find("AU-076").expect("should succeed"),
        "histogram must be ordered by frequency (AU-099 before AU-076)"
    );
}

#[test]
fn debug_bundle_labels_a_true_au059_synergy_fix_distinctly_from_single_signal() {
    // H2 (debug-bundle review, 2026-07-06): `render_debug_bundle` used to label
    // EVERY non-null `extract_au_location_fix` result "(AU-059)" and read
    // `synergy_confidence`/`severity` via `.unwrap_or` defaults, even when the
    // JSON was actually the coarser single-signal fallback shape (which has no
    // `synergy_confidence`/`severity` fields at all — those default to 0.0/"").
    // This test drives the TRUE synergy shape: ≥2 AU person-anchored
    // coordinates across ≥2 orthogonal source classes, so `au059_synergy_fix`
    // fires for real and the rendered line must say "(AU-059)", include the
    // `radius_km` the old code silently dropped, and carry a non-zero
    // synergy_confidence/severity.
    use crate::core::correlator::{Correlation, Severity};
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let dir = tempfile::tempdir().expect("should succeed");
    let store = Store::open(
        dir.path()
            .join("au059.db")
            .to_str()
            .expect("should succeed"),
    )
    .expect("should succeed");
    let scan = Scan::new(
        "scan-au059",
        Target::new(TargetKind::Email, "au059@example-real.com"),
    );
    store.upsert_scan(&scan).expect("should succeed");

    let sighting = |source: &str, lat: f64, lon: f64, conf: f64| {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            format!("{lat:.4},{lon:.4}"),
            conf,
            "scan-au059",
        );
        e.tag("au-state:NSW");
        e.tag("country:AU");
        e.add_evidence(Evidence::new(source, "fixture"));
        e
    };
    // Two orthogonal source classes (PhotoGps + WifiSensor) agreeing near Sydney.
    let entities = vec![
        sighting("exif_geo", -33.8688, 151.2093, 0.85),
        sighting("wigle", -33.8700, 151.2100, 0.78),
    ];
    let uids: Vec<String> = entities.iter().map(|e| e.uid.clone()).collect();
    store
        .upsert_entities_batch(&entities)
        .expect("should succeed");
    store
        .upsert_correlation(&Correlation::new(
            "AU-059",
            "AU cross-seed geo-synergy",
            Severity::Medium,
            "synergy fixture".to_string(),
            uids,
            "scan-au059",
            0,
        ))
        .expect("should succeed");

    let out = render_debug_bundle(&store, "scan-au059").expect("should succeed");
    assert!(
        out.contains("BEST AU LOCATION FIX (AU-059)"),
        "a true multi-class synergy fix must be labelled AU-059: {out}"
    );
    assert!(
        !out.contains("BEST AU LOCATION FIX (single-signal)"),
        "must not ALSO render the single-signal label: {out}"
    );
    // Scope the radius check to the fix line itself — the unrelated exposure-index
    // "geo : N fix(es) / M source(s) · spread NN km · ..." line also contains "km",
    // so a bare `out.contains("km")` would pass even if the fix line omitted it.
    let idx = out
        .find("BEST AU LOCATION FIX (AU-059)")
        .expect("AU-059 fix line must be present");
    let fix_line = &out[idx..(idx + 300).min(out.len())];
    assert!(
        fix_line.contains(" km ·"),
        "the fix line must include the radius_km field: {fix_line}"
    );
    assert!(
        fix_line.contains("synergy_conf=") && !fix_line.contains("synergy_conf=0.00"),
        "a real synergy fix must carry a non-zero synergy confidence: {fix_line}"
    );
}

#[test]
fn debug_bundle_single_signal_fallback_fix_is_not_mislabelled_au059() {
    // The mirror case: a lone AU coordinate is below AU-059's ≥2-signal gate,
    // so `extract_au_location_fix` returns the coarser single-signal fallback
    // shape (`confidence`/`basis`, no `synergy_confidence`/`severity`). The
    // pre-fix code still printed "(AU-059)" for this shape and read its
    // (absent) `synergy_confidence` as a silently-defaulted 0.00 — overstating
    // a single hardcoded/low-rigour signal as a corroborated cross-seed fix.
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let dir = tempfile::tempdir().expect("should succeed");
    let store = Store::open(
        dir.path()
            .join("single_signal.db")
            .to_str()
            .expect("should succeed"),
    )
    .expect("should succeed");
    let scan = Scan::new(
        "scan-single",
        Target::new(TargetKind::Email, "single@example-real.com"),
    );
    store.upsert_scan(&scan).expect("should succeed");

    let mut coord = Entity::new(
        EntityKind::Coordinates,
        "-33.8688,151.2093",
        0.85,
        "scan-single",
    );
    coord.tag("au-state:NSW");
    coord.tag("country:AU");
    coord.add_evidence(Evidence::new("exif_geo", "fixture"));
    store
        .upsert_entities_batch(&[coord])
        .expect("should succeed");
    // No AU-059 correlation stored — a lone coordinate never fires the rule.

    let out = render_debug_bundle(&store, "scan-single").expect("should succeed");
    assert!(
        out.contains("BEST AU LOCATION FIX (single-signal)"),
        "a lone coordinate must fall back to the single-signal label: {out}"
    );
    assert!(
        !out.contains("BEST AU LOCATION FIX (AU-059)"),
        "a single-signal fix must NOT be mislabelled AU-059: {out}"
    );
    assert!(
        out.contains("basis=confirmed coordinate"),
        "the single-signal line must surface its basis: {out}"
    );
    assert!(
        !out.contains("synergy_conf="),
        "the single-signal shape has no synergy_confidence field to render: {out}"
    );
}

#[test]
fn debug_bundle_is_deterministic() {
    // DETERMINISM REQUIREMENT (evidence, not assertion): re-exporting the
    // same immutable stored scan must be byte-identical, so the artifact is
    // diffable across runs/time. This is the experiment that proves it.
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::event::{Event, EventKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let store = Store::open(dir.path().join("det.db").to_str().expect("should succeed"))
        .expect("should succeed");
    let scan = Scan::new(
        "scan-det",
        Target::new(TargetKind::Email, "a@example-real.com"),
    );
    store.upsert_scan(&scan).expect("should succeed");
    // Several entities + events so any unstable iteration order would surface.
    store
        .upsert_entities_batch(&[
            Entity::new(EntityKind::Email, "a@example-real.com", 0.8, "scan-det"),
            Entity::new(EntityKind::Username, "alpha", 0.6, "scan-det"),
            Entity::new(EntityKind::Username, "bravo", 0.6, "scan-det"),
            Entity::new(EntityKind::Domain, "example-real.com", 0.5, "scan-det"),
        ])
        .expect("should succeed");
    for m in ["hibp", "gravatar", "crtsh"] {
        store
            .insert_event(&Event::new(
                "scan-det",
                EventKind::ModuleStart { module: m.into() },
            ))
            .expect("should succeed");
    }
    let a = render_debug_bundle(&store, "scan-det").expect("should succeed");
    let b = render_debug_bundle(&store, "scan-det").expect("should succeed");
    assert_eq!(
        a, b,
        "debug bundle is not byte-deterministic across exports"
    );
    // And it carries no wall-clock generation timestamp that would break that.
    assert!(!a.contains("generated_at"));
}

#[test]
fn export_formats_determinism_audit() {
    // DETERMINISM REQUIREMENT: evidence (not assertion) that every export
    // format is byte-reproducible for a fixed store — so exports are diffable
    // across runs/time — with `report.json`'s `exported_at` as the ONE
    // documented exception. If a future change adds non-determinism anywhere
    // else, this fails.
    use crate::core::entity::{Entity, EntityKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let store = Store::open(
        dir.path()
            .join("audit.db")
            .to_str()
            .expect("should succeed"),
    )
    .expect("should succeed");
    let scan = Scan::new(
        "scan-au",
        Target::new(TargetKind::Email, "z@example-real.com"),
    );
    store.upsert_scan(&scan).expect("should succeed");
    store
        .upsert_entities_batch(&[
            Entity::new(EntityKind::Email, "z@example-real.com", 0.8, "scan-au"),
            Entity::new(EntityKind::Username, "zeta", 0.6, "scan-au"),
            Entity::new(EntityKind::Domain, "example-real.com", 0.5, "scan-au"),
        ])
        .expect("should succeed");

    use crate::core::error::Result;
    type StoreFmt = fn(&Store, &str, bool) -> Result<String>;
    type PortFmt = fn(&dyn crate::core::port::StoragePort, &str) -> Result<String>;

    // Byte-reproducible formats (Store-typed). Exercised in both the plain and
    // `--redact` modes — redaction must be deterministic too.
    let store_fmts: &[(&str, StoreFmt)] = &[
        ("json", render_json),
        ("csv", render_csv),
        ("gexf", render_gexf),
    ];
    for (name, render) in store_fmts {
        for redact in [false, true] {
            let a = render(&store, "scan-au", redact).expect("should succeed");
            let b = render(&store, "scan-au", redact).expect("should succeed");
            assert_eq!(
                a, b,
                "format `{name}` (redact={redact}) is not byte-deterministic"
            );
        }
    }
    // full + debug take `&dyn StoragePort`.
    let port_fmts: &[(&str, PortFmt)] = &[("full", render_full), ("debug", render_debug_bundle)];
    for (name, render) in port_fmts {
        let a = render(&store, "scan-au").expect("should succeed");
        let b = render(&store, "scan-au").expect("should succeed");
        assert_eq!(a, b, "format `{name}` is not byte-deterministic");
    }

    // report.json: deterministic EXCEPT the documented `exported_at`. Compare
    // structurally with that one field removed — robust regardless of whether
    // the two renders happened to land in the same wall-clock second.
    let mut r1: serde_json::Value =
        serde_json::from_str(&render_report(&store, "scan-au", false).expect("should succeed"))
            .expect("should succeed");
    let mut r2: serde_json::Value =
        serde_json::from_str(&render_report(&store, "scan-au", false).expect("should succeed"))
            .expect("should succeed");
    assert!(
        r1.get("exported_at").is_some(),
        "exported_at must be present"
    );
    for r in [&mut r1, &mut r2] {
        r.as_object_mut()
            .expect("should succeed")
            .remove("exported_at");
    }
    assert_eq!(
        r1, r2,
        "report.json varies in a field OTHER than the documented `exported_at`"
    );

    // snake.svg — the sixth served export route (`GET .../snake.svg`), previously absent from
    // this audit even though the comment above claims EVERY export format. It is built from the
    // stored entities rather than rendered through a `Store`/`StoragePort` fn, so it needs its
    // own check rather than a row in either table. Its node order comes from a `BTreeMap` and its
    // lookup maps are read-only, so it should already be reproducible — this makes that a
    // guarded fact instead of an unverified one, and would catch a future change that fed
    // `HashMap`/`HashSet` iteration into the geometry or the element order.
    let svg_entities = store.entities_for_scan("scan-au").expect("should succeed");
    let centre_uid = svg_entities
        .first()
        .map(|e| e.uid.clone())
        .expect("the audit fixture seeds entities");
    let svg = |size: f64| {
        crate::core::snake_graph::SnakeGraph::build(&centre_uid, &svg_entities, &[], 2).to_svg(size)
    };
    assert_eq!(
        svg(400.0),
        svg(400.0),
        "format `snake.svg` is not byte-deterministic"
    );
}

#[test]
fn explicit_scan_id_is_existence_checked_no_silent_empty_export() {
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("export_test.db");
    let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");

    // Unknown id -> a clear "not found" error (no silent empty export). The
    // existence check now lives in the shared `cli::resolve_scan_id`.
    let err = crate::app::runtime::resolve_scan_id(&store, "no-such-scan")
        .expect_err("should be an error")
        .to_string();
    assert!(
        err.contains("not found"),
        "expected not-found error, got: {err}"
    );

    // After a *complete* scan exists, resolution returns the id.
    let target = Target::new(TargetKind::Email, "x@b.com");
    let mut scan = Scan::new("scan-present", target);
    scan.status = ScanStatus::Complete;
    store.upsert_scan(&scan).expect("should succeed");
    assert_eq!(
        crate::app::runtime::resolve_scan_id(&store, "scan-present").expect("should succeed"),
        "scan-present"
    );
}

// ── join_or_dash ──────────────────────────────────────────────────────────────

#[test]
fn join_or_dash_comma_joins_multiple_values() {
    let v = ["a".to_string(), "b".to_string(), "c".to_string()];
    assert_eq!(join_or_dash(v.iter()), "a, b, c");
}

#[test]
fn join_or_dash_single_value_has_no_separator() {
    let v = ["solo".to_string()];
    assert_eq!(join_or_dash(v.iter()), "solo");
}

#[test]
fn join_or_dash_empty_iterator_is_explicit_none() {
    let v: Vec<String> = Vec::new();
    assert_eq!(join_or_dash(v.iter()), "(none)");
}

// ── Property test: export determinism as a GENERAL property ─────────────────
//
// `export_formats_determinism_audit` above proves byte-reproducibility for one
// hand-built fixture (double-rendering the same store). This generalises that
// to the stronger, doctrine-defining property: output is "independent of
// `HashMap` iteration or task-completion order":
// the SAME entities inserted in TWO different orders must export byte-
// identically. That exercises both order-sensitive legs at once — the store's
// merge-on-conflict fold and every renderer's own attribute/tag/evidence
// serialisation — over arbitrary well-formed input rather than a single
// scenario, closing `SOLUTION_TREE` §4a's C7 "general property, not
// case-by-case" gap.
mod prop {
    use super::{
        Scan, Store, Target, TargetKind, render_csv, render_debug_bundle, render_full, render_gexf,
        render_json,
    };
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use proptest::prelude::*;

    /// A representative spread of kinds so generated entities hit varied
    /// renderer branches — identity (Email/Username/Person), infrastructure
    /// (IpAddress/Domain), a secret (Password), and geo (Coordinates).
    fn any_kind() -> impl Strategy<Value = EntityKind> {
        prop_oneof![
            Just(EntityKind::Email),
            Just(EntityKind::Username),
            Just(EntityKind::Person),
            Just(EntityKind::IpAddress),
            Just(EntityKind::Domain),
            Just(EntityKind::Password),
            Just(EntityKind::Coordinates),
        ]
    }

    /// One arbitrary entity carrying the fields whose ordering, if leaked from
    /// a `HashMap` or left order-sensitive, would break byte-determinism: a
    /// value, confidence, corroboration, a tag set, and evidence records each
    /// with their own attribute map.
    fn any_entity() -> impl Strategy<Value = Entity> {
        (
            any_kind(),
            "[a-z0-9._-]{1,16}",
            0.0f64..=1.0,
            1u32..8,
            prop::collection::vec("[a-z]{1,8}", 0..4),
            prop::collection::vec(
                (
                    "[a-z_]{1,10}",
                    prop::collection::vec(("[a-z_]{1,8}", "[a-zA-Z0-9 ._-]{0,12}"), 0..4),
                ),
                0..3,
            ),
        )
            .prop_map(|(kind, val, conf, corr, tags, evs)| {
                let mut e = Entity::new(kind, &val, conf, "scan-prop");
                e.corroboration = corr;
                for t in tags {
                    e.tag(t);
                }
                for (src, attrs) in evs {
                    let mut ev = Evidence::new(src, "prop-generated evidence");
                    for (k, v) in attrs {
                        ev = ev.with_attr(k, v);
                    }
                    e.add_evidence(ev);
                }
                e
            })
    }

    /// Build a fresh store under `dir` holding `order`-sequenced entities.
    fn store_with(dir: &std::path::Path, name: &str, order: &[Entity]) -> Store {
        let store =
            Store::open(dir.join(name).to_str().expect("should succeed")).expect("should succeed");
        let scan = Scan::new(
            "scan-prop",
            Target::new(TargetKind::Email, "seed@example-real.com"),
        );
        store.upsert_scan(&scan).expect("should succeed");
        store.upsert_entities_batch(order).expect("should succeed");
        store
    }

    proptest! {
        // DB-per-case (open + insert + 10 renders), so bound the case count to
        // keep the suite fast on-device while still fuzzing a real spread.
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Every byte-deterministic export renderer is insertion-order-
        /// independent: the same entities inserted forwards vs. reversed must
        /// serialise identically. (`report.json`'s documented `exported_at`
        /// wall-clock field keeps it out of this set, exactly as the
        /// single-fixture audit above excludes it.)
        #[test]
        fn exports_are_insertion_order_independent(
            mut ents in prop::collection::vec(any_entity(), 1..6),
        ) {
            let dir = tempfile::tempdir().expect("should succeed");
            let forward = store_with(dir.path(), "fwd.db", &ents);
            ents.reverse();
            let reversed = store_with(dir.path(), "rev.db", &ents);

            // Store-typed formats.
            prop_assert_eq!(
                render_json(&forward, "scan-prop", false).expect("should succeed"),
                render_json(&reversed, "scan-prop", false).expect("should succeed"),
                "json leaked insertion order"
            );
            prop_assert_eq!(
                render_csv(&forward, "scan-prop", false).expect("should succeed"),
                render_csv(&reversed, "scan-prop", false).expect("should succeed"),
                "csv leaked insertion order"
            );
            prop_assert_eq!(
                render_gexf(&forward, "scan-prop", false).expect("should succeed"),
                render_gexf(&reversed, "scan-prop", false).expect("should succeed"),
                "gexf leaked insertion order"
            );
            // Port-typed formats (`&dyn StoragePort`).
            prop_assert_eq!(
                render_full(&forward, "scan-prop").expect("should succeed"),
                render_full(&reversed, "scan-prop").expect("should succeed"),
                "full dossier leaked insertion order"
            );
            // The debug bundle embeds an ENVIRONMENT snapshot whose
            // `keys_present`/`keys_absent` lines come from `keys::load()`
            // ($HOME/.huntsman.env) — ambient PROCESS state, not a function of
            // the entities or their insertion order. Under cargo's parallel test
            // execution a sibling test that isolates its own vault by mutating the
            // global `$HOME` toggles what THIS test's two renders observe (a real
            // CI flake: one render saw `HUNTSMAN_SHODAN_KEY`, the other did not).
            // That is exactly the class of volatile field the `report.json`
            // `exported_at` exclusion above already carves out, so strip those two
            // lines before comparing — the property under test is entity-order
            // independence, and every other line of the bundle is still asserted.
            prop_assert_eq!(
                strip_ambient_env_keys(&render_debug_bundle(&forward, "scan-prop").expect("should succeed")),
                strip_ambient_env_keys(&render_debug_bundle(&reversed, "scan-prop").expect("should succeed")),
                "debug bundle leaked insertion order"
            );
        }
    }

    /// Remove the two ambient, process-global key-inventory lines
    /// (`keys_present:` / `keys_absent :`) from a debug bundle. Their content is
    /// derived from `$HOME/.huntsman.env` via `keys::load()`, so under parallel
    /// tests that mutate the global `$HOME` it is non-deterministic and unrelated
    /// to the entity-insertion-order property under test.
    fn strip_ambient_env_keys(bundle: &str) -> String {
        bundle
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("keys_present:") && !t.starts_with("keys_absent :")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ── System self-diagnosis bundle ───────────────────────────────────────────

fn passing_selftest() -> crate::selftest::Report {
    crate::selftest::Report {
        ok: true,
        passed: 1,
        warned: 0,
        failed: 0,
        total: 1,
        elapsed_ms: 3,
        version: "test".into(),
        checks: vec![crate::selftest::Check {
            name: "modules.registry".into(),
            status: crate::selftest::Status::Pass,
            detail: "ok".into(),
        }],
    }
}

fn failing_selftest() -> crate::selftest::Report {
    crate::selftest::Report {
        ok: false,
        passed: 0,
        warned: 0,
        failed: 1,
        total: 1,
        elapsed_ms: 4,
        version: "test".into(),
        checks: vec![crate::selftest::Check {
            name: "storage".into(),
            status: crate::selftest::Status::Fail,
            detail: "temp db open failed".into(),
        }],
    }
}

fn healthy_issue_inputs() -> IssueInputs<'static> {
    IssueInputs {
        selftest_ok: true,
        selftest_failures: vec![],
        curl_present: true,
        unhealthy_modules: vec![],
        engines_down: vec![],
        engines_blocked: vec![],
        scrapers_drifted: vec![],
        scrapers_yield_drifted: vec![],
        failed_scans: 0,
        quota_exhausted_providers: vec![],
        update_error: None,
        update_commits_behind: None,
        dead_key_services: vec![],
        db_integrity_issue: None,
        wal_oversized: false,
    }
}

#[test]
fn detect_issues_is_empty_for_a_fully_healthy_engine() {
    // The idempotency/"all green" case: nothing wrong ⇒ no issues, which the
    // renderer turns into an explicit "no issues auto-detected".
    assert!(detect_issues(&healthy_issue_inputs()).is_empty());
}

#[test]
fn detect_issues_flags_a_failing_selftest_check_as_critical() {
    let mut inp = healthy_issue_inputs();
    inp.selftest_ok = false;
    inp.selftest_failures = vec![("storage", "temp db open failed")];
    let issues = detect_issues(&inp);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, SEV_CRITICAL);
    assert_eq!(issues[0].category, "self-test");
    assert!(issues[0].detail.contains("storage"));
    assert!(issues[0].detail.contains("temp db open failed"));
}

#[test]
fn detect_issues_flags_missing_curl_as_critical() {
    let mut inp = healthy_issue_inputs();
    inp.curl_present = false;
    let issues = detect_issues(&inp);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, SEV_CRITICAL);
    assert_eq!(issues[0].category, "environment");
    assert!(issues[0].detail.contains("curl"));
}

#[test]
fn detect_issues_flags_module_engine_scraper_drift_and_failed_scans_as_warnings() {
    let mut inp = healthy_issue_inputs();
    inp.unhealthy_modules = vec![("gravatar", 3)];
    inp.engines_down = vec!["bing"];
    inp.engines_blocked = vec!["brave"];
    inp.scrapers_drifted = vec![("psbdmp", 5)];
    inp.scrapers_yield_drifted = vec!["hibp"];
    inp.failed_scans = 2;
    let issues = detect_issues(&inp);
    assert_eq!(issues.len(), 6, "one issue per distinct signal");
    assert!(
        issues.iter().all(|i| i.severity == SEV_WARNING),
        "degradations are warnings, not criticals"
    );
    let cats: std::collections::BTreeSet<&str> = issues.iter().map(|i| i.category).collect();
    for expected in [
        "module-health",
        "search-engine",
        "scraper-drift",
        "scraper-yield-drift",
        "scans",
    ] {
        assert!(cats.contains(expected), "missing category {expected}");
    }
}

#[test]
fn detect_issues_flags_an_exhausted_provider_quota_as_a_warning() {
    let mut inp = healthy_issue_inputs();
    inp.quota_exhausted_providers = vec!["seeknow", "wigle:geo"];
    let issues = detect_issues(&inp);
    assert_eq!(issues.len(), 2);
    assert!(issues.iter().all(|i| i.severity == SEV_WARNING));
    assert!(issues.iter().all(|i| i.category == "provider-quota"));
    assert!(issues.iter().any(|i| i.detail.contains("seeknow")));
}

#[test]
fn detect_issues_flags_a_stale_build_as_a_warning_pointing_at_update() {
    // Grounded in a real operator debug bundle: three module errors, every one
    // already fixed upstream, on a build with no way to say "you're behind".
    let mut inp = healthy_issue_inputs();
    inp.update_commits_behind = Some(12);
    let issues = detect_issues(&inp);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, SEV_WARNING);
    assert_eq!(issues[0].category, "update");
    assert!(issues[0].detail.contains("12 commit"));
    assert!(issues[0].detail.contains("hse update"));
    // A commits_behind of 0 (up to date) must NOT raise an issue.
    let mut fresh = healthy_issue_inputs();
    fresh.update_commits_behind = Some(0);
    assert!(detect_issues(&fresh).is_empty());
}

#[test]
fn detect_issues_flags_a_fully_dead_key_pool_as_a_warning() {
    // The "largest invisible failure class": a service with keys but 0 active
    // returns Ok(empty) with no error, so only the pool can surface it.
    let mut inp = healthy_issue_inputs();
    inp.dead_key_services = vec![("seeknow", 2), ("hibp", 1)];
    let issues = detect_issues(&inp);
    assert_eq!(issues.len(), 2);
    assert!(issues.iter().all(|i| i.severity == SEV_WARNING));
    assert!(issues.iter().all(|i| i.category == "key-pool"));
    let seeknow = issues
        .iter()
        .find(|i| i.detail.contains("seeknow"))
        .expect("should succeed");
    assert!(seeknow.detail.contains("all 2 pooled key"));
    assert!(seeknow.detail.contains("hse keys"));
}

#[test]
fn key_pool_untested_key_is_not_counted_dead() {
    // Regression (found by a real `hse serve` run): an UNTESTED key has simply
    // not been probed yet — it may work on first use — so a pool holding only
    // untested keys is NOT dead and must not be flagged.
    let untested = KeyPoolSummary {
        service: "shodan".into(),
        total: 1,
        active: 0,
        untested: 1,
        rate_limited: 0,
        exhausted: 0,
        invalid: 0,
        revoked: 0,
        // An untested-only pool has no exercised key to grade → health is None.
        avg_health: None,
    };
    assert!(!untested.is_dead(), "an untested-only pool is not dead");
    // But an all-exhausted/invalid pool with no untested key IS dead.
    let dead = KeyPoolSummary {
        service: "seeknow".into(),
        total: 2,
        active: 0,
        untested: 0,
        rate_limited: 0,
        exhausted: 2,
        invalid: 0,
        revoked: 0,
        avg_health: Some(0.0),
    };
    assert!(dead.is_dead());
}

#[test]
fn detect_issues_flags_db_corruption_as_critical_and_a_runaway_wal_as_warning() {
    // On-disk corruption is invisible to the self-test (throwaway temp DB), so
    // the bundle is the only place it can surface — at CRITICAL.
    let mut corrupt = healthy_issue_inputs();
    corrupt.db_integrity_issue = Some("row 42 missing from index idx_entities_uid");
    let issues = detect_issues(&corrupt);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, SEV_CRITICAL);
    assert_eq!(issues[0].category, "storage");
    assert!(issues[0].detail.contains("row 42 missing"));
    // A runaway WAL is a real device disk-footprint failure → WARNING.
    let mut wal = healthy_issue_inputs();
    wal.wal_oversized = true;
    let issues = detect_issues(&wal);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, SEV_WARNING);
    assert_eq!(issues[0].category, "storage");
    // A healthy DB raises nothing.
    assert!(detect_issues(&healthy_issue_inputs()).is_empty());
}

#[test]
fn detect_issues_flags_a_failed_self_update_as_critical() {
    let mut inp = healthy_issue_inputs();
    inp.update_error = Some("git pull rejected: local changes");
    let issues = detect_issues(&inp);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, SEV_CRITICAL);
    assert_eq!(issues[0].category, "update");
    assert!(issues[0].detail.contains("git pull rejected"));
}

#[test]
fn detect_issues_sorts_critical_before_warning() {
    let mut inp = healthy_issue_inputs();
    inp.curl_present = false; // 1 critical
    inp.engines_down = vec!["bing"]; // 1 warning
    let issues = detect_issues(&inp);
    assert_eq!(issues.len(), 2);
    assert_eq!(
        issues[0].severity, SEV_CRITICAL,
        "critical issues must render first"
    );
    assert_eq!(issues[1].severity, SEV_WARNING);
}

#[test]
fn detect_issues_ordering_is_deterministic_across_input_permutations() {
    // Two IssueInputs describing the same state but built in a different order
    // must yield byte-identical verdicts, so two bundles diff cleanly.
    let mut a = healthy_issue_inputs();
    a.engines_down = vec!["bing", "brave"];
    a.unhealthy_modules = vec![("gravatar", 2), ("psbdmp", 4)];
    let mut b = healthy_issue_inputs();
    b.engines_down = vec!["brave", "bing"];
    b.unhealthy_modules = vec![("psbdmp", 4), ("gravatar", 2)];
    assert_eq!(detect_issues(&a), detect_issues(&b));
}

#[test]
fn system_bundle_has_every_section_and_surfaces_verdict_logs_and_failed_scan_error() {
    let mut scan = Scan::new("scan-sysdbg", Target::new(TargetKind::Email, "x@y.com"));
    scan.status = ScanStatus::Failed;
    scan.error = Some("connector boom".into());
    let inputs = SystemDebugInputs {
        selftest: failing_selftest(),
        scans: vec![scan],
        scraper_health: vec![],
        scraper_events_checked: 0,
        log_dump: "TRACE hse::marker unique-log-line-42\n".into(),
        log_lines: 1,
        key_pool: vec![KeyPoolSummary {
            service: "seeknow".into(),
            total: 2,
            active: 0,
            untested: 0,
            rate_limited: 1,
            exhausted: 1,
            invalid: 0,
            revoked: 0,
            avg_health: Some(0.1),
        }],
        db_integrity: vec!["*** in database main ***".into(), "row 7 missing".into()],
        wal_bytes: Some(128 * 1024 * 1024),
        update_commits_behind: Some(3),
        update_last_checked: 1_700_000_000,
        update_phase: "idle".into(),
    };
    let out = render_system_debug_bundle(&inputs);

    for header in [
        "HUNTSMAN SYSTEM DEBUG BUNDLE",
        "── DETECTED ISSUES",
        "── ENVIRONMENT",
        "── UPDATE STATUS ──",
        "── DISABLED CAPABILITIES",
        "── VALIDATION (SELF-TEST) ──",
        "── MODULE HEALTH",
        "── SEARCH-ENGINE LIVENESS",
        "── SCRAPER HEALTH",
        "── PROVIDER QUOTAS",
        "── KEY POOL",
        "── STORAGE HEALTH",
        "── RECENT SCANS",
        "── RECENT LOGS",
        "── SOURCE FILES",
    ] {
        assert!(out.contains(header), "missing section header: {header}");
    }
    // The stale-build fixture (3 commits behind) surfaces the update prompt.
    assert!(out.contains("3 commit(s) BEHIND"));
    // The fully-dead seeknow pool is marked and reaches the verdict.
    assert!(out.contains("ALL DEAD"));
    assert!(out.contains("all 2 pooled key"));
    // Corrupt DB + runaway WAL both render and reach the verdict.
    assert!(out.contains("integrity: FAIL"));
    assert!(out.contains("row 7 missing"));
    assert!(out.contains("RUNAWAY"));
    assert!(out.contains("database integrity check FAILED"));
    // The self-diagnosing verdict surfaces the failing self-test check.
    assert!(out.contains("[CRITICAL]"), "verdict must flag the failure");
    assert!(out.contains("temp db open failed"));
    // The failed scan's error is inline — the debuggability gap the UI map
    // flagged (a failed scan's top-level error was unreachable in the SPA).
    assert!(out.contains("error: connector boom"));
    // Traceability with no redaction: the exact log line is carried verbatim.
    assert!(out.contains("unique-log-line-42"));
}

#[test]
fn system_bundle_reports_all_clear_when_healthy() {
    // A passing self-test, no scans, no drift ⇒ the headline verdict is the
    // explicit all-clear, not a blank section.
    let inputs = SystemDebugInputs {
        selftest: passing_selftest(),
        scans: vec![],
        scraper_health: vec![],
        scraper_events_checked: 0,
        log_dump: String::new(),
        log_lines: 0,
        key_pool: vec![],
        db_integrity: vec!["ok".into()],
        wal_bytes: Some(4096),
        update_commits_behind: Some(0),
        update_last_checked: 0,
        update_phase: "idle".into(),
    };
    let out = render_system_debug_bundle(&inputs);
    // NOTE: the DETECTED ISSUES verdict is deliberately NOT asserted here — the
    // renderer reads live process-global health (the shared module-health map,
    // the engine-liveness cache, real `curl`) that this test doesn't inject, so
    // an "all clear" is not guaranteed in a polluted/parallel test binary or on
    // a host without curl. The all-clear CLASSIFICATION is covered hermetically
    // by `detect_issues_is_empty_for_a_fully_healthy_engine`; here we assert
    // only what the injected inputs deterministically control.
    assert!(
        out.contains("log ring empty"),
        "empty log ring must be stated, not silently omitted"
    );
    assert!(out.contains("HUNTSMAN SYSTEM DEBUG BUNDLE"));
}

#[test]
fn render_full_shows_the_live_event_tally_while_a_scan_is_still_running() {
    // Regression, from two real debug bundles: both exported mid-scan, both
    // headed `status : Running`, and both printing
    // `modules : 0 run, 0 errored, 0 timed out, 0 skipped, 0 cached, 0 deduped`
    // while the SAME scan's event stream held ~70 module_start, ~60
    // module_done, ~9 module_error and ~11 module_skipped. The counters are
    // written once, in `finalise_scan`, so mid-scan they are structurally
    // zero — the header must say so AND surface the tally that does exist.
    use crate::core::event::{Event, EventKind};
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let db = dir.path().join("running_tally.db");
    let store = Store::open(db.to_str().expect("db path should be UTF-8"))
        .expect("store should open on a fresh temp db");

    let mut scan = Scan::new("scan-running", Target::new(TargetKind::Email, "a@b.com"));
    scan.status = ScanStatus::Running;
    store.upsert_scan(&scan).expect("scan row should persist");

    for (module, done) in [("dns", true), ("whois", true), ("crtsh", false)] {
        store
            .insert_event(&Event::new(
                "scan-running",
                EventKind::ModuleStart {
                    module: module.into(),
                },
            ))
            .expect("module_start should persist");
        let kind = if done {
            EventKind::ModuleDone {
                module: module.into(),
                found: 2,
            }
        } else {
            EventKind::ModuleError {
                module: module.into(),
                error: "timed out".into(),
            }
        };
        store
            .insert_event(&Event::new("scan-running", kind))
            .expect("module outcome should persist");
    }
    store
        .insert_event(&Event::new(
            "scan-running",
            EventKind::ModuleSkipped {
                module: "shodan".into(),
                reason: "needs API key".into(),
                class: Some(crate::core::event::SkipClass::Unavailable),
            },
        ))
        .expect("module_skipped should persist");

    let out = render_full(&store, "scan-running").expect("render_full should succeed");

    // The zeros are still printed — but never bare.
    assert!(
        out.contains("0 run, 0 errored, 0 timed out, 0 skipped, 0 cached, 0 deduped"),
        "the persisted counters must still be reported verbatim: {out}"
    );
    assert!(
        out.contains("NOT YET FINAL"),
        "mid-scan zeros must be disclosed as unwritten, not left to read as \
         'nothing ran': {out}"
    );
    // …and the work that HAS happened is surfaced from the event stream.
    assert!(
        out.contains(
            "observed   : 3 module_start, 2 module_done, 1 module_error, 1 module_skipped"
        ),
        "the live event tally must appear for a non-terminal scan: {out}"
    );
}

#[test]
fn render_full_omits_the_live_tally_once_the_scan_is_terminal() {
    // The determinism contract in `render_debug_bundle` requires a completed
    // scan to export byte-identically every time, so the live line must be
    // strictly a non-terminal-path addition — and a finalised scan's own
    // counters are authoritative, making it redundant as well as unsafe.
    use crate::core::event::{Event, EventKind};
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let db = dir.path().join("complete_tally.db");
    let store = Store::open(db.to_str().expect("db path should be UTF-8"))
        .expect("store should open on a fresh temp db");

    let mut scan = Scan::new("scan-complete", Target::new(TargetKind::Email, "a@b.com"));
    scan.status = ScanStatus::Complete;
    scan.modules_run = 2;
    store.upsert_scan(&scan).expect("scan row should persist");
    store
        .insert_event(&Event::new(
            "scan-complete",
            EventKind::ModuleStart {
                module: "dns".into(),
            },
        ))
        .expect("module_start should persist");

    let out = render_full(&store, "scan-complete").expect("render_full should succeed");
    assert!(
        out.contains("2 run, 0 errored, 0 timed out, 0 skipped, 0 cached, 0 deduped"),
        "a terminal scan reports its real counters: {out}"
    );
    assert!(
        !out.contains("NOT YET FINAL"),
        "no caveat belongs on a finalised scan: {out}"
    );
    assert!(
        !out.contains("observed   :"),
        "the live tally must not appear on a finalised scan: {out}"
    );
}

#[test]
fn provenance_names_the_modules_when_no_provider_attributes_exist() {
    // Regression (live andersonbushikai.com scan, debug bundle 6b2d34664852…):
    // the PROVENANCE block reported `providers/api key origins/sources: (none)`
    // three times for a scan whose 17 entities were produced by seven named
    // modules — dns_intel, doh_resolver, mnemonic_pdns, url_extract,
    // search_engines, waf_detect, webserver_banner — every one of them printed
    // in the evidence tree immediately below. The roll-up only read optional
    // `provider`/`source`/`source_db` ATTRIBUTES that paid providers happen to
    // set, and ignored `Evidence::source`, which is documented as "Module that
    // produced this evidence". A section whose whole job is to say where the
    // data came from asserted that nothing was known.
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("prov_test.db");
    let store = Store::open(db.to_str().expect("should succeed")).expect("should succeed");
    let target = Target::new(TargetKind::Url, "https://example.com/locations");
    let scan = Scan::new("scan-prov", target);
    store.upsert_scan(&scan).expect("should succeed");
    let mut e = Entity::new(EntityKind::Domain, "example.com", 0.92, "scan-prov");
    e.add_evidence(Evidence::new("dns_intel", "SOA record for example.com"));
    e.add_evidence(Evidence::new("doh_resolver", "A record"));
    store.upsert_entity(&e).expect("should succeed");

    let out = render_full(&store, "scan-prov").expect("should succeed");
    assert!(
        out.contains("sources/sites  : dns_intel, doh_resolver"),
        "modules that produced the evidence must be named, got:\n{}",
        out.lines()
            .filter(|l| l.starts_with("sources/sites")
                || l.starts_with("providers")
                || l.starts_with("api key origins"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ── build_scan_report ───────────────────────────────────────────────────

#[test]
fn report_distinguishes_a_clean_sweep_from_one_nobody_answered() {
    // A thin report is ambiguous without this: a scan that asked everything and
    // found nothing renders identically to one where every provider broke, and
    // only the first is evidence of absence.
    use crate::core::event::{Event, EventKind};
    use crate::core::scan::{Scan, Target, TargetKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("coverage.db");
    let store =
        crate::storage::Store::open(db.to_str().expect("should succeed")).expect("should succeed");
    let sid = "coverage-scan";
    store
        .upsert_scan(&Scan::new(
            sid,
            Target::new(TargetKind::FullName, "Jordan Avery"),
        ))
        .expect("should succeed");
    let port = &store as &dyn crate::core::port::StoragePort;

    // No retained events: NULL, never an empty list that would read as
    // "every provider answered".
    let bare = build_scan_report(port, sid, false, false)
        .expect("should succeed")
        .expect("should succeed");
    assert!(
        bare["provider_coverage"].is_null(),
        "an unknown coverage must not render as a complete one: {}",
        bare["provider_coverage"]
    );

    for kind in [
        EventKind::ModuleDone {
            module: "asked_and_answered".to_string(),
            found: 0,
        },
        EventKind::ModuleError {
            module: "broke".to_string(),
            error: "upstream 502".to_string(),
        },
    ] {
        store
            .insert_event(&Event::new(sid, kind))
            .expect("should succeed");
    }

    let report = build_scan_report(port, sid, false, false)
        .expect("should succeed")
        .expect("should succeed");
    let coverage = &report["provider_coverage"];
    assert_eq!(
        coverage["all_available_providers_answered"].as_bool(),
        Some(false),
        "a provider that broke is a fault, reported as one"
    );
    assert_eq!(coverage["exhaustive"].as_bool(), Some(false));
    assert_eq!(coverage["unavailable_count"].as_u64(), Some(1));
    assert_eq!(
        coverage["out_of_scope_count"].as_u64(),
        Some(0),
        "nothing here was narrowed out; the two axes are never summed"
    );
    let providers = coverage["providers"]
        .as_array()
        .expect("provider rows are a list");
    assert_eq!(providers.len(), 2);
    assert_eq!(
        providers[0]["provider_id"].as_str(),
        Some("asked_and_answered")
    );
    assert_eq!(
        providers[0]["outcome"]["kind"].as_str(),
        Some("clean_negative")
    );
    assert_eq!(providers[1]["provider_id"].as_str(), Some("broke"));
    assert_eq!(providers[1]["outcome"]["kind"].as_str(), Some("failed"));
    assert_eq!(
        providers[1]["outcome"]["reason"].as_str(),
        Some("upstream 502"),
        "the operator is told what to re-run and why"
    );
}

#[test]
fn report_hides_candidates_by_default_and_includes_on_request() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::{Scan, Target, TargetKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("report.db");
    let store =
        crate::storage::Store::open(db.to_str().expect("should succeed")).expect("should succeed");
    let sid = "rep-scan";
    store
        .upsert_scan(&Scan::new(
            sid,
            Target::new(TargetKind::FullName, "Jordan Avery"),
        ))
        .expect("should succeed");
    store
        .upsert_entity(&Entity::new(EntityKind::Email, "me@real.com", 0.85, sid))
        .expect("should succeed");
    let mut candidate = Entity::new(EntityKind::Email, "stranger@bank.com", 0.25, sid);
    candidate.tag(crate::core::tags::CANDIDATE);
    store.upsert_entity(&candidate).expect("should succeed");

    let port = &store as &dyn crate::core::port::StoragePort;
    let default = build_scan_report(port, sid, false, false)
        .expect("should succeed")
        .expect("should succeed");
    assert_eq!(
        default["entity_count"].as_u64(),
        Some(1),
        "default report hides the candidate"
    );
    let full = build_scan_report(port, sid, true, false)
        .expect("should succeed")
        .expect("should succeed");
    assert_eq!(
        full["entity_count"].as_u64(),
        Some(2),
        "include_candidates returns the full set"
    );
    // The report envelope must carry the Exposure Index headline the CLI
    // dossier and debug bundle both open with — score (0..=100), band label,
    // and the transparent per-signal breakdown — so report.json is a
    // complete dossier on its own, not one that forces the reader to
    // recompute the summary verdict.
    let exposure = &default["exposure"];
    assert!(
        exposure["score"].as_u64().is_some_and(|s| s <= 100),
        "report must carry the exposure score: {default}"
    );
    assert!(
        exposure["band"].as_str().is_some(),
        "report must carry the exposure band label"
    );
    assert!(
        exposure["components"].is_array(),
        "report must carry the per-signal exposure breakdown"
    );
}

#[test]
fn report_hides_platform_infra_by_default_and_includes_on_request() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::{Scan, Target, TargetKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("infra.db");
    let store =
        crate::storage::Store::open(db.to_str().expect("should succeed")).expect("should succeed");
    let sid = "infra-scan";
    store
        .upsert_scan(&Scan::new(
            sid,
            Target::new(TargetKind::Username, "testuser"),
        ))
        .expect("should succeed");
    store
        .upsert_entity(&Entity::new(EntityKind::Email, "me@real.com", 0.85, sid))
        .expect("should succeed");
    let mut infra = Entity::new(EntityKind::Domain, "s3.amazonaws.com", 0.40, sid);
    infra.tag("platform-infra");
    store.upsert_entity(&infra).expect("should succeed");

    let port = &store as &dyn crate::core::port::StoragePort;
    let default = build_scan_report(port, sid, false, false)
        .expect("should succeed")
        .expect("should succeed");
    assert_eq!(
        default["entity_count"].as_u64(),
        Some(1),
        "default report hides platform-infra entity"
    );
    let with_infra = build_scan_report(port, sid, false, true)
        .expect("should succeed")
        .expect("should succeed");
    assert_eq!(
        with_infra["entity_count"].as_u64(),
        Some(2),
        "include_infra=true returns the infra entity"
    );
}

#[test]
fn report_correlations_always_resolve_against_its_own_entities() {
    // The correlator runs over the infra-inclusive set, so a Critical finding
    // on a platform-infra entity (AU-004 on a compromised hosting IP) used to
    // reference a UID the default (`include_infra=false`) envelope had
    // filtered out of `entities` — the report's top finding was unexplainable
    // from the document itself. Referenced infra entities are unioned back; a
    // finding on a hidden CANDIDATE is dropped (quarantine wins).
    use crate::core::correlator::{Correlation, Severity};
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::{Scan, Target, TargetKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("resolve.db");
    let store =
        crate::storage::Store::open(db.to_str().expect("should succeed")).expect("should succeed");
    let sid = "resolve-scan";
    store
        .upsert_scan(&Scan::new(
            sid,
            Target::new(TargetKind::Username, "testuser"),
        ))
        .expect("should succeed");
    store
        .upsert_entity(&Entity::new(EntityKind::Email, "me@real.com", 0.85, sid))
        .expect("should succeed");
    let mut infra = Entity::new(EntityKind::IpAddress, "203.0.113.9", 0.7, sid);
    infra.tag("platform-infra");
    infra.tag("malicious");
    store.upsert_entity(&infra).expect("should succeed");
    let mut candidate = Entity::new(EntityKind::Email, "stranger@breach.example", 0.4, sid);
    candidate.tag(crate::core::tags::CANDIDATE);
    store.upsert_entity(&candidate).expect("should succeed");
    store
        .upsert_correlation(&Correlation::new(
            "AU-004",
            "Malicious infrastructure",
            Severity::Critical,
            "compromised hosting IP".into(),
            vec![infra.uid.clone()],
            sid,
            0,
        ))
        .expect("should succeed");
    store
        .upsert_correlation(&Correlation::new(
            "AU-999",
            "Finding on a quarantined row",
            Severity::Low,
            "must not surface by default".into(),
            vec![candidate.uid.clone()],
            sid,
            0,
        ))
        .expect("should succeed");

    let port = &store as &dyn crate::core::port::StoragePort;
    let check = |report: &serde_json::Value, label: &str| {
        let uids: std::collections::HashSet<String> = report["entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["uid"].as_str().unwrap().to_string())
            .collect();
        for c in report["correlations"].as_array().unwrap() {
            for u in c["entity_uids"].as_array().unwrap() {
                assert!(
                    uids.contains(u.as_str().unwrap()),
                    "{label}: correlation {} references a UID absent from entities",
                    c["rule_id"]
                );
            }
        }
    };
    let default = build_scan_report(port, sid, false, false)
        .expect("should succeed")
        .expect("should succeed");
    check(&default, "default");
    let rules: Vec<&str> = default["correlations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["rule_id"].as_str().unwrap())
        .collect();
    assert!(
        rules.contains(&"AU-004"),
        "the Critical infra finding is kept, with its entity restored: {rules:?}"
    );
    assert!(
        !rules.contains(&"AU-999"),
        "a finding on a hidden candidate is dropped: {rules:?}"
    );
    assert_eq!(default["correlation_count"].as_u64(), Some(1));
    let full = build_scan_report(port, sid, true, true)
        .expect("should succeed")
        .expect("should succeed");
    check(&full, "include_candidates+include_infra");
    assert_eq!(full["correlation_count"].as_u64(), Some(2));
}

#[test]
fn default_report_always_keeps_the_seed_even_if_it_is_infrastructure() {
    // A scan seeded with a datacenter/CDN IP: an IP module re-emits the seed
    // as `hosting`, merging `platform-infra` onto the seed anchor. The
    // subject must never vanish from its own report — `seed` is preserved
    // even under default (infra-suppressed) export.
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::{Scan, Target, TargetKind};
    let dir = tempfile::tempdir().expect("should succeed");
    let db = dir.path().join("seed_infra.db");
    let store =
        crate::storage::Store::open(db.to_str().expect("should succeed")).expect("should succeed");
    let sid = "seed-infra-scan";
    store
        .upsert_scan(&Scan::new(
            sid,
            Target::new(TargetKind::IpAddress, "104.16.0.1"),
        ))
        .expect("should succeed");
    // The seed anchor that also got classified as hosting infrastructure.
    let mut seed = Entity::new(EntityKind::IpAddress, "104.16.0.1", 0.90, sid);
    seed.tag("seed");
    seed.tag("subject");
    seed.tag("hosting");
    seed.tag("platform-infra");
    store.upsert_entity(&seed).expect("should succeed");

    let port = &store as &dyn crate::core::port::StoragePort;
    let default = build_scan_report(port, sid, false, false)
        .expect("should succeed")
        .expect("should succeed");
    assert_eq!(
        default["entity_count"].as_u64(),
        Some(1),
        "the seed/subject must survive default infra suppression"
    );
}

// ── entities_to_csv ─────────────────────────────────────────────────────

#[test]
fn entities_to_csv_assembles_header_and_escaped_rows() {
    use crate::core::entity::{Entity, EntityKind};

    // Empty input still emits exactly the column header — export consumers
    // (the SPA download button, external tooling) parse this header row.
    assert_eq!(
        entities_to_csv(&[]).trim_end(),
        "kind,value,raw_value,confidence,c_effective,corroboration,source_count,classification,observed_at,sources,corroborating_sources,evidence_urls,evidence,tags,uid,generation"
    );

    let mut e = Entity::new(EntityKind::Email, "a@b.com", 0.60, "src");
    e.tag("plain");
    e.tag("has,comma"); // a comma inside an assembled field must be quoted
    let csv = entities_to_csv(&[e]);
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 2, "header + exactly one row per entity");

    let row = lines[1];
    // Column order + 3-dp numeric formatting (kind,value,raw_value,conf,c_eff,…).
    assert!(
        row.starts_with("email,a@b.com,a@b.com,0.600,0.600,"),
        "field order / numeric formatting drifted: {row}"
    );
    // The comma-bearing tag is RFC-4180 quoted, proving entities_to_csv
    // routes assembled fields through csv_escape. `tags` is followed by the
    // appended join-key columns, so it is no longer the final field.
    assert!(
        row.contains(",\"plain|has,comma\","),
        "tags column not escaped through csv_escape: {row}"
    );
    // `uid` + `generation` close the row: the uid is what every other
    // artifact (JSON export, debug bundle, Browse, /entities/{uid}) keys a
    // finding by, so a CSV row must be joinable back to them.
    let e2 = Entity::new(EntityKind::Email, "a@b.com", 0.60, "src");
    assert!(
        row.ends_with(&format!(",{},0", e2.uid)),
        "row must end with the uid join key and generation: {row}"
    );
}

#[test]
fn csv_carries_verifiable_evidence_urls_and_summaries() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut e = Entity::new(EntityKind::Username, "jordanavery", 0.80, "src");
    e.add_evidence(
        Evidence::new("username_search", "@jordanavery has a profile on GitHub")
            .with_attr("url", "https://github.com/jordanavery"),
    );
    e.add_evidence(
        Evidence::new("github_user", "12 public events")
            .with_attr("profile_url", "https://github.com/jordanavery?tab=overview"),
    );
    let csv = entities_to_csv(&[e]);
    let row = csv.lines().nth(1).expect("should succeed");
    assert!(
        row.contains("https://github.com/jordanavery"),
        "evidence URL missing: {row}"
    );
    assert!(
        row.contains("?tab=overview"),
        "second evidence URL missing: {row}"
    );
    assert!(
        row.contains("[username_search]") && row.contains("[github_user]"),
        "evidence trail missing: {row}"
    );
    assert!(
        row.contains("has a profile on GitHub"),
        "evidence summary missing: {row}"
    );
}

#[test]
fn csv_evidence_column_carries_structured_attributes_not_just_summary() {
    // Regression: the CSV documents itself as making "every row
    // self-verifiable... without reconstructing anything from the value
    // alone", but only the prose `summary` was ever written — a module
    // that records hard evidentiary detail (a leaked DOB, a password hash)
    // as structured `attributes` rather than folding it into prose text was
    // silently dropped from the export, even though the SPA's evidence
    // panel and the full dossier both show it in full.
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut e = Entity::new(EntityKind::Person, "Jordan Avery", 0.80, "src");
    e.add_evidence(
        Evidence::new("breach_rich", "breach record found")
            .with_attr("date_of_birth", "1990-04-12")
            .with_attr("password_hash", "5f4dcc3b5aa765d61d8327deb882cf99"),
    );
    let csv = entities_to_csv(&[e]);
    let row = csv.lines().nth(1).expect("should succeed");
    assert!(
        row.contains("date_of_birth=1990-04-12"),
        "structured DOB attribute missing from CSV evidence cell: {row}"
    );
    assert!(
        row.contains("password_hash=5f4dcc3b5aa765d61d8327deb882cf99"),
        "structured password_hash attribute missing from CSV evidence cell: {row}"
    );
    assert!(
        row.contains("[breach_rich] breach record found"),
        "the prose summary must still be present alongside the attributes: {row}"
    );
}

#[test]
fn csv_source_count_and_corroborating_sources_reflect_the_filtered_count_not_the_raw_magnitude() {
    // Regression: `corroboration` is a raw per-module observation magnitude
    // (summed on merge, never deduplicated) that does NOT drive `c_effective`
    // — a real scan showed ~19 mutually-exclusive breach-derived addresses
    // all carrying an identical `corroboration=8` inherited from the emitting
    // module, with no CSV column anywhere showing the `source_count` that
    // actually drove confidence. A reader had no way to tell from the CSV
    // alone whether that "8" meant anything.
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut e = Entity::new(EntityKind::Address, "1 Example St", 0.82, "src");
    // Raw magnitude seeded high, as a breach module might.
    e.corroboration = 8;
    // Only two evidence sources are genuinely corroborating; `geo_normalize`
    // is a deterministic enrichment pass and must not count.
    e.add_evidence(Evidence::new("oathnet_pro", "Breach on ebay.com"));
    e.add_evidence(Evidence::new(
        "search_engines",
        "5 engines returned results",
    ));
    e.add_evidence(Evidence::new(
        "geo_normalize",
        "Address parse + normalization",
    ));

    let csv = entities_to_csv(&[e]);
    let header: Vec<&str> = csv
        .lines()
        .next()
        .expect("should succeed")
        .split(',')
        .collect();
    let row: Vec<&str> = csv
        .lines()
        .nth(1)
        .expect("should succeed")
        .split(',')
        .collect();

    let col = |name: &str| {
        let idx = header
            .iter()
            .position(|h| *h == name)
            .expect("should succeed");
        row[idx]
    };
    assert_eq!(col("corroboration"), "8", "raw magnitude is unchanged");
    assert_eq!(
        col("source_count"),
        "2",
        "source_count must reflect the 2 genuinely distinct, non-enrichment sources"
    );
    assert_eq!(
        col("corroborating_sources"),
        "oathnet_pro|search_engines",
        "corroborating_sources must list only the genuine sources, excluding geo_normalize"
    );
}

#[test]
fn csv_evidence_column_omits_empty_attribute_values() {
    // An attribute present with an empty value (a module that recorded the
    // key but had nothing to put in it) must not pollute the cell with a
    // bare trailing `key=`.
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.5, "src");
    e.add_evidence(Evidence::new("some_module", "found it").with_attr("country", ""));
    let csv = entities_to_csv(&[e]);
    let row = csv.lines().nth(1).expect("should succeed");
    assert!(
        !row.contains("country="),
        "an empty attribute value must not be emitted: {row}"
    );
    assert!(
        row.contains("[some_module] found it"),
        "summary must be unaffected: {row}"
    );
}

// ── AU-059 best_location emit→extract contract ───────────────────────────

/// Build a tagged AU `Coordinates` entity for a given source, mirroring the
/// correlator's own fixture so the convergence path is identical.
fn au_sighting(value: &str, conf: f64, source: &str, state: &str) -> crate::core::entity::Entity {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut e = Entity::new(EntityKind::Coordinates, value, conf, "s");
    e.tag(format!("au-state:{state}"));
    e.tag("country:AU");
    e.add_evidence(Evidence::new(source, "geo sighting"));
    e
}

#[test]
fn extract_au_location_fix_round_trips_every_field() {
    let ents = vec![
        au_sighting("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
        au_sighting("-33.8700,151.2100", 0.70, "exif_geo", "NSW"),
    ];
    let corrs = crate::core::correlator::correlate_entities(&ents, "s");
    assert!(
        corrs.iter().any(|c| c.rule_id == "AU-059"),
        "fixture must produce an AU-059 firing"
    );

    let fix = extract_au_location_fix(&corrs, &ents);
    assert!(
        fix.is_object(),
        "fix must be a structured object, got {fix}"
    );
    assert_eq!(fix["state"], "NSW");
    assert_eq!(fix["rule_id"], "AU-059");
    let lat = fix["lat"].as_f64().expect("should succeed");
    let lon = fix["lon"].as_f64().expect("should succeed");
    assert!((-34.0..-33.0).contains(&lat), "lat off Sydney: {lat}");
    assert!((150.0..152.0).contains(&lon), "lon off Sydney: {lon}");
    assert!(
        !fix["geohash"].as_str().expect("should succeed").is_empty(),
        "geohash empty"
    );
    let sc = fix["synergy_confidence"].as_f64().expect("should succeed");
    assert!(
        (0.0..=0.97).contains(&sc) && sc > 0.0,
        "synergy_conf range: {sc}"
    );
    assert_eq!(fix["class_count"], 2);
    assert!(fix["source_count"].as_u64().expect("should succeed") >= 2);
    assert_eq!(fix["severity"], "medium", "2 classes ⇒ medium");
    // Confidence radius: present, finite, non-negative, and tight for two
    // coordinates ~150 m apart.
    let radius = fix["radius_km"].as_f64().expect("radius_km present");
    assert!(
        radius.is_finite() && (0.0..5.0).contains(&radius),
        "radius: {radius}"
    );
}

#[test]
fn extract_au_location_fix_falls_back_to_single_signal_without_au_059() {
    use crate::core::entity::{Entity, EntityKind};
    // Two AU coordinates that don't reach the AU-059 ≥2-orthogonal-class gate
    // still yield a headline fix via the single-signal fallback — the API
    // surface now always carries a best-location answer when any AU signal
    // exists, with its precision radius and the basis it was derived from.
    let ents = vec![
        au_sighting("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
        au_sighting("-33.8700,151.2100", 0.75, "acnc_charities", "NSW"),
    ];
    let corrs = crate::core::correlator::correlate_entities(&ents, "s");
    let fix = extract_au_location_fix(&corrs, &ents);
    assert!(fix.is_object(), "single-signal fallback must produce a fix");
    assert_eq!(fix["source"], "single-signal");
    assert_eq!(fix["state"], "NSW");
    assert!(fix["basis"].is_string());
    assert!(fix["radius_km"].as_f64().expect("should succeed") > 0.0);

    // But with NO location signal at all (an email only), it stays Null —
    // the fallback never fabricates a location out of nothing.
    let no_geo = vec![Entity::new(EntityKind::Email, "x@y.com", 0.9, "s")];
    assert_eq!(
        extract_au_location_fix(&[], &no_geo),
        serde_json::Value::Null
    );
}

/// The structured fields come from the **entities**, not the finding prose —
/// so a reworded (or, here, deliberately corrupted) AU-059 description cannot
/// drift `best_location`. This is the whole point of reading the fix
/// structurally instead of string-splitting the description.
#[test]
fn extract_au_location_fix_reads_entities_not_prose() {
    let ents = vec![
        au_sighting("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
        au_sighting("-33.8700,151.2100", 0.70, "exif_geo", "NSW"),
    ];
    let mut corrs = crate::core::correlator::correlate_entities(&ents, "s");
    let au059 = corrs
        .iter_mut()
        .find(|c| c.rule_id == "AU-059")
        .expect("fixture must produce an AU-059 firing");
    // Corrupt the prose the old parser depended on — the fields must survive.
    au059.description = "garbage — no parseable coordinates here".into();

    let fix = extract_au_location_fix(&corrs, &ents);
    assert!(fix.is_object(), "fix must survive a corrupted description");
    assert_eq!(fix["state"], "NSW");
    assert_eq!(fix["class_count"], 2);
    let lat = fix["lat"].as_f64().expect("should succeed");
    let lon = fix["lon"].as_f64().expect("should succeed");
    assert!((-34.0..-33.0).contains(&lat) && (150.0..152.0).contains(&lon));

    // It is exactly the canonical helper — the single source of truth.
    let direct = crate::core::correlator::au059_synergy_fix(&ents).expect("should succeed");
    assert!((lat - direct.lat).abs() < 1e-9);
    assert!((lon - direct.lon).abs() < 1e-9);
    assert_eq!(
        fix["geohash"].as_str().expect("should succeed"),
        direct.geohash
    );
}
