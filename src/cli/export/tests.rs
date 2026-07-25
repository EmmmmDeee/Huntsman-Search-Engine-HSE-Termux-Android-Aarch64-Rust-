use super::dossier::join_or_dash;
use super::renderers::{
    IssueInputs, KeyPoolSummary, SEV_CRITICAL, SEV_WARNING, SystemDebugInputs, detect_issues,
    render_csv, render_debug_bundle, render_full, render_gexf, render_json, render_report,
    render_system_debug_bundle,
};
use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};
use crate::storage::Store;

#[test]
fn render_full_dumps_every_field_and_provenance() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("full_test.db");
    let store = Store::open(db.to_str().unwrap()).unwrap();

    let target = Target::new(TargetKind::Email, "vanamill@hotmail.com");
    let scan = Scan::new("scan-full", target);
    store.upsert_scan(&scan).unwrap();

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
    store.upsert_entities_batch(&[e, mixed]).unwrap();

    let out = render_full(&store, "scan-full").unwrap();
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
fn render_full_resolves_relation_labels_and_reports_all_module_counts() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::relation::{Relation, RelationKind};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("full_rel.db");
    let store = Store::open(db.to_str().unwrap()).unwrap();

    let mut scan = Scan::new("scan-fr", Target::new(TargetKind::FullName, "Jordan Avery"));
    scan.modules_run = 12;
    scan.modules_timed_out = 3;
    scan.modules_skipped = 1;
    scan.modules_cached = 2;
    store.upsert_scan(&scan).unwrap();

    let email = Entity::new(EntityKind::Email, "jordan@real.com", 0.85, "scan-fr");
    let user = Entity::new(EntityKind::Username, "jordanavery", 0.80, "scan-fr");
    store
        .upsert_entities_batch(&[email.clone(), user.clone()])
        .unwrap();
    store
        .upsert_relation(&Relation::new(
            &email.uid,
            &user.uid,
            RelationKind::AliasOf,
            0.8,
            "scan-fr",
        ))
        .unwrap();

    let out = render_full(&store, "scan-fr").unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("source_count_test.db");
    let store = Store::open(db.to_str().unwrap()).unwrap();

    let target = Target::new(TargetKind::Address, "1 Example St");
    let scan = Scan::new("scan-sc", target);
    store.upsert_scan(&scan).unwrap();

    let mut e = Entity::new(EntityKind::Address, "1 Example St", 0.82, "scan-sc");
    e.corroboration = 8;
    e.add_evidence(Evidence::new("oathnet_pro", "Breach on ebay.com"));
    e.add_evidence(Evidence::new(
        "geo_normalize",
        "Address parse + normalization",
    ));
    store.upsert_entities_batch(&[e]).unwrap();

    let out = render_full(&store, "scan-sc").unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("quarantine_test.db");
    let store = Store::open(db.to_str().unwrap()).unwrap();

    let target = Target::new(TargetKind::Email, "subject@example-real.com");
    let scan = Scan::new("scan-q", target);
    store.upsert_scan(&scan).unwrap();

    let confirmed = Entity::new(EntityKind::Email, "subject@example-real.com", 0.8, "scan-q");
    let mut stranger = Entity::new(EntityKind::Person, "Random Stranger", 0.25, "scan-q");
    stranger.demote_to_candidate(); // tags `candidate`
    store.upsert_entities_batch(&[confirmed, stranger]).unwrap();

    for body in [
        render_csv(&store, "scan-q", false).unwrap(),
        render_json(&store, "scan-q", false).unwrap(),
        render_gexf(&store, "scan-q", false).unwrap(),
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
    let full = render_full(&store, "scan-q").unwrap();
    assert!(
        full.contains("Random Stranger"),
        "the full bundle retains quarantined rows for transparency"
    );
}

#[test]
fn debug_bundle_includes_dossier_sequence_and_audit() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::event::{Event, EventKind};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("debug_test.db");
    let store = Store::open(db.to_str().unwrap()).unwrap();

    let target = Target::new(TargetKind::Email, "isaac@example-real.com");
    let scan = Scan::new("scan-dbg", target);
    store.upsert_scan(&scan).unwrap();
    store
        .upsert_entities_batch(&[Entity::new(
            EntityKind::Email,
            "isaac@example-real.com",
            0.8,
            "scan-dbg",
        )])
        .unwrap();
    // A recorded sequence including an exclusion (so the audit ledger fires).
    store
        .insert_event(&Event::new(
            "scan-dbg",
            EventKind::ModuleStart {
                module: "hibp".into(),
            },
        ))
        .unwrap();
    store
        .insert_event(&Event::new(
            "scan-dbg",
            EventKind::EntityExcluded {
                kind: "username".into(),
                value: "stranger".into(),
                reason: "identity_mismatch".into(),
            },
        ))
        .unwrap();

    let out = render_debug_bundle(&store, "scan-dbg").unwrap();
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
    assert!(out.contains("src/cli/export/mod.rs"));
    assert!(out.contains("HUNTSMAN FULL DOSSIER")); // §1 embeds render_full
    assert!(out.contains("── EXPOSURE INDEX")); // §1 headline mirrors live dossier
    assert!(out.contains("── CORRELATIONS")); // §2
    assert!(out.contains("── SCAN SEQUENCE · 2 events")); // §3 header
    assert!(out.contains("module_start")); // per-type breakdown
    assert!(out.contains("▶ hibp")); // module_start rendered in the human timeline
    assert!(out.contains("⊘ not expanded · username stranger")); // exclusion event rendered readably, with its reason
    assert!(out.contains("identity_mismatch")); // …and its reason is preserved on that line
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
            },
        ),
    ];
    let out = crate::cli::export::render_event_log(&evs);

    // Structure: header with count, a by-type breakdown, and a UTC timeline.
    assert!(out.contains("── SCAN SEQUENCE · 8 events ──"));
    assert!(out.contains("By type:"));
    assert!(out.contains("Timeline (UTC):"));
    // Each event kind renders as a readable, glyph-led line (spacing-agnostic).
    assert!(out.contains("● scan started · username=alameddine"));
    assert!(out.contains("▶ dehashed"));
    assert!(out.contains("✓ dehashed  (0 found)"));
    assert!(out.contains("◌ psbdmp  capability-quarantined"));
    assert!(out.contains("+ email  a@b.com  ·0.90"));
    assert!(out.contains("(candidate)")); // candidate entity flagged
    assert!(out.contains("⊘ not expanded · username stranger  identity_mismatch"));
    assert!(out.contains("✔ scan complete · 2 entities"));
    // Category columns present for grouping.
    for cat in ["scan", "module", "entity", "expand"] {
        assert!(out.contains(cat), "category column `{cat}` must appear");
    }

    println!("\n===== render_event_log sample =====\n{out}=====");
}

#[test]
fn debug_bundle_correlation_histogram_surfaces_a_dominant_rule() {
    use crate::core::correlator::{Correlation, Severity};
    use crate::core::entity::{Entity, EntityKind};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("debug_histo.db");
    let store = Store::open(db.to_str().unwrap()).unwrap();

    let scan = Scan::new("scan-histo", Target::new(TargetKind::Email, "x@y.com"));
    store.upsert_scan(&scan).unwrap();
    store
        .upsert_entities_batch(&[Entity::new(EntityKind::Email, "x@y.com", 0.8, "scan-histo")])
        .unwrap();
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
            .unwrap();
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
        .unwrap();

    let out = render_debug_bundle(&store, "scan-histo").unwrap();
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
    let hi = out.find("rule histogram").unwrap();
    let tail = &out[hi..];
    assert!(
        tail.find("AU-099").unwrap() < tail.find("AU-076").unwrap(),
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
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("au059.db").to_str().unwrap()).unwrap();
    let scan = Scan::new(
        "scan-au059",
        Target::new(TargetKind::Email, "au059@example-real.com"),
    );
    store.upsert_scan(&scan).unwrap();

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
    store.upsert_entities_batch(&entities).unwrap();
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
        .unwrap();

    let out = render_debug_bundle(&store, "scan-au059").unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("single_signal.db").to_str().unwrap()).unwrap();
    let scan = Scan::new(
        "scan-single",
        Target::new(TargetKind::Email, "single@example-real.com"),
    );
    store.upsert_scan(&scan).unwrap();

    let mut coord = Entity::new(
        EntityKind::Coordinates,
        "-33.8688,151.2093",
        0.85,
        "scan-single",
    );
    coord.tag("au-state:NSW");
    coord.tag("country:AU");
    coord.add_evidence(Evidence::new("exif_geo", "fixture"));
    store.upsert_entities_batch(&[coord]).unwrap();
    // No AU-059 correlation stored — a lone coordinate never fires the rule.

    let out = render_debug_bundle(&store, "scan-single").unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("det.db").to_str().unwrap()).unwrap();
    let scan = Scan::new(
        "scan-det",
        Target::new(TargetKind::Email, "a@example-real.com"),
    );
    store.upsert_scan(&scan).unwrap();
    // Several entities + events so any unstable iteration order would surface.
    store
        .upsert_entities_batch(&[
            Entity::new(EntityKind::Email, "a@example-real.com", 0.8, "scan-det"),
            Entity::new(EntityKind::Username, "alpha", 0.6, "scan-det"),
            Entity::new(EntityKind::Username, "bravo", 0.6, "scan-det"),
            Entity::new(EntityKind::Domain, "example-real.com", 0.5, "scan-det"),
        ])
        .unwrap();
    for m in ["hibp", "gravatar", "crtsh"] {
        store
            .insert_event(&Event::new(
                "scan-det",
                EventKind::ModuleStart { module: m.into() },
            ))
            .unwrap();
    }
    let a = render_debug_bundle(&store, "scan-det").unwrap();
    let b = render_debug_bundle(&store, "scan-det").unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("audit.db").to_str().unwrap()).unwrap();
    let scan = Scan::new(
        "scan-au",
        Target::new(TargetKind::Email, "z@example-real.com"),
    );
    store.upsert_scan(&scan).unwrap();
    store
        .upsert_entities_batch(&[
            Entity::new(EntityKind::Email, "z@example-real.com", 0.8, "scan-au"),
            Entity::new(EntityKind::Username, "zeta", 0.6, "scan-au"),
            Entity::new(EntityKind::Domain, "example-real.com", 0.5, "scan-au"),
        ])
        .unwrap();

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
            let a = render(&store, "scan-au", redact).unwrap();
            let b = render(&store, "scan-au", redact).unwrap();
            assert_eq!(
                a, b,
                "format `{name}` (redact={redact}) is not byte-deterministic"
            );
        }
    }
    // full + debug take `&dyn StoragePort`.
    let port_fmts: &[(&str, PortFmt)] = &[("full", render_full), ("debug", render_debug_bundle)];
    for (name, render) in port_fmts {
        let a = render(&store, "scan-au").unwrap();
        let b = render(&store, "scan-au").unwrap();
        assert_eq!(a, b, "format `{name}` is not byte-deterministic");
    }

    // report.json: deterministic EXCEPT the documented `exported_at`. Compare
    // structurally with that one field removed — robust regardless of whether
    // the two renders happened to land in the same wall-clock second.
    let mut r1: serde_json::Value =
        serde_json::from_str(&render_report(&store, "scan-au", false).unwrap()).unwrap();
    let mut r2: serde_json::Value =
        serde_json::from_str(&render_report(&store, "scan-au", false).unwrap()).unwrap();
    assert!(
        r1.get("exported_at").is_some(),
        "exported_at must be present"
    );
    for r in [&mut r1, &mut r2] {
        r.as_object_mut().unwrap().remove("exported_at");
    }
    assert_eq!(
        r1, r2,
        "report.json varies in a field OTHER than the documented `exported_at`"
    );
}

#[test]
fn explicit_scan_id_is_existence_checked_no_silent_empty_export() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("export_test.db");
    let store = Store::open(db.to_str().unwrap()).unwrap();

    // Unknown id -> a clear "not found" error (no silent empty export). The
    // existence check now lives in the shared `cli::resolve_scan_id`.
    let err = crate::cli::resolve_scan_id(&store, "no-such-scan")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("not found"),
        "expected not-found error, got: {err}"
    );

    // After a *complete* scan exists, resolution returns the id.
    let target = Target::new(TargetKind::Email, "x@b.com");
    let mut scan = Scan::new("scan-present", target);
    scan.status = ScanStatus::Complete;
    store.upsert_scan(&scan).unwrap();
    assert_eq!(
        crate::cli::resolve_scan_id(&store, "scan-present").unwrap(),
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
// to the stronger, doctrine-defining property (`docs/CONVENTIONS.md` §5:
// output is "independent of `HashMap` iteration or task-completion order"):
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
        let store = Store::open(dir.join(name).to_str().unwrap()).unwrap();
        let scan = Scan::new(
            "scan-prop",
            Target::new(TargetKind::Email, "seed@example-real.com"),
        );
        store.upsert_scan(&scan).unwrap();
        store.upsert_entities_batch(order).unwrap();
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
            let dir = tempfile::tempdir().unwrap();
            let forward = store_with(dir.path(), "fwd.db", &ents);
            ents.reverse();
            let reversed = store_with(dir.path(), "rev.db", &ents);

            // Store-typed formats.
            prop_assert_eq!(
                render_json(&forward, "scan-prop", false).unwrap(),
                render_json(&reversed, "scan-prop", false).unwrap(),
                "json leaked insertion order"
            );
            prop_assert_eq!(
                render_csv(&forward, "scan-prop", false).unwrap(),
                render_csv(&reversed, "scan-prop", false).unwrap(),
                "csv leaked insertion order"
            );
            prop_assert_eq!(
                render_gexf(&forward, "scan-prop", false).unwrap(),
                render_gexf(&reversed, "scan-prop", false).unwrap(),
                "gexf leaked insertion order"
            );
            // Port-typed formats (`&dyn StoragePort`).
            prop_assert_eq!(
                render_full(&forward, "scan-prop").unwrap(),
                render_full(&reversed, "scan-prop").unwrap(),
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
                strip_ambient_env_keys(&render_debug_bundle(&forward, "scan-prop").unwrap()),
                strip_ambient_env_keys(&render_debug_bundle(&reversed, "scan-prop").unwrap()),
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
        .unwrap();
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
