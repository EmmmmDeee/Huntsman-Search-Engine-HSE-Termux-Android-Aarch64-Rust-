use super::dossier::join_or_dash;
use super::renderers::{
    render_csv, render_debug_bundle, render_full, render_gexf, render_json, render_report,
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
            .with_attr("provider", "see-know.eu")
            .with_attr("api_key_origin", "see-know.eu:seek-62650f9a…0fd0a4")
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
    assert!(out.contains("providers      : see-know.eu"));
    assert!(out.contains("api key origins: see-know.eu:seek-62650f9a…0fd0a4"));
    assert!(out.contains("sources/sites  : Snusbase"));
    // The entity, its value, and EVERY evidence attribute verbatim.
    assert!(out.contains("password = thelord"));
    assert!(out.contains("api_key_origin = see-know.eu:seek-62650f9a…0fd0a4"));
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
        render_csv(&store, "scan-q").unwrap(),
        render_json(&store, "scan-q").unwrap(),
        render_gexf(&store, "scan-q").unwrap(),
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
    assert!(out.contains("── SCAN SEQUENCE (2 events)")); // §3
    assert!(out.contains("module_start")); // histogram + JSONL
    assert!(out.contains("\"reason\":\"identity_mismatch\"")); // loss-less event
    assert!(out.contains("── SELF-AUDIT")); // §4
    assert!(out.contains("score      :"));
    assert!(out.contains("exclusions : identity_mismatch×1")); // ledger folded in
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
    type StoreFmt = fn(&Store, &str) -> Result<String>;
    type PortFmt = fn(&dyn crate::core::port::StoragePort, &str) -> Result<String>;

    // Byte-reproducible formats (Store-typed).
    let store_fmts: &[(&str, StoreFmt)] = &[
        ("json", render_json),
        ("csv", render_csv),
        ("gexf", render_gexf),
    ];
    for (name, render) in store_fmts {
        let a = render(&store, "scan-au").unwrap();
        let b = render(&store, "scan-au").unwrap();
        assert_eq!(a, b, "format `{name}` is not byte-deterministic");
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
                render_json(&forward, "scan-prop").unwrap(),
                render_json(&reversed, "scan-prop").unwrap(),
                "json leaked insertion order"
            );
            prop_assert_eq!(
                render_csv(&forward, "scan-prop").unwrap(),
                render_csv(&reversed, "scan-prop").unwrap(),
                "csv leaked insertion order"
            );
            prop_assert_eq!(
                render_gexf(&forward, "scan-prop").unwrap(),
                render_gexf(&reversed, "scan-prop").unwrap(),
                "gexf leaked insertion order"
            );
            // Port-typed formats (`&dyn StoragePort`).
            prop_assert_eq!(
                render_full(&forward, "scan-prop").unwrap(),
                render_full(&reversed, "scan-prop").unwrap(),
                "full dossier leaked insertion order"
            );
            prop_assert_eq!(
                render_debug_bundle(&forward, "scan-prop").unwrap(),
                render_debug_bundle(&reversed, "scan-prop").unwrap(),
                "debug bundle leaked insertion order"
            );
        }
    }
}
