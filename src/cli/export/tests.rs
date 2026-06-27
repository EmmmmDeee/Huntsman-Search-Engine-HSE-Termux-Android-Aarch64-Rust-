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
    store.upsert_entities_batch(&[e]).unwrap();

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

#[test]
fn render_full_orders_foreign_keys_by_roi_tier() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("roi_order.db");
    let store = Store::open(db.to_str().unwrap()).unwrap();

    let scan = Scan::new(
        "scan-roi",
        Target::new(TargetKind::Email, "x@example-real.com"),
    );
    store.upsert_scan(&scan).unwrap();

    // A Terminal-tier key (abuseipdb) inserted FIRST, a Multiplier-tier key
    // (shodan) second — the renderer must reorder so the higher-ROI key leads,
    // regardless of insertion/confidence order.
    let mut terminal = Entity::new(
        EntityKind::ApiKey,
        "abuseipdb:fake-terminal-val",
        0.80,
        "scan-roi",
    );
    terminal.tag("foreign-key");
    terminal.add_evidence(
        Evidence::new("api_key_probe", "harvested").with_attr("service", "abuseipdb"),
    );
    let mut multiplier = Entity::new(
        EntityKind::ApiKey,
        "shodan:fake-multiplier-val",
        0.80,
        "scan-roi",
    );
    multiplier.tag("foreign-key");
    multiplier
        .add_evidence(Evidence::new("api_key_probe", "harvested").with_attr("service", "shodan"));
    store
        .upsert_entities_batch(&[terminal, multiplier])
        .unwrap();

    let out = render_full(&store, "scan-roi").unwrap();
    // Each line leads with the ROI tier label, then the service.
    assert!(out.contains("[multiplier] [shodan]"), "{out}");
    assert!(out.contains("[terminal] [abuseipdb]"), "{out}");
    // The Multiplier key is surfaced BEFORE the Terminal key despite being
    // inserted second — strategic value, not arrival order, drives the listing.
    let mpos = out.find("[multiplier] [shodan]").unwrap();
    let tpos = out.find("[terminal] [abuseipdb]").unwrap();
    assert!(
        mpos < tpos,
        "Multiplier key must lead the foreign-keys section:\n{out}"
    );
}
