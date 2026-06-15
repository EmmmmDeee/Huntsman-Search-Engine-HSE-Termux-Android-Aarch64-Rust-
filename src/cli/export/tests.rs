use super::renderers::{
    render_csv, render_debug_bundle, render_full, render_gexf, render_json, render_maltego,
    render_misp, render_report, write_spiderfoot_db,
};
use crate::core::scan::{Scan, Target, TargetKind};
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
    assert!(out.contains("── CORRELATIONS")); // §2
    assert!(out.contains("── SCAN SEQUENCE (2 events)")); // §3
    assert!(out.contains("module_start")); // histogram + JSONL
    assert!(out.contains("\"reason\":\"identity_mismatch\"")); // loss-less event
    assert!(out.contains("── SELF-AUDIT")); // §4
    assert!(out.contains("score      :"));
    assert!(out.contains("exclusions : identity_mismatch×1")); // ledger folded in
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
        serde_json::from_str(&render_report(&store, "scan-au").unwrap()).unwrap();
    let mut r2: serde_json::Value =
        serde_json::from_str(&render_report(&store, "scan-au").unwrap()).unwrap();
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

    // After the scan exists, resolution returns the id.
    let target = Target::new(TargetKind::Email, "x@b.com");
    store
        .upsert_scan(&Scan::new("scan-present", target))
        .unwrap();
    assert_eq!(
        crate::cli::resolve_scan_id(&store, "scan-present").unwrap(),
        "scan-present"
    );
}

#[test]
fn render_misp_produces_valid_event_json() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::{Scan, Target, TargetKind};
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("misp.db").to_str().unwrap()).unwrap();
    let scan = Scan::new(
        "scan-misp",
        Target::new(TargetKind::Email, "a@example-real.com"),
    );
    store.upsert_scan(&scan).unwrap();
    store
        .upsert_entities_batch(&[
            Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.9, "scan-misp"),
            Entity::new(EntityKind::Email, "a@example-real.com", 0.8, "scan-misp"),
            Entity::new(EntityKind::Domain, "example-real.com", 0.7, "scan-misp"),
        ])
        .unwrap();
    let out = render_misp(&store, "scan-misp").unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).expect("MISP output must be valid JSON");
    assert!(v.get("Event").is_some(), "top-level Event key missing");
    let attrs = v["Event"]["Attribute"].as_array().unwrap();
    assert_eq!(attrs.len(), 3);
    assert!(attrs.iter().any(|a| a["type"] == "ip-dst"));
    assert!(attrs.iter().any(|a| a["type"] == "email-dst"));
    assert!(attrs.iter().any(|a| a["type"] == "domain"));
}

#[test]
fn render_maltego_produces_valid_xml() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::{Scan, Target, TargetKind};
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("maltego.db").to_str().unwrap()).unwrap();
    let scan = Scan::new(
        "scan-mt",
        Target::new(TargetKind::Email, "b@example-real.com"),
    );
    store.upsert_scan(&scan).unwrap();
    store
        .upsert_entities_batch(&[
            Entity::new(EntityKind::IpAddress, "5.6.7.8", 0.85, "scan-mt"),
            Entity::new(EntityKind::Domain, "example-real.com", 0.7, "scan-mt"),
        ])
        .unwrap();
    let out = render_maltego(&store, "scan-mt").unwrap();
    assert!(out.contains("<?xml"), "missing XML declaration");
    assert!(out.contains("MaltegoMessage"), "missing root element");
    assert!(
        out.contains("maltego.IPv4Address"),
        "missing IP entity type"
    );
    assert!(
        out.contains("maltego.DNSName"),
        "missing domain entity type"
    );
    assert!(out.contains("5.6.7.8"), "IP value missing");
    assert!(out.contains("example-real.com"), "domain value missing");
}

#[test]
fn write_spiderfoot_db_creates_readable_sqlite() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::{Scan, Target, TargetKind};
    use rusqlite::Connection;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("sf.db");
    let store_path = dir.path().join("hse.db");
    let store = Store::open(store_path.to_str().unwrap()).unwrap();
    let scan = Scan::new(
        "scan-sf",
        Target::new(TargetKind::Email, "c@example-real.com"),
    );
    store.upsert_scan(&scan).unwrap();
    store
        .upsert_entities_batch(&[
            Entity::new(EntityKind::IpAddress, "9.10.11.12", 0.9, "scan-sf"),
            Entity::new(EntityKind::Email, "c@example-real.com", 0.8, "scan-sf"),
        ])
        .unwrap();
    write_spiderfoot_db(&store, "scan-sf", db_path.to_str().unwrap()).unwrap();
    let conn = Connection::open(&db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM tbl_scan_results", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2, "expected 2 result rows in SpiderFoot DB");
    let types: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT type FROM tbl_scan_results ORDER BY type")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert!(types.contains(&"IP_ADDRESS".to_string()));
    assert!(types.contains(&"EMAILADDR".to_string()));
}
