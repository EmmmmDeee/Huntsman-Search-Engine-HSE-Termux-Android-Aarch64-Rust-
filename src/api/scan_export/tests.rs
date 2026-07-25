use super::*;

    // ── build_scan_report ───────────────────────────────────────────────────

    #[test]
    fn report_hides_candidates_by_default_and_includes_on_request() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::scan::{Scan, Target, TargetKind};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("report.db");
        let store = crate::storage::Store::open(db.to_str().unwrap()).unwrap();
        let sid = "rep-scan";
        store
            .upsert_scan(&Scan::new(
                sid,
                Target::new(TargetKind::FullName, "Jordan Avery"),
            ))
            .unwrap();
        store
            .upsert_entity(&Entity::new(EntityKind::Email, "me@real.com", 0.85, sid))
            .unwrap();
        let mut candidate = Entity::new(EntityKind::Email, "stranger@bank.com", 0.25, sid);
        candidate.tag(crate::core::tags::CANDIDATE);
        store.upsert_entity(&candidate).unwrap();

        let port = &store as &dyn crate::core::port::StoragePort;
        let default = build_scan_report(port, sid, false, false).unwrap().unwrap();
        assert_eq!(
            default["entity_count"].as_u64(),
            Some(1),
            "default report hides the candidate"
        );
        let full = build_scan_report(port, sid, true, false).unwrap().unwrap();
        assert_eq!(
            full["entity_count"].as_u64(),
            Some(2),
            "include_candidates returns the full set"
        );
    }

    #[test]
    fn report_hides_platform_infra_by_default_and_includes_on_request() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::scan::{Scan, Target, TargetKind};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("infra.db");
        let store = crate::storage::Store::open(db.to_str().unwrap()).unwrap();
        let sid = "infra-scan";
        store
            .upsert_scan(&Scan::new(
                sid,
                Target::new(TargetKind::Username, "testuser"),
            ))
            .unwrap();
        store
            .upsert_entity(&Entity::new(EntityKind::Email, "me@real.com", 0.85, sid))
            .unwrap();
        let mut infra = Entity::new(EntityKind::Domain, "s3.amazonaws.com", 0.40, sid);
        infra.tag("platform-infra");
        store.upsert_entity(&infra).unwrap();

        let port = &store as &dyn crate::core::port::StoragePort;
        let default = build_scan_report(port, sid, false, false).unwrap().unwrap();
        assert_eq!(
            default["entity_count"].as_u64(),
            Some(1),
            "default report hides platform-infra entity"
        );
        let with_infra = build_scan_report(port, sid, false, true).unwrap().unwrap();
        assert_eq!(
            with_infra["entity_count"].as_u64(),
            Some(2),
            "include_infra=true returns the infra entity"
        );
    }

    #[test]
    fn default_report_always_keeps_the_seed_even_if_it_is_infrastructure() {
        // A scan seeded with a datacenter/CDN IP: an IP module re-emits the seed
        // as `hosting`, merging `platform-infra` onto the seed anchor. The
        // subject must never vanish from its own report — `seed` is preserved
        // even under default (infra-suppressed) export.
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::scan::{Scan, Target, TargetKind};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("seed_infra.db");
        let store = crate::storage::Store::open(db.to_str().unwrap()).unwrap();
        let sid = "seed-infra-scan";
        store
            .upsert_scan(&Scan::new(
                sid,
                Target::new(TargetKind::IpAddress, "104.16.0.1"),
            ))
            .unwrap();
        // The seed anchor that also got classified as hosting infrastructure.
        let mut seed = Entity::new(EntityKind::IpAddress, "104.16.0.1", 0.90, sid);
        seed.tag("seed");
        seed.tag("subject");
        seed.tag("hosting");
        seed.tag("platform-infra");
        store.upsert_entity(&seed).unwrap();

        let port = &store as &dyn crate::core::port::StoragePort;
        let default = build_scan_report(port, sid, false, false).unwrap().unwrap();
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
        let row = csv.lines().nth(1).unwrap();
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
        let row = csv.lines().nth(1).unwrap();
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
        e.add_evidence(Evidence::new("search_engines", "5 engines returned results"));
        e.add_evidence(Evidence::new("geo_normalize", "Address parse + normalization"));

        let csv = entities_to_csv(&[e]);
        let header: Vec<&str> = csv.lines().next().unwrap().split(',').collect();
        let row: Vec<&str> = csv.lines().nth(1).unwrap().split(',').collect();

        let col = |name: &str| {
            let idx = header.iter().position(|h| *h == name).unwrap();
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
        let row = csv.lines().nth(1).unwrap();
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
    fn au_sighting(
        value: &str,
        conf: f64,
        source: &str,
        state: &str,
    ) -> crate::core::entity::Entity {
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
        assert!(fix.is_object(), "fix must be a structured object, got {fix}");
        assert_eq!(fix["state"], "NSW");
        assert_eq!(fix["rule_id"], "AU-059");
        let lat = fix["lat"].as_f64().unwrap();
        let lon = fix["lon"].as_f64().unwrap();
        assert!((-34.0..-33.0).contains(&lat), "lat off Sydney: {lat}");
        assert!((150.0..152.0).contains(&lon), "lon off Sydney: {lon}");
        assert!(
            !fix["geohash"].as_str().unwrap().is_empty(),
            "geohash empty"
        );
        let sc = fix["synergy_confidence"].as_f64().unwrap();
        assert!(
            (0.0..=0.97).contains(&sc) && sc > 0.0,
            "synergy_conf range: {sc}"
        );
        assert_eq!(fix["class_count"], 2);
        assert!(fix["source_count"].as_u64().unwrap() >= 2);
        assert_eq!(fix["severity"], "medium", "2 classes ⇒ medium");
        // Confidence radius: present, finite, non-negative, and tight for two
        // coordinates ~150 m apart.
        let radius = fix["radius_km"].as_f64().expect("radius_km present");
        assert!(radius.is_finite() && (0.0..5.0).contains(&radius), "radius: {radius}");
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
        assert!(fix["radius_km"].as_f64().unwrap() > 0.0);

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
        let lat = fix["lat"].as_f64().unwrap();
        let lon = fix["lon"].as_f64().unwrap();
        assert!((-34.0..-33.0).contains(&lat) && (150.0..152.0).contains(&lon));

        // It is exactly the canonical helper — the single source of truth.
        let direct = crate::core::correlator::au059_synergy_fix(&ents).unwrap();
        assert!((lat - direct.lat).abs() < 1e-9);
        assert!((lon - direct.lon).abs() < 1e-9);
        assert_eq!(fix["geohash"].as_str().unwrap(), direct.geohash);
    }

// ── canonical download helper (attachment_response / download_response) ───────

#[test]
fn download_response_sets_attachment_disposition_with_scan_scoped_filename() {
    // The scan-scoped exports (CSV / JSON / GEXF / navigator) frame the name as
    // `hse-<stem>-<short_id>.<ext>` with the scan id truncated to 12 chars.
    let resp = download_response(
        "{}".to_string(),
        "application/json; charset=utf-8",
        "abcdef0123456789deadbeef",
        "navigator",
        "json",
    );
    let cd = resp
        .headers()
        .get(axum::http::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert_eq!(cd, "attachment; filename=\"hse-navigator-abcdef012345.json\"");
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert_eq!(ct, "application/json; charset=utf-8");
}

#[test]
fn attachment_response_uses_the_filename_verbatim_for_system_downloads() {
    // The logs / debug-bundle path shares the SAME builder but supplies a
    // timestamped name directly (no scan id to truncate) — it must land in the
    // Content-Disposition unchanged, so the two download families can't drift.
    let resp = attachment_response(
        "log line\n".to_string(),
        "text/plain; charset=utf-8",
        "hse-debug-1700000000.log",
    );
    let cd = resp
        .headers()
        .get(axum::http::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert_eq!(cd, "attachment; filename=\"hse-debug-1700000000.log\"");
}
