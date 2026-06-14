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
        let default = build_scan_report(port, sid, false).unwrap().unwrap();
        assert_eq!(
            default["entity_count"].as_u64(),
            Some(1),
            "default report hides the candidate"
        );
        let full = build_scan_report(port, sid, true).unwrap().unwrap();
        assert_eq!(
            full["entity_count"].as_u64(),
            Some(2),
            "include_candidates returns the full set"
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
            "kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,evidence_urls,evidence,tags"
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
        // `tags` is the final column; the comma-bearing tag is RFC-4180 quoted,
        // proving entities_to_csv routes assembled fields through csv_escape.
        assert!(
            row.ends_with(",\"plain|has,comma\""),
            "tags column not escaped through csv_escape: {row}"
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

        let fix = extract_au_location_fix(&corrs);
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
    }

    #[test]
    fn extract_au_location_fix_is_null_without_au_059() {
        let ents = vec![
            au_sighting("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
            au_sighting("-33.8700,151.2100", 0.75, "acnc_charities", "NSW"),
        ];
        let corrs = crate::core::correlator::correlate_entities(&ents, "s");
        assert_eq!(extract_au_location_fix(&corrs), serde_json::Value::Null);
        assert_eq!(extract_au_location_fix(&[]), serde_json::Value::Null);
    }

    #[test]
    fn extract_au_location_fix_picks_highest_rank_when_several() {
        use crate::core::correlator::{Correlation, Severity};
        let mut low = Correlation::new(
            "AU-059",
            "Cross-seed geographic synergy (orthogonal-class fix)",
            Severity::Medium,
            "2 AU coordinate(s) from 2 orthogonal source class(es) [Registry, Social] \
             converge on -37.8136,144.9631 (geohash=r1r0fs, state=VIC); synergy confidence \
             0.55 — MITRE T1591.001"
                .into(),
            vec!["a".into(), "b".into()],
            "s",
            0,
        );
        low.rank = 1.1;
        let mut high = Correlation::new(
            "AU-059",
            "Cross-seed geographic synergy (orthogonal-class fix)",
            Severity::High,
            "3 AU coordinate(s) from 3 orthogonal source class(es) [PhotoGps, Registry, \
             Directory] converge on -33.8688,151.2093 (geohash=r3gx2f, state=NSW); synergy \
             confidence 0.81 — MITRE T1591.001"
                .into(),
            vec!["c".into(), "d".into(), "e".into()],
            "s",
            0,
        );
        high.rank = 2.7;

        let fix = extract_au_location_fix(&[low, high]);
        assert_eq!(fix["state"], "NSW", "must pick the higher-rank firing");
        assert_eq!(fix["class_count"], 3);
        assert_eq!(fix["source_count"], 3);
        assert_eq!(fix["severity"], "high");
        assert!((fix["synergy_confidence"].as_f64().unwrap() - 0.81).abs() < 1e-9);
        assert!((fix["lat"].as_f64().unwrap() - -33.8688).abs() < 1e-4);
    }
