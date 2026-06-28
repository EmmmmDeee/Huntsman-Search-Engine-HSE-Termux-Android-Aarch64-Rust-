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

    // ── correlations_to_csv ─────────────────────────────────────────────────

    #[test]
    fn correlations_to_csv_assembles_header_and_escaped_rows() {
        use crate::core::correlator::{Correlation, Severity};

        // Empty input still emits exactly the column header — the spreadsheet
        // pipeline parses this row to know the schema even on a no-hit scan.
        assert_eq!(
            correlations_to_csv(&[]).trim_end(),
            "rule_id,rule_name,severity,rank,description,entity_count,entity_uids,observed_at"
        );

        let mut c = Correlation::new(
            "AU-076",
            "Email-username local-part identity bridge",
            Severity::High,
            "alice@host ↔ username alice, exact".to_string(), // comma forces quoting
            vec!["uid-a".to_string(), "uid-b".to_string()],
            "scan-x",
            1_700_000_000,
        );
        c.rank = 2.5;
        let csv = correlations_to_csv(&[c]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2, "header + exactly one row per correlation");

        let row = lines[1];
        // Column order + 3-dp rank formatting.
        assert!(
            row.starts_with("AU-076,"),
            "rule_id must lead the row: {row}"
        );
        assert!(row.contains(",HIGH,2.500,"), "severity/rank drifted: {row}");
        // The comma-bearing description is RFC-4180 quoted, proving the row
        // routes assembled fields through csv_escape like the entity CSV.
        assert!(
            row.contains("\"alice@host ↔ username alice, exact\""),
            "description not escaped through csv_escape: {row}"
        );
        // entity_uids `|`-joined (joinable back to the entity CSV) + count + ts.
        assert!(row.contains(",2,uid-a|uid-b,1700000000"), "uid/count/ts: {row}");
    }

    #[test]
    fn correlations_to_csv_defangs_formula_injection() {
        use crate::core::correlator::{Correlation, Severity};
        // A hostile rule description starting with `=` must be neutralised the
        // same way the entity CSV neutralises a hostile value (OWASP CSV-injection).
        let c = Correlation::new(
            "AU-001",
            "rule",
            Severity::Low,
            "=cmd|'/c calc'!A1".to_string(),
            vec!["uid".to_string()],
            "scan-x",
            0,
        );
        let csv = correlations_to_csv(&[c]);
        let row = csv.lines().nth(1).unwrap();
        // Defanged with a leading `'` (no outer RFC-4180 quoting is needed — the
        // payload carries no comma/quote/newline), exactly as the entity CSV does.
        assert!(
            row.contains(",'=cmd|'/c calc'!A1,"),
            "formula not defanged with leading quote: {row}"
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

    // ── chunked_stream (export body streaming) ───────────────────────────────

    /// Drain a streamed [`axum::body::Body`] back into one `Vec<u8>`. The
    /// streaming export path must be byte-for-byte identical to handing axum the
    /// whole String, so every test below reassembles the frames and compares.
    /// Uses axum's own `into_data_stream` + `futures::StreamExt` (both already
    /// direct deps) so no extra crate is pulled in just to test this.
    async fn drain(body: axum::body::Body) -> Vec<u8> {
        use futures::StreamExt as _;
        let mut out = Vec::new();
        let mut frames = body.into_data_stream();
        while let Some(frame) = frames.next().await {
            out.extend_from_slice(&frame.expect("export body stream is infallible"));
        }
        out
    }

    #[tokio::test]
    async fn chunked_stream_reassembles_multiframe_body_byte_for_byte() {
        // A body several chunks long (> EXPORT_CHUNK_BYTES) must stream and
        // reassemble to exactly the input — the frame-boundary slicing is the
        // whole risk here, so prove the seams add/drop nothing.
        let big: String = (0..EXPORT_CHUNK_BYTES * 3 + 777)
            .map(|i| (b'a' + (i % 26) as u8) as char)
            .collect();
        let got = drain(chunked_stream(big.clone())).await;
        assert_eq!(got, big.as_bytes(), "multi-frame stream must round-trip");
    }

    #[tokio::test]
    async fn chunked_stream_handles_small_and_empty_bodies() {
        // Body smaller than one frame → a single frame, identical bytes.
        let small = "kind,value\nemail,a@b.com\n".to_string();
        assert_eq!(drain(chunked_stream(small.clone())).await, small.as_bytes());
        // Empty body → zero frames → empty payload (the degenerate but valid
        // export, e.g. an immediate 304-then-200 race producing no rows).
        assert!(drain(chunked_stream(String::new())).await.is_empty());
    }

    #[tokio::test]
    async fn chunked_stream_preserves_utf8_multibyte_payload() {
        // Slicing is on byte offsets, not char boundaries — that is correct for a
        // wire body (HTTP frames are byte windows, reassembled losslessly), so a
        // multibyte UTF-8 export (AU localities carry non-ASCII) must survive even
        // when a frame edge lands mid-codepoint.
        let unit = "Ñoño café — Wagga Wagga 🇦🇺 ";
        let body: String = unit.repeat(EXPORT_CHUNK_BYTES / unit.len() + 5);
        assert_eq!(drain(chunked_stream(body.clone())).await, body.as_bytes());
    }
