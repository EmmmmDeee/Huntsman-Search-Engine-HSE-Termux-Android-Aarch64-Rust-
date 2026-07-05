use super::*;

#[test]
fn accepts_coordinates_only() {
        let m = Overpass;
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8,151.2")));
        assert!(!m.accepts(&Target::new(TargetKind::Address, "Sydney")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Overpass.name(), "overpass");
        assert_eq!(Overpass.priority(), 15);
        assert_eq!(Overpass.max_timeout_ms(), 30_000);
    }

    #[test]
    fn parse_response() {
        let raw = r#"{
            "version": 0.6,
            "elements": [
                {
                    "type": "node",
                    "id": 12345,
                    "lat": -33.8688,
                    "lon": 151.2093,
                    "tags": {
                        "man_made": "mast",
                        "operator": "Telstra",
                        "name": "Cell Tower A"
                    }
                }
            ]
        }"#;
        let r: OverpassResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.elements.len(), 1);
        let e = &r.elements[0];
        assert_eq!(e.id, Some(12345));
        assert_eq!(e.tags.as_ref().unwrap().get("operator").unwrap(), "Telstra");
    }

    fn tags(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn classify_element_covers_every_category() {
        assert_eq!(
            classify_element(&tags(&[("man_made", "mast")])),
            "cell_tower"
        );
        assert_eq!(
            classify_element(&tags(&[("tower:type", "communication")])),
            "comm_tower"
        );
        assert_eq!(
            classify_element(&tags(&[("man_made", "surveillance")])),
            "surveillance"
        );
        assert_eq!(
            classify_element(&tags(&[("power", "substation")])),
            "substation"
        );
        assert_eq!(classify_element(&tags(&[("amenity", "police")])), "police");
        assert_eq!(
            classify_element(&tags(&[("amenity", "fire_station")])),
            "fire_station"
        );
        // Matched the query but carries none of the discriminating tags.
        assert_eq!(
            classify_element(&tags(&[("man_made", "antenna")])),
            "infrastructure"
        );
    }

    fn elements(json: &str) -> Vec<OsmElement> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn build_entities_emits_summary_plus_classified_nodes() {
        let els = elements(
            r#"[
              {"type":"node","id":1,"lat":-33.8688,"lon":151.2093,
               "tags":{"man_made":"mast","operator":"Telstra","name":"Tower A"}},
              {"type":"node","id":2,"lat":-33.8690,"lon":151.2095,
               "tags":{"man_made":"surveillance"}},
              {"type":"node","id":3,"lat":-33.8692,"lon":151.2097,
               "tags":{"man_made":"mast"}}
            ]"#,
        );
        let out = build_entities("-33.8688,151.2093", &els, "s");
        // Summary + 3 node entities.
        assert_eq!(out.len(), 4);

        let summary = &out[0];
        assert!(summary.has_tag("overpass") && summary.has_tag("geoint"));
        assert_eq!(
            summary.evidence[0]
                .attributes
                .get("node_count")
                .map(String::as_str),
            Some("3")
        );
        // Breakdown evidence is appended as the summary's second evidence row;
        // BTreeMap → deterministic category order.
        assert_eq!(
            summary.evidence[1]
                .attributes
                .get("categories")
                .map(String::as_str),
            Some("cell_tower=2, surveillance=1")
        );

        // First node: classified cell_tower with name/operator/osm_id evidence.
        let n1 = &out[1];
        assert!(n1.has_tag("infra:cell_tower"));
        assert_eq!(
            n1.evidence[0]
                .attributes
                .get("operator")
                .map(String::as_str),
            Some("Telstra")
        );
        assert_eq!(
            n1.evidence[0].attributes.get("osm_id").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn build_entities_caps_nodes_but_counts_all_in_summary() {
        let els: Vec<OsmElement> = elements(&format!(
            "[{}]",
            (0..MAX_NODES + 10)
                .map(|i| format!(
                    r#"{{"type":"node","id":{i},"lat":{},"lon":151.0,"tags":{{"man_made":"mast"}}}}"#,
                    -33.0 - i as f64 / 1000.0
                ))
                .collect::<Vec<_>>()
                .join(",")
        ));
        let out = build_entities("-33.0,151.0", &els, "s");
        // Summary node_count reflects ALL elements...
        assert_eq!(
            out[0].evidence[0]
                .attributes
                .get("node_count")
                .map(String::as_str),
            Some(&(MAX_NODES + 10).to_string()[..])
        );
        // ...but only MAX_NODES node entities are emitted (+1 summary).
        assert_eq!(out.len(), MAX_NODES + 1);
        // ...and the category breakdown counts EVERY node, not just the emitted
        // subset, so it can never contradict node_count (all mast → cell_tower).
        assert_eq!(
            out[0].evidence[1]
                .attributes
                .get("categories")
                .map(String::as_str),
            Some(&format!("cell_tower={}", MAX_NODES + 10)[..])
        );
    }

    #[test]
    fn way_and_relation_located_via_centroid_with_osm_type() {
        // A substation mapped as a WAY (no own lat/lon) carries a center; a node
        // carries its own coords. Both must be located, and tagged by osm type.
        let els = elements(
            r#"[
              {"type":"way","id":10,"center":{"lat":-33.87,"lon":151.21},
               "tags":{"power":"substation","operator":"Ausgrid"}},
              {"type":"node","id":11,"lat":-33.8702,"lon":151.2103,
               "tags":{"amenity":"police","name":"Sydney City"}}
            ]"#,
        );
        let out = build_entities("-33.87,151.21", &els, "s");
        // Summary + 2 located nodes (the way resolved via its centroid).
        assert_eq!(out.len(), 3);

        let way = &out[1];
        assert_eq!(way.value, "-33.870000,151.210000");
        assert!(way.has_tag("infra:substation"));
        assert!(way.has_tag("osm:way"));
        assert_eq!(way.evidence[0].attributes.get("osm_type").map(String::as_str), Some("way"));

        let node = &out[2];
        assert!(node.has_tag("infra:police") && node.has_tag("osm:node"));
    }

    #[test]
    fn element_without_coords_or_center_is_skipped() {
        // A relation with neither lat/lon nor a resolvable center contributes to
        // the count but yields no located node entity.
        let els = elements(
            r#"[{"type":"relation","id":20,"tags":{"amenity":"fire_station"}}]"#,
        );
        let out = build_entities("-33.0,151.0", &els, "s");
        assert_eq!(out.len(), 1, "only the summary — the unlocatable relation is skipped");
        assert_eq!(
            out[0].evidence[0].attributes.get("node_count").map(String::as_str),
            Some("1")
        );
    }
