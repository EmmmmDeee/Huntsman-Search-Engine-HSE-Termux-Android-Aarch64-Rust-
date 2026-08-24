use super::*;

    #[test]
    fn csv_scan_id_conflict_note_names_the_winning_path() {
        let note = csv_scan_id_conflict_note("/tmp/export.csv");
        assert!(note.contains("--csv"));
        assert!(note.contains("--scan-id"));
        assert!(note.contains("/tmp/export.csv"));
    }

    #[test]
    fn csv_parses_old_format_header_driven() {
        let csv = "kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,tags\n\
            ip_address,172.66.147.185,172.66.147.185,0.950,1.000,258,VERIFIED,1780814281,dns_intel|shodan,cloudflare|hosting\n\
            email,jordanavery@gmail.com,jordanavery@gmail.com,0.850,1.000,4,VERIFIED,1780814282,oathnet_pro|smtp_vrfy,verified\n";
        let ents = parse_csv(csv).expect("should succeed");
        assert_eq!(ents.len(), 2);
        assert_eq!(ents[0].kind, "ip_address");
        assert_eq!(ents[0].corroboration, 258);
        assert_eq!(ents[0].sources, vec!["dns_intel", "shodan"]);
        assert!(ents[0].tags.contains(&"cloudflare".to_string()));
        assert_eq!(ents[1].value, "jordanavery@gmail.com");
    }

    #[test]
    fn csv_parses_new_format_with_evidence_columns() {
        // Header order differs and adds columns — must still map by name.
        let csv = "kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,evidence_urls,evidence,tags\n\
            domain,cloudflare.com,cloudflare.com,1.0,1.0,5,VERIFIED,1,whois,https://x,e,infra\n";
        let ents = parse_csv(csv).expect("should succeed");
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].kind, "domain");
        assert_eq!(ents[0].tags, vec!["infra"]);
    }

    #[test]
    fn csv_handles_quoted_commas() {
        let csv = "kind,value\nperson,\"Doe, Jane\"\n";
        let ents = parse_csv(csv).expect("should succeed");
        assert_eq!(ents[0].value, "Doe, Jane");
    }

    #[test]
    fn csv_handles_newline_inside_quoted_field() {
        // A quoted field containing a literal newline is a single record per
        // RFC 4180. The hand-rolled line splitter this parser replaced would
        // have torn this into two malformed rows; the csv crate keeps it whole.
        let csv = "kind,value,tags\nperson,\"Jane\nDoe\",\"vip|note\"\n";
        let ents = parse_csv(csv).expect("should succeed");
        assert_eq!(ents.len(), 1, "one record despite the embedded newline");
        assert_eq!(ents[0].value, "Jane\nDoe");
        assert!(ents[0].tags.contains(&"vip".to_string()));
    }

    #[test]
    fn log_text_extracts_engine_and_module_health() {
        let log = "\
2026-06-07T08:36:03Z INFO huntsman::engine_health: search engine liveness probe engine=\"google\" status=\"blocked\" detail=\"anti-bot\" results=0\n\
2026-06-07T08:36:04Z INFO huntsman::engine_health: search engine liveness probe engine=\"brave\" status=\"blocked\" detail=\"page carried ~13 links but the parser extracted 0 results — likely a PARSER defect\" results=0\n\
2026-06-07T08:36:05Z INFO huntsman::engine_health: liveness probe engine=\"mojeek\" status=\"down\" results=0\n\
2026-06-07T08:36:06Z WARN huntsman::core::engine: module error module=\"crtsh\" error=timeout\n";
        let s = parse_log(log);
        assert_eq!(s.lines_parsed, 4);
        assert_eq!(s.engines_blocked, vec!["google"]);
        assert_eq!(s.engine_parser_defects, vec!["brave"]);
        assert_eq!(s.engines_down, vec!["mojeek"]);
        assert_eq!(s.module_errors.get("crtsh"), Some(&1));
    }

    #[test]
    fn log_jsonl_events_are_ingested() {
        let log = "\
{\"type\":\"module_error\",\"module\":\"hibp\",\"error\":\"429\"}\n\
{\"type\":\"expansion_stop\",\"reason\":\"max_entities=200 reached\"}\n\
{\"type\":\"entity_excluded\",\"kind\":\"username\",\"value\":\"arizonambb\",\"reason\":\"identity_mismatch\"}\n\
{\"type\":\"entity_excluded\",\"kind\":\"username\",\"value\":\"centenario\",\"reason\":\"identity_mismatch\"}\n\
{\"type\":\"entity_excluded\",\"kind\":\"credential\",\"value\":\"x\",\"reason\":\"non_pivotable_kind\"}\n\
{\"engine\":\"qwant\",\"status\":\"blocked\",\"detail\":\"anti-bot\"}\n";
        let s = parse_log(log);
        assert_eq!(s.module_errors.get("hibp"), Some(&1));
        assert_eq!(s.expansion_stops, vec!["max_entities=200 reached"]);
        assert_eq!(s.engines_blocked, vec!["qwant"]);
        assert_eq!(s.excluded_reasons.get("identity_mismatch"), Some(&2));
        assert_eq!(s.excluded_reasons.get("non_pivotable_kind"), Some(&1));
    }

    #[test]
    fn field_extracts_quoted_and_bare_values() {
        assert_eq!(field("a status=\"blocked\" b", "status"), Some("blocked"));
        assert_eq!(field("a results=0 b", "results"), Some("0"));
        assert_eq!(field("no key here", "status"), None);
    }

    #[test]
    fn empty_scan_triggers_high_severity_exit_path() {
        // An empty entity list produces a HIGH "empty-result" finding — exactly
        // the condition that now causes cmd_audit to return Err (non-zero exit).
        let report = audit(&[], LogSignals::default());
        assert!(
            report
                .findings
                .iter()
                .any(|f| matches!(f.severity, Severity::Critical | Severity::High)),
            "empty-result should produce a HIGH finding that triggers non-zero exit"
        );
    }
