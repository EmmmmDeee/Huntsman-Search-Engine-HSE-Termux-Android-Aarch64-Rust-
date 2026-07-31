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

/// `hse export --format csv` then `hse audit --csv` must round-trip values
/// byte-for-byte.
///
/// The exporter defangs spreadsheet formula injection by prepending `'` to any
/// value starting with `= + - @ TAB CR '` (OWASP guidance — a hostile
/// `first_name = "=cmd|'/c calc'!A1"` would otherwise be RCE on the operator's
/// workstation when they open the file). `csv_escape`'s own doc calls that a
/// "clean bijection", and the import path reverses it. This parser did not, so
/// the guard leaked into the audited data:
///
///   * a southern-hemisphere coordinate `-33.8688,151.2093` audited as
///     `'-33.8688,151.2093`, which `parse_coords` cannot read — so the finding
///     vanished from the geo cross-validation that is the whole point of
///     auditing coordinates;
///   * an E.164 phone `+61...` audited as `'+61...`, failing the same validity
///     shape the phone rules apply.
///
/// Every affected value is one an Australian-focused OSINT tool sees constantly.
#[test]
fn csv_audit_reverses_the_export_formula_guard() {
    use crate::api::scan_export::csv_escape;

    // The exact values an export would defang, escaped by the real exporter so
    // this test cannot drift from the escaping it is meant to invert.
    let cases = [
        ("coordinates", "-33.8688,151.2093"),
        ("phone", "+61712345678"),
        ("person", "=cmd|'/c calc'!A1"),
        ("username", "@handle"),
        ("domain", "'quoted.example"),
        ("email", "plain@example.com"), // untouched by the guard
    ];

    let mut csv = String::from("kind,value,confidence,c_effective,corroboration,sources,tags\n");
    for (kind, value) in cases {
        csv.push_str(&format!(
            "{},{},0.900,0.900,1,test,\n",
            csv_escape(kind),
            csv_escape(value)
        ));
    }

    let parsed = super::parse_csv(&csv).expect("parse");
    assert_eq!(parsed.len(), cases.len(), "every row must parse");
    for (got, (kind, want)) in parsed.iter().zip(cases) {
        assert_eq!(got.kind, kind);
        assert_eq!(
            got.value, want,
            "value must survive the export guard unchanged; a leading apostrophe here \
             means the audit is analysing a value the scan never found"
        );
    }
}

/// The audited coordinate must actually be parseable — the consequence the test
/// above exists to prevent, asserted against the real geo path rather than
/// inferred from the string.
#[test]
fn a_guarded_negative_coordinate_still_reaches_the_geo_audit() {
    use crate::api::scan_export::csv_escape;

    let mut csv = String::from("kind,value,confidence,c_effective,corroboration,sources,tags\n");
    for coord in ["-33.8688,151.2093", "-33.8700,151.2100"] {
        csv.push_str(&format!(
            "coordinates,{},0.900,0.900,1,exif_geo,\n",
            csv_escape(coord)
        ));
    }
    let parsed = super::parse_csv(&csv).expect("parse");
    let report = crate::audit::audit(&parsed, crate::audit::LogSignals::default());
    assert_eq!(
        report.geo.coord_count, 2,
        "both guarded coordinates must be recognised as coordinates by the geo audit"
    );
}
