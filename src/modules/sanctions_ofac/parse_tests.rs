use super::*;

// Real rows pulled live from OFAC's SDN.CSV on 2026-07-09 (see module doc).

const ROW_INDIVIDUAL: &str = r#"2674,"ABBAS, Abu","individual","SDGT","Director of PALESTINE LIBERATION FRONT - ABU ABBAS FACTION",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"DOB 10 Dec 1948; Secondary sanctions risk: section 1(b) of Executive Order 13224, as amended by Executive Order 13886; Director of PALESTINE LIBERATION FRONT - ABU ABBAS FACTION.""#;

const ROW_ORGANISATION_BLANK_TYPE: &str =
    r#"36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- "#;

const ROW_ORGANISATION_WITH_REMARKS: &str =
    r#"306,"BANCO NACIONAL DE CUBA",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"a.k.a. 'BNC'.""#;

const ROW_VESSEL: &str = r#"4238,"MAR AZUL","vessel","CUBA",-0- ,"CL2192","Tug",-0- ,"212","Cuba","Samir de Navegacion S.A.",-0-"#;

const ROW_ORG_WITH_COMMA_IN_NAME: &str =
    r#"480,"CECOEX, S.A.",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- "#;

#[test]
fn split_csv_line_handles_quoted_and_bare_fields() {
    let fields = split_csv_line(ROW_INDIVIDUAL);
    assert_eq!(fields.len(), 12, "expected 12 fields, got {fields:?}");
    assert_eq!(fields[0], "2674");
    assert_eq!(fields[1], "ABBAS, Abu");
    assert_eq!(fields[2], "individual");
    assert_eq!(fields[3], "SDGT");
    assert!(fields[5].trim() == "-0-");
}

#[test]
fn split_csv_line_keeps_comma_inside_quoted_field_as_one_field() {
    // "CECOEX, S.A." must stay ONE field (name), not split into two at the
    // internal comma — the quote-tracking state machine is what makes this work.
    let fields = split_csv_line(ROW_ORG_WITH_COMMA_IN_NAME);
    assert_eq!(fields.len(), 12, "expected 12 fields, got {fields:?}");
    assert_eq!(fields[1], "CECOEX, S.A.");
}

#[test]
fn parse_individual_row_maps_correctly() {
    let rec = parse_sdn_line(ROW_INDIVIDUAL).expect("row should parse");
    assert_eq!(rec.ent_num, 2674);
    assert_eq!(rec.name, "ABBAS, Abu");
    assert_eq!(rec.kind, SdnKind::Individual);
    assert_eq!(rec.program, "SDGT");
    assert_eq!(rec.title, "Director of PALESTINE LIBERATION FRONT - ABU ABBAS FACTION");
    assert!(rec.remarks.contains("DOB 10 Dec 1948"));
}

#[test]
fn parse_organisation_row_with_blank_type_maps_correctly() {
    // Blank SDN_Type is the organisation bucket, NOT skipped/misclassified.
    let rec = parse_sdn_line(ROW_ORGANISATION_BLANK_TYPE).expect("row should parse");
    assert_eq!(rec.ent_num, 36);
    assert_eq!(rec.name, "AEROCARIBBEAN AIRLINES");
    assert_eq!(rec.kind, SdnKind::Organisation);
    assert_eq!(rec.program, "CUBA");
    assert_eq!(rec.title, "", "the -0- title placeholder must normalise to empty");
    assert_eq!(rec.remarks, "", "the -0- remarks placeholder must normalise to empty");
}

#[test]
fn parse_organisation_row_keeps_real_remarks() {
    let rec = parse_sdn_line(ROW_ORGANISATION_WITH_REMARKS).expect("row should parse");
    assert_eq!(rec.name, "BANCO NACIONAL DE CUBA");
    assert_eq!(rec.kind, SdnKind::Organisation);
    assert_eq!(rec.remarks, "a.k.a. 'BNC'.");
}

#[test]
fn parse_vessel_row_is_classified_as_vessel_not_organisation() {
    let rec = parse_sdn_line(ROW_VESSEL).expect("row should parse");
    assert_eq!(rec.name, "MAR AZUL");
    assert_eq!(rec.kind, SdnKind::Vessel);
    assert_eq!(rec.program, "CUBA");
}

#[test]
fn parse_sdn_csv_skips_blank_lines_and_keeps_valid_rows() {
    let body = format!("\n{ROW_INDIVIDUAL}\n\n{ROW_ORGANISATION_BLANK_TYPE}\n");
    let recs = parse_sdn_csv(&body);
    assert_eq!(recs.len(), 2);
}

#[test]
fn parse_sdn_csv_drops_malformed_rows_without_panicking() {
    let body = format!("{ROW_INDIVIDUAL}\nnot,enough,fields\n{ROW_VESSEL}\n,,");
    let recs = parse_sdn_csv(&body);
    // Only the two well-formed rows survive; malformed rows are silently dropped.
    assert_eq!(recs.len(), 2);
}

#[test]
fn humanise_name_reorders_surname_first() {
    assert_eq!(humanise_name("ABBAS, Abu"), "Abu Abbas");
    assert_eq!(humanise_name("AL ZAWAHIRI, Dr. Ayman"), "Dr. Ayman Al Zawahiri");
    // No comma → left as-is (title-cased), matching asic_persons' own fallback.
    assert_eq!(humanise_name("AEROCARIBBEAN AIRLINES"), "Aerocaribbean Airlines");
}

#[test]
fn name_tokens_requires_three_chars_and_lowercases() {
    let toks = name_tokens("Al Zawahiri");
    assert_eq!(toks, vec!["zawahiri"], "single-letter/short tokens dropped, rest lowercased");
    // Both tokens length >= 3 survive.
    let toks2 = name_tokens("Abu Abbas");
    assert_eq!(toks2, vec!["abu", "abbas"]);
}

#[test]
fn record_name_matches_requires_all_tokens_present() {
    let tokens = name_tokens("Abu Abbas");
    assert!(record_name_matches("ABBAS, Abu", &tokens));
    assert!(!record_name_matches("ABBAS, Someone Else", &tokens));
    assert!(!record_name_matches("Totally Unrelated Name", &tokens));
}

#[test]
fn record_name_matches_empty_tokens_never_matches() {
    assert!(!record_name_matches("ABBAS, Abu", &[]));
}
