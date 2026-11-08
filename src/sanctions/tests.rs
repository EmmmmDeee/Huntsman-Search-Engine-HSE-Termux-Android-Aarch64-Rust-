use super::*;
use crate::test_support::RoutedTransport;

/// Rows shaped like the live OFAC export on 2026-11-07, with its trailing end-of-file byte.
const SDN: &str = "20157,\"KIM, Jong Un\",\"individual\",\"DPRK3\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"DOB 08 Jan 1984; nationality Korea, North.\"\r\n\
8279,\"BOUT, Viktor Anatolijevitch\",\"individual\",\"DRCONGO\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"DOB 13 Jan 1967; POB Dushanbe, Tajikistan.\"\r\n\
306,\"BANCO NACIONAL DE CUBA\",-0- ,\"CUBA\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"a.k.a. 'BNC'.\"\r\n\x1a";
const ALT: &str =
    "8279,1,\"aka\",\"BUTT, Victor\",-0- \r\n306,220,\"aka\",\"NATIONAL BANK OF CUBA\",-0- \r\n";
const UN_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CONSOLIDATED_LIST><INDIVIDUALS>\
<INDIVIDUAL><FIRST_NAME>ERIC</FIRST_NAME><SECOND_NAME>BADEGE</SECOND_NAME><UN_LIST_TYPE>DRC</UN_LIST_TYPE>\
<REFERENCE_NUMBER>CDi.001</REFERENCE_NUMBER><LISTED_ON>2012-12-31</LISTED_ON>\
<NATIONALITY><VALUE>Democratic Republic of the Congo</VALUE></NATIONALITY>\
<INDIVIDUAL_ALIAS><QUALITY/><ALIAS_NAME/></INDIVIDUAL_ALIAS>\
<INDIVIDUAL_DATE_OF_BIRTH><TYPE_OF_DATE>EXACT</TYPE_OF_DATE><YEAR>1971</YEAR></INDIVIDUAL_DATE_OF_BIRTH>\
</INDIVIDUAL></INDIVIDUALS><ENTITIES><ENTITY><FIRST_NAME>AL-QAIDA &amp; ASSOCIATES</FIRST_NAME>\
<REFERENCE_NUMBER>QDe.004</REFERENCE_NUMBER><ENTITY_ALIAS><ALIAS_NAME>THE BASE</ALIAS_NAME></ENTITY_ALIAS>\
</ENTITY></ENTITIES></CONSOLIDATED_LIST>";

/// Rows shaped like the live EU export on 2026-11-07: a byte-order mark, `;` separators and one
/// row per name and birth date of a subject. Eric Badege's two rows are one subject; KHARBOUTLI
/// holds the letters "bout" without the word.
const EU_CSV: &str = "\u{feff}fileGenerationDate;Entity_LogicalId;Entity_EU_ReferenceNumber;Entity_SubjectType;Entity_Regulation_Programme;NameAlias_FirstName;NameAlias_LastName;NameAlias_WholeName;BirthDate_BirthDate;Citizenship_CountryDescription\r\n\
07/11/2026;7200;EU.3606.65;P;COD;Eric;Badege;Eric Badege;1971-01-01;Democratic Republic of the Congo\r\n\
07/11/2026;7200;EU.3606.65;P;COD;;;Eric BADEGE;1971-01-01;Democratic Republic of the Congo\r\n\
07/11/2026;110142;EU.3843.7;P;SYR;;;Mohammed Zahir KHARBOUTLI;;Syria\r\n";

fn lists() -> Lists {
    Lists::new(
        Box::new(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, SDN),
            (OFAC_ALT.url, 200, ALT),
            (UN_SC.url, 200, UN_XML),
            (EU_FSF.url, 200, EU_CSV),
        ])),
        None,
    )
}

fn values(entities: &[Entity]) -> Vec<&str> {
    entities.iter().map(|e| e.raw_value.as_str()).collect()
}

#[test]
fn a_listing_matches_only_when_it_carries_every_word_of_the_name() {
    let (entities, outcomes) = check(&lists(), "Kim Jong Un", "scan", 1);
    assert_eq!(
        values(&entities),
        ["https://sanctionssearch.ofac.treas.gov/Details.aspx?id=20157"]
    );
    assert_eq!(entities[0].kind, EntityKind::Document);
    let evidence = &entities[0].evidence[0];
    assert_eq!(
        evidence.attributes.get("program").map(String::as_str),
        Some("DPRK3")
    );
    assert!(evidence.attributes["remarks"].contains("DOB 08 Jan 1984"));
    assert_eq!(outcomes.len(), 3);
    assert_eq!(outcomes[0].module, OFAC);
    assert_eq!(outcomes[0].kind, SourceOutcomeKind::Success);
    assert_eq!(outcomes[1].module, UN);
    assert_eq!(outcomes[1].kind, SourceOutcomeKind::ValidZero);
    assert_eq!(outcomes[2].module, EU);
    assert_eq!(outcomes[2].kind, SourceOutcomeKind::ValidZero);
    // A namesake carrying only some of the words is never a match.
    let (none, _) = check(&lists(), "Kim Jong Il", "scan", 1);
    assert!(none.is_empty(), "{:?}", values(&none));
}

#[test]
fn an_alias_matches_and_the_whole_listing_is_kept() {
    let (entities, _) = check(&lists(), "Victor Butt", "scan", 1);
    assert_eq!(
        values(&entities),
        ["https://sanctionssearch.ofac.treas.gov/Details.aspx?id=8279"]
    );
    let evidence = &entities[0].evidence[0];
    assert_eq!(
        evidence.attributes.get("matched_name").map(String::as_str),
        Some("BUTT, Victor")
    );
    assert!(evidence.attributes["remarks"].contains("POB Dushanbe"));
}

#[test]
fn the_un_list_is_read_with_its_name_parts_entities_and_escapes() {
    let (entities, outcomes) = check(&lists(), "Eric Badege", "scan", 1);
    let un: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.raw_value.starts_with("https://scsanctions.un.org/"))
        .collect();
    assert_eq!(
        un.iter().map(|e| e.raw_value.as_str()).collect::<Vec<_>>(),
        ["https://scsanctions.un.org/resources/xml/en/consolidated.xml#CDi.001"]
    );
    let evidence = &un[0].evidence[0];
    assert_eq!(
        evidence.attributes.get("nationality").map(String::as_str),
        Some("Democratic Republic of the Congo")
    );
    assert_eq!(
        evidence.attributes.get("date_of_birth").map(String::as_str),
        Some("1971")
    );
    assert_eq!(outcomes[1].kind, SourceOutcomeKind::Success);
    let (entity, _) = check(&lists(), "Al-Qaida Associates", "scan", 1);
    assert_eq!(
        entity.len(),
        1,
        "&amp; is unescaped and the entity block read"
    );
    let (alias, _) = check(&lists(), "The Base", "scan", 1);
    assert_eq!(alias.len(), 1, "an entity alias matches");
}

#[test]
fn no_lists_consults_nothing_and_a_failed_download_is_never_a_clean_zero() {
    let (entities, outcomes) = check(&Lists::none(), "Kim Jong Un", "scan", 1);
    assert!(entities.is_empty() && outcomes.is_empty());

    let silent = Lists::new(Box::new(RoutedTransport::new(&[])), None);
    let (entities, outcomes) = check(&silent, "Kim Jong Un", "scan", 1);
    assert!(entities.is_empty());
    assert_eq!(outcomes.len(), 3);
    for outcome in outcomes {
        assert_ne!(outcome.kind, SourceOutcomeKind::ValidZero, "{outcome:?}");
        assert_ne!(outcome.kind, SourceOutcomeKind::Success, "{outcome:?}");
    }
}

#[test]
fn a_single_word_name_asks_nothing() {
    let (entities, outcomes) = check(&lists(), "Kim", "scan", 1);
    assert!(entities.is_empty() && outcomes.is_empty());
}

#[test]
fn the_eu_list_groups_a_subject_s_rows_and_matches_only_whole_words() {
    let (entities, outcomes) = check(&lists(), "Eric Badege", "scan", 1);
    let eu: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.raw_value.ends_with("#EU.3606.65"))
        .collect();
    assert_eq!(eu.len(), 1, "two rows of one subject are one listing");
    assert_eq!(
        eu[0].evidence.len(),
        1,
        "one record per subject, not one per row"
    );
    let evidence = &eu[0].evidence[0];
    assert_eq!(
        evidence.attributes.get("alias").map(String::as_str),
        Some("Eric BADEGE"),
        "every name a subject's rows carry is kept on its one listing"
    );
    assert_eq!(
        evidence.attributes.get("program").map(String::as_str),
        Some("COD")
    );
    assert_eq!(
        evidence.attributes.get("date_of_birth").map(String::as_str),
        Some("1971-01-01"),
        "a value repeated across a subject's rows is kept once"
    );
    assert_eq!(outcomes[2].kind, SourceOutcomeKind::Success);
    // The fixture lists him on the UN and EU lists (the live OFAC list names him too).
    assert_eq!(
        entities.len(),
        2,
        "one listing per authority that names him"
    );
    // "Viktor Bout" carries the letters of KHARBOUTLI but not its words: never a match.
    let (bout, _) = check(&lists(), "Viktor Bout", "scan", 1);
    assert!(
        bout.iter().all(|e| !e.raw_value.contains("EU.3843.7")),
        "{:?}",
        values(&bout)
    );
}

#[test]
fn a_failed_refresh_preserves_historical_matches_without_current_clearance() {
    let dir = std::env::temp_dir().join(format!(
        "hse-sanctions-stale-{}",
        crate::entity::scan_id("sanctions-test", "freshness")
    ));
    std::fs::create_dir_all(&dir).expect("test cache directory");
    let start = crate::clock::unix_now();
    let first = Lists::new(
        Box::new(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, SDN),
            (OFAC_ALT.url, 200, ALT),
            (UN_SC.url, 200, UN_XML),
        ])),
        Some(dir.clone()),
    );
    let (_, initial) = check(&first, "Kim Jong Un", "scan", start);
    assert_eq!(initial[0].kind, SourceOutcomeKind::Success);
    assert_eq!(initial[1].kind, SourceOutcomeKind::ValidZero);

    // Twenty-five hours later, every publisher is unreachable. The last valid copies
    // are still read, including the historical positive, but neither list is current.
    let offline = Lists::new(Box::new(RoutedTransport::new(&[])), Some(dir.clone()));
    let (previous, outcomes) = check(&offline, "Kim Jong Un", "scan", start + MAX_AGE + 1);
    assert_eq!(
        values(&previous),
        ["https://sanctionssearch.ofac.treas.gov/Details.aspx?id=20157"]
    );
    assert_eq!(outcomes.len(), 3);
    for outcome in &outcomes[..2] {
        assert_eq!(outcome.kind, SourceOutcomeKind::Inconclusive, "{outcome:?}");
        assert!(
            outcome
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("could not be downloaded again"),
            "{outcome:?}"
        );
    }
    assert_eq!(outcomes[0].found, Some(1));
    assert_eq!(outcomes[1].found, Some(0));
    std::fs::remove_dir_all(dir).expect("test cleanup");
}

#[test]
fn missing_ofac_aliases_cannot_prove_absence() {
    let partial = Lists::new(
        Box::new(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, SDN),
            (UN_SC.url, 200, UN_XML),
        ])),
        None,
    );
    let (entities, outcomes) = check(&partial, "Ada Lovelace", "scan", 1);
    assert!(entities.is_empty());
    assert_eq!(outcomes[0].module, OFAC);
    assert_eq!(outcomes[0].kind, SourceOutcomeKind::Inconclusive);
    assert!(
        outcomes[0]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("aliases unavailable")
    );
    assert_eq!(outcomes[1].kind, SourceOutcomeKind::ValidZero);
}

#[test]
fn a_match_cap_is_reported_never_a_silent_complete_success() {
    // 51 OFAC rows that all carry one name: the 50-match cap attaches 50 and the detail says one
    // more matched. A capped result is a Success that admits it was cut off, never a clean count.
    use std::fmt::Write as _;
    let mut sdn = String::new();
    for ent in 1000..1051 {
        let _ = write!(
            sdn,
            "{ent},\"COMMON, Name\",\"individual\",\"X\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- \r\n"
        );
    }
    sdn.push('\u{1a}');
    let sdn: &'static str = Box::leak(sdn.into_boxed_str());
    let capped = Lists::new(
        Box::new(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, sdn),
            (OFAC_ALT.url, 200, ""),
            (UN_SC.url, 200, UN_XML),
            (EU_FSF.url, 200, EU_CSV),
        ])),
        None,
    );
    let (entities, outcomes) = check(&capped, "Name Common", "scan", 1);
    let ofac: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.raw_value.starts_with("https://sanctionssearch.ofac"))
        .collect();
    assert_eq!(ofac.len(), 50, "at most the cap is attached");
    assert_eq!(outcomes[0].module, OFAC);
    assert_eq!(outcomes[0].kind, SourceOutcomeKind::Success);
    assert!(
        outcomes[0]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 more matching listings beyond the first 50 were not attached"),
        "{:?}",
        outcomes[0]
    );
}

#[test]
fn unreadable_rows_block_a_clean_zero() {
    // One readable listing that does not match, and one row too short to read: the subject could be
    // in the unreadable row, so the outcome is Inconclusive, never a clean valid_zero.
    const SHORT: &str = "306,\"BANCO NACIONAL DE CUBA\",-0- ,\"CUBA\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"a.k.a. 'BNC'.\"\r\n9,\"TOO FEW COLUMNS\"\r\n\x1a";
    let partial = Lists::new(
        Box::new(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, SHORT),
            (OFAC_ALT.url, 200, ""),
            (UN_SC.url, 200, UN_XML),
            (EU_FSF.url, 200, EU_CSV),
        ])),
        None,
    );
    let (_entities, outcomes) = check(&partial, "Jane Doe", "scan", 1);
    assert_eq!(outcomes[0].module, OFAC);
    assert_eq!(
        outcomes[0].kind,
        SourceOutcomeKind::Inconclusive,
        "{:?}",
        outcomes[0]
    );
    assert!(
        outcomes[0]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("rows could not be read"),
        "{:?}",
        outcomes[0]
    );
}
