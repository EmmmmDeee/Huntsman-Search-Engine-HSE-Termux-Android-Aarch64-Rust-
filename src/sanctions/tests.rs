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

fn lists() -> Lists {
    Lists::new(
        Box::new(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, SDN),
            (OFAC_ALT.url, 200, ALT),
            (UN_SC.url, 200, UN_XML),
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
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0].module, OFAC);
    assert_eq!(outcomes[0].kind, SourceOutcomeKind::Success);
    assert_eq!(outcomes[1].module, UN);
    assert_eq!(outcomes[1].kind, SourceOutcomeKind::ValidZero);
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
    assert_eq!(
        values(&entities),
        ["https://scsanctions.un.org/resources/xml/en/consolidated.xml#CDi.001"]
    );
    let evidence = &entities[0].evidence[0];
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
    assert_eq!(outcomes.len(), 2);
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
    assert_eq!(outcomes.len(), 2);
    for outcome in &outcomes {
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
