use super::*;

use super::super::parse::SdnKind;

/// A real remarks string shape from the live SDN.CSV: identity data first, then
/// a run of `;`-separated address clauses with OFAC's `alt. ` prefix on every
/// address after the first.
const REMARKS_MULTI: &str = "DOB 01 Jan 1980; nationality Russia; Digital Currency Address - XBT \
                             1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; alt. Digital Currency Address - \
                             XBT 1BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; alt. Digital Currency \
                             Address - ETH 0xAbCdEf0123456789AbCdEf0123456789AbCdEf01; Secondary \
                             sanctions risk: this person.";

fn record(ent_num: u64, name: &str, remarks: &str) -> SdnRecord {
    SdnRecord {
        ent_num,
        name: name.to_string(),
        kind: SdnKind::Individual,
        program: "CYBER2".to_string(),
        title: String::new(),
        remarks: remarks.to_string(),
    }
}

#[test]
fn extracts_every_address_including_alt_prefixed_ones() {
    let found = digital_currency_addresses(REMARKS_MULTI);
    assert_eq!(
        found.len(),
        3,
        "the first clause plus both `alt. ` clauses must all be read, got {found:?}"
    );
    assert_eq!(found[0].symbol, "XBT");
    assert_eq!(found[0].address, "1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(found[1].address, "1BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    assert_eq!(found[2].symbol, "ETH");
    assert_eq!(
        found[2].address, "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
        "the address must be kept verbatim — EIP-55 case is data, not noise"
    );
}

#[test]
fn non_address_clauses_and_empty_remarks_yield_nothing() {
    assert!(digital_currency_addresses("").is_empty());
    assert!(
        digital_currency_addresses("DOB 01 Jan 1980; nationality Russia; passport 123456").is_empty(),
        "identity clauses are not address designations"
    );
}

#[test]
fn malformed_clauses_are_skipped_not_guessed_at() {
    // Symbol but no address, address but no symbol, and a three-token payload —
    // none of these are the documented grammar, so none may produce a finding.
    let remarks = "Digital Currency Address - XBT; \
                   Digital Currency Address - ; \
                   Digital Currency Address - XBT 1AAA extra; \
                   Digital Currency Address - XBT 1GOODGOODGOODGOODGOODGOODGOODGOOD";
    let found = digital_currency_addresses(remarks);
    assert_eq!(found.len(), 1, "only the well-formed clause survives: {found:?}");
    assert_eq!(found[0].address, "1GOODGOODGOODGOODGOODGOODGOODGOOD");
}

#[test]
fn evm_addresses_match_case_insensitively_in_both_directions() {
    let checksummed = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01";
    let lowercase = "0xabcdef0123456789abcdef0123456789abcdef01";
    let uppercase = "0xABCDEF0123456789ABCDEF0123456789ABCDEF01";
    // The screening false negative this exists to prevent: an operator pastes
    // the all-lowercase form their wallet or explorer showed them, while OFAC
    // published the EIP-55 checksummed form.
    assert!(addresses_match(checksummed, lowercase));
    assert!(addresses_match(lowercase, checksummed));
    assert!(addresses_match(checksummed, uppercase));
    // A `0X` prefix is the same address written by a different tool.
    assert!(addresses_match(checksummed, "0XABCDEF0123456789ABCDEF0123456789ABCDEF01"));
    // Same length, one hex digit different — still not a match.
    assert!(!addresses_match(
        checksummed,
        "0xabcdef0123456789abcdef0123456789abcdef02"
    ));
}

#[test]
fn base58_addresses_are_case_sensitive() {
    // Base58's alphabet contains both cases as DISTINCT characters. Folding
    // these would manufacture a sanctions match OFAC never made — the worse of
    // the two failure directions.
    let btc = "1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert!(!addresses_match(btc, &btc.to_ascii_lowercase()));
    assert!(addresses_match(btc, btc));
    let sol = "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH";
    assert!(!addresses_match(sol, &sol.to_ascii_uppercase()));
}

#[test]
fn a_hex_string_without_the_0x_prefix_is_not_folded() {
    // Only `0x…` is treated as EVM hex. A bare hex blob could be anything, and
    // case-folding it would widen matching on a value whose encoding is unknown.
    let bare = "AbCdEf0123456789AbCdEf0123456789AbCdEf01";
    assert!(!addresses_match(bare, &bare.to_ascii_lowercase()));
}

#[test]
fn screen_address_returns_every_co_designating_row() {
    // One wallet, two SDN rows — a co-designation. Returning only the first
    // would hide a party OFAC tied to the same address.
    let shared = "1SHAREDSHAREDSHAREDSHAREDSHAREDSHA";
    let records = vec![
        record(1, "ALPHA, Ann", &format!("Digital Currency Address - XBT {shared}")),
        record(2, "BETA, Bob", "DOB 02 Feb 1982"),
        record(
            3,
            "GAMMA, Gia",
            &format!("nationality Iran; alt. Digital Currency Address - XBT {shared}"),
        ),
    ];
    let hits = screen_address(&records, shared);
    assert_eq!(hits.len(), 2, "both designating rows must come back");
    assert_eq!(hits[0].0.ent_num, 1);
    assert_eq!(hits[1].0.ent_num, 3);
    assert!(hits.iter().all(|(_, sa)| sa.symbol == "XBT"));
}

#[test]
fn screen_address_ignores_surrounding_whitespace_and_rejects_a_blank_query() {
    let records = vec![record(
        7,
        "DELTA, Dan",
        "Digital Currency Address - LTC LAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )];
    assert_eq!(
        screen_address(&records, "  LAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \t").len(),
        1
    );
    // A blank query must never match every row that happens to carry an address.
    assert!(screen_address(&records, "   ").is_empty());
    assert!(screen_address(&records, "").is_empty());
}

#[test]
fn screen_address_matches_the_checksummed_designation_from_a_lowercase_query() {
    let records = vec![record(
        9,
        "EPSILON, Eve",
        "Digital Currency Address - ETH 0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
    )];
    let hits = screen_address(&records, "0xabcdef0123456789abcdef0123456789abcdef01");
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].1.address, "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
        "the designation is reported as OFAC published it, not as the operator typed it"
    );
}
