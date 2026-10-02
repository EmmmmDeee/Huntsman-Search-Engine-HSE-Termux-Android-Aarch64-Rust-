use super::*;

const HEADER: &str = "Registry,Assignment,Organization Name,Organization Address\n";

fn csv(rows: &str) -> Vec<u8> {
    format!("{HEADER}{rows}").into_bytes()
}

fn le_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

fn le_u16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(data[at..at + 2].try_into().unwrap())
}

#[test]
fn empty_csv_produces_an_empty_registry() {
    // No rows at all — the header-only case a fresh/truncated download could
    // produce. Must not panic or error; zero assignments is a valid registry.
    let out = build(&csv("")).expect("should succeed");
    assert_eq!(&out[..MAGIC.len()], MAGIC);
    assert_eq!(le_u32(&out, 8), 0, "count");
    assert_eq!(le_u32(&out, 12), 0, "vcount");
    assert_eq!(out.len(), 16 + 4); // header + the lone voff[0] entry
}

#[test]
fn missing_expected_headers_yields_zero_rows_not_an_error() {
    // A CSV with neither "Assignment" nor "Organization Name" columns at all
    // (a garbled download, or a future registry export change). Python's
    // `row.get("Assignment")` returns `None` -> "" for every row when the key
    // never exists, so every row fails the length check and is dropped —
    // the whole build degrades to an empty registry rather than erroring.
    let bytes = b"Foo,Bar\nMA-L,286FB9\n".to_vec();
    let out = build(&bytes).expect("should succeed");
    assert_eq!(le_u32(&out, 8), 0);
}

#[test]
fn lowercase_hex_assignment_is_accepted_and_uppercased() {
    let out = build(&csv("MA-L,286fb9,Acme Corp,addr\n")).expect("should succeed");
    assert_eq!(le_u32(&out, 8), 1);
    assert_eq!(le_u32(&out, 16), 0x0028_6FB9);
}

#[test]
fn non_hex_assignment_is_rejected() {
    let out = build(&csv("MA-L,28G6F9,Acme Corp,addr\n")).expect("should succeed");
    assert_eq!(le_u32(&out, 8), 0, "'G' is not a hex digit");
}

#[test]
fn wrong_length_assignment_is_rejected() {
    let short = build(&csv("MA-L,286FB,Acme Corp,addr\n")).expect("should succeed");
    assert_eq!(le_u32(&short, 8), 0, "5 hex chars");
    let long = build(&csv("MA-L,286FB99,Acme Corp,addr\n")).expect("should succeed");
    assert_eq!(le_u32(&long, 8), 0, "7 hex chars");
}

#[test]
fn organization_name_whitespace_is_collapsed_and_trimmed() {
    // A tab, a run of spaces, and an embedded newline (some real registry
    // rows carry one inside a quoted field) all fold to one space, and the
    // ends are trimmed — matching `" ".join(vendor.split())`.
    let out = build(&csv("MA-L,286FB9,\"  Acme\t Corp\n Ltd  \",addr\n")).expect("should succeed");
    let name = vendor_name(&out, 0);
    assert_eq!(name, "Acme Corp Ltd");
}

#[test]
fn empty_organization_name_is_rejected() {
    let out = build(&csv("MA-L,286FB9,,addr\n")).expect("should succeed");
    assert_eq!(le_u32(&out, 8), 0);
}

#[test]
fn private_and_ieee_registration_authority_placeholders_are_rejected_case_insensitively() {
    // These two strings identify nobody — the registry's placeholder for a
    // withheld name — so surfacing them as a vendor would read as an
    // attribution rather than the absence of one.
    for placeholder in ["Private", "PRIVATE", "private", "IEEE Registration Authority"] {
        let rows = format!("MA-L,286FB9,{placeholder},addr\n");
        let out = build(&csv(&rows)).expect("should succeed");
        assert_eq!(le_u32(&out, 8), 0, "{placeholder} must be filtered");
    }
}

#[test]
fn duplicate_assignment_keeps_the_first_vendor_seen() {
    // A duplicate assignment should not exist in a real registry; if the
    // input ever carries one, the output must be a pure function of input
    // ORDER, not last-write-wins, so re-running on the same bytes is
    // deterministic even if a future registry export reorders unrelated rows.
    let out = build(&csv(
        "MA-L,286FB9,First Vendor,addr\nMA-L,286FB9,Second Vendor,addr\n",
    ))
    .expect("should succeed");
    assert_eq!(le_u32(&out, 8), 1, "one prefix, not two");
    assert_eq!(vendor_name(&out, 0), "First Vendor");
}

#[test]
fn vendor_table_order_follows_ascending_prefix_not_csv_row_order() {
    // Three prefixes, deliberately fed OUT of ascending order and with the
    // vendor for the numerically-highest prefix appearing FIRST in the CSV.
    // If vendor ids were assigned in raw row order, "High" would get id 0;
    // the correct behaviour (matching the Python original's
    // `for p in sorted(seen): ...`) assigns ids by walking prefixes in
    // ASCENDING order, so "Low" (0x100000, the smallest) must get id 0.
    let out = build(&csv(
        "MA-L,FFFFFF,High,addr\nMA-L,100000,Low,addr\nMA-L,800000,Mid,addr\n",
    ))
    .expect("should succeed");
    assert_eq!(le_u32(&out, 8), 3);
    assert_eq!(le_u32(&out, 12), 3, "three distinct vendors");
    // prefixes[] must be ascending regardless of input row order.
    assert_eq!(le_u32(&out, 16), 0x0010_0000);
    assert_eq!(le_u32(&out, 20), 0x0080_0000);
    assert_eq!(le_u32(&out, 24), 0x00FF_FFFF);
    // vidx[] runs parallel to prefixes[] (header(16) + 3×u32 prefixes = 28).
    assert_eq!(le_u16(&out, 28), 0, "Low (lowest prefix) must claim vendor id 0");
    assert_eq!(le_u16(&out, 30), 1, "Mid");
    assert_eq!(le_u16(&out, 32), 2, "High");
    assert_eq!(vendor_name(&out, 0), "Low");
}

#[test]
fn shared_vendor_across_two_prefixes_gets_one_table_entry() {
    let out = build(&csv(
        "MA-L,100000,Acme,addr\nMA-L,200000,Acme,addr\n",
    ))
    .expect("should succeed");
    assert_eq!(le_u32(&out, 8), 2, "two assignments");
    assert_eq!(le_u32(&out, 12), 1, "one shared vendor entry");
}

#[test]
fn invalid_utf8_in_a_field_becomes_the_replacement_character_not_an_error() {
    // Mirrors the Python original's whole-stream `errors="replace"` decode:
    // a lone invalid byte degrades to U+FFFD rather than aborting the parse
    // or silently dropping the row.
    let mut bytes = HEADER.as_bytes().to_vec();
    bytes.extend_from_slice(b"MA-L,286FB9,Ac\xFFme,addr\n");
    let out = build(&bytes).expect("should succeed");
    assert_eq!(le_u32(&out, 8), 1);
    assert!(vendor_name(&out, 0).contains('\u{FFFD}'));
}

#[test]
fn ragged_rows_are_tolerated_not_an_error() {
    // A row with fewer fields than the header (a truncated download, or a
    // registry export quirk) must not abort the whole build — Python's
    // `DictReader` fills missing trailing fields with `None`.
    let bytes = format!("{HEADER}MA-L,286FB9\n");
    let out = build(bytes.as_bytes()).expect("should succeed");
    assert_eq!(le_u32(&out, 8), 0, "empty Organization Name -> rejected");
}

#[test]
fn byte_layout_is_exact_for_a_two_row_case() {
    // The strongest proof of the encoder: hand-derive every byte for a small,
    // fully worked example and assert the whole blob, not just field reads.
    // Two prefixes, two distinct vendors, "A" (1 byte) and "BB" (2 bytes).
    let out = build(&csv("MA-L,000001,A,addr\nMA-L,000002,BB,addr\n")).expect("should succeed");

    let mut expected = Vec::new();
    expected.extend_from_slice(MAGIC); // 8
    expected.extend_from_slice(&2u32.to_le_bytes()); // count
    expected.extend_from_slice(&2u32.to_le_bytes()); // vcount
    expected.extend_from_slice(&1u32.to_le_bytes()); // prefixes[0] = 0x000001
    expected.extend_from_slice(&2u32.to_le_bytes()); // prefixes[1] = 0x000002
    expected.extend_from_slice(&0u16.to_le_bytes()); // vidx[0] -> vendor 0 ("A")
    expected.extend_from_slice(&1u16.to_le_bytes()); // vidx[1] -> vendor 1 ("BB")
    // header(16) + prefixes(8) + vidx(4) = 28, already 4-aligned -> no pad.
    expected.extend_from_slice(&0u32.to_le_bytes()); // voff[0]
    expected.extend_from_slice(&1u32.to_le_bytes()); // voff[1] (end of "A")
    expected.extend_from_slice(&3u32.to_le_bytes()); // voff[2] (end of "BB")
    expected.extend_from_slice(b"A");
    expected.extend_from_slice(b"BB");

    assert_eq!(out, expected);
}

#[test]
fn byte_layout_is_exact_for_an_odd_count_that_needs_padding() {
    // An ODD assignment count is the padding branch the two-row case above
    // can never reach: header(16) + prefixes(4n) + vidx(2n) is 4-aligned
    // exactly when n is even (2n mod 4 == 0), and needs a 2-byte pad
    // otherwise. Three prefixes, three distinct one/two-char vendors.
    let out = build(&csv(
        "MA-L,000001,A,addr\nMA-L,000002,BB,addr\nMA-L,000003,C,addr\n",
    ))
    .expect("should succeed");

    let mut expected = Vec::new();
    expected.extend_from_slice(MAGIC);
    expected.extend_from_slice(&3u32.to_le_bytes()); // count
    expected.extend_from_slice(&3u32.to_le_bytes()); // vcount
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(&3u32.to_le_bytes());
    expected.extend_from_slice(&0u16.to_le_bytes());
    expected.extend_from_slice(&1u16.to_le_bytes());
    expected.extend_from_slice(&2u16.to_le_bytes());
    // header(16) + prefixes(12) + vidx(6) = 34 -> 2 bytes pad to reach 36.
    expected.extend_from_slice(&[0, 0]);
    expected.extend_from_slice(&0u32.to_le_bytes()); // voff[0]
    expected.extend_from_slice(&1u32.to_le_bytes()); // voff[1] (end of "A")
    expected.extend_from_slice(&3u32.to_le_bytes()); // voff[2] (end of "BB")
    expected.extend_from_slice(&4u32.to_le_bytes()); // voff[3] (end of "C")
    expected.extend_from_slice(b"ABBC");

    assert_eq!(out, expected);
}

#[test]
fn vendor_count_above_u16_width_is_a_named_error_not_a_silent_wraparound() {
    // One row per distinct vendor, one more than a u16 index can address.
    // Without the explicit guard this would silently wrap the id into
    // `vidx`, corrupting the vendor table rather than failing loudly.
    let want = usize::from(u16::MAX) + 1;
    let mut rows = String::with_capacity(want * 24);
    for i in 0..want {
        rows.push_str(&format!("MA-L,{i:06X},Vendor{i},addr\n"));
    }
    let err = build(&csv(&rows)).expect_err("must reject, not wrap around");
    assert!(err.contains("u16"), "error should name the actual limit: {err}");
}

/// Read vendor name `i` back out of a built blob — the same walk
/// `src/util/oui/ieee.rs::vendor_for` performs, reimplemented here rather
/// than imported so this test suite doesn't depend on the consumer crate
/// compiling first.
fn vendor_name(data: &[u8], i: usize) -> String {
    let count = le_u32(data, 8) as usize;
    let vcount = le_u32(data, 12) as usize;
    let voff_start = {
        let unpadded = 16 + count * 4 + count * 2;
        unpadded + (4 - unpadded % 4) % 4
    };
    let blob_start = voff_start + (vcount + 1) * 4;
    let start = le_u32(data, voff_start + i * 4) as usize;
    let end = le_u32(data, voff_start + (i + 1) * 4) as usize;
    String::from_utf8(data[blob_start + start..blob_start + end].to_vec()).unwrap()
}
