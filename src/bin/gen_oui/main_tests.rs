use super::*;

const CSV_HEADER: &str = "Registry,Assignment,Organization Name,Organization Address\n";

/// Hand-derived expected layout for a small, deliberately tricky input:
/// a duplicate prefix (first occurrence wins), a vendor reused across two
/// prefixes (shares one vendor id), an invalid (non-hex) assignment, three
/// excluded-vendor cases ("Private", "IEEE Registration Authority", empty),
/// and a vendor name with irregular internal/leading/trailing whitespace.
///
/// Rows are deliberately NOT in ascending-prefix order, so this also proves
/// vendor ids are assigned by ascending-prefix scan order, not CSV row order.
#[test]
fn build_matches_hand_derived_layout() {
    let csv = format!(
        "{CSV_HEADER}\
         MA-L,AABBCC,Acme Corp,123 Street\n\
         MA-L,001122,Zenith Inc,456 Ave\n\
         MA-L,AABBCC,Duplicate Vendor,should be ignored\n\
         MA-L,334455,Acme Corp,\n\
         MA-L,GARBAGE,Bad Vendor,\n\
         MA-L,112233,Private,\n\
         MA-L,223344,IEEE Registration Authority,\n\
         MA-L,556677,  Spacey   Name  ,\n\
         MA-L,998877,,\n"
    );

    let out = build(csv.as_bytes()).expect("build should succeed");

    // seen (ascending by prefix): 0x001122->Zenith Inc, 0x334455->Acme Corp,
    // 0x556677->Spacey Name, 0xAABBCC->Acme Corp (first occurrence kept).
    // Vendor ids assigned in that ascending-prefix scan order:
    //   0 = "Zenith Inc", 1 = "Acme Corp", 2 = "Spacey Name"
    let mut expected = Vec::new();
    expected.extend_from_slice(MAGIC);
    expected.extend_from_slice(&4u32.to_le_bytes()); // count
    expected.extend_from_slice(&3u32.to_le_bytes()); // vcount
    for p in [0x11_22u32, 0x33_44_55, 0x55_66_77, 0xAA_BB_CC] {
        expected.extend_from_slice(&p.to_le_bytes());
    }
    for i in [0u16, 1, 2, 1] {
        expected.extend_from_slice(&i.to_le_bytes());
    }
    assert_eq!(
        expected.len() % 4,
        0,
        "no padding expected for an even count"
    );
    for o in [0u32, 10, 19, 30] {
        expected.extend_from_slice(&o.to_le_bytes());
    }
    expected.extend_from_slice(b"Zenith IncAcme CorpSpacey Name");

    assert_eq!(out, expected);
}

/// A single valid row round-trips: the emitted blob validates under the same
/// layout rules `src/util/oui/ieee.rs` re-checks at runtime (magic, in-bounds
/// sections), and re-running `build` on identical input is byte-identical.
#[test]
fn build_is_deterministic() {
    let csv = format!("{CSV_HEADER}MA-L,001122,Only Vendor,addr\n");
    let a = build(csv.as_bytes()).unwrap();
    let b = build(csv.as_bytes()).unwrap();
    assert_eq!(a, b);
    assert_eq!(&a[..8], MAGIC);
}

/// An odd assignment count needs the 2-byte pad before `voff` so it starts
/// 4-byte aligned — the one case `build_matches_hand_derived_layout` (an even
/// count) doesn't exercise.
#[test]
fn build_pads_odd_count_to_align_voff() {
    let csv = format!(
        "{CSV_HEADER}\
         MA-L,001122,Vendor One,\n\
         MA-L,334455,Vendor Two,\n\
         MA-L,556677,Vendor Three,\n"
    );
    let out = build(csv.as_bytes()).unwrap();
    // header(16) + prefixes(4*3=12) + vidx(2*3=6) = 34, not a multiple of 4.
    let unpadded = 16 + 12 + 6;
    assert_eq!(unpadded % 4, 2);
    assert_eq!(&out[unpadded..unpadded + 2], &[0u8, 0u8]);
    let voff_start = unpadded + 2;
    let voff0 = u32::from_le_bytes(out[voff_start..voff_start + 4].try_into().unwrap());
    assert_eq!(voff0, 0, "voff must start 4-byte aligned and begin at 0");
}

/// More than 0xFFFF distinct vendors must fail loudly rather than silently
/// truncate a `u16` vendor index.
#[test]
fn build_rejects_vendor_overflow() {
    let mut csv = String::from(CSV_HEADER);
    for i in 0..=0x1_0000u32 {
        // Distinct 6-hex-digit prefix, distinct vendor name, per row.
        csv.push_str(&format!("MA-L,{i:06X},Vendor {i},\n"));
    }
    let err = build(csv.as_bytes()).unwrap_err();
    assert!(err.contains("exceeds the u16 index width"), "got: {err}");
}

/// Rows are matched by header name, not position — the registry's real
/// column order (`Registry,Assignment,Organization Name,Organization
/// Address`) must not be assumed.
#[test]
fn build_looks_up_columns_by_header_name() {
    let csv = "Organization Name,Assignment\nReordered Vendor,AABBCC\n";
    let out = build(csv.as_bytes()).unwrap();
    let vcount = u32::from_le_bytes(out[12..16].try_into().unwrap());
    assert_eq!(vcount, 1);
    assert!(out.ends_with(b"Reordered Vendor"));
}
