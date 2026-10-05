// Tests for `util::iptc` — included as an inline module from iptc.rs.

use super::{ImageIptc, parse};

/// Build one IIM application-record (record 2) dataset: `0x1C 0x02 <ds> <len BE> <val>`.
fn dataset(ds: u8, val: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1C, 0x02, ds];
    out.extend_from_slice(&(val.len() as u16).to_be_bytes());
    out.extend_from_slice(val);
    out
}

/// Wrap IIM datasets in a Photoshop IRB with the IPTC (`0x0404`) `8BIM` resource,
/// exactly as a JPEG `APP13` segment carries it. `lead_ids` prepends unrelated
/// `8BIM` resources so the walker must skip past them to reach the IPTC one.
fn irb(datasets: &[Vec<u8>], lead_ids: &[u16]) -> Vec<u8> {
    let mut iim = Vec::new();
    for d in datasets {
        iim.extend_from_slice(d);
    }
    let mut irb = Vec::new();
    irb.extend_from_slice(b"Photoshop 3.0\0");
    // Unrelated resource blocks before the IPTC one (empty payloads).
    for &id in lead_ids {
        irb.extend_from_slice(b"8BIM");
        irb.extend_from_slice(&id.to_be_bytes());
        irb.extend_from_slice(&[0x00, 0x00]); // empty Pascal name (len 0 + pad)
        irb.extend_from_slice(&0u32.to_be_bytes()); // size 0
    }
    // The IPTC resource.
    irb.extend_from_slice(b"8BIM");
    irb.extend_from_slice(&0x0404u16.to_be_bytes());
    irb.extend_from_slice(&[0x00, 0x00]); // empty Pascal name
    irb.extend_from_slice(&(iim.len() as u32).to_be_bytes());
    irb.extend_from_slice(&iim);
    if iim.len() % 2 == 1 {
        irb.push(0x00); // even data padding
    }
    irb
}

#[test]
fn extracts_byline_keywords_location_and_caption() {
    let bytes = irb(
        &[
            dataset(80, b"Jane Roe"),                       // By-line
            dataset(25, b"portrait"),                        // Keyword
            dataset(25, b"John Doe"),                        // Keyword (a named subject)
            dataset(92, b"Opera House"),                     // Sub-location
            dataset(90, b"Sydney"),                          // City
            dataset(95, b"NSW"),                             // State
            dataset(101, b"Australia"),                      // Country
            dataset(120, b"Jane Roe photographs John Doe."), // Caption
        ],
        &[],
    );
    let m = parse(&bytes);
    assert_eq!(m.by_lines, vec!["Jane Roe".to_string()]);
    assert_eq!(m.keywords, vec!["portrait".to_string(), "John Doe".to_string()]);
    assert_eq!(
        m.location.as_deref(),
        Some("Opera House, Sydney, NSW, Australia")
    );
    assert_eq!(m.caption.as_deref(), Some("Jane Roe photographs John Doe."));
    assert!(!m.is_empty());
}

#[test]
fn a_non_image_or_stripped_image_is_empty() {
    // No Photoshop IRB signature anywhere → nothing extracted.
    assert!(parse(b"not an image, no IRB here").is_empty());
    assert!(parse(&[]).is_empty());
    assert_eq!(parse(b"plain bytes"), ImageIptc::default());
}

#[test]
fn stray_dataset_marker_in_pixel_data_is_not_parsed() {
    // The IIM dataset lead bytes 0x1C 0x02 appear, but NOT inside a Photoshop
    // IRB — so precision-anchoring means they are ignored, not mistaken for a
    // by-line. This is the false-positive guard that lets the module run on
    // real (compressed) image bytes safely.
    let pixelish = [
        0xFF, 0xD8, 0x1C, 0x02, 80, 0x00, 0x08, b'H', b'a', b'c', b'k', b'e', b'r', b'!', b'!',
        0xFF, 0xD9,
    ];
    assert!(parse(&pixelish).is_empty());
}

#[test]
fn ipct_resource_is_found_after_unrelated_8bim_blocks() {
    // Real files put resolution (0x03ED), thumbnail (0x040C) etc. before IPTC.
    let bytes = irb(&[dataset(80, b"Press Photographer")], &[0x03ED, 0x040C, 0x0425]);
    let m = parse(&bytes);
    assert_eq!(m.by_lines, vec!["Press Photographer".to_string()]);
}

#[test]
fn duplicate_bylines_are_deduplicated() {
    let bytes = irb(
        &[
            dataset(80, b"Same Name"),
            dataset(80, b"Same Name"),
            dataset(80, b"Other Name"),
        ],
        &[],
    );
    let m = parse(&bytes);
    assert_eq!(
        m.by_lines,
        vec!["Same Name".to_string(), "Other Name".to_string()]
    );
}

#[test]
fn an_over_length_field_is_rejected_as_junk() {
    // A 250-char "by-line" is a parser desync / junk, not a name (NAME_MAX=200).
    let long = vec![b'x'; 250];
    let bytes = irb(&[dataset(80, &long), dataset(80, b"Real Name")], &[]);
    let m = parse(&bytes);
    assert_eq!(m.by_lines, vec!["Real Name".to_string()]);
}

#[test]
fn latin1_high_bytes_are_preserved_not_replaced() {
    // 0xE9 is 'é' in Latin-1; a name is preserved rather than mangled to U+FFFD.
    let bytes = irb(&[dataset(80, &[b'R', b'e', b'n', 0xE9, b' ', b'C', b'o', b't', b'y'])], &[]);
    let m = parse(&bytes);
    assert_eq!(m.by_lines, vec!["Ren\u{e9} Coty".to_string()]);
}

#[test]
fn caption_only_is_not_empty_but_yields_no_byline() {
    // A caption without a by-line: present (is_empty false) but no name to emit —
    // the module keeps it as context only, never invents a Person from free text.
    let bytes = irb(&[dataset(120, b"An unattributed scene.")], &[]);
    let m = parse(&bytes);
    assert!(m.by_lines.is_empty());
    assert_eq!(m.caption.as_deref(), Some("An unattributed scene."));
    assert!(!m.is_empty());
}
