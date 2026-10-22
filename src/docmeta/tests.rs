//! Parser and command tests over hand-built byte streams, so no binary fixture is committed and the
//! whole XMP-packet and PDF `/Info` path -- including embedded GPS -- is exercised deterministically.

use super::{DocmetaArgs, DocmetaRun, EntityKind, parse, run};

/// An XMP packet with `dc:creator` (a Seq list), a localised `dc:title`, two `xmp:*` attributes and
/// an embedded GPS position (48.85N, 2.3333E) as `exif:GPS*` attributes.
fn xmp_packet() -> String {
    "\
<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>
<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">
 <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">
  <rdf:Description rdf:about=\"\"
    xmlns:dc=\"http://purl.org/dc/elements/1.1/\"
    xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"
    xmlns:exif=\"http://ns.adobe.com/exif/1.0/\"
    xmp:CreatorTool=\"Acme Scanner 3.0\"
    xmp:CreateDate=\"2024-01-02T03:04:05Z\"
    exif:GPSLatitude=\"48,51.00N\"
    exif:GPSLongitude=\"2,20.00E\">
   <dc:creator>
    <rdf:Seq>
     <rdf:li>Ada Lovelace</rdf:li>
     <rdf:li>Alan Turing</rdf:li>
    </rdf:Seq>
   </dc:creator>
   <dc:title>
    <rdf:Alt>
     <rdf:li xml:lang=\"x-default\">Field &amp; Stream Notes</rdf:li>
    </rdf:Alt>
   </dc:title>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end=\"w\"?>"
        .to_owned()
}

/// A minimal JPEG carrying the XMP packet: just the SOI/EOI markers around the raw packet, which is
/// all the scanner needs to find `<x:xmpmeta>`.
fn jpeg_with_xmp() -> Vec<u8> {
    let mut jpeg = vec![0xFF, 0xD8];
    jpeg.extend_from_slice(xmp_packet().as_bytes());
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    jpeg
}

fn field<'a>(parsed: &'a super::Parsed, key: &str) -> Option<&'a str> {
    parsed
        .fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

#[test]
fn flattens_an_xmp_packet_into_prefixed_fields() {
    let parsed = parse(&jpeg_with_xmp());
    assert_eq!(parsed.format, "JPEG");
    assert_eq!(field(&parsed, "xmp:CreatorTool"), Some("Acme Scanner 3.0"));
    assert_eq!(
        field(&parsed, "xmp:CreateDate"),
        Some("2024-01-02T03:04:05Z")
    );
    // An rdf:Seq of authors is joined, not dropped.
    assert_eq!(
        field(&parsed, "dc:creator"),
        Some("Ada Lovelace; Alan Turing")
    );
    // An rdf:Alt localised title, with its XML entity unescaped.
    assert_eq!(field(&parsed, "dc:title"), Some("Field & Stream Notes"));
    // xmlns declarations and rdf:about are structural and never surface as fields.
    assert!(field(&parsed, "rdf:about").is_none());
    assert!(parsed.fields.iter().all(|(k, _)| !k.starts_with("xmlns")));
}

#[test]
fn reads_an_embedded_gps_position_from_xmp() {
    let parsed = parse(&jpeg_with_xmp());
    let (lat, lon) = parsed.gps.expect("a GPS position");
    assert!((lat - 48.85).abs() < 1e-6, "lat {lat}");
    assert!((lon - 2.333_333).abs() < 1e-5, "lon {lon}");
}

#[test]
fn a_southern_western_xmp_point_is_negative() {
    let packet = xmp_packet()
        .replace("48,51.00N", "48,51.00S")
        .replace("2,20.00E", "2,20.00W");
    let mut jpeg = vec![0xFF, 0xD8];
    jpeg.extend_from_slice(packet.as_bytes());
    let (lat, lon) = parse(&jpeg).gps.expect("a GPS position");
    assert!(lat < 0.0, "lat {lat}");
    assert!(lon < 0.0, "lon {lon}");
}

/// A tiny uncompressed PDF whose `/Info` dictionary holds literal-string entries, plus a `/TitleCase`
/// decoy the delimiter guard must not mistake for `/Title`, and an incremental `/Author` override.
fn pdf_with_info() -> Vec<u8> {
    b"%PDF-1.7\n\
1 0 obj\n\
<< /TitleCase (decoy must not match) /Title (Field Notes) \
/Author (Ada Lovelace) /Producer (Acme PDF 2.1) \
/CreationDate (D:20240102030405Z) >>\n\
endobj\n\
2 0 obj\n\
<< /Author (Grace Hopper) >>\n\
endobj\n\
%%EOF\n"
        .to_vec()
}

#[test]
fn reads_the_pdf_info_dictionary() {
    let parsed = parse(&pdf_with_info());
    assert_eq!(parsed.format, "PDF 1.7");
    assert_eq!(field(&parsed, "info:Title"), Some("Field Notes"));
    assert_eq!(field(&parsed, "info:Producer"), Some("Acme PDF 2.1"));
    assert_eq!(
        field(&parsed, "info:CreationDate"),
        Some("D:20240102030405Z")
    );
    // The `/TitleCase` decoy ends at a non-delimiter after `/Title`, so it never matches.
    assert_ne!(field(&parsed, "info:Title"), Some("decoy must not match"));
    // The later `/Author` in an incremental object wins.
    assert_eq!(field(&parsed, "info:Author"), Some("Grace Hopper"));
}

#[test]
fn reads_a_utf16be_hex_pdf_string() {
    // `/Title <FEFF0048 0049>` -> UTF-16BE BOM + "HI".
    let pdf = b"%PDF-1.4\n<< /Title <FEFF00480049> >>\n%%EOF".to_vec();
    let parsed = parse(&pdf);
    assert_eq!(parsed.format, "PDF 1.4");
    assert_eq!(field(&parsed, "info:Title"), Some("HI"));
}

#[test]
fn an_octal_and_paren_literal_decodes() {
    // `\050` is `(`, `\051` is `)`, and a balanced inner pair survives.
    let pdf = b"%PDF-1.5\n<< /Title (a\\050b\\051 (c)) >>\n%%EOF".to_vec();
    let parsed = parse(&pdf);
    assert_eq!(field(&parsed, "info:Title"), Some("a(b) (c)"));
}

#[test]
fn a_file_without_metadata_is_a_clean_empty_result() {
    let png = parse(b"\x89PNG\r\n\x1a\n and then nothing");
    assert_eq!(png.format, "PNG");
    assert!(png.fields.is_empty());
    assert!(png.gps.is_none());

    let unknown = parse(b"just some bytes");
    assert_eq!(unknown.format, "unknown");
    assert!(unknown.fields.is_empty());

    let empty = parse(&[]);
    assert_eq!(empty.format, "unknown");
    assert!(empty.fields.is_empty());
}

#[test]
fn run_emits_document_and_coordinates_entities() {
    match run(&jpeg_with_xmp(), "notes.jpg", 1) {
        DocmetaRun::Printed { text, report } => {
            assert!(text.contains("docmeta\tsuccess"), "{text}");
            assert!(
                report
                    .entities
                    .iter()
                    .any(|entity| entity.kind == EntityKind::Document),
                "no document entity in {:?}",
                report.entities
            );
            assert!(
                report
                    .entities
                    .iter()
                    .any(|entity| entity.kind == EntityKind::Coordinates),
                "no coordinates entity in {:?}",
                report.entities
            );
        }
        DocmetaRun::Network(why) | DocmetaRun::Failed(why) => panic!("{why}"),
    }
}

#[test]
fn run_on_a_plain_file_still_succeeds_with_a_document_entity() {
    match run(b"%PDF-1.7\n<< >>\n%%EOF", "empty.pdf", 1) {
        DocmetaRun::Printed { report, .. } => {
            assert!(
                report
                    .entities
                    .iter()
                    .any(|entity| entity.kind == EntityKind::Document),
                "a file always yields its document entity"
            );
            assert!(
                report
                    .entities
                    .iter()
                    .all(|entity| entity.kind != EntityKind::Coordinates),
                "no GPS, so no coordinates entity"
            );
        }
        DocmetaRun::Network(why) | DocmetaRun::Failed(why) => panic!("{why}"),
    }
}

#[test]
fn a_value_is_capped_and_fields_are_bounded() {
    let huge = "A".repeat(super::MAX_VALUE_BYTES * 2);
    let packet = format!(
        "<x:xmpmeta><rdf:RDF><rdf:Description xmlns:dc=\"d\" dc:rights=\"{huge}\">\
         </rdf:Description></rdf:RDF></x:xmpmeta>"
    );
    let parsed = parse(packet.as_bytes());
    let rights = field(&parsed, "dc:rights").expect("the capped field");
    assert!(
        rights.len() <= super::MAX_VALUE_BYTES,
        "len {}",
        rights.len()
    );
}

#[test]
fn args_parse_one_path_and_reject_the_rest() {
    assert_eq!(
        DocmetaArgs::parse(&["notes.pdf".into()]).unwrap().label,
        "notes.pdf"
    );
    assert!(DocmetaArgs::parse(&[]).is_err());
    assert!(DocmetaArgs::parse(&["a".into(), "b".into()]).is_err());
    assert!(DocmetaArgs::parse(&["   ".into()]).is_err());
}
