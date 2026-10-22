//! Parser and command tests over hand-built byte streams, so no binary fixture is committed and the
//! whole XMP-packet and PDF `/Info` path -- including embedded GPS -- is exercised deterministically.

use std::fmt::Write as _;

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

/// XML's numeric character references (`&#xA;`, the line feed XMP writers put in a multi-line
/// description, and `&#169;`) are decoded in list items, element text and attribute values alike,
/// and an escaped ampersand is decoded once.
#[test]
fn numeric_character_references_in_xmp_are_decoded() {
    let packet = xmp_packet()
        .replace(
            "xmp:CreatorTool=\"Acme Scanner 3.0\"",
            "xmp:CreatorTool=\"Acme&#x20;Scanner &#51;.0\"",
        )
        .replace(
            "   <dc:title>",
            "   <dc:description>\n    <rdf:Alt>\n     \
             <rdf:li xml:lang=\"x-default\">line one&#xA;line two &#169; 2024</rdf:li>\n    \
             </rdf:Alt>\n   </dc:description>\n   \
             <dc:rights>&#169; Ada &amp;amp; co</dc:rights>\n   <dc:title>",
        );
    let mut jpeg = vec![0xFF, 0xD8];
    jpeg.extend_from_slice(packet.as_bytes());
    let parsed = parse(&jpeg);
    assert_eq!(
        field(&parsed, "dc:description"),
        Some("line one\nline two \u{a9} 2024")
    );
    assert_eq!(field(&parsed, "dc:rights"), Some("\u{a9} Ada &amp; co"));
    assert_eq!(field(&parsed, "xmp:CreatorTool"), Some("Acme Scanner 3.0"));
    assert_eq!(field(&parsed, "dc:title"), Some("Field & Stream Notes"));
}

/// XMP is XML, so its references are read by XML's rules and not HTML's. `&nbsp;` is not an XML
/// entity and stays as written, and so do `&#X41;` (an upper-case `x`), `&#+65;` (a sign), `&#0;`
/// and `&#x1;` (characters XML does not allow) and `&#xD800;` (a surrogate). The five named
/// entities and the numeric references to allowed characters decode, each once.
#[test]
fn xmp_references_are_read_by_xml_rules_not_html() {
    let packet = xmp_packet()
        .replace(
            "xmp:CreatorTool=\"Acme Scanner 3.0\"",
            "xmp:CreatorTool=\"Acme&nbsp;&#X41;&#+65;&#0;&#x1;&#169;\"",
        )
        .replace(
            "   <dc:title>",
            "   <dc:rights>[&nbsp;&#X41;&#+65;&#0;&#x1;&#xA;&#32;&amp;&#169;\
             &#xD800;]</dc:rights>\n   <dc:title>",
        );
    let mut jpeg = vec![0xFF, 0xD8];
    jpeg.extend_from_slice(packet.as_bytes());
    let parsed = parse(&jpeg);
    assert_eq!(
        field(&parsed, "xmp:CreatorTool"),
        Some("Acme&nbsp;&#X41;&#+65;&#0;&#x1;\u{a9}")
    );
    assert_eq!(
        field(&parsed, "dc:rights"),
        Some("[&nbsp;&#X41;&#+65;&#0;&#x1;\n &\u{a9}&#xD800;]")
    );
}

/// A reference that decodes to whitespace is trimmed as literal whitespace is. A list item that is
/// only a decoded space is empty and is dropped, and a value that ends in a decoded line feed does
/// not keep it.
#[test]
fn whitespace_a_reference_decodes_to_is_trimmed_like_literal_whitespace() {
    let packet = xmp_packet().replace(
        "   <dc:title>",
        "   <dc:subject>\n    <rdf:Bag>\n     <rdf:li>&#32;</rdf:li>\n     \
             <rdf:li>kept</rdf:li>\n    </rdf:Bag>\n   </dc:subject>\n   \
             <dc:format>\n    <rdf:Bag>\n     <rdf:li>&#32;</rdf:li>\n    </rdf:Bag>\n   \
             </dc:format>\n   <dc:description>\n    <rdf:Alt>\n     \
             <rdf:li xml:lang=\"x-default\">line one&#xA;</rdf:li>\n    </rdf:Alt>\n   \
             </dc:description>\n   <dc:rights>&#32;&#xA;</dc:rights>\n   <dc:title>",
    );
    let mut jpeg = vec![0xFF, 0xD8];
    jpeg.extend_from_slice(packet.as_bytes());
    let parsed = parse(&jpeg);
    assert_eq!(field(&parsed, "dc:subject"), Some("kept"));
    assert_eq!(field(&parsed, "dc:description"), Some("line one"));
    assert!(field(&parsed, "dc:format").is_none());
    assert!(field(&parsed, "dc:rights").is_none());
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

/// A tiny uncompressed PDF whose trailer names an `/Info` dictionary holding literal-string entries,
/// plus a `/TitleCase` decoy the delimiter guard must not mistake for `/Title`, and an incremental
/// update that rewrites the same object with a new `/Author`.
fn pdf_with_info() -> Vec<u8> {
    b"%PDF-1.7\n\
1 0 obj\n\
<< /TitleCase (decoy must not match) /Title (Field Notes) \
/Author (Ada Lovelace) /Producer (Acme PDF 2.1) \
/CreationDate (D:20240102030405Z) >>\n\
endobj\n\
trailer\n<< /Size 2 /Info 1 0 R >>\n\
%%EOF\n\
1 0 obj\n\
<< /TitleCase (decoy must not match) /Title (Field Notes) \
/Author (Grace Hopper) /Producer (Acme PDF 2.1) \
/CreationDate (D:20240102030405Z) >>\n\
endobj\n\
trailer\n<< /Size 2 /Info 1 0 R /Prev 9 >>\n\
%%EOF\n"
        .to_vec()
}

/// An uncompressed PDF whose `/Info` is object `info` and which also holds `extra` objects, with
/// the trailer naming `/Info info_ref`.
fn pdf(info: &str, extra: &str, info_ref: &str) -> Vec<u8> {
    format!(
        "%PDF-1.4\n1 0 obj\n{info}\nendobj\n{extra}\ntrailer\n<< /Size 9 /Info {info_ref} >>\n%%EOF"
    )
    .into_bytes()
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
    // The incremental update's newer copy of the `/Info` object wins, and the value it replaced
    // is still reported, as the prior revision's.
    assert_eq!(field(&parsed, "info:Author"), Some("Grace Hopper"));
    assert_eq!(field(&parsed, "info-prior:Author"), Some("Ada Lovelace"));
    assert_eq!(field(&parsed, "pdf:InfoRevisions"), Some("2"));
    // An unchanged value is the current one only, never repeated as a prior.
    assert!(field(&parsed, "info-prior:Title").is_none());
}

#[test]
fn reads_a_utf16be_hex_pdf_string() {
    // `/Title <FEFF0048 0049>` -> UTF-16BE BOM + "HI".
    let pdf = pdf("<< /Title <FEFF00480049> >>", "", "1 0 R");
    let parsed = parse(&pdf);
    assert_eq!(parsed.format, "PDF 1.4");
    assert_eq!(field(&parsed, "info:Title"), Some("HI"));
}

#[test]
fn an_octal_and_paren_literal_decodes() {
    // `\050` is `(`, `\051` is `)`, and a balanced inner pair survives.
    let pdf = pdf("<< /Title (a\\050b\\051 (c)) >>", "", "1 0 R");
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
    let huge = "A".repeat(crate::exif::MAX_METADATA_VALUE_BYTES * 2);
    let packet = format!(
        "<x:xmpmeta><rdf:RDF><rdf:Description xmlns:dc=\"d\" dc:rights=\"{huge}\">\
         </rdf:Description></rdf:RDF></x:xmpmeta>"
    );
    let parsed = parse(packet.as_bytes());
    let rights = field(&parsed, "dc:rights").expect("the capped field");
    assert!(
        rights.len() <= crate::exif::MAX_METADATA_VALUE_BYTES,
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

#[test]
fn an_outline_bookmark_title_is_never_the_document_title() {
    // A bookmark later in the file carries its own `/Title`; only the dictionary the trailer names
    // is the document's `/Info`. `11 0 obj` must not be taken for `1 0 obj` either.
    let pdf = pdf(
        "<< /Title (Quarterly Report) /Author (Ada) >>",
        "2 0 obj\n<< /Title (Chapter 9) /Parent 3 0 R >>\nendobj\n\
         11 0 obj\n<< /Title (Wrong Object) >>\nendobj",
        "1 0 R",
    );
    let parsed = parse(&pdf);
    assert_eq!(field(&parsed, "info:Title"), Some("Quarterly Report"));
    assert_eq!(field(&parsed, "info:Author"), Some("Ada"));
}

#[test]
fn an_info_dictionary_out_of_reach_reports_nothing_rather_than_a_guess() {
    // The trailer names object 7, which sits in a compressed object stream: no `/Title` elsewhere
    // in the file may stand in for it, and a PDF with no trailer `/Info` has no `/Info` fields.
    let compressed = pdf("<< /Title (Chapter 1) /Parent 3 0 R >>", "", "7 0 R");
    assert!(field(&parse(&compressed), "info:Title").is_none());
    let trailerless = b"%PDF-1.4\n<< /Title (Loose) >>\n%%EOF".to_vec();
    assert!(parse(&trailerless).fields.is_empty());
}

#[test]
fn an_encrypted_pdf_flags_its_info_rather_than_showing_ciphertext() {
    let mut pdf = pdf("<< /Title (\u{8f}\x01ciphertext) >>", "", "1 0 R");
    pdf.extend_from_slice(b"\ntrailer\n<< /Info 1 0 R /Encrypt 5 0 R >>\n%%EOF");
    let parsed = parse(&pdf);
    assert!(field(&parsed, "info:Title").is_none());
    assert!(
        field(&parsed, "pdf:Encrypted").is_some_and(|value| value.starts_with("true")),
        "{:?}",
        parsed.fields
    );
    // `/EncryptMetadata` alone is not an encryption dictionary reference.
    let plain = pdf_with_info();
    let mut decoy = plain.clone();
    decoy.extend_from_slice(b"<< /EncryptMetadata false >>");
    assert!(field(&parse(&decoy), "pdf:Encrypted").is_none());
}

/// An XMP packet in the shape Photoshop and GIMP write: the toolkit on `x:xmpmeta`, the source
/// document as `xmpMM:DerivedFrom` struct shorthand, `xmpMM:History` events in both the attribute
/// and the element struct form, a nested `exif:Flash` struct and an `rdf:resource` licence.
fn edit_history_packet() -> String {
    "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c140\">\
<rdf:RDF><rdf:Description rdf:about=\"\">\
<xmpMM:DocumentID>xmp.did:CHILD</xmpMM:DocumentID>\
<xmpMM:DerivedFrom stRef:documentID=\"xmp.did:PARENT\" stRef:instanceID=\"xmp.iid:P1\"/>\
<xmpMM:History><rdf:Seq>\
<rdf:li stEvt:action=\"created\" stEvt:softwareAgent=\"Adobe Photoshop 25.0\" \
stEvt:when=\"2024-03-01T10:00:00Z\"/>\
<rdf:li rdf:parseType=\"Resource\"><stEvt:action>saved</stEvt:action>\
<stEvt:softwareAgent>GIMP 2.10</stEvt:softwareAgent>\
<stEvt:when>2024-03-02T11:00:00Z</stEvt:when></rdf:li>\
</rdf:Seq></xmpMM:History>\
<exif:Flash rdf:parseType=\"Resource\"><exif:Fired>False</exif:Fired></exif:Flash>\
<cc:license rdf:resource=\"https://creativecommons.org/licenses/by/4.0/\"/>\
</rdf:Description></rdf:RDF></x:xmpmeta>"
        .to_owned()
}

#[test]
fn edit_history_lineage_and_structs_surface_as_fields() {
    let parsed = parse(edit_history_packet().as_bytes());
    assert_eq!(field(&parsed, "x:xmptk"), Some("Adobe XMP Core 5.6-c140"));
    assert_eq!(field(&parsed, "xmpMM:DocumentID"), Some("xmp.did:CHILD"));
    assert_eq!(field(&parsed, "stRef:documentID"), Some("xmp.did:PARENT"));
    assert_eq!(field(&parsed, "stRef:instanceID"), Some("xmp.iid:P1"));
    // One value per history event, in the order the events were written.
    assert_eq!(field(&parsed, "stEvt:action"), Some("created; saved"));
    assert_eq!(
        field(&parsed, "stEvt:softwareAgent"),
        Some("Adobe Photoshop 25.0; GIMP 2.10")
    );
    assert_eq!(
        field(&parsed, "stEvt:when"),
        Some("2024-03-01T10:00:00Z; 2024-03-02T11:00:00Z")
    );
    assert_eq!(field(&parsed, "exif:Fired"), Some("False"));
    assert_eq!(
        field(&parsed, "cc:license"),
        Some("https://creativecommons.org/licenses/by/4.0/")
    );
    // RDF syntax never surfaces as a field.
    assert!(parsed.fields.iter().all(|(k, _)| !k.starts_with("rdf:")));
}

#[test]
fn every_packet_is_read_and_a_repeated_value_is_kept_once() {
    // A PDF's document packet and an embedded image's packet each state a creator tool; the same
    // value stated twice is kept once.
    let packet = |tool: &str| {
        format!(
            "<x:xmpmeta><rdf:RDF><rdf:Description xmp:CreatorTool=\"{tool}\" \
             dc:format=\"application/pdf\"/></rdf:RDF></x:xmpmeta>"
        )
    };
    let file = format!(
        "%PDF-1.6\n{}\nstream bytes\n{}\n%%EOF",
        packet("Word 16"),
        packet("Camera 3")
    );
    let parsed = parse(file.as_bytes());
    assert_eq!(field(&parsed, "xmp:CreatorTool"), Some("Word 16; Camera 3"));
    assert_eq!(field(&parsed, "dc:format"), Some("application/pdf"));
}

#[test]
fn conflicting_gps_positions_yield_no_coordinates() {
    // Two packets disagreeing on the position: neither is asserted as the file's location.
    let mut file = jpeg_with_xmp();
    file.extend_from_slice(xmp_packet().replace("48,51.00N", "10,0.00N").as_bytes());
    assert!(parse(&file).gps.is_none());
    assert!(parse(&jpeg_with_xmp()).gps.is_some());
}

#[test]
fn a_hostile_packet_is_scanned_in_linear_time() {
    // Unclosed properties, unclosed lists and unterminated tags at the full packet bound, each once
    // with no close and once with a single distant close of every kind, so the list path is reached
    // too (lists never itemised, items never closed). A scanner that re-searches the rest of the
    // packet per tag takes minutes here; a linear one, milliseconds.
    let limit = super::MAX_XMP_BYTES - 128;
    let units = [
        "<a:b>",
        "<a:b><rdf:Seq>",
        "<a:b x:y",
        "<a:b><c:d>t</c:e>",
        "<a:b><rdf:Seq><rdf:li>t",
        "<a:b><rdf:Bag> <rdf:li/>",
        "<a:b><rdf:Seq><!--",
        "<a:b><rdf:Alt><?x ",
        "<a:b><rdf:Bag><!--c--><rdf:li>t</rdf:li><?p?>",
    ];
    for (unit, tail) in units.iter().flat_map(|unit| {
        [
            (unit, ""),
            (unit, "--> ?></rdf:li></rdf:Seq></rdf:Bag></rdf:Alt></a:b>"),
        ]
    }) {
        let mut packet = String::from("<x:xmpmeta>");
        while packet.len() < limit {
            packet.push_str(unit);
        }
        packet.push('>');
        packet.push_str(tail);
        packet.push_str("</x:xmpmeta>");
        let started = std::time::Instant::now();
        let parsed = parse(packet.as_bytes());
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "{unit:?} {tail:?}: {elapsed:?}"
        );
        assert!(parsed.fields.len() <= crate::exif::MAX_METADATA_FIELDS);
    }
}

#[test]
fn a_value_an_edit_removed_or_replaced_is_still_revealed() {
    // The original save names object 1 as `/Info`; an incremental update writes a fresh object 5,
    // drops `/Author` and renames the document, and its trailer names object 5. Both of the original
    // values are still in the file.
    let mut pdf = pdf(
        "<< /Title (Draft: layoffs Q3) /Author (J. Smith) /Producer (Word) >>",
        "",
        "1 0 R",
    );
    pdf.extend_from_slice(
        b"\n5 0 obj\n<< /Title (Quarterly Update) /Producer (Word) >>\nendobj\n\
          trailer\n<< /Size 6 /Info 5 0 R /Prev 100 >>\n%%EOF",
    );
    let parsed = parse(&pdf);
    assert_eq!(field(&parsed, "info:Title"), Some("Quarterly Update"));
    assert!(field(&parsed, "info:Author").is_none());
    assert_eq!(
        field(&parsed, "info-prior:Title"),
        Some("Draft: layoffs Q3")
    );
    assert_eq!(field(&parsed, "info-prior:Author"), Some("J. Smith"));
    assert!(field(&parsed, "info-prior:Producer").is_none());
    assert_eq!(field(&parsed, "pdf:InfoRevisions"), Some("2"));
}

#[test]
fn a_single_revision_reports_no_prior_values() {
    let parsed = parse(&pdf("<< /Title (Only) >>", "", "1 0 R"));
    assert_eq!(field(&parsed, "info:Title"), Some("Only"));
    assert!(
        parsed
            .fields
            .iter()
            .all(|(k, _)| !k.starts_with("info-prior:"))
    );
    assert!(field(&parsed, "pdf:InfoRevisions").is_none());
}

/// One PNG chunk: a four-byte big-endian length, the four-byte type, the body, and a four-byte CRC
/// placeholder (the parser does not validate the CRC, so any four bytes serve).
fn png_chunk(kind: &[u8], body: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::new();
    let length = u32::try_from(body.len()).unwrap_or_default();
    chunk.extend_from_slice(&length.to_be_bytes());
    chunk.extend_from_slice(kind);
    chunk.extend_from_slice(body);
    chunk.extend_from_slice(&[0, 0, 0, 0]);
    chunk
}

/// A PNG assembled from the signature, the given chunks, and a closing `IEND`.
fn png(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
    for chunk in chunks {
        data.extend_from_slice(chunk);
    }
    data.extend_from_slice(&png_chunk(b"IEND", &[]));
    data
}

/// A PNG with a `tEXt` (`Author`), an uncompressed `iTXt` (`Description`, non-ASCII UTF-8), a
/// compressed `iTXt` (`Comment`, which must be skipped) and a `tIME` chunk.
fn png_with_text() -> Vec<u8> {
    let mut author = b"Author".to_vec();
    author.push(0);
    author.extend_from_slice(b"Ada Lovelace");

    // iTXt: keyword NUL flag(0) method(0) lang NUL transkeyword NUL text(UTF-8).
    let mut description = b"Description".to_vec();
    description.push(0);
    description.extend_from_slice(&[0, 0]);
    description.push(0);
    description.push(0);
    description.extend_from_slice("Survey près du café".as_bytes());

    // iTXt with the compression flag set: its bytes must never be inflated.
    let mut comment = b"Comment".to_vec();
    comment.push(0);
    comment.extend_from_slice(&[1, 0]);
    comment.push(0);
    comment.push(0);
    comment.extend_from_slice(&[0x78, 0x9c, 0xde, 0xad]);

    let time = [0x07, 0xE8, 1, 2, 3, 4, 5];

    png(&[
        png_chunk(b"tEXt", &author),
        png_chunk(b"iTXt", &description),
        png_chunk(b"iTXt", &comment),
        png_chunk(b"tIME", &time),
    ])
}

#[test]
fn reads_png_textual_and_time_chunks() {
    let parsed = parse(&png_with_text());
    assert_eq!(parsed.format, "PNG");
    assert_eq!(field(&parsed, "png:Author"), Some("Ada Lovelace"));
    assert_eq!(
        field(&parsed, "png:Description"),
        Some("Survey près du café")
    );
    assert_eq!(
        field(&parsed, "png:ModificationTime"),
        Some("2024-01-02 03:04:05")
    );
    // A compressed iTXt is never inflated, so its keyword yields no field.
    assert!(field(&parsed, "png:Comment").is_none());
}

#[test]
fn a_png_surfaces_both_its_text_chunk_and_an_embedded_xmp_packet() {
    let mut software = b"Software".to_vec();
    software.push(0);
    software.extend_from_slice(b"Acme Editor 1.0");

    // The XMP packet carried as an uncompressed iTXt keyed XML:com.adobe.xmp.
    let mut xmp = b"XML:com.adobe.xmp".to_vec();
    xmp.push(0);
    xmp.extend_from_slice(&[0, 0]);
    xmp.push(0);
    xmp.push(0);
    xmp.extend_from_slice(xmp_packet().as_bytes());

    let parsed = parse(&png(&[
        png_chunk(b"tEXt", &software),
        png_chunk(b"iTXt", &xmp),
    ]));
    assert_eq!(parsed.format, "PNG");
    // The tEXt chunk is read as a png:* field.
    assert_eq!(field(&parsed, "png:Software"), Some("Acme Editor 1.0"));
    // The XMP packet inside the iTXt is read by the XMP scanner...
    assert_eq!(field(&parsed, "xmp:CreatorTool"), Some("Acme Scanner 3.0"));
    // ...and is not also dumped verbatim as a png: field.
    assert!(field(&parsed, "png:XML:com.adobe.xmp").is_none());
    // The embedded GPS still becomes a position.
    assert!(parsed.gps.is_some());
}

#[test]
fn a_truncated_png_chunk_is_a_clean_result_not_a_panic() {
    // A tEXt chunk whose declared length runs far past the end of the file.
    let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
    data.extend_from_slice(&1000u32.to_be_bytes());
    data.extend_from_slice(b"tEXt");
    data.extend_from_slice(b"Author\x00Ada");
    let parsed = parse(&data);
    assert_eq!(parsed.format, "PNG");
    // The over-long chunk is refused rather than read out of bounds, so nothing surfaces.
    assert!(parsed.fields.is_empty());
}

#[test]
fn a_comment_cannot_replace_the_last_trailer_info_reference() {
    let bytes = b"%PDF-1.4\n\
1 0 obj\n<< /Title (Original) >>\nendobj\n\
2 0 obj\n<< /Title (Forged) >>\nendobj\n\
trailer\n<< /Size 3 /Info 1 0 R >>\n\
% /Info 2 0 R\n\
% trailer << /Info 2 0 R >>\n\
startxref\n0\n%%EOF";
    let parsed = parse(bytes);
    assert_eq!(field(&parsed, "info:Title"), Some("Original"));
    assert!(field(&parsed, "info-prior:Title").is_none());
}

#[test]
fn an_unrelated_encrypt_name_does_not_suppress_public_pdf_info() {
    let bytes = b"%PDF-1.4\n\
1 0 obj\n<< /Title (Public) >>\nendobj\n\
2 0 obj\n<< /Encrypt 9 0 R >>\nendobj\n\
trailer\n<< /Size 3 /Info 1 0 R >>\n\
startxref\n0\n%%EOF";
    let parsed = parse(bytes);
    assert_eq!(field(&parsed, "info:Title"), Some("Public"));
    assert!(field(&parsed, "pdf:Encrypted").is_none());
}

/// A PDF 1.5 file whose trailer is a cross-reference stream: no `trailer` keyword, its `/Info`
/// reference in the `/Type /XRef` stream dictionary that `startxref` points at. `forged` is an
/// object that looks like one but that no `startxref` names.
fn pdf_with_xref_stream(forged: &str) -> Vec<u8> {
    let mut pdf = format!(
        "%PDF-1.5\n1 0 obj\n<< /Title (Thesis) /Author (Ada) >>\nendobj\n\
         2 0 obj\n<< /Title (Forged) >>\nendobj\n{forged}"
    )
    .into_bytes();
    let offset = pdf.len();
    pdf.extend_from_slice(
        b"5 0 obj\n<< /Type /XRef /Size 6 /W [1 2 1] /Root 3 0 R /Info 1 0 R /Length 4 >>\n\
          stream\n\x01\x00\x0f\x00\nendstream\nendobj\n",
    );
    pdf.extend_from_slice(format!("startxref\n{offset}\n%%EOF\n").as_bytes());
    pdf
}

#[test]
fn a_cross_reference_stream_trailer_names_the_info() {
    let parsed = parse(&pdf_with_xref_stream(""));
    assert_eq!(field(&parsed, "info:Title"), Some("Thesis"));
    assert_eq!(field(&parsed, "info:Author"), Some("Ada"));
}

#[test]
fn an_object_that_only_looks_like_a_cross_reference_stream_names_nothing() {
    // The forged XRef dictionary sits earlier in the file but no `startxref` points at it, so the
    // real one still decides, and neither its `/Info` nor its `/Encrypt` is read.
    let forged =
        "4 0 obj\n<< /Type /XRef /Info 2 0 R /Encrypt 9 0 R >>\nstream\nendstream\nendobj\n";
    let parsed = parse(&pdf_with_xref_stream(forged));
    assert_eq!(field(&parsed, "info:Title"), Some("Thesis"));
    assert!(field(&parsed, "info-prior:Title").is_none());
    assert!(field(&parsed, "pdf:Encrypted").is_none());
}

#[test]
fn xmp_gps_rejects_invalid_hemispheres_and_coordinate_components() {
    // A previous parse accepted any trailing letter as positive and normalised
    // minutes >= 60, silently turning invalid metadata into plausible GEOINT.
    for invalid in [
        "48,51Q",
        "48,51E",
        "48,60N",
        "48,-1N",
        "48,30,60N",
        "48,51,0,1N",
        "91N",
        "90,0.01N",
        "-48,51N",
        "NaNN",
        "infN",
    ] {
        let packet = xmp_packet().replace("48,51.00N", invalid);
        let parsed = parse(packet.as_bytes());
        assert!(parsed.gps.is_none(), "accepted invalid latitude {invalid}");
    }
    for invalid in [
        "2,20Q",
        "2,20N",
        "2,60E",
        "2,30,60E",
        "181E",
        "180,0.01E",
        "-2,20E",
        "NaNE",
    ] {
        let packet = xmp_packet().replace("2,20.00E", invalid);
        let parsed = parse(packet.as_bytes());
        assert!(parsed.gps.is_none(), "accepted invalid longitude {invalid}");
    }
}

#[test]
fn xmp_gps_accepts_lowercase_and_valid_world_boundaries() {
    let packet = xmp_packet()
        .replace("48,51.00N", "90n")
        .replace("2,20.00E", "180w");
    let (lat, lon) = parse(packet.as_bytes())
        .gps
        .expect("valid boundary position");
    assert!((lat - 90.0).abs() < f64::EPSILON);
    assert!((lon + 180.0).abs() < f64::EPSILON);

    let packet = xmp_packet()
        .replace("48,51.00N", "48,30,30s")
        .replace("2,20.00E", "2,15,15e");
    let (lat, lon) = parse(packet.as_bytes()).gps.expect("valid DMS position");
    assert!((lat + 48.508_333).abs() < 0.000_001);
    assert!((lon - 2.254_166_667).abs() < 0.000_001);
}

#[test]
fn invalid_xmp_gps_never_becomes_a_coordinates_entity() {
    let packet = xmp_packet().replace("48,51.00N", "48,99N");
    match run(packet.as_bytes(), "invalid-gps.jpg", 1) {
        DocmetaRun::Printed { report, .. } => {
            assert!(
                report
                    .entities
                    .iter()
                    .any(|e| e.kind == EntityKind::Document)
            );
            assert!(
                report
                    .entities
                    .iter()
                    .all(|e| e.kind != EntityKind::Coordinates)
            );
        }
        DocmetaRun::Network(reason) | DocmetaRun::Failed(reason) => panic!("{reason}"),
    }
}

#[test]
fn the_word_at_a_time_search_finds_what_a_plain_scan_finds() {
    let naive = |haystack: &[u8], needle: &[u8]| {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }
        haystack.windows(needle.len()).position(|w| w == needle)
    };
    // A small alphabet makes partial matches, word-boundary straddles and repeats common.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..2000 {
        let len = usize::try_from(next() % 70).unwrap();
        let haystack: Vec<u8> = (0..len)
            .map(|_| b"ab<\xff"[usize::try_from(next() % 4).unwrap()])
            .collect();
        let needle_len = usize::try_from(next() % 5).unwrap();
        let needle: Vec<u8> = (0..needle_len)
            .map(|_| b"ab<\xff"[usize::try_from(next() % 4).unwrap()])
            .collect();
        assert_eq!(
            super::find_bytes(&haystack, &needle),
            naive(&haystack, &needle),
            "{haystack:?} {needle:?}"
        );
    }
    assert_eq!(super::find_bytes(b"", b""), None);
    assert_eq!(super::find_bytes(b"abc", b""), None);
    assert_eq!(super::find_bytes(b"ab", b"abc"), None);
    assert_eq!(
        super::find_bytes(b"0123456789trailer", b"trailer"),
        Some(10)
    );
}

/// A PDF whose `/Info` is object 1 (`info`) with the trailer dictionary `trailer`.
fn pdf_with_trailer(info: &str, trailer: &str) -> Vec<u8> {
    format!("%PDF-1.4\n1 0 obj\n{info}\nendobj\n2 0 obj\n<< /Title (Forged) >>\nendobj\ntrailer\n{trailer}\nstartxref\n9\n%%EOF\n")
        .into_bytes()
}

#[test]
fn a_trailer_key_written_inside_a_string_or_comment_is_not_a_key() {
    let info = "<< /Title (Real) /Author (Alice) >>";
    // An /Encrypt in a string or a comment neither flags the file nor hides its /Info.
    for trailer in [
        "<< /Root 3 0 R /Note (contact /Encrypt 9 0 R office) /Info 1 0 R >>",
        "<< /Root 3 0 R % /Encrypt 9 0 R\n/Info 1 0 R >>",
    ] {
        let parsed = parse(&pdf_with_trailer(info, trailer));
        assert!(field(&parsed, "pdf:Encrypted").is_none(), "{trailer}");
        assert_eq!(field(&parsed, "info:Title"), Some("Real"), "{trailer}");
    }
    // A forged /Info in a string or comment, before or after the real one, is no revision.
    for trailer in [
        "<< /Note (see /Info 2 0 R) /Info 1 0 R >>",
        "<< %cross ref /Info 2 0 R\n/Info 1 0 R >>",
        "<< /Info 1 0 R /Note (see /Info 2 0 R) >>",
        "<< /Info 1 0 R /Sub << /Info 2 0 R >> /Kids [/Info 2 0 R] >>",
    ] {
        let parsed = parse(&pdf_with_trailer(info, trailer));
        assert_eq!(field(&parsed, "info:Title"), Some("Real"), "{trailer}");
        assert!(field(&parsed, "info-prior:Title").is_none(), "{trailer}");
        assert!(field(&parsed, "pdf:InfoRevisions").is_none(), "{trailer}");
    }
}

#[test]
fn a_comment_inside_a_dictionary_is_whitespace() {
    // A `>>` or a lone `(` in a comment neither closes nor swallows the dictionary around it.
    for info in [
        "<< /Title (Hi) % note >> end\n /Author (Alice) >>",
        "<< /Title (Hi) % don't (worry\n /Author (Alice) >>",
        "<< /Title % the title follows\n (Hi) /Author (Alice) >>",
    ] {
        let parsed = parse(&pdf_with_trailer(info, "<< /Info 1 0 R >>"));
        assert_eq!(field(&parsed, "info:Title"), Some("Hi"), "{info}");
        assert_eq!(field(&parsed, "info:Author"), Some("Alice"), "{info}");
    }
    let parsed = parse(&pdf_with_trailer(
        "<< /Title (Hi) >>",
        "<< /Root 3 0 R % xref >>\n /Info 1 0 R >>",
    ));
    assert_eq!(field(&parsed, "info:Title"), Some("Hi"));
}

#[test]
fn countless_unclosed_trailers_are_scanned_in_linear_time() {
    // Each unclosed `trailer <<` used to cost a 256 KiB dictionary scan, so ~860 KB of them took
    // ~13 s in a release build. The trailer pass now reads the newest keywords within one budget.
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Title (Kept) >>\nendobj\n".to_vec();
    while pdf.len() < 4 * 1024 * 1024 {
        pdf.extend_from_slice(b"trailer <<\n");
    }
    let started = std::time::Instant::now();
    let parsed = parse(&pdf);
    let elapsed = started.elapsed();
    assert!(elapsed < std::time::Duration::from_secs(10), "{elapsed:?}");
    assert!(field(&parsed, "info:Title").is_none());
    // The real trailer after the junk still decides.
    pdf.extend_from_slice(b"trailer\n<< /Info 1 0 R >>\nstartxref\n9\n%%EOF\n");
    assert_eq!(field(&parse(&pdf), "info:Title"), Some("Kept"));
}

#[test]
fn a_png_text_chunk_after_thousands_of_image_chunks_is_read() {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut chunk = |kind: &[u8; 4], body: &[u8]| {
        png.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        png.extend_from_slice(kind);
        png.extend_from_slice(body);
        png.extend_from_slice(&[0; 4]);
    };
    chunk(b"IHDR", &[0; 13]);
    for _ in 0..5000 {
        chunk(b"IDAT", &[0; 8]);
    }
    chunk(b"tEXt", b"Author\0Jane Doe");
    chunk(b"IEND", &[]);
    assert_eq!(field(&parse(&png), "png:Author"), Some("Jane Doe"));
}

#[test]
fn junk_trailer_lines_never_cost_the_real_trailer_its_scan() {
    // A PDF 1.5 file whose trailer is a cross-reference stream, after a stream holding eight
    // unclosed `trailer <<` lines each followed by more than a dictionary scan's worth of bytes.
    // Every dictionary has its own scan window, so the junk cannot use up the real trailer's.
    let mut junk = Vec::new();
    for _ in 0..8 {
        junk.extend_from_slice(b"trailer <<\n");
        junk.extend(std::iter::repeat_n(b'A', 260 * 1024));
        junk.push(b'\n');
    }
    let mut pdf =
        b"%PDF-1.5\n4 0 obj\n<< /Title (Secret Plan) /Author (Alice) >>\nendobj\n".to_vec();
    pdf.extend_from_slice(format!("5 0 obj\n<< /Length {} >>\nstream\n", junk.len()).as_bytes());
    pdf.extend_from_slice(&junk);
    pdf.extend_from_slice(b"endstream\nendobj\n");
    let xref = pdf.len();
    pdf.extend_from_slice(
        b"6 0 obj\n<< /Type /XRef /Size 7 /Info 4 0 R /Length 0 >>\nstream\n\nendstream\nendobj\n",
    );
    pdf.extend_from_slice(format!("startxref\n{xref}\n%%EOF\n").as_bytes());
    let parsed = parse(&pdf);
    assert_eq!(field(&parsed, "info:Title"), Some("Secret Plan"));
    assert_eq!(field(&parsed, "info:Author"), Some("Alice"));
}

#[test]
fn a_bare_trailer_word_takes_no_place_from_a_real_trailer() {
    // A linearized-style file names /Info only in its first trailer; a stream after it holds many
    // text lines that start with the word "trailer" but open no dictionary.
    let mut text = String::new();
    for n in 0..200 {
        writeln!(text, "trailer {n} arrived at dock 4").unwrap();
    }
    let pdf = format!(
        "%PDF-1.4\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 6 /Info 4 0 R >>\nstartxref\n9\n%%EOF\n\
4 0 obj\n<< /Title (Secret Plan) >>\nendobj\n5 0 obj\n<< /Length {} >>\nstream\n{text}endstream\nendobj\n\
xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 6 >>\nstartxref\n9\n%%EOF\n",
        text.len()
    );
    assert_eq!(
        field(&parse(pdf.as_bytes()), "info:Title"),
        Some("Secret Plan")
    );
}

#[test]
fn a_comment_or_processing_instruction_inside_a_list_is_skipped() {
    let packet = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
<rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\n\
<dc:creator><rdf:Seq>\n <!-- primary author -->\n <rdf:li>Jane Doe</rdf:li>\n</rdf:Seq></dc:creator>\n\
<dc:subject><rdf:Bag>\n <rdf:li>protest</rdf:li>\n <?editor added?>\n <rdf:li>Kyiv</rdf:li>\n</rdf:Bag></dc:subject>\n\
<dc:rights><rdf:Alt><rdf:li xml:lang=\"x-default\">CC-BY</rdf:li><!-- trailing --></rdf:Alt></dc:rights>\n\
</rdf:Description></rdf:RDF></x:xmpmeta>\n";
    let parsed = parse(packet.as_bytes());
    assert_eq!(field(&parsed, "dc:creator"), Some("Jane Doe"));
    assert_eq!(field(&parsed, "dc:subject"), Some("protest; Kyiv"));
    assert_eq!(field(&parsed, "dc:rights"), Some("CC-BY"));
}

#[test]
fn a_forward_search_that_moves_back_searches_again() {
    let mut search = super::Forward::new("-->");
    let text = "a-->b-->c";
    assert_eq!(search.find(text, 5), Some(5));
    assert_eq!(search.find(text, 0), Some(1));
    assert_eq!(search.find(text, 2), Some(5));
    assert_eq!(search.find(text, 9), None);
    assert_eq!(search.find(text, 3), Some(5));
}

/// A JPEG with a main XMP packet and an extended XMP packet split into `APP1` chunks at `cuts`, the
/// chunks stored in the order `order`.
fn jpeg_with_extended_xmp(extended: &str, cuts: &[usize], order: &[usize]) -> Vec<u8> {
    let segment = |jpeg: &mut Vec<u8>, payload: &[u8]| {
        jpeg.extend_from_slice(&[0xFF, 0xE1]);
        jpeg.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap().to_be_bytes());
        jpeg.extend_from_slice(payload);
    };
    let mut jpeg = vec![0xFF, 0xD8];
    let main = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
<rdf:Description rdf:about=\"\" xmlns:xmpNote=\"http://ns.adobe.com/xmp/note/\" xmpNote:HasExtendedXMP=\"0123456789ABCDEF0123456789ABCDEF\"/>\
</rdf:RDF></x:xmpmeta>";
    segment(
        &mut jpeg,
        &[
            b"http://ns.adobe.com/xap/1.0/\0".as_slice(),
            main.as_bytes(),
        ]
        .concat(),
    );
    let mut bounds = vec![0];
    bounds.extend_from_slice(cuts);
    bounds.push(extended.len());
    for &chunk in order {
        let (start, end) = (bounds[chunk], bounds[chunk + 1]);
        let mut payload = b"http://ns.adobe.com/xmp/extension/\0".to_vec();
        payload.extend_from_slice(b"0123456789ABCDEF0123456789ABCDEF");
        payload.extend_from_slice(&u32::try_from(extended.len()).unwrap().to_be_bytes());
        payload.extend_from_slice(&u32::try_from(start).unwrap().to_be_bytes());
        payload.extend_from_slice(&extended.as_bytes()[start..end]);
        segment(&mut jpeg, &payload);
    }
    jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0x11, 0x22, 0xFF, 0xD9]);
    jpeg
}

#[test]
fn an_extended_xmp_list_split_across_segments_is_read_whole() {
    let ancestors: Vec<String> = (0..40)
        .map(|n| format!("adobe:docid:photoshop:{n:04x}-0d37"))
        .collect();
    let mut items = String::new();
    for id in &ancestors {
        write!(items, "\n            <rdf:li>{id}</rdf:li>").unwrap();
    }
    let extended = format!(
        "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\">\
<photoshop:DocumentAncestors><rdf:Bag>{items}\n</rdf:Bag></photoshop:DocumentAncestors>\
</rdf:Description></rdf:RDF></x:xmpmeta>"
    );
    // Splits inside an item's open tag, in the indentation between items, and inside a close tag:
    // each lost the list or an item before.
    let open = extended.match_indices("<rdf:li>").nth(5).unwrap().0 + 4;
    let indent = extended.match_indices("\n      ").nth(15).unwrap().0 + 3;
    let close = extended.match_indices("</rdf:li>").nth(30).unwrap().0 + 5;
    let jpeg = jpeg_with_extended_xmp(&extended, &[open, indent, close], &[1, 0, 3, 2]);
    let parsed = parse(&jpeg);
    assert_eq!(
        field(&parsed, "photoshop:DocumentAncestors"),
        Some(ancestors.join("; ").as_str())
    );
    assert_eq!(
        field(&parsed, "xmpNote:HasExtendedXMP"),
        Some("0123456789ABCDEF0123456789ABCDEF")
    );
}

#[test]
fn trailers_packed_with_info_references_are_read_in_linear_time() {
    // Sixteen closed trailer dictionaries, each 256 KiB of distinct `/Info N G R` entries: some
    // 290 000 references. Deduplicating each against all the others took minutes; only the newest
    // MAX_INFO_REVISIONS distinct ones are kept, so each is checked against at most that many.
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Title (Kept) >>\nendobj\n".to_vec();
    let mut n = 1000u32;
    for _ in 0..16 {
        pdf.extend_from_slice(b"trailer\n<< ");
        let start = pdf.len();
        while pdf.len() - start < 256 * 1024 - 300 {
            pdf.extend_from_slice(format!("/Info {} {} R", n / 1000, n % 1000).as_bytes());
            n += 1;
        }
        pdf.extend_from_slice(b" >>\n");
    }
    pdf.extend_from_slice(b"trailer\n<< /Info 1 0 R >>\nstartxref\n9\n%%EOF\n");
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sent.send(field(&parse(&pdf), "info:Title").map(str::to_owned));
    });
    let title = received
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the parse finishes in bounded time");
    assert_eq!(title.as_deref(), Some("Kept"));
}
