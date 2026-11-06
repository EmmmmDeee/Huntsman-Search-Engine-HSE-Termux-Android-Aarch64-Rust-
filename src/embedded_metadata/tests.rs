use super::*;
use crate::entity::EntityKind;
use crate::source_outcome::SourceOutcomeKind;
use crate::test_support::images::{
    GPS, ascii_value, exif_tiff, jpeg_with, jpeg_with_metadata, png_with_metadata,
    webp_with_metadata,
};

/// The value of `key` on the first evidence of `entity` that holds it.
fn attr<'a>(entity: &'a Entity, key: &str) -> Option<&'a str> {
    entity
        .evidence
        .iter()
        .find_map(|evidence| evidence.attributes.get(key).map(String::as_str))
}

fn found<'a>(inspected: &'a Inspected, kind: &EntityKind, value: &str) -> &'a Entity {
    inspected
        .entities
        .iter()
        .find(|entity| entity.kind == *kind && entity.value == value)
        .unwrap_or_else(|| panic!("no {kind:?} {value}: {:#?}", inspected.entities))
}

/// An XMP packet whose rights statement names an address, a web page and a phone number, inside
/// otherwise opaque bytes: the document reader finds XMP in any file.
fn file_with_rights() -> Vec<u8> {
    let mut file = b"\x00\x01binary prefix ".to_vec();
    file.extend_from_slice(
        br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:rights><rdf:Alt><rdf:li xml:lang="x-default">(c) Ada, ada@example.org, https://example.org/ada</rdf:li></rdf:Alt></dc:rights></rdf:Description></rdf:RDF></x:xmpmeta>"#,
    );
    file.extend_from_slice(b" \xff\xfe trailing");
    file
}

/// A JPEG whose Exif `Artist` field holds an address, as a camera owner sets it.
fn jpeg_with_artist(artist: &str) -> Vec<u8> {
    let artist = ascii_value(artist);
    jpeg_with(&exif_tiff(false, &[(0x013B, 2, &artist)], &[]), None)
}

/// The kinds and values of every entity found inside a metadata value, sorted.
fn found_in_values(inspected: &Inspected) -> Vec<(EntityKind, String)> {
    let mut found: Vec<(EntityKind, String)> = inspected
        .entities
        .iter()
        .filter(|entity| entity.tags.iter().any(|tag| tag == TAG))
        .map(|entity| (entity.kind.clone(), entity.value.clone()))
        .collect();
    found.sort_by(|a, b| a.1.cmp(&b.1));
    found
}

/// A phone's photo, as its camera and an editor leave it: serial numbers, a unique id, sub-second
/// and offset times and a software build in the Exif, and in the XMP the toolkit's version string,
/// document and instance ids, a creator tool and dates, beside the contact details and comment a
/// person wrote.
fn phone_photo() -> Vec<u8> {
    let make = ascii_value("Google");
    let model = ascii_value("Pixel 7 Pro");
    let software = ascii_value("HDR+ 1.0.540104767zd");
    let edited = ascii_value("2024:05:01 10:20:30");
    let description = ascii_value("Harbour at dusk, ISO 192, f/1.85 on 6.81mm, see example.org");
    let owner = ascii_value("Ada Lovelace");
    let body_serial = ascii_value("0412345678");
    let lens_serial = ascii_value("61412345678");
    let unique = ascii_value("a4f1c2d3e5b6a7980a1b2c3d4e5f6a7b");
    let subsec = ascii_value("123456");
    let offset = ascii_value("+10:00");
    let mut comment = b"ASCII\0\0\0".to_vec();
    comment.extend_from_slice(b"call 0398765432 after six");
    let tiff = exif_tiff(
        false,
        &[
            (0x010E, 2, &description),
            (0x010F, 2, &make),
            (0x0110, 2, &model),
            (0x0131, 2, &software),
            (0x0132, 2, &edited),
        ],
        &[
            (0x9010, 2, &offset),
            (0x9286, 7, &comment),
            (0x9290, 2, &subsec),
            (0xA420, 2, &unique),
            (0xA430, 2, &owner),
            (0xA431, 2, &body_serial),
            (0xA435, 2, &lens_serial),
        ],
    );
    let xmp = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 9.1-c001 79.1462899, 2023/06/25-20:01:55"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" xmlns:aux="http://ns.adobe.com/exif/1.0/aux/" xmlns:Iptc4xmpCore="http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/" xmp:CreatorTool="Darkroom 13.2 (https://example.net/darkroom)" xmp:CreateDate="2024-05-01T10:20:30.123+10:00" xmpMM:DocumentID="xmp.did:5b1c2e3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f" xmpMM:OriginalDocumentID="5B1C2E3F4A5B6C7D8E9F0A1B2C3D4E5F" photoshop:LegacyIPTCDigest="0412345678" aux:SerialNumber="0298765432" aux:OwnerName="Ada Lovelace"><Iptc4xmpCore:CreatorContactInfo Iptc4xmpCore:CiEmailWork="studio@example.org" Iptc4xmpCore:CiTelWork="+61 2 9876 5432" Iptc4xmpCore:CiUrlWork="https://example.org/portfolio"/></rdf:Description></rdf:RDF></x:xmpmeta>"#;
    jpeg_with(&tiff, Some(xmp))
}

#[test]
fn an_identifier_in_an_xmp_value_becomes_an_entity_attributed_to_its_field() {
    let inspected = inspect(&file_with_rights(), "scan.bin", 7).unwrap();
    for (kind, value) in [
        (EntityKind::Email, "ada@example.org"),
        (EntityKind::Url, "https://example.org/ada"),
    ] {
        let entity = found(&inspected, &kind, value);
        assert!(entity.tags.iter().any(|tag| tag == TAG), "{entity:?}");
        let evidence = &entity.evidence[0];
        assert_eq!(evidence.provenance.source, docmeta::SOURCE);
        assert_eq!(attr(entity, "source_file"), Some("scan.bin"));
        assert!(
            attr(entity, "metadata_field").is_some_and(|field| field.contains("rights")),
            "{entity:?}"
        );
    }
    // The value itself stays whole on the document entity: nothing is dropped or rewritten.
    assert!(inspected.entities.iter().any(|entity| {
        entity.kind == EntityKind::Document
            && entity.evidence.iter().any(|evidence| {
                evidence
                    .attributes
                    .values()
                    .any(|value| value.contains("ada@example.org, https://example.org/ada"))
            })
    }));
}

#[test]
fn an_identifier_in_an_exif_field_is_attributed_to_the_exif_reader_and_its_tag() {
    let inspected = inspect(&jpeg_with_artist("Ada <ada@example.org>"), "photo.jpg", 7).unwrap();
    let email = found(&inspected, &EntityKind::Email, "ada@example.org");
    assert_eq!(email.evidence[0].provenance.source, exif::SOURCE);
    assert_eq!(attr(email, "metadata_field"), Some("Artist"));
    assert_eq!(attr(email, "source_file"), Some("photo.jpg"));
}

#[test]
fn a_photo_keeps_its_gps_position_its_fields_and_both_readers_outcomes() {
    let inspected = inspect(&jpeg_with_metadata(), "photo.jpg", 7).unwrap();
    let coordinates: Vec<&Entity> = inspected
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Coordinates)
        .collect();
    assert!(!coordinates.is_empty(), "{:#?}", inspected.entities);
    let (lat, lon) = crate::geohash::parse_coords(&coordinates[0].value).unwrap();
    assert!(
        (lat - GPS.0).abs() < 1e-6 && (lon - GPS.1).abs() < 1e-6,
        "{lat},{lon}"
    );
    let sources: Vec<&str> = inspected
        .outcomes
        .iter()
        .map(|outcome| outcome.module.as_str())
        .collect();
    assert_eq!(sources, [exif::SOURCE, docmeta::SOURCE]);
    assert!(
        inspected
            .outcomes
            .iter()
            .all(|outcome| outcome.kind == SourceOutcomeKind::Success)
    );
    assert!(carries_metadata(&jpeg_with_metadata()));
}

#[test]
fn a_file_without_metadata_gets_the_document_reader_alone_and_no_invented_entities() {
    let text = b"plain notes with no embedded metadata";
    assert!(!carries_metadata(text));
    let inspected = inspect(text, "notes.txt", 7).unwrap();
    assert_eq!(inspected.outcomes.len(), 2);
    assert_eq!(inspected.outcomes[0].module, exif::SOURCE);
    assert_eq!(inspected.outcomes[0].kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(inspected.outcomes[1].module, docmeta::SOURCE);
    assert!(
        inspected
            .entities
            .iter()
            .all(|entity| entity.kind == EntityKind::Document),
        "{:#?}",
        inspected.entities
    );
}

/// A PNG's `eXIf` chunk and a WebP's `EXIF` chunk are read like a JPEG's, and so are the XMP
/// packets beside them: every container a phone or an editor writes keeps its position as
/// evidence.
#[test]
fn png_and_webp_metadata_is_read_like_a_jpegs() {
    for (label, file) in [
        ("photo.png", png_with_metadata()),
        ("photo.webp", webp_with_metadata()),
    ] {
        assert!(carries_metadata(&file), "{label}");
        let inspected = inspect(&file, label, 7).unwrap();
        let positions: Vec<(f64, f64)> = inspected
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Coordinates)
            .filter_map(|entity| crate::geohash::parse_coords(&entity.value))
            .collect();
        assert!(
            positions
                .iter()
                .any(|(lat, lon)| (lat - GPS.0).abs() < 1e-6 && (lon - GPS.1).abs() < 1e-6),
            "{label}: {positions:?}"
        );
        assert!(
            inspected
                .outcomes
                .iter()
                .all(|outcome| outcome.kind == SourceOutcomeKind::Success),
            "{label}: {:?}",
            inspected.outcomes
        );
    }
}

/// Digits a camera or a program writes -- a serial number, a toolkit version, a digest -- that
/// happen to have a phone number's shape are not read as one; the same shape in a field a person
/// wrote is. A program's field still yields its link.
#[test]
fn only_fields_people_write_yield_number_shaped_identifiers() {
    let inspected = inspect(&phone_photo(), "photo.jpg", 7).unwrap();
    assert_eq!(
        found_in_values(&inspected),
        [
            (EntityKind::Phone, "+61298765432".to_owned()),
            (EntityKind::Phone, "+61398765432".to_owned()),
            (EntityKind::Person, "ada lovelace".to_owned()),
            (EntityKind::Domain, "example.org".to_owned()),
            (EntityKind::Url, "https://example.net/darkroom".to_owned()),
            (EntityKind::Url, "https://example.org/portfolio".to_owned()),
            (EntityKind::Email, "studio@example.org".to_owned()),
        ],
        "{:#?}",
        inspected.entities
    );
    let field_of =
        |kind: &EntityKind, value: &str| attr(found(&inspected, kind, value), "metadata_field");
    assert_eq!(
        field_of(&EntityKind::Phone, "+61398765432"),
        Some("UserComment")
    );
    assert_eq!(
        field_of(&EntityKind::Phone, "+61298765432"),
        Some("Iptc4xmpCore:CiTelWork")
    );
    assert_eq!(
        field_of(&EntityKind::Url, "https://example.net/darkroom"),
        Some("xmp:CreatorTool")
    );
    // Every value, the serial numbers and the version string included, stays on the document.
    let document = inspected
        .entities
        .iter()
        .find(|entity| entity.kind == EntityKind::Document)
        .unwrap();
    let values: Vec<&str> = document
        .evidence
        .iter()
        .flat_map(|evidence| evidence.attributes.values().map(String::as_str))
        .collect();
    for kept in ["0412345678", "61412345678", "0298765432"] {
        assert!(values.contains(&kept), "{kept}: {values:?}");
    }
    assert!(values.iter().any(|value| value.contains("79.1462899")));
}

/// Asserts that `reader` reads every one of `fields` as written by `writer`.
fn expect_writer(
    reader: fn(&str) -> crate::metadata_identifiers::Field,
    writer: crate::metadata_identifiers::Field,
    fields: &[&str],
) {
    for field in fields {
        assert_eq!(reader(field), writer, "{field}");
    }
}

#[test]
fn each_exif_tag_is_read_by_who_writes_it() {
    use crate::metadata_identifiers::Field;
    let expect = expect_writer;
    expect(
        exif::field,
        Field::Name,
        &[
            "Artist",
            "XPAuthor",
            "CameraOwnerName",
            "OwnerName",
            "Photographer",
            "ImageEditor",
        ],
    );
    expect(
        exif::field,
        Field::People,
        &[
            "Copyright",
            "ImageDescription",
            "ImageTitle",
            "UserComment",
            "XPComment",
            "XPKeywords",
        ],
    );
    expect(
        exif::field,
        Field::Program,
        &[
            "Make",
            "Software",
            "BodySerialNumber",
            "ImageUniqueID",
            "DateTimeOriginal",
            "GPSLatitude",
            "tag_0x9999",
        ],
    );
}

#[test]
fn each_document_field_is_read_by_who_writes_it() {
    use crate::metadata_identifiers::Field;
    let expect = expect_writer;
    expect(
        docmeta::field,
        Field::Name,
        &[
            "dc:creator",
            "dc:contributor",
            "info:Author",
            "info-prior:Author",
            "png:Author",
            "iptc:Byline",
            "iptc:CaptionWriter",
            "photoshop:CaptionWriter",
            "xmpRights:Owner",
            "Iptc4xmpExt:PersonInImage",
            "mwg-rs:Name",
            "MPReg:PersonDisplayName",
            "plus:ImageCreatorName",
            "tiff:Artist",
            "aux:OwnerName",
            "exifEX:CameraOwnerName",
        ],
    );
    expect(
        docmeta::field,
        Field::People,
        &[
            "dc:rights",
            "dc:description",
            "Iptc4xmpCore:CiTelWork",
            "photoshop:City",
            "info-prior:Title",
            "png:Comment",
            "gif:Comment",
            "iptc:Credit",
            "tiff:Copyright",
            "pdfx:Phone",
        ],
    );
    expect(
        docmeta::field,
        Field::Program,
        &[
            "x:xmptk",
            "xmpMM:DocumentID",
            "stEvt:softwareAgent",
            "xmp:CreatorTool",
            "xmp:CreateDate",
            "photoshop:DocumentAncestors",
            "photoshop:LegacyIPTCDigest",
            "tiff:Make",
            "aux:SerialNumber",
            "exif:GPSLatitude",
            "info:Creator",
            "info:Producer",
            "info-prior:ModDate",
            "pdf:InfoRevisions",
            "png:Software",
            "png:Creation Time",
            "png:Raw profile type exif",
            "iptc:OriginatingProgram",
            "iptc:BylineRawSha256",
            "iptc:BylineRawByteCount",
            "plus:ImageCreatorID",
        ],
    );
}

/// Each name written in a field that names someone becomes a person or an organisation, in a
/// list as in a single value. A placeholder a program writes for an unknown user, a copyright line
/// in a rights field, a single word and a program's own name are not people.
#[test]
fn names_in_name_fields_become_people_and_organisations() {
    let artist = ascii_value("Ada Lovelace");
    let tiff = exif_tiff(false, &[(0x013B, 2, &artist)], &[]);
    let xmp = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/" xmp:CreatorTool="Adobe Photoshop" photoshop:CaptionWriter="Microsoft Office User"><dc:creator><rdf:Seq><rdf:li>Ada Lovelace</rdf:li><rdf:li>Analytical Engines Pty Ltd</rdf:li><rdf:li>Babbage</rdf:li></rdf:Seq></dc:creator><dc:rights><rdf:Alt><rdf:li xml:lang="x-default">Copyright 2024 Ada Lovelace</rdf:li></rdf:Alt></dc:rights><dc:description><rdf:Alt><rdf:li xml:lang="x-default">Charles Babbage at the engine</rdf:li></rdf:Alt></dc:description><Iptc4xmpExt:PersonInImage><rdf:Bag><rdf:li>Charles Babbage</rdf:li></rdf:Bag></Iptc4xmpExt:PersonInImage></rdf:Description></rdf:RDF></x:xmpmeta>"#;
    let inspected = inspect(&jpeg_with(&tiff, Some(xmp)), "engine.jpg", 7).unwrap();
    let named: Vec<(EntityKind, String)> = found_in_values(&inspected)
        .into_iter()
        .filter(|(kind, _)| matches!(kind, EntityKind::Person | EntityKind::Organisation))
        .collect();
    assert_eq!(
        named,
        [
            (EntityKind::Person, "ada lovelace".to_owned()),
            (
                EntityKind::Organisation,
                "analytical engines pty ltd".to_owned()
            ),
            (EntityKind::Person, "charles babbage".to_owned()),
        ],
        "{:#?}",
        inspected.entities
    );
    // Ada Lovelace is named by both readers: one entity, with each field as its evidence. The
    // entity keeps the name as written beside its canonical, lower-case value.
    let ada = found(&inspected, &EntityKind::Person, "ada lovelace");
    assert_eq!(ada.raw_value, "Ada Lovelace");
    let fields: Vec<&str> = ada
        .evidence
        .iter()
        .filter_map(|evidence| {
            evidence
                .attributes
                .get("metadata_field")
                .map(String::as_str)
        })
        .collect();
    assert!(
        fields.contains(&"Artist") && fields.contains(&"dc:creator"),
        "{fields:?}"
    );
    let babbage = found(&inspected, &EntityKind::Person, "charles babbage");
    assert_eq!(
        attr(babbage, "metadata_field"),
        Some("Iptc4xmpExt:PersonInImage")
    );
}

/// A file crafted to carry far more identifiers than any real file keeps a bounded number of
/// them, per reader, and says how many more it held; the values themselves stay as evidence.
#[test]
fn a_file_crafted_to_carry_many_identifiers_keeps_a_bounded_number_and_counts_the_rest() {
    use crate::metadata_identifiers::MAX_METADATA_IDENTIFIERS;
    use std::fmt::Write as _;
    let mut properties = String::new();
    for field in 0..4 {
        let emails: Vec<String> = (0..100)
            .map(|n| format!("u{field}x{n}@example.org"))
            .collect();
        write!(properties, "<n:f{field}>{}</n:f{field}>", emails.join(" ")).unwrap();
    }
    let file = format!(
        "notes <x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description xmlns:n=\"urn:example\">{properties}</rdf:Description></rdf:RDF></x:xmpmeta>"
    );
    let inspected = inspect(file.as_bytes(), "crafted.bin", 7).unwrap();
    let emails = inspected
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Email)
        .count();
    assert_eq!(emails, MAX_METADATA_IDENTIFIERS);
    let document = inspected
        .entities
        .iter()
        .find(|entity| entity.kind == EntityKind::Document)
        .unwrap();
    assert_eq!(
        attr(document, "metadata_identifiers_omitted"),
        Some((400 - MAX_METADATA_IDENTIFIERS).to_string().as_str())
    );
}

/// The `exif` and `docmeta` commands report the identifiers their own fields hold, each with the
/// reader's own scan, so every path that reads a file finds them.
#[test]
fn each_reader_reports_the_identifiers_its_fields_hold() {
    let photo = phone_photo();
    let SourceRun::Printed { report, text } = exif::run(&photo, "photo.jpg", 7) else {
        panic!("the exif reader reads the photo");
    };
    assert!(
        report
            .entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Phone
                && entity.value == "+61398765432"
                && entity.evidence[0].provenance.source == exif::SOURCE)
    );
    assert!(text.contains("+61398765432"), "{text}");
    let SourceRun::Printed { report, text } = docmeta::run(&photo, "photo.jpg", 7) else {
        panic!("the document reader reads the photo");
    };
    assert!(
        report
            .entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Email
                && entity.value == "studio@example.org"
                && entity.evidence[0].provenance.source == docmeta::SOURCE)
    );
    assert!(text.contains("studio@example.org"), "{text}");
}

/// Windows writes a file's Authors, Title and Comments as UCS-2 tags, little-endian even in a
/// big-endian block; an address written there is found like one in `Artist`.
#[test]
fn an_identifier_in_a_windows_text_tag_is_found() {
    let author: Vec<u8> = "Ada <ada@example.org>"
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let photo = jpeg_with(&exif_tiff(true, &[(0x9C9D, 1, &author)], &[]), None);
    let inspected = inspect(&photo, "photo.jpg", 7).unwrap();
    let email = found(&inspected, &EntityKind::Email, "ada@example.org");
    assert_eq!(attr(email, "metadata_field"), Some("XPAuthor"));
}
