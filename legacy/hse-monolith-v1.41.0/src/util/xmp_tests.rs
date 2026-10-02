use super::*;

/// Wrap an XMP packet in a minimal JPEG-shaped byte buffer (SOI + an APP1-ish
/// header + EOI) so the tests exercise the byte scan against surrounding binary,
/// exactly as a real fetched image presents it.
fn img_with_xmp(xmp: &str) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x00];
    v.extend_from_slice(b"http://ns.adobe.com/xap/1.0/\x00");
    v.extend_from_slice(xmp.as_bytes());
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

#[test]
fn mwg_face_region_names_are_read_both_serialisations() {
    // Element form (digiKam/Photo Gallery) and attribute form (Lightroom).
    let xmp = r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF
      xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
      <rdf:Description xmlns:mwg-rs="http://www.metadataworkinggroup.com/schemas/regions/">
       <mwg-rs:Regions rdf:parseType="Resource"><mwg-rs:RegionList><rdf:Bag>
        <rdf:li rdf:parseType="Resource">
         <mwg-rs:Type>Face</mwg-rs:Type>
         <mwg-rs:Name>Jane Roe</mwg-rs:Name>
        </rdf:li>
        <rdf:li mwg-rs:Type="Face" mwg-rs:Name="John Q. Public"/>
       </rdf:Bag></mwg-rs:RegionList></mwg-rs:Regions>
      </rdf:Description></rdf:RDF></x:xmpmeta>"#;
    let meta = parse(&img_with_xmp(xmp));
    assert_eq!(meta.people, vec!["Jane Roe", "John Q. Public"]);
}

#[test]
fn microsoft_people_tags_are_read() {
    let xmp = r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>
      <rdf:Description xmlns:MPReg="http://ns.microsoft.com/photo/1.2/t/Region#">
       <MP:RegionInfo><MPRI:Regions><rdf:Bag>
        <rdf:li><MPReg:PersonDisplayName>Alice Example</MPReg:PersonDisplayName></rdf:li>
        <rdf:li MPReg:PersonDisplayName="Carlos Réal"/>
       </rdf:Bag></MPRI:Regions></MP:RegionInfo>
      </rdf:Description></rdf:RDF></x:xmpmeta>"#;
    let meta = parse(&img_with_xmp(xmp));
    assert_eq!(meta.people, vec!["Alice Example", "Carlos Réal"]);
}

#[test]
fn creator_keywords_description_and_location_are_read() {
    let xmp = r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>
      <rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/">
       <dc:creator><rdf:Seq><rdf:li>Bob Photographer</rdf:li></rdf:Seq></dc:creator>
       <dc:subject><rdf:Bag><rdf:li>protest</rdf:li><rdf:li>town hall</rdf:li></rdf:Bag></dc:subject>
       <dc:description><rdf:Alt><rdf:li xml:lang="x-default">Rally at Town Hall</rdf:li></rdf:Alt></dc:description>
       <photoshop:City>Sydney</photoshop:City>
       <photoshop:State>NSW</photoshop:State>
       <photoshop:Country>Australia</photoshop:Country>
      </rdf:Description></rdf:RDF></x:xmpmeta>"#;
    let meta = parse(&img_with_xmp(xmp));
    assert_eq!(meta.creators, vec!["Bob Photographer"]);
    assert_eq!(meta.keywords, vec!["protest", "town hall"]);
    assert_eq!(meta.description.as_deref(), Some("Rally at Town Hall"));
    assert_eq!(meta.location.as_deref(), Some("Sydney, NSW, Australia"));
}

#[test]
fn xml_entities_are_decoded_in_values() {
    let xmp = r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>
      <rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">
       <dc:subject><rdf:Bag><rdf:li>R&amp;D team</rdf:li></rdf:Bag></dc:subject>
      </rdf:Description></rdf:RDF></x:xmpmeta>"#;
    let meta = parse(&img_with_xmp(xmp));
    assert_eq!(meta.keywords, vec!["R&D team"]);
}

#[test]
fn duplicate_person_names_are_deduplicated() {
    let xmp = r#"<x:xmpmeta xmlns:x="adobe:ns:meta/">
      <mwg-rs:Name>Same Person</mwg-rs:Name>
      <mwg-rs:Name>Same Person</mwg-rs:Name></x:xmpmeta>"#;
    let meta = parse(&img_with_xmp(xmp));
    assert_eq!(meta.people, vec!["Same Person"]);
}

#[test]
fn an_absurdly_long_value_is_dropped_not_emitted() {
    let long = "x".repeat(MAX_FIELD_LEN + 1);
    let xmp = format!(
        r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><mwg-rs:Name>{long}</mwg-rs:Name></x:xmpmeta>"#
    );
    let meta = parse(&img_with_xmp(&xmp));
    assert!(meta.people.is_empty(), "over-length name must be rejected");
    assert!(meta.is_empty());
}

#[test]
fn an_image_without_an_xmp_packet_yields_nothing() {
    // Plain bytes, no `<x:xmpmeta>` — a re-encoded, metadata-stripped image.
    let bytes = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9];
    let meta = parse(&bytes);
    assert!(meta.is_empty());
    assert!(meta.people.is_empty() && meta.location.is_none());
}
