//! Dependency-free extraction of the identity/context metadata that photo
//! software embeds in an image's **XMP packet** — read from the file, never
//! computed by biometric face recognition.
//!
//! When a person tags faces in Picasa, Lightroom, digiKam, Windows (Live) Photo
//! Gallery, or exports Apple Photos face tags, the software writes the **names**
//! of the tagged people into the image's XMP metadata: Metadata Working Group
//! person regions (`mwg-rs:Name` on a region) and Microsoft People Tags
//! (`MPReg:PersonDisplayName`). Reading those names — plus the creator/by-line
//! (`dc:creator`), subject keywords (`dc:subject`), caption (`dc:description`)
//! and embedded place (`photoshop:City`/`State`/`Country`, `Iptc4xmpCore:Location`)
//! — is a lawful, non-biometric way to identify the people and context in an
//! image *beyond EXIF*.
//!
//! This module runs **no** face detection or matching and builds **no** face
//! database. It only parses text an author's own tool already stored in the
//! file, exactly as an image viewer's "properties" panel would show it. XMP is
//! stored as a literal UTF-8 XML packet, so extraction is a bounded byte scan
//! plus a few field reads — no XML dependency, no network.

use std::sync::LazyLock;

use regex::Regex;

use crate::util::html::decode_entities;

/// Longest field value we keep. A tagged person name, by-line or keyword is
/// short; anything longer is almost certainly a mis-parse (or an entire caption
/// mislabelled), and is dropped rather than emitted as a bogus lead.
const MAX_FIELD_LEN: usize = 200;

/// Identity and context metadata read from an image's XMP packet. Every field is
/// text the image author's software wrote — none is inferred from pixels.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImageXmp {
    /// Names of people tagged in the image (MWG face-region names and Microsoft
    /// People Tags), de-duplicated in first-seen order.
    pub people: Vec<String>,
    /// Creator / by-line (`dc:creator`, else `photoshop:Credit`).
    pub creators: Vec<String>,
    /// Subject keywords (`dc:subject` / IPTC Keywords).
    pub keywords: Vec<String>,
    /// A place string assembled from `photoshop:City`/`State`/`Country` or
    /// `Iptc4xmpCore:Location`, when present.
    pub location: Option<String>,
    /// Caption / description (`dc:description`).
    pub description: Option<String>,
}

impl ImageXmp {
    /// True when no field carried anything — the common case for a re-encoded,
    /// metadata-stripped social-media image.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.people.is_empty()
            && self.creators.is_empty()
            && self.keywords.is_empty()
            && self.location.is_none()
            && self.description.is_none()
    }
}

/// MWG person-region name, in either XMP serialisation: the element form
/// `<mwg-rs:Name>…</mwg-rs:Name>` or the attribute form `mwg-rs:Name="…"`.
static MWG_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"<mwg-rs:Name>\s*([^<]{1,200}?)\s*</mwg-rs:Name>|mwg-rs:Name\s*=\s*"([^"]{1,200})""#,
    )
    .expect("static MWG_NAME regex is valid")
});

/// Microsoft People Tag display name, element or attribute form.
static MS_PERSON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"<MPReg:PersonDisplayName>\s*([^<]{1,200}?)\s*</MPReg:PersonDisplayName>|MPReg:PersonDisplayName\s*=\s*"([^"]{1,200})""#,
    )
    .expect("static MS_PERSON regex is valid")
});

/// One `<rdf:li>…</rdf:li>` item (the RDF list element XMP uses for `dc:creator`,
/// `dc:subject`, `dc:description`, …).
static RDF_LI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<rdf:li[^>]*>\s*([^<]{1,300}?)\s*</rdf:li>"#)
        .expect("static RDF_LI regex is valid")
});

/// Extract identity/context metadata from image `bytes`. Returns an empty
/// [`ImageXmp`] when the image carries no XMP packet (or none of the fields).
#[must_use]
pub fn parse(bytes: &[u8]) -> ImageXmp {
    let Some(xmp) = extract_packet(bytes) else {
        return ImageXmp::default();
    };

    let mut out = ImageXmp::default();

    // People — the star field: names the author's face-tagging software wrote.
    for re in [&*MWG_NAME, &*MS_PERSON] {
        for caps in re.captures_iter(&xmp) {
            if let Some(m) = caps.get(1).or_else(|| caps.get(2)) {
                push_clean(&mut out.people, m.as_str());
            }
        }
    }

    // Creator / by-line (fall back to photoshop:Credit when dc:creator absent).
    out.creators = li_items(&xmp, "dc:creator");
    if out.creators.is_empty() {
        out.creators.extend(field(&xmp, "photoshop:Credit"));
    }

    // Subject keywords.
    out.keywords = li_items(&xmp, "dc:subject");

    // Embedded place.
    out.location = assemble_location(&xmp);

    // Caption / description (RDF-wrapped, else a plain field).
    out.description = li_items(&xmp, "dc:description")
        .into_iter()
        .next()
        .or_else(|| field(&xmp, "dc:description"));

    out
}

/// Locate the XMP packet (the `<x:xmpmeta>…</x:xmpmeta>` element, stored as
/// literal UTF-8 XML) in the image bytes and return it as a string. `None` when
/// no packet is present.
fn extract_packet(bytes: &[u8]) -> Option<String> {
    const START: &[u8] = b"<x:xmpmeta";
    const END: &[u8] = b"</x:xmpmeta>";
    let start = find_bytes(bytes, START)?;
    let end_rel = find_bytes(&bytes[start..], END)?;
    let end = start + end_rel + END.len();
    Some(String::from_utf8_lossy(&bytes[start..end]).into_owned())
}

/// First index of `needle` in `haystack`, or `None`. A plain scan — `needle` is
/// short (a marker), `haystack` is bounded by the caller's fetch cap.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Pull every `<rdf:li>` item out of the `<container>…</container>` span(s).
fn li_items(xmp: &str, container: &str) -> Vec<String> {
    let open = format!("<{container}");
    let close = format!("</{container}>");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = xmp[from..].find(&open) {
        let start = from + rel;
        let Some(end_rel) = xmp[start..].find(&close) else {
            break;
        };
        let span = &xmp[start..start + end_rel];
        for caps in RDF_LI.captures_iter(span) {
            if let Some(m) = caps.get(1) {
                push_clean(&mut out, m.as_str());
            }
        }
        from = start + end_rel + close.len();
    }
    out
}

/// Read a single field in either serialisation: the element form
/// `<tag>value</tag>` or the attribute form `tag="value"`. Regex-free (the tag
/// varies per call), so no per-call compilation.
fn field(xmp: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    if let Some(s) = xmp.find(&open) {
        let rest = &xmp[s + open.len()..];
        if let Some(e) = rest.find('<') {
            let v = clean(&rest[..e]);
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    let attr = format!("{tag}=\"");
    if let Some(s) = xmp.find(&attr) {
        let rest = &xmp[s + attr.len()..];
        if let Some(e) = rest.find('"') {
            let v = clean(&rest[..e]);
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Assemble a human place string from the IPTC/photoshop location fields, most
/// specific first. `None` when none are present.
fn assemble_location(xmp: &str) -> Option<String> {
    let parts: Vec<String> = [
        "Iptc4xmpCore:Location",
        "photoshop:City",
        "photoshop:State",
        "photoshop:Country",
    ]
    .into_iter()
    .filter_map(|tag| field(xmp, tag))
    .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

/// Decode XML entities and trim a raw field value.
fn clean(raw: &str) -> String {
    decode_entities(raw).trim().to_string()
}

/// Clean `raw` and push it onto `vec` if it is a usable, non-duplicate value.
fn push_clean(vec: &mut Vec<String>, raw: &str) {
    let v = clean(raw);
    if !v.is_empty() && v.len() <= MAX_FIELD_LEN && !vec.iter().any(|e| e == &v) {
        vec.push(v);
    }
}

#[cfg(test)]
mod tests {
    include!("xmp_tests.rs");
}
