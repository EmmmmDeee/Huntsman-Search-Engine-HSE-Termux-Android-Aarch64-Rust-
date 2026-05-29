//! Pure, in-memory metadata parsers for images (XMP) and documents (PDF).
//!
//! Consumed by the `exif_geo` and `doc_meta` modules. Every function here is
//! **pure**: it takes a byte slice already held in memory and returns parsed
//! fields, performing NO file I/O of its own. The calling module fetches the
//! bytes over HTTP into memory, parses, and drops them — **no fetched
//! document is ever written to disk** (a hard requirement on the
//! privacy-sensitive, storage-constrained Termux target).
//!
//! The parsers are deliberately dependency-free byte-scanners (no zip/PDF/XML
//! crates): they locate the uncompressed XMP packet and the PDF `/Info`
//! dictionary directly. This covers the overwhelming majority of real-world
//! files (most PDFs store `/Info` and XMP uncompressed) without pulling a
//! heavy parser into the single-binary build. Encrypted or fully
//! object-streamed metadata simply yields `None` — never a panic.

/// Camera / XMP metadata extracted from an in-memory image.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct XmpMeta {
    /// `(lat, lon)` decimal degrees, from XMP `exif:GPS*` (EXIF is parsed
    /// separately by the caller and takes precedence).
    pub gps: Option<(f64, f64)>,
    pub make: Option<String>,
    pub model: Option<String>,
    /// Camera body serial — turns a make/model into a *strong* device key.
    pub serial: Option<String>,
    /// Authoring/processing tool (`xmp:CreatorTool`).
    pub creator_tool: Option<String>,
    /// `dc:creator` — author / camera owner.
    pub creator: Option<String>,
    /// `dc:rights` — copyright holder.
    pub rights: Option<String>,
}

/// Document (PDF) metadata.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DocMeta {
    pub title: Option<String>,
    pub author: Option<String>,
    /// Authoring application (`/Creator`).
    pub creator: Option<String>,
    /// Producing application/library (`/Producer`).
    pub producer: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    /// GPS from an embedded XMP packet (rare in PDFs, but free to harvest).
    pub gps: Option<(f64, f64)>,
}

/// Naive subslice search — adequate for the size-capped buffers these
/// parsers run on (≤16 MiB).
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ─── XMP (images and PDFs both embed it) ─────────────────────────────────────

/// Locate the uncompressed XMP packet and UTF-8-decode just that region.
/// Returns `None` if no `<x:xmpmeta>` packet is present.
fn extract_xmp_region(bytes: &[u8]) -> Option<String> {
    let start = find_subslice(bytes, b"<x:xmpmeta")?;
    const END: &[u8] = b"</x:xmpmeta>";
    let end_rel = find_subslice(&bytes[start..], END)?;
    let end = start + end_rel + END.len();
    Some(String::from_utf8_lossy(&bytes[start..end]).into_owned())
}

/// Minimal XML-entity unescape for the handful that appear in XMP text.
fn unescape_xml(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .trim()
        .to_string()
}

/// Pull a value for `key` from an XMP packet, trying element form
/// (`<key>VALUE</key>`, incl. an `<rdf:li>` array) then attribute form
/// (`key="VALUE"`). Returns `None` if absent or empty.
fn xmp_get(xmp: &str, key: &str) -> Option<String> {
    // Element form.
    let open = format!("<{key}>");
    if let Some(i) = xmp.find(&open) {
        let after = &xmp[i + open.len()..];
        let close = format!("</{key}>");
        if let Some(j) = after.find(&close) {
            let inner = &after[..j];
            // RDF arrays: `<rdf:Seq><rdf:li>TEXT</rdf:li>…`.
            if let Some(li) = inner.find("<rdf:li") {
                let li_rest = &inner[li..];
                if let Some(gt) = li_rest.find('>') {
                    let li_text = &li_rest[gt + 1..];
                    if let Some(end) = li_text.find("</rdf:li>") {
                        let v = unescape_xml(&li_text[..end]);
                        if !v.is_empty() {
                            return Some(v);
                        }
                    }
                }
            }
            let v = unescape_xml(inner);
            if !v.is_empty() && !v.contains('<') {
                return Some(v);
            }
        }
    }
    // Attribute form (single or double quoted).
    for quote in ['"', '\''] {
        let pat = format!("{key}={quote}");
        if let Some(i) = xmp.find(&pat) {
            let after = &xmp[i + pat.len()..];
            if let Some(j) = after.find(quote) {
                let v = unescape_xml(&after[..j]);
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Parse an XMP GPS coordinate of the form `DDD,MM.mmmmH` or `DDD,MM,SSH`
/// (hemisphere letter `N/S/E/W`), or a bare decimal. Returns signed decimal
/// degrees.
fn parse_xmp_coord(raw: &str) -> Option<f64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let last = s.as_bytes()[s.len() - 1].to_ascii_uppercase();
    let (body, sign) = match last {
        b'N' | b'E' => (&s[..s.len() - 1], 1.0),
        b'S' | b'W' => (&s[..s.len() - 1], -1.0),
        _ => (s, 1.0),
    };
    let parts: Vec<&str> = body.split(',').collect();
    let deg = match parts.first() {
        Some(p) => p.trim().parse::<f64>().ok()?,
        None => return None,
    };
    let value = match parts.len() {
        1 => deg, // bare decimal degrees
        2 => deg + parts[1].trim().parse::<f64>().ok()? / 60.0,
        _ => {
            deg + parts[1].trim().parse::<f64>().ok()? / 60.0
                + parts[2].trim().parse::<f64>().ok()? / 3600.0
        }
    };
    if !value.is_finite() {
        return None;
    }
    Some(sign * value)
}

/// Parse the camera/author fields and any GPS out of an image's XMP packet.
/// Returns a default (all-`None`) `XmpMeta` when no packet is present.
pub fn parse_image_xmp(bytes: &[u8]) -> XmpMeta {
    let Some(xmp) = extract_xmp_region(bytes) else {
        return XmpMeta::default();
    };
    let lat = xmp_get(&xmp, "exif:GPSLatitude").and_then(|v| parse_xmp_coord(&v));
    let lon = xmp_get(&xmp, "exif:GPSLongitude").and_then(|v| parse_xmp_coord(&v));
    let gps = match (lat, lon) {
        (Some(la), Some(lo)) if (-90.0..=90.0).contains(&la) && (-180.0..=180.0).contains(&lo) => {
            Some((la, lo))
        }
        _ => None,
    };
    XmpMeta {
        gps,
        make: xmp_get(&xmp, "tiff:Make"),
        model: xmp_get(&xmp, "tiff:Model"),
        serial: xmp_get(&xmp, "aux:SerialNumber")
            .or_else(|| xmp_get(&xmp, "exifEX:BodySerialNumber")),
        creator_tool: xmp_get(&xmp, "xmp:CreatorTool"),
        creator: xmp_get(&xmp, "dc:creator"),
        rights: xmp_get(&xmp, "dc:rights"),
    }
}

// ─── PDF `/Info` dictionary ──────────────────────────────────────────────────

/// Decode a run of PDF string bytes (already stripped of the opening
/// delimiter) into a Rust string, honouring a UTF-16BE BOM. Used for both
/// literal and hex string bodies after they've been collected.
fn decode_pdf_bytes(raw: &[u8]) -> String {
    if raw.len() >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
        // UTF-16BE.
        let units: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units).trim().to_string()
    } else {
        String::from_utf8_lossy(raw).trim().to_string()
    }
}

/// Read a PDF literal string `(...)` body starting at `rest[0]` (just after
/// the `(`), honouring `\` escapes and balanced inner parens.
fn read_pdf_literal(rest: &[u8]) -> String {
    let mut out = Vec::new();
    let mut depth = 1i32;
    let mut i = 0;
    while i < rest.len() {
        match rest[i] {
            b'\\' if i + 1 < rest.len() => {
                let c = rest[i + 1];
                out.push(match c {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    other => other, // \( \) \\ and the rest pass through literally
                });
                i += 2;
            }
            b'(' => {
                depth += 1;
                out.push(b'(');
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                out.push(b')');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    decode_pdf_bytes(&out)
}

/// Read a PDF hex string `<...>` body starting just after the `<`.
fn read_pdf_hex(rest: &[u8]) -> String {
    let mut hex = String::new();
    for &b in rest {
        if b == b'>' {
            break;
        }
        if !(b as char).is_whitespace() {
            hex.push(b as char);
        }
    }
    if hex.len() % 2 == 1 {
        hex.push('0'); // PDF spec: pad an odd final nibble with 0.
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    decode_pdf_bytes(&bytes)
}

/// Find `/<name>` followed by a string object and return its decoded value.
/// Guards against prefix collisions (`/Creator` vs `/CreationDate`) by
/// requiring a delimiter after the key.
fn pdf_value(bytes: &[u8], name: &str) -> Option<String> {
    let key = format!("/{name}").into_bytes();
    let mut from = 0;
    while let Some(rel) = find_subslice(&bytes[from..], &key) {
        let after_key = from + rel + key.len();
        let rest = &bytes[after_key..];
        // Next byte must be a PDF delimiter/whitespace, else this is a
        // longer key that merely starts with `name`.
        let boundary_ok = rest
            .first()
            .is_some_and(|&b| b.is_ascii_whitespace() || b == b'(' || b == b'<');
        if boundary_ok {
            let mut i = 0;
            while i < rest.len() && rest[i].is_ascii_whitespace() {
                i += 1;
            }
            match rest.get(i) {
                Some(b'(') => {
                    let v = read_pdf_literal(&rest[i + 1..]);
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
                Some(b'<') if rest.get(i + 1) != Some(&b'<') => {
                    let v = read_pdf_hex(&rest[i + 1..]);
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
                _ => {}
            }
        }
        from = after_key;
    }
    None
}

/// Parse a PDF's `/Info` dictionary fields plus any embedded XMP GPS.
pub fn parse_pdf(bytes: &[u8]) -> DocMeta {
    let xmp = parse_image_xmp(bytes); // PDFs frequently embed an XMP packet too
    DocMeta {
        title: pdf_value(bytes, "Title"),
        author: pdf_value(bytes, "Author").or(xmp.creator),
        creator: pdf_value(bytes, "Creator").or_else(|| xmp.creator_tool.clone()),
        producer: pdf_value(bytes, "Producer"),
        created: pdf_value(bytes, "CreationDate"),
        modified: pdf_value(bytes, "ModDate"),
        gps: xmp.gps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XMP: &str = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description tiff:Make="Canon" tiff:Model="Canon EOS 5D Mark IV"
     xmp:CreatorTool="Adobe Lightroom" aux:SerialNumber="023021000537">
   <dc:creator><rdf:Seq><rdf:li>Jane Photographer</rdf:li></rdf:Seq></dc:creator>
   <dc:rights><rdf:Alt><rdf:li xml:lang="x-default">ACME Media Pty Ltd</rdf:li></rdf:Alt></dc:rights>
   <exif:GPSLatitude>27,28.6000S</exif:GPSLatitude>
   <exif:GPSLongitude>153,1.5000E</exif:GPSLongitude>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

    #[test]
    fn xmp_extracts_camera_author_and_gps() {
        // Wrap the packet in some leading binary noise like a real JPEG would.
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x00];
        bytes.extend_from_slice(XMP.as_bytes());
        let m = parse_image_xmp(&bytes);
        assert_eq!(m.make.as_deref(), Some("Canon"));
        assert_eq!(m.model.as_deref(), Some("Canon EOS 5D Mark IV"));
        assert_eq!(m.serial.as_deref(), Some("023021000537"));
        assert_eq!(m.creator_tool.as_deref(), Some("Adobe Lightroom"));
        assert_eq!(m.creator.as_deref(), Some("Jane Photographer"));
        assert_eq!(m.rights.as_deref(), Some("ACME Media Pty Ltd"));
        let (lat, lon) = m.gps.expect("gps");
        assert!((lat - (-27.476667)).abs() < 1e-4, "lat {lat}");
        assert!((lon - 153.025).abs() < 1e-4, "lon {lon}");
    }

    #[test]
    fn xmp_absent_yields_default() {
        assert_eq!(
            parse_image_xmp(b"not an image with xmp"),
            XmpMeta::default()
        );
    }

    #[test]
    fn coord_parses_decimal_minutes_and_dms() {
        assert!((parse_xmp_coord("27,28.6000S").unwrap() - (-27.476667)).abs() < 1e-4);
        assert!((parse_xmp_coord("153,1,30E").unwrap() - 153.025).abs() < 1e-4);
        assert!((parse_xmp_coord("12.5").unwrap() - 12.5).abs() < 1e-9);
        assert_eq!(parse_xmp_coord(""), None);
        assert_eq!(parse_xmp_coord("not-a-coord"), None);
    }

    #[test]
    fn pdf_info_literal_and_hex_strings() {
        // Minimal PDF Info-dict fragment: a literal Author and a hex Title.
        let pdf = b"%PDF-1.7\n5 0 obj<< /Author (Bob Smith) /Creator (Microsoft Word) \
                    /Producer (Acme PDF 2.1) /Title <426F62> /CreationDate (D:20240115) >>endobj";
        let m = parse_pdf(pdf);
        assert_eq!(m.author.as_deref(), Some("Bob Smith"));
        assert_eq!(m.creator.as_deref(), Some("Microsoft Word"));
        assert_eq!(m.producer.as_deref(), Some("Acme PDF 2.1"));
        assert_eq!(m.title.as_deref(), Some("Bob")); // 0x42 0x6F 0x62
        assert_eq!(m.created.as_deref(), Some("D:20240115"));
        assert_eq!(m.modified, None);
    }

    #[test]
    fn pdf_creator_does_not_collide_with_creationdate() {
        // `/CreationDate` must not be returned for a `/Creator` query.
        let pdf = b"<< /CreationDate (D:20240101000000Z) >>";
        assert_eq!(pdf_value(pdf, "Creator"), None);
        assert_eq!(
            pdf_value(pdf, "CreationDate").as_deref(),
            Some("D:20240101000000Z")
        );
    }

    #[test]
    fn pdf_utf16be_bom_decoded() {
        // "Hi" in UTF-16BE with BOM inside a literal string.
        let pdf = b"<< /Author (\xFE\xFF\x00H\x00i) >>";
        assert_eq!(parse_pdf(pdf).author.as_deref(), Some("Hi"));
    }

    #[test]
    fn pdf_absent_info_yields_default() {
        assert_eq!(parse_pdf(b"%PDF-1.4 no info here"), DocMeta::default());
    }
}
