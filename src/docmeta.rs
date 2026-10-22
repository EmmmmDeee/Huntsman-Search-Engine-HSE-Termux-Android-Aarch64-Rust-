//! Keyless, offline extraction of the metadata a document embeds in itself.
//!
//! One `docmeta FILE` reads the bytes already on the device -- no network, no key -- and surfaces
//! the provenance a file carries without anyone meaning to ship it: the XMP metadata packet (the
//! uncompressed `<x:xmpmeta>` XML block that PDFs, JPEG, TIFF and PNG embed), for a PDF the
//! `/Info` dictionary, and for a PNG its uncompressed textual chunks (`tEXt`, `iTXt`) and
//! modification time (`tIME`). Author, creator tool, create and modify timestamps, document and instance
//! identifiers, producer and title are kept as evidence on a [`EntityKind::Document`] entity for the
//! file, so nothing the metadata states is dropped. When the XMP carries a GPS position it also
//! becomes a [`EntityKind::Coordinates`] entity -- the same `lat,lon` the `geocode` command
//! reverse-geocodes into an address.
//!
//! This complements the `exif` command, which decodes the binary EXIF block; `docmeta` reads the
//! XMP packet and PDF dictionary, which `exif` does not. Metadata is editable, so every field is the
//! file's embedded claim, not an independently verified fact. The scanner is bounds-checked and
//! allocation-bounded: it searches for the uncompressed metadata only, never decompresses, and caps
//! the packet, the field count and each value, so a malformed or hostile file yields a clean result,
//! never a panic or a runaway. Office Open XML (`.docx`, `.xlsx`, `.pptx`) keeps its core properties
//! in a deflate-compressed part, which is not read here; an embedded XMP packet in such a file is. A
//! PNG's compressed text chunks (`zTXt`, compressed `iTXt`) are likewise not inflated, and its binary
//! `eXIf` block is left to the `exif` command.

use std::path::PathBuf;

use crate::canonical::canonical_coordinates;
use crate::entity::{
    Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity, scan_id,
};
use crate::error::Error;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

/// The source/module name this command reports its findings under.
pub const SOURCE: &str = "docmeta";

pub const DOCMETA_USAGE: &str = "usage: huntsman-recon docmeta FILE";

pub const DOCMETA_HELP: &str = "\
docmeta FILE
Read the metadata a document embeds in itself, keyless and offline: no network request and no key. The uncompressed XMP metadata packet (the <x:xmpmeta> XML block PDFs, JPEG, TIFF and PNG carry) is flattened field by field, and a PDF's /Info dictionary (Title, Author, Subject, Keywords, Creator, Producer, CreationDate, ModDate) is read too, and for a PNG its uncompressed textual chunks (tEXt and iTXt) and modification time (tIME) become png:* fields (compressed chunks and the binary EXIF block, left to the exif command, are not read); every field is kept as evidence on a document entity for the file, so author, creator tool, create/modify timestamps, document and instance identifiers and title are preserved. When the XMP holds a GPS position it also becomes a coordinates entity -- the same lat,lon the geocode command reverse-geocodes to an address. Metadata is editable, so each field is the file's embedded claim, not an independently verified fact. This complements the exif command, which decodes the binary EXIF block; docmeta reads the XMP packet and PDF dictionary instead. A file with no embedded metadata is a clean result naming its format and size. Office Open XML (.docx, .xlsx, .pptx) keeps its core properties in a deflate-compressed part, which is not read; an embedded XMP packet in such a file is.";

/// The largest file read, in bytes. The whole file is read because a PDF's `/Info` and the XMP
/// packet can sit anywhere in it; a larger file is refused by name.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The file is read directly, so its metadata is reported with high but not absolute confidence:
/// embedded metadata is editable.
const DOCUMENT_CONFIDENCE: f64 = 0.9;

/// A GPS position is the file's embedded claim and can be spoofed, so it is reported a notch below
/// the document it came from.
const GPS_CONFIDENCE: f64 = 0.85;

/// Most metadata fields surfaced from one file. A real document declares a few dozen; a larger count
/// is corrupt or hostile and is not collected past this bound.
const MAX_FIELDS: usize = 512;

/// Most bytes one field's value may occupy. Longer values are truncated for display.
const MAX_DOCMETA_VALUE_BYTES: usize = 8192;

/// Most bytes of one XMP packet scanned, so a file that claims a huge packet is bounded.
const MAX_XMP_BYTES: usize = 1024 * 1024;

/// The PNG file signature: the eight bytes every PNG begins with.
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Most PNG chunks walked before giving up, so a file claiming countless chunks is bounded.
const MAX_PNG_CHUNKS: usize = 4096;

/// The PDF `/Info` string keys read, in report order.
const PDF_INFO_KEYS: &[&str] = &[
    "Title",
    "Author",
    "Subject",
    "Keywords",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
];

pub type DocmetaRun = SourceRun<Report>;

/// A finished `docmeta` run: the rendered report, the entities it is made of, and the outcome.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// One parsed `docmeta FILE` argument: the path to read and a label for the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocmetaArgs {
    pub path: PathBuf,
    pub label: String,
}

impl DocmetaArgs {
    /// # Errors
    /// [`Error::Invalid`] for a missing or extra argument, [`Error::InvalidValue`] for an empty path.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let [raw] = args else {
            return Err(Error::Invalid("docmeta needs exactly one file".into()));
        };
        if raw.trim().is_empty() {
            return Err(Error::invalid_value("the file path is empty"));
        }
        Ok(Self {
            path: PathBuf::from(raw),
            label: raw.clone(),
        })
    }
}

/// Everything one file's embedded metadata yields: its container format, every field in report
/// order, and the GPS position when the XMP carries one.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Parsed {
    pub format: String,
    pub fields: Vec<(String, String)>,
    pub gps: Option<(f64, f64)>,
}

/// Parse one file's embedded metadata. Never fails: a file with no recognised metadata returns a
/// [`Parsed`] with its detected format and no fields.
#[must_use]
pub fn parse(data: &[u8]) -> Parsed {
    let format = detect_format(data);
    let mut fields = Vec::new();
    if format.starts_with("PDF") {
        extract_pdf_info(data, &mut fields);
    }
    if format == "PNG" {
        extract_png_text(data, &mut fields);
    }
    for (key, value) in extract_xmp(data) {
        push_field(&mut fields, key, value);
    }
    let gps = xmp_gps(&fields);
    Parsed {
        format,
        fields,
        gps,
    }
}

/// Run the whole command: parse `data`, build the entities, and render the report. `label` names the
/// file in the report and entity values.
#[must_use]
pub fn run(data: &[u8], label: &str, now_unix: u64) -> DocmetaRun {
    let parsed = parse(data);
    let sid = scan_id(SOURCE, label);
    let mut entities = Vec::new();
    document_entity(&mut entities, &parsed, label, &sid);
    gps_entity(&mut entities, parsed.gps, label, &sid);
    merge_by_uid(&mut entities);

    let outcome = SourceExecutionOutcome::success(SOURCE, now_unix, entities.len());
    let outcomes = vec![outcome];
    match lookup_report::render(&entities, &outcomes) {
        Ok(text) => DocmetaRun::Printed {
            text,
            report: Report { entities, outcomes },
        },
        Err(message) => DocmetaRun::Failed(message),
    }
}

/// The document entity for the file, carrying its format and every field as evidence.
fn document_entity(entities: &mut Vec<Entity>, parsed: &Parsed, label: &str, sid: &str) {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, sid),
        summary(parsed, label),
    )
    .with_attr("format", parsed.format.as_str())
    .with_attr("metadata_field_count", parsed.fields.len().to_string());
    for (name, value) in &parsed.fields {
        evidence = evidence.with_attr(name.as_str(), value.as_str());
    }
    push_entity(
        entities,
        EntityKind::Document,
        label,
        DOCUMENT_CONFIDENCE,
        sid,
        evidence,
        &[SOURCE, "metadata"],
    );
}

/// The coordinates entity for a GPS position embedded in the XMP, when one is present and in range.
fn gps_entity(entities: &mut Vec<Entity>, gps: Option<(f64, f64)>, label: &str, sid: &str) {
    let Some((lat, lon)) = gps else { return };
    let Some(coordinates) = canonical_coordinates(&format!("{lat},{lon}")) else {
        return;
    };
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, sid),
        format!("GPS position embedded in {label}"),
    )
    .with_attr("source_file", label)
    .with_attr("coordinates", coordinates.as_str())
    .with_attr("derivation", "XMP exif:GPSLatitude/GPSLongitude");
    push_entity(
        entities,
        EntityKind::Coordinates,
        &coordinates,
        GPS_CONFIDENCE,
        sid,
        evidence,
        &[SOURCE, "gps", "geoint"],
    );
}

/// The one-line summary for the document entity.
fn summary(parsed: &Parsed, label: &str) -> String {
    if parsed.fields.is_empty() {
        format!("{} file {label} with no embedded metadata", parsed.format)
    } else {
        format!(
            "{} file {label} with {} embedded metadata field(s)",
            parsed.format,
            parsed.fields.len()
        )
    }
}

/// Append a named field, capped and de-duplicated, skipping an empty value. **Pure.**
fn push_field(
    fields: &mut Vec<(String, String)>,
    key: impl Into<String>,
    value: impl Into<String>,
) {
    if fields.len() >= MAX_FIELDS {
        return;
    }
    let key = key.into();
    let value = value.into();
    let value = cap(&value);
    if value.is_empty() || fields.iter().any(|(existing, _)| *existing == key) {
        return;
    }
    fields.push((key, value));
}

/// Truncate `value` to [`MAX_DOCMETA_VALUE_BYTES`] on a char boundary. **Pure.**
fn cap(value: &str) -> String {
    let value = value.trim();
    if value.len() <= MAX_DOCMETA_VALUE_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_DOCMETA_VALUE_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

// ── format ───────────────────────────────────────────────────────────────────────────────

/// The container format from the file's magic bytes. **Pure.**
fn detect_format(data: &[u8]) -> String {
    if data.starts_with(b"%PDF-") {
        let version = data
            .get(5..8)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim)
            .filter(|version| !version.is_empty());
        return match version {
            Some(version) => format!("PDF {version}"),
            None => "PDF".to_owned(),
        };
    }
    if data.starts_with(&[0xFF, 0xD8]) {
        "JPEG".to_owned()
    } else if data.starts_with(b"II\x2a\x00") || data.starts_with(b"MM\x00\x2a") {
        "TIFF".to_owned()
    } else if data.starts_with(PNG_SIGNATURE) {
        "PNG".to_owned()
    } else if data.starts_with(b"PK\x03\x04") {
        "ZIP/OOXML".to_owned()
    } else {
        "unknown".to_owned()
    }
}

// ── XMP ──────────────────────────────────────────────────────────────────────────────────

/// Every field an embedded XMP packet states, as `prefix:Local` keys: both the attribute form on an
/// `rdf:Description` and the element form (`<ns:Name>`, including `rdf:Seq`/`rdf:Bag`/`rdf:Alt` lists
/// of `rdf:li`). Empty when there is no packet. **Pure.**
fn extract_xmp(data: &[u8]) -> Vec<(String, String)> {
    let Some(packet) = find_xmp_packet(data) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(packet);
    let mut fields = Vec::new();
    collect_description_attrs(&text, &mut fields);
    collect_elements(&text, &mut fields);
    fields
}

/// The `<x:xmpmeta> … </x:xmpmeta>` packet, bounded by [`MAX_XMP_BYTES`]. **Pure.**
fn find_xmp_packet(data: &[u8]) -> Option<&[u8]> {
    const CLOSE: &[u8] = b"</x:xmpmeta>";
    let start = find_bytes(data, b"<x:xmpmeta")?;
    let end_rel = find_bytes(data.get(start..)?, CLOSE)?;
    let end = (start + end_rel + CLOSE.len()).min(start + MAX_XMP_BYTES);
    data.get(start..end)
}

/// Collect `prefix:Local="value"` attributes off every `rdf:Description`. **Pure.**
fn collect_description_attrs(text: &str, fields: &mut Vec<(String, String)>) {
    let mut rest = text;
    while let Some(open) = rest.find("<rdf:Description") {
        let after = &rest[open + "<rdf:Description".len()..];
        let Some(gt) = after.find('>') else { break };
        parse_attrs(&after[..gt], fields);
        rest = &after[gt + 1..];
    }
}

/// Parse `name="value"` / `name='value'` pairs from one start tag's body, keeping the namespaced
/// ones that are not `xmlns:*` or `rdf:about`. **Pure.**
fn parse_attrs(tag: &str, fields: &mut Vec<(String, String)>) {
    let mut rest = tag;
    while let Some(eq) = rest.find('=') {
        let name = rest[..eq]
            .rsplit([' ', '\t', '\r', '\n'])
            .next()
            .unwrap_or("")
            .trim();
        let after = rest[eq + 1..].trim_start();
        let Some(quote) = after.chars().next() else {
            break;
        };
        if quote != '"' && quote != '\'' {
            rest = after;
            continue;
        }
        let body = &after[1..];
        let Some(end) = body.find(quote) else { break };
        let value = &body[..end];
        if name.contains(':') && !name.starts_with("xmlns") && name != "rdf:about" {
            push_field(fields, name, unescape_xml(value));
        }
        rest = &body[end + 1..];
    }
}

/// Collect leaf and `rdf:li`-list elements `<prefix:Local> … </prefix:Local>`. **Pure.**
fn collect_elements(text: &str, fields: &mut Vec<(String, String)>) {
    let mut from = 0usize;
    while from < text.len() && fields.len() < MAX_FIELDS {
        let Some(rel) = text[from..].find('<') else {
            break;
        };
        let lt = from + rel;
        let Some(name) = tag_name(&text[lt + 1..]) else {
            from = lt + 1;
            continue;
        };
        if name.starts_with("rdf:") || name.starts_with("x:") || !name.contains(':') {
            from = lt + 1;
            continue;
        }
        let Some(gt_rel) = text[lt..].find('>') else {
            break;
        };
        let open_end = lt + gt_rel + 1;
        // A self-closing tag (…/>) has no content.
        if text[lt..open_end].ends_with("/>") {
            from = open_end;
            continue;
        }
        let close = format!("</{name}>");
        let Some(close_rel) = text[open_end..].find(&close) else {
            from = open_end;
            continue;
        };
        let inner = &text[open_end..open_end + close_rel];
        if let Some(value) = element_value(inner) {
            push_field(fields, name, value);
        }
        from = open_end + close_rel + close.len();
    }
}

/// The element name after a `<`, made of name characters and containing a namespace colon, or `None`
/// for a closing tag, a processing instruction or a non-namespaced name. **Pure.**
fn tag_name(after_lt: &str) -> Option<String> {
    let name: String = after_lt
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '.' | '_'))
        .collect();
    (!name.is_empty()).then_some(name)
}

/// A leaf element's text, or the joined `rdf:li` items of a list element, or `None` when the content
/// is structural with nothing to show. **Pure.**
fn element_value(inner: &str) -> Option<String> {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.contains('<') {
        return Some(unescape_xml(trimmed));
    }
    let mut items = Vec::new();
    let mut rest = trimmed;
    while let Some(open) = rest.find("<rdf:li") {
        let after = &rest[open..];
        let Some(gt) = after.find('>') else { break };
        let content = &after[gt + 1..];
        let Some(close) = content.find("</rdf:li>") else {
            break;
        };
        let text = &content[..close];
        if !text.contains('<') {
            let text = unescape_xml(text.trim());
            if !text.is_empty() {
                items.push(text);
            }
        }
        rest = &content[close + "</rdf:li>".len()..];
    }
    (!items.is_empty()).then(|| items.join("; "))
}

/// Replace the five predefined XML entities. **Pure.**
fn unescape_xml(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

// ── XMP GPS ──────────────────────────────────────────────────────────────────────────────

/// The GPS position from the XMP `exif:GPSLatitude`/`exif:GPSLongitude` fields, when both parse.
/// **Pure.**
fn xmp_gps(fields: &[(String, String)]) -> Option<(f64, f64)> {
    let find = |key: &str| {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let lat = parse_xmp_coord(find("exif:GPSLatitude")?, 'S')?;
    let lon = parse_xmp_coord(find("exif:GPSLongitude")?, 'W')?;
    Some((lat, lon))
}

/// An XMP GPS coordinate, written `deg,min.decH` or `deg,min,secH` with a trailing hemisphere letter,
/// as signed decimal degrees. `negative` is the hemisphere letter that negates it (`S` or `W`).
/// **Pure.**
fn parse_xmp_coord(value: &str, negative: char) -> Option<f64> {
    let value = value.trim();
    let hemisphere = value.chars().last()?;
    if !hemisphere.is_ascii_alphabetic() {
        return None;
    }
    let body = &value[..value.len() - hemisphere.len_utf8()];
    let mut parts = body.split(',');
    let degrees: f64 = parts.next()?.trim().parse().ok()?;
    let minutes: f64 = match parts.next() {
        Some(raw) => raw.trim().parse().ok()?,
        None => 0.0,
    };
    let seconds: f64 = match parts.next() {
        Some(raw) => raw.trim().parse().ok()?,
        None => 0.0,
    };
    let magnitude = degrees + minutes / 60.0 + seconds / 3600.0;
    Some(if hemisphere.eq_ignore_ascii_case(&negative) {
        -magnitude
    } else {
        magnitude
    })
}

// ── PDF /Info dictionary ───────────────────────────────────────────────────────────────────

/// Collect the PDF `/Info` string entries as `info:Key` fields, best-effort over the uncompressed
/// bytes (a `/Info` object inside a compressed object stream is not reachable without inflate).
/// **Pure.**
fn extract_pdf_info(data: &[u8], fields: &mut Vec<(String, String)>) {
    for key in PDF_INFO_KEYS {
        if let Some(value) = pdf_find_string(data, key) {
            push_field(fields, format!("info:{key}"), value);
        }
    }
}

/// The last parseable value of a PDF name `/Key` whose next token is a `(literal)` or `<hex>` string.
/// The last wins, so an incremental update's newer value is preferred. **Pure.**
fn pdf_find_string(data: &[u8], key: &str) -> Option<String> {
    let needle = format!("/{key}");
    let needle = needle.as_bytes();
    let mut from = 0usize;
    let mut found = None;
    while let Some(rel) = find_bytes(data.get(from..)?, needle) {
        let at = from + rel + needle.len();
        from = at;
        // The name must end at a delimiter, so `/Title` does not match `/TitleCase`.
        let mut cursor = at;
        match data.get(cursor) {
            Some(byte) if byte.is_ascii_whitespace() || *byte == b'(' || *byte == b'<' => {}
            _ => continue,
        }
        while data.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        match data.get(cursor) {
            Some(b'(') => found = Some(read_pdf_literal(data, cursor + 1)),
            Some(b'<') => found = Some(read_pdf_hex(data, cursor + 1)),
            _ => {}
        }
    }
    found
}

/// A PDF literal string from just past its opening `(`: balanced parentheses, backslash escapes and
/// octal codes, decoded as UTF-16BE when it carries a byte-order mark. **Pure.**
fn read_pdf_literal(data: &[u8], start: usize) -> String {
    let mut depth = 1usize;
    let mut out = Vec::new();
    let mut i = start;
    while let Some(&byte) = data.get(i) {
        match byte {
            b'\\' => {
                i += 1;
                let Some(&escaped) = data.get(i) else { break };
                match escaped {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'0'..=b'7' => i = push_octal(data, i, &mut out),
                    other => out.push(other),
                }
            }
            b'(' => {
                depth += 1;
                out.push(b'(');
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                out.push(b')');
            }
            other => out.push(other),
        }
        if out.len() > MAX_DOCMETA_VALUE_BYTES {
            break;
        }
        i += 1;
    }
    decode_pdf_text(&out)
}

/// Consume an octal escape (`\ddd`) starting at `i` (the first digit), pushing the byte, and return
/// the index of the last digit consumed. **Pure.**
fn push_octal(data: &[u8], i: usize, out: &mut Vec<u8>) -> usize {
    let mut value = 0u32;
    let mut end = i;
    for step in 0..3 {
        match data.get(i + step) {
            Some(digit @ b'0'..=b'7') => {
                value = value * 8 + u32::from(digit - b'0');
                end = i + step;
            }
            _ => break,
        }
    }
    out.push(u8::try_from(value & 0xFF).unwrap_or(0));
    end
}

/// A PDF hex string from just past its opening `<`: hex digit pairs up to `>`, decoded as UTF-16BE
/// when it carries a byte-order mark. **Pure.**
fn read_pdf_hex(data: &[u8], start: usize) -> String {
    let mut nibbles = Vec::new();
    let mut i = start;
    while let Some(&byte) = data.get(i) {
        if byte == b'>' {
            break;
        }
        if let Some(value) = (byte as char).to_digit(16) {
            nibbles.push(u8::try_from(value).unwrap_or(0));
        }
        if nibbles.len() > MAX_DOCMETA_VALUE_BYTES * 2 {
            break;
        }
        i += 1;
    }
    if nibbles.len() % 2 == 1 {
        nibbles.push(0);
    }
    let bytes: Vec<u8> = nibbles
        .chunks_exact(2)
        .map(|pair| pair[0] << 4 | pair[1])
        .collect();
    decode_pdf_text(&bytes)
}

/// Decode a PDF text string: UTF-16BE when it starts with the `FE FF` byte-order mark, otherwise the
/// bytes as lossy UTF-8 (a superset of the common ASCII case). **Pure.**
fn decode_pdf_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units).trim().to_owned()
    } else {
        String::from_utf8_lossy(bytes).trim().to_owned()
    }
}

// ── PNG textual chunks ───────────────────────────────────────────────────────────────────

/// Collect a PNG's uncompressed textual and time metadata, kept on the file as `png:*` fields: each
/// `tEXt` and uncompressed `iTXt` chunk as `png:<keyword>`, and `tIME` as `png:ModificationTime`.
/// Compressed chunks (`zTXt` and compressed `iTXt`) are not inflated and the binary `eXIf` block is
/// left to the `exif` command, keeping the no-decompression, complement-not-duplicate contract. An
/// `iTXt` that merely carries the XMP packet (`XML:com.adobe.xmp`) is skipped, since [`extract_xmp`]
/// already reads it. A chunk that runs past the end of the file stops the walk. **Pure.**
fn extract_png_text(data: &[u8], fields: &mut Vec<(String, String)>) {
    let mut at = PNG_SIGNATURE.len();
    let mut chunks = 0usize;
    while chunks < MAX_PNG_CHUNKS && fields.len() < MAX_FIELDS {
        chunks += 1;
        let Some(length) = data.get(at..at + 4).map(read_u32_be) else {
            break;
        };
        let Some(kind) = data.get(at + 4..at + 8) else {
            break;
        };
        let body_start = at + 8;
        let Some(body) = body_start
            .checked_add(length)
            .and_then(|end| data.get(body_start..end))
        else {
            break;
        };
        match kind {
            b"IEND" => break,
            b"tEXt" => png_text_chunk(body, fields),
            b"iTXt" => png_itxt_chunk(body, fields),
            b"tIME" => png_time_chunk(body, fields),
            _ => {}
        }
        // length(4) + type(4) + body(length) + crc(4).
        let Some(next) = body_start
            .checked_add(length)
            .and_then(|e| e.checked_add(4))
        else {
            break;
        };
        at = next;
    }
}

/// A `tEXt` chunk: a Latin-1 `keyword`, a `NUL`, then Latin-1 text. **Pure.**
fn png_text_chunk(body: &[u8], fields: &mut Vec<(String, String)>) {
    let Some(sep) = body.iter().position(|&b| b == 0) else {
        return;
    };
    let keyword = latin1(&body[..sep]);
    let text = latin1(body.get(sep + 1..).unwrap_or_default());
    push_png_field(fields, &keyword, text);
}

/// An `iTXt` chunk: `keyword NUL flag method lang NUL transkeyword NUL text`. Only uncompressed text
/// (compression flag `0`) is read, as UTF-8; a compressed chunk, and an XMP packet carried as an
/// `iTXt`, are skipped. **Pure.**
fn png_itxt_chunk(body: &[u8], fields: &mut Vec<(String, String)>) {
    let Some(k_end) = body.iter().position(|&b| b == 0) else {
        return;
    };
    let keyword = latin1(&body[..k_end]);
    if keyword == "XML:com.adobe.xmp" {
        return;
    }
    // The compression flag must be present and zero, or the text is compressed and not inflated.
    if body.get(k_end + 1).copied() != Some(0) {
        return;
    }
    // Skip the flag and compression-method bytes, then the NUL-terminated language and translated
    // keyword, to reach the text.
    let mut cursor = k_end + 3;
    for _ in 0..2 {
        let Some(rel) = body
            .get(cursor..)
            .and_then(|rest| rest.iter().position(|&b| b == 0))
        else {
            return;
        };
        cursor += rel + 1;
    }
    let text = String::from_utf8_lossy(body.get(cursor..).unwrap_or_default()).into_owned();
    push_png_field(fields, &keyword, text);
}

/// A `tIME` chunk: year (two bytes), month, day, hour, minute, second, as `png:ModificationTime`.
/// **Pure.**
fn png_time_chunk(body: &[u8], fields: &mut Vec<(String, String)>) {
    let Some(b) = body.get(..7) else {
        return;
    };
    let year = u16::from_be_bytes([b[0], b[1]]);
    push_field(
        fields,
        "png:ModificationTime",
        format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}",
            month = b[2],
            day = b[3],
            hour = b[4],
            minute = b[5],
            second = b[6],
        ),
    );
}

/// Add a `tEXt`/`iTXt` value as a `png:<keyword>` field, skipping an empty keyword. **Pure.**
fn push_png_field(fields: &mut Vec<(String, String)>, keyword: &str, text: String) {
    let keyword = keyword.trim();
    if keyword.is_empty() {
        return;
    }
    push_field(fields, format!("png:{keyword}"), text);
}

/// Decode Latin-1 bytes, each byte one code point, to a `String`. **Pure.**
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

// ── bytes ──────────────────────────────────────────────────────────────────────────────────

/// The first index of `needle` in `haystack`, or `None`. **Pure.**
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A big-endian `u32` read from a four-byte slice, as a `usize`. **Pure.**
fn read_u32_be(bytes: &[u8]) -> usize {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
}

#[cfg(test)]
mod tests;
