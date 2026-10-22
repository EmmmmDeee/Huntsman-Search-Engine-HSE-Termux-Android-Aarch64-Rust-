//! Keyless, offline extraction of the metadata a document embeds in itself.
//!
//! One `docmeta FILE` reads the bytes already on the device -- no network, no key -- and surfaces
//! the provenance a file carries without anyone meaning to ship it: every XMP metadata packet (the
//! uncompressed `<x:xmpmeta>` XML block that PDFs, JPEG, TIFF and PNG embed; a PDF carries one for
//! the document and one per embedded image that kept its own), for a PDF the `/Info` dictionary its
//! trailer names, and for a PNG its uncompressed textual chunks (`tEXt`, `iTXt`) and modification
//! time (`tIME`). Author, creator tool, create and modify timestamps, document and instance
//! identifiers, the edit history (`xmpMM:History` events: action, software agent, time), the
//! documents a file was derived from (`xmpMM:DerivedFrom`), producer and title are kept as evidence on
//! a [`EntityKind::Document`] entity for the file, so nothing the metadata states is dropped: a
//! property stated more than once keeps each distinct value, and a PDF `/Info` value an incremental
//! update replaced or removed -- still stored in the file -- is reported as `info-prior:Key`. When
//! the XMP carries a GPS position it also becomes a [`EntityKind::Coordinates`] entity -- the same
//! `lat,lon` the `geocode` command
//! reverse-geocodes into an address.
//!
//! This complements the `exif` command, which decodes the binary EXIF block; `docmeta` reads the
//! XMP packet and PDF dictionary, which `exif` does not. Metadata is editable, so every field is the
//! file's embedded claim, not an independently verified fact. The scanner is bounds-checked and
//! allocation-bounded: it searches for the uncompressed metadata only, never decompresses, and caps
//! the packets, the field count and each value, and scans in time linear in the packet, so a
//! malformed or hostile file yields a clean result, never a panic or a runaway. Office Open XML
//! (`.docx`, `.xlsx`, `.pptx`) keeps its core properties
//! in a deflate-compressed part, which is not read here; an embedded XMP packet in such a file is. A
//! PNG's compressed text chunks (`zTXt`, compressed `iTXt`) are likewise not inflated, and its binary
//! `eXIf` block is left to the `exif` command.

use std::collections::{HashMap, HashSet};
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
Read the metadata a document embeds in itself, keyless and offline: no network request and no key. Every uncompressed XMP metadata packet (the <x:xmpmeta> XML block PDFs, JPEG, TIFF and PNG carry) is flattened field by field, including structured properties such as the xmpMM:History edit events and the xmpMM:DerivedFrom source document, and the /Info dictionary a PDF's trailer names (Title, Author, Subject, Keywords, Creator, Producer, CreationDate, ModDate) is read too, and for a PNG its uncompressed textual chunks (tEXt and iTXt) and modification time (tIME) become png:* fields (compressed chunks and the binary EXIF block, left to the exif command, are not read); an outline bookmark's title is never mistaken for the document's, an encrypted PDF's /Info strings are flagged rather than shown as ciphertext, and when an incremental update replaced or removed an /Info value, the superseded value still stored in the file is reported as info-prior:KEY with pdf:InfoRevisions counting the revisions. Every field is kept as evidence on a document entity for the file, so author, creator tool, create/modify timestamps, edit history, document and instance identifiers and title are preserved; a property stated more than once keeps each distinct value. When the XMP holds a GPS position it also becomes a coordinates entity -- the same lat,lon the geocode command reverse-geocodes to an address. Metadata is editable, so each field is the file's embedded claim, not an independently verified fact. This complements the exif command, which decodes the binary EXIF block; docmeta reads the XMP packet and PDF dictionary instead. A file with no embedded metadata is a clean result naming its format and size. Office Open XML (.docx, .xlsx, .pptx) keeps its core properties in a deflate-compressed part, which is not read; an embedded XMP packet in such a file is.";

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

/// Most XMP packets read from one file. A PDF carries one for the document and one per embedded image
/// that kept its own; a larger count is not collected past this bound.
const MAX_XMP_PACKETS: usize = 64;

/// Most XMP bytes scanned across every packet of one file.
const MAX_XMP_TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// Most `/Info` dictionary revisions read from one PDF, the current one included. Each incremental
/// update can add one; a larger count is not collected past this bound.
const MAX_INFO_REVISIONS: usize = 8;

/// Most bytes of a PDF `/Info` dictionary scanned for its closing `>>`.
const MAX_INFO_DICT_BYTES: usize = 256 * 1024;

/// The XMP list containers whose `rdf:li` items make up one property's value, with their close tags.
const XMP_CONTAINERS: [(&str, &str); 3] = [
    ("rdf:Seq", "</rdf:Seq>"),
    ("rdf:Bag", "</rdf:Bag>"),
    ("rdf:Alt", "</rdf:Alt>"),
];

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
    let mut fields = Fields::default();
    if format.starts_with("PDF") {
        extract_pdf_info(data, &mut fields);
    }
    if format == "PNG" {
        extract_png_text(data, &mut fields);
    }
    extract_xmp(data, &mut fields);
    let fields = fields.list;
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

/// The fields collected from one file, in first-seen order. A key stated more than once keeps each
/// distinct value, joined with `; ` in the order stated, so a repeated property (one `stEvt:action`
/// per history event, a second packet's `xmp:CreatorTool`) is never dropped.
#[derive(Debug, Default)]
struct Fields {
    list: Vec<(String, String)>,
    index: HashMap<String, usize>,
    seen: HashSet<(String, String)>,
}

impl Fields {
    /// Record `value` under `key`, capped, skipping an empty or already recorded value. A new key past
    /// [`MAX_FIELDS`] is not collected; a value is not appended to one already at the value cap.
    fn push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = cap(&value.into());
        if value.is_empty() {
            return;
        }
        if let Some(&at) = self.index.get(&key) {
            if self.list[at].1.len() >= MAX_DOCMETA_VALUE_BYTES
                || self.seen.contains(&(key.clone(), value.clone()))
            {
                return;
            }
            let joined = format!("{}; {value}", self.list[at].1);
            self.list[at].1 = cap(&joined);
        } else {
            if self.list.len() >= MAX_FIELDS {
                return;
            }
            self.index.insert(key.clone(), self.list.len());
            self.list.push((key.clone(), value.clone()));
        }
        self.seen.insert((key, value));
    }
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

/// Every field the file's embedded XMP packets state, as `prefix:Local` keys: attributes on any
/// element (an `rdf:Description`, and the struct shorthand on a property or `rdf:li`, as
/// `xmpMM:History` events are usually written), leaf elements (`<ns:Name>text</ns:Name>`), lists
/// (`rdf:Seq`/`rdf:Bag`/`rdf:Alt` of text `rdf:li`) and the members of structured properties. Every
/// packet is read, up to [`MAX_XMP_PACKETS`] and [`MAX_XMP_TOTAL_BYTES`]. **Pure.**
fn extract_xmp(data: &[u8], fields: &mut Fields) {
    let mut from = 0usize;
    let mut budget = MAX_XMP_TOTAL_BYTES;
    for _ in 0..MAX_XMP_PACKETS {
        let Some((start, end)) = find_xmp_packet(data, from) else {
            break;
        };
        let scanned = (end - start).min(MAX_XMP_BYTES).min(budget);
        collect_packet(
            &String::from_utf8_lossy(&data[start..start + scanned]),
            fields,
        );
        budget -= scanned;
        from = end;
        if budget == 0 {
            break;
        }
    }
}

/// The span of the next `<x:xmpmeta> … </x:xmpmeta>` packet at or after `from`. **Pure.**
fn find_xmp_packet(data: &[u8], from: usize) -> Option<(usize, usize)> {
    const CLOSE: &[u8] = b"</x:xmpmeta>";
    let start = from + find_bytes(data.get(from..)?, b"<x:xmpmeta")?;
    let end = start + find_bytes(data.get(start..)?, CLOSE)? + CLOSE.len();
    Some((start, end))
}

/// The next position of a fixed needle, remembered across calls whose start only moves forward, so
/// repeated searches over one packet scan each byte a bounded number of times. A needle found at `at`
/// from start `s` is also the first one at or after any later start up to `at`; a needle absent from
/// `s` on is absent from every later start.
struct Forward {
    needle: &'static str,
    last: Searched,
}

/// What a [`Forward`] search last learned.
#[derive(Clone, Copy)]
enum Searched {
    Never,
    Found(usize),
    Absent,
}

impl Forward {
    const fn new(needle: &'static str) -> Self {
        Self {
            needle,
            last: Searched::Never,
        }
    }

    fn find(&mut self, text: &str, from: usize) -> Option<usize> {
        match self.last {
            Searched::Absent => return None,
            Searched::Found(at) if at >= from => return Some(at),
            Searched::Found(_) | Searched::Never => {}
        }
        let found = text
            .get(from..)
            .and_then(|rest| rest.find(self.needle))
            .map(|rel| from + rel);
        self.last = found.map_or(Searched::Absent, Searched::Found);
        found
    }
}

/// Walk one packet's tags once, collecting attributes and property values. A property whose content
/// is a text leaf or a text list is recorded whole and skipped; any other content is structural and
/// is descended into, so a struct's members surface as their own fields. **Pure.**
fn collect_packet(text: &str, fields: &mut Fields) {
    let mut gt = Forward::new(">");
    let mut containers = XMP_CONTAINERS.map(|(_, close)| Forward::new(close));
    let mut from = 0usize;
    while let Some(rel) = text[from..].find('<') {
        let lt = from + rel;
        let Some(close_at) = gt.find(text, lt) else {
            break;
        };
        let open_end = close_at + 1;
        let tag = &text[lt + 1..close_at];
        let Some(name) = tag_name(tag) else {
            // A closing tag, a processing instruction or a comment.
            from = lt + 1;
            continue;
        };
        let property = is_property(&name);
        parse_attrs(
            &tag[name.len()..],
            property.then_some(name.as_str()),
            fields,
        );
        from = open_end;
        if !property || tag.ends_with('/') {
            continue;
        }
        if let Some((value, after)) = property_value(text, open_end, &name, &mut containers) {
            fields.push(name, value);
            from = after;
        }
    }
}

/// Whether an element name is an XMP property, not RDF or packet structure. **Pure.**
fn is_property(name: &str) -> bool {
    name.contains(':') && !name.starts_with("rdf:") && !name.starts_with("x:")
}

/// The value of the property `name` whose start tag ends at `open_end`, and the index just past it:
/// its text when the next tag is its own close, or its joined items when its content is a list of text
/// `rdf:li`. `None` for structured content, which the caller descends into. **Pure.**
fn property_value(
    text: &str,
    open_end: usize,
    name: &str,
    containers: &mut [Forward; 3],
) -> Option<(String, usize)> {
    let next = open_end + text[open_end..].find('<')?;
    let after_lt = &text[next + 1..];
    if after_lt
        .strip_prefix('/')
        .and_then(|rest| rest.strip_prefix(name))
        .is_some_and(|rest| rest.starts_with('>'))
    {
        let value = unescape_xml(text[open_end..next].trim());
        return Some((value, next + name.len() + 3));
    }
    let slot = XMP_CONTAINERS.iter().position(|(container, _)| {
        after_lt
            .strip_prefix(container)
            .is_some_and(|rest| rest.starts_with(['>', ' ', '\t', '\r', '\n']))
    })?;
    let close = &mut containers[slot];
    let end = close.find(text, next)?;
    let value = element_value(&text[next..end])?;
    Some((value, end + close.needle.len()))
}

/// Parse `name="value"` / `name='value'` pairs from one start tag's body, keeping the namespaced ones
/// that are not `xmlns:*`, `xml:*` or RDF syntax. On a property element (`element`), an
/// `rdf:resource` URI is that property's value. **Pure.**
fn parse_attrs(tag: &str, element: Option<&str>, fields: &mut Fields) {
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
        if name == "rdf:resource" {
            if let Some(element) = element {
                fields.push(element, unescape_xml(value));
            }
        } else if name.contains(':')
            && !name.starts_with("xmlns")
            && !name.starts_with("xml:")
            && !name.starts_with("rdf:")
        {
            fields.push(name, unescape_xml(value));
        }
        rest = &body[end + 1..];
    }
}

/// The element name at the start of a tag body, made of name characters, or `None` for a closing
/// tag, a processing instruction or a comment. **Pure.**
fn tag_name(tag: &str) -> Option<String> {
    let name: String = tag
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '.' | '_'))
        .collect();
    (!name.is_empty()).then_some(name)
}

/// The joined items of a list container's content (from its `<rdf:Seq>` start tag to just before its
/// close), or `None` when it has no text item or any item is structured (a self-closing `rdf:li` or
/// one with child elements), which the caller descends into instead. **Pure.**
fn element_value(list: &str) -> Option<String> {
    let mut items = Vec::new();
    let mut rest = list;
    while let Some(open) = rest.find("<rdf:li") {
        let after = &rest[open..];
        let gt = after.find('>')?;
        if after[..gt].ends_with('/') {
            return None;
        }
        let content = &after[gt + 1..];
        let close = content.find("</rdf:li>")?;
        let text = &content[..close];
        if text.contains('<') {
            return None;
        }
        let text = unescape_xml(text.trim());
        if !text.is_empty() {
            items.push(text);
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

/// Collect the string entries of the `/Info` dictionary the PDF's last trailer names as `info:Key`
/// fields. Only that dictionary is read, so an outline bookmark's or annotation's `/Title` is never
/// reported as the document's; nothing is read when no trailer names one or its object sits inside a
/// compressed object stream (not reachable without inflate). An encrypted PDF's `/Info` strings are
/// ciphertext, so they are not decoded: `pdf:Encrypted` says why they are absent. **Pure.**
fn extract_pdf_info(data: &[u8], fields: &mut Fields) {
    if pdf_is_encrypted(data) {
        fields.push(
            "pdf:Encrypted",
            "true; /Info strings are encrypted and not decoded",
        );
        return;
    }
    let revisions = pdf_info_revisions(data);
    let Some((current, prior)) = revisions.split_last() else {
        return;
    };
    for key in PDF_INFO_KEYS {
        if let Some(value) = pdf_find_string(current, key) {
            fields.push(format!("info:{key}"), value);
        }
    }
    if prior.is_empty() {
        return;
    }
    fields.push("pdf:InfoRevisions", revisions.len().to_string());
    // An incremental update appends the new `/Info` and leaves the old one in the file: a value
    // an editor replaced or removed is still there, and is reported as `info-prior:Key`.
    for key in PDF_INFO_KEYS {
        let now = pdf_find_string(current, key);
        for dict in prior {
            if let Some(value) = pdf_find_string(dict, key) {
                if now.as_deref() != Some(value.as_str()) {
                    fields.push(format!("info-prior:{key}"), value);
                }
            }
        }
    }
}

/// Whether a trailer names an `/Encrypt` dictionary (`/Encrypt N G R` or an inline `<<`). **Pure.**
fn pdf_is_encrypted(data: &[u8]) -> bool {
    pdf_trailer_dictionaries(data).any(|trailer| {
        pdf_name_values(trailer, b"/Encrypt").any(|at| {
            let at = skip_pdf_whitespace(trailer, at);
            trailer.get(at) == Some(&b'<') || pdf_reference(trailer, at).is_some()
        })
    })
}

/// Read only explicit uncompressed trailer dictionaries. A keyword inside a PDF object or comment
/// must not select unrelated metadata. Cross-reference streams need separate structured parsing.
fn pdf_trailer_dictionaries(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut from = 0usize;
    std::iter::from_fn(move || {
        loop {
            let at = from + find_bytes(data.get(from..)?, b"trailer")?;
            from = at + b"trailer".len();
            if data.get(from).is_some_and(|byte| !is_pdf_delimiter(*byte)) {
                continue;
            }
            let mut line_start = at;
            while line_start > 0 && matches!(data[line_start - 1], b' ' | b'\t') {
                line_start -= 1;
            }
            if line_start > 0 && !matches!(data[line_start - 1], b'\n' | b'\r') {
                continue;
            }
            if let Some(dict) = pdf_dictionary(data, skip_pdf_whitespace(data, from)) {
                return Some(dict);
            }
        }
    })
}

/// Every revision of the document's `/Info` dictionary, oldest first and the current one last: each
/// stored definition of each object a trailer names as `/Info`, up to [`MAX_INFO_REVISIONS`]. The
/// current one is the newest definition of the object the last trailer names (an incremental
/// update's newer copy wins); empty when no trailer names one or its object is not stored
/// uncompressed. **Pure.**
fn pdf_info_revisions(data: &[u8]) -> Vec<&[u8]> {
    let mut references: Vec<(u32, u16)> = Vec::new();
    for trailer in pdf_trailer_dictionaries(data) {
        for reference in pdf_name_values(trailer, b"/Info")
            .filter_map(|at| pdf_reference(trailer, skip_pdf_whitespace(trailer, at)))
        {
            references.retain(|known| *known != reference);
            references.push(reference);
        }
    }
    let Some(&current) = references.last() else {
        return Vec::new();
    };
    let skip = references.len().saturating_sub(MAX_INFO_REVISIONS);
    let mut definitions: Vec<(usize, bool)> = Vec::new();
    for &reference in &references[skip..] {
        definitions
            .extend(pdf_object_bodies(data, reference).map(|body| (body, reference == current)));
    }
    definitions.sort_unstable();
    let Some(newest) = definitions.iter().rposition(|&(_, is_current)| is_current) else {
        return Vec::new();
    };
    let newest = definitions.remove(newest);
    let mut revisions: Vec<&[u8]> = definitions
        .iter()
        .rev()
        .take(MAX_INFO_REVISIONS - 1)
        .rev()
        .filter_map(|&(body, _)| pdf_dictionary(data, skip_pdf_whitespace(data, body)))
        .collect();
    let Some(current) = pdf_dictionary(data, skip_pdf_whitespace(data, newest.0)) else {
        return Vec::new();
    };
    revisions.push(current);
    revisions
}

/// The index just past each `N G obj` header that defines `reference`, in file order. The header
/// must stand as its own tokens, so `11 0 obj` never counts as `1 0 obj`. **Pure.**
fn pdf_object_bodies(data: &[u8], (number, generation): (u32, u16)) -> impl Iterator<Item = usize> {
    let header = format!("{number} {generation} obj").into_bytes();
    let mut from = 0usize;
    std::iter::from_fn(move || {
        loop {
            let at = from + find_bytes(data.get(from..)?, &header)?;
            from = at + header.len();
            let starts_token = at == 0 || is_pdf_delimiter(data[at - 1]);
            let ends_token = data.get(from).is_none_or(|byte| is_pdf_delimiter(*byte));
            if starts_token && ends_token {
                return Some(from);
            }
        }
    })
}

/// The index just past every occurrence of the PDF name `name` that ends at a delimiter, so `/Info`
/// does not match `/InfoX` and `/Encrypt` does not match `/EncryptMetadata`. **Pure.**
fn pdf_name_values<'a>(data: &'a [u8], name: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0usize;
    std::iter::from_fn(move || {
        loop {
            let at = from + find_bytes(data.get(from..)?, name)? + name.len();
            from = at;
            if data.get(at).is_none_or(|byte| is_pdf_delimiter(*byte)) {
                return Some(at);
            }
        }
    })
}

/// An indirect reference `N G R` starting at `at`. **Pure.**
fn pdf_reference(data: &[u8], at: usize) -> Option<(u32, u16)> {
    let (number, at) = pdf_integer(data, at)?;
    let at = skip_pdf_whitespace(data, at);
    let (generation, at) = pdf_integer(data, at)?;
    let at = skip_pdf_whitespace(data, at);
    if data.get(at) != Some(&b'R')
        || data
            .get(at + 1)
            .is_some_and(|byte| !is_pdf_delimiter(*byte))
    {
        return None;
    }
    Some((number.try_into().ok()?, generation.try_into().ok()?))
}

/// An unsigned decimal integer of at most ten digits at `at`, and the index past it. **Pure.**
fn pdf_integer(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let digits = data
        .get(at..)?
        .iter()
        .take(11)
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits == 0 || digits > 10 {
        return None;
    }
    let value = std::str::from_utf8(&data[at..at + digits])
        .ok()?
        .parse()
        .ok()?;
    Some((value, at + digits))
}

/// The dictionary `<< … >>` starting at `at`, matched through nested dictionaries and literal and hex
/// strings, within [`MAX_INFO_DICT_BYTES`]. `None` when it is absent or unclosed. **Pure.**
fn pdf_dictionary(data: &[u8], at: usize) -> Option<&[u8]> {
    if data.get(at..at + 2)? != b"<<" {
        return None;
    }
    let limit = data.len().min(at.saturating_add(MAX_INFO_DICT_BYTES));
    let mut depth = 0usize;
    let mut i = at;
    while i < limit {
        match data[i] {
            b'<' if data.get(i + 1) == Some(&b'<') => {
                depth += 1;
                i += 2;
            }
            b'>' if data.get(i + 1) == Some(&b'>') => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return Some(&data[at..i]);
                }
            }
            b'<' => i += data[i..limit].iter().position(|&byte| byte == b'>')? + 1,
            b'(' => i = skip_pdf_literal(data, i + 1, limit)?,
            _ => i += 1,
        }
    }
    None
}

/// The index just past the `)` closing a literal string whose body starts at `i`. **Pure.**
fn skip_pdf_literal(data: &[u8], mut i: usize, limit: usize) -> Option<usize> {
    let mut depth = 1usize;
    while i < limit {
        match data[i] {
            b'\\' => i += 1,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The index of the first non-whitespace byte at or after `at`. **Pure.**
fn skip_pdf_whitespace(data: &[u8], mut at: usize) -> usize {
    while data
        .get(at)
        .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == 0)
    {
        at += 1;
    }
    at
}

/// A PDF whitespace or delimiter byte, which ends a name or number token. **Pure.**
fn is_pdf_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || byte == 0
        || matches!(
            byte,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

/// The last parseable value, within one dictionary, of a PDF name `/Key` whose next token is a
/// `(literal)` or `<hex>` string. **Pure.**
fn pdf_find_string(dict: &[u8], key: &str) -> Option<String> {
    let needle = format!("/{key}");
    let mut found = None;
    for at in pdf_name_values(dict, needle.as_bytes()) {
        let cursor = skip_pdf_whitespace(dict, at);
        match dict.get(cursor) {
            Some(b'(') => found = Some(read_pdf_literal(dict, cursor + 1)),
            Some(b'<') if dict.get(cursor + 1) != Some(&b'<') => {
                found = Some(read_pdf_hex(dict, cursor + 1));
            }
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
fn extract_png_text(data: &[u8], fields: &mut Fields) {
    let mut at = PNG_SIGNATURE.len();
    let mut chunks = 0usize;
    while chunks < MAX_PNG_CHUNKS && fields.list.len() < MAX_FIELDS {
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
fn png_text_chunk(body: &[u8], fields: &mut Fields) {
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
fn png_itxt_chunk(body: &[u8], fields: &mut Fields) {
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
fn png_time_chunk(body: &[u8], fields: &mut Fields) {
    let Some(b) = body.get(..7) else {
        return;
    };
    let year = u16::from_be_bytes([b[0], b[1]]);
    fields.push(
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
fn push_png_field(fields: &mut Fields, keyword: &str, text: String) {
    let keyword = keyword.trim();
    if keyword.is_empty() {
        return;
    }
    fields.push(format!("png:{keyword}"), text);
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
