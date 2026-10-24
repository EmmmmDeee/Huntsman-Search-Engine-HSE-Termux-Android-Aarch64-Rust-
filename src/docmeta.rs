//! Keyless, offline extraction of the metadata a document embeds in itself.
//!
//! One `docmeta FILE` reads the bytes already on the device -- no network, no key -- and surfaces
//! the provenance a file carries without anyone meaning to ship it: every XMP metadata packet (the
//! uncompressed `<x:xmpmeta>` XML block that PDFs, JPEG, TIFF and PNG embed; a PDF carries one for
//! the document and one per embedded image that kept its own), for a PDF the `/Info` dictionary its
//! trailer names, for a PNG its uncompressed textual chunks (`tEXt`, `iTXt`) and modification
//! time (`tIME`), and for a GIF its Comment Extension blocks (`gif:Comment`). Author, creator tool, create and modify timestamps, document and instance
//! identifiers, the edit history (`xmpMM:History` events: action, software agent, time), the
//! documents a file was derived from (`xmpMM:DerivedFrom`), producer and title are kept as evidence on
//! a [`EntityKind::Document`] entity for the file, so nothing the metadata states is dropped: a
//! property stated more than once keeps each distinct value, and a PDF `/Info` value an incremental
//! update replaced or removed -- still stored in the file -- is reported as `info-prior:Key`. When
//! the XMP carries a GPS position it also becomes a [`EntityKind::Coordinates`] entity -- the same
//! `lat,lon` the `geocode` command
//! reverse-geocodes into an address.
//!
//! A WebP or GIF is recognised by its container magic and named as such even when it carries only an
//! embedded XMP packet (found the same byte-scanned way as in any other container) or, for a GIF, a
//! comment. A JPEG's IPTC IIM block (the legacy Photoshop `APP13` record) is read too, surfacing the
//! by-line and caption writer, credit and source, headline and caption, keywords and the named
//! location (city, province, country) as `iptc:*` fields. This complements the `exif` command, which decodes the binary EXIF block; `docmeta` reads the
//! XMP packet and PDF dictionary, which `exif` does not. Metadata is editable, so every field is the
//! file's embedded claim, not an independently verified fact. The scanner is bounds-checked and
//! allocation-bounded: it searches for the uncompressed metadata only, never decompresses, and caps
//! the packets, the field count and each value, and scans in time linear in the packet, so a
//! malformed or hostile file yields a clean result, never a panic or a runaway. Office Open XML
//! (`.docx`, `.xlsx`, `.pptx`) keeps its core properties
//! in a deflate-compressed part, which is not read here; an embedded XMP packet in such a file is. A
//! PNG's compressed text chunks (`zTXt`, compressed `iTXt`) are likewise not inflated, and its binary
//! `eXIf` block is left to the `exif` command.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::canonical::canonical_coordinates;
use crate::entity::{
    Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity, scan_id,
};
use crate::error::Error;
use crate::exif::{
    MAX_METADATA_FIELDS, MAX_METADATA_VALUE_BYTES, PNG_SIGNATURE, cap_value, jpeg_segments,
    png_chunks,
};
use crate::lookup_report;
use crate::sha256::{hex32, sha256};
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};
use crate::textnorm::decode_xml_references;

/// The source/module name this command reports its findings under.
pub const SOURCE: &str = "docmeta";

pub const DOCMETA_USAGE: &str = "usage: huntsman-recon docmeta FILE";

pub const DOCMETA_HELP: &str = "\
docmeta FILE
Read the metadata a document embeds in itself, keyless and offline: no network request and no key. Every uncompressed XMP metadata packet (the <x:xmpmeta> XML block PDFs, JPEG, TIFF and PNG carry) is flattened field by field, including structured properties such as the xmpMM:History edit events and the xmpMM:DerivedFrom source document, and the /Info dictionary a PDF's trailer names (Title, Author, Subject, Keywords, Creator, Producer, CreationDate, ModDate) is read too, and for a PNG its uncompressed textual chunks (tEXt and iTXt) and modification time (tIME) become png:* fields (compressed chunks and the binary EXIF block, left to the exif command, are not read), and a GIF's Comment Extension blocks become gif:Comment fields, and a JPEG's IPTC IIM block (the legacy Photoshop APP13 record) becomes iptc:* fields (by-line, caption writer, credit, source, headline, caption, keywords and the named city/province/country location); an outline bookmark's title is never mistaken for the document's, an encrypted PDF's /Info strings are flagged rather than shown as ciphertext, and when an incremental update replaced or removed an /Info value, the superseded value still stored in the file is reported as info-prior:KEY with pdf:InfoRevisions counting the revisions. Every field is kept as evidence on a document entity for the file, so author, creator tool, create/modify timestamps, edit history, document and instance identifiers and title are preserved; a property stated more than once keeps each distinct value. When the XMP holds a GPS position it also becomes a coordinates entity -- the same lat,lon the geocode command reverse-geocodes to an address. Metadata is editable, so each field is the file's embedded claim, not an independently verified fact. This complements the exif command, which decodes the binary EXIF block; docmeta reads the XMP packet and PDF dictionary instead. A file with no embedded metadata is a clean result naming its format and size. Office Open XML (.docx, .xlsx, .pptx) keeps its core properties in a deflate-compressed part, which is not read; an embedded XMP packet in such a file is.";

/// The largest file read, in bytes. The whole file is read because a PDF's `/Info` and the XMP
/// packet can sit anywhere in it; a larger file is refused by name.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The file is read directly, so its metadata is reported with high but not absolute confidence:
/// embedded metadata is editable.
const DOCUMENT_CONFIDENCE: f64 = 0.9;

/// A GPS position is the file's embedded claim and can be spoofed, so it is reported a notch below
/// the document it came from.
const GPS_CONFIDENCE: f64 = 0.85;

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

/// Most trailers read by keyword, the newest of each kind: `trailer` lines that open a dictionary and
/// `startxref` lines that give an offset. An incremental update adds one of each, so this keeps a
/// long revision history whole, while a file of countless unclosed `trailer <<` costs at most this
/// many dictionary scans of [`MAX_INFO_DICT_BYTES`]. A bare word that opens nothing takes no place.
const MAX_PDF_TRAILERS: usize = 64;

/// Most blocks walked in one GIF's block stream, and most sub-blocks read from one of them. A GIF of
/// countless empty blocks or an unterminated sub-block chain costs at most this many steps.
const MAX_GIF_BLOCKS: usize = 4096;

/// Most Photoshop image-resource blocks walked in one JPEG APP13 segment.
const MAX_PHOTOSHOP_BLOCKS: usize = 256;

/// Most IPTC datasets read from one IPTC image-resource block.
const MAX_IPTC_DATASETS: usize = 512;

/// The XMP list containers whose `rdf:li` items make up one property's value, with their close tags.
const XMP_CONTAINERS: [(&str, &str); 3] = [
    ("rdf:Seq", "</rdf:Seq>"),
    ("rdf:Bag", "</rdf:Bag>"),
    ("rdf:Alt", "</rdf:Alt>"),
];

/// A list item's open-tag prefix and close tag.
const XMP_ITEM: (&str, &str) = ("<rdf:li", "</rdf:li>");

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
    if format == "GIF" {
        extract_gif_comments(data, &mut fields);
    }
    if format == "JPEG" {
        extract_iptc(data, &mut fields);
    }
    extract_xmp(&xmp_source(data), &mut fields);
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
    document_entity(&mut entities, &parsed, label, &sid, data);
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
fn document_entity(
    entities: &mut Vec<Entity>,
    parsed: &Parsed,
    label: &str,
    sid: &str,
    data: &[u8],
) {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, sid),
        summary(parsed, label),
    )
    .with_attr("format", parsed.format.as_str())
    .with_attr("metadata_field_count", parsed.fields.len().to_string())
    // Local observation over the exact bytes, independent of editable embedded metadata.
    .with_attr("file_sha256", hex32(&sha256(data)))
    .with_attr("file_size_bytes", data.len().to_string())
    .with_attr("file_hash_scope", "exact_input_bytes");
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
        &[SOURCE, "gps", crate::tags::GEOINT],
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
    /// [`MAX_METADATA_FIELDS`] is not collected; a value is not appended to one already at the value cap.
    fn push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = cap_value(&value.into());
        if value.is_empty() {
            return;
        }
        if let Some(&at) = self.index.get(&key) {
            if self.list[at].1.len() >= MAX_METADATA_VALUE_BYTES
                || self.seen.contains(&(key.clone(), value.clone()))
            {
                return;
            }
            let joined = format!("{}; {value}", self.list[at].1);
            self.list[at].1 = cap_value(&joined);
        } else {
            if self.list.len() >= MAX_METADATA_FIELDS {
                return;
            }
            self.index.insert(key.clone(), self.list.len());
            self.list.push((key.clone(), value.clone()));
        }
        self.seen.insert((key, value));
    }
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
    } else if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") {
        "WebP".to_owned()
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        "GIF".to_owned()
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

/// The namespace that opens a JPEG extended XMP `APP1` segment, before its 32-character GUID, the
/// packet's full length and this chunk's offset (four bytes each, big-endian).
const XMP_EXTENSION: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";

/// The bytes the XMP scan reads. A JPEG whose XMP outgrew one 64 KB segment (extended XMP, how
/// Photoshop stores a long `photoshop:DocumentAncestors` list) splits the extended packet into
/// chunks across `APP1` segments, each behind a header that would otherwise sit inside the packet
/// text. Those segments are cut out, and each packet is put back together from its chunks in offset
/// order and appended whole. Any other file is read as it is. **Pure.**
fn xmp_source(data: &[u8]) -> Cow<'_, [u8]> {
    if !data.starts_with(&[0xFF, 0xD8]) {
        return Cow::Borrowed(data);
    }
    let mut cuts = Vec::new();
    let mut chunks: Vec<(&[u8], u32, &[u8])> = Vec::new();
    for segment in jpeg_segments(data).filter(|segment| segment.marker == 0xE1) {
        let Some(header) = segment.payload.strip_prefix(XMP_EXTENSION) else {
            continue;
        };
        let (Some(guid), Some(offset), Some(chunk)) =
            (header.get(..32), header.get(36..40), header.get(40..))
        else {
            continue;
        };
        let offset = u32::from_be_bytes(offset.try_into().unwrap_or_default());
        cuts.push(segment.span);
        chunks.push((guid, offset, chunk));
    }
    if cuts.is_empty() {
        return Cow::Borrowed(data);
    }
    let mut joined = Vec::with_capacity(data.len());
    let mut kept_from = 0;
    for cut in cuts {
        joined.extend_from_slice(&data[kept_from..cut.start]);
        kept_from = cut.end;
    }
    joined.extend_from_slice(&data[kept_from..]);
    chunks.sort_by_key(|&(guid, offset, _)| (guid, offset));
    chunks.dedup_by_key(|&mut (guid, offset, _)| (guid, offset));
    for (_, _, chunk) in chunks {
        joined.extend_from_slice(chunk);
    }
    Cow::Owned(joined)
}

/// The span of the next `<x:xmpmeta> … </x:xmpmeta>` packet at or after `from`. **Pure.**
fn find_xmp_packet(data: &[u8], from: usize) -> Option<(usize, usize)> {
    const CLOSE: &[u8] = b"</x:xmpmeta>";
    let start = from + find_bytes(data.get(from..)?, b"<x:xmpmeta")?;
    let end = start + find_bytes(data.get(start..)?, CLOSE)? + CLOSE.len();
    Some((start, end))
}

/// The next position of a fixed needle, remembered across calls, so repeated searches over one packet
/// whose starts move forward scan each byte a bounded number of times. A needle found at `at` from
/// start `s` is also the first one at or after any later start up to `at`; a needle absent from `s`
/// on is absent from every later start. A start before the last one searches again.
struct Forward {
    needle: &'static str,
    /// Where the last search started, and what it found.
    last: Option<(usize, Option<usize>)>,
}

impl Forward {
    const fn new(needle: &'static str) -> Self {
        Self { needle, last: None }
    }

    fn find(&mut self, text: &str, from: usize) -> Option<usize> {
        if let Some((started, found)) = self.last {
            if from >= started && found.is_none_or(|at| at >= from) {
                return found;
            }
        }
        let found = text
            .get(from..)
            .and_then(|rest| rest.find(self.needle))
            .map(|rel| from + rel);
        self.last = Some((from, found));
        found
    }
}

/// Markup that may sit between a list's items and carries no value, with its terminator: comments
/// and processing instructions.
const XMP_IGNORABLE: [(&str, &str); 2] = [("<!--", "-->"), ("<?", "?>")];

/// Walk one packet's tags once, collecting attributes and property values. A property whose content
/// is a text leaf or a text list is recorded whole and skipped; any other content is structural and
/// is descended into, so a struct's members surface as their own fields. **Pure.**
fn collect_packet(text: &str, fields: &mut Fields) {
    let mut gt = Forward::new(">");
    let mut ignorable = XMP_IGNORABLE.map(|(_, end)| Forward::new(end));
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
        if let Some((value, after)) = property_value(text, open_end, &name, &mut ignorable) {
            fields.push(name, value);
            from = after;
        }
    }
}

/// Whether an element name is an XMP property, not RDF or packet structure. **Pure.**
fn is_property(name: &str) -> bool {
    name.contains(':') && !name.starts_with("rdf:") && !name.starts_with("x:")
}

/// The text of a value's raw XML, decoded by XML's rules and trimmed on both sides after decoding,
/// so a reference that decodes to whitespace is trimmed as literal whitespace is. **Pure.**
fn decoded_text(raw: &str) -> String {
    decode_xml_references(raw.trim()).trim().to_owned()
}

/// The value of the property `name` whose start tag ends at `open_end`, and the index just past it:
/// its text when the next tag is its own close, or its joined items when its content is a list of text
/// `rdf:li`. `None` for structured content, which the caller descends into. **Pure.**
fn property_value(
    text: &str,
    open_end: usize,
    name: &str,
    ignorable: &mut [Forward; 2],
) -> Option<(String, usize)> {
    let next = open_end + text[open_end..].find('<')?;
    let after_lt = &text[next + 1..];
    if after_lt
        .strip_prefix('/')
        .and_then(|rest| rest.strip_prefix(name))
        .is_some_and(|rest| rest.starts_with('>'))
    {
        return Some((decoded_text(&text[open_end..next]), next + name.len() + 3));
    }
    let &(_, close) = XMP_CONTAINERS.iter().find(|(container, _)| {
        after_lt
            .strip_prefix(container)
            .is_some_and(|rest| rest.starts_with(['>', ' ', '\t', '\r', '\n']))
    })?;
    let (items, end) = list_items(text, next, close, ignorable)?;
    (!items.is_empty()).then(|| (items.join("; "), end))
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
                fields.push(element, decode_xml_references(value));
            }
        } else if name.contains(':')
            && !name.starts_with("xmlns")
            && !name.starts_with("xml:")
            && !name.starts_with("rdf:")
        {
            fields.push(name, decode_xml_references(value));
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

/// The text items of the list container whose start tag begins at `at`, and the index just past
/// its `close` tag, read child by child in order: whitespace, comments and processing instructions,
/// then text `rdf:li` items, then the close. `None` at the first child that is anything else (a
/// self-closing or structured item, a property, stray text, an unterminated comment), which the
/// caller descends into instead. Each byte is read at most once, the terminators of `ignorable`
/// markup are found through the packet's shared searches, and a refusal stops where the unexpected
/// child starts, so a packet of lists that are never closed or never itemised is still read in
/// linear time. **Pure.**
fn list_items(
    text: &str,
    at: usize,
    close: &str,
    ignorable: &mut [Forward; 2],
) -> Option<(Vec<String>, usize)> {
    let (item_open, item_close) = XMP_ITEM;
    let start_end = at + text[at..].find('>')?;
    if text[at..start_end].ends_with('/') {
        return None;
    }
    let mut items = Vec::new();
    let mut i = start_end + 1;
    loop {
        let lt = i + text[i..].find('<')?;
        if !text[i..lt].trim().is_empty() {
            return None;
        }
        let rest = &text[lt..];
        if rest.starts_with(close) {
            return Some((items, lt + close.len()));
        }
        if let Some(slot) = XMP_IGNORABLE
            .iter()
            .position(|(open, _)| rest.starts_with(open))
        {
            let terminator = &mut ignorable[slot];
            i = terminator.find(text, lt + XMP_IGNORABLE[slot].0.len())? + terminator.needle.len();
            continue;
        }
        let is_item = rest
            .strip_prefix(item_open)
            .is_some_and(|after| after.starts_with(['>', ' ', '\t', '\r', '\n']));
        if !is_item {
            return None;
        }
        let gt = lt + rest.find('>')?;
        if text[lt..gt].ends_with('/') {
            return None;
        }
        let content = gt + 1;
        let content_end = content + text[content..].find('<')?;
        if !text[content_end..].starts_with(item_close) {
            return None;
        }
        let item = decoded_text(&text[content..content_end]);
        if !item.is_empty() {
            items.push(item);
        }
        i = content_end + item_close.len();
    }
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
    let (positive, negative_mark, maximum) = match negative {
        'S' => (b'N', b'S', 90.0),
        'W' => (b'E', b'W', 180.0),
        _ => return None,
    };
    let value = value.trim();
    let hemisphere = value.as_bytes().last()?.to_ascii_uppercase();
    if hemisphere != positive && hemisphere != negative_mark {
        return None;
    }
    // Hemisphere is an ASCII byte. Do not infer north/east from any other trailing letter.
    let body = value.get(..value.len().checked_sub(1)?)?;
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
    // A fourth component, negative angle, non-finite value or minute/second overflow
    // cannot be interpreted as a location. Reject it rather than normalising a bad claim.
    if parts.next().is_some()
        || !degrees.is_finite()
        || !minutes.is_finite()
        || !seconds.is_finite()
        || degrees < 0.0
        || minutes < 0.0
        || minutes >= 60.0
        || seconds < 0.0
        || seconds >= 60.0
    {
        return None;
    }
    let magnitude = degrees + minutes / 60.0 + seconds / 3600.0;
    if !magnitude.is_finite() || magnitude > maximum {
        return None;
    }
    Some(if hemisphere == negative_mark {
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
    // Every lookup below reads the same trailers, so the file is scanned for them once.
    let trailers: Vec<&[u8]> = pdf_trailer_dictionaries(data).collect();
    if pdf_is_encrypted(&trailers) {
        fields.push(
            "pdf:Encrypted",
            "true; /Info strings are encrypted and not decoded",
        );
        return;
    }
    let revisions = pdf_info_revisions(data, &trailers);
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
fn pdf_is_encrypted(trailers: &[&[u8]]) -> bool {
    trailers.iter().any(|trailer| {
        pdf_name_values(trailer, b"/Encrypt").any(|at| {
            let at = skip_pdf_whitespace(trailer, at);
            trailer.get(at) == Some(&b'<') || pdf_reference(trailer, at).is_some()
        })
    })
}

/// The document's trailer dictionaries, in file order: each explicit `trailer << … >>` that starts
/// a line, and each cross-reference stream dictionary (`/Type /XRef`, how PDF 1.5 and later write
/// a trailer, with no `trailer` keyword) that a `startxref` offset points at. Only these name the
/// document's `/Info` and `/Encrypt`; the same keywords inside an object, a string or a comment
/// select nothing. **Pure.**
fn pdf_trailer_dictionaries(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let opens_dictionary = |at: usize| data.get(at..at + 2) == Some(b"<<");
    let mut found: Vec<(usize, &[u8])> = newest_keyword_lines(data, b"trailer", opens_dictionary)
        .into_iter()
        .filter_map(|at| Some((at, pdf_dictionary(data, at)?)))
        .collect();
    let offset = |at: usize| usize::try_from(pdf_integer(data, at)?.0).ok();
    found.extend(
        newest_keyword_lines(data, b"startxref", |at| offset(at).is_some())
            .into_iter()
            .filter_map(|at| {
                let offset = offset(at)?;
                Some((offset, pdf_xref_stream_dictionary(data, offset)?))
            }),
    );
    found.sort_unstable_by_key(|&(at, _)| at);
    found.dedup_by_key(|&mut (at, _)| at);
    found.into_iter().map(|(_, dict)| dict)
}

/// The start of the next token after each of the newest [`MAX_PDF_TRAILERS`] lines of
/// [`pdf_keyword_lines`] whose next token `follows` accepts, in file order. **Pure.**
fn newest_keyword_lines(
    data: &[u8],
    keyword: &[u8],
    follows: impl Fn(usize) -> bool,
) -> Vec<usize> {
    let mut kept = std::collections::VecDeque::with_capacity(MAX_PDF_TRAILERS);
    for at in pdf_keyword_lines(data, keyword)
        .map(|at| skip_pdf_whitespace(data, at))
        .filter(|&at| follows(at))
    {
        if kept.len() == MAX_PDF_TRAILERS {
            kept.pop_front();
        }
        kept.push_back(at);
    }
    kept.into()
}

/// The index just past each `keyword` that starts a line (after optional spaces) and ends at a
/// delimiter. **Pure.**
fn pdf_keyword_lines<'a>(data: &'a [u8], keyword: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0usize;
    std::iter::from_fn(move || {
        loop {
            let at = from + find_bytes(data.get(from..)?, keyword)?;
            from = at + keyword.len();
            if data.get(from).is_some_and(|byte| !is_pdf_delimiter(*byte)) {
                continue;
            }
            let mut line_start = at;
            while line_start > 0 && matches!(data[line_start - 1], b' ' | b'\t') {
                line_start -= 1;
            }
            if line_start == 0 || matches!(data[line_start - 1], b'\n' | b'\r') {
                return Some(from);
            }
        }
    })
}

/// The dictionary of the cross-reference stream object `N G obj << /Type /XRef … >>` starting at
/// `offset`, or `None` when no such object starts there (a classic `xref` table, whose trailer
/// [`pdf_trailer_dictionaries`] reads by its keyword, or a wrong offset). **Pure.**
fn pdf_xref_stream_dictionary(data: &[u8], offset: usize) -> Option<&[u8]> {
    let (_, at) = pdf_integer(data, offset)?;
    let (_, at) = pdf_integer(data, skip_pdf_whitespace(data, at))?;
    let at = skip_pdf_whitespace(data, at);
    if data.get(at..at + 3)? != b"obj" {
        return None;
    }
    let dict = pdf_dictionary(data, skip_pdf_whitespace(data, at + 3))?;
    pdf_name_values(dict, b"/Type")
        .any(|at| {
            let at = skip_pdf_whitespace(dict, at);
            dict.get(at..at + 5) == Some(b"/XRef")
                && dict.get(at + 5).is_none_or(|byte| is_pdf_delimiter(*byte))
        })
        .then_some(dict)
}

/// Every revision of the document's `/Info` dictionary, oldest first and the current one last: each
/// stored definition of each object a trailer names as `/Info`, up to [`MAX_INFO_REVISIONS`]. The
/// current one is the newest definition of the object the last trailer names (an incremental
/// update's newer copy wins); empty when no trailer names one or its object is not stored
/// uncompressed. **Pure.**
fn pdf_info_revisions<'a>(data: &'a [u8], trailers: &[&[u8]]) -> Vec<&'a [u8]> {
    // Walking the trailers newest first, the first sight of a reference is its newest naming, so
    // the first MAX_INFO_REVISIONS distinct ones are the revisions kept, and each is checked
    // against at most that many: a trailer packed with references costs linear time.
    let mut references: Vec<(u32, u16)> = Vec::with_capacity(MAX_INFO_REVISIONS);
    'trailers: for trailer in trailers.iter().rev() {
        let named: Vec<(u32, u16)> = pdf_name_values(trailer, b"/Info")
            .filter_map(|at| pdf_reference(trailer, skip_pdf_whitespace(trailer, at)))
            .collect();
        for reference in named.into_iter().rev() {
            if !references.contains(&reference) {
                references.push(reference);
                if references.len() == MAX_INFO_REVISIONS {
                    break 'trailers;
                }
            }
        }
    }
    references.reverse();
    let Some(&current) = references.last() else {
        return Vec::new();
    };
    let mut definitions: Vec<(usize, bool)> = Vec::new();
    for &reference in &references {
        definitions
            .extend(pdf_object_bodies(data, reference).map(|body| (body, reference == current)));
    }
    definitions.sort_unstable();
    let Some(newest) = definitions.iter().rposition(|&(_, is_current)| is_current) else {
        return Vec::new();
    };
    let newest = definitions.remove(newest);
    let Some(current) = pdf_dictionary(data, skip_pdf_whitespace(data, newest.0)) else {
        return Vec::new();
    };
    let mut revisions: Vec<&[u8]> = definitions
        .iter()
        .rev()
        .take(MAX_INFO_REVISIONS - 1)
        .rev()
        .filter_map(|&(body, _)| pdf_dictionary(data, skip_pdf_whitespace(data, body)))
        .collect();
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

/// The index just past each key `name` of the dictionary `dict` (`<< … >>`): a whole name token at
/// the dictionary's top level, so `/Info` never matches `/InfoX`, a key of a nested dictionary, a
/// name in an array, or the bytes of a string or comment. **Pure.**
fn pdf_name_values<'a>(dict: &'a [u8], name: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let mut at = 0usize;
    let (mut depth, mut arrays) = (0usize, 0usize);
    std::iter::from_fn(move || {
        while at < dict.len() {
            let (token, next) = pdf_token(dict, at, dict.len())?;
            let start = std::mem::replace(&mut at, next);
            match token {
                PdfToken::DictOpen => depth += 1,
                PdfToken::DictClose => depth = depth.saturating_sub(1),
                PdfToken::ArrayOpen => arrays += 1,
                PdfToken::ArrayClose => arrays = arrays.saturating_sub(1),
                PdfToken::Name if depth == 1 && arrays == 0 && dict[start..next] == *name => {
                    return Some(next);
                }
                PdfToken::Name | PdfToken::Other => {}
            }
        }
        None
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

/// The dictionary `<< … >>` starting at `at`, its brackets matched through [`pdf_token`] (so a
/// `>>` or `(` inside a string or comment is not syntax), within [`MAX_INFO_DICT_BYTES`]. `None`
/// when it is absent or unclosed. **Pure.**
fn pdf_dictionary(data: &[u8], at: usize) -> Option<&[u8]> {
    if data.get(at..at + 2)? != b"<<" {
        return None;
    }
    let limit = data.len().min(at.saturating_add(MAX_INFO_DICT_BYTES));
    let mut depth = 0usize;
    let mut i = at;
    while i < limit {
        let (token, next) = pdf_token(data, i, limit)?;
        i = next;
        match token {
            PdfToken::DictOpen => depth += 1,
            PdfToken::DictClose => {
                depth -= 1;
                if depth == 0 {
                    return Some(&data[at..i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// What one PDF token is, as far as finding a dictionary's extent and its keys needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PdfToken {
    DictOpen,
    DictClose,
    ArrayOpen,
    ArrayClose,
    Name,
    /// A number, keyword, string, hex string or comment, read whole.
    Other,
}

/// The token starting at `i` and the index just past it, within `data[..limit]`. Literal strings,
/// hex strings and `%` comments are read whole, so nothing inside one is mistaken for syntax: the
/// one place the PDF path tells structure from text. `None` when a string or hex string runs past
/// `limit`; a comment runs to its line end or to `limit`. **Pure.**
fn pdf_token(data: &[u8], i: usize, limit: usize) -> Option<(PdfToken, usize)> {
    let pair = |byte| data.get(i + 1) == Some(&byte) && i + 1 < limit;
    Some(match data[i] {
        b'<' if pair(b'<') => (PdfToken::DictOpen, i + 2),
        b'>' if pair(b'>') => (PdfToken::DictClose, i + 2),
        b'[' => (PdfToken::ArrayOpen, i + 1),
        b']' => (PdfToken::ArrayClose, i + 1),
        b'<' => (
            PdfToken::Other,
            i + data[i..limit].iter().position(|&byte| byte == b'>')? + 1,
        ),
        b'(' => (PdfToken::Other, skip_pdf_literal(data, i + 1, limit)?),
        b'%' => (PdfToken::Other, pdf_comment_end(data, i, limit)),
        b'/' => {
            let end = data[i + 1..limit]
                .iter()
                .position(|&byte| is_pdf_delimiter(byte))
                .map_or(limit, |at| i + 1 + at);
            (PdfToken::Name, end)
        }
        _ => (PdfToken::Other, i + 1),
    })
}

/// The index of the line end closing the comment that starts at `i`, or `limit`. **Pure.**
fn pdf_comment_end(data: &[u8], i: usize, limit: usize) -> usize {
    data[i..limit]
        .iter()
        .position(|&byte| matches!(byte, b'\n' | b'\r'))
        .map_or(limit, |at| i + at)
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

/// The index of the first byte at or after `at` that is neither whitespace nor in a `%` comment,
/// which PDF reads as whitespace. **Pure.**
fn skip_pdf_whitespace(data: &[u8], mut at: usize) -> usize {
    loop {
        match data.get(at) {
            Some(byte) if byte.is_ascii_whitespace() || *byte == 0 => at += 1,
            Some(b'%') => at = pdf_comment_end(data, at, data.len()),
            _ => return at,
        }
    }
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
                    // A backslash before an end of line joins the lines: neither is kept.
                    b'\r' => {
                        if data.get(i + 1) == Some(&b'\n') {
                            i += 1;
                        }
                    }
                    b'\n' => {}
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
        if out.len() > MAX_METADATA_VALUE_BYTES {
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
        if nibbles.len() > MAX_METADATA_VALUE_BYTES * 2 {
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

/// Decode a PDF text string (PDF 32000 section 7.9.2.2): UTF-16BE after the `FE FF` byte-order
/// mark, UTF-8 after `EF BB BF` (PDF 2.0), and otherwise `PDFDocEncoding`. Bytes that are already
/// valid UTF-8 without the mark, as some producers write, are read as UTF-8: `PDFDocEncoding` text
/// almost never forms valid multi-byte UTF-8, and ASCII reads the same either way. **Pure.**
fn decode_pdf_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units).trim().to_owned()
    } else if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(rest).trim().to_owned()
    } else if let Ok(text) = std::str::from_utf8(bytes) {
        text.trim().to_owned()
    } else {
        bytes
            .iter()
            .map(|&byte| pdf_doc_char(byte))
            .collect::<String>()
            .trim()
            .to_owned()
    }
}

/// One `PDFDocEncoding` byte (PDF 32000 Annex D.2): Latin-1 but for the accents at `18`-`1F`, the
/// punctuation and letters at `80`-`A0`, and the codes it leaves undefined. **Pure.**
fn pdf_doc_char(byte: u8) -> char {
    const ACCENTS: [char; 8] = ['˘', 'ˇ', 'ˆ', '˙', '˝', '˛', '˚', '˜'];
    const HIGH: [char; 33] = [
        '•', '†', '‡', '…', '—', '–', 'ƒ', '⁄', '‹', '›', '−', '‰', '„', '“', '”', '‘', '’', '‚',
        '™', 'ﬁ', 'ﬂ', 'Ł', 'Œ', 'Š', 'Ÿ', 'Ž', 'ı', 'ł', 'œ', 'š', 'ž', '\u{FFFD}', '€',
    ];
    match byte {
        0x18..=0x1F => ACCENTS[usize::from(byte - 0x18)],
        0x80..=0xA0 => HIGH[usize::from(byte - 0x80)],
        0x7F | 0xAD => char::REPLACEMENT_CHARACTER,
        _ => char::from(byte),
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
    for (kind, body) in png_chunks(data).map_while(Result::ok) {
        if fields.list.len() >= MAX_METADATA_FIELDS {
            break;
        }
        match kind {
            b"tEXt" => png_text_chunk(body, fields),
            b"iTXt" => png_itxt_chunk(body, fields),
            b"tIME" => png_time_chunk(body, fields),
            _ => {}
        }
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

// ── GIF ────────────────────────────────────────────────────────────────────────────────────

/// A GIF's Comment Extensions, read keyless and offline: each `0x21 0xFE` block's text becomes a
/// `gif:Comment` field. Image data is LZW-compressed and is skipped, not inflated; other extensions
/// and colour tables carry no document metadata and are stepped over. **Pure.**
fn extract_gif_comments(data: &[u8], fields: &mut Fields) {
    for comment in gif_comments(data) {
        if fields.list.len() >= MAX_METADATA_FIELDS {
            break;
        }
        fields.push("gif:Comment", comment);
    }
}

/// Every Comment Extension in a GIF's block stream, as Latin-1 text. The header, logical screen
/// descriptor and optional global colour table are stepped over; each later block is skipped by its
/// own structure (an image descriptor's local colour table and sub-blocks, an extension's
/// sub-blocks) so a `0x21 0xFE` inside compressed image data is never mistaken for a comment. A
/// malformed, truncated or unknown block ends the walk. Bounded by [`MAX_GIF_BLOCKS`]. **Pure.**
fn gif_comments(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    // Header (6 bytes) then the logical screen descriptor (7 bytes); its packed field is byte 10.
    let Some(packed) = data.get(10).copied() else {
        return out;
    };
    let mut cursor = 13usize;
    if packed & 0x80 != 0 {
        cursor += 3 * gif_color_table_entries(packed);
    }
    for _ in 0..MAX_GIF_BLOCKS {
        match data.get(cursor).copied() {
            // Extension: introducer, label, then a sub-block chain. Only a Comment Extension's bytes
            // are collected; any other extension is skipped without copying its payload.
            Some(0x21) => {
                let label = data.get(cursor + 1).copied();
                if label == Some(0xFE) {
                    let (text, next) = gif_sub_blocks(data, cursor + 2);
                    // A comment is surfaced only when its chain reached the zero-length terminator;
                    // a chain that ran off the end of the file is truncated evidence, not a complete
                    // field, so it is dropped rather than promoted.
                    let Some(next) = next else { break };
                    if let Some(bytes) = text {
                        out.push(latin1(&bytes));
                    }
                    cursor = next;
                } else {
                    let Some(next) = gif_skip_sub_blocks(data, cursor + 2) else {
                        break;
                    };
                    cursor = next;
                }
            }
            // Image descriptor: 9 fixed bytes, a packed byte, an optional local colour table, the
            // LZW minimum-code-size byte, then an image-data sub-block chain. The compressed image
            // data is skipped by its lengths, never copied.
            Some(0x2C) => {
                let Some(local) = data.get(cursor + 9).copied() else {
                    break;
                };
                let mut at = cursor + 10;
                if local & 0x80 != 0 {
                    at += 3 * gif_color_table_entries(local);
                }
                at += 1;
                let Some(next) = gif_skip_sub_blocks(data, at) else {
                    break;
                };
                cursor = next;
            }
            // The trailer (0x3B), a malformed byte, or the end of the stream all stop the walk.
            _ => break,
        }
    }
    out
}

/// The entry count of a GIF colour table from its owner's packed field: `2^(size+1)`, the low three
/// bits giving `size`. **Pure.**
fn gif_color_table_entries(packed: u8) -> usize {
    1usize << (u32::from(packed & 0x07) + 1)
}

/// Walk a GIF sub-block chain from `from`: a length byte then that many data bytes, repeating until a
/// zero-length block. Returns the concatenated data, when any, and the index one past the terminator,
/// or `None` for the index when the chain is truncated. Bounded by [`MAX_GIF_BLOCKS`]. **Pure.**
fn gif_sub_blocks(data: &[u8], from: usize) -> (Option<Vec<u8>>, Option<usize>) {
    let mut cursor = from;
    let mut collected: Option<Vec<u8>> = None;
    for _ in 0..MAX_GIF_BLOCKS {
        let Some(len) = data.get(cursor).copied() else {
            return (collected, None);
        };
        if len == 0 {
            return (collected, Some(cursor + 1));
        }
        let start = cursor + 1;
        let end = start + usize::from(len);
        let Some(chunk) = data.get(start..end) else {
            return (collected, None);
        };
        collected
            .get_or_insert_with(Vec::new)
            .extend_from_slice(chunk);
        cursor = end;
    }
    (collected, None)
}

/// Advance past a GIF sub-block chain from `from` without collecting it, used for image data and
/// non-comment extensions so a frame's compressed bytes are never copied. Returns the index one past
/// the zero-length terminator, or `None` when the chain runs off the end of the file. Bounded by
/// [`MAX_GIF_BLOCKS`]. **Pure.**
fn gif_skip_sub_blocks(data: &[u8], from: usize) -> Option<usize> {
    let mut cursor = from;
    for _ in 0..MAX_GIF_BLOCKS {
        let len = data.get(cursor).copied()?;
        if len == 0 {
            return Some(cursor + 1);
        }
        cursor = cursor + 1 + usize::from(len);
        // A sub-block whose data extends past the end of the file is a truncated chain.
        if cursor > data.len() {
            return None;
        }
    }
    None
}

// ── IPTC (Photoshop APP13) ───────────────────────────────────────────────────────────────

/// A JPEG's IPTC IIM metadata, read keyless and offline. The IIM datasets ride in an APP13 (`0xED`)
/// "Photoshop 3.0" segment, inside the `8BIM` image-resource block whose id is `0x0404`. Each known
/// Application-Record text dataset becomes an `iptc:<Field>` field: the by-line and caption writer
/// (who made or captioned the file), the credit and source, the headline and caption, the keywords,
/// and the named location (city, sub-location, province, country). A repeated dataset such as a
/// keyword keeps each value. Values are read as UTF-8. **Pure.**
fn extract_iptc(data: &[u8], fields: &mut Fields) {
    for segment in jpeg_segments(data).filter(|segment| segment.marker == 0xED) {
        let Some(mut irb) = segment.payload.strip_prefix(b"Photoshop 3.0\0") else {
            continue;
        };
        for _ in 0..MAX_PHOTOSHOP_BLOCKS {
            let Some((id, block, rest)) = photoshop_block(irb) else {
                break;
            };
            if id == 0x0404 {
                parse_iptc_datasets(block, fields);
            }
            irb = rest;
        }
        if fields.list.len() >= MAX_METADATA_FIELDS {
            break;
        }
    }
}

/// Split the first `8BIM` image-resource block off `irb`: its resource id, its data, and the bytes
/// after it. The Pascal name field (a length byte then the name) and the data are each padded to an
/// even length. `None` when `irb` does not begin with a whole block. **Pure.**
fn photoshop_block(irb: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    let rest = irb.strip_prefix(b"8BIM")?;
    let id = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
    let name_total = 1 + usize::from(*rest.get(2)?);
    // Pad the name field to an even length.
    let name_total = name_total + (name_total % 2);
    let after_name = rest.get(2 + name_total..)?;
    let size = usize::try_from(u32::from_be_bytes([
        *after_name.first()?,
        *after_name.get(1)?,
        *after_name.get(2)?,
        *after_name.get(3)?,
    ]))
    .ok()?;
    let data = after_name.get(4..4 + size)?;
    let padded = size + (size % 2);
    let tail = after_name.get(4 + padded..).unwrap_or_default();
    Some((id, data, tail))
}

/// Walk the IPTC IIM datasets in one resource block: each is `0x1C`, a record byte, a dataset byte, a
/// two-byte big-endian length, then the value. A known Application-Record text dataset is pushed as
/// an `iptc:<Field>` field; an unknown or binary dataset is stepped over. An extended-length marker
/// (rare, the high bit set) ends the walk rather than risk a misread. Bounded by
/// [`MAX_IPTC_DATASETS`]. **Pure.**
fn parse_iptc_datasets(data: &[u8], fields: &mut Fields) {
    // Collect bounded borrowed slices first: record 1:90 can appear after a text field.
    // This avoids interpreting the same bytes differently depending on dataset order.
    let mut datasets = Vec::new();
    let mut at = 0usize;
    for _ in 0..MAX_IPTC_DATASETS {
        if data.get(at).copied() != Some(0x1C) {
            break;
        }
        let (Some(&record), Some(&dataset)) = (data.get(at + 1), data.get(at + 2)) else {
            break;
        };
        let Some(len) = data
            .get(at + 3..at + 5)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        else {
            break;
        };
        if len & 0x8000 != 0 {
            break;
        }
        let end = at + 5 + usize::from(len);
        let Some(value) = data.get(at + 5..end) else {
            break;
        };
        datasets.push((record, dataset, value));
        at = end;
    }

    // IPTC IIM envelope 1:90, ESC % G, explicitly designates UTF-8.
    // Without that declaration, even valid non-ASCII UTF-8 is only a tentative interpretation.
    let declared_utf8 = datasets
        .iter()
        .any(|&(record, dataset, value)| record == 1 && dataset == 90 && value == b"\x1b%G");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (record, dataset, value) in datasets {
        let Some(name) = iptc_field_name(record, dataset) else {
            continue;
        };
        match std::str::from_utf8(value) {
            Ok(text) => {
                fields.push(format!("iptc:{name}"), text);
                if !declared_utf8 && !value.is_ascii() {
                    fields.push(
                        format!("iptc:{name}Encoding"),
                        "character set undeclared; UTF-8-compatible text is unverified",
                    );
                }
            }
            Err(_) => {
                // Never replace unknown legacy bytes with U+FFFD and call that exact evidence.
                // Keep a bounded hex preview plus a digest and length for full-byte provenance.
                let shown = value.len().min(512);
                let mut hex = String::with_capacity(shown * 2);
                for &byte in &value[..shown] {
                    hex.push(char::from(HEX[usize::from(byte >> 4)]));
                    hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
                }
                let suffix = if shown < value.len() {
                    "; hex prefix only; original bytes retained in source file"
                } else {
                    ""
                };
                fields.push(
                    format!("iptc:{name}"),
                    format!("[undecoded IPTC bytes hex:{hex}{suffix}]"),
                );
                fields.push(
                    format!("iptc:{name}Encoding"),
                    if declared_utf8 {
                        "declared UTF-8; invalid byte sequence"
                    } else {
                        "character set undeclared; exact text decoding unavailable"
                    },
                );
                fields.push(format!("iptc:{name}RawSha256"), hex32(&sha256(value)));
                fields.push(format!("iptc:{name}RawByteCount"), value.len().to_string());
            }
        }
    }
}

/// The field name for an IPTC Application-Record (record `2`) text dataset, or `None` for a binary or
/// unmapped dataset. **Pure.**
fn iptc_field_name(record: u8, dataset: u8) -> Option<&'static str> {
    if record != 2 {
        return None;
    }
    Some(match dataset {
        5 => "ObjectName",
        25 => "Keywords",
        40 => "SpecialInstructions",
        55 => "DateCreated",
        60 => "TimeCreated",
        80 => "Byline",
        85 => "BylineTitle",
        90 => "City",
        92 => "SubLocation",
        95 => "ProvinceState",
        100 => "CountryCode",
        101 => "CountryName",
        103 => "TransmissionReference",
        105 => "Headline",
        110 => "Credit",
        115 => "Source",
        116 => "CopyrightNotice",
        118 => "Contact",
        120 => "Caption",
        122 => "CaptionWriter",
        _ => return None,
    })
}

// ── bytes ──────────────────────────────────────────────────────────────────────────────────

/// The first index of `needle` in `haystack`, or `None`. A file is scanned many times over (up to
/// [`MAX_FILE_BYTES`] for each keyword), so candidates are found with [`find_byte`], eight bytes at
/// a time, and only they are compared whole. **Pure.**
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let (&first, rest) = needle.split_first()?;
    let last_start = haystack.len().checked_sub(needle.len())?;
    let mut from = 0usize;
    while from <= last_start {
        let at = from + find_byte(&haystack[from..=last_start], first)?;
        if haystack[at + 1..at + needle.len()] == *rest {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// The first index of `byte` in `haystack`, testing a 64-bit word at a time for a byte equal to it
/// (the word XOR `byte` repeated has a zero byte exactly where one matches). **Pure.**
fn find_byte(haystack: &[u8], byte: u8) -> Option<usize> {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    let repeated = ONES * u64::from(byte);
    let mut words = haystack.chunks_exact(8);
    let mut offset = 0usize;
    for word in &mut words {
        let bytes = [
            word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
        ];
        let diff = u64::from_le_bytes(bytes) ^ repeated;
        if diff.wrapping_sub(ONES) & !diff & HIGHS != 0 {
            return word.iter().position(|&b| b == byte).map(|at| offset + at);
        }
        offset += 8;
    }
    words
        .remainder()
        .iter()
        .position(|&b| b == byte)
        .map(|at| offset + at)
}

#[cfg(test)]
mod tests;
