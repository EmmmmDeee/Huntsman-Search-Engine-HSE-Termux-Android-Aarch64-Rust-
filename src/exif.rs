//! Keyless, offline EXIF metadata and GPS extraction from an image file.
//!
//! One `exif IMAGE-FILE` reads the bytes already on the device -- no network, no key -- and parses
//! the EXIF block a camera embeds. JPEG (the `APP1` `Exif\0\0` segment), TIFF (the whole file),
//! WebP (the `EXIF` RIFF chunk) and PNG (the `eXIf` chunk) are understood; all carry the same
//! TIFF-structured image-file directories (IFDs). Every tag the
//! directories name is kept as evidence on a [`EntityKind::Document`] entity for the file, up to
//! [`MAX_METADATA_FIELDS`] shared between the directories so none crowds out another, with a count of
//! any not kept, and when the GPS IFD holds a position it also becomes a
//! [`EntityKind::Coordinates`] entity -- the same `lat,lon` the `geocode` command reverse-geocodes
//! into an address. Nothing is inferred beyond what the tags state; EXIF can be edited, so the
//! position is the file's embedded claim, not an independently verified location.
//!
//! The parser is bounds-checked and allocation-bounded: every read is range-checked against the
//! buffer, directory entry counts and value lengths are capped, and only the Exif and GPS sub-IFDs
//! are followed, so a malformed or hostile file yields a clean error, never a panic or a runaway.

use std::path::PathBuf;

use crate::canonical::canonical_coordinates;
use crate::entity::{
    Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity, scan_id,
};
use crate::error::Error;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};
use crate::textnorm;

/// The source/module name this command reports its findings under.
pub const SOURCE: &str = "exif";

pub const EXIF_USAGE: &str = "usage: huntsman-recon exif IMAGE-FILE";

pub const EXIF_HELP: &str = "\
exif IMAGE-FILE
Read the EXIF metadata a camera embeds in a local image, keyless and offline: no network request and no key. JPEG, TIFF, WebP and PNG images are parsed; the EXIF image-file directories (IFD0, the Exif sub-IFD and the GPS IFD) are decoded and every tag is kept as evidence on a document entity for the file, so camera make and model, lens, timestamps, orientation, dimensions and every other field are preserved, up to 512 fields shared between the directories so none crowds out another (a file holding more says how many were not kept), each value shown up to 8 KiB and a long list of numbers as whole numbers with its count. When the GPS IFD holds a position it also becomes a coordinates entity -- the same lat,lon the geocode command reverse-geocodes to an address -- with altitude and GPS timestamp when present. EXIF can be edited, so the position is the file's embedded claim, not an independently verified location. A file that is not a JPEG, TIFF, WebP or PNG image, or whose EXIF is malformed, is reported as such; a readable image with no EXIF is a clean result with the file's format and size.";

/// The largest image read, in bytes. EXIF sits at the head of the file, but the whole file is read
/// so a TIFF whose directories point deep into it still parses; a larger file is refused by name.
pub const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

/// The image is the file itself, read directly, so its metadata is reported with high but not
/// absolute confidence: EXIF is editable.
const DOCUMENT_CONFIDENCE: f64 = 0.9;

/// A GPS position is the camera's embedded claim and can be spoofed, so it is reported a notch below
/// the document it came from.
const GPS_CONFIDENCE: f64 = 0.85;

/// Most entries one IFD may declare. A real directory holds a few dozen; a larger count is corrupt
/// or hostile and is not walked past this bound.
const MAX_IFD_ENTRIES: u16 = 4096;

/// Most bytes one tag's value may occupy. ASCII and arrays beyond this are truncated for display
/// rather than allocated in full.
const MAX_EXIF_VALUE_BYTES: usize = 8192;

/// Most metadata fields surfaced from one file, by this reader and by [`crate::docmeta`] alike. A
/// real file declares a few dozen; a larger count is corrupt or hostile and is not collected past
/// this bound, so what one file yields, and one inspection's answer, stays bounded.
pub(crate) const MAX_METADATA_FIELDS: usize = 512;

/// Most bytes one field's displayed value may occupy, for both readers. A value rendered longer, such
/// as an array of thousands of numbers, is truncated for display.
pub(crate) const MAX_METADATA_VALUE_BYTES: usize = 8192;

/// `value` trimmed and cut on a char boundary so its rendering is at most
/// [`MAX_METADATA_VALUE_BYTES`]: a character the report escapes ([`textnorm::is_escaped`]) counts at
/// the length of its escape, so a value of control bytes cannot render several times the bound.
/// **Pure.**
pub(crate) fn cap_value(value: &str) -> String {
    let value = value.trim();
    let mut shown = 0usize;
    for (at, c) in value.char_indices() {
        shown += if textnorm::is_escaped(c) {
            c.escape_default().len()
        } else {
            c.len_utf8()
        };
        if shown > MAX_METADATA_VALUE_BYTES {
            return value[..at].to_owned();
        }
    }
    value.to_owned()
}

pub type ExifRun = SourceRun<Report>;

/// A finished `exif` run: the rendered report, the entities it is made of, and the source outcome.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// One parsed `exif IMAGE-FILE` argument: the path to read and a label for the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExifArgs {
    pub path: PathBuf,
    pub label: String,
}

impl ExifArgs {
    /// # Errors
    /// [`Error::Invalid`] for a missing or extra argument, [`Error::InvalidValue`] for an empty path.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let [raw] = args else {
            return Err(Error::Invalid("exif needs exactly one image file".into()));
        };
        if raw.trim().is_empty() {
            return Err(Error::invalid_value("the image path is empty"));
        }
        Ok(Self {
            path: PathBuf::from(raw),
            label: raw.clone(),
        })
    }
}

/// A GPS position read from the GPS IFD. `lat`/`lon` are signed decimal degrees.
#[derive(Debug, Clone, PartialEq)]
pub struct GpsFix {
    pub lat: f64,
    pub lon: f64,
    pub altitude_m: Option<f64>,
    pub timestamp_utc: Option<String>,
}

/// Everything one image's EXIF yields: its container format, every decoded tag in directory order,
/// and the GPS position when one is present and in range.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Parsed {
    pub format: &'static str,
    pub fields: Vec<(String, String)>,
    /// Fields the file holds past [`MAX_METADATA_FIELDS`], which are not kept.
    pub omitted: usize,
    pub gps: Option<GpsFix>,
}

/// Parse the EXIF of one image.
///
/// # Errors
/// A static message when `image` is not a JPEG, TIFF, WebP or PNG image, its container is
/// truncated, or its TIFF header is malformed. An image with no EXIF block, or a readable one with an
/// empty directory, is not an error: it returns a [`Parsed`] with its format and no fields.
pub fn parse(image: &[u8]) -> Result<Parsed, &'static str> {
    if image.starts_with(&[0xFF, 0xD8]) {
        let format = "JPEG";
        match find_jpeg_exif(image) {
            Some(tiff) => decode_tiff(tiff, format),
            None => Ok(Parsed {
                format,
                ..Parsed::default()
            }),
        }
    } else if image.starts_with(b"II\x2a\x00") || image.starts_with(b"MM\x00\x2a") {
        decode_tiff(image, "TIFF")
    } else if image.starts_with(b"RIFF") && image.get(8..12) == Some(b"WEBP") {
        decode_found(find_webp_exif(image)?, "WebP")
    } else if image.starts_with(PNG_SIGNATURE) {
        decode_found(find_png_exif(image)?, "PNG")
    } else {
        Err("not a JPEG, TIFF, WebP or PNG image")
    }
}

/// The decoded EXIF block a container held, or a clean result naming the format when it held none.
fn decode_found(tiff: Option<&[u8]>, format: &'static str) -> Result<Parsed, &'static str> {
    match tiff {
        Some(tiff) => decode_tiff(tiff, format),
        None => Ok(Parsed {
            format,
            ..Parsed::default()
        }),
    }
}

/// A container's EXIF payload with the `Exif\0\0` signature some writers put before it removed,
/// leaving the TIFF block.
fn without_exif_signature(payload: &[u8]) -> &[u8] {
    payload.strip_prefix(b"Exif\x00\x00").unwrap_or(payload)
}

/// Run the whole command: parse `image`, build the entities, and render the report. `label` names
/// the file in the report and entity values.
#[must_use]
pub fn run(image: &[u8], label: &str, now_unix: u64) -> ExifRun {
    let parsed = match parse(image) {
        Ok(parsed) => parsed,
        Err(why) => return ExifRun::Failed(format!("{label}: {why}")),
    };
    let sid = scan_id(SOURCE, label);
    let mut entities = Vec::new();
    document_entity(&mut entities, &parsed, label, &sid);
    gps_entity(&mut entities, parsed.gps.as_ref(), label, &sid);
    merge_by_uid(&mut entities);

    let outcome = SourceExecutionOutcome::success(SOURCE, now_unix, entities.len());
    let outcomes = vec![outcome];
    match lookup_report::render(&entities, &outcomes) {
        Ok(text) => ExifRun::Printed {
            text,
            report: Report { entities, outcomes },
        },
        Err(message) => ExifRun::Failed(message),
    }
}

/// The document entity for the file, carrying its format and every decoded tag as evidence.
fn document_entity(entities: &mut Vec<Entity>, parsed: &Parsed, label: &str, sid: &str) {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, sid),
        exif_summary(parsed, label),
    )
    .with_attr("format", parsed.format)
    .with_attr("exif_field_count", parsed.fields.len().to_string());
    if parsed.omitted > 0 {
        evidence = evidence.with_attr("exif_fields_omitted", parsed.omitted.to_string());
    }
    for (name, value) in &parsed.fields {
        evidence = evidence.with_attr(format!("exif_{name}"), value.as_str());
    }
    push_entity(
        entities,
        EntityKind::Document,
        label,
        DOCUMENT_CONFIDENCE,
        sid,
        evidence,
        &[SOURCE, "image"],
    );
}

/// The coordinates entity for an embedded GPS position, when one is present and in range.
fn gps_entity(entities: &mut Vec<Entity>, gps: Option<&GpsFix>, label: &str, sid: &str) {
    let Some(gps) = gps else { return };
    let Some(coordinates) = canonical_coordinates(&format!("{},{}", gps.lat, gps.lon)) else {
        return;
    };
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, sid),
        format!("GPS position embedded in {label}"),
    )
    .with_attr("source_file", label)
    .with_attr("coordinates", coordinates.as_str())
    .with_attr("derivation", "EXIF GPS IFD");
    if let Some(altitude) = gps.altitude_m {
        evidence = evidence.with_attr("altitude_m", format!("{altitude:.2}"));
    }
    if let Some(timestamp) = &gps.timestamp_utc {
        evidence = evidence.with_attr("gps_timestamp_utc", timestamp.as_str());
    }
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
fn exif_summary(parsed: &Parsed, label: &str) -> String {
    if parsed.fields.is_empty() {
        format!("{} image {label} with no EXIF metadata", parsed.format)
    } else if parsed.omitted > 0 {
        format!(
            "{} image {label} with {} EXIF field(s) kept and {} more not kept",
            parsed.format,
            parsed.fields.len(),
            parsed.omitted
        )
    } else {
        format!(
            "{} image {label} with {} EXIF field(s)",
            parsed.format,
            parsed.fields.len()
        )
    }
}

// ── JPEG container ───────────────────────────────────────────────────────────────────────

/// The TIFF block inside a JPEG's `APP1 Exif\0\0` segment, or `None` when there is none. **Pure.**
fn find_jpeg_exif(image: &[u8]) -> Option<&[u8]> {
    jpeg_segments(image).find_map(|segment| {
        (segment.marker == 0xE1)
            .then_some(segment.payload)?
            .strip_prefix(b"Exif\x00\x00")
    })
}

/// One marker segment of a JPEG: its marker byte, its whole span from its `0xFF`, and the payload
/// after its length.
pub(crate) struct JpegSegment<'a> {
    pub(crate) marker: u8,
    pub(crate) span: std::ops::Range<usize>,
    pub(crate) payload: &'a [u8],
}

/// Each marker segment of a JPEG after its SOI marker, up to the start of scan or end of image: the
/// one JPEG segment walker, shared with [`crate::docmeta`]. Fill bytes are skipped and standalone
/// markers carry no segment; a malformed segment ends the walk. **Pure.**
pub(crate) fn jpeg_segments(image: &[u8]) -> impl Iterator<Item = JpegSegment<'_>> {
    let mut i = 2; // past the SOI marker
    std::iter::from_fn(move || {
        loop {
            // Skip any 0xFF fill bytes before a marker.
            while image.get(i) == Some(&0xFF) && image.get(i + 1) == Some(&0xFF) {
                i += 1;
            }
            if *image.get(i)? != 0xFF {
                return None;
            }
            let start = i;
            let marker = *image.get(i + 1)?;
            i += 2;
            // Start of scan or end of image: no metadata segment follows.
            if marker == 0xDA || marker == 0xD9 {
                return None;
            }
            // Standalone markers carry no length.
            if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
                continue;
            }
            let length = usize::from(be_u16(image, i)?);
            if length < 2 {
                return None;
            }
            let payload = image.get(i + 2..i + length)?;
            i += length;
            return Some(JpegSegment {
                marker,
                span: start..i,
                payload,
            });
        }
    })
    .fuse()
}

/// A big-endian u16 at `offset`. **Pure.**
fn be_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = buf.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

// ── WebP RIFF container ────────────────────────────────────────────────────────────────

/// Read the EXIF payload in a bounded WebP RIFF chunk stream. An EXIF chunk contains the
/// existing TIFF structure, sometimes preceded by the six-byte Exif signature.
/// Malformed bounds are an error, never a clean absence of metadata.
fn find_webp_exif(image: &[u8]) -> Result<Option<&[u8]>, &'static str> {
    if !image.starts_with(b"RIFF") || image.get(8..12) != Some(b"WEBP") {
        return Err("WebP: invalid RIFF header");
    }
    let size: [u8; 4] = image
        .get(4..8)
        .and_then(|raw| raw.try_into().ok())
        .ok_or("WebP: truncated RIFF size")?;
    let end = usize::try_from(u32::from_le_bytes(size))
        .ok()
        .and_then(|length| length.checked_add(8))
        .ok_or("WebP: invalid RIFF size")?;
    if end < 12 || end > image.len() {
        return Err("WebP: truncated RIFF container");
    }
    let mut offset = 12usize;
    while offset < end {
        let header = image
            .get(offset..offset + 8)
            .filter(|_| offset + 8 <= end)
            .ok_or("WebP: truncated chunk header")?;
        let length = u32::from_le_bytes(
            header[4..8]
                .try_into()
                .map_err(|_| "WebP: invalid chunk size")?,
        );
        let start = offset + 8;
        let tail = usize::try_from(length)
            .ok()
            .and_then(|len| start.checked_add(len))
            .ok_or("WebP: invalid chunk size")?;
        let next = tail
            .checked_add(usize::from(u8::from(length % 2 != 0)))
            .ok_or("WebP: invalid chunk padding")?;
        if next > end {
            return Err("WebP: truncated chunk payload");
        }
        if &header[..4] == b"EXIF" {
            return Ok(Some(without_exif_signature(&image[start..tail])));
        }
        offset = next;
    }
    Ok(None)
}

// ── PNG chunk stream ─────────────────────────────────────────────────────────────────────

/// The PNG file signature: the eight bytes every PNG begins with.
pub(crate) const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Each chunk of a PNG after its signature, as its four-byte type and its body, through `IEND`: the
/// one chunk walker, shared with [`crate::docmeta`]. A chunk that runs past the end of the file is an
/// `Err` item and ends the walk; a file that ends cleanly on a chunk boundary without `IEND` ends it
/// too. Every chunk takes at least twelve bytes, so the walk is bounded by the file, never by a count
/// that a large image's thousands of `IDAT` chunks would reach before a later `eXIf` or text chunk.
/// **Pure.**
pub(crate) fn png_chunks(
    data: &[u8],
) -> impl Iterator<Item = Result<(&[u8], &[u8]), &'static str>> {
    let mut at = PNG_SIGNATURE.len();
    let mut done = false;
    std::iter::from_fn(move || {
        if done || at == data.len() {
            return None;
        }
        let chunk = data.get(at..at + 8).and_then(|header| {
            let length = usize::try_from(u32::from_be_bytes(header[..4].try_into().ok()?)).ok()?;
            let body_end = (at + 8).checked_add(length)?;
            let body = data.get(at + 8..body_end)?;
            // length(4) + type(4) + body + crc(4).
            let next = body_end.checked_add(4)?;
            data.get(body_end..next)?;
            Some((&header[4..], body, next))
        });
        let Some((kind, body, next)) = chunk else {
            done = true;
            return Some(Err("PNG: truncated chunk"));
        };
        at = next;
        done = kind == b"IEND";
        Some(Ok((kind, body)))
    })
}

/// The payload of a PNG's `eXIf` chunk, a TIFF block. Truncated chunks before it are an error,
/// never a clean absence of metadata.
fn find_png_exif(image: &[u8]) -> Result<Option<&[u8]>, &'static str> {
    for chunk in png_chunks(image) {
        let (kind, body) = chunk?;
        if kind == b"eXIf" {
            return Ok(Some(without_exif_signature(body)));
        }
    }
    Ok(None)
}

// ── TIFF directories ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

/// A bounds-checked reader over the TIFF block, honouring its byte order.
struct Tiff<'a> {
    buf: &'a [u8],
    endian: Endian,
}

impl Tiff<'_> {
    fn u16(&self, offset: usize) -> Option<u16> {
        let bytes: [u8; 2] = self.buf.get(offset..offset + 2)?.try_into().ok()?;
        Some(match self.endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        })
    }

    fn u32(&self, offset: usize) -> Option<u32> {
        let bytes: [u8; 4] = self.buf.get(offset..offset + 4)?.try_into().ok()?;
        Some(match self.endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        })
    }

    fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        self.buf.get(offset..offset.checked_add(len)?)
    }
}

/// One raw directory entry, with its value bytes already located and copied out.
struct Entry {
    tag: u16,
    typ: u16,
    /// The value bytes (inline or followed to their offset), capped at [`MAX_EXIF_VALUE_BYTES`].
    value: Vec<u8>,
}

/// Decode a TIFF block (the whole TIFF file, or a JPEG's embedded Exif block) into a [`Parsed`].
fn decode_tiff(buf: &[u8], format: &'static str) -> Result<Parsed, &'static str> {
    let endian = match buf.get(0..2) {
        Some(b"II") => Endian::Little,
        Some(b"MM") => Endian::Big,
        _ => return Err("EXIF: bad TIFF byte order"),
    };
    let tiff = Tiff { buf, endian };
    if tiff.u16(2) != Some(42) {
        return Err("EXIF: bad TIFF magic number");
    }
    let ifd0 = tiff.u32(4).ok_or("EXIF: truncated TIFF header")? as usize;

    let (mut image, mut camera, mut position) = (
        Directory::default(),
        Directory::default(),
        Directory::default(),
    );
    let mut gps_offset = None;
    let mut exif_offset = None;

    for entry in read_ifd(&tiff, ifd0) {
        match entry.tag {
            0x8769 => exif_offset = pointer(&tiff, &entry),
            0x8825 => gps_offset = pointer(&tiff, &entry),
            _ => image.push(ifd0_tag_name(entry.tag), &named_value(&tiff, &entry)),
        }
    }
    if let Some(offset) = exif_offset {
        for entry in read_ifd(&tiff, offset) {
            if entry.tag == 0x8825 {
                gps_offset = gps_offset.or_else(|| pointer(&tiff, &entry));
            } else {
                camera.push(exif_tag_name(entry.tag), &named_value(&tiff, &entry));
            }
        }
    }
    let gps = gps_offset.and_then(|offset| decode_gps(&tiff, offset, &mut position));
    let (fields, omitted) = share_fields([image, camera, position]);

    Ok(Parsed {
        format,
        fields,
        omitted,
        gps,
    })
}

/// The fields one directory (IFD0, the Exif sub-IFD, the GPS IFD) yields, at most
/// [`MAX_METADATA_FIELDS`], and how many more it held.
#[derive(Default)]
struct Directory {
    fields: Vec<(String, String)>,
    omitted: usize,
}

impl Directory {
    /// Keep a named field with its display value capped, skipping an empty one. **Pure.**
    fn push(&mut self, name: String, value: &str) {
        let value = cap_value(value);
        if value.is_empty() {
            return;
        }
        if self.fields.len() < MAX_METADATA_FIELDS {
            self.fields.push((name, value));
        } else {
            self.omitted += 1;
        }
    }
}

/// The directories' fields in directory order within [`MAX_METADATA_FIELDS`], shared so that no
/// directory crowds out another: the smallest keep all of theirs and the rest share what is left
/// equally, so a first directory padded with junk tags cannot hide the camera and GPS fields after
/// it. Returns them with the count of fields not kept. **Pure.**
fn share_fields(directories: [Directory; 3]) -> (Vec<(String, String)>, usize) {
    let mut smallest_first = [0, 1, 2];
    smallest_first.sort_by_key(|&at| directories[at].fields.len());
    let mut share = [0; 3];
    let mut left = MAX_METADATA_FIELDS;
    for (done, &at) in smallest_first.iter().enumerate() {
        share[at] = directories[at].fields.len().min(left / (3 - done));
        left -= share[at];
    }
    let mut fields = Vec::new();
    let mut omitted = 0;
    for (directory, share) in directories.into_iter().zip(share) {
        omitted += directory.omitted + directory.fields.len() - share;
        fields.extend(directory.fields.into_iter().take(share));
    }
    (fields, omitted)
}

/// The entries of the IFD at `offset`, bounded by [`MAX_IFD_ENTRIES`]. **Pure.**
fn read_ifd(tiff: &Tiff, offset: usize) -> Vec<Entry> {
    let mut entries = Vec::new();
    let Some(count) = tiff.u16(offset) else {
        return entries;
    };
    let count = count.min(MAX_IFD_ENTRIES);
    for index in 0..count {
        let at = offset + 2 + usize::from(index) * 12;
        let (Some(tag), Some(typ), Some(cnt)) = (tiff.u16(at), tiff.u16(at + 2), tiff.u32(at + 4))
        else {
            break;
        };
        let Some(value) = read_value(tiff, typ, cnt, at + 8) else {
            continue;
        };
        entries.push(Entry { tag, typ, value });
    }
    entries
}

/// Copy a tag's value bytes, whether they sit inline in the 4-byte field at `field` or at the
/// offset those 4 bytes hold. Capped at [`MAX_EXIF_VALUE_BYTES`]. **Pure.**
fn read_value(tiff: &Tiff, typ: u16, count: u32, field: usize) -> Option<Vec<u8>> {
    let unit = type_size(typ)?;
    let total = usize::try_from(count).ok()?.checked_mul(unit)?;
    let total = total.min(MAX_EXIF_VALUE_BYTES);
    let bytes = if total <= 4 {
        tiff.slice(field, total)?
    } else {
        let offset = usize::try_from(tiff.u32(field)?).ok()?;
        tiff.slice(offset, total)?
    };
    Some(bytes.to_vec())
}

/// The byte width of one value of TIFF type `typ`, or `None` for an unknown type. **Pure.**
fn type_size(typ: u16) -> Option<usize> {
    Some(match typ {
        1 | 2 | 6 | 7 => 1, // BYTE, ASCII, SBYTE, UNDEFINED
        3 | 8 => 2,         // SHORT, SSHORT
        4 | 9 | 11 => 4,    // LONG, SLONG, FLOAT
        5 | 10 | 12 => 8,   // RATIONAL, SRATIONAL, DOUBLE
        _ => return None,
    })
}

/// The IFD offset a pointer tag (Exif or GPS sub-IFD) holds. **Pure.**
fn pointer(tiff: &Tiff, entry: &Entry) -> Option<usize> {
    let bytes: [u8; 4] = entry.value.get(0..4)?.try_into().ok()?;
    let offset = match tiff.endian {
        Endian::Little => u32::from_le_bytes(bytes),
        Endian::Big => u32::from_be_bytes(bytes),
    };
    usize::try_from(offset).ok()
}

// ── value formatting ─────────────────────────────────────────────────────────────────────

/// A human-readable rendering of one entry's value. **Pure.**
fn named_value(tiff: &Tiff, entry: &Entry) -> String {
    match entry.typ {
        2 => ascii(&entry.value),
        3 => numbers(&entry.value, 2, |b| u64::from(read_u16(tiff.endian, b))),
        4 => numbers(&entry.value, 4, |b| u64::from(read_u32(tiff.endian, b))),
        5 => rationals(tiff.endian, &entry.value, false),
        10 => rationals(tiff.endian, &entry.value, true),
        // TIFF type 1 (BYTE), 7 (UNDEFINED) and any unknown type fall back to a hex rendering.
        _ => bytes_hint(&entry.value),
    }
}

/// An ASCII value: the bytes up to the first NUL, trimmed, as lossless UTF-8. **Pure.**
fn ascii(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_owned()
}

/// A fallback for byte and undefined values: a short hex rendering. **Pure.**
fn bytes_hint(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A comma-joined list of fixed-width integers read by `read`. **Pure.**
fn numbers(bytes: &[u8], width: usize, read: impl Fn(&[u8]) -> u64) -> String {
    listed(
        bytes
            .chunks_exact(width)
            .map(|chunk| read(chunk).to_string()),
    )
}

/// `items` joined with `", "`, as many whole ones as fit in [`MAX_METADATA_VALUE_BYTES`]; when some
/// do not, the text ends with how many there are, so a value is never shown cut part way through.
/// **Pure.**
fn listed(items: impl ExactSizeIterator<Item = String>) -> String {
    let total = items.len();
    let more = format!(" \u{2026} ({total} values)");
    let mut out = String::new();
    for (at, item) in items.enumerate() {
        let separator = if at == 0 { 0 } else { 2 };
        let reserve = if at + 1 < total { more.len() } else { 0 };
        if out.len() + separator + item.len() + reserve > MAX_METADATA_VALUE_BYTES {
            out.push_str(&more);
            return out;
        }
        if separator > 0 {
            out.push_str(", ");
        }
        out.push_str(&item);
    }
    out
}

/// A comma-joined list of rationals, each `num/den` or its decimal when it divides evenly. **Pure.**
fn rationals(endian: Endian, bytes: &[u8], signed: bool) -> String {
    listed(bytes.chunks_exact(8).map(|chunk| {
        let (num, den) = read_rational(endian, chunk, signed);
        if den == 0 {
            format!("{num}/0")
        } else if num % den == 0 {
            (num / den).to_string()
        } else {
            format!("{num}/{den}")
        }
    }))
}

/// A single rational's numerator and denominator (as `i64` so signed and unsigned share a path).
/// **Pure.**
fn read_rational(endian: Endian, chunk: &[u8], signed: bool) -> (i64, i64) {
    let num = read_u32(endian, chunk);
    let den = read_u32(endian, &chunk[4..]);
    if signed {
        (i64::from(num.cast_signed()), i64::from(den.cast_signed()))
    } else {
        (i64::from(num), i64::from(den))
    }
}

fn read_u16(endian: Endian, bytes: &[u8]) -> u16 {
    let array: [u8; 2] = bytes
        .get(..2)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0; 2]);
    match endian {
        Endian::Little => u16::from_le_bytes(array),
        Endian::Big => u16::from_be_bytes(array),
    }
}

fn read_u32(endian: Endian, bytes: &[u8]) -> u32 {
    let array: [u8; 4] = bytes
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0; 4]);
    match endian {
        Endian::Little => u32::from_le_bytes(array),
        Endian::Big => u32::from_be_bytes(array),
    }
}

// ── GPS ──────────────────────────────────────────────────────────────────────────────────

/// Decode the GPS IFD at `offset`: add every GPS tag to `fields` and return the position when the
/// coordinate tags resolve to an in-range `lat,lon`. **Pure.**
fn decode_gps(tiff: &Tiff, offset: usize, fields: &mut Directory) -> Option<GpsFix> {
    let entries = read_ifd(tiff, offset);
    let mut lat_ref = None;
    let mut lon_ref = None;
    let mut lat = None;
    let mut lon = None;
    let mut altitude = None;
    let mut altitude_ref = 0u8;
    let mut time = None;
    let mut date = None;

    for entry in &entries {
        fields.push(gps_tag_name(entry.tag), &named_value(tiff, entry));
        match entry.tag {
            0x0001 => lat_ref = Some(ascii(&entry.value)),
            0x0002 => lat = degrees(tiff.endian, &entry.value),
            0x0003 => lon_ref = Some(ascii(&entry.value)),
            0x0004 => lon = degrees(tiff.endian, &entry.value),
            0x0005 => altitude_ref = entry.value.first().copied().unwrap_or(0),
            0x0006 => altitude = first_ratio(tiff.endian, &entry.value),
            0x0007 => time = gps_time(tiff.endian, &entry.value),
            0x001D => date = Some(ascii(&entry.value)),
            _ => {}
        }
    }

    let lat = apply_sign(lat?, lat_ref.as_deref(), "S");
    let lon = apply_sign(lon?, lon_ref.as_deref(), "W");
    Some(GpsFix {
        lat,
        lon,
        altitude_m: altitude.map(|a| if altitude_ref == 1 { -a } else { a }),
        timestamp_utc: gps_timestamp(date.as_deref(), time.as_deref()),
    })
}

/// Negate `value` when its reference hemisphere is the negative one (`S` for latitude, `W` for
/// longitude). **Pure.**
fn apply_sign(value: f64, reference: Option<&str>, negative: &str) -> f64 {
    if reference.map(str::trim) == Some(negative) {
        -value
    } else {
        value
    }
}

/// Decimal degrees from the three `deg, min, sec` rationals of a GPS coordinate. **Pure.**
fn degrees(endian: Endian, bytes: &[u8]) -> Option<f64> {
    let parts: Vec<f64> = bytes
        .chunks_exact(8)
        .map(|chunk| {
            let (num, den) = read_rational(endian, chunk, false);
            ratio(num, den)
        })
        .collect::<Option<Vec<f64>>>()?;
    let degrees = *parts.first()?;
    let minutes = parts.get(1).copied().unwrap_or(0.0);
    let seconds = parts.get(2).copied().unwrap_or(0.0);
    Some(degrees + minutes / 60.0 + seconds / 3600.0)
}

/// The first rational of a value as a float, when it is defined. **Pure.**
fn first_ratio(endian: Endian, bytes: &[u8]) -> Option<f64> {
    let chunk = bytes.get(0..8)?;
    let (num, den) = read_rational(endian, chunk, false);
    ratio(num, den)
}

/// `num/den` as a float, `0` for `0/0`, and `None` for a non-zero value over a zero denominator.
/// **Pure.**
#[allow(clippy::cast_precision_loss)]
fn ratio(num: i64, den: i64) -> Option<f64> {
    if den == 0 {
        return (num == 0).then_some(0.0);
    }
    Some(num as f64 / den as f64)
}

/// `HH:MM:SS` from the three GPS-timestamp rationals. **Pure.**
fn gps_time(endian: Endian, bytes: &[u8]) -> Option<String> {
    let parts: Vec<i64> = bytes
        .chunks_exact(8)
        .map(|chunk| {
            let (num, den) = read_rational(endian, chunk, false);
            if den == 0 { num } else { num / den }
        })
        .collect();
    let [hour, minute, second] = parts.get(0..3)?.try_into().ok()?;
    Some(format!("{hour:02}:{minute:02}:{second:02}"))
}

/// A UTC timestamp from the GPS date stamp (`YYYY:MM:DD`) and time, when both are present. **Pure.**
fn gps_timestamp(date: Option<&str>, time: Option<&str>) -> Option<String> {
    let date = date?.trim();
    if date.is_empty() {
        return None;
    }
    match time {
        Some(time) => Some(format!("{date} {time}Z")),
        None => Some(date.to_owned()),
    }
}

// ── tag names ────────────────────────────────────────────────────────────────────────────

/// The IFD0 tag name, or a hex fallback for an unnamed tag. **Pure.**
fn ifd0_tag_name(tag: u16) -> String {
    match tag {
        0x0100 => "ImageWidth",
        0x0101 => "ImageLength",
        0x0102 => "BitsPerSample",
        0x010E => "ImageDescription",
        0x010F => "Make",
        0x0110 => "Model",
        0x0112 => "Orientation",
        0x011A => "XResolution",
        0x011B => "YResolution",
        0x0128 => "ResolutionUnit",
        0x0131 => "Software",
        0x0132 => "DateTime",
        0x013B => "Artist",
        0x8298 => "Copyright",
        _ => return unknown_tag(tag),
    }
    .to_owned()
}

/// The Exif sub-IFD tag name, or a hex fallback. **Pure.**
fn exif_tag_name(tag: u16) -> String {
    match tag {
        0x829A => "ExposureTime",
        0x829D => "FNumber",
        0x8822 => "ExposureProgram",
        0x8827 => "ISOSpeedRatings",
        0x9003 => "DateTimeOriginal",
        0x9004 => "DateTimeDigitized",
        0x920A => "FocalLength",
        0xA002 => "PixelXDimension",
        0xA003 => "PixelYDimension",
        0xA402 => "ExposureMode",
        0xA403 => "WhiteBalance",
        0xA430 => "CameraOwnerName",
        0xA431 => "BodySerialNumber",
        0xA433 => "LensMake",
        0xA434 => "LensModel",
        0xA435 => "LensSerialNumber",
        _ => return unknown_tag(tag),
    }
    .to_owned()
}

/// The GPS IFD tag name, or a hex fallback. **Pure.**
fn gps_tag_name(tag: u16) -> String {
    match tag {
        0x0000 => "GPSVersionID",
        0x0001 => "GPSLatitudeRef",
        0x0002 => "GPSLatitude",
        0x0003 => "GPSLongitudeRef",
        0x0004 => "GPSLongitude",
        0x0005 => "GPSAltitudeRef",
        0x0006 => "GPSAltitude",
        0x0007 => "GPSTimeStamp",
        0x0008 => "GPSSatellites",
        0x0012 => "GPSMapDatum",
        0x001B => "GPSProcessingMethod",
        0x001D => "GPSDateStamp",
        _ => return unknown_tag(tag),
    }
    .to_owned()
}

/// `tag_0xXXXX` for a tag with no name in the tables above. **Pure.**
fn unknown_tag(tag: u16) -> String {
    format!("tag_0x{tag:04x}")
}

#[cfg(test)]
mod tests;
