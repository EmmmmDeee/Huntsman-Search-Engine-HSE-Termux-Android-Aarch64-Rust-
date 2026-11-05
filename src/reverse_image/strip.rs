//! Removes an image's embedded metadata before it is uploaded, so a provider receives only what a
//! decoder needs to rebuild the picture.
//!
//! The rule keeps what decoding needs and drops everything else, so metadata in a segment or chunk
//! no list names (an `APP11` content credential, a maker note in `APP6`, a private PNG chunk) goes
//! too:
//!
//! - JPEG keeps its frame header, tables, restart interval, scans and the Adobe `APP14` colour
//!   transform. It drops every other application segment (`APP0` to `APP15`: JFIF, Exif and XMP
//!   in `APP1`, ICC profiles and multi-picture indexes in `APP2`, IPTC in `APP13`) and every
//!   comment, anywhere before or between scans.
//! - PNG keeps `IHDR`, `PLTE`, `tRNS`, `IDAT` and `IEND`, and drops every other ancillary chunk
//!   (`eXIf`, `tEXt`, `zTXt`, `iTXt`, `tIME`, colour profiles, private chunks).
//! - A still WebP keeps `VP8X`, `ALPH` and its one `VP8 ` or `VP8L` image, drops `EXIF`, `XMP `,
//!   `ICCP` and unknown chunks, and clears the `VP8X` flags of what it dropped.
//!
//! Anything after the end of the image (an appended video or second picture) is dropped too. The
//! containers are walked by the walkers the `exif` and `docmeta` readers use ([`crate::exif`]), and
//! the result is read again by both readers: an image either still finds metadata in is refused.
//! A GIF or any other format, an animated WebP, an unknown critical PNG chunk or JPEG marker, and
//! a file whose structure does not parse whole are refused, so nothing is sent that was not
//! understood. Each byte is read a bounded number of times and the result is never larger than
//! the input.

use super::Format;
use crate::exif::{PNG_SIGNATURE, jpeg_marker_at, png_chunk_spans, webp_chunks};

/// The most kinds of removed data one report names; further kinds are summed up as [`MORE`].
const MAX_REMOVED_KINDS: usize = 16;
/// The last kind named when more kinds were removed than [`MAX_REMOVED_KINDS`].
const MORE: &str = "more kinds";
/// What bytes after the end of the image are named as.
const TRAILING: &str = "trailing data";

/// The `VP8X` flags of an ICC profile, Exif and XMP, and of an animation.
const VP8X_ICC: u8 = 0x20;
const VP8X_EXIF: u8 = 0x08;
const VP8X_XMP: u8 = 0x04;
const VP8X_ANIMATION: u8 = 0x02;

/// An image ready to upload: its bytes without embedded metadata, and what was removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Stripped {
    pub(super) bytes: Vec<u8>,
    /// The kinds of data removed, each once, in the order first met: JPEG segment names (`APP1`,
    /// `COM`), PNG chunk types (`eXIf`, `tEXt`), WebP chunk codes (`EXIF`, `XMP`), and
    /// [`TRAILING`].
    pub(super) removed: Vec<String>,
}

/// `image`, a `format` file, without its embedded metadata.
///
/// # Errors
/// A static message, and nothing to upload, for a GIF, an animated WebP, a file whose structure
/// does not parse whole, a JPEG marker or PNG chunk a decoder may need that is not known here, and
/// an image the `exif` or `docmeta` reader still finds metadata in after stripping.
pub(super) fn strip(image: &[u8], format: Format) -> Result<Stripped, &'static str> {
    let mut removed = Removed::default();
    let bytes = match format {
        Format::Jpeg => jpeg(image, &mut removed)?,
        Format::Png => png(image, &mut removed)?,
        Format::WebP => webp(image, &mut removed)?,
        Format::Gif => {
            return Err(
                "a GIF is not uploaded: only a JPEG, PNG or still WebP image has its metadata removed",
            );
        }
    };
    let exif_left = !crate::exif::parse(&bytes)
        .is_ok_and(|parsed| parsed.fields.is_empty() && parsed.gps.is_none());
    if exif_left || !crate::docmeta::parse(&bytes).fields.is_empty() {
        return Err("metadata was still found after it was removed");
    }
    Ok(Stripped {
        bytes,
        removed: removed.0,
    })
}

/// The kinds of data removed, each once, in the order first met, at most [`MAX_REMOVED_KINDS`].
#[derive(Debug, Default)]
struct Removed(Vec<String>);

impl Removed {
    fn note(&mut self, kind: &str) {
        if self.0.iter().any(|seen| seen == kind) {
            return;
        }
        if self.0.len() + 1 < MAX_REMOVED_KINDS {
            self.0.push(kind.to_owned());
        } else if self.0.last().is_none_or(|last| last != MORE) {
            self.0.push(MORE.to_owned());
        }
    }
}

/// A JPEG's SOI, frame, tables, scans and end of image, without any application segment but the
/// Adobe colour transform, without comments, and without anything after the end of the image.
fn jpeg(image: &[u8], removed: &mut Removed) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(image.len());
    out.extend_from_slice(&image[..2]);
    let (mut at, mut frame, mut scanned) = (2, false, false);
    loop {
        let segment = jpeg_marker_at(image, at).ok_or("JPEG: a marker segment is malformed")?;
        at = segment.span.end;
        match segment.marker {
            0xD9 => {
                if !(frame && scanned) {
                    return Err("JPEG: the image ends before its frame and scan");
                }
                out.extend_from_slice(&[0xFF, 0xD9]);
                if at < image.len() {
                    removed.note(TRAILING);
                }
                return Ok(out);
            }
            0xDA if frame => {
                let data_end = scan_end(image, at)?;
                out.extend_from_slice(&image[segment.span.start..data_end]);
                at = data_end;
                scanned = true;
            }
            0xDA => return Err("JPEG: a scan comes before the frame header"),
            // SOF0 to SOF15: every frame type but the codes DHT, JPG and DAC take.
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                frame = true;
                out.extend_from_slice(&image[segment.span]);
            }
            // DHT, DAC, DQT, DNL, DRI: tables and restart intervals.
            0xC4 | 0xCC | 0xDB | 0xDC | 0xDD => out.extend_from_slice(&image[segment.span]),
            0xEE if segment.payload.starts_with(b"Adobe") => {
                out.extend_from_slice(&image[segment.span]);
            }
            marker @ 0xE0..=0xEF => removed.note(&format!("APP{}", marker - 0xE0)),
            0xFE => removed.note("COM"),
            // A restart or temporary marker outside a scan carries nothing to decode.
            0x01 | 0xD0..=0xD7 => {}
            _ => return Err("JPEG: an unsupported marker (hierarchical, extension or reserved)"),
        }
    }
}

/// Where the entropy-coded data of the scan that starts at `at` ends: at the first `0xFF` that,
/// after any fill bytes, is followed by a marker other than a stuffed zero or a restart marker.
fn scan_end(image: &[u8], mut at: usize) -> Result<usize, &'static str> {
    const PAST_END: &str = "JPEG: a scan runs past the end of the file";
    loop {
        let ff = image
            .get(at..)
            .and_then(|rest| rest.iter().position(|&byte| byte == 0xFF))
            .ok_or(PAST_END)?
            + at;
        let mut next = ff + 1;
        while image.get(next) == Some(&0xFF) {
            next += 1;
        }
        match image.get(next) {
            None => return Err(PAST_END),
            Some(0x00 | 0xD0..=0xD7) => at = next + 1,
            Some(_) => return Ok(ff),
        }
    }
}

/// A PNG's signature and its `IHDR`, `PLTE`, `tRNS`, `IDAT` and `IEND` chunks, as they were.
fn png(image: &[u8], removed: &mut Removed) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(image.len());
    out.extend_from_slice(PNG_SIGNATURE);
    let (mut end, mut header, mut data, mut closed) = (PNG_SIGNATURE.len(), false, false, false);
    for chunk in png_chunk_spans(image) {
        let chunk = chunk?;
        end = chunk.span.end;
        if !chunk.kind.iter().all(u8::is_ascii_alphabetic) {
            return Err("PNG: a chunk type is not four letters");
        }
        match chunk.kind {
            b"IHDR" if !header => header = true,
            b"IHDR" => return Err("PNG: IHDR is repeated"),
            _ if !header => return Err("PNG: the first chunk is not IHDR"),
            b"IDAT" => data = true,
            b"IEND" => closed = true,
            b"PLTE" | b"tRNS" => {}
            // An uppercase first letter marks a chunk a decoder cannot do without.
            kind if kind[0].is_ascii_uppercase() => {
                return Err("PNG: an unknown critical chunk");
            }
            kind => {
                removed.note(&String::from_utf8_lossy(kind));
                continue;
            }
        }
        out.extend_from_slice(&image[chunk.span]);
    }
    if !(data && closed) {
        return Err("PNG: no image data, or no IEND");
    }
    if end < image.len() {
        removed.note(TRAILING);
    }
    Ok(out)
}

/// A still WebP's `VP8X` (its metadata flags cleared), `ALPH` and image chunk, in a container
/// whose size is rewritten to match.
fn webp(image: &[u8], removed: &mut Removed) -> Result<Vec<u8>, &'static str> {
    const ANIMATED: &str = "an animated WebP is not uploaded: save one frame as a still image";
    let mut out = Vec::with_capacity(image.len());
    out.extend_from_slice(&image[..12]);
    let (mut end, mut flags, mut pictures) = (12, None, 0usize);
    for (index, chunk) in webp_chunks(image)?.enumerate() {
        let chunk = chunk?;
        end = chunk.span.end;
        match chunk.fourcc {
            b"VP8X" if index == 0 => {
                // Flags (1 byte), reserved (3) and the canvas width and height (3 each).
                if chunk.payload.len() < 10 {
                    return Err("WebP: VP8X is too short");
                }
                if chunk.payload[0] & VP8X_ANIMATION != 0 {
                    return Err(ANIMATED);
                }
                flags = Some(out.len() + 8);
            }
            b"VP8X" => return Err("WebP: VP8X is not the first chunk"),
            b"ANIM" | b"ANMF" => return Err(ANIMATED),
            b"VP8 " | b"VP8L" => pictures += 1,
            b"ALPH" => {}
            fourcc => {
                removed.note(&webp_kind(fourcc));
                continue;
            }
        }
        out.extend_from_slice(&image[chunk.span]);
    }
    if pictures != 1 {
        return Err("WebP: not exactly one image chunk");
    }
    if let Some(at) = flags {
        out[at] &= !(VP8X_ICC | VP8X_EXIF | VP8X_XMP);
    }
    if end < image.len() {
        removed.note(TRAILING);
    }
    let size = u32::try_from(out.len() - 8).map_err(|_| "WebP: too large")?;
    out[4..8].copy_from_slice(&size.to_le_bytes());
    Ok(out)
}

/// How a removed WebP chunk is named: its code without trailing spaces when it is letters and
/// digits, else `unknown chunk`. **Pure.**
fn webp_kind(fourcc: &[u8]) -> String {
    let code = fourcc.trim_ascii_end();
    if !code.is_empty() && code.iter().all(u8::is_ascii_alphanumeric) {
        String::from_utf8_lossy(code).into_owned()
    } else {
        "unknown chunk".to_owned()
    }
}

#[cfg(test)]
mod tests;
