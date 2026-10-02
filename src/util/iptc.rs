//! IPTC-IIM ("IPTC-NAA") metadata extraction from image bytes.
//!
//! Complements [`crate::util::xmp`]: XMP is the modern serialisation, but a large
//! body of press-agency, newsroom and older-camera images carry their
//! identity/caption metadata ONLY in the legacy IPTC-IIM block — the Photoshop
//! `8BIM` image-resource `0x0404` inside a JPEG `APP13` segment. Reading it
//! recovers the photographer (by-line), the caption (which routinely NAMES the
//! people pictured), the subject keywords and the place. Every field is text the
//! author's software embedded — nothing here is inferred from pixels, and no face
//! recognition is performed.
//!
//! # Precision
//! An IIM dataset begins with the bytes `0x1C 0x02`, a pair that also occurs by
//! chance in compressed pixel data. Parsing is therefore **anchored** to the
//! `Photoshop 3.0` image-resource signature and **bounded** by the IPTC
//! resource's own declared length, so a stray `0x1C 0x02` in the image body can
//! never be mistaken for a dataset. An image with no IRB yields an empty result.

/// Cap on a name/keyword/place field — longer than this is a parser desync or a
/// junk value, not a person or a place. Matches [`crate::util::xmp`]'s bound.
const NAME_MAX: usize = 200;
/// Cap on the free-text caption (IPTC allows up to 2000 octets).
const CAPTION_MAX: usize = 2000;

/// The Photoshop image-resource signature that introduces the `8BIM` records in a
/// JPEG `APP13` segment.
const IRB_SIG: &[u8] = b"Photoshop 3.0\0";
/// `8BIM` resource id for the IPTC-NAA (IIM) record.
const IPTC_RESOURCE_ID: u16 = 0x0404;

// IIM application-record (record 2) dataset numbers we read.
const DS_KEYWORDS: u8 = 25; // 2:25  Keywords (repeatable)
const DS_BYLINE: u8 = 80; // 2:80  By-line (creator/photographer)
const DS_CITY: u8 = 90; // 2:90  City
const DS_SUBLOCATION: u8 = 92; // 2:92  Sub-location
const DS_STATE: u8 = 95; // 2:95  Province/State
const DS_COUNTRY: u8 = 101; // 2:101 Country/primary location name
const DS_CAPTION: u8 = 120; // 2:120 Caption/Abstract

/// Identity and context metadata read from an image's IPTC-IIM block. Every field
/// is text the image author embedded — none is inferred from pixels.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImageIptc {
    /// By-line(s) (dataset 2:80) — the photographer/author name(s).
    pub by_lines: Vec<String>,
    /// Subject keywords (dataset 2:25, repeatable).
    pub keywords: Vec<String>,
    /// Place assembled most-specific-first from sub-location/city/state/country
    /// (2:92 / 2:90 / 2:95 / 2:101), when any are present.
    pub location: Option<String>,
    /// Caption/Abstract (dataset 2:120) — free text that routinely names subjects.
    pub caption: Option<String>,
}

impl ImageIptc {
    /// True when no field carried anything — the common case for a re-encoded,
    /// metadata-stripped social-media image.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_lines.is_empty()
            && self.keywords.is_empty()
            && self.location.is_none()
            && self.caption.is_none()
    }
}

/// Extract the IPTC-IIM metadata from image `bytes`. Returns an empty
/// [`ImageIptc`] when the image carries no Photoshop IRB or no IPTC resource.
#[must_use]
pub fn parse(bytes: &[u8]) -> ImageIptc {
    let mut out = ImageIptc::default();
    let Some(iim) = find_iptc_resource(bytes) else {
        return out;
    };

    // Location parts are collected separately then assembled most-specific-first.
    let (mut sublocation, mut city, mut state, mut country) = (None, None, None, None);
    for (dataset, value) in iim_datasets(iim) {
        match dataset {
            DS_BYLINE => push_clean(&mut out.by_lines, value),
            DS_KEYWORDS => push_clean(&mut out.keywords, value),
            DS_CAPTION => set_once(&mut out.caption, value, CAPTION_MAX),
            DS_SUBLOCATION => set_once(&mut sublocation, value, NAME_MAX),
            DS_CITY => set_once(&mut city, value, NAME_MAX),
            DS_STATE => set_once(&mut state, value, NAME_MAX),
            DS_COUNTRY => set_once(&mut country, value, NAME_MAX),
            _ => {}
        }
    }
    out.location = assemble(&[sublocation, city, state, country]);
    out
}

/// Find the IPTC (`0x0404`) `8BIM` image-resource and return its raw IIM payload.
/// Walks the resource blocks from the `Photoshop 3.0` signature, honouring each
/// block's Pascal name padding and even-length data padding, so a non-IPTC block
/// before the IPTC one is skipped correctly.
fn find_iptc_resource(bytes: &[u8]) -> Option<&[u8]> {
    let sig = find_bytes(bytes, IRB_SIG)?;
    let mut p = sig + IRB_SIG.len();

    while p + 4 <= bytes.len() && &bytes[p..p + 4] == b"8BIM" {
        p += 4;
        // Resource id (2 bytes, big-endian).
        if p + 2 > bytes.len() {
            break;
        }
        let id = u16::from_be_bytes([bytes[p], bytes[p + 1]]);
        p += 2;
        // Pascal name: 1 length byte + name, the whole padded to an even length.
        if p >= bytes.len() {
            break;
        }
        let name_len = bytes[p] as usize;
        p += 1 + name_len;
        if !(1 + name_len).is_multiple_of(2) {
            p += 1; // pad byte so (len byte + name) is even
        }
        // Data size (4 bytes, big-endian), then the data itself.
        if p + 4 > bytes.len() {
            break;
        }
        let size =
            u32::from_be_bytes([bytes[p], bytes[p + 1], bytes[p + 2], bytes[p + 3]]) as usize;
        p += 4;
        if p + size > bytes.len() {
            break;
        }
        if id == IPTC_RESOURCE_ID {
            return Some(&bytes[p..p + size]);
        }
        // Skip this block's data, which is padded to an even length.
        p += size + (size & 1);
    }
    None
}

/// Iterate the IIM datasets inside one IPTC resource payload, yielding
/// `(dataset_number, value_bytes)` for application-record (record 2) datasets.
/// Bounded by the payload length; stops at the first byte that is not a dataset
/// marker (a desync) or at an extended-length dataset (rare — bailed rather than
/// risk a misparse).
fn iim_datasets(iim: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut p = 0;
    // Each dataset header is 5 bytes: 0x1C, record, dataset, len(2 BE).
    while p + 5 <= iim.len() {
        if iim[p] != 0x1C {
            break;
        }
        let record = iim[p + 1];
        let dataset = iim[p + 2];
        let len = u16::from_be_bytes([iim[p + 3], iim[p + 4]]) as usize;
        p += 5;
        if len & 0x8000 != 0 {
            break; // extended length — out of scope
        }
        if p + len > iim.len() {
            break;
        }
        if record == 2 {
            out.push((dataset, &iim[p..p + len]));
        }
        p += len;
    }
    out
}

/// Decode an IIM value. IIM text is UTF-8 when the record declares it (the modern
/// default) and Latin-1 otherwise; try UTF-8 first and fall back to Latin-1 so an
/// accented name is preserved rather than replaced with `U+FFFD`.
fn decode_value(raw: &[u8]) -> String {
    let s = match std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => raw.iter().map(|&b| b as char).collect(),
    };
    s.trim().to_string()
}

/// Clean `raw` and push it onto `vec` if it is a usable, non-duplicate name/keyword.
fn push_clean(vec: &mut Vec<String>, raw: &[u8]) {
    let v = decode_value(raw);
    if !v.is_empty() && v.len() <= NAME_MAX && !vec.iter().any(|e| e == &v) {
        vec.push(v);
    }
}

/// Set `slot` to the cleaned `raw` if not already set and within `max`.
fn set_once(slot: &mut Option<String>, raw: &[u8], max: usize) {
    if slot.is_some() {
        return;
    }
    let v = decode_value(raw);
    if !v.is_empty() && v.len() <= max {
        *slot = Some(v);
    }
}

/// Join the present location parts most-specific-first, or `None`.
fn assemble(parts: &[Option<String>]) -> Option<String> {
    let joined: Vec<&str> = parts.iter().filter_map(Option::as_deref).collect();
    if joined.is_empty() {
        None
    } else {
        Some(joined.join(", "))
    }
}

/// First index of `needle` in `haystack`, or `None`. A plain scan — `needle` is a
/// short signature, `haystack` is bounded by the caller's image-fetch cap.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    include!("iptc_tests.rs");
}
