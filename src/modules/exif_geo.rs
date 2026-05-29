//! EXIF-based geolocation from image URLs.
//!
//! Closes a gap surfaced by the geolocation gap analysis: image URLs
//! discovered by `search_engines`, `web_crawler`, social profile
//! modules, and breach corpora often embed GPS coordinates in their
//! EXIF metadata, but no module was extracting them.
//!
//! Workflow when a `Url` target arrives:
//!   1. Skip non-image URLs by file extension (`.jpg`, `.jpeg`,
//!      `.png`, `.tif`, `.tiff`, `.webp`, `.heic`).
//!   2. Fetch the bytes via `ctx.http` (capped at 8 MB so a
//!      misclassified video URL doesn't drain memory).
//!   3. Parse with `kamadak-exif`. Returns `None` if no EXIF tags or
//!      the image is metadata-stripped (the typical case after
//!      most social platforms re-encode).
//!   4. Pull `GPSLatitude` / `GPSLongitude` / `GPSLatitudeRef` /
//!      `GPSLongitudeRef` from the GPS IFD; emit a `Coordinates`
//!      entity tagged `exif`.
//!   5. Surface camera Make + Model + timestamp as evidence
//!      attributes so the operator can correlate the image source
//!      and shoot time downstream.
//!
//! Privacy: most chat apps (WhatsApp, Signal, Telegram, iOS
//! Messages, Instagram) strip EXIF on send, so URLs to those
//! sources usually return empty. Photos hosted on personal
//! websites, archive sites, and old social-platform uploads
//! frequently retain GPS. Confidence is set conservatively (0.80)
//! because EXIF GPS can be wrong by ±50 m on the originating
//! device but is otherwise authoritative.

use async_trait::async_trait;
use exif::{In, Reader, Tag, Value};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "exif_geo";

/// Cap on image fetch size (8 MiB). A high-res JPEG / HEIC normally
/// fits well under this; large RAW files (CR3, ARW) typically
/// exceed it but rarely appear from URL pivots. Prevents a
/// misclassified video URL or PDF from draining memory.
const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// File extensions worth fetching for EXIF analysis. Anything else
/// short-circuits before the HTTP call — no point downloading a
/// PNG just to fail at the EXIF reader (PNGs *can* embed EXIF in
/// rare cases but the vast majority don't, and we'd rather save the
/// quota).
const IMAGE_EXTS: &[&str] = &[
    ".jpg", ".jpeg", ".jpe", ".jfif", ".tif", ".tiff", ".heic", ".heif", ".webp",
];

pub struct ExifGeo;

#[async_trait]
impl Module for ExifGeo {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Extract GPS coordinates + camera metadata from image URLs via EXIF parsing"
    }

    fn priority(&self) -> u8 {
        // Below the search engines (25) and web_crawler (38) that
        // surface the URLs in the first place, but above the
        // background IP-geo bench so a tight EXIF GPS lead wins the
        // expansion ranker over a coarse IP-geo Coords on the same
        // entity.
        28
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Url) && looks_like_image_url(&t.value)
    }

    fn max_timeout_ms(&self) -> u64 {
        // Image download + parse. 12s catches slow CDN tail latency
        // without making the engine wait on dead URLs.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let url = target.value.trim();
        if url.is_empty() {
            return Ok(result);
        }

        // Range-limit the download. We don't need the whole image to
        // parse EXIF — the metadata sits in the first few KB of a
        // JPEG. Setting the Range header makes the polite-side of
        // the trade visible to upstream servers.
        let resp = match ctx
            .http
            .get(url)
            .header("Range", format!("bytes=0-{}", MAX_BYTES.saturating_sub(1)))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(result),
        };
        if !resp.status().is_success() && resp.status().as_u16() != 206 {
            return Ok(result);
        }

        // bytes_stream + manual byte-accumulation would let us bail
        // earlier on oversize; reqwest's `.bytes()` already caps at
        // the response's content-length, and the Range header above
        // bounded the server response. Trade clarity for control
        // here — a deliberately misbehaving server can still send
        // 8 MB; that's the worst case.
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(_) => return Ok(result),
        };
        if bytes.len() > MAX_BYTES as usize {
            return Ok(result);
        }

        let mut cursor = std::io::Cursor::new(bytes.as_ref());
        let exif = match Reader::new().read_from_container(&mut cursor) {
            Ok(e) => e,
            Err(_) => return Ok(result),
        };

        let Some((lat, lon)) = extract_gps(&exif) else {
            return Ok(result);
        };

        // EXIF GPS is empirically reliable to ~10–50 m on the source
        // device. Set base confidence at 0.80 — meaningfully above
        // single-source IP-geo (now 0.55–0.60 post-recalibration)
        // but below WiGLE WiFi consensus (0.85) which has multiple
        // observers.
        let coord_str = format!("{lat:.6},{lon:.6}");
        let mut e = Entity::new(EntityKind::Coordinates, &coord_str, 0.80, &ctx.scan_id);
        e.tag("geoint");
        e.tag("exif");
        e.tag("photo-derived");

        let mut ev = Evidence::new(SRC, format!("EXIF GPS extracted from {url}"))
            .with_attr("url", url)
            .with_attr("latitude", lat.to_string())
            .with_attr("longitude", lon.to_string());

        // Camera Make / Model / DateTime — useful operator context.
        if let Some(make) = read_str(&exif, Tag::Make) {
            ev = ev.with_attr("camera_make", make);
        }
        if let Some(model) = read_str(&exif, Tag::Model) {
            ev = ev.with_attr("camera_model", model);
        }
        if let Some(dt) = read_str(&exif, Tag::DateTimeOriginal) {
            ev = ev.with_attr("shot_time", dt);
        } else if let Some(dt) = read_str(&exif, Tag::DateTime) {
            ev = ev.with_attr("shot_time", dt);
        }

        e.add_evidence(ev);
        result.push(e);
        Ok(result)
    }
}

/// True if the URL ends (case-insensitive) with one of the
/// image extensions we extract EXIF from. Query strings and
/// fragments are stripped before the check so
/// `https://x.com/a.jpg?w=1024` still matches.
fn looks_like_image_url(url: &str) -> bool {
    let trimmed = url.trim();
    // Strip query string and fragment in one pass. `split(['?', '#'])`
    // splits at either delimiter; the first segment is the URL path,
    // which is what we want to extension-check.
    let path = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    let lower = path.to_lowercase();
    IMAGE_EXTS.iter().any(|ext| lower.ends_with(ext))
}

/// Extract `(lat, lon)` from the EXIF GPS IFD, honouring the
/// N/S/E/W reference tags. Returns `None` if either coordinate is
/// missing or unparseable.
fn extract_gps(exif: &exif::Exif) -> Option<(f64, f64)> {
    let lat_raw = exif.get_field(Tag::GPSLatitude, In::PRIMARY)?;
    let lon_raw = exif.get_field(Tag::GPSLongitude, In::PRIMARY)?;
    let lat_ref = exif
        .get_field(Tag::GPSLatitudeRef, In::PRIMARY)
        .and_then(|f| match &f.value {
            Value::Ascii(v) if !v.is_empty() && !v[0].is_empty() => Some(v[0][0]),
            _ => None,
        })
        .unwrap_or(b'N');
    let lon_ref = exif
        .get_field(Tag::GPSLongitudeRef, In::PRIMARY)
        .and_then(|f| match &f.value {
            Value::Ascii(v) if !v.is_empty() && !v[0].is_empty() => Some(v[0][0]),
            _ => None,
        })
        .unwrap_or(b'E');

    let lat_deg = dms_to_decimal(&lat_raw.value)?;
    let lon_deg = dms_to_decimal(&lon_raw.value)?;
    let lat = if lat_ref == b'S' || lat_ref == b's' {
        -lat_deg
    } else {
        lat_deg
    };
    let lon = if lon_ref == b'W' || lon_ref == b'w' {
        -lon_deg
    } else {
        lon_deg
    };
    // Sanity-bound — anything outside [-90,90] x [-180,180] is
    // either malformed EXIF or a synthesised tag we don't trust.
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some((lat, lon))
}

/// Convert a 3-rational EXIF GPS value to decimal degrees.
///
/// The GPS IFD encodes coordinates as three rationals: degrees,
/// minutes, seconds. Decimal = D + M/60 + S/3600.
fn dms_to_decimal(value: &Value) -> Option<f64> {
    let Value::Rational(rs) = value else {
        return None;
    };
    if rs.len() < 3 {
        return None;
    }
    let d = rs[0].to_f64();
    let m = rs[1].to_f64();
    let s = rs[2].to_f64();
    if !d.is_finite() || !m.is_finite() || !s.is_finite() {
        return None;
    }
    Some(d + m / 60.0 + s / 3600.0)
}

/// Read an ASCII string field if it exists, trimming nulls and
/// whitespace. Returns `None` for empty / missing fields.
fn read_str(exif: &exif::Exif, tag: Tag) -> Option<String> {
    let field = exif.get_field(tag, In::PRIMARY)?;
    if let Value::Ascii(vs) = &field.value
        && let Some(first) = vs.first()
    {
        let cow = String::from_utf8_lossy(first);
        let s = cow.trim_end_matches('\0').trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── accepts() URL classifier ────────────────────────────────

    #[test]
    fn accepts_only_image_urls() {
        let m = ExifGeo;
        let yes = [
            "https://example.com/photo.jpg",
            "https://x.com/img.JPEG",
            "https://cdn.x.com/path/to/file.heic",
            "https://example.com/a/b/c.tiff?w=1024",
            "https://example.com/x.webp#frag",
        ];
        for u in yes {
            assert!(
                m.accepts(&Target::new(TargetKind::Url, u)),
                "expected to accept {u}"
            );
        }
        let no = [
            "https://example.com/page.html",
            "https://example.com/doc.pdf",
            "https://example.com/video.mp4",
            "https://example.com/no-extension",
            "https://example.com/img.png", // PNGs rarely carry EXIF
            "",
        ];
        for u in no {
            assert!(
                !m.accepts(&Target::new(TargetKind::Url, u)),
                "expected to reject {u}"
            );
        }
    }

    #[test]
    fn rejects_non_url_kinds_even_with_image_extension() {
        let m = ExifGeo;
        // Email values shaped like an image URL must NOT route here.
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.jpg")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.jpg")));
    }

    // ── looks_like_image_url helper ────────────────────────────

    #[test]
    fn looks_like_image_url_strips_query_and_fragment() {
        assert!(looks_like_image_url("https://a.b/c.jpg?x=1&y=2"));
        assert!(looks_like_image_url("https://a.b/c.jpg#abc"));
        assert!(looks_like_image_url("https://a.b/c.JPG?abc"));
        assert!(!looks_like_image_url("https://a.b/c.html?img=x.jpg"));
    }

    #[test]
    fn looks_like_image_url_case_insensitive() {
        assert!(looks_like_image_url("https://x.com/A.JPG"));
        assert!(looks_like_image_url("https://x.com/A.HeIc"));
    }

    // ── module metadata ────────────────────────────────────────

    #[test]
    fn category_is_geo() {
        assert_eq!(ExifGeo.category(), ModuleCategory::Geo);
    }

    #[test]
    fn produces_coordinates_only() {
        assert_eq!(ExifGeo.produces(), &[EntityKind::Coordinates]);
    }

    #[test]
    fn priority_places_above_ip_geo_bench() {
        // ip_geo et al sit in the 10–20 range; exif_geo at 28 ranks
        // above so the EXIF lead wins the merge on the same entity.
        assert!(ExifGeo.priority() >= 25);
    }

    // ── dms_to_decimal ─────────────────────────────────────────

    fn rat(num: u32, den: u32) -> exif::Rational {
        exif::Rational { num, denom: den }
    }

    #[test]
    fn dms_zero_zero_zero_is_zero_decimal() {
        let v = Value::Rational(vec![rat(0, 1), rat(0, 1), rat(0, 1)]);
        assert_eq!(dms_to_decimal(&v), Some(0.0));
    }

    #[test]
    fn dms_one_degree_thirty_minutes_is_one_point_five() {
        let v = Value::Rational(vec![rat(1, 1), rat(30, 1), rat(0, 1)]);
        let d = dms_to_decimal(&v).unwrap();
        assert!((d - 1.5).abs() < 1e-9);
    }

    #[test]
    fn dms_with_fractional_seconds() {
        // 27° 28' 35.76" → 27.476600
        let v = Value::Rational(vec![rat(27, 1), rat(28, 1), rat(3576, 100)]);
        let d = dms_to_decimal(&v).unwrap();
        assert!((d - 27.476600).abs() < 1e-4, "got {d}");
    }

    #[test]
    fn dms_rejects_non_rational_values() {
        let v = Value::Byte(vec![1, 2, 3]);
        assert!(dms_to_decimal(&v).is_none());
    }

    #[test]
    fn dms_rejects_truncated_input() {
        let v = Value::Rational(vec![rat(1, 1), rat(0, 1)]); // only D, M
        assert!(dms_to_decimal(&v).is_none());
    }

    #[test]
    fn dms_rejects_division_by_zero() {
        // 1/0 D should produce non-finite — dms_to_decimal returns None.
        let v = Value::Rational(vec![rat(1, 0), rat(0, 1), rat(0, 1)]);
        assert!(dms_to_decimal(&v).is_none());
    }
}
