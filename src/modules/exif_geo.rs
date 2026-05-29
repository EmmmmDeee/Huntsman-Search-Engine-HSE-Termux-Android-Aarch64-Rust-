//! Image metadata intelligence from image URLs — GPS, capture device, author.
//!
//! Image URLs discovered by `search_engines`, `web_crawler`, social-profile
//! modules, and breach corpora frequently embed rich metadata. This module
//! harvests three intelligence products from one in-memory fetch:
//!   - **`Coordinates`** — GPS fix (the geolocation pipeline's strongest lead).
//!   - **`DeviceId`** — the capture device (make/model, serial-keyed when
//!     present), so the same camera across photos links as one graph node.
//!   - **`Person`** — the camera owner / artist when embedded.
//!
//! Workflow when an image `Url` target arrives:
//!   1. Skip non-image URLs by extension (`.jpg`/`.jpeg`/`.heic`/`.tiff`/…).
//!   2. Range-fetch the leading bytes via `ctx.http` (capped at 8 MB).
//!   3. Parse **EXIF** (`kamadak-exif`) *and* the **XMP** packet
//!      (`util::metadata`) — complementary, since platforms often strip one
//!      but pass the other. EXIF wins where they overlap; XMP backfills GPS,
//!      make/model, serial, creator-tool, and `dc:creator`.
//!   4. Emit the entities above, each carrying a `media_url` evidence
//!      attribute so the AU-033 correlator can cluster shared origins.
//!
//! In-memory only: the fetched image is parsed and dropped — **never written
//! to disk** (privacy + storage constraint on Termux).
//!
//! Privacy/coverage: most chat apps (WhatsApp, Signal, Telegram, iOS Messages,
//! Instagram) strip metadata on send; photos on personal sites, archives, and
//! older uploads often retain it. GPS confidence is 0.80 (±50 m on-device);
//! a make/model-only device key is a weak cohort signal (tagged
//! `weak-device-link`), a serial-keyed one is strong.

use async_trait::async_trait;
use exif::{In, Reader, Tag, Value};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::metadata::parse_image_xmp;

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
        "Harvest GPS, capture device, and author from image EXIF + XMP metadata"
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
        const KINDS: &[EntityKind] = &[
            EntityKind::Coordinates,
            EntityKind::DeviceId,
            EntityKind::Person,
        ];
        KINDS
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only gate so the probe-derived dispatch index includes `Url`
        // (a value-shaped check here would yield an empty `consumes()` and the
        // module would never be dispatched). The image-extension filter runs
        // in `process()` below.
        matches!(t.kind, TargetKind::Url)
    }

    fn consumes(&self) -> Vec<TargetKind> {
        vec![TargetKind::Url]
    }

    fn max_timeout_ms(&self) -> u64 {
        // Image download + parse. 12s catches slow CDN tail latency
        // without making the engine wait on dead URLs.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let url = target.value.trim();
        // Value-shape gate (moved out of `accepts()`): only fetch URLs whose
        // path looks like an image we can read EXIF/XMP from.
        if url.is_empty() || !looks_like_image_url(url) {
            return Ok(result);
        }

        // In-memory only: range-fetch the leading bytes (metadata lives near
        // the head of a JPEG/HEIC), parse, then drop. The image is NEVER
        // written to disk — a privacy + storage constraint on Termux.
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
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(_) => return Ok(result),
        };
        if bytes.len() > MAX_BYTES as usize {
            return Ok(result);
        }

        // EXIF (binary IFD) and XMP (text packet) are complementary: many
        // platforms strip one but pass the other through, so we read both and
        // prefer EXIF where they overlap.
        let exif = {
            let mut cursor = std::io::Cursor::new(bytes.as_ref());
            Reader::new().read_from_container(&mut cursor).ok()
        };
        let xmp = parse_image_xmp(&bytes);

        let ex = |tag: Tag| exif.as_ref().and_then(|x| read_str(x, tag));

        // ── GPS → Coordinates (EXIF preferred, XMP fallback) ──
        if let Some((lat, lon)) = exif.as_ref().and_then(extract_gps).or(xmp.gps) {
            // EXIF/XMP GPS is empirically reliable to ~10–50 m on the source
            // device — base confidence 0.80, above single-source IP-geo, below
            // WiGLE multi-observer consensus (0.85).
            let coord_str = format!("{lat:.6},{lon:.6}");
            let mut e = Entity::new(EntityKind::Coordinates, &coord_str, 0.80, &ctx.scan_id);
            e.tag("geoint");
            e.tag("exif");
            e.tag("photo-derived");
            e.add_evidence(
                Evidence::new(SRC, format!("photo GPS extracted from {url}"))
                    .with_attr("media_url", url)
                    .with_attr("latitude", lat.to_string())
                    .with_attr("longitude", lon.to_string()),
            );
            result.push(e);
        }

        // Field harvest — EXIF first, XMP fallback.
        let make = ex(Tag::Make).or(xmp.make);
        let model = ex(Tag::Model).or(xmp.model);
        let serial = ex(Tag::BodySerialNumber).or(xmp.serial);
        let software = ex(Tag::Software).or(xmp.creator_tool);
        let owner = ex(Tag::CameraOwnerName)
            .or_else(|| ex(Tag::Artist))
            .or(xmp.creator);
        let shot_time = ex(Tag::DateTimeOriginal).or_else(|| ex(Tag::DateTime));

        // ── Camera → DeviceId (the device-linking node) ──
        if let Some(key) = device_key(make.as_deref(), model.as_deref(), serial.as_deref()) {
            // A serial pins one physical body (strong link); make+model alone
            // is only a cohort signal (weak).
            let strong = serial.as_deref().is_some_and(|s| !s.trim().is_empty());
            let mut e = Entity::new(
                EntityKind::DeviceId,
                &key,
                if strong { 0.75 } else { 0.50 },
                &ctx.scan_id,
            );
            e.tag("capture-device");
            e.tag("exif");
            if !strong {
                e.tag("weak-device-link");
            }
            let mut ev =
                Evidence::new(SRC, format!("capture device for {url}")).with_attr("media_url", url);
            for (k, v) in [
                ("make", &make),
                ("model", &model),
                ("serial", &serial),
                ("software", &software),
                ("shot_time", &shot_time),
            ] {
                if let Some(val) = v.as_deref().filter(|s| !s.trim().is_empty()) {
                    ev = ev.with_attr(k, val);
                }
            }
            e.add_evidence(ev);
            result.push(e);
        }

        // ── Owner / artist → Person ──
        if let Some(person) = owner.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let mut e = Entity::new(EntityKind::Person, person, 0.70, &ctx.scan_id);
            e.tag("media-author");
            e.tag("photo-derived");
            e.add_evidence(
                Evidence::new(SRC, format!("image author/owner from {url}"))
                    .with_attr("media_url", url),
            );
            result.push(e);
        }

        Ok(result)
    }
}

/// Build a normalised capture-device key from make / model / serial. Returns
/// `None` when both make and model are blank. Models usually already include
/// the make (`"Canon EOS 5D"`), so we avoid a doubled `"Canon Canon EOS 5D"`.
/// A serial appends `#<serial>`, pinning one physical body.
fn device_key(make: Option<&str>, model: Option<&str>, serial: Option<&str>) -> Option<String> {
    let mk = make.unwrap_or("").trim();
    let md = model.unwrap_or("").trim();
    let base = if !mk.is_empty() && md.to_lowercase().starts_with(&mk.to_lowercase()) {
        md.to_string()
    } else {
        format!("{mk} {md}")
    };
    let base = base.trim();
    if base.is_empty() {
        return None;
    }
    Some(match serial.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => format!("{base} #{s}"),
        None => base.to_string(),
    })
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

    // ── accepts() is kind-only (Url); image filter lives in process() ──

    #[test]
    fn accepts_url_kind_regardless_of_extension() {
        // Kind-only gate so the dispatch index includes Url. The
        // image-extension filter is applied in process(), not accepts().
        let m = ExifGeo;
        for u in [
            "https://example.com/photo.jpg",
            "https://example.com/page.html", // non-image Url still accepted at the kind gate
            "https://example.com/no-extension",
        ] {
            assert!(m.accepts(&Target::new(TargetKind::Url, u)), "accept {u}");
        }
        // consumes() must surface Url so the engine builds the dispatch index.
        assert_eq!(m.consumes(), vec![TargetKind::Url]);
    }

    #[test]
    fn rejects_non_url_kinds() {
        let m = ExifGeo;
        // Even image-shaped values of a non-Url kind must NOT route here.
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
    fn produces_coordinates_device_and_person() {
        assert_eq!(
            ExifGeo.produces(),
            &[
                EntityKind::Coordinates,
                EntityKind::DeviceId,
                EntityKind::Person
            ]
        );
    }

    // ── device_key ──────────────────────────────────────────────

    #[test]
    fn device_key_dedups_make_prefix_and_appends_serial() {
        // Model already carries the make → no "Canon Canon".
        assert_eq!(
            device_key(Some("Canon"), Some("Canon EOS 5D"), None).as_deref(),
            Some("Canon EOS 5D")
        );
        // Distinct make + model.
        assert_eq!(
            device_key(Some("Apple"), Some("iPhone 14"), None).as_deref(),
            Some("Apple iPhone 14")
        );
        // Serial pins one body.
        assert_eq!(
            device_key(Some("Nikon"), Some("D850"), Some("301234")).as_deref(),
            Some("Nikon D850 #301234")
        );
        // Nothing usable.
        assert_eq!(device_key(None, None, None), None);
        assert_eq!(device_key(Some("  "), Some(""), Some(" ")), None);
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
