//! EXIF-based geolocation from image URLs.
//!
//! Closes a gap surfaced by the geolocation gap analysis: image URLs
//! discovered by `search_engines`, `web_crawler`, social profile
//! modules, and breach corpora often embed GPS coordinates in their
//! EXIF metadata, but no module was extracting them.
//!
//! Workflow when a `Url` target arrives:
//!   1. Skip non-image URLs by file extension (`.jpg`, `.jpeg`,
//!      `.tif`, `.tiff`, `.webp`, `.heic`). `.png` is deliberately
//!      excluded (see [`IMAGE_EXTS`]): PNGs almost never carry EXIF GPS,
//!      so fetching them only wastes quota.
//!   2. Fetch the bytes via `ctx.http` (capped at 8 MB so a
//!      misclassified video URL doesn't drain memory).
//!   3. Parse with `kamadak-exif`. Returns nothing if no EXIF tags or
//!      the image is metadata-stripped (the typical case after
//!      most social platforms re-encode).
//!   4. Emit, independently (an image needn't have all three):
//!      * `Coordinates` from the GPS IFD (`GPSLatitude`/`GPSLongitude`/refs);
//!      * `DeviceId` when a camera **serial** is present — a unique
//!        cross-image anchor: the same serial recovered from two photos
//!        links them to the same physical camera (and usually owner);
//!      * `Person` from `CameraOwnerName`/`Artist` — the owner named in
//!        metadata, a real identity lead that correlates with same-named
//!        Person entities from search/breach modules.
//!   5. Camera make/model/serial/lens/software/owner/shot-time ride along
//!      as evidence attributes on every emitted entity.
//!
//! This is the cross-correlation the search-engine scrapers feed: those
//! modules surface image URLs as `Url` entities, the expansion loop dispatches
//! them here, and the resulting Coordinates/DeviceId/Person entities fuse with
//! the rest of the graph via the correlator — all with **no external API**
//! (pure-Rust `kamadak-exif`).
//!
//! Privacy: most chat apps (WhatsApp, Signal, Telegram, iOS
//! Messages, Instagram) strip EXIF on send, so URLs to those
//! sources usually return empty. Photos hosted on personal
//! websites, archive sites, and old social-platform uploads
//! frequently retain GPS. Confidence is set conservatively (confidence::HIGH_PLUSPLUS)
//! because EXIF GPS can be wrong by ±50 m on the originating
//! device but is otherwise authoritative.

mod extract;
mod parse;

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use exif::{Reader, Tag};

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

use extract::{clean_owner, device_fingerprint, looks_like_image_url};
use parse::{extract_gps, read_str};

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
pub(super) const IMAGE_EXTS: &[&str] = &[
    ".jpg", ".jpeg", ".jpe", ".jfif", ".tif", ".tiff", ".heic", ".heif", ".webp",
];

pub struct ExifGeo;

#[async_trait]
impl Module for ExifGeo {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "EXIF geolocation — parses image URLs to extract GPS coordinates and camera metadata for geolocation"
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

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1589.003", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Coordinates (GPS IFD), DeviceId (camera serial — a cross-image
        // correlation anchor), and Person (the owner/artist named in metadata).
        const KINDS: &[EntityKind] = &[
            EntityKind::Coordinates,
            EntityKind::DeviceId,
            EntityKind::Person,
        ];
        KINDS
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Url) && looks_like_image_url(&t.value)
    }

    /// `accepts()` value-gates (the URL must look like an image), so the default
    /// probe-based `consumes()` is empty — which would leave this module out of
    /// the Url dispatch bucket and silently never run on any image URL. Declare
    /// the kind explicitly; the per-target `accepts()` re-check at dispatch keeps
    /// the image-URL filter so it still only runs on actual images.
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

        // Stream the body and bail the moment the running total exceeds
        // MAX_BYTES. The `Range` header above is only a *request*: the image URL
        // is scraper-discovered (attacker-influenced), and a hostile host can
        // ignore Range and stream an unbounded body — `.bytes()` would buffer the
        // whole thing and OOM the device before the size check ever ran. Capping
        // the in-memory buffer mid-stream is the fix (T2.8). A valid image under
        // the cap is read in full and parses exactly as before.
        use futures::StreamExt as _;
        let mut stream = resp.bytes_stream();
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => return Ok(result),
            };
            if body.len() + chunk.len() > MAX_BYTES as usize {
                return Ok(result);
            }
            body.extend_from_slice(&chunk);
        }

        let mut cursor = std::io::Cursor::new(body.as_slice());
        let exif = match Reader::new().read_from_container(&mut cursor) {
            Ok(e) => e,
            Err(_) => return Ok(result),
        };

        // Gather every cross-correlation signal once — these exist even when the
        // image has no GPS, so an EXIF-stripped-of-location photo can still yield
        // a device serial or an owner name (the prior version emitted nothing
        // without GPS, discarding both).
        let make = read_str(&exif, Tag::Make);
        let model = read_str(&exif, Tag::Model);
        let serial = read_str(&exif, Tag::BodySerialNumber)
            .or_else(|| read_str(&exif, Tag::LensSerialNumber));
        let owner = read_str(&exif, Tag::CameraOwnerName).or_else(|| read_str(&exif, Tag::Artist));
        let software = read_str(&exif, Tag::Software);
        let lens = read_str(&exif, Tag::LensModel);
        let shot_time =
            read_str(&exif, Tag::DateTimeOriginal).or_else(|| read_str(&exif, Tag::DateTime));

        let gps = extract_gps(&exif);
        let person_name = clean_owner(owner.as_deref());
        let fingerprint = device_fingerprint(make.as_deref(), model.as_deref(), serial.as_deref());

        // Nothing actionable in the metadata → done (most re-encoded social images).
        if gps.is_none() && fingerprint.is_none() && person_name.is_none() {
            return Ok(result);
        }

        // Shared evidence: every emitted entity carries the same camera/owner
        // attribute set so the operator can correlate source, device and shot time.
        let evidence = |summary: String| {
            // Fold the present camera/owner fields onto the shared evidence base.
            [
                ("camera_make", make.as_deref()),
                ("camera_model", model.as_deref()),
                ("camera_serial", serial.as_deref()),
                ("lens_model", lens.as_deref()),
                ("software", software.as_deref()),
                ("owner_name", owner.as_deref()),
                ("shot_time", shot_time.as_deref()),
            ]
            .into_iter()
            .filter_map(|(k, v)| v.map(|val| (k, val)))
            .fold(
                Evidence::new(SRC, summary).with_attr("url", url),
                |ev, (k, val)| ev.with_attr(k, val),
            )
        };

        // 1. Coordinates — GPS IFD. Empirically reliable to ~10–50 m; base confidence::HIGH_PLUSPLUS,
        //    above single-source IP-geo (confidence::MEDIUM_HIGH–confidence::MEDIUM_PLUS), below WiGLE consensus (confidence::HIGH_PLUSPLUS_PLUS).
        if let Some((lat, lon)) = gps {
            let coord_str = format!("{lat:.6},{lon:.6}");
            let mut e = Entity::new(
                EntityKind::Coordinates,
                &coord_str,
                confidence::HIGH_PLUSPLUS,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag("exif");
            e.tag("photo-derived");
            crate::util::geo::tag_au_state(&mut e, lat, lon);
            e.add_evidence(
                evidence(format!("EXIF GPS extracted from {url}"))
                    .with_attr("latitude", lat.to_string())
                    .with_attr("longitude", lon.to_string()),
            );
            result.push(e);
        }

        // 2. DeviceId — a camera serial uniquely identifies one physical device,
        //    so the same serial across images links them to the same camera (and
        //    usually the same person): the highest-value EXIF cross-correlation.
        //    Authoritative (camera firmware wrote it) → confidence::VERY_HIGH.
        if let Some(fp) = fingerprint {
            let mut e = Entity::new(
                EntityKind::DeviceId,
                &fp,
                confidence::VERY_HIGH,
                &ctx.scan_id,
            );
            e.tag("exif");
            e.tag("camera");
            e.tag("device-fingerprint");
            e.add_evidence(evidence(format!(
                "Camera serial recovered from EXIF of {url}"
            )));
            result.push(e);
        }

        // 3. Person — the owner/artist named in metadata. CameraOwnerName is set
        //    in-camera by the owner, so it is a real identity lead. Kept below the
        //    confidence::MEDIUM expansion floor (a metadata name is a lead, not a confirmed
        //    identity) but NOT quarantined, so it correlates with same-named
        //    Person entities surfaced by search/breach modules.
        if let Some(name) = person_name {
            let mut e = Entity::new(
                EntityKind::Person,
                &name,
                confidence::LOW_MEDIUM,
                &ctx.scan_id,
            );
            e.tag("exif");
            e.tag("photo-owner");
            e.add_evidence(evidence(format!(
                "Photo owner/artist named in EXIF of {url}"
            )));
            result.push(e);
        }

        Ok(result)
    }
}
