//! Confidence scoring and source scrutiny for media (images) and documents.
//!
//! Two confidences are computed **independently** for an image:
//!   - [`image_content_confidence`] — is this a substantive, real image worth
//!     keeping and linking by perceptual hash? Driven by visual detail and
//!     source trust; it does **not** depend on metadata. A metadata-stripped
//!     photo can still be a high-value content anchor (the local equivalent of
//!     a reverse-image search), so it is scored on its own merits.
//!   - [`image_metadata_confidence`] — is the *embedded metadata* trustworthy
//!     and non-junk? Driven by GPS plausibility and camera/serial/author
//!     richness. A vivid photo can carry worthless metadata and vice-versa.
//!
//! Documents get an analogous [`doc_metadata_confidence`] with junk-author
//! filtering, so a PDF stamped `Author: user` by a default template isn't
//! treated as an identity lead.
//!
//! The threshold consts encode the **minimal confidence at which each approach
//! is used** in the pipeline:
//!   - below [`IMAGE_KEEP_MIN`] an image isn't kept even as a similarity anchor;
//!   - below [`META_EMIT_MIN`] / [`DOC_META_EMIT_MIN`] metadata is treated as
//!     junk and not emitted as entities — so low-relevance media can't recurse
//!     and flood the graph.
//!
//! Provenance-aware cross-correlation against pre-existing high-confidence data
//! happens later, in the graph-aware correlator (AU-033/AU-034); this module
//! provides the intrinsic, per-item scores that gate the recursion.

/// Detail (luma std-dev) below which an image is treated as near-flat — a
/// logo, spacer, solid banner, or tracking pixel — and heavily down-ranked.
pub const FLAT_DETAIL: f64 = 6.0;

/// Minimum content confidence to keep an image as a similarity anchor at all.
pub const IMAGE_KEEP_MIN: f64 = 0.25;

/// Minimum metadata confidence to emit image metadata entities (GPS / device /
/// author). Below this the metadata is treated as junk and dropped, so the
/// image cannot seed excessive recursion on worthless tags.
pub const META_EMIT_MIN: f64 = 0.45;

/// Minimum metadata confidence to emit document metadata entities.
pub const DOC_META_EMIT_MIN: f64 = 0.45;

/// URL-shortener / indirection hosts — provenance is obscured, so trust is low.
const SHORTENERS: &[&str] = &[
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
];

/// Path tokens that mark an image as boilerplate chrome rather than content.
const JUNK_PATH_TOKENS: &[&str] = &[
    "sprite",
    "spacer",
    "tracking",
    "pixel",
    "placeholder",
    "/icons/",
    "avatar-default",
    "default-avatar",
    "blank",
];

/// Generic / default author strings that carry no identity value.
const GENERIC_AUTHORS: &[&str] = &[
    "user",
    "admin",
    "administrator",
    "owner",
    "guest",
    "default",
    "microsoft office user",
    "windows user",
    "word user",
    "unknown",
    "author",
    "none",
    "n/a",
];

/// Scrutinise a media URL's provenance and return a trust factor in `0.0..=1.0`.
/// Considers scheme (https vs http), host (shorteners/blank), and path tokens
/// that mark boilerplate chrome. Intrinsic only — graph-aware provenance
/// (does the host match a high-confidence entity?) is the correlator's job.
pub fn source_trust(url: &str) -> f64 {
    let u = url.trim();
    let lower = u.to_lowercase();

    let insecure = lower.starts_with("http://");
    // Host = between scheme and the next '/'.
    let after_scheme = lower
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(&lower);
    let host = after_scheme.split(['/', '?', '#']).next().unwrap_or("");

    let mut trust: f64 = if host.is_empty() || lower.starts_with("data:") {
        0.20
    } else if SHORTENERS
        .iter()
        .any(|s| host == *s || host.ends_with(&format!(".{s}")))
    {
        0.30
    } else {
        0.60
    };

    if insecure {
        trust *= 0.85;
    }
    if JUNK_PATH_TOKENS.iter().any(|t| lower.contains(t)) {
        trust *= 0.40;
    }
    trust.clamp(0.0, 1.0)
}

/// Content confidence for an image: does it look like a substantive, real
/// image worth keeping and linking? Independent of metadata.
///
/// `detail` is the luma std-dev from [`crate::util::phash`]; `area_px` is
/// `width*height`; `source_trust` comes from [`source_trust`].
pub fn image_content_confidence(detail: f64, area_px: u64, source_trust: f64) -> f64 {
    let detail_factor = (detail / 30.0).clamp(0.0, 1.0);
    // A modest bonus for larger images (real photos vs thumbnails); saturates
    // by ~0.25 MP so a hero image doesn't dominate.
    let area_factor = ((area_px as f64) / 250_000.0).clamp(0.0, 1.0);

    let mut c = 0.25 + 0.45 * detail_factor + 0.20 * source_trust + 0.10 * area_factor;
    // Near-flat images (logos/spacers) are almost never useful content.
    if detail < FLAT_DETAIL {
        c *= 0.35;
    }
    c.clamp(0.0, 1.0)
}

/// Whether `(lat, lon)` is a plausible real-world fix: in range and not the
/// Null-Island `(0,0)` default that cameras/strippers leave behind.
pub fn gps_plausible(lat: f64, lon: f64) -> bool {
    (-90.0..=90.0).contains(&lat)
        && (-180.0..=180.0).contains(&lon)
        && !(lat.abs() < 0.01 && lon.abs() < 0.01)
}

/// Presence/quality signals harvested from an image's EXIF + XMP.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImageMetaSignals {
    /// GPS already validated as plausible by the caller.
    pub gps_plausible: bool,
    pub make: bool,
    pub model: bool,
    pub serial: bool,
    pub author: bool,
    pub software: bool,
}

/// Metadata confidence for an image — how trustworthy/rich is the embedded
/// metadata? Additive, capped at 1.0. Zero when nothing usable is present.
pub fn image_metadata_confidence(s: &ImageMetaSignals) -> f64 {
    let mut c: f64 = 0.0;
    if s.gps_plausible {
        c += 0.35;
    }
    if s.make && s.model {
        c += 0.20;
    }
    if s.serial {
        c += 0.25; // a body serial is a strong, hard-to-fake device identifier
    }
    if s.author {
        c += 0.20;
    }
    if s.software {
        c += 0.05;
    }
    c.clamp(0.0, 1.0)
}

/// True if `name` is a generic/default author string with no identity value.
pub fn is_generic_author(name: &str) -> bool {
    let n = name.trim().to_lowercase();
    n.is_empty() || n.chars().count() <= 1 || GENERIC_AUTHORS.iter().any(|g| n == *g)
}

/// Presence/quality signals harvested from a document's metadata.
#[derive(Debug, Default, Clone, Copy)]
pub struct DocMetaSignals {
    /// Author present AND not a generic/default string.
    pub author_ok: bool,
    pub title: bool,
    /// Authoring tool / producer present and non-empty.
    pub tool: bool,
    /// A creation/modification date was present.
    pub dated: bool,
}

/// Metadata confidence for a document. Author dominates (it's the identity
/// lead); a title/tool/date add corroboration.
pub fn doc_metadata_confidence(s: &DocMetaSignals) -> f64 {
    // Author dominates — it's the identity lead. Title/tool/date are weak
    // corroboration that, on their own, must stay below the emit gate so a
    // template-stamped PDF with no real author isn't mined recursively.
    let mut c: f64 = 0.0;
    if s.author_ok {
        c += 0.45;
    }
    if s.title {
        c += 0.10;
    }
    if s.tool {
        c += 0.15;
    }
    if s.dated {
        c += 0.10;
    }
    c.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_trust_penalises_shorteners_insecure_and_junk() {
        assert!(source_trust("https://example.com/photo.jpg") >= 0.55);
        assert!(
            source_trust("http://example.com/photo.jpg")
                < source_trust("https://example.com/photo.jpg")
        );
        assert!(source_trust("https://bit.ly/abc") <= 0.35);
        assert!(source_trust("https://cdn.example.com/sprite-sheet.png") < 0.30);
        assert!(source_trust("data:image/png;base64,AAAA") <= 0.25);
    }

    #[test]
    fn content_confidence_rewards_detail_and_trust() {
        let flat = image_content_confidence(2.0, 300_000, 0.6);
        let vivid = image_content_confidence(40.0, 300_000, 0.6);
        assert!(vivid > flat);
        assert!(
            flat < IMAGE_KEEP_MIN,
            "near-flat image should fall below keep floor: {flat}"
        );
        assert!(vivid > 0.6);
        // Source trust moves the needle.
        assert!(
            image_content_confidence(40.0, 300_000, 0.6)
                > image_content_confidence(40.0, 300_000, 0.2)
        );
    }

    #[test]
    fn gps_plausible_rejects_null_island() {
        assert!(gps_plausible(-27.47, 153.02));
        assert!(!gps_plausible(0.0, 0.0));
        assert!(!gps_plausible(91.0, 0.0));
    }

    #[test]
    fn image_metadata_confidence_scales_with_richness() {
        let none = image_metadata_confidence(&ImageMetaSignals::default());
        assert_eq!(none, 0.0);
        let gps_only = image_metadata_confidence(&ImageMetaSignals {
            gps_plausible: true,
            ..Default::default()
        });
        assert!((gps_only - 0.35).abs() < 1e-9);
        let rich = image_metadata_confidence(&ImageMetaSignals {
            gps_plausible: true,
            make: true,
            model: true,
            serial: true,
            author: true,
            software: true,
        });
        assert!((META_EMIT_MIN..=1.0).contains(&rich));
    }

    #[test]
    fn generic_authors_are_rejected() {
        for j in [
            "user",
            "Administrator",
            "Microsoft Office User",
            "",
            "x",
            "  owner ",
        ] {
            assert!(is_generic_author(j), "{j:?} should be generic");
        }
        for real in ["Jane Photographer", "Bob Smith", "J. Meyers"] {
            assert!(!is_generic_author(real), "{real:?} should be real");
        }
    }

    #[test]
    fn doc_confidence_needs_real_author_to_clear_threshold() {
        // Tool + date but no real author → below emit threshold.
        let weak = doc_metadata_confidence(&DocMetaSignals {
            author_ok: false,
            title: true,
            tool: true,
            dated: true,
        });
        assert!(weak < DOC_META_EMIT_MIN);
        // A real author alone clears it.
        let ok = doc_metadata_confidence(&DocMetaSignals {
            author_ok: true,
            ..Default::default()
        });
        assert!(ok >= DOC_META_EMIT_MIN);
    }
}
