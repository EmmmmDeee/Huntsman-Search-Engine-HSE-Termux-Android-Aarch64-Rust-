//! Image reverse search preparation: multi-size generation for search engine compatibility.
//!
//! Generates image variants sized for the major reverse-image engines, which
//! each re-encode uploads to their own working resolution. Feeding an engine a
//! variant near that resolution avoids a lossy double-resize and keeps the
//! upload small enough to submit quickly.
//!
//! Every variant is encoded in a format this build can actually produce, and
//! the declared `format` always matches the bytes — a mismatch would be
//! rejected (or silently mis-decoded) by the receiving engine.

use image::{DynamicImage, ImageEncoder};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::debug;

use super::DocumentResult;

/// Encoding used for a generated variant.
///
/// Deliberately closed over the formats this build can encode. `image` 0.25
/// ships a WebP *decoder* only, so WebP is not representable here — an engine
/// that prefers WebP is served JPEG, which every one of them accepts, rather
/// than JPEG bytes mislabelled `.webp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VariantFormat {
    Jpeg,
    Png,
}

impl VariantFormat {
    /// File extension and the value published in variant metadata.
    fn as_str(self) -> &'static str {
        match self {
            Self::Jpeg => "jpeg",
            Self::Png => "png",
        }
    }
}

/// Image variant optimized for a specific reverse search engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageVariant {
    /// Engine name: "google", "bing", "tineye", "yandex", "baidu", "thumbnail"
    pub engine: String,
    /// Image dimensions (width x height)
    pub dimensions: (u32, u32),
    /// Encoded format: "jpeg" or "png". Always matches `data`.
    pub format: String,
    /// Quality setting (0-100, JPEG only)
    pub quality: u8,
    /// Encoded size in bytes
    pub file_size_bytes: usize,
    /// Raw image bytes
    #[serde(skip)]
    pub data: Vec<u8>,
}

/// Collection of image variants for reverse image searching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseImageSearchSet {
    /// Original image dimensions
    pub original_dimensions: (u32, u32),
    /// All generated variants
    pub variants: Vec<ImageVariant>,
    /// Recommended primary variant for fastest search
    pub primary_variant: Option<String>,
    /// Perceptual hash of the original image, for deduplication
    pub image_hash: String,
}

/// Image size configuration for a specific search engine.
#[derive(Debug, Clone, Copy)]
struct SearchEngineConfig {
    name: &'static str,
    width: u32,
    height: u32,
    format: VariantFormat,
    quality: u8,
    description: &'static str,
}

/// Target sizes per engine. A `const` table rather than a constructed `Vec` —
/// the set is fixed at compile time and rebuilding it per image was pure churn.
const SEARCH_ENGINES: &[SearchEngineConfig] = &[
    SearchEngineConfig {
        name: "google",
        width: 800,
        height: 600,
        format: VariantFormat::Jpeg,
        quality: 85,
        description: "Google Images - balanced quality/speed",
    },
    SearchEngineConfig {
        name: "bing",
        width: 640,
        height: 480,
        format: VariantFormat::Jpeg,
        quality: 80,
        description: "Bing Visual Search - optimized for web",
    },
    // TinEye matches exact and near-duplicate images rather than semantic
    // content, so it is the one engine where re-compression actively hurts:
    // JPEG artifacts perturb the very signature it fingerprints. Ship it the
    // resize losslessly. `quality` is inert for PNG.
    SearchEngineConfig {
        name: "tineye",
        width: 500,
        height: 375,
        format: VariantFormat::Png,
        quality: 100,
        description: "TinEye - lossless, exact/near-duplicate matching",
    },
    SearchEngineConfig {
        name: "yandex",
        width: 640,
        height: 480,
        format: VariantFormat::Jpeg,
        quality: 80,
        description: "Yandex Images - JPEG (no WebP encoder in this build)",
    },
    SearchEngineConfig {
        name: "baidu",
        width: 400,
        height: 300,
        format: VariantFormat::Jpeg,
        quality: 75,
        description: "Baidu Images - smaller upload for slower links",
    },
    SearchEngineConfig {
        name: "thumbnail",
        width: 200,
        height: 150,
        format: VariantFormat::Jpeg,
        quality: 70,
        description: "Quick thumbnail - preview + hashing",
    },
];

/// Generate reverse image search variants from an image file.
pub fn generate_reverse_image_variants<P: AsRef<Path>>(
    image_path: P,
) -> DocumentResult<ReverseImageSearchSet> {
    let path = image_path.as_ref();
    debug!(
        "Generating reverse image search variants for: {}",
        path.display()
    );
    let img = image::ImageReader::open(path)?.decode()?;
    generate_variants_from_image(&img)
}

/// Generate variants from an already-decoded image.
///
/// Exposed separately so a caller that has decoded the image for another
/// purpose does not pay to decode it a second time.
pub fn generate_variants_from_image(img: &DynamicImage) -> DocumentResult<ReverseImageSearchSet> {
    let original_dimensions = (img.width(), img.height());
    debug!(
        width = original_dimensions.0,
        height = original_dimensions.1,
        "source image decoded"
    );

    let mut variants = Vec::with_capacity(SEARCH_ENGINES.len());
    for config in SEARCH_ENGINES {
        let variant = generate_image_variant(img, config)?;
        debug!(
            engine = config.name,
            width = variant.dimensions.0,
            height = variant.dimensions.1,
            bytes = variant.file_size_bytes,
            purpose = config.description,
            "generated variant"
        );
        variants.push(variant);
    }

    // Google's variant is the primary: the largest of the set, and the engine
    // with the broadest index, so a single-shot search starts there.
    let primary_variant = variants
        .iter()
        .find(|v| v.engine == "google")
        .map(|v| v.engine.clone());

    Ok(ReverseImageSearchSet {
        original_dimensions,
        variants,
        primary_variant,
        image_hash: compute_image_hash(img),
    })
}

/// Generate a single image variant for a search engine.
fn generate_image_variant(
    img: &DynamicImage,
    config: &SearchEngineConfig,
) -> DocumentResult<ImageVariant> {
    let resized = resize_image_maintain_aspect(img, config.width, config.height);
    let rgb = resized.to_rgb8();
    let mut buffer = Vec::new();

    match config.format {
        VariantFormat::Jpeg => {
            image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buffer, config.quality)
                .encode(
                    &rgb,
                    rgb.width(),
                    rgb.height(),
                    image::ExtendedColorType::Rgb8,
                )?;
        }
        VariantFormat::Png => {
            image::codecs::png::PngEncoder::new(&mut buffer).write_image(
                &rgb,
                rgb.width(),
                rgb.height(),
                image::ExtendedColorType::Rgb8,
            )?;
        }
    }

    Ok(ImageVariant {
        engine: config.name.to_string(),
        dimensions: (rgb.width(), rgb.height()),
        format: config.format.as_str().to_string(),
        quality: config.quality,
        file_size_bytes: buffer.len(),
        data: buffer,
    })
}

/// Resize to fit within `max_width` x `max_height`, preserving aspect ratio and
/// never upscaling — enlarging a small source invents detail the engines would
/// then match against.
fn resize_image_maintain_aspect(
    img: &DynamicImage,
    max_width: u32,
    max_height: u32,
) -> DynamicImage {
    let (orig_w, orig_h) = (img.width(), img.height());
    if orig_w == 0 || orig_h == 0 {
        return img.clone();
    }

    let scale = (max_width as f64 / orig_w as f64)
        .min(max_height as f64 / orig_h as f64)
        .min(1.0);

    // Clamp to at least one pixel per axis: an extreme aspect ratio (a 10000x1
    // banner, say) scales its short axis to zero, and a zero-dimension resize
    // yields an image no encoder can write.
    let new_w = ((orig_w as f64 * scale) as u32).max(1);
    let new_h = ((orig_h as f64 * scale) as u32).max(1);

    img.resize(new_w, new_h, image::imageops::FilterType::Lanczos3)
}

/// Compute a 64-bit average-hash (aHash) of an image, rendered as 16 hex chars.
///
/// Uses `resize_exact` rather than an aspect-preserving resize: the hash is a
/// fixed 8x8 grid, so letting the grid change shape with the source would make
/// hashes of differently-proportioned images incomparable — which defeats the
/// deduplication the hash exists for.
fn compute_image_hash(img: &DynamicImage) -> String {
    let gray = img
        .resize_exact(8, 8, image::imageops::FilterType::Lanczos3)
        .to_luma8();
    let pixels = gray.as_raw();

    let sum: u32 = pixels.iter().map(|&p| u32::from(p)).sum();
    let mean = sum / pixels.len() as u32;

    // Each of the 64 cells contributes one bit: brighter than the mean → 1.
    let mut bits: u64 = 0;
    for &pixel in pixels {
        bits = (bits << 1) | u64::from(u32::from(pixel) > mean);
    }
    format!("{bits:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, RgbImage};

    /// A deterministic gradient image — distinct enough per size that hashes
    /// of different content differ.
    fn gradient(width: u32, height: u32) -> DynamicImage {
        DynamicImage::ImageRgb8(RgbImage::from_fn(width, height, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8])
        }))
    }

    fn solid(width: u32, height: u32, level: u8) -> DynamicImage {
        DynamicImage::ImageRgb8(RgbImage::from_fn(width, height, |_, _| {
            image::Rgb([level, level, level])
        }))
    }

    #[test]
    fn every_variant_decodes_as_the_format_it_claims() {
        // The regression that matters: a variant labelled `jpeg`/`png` whose
        // bytes are actually something else would be rejected by the engine it
        // was built for. Decode each variant back and confirm the guessed
        // format matches the declaration.
        let set = generate_variants_from_image(&gradient(1200, 900)).unwrap();
        assert_eq!(set.variants.len(), SEARCH_ENGINES.len());

        for variant in &set.variants {
            assert!(
                !variant.data.is_empty(),
                "{} variant encoded to zero bytes",
                variant.engine
            );
            assert_eq!(variant.file_size_bytes, variant.data.len());

            let format = image::guess_format(&variant.data).unwrap_or_else(|e| {
                panic!(
                    "{} variant is not a recognisable image: {e}",
                    variant.engine
                )
            });
            let expected = match variant.format.as_str() {
                "jpeg" => image::ImageFormat::Jpeg,
                "png" => image::ImageFormat::Png,
                other => panic!("{} declared an unencodable format {other}", variant.engine),
            };
            assert_eq!(
                format, expected,
                "{} declares {} but the bytes are {format:?}",
                variant.engine, variant.format
            );

            let decoded = image::load_from_memory(&variant.data).expect("variant must decode");
            assert_eq!(
                (decoded.width(), decoded.height()),
                variant.dimensions,
                "{} reports dimensions that disagree with its bytes",
                variant.engine
            );
        }
    }

    #[test]
    fn variants_fit_within_their_engine_bounds() {
        let set = generate_variants_from_image(&gradient(1200, 900)).unwrap();
        for config in SEARCH_ENGINES {
            let variant = set
                .variants
                .iter()
                .find(|v| v.engine == config.name)
                .unwrap_or_else(|| panic!("missing variant for {}", config.name));
            assert!(
                variant.dimensions.0 <= config.width && variant.dimensions.1 <= config.height,
                "{} variant {:?} exceeds its {}x{} budget",
                config.name,
                variant.dimensions,
                config.width,
                config.height
            );
        }
        assert_eq!(set.primary_variant.as_deref(), Some("google"));
        assert_eq!(set.original_dimensions, (1200, 900));
    }

    #[test]
    fn resize_preserves_aspect_ratio() {
        let resized = resize_image_maintain_aspect(&gradient(1000, 500), 640, 480);
        // 1000x500 into 640x480: width binds first (0.64 < 0.96) → 640x320.
        assert_eq!((resized.width(), resized.height()), (640, 320));
    }

    #[test]
    fn resize_never_upscales() {
        let resized = resize_image_maintain_aspect(&gradient(100, 80), 800, 600);
        assert_eq!(
            (resized.width(), resized.height()),
            (100, 80),
            "a source smaller than the target must be left alone"
        );
    }

    #[test]
    fn resize_of_extreme_aspect_ratio_keeps_both_axes_nonzero() {
        // The short axis scales to 0.08px here; a zero-dimension image cannot
        // be encoded, so both axes must clamp to at least one pixel.
        let resized = resize_image_maintain_aspect(&gradient(10_000, 1), 800, 600);
        assert!(
            resized.width() >= 1 && resized.height() >= 1,
            "got {resized:?}"
        );
        // And it must still be encodable end-to-end.
        let set = generate_variants_from_image(&gradient(10_000, 1)).unwrap();
        assert!(set.variants.iter().all(|v| !v.data.is_empty()));
    }

    #[test]
    fn hash_is_stable_and_fixed_width() {
        let hash = compute_image_hash(&gradient(640, 480));
        assert_eq!(hash.len(), 16, "aHash must render as 16 hex chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            hash,
            compute_image_hash(&gradient(640, 480)),
            "the same image must hash identically"
        );
    }

    #[test]
    fn hash_width_is_independent_of_aspect_ratio() {
        // The bug this pins: an aspect-preserving resize gave a 1000x500 image
        // a 32-bit hash and a square image a 64-bit one, so the two could
        // never be compared.
        let wide = compute_image_hash(&gradient(1000, 500));
        let square = compute_image_hash(&gradient(500, 500));
        let tall = compute_image_hash(&gradient(500, 1000));
        assert_eq!(wide.len(), 16);
        assert_eq!(square.len(), 16);
        assert_eq!(tall.len(), 16);
    }

    #[test]
    fn hash_distinguishes_different_images() {
        assert_ne!(
            compute_image_hash(&gradient(256, 256)),
            compute_image_hash(&solid(256, 256, 200)),
        );
    }

    #[test]
    fn flat_image_hashes_without_panicking() {
        // Every pixel equals the mean, so no bit is set. Exercises the
        // divide-and-compare path against a uniform source.
        assert_eq!(compute_image_hash(&solid(64, 64, 128)), "0".repeat(16));
    }

    #[test]
    fn generate_variants_nonexistent_image() {
        assert!(generate_reverse_image_variants("/nonexistent/image.jpg").is_err());
    }
}
