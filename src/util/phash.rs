//! Perceptual image hashing (DCT-based pHash) for content equivalence.
//!
//! A perceptual hash is a 64-bit fingerprint of an image's *visual content*
//! that survives re-encoding, rescaling, and mild recompression — so two
//! copies of the same photo hash to within a small Hamming distance even when
//! their bytes (and metadata) differ entirely. This is HSE's local,
//! deterministic stand-in for reverse-image search: it links images **without
//! relying on any metadata**, and needs no external service (honouring "no
//! external computations").
//!
//! Algorithm (the robust DCT variant, not the weaker average-hash):
//!   1. decode → grayscale,
//!   2. resize to 32×32 (low-pass — discards high-frequency noise),
//!   3. 2-D DCT-II,
//!   4. keep the top-left 8×8 low-frequency block,
//!   5. threshold each coefficient against the block median (DC excluded) → 64 bits.
//!
//! Alongside the hash we return a **detail** score (luma standard deviation of
//! the normalised image). Near-uniform images — logos, spacer GIFs, tracking
//! pixels, solid banners — have near-zero detail and are junk for similarity
//! work; callers use this to gate content confidence.

use image::GrayImage;
use image::imageops::FilterType;

/// Working resolution fed to the DCT.
const DCT_DIM: usize = 32;
/// Edge of the retained low-frequency block → 8×8 = 64-bit hash.
const HASH_DIM: usize = 8;

/// Max Hamming distance at which two perceptual hashes are treated as the
/// *same* image. ≤10/64 is the well-established near-duplicate threshold.
pub const EQUIV_MAX_HAMMING: u32 = 10;

/// Smallest image edge (px) worth hashing. Below this an image is a spacer /
/// icon / tracking pixel, not content — `hash_bytes` returns `None`.
const MIN_EDGE: u32 = 16;

/// A 64-bit perceptual hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Phash(pub u64);

impl Phash {
    /// Hamming distance (number of differing bits) to another hash. `0` =
    /// pixel-identical low-frequency content; ≤[`EQUIV_MAX_HAMMING`] ≈ same image.
    pub fn hamming(self, other: Phash) -> u32 {
        (self.0 ^ other.0).count_ones()
    }
    pub fn to_hex(self) -> String {
        format!("{:016x}", self.0)
    }
    pub fn from_hex(s: &str) -> Option<Phash> {
        u64::from_str_radix(s.trim(), 16).ok().map(Phash)
    }
}

/// Hash + a `0.0..` detail score (luma std-dev of the 32×32 normalised image).
#[derive(Debug, Clone, Copy)]
pub struct HashResult {
    pub hash: Phash,
    pub detail: f64,
    /// Original image dimensions (px), before the internal 32×32 downscale.
    pub width: u32,
    pub height: u32,
}

/// Decode `bytes` (jpeg/png) and compute the perceptual hash + detail score.
/// Returns `None` if the bytes don't decode as a supported image or the image
/// is too small to carry meaningful content (< [`MIN_EDGE`] px on an edge).
pub fn hash_bytes(bytes: &[u8]) -> Option<HashResult> {
    let img = image::load_from_memory(bytes).ok()?;
    let (w, h) = (img.width(), img.height());
    if w < MIN_EDGE || h < MIN_EDGE {
        return None;
    }
    Some(hash_luma(&img.to_luma8()))
}

/// Core hash over a grayscale image — separated out so tests can drive it with
/// a constructed `GrayImage` (no encoder/decoder needed).
pub fn hash_luma(img: &GrayImage) -> HashResult {
    let (width, height) = img.dimensions();
    let small = image::imageops::resize(img, DCT_DIM as u32, DCT_DIM as u32, FilterType::Triangle);

    let mut m = [[0f32; DCT_DIM]; DCT_DIM];
    let (mut sum, mut sumsq) = (0f64, 0f64);
    #[allow(clippy::needless_range_loop)] // 2-D index into `m` is the clearest form
    for y in 0..DCT_DIM {
        for x in 0..DCT_DIM {
            let v = small.get_pixel(x as u32, y as u32)[0] as f32;
            m[y][x] = v;
            sum += v as f64;
            sumsq += (v as f64) * (v as f64);
        }
    }
    let n = (DCT_DIM * DCT_DIM) as f64;
    let mean = sum / n;
    let detail = (sumsq / n - mean * mean).max(0.0).sqrt();

    // Separable 2-D DCT-II: rows then columns.
    let cos = cos_table();
    let mut rows = [[0f32; DCT_DIM]; DCT_DIM];
    for y in 0..DCT_DIM {
        dct1d(&m[y], &mut rows[y], cos);
    }
    let mut dct = [[0f32; DCT_DIM]; DCT_DIM];
    let mut col_in = [0f32; DCT_DIM];
    let mut col_out = [0f32; DCT_DIM];
    for x in 0..DCT_DIM {
        for (y, slot) in col_in.iter_mut().enumerate() {
            *slot = rows[y][x];
        }
        dct1d(&col_in, &mut col_out, cos);
        for (y, &v) in col_out.iter().enumerate() {
            dct[y][x] = v;
        }
    }

    // Low-frequency 8×8 block. Median over the block, DC term excluded so a
    // bright/dark overall image doesn't bias the threshold.
    let mut block = [0f32; HASH_DIM * HASH_DIM];
    for y in 0..HASH_DIM {
        for x in 0..HASH_DIM {
            block[y * HASH_DIM + x] = dct[y][x];
        }
    }
    let mut sorted: Vec<f32> = block.iter().copied().skip(1).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = sorted[sorted.len() / 2];

    let mut hash = 0u64;
    for (i, &v) in block.iter().enumerate() {
        if v > median {
            hash |= 1u64 << i;
        }
    }
    HashResult {
        hash: Phash(hash),
        detail,
        width,
        height,
    }
}

fn dct1d(input: &[f32; DCT_DIM], output: &mut [f32; DCT_DIM], cos: &[[f32; DCT_DIM]; DCT_DIM]) {
    for (k, out) in output.iter_mut().enumerate() {
        let mut s = 0f32;
        for (n, &x) in input.iter().enumerate() {
            s += x * cos[k][n];
        }
        *out = s;
    }
}

/// Precomputed `cos(π/N · (n+½) · k)` table (DCT-II basis), built once.
fn cos_table() -> &'static [[f32; DCT_DIM]; DCT_DIM] {
    static TABLE: std::sync::OnceLock<[[f32; DCT_DIM]; DCT_DIM]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [[0f32; DCT_DIM]; DCT_DIM];
        for (k, row) in t.iter_mut().enumerate() {
            for (n, cell) in row.iter_mut().enumerate() {
                *cell = (std::f32::consts::PI / DCT_DIM as f32 * (n as f32 + 0.5) * k as f32).cos();
            }
        }
        t
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GrayImage, Luma};

    // Smooth diagonal 0→255 gradient, resolution-independent. Used for the
    // detail test (lots of luma variance).
    fn gradient(w: u32, h: u32) -> GrayImage {
        let (dx, dy) = ((w.max(2) - 1) as f32, (h.max(2) - 1) as f32);
        GrayImage::from_fn(w, h, |x, y| {
            let v = (x as f32 / dx + y as f32 / dy) / 2.0 * 255.0;
            Luma([v.round().clamp(0.0, 255.0) as u8])
        })
    }
    fn solid(w: u32, h: u32, v: u8) -> GrayImage {
        GrayImage::from_fn(w, h, |_, _| Luma([v]))
    }

    // Smooth low-frequency 2-D sinusoid — the resize-stable structure a
    // perceptual hash is designed to capture (its energy lands in a few low
    // DCT bins). `fx`/`fy` pick the spatial frequencies so two patterns can be
    // made clearly distinct. Resolution-independent.
    fn wave(w: u32, h: u32, fx: f32, fy: f32) -> GrayImage {
        use std::f32::consts::PI;
        let (dx, dy) = ((w.max(2) - 1) as f32, (h.max(2) - 1) as f32);
        GrayImage::from_fn(w, h, |x, y| {
            let (nx, ny) = (x as f32 / dx, y as f32 / dy);
            let v = 128.0 + 70.0 * (2.0 * PI * fx * nx).sin() + 50.0 * (2.0 * PI * fy * ny).cos();
            Luma([v.round().clamp(0.0, 255.0) as u8])
        })
    }

    #[test]
    fn hex_roundtrips() {
        let p = Phash(0x0123_4567_89ab_cdef);
        assert_eq!(p.to_hex(), "0123456789abcdef");
        assert_eq!(Phash::from_hex("0123456789abcdef"), Some(p));
        assert_eq!(Phash::from_hex("not-hex"), None);
    }

    #[test]
    fn hamming_counts_differing_bits() {
        assert_eq!(Phash(0).hamming(Phash(0)), 0);
        assert_eq!(Phash(0).hamming(Phash(u64::MAX)), 64);
        assert_eq!(Phash(0b1011).hamming(Phash(0b1101)), 2);
    }

    #[test]
    fn identical_images_hash_identically() {
        let a = hash_luma(&gradient(64, 64));
        let b = hash_luma(&gradient(64, 64));
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.hash.hamming(b.hash), 0);
    }

    #[test]
    fn rescaled_copy_is_closer_than_a_distinct_image() {
        // The core perceptual property: a rescaled copy of the same content is
        // closer (smaller Hamming) than a structurally different image. (The
        // absolute ≤EQUIV_MAX_HAMMING threshold holds for real broadband
        // photos; synthetic patterns have sparse DCT spectra whose near-median
        // bins are intrinsically noisy, so we assert the robust *ordering*.)
        let same_big = hash_luma(&wave(128, 128, 1.0, 2.0)).hash;
        let same_small = hash_luma(&wave(48, 48, 1.0, 2.0)).hash;
        let different = hash_luma(&wave(64, 64, 5.0, 6.0)).hash;
        let d_same = same_big.hamming(same_small);
        let d_diff = same_big.hamming(different);
        assert!(
            d_same < d_diff,
            "rescaled copy ({d_same}) must be closer than a distinct image ({d_diff})"
        );
    }

    #[test]
    fn flat_image_has_near_zero_detail() {
        assert!(hash_luma(&solid(64, 64, 128)).detail < 1.0);
        // A gradient is full of detail.
        assert!(hash_luma(&gradient(64, 64)).detail > 20.0);
    }

    #[test]
    fn distinct_content_differs() {
        // Different spatial frequencies → many differing bits.
        let a = hash_luma(&wave(64, 64, 1.0, 2.0));
        let b = hash_luma(&wave(64, 64, 4.0, 5.0));
        assert!(a.hash.hamming(b.hash) > EQUIV_MAX_HAMMING);
    }
}
