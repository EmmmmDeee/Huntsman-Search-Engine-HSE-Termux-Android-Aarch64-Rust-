mod features;
mod pixels;

use self::pixels::{Alignment, pixel_agreement};
use image::GrayImage;

#[allow(clippy::cast_precision_loss)] // Each plane dimension is at most 896 pixels.
pub(crate) fn full_frame(a: &GrayImage, b: &GrayImage) -> Option<String> {
    let sx = b.width() as f32 / a.width() as f32;
    let sy = b.height() as f32 / a.height() as f32;
    if ((sx / sy) - 1.0).abs() < 0.025 {
        let score = pixel_agreement(
            a,
            b,
            Alignment {
                sx,
                sy,
                dx: 0.0,
                dy: 0.0,
            },
        );
        if score.accepts(5.5, 0.94) {
            return Some(score.describe());
        }
    }

    None
}

pub(crate) fn aligned_overlap(a: &GrayImage, b: &GrayImage) -> Option<String> {
    features::local_match(a, b)
        .map(|(hits, score)| format!("{hits} aligned features. {}", score.describe()))
}
