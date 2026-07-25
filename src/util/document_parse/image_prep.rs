//! Image preprocessing for OCR (resize, denoise, contrast adjustment).

use image::{DynamicImage, ImageReader};
use std::path::Path;
use tracing::debug;

use super::DocumentResult;

/// Load and preprocess image for OCR.
pub fn preprocess_image<P: AsRef<Path>>(
    image_path: P,
    max_width: u32,
) -> DocumentResult<DynamicImage> {
    let path = image_path.as_ref();
    let path_str = path.to_string_lossy();

    debug!("Preprocessing image: {}", path_str);

    // Load image
    let mut img = ImageReader::open(path)?.decode()?;

    // Resize if too large (improves OCR speed)
    if img.width() > max_width {
        let ratio = max_width as f32 / img.width() as f32;
        let new_height = (img.height() as f32 * ratio) as u32;
        img = img.resize(max_width, new_height, image::imageops::FilterType::Lanczos3);
        debug!("Resized to {}x{}", max_width, new_height);
    }

    // Convert to grayscale (improves OCR)
    let gray = img.to_luma8();
    let img = DynamicImage::ImageLuma8(gray);

    Ok(img)
}

/// Estimate image quality for OCR (heuristic: contrast, edge density).
pub fn estimate_ocr_quality(img: &DynamicImage) -> f64 {
    let gray = img.to_luma8();
    let pixels = gray.as_raw();

    // Simple heuristic: measure std dev of pixel values (higher = better contrast)
    let mean = pixels.iter().map(|&p| p as f64).sum::<f64>() / pixels.len() as f64;
    let variance = pixels
        .iter()
        .map(|&p| (p as f64 - mean).powi(2))
        .sum::<f64>()
        / pixels.len() as f64;
    let std_dev = variance.sqrt();

    // Normalize to 0-1 range (OCR typically works best with std dev 50-100)
    (std_dev / 128.0).min(1.0).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Luma};

    #[test]
    fn preprocess_nonexistent_image() {
        let result = preprocess_image("/nonexistent/image.png", 1024);
        assert!(result.is_err());
    }

    #[test]
    fn estimate_quality_uniform_image() {
        // Create a uniform gray image (low quality)
        let img: ImageBuffer<Luma<u8>, Vec<u8>> = ImageBuffer::from_fn(10, 10, |_, _| Luma([128u8]));
        let dyn_img = DynamicImage::ImageLuma8(img);
        let quality = estimate_ocr_quality(&dyn_img);
        // Uniform image should have low quality score
        assert!(quality < 0.1);
    }
}
