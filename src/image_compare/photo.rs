use image::{DynamicImage, GrayImage, ImageReader, Limits, imageops};
use std::io::Cursor;

use crate::sha256::{hex32, sha256};

pub const MAX_FILE_BYTES: usize = 20 * 1024 * 1024;
const MAX_PIXELS: u64 = 16_000_000;
pub(super) const MIN_SIDE: u32 = 64;

fn validate_size(bytes: &[u8], name: &str) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
        return Err(format!("{name} must be between 1 byte and 20 MiB."));
    }
    Ok(())
}

pub(super) struct Photo {
    pub gray: GrayImage,
    pub file: super::ImageFile,
}

pub(super) fn decode(bytes: &[u8], name: &str) -> Result<Photo, String> {
    validate_size(bytes, name)?;
    let reader = || {
        ImageReader::new(Cursor::new(bytes))
            .with_guessed_format()
            .map_err(|_| format!("Could not read {name}."))
    };
    let (width, height) = reader()?
        .into_dimensions()
        .map_err(|_| format!("Could not read {name}. Use JPEG, PNG or WebP."))?;
    if width < MIN_SIDE || height < MIN_SIDE || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(format!(
            "{name} must be at least 64 × 64 and at most 16 megapixels."
        ));
    }
    let mut reader = reader()?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(width);
    limits.max_image_height = Some(height);
    limits.max_alloc = Some(96 * 1024 * 1024);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|_| format!("Could not decode {name}."))?;
    let orientation = crate::exif::parse(bytes)
        .ok()
        .and_then(|parsed| {
            parsed
                .fields
                .into_iter()
                .find(|(key, _)| key == "Orientation")
        })
        .and_then(|(_, value)| value.parse::<u8>().ok())
        .unwrap_or(1);
    let image = match orientation {
        2 => image.fliph(),
        3 => image.rotate180(),
        4 => image.flipv(),
        5 => image.rotate90().fliph(),
        6 => image.rotate90(),
        7 => image.rotate90().flipv(),
        8 => image.rotate270(),
        _ => image,
    };
    let (width, height) = (image.width(), image.height());
    let small = image.resize(896, 896, imageops::FilterType::Triangle);
    let gray = composite(small);
    let file = super::ImageFile {
        sha256: hex32(&sha256(bytes)),
        bytes: bytes.len(),
        width,
        height,
    };
    Ok(Photo { gray, file })
}

#[allow(clippy::cast_possible_truncation)] // Weighted channels stay in 0..=255.
fn composite(image: DynamicImage) -> GrayImage {
    let rgba = image.into_rgba8();
    GrayImage::from_fn(rgba.width(), rgba.height(), |x, y| {
        let [r, g, b, a] = rgba.get_pixel(x, y).0.map(u32::from);
        let luma = (299 * r + 587 * g + 114 * b) / 1000;
        image::Luma([((luma * a + 255 * (255 - a)) / 255) as u8])
    })
}
