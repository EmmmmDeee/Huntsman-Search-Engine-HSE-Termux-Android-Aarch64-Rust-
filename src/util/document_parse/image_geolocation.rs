//! Image geolocation detection: EXIF GPS extraction + metadata analysis.
//!
//! Extracts location information from local image files via:
//! - EXIF GPS coordinates (latitude, longitude, altitude)
//! - EXIF datetime (can correlate with known events/locations)
//! - Camera make/model and authoring software (source analysis)
//!
//! The GPS IFD is decoded through [`crate::util::exif`], the same code path the
//! `exif_geo` scan module uses for remote image URLs, so a coordinate means the
//! same thing however the image reached HSE.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::debug;

use super::DocumentResult;
use crate::core::confidence;

/// Confidence assigned to a coordinate read straight out of the GPS IFD.
///
/// Not `CERTAIN`: consumer GPS is accurate to roughly ±50 m at the point of
/// capture, and EXIF is trivially editable — high trust, never absolute.
const EXIF_GPS_CONFIDENCE: f64 = confidence::VERY_HIGH_PLUSPLUS;

/// Geographic coordinates extracted from image metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeoCoordinates {
    /// Latitude (-90 to 90)
    pub latitude: f64,
    /// Longitude (-180 to 180)
    pub longitude: f64,
    /// Altitude in meters (optional, from EXIF; negative = below sea level)
    pub altitude_m: Option<f64>,
    /// Accuracy estimate in meters (optional)
    pub accuracy_m: Option<u32>,
    /// Source: "exif_gps"
    pub source: String,
    /// Confidence 0.0-1.0
    pub confidence: f64,
}

/// Image metadata relevant to geolocation and source analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageGeolocationMetadata {
    /// GPS coordinates if present
    pub coordinates: Option<GeoCoordinates>,
    /// Capture datetime (EXIF DateTimeOriginal, falling back to DateTime)
    pub datetime: Option<String>,
    /// Camera make and model (e.g., "Apple iPhone 15 Pro")
    pub camera_model: Option<String>,
    /// Image dimensions (width x height)
    pub dimensions: Option<(u32, u32)>,
    /// Software/app used (from EXIF Software tag)
    pub software: Option<String>,
    /// Copyright/attribution (from EXIF Copyright tag)
    pub copyright: Option<String>,
    /// All EXIF tags found (for analysis)
    pub exif_tags: Vec<String>,
    /// Confidence in geolocation result (0.0 when no coordinate was recovered)
    pub geolocation_confidence: f64,
}

impl Default for ImageGeolocationMetadata {
    fn default() -> Self {
        Self {
            coordinates: None,
            datetime: None,
            camera_model: None,
            dimensions: None,
            software: None,
            copyright: None,
            exif_tags: Vec::new(),
            geolocation_confidence: 0.0,
        }
    }
}

/// Extract geolocation and metadata from an image file.
///
/// Errors only when the path itself cannot be read. A file with no EXIF
/// container — a metadata-stripped social upload, a PNG, a screenshot — yields
/// an empty-but-valid record rather than an error: absent metadata is the
/// common case, not a failure.
pub fn extract_image_geolocation<P: AsRef<Path>>(
    image_path: P,
) -> DocumentResult<ImageGeolocationMetadata> {
    let path = image_path.as_ref();

    debug!("Extracting geolocation metadata from: {}", path.display());

    // Dimensions come from the header alone. Fully decoding the pixel buffer
    // just to read width/height would cost hundreds of megabytes on a large
    // panorama or RAW for two integers we already have after the header.
    let mut metadata = ImageGeolocationMetadata {
        dimensions: image::ImageReader::open(path)?.into_dimensions().ok(),
        ..Default::default()
    };

    match crate::util::exif::read_from_path(path) {
        Some(exif) => extract_exif_metadata(&exif, &mut metadata),
        None => debug!("No EXIF container in image: {}", path.display()),
    }

    Ok(metadata)
}

/// Populate `metadata` from a parsed EXIF container.
fn extract_exif_metadata(exif: &exif::Exif, metadata: &mut ImageGeolocationMetadata) {
    use crate::util::exif::read_str;
    use exif::Tag;

    metadata.exif_tags = exif
        .fields()
        .map(|field| format!("{:?}", field.tag))
        .collect();

    // DateTimeOriginal is the shutter moment; DateTime is the file's last
    // edit and only a fallback — preferring it would date a 2015 photo to the
    // day someone cropped it.
    metadata.datetime =
        read_str(exif, Tag::DateTimeOriginal).or_else(|| read_str(exif, Tag::DateTime));

    // Make and Model are separate tags describing one device ("Apple",
    // "iPhone 15 Pro"); joined they read as the device a human would name.
    metadata.camera_model = match (read_str(exif, Tag::Make), read_str(exif, Tag::Model)) {
        (Some(make), Some(model)) => Some(format!("{make} {model}")),
        (make, model) => make.or(model),
    };

    metadata.software = read_str(exif, Tag::Software);
    metadata.copyright = read_str(exif, Tag::Copyright);

    if let Some((latitude, longitude)) = crate::util::exif::extract_gps(exif) {
        let altitude_m = crate::util::exif::extract_altitude(exif);
        debug!(
            latitude,
            longitude,
            altitude_m = altitude_m.unwrap_or(f64::NAN),
            "recovered GPS fix from EXIF"
        );
        metadata.coordinates = Some(GeoCoordinates {
            latitude,
            longitude,
            altitude_m,
            // EXIF has no accuracy field; leave it unset rather than invent a
            // radius the metadata never claimed.
            accuracy_m: None,
            source: "exif_gps".to_string(),
            confidence: EXIF_GPS_CONFIDENCE,
        });
        metadata.geolocation_confidence = EXIF_GPS_CONFIDENCE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exif::{Rational, Value};
    use std::io::Cursor;

    /// Build a minimal TIFF/EXIF container carrying the given fields, then
    /// parse it back — exercising real container reading rather than a
    /// hand-built `Exif` the parser never sees.
    fn exif_with(fields: &[(exif::Tag, Value)]) -> exif::Exif {
        let mut writer = exif::experimental::Writer::new();
        let owned: Vec<exif::Field> = fields
            .iter()
            .map(|(tag, value)| exif::Field {
                tag: *tag,
                ifd_num: exif::In::PRIMARY,
                value: value.clone(),
            })
            .collect();
        for field in &owned {
            writer.push_field(field);
        }
        let mut buf = Cursor::new(Vec::new());
        writer.write(&mut buf, false).expect("write EXIF container");
        exif::Reader::new()
            .read_raw(buf.into_inner())
            .expect("parse EXIF container")
    }

    fn rat(num: u32, denom: u32) -> Rational {
        Rational { num, denom }
    }

    fn dms(d: u32, m: u32, s: u32) -> Value {
        Value::Rational(vec![rat(d, 1), rat(m, 1), rat(s, 1)])
    }

    fn ascii(s: &str) -> Value {
        Value::Ascii(vec![s.as_bytes().to_vec()])
    }

    #[test]
    fn gps_fix_populates_coordinates_and_confidence() {
        // Sydney Opera House: 33°51'25"S, 151°12'55"E
        let exif = exif_with(&[
            (exif::Tag::GPSLatitude, dms(33, 51, 25)),
            (exif::Tag::GPSLatitudeRef, ascii("S")),
            (exif::Tag::GPSLongitude, dms(151, 12, 55)),
            (exif::Tag::GPSLongitudeRef, ascii("E")),
        ]);
        let mut metadata = ImageGeolocationMetadata::default();
        extract_exif_metadata(&exif, &mut metadata);

        let coords = metadata
            .coordinates
            .expect("southern-hemisphere GPS IFD must yield a coordinate");
        assert!(
            (coords.latitude - -33.857).abs() < 0.01,
            "latitude must be negative in the southern hemisphere, got {}",
            coords.latitude
        );
        assert!(
            (coords.longitude - 151.215).abs() < 0.01,
            "got {}",
            coords.longitude
        );
        assert_eq!(coords.source, "exif_gps");
        assert_eq!(metadata.geolocation_confidence, EXIF_GPS_CONFIDENCE);
    }

    #[test]
    fn altitude_below_sea_level_is_negative() {
        let exif = exif_with(&[
            (exif::Tag::GPSLatitude, dms(33, 51, 25)),
            (exif::Tag::GPSLatitudeRef, ascii("S")),
            (exif::Tag::GPSLongitude, dms(151, 12, 55)),
            (exif::Tag::GPSLongitudeRef, ascii("E")),
            (exif::Tag::GPSAltitude, Value::Rational(vec![rat(120, 1)])),
            (exif::Tag::GPSAltitudeRef, Value::Byte(vec![1])),
        ]);
        let mut metadata = ImageGeolocationMetadata::default();
        extract_exif_metadata(&exif, &mut metadata);

        let altitude = metadata
            .coordinates
            .and_then(|c| c.altitude_m)
            .expect("altitude must be recovered");
        assert!((altitude - -120.0).abs() < 1e-9, "got {altitude}");
    }

    #[test]
    fn null_island_coordinates_are_rejected() {
        // A sensor-zeroed image encodes 0/1,0/1,0/1 on both axes. That is not
        // a fix off the coast of Africa — it is missing data, and admitting it
        // would fabricate a location.
        let exif = exif_with(&[
            (exif::Tag::GPSLatitude, dms(0, 0, 0)),
            (exif::Tag::GPSLatitudeRef, ascii("N")),
            (exif::Tag::GPSLongitude, dms(0, 0, 0)),
            (exif::Tag::GPSLongitudeRef, ascii("E")),
        ]);
        let mut metadata = ImageGeolocationMetadata::default();
        extract_exif_metadata(&exif, &mut metadata);

        assert!(metadata.coordinates.is_none());
        assert_eq!(metadata.geolocation_confidence, 0.0);
    }

    #[test]
    fn camera_make_and_model_are_joined() {
        let exif = exif_with(&[
            (exif::Tag::Make, ascii("Apple")),
            (exif::Tag::Model, ascii("iPhone 15 Pro")),
        ]);
        let mut metadata = ImageGeolocationMetadata::default();
        extract_exif_metadata(&exif, &mut metadata);

        assert_eq!(metadata.camera_model.as_deref(), Some("Apple iPhone 15 Pro"));
    }

    #[test]
    fn datetime_original_wins_over_file_datetime() {
        let exif = exif_with(&[
            (exif::Tag::DateTime, ascii("2024:01:01 00:00:00")),
            (exif::Tag::DateTimeOriginal, ascii("2015:06:12 09:30:00")),
        ]);
        let mut metadata = ImageGeolocationMetadata::default();
        extract_exif_metadata(&exif, &mut metadata);

        assert_eq!(
            metadata.datetime.as_deref(),
            Some("2015:06:12 09:30:00"),
            "the shutter moment must win over the last-edit timestamp"
        );
    }

    #[test]
    fn metadata_without_gps_stays_unlocated() {
        let exif = exif_with(&[(exif::Tag::Software, ascii("Adobe Photoshop"))]);
        let mut metadata = ImageGeolocationMetadata::default();
        extract_exif_metadata(&exif, &mut metadata);

        assert_eq!(metadata.software.as_deref(), Some("Adobe Photoshop"));
        assert!(metadata.coordinates.is_none());
        assert_eq!(metadata.geolocation_confidence, 0.0);
        assert!(!metadata.exif_tags.is_empty());
    }

    #[test]
    fn extract_geolocation_nonexistent_image() {
        assert!(extract_image_geolocation("/nonexistent/image.jpg").is_err());
    }

    /// Wrap a TIFF/EXIF blob in a JPEG APP1 segment and splice it in directly
    /// after the SOI marker — the layout every camera writes.
    fn jpeg_with_exif(fields: &[(exif::Tag, Value)]) -> Vec<u8> {
        let mut writer = exif::experimental::Writer::new();
        let owned: Vec<exif::Field> = fields
            .iter()
            .map(|(tag, value)| exif::Field {
                tag: *tag,
                ifd_num: exif::In::PRIMARY,
                value: value.clone(),
            })
            .collect();
        for field in &owned {
            writer.push_field(field);
        }
        let mut tiff = Cursor::new(Vec::new());
        writer.write(&mut tiff, false).expect("write TIFF");
        let tiff = tiff.into_inner();

        let image = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
            16,
            12,
            image::Rgb([90, 140, 200]),
        ));
        let mut jpeg = Cursor::new(Vec::new());
        image
            .write_to(&mut jpeg, image::ImageFormat::Jpeg)
            .expect("encode JPEG");
        let jpeg = jpeg.into_inner();

        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(&tiff);

        let mut out = Vec::with_capacity(jpeg.len() + payload.len() + 4);
        out.extend_from_slice(&jpeg[..2]); // SOI
        out.extend_from_slice(&[0xFF, 0xE1]); // APP1
        out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&jpeg[2..]);
        out
    }

    #[test]
    fn end_to_end_reads_gps_from_a_real_jpeg_on_disk() {
        // The whole feature, through the same entry point the `hse ingest`
        // command calls: a JPEG file on disk carrying a GPS IFD must come back
        // with dimensions from the header and a located, confident coordinate.
        let bytes = jpeg_with_exif(&[
            (exif::Tag::Make, ascii("Canon")),
            (exif::Tag::Model, ascii("EOS R5")),
            (exif::Tag::GPSLatitude, dms(27, 28, 35)),
            (exif::Tag::GPSLatitudeRef, ascii("S")),
            (exif::Tag::GPSLongitude, dms(153, 0, 59)),
            (exif::Tag::GPSLongitudeRef, ascii("E")),
        ]);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("photo.jpg");
        std::fs::write(&path, &bytes).expect("write fixture");

        let metadata = extract_image_geolocation(&path).expect("ingest must read the file");

        assert_eq!(metadata.dimensions, Some((16, 12)));
        assert_eq!(metadata.camera_model.as_deref(), Some("Canon EOS R5"));

        let coords = metadata
            .coordinates
            .expect("a JPEG with a GPS IFD must yield coordinates");
        // Brisbane: S 27°28'35", E 153°0'59".
        assert!((coords.latitude - -27.476).abs() < 0.01, "{}", coords.latitude);
        assert!((coords.longitude - 153.016).abs() < 0.01, "{}", coords.longitude);
        assert_eq!(metadata.geolocation_confidence, EXIF_GPS_CONFIDENCE);
    }

    #[test]
    fn end_to_end_image_without_exif_is_not_an_error() {
        // A plain re-encoded upload (the common case after social platforms
        // strip metadata) must ingest cleanly, just without a location.
        let image = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
            20,
            10,
            image::Rgb([10, 20, 30]),
        ));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stripped.png");
        image.save(&path).expect("write png");

        let metadata = extract_image_geolocation(&path).expect("stripped image must still ingest");
        assert_eq!(metadata.dimensions, Some((20, 10)));
        assert!(metadata.coordinates.is_none());
        assert_eq!(metadata.geolocation_confidence, 0.0);
    }
}
