//! EXIF parsing for this module.
//!
//! The implementation lives in [`crate::util::exif`] so that this module and
//! `util::document_parse::image_geolocation` (the `hse ingest` path) read the
//! GPS IFD through exactly one code path — sign handling, Null-Island
//! rejection, and null-trimming cannot drift between remote-URL and local-file
//! geolocation. Re-exported here so call sites and tests keep naming
//! `parse::{...}`.

pub(super) use crate::util::exif::{
    extract_altitude, extract_gps, extract_img_direction, extract_positioning_error, read_str,
};

#[cfg(test)]
pub(super) use crate::util::exif::dms_to_decimal;
