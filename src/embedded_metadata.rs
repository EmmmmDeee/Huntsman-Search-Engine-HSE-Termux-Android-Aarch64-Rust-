//! One reading of everything a file's embedded metadata says, shared by every path that holds a
//! file: the `exif` and `docmeta` commands, the web UI's inspect view, `investigate --file` and
//! `reverse-image`.
//!
//! [`inspect`] runs the [`crate::exif`] and [`crate::docmeta`] readers over the same bytes and
//! keeps what each finds: the document entity carrying every field as evidence, a GPS position as
//! coordinates, and the identifiers each reader found in the fields people write
//! ([`crate::metadata_identifiers`]): an email address, a link, a domain, an IP address or a phone
//! number written into an author, rights, contact, comment or description field, attributed to the
//! file and to the field that holds it, pivots like any other entity, as does each person or
//! organisation named in a field that names someone. A value a device or a program writes for
//! itself -- a serial number, an identifier, a version, a time -- is read only for an email address
//! or a link. A file yields a bounded number of these, and says how many more it held.
//!
//! Metadata is only read here, never removed or rewritten. A value in which nothing is found stays,
//! as written, in the document entity's evidence.

use crate::docmeta;
use crate::entity::merge_by_uid;
use crate::exif;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

pub use crate::metadata_identifiers::TAG;

/// What one file's embedded metadata says: the entities, and how each reader's pass ended.
pub type Inspected = crate::lookup_report::LookupReport;

/// Everything `bytes`' embedded metadata says, for a file the operator knows as `label`.
///
/// A file the EXIF reader cannot read (not an image it knows) keeps an inconclusive EXIF outcome
/// beside whatever the document reader finds; the document reader reads any file.
///
/// # Errors
/// The document reader's failure to render its report.
pub fn inspect(bytes: &[u8], label: &str, now_unix: u64) -> Result<Inspected, String> {
    let mut inspected = Inspected::default();
    match exif::run(bytes, label, now_unix) {
        SourceRun::Printed { report, .. } => {
            inspected.entities.extend(report.entities);
            inspected.outcomes.extend(report.outcomes);
        }
        SourceRun::Network(why) | SourceRun::Failed(why) => {
            inspected
                .outcomes
                .push(SourceExecutionOutcome::inconclusive(
                    exif::SOURCE,
                    now_unix,
                    why,
                ));
        }
    }
    match docmeta::run(bytes, label, now_unix) {
        SourceRun::Printed { report, .. } => {
            inspected.entities.extend(report.entities);
            inspected.outcomes.extend(report.outcomes);
        }
        SourceRun::Network(why) | SourceRun::Failed(why) => return Err(why),
    }
    merge_by_uid(&mut inspected.entities);
    Ok(inspected)
}

/// Whether either reader finds embedded metadata in `bytes`: a field or a GPS position. **Pure.**
#[must_use]
pub fn carries_metadata(bytes: &[u8]) -> bool {
    let image =
        exif::parse(bytes).is_ok_and(|parsed| !parsed.fields.is_empty() || parsed.gps.is_some());
    let document = docmeta::parse(bytes);
    image || !document.fields.is_empty() || document.gps.is_some()
}

#[cfg(test)]
mod tests;
