//! The one place a value read from a file's embedded metadata becomes an entity: the identifiers
//! the indicator classifier ([`crate::classifier`]) finds in it, each attributed to the file and to
//! the field that holds it. The [`crate::exif`] and [`crate::docmeta`] readers call [`identifiers`]
//! on the fields they read, so the `exif` and `docmeta` commands and every path that reads a file
//! through [`crate::embedded_metadata`] report them alike.
//!
//! Each reader says which of its fields people write, since each names its own fields: an author,
//! rights, contact, comment or description field yields every actionable kind (an email address, a
//! link, a domain, an IP address, a phone number). A value a device or a program writes for itself
//! -- a serial number, an identifier, a version, a time, a setting -- yields only an email address
//! or a link: digits in it that happen to have the shape of a phone number, an ABN or an IP address
//! are not one. Every value stays, as written, in the reader's document entity either way.

use crate::classifier::{self, Classified};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

/// The tag on every entity found inside a metadata value.
pub const TAG: &str = "embedded-metadata";

/// Every identifier the classifier finds in the `fields` the reader `source` read from the file
/// the operator knows as `label`, added to `entities` in that reader's scan `sid`, each with
/// evidence naming the file and the field. A field `written_by_people` accepts yields every
/// actionable kind; any other field yields only an email address or a link. **Pure.**
pub(crate) fn identifiers(
    entities: &mut Vec<Entity>,
    source: &str,
    label: &str,
    sid: &str,
    fields: &[(String, String)],
    written_by_people: impl Fn(&str) -> bool,
) {
    for (field, value) in fields {
        let by_people = written_by_people(field);
        for found in classifier::extract(value)
            .into_iter()
            .filter(Classified::is_actionable)
            .filter(|found| by_people || matches!(found.kind, EntityKind::Email | EntityKind::Url))
        {
            let evidence = Evidence::new(
                EvidenceProvenance::for_scan(source, sid),
                format!("{} in the {field} metadata of {label}", found.signal),
            )
            .with_attr("source_file", label)
            .with_attr("metadata_field", field.as_str())
            .with_attr("signal", found.signal);
            entities.push(
                Entity::builder(found.kind, found.value, found.confidence, sid)
                    .tag(source)
                    .tag(TAG)
                    .evidence(evidence)
                    .build(),
            );
        }
    }
}
