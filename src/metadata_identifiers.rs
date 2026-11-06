//! The one place a value read from a file's embedded metadata becomes an entity: the identifiers
//! the indicator classifier ([`crate::classifier`]) finds in it, each attributed to the file and to
//! the field that holds it. The [`crate::exif`] and [`crate::docmeta`] readers call [`identifiers`]
//! on the fields they read, so the `exif` and `docmeta` commands and every path that reads a file
//! through [`crate::embedded_metadata`] report them alike.
//!
//! Each reader says who writes each of its fields ([`Field`]), since each names its own fields:
//! - a field people write (rights, contact, comment, description) yields every actionable kind:
//!   an email address, a link, a domain, an IP address, a phone number;
//! - a field that names someone (an author, creator, owner, editor or person shown) yields those
//!   too, and each name written in it as a person or an organisation, unless it is a placeholder a
//!   program writes for a user it does not know ("Microsoft Office User");
//! - a value a device or a program writes for itself (a serial number, an identifier, a version, a
//!   time, a setting) yields only an email address or a link: digits in it that happen to have the
//!   shape of a phone number, an ABN or an IP address are not one.
//!
//! A file yields at most [`MAX_METADATA_IDENTIFIERS`] such entities per reader, and the reader's
//! document entity says how many more it held. Every value stays, as written, in the reader's
//! document entity either way.

use crate::classifier::{self, Classified};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

/// The tag on every entity found inside a metadata value.
pub const TAG: &str = "embedded-metadata";

/// Most entities one reader takes from one file's metadata values. A real file holds a handful; a
/// file crafted to hold more -- 512 fields of 8 KiB can carry 300,000 addresses -- would otherwise
/// become that many entities, gigabytes on a phone. What a file holds past this is counted, not
/// kept.
pub const MAX_METADATA_IDENTIFIERS: usize = 256;

/// The longest text read as one name.
const MAX_NAME_BYTES: usize = 128;

/// Who writes a metadata field, which decides what its value can yield.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    /// A device or a program writes it for itself: its value yields only an email address or a
    /// link.
    Program,
    /// People write it: its value yields every actionable identifier.
    People,
    /// People write a name in it -- an author, creator, owner, editor or person shown: every
    /// actionable identifier, and each `;`-separated name as a person or an organisation.
    Name,
}

/// Names a program writes when it does not know who its user is, compared ignoring case.
const PLACEHOLDER_NAMES: [&str; 12] = [
    "authorised user",
    "authorized user",
    "default user",
    "licensed user",
    "microsoft office user",
    "office user",
    "preferred customer",
    "registered user",
    "unknown author",
    "unknown user",
    "valued customer",
    "windows user",
];

/// Every identifier the classifier finds in the `fields` the reader `source` read from the file
/// the operator knows as `label`, added to `entities` in that reader's scan `sid`, each with
/// evidence naming the file and the field; `field` says who writes each field. At most
/// [`MAX_METADATA_IDENTIFIERS`] are added; returns how many more were found and not kept.
/// **Pure.**
pub(crate) fn identifiers(
    entities: &mut Vec<Entity>,
    source: &str,
    label: &str,
    sid: &str,
    fields: &[(String, String)],
    field: impl Fn(&str) -> Field,
) -> usize {
    let mut found_in_file = Found {
        entities,
        source,
        label,
        sid,
        kept: 0,
        omitted: 0,
    };
    for (name, value) in fields {
        let writer = field(name);
        for found in classifier::extract(value)
            .into_iter()
            .filter(Classified::is_actionable)
            .filter(|found| {
                writer != Field::Program
                    || matches!(found.kind, EntityKind::Email | EntityKind::Url)
            })
        {
            let summary = format!("{} in the {name} metadata of {label}", found.signal);
            found_in_file.keep(found, name, summary);
        }
        if writer == Field::Name {
            for found in names(value) {
                let summary = format!("named in the {name} metadata of {label}");
                found_in_file.keep(found, name, summary);
            }
        }
    }
    found_in_file.omitted
}

/// The entities one reader is taking from one file, within [`MAX_METADATA_IDENTIFIERS`].
struct Found<'a> {
    entities: &'a mut Vec<Entity>,
    source: &'a str,
    label: &'a str,
    sid: &'a str,
    kept: usize,
    omitted: usize,
}

impl Found<'_> {
    /// Keep `found`, read from the field `name`, unless the bound is reached; count it if so.
    fn keep(&mut self, found: Classified, name: &str, summary: String) {
        if self.kept == MAX_METADATA_IDENTIFIERS {
            self.omitted += 1;
            return;
        }
        self.kept += 1;
        let evidence = Evidence::new(EvidenceProvenance::for_scan(self.source, self.sid), summary)
            .with_attr("source_file", self.label)
            .with_attr("metadata_field", name)
            .with_attr("signal", found.signal);
        self.entities.push(
            Entity::builder(found.kind, found.value, found.confidence, self.sid)
                .tag(self.source)
                .tag(TAG)
                .evidence(evidence)
                .build(),
        );
    }
}

/// The names written in one name field's value: each `;`-separated item made of letters and the
/// punctuation names use, that is not a placeholder and that the classifier reads, whole, as a
/// person or an organisation. A copyright line, a handle, an address or a single word is not one.
/// **Pure.**
fn names(value: &str) -> impl Iterator<Item = Classified> + '_ {
    value
        .split(';')
        .map(str::trim)
        .filter(|item| is_name_text(item) && !is_placeholder(item))
        .map(classifier::classify)
        .filter(|found| {
            matches!(found.kind, EntityKind::Person | EntityKind::Organisation)
                && found.is_actionable()
        })
}

/// Whether `item` is written as a name is: letters, spaces and the punctuation of initials,
/// surnames and company names, within [`MAX_NAME_BYTES`]. **Pure.**
fn is_name_text(item: &str) -> bool {
    !item.is_empty()
        && item.len() <= MAX_NAME_BYTES
        && item.chars().all(|c| {
            c.is_alphabetic() || matches!(c, ' ' | '.' | '\'' | '\u{2019}' | '-' | ',' | '&')
        })
}

/// Whether `item` is one of the [`PLACEHOLDER_NAMES`]. **Pure.**
fn is_placeholder(item: &str) -> bool {
    let lower = item.to_lowercase();
    PLACEHOLDER_NAMES.contains(&lower.as_str())
}
