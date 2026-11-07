//! Consolidated sanctions lists, read offline from copies kept on the device: the US Treasury
//! OFAC Specially Designated Nationals list (with its alias table), the UN Security Council
//! Consolidated List and the EU Financial Sanctions consolidated list.
//!
//! Each list is one keyless public download, kept in the list directory and downloaded again
//! once a day through the same download-and-keep machinery as the threat feeds
//! ([`crate::threat_feeds::load`]); a name is then matched locally, so a lookup sends nothing
//! about who is being looked up. A listing matches only when its name or one of its aliases
//! carries every word of the name asked. A match is a lead to review, never proof that the
//! person is the one designated: each is a `Document` keyed by the listing's own address, its
//! whole listing kept verbatim as evidence (remarks, dates of birth, nationality, programmes) so
//! it can be compared with what else is known.

use std::path::{Path, PathBuf};

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::http::Transport;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::threat_feeds::{CachedList, csv_fields, delimited_fields, load};

/// The module that selects every sanctions list.
pub const SOURCE: &str = "sanctions";
/// The OFAC Specially Designated Nationals list's outcome label.
pub const OFAC: &str = "sanctions.ofac_sdn";
/// The UN Security Council Consolidated List's outcome label.
pub const UN: &str = "sanctions.un_sc";
/// The EU Financial Sanctions consolidated list's outcome label.
pub const EU: &str = "sanctions.eu_fsf";

/// A name match on a sanctions list: a strong lead, below a confirmed identity.
const LISTED_CONFIDENCE: f64 = 0.6;
/// The lists are published at least daily.
const MAX_AGE: u64 = 24 * 3_600;
/// The most matches one list reports for one name.
const MAX_MATCHES: usize = 50;

const OFAC_SDN: CachedList = CachedList {
    id: "sanctions-ofac-sdn.csv",
    source: OFAC,
    url: "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV",
    max_age: MAX_AGE,
    xml_root: None,
};
const OFAC_ALT: CachedList = CachedList {
    id: "sanctions-ofac-alt.csv",
    source: OFAC,
    url: "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ALT.CSV",
    max_age: MAX_AGE,
    xml_root: None,
};
/// The EU's consolidated list: one `;`-separated row per name, address, birth date, document and
/// citizenship of each subject, about 25 MB. Its token is a fixed public value, not a credential.
const EU_FSF: CachedList = CachedList {
    id: "sanctions-eu-fsf.csv",
    source: EU,
    url: "https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw",
    max_age: MAX_AGE,
    xml_root: None,
};
const UN_SC: CachedList = CachedList {
    id: "sanctions-un-consolidated.xml",
    source: UN,
    url: "https://scsanctions.un.org/resources/xml/en/consolidated.xml",
    max_age: MAX_AGE,
    xml_root: Some("CONSOLIDATED_LIST"),
};

/// Where the lists come from and where their copies are kept: a transport able to carry the
/// largest list, and the directory the copies live in. [`Lists::none`] consults no list.
pub struct Lists {
    transport: Option<Box<dyn Transport + Send + Sync>>,
    dir: Option<PathBuf>,
}

impl Lists {
    /// No list is consulted.
    #[must_use]
    pub fn none() -> Self {
        Self {
            transport: None,
            dir: None,
        }
    }

    /// The lists, downloaded over `transport` (it must carry a body of several MiB: see
    /// [`crate::threat_feeds::transport_config`]) and kept in `dir` (none keeps no copy).
    #[must_use]
    pub fn new(transport: Box<dyn Transport + Send + Sync>, dir: Option<PathBuf>) -> Self {
        Self {
            transport: Some(transport),
            dir,
        }
    }
}

/// One listing: its key, the names it is known by, and every field kept for the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listing {
    /// The listing's own address, the entity's value.
    url: String,
    /// The primary name, then every alias.
    names: Vec<String>,
    /// Every field the list holds for it, verbatim, in list order.
    fields: Vec<(&'static str, String)>,
}

/// Whether `listed` carries every word of `query`. **Pure.**
fn names_query(listed: &str, query: &[String]) -> bool {
    let have = crate::textnorm::name_tokens(listed);
    query.iter().all(|word| have.contains(word))
}

/// Match `name` against every consulted list: the listings that carry it, and one outcome per
/// list. A list that cannot be downloaded and has no kept copy is reported as such, never as a
/// clean zero.
#[must_use]
pub fn check(
    lists: &Lists,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> (Vec<Entity>, Vec<SourceExecutionOutcome>) {
    let Some(transport) = lists.transport.as_deref() else {
        return (Vec::new(), Vec::new());
    };
    if !transport.runs_module(SOURCE) {
        return (Vec::new(), Vec::new());
    }
    let query = crate::textnorm::name_tokens(name);
    if query.len() < 2 {
        return (Vec::new(), Vec::new());
    }
    let dir = lists.dir.as_deref();
    let mut entities = Vec::new();
    let mut outcomes = Vec::new();
    for (label, read) in [
        (OFAC, read_ofac(transport, dir, now_unix)),
        (UN, read_un(transport, dir, now_unix)),
        (EU, read_eu(transport, dir, now_unix)),
    ] {
        outcomes.push(match read {
            Ok((listings, note)) => {
                let found = record_matches(&listings, &query, label, scan_id, &mut entities);
                let mut outcome = if found == 0 {
                    SourceExecutionOutcome::valid_zero(label, now_unix)
                } else {
                    SourceExecutionOutcome::success(label, now_unix, found)
                };
                let mut detail = format!("{} listings read", listings.len());
                if let Some(note) = note {
                    detail.push_str("; ");
                    detail.push_str(&note);
                }
                outcome = outcome.with_detail(detail);
                outcome
            }
            Err((kind, why)) => SourceExecutionOutcome::failed(label, now_unix, kind, None, why),
        });
    }
    merge_by_uid(&mut entities);
    (entities, outcomes)
}

/// Push every listing in `listings` that names `query`, at most [`MAX_MATCHES`]. **Pure.**
fn record_matches(
    listings: &[Listing],
    query: &[String],
    label: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) -> usize {
    let mut found = 0;
    for listing in listings {
        let Some(matched) = listing
            .names
            .iter()
            .find(|listed| names_query(listed, query))
        else {
            continue;
        };
        if found == MAX_MATCHES {
            break;
        }
        found += 1;
        let primary = listing.names.first().map_or("", String::as_str);
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(label, scan_id),
            format!(
                "Listed on {} as {primary}; the name asked matches {matched}. A name match, not proof it is the same person: compare the dates of birth, nationality and remarks kept here",
                list_title(label)
            ),
        )
        .with_attr("dataset", list_title(label))
        .with_attr("matched_name", matched.as_str());
        for alias in listing.names.iter().skip(1) {
            evidence = evidence.with_attr("alias", alias.as_str());
        }
        for (key, value) in &listing.fields {
            evidence = evidence.with_attr(*key, value.as_str());
        }
        push_entity(
            entities,
            EntityKind::Document,
            &listing.url,
            LISTED_CONFIDENCE,
            scan_id,
            evidence,
            &["sanctions", "name-match-lead"],
        );
    }
    found
}

const fn list_title(label: &str) -> &'static str {
    match label.as_bytes() {
        b"sanctions.ofac_sdn" => "OFAC Specially Designated Nationals list",
        b"sanctions.eu_fsf" => "EU Financial Sanctions consolidated list",
        _ => "UN Security Council Consolidated List",
    }
}

/// A list's copy (kept or downloaded) and what its outcome should say about the copy.
fn copy_of(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    list: &CachedList,
    now_unix: u64,
) -> Result<(String, Option<String>), crate::threat_feeds::Failure> {
    let copy = load(transport, dir, list, now_unix)?;
    let age = now_unix.saturating_sub(copy.fetched);
    let mut note = format!(
        "copy {} ({}s old)",
        if copy.downloaded {
            "downloaded now"
        } else {
            "kept"
        },
        age
    );
    if let Some(extra) = copy.note {
        note.push_str("; ");
        note.push_str(&extra);
    }
    Ok((String::from_utf8_lossy(&copy.body).into_owned(), Some(note)))
}

/// OFAC's SDN rows joined with their aliases.
fn read_ofac(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    now_unix: u64,
) -> Result<(Vec<Listing>, Option<String>), crate::threat_feeds::Failure> {
    let (sdn, note) = copy_of(transport, dir, &OFAC_SDN, now_unix)?;
    // The alias table enriches the names; a list read without it still answers for primary names.
    let (alt, alt_note) = match copy_of(transport, dir, &OFAC_ALT, now_unix) {
        Ok((alt, _)) => (alt, None),
        Err((_, why)) => (String::new(), Some(format!("aliases unavailable ({why})"))),
    };
    let listings = parse_ofac(&sdn, &alt);
    if listings.is_empty() {
        return Err((
            SourceOutcomeKind::ProtocolDrift,
            format!("no SDN row could be read in {} bytes", sdn.len()),
        ));
    }
    let note = [note, alt_note]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
    Ok((listings, Some(note)))
}

/// The UN list's individuals and entities.
fn read_un(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    now_unix: u64,
) -> Result<(Vec<Listing>, Option<String>), crate::threat_feeds::Failure> {
    let (xml, note) = copy_of(transport, dir, &UN_SC, now_unix)?;
    let listings = parse_un(&xml);
    if listings.is_empty() {
        return Err((
            SourceOutcomeKind::ProtocolDrift,
            format!("no listing could be read in {} bytes", xml.len()),
        ));
    }
    Ok((listings, note))
}

/// The EU list's subjects.
fn read_eu(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    now_unix: u64,
) -> Result<(Vec<Listing>, Option<String>), crate::threat_feeds::Failure> {
    let (csv, note) = copy_of(transport, dir, &EU_FSF, now_unix)?;
    let listings = parse_eu(&csv);
    if listings.is_empty() {
        return Err((
            SourceOutcomeKind::ProtocolDrift,
            format!("no subject could be read in {} bytes", csv.len()),
        ));
    }
    Ok((listings, note))
}

/// The EU list's columns kept for the evidence, by header name, and the attribute each becomes.
const EU_FIELDS: [(&str, &str); 16] = [
    ("Entity_EU_ReferenceNumber", "reference_number"),
    ("Entity_SubjectType", "subject_type"),
    ("Entity_Remark", "remarks"),
    ("Entity_Regulation_Programme", "program"),
    ("Entity_Regulation_NumberTitle", "regulation"),
    ("Entity_Regulation_PublicationDate", "listed_on"),
    ("Entity_Regulation_PublicationUrl", "regulation_url"),
    ("NameAlias_Function", "function"),
    ("NameAlias_Title", "title"),
    ("NameAlias_Gender", "gender"),
    ("BirthDate_BirthDate", "date_of_birth"),
    ("BirthDate_Year", "birth_year"),
    ("BirthDate_City", "place_of_birth"),
    ("BirthDate_CountryDescription", "country_of_birth"),
    ("Citizenship_CountryDescription", "nationality"),
    ("Identification_Remark", "identification"),
];

/// Every subject on the EU list. The file holds one row per combination of a subject's names,
/// addresses, birth dates, documents and citizenships, so rows are grouped by
/// `Entity_LogicalId` and each value is kept once, in file order. **Pure.**
fn parse_eu(csv: &str) -> Vec<Listing> {
    let mut lines = csv.trim_start_matches('\u{feff}').lines();
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let header = delimited_fields(header, ';');
    let column = |name: &str| header.iter().position(|h| h == name);
    let (Some(id_at), Some(whole_at)) = (column("Entity_LogicalId"), column("NameAlias_WholeName"))
    else {
        return Vec::new();
    };
    let parts_at = [
        column("NameAlias_FirstName"),
        column("NameAlias_MiddleName"),
        column("NameAlias_LastName"),
    ];
    let kept: Vec<(usize, &'static str)> = EU_FIELDS
        .iter()
        .filter_map(|(name, key)| column(name).map(|at| (at, *key)))
        .collect();
    let mut order: Vec<String> = Vec::new();
    let mut subjects: std::collections::HashMap<String, Listing> = std::collections::HashMap::new();
    for line in lines {
        let fields = delimited_fields(line.trim_end_matches('\r'), ';');
        if fields.len() != header.len() {
            continue;
        }
        let id = fields[id_at].trim();
        if id.is_empty() {
            continue;
        }
        let listing = subjects.entry(id.to_owned()).or_insert_with(|| {
            order.push(id.to_owned());
            Listing {
                url: String::new(),
                names: Vec::new(),
                fields: vec![("eu_logical_id", id.to_owned())],
            }
        });
        let whole = fields[whole_at].trim();
        let name = if whole.is_empty() {
            parts_at
                .iter()
                .filter_map(|at| at.map(|at| fields[at].trim()))
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            whole.to_owned()
        };
        if !name.is_empty() && !listing.names.contains(&name) {
            listing.names.push(name);
        }
        for (at, key) in &kept {
            let value = fields[*at].trim();
            if !value.is_empty() && !listing.fields.iter().any(|(k, v)| k == key && v == value) {
                listing.fields.push((key, value.to_owned()));
            }
        }
    }
    order
        .into_iter()
        .filter_map(|id| subjects.remove(&id))
        .filter(|listing| !listing.names.is_empty())
        .map(|mut listing| {
            let reference = listing
                .fields
                .iter()
                .find(|(k, _)| *k == "reference_number")
                .map_or_else(
                    || {
                        listing
                            .fields
                            .first()
                            .map_or_else(String::new, |(_, id)| format!("id-{id}"))
                    },
                    |(_, r)| r.clone(),
                );
            listing.url = format!("https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/content#{reference}");
            listing
        })
        .collect()
}

/// OFAC's "no value" marker.
fn ofac_value(field: &str) -> Option<String> {
    let value = field.trim();
    (!value.is_empty() && value != "-0-").then(|| value.to_owned())
}

/// Every SDN row (`ent_num, name, type, program, title, call sign, vessel type, tonnage, GRT,
/// vessel flag, vessel owner, remarks`) with the aliases `ALT.CSV` lists under its number. A
/// line that is not a full row (the file's trailing end-of-file byte) is skipped. **Pure.**
fn parse_ofac(sdn: &str, alt: &str) -> Vec<Listing> {
    let mut aliases: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for line in alt.lines() {
        let fields = csv_fields(line.trim_end_matches('\r'));
        if let (Some(number), Some(name)) = (
            fields.first().and_then(|f| ofac_value(f)),
            fields.get(3).and_then(|f| ofac_value(f)),
        ) {
            aliases.entry(number).or_default().push(name);
        }
    }
    const COLUMNS: [&str; 12] = [
        "ent_num",
        "sdn_name",
        "sdn_type",
        "program",
        "title",
        "call_sign",
        "vessel_type",
        "tonnage",
        "grt",
        "vessel_flag",
        "vessel_owner",
        "remarks",
    ];
    let mut listings = Vec::new();
    for line in sdn.lines() {
        let fields = csv_fields(line.trim_end_matches('\r'));
        if fields.len() < COLUMNS.len() {
            continue;
        }
        let (Some(number), Some(name)) = (ofac_value(&fields[0]), ofac_value(&fields[1])) else {
            continue;
        };
        if !number.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let mut names = vec![name];
        names.extend(aliases.remove(&number).unwrap_or_default());
        let kept = COLUMNS
            .iter()
            .zip(&fields)
            .filter_map(|(key, field)| ofac_value(field).map(|value| (*key, value)))
            .collect();
        listings.push(Listing {
            url: format!("https://sanctionssearch.ofac.treas.gov/Details.aspx?id={number}"),
            names,
            fields: kept,
        });
    }
    listings
}

/// The text of every `<tag>…</tag>` in `block`, unescaped, in order. **Pure.**
fn tag_values(block: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut values = Vec::new();
    let mut rest = block;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        let value = unescape(after[..end].trim());
        if !value.is_empty() {
            values.push(value);
        }
        rest = &after[end + close.len()..];
    }
    values
}

/// XML's five named entities and decimal or hexadecimal character references. **Pure.**
fn unescape(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(end) = tail.find(';').filter(|end| *end <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                .and_then(char::from_u32),
        };
        if let Some(c) = decoded {
            out.push(c);
            rest = &tail[end + 1..];
        } else {
            out.push('&');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

/// The `<element>…</element>` blocks of `xml`, in order. **Pure.**
fn blocks<'a>(xml: &'a str, element: &str) -> Vec<&'a str> {
    let open = format!("<{element}>");
    let close = format!("</{element}>");
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        found.push(&after[..end]);
        rest = &after[end + close.len()..];
    }
    found
}

/// Every individual and entity on the UN list: the name parts joined, every alias, and every
/// field kept for the evidence. **Pure.**
fn parse_un(xml: &str) -> Vec<Listing> {
    let mut listings = Vec::new();
    for (element, kind) in [("INDIVIDUAL", "individual"), ("ENTITY", "entity")] {
        for block in blocks(xml, element) {
            let parts: Vec<String> = ["FIRST_NAME", "SECOND_NAME", "THIRD_NAME", "FOURTH_NAME"]
                .iter()
                .filter_map(|tag| tag_values(block, tag).into_iter().next())
                .collect();
            let Some(reference) = tag_values(block, "REFERENCE_NUMBER").into_iter().next() else {
                continue;
            };
            if parts.is_empty() {
                continue;
            }
            let mut names = vec![parts.join(" ")];
            names.extend(tag_values(block, "ALIAS_NAME"));
            names.extend(tag_values(block, "NAME_ORIGINAL_SCRIPT"));
            let mut fields: Vec<(&'static str, String)> = vec![
                ("listing_type", kind.to_owned()),
                ("reference_number", reference.clone()),
            ];
            for (key, tag) in [
                ("un_list_type", "UN_LIST_TYPE"),
                ("listed_on", "LISTED_ON"),
                ("gender", "GENDER"),
                ("comments", "COMMENTS1"),
                ("interpol_link", "INTERPOL_LINK"),
            ] {
                for value in tag_values(block, tag) {
                    fields.push((key, value));
                }
            }
            for (key, container) in [
                ("nationality", "NATIONALITY"),
                ("designation", "DESIGNATION"),
                ("title", "TITLE"),
            ] {
                for inner in blocks(block, container) {
                    for value in tag_values(inner, "VALUE") {
                        fields.push((key, value));
                    }
                }
            }
            for birth in blocks(block, "INDIVIDUAL_DATE_OF_BIRTH") {
                for tag in ["DATE", "YEAR", "FROM_YEAR", "TO_YEAR"] {
                    for value in tag_values(birth, tag) {
                        fields.push(("date_of_birth", value));
                    }
                }
            }
            for place in blocks(block, "INDIVIDUAL_PLACE_OF_BIRTH") {
                for tag in ["CITY", "STATE_PROVINCE", "COUNTRY"] {
                    for value in tag_values(place, tag) {
                        fields.push(("place_of_birth", value));
                    }
                }
            }
            listings.push(Listing {
                url: format!("{}#{reference}", UN_SC.url),
                names,
                fields,
            });
        }
    }
    listings
}

#[cfg(test)]
mod tests;
