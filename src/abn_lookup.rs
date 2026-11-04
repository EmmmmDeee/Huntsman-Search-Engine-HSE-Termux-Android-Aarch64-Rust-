//! ABN Lookup: the Australian Business Register's authoritative record for one ABN or ACN, through
//! the ABR's JSON web service (free GUID, registered at abr.business.gov.au/Tools/WebServices).
//!
//! One lookup is one `GET https://abr.business.gov.au/json/AbnDetails.aspx?abn={abn}` (or
//! `AcnDetails.aspx?acn={acn}`) with the operator's GUID in the `guid` query parameter, added only
//! as the request is sent. It runs only when `HUNTSMAN_ABR_GUID` is set. The service answers in
//! JSONP; the `callback(...)` wrapper is removed before decoding.
//!
//! The service answers an unrecognised GUID with HTTP 200 and a `Message` naming the GUID, so that
//! answer is a rejected key, never a missing record. Any other answer without a record is
//! inconclusive: the record must name exactly the ABN or ACN that was asked before it is evidence.
//! The record keeps the entity name, type, ABN status and effective date, GST registration, the
//! registered state and postcode, and every business name the entity trades under. ABR is a
//! verified registry source, so its evidence carries `registry: ABR` lineage.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::api_leg::{self, Api, KeyPlace, KeyUse, LegError};
use crate::au_id::{is_valid_abn, is_valid_acn};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::http::Transport;
use crate::keys::Keys;
use crate::textnorm::nonblank;

pub const SOURCE: &str = "abn_lookup";
pub const KEY_SLOT: &str = crate::environment::ABR_GUID_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "abr.business.gov.au",
    origin: "https://abr.business.gov.au:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("guid"),
        required: true,
    }),
};
const BASE: &str = "https://abr.business.gov.au/json";

const CONF_ORG: f64 = 0.85;
const CONF_ID: f64 = 0.85;
const CONF_NAME: f64 = 0.75;

/// The identifier one lookup asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Id<'a> {
    Abn(&'a str),
    Acn(&'a str),
}

/// One ABR record.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Record {
    #[serde(default)]
    pub abn: String,
    #[serde(default)]
    pub abn_status: Option<String>,
    #[serde(default)]
    pub abn_status_effective_from: Option<String>,
    #[serde(default)]
    pub acn: Option<String>,
    #[serde(default)]
    pub address_date: Option<String>,
    #[serde(default)]
    pub address_postcode: Option<String>,
    #[serde(default)]
    pub address_state: Option<String>,
    #[serde(default)]
    pub business_name: Vec<String>,
    #[serde(default)]
    pub entity_name: Option<String>,
    #[serde(default)]
    pub entity_type_code: Option<String>,
    #[serde(default)]
    pub entity_type_name: Option<String>,
    #[serde(default)]
    pub gst: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// The request URL for `id`, without the GUID. `None` for a number that fails its checksum.
/// **Pure.**
#[must_use]
pub fn url(id: Id<'_>) -> Option<String> {
    match id {
        Id::Abn(abn) if is_valid_abn(abn) => Some(format!("{BASE}/AbnDetails.aspx?abn={abn}")),
        Id::Acn(acn) if is_valid_acn(acn) => Some(format!("{BASE}/AcnDetails.aspx?acn={acn}")),
        _ => None,
    }
}

/// Look up `id` on the ABR with the GUID in `keys`.
///
/// # Errors
/// [`LegError::MissingKey`] before any request when no GUID is configured; otherwise the
/// [`LegError`] that stopped the lookup, [`LegError::Unauthorized`] for an unrecognised GUID.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    id: Id<'_>,
    now_unix: u64,
) -> Result<Record, LegError> {
    let url = url(id).ok_or_else(|| LegError::Refused("not a valid ABN or ACN".into()))?;
    let body = api_leg::get(transport, &API, keys, &url, now_unix)?.body_or_unexpected()?;
    decode(&body, id)
}

/// Remove a JSONP `name(...)` wrapper, if present. **Pure.**
fn unwrap_jsonp(body: &[u8]) -> &[u8] {
    let trimmed = body.trim_ascii();
    let (Some(open), Some(&b')')) = (
        trimmed.iter().position(|&b| b == b'('),
        trimmed
            .iter()
            .rev()
            .find(|b| !b.is_ascii_whitespace() && **b != b';'),
    ) else {
        return trimmed;
    };
    let name = &trimmed[..open];
    if name.is_empty() || !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') {
        return trimmed;
    }
    let close = trimmed
        .iter()
        .rposition(|&b| b == b')')
        .unwrap_or(trimmed.len());
    &trimmed[open + 1..close]
}

/// One ABR answer body for `id`. **Pure.**
///
/// # Errors
/// [`LegError::Unauthorized`] when the ABR does not recognise the GUID; [`LegError::Decode`] for
/// a body that is not the documented shape, carries no record, or is about another number.
pub fn decode(body: &[u8], id: Id<'_>) -> Result<Record, LegError> {
    let record: Record = api_leg::decode(unwrap_jsonp(body))?;
    if record.abn.trim().is_empty() {
        let message = nonblank(record.message.as_deref()).unwrap_or("no record and no message");
        if message.to_ascii_lowercase().contains("guid") {
            return Err(LegError::Unauthorized);
        }
        return Err(LegError::Decode(format!(
            "ABR returned no record: {message}"
        )));
    }
    let _bound = match id {
        Id::Abn(abn) => api_leg::bound_to_query(Some(record.abn.as_str()), "Abn", |got| {
            crate::textnorm::ascii_digits(got) == abn
        })?,
        Id::Acn(acn) => api_leg::bound_to_query(record.acn.as_deref(), "Acn", |got| {
            crate::textnorm::ascii_digits(got) == acn
        })?,
    };
    Ok(record)
}

/// The record's entities: the registered entity, its ABN and ACN pivots, every business name it
/// trades under, and its registered state and postcode. **Pure.**
#[must_use]
pub fn entities(record: &Record, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let abn = crate::textnorm::ascii_digits(&record.abn);
    let name = nonblank(record.entity_name.as_deref())
        .unwrap_or(abn.as_str())
        .to_owned();
    let provenance = || EvidenceProvenance::for_scan(SOURCE, scan_id);
    let ev = Evidence::new(provenance(), format!("ABR record for ABN {abn}: {name}"))
        .with_attr("registry", "ABR")
        .with_attr("dataset", "Australian Business Register")
        .with_attr("abn", &abn)
        .with_optional_attrs([
            ("acn", nonblank(record.acn.as_deref())),
            ("abn_status", nonblank(record.abn_status.as_deref())),
            (
                "abn_status_effective_from",
                nonblank(record.abn_status_effective_from.as_deref()),
            ),
            (
                "entity_type_code",
                nonblank(record.entity_type_code.as_deref()),
            ),
            ("entity_type", nonblank(record.entity_type_name.as_deref())),
            ("gst_registered_from", nonblank(record.gst.as_deref())),
            ("address_state", nonblank(record.address_state.as_deref())),
            (
                "address_postcode",
                nonblank(record.address_postcode.as_deref()),
            ),
            ("address_date", nonblank(record.address_date.as_deref())),
        ]);
    let mut org = Entity::new(EntityKind::Organisation, &name, CONF_ORG, scan_id);
    org.tag("au");
    org.tag("abr");
    if record
        .abn_status
        .as_deref()
        .is_some_and(|status| status.eq_ignore_ascii_case("cancelled"))
    {
        org.tag("abn-cancelled");
    }
    org.add_evidence(ev.clone());
    out.push(org);

    for id in [
        Some(abn.clone()),
        record.acn.as_deref().map(crate::textnorm::ascii_digits),
    ]
    .into_iter()
    .flatten()
    .filter(|id| is_valid_abn(id) || is_valid_acn(id))
    {
        let mut e = Entity::new(EntityKind::AbnAcn, &id, CONF_ID, scan_id);
        e.tag("au");
        e.tag("abr");
        e.add_evidence(ev.clone());
        out.push(e);
    }

    for business in record
        .business_name
        .iter()
        .filter_map(|n| nonblank(Some(n)))
    {
        let mut bn = Entity::new(EntityKind::Organisation, business, CONF_NAME, scan_id);
        bn.tag("au");
        bn.tag("abr");
        bn.tag("abr-business-name");
        bn.add_evidence(
            Evidence::new(
                provenance(),
                format!("Business name of ABN {abn} on the ABR"),
            )
            .with_attr("registry", "ABR")
            .with_attr("holder_abn", &abn)
            .with_attr("holder", &name),
        );
        out.push(bn);
    }

    let mut columns = Map::new();
    for (key, value) in [
        ("AddressState", record.address_state.as_deref()),
        ("AddressPostcode", record.address_postcode.as_deref()),
    ] {
        if let Some(value) = nonblank(value) {
            columns.insert(key.to_owned(), Value::String(value.to_owned()));
        }
    }
    crate::asic_persons::push_address(
        &columns,
        "AddressLocality",
        "AddressState",
        "AddressPostcode",
        &name,
        "abr",
        scan_id,
        &mut out,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABR's answer to an unrecognised GUID, captured live on 2026-11-04.
    const BAD_GUID: &str = r#"callback({"Abn":"","AbnStatus":"","AbnStatusEffectiveFrom":"","Acn":"","AddressDate":null,"AddressPostcode":"","AddressState":"","BusinessName":[],"EntityName":"","EntityTypeCode":"","EntityTypeName":"","Gst":null,"Message":"The GUID entered is not recognised as a Registered Party"})"#;
    /// A record in the documented shape for a real ABN.
    const RECORD: &str = r#"callback({"Abn":"31163147680","AbnStatus":"Active","AbnStatusEffectiveFrom":"2013-04-15","Acn":"163147680","AddressDate":"2019-02-05","AddressPostcode":"3000","AddressState":"VIC","BusinessName":["KordaMentha Advisory"],"EntityName":"KORDAMENTHA ADVISORY PTY LTD","EntityTypeCode":"PRV","EntityTypeName":"Australian Private Company","Gst":"2013-04-15","Message":""})"#;

    #[test]
    fn urls_need_a_checksummed_number_and_never_hold_the_guid() {
        assert_eq!(
            url(Id::Abn("31163147680")).as_deref(),
            Some("https://abr.business.gov.au/json/AbnDetails.aspx?abn=31163147680")
        );
        assert_eq!(
            url(Id::Acn("163147680")).as_deref(),
            Some("https://abr.business.gov.au/json/AcnDetails.aspx?acn=163147680")
        );
        assert_eq!(url(Id::Abn("31163147681")), None);
        assert!(!url(Id::Abn("31163147680")).unwrap().contains("guid"));
    }

    #[test]
    fn an_unrecognised_guid_is_a_rejected_key_not_a_missing_record() {
        assert!(matches!(
            decode(BAD_GUID.as_bytes(), Id::Abn("31163147680")),
            Err(LegError::Unauthorized)
        ));
    }

    #[test]
    fn a_record_is_bound_to_the_number_asked() {
        let record = decode(RECORD.as_bytes(), Id::Abn("31163147680")).unwrap();
        assert_eq!(
            record.entity_name.as_deref(),
            Some("KORDAMENTHA ADVISORY PTY LTD")
        );
        assert!(decode(RECORD.as_bytes(), Id::Acn("163147680")).is_ok());
        assert!(matches!(
            decode(RECORD.as_bytes(), Id::Abn("53004085616")),
            Err(LegError::Decode(_))
        ));
    }

    #[test]
    fn a_record_without_an_abn_and_without_a_guid_message_is_inconclusive() {
        let empty = r#"callback({"Abn":"","Message":"Search text is not a valid ABN or ACN"})"#;
        assert!(matches!(
            decode(empty.as_bytes(), Id::Abn("31163147680")),
            Err(LegError::Decode(_))
        ));
    }

    #[test]
    fn the_record_is_an_organisation_with_its_numbers_business_names_and_place() {
        let record = decode(RECORD.as_bytes(), Id::Abn("31163147680")).unwrap();
        let out = entities(&record, "s");
        let org = out
            .iter()
            .find(|e| {
                e.kind == EntityKind::Organisation && e.raw_value == "KORDAMENTHA ADVISORY PTY LTD"
            })
            .expect("entity");
        let attr = |key: &str| org.evidence[0].attributes.get(key).map(String::as_str);
        assert_eq!(attr("registry"), Some("ABR"));
        assert_eq!(attr("entity_type"), Some("Australian Private Company"));
        assert_eq!(attr("gst_registered_from"), Some("2013-04-15"));
        for id in ["31163147680", "163147680"] {
            assert!(
                out.iter()
                    .any(|e| e.kind == EntityKind::AbnAcn && e.raw_value == id),
                "{id}"
            );
        }
        assert!(
            out.iter()
                .any(|e| e.raw_value == "KordaMentha Advisory" && e.has_tag("abr-business-name"))
        );
        assert!(
            out.iter()
                .any(|e| e.kind == EntityKind::Address && e.raw_value == "VIC 3000")
        );
    }

    #[test]
    fn jsonp_wrappers_are_removed_and_plain_json_is_kept() {
        assert_eq!(unwrap_jsonp(b"cb({\"a\":1});"), b"{\"a\":1}");
        assert_eq!(unwrap_jsonp(b" {\"a\":1} "), b"{\"a\":1}");
    }
}
