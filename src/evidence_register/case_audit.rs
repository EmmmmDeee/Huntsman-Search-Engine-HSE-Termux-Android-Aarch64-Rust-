//! Offline, bounded validation of externally collected public-business OSINT case evidence.
//!
//! This validates package integrity and source references. It does not fetch sources,
//! authenticate claims, infer licence status or turn a missing result into evidence of absence.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::sha256::{hex32, sha256};

pub const MAX_CASE_BYTES: usize = 256 * 1024;
pub const MAX_ADVERT_BYTES: usize = 16 * 1024;
const MAX_SOURCES: usize = 64;
const MAX_CLAIMS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseAudit {
    pub case_id: String,
    pub source_count: usize,
    pub claim_count: usize,
    pub unresolved_claim_ids: Vec<String>,
    pub original_publication_unknown: bool,
    pub original_year_unknown: bool,
}

fn field<'a>(object: &'a Value, key: &str) -> Result<&'a Value, String> {
    object
        .get(key)
        .ok_or_else(|| format!("missing field {key}"))
}

fn text_field<'a>(object: &'a Value, key: &str) -> Result<&'a str, String> {
    field(object, key)?
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{key} must be a nonempty string"))
}

fn array_field<'a>(object: &'a Value, key: &str, max: usize) -> Result<&'a [Value], String> {
    let array = field(object, key)?
        .as_array()
        .ok_or_else(|| format!("{key} must be an array"))?;
    if array.len() > max {
        return Err(format!("{key} exceeds {max} entries"));
    }
    Ok(array)
}

/// Checks an evidence package against its exact original advertisement bytes.
///
/// A passing result attests only to structural and input integrity, not to
/// the external truth of the claims or validity of a professional licence.
pub fn audit_case(case_bytes: &[u8], advert_bytes: &[u8]) -> Result<CaseAudit, String> {
    if case_bytes.len() > MAX_CASE_BYTES || advert_bytes.len() > MAX_ADVERT_BYTES {
        return Err("input exceeds bounded case or advertisement size".into());
    }
    let case: Value =
        serde_json::from_slice(case_bytes).map_err(|e| format!("invalid case JSON: {e}"))?;
    let case_id = text_field(&case, "case_id")?.to_owned();
    let input = field(&case, "primary_input")?;
    let expected_bytes = field(input, "bytes")?
        .as_u64()
        .ok_or_else(|| "primary_input.bytes must be an unsigned integer".to_owned())?;
    let expected_text = text_field(input, "literal_text")?;
    let expected_digest = text_field(input, "literal_sha256")?;
    let actual_digest = hex32(&sha256(advert_bytes));
    if expected_bytes != u64::try_from(advert_bytes.len()).unwrap_or(u64::MAX)
        || expected_text.as_bytes() != advert_bytes
        || expected_digest != actual_digest
    {
        return Err("advertisement bytes, literal text or SHA-256 disagree".into());
    }

    let mut sources = BTreeMap::<&str, &str>::new();
    for source in array_field(&case, "sources", MAX_SOURCES)? {
        let id = text_field(source, "id")?;
        let kind = text_field(source, "source_type")?;
        if sources.insert(id, kind).is_some() {
            return Err(format!("duplicate source ID: {id}"));
        }
        if let Some(url) = source.get("url").and_then(Value::as_str) {
            if !url.starts_with("https://") {
                return Err(format!("source {id} has a non-HTTPS URL"));
            }
        }
    }
    if !sources.contains_key("ORIGINAL") {
        return Err("missing ORIGINAL provenance source".into());
    }

    let mut ids = BTreeSet::new();
    let mut unresolved = Vec::new();
    let claims = array_field(&case, "facts_and_assessments", MAX_CLAIMS)?;
    for claim in claims {
        let id = text_field(claim, "id")?;
        if !ids.insert(id) {
            return Err(format!("duplicate claim ID: {id}"));
        }
        let class = text_field(claim, "class")?;
        let _ = text_field(claim, "assertion")?;
        let references = array_field(claim, "sources", MAX_SOURCES)?;
        if references.is_empty() {
            return Err(format!("claim {id} lacks source references"));
        }
        let mut authoritative_registry = false;
        for reference in references {
            let sid = reference
                .as_str()
                .ok_or_else(|| format!("claim {id} has a non-string source ID"))?;
            let Some(kind) = sources.get(sid) else {
                return Err(format!("claim {id} refers to unknown source {sid}"));
            };
            if matches!(*kind, "government_registry" | "government_holder_record") {
                authoritative_registry = true;
            }
        }
        if class == "verified_primary_record" && !authoritative_registry {
            return Err(format!(
                "claim {id} asserts government verification without a registry source"
            ));
        }
        if matches!(
            class,
            "unverified" | "inference_not_verified" | "not_stated"
        ) {
            unresolved.push(id.to_owned());
        }
    }
    Ok(CaseAudit {
        case_id,
        source_count: sources.len(),
        claim_count: claims.len(),
        unresolved_claim_ids: unresolved,
        original_publication_unknown: input.get("original_url").is_none_or(Value::is_null),
        original_year_unknown: input.get("year").is_none_or(Value::is_null),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const AD: &str = "Hi everyone, Bendigo. Contact chris@example.com.";

    fn example() -> Value {
        json!({
            "case_id":"test-vero",
            "primary_input":{
                "literal_text":AD,
                "literal_sha256":hex32(&sha256(AD.as_bytes())),
                "bytes":AD.len(),
                "year":null,
                "original_url":null
            },
            "sources":[
                {"id":"ORIGINAL","source_type":"user_chat_literal"},
                {"id":"ABR","source_type":"government_registry","url":"https://abr.business.gov.au/"},
                {"id":"COMPANY","source_type":"first_party_website","url":"https://example.com/"}
            ],
            "facts_and_assessments":[
                {"id":"C01","class":"verified_primary_record","assertion":"ABN record","sources":["ABR"]},
                {"id":"C02","class":"unverified","assertion":"Advert author","sources":["ORIGINAL","COMPANY"]}
            ]
        })
    }

    fn check(v: &Value) -> Result<CaseAudit, String> {
        audit_case(v.to_string().as_bytes(), AD.as_bytes())
    }

    #[test]
    fn valid_case_preserves_unknowns() {
        let r = check(&example()).expect("case");
        assert_eq!(r.source_count, 3);
        assert_eq!(r.claim_count, 2);
        assert_eq!(r.unresolved_claim_ids, ["C02"]);
        assert!(r.original_publication_unknown && r.original_year_unknown);
    }

    #[test]
    fn tampered_advert_is_rejected() {
        let err = audit_case(example().to_string().as_bytes(), b"altered");
        assert!(err.is_err());
    }

    #[test]
    fn duplicate_source_and_claim_refused() {
        let mut v = example();
        let source = v["sources"][0].clone();
        v["sources"].as_array_mut().expect("array").push(source);
        assert!(check(&v).is_err());
        let mut v = example();
        let claim = v["facts_and_assessments"][0].clone();
        v["facts_and_assessments"]
            .as_array_mut()
            .expect("array")
            .push(claim);
        assert!(check(&v).is_err());
    }

    #[test]
    fn dangling_reference_refused() {
        let mut v = example();
        v["facts_and_assessments"][0]["sources"] = json!(["NO_SUCH_SOURCE"]);
        assert!(check(&v).is_err());
    }

    #[test]
    fn first_party_cannot_validate_government_status() {
        let mut v = example();
        v["facts_and_assessments"][0]["sources"] = json!(["COMPANY"]);
        assert!(check(&v).is_err());
    }

    #[test]
    fn refuses_unsafe_url_and_oversize() {
        let mut v = example();
        v["sources"][1]["url"] = json!("http://localhost/");
        assert!(check(&v).is_err());
        assert!(audit_case(&vec![b'x'; MAX_CASE_BYTES + 1], AD.as_bytes()).is_err());
    }
}
