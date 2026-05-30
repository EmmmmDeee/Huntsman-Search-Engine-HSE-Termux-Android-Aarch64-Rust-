//! Queensland Public Trustee unclaimed-money lookup (keyless, free).
//!
//! Endpoint: `GET https://www.data.qld.gov.au/api/3/action/datastore_search`
//!           `?resource_id={RESOURCE_ID}&q={name}&limit=20`
//! Auth:     none — the Queensland Government Open Data Portal (CKAN) exposes
//!           the Public Trustee's unclaimed-monies register as a public,
//!           datastore-active resource refreshed weekly.
//!
//! The register lists money owed to people from deceased estates and lodged
//! unclaimed funds (insurance refunds, payroll remainders, government refunds,
//! …). For a person/organisation seed we full-text search the register and, for
//! every matching record, emit the owner's lodged postcode as a geocodable
//! `Address` (so the GEOINT pipeline can pivot on it) carrying the owner, amount,
//! sender, date and reference number as evidence. Records with no usable
//! postcode still surface as an `unclaimed_money` finding so the money is never
//! silently dropped.
//!
//! This is exactly the Australian people-centric public-records source the
//! charter targets: free, keyless, structured JSON, and it chains into geocode →
//! coordinates.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json, urlencode};

const SRC: &str = "qld_unclaimed";

/// CKAN resource id of the Public Trustee "Unclaimed monies" register on
/// `data.qld.gov.au`. Stable per-resource; if the portal ever re-publishes the
/// register under a new resource this is the single value to update.
const RESOURCE_ID: &str = "872065ae-ddfd-4b5f-ad15-e1935dadd883";

/// Cap on records turned into entities for one seed — common surnames can match
/// hundreds of rows; we keep the highest-ranked handful so a single name doesn't
/// flood the graph.
const MAX_RECORDS: usize = 20;

pub struct QldUnclaimed;

#[derive(Deserialize)]
struct CkanResp {
    #[serde(default)]
    result: Option<CkanResult>,
}

#[derive(Deserialize)]
struct CkanResult {
    #[serde(default)]
    total: Option<u64>,
    /// Records are returned with CKAN-inferred field types (text vs numeric), so
    /// we keep them as raw JSON objects and stringify fields defensively rather
    /// than risk a deserialize failure on a numeric `Amount`/`PCode`.
    #[serde(default)]
    records: Vec<Map<String, Value>>,
}

/// Stringify a CKAN field value (text stays as-is, numbers/bools are rendered,
/// null/missing → `None`) and trim it; empty becomes `None`.
fn field_str(rec: &Map<String, Value>, key: &str) -> Option<String> {
    let s = match rec.get(key)? {
        Value::String(s) => s.trim().to_string(),
        Value::Null => return None,
        other => other.to_string(),
    };
    if s.is_empty() { None } else { Some(s) }
}

/// A 4-digit Australian postcode, else `None`.
fn postcode(rec: &Map<String, Value>) -> Option<String> {
    let p = field_str(rec, "PCode")?;
    (p.len() == 4 && p.bytes().all(|b| b.is_ascii_digit())).then_some(p)
}

/// The register's full-text search ANDs multi-word queries, so seeding a full
/// name (`"Matthew Diegmann"`) only matches a row whose owner contains *both*
/// tokens — which silently misses the deceased-estate funds the register mostly
/// holds, where the money is owed to a *relative* (a different given name, same
/// surname). For a multi-token `FullName` we therefore search the **surname**
/// (last token) to surface the whole family, then classify each row back against
/// the full seed (see [`owner_matches_full_name`]). Single-token names and
/// organisations are searched verbatim.
fn derive_query(target: &Target) -> &str {
    let v = target.value.trim();
    if matches!(target.kind, TargetKind::FullName)
        && let Some(surname) = v.split_whitespace().next_back()
        && surname.len() >= 3
        && surname.len() < v.len()
    {
        return surname;
    }
    v
}

/// True if `owner` contains every whitespace token of the seed name (case-
/// insensitive) — i.e. this row is the seeded person, not merely a surname-match
/// relative. Used to tag exact hits vs family candidates and weight confidence.
fn owner_matches_full_name(owner: &str, seed: &str) -> bool {
    let owner_up = owner.to_uppercase();
    let mut any = false;
    for tok in seed.split_whitespace() {
        any = true;
        if !owner_up.contains(&tok.to_uppercase()) {
            return false;
        }
    }
    any
}

/// Pure transform: CKAN records → entities. One entity per record — a geocodable
/// `Address` built from the lodged postcode when present (so geocode/coords can
/// pivot on it), otherwise an `unclaimed_money` finding so the record is never
/// dropped. Each carries owner / amount / sender / date / reference as evidence.
fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    seed: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let owner = field_str(rec, "Owner").unwrap_or_else(|| "(unknown owner)".to_string());
        // Is this the seeded person, or a same-surname relative the broadened
        // surname search swept in? Exact hits rank higher and are tagged so.
        let exact = owner_matches_full_name(&owner, seed);
        let amount = field_str(rec, "Amount");
        let sender = field_str(rec, "SenderName");
        let date = field_str(rec, "DateRec");
        let reference = field_str(rec, "ClientId_ActNo");

        let mut ev = Evidence::new(SRC, format!("QLD unclaimed money: {owner}"));
        ev = ev.with_attr("owner", &owner);
        if let Some(a) = amount.as_deref() {
            ev = ev.with_attr("amount_aud", a);
        }
        if let Some(s) = sender.as_deref() {
            ev = ev.with_attr("sender", s);
        }
        if let Some(d) = date.as_deref() {
            ev = ev.with_attr("date_received", d);
        }
        if let Some(r) = reference.as_deref() {
            ev = ev.with_attr("reference", r);
        }
        if let Some(p) = postcode(rec) {
            ev = ev.with_attr("postcode", &p);
        }
        ev = ev
            .with_attr("register", "QLD Public Trustee unclaimed monies")
            .with_attr("total_matches", total.to_string());

        // Exact-name hits are worth more than surname-only family candidates;
        // weight confidence and tag accordingly so the engine ranks them.
        let (addr_conf, find_conf) = if exact { (0.50, 0.60) } else { (0.40, 0.50) };

        // Geo pivot when we have a usable postcode; otherwise a plain finding.
        let mut entity = match postcode(rec) {
            Some(p) => {
                let mut e = Entity::new(
                    EntityKind::Address,
                    format!("QLD {p}, Australia"),
                    addr_conf,
                    scan_id,
                );
                e.tag("postcode-only");
                e
            }
            None => {
                let amt = amount.as_deref().unwrap_or("?");
                Entity::new(
                    EntityKind::Other("unclaimed_money".to_string()),
                    format!("{owner} — ${amt}"),
                    find_conf,
                    scan_id,
                )
            }
        };
        entity.tag(SRC);
        entity.tag("unclaimed-money");
        entity.tag("country:AU");
        entity.tag("geoint");
        entity.tag(if exact {
            "exact-name-match"
        } else {
            "family-candidate"
        });
        entity.add_evidence(ev);
        out.push(entity);
    }
    out
}

#[async_trait]
impl Module for QldUnclaimed {
    fn name(&self) -> &'static str {
        "qld_unclaimed"
    }

    fn description(&self) -> &'static str {
        "Queensland Public Trustee unclaimed-money register lookup (free, keyless)"
    }

    fn priority(&self) -> u8 {
        58
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Search broadens a full name to its surname to catch deceased-estate
        // funds owed to relatives; the original full name is kept to classify
        // exact hits vs family candidates.
        let query = derive_query(target);
        // The register full-text search needs a meaningful token; a 1–2 char
        // query would match noise across a 240 MB dataset.
        if query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://www.data.qld.gov.au/api/3/action/datastore_search?resource_id={RESOURCE_ID}&q={}&limit={MAX_RECORDS}",
            urlencode(query),
        );

        let resp: CkanResp = fetch_json(&ctx.http, SRC, &url).await?;
        let Some(result) = resp.result else {
            return Ok(ModuleResult::new());
        };
        let total = result.total.unwrap_or(result.records.len() as u64);

        let mut out = ModuleResult::new();
        out.extend(records_to_entities(
            &result.records,
            total,
            target.value.trim(),
            &ctx.scan_id,
        ));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CkanResp {
        // The exact shape returned by datastore_search for q=Diegmann.
        let raw = r#"{
            "result": {
                "total": 3,
                "records": [
                    {"_id":1938437,"ClientId_ActNo":"210580670460","Owner":"HAYLEY DIEGMANN & CURT DIEGMANN","Amount":"545.74","SenderName":"INSURANCE AUSTRALIA GROUP LIMITED","DateRec":"2024-03-14","PCode":"4557","rank":0.0706241},
                    {"_id":913780,"ClientId_ActNo":"207768336631","Owner":"CURT DIEGMANN","Amount":"0.92","SenderName":"REMUNERATION SERVICES","DateRec":"2015-03-31","PCode":"4555","rank":0.057308756},
                    {"_id":1082370,"ClientId_ActNo":"208285682789","Owner":"ERIK DIEGMANN","Amount":"115.45","SenderName":"UNCM DEPT OF TPT AND MAIN ROADS - MAIN ROAD","DateRec":"2016-10-17","PCode":"4552","rank":0.057308756}
                ]
            }
        }"#;
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn accepts_fullname_and_org_only() {
        let m = QldUnclaimed;
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Matthew Diegmann")));
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "ACME Pty Ltd")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn module_metadata() {
        let m = QldUnclaimed;
        assert_eq!(m.name(), "qld_unclaimed");
        assert!(!m.description().is_empty());
        assert_eq!(m.cost(), ModuleCost::Free);
    }

    #[test]
    fn derive_query_broadens_full_name_to_surname() {
        // Full name → surname (so the AND search surfaces relatives' estate funds).
        assert_eq!(
            derive_query(&Target::new(TargetKind::FullName, "Matthew Diegmann")),
            "Diegmann"
        );
        assert_eq!(
            derive_query(&Target::new(TargetKind::FullName, "  Curt   Diegmann  ")),
            "Diegmann"
        );
        // Single-token name → verbatim.
        assert_eq!(
            derive_query(&Target::new(TargetKind::FullName, "Cher")),
            "Cher"
        );
        // Organisation → verbatim (no surname semantics).
        assert_eq!(
            derive_query(&Target::new(TargetKind::Organisation, "ACME Pty Ltd")),
            "ACME Pty Ltd"
        );
    }

    #[test]
    fn classifies_exact_person_vs_surname_only_family() {
        let resp = sample();
        let result = resp.result.unwrap();

        // Seeding the user's full name (no register row contains "MATTHEW"):
        // every Diegmann row is a family candidate, none an exact match.
        let fam = records_to_entities(&result.records, 3, "Matthew Diegmann", "s");
        assert!(
            fam.iter()
                .all(|e| e.tags.iter().any(|t| t.as_str() == "family-candidate")),
            "surname-only relatives must be tagged family-candidate"
        );
        assert!(
            fam.iter()
                .all(|e| !e.tags.iter().any(|t| t.as_str() == "exact-name-match"))
        );

        // Seeding "Curt Diegmann": the two Curt rows are exact, Erik is family.
        let resp2 = sample();
        let result2 = resp2.result.unwrap();
        let curt = records_to_entities(&result2.records, 3, "Curt Diegmann", "s");
        let exact = |e: &Entity| e.tags.iter().any(|t| t.as_str() == "exact-name-match");
        assert!(exact(&curt[0]), "HAYLEY & CURT row is an exact Curt match");
        assert!(exact(&curt[1]), "CURT DIEGMANN row is an exact Curt match");
        assert!(!exact(&curt[2]), "ERIK row is only a surname match");
        // Exact hits outrank family candidates on confidence.
        assert!(curt[1].confidence > curt[2].confidence);
    }

    #[test]
    fn common_polysemous_surname_produces_no_false_exact_matches() {
        // Real rows from q=Kareem — a common name appearing as given name, surname
        // and middle element across UNRELATED people state-wide. Seeding "Ali
        // Kareem" (no row contains "ALI") must classify every row as a low-weight
        // family-candidate and zero as an exact match, so a common surname can't
        // masquerade as the seeded person or auto-expand (0.40 C_eff < 0.50 floor).
        let raw = r#"{"result":{"total":17,"records":[
            {"_id":1,"Owner":"KAREEM AYALA","Amount":"4.45","SenderName":"GOLDEN CASKET","DateRec":"2024-03-19","PCode":"4740"},
            {"_id":2,"Owner":"MS SILVA KAREEM","Amount":"387.54","SenderName":"QLD URBAN UTILITIES","DateRec":"2024-07-25","PCode":"4305"},
            {"_id":3,"Owner":"HUSSEIN KHALEEL KAREEM","Amount":"267.45","SenderName":"DEPT TPT MAIN ROADS","DateRec":"2021-02-18","PCode":"4118"},
            {"_id":4,"Owner":"MR J KAREEM","Amount":"1.95","SenderName":"ENERGEX","DateRec":"2006-02-16","PCode":"2880"}
        ]}}"#;
        let resp: CkanResp = serde_json::from_str(raw).unwrap();
        let recs = resp.result.unwrap().records;
        let ents = records_to_entities(&recs, 17, "Ali Kareem", "s");
        assert_eq!(ents.len(), 4);
        for e in &ents {
            assert!(
                e.tags.iter().any(|t| t.as_str() == "family-candidate"),
                "common-surname row must be a family candidate, not the seed"
            );
            assert!(!e.tags.iter().any(|t| t.as_str() == "exact-name-match"));
            // Below the 0.50 expansion floor, so state-wide name noise can't pivot.
            assert!(e.confidence < 0.50);
        }
        // The interstate row (Broken Hill, NSW 2880) is still surfaced, not dropped.
        assert!(ents.iter().any(|e| e.value.contains("2880")));

        // Control: a seed that genuinely matches one row ("Silva Kareem") flips
        // exactly that row to an exact match — the classifier is not just always-family.
        let silva = records_to_entities(&recs, 17, "Silva Kareem", "s");
        assert!(
            silva[1]
                .tags
                .iter()
                .any(|t| t.as_str() == "exact-name-match"),
            "MS SILVA KAREEM must be exact for seed 'Silva Kareem'"
        );
        assert!(
            !silva[0]
                .tags
                .iter()
                .any(|t| t.as_str() == "exact-name-match"),
            "KAREEM AYALA must stay a family candidate for seed 'Silva Kareem'"
        );
    }

    #[test]
    fn parses_records_into_geo_addresses() {
        let resp = sample();
        let result = resp.result.unwrap();
        let ents =
            records_to_entities(&result.records, result.total.unwrap(), "Diegmann", "scan-1");
        assert_eq!(ents.len(), 3, "one entity per record");

        // All three rows have valid 4-digit postcodes → geocodable Address entities.
        for e in &ents {
            assert_eq!(e.kind, EntityKind::Address);
            assert!(e.value.contains("QLD"));
            assert!(e.value.ends_with(", Australia"));
            assert!(e.tags.iter().any(|t| t.as_str() == "unclaimed-money"));
            assert!(e.tags.iter().any(|t| t.as_str() == "country:AU"));
        }
        assert_eq!(ents[0].value, "QLD 4557, Australia");

        // Evidence preserves the money trail verbatim (owner / amount / sender).
        let ev0 = &ents[0].evidence[0];
        let attr = |k: &str| {
            ev0.attributes
                .iter()
                .find(|(a, _)| a.as_str() == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(attr("owner"), Some("HAYLEY DIEGMANN & CURT DIEGMANN"));
        assert_eq!(attr("amount_aud"), Some("545.74"));
        assert_eq!(attr("sender"), Some("INSURANCE AUSTRALIA GROUP LIMITED"));
        assert_eq!(attr("postcode"), Some("4557"));
        assert_eq!(attr("reference"), Some("210580670460"));
        assert_eq!(attr("total_matches"), Some("3"));
    }

    #[test]
    fn record_without_postcode_becomes_finding_not_dropped() {
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":1,"Owner":"NO POSTCODE PERSON","Amount":"42.00","SenderName":"SOME SENDER"}
        ]}}"#;
        let resp: CkanResp = serde_json::from_str(raw).unwrap();
        let result = resp.result.unwrap();
        let ents = records_to_entities(&result.records, 1, "NO POSTCODE PERSON", "scan-1");
        assert_eq!(ents.len(), 1, "no-postcode record must still surface");
        assert_eq!(
            ents[0].kind,
            EntityKind::Other("unclaimed_money".to_string())
        );
        assert!(ents[0].value.contains("NO POSTCODE PERSON"));
        assert!(ents[0].value.contains("42.00"));
    }

    #[test]
    fn numeric_ckan_fields_are_stringified_not_dropped() {
        // CKAN may type Amount/PCode as numbers; field_str must still render them.
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":2,"Owner":"NUMERIC FIELDS","Amount":99.5,"SenderName":"X","PCode":4000}
        ]}}"#;
        let resp: CkanResp = serde_json::from_str(raw).unwrap();
        let result = resp.result.unwrap();
        let ents = records_to_entities(&result.records, 1, "NUMERIC FIELDS", "scan-1");
        assert_eq!(ents.len(), 1);
        // PCode 4000 (numeric) is recognised as a valid postcode → Address.
        assert_eq!(ents[0].kind, EntityKind::Address);
        assert_eq!(ents[0].value, "QLD 4000, Australia");
        let ev = &ents[0].evidence[0];
        let amt = ev
            .attributes
            .iter()
            .find(|(a, _)| a.as_str() == "amount_aud")
            .map(|(_, v)| v.as_str());
        assert_eq!(amt, Some("99.5"));
    }
}
