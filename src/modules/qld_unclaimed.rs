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
use crate::util::postcode_au::Locality;

const SRC: &str = "qld_unclaimed";

/// CKAN resource id of the Public Trustee "Unclaimed monies" register on
/// `data.qld.gov.au`. Stable per-resource; if the portal ever re-publishes the
/// register under a new resource this is the single value to update.
const RESOURCE_ID: &str = "872065ae-ddfd-4b5f-ad15-e1935dadd883";

/// Cap on records turned into entities for one seed — common surnames can match
/// hundreds of rows; we keep the highest-ranked handful so a single name doesn't
/// flood the graph.
const MAX_RECORDS: usize = 20;

/// Max distinct postcodes resolved to suburb-sets per scan (each is one HTTP
/// call to Zippopotam), and max suburbs enumerated per postcode.
const POSTCODE_CAP: usize = 6;
const SUBURB_CAP: usize = 8;

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

/// The datastore_search URL for one full-text query.
fn query_url(q: &str) -> String {
    format!(
        "https://www.data.qld.gov.au/api/3/action/datastore_search?resource_id={RESOURCE_ID}&q={}&limit={MAX_RECORDS}",
        urlencode(q)
    )
}

/// Merge an exact-name (`primary`) record set *ahead of* a broad surname
/// (`secondary`) set, de-duplicating on the CKAN row `_id`. Exact rows lead so
/// the seeded person's own record survives the `MAX_RECORDS` cap even when a
/// common surname returns a flood of unrelated namesakes ranked above them.
fn merge_records(
    primary: Vec<Map<String, Value>>,
    secondary: Vec<Map<String, Value>>,
) -> Vec<Map<String, Value>> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(primary.len() + secondary.len());
    for rec in primary.into_iter().chain(secondary) {
        let id = field_str(&rec, "_id").unwrap_or_default();
        // Keep id-less rows (CKAN always sets `_id`, so this is just defensive)
        // and any id not seen before.
        if id.is_empty() || seen.insert(id) {
            out.push(rec);
        }
    }
    out
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

        // Unclaimed money is often owed to *companies* (dividends, refunds) — and
        // frequently to joint syndicates of several companies. Emit one
        // `Organisation` per individually-resolvable company name so the engine's
        // expansion pivots each into abn_lookup / opencorporates and resolves its
        // ABN/ACN, connecting the unclaimed-money graph to the business registry.
        for company in crate::util::abn::company_names(&owner) {
            let mut org = Entity::new(EntityKind::Organisation, &company, find_conf, scan_id);
            org.tag(SRC);
            org.tag("unclaimed-money");
            org.tag("country:AU");
            org.tag("company-owner");
            let mut oev = Evidence::new(SRC, format!("Company owed unclaimed money: {company}"))
                .with_attr("register", "QLD Public Trustee unclaimed monies");
            if company != owner {
                oev = oev.with_attr("joint_owner", &owner);
            }
            org.add_evidence(oev);
            out.push(org);
        }
    }
    out
}

/// Depth-of-enumeration: turn each resolved postcode→localities set into geo
/// entities — one rough `Coordinates` anchor at the postcode centroid plus a
/// suburb-precise, individually geocodable `Address` per locality
/// (`"Maleny, QLD 4552, Australia"`). These are *candidate* localities (the
/// owner is in one of them), so confidence is low and they carry a
/// `candidate-suburb` tag; the engine surfaces them as enumeration without
/// auto-expanding (below the 0.50 floor). Pure: takes the already-fetched map.
fn suburbs_to_entities(pc_localities: &[(String, Vec<Locality>)], scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    for (pc, locs) in pc_localities {
        if let Some(first) = locs.first() {
            let coords = format!("{:.5},{:.5}", first.lat, first.lon);
            let mut c = Entity::new(EntityKind::Coordinates, coords, 0.40, scan_id);
            c.tag(SRC);
            c.tag("country:AU");
            c.tag("geoint");
            c.tag("postcode-centroid");
            c.add_evidence(
                Evidence::new(SRC, format!("Centroid of postcode {pc}"))
                    .with_attr("postcode", pc)
                    .with_attr("source", "zippopotam"),
            );
            out.push(c);
        }
        for loc in locs.iter().take(SUBURB_CAP) {
            let mut a = Entity::new(
                EntityKind::Address,
                format!("{}, QLD {pc}, Australia", loc.suburb),
                0.40,
                scan_id,
            );
            a.tag(SRC);
            a.tag("country:AU");
            a.tag("geoint");
            a.tag("candidate-suburb");
            a.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Locality within postcode {pc}: {}", loc.suburb),
                )
                .with_attr("suburb", &loc.suburb)
                .with_attr("postcode", pc)
                .with_attr("lat", format!("{:.5}", loc.lat))
                .with_attr("lon", format!("{:.5}", loc.lon))
                .with_attr("source", "zippopotam"),
            );
            out.push(a);
        }
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
        const KINDS: &[EntityKind] = &[EntityKind::Address, EntityKind::Organisation];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full = target.value.trim();
        // The register full-text search needs a meaningful token; a 1–2 char
        // query would match noise across a 240 MB dataset.
        if full.len() < 3 {
            return Ok(ModuleResult::new());
        }
        // `derive_query` broadens a multi-token full name to its surname so
        // relatives' deceased-estate funds surface; equals `full` otherwise.
        let surname = derive_query(target);

        // Broad query (surname, or the verbatim value): family-level recall.
        let broad: CkanResp = fetch_json(&ctx.http, SRC, &query_url(surname)).await?;
        let Some(broad_res) = broad.result else {
            return Ok(ModuleResult::new());
        };
        let total = broad_res.total.unwrap_or(broad_res.records.len() as u64);
        let mut records = broad_res.records;

        // Two-tier precision: when we broadened to a surname, also run the exact
        // full-name query (AND-matched) and place those rows FIRST, so the
        // seeded person's own record is never capped out behind a common
        // surname's namesakes. A failed exact probe is non-fatal — broad stands.
        if surname != full
            && let Ok(exact) = fetch_json::<CkanResp>(&ctx.http, SRC, &query_url(full)).await
            && let Some(exact_res) = exact.result
        {
            records = merge_records(exact_res.records, records);
        }

        // Depth-of-enumeration: resolve each distinct postcode in the results to
        // its constituent suburbs (Zippopotam, keyless). A bare postcode is a
        // coarse signal — a QLD postcode spans many localities — so we expand it
        // into suburb-precise, geocodable Address candidates. Best-effort and
        // capped; each lookup is non-fatal.
        let mut seen_pc: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut unique_pcs: Vec<String> = Vec::new();
        for rec in &records {
            if let Some(pc) = postcode(rec)
                && seen_pc.insert(pc.clone())
            {
                unique_pcs.push(pc);
                if unique_pcs.len() >= POSTCODE_CAP {
                    break;
                }
            }
        }
        let mut pc_localities: Vec<(String, Vec<Locality>)> = Vec::new();
        for pc in unique_pcs {
            let locs = crate::util::postcode_au::localities(&ctx.http, &pc).await;
            if !locs.is_empty() {
                pc_localities.push((pc, locs));
            }
        }

        let mut out = ModuleResult::new();
        out.extend(records_to_entities(&records, total, full, &ctx.scan_id));
        out.extend(suburbs_to_entities(&pc_localities, &ctx.scan_id));
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
    fn company_owner_emits_organisation_for_abn_pivot() {
        // Unclaimed money owed to a company → an extra Organisation entity that
        // the engine will expand into abn_lookup / opencorporates.
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":7,"Owner":"ACME WIDGETS PTY LTD","Amount":"1200.00","SenderName":"ASX","PCode":"4000"}
        ]}}"#;
        let resp: CkanResp = serde_json::from_str(raw).unwrap();
        let recs = resp.result.unwrap().records;
        let ents = records_to_entities(&recs, 1, "ACME Widgets", "s");
        // Address (geo) + Organisation (ABN pivot).
        assert_eq!(ents.len(), 2);
        assert!(ents.iter().any(|e| e.kind == EntityKind::Address));
        let org = ents
            .iter()
            .find(|e| e.kind == EntityKind::Organisation)
            .expect("company owner must emit an Organisation");
        assert_eq!(org.value, "ACME WIDGETS PTY LTD");
        assert!(org.tags.iter().any(|t| t.as_str() == "company-owner"));

        // An individual owner emits no Organisation (no ABN pivot noise).
        let raw2 = r#"{"result":{"total":1,"records":[
            {"_id":8,"Owner":"JANE CITIZEN","Amount":"5.00","PCode":"4000"}
        ]}}"#;
        let recs2: Vec<Map<String, Value>> = serde_json::from_str::<CkanResp>(raw2)
            .unwrap()
            .result
            .unwrap()
            .records;
        let ents2 = records_to_entities(&recs2, 1, "Jane Citizen", "s");
        assert_eq!(ents2.len(), 1, "individual owner → no Organisation");
        assert!(ents2.iter().all(|e| e.kind != EntityKind::Organisation));

        // A real joint syndicate splits into one resolvable Organisation each.
        let raw3 = r#"{"result":{"total":1,"records":[
            {"_id":9,"Owner":"DEV PTY LTD & GWAD PTY LTD & GWAD2 PTY LTD","Amount":"508.80","SenderName":"QLD URBAN UTILITIES","PCode":"4051"}
        ]}}"#;
        let recs3: Vec<Map<String, Value>> = serde_json::from_str::<CkanResp>(raw3)
            .unwrap()
            .result
            .unwrap()
            .records;
        let ents3 = records_to_entities(&recs3, 1, "DEV", "s");
        let orgs: Vec<&str> = ents3
            .iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(orgs, vec!["DEV PTY LTD", "GWAD PTY LTD", "GWAD2 PTY LTD"]);
        // Split orgs carry the original joint owner in evidence for context.
        let dev = ents3.iter().find(|e| e.value == "DEV PTY LTD").unwrap();
        assert!(
            dev.evidence[0]
                .attributes
                .iter()
                .any(|(k, _)| k.as_str() == "joint_owner")
        );
    }

    #[test]
    fn suburbs_enumerate_into_geocodable_candidates() {
        // Postcode 4552 → its localities (incl. the user's home, Booroobin).
        let locs = vec![
            Locality {
                suburb: "Maleny".into(),
                lat: -26.729,
                lon: 152.7554,
            },
            Locality {
                suburb: "Booroobin".into(),
                lat: -26.729,
                lon: 152.7554,
            },
            Locality {
                suburb: "Conondale".into(),
                lat: -26.7333,
                lon: 152.7167,
            },
        ];
        let ents = suburbs_to_entities(&[("4552".to_string(), locs)], "s");
        // One centroid Coordinates + one Address per locality.
        let coords: Vec<&Entity> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .collect();
        assert_eq!(coords.len(), 1);
        assert!(
            coords[0]
                .tags
                .iter()
                .any(|t| t.as_str() == "postcode-centroid")
        );

        let addrs: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(
            addrs,
            vec![
                "Maleny, QLD 4552, Australia",
                "Booroobin, QLD 4552, Australia",
                "Conondale, QLD 4552, Australia",
            ]
        );
        // Candidate suburbs stay below the 0.50 expansion floor.
        assert!(
            ents.iter()
                .all(|e| e.confidence < 0.50 && e.tags.iter().any(|t| t.as_str() == SRC))
        );
        // The Address evidence carries the suburb + per-locality coordinates.
        let maleny = ents.iter().find(|e| e.value.starts_with("Maleny")).unwrap();
        let attr = |k: &str| {
            maleny.evidence[0]
                .attributes
                .iter()
                .find(|(a, _)| a.as_str() == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(attr("suburb"), Some("Maleny"));
        assert_eq!(attr("postcode"), Some("4552"));
    }

    #[test]
    fn merge_records_puts_exact_first_and_dedups_on_id() {
        // Exact probe returns the seeded person (id 50); broad surname probe
        // returns a flood including that same row (id 50) plus namesakes.
        let exact: Vec<Map<String, Value>> =
            serde_json::from_str(r#"[{"_id":50,"Owner":"JOHN SMITH","PCode":"4000"}]"#).unwrap();
        let broad: Vec<Map<String, Value>> = serde_json::from_str(
            r#"[{"_id":11,"Owner":"ALICE SMITH"},{"_id":50,"Owner":"JOHN SMITH"},{"_id":12,"Owner":"BOB SMITH"}]"#,
        )
        .unwrap();
        let merged = merge_records(exact, broad);
        // id 50 appears once, and FIRST (survives the cap ahead of namesakes).
        assert_eq!(merged.len(), 3, "the duplicate id 50 is collapsed");
        assert_eq!(field_str(&merged[0], "_id").as_deref(), Some("50"));
        let ids: Vec<String> = merged.iter().filter_map(|r| field_str(r, "_id")).collect();
        assert_eq!(ids, vec!["50", "11", "12"]);
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
        // All four Kareem owners are individuals → no Organisation/ABN pivots:
        // four entities exactly, none a company (the ABN incorporation stays
        // silent on a non-business family).
        assert_eq!(ents.len(), 4);
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Organisation),
            "individual owners must not manufacture company/ABN entities"
        );
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
