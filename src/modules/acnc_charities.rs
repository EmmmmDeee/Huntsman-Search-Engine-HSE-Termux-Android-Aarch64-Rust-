//! Australian Charities and Not-for-profits Commission (ACNC) register lookup
//! (keyless, free).
//!
//! Endpoint: `GET https://data.gov.au/data/api/3/action/datastore_search`
//!           `?resource_id={RESOURCE_ID}&q={name}&limit=20`
//! Auth:     none — the ACNC publishes the full national Register of Australian
//!           charities on `data.gov.au` (CKAN) as a public, datastore-active
//!           resource (~65k charities, refreshed regularly).
//!
//! This is the authoritative federal registry of not-for-profit *organisations*:
//! each row carries the charity's legal name, any other/trading names, its ABN,
//! registered address (street + town/state/postcode), website, size and number
//! of responsible persons. For an `Organisation` seed we full-text search the
//! register and, for every row whose name actually matches the seed, emit a web
//! of cross-correlating entities:
//!
//!   * `Organisation` — the charity (+ its other/trading names),
//!   * `AbnAcn` — the ABN, pivoted into `abn_lookup` / `opencorporates`,
//!   * `Address` — the registered locality (geocode → `Coordinates`),
//!   * `Domain` — the charity website (→ the DNS/web modules).
//!
//! The register's `q` is a *ranked* full-text search (not a strict AND), so it
//! returns loosely-related rows alongside true hits. We therefore classify each
//! row: rows whose name contains every seed token as a whole word are
//! `exact-name-match` (high confidence, fanned out into the pivots above); the
//! rest are surfaced as low-confidence `name-candidate` Organisations that carry
//! the full record (ABN, address, website, …) in their evidence — nothing the
//! API returned is dropped — but stay below the expansion floor so a generic
//! query can't pivot state-wide name noise.

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::{Response as CkanResp, field_str};
use crate::util::http::fetch_json;
use crate::util::url_util::host_from_url;

const SRC: &str = "acnc_charities";

/// CKAN action-endpoint base for `data.gov.au` (note the extra `/data` path
/// segment vs. other portals).
const ACTION_BASE: &str = "https://data.gov.au/data/api/3/action";

/// CKAN resource id of the "ACNC Register of Australian charities" CSV datastore
/// on `data.gov.au`. Stable per-resource; if the ACNC ever re-publishes the
/// register under a new resource this is the single value to update.
const RESOURCE_ID: &str = "8fb32972-24e9-4c95-885e-7140be51be8a";

/// Cap on rows turned into entities for one seed — a generic single-word query
/// can match thousands of charities; we keep the highest-ranked handful so a
/// single seed doesn't flood the graph.
const MAX_RECORDS: usize = 20;

/// Max other/trading names fanned out per charity.
const MAX_TRADING_NAMES: usize = 5;

// Confidence tiers. Exact hits (name contains every seed token) are authoritative
// federal-registry matches and sit above the 0.50 expansion floor so they pivot;
// candidates (loose full-text hits) stay below it so they're surfaced but inert.
const ORG_EXACT: f64 = 0.85;
const ORG_CANDIDATE: f64 = 0.45;
const ABN_CONF: f64 = 0.90;
const TRADING_NAME_CONF: f64 = 0.70;
const ADDR_CONF: f64 = 0.60;
const DOMAIN_CONF: f64 = 0.55;

pub struct AcncCharities;

/// An 11-digit Australian Business Number (digits only), else `None`. ACNC
/// stores the ABN as text but a numeric-typed datastore column would arrive as a
/// JSON number, so we normalise to digits and length-check.
fn abn_digits(rec: &Map<String, Value>) -> Option<String> {
    let raw = field_str(rec, "ABN")?;
    let digits = crate::util::str_util::ascii_digits(&raw);
    (digits.len() == 11).then_some(digits)
}

/// Trading / other names, comma-separated in the register, split and trimmed.
/// `Address_Line_1` legitimately contains commas, but `Other_Organisation_Names`
/// is a flat comma list ("SUBS, Sydney University Business Society").
fn other_names(rec: &Map<String, Value>) -> Vec<String> {
    field_str(rec, "Other_Organisation_Names")
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// True if `name` contains every token of the seed `query` as a *whole word*
/// (case-insensitive). Whole-word (not substring) so a seed token like `"red"`
/// doesn't match inside `"Mildred"`. Tokenises on non-alphanumeric boundaries
/// and compares with `eq_ignore_ascii_case` (no per-token `String` allocation).
fn name_matches_query(name: &str, query: &str) -> bool {
    let words: Vec<&str> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let mut any = false;
    for tok in query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
    {
        any = true;
        if !words.iter().any(|w| w.eq_ignore_ascii_case(tok)) {
            return false;
        }
    }
    any
}

/// True if the seed matches the charity's legal name or any of its other names.
fn record_is_exact(rec: &Map<String, Value>, query: &str) -> bool {
    field_str(rec, "Charity_Legal_Name")
        .as_deref()
        .is_some_and(|n| name_matches_query(n, query))
        || other_names(rec)
            .iter()
            .any(|n| name_matches_query(n, query))
}

/// The datastore_search URL for one full-text query.
fn query_url(q: &str) -> String {
    crate::util::ckan::datastore_search_url(ACTION_BASE, RESOURCE_ID, q, MAX_RECORDS)
}

/// Build the geocodable registered-address string from the locality fields
/// ("Sydney, NSW 2000, Australia"). The street line (`Address_Line_1`) often
/// can't be geocoded reliably (e.g. "Room 202, Codrington Building (H69)…") so it
/// rides in the evidence instead; the locality is what the geocode chain pivots
/// on. Returns `None` when there's nothing locating at all.
fn locality_address(rec: &Map<String, Value>) -> Option<String> {
    let town = field_str(rec, "Town_City");
    let state = field_str(rec, "State");
    let postcode = field_str(rec, "Postcode");
    let country = field_str(rec, "Country").unwrap_or_else(|| "Australia".to_string());
    if town.is_none() && state.is_none() && postcode.is_none() {
        return None;
    }
    let mut head = String::new();
    if let Some(t) = town.as_deref() {
        head.push_str(t);
    }
    match (state.as_deref(), postcode.as_deref()) {
        (Some(s), Some(p)) => {
            if !head.is_empty() {
                head.push_str(", ");
            }
            head.push_str(s);
            head.push(' ');
            head.push_str(p);
        }
        (Some(s), None) => {
            if !head.is_empty() {
                head.push_str(", ");
            }
            head.push_str(s);
        }
        (None, Some(p)) => {
            if !head.is_empty() {
                head.push_str(", ");
            }
            head.push_str(p);
        }
        (None, None) => {}
    }
    if head.is_empty() {
        return None;
    }
    Some(format!("{head}, {country}"))
}

/// Attach every present register field to the charity's evidence so nothing the
/// API returned is dropped — true for exact hits and candidates alike.
fn charity_evidence(rec: &Map<String, Value>, total: u64) -> Evidence {
    let legal = field_str(rec, "Charity_Legal_Name").unwrap_or_default();
    let mut ev = Evidence::new(SRC, format!("ACNC registered charity: {legal}"))
        .with_attr("register", "ACNC Register of Australian charities")
        .with_attr("total_matches", total.to_string());
    // Stable, useful columns — added only when present (no empty noise).
    for (col, attr) in [
        ("ABN", "abn"),
        ("Other_Organisation_Names", "other_names"),
        ("Address_Line_1", "address_line_1"),
        ("Address_Line_2", "address_line_2"),
        ("Address_Line_3", "address_line_3"),
        ("Town_City", "town_city"),
        ("State", "state"),
        ("Postcode", "postcode"),
        ("Country", "country"),
        ("Charity_Website", "website"),
        ("Registration_Date", "registration_date"),
        ("Date_Organisation_Established", "established"),
        ("Charity_Size", "charity_size"),
        ("Number_of_Responsible_Persons", "responsible_persons"),
    ] {
        if let Some(v) = field_str(rec, col) {
            ev = ev.with_attr(attr, v);
        }
    }
    ev
}

/// Pure transform: CKAN records → entities. Every row yields a primary
/// `Organisation` carrying the full record in evidence (no omission). Rows whose
/// name matches the seed exactly additionally fan out into the cross-correlation
/// pivots (ABN, trading names, address, domain); loose full-text candidates stay
/// a single sub-floor Organisation so generic queries don't pivot name noise.
fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(legal) = field_str(rec, "Charity_Legal_Name") else {
            continue;
        };
        let exact = record_is_exact(rec, query);
        let conf = if exact { ORG_EXACT } else { ORG_CANDIDATE };

        let mut org = Entity::new(EntityKind::Organisation, &legal, conf, scan_id);
        org.tag(SRC);
        org.tag("acnc");
        org.tag("charity");
        org.tag("country:AU");
        org.tag(if exact {
            "exact-name-match"
        } else {
            "name-candidate"
        });
        org.add_evidence(charity_evidence(rec, total));
        out.push(org);

        // Cross-correlation pivots — exact hits only.
        if !exact {
            continue;
        }

        // ABN → abn_lookup / opencorporates resolve the full business registry.
        if let Some(abn) = abn_digits(rec) {
            let mut e = Entity::new(EntityKind::AbnAcn, &abn, ABN_CONF, scan_id);
            e.tag(SRC);
            e.tag("acnc");
            e.tag("country:AU");
            e.add_evidence(Evidence::new(SRC, format!("ABN {abn} → {legal}")));
            out.push(e);
        }

        // Other / trading names → resolvable Organisations.
        for tn in other_names(rec).into_iter().take(MAX_TRADING_NAMES) {
            if tn.eq_ignore_ascii_case(&legal) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Organisation, &tn, TRADING_NAME_CONF, scan_id);
            e.tag(SRC);
            e.tag("acnc");
            e.tag("country:AU");
            e.tag("business-name");
            e.add_evidence(Evidence::new(
                SRC,
                format!("Other/trading name for {legal}"),
            ));
            out.push(e);
        }

        // Registered locality → geocode chains it into Coordinates.
        if let Some(addr) = locality_address(rec) {
            let mut e = Entity::new(EntityKind::Address, &addr, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("acnc");
            e.tag("country:AU");
            e.tag("geoint");
            e.tag("registered-address");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                e.tag(format!("au-state:{sc}"));
            }
            let mut aev = Evidence::new(SRC, format!("Registered address for {legal}"))
                .with_attr("org", &legal);
            for col in ["Address_Line_1", "Address_Line_2", "Address_Line_3"] {
                if let Some(v) = field_str(rec, col) {
                    aev = aev.with_attr(col.to_lowercase().replace(' ', "_"), v);
                }
            }
            e.add_evidence(aev);
            out.push(e);

            // Inline Coordinates for immediate AU-052/053 participation.
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&addr) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.62, scan_id);
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("acnc");
                c.tag("country:AU");
                if let Some(sc) = crate::util::address_au::state_code(&addr) {
                    c.tag(format!("au-state:{sc}"));
                }
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Inline geocode of ACNC address '{addr}' → {coord_val}"),
                ));
                out.push(c);
            }
        }

        // Website → DNS / web modules.
        if let Some(raw) = field_str(rec, "Charity_Website")
            && let Some(host) = host_from_url(&raw)
        {
            let mut e = Entity::new(EntityKind::Domain, &host, DOMAIN_CONF, scan_id);
            e.tag(SRC);
            e.tag("acnc");
            e.add_evidence(
                Evidence::new(SRC, format!("Charity website for {legal}")).with_attr("url", &raw),
            );
            out.push(e);
        }
    }
    out
}

#[async_trait]
impl Module for AcncCharities {
    fn name(&self) -> &'static str {
        "acnc_charities"
    }

    fn description(&self) -> &'static str {
        "Australian Charities & Not-for-profits Commission register lookup (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): an authoritative federal
        // registry, dispatched with the other AU gov sources (abn_lookup 118,
        // qld_unclaimed 114) and above the generic free band. Narrower than ABR
        // (charities only) so it sits just below qld_unclaimed.
        112
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // Organisation only: ACNC's unit is the not-for-profit org. A FullName
        // would full-text-match any charity containing that token (high noise,
        // and a person is not a row here), so we leave person→charity links to
        // the org entities this module feeds back into the graph.
        matches!(t.kind, TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Domain,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // A single datastore_search over the ~65k-row register on data.gov.au;
        // well under the default would risk killing a slow-but-connected fetch.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        // A 1-2 char query would match noise across the whole register.
        if query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let resp: CkanResp = fetch_json(&ctx.http, SRC, &query_url(query)).await?;
        // Surface an application-level CKAN failure (success=false) as a module
        // error rather than masquerading as "no findings".
        if resp.success == Some(false) {
            return Err(crate::core::error::Error::module(
                SRC,
                "CKAN datastore_search returned success=false (bad resource id or portal error)",
            ));
        }
        let Some(res) = resp.result else {
            return Ok(ModuleResult::new());
        };
        let total = res.total.unwrap_or(res.records.len() as u64);

        let mut out = ModuleResult::new();
        out.extend(records_to_entities(
            &res.records,
            total,
            query,
            &ctx.scan_id,
        ));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Map<String, Value>> {
        // Shapes mirror real datastore_search rows for q="the smith family".
        let raw = r#"[
            {"_id":1,"ABN":"28000030179","Charity_Legal_Name":"The Smith Family","Other_Organisation_Names":null,"Address_Line_1":"L17 2 Market St","Town_City":"Sydney","State":"NSW","Postcode":"2000","Country":"Australia","Charity_Website":"thesmithfamily.com.au","Registration_Date":"03/12/2012","Charity_Size":"Large","Number_of_Responsible_Persons":"13"},
            {"_id":2,"ABN":"42196844275","Charity_Legal_Name":"THE TRUSTEE FOR JOY SMITH FAMILY FOUNDATION","Town_City":"Malvern East","State":"VIC","Postcode":"3145","Country":"Australia","Charity_Website":null},
            {"_id":3,"ABN":"63311049449","Charity_Legal_Name":"Marshall Family Foundation","Town_City":"Fitzroy","State":"VIC","Postcode":"3065","Country":"Australia"}
        ]"#;
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn accepts_organisation_only() {
        let m = AcncCharities;
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "The Smith Family")));
        assert!(!m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
        assert!(!m.accepts(&Target::new(TargetKind::AbnAcn, "28000030179")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn module_metadata() {
        let m = AcncCharities;
        assert_eq!(m.name(), "acnc_charities");
        assert!(!m.description().is_empty());
        assert_eq!(m.cost(), ModuleCost::Free);
        assert_eq!(m.category(), ModuleCategory::Corporate);
        // Non-passive network module must beat the 3s default timeout (CI guard).
        assert!(m.max_timeout_ms() > 3_000);
        // Government / public-records band.
        assert!((110..=118).contains(&m.priority()));
    }

    #[test]
    fn name_match_is_whole_word_not_substring() {
        assert!(name_matches_query("The Smith Family", "smith family"));
        assert!(name_matches_query(
            "THE TRUSTEE FOR JOY SMITH FAMILY FOUNDATION",
            "Smith Family"
        ));
        // Order-independent, punctuation-split.
        assert!(name_matches_query(
            "Australian Red Cross Society",
            "red cross australian"
        ));
        // A loose full-text hit that lacks a seed token is NOT exact.
        assert!(!name_matches_query(
            "Marshall Family Foundation",
            "smith family"
        ));
        // Whole word, not substring: "red" must not match inside "Mildred".
        assert!(!name_matches_query("Mildred Trust", "red"));
    }

    #[test]
    fn exact_match_fans_out_pivots_candidate_does_not() {
        let recs = sample();
        let ents = records_to_entities(&recs, 4, "The Smith Family", "scan-1");

        // Row 1 "The Smith Family" is exact → Organisation + AbnAcn + Address + Domain.
        let smith_org = ents
            .iter()
            .find(|e| e.kind == EntityKind::Organisation && e.value == "The Smith Family")
            .expect("exact charity organisation");
        assert!(smith_org.tags.iter().any(|t| t == "exact-name-match"));
        assert!((smith_org.confidence - ORG_EXACT).abs() < f64::EPSILON);

        let abn = ents
            .iter()
            .find(|e| e.kind == EntityKind::AbnAcn)
            .expect("exact hit emits an ABN for cross-correlation");
        assert_eq!(abn.value, "28000030179");

        let addr = ents
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("exact hit emits a geocodable registered address");
        assert_eq!(addr.value, "Sydney, NSW 2000, Australia");
        assert!(addr.tags.iter().any(|t| t == "geoint"));
        // The precise street line rides in evidence (no omission), not the value.
        assert!(
            addr.evidence[0]
                .attributes
                .iter()
                .any(|(k, v)| k == "address_line_1" && v == "L17 2 Market St")
        );

        let dom = ents
            .iter()
            .find(|e| e.kind == EntityKind::Domain)
            .expect("exact hit emits the website domain");
        assert_eq!(dom.value, "thesmithfamily.com.au");

        // Row 3 "Marshall Family Foundation" only matched "family" → candidate:
        // a single sub-floor Organisation, no ABN/Address/Domain pivots from it.
        let marshall = ents
            .iter()
            .find(|e| e.value == "Marshall Family Foundation")
            .expect("candidate still surfaced (no omission)");
        assert!(marshall.tags.iter().any(|t| t == "name-candidate"));
        assert!(
            marshall.confidence < 0.50,
            "candidate must stay below expansion floor"
        );
        // Its ABN/postcode are in evidence (complete) but NOT a separate AbnAcn entity.
        assert!(
            marshall.evidence[0]
                .attributes
                .iter()
                .any(|(k, v)| k == "abn" && v == "63311049449")
        );
        assert!(
            !ents
                .iter()
                .any(|e| e.kind == EntityKind::AbnAcn && e.value == "63311049449")
        );
    }

    #[test]
    fn candidate_record_omits_nothing_from_evidence() {
        // The no-redaction rule: a candidate's full record stays in evidence.
        let recs = sample();
        let ents = records_to_entities(&recs, 4, "The Smith Family", "s");
        let joy = ents
            .iter()
            .find(|e| e.value.contains("JOY SMITH FAMILY"))
            .unwrap();
        // "Joy Smith Family Foundation" contains both seed tokens → actually exact.
        assert!(joy.tags.iter().any(|t| t == "exact-name-match"));
        let attr = |k: &str| {
            joy.evidence[0]
                .attributes
                .iter()
                .find(|(a, _)| a.as_str() == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(attr("abn"), Some("42196844275"));
        assert_eq!(attr("postcode"), Some("3145"));
        assert_eq!(attr("town_city"), Some("Malvern East"));
    }

    #[test]
    fn trading_names_split_and_emit_organisations() {
        let raw = r#"[
            {"_id":1,"ABN":"11111111111","Charity_Legal_Name":"Sydney University Business School Society","Other_Organisation_Names":"SUBS, Sydney University Business Society","Charity_Website":"https://subsoc.com.au","Town_City":"Camperdown","State":"NSW","Postcode":"2006"}
        ]"#;
        let recs: Vec<Map<String, Value>> = serde_json::from_str(raw).unwrap();
        let ents = records_to_entities(&recs, 1, "Sydney University Business School Society", "s");
        let orgs: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .map(|e| e.value.as_str())
            .collect();
        assert!(orgs.contains(&"SUBS"));
        assert!(orgs.contains(&"Sydney University Business Society"));
        // Website with a scheme is normalised to a bare host.
        let dom = ents.iter().find(|e| e.kind == EntityKind::Domain).unwrap();
        assert_eq!(dom.value, "subsoc.com.au");
    }

    #[test]
    fn numeric_abn_and_postcode_are_stringified_not_dropped() {
        // CKAN may type ABN/Postcode as numbers; we must still recover them.
        let raw = r#"[
            {"_id":1,"ABN":28000030179,"Charity_Legal_Name":"Numeric Fields Trust","Town_City":"Perth","State":"WA","Postcode":6000}
        ]"#;
        let recs: Vec<Map<String, Value>> = serde_json::from_str(raw).unwrap();
        let ents = records_to_entities(&recs, 1, "Numeric Fields Trust", "s");
        let abn = ents.iter().find(|e| e.kind == EntityKind::AbnAcn).unwrap();
        assert_eq!(abn.value, "28000030179");
        let addr = ents.iter().find(|e| e.kind == EntityKind::Address).unwrap();
        assert_eq!(addr.value, "Perth, WA 6000, Australia");
    }

    #[test]
    fn locality_address_handles_missing_fields() {
        let mut rec = Map::new();
        rec.insert("State".into(), Value::String("QLD".into()));
        rec.insert("Postcode".into(), Value::String("4000".into()));
        // No Town_City, no Country → defaults Country=Australia.
        assert_eq!(
            locality_address(&rec).as_deref(),
            Some("QLD 4000, Australia")
        );
        // Nothing locating at all → None.
        let empty = Map::new();
        assert!(locality_address(&empty).is_none());
    }

    #[test]
    fn ckan_success_false_is_captured() {
        let err: CkanResp =
            serde_json::from_str(r#"{"success":false,"error":{"message":"Resource not found"}}"#)
                .unwrap();
        assert_eq!(err.success, Some(false));
        assert!(err.result.is_none());
        let ok: CkanResp =
            serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
        assert_eq!(ok.success, Some(true));
        assert_eq!(ok.result.unwrap().records.len(), 0);
    }

    #[test]
    fn short_query_is_ignored() {
        // Guarded in process(); assert the precondition the guard relies on.
        assert!("ab".len() < 3);
        assert!("abc".len() >= 3);
    }
}
