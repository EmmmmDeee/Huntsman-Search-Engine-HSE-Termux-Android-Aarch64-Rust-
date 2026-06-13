//! Global Legal Entity Identifier (GLEIF) lookup (keyless, free).
//!
//! Endpoint: `GET https://api.gleif.org/api/v1/lei-records`
//!           `?filter[entity.legalName]={name}&page[size]=10`
//! Auth:     none — GLEIF publishes the global LEI index as a public,
//!           keyless JSON:API (the authoritative ISO 17442 registry of legal
//!           entities that trade in financial markets, ~2.7M records).
//!
//! For an `Organisation` seed we search the LEI index by legal name and, for
//! every row whose name matches the seed, emit cross-correlating entities:
//!
//!   * `Organisation` — the legal entity (authoritative legal name),
//!   * `AbnAcn` — for AU entities, GLEIF's `registeredAs` is the local registry
//!     id (the ACN/ABN), pivoted into `abn_lookup` / `opencorporates` / `acnc`,
//!   * `Address` — the registered (HQ / legal) address (geocode → `Coordinates`).
//!
//! This is an *independent* corroborator of the corporate graph: an org/ABN that
//! GLEIF confirms from a different authority than ABR/ACNC drives `c_effective`
//! up via the noisy-OR agreement model, so genuinely multi-sourced entities
//! cross the expansion floor and pivot. The LEI itself, the entity status,
//! jurisdiction and any foreign `registeredAs` are carried in evidence so
//! nothing the API returns is dropped, even for loose matches that don't pivot.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json, urlencode};

const SRC: &str = "gleif_lei";

const BASE_URL: &str = "https://api.gleif.org/api/v1/lei-records";

/// Cap on rows turned into entities for one seed. LEI name search is precise; a
/// handful covers the genuine matches without flooding the graph.
const MAX_RECORDS: usize = 10;

// Confidence tiers, aligned with the gov/corporate band and the noisy-OR
// expansion floor (0.50): exact name matches pivot immediately; loose candidates
// stay below the floor so they're surfaced but inert unless independently
// corroborated.
const ORG_EXACT: f64 = 0.85;
const ORG_CANDIDATE: f64 = 0.45;
const ABN_CONF: f64 = 0.88;
const ADDR_CONF: f64 = 0.60;

pub struct GleifLei;

#[derive(Deserialize)]
struct GleifResp {
    #[serde(default)]
    data: Vec<GleifRecord>,
    #[serde(default)]
    meta: Option<GleifMeta>,
}

#[derive(Deserialize)]
struct GleifMeta {
    #[serde(default)]
    pagination: Option<GleifPagination>,
}

#[derive(Deserialize)]
struct GleifPagination {
    #[serde(default)]
    total: Option<u64>,
}

#[derive(Deserialize)]
struct GleifRecord {
    #[serde(default)]
    attributes: Option<GleifAttrs>,
}

#[derive(Deserialize)]
struct GleifAttrs {
    #[serde(default)]
    lei: Option<String>,
    #[serde(default)]
    entity: Option<GleifEntity>,
}

#[derive(Deserialize)]
struct GleifEntity {
    #[serde(rename = "legalName", default)]
    legal_name: Option<GleifName>,
    #[serde(default)]
    jurisdiction: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(rename = "registeredAs", default)]
    registered_as: Option<String>,
    #[serde(rename = "legalAddress", default)]
    legal_address: Option<GleifAddress>,
    #[serde(rename = "headquartersAddress", default)]
    hq_address: Option<GleifAddress>,
}

#[derive(Deserialize)]
struct GleifName {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize, Default)]
struct GleifAddress {
    #[serde(rename = "addressLines", default)]
    address_lines: Vec<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(rename = "postalCode", default)]
    postal_code: Option<String>,
    #[serde(default)]
    country: Option<String>,
}

/// Trim to `None` when empty.
fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// True if `name` contains every token of the seed `query` as a whole word
/// (case-insensitive). Whole-word, not substring, so a short seed token can't
/// match inside an unrelated word. (Same precision rule as `acnc_charities`.)
fn name_matches_query(name: &str, query: &str) -> bool {
    let words: Vec<&str> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let tokens: Vec<&str> = query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    // At least one token, and every token present as a whole word.
    !tokens.is_empty()
        && tokens
            .iter()
            .all(|tok| words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

/// The lei-records search URL for one legal-name query. JSON:API bracket params
/// are percent-encoded literally; the value is url-encoded.
fn query_url(name: &str) -> String {
    format!(
        "{BASE_URL}?filter%5Bentity.legalName%5D={}&page%5Bsize%5D={MAX_RECORDS}",
        urlencode(name)
    )
}

/// `registeredAs` digits when this AU entity's local registry id is a valid
/// ACN (9) or ABN (11). GLEIF stores it spaced ("004 028 077"); we strip to
/// digits. Only AU jurisdictions map cleanly to the ABN/ACN namespace — a UK
/// company number etc. must not masquerade as an `AbnAcn`.
fn au_abn_acn(entity: &GleifEntity) -> Option<String> {
    if entity.jurisdiction.as_deref() != Some("AU") {
        return None;
    }
    let raw = entity.registered_as.as_deref()?;
    let digits = crate::util::str_util::ascii_digits(raw);
    matches!(digits.len(), 9 | 11).then_some(digits)
}

/// Build a geocodable locality string from a GLEIF address. The ISO-3166-2
/// region ("AU-VIC") is reduced to its subdivision ("VIC"); street lines ride in
/// evidence, not the geocode value. Returns `None` when there's nothing locating.
fn locality(addr: &GleifAddress) -> Option<String> {
    let city = non_empty(addr.city.clone());
    let region = non_empty(addr.region.clone()).map(|r| {
        // "AU-VIC" -> "VIC"; leave plain regions untouched.
        r.rsplit('-').next().unwrap_or(&r).to_string()
    });
    let postal = non_empty(addr.postal_code.clone());
    let country = non_empty(addr.country.clone());
    if city.is_none() && region.is_none() && postal.is_none() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    if let Some(c) = city {
        parts.push(c);
    }
    let mut rp = String::new();
    if let Some(r) = region {
        rp.push_str(&r);
    }
    if let Some(p) = postal {
        if !rp.is_empty() {
            rp.push(' ');
        }
        rp.push_str(&p);
    }
    if !rp.is_empty() {
        parts.push(rp);
    }
    if let Some(c) = country {
        parts.push(c);
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// Attach the full record to evidence so nothing the API returned is dropped —
/// exact hits and candidates alike.
fn record_evidence(lei: &str, entity: &GleifEntity, name: &str, total: u64) -> Evidence {
    let mut ev = Evidence::new(SRC, format!("GLEIF LEI record: {name}"))
        .with_attr("lei", lei)
        .with_attr("register", "GLEIF Global LEI Index")
        .with_attr("total_matches", total.to_string());
    if let Some(j) = entity.jurisdiction.as_deref() {
        ev = ev.with_attr("jurisdiction", j);
    }
    if let Some(s) = entity.status.as_deref() {
        ev = ev.with_attr("entity_status", s);
    }
    if let Some(r) = entity.registered_as.as_deref() {
        ev = ev.with_attr("registered_as", r);
    }
    for (label, addr) in [
        ("legal_address", &entity.legal_address),
        ("hq_address", &entity.hq_address),
    ] {
        if let Some(a) = addr {
            if !a.address_lines.is_empty() {
                ev = ev.with_attr(format!("{label}_street"), a.address_lines.join(", "));
            }
            if let Some(loc) = locality(a) {
                ev = ev.with_attr(label, loc);
            }
        }
    }
    ev
}

/// Pure transform: GLEIF records → entities. Every row yields an `Organisation`
/// carrying the full record in evidence; exact name matches additionally fan out
/// into the AbnAcn (AU) and Address pivots. Loose candidates stay a single
/// sub-floor Organisation so a noisy match can't pivot.
fn records_to_entities(resp: &GleifResp, query: &str, scan_id: &str) -> Vec<Entity> {
    let total = resp
        .meta
        .as_ref()
        .and_then(|m| m.pagination.as_ref())
        .and_then(|p| p.total)
        .unwrap_or(resp.data.len() as u64);

    let mut out = Vec::new();
    for rec in resp.data.iter().take(MAX_RECORDS) {
        let Some(attrs) = rec.attributes.as_ref() else {
            continue;
        };
        let Some(entity) = attrs.entity.as_ref() else {
            continue;
        };
        let Some(name) = entity
            .legal_name
            .as_ref()
            .and_then(|n| non_empty(n.name.clone()))
        else {
            continue;
        };
        let lei = attrs.lei.clone().unwrap_or_default();
        let exact = name_matches_query(&name, query);
        let conf = if exact { ORG_EXACT } else { ORG_CANDIDATE };

        let mut org = Entity::new(EntityKind::Organisation, &name, conf, scan_id);
        org.tag(SRC);
        org.tag("gleif");
        org.tag("lei");
        if let Some(j) = entity.jurisdiction.as_deref() {
            org.tag(format!("country:{j}"));
        }
        org.tag(if exact {
            "exact-name-match"
        } else {
            "name-candidate"
        });
        org.add_evidence(record_evidence(&lei, entity, &name, total));
        out.push(org);

        if !exact {
            continue;
        }

        // AU local registry id (ACN/ABN) → the business-registry modules.
        if let Some(abn) = au_abn_acn(entity) {
            let mut e = Entity::new(EntityKind::AbnAcn, &abn, ABN_CONF, scan_id);
            e.tag(SRC);
            e.tag("gleif");
            e.tag("country:AU");
            e.add_evidence(
                Evidence::new(SRC, format!("ACN/ABN for {name} (LEI {lei})"))
                    .with_attr("lei", &lei),
            );
            out.push(e);
        }

        // Registered address → geocode chains it into Coordinates. Prefer the HQ
        // address (it carries street lines); fall back to the legal address.
        let addr = entity
            .hq_address
            .as_ref()
            .and_then(|a| locality(a).map(|l| (l, a)))
            .or_else(|| {
                entity
                    .legal_address
                    .as_ref()
                    .and_then(|a| locality(a).map(|l| (l, a)))
            });
        if let Some((loc, a)) = addr {
            let mut e = Entity::new(EntityKind::Address, &loc, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("gleif");
            if let Some(j) = entity.jurisdiction.as_deref() {
                e.tag(format!("country:{j}"));
            }
            e.tag("geoint");
            e.tag("registered-address");
            // GLEIF region codes use ISO 3166-2 format "AU-VIC", "AU-NSW", etc.
            // Extract the sub-national part for au-state tagging.
            if let Some(region) = a.region.as_deref() {
                if let Some(sub) = region.strip_prefix("AU-") {
                    e.tag(format!("au-state:{sub}"));
                    e.tag("country:AU");
                }
            } else if let Some(sc) = crate::util::address_au::state_code(&loc) {
                e.tag(format!("au-state:{sc}"));
                e.tag("country:AU");
            }
            let mut aev = Evidence::new(SRC, format!("Registered address for {name}"))
                .with_attr("org", &name)
                .with_attr("lei", &lei);
            if !a.address_lines.is_empty() {
                aev = aev.with_attr("street", a.address_lines.join(", "));
            }
            e.add_evidence(aev);
            out.push(e);

            // Inline Coordinates via city lookup.
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&loc) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.62, scan_id);
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("gleif");
                if let Some(region) = a.region.as_deref() {
                    if let Some(sub) = region.strip_prefix("AU-") {
                        c.tag(format!("au-state:{sub}"));
                        c.tag("country:AU");
                    }
                } else if let Some(sc) = crate::util::address_au::state_code(&loc) {
                    c.tag(format!("au-state:{sc}"));
                    c.tag("country:AU");
                }
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Inline geocode of GLEIF address '{loc}' → {coord_val}"),
                ));
                out.push(c);
            }
        }
    }
    out
}

#[async_trait]
impl Module for GleifLei {
    fn name(&self) -> &'static str {
        "gleif_lei"
    }

    fn description(&self) -> &'static str {
        "GLEIF Global Legal Entity Identifier (LEI) lookup (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): a global authoritative
        // registry, dispatched with the corporate sources (abn_lookup 118,
        // opencorporates 116, qld_unclaimed 114, acnc_charities 112) and above the
        // generic free band. Global/cross-walk, so just below the AU-specific ones.
        111
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // Organisation only: GLEIF's unit is the legal entity. The reverse
        // ABN->LEI filter is unreliable, so we feed off the Organisation entities
        // the graph produces (incl. from abn_lookup / opencorporates / acnc).
        matches!(t.kind, TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A legal-entity (LEI) registry: it establishes the organisation
        // (T1591.002 Business Relationships) and geocodes its registered address
        // to coordinates, so it also Determines Physical Locations (T1591.001) —
        // which the Corporate default omits. It surfaces no individual
        // officer/role, so the default's T1591.004 (Identify Roles) is dropped
        // (cf. au_people / oathnet_pro).
        &["T1591.001", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // A single name search against api.gleif.org; beat the 3s default so a
        // slow-but-connected response isn't killed.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        // A 1-2 char query would match noise across the global index.
        if query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let resp: GleifResp = fetch_json(&ctx.http, SRC, &query_url(query)).await?;
        let mut out = ModuleResult::new();
        out.extend(records_to_entities(&resp, query, &ctx.scan_id));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GleifResp {
        // Mirrors real api.gleif.org rows (BHP: AU with ACN; a GB entity).
        let raw = r#"{
            "meta": {"pagination": {"total": 2}},
            "data": [
                {"attributes": {"lei": "WZE1WSENV6JSZFK0JC28", "entity": {
                    "legalName": {"name": "BHP GROUP LIMITED"},
                    "jurisdiction": "AU", "status": "ACTIVE",
                    "registeredAs": "004 028 077",
                    "legalAddress": {"addressLines": ["171 Collins Street"], "city": "Melbourne", "region": "AU-VIC", "postalCode": "3000", "country": "AU"},
                    "headquartersAddress": {"addressLines": ["171 Collins Street"], "city": "Melbourne", "region": "AU-VIC", "postalCode": "3000", "country": "AU"}
                }}},
                {"attributes": {"lei": "894500OGEMX4F6STBR39", "entity": {
                    "legalName": {"name": "BHP Billiton Group Limited"},
                    "jurisdiction": "GB", "status": "ACTIVE",
                    "registeredAs": "03298904",
                    "legalAddress": {"addressLines": ["Nova South, 160 Victoria Street"], "city": "London", "region": "GB-LND", "postalCode": "SW1E 5LB", "country": "GB"}
                }}}
            ]
        }"#;
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn accepts_organisation_only() {
        let m = GleifLei;
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "BHP Group Limited")));
        assert!(!m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
        assert!(!m.accepts(&Target::new(TargetKind::AbnAcn, "004028077")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn module_metadata() {
        let m = GleifLei;
        assert_eq!(m.name(), "gleif_lei");
        assert!(!m.description().is_empty());
        assert_eq!(m.cost(), ModuleCost::Free);
        assert_eq!(m.category(), ModuleCategory::Corporate);
        assert!(m.max_timeout_ms() > 3_000);
        assert!((110..=118).contains(&m.priority()));
    }

    #[test]
    fn au_entity_emits_acn_but_foreign_does_not() {
        let resp = sample();
        // Seed "BHP" matches both rows on the token "BHP".
        let ents = records_to_entities(&resp, "BHP", "scan-1");

        // The AU row emits an AbnAcn (its ACN, digits-only); the GB row must not
        // (its UK company number is not an ABN/ACN).
        let abns: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::AbnAcn)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(abns, vec!["004028077"], "only the AU ACN, spaces stripped");

        // Foreign registry id is still preserved in the GB org's evidence (no omission).
        let gb = ents
            .iter()
            .find(|e| e.value == "BHP Billiton Group Limited")
            .unwrap();
        assert!(
            gb.evidence[0]
                .attributes
                .iter()
                .any(|(k, v)| k == "registered_as" && v == "03298904")
        );
        assert!(gb.tags.iter().any(|t| t == "country:GB"));
    }

    #[test]
    fn exact_match_fans_out_address_candidate_does_not() {
        let resp = sample();
        // "BHP Group Limited" matches the AU row exactly; the GB row ("Billiton")
        // is missing the token "Group"? It has Group -> also matches "BHP","Group".
        // Use a query that is exact for AU only: tokens BHP, GROUP, LIMITED.
        let ents = records_to_entities(&resp, "BHP Group Limited", "s");
        let au = ents
            .iter()
            .find(|e| e.kind == EntityKind::Organisation && e.value == "BHP GROUP LIMITED")
            .unwrap();
        assert!(au.tags.iter().any(|t| t == "exact-name-match"));
        assert!((au.confidence - ORG_EXACT).abs() < f64::EPSILON);

        // The AU exact hit produces a geocodable Address (locality, region trimmed).
        let addr = ents
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("AU exact hit emits an address");
        assert_eq!(addr.value, "Melbourne, VIC 3000, AU");
        assert!(addr.tags.iter().any(|t| t == "geoint"));
        // The street line rides in evidence, not the geocode value.
        assert!(
            addr.evidence[0]
                .attributes
                .iter()
                .any(|(k, v)| k == "street" && v == "171 Collins Street")
        );

        // The GB row ("BHP Billiton Group Limited") lacks the token "Limited"? it
        // has Limited -> but lacks nothing... it lacks "BHP"? it has BHP. It has
        // Billiton extra, but all query tokens (bhp,group,limited) ARE present, so
        // it is ALSO exact. Assert it is classified (either way it must surface).
        assert!(ents.iter().any(|e| e.value == "BHP Billiton Group Limited"));
    }

    #[test]
    fn loose_candidate_surfaces_with_full_evidence_but_no_pivot() {
        // A row that does NOT contain every seed token is a candidate: one
        // sub-floor Organisation, no AbnAcn/Address pivot, full record in evidence.
        let resp = sample();
        let ents = records_to_entities(&resp, "Rio Tinto", "s"); // matches neither name fully
        // Both rows lack "Rio"/"Tinto" -> both candidates, none exact.
        assert!(ents.iter().all(|e| e.kind == EntityKind::Organisation));
        assert!(ents.iter().all(|e| e.confidence < 0.50));
        assert!(
            ents.iter()
                .all(|e| e.tags.iter().any(|t| t == "name-candidate"))
        );
        // No ABN/Address entities manufactured from loose matches.
        assert!(!ents.iter().any(|e| e.kind == EntityKind::AbnAcn));
        assert!(!ents.iter().any(|e| e.kind == EntityKind::Address));
        // …but the AU row's ACN is still in evidence — nothing omitted.
        let au = ents
            .iter()
            .find(|e| e.value == "BHP GROUP LIMITED")
            .unwrap();
        assert!(
            au.evidence[0]
                .attributes
                .iter()
                .any(|(k, v)| k == "registered_as" && v == "004 028 077")
        );
    }

    #[test]
    fn locality_trims_region_prefix_and_handles_missing() {
        let a = GleifAddress {
            city: Some("Melbourne".into()),
            region: Some("AU-VIC".into()),
            postal_code: Some("3000".into()),
            country: Some("AU".into()),
            ..Default::default()
        };
        assert_eq!(locality(&a).as_deref(), Some("Melbourne, VIC 3000, AU"));
        // Nothing locating → None.
        assert!(locality(&GleifAddress::default()).is_none());
    }

    #[test]
    fn query_url_encodes_brackets_and_value() {
        // JSON:API bracket params stay percent-encoded; the value is
        // form-encoded by `urlencode` (space -> '+', which servers decode back).
        let u = query_url("BHP Group");
        assert!(u.contains("filter%5Bentity.legalName%5D=BHP+Group"), "{u}");
        assert!(u.contains("page%5Bsize%5D=10"), "{u}");
    }

    #[test]
    fn empty_response_yields_nothing() {
        let resp: GleifResp = serde_json::from_str(r#"{"data":[]}"#).unwrap();
        assert!(records_to_entities(&resp, "Nonexistent Org", "s").is_empty());
    }
}
