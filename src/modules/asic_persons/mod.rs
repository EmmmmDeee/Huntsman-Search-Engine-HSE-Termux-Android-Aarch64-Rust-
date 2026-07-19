//! ASIC people registers — banned/disqualified persons, financial advisers, and
//! credit/finance-broker representatives. Free, **no API key** (the open
//! data.gov.au datastore, unlike the key-gated [`crate::modules::abn_lookup`]).
//!
//! For a personal name this queries three authoritative ASIC registers the
//! corporate regulator publishes as open data:
//!
//! * **Banned & Disqualified Persons** — people ASIC has banned from providing
//!   financial services or disqualified from managing corporations. A hit is a
//!   high-signal adverse finding (the ban type, period, and the person's
//!   suburb/state).
//! * **Financial Advisers Register** — every current/former licensed financial
//!   adviser: their role and registration status, the **licensee they operate
//!   under** (employer), its AFS licence number and ABN, and any recorded
//!   **disciplinary action**.
//! * **Credit Representatives** — mortgage and finance brokers authorised under
//!   a credit licence: the rep's ABN/ACN, the credit licence they act under, and
//!   their authorisation period and registered locality — a distinct lending
//!   industry the advisers register doesn't cover.
//!
//! Each is queried by name through the data.gov.au CKAN `datastore_search`
//! API (full-text, keyless) and matched on all of the target's name tokens. The
//! findings are synergistic: the licensee becomes an `Organisation`, its ABN an
//! `AbnAcn`, and the registered address an `Address`, each a pivot into the rest
//! of the AU stack ([`crate::modules::abn_lookup`], `asic_director`,
//! `au_property`, `geocode`). No mock: the JSON is fetched live from ASIC's own
//! open dataset.

use serde_json::{Map, Value};

use async_trait::async_trait;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::{Response as CkanResp, datastore_search_url, field_str};
use crate::util::http::fetch_json;

const SRC: &str = "asic_persons";
/// data.gov.au CKAN action base — `datastore_search` is appended by
/// [`datastore_search_url`].
const CKAN_BASE: &str = "https://data.gov.au/data/api/3/action";
/// ASIC – Banned and Disqualified Persons dataset (data.gov.au resource).
const BANNED_RES: &str = "741da9e3-7e0c-458e-830c-c518698e1788";
/// ASIC – Financial Advisers dataset (data.gov.au resource).
const ADVISER_RES: &str = "91d80440-5787-46fc-99de-0c1d93e6cc9f";
/// ASIC – Credit Representative dataset (mortgage/finance brokers).
const CREDIT_RES: &str = "999d9e92-df2c-4d6d-b580-321dcd205292";
/// Max matched records surfaced per register. Raised to the query `limit` so no
/// genuine register hit is omitted (directive: never omit an API-derived AU
/// government result); the per-row name classifier still gates quality.
const MAX_HITS: usize = 100;

pub struct AsicPersons;

#[async_trait]
impl Module for AsicPersons {
    fn name(&self) -> &'static str {
        "asic_persons"
    }

    fn description(&self) -> &'static str {
        "ASIC people-registers recon (keyless) — pivots a name across banned & disqualified, financial advisers, and credit/finance-broker representatives to regulatory status, licensee, disciplinary action, and address"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band, alongside the other AU registries.
        112
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only; the multi-token name gate is applied in process().
        matches!(t.kind, TargetKind::FullName)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Confirms a person's role (adviser/licensee — T1591.004), the business
        // relationship to that licensee (T1591.002), and their registered
        // location (T1591.001).
        &["T1591.002", "T1591.004", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let tokens = name_tokens(&target.value);
        // A single token is too ambiguous for a national name register.
        if tokens.len() < 2 {
            return Ok(result);
        }

        let (banned, advisers, credit) = tokio::join!(
            ckan_query(ctx, BANNED_RES, &target.value),
            ckan_query(ctx, ADVISER_RES, &target.value),
            ckan_query(ctx, CREDIT_RES, &target.value),
        );

        // The three registers are independent concurrent CKAN queries (T2.118),
        // so this mirrors `niamonx`'s multi-endpoint fold (T2.114): the last
        // hard failure across them is remembered, real evidence from any register
        // that DID answer is always kept, and only a genuine zero-evidence
        // outcome with at least one real failure surfaces as an error via
        // `ModuleResult::or_hard_failure` — a total data.gov.au outage no longer
        // reads as "this person is in none of ASIC's people registers".
        let mut hard_failure: Option<Error> = None;
        match banned {
            Ok(records) => {
                for rec in records
                    .iter()
                    .filter(|r| record_name_matches(r, "BD_PER_NAME", &tokens))
                    .take(MAX_HITS)
                {
                    emit_banned(rec, &ctx.scan_id, &mut result);
                }
            }
            Err(e) => {
                hard_failure.get_or_insert(e);
            }
        }
        match advisers {
            Ok(records) => {
                for rec in records
                    .iter()
                    .filter(|r| record_name_matches(r, "ADV_NAME", &tokens))
                    .take(MAX_HITS)
                {
                    emit_adviser(rec, &ctx.scan_id, &mut result);
                }
            }
            Err(e) => {
                hard_failure.get_or_insert(e);
            }
        }
        match credit {
            Ok(records) => {
                for rec in records
                    .iter()
                    .filter(|r| record_name_matches(r, "CRED_REP_NAME", &tokens))
                    .take(MAX_HITS)
                {
                    emit_credit_rep(rec, &ctx.scan_id, &mut result);
                }
            }
            Err(e) => {
                hard_failure.get_or_insert(e);
            }
        }

        result.or_hard_failure(hard_failure)
    }
}

/// Query one CKAN datastore resource by free-text name, via the shared CKAN
/// envelope (T2.118). Returns the matched records, or a real `Error` when the
/// register genuinely failed to answer — a transport error, non-2xx status, or
/// unparseable body (propagated by `fetch_json` via `?`), or a CKAN application
/// error (`success: false`, which CKAN returns with HTTP 200 on a bad resource
/// id / offline datastore / rate-limit). Previously every one of these
/// collapsed into an empty `Vec` indistinguishable from a genuine "not in this
/// register"; `process()` now folds the three registers' results so a real
/// outage surfaces instead (see its `or_hard_failure` fold).
async fn ckan_query(
    ctx: &ModuleContext,
    resource_id: &str,
    name: &str,
) -> Result<Vec<Map<String, Value>>> {
    let url = datastore_search_url(CKAN_BASE, resource_id, name, MAX_HITS);
    let resp: CkanResp = fetch_json(&ctx.http, SRC, &url).await?;
    if resp.success == Some(false) {
        return Err(Error::module(
            SRC,
            "CKAN datastore_search returned success=false (bad resource id or portal error)",
        ));
    }
    Ok(resp.result.map(|r| r.records).unwrap_or_default())
}

/// Lower-cased alphabetic name tokens (≥2 chars) of a full name.
fn name_tokens(full: &str) -> Vec<String> {
    full.split(|c: char| !c.is_alphabetic())
        .filter(|t| t.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// True if a record's name field contains every target token (order-independent,
/// so `"Bill Abbott"` matches `"ABBOTT, BILL"`).
fn record_name_matches(rec: &Map<String, Value>, name_field: &str, tokens: &[String]) -> bool {
    let Some(name) = field(rec, name_field) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    tokens.iter().all(|t| lower.contains(t.as_str()))
}

/// Normalise a name/organisation string for order-preserving equality: trim,
/// collapse internal whitespace, upper-case. Used to tell a genuinely-distinct
/// appointing firm apart from a self-appointment or the licensee itself.
fn norm_name(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

/// Classify a linked register name (a licensee controller) by shape: a corporate
/// legal-form suffix (`looks_like_company`) → an `Organisation` kept
/// as-registered; otherwise the controller is a natural person — a small firm's
/// controlling principal — surfaced as a humanised `Person`. Both are public
/// regulatory-ownership relationships, not contact PII. **Pure.**
fn classify_linked(name: &str) -> (EntityKind, String) {
    if crate::util::abn::looks_like_company(name) {
        (EntityKind::Organisation, name.trim().to_string())
    } else {
        (EntityKind::Person, humanise_name(name))
    }
}

/// Parse ASIC's `LICENCE_CONTROLLED_BY` field into `(controller, ceased_date)`
/// pairs. The field lists one or more controlling entities separated by `~`,
/// each optionally suffixed with a bracketed status marker, e.g.
/// `"NATIONAL AUSTRALIA BANK LIMITED [Date Ceased: 21/08/2023] ~ MLC WEALTH LIMITED [Date Ceased: 20/05/2021]"`.
/// The controller name is everything before the first `[`; a `Date Ceased:`
/// value inside the marker (a historical controller) is returned alongside.
/// **Pure.** Entries whose cleaned name is under 3 chars are dropped.
fn parse_controllers(raw: &str) -> Vec<(String, Option<String>)> {
    raw.split('~')
        .filter_map(|part| {
            let part = part.trim();
            let name = part.split('[').next().unwrap_or(part).trim();
            if name.len() < 3 {
                return None;
            }
            let ceased = part
                .split_once("Date Ceased:")
                .and_then(|(_, rest)| rest.split(']').next())
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(str::to_string);
            Some((name.to_string(), ceased))
        })
        .collect()
}

/// Emit the banned/disqualified finding: an adverse-flagged Person plus the
/// registered address.
fn emit_banned(rec: &Map<String, Value>, scan_id: &str, result: &mut ModuleResult) {
    let Some(raw_name) = field(rec, "BD_PER_NAME") else {
        return;
    };
    let person_name = humanise_name(&raw_name);

    let mut ev = Evidence::new(SRC, format!("ASIC banned/disqualified: {person_name}"))
        .with_attr("register", "ASIC Banned & Disqualified Persons")
        .with_attr("matched_name", &raw_name);
    for (key, attr) in [
        ("BD_PER_TYPE", "ban_type"),
        ("BD_PER_START_DT", "ban_start"),
        ("BD_PER_END_DT", "ban_end"),
        ("BD_PER_DOC_NUM", "document_no"),
        ("BD_PER_COMMENTS", "comments"),
    ] {
        if let Some(v) = field(rec, key) {
            ev = ev.with_attr(attr, v);
        }
    }

    let mut p = Entity::new(EntityKind::Person, &person_name, confidence::MEDIUM_PLUS, scan_id);
    p.tag("au");
    p.tag("asic");
    p.tag("asic-banned");
    p.tag("regulatory-action");
    p.add_evidence(ev.clone());
    result.push(p);

    push_address(
        rec,
        "BD_PER_ADD_LOCAL",
        "BD_PER_ADD_STATE",
        "BD_PER_ADD_PCODE",
        &person_name,
        "asic-banned",
        scan_id,
        result,
    );
}

/// Emit the financial-adviser profile: the adviser Person, the licensee
/// Organisation + ABN, any disciplinary action, and the registered address.
fn emit_adviser(rec: &Map<String, Value>, scan_id: &str, result: &mut ModuleResult) {
    let Some(raw_name) = field(rec, "ADV_NAME") else {
        return;
    };
    let person_name = humanise_name(&raw_name);
    let has_discipline = field(rec, "ADV_DA_TYPE").is_some();

    let mut ev = Evidence::new(SRC, format!("ASIC financial adviser: {person_name}"))
        .with_attr("register", "ASIC Financial Advisers")
        .with_attr("matched_name", &raw_name);
    for (key, attr) in [
        ("ADV_ROLE", "adviser_role"),
        ("OVERALL_REGISTRATION_STATUS", "registration_status"),
        ("ADV_NUMBER", "adviser_number"),
        ("ADV_FIRST_PROVIDED_ADVICE", "first_advice"),
        ("LICENCE_NAME", "licensee"),
        ("LICENCE_NUMBER", "afs_licence_no"),
        ("LICENCE_CONTROLLED_BY", "licensee_controlled_by"),
        ("REP_APPOINTED_BY", "appointed_by"),
        ("REP_APPOINTED_NUM", "authorised_rep_no"),
        ("ADV_DA_TYPE", "disciplinary_action"),
        ("ADV_DA_DESCRIPTION", "disciplinary_detail"),
    ] {
        if let Some(v) = field(rec, key) {
            ev = ev.with_attr(attr, v);
        }
    }

    let mut p = Entity::new(EntityKind::Person, &person_name, confidence::MEDIUM_PLUS, scan_id);
    p.tag("au");
    p.tag("asic");
    p.tag("asic-financial-adviser");
    if has_discipline {
        p.tag("regulatory-action");
        p.tag("disciplinary-action");
    }
    p.add_evidence(ev.clone());
    result.push(p);

    // The licensee the adviser operates under — an employer/affiliation pivot.
    let licensee = field(rec, "LICENCE_NAME");
    if let Some(licensee) = &licensee {
        let mut org = Entity::new(EntityKind::Organisation, licensee, 0.62, scan_id);
        org.tag("au");
        org.tag("asic");
        org.tag("afs-licensee");
        let mut oev = Evidence::new(SRC, format!("AFS licensee of adviser {person_name}"))
            .with_attr("licensee", licensee);
        if let Some(no) = field(rec, "LICENCE_NUMBER") {
            oev = oev.with_attr("afs_licence_no", no);
        }
        org.add_evidence(oev);
        result.push(org);
    }

    // Corporate controller(s) of the AFS licensee — the ultimate parent behind
    // the licence, a marquee ownership pivot: a small-looking advice firm is
    // frequently `LICENCE_CONTROLLED_BY` a major bank / wealth group. The field
    // is a `~`-separated list, each entry optionally carrying a
    // `[Date Ceased: DD/MM/YYYY]` marker for a historical controller.
    if let Some(raw) = field(rec, "LICENCE_CONTROLLED_BY") {
        for (name, ceased) in parse_controllers(&raw) {
            let (kind, value) = classify_linked(&name);
            let mut ent = Entity::new(kind, &value, 0.58, scan_id);
            ent.tag("au");
            ent.tag("asic");
            ent.tag("afs-licensee-controller");
            let mut cev = Evidence::new(
                SRC,
                format!(
                    "Controls AFS licensee {} (adviser {person_name})",
                    licensee.as_deref().unwrap_or("(unknown)")
                ),
            )
            .with_attr("relationship", "licence_controlled_by");
            if let Some(l) = &licensee {
                cev = cev.with_attr("controls_licensee", l);
            }
            if let Some(d) = ceased {
                ent.tag("ceased");
                cev = cev.with_attr("date_ceased", d);
            }
            ent.add_evidence(cev);
            result.push(ent);
        }
    }

    // The corporate authorised representative that appointed the adviser. Often
    // a distinct practice/firm sitting BETWEEN the adviser and the licensee
    // (e.g. the adviser's own named practice), so it is a stronger personal
    // attribution pivot than the big licensee. Emitted only when it differs from
    // both the adviser's own name (a self-appointment) and the licensee (already
    // captured above) AND is company-shaped — the corporate-AR relationship is
    // inherently corporate, so a person-shaped distinct appointer is treated as
    // ambiguous noise and skipped for precision.
    if let Some(appby) = field(rec, "REP_APPOINTED_BY") {
        let n = norm_name(&appby);
        let is_self = n == norm_name(&raw_name);
        let is_licensee = licensee.as_deref().is_some_and(|l| n == norm_name(l));
        if !is_self && !is_licensee && crate::util::abn::looks_like_company(&appby) {
            let mut org = Entity::new(EntityKind::Organisation, &appby, confidence::MEDIUM_PLUS, scan_id);
            org.tag("au");
            org.tag("asic");
            org.tag("authorised-rep-firm");
            let mut aev = Evidence::new(SRC, format!("Appointed {person_name} as authorised rep"))
                .with_attr("relationship", "rep_appointed_by");
            if let Some(num) = field(rec, "REP_APPOINTED_NUM") {
                aev = aev.with_attr("authorised_rep_no", num);
            }
            org.add_evidence(aev);
            result.push(org);
        }
    }

    // ABNs: the adviser's own, the licensee's, and the appointing rep firm's —
    // each a pivot into the ABR/ASIC. Dedup merges any that coincide.
    for (key, label) in [
        ("ADV_ABN", "adviser"),
        ("LICENCE_ABN", "licensee"),
        ("REP_APPOINTED_ABN", "rep_appointer"),
    ] {
        if let Some(abn) =
            field(rec, key).filter(|a| a.chars().filter(char::is_ascii_digit).count() == 11)
        {
            let mut e = Entity::new(EntityKind::AbnAcn, &abn, 0.62, scan_id);
            e.tag("au");
            e.tag("asic");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("{label} ABN from ASIC adviser record of {person_name}"),
                )
                .with_attr("abn", &abn)
                .with_attr("role", label),
            );
            result.push(e);
        }
    }

    push_address(
        rec,
        "ADV_ADD_LOCAL",
        "ADV_ADD_STATE",
        "ADV_ADD_PCODE",
        &person_name,
        "asic-financial-adviser",
        scan_id,
        result,
    );
}

/// Emit a credit/finance-broker representative: the Person, an ABN/ACN pivot,
/// and the registered address. The licensee they operate under (a credit
/// licence number) and authorisation period ride on the evidence.
fn emit_credit_rep(rec: &Map<String, Value>, scan_id: &str, result: &mut ModuleResult) {
    let Some(raw_name) = field(rec, "CRED_REP_NAME") else {
        return;
    };
    let person_name = humanise_name(&raw_name);

    let mut ev = Evidence::new(SRC, format!("ASIC credit representative: {person_name}"))
        .with_attr("register", "ASIC Credit Representatives")
        .with_attr("matched_name", &raw_name);
    for (key, attr) in [
        ("CRED_REP_NUM", "credit_rep_number"),
        ("CRED_LIC_NUM", "credit_licence_no"),
        ("CRED_REP_START_DT", "authorised_from"),
        ("CRED_REP_END_DT", "authorised_to"),
        ("CRED_REP_EDRS", "dispute_scheme"),
    ] {
        if let Some(v) = field(rec, key) {
            ev = ev.with_attr(attr, v);
        }
    }

    let mut p = Entity::new(EntityKind::Person, &person_name, confidence::MEDIUM_PLUS, scan_id);
    p.tag("au");
    p.tag("asic");
    p.tag("asic-credit-rep");
    p.add_evidence(ev.clone());
    result.push(p);

    // The rep's own ABN/ACN (11- or 9-digit), when registered against the name.
    if let Some(id) = field(rec, "CRED_REP_ABN_ACN").filter(|a| {
        let n = a.chars().filter(char::is_ascii_digit).count();
        n == 11 || n == 9
    }) {
        let mut e = Entity::new(EntityKind::AbnAcn, &id, confidence::MEDIUM_PLUS, scan_id);
        e.tag("au");
        e.tag("asic");
        e.tag("asic-credit-rep");
        e.add_evidence(
            Evidence::new(
                SRC,
                format!("ABN/ACN of credit representative {person_name}"),
            )
            .with_attr("abn_acn", &id),
        );
        result.push(e);
    }

    push_address(
        rec,
        "CRED_REP_LOCALITY",
        "CRED_REP_STATE",
        "CRED_REP_PCODE",
        &person_name,
        "asic-credit-rep",
        scan_id,
        result,
    );
}

/// Compose `LOCAL STATE PCODE` into an Address entity, if any part is present.
#[allow(clippy::too_many_arguments)]
fn push_address(
    rec: &Map<String, Value>,
    local_key: &str,
    state_key: &str,
    pcode_key: &str,
    person: &str,
    tag: &str,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    let parts: Vec<String> = [local_key, state_key, pcode_key]
        .into_iter()
        .filter_map(|k| field(rec, k))
        .collect();
    if parts.is_empty() {
        return;
    }
    let addr = parts.join(" ");
    // The AU state of the register address, resolved once and reused for both the
    // Address and Coordinates tags so this register participates in the AU
    // geo/jurisdiction correlators like every other AU module.
    let sc = crate::util::address_au::state_code(&addr);
    let mut a = Entity::new(EntityKind::Address, &addr, confidence::MEDIUM_HIGH, scan_id);
    a.tag("au");
    a.tag("asic");
    a.tag(tag);
    a.tag("country:AU");
    if let Some(s) = sc {
        a.tag(format!("au-state:{s}"));
    }
    a.add_evidence(
        Evidence::new(SRC, format!("Registered address for {person}"))
            .with_attr("address", &addr)
            .with_attr("source", "asic-register"),
    );
    result.push(a);

    // Inline-geocode the register address to a Coordinates anchor (offline
    // gazetteer) so the registered locality enters the AU geo correlators
    // (AU-052/053) immediately, without waiting on a network forward-geocode —
    // exactly as the sibling AU register modules do.
    if let Some((lat, lon)) = crate::util::city_coords::city_coords(&addr) {
        let coord_val = format!("{lat:.4},{lon:.4}");
        let mut c = Entity::new(EntityKind::Coordinates, &coord_val, confidence::LOW_MEDIUM, scan_id);
        c.tag("au");
        c.tag("asic");
        c.tag("addr-derived");
        c.tag("geoint");
        c.tag("country:AU");
        if let Some(s) = sc {
            c.tag(format!("au-state:{s}"));
        }
        c.add_evidence(
            Evidence::new(SRC, format!("Geocoded register address for {person}"))
                .with_attr("source_address", &addr),
        );
        result.push(c);
    }
}

/// A non-empty, non-`"null"` trimmed string field (JSON string or number).
/// A usable ASIC field value: the shared CKAN [`field_str`] stringification
/// (CONVENTIONS §4 — one stringifier, not a per-module copy) with this
/// register's `"null"` sentinel filter on top (`field_str` only drops JSON
/// null / empty, so the literal string `"null"` would otherwise pass through).
fn field(rec: &Map<String, Value>, key: &str) -> Option<String> {
    field_str(rec, key).filter(|s| !s.eq_ignore_ascii_case("null"))
}

/// `"SURNAME, FIRSTNAME"` → `"Firstname Surname"` (title-cased); other forms are
/// title-cased as-is.
fn humanise_name(s: &str) -> String {
    let reordered = match s.split_once(',') {
        Some((surname, first)) => format!("{} {}", first.trim(), surname.trim()),
        None => s.trim().to_string(),
    };
    crate::util::str_util::title_case(&reordered.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
