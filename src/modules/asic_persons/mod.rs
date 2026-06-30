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

use serde::Deserialize;
use serde_json::{Map, Value};

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_text, urlencode};

const SRC: &str = "asic_persons";
const CKAN: &str = "https://data.gov.au/data/api/3/action/datastore_search";
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

#[derive(Deserialize, Default)]
#[serde(default)]
struct CkanResp {
    result: CkanResult,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CkanResult {
    records: Vec<Map<String, Value>>,
}

#[async_trait]
impl Module for AsicPersons {
    fn name(&self) -> &'static str {
        "asic_persons"
    }

    fn description(&self) -> &'static str {
        "ASIC people registers (banned & disqualified, financial advisers, credit/finance-broker representatives) — name → regulatory status, licensee, disciplinary action, address (keyless)"
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

        for rec in banned
            .iter()
            .filter(|r| record_name_matches(r, "BD_PER_NAME", &tokens))
            .take(MAX_HITS)
        {
            emit_banned(rec, &ctx.scan_id, &mut result);
        }
        for rec in advisers
            .iter()
            .filter(|r| record_name_matches(r, "ADV_NAME", &tokens))
            .take(MAX_HITS)
        {
            emit_adviser(rec, &ctx.scan_id, &mut result);
        }
        for rec in credit
            .iter()
            .filter(|r| record_name_matches(r, "CRED_REP_NAME", &tokens))
            .take(MAX_HITS)
        {
            emit_credit_rep(rec, &ctx.scan_id, &mut result);
        }

        Ok(result)
    }
}

/// Query a CKAN datastore resource by free-text name. Best-effort: any
/// transport/parse failure yields no records, never a scan error.
async fn ckan_query(ctx: &ModuleContext, resource_id: &str, name: &str) -> Vec<Map<String, Value>> {
    let url = format!(
        "{CKAN}?resource_id={resource_id}&limit=100&q={}",
        urlencode(name)
    );
    let Ok(resp) = ctx
        .http
        .get(&url)
        .header("User-Agent", UA_BROWSER)
        .send_tagged(SRC)
        .await
    else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let Ok(body) = read_text(SRC, resp).await else {
        return Vec::new();
    };
    serde_json::from_str::<CkanResp>(&body)
        .map(|r| r.result.records)
        .unwrap_or_default()
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

    let mut p = Entity::new(EntityKind::Person, &person_name, 0.60, scan_id);
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
        ("ADV_DA_TYPE", "disciplinary_action"),
        ("ADV_DA_DESCRIPTION", "disciplinary_detail"),
    ] {
        if let Some(v) = field(rec, key) {
            ev = ev.with_attr(attr, v);
        }
    }

    let mut p = Entity::new(EntityKind::Person, &person_name, 0.60, scan_id);
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
    if let Some(licensee) = field(rec, "LICENCE_NAME") {
        let mut org = Entity::new(EntityKind::Organisation, &licensee, 0.62, scan_id);
        org.tag("au");
        org.tag("asic");
        org.tag("afs-licensee");
        let mut oev = Evidence::new(SRC, format!("AFS licensee of adviser {person_name}"))
            .with_attr("licensee", &licensee);
        if let Some(no) = field(rec, "LICENCE_NUMBER") {
            oev = oev.with_attr("afs_licence_no", no);
        }
        org.add_evidence(oev);
        result.push(org);
    }

    // ABNs: the adviser's own and the licensee's — pivots into the ABR/ASIC.
    for (key, label) in [("ADV_ABN", "adviser"), ("LICENCE_ABN", "licensee")] {
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

    let mut p = Entity::new(EntityKind::Person, &person_name, 0.60, scan_id);
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
        let mut e = Entity::new(EntityKind::AbnAcn, &id, 0.60, scan_id);
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
    let mut a = Entity::new(EntityKind::Address, &addr, 0.55, scan_id);
    a.tag("au");
    a.tag("asic");
    a.tag(tag);
    a.add_evidence(
        Evidence::new(SRC, format!("Registered address for {person}"))
            .with_attr("address", &addr)
            .with_attr("source", "asic-register"),
    );
    result.push(a);
}

/// A non-empty, non-`"null"` trimmed string field (JSON string or number).
fn field(rec: &Map<String, Value>, key: &str) -> Option<String> {
    match rec.get(key)? {
        Value::String(s) => {
            let t = s.trim();
            (!t.is_empty() && !t.eq_ignore_ascii_case("null")).then(|| t.to_string())
        }
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
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
