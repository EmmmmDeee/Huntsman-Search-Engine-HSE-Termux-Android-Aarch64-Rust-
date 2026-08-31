//! ASIC Banned & Disqualified **Organisations** register — keyless. The
//! entity-side complement to [`crate::modules::asic_persons`] (banned people):
//! an organisation name → whether ASIC has banned or disqualified that company
//! from providing financial services or managing corporations, with the ban
//! type, period, and the company's **ACN**.
//!
//! A hit is a high-signal adverse finding for due diligence on any Australian
//! company. Queried by name through the data.gov.au CKAN `datastore_search`
//! API (full-text, keyless) and matched on all of the target's name tokens; the
//! ACN is emitted as an `AbnAcn` pivot into the rest of the corporate stack
//! (`abn_lookup`, `asic_director`). No mock: fetched live from ASIC's own open
//! dataset.

use serde_json::{Map, Value};

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::{self, datastore_search_url};

const SRC: &str = "asic_banned_orgs";
/// data.gov.au CKAN action base — `datastore_search` is appended by
/// [`datastore_search_url`].
const CKAN_BASE: &str = "https://data.gov.au/data/api/3/action";
/// ASIC – Banned and Disqualified Organisations dataset (data.gov.au resource).
const RES: &str = "ced03961-e6f7-4263-895a-0fd1d7996043";
/// Max matched records surfaced. Raised to the query `limit` so no genuine
/// banned-organisation record is omitted (directive: never omit an API-derived
/// AU government result).
const MAX_HITS: usize = 100;

pub struct AsicBannedOrgs;

#[async_trait]
impl Module for AsicBannedOrgs {
    fn name(&self) -> &'static str {
        "asic_banned_orgs"
    }

    fn description(&self) -> &'static str {
        "ASIC Banned & Disqualified Organisations recon (keyless) — pivots an org name to ban status, ACN, and period"
    }

    fn priority(&self) -> u8 {
        112
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Adverse status of a business entity — T1591.002 Business Relationships.
        &["T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Organisation, EntityKind::AbnAcn];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let name = target.value.trim();
        let tokens = name_tokens(name);
        // A national company register needs a discriminating multi-token name.
        if tokens.len() < 2 {
            return Ok(result);
        }

        let records = ckan_query(ctx, name).await?;
        // Pure epoch-day count `emit_banned_org` compares each ban's own end
        // date against; not called internally (a `SystemTime::now()` reaching
        // into a "pure" builder would make its tests depend on wall-clock
        // time — see `hudsonrock::compute_confidence`'s identical rationale).
        let today_days = (crate::core::entity::unix_now() / 86_400) as i64;
        let mut matched_count = 0usize;
        for rec in records
            .iter()
            .filter(|r| record_name_matches(r, name))
            .take(MAX_HITS)
        {
            matched_count += 1;
            emit_banned_org(rec, &ctx.scan_id, today_days, &mut result);
        }

        if matched_count == 0 {
            return Ok(result);
        }

        // Signal if results were truncated.
        let total_matches = records
            .iter()
            .filter(|r| record_name_matches(r, name))
            .count();
        let matches_capped = total_matches > MAX_HITS;

        let mut seed = Entity::new(
            EntityKind::Organisation,
            name,
            confidence::MEDIUM_HIGH,
            &ctx.scan_id,
        );
        seed.tag("asic");
        seed.tag("search-result");
        let mut ev = Evidence::new(
            SRC,
            format!("ASIC Banned & Disqualified Organisations search for '{name}'"),
        )
        .with_attr("matched_count", matched_count.to_string())
        .with_attr("total_matches", total_matches.to_string());
        if matches_capped {
            ev = ev.with_attr("matches_capped", "true");
            seed.tag("truncated");
        }
        seed.add_evidence(ev);
        result.push(seed);

        Ok(result)
    }
}

/// Query the Banned & Disqualified Organisations datastore by free-text name,
/// via the shared CKAN helper (T2.118). Unlike the previous hand-rolled fetch
/// — which collapsed a transport error, a non-2xx status, a body-read failure,
/// AND a CKAN application error (`success: false`, returned with HTTP 200) all
/// into an empty `Vec` indistinguishable from a genuine "no banned org by this
/// name" — every real failure now surfaces through
/// [`crate::util::ckan::validated_result`]: `fetch_json` propagates transport/
/// status/parse failures via `?`, and a `success == Some(false)` envelope
/// (bad resource id / datastore offline / rate-limit) becomes an explicit
/// `Error::module`. A genuine empty result set (no `result`, or an empty
/// `records`) is still the honest clean miss.
async fn ckan_query(ctx: &ModuleContext, name: &str) -> Result<Vec<Map<String, Value>>> {
    let url = datastore_search_url(CKAN_BASE, RES, name, MAX_HITS);
    Ok(crate::util::ckan::validated_result(&ctx.http, SRC, &url)
        .await?
        .map(|r| r.records)
        .unwrap_or_default())
}

fn name_tokens(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// True if the record's `BD_ORG_NAME` shares every whole-word token with the
/// queried organisation name. Whole-word, not substring — a raw `.contains()`
/// check lets two query tokens each land inside a DIFFERENT unrelated word
/// of an otherwise-unrelated banned entity (e.g. "cotton"/"on" both land
/// inside "sCOTTONi"/"cONstruction"), attributing a real company's ASIC ban
/// to an unrelated business searched by a similar-looking name — unusually
/// costly for this specific register, whose whole purpose is due-diligence
/// on adverse findings. Same precision gate `acnc_charities`/`gleif_lei` use
/// for their own full-text CKAN search results.
fn record_name_matches(rec: &Map<String, Value>, query: &str) -> bool {
    let Some(name) = field(rec, "BD_ORG_NAME") else {
        return false;
    };
    crate::util::str_util::whole_word_token_match(&name, query)
}

/// Parse an ASIC register date (`DD/MM/YYYY`) to a Unix epoch-day count.
/// `None` for anything else — `BD_ORG_END_DT` is genuinely mixed in the live
/// data: a real date, the JSON `null` (open-ended ban), or free text like
/// `"Permanent banning"`, and only the first shape is a comparable date.
/// Bounded to a plausible calendar year (matches `hudsonrock::parse_iso_epoch`
/// /`core::timeline::parse_date`'s convention for untrusted date strings) so a
/// malformed or wildly out-of-range value can't overflow
/// [`crate::core::timeline::days_from_civil`].
fn parse_au_date(s: &str) -> Option<i64> {
    let mut parts = s.trim().split('/');
    let day: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let year: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some()
        || !(1900..=2100).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }
    Some(crate::core::timeline::days_from_civil(year, month, day))
}

/// True when a ban's own `BD_ORG_END_DT` names a real, parseable date that
/// has already passed relative to `today_days` (a Unix epoch-day count).
/// Absent, `null`, or unparseable (e.g. `"Permanent banning"`) is treated as
/// still current — only a genuine, comparable past date counts as expired,
/// never an inability to parse the field.
fn ban_is_expired(end_dt: Option<&str>, today_days: i64) -> bool {
    end_dt
        .and_then(parse_au_date)
        .is_some_and(|d| d < today_days)
}

/// Emit the adverse-flagged organisation and its ACN. `today_days` is a Unix
/// epoch-day count, threaded in from `process()` rather than read internally
/// via the wall clock, so this stays pure and its tests deterministic —
/// same rationale as `hudsonrock::compute_confidence`'s caller-supplied clock.
fn emit_banned_org(
    rec: &Map<String, Value>,
    scan_id: &str,
    today_days: i64,
    result: &mut ModuleResult,
) {
    let Some(org_name) = field(rec, "BD_ORG_NAME") else {
        return;
    };
    // ASIC stores some names with a non-breaking space; normalise for display.
    let org_name = org_name.replace('\u{a0}', " ");
    let end_dt = field(rec, "BD_ORG_END_DT");
    let expired = ban_is_expired(end_dt.as_deref(), today_days);

    let mut ev = Evidence::new(
        SRC,
        if expired {
            format!("ASIC banned/disqualified organisation (ban expired): {org_name}")
        } else {
            format!("ASIC banned/disqualified organisation: {org_name}")
        },
    )
    .with_attr("register", "ASIC Banned & Disqualified Organisations")
    .with_attr("organisation", &org_name);
    for (key, attr) in [
        ("BD_ORG_TYPE", "ban_type"),
        ("BD_ORG_START_DT", "ban_start"),
        ("BD_ORG_END_DT", "ban_end"),
        ("BD_ORG_ACN", "acn"),
        ("BD_ORG_COMMENT", "comments"),
    ] {
        if let Some(v) = field(rec, key) {
            ev = ev.with_attr(attr, v);
        }
    }

    // A ban that already ended (per the register's own end date) is a
    // historical, not a current, adverse finding — an 18-year-expired ban
    // read identically to one active for another 13 months otherwise, with
    // nothing short of the operator doing their own date arithmetic on the
    // raw `ban_end` attribute to tell them apart.
    let conf = if expired {
        confidence::derived_from(confidence::MEDIUM_PLUS)
    } else {
        confidence::MEDIUM_PLUS
    };
    let mut org = Entity::new(EntityKind::Organisation, &org_name, conf, scan_id);
    org.tag("au");
    org.tag("asic");
    org.tag("asic-banned");
    org.tag("regulatory-action");
    if expired {
        org.tag("ban-expired");
    }
    org.add_evidence(ev.clone());
    result.push(org);

    // The ACN — a pivot into the company register, kept only when it is a
    // genuinely checksum-valid ACN rather than merely 9 digits.
    if let Some(acn) = field(rec, "BD_ORG_ACN").filter(|a| crate::util::abn::is_valid_acn(a)) {
        let mut e = Entity::new(EntityKind::AbnAcn, &acn, confidence::NOTABLE, scan_id);
        e.tag("au");
        e.tag("asic");
        e.tag("asic-banned");
        e.add_evidence(
            Evidence::new(SRC, format!("ACN of banned organisation {org_name}"))
                .with_attr("acn", &acn)
                .with_attr("organisation", &org_name),
        );
        result.push(e);
    }
}

/// A usable ASIC field value: the shared [`ckan::field`] (null-filtered
/// stringification) with this register's own extra sentinel on top — ASIC
/// stores an absent value here as the literal `"null"` **or** `"Not
/// available"` text, and only the former is a generic-enough CKAN quirk to
/// live in the shared helper.
fn field(rec: &Map<String, Value>, key: &str) -> Option<String> {
    ckan::field(rec, key).filter(|s| !s.eq_ignore_ascii_case("Not available"))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
