//! BreachDirectory credential-exposure search, via RapidAPI. Key-gated; the
//! RapidAPI "Basic" plan is free (10 requests/month).
//!
//! Endpoint: `GET https://breachdirectory.p.rapidapi.com/?func=auto&term=<email-or-username>`
//! Auth:     `X-RapidAPI-Key: <key>` **and** `X-RapidAPI-Host: breachdirectory.p.rapidapi.com`
//!           — every independent client of this listing (cited below) sends
//!           both headers unconditionally, not the key alone, so this module
//!           does too rather than relying on the gateway accepting a partial
//!           request.
//!
//! `func=auto` lets the API infer whether `term` is an email or a username, and
//! returns every breach record it holds for that identifier: which corpora
//! (`sources`) it appeared in, and — per record — whether a password/hash was
//! actually recovered (`has_password`, plus `password`/`sha1`/`hash` fields when
//! so). Per this crate's breach-module convention (see `hibp`/`dehashed`), the
//! raw leaked password/hash value is never persisted into evidence: only the
//! fact of exposure (`password-at-risk` tag) and a count.
//!
//! The RapidAPI listing page itself renders client-side (its docs did not survive
//! a plain fetch), so the endpoint/headers/response-shape below were confirmed
//! against independent, already-shipping API clients rather than guessed:
//!   * <https://rapidapi.com/rohan-patra/api/breachdirectory> — the listing (free
//!     "Basic" plan = 10 req/month, hence `ModuleCost::KeyGated`).
//!   * <https://github.com/alpkeskin/mosint/blob/main/v3/pkg/services/breachdirectory/breachdirectory.go>
//!     — a typed Go client: confirms the exact request (URL, both headers) and
//!     the `{success, found, result:[{has_password, sources, password, sha1,
//!     hash}]}` response shape.
//!   * <https://github.com/rdillon73/eBreached> — confirms the same request
//!     shape and that a miss is signalled in the response body, not by a
//!     dedicated HTTP status (its own comments note 404/500 are ambiguous
//!     transport/gateway conditions, not a documented "no data" contract).
//!   * <https://github.com/v4resk/BreachCheck> — confirms `success`/`found` are
//!     read from the body to detect "no results", matching the shape above.
//!
//! No HTTP status is corroborated as this endpoint's "clean miss" signal (unlike
//! LeakIX's 404), so — exactly as `dehashed`'s fixed search endpoint does —
//! `absent_statuses: &[]` is passed to the key cascade: a miss is read from the
//! body (`success:false` or an empty `result` array) instead.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::urlencode;

const KEY_ENV: &str = "HUNTSMAN_BREACHDIR_KEY";
const SRC: &str = "breachdirectory";
const RAPIDAPI_HOST: &str = "breachdirectory.p.rapidapi.com";

/// Top-N breach-corpus names kept in the summary evidence (frequency-ranked,
/// same convention as `leakix`/`hibp`) — enough signal without letting an
/// identifier exposed in dozens of corpora bloat the evidence row.
const TOP_SOURCES: usize = 10;

/// One row of the `result` array. Present only when the identifier was found in
/// at least one corpus; `has_password` gates whether `password`/`sha1`/`hash`
/// carry anything (confirmed by the `mosint` client: it only reads those three
/// fields when `has_password` is true).
#[derive(Deserialize)]
struct ResultRow {
    #[serde(default)]
    has_password: bool,
    #[serde(default)]
    sources: Vec<String>,
    // The plaintext password / SHA-1 / other hash digest are intentionally
    // NOT modelled: this module surfaces exposure as a tag + count, never the
    // leaked secret itself (the `hibp`/`dehashed` convention for a redacted
    // field — dehashed differs only because ITS module doc explicitly makes
    // the hash a first-class reverse-searchable node; this one does not).
}

#[derive(Deserialize)]
struct BreachDirResp {
    #[serde(default)]
    success: bool,
    /// The API's own reported hit count. Cosmetic only — `result.len()` (what
    /// was actually returned) is the source of truth this module builds from,
    /// so a mismatch between the two can't under- or over-report the evidence.
    #[serde(default)]
    found: u64,
    #[serde(default)]
    result: Vec<ResultRow>,
}

/// Build the breach-exposure entity from a non-empty, successful BreachDirectory
/// response. **Pure** (no network/IO): tallies which corpora the identifier
/// appeared in (top-N by frequency) and how many records carried a recovered
/// password/hash, raising `password-at-risk` only when at least one did — never
/// touching the redacted `password`/`sha1`/`hash` values themselves. Caller
/// guarantees `body.result` is non-empty (an empty/`success:false` response is
/// this module's clean-miss case, handled before this is called).
fn build_breach_entity(
    kind: EntityKind,
    value: &str,
    body: &BreachDirResp,
    scan_id: &str,
) -> Entity {
    let record_count = body.result.len();
    let password_exposed = body.result.iter().filter(|r| r.has_password).count();

    // A record with an actually-recovered password/hash is stronger evidence
    // of a genuine, current exposure than a bare corpus-membership hit, so it
    // earns the higher confidence tier — same shape as `hibp`'s
    // verified-count-driven base_conf, scaled down: BreachDirectory is an
    // unofficial third-party aggregator over HIBP/Leakcheck/Vigilante.pw (per
    // its own listing), not a primary source, so both tiers sit a notch below
    // HIBP's own HIGH/HIGH_PLUSPLUS+ floor.
    let base_conf = if password_exposed > 0 {
        confidence::HIGH
    } else {
        confidence::MEDIUM_PLUS
    };

    let mut entity = Entity::new(kind, value, base_conf, scan_id);
    entity.tag(tags::BREACH);
    entity.tag(SRC);
    if password_exposed > 0 {
        entity.tag(tags::PASSWORD_AT_RISK);
    }

    let sources = crate::util::freq::top_n(
        body.result
            .iter()
            .flat_map(|r| r.sources.iter().map(String::as_str)),
        TOP_SOURCES,
    );

    let mut ev = Evidence::new(
        SRC,
        if password_exposed > 0 {
            format!(
                "Found in {record_count} breach record(s), {password_exposed} with a recovered password/hash"
            )
        } else {
            format!("Found in {record_count} breach record(s)")
        },
    )
    .with_attr("record_count", record_count.to_string())
    .with_attr("password_exposed_count", password_exposed.to_string());
    if !sources.is_empty() {
        ev = ev.with_attr("sources", sources);
    }
    if body.found > 0 {
        ev = ev.with_attr("reported_found", body.found.to_string());
    }
    entity.add_evidence(ev);
    entity
}

pub struct BreachDirectory;

#[async_trait]
impl Module for BreachDirectory {
    fn name(&self) -> &'static str {
        "breachdirectory"
    }
    fn description(&self) -> &'static str {
        "BreachDirectory recon — surfaces which breach corpora an email/username appears in and whether a password was exposed"
    }
    fn priority(&self) -> u8 {
        100
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn cache_ttl_secs(&self) -> u64 {
        // Breach corpus membership is immutable once indexed — the same
        // "IP intel: 24h" bracket generalised to every other breach module
        // (hibp/dehashed/see_know/oathnet_pro/intelx), so a repeat lookup
        // within a day replays instead of spending another of the free
        // plan's 10 monthly requests.
        86_400
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Username)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Re-emits the input Email/Username carrying corpus-membership +
        // password-exposure evidence — no other entity kinds. Unlike DeHashed
        // this module extracts no long-tail per-record fields (BreachDirectory's
        // response carries none beyond sources/has_password/password/sha1/hash),
        // so there is nothing further to pivot on.
        const KINDS: &[EntityKind] = &[EntityKind::Email, EntityKind::Username];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let initial_key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        let term = urlencode(value);
        let url = format!("https://{RAPIDAPI_HOST}/?func=auto&term={term}");
        // Key cascade via the shared primitive: on a terminal key/quota failure
        // (incl. the RapidAPI-gateway 429 a Basic-plan monthly quota returns),
        // rotate to the next untried usable pooled key so one call spends every
        // credential the pool holds. `absent_statuses: &[]` — no status is
        // corroborated as this endpoint's "no data" signal (see the module doc);
        // a miss is read from the response BODY below instead, exactly as
        // `dehashed`'s fixed search endpoint does.
        let Some(resp) = crate::util::http::keyed_cascade(ctx, SRC, initial_key, &[], |key| {
            ctx.http
                .get(&url)
                .header("X-RapidAPI-Key", key)
                .header("X-RapidAPI-Host", RAPIDAPI_HOST)
                .header("Accept", "application/json")
        })
        .await?
        else {
            return Ok(ModuleResult::new());
        };
        // json_scanned: a breach record's `sources`/hash fields are attacker-
        // supplied free text that could plausibly hide a third-party API key —
        // scan the raw body, same as every other breach module.
        let body: BreachDirResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| crate::core::error::Error::module(SRC, e))?;

        if !body.success || body.result.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        result.push(build_breach_entity(
            target.kind.to_entity_kind(),
            value,
            &body,
            &ctx.scan_id,
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
