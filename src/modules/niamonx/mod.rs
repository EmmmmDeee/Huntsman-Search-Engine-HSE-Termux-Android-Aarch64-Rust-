//! NiamonX — concurrent PBS v1/v2 breach search and ULP infostealer lookup.
//!
//! Three POST endpoints, all issued concurrently via `tokio::join!`:
//!   `/api/v2/breaches_search`  PBS v1 — 140 B records, risk score
//!   `/api/v2/breaches_s_v2`   PBS v2 — encrypted datasets, per-record metadata
//!   `/api/v2/ulp_search`       ULP   — infostealer URL·LOGIN·PASS triples
//!
//! Accepts: Email | Username | IpAddress | Domain. Requires `HUNTSMAN_NIAMONX_KEY`.
//!
//! Invariants:
//!   • Plaintext passwords NEVER stored, emitted, or present in any struct field.
//!   • `password` field absent from `NxPbsV2Record` — never bound.
//!   • `pass` field absent from `NxUlpRecord` — never bound.
//!   • ULP `login` promoted to pivot only when it differs from the query target.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::str_util::slugify;

const SRC: &str = "niamonx";
const KEY_ENV: &str = "HUNTSMAN_NIAMONX_KEY";
const BASE: &str = "https://dash.niamonx.io/api/v2";
const ULP_LIMIT: u32 = 200;

pub struct NiamonX;

// ── Request bodies ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct PbsV1Body<'a> {
    query: &'a str,
}

#[derive(Serialize)]
struct PbsV2Body<'a> {
    value: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
}

#[derive(Serialize)]
struct UlpBody<'a> {
    action: &'static str,
    value: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    exact: bool,
    limit: u32,
}

// ── Response types — PBS v1 ────────────────────────────────────────────────

#[derive(Deserialize)]
struct PbsV1Response {
    success: bool,
    data: Option<PbsV1Data>,
}

#[derive(Deserialize)]
struct PbsV1Data {
    status: Option<String>,
    error: Option<String>,
    meta: Option<PbsV1Meta>,
    risk: Option<PbsV1Risk>,
    blocks: Option<Vec<PbsV1Block>>,
    rate: Option<PbsV1Rate>,
}

#[derive(Deserialize)]
struct PbsV1Meta {
    blocks_total: u32,
    emails: Option<Vec<String>>,
    names: Option<Vec<String>>,
    first_seen: Option<String>,
    last_seen: Option<String>,
}

#[derive(Deserialize)]
struct PbsV1Risk {
    score: u32,
    level: String,
}

#[derive(Deserialize)]
struct PbsV1Block {
    title: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct PbsV1Rate {
    remaining: u32,
}

// ── Response types — PBS v2 ────────────────────────────────────────────────

#[derive(Deserialize)]
struct PbsV2Response {
    success: bool,
    data: Option<PbsV2Data>,
}

#[derive(Deserialize)]
struct PbsV2Data {
    #[serde(default = "default_true")]
    niamonx_success: bool,
    error: Option<String>,
    stats: Option<PbsV2Stats>,
    records: Option<Vec<PbsV2Record>>,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct PbsV2Stats {
    found: u32,
    with_passwords: u32,
    unique_sources: u32,
}

#[derive(Deserialize)]
struct PbsV2Record {
    source: Option<PbsV2Source>,
    email: Option<String>,
    username: Option<String>,
    phone: Option<String>,
    // `password` field intentionally absent — never stored or emitted.
    fields: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct PbsV2Source {
    name: Option<String>,
    breach_date: Option<String>,
    compilation: Option<u8>,
}

// ── Response types — ULP ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct UlpResponse {
    success: bool,
    data: Option<UlpData>,
}

#[derive(Deserialize)]
struct UlpData {
    error: Option<String>,
    stats: Option<UlpStats>,
    records: Option<Vec<UlpRecord>>,
}

#[derive(Deserialize)]
struct UlpStats {
    total: u32,
    unique_hosts: u32,
    with_password: u32,
}

#[derive(Deserialize)]
struct UlpRecord {
    url: Option<String>,
    host: Option<String>,
    login: Option<String>,
    // `pass` field intentionally absent — never stored or emitted.
}

// ── Module trait ─────────────────────────────────────────────────────────

#[async_trait]
impl Module for NiamonX {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "NiamonX PBS v1/v2 breach search and ULP infostealer lookup"
    }

    fn priority(&self) -> u8 {
        122
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email | TargetKind::Username | TargetKind::IpAddress | TargetKind::Domain
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Breach default covers Credentials (T1589.001) + Email Addresses
        // (T1589.002), but PBS v1's `meta.names` corroboration also mints
        // Person entities (see `produces()`/`process()` below) → T1589.003
        // Employee Names, which the default omits. Same pattern as
        // `dehashed`/`see_know`/`oathnet_pro` declaring it for their own
        // name-field Person extraction.
        &["T1589.001", "T1589.002", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Domain is accepted as input but no Domain pivot entity is ever emitted.
        // Person is emitted from PBS v1 meta.names corroboration.
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::Person,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let query = &target.value;
        let ulp_type = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Domain => "domain",
            _ => "auto",
        };

        // Key cascade across the concurrent endpoint batch. The three endpoints
        // share one key; if EVERY one fails AND that key was burned in the pool
        // this call (a 401/403/429 routed through `note_keyed_error` marks it
        // non-usable), rotate to the next usable pooled key and retry the whole
        // batch — so one process() spends every credential the pool holds before
        // reporting an outage. A partial success, or a non-key failure such as a
        // transient 5xx, leaves the key usable and does NOT cascade, so keys are
        // never churned on anything but a genuine key/quota failure. `tried` stops
        // re-handing a burned key; single-key setups never enter the branch.
        use crate::util::key_pool::KeyStatus;
        // A key is "burned" once the pool marks it non-usable. We compare the
        // pool status BEFORE and AFTER this batch so a cascade fires only on a
        // FRESH burn THIS batch caused (usable before, non-usable after). Reading
        // only the after-status would misfire on a stale RateLimited/Invalid mark
        // left by an EARLIER target in the same scan: a genuine key-independent
        // outage (all three endpoints 5xx) would then churn a good second key even
        // though nothing here was a key problem.
        let is_burned = |s: Option<KeyStatus>| {
            matches!(
                s,
                Some(
                    KeyStatus::Invalid
                        | KeyStatus::RateLimited
                        | KeyStatus::Revoked
                        | KeyStatus::Exhausted
                )
            )
        };
        let mut tried: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut key = ctx.key(KEY_ENV)?.to_string();
        let (r1, r2, r3) = loop {
            tried.insert(key.clone());
            let before = crate::util::key_pool::global_pool().entry_status(SRC, &key);
            // All three endpoints are independent — run concurrently.
            let results = tokio::join!(
                fetch_pbs_v1(&ctx.http, &key, query, ctx),
                fetch_pbs_v2(&ctx.http, &key, query, ctx),
                fetch_ulp(&ctx.http, &key, query, ulp_type, ctx),
            );
            let all_failed = results.0.is_err() && results.1.is_err() && results.2.is_err();
            if all_failed {
                let after = crate::util::key_pool::global_pool().entry_status(SRC, &key);
                // Cascade only when this batch turned a usable key non-usable — a
                // 5xx outage leaves it usable, and a pre-existing bad status is
                // never re-attributed to this call.
                if is_burned(after)
                    && !is_burned(before)
                    && let Some(next) = ctx.next_pooled_key(SRC, &tried)
                {
                    key = next;
                    continue;
                }
            }
            break results;
        };

        let mut entity = target.to_entity(0.80, &ctx.scan_id);
        entity.tag(SRC);

        // The last genuine transport/parse failure seen across the three
        // independent endpoints (T2.114). Real evidence from any endpoint is
        // never discarded because a *different* endpoint failed — see
        // `ModuleResult::or_hard_failure` below.
        let mut hard_failure: Option<Error> = None;
        match r1 {
            Ok(r) => emit_pbs_v1(r, &mut entity, &mut result, query, &ctx.scan_id),
            Err(e) => {
                warn!(error = %e, "niamonx pbs_v1 failed");
                hard_failure = Some(e);
            }
        }
        match r2 {
            Ok(r) => emit_pbs_v2(r, &mut entity, &mut result, query, &ctx.scan_id),
            Err(e) => {
                warn!(error = %e, "niamonx pbs_v2 failed");
                hard_failure.get_or_insert(e);
            }
        }
        match r3 {
            Ok(r) => emit_ulp(r, &mut entity, &mut result, query, &ctx.scan_id),
            Err(e) => {
                warn!(error = %e, "niamonx ulp failed");
                hard_failure.get_or_insert(e);
            }
        }

        // Only emit the entity when at least one endpoint contributed evidence.
        if !entity.evidence.is_empty() {
            result.push(entity);
        }
        // All three endpoints failing (e.g. a revoked API key, or a full
        // dash.niamonx.io outage) previously read as "nothing found on any of
        // the three PBS/ULP surfaces" — indistinguishable from a genuine
        // triple-negative. Surface it as a real error instead, unless at
        // least one endpoint already produced real evidence.
        result.or_hard_failure(hard_failure)
    }
}

// ── HTTP helpers ─────────────────────────────────────────────────────────

async fn fetch_pbs_v1(
    http: &reqwest::Client,
    key: &str,
    query: &str,
    ctx: &crate::core::module::ModuleContext,
) -> Result<PbsV1Response> {
    let resp = http
        .post(format!("{BASE}/breaches_search"))
        .header("X-API-Key", key)
        .json(&PbsV1Body { query })
        .send_tagged(SRC)
        .await?;
    // 401/403/429 → note_keyed_error + Err; other non-2xx → Err. 404 is
    // unexpected (empty results arrive as 200+body) so treat it as an error.
    let resp = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp)
        .await?
        .ok_or_else(|| Error::module(SRC, "HTTP 404 from breaches_search"))?;
    crate::util::http::json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))
}

async fn fetch_pbs_v2(
    http: &reqwest::Client,
    key: &str,
    query: &str,
    ctx: &crate::core::module::ModuleContext,
) -> Result<PbsV2Response> {
    let resp = http
        .post(format!("{BASE}/breaches_s_v2"))
        .header("X-API-Key", key)
        .json(&PbsV2Body {
            value: query,
            kind: "auto",
        })
        .send_tagged(SRC)
        .await?;
    // 401/403/429 → note_keyed_error + Err; other non-2xx → Err. 404 is
    // unexpected (empty results arrive as 200+body) so treat it as an error.
    let resp = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp)
        .await?
        .ok_or_else(|| Error::module(SRC, "HTTP 404 from breaches_s_v2"))?;
    crate::util::http::json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))
}

async fn fetch_ulp(
    http: &reqwest::Client,
    key: &str,
    query: &str,
    ulp_type: &str,
    ctx: &crate::core::module::ModuleContext,
) -> Result<UlpResponse> {
    let resp = http
        .post(format!("{BASE}/ulp_search"))
        .header("X-API-Key", key)
        .json(&UlpBody {
            action: "search",
            value: query,
            kind: ulp_type,
            exact: true,
            limit: ULP_LIMIT,
        })
        .send_tagged(SRC)
        .await?;
    // 401/403/429 → note_keyed_error + Err; other non-2xx → Err. 404 is
    // unexpected (empty results arrive as 200+body) so treat it as an error.
    let resp = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp)
        .await?
        .ok_or_else(|| Error::module(SRC, "HTTP 404 from ulp_search"))?;
    crate::util::http::json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))
}

// ── Emitters ──────────────────────────────────────────────────────────────

fn emit_pbs_v1(
    resp: PbsV1Response,
    entity: &mut Entity,
    result: &mut ModuleResult,
    query: &str,
    scan_id: &str,
) {
    if !resp.success {
        return;
    }
    let Some(data) = resp.data else { return };
    if let Some(err) = &data.error {
        debug!(reason = %err, "niamonx pbs_v1 dataguard");
        return;
    }
    // The documented no-results response carries status "not_found"; a hit
    // carries a positive status string (e.g. "found") that the API does not
    // pin to a fixed constant. Skip only the explicit negative so a real hit
    // is never silently dropped — the content checks below gate the actual
    // emission, so an unexpected or absent status is safe to fall through.
    if data.status.as_deref() == Some("not_found") {
        return;
    }

    if let Some(risk) = &data.risk
        && risk.score > 0
    {
        entity.tag("breach");
        entity.add_evidence(
            Evidence::new(
                SRC,
                format!("NiamonX risk score {}/10 ({})", risk.score, risk.level),
            )
            .with_attr("risk_score", risk.score.to_string())
            .with_attr("risk_level", &risk.level),
        );
    }

    if let Some(meta) = &data.meta {
        if meta.blocks_total > 0 {
            // A breach hit even when risk score is 0/absent — tag it so
            // downstream consumers that key off `breach` see the hit.
            entity.tag("breach");
            let mut ev = Evidence::new(
                SRC,
                format!(
                    "{} breach block(s) in NiamonX 140B dataset",
                    meta.blocks_total
                ),
            )
            .with_attr("blocks_total", meta.blocks_total.to_string());
            if let Some(first_seen) = &meta.first_seen {
                ev = ev.with_attr("first_seen", first_seen);
                // Mirror the PBS-v2 path's canonical `breach_date` key (see the
                // `.with_attr("breach_date", …)` in emit_pbs_v2): the entity is
                // `breach`-tagged, so AU-019's temporal breach-cluster rule
                // (rules/breach.rs) reads `breach_date`, not `first_seen`. Its
                // absence here left every PBS-v1 breach hit unable to
                // date-cluster despite carrying an earliest-exposure date.
                ev = ev.with_attr("breach_date", first_seen);
            }
            if let Some(last_seen) = &meta.last_seen {
                ev = ev.with_attr("last_seen", last_seen);
            }
            entity.add_evidence(ev);
        }
        // Corroborating emails as BFS pivots.
        for email in meta.emails.iter().flatten() {
            if !email.eq_ignore_ascii_case(query) {
                let mut pivot = Entity::new(EntityKind::Email, email, 0.70, scan_id);
                pivot.tag(SRC);
                pivot.tag("pbs-v1-pivot");
                result.push(pivot);
            }
        }
        // Corroborating names as Person pivots. Some breach databases store
        // `names = ["{username} {username}"]` (doubled/slug usernames) when no
        // real name is available — the same schema the sibling see_know and
        // oathnet_pro extractors guard against. Reject before it reaches the graph
        // so a slug username is never minted as a fabricated Person.
        for name in meta.names.iter().flatten() {
            if !name.eq_ignore_ascii_case(query)
                && !crate::core::validation::is_username_derived_name(name)
            {
                let mut pivot = Entity::new(EntityKind::Person, name, 0.65, scan_id);
                pivot.tag(SRC);
                pivot.tag("pbs-v1-pivot");
                result.push(pivot);
            }
        }
    }

    if let Some(rate) = &data.rate
        && rate.remaining < 10
    {
        warn!(remaining = rate.remaining, "niamonx pbs_v1 quota low");
    }

    let blocks = data.blocks.unwrap_or_default();
    if !blocks.is_empty() {
        // Block records are breach hits even when risk score is 0/absent.
        entity.tag("breach");
    }
    for block in blocks {
        let source = block.title.as_deref().unwrap_or("unknown");
        entity.tag(format!("niamonx:breach:{}", slugify(source)));
        if let Some(desc) = &block.description {
            // Full-fidelity policy: the breach description is stored verbatim,
            // never truncated — the operator sees the authentic discovered text.
            entity.add_evidence(
                Evidence::new(SRC, format!("[{source}] {desc}")).with_attr("source", source),
            );
        }
    }
}

fn emit_pbs_v2(
    resp: PbsV2Response,
    entity: &mut Entity,
    result: &mut ModuleResult,
    query: &str,
    scan_id: &str,
) {
    if !resp.success {
        return;
    }
    let Some(data) = resp.data else { return };
    if let Some(err) = &data.error {
        debug!(reason = %err, "niamonx pbs_v2 dataguard");
        return;
    }
    if !data.niamonx_success {
        return;
    }

    // Guard: if stats are present and found == 0 there is nothing to emit.
    // When stats are absent we still process any records in the response
    // (forward-compatible with API changes) but we need the same breach tag.
    if let Some(stats) = &data.stats {
        if stats.found == 0 {
            return;
        }
        entity.tag("breach");
        entity.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "PBS v2: {} record(s) across {} source(s), {} with credentials",
                    stats.found, stats.unique_sources, stats.with_passwords
                ),
            )
            .with_attr("found", stats.found.to_string())
            .with_attr("unique_sources", stats.unique_sources.to_string())
            .with_attr("with_passwords", stats.with_passwords.to_string()),
        );
    }

    let records = data.records.unwrap_or_default();
    if records.is_empty() {
        return;
    }
    // Ensure the breach tag is always set when records are present, even if
    // the stats block was absent (forward-compatibility with API changes).
    entity.tag("breach");

    for record in records {
        let source_name = record
            .source
            .as_ref()
            .and_then(|s| s.name.as_deref())
            .unwrap_or("unknown");
        let breach_date = record
            .source
            .as_ref()
            .and_then(|s| s.breach_date.as_deref())
            .unwrap_or("unknown date");
        let is_compilation = record
            .source
            .as_ref()
            .and_then(|s| s.compilation)
            .unwrap_or(0)
            == 1;

        let label = if is_compilation {
            format!("{source_name} [compilation] ({breach_date})")
        } else {
            format!("{source_name} ({breach_date})")
        };

        entity.tag(format!("niamonx:breach:{}", slugify(source_name)));
        entity.add_evidence(
            Evidence::new(SRC, format!("Breach record: {label}"))
                .with_attr("source", source_name)
                .with_attr("breach_date", breach_date),
        );

        if let Some(email) = record
            .email
            .as_deref()
            .filter(|e| !e.eq_ignore_ascii_case(query))
        {
            let mut pivot = Entity::new(EntityKind::Email, email, 0.70, scan_id);
            pivot.tag(SRC);
            pivot.tag("pbs-v2-pivot");
            result.push(pivot);
        }
        if let Some(uname) = record
            .username
            .as_deref()
            .filter(|u| !u.eq_ignore_ascii_case(query))
        {
            let mut pivot = Entity::new(EntityKind::Username, uname, 0.70, scan_id);
            pivot.tag(SRC);
            pivot.tag("pbs-v2-pivot");
            result.push(pivot);
        }
        if let Some(phone) = &record.phone {
            let mut pivot = Entity::new(EntityKind::Phone, phone, 0.70, scan_id);
            pivot.tag(SRC);
            pivot.tag("pbs-v2-pivot");
            result.push(pivot);
        }
        if let Some(fields) = &record.fields {
            let joined = fields.join(", ");
            entity.add_evidence(
                Evidence::new(SRC, format!("Fields exposed: {joined}")).with_attr("fields", joined),
            );
        }
    }
}

fn emit_ulp(
    resp: UlpResponse,
    entity: &mut Entity,
    result: &mut ModuleResult,
    query: &str,
    scan_id: &str,
) {
    if !resp.success {
        return;
    }
    let Some(data) = resp.data else { return };
    if let Some(err) = &data.error {
        debug!(reason = %err, "niamonx ulp dataguard");
        return;
    }
    let Some(stats) = data.stats else { return };
    if stats.total == 0 {
        return;
    }

    entity.tag("stealer-log");
    entity.tag("infostealer");
    entity.add_evidence(
        Evidence::new(
            SRC,
            format!(
                "ULP (infostealer): {} record(s) across {} host(s), {} with credentials",
                stats.total, stats.unique_hosts, stats.with_password
            ),
        )
        .with_attr("ulp_total", stats.total.to_string())
        .with_attr("unique_hosts", stats.unique_hosts.to_string())
        .with_attr("with_password", stats.with_password.to_string()),
    );

    for record in data.records.unwrap_or_default() {
        let host = record.host.as_deref().unwrap_or("unknown");
        let url = record.url.as_deref().unwrap_or(host);

        entity.tag(format!("niamonx:ulp:{}", slugify(host)));
        let mut ev = Evidence::new(SRC, format!("Stealer log hit: {url}"))
            .with_attr("host", host)
            .with_attr("url", url);
        // Always preserve the captured login on the record evidence (full fidelity),
        // on EVERY target kind — the previous target-kind gate dropped it entirely on
        // Username/IpAddress scans, losing the compromised account for that host.
        if let Some(login) = &record.login {
            ev = ev.with_attr("login", login);
        }
        entity.add_evidence(ev);

        // Promote the login to a first-class pivot when it ADDS information (differs
        // from the query value) — on every target kind. The old Email/Domain-only
        // gate silently dropped a genuinely-new identity that a Username scan surfaces
        // (login `jsmith@gmail.com` for query `jsmith`) or an IpAddress scan surfaces
        // (each compromised account exfiltrated from the victim host). `differs`
        // already suppresses the redundant query-equal login.
        if let Some(login) = &record.login
            && !login.eq_ignore_ascii_case(query)
        {
            let kind = if login.contains('@') {
                EntityKind::Email
            } else {
                EntityKind::Username
            };
            let mut pivot = Entity::new(kind, login, 0.70, scan_id);
            pivot.tag(SRC);
            pivot.tag("ulp-pivot");
            result.push(pivot);
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
