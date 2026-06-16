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
use crate::util::str_util::{slugify, truncate_display};

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

    fn produces(&self) -> &'static [EntityKind] {
        // Domain is accepted as input but no Domain pivot entity is ever emitted.
        const KINDS: &[EntityKind] = &[EntityKind::Email, EntityKind::Username, EntityKind::Phone];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let query = &target.value;
        let key = ctx.key(KEY_ENV)?;
        let ulp_type = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Domain => "domain",
            _ => "auto",
        };

        // All three endpoints are independent — run concurrently.
        let (r1, r2, r3) = tokio::join!(
            fetch_pbs_v1(&ctx.http, key, query, ctx),
            fetch_pbs_v2(&ctx.http, key, query, ctx),
            fetch_ulp(&ctx.http, key, query, ulp_type, ctx),
        );

        let mut entity = target.to_entity(0.80, &ctx.scan_id);
        entity.tag(SRC);

        match r1 {
            Ok(r) => emit_pbs_v1(r, &mut entity, &mut result, query, &ctx.scan_id),
            Err(e) => warn!(error = %e, "niamonx pbs_v1 failed"),
        }
        match r2 {
            Ok(r) => emit_pbs_v2(r, &mut entity, &mut result, query, &ctx.scan_id),
            Err(e) => warn!(error = %e, "niamonx pbs_v2 failed"),
        }
        match r3 {
            Ok(r) => emit_ulp(
                r,
                target.kind,
                &mut entity,
                &mut result,
                query,
                &ctx.scan_id,
            ),
            Err(e) => warn!(error = %e, "niamonx ulp failed"),
        }

        // Only emit the entity when at least one endpoint contributed evidence.
        if !entity.evidence.is_empty() {
            result.push(entity);
        }
        Ok(result)
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
        .send()
        .await
        .map_err(|e| Error::module(SRC, e.to_string()))?;
    if !resp.status().is_success() {
        crate::util::http::note_keyed_error(resp.status().as_u16(), SRC, key, ctx);
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
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
        .send()
        .await
        .map_err(|e| Error::module(SRC, e.to_string()))?;
    if !resp.status().is_success() {
        crate::util::http::note_keyed_error(resp.status().as_u16(), SRC, key, ctx);
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
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
        .send()
        .await
        .map_err(|e| Error::module(SRC, e.to_string()))?;
    if !resp.status().is_success() {
        crate::util::http::note_keyed_error(resp.status().as_u16(), SRC, key, ctx);
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
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
    if data.status.as_deref() != Some("ok") {
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
            entity.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "{} breach block(s) in NiamonX 140B dataset",
                        meta.blocks_total
                    ),
                )
                .with_attr("blocks_total", meta.blocks_total.to_string()),
            );
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
            entity.add_evidence(
                Evidence::new(SRC, format!("[{source}] {}", truncate_display(desc, 200)))
                    .with_attr("source", source),
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
    target_kind: TargetKind,
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
        entity.add_evidence(
            Evidence::new(SRC, format!("Stealer log hit: {url}"))
                .with_attr("host", host)
                .with_attr("url", url),
        );

        // Promote login to pivot only when it adds information.
        if let Some(login) = &record.login {
            let differs = !login.eq_ignore_ascii_case(query);
            let useful = matches!(target_kind, TargetKind::Email | TargetKind::Domain);
            if differs && useful {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn accepts_expected_kinds() {
        let m = NiamonX;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    }

    #[test]
    fn pbs_v1_skips_non_ok_status() {
        let resp = PbsV1Response {
            success: true,
            data: Some(PbsV1Data {
                status: Some("not_found".to_string()),
                error: None,
                meta: None,
                risk: None,
                blocks: None,
                rate: None,
            }),
        };
        let target = Target::new(TargetKind::Email, "x@y.com");
        let mut entity = target.to_entity(0.80, "s");
        let mut result = ModuleResult::new();
        emit_pbs_v1(resp, &mut entity, &mut result, "x@y.com", "s");
        assert!(!entity.has_tag("breach"));
        assert!(entity.evidence.is_empty());
    }

    #[test]
    fn pbs_v1_tags_breach_on_blocks_without_risk() {
        // A real hit with breach blocks but no/zero risk score must still set
        // the generic `breach` tag so downstream consumers see it.
        let resp = PbsV1Response {
            success: true,
            data: Some(PbsV1Data {
                status: Some("ok".to_string()),
                error: None,
                meta: Some(PbsV1Meta {
                    blocks_total: 2,
                    emails: None,
                }),
                risk: None,
                blocks: Some(vec![PbsV1Block {
                    title: Some("ExampleLeak".to_string()),
                    description: Some("leak".to_string()),
                }]),
                rate: None,
            }),
        };
        let target = Target::new(TargetKind::Email, "x@y.com");
        let mut entity = target.to_entity(0.80, "s");
        let mut result = ModuleResult::new();
        emit_pbs_v1(resp, &mut entity, &mut result, "x@y.com", "s");
        assert!(entity.has_tag("breach"));
        assert!(entity.has_tag("niamonx:breach:exampleleak"));
    }

    #[test]
    fn ulp_emits_stealer_tag_and_pivots() {
        let resp = UlpResponse {
            success: true,
            data: Some(UlpData {
                error: None,
                stats: Some(UlpStats {
                    total: 1,
                    unique_hosts: 1,
                    with_password: 1,
                }),
                records: Some(vec![UlpRecord {
                    url: Some("https://bank.example.com/login".to_string()),
                    host: Some("bank.example.com".to_string()),
                    login: Some("other@example.com".to_string()),
                }]),
            }),
        };
        let target = Target::new(TargetKind::Email, "victim@example.com");
        let mut entity = target.to_entity(0.80, "s");
        let mut result = ModuleResult::new();
        emit_ulp(
            resp,
            TargetKind::Email,
            &mut entity,
            &mut result,
            "victim@example.com",
            "s",
        );
        assert!(entity.has_tag("stealer-log"));
        assert!(entity.has_tag("infostealer"));
        // login differs from query and target is Email → pivot emitted
        assert_eq!(result.entities.len(), 1);
        assert_eq!(result.entities[0].kind, EntityKind::Email);
    }
}
