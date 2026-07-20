//! DeHashed breach search (v2 API). Paid; requires `HUNTSMAN_DEHASHED_KEY`
//! **and** an active DeHashed *search subscription* + API credits on the
//! account.
//!
//! Endpoint: `POST https://api.dehashed.com/v2/search`
//! Auth:     `Dehashed-Api-Key: <key>` header.
//!
//! v2 is **key-only**. The legacy v1 `GET /search` endpoint (HTTP Basic with
//! an account email + key) was sunset and now returns 404, so the old
//! account-email variable (formerly required alongside the key) is gone — a
//! single API key is all v2 needs.
//!
//! Full-fidelity extraction: DeHashed exists to return breach records — incl.
//! the password and `hashed_password` digest — so the per-record extractor
//! surfaces EVERY field. The hash becomes a first-class `Password` entity (a
//! reverse-searchable node) and rides on each record's evidence as the
//! `hashed_password` attribute the hash-reuse identity linker (`AU-105`) groups
//! on, so the same hash across two accounts (or two providers) links them.
//! Nothing is redacted or truncated. A broad search (above all a `name` query)
//! can return same-name strangers; their entities are demoted to quarantined
//! `candidate` leads — retained for transparency, never masquerading as the
//! subject — exactly as `oathnet_pro` / `see_know` do.

use async_trait::async_trait;

use crate::core::{
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::handle_keyed_error;

mod types;
use types::DehashedResp;

mod build;
use build::{balance_str, build_breach_entity, extract_records, selector_for};

#[cfg(test)]
mod tests;

const KEY_ENV: &str = "HUNTSMAN_DEHASHED_KEY";

/// v2 search endpoint — POST, JSON body, key in the `Dehashed-Api-Key` header.
const V2_SEARCH_URL: &str = "https://api.dehashed.com/v2/search";

/// Results requested per page. The aggregate evidence only needs the server's
/// `total` count plus a representative sample of `database_name`s, so the page
/// is kept small to bound both the response size and the credit cost (v2 bills
/// against a per-account credit pool) rather than pulling up to 10,000 rows.
const PAGE_SIZE: u32 = 100;

pub struct DeHashed;

#[async_trait]
impl Module for DeHashed {
    fn name(&self) -> &'static str {
        "dehashed"
    }
    fn description(&self) -> &'static str {
        "Breach record search across leaked databases"
    }
    fn priority(&self) -> u8 {
        118
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::Phone
                | TargetKind::FullName
                | TargetKind::IpAddress
                | TargetKind::Domain
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // DeHashed's per-record extractor (this file, ip_address/ip/last_ip)
        // plus the shared `breach_rich::extract_rich_detail` "maximum raw
        // data" pass it runs (see `build.rs`'s call site) together mint the
        // full breach-pool surface — the same set `see_know`/`oathnet_pro`
        // declare for running the identical shared extractor — not just
        // credentials/email/name. Declaring only three under-reports what
        // every hit actually collects.
        &[
            "T1589.001", // Credentials — leaked passwords / hashes
            "T1589.002", // Email Addresses
            "T1589.003", // Employee Names — name / full_name → Person
            "T1590.005", // IP Addresses — ip_address / ip / last_ip
            "T1591.001", // Determine Physical Locations — address / coords / city-state
            "T1591.002", // Business Relationships — company / employer / org
            "T1592",     // Gather Victim Host Information — MAC / HWID / device_id
            "T1593.001", // Social Media — telegram / facebook / instagram / … handles
            "T1597.002", // Purchase Technical Data — a paid, closed breach-data feed
        ]
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        // Per-record extraction surfaces the full breach record: identity, the
        // credential secret (incl. the hash → `Password`), and the long tail via
        // the shared `breach_rich` pass (plus `Other(<field>)` for every remaining
        // raw field — an unbounded set, so not enumerable here).
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::Person,
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Password,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Organisation,
            EntityKind::MacAddress,
            EntityKind::DeviceId,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(initial_key) = ctx.key_opt(KEY_ENV) else {
            return Ok(ModuleResult::new());
        };
        let Some(selector) = selector_for(target.kind) else {
            return Ok(ModuleResult::new());
        };
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        // v2: POST a JSON body with the query string + pagination. The key
        // rides in the `Dehashed-Api-Key` header (no Basic auth, no email).
        let payload = serde_json::json!({
            "query": format!("{selector}:{value}"),
            "page": 1,
            "size": PAGE_SIZE,
        });

        // Key cascade: begin on the hot-injected key and, on a terminal
        // 401/403/429 (quota/auth failure), rotate to the next USABLE pooled key
        // the pool holds for DeHashed and retry — so one process() call spends
        // every credential available instead of dying on the first key's quota
        // while sibling keys sit idle. `tried` records each burned key so the
        // cascade never re-hands one, and terminates once no untried key remains.
        let mut tried: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut key = initial_key.to_string();
        let body: DehashedResp = 'cascade: loop {
            tried.insert(key.clone());
            let mut retries = 2u8;
            loop {
                if ctx.cancel.is_cancelled() {
                    return Ok(ModuleResult::new());
                }
                let resp = ctx
                    .http
                    .post(V2_SEARCH_URL)
                    .header("Dehashed-Api-Key", &key)
                    .header("Accept", "application/json")
                    .json(&payload)
                    .send_tagged(build::SRC)
                    .await?;
                let status = resp.status();
                if !status.is_success() {
                    let code = status.as_u16();
                    if handle_keyed_error(code, resp.headers(), &mut retries, build::SRC, &key, ctx)
                        .await
                    {
                        continue;
                    }
                    // Terminal on this key. If it was a key quota/auth failure and
                    // the pool still has an untried, usable key, cascade to it
                    // rather than surfacing an outage the pool could have avoided.
                    if crate::util::http::is_keyed_error_status(code)
                        && let Some(next) = ctx.next_pooled_key(build::SRC, &tried)
                    {
                        key = next;
                        continue 'cascade;
                    }
                    // The body carries DeHashed's own reason — notably the 401
                    // "You need a search subscription and API credits to use the
                    // API" that an account without an active search plan returns —
                    // so surface it verbatim for the operator.
                    return Err(crate::util::http::http_status_error(build::SRC, resp).await);
                }
                // json_scanned: dehashed responses contain breach data including
                // leaked credentials — scan the raw body for API keys.
                break 'cascade crate::util::http::json_scanned(resp, build::SRC)
                    .await
                    .map_err(|e| crate::core::error::Error::module(build::SRC, e))?;
            }
        };

        let entries = body.entries.unwrap_or_default();
        let total = body.total.unwrap_or(entries.len() as u64);
        if entries.is_empty() && total == 0 {
            return Ok(ModuleResult::new());
        }

        // Stable origin fingerprint of the exact key in use — stamped onto every
        // record's evidence as `api_key_origin`, so each finding declares its
        // provenance. The full secret is never written (the middle is elided).
        let key_fp = crate::util::oathnet::key_fingerprint(&key);
        let balance = balance_str(&body.balance);
        let mut result = ModuleResult::new();
        // The breach-presence headline is emitted ONLY when the response is
        // attributable to the subject — a bare `name:` count, or a page of
        // same-name strangers, yields `None` rather than a false 0.88 hit on the
        // engine's pre-seeded subject anchor (see `build_breach_entity`).
        if let Some(headline) = build_breach_entity(
            target.kind.to_entity_kind(),
            value,
            selector,
            &entries,
            total,
            balance.as_deref(),
            &ctx.scan_id,
        ) {
            result.push(headline);
        }
        // Surface every record's identity, credential (incl. the hash digest),
        // and full long tail — non-target strangers demoted to quarantined
        // candidates. This is what makes DeHashed hashes reverse-searchable and
        // AU-105-linkable rather than discarded.
        let mut seen = std::collections::HashSet::new();
        extract_records(
            &entries,
            value,
            &key_fp,
            &ctx.scan_id,
            &mut seen,
            &mut result,
        );
        Ok(result)
    }
}
