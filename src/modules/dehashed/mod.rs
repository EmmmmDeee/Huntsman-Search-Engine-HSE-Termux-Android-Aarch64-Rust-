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
//! Per the project's no-credentials-in-evidence invariant, we deliberately do
//! NOT bind the `password` / `hashed_password` fields a v2 entry carries —
//! serde drops every field we don't name, so they can't even accidentally be
//! surfaced. Only aggregate metadata escapes: total hits, rows returned, the
//! top source databases, and the remaining API credit balance.

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
use build::{balance_str, build_breach_entity, selector_for};

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
        &["T1589.001", "T1589.002", "T1589.003"]
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        // DeHashed enriches the seed entity only — breach metadata is attached
        // as evidence attrs rather than new pivot entities.
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::Person,
            EntityKind::IpAddress,
            EntityKind::Domain,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(key) = ctx.key_opt(KEY_ENV) else {
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

        let mut retries = 2u8;
        let body: DehashedResp = loop {
            if ctx.cancel.is_cancelled() {
                return Ok(ModuleResult::new());
            }
            let resp = ctx
                .http
                .post(V2_SEARCH_URL)
                .header("Dehashed-Api-Key", key)
                .header("Accept", "application/json")
                .json(&payload)
                .send_tagged(build::SRC)
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, build::SRC, key, ctx)
                    .await
                {
                    continue;
                }
                // The body carries DeHashed's own reason — notably the 401
                // "You need a search subscription and API credits to use the
                // API" that an account without an active search plan returns —
                // so surface it verbatim for the operator.
                return Err(crate::util::http::http_status_error(build::SRC, resp).await);
            }
            // json_scanned: dehashed responses contain breach data including
            // leaked credentials — scan the raw body for API keys.
            break crate::util::http::json_scanned(resp, build::SRC)
                .await
                .map_err(|e| crate::core::error::Error::module(build::SRC, e))?;
        };

        let entries = body.entries.unwrap_or_default();
        let total = body.total.unwrap_or(entries.len() as u64);
        if entries.is_empty() && total == 0 {
            return Ok(ModuleResult::new());
        }

        let balance = balance_str(&body.balance);
        let mut result = ModuleResult::new();
        result.push(build_breach_entity(
            target.kind.to_entity_kind(),
            value,
            selector,
            &entries,
            total,
            balance.as_deref(),
            &ctx.scan_id,
        ));
        Ok(result)
    }
}
