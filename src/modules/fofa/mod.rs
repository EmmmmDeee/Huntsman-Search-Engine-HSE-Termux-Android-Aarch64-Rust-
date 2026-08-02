//! FOFA infrastructure search engine — host/domain/IP reconnaissance.
//!
//! FOFA is a specialized search engine for discovering internet-connected
//! infrastructure, with deep indexes of open ports, banners, technologies,
//! and TLS certificates. This module queries the FOFA API for Domain/IpAddress
//! targets and surfaces host facts (ports, technologies, organizations).
//!
//! Endpoint: `POST https://fofa.info/api/v1/search`
//! Query format: base64-encoded filter expression (e.g., `host="example.com"`)
//! Auth: `key` query parameter
//!
//! Output: hosting domains/IPs, open ports, observed technologies, registrant
//! organizations — providing lateral-movement and infrastructure-mapping signals.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "fofa";
const KEY_ENV: &str = "HUNTSMAN_FOFA_KEY";

pub struct Fofa;

#[derive(Deserialize, Default)]
#[serde(default)]
struct FofaResp {
    error: bool,
    errmsg: Option<String>,
    results: Vec<FofaResult>,
}

#[derive(Deserialize)]
struct FofaResult {
    #[serde(default)]
    #[allow(dead_code)]
    host: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    os: String,
}

/// Encode a FOFA search filter to base64. FOFA requires base64-encoded queries.
/// Examples: `host="example.com"`, `ip="1.1.1.1"`, etc.
pub(super) fn encode_fofa_query(filter: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(filter.as_bytes())
}

/// Build the FOFA filter for a target. IP → `ip="x.x.x.x"`, Domain → `host="domain.com"`,
/// Email → fall back to a domain-extraction search (if the email part looks domain-like).
pub(super) fn fofa_filter(target: &Target) -> Option<String> {
    match target.kind {
        TargetKind::IpAddress => Some(format!("ip=\"{}\"", target.value.trim())),
        TargetKind::Domain => Some(format!("host=\"{}\"", target.value.trim())),
        _ => None,
    }
}

#[async_trait]
impl Module for Fofa {
    fn name(&self) -> &'static str {
        "fofa"
    }

    fn description(&self) -> &'static str {
        "FOFA infrastructure search: open ports, technologies, hosting domains, TLS certificates"
    }

    fn priority(&self) -> u8 {
        78
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Organisation,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        172_800
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        let filter = match fofa_filter(target) {
            Some(f) => f,
            None => return Ok(ModuleResult::new()),
        };

        let query = encode_fofa_query(&filter);
        let url = format!(
            "https://fofa.info/api/v1/search?key={key}&qbase64={query}&size=100&full=false"
        );

        let resp = ctx
            .http
            .post(&url)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;

        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: FofaResp = crate::util::http::json_decode(SRC, resp).await?;

        if body.error {
            if let Some(msg) = body.errmsg {
                tracing::warn!(target: "module.fofa", "FOFA error: {}", msg);
            }
            return Ok(ModuleResult::new());
        }

        Ok(build_entities(&body, &ctx.scan_id))
    }
}

/// Map a decoded FOFA response to entities. **Pure** (no network/IO).
/// Emits IP, Domain, and Organisation entities from each result.
fn build_entities(body: &FofaResp, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    for hit in &body.results {
        if !hit.ip.is_empty() {
            let mut ip_entity = Entity::new(EntityKind::IpAddress, &hit.ip, 0.80, scan_id);
            ip_entity.tag("fofa-host");

            let mut evidence = Evidence::new(SRC, format!("FOFA intelligence for {}", hit.ip));
            if !hit.protocol.is_empty() {
                evidence = evidence.with_attr("protocol", &hit.protocol);
            }
            if !hit.title.is_empty() {
                evidence = evidence.with_attr("service_title", &hit.title);
            }
            if !hit.os.is_empty() {
                evidence = evidence.with_attr("os", &hit.os);
            }
            if hit.port > 0 {
                evidence = evidence.with_attr("open_port", hit.port.to_string());
            }

            ip_entity.add_evidence(evidence);
            result.push(ip_entity);
        }

        if !hit.domain.is_empty() && hit.domain != "-" {
            let mut domain_entity = Entity::new(EntityKind::Domain, &hit.domain, 0.75, scan_id);
            domain_entity.tag("fofa-discovered");
            domain_entity.add_evidence(Evidence::new(
                SRC,
                format!("Domain discovered via FOFA for {}", hit.ip),
            ));
            result.push(domain_entity);
        }
    }

    result
}
