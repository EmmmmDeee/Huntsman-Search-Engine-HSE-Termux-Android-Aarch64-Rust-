//! FOFA infrastructure search engine — host/domain/IP reconnaissance.
//!
//! FOFA is a specialized search engine for discovering internet-connected
//! infrastructure, with deep indexes of open ports, banners, technologies,
//! and TLS certificates. This module queries the FOFA API for Domain/IpAddress
//! targets and surfaces host facts (ports, technologies, service banners).
//!
//! Endpoint: `POST https://fofa.info/api/v1/search`
//! Query format: base64-encoded filter expression (e.g., `host="example.com"`)
//! Auth: `key` query parameter
//!
//! Output: `IpAddress` and `Domain` entities for the hosting infrastructure;
//! open ports, observed technologies, service titles, and OS are attached as
//! evidence attributes on the IP entity rather than emitted as their own
//! entities — providing lateral-movement and infrastructure-mapping signals.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
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
    // Deserialised but not emitted. `host` is FOFA's `host:port` form of the
    // same record `ip` and `port` already carry separately, so emitting it would
    // duplicate an entity the pair below already produces in its canonical
    // shape. Kept rather than dropped because it records the response contract
    // this struct is asserting against — a future change that needs the
    // authority (e.g. a URL-shaped host) has the field already mapped.
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

/// Escape a value for embedding inside a double-quoted FOFA filter literal.
///
/// # Why this exists
///
/// [`fofa_filter`] builds `ip="{value}"` / `host="{value}"` and the whole
/// filter is base64'd, not JSON- or URL-encoded, so nothing downstream
/// escapes it — this is the only point that can. `target.value` reaches here
/// from two different places with two different trust levels:
///
/// - **Seed targets** go through [`Target::validate`](crate::core::scan::Target::validate),
///   which restricts a `Domain` to ASCII alphanumeric/`.`/`-`/`_` and parses an
///   `IpAddress` through [`std::net::IpAddr`] — neither can contain a `"`.
/// - **Pivot targets**, built during expansion from an entity's value
///   (`Target::new(tk, entity.value.clone())` in `core/engine/mod.rs`), do
///   **not** go through that gate before dispatch. And a Domain/IP entity can
///   come from this very module: [`build_entities`] mints one straight from
///   `hit.domain` / `hit.ip` in FOFA's own JSON response — a field describing
///   whatever the scanned host presents, not something this crate controls.
///
/// So an unescaped `"` in a later round's pivot value would close the filter
/// early and splice arbitrary FOFA query syntax into a search run under the
/// operator's own paid key. Escaping here removes that path regardless of
/// which caller the value came from, rather than trusting every caller to
/// have validated first.
///
/// FOFA's own escaping grammar is not verified against live documentation
/// (unavailable from this environment); this applies the minimal transform
/// correct for virtually every quoted-string query DSL — backslash-escape `\`
/// first, then `"` — so a value can never terminate the literal early. Order
/// matters: escaping the quote before the backslash would double-escape the
/// backslash just inserted.
fn escape_fofa_value(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Build the FOFA filter for a target. IP → `ip="x.x.x.x"`, Domain → `host="domain.com"`,
/// Email → fall back to a domain-extraction search (if the email part looks domain-like).
pub(super) fn fofa_filter(target: &Target) -> Option<String> {
    match target.kind {
        TargetKind::IpAddress => Some(format!("ip=\"{}\"", escape_fofa_value(target.value.trim()))),
        TargetKind::Domain => Some(format!(
            "host=\"{}\"",
            escape_fofa_value(target.value.trim())
        )),
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
        // Exactly the kinds `build_entities` can mint. `Organisation` was listed
        // here but never emitted: FOFA's response as this module models it
        // (`FofaResult`) carries no organisation field, and inventing one would
        // require a live-schema field name this environment cannot verify — so
        // the honest contract is IP + Domain only. A phantom `produces()` entry
        // misleads scan planning and the `hse modules` reference into thinking
        // the module can yield an entity kind it structurally cannot. Pinned by
        // `produces_lists_exactly_the_kinds_build_entities_emits`.
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Domain];
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
/// Emits `IpAddress` and `Domain` entities from each result (ports/technologies/
/// OS ride as evidence on the IP, not as their own entities).
fn build_entities(body: &FofaResp, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    for hit in &body.results {
        if !hit.ip.is_empty() {
            // An IP FOFA returns for the queried host is a direct, indexed
            // observation of that host's infrastructure — the provider scanned
            // it — so it sits a rung above the domain below, which is derived
            // from the same record rather than observed on its own.
            let mut ip_entity = Entity::new(
                EntityKind::IpAddress,
                &hit.ip,
                confidence::HIGH_PLUSPLUS,
                scan_id,
            );
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
            // A domain read off the same record is the provider's own
            // association rather than something it scanned directly, so it
            // stays one rung below the IP.
            let mut domain_entity = Entity::new(
                EntityKind::Domain,
                &hit.domain,
                confidence::VERY_HIGH,
                scan_id,
            );
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
