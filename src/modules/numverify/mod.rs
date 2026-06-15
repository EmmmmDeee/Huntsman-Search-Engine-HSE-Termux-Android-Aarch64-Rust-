//! NumVerify phone validation — live carrier, line type & region for a number.
//!
//! Endpoint: `GET https://api.apilayer.com/number_verification/validate?number=…`
//! Auth:     `apikey` header. Key-gated (`HUNTSMAN_NUMVERIFY_KEY`, free tier
//!           available). Inert with no key.
//!
//! Upgrades the project's *offline* phone-geo tables (`phone_intl`,
//! `phone_carrier_geo`) to authoritative live data: for a `+61` (or any) number
//! it returns validity, **carrier**, **line type** (mobile/landline/voip), and
//! **region** — emitted as a geocodable `Address` plus carrier/line evidence.
//!
//! The response→entity mapping is the pure [`build_entity`] (unit-tested); the
//! network shell owns only auth/transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

const SRC: &str = "numverify";
const KEY_ENV: &str = "HUNTSMAN_NUMVERIFY_KEY";

pub struct NumVerify;

#[derive(Deserialize, Default)]
#[serde(default)]
struct NvResp {
    valid: bool,
    country_code: Option<String>,
    country_name: Option<String>,
    location: Option<String>,
    carrier: Option<String>,
    line_type: Option<String>,
    international_format: Option<String>,
}

#[async_trait]
impl Module for NumVerify {
    fn name(&self) -> &'static str {
        "numverify"
    }

    fn description(&self) -> &'static str {
        "NumVerify phone validation — live carrier, line type & region (key-gated)"
    }

    fn priority(&self) -> u8 {
        139
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Phone)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Phone
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Phone default (T1589 Gather Victim Identity Information) is correct for
        // phone number lookup, but numverify also maps the carrier country to an
        // Address entity — Determine Physical Locations (T1591.001).
        &["T1589", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(key) = ctx.key_opt(KEY_ENV) else {
            return Ok(ModuleResult::new());
        };
        let number = target.value.trim();
        let url = format!(
            "https://api.apilayer.com/number_verification/validate?number={}",
            urlencode(number)
        );
        let cache_key = number.to_lowercase();
        let nv_text: String =
            if let Some(cached) = crate::core::api_cache::global().get(SRC, &cache_key) {
                cached.body
            } else {
                let resp = ctx
                    .http
                    .get(&url)
                    .header("apikey", key)
                    .send_tagged(SRC)
                    .await?;

                let status = resp.status();
                if !status.is_success() {
                    let code = status.as_u16();
                    crate::util::http::note_keyed_error(code, SRC, key, ctx);
                    return Err(Error::module(SRC, format!("HTTP {status}")));
                }
                let text = resp
                    .text()
                    .await
                    .map_err(|e| Error::module(SRC, format!("body: {e}")))?;
                crate::core::api_cache::global().put(
                    SRC,
                    &cache_key,
                    &text,
                    crate::core::api_cache::ttl_secs(SRC),
                );
                text
            };
        let parsed: NvResp =
            serde_json::from_str(&nv_text).map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        let mut result = ModuleResult::new();
        if let Some(e) = build_entity(&parsed, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

/// Map a validation response to a geocodable region `Address` carrying carrier /
/// line-type / country evidence. `None` when the number is invalid or carries no
/// usable region. Pure of I/O (unit-tested).
fn build_entity(r: &NvResp, scan_id: &str) -> Option<Entity> {
    if !r.valid {
        return None;
    }
    // A geocodable place string from region + country (either may be absent).
    let region = r
        .location
        .as_deref()
        .map(str::trim)
        .filter(|s| s.len() >= 2);
    let country = r
        .country_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let place = match (region, country) {
        (Some(reg), Some(c)) => format!("{reg}, {c}"),
        (Some(reg), None) => reg.to_string(),
        (None, Some(c)) => c.to_string(),
        (None, None) => return None,
    };

    let mut e = Entity::new(EntityKind::Address, &place, 0.55, scan_id);
    e.tag(SRC);
    e.tag("geo-hint");
    e.tag("phone-region");
    let mut ev = Evidence::new(SRC, "NumVerify phone metadata");
    if let Some(c) = r.carrier.as_deref().filter(|c| !c.is_empty()) {
        e.tag("carrier-known");
        ev = ev.with_attr("carrier", c);
    }
    if let Some(lt) = r.line_type.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("line_type", lt);
        e.tag(format!("line:{lt}"));
    }
    if let Some(cc) = &r.country_code {
        ev = ev.with_attr("country_code", cc);
    }
    if let Some(intl) = &r.international_format {
        ev = ev.with_attr("international_format", intl);
    }
    e.add_evidence(ev);
    Some(e)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
