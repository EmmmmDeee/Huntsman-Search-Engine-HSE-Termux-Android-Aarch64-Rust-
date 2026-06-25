//! NumVerify phone validation — live carrier, line type & region for a number.
//!
//! Endpoint: `GET https://api.apilayer.com/number_verification/validate?number=…`
//! Auth:     `apikey` header. Key-gated (`HUNTSMAN_NUMVERIFY_KEY`, free tier
//!           available). Inert with no key.
//!
//! Upgrades the project's *offline* phone-geo tables (`phone_intl`,
//! `phone_geo`) to authoritative live data: for a `+61` (or any) number
//! it returns validity, **carrier**, **line type** (mobile/landline/voip), and
//! **region** — emitted as a geocodable `Address` plus carrier/line evidence.
//!
//! The response→entity mapping is the pure `build_entity` (unit-tested); the
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
        const KINDS: &[EntityKind] = &[EntityKind::Address, EntityKind::Organisation];
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
        let resp = ctx
            .http
            .get(&url)
            .header("apikey", key)
            .send_tagged(SRC)
            .await?;

        // 401/403/429 → note_keyed_error + Err; 404 → empty; other non-2xx → Err.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };
        let parsed: NvResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| Error::module(SRC, e))?;

        let mut result = ModuleResult::new();
        result
            .entities
            .extend(build_entities(&parsed, &ctx.scan_id));
        Ok(result)
    }
}

/// Map a validation response to entities. **Pure** (no network/IO):
/// emits an `Address` (geocodable region/country) and, when the carrier
/// is present, an `Organisation` for the carrier — consistent with
/// ip2location/ipquery which emit the ISP as an Organisation pivot.
/// Returns an empty `Vec` when the number is invalid or carries no usable region.
fn build_entities(r: &NvResp, scan_id: &str) -> Vec<Entity> {
    if !r.valid {
        return Vec::new();
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
        (None, None) => return Vec::new(),
    };

    let mut out = Vec::new();

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
    out.push(e);

    // Carrier → Organisation pivot (same pattern as ip2location ISP extraction).
    if let Some(carrier) = r.carrier.as_deref().map(str::trim).filter(|c| c.len() >= 2) {
        let mut oe = Entity::new(EntityKind::Organisation, carrier, 0.60, scan_id);
        oe.tag(SRC);
        oe.tag("carrier");
        oe.add_evidence(Evidence::new(SRC, format!("Phone carrier: {carrier}")));
        out.push(oe);
    }

    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
