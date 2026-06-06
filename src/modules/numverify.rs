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
        let resp = ctx
            .http
            .get(&url)
            .header("apikey", key)
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            if matches!(code, 401 | 403 | 429) {
                ctx.report_key_exhausted(SRC, key, code);
            }
            return Err(Error::module(SRC, format!("HTTP {status}")));
        }
        let parsed: NvResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| Error::module(SRC, e))?;

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
    use super::*;

    #[test]
    fn build_entity_emits_region_with_carrier_evidence() {
        let r = NvResp {
            valid: true,
            country_code: Some("AU".into()),
            country_name: Some("Australia".into()),
            location: Some("Queensland".into()),
            carrier: Some("Telstra".into()),
            line_type: Some("mobile".into()),
            international_format: Some("+61400000000".into()),
        };
        let e = build_entity(&r, "scan").unwrap();
        assert_eq!(e.kind, EntityKind::Address);
        assert_eq!(e.value, "Queensland, Australia");
        assert!(
            e.has_tag("phone-region") && e.has_tag("carrier-known") && e.has_tag("line:mobile")
        );
        let attr = |k: &str| e.evidence[0].attributes.get(k).cloned().unwrap_or_default();
        assert_eq!(attr("carrier"), "Telstra");
        assert_eq!(attr("line_type"), "mobile");
        assert_eq!(attr("country_code"), "AU");
    }

    #[test]
    fn invalid_number_yields_nothing() {
        let r = NvResp {
            valid: false,
            ..Default::default()
        };
        assert!(build_entity(&r, "scan").is_none());
    }

    #[test]
    fn country_only_still_geolocates() {
        let r = NvResp {
            valid: true,
            country_name: Some("Australia".into()),
            ..Default::default()
        };
        assert_eq!(build_entity(&r, "scan").unwrap().value, "Australia");
    }

    #[test]
    fn metadata_is_keygated_phone() {
        let m = NumVerify;
        assert_eq!(m.cost(), ModuleCost::KeyGated);
        assert_eq!(m.category(), ModuleCategory::Phone);
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }
}
