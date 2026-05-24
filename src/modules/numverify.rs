//! Numverify phone validation. Key-gated, 100 free lookups/month.
//!
//! Endpoint: `GET http://apilayer.net/api/validate?access_key={KEY}&number={E164}`
//! Returns: validity flag + country/carrier/line-type. The free plan
//! is HTTP-only (the docs note this); we honour that to avoid a TLS
//! handshake the upstream will reject for free-tier callers.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const KEY_ENV: &str = "HUNTSMAN_NUMVERIFY_KEY";

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    number: Option<String>,
    #[serde(default)]
    local_format: Option<String>,
    #[serde(default)]
    international_format: Option<String>,
    #[serde(default)]
    country_prefix: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    carrier: Option<String>,
    #[serde(default)]
    line_type: Option<String>,
}

pub struct Numverify;

#[async_trait]
impl Module for Numverify {
    fn name(&self) -> &'static str {
        "numverify"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Phone)
    }
    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let phone: String = target
            .value
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '+')
            .collect();
        if phone.is_empty() {
            return Ok(ModuleResult::new());
        }
        // Numverify accepts both formats; strip leading '+' since their
        // examples use E.164 without it.
        let q = phone.trim_start_matches('+');
        let url = format!(
            "http://apilayer.net/api/validate?access_key={}&number={}",
            urlencode(key),
            urlencode(q),
        );
        let Some(body): Option<Resp> = fetch_json_or_404(&ctx.http, "numverify", &url).await?
        else {
            return Ok(ModuleResult::new());
        };
        if body.valid != Some(true) {
            return Ok(ModuleResult::new());
        }
        let mut entity = Entity::new(EntityKind::Phone, &target.value, 0.92, &ctx.scan_id);
        entity.tag("numverify");
        entity.tag("validated");
        if let Some(c) = body.country_code.as_deref() {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }
        if let Some(lt) = body.line_type.as_deref()
            && !lt.is_empty()
        {
            entity.tag(format!("line:{lt}"));
        }
        let mut ev = Evidence::new(
            "numverify",
            format!("Numverify confirmed valid phone {}", target.value),
        );
        if let Some(v) = body.number.as_deref() {
            ev = ev.with_attr("normalised", v);
        }
        if let Some(v) = body.international_format.as_deref() {
            ev = ev.with_attr("international", v);
        }
        if let Some(v) = body.local_format.as_deref() {
            ev = ev.with_attr("local", v);
        }
        if let Some(v) = body.country_prefix.as_deref() {
            ev = ev.with_attr("country_prefix", v);
        }
        if let Some(v) = body.country_name.as_deref() {
            ev = ev.with_attr("country", v);
        }
        if let Some(v) = body.location.as_deref() {
            ev = ev.with_attr("location", v);
        }
        if let Some(v) = body.carrier.as_deref() {
            ev = ev.with_attr("carrier", v);
        }
        if let Some(v) = body.line_type.as_deref() {
            ev = ev.with_attr("line_type", v);
        }
        entity.add_evidence(ev);
        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_phone() {
        let m = Numverify;
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(Numverify.cost(), ModuleCost::KeyGated));
    }
}
