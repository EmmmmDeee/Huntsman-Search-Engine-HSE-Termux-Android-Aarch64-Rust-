use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::Evidence,
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
    fn description(&self) -> &'static str {
        "Phone number validation and carrier lookup"
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
        let mut phone = String::with_capacity(target.value.len());
        phone.extend(
            target
                .value
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '+'),
        );
        if phone.is_empty() {
            return Ok(ModuleResult::new());
        }
        let q = phone.trim_start_matches('+');
        let qs = format!(
            "/api/validate?access_key={}&number={}",
            urlencode(key),
            urlencode(q),
        );
        // HTTPS first; free-tier may reject TLS, so fall back to HTTP.
        let https = format!("https://apilayer.net{qs}");
        let (body_opt, transport): (Option<Resp>, &'static str) =
            match fetch_json_or_404(&ctx.http, "numverify", &https).await {
                Ok(b) => (b, "https"),
                Err(_) => {
                    let http = format!("http://apilayer.net{qs}");
                    (
                        fetch_json_or_404(&ctx.http, "numverify", &http).await?,
                        "http",
                    )
                }
            };
        let Some(body) = body_opt else {
            return Ok(ModuleResult::new());
        };
        if body.valid != Some(true) {
            return Ok(ModuleResult::new());
        }
        let mut entity = target.to_entity(0.92, &ctx.scan_id);
        entity.tag("numverify");
        entity.tag("validated");
        entity.tag(format!("transport:{transport}"));
        if let Some(c) = body.country_code.as_deref() {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }
        if let Some(lt) = body.line_type.as_deref()
            && !lt.is_empty()
        {
            entity.tag(format!("line:{lt}"));
        }
        let ev = Evidence::new(
            "numverify",
            format!("Numverify confirmed valid phone {}", target.value),
        )
        .with_attr("transport", transport)
        .with_opt_attr("normalised", body.number.as_deref())
        .with_opt_attr("international", body.international_format.as_deref())
        .with_opt_attr("local", body.local_format.as_deref())
        .with_opt_attr("country_prefix", body.country_prefix.as_deref())
        .with_opt_attr("country", body.country_name.as_deref())
        .with_opt_attr("location", body.location.as_deref())
        .with_opt_attr("carrier", body.carrier.as_deref())
        .with_opt_attr("line_type", body.line_type.as_deref());
        entity.add_evidence(ev);

        // OathNet phone lookup enrichment
        let oathnet_key =
            crate::util::oathnet::resolve_key(ctx.key_opt(crate::util::oathnet::KEY_ENV));
        if !ctx.cancel.is_cancelled()
            && let Ok(Some(phone_data)) = crate::util::oathnet::osint_opt(
                oathnet_key,
                crate::util::oathnet::paths::PHONE_LOOKUP,
                "phone",
                &target.value,
            )
            .await
        {
            let mut phone_ev = Evidence::new(
                "numverify:oathnet",
                format!("OathNet phone intelligence for {}", target.value),
            )
            .with_attr("source", "phone-lookup");
            for (field, attr) in [
                ("carrier", "oathnet_carrier"),
                ("country", "oathnet_country"),
                ("line_type", "oathnet_line_type"),
                ("location", "oathnet_location"),
                ("name", "registered_name"),
                ("caller_name", "caller_name"),
            ] {
                phone_ev =
                    phone_ev.with_opt_attr(attr, crate::util::oathnet::val_str(&phone_data, field));
            }
            entity.add_evidence(phone_ev);
        }

        // OathNet breach search for the phone number
        if !ctx.cancel.is_cancelled()
            && let Ok(breach_items) = crate::util::oathnet::search(
                oathnet_key,
                crate::util::oathnet::paths::BREACH,
                "phone",
                &target.value,
                10,
            )
            .await
            && !breach_items.is_empty()
        {
            let top_dbs = crate::util::oathnet::top_dbnames(&breach_items, 3);
            entity.tag(crate::core::tags::BREACH);
            entity.tag("oathnet-enriched");
            entity.add_evidence(
                Evidence::new(
                    "numverify:oathnet",
                    format!(
                        "Phone in {} breach(es) — {}",
                        breach_items.len(),
                        top_dbs.join(", ")
                    ),
                )
                .with_attr("breach_hits", breach_items.len().to_string())
                .with_attr("top_dbnames", top_dbs.join(", ")),
            );
        }

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
