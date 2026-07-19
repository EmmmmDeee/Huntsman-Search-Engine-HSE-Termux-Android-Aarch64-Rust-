//! HLR/CNAM phone lookup. Key-gated; requires HUNTSMAN_HLR_KEY (hlrlookup.com)
//! and optionally HUNTSMAN_OPENCNAM_KEY (opencnam.com).
//!
//! Stage 1: hlrlookup.com — live HLR status, MCC/MNC, ported/roaming flags.
//! Stage 2: OpenCNAM — CNAM subscriber name registered on the PSTN.
//! Pivot: CNAM name → Person entity (confidence 0.55).

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

const SRC: &str = "hlr_cnam";
const HLR_KEY_ENV: &str = "HUNTSMAN_HLR_KEY";
const CNAM_KEY_ENV: &str = "HUNTSMAN_OPENCNAM_KEY";

pub struct HlrCnam;

#[derive(Deserialize, Default)]
#[serde(default)]
struct HlrResp {
    status: Option<String>,
    mcc: Option<String>,
    mnc: Option<String>,
    original_network_name: Option<String>,
    current_network_name: Option<String>,
    ported: Option<bool>,
    roaming: Option<bool>,
    roaming_country_code: Option<String>,
    msisdn: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CnamResp {
    name: Option<String>,
    number: Option<String>,
}

#[async_trait]
impl Module for HlrCnam {
    fn name(&self) -> &'static str {
        "hlr_cnam"
    }

    fn description(&self) -> &'static str {
        "HLR live-status probe — resolves a phone's ported/roaming/MCC-MNC state and cross-links CNAM subscriber name"
    }

    fn priority(&self) -> u8 {
        138
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

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Phone,
            EntityKind::Organisation,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let hlr_key = match ctx.key_opt(HLR_KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        let number = target.value.trim();
        if number.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://api.hlrlookups.com/api/lookup?msisdn={}&api_key={}",
            crate::util::http::urlencode(number),
            crate::util::http::urlencode(hlr_key),
        );

        let resp = ctx.http.get(&url).send_tagged(SRC).await?;
        // 401/403/429 → note_keyed_error + Err; 404 → clean miss; other non-2xx → Err.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, hlr_key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let hlr: HlrResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut result = ModuleResult::new();
        result
            .entities
            .extend(build_hlr_entities(&hlr, number, &ctx.scan_id));

        // Stage 2: OpenCNAM subscriber name.
        if let Some(cnam_key) = ctx.key_opt(CNAM_KEY_ENV) {
            let cnam_url = format!(
                "https://api.opencnam.com/v2/phone/{}?account_sid=huntsman&auth_token={}",
                crate::util::http::urlencode(number),
                crate::util::http::urlencode(cnam_key),
            );
            if let Ok(cr) = ctx.http.get(&cnam_url).send_tagged(SRC).await
                && cr.status().is_success()
                && let Ok(cnam) = crate::util::http::json_decode::<CnamResp>(SRC, cr).await
                && let Some(person) = build_cnam_person(&cnam, number, &ctx.scan_id)
            {
                result.push(person);
            }
        }

        Ok(result)
    }
}

/// Map an HLR response to the verified phone entity (with full network/status
/// evidence) and the current-network carrier Organisation pivot. **Pure** (no
/// network/IO). The provider's canonical `msisdn` is carried as evidence so the
/// authoritative international form the HLR returns is never dropped, even when
/// it differs from the queried number's local formatting.
fn build_hlr_entities(hlr: &HlrResp, number: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();

    let mut phone = Entity::new(EntityKind::Phone, number, 0.85, scan_id);
    phone.tag("hlr-verified");
    if hlr.ported == Some(true) {
        phone.tag("ported");
    }
    if hlr.roaming == Some(true) {
        phone.tag("roaming");
    }
    let mut ev = Evidence::new(SRC, format!("HLR lookup for {number}"));
    if let Some(s) = &hlr.status {
        ev = ev.with_attr("hlr_status", s);
    }
    if let Some(mcc) = &hlr.mcc {
        ev = ev.with_attr("mcc", mcc);
    }
    if let Some(mnc) = &hlr.mnc {
        ev = ev.with_attr("mnc", mnc);
    }
    if let Some(net) = &hlr.current_network_name {
        ev = ev.with_attr("network", net);
        // Classify the SIM's anonymity tier from the carrier name: a VoIP /
        // virtual number or an anonymity-friendly prepaid MVNO is a weak
        // identity anchor (a likely burner), which AU-068 surfaces and the
        // linker weighs. Deterministic, offline; unknown/major carriers are
        // left unclassified.
        if let Some(tier) = crate::util::sim_anonymity::classify_carrier(net) {
            phone.tag(tier.tag());
            ev = ev.with_attr("sim_anonymity", tier.label());
        }
    }
    if let Some(orig) = &hlr.original_network_name {
        ev = ev.with_attr("ported_from_carrier", orig);
    }
    if let Some(rc) = &hlr.roaming_country_code {
        ev = ev.with_attr("roaming_country", rc);
    }
    if let Some(m) = hlr
        .msisdn
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
    {
        ev = ev.with_attr("msisdn", m);
    }
    phone.add_evidence(ev);
    out.push(phone);

    // Current network/carrier → Organisation pivot (consistent with ip2location/ipquery).
    if let Some(net) = hlr
        .current_network_name
        .as_deref()
        .map(str::trim)
        .filter(|n| n.len() >= 2)
    {
        let mut oe = Entity::new(EntityKind::Organisation, net, 0.62, scan_id);
        oe.tag("hlr-cnam");
        oe.tag("carrier");
        oe.add_evidence(
            Evidence::new(SRC, format!("Carrier/network for {number} per HLR"))
                .with_attr("phone", number),
        );
        out.push(oe);
    }

    out
}

/// Map a CNAM response to a PSTN-subscriber `Person`. **Pure** (no network/IO).
/// Returns `None` when no usable subscriber name is present. The number CNAM
/// echoed back (`number`) is preserved as evidence so the subscriber name stays
/// tied to the exact PSTN number the lookup resolved.
fn build_cnam_person(cnam: &CnamResp, number: &str, scan_id: &str) -> Option<Entity> {
    let name = cnam.name.as_deref().filter(|n| n.len() >= 2)?;
    let mut person = Entity::new(EntityKind::Person, name, 0.55, scan_id);
    person.tag("cnam");
    person.tag("pstn-subscriber");
    let mut ev = Evidence::new(SRC, format!("CNAM subscriber name for {number}"))
        .with_attr("cnam_name", name)
        .with_attr("source", "opencnam");
    if let Some(n) = cnam
        .number
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        ev = ev.with_attr("cnam_number", n);
    }
    person.add_evidence(ev);
    Some(person)
}
