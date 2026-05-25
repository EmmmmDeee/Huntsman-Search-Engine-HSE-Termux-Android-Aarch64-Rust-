//! AlienVault OTX — public threat-intel pulse lookup.
//!
//! Free, no key required. Endpoint:
//!   `https://otx.alienvault.com/api/v1/indicators/{IPv4|domain}/{value}/general`
//!
//! Returns the count of OTX "pulses" (community-reported threat indicators)
//! the target appears in. Used by `AU-010` (infrastructure consensus) when
//! threat intel adds another source to an already-discovered domain/IP.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::Evidence,
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

pub struct AlienVaultOtx;

#[derive(Deserialize)]
struct OtxResp {
    pulse_info: Option<PulseInfo>,
}

#[derive(Deserialize)]
struct PulseInfo {
    count: Option<u64>,
    #[serde(default)]
    pulses: Vec<Pulse>,
}

#[derive(Deserialize)]
struct Pulse {
    name: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    adversary: Option<String>,
    tlp: Option<String>,
    created: Option<String>,
}

#[async_trait]
impl Module for AlienVaultOtx {
    fn name(&self) -> &'static str {
        "alienvault_otx"
    }

    fn priority(&self) -> u8 {
        78
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let itype = match target.kind {
            TargetKind::IpAddress => "IPv4",
            TargetKind::Domain => "domain",
            _ => return Ok(ModuleResult::new()),
        };

        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/{}/{}/general",
            itype,
            urlencode(&target.value)
        );

        // 404 = target not in OTX (no findings); 429 / 5xx surface as
        // module_error via fetch_json_or_404's standard error path.
        let Some(data): Option<OtxResp> =
            fetch_json_or_404(&ctx.http, "alienvault_otx", &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        let pulse_info = match data.pulse_info {
            Some(p) => p,
            None => return Ok(ModuleResult::new()),
        };
        let pulse_count = pulse_info.count.unwrap_or(0);
        if pulse_count == 0 {
            return Ok(ModuleResult::new());
        }

        let mut entity = target.to_entity(0.72, &ctx.scan_id);
        entity.tag("threat-intel");

        // Surface up to 5 pulse names + tag aggregate so the evidence is
        // actually actionable rather than just a count. Tags from across
        // all pulses are deduped and joined; the top pulse's adversary
        // (when present) is highlighted.
        let pulse_names: Vec<&str> = pulse_info
            .pulses
            .iter()
            .filter_map(|p| p.name.as_deref())
            .take(5)
            .collect();
        let tag_count_estimate: usize = pulse_info.pulses.iter().map(|p| p.tags.len()).sum();
        let mut all_tags: Vec<&str> = Vec::with_capacity(tag_count_estimate);
        all_tags.extend(
            pulse_info
                .pulses
                .iter()
                .flat_map(|p| p.tags.iter().map(String::as_str)),
        );
        all_tags.sort_unstable();
        all_tags.dedup();
        // Hard cap to keep the evidence row compact for the SPA.
        all_tags.truncate(20);
        let adversary = pulse_info
            .pulses
            .iter()
            .find_map(|p| p.adversary.as_deref().filter(|s| !s.is_empty()));

        // The most recent pulse's TLP tier — strong signal of how
        // sensitive the underlying intelligence is.
        let latest_tlp = pulse_info
            .pulses
            .iter()
            .find_map(|p| p.tlp.as_deref().filter(|s| !s.is_empty()));
        let earliest_created = pulse_info
            .pulses
            .iter()
            .filter_map(|p| p.created.as_deref())
            .min();

        // Tag the entity with high-level threat hints so the SPA can
        // colour-code rows. These are bucketed from the raw pulse tags.
        let combined_tags = all_tags.join(",").to_lowercase();
        for hint in ["malware", "ransomware", "apt", "phishing", "botnet", "c2"] {
            if combined_tags.contains(hint) {
                entity.tag(format!("ti:{hint}"));
            }
        }

        let mut ev = Evidence::new(
            "alienvault_otx",
            format!("OTX: {pulse_count} threat pulse(s)"),
        )
        .with_attr("pulse_count", pulse_count.to_string())
        .with_attr("indicator_type", itype);
        if !pulse_names.is_empty() {
            ev = ev.with_attr("recent_pulses", pulse_names.join(" | "));
        }
        if !all_tags.is_empty() {
            ev = ev.with_attr("pulse_tags", all_tags.join(", "));
        }
        if let Some(a) = adversary {
            ev = ev.with_attr("adversary", a);
        }
        if let Some(t) = latest_tlp {
            ev = ev.with_attr("tlp", t);
        }
        if let Some(c) = earliest_created {
            ev = ev.with_attr("first_pulse_created", c);
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
    fn accepts_ip_and_domain() {
        let m = AlienVaultOtx;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
}
