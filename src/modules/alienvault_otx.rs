use std::collections::HashMap;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

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
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    references: Option<Vec<String>>,
    #[serde(default)]
    author_name: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[async_trait]
impl Module for AlienVaultOtx {
    fn name(&self) -> &'static str {
        "alienvault_otx"
    }

    fn description(&self) -> &'static str {
        "OTX pulse threat intelligence for IPs and domains"
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
        all_tags.truncate(20);
        let adversary = pulse_info
            .pulses
            .iter()
            .find_map(|p| p.adversary.as_deref().filter(|s| !s.is_empty()));

        let latest_tlp = pulse_info
            .pulses
            .iter()
            .find_map(|p| p.tlp.as_deref().filter(|s| !s.is_empty()));
        let earliest_created = pulse_info
            .pulses
            .iter()
            .filter_map(|p| p.created.as_deref())
            .min();

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
        // Collect descriptions and references from pulses
        let descriptions: Vec<&str> = pulse_info
            .pulses
            .iter()
            .filter_map(|p| p.description.as_deref().filter(|d| !d.is_empty()))
            .take(3)
            .collect();
        let references: Vec<&str> = pulse_info
            .pulses
            .iter()
            .filter_map(|p| p.references.as_ref())
            .flat_map(|refs| refs.iter().map(String::as_str))
            .take(10)
            .collect();
        let authors: Vec<&str> = pulse_info
            .pulses
            .iter()
            .filter_map(|p| p.author_name.as_deref().filter(|a| !a.is_empty()))
            .collect();
        let mut unique_authors = authors.clone();
        unique_authors.sort_unstable();
        unique_authors.dedup();
        unique_authors.truncate(5);

        ev = ev
            .with_opt_attr("adversary", adversary)
            .with_opt_attr("tlp", latest_tlp)
            .with_opt_attr("first_pulse_created", earliest_created);
        if !descriptions.is_empty() {
            ev = ev.with_attr("pulse_descriptions", descriptions.join(" | "));
        }
        if !references.is_empty() {
            ev = ev.with_attr("pulse_references", references.join(", "));
        }
        if !unique_authors.is_empty() {
            ev = ev.with_attr("pulse_authors", unique_authors.join(", "));
        }
        // Store overflow fields from each pulse
        for pulse in &pulse_info.pulses {
            for (k, v) in &pulse.extra {
                let val_str = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                ev = ev.with_attr(format!("otx_{k}"), val_str);
            }
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
