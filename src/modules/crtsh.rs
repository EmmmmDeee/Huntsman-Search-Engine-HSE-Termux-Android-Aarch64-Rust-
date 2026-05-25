use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;

pub struct Crtsh;

#[derive(Deserialize)]
struct CrtEntry {
    name_value: String,
    issuer_name: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    serial_number: Option<String>,
}

#[async_trait]
impl Module for Crtsh {
    fn name(&self) -> &'static str {
        "crtsh"
    }

    fn description(&self) -> &'static str {
        "Certificate transparency log subdomain discovery"
    }

    fn priority(&self) -> u8 {
        35
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = format!("https://crt.sh/?q=%.{}&output=json", target.value);
        let entries: Vec<CrtEntry> = fetch_json(&ctx.http, "crtsh", &url).await?;

        let mut seen: HashSet<String> = HashSet::with_capacity(entries.len());
        let mut result = ModuleResult::new();
        let parent = target.value.to_lowercase();

        for entry in &entries {
            for name in entry.name_value.split('\n') {
                let name = name.trim().trim_start_matches("*.").to_lowercase();
                if name.is_empty() || !name.contains('.') {
                    continue;
                }
                if name == parent {
                    continue;
                }
                if seen.insert(name.clone()) {
                    let mut e = Entity::new(EntityKind::Domain, &name, 0.88, &ctx.scan_id);
                    e.tag(crate::core::tags::CT_LOG);
                    e.add_evidence(
                        Evidence::new("crtsh", format!("Certificate transparency: {name}"))
                            .with_attr("issuer", entry.issuer_name.as_deref().unwrap_or("-"))
                            .with_attr("not_before", entry.not_before.as_deref().unwrap_or("-"))
                            .with_attr("not_after", entry.not_after.as_deref().unwrap_or("-"))
                            .with_attr(
                                "serial_number",
                                entry.serial_number.as_deref().unwrap_or("-"),
                            )
                            .with_attr("parent_domain", &target.value),
                    );
                    result.push(e);
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_only() {
        let m = Crtsh;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x")));
    }
}
