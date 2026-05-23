//! crt.sh certificate transparency. Free, no key required.
//!
//! Returns subdomain entities discovered via CT log entries for the parent
//! domain. Each entry includes the issuer name and not-before timestamp.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct Crtsh;

#[derive(Deserialize)]
struct CrtEntry {
    name_value: String,
    issuer_name: Option<String>,
    not_before: Option<String>,
}

#[async_trait]
impl Module for Crtsh {
    fn name(&self) -> &'static str {
        "crtsh"
    }

    fn priority(&self) -> u8 {
        35
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = format!("https://crt.sh/?q=%.{}&output=json", target.value);

        let resp = ctx
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::module("crtsh", e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::module("crtsh", format!("HTTP {}", resp.status())));
        }

        let entries: Vec<CrtEntry> = resp
            .json()
            .await
            .map_err(|e| Error::module("crtsh", e.to_string()))?;

        let mut seen: HashSet<String> = HashSet::new();
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
                    e.tag("ct-log");
                    e.add_evidence(
                        Evidence::new("crtsh", format!("Certificate transparency: {name}"))
                            .with_attr("issuer", entry.issuer_name.as_deref().unwrap_or("-"))
                            .with_attr("not_before", entry.not_before.as_deref().unwrap_or("-"))
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

    #[test]
    fn is_free() {
        assert_eq!(Crtsh.cost(), ModuleCost::Free);
    }
}
