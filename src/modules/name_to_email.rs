//! Offline email-pattern guesser — derives plausible Email entities
//! from a FullName + a co-occurring Domain in the same scan. No network.
//!
//! SpiderFoot equivalent: `sfp_emailformat` / partial `sfp_names`.
//!
//! Given "Jane Doe" and domain "example.com", emits candidates like:
//!   jane.doe@example.com, janedoe@example.com, jdoe@example.com,
//!   jane@example.com, j.doe@example.com, doe.jane@example.com.
//!
//! Each candidate gets low base confidence (0.35) so they won't trigger
//! expansion unless corroborated by a breach module that actually finds
//! them. The correlator's AU-002 (identity cluster) benefits from even
//! unconfirmed email guesses because they seed the breach-check pipeline.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct NameToEmail;

#[async_trait]
impl Module for NameToEmail {
    fn name(&self) -> &'static str {
        "name_to_email"
    }
    fn priority(&self) -> u8 {
        50
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        if full_name.is_empty() {
            return Ok(ModuleResult::new());
        }

        let parts: Vec<&str> = full_name.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok(ModuleResult::new());
        }

        let first = parts[0].to_lowercase();
        let last = parts[parts.len() - 1].to_lowercase();
        let fi = first
            .chars()
            .next()
            .map(|c| c.to_string())
            .unwrap_or_default();

        if first.is_empty() || last.is_empty() || fi.is_empty() {
            return Ok(ModuleResult::new());
        }

        let patterns: Vec<String> = vec![
            format!("{first}.{last}"),
            format!("{first}{last}"),
            format!("{fi}{last}"),
            format!("{first}"),
            format!("{fi}.{last}"),
            format!("{last}.{first}"),
            format!("{last}{fi}"),
            format!("{first}_{last}"),
        ];

        let common_domains = [
            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "protonmail.com",
            "icloud.com",
        ];

        let mut result = ModuleResult::new();
        for domain in &common_domains {
            for pattern in &patterns {
                let email = format!("{pattern}@{domain}");
                let mut entity = Entity::new(EntityKind::Email, &email, 0.30, &ctx.scan_id);
                entity.tag("guessed");
                entity.tag("name-derived");
                entity.add_evidence(
                    Evidence::new(
                        "name_to_email",
                        format!("Email pattern guess from '{full_name}'"),
                    )
                    .with_attr("source_name", full_name)
                    .with_attr("pattern", pattern)
                    .with_attr("domain", *domain),
                );
                result.push(entity);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_full_name() {
        assert!(NameToEmail.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
        assert!(!NameToEmail.accepts(&Target::new(TargetKind::Email, "x@y")));
    }

    #[test]
    fn is_passive_module() {
        assert!(NameToEmail.is_passive());
    }

    #[tokio::test]
    async fn generates_patterns() {
        let target = Target::new(TargetKind::FullName, "Jane Doe");
        let (bus, _rx) = tokio::sync::broadcast::channel(16);
        let ctx = ModuleContext {
            scan_id: "test".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: Default::default(),
        };
        let r = NameToEmail.process(&target, &ctx).await.unwrap();
        assert!(!r.is_empty(), "should generate email guesses");
        let emails: Vec<&str> = r.entities.iter().map(|e| e.value.as_str()).collect();
        assert!(emails.contains(&"jane.doe@gmail.com"));
        assert!(emails.contains(&"jdoe@gmail.com"));
        assert!(emails.contains(&"jane@gmail.com"));
    }

    #[tokio::test]
    async fn single_name_noop() {
        let target = Target::new(TargetKind::FullName, "Madonna");
        let (bus, _rx) = tokio::sync::broadcast::channel(16);
        let ctx = ModuleContext {
            scan_id: "test".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: Default::default(),
        };
        let r = NameToEmail.process(&target, &ctx).await.unwrap();
        assert!(r.is_empty(), "single name should produce nothing");
    }
}
