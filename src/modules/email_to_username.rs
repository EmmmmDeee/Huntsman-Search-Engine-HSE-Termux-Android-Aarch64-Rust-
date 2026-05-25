//! Derive plausible Username entities from an Email's local part. No network.

use async_trait::async_trait;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct EmailToUsername;

#[async_trait]
impl Module for EmailToUsername {
    fn name(&self) -> &'static str {
        "email_to_username"
    }

    fn description(&self) -> &'static str {
        "Derive plausible usernames from email local part"
    }

    fn priority(&self) -> u8 {
        95
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(local) = target.value.split('@').next() else {
            return Ok(ModuleResult::new());
        };
        let local = local.to_lowercase();
        if local.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut candidates: HashSet<String> = HashSet::with_capacity(8);

        // Strip +tag suffix → also feeds the splitter below.
        let detagged = if let Some(pos) = local.find('+') {
            let s = local[..pos].to_string();
            candidates.insert(s.clone());
            s
        } else {
            local.clone()
        };
        candidates.insert(local);

        // Strip trailing digits (john42 → john)
        let stripped = detagged.trim_end_matches(|c: char| c.is_ascii_digit());
        if stripped.len() > 2 {
            candidates.insert(stripped.to_string());
        }

        // Collapse separators (john.doe → johndoe)
        let collapsed: String = detagged
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        if collapsed.len() > 2 {
            candidates.insert(collapsed);
        }

        // Split on separators (john.doe → john, doe). Apply to the de-tagged
        // version so "+work" doesn't get treated as part of a username token.
        for part in detagged.split(['.', '_', '-']) {
            if part.len() > 2 {
                candidates.insert(part.to_string());
            }
        }

        let mut result = ModuleResult::new();
        for candidate in candidates {
            let mut entity = Entity::new(EntityKind::Username, &candidate, 0.45, &ctx.scan_id);
            entity.tag("derived");
            entity.add_evidence(
                Evidence::new(
                    "email_to_username",
                    format!("Derived from {}", target.value),
                )
                .with_attr("source_email", &target.value)
                .with_attr("derivation", "local_part"),
            );
            result.push(entity);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
        }
    }

    #[tokio::test]
    async fn derives_multiple_candidates() {
        let m = EmailToUsername;
        let t = Target::new(TargetKind::Email, "john.doe+work@example.com");
        let r = m.process(&t, &ctx()).await.unwrap();
        let values: Vec<&str> = r.entities.iter().map(|e| e.value.as_str()).collect();
        assert!(values.contains(&"john"));
        assert!(values.contains(&"doe"));
    }

    #[test]
    fn is_passive_no_network() {
        assert!(EmailToUsername.is_passive());
    }
}
