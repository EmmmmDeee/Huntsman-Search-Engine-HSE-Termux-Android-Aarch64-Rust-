use async_trait::async_trait;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct NameToUsername;

#[async_trait]
impl Module for NameToUsername {
    fn name(&self) -> &'static str {
        "name_to_username"
    }

    fn description(&self) -> &'static str {
        "Derive plausible usernames from a full name for expansion"
    }

    fn priority(&self) -> u8 {
        139
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let name = target.value.trim();
        if name.is_empty() || !name.contains(' ') {
            return Ok(ModuleResult::new());
        }

        let parts: Vec<&str> = name.split_whitespace().filter(|p| p.len() >= 2).collect();
        if parts.is_empty() {
            return Ok(ModuleResult::new());
        }

        let lower: Vec<String> = parts.iter().map(|p| p.to_lowercase()).collect();
        let mut candidates: HashSet<String> = HashSet::with_capacity(16);

        let first = &lower[0];
        let last = &lower[lower.len() - 1];
        let fi = &first[..1];

        // firstname.lastname, firstname_lastname, firstname-lastname
        candidates.insert(format!("{first}.{last}"));
        candidates.insert(format!("{first}_{last}"));
        candidates.insert(format!("{first}-{last}"));
        candidates.insert(format!("{first}{last}"));

        // firstnamelastname, lastnamefirstname
        candidates.insert(format!("{last}{first}"));

        // flast, f.last, f_last
        candidates.insert(format!("{fi}{last}"));
        candidates.insert(format!("{fi}.{last}"));
        candidates.insert(format!("{fi}_{last}"));

        // firstl
        if !last.is_empty() {
            let li = &last[..1];
            candidates.insert(format!("{first}{li}"));
        }

        // firstname, lastname standalone
        if first.len() >= 3 {
            candidates.insert(first.clone());
        }
        if last.len() >= 3 {
            candidates.insert(last.clone());
        }

        // Handle middle names: first.middle.last
        if lower.len() >= 3 {
            let middle = &lower[1];
            let mi = &middle[..1];
            candidates.insert(format!("{first}.{middle}.{last}"));
            candidates.insert(format!("{fi}{mi}{last}"));
        }

        let mut result = ModuleResult::new();
        for candidate in &candidates {
            if candidate.len() < 3 || candidate.len() > 30 {
                continue;
            }
            let mut entity = Entity::new(EntityKind::Username, candidate, 0.55, &ctx.scan_id);
            entity.tag("derived");
            entity.tag("name-derived");
            entity.add_evidence(
                Evidence::new(
                    "name_to_username",
                    format!("Derived username from '{name}'"),
                )
                .with_attr("source_name", name)
                .with_attr("derivation", "name_patterns"),
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
        let store = std::sync::Arc::new(crate::storage::store::Store::open(":memory:").unwrap());
        ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
            store,
        }
    }

    #[tokio::test]
    async fn derives_standard_patterns() {
        let m = NameToUsername;
        let t = Target::new(TargetKind::FullName, "Jerome Despal");
        let r = m.process(&t, &ctx()).await.unwrap();
        let values: HashSet<&str> = r.entities.iter().map(|e| e.value.as_str()).collect();
        assert!(
            values.contains("jerome.despal"),
            "missing jerome.despal: {values:?}"
        );
        assert!(values.contains("jerome_despal"), "missing jerome_despal");
        assert!(values.contains("jeromedespal"), "missing jeromedespal");
        assert!(values.contains("jdespal"), "missing jdespal");
        assert!(values.contains("j.despal"), "missing j.despal");
        assert!(values.contains("despaljerome"), "missing despaljerome");
        assert!(values.contains("jerome"), "missing jerome");
        assert!(values.contains("despal"), "missing despal");
        assert!(
            r.entities.len() >= 8,
            "expected at least 8 candidates, got {}",
            r.entities.len()
        );
    }

    #[tokio::test]
    async fn handles_three_part_name() {
        let m = NameToUsername;
        let t = Target::new(TargetKind::FullName, "John Paul Smith");
        let r = m.process(&t, &ctx()).await.unwrap();
        let values: HashSet<&str> = r.entities.iter().map(|e| e.value.as_str()).collect();
        assert!(values.contains("john.paul.smith"));
        assert!(values.contains("jpsmith"));
    }

    #[tokio::test]
    async fn skips_single_word() {
        let m = NameToUsername;
        let t = Target::new(TargetKind::FullName, "Madonna");
        let r = m.process(&t, &ctx()).await.unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn is_passive_no_network() {
        assert!(NameToUsername.is_passive());
    }

    #[test]
    fn accepts_fullname_only() {
        let m = NameToUsername;
        assert!(m.accepts(&Target::new(TargetKind::FullName, "x y")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
    }
}
