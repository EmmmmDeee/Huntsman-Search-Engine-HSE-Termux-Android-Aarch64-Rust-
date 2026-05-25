use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct NameToEmail;

const DOMAINS: &[&str] = &[
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "protonmail.com",
    "icloud.com",
];

const PATTERNS: &[fn(&str, &str) -> String] = &[
    |f, l| format!("{f}.{l}"),
    |f, l| format!("{f}{l}"),
    |f, l| format!("{}{l}", &f[..1]),
    |f, l| format!("{f}_{l}"),
    |f, l| format!("{f}-{l}"),
    |f, l| format!("{l}.{f}"),
    |f, l| format!("{l}{f}"),
    |f, l| format!("{}{}", &f[..1], &l[..1.min(l.len())]),
];

#[async_trait]
impl Module for NameToEmail {
    fn name(&self) -> &'static str {
        "name_to_email"
    }

    fn description(&self) -> &'static str {
        "Derive plausible email addresses from a full name for expansion"
    }

    fn priority(&self) -> u8 {
        138
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
        if parts.len() < 2 {
            return Ok(ModuleResult::new());
        }

        let first = parts[0].to_lowercase();
        let last = parts[parts.len() - 1].to_lowercase();

        let mut result = ModuleResult::new();
        let mut seen = std::collections::HashSet::new();

        for pattern_fn in PATTERNS {
            let local = pattern_fn(&first, &last);
            if local.len() < 3 {
                continue;
            }
            for domain in DOMAINS {
                let email = format!("{local}@{domain}");
                if !seen.insert(email.clone()) {
                    continue;
                }
                let mut entity = Entity::new(EntityKind::Email, &email, 0.40, &ctx.scan_id);
                entity.tag("derived");
                entity.tag("name-derived");
                entity.tag("candidate");
                entity.add_evidence(
                    Evidence::new("name_to_email", format!("Derived email from '{name}'"))
                        .with_attr("source_name", name)
                        .with_attr("pattern", &local)
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
    async fn derives_gmail_variants() {
        let m = NameToEmail;
        let t = Target::new(TargetKind::FullName, "Jerome Despal");
        let r = m.process(&t, &ctx()).await.unwrap();
        let values: Vec<&str> = r.entities.iter().map(|e| e.value.as_str()).collect();
        assert!(values.contains(&"jerome.despal@gmail.com"));
        assert!(values.contains(&"jeromedespal@gmail.com"));
        assert!(values.contains(&"jdespal@gmail.com"));
        assert!(values.contains(&"jerome.despal@outlook.com"));
        assert!(r.entities.len() >= 30, "got {}", r.entities.len());
    }

    #[tokio::test]
    async fn skips_single_word() {
        let m = NameToEmail;
        let t = Target::new(TargetKind::FullName, "Cher");
        let r = m.process(&t, &ctx()).await.unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn accepts_fullname_only() {
        assert!(NameToEmail.accepts(&Target::new(TargetKind::FullName, "x y")));
        assert!(!NameToEmail.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
}
