//! Extract the domain part of an Email target and emit it as a Domain entity.
//! No network — pure string transformation.
//!
//! This is the critical enrichment bridge between identity modules and
//! infrastructure modules. Without it, an email scan with `--depth 1+`
//! never triggers DNS, WHOIS, crt.sh, web crawler, webserver banner, or
//! any of the 15+ domain-accepting modules — the expansion engine can
//! only feed entities whose kind maps to a TargetKind, and no other
//! email module emits a Domain entity.
//!
//! With this module, `hse scan --kind email --value user@acme.com --depth 1`
//! produces:
//!   Round 0: Email entities (breach modules) + Username entities
//!            (email_to_username) + **Domain entity `acme.com`** (this module)
//!   Round 1: Domain `acme.com` triggers dns_resolver, crtsh, whois,
//!            web_crawler, webserver_banner, wayback, dns_brute,
//!            securitytrails, urlhaus, leakix, hudsonrock (domain mode) ...
//!
//! Priority is set high (96) so the Domain entity is available early in
//! the seed round for the engine's expansion candidate selection.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct EmailToDomain;

#[async_trait]
impl Module for EmailToDomain {
    fn name(&self) -> &'static str {
        "email_to_domain"
    }

    fn priority(&self) -> u8 {
        96
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = match target.value.rsplit_once('@') {
            Some((_, d)) if !d.is_empty() && d.contains('.') => d.to_lowercase(),
            _ => return Ok(ModuleResult::new()),
        };

        if is_freemail(&domain) {
            return Ok(ModuleResult::new());
        }

        let mut entity = Entity::new(EntityKind::Domain, &domain, 0.80, &ctx.scan_id);
        entity.tag("derived");
        entity.tag("email-domain");
        entity.add_evidence(
            Evidence::new("email_to_domain", format!("Domain extracted from {}", target.value))
                .with_attr("source_email", &target.value),
        );

        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

fn is_freemail(domain: &str) -> bool {
    const FREE: &[&str] = &[
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
        "icloud.com", "mail.com", "protonmail.com", "proton.me",
        "zoho.com", "yandex.com", "gmx.com", "gmx.net", "live.com",
        "msn.com", "me.com", "mac.com", "fastmail.com",
        "tutanota.com", "tuta.io",
    ];
    FREE.contains(&domain)
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
    async fn extracts_corporate_domain() {
        let t = Target::new(TargetKind::Email, "ceo@acme.com");
        let r = EmailToDomain.process(&t, &ctx()).await.unwrap();
        assert_eq!(r.entities.len(), 1);
        assert_eq!(r.entities[0].kind, EntityKind::Domain);
        assert_eq!(r.entities[0].value, "acme.com");
        assert!(r.entities[0].has_tag("derived"));
        assert!(r.entities[0].has_tag("email-domain"));
    }

    #[tokio::test]
    async fn skips_freemail_providers() {
        for addr in ["user@gmail.com", "user@yahoo.com", "user@protonmail.com"] {
            let t = Target::new(TargetKind::Email, addr);
            let r = EmailToDomain.process(&t, &ctx()).await.unwrap();
            assert!(r.entities.is_empty(), "should skip freemail: {addr}");
        }
    }

    #[tokio::test]
    async fn skips_malformed_email() {
        let t = Target::new(TargetKind::Email, "noatsign");
        let r = EmailToDomain.process(&t, &ctx()).await.unwrap();
        assert!(r.entities.is_empty());
    }

    #[test]
    fn is_passive() {
        assert!(EmailToDomain.is_passive());
    }

    #[test]
    fn accepts_email_only() {
        assert!(EmailToDomain.accepts(&Target::new(TargetKind::Email, "x")));
        assert!(!EmailToDomain.accepts(&Target::new(TargetKind::Domain, "x")));
    }
}
