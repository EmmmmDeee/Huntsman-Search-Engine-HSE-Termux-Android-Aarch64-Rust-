//! Extract the domain and derive plausible usernames from an Email target.
//! No network — pure string transformations.
//!
//! This module merges the former `email_to_domain` and `email_to_username`
//! modules into a single enrichment pass. It is the critical bridge between
//! identity modules and infrastructure modules: without the Domain entity it
//! emits, an email scan with `--depth 1+` never triggers DNS, WHOIS, crt.sh,
//! web crawler, webserver banner, or any of the 15+ domain-accepting modules.
//!
//! With this module, `hse scan --kind email --value user@acme.com --depth 1`
//! produces:
//!   Round 0: Email entities (breach modules) + Username entities
//!            (username derivation) + **Domain entity `acme.com`** (domain
//!            extraction)
//!   Round 1: Domain `acme.com` triggers dns_resolver, crtsh, whois,
//!            web_crawler, webserver_banner, wayback, dns_brute,
//!            securitytrails, urlhaus, leakix, hudsonrock (domain mode) ...
//!
//! Priority is set high (96) so the Domain entity is available early in
//! the seed round for the engine's expansion candidate selection.

use async_trait::async_trait;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "email_parse";

pub struct EmailParse;

#[async_trait]
impl Module for EmailParse {
    fn name(&self) -> &'static str {
        "email_parse"
    }

    fn description(&self) -> &'static str {
        "Extract domain and derive usernames from email local part"
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
        let mut result = ModuleResult::new();

        // ── Domain extraction ──────────────────────────────────────────
        if let Some((_, d)) = target.value.rsplit_once('@')
            && !d.is_empty()
            && d.contains('.')
        {
            let domain = d.to_lowercase();
            if !is_freemail(&domain) {
                let mut entity = Entity::new(EntityKind::Domain, &domain, 0.80, &ctx.scan_id);
                entity.tag("derived");
                entity.tag("email-domain");
                entity.add_evidence(
                    Evidence::new(SRC, format!("Domain extracted from {}", target.value))
                        .with_attr("source_email", &target.value),
                );
                result.push(entity);
            }
        }

        // ── Username derivation ────────────────────────────────────────
        if let Some(local) = target.value.split('@').next() {
            let local = local.to_lowercase();
            if !local.is_empty() {
                let mut candidates: HashSet<String> = HashSet::with_capacity(8);

                // Strip +tag suffix; also feeds the splitter below.
                let detagged = if let Some(pos) = local.find('+') {
                    let s = local[..pos].to_string();
                    candidates.insert(s.clone());
                    s
                } else {
                    local.clone()
                };
                candidates.insert(local);

                // Strip trailing digits (john42 -> john)
                let stripped = detagged.trim_end_matches(|c: char| c.is_ascii_digit());
                if stripped.len() > 2 {
                    candidates.insert(stripped.to_string());
                }

                // Collapse separators (john.doe -> johndoe)
                let collapsed: String = detagged
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .collect();
                if collapsed.len() > 2 {
                    candidates.insert(collapsed);
                }

                // Split on separators (john.doe -> john, doe). Apply to the
                // de-tagged version so "+work" doesn't become a username token.
                for part in detagged.split(['.', '_', '-']) {
                    if part.len() > 2 {
                        candidates.insert(part.to_string());
                    }
                }

                let email_domain = target.value.split('@').nth(1).unwrap_or("").to_lowercase();
                let is_corporate = ![
                    "gmail.com",
                    "hotmail.com",
                    "yahoo.com",
                    "outlook.com",
                    "live.com",
                    "icloud.com",
                    "protonmail.com",
                    "aol.com",
                ]
                .iter()
                .any(|d| email_domain == *d);
                let uname_conf = if is_corporate { 0.70 } else { 0.55 };
                for candidate in candidates {
                    let mut entity =
                        Entity::new(EntityKind::Username, &candidate, uname_conf, &ctx.scan_id);
                    entity.tag("derived");
                    entity.add_evidence(
                        Evidence::new(SRC, format!("Derived from {}", target.value))
                            .with_attr("source_email", &target.value)
                            .with_attr("derivation", "local_part"),
                    );
                    result.push(entity);
                }

                // firstname.lastname → Person entity (corporate emails)
                let parts: Vec<&str> = detagged.split(['.', '_']).collect();
                if parts.len() == 2
                    && parts[0].len() >= 2
                    && parts[1].len() >= 2
                    && parts[0].chars().all(|c| c.is_ascii_alphabetic())
                    && parts[1].chars().all(|c| c.is_ascii_alphabetic())
                    && is_corporate
                {
                    let name = format!("{} {}", capitalise(parts[0]), capitalise(parts[1]));
                    let mut pe = Entity::new(EntityKind::Person, &name, 0.55, &ctx.scan_id);
                    pe.tag("derived");
                    pe.tag("email-inferred");
                    pe.add_evidence(
                        Evidence::new(SRC, format!("Name inferred from {}", target.value))
                            .with_attr("source_email", &target.value)
                            .with_attr("pattern", "firstname.lastname"),
                    );
                    result.push(pe);
                }
            }
        }

        Ok(result)
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().chain(c).collect(),
    }
}

pub fn is_freemail(domain: &str) -> bool {
    const FREE: &[&str] = &[
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com",
        "icloud.com",
        "mail.com",
        "protonmail.com",
        "proton.me",
        "zoho.com",
        "yandex.com",
        "gmx.com",
        "gmx.net",
        "live.com",
        "msn.com",
        "me.com",
        "mac.com",
        "fastmail.com",
        "tutanota.com",
        "tuta.io",
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
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        }
    }

    // ── Tests from email_to_domain ─────────────────────────────────────

    #[tokio::test]
    async fn extracts_corporate_domain() {
        let t = Target::new(TargetKind::Email, "ceo@acme.com");
        let r = EmailParse.process(&t, &ctx()).await.unwrap();
        let domains: Vec<&Entity> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .collect();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].value, "acme.com");
        assert!(domains[0].has_tag("derived"));
        assert!(domains[0].has_tag("email-domain"));
    }

    #[tokio::test]
    async fn skips_freemail_providers() {
        for addr in ["user@gmail.com", "user@yahoo.com", "user@protonmail.com"] {
            let t = Target::new(TargetKind::Email, addr);
            let r = EmailParse.process(&t, &ctx()).await.unwrap();
            let domains: Vec<&Entity> = r
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Domain)
                .collect();
            assert!(domains.is_empty(), "should skip freemail domain: {addr}");
        }
    }

    #[tokio::test]
    async fn skips_domain_for_malformed_email() {
        let t = Target::new(TargetKind::Email, "noatsign");
        let r = EmailParse.process(&t, &ctx()).await.unwrap();
        let domains: Vec<&Entity> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .collect();
        assert!(domains.is_empty());
    }

    // ── Tests from email_to_username ───────────────────────────────────

    #[tokio::test]
    async fn derives_multiple_username_candidates() {
        let t = Target::new(TargetKind::Email, "john.doe+work@example.com");
        let r = EmailParse.process(&t, &ctx()).await.unwrap();
        let usernames: Vec<&str> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Username)
            .map(|e| e.value.as_str())
            .collect();
        assert!(usernames.contains(&"john"));
        assert!(usernames.contains(&"doe"));
    }

    // ── Shared / merged tests ──────────────────────────────────────────

    #[test]
    fn is_passive() {
        assert!(EmailParse.is_passive());
    }

    #[test]
    fn accepts_email_only() {
        assert!(EmailParse.accepts(&Target::new(TargetKind::Email, "x")));
        assert!(!EmailParse.accepts(&Target::new(TargetKind::Domain, "x")));
    }

    #[tokio::test]
    async fn emits_both_domain_and_usernames() {
        let t = Target::new(TargetKind::Email, "admin@corp.io");
        let r = EmailParse.process(&t, &ctx()).await.unwrap();
        let has_domain = r.entities.iter().any(|e| e.kind == EntityKind::Domain);
        let has_username = r.entities.iter().any(|e| e.kind == EntityKind::Username);
        assert!(has_domain, "should emit a Domain entity for corp.io");
        assert!(
            has_username,
            "should emit Username entities from local part"
        );
    }

    #[tokio::test]
    async fn freemail_still_derives_usernames() {
        let t = Target::new(TargetKind::Email, "john.doe@gmail.com");
        let r = EmailParse.process(&t, &ctx()).await.unwrap();
        let domains: Vec<&Entity> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .collect();
        let usernames: Vec<&str> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Username)
            .map(|e| e.value.as_str())
            .collect();
        assert!(domains.is_empty(), "freemail domain should be skipped");
        assert!(!usernames.is_empty(), "usernames should still be derived");
        assert!(usernames.contains(&"john"));
        assert!(usernames.contains(&"doe"));
    }

    #[tokio::test]
    async fn evidence_source_is_email_parse() {
        let t = Target::new(TargetKind::Email, "alice@widgets.co");
        let r = EmailParse.process(&t, &ctx()).await.unwrap();
        for entity in &r.entities {
            for ev in &entity.evidence {
                assert_eq!(
                    ev.source, "email_parse",
                    "all evidence should cite email_parse, got: {}",
                    ev.source
                );
            }
        }
    }
}
