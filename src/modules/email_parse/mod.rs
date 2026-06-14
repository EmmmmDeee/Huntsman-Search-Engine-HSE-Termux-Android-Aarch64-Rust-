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
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "email_parse";

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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Email
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // The email yields its domain + derived usernames (T1589.002 Email
        // Addresses, the category default) and, for a corporate
        // firstname.lastname local-part, infers the person's name — add
        // T1589.003 (Employee Names). Superset of the default; coverage cannot
        // regress.
        &["T1589.002", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] =
            &[EntityKind::Domain, EntityKind::Username, EntityKind::Person];
        KINDS
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
            // Role / generic mailbox local-parts (`dns@`, `abuse@`, `info@`,
            // `noreply@`, …) are not a person's handle — deriving a Username from
            // one promotes a generic token (a real scan turned `dns@cloudflare.com`
            // into a VERIFIED multi-platform username `dns`). Skip username/person
            // derivation for them; the Domain is still extracted above.
            if !local.is_empty() && !crate::util::domains::is_role_localpart(&local) {
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
                candidates.extend(
                    detagged
                        .split(['.', '_', '-'])
                        .filter(|p| p.len() > 2)
                        .map(str::to_string),
                );

                // "Corporate" = not a consumer mailbox. Use the SAME shared
                // freemail list the domain-extraction step above uses, not a
                // second, shorter inline list. The inline list held only 8 of
                // the ~40 freemail/ISP providers `is_freemail` knows, so
                // country/ISP webmail (bigpond, comcast, gmx, yandex.ru, …) was
                // scored as corporate (0.70 confidence) AND had a Person inferred
                // from `firstname.lastname` — fabricating a real name from a
                // throwaway consumer address, and disagreeing with the very
                // freemail check that skipped the Domain two blocks up.
                let email_domain = target.value.split('@').nth(1).unwrap_or("").to_lowercase();
                let is_corporate = !is_freemail(&email_domain);
                let uname_conf = if is_corporate { 0.70 } else { 0.55 };
                result.extend(candidates.into_iter().map(|candidate| {
                    let mut entity =
                        Entity::new(EntityKind::Username, &candidate, uname_conf, &ctx.scan_id);
                    entity.tag("derived");
                    entity.add_evidence(
                        Evidence::new(SRC, format!("Derived from {}", target.value))
                            .with_attr("source_email", &target.value)
                            .with_attr("derivation", "local_part"),
                    );
                    entity
                }));

                // firstname.lastname → Person entity (corporate emails)
                let parts: Vec<&str> = detagged.split(['.', '_']).collect();
                if parts.len() == 2
                    && parts[0].len() >= 2
                    && parts[1].len() >= 2
                    && parts[0].chars().all(|c| c.is_alphabetic())
                    && parts[1].chars().all(|c| c.is_alphabetic())
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

pub(super) fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().chain(c).collect(),
    }
}

/// Re-export of the shared freemail check. Kept for backwards
/// compatibility — new callers should use [`crate::util::domains::is_freemail`].
pub fn is_freemail(domain: &str) -> bool {
    crate::util::domains::is_freemail(domain)
}
