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
    confidence,
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
        "Email dissection — splits out the host domain and derives candidate usernames from the local part for onward pivoting"
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
            // Only a *corporate/self-owned* mail domain is a real finding. Beyond
            // the freemail list, suppress every mega/social/shared-infrastructure
            // host (ISP webmail like `rr.com`, regional providers like `web.de`,
            // data brokers like `peekyou.com`) — `is_noncentral_domain` is the
            // authoritative set. These leaked as standalone Domain entities and
            // drove the CRITICAL infrastructure-pollution an on-device scan flagged.
            if !is_freemail(&domain) && !crate::core::scan::is_noncentral_domain(&domain) {
                let mut entity = Entity::new(
                    EntityKind::Domain,
                    &domain,
                    confidence::HIGH_PLUSPLUS,
                    &ctx.scan_id,
                );
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

                // ── Initial-blend and separator-swap patterns ─────────────────
                // When the local part is a two-token firstname.lastname (or
                // firstname_lastname / firstname-lastname) shape, derive the
                // initial-blend handles that dominate real-world platform
                // username conventions but are absent from a plain local-part
                // extraction. These are the highest-value free derivations:
                // `flast` (hbamford) and `first_last` (haigen_bamford) together
                // cover the majority of corporate email→username mappings.
                // Restricted to exactly 2 all-alphabetic tokens of length ≥ 2
                // so single-token locals and numeric-suffixed locals don't fire.
                let name_parts: Vec<&str> = detagged
                    .split(['.', '_', '-'])
                    .filter(|p| p.len() >= 2 && p.chars().all(char::is_alphabetic))
                    .collect();
                if name_parts.len() == 2 {
                    let f = name_parts[0];
                    let l = name_parts[1];
                    let fi = f.chars().next().unwrap_or('x');
                    let li = l.chars().next().unwrap_or('x');
                    // flast  — initial + last:  e.g. hbamford
                    candidates.insert(format!("{fi}{l}"));
                    // firstl — first + last-initial:  e.g. haigenb
                    candidates.insert(format!("{f}{li}"));
                    // i.last — initial dot last:  e.g. h.bamford
                    candidates.insert(format!("{fi}.{l}"));
                    // first_last — underscore form:  e.g. haigen_bamford
                    candidates.insert(format!("{f}_{l}"));
                    // first-last — hyphen form:  e.g. haigen-bamford
                    candidates.insert(format!("{f}-{l}"));
                }

                // "Corporate" = not a consumer mailbox. Use the SAME shared
                // freemail list the domain-extraction step above uses, not a
                // second, shorter inline list. The inline list held only 8 of
                // the ~40 freemail/ISP providers `is_freemail` knows, so
                // country/ISP webmail (bigpond, comcast, gmx, yandex.ru, …) was
                // scored as corporate (confidence::HIGH_PLUS confidence) AND had a Person inferred
                // from `firstname.lastname` — fabricating a real name from a
                // throwaway consumer address, and disagreeing with the very
                // freemail check that skipped the Domain two blocks up.
                let email_domain = target.value.split('@').nth(1).unwrap_or("").to_lowercase();
                let is_corporate = !is_freemail(&email_domain);
                let uname_conf = if is_corporate {
                    confidence::HIGH_PLUS
                } else {
                    confidence::MEDIUM_HIGH
                };
                // Sorted before emission so the HashSet's randomised iteration
                // order never leaks into entity order (the same determinism-leak
                // class fixed for `reddit_user`/`hacker_news`/`web_crawler`).
                let mut candidates: Vec<String> = candidates.into_iter().collect();
                candidates.sort_unstable();
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

                // firstname.lastname → Person entity (corporate at confidence::MEDIUM_HIGH, freemail at confidence::LOW_MEDIUM).
                // Freemail usernames like ryne.manka@gmail.com still produce a Person
                // candidate — the lower confidence and `freemail-inferred` tag signal
                // that the inference is weaker and requires corroboration.
                let parts: Vec<&str> = detagged.split(['.', '_']).collect();
                if parts.len() == 2
                    && parts[0].len() >= 2
                    && parts[1].len() >= 2
                    && parts[0].chars().all(char::is_alphabetic)
                    && parts[1].chars().all(char::is_alphabetic)
                {
                    let person_conf = if is_corporate {
                        confidence::MEDIUM_HIGH
                    } else {
                        confidence::LOW_MEDIUM
                    };
                    let name = format!("{} {}", capitalise(parts[0]), capitalise(parts[1]));
                    let mut pe = Entity::new(EntityKind::Person, &name, person_conf, &ctx.scan_id);
                    pe.tag("derived");
                    pe.tag("email-inferred");
                    if !is_corporate {
                        pe.tag("freemail-inferred");
                    }
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

/// Upper-case the first character of `s`, leaving the rest untouched — turns a
/// lowercased email local-part token (`"jane"`) into a display name component
/// (`"Jane"`) for the inferred `Person` entity. Empty input yields `""`.
pub(super) fn capitalise(s: &str) -> String {
    crate::util::str_util::upper_first(s)
}

/// Re-export of the shared freemail check. Kept for backwards
/// compatibility — new callers should use [`crate::util::domains::is_freemail`].
pub fn is_freemail(domain: &str) -> bool {
    crate::util::domains::is_freemail(domain)
}
