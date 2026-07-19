//! Free, **offline** intelligence decoded from an Australian business
//! identifier — the ABN/ACN analogue of [`crate::modules::structured_id`].
//!
//! An ABN or ACN is not an opaque token: it carries a deterministic check digit
//! (validated keylessly by [`crate::util::abn`]) and, for a **company**, the ABN
//! *embeds the ACN* as its trailing nine digits behind a two-digit checksum.
//! This module reads that structure straight out of the number — no API, no key,
//! no network — and turns it into two pieces of synergistic intelligence:
//!
//!   * **Entity-type classification.** A checksum-valid ABN whose trailing nine
//!     digits are themselves a valid ACN belongs to an ASIC-registered
//!     **company** (`au-company`); one whose tail is not an ACN belongs to a
//!     **non-company** (`au-non-company` — sole trader, trust, partnership or
//!     super fund). That is a person-vs-incorporated-entity signal recovered
//!     from the identifier alone, before any register is queried.
//!   * **ACN pivot.** For a company ABN it emits the embedded ACN as a
//!     first-class `AbnAcn` entity. The ACN — not the ABN — is the key ASIC,
//!     ASX and court/tribunal records index on, so surfacing it opens the
//!     company → officeholders/directors → people → registered-office address →
//!     coordinates pivot chain through the `opencorporates` / `abn_lookup`
//!     resolvers that consume `AbnAcn` targets. A seed ABN that previously dead-
//!     ended at the ABR now reaches the people behind the company.
//!
//! Deliberately conservative and non-fabricating:
//!   * It never **invents** an identifier. The ACN it emits is literally the
//!     ABN's own trailing nine digits, and only when that slice independently
//!     passes the ASIC check digit — so a non-company ABN yields no ACN rather
//!     than a plausible-looking fake.
//!   * It cannot derive an ABN *from* an ACN (the ABN's two check digits are
//!     assigned at registration, not computable from the ACN), so a bare ACN is
//!     classified and tagged but produces no derived ABN.
//!   * Pure lookup, < 1 ms, fully deterministic on aarch64/Termux — applies to
//!     the millions of Australian sole traders and companies whose ABN/ACN turns
//!     up in registry, breach, invoice or scraped data.

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::abn::{derive_acn, is_valid_abn, is_valid_acn};

const SRC: &str = "au_business_id";

/// Group a bare ACN as `NNN NNN NNN` for display; passthrough if not 9 digits.
/// Pure.
fn format_acn(acn: &str) -> String {
    if acn.len() == 9 && acn.bytes().all(|b| b.is_ascii_digit()) {
        format!("{} {} {}", &acn[0..3], &acn[3..6], &acn[6..9])
    } else {
        acn.to_string()
    }
}

pub struct AuBusinessId;

#[async_trait]
impl Module for AuBusinessId {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Offline ABN/ACN decode — classifies company vs non-company and derives the embedded ACN pivot"
    }

    fn priority(&self) -> u8 {
        // Offline-decode band, alongside `structured_id` (103). Ordering only —
        // it runs independently of the live ABR/ASIC resolvers.
        104
    }

    fn is_passive(&self) -> bool {
        // Pure offline computation — no network, no I/O, no key.
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only gate; the checksum decision is made in `process()`.
        matches!(t.kind, TargetKind::AbnAcn)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::AbnAcn];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let value = target.value.trim();

        if is_valid_abn(value) {
            // A checksum-valid ABN. Classify it by whether it embeds an ACN.
            let mut e = target.to_entity(0.55, &ctx.scan_id);
            e.tag(SRC);
            e.tag("abn-valid");
            if let Some(acn) = derive_acn(value) {
                // Company ABN — tag it and surface the embedded ACN as a pivot.
                e.tag("au-company");
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!(
                            "Checksum-valid company ABN; embeds ACN {} (decoded offline)",
                            format_acn(&acn)
                        ),
                    )
                    .with_attr("abn_valid", "true")
                    .with_attr("entity_type", "company")
                    .with_attr("derived_acn", acn.as_str()),
                );
                result.push(e);

                let mut acn_e = Entity::new(EntityKind::AbnAcn, &acn, 0.80, &ctx.scan_id);
                acn_e.tag(SRC);
                acn_e.tag("acn-valid");
                acn_e.tag("au-company");
                acn_e.tag("derived");
                acn_e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!(
                            "ACN {} derived from company ABN {} (offline; ASIC check digit holds)",
                            format_acn(&acn),
                            value
                        ),
                    )
                    .with_attr("source_abn", value)
                    .with_attr("acn_grouped", format_acn(&acn).as_str()),
                );
                result.push(acn_e);
            } else {
                // Valid ABN whose tail is not an ACN → a non-company holder.
                e.tag("au-non-company");
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        "Checksum-valid non-company ABN (sole trader / trust / partnership / \
                         super fund — no embedded ACN)"
                            .to_string(),
                    )
                    .with_attr("abn_valid", "true")
                    .with_attr("entity_type", "non_company"),
                );
                result.push(e);
            }
        } else if is_valid_acn(value) {
            // A bare, checksum-valid ACN. Classify as a company identifier. The
            // ABN is not derivable from the ACN, so no ABN is emitted.
            let mut e = target.to_entity(0.55, &ctx.scan_id);
            e.tag(SRC);
            e.tag("acn-valid");
            e.tag("au-company");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Checksum-valid ACN {} — an ASIC-registered company (offline)",
                        format_acn(value)
                    ),
                )
                .with_attr("acn_valid", "true")
                .with_attr("entity_type", "company"),
            );
            result.push(e);
        }
        // A value that is neither a valid ABN nor ACN yields nothing — the
        // classifier only mints `AbnAcn` targets from checksum-valid strings, so
        // this branch is a defensive no-op rather than an error.

        Ok(result)
    }
}
