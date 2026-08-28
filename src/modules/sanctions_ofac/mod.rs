//! OFAC sanctions screening — SDN + Consolidated (non-SDN) lists, keyless.
//!
//! Screens against BOTH official OFAC lists: the Specially Designated Nationals
//! (SDN) list (full blocking) AND the Consolidated (non-SDN) list — the
//! sectoral/FSE/PLC/ISA designations that are sanctions but not full SDN
//! blocking. Both share the same CSV schema, so both feed one screening set;
//! screening SDN alone silently missed every consolidated-list designation.
//!
//! Two things go in, and they are screened by two different mechanisms:
//!
//! | Target | Matched on | Grade |
//! |---|---|---|
//! | `FullName` / `Organisation` | fuzzy, all-tokens name comparison | [`entity::HIT_CONFIDENCE`] + identity hedge |
//! | `CryptoAddress` | exact digital-currency-address designation | [`entity::ADDRESS_HIT_CONFIDENCE`], no hedge |
//!
//! The highest-signal due-diligence register a lawful OSINT tool can query: a
//! sanctions hit is precisely the kind of adverse finding
//! `asic_banned_orgs`/`asic_persons` already surface for Australia, extended
//! here to a global, official U.S. government list.
//!
//! # Data source
//! `GET .../api/download/SDN.CSV` and `.../CONS_PRIM.CSV` on
//! `sanctionslistservice.ofac.treas.gov` — OFAC's Sanctions List Service (the
//! SDN and Consolidated lists respectively). No auth, no API key, no published rate
//! limit; bulk/automated download is the OFFICIAL intended use (Treasury
//! recommends pulling the whole file and refreshing wholesale, not polling
//! per query). A U.S. federal government work — not subject to domestic
//! copyright (17 U.S.C. §105) — published specifically for third-party
//! compliance/screening tools to consume programmatically. The endpoint
//! redirects (302) to a time-limited, pre-signed S3 URL; the shared HTTP
//! client follows redirects automatically (see `util::http::ssrf`), so no
//! special handling is needed here.
//!
//! There is no per-name search API, unlike the CKAN-backed AU registers
//! (`asic_persons`/`asic_banned_orgs`), so the whole file is downloaded once
//! and cached in-process (see [`list`]), then matched against locally per query
//! — see [`parse`] for the CSV format and [`parse::SdnKind`] classification.
//!
//! # Digital-currency screening
//! OFAC designates wallet addresses inline in the `Remarks` column rather than
//! in a field of their own, so the addresses were already being downloaded and
//! parsed on every name query — and then thrown away, because screening only
//! ever looked at names. A sanctioned wallet pasted into HSE would get on-chain
//! balance from `chain_intel` and no sanctions verdict at all.
//!
//! [`crypto`] reads them out of the remarks the module already holds: no new
//! dependency, no new network source, no new key. Both directions are wired —
//! address in, and (as pivot material for `chain_intel`) address out of a name
//! match. See [`entity::Provenance`] for why the two are graded differently.
//!
//! # Misattribution risk (deliberately mitigated, not left implicit)
//! OFAC's list is dominated by common transliterated names, so a bare name
//! match against a global, several-thousand-row list carries a real
//! false-positive risk — wrongly implying a person is sanctioned is a serious
//! harm. Mitigations, all of which apply to the NAME path specifically:
//!   1. Confidence is **confidence::MEDIUM** — deliberately BELOW the confidence::MEDIUM_PLUS the AU registers
//!      use for an equivalent single-source adverse-register hit
//!      (`asic_persons`/`asic_banned_orgs`), because this source's collision
//!      risk is objectively higher (a global name pool vs. a national
//!      register) — a bare hit here must read as a weaker lead, not an
//!      equally-confident one.
//!   2. Every hit's evidence carries an explicit `caution` attribute telling
//!      the operator to verify identity (DOB/nationality/passport in
//!      `Remarks`) before treating it as confirmed.
//!   3. Entities are tagged `needs-identity-verification` in addition to
//!      `sanctions`/`ofac`/`regulatory-action`, so any downstream UI/report
//!      can visually flag "unconfirmed" rather than "confirmed sanctioned".
//!   4. Name matching requires ALL tokens of length >= 3 present
//!      ([`parse::name_tokens`]/[`parse::record_name_matches`]) — stricter than
//!      the AU registers' >= 2-character floor, to reduce spurious
//!      single-token collisions on a global name pool.
//!
//! None of the four applies to the ADDRESS path, and that is deliberate rather
//! than an oversight: every one of them exists because a *name* comparison is
//! fuzzy. An address comparison is not, so carrying the hedge across would
//! understate a certain finding just as badly as dropping it would overstate an
//! uncertain one.
//!
//! `Vessel`/`Aircraft`-typed rows are not emitted as subjects at all — HSE
//! has no matching `EntityKind`, and mapping a ship/plane to `Person` or
//! `Organisation` would misrepresent it. A wallet such a row designates IS
//! still emitted; the designation is real regardless of the subject's shape.

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

mod crypto;
mod entity;
mod list;
mod parse;

use entity::{Provenance, build_subject, build_wallet};
use list::fetch_sdn_list;
use parse::{SdnRecord, name_tokens, record_name_matches};

const SRC: &str = "sanctions_ofac";

/// Cap on emitted name hits per query — a very common name could match dozens
/// of distinct SDN entries; beyond this it reads as noise rather than a lead
/// (mirrors the bounded-emission discipline used throughout this codebase,
/// e.g. `web_crawler`'s `CONTACT_DUMP_LIMIT`).
///
/// Applies to the NAME path only, and never silently: an overflow is logged
/// with the true total. The address path is uncapped — see
/// [`crypto::screen_address`] for why a cap there could only hide a genuine
/// co-designation.
const MAX_HITS: usize = 20;

/// Screen a digital-currency address against every designation OFAC published.
///
/// Emits, per designating row, the sanctioned person/organisation AND the
/// wallet itself — the operator asked about an address, so the answer must name
/// who it belongs to, and re-emitting the address carries the verdict onto the
/// entity the rest of the scan already has.
async fn screen_wallet(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();
    let addr = target.value.trim();
    if addr.is_empty() {
        return Ok(result);
    }

    // `?`: a list that could not be loaded must NOT read as "no designations
    // matched" — see `list::degrade_on_fetch_failure`.
    let records = fetch_sdn_list(ctx).await?;
    for (rec, sa) in crypto::screen_address(&records, addr) {
        if let Some(e) = build_subject(rec, &ctx.scan_id, Provenance::Address) {
            result.push(e);
        }
        result.push(build_wallet(rec, &sa, &ctx.scan_id, Provenance::Address));
    }
    Ok(result)
}

/// Screen a name against the list, and expand each hit into the wallets that
/// row designates.
///
/// The wallets are pivot material, not verdicts about the operator's subject —
/// see [`build_wallet`] — but they are what lets a name scan reach on-chain
/// activity at all.
async fn screen_name(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();
    let name = target.value.trim();
    let tokens = name_tokens(name);
    if tokens.len() < 2 {
        // A single-token query against a global list is far too weak a
        // discriminator (see the module doc's misattribution-risk note).
        return Ok(result);
    }

    // `?`: a list that could not be loaded must NOT read as "no designations
    // matched" — see `list::degrade_on_fetch_failure`.
    let records = fetch_sdn_list(ctx).await?;
    let matches: Vec<&SdnRecord> = records
        .iter()
        .filter(|r| record_name_matches(&r.name, &tokens))
        .collect();
    if matches.len() > MAX_HITS {
        // Never drop silently: an operator reading 20 hits must be able to tell
        // "20 designations exist" from "20 of 300 are shown".
        tracing::warn!(
            "{SRC}: '{name}' matched {} sanctions entries; emitting the first {MAX_HITS} — \
             the rest are NOT in this scan's results",
            matches.len()
        );
    }

    for rec in matches.into_iter().take(MAX_HITS) {
        if let Some(e) = build_subject(rec, &ctx.scan_id, Provenance::Name) {
            result.push(e);
        }
        for sa in crypto::digital_currency_addresses(&rec.remarks) {
            result.push(build_wallet(rec, &sa, &ctx.scan_id, Provenance::Name));
        }
    }
    Ok(result)
}

pub struct SanctionsOfac;

#[async_trait]
impl Module for SanctionsOfac {
    fn name(&self) -> &'static str {
        "sanctions_ofac"
    }

    fn description(&self) -> &'static str {
        "OFAC sanctions screening (keyless) — pivots a name OR a crypto wallet to designations, program, and remarks"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): a global authoritative
        // register, alongside gleif_lei (111) rather than the AU-specific
        // registers (112-118) — both are global/cross-jurisdiction sources.
        111
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::FullName | TargetKind::Organisation | TargetKind::CryptoAddress
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A government adverse-finding register on a person/organisation —
        // T1591.002 Business Relationships (for the org side) and identifying
        // roles/associations for the person side. The wallet path additionally
        // queries an open technical database keyed on an identifier (T1596).
        &["T1591.002", "T1596"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::CryptoAddress,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // A cold cache means a multi-MB download; a warm cache is instant.
        20_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::CryptoAddress => screen_wallet(target, ctx).await,
            _ => screen_name(target, ctx).await,
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
