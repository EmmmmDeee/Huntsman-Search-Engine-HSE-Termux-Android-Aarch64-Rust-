//! Turning a matched OFAC row into entities — and grading it honestly.
//!
//! This file exists because the module now reaches its rows two very different
//! ways, and the two must NOT be graded the same. See [`Provenance`]: that
//! distinction is the whole point of separating this from [`super::parse`].
//!
//! Pure: no network, no IO, no global state.

use crate::core::{
    confidence,
    crypto::{chain_label, classify_crypto_address},
    entity::{Entity, EntityKind, Evidence},
};

use super::SRC;
use super::crypto::SanctionedAddress;
use super::parse::{SdnKind, SdnRecord, humanise_name};

/// Confidence for a bare, single-source NAME hit — see the module doc's
/// misattribution-risk section for why this is deliberately below the AU
/// registers' `confidence::MEDIUM_PLUS` precedent.
pub(super) const HIT_CONFIDENCE: f64 = confidence::MEDIUM;
// Compile-time pin: a careless future edit must not silently raise this back
// to (or above) the AU registers' confidence::MEDIUM_PLUS without revisiting
// the rationale above.
const _: () = assert!(HIT_CONFIDENCE < confidence::MEDIUM_PLUS);

/// Confidence for a digital-currency-ADDRESS hit.
///
/// Graded far above [`HIT_CONFIDENCE`] because it is a categorically stronger
/// finding, not a stronger guess. A wallet address is a high-entropy identifier
/// that denotes exactly one thing; matching one against OFAC's published
/// designation is a string equality on an authoritative government list, not a
/// fuzzy comparison of a common transliterated name against a global pool. None
/// of the collision risk the name path is hedged against exists here.
///
/// Deliberately NOT `CERTAIN`: what remains uncertain is the list snapshot, not
/// the match — OFAC amends designations, and this module screens against a
/// cached copy up to [`LIST_CACHE_TTL_SECS`](super::list) old. The residual
/// doubt is staleness, and it is small.
pub(super) const ADDRESS_HIT_CONFIDENCE: f64 = confidence::VERY_HIGH_PLUSPLUS;
// Compile-time pin on the asymmetry itself: an exact identifier match must
// always outrank a fuzzy name match, whatever either constant is later tuned to.
const _: () = assert!(ADDRESS_HIT_CONFIDENCE > HIT_CONFIDENCE);

/// How a designation was reached. Decides the confidence every entity derived
/// from it carries, and whether it must warn the operator about identity.
///
/// This is the module's central honesty mechanism. The same SDN row can be
/// found by a fuzzy name match or by an exact wallet match, and the two say
/// genuinely different things:
///
/// - [`Provenance::Name`] — "a row on the list has a name like your subject's".
///   Might be them. Might be someone with the same transliteration.
/// - [`Provenance::Address`] — "the identifier you gave me is on the list".
///   No might about it.
///
/// Collapsing these into one grade would either understate a certain finding or
/// overstate an uncertain one; both are failures, and the second is the kind
/// that wrongly brands a person as sanctioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Provenance {
    /// The operator's target was a name that fuzzily matched this row.
    Name,
    /// The operator's target WAS a digital-currency address this row designates.
    Address,
}

impl Provenance {
    /// The confidence entities from this provenance carry.
    pub(super) const fn confidence(self) -> f64 {
        match self {
            Self::Name => HIT_CONFIDENCE,
            Self::Address => ADDRESS_HIT_CONFIDENCE,
        }
    }

    /// Whether findings from this provenance need the identity-verification
    /// hedge — true exactly when the link to the operator's subject is a name
    /// comparison rather than an identifier match.
    const fn needs_identity_verification(self) -> bool {
        matches!(self, Self::Name)
    }
}

/// The tags every entity this module emits carries, whatever its kind.
fn tag_common(e: &mut Entity, prov: Provenance) {
    e.tag("sanctions");
    e.tag("ofac");
    e.tag("regulatory-action");
    if prov.needs_identity_verification() {
        e.tag("needs-identity-verification");
    }
}

/// The evidence shared by every finding off one row: which register, which
/// designation, and — for a name match only — the caution.
fn base_evidence(rec: &SdnRecord, summary: String, prov: Provenance) -> Evidence {
    let mut ev = Evidence::new(SRC, summary)
        .with_attr("register", "OFAC Specially Designated Nationals (SDN) List")
        .with_attr("ent_num", rec.ent_num.to_string());
    ev = match prov {
        Provenance::Name => ev.with_attr(
            "caution",
            "Name-only match against a global sanctions list — verify identity \
             (DOB, nationality, passport/ID) via the remarks before treating this \
             as a confirmed match; common transliterated names collide.",
        ),
        // No caution, because there is nothing to caution about: the operator's
        // own input is the string OFAC designated. Stating the basis instead of
        // a warning is the honest thing to record.
        Provenance::Address => ev.with_attr(
            "match_basis",
            "Exact match on a digital-currency address OFAC designated on this \
             entry — an identifier match, not a name match.",
        ),
    };
    if !rec.program.is_empty() {
        ev = ev.with_attr("program", &rec.program);
    }
    if !rec.title.is_empty() {
        ev = ev.with_attr("title", &rec.title);
    }
    if !rec.remarks.is_empty() {
        ev = ev.with_attr("remarks", &rec.remarks);
    }
    ev
}

/// Map one matched SDN record to the person/organisation it names, if its kind
/// has a matching `EntityKind` — `Vessel`/`Aircraft` rows return `None` (see
/// module doc). **Pure** — no network/IO.
pub(super) fn build_subject(rec: &SdnRecord, scan_id: &str, prov: Provenance) -> Option<Entity> {
    let (kind, display_name) = match rec.kind {
        SdnKind::Individual => (EntityKind::Person, humanise_name(&rec.name)),
        SdnKind::Organisation => (EntityKind::Organisation, rec.name.clone()),
        SdnKind::Vessel | SdnKind::Aircraft => return None,
    };
    if display_name.trim().is_empty() {
        return None;
    }

    let mut e = Entity::new(kind, &display_name, prov.confidence(), scan_id);
    tag_common(&mut e, prov);
    e.add_evidence(base_evidence(
        rec,
        format!("OFAC SDN list match: {display_name}"),
        prov,
    ));
    Some(e)
}

/// The designated wallet itself, as a `CryptoAddress` entity.
///
/// Emitted on BOTH paths, and that is the point:
///
/// - Reached by address ([`Provenance::Address`]) it is the operator's own
///   target, confirmed sanctioned — the finding.
/// - Reached by name ([`Provenance::Name`]) it is a **pivot**: OFAC certainly
///   designated this wallet, but its link to the operator's subject is only as
///   strong as the name match that surfaced it, so it inherits that weaker
///   grade and keeps the identity hedge. Emitting it lets the engine hand the
///   address to `chain_intel` for on-chain enrichment — a name-to-wallet-to-
///   blockchain expansion chain the module could not previously produce at all.
///
/// The address is recorded exactly as OFAC published it (EIP-55 case included),
/// never as the operator typed it, so the entity is quotable against the source.
pub(super) fn build_wallet(
    rec: &SdnRecord,
    sa: &SanctionedAddress,
    scan_id: &str,
    prov: Provenance,
) -> Entity {
    let subject = match rec.kind {
        SdnKind::Individual => humanise_name(&rec.name),
        _ => rec.name.clone(),
    };

    let mut e = Entity::new(
        EntityKind::CryptoAddress,
        &sa.address,
        prov.confidence(),
        scan_id,
    );
    tag_common(&mut e, prov);
    e.tag("crypto-address");
    e.tag("sanctioned-wallet");
    // HSE's own shape-based classification, kept as a separate `chain:` tag from
    // the `designated_currency` attribute below: one is our inference, the other
    // is Treasury's statement. `chain_intel` keys its pivots off this tag.
    if let Some(chain) = classify_crypto_address(&sa.address) {
        e.tag(format!("chain:{}", chain_label(chain)));
    }

    let ev = base_evidence(
        rec,
        format!("OFAC designated this address on the entry for {subject}"),
        prov,
    )
    // OFAC's OWN currency symbol, verbatim — see `crypto::SanctionedAddress`
    // for why this is not folded into the inferred `chain:` tag.
    .with_attr("designated_currency", &sa.symbol)
    .with_attr("designated_entity", &subject);
    e.add_evidence(ev);
    e
}
