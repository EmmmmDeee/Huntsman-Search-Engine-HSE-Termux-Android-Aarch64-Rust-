//! Manual operator query-pack generation.
//!
//! For one scan target, produce the ranked set of queries an operator runs **by
//! hand** against the manual / paid exposure providers — the operator-assisted
//! mode for sources HSE cannot auto-query (no entitlement) or where a human must
//! confirm a hit before it is trusted.
//!
//! ## Why this is safe to generate offline (RULE 1)
//!
//! This module is **purely deterministic and does no I/O**. It emits the query
//! STRING and names the provider surface to run it on; HSE makes no network call
//! and parses no response here, so it declares no provider API contract and can
//! fabricate no finding — nothing here observes one. A `ManualQuery` is an
//! instruction for a person, not evidence.
//!
//! Every provider surface named here is a domain **this codebase already
//! reaches** through that provider's own module, so the pack points an operator
//! only at services HSE has itself verified — never a guessed endpoint. A
//! provider that HSE does not yet integrate (no verified surface) is
//! deliberately absent rather than pointed at a fabricated URL; it joins the
//! pack when its module lands.
//!
//! ## Scope: DISCOVERY / EXPOSURE VERIFICATION / CORRELATION only
//!
//! The pack asks *"is this identifier exposed on provider X?"* — never *"use
//! this credential"*. It contains no account-takeover, credential-stuffing,
//! session-replay, or authentication-bypass workflow: every entry is a lookup
//! of the operator's own authorised target value against an exposure index.

#[cfg(test)]
mod tests;

use crate::core::scan::{Target, TargetKind};

/// One manual query for an operator to run against one provider.
///
/// Fields mirror the operator-pack schema: which provider, its manual-pack rank,
/// the query and its type, where to run it, the class of result to expect, the
/// seed target it descends from ([`ManualQuery::parent_query_id`], stable per
/// target so a whole pack links back to one seed), and when it was generated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualQuery {
    /// The provider the operator runs this query against.
    pub provider: &'static str,
    /// Manual-pack execution rank — the order to work the providers, lower
    /// first. Stable per provider, independent of which providers a given target
    /// skips, so two packs rank the same provider identically.
    pub rank: u32,
    /// The query string to run — the operator's own authorised target value.
    pub query: String,
    /// The kind of the query value (`email`, `domain`, …), the target's
    /// canonical kind name.
    pub query_type: &'static str,
    /// The provider's canonical surface — a domain this codebase already
    /// reaches — that the operator opens to run the query.
    pub manual_entrypoint: &'static str,
    /// What class of result to expect, including any corroboration caveat (a
    /// gateway is flagged as non-independent; a high-trust miss is flagged as
    /// not proof of absence).
    pub expected_result_class: &'static str,
    /// Stable id of the seed target this query descends from, so an operator (or
    /// a later correlation pass) can group a whole pack under one origin.
    pub parent_query_id: String,
    /// Unix seconds the pack was generated. Passed in by the caller so the
    /// generator stays pure and deterministic (tests pass a fixed value).
    pub generated_at: u64,
}

/// A manual-provider entry: its stable rank, canonical surface (a domain this
/// codebase already reaches), the result class an operator should expect, and
/// the target kinds it can be queried for.
struct Provider {
    name: &'static str,
    rank: u32,
    entrypoint: &'static str,
    expected_result_class: &'static str,
    accepts: &'static [TargetKind],
}

/// Identity-bearing kinds a broad breach/exposure engine accepts. Shared by the
/// general breach providers so their acceptance can't drift apart.
const BREACH_KINDS: &[TargetKind] = &[
    TargetKind::Email,
    TargetKind::Username,
    TargetKind::Domain,
    TargetKind::Phone,
    TargetKind::FullName,
    TargetKind::IpAddress,
];

/// The manual providers, in manual-pack order, restricted to those whose surface
/// this codebase already verifies (each domain appears in that provider's own
/// module). Ranks follow the manual-provider ordering; a provider HSE does not
/// yet integrate is intentionally omitted rather than pointed at a guessed URL.
const PROVIDERS: &[Provider] = &[
    Provider {
        name: "Intelligence X",
        rank: 1,
        entrypoint: "intelx.io",
        expected_result_class: "historical / archive / dark-web / document exposure (IntelX auto-classifies the selector)",
        // IntelX's structured-selector set plus its text fallback — the same
        // kinds `modules::intelx` forwards.
        accepts: &[
            TargetKind::Email,
            TargetKind::Domain,
            TargetKind::Url,
            TargetKind::IpAddress,
            TargetKind::Cidr,
            TargetKind::Phone,
            TargetKind::CryptoAddress,
            TargetKind::MacAddress,
            TargetKind::Username,
            TargetKind::FullName,
        ],
    },
    Provider {
        name: "OathNet",
        rank: 2,
        entrypoint: "oathnet.org",
        expected_result_class: "breach + infostealer records (run breach and stealer surfaces separately)",
        accepts: BREACH_KINDS,
    },
    Provider {
        name: "Stolen.tax",
        rank: 3,
        entrypoint: "stolen.tax",
        expected_result_class: "MULTI-SOURCE GATEWAY — corroborate against direct upstreams; a hit here is NOT an independent source",
        accepts: BREACH_KINDS,
    },
    Provider {
        name: "DeHashed",
        rank: 4,
        entrypoint: "dehashed.com",
        expected_result_class: "breach credentials (broad conventional engine)",
        accepts: BREACH_KINDS,
    },
    Provider {
        name: "XposedOrNot",
        rank: 5,
        entrypoint: "xposedornot.com",
        expected_result_class: "email breach exposure + breach catalogue",
        accepts: &[TargetKind::Email, TargetKind::Domain],
    },
    Provider {
        name: "Have I Been Pwned",
        rank: 6,
        entrypoint: "haveibeenpwned.com",
        expected_result_class: "breach attribution / confirmation — a MISS is NOT proof of no exposure",
        accepts: &[TargetKind::Email, TargetKind::Domain],
    },
];

/// Build the manual query pack for `target`, stamped `generated_at` (Unix
/// seconds). **Pure**: no I/O, deterministic for a given `(target, generated_at)`.
///
/// Returns one [`ManualQuery`] per provider that accepts the target's kind, in
/// ascending [`ManualQuery::rank`] order, each carrying the same
/// `parent_query_id` derived from the target so the whole pack groups under one
/// seed. An empty target value, or a kind no manual provider accepts (e.g. a
/// coordinate or a local device id), yields an empty pack rather than a fake
/// entry.
#[must_use]
pub fn generate(target: &Target, generated_at: u64) -> Vec<ManualQuery> {
    let value = target.value.trim();
    if value.is_empty() {
        return Vec::new();
    }
    let parent_query_id = parent_id(target.kind.canonical_str(), value);
    PROVIDERS
        .iter()
        .filter(|p| p.accepts.contains(&target.kind))
        .map(|p| ManualQuery {
            provider: p.name,
            rank: p.rank,
            query: value.to_string(),
            query_type: target.kind.canonical_str(),
            manual_entrypoint: p.entrypoint,
            expected_result_class: p.expected_result_class,
            parent_query_id: parent_query_id.clone(),
            generated_at,
        })
        .collect()
}

/// Stable, target-specific pack id: `qp-<16 hex>` over `"<kind>:<value>"`.
///
/// Deterministic content hash (NOT [`crate::util::uid::scan_id`], which mixes in
/// a timestamp/counter to make each scan unique — the opposite of what a pack id
/// needs). Same target → same id across runs; different targets → different ids,
/// so packs never cross-link.
fn parent_id(kind: &str, value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{kind}:{value}").as_bytes());
    let n = u64::from_be_bytes(digest[..8].try_into().expect("sha256 digest is 32 bytes"));
    format!("qp-{n:016x}")
}
