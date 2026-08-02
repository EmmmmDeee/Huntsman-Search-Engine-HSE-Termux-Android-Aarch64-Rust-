//! PART I — the findings themselves, grouped by entity type.
//!
//! This is the body of the dossier. Everything else in the document either
//! introduces it ([`super::frontmatter`]), draws conclusions from it
//! ([`super::analysis`]), or supports it ([`super::appendix`]).

use std::collections::BTreeMap;

use crate::core::entity::Entity;

/// Curated display order for the findings sections. Kinds not listed here are
/// still rendered — appended after, in deterministic key order, by
/// [`order_dossier_kinds`] — so no finding is ever dropped from the dossier.
pub(super) const DOSSIER_KIND_ORDER: &[&str] = &[
    "person",
    "email",
    "phone",
    "username",
    "credential",
    "api_key",
    "password",
    "address",
    "coordinates",
    "organisation",
    "abn_acn",
    "asn",
    "domain",
    "ip_address",
    "url",
    "mac_address",
    "device_id",
    "cidr",
    "ssid",
    "tracking_id",
    "crypto_address",
];

/// The order to render the findings sections in: the curated
/// [`DOSSIER_KIND_ORDER`] (those present) first, then EVERY other present kind
/// — a rarer `EntityKind` or an `other:<custom>` — in deterministic
/// (sorted-key) order.
///
/// The dossier previously iterated a fixed allowlist and silently dropped any
/// unlisted kind (`cidr`, `ssid`, `tracking_id`, `crypto_address`, every
/// `other:*`); this guarantees it is a COMPLETE view of the working set. Pure.
pub(super) fn order_dossier_kinds<'a>(by_kind: &'a BTreeMap<String, Vec<&Entity>>) -> Vec<&'a str> {
    let mut ordered: Vec<&str> = DOSSIER_KIND_ORDER
        .iter()
        .copied()
        .filter(|k| by_kind.contains_key(*k))
        .collect();
    // Catch-all: every present kind not in the curated list, in BTreeMap key
    // order (deterministic), so nothing is dropped and the output is stable.
    for k in by_kind.keys() {
        if !DOSSIER_KIND_ORDER.contains(&k.as_str()) {
            ordered.push(k.as_str());
        }
    }
    ordered
}

/// The operator-facing heading for a kind. An unrecognised kind — a rare
/// variant or an `other:<custom>` — is titled with its own key rather than
/// bucketed under a generic "OTHER", so the heading never misdescribes what is
/// under it. Pure.
pub(super) fn kind_heading(kind_name: &str) -> &str {
    match kind_name {
        "person" => "PERSONS",
        "email" => "EMAIL ADDRESSES",
        "phone" => "PHONE NUMBERS",
        "username" => "USERNAMES / HANDLES",
        "credential" => "CREDENTIALS (from breach/stealer data)",
        "api_key" => "API KEYS (from breach/stealer data)",
        "password" => "PASSWORDS (from breach/stealer data)",
        "address" => "PHYSICAL ADDRESSES / LOCATIONS",
        "coordinates" => "GPS COORDINATES",
        "organisation" => "ORGANISATIONS",
        "abn_acn" => "ABN / ACN (Australian Business Numbers)",
        "domain" => "DOMAINS",
        "ip_address" => "IP ADDRESSES",
        "url" => "URLS / PROFILES",
        "mac_address" => "MAC ADDRESSES (network devices)",
        "device_id" => "DEVICE IDENTIFIERS",
        "asn" => "ASN (autonomous systems)",
        "cidr" => "CIDR RANGES (network blocks)",
        "ssid" => "WIFI NETWORKS (SSIDs)",
        "tracking_id" => "TRACKING IDENTIFIERS",
        "crypto_address" => "CRYPTOCURRENCY ADDRESSES",
        other => other,
    }
}

/// Group the working set by entity kind. Kept as its own step so the caller
/// can count kinds and findings for the CONTENTS index before printing.
pub(super) fn group_by_kind(entities: &[Entity]) -> BTreeMap<String, Vec<&Entity>> {
    let mut by_kind: BTreeMap<String, Vec<&Entity>> = BTreeMap::new();
    for e in entities {
        by_kind.entry(e.kind.to_string()).or_default().push(e);
    }
    by_kind
}

/// Render every kind section, curated order first and then everything else —
/// see [`order_dossier_kinds`]. A previous fixed allowlist silently DROPPED any
/// kind not listed, hiding real, collected intel from the operator's dossier.
///
/// `hints_letter` is the letter the optimisation-hints appendix will print
/// under, taken from the same plan that letters the back matter — so the
/// empty-set cross-reference below points at a section that provably exists.
pub(super) fn print(by_kind: &BTreeMap<String, Vec<&Entity>>, hints_letter: Option<char>) {
    println!("━━━ PART I — FINDINGS BY ENTITY TYPE ━━━");
    println!();

    if by_kind.is_empty() {
        // Never silently empty: an operator must be able to tell "nothing was
        // found" from "the section failed to render". The why, when there is
        // one, is in the optimisation-hints appendix.
        let pointer = hints_letter.map_or_else(String::new, |l| format!(" — see Appendix {l}"));
        println!("  No entities were admitted for this target{pointer}.");
        println!();
        return;
    }

    for kind_name in order_dossier_kinds(by_kind) {
        let group = &by_kind[kind_name];
        println!("━━━ {} ({}) ━━━", kind_heading(kind_name), group.len());
        println!();

        for e in &sort_findings(group) {
            print_finding(e);
        }
    }
}

/// One kind's findings in print order: confidence descending, uid ascending —
/// the SAME total order the store applies (`ORDER BY e.confidence DESC, e.uid
/// ASC`).
///
/// The uid tie-break is not decoration. `sort_by` is stable, so without it
/// equal-confidence findings keep whatever order the caller handed them, which
/// is the backend's row order rather than the dossier's own; two runs over the
/// same data would then be free to disagree. A dossier an operator cannot diff
/// against yesterday's is a dossier they cannot cite. Pure.
pub(super) fn sort_findings<'a>(group: &[&'a Entity]) -> Vec<&'a Entity> {
    let mut sorted = group.to_vec();
    sorted.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.uid.cmp(&b.uid))
    });
    sorted
}

/// One finding: the value, how well it is believed, its tags, the collection
/// technique(s) that produced it, and every piece of evidence behind it.
fn print_finding(e: &Entity) {
    println!(
        "  {} [{}]  conf={:.2}  c_eff={:.2}  corr={}",
        e.value,
        e.classify(),
        e.confidence,
        e.c_effective(),
        e.corroboration
    );

    if !e.tags.is_empty() {
        println!("    tags: {}", e.tags.join(", "));
    }

    // Compact MITRE ATT&CK provenance: the inline `attack:<ID>` tags the engine
    // stamps onto every admitted entity, resolved to their Reconnaissance
    // technique names. Surfaces, per finding, exactly which collection
    // technique(s) produced it — the alignment lives in the data, not a
    // separate coverage report. (CLI may import core::attack.)
    let mitre: Vec<String> = e
        .tags
        .iter()
        .filter_map(|t| t.strip_prefix("attack:"))
        .map(|id| {
            crate::core::attack::technique(id)
                .map_or_else(|| id.to_string(), |t| format!("{} {}", t.id, t.name))
        })
        .collect();
    if !mitre.is_empty() {
        println!("    MITRE ATT&CK: {}", mitre.join("; "));
    }

    for ev in &e.evidence {
        // Two qualifiers that decide how much weight a reader should give the
        // line, and which the sibling renderers (the debug bundle's ENTITIES
        // section and the web Browse evidence block) already show — the live
        // dossier was the one consumer rendering all evidence as if it were
        // equal, direct observation:
        //   * non-corroborating — a self-enrichment/recall/cross-scan/consensus
        //     pass that attaches real detail but never counts toward
        //     `source_count`, so it must not read as independent confirmation;
        //   * inferred — a derivation (name permuted from a username,
        //     coordinates computed from an address), not an observation.
        let marker = if crate::core::entity::is_non_corroborating_source(&ev.source) {
            "  (non-corroborating)"
        } else {
            ""
        };
        let inferred = if ev.is_inferred { "  (inferred)" } else { "" };
        println!(
            "    ├─ {src} — {summary}{marker}{inferred}",
            src = ev.source,
            summary = ev.summary
        );
        for (k, v) in &ev.attributes {
            if !v.is_empty() {
                println!("    │  {k}: {v}");
            }
        }
    }
    println!();
}
