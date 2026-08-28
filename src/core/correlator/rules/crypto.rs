//! AU correlation rules — crypto family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

/// Buckets `ents` by each of their own corroborating evidence sources, so an
/// anchor lookup for one entity is a handful of `source → candidates` map
/// probes instead of a full rescan. Shared by [`rule_au_039_wallet_identity`]'s
/// wallet→Person and wallet→Email anchor passes.
fn index_by_source<'a>(ents: &[&'a Entity]) -> HashMap<&'a str, Vec<&'a Entity>> {
    let mut idx: HashMap<&str, Vec<&Entity>> = HashMap::new();
    for &e in ents {
        for s in e.corroborating_sources() {
            idx.entry(s).or_default().push(e);
        }
    }
    idx
}

/// Entities in `idx` sharing ANY corroborating source with `w`, deduped by
/// uid — exactly the set `ents.iter().filter(|e| shares_corroborating_source(w,
/// e))` would collect, just reached via the source index instead of a rescan.
fn anchors_for<'a>(w: &Entity, idx: &HashMap<&str, Vec<&'a Entity>>) -> Vec<&'a Entity> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut v: Vec<&Entity> = Vec::new();
    for s in w.corroborating_sources() {
        if let Some(candidates) = idx.get(s) {
            for &c in candidates {
                if seen.insert(c.uid.as_str()) {
                    v.push(c);
                }
            }
        }
    }
    v
}

/// AU-039 — a cryptocurrency wallet co-occurring with a real identity (Person or
/// Email) **in a shared collection source**: an attribution lead linking on-chain
/// funds to a person. Co-presence, not proof, so `High` (warrants attention)
/// rather than `Critical`.
///
/// Attribution requires a real co-location tie, not mere co-existence in the same
/// scan. The pre-fix rule anchored EVERY wallet to the single lexicographically-
/// smallest Person UID (else Email) across the whole confirmed set, with no check
/// that the wallet and that identity shared any evidence — so a scan carrying
/// several unrelated people (spouse / next-of-kin / stealer-log owner, all minted
/// by AU-075) reported one wallet as belonging to whichever name sorted first,
/// fabricating attribution to a bystander purely by UID order (T2.39). Instead,
/// each wallet is anchored only to identities that share a *corroborating*
/// evidence source with it (some single module surfaced both — a stealer log /
/// breach record stamps the same `source` on the owner and their wallet). Person
/// is preferred over Email as the more specific identity; when several identities
/// of the preferred kind are genuinely tied, each is reported (every pair is an
/// independent, real lead — none is arbitrarily singled out); when no identity
/// shares a source with the wallet, no attribution is emitted. The selection is a
/// pure function of the entity set (source membership + UID order), so the live
/// (HashMap-ordered) and finalise passes agree — the disjoint-set double-persist
/// the UID tie-break was added to prevent stays fixed.
///
/// Anchor lookup is index-based, not the pairwise `wallets × persons` (+
/// `wallets × emails`) rescan every anchor used to cost: each Person/Email is
/// bucketed once by its own corroborating sources (`corroborating_sources` is
/// O(evidence-count), bounded per entity), so finding a wallet's anchors is a
/// handful of `source → candidates` lookups keyed by the wallet's own sources
/// instead of a full rescan of `persons`/`emails`. Same
/// `shares_corroborating_source` semantics — a candidate surfaces here iff its
/// corroborating-source set intersects the wallet's. Measured via
/// `correlator::perf::per_rule_breakdown` as one of the two rules (the other
/// is AU-087) dominating the correlation pass's entity-count scaling.
pub(in crate::core::correlator) fn rule_au_039_wallet_identity(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    let wallets = entities_of_kind(entities, EntityKind::CryptoAddress);
    if wallets.is_empty() {
        return Vec::new();
    }
    let persons = entities_of_kind(entities, EntityKind::Person);
    let emails = entities_of_kind(entities, EntityKind::Email);

    let persons_by_source = index_by_source(&persons);
    let emails_by_source = index_by_source(&emails);

    let mut out = Vec::new();
    for w in wallets {
        // Person preferred over Email: only fall back to email anchors when no
        // person is tied to this wallet by a shared source.
        let mut tied = anchors_for(w, &persons_by_source);
        if tied.is_empty() {
            tied = anchors_for(w, &emails_by_source);
        }
        // Deterministic order for the (same-rule_id) tie-break downstream.
        tied.sort_by(|a, b| a.uid.cmp(&b.uid));
        for anchor in tied {
            out.push(Correlation::new(
                "AU-039",
                "Cryptocurrency wallet linked to identity",
                Severity::High,
                format!(
                    "Wallet {} co-occurs with identity {} in a shared source — possible attribution",
                    w.value, anchor.value
                ),
                vec![w.uid.clone(), anchor.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

/// AU-040 — a cryptocurrency wallet recovered from breach / stealer data
/// (clipboard-hijacker malware harvests these in volume). Distinct from AU-039:
/// this is about the *exposure source*, not co-located identity.
pub(in crate::core::correlator) fn rule_au_040_wallet_breach_exposure(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::CryptoAddress)
        .filter(|e| is_breach_exposed_wallet(e))
        .map(|e| {
            Correlation::new(
                "AU-040",
                "Cryptocurrency wallet exposed in breach/stealer data",
                Severity::High,
                format!("Wallet {} was recovered from leaked/stealer data", e.value),
                vec![e.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
}

/// AU-041 — an ENS reverse name resolved an EVM address to a human-chosen handle
/// (`chain_intel`): an on-chain → identity edge. `Medium` (a handle is a lead,
/// not an identity by itself).
pub(in crate::core::correlator) fn rule_au_041_ens_identity(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username && e.has_tag("ens"))
        .map(|e| {
            // The ENS name is on the entity's evidence; surface it when present.
            let ens = e
                .evidence
                .iter()
                .find_map(|ev| ev.attributes.get("ens_name").cloned())
                .unwrap_or_else(|| e.value.clone());
            Correlation::new(
                "AU-041",
                "On-chain identity via ENS",
                Severity::Medium,
                format!(
                    "ENS name {ens} ties an EVM address to the handle '{}'",
                    e.value
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
}
