//! AU correlation rules — crypto family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

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
pub(in crate::core::correlator) fn rule_au_039_wallet_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let wallets = entities_of_kind(entities, EntityKind::CryptoAddress);
    if wallets.is_empty() {
        return Vec::new();
    }
    let persons = entities_of_kind(entities, EntityKind::Person);
    let emails = entities_of_kind(entities, EntityKind::Email);

    let mut out = Vec::new();
    for w in wallets {
        // Person preferred over Email: only fall back to email anchors when no
        // person is tied to this wallet by a shared source.
        let mut tied: Vec<&Entity> = persons
            .iter()
            .copied()
            .filter(|p| shares_corroborating_source(w, p))
            .collect();
        if tied.is_empty() {
            tied = emails
                .iter()
                .copied()
                .filter(|e| shares_corroborating_source(w, e))
                .collect();
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
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
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
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
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
