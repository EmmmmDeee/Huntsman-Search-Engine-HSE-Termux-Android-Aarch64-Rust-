//! AU correlation rules — crypto family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

/// AU-039 — a cryptocurrency wallet co-occurring with a real identity (Person or
/// Email) in the same confirmed scan: an attribution lead linking on-chain funds
/// to a person. Co-presence, not proof, so `High` (warrants attention) rather
/// than `Critical`. One firing per wallet, anchored to the most specific
/// identity present (Person preferred over Email).
pub(in crate::core::correlator) fn rule_au_039_wallet_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let wallets = entities_of_kind(entities, EntityKind::CryptoAddress);
    if wallets.is_empty() {
        return Vec::new();
    }
    // Single pass for the anchor: track the best (Person preferred over Email)
    // candidate seen so far instead of scanning the entity list once for each
    // kind. A Person found at any point wins outright and ends the search.
    let mut anchor: Option<&Entity> = None;
    for e in entities {
        if e.kind == EntityKind::Person {
            anchor = Some(e);
            break;
        }
        if anchor.is_none() && e.kind == EntityKind::Email {
            anchor = Some(e);
        }
    }
    let Some(anchor) = anchor else {
        return Vec::new();
    };
    wallets
        .into_iter()
        .map(|w| {
            Correlation::new(
                "AU-039",
                "Cryptocurrency wallet linked to identity",
                Severity::High,
                format!(
                    "Wallet {} co-occurs with identity {} — possible attribution",
                    w.value, anchor.value
                ),
                vec![w.uid.clone(), anchor.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
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
