//! AU correlation rules — crypto family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;
use crate::core::entity::is_enrichment_source;

/// Source record identifiers extracted from evidence attributes.
/// Used to determine if a wallet and identity come from the same breach record.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceRecord {
    /// Breach record (oathnet_pro, see_know): identified by (dbname, email, username)
    BreachRecord {
        dbname: String,
        email: String,
        username: String,
    },
    /// Chain intelligence record: identified by (chain, address)
    ChainRecord { chain: String, address: String },
    /// Enrichment or non-matching source (intelx, chain_intel enrichment, etc.)
    Other,
}

/// Extract source record identifiers from an entity's evidence.
/// Returns the record identifier if the entity comes from a known breach record type,
/// or `None` if it's enrichment-only, aggregator, or unrecognized.
fn extract_source_record(entity: &Entity) -> SourceRecord {
    for ev in &entity.evidence {
        match ev.source.as_str() {
            // Breach modules: use (dbname, email, username) as the record identifier
            "oathnet_pro" | "see_know" => {
                if let (Some(dbname), Some(email), Some(username)) = (
                    ev.attributes.get("dbname"),
                    ev.attributes.get("email"),
                    ev.attributes.get("username"),
                ) {
                    return SourceRecord::BreachRecord {
                        dbname: dbname.clone(),
                        email: email.clone(),
                        username: username.clone(),
                    };
                }
            }
            // Chain intelligence: use (chain, address) as the record identifier
            "chain_intel" => {
                if let (Some(chain), Some(address)) =
                    (ev.attributes.get("chain"), ev.attributes.get("address"))
                {
                    return SourceRecord::ChainRecord {
                        chain: chain.clone(),
                        address: address.clone(),
                    };
                }
            }
            // intelx is explicitly rejected (re-emission only, no shared record)
            "intelx" => return SourceRecord::Other,
            // Enrichment-only sources don't carry record markers
            _ if is_enrichment_source(ev.source.as_str()) => continue,
            _ => {}
        }
    }
    SourceRecord::Other
}

/// Check if a wallet and an identity come from the same source record.
/// This validates the "relatedness criterion" — both must originate from the same
/// breach/stealer dump record (same dbname + email + username) or the same
/// chain-intelligence lookup.
fn is_same_source_record(wallet: &Entity, identity: &Entity) -> bool {
    let wallet_record = extract_source_record(wallet);
    let identity_record = extract_source_record(identity);

    match (&wallet_record, &identity_record) {
        // Both from same breach record: dbname, email, and username must match
        (
            SourceRecord::BreachRecord {
                dbname: w_db,
                email: w_email,
                username: w_user,
            },
            SourceRecord::BreachRecord {
                dbname: i_db,
                email: i_email,
                username: i_user,
            },
        ) => w_db == i_db && w_email == i_email && w_user == i_user,

        // Both from same chain record: chain and address must match
        (
            SourceRecord::ChainRecord {
                chain: w_chain,
                address: w_addr,
            },
            SourceRecord::ChainRecord {
                chain: i_chain,
                address: i_addr,
            },
        ) => w_chain == i_chain && w_addr == i_addr,

        // All other combinations (mixed sources, enrichment-only, intelx) = unrelated
        _ => false,
    }
}

/// AU-039 — a cryptocurrency wallet co-occurring with a real identity (Person or
/// Email) in the same confirmed scan: an attribution lead linking on-chain funds
/// to a person. Co-presence alone is NOT proof; this rule applies **validated
/// linkage only** — both wallet and identity must originate from the same source
/// record within a breach/stealer dump (shared dbname + email + username for breach
/// modules, or shared chain for chain_intel). This filters out random cross-module
/// collisions that pass the co-presence gate but have no shared provenance.
///
/// Severity: `High` for validated same-record attribution. Unlinked co-occurrences
/// (wallet and identity from different sources, or enrichment-only) do not fire
/// (or fire as a lower-severity `AU-039b` co-presence lead in future revisions).
///
/// One firing per wallet, anchored to the most specific identity present
/// (Person preferred over Email) that shares the same source record.
pub(in crate::core::correlator) fn rule_au_039_wallet_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let wallets = entities_of_kind(entities, EntityKind::CryptoAddress);
    if wallets.is_empty() {
        return Vec::new();
    }

    let mut correlations = Vec::new();

    for wallet in wallets {
        // Find the best anchor (Person or Email) that shares the same source record
        // as the wallet. Prefer Person over Email; among the same kind, prefer the
        // lexicographically smallest UID for determinism.
        let anchor = entities
            .iter()
            .filter(|e| e.kind == EntityKind::Person && is_same_source_record(wallet, e))
            .min_by(|a, b| a.uid.cmp(&b.uid))
            .or_else(|| {
                entities
                    .iter()
                    .filter(|e| e.kind == EntityKind::Email && is_same_source_record(wallet, e))
                    .min_by(|a, b| a.uid.cmp(&b.uid))
            });

        // Only fire if we found a related identity from the same source record.
        if let Some(anchor) = anchor {
            correlations.push(Correlation::new(
                "AU-039",
                "Cryptocurrency wallet linked to identity",
                Severity::High,
                format!(
                    "Wallet {} and identity {} originate from the same source record — \
                     validated attribution",
                    wallet.value, anchor.value
                ),
                vec![wallet.uid.clone(), anchor.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }

    correlations
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
