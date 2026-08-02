//! AU correlation rules — crypto family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;
use crate::core::entity::is_enrichment_source;

/// Source record identifiers extracted from evidence attributes.
/// Used to determine if a wallet and identity come from the same breach record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

/// Buckets `ents` by their [`SourceRecord`] — dbname+email+username for a breach
/// record, chain+address for a chain-intel record — so an anchor lookup for one
/// entity is a single `record → candidates` map probe instead of a full rescan.
/// `SourceRecord::Other` (enrichment-only / unrecognised / no shared provenance)
/// is deliberately never indexed: two `Other`-classified entities must NOT be
/// treated as sharing a record just because they hash to the same key — that is
/// exactly the "random cross-module collision" this rule's own docs say must not
/// fire. Shared by [`rule_au_039_wallet_identity`]'s wallet→Person and
/// wallet→Email anchor passes.
fn index_by_source<'a>(ents: &[&'a Entity]) -> HashMap<SourceRecord, Vec<&'a Entity>> {
    let mut idx: HashMap<SourceRecord, Vec<&Entity>> = HashMap::new();
    for &e in ents {
        let rec = extract_source_record(e);
        if rec != SourceRecord::Other {
            idx.entry(rec).or_default().push(e);
        }
    }
    idx
}

/// Entities in `idx` that share `w`'s EXACT [`SourceRecord`], reached via the
/// record index instead of a rescan. `w` classifying as `SourceRecord::Other`
/// yields no anchors (an unlinked wallet has no validated attribution).
fn anchors_for<'a>(w: &Entity, idx: &HashMap<SourceRecord, Vec<&'a Entity>>) -> Vec<&'a Entity> {
    let rec = extract_source_record(w);
    if rec == SourceRecord::Other {
        return Vec::new();
    }
    idx.get(&rec).cloned().unwrap_or_default()
}

/// AU-039 — a cryptocurrency wallet co-occurring with a real identity (Person or
/// Email) that **originate from the same source record**: an attribution lead
/// linking on-chain funds to a person. Co-presence alone is NOT proof; this rule
/// applies validated linkage only — both wallet and identity must originate from
/// the same source record within a breach/stealer dump (shared dbname + email +
/// username for breach modules, or shared chain for chain_intel), so `High`
/// (warrants attention) rather than `Critical`.
///
/// Attribution requires a real co-location tie, not mere co-existence in the same
/// scan. The pre-fix rule anchored EVERY wallet to the single lexicographically-
/// smallest Person UID (else Email) across the whole confirmed set, with no check
/// that the wallet and that identity shared any evidence — so a scan carrying
/// several unrelated people (spouse / next-of-kin / stealer-log owner, all minted
/// by AU-075) reported one wallet as belonging to whichever name sorted first,
/// fabricating attribution to a bystander purely by UID order (T2.39). Instead,
/// each wallet is anchored only to identities that share its EXACT [`SourceRecord`]
/// — not merely the same collecting module: two different breach dumps
/// oathnet_pro happens to have surfaced are
/// NOT "the same source" and must not cross-attribute). Person is preferred over
/// Email as the more specific identity; when several identities of the preferred
/// kind are genuinely tied, each is reported (every pair is an independent, real
/// lead — none is arbitrarily singled out); when no identity shares the wallet's
/// exact record, no attribution is emitted. The selection is a pure function of
/// the entity set (record membership + UID order), so the live (HashMap-ordered)
/// and finalise passes agree.
///
/// Anchor lookup is index-based, not the pairwise `wallets × persons` (+
/// `wallets × emails`) rescan every anchor used to cost: each Person/Email is
/// bucketed once by its own [`SourceRecord`] (O(evidence-count), bounded per
/// entity), so finding a wallet's anchors is a single `record → candidates`
/// lookup instead of a full rescan of `persons`/`emails`. Measured via
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
    for wallet in wallets {
        // Person preferred over Email: only fall back to email anchors when no
        // person is tied to this wallet by its exact source record.
        let mut tied = anchors_for(wallet, &persons_by_source);
        if tied.is_empty() {
            tied = anchors_for(wallet, &emails_by_source);
        }
        // Deterministic order for the (same-rule_id) tie-break downstream.
        tied.sort_by(|a, b| a.uid.cmp(&b.uid));
        for anchor in tied {
            out.push(Correlation::new(
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
