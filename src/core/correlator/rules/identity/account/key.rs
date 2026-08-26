//! Cryptographic-key identity rules — shared public keys and PGP/email binding.
//! Split from `account.rs`; rules re-exported by `super`.

use super::super::*;

/// AU-048 — Shared public key links accounts (cryptographic proof of control).
///
/// The strongest cross-account link in the engine. A public key (SSH or PGP)
/// published on two accounts proves the **same person holds the matching private
/// key** — stronger than password reuse, because there is no plaintext two
/// unrelated people could coincidentally share. When one key-tagged Credential
/// (fingerprinted by `github_user`/keyserver modules so the same key folds to one
/// uid) carries ≥2 distinct producing accounts in its evidence, those accounts
/// are one controller. Exactly the seam that links a target's rotated/burner
/// handles when they didn't regenerate their key. Critical.
pub(in crate::core::correlator) fn rule_au_048_shared_public_key(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::BTreeSet;
    // Cheap precondition: with no key-tagged credential present, no link can
    // fire — bail before building the identity index.
    let has_shared_key = entities.iter().any(|e| {
        e.kind == EntityKind::Credential && (e.has_tag("ssh-key") || e.has_tag("pgp-key"))
    });
    if !has_shared_key {
        return Vec::new();
    }
    // Pre-lowercase the Username/Email index ONCE. The previous form
    // re-lowercased every account entity's value for every shared key (an
    // O(keys×accounts) allocation storm); building it a single time turns the
    // per-key linking into plain set membership. Entity iteration order is
    // preserved, so the emitted uid order is identical to before.
    let id_index: Vec<(String, &str)> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Username | EntityKind::Email))
        .map(|e| (e.value.trim().to_lowercase(), e.uid.as_str()))
        .collect();

    let mut out = Vec::new();
    for key in entities.iter().filter(|e| {
        e.kind == EntityKind::Credential && (e.has_tag("ssh-key") || e.has_tag("pgp-key"))
    }) {
        // Distinct accounts that published this exact key, from the evidence the
        // key-emitting modules attach (a github login, username, or email).
        let accounts: BTreeSet<String> = key
            .evidence
            .iter()
            .flat_map(|ev| {
                ["github_login", "username", "email"]
                    .iter()
                    .filter_map(|k| ev.attributes.get(*k))
            })
            .map(|v| v.trim().to_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
        if accounts.len() < 2 {
            continue;
        }
        // Distinct CONTROLLER accounts, not just distinct identifier spellings.
        // The attrs mix identifier types (login / username / email). A single
        // account whose key evidence carries BOTH its login and its email
        // ("alice" + "alice@x.com") is two strings but ONE account, so firing a
        // Critical "controls 2 accounts" on it would be a false positive.
        //
        // But two GENUINELY distinct accounts that merely share an email
        // local-part across different domains ("john@gmail.com" + "john@acme.com")
        // are exactly the rotated/burner seam this rule exists to expose, and
        // MUST still fire. The previous fold reduced every identifier — full
        // emails included — to its bare local-part, so it silently collapsed
        // those two accounts and dropped the Critical link (cryptographic proof
        // of common control, thrown away).
        //
        // So: a full email keeps its `local@domain` identity; a bare login is a
        // SEPARATE account only when its canonical handle matches NO email's
        // local-part (otherwise it is that email's own login). Genuinely distinct
        // handles ("ghost91" + "jsmith_work", "@alice" + "bob@x.com") still fire.
        let mut emails: BTreeSet<&str> = BTreeSet::new();
        let mut logins: BTreeSet<String> = BTreeSet::new();
        for a in &accounts {
            match a.split_once('@') {
                Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
                    emails.insert(a.as_str());
                }
                _ => {
                    logins.insert(canonical_handle(a.trim_start_matches('@')));
                }
            }
        }
        let email_locals: BTreeSet<String> = emails
            .iter()
            .filter_map(|e| e.split('@').next())
            .map(canonical_handle)
            .collect();
        let distinct_logins = logins.iter().filter(|l| !email_locals.contains(*l)).count();
        let account_keys = emails.len() + distinct_logins;
        if account_keys < 2 {
            continue;
        }
        let mut uids = vec![key.uid.clone()];
        for (value_lc, uid) in &id_index {
            if accounts.contains(value_lc) {
                uids.push((*uid).to_owned());
            }
        }
        out.push(Correlation {
            rule_id: "AU-048".into(),
            rule_name: "Shared public key links accounts".into(),
            severity: Severity::Critical,
            description: format!(
                "A reused public key proves one person controls {} accounts (same private key) \
                 — key evidence names: {}",
                // Count DISTINCT controller accounts, not identifier spellings: the
                // guard above already treats "alice" + "alice@x.com" as ONE account,
                // so reporting `accounts.len()` here would over-state control (e.g.
                // "3 accounts" for alice's login+email plus bob, who are 2 owners).
                account_keys,
                join_capped(accounts.iter().map(String::as_str), 6)
            ),
            entity_uids: uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        });
    }
    out
}

/// AU-042 — two or more email addresses bound to the **same** PGP key (`pgp`
/// module): strong same-owner evidence (the key holder asserted these are theirs).
/// `High`. One firing PER KEY, over the emails that key binds.
///
/// Partitioned by the key fingerprint each `pgp-linked` email carries (the
/// `key_fingerprint` evidence attribute the `pgp` module attaches): emails bound
/// to DIFFERENT keys are separate assertions — possibly different people — so they
/// must never be fused into one owner, and a key binding only ONE address is not
/// multi-email evidence, so it does not fire (the rule's "two or more" contract).
/// An email with no fingerprint can't be attributed to a key and is excluded.
pub(in crate::core::correlator) fn rule_au_042_pgp_email_identity(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::{BTreeMap, BTreeSet};
    // fingerprint -> (address -> emitting uid). BTreeMaps keep the output
    // deterministic (fingerprint order, then address order) with no HashMap leak.
    let mut by_key: BTreeMap<&str, BTreeMap<&str, String>> = BTreeMap::new();
    for e in entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email && e.has_tag("pgp-linked"))
    {
        // An email merged from several keyserver hits can carry more than one
        // fingerprint; it legitimately belongs to each key that bound it.
        let fingerprints: BTreeSet<&str> = e
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("key_fingerprint").map(String::as_str))
            .filter(|f| !f.is_empty())
            .collect();
        for fpr in fingerprints {
            by_key
                .entry(fpr)
                .or_default()
                .entry(e.value.as_str())
                .or_insert_with(|| e.uid.clone());
        }
    }

    by_key
        .into_iter()
        .filter(|(_, addrs)| addrs.len() >= 2)
        .map(|(fpr, addrs)| {
            let addr_list: Vec<&str> = addrs.keys().copied().collect();
            let uids: Vec<String> = addrs.values().cloned().collect();
            Correlation::new(
                "AU-042",
                "PGP key binds multiple emails to one identity",
                Severity::High,
                format!(
                    "PGP key {fpr} links {} email address(es) to one owner: {}",
                    addr_list.len(),
                    addr_list.join(", ")
                ),
                uids,
                scan_id,
                ts,
            )
        })
        .collect()
}
