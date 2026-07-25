//! AU-121 — Transitive credential-reuse blast radius.
//!
//! AU-047 links the accounts a *single* reused secret was seen against. But
//! secret reuse **chains**: secret A ties accounts {1, 2}, a *different* secret
//! B ties {2, 3}, so accounts 1 and 3 fall under one controller's takeover
//! surface even though they share no secret directly — a link no per-secret rule
//! can express, because no single secret spans the whole set. This rule computes
//! the **transitive closure** of that reuse graph (a recursive union over
//! accounts joined by any shared secret) and reports each connected component as
//! one *credential-reuse blast radius*: the full set of accounts a single
//! compromised credential in the chain cascades to.
//!
//! It reuses the correlator's one secret classifier ([`Secret::classify`], the
//! same gate AU-047 and the `SharesSecretWith` relation builder fire on) and the
//! shared [`canonical_handle`] folder, so "which secrets link" and "which
//! accounts are the same controller" can never drift from the rest of the
//! engine (Rule 4: delegate, never copy).
//!
//! Firing gate — deliberately disjoint from AU-047 so the two never
//! double-report the same finding:
//!   * the component spans **≥ 3 distinct account handles** (a real blast
//!     radius, not a pair), and
//!   * **no single secret covers the whole component** — i.e. it is genuinely
//!     transitive. A component that one secret spans end-to-end is exactly an
//!     AU-047 finding and is left to AU-047.
//!
//! Severity: **Critical** when any binding secret is unique by construction (a
//! salted hash, session token, wallet address, or API key — no coincidence
//! possible); **High** when the whole chain is bound only by reused plaintext
//! passwords (individually strong, but a shared password carries a residual
//! coincidence risk, mirroring AU-047's plaintext tier).

use super::*;

/// AU-121 — Transitive credential-reuse blast radius.
///
/// Entity-only: builds a union-find over account handles joined by any shared
/// secret (drawn from each secret's own breach-record evidence, the same
/// `email`/`username` attributes AU-047 reads), then emits one correlation per
/// transitive component of ≥3 handles that no single secret spans. `entity_uids`
/// carries every binding secret plus every in-scope `Email`/`Username` entity in
/// the component, in entity order, so the SPA Correlations view can render the
/// whole chain.
pub(in crate::core::correlator) fn rule_au_121_credential_reuse_blast_radius(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    /// A component must reach this many distinct handles to count as a blast
    /// radius (a 2-handle link is a single-secret AU-047 pair's job).
    const MIN_HANDLES: usize = 3;

    // Every linkable secret and the account handles its evidence ties together.
    // A secret contributing <2 handles cannot chain anything, so it is dropped
    // up front — the union graph only needs the edge-bearing secrets.
    struct SecretGroup<'a> {
        uid: &'a str,
        kind: Secret,
        handles: Vec<String>,
        // Raw identifiers (emails/usernames as observed) for the human summary.
        raw: Vec<String>,
    }
    let groups: Vec<SecretGroup> = entities
        .iter()
        .filter_map(|e| {
            let kind = Secret::classify(e)?;
            let mut raw: Vec<String> = Vec::new();
            let mut handles: Vec<String> = Vec::new();
            for ev in &e.evidence {
                if let Some(email) = ev.attributes.get("email") {
                    let email = email.trim().to_lowercase();
                    if email.contains('@') {
                        let handle = canonical_handle(email.split('@').next().unwrap_or(&email));
                        if !handle.is_empty() && !handles.contains(&handle) {
                            handles.push(handle);
                            raw.push(email);
                        }
                    }
                }
                if let Some(username) = ev.attributes.get("username") {
                    let username = username.trim().to_lowercase();
                    if !username.is_empty() {
                        let handle = canonical_handle(&username);
                        if !handle.is_empty() && !handles.contains(&handle) {
                            handles.push(handle);
                            raw.push(username);
                        }
                    }
                }
            }
            // Only edge-bearing secrets (≥2 handles) participate in the closure.
            (handles.len() >= 2).then_some(SecretGroup {
                uid: &e.uid,
                kind,
                handles,
                raw,
            })
        })
        .collect();
    if groups.len() < 2 {
        // A single edge-bearing secret can only produce an AU-047 finding, never
        // a transitive chain — bail before building the union graph.
        return Vec::new();
    }

    // ── Union-find over the distinct handles ──────────────────────────────────
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut handle_list: Vec<&str> = Vec::new();
    for g in &groups {
        for h in &g.handles {
            if !index.contains_key(h.as_str()) {
                index.insert(h.as_str(), handle_list.len());
                handle_list.push(h.as_str());
            }
        }
    }
    let mut uf = crate::util::union_find::UnionFind::new(handle_list.len());
    for g in &groups {
        // Union every handle in this secret's set to the first one.
        let first = index[g.handles[0].as_str()];
        for h in &g.handles[1..] {
            uf.union(first, index[h.as_str()]);
        }
    }

    // ── Aggregate per component (keyed by canonical root) ─────────────────────
    // Deterministic: BTreeMap over the component's lexicographically-smallest
    // handle, and every member set is a BTreeSet, so the output order and content
    // are input-order-independent.
    struct Component {
        handles: BTreeSet<String>,
        secret_uids: BTreeSet<String>,
        raw: BTreeSet<String>,
        // The largest single-secret handle-span in this component — the AU-047
        // reach. If it equals the component size, one secret covers everything.
        max_single_span: usize,
        critical: bool,
    }
    let mut comps: HashMap<usize, Component> = HashMap::new();
    for g in &groups {
        let root = uf.find(index[g.handles[0].as_str()]);
        // Every handle in a given secret shares one root (we just unioned them).
        let comp = comps.entry(root).or_insert_with(|| Component {
            handles: BTreeSet::new(),
            secret_uids: BTreeSet::new(),
            raw: BTreeSet::new(),
            max_single_span: 0,
            critical: false,
        });
        for h in &g.handles {
            comp.handles.insert(h.clone());
        }
        for r in &g.raw {
            comp.raw.insert(r.clone());
        }
        comp.secret_uids.insert(g.uid.to_owned());
        comp.max_single_span = comp.max_single_span.max(g.handles.len());
        // Any construction-unique secret makes the whole chain certain.
        if !matches!(g.kind, Secret::PlaintextPassword) {
            comp.critical = true;
        }
    }

    // Pre-index identity entities (Email/Username) by canonical handle so the
    // component's account entities can be named in `entity_uids`, in entity
    // order. Built once, not per component.
    let identities: Vec<(String, &str)> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Email | EntityKind::Username))
        .map(|e| {
            let raw = e.value.trim().to_lowercase();
            let base = if e.kind == EntityKind::Email {
                raw.split('@').next().unwrap_or(&raw).to_string()
            } else {
                raw
            };
            (canonical_handle(&base), e.uid.as_str())
        })
        .collect();

    // Deterministic component order: by smallest handle.
    let mut ordered: Vec<&Component> = comps.values().collect();
    ordered.sort_by(|a, b| a.handles.iter().next().cmp(&b.handles.iter().next()));

    let mut out = Vec::new();
    for comp in ordered {
        let n = comp.handles.len();
        // Blast radius AND genuinely transitive (no single secret spans it all —
        // that case is AU-047's).
        if n < MIN_HANDLES || comp.max_single_span >= n || comp.secret_uids.len() < 2 {
            continue;
        }

        // entity_uids: binding secrets + the account entities present in scope,
        // in entity order for a stable render.
        let mut uids: Vec<String> = Vec::new();
        for e in entities {
            if comp.secret_uids.contains(&e.uid) {
                uids.push(e.uid.clone());
            }
        }
        for (handle, uid) in &identities {
            if comp.handles.contains(handle) && !uids.iter().any(|u| u == uid) {
                uids.push((*uid).to_owned());
            }
        }

        let k = comp.secret_uids.len();
        let listed = comp
            .raw
            .iter()
            .take(6)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let more = comp.raw.len().saturating_sub(6);
        let suffix = if more > 0 {
            format!(", +{more} more")
        } else {
            String::new()
        };
        let severity = if comp.critical {
            Severity::Critical
        } else {
            Severity::High
        };

        out.push(Correlation::new(
            "AU-121",
            "Transitive credential-reuse blast radius",
            severity,
            format!(
                "{n} accounts chain into one credential-reuse blast radius via {k} reused \
                 secrets — no single secret spans them all, so per-secret reuse detection \
                 misses the full chain; one compromised credential cascades to every linked \
                 account: {listed}{suffix}",
            ),
            uids,
            scan_id,
            ts,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::Evidence;

    /// A secret entity whose evidence records the accounts it was seen against —
    /// the exact shape `Secret::classify` + the AU-047 join read.
    fn secret_with(kind: EntityKind, value: &str, accounts: &[(&str, &str)]) -> Entity {
        let mut e = Entity::new(kind, value, 0.9, "s");
        for (attr, who) in accounts {
            e.add_evidence(Evidence::new("breach", "leaked record").with_attr(*attr, *who));
        }
        e
    }

    // A salted hash — classified as SaltedHash (construction-unique → Critical).
    const HASH_A: &str = "$2b$12$abcdefghijklmnopqrstuv0123456789ABCDEFGHIJKLMNOPqrst";
    const HASH_B: &str = "$2b$12$ZYXWVUTSRQPONMLKJIHGFE9876543210zyxwvutsrqponmlkAAAA";

    #[test]
    fn au114_fires_on_a_transitive_chain_no_single_secret_spans() {
        // Secret A ties alice+bob; secret B ties bob+carol. alice and carol share
        // no secret, but the chain makes all three one blast radius.
        let a = secret_with(
            EntityKind::Password,
            HASH_A,
            &[("username", "alice"), ("username", "bob")],
        );
        let b = secret_with(
            EntityKind::Password,
            HASH_B,
            &[("username", "bob"), ("username", "carol")],
        );
        let out = rule_au_121_credential_reuse_blast_radius(&RuleContext::new(&[a, b]), "s", 0);
        assert_eq!(out.len(), 1, "the transitive chain must fire once");
        assert_eq!(out[0].rule_id, "AU-121");
        assert_eq!(
            out[0].severity,
            Severity::Critical,
            "a salted-hash chain is construction-unique → Critical"
        );
    }

    #[test]
    fn au114_silent_when_one_secret_spans_the_whole_set() {
        // A single secret ties all three — that is exactly an AU-047 finding, not
        // a transitive chain, so AU-121 must stay silent (no double-report).
        let a = secret_with(
            EntityKind::Password,
            HASH_A,
            &[
                ("username", "alice"),
                ("username", "bob"),
                ("username", "carol"),
            ],
        );
        assert!(
            rule_au_121_credential_reuse_blast_radius(&RuleContext::new(&[a]), "s", 0).is_empty(),
            "a single-secret span is AU-047's job, not AU-121's"
        );
    }

    #[test]
    fn au114_silent_on_a_two_account_chain() {
        // Two secrets, but only two handles total — below the blast-radius floor.
        let a = secret_with(
            EntityKind::Password,
            HASH_A,
            &[("username", "alice"), ("username", "bob")],
        );
        let b = secret_with(
            EntityKind::Password,
            HASH_B,
            &[("username", "alice"), ("username", "bob")],
        );
        assert!(
            rule_au_121_credential_reuse_blast_radius(&RuleContext::new(&[a, b]), "s", 0)
                .is_empty(),
            "two handles is a pair, not a blast radius"
        );
    }

    #[test]
    fn au114_plaintext_only_chain_is_high_not_critical() {
        // Reused plaintext passwords (strong, high-entropy) chain three accounts,
        // but carry a residual coincidence risk → High, mirroring AU-047.
        let a = secret_with(
            EntityKind::Password,
            "Tr0ub4dour&3xtra_L0ng!",
            &[("username", "alice"), ("username", "bob")],
        );
        let b = secret_with(
            EntityKind::Password,
            "c0rrect-h0rse-b4ttery-st4ple-9",
            &[("username", "bob"), ("username", "carol")],
        );
        let out = rule_au_121_credential_reuse_blast_radius(&RuleContext::new(&[a, b]), "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
    }
}
