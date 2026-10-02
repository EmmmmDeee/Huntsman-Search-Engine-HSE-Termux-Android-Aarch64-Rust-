//! AU-116 — Transitive infrastructure closure.
//!
//! AU-109 (shared registrant), AU-110 (shared hosting IP) and AU-112 (shared
//! CIDR block) each capture a SINGLE-hop infrastructure fact: two domains on one
//! IP, or two IPs in one block. But infrastructure pivots CHAIN — domain A
//! resolves to IP1, IP1 also hosts domain B, and B resolves to IP2 which hosts
//! domain C. A and C share neither an IP nor a registrant directly, yet they sit
//! in one hosting footprint reached by walking the graph. This is the
//! infrastructure analogue of AU-060's transitive *identity* closure, and it is
//! exactly the multi-hop netblock pivot SpiderFoot's infrastructure modules are
//! built around.
//!
//! This rule computes the connected components of the infrastructure graph (a
//! recursive union over `ResolvesTo` / `HostedOn` / `SubdomainOf` /
//! `BelongsToDomain` edges among `Domain` / `IpAddress` nodes) and reports a
//! component that spans **≥3 distinct registrable domains** connected through
//! **≥2 distinct IP nodes** — a genuine multi-server chain, not a single shared
//! host (that is AU-110's case, and is deliberately left to it).
//!
//! False-positive control — the standing trap for shared-hosting rules is a CDN
//! / cloud edge that co-hosts millions of unrelated sites:
//!   * any IP carrying an authoritative known-benign-infrastructure verdict
//!     (`is_benign_infra` — GreyNoise RIOT / benign, the same veto the threat
//!     rules use) is NOT traversed, so a Cloudflare/Fastly anycast address can
//!     never fuse unrelated domains into a phantom footprint;
//!   * domains fold to their registrable form ([`registrable_domain`]) before
//!     the ≥3-distinct-owner count, so `a.example.com` / `b.example.com` (one
//!     owner's subdomains) do not inflate the domain spread.
//!
//! Severity **Medium**: a shared multi-server footprint is a strong attribution
//! lead (common operator / same tenant), not a compromise on its own.

use super::*;
use crate::util::domains::registrable_domain;

/// AU-116 — Transitive infrastructure closure.
///
/// Graph-aware: unions `Domain`/`IpAddress` nodes over the infrastructure edge
/// kinds (skipping any benign-CDN IP), then emits one correlation per component
/// of ≥3 registrable domains bound through ≥2 IP nodes. `entity_uids` carries
/// every domain and IP in the footprint, in entity order.
pub(in crate::core::correlator) fn rule_au_116_infrastructure_pivot_closure(
    context: &RuleContext,
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    /// Weakest edge confidence that still counts as a real infrastructure link
    /// (mirrors the Probable floor the identity-graph rules resolve under).
    const MIN_CONF: f64 = crate::core::relation::IDENTITY_LINK_MIN_CONF;
    const MIN_DOMAINS: usize = 3;
    const MIN_IPS: usize = 2;

    // Infra nodes: Domain + IpAddress, indexed by uid. A benign-CDN IP is
    // recorded but never traversed (see below), so it can't bridge domains.
    use std::collections::{BTreeSet, HashMap};
    let mut node_ix: HashMap<&str, usize> = HashMap::new();
    let mut nodes: Vec<&Entity> = Vec::new();
    let mut benign_ip: Vec<bool> = Vec::new();
    for e in entities {
        if matches!(e.kind, EntityKind::Domain | EntityKind::IpAddress) {
            node_ix.insert(e.uid.as_str(), nodes.len());
            benign_ip.push(e.kind == EntityKind::IpAddress && is_benign_infra(e));
            nodes.push(e);
        }
    }
    if nodes.len() < MIN_DOMAINS + MIN_IPS {
        return Vec::new();
    }

    // Union-find over the infra nodes — the canonical disjoint-set primitive.
    let mut uf = crate::util::union_find::UnionFind::new(nodes.len());
    for r in relations {
        if r.confidence < MIN_CONF {
            continue;
        }
        if !matches!(
            r.kind,
            RelationKind::ResolvesTo
                | RelationKind::HostedOn
                | RelationKind::SubdomainOf
                | RelationKind::BelongsToDomain
        ) {
            continue;
        }
        let (Some(&a), Some(&b)) = (
            node_ix.get(r.from_uid.as_str()),
            node_ix.get(r.to_uid.as_str()),
        ) else {
            continue;
        };
        // Never traverse a benign-CDN IP — a shared anycast edge is not an
        // ownership link and would fuse unrelated domains.
        if benign_ip[a] || benign_ip[b] {
            continue;
        }
        uf.union(a, b);
    }

    // Aggregate per component. Deterministic: BTreeSet members + BTreeMap keyed
    // by the component's smallest registrable domain.
    struct Comp {
        domains: BTreeSet<String>, // registrable forms — the distinct-owner count
        node_uids: BTreeSet<String>,
        ip_count: usize,
        ip_seen: BTreeSet<String>,
    }
    let mut comps: HashMap<usize, Comp> = HashMap::new();
    for (i, e) in nodes.iter().enumerate() {
        let root = uf.find(i);
        let comp = comps.entry(root).or_insert_with(|| Comp {
            domains: BTreeSet::new(),
            node_uids: BTreeSet::new(),
            ip_count: 0,
            ip_seen: BTreeSet::new(),
        });
        comp.node_uids.insert(e.uid.clone());
        match e.kind {
            EntityKind::Domain => {
                if let Some(reg) = registrable_domain(e.value.trim()) {
                    comp.domains.insert(reg);
                }
            }
            EntityKind::IpAddress => {
                // Count each distinct IP once. `insert` returns false for a
                // duplicate, so `usize::from(bool)` adds 1 only on first sight —
                // keeping the dedup side effect without a nested `if` (which
                // newer clippy flags as collapsible into a side-effecting guard).
                comp.ip_count += usize::from(comp.ip_seen.insert(e.value.trim().to_lowercase()));
            }
            _ => {}
        }
    }

    // Keep only qualifying components — ≥3 distinct owners AND ≥2 IP nodes → a
    // genuine multi-server chain, not a single shared host (AU-110's job) —
    // BEFORE sorting, so the sort never touches the many single-node (0-domain)
    // components a large graph produces.
    let mut ordered: Vec<&Comp> = comps
        .values()
        .filter(|c| c.domains.len() >= MIN_DOMAINS && c.ip_count >= MIN_IPS)
        .collect();
    ordered.sort_by(|a, b| a.domains.iter().next().cmp(&b.domains.iter().next()));

    let mut out = Vec::new();
    for comp in ordered {
        let d = comp.domains.len();
        // entity_uids in entity order for a stable render.
        let uids: Vec<String> = entities
            .iter()
            .filter(|e| comp.node_uids.contains(&e.uid))
            .map(|e| e.uid.clone())
            .collect();

        let listed = comp
            .domains
            .iter()
            .take(6)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let more = comp.domains.len().saturating_sub(6);
        let suffix = if more > 0 {
            format!(", +{more} more")
        } else {
            String::new()
        };

        out.push(Correlation::new(
            "AU-116",
            "Transitive infrastructure closure",
            Severity::Medium,
            format!(
                "{d} registrable domains sit in one hosting footprint chained through {} IP \
                 addresses — reachable only by walking the infrastructure graph (no single shared \
                 host connects them all), a multi-server pivot a single-hop rule cannot see: \
                 {listed}{suffix}",
                comp.ip_count,
            ),
            uids,
            scan_id,
            now,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;
    use crate::core::relation::{Relation, RelationKind};

    fn dom(v: &str) -> Entity {
        Entity::new(EntityKind::Domain, v, confidence::HIGH_PLUSPLUS, "s")
    }
    fn ip(v: &str) -> Entity {
        Entity::new(EntityKind::IpAddress, v, confidence::HIGH_PLUSPLUS, "s")
    }
    fn edge(from: &Entity, to: &Entity, kind: RelationKind) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    }

    #[test]
    fn au116_fires_on_a_multi_server_chain_no_single_host_connects() {
        // a.com → IP1 ← b.com → IP2 ← c.com. a.com and c.com share no IP, but
        // the chain binds all three into one footprint through two IP nodes.
        let a = dom("a.com");
        let b = dom("b.com");
        let c = dom("c.com");
        let ip1 = ip("203.0.113.1");
        let ip2 = ip("203.0.113.2");
        let rels = [
            edge(&a, &ip1, RelationKind::ResolvesTo),
            edge(&b, &ip1, RelationKind::ResolvesTo),
            edge(&b, &ip2, RelationKind::ResolvesTo),
            edge(&c, &ip2, RelationKind::ResolvesTo),
        ];
        let ents = [a, b, c, ip1, ip2];
        let out = rule_au_116_infrastructure_pivot_closure(&RuleContext::new(&ents), &rels, "s", 0);
        assert_eq!(out.len(), 1, "the transitive chain must fire once");
        assert_eq!(out[0].rule_id, "AU-116");
        assert_eq!(out[0].severity, Severity::Medium);
    }

    #[test]
    fn au116_silent_on_a_single_shared_host() {
        // Three domains all on ONE IP — that is AU-110's single-hub case (one IP
        // node), so AU-116 (which needs ≥2 IP connectors) stays silent.
        let a = dom("a.com");
        let b = dom("b.com");
        let c = dom("c.com");
        let ip1 = ip("203.0.113.1");
        let rels = [
            edge(&a, &ip1, RelationKind::ResolvesTo),
            edge(&b, &ip1, RelationKind::ResolvesTo),
            edge(&c, &ip1, RelationKind::ResolvesTo),
        ];
        assert!(
            rule_au_116_infrastructure_pivot_closure(
                &RuleContext::new(&[a, b, c, ip1]),
                &rels,
                "s",
                0
            )
            .is_empty(),
            "a single shared host is AU-110's job, not a transitive chain"
        );
    }

    #[test]
    fn au116_does_not_traverse_a_benign_cdn_ip() {
        // The bridging IP is a benign CDN edge (GreyNoise RIOT) — it must not
        // fuse the two otherwise-unrelated domains into a phantom footprint.
        let a = dom("a.com");
        let b = dom("b.com");
        let c = dom("c.com");
        let mut cdn = ip("203.0.113.9");
        cdn.tag("greynoise-riot");
        let ip2 = ip("203.0.113.2");
        let rels = [
            edge(&a, &cdn, RelationKind::ResolvesTo),
            edge(&b, &cdn, RelationKind::ResolvesTo),
            edge(&c, &cdn, RelationKind::ResolvesTo),
            edge(&c, &ip2, RelationKind::ResolvesTo),
        ];
        assert!(
            rule_au_116_infrastructure_pivot_closure(
                &RuleContext::new(&[a, b, c, cdn, ip2]),
                &rels,
                "s",
                0
            )
            .is_empty(),
            "a benign CDN IP must never bridge domains"
        );
    }

    #[test]
    fn au116_folds_subdomains_to_one_owner() {
        // a.example.com / b.example.com / c.example.com across two IPs are ONE
        // registrable owner (example.com) — below the ≥3-distinct-owner floor.
        let a = dom("a.example.com");
        let b = dom("b.example.com");
        let c = dom("c.example.com");
        let ip1 = ip("203.0.113.1");
        let ip2 = ip("203.0.113.2");
        let rels = [
            edge(&a, &ip1, RelationKind::ResolvesTo),
            edge(&b, &ip1, RelationKind::ResolvesTo),
            edge(&b, &ip2, RelationKind::ResolvesTo),
            edge(&c, &ip2, RelationKind::ResolvesTo),
        ];
        assert!(
            rule_au_116_infrastructure_pivot_closure(
                &RuleContext::new(&[a, b, c, ip1, ip2]),
                &rels,
                "s",
                0
            )
            .is_empty(),
            "one owner's subdomains are not a multi-owner footprint"
        );
    }
}
