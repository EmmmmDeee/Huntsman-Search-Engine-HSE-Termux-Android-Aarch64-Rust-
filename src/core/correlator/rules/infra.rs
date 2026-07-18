//! AU correlation rules — infra family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

pub(in crate::core::correlator) fn rule_au_004_malicious_infrastructure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                EntityKind::Domain | EntityKind::IpAddress | EntityKind::Url
            )
        })
        // A GreyNoise RIOT/benign verdict vetoes a `malicious` tag picked up on
        // the same (shared-edge) IP from a weaker source. Require at least two
        // independent corroborating sources — a single-source `malicious` tag is
        // insufficient evidence for CRITICAL severity (shared infra like CDN/ESP
        // nodes routinely appear in one blocklist without being subject-owned).
        .filter(|e| {
            e.has_tag(crate::core::tags::MALICIOUS) && !is_benign_infra(e) && e.source_count() >= 2
        })
        .map(|e| Correlation {
            rule_id: "AU-004".into(),
            rule_name: "Malicious infrastructure".into(),
            severity: Severity::Critical,
            description: format!(
                "{} '{}' flagged malicious by blocklist sources",
                e.kind, e.value
            ),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_005_anonymous_network(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const ANON_TAGS: &[&str] = &["tor-exit", "tor", "anonymous-network", "anonymous-vpn"];
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        // Collect the matching tags once and gate on non-emptiness, instead of
        // scanning ANON_TAGS for `.any()` and then a second time to build `hits`.
        .filter_map(|e| {
            let hits: Vec<&str> = ANON_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            if hits.is_empty() {
                return None;
            }
            Some(Correlation {
                rule_id: "AU-005".into(),
                rule_name: "Anonymous-network exit".into(),
                severity: Severity::High,
                description: format!(
                    "IP {} is an anonymous-network exit ({})",
                    e.value,
                    hits.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            })
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_006_proxy_vpn(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const ANON_TAGS: &[&str] = &["tor-exit", "tor", "anonymous-network", "anonymous-vpn"];
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        // Resolve the proxy/vpn tag presence once and reuse it for both the gate
        // and the `hits` label, rather than re-checking each tag twice.
        .filter_map(|e| {
            let proxy = e.has_tag("proxy");
            let vpn = e.has_tag("vpn");
            if !(proxy || vpn) || ANON_TAGS.iter().any(|t| e.has_tag(t)) {
                return None;
            }
            let mut hits: Vec<&str> = Vec::new();
            if proxy {
                hits.push("proxy");
            }
            if vpn {
                hits.push("vpn");
            }
            Some(Correlation {
                rule_id: "AU-006".into(),
                rule_name: "Proxy/VPN-fronted IP".into(),
                severity: Severity::Medium,
                description: format!("IP {} is fronted by {}", e.value, hits.join(" + ")),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            })
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_007_high_risk_reputation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const RISK_TAGS: &[&str] = &[
        "high-risk",
        "high-risk-inbound",
        "high-risk-outbound",
        "recent-abuse",
        "scanner",
    ];
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        // Build the matching-tag list once; gate on non-emptiness instead of a
        // separate `.any()` pre-scan.
        .filter_map(|e| {
            let hits: Vec<&str> = RISK_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            if hits.is_empty() {
                return None;
            }
            Some(Correlation {
                rule_id: "AU-007".into(),
                rule_name: "High-risk IP reputation".into(),
                severity: Severity::High,
                description: format!(
                    "IP {} has high-risk reputation signals: {}",
                    e.value,
                    hits.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            })
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_008_exposed_service(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const EXPOSURE_TAGS: &[&str] = &[crate::core::tags::VULNERABLE, "ssh-exposed", "leak"];
    entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Domain | EntityKind::IpAddress))
        // GreyNoise RIOT/benign exonerates a shared CDN/cloud edge that a CVE
        // scanner tagged `vulnerable` — don't report it as an exposed service.
        .filter(|e| EXPOSURE_TAGS.iter().any(|t| e.has_tag(t)) && !is_benign_infra(e))
        .map(|e| {
            let hits: Vec<&str> = EXPOSURE_TAGS
                .iter()
                .copied()
                .filter(|t| e.has_tag(t))
                .collect();
            Correlation {
                rule_id: "AU-008".into(),
                rule_name: "Exposed service".into(),
                severity: Severity::High,
                description: format!(
                    "{} '{}' exposes service signals: {}",
                    e.kind,
                    e.value,
                    hits.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_010_infra_consensus(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Domain | EntityKind::IpAddress))
    {
        // INDEPENDENT sources only: `recall` (a replay of a prior scan's same
        // observation) and the deterministic enrichment passes are not new
        // sightings, so they must not manufacture an "infrastructure consensus".
        // A live person-scan surfaced 265 AU-010 firings on CDN/provider edge IPs
        // "confirmed by dns_intel, doh_resolver, recall" — 2 resolvers + 1 replay,
        // which `corroborating_sources` (the same set `c_effective` counts) drops
        // below the 3-source bar, retiring the bulk of the infrastructure noise.
        let sources = e.corroborating_sources();
        if sources.len() >= 3 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            out.push(Correlation {
                rule_id: "AU-010".into(),
                rule_name: "Infrastructure consensus".into(),
                severity: Severity::Medium,
                description: format!(
                    "{} '{}' confirmed by {} infrastructure sources: {}",
                    e.kind,
                    e.value,
                    names.len(),
                    names.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }
    out
}

pub(in crate::core::correlator) fn rule_au_015_threat_intel_hit(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const TI_SOURCES: &[&str] = &["ip_reputation", "threatfox"];

    entities
        .iter()
        // A GreyNoise RIOT/benign IP that a reputation feed also flagged is a
        // shared-edge false positive — exonerate it.
        .filter(|e| e.has_tag(crate::core::tags::THREAT_INTEL) && !is_benign_infra(e))
        .map(|e| {
            let sources: std::collections::BTreeSet<&str> = e
                .evidence
                .iter()
                .map(|ev| ev.source.as_str())
                .filter(|s| TI_SOURCES.contains(s))
                .collect();
            let attribution = if sources.is_empty() {
                "a curated threat-intel feed".to_string()
            } else {
                sources.into_iter().collect::<Vec<_>>().join(" + ")
            };
            let ti_hints: Vec<&str> = e
                .tags
                .iter()
                .filter_map(|t| t.strip_prefix("ti:"))
                .collect();
            let detail = if ti_hints.is_empty() {
                String::new()
            } else {
                format!(": {}", ti_hints.join(", "))
            };
            Correlation {
                rule_id: "AU-015".into(),
                rule_name: "Threat-intel hit".into(),
                severity: Severity::High,
                description: format!("{} '{}' present in {attribution}{detail}", e.kind, e.value),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_028_subdomain_takeover_risk(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.has_tag("subdomain-takeover"))
        .map(|e| {
            Correlation::new(
                "AU-028",
                "Subdomain takeover vulnerability",
                Severity::Critical,
                format!(
                    "Domain '{}' has a dangling CNAME vulnerable to takeover",
                    e.value
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_029_cloud_storage_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let exposed: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.has_tag("cloud-storage") && e.has_tag(crate::core::tags::VULNERABLE))
        .collect();
    if exposed.is_empty() {
        return Vec::new();
    }
    let uids: Vec<String> = exposed.iter().map(|e| e.uid.clone()).collect();
    vec![Correlation::new(
        "AU-029",
        "Exposed cloud storage",
        Severity::Critical,
        format!(
            "{} publicly accessible cloud storage bucket(s) discovered",
            exposed.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-031 — Malicious adjacency (graph-aware). Surfaces a *benign* entity that
/// is one relation-edge away from a known-bad entity (tagged malicious /
/// threat-intel / vulnerable): a subdomain of a malicious apex, an entity
/// derived from a flagged node during expansion, or coordinates co-located with
/// bad infra.
///
/// **Ground-truth veto, then fan-out backstop.** Most "shared infrastructure"
/// is identified explicitly in the data — a CDN/cloud edge IP carries a GreyNoise
/// RIOT/benign verdict ([`is_benign_infra`]) — so such a node is never treated as
/// bad here, and an adjacency explosion (a real scan produced 792 rows from four
/// shared parents) cannot start. For shared infra that LACKS such a verdict
/// (e.g. a flagged ESP/mail *domain*), a fan-out backstop applies: a bad node
/// with more than `FANOUT_CAP` distinct benign neighbours collapses to ONE
/// aggregated finding (Medium, or High when the reason is `malicious` — a
/// genuine large malicious cluster stays loud) instead of N rows; dedicated
/// infra (≤ cap) still fires per-neighbour at High. Edges between two
/// already-flagged nodes are left to AU-004/AU-008/AU-015. Deterministic
/// (BTreeMap-ordered).
pub(in crate::core::correlator) fn rule_au_031_malicious_adjacency(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use crate::core::relation::RelationKind;
    use std::collections::{BTreeMap, HashMap};

    /// A flagged node with more than this many distinct benign neighbours is
    /// shared hosting/CDN/ESP: emit one aggregate, not one row per neighbour.
    const FANOUT_CAP: usize = 8;
    /// Benign uids to carry on an aggregate finding (the full count is in text).
    const AGG_SAMPLE: usize = 12;

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let bad_reason = |e: &Entity| -> Option<&'static str> {
        // Ground-truth veto: a GreyNoise RIOT/benign node is not bad
        // infrastructure even if a scanner also tagged it, so it never anchors an
        // adjacency explosion. The fan-out cap below is only the backstop for
        // shared infra that carries no such verdict.
        if is_benign_infra(e) {
            return None;
        }
        ADJACENCY_BAD_TAGS.iter().copied().find(|t| e.has_tag(t))
    };

    // Group benign neighbours under each flagged node, deduped by benign uid (a
    // node can reach the same bad node by more than one edge). BTreeMaps keep
    // the whole pass deterministic regardless of relation order.
    #[allow(clippy::type_complexity)]
    let mut groups: BTreeMap<
        &str,
        (
            &Entity,
            &'static str,
            BTreeMap<&str, (&Entity, RelationKind)>,
        ),
    > = BTreeMap::new();
    for r in relations {
        let (Some(&from), Some(&to)) = (
            by_uid.get(r.from_uid.as_str()),
            by_uid.get(r.to_uid.as_str()),
        ) else {
            continue;
        };
        // Exactly one endpoint flagged → the other is "adjacent to bad".
        let (benign, bad, reason) = match (bad_reason(from), bad_reason(to)) {
            (None, Some(reason)) => (from, to, reason),
            (Some(reason), None) => (to, from, reason),
            _ => continue,
        };
        let entry = groups
            .entry(bad.uid.as_str())
            .or_insert_with(|| (bad, reason, BTreeMap::new()));
        entry
            .2
            .entry(benign.uid.as_str())
            .or_insert((benign, r.kind));
    }

    let mut out = Vec::new();
    for (_bad_uid, (bad, reason, neighbours)) in groups {
        if neighbours.len() <= FANOUT_CAP {
            // Dedicated infra — meaningful per-neighbour attribution.
            for (benign, rkind) in neighbours.values() {
                out.push(Correlation::new(
                    "AU-031",
                    "Adjacency to known-bad infrastructure",
                    Severity::High,
                    format!(
                        "{} ({}) is {} flagged-{} {} ({})",
                        benign.value, benign.kind, rkind, reason, bad.value, bad.kind
                    ),
                    vec![benign.uid.clone(), bad.uid.clone()],
                    scan_id,
                    ts,
                ));
            }
        } else {
            // High fan-out without a benign verdict — shared hosting/ESP. One
            // aggregate, not N noise rows. A large *malicious* cluster is a real
            // threat and stays High; weaker reasons (vulnerable/threat-intel on
            // shared infra) are Medium.
            let agg_sev = if reason == "malicious" {
                Severity::High
            } else {
                Severity::Medium
            };
            let mut uids: Vec<String> = neighbours
                .keys()
                .take(AGG_SAMPLE)
                .map(std::string::ToString::to_string)
                .collect();
            uids.push(bad.uid.clone());
            out.push(Correlation::new(
                "AU-031",
                "Adjacency to known-bad infrastructure",
                agg_sev,
                format!(
                    "{} entities are adjacent to flagged-{} shared infrastructure {} ({}) — likely shared hosting/CDN, not a dedicated link",
                    neighbours.len(),
                    reason,
                    bad.value,
                    bad.kind
                ),
                uids,
                scan_id,
                ts,
            ));
        }
    }
    out
}

use crate::util::address_au::AuNetworkKind;

/// The Australian network an `IpAddress`/`Asn` entity names, read from its value
/// (`AS1221 Telstra`) and its network attributes (`isp`/`org`/`as`/`descr`/…),
/// delegating the brand match to the shared [`crate::util::address_au::au_network_operator`]
/// (the single source AU-097 and AU-098 both use). `None` for a non-AU /
/// unrecognised network. Pure. `pub(in crate::core::correlator)` so AU-098 reuses it.
pub(in crate::core::correlator) fn au_network_of(
    e: &Entity,
) -> Option<(&'static str, AuNetworkKind)> {
    const KEYS: &[&str] = &[
        "isp",
        "org",
        "as",
        "asn",
        "as_name",
        "asname",
        "as_org",
        "descr",
        "network",
        "org_name",
        "isp_name",
        "carrier",
        "connection_org",
    ];
    let mut hay = e.value.clone();
    for ev in &e.evidence {
        for (k, v) in &ev.attributes {
            if KEYS.iter().any(|key| k.eq_ignore_ascii_case(key)) {
                hay.push(' ');
                hay.push_str(v);
            }
        }
    }
    crate::util::address_au::au_network_operator(&hay)
}

/// AU-097 — Australian ISP / network attribution.
///
/// When a subject's `IpAddress`/`Asn` belongs to an Australian network operator
/// — read from the `isp`/`org`/`as` data the IP modules already collect — that
/// is an independent **network-layer** residency signal, orthogonal to the
/// address/coordinate/breach-field geo: a domestic consumer ISP (Telstra, Optus,
/// TPG, iiNet, Aussie Broadband, …) places a *person* on an Australian
/// connection (not foreign or hosting infrastructure), and AARNet marks a
/// university / research / government user — a strong institutional affiliation.
///
/// One finding per distinct network. Consumer ISP → Medium (residency/connection
/// signal); AARNet → High (specific affiliation). Pure over the confirmed set.
pub(in crate::core::correlator) fn rule_au_097_au_isp_network(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut found: BTreeMap<&'static str, (AuNetworkKind, BTreeSet<String>)> = BTreeMap::new();
    for e in entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::IpAddress | EntityKind::Asn))
    {
        if let Some((name, kind)) = au_network_of(e) {
            found
                .entry(name)
                .or_insert_with(|| (kind, BTreeSet::new()))
                .1
                .insert(e.uid.clone());
        }
    }

    found
        .into_iter()
        .map(|(name, (kind, uids))| {
            let (severity, description) = match kind {
                AuNetworkKind::Academic => (
                    Severity::High,
                    format!(
                        "Subject's IP/ASN is on {name} — Australia's academic & research network: \
                         a university / research / government user, a strong institutional \
                         affiliation"
                    ),
                ),
                AuNetworkKind::Consumer => (
                    Severity::Medium,
                    format!(
                        "Subject's IP/ASN belongs to {name}, an Australian consumer ISP — a \
                         network-layer AU residency/connection signal (a person on a domestic \
                         network, not foreign or hosting infrastructure)"
                    ),
                ),
            };
            Correlation::new(
                "AU-097",
                "Australian ISP / network attribution",
                severity,
                description,
                uids.into_iter().collect(),
                scan_id,
                ts,
            )
        })
        .collect()
}

/// CDN/reverse-proxy providers known to front DNS **globally**, via an anycast
/// edge network — the visible A/AAAA record is always the CDN's edge, never
/// the origin. Deliberately excludes the on-premise WAF appliances
/// `waf_detect` also fingerprints (F5 BIG-IP, Citrix NetScaler, Barracuda,
/// ModSecurity): those typically sit in front of infrastructure that still
/// resolves directly on the operator's own network, so treating their
/// presence as "the DNS record isn't the origin" would be an unsupported
/// generalisation — precision over recall, matching this codebase's stance
/// that a false unmasking claim is worse than a missed one.
const DNS_FRONTING_CDN_PROVIDERS: &[&str] = &[
    "Cloudflare",
    "Akamai",
    "Fastly",
    "CloudFront",
    "Sucuri",
    "Incapsula",
    "StackPath",
    "KeyCDN",
];

/// AU-111 — CDN-fronted domain's SPF-authorised sender IP is a likely origin
/// candidate.
///
/// `waf_detect` fingerprints a domain sitting behind a global anycast CDN
/// (Cloudflare et al.) from its HTTP response headers/cookies. When
/// `dns_intel` finds that same domain's SPF record authorising a specific IP
/// as a mail sender, that IP is genuine mail infrastructure — SMTP isn't
/// proxied the way HTTP/HTTPS is, so a CDN reverse-proxy never fronts it —
/// making it a likely member of the same network as the true web origin the
/// CDN is hiding. This is `PROBLEM_TREE` C4's named "MX/SPF/TXT records (mail
/// isn't proxied → origin leak)" origin-unmasking signal, built from data
/// both modules already collect (no new external API/network dependency).
///
/// Not a certainty — a subject may run mail on infrastructure entirely
/// separate from their web origin — so this is Medium, an operator pivot
/// point rather than a confirmed unmasking. Sibling signal: AU-113 unmasks
/// the same CDN-origin question from a direct-connect-subdomain angle
/// instead of SPF (`rules::org`) — kept as two independent rules rather than
/// merged, per the technique-diversity principle (TA0043): each is real
/// evidence from a different angle, and either firing alone is still useful
/// even when the other's precondition (an SPF record / a direct-connect
/// subdomain) doesn't hold.
pub(in crate::core::correlator) fn rule_au_111_cdn_origin_candidate(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let fronted: Vec<(&Entity, &str)> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.has_tag("waf-detected"))
        .filter_map(|e| {
            DNS_FRONTING_CDN_PROVIDERS
                .iter()
                .find(|p| e.has_tag(&format!("waf:{p}")))
                .map(|p| (e, *p))
        })
        .collect();
    if fronted.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for (dom, provider) in fronted {
        let candidates = entities.iter().filter(|e| {
            e.kind == EntityKind::IpAddress
                && e.has_tag("spf")
                && e.evidence
                    .iter()
                    .any(|ev| ev.attributes.get("domain").is_some_and(|d| d == &dom.value))
        });
        for ip in candidates {
            out.push(Correlation::new(
                "AU-111",
                "CDN origin candidate",
                Severity::Medium,
                format!(
                    "'{}' is CDN-fronted ({provider}); its SPF-authorised mail sender {} is not \
                     proxied by the CDN and is a likely origin/hosting-network candidate",
                    dom.value, ip.value
                ),
                vec![dom.uid.clone(), ip.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

/// Narrowest-permitted (largest) IPv4 block this rule will treat as a
/// meaningful shared-infrastructure signal: `/22`, the same "largest block a
/// single operator typically owns end-to-end" floor `netblock`'s `MAX_HOSTS`
/// comment already establishes. A `Cidr` entity broader than this (an ISP or
/// cloud-provider allocation spanning many unrelated customers) would turn
/// "these two IPs are in the same block" into noise rather than signal.
const MIN_IPV4_CIDR_PREFIX: u8 = 22;

/// The IPv6 analogue of [`MIN_IPV4_CIDR_PREFIX`]: `/48` is the conventional
/// smallest end-site allocation (RFC 6177), so anything broader is provider-
/// scale address space, not a single shared deployment.
const MIN_IPV6_CIDR_PREFIX: u8 = 48;

/// True if `ip_entity` is already explicitly linked to `block` by another
/// module's own evidence (e.g. `netblock`'s host-expansion, which tags each
/// emitted `IpAddress` `netblock-member` and records the parent block as a
/// `cidr` evidence attribute). Re-deriving that as a fresh AU-112 correlation
/// would just restate an already-explicit parent/child relationship as if it
/// were a new inference.
fn already_linked_to_block(ip_entity: &Entity, block: &str) -> bool {
    ip_entity
        .evidence
        .iter()
        .any(|ev| ev.attributes.get("cidr").is_some_and(|c| c == block))
}

/// AU-112 — an independently-discovered IP address falls within a network
/// block (`Cidr` entity) also discovered in this scan — shared hosting
/// infrastructure, not personal ownership.
///
/// `bgpview`/`ripestat`/`netblock` surface `Cidr` entities (an ASN's announced
/// prefix, or an explicit netblock target) using the CIDR-containment maths
/// [`crate::util::spf`] already built (and tests) for SPF `ip4:`/`ip6:`
/// mechanisms — reused here rather than re-implemented, per this project's
/// one-classifier-per-concern convention. An `IpAddress` entity reached by a
/// *different* route (DNS resolution, a banner grab, a second subdomain) that
/// happens to fall inside that same block is evidence the two share a hosting
/// network/provider — useful for infrastructure mapping, but explicitly not a
/// personal-ownership or co-location claim, so this stays Medium and framed as
/// a hosting/infra pivot, matching AU-111's precedent for inferred
/// infrastructure signals. Scoped to narrow blocks only
/// ([`MIN_IPV4_CIDR_PREFIX`]/[`MIN_IPV6_CIDR_PREFIX`]) so a broad ISP/cloud
/// allocation containing thousands of unrelated customers can't manufacture
/// noise, and skips pairs [`already_linked_to_block`] already makes explicit.
pub(in crate::core::correlator) fn rule_au_112_shared_cidr_infrastructure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use crate::util::spf::Ipv4Cidr;
    use crate::util::spf::Ipv6Cidr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    enum Block {
        V4(Ipv4Cidr),
        V6(Ipv6Cidr),
    }

    let mut blocks: Vec<(&Entity, Block)> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Cidr)
        .filter_map(|e| {
            let v = e.value.trim();
            if v.contains(':') {
                let c = Ipv6Cidr::parse(v)?;
                (c.prefix_len() >= MIN_IPV6_CIDR_PREFIX).then_some((e, Block::V6(c)))
            } else {
                let c = Ipv4Cidr::parse(v)?;
                (c.prefix_len() >= MIN_IPV4_CIDR_PREFIX).then_some((e, Block::V4(c)))
            }
        })
        .collect();
    if blocks.is_empty() {
        return Vec::new();
    }
    // Deterministic (CONVENTIONS.md §5): `entities` order is not guaranteed
    // stable across runs, so fix the iteration order explicitly rather than
    // let it leak into which pair's Correlation is constructed first.
    blocks.sort_by(|a, b| a.0.value.cmp(&b.0.value).then(a.0.uid.cmp(&b.0.uid)));

    let mut ips: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .collect();
    ips.sort_by(|a, b| a.value.cmp(&b.value).then(a.uid.cmp(&b.uid)));

    let mut out = Vec::new();
    for (block_entity, block) in &blocks {
        for ip in &ips {
            if already_linked_to_block(ip, &block_entity.value) {
                continue;
            }
            let contained = match block {
                Block::V4(c) => ip.value.parse::<Ipv4Addr>().is_ok_and(|a| c.contains(a)),
                Block::V6(c) => ip.value.parse::<Ipv6Addr>().is_ok_and(|a| c.contains(a)),
            };
            if !contained {
                continue;
            }
            out.push(Correlation::new(
                "AU-112",
                "Shared CIDR infrastructure",
                Severity::Medium,
                format!(
                    "IP {} falls within network block {} also discovered this scan — likely \
                     shared hosting infrastructure, not necessarily common ownership",
                    ip.value, block_entity.value
                ),
                vec![block_entity.uid.clone(), ip.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}
