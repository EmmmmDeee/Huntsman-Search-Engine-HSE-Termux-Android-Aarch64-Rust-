use std::collections::{HashMap, HashSet};

use super::{Correlation, Severity};
use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::{Relation, RelationKind};

fn entities_of_kind(entities: &[Entity], kind: EntityKind) -> Vec<&Entity> {
    entities.iter().filter(|e| e.kind == kind).collect()
}

fn tagged_matching_sources<'a>(entity: &'a Entity, allowed: &[&str]) -> HashSet<&'a str> {
    entity
        .evidence_sources()
        .into_iter()
        .filter(|s| allowed.contains(s))
        .collect()
}

/// Authoritative "known-benign infrastructure" verdicts — GreyNoise RIOT (a
/// catalogued benign service: a CDN/cloud/SaaS edge) and GreyNoise's `benign`
/// classification. Both are IP-level.
///
/// When a node carries one of these, the blocklist/scanner tags it ALSO carries
/// (`vulnerable`, `threat-intel`, `malicious`, `blocklisted`, …) are shared-edge
/// or scan artefacts, not a real threat: a Cloudflare anycast IP picks up
/// `vulnerable` from a CVE scan of the *shared* edge while GreyNoise correctly
/// catalogues it RIOT, and an emitted-on-every-co-hosted-domain explosion
/// follows. A benign verdict therefore VETOES those tags for the threat
/// correlations (AU-004/008/015/031) — the data's own ground truth, rather than
/// inferring "shared infra" from edge fan-out. Because the veto tags are IP-only,
/// a malicious *domain* behind a CDN is unaffected (it carries no benign
/// verdict); only the shared-edge IP is exonerated.
const BENIGN_INFRA_TAGS: &[&str] = &["greynoise-riot", "greynoise-benign"];

/// True if `e` carries an authoritative known-benign-infrastructure verdict that
/// vetoes bad-infra tags for threat classification (see [`BENIGN_INFRA_TAGS`]).
fn is_benign_infra(e: &Entity) -> bool {
    BENIGN_INFRA_TAGS.iter().any(|t| e.has_tag(t))
}

/// True if `text` mentions `ip` as a whole dotted address, not as a substring of
/// a longer number. A bare `contains` is wrong: `"11.2.3.45".contains("1.2.3.4")`
/// is `true`, so an unrelated IP in an evidence summary would falsely chain. We
/// reject a match flanked by an IP-*extending* char (digit or `.`); a following
/// `:`/space/`)` is a legitimate boundary (`"1.2.3.4:8080"`, `"1.2.3.4: City"`).
/// `ip`/`text` index by byte safely — `ip` is ASCII.
fn text_mentions_ip(text: &str, ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let n = ip.len();
    let extends = |b: u8| b.is_ascii_digit() || b == b'.';
    let mut from = 0;
    while let Some(rel) = text[from..].find(ip) {
        let i = from + rel;
        let before_ok = i == 0 || !extends(bytes[i - 1]);
        let after_ok = i + n >= bytes.len() || !extends(bytes[i + n]);
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

pub(super) fn rule_au_001_multi_breach(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const BREACH_SOURCES: &[&str] = &[
        "hudsonrock",
        "xposed_or_not",
        "breach_directory",
        "dehashed",
        "hibp",
        "oathnet_pro",
        "emailrep",
        // NOTE: the generic `search_engines` source is deliberately NOT listed.
        // A web-search hit is not breach corroboration, and counting it would let
        // one real breach + one search result fire a false Critical. (An earlier
        // `search_engines:oathnet` entry was dead — the module emits the plain
        // `search_engines` source — so it was removed rather than "fixed" to
        // `search_engines`, which would introduce exactly that false positive.)
    ];
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Email) {
        let sources = tagged_matching_sources(e, BREACH_SOURCES);
        if sources.len() >= 2 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            out.push(Correlation::new(
                "AU-001",
                "Multi-source breach corroboration",
                Severity::Critical,
                format!(
                    "{} found in {} breach sources: {}",
                    e.value,
                    names.len(),
                    names.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

pub(super) fn rule_au_002_identity_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // A confidence floor on top of the upstream candidate-exclusion: a genuine
    // identity cluster is built from corroborated entities, not weak guesses.
    const MIN_CONF: f64 = 0.50;
    // One person does not own dozens of distinct emails or phones — that many
    // is the signature of a breach dump spanning many people. Refuse to fuse it
    // into a CRITICAL "one identity" correlation (the exact failure that fused
    // 179 strangers from a name search). Candidate-exclusion makes this rare;
    // this is the backstop for any non-candidate bulk source.
    const MAX_PER_KIND: usize = 25;
    let of_kind = |k| -> Vec<&Entity> {
        entities_of_kind(entities, k)
            .into_iter()
            .filter(|e| e.confidence >= MIN_CONF)
            .collect()
    };
    let emails = of_kind(EntityKind::Email);
    let usernames = of_kind(EntityKind::Username);
    let phones = of_kind(EntityKind::Phone);

    if emails.is_empty() || usernames.is_empty() || phones.is_empty() {
        return Vec::new();
    }
    if emails.len() > MAX_PER_KIND || usernames.len() > MAX_PER_KIND || phones.len() > MAX_PER_KIND
    {
        return Vec::new();
    }

    let mut uids: Vec<String> = emails.iter().map(|e| e.uid.clone()).collect();
    uids.extend(usernames.iter().map(|e| e.uid.clone()));
    uids.extend(phones.iter().map(|e| e.uid.clone()));

    vec![Correlation {
        rule_id: "AU-002".into(),
        rule_name: "Identity cluster".into(),
        severity: Severity::Critical,
        description: format!(
            "Email + Username + Phone co-located: {} email(s), {} username(s), {} phone(s)",
            emails.len(),
            usernames.len(),
            phones.len()
        ),
        entity_uids: uids,
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}

pub(super) fn rule_au_003_high_corroboration(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Thresholds are on DISTINCT corroborating sources (source_count), not the
    // summed observation-magnitude field. Calibrated for real distinct-source
    // counts: infra entities (domain/url/ip) reach high agreement easily across
    // resolver/cert/whois/geo modules, so they need 3; identity entities
    // (email/person/username/phone) are strong at 2 distinct independent
    // sources. The old thresholds (5/4/3) were tuned to the inflated summed
    // counter and effectively never fired on honest distinct-source counts.
    let min_sources = |kind: &crate::core::entity::EntityKind| -> u32 {
        match kind {
            EntityKind::Domain | EntityKind::Url | EntityKind::IpAddress => 3,
            _ => 2,
        }
    };
    entities
        .iter()
        .filter(|e| e.source_count() >= min_sources(&e.kind))
        .map(|e| Correlation {
            rule_id: "AU-003".into(),
            rule_name: "High cross-source corroboration".into(),
            severity: Severity::Medium,
            description: format!(
                "{} entity '{}' corroborated by {} independent source(s) (C_eff={:.3})",
                e.kind,
                e.value,
                e.source_count(),
                e.c_effective()
            ),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

pub(super) fn rule_au_004_malicious_infrastructure(
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
        // the same (shared-edge) IP from a weaker source.
        .filter(|e| e.has_tag("malicious") && !is_benign_infra(e))
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

pub(super) fn rule_au_005_anonymous_network(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const ANON_TAGS: &[&str] = &["tor-exit", "tor", "anonymous-network", "anonymous-vpn"];
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .filter(|e| ANON_TAGS.iter().any(|t| e.has_tag(t)))
        .map(|e| {
            let hits: Vec<&str> = ANON_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            Correlation {
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
            }
        })
        .collect()
}

pub(super) fn rule_au_006_proxy_vpn(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const ANON_TAGS: &[&str] = &["tor-exit", "tor", "anonymous-network", "anonymous-vpn"];
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .filter(|e| {
            (e.has_tag("proxy") || e.has_tag("vpn")) && !ANON_TAGS.iter().any(|t| e.has_tag(t))
        })
        .map(|e| {
            let mut hits: Vec<&str> = Vec::new();
            if e.has_tag("proxy") {
                hits.push("proxy");
            }
            if e.has_tag("vpn") {
                hits.push("vpn");
            }
            Correlation {
                rule_id: "AU-006".into(),
                rule_name: "Proxy/VPN-fronted IP".into(),
                severity: Severity::Medium,
                description: format!("IP {} is fronted by {}", e.value, hits.join(" + ")),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(super) fn rule_au_007_high_risk_reputation(
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
        .filter(|e| RISK_TAGS.iter().any(|t| e.has_tag(t)))
        .map(|e| {
            let hits: Vec<&str> = RISK_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            Correlation {
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
            }
        })
        .collect()
}

pub(super) fn rule_au_008_exposed_service(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const EXPOSURE_TAGS: &[&str] = &["vulnerable", "ssh-exposed", "leak"];
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

pub(super) fn rule_au_009_stealer_log(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email && e.has_tag("stealer-log"))
        .map(|e| Correlation {
            rule_id: "AU-009".into(),
            rule_name: "Stealer-log compromise".into(),
            severity: Severity::High,
            description: format!("Email {} observed in info-stealer log dumps", e.value),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

pub(super) fn rule_au_010_infra_consensus(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Domain | EntityKind::IpAddress))
    {
        let sources = e.evidence_sources();
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

pub(super) fn rule_au_011_cross_platform_username(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .filter_map(|e| {
            let mut max_count: u64 = 0;
            let mut best_list: Option<&str> = None;
            for ev in &e.evidence {
                let count = ev
                    .attributes
                    .get("platforms_count")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                if count > max_count {
                    max_count = count;
                    best_list = ev.attributes.get("platforms").map(String::as_str);
                }
            }
            if max_count >= 3 {
                let detail = best_list.map(|s| format!(": {s}")).unwrap_or_default();
                Some(Correlation {
                    rule_id: "AU-011".into(),
                    rule_name: "Cross-platform username footprint".into(),
                    severity: Severity::Medium,
                    description: format!(
                        "Username '{}' present on {max_count} platforms{detail}",
                        e.value
                    ),
                    entity_uids: vec![e.uid.clone()],
                    scan_id: scan_id.into(),
                    ts,
                    rank: 0.0,
                })
            } else {
                None
            }
        })
        .collect()
}

pub(super) fn rule_au_012_identity_linked_domain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let username_uids: Vec<String> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|u| u.uid.clone())
        .collect();
    if username_uids.is_empty() {
        return Vec::new();
    }
    entities
        .iter()
        .filter(|e| {
            matches!(e.kind, EntityKind::Url | EntityKind::Domain) && e.has_tag("personal-site")
        })
        .map(|d| {
            let mut uids = Vec::with_capacity(1 + username_uids.len());
            uids.push(d.uid.clone());
            uids.extend(username_uids.iter().cloned());
            Correlation {
                rule_id: "AU-012".into(),
                rule_name: "Identity-linked site".into(),
                severity: Severity::Medium,
                description: format!(
                    "Personal site '{}' co-occurs with {} username(s) in scan",
                    d.value,
                    username_uids.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(super) fn rule_au_013_local_network_discovery(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const LAN_TAGS: &[&str] = &["local-arp", "local-interface", "wifi-ap"];
    let hits: Vec<&Entity> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::IpAddress | EntityKind::MacAddress))
        .filter(|e| LAN_TAGS.iter().any(|t| e.has_tag(t)))
        .collect();
    if hits.len() < 2 {
        return Vec::new();
    }
    vec![Correlation {
        rule_id: "AU-013".into(),
        rule_name: "Local-network discovery".into(),
        severity: Severity::Low,
        description: format!(
            "{} entities observed on the local network (ARP / interfaces / Wi-Fi APs)",
            hits.len()
        ),
        entity_uids: hits.iter().map(|e| e.uid.clone()).collect(),
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}

pub(super) fn rule_au_014_geo_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const GEO_TAGS: &[&str] = &["geoint", "wifi-observed"];
    entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter_map(|e| {
            let hits: Vec<&str> = GEO_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            // Corroborating sources only: the deterministic `geo_normalize`
            // enrichment pass is not an independent geo observation, so a lone
            // postcode-centroid it touched must not look like a "cluster".
            let sources = e.corroborating_sources();
            if hits.len() >= 2 || sources.len() >= 2 {
                Some(Correlation {
                    rule_id: "AU-014".into(),
                    rule_name: "Geolocation cluster".into(),
                    severity: Severity::Medium,
                    description: format!(
                        "Coordinates '{}' confirmed by {} geo source(s)",
                        e.value,
                        sources.len().max(hits.len())
                    ),
                    entity_uids: vec![e.uid.clone()],
                    scan_id: scan_id.into(),
                    ts,
                    rank: 0.0,
                })
            } else {
                None
            }
        })
        .collect()
}

pub(super) fn rule_au_015_threat_intel_hit(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const TI_SOURCES: &[&str] = &["ip_reputation", "threatfox"];

    entities
        .iter()
        // A GreyNoise RIOT/benign IP that a reputation feed also flagged is a
        // shared-edge false positive — exonerate it.
        .filter(|e| e.has_tag("threat-intel") && !is_benign_infra(e))
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

pub(super) fn rule_au_016_breach_ip_geo_chain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let breach_ips: Vec<&Entity> = entities_of_kind(entities, EntityKind::IpAddress)
        .into_iter()
        .filter(|e| e.has_tag("breach"))
        .collect();
    let coords: Vec<&Entity> = entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter(|e| e.confidence >= 0.60)
        .collect();
    if breach_ips.is_empty() || coords.is_empty() {
        return Vec::new();
    }
    let linked: Vec<&Entity> = coords
        .iter()
        .filter(|c| {
            c.evidence.iter().any(|ev| {
                breach_ips
                    .iter()
                    .any(|ip| text_mentions_ip(&ev.summary, &ip.value))
            })
        })
        .copied()
        .collect();
    if linked.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = breach_ips.iter().map(|e| e.uid.clone()).collect();
    uids.extend(linked.iter().map(|e| e.uid.clone()));
    vec![Correlation {
        rule_id: "AU-016".into(),
        rule_name: "Breach IP → geolocation chain".into(),
        severity: Severity::High,
        description: format!(
            "{} breach IP(s) resolved to {} coordinate(s) via geolocation pipeline",
            breach_ips.len(),
            linked.len()
        ),
        entity_uids: uids,
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}

pub(super) fn rule_au_017_multi_geo_convergence(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let coords: Vec<&Entity> = entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter(|e| e.confidence >= 0.50)
        .collect();
    if coords.len() < 2 {
        return Vec::new();
    }
    // Parse once through the canonical, range-validating helper so out-of-range
    // junk ("200,300") is dropped here rather than silently clustered. Each
    // surviving entity carries its (lat, lon) so the inner loop never re-parses.
    let parsed: Vec<(&Entity, (f64, f64))> = coords
        .iter()
        .filter_map(|c| crate::util::geohash::parse_coords(&c.value).map(|ll| (*c, ll)))
        .collect();
    let mut clusters: Vec<Vec<(&Entity, (f64, f64))>> = Vec::new();
    for &(c, (lat, lon)) in &parsed {
        let mut found = false;
        for cluster in &mut clusters {
            let (_, (rl, ro)) = cluster[0];
            if (lat - rl).abs() < 0.5 && (lon - ro).abs() < 0.5 {
                cluster.push((c, (lat, lon)));
                found = true;
                break;
            }
        }
        if !found {
            clusters.push(vec![(c, (lat, lon))]);
        }
    }
    clusters
        .into_iter()
        .filter(|cl| cl.len() >= 2)
        .map(|cl| {
            let uids: Vec<String> = cl.iter().map(|(e, _)| e.uid.clone()).collect();
            let sources: HashSet<&str> = cl
                .iter()
                .flat_map(|(e, _)| e.evidence.iter().map(|ev| ev.source.as_str()))
                .collect();
            Correlation {
                rule_id: "AU-017".into(),
                rule_name: "Multi-source geographic convergence".into(),
                severity: Severity::High,
                description: format!(
                    "{} coordinate entities converge within 0.5° (~55km), from {} source(s)",
                    cl.len(),
                    sources.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(super) fn rule_au_018_email_address_colocation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let emails: Vec<&Entity> = entities_of_kind(entities, EntityKind::Email)
        .into_iter()
        .filter(|e| e.confidence >= 0.60)
        .collect();
    let addresses: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            matches!(e.kind, EntityKind::Address | EntityKind::Coordinates) && e.confidence >= 0.50
        })
        .collect();
    if emails.is_empty() || addresses.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = emails.iter().take(10).map(|e| e.uid.clone()).collect();
    uids.extend(addresses.iter().take(5).map(|e| e.uid.clone()));
    vec![Correlation {
        rule_id: "AU-018".into(),
        rule_name: "Email + physical location co-located".into(),
        severity: Severity::High,
        description: format!(
            "{} email(s) co-located with {} address/coordinate(s) — identity-location linkage",
            emails.len(),
            addresses.len()
        ),
        entity_uids: uids,
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}

pub(super) fn rule_au_019_temporal_breach_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut breach_dates: Vec<(&Entity, &str)> = Vec::new();
    for e in entities {
        if !e.has_tag("breach") {
            continue;
        }
        for ev in &e.evidence {
            for field in ["breach_date", "not_before", "earliest_record", "date"] {
                if let Some(d) = ev.attributes.get(field)
                    && let Some(day) = d.get(..10)
                {
                    breach_dates.push((e, day));
                }
            }
        }
    }
    if breach_dates.len() < 3 {
        return Vec::new();
    }
    breach_dates.sort_by_key(|(_, d)| *d);
    let mut clusters: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = vec![breach_dates[0].0.uid.clone()];
    // Anchor the window to the cluster's FIRST (earliest, since sorted) date, not
    // a rolling previous date. A rolling gap chains — Jan 1 / Jan 30 / Feb 28 /
    // Mar 30 are each ≤30 days apart and would collapse into one 88-day "cluster",
    // contradicting the "within 30 days" claim. Anchoring bounds every cluster to
    // a genuine ≤30-day span (a real coordinated-compromise window).
    let mut anchor = breach_dates[0].1;
    for &(e, d) in &breach_dates[1..] {
        if date_diff_days(anchor, d) <= 30 {
            if !current.contains(&e.uid) {
                current.push(e.uid.clone());
            }
        } else {
            if current.len() >= 3 {
                clusters.push(current);
            }
            current = vec![e.uid.clone()];
            anchor = d;
        }
    }
    if current.len() >= 3 {
        clusters.push(current);
    }
    clusters
        .into_iter()
        .map(|uids| Correlation {
            rule_id: "AU-019".into(),
            rule_name: "Temporal breach cluster".into(),
            severity: Severity::High,
            description: format!(
                "{} breach entities clustered within 30 days — potential coordinated compromise",
                uids.len()
            ),
            entity_uids: uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

/// Approximate the absolute day gap between two `YYYY-MM-DD` strings.
///
/// Intentionally dependency-free (no `chrono`/`time`): days are estimated as
/// `y*365 + m*30 + d`, so the result is **not** an exact calendar difference.
/// Error is bounded to a few days near month/year boundaries (e.g. `2020-01-31`
/// vs `2020-02-01` reads as 0). Every caller (AU-019 temporal clustering) uses a
/// coarse window (≥30 days) where this noise is irrelevant — do not reuse this
/// where exact-day precision matters. Returns `u64::MAX` if either side fails to
/// parse, which sorts/compares as "infinitely far apart" (never clusters).
pub(super) fn date_diff_days(a: &str, b: &str) -> u64 {
    let parse = |s: &str| -> Option<u64> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            return None;
        }
        let y: u64 = parts[0].parse().ok()?;
        let m: u64 = parts[1].parse().ok()?;
        let d: u64 = parts[2].parse().ok()?;
        Some(y * 365 + m * 30 + d)
    };
    match (parse(a), parse(b)) {
        (Some(da), Some(db)) => da.abs_diff(db),
        _ => u64::MAX,
    }
}

pub(super) fn rule_au_020_person_entity_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let persons: Vec<&Entity> = entities_of_kind(entities, EntityKind::Person)
        .into_iter()
        .filter(|e| e.confidence >= 0.50)
        .collect();
    if persons.len() < 2 {
        return Vec::new();
    }
    let uids: Vec<String> = persons.iter().map(|e| e.uid.clone()).collect();
    vec![Correlation::new(
        "AU-020",
        "Multiple person entities",
        Severity::Medium,
        format!(
            "{} person entities discovered — potential identity disambiguation needed",
            persons.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

pub(super) fn rule_au_021_api_key_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::ApiKey)
        .map(|e| {
            Correlation::new(
                "AU-021",
                "API key exposure",
                Severity::Critical,
                format!("API key '{}' discovered in breach/stealer data", e.value),
                vec![e.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
}

pub(super) fn rule_au_022_organisation_with_breach(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let orgs: Vec<&Entity> = entities_of_kind(entities, EntityKind::Organisation)
        .into_iter()
        .filter(|e| e.confidence >= 0.60)
        .collect();
    let breach_entities: Vec<&Entity> = entities.iter().filter(|e| e.has_tag("breach")).collect();
    if orgs.is_empty() || breach_entities.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = orgs.iter().map(|e| e.uid.clone()).collect();
    uids.extend(breach_entities.iter().take(5).map(|e| e.uid.clone()));
    vec![Correlation::new(
        "AU-022",
        "Organisation linked to breach data",
        Severity::High,
        format!(
            "{} organisation(s) co-located with {} breach entities",
            orgs.len(),
            breach_entities.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

pub(super) fn rule_au_023_cross_platform_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const IDENTITY_SOURCES: &[&str] = &[
        "keybase",
        "github_user",
        "proxycurl",
        "epieos",
        "seon",
        "contact_enrich",
    ];
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Person)
        .into_iter()
        .filter(|e| e.confidence >= 0.60)
    {
        let sources = tagged_matching_sources(e, IDENTITY_SOURCES);
        if sources.len() >= 2 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            out.push(Correlation::new(
                "AU-023",
                "Cross-platform identity convergence",
                Severity::High,
                format!(
                    "Person '{}' confirmed by {} independent identity source(s): {}",
                    e.value,
                    names.len(),
                    names.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

pub(super) fn rule_au_024_email_fraud_signal(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .filter(|e| {
            let s = e.has_tag("suspicious") || e.has_tag("high-risk");
            let b = e.has_tag("breach");
            let d = e.has_tag("disposable");
            u32::from(s) + u32::from(b) + u32::from(d) >= 2
        })
        .map(|e| {
            let mut signals: Vec<&str> = Vec::new();
            if e.has_tag("suspicious") || e.has_tag("high-risk") {
                signals.push("fraud-flagged");
            }
            if e.has_tag("breach") {
                signals.push("breach-exposed");
            }
            if e.has_tag("disposable") {
                signals.push("disposable");
            }
            Correlation::new(
                "AU-024",
                "Multi-signal email fraud indicator",
                Severity::High,
                format!(
                    "Email '{}' has converging risk signals: {}",
                    e.value,
                    signals.join(" + ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
}

pub(super) fn rule_au_025_corporate_identity_link(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let orgs: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation && e.has_tag("opencorporates"))
        .collect();
    let persons: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person && e.confidence >= 0.60)
        .collect();
    if orgs.is_empty() || persons.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = orgs.iter().map(|o| o.uid.clone()).collect();
    uids.extend(persons.iter().take(5).map(|p| p.uid.clone()));
    vec![Correlation::new(
        "AU-025",
        "Corporate registry linked to identity",
        Severity::Medium,
        format!(
            "{} registered company/ies co-located with {} person entities",
            orgs.len(),
            persons.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

pub(super) fn rule_au_026_validated_address(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const GEO_SOURCES: &[&str] = &[
        "geocode",
        "photon",
        "geo_intel",
        "wigle",
        "overpass",
        "ip_geo",
        "ip2location",
        "ipapi",
        "ipinfo",
        "opencorporates",
        "epieos",
        "proxycurl",
        "contact_enrich",
        // Authoritative registries that emit a registered address (parity with
        // opencorporates): ACNC charities register + GLEIF LEI index.
        "acnc_charities",
        "gleif_lei",
    ];
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Address)
        .into_iter()
        .filter(|e| e.confidence >= 0.50)
    {
        let sources = tagged_matching_sources(e, GEO_SOURCES);
        if sources.len() >= 2 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            out.push(Correlation::new(
                "AU-026",
                "Multi-source validated address",
                Severity::High,
                format!(
                    "Address '{}' confirmed by {} independent source(s): {}",
                    e.value,
                    names.len(),
                    names.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

/// AU-027 — Address ↔ coordinates geolocation chain.
///
/// Co-presence signal: fires when the scan holds both geo-tagged `Address` and
/// `Coordinates` entities (confidence ≥ 0.55). It asserts that multiple geo
/// artefacts were derived for the subject, NOT that a given address geocodes to
/// a given coordinate — the correlator runs in `core` and cannot call the
/// `util::geohash` distance helpers (the `core_does_not_import_util` layering
/// invariant), so cross-kind proximity is intentionally not verified here.
/// Spatial proximity between coordinate sets is AU-017's job.
pub(super) fn rule_au_027_address_coordinates_chain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let addresses: Vec<&Entity> = entities_of_kind(entities, EntityKind::Address)
        .into_iter()
        .filter(|e| e.confidence >= 0.55)
        .collect();
    let coords: Vec<&Entity> = entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter(|e| e.confidence >= 0.55)
        .collect();
    if addresses.is_empty() || coords.is_empty() {
        return Vec::new();
    }
    let addr_has_geo_tag = addresses
        .iter()
        .any(|a| a.has_tag("geoint") || a.has_tag("reverse-geocoded") || a.has_tag("validated"));
    let coords_has_geo_tag = coords
        .iter()
        .any(|c| c.has_tag("geoint") || c.has_tag("geocoded"));
    if !addr_has_geo_tag && !coords_has_geo_tag {
        return Vec::new();
    }
    let mut uids: Vec<String> = addresses.iter().take(3).map(|a| a.uid.clone()).collect();
    uids.extend(coords.iter().take(3).map(|c| c.uid.clone()));
    vec![Correlation::new(
        "AU-027",
        "Address-coordinates geolocation chain",
        Severity::High,
        format!(
            "{} address(es) and {} coordinate set(s) form a validated geolocation chain",
            addresses.len(),
            coords.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

pub(super) fn rule_au_028_subdomain_takeover_risk(
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

pub(super) fn rule_au_029_cloud_storage_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let exposed: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.has_tag("cloud-storage") && e.has_tag("vulnerable"))
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

/// AU-030 — Multi-source geolocation convergence (source breadth).
///
/// Measures how many INDEPENDENT sources produced geo entities for the subject
/// (`corroborating_sources`, so the unconditional `geo_normalize` enrichment
/// pass can't inflate the count), escalating Medium→High→Critical at 3/4/5+. It
/// is source *convergence* — many sources agreeing to provide geolocation — not
/// a check that those sources agree on the same place; cross-kind proximity is
/// not verified here (see AU-027 on why the correlator can't). AU-017 covers
/// spatial clustering of `Coordinates`.
pub(super) fn rule_au_030_geo_convergence_score(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let geo_entities: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            matches!(e.kind, EntityKind::Address | EntityKind::Coordinates) && e.confidence >= 0.40
        })
        .collect();

    if geo_entities.len() < 2 {
        return Vec::new();
    }

    // Corroborating sources only — exclude the `geo_normalize` enrichment pass,
    // which touches every geo entity and would otherwise manufacture the third
    // "independent source" this convergence score requires out of nothing.
    let mut all_sources: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for e in &geo_entities {
        for src in e.corroborating_sources() {
            all_sources.insert(src);
        }
    }

    if all_sources.len() < 3 {
        return Vec::new();
    }

    let mut sources: Vec<&str> = all_sources.into_iter().collect();
    sources.sort_unstable();
    let uids: Vec<String> = geo_entities.iter().map(|e| e.uid.clone()).collect();

    let severity = if sources.len() >= 5 {
        Severity::Critical
    } else if sources.len() >= 4 {
        Severity::High
    } else {
        Severity::Medium
    };

    vec![Correlation::new(
        "AU-030",
        "Multi-source geolocation convergence",
        severity,
        format!(
            "{} independent sources produced {} geo entities: {}",
            sources.len(),
            geo_entities.len(),
            sources.join(", ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-033 — Australian business identity. Links an ABN/ACN registration to the
/// registered organisation(s) it belongs to when both are present from an
/// Australian registry (`abn_lookup` → `abr`, `opencorporates`, `acnc_charities`
/// → `acnc`, `gleif_lei` → `gleif`). Surfaces the
/// ABN/ACN ↔ Organisation chain those modules produce but no prior rule joined
/// (AU-025 covers Organisation ↔ Person). Organisations are gated on a registry
/// tag so unrelated `Organisation` names (e.g. from search_engines) don't link.
pub(super) fn rule_au_033_abn_organisation_link(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let abns: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::AbnAcn)
        .collect();
    let orgs: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Organisation
                && (e.has_tag("abr")
                    || e.has_tag("opencorporates")
                    || e.has_tag("acnc")
                    || e.has_tag("gleif"))
        })
        .collect();
    if abns.is_empty() || orgs.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = abns.iter().map(|a| a.uid.clone()).collect();
    uids.extend(orgs.iter().map(|o| o.uid.clone()));
    vec![Correlation::new(
        "AU-033",
        "Australian business identity (ABN/ACN \u{2194} organisation)",
        Severity::Medium,
        format!(
            "{} ABN/ACN registration(s) linked to {} registered organisation(s) \
             via the Australian Business Register / corporate registries",
            abns.len(),
            orgs.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// Role-mailbox / shared-inbox handles that identify an organisation function,
/// not a person — matching identities on these links unrelated people, so they
/// are excluded from AU-034. Complements `preflight::is_placeholder_username`
/// (admin/test/guest/…) with the shared-mailbox local-parts that pad email
/// sets. Entries are stored in canonical (separator-free, lowercase) form to
/// match [`canonical_handle`] output.
const GENERIC_HANDLES: &[&str] = &[
    "info",
    "contact",
    "support",
    "sales",
    "help",
    "hello",
    "office",
    "mail",
    "team",
    "noreply",
    "donotreply",
    "service",
    "services",
    "billing",
    "marketing",
    "press",
    "media",
    "jobs",
    "careers",
    "abuse",
    "postmaster",
    "webmaster",
    "hostmaster",
    "enquiries",
    "enquiry",
    "general",
    "accounts",
    "account",
    "newsletter",
    "subscribe",
];

/// Canonical comparison form of a handle: ASCII-lowercased with the handle
/// separators (`.`, `_`, `-`) removed, so the same handle written with
/// inconsistent punctuation collapses to one token (`jordan.meyers`,
/// `jordan_meyers`, `jordanmeyers` → `jordanmeyers`). People reuse a single
/// handle across services with different separators; this is the comparison
/// the match needs.
fn canonical_handle(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '.' | '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// True if `handle` (already canonicalised) is too generic to identify a
/// person — a placeholder username or a role mailbox.
fn is_generic_handle(handle: &str) -> bool {
    crate::util::preflight::is_placeholder_username(handle) || GENERIC_HANDLES.contains(&handle)
}

/// AU-034 — Handle reuse linking a username and an email.
///
/// When a discovered `Username` and the local-part of a discovered `Email`
/// share the same separator-insensitive handle (username `jmeyers` ↔
/// `jmeyers@gmail.com`), they very likely belong to the same person — the
/// everyday analyst pivot the kind-specific identity rules don't make
/// (AU-011 is one username across many platforms; AU-020/AU-023 cluster
/// `Person` entities). Gmail-style `+tag` suffixes are stripped before the
/// comparison so `jmeyers+news@…` still matches.
///
/// Gated to stay low-noise:
///   * the handle must be ≥ `MIN_HANDLE_LEN` chars and neither a placeholder
///     nor a role mailbox (`info@`, `admin`, …);
///   * the username and its matched emails must carry ≥ `MIN_DISTINCT_SOURCES`
///     *distinct* evidence sources between them, so a single module that mints
///     both a candidate username and a candidate email from one seed (e.g.
///     `name_intel`) can't self-correlate — the reuse must be independently
///     observed. This mirrors the ≥2-source gate AU-001/AU-023 use.
pub(super) fn rule_au_034_handle_reuse_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const MIN_HANDLE_LEN: usize = 4;
    const MIN_DISTINCT_SOURCES: usize = 2;

    let usernames = entities_of_kind(entities, EntityKind::Username);
    let emails = entities_of_kind(entities, EntityKind::Email);
    if usernames.is_empty() || emails.is_empty() {
        return Vec::new();
    }

    // Bucket emails by the canonical handle of their local-part ONCE — O(E) —
    // instead of recomputing `canonical_handle` for every email inside the
    // per-username loop (which was O(U×E) String allocations and dominated the
    // whole correlation pass on large scans). Each username then resolves its
    // matches with a single hash lookup, making the rule O(U + E).
    let mut emails_by_handle: HashMap<String, Vec<&Entity>> = HashMap::new();
    for e in &emails {
        // local-part, minus any Gmail-style `+tag` suffix.
        let local = e.value.split('@').next().unwrap_or_default();
        let base = local.split('+').next().unwrap_or_default();
        if !base.is_empty() {
            emails_by_handle
                .entry(canonical_handle(base))
                .or_default()
                .push(e);
        }
    }

    let mut out = Vec::new();
    for u in &usernames {
        let handle = canonical_handle(&u.value);
        if handle.len() < MIN_HANDLE_LEN || is_generic_handle(&handle) {
            continue;
        }
        let Some(matches) = emails_by_handle.get(&handle) else {
            continue;
        };
        let mut sources: HashSet<&str> = u.evidence_sources();
        let mut matched_uids: Vec<String> = Vec::with_capacity(matches.len());
        let mut matched_values: Vec<&str> = Vec::with_capacity(matches.len());
        for e in matches {
            matched_uids.push(e.uid.clone());
            matched_values.push(e.value.as_str());
            sources.extend(e.evidence_sources());
        }
        if sources.len() < MIN_DISTINCT_SOURCES {
            continue;
        }
        matched_uids.sort_unstable();
        matched_values.sort_unstable();
        let mut uids = Vec::with_capacity(1 + matched_uids.len());
        uids.push(u.uid.clone());
        uids.extend(matched_uids);
        out.push(Correlation::new(
            "AU-034",
            "Handle reuse (username \u{2194} email)",
            Severity::Medium,
            format!(
                "Username '{}' shares its handle with {} email(s): {}",
                u.value,
                matched_values.len(),
                matched_values.join(", ")
            ),
            uids,
            scan_id,
            ts,
        ));
    }
    out
}

/// Modules that *derive* a username by inference — a name permutation, an email
/// local-part, or a handle variant — rather than observing it on a platform.
const USERNAME_DERIVATION_SOURCES: &[&str] = &["name_intel", "email_parse", "username_variants"];

/// Modules that *discover* a username by observing it live on a real platform /
/// corpus, confirming the handle exists.
const USERNAME_DISCOVERY_SOURCES: &[&str] = &[
    "username_search",
    "github_user",
    "keybase",
    "social_probe",
    "proxycurl",
    "epieos",
    "see_know",
    "oathnet_pro",
];

/// AU-035 — Inferred handle confirmed in the wild.
///
/// A `Username` that was first *derived* by inference (a name permutation from
/// `name_intel`, an email local-part from `email_parse`, or a handle variant
/// from `username_variants`) and then *independently observed* on a real
/// platform (`username_search`, `github_user`, `keybase`, …) is a high-value
/// identity hit: a guessed handle that turned out to exist. This is the payoff
/// the derivation modules set up but no rule surfaced — distinct from AU-011
/// (one handle across many platforms) and AU-034 (username ↔ email handle
/// reuse). Both an inference source and a discovery source must be present on
/// the same merged entity, so a handle that was only ever observed (a normal
/// find) or only ever guessed (an unconfirmed candidate) does not fire.
pub(super) fn rule_au_035_confirmed_derived_handle(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Username) {
        let sources = e.evidence_sources();
        let mut inferred_by: Vec<&str> = sources
            .iter()
            .copied()
            .filter(|s| USERNAME_DERIVATION_SOURCES.contains(s))
            .collect();
        let mut confirmed_by: Vec<&str> = sources
            .iter()
            .copied()
            .filter(|s| USERNAME_DISCOVERY_SOURCES.contains(s))
            .collect();
        if inferred_by.is_empty() || confirmed_by.is_empty() {
            continue;
        }
        inferred_by.sort_unstable();
        confirmed_by.sort_unstable();
        out.push(Correlation::new(
            "AU-035",
            "Inferred handle confirmed in the wild",
            Severity::Medium,
            format!(
                "Handle '{}' was inferred ({}) and then independently confirmed ({})",
                e.value,
                inferred_by.join(", "),
                confirmed_by.join(", ")
            ),
            vec![e.uid.clone()],
            scan_id,
            ts,
        ));
    }
    out
}

/// AU-036 — Email alias convergence (one mailbox).
///
/// Multiple distinct addresses that `email_canonical` reduced to the SAME
/// mailbox (e.g. `j.doe@gmail.com` and `jdoe+news@gmail.com` both →
/// `jdoe@gmail.com`) are aliases of a single inbox: a strong same-person link
/// and useful intel in itself. Reads the canonical `Email` entity's
/// accumulated `email_canonical` evidence — each record carries the
/// `source_email` it was folded from (the per-source summaries survive the
/// merge-dedup) — and fires when ≥2 distinct source addresses converged. This
/// closes the `email_canonical` loop the way AU-035 closes the handle-
/// derivation loop. Deterministic; no module logic is duplicated.
pub(super) fn rule_au_036_email_alias_convergence(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Email) {
        let mut aliases: Vec<&str> = e
            .evidence
            .iter()
            .filter(|ev| ev.source == "email_canonical")
            .filter_map(|ev| ev.attributes.get("source_email").map(String::as_str))
            .collect();
        aliases.sort_unstable();
        aliases.dedup();
        if aliases.len() >= 2 {
            out.push(Correlation::new(
                "AU-036",
                "Email alias convergence (one mailbox)",
                Severity::Medium,
                format!(
                    "{} addresses resolve to one mailbox '{}': {}",
                    aliases.len(),
                    e.value,
                    aliases.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

/// Tags that mark an entity as known-bad for adjacency analysis.
const ADJACENCY_BAD_TAGS: &[&str] = &["malicious", "threat-intel", "vulnerable"];

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
pub(super) fn rule_au_031_malicious_adjacency(
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
                .map(|u| u.to_string())
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

/// Minimum members for a co-location cluster to be reported.
const COLOCATION_CLUSTER_MIN: usize = 3;

/// AU-032 — Geographic co-location cluster (graph-aware). Walks the
/// `CoLocatedWith` edge graph and reports each connected component of
/// `COLOCATION_CLUSTER_MIN`+ Coordinates entities — i.e. three or more
/// independent coordinate sources that transitively converge within
/// `CO_LOCATION_KM`. This is the graph-structural (transitive-closure) signal
/// the pairwise geo rules (AU-017/AU-030) don't surface. Deterministic:
/// component membership is edge-defined and the output is uid-sorted.
pub(super) fn rule_au_032_colocation_cluster(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{HashMap, HashSet};

    // Undirected adjacency from CoLocatedWith edges only.
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for r in relations {
        if r.kind == RelationKind::CoLocatedWith {
            adj.entry(r.from_uid.as_str()).or_default().push(&r.to_uid);
            adj.entry(r.to_uid.as_str()).or_default().push(&r.from_uid);
        }
    }
    if adj.is_empty() {
        return Vec::new();
    }

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    // Connected components via DFS (stack). Iterate seed nodes in sorted order
    // so the emitted clusters are deterministic regardless of edge ordering.
    let mut nodes: Vec<&str> = adj.keys().copied().collect();
    nodes.sort_unstable();
    let mut visited: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for &start in &nodes {
        if !visited.insert(start) {
            continue;
        }
        let mut comp = vec![start];
        let mut stack = vec![start];
        while let Some(n) = stack.pop() {
            if let Some(neighbours) = adj.get(n) {
                for &m in neighbours {
                    if visited.insert(m) {
                        comp.push(m);
                        stack.push(m);
                    }
                }
            }
        }
        if comp.len() >= COLOCATION_CLUSTER_MIN {
            comp.sort_unstable();
            let sample = by_uid.get(comp[0]).map_or(comp[0], |e| e.value.as_str());
            let uids: Vec<String> = comp.iter().map(|u| (*u).to_string()).collect();
            out.push(Correlation::new(
                "AU-032",
                "Geographic co-location cluster",
                Severity::Medium,
                format!(
                    "{} coordinates converge within {:.0} km (e.g. {})",
                    comp.len(),
                    crate::core::relation::CO_LOCATION_KM,
                    sample
                ),
                uids,
                scan_id,
                ts,
            ));
        }
    }
    out
}

/// AU-037 — Plaintext credential exposure.
///
/// The single most actionable OSINT finding: an actual leaked secret. The
/// breach/stealer modules surface the canonical secret as a first-class
/// `Password` / `Credential` entity (distinct from `ApiKey`, which AU-021
/// covers), but nothing previously synthesised them into an alert. This fires
/// CRITICAL when any are present, links the secret entities (capped) plus the
/// exposed identity (emails/usernames) so the operator sees *whose* credentials
/// leaked, and reports only COUNTS — the raw secret values stay in the entities
/// (full-fidelity policy) and are never copied into correlation text.
pub(super) fn rule_au_037_credential_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let secrets: Vec<&Entity> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Password | EntityKind::Credential))
        .collect();
    if secrets.is_empty() {
        return Vec::new();
    }
    let passwords = secrets
        .iter()
        .filter(|e| e.kind == EntityKind::Password)
        .count();
    let credentials = secrets.len() - passwords;

    // Affected secrets first (capped), then the identity they pertain to.
    let mut uids: Vec<String> = secrets.iter().take(20).map(|e| e.uid.clone()).collect();
    uids.extend(
        entities
            .iter()
            .filter(|e| matches!(e.kind, EntityKind::Email | EntityKind::Username))
            .take(5)
            .map(|e| e.uid.clone()),
    );

    let mut parts = Vec::new();
    if passwords > 0 {
        parts.push(format!(
            "{passwords} plaintext password{}",
            if passwords == 1 { "" } else { "s" }
        ));
    }
    if credentials > 0 {
        parts.push(format!(
            "{credentials} credential record{}",
            if credentials == 1 { "" } else { "s" }
        ));
    }
    vec![Correlation::new(
        "AU-037",
        "Plaintext credential exposure",
        Severity::Critical,
        format!(
            "{} exposed in breach/stealer data — the affected identity's secret(s) are directly recoverable",
            parts.join(" and ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-038 — Verified cross-platform identity.
///
/// Two modules independently confirm the target's OWN profile (not a mention):
/// `social_probe` tags a `Url` `social-profile` after a direct platform probe of
/// the exact handle, and `search_engines` tags one `confirmed-profile` when the
/// searched handle is the exact path on a canonical social host (corroborated by
/// the returning engines). Either tag denotes a verified profile; the direct
/// probe is the stronger signal. When the same identity is confirmed on ≥2
/// DISTINCT platforms, that is a strong, engine-/probe-verified cross-platform
/// identity worth synthesising. Complements AU-011, which needs
/// `username_search`'s `platforms_count`: AU-038 fires from the search-engine or
/// social-probe signal alone, so either source surfaces the cross-platform
/// identity on its own.
pub(super) fn rule_au_038_verified_cross_platform_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeSet;
    let confirmed: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Url
                && (e.has_tag("confirmed-profile") || e.has_tag("social-profile"))
        })
        .collect();
    // Distinct registrable-ish hosts among the confirmed profiles (www-stripped).
    let hosts: BTreeSet<String> = confirmed
        .iter()
        .filter_map(|e| url::Url::parse(&e.value).ok())
        .filter_map(|u| {
            u.host_str()
                .map(|h| h.trim_start_matches("www.").to_lowercase())
        })
        .collect();
    if hosts.len() < 2 {
        return Vec::new();
    }
    let uids: Vec<String> = confirmed.iter().map(|e| e.uid.clone()).collect();
    vec![Correlation::new(
        "AU-038",
        "Verified cross-platform identity",
        Severity::Medium,
        format!(
            "Identity confirmed on {} distinct platforms: {}",
            hosts.len(),
            hosts.into_iter().collect::<Vec<_>>().join(", ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

// ─── Crypto / identity / exposure rules (AU-039 … AU-043) ────────────────────
//
// These exploit signal that earlier rules never saw: first-class crypto wallet
// addresses (`chain_intel`, breach-harvested), ENS-derived handles, PGP-key
// linked emails, and public paste exposure (`psbdmp`). Each turns a raw
// enrichment into a ranked, actionable finding.

/// True when a wallet was genuinely *recovered from breach/stealer data* — not
/// merely seen in some API response. Precision matters: the universal
/// `found_keys` scanner harvests crypto addresses from EVERY response body
/// (including `chain_intel`'s own blockchain-explorer replies, which list
/// contract/related addresses), so a bare `retrieved` tag would mislabel an
/// explorer artifact as a leak. We therefore require either:
///   * a breach-record-field harvest (`key_harvest::emit_key`, whose evidence
///     source is `oathnet_pro` — the shared path both breach pools use), or
///   * a `found_keys` hit whose `source_provider` is an actual breach pool.
fn is_breach_exposed_wallet(e: &Entity) -> bool {
    e.evidence.iter().any(|ev| {
        let src = ev.source.as_str();
        src == "oathnet_pro"
            || src == "see_know"
            || (src == "found_keys"
                && ev
                    .attributes
                    .get("source_provider")
                    .is_some_and(|p| matches!(p.as_str(), "see-know" | "oathnet")))
    })
}

/// AU-039 — a cryptocurrency wallet co-occurring with a real identity (Person or
/// Email) in the same confirmed scan: an attribution lead linking on-chain funds
/// to a person. Co-presence, not proof, so `High` (warrants attention) rather
/// than `Critical`. One firing per wallet, anchored to the most specific
/// identity present (Person preferred over Email).
pub(super) fn rule_au_039_wallet_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let wallets = entities_of_kind(entities, EntityKind::CryptoAddress);
    if wallets.is_empty() {
        return Vec::new();
    }
    let anchor = entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .or_else(|| entities.iter().find(|e| e.kind == EntityKind::Email));
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
pub(super) fn rule_au_040_wallet_breach_exposure(
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
pub(super) fn rule_au_041_ens_identity(
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

/// AU-042 — two or more email addresses bound to the same PGP key (`pgp` module):
/// strong same-owner evidence (the key holder asserted these are theirs).
/// `High`. One grouped firing over all key-linked emails.
pub(super) fn rule_au_042_pgp_email_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let linked: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email && e.has_tag("pgp-linked"))
        .collect();
    if linked.is_empty() {
        return Vec::new();
    }
    let mut addrs: Vec<&str> = linked.iter().map(|e| e.value.as_str()).collect();
    addrs.sort_unstable();
    let uids: Vec<String> = linked.iter().map(|e| e.uid.clone()).collect();
    vec![Correlation::new(
        "AU-042",
        "PGP key binds multiple emails to one identity",
        Severity::High,
        format!(
            "A PGP key links {} email address(es) to one owner: {}",
            addrs.len(),
            addrs.join(", ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-043 — the subject's data appears in one or more public pastes (`psbdmp`):
/// a public-exposure signal that corroborates breach findings. `Medium`. One
/// grouped firing over all paste URLs.
pub(super) fn rule_au_043_paste_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let pastes: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url && e.has_tag(crate::core::tags::PASTE_EXPOSED))
        .collect();
    if pastes.is_empty() {
        return Vec::new();
    }
    let uids: Vec<String> = pastes.iter().map(|e| e.uid.clone()).collect();
    vec![Correlation::new(
        "AU-043",
        "Public paste exposure",
        Severity::Medium,
        format!("Subject data found in {} public paste(s)", pastes.len()),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-044 — Shared web-analytics ID ⇒ common ownership. A Google Analytics /
/// AdSense / Tag-Manager / Facebook-Pixel id that appears on two or more
/// otherwise-unrelated sites is strong evidence the same operator runs them — the
/// "affiliate" pivot. `web_crawler` records the carrying site in each
/// `TrackingId` evidence entry's `source_domain`; entities merge by value, so a
/// shared id accumulates one evidence row per site. Fires when ≥2 distinct sites
/// carry the same id.
pub(super) fn rule_au_044_shared_tracking_id(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::TrackingId)
        .filter_map(|e| {
            let mut sites: Vec<&str> = e
                .evidence
                .iter()
                .filter_map(|ev| ev.attributes.get("source_domain").map(String::as_str))
                .collect();
            sites.sort_unstable();
            sites.dedup();
            if sites.len() < 2 {
                return None;
            }
            Some(Correlation::new(
                "AU-044",
                "Shared web-analytics ID (common ownership)",
                Severity::High,
                format!(
                    "Tracking id '{}' appears on {} sites ({}) — a shared analytics/ads id \
                     indicates the sites share an owner or operator",
                    e.value,
                    sites.len(),
                    sites.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ))
        })
        .collect()
}
