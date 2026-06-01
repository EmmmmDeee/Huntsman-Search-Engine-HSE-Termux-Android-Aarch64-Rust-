use std::collections::HashSet;

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
        "search_engines:oathnet",
        "emailrep",
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
        .filter(|e| e.has_tag("malicious"))
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
        .filter(|e| EXPOSURE_TAGS.iter().any(|t| e.has_tag(t)))
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
            let sources = e.evidence_sources();
            if hits.len() >= 2 || sources.len() >= 2 {
                Some(Correlation {
                    rule_id: "AU-014".into(),
                    rule_name: "Geolocation cluster".into(),
                    severity: Severity::Medium,
                    description: format!(
                        "Coordinates '{}' confirmed by {} geo source(s)",
                        e.value,
                        // Report the true independent-source count, not
                        // `max(sources, tag_hits)` — 2 matching tags on a
                        // single-source entity must not read as "2 geo sources".
                        sources.len()
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
        .filter(|e| e.has_tag("threat-intel"))
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
                    .any(|ip| summary_mentions_ip(&ev.summary, &ip.value))
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
    let mut clusters: Vec<Vec<&Entity>> = Vec::new();
    for c in &coords {
        let parts: Vec<&str> = c.value.split(',').collect();
        let (lat, lon) = match (parts.first(), parts.get(1)) {
            (Some(a), Some(b)) => match (a.trim().parse::<f64>(), b.trim().parse::<f64>()) {
                (Ok(la), Ok(lo)) => (la, lo),
                _ => continue,
            },
            _ => continue,
        };
        let mut found = false;
        for cluster in &mut clusters {
            let rep = cluster[0];
            let rp: Vec<&str> = rep.value.split(',').collect();
            if let (Some(a), Some(b)) = (rp.first(), rp.get(1))
                && let (Ok(rl), Ok(ro)) = (a.trim().parse::<f64>(), b.trim().parse::<f64>())
                && (lat - rl).abs() < 0.5
                && (lon - ro).abs() < 0.5
            {
                cluster.push(c);
                found = true;
                break;
            }
        }
        if !found {
            clusters.push(vec![c]);
        }
    }
    clusters
        .into_iter()
        .filter(|cl| cl.len() >= 2)
        .map(|cl| {
            let uids: Vec<String> = cl.iter().map(|e| e.uid.clone()).collect();
            let sources: HashSet<&str> = cl
                .iter()
                .flat_map(|e| e.evidence.iter().map(|ev| ev.source.as_str()))
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
                // `d.get(..10)` is char-boundary-safe: byte slicing `&d[..10]`
                // panics if byte 10 lands mid-char (a non-ASCII date attribute
                // from external evidence) — process-fatal under panic=abort.
                // `get` also subsumes the length check (None if shorter than 10).
                if let Some(d) = ev.attributes.get(field)
                    && let Some(d10) = d.get(..10)
                {
                    breach_dates.push((e, d10));
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
    let mut prev_date = breach_dates[0].1;
    for &(e, d) in &breach_dates[1..] {
        let days_apart = date_diff_days(prev_date, d);
        if days_apart <= 30 {
            if !current.contains(&e.uid) {
                current.push(e.uid.clone());
            }
        } else {
            if current.len() >= 3 {
                clusters.push(current);
            }
            current = vec![e.uid.clone()];
        }
        prev_date = d;
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

pub(super) fn date_diff_days(a: &str, b: &str) -> u64 {
    // True calendar day count via the shared civil-day serial number. The
    // previous `y*365 + m*30 + d` model mismeasured across month/year
    // boundaries (e.g. 2023-12-31 → 2024-01-01 is 1 day but computed as 5),
    // wrongly splitting/merging the breach-date clusters AU-019 keys on this.
    let parse = |s: &str| -> Option<i64> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            return None;
        }
        let y: i64 = parts[0].parse().ok()?;
        let m: i64 = parts[1].parse().ok()?;
        let d: i64 = parts[2].parse().ok()?;
        if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
            return None;
        }
        Some(crate::core::timeline::days_from_civil(y, m, d))
    };
    match (parse(a), parse(b)) {
        (Some(da), Some(db)) => da.abs_diff(db),
        _ => u64::MAX,
    }
}

/// True if `summary` mentions `ip` as a whole IP token, not as a substring of a
/// larger literal. `"Geolocation for 11.2.3.40".contains("1.2.3.4")` is `true`,
/// so AU-016 would otherwise chain a breach IP to a coordinate geolocated for a
/// DIFFERENT IP. We require the match not to be flanked by a hex digit or `.`
/// (i.e. not part of a longer numeric IP literal). `:` is deliberately NOT a
/// boundary char: these summaries use it as the IP→text separator
/// ("Geolocation for 1.2.3.4: …"), so treating it as a continuation would reject
/// the legitimate match. The remaining v6-substring-of-v6 edge is bounded by the
/// hex-digit guard and is not a real concern for full breach-IP values.
pub(super) fn summary_mentions_ip(summary: &str, ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    let is_ip_char = |b: u8| b.is_ascii_hexdigit() || b == b'.';
    let bytes = summary.as_bytes();
    let mut from = 0;
    while let Some(rel) = summary[from..].find(ip) {
        let start = from + rel;
        let end = start + ip.len();
        let before_ok = start == 0 || !is_ip_char(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ip_char(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1; // ip is ASCII, so start+1 is a char boundary
        if from >= summary.len() {
            break;
        }
    }
    false
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

    let mut all_sources: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for e in &geo_entities {
        for src in e.evidence_sources() {
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
/// Australian registry (`abn_lookup` → `abr`, `opencorporates`). Surfaces the
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
            e.kind == EntityKind::Organisation && (e.has_tag("abr") || e.has_tag("opencorporates"))
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

    let mut out = Vec::new();
    for u in &usernames {
        let handle = canonical_handle(&u.value);
        if handle.len() < MIN_HANDLE_LEN || is_generic_handle(&handle) {
            continue;
        }
        let mut sources: HashSet<&str> = u.evidence_sources();
        let mut matched_uids: Vec<String> = Vec::new();
        let mut matched_values: Vec<&str> = Vec::new();
        for e in &emails {
            // local-part, minus any Gmail-style `+tag` suffix.
            let local = e.value.split('@').next().unwrap_or_default();
            let base = local.split('+').next().unwrap_or_default();
            if !base.is_empty() && canonical_handle(base) == handle {
                matched_uids.push(e.uid.clone());
                matched_values.push(e.value.as_str());
                sources.extend(e.evidence_sources());
            }
        }
        if matched_uids.is_empty() || sources.len() < MIN_DISTINCT_SOURCES {
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
/// threat-intel / vulnerable). This is the attribution pathway the flat entity
/// list can't show: a subdomain of a malicious apex, an entity derived from a
/// flagged node during expansion, or coordinates co-located with bad infra.
///
/// Fires once per benign↔bad edge (exactly one endpoint bad — edges between two
/// already-flagged nodes are left to AU-004/AU-008/AU-015). Deterministic.
pub(super) fn rule_au_031_malicious_adjacency(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::HashMap;

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let bad_reason = |e: &Entity| -> Option<&'static str> {
        ADJACENCY_BAD_TAGS.iter().copied().find(|t| e.has_tag(t))
    };

    let mut out = Vec::new();
    for r in relations {
        let (Some(&from), Some(&to)) = (
            by_uid.get(r.from_uid.as_str()),
            by_uid.get(r.to_uid.as_str()),
        ) else {
            continue;
        };
        // Exactly one endpoint flagged → the other is "adjacent to bad".
        // Edges between two already-flagged nodes are left to AU-004/008/015.
        let (benign, bad, reason) = match (bad_reason(from), bad_reason(to)) {
            (None, Some(reason)) => (from, to, reason),
            (Some(reason), None) => (to, from, reason),
            _ => continue,
        };
        out.push(Correlation::new(
            "AU-031",
            "Adjacency to known-bad infrastructure",
            Severity::High,
            format!(
                "{} ({}) is {} flagged-{} {} ({})",
                benign.value, benign.kind, r.kind, reason, bad.value, bad.kind
            ),
            vec![benign.uid.clone(), bad.uid.clone()],
            scan_id,
            ts,
        ));
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

    // Confirmed-entity lookup. AU-032 receives `entities` already filtered to
    // confirmed-only (candidates quarantined), but `relations` is UNfiltered, so
    // build adjacency ONLY from edges whose BOTH endpoints are confirmed —
    // mirroring AU-031's guard. Without this a quarantined `candidate` coordinate
    // leaks into the cluster (and inflates the "N coordinates converge" count),
    // defeating the candidate quarantine the relation rules are meant to honour.
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    // Undirected adjacency from CoLocatedWith edges between confirmed entities.
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for r in relations {
        if r.kind == RelationKind::CoLocatedWith
            && by_uid.contains_key(r.from_uid.as_str())
            && by_uid.contains_key(r.to_uid.as_str())
        {
            adj.entry(r.from_uid.as_str()).or_default().push(&r.to_uid);
            adj.entry(r.to_uid.as_str()).or_default().push(&r.from_uid);
        }
    }
    if adj.is_empty() {
        return Vec::new();
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_diff_days_is_calendar_accurate_across_boundaries() {
        // Regression: the old y*365+m*30+d model gave 5 here, mis-clustering.
        assert_eq!(date_diff_days("2024-01-01", "2023-12-31"), 1);
        assert_eq!(date_diff_days("2023-02-15", "2023-01-15"), 31); // Jan = 31 days
        assert_eq!(date_diff_days("2024-03-01", "2024-02-28"), 2); // 2024 is leap
        assert_eq!(date_diff_days("2020-06-15", "2020-06-15"), 0);
        assert_eq!(date_diff_days("garbage", "2020-01-01"), u64::MAX);
        assert_eq!(date_diff_days("2020-13-40", "2020-01-01"), u64::MAX); // invalid m/d
    }

    #[test]
    fn summary_mentions_ip_requires_a_token_boundary() {
        assert!(summary_mentions_ip(
            "Geolocation for 1.2.3.4: Brisbane",
            "1.2.3.4"
        ));
        assert!(summary_mentions_ip("1.2.3.4", "1.2.3.4"));
        assert!(summary_mentions_ip("(1.2.3.4)", "1.2.3.4"));
        // The substring-in-a-larger-IP false positives that motivated the fix.
        assert!(!summary_mentions_ip("Geolocation for 11.2.3.40", "1.2.3.4"));
        assert!(!summary_mentions_ip("110.0.0.1 is the host", "10.0.0.1"));
        assert!(!summary_mentions_ip("", "1.2.3.4"));
    }
}
