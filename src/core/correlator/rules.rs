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
    // Relevance gate: only Probable-or-better (≥0.50) entities may anchor a
    // Critical identity cluster. Without it, speculative leads — notably
    // `name_to_username`'s 0.35-confidence derived usernames — would raise a
    // Critical correlation on any scan that also surfaced an unrelated email
    // and phone, a false positive. Mirrors the ≥0.50 floor used by AU-020.
    const MIN_CONF: f64 = 0.50;
    let pick = |kind| -> Vec<&Entity> {
        entities_of_kind(entities, kind)
            .into_iter()
            .filter(|e| e.confidence >= MIN_CONF)
            .collect()
    };
    let emails = pick(EntityKind::Email);
    let usernames = pick(EntityKind::Username);
    let phones = pick(EntityKind::Phone);

    if emails.is_empty() || usernames.is_empty() || phones.is_empty() {
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
    }]
}

pub(super) fn rule_au_003_high_corroboration(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let min_corr = |kind: &crate::core::entity::EntityKind| -> u32 {
        match kind {
            EntityKind::Domain | EntityKind::Url => 5,
            EntityKind::IpAddress => 4,
            _ => 3,
        }
    };
    entities
        .iter()
        .filter(|e| e.corroboration >= min_corr(&e.kind))
        .map(|e| Correlation {
            rule_id: "AU-003".into(),
            rule_name: "High cross-source corroboration".into(),
            severity: Severity::Medium,
            description: format!(
                "{} entity '{}' corroborated by {} independent sources (C_eff={:.3})",
                e.kind,
                e.value,
                e.corroboration,
                e.c_effective()
            ),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
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
                        sources.len().max(hits.len())
                    ),
                    entity_uids: vec![e.uid.clone()],
                    scan_id: scan_id.into(),
                    ts,
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
            c.evidence
                .iter()
                .any(|ev| breach_ips.iter().any(|ip| ev.summary.contains(&ip.value)))
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
                // `get(..10)` yields the leading `YYYY-MM-DD` only when byte 10
                // is a char boundary — char-safe (a raw `&d[..10]` would panic
                // on a multi-byte codepoint in untrusted breach data) and also
                // subsumes the length check.
                if let Some(d) = ev.attributes.get(field)
                    && let Some(date10) = d.get(..10)
                {
                    breach_dates.push((e, date10));
                }
            }
        }
    }
    if breach_dates.len() < 3 {
        return Vec::new();
    }
    breach_dates.sort_by_key(|(_, d)| *d);
    // Single-linkage clustering: consecutive breaches no more than 30 days
    // apart chain into one cluster. A chain can therefore span well beyond
    // 30 days end-to-end, so each cluster carries its actual (start, end)
    // window for a truthful description rather than the old fixed
    // "within 30 days" claim, which was false whenever ≥3 breaches chained
    // across a longer period.
    let mut clusters: Vec<(Vec<String>, &str, &str)> = Vec::new();
    let mut current: Vec<String> = vec![breach_dates[0].0.uid.clone()];
    let mut start_date = breach_dates[0].1;
    let mut prev_date = breach_dates[0].1;
    for &(e, d) in &breach_dates[1..] {
        let days_apart = date_diff_days(prev_date, d);
        if days_apart <= 30 {
            if !current.contains(&e.uid) {
                current.push(e.uid.clone());
            }
        } else {
            if current.len() >= 3 {
                clusters.push((current.clone(), start_date, prev_date));
            }
            current = vec![e.uid.clone()];
            start_date = d;
        }
        prev_date = d;
    }
    if current.len() >= 3 {
        clusters.push((current, start_date, prev_date));
    }
    clusters
        .into_iter()
        .map(|(uids, start, end)| {
            let span = date_diff_days(start, end);
            Correlation {
                rule_id: "AU-019".into(),
                rule_name: "Temporal breach cluster".into(),
                severity: Severity::High,
                description: format!(
                    "{} breach entities span {start}…{end} ({span}-day window, \
                     consecutive gaps ≤30d) — potential coordinated compromise",
                    uids.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
            }
        })
        .collect()
}

/// Days since 1970-01-01 in the proleptic Gregorian calendar. Exact —
/// accounts for leap years and real month lengths — and dependency-free
/// (Howard Hinnant's `days_from_civil`). Replaces the old
/// `y*365 + m*30 + d` approximation, which drifted by up to ~5 days near
/// year boundaries (e.g. 2020-01-01 → 2020-12-31 is 365 days, not 360) and
/// so mis-decided AU-019's "≤ 30 days apart" breach clustering at month and
/// year edges.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

pub(super) fn date_diff_days(a: &str, b: &str) -> u64 {
    let parse = |s: &str| -> Option<i64> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            return None;
        }
        let y: i64 = parts[0].parse().ok()?;
        let m: i64 = parts[1].parse().ok()?;
        let d: i64 = parts[2].parse().ok()?;
        // Reject out-of-range components so a garbage "date" can't masquerade
        // as a near neighbour and wrongly extend a cluster.
        if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
            return None;
        }
        Some(days_from_civil(y, m, d))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_diff_days_is_calendar_exact() {
        // Same day.
        assert_eq!(date_diff_days("2023-06-15", "2023-06-15"), 0);
        // One month with a 30-day June.
        assert_eq!(date_diff_days("2023-06-15", "2023-07-15"), 30);
        // Full leap year: 2020-01-01 → 2020-12-31 is 365 days (old y*365+m*30+d
        // gave 360 — the bug this fix removes).
        assert_eq!(date_diff_days("2020-01-01", "2020-12-31"), 365);
        // Full non-leap year span is 364 days end-to-end.
        assert_eq!(date_diff_days("2023-01-01", "2023-12-31"), 364);
        // Leap-day boundary: Feb 28 → Mar 1 is 2 days in 2020 (Feb 29 exists)…
        assert_eq!(date_diff_days("2020-02-28", "2020-03-01"), 2);
        // …and 1 day in a non-leap year.
        assert_eq!(date_diff_days("2021-02-28", "2021-03-01"), 1);
    }

    #[test]
    fn date_diff_days_is_symmetric() {
        assert_eq!(
            date_diff_days("2022-11-03", "2023-02-17"),
            date_diff_days("2023-02-17", "2022-11-03")
        );
    }

    #[test]
    fn date_diff_days_rejects_malformed_or_out_of_range() {
        // Unparseable / wrong arity / out-of-range → MAX, so it never reads as
        // a near neighbour that could wrongly extend a breach cluster.
        assert_eq!(date_diff_days("not-a-date", "2020-01-01"), u64::MAX);
        assert_eq!(date_diff_days("2020-01", "2020-01-01"), u64::MAX);
        assert_eq!(date_diff_days("2020-13-01", "2020-01-01"), u64::MAX);
        assert_eq!(date_diff_days("2020-00-10", "2020-01-01"), u64::MAX);
        assert_eq!(date_diff_days("2020-02-32", "2020-01-01"), u64::MAX);
    }

    #[test]
    fn breach_cluster_uses_exact_30_day_boundary() {
        // Exactly 30 days apart clusters; 31 does not. With the old
        // approximation these month-crossing pairs were off by a day.
        assert!(date_diff_days("2023-06-15", "2023-07-15") <= 30);
        assert!(date_diff_days("2023-06-15", "2023-07-16") > 30);
    }

    fn breach_entity(uid_seed: &str, date: &str) -> Entity {
        use crate::core::entity::Evidence;
        let mut e = Entity::new(EntityKind::Email, format!("{uid_seed}@x.com"), 0.9, "sid");
        e.tag("breach");
        e.add_evidence(Evidence::new("hibp", "seen in breach").with_attr("breach_date", date));
        e
    }

    #[test]
    fn au_019_reports_true_window_span_not_a_fixed_30_days() {
        // Three breaches that chain (gaps 19d then 21d) span 40 days end to
        // end. The old description always claimed "within 30 days"; the rule
        // must now report the real 40-day window so the analyst isn't misled.
        let entities = vec![
            breach_entity("a", "2023-01-01"),
            breach_entity("b", "2023-01-20"),
            breach_entity("c", "2023-02-10"),
        ];
        let out = rule_au_019_temporal_breach_cluster(&entities, "sid", 0);
        assert_eq!(out.len(), 1, "the three breaches single-link into one cluster");
        let c = &out[0];
        assert_eq!(c.rule_id, "AU-019");
        assert_eq!(c.entity_uids.len(), 3);
        assert!(
            c.description.contains("40-day window"),
            "must state the true span, got: {}",
            c.description
        );
        assert!(c.description.contains("2023-01-01…2023-02-10"));
        assert!(
            !c.description.contains("within 30 days"),
            "stale misleading claim must be gone"
        );
    }

    #[test]
    fn au_019_requires_at_least_three_breaches() {
        let entities = vec![
            breach_entity("a", "2023-01-01"),
            breach_entity("b", "2023-01-10"),
        ];
        assert!(rule_au_019_temporal_breach_cluster(&entities, "sid", 0).is_empty());
    }

    fn ent(kind: EntityKind, val: &str, conf: f64) -> Entity {
        Entity::new(kind, val, conf, "sid")
    }

    #[test]
    fn au_002_ignores_speculative_low_confidence_leads() {
        // A real email + phone plus only a speculative 0.35 derived username
        // (what name_to_username emits) must NOT raise a Critical identity
        // cluster — the username is below the Probable floor.
        let entities = vec![
            ent(EntityKind::Email, "a@x.com", 0.9),
            ent(EntityKind::Phone, "+15551234567", 0.9),
            ent(EntityKind::Username, "jmeyer", 0.35),
        ];
        assert!(
            rule_au_002_identity_cluster(&entities, "sid", 0).is_empty(),
            "0.35 username must not anchor a Critical cluster"
        );
    }

    #[test]
    fn au_002_fires_and_includes_only_qualifying_entities() {
        // All three facets present at/above the floor → one Critical cluster.
        // A second, low-confidence username must be excluded from the uids.
        let entities = vec![
            ent(EntityKind::Email, "a@x.com", 0.9),
            ent(EntityKind::Username, "realhandle", 0.7),
            ent(EntityKind::Username, "speculative", 0.30),
            ent(EntityKind::Phone, "+15551234567", 0.8),
        ];
        let out = rule_au_002_identity_cluster(&entities, "sid", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Critical);
        // email + 1 qualifying username + phone = 3 (the 0.30 username dropped).
        assert_eq!(
            out[0].entity_uids.len(),
            3,
            "low-confidence username must be excluded from the cluster"
        );
    }
}
