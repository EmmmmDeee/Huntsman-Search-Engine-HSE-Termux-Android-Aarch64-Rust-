use super::*;

pub(in crate::core::correlator) fn rule_au_018_email_address_colocation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Single pass partitions the two member classes instead of filtering the
    // entity list twice (once for emails, once for addresses/coordinates).
    let mut emails: Vec<&Entity> = Vec::new();
    let mut addresses: Vec<&Entity> = Vec::new();
    for e in entities {
        if e.kind == EntityKind::Email && e.confidence >= 0.60 {
            emails.push(e);
        } else if matches!(e.kind, EntityKind::Address | EntityKind::Coordinates)
            && e.confidence >= 0.50
            // Infrastructure geo (a WHOIS registrant filing address, a CDN/host
            // location, an IP-only fix) is not the subject's home — it must not
            // forge an identity↔location linkage with the email.
            && !is_infrastructure_geo(e)
        {
            addresses.push(e);
        }
    }
    if emails.is_empty() || addresses.is_empty() {
        return Vec::new();
    }
    // Include the FULL member set (no `take` cap). Entities only grow during a
    // scan, so the live-pass set is a strict subset of the finalize set — which
    // lets `upsert_correlation`'s containment dedup supersede the live partial
    // with the finalize row. A capped sample (`take(5)`) of a growing collection
    // produced DISJOINT live/finalize sets (different 5 addresses), which the
    // superset-supersede couldn't fold together, so AU-018 persisted twice
    // ("co-located with 6" and "with 9") for one scan.
    let mut uids: Vec<String> = emails.iter().map(|e| e.uid.clone()).collect();
    uids.extend(addresses.iter().map(|e| e.uid.clone()));
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

/// AU-058 — Professional profile geographic signal (T1591.002).
///
/// AU real estate agent profile URLs embed a suburb-level workplace location in
/// the URL slug — no live HTTP fetch required. ratemyagent.com.au slugs follow
/// `/real-estate-agent/<name>-<suburb>-<id>/`; the suburb token is extracted and
/// surfaced as a geographic signal aligned with MITRE T1591.002 (Business
/// Relationships — physical location inferred from professional context).
pub(in crate::core::correlator) fn rule_au_058_professional_profile_geo(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const PROF_HOSTS: &[&str] = &["ratemyagent.com.au", "homely.com.au", "soho.com.au"];

    let mut out = Vec::new();

    for e in entities_of_kind(entities, EntityKind::Url) {
        if e.confidence < 0.45 {
            continue;
        }
        let url_lower = e.value.to_lowercase();
        let Some(host) = PROF_HOSTS.iter().find(|h| url_lower.contains(*h)) else {
            continue;
        };

        let suburb = if host.contains("ratemyagent") {
            extract_ratemyagent_suburb(&e.value)
        } else {
            None
        };

        let Some(suburb) = suburb else {
            continue;
        };

        out.push(Correlation::new(
            "AU-058",
            "Professional profile geographic signal",
            Severity::Medium,
            format!(
                "Real estate agent profile at {host} indicates subject operates in \
                 '{suburb}' — MITRE T1591.002 (Business Relationships)"
            ),
            vec![e.uid.clone()],
            scan_id,
            ts,
        ));
    }

    out
}

/// Extract the suburb token from a ratemyagent.com.au agent URL slug.
///
/// Pattern: `/real-estate-agent/<name>-<suburb>-<id>/`
/// The trailing ID is stripped; the preceding token is the suburb.
pub(super) fn extract_ratemyagent_suburb(url: &str) -> Option<String> {
    let path_start = url.find("/real-estate-agent/")?;
    let slug_area = &url[path_start + "/real-estate-agent/".len()..];
    let slug = slug_area
        .trim_end_matches('/')
        .split('?')
        .next()
        .unwrap_or(slug_area);
    let parts: Vec<&str> = slug.split('-').collect();
    if parts.len() < 4 {
        return None;
    }
    let id = *parts.last()?;
    if !id.chars().all(|c| c.is_ascii_alphanumeric()) || id.len() < 2 {
        return None;
    }
    let suburb = parts[parts.len() - 2];
    if suburb.len() >= 4 && suburb.chars().all(|c| c.is_ascii_alphabetic()) {
        Some(suburb.to_string())
    } else {
        None
    }
}

/// AU-061 — Family geo-corroboration (surname kin in the subject's confirmed area).
///
/// The free, offline SECOND ANGLE on family — the *finding* counterpart to the
/// engine's promotion pass, both built on the one shared detector
/// [`crate::core::geo_family`]. A name scan surfaces `family-candidate`
/// people/addresses (shared surname) at postcode grain, while `signal_radar` /
/// geo give the SUBJECT a confirmed coordinate fix; this keeps the
/// family-candidates within [`crate::core::geo_family::FAMILY_GEO_KM`] of that
/// fix, so "shared surname" and "same area as the subject" independently agree —
/// turning a lone candidate into a reliable relative. Nothing fires without both
/// a confirmed subject coordinate and ≥1 in-area family-candidate.
pub(in crate::core::correlator) fn rule_au_061_family_geo_corroboration(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use crate::core::geo_family::{FAMILY_GEO_KM, distance_to_subject, subject_fixes};

    // The subject's confirmed location(s) — the one shared anchor (a GPS fix OR
    // the subject's own name-matched address), so the correlator and the engine
    // passes agree on where the subject is. Keeps each fix's uid for the edge.
    let subject = subject_fixes(entities);
    if subject.is_empty() {
        return Vec::new();
    }
    let coords: Vec<(f64, f64)> = subject.iter().map(|f| f.coord).collect();

    // Family-candidates within FAMILY_GEO_KM of the subject — nearest first for a
    // deterministic, readable description.
    let mut in_area: Vec<(&Entity, f64)> = entities
        .iter()
        .filter(|e| e.has_tag("family-candidate"))
        .filter_map(|e| {
            distance_to_subject(e, &coords)
                .filter(|&km| km <= FAMILY_GEO_KM)
                .map(|km| (e, km))
        })
        .collect();
    // Accuracy of the "shared surname" claim: the `family-candidate` tag is ALSO
    // applied by the see_know household path to co-located people who do NOT share
    // the subject's surname. When the subject's surname is known, drop such Person
    // candidates — being in the same 150 km region without the shared surname is not
    // a finding (millions share a metro), and asserting "shared surname relative"
    // for them would be a FALSE evidentiary basis. Address family-candidates are
    // surname-matched by their producing module (qld_unclaimed/au_people) and a bare
    // Address carries no surname to re-check, so they are kept.
    let subject_sn = crate::core::geo_family::subject_surname(entities);
    if let Some(sn) = subject_sn.as_deref() {
        in_area.retain(|(e, _)| {
            e.kind != EntityKind::Person
                || crate::util::surnames::surname_of(&e.value).as_deref() == Some(sn)
        });
    }
    if in_area.is_empty() {
        return Vec::new();
    }
    in_area.sort_by(|a, b| {
        a.1.partial_cmp(&b.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.uid.cmp(&b.0.uid))
    });

    let shown: Vec<String> = in_area
        .iter()
        .take(8)
        .map(|(e, km)| format!("{} (~{km:.0} km)", e.value))
        .collect();
    let extra = in_area.len().saturating_sub(shown.len());
    let mut uids: Vec<String> = subject.iter().map(|f| f.uid.clone()).collect();
    uids.extend(in_area.iter().map(|(e, _)| e.uid.clone()));

    // Commonness gate (mirrors AU-051 / the kinship builder): within FAMILY_GEO_KM
    // the namesake pass doesn't fire (it guards only beyond NAMESAKE_GEO_KM), so a
    // COMMON subject surname would otherwise escalate to Critical on three unrelated
    // same-surname people sharing one metro catchment — a confident false "household
    // of relatives". A common surname makes shared-region co-location weak evidence,
    // so it never reaches Critical (stays a High lead) and the wording is softened;
    // a DISTINCTIVE surname keeps the strong "independently corroborate" reading.
    let surname_common = subject_sn
        .as_deref()
        .is_some_and(crate::util::surnames::is_common);
    let severity = if in_area.len() >= 3 && !surname_common {
        Severity::Critical
    } else {
        Severity::High
    };
    let basis = if surname_common {
        "a COMMON surname, so shared region is weak corroboration — verify before treating as kin"
    } else {
        "shared surname AND same area as the subject independently corroborate them as relatives"
    };
    vec![Correlation::new(
        "AU-061",
        "Family geo-corroborated (surname kin in subject's area)",
        severity,
        format!(
            "{} family-candidate(s) resolve to the subject's confirmed area (within {FAMILY_GEO_KM:.0} km): {}{} — {basis}",
            in_area.len(),
            shown.join(", "),
            if extra > 0 {
                format!(", +{extra} more")
            } else {
                String::new()
            },
        ),
        uids,
        scan_id,
        ts,
    )]
}
