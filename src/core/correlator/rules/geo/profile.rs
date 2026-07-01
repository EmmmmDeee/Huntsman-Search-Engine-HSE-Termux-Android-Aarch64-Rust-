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

/// Australian mobile country code (ITU E.212 / ACMA) — the MCC every Australian
/// cellular network advertises.
const AU_MCC: &str = "505";

/// Pluralising suffix for a count — `""` for one, `"s"` otherwise.
fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Join a list with commas and a closing "and" (`a`, `a and b`, `a, b and c`).
fn join_and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

/// One passively-collected device location fix, with the fields that order it.
/// (Contributing fix uids are gathered separately into the finding's uid set.)
struct SelfFix {
    is_gps: bool,
    accuracy_m: f64,
    confidence: f64,
    lat: f64,
    lon: f64,
}

/// The `accuracy:<n>m` tag a device-sensor fix carries, in metres; a fix with no
/// accuracy tag is treated as very coarse so a tagged fix always outranks it.
fn device_fix_accuracy_m(e: &Entity) -> f64 {
    e.tags
        .iter()
        .find_map(|t| {
            t.strip_prefix("accuracy:")
                .and_then(|s| s.strip_suffix('m'))
                .and_then(|n| n.parse::<f64>().ok())
        })
        .unwrap_or(100_000.0)
}

/// A roaming / spoofed-GPS note when the best fix's country (AU vs not) disagrees
/// with the serving/visible cells' MCC — an Interpol-grade cross-check that the
/// GPS fix and the radio network agree on the country. Empty when consistent or
/// undeterminable.
fn cell_country_note(fix_in_au: bool, cells: &[&Entity]) -> String {
    let mut saw_au = false;
    let mut foreign: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for c in cells {
        // The cell DeviceId is `mcc-mnc-lac-cid`; the first segment is the MCC.
        if let Some(mcc) = c.value.split('-').next() {
            if mcc == AU_MCC {
                saw_au = true;
            } else if !mcc.is_empty() {
                foreign.insert(mcc);
            }
        }
    }
    if fix_in_au && !saw_au && !foreign.is_empty() {
        format!(
            " Serving cell MCC {} is non-Australian — roaming or a relocated SIM, worth a second look.",
            foreign.into_iter().collect::<Vec<_>>().join("/")
        )
    } else if !fix_in_au && saw_au {
        " The fix is outside Australia yet the serving cell is Australian (MCC 505) — \
         inconsistent, possible spoofed GPS."
            .to_string()
    } else {
        String::new()
    }
}

/// AU-103 — Autonomous device self-location (radar self-fix).
///
/// The radar's autonomous geolocation output: it fuses ONLY the passively
/// collected on-device signals — the GPS/network location fix, visible Wi-Fi
/// APs, the serving/visible cell towers, Bluetooth devices and LAN neighbours —
/// into the operator device's own position, with no seed and no subject input.
/// This is what makes the radar 100% autonomous: even with no precise fix this
/// sweep, the surrounding RF establishes the device's presence and live context.
///
/// * a best fix is chosen from the `device-sensor` `Coordinates` (a GPS lock
///   outranks a network fix, then tighter accuracy, then higher confidence) and
///   reverse-geocoded offline to an AU locality + state (no network call);
/// * the visible Wi-Fi APs, cells, Bluetooth devices and LAN neighbours
///   corroborate presence at that place and time;
/// * the serving cell's MCC is cross-checked against the fix's country — a GPS
///   fix in Australia served by a foreign cell (or vice-versa) is surfaced as a
///   roaming / spoofed-GPS inconsistency.
///
/// High when a GPS-grade fix anchors it, Medium for a network-grade fix only,
/// Low when there is no fix but the device sits in a live RF environment
/// (presence/location-context without a precise point). Keys exclusively on the
/// on-device sensor tags, so it concerns only the operator's own device and
/// never a remote subject. Pure over the confirmed set.
pub(in crate::core::correlator) fn rule_au_103_device_self_location(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Best passive on-device location fix.
    let mut best: Option<SelfFix> = None;
    let mut fix_uids: Vec<String> = Vec::new();
    for e in entities {
        if e.kind != EntityKind::Coordinates || !e.has_tag("device-sensor") {
            continue;
        }
        let Some((lat, lon)) = crate::util::geohash::parse_coords(&e.value) else {
            continue;
        };
        fix_uids.push(e.uid.clone());
        let cand = SelfFix {
            is_gps: e.has_tag("provider:gps"),
            accuracy_m: device_fix_accuracy_m(e),
            confidence: e.confidence,
            lat,
            lon,
        };
        let better = match &best {
            None => true,
            // GPS over network, then tighter accuracy, then higher confidence.
            Some(b) => {
                (cand.is_gps, -cand.accuracy_m, cand.confidence)
                    > (b.is_gps, -b.accuracy_m, b.confidence)
            }
        };
        if better {
            best = Some(cand);
        }
    }

    // Corroborating passive presence signals (each independent of the fix).
    let mut wifi = 0usize;
    let mut bt = 0usize;
    let mut lan = 0usize;
    let mut cells: Vec<&Entity> = Vec::new();
    let mut corro_uids: Vec<String> = Vec::new();
    for e in entities {
        if e.has_tag(crate::core::tags::WIFI_AP) {
            wifi += 1;
        } else if e.has_tag("bluetooth") {
            bt += 1;
        } else if e.has_tag(crate::core::tags::CELL_TOWER) {
            cells.push(e);
        } else if e.has_tag("arp-neighbor") {
            lan += 1;
        } else {
            continue;
        }
        corro_uids.push(e.uid.clone());
    }

    let has_presence = wifi > 0 || bt > 0 || lan > 0 || !cells.is_empty();
    if best.is_none() && !has_presence {
        return Vec::new(); // nothing passive to report this sweep
    }

    // Corroboration phrase (only the non-zero classes).
    let mut corro: Vec<String> = Vec::new();
    if wifi > 0 {
        corro.push(format!("{wifi} Wi-Fi AP{}", plural(wifi)));
    }
    if !cells.is_empty() {
        corro.push(format!("{} cell{}", cells.len(), plural(cells.len())));
    }
    if bt > 0 {
        corro.push(format!("{bt} Bluetooth device{}", plural(bt)));
    }
    if lan > 0 {
        corro.push(format!("{lan} LAN neighbour{}", plural(lan)));
    }

    let mut uids = fix_uids;
    uids.extend(corro_uids);
    uids.sort_unstable();
    uids.dedup();

    let (severity, description) = if let Some(b) = &best {
        let fix_in_au = crate::util::geo::au_state_for_coords(b.lat, b.lon).is_some();
        let place = match crate::util::geo::nearest_au_locality(b.lat, b.lon) {
            Some((name, st, km)) => format!(" — near {name}, {st} (≈{km:.0} km)"),
            None if fix_in_au => " — within Australia".to_string(),
            None => " — outside the AU gazetteer".to_string(),
        };
        let grade = if b.is_gps { "GPS" } else { "network" };
        let acc = if b.accuracy_m < 100_000.0 {
            format!(", ±{:.0} m", b.accuracy_m)
        } else {
            String::new()
        };
        let corro_note = if corro.is_empty() {
            String::new()
        } else {
            format!(" Corroborated by {}.", join_and(&corro))
        };
        let cell_note = cell_country_note(fix_in_au, &cells);
        let severity = if b.is_gps {
            Severity::High
        } else {
            Severity::Medium
        };
        (
            severity,
            format!(
                "Autonomous device self-location: {:.5},{:.5}{place} ({grade} fix{acc}).{corro_note}{cell_note} \
                 Established from passive on-device sensors alone — no seed input.",
                b.lat, b.lon
            ),
        )
    } else {
        (
            Severity::Low,
            format!(
                "Autonomous device presence: no precise fix this sweep, but the device sits in a live \
                 RF environment ({}). Established from passive on-device sensors alone — no seed input.",
                join_and(&corro)
            ),
        )
    };

    vec![Correlation::new(
        "AU-103",
        "Autonomous device self-location",
        severity,
        description,
        uids,
        scan_id,
        ts,
    )]
}
