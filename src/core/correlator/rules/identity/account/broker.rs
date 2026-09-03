//! Data-broker / authoritative-register rules — broker exposure, primary-source
//! accounts, register confirmation and breach social footprint.
//! Split from `account.rs`; rules re-exported by `super`.

use super::super::*;
use super::*;

/// AU-054 — PII located on data broker(s).
///
/// When the scan surfaced a `Url` whose host is a known people-search /
/// data-broker site (Spokeo, BeenVerified, Whitepages, …), the subject's PII is
/// being brokered/redistributed there — a location finding: *where the
/// subject's data lives*. This is the locating counterpart to the engine's
/// expansion gate, which already treats these domains as aggregator noise.
///
/// **Brokers are low-credibility OSINT and are NOT preferenced over other
/// sources.** A people-search listing aggregates (frequently from other
/// brokers), goes stale, and a single one proves little — so a lone broker
/// fires at `Low`, ranked *below* any corroborated identity/geo finding.
/// Listings across ≥2 *independent* brokers corroborate more, but because
/// brokers cross-source each other the ceiling is `Medium` — on par with other
/// corroborated OSINT, never above it (never `High`/`Critical`). The finding
/// says so explicitly: it is a lead to verify against primary sources, not
/// confirmation.
///
/// One grouped finding so cross-broker corroboration drives the severity.
/// Matches `Url` entities only (a profile URL is a real listing), not a bare
/// broker `Domain`. Broker names and uids are sorted, so output is deterministic.
pub(in crate::core::correlator) fn rule_au_054_data_broker_exposure(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use crate::core::data_broker::broker_for_host;
    use std::collections::BTreeSet;

    // Distinct brokers (by display name, sorted) the subject is listed on, and
    // every broker-URL uid backing the finding.
    let mut brokers: BTreeSet<&'static str> = BTreeSet::new();
    let mut uids: Vec<String> = Vec::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::Url) {
        if let Some(host) = url::Url::parse(&e.value)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            && let Some(broker) = broker_for_host(&host)
        {
            brokers.insert(broker.name);
            uids.push(e.uid.clone());
        }
    }
    if brokers.is_empty() {
        return Vec::new();
    }
    uids.sort_unstable();
    uids.dedup();
    let names: Vec<&str> = brokers.iter().copied().collect();

    // Corroboration-scaled, capped at Medium so brokers never outrank other
    // OSINT: one broker = Low (weak, not credible alone); ≥2 independent
    // brokers = Medium (corroborated, but brokers cross-source — not High).
    let severity = if names.len() >= 2 {
        Severity::Medium
    } else {
        Severity::Low
    };

    vec![Correlation {
        rule_id: "AU-054".into(),
        rule_name: "PII located on data broker(s)".into(),
        severity,
        description: format!(
            "Subject's PII is brokered on {} people-search site(s): {} — data-broker \
             listings aggregate (often from each other) and corroborate weakly; treat \
             as a lead to verify against primary sources, not confirmation",
            names.len(),
            names.join(", ")
        ),
        entity_uids: uids,
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}

/// AU-055 — Subject's primary-source accounts located.
///
/// The affirmative primary-source finding, and the counterweight to AU-054:
/// the accounts the subject actually CONTROLS are first-class, high-credibility
/// intelligence — far stronger than any second-hand broker listing. A `Url`
/// directly confirmed as the subject's own account/profile (`social-profile`
/// from a direct platform probe, `confirmed-profile` from engine-corroborated
/// search, `public-profile` from a code/forum account API, or `personal-site`)
/// is a primary source.
///
/// Unlike AU-038 (which only fires on ≥2 *social* platforms), this fires from a
/// SINGLE confirmed account — one verified primary source is credible on its
/// own — and spans code hosts, forums and personal sites too. Crucially it
/// EXCLUDES broker hosts: a `social-profile`-tagged URL on a people-search site
/// is the broker's listing, not the subject's account, and belongs to AU-054
/// (low-credibility), never here.
///
/// Also excludes `weak-detection`-tagged URLs: `username_search`/
/// `streaming_probe` tag a hit `social-profile` regardless of whether the
/// match came from a body-marker check (`verified-detection`) or a bare
/// HTTP-status guess (`weak-detection` — a soft-404/SPA-shell can fake this
/// for almost any handle). A real scan against a guessed handle produced a
/// `CRITICAL "primary-source accounts... the subject controls"` finding
/// across 60+ platforms where nearly every one was `weak-detection` — status-
/// only guesses presented as confirmed ownership. Requiring the absence of
/// that tag means a lone `verified-detection` hit (or a tag-only source with
/// no strength marker at all, e.g. a real account API) still fires this rule
/// the same as before; only the unverified guesses are excluded.
///
/// Severity puts primary sources above brokers by construction: High for one or
/// two confirmed accounts, Critical for a confirmed footprint across ≥3 distinct
/// platforms — always outranking AU-054's Low/Medium broker findings.
pub(in crate::core::correlator) fn rule_au_055_primary_source_accounts(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use crate::core::data_broker::broker_for_host;
    use std::collections::BTreeSet;

    const OWNED_ACCOUNT_TAGS: &[&str] = &[
        "social-profile",
        "confirmed-profile",
        "public-profile",
        "personal-site",
    ];

    // Distinct platform hosts (www-stripped) of confirmed owned-account URLs,
    // and the backing uids. Broker hosts are excluded — a broker listing is not
    // an account the subject controls. `weak-detection`-tagged hits are
    // excluded too — a bare status-code guess is not a confirmed account.
    let mut platforms: BTreeSet<String> = BTreeSet::new();
    let mut uids: Vec<String> = Vec::new();
    for e in entities.iter().filter(|e| {
        e.kind == EntityKind::Url
            && OWNED_ACCOUNT_TAGS.iter().any(|t| e.has_tag(t))
            && !e.has_tag("weak-detection")
    }) {
        let Some(host) = www_stripped_host(&e.value) else {
            continue;
        };
        if broker_for_host(&host).is_some() {
            continue; // a broker's listing page, not the subject's account
        }
        platforms.insert(host);
        uids.push(e.uid.clone());
    }
    if platforms.is_empty() {
        return Vec::new();
    }
    uids.sort_unstable();
    uids.dedup();
    let hosts: Vec<&str> = platforms.iter().map(String::as_str).collect();

    let severity = if hosts.len() >= 3 {
        Severity::Critical
    } else {
        Severity::High
    };

    vec![Correlation {
        rule_id: "AU-055".into(),
        rule_name: "Primary-source accounts located".into(),
        severity,
        description: format!(
            "Subject's own confirmed account(s)/profile(s) located across {} platform(s): {} \
             — primary sources the subject controls (direct probe / engine-corroborated)",
            hosts.len(),
            hosts.join(", ")
        ),
        entity_uids: uids,
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}

/// The issuing authority for an evidence `source`, or `None` when the source is
/// not an authoritative AU register.
fn au_register_authority(source: &str) -> Option<&'static str> {
    AUTHORITATIVE_AU_REGISTERS
        .iter()
        .find(|(src, _)| *src == source)
        .map(|(_, authority)| *authority)
}

/// AU-088 — Authoritative AU public-register confirmation.
///
/// The affirmative identity-verification finding for an Australian subject. Every
/// entity carrying evidence from an authoritative AU public register — AHPRA,
/// ASIC, the electoral roll, the property / title register, AustLII, the ACNC,
/// the Australian Business Register — is government-grounded fact, not a scraped
/// or brokered listing. This rule counts how many DISTINCT register authorities
/// independently returned data on the subject and fires once per scan: a single
/// register is a `High` confirmation, two or more is `Critical`. Multi-register
/// agreement is the strongest identity corroboration HSE can assert, and the
/// cleanest way to separate the real subject from the search-engine namesakes a
/// broad name scan drags in — the affirmative complement to AU-054 (broker
/// listings) and AU-075 (breach-stated associates).
///
/// Operates on the already-quarantine-filtered confirmed set (the caller drops
/// `candidate`s), so a namesake's speculative register hit can't manufacture a
/// false confirmation. The ASIC sub-feeds collapse to one authority (see
/// [`AUTHORITATIVE_AU_REGISTERS`]). Deterministic: authorities and linked uids
/// are emitted in sorted (`BTreeSet`) order.
pub(in crate::core::correlator) fn rule_au_088_authoritative_register_confirmation(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::BTreeSet;
    let mut authorities: BTreeSet<&'static str> = BTreeSet::new();
    let mut uids: BTreeSet<String> = BTreeSet::new();
    for e in entities {
        for ev in &e.evidence {
            if let Some(authority) = au_register_authority(ev.source.as_str()) {
                authorities.insert(authority);
                uids.insert(e.uid.clone());
            }
        }
    }
    if authorities.is_empty() {
        return Vec::new();
    }
    let labels: Vec<&str> = authorities.iter().copied().collect();
    let severity = if authorities.len() >= 2 {
        Severity::Critical
    } else {
        Severity::High
    };
    vec![Correlation::new(
        "AU-088",
        "Authoritative AU register confirmation",
        severity,
        format!(
            "Subject corroborated by {} authoritative Australian public register(s): {} — \
             government-grounded identity, far stronger than any scraped or brokered listing",
            authorities.len(),
            labels.join(", ")
        ),
        uids.into_iter().collect(),
        scan_id,
        ts,
    )]
}

/// Platforms whose `platform:handle` Username nodes `breach_rich` mints — the
/// SAME constant `breach_rich` iterates (`core::breach_platforms`), so the two
/// cannot drift: this rule was blind to `github`/`tiktok`/`reddit` for as long
/// as it kept its own copy. A breach-listed account on one of these counts
/// toward the cross-platform footprint; any other value prefix (an epieos
/// `google:<id>`, …) is ignored.
use crate::core::breach_platforms::BREACH_SOCIAL_PLATFORMS;

/// AU-108 — Breach-listed cross-platform handle footprint.
///
/// `breach_rich` surfaces a subject's extra social accounts as `platform:handle`
/// Usernames (`twitter:alice`, `telegram:alice`, …, tagged `breach`). Individually
/// each is one account; together, ≥2 DISTINCT platforms named by breach data is a
/// cross-platform footprint worth synthesising — which no rule reported (the
/// platform-prefixed nodes were produced only to merge by value). Medium: a stated
/// set of accounts, weaker than a live-verified cross-platform identity
/// (AU-038/AU-046), and a lead to corroborate against live profile discovery.
///
/// Precision: the platform is the literal value prefix before `:` (breach_rich's
/// own convention); only platforms on [`BREACH_SOCIAL_PLATFORMS`] count (so an
/// epieos `google:<id>` or any other prefixed value is ignored); the node must be
/// `breach`-tagged; and ≥2 DISTINCT platforms are required (a single account never
/// fires; two handles on one platform don't inflate). Runs on the confirmed view.
/// Deterministic (`BTreeSet` of platforms, sorted uids).
pub(in crate::core::correlator) fn rule_au_108_breach_social_footprint(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::BTreeSet;
    let mut platforms: BTreeSet<&'static str> = BTreeSet::new();
    let mut uids: Vec<String> = Vec::new();
    for e in entities_of_kind_with_tag(entities, EntityKind::Username, "breach") {
        let Some((prefix, handle)) = e.value.split_once(':') else {
            continue;
        };
        if handle.is_empty() {
            continue;
        }
        let Some(plat) = BREACH_SOCIAL_PLATFORMS
            .iter()
            .copied()
            .find(|&p| p == prefix)
        else {
            continue;
        };
        platforms.insert(plat);
        uids.push(e.uid.clone());
    }
    if platforms.len() < 2 {
        return Vec::new();
    }
    uids.sort_unstable();
    uids.dedup();
    let listed: Vec<&str> = platforms.iter().copied().collect();
    vec![Correlation::new(
        "AU-108",
        "Breach-listed cross-platform handle footprint",
        Severity::Medium,
        format!(
            "Breach data lists the subject's accounts across {} platforms: {} — a stated \
             cross-platform footprint to corroborate against live profile discovery",
            listed.len(),
            listed.join(", ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// Authoritative Australian public registers — the `source` string each register
/// module stamps on its evidence, mapped to the issuing AUTHORITY. The ASIC
/// sub-modules deliberately collapse to one authority so three ASIC feeds count
/// as a SINGLE independent confirmation, not three. Adding a new AU register
/// module here makes it count toward AU-088 with no other change.
const AUTHORITATIVE_AU_REGISTERS: &[(&str, &str)] = &[
    ("ahpra", "AHPRA (health-practitioner register)"),
    ("asic_persons", "ASIC"),
    ("asic_director", "ASIC"),
    ("asic_banned_orgs", "ASIC"),
    ("au_electoral", "AU electoral roll"),
    ("au_property", "AU property / title register"),
    ("austlii", "AustLII (court & tribunal records)"),
    ("acnc_charities", "ACNC (charities register)"),
    ("abn_lookup", "Australian Business Register (ABN)"),
];
