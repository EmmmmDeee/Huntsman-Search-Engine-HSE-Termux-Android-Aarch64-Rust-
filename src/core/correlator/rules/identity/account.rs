//! AU correlation rules — handle, platform, key, tracking and broker family.
//! See `super::super` (rules/mod.rs) for the shared helpers; all reach them via
//! `use super::*` → `identity/mod.rs` → `use super::*` → `rules/mod.rs`.

use super::*;
// USERNAME_* constants are private in rules/mod.rs but accessible to descendants.
use super::super::{USERNAME_DERIVATION_SOURCES, USERNAME_DISCOVERY_SOURCES};

pub(in crate::core::correlator) fn rule_au_011_cross_platform_username(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Username-keyed account modules: each one that independently confirms a
    // handle is a distinct PLATFORM, so three of them agreeing is a genuine
    // cross-platform footprint even when no single module reported a count.
    const PLATFORM_SOURCES: &[&str] = &[
        "github_user",
        "reddit_user",
        "hacker_news",
        "keybase",
        "gravatar",
    ];
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
            // Distinct independent platform-module confirmations (github_user +
            // reddit_user + hacker_news + …). Folded in with `max` so a handle
            // confirmed on three platforms by three SEPARATE modules surfaces the
            // same footprint as one module reporting three — the cross-service
            // signal the keyless social modules produce.
            let mut platform_srcs: Vec<&str> = e
                .corroborating_sources()
                .into_iter()
                .filter(|s| PLATFORM_SOURCES.contains(s))
                .collect();
            platform_srcs.sort_unstable();
            let src_count = platform_srcs.len() as u64;
            let owned_list;
            let count = if src_count > max_count {
                owned_list = platform_srcs.join(", ");
                best_list = Some(owned_list.as_str());
                src_count
            } else {
                max_count
            };
            if count >= 3 {
                let detail = best_list.map(|s| format!(": {s}")).unwrap_or_default();
                Some(Correlation {
                    rule_id: "AU-011".into(),
                    rule_name: "Cross-platform username footprint".into(),
                    severity: Severity::Medium,
                    description: format!(
                        "Username '{}' present on {count} platforms{detail}",
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
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeSet;
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
        // Distinct CONTROLLER handles, not just distinct identifier spellings:
        // the attrs mix identifier types (login / username / email), so a
        // single account whose key evidence carries both its login and its
        // email ("alice" + "alice@x.com") is two strings but ONE account —
        // firing a Critical "controls 2 accounts" on that is a false positive.
        // Fold each identifier to its canonical handle (email local-part,
        // separator-insensitive, same comparison AU-034 uses) and require two
        // to actually differ. Genuinely distinct handles sharing a key
        // ("ghost91" + "jsmith_work", or "@alice" + "bob@x.com") still fire.
        let handles: BTreeSet<String> = accounts
            .iter()
            .map(|a| canonical_handle(a.split('@').next().unwrap_or(a)))
            .collect();
        if handles.len() < 2 {
            continue;
        }
        let mut uids = vec![key.uid.clone()];
        for e in entities
            .iter()
            .filter(|e| matches!(e.kind, EntityKind::Username | EntityKind::Email))
        {
            if accounts.contains(&e.value.trim().to_lowercase()) {
                uids.push(e.uid.clone());
            }
        }
        let listed: Vec<&str> = accounts.iter().take(6).map(String::as_str).collect();
        out.push(Correlation {
            rule_id: "AU-048".into(),
            rule_name: "Shared public key links accounts".into(),
            severity: Severity::Critical,
            description: format!(
                "A reused public key proves one person controls {} accounts (same private key): {}",
                accounts.len(),
                listed.join(", ")
            ),
            entity_uids: uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        });
    }
    out
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
pub(in crate::core::correlator) fn rule_au_034_handle_reuse_identity(
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
pub(in crate::core::correlator) fn rule_au_035_confirmed_derived_handle(
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
pub(in crate::core::correlator) fn rule_au_036_email_alias_convergence(
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
pub(in crate::core::correlator) fn rule_au_038_verified_cross_platform_identity(
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

/// AU-042 — two or more email addresses bound to the same PGP key (`pgp` module):
/// strong same-owner evidence (the key holder asserted these are theirs).
/// `High`. One grouped firing over all key-linked emails.
pub(in crate::core::correlator) fn rule_au_042_pgp_email_identity(
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

/// AU-044 — Shared web-analytics ID ⇒ common ownership. A Google Analytics /
/// AdSense / Tag-Manager / Facebook-Pixel id that appears on two or more
/// otherwise-unrelated sites is strong evidence the same operator runs them — the
/// "affiliate" pivot. `web_crawler` records the carrying site in each
/// `TrackingId` evidence entry's `source_domain`; entities merge by value, so a
/// shared id accumulates one evidence row per site. Fires when ≥2 distinct sites
/// carry the same id.
pub(in crate::core::correlator) fn rule_au_044_shared_tracking_id(
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
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
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
/// Severity puts primary sources above brokers by construction: High for one or
/// two confirmed accounts, Critical for a confirmed footprint across ≥3 distinct
/// platforms — always outranking AU-054's Low/Medium broker findings.
pub(in crate::core::correlator) fn rule_au_055_primary_source_accounts(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
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
    // an account the subject controls.
    let mut platforms: BTreeSet<String> = BTreeSet::new();
    let mut uids: Vec<String> = Vec::new();
    for e in entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url && OWNED_ACCOUNT_TAGS.iter().any(|t| e.has_tag(t)))
    {
        let Some(host) = url::Url::parse(&e.value).ok().and_then(|u| {
            u.host_str()
                .map(|h| h.trim_start_matches("www.").to_lowercase())
        }) else {
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
