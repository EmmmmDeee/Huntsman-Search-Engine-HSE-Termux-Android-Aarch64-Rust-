//! AU correlation rules — handle, platform, key, tracking and broker family.
//! See `super::super` (rules/mod.rs) for the shared helpers; all reach them via
//! `use super::*` → `identity/mod.rs` → `use super::*` → `rules/mod.rs`.

use super::*;
// USERNAME_* constants are private in rules/mod.rs but accessible to descendants.
use super::super::{
    EMAIL_CONFIRMATION_SOURCES, USERNAME_DERIVATION_SOURCES, USERNAME_DISCOVERY_SOURCES,
};

pub(in crate::core::correlator) fn rule_au_011_cross_platform_username(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Username-keyed account modules: each one that independently confirms a
    // handle is a distinct PLATFORM, so three of them agreeing is a genuine
    // cross-platform footprint even when no single module reported a count.
    // Every module that independently confirms a username on a specific
    // platform — adding a new module here makes it count toward the ≥3
    // corroboration threshold without any other changes required.
    const PLATFORM_SOURCES: &[&str] = &[
        "github_user",
        "gitlab_user",
        "bitbucket_user",
        "codeberg_user",
        "reddit_user",
        "hacker_news",
        "lobsters",
        "devto",
        "stackoverflow_user",
        "bluesky_user",
        "mastodon_user",
        "keybase",
        "gravatar",
        "huggingface_user",
        "dockerhub_user",
        "hexpm_user",
        "codewars_user",
        "launchpad_user",
        "gitea_user",
        "sourceforge_user",
        "cpan_user",
        "rubygems_user",
        "pypi_user",
        "crates_io",
        "npm_author",
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
                let list = ev.attributes.get("platforms").map(String::as_str);
                if count > max_count {
                    max_count = count;
                    best_list = list;
                } else if count == max_count && count > 0 {
                    // Deterministic tie-break: keep the lexicographically-smaller
                    // `platforms` string so the description text doesn't depend on
                    // evidence iteration order (which isn't pinned here).
                    if let Some(l) = list {
                        best_list = Some(best_list.map_or(l, |b| b.min(l)));
                    }
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
    // Cheap precondition: with no key-tagged credential present, no link can
    // fire — bail before building the identity index.
    let has_shared_key = entities.iter().any(|e| {
        e.kind == EntityKind::Credential && (e.has_tag("ssh-key") || e.has_tag("pgp-key"))
    });
    if !has_shared_key {
        return Vec::new();
    }
    // Pre-lowercase the Username/Email index ONCE. The previous form
    // re-lowercased every account entity's value for every shared key (an
    // O(keys×accounts) allocation storm); building it a single time turns the
    // per-key linking into plain set membership. Entity iteration order is
    // preserved, so the emitted uid order is identical to before.
    let id_index: Vec<(String, &str)> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Username | EntityKind::Email))
        .map(|e| (e.value.trim().to_lowercase(), e.uid.as_str()))
        .collect();

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
        for (value_lc, uid) in &id_index {
            if accounts.contains(value_lc) {
                uids.push((*uid).to_owned());
            }
        }
        out.push(Correlation {
            rule_id: "AU-048".into(),
            rule_name: "Shared public key links accounts".into(),
            severity: Severity::Critical,
            description: format!(
                "A reused public key proves one person controls {} accounts (same private key) \
                 — key evidence names: {}",
                // Count DISTINCT controllers (handles), not identifier spellings: the
                // guard above already treats "alice" + "alice@x.com" as ONE account,
                // so reporting `accounts.len()` here would over-state control (e.g.
                // "3 accounts" for alice's login+email plus bob, who are 2 owners).
                handles.len(),
                join_capped(accounts.iter().map(String::as_str), 6)
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
        // The independence gate must count only genuine, independent
        // observations: `corroborating_sources()` (not `evidence_sources()`)
        // excludes the replay/derivation passes — `recall`, `cross_scan_history`,
        // `name_intel`, `geo_normalize` — so a name-permuted handle + email that
        // each merely picked up a `recall` record can't manufacture two "distinct
        // sources" and self-correlate. Matches AU-011/AU-023 and the geo rules.
        let mut sources: HashSet<&str> = u.corroborating_sources();
        let mut matched_uids: Vec<String> = Vec::with_capacity(matches.len());
        let mut matched_values: Vec<&str> = Vec::with_capacity(matches.len());
        for e in matches {
            matched_uids.push(e.uid.clone());
            matched_values.push(e.value.as_str());
            sources.extend(e.corroborating_sources());
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
///
/// Excludes `weak-detection`-tagged URLs for the same reason as AU-055: a
/// `social-profile` tag is applied to a bare HTTP-status guess just as readily
/// as to a body-marker-confirmed hit, and this rule's own name promises
/// "verified" — a claim only the latter earns. See AU-055's doc comment for
/// the real-scan finding that surfaced this.
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
                && !e.has_tag("weak-detection")
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

/// AU-042 — two or more email addresses bound to the **same** PGP key (`pgp`
/// module): strong same-owner evidence (the key holder asserted these are theirs).
/// `High`. One firing PER KEY, over the emails that key binds.
///
/// Partitioned by the key fingerprint each `pgp-linked` email carries (the
/// `key_fingerprint` evidence attribute the `pgp` module attaches): emails bound
/// to DIFFERENT keys are separate assertions — possibly different people — so they
/// must never be fused into one owner, and a key binding only ONE address is not
/// multi-email evidence, so it does not fire (the rule's "two or more" contract).
/// An email with no fingerprint can't be attributed to a key and is excluded.
pub(in crate::core::correlator) fn rule_au_042_pgp_email_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};
    // fingerprint -> (address -> emitting uid). BTreeMaps keep the output
    // deterministic (fingerprint order, then address order) with no HashMap leak.
    let mut by_key: BTreeMap<&str, BTreeMap<&str, String>> = BTreeMap::new();
    for e in entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email && e.has_tag("pgp-linked"))
    {
        // An email merged from several keyserver hits can carry more than one
        // fingerprint; it legitimately belongs to each key that bound it.
        let fingerprints: BTreeSet<&str> = e
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("key_fingerprint").map(String::as_str))
            .filter(|f| !f.is_empty())
            .collect();
        for fpr in fingerprints {
            by_key
                .entry(fpr)
                .or_default()
                .entry(e.value.as_str())
                .or_insert_with(|| e.uid.clone());
        }
    }

    by_key
        .into_iter()
        .filter(|(_, addrs)| addrs.len() >= 2)
        .map(|(fpr, addrs)| {
            let addr_list: Vec<&str> = addrs.keys().copied().collect();
            let uids: Vec<String> = addrs.values().cloned().collect();
            Correlation::new(
                "AU-042",
                "PGP key binds multiple emails to one identity",
                Severity::High,
                format!(
                    "PGP key {fpr} links {} email address(es) to one owner: {}",
                    addr_list.len(),
                    addr_list.join(", ")
                ),
                uids,
                scan_id,
                ts,
            )
        })
        .collect()
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
    // an account the subject controls. `weak-detection`-tagged hits are
    // excluded too — a bare status-code guess is not a confirmed account.
    let mut platforms: BTreeSet<String> = BTreeSet::new();
    let mut uids: Vec<String> = Vec::new();
    for e in entities.iter().filter(|e| {
        e.kind == EntityKind::Url
            && OWNED_ACCOUNT_TAGS.iter().any(|t| e.has_tag(t))
            && !e.has_tag("weak-detection")
    }) {
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

/// AU-076 — Email local-part ↔ Username canonical identity bridge.
///
/// When an Email entity's local part (text before the `@`) canonicalises to the
/// same handle as a Username entity — where canonical means separator-stripped
/// lowercase (`john.doe` = `john_doe` = `johndoe`) — both almost certainly belong
/// to the same subject: the username *is* the email login. This is the strongest
/// purely free, zero-API identity link the engine can derive, requiring no
/// external service and no historical data.
///
/// Excludes generic/role handles (`info`, `support`, `dns`, …) that would create
/// spurious links between unrelated entities. Severity: High because the
/// conjunction is highly specific — the same canonical string appearing in two
/// entity kinds from independent sources is not coincidental.
///
/// **Consolidated by canonical handle.** A name seed derives many email
/// permutations (`x@gmail.com`, `x@yahoo.com`, …) and many username forms
/// (`x`, `x.y`, `x_y`) that all canonicalise to the SAME handle, so a naive
/// per-pair emission produced an N×M flood of identical High findings (observed:
/// 80 rows for one subject). This emits ONE finding per canonical handle, listing
/// every email form and every username form it unifies — the full identity
/// cluster in a single row, with no value lost.
pub(in crate::core::correlator) fn rule_au_076_email_username_localpart_bridge(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};

    // Username index: canonical_handle → the Username entities sharing it.
    // Filter generic handles up front so none is ever considered.
    let mut usernames_by_canon: BTreeMap<String, Vec<&Entity>> = BTreeMap::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::Username) {
        let ch = canonical_handle(&e.value);
        if ch.len() >= 4 && !is_generic_handle(&ch) {
            usernames_by_canon.entry(ch).or_default().push(e);
        }
    }
    if usernames_by_canon.is_empty() {
        return Vec::new();
    }

    // Email side: bucket every Email whose canonical local-part matches a
    // username handle under that canonical handle.
    let mut emails_by_canon: BTreeMap<String, Vec<&Entity>> = BTreeMap::new();
    for email_e in entities.iter().filter(|e| e.kind == EntityKind::Email) {
        let Some(local_raw) = email_e.value.split('@').next().filter(|l| !l.is_empty()) else {
            continue;
        };
        // Strip plus-addressing (`haigen+tag@…` → `haigen`) before canonicalising.
        let local = local_raw.split('+').next().unwrap_or(local_raw);
        let canon_local = canonical_handle(local);
        if canon_local.len() < 4 || is_generic_handle(&canon_local) {
            continue;
        }
        if usernames_by_canon.contains_key(&canon_local) {
            emails_by_canon
                .entry(canon_local)
                .or_default()
                .push(email_e);
        }
    }

    // One consolidated finding per canonical handle that bridges an email to a
    // username (BTreeMap key order → deterministic output).
    let mut out: Vec<Correlation> = Vec::new();
    for (canon, emails) in &emails_by_canon {
        let usernames = &usernames_by_canon[canon];
        let email_vals: BTreeSet<&str> = emails.iter().map(|e| e.value.as_str()).collect();
        let uname_vals: BTreeSet<&str> = usernames.iter().map(|e| e.value.as_str()).collect();

        let mut uids: Vec<String> = emails
            .iter()
            .chain(usernames.iter())
            .map(|e| e.uid.clone())
            .collect();
        uids.sort_unstable();
        uids.dedup();

        let description = if email_vals.len() == 1 && uname_vals.len() == 1 {
            // Preserve the original single-pair wording (the common, exact case).
            format!(
                "Email '{}' local-part canonicalises to username '{}' — the handle is the \
                 email login (free, offline, zero-API identity resolution)",
                email_vals.iter().next().expect("one email"),
                uname_vals.iter().next().expect("one username"),
            )
        } else {
            format!(
                "Handle '{canon}' is one identity's email login — it unifies {} email form(s) ({}) \
                 and {} username form(s) ({}); the username is the email login (free, offline, \
                 zero-API identity resolution)",
                email_vals.len(),
                join_capped(email_vals.iter().copied(), 8),
                uname_vals.len(),
                join_capped(uname_vals.iter().copied(), 8),
            )
        };

        out.push(Correlation {
            rule_id: "AU-076".into(),
            rule_name: "Email-username local-part identity bridge".into(),
            severity: Severity::High,
            description,
            entity_uids: uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        });
    }
    out
}

/// AU-077 — Name-derived username independently confirmed on a platform.
///
/// When a username was *derived* from a name or email (via `name_intel`,
/// `email_parse`, or `username_variants`) AND separately *confirmed* live by a
/// platform-discovery module (`github_user`, `social_probe`, etc.), the
/// conjunction is a high-confidence identity bridge: the name PREDICTED the
/// handle, and the platform VERIFIED it exists. Purely free — requires no API
/// keys beyond whichever discovery module ran (many of which are also free).
///
/// This is the engine's core "prediction confirmed" signal: a permutation that a
/// name-intelligence pass emitted as a speculative candidate but that a live probe
/// independently found in the wild is almost certainly the subject's actual handle.
pub(in crate::core::correlator) fn rule_au_077_name_derived_username_confirmed(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .filter(|e| {
            // Must carry at least one derivation AND at least one discovery source.
            let has_derived = e
                .evidence
                .iter()
                .any(|ev| USERNAME_DERIVATION_SOURCES.contains(&ev.source.as_str()));
            let has_confirmed = e
                .evidence
                .iter()
                .any(|ev| USERNAME_DISCOVERY_SOURCES.contains(&ev.source.as_str()));
            has_derived && has_confirmed
        })
        .map(|e| {
            let confirmed_by: Vec<&str> = e
                .evidence
                .iter()
                .filter(|ev| USERNAME_DISCOVERY_SOURCES.contains(&ev.source.as_str()))
                .map(|ev| ev.source.as_str())
                .collect::<std::collections::BTreeSet<&str>>()
                .into_iter()
                .collect();
            let confirmed_by_str = confirmed_by.join(", ");
            Correlation {
                rule_id: "AU-077".into(),
                rule_name: "Name-derived username confirmed on platform".into(),
                severity: Severity::High,
                description: format!(
                    "Username '{}' was predicted by a name/email derivation pass and \
                     independently confirmed live on: {} — prediction + verification is a \
                     strong, free identity bridge requiring no breach data",
                    e.value, confirmed_by_str,
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

/// AU-086 — Name-derived email independently confirmed.
///
/// The email analogue of AU-077. `name_intel` permutes a subject's name into the
/// likely `firstname.lastname@provider` addresses (tagged `name-derived`,
/// emitted at CANDIDATE confidence). On their own they are guesses — but when an
/// independent breach / account-presence / profile source
/// ([`EMAIL_CONFIRMATION_SOURCES`] — HIBP, OathNet, Gravatar, holehe, …) finds
/// that exact address in real data, the name PREDICTED the email and a real
/// corpus VERIFIED it: it is almost certainly the subject's actual address.
///
/// This exists because the predicted-then-confirmed signal for emails was
/// previously surfaced for usernames only (AU-035/AU-077), so a confirmed
/// name-derived email stayed a low-confidence CANDIDATE buried among the dozens
/// of unconfirmed permutations — a real finding lost in the noise. AU-086 lifts
/// it to a High correlation so the operator sees exactly which guessed address
/// was confirmed real.
pub(in crate::core::correlator) fn rule_au_086_name_derived_email_confirmed(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .filter(|e| {
            // Predicted by a name-derivation pass (name_intel's permutation)…
            let derived =
                e.has_tag("name-derived") || e.evidence.iter().any(|ev| ev.source == "name_intel");
            // …AND independently confirmed in real data by ≥1 corpus/probe.
            let confirmed = e
                .evidence
                .iter()
                .any(|ev| EMAIL_CONFIRMATION_SOURCES.contains(&ev.source.as_str()));
            derived && confirmed
        })
        .map(|e| {
            let confirmed_by: Vec<&str> = e
                .evidence
                .iter()
                .filter(|ev| EMAIL_CONFIRMATION_SOURCES.contains(&ev.source.as_str()))
                .map(|ev| ev.source.as_str())
                .collect::<std::collections::BTreeSet<&str>>()
                .into_iter()
                .collect();
            Correlation {
                rule_id: "AU-086".into(),
                rule_name: "Name-derived email confirmed".into(),
                severity: Severity::High,
                description: format!(
                    "Email '{}' was predicted by a name-derivation pass and independently \
                     confirmed in real data by: {} — a guessed address verified against a \
                     breach/presence source is almost certainly the subject's actual email",
                    e.value,
                    confirmed_by.join(", "),
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

/// AU-078 — High-leverage cross-investigation hub entity.
///
/// An entity tagged `hub-entity` by the cross-scan history pass has been observed
/// in three or more distinct prior investigations.
/// Hub identifiers are the highest-value data points in the intelligence database:
/// each recurrence is a join that connects two otherwise-separate dossiers, and a
/// hub seen in many investigations often represents a shared address, phone number,
/// email alias, or cryptocurrency address belonging to a prolific subject.
///
/// Surfaced as Medium — not High/Critical — because the hub classification is
/// database-relative (only meaningful with prior scan history) and provenance-only
/// (never inflates the entity's own confidence score).
///
/// Only fires when the `feature.recall` toggle is on (the same gate that enables
/// the cross-scan history pass that produces the tag); when recall is off the tag
/// is never written and this rule never fires.
pub(in crate::core::correlator) fn rule_au_078_hub_entity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.has_tag("hub-entity"))
        .map(|e| Correlation {
            rule_id: "AU-078".into(),
            rule_name: "High-leverage cross-investigation hub entity".into(),
            severity: Severity::Medium,
            description: format!(
                "{} '{}' is a hub identifier recorded in 3+ prior investigations in the local \
                 intelligence database — a high-leverage anchor for cross-case attribution; \
                 prioritise for further enrichment",
                e.kind, e.value,
            ),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

// ── Free offline identity-resolution rules (AU-079 … AU-081) ─────────────────
//
// These three rules are zero-API, no-key, offline-capable and fire on every
// scan that has the relevant entity types.  They extend the free scanning
// identity-linking surface introduced by AU-076/077/078.

/// Extract @-mentions (handles prefixed with `@`) from any freetext bio /
/// profile-description string.  Returns lowercase strings stripped of the
/// leading `@`; only those ≥ 4 chars are returned (shorter ones are
/// initials / noise).  Pure, alloc-bounded (≤ MAX_AT_MENTIONS per call).
fn extract_at_mentions(text: &str) -> Vec<String> {
    const MAX_AT_MENTIONS: usize = 12;
    let mut out: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find('@') {
        rest = &rest[pos + 1..];
        let handle: String = rest
            .chars()
            .take_while(|&c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
            .collect();
        if handle.len() >= 4 {
            out.push(handle.to_lowercase());
        }
        if out.len() >= MAX_AT_MENTIONS {
            break;
        }
    }
    out
}

/// AU-079 — Profile attribute cross-mention identity bridge.
///
/// A platform profile's bio / about-me / twitter-handle field that names a
/// handle already in the entity graph is an explicit cross-platform self-
/// attribution by the subject — higher specificity than handle-variant
/// matching because the subject wrote it themselves.
///
/// Two classes of attribute are exploited:
///   * `twitter` — GitHub/LinkedIn store the linked Twitter handle as a
///     discrete structured attribute; no text parsing required.
///   * `bio`, `about_me` — freetext profile descriptions; @-mentions are
///     extracted and canonicalised.
///
/// Excludes generic/role handles (minimum 4 chars, `is_generic_handle` gate).
/// Severity: High — explicit self-reference across platforms from independent
/// sources is one of the strongest free identity links available.
pub(in crate::core::correlator) fn rule_au_079_bio_cross_mention(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Pre-build canonical username index so inner loop is O(1) per mention.
    let username_index: HashMap<String, &Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .filter_map(|e| {
            let ch = canonical_handle(&e.value);
            if ch.len() >= 4 && !is_generic_handle(&ch) {
                Some((ch, e))
            } else {
                None
            }
        })
        .collect();

    if username_index.is_empty() {
        return Vec::new();
    }

    // Attributes that may carry cross-platform handle references.
    const STRUCTURED_HANDLE_ATTRS: &[&str] = &["twitter", "instagram", "mastodon"];
    const BIO_TEXT_ATTRS: &[&str] = &["bio", "about_me", "description", "website", "blog"];

    let mut out: Vec<Correlation> = Vec::new();
    // Deduplicate (source_uid, mentioned_uid) pairs so the same cross-mention
    // from multiple evidence records doesn't produce duplicate correlations.
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for entity in entities.iter().filter(|e| e.kind == EntityKind::Username) {
        let src_canon = canonical_handle(&entity.value);
        if src_canon.len() < 4 || is_generic_handle(&src_canon) {
            continue;
        }

        for ev in &entity.evidence {
            // ── Structured handle attributes (no text parsing) ──────────────
            for attr in STRUCTURED_HANDLE_ATTRS {
                let Some(raw_handle) = ev.attributes.get(*attr) else {
                    continue;
                };
                let handle = raw_handle.trim_start_matches('@');
                let canon = canonical_handle(handle);
                if canon.len() < 4 || is_generic_handle(&canon) || canon == src_canon {
                    continue;
                }
                let Some(&mentioned_e) = username_index.get(&canon) else {
                    continue;
                };
                let pair = (entity.uid.clone(), mentioned_e.uid.clone());
                if seen.insert(pair) {
                    let mut uids = vec![entity.uid.clone(), mentioned_e.uid.clone()];
                    uids.sort_unstable();
                    out.push(Correlation {
                        rule_id: "AU-079".into(),
                        rule_name: "Profile attribute cross-mention identity bridge".into(),
                        severity: Severity::High,
                        description: format!(
                            "Username '{}' profile explicitly links to '{}' via the '{attr}' \
                             attribute — cross-platform self-attribution confirmed in a \
                             structured profile field (free, offline identity bridge)",
                            entity.value, mentioned_e.value,
                        ),
                        entity_uids: uids,
                        scan_id: scan_id.into(),
                        ts,
                        rank: 0.0,
                    });
                }
            }

            // ── Bio / freetext attributes (extract @-mentions) ──────────────
            for attr in BIO_TEXT_ATTRS {
                let Some(bio_text) = ev.attributes.get(*attr) else {
                    continue;
                };
                for mentioned_handle in extract_at_mentions(bio_text) {
                    let canon = canonical_handle(&mentioned_handle);
                    if canon.len() < 4 || is_generic_handle(&canon) || canon == src_canon {
                        continue;
                    }
                    let Some(&mentioned_e) = username_index.get(&canon) else {
                        continue;
                    };
                    let pair = (entity.uid.clone(), mentioned_e.uid.clone());
                    if seen.insert(pair) {
                        let mut uids = vec![entity.uid.clone(), mentioned_e.uid.clone()];
                        uids.sort_unstable();
                        out.push(Correlation {
                            rule_id: "AU-079".into(),
                            rule_name: "Profile attribute cross-mention identity bridge".into(),
                            severity: Severity::High,
                            description: format!(
                                "Username '{}' profile bio (@-mention) names '{}' — explicit \
                                 cross-platform self-reference written by the subject in their \
                                 '{attr}' field (free, offline identity bridge)",
                                entity.value, mentioned_e.value,
                            ),
                            entity_uids: uids,
                            scan_id: scan_id.into(),
                            ts,
                            rank: 0.0,
                        });
                    }
                }
            }
        }
    }
    out
}

/// AU-080 — Recurring co-occurrence identity association.
///
/// The cross-scan history pass tags entities that have appeared together in
/// prior investigations with `cross-scan-cooccurrence` and records the
/// partner's value in the evidence summary.  When both endpoints of a
/// historical co-occurrence appear in the current scan, the recurring
/// pairing is surfaced as an explicit correlation: two identifiers that
/// co-occur across multiple independent investigations are almost certainly
/// linked to the same subject.
///
/// Severity scales with frequency:
///   * High when either endpoint carries `hub-cooccurrence` (≥ 3 prior
///     scans) — a structurally significant, high-frequency association.
///   * Medium for pairs seen in fewer than 3 prior scans (a recurring
///     association, but not yet elevated to hub status).
///
/// Evidence is provenance-only (non-corroborating by design); this rule
/// surfaces the association as a visible finding without inflating C_eff.
pub(in crate::core::correlator) fn rule_au_080_recurring_cooccurrence_link(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // The co-occurrence evidence summary prefix written by the history pass.
    const COOCCURRENCE_PREFIX: &str = "Co-occurred with `";

    // Index entities by value for O(1) lookup of co-occurrence partners.
    let entity_by_value: HashMap<&str, &Entity> =
        entities.iter().map(|e| (e.value.as_str(), e)).collect();

    let mut out: Vec<Correlation> = Vec::new();
    // Deduplicate pairs (order-independent) so A→B and B→A don't both fire.
    let mut seen: HashSet<[String; 2]> = HashSet::new();

    for entity in entities
        .iter()
        .filter(|e| e.has_tag("cross-scan-cooccurrence"))
    {
        for ev in &entity.evidence {
            // Only parse cross-scan-history co-occurrence records.
            if ev.source != "cross_scan_history" {
                continue;
            }
            let Some(after_prefix) = ev.summary.strip_prefix(COOCCURRENCE_PREFIX) else {
                continue;
            };
            // Partner value is wrapped in backticks: `{value}` across ...
            let Some(backtick_end) = after_prefix.find('`') else {
                continue;
            };
            let partner_value = &after_prefix[..backtick_end];
            let Some(&partner_e) = entity_by_value.get(partner_value) else {
                continue;
            };

            // Deduplicate the pair (alphabetical order of UIDs).
            let mut pair = [entity.uid.clone(), partner_e.uid.clone()];
            pair.sort();
            if !seen.insert(pair) {
                continue;
            }

            // Parse shared scan count from "... across {n} earlier scan(s)..."
            let shared: usize = after_prefix[backtick_end + 1..]
                .trim_start()
                .strip_prefix("across ")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);

            let is_hub =
                entity.has_tag("hub-cooccurrence") || partner_e.has_tag("hub-cooccurrence");
            let severity = if is_hub {
                Severity::High
            } else {
                Severity::Medium
            };

            let mut uids = vec![entity.uid.clone(), partner_e.uid.clone()];
            uids.sort_unstable();
            out.push(Correlation {
                rule_id: "AU-080".into(),
                rule_name: "Recurring co-occurrence identity association".into(),
                severity,
                description: format!(
                    "{} '{}' and {} '{}' have appeared together in {shared} prior \
                     investigation(s) — a recurring structural association in the local \
                     intelligence database that bridges cases{}",
                    entity.kind,
                    entity.value,
                    partner_e.kind,
                    partner_e.value,
                    if is_hub { " (hub-level frequency)" } else { "" },
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }
    out
}

/// AU-081 — Canonical person name match across independent sources.
///
/// Two `Person` entities that normalise to the same canonical name but were
/// produced by different source families are almost certainly the same
/// individual: the same real-world person recorded by two independent
/// collection methods (e.g. name extracted from a breach record *and* from
/// a public professional profile).
///
/// Canonical normalisation: lowercase all words, strip punctuation used in
/// "Last, First" or hyphenated formats, sort tokens alphabetically.  This
/// makes all of `"Haigen Bamford"`, `"HAIGEN BAMFORD"`, `"Bamford, Haigen"`,
/// and `"Bamford-Haigen"` equivalent — the sort removes ordering ambiguity
/// and the case-fold handles all-caps breach dumps.
///
/// Gates: both entities must have ≥ 2 non-trivial (len ≥ 2) name tokens
/// after normalisation, and must come from at least one source family the
/// other does not share (independence requirement).  Single-token names
/// (initials only) are too ambiguous to link — excluded by the token-count
/// floor.
///
/// Commonness discount (mirrors AU-051 / AU-061 / `derive_kinship`): a full
/// name containing a *common* family name ("John Smith", "David Jones") is a
/// high-volume coincidence — many unrelated people share it, so an
/// independent match is a lead to VERIFY, not a confirmed merge. Such matches
/// fire at [`Severity::Medium`]; a match on a *distinctive* name (no common
/// token) stays [`Severity::High`], the confident identity bridge it has
/// always been. Conflating two real strangers who happen to share "John
/// Smith" mis-attributes evidence between them — the worst outcome for an
/// evidentiary tool, so the discount is applied here exactly as the kin rules
/// apply it to shared-surname pivots.
pub(in crate::core::correlator) fn rule_au_081_canonical_person_name_match(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Normalise: lowercase → split on whitespace/comma/hyphen/period → filter
    // ≥ 2-char tokens → sort → join with space.
    fn normalise_name(s: &str) -> Option<String> {
        let mut tokens: Vec<String> = s
            .split(|c: char| c.is_whitespace() || c == ',' || c == '-' || c == '.')
            .filter(|t| !t.is_empty())
            .map(str::to_lowercase)
            .filter(|t| t.len() >= 2)
            .collect();
        if tokens.len() < 2 {
            return None; // too ambiguous
        }
        tokens.sort();
        Some(tokens.join(" "))
    }

    let persons: Vec<(String, &Entity)> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .filter_map(|e| normalise_name(&e.value).map(|n| (n, e)))
        .collect();

    if persons.len() < 2 {
        return Vec::new();
    }

    let mut out: Vec<Correlation> = Vec::new();
    let mut seen: HashSet<[String; 2]> = HashSet::new();

    for i in 0..persons.len() {
        for j in (i + 1)..persons.len() {
            if persons[i].0 != persons[j].0 {
                continue;
            }
            let e1 = persons[i].1;
            let e2 = persons[j].1;

            // Independence gate. "Independent" means the two records were
            // collected by genuinely different real-world methods — so every part
            // of the gate runs over CORROBORATING sources only
            // ([`Entity::corroborating_sources`]), NOT the raw `evidence` list.
            // The deterministic self-enrichment passes (`name_intel`'s own
            // firstname/lastname permutation of the seed, `geo_normalize`) and the
            // `recall` / `cross_scan_history` replays attach useful evidence but
            // are NOT independent observations — `name_intel` in particular DERIVES
            // a `Person` from the seed name and maps to the real `identity_registry`
            // family, so hand-rolling the sets from raw `evidence` (as this rule
            // used to) let the tool's OWN name derivation pose as a second,
            // independently-sourced record and manufacture a High "same individual"
            // match. This is the identical honest set `source_families` /
            // `source_count` already build on.
            let src1 = e1.corroborating_sources();
            let src2 = e2.corroborating_sources();
            // (0) A name known ONLY from the tool's own derivation (`name_intel`)
            //     or a prior-scan replay (`recall`) is not an independently
            //     collected record at all — a side with no corroborating source
            //     can never be one half of an "independent match".
            if src1.is_empty() || src2.is_empty() {
                continue;
            }
            // (1) Skip when the exact corroborating-source SETS are equal —
            //     literally the same source(s) re-derived the name.
            if src1 == src2 {
                continue; // exactly the same source(s) — not independent
            }
            // (2) Skip when the source FAMILY sets are equal — records of the same
            //     family are co-derived, not independent, so two breach databases
            //     (both family "breach") do NOT fire on their own; a match needs at
            //     least one differing family (e.g. breach + social). This is
            //     stricter than gate (1): identical families can still have
            //     different `source` strings, which (1) alone would let through.
            let fam1: HashSet<&str> = src1.iter().map(|s| source_family(s)).collect();
            let fam2: HashSet<&str> = src2.iter().map(|s| source_family(s)).collect();
            if fam1 == fam2 {
                continue;
            }

            let mut pair = [e1.uid.clone(), e2.uid.clone()];
            pair.sort();
            if !seen.insert(pair) {
                continue;
            }

            // Label the match with the first genuine (corroborating) source, never
            // a `name_intel`/`recall` pass — the gate above guarantees both sides
            // carry one, so the `"unknown"` fallback is purely defensive. A local
            // `fn` (not a closure) so the returned `&str` borrows from its argument.
            fn corr_label(e: &Entity) -> &str {
                e.evidence
                    .iter()
                    .map(|ev| ev.source.as_str())
                    .find(|s| !crate::core::entity::is_non_corroborating_source(s))
                    .unwrap_or("unknown")
            }
            let src1_label = corr_label(e1);
            let src2_label = corr_label(e2);

            let mut uids = vec![e1.uid.clone(), e2.uid.clone()];
            uids.sort_unstable();

            // A common family name inflates full-name coincidence (many
            // unrelated "John Smith"s share it), so an independent match is a
            // lead to VERIFY — not a confirmed merge. Mirror the AU-051 /
            // AU-061 / kinship commonness discount: distinctive names stay a
            // High identity bridge, common ones drop to a Medium lead. The
            // canonical name is already lowercased and space-joined, so its
            // tokens feed `is_common` directly.
            let common = persons[i]
                .0
                .split(' ')
                .any(crate::util::surnames::is_common);
            let (severity, tail) = if common {
                (
                    Severity::Medium,
                    "a COMMON name many unrelated people share — a lead to VERIFY, \
                     not a confirmed merge",
                )
            } else {
                (
                    Severity::High,
                    "independently-sourced records for the same individual \
                     (free, offline identity bridge)",
                )
            };
            out.push(Correlation {
                rule_id: "AU-081".into(),
                rule_name: "Canonical person name match".into(),
                severity,
                description: format!(
                    "Person records '{}' (via {src1_label}) and '{}' (via {src2_label}) \
                     normalise to the same canonical name — {tail}",
                    e1.value, e2.value,
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }
    out
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
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
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

/// Platforms whose `platform:handle` Username nodes `breach_rich` mints — kept in
/// lockstep with `breach_rich`'s extra-social-handle list (`breach_rich.rs`). A
/// breach-listed account on one of these counts toward the cross-platform
/// footprint; any other value prefix (an epieos `google:<id>`, …) is ignored.
const BREACH_SOCIAL_PLATFORMS: &[&str] = &[
    "telegram",
    "skype",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "vk",
    "snapchat",
];

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
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeSet;
    let mut platforms: BTreeSet<&'static str> = BTreeSet::new();
    let mut uids: Vec<String> = Vec::new();
    for e in entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username && e.has_tag("breach"))
    {
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
