//! AU correlation rules — identity family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

pub(in crate::core::correlator) fn rule_au_002_identity_cluster(
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

/// AU-045 — Multi-service identity confirmation.
///
/// An identity value (email / username / person) whose corroborating sources
/// span **two or more distinct service families** (breach, social, presence,
/// search, email-intel, identity-registry, infra) is independently confirmed
/// across the system, not merely echoed by one kind of provider. This is the
/// strongest honest signal for an alias investigation and the explicit
/// cross-service cross-reference the operator program asks for: it differs from
/// AU-003 (which counts distinct sources regardless of kind) by requiring
/// *diversity of provider family* — a handle confirmed by GitHub AND a breach DB
/// AND a search engine is far stronger evidence of a real identity than three
/// breach DBs that may all quote one leaked record. Directly counters the
/// single-source fragility a result-matrix analysis surfaced: it rewards genuine
/// cross-provider agreement and makes it a first-class, ranked finding.
pub(in crate::core::correlator) fn rule_au_045_multi_service_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeSet;
    const MIN_FAMILIES: usize = 2;
    entities
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                EntityKind::Email | EntityKind::Username | EntityKind::Person
            )
        })
        .filter_map(|e| {
            // Distinct provider families across this entity's corroborating
            // sources, ignoring the unclassified `other` bucket so a stray
            // unknown source can't fabricate diversity.
            let families: BTreeSet<&'static str> = e
                .corroborating_sources()
                .iter()
                .map(|s| source_family(s))
                .filter(|f| *f != "other")
                .collect();
            if families.len() < MIN_FAMILIES {
                return None;
            }
            let listed: Vec<&str> = families.iter().copied().collect();
            Some(Correlation {
                rule_id: "AU-045".into(),
                rule_name: "Multi-service identity confirmation".into(),
                severity: Severity::High,
                description: format!(
                    "{} '{}' independently confirmed across {} service families: {}",
                    e.kind,
                    e.value,
                    listed.len(),
                    listed.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            })
        })
        .collect()
}

/// AU-046 — Cross-platform identity resolution.
///
/// The investigative payoff of the keyless account modules: when an alias
/// (a Username confirmed across **≥2 distinct platform families** — code/forum/
/// social/presence) has also yielded real-world identifiers (an Email or Person)
/// *from those platform accounts*, the handle is no longer just "present on N
/// sites" — it is **resolved to an identity**. This links the alias to the
/// email(s)/person(s) its GitHub/npm/Reddit/Keybase profiles expose, producing
/// the individualised, subject-as-hub result an alias investigation is for.
///
/// Distinct from AU-045 (which only confirms the handle exists across families)
/// and AU-002 (which needs email+username+phone all present): AU-046 is the
/// *handle → identity* edge, drawn only from identifiers a platform account
/// itself published, so it can't fuse unrelated breach-dump strangers.
pub(in crate::core::correlator) fn rule_au_046_cross_platform_identity_resolution(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeSet;
    // Platform-account provider families — the ones where a confirmed handle is
    // an account a person controls (not infra/breach corpora).
    let is_platform = |f: &str| matches!(f, "code" | "forum" | "social" | "presence");
    let platform_families = |e: &Entity| -> BTreeSet<&'static str> {
        e.corroborating_sources()
            .iter()
            .map(|s| source_family(s))
            .filter(|f| is_platform(f))
            .collect()
    };

    // The alias: a username controlled across ≥2 distinct platform families.
    let aliases: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username && platform_families(e).len() >= 2)
        .collect();
    if aliases.is_empty() {
        return Vec::new();
    }

    // Real-world identifiers the platform accounts themselves exposed.
    let resolved: Vec<&Entity> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Email | EntityKind::Person))
        .filter(|e| {
            e.corroborating_sources()
                .iter()
                .any(|s| matches!(source_family(s), "code" | "forum" | "social"))
        })
        .collect();
    if resolved.is_empty() {
        return Vec::new();
    }

    let resolved_uids: Vec<String> = resolved.iter().map(|e| e.uid.clone()).collect();
    aliases
        .iter()
        .map(|alias| {
            let fams = platform_families(alias);
            let fam_list: Vec<&str> = fams.iter().copied().collect();
            let mut uids = vec![alias.uid.clone()];
            uids.extend(resolved_uids.iter().cloned());
            Correlation {
                rule_id: "AU-046".into(),
                rule_name: "Cross-platform identity resolution".into(),
                severity: Severity::High,
                description: format!(
                    "Alias '{}' (confirmed across {}: {}) resolves to {} real-world identifier(s) via its platform accounts",
                    alias.value,
                    fam_list.len(),
                    fam_list.join(", "),
                    resolved.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
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

pub(in crate::core::correlator) fn rule_au_003_high_corroboration(
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

pub(in crate::core::correlator) fn rule_au_020_person_entity_cluster(
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

pub(in crate::core::correlator) fn rule_au_023_cross_platform_identity(
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
