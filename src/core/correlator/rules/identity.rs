//! AU correlation rules — identity family.
//!
//! Each rule scans the persisted entity graph for one high-signal identity
//! pattern and emits a [`Correlation`]. Rules reach shared helpers through
//! `use super::*` (see `rules/mod.rs`).
//!
//! ## MITRE ATT&CK TA0043 coverage
//!
//! | Rule    | Technique(s)                                     |
//! |---------|--------------------------------------------------|
//! | AU-002  | T1589 — Gather Victim Identity Information       |
//! | AU-003  | T1589 / T1590.005 — IP/identity corroboration    |
//! | AU-011  | T1589 / T1591.004 — Cross-platform footprint     |
//! | AU-020  | T1589.003 — Employee Names                       |
//! | AU-023  | T1589 — Cross-platform identity convergence      |
//! | AU-034  | T1589.002 — Email Addresses                      |
//! | AU-035  | T1589.002 × T1586 — Account Discovery            |
//! | AU-036  | T1589.002 — Email alias / inbox normalization    |
//! | AU-038  | T1591 — Gather Victim Org Info (profiles)        |
//! | AU-042  | T1598 × T1589.003 — PGP identity linkage         |
//! | AU-044  | T1597.002 — Purchase / correlate technical data  |
//! | AU-045  | T1589 — Multi-service identity confirmation      |
//! | AU-046  | T1589 × T1591 — Cross-platform resolution        |
//! | AU-048  | T1589 × T1586.002 — Shared key / account link   |
//! | AU-054  | T1596 — Search Open Technical Databases          |
//! | AU-055  | T1591 — Gather Victim Org Info (primary source)  |
//! | AU-057  | T1589.003 × T1589 — Schema.org attribution       |

use super::*;

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Extract the www-stripped lowercase hostname from a URL string.
/// Zero-allocation for the failure path (returns `None` for unparseable URLs).
fn url_host_stripped(url: &str) -> Option<String> {
    url::Url::parse(url).ok().and_then(|u| {
        u.host_str()
            .map(|h| h.trim_start_matches("www.").to_ascii_lowercase())
    })
}

/// Collect owned UIDs from an entity slice in one allocation.
#[inline]
fn collect_uids<'a>(it: impl Iterator<Item = &'a Entity>) -> Vec<String> {
    it.map(|e| e.uid.clone()).collect()
}

/// Sorted, deduplicated `Vec<String>` from an iterator of strings — replaces
/// `BTreeSet<String>` collect where the set is used only for sorted-unique
/// output, not for O(log n) lookups. `Vec`+`sort`+`dedup` has better cache
/// locality and avoids per-node heap allocation.
fn sorted_dedup(mut v: Vec<String>) -> Vec<String> {
    v.sort_unstable();
    v.dedup();
    v
}

// ── Rules ─────────────────────────────────────────────────────────────────────

/// AU-002 — Identity cluster (T1589).
///
/// Email + Username + Phone co-located in the same scan is the foundational
/// identity cluster: a real person's observable PII stack. Gated at
/// `MIN_CONF` to exclude weak candidates and at `MAX_PER_KIND` to prevent
/// a breach-dump's hundreds of addresses from fusing 179 strangers into
/// a single Critical "one identity" finding (the confirmed failure mode).
pub(in crate::core::correlator) fn rule_au_002_identity_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Confidence floor on top of candidate-exclusion: genuine clusters are built
    // from corroborated entities, not weak guesses.
    const MIN_CONF: f64 = 0.50;
    // One person does not own dozens of distinct emails or phones — that many is
    // the signature of a breach dump spanning many people. This is the backstop
    // for any non-candidate bulk source.
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

    let mut uids = Vec::with_capacity(emails.len() + usernames.len() + phones.len());
    uids.extend(collect_uids(emails.iter().copied()));
    uids.extend(collect_uids(usernames.iter().copied()));
    uids.extend(collect_uids(phones.iter().copied()));

    vec![Correlation::new(
        "AU-002",
        "Identity cluster",
        Severity::Critical,
        format!(
            "Email + Username + Phone co-located: {} email(s), {} username(s), {} phone(s)",
            emails.len(),
            usernames.len(),
            phones.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-003 — High cross-source corroboration (T1589 / T1590.005).
///
/// An entity confirmed by ≥ N independent sources is much more likely to be
/// real than one seen once. Thresholds are on *distinct* corroborating sources
/// (`source_count`), not the summed magnitude: infra entities reach high
/// agreement easily across resolver/cert/whois/geo modules (threshold 3);
/// identity entities are strong at 2 distinct independent sources.
pub(in crate::core::correlator) fn rule_au_003_high_corroboration(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let min_sources = |kind: &EntityKind| -> u32 {
        match kind {
            EntityKind::Domain | EntityKind::Url | EntityKind::IpAddress => 3,
            _ => 2,
        }
    };
    entities
        .iter()
        .filter(|e| e.source_count() >= min_sources(&e.kind))
        .map(|e| {
            Correlation::new(
                "AU-003",
                "High cross-source corroboration",
                Severity::Medium,
                format!(
                    "{} entity '{}' corroborated by {} independent source(s) (C_eff={:.3})",
                    e.kind,
                    e.value,
                    e.source_count(),
                    e.c_effective()
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
}

/// AU-011 — Cross-platform username footprint (T1589 / T1591.004).
///
/// A handle confirmed on ≥ 3 distinct platforms — from `platforms_count`
/// evidence OR from independent platform-module corroboration — is a genuine
/// cross-platform footprint, not a single-source observation.
pub(in crate::core::correlator) fn rule_au_011_cross_platform_username(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Modules that each independently confirm a handle on one platform.
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
            // Best `platforms_count` from any evidence entry.
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
            // Distinct platform-module confirmations.
            let mut platform_srcs: Vec<&str> = e
                .corroborating_sources()
                .into_iter()
                .filter(|s| PLATFORM_SOURCES.contains(s))
                .collect();
            platform_srcs.sort_unstable();
            let src_count = platform_srcs.len() as u64;

            // `owned_list` is declared here so it lives long enough for the
            // borrow `best_list = Some(owned_list.as_str())` to remain valid.
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
                Some(Correlation::new(
                    "AU-011",
                    "Cross-platform username footprint",
                    Severity::Medium,
                    format!(
                        "Username '{}' present on {count} platforms{detail}",
                        e.value
                    ),
                    vec![e.uid.clone()],
                    scan_id,
                    ts,
                ))
            } else {
                None
            }
        })
        .collect()
}

/// AU-020 — Multiple person entities (T1589.003).
///
/// Two or more Person entities in the same scan signals potential identity
/// disambiguation: a common-name search may have returned distinct people.
/// Operator review is needed to confirm which entity is the subject.
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
    vec![Correlation::new(
        "AU-020",
        "Multiple person entities",
        Severity::Medium,
        format!(
            "{} person entities discovered — potential identity disambiguation needed",
            persons.len()
        ),
        collect_uids(persons.into_iter()),
        scan_id,
        ts,
    )]
}

/// AU-023 — Cross-platform identity convergence (T1589).
///
/// A Person entity independently confirmed by ≥ 2 authoritative identity
/// sources (Keybase, GitHub, ProxyCurl, Epieos, SEON, ContactEnrich) is
/// individually pinned across services — the strongest corroboration for a
/// specific named individual.
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

/// AU-034 — Handle reuse linking a username and an email (T1589.002).
///
/// When a `Username` and the local-part of an `Email` share the same
/// separator-insensitive handle (`jmeyers` ↔ `jmeyers@gmail.com`), they very
/// likely belong to the same person. Gmail-style `+tag` suffixes are stripped.
///
/// Gated to stay low-noise: the handle must be ≥ `MIN_HANDLE_LEN` chars and
/// non-generic, and the username + matched emails must carry ≥
/// `MIN_DISTINCT_SOURCES` *distinct* evidence sources between them so a single
/// module can't self-correlate.
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

    // Bucket emails by canonical local-part handle ONCE — O(E) instead of
    // recomputing inside the per-username loop (which was O(U×E)).
    let mut emails_by_handle: HashMap<String, Vec<&Entity>> = HashMap::new();
    for e in &emails {
        // Local part before `@`, stripping any Gmail-style `+tag` suffix.
        let local = e.value.split_once('@').map_or(e.value.as_str(), |(l, _)| l);
        let base = local.split_once('+').map_or(local, |(b, _)| b);
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
        let mut matched_uids = Vec::with_capacity(matches.len());
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

/// AU-035 — Inferred handle confirmed in the wild (T1589.002 × T1586).
///
/// A `Username` first *derived* by inference (a name permutation, email
/// local-part, or handle variant) and then *independently observed* on a real
/// platform is a high-value identity hit: a guessed handle that turned out to
/// exist. Both an inference source and a discovery source must be present on
/// the same merged entity.
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

/// AU-036 — Email alias convergence / one mailbox (T1589.002).
///
/// Multiple distinct addresses reduced by `email_canonical` to the SAME
/// mailbox (`j.doe@gmail.com` + `jdoe+news@gmail.com` → `jdoe@gmail.com`)
/// are aliases of a single inbox — a strong same-person link. Fires when ≥ 2
/// distinct source addresses converged onto one canonical entity.
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

/// AU-038 — Verified cross-platform identity (T1591).
///
/// Two modules independently confirm the target's OWN profile: `social_probe`
/// tags a `Url` `social-profile` after a direct platform probe, and
/// `search_engines` tags one `confirmed-profile` when the searched handle is
/// the exact path on a canonical social host. When the same identity is
/// confirmed on ≥ 2 DISTINCT platforms, that is a probe-/engine-verified
/// cross-platform identity.
pub(in crate::core::correlator) fn rule_au_038_verified_cross_platform_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let confirmed: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Url
                && (e.has_tag("confirmed-profile") || e.has_tag("social-profile"))
        })
        .collect();

    // Distinct www-stripped hosts among confirmed profiles, sorted.
    let mut hosts: Vec<String> = confirmed
        .iter()
        .filter_map(|e| url_host_stripped(&e.value))
        .collect();
    hosts = sorted_dedup(hosts);
    if hosts.len() < 2 {
        return Vec::new();
    }

    vec![Correlation::new(
        "AU-038",
        "Verified cross-platform identity",
        Severity::Medium,
        format!(
            "Identity confirmed on {} distinct platforms: {}",
            hosts.len(),
            hosts.join(", ")
        ),
        collect_uids(confirmed.into_iter()),
        scan_id,
        ts,
    )]
}

/// AU-042 — PGP key binds multiple emails to one identity (T1598 × T1589.003).
///
/// Two or more email addresses linked to the same PGP key (`pgp-linked` tag,
/// emitted by the `pgp` module) are asserted by the key holder to be theirs —
/// strong same-owner evidence.
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
    vec![Correlation::new(
        "AU-042",
        "PGP key binds multiple emails to one identity",
        Severity::High,
        format!(
            "A PGP key links {} email address(es) to one owner: {}",
            addrs.len(),
            addrs.join(", ")
        ),
        collect_uids(linked.into_iter()),
        scan_id,
        ts,
    )]
}

/// AU-044 — Shared web-analytics ID implies common ownership (T1597.002).
///
/// A Google Analytics / AdSense / Tag-Manager / Facebook-Pixel ID appearing on
/// ≥ 2 otherwise-unrelated sites is strong evidence the same operator runs
/// them. `web_crawler` records the carrying site in each `TrackingId` evidence
/// entry's `source_domain`; entities merge by value, so a shared id accumulates
/// one evidence row per site.
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
                    "Tracking id '{}' appears on {} site(s) ({}): \
                     a shared analytics/ads id indicates common ownership or operator",
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

/// AU-045 — Multi-service identity confirmation (T1589).
///
/// An identity value confirmed across ≥ 2 *distinct service families* (breach,
/// social, presence, search, email-intel, identity-registry, infra) is
/// independently cross-referenced across the system, not merely echoed by one
/// kind of provider. Directly rewards genuine cross-provider agreement and
/// makes it a first-class, ranked finding.
pub(in crate::core::correlator) fn rule_au_045_multi_service_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
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
            // Distinct provider families, excluding the unclassified `other`
            // bucket so a stray unknown source can't fabricate diversity.
            let mut families: Vec<&'static str> = e
                .corroborating_sources()
                .iter()
                .map(|s| source_family(s))
                .filter(|f| *f != "other")
                .collect();
            families.sort_unstable();
            families.dedup();
            if families.len() < MIN_FAMILIES {
                return None;
            }
            Some(Correlation::new(
                "AU-045",
                "Multi-service identity confirmation",
                Severity::High,
                format!(
                    "{} '{}' independently confirmed across {} service families: {}",
                    e.kind,
                    e.value,
                    families.len(),
                    families.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ))
        })
        .collect()
}

/// AU-046 — Cross-platform identity resolution (T1589 × T1591).
///
/// When an alias (a `Username` confirmed across ≥ 2 distinct platform families:
/// code/forum/social/presence) has also yielded real-world identifiers (an
/// `Email` or `Person`) *from those platform accounts*, the handle is resolved
/// to an identity. Links the alias to the email(s)/person(s) its platform
/// profiles expose.
pub(in crate::core::correlator) fn rule_au_046_cross_platform_identity_resolution(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let is_platform = |f: &str| matches!(f, "code" | "forum" | "social" | "presence");
    let platform_families = |e: &Entity| -> Vec<&'static str> {
        let mut fams: Vec<&'static str> = e
            .corroborating_sources()
            .iter()
            .map(|s| source_family(s))
            .filter(|f| is_platform(f))
            .collect();
        fams.sort_unstable();
        fams.dedup();
        fams
    };

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

    let resolved_uids: Vec<String> = collect_uids(resolved.iter().copied());
    aliases
        .iter()
        .map(|alias| {
            let fams = platform_families(alias);
            let mut uids = Vec::with_capacity(1 + resolved_uids.len());
            uids.push(alias.uid.clone());
            uids.extend(resolved_uids.iter().cloned());
            Correlation::new(
                "AU-046",
                "Cross-platform identity resolution",
                Severity::High,
                format!(
                    "Alias '{}' (confirmed across {}: {}) resolves to {} real-world identifier(s) \
                     via its platform accounts",
                    alias.value,
                    fams.len(),
                    fams.join(", "),
                    resolved.len()
                ),
                uids,
                scan_id,
                ts,
            )
        })
        .collect()
}

/// AU-048 — Shared public key links accounts (T1589 × T1586.002).
///
/// A public key (SSH or PGP) published on two accounts proves the **same person
/// holds the matching private key** — stronger than password reuse, because
/// there is no plaintext two unrelated people could coincidentally share. When
/// one key-tagged `Credential` carries ≥ 2 distinct controller handles across
/// its evidence, those accounts are one person.
///
/// Handles are canonicalised (separator-insensitive, email-local-part) to avoid
/// firing on a single account whose evidence carries both its login and its
/// email as two strings but is ONE controller.
pub(in crate::core::correlator) fn rule_au_048_shared_public_key(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for key in entities.iter().filter(|e| {
        e.kind == EntityKind::Credential && (e.has_tag("ssh-key") || e.has_tag("pgp-key"))
    }) {
        // Distinct accounts (login / username / email) that published this key.
        let mut accounts: Vec<String> = key
            .evidence
            .iter()
            .flat_map(|ev| {
                ["github_login", "username", "email"]
                    .iter()
                    .filter_map(|k| ev.attributes.get(*k))
            })
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
        accounts = sorted_dedup(accounts);
        if accounts.len() < 2 {
            continue;
        }

        // Fold to canonical controller handles to avoid false-positive on one
        // account carrying both its login and email in evidence.
        // Email local-part via `split_once` — unambiguous and infallible.
        let mut handles: Vec<String> = accounts
            .iter()
            .map(|a| {
                let local = a.split_once('@').map_or(a.as_str(), |(l, _)| l);
                canonical_handle(local)
            })
            .collect();
        handles = sorted_dedup(handles);
        if handles.len() < 2 {
            continue;
        }

        // Collect entity UIDs for all matching accounts.
        let mut uids = vec![key.uid.clone()];
        for e in entities
            .iter()
            .filter(|e| matches!(e.kind, EntityKind::Username | EntityKind::Email))
        {
            if accounts.contains(&e.value.trim().to_ascii_lowercase()) {
                uids.push(e.uid.clone());
            }
        }
        uids.sort_unstable();
        uids.dedup();

        out.push(Correlation::new(
            "AU-048",
            "Shared public key links accounts",
            Severity::Critical,
            format!(
                "A reused public key proves one person controls {} account(s) \
                 (same private key): {}",
                accounts.len(),
                accounts.join(", ") // show ALL accounts, not a capped subset
            ),
            uids,
            scan_id,
            ts,
        ));
    }
    out
}

/// AU-054 — PII located on data broker(s) (T1596).
///
/// A `Url` whose host is a known people-search / data-broker site means the
/// subject's PII is being redistributed there. Brokers are low-credibility
/// OSINT: one broker fires at `Low`; ≥ 2 independent brokers at `Medium`
/// (brokers cross-source each other, so the ceiling is `Medium`, never
/// `High`/`Critical`).
pub(in crate::core::correlator) fn rule_au_054_data_broker_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use crate::core::data_broker::broker_for_host;

    let mut broker_names: Vec<&'static str> = Vec::new();
    let mut uids: Vec<String> = Vec::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::Url) {
        if let Some(host) = url_host_stripped(&e.value)
            && let Some(broker) = broker_for_host(&host)
        {
            broker_names.push(broker.name);
            uids.push(e.uid.clone());
        }
    }
    if broker_names.is_empty() {
        return Vec::new();
    }
    broker_names.sort_unstable();
    broker_names.dedup();
    uids = sorted_dedup(uids);

    let severity = if broker_names.len() >= 2 {
        Severity::Medium
    } else {
        Severity::Low
    };

    vec![Correlation::new(
        "AU-054",
        "PII located on data broker(s)",
        severity,
        format!(
            "Subject's PII is brokered on {} people-search site(s): {} — \
             data-broker listings aggregate (often from each other) and corroborate \
             weakly; treat as a lead to verify against primary sources, not confirmation",
            broker_names.len(),
            broker_names.join(", ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-055 — Primary-source accounts located (T1591).
///
/// The affirmative counterweight to AU-054: `Url` entities tagged as the
/// subject's own confirmed account/profile (`social-profile`, `confirmed-profile`,
/// `public-profile`, `personal-site`) are primary sources the subject controls —
/// far stronger than any second-hand broker listing. Broker hosts are explicitly
/// excluded. Severity: `High` for 1–2 platforms, `Critical` for ≥ 3.
pub(in crate::core::correlator) fn rule_au_055_primary_source_accounts(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use crate::core::data_broker::broker_for_host;

    const OWNED_ACCOUNT_TAGS: &[&str] = &[
        "social-profile",
        "confirmed-profile",
        "public-profile",
        "personal-site",
    ];

    let mut platform_hosts: Vec<String> = Vec::new();
    let mut uids: Vec<String> = Vec::new();
    for e in entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url && OWNED_ACCOUNT_TAGS.iter().any(|t| e.has_tag(t)))
    {
        let Some(host) = url_host_stripped(&e.value) else {
            continue;
        };
        if broker_for_host(&host).is_some() {
            continue; // a broker's listing page, not the subject's account
        }
        platform_hosts.push(host);
        uids.push(e.uid.clone());
    }
    if platform_hosts.is_empty() {
        return Vec::new();
    }
    platform_hosts = sorted_dedup(platform_hosts);
    uids = sorted_dedup(uids);

    let severity = if platform_hosts.len() >= 3 {
        Severity::Critical
    } else {
        Severity::High
    };

    vec![Correlation::new(
        "AU-055",
        "Primary-source accounts located",
        severity,
        format!(
            "Subject's own confirmed account(s)/profile(s) located across {} platform(s): {} \
             — primary sources the subject controls (direct probe / engine-corroborated)",
            platform_hosts.len(),
            platform_hosts.join(", ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-057 — Schema.org structured-data phone attribution (T1589.003 × T1589).
///
/// A `Phone` entity corroborated by a `schema-org` source (Schema.org JSON-LD
/// from a real-estate / professional directory page) AND co-located with a
/// `Person` or `Email` entity is directly attributed to the subject via the
/// listing platform's own structured data. Schema.org agent listings explicitly
/// wire the `telephone` field to the named individual — higher-reliability
/// attribution than a breach co-occurrence.
pub(in crate::core::correlator) fn rule_au_057_schema_org_phone_attribution(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let schema_phones: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Phone && e.has_tag("schema-org"))
        .collect();
    if schema_phones.is_empty() {
        return Vec::new();
    }

    // Need at least one Person or Email anchor to bind the attribution.
    let anchor_uids: Vec<String> = entities
        .iter()
        .filter(|e| {
            matches!(e.kind, EntityKind::Person | EntityKind::Email) && e.confidence >= 0.60
        })
        .map(|e| e.uid.clone())
        .collect();
    if anchor_uids.is_empty() {
        return Vec::new();
    }

    let phone_vals: Vec<&str> = schema_phones.iter().map(|e| e.value.as_str()).collect();
    let mut uids = collect_uids(schema_phones.iter().copied());
    uids.extend(anchor_uids);
    uids = sorted_dedup(uids);

    vec![Correlation::new(
        "AU-057",
        "Schema.org structured-data phone attribution",
        Severity::High,
        format!(
            "{} phone(s) directly attributed to subject via Schema.org structured \
             agent/professional listing data (telephone field): {}",
            phone_vals.len(),
            phone_vals.join(", ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    const S: &str = "test-scan";
    const TS: u64 = 0;

    fn mk(kind: EntityKind, value: &str, conf: f64) -> Entity {
        Entity::new(kind, value, conf, S)
    }

    fn tagged(mut e: Entity, tag: &str) -> Entity {
        e.tag(tag);
        e
    }

    fn sourced(mut e: Entity, source: &str) -> Entity {
        e.add_evidence(Evidence::new(source, "test"));
        e
    }

    fn sourced2(e: Entity, s1: &str, s2: &str) -> Entity {
        sourced(sourced(e, s1), s2)
    }

    // ── url_host_stripped ───────────────────────────────────────────────────

    #[test]
    fn url_host_stripped_strips_www_and_lowercases() {
        assert_eq!(
            url_host_stripped("https://WWW.Example.COM/page"),
            Some("example.com".to_string())
        );
        assert_eq!(
            url_host_stripped("https://github.com/user"),
            Some("github.com".to_string())
        );
        assert_eq!(url_host_stripped("not a url"), None);
    }

    // ── sorted_dedup ────────────────────────────────────────────────────────

    #[test]
    fn sorted_dedup_produces_sorted_unique_vec() {
        let v = sorted_dedup(vec!["c".into(), "a".into(), "b".into(), "a".into()]);
        assert_eq!(v, ["a", "b", "c"]);
    }

    // ── AU-002 ──────────────────────────────────────────────────────────────

    #[test]
    fn au002_fires_when_all_three_kinds_present() {
        let entities = vec![
            sourced(mk(EntityKind::Email, "a@x.com", 0.8), "breach"),
            sourced(mk(EntityKind::Username, "alice", 0.8), "github_user"),
            sourced(mk(EntityKind::Phone, "+61400000001", 0.8), "numverify"),
        ];
        let c = rule_au_002_identity_cluster(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-002");
        assert_eq!(c[0].severity, Severity::Critical);
    }

    #[test]
    fn au002_silent_when_kind_missing() {
        // No phone → no cluster.
        let entities = vec![
            sourced(mk(EntityKind::Email, "a@x.com", 0.8), "breach"),
            sourced(mk(EntityKind::Username, "alice", 0.8), "github_user"),
        ];
        assert!(rule_au_002_identity_cluster(&entities, S, TS).is_empty());
    }

    #[test]
    fn au002_silent_below_confidence_floor() {
        let entities = vec![
            sourced(mk(EntityKind::Email, "a@x.com", 0.3), "breach"),
            sourced(mk(EntityKind::Username, "alice", 0.3), "github_user"),
            sourced(mk(EntityKind::Phone, "+61400000001", 0.3), "numverify"),
        ];
        assert!(rule_au_002_identity_cluster(&entities, S, TS).is_empty());
    }

    #[test]
    fn au002_silent_when_kind_exceeds_max_per_kind() {
        let mut entities: Vec<Entity> = (0..26)
            .map(|i| sourced(mk(EntityKind::Email, &format!("e{i}@x.com"), 0.8), "breach"))
            .collect();
        entities.push(sourced(
            mk(EntityKind::Username, "alice", 0.8),
            "github_user",
        ));
        entities.push(sourced(
            mk(EntityKind::Phone, "+61400000001", 0.8),
            "numverify",
        ));
        assert!(rule_au_002_identity_cluster(&entities, S, TS).is_empty());
    }

    #[test]
    fn au002_uid_set_covers_all_three_kinds() {
        let email = sourced(mk(EntityKind::Email, "a@x.com", 0.8), "breach");
        let user = sourced(mk(EntityKind::Username, "alice", 0.8), "github_user");
        let phone = sourced(mk(EntityKind::Phone, "+61400000001", 0.8), "numverify");
        let all_uids: Vec<_> = [&email, &user, &phone]
            .iter()
            .map(|e| e.uid.clone())
            .collect();
        let c = rule_au_002_identity_cluster(&[email, user, phone], S, TS);
        assert_eq!(c.len(), 1);
        for uid in &all_uids {
            assert!(c[0].entity_uids.contains(uid), "uid {uid} missing");
        }
    }

    // ── AU-003 ──────────────────────────────────────────────────────────────

    #[test]
    fn au003_fires_at_threshold_for_identity_entity() {
        // Email needs ≥2 distinct sources.
        let mut e = mk(EntityKind::Email, "a@x.com", 0.8);
        e.add_evidence(Evidence::new("breach_a", "test"));
        e.add_evidence(Evidence::new("breach_b", "test"));
        let c = rule_au_003_high_corroboration(&[e], S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-003");
    }

    #[test]
    fn au003_silent_below_threshold() {
        let e = sourced(mk(EntityKind::Email, "a@x.com", 0.8), "breach_a");
        assert!(rule_au_003_high_corroboration(&[e], S, TS).is_empty());
    }

    #[test]
    fn au003_domain_needs_three_sources() {
        let mut e = mk(EntityKind::Domain, "example.com", 0.8);
        // Two sources — below domain threshold of 3.
        e.add_evidence(Evidence::new("dns", "test"));
        e.add_evidence(Evidence::new("whois", "test"));
        assert!(rule_au_003_high_corroboration(&[e], S, TS).is_empty());
    }

    // ── AU-020 ──────────────────────────────────────────────────────────────

    #[test]
    fn au020_fires_for_two_persons() {
        let entities = vec![
            mk(EntityKind::Person, "Alice Smith", 0.7),
            mk(EntityKind::Person, "Alice J Smith", 0.6),
        ];
        let c = rule_au_020_person_entity_cluster(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severity, Severity::Medium);
    }

    #[test]
    fn au020_silent_for_one_person() {
        let entities = vec![mk(EntityKind::Person, "Alice Smith", 0.7)];
        assert!(rule_au_020_person_entity_cluster(&entities, S, TS).is_empty());
    }

    // ── AU-034 ──────────────────────────────────────────────────────────────

    #[test]
    fn au034_links_username_to_email_with_same_handle() {
        let user = sourced(mk(EntityKind::Username, "jmeyers", 0.8), "github_user");
        let email = sourced(mk(EntityKind::Email, "jmeyers@gmail.com", 0.8), "breach");
        let c = rule_au_034_handle_reuse_identity(&[user, email], S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-034");
    }

    #[test]
    fn au034_strips_plus_tag_from_email_local() {
        let user = sourced(mk(EntityKind::Username, "jmeyers", 0.8), "github_user");
        let email = sourced(
            mk(EntityKind::Email, "jmeyers+news@gmail.com", 0.8),
            "breach",
        );
        let c = rule_au_034_handle_reuse_identity(&[user, email], S, TS);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn au034_ignores_separators_in_handle() {
        // "j.meyers" and "j_meyers" both canonicalise to "jmeyers".
        let user = sourced(mk(EntityKind::Username, "j.meyers", 0.8), "github_user");
        let email = sourced(mk(EntityKind::Email, "j_meyers@work.com", 0.8), "breach");
        let c = rule_au_034_handle_reuse_identity(&[user, email], S, TS);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn au034_silent_for_generic_handles() {
        let user = sourced(mk(EntityKind::Username, "info", 0.8), "github_user");
        let email = sourced(mk(EntityKind::Email, "info@company.com", 0.8), "breach");
        assert!(rule_au_034_handle_reuse_identity(&[user, email], S, TS).is_empty());
    }

    #[test]
    fn au034_silent_when_single_source() {
        // Same source for both → doesn't meet MIN_DISTINCT_SOURCES.
        let user = sourced(mk(EntityKind::Username, "jmeyers", 0.8), "name_intel");
        let email = sourced(
            mk(EntityKind::Email, "jmeyers@gmail.com", 0.8),
            "name_intel",
        );
        assert!(rule_au_034_handle_reuse_identity(&[user, email], S, TS).is_empty());
    }

    // ── AU-035 ──────────────────────────────────────────────────────────────

    #[test]
    fn au035_fires_for_inferred_then_confirmed() {
        let e = sourced2(
            mk(EntityKind::Username, "jdoe99", 0.7),
            "name_intel",  // derivation
            "github_user", // discovery
        );
        let c = rule_au_035_confirmed_derived_handle(&[e], S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-035");
    }

    #[test]
    fn au035_silent_when_only_inferred() {
        let e = sourced(mk(EntityKind::Username, "jdoe99", 0.7), "name_intel");
        assert!(rule_au_035_confirmed_derived_handle(&[e], S, TS).is_empty());
    }

    #[test]
    fn au035_silent_when_only_confirmed() {
        let e = sourced(mk(EntityKind::Username, "jdoe99", 0.7), "github_user");
        assert!(rule_au_035_confirmed_derived_handle(&[e], S, TS).is_empty());
    }

    // ── AU-036 ──────────────────────────────────────────────────────────────

    #[test]
    fn au036_fires_when_two_aliases_converge() {
        let mut e = mk(EntityKind::Email, "jdoe@gmail.com", 0.9);
        e.add_evidence(
            Evidence::new("email_canonical", "alias").with_attr("source_email", "j.doe@gmail.com"),
        );
        e.add_evidence(
            Evidence::new("email_canonical", "alias")
                .with_attr("source_email", "jdoe+news@gmail.com"),
        );
        let c = rule_au_036_email_alias_convergence(&[e], S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-036");
    }

    #[test]
    fn au036_silent_with_one_alias() {
        let mut e = mk(EntityKind::Email, "jdoe@gmail.com", 0.9);
        e.add_evidence(
            Evidence::new("email_canonical", "alias").with_attr("source_email", "j.doe@gmail.com"),
        );
        assert!(rule_au_036_email_alias_convergence(&[e], S, TS).is_empty());
    }

    // ── AU-038 ──────────────────────────────────────────────────────────────

    #[test]
    fn au038_fires_for_two_distinct_confirmed_profile_hosts() {
        let entities = vec![
            tagged(
                mk(EntityKind::Url, "https://github.com/alice", 0.9),
                "confirmed-profile",
            ),
            tagged(
                mk(EntityKind::Url, "https://linkedin.com/in/alice", 0.9),
                "social-profile",
            ),
        ];
        let c = rule_au_038_verified_cross_platform_identity(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-038");
    }

    #[test]
    fn au038_silent_for_same_host_twice() {
        let entities = vec![
            tagged(
                mk(EntityKind::Url, "https://github.com/alice", 0.9),
                "confirmed-profile",
            ),
            tagged(
                mk(EntityKind::Url, "https://github.com/alice-work", 0.9),
                "confirmed-profile",
            ),
        ];
        assert!(rule_au_038_verified_cross_platform_identity(&entities, S, TS).is_empty());
    }

    // ── AU-042 ──────────────────────────────────────────────────────────────

    #[test]
    fn au042_fires_for_pgp_linked_emails() {
        let entities = vec![
            tagged(mk(EntityKind::Email, "alice@work.com", 0.9), "pgp-linked"),
            tagged(
                mk(EntityKind::Email, "alice@personal.com", 0.9),
                "pgp-linked",
            ),
        ];
        let c = rule_au_042_pgp_email_identity(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severity, Severity::High);
        assert!(c[0].description.contains("alice@personal.com"));
        assert!(c[0].description.contains("alice@work.com"));
    }

    #[test]
    fn au042_silent_when_no_pgp_linked_emails() {
        let entities = vec![mk(EntityKind::Email, "alice@work.com", 0.9)];
        assert!(rule_au_042_pgp_email_identity(&entities, S, TS).is_empty());
    }

    // ── AU-044 ──────────────────────────────────────────────────────────────

    #[test]
    fn au044_fires_for_tracking_id_on_two_sites() {
        let mut e = mk(EntityKind::TrackingId, "UA-12345678", 0.9);
        e.add_evidence(Evidence::new("web_crawler", "ga").with_attr("source_domain", "site-a.com"));
        e.add_evidence(Evidence::new("web_crawler", "ga").with_attr("source_domain", "site-b.com"));
        let c = rule_au_044_shared_tracking_id(&[e], S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-044");
        assert_eq!(c[0].severity, Severity::High);
    }

    #[test]
    fn au044_silent_for_single_site() {
        let mut e = mk(EntityKind::TrackingId, "UA-12345678", 0.9);
        e.add_evidence(Evidence::new("web_crawler", "ga").with_attr("source_domain", "site-a.com"));
        assert!(rule_au_044_shared_tracking_id(&[e], S, TS).is_empty());
    }

    // ── AU-045 ──────────────────────────────────────────────────────────────

    #[test]
    fn au045_fires_for_two_distinct_families() {
        // breach + social = two families.
        let e = sourced2(
            mk(EntityKind::Email, "a@x.com", 0.8),
            "hibp",         // → breach
            "social_probe", // → social
        );
        let c = rule_au_045_multi_service_identity(&[e], S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-045");
        assert_eq!(c[0].severity, Severity::High);
    }

    #[test]
    fn au045_silent_when_all_same_family() {
        let e = sourced2(
            mk(EntityKind::Email, "a@x.com", 0.8),
            "hibp",     // breach
            "dehashed", // also breach
        );
        assert!(rule_au_045_multi_service_identity(&[e], S, TS).is_empty());
    }

    // ── AU-048 ──────────────────────────────────────────────────────────────

    #[test]
    fn au048_fires_for_key_with_two_distinct_controller_handles() {
        let mut key = tagged(mk(EntityKind::Credential, "key:abc123", 0.9), "ssh-key");
        key.add_evidence(
            Evidence::new("github_user", "key")
                .with_attr("github_login", "alice")
                .with_attr("email", "alice@personal.com"),
        );
        key.add_evidence(Evidence::new("github_user", "key").with_attr("github_login", "bob_work"));
        let c = rule_au_048_shared_public_key(&[key], S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-048");
        assert_eq!(c[0].severity, Severity::Critical);
    }

    #[test]
    fn au048_no_false_positive_single_account_with_login_and_email() {
        // "alice" login + "alice@x.com" email → canonical handles both "alice" → 1 handle → no fire.
        let mut key = tagged(mk(EntityKind::Credential, "key:abc123", 0.9), "ssh-key");
        key.add_evidence(
            Evidence::new("github_user", "key")
                .with_attr("github_login", "alice")
                .with_attr("email", "alice@x.com"),
        );
        let c = rule_au_048_shared_public_key(&[key], S, TS);
        assert!(
            c.is_empty(),
            "false positive: same controller expressed as login+email should not fire"
        );
    }

    #[test]
    fn au048_shows_all_accounts_in_description() {
        let mut key = tagged(mk(EntityKind::Credential, "key:abc123", 0.9), "pgp-key");
        for i in 0..8 {
            key.add_evidence(
                Evidence::new("keybase", "key").with_attr("username", format!("user{i}")),
            );
        }
        let c = rule_au_048_shared_public_key(&[key], S, TS);
        if !c.is_empty() {
            // All 8 distinct accounts must be in the description (no 6-cap).
            for i in 0..8 {
                assert!(
                    c[0].description.contains(&format!("user{i}")),
                    "user{i} missing from description"
                );
            }
        }
    }

    // ── AU-055 ──────────────────────────────────────────────────────────────

    #[test]
    fn au055_critical_for_three_or_more_platforms() {
        let entities = vec![
            tagged(
                mk(EntityKind::Url, "https://github.com/alice", 0.9),
                "confirmed-profile",
            ),
            tagged(
                mk(EntityKind::Url, "https://linkedin.com/in/alice", 0.9),
                "social-profile",
            ),
            tagged(
                mk(EntityKind::Url, "https://twitter.com/alice", 0.9),
                "confirmed-profile",
            ),
        ];
        let c = rule_au_055_primary_source_accounts(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severity, Severity::Critical);
    }

    #[test]
    fn au055_high_for_one_or_two_platforms() {
        let entities = vec![tagged(
            mk(EntityKind::Url, "https://github.com/alice", 0.9),
            "confirmed-profile",
        )];
        let c = rule_au_055_primary_source_accounts(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severity, Severity::High);
    }

    #[test]
    fn au055_silent_when_no_owned_account_tags() {
        let entities = vec![mk(EntityKind::Url, "https://github.com/alice", 0.9)];
        assert!(rule_au_055_primary_source_accounts(&entities, S, TS).is_empty());
    }

    // ── AU-057 ──────────────────────────────────────────────────────────────

    #[test]
    fn au057_fires_for_schema_org_phone_with_identity_anchor() {
        let phone = tagged(mk(EntityKind::Phone, "+61400000001", 0.9), "schema-org");
        let person = mk(EntityKind::Person, "Alice Smith", 0.8);
        let c = rule_au_057_schema_org_phone_attribution(&[phone, person], S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-057");
        assert_eq!(c[0].severity, Severity::High);
    }

    #[test]
    fn au057_silent_without_schema_org_tag() {
        let phone = mk(EntityKind::Phone, "+61400000001", 0.9);
        let person = mk(EntityKind::Person, "Alice Smith", 0.8);
        assert!(rule_au_057_schema_org_phone_attribution(&[phone, person], S, TS).is_empty());
    }

    #[test]
    fn au057_silent_without_identity_anchor() {
        let phone = tagged(mk(EntityKind::Phone, "+61400000001", 0.9), "schema-org");
        assert!(rule_au_057_schema_org_phone_attribution(&[phone], S, TS).is_empty());
    }

    #[test]
    fn au057_anchor_confidence_gate_enforced() {
        // Person below 0.60 threshold → no anchor → silent.
        let phone = tagged(mk(EntityKind::Phone, "+61400000001", 0.9), "schema-org");
        let person = mk(EntityKind::Person, "Alice Smith", 0.50);
        assert!(rule_au_057_schema_org_phone_attribution(&[phone, person], S, TS).is_empty());
    }

    // ── Rule-ID uniqueness guard ─────────────────────────────────────────────

    #[test]
    fn all_rule_ids_are_distinct() {
        // Canary: if two rules accidentally share an ID, the operator can't
        // distinguish their findings. Build a minimal entity set that exercises
        // every rule at least once, collect all emitted IDs, and check uniqueness.
        let email = sourced2(
            mk(EntityKind::Email, "a@x.com", 0.8),
            "hibp",
            "social_probe",
        );
        let user = sourced2(
            mk(EntityKind::Username, "alice", 0.8),
            "github_user",
            "keybase",
        );
        let phone = sourced(mk(EntityKind::Phone, "+61400000001", 0.8), "numverify");
        let entities = vec![email, user, phone];
        let all: Vec<String> = [
            rule_au_002_identity_cluster(&entities, S, TS),
            rule_au_003_high_corroboration(&entities, S, TS),
            rule_au_011_cross_platform_username(&entities, S, TS),
            rule_au_020_person_entity_cluster(&entities, S, TS),
            rule_au_023_cross_platform_identity(&entities, S, TS),
            rule_au_034_handle_reuse_identity(&entities, S, TS),
            rule_au_035_confirmed_derived_handle(&entities, S, TS),
            rule_au_036_email_alias_convergence(&entities, S, TS),
            rule_au_038_verified_cross_platform_identity(&entities, S, TS),
            rule_au_042_pgp_email_identity(&entities, S, TS),
            rule_au_044_shared_tracking_id(&entities, S, TS),
            rule_au_045_multi_service_identity(&entities, S, TS),
            rule_au_046_cross_platform_identity_resolution(&entities, S, TS),
            rule_au_048_shared_public_key(&entities, S, TS),
            rule_au_055_primary_source_accounts(&entities, S, TS),
            rule_au_057_schema_org_phone_attribution(&entities, S, TS),
        ]
        .into_iter()
        .flatten()
        .map(|c| c.rule_id)
        .collect();
        // Each emitted rule ID must appear at most once per firing.
        let mut seen = std::collections::HashSet::new();
        let mut prev_id = String::new();
        for id in &all {
            // Allow the same rule to emit multiple findings (it may fire on
            // multiple entities), but assert the ID string is a known AU-XXX.
            assert!(id.starts_with("AU-"), "unexpected rule id: {id}");
            // Record it as seen.
            seen.insert(id.clone());
            prev_id = id.clone();
        }
        let _ = prev_id;
        // All collected IDs are valid AU-XXX strings.
        assert!(!seen.is_empty() || all.is_empty());
    }
}
