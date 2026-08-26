//! Handle / username correlation rules — handle reuse and name-derivation.
//!
//! Split from the former ~1.9k-line `account.rs`; each rule stays
//! `pub(in crate::core::correlator)` and is re-exported by `super` (`account/mod.rs`),
//! so every existing call path is unchanged.

use super::super::super::{USERNAME_DERIVATION_SOURCES, USERNAME_DISCOVERY_SOURCES};
use super::super::*;
use super::*;

pub(in crate::core::correlator) fn rule_au_011_cross_platform_username(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
                let raw_count = ev
                    .attributes
                    .get("platforms_count")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                // `platforms_count`/`platforms` count EVERY hit a sweep module
                // found, including status-only HTTP-code guesses with no body
                // verification (see AU-055's doc comment below for a real scan
                // where nearly every "hit" was exactly this). When the same
                // evidence record also carries `hits_verified` (username_search's
                // aggregate summary does), trust that count instead — it excludes
                // the unverified guesses that would otherwise fabricate a false
                // "confirmed on N platforms" claim. The specific platform NAMES
                // can't be split by verification status from `platforms` (one
                // joined string), so a verified-count record contributes no name
                // list: a smaller, honest claim beats a detailed, fabricated one.
                let verified = ev
                    .attributes
                    .get("hits_verified")
                    .and_then(|s| s.parse::<u64>().ok());
                let (count, list) = match verified {
                    Some(v) => (v, None),
                    None => (
                        raw_count,
                        ev.attributes.get("platforms").map(String::as_str),
                    ),
                };
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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

/// A discovery source CONFIRMS a handle only when it actually DETECTED it, not
/// when it merely guessed from a bare HTTP status. `social_probe`/`username_search`
/// tag a status guess `detection: status-only`; `username_search`'s aggregate
/// summary entity instead carries `hits_verified`/`hits_status_only`, so an
/// all-guess summary (`hits_verified == 0`) is NOT a confirmation. Shared by
/// AU-035 and AU-077 — both merge a derivation source with a discovery source
/// on the same entity, so both need the identical status-only discount (mirrors
/// AU-045/AU-003/AU-055).
fn is_verified_discovery(ev: &crate::core::entity::Evidence) -> bool {
    USERNAME_DISCOVERY_SOURCES.contains(&ev.source.as_str())
        && ev.attributes.get("detection").map(String::as_str) != Some("status-only")
        && ev
            .attributes
            .get("hits_verified")
            .and_then(|v| v.parse::<u32>().ok())
            .is_none_or(|n| n > 0)
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Username) {
        let sources = e.evidence_sources();
        let mut inferred_by: Vec<&str> = sources
            .iter()
            .copied()
            .filter(|s| USERNAME_DERIVATION_SOURCES.contains(s))
            .collect();
        // Membership in USERNAME_DISCOVERY_SOURCES alone isn't confirmation — a
        // status-only guess (no body verification) is not independent proof the
        // handle is real. Filter to evidence records that pass the same
        // verified-discovery discount AU-077 applies for the identical
        // derived+discovered merge on this same entity kind. Collected via
        // BTreeSet (not Vec+sort) so a source with multiple qualifying evidence
        // records lists once, not once per record.
        let confirmed_by: Vec<&str> = sorted_evidence_sources(&e.evidence, is_verified_discovery);
        if inferred_by.is_empty() || confirmed_by.is_empty() {
            continue;
        }
        inferred_by.sort_unstable();
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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

        // Source-independence gate (mirrors sibling AU-034). The High "same
        // identity" claim requires the bridged email and username to be attested
        // by >= 2 DISTINCT corroborating sources. `corroborating_sources()`
        // excludes the self-enrichment / replay passes (name_intel, geo_normalize,
        // recall, cross_scan …), so an email + username both MINTED from one seed
        // — a single name_intel derivation shares `canonical_handle` by
        // construction — cannot manufacture two "distinct sources" and
        // self-correlate into a phantom High identity bridge on a single-source
        // scan. A genuine cross-source match (a breach email + a platform-confirmed
        // username) still clears the gate.
        const MIN_DISTINCT_SOURCES: usize = 2;
        let sources: HashSet<&str> = emails
            .iter()
            .chain(usernames.iter())
            .flat_map(|e| e.corroborating_sources())
            .collect();
        if sources.len() < MIN_DISTINCT_SOURCES {
            continue;
        }

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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    // Uses the shared `is_verified_discovery` (above AU-035) — because it merges
    // by value with a `name_intel`-derived handle, an unguarded discovery-source
    // membership check fired a false High "prediction confirmed" on two stacked
    // guesses with zero verified hits.
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .filter(|e| {
            // Must carry a derivation AND at least one VERIFIED discovery (a genuine
            // detection, not a status-only guess).
            let has_derived = e
                .evidence
                .iter()
                .any(|ev| USERNAME_DERIVATION_SOURCES.contains(&ev.source.as_str()));
            let has_confirmed = e.evidence.iter().any(is_verified_discovery);
            has_derived && has_confirmed
        })
        .map(|e| {
            let confirmed_by: Vec<&str> =
                sorted_evidence_sources(&e.evidence, is_verified_discovery);
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
