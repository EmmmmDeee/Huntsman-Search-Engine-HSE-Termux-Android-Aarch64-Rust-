//! Cross-platform identity rules — email/name convergence, verified cross-platform
//! identity, hub and bio-mention graph links, and canonical person-name matching.
//! Split from `account.rs`; rules re-exported by `super`.

use super::super::super::EMAIL_CONFIRMATION_SOURCES;
use super::super::*;

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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
                            // A structured platform field (twitter/instagram/…) is the
                            // subject's own declared link → High above. A free-text bio
                            // @-mention is NOT self-attribution: the subject may simply be
                            // naming a third party ("follow @someone"). It is a lead to
                            // VERIFY, not a confirmed identity bridge, so it fires Medium.
                            severity: Severity::Medium,
                            description: format!(
                                "Username '{}' profile bio names '{}' via an @-mention in their \
                                 '{attr}' field — a possible cross-platform reference (the subject \
                                 themselves OR a third party they mention); verify before treating \
                                 as the same identity (free, offline lead)",
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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

    // The name's tokens in ORIGINAL order (unsorted). Two records that group on the
    // same sorted canonical but differ here matched only by REORDERING.
    fn ordered_tokens(s: &str) -> Vec<String> {
        s.split(|c: char| c.is_whitespace() || c == ',' || c == '-' || c == '.')
            .filter(|t| !t.is_empty())
            .map(str::to_lowercase)
            .filter(|t| t.len() >= 2)
            .collect()
    }
    // A "bare transposition": the two names share a token multiset (they already
    // grouped on the sorted canonical) but differ in order, and NEITHER declared
    // surname-first with a comma. "Cameron Tyler" and "Tyler Cameron" are then two
    // plausibly-DIFFERENT people, so the match is a Medium lead, not a High merge —
    // whereas "Bamford, Haigen" (comma) vs "Haigen Bamford" is a confident match.
    fn is_bare_transposition(a: &str, b: &str) -> bool {
        ordered_tokens(a) != ordered_tokens(b) && !a.contains(',') && !b.contains(',')
    }

    let persons: Vec<(String, &Entity)> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .filter_map(|e| normalise_name(&e.value).map(|n| (n, e)))
        .collect();

    if persons.len() < 2 {
        return Vec::new();
    }

    // Group person indices by canonical name in one O(P) pass. Only a same-name
    // group of size >= 2 can produce a pair, so pairing WITHIN groups replaces
    // the former O(P^2) all-pairs name comparison. This is never worse than the
    // old scan — when every name is distinct each group is a singleton and the
    // body below does no work — and strictly better in the multi-namesake
    // clusters this rule exists to resolve (where a recall/breach sweep can push
    // the same-name group into the dozens or hundreds).
    let mut groups: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, (name, _)) in persons.iter().enumerate() {
        groups.entry(name.as_str()).or_default().push(idx);
    }

    // Precompute each duplicated person's corroborating-source set and its
    // source-FAMILY set exactly once. The old code rebuilt BOTH (a fresh HashSet
    // allocation each) for every pair a person took part in — O(g^2) set
    // allocations for a same-name group of size g; this is O(g). Persons in a
    // singleton group never pair, so their sets are never built (`None`).
    let mut precomp: Vec<Option<(HashSet<&str>, HashSet<&'static str>)>> =
        std::iter::repeat_with(|| None)
            .take(persons.len())
            .collect();
    for members in groups.values() {
        if members.len() < 2 {
            continue;
        }
        for &idx in members {
            let src = persons[idx].1.corroborating_sources();
            let fam: HashSet<&'static str> = src.iter().map(|s| source_family(s)).collect();
            precomp[idx] = Some((src, fam));
        }
    }

    let mut out: Vec<Correlation> = Vec::new();
    let mut seen: HashSet<[String; 2]> = HashSet::new();

    // Iterate i ascending and pair with same-name members j > i. This reproduces
    // the EXACT (i, j) ordering — hence the exact output order and `seen` dedup
    // behaviour — of the former nested `for i { for j in i+1.. }` scan.
    for i in 0..persons.len() {
        // Independence gate. "Independent" means the two records were collected
        // by genuinely different real-world methods — so every part of the gate
        // runs over CORROBORATING sources only ([`Entity::corroborating_sources`]),
        // NOT the raw `evidence` list. The deterministic self-enrichment passes
        // (`name_intel`'s own firstname/lastname permutation of the seed,
        // `geo_normalize`) and the `recall` / `cross_scan_history` replays attach
        // useful evidence but are NOT independent observations — `name_intel` in
        // particular DERIVES a `Person` from the seed name and maps to the real
        // `identity_registry` family, so hand-rolling the sets from raw `evidence`
        // (as this rule used to) let the tool's OWN name derivation pose as a
        // second, independently-sourced record and manufacture a High "same
        // individual" match. This is the identical honest set `source_families` /
        // `source_count` already build on.
        //
        // (0) A name known ONLY from the tool's own derivation (`name_intel`) or a
        //     prior-scan replay (`recall`) is not an independently collected record
        //     at all — a side with no corroborating source can never be one half of
        //     an "independent match". `precomp[i]` is `None` for singleton-group
        //     persons (which never pair); an empty corroborating set is the
        //     no-independent-source case handled here.
        let Some((src1, fam1)) = precomp[i].as_ref() else {
            continue;
        };
        if src1.is_empty() {
            continue;
        }
        for &j in &groups[persons[i].0.as_str()] {
            if j <= i {
                continue;
            }
            let e1 = persons[i].1;
            let e2 = persons[j].1;
            let (src2, fam2) = precomp[j]
                .as_ref()
                .expect("j is drawn from the same multi-member group as i");
            if src2.is_empty() {
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
            // A bare token transposition ("Cameron Tyler" vs "Tyler Cameron", no
            // comma to declare surname-first) may be two DIFFERENT people, so it is
            // a lead to VERIFY, not a confident merge — even for a distinctive name.
            // An exact-order or comma-confirmed match stays High.
            let (severity, tail) = if common {
                (
                    Severity::Medium,
                    "a COMMON name many unrelated people share — a lead to VERIFY, \
                     not a confirmed merge",
                )
            } else if is_bare_transposition(&e1.value, &e2.value) {
                (
                    Severity::Medium,
                    "matched only by reordering the name tokens, with no 'Last, First' \
                     comma to confirm the order — a possible transposition of two \
                     different people; a lead to VERIFY, not a confirmed merge",
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
