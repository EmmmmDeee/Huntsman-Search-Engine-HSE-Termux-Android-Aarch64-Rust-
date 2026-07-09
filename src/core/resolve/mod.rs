//! `core::resolve` — near-duplicate / canonical-form entity resolution.
//!
//! HSE derives each entity's UID from its *normalised* value
//! ([`crate::core::entity::normalise`] + [`crate::core::entity::derive_uid`]),
//! so two spellings that normalise identically already collapse to ONE entity —
//! that is the job of the exact-UID correlator, and this module deliberately
//! does NOT duplicate it. What the exact matcher cannot see are values that are
//! the *same real-world identifier* yet survive normalisation as DISTINCT UIDs
//! because they differ only in a **provider-specific canonical form** the
//! normaliser intentionally leaves intact:
//!
//! * Gmail dot-blindness and `+tag` subaddressing — `jo.hn@gmail.com`,
//!   `john+news@googlemail.com` and `john@gmail.com` are one mailbox but three
//!   UIDs (the entity normaliser only lowercases/trims an `Email`).
//! * Phone notation — the `+` sigil survives the entity normaliser (which keeps
//!   a leading `+`), so `+61400111222` and a scraped `61400111222` are the same
//!   dialled digits but two UIDs.
//! * Case / whitespace / punctuation and token order in names and handles —
//!   `"Jane Citizen"` and `"Citizen, Jane"` are one person, two UIDs.
//!
//! Left unresolved, each such pair FRAGMENTS the graph: corroboration that
//! should accumulate on one identity is split across two weak singletons, and
//! the analyst sees duplicates. This module surfaces those probable duplicates
//! as **merge suggestions** so the operator (or a later pass) can fuse them —
//! it complements, and never replaces, the exact-match correlator.
//!
//! # Read-only — mutates nothing
//! [`suggest_merges`] is a pure function of the entity slice. It allocates its
//! own working state, borrows the input immutably, and returns a fresh
//! `Vec<`[`ResolutionGroup`]`>`. It changes no entity, performs no I/O, and the
//! caller is free to ignore every suggestion — nothing here is forced on the
//! graph.
//!
//! # Determinism
//! Output is a pure function of the input multiset, independent of input
//! ORDER: members within a group are sorted by UID, and groups are sorted by
//! `(kind, canonical)`. Shuffling the input yields byte-identical output (see
//! the tests), as HSE's reproducibility requirement demands.
//!
//! # Conservative by design — the false-merge caution
//! Fusing two *distinct* people, or two *different* phone numbers, is a far
//! worse failure than missing a duplicate: it corrupts the truth the graph
//! asserts. Every rule here is therefore restricted to **high-confidence
//! canonical collisions** — equivalences a provider documents
//! (Gmail/`+tag` routing) or that are mechanically exact (identical dialled
//! digits, an identical name-token multiset). In particular this module does
//! **not** group on a mere shared surname, a partial name overlap, a phone
//! substring, or an inferred country code — those are weaker signals handled
//! elsewhere (e.g. [`crate::core::geo_family`] for the shared-surname family
//! angle). When in doubt it suggests nothing.
//!
//! Self-contained canonical helpers
//! The module layer has a `modules::email_canonical` that does the *enrichment*
//! side of this (emitting a canonical `Email` entity for one seed). `core` must
//! not depend on `modules`, so the small canonical-form helpers below
//! ([`canonical_email`], [`canonical_phone`], [`canonical_name`],
//! [`canonical_handle`]) are reimplemented here, self-contained and minimal.
//! Their behaviour is documented per function so the provider-specific stance
//! (which forms collapse, which are deliberately kept) is auditable in one
//! place.

use std::collections::BTreeMap;

use crate::core::entity::{Entity, EntityKind};

/// The two Gmail-family domains that share one mailbox namespace and treat dots
/// in the local-part as insignificant. `googlemail.com` is a legacy alias of
/// `gmail.com`, so both canonicalise to `gmail.com` (see [`canonical_email`]).
const GMAIL_DOMAINS: [&str; 2] = ["gmail.com", "googlemail.com"];

/// A suggested SAME-ENTITY group: a set of existing entities that are probably
/// the one real-world identifier, surfaced because their provider-specific
/// canonical forms collide even though their stored values differ.
///
/// Purely advisory — produced by [`suggest_merges`] and acted on (or ignored)
/// entirely at the caller's discretion. `Serialize` (no `Deserialize`: this is
/// an output report, never parsed back) so it can be emitted in a dossier /
/// API response alongside the other analysis surfaces.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ResolutionGroup {
    /// The shared entity kind, as [`crate::core::entity::EntityKind`]'s
    /// `Display` string (`"email"`, `"phone"`, `"username"`, `"person"`, …).
    /// Only same-kind entities are ever grouped.
    pub kind: String,
    /// The canonical form all members share — the collision key (e.g. the
    /// dot-stripped Gmail mailbox, the digits-only phone, the order-normalised
    /// name). Shown so the operator can see *why* the members were grouped.
    pub canonical: String,
    /// The grouped entities' UIDs, de-duplicated and **sorted ascending** for
    /// deterministic output. Always ≥ 2 distinct UIDs.
    pub members: Vec<String>,
    /// Short, human-readable explanation of the canonical equivalence that
    /// triggered the suggestion (e.g. "Gmail dot/＋tag-insensitive mailbox").
    pub reason: String,
}

/// Suggest probable SAME-ENTITY merges the exact-UID correlator misses.
///
/// Groups same-[`kind`](crate::core::entity::EntityKind) entities whose
/// provider-specific **canonical form** collides while their stored
/// [`value`](crate::core::entity::Entity::value)s differ — i.e. genuine
/// duplicates that survived normalisation as separate UIDs. A group is emitted
/// only when it contains **≥ 2 distinct members** (distinct UIDs spanning ≥ 2
/// distinct stored values); a value that is already its own canonical form with
/// no differing sibling yields nothing (the exact matcher already covers true
/// UID collisions, so there is nothing to suggest).
///
/// # What is grouped
/// Per kind, via a private canonical function (all documented on the helpers):
/// * [`EntityKind::Email`] → [`canonical_email`] (Gmail dots/`+tag`; `+tag`
///   only for other domains, dots kept);
/// * [`EntityKind::Phone`] → [`canonical_phone`] (digits only, optional
///   leading `+`; equality only — never country-code inference);
/// * [`EntityKind::Username`] → [`canonical_handle`] (case/space/punctuation);
/// * [`EntityKind::Person`] → [`canonical_name`] (the above **plus** an
///   order-insensitive token multiset, so `"Jane Citizen" == "Citizen, Jane"`
///   but never a mere shared surname).
///
/// Any other kind is left untouched — their normalised value is already the
/// only sensible identity key, so a canonical collision there is exactly a UID
/// collision the exact matcher owns.
///
/// # Determinism & cost
/// Output is independent of input order: members are sorted by UID and groups
/// by `(kind, canonical)`. The pass is a single linear scan that buckets into a
/// [`BTreeMap`] keyed by `(kind, canonical)` — `O(n log n)` in the entity count
/// `n`, allocating one small bucket per distinct canonical form (bounded by
/// `n`), which keeps it modest enough for Termux.
///
/// # Read-only & advisory
/// Pure: borrows `entities` immutably, mutates nothing, does no I/O, and the
/// returned suggestions oblige the caller to nothing.
///
/// # False-merge caution
/// Conservative by design — see the [module docs](crate::core::resolve). Only
/// high-confidence canonical collisions are grouped, to avoid fragmenting truth
/// or fusing distinct people/numbers.
///
/// ```
/// use huntsman_search_engine::core::entity::{Entity, EntityKind};
/// use huntsman_search_engine::core::resolve::suggest_merges;
///
/// let entities = [
///     Entity::new(EntityKind::Email, "jo.hn@gmail.com", 0.6, "s"),
///     Entity::new(EntityKind::Email, "john+x@googlemail.com", 0.6, "s"),
/// ];
/// let groups = suggest_merges(&entities);
/// assert_eq!(groups.len(), 1);
/// assert_eq!(groups[0].canonical, "john@gmail.com");
/// assert_eq!(groups[0].members.len(), 2);
/// ```
#[must_use]
pub fn suggest_merges(entities: &[Entity]) -> Vec<ResolutionGroup> {
    /// One accumulating bucket of entities sharing a `(kind, canonical)` key.
    struct Bucket<'a> {
        /// Display string of the shared kind (for the emitted `kind` field).
        kind: String,
        /// Why these collide (for the emitted `reason` field).
        reason: &'static str,
        /// Distinct stored `value`s seen — the "are they genuinely different
        /// spellings?" test (a group needs ≥ 2 of these).
        values: Vec<&'a str>,
        /// Distinct member UIDs, kept sorted for deterministic output.
        members: Vec<&'a str>,
    }

    // Key on (kind discriminant, canonical) so different kinds with the same
    // canonical string never collide, and so groups come out sorted by
    // (kind, canonical) for free — BTreeMap iterates in key order. The kind
    // string is captured inside the bucket for the output; the key's first
    // element is the stable Display string, which orders kinds deterministically.
    let mut buckets: BTreeMap<(String, String), Bucket<'_>> = BTreeMap::new();

    for e in entities {
        let Some((canonical, reason)) = canonicalise(e) else {
            continue;
        };
        let kind = e.kind.to_string();
        let bucket = buckets
            .entry((kind.clone(), canonical))
            .or_insert_with(|| Bucket {
                kind,
                reason,
                values: Vec::new(),
                members: Vec::new(),
            });

        // Track distinct stored values: two entities differing only in a
        // canonical form have different `value`s, which is what makes this a
        // duplicate the exact matcher missed (rather than a re-observation that
        // already shares a UID).
        if !bucket.values.contains(&e.value.as_str()) {
            bucket.values.push(e.value.as_str());
        }
        // Distinct UIDs, inserted in sorted position so the final list is
        // ordered without a second sort. Two entities with the SAME UID (an
        // already-merged true duplicate) are counted once.
        if let Err(pos) = bucket.members.binary_search(&e.uid.as_str()) {
            bucket.members.insert(pos, e.uid.as_str());
        }
    }

    // Emit only genuine duplicate groups: ≥ 2 distinct members spanning ≥ 2
    // distinct stored values. BTreeMap iteration is already (kind, canonical)
    // order, so no final sort is needed.
    let mut out = Vec::new();
    for ((_, canonical), bucket) in buckets {
        if bucket.members.len() >= 2 && bucket.values.len() >= 2 {
            out.push(ResolutionGroup {
                kind: bucket.kind,
                canonical,
                members: bucket.members.into_iter().map(String::from).collect(),
                reason: bucket.reason.to_string(),
            });
        }
    }
    out
}

/// The canonical form + the reason string for `e`, or `None` when `e`'s kind is
/// not one this module resolves (or its value has no usable canonical form).
///
/// The single dispatch point [`suggest_merges`] uses, so the kind→helper map
/// and the per-kind `reason` strings live in one place.
fn canonicalise(e: &Entity) -> Option<(String, &'static str)> {
    match e.kind {
        EntityKind::Email => canonical_email(&e.value).map(|c| {
            (
                c,
                "Email canonical mailbox (Gmail dot/+tag-insensitive; +tag stripped)",
            )
        }),
        EntityKind::Phone => canonical_phone(&e.value)
            .map(|c| (c, "Phone reduced to canonical digits (exact-equality only)")),
        EntityKind::Username => canonical_handle(&e.value)
            .map(|c| (c, "Username canonicalised (case/whitespace/punctuation)")),
        EntityKind::Person => canonical_name(&e.value).map(|c| {
            (
                c,
                "Person name canonicalised (case/space/punctuation, token-order-insensitive)",
            )
        }),
        _ => None,
    }
}

/// Canonical mailbox form of an email address, or `None` when it has no `@`, an
/// empty local-part or domain, or no canonical local-part survives.
///
/// Rules (the equivalences are documented routing behaviour, not guesses):
/// * lowercase the whole address (the entity normaliser already does this, but
///   this helper stays correct for any caller / unnormalised input);
/// * strip a `+tag` suffix from the local-part — plus-addressing routes to the
///   base mailbox on every major provider (Gmail, Outlook/Microsoft, Fastmail,
///   Proton, iCloud, …), so it never distinguishes identity;
/// * for **Gmail only** (`gmail.com` and its legacy alias `googlemail.com`)
///   additionally drop **all dots** in the local-part and fold the domain to
///   `gmail.com` — Gmail treats `j.o.h.n` and `john` as one mailbox.
///
/// Provider-specific stance: dots are **kept** for every non-Gmail domain.
/// Most providers treat `a.b@corp.com` and `ab@corp.com` as *different*
/// mailboxes, so stripping dots universally would be a false merge. This is
/// deliberately the conservative choice — only the documented Gmail rule drops
/// dots.
pub(crate) fn canonical_email(value: &str) -> Option<String> {
    let lower = value.trim().to_lowercase();
    let (local, domain) = lower.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }

    // `+tag` subaddressing: the base mailbox before the first '+' is the
    // identity. Universally safe — every major provider routes the base.
    let base = local.split('+').next().unwrap_or(local);

    let (local_canon, domain_canon) = if GMAIL_DOMAINS.contains(&domain) {
        // Gmail dot-blindness, and googlemail.com == gmail.com.
        (base.replace('.', ""), "gmail.com")
    } else {
        // Non-Gmail: keep dots (significant on most providers), keep the domain.
        (base.to_string(), domain)
    };

    if local_canon.is_empty() {
        return None;
    }
    Some(format!("{local_canon}@{domain_canon}"))
}

/// Canonical digit form of a phone number, or `None` when it contains no
/// digits.
///
/// Reduces the value to its **digits only** — every separator AND the leading
/// `+` sigil are dropped — so spellings that differ purely in presentation
/// collapse: `0400 111 222`, `(0400)111-222` and the entity-normalised
/// `0400111222` all yield `0400111222`, and `+61 400 111 222` yields
/// `61400111222`.
///
/// Why drop the `+` (when [`crate::core::entity::normalise`] keeps it): the
/// entity UID normaliser already strips a phone to digits-plus-a-leading-`+`,
/// so two formattings of the same digits ALREADY share a UID and the exact
/// matcher owns them — there is nothing for this module to add there. The one
/// presentation difference that survives normalisation as a *distinct* UID is
/// the `+` sigil itself (`+61400111222` vs a scraped `61400111222`). The `+` is
/// pure notation for the identical dialled digits, so folding it here is what
/// lets [`suggest_merges`] reunite those two fragments — the resolver's actual
/// job — without it being redundant with the UID normaliser.
///
/// Conservative — equality only: this is purely a *formatting* normalisation.
/// It does **not** infer or add a country code, strip a national trunk `0`, or
/// otherwise reconcile a local number against its international form. Such
/// inference can merge genuinely distinct numbers (a national number in one
/// country can collide with a different country's local number), so
/// [`suggest_merges`] groups two phones only when these digit-canonical forms
/// are **exactly equal**. The trunk-`0`/country-code pair `0400111222` and
/// `61400111222` therefore have different digits and are left as separate
/// identities by design, avoiding false merges at the cost of missing a
/// country-code-only difference.
fn canonical_phone(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let mut out = String::with_capacity(trimmed.len());
    out.extend(trimmed.chars().filter(char::is_ascii_digit));
    // Reject a value with no digits (e.g. "+" alone, or stray punctuation):
    // an all-symbol "number" is not a usable identity key.
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// Canonical form of a free-text token string — lowercase, trimmed, with
/// internal whitespace collapsed to single spaces and surrounding punctuation
/// stripped. The shared core of [`canonical_handle`] and [`canonical_name`].
///
/// Returns `None` when nothing remains after stripping (an empty or
/// punctuation-only value), since an empty key cannot identify anything.
fn canonical_tokens(value: &str) -> Option<String> {
    // Lowercase, then split on any non-alphanumeric boundary so punctuation and
    // runs of whitespace both act as separators; rejoin tokens with single
    // spaces. This collapses "  Jane   Citizen  ", "Jane Citizen" and
    // "Jane.Citizen" to the same "jane citizen", and strips surrounding
    // punctuation as a side effect of dropping empty split fragments.
    let lower = value.to_lowercase();
    let mut canon = String::with_capacity(lower.len());
    for tok in lower.split(|c: char| !c.is_alphanumeric()) {
        if tok.is_empty() {
            continue;
        }
        if !canon.is_empty() {
            canon.push(' ');
        }
        canon.push_str(tok);
    }
    (!canon.is_empty()).then_some(canon)
}

/// Canonical form of a username / handle: [`canonical_tokens`] applied to the
/// value (lowercase, trim, collapse whitespace, strip surrounding punctuation).
///
/// Order is preserved for handles (unlike [`canonical_name`]): a handle is an
/// opaque token, so its internal order is significant — only formatting noise is
/// normalised away.
fn canonical_handle(value: &str) -> Option<String> {
    canonical_tokens(value)
}

/// Canonical form of a person's name: [`canonical_tokens`] **plus** an
/// order-insensitive sort of the resulting tokens, so the FULL name-token
/// multiset — not its order — is the identity key.
///
/// This makes `"Jane Citizen"` and `"Citizen, Jane"` (both → `"citizen jane"`)
/// one identity, while keeping the rule strict: it groups only when the *entire*
/// token multiset matches. A merely shared surname (`"Jane Citizen"` vs
/// `"John Citizen"` → `"citizen jane"` vs `"citizen john"`) does **not** match,
/// so this never fuses two different people on a partial-name overlap — that
/// weaker shared-surname signal is handled elsewhere (e.g.
/// [`crate::core::geo_family`]).
fn canonical_name(value: &str) -> Option<String> {
    let canon = canonical_tokens(value)?;
    let mut tokens: Vec<&str> = canon.split(' ').collect();
    tokens.sort_unstable();
    Some(tokens.join(" "))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
