//! AU correlation rules — associates / household family. See `super`
//! (rules/mod.rs) for the shared helpers; every rule reaches them through
//! `use super::*`.
//!
//! This family links a subject to the people connected to them — co-residents,
//! relatives, and associates — through records they have in common, chiefly a
//! shared residential address or phone number. When a subject has little direct
//! footprint of their own, these shared records still surface the relationships
//! that place them in context. It applies to the average subject too, since most
//! people share an address with someone, which is the overlap this rule set
//! looks for.

use super::*;

/// Normalise a free-form postal address for grouping: lowercase, fold commas to
/// spaces, drop the punctuation that varies between records (`#`, `.`, `-`), and
/// collapse runs of whitespace. Two records that name the same residence with
/// inconsistent formatting (`"123 Main St, Apt 4"` vs `"123 main st apt 4"`)
/// must collapse to one key, or the household never forms.
fn normalise_address(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_space = true; // trims leading space
    for c in raw.chars() {
        let c = if c == ',' || c.is_whitespace() {
            ' '
        } else if matches!(c, '#' | '.' | '-' | '/' | '\\') {
            continue;
        } else {
            c.to_ascii_lowercase()
        };
        if c == ' ' {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(c);
            last_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// True when a normalised address is specific enough to identify a *residence*
/// rather than a region — a bare country/state ("USA", "California") names a
/// place thousands of unrelated people share, and clustering on it would fuse
/// strangers into a false household. The definition is single-sourced with the
/// breach importer's Address-promotion gate (see
/// [`crate::core::validation::is_specific_residence`]) so the two never drift.
fn is_residence_address(normalised: &str) -> bool {
    crate::core::validation::is_specific_residence(normalised)
}

/// Pull every specific residence address attached to an entity's evidence
/// (breach/dossier records carry the subject's postal address under an
/// `address` attribute). Returns the *normalised* keys, deduplicated.
fn entity_residences(e: &Entity) -> Vec<String> {
    // Order-preserving dedup via a `BTreeSet` membership side-index, so the
    // dedup check is O(log n) instead of an O(n) linear scan of the growing
    // `out` vec for every evidence record.
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for ev in &e.evidence {
        if let Some(raw) = ev.attributes.get("address") {
            // A value may carry several distinct observations accumulated as
            // "a; b" (the `with_attr` / `merge_evidence_attrs` convention, also
            // split by `breach_pii::scan_evidence`), so judge each candidate
            // residence on its own — a multi-value string normalised whole would
            // garble into one non-matching key.
            for part in raw.split("; ") {
                let key = normalise_address(part.trim());
                if is_residence_address(&key) && seen.insert(key.clone()) {
                    out.push(key);
                }
            }
        }
    }
    out
}

/// Digits-only comparison key for a phone string. A leading `+`, spaces,
/// dashes and parens are dropped so the same line written `+1 (415) 555-0100`
/// and `14155550100` collapses to one key. Returns `None` for a run shorter
/// than 8 digits (short codes / fragments) or an all-same-digit placeholder
/// (`+00000000`), neither of which identifies a real subscriber line.
fn normalise_phone(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
    if digits.len() < 8 {
        return None;
    }
    let first = digits.as_bytes()[0];
    if digits.bytes().all(|b| b == first) {
        return None;
    }
    Some(digits)
}

/// Pull every plausible subscriber phone attached to an entity's evidence
/// (breach/dossier records carry it under a `phone` attribute). Normalised,
/// deduplicated keys.
fn entity_phones(e: &Entity) -> Vec<String> {
    // Order-preserving dedup via a `BTreeSet` membership side-index (O(log n)
    // per record) rather than rescanning the growing `out` vec linearly.
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for ev in &e.evidence {
        let Some(raw) = ev.attributes.get("phone") else {
            continue;
        };
        // Split the multi-value "a; b" accumulation convention so two distinct
        // numbers aren't concatenated into one bogus digit-run key (the same
        // handling `breach_pii::scan_evidence` already applies).
        for part in raw.split("; ") {
            if let Some(key) = normalise_phone(part)
                && seen.insert(key.clone())
            {
                out.push(key);
            }
        }
    }
    out
}

/// The surname (family-name) token of a person value — the last alphabetic
/// whitespace token, lowercased. `None` when the trailing token is too short to
/// be a real family name. Used by the kin rule to tell relatives (shared family
/// name *and* residence) from unrelated co-residents.
fn surname(name_value: &str) -> Option<String> {
    let last = name_value.split_whitespace().last()?;
    let s: String = last
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (s.len() >= 2).then_some(s)
}

/// A cluster of identities sharing one grouping key (a residence or a phone):
/// the distinct named persons (value → uid), any directly-reachable handle uids
/// (emails/phones), and the uid of the first-class anchor node (the Address or
/// Phone entity) for that key, when one is present.
#[derive(Default)]
struct Group {
    persons: std::collections::BTreeMap<String, String>,
    /// Distinct reachable handle uids (emails/phones) for this key, held in a
    /// `BTreeSet` so the dedup check is O(log n) instead of the old O(n) linear
    /// `Vec::contains` scan of a growing vec for every handle added (an O(n²) hot
    /// path when many handles cluster on one key). The set is also already sorted,
    /// which `firing_uids` consumes directly — the firing's bounded, sorted handle
    /// order is identical to the previous clone-and-sort.
    handle_set: std::collections::BTreeSet<String>,
    anchor_uid: Option<String>,
}

impl Group {
    fn add_identity(&mut self, e: &Entity) {
        match e.kind {
            EntityKind::Person => {
                self.persons
                    .entry(e.value.clone())
                    .or_insert_with(|| e.uid.clone());
            }
            EntityKind::Email | EntityKind::Phone => {
                self.handle_set.insert(e.uid.clone());
            }
            _ => {}
        }
    }

    /// Deterministic firing uid list: anchor node, then sorted person uids, then
    /// a bounded, sorted set of reachable handles.
    fn firing_uids(&self) -> Vec<String> {
        let mut uids: Vec<String> = Vec::new();
        if let Some(u) = &self.anchor_uid {
            uids.push(u.clone());
        }
        let mut person_uids: Vec<String> = self.persons.values().cloned().collect();
        person_uids.sort_unstable();
        uids.extend(person_uids);
        // Emit EVERY reachable email/phone handle uid, not a bounded subset: these
        // are the correlation's `entity_uids` (the actual linkage the finding
        // asserts, not a display string), so a silent `.take(8)` dropped handles 9+
        // of a large household / shared-line cluster from the finding with no count
        // surfaced. `handle_set` is a BTreeSet, so the uids are already sorted (the
        // sibling AU-051 applies no handle cap either).
        uids.extend(self.handle_set.iter().cloned());
        uids
    }
}

/// Group every identity entity by the residence(s) recorded in its evidence,
/// pre-seeding anchor nodes from first-class `Address` entities. Shared by the
/// household (AU-049) and kin (AU-051) rules so they cluster identically.
fn residence_groups(entities: &[Entity]) -> std::collections::BTreeMap<String, Group> {
    let mut groups: std::collections::BTreeMap<String, Group> = std::collections::BTreeMap::new();
    for a in entities_of_kind(entities, EntityKind::Address) {
        let key = normalise_address(&a.value);
        if is_residence_address(&key) {
            groups
                .entry(key)
                .or_default()
                .anchor_uid
                // Lazy: only the FIRST entity in each residence group sets the
                // anchor, so clone the uid only when the slot is still empty.
                .get_or_insert_with(|| a.uid.clone());
        }
    }
    for e in entities {
        for key in entity_residences(e) {
            groups.entry(key).or_default().add_identity(e);
        }
    }
    groups
}

/// AU-049 — Shared-address association (household / associate cluster).
///
/// Groups identity-bearing entities by the specific residence address recorded
/// in their evidence and fires when **two or more distinct persons** share one
/// address. That is the associate link: the named co-residents are the
/// connection to a subject who has little direct footprint of their own. Any emails /
/// phones recorded at the same address ride along in the firing as the directly
/// reachable handles for those co-residents.
///
/// Precision discipline (mirrors AU-047): the address must be specific enough to
/// be a residence (see [`is_residence_address`]) and the cluster must contain
/// ≥2 *distinct person names* — two of one person's own emails at one address is
/// not an association, so the anchor is named people, not raw handle count.
pub(in crate::core::correlator) fn rule_au_049_shared_address_association(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    // Cheap precondition: every firing needs ≥2 distinct persons in one group,
    // so fewer than two Person entities anywhere means no household can form —
    // bail before building the residence-group map.
    if entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .count()
        < 2
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (addr, g) in residence_groups(entities) {
        if g.persons.len() < 2 {
            continue;
        }
        let mut names: Vec<&str> = g.persons.keys().map(String::as_str).collect();
        names.sort_unstable();
        out.push(Correlation::new(
            "AU-049",
            "Shared-address association (household)",
            Severity::High,
            format!(
                "{} people recorded at one residence ('{}'): {} — household / associate \
                 cluster; co-residents are the pivot to reach the subject",
                names.len(),
                addr,
                names.join(", ")
            ),
            g.firing_uids(),
            scan_id,
            ts,
        ));
    }
    out
}

/// AU-050 — Shared-phone association (associate cluster).
///
/// The phone-number analogue of AU-049: a number shared by two or more distinct
/// named persons (family plan, shared landline, a relative's contact line) is an
/// associate seam independent of address — it links people who may live in
/// different cities. Keyed purely on the phone, so it reaches associations the
/// residence rule never sees.
///
/// Same precision discipline: the number must be a plausible subscriber line
/// (≥8 digits, not an all-same-digit placeholder — see [`normalise_phone`]) and
/// the cluster must contain ≥2 *distinct person names*, never one person's two
/// addresses on a single line.
pub(in crate::core::correlator) fn rule_au_050_shared_phone_association(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    // Cheap precondition: every firing needs ≥2 distinct persons on one line, so
    // fewer than two Person entities anywhere means no association can form.
    if entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .count()
        < 2
    {
        return Vec::new();
    }
    let mut groups: std::collections::BTreeMap<String, Group> = std::collections::BTreeMap::new();
    // Pre-seed anchor nodes from first-class Phone entities.
    for ph in entities_of_kind(entities, EntityKind::Phone) {
        if let Some(key) = normalise_phone(&ph.value) {
            groups
                .entry(key)
                .or_default()
                .anchor_uid
                // Lazy: clone the uid only for the first phone in each group.
                .get_or_insert_with(|| ph.uid.clone());
        }
    }
    for e in entities {
        for key in entity_phones(e) {
            groups.entry(key).or_default().add_identity(e);
        }
    }

    let mut out = Vec::new();
    for (phone, g) in groups {
        if g.persons.len() < 2 {
            continue;
        }
        // A shared business/service line — freephone (`1800`), local-rate
        // (`13`/`1300`) or premium (`190x`) — is an organisational desk that many
        // unrelated people legitimately reach (a company's booking/support/office
        // number). Two persons sharing one is NOT evidence they are associates, so
        // it must not fire an "associate cluster; a direct pivot to reach the
        // subject" link. Only a personal line (a mobile or a geographic fixed line)
        // ties specific people together. Non-AU numbers stay grouped (the AU
        // classifier returns `None`), unchanged from before.
        if crate::util::address_au::au_phone_line_type(&phone)
            .is_some_and(|(t, _)| t.is_business_service())
        {
            continue;
        }
        let mut names: Vec<&str> = g.persons.keys().map(String::as_str).collect();
        names.sort_unstable();
        out.push(Correlation::new(
            "AU-050",
            "Shared-phone association",
            Severity::High,
            format!(
                "{} people share one phone line (…{}): {} — associate cluster; the line is \
                 a direct pivot to reach the subject",
                names.len(),
                &phone[phone.len().saturating_sub(4)..],
                names.join(", ")
            ),
            g.firing_uids(),
            scan_id,
            ts,
        ));
    }
    out
}

/// AU-051 — Shared-surname kin signal (likely relatives).
///
/// A strict escalation of AU-049: when two or more co-residents at one address
/// also share a **family name**, they are likely *relatives*, not merely
/// roommates — the kin link that lets an investigator walk a family tree to a
/// target who is themselves dark. Requires both a shared residence and a
/// shared surname (so two unrelated same-surname people at different
/// addresses never link).
///
/// Severity depends on how distinctive the surname is
/// ([`crate::util::surnames::is_common`]): a distinctive shared surname fires
/// Critical as a confirmed kin pivot, but a *common* surname (Smith, Nguyen,
/// …) is downgraded to a High "verify before treating as a kin pivot" lead —
/// an apartment tower or share-house whose unit numbers are absent from the
/// data can collapse unrelated same-surname co-residents onto one residence
/// key, and a popular name makes that coincidence likely enough that
/// asserting a confirmed kin pivot at Critical would be a confident false
/// claim.
pub(in crate::core::correlator) fn rule_au_051_shared_surname_kin(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    // Cheap precondition: kin needs ≥2 distinct persons sharing a residence, so
    // fewer than two Person entities anywhere can never fire — bail before
    // building the residence-group map.
    if entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .count()
        < 2
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (addr, g) in residence_groups(entities) {
        if g.persons.len() < 2 {
            continue;
        }
        // Bucket the residence's named persons by surname; a bucket with ≥2
        // distinct people is a kin set.
        let mut by_surname: std::collections::BTreeMap<String, Vec<(&str, &str)>> =
            std::collections::BTreeMap::new();
        for (name, uid) in &g.persons {
            if let Some(sn) = surname(name) {
                by_surname.entry(sn).or_default().push((name, uid));
            }
        }
        for (sn, members) in by_surname {
            if members.len() < 2 {
                continue;
            }
            let mut names: Vec<&str> = members.iter().map(|(n, _)| *n).collect();
            names.sort_unstable();
            let mut uids: Vec<String> = Vec::new();
            if let Some(u) = &g.anchor_uid {
                uids.push(u.clone());
            }
            let mut kin_uids: Vec<String> = members.iter().map(|(_, u)| u.to_string()).collect();
            kin_uids.sort_unstable();
            uids.extend(kin_uids);
            // A COMMON surname (Smith, Nguyen, …) shared at one address is far
            // weaker kin evidence: an apartment tower or share-house whose unit
            // numbers are absent from the data collapses unrelated same-surname
            // co-residents onto one residence key, and a popular name makes that
            // coincidence likely. Asserting "likely relatives; kin pivot" at
            // Critical there is a confident false claim — surface it as a High LEAD
            // to verify instead. A distinctive surname at one residence stays the
            // Critical kin signal it has always been. (Same `is_common` discount the
            // kinship/leads/engine paths already apply.)
            let common = crate::util::surnames::is_common(&sn);
            let (severity, qualifier) = if common {
                (
                    Severity::High,
                    "possibly relatives (common surname — verify before treating as a kin pivot)",
                )
            } else {
                (
                    Severity::Critical,
                    "likely relatives; kin pivot to reach the subject",
                )
            };
            out.push(Correlation::new(
                "AU-051",
                "Shared-surname kin (likely relatives)",
                severity,
                format!(
                    "{} people sharing the family name '{}' co-located at one residence ('{}'): \
                     {} — {}",
                    names.len(),
                    sn,
                    addr,
                    names.join(", "),
                    qualifier
                ),
                uids,
                scan_id,
                ts,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;
    use crate::core::entity::Evidence;

    // ── normalise_address ─────────────────────────────────────────────────────

    #[test]
    fn normalise_address_collapses_punctuation_and_case() {
        // Two spellings of the same residence must collapse to one key.
        assert_eq!(
            normalise_address("123 Main St, Apt 4"),
            normalise_address("123 main st apt 4")
        );
        assert_eq!(normalise_address("123 Main St, Apt 4"), "123 main st apt 4");
    }

    #[test]
    fn normalise_address_drops_format_punctuation_and_trims() {
        // `#`, `.`, `-`, `/`, `\` are removed (joining adjacent tokens, so
        // `Main-St` ⇒ `mainst`); commas/whitespace runs collapse; ends trimmed.
        assert_eq!(
            normalise_address("  Apt #4, 123 Main-St.  "),
            "apt 4 123 mainst"
        );
    }

    // ── normalise_phone ───────────────────────────────────────────────────────

    #[test]
    fn normalise_phone_collapses_formatting_to_digits() {
        assert_eq!(
            normalise_phone("+1 (415) 555-0100"),
            Some("14155550100".into())
        );
        assert_eq!(normalise_phone("14155550100"), Some("14155550100".into()));
    }

    #[test]
    fn normalise_phone_rejects_short_and_placeholder_runs() {
        assert_eq!(normalise_phone("12345"), None); // < 8 digits
        assert_eq!(normalise_phone("+00000000"), None); // all-same-digit placeholder
    }

    // ── surname ───────────────────────────────────────────────────────────────

    #[test]
    fn surname_takes_last_alpha_token_lowercased() {
        assert_eq!(surname("Jane Mary Doe"), Some("doe".into()));
        assert_eq!(surname("Cher"), Some("cher".into()));
    }

    #[test]
    fn surname_none_when_trailing_token_too_short() {
        // After alpha-filtering, a 1-char trailing token is rejected.
        assert_eq!(surname("Alice B"), None);
        assert_eq!(surname("Bob 3"), None); // digits filtered out → empty
    }

    // ── entity_phones ─────────────────────────────────────────────────────────

    #[test]
    fn entity_phones_normalises_and_dedups_across_evidence() {
        let mut e = Entity::new(EntityKind::Person, "Jane Doe", confidence::MEDIUM_PLUS, "s");
        e.add_evidence(Evidence::new("oathnet", "hit").with_attr("phone", "+1 (415) 555-0100"));
        // Same line, different formatting → one key after normalisation.
        e.add_evidence(Evidence::new("dehashed", "hit").with_attr("phone", "1-415-555-0100"));
        // A short fragment is dropped.
        e.add_evidence(Evidence::new("see_know", "hit").with_attr("phone", "911"));
        let phones = entity_phones(&e);
        assert_eq!(phones, vec!["14155550100".to_string()]);
    }

    #[test]
    fn entity_phones_and_residences_split_multi_value_observations() {
        // When two distinct observations are accumulated under one key as "a; b"
        // (the with_attr / absorb convention), each must be judged on its own — a
        // whole-string normalise would concatenate the two phones' digits into one
        // bogus key and garble the two addresses into one non-matching key.
        let mut e = Entity::new(EntityKind::Person, "Jane Doe", confidence::MEDIUM_PLUS, "s");
        e.add_evidence(
            Evidence::new("oathnet", "hit")
                .with_attr("phone", "+1 (415) 555-0100")
                .with_attr("phone", "+61 400 000 001"),
        );
        let mut phones = entity_phones(&e);
        phones.sort();
        assert_eq!(
            phones,
            vec!["14155550100".to_string(), "61400000001".to_string()],
            "both numbers recovered, not a concatenated digit-run"
        );

        let mut h = Entity::new(EntityKind::Person, "Jane Doe", confidence::MEDIUM_PLUS, "s");
        h.add_evidence(
            Evidence::new("oathnet", "hit")
                .with_attr("address", "12 Wattle St, Logan QLD 4114")
                .with_attr("address", "99 Oak Ave, Ipswich QLD 4305"),
        );
        let res = entity_residences(&h);
        assert_eq!(res.len(), 2, "both residences recovered: {res:?}");
    }
}
