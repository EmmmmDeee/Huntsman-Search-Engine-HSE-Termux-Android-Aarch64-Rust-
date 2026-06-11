//! AU correlation rules — associates / household family.
//!
//! This family implements the professional move against a target who has gone
//! dark: you do not find *them*, you find the people around them who are not
//! hiding. A shared residence is the strongest such seam — co-residents,
//! relatives, and associates leak the footprint the individual has scrubbed.
//! It works on a true ghost (the network leaks what the person doesn't) and it
//! works on the average person (almost everyone shares an address with someone),
//! which is exactly the intersection this rule set targets.
//!
//! ## MITRE ATT&CK TA0043 coverage
//!
//! | Rule    | Technique(s)                                          |
//! |---------|-------------------------------------------------------|
//! | AU-049  | T1589 × T1598.003 — identity info via shared address  |
//! | AU-050  | T1589.001 — Credentials / contact line linkage        |
//! | AU-051  | T1589.003 × T1598.003 — kinship / employee-name pivot |
//!
//! Rules reach shared helpers through `use super::*` (see `rules/mod.rs`).

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

/// Collect the deduplicated, normalised values of one evidence attribute across
/// an entity's evidence, keeping the first-seen order. Dedup is O(1) per item
/// via a `HashSet` guard rather than the former O(n) `Vec::contains` scan inside
/// the loop — an entity carrying many breach records (each with an `address` or
/// `phone` field) no longer degrades quadratically. `normalise` returns the key
/// to store (or `None` to skip the record).
fn dedup_attr<F>(e: &Entity, attr: &str, normalise: F) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for ev in &e.evidence {
        if let Some(raw) = ev.attributes.get(attr)
            && let Some(key) = normalise(raw)
            && seen.insert(key.clone())
        {
            out.push(key);
        }
    }
    out
}

/// Pull every specific residence address attached to an entity's evidence
/// (breach/dossier records carry the subject's postal address under an
/// `address` attribute). Returns the *normalised* keys, deduplicated.
fn entity_residences(e: &Entity) -> Vec<String> {
    dedup_attr(e, "address", |raw| {
        let key = normalise_address(raw);
        is_residence_address(&key).then_some(key)
    })
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
    dedup_attr(e, "phone", normalise_phone)
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

/// Maximum reachable handles attached to a firing — bounds the UID list so a
/// pathological address with hundreds of co-located handles can't bloat one
/// correlation's payload.
const MAX_FIRING_HANDLES: usize = 8;

/// A cluster of identities sharing one grouping key (a residence or a phone):
/// the distinct named persons (value → uid), any directly-reachable handle uids
/// (emails/phones), and the uid of the first-class anchor node (the Address or
/// Phone entity) for that key, when one is present.
#[derive(Default)]
struct Group {
    persons: std::collections::BTreeMap<String, String>,
    handles: Vec<String>,
    handle_set: HashSet<String>,
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
                // O(1) dedup via the companion set, rather than a linear
                // `Vec::contains` on every handle insert.
                if self.handle_set.insert(e.uid.clone()) {
                    self.handles.push(e.uid.clone());
                }
            }
            _ => {}
        }
    }

    /// Deterministic firing uid list: anchor node, then sorted person uids, then
    /// a bounded, sorted set of reachable handles.
    fn firing_uids(&self) -> Vec<String> {
        let mut uids: Vec<String> =
            Vec::with_capacity(1 + self.persons.len() + self.handles.len().min(MAX_FIRING_HANDLES));
        if let Some(u) = &self.anchor_uid {
            uids.push(u.clone());
        }
        let mut person_uids: Vec<String> = self.persons.values().cloned().collect();
        person_uids.sort_unstable();
        uids.extend(person_uids);
        let mut handles = self.handles.clone();
        handles.sort_unstable();
        uids.extend(handles.into_iter().take(MAX_FIRING_HANDLES));
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
                .get_or_insert(a.uid.clone());
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
/// MITRE T1589 × T1598.003: groups identity-bearing entities by the specific
/// residence address recorded in their evidence and fires when **two or more
/// distinct persons** share one address. That is the associate seam: the named
/// co-residents are the pivot to reach a subject who has otherwise scrubbed
/// their own footprint. Any emails / phones recorded at the same address ride
/// along in the firing as the directly reachable handles for those co-residents.
///
/// Precision discipline (mirrors AU-047): the address must be specific enough to
/// be a residence (see [`is_residence_address`]) and the cluster must contain
/// ≥2 *distinct person names* — two of one person's own emails at one address is
/// not an association, so the anchor is named people, not raw handle count.
pub(in crate::core::correlator) fn rule_au_049_shared_address_association(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
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
/// MITRE T1589.001: the phone-number analogue of AU-049 — a number shared by two
/// or more distinct named persons (family plan, shared landline, a relative's
/// contact line) is an associate seam independent of address; it links people
/// who may live in different cities. Keyed purely on the phone, so it reaches
/// associations the residence rule never sees.
///
/// Same precision discipline: the number must be a plausible subscriber line
/// (≥8 digits, not an all-same-digit placeholder — see [`normalise_phone`]) and
/// the cluster must contain ≥2 *distinct person names*, never one person's two
/// addresses on a single line.
pub(in crate::core::correlator) fn rule_au_050_shared_phone_association(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut groups: std::collections::BTreeMap<String, Group> = std::collections::BTreeMap::new();
    // Pre-seed anchor nodes from first-class Phone entities.
    for ph in entities_of_kind(entities, EntityKind::Phone) {
        if let Some(key) = normalise_phone(&ph.value) {
            groups
                .entry(key)
                .or_default()
                .anchor_uid
                .get_or_insert(ph.uid.clone());
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
/// MITRE T1589.003 × T1598.003: a strict escalation of AU-049 — when two or more
/// co-residents at one address also share a **family name**, they are very likely
/// *relatives*, not merely roommates — the kin link that lets an investigator
/// walk a family tree to a target who is themselves dark. Requires both a shared
/// residence (so two unrelated people named "Smith" never link) and a shared
/// surname, and fires Critical because a confirmed kin relationship is the
/// highest-value pivot in this family.
pub(in crate::core::correlator) fn rule_au_051_shared_surname_kin(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
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
            let mut uids: Vec<String> = Vec::with_capacity(1 + members.len());
            if let Some(u) = &g.anchor_uid {
                uids.push(u.clone());
            }
            let mut kin_uids: Vec<String> = members.iter().map(|(_, u)| u.to_string()).collect();
            kin_uids.sort_unstable();
            uids.extend(kin_uids);
            out.push(Correlation::new(
                "AU-051",
                "Shared-surname kin (likely relatives)",
                Severity::Critical,
                format!(
                    "{} people sharing the family name '{}' co-located at one residence ('{}'): \
                     {} — likely relatives; kin pivot to reach the subject",
                    names.len(),
                    sn,
                    addr,
                    names.join(", ")
                ),
                uids,
                scan_id,
                ts,
            ));
        }
    }
    out
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

    /// Build a Person entity carrying an `address` evidence attribute.
    fn person_at(name: &str, address: &str) -> Entity {
        let mut e = mk(EntityKind::Person, name, 0.8);
        e.add_evidence(Evidence::new("breach", "record").with_attr("address", address));
        e
    }

    /// Build a Person entity carrying a `phone` evidence attribute.
    fn person_with_phone(name: &str, phone: &str) -> Entity {
        let mut e = mk(EntityKind::Person, name, 0.8);
        e.add_evidence(Evidence::new("breach", "record").with_attr("phone", phone));
        e
    }

    // ── normalise_address ────────────────────────────────────────────────────

    #[test]
    fn normalise_address_collapses_formatting_variants() {
        assert_eq!(
            normalise_address("123 Main St, Apt 4"),
            normalise_address("123 main st apt 4")
        );
        assert_eq!(normalise_address("12-34 O'Brien Rd."), "1234 o'brien rd");
        assert_eq!(normalise_address("  10   George   St  "), "10 george st");
    }

    #[test]
    fn normalise_address_handles_empty_and_punct_only() {
        assert_eq!(normalise_address(""), "");
        assert_eq!(normalise_address("#.-/\\"), "");
    }

    // ── normalise_phone ──────────────────────────────────────────────────────

    #[test]
    fn normalise_phone_strips_formatting() {
        assert_eq!(
            normalise_phone("+1 (415) 555-0100"),
            Some("14155550100".to_string())
        );
        assert_eq!(
            normalise_phone("14155550100"),
            Some("14155550100".to_string())
        );
    }

    #[test]
    fn normalise_phone_rejects_short_and_placeholder() {
        assert_eq!(normalise_phone("1234567"), None); // 7 digits
        assert_eq!(normalise_phone("+00000000"), None); // all-same
        assert_eq!(normalise_phone("00000000000"), None); // all-same, long
        assert_eq!(normalise_phone("abc"), None); // no digits
    }

    // ── surname ──────────────────────────────────────────────────────────────

    #[test]
    fn surname_extracts_last_alpha_token() {
        assert_eq!(surname("Haigen Bamford"), Some("bamford".to_string()));
        assert_eq!(surname("Mary-Jane O'Brien"), Some("obrien".to_string()));
        assert_eq!(surname("Cher"), Some("cher".to_string()));
    }

    #[test]
    fn surname_rejects_too_short_trailing_token() {
        assert_eq!(surname("John Q"), None); // single trailing char
        assert_eq!(surname(""), None);
    }

    // ── dedup_attr / entity_residences O(1) dedup ────────────────────────────

    #[test]
    fn entity_residences_dedups_repeated_address() {
        let mut e = mk(EntityKind::Person, "Alice Smith", 0.8);
        // Same residence under three different formattings + one region.
        e.add_evidence(
            Evidence::new("breach_a", "r").with_attr("address", "10 George St, Brisbane QLD 4000"),
        );
        e.add_evidence(
            Evidence::new("breach_b", "r").with_attr("address", "10 george st brisbane qld 4000"),
        );
        e.add_evidence(Evidence::new("breach_c", "r").with_attr("address", "Australia")); // region, dropped
        let res = entity_residences(&e);
        assert_eq!(res.len(), 1, "duplicate residence not collapsed: {res:?}");
    }

    #[test]
    fn entity_phones_dedups_repeated_number() {
        let mut e = mk(EntityKind::Person, "Alice Smith", 0.8);
        e.add_evidence(Evidence::new("breach_a", "r").with_attr("phone", "+61 7 3000 0001"));
        e.add_evidence(Evidence::new("breach_b", "r").with_attr("phone", "0730000001")); // different repr
        e.add_evidence(Evidence::new("breach_c", "r").with_attr("phone", "+61 7 3000 0001")); // dup of first
        let phones = entity_phones(&e);
        // First two normalise differently (country code present/absent); the
        // third dups the first. So 2 distinct keys, not 3.
        assert_eq!(phones.len(), 2, "phone dedup wrong: {phones:?}");
    }

    // ── AU-049 shared address ────────────────────────────────────────────────

    #[test]
    fn au049_fires_for_two_people_at_one_residence() {
        let addr = "10 George St, Brisbane QLD 4000";
        let entities = vec![person_at("Alice Smith", addr), person_at("Bob Jones", addr)];
        let c = rule_au_049_shared_address_association(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-049");
        assert_eq!(c[0].severity, Severity::High);
        assert!(c[0].description.contains("Alice Smith"));
        assert!(c[0].description.contains("Bob Jones"));
    }

    #[test]
    fn au049_silent_for_single_person() {
        let entities = vec![person_at("Alice Smith", "10 George St, Brisbane QLD 4000")];
        assert!(rule_au_049_shared_address_association(&entities, S, TS).is_empty());
    }

    #[test]
    fn au049_silent_for_region_only_address() {
        // Two people but only a region (not a specific residence) → no household.
        let entities = vec![
            person_at("Alice Smith", "Australia"),
            person_at("Bob Jones", "Australia"),
        ];
        assert!(rule_au_049_shared_address_association(&entities, S, TS).is_empty());
    }

    #[test]
    fn au049_does_not_fuse_two_emails_of_one_person() {
        // One person, two email handles at the same address → not an association.
        let addr = "10 George St, Brisbane QLD 4000";
        let person = person_at("Alice Smith", addr);
        let mut email1 = mk(EntityKind::Email, "alice@x.com", 0.8);
        email1.add_evidence(Evidence::new("breach", "r").with_attr("address", addr));
        let mut email2 = mk(EntityKind::Email, "alice@y.com", 0.8);
        email2.add_evidence(Evidence::new("breach", "r").with_attr("address", addr));
        let entities = vec![person, email1, email2];
        // Only one distinct person name → no fire.
        assert!(rule_au_049_shared_address_association(&entities, S, TS).is_empty());
    }

    #[test]
    fn au049_includes_address_anchor_uid() {
        let addr = "10 George St, Brisbane QLD 4000";
        let anchor = mk(EntityKind::Address, addr, 0.9);
        let anchor_uid = anchor.uid.clone();
        let entities = vec![
            anchor,
            person_at("Alice Smith", addr),
            person_at("Bob Jones", addr),
        ];
        let c = rule_au_049_shared_address_association(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert!(
            c[0].entity_uids.contains(&anchor_uid),
            "address anchor uid missing from firing"
        );
    }

    // ── AU-050 shared phone ──────────────────────────────────────────────────

    #[test]
    fn au050_fires_for_two_people_on_one_line() {
        let phone = "+61 7 3000 0001";
        let entities = vec![
            person_with_phone("Alice Smith", phone),
            person_with_phone("Bob Jones", phone),
        ];
        let c = rule_au_050_shared_phone_association(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-050");
        assert_eq!(c[0].severity, Severity::High);
    }

    #[test]
    fn au050_silent_for_single_person() {
        let entities = vec![person_with_phone("Alice Smith", "+61 7 3000 0001")];
        assert!(rule_au_050_shared_phone_association(&entities, S, TS).is_empty());
    }

    #[test]
    fn au050_silent_for_placeholder_number() {
        let entities = vec![
            person_with_phone("Alice Smith", "00000000000"),
            person_with_phone("Bob Jones", "00000000000"),
        ];
        assert!(rule_au_050_shared_phone_association(&entities, S, TS).is_empty());
    }

    #[test]
    fn au050_description_shows_last_four_digits() {
        let phone = "+61 7 3000 1234";
        let entities = vec![
            person_with_phone("Alice Smith", phone),
            person_with_phone("Bob Jones", phone),
        ];
        let c = rule_au_050_shared_phone_association(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert!(
            c[0].description.contains("1234"),
            "last-4 not shown: {}",
            c[0].description
        );
    }

    // ── AU-051 kin ───────────────────────────────────────────────────────────

    #[test]
    fn au051_fires_for_shared_surname_at_one_residence() {
        let addr = "10 George St, Brisbane QLD 4000";
        let entities = vec![
            person_at("Alice Bamford", addr),
            person_at("Haigen Bamford", addr),
        ];
        let c = rule_au_051_shared_surname_kin(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].rule_id, "AU-051");
        assert_eq!(c[0].severity, Severity::Critical);
        assert!(c[0].description.contains("bamford"));
    }

    #[test]
    fn au051_silent_for_different_surnames_same_residence() {
        // Co-residents but unrelated surnames → AU-049 fires, AU-051 does not.
        let addr = "10 George St, Brisbane QLD 4000";
        let entities = vec![person_at("Alice Smith", addr), person_at("Bob Jones", addr)];
        assert!(rule_au_051_shared_surname_kin(&entities, S, TS).is_empty());
        // Sanity: AU-049 still fires on the same input.
        assert_eq!(
            rule_au_049_shared_address_association(&entities, S, TS).len(),
            1
        );
    }

    #[test]
    fn au051_silent_for_same_surname_different_residences() {
        // Two "Smith"s at different addresses must NOT link as kin.
        let entities = vec![
            person_at("Alice Smith", "10 George St, Brisbane QLD 4000"),
            person_at("Bob Smith", "99 Queen St, Melbourne VIC 3000"),
        ];
        assert!(rule_au_051_shared_surname_kin(&entities, S, TS).is_empty());
    }

    #[test]
    fn au051_three_relatives_one_household() {
        let addr = "10 George St, Brisbane QLD 4000";
        let entities = vec![
            person_at("Alice Bamford", addr),
            person_at("Haigen Bamford", addr),
            person_at("Mary Bamford", addr),
        ];
        let c = rule_au_051_shared_surname_kin(&entities, S, TS);
        assert_eq!(c.len(), 1);
        assert!(c[0].description.contains("3 people"));
    }

    // ── Group bounded firing ─────────────────────────────────────────────────

    #[test]
    fn firing_uids_bounds_handles() {
        let mut g = Group::default();
        for i in 0..20 {
            let e = mk(EntityKind::Email, &format!("e{i}@x.com"), 0.8);
            g.add_identity(&e);
        }
        // No persons, but verify handles are bounded by MAX_FIRING_HANDLES.
        let uids = g.firing_uids();
        assert!(
            uids.len() <= MAX_FIRING_HANDLES,
            "handles not bounded: {}",
            uids.len()
        );
    }

    #[test]
    fn group_add_identity_dedups_handles() {
        let mut g = Group::default();
        let e = mk(EntityKind::Email, "alice@x.com", 0.8);
        g.add_identity(&e);
        g.add_identity(&e); // same uid → should not double-count
        assert_eq!(g.handles.len(), 1);
    }
}
