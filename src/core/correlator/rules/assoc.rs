//! AU correlation rules — associates / household family. See `super`
//! (rules/mod.rs) for the shared helpers; every rule reaches them through
//! `use super::*`.
//!
//! This family implements the professional move against a target who has gone
//! dark: you do not find *them*, you find the people around them who are not
//! hiding. A shared residence is the strongest such seam — co-residents,
//! relatives, and associates leak the footprint the individual has scrubbed.
//! It works on a true ghost (the network leaks what the person doesn't) and it
//! works on the average person (almost everyone shares an address with someone),
//! which is exactly the intersection this rule set targets.

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

/// True when an address string is specific enough to identify a *residence*
/// rather than a region. A bare country/state/city ("USA", "California", "New
/// York") names a place thousands of unrelated people share — clustering on it
/// would fuse strangers into a false household. We require a street-number
/// signal (an ASCII digit) and at least three tokens, which admits
/// `"123 Main St, Springfield"` while rejecting `"United States"`. Precision
/// over recall: a missed digit-less address is far cheaper than a fabricated
/// link between unrelated people.
fn is_residence_address(normalised: &str) -> bool {
    let tokens = normalised.split(' ').filter(|t| !t.is_empty()).count();
    let has_digit = normalised.bytes().any(|b| b.is_ascii_digit());
    tokens >= 3 && has_digit && normalised.len() >= 8
}

/// Pull every specific residence address attached to an entity's evidence
/// (breach/dossier records carry the subject's postal address under an
/// `address` attribute). Returns the *normalised* keys, deduplicated.
fn entity_residences(e: &Entity) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for ev in &e.evidence {
        if let Some(raw) = ev.attributes.get("address") {
            let key = normalise_address(raw);
            if is_residence_address(&key) && !out.contains(&key) {
                out.push(key);
            }
        }
    }
    out
}

/// AU-049 — Shared-address association (household / associate cluster).
///
/// Groups identity-bearing entities by the specific residence address recorded
/// in their evidence and fires when **two or more distinct persons** share one
/// address. That is the associate seam: the named co-residents are the pivot to
/// reach a subject who has otherwise scrubbed their own footprint. Any emails /
/// phones recorded at the same address ride along in the firing as the directly
/// reachable handles for those co-residents.
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
    use std::collections::BTreeMap;

    // normalised address -> (distinct person value -> uid), context handle uids,
    // and the Address entity uid if one is present for that residence.
    #[derive(Default)]
    struct Group {
        persons: BTreeMap<String, String>,
        handles: Vec<String>,
        address_uid: Option<String>,
    }
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();

    // Index Address entities by their own normalised value so the firing can
    // reference the first-class Address node (and so a residence that exists as
    // an Address entity is recognised even if no identity carries the attribute).
    for a in entities_of_kind(entities, EntityKind::Address) {
        let key = normalise_address(&a.value);
        if is_residence_address(&key) {
            groups
                .entry(key)
                .or_default()
                .address_uid
                .get_or_insert(a.uid.clone());
        }
    }

    for e in entities {
        for key in entity_residences(e) {
            let g = groups.entry(key).or_default();
            match e.kind {
                EntityKind::Person => {
                    g.persons
                        .entry(e.value.clone())
                        .or_insert_with(|| e.uid.clone());
                }
                EntityKind::Email | EntityKind::Phone => {
                    if !g.handles.contains(&e.uid) {
                        g.handles.push(e.uid.clone());
                    }
                }
                _ => {}
            }
        }
    }

    let mut out = Vec::new();
    for (addr, g) in groups {
        if g.persons.len() < 2 {
            continue;
        }
        let mut names: Vec<&str> = g.persons.keys().map(String::as_str).collect();
        names.sort_unstable();

        // Stable, deterministic uid order: address node, then person uids, then a
        // bounded set of reachable handles.
        let mut uids: Vec<String> = Vec::new();
        if let Some(u) = &g.address_uid {
            uids.push(u.clone());
        }
        let mut person_uids: Vec<String> = g.persons.values().cloned().collect();
        person_uids.sort_unstable();
        uids.extend(person_uids);
        let mut handles = g.handles.clone();
        handles.sort_unstable();
        uids.extend(handles.into_iter().take(8));

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
            uids,
            scan_id,
            ts,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    fn person_at(name: &str, addr: &str) -> Entity {
        let mut e = Entity::new(EntityKind::Person, name, 0.62, "s");
        e.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("address", addr));
        e
    }

    #[test]
    fn fires_on_two_people_one_residence() {
        let ents = vec![
            person_at("Jordan Meyers", "123 Main St, Springfield, IL"),
            person_at("Dana Meyers", "123 Main St Springfield IL"),
        ];
        let hits = rule_au_049_shared_address_association(&ents, "s", 0);
        assert_eq!(hits.len(), 1, "one household cluster expected");
        assert_eq!(hits[0].rule_id, "AU-049");
        assert!(hits[0].description.contains("2 people"));
    }

    #[test]
    fn single_person_does_not_fire() {
        let ents = vec![person_at("Jordan Meyers", "123 Main St, Springfield, IL")];
        assert!(rule_au_049_shared_address_association(&ents, "s", 0).is_empty());
    }

    #[test]
    fn one_persons_two_emails_is_not_a_household() {
        // Two emails + one named person at an address is the SAME person's
        // handles, not an association — must not fire.
        let mut e1 = Entity::new(EntityKind::Email, "jordan@gmail.com", 0.72, "s");
        e1.add_evidence(
            Evidence::new("import:dossier", "e").with_attr("address", "123 Main St, Springfield"),
        );
        let mut e2 = Entity::new(EntityKind::Email, "j.meyers@work.com", 0.72, "s");
        e2.add_evidence(
            Evidence::new("import:dossier", "e").with_attr("address", "123 Main St, Springfield"),
        );
        let ents = vec![
            person_at("Jordan Meyers", "123 Main St, Springfield"),
            e1,
            e2,
        ];
        assert!(rule_au_049_shared_address_association(&ents, "s", 0).is_empty());
    }

    #[test]
    fn region_only_address_never_clusters() {
        // A bare region shared by strangers must not fuse a household.
        let ents = vec![
            person_at("Jordan Meyers", "California"),
            person_at("Unrelated Stranger", "California"),
        ];
        assert!(rule_au_049_shared_address_association(&ents, "s", 0).is_empty());
    }

    #[test]
    fn includes_reachable_handles_and_address_node() {
        let mut email = Entity::new(EntityKind::Email, "dana@gmail.com", 0.72, "s");
        email.add_evidence(
            Evidence::new("import:dossier", "e").with_attr("address", "123 Main St, Springfield"),
        );
        let addr = Entity::new(EntityKind::Address, "123 Main St, Springfield", 0.58, "s");
        let addr_uid = addr.uid.clone();
        let email_uid = email.uid.clone();
        let ents = vec![
            person_at("Jordan Meyers", "123 Main St, Springfield"),
            person_at("Dana Meyers", "123 Main St, Springfield"),
            email,
            addr,
        ];
        let hits = rule_au_049_shared_address_association(&ents, "s", 0);
        assert_eq!(hits.len(), 1);
        assert!(
            hits[0].entity_uids.contains(&addr_uid),
            "address node referenced"
        );
        assert!(
            hits[0].entity_uids.contains(&email_uid),
            "reachable handle referenced"
        );
    }

    #[test]
    fn address_normalisation_collapses_formatting() {
        assert_eq!(
            normalise_address("123 Main St., Apt #4"),
            normalise_address("123  main st apt 4")
        );
    }

    #[test]
    fn residence_requires_street_signal() {
        assert!(is_residence_address(&normalise_address(
            "123 Main St, Springfield"
        )));
        assert!(!is_residence_address(&normalise_address("United States")));
        assert!(!is_residence_address(&normalise_address("California")));
    }
}
