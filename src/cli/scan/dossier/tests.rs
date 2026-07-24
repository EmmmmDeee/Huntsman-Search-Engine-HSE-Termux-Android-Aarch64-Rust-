use super::analysis::confine_relations_to_visible;
use super::appendix::{tenure_headline, total_dead_scan_hint};
use super::findings::{DOSSIER_KIND_ORDER, group_by_kind, kind_heading, order_dossier_kinds};
use super::frontmatter::entities_header_line;
use super::plan::{Appendix, Plan, contents_lines, letter_appendices};
use super::truncation_note;

use crate::core::entity::{Entity, EntityKind};
use crate::core::event::{Event, EventKind};
use crate::core::module::ModuleCost;
use crate::core::relation::{Relation, RelationKind};
use crate::core::timeline::{FootprintRecency, FootprintStatus, OnlineTenure};
use crate::util::diagnostics::keyed_or_paid_zero_yield_modules;
use std::collections::HashMap;

// ─── PART I — findings by entity type ──────────────────────────────────────

#[test]
fn dossier_renders_every_present_kind_never_dropping_one() {
    // Regression: the dossier used to iterate a fixed allowlist and silently
    // drop any kind not in it — `cidr`, `ssid`, `tracking_id`,
    // `crypto_address`, and every `other:<custom>` vanished from the operator's
    // output. `order_dossier_kinds` must surface EVERY present kind.
    let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.9, "s");
    let ents = [
        mk(EntityKind::Email, "a@b.com"),
        mk(EntityKind::CryptoAddress, "bc1qexample"),
        mk(EntityKind::Ssid, "HOME-WIFI"),
        mk(EntityKind::TrackingId, "UA-12345-6"),
        mk(EntityKind::Cidr, "10.0.0.0/8"),
        mk(EntityKind::Other("passport".to_string()), "X1234567"),
        mk(EntityKind::Person, "Jane Doe"),
    ];
    let by_kind = group_by_kind(&ents);

    let ordered = order_dossier_kinds(&by_kind);

    // Every present kind appears exactly once — none dropped.
    assert_eq!(
        ordered.len(),
        by_kind.len(),
        "the ordering must cover every present kind, ordered was {ordered:?}"
    );
    for k in by_kind.keys() {
        assert!(
            ordered.contains(&k.as_str()),
            "kind {k:?} was dropped from the dossier ordering {ordered:?}"
        );
    }
    // The previously-dropped kinds are specifically present.
    for dropped in [
        "crypto_address",
        "ssid",
        "tracking_id",
        "cidr",
        "other:passport",
    ] {
        assert!(
            ordered.contains(&dropped),
            "the formerly-dropped kind {dropped} must now render"
        );
    }

    // Curated kinds keep their relative order (person before email), and the
    // uncurated `other:*` kind is appended AFTER all curated ones.
    let pos = |k: &str| ordered.iter().position(|x| *x == k).unwrap();
    assert!(pos("person") < pos("email"));
    assert!(pos("crypto_address") < pos("other:passport"));
    assert!(
        DOSSIER_KIND_ORDER.contains(&"crypto_address"),
        "crypto_address must be in the curated order, not just the catch-all"
    );
}

#[test]
fn group_by_kind_keeps_every_entity() {
    let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.9, "s");
    let ents = [
        mk(EntityKind::Email, "a@b.com"),
        mk(EntityKind::Email, "c@d.com"),
        mk(EntityKind::Person, "Jane Doe"),
    ];
    let by_kind = group_by_kind(&ents);
    assert_eq!(by_kind.len(), 2, "two distinct kinds");
    assert_eq!(
        by_kind.values().map(Vec::len).sum::<usize>(),
        ents.len(),
        "grouping must not drop an entity"
    );
}

/// An unrecognised kind must be titled with its own key rather than bucketed
/// under a generic heading that would misdescribe what is beneath it.
#[test]
fn kind_heading_titles_an_unknown_kind_with_its_own_key() {
    assert_eq!(kind_heading("email"), "EMAIL ADDRESSES");
    assert_eq!(kind_heading("other:passport"), "other:passport");
    assert_eq!(
        kind_heading("a_kind_added_next_year"),
        "a_kind_added_next_year"
    );
}

// ─── CONTENTS / appendix lettering ─────────────────────────────────────────

/// The property the whole `plan` module exists for: an absent appendix
/// consumes no letter, so the sequence a reader sees is always A, B, C… with
/// no hole. A gap would read as a lost page rather than an omitted section.
#[test]
fn appendix_letters_are_contiguous_from_a() {
    // A first-ever scan with no bridges, no lineage and no hints: the three
    // unconditional appendices are all that remain, and they must letter A/B/C
    // — not B/C/D as they would if the absent cross-scan appendix reserved A.
    let lettered = letter_appendices(&[Appendix::Collection, Appendix::Geo, Appendix::Timeline]);
    assert_eq!(
        lettered,
        vec![
            ('A', Appendix::Collection),
            ('B', Appendix::Geo),
            ('C', Appendix::Timeline),
        ]
    );

    // And with every appendix present, the letters run the full span in the
    // fixed presentation order.
    let all = letter_appendices(Appendix::ORDER);
    let letters: Vec<char> = all.iter().map(|(l, _)| *l).collect();
    assert_eq!(letters, vec!['A', 'B', 'C', 'D', 'E', 'F']);
    assert_eq!(
        all.iter().map(|(_, a)| *a).collect::<Vec<_>>(),
        Appendix::ORDER.to_vec(),
        "presence filters the order, it never reorders it"
    );
}

/// `letter_appendices` maps index → `b'A' + index`, which silently assumes the
/// back matter can never outgrow the alphabet. Pin that assumption here so
/// adding a 27th appendix fails a test rather than printing a stray glyph.
#[test]
fn the_back_matter_fits_in_the_alphabet() {
    assert!(
        Appendix::ORDER.len() <= 26,
        "an appendix past Z has no letter to print under"
    );
}

/// The index and the body are rendered from one plan, so the index cannot
/// promise a section the dossier does not carry.
#[test]
fn contents_lists_exactly_what_the_dossier_carries() {
    let present = [Appendix::Collection, Appendix::Geo, Appendix::Timeline];
    let plan = Plan::new(vec!["correlations", "connections"], &present);
    let lines = contents_lines(3, 12, &plan);

    assert!(lines[0].contains("PART I"), "{lines:?}");
    assert!(lines[0].contains("3 kinds, 12 findings"), "{lines:?}");
    assert!(
        lines[1].contains("PART II") && lines[1].contains("correlations, connections"),
        "{lines:?}"
    );

    // Every appendix line corresponds to a present appendix, and every present
    // appendix has a line — neither over- nor under-promising.
    let appendix_lines: Vec<&String> = lines.iter().filter(|l| l.contains("APPENDIX")).collect();
    assert_eq!(appendix_lines.len(), present.len(), "{lines:?}");
    for a in present {
        assert!(
            appendix_lines.iter().any(|l| l.contains(a.title())),
            "{} is carried but not listed: {lines:?}",
            a.title()
        );
    }
    // The absent ones are named nowhere.
    for absent in [
        Appendix::CrossScanLeverage,
        Appendix::Lineage,
        Appendix::Hints,
    ] {
        assert!(
            !lines.iter().any(|l| l.contains(absent.title())),
            "{} is absent but listed: {lines:?}",
            absent.title()
        );
    }
}

/// With nothing to analyse, PART II must not be announced — the dossier goes
/// straight from the findings to the back matter.
#[test]
fn contents_omits_part_two_when_there_is_nothing_to_analyse() {
    let plan = Plan::new(Vec::new(), &[Appendix::Collection]);
    let lines = contents_lines(1, 1, &plan);
    assert!(
        !lines.iter().any(|l| l.contains("PART II")),
        "an empty analysis part must not be listed: {lines:?}"
    );
    // Singular nouns for a single kind / single finding.
    assert!(lines[0].contains("1 kind, 1 finding"), "{lines:?}");
}

/// The cross-reference PART I prints for an empty working set must name the
/// letter the hints appendix will actually print under.
#[test]
fn the_plan_answers_which_letter_an_appendix_will_carry() {
    let plan = Plan::new(Vec::new(), &[Appendix::Collection, Appendix::Hints]);
    assert_eq!(plan.letter(Appendix::Hints), Some('B'));
    assert_eq!(
        plan.letter(Appendix::Geo),
        None,
        "an absent appendix has no letter to point at"
    );
}

// ─── PART II — analysis ────────────────────────────────────────────────────

#[test]
fn confine_relations_to_visible_drops_edges_with_an_excluded_endpoint() {
    // Mirrors `core::relation::sorted_confined_adjacency`'s own confinement:
    // an edge is only traversable/renderable when BOTH endpoints are in the
    // visible entity set. Previously the raw RELATIONS section ignored this
    // entirely and printed every relation regardless.
    let a = Entity::new(EntityKind::Domain, "a.example", 0.9, "s");
    let b = Entity::new(EntityKind::Domain, "b.example", 0.9, "s");
    let hidden_uid = "deadbeef00000000000000000000000000000000000000000000000000000";
    let entities = [a.clone(), b.clone()];
    let relations = [
        Relation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::CoLocatedWith,
            0.8,
            "s",
        ),
        Relation::new(
            a.uid.clone(),
            hidden_uid,
            RelationKind::CoLocatedWith,
            0.8,
            "s",
        ),
    ];
    let confined = confine_relations_to_visible(&entities, &relations);
    assert_eq!(confined.len(), 1, "only the fully-visible edge survives");
    assert_eq!(confined[0].to_uid, b.uid);
}

/// A section is only announced in CONTENTS when it has data — the same
/// emptiness checks the renderers use, read once by the plan.
#[test]
fn analysis_announces_only_the_sections_with_data() {
    let a = Entity::new(EntityKind::Domain, "a.example", 0.9, "s");
    let b = Entity::new(EntityKind::Domain, "b.example", 0.9, "s");
    let entities = [a.clone(), b.clone()];
    let relations = [Relation::new(
        a.uid.clone(),
        b.uid.clone(),
        RelationKind::CoLocatedWith,
        0.8,
        "s",
    )];

    let linkage = super::analysis::Linkage::build(&entities, &relations);
    let titles = linkage.section_titles(&[]);
    assert!(
        titles.contains(&"relations"),
        "a visible edge exists: {titles:?}"
    );
    assert!(
        !titles.contains(&"correlations"),
        "no correlations were passed: {titles:?}"
    );
    assert!(
        !titles.contains(&"derivation trails"),
        "both entities are seed-generation: {titles:?}"
    );

    // Nothing at all to analyse — no titles, so PART II is skipped entirely.
    let empty = super::analysis::Linkage::build(&[], &[]);
    assert!(empty.section_titles(&[]).is_empty());
}

// ─── Front matter ──────────────────────────────────────────────────────────

#[test]
fn entities_header_line_discloses_infra_excluded_gap() {
    // The bug: the header always printed the RAW `scan.entity_count`, even
    // though every section below renders the caller's infra-filtered list —
    // a scan with platform-infra entities showed a header count higher than
    // anything actually listed, with no explanation of the gap.
    assert_eq!(
        entities_header_line(42, 50),
        "  Entities:  42 (8 platform-infra excluded of 50 total — pass --include-infra to show)"
    );
}

#[test]
fn entities_header_line_is_plain_when_nothing_was_excluded() {
    assert_eq!(entities_header_line(50, 50), "  Entities:  50");
}

// ─── Shared helpers ────────────────────────────────────────────────────────

#[test]
fn truncation_note_discloses_the_hidden_count() {
    assert_eq!(truncation_note(8, 20), Some("  … 12 more".to_string()));
    assert_eq!(truncation_note(20, 20), None);
    assert_eq!(
        truncation_note(20, 5),
        None,
        "fewer than the cap: nothing hidden"
    );
}

// ─── Appendices ────────────────────────────────────────────────────────────

fn costs() -> HashMap<String, ModuleCost> {
    [
        ("shodan".to_string(), ModuleCost::Paid),
        ("hunter_io".to_string(), ModuleCost::KeyGated),
        ("search_engines".to_string(), ModuleCost::Free),
    ]
    .into_iter()
    .collect()
}

/// The whole point of this helper: a `KeyGated`/`Paid` module that ran and
/// found nothing must be reported, even though it is entirely absent from
/// `ScanDiagnostics::modules_by_yield` (built only from emitted entities).
#[test]
fn flags_a_zero_yield_keyed_or_paid_module() {
    let events = vec![Event::new(
        "s",
        EventKind::ModuleDone {
            module: "shodan".into(),
            found: 0,
        },
    )];
    assert_eq!(
        keyed_or_paid_zero_yield_modules(&events, &costs()),
        vec!["shodan".to_string()]
    );
}

/// A module that DID find something must not be flagged, however costly.
#[test]
fn ignores_a_module_that_found_something() {
    let events = vec![Event::new(
        "s",
        EventKind::ModuleDone {
            module: "shodan".into(),
            found: 3,
        },
    )];
    assert!(keyed_or_paid_zero_yield_modules(&events, &costs()).is_empty());
}

/// A free module that yields nothing is not a wasted spend — nothing to
/// warn about, so it must not appear.
#[test]
fn ignores_a_free_module_with_zero_yield() {
    let events = vec![Event::new(
        "s",
        EventKind::ModuleDone {
            module: "search_engines".into(),
            found: 0,
        },
    )];
    assert!(keyed_or_paid_zero_yield_modules(&events, &costs()).is_empty());
}

/// Output is sorted and deduped — deterministic regardless of event order
/// or a module appearing more than once (e.g. re-dispatched on expansion).
#[test]
fn output_is_sorted_and_deduped() {
    let mk = |m: &str| {
        Event::new(
            "s",
            EventKind::ModuleDone {
                module: m.into(),
                found: 0,
            },
        )
    };
    let events = vec![mk("shodan"), mk("hunter_io"), mk("shodan")];
    assert_eq!(
        keyed_or_paid_zero_yield_modules(&events, &costs()),
        vec!["hunter_io".to_string(), "shodan".to_string()]
    );
}

fn tenure(breach_count: usize) -> OnlineTenure {
    OnlineTenure {
        earliest_ts: 0,
        earliest_iso: "2008-01-01".into(),
        latest_ts: 100,
        latest_iso: "2025-01-01".into(),
        span_years: 17,
        event_count: 9,
        breach_count,
    }
}

fn recency(status: FootprintStatus) -> FootprintRecency {
    FootprintRecency {
        years_since_latest: 0,
        status,
    }
}

#[test]
fn tenure_headline_pluralises_breach_count() {
    assert_eq!(
        tenure_headline(&tenure(1), &recency(FootprintStatus::Active)),
        "Online since 2008-01-01 — 17y span, 1 breach exposure, footprint active"
    );
    assert_eq!(
        tenure_headline(&tenure(9), &recency(FootprintStatus::Dormant)),
        "Online since 2008-01-01 — 17y span, 9 breach exposures, footprint dormant"
    );
    assert_eq!(
        tenure_headline(&tenure(0), &recency(FootprintStatus::Recent)),
        "Online since 2008-01-01 — 17y span, 0 breach exposures, footprint recent"
    );
}

/// The whole point of this hint: every dispatched module ran and the scan
/// still yielded nothing at all — a near-certain misconfiguration/dead-
/// target signal, distinct from the normal "many modules found nothing
/// for this kind" case.
#[test]
fn total_dead_scan_hint_fires_when_modules_ran_and_found_nothing() {
    let hint = total_dead_scan_hint(&[], 12).expect("must fire");
    assert!(hint.contains("12"));
    assert!(hint.contains("scan-wide"));
}

/// Every candidate module was gate-skipped before dispatch (e.g. an
/// unsupported target kind) — a different, already-explained situation,
/// not "ran and found nothing". Must not fire.
#[test]
fn total_dead_scan_hint_is_silent_when_nothing_was_even_dispatched() {
    assert_eq!(total_dead_scan_hint(&[], 0), None);
}

/// A normal successful scan — must never fire regardless of module count.
#[test]
fn total_dead_scan_hint_is_silent_when_entities_were_found() {
    let entities = vec![Entity::new(EntityKind::Email, "a@b.com", 0.5, "s")];
    assert_eq!(total_dead_scan_hint(&entities, 12), None);
}
