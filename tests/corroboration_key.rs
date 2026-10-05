//! `Entity::source_count` and `Entity::corroborating_sources` count families derived
//! from each record's `provenance.source`, never the stored `provenance.source_family`,
//! which is loaded from saved data (Security low finding on #684).

use std::collections::BTreeSet;

use huntsman_recon::confidence::{Classification, VERIFIED_MIN, effective};
use huntsman_recon::correlator::{RuleContext, rule_au_003_high_corroboration};
use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use huntsman_recon::roi::is_saturated;

fn honest(collector: &str) -> Evidence {
    Evidence::new(EvidenceProvenance::new(collector), "breach record").with_attr("breach", "Adobe")
}

/// An entity as a saved record would reload it: built honestly, serialised, the
/// stored `source_family` of each listed record overwritten (`""` removes it), and
/// deserialised without going through `add_evidence`.
fn reloaded(collectors: &[&str], stored: &[(usize, &str)]) -> Entity {
    reloaded_at(0.5, collectors, stored)
}

fn reloaded_at(confidence: f64, collectors: &[&str], stored: &[(usize, &str)]) -> Entity {
    let mut entity = Entity::new(EntityKind::Email, "jane@example.com", confidence, "scan-1");
    for collector in collectors {
        entity.add_evidence(honest(collector));
    }
    let mut json = serde_json::to_value(&entity).unwrap();
    for (index, family) in stored {
        let provenance = json["evidence"][*index]["provenance"]
            .as_object_mut()
            .unwrap();
        if family.is_empty() {
            provenance.remove("source_family");
        } else {
            provenance.insert("source_family".into(), (*family).into());
        }
    }
    let entity: Entity = serde_json::from_value(json).unwrap();
    for (index, family) in stored {
        assert_eq!(entity.evidence[*index].provenance.source_family, *family);
    }
    entity
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn tampered_stored_family_cannot_inflate_source_count() {
    for (label, collectors, stored) in [
        (
            "second row claims another corpus",
            &["hibp", "hibp"][..],
            &[(1, "spoof-corpus")][..],
        ),
        (
            "second row claims registry class",
            &["hibp", "hibp"],
            &[(1, "abn_lookup")],
        ),
        (
            "three rows, three invented families",
            &["hibp", "hibp", "hibp"],
            &[(0, "a"), (1, "b"), (2, "c")],
        ),
    ] {
        let entity = reloaded(collectors, stored);
        assert_eq!(entity.source_count(), 1, "{label}");
        assert_eq!(entity.corroborating_sources(), set(&["hibp"]), "{label}");
    }
}

#[test]
fn tampered_stored_family_cannot_merge_distinct_collectors() {
    // The other direction: a stored family copied from another collector does not
    // collapse two real collectors into one.
    let entity = reloaded(&["hibp", "dehashed"], &[(1, "hibp")]);
    assert_eq!(entity.source_count(), 2);
    assert_eq!(entity.corroborating_sources(), set(&["dehashed", "hibp"]));
}

/// Pinned, not changed: a saved record with no stored family counts under its raw
/// `source`, as on main and in legacy 7dca720, so `HIBP` and `hibp` stay two sources.
/// Folding them into one is a count change legacy does not make; it is left for
/// Chief's decision.
#[test]
fn empty_stored_family_keeps_counting_the_raw_source() {
    let entity = reloaded(&["HIBP", "hibp"], &[(0, "")]);
    assert_eq!(entity.source_count(), 2);
    assert_eq!(entity.corroborating_sources(), set(&["HIBP", "hibp"]));

    let same = reloaded(&["hibp", "hibp"], &[(0, "")]);
    assert_eq!(same.source_count(), 1);
    assert_eq!(same.corroborating_sources(), set(&["hibp"]));
}

#[test]
fn honest_records_count_as_before() {
    for (collectors, count, sources) in [
        (&["hibp"][..], 1, &["hibp"][..]),
        (&["hibp", "hibp"], 1, &["hibp"]),
        (&["hibp", "dehashed"], 2, &["dehashed", "hibp"]),
        (
            &["hibp", "dehashed", "abn_lookup"],
            3,
            &["abn_lookup", "dehashed", "hibp"],
        ),
        (&["hibp", "HIBP"], 1, &["hibp"]),
        (
            &["hibp", "leakcheck", "oathnet", "snusbase"],
            4,
            &["hibp", "leakcheck", "oathnet", "snusbase"],
        ),
    ] {
        let entity = reloaded(collectors, &[]);
        assert_eq!(entity.source_count(), count, "{collectors:?}");
        assert_eq!(
            entity.corroborating_sources(),
            set(sources),
            "{collectors:?}"
        );
    }
}

fn au_003_fires(entity: &Entity) -> bool {
    let entities = [entity.clone()];
    !rule_au_003_high_corroboration(&RuleContext::new(&entities, &[]), "scan-1", 0).is_empty()
}

/// On main a spoofed second family lifted `source_count` from 1 to 2. With two sources
/// `effective` is `1 - 0.65 * (1 - c)`, which crosses `VERIFIED_MIN` (0.75) and fires
/// AU-003 from confidence 0.6154 (`1 - 0.25/0.65`) up; one source stays Probable below
/// 0.75. The edges are pinned by the two band-edge tests below.
#[test]
fn tampered_family_cannot_lift_probable_to_verified_or_fire_au_003() {
    for confidence in [0.65, 0.70, 0.74] {
        let spoofed = reloaded_at(confidence, &["hibp", "hibp"], &[(1, "spoof-corpus")]);
        assert_eq!(
            spoofed.classify(),
            Classification::Probable,
            "c={confidence}"
        );
        assert!(!au_003_fires(&spoofed), "AU-003 fired at c={confidence}");

        // Control: two real collectors at the same confidence do reach Verified + AU-003.
        let real = reloaded_at(confidence, &["hibp", "dehashed"], &[]);
        assert_eq!(real.classify(), Classification::Verified, "c={confidence}");
        assert!(au_003_fires(&real), "control c={confidence}");
    }
}

/// Lower edge of the band: at confidence 0.62 two sources give `effective` 0.753, so on
/// main the spoofed entity was Verified and fired AU-003. It must stay Probable here
/// while two real collectors still reach Verified.
#[test]
fn band_lower_edge_spoofed_family_stays_probable_at_0_62() {
    assert!(effective(0.62, 2) >= VERIFIED_MIN);
    assert!(effective(0.62, 1) < VERIFIED_MIN);

    let spoofed = reloaded_at(0.62, &["hibp", "hibp"], &[(1, "spoof-corpus")]);
    assert_eq!(spoofed.source_count(), 1);
    assert_eq!(spoofed.classify(), Classification::Probable);
    assert!(!au_003_fires(&spoofed), "AU-003 fired at c=0.62");

    let real = reloaded_at(0.62, &["hibp", "dehashed"], &[]);
    assert_eq!(real.classify(), Classification::Verified);
    assert!(au_003_fires(&real), "control c=0.62");
}

/// Just under the edge (0.6154): at 0.615 two sources give `effective` 0.74975, so the
/// spoofed entity and even two real collectors stay Probable and AU-003 does not fire.
#[test]
fn just_under_band_edge_stays_probable() {
    assert!(effective(0.6154, 2) >= VERIFIED_MIN);
    assert!(effective(0.6153, 2) < VERIFIED_MIN);

    for (collectors, stored) in [
        (&["hibp", "hibp"][..], &[(1, "spoof-corpus")][..]),
        (&["hibp", "dehashed"], &[]),
    ] {
        let entity = reloaded_at(0.615, collectors, stored);
        assert_eq!(
            entity.classify(),
            Classification::Probable,
            "{collectors:?}"
        );
        assert!(
            !au_003_fires(&entity),
            "AU-003 fired for {collectors:?} at c=0.615"
        );
    }
}

/// On main a spoofed second family met `SATURATION_CORROBORATION` (2) and, from
/// confidence 0.7692 (`1 - 0.15/0.65`; tested at 0.85), marked the entity saturated.
#[test]
fn tampered_family_cannot_mark_an_entity_saturated() {
    let spoofed = reloaded_at(0.85, &["hibp", "hibp"], &[(1, "spoof-corpus")]);
    assert_eq!(spoofed.source_count(), 1);
    assert!(!is_saturated(&spoofed));

    let real = reloaded_at(0.85, &["hibp", "dehashed"], &[]);
    assert!(is_saturated(&real), "control");
}
