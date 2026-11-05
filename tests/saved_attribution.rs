//! The attribution snapshot: the `(label, component)` pair each saved-lookup policy records for
//! every known source ID.
//!
//! A `lookup_save` policy credits each saved row to a label and a component, the Rust file that
//! produced it. For every source ID in the classification snapshot, and each side of every
//! policy, `tests/fixtures/saved_attribution.tsv` holds the pair the policy gives an unregistered
//! ID (its default) and each pair that differs from it. A refactor that derives the maps from
//! somewhere else must leave every pair as it is; a deliberate change rewrites its rows.

use huntsman_recon::lookup_save::{self, ProvenanceFn, SavePolicy};

/// The source IDs: the first column of the classification snapshot.
const IDS: &str = include_str!("fixtures/source_classification.tsv");
const SNAPSHOT: &str = include_str!("fixtures/saved_attribution.tsv");
/// An ID no policy names, so each policy's answer for it is that policy's default.
const PROBE: &str = "zz_unregistered_probe";

const POLICIES: [(&str, SavePolicy); 14] = [
    ("email", lookup_save::EMAIL_POLICY),
    ("username", lookup_save::USERNAME_POLICY),
    ("people", lookup_save::PEOPLE_POLICY),
    ("phone", lookup_save::PHONE_POLICY),
    ("exposure", lookup_save::EXPOSURE_POLICY),
    ("email_exposure", lookup_save::EMAIL_EXPOSURE_POLICY),
    ("username_exposure", lookup_save::USERNAME_EXPOSURE_POLICY),
    ("domain", lookup_save::DOMAIN_POLICY),
    ("ip", lookup_save::IP_POLICY),
    ("netblock", lookup_save::NETBLOCK_POLICY),
    ("asn", lookup_save::ASN_POLICY),
    ("network", lookup_save::NETWORK_POLICY),
    ("crypto", lookup_save::CRYPTO_POLICY),
    ("place", lookup_save::PLACE_POLICY),
];

fn data_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
}

fn ids() -> Vec<&'static str> {
    data_lines(IDS)
        .map(|line| line.split('\t').next().unwrap_or_default())
        .collect()
}

/// The snapshot as this build gives it: per policy and side, a `*` row with the default pair (a
/// `*` label is the ID itself), then a row for each ID whose pair differs from that default.
fn found() -> Vec<String> {
    let ids = ids();
    assert!(
        ids.contains(&PROBE),
        "the classification snapshot lost {PROBE}"
    );
    let mut rows = Vec::new();
    for (name, policy) in POLICIES {
        let sides: [(&str, ProvenanceFn); 2] = [
            ("outcome", policy.outcome_provenance),
            ("entity", policy.entity_provenance),
        ];
        for (side, credit) in sides {
            let (probe_label, default) = credit(PROBE);
            let relabels = probe_label != PROBE;
            let label_cell = if relabels { probe_label } else { "*" };
            rows.push(format!("{name}\t{side}\t*\t{label_cell}\t{default}"));
            for id in &ids {
                let (label, component) = credit(id);
                let expected_label = if relabels { probe_label } else { id };
                if (label, component) != (expected_label, default) {
                    rows.push(format!("{name}\t{side}\t{id}\t{label}\t{component}"));
                }
            }
        }
    }
    rows
}

#[test]
fn every_policy_keeps_its_attribution() {
    let expected: Vec<&str> = data_lines(SNAPSHOT).collect();
    let found = found();
    let missing: Vec<&&str> = expected
        .iter()
        .filter(|row| !found.iter().any(|f| f == **row))
        .collect();
    let added: Vec<&String> = found
        .iter()
        .filter(|row| !expected.contains(&row.as_str()))
        .collect();
    assert!(
        missing.is_empty() && added.is_empty(),
        "attribution changed.\nRows no longer given:\n{missing:#?}\nRows newly given:\n{added:#?}\n\
         The snapshot as this run found it:\n{}",
        found.join("\n")
    );
}
