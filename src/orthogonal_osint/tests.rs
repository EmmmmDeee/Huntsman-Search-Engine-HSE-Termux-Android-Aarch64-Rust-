//! The classification snapshot: what each source classifier says about every known source ID.
//!
//! `correlator::source_family` and [`acquisition_modality`] both classify a provenance source ID,
//! from match arms and, for an ID neither names, substring rules. Each ID that a collector
//! constant, a registry row, a classifier arm or a saved-attribution arm names, and probes of the
//! substring rules and normalisation, are held to the class each classifier gave them when the
//! snapshot was taken. A refactor that routes the classifiers elsewhere must leave every row as
//! it is; a deliberate change rewrites its rows.

use std::fmt::Write as _;

use super::acquisition_modality;
use crate::correlator::source_family;

const SNAPSHOT: &str = include_str!("../../tests/fixtures/source_classification.tsv");

/// Each snapshot row as `(id, family, modality)`; a missing column reads as empty.
fn rows() -> Vec<(&'static str, &'static str, &'static str)> {
    SNAPSHOT
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let mut fields = line.split('\t');
            let id = fields.next().unwrap_or_default();
            let family = fields.next().unwrap_or_default();
            let modality = fields.next().unwrap_or_default();
            assert!(
                fields.next().is_none(),
                "{line:?} has more than three columns"
            );
            (id, family, modality)
        })
        .collect()
}

#[test]
fn every_known_source_keeps_its_classification() {
    let rows = rows();
    assert!(
        rows.len() >= 200,
        "the snapshot holds only {} rows",
        rows.len()
    );
    let mut wrong = Vec::new();
    let mut found = String::new();
    for (id, family, modality) in &rows {
        let now = (source_family(id), acquisition_modality(id));
        writeln!(found, "{id}\t{}\t{}", now.0, now.1).expect("a String takes a write");
        if now != (*family, *modality) {
            wrong.push(format!(
                "  {id:?}: {family}/{modality} is now {}/{}",
                now.0, now.1
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} rows changed class:\n{}\nThe rows as this run found them:\n{found}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
}

#[test]
fn the_snapshot_names_each_id_once() {
    let mut ids: Vec<&str> = rows().into_iter().map(|(id, _, _)| id).collect();
    let all = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), all, "an ID is listed twice");
}
