//! Dossier renderer for `hse scan --output dossier`.
//!
//! The dossier is a document, not a log, and it is organised like one:
//!
//! ```text
//!   front matter   subject, scan accounting, exposure index   (frontmatter)
//!   CONTENTS       what this dossier actually contains        (plan)
//!   PART I         findings, grouped by entity type           (findings)
//!   PART II        what the findings mean together            (analysis)
//!   APPENDIX A…    the supporting material                    (appendix)
//! ```
//!
//! The ordering is the argument. A reader wants the findings first, the
//! analysis drawn from them second, and the collection/geo/timeline/lineage
//! material behind both — those answer "how do I trust this and what do I run
//! next", which is a question you only have once you have read the findings.
//! The renderer previously interleaved all three, so operator-facing intel and
//! run diagnostics arrived in whatever order the code happened to be written.
//!
//! Presence is decided once, before anything prints (see [`plan`]), which is
//! what lets the CONTENTS index exist at all: it and the body are rendered from
//! the same [`plan::Plan`], so the index can neither promise a section the
//! dossier lacks nor omit one it carries.

mod analysis;
mod appendix;
mod findings;
mod frontmatter;
mod plan;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use crate::core::{correlator::Correlation, entity::Entity, relation::Relation, scan::Scan};

use plan::{Appendix, Plan};

/// Bundled args for [`print_dossier`] — a plain struct rather than 8 loose
/// parameters (`clippy::too_many_arguments`), mirroring the `DispatchCx`/
/// `DispatchState` precedent (`PROBLEM_TREE` T2.5) rather than an `#[allow]`.
pub(super) struct DossierArgs<'a> {
    pub(super) scan: &'a Scan,
    pub(super) entities: &'a [Entity],
    pub(super) correlations: &'a [Correlation],
    pub(super) relations: &'a [Relation],
    pub(super) kind: &'a str,
    pub(super) value: &'a str,
    pub(super) leverage: &'a [crate::core::engine::LeverageRanked],
    pub(super) store: &'a dyn crate::core::port::StoragePort,
}

/// The trailing "… N more" disclosure for a ranked list truncated to `shown`
/// of `total` — `None` when the full list already fits.
///
/// Every capped list in the dossier routes through this. A section that
/// truncates without saying so reads as a complete answer, which is the one
/// thing an intelligence document must never do. Pure.
fn truncation_note(shown: usize, total: usize) -> Option<String> {
    (total > shown).then(|| format!("  … {} more", total - shown))
}

/// Resolves a relation-endpoint UID to a display label against the visible
/// entity set.
///
/// Five sections used to each build their own `by_uid` map and their own
/// near-identical closure, differing only in truncation width and whether the
/// kind was appended — five chances for one uid to render five ways, and five
/// allocations over the same slice. The unresolvable-uid fallback is delegated
/// to [`crate::cli::relation_endpoint_label`], whose whole purpose is to be the
/// single place that stub is spelled; four of those closures had quietly grown
/// their own copy of it.
struct Labeller<'a> {
    by_uid: HashMap<&'a str, &'a Entity>,
}

impl<'a> Labeller<'a> {
    fn new(entities: &'a [Entity]) -> Self {
        Self {
            by_uid: entities.iter().map(|e| (e.uid.as_str(), e)).collect(),
        }
    }

    /// Just the value, truncated to `width`.
    fn value(&self, uid: &str, width: usize) -> String {
        crate::app::export::relation_endpoint_label(&self.by_uid, uid, |e| {
            crate::cli::truncate(&e.value, width)
        })
    }

    /// `value (kind)` — for lists of bare identifiers with no other column to
    /// carry the kind.
    fn with_kind(&self, uid: &str, width: usize) -> String {
        crate::app::export::relation_endpoint_label(&self.by_uid, uid, |e| {
            format!("{} ({})", crate::cli::truncate(&e.value, width), e.kind)
        })
    }

    /// Value and kind separately, for callers that place them independently.
    /// An unresolvable uid's kind is `?` — never guessed.
    fn parts(&self, uid: &str, width: usize) -> (String, String) {
        self.by_uid.get(uid).map_or_else(
            || (self.value(uid, width), "?".to_string()),
            |e| (crate::cli::truncate(&e.value, width), e.kind.to_string()),
        )
    }
}

/// Which appendices this dossier carries. Order is fixed by
/// [`Appendix::ORDER`]; this only decides membership.
fn present_appendices(has_bridges: bool, collection: &appendix::Collection) -> Vec<Appendix> {
    let mut present = Vec::new();
    if has_bridges {
        present.push(Appendix::CrossScanLeverage);
    }
    // Collection, geo and timeline are unconditional: each states its own zero
    // ("0 coordinates", "no dated events"). Dropping them when empty would
    // leave the operator unable to tell "assessed and found nothing" from
    // "never assessed" — for a geo or timeline question, those are very
    // different answers.
    present.push(Appendix::Collection);
    present.push(Appendix::Geo);
    present.push(Appendix::Timeline);
    if collection.has_lineage() {
        present.push(Appendix::Lineage);
    }
    if collection.has_hints() {
        present.push(Appendix::Hints);
    }
    present
}

pub(super) fn print_dossier(args: DossierArgs<'_>) {
    let DossierArgs {
        scan,
        entities,
        correlations,
        relations,
        kind,
        value,
        leverage,
        store,
    } = args;

    // Everything the document's structure depends on, computed before a line is
    // printed — the CONTENTS index cannot be written after the body it indexes.
    let by_kind = findings::group_by_kind(entities);
    let linkage = analysis::Linkage::build(entities, relations);
    let collection = appendix::Collection::build(scan, entities, kind, value, &scan.id, store);
    let bridges: Vec<&crate::core::engine::LeverageRanked> = leverage
        .iter()
        .filter(|l| l.cross_scan_degree >= 2)
        .collect();

    let plan = Plan::new(
        linkage.section_titles(correlations),
        &present_appendices(!bridges.is_empty(), &collection),
    );

    frontmatter::print(scan, entities, correlations, kind, value);

    println!("━━━ CONTENTS ━━━");
    println!();
    for line in plan::contents_lines(by_kind.len(), entities.len(), &plan) {
        println!("{line}");
    }
    println!();

    findings::print(&by_kind, plan.letter(Appendix::Hints));

    if !plan.analysis.is_empty() {
        linkage.print(correlations, &Labeller::new(entities));
    }

    for (letter, section) in &plan.appendices {
        println!("━━━ APPENDIX {letter} — {} ━━━", section.title());
        println!();
        match section {
            Appendix::CrossScanLeverage => appendix::print_cross_scan_leverage(&bridges),
            Appendix::Collection => collection.print_collection(),
            Appendix::Geo => collection.print_geo(entities),
            Appendix::Timeline => appendix::print_timeline(scan, entities),
            Appendix::Lineage => collection.print_lineage(),
            Appendix::Hints => collection.print_hints(),
        }
    }

    println!("━━━ END OF DOSSIER ━━━");
}
