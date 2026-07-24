//! The dossier's table of contents, decided before a single line is printed.
//!
//! The renderer used to be a straight `println!` cascade in which every
//! section decided for itself, mid-print, whether it had anything to say. That
//! is fine for a section but useless for a *document*: nothing could state up
//! front what the dossier contained, and nothing could be tested short of
//! capturing stdout.
//!
//! So presence is now a decision, made once, here. [`Plan`] is built from the
//! data, the CONTENTS index is rendered from the plan, and the body is
//! rendered from the same plan — which is what makes the index trustworthy: a
//! section listed in it is always printed, and a section printed is always
//! listed. Neither can drift, because neither is consulted twice.

/// The dossier's back matter, in fixed presentation order.
///
/// Letters are NOT part of the identity — they are assigned at render time by
/// [`letter_appendices`] to the appendices actually present, so they are
/// always contiguous from A. An operator who reads "Appendix D" must be able
/// to find an Appendix D; a gap in the sequence reads as a lost page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Appendix {
    /// Identifiers in this scan that also appear in earlier investigations.
    CrossScanLeverage,
    /// What ran, what it cost, and what it yielded.
    Collection,
    /// Locations, precision, and convergence.
    Geo,
    /// Dated events and movement between fixes.
    Timeline,
    /// The source chain behind each enriched finding.
    Lineage,
    /// Actionable tuning advice for the next run.
    Hints,
}

impl Appendix {
    /// Every appendix, in the order they are presented. Presence is filtered
    /// out of this list, never reordered — the back matter of two dossiers for
    /// different subjects reads the same way round.
    pub(super) const ORDER: &'static [Self] = &[
        Self::CrossScanLeverage,
        Self::Collection,
        Self::Geo,
        Self::Timeline,
        Self::Lineage,
        Self::Hints,
    ];

    /// The appendix heading, used identically in the CONTENTS index and in the
    /// body's `━━━ APPENDIX X — … ━━━` divider, so the two cannot disagree.
    pub(super) fn title(self) -> &'static str {
        match self {
            Self::CrossScanLeverage => "CROSS-SCAN LEVERAGE",
            Self::Collection => "COLLECTION DIAGNOSTICS",
            Self::Geo => "GEO INTELLIGENCE",
            Self::Timeline => "TIMELINE & MOVEMENT",
            Self::Lineage => "ENRICHMENT LINEAGE",
            Self::Hints => "OPTIMISATION HINTS",
        }
    }
}

/// Assign contiguous letters `A`, `B`, `C`… to the appendices that are
/// actually present, preserving [`Appendix::ORDER`].
///
/// Absent appendices consume no letter: reserving one would leave a hole in
/// the sequence, and a reader who cannot find "Appendix C" has no way to tell
/// a section that was omitted from a section that was lost. Pure.
///
/// `ORDER` is a six-entry constant, so the letter can never run past `Z`;
/// [`super::tests`] pins that, since the arithmetic below silently assumes it.
pub(super) fn letter_appendices(present: &[Appendix]) -> Vec<(char, Appendix)> {
    Appendix::ORDER
        .iter()
        .filter(|a| present.contains(a))
        .enumerate()
        .map(|(i, a)| (char::from(b'A' + u8::try_from(i).unwrap_or(25)), *a))
        .collect()
}

/// What this particular dossier contains: the optional analysis sections that
/// have data, and the appendices that have data, with the letters they will be
/// printed under.
pub(super) struct Plan {
    /// Titles of the PART II sections with something to show, in print order.
    pub(super) analysis: Vec<&'static str>,
    /// The present appendices, already lettered.
    pub(super) appendices: Vec<(char, Appendix)>,
}

impl Plan {
    pub(super) fn new(analysis: Vec<&'static str>, present: &[Appendix]) -> Self {
        Self {
            analysis,
            appendices: letter_appendices(present),
        }
    }

    /// The letter an appendix will print under, or `None` if this dossier does
    /// not carry it. The body asks the plan rather than tracking a counter of
    /// its own — one source of truth for the lettering.
    pub(super) fn letter(&self, appendix: Appendix) -> Option<char> {
        self.appendices
            .iter()
            .find(|(_, a)| *a == appendix)
            .map(|(l, _)| *l)
    }
}

/// `""` or `"s"` — so counted nouns in the index read as English.
fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// The CONTENTS index: what the reader will find below, and nothing else.
///
/// Built from the same [`Plan`] the body renders from, which is the whole
/// point — the index cannot promise a section the dossier does not contain,
/// nor omit one it does. Pure, so that property is testable without capturing
/// stdout.
pub(super) fn contents_lines(kinds: usize, findings: usize, plan: &Plan) -> Vec<String> {
    let mut lines = Vec::with_capacity(2 + plan.appendices.len());
    lines.push(format!(
        "  PART I      Findings by entity type — {kinds} kind{}, {findings} finding{}",
        plural(kinds),
        plural(findings)
    ));
    if !plan.analysis.is_empty() {
        lines.push(format!(
            "  PART II     Analysis — {}",
            plan.analysis.join(", ")
        ));
    }
    for (letter, appendix) in &plan.appendices {
        lines.push(format!("  APPENDIX {letter}  {}", appendix.title()));
    }
    lines
}
