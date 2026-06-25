//! `util::surnames` — offline surname-distinctiveness heuristic.
//!
//! The free family-linking chain rests on a SHARED SURNAME between the subject
//! and a candidate, but not every shared surname carries equal evidential weight:
//! two people named "Diegmann" in the same area are almost certainly kin (a rare
//! name), while two "Smith"s may be perfect strangers (a very common one). This is
//! the free, offline distinctiveness signal that lets the leads ranking treat a
//! shared *rare* surname as corroborating — surfacing a rare-surname subject's real
//! family higher and shielding it from over-eager namesake demotion — and a shared
//! *common* one with caution, so a common-surname subject isn't buried under
//! coincidental matches.
//!
//! No data feed, no network: just a small embedded table of the most common
//! English / Australian family names. Pure and dependency-free (a leaf util with
//! no upward deps), so the heuristic is deterministic and cheap on a Termux device.

use std::collections::HashSet;
use std::sync::LazyLock;

/// The most common English / Australian family names (lowercased). A shared-surname
/// match on one of these is weak evidence of kinship: there are simply too many
/// unrelated bearers for "same surname" to mean much on its own. Conservative on
/// purpose — only genuinely high-frequency names — so a merely *uncommon* surname
/// still counts as the strong, distinctive signal it is.
static COMMON_SURNAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        // Top English / Australian surnames.
        "smith",
        "jones",
        "williams",
        "brown",
        "taylor",
        "davies",
        "wilson",
        "evans",
        "thomas",
        "johnson",
        "roberts",
        "walker",
        "robinson",
        "thompson",
        "white",
        "watson",
        "jackson",
        "wright",
        "green",
        "harris",
        "cooper",
        "king",
        "lee",
        "martin",
        "clarke",
        "clark",
        "james",
        "morgan",
        "hughes",
        "edwards",
        "hill",
        "moore",
        "harrison",
        "scott",
        "young",
        "morris",
        "hall",
        "ward",
        "turner",
        "carter",
        "phillips",
        "mitchell",
        "patel",
        "adams",
        "campbell",
        "anderson",
        "allen",
        "cook",
        "bailey",
        "parker",
        "miller",
        "davis",
        "murphy",
        "kelly",
        "ryan",
        "sullivan",
        "byrne",
        "oconnor",
        "connor",
        "murray",
        "walsh",
        "kennedy",
        "lewis",
        "wood",
        "baker",
        "price",
        "gray",
        "bennett",
        "stewart",
        "robertson",
        "marshall",
        "simpson",
        "graham",
        "collins",
        "bell",
        "shaw",
        "mason",
        "knight",
        "russell",
        "fisher",
        "butler",
        "barnes",
        "henderson",
        "holmes",
        "wells",
        "webb",
        "hunt",
        "stevens",
        "richardson",
        "palmer",
        "rose",
        "reid",
        "ross",
        "watts",
        "barker",
        "gibson",
        "ellis",
        "fraser",
        "grant",
        // Further top-~100 English / Welsh / Scottish names (as common as, or more
        // common than, several already listed) — their absence let AU-051/AU-061
        // assert a "distinctive shared surname → Critical kin" on a name that is in
        // fact commonplace (two Griffiths / Coxes in one metro are not evident kin).
        "griffiths",
        "cox",
        "chapman",
        "reynolds",
        "lloyd",
        "harvey",
        "owen",
        "owens",
        "fox",
        "griffin",
        "johnston",
        "hamilton",
        "wallace",
        "fletcher",
        "pearson",
        // Common migrant surnames in AU.
        "nguyen",
        "tran",
        "le",
        "pham",
        "wong",
        "chan",
        "li",
        "wang",
        "zhang",
        "liu",
        "chen",
        "yang",
        "huang",
        "kim",
        "park",
        "singh",
        "kaur",
        "khan",
        "ali",
        "ahmed",
        "hussain",
        "kumar",
        "sharma",
        "gupta",
        "lin",
        "ng",
        // Common Celtic / Italian / Greek / Hispanic AU surnames.
        "obrien",
        "oneill",
        "mccarthy",
        "doyle",
        "gallagher",
        "russo",
        "romano",
        "ferrari",
        "esposito",
        "rossi",
        "bruno",
        "marino",
        "papadopoulos",
        "garcia",
        "rodriguez",
        "martinez",
        "lopez",
        "gonzalez",
    ]
    .into_iter()
    .collect()
});

/// The surname token of a full name — the last whitespace-separated word, folded
/// to lowercase. `None` for an empty / whitespace-only name. Mirrors the relation
/// layer's surname extraction (last token) so "who shares a surname" is judged the
/// same way the kinship edges were built.
#[must_use]
pub fn surname_of(full_name: &str) -> Option<String> {
    full_name
        .split_whitespace()
        .next_back()
        .map(str::to_lowercase)
}

/// True if `surname` is among the most common English / Australian family names —
/// so a bare shared-surname match on it is weak evidence of kinship and should be
/// corroborated by another angle. Case-insensitive; surrounding whitespace ignored.
#[must_use]
pub fn is_common(surname: &str) -> bool {
    let key = surname.trim().to_lowercase();
    COMMON_SURNAMES.contains(key.as_str())
}

#[cfg(test)]
mod tests;
