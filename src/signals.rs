//! Small pure signal helpers rebuilt from the legacy tree.

use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

#[must_use]
pub(crate) fn record_tag(raw: &str) -> Option<(String, &str)> {
    let tag = raw.trim();
    let (name, value) = tag.split_once('=')?;
    let name = name.trim();
    (!name.is_empty()).then(|| (name.to_ascii_lowercase(), value.trim()))
}

#[must_use]
pub fn fingerprint(prefix: &str, key: &str, short_max: usize, head: usize, tail: usize) -> String {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return format!("{prefix}:(no key)");
    }
    if trimmed.len() <= short_max {
        return format!("{prefix}:{trimmed}");
    }
    let head_part: String = trimmed.chars().take(head).collect();
    let mut tail_chars: Vec<char> = trimmed.chars().rev().take(tail).collect();
    tail_chars.reverse();
    let tail_part: String = tail_chars.into_iter().collect();
    format!("{prefix}:{head_part}\u{2026}{tail_part}")
}

static COMMON_SURNAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
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
        "white",
        "harris",
        "miller",
        "davis",
        "nguyen",
        "patel",
        "o'connor",
        "obrien",
        "oneill",
        "oconnor",
        "griffiths",
        "cox",
        "chapman",
        "lloyd",
        "owen",
        "hamilton",
        "kim",
        "park",
        "singh",
        "kaur",
        "khan",
        "ali",
        "ahmed",
        "garcia",
        "rodriguez",
    ]
    .into_iter()
    .collect()
});

#[must_use]
pub fn surname_of(full_name: &str) -> Option<String> {
    full_name
        .split_whitespace()
        .next_back()
        .map(str::to_lowercase)
}

#[must_use]
pub fn is_common_surname(surname: &str) -> bool {
    let key = surname
        .trim()
        .to_lowercase()
        .replace(['\'', '\u{2019}'], "");
    COMMON_SURNAMES.contains(key.as_str())
        || COMMON_SURNAMES.contains(surname.trim().to_ascii_lowercase().as_str())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimAnonymity {
    PrepaidMvno,
    VoipVirtual,
}

impl SimAnonymity {
    #[must_use]
    pub fn score(self) -> f64 {
        match self {
            Self::PrepaidMvno => 0.55,
            Self::VoipVirtual => 0.80,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::PrepaidMvno => "prepaid MVNO (weak identity assurance)",
            Self::VoipVirtual => "VoIP/virtual number (minimal identity assurance)",
        }
    }

    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::PrepaidMvno => "sim-mvno-prepaid",
            Self::VoipVirtual => "sim-voip",
        }
    }
}

pub const ANONYMITY_TAGS: &[&str] = &["sim-mvno-prepaid", "sim-voip"];

#[must_use]
pub fn tier_for_tag(tag: &str) -> Option<SimAnonymity> {
    match tag {
        "sim-mvno-prepaid" => Some(SimAnonymity::PrepaidMvno),
        "sim-voip" => Some(SimAnonymity::VoipVirtual),
        _ => None,
    }
}

const VOIP_VIRTUAL: &[&str] = &[
    "textnow",
    "textfree",
    "google voice",
    "google-voice",
    "googlevoice",
    "voip",
    "twilio",
    "bandwidth",
    "skype",
    "sideline",
    "talkatone",
    "magicjack",
    "telnyx",
    "vonage",
    "freedompop",
    "burner",
    "hushed",
    "openphone",
    "dialpad",
    "ringcentral",
];
const PREPAID_MVNO: &[&str] = &[
    "aldi",
    "boost",
    "kogan",
    "circles",
    "lebara",
    "lyca",
    "amaysim",
    "felix",
    "moose",
    "belong",
    "mint mobile",
    "cricket",
    "metropcs",
    "tracfone",
    "giffgaff",
    "tesco mobile",
    "smarty",
];

#[must_use]
pub fn classify_carrier(network: &str) -> Option<SimAnonymity> {
    let lower = network.to_ascii_lowercase();
    if VOIP_VIRTUAL.iter().any(|needle| lower.contains(needle)) {
        Some(SimAnonymity::VoipVirtual)
    } else if PREPAID_MVNO.iter().any(|needle| lower.contains(needle)) {
        Some(SimAnonymity::PrepaidMvno)
    } else {
        None
    }
}

#[must_use]
pub fn is_meaningful_tag(tag: &str) -> bool {
    let len = tag.len();
    (3..=32).contains(&len)
        && tag
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
        && tag.chars().filter(char::is_ascii_alphabetic).count() * 2 >= len
        && !tag.contains(['/', '\\', ':', '|', '=', '(', ')'])
        && !tag.to_ascii_lowercase().contains("hash")
        && tag.split_whitespace().count() <= 4
}

#[must_use]
pub fn top_n<'a>(items: impl Iterator<Item = &'a str>, n: usize) -> String {
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for item in items {
        *counts.entry(item).or_insert(0) += 1;
    }
    let mut ranked: Vec<(&str, u32)> = counts.into_iter().collect();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    ranked.truncate(n);
    ranked
        .iter()
        .map(|(key, count)| format!("{key}\u{00d7}{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[must_use]
pub fn detection_strength(body_verified: bool) -> (f64, bool) {
    if body_verified {
        (0.92, true)
    } else {
        (0.74, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_fingerprints_and_surnames_work() {
        assert_eq!(fingerprint("svc", "  abc123  ", 12, 8, 4), "svc:abc123");
        assert_eq!(
            fingerprint("svc", "0123456789abcdef", 12, 8, 4),
            "svc:01234567…cdef"
        );
        assert_eq!(
            surname_of("Grace O\u{2019}Connor").as_deref(),
            Some("o’connor")
        );
        assert!(is_common_surname("O'Connor"));
        assert!(!is_common_surname("Diegmann"));
    }

    #[test]
    fn sim_and_threat_helpers_are_conservative() {
        assert_eq!(
            classify_carrier("Google Voice"),
            Some(SimAnonymity::VoipVirtual)
        );
        assert_eq!(
            classify_carrier("ALDI Mobile"),
            Some(SimAnonymity::PrepaidMvno)
        );
        assert_eq!(classify_carrier("Telstra"), None);
        assert_eq!(
            tier_for_tag(SimAnonymity::VoipVirtual.tag()),
            Some(SimAnonymity::VoipVirtual)
        );
        assert!(is_meaningful_tag("phishing kit"));
        assert!(!is_meaningful_tag("path/traversal"));
    }

    #[test]
    fn freq_and_probe_strength_are_stable() {
        let values = ["a", "b", "a", "c", "b", "a"];
        assert_eq!(top_n(values.iter().copied(), 3), "a×3, b×2, c×1");
        assert_eq!(detection_strength(true), (0.92, true));
        assert_eq!(detection_strength(false), (0.74, false));
    }

    #[test]
    fn record_tag_parser_normalises_name_and_trims_value() {
        assert_eq!(record_tag(" Pct = 75 "), Some(("pct".to_string(), "75")));
        assert_eq!(record_tag("missing"), None);
    }
}
