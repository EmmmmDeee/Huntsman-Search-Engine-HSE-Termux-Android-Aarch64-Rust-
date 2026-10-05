//! SIM anonymity classification — a deterministic, offline heuristic mapping a
//! phone's HLR/CNAM carrier (network) name to an anonymity tier.
//!
//! A phone is only as strong an identity anchor as the SIM behind it: a number on
//! a major postpaid account is tightly bound to a real person, while a VoIP /
//! virtual number or an anonymity-friendly prepaid MVNO can be obtained with an
//! email and little or no government ID. Surfacing that distinction tells the
//! recursive linker how much attribution weight a phone-based connection deserves
//! — and flags a likely burner tied to a subject. Applied by `hlr_cnam` to the
//! carrier it resolves; read back by the AU-068 correlator rule via the tier tags
//! (one classifier, no drift).
//!
//! Heuristic and deliberately conservative: an HLR lookup of an MVNO often returns
//! its HOST network, masking it, so this classifies only the anonymity-relevant
//! tiers from distinctive carrier names and returns `None` for an unknown or major
//! identity-linked carrier rather than guess.
//!
//! (Merged from the `hse_modules` `sim_classify` prototype — the algorithm and
//! curated carrier intelligence, re-expressed natively over the engine's types.)

/// The anonymity tier of the SIM / number behind a phone, by how hard the number
/// is to attribute to a real identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimAnonymity {
    /// Prepaid MVNO — light, often online-only ID; resold network capacity.
    PrepaidMvno,
    /// VoIP / virtual number — email signup, minimal or no identity assurance.
    VoipVirtual,
}

impl SimAnonymity {
    /// Anonymity score in `[0,1]` — higher means harder to attribute.
    pub fn score(self) -> f64 {
        match self {
            Self::PrepaidMvno => 0.55,
            Self::VoipVirtual => 0.80,
        }
    }

    /// Human label for evidence and findings.
    pub fn label(self) -> &'static str {
        match self {
            Self::PrepaidMvno => "prepaid MVNO (weak identity assurance)",
            Self::VoipVirtual => "VoIP/virtual number (minimal identity assurance)",
        }
    }

    /// The stable entity tag a phone of this tier carries — the cross-module
    /// contract between `hlr_cnam` (which sets it) and AU-068 (which reads it).
    pub fn tag(self) -> &'static str {
        match self {
            Self::PrepaidMvno => "sim-mvno-prepaid",
            Self::VoipVirtual => "sim-voip",
        }
    }
}

/// Every tier tag, for the correlator rule that surfaces an anonymous SIM.
pub const ANONYMITY_TAGS: &[&str] = &["sim-mvno-prepaid", "sim-voip"];

/// Recover the tier from one of its [`SimAnonymity::tag`] strings (the inverse of
/// `tag`), so a reader (AU-068) can render the label from an entity's tag alone.
pub fn tier_for_tag(tag: &str) -> Option<SimAnonymity> {
    match tag {
        "sim-mvno-prepaid" => Some(SimAnonymity::PrepaidMvno),
        "sim-voip" => Some(SimAnonymity::VoipVirtual),
        _ => None,
    }
}

/// Classify a phone's anonymity tier from its HLR/CNAM carrier (network) name.
/// Deterministic, offline substring match over a curated table; `None` when the
/// carrier is unknown or a major identity-linked network — i.e. no anonymity
/// signal, never a guess.
pub fn classify_carrier(network: &str) -> Option<SimAnonymity> {
    let n = network.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|x| n.contains(x));
    // VoIP / virtual first — the strongest, most distinctly-named tier.
    if has(VOIP_VIRTUAL) {
        Some(SimAnonymity::VoipVirtual)
    } else if has(PREPAID_MVNO) {
        Some(SimAnonymity::PrepaidMvno)
    } else {
        None
    }
}

/// VoIP / virtual-number providers — email-signup numbers with minimal identity
/// assurance. Distinctly named, so substring matching is reliable.
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
    "pinger",
    "sideline",
    "talkatone",
    "magicjack",
    "telnyx",
    "plivo",
    "vonage",
    "freedompop",
    "ring4",
    "burner",
    "hushed",
    "grasshopper",
    "openphone",
    "dialpad",
    "ringcentral",
    "8x8",
    "ooma",
    "nextiva",
    "line2",
    "2ndline",
    "numbrix",
    "flyp",
    "vumber",
    "callcentric",
    "sipgate",
    "rebtel",
];

/// Anonymity-friendly prepaid MVNOs (AU-focused, plus common US resellers) —
/// light or online-only ID. Matched only when the HLR returns the MVNO's own name.
const PREPAID_MVNO: &[&str] = &[
    // AU
    "aldi",
    "boost",
    "kogan",
    "circles",
    "lebara",
    "lyca",
    "amaysim",
    "felix",
    "moose",
    "catch connect",
    "tangerine",
    "belong",
    "spintel",
    "dodo",
    "woolworths mobile",
    "coles mobile",
    "vaya",
    "ovo mobile",
    "numobile",
    "live connected",
    "hello mobile",
    // US
    "mint mobile",
    "cricket",
    "metropcs",
    "metro by",
    "tracfone",
    "straight talk",
    "simple mobile",
    "total wireless",
    "us mobile",
    "consumer cellular",
    "republic wireless",
    "ting",
    "h2o wireless",
    "net10",
    "pageplus",
    "red pocket",
    "twigby",
    "visible",
    // UK
    "giffgaff",
    "tesco mobile",
    "id mobile",
    "smarty",
    "voxi",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_voip_and_mvno_conservatively() {
        assert_eq!(classify_carrier("TextNow"), Some(SimAnonymity::VoipVirtual));
        assert_eq!(
            classify_carrier("Google Voice"),
            Some(SimAnonymity::VoipVirtual)
        );
        assert_eq!(
            classify_carrier("ALDI Mobile"),
            Some(SimAnonymity::PrepaidMvno)
        );
        assert_eq!(
            classify_carrier("Boost Mobile"),
            Some(SimAnonymity::PrepaidMvno)
        );
        // Carriers whose redundant table entries were removed still classify via
        // the subsuming needle ("lyca"/"lebara"/"boost") or the VoIP table.
        assert_eq!(
            classify_carrier("Lycamobile"),
            Some(SimAnonymity::PrepaidMvno)
        );
        assert_eq!(
            classify_carrier("Lebara UK"),
            Some(SimAnonymity::PrepaidMvno)
        );
        assert_eq!(
            classify_carrier("FreedomPop"),
            Some(SimAnonymity::VoipVirtual)
        );
        // Major identity-linked carriers and unknowns are deliberately unclassified.
        assert_eq!(classify_carrier("Telstra"), None);
        assert_eq!(classify_carrier("Verizon Wireless"), None);
        assert_eq!(classify_carrier(""), None);
    }

    #[test]
    fn tag_round_trips_and_scores_rank() {
        for t in [SimAnonymity::PrepaidMvno, SimAnonymity::VoipVirtual] {
            assert_eq!(tier_for_tag(t.tag()), Some(t));
            assert!(ANONYMITY_TAGS.contains(&t.tag()));
        }
        assert_eq!(tier_for_tag("hlr-verified"), None);
        // VoIP is harder to attribute than an MVNO.
        assert!(SimAnonymity::VoipVirtual.score() > SimAnonymity::PrepaidMvno.score());
    }
}
