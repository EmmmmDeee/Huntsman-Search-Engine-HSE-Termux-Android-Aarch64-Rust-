//! Shared ccTLD → country (+ locale code) lookup — the single source of
//! truth `modules::email_header_geo` and `modules::email_locale` both draw
//! from, so the same objective fact ("this ccTLD belongs to this country")
//! can't drift into two different spellings, or two different countries
//! being recognised, across the two independently-maintained call sites that
//! used to hand-carry their own copy.
//!
//! Keyed on the bare, lowercase two-letter TLD — no leading dot.

/// `(tld, country_name, locale_code)`. The union of every ccTLD either of
/// the two consuming modules recognised before this table existed; no
/// entry here narrows either module's prior coverage.
pub const CCTLD_COUNTRY: &[(&str, &str, &str)] = &[
    ("de", "Germany", "de"),
    ("fr", "France", "fr"),
    ("it", "Italy", "it"),
    ("es", "Spain", "es"),
    ("nl", "Netherlands", "nl"),
    ("pl", "Poland", "pl"),
    ("ru", "Russia", "ru"),
    ("ua", "Ukraine", "ua"),
    ("se", "Sweden", "se"),
    ("no", "Norway", "no"),
    ("dk", "Denmark", "dk"),
    ("fi", "Finland", "fi"),
    ("pt", "Portugal", "pt"),
    ("ro", "Romania", "ro"),
    ("cz", "Czech Republic", "cz"),
    ("sk", "Slovakia", "sk"),
    ("hu", "Hungary", "hu"),
    ("at", "Austria", "at"),
    ("be", "Belgium", "be"),
    ("ch", "Switzerland", "ch"),
    ("gr", "Greece", "el"),
    ("tr", "Turkey", "tr"),
    ("jp", "Japan", "ja"),
    ("cn", "China", "zh"),
    ("kr", "South Korea", "ko"),
    ("in", "India", "hi"),
    ("au", "Australia", "en-au"),
    ("nz", "New Zealand", "en-nz"),
    ("za", "South Africa", "af"),
    ("br", "Brazil", "pt-br"),
    ("mx", "Mexico", "es-mx"),
    ("ar", "Argentina", "es-ar"),
    ("uk", "United Kingdom", "en-gb"),
    ("sg", "Singapore", "en-sg"),
    ("my", "Malaysia", "ms"),
    ("ca", "Canada", "en-ca"),
];

/// Look up a bare, lowercase ccTLD's `(country_name, locale_code)`. `None`
/// for an unrecognised or non-geographic TLD (`.io`, `.ai`, `.co`, …).
#[must_use]
pub fn country_for(tld: &str) -> Option<(&'static str, &'static str)> {
    CCTLD_COUNTRY
        .iter()
        .find(|(t, _, _)| *t == tld)
        .map(|&(_, country, locale)| (country, locale))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_geographic_tld_resolves() {
        assert_eq!(country_for("de"), Some(("Germany", "de")));
        assert_eq!(country_for("au"), Some(("Australia", "en-au")));
    }

    #[test]
    fn unknown_or_generic_tld_yields_none() {
        assert_eq!(country_for("io"), None);
        assert_eq!(country_for("com"), None);
        assert_eq!(country_for(""), None);
    }

    #[test]
    fn every_entry_is_a_lowercase_bare_tld_with_no_duplicates() {
        for &(tld, _, _) in CCTLD_COUNTRY {
            assert!(
                !tld.is_empty() && !tld.contains('.') && tld == tld.to_ascii_lowercase(),
                "{tld:?} must be a bare lowercase TLD"
            );
        }
        let mut seen = std::collections::HashSet::new();
        for &(tld, _, _) in CCTLD_COUNTRY {
            assert!(seen.insert(tld), "duplicate ccTLD entry: {tld:?}");
        }
    }
}
