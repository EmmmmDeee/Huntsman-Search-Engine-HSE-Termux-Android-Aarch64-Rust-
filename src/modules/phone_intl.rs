//! Offline international phone-number parser.
//!
//! Closes the `TargetKind::Phone` coverage gap. Splits a phone string
//! into its E.164 country-code prefix and national number, looks up
//! the country in an embedded table, and emits one Phone entity tagged
//! with the country / region. No network calls — this is purely a
//! syntactic and lookup step that runs in < 1 ms.
//!
//! Not a full libphonenumber replacement: doesn't validate the
//! national-number length against per-country rules, doesn't detect
//! carriers, doesn't know about mobile-vs-landline. For OSINT
//! triage it's enough — "is this number plausible, and which country
//! does it belong to" answers most pre-scan questions.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "phone_intl";

pub struct PhoneIntl;

/// (E.164 country-code prefix, ISO 3166-1 alpha-2, English name).
/// Sorted longest-prefix-first so 1-242 (Bahamas) matches before 1
/// (NANP, USA/Canada). Only the entries with unambiguous country
/// boundaries are listed — the NANP shares +1 across 25+ countries,
/// so a bare +1 maps to "NANP (US/CA)" and the caller is expected to
/// add a regex disambiguator for finer detail later.
const COUNTRIES: &[(&str, &str, &str)] = &[
    // Multi-digit codes first (longest-prefix-first).
    ("1242", "BS", "Bahamas"),
    ("1246", "BB", "Barbados"),
    ("1264", "AI", "Anguilla"),
    ("1268", "AG", "Antigua and Barbuda"),
    ("1284", "VG", "British Virgin Islands"),
    ("1340", "VI", "US Virgin Islands"),
    ("1345", "KY", "Cayman Islands"),
    ("1441", "BM", "Bermuda"),
    ("1473", "GD", "Grenada"),
    ("1649", "TC", "Turks and Caicos"),
    ("1664", "MS", "Montserrat"),
    ("1670", "MP", "Northern Mariana Islands"),
    ("1671", "GU", "Guam"),
    ("1684", "AS", "American Samoa"),
    ("1721", "SX", "Sint Maarten"),
    ("1758", "LC", "Saint Lucia"),
    ("1767", "DM", "Dominica"),
    ("1784", "VC", "Saint Vincent and the Grenadines"),
    ("1787", "PR", "Puerto Rico"),
    ("1809", "DO", "Dominican Republic"),
    ("1829", "DO", "Dominican Republic"),
    ("1849", "DO", "Dominican Republic"),
    ("1868", "TT", "Trinidad and Tobago"),
    ("1869", "KN", "Saint Kitts and Nevis"),
    ("1876", "JM", "Jamaica"),
    ("1939", "PR", "Puerto Rico"),
    // Three-digit codes
    ("212", "MA", "Morocco"),
    ("213", "DZ", "Algeria"),
    ("216", "TN", "Tunisia"),
    ("218", "LY", "Libya"),
    ("220", "GM", "Gambia"),
    ("221", "SN", "Senegal"),
    ("222", "MR", "Mauritania"),
    ("223", "ML", "Mali"),
    ("224", "GN", "Guinea"),
    ("225", "CI", "Ivory Coast"),
    ("226", "BF", "Burkina Faso"),
    ("227", "NE", "Niger"),
    ("228", "TG", "Togo"),
    ("229", "BJ", "Benin"),
    ("230", "MU", "Mauritius"),
    ("231", "LR", "Liberia"),
    ("232", "SL", "Sierra Leone"),
    ("233", "GH", "Ghana"),
    ("234", "NG", "Nigeria"),
    ("235", "TD", "Chad"),
    ("236", "CF", "Central African Republic"),
    ("237", "CM", "Cameroon"),
    ("238", "CV", "Cape Verde"),
    ("239", "ST", "São Tomé and Príncipe"),
    ("240", "GQ", "Equatorial Guinea"),
    ("241", "GA", "Gabon"),
    ("242", "CG", "Republic of the Congo"),
    ("243", "CD", "Democratic Republic of the Congo"),
    ("244", "AO", "Angola"),
    ("245", "GW", "Guinea-Bissau"),
    ("248", "SC", "Seychelles"),
    ("249", "SD", "Sudan"),
    ("250", "RW", "Rwanda"),
    ("251", "ET", "Ethiopia"),
    ("252", "SO", "Somalia"),
    ("253", "DJ", "Djibouti"),
    ("254", "KE", "Kenya"),
    ("255", "TZ", "Tanzania"),
    ("256", "UG", "Uganda"),
    ("257", "BI", "Burundi"),
    ("258", "MZ", "Mozambique"),
    ("260", "ZM", "Zambia"),
    ("261", "MG", "Madagascar"),
    ("262", "RE", "Réunion / Mayotte"),
    ("263", "ZW", "Zimbabwe"),
    ("264", "NA", "Namibia"),
    ("265", "MW", "Malawi"),
    ("266", "LS", "Lesotho"),
    ("267", "BW", "Botswana"),
    ("268", "SZ", "Eswatini"),
    ("269", "KM", "Comoros"),
    ("290", "SH", "Saint Helena"),
    ("291", "ER", "Eritrea"),
    ("297", "AW", "Aruba"),
    ("298", "FO", "Faroe Islands"),
    ("299", "GL", "Greenland"),
    ("350", "GI", "Gibraltar"),
    ("351", "PT", "Portugal"),
    ("352", "LU", "Luxembourg"),
    ("353", "IE", "Ireland"),
    ("354", "IS", "Iceland"),
    ("355", "AL", "Albania"),
    ("356", "MT", "Malta"),
    ("357", "CY", "Cyprus"),
    ("358", "FI", "Finland"),
    ("359", "BG", "Bulgaria"),
    ("370", "LT", "Lithuania"),
    ("371", "LV", "Latvia"),
    ("372", "EE", "Estonia"),
    ("373", "MD", "Moldova"),
    ("374", "AM", "Armenia"),
    ("375", "BY", "Belarus"),
    ("376", "AD", "Andorra"),
    ("377", "MC", "Monaco"),
    ("378", "SM", "San Marino"),
    ("380", "UA", "Ukraine"),
    ("381", "RS", "Serbia"),
    ("382", "ME", "Montenegro"),
    ("383", "XK", "Kosovo"),
    ("385", "HR", "Croatia"),
    ("386", "SI", "Slovenia"),
    ("387", "BA", "Bosnia and Herzegovina"),
    ("389", "MK", "North Macedonia"),
    ("420", "CZ", "Czech Republic"),
    ("421", "SK", "Slovakia"),
    ("423", "LI", "Liechtenstein"),
    ("500", "FK", "Falkland Islands"),
    ("501", "BZ", "Belize"),
    ("502", "GT", "Guatemala"),
    ("503", "SV", "El Salvador"),
    ("504", "HN", "Honduras"),
    ("505", "NI", "Nicaragua"),
    ("506", "CR", "Costa Rica"),
    ("507", "PA", "Panama"),
    ("508", "PM", "Saint Pierre and Miquelon"),
    ("509", "HT", "Haiti"),
    ("590", "GP", "Guadeloupe"),
    ("591", "BO", "Bolivia"),
    ("592", "GY", "Guyana"),
    ("593", "EC", "Ecuador"),
    ("594", "GF", "French Guiana"),
    ("595", "PY", "Paraguay"),
    ("596", "MQ", "Martinique"),
    ("597", "SR", "Suriname"),
    ("598", "UY", "Uruguay"),
    ("599", "CW", "Curaçao"),
    ("670", "TL", "Timor-Leste"),
    ("672", "NF", "Norfolk Island"),
    ("673", "BN", "Brunei"),
    ("674", "NR", "Nauru"),
    ("675", "PG", "Papua New Guinea"),
    ("676", "TO", "Tonga"),
    ("677", "SB", "Solomon Islands"),
    ("678", "VU", "Vanuatu"),
    ("679", "FJ", "Fiji"),
    ("680", "PW", "Palau"),
    ("681", "WF", "Wallis and Futuna"),
    ("682", "CK", "Cook Islands"),
    ("683", "NU", "Niue"),
    ("685", "WS", "Samoa"),
    ("686", "KI", "Kiribati"),
    ("687", "NC", "New Caledonia"),
    ("688", "TV", "Tuvalu"),
    ("689", "PF", "French Polynesia"),
    ("690", "TK", "Tokelau"),
    ("691", "FM", "Micronesia"),
    ("692", "MH", "Marshall Islands"),
    ("850", "KP", "North Korea"),
    ("852", "HK", "Hong Kong"),
    ("853", "MO", "Macau"),
    ("855", "KH", "Cambodia"),
    ("856", "LA", "Laos"),
    ("880", "BD", "Bangladesh"),
    ("886", "TW", "Taiwan"),
    ("960", "MV", "Maldives"),
    ("961", "LB", "Lebanon"),
    ("962", "JO", "Jordan"),
    ("963", "SY", "Syria"),
    ("964", "IQ", "Iraq"),
    ("965", "KW", "Kuwait"),
    ("966", "SA", "Saudi Arabia"),
    ("967", "YE", "Yemen"),
    ("968", "OM", "Oman"),
    ("970", "PS", "Palestine"),
    ("971", "AE", "United Arab Emirates"),
    ("972", "IL", "Israel"),
    ("973", "BH", "Bahrain"),
    ("974", "QA", "Qatar"),
    ("975", "BT", "Bhutan"),
    ("976", "MN", "Mongolia"),
    ("977", "NP", "Nepal"),
    ("992", "TJ", "Tajikistan"),
    ("993", "TM", "Turkmenistan"),
    ("994", "AZ", "Azerbaijan"),
    ("995", "GE", "Georgia"),
    ("996", "KG", "Kyrgyzstan"),
    ("998", "UZ", "Uzbekistan"),
    // Two-digit codes
    ("20", "EG", "Egypt"),
    ("27", "ZA", "South Africa"),
    ("30", "GR", "Greece"),
    ("31", "NL", "Netherlands"),
    ("32", "BE", "Belgium"),
    ("33", "FR", "France"),
    ("34", "ES", "Spain"),
    ("36", "HU", "Hungary"),
    ("39", "IT", "Italy"),
    ("40", "RO", "Romania"),
    ("41", "CH", "Switzerland"),
    ("43", "AT", "Austria"),
    ("44", "GB", "United Kingdom"),
    ("45", "DK", "Denmark"),
    ("46", "SE", "Sweden"),
    ("47", "NO", "Norway"),
    ("48", "PL", "Poland"),
    ("49", "DE", "Germany"),
    ("51", "PE", "Peru"),
    ("52", "MX", "Mexico"),
    ("53", "CU", "Cuba"),
    ("54", "AR", "Argentina"),
    ("55", "BR", "Brazil"),
    ("56", "CL", "Chile"),
    ("57", "CO", "Colombia"),
    ("58", "VE", "Venezuela"),
    ("60", "MY", "Malaysia"),
    ("61", "AU", "Australia"),
    ("62", "ID", "Indonesia"),
    ("63", "PH", "Philippines"),
    ("64", "NZ", "New Zealand"),
    ("65", "SG", "Singapore"),
    ("66", "TH", "Thailand"),
    ("81", "JP", "Japan"),
    ("82", "KR", "South Korea"),
    ("84", "VN", "Vietnam"),
    ("86", "CN", "China"),
    ("90", "TR", "Turkey"),
    ("91", "IN", "India"),
    ("92", "PK", "Pakistan"),
    ("93", "AF", "Afghanistan"),
    ("94", "LK", "Sri Lanka"),
    ("95", "MM", "Myanmar"),
    ("98", "IR", "Iran"),
    // Single-digit
    ("7", "RU", "Russia / Kazakhstan (NANP)"),
    ("1", "US", "NANP (US / Canada)"),
];

#[async_trait]
impl Module for PhoneIntl {
    fn name(&self) -> &'static str {
        "phone_intl"
    }

    fn description(&self) -> &'static str {
        "Offline phone number country and format analysis"
    }

    fn priority(&self) -> u8 {
        // Highest among Phone-accepting modules so it runs before any
        // future paid carrier-lookup modules — country code is the
        // gate for whether those should fire at all.
        140
    }

    fn is_passive(&self) -> bool {
        // Pure local computation — no network.
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Phone)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Phone
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Phone];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Country-code attribution requires an EXPLICIT international form (see
        // `international_digits`). Without it the leading digits are ambiguous,
        // and guessing fabricates a wrong country + a bogus "+E.164" number.
        let Some(digits) = international_digits(&target.value) else {
            return Ok(ModuleResult::new());
        };
        if digits.len() < 7 || digits.len() > 15 {
            // E.164 mandates 7–15 digits total (incl. country code).
            return Ok(ModuleResult::new());
        }

        let Some((prefix, iso, name)) = match_country(&digits) else {
            return Ok(ModuleResult::new());
        };

        let national = &digits[prefix.len()..];

        // Re-emit canonical E.164 form so downstream entities dedupe.
        let canonical = format!("+{digits}");
        let mut entity = Entity::new(EntityKind::Phone, &canonical, 0.85, &ctx.scan_id);
        entity.tag("e164");
        entity.tag(format!("country:{iso}"));
        entity.add_evidence(
            Evidence::new(SRC, format!("Phone {canonical} → {name}"))
                .with_attr("country_code", prefix)
                .with_attr("country_iso", iso)
                .with_attr("country_name", name)
                .with_attr("national_number", national)
                .with_attr("total_digits", digits.len().to_string()),
        );

        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

/// Reduce a phone string to its E.164 digit string (country code + national
/// number) **iff** it is written in an explicit international form: a leading
/// `+` (E.164) or the ITU `00` international-call prefix. Returns `None` for a
/// national or otherwise ambiguous number.
///
/// This gate is what keeps the country lookup honest. The leading digits of a
/// bare national number are indistinguishable from a country code — a US
/// national `202-555-0100` begins with `202`, which would otherwise match `20`
/// (Egypt) — so without an explicit marker any attribution is a guess. The old
/// code stripped the `+` and matched regardless, fabricating a wrong country
/// and a bogus `+2025550100` canonical at 0.85 confidence: a false GEOINT lead.
/// A national/ambiguous number is simply out of this offline parser's scope.
///
/// ```
/// use huntsman_search_engine::modules::phone_intl::international_digits;
///
/// assert_eq!(international_digits("+61 400 000 000").as_deref(), Some("61400000000"));
/// assert_eq!(international_digits("0061 400 000 000").as_deref(), Some("61400000000"));
/// assert_eq!(international_digits("202-555-0100"), None); // US national, no marker
/// ```
#[must_use]
pub fn international_digits(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let digits = crate::util::str_util::ascii_digits(raw);
    if raw.starts_with('+') {
        Some(digits)
    } else {
        // ITU '00' international-call prefix → strip it to expose the country
        // code. National trunk prefixes are a single '0', never '00', so this
        // never mistakes a national number for an international one.
        digits.strip_prefix("00").map(str::to_string)
    }
}

/// Longest-prefix match against `COUNTRIES`. Returns `(prefix, iso, name)`.
/// Resolve a digits-only international number to `(dialling_prefix, ISO, name)`
/// by longest-prefix-first match. `pub(crate)` so `geo_intel` reuses this single
/// source of truth instead of maintaining a second, divergent prefix table.
pub(crate) fn match_country(digits: &str) -> Option<(&'static str, &'static str, &'static str)> {
    COUNTRIES
        .iter()
        .find(|&&(prefix, ..)| digits.starts_with(prefix))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_phone() {
        let m = PhoneIntl;
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+1234567890")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x")));
    }

    #[test]
    fn longest_prefix_wins() {
        let (prefix, iso, _name) = match_country("18764567890").unwrap();
        assert_eq!(prefix, "1876");
        assert_eq!(iso, "JM");

        let (prefix, iso, _name) = match_country("12025550100").unwrap();
        assert_eq!(prefix, "1");
        assert_eq!(iso, "US");
    }

    #[test]
    fn international_codes() {
        assert_eq!(match_country("442071838750").unwrap().1, "GB");
        assert_eq!(match_country("61400000000").unwrap().1, "AU");
        assert_eq!(match_country("33123456789").unwrap().1, "FR");
        assert_eq!(match_country("861234567890").unwrap().1, "CN");
    }

    #[test]
    fn unknown_prefix() {
        assert!(match_country("000000000").is_none());
    }

    #[test]
    fn international_digits_requires_explicit_marker() {
        // Explicit '+' (E.164) → the country-code-leading digit string.
        assert_eq!(
            international_digits("+1 876 456 7890").as_deref(),
            Some("18764567890")
        );
        assert_eq!(
            international_digits(" +61 (4) 0000 0000 ").as_deref(),
            Some("61400000000")
        );
        // ITU '00' international-call prefix → stripped to expose the code.
        assert_eq!(
            international_digits("0061 400 000 000").as_deref(),
            Some("61400000000")
        );
        // No marker → None, even though the leading digits LOOK like a country
        // code. This is the regression: a US national number begins with an
        // area code (202, 415, 650 …) that the old all-digits match mis-read as
        // Egypt (+20), Switzerland (+41), Singapore (+65) and emitted a bogus
        // "+E.164" number. A national/ambiguous number must resolve to nothing.
        assert_eq!(international_digits("202-555-0100"), None);
        assert_eq!(international_digits("(415) 555-0100"), None);
        assert_eq!(international_digits("650 555 0100"), None);
        // A national trunk '0' is a single zero, not the '00' international
        // prefix, so it is correctly treated as national (no attribution).
        assert_eq!(international_digits("0400 000 000"), None);
    }

    #[test]
    fn country_table_is_well_formed_and_prefix_ordered() {
        // 1. Every entry is well-formed: a digit-only dialling prefix, a 2-letter
        //    uppercase ISO code, and a non-empty name.
        for (prefix, iso, name) in COUNTRIES {
            assert!(
                !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()),
                "bad dialling prefix {prefix:?} ({name})"
            );
            assert!(
                iso.len() == 2 && iso.bytes().all(|b| b.is_ascii_uppercase()),
                "bad ISO code {iso:?} ({name})"
            );
            assert!(!name.is_empty(), "empty country name for {iso}");
        }

        // 2. Longest-prefix-first ordering, table-wide. `match_country` returns the
        //    FIRST prefix that the number starts with, so when an earlier entry's
        //    prefix is a string-prefix of a later one's, that later country is
        //    unreachable — every one of its numbers resolves to the earlier code.
        //    The specific code must precede its generic stem (1876 Jamaica before
        //    1 US). Generalises the hand-picked `longest_prefix_wins` check to all
        //    229 entries and any future addition. (Also catches an exact-duplicate
        //    prefix, which `starts_with` flags.)
        let mut violations = Vec::new();
        for (i, (earlier, _, ename)) in COUNTRIES.iter().enumerate() {
            for (later, _, lname) in &COUNTRIES[i + 1..] {
                if later.starts_with(earlier) {
                    violations.push(format!(
                        "+{later} ({lname}) is shadowed by the earlier +{earlier} ({ename})"
                    ));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "phone-prefix ordering violated — move the specific code above its generic stem:\n  {}",
            violations.join("\n  ")
        );
    }
}
