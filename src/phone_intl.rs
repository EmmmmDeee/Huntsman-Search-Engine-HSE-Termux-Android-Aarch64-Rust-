//! Offline phone canonicalisation and international dialling-prefix lookup.
//!
//! The country table is ported from the legacy Huntsman `phone_intl` module.
//! This module performs no network I/O.

use crate::address_au;
use crate::textnorm;
use crate::validation::validate_phone_e164;

pub const COUNTRIES: &[(&str, &str, &str)] = &[
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
    ("1658", "JM", "Jamaica"),
    ("1876", "JM", "Jamaica"),
    ("1939", "PR", "Puerto Rico"),
    // The Caribbean Netherlands share +599 with Curaçao (+599 9).
    ("5993", "BQ", "Sint Eustatius"),
    ("5994", "BQ", "Saba"),
    ("5997", "BQ", "Bonaire"),
    // Three-digit codes
    ("211", "SS", "South Sudan"),
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
    ("246", "IO", "Diego Garcia"),
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
    // Kazakhstan shares +7 with Russia: its numbers are +7 6 and +7 7.
    ("76", "KZ", "Kazakhstan"),
    ("77", "KZ", "Kazakhstan"),
    // Single-digit
    ("7", "RU", "Russia"),
    ("1", "US", "NANP (US / Canada)"),
];

/// Longest-prefix country match.
#[must_use]
pub fn match_country(digits: &str) -> Option<(&'static str, &'static str, &'static str)> {
    COUNTRIES
        .iter()
        .find(|&&(prefix, ..)| digits.starts_with(prefix))
        .copied()
}

/// Canonicalise an explicit international number or a recognised Australian
/// national number to E.164.
///
/// This follows the current repository validation contract (10..=15 total
/// digits) and never guesses the country of a bare non-Australian number. A
/// number with digits after an extension marker (`x12`, `;ext=12`, `#12`) is
/// refused: dropping the marker would join the extension onto the number.
/// An Australian number keeps no trunk zero (`+61 (0)4…` is `+614…`).
#[must_use]
pub fn canonicalize(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if has_digits_after_a_marker(trimmed) {
        return None;
    }
    let candidate = if trimmed.starts_with('+') {
        textnorm::ascii_digits_and_plus(trimmed)
    } else if trimmed.starts_with("00") {
        let digits = textnorm::ascii_digits(trimmed);
        format!("+{}", digits.strip_prefix("00")?)
    } else {
        return address_au::normalise_phone(trimmed);
    };
    if candidate.starts_with("+61") {
        if let Some(australian) = address_au::normalise_phone(&candidate) {
            return Some(australian);
        }
    }
    validate_phone_e164(&candidate).valid.then_some(candidate)
}

/// Whether a letter, `#`, `;` or `,` stands between two of `raw`'s digits: an extension, a
/// dialling pause or a vanity word, after which the remaining digits are not the number's own.
/// A marker before the first digit (`tel:`) or words after the last (`(office)`) are not.
fn has_digits_after_a_marker(raw: &str) -> bool {
    let mut seen_digit = false;
    let mut marker = false;
    for character in raw.chars() {
        if character.is_ascii_digit() {
            if marker {
                return true;
            }
            seen_digit = true;
        } else if seen_digit && (character.is_alphabetic() || matches!(character, '#' | ';' | ','))
        {
            marker = true;
        }
    }
    false
}

/// Resolve a canonical E.164 number to country metadata.
#[must_use]
pub fn country_of(e164: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let digits = e164.strip_prefix('+')?;
    match_country(digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_number_is_australian_or_nothing_never_a_guessed_country() {
        // Without a `+` or `00` marker only the Australian national rule applies.
        assert_eq!(canonicalize("202-555-0100"), None);
        assert_eq!(
            canonicalize("0400 000 000").as_deref(),
            Some("+61400000000")
        );
    }

    #[test]
    fn an_australian_number_keeps_no_trunk_zero() {
        for raw in [
            "+61 (0)412 345 678",
            "0061 (0)412 345 678",
            "+61 412 345 678",
        ] {
            assert_eq!(canonicalize(raw).as_deref(), Some("+61412345678"), "{raw}");
        }
    }

    #[test]
    fn an_extension_is_refused_not_joined_onto_the_number() {
        for raw in [
            "+1 415 555 2671 x12",
            "+1 415 555 2671 ext. 12",
            "+1-415-555-2671;ext=12",
            "+1 415 555 2671 #12",
            "+1 415 555 2671,,12",
            "0044 20 7183 8750 x3",
            "+1 800 FLOWERS 1",
        ] {
            assert_eq!(canonicalize(raw), None, "{raw}");
        }
        assert_eq!(
            canonicalize("+44 20 7183 8750 (office)").as_deref(),
            Some("+442071838750")
        );
    }

    #[test]
    fn current_itu_assignments_resolve_to_their_country() {
        for (digits, country) in [
            ("211912345678", "SS"),
            ("16581234567", "JM"),
            ("77011234567", "KZ"),
            ("76151234567", "KZ"),
            ("74951234567", "RU"),
            ("5997171234", "BQ"),
            ("5993181234", "BQ"),
            ("5999461234", "CW"),
            ("2463801234", "IO"),
        ] {
            assert_eq!(
                match_country(digits).map(|row| row.1),
                Some(country),
                "{digits}"
            );
        }
        assert_eq!(match_country("74951234567").unwrap().2, "Russia");
    }

    #[test]
    fn longest_prefix_wins() {
        assert_eq!(match_country("18764567890").unwrap().1, "JM");
        assert_eq!(match_country("12025550100").unwrap().1, "US");
        assert_eq!(match_country("61400000000").unwrap().1, "AU");
        assert_eq!(match_country("442071838750").unwrap().1, "GB");
    }

    #[test]
    fn canonicalizes_international_and_au_local() {
        assert_eq!(
            canonicalize("+1 (415) 555-2671").as_deref(),
            Some("+14155552671")
        );
        assert_eq!(
            canonicalize("0061 412 345 678").as_deref(),
            Some("+61412345678")
        );
        assert_eq!(
            canonicalize("0412 345 678").as_deref(),
            Some("+61412345678")
        );
        assert!(canonicalize("415 555 2671").is_none());
    }

    #[test]
    fn country_table_is_prefix_safe() {
        for (index, (earlier, _, _)) in COUNTRIES.iter().enumerate() {
            for (later, _, _) in &COUNTRIES[index + 1..] {
                assert!(
                    !later.starts_with(earlier),
                    "{later} is shadowed by earlier {earlier}"
                );
            }
        }
    }
}
