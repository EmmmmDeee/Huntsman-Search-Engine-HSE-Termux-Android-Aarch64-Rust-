//! Country names, as Spiderfoot's `sfp_countryname` finds them in a scan's data.
//!
//! A phone number's dialling code, a domain's country-code TLD (and, as Spiderfoot reads them,
//! `.com`, `.net`, `.org`, `.gov` and `.mil` as the United States), an IBAN's first two letters,
//! and the country names written in a WHOIS record, a place or an address each name a country.
//! The names are Spiderfoot's own (`SpiderFootHelpers.countryCodes`), so its correlation rules
//! and anything written against its exports see the same strings.
//!
//! Three things Spiderfoot means to do and does not, done here: a country name at the very start
//! or end of the text counts (Spiderfoot's pattern needs a delimiter on both sides, so it never
//! finds the country that ends a place such as `Sydney, New South Wales, Australia`); a closing
//! bracket ends a name as an opening one starts it (`(France)`); and the value after `Country:`
//! is read whole (Spiderfoot's lazy `(.+?)` captures one character, so it never matched).

use crate::phone_intl;

/// Spiderfoot's table of country codes and names, in its order.
const COUNTRIES: [(&str, &str); 256] = [
    ("AF", "Afghanistan"),
    ("AX", "Aland Islands"),
    ("AL", "Albania"),
    ("DZ", "Algeria"),
    ("AS", "American Samoa"),
    ("AD", "Andorra"),
    ("AO", "Angola"),
    ("AI", "Anguilla"),
    ("AQ", "Antarctica"),
    ("AG", "Antigua and Barbuda"),
    ("AR", "Argentina"),
    ("AM", "Armenia"),
    ("AW", "Aruba"),
    ("AU", "Australia"),
    ("AT", "Austria"),
    ("AZ", "Azerbaijan"),
    ("BS", "Bahamas"),
    ("BH", "Bahrain"),
    ("BD", "Bangladesh"),
    ("BB", "Barbados"),
    ("BY", "Belarus"),
    ("BE", "Belgium"),
    ("BZ", "Belize"),
    ("BJ", "Benin"),
    ("BM", "Bermuda"),
    ("BT", "Bhutan"),
    ("BO", "Bolivia"),
    ("BQ", "Bonaire, Saint Eustatius and Saba"),
    ("BA", "Bosnia and Herzegovina"),
    ("BW", "Botswana"),
    ("BV", "Bouvet Island"),
    ("BR", "Brazil"),
    ("IO", "British Indian Ocean Territory"),
    ("VG", "British Virgin Islands"),
    ("BN", "Brunei"),
    ("BG", "Bulgaria"),
    ("BF", "Burkina Faso"),
    ("BI", "Burundi"),
    ("KH", "Cambodia"),
    ("CM", "Cameroon"),
    ("CA", "Canada"),
    ("CV", "Cape Verde"),
    ("KY", "Cayman Islands"),
    ("CF", "Central African Republic"),
    ("TD", "Chad"),
    ("CL", "Chile"),
    ("CN", "China"),
    ("CX", "Christmas Island"),
    ("CC", "Cocos Islands"),
    ("CO", "Colombia"),
    ("KM", "Comoros"),
    ("CK", "Cook Islands"),
    ("CR", "Costa Rica"),
    ("HR", "Croatia"),
    ("CU", "Cuba"),
    ("CW", "Curacao"),
    ("CY", "Cyprus"),
    ("CZ", "Czech Republic"),
    ("CD", "Democratic Republic of the Congo"),
    ("DK", "Denmark"),
    ("DJ", "Djibouti"),
    ("DM", "Dominica"),
    ("DO", "Dominican Republic"),
    ("TL", "East Timor"),
    ("EC", "Ecuador"),
    ("EG", "Egypt"),
    ("SV", "El Salvador"),
    ("GQ", "Equatorial Guinea"),
    ("ER", "Eritrea"),
    ("EE", "Estonia"),
    ("ET", "Ethiopia"),
    ("FK", "Falkland Islands"),
    ("FO", "Faroe Islands"),
    ("FJ", "Fiji"),
    ("FI", "Finland"),
    ("FR", "France"),
    ("GF", "French Guiana"),
    ("PF", "French Polynesia"),
    ("TF", "French Southern Territories"),
    ("GA", "Gabon"),
    ("GM", "Gambia"),
    ("GE", "Georgia"),
    ("DE", "Germany"),
    ("GH", "Ghana"),
    ("GI", "Gibraltar"),
    ("GR", "Greece"),
    ("GL", "Greenland"),
    ("GD", "Grenada"),
    ("GP", "Guadeloupe"),
    ("GU", "Guam"),
    ("GT", "Guatemala"),
    ("GG", "Guernsey"),
    ("GN", "Guinea"),
    ("GW", "Guinea-Bissau"),
    ("GY", "Guyana"),
    ("HT", "Haiti"),
    ("HM", "Heard Island and McDonald Islands"),
    ("HN", "Honduras"),
    ("HK", "Hong Kong"),
    ("HU", "Hungary"),
    ("IS", "Iceland"),
    ("IN", "India"),
    ("ID", "Indonesia"),
    ("IR", "Iran"),
    ("IQ", "Iraq"),
    ("IE", "Ireland"),
    ("IM", "Isle of Man"),
    ("IL", "Israel"),
    ("IT", "Italy"),
    ("CI", "Ivory Coast"),
    ("JM", "Jamaica"),
    ("JP", "Japan"),
    ("JE", "Jersey"),
    ("JO", "Jordan"),
    ("KZ", "Kazakhstan"),
    ("KE", "Kenya"),
    ("KI", "Kiribati"),
    ("XK", "Kosovo"),
    ("KW", "Kuwait"),
    ("KG", "Kyrgyzstan"),
    ("LA", "Laos"),
    ("LV", "Latvia"),
    ("LB", "Lebanon"),
    ("LS", "Lesotho"),
    ("LR", "Liberia"),
    ("LY", "Libya"),
    ("LI", "Liechtenstein"),
    ("LT", "Lithuania"),
    ("LU", "Luxembourg"),
    ("MO", "Macao"),
    ("MK", "Macedonia"),
    ("MG", "Madagascar"),
    ("MW", "Malawi"),
    ("MY", "Malaysia"),
    ("MV", "Maldives"),
    ("ML", "Mali"),
    ("MT", "Malta"),
    ("MH", "Marshall Islands"),
    ("MQ", "Martinique"),
    ("MR", "Mauritania"),
    ("MU", "Mauritius"),
    ("YT", "Mayotte"),
    ("MX", "Mexico"),
    ("FM", "Micronesia"),
    ("MD", "Moldova"),
    ("MC", "Monaco"),
    ("MN", "Mongolia"),
    ("ME", "Montenegro"),
    ("MS", "Montserrat"),
    ("MA", "Morocco"),
    ("MZ", "Mozambique"),
    ("MM", "Myanmar"),
    ("NA", "Namibia"),
    ("NR", "Nauru"),
    ("NP", "Nepal"),
    ("NL", "Netherlands"),
    ("AN", "Netherlands Antilles"),
    ("NC", "New Caledonia"),
    ("NZ", "New Zealand"),
    ("NI", "Nicaragua"),
    ("NE", "Niger"),
    ("NG", "Nigeria"),
    ("NU", "Niue"),
    ("NF", "Norfolk Island"),
    ("KP", "North Korea"),
    ("MP", "Northern Mariana Islands"),
    ("NO", "Norway"),
    ("OM", "Oman"),
    ("PK", "Pakistan"),
    ("PW", "Palau"),
    ("PS", "Palestinian Territory"),
    ("PA", "Panama"),
    ("PG", "Papua New Guinea"),
    ("PY", "Paraguay"),
    ("PE", "Peru"),
    ("PH", "Philippines"),
    ("PN", "Pitcairn"),
    ("PL", "Poland"),
    ("PT", "Portugal"),
    ("PR", "Puerto Rico"),
    ("QA", "Qatar"),
    ("CG", "Republic of the Congo"),
    ("RE", "Reunion"),
    ("RO", "Romania"),
    ("RU", "Russia"),
    ("RW", "Rwanda"),
    ("BL", "Saint Barthelemy"),
    ("SH", "Saint Helena"),
    ("KN", "Saint Kitts and Nevis"),
    ("LC", "Saint Lucia"),
    ("MF", "Saint Martin"),
    ("PM", "Saint Pierre and Miquelon"),
    ("VC", "Saint Vincent and the Grenadines"),
    ("WS", "Samoa"),
    ("SM", "San Marino"),
    ("ST", "Sao Tome and Principe"),
    ("SA", "Saudi Arabia"),
    ("SN", "Senegal"),
    ("RS", "Serbia"),
    ("CS", "Serbia and Montenegro"),
    ("SC", "Seychelles"),
    ("SL", "Sierra Leone"),
    ("SG", "Singapore"),
    ("SX", "Sint Maarten"),
    ("SK", "Slovakia"),
    ("SI", "Slovenia"),
    ("SB", "Solomon Islands"),
    ("SO", "Somalia"),
    ("ZA", "South Africa"),
    ("GS", "South Georgia and the South Sandwich Islands"),
    ("KR", "South Korea"),
    ("SS", "South Sudan"),
    ("ES", "Spain"),
    ("LK", "Sri Lanka"),
    ("SD", "Sudan"),
    ("SR", "Suriname"),
    ("SJ", "Svalbard and Jan Mayen"),
    ("SZ", "Swaziland"),
    ("SE", "Sweden"),
    ("CH", "Switzerland"),
    ("SY", "Syria"),
    ("TW", "Taiwan"),
    ("TJ", "Tajikistan"),
    ("TZ", "Tanzania"),
    ("TH", "Thailand"),
    ("TG", "Togo"),
    ("TK", "Tokelau"),
    ("TO", "Tonga"),
    ("TT", "Trinidad and Tobago"),
    ("TN", "Tunisia"),
    ("TR", "Turkey"),
    ("TM", "Turkmenistan"),
    ("TC", "Turks and Caicos Islands"),
    ("TV", "Tuvalu"),
    ("VI", "U.S. Virgin Islands"),
    ("UG", "Uganda"),
    ("UA", "Ukraine"),
    ("AE", "United Arab Emirates"),
    ("GB", "United Kingdom"),
    ("US", "United States"),
    ("UM", "United States Minor Outlying Islands"),
    ("UY", "Uruguay"),
    ("UZ", "Uzbekistan"),
    ("VU", "Vanuatu"),
    ("VA", "Vatican"),
    ("VE", "Venezuela"),
    ("VN", "Vietnam"),
    ("WF", "Wallis and Futuna"),
    ("EH", "Western Sahara"),
    ("YE", "Yemen"),
    ("ZM", "Zambia"),
    ("ZW", "Zimbabwe"),
    ("AC", "Ascension Island"),
    ("EU", "European Union"),
    ("SU", "Soviet Union"),
    ("UK", "United Kingdom"),
];

/// TLDs no country owns that Spiderfoot reads as the United States.
const GENERIC_TLDS: [&str; 5] = ["COM", "NET", "ORG", "GOV", "MIL"];

/// The country Spiderfoot names for a two-letter code, in any case.
#[must_use]
pub fn from_code(code: &str) -> Option<&'static str> {
    let code = code.trim();
    COUNTRIES
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(code))
        .map(|&(_, name)| name)
}

/// The country one domain label names: a country-code TLD, or a generic TLD Spiderfoot reads as
/// the United States.
#[must_use]
pub fn from_tld(label: &str) -> Option<&'static str> {
    from_code(label).or_else(|| {
        GENERIC_TLDS
            .iter()
            .any(|tld| tld.eq_ignore_ascii_case(label.trim()))
            .then_some("United States")
    })
}

/// The country of a domain: its labels read from the right, the first that names one, as
/// Spiderfoot reads them (so `example.com.au` is Australia).
#[must_use]
pub fn from_domain(domain: &str) -> Option<&'static str> {
    domain
        .trim()
        .trim_end_matches('.')
        .rsplit('.')
        .find_map(from_tld)
}

/// The country of a phone number's dialling code. A number without its country code (other than
/// an Australian one, which the phone lookups accept) names none.
#[must_use]
pub fn from_phone(number: &str) -> Option<&'static str> {
    let canonical = phone_intl::canonicalize(number)?;
    let (_, iso, _) = phone_intl::country_of(&canonical)?;
    from_code(iso)
}

/// The country of an IBAN: its first two letters.
#[must_use]
pub fn from_iban(iban: &str) -> Option<&'static str> {
    from_code(iban.trim().get(..2)?)
}

/// What may stand around a country name in text: Spiderfoot's pattern's characters, with the
/// closing brackets its pattern lists as a second `[` and leaves out.
fn delimiter(c: char) -> bool {
    matches!(
        c,
        ',' | '\'' | '"' | ':' | '=' | '[' | ']' | '(' | ')' | '\n' | '\t' | '\r' | '.'
    )
}

/// Whether `name` appears in `text` as Spiderfoot looks for it: without regard to case, with a
/// delimiter (or the start of the text), then perhaps one space, before it, and a delimiter (or
/// the end of the text) after it. A name inside a longer one (`Jersey` in `New Jersey`, `Niger`
/// in `Nigeria`) does not count.
fn written_in(text: &str, name: &str) -> bool {
    let lower = text.to_lowercase();
    let wanted = name.to_lowercase();
    let mut from = 0;
    while let Some(found) = lower[from..].find(&wanted) {
        let start = from + found;
        let end = start + wanted.len();
        let mut before = lower[..start].chars().rev();
        let opened = match before.next() {
            None => true,
            Some(' ') => before.next().is_none_or(delimiter),
            Some(c) => delimiter(c),
        };
        let closed = lower[end..].chars().next().is_none_or(delimiter);
        if opened && closed {
            return true;
        }
        from = start + wanted.chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// The countries named in free text such as a WHOIS record, a place or an address, each once, in
/// Spiderfoot's table order: every country name written in it, then the code or name after a
/// `Country:` (`Registrant Country: AU`) on any line.
#[must_use]
pub fn in_text(text: &str) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    for &(_, name) in &COUNTRIES {
        if !found.contains(&name) && written_in(text, name) {
            found.push(name);
        }
    }
    for line in text.lines() {
        let Some(at) = line.to_ascii_lowercase().find("country:") else {
            continue;
        };
        let value = line[at + "country:".len()..].trim();
        let named = from_code(value).or_else(|| {
            COUNTRIES
                .iter()
                .map(|&(_, name)| name)
                .find(|name| name.eq_ignore_ascii_case(value))
        });
        if let Some(name) = named {
            if !found.contains(&name) {
                found.push(name);
            }
        }
    }
    found
}

/// The element types `sfp_countryname` reads a country from.
pub const WATCHED: [&str; 10] = [
    "PHONE_NUMBER",
    "DOMAIN_NAME",
    "AFFILIATE_DOMAIN_NAME",
    "CO_HOSTED_SITE_DOMAIN",
    "IBAN_NUMBER",
    "DOMAIN_WHOIS",
    "AFFILIATE_DOMAIN_WHOIS",
    "CO_HOSTED_SITE_DOMAIN_WHOIS",
    "GEOINFO",
    "PHYSICAL_ADDRESS",
];

/// The countries an element of Spiderfoot type `kind` names, as `sfp_countryname` reads each of
/// the [`WATCHED`] types; none for any other type. A place that ends in a two-letter country
/// code, as a geolocation provider writes one (`Sydney, NSW, AU`), names that country too.
#[must_use]
pub fn of_element(kind: &str, data: &str) -> Vec<&'static str> {
    let one = match kind {
        "PHONE_NUMBER" => from_phone(data),
        "DOMAIN_NAME" | "AFFILIATE_DOMAIN_NAME" | "CO_HOSTED_SITE_DOMAIN" => from_domain(data),
        "IBAN_NUMBER" => from_iban(data),
        "GEOINFO" => {
            let mut found = in_text(data);
            let last = data.rsplit(',').next().unwrap_or_default().trim();
            if let Some(name) = (last.len() == 2).then(|| from_code(last)).flatten() {
                if !found.contains(&name) {
                    found.push(name);
                }
            }
            return found;
        }
        "DOMAIN_WHOIS"
        | "PHYSICAL_ADDRESS"
        | "AFFILIATE_DOMAIN_WHOIS"
        | "CO_HOSTED_SITE_DOMAIN_WHOIS" => return in_text(data),
        _ => None,
    };
    one.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spiderfoots_table_is_whole_with_its_extra_codes() {
        assert_eq!(COUNTRIES.len(), 256);
        assert_eq!(from_code("au"), Some("Australia"));
        assert_eq!(from_code("UK"), Some("United Kingdom"));
        assert_eq!(from_code("GB"), Some("United Kingdom"));
        assert_eq!(from_code("EU"), Some("European Union"));
        assert_eq!(from_code("ZZ"), None);
        let mut codes: Vec<&str> = COUNTRIES.iter().map(|(code, _)| *code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), COUNTRIES.len(), "no code twice");
    }

    #[test]
    fn domains_phones_and_ibans_name_their_country() {
        assert_eq!(from_domain("www.example.com.au"), Some("Australia"));
        assert_eq!(from_domain("example.co.uk."), Some("United Kingdom"));
        assert_eq!(from_domain("example.com"), Some("United States"));
        assert_eq!(
            from_domain("example.io"),
            Some("British Indian Ocean Territory")
        );
        assert_eq!(from_domain("example.xyz"), None);
        assert_eq!(from_phone("+61412345678"), Some("Australia"));
        assert_eq!(from_phone("+442071838750"), Some("United Kingdom"));
        assert_eq!(from_phone("+18764567890"), Some("Jamaica"));
        assert_eq!(from_phone("+14165550199"), Some("Canada"));
        assert_eq!(from_phone("+12025550123"), Some("United States"));
        assert_eq!(from_phone("0412 345 678"), Some("Australia"));
        assert_eq!(from_phone("not a number"), None);
        assert_eq!(from_iban("DE89370400440532013000"), Some("Germany"));
        assert_eq!(from_iban("X"), None);
    }

    #[test]
    fn text_names_a_country_only_as_a_whole_name() {
        assert_eq!(in_text("Sydney, New South Wales, Australia"), ["Australia"]);
        assert_eq!(in_text("Australia"), ["Australia"]);
        assert_eq!(in_text("Trenton, New Jersey, US"), Vec::<&str>::new());
        assert_eq!(in_text("Abuja, Nigeria."), ["Nigeria"]);
        assert_eq!(
            in_text("Registrant Country: AU\nAdmin Country: Germany\nTech Country: zz"),
            ["Germany", "Australia"]
        );
        // Spiderfoot's table has the United Kingdom twice, as GB and UK; it is found once.
        assert_eq!(
            in_text("'united kingdom', (France)"),
            ["France", "United Kingdom"]
        );
        assert_eq!(
            in_text("Guinea-Bissau, South Sudan"),
            ["Guinea-Bissau", "South Sudan"],
            "not Guinea, not Sudan"
        );
        assert_eq!(
            in_text("St Thomas, U.S. Virgin Islands"),
            ["U.S. Virgin Islands"]
        );
    }

    #[test]
    fn each_watched_type_is_read_its_own_way() {
        assert_eq!(of_element("PHONE_NUMBER", "+61412345678"), ["Australia"]);
        assert_eq!(of_element("DOMAIN_NAME", "example.de"), ["Germany"]);
        assert_eq!(of_element("GEOINFO", "Berlin, Germany"), ["Germany"]);
        assert_eq!(
            of_element("GEOINFO", "Sydney, New South Wales, AU"),
            ["Australia"]
        );
        assert_eq!(
            of_element("PHYSICAL_ADDRESS", "1 Main St, Springfield, AU"),
            Vec::<&str>::new()
        );
        for kind in WATCHED {
            assert!(
                crate::sf_types::find(kind).is_some(),
                "{kind} is not catalogued"
            );
        }
        assert_eq!(
            of_element("INTERNET_NAME", "example.de"),
            Vec::<&str>::new()
        );
    }
}
