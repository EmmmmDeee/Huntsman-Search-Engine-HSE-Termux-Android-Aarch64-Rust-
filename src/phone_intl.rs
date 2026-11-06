//! Offline phone canonicalisation and international dialling-prefix lookup.
//!
//! The country table is ported from the legacy Huntsman `phone_intl` module.
//! This module performs no network I/O.

/// Source label for offline E.164 and international dialling-prefix evidence and outcomes.
pub const SOURCE: &str = "phone_intl";

/// The label the Australian numbering-plan reading records its evidence and outcome under.
pub const AU_SOURCE: &str = "phone_au";

/// The label the North American Numbering Plan reading records its evidence and outcome under.
pub const NANP_SOURCE: &str = "phone_nanp";

/// The label the United Arab Emirates numbering-plan reading records its evidence and outcome
/// under.
pub const AE_SOURCE: &str = "phone_ae";

/// Each ITU calling code with its ISO 3166 code and country name, longest code first. Codes are
/// numbers, not text, for the reason [`NANP_TOLL_FREE`] gives: as text, whole-program
/// optimisation packed them into long digit strings that the release key scan reads as a key.
pub const COUNTRIES: &[(u16, &str, &str)] = &[
    // Multi-digit codes first (longest-prefix-first).
    (1242, "BS", "Bahamas"),
    (1246, "BB", "Barbados"),
    (1264, "AI", "Anguilla"),
    (1268, "AG", "Antigua and Barbuda"),
    (1284, "VG", "British Virgin Islands"),
    (1340, "VI", "US Virgin Islands"),
    (1345, "KY", "Cayman Islands"),
    (1441, "BM", "Bermuda"),
    (1473, "GD", "Grenada"),
    (1649, "TC", "Turks and Caicos"),
    (1664, "MS", "Montserrat"),
    (1670, "MP", "Northern Mariana Islands"),
    (1671, "GU", "Guam"),
    (1684, "AS", "American Samoa"),
    (1721, "SX", "Sint Maarten"),
    (1758, "LC", "Saint Lucia"),
    (1767, "DM", "Dominica"),
    (1784, "VC", "Saint Vincent and the Grenadines"),
    (1787, "PR", "Puerto Rico"),
    (1809, "DO", "Dominican Republic"),
    (1829, "DO", "Dominican Republic"),
    (1849, "DO", "Dominican Republic"),
    (1868, "TT", "Trinidad and Tobago"),
    (1869, "KN", "Saint Kitts and Nevis"),
    (1658, "JM", "Jamaica"),
    (1876, "JM", "Jamaica"),
    (1939, "PR", "Puerto Rico"),
    // Canada's geographic area codes, in service or assigned (NANP area-code list, 2026-10).
    (1204, "CA", "Canada"),
    (1226, "CA", "Canada"),
    (1236, "CA", "Canada"),
    (1249, "CA", "Canada"),
    (1250, "CA", "Canada"),
    (1257, "CA", "Canada"),
    (1263, "CA", "Canada"),
    (1289, "CA", "Canada"),
    (1306, "CA", "Canada"),
    (1343, "CA", "Canada"),
    (1354, "CA", "Canada"),
    (1365, "CA", "Canada"),
    (1367, "CA", "Canada"),
    (1368, "CA", "Canada"),
    (1382, "CA", "Canada"),
    (1403, "CA", "Canada"),
    (1416, "CA", "Canada"),
    (1418, "CA", "Canada"),
    (1428, "CA", "Canada"),
    (1431, "CA", "Canada"),
    (1437, "CA", "Canada"),
    (1438, "CA", "Canada"),
    (1450, "CA", "Canada"),
    (1468, "CA", "Canada"),
    (1474, "CA", "Canada"),
    (1506, "CA", "Canada"),
    (1514, "CA", "Canada"),
    (1519, "CA", "Canada"),
    (1548, "CA", "Canada"),
    (1579, "CA", "Canada"),
    (1581, "CA", "Canada"),
    (1584, "CA", "Canada"),
    (1587, "CA", "Canada"),
    (1604, "CA", "Canada"),
    (1613, "CA", "Canada"),
    (1639, "CA", "Canada"),
    (1647, "CA", "Canada"),
    (1672, "CA", "Canada"),
    (1683, "CA", "Canada"),
    (1705, "CA", "Canada"),
    (1709, "CA", "Canada"),
    (1742, "CA", "Canada"),
    (1753, "CA", "Canada"),
    (1778, "CA", "Canada"),
    (1780, "CA", "Canada"),
    (1782, "CA", "Canada"),
    (1807, "CA", "Canada"),
    (1819, "CA", "Canada"),
    (1825, "CA", "Canada"),
    (1867, "CA", "Canada"),
    (1873, "CA", "Canada"),
    (1879, "CA", "Canada"),
    (1902, "CA", "Canada"),
    (1905, "CA", "Canada"),
    (1942, "CA", "Canada"),
    // The Caribbean Netherlands share +599 with Curaçao (+599 9).
    (5993, "BQ", "Sint Eustatius"),
    (5994, "BQ", "Saba"),
    (5997, "BQ", "Bonaire"),
    // Three-digit codes
    (211, "SS", "South Sudan"),
    (212, "MA", "Morocco"),
    (213, "DZ", "Algeria"),
    (216, "TN", "Tunisia"),
    (218, "LY", "Libya"),
    (220, "GM", "Gambia"),
    (221, "SN", "Senegal"),
    (222, "MR", "Mauritania"),
    (223, "ML", "Mali"),
    (224, "GN", "Guinea"),
    (225, "CI", "Ivory Coast"),
    (226, "BF", "Burkina Faso"),
    (227, "NE", "Niger"),
    (228, "TG", "Togo"),
    (229, "BJ", "Benin"),
    (230, "MU", "Mauritius"),
    (231, "LR", "Liberia"),
    (232, "SL", "Sierra Leone"),
    (233, "GH", "Ghana"),
    (234, "NG", "Nigeria"),
    (235, "TD", "Chad"),
    (236, "CF", "Central African Republic"),
    (237, "CM", "Cameroon"),
    (238, "CV", "Cape Verde"),
    (239, "ST", "São Tomé and Príncipe"),
    (240, "GQ", "Equatorial Guinea"),
    (241, "GA", "Gabon"),
    (242, "CG", "Republic of the Congo"),
    (243, "CD", "Democratic Republic of the Congo"),
    (244, "AO", "Angola"),
    (245, "GW", "Guinea-Bissau"),
    (246, "IO", "Diego Garcia"),
    (248, "SC", "Seychelles"),
    (249, "SD", "Sudan"),
    (250, "RW", "Rwanda"),
    (251, "ET", "Ethiopia"),
    (252, "SO", "Somalia"),
    (253, "DJ", "Djibouti"),
    (254, "KE", "Kenya"),
    (255, "TZ", "Tanzania"),
    (256, "UG", "Uganda"),
    (257, "BI", "Burundi"),
    (258, "MZ", "Mozambique"),
    (260, "ZM", "Zambia"),
    (261, "MG", "Madagascar"),
    (262, "RE", "Réunion / Mayotte"),
    (263, "ZW", "Zimbabwe"),
    (264, "NA", "Namibia"),
    (265, "MW", "Malawi"),
    (266, "LS", "Lesotho"),
    (267, "BW", "Botswana"),
    (268, "SZ", "Eswatini"),
    (269, "KM", "Comoros"),
    (290, "SH", "Saint Helena"),
    (291, "ER", "Eritrea"),
    (297, "AW", "Aruba"),
    (298, "FO", "Faroe Islands"),
    (299, "GL", "Greenland"),
    (350, "GI", "Gibraltar"),
    (351, "PT", "Portugal"),
    (352, "LU", "Luxembourg"),
    (353, "IE", "Ireland"),
    (354, "IS", "Iceland"),
    (355, "AL", "Albania"),
    (356, "MT", "Malta"),
    (357, "CY", "Cyprus"),
    (358, "FI", "Finland"),
    (359, "BG", "Bulgaria"),
    (370, "LT", "Lithuania"),
    (371, "LV", "Latvia"),
    (372, "EE", "Estonia"),
    (373, "MD", "Moldova"),
    (374, "AM", "Armenia"),
    (375, "BY", "Belarus"),
    (376, "AD", "Andorra"),
    (377, "MC", "Monaco"),
    (378, "SM", "San Marino"),
    (380, "UA", "Ukraine"),
    (381, "RS", "Serbia"),
    (382, "ME", "Montenegro"),
    (383, "XK", "Kosovo"),
    (385, "HR", "Croatia"),
    (386, "SI", "Slovenia"),
    (387, "BA", "Bosnia and Herzegovina"),
    (389, "MK", "North Macedonia"),
    (420, "CZ", "Czech Republic"),
    (421, "SK", "Slovakia"),
    (423, "LI", "Liechtenstein"),
    (500, "FK", "Falkland Islands"),
    (501, "BZ", "Belize"),
    (502, "GT", "Guatemala"),
    (503, "SV", "El Salvador"),
    (504, "HN", "Honduras"),
    (505, "NI", "Nicaragua"),
    (506, "CR", "Costa Rica"),
    (507, "PA", "Panama"),
    (508, "PM", "Saint Pierre and Miquelon"),
    (509, "HT", "Haiti"),
    (590, "GP", "Guadeloupe"),
    (591, "BO", "Bolivia"),
    (592, "GY", "Guyana"),
    (593, "EC", "Ecuador"),
    (594, "GF", "French Guiana"),
    (595, "PY", "Paraguay"),
    (596, "MQ", "Martinique"),
    (597, "SR", "Suriname"),
    (598, "UY", "Uruguay"),
    (599, "CW", "Curaçao"),
    (670, "TL", "Timor-Leste"),
    (672, "NF", "Norfolk Island"),
    (673, "BN", "Brunei"),
    (674, "NR", "Nauru"),
    (675, "PG", "Papua New Guinea"),
    (676, "TO", "Tonga"),
    (677, "SB", "Solomon Islands"),
    (678, "VU", "Vanuatu"),
    (679, "FJ", "Fiji"),
    (680, "PW", "Palau"),
    (681, "WF", "Wallis and Futuna"),
    (682, "CK", "Cook Islands"),
    (683, "NU", "Niue"),
    (685, "WS", "Samoa"),
    (686, "KI", "Kiribati"),
    (687, "NC", "New Caledonia"),
    (688, "TV", "Tuvalu"),
    (689, "PF", "French Polynesia"),
    (690, "TK", "Tokelau"),
    (691, "FM", "Micronesia"),
    (692, "MH", "Marshall Islands"),
    (850, "KP", "North Korea"),
    (852, "HK", "Hong Kong"),
    (853, "MO", "Macau"),
    (855, "KH", "Cambodia"),
    (856, "LA", "Laos"),
    (880, "BD", "Bangladesh"),
    (886, "TW", "Taiwan"),
    (960, "MV", "Maldives"),
    (961, "LB", "Lebanon"),
    (962, "JO", "Jordan"),
    (963, "SY", "Syria"),
    (964, "IQ", "Iraq"),
    (965, "KW", "Kuwait"),
    (966, "SA", "Saudi Arabia"),
    (967, "YE", "Yemen"),
    (968, "OM", "Oman"),
    (970, "PS", "Palestine"),
    (971, "AE", "United Arab Emirates"),
    (972, "IL", "Israel"),
    (973, "BH", "Bahrain"),
    (974, "QA", "Qatar"),
    (975, "BT", "Bhutan"),
    (976, "MN", "Mongolia"),
    (977, "NP", "Nepal"),
    (992, "TJ", "Tajikistan"),
    (993, "TM", "Turkmenistan"),
    (994, "AZ", "Azerbaijan"),
    (995, "GE", "Georgia"),
    (996, "KG", "Kyrgyzstan"),
    (998, "UZ", "Uzbekistan"),
    // Two-digit codes
    (20, "EG", "Egypt"),
    (27, "ZA", "South Africa"),
    (30, "GR", "Greece"),
    (31, "NL", "Netherlands"),
    (32, "BE", "Belgium"),
    (33, "FR", "France"),
    (34, "ES", "Spain"),
    (36, "HU", "Hungary"),
    (39, "IT", "Italy"),
    (40, "RO", "Romania"),
    (41, "CH", "Switzerland"),
    (43, "AT", "Austria"),
    (44, "GB", "United Kingdom"),
    (45, "DK", "Denmark"),
    (46, "SE", "Sweden"),
    (47, "NO", "Norway"),
    (48, "PL", "Poland"),
    (49, "DE", "Germany"),
    (51, "PE", "Peru"),
    (52, "MX", "Mexico"),
    (53, "CU", "Cuba"),
    (54, "AR", "Argentina"),
    (55, "BR", "Brazil"),
    (56, "CL", "Chile"),
    (57, "CO", "Colombia"),
    (58, "VE", "Venezuela"),
    (60, "MY", "Malaysia"),
    (61, "AU", "Australia"),
    (62, "ID", "Indonesia"),
    (63, "PH", "Philippines"),
    (64, "NZ", "New Zealand"),
    (65, "SG", "Singapore"),
    (66, "TH", "Thailand"),
    (81, "JP", "Japan"),
    (82, "KR", "South Korea"),
    (84, "VN", "Vietnam"),
    (86, "CN", "China"),
    (90, "TR", "Turkey"),
    (91, "IN", "India"),
    (92, "PK", "Pakistan"),
    (93, "AF", "Afghanistan"),
    (94, "LK", "Sri Lanka"),
    (95, "MM", "Myanmar"),
    (98, "IR", "Iran"),
    // Kazakhstan shares +7 with Russia: its numbers are +7 6 and +7 7.
    (76, "KZ", "Kazakhstan"),
    (77, "KZ", "Kazakhstan"),
    // Single-digit
    (7, "RU", "Russia"),
    // Every other +1 number: the United States, or a toll-free or service code of the plan.
    (1, "US", "United States"),
];

/// Longest-prefix country match.
#[must_use]
pub fn match_country(digits: &str) -> Option<(u16, &'static str, &'static str)> {
    COUNTRIES
        .iter()
        .find(|&&(code, ..)| begins_with_code(digits, code))
        .copied()
}

/// How many decimal digits `code` has.
const fn digit_count(code: u16) -> usize {
    let mut count = 1;
    let mut rest = code / 10;
    while rest > 0 {
        count += 1;
        rest /= 10;
    }
    count
}

/// Whether `digits` begins with `code` written in decimal. No calling code begins with 0.
fn begins_with_code(digits: &str, code: u16) -> bool {
    digits
        .get(..digit_count(code))
        .filter(|prefix| prefix.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|prefix| prefix.parse::<u16>().ok())
        == Some(code)
}

/// Canonicalise an explicit international number or a recognised Australian national number to
/// E.164, by [`crate::value_syntax::canonical_phone`]: the one rule every phone value is read by,
/// so a scan's selector and the entities its sources report key one number alike.
#[must_use]
pub fn canonicalize(raw: &str) -> Option<String> {
    crate::value_syntax::canonical_phone(raw)
}

/// The ITU calling code of a canonical E.164 number: the shortest prefix in [`COUNTRIES`] it
/// starts with. Calling codes are prefix-free, so a longer entry that starts with a shorter one is
/// a share of that code (a NANP area code under `1`, Kazakhstan's `77` under `7`), not a code of
/// its own. **Pure.**
#[must_use]
pub fn calling_code(e164: &str) -> Option<u16> {
    let digits = e164.strip_prefix('+')?;
    COUNTRIES
        .iter()
        .map(|&(code, ..)| code)
        .filter(|&code| begins_with_code(digits, code))
        .min_by_key(|&code| digit_count(code))
}

/// Resolve a canonical E.164 number to country metadata.
#[must_use]
pub fn country_of(e164: &str) -> Option<(u16, &'static str, &'static str)> {
    let digits = e164.strip_prefix('+')?;
    match_country(digits)
}

/// Toll-free codes: those in service and those set aside for toll-free use, never geographic.
/// Codes are numbers, not text: as text, a run of them lands in the binary as one long digit
/// string that the release key scan reads as a key wherever a hex letter abuts it.
const NANP_TOLL_FREE: &[u16] = &[
    800, 822, 833, 844, 855, 866, 877, 880, 881, 882, 883, 884, 885, 886, 887, 888, 889,
];

/// Other non-geographic service codes and what each carries. `900` is premium-rate, kept apart.
const NANP_SERVICE: &[(u16, &str)] = &[
    (500, "personal communications service"),
    (521, "personal communications service"),
    (522, "personal communications service"),
    (523, "personal communications service"),
    (524, "personal communications service"),
    (525, "personal communications service"),
    (526, "personal communications service"),
    (527, "personal communications service"),
    (528, "personal communications service"),
    (529, "personal communications service"),
    (532, "personal communications service"),
    (533, "personal communications service"),
    (544, "personal communications service"),
    (566, "personal communications service"),
    (577, "personal communications service"),
    (588, "personal communications service"),
    (600, "Canadian non-geographic service"),
    (622, "Canadian non-geographic service"),
    (633, "Canadian non-geographic service"),
    (700, "interexchange carrier service"),
    (710, "US government special service"),
];

/// What the North American Numbering Plan says about a `+1` number, offline: its area code (NPA),
/// central office code (NXX) and line number, its class, and the country or territory its area
/// code is assigned to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nanp {
    pub npa: String,
    pub nxx: String,
    pub line: String,
    pub class: NanpClass,
    /// The country or territory a geographic area code belongs to, as ISO 3166-1 alpha-2 and
    /// name, and whether a list named it (`true`) or it is the United States because no list of
    /// another country's codes holds it (`false`).
    pub region: Option<(&'static str, &'static str, bool)>,
    /// `555-0100` to `555-0199`: set aside for fiction, never assigned to a subscriber.
    pub fictional: bool,
}

/// The kind of service an area code carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NanpClass {
    Geographic,
    TollFree,
    Premium,
    /// Another non-geographic service code, with its purpose.
    NonGeographic(&'static str),
}

impl NanpClass {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Geographic => "geographic",
            Self::TollFree => "toll-free",
            Self::Premium => "premium",
            Self::NonGeographic(_) => "non-geographic",
        }
    }
}

/// Why a `+1` number cannot be a NANP number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NanpError {
    #[error("a NANP number has ten digits after +1")]
    Length,
    #[error("a NANP area code cannot begin with 0 or 1")]
    AreaCodeStart,
    #[error("an N11 code such as 411 or 911 is a service code, not an area code")]
    AreaCodeN11,
    #[error("area codes with a middle 9, and 37X and 96X, are reserved and never assigned")]
    AreaCodeReserved,
    #[error("a NANP exchange (central office code) cannot begin with 0 or 1")]
    ExchangeStart,
    #[error("an N11 code such as 411 or 911 is a service code, not an exchange")]
    ExchangeN11,
}

impl Nanp {
    /// The national form, as dialled within the plan: `(706) 828-5611`.
    #[must_use]
    pub fn local(&self) -> String {
        format!("({}) {}-{}", self.npa, self.nxx, self.line)
    }

    /// The ITU-T E.123 international form: `+1 706 828 5611`.
    #[must_use]
    pub fn international(&self) -> String {
        format!("+1 {} {} {}", self.npa, self.nxx, self.line)
    }
}

fn is_n11(code: &str) -> bool {
    code.as_bytes()[1..] == *b"11"
}

/// The NANP reading of a canonical E.164 number: `None` when it is not a `+1` number, else the
/// number's parts or the plan rule it breaks. **Pure.**
///
/// # Errors
/// The [`NanpError`] for a `+1` number the plan cannot hold.
#[must_use]
pub fn nanp(e164: &str) -> Option<Result<Nanp, NanpError>> {
    let national = e164.strip_prefix("+1")?;
    Some(nanp_national(national))
}

fn nanp_national(national: &str) -> Result<Nanp, NanpError> {
    if national.len() != 10 || !national.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NanpError::Length);
    }
    let (npa, rest) = national.split_at(3);
    let (nxx, line) = rest.split_at(3);
    if matches!(npa.as_bytes()[0], b'0' | b'1') {
        return Err(NanpError::AreaCodeStart);
    }
    if is_n11(npa) {
        return Err(NanpError::AreaCodeN11);
    }
    if npa.as_bytes()[1] == b'9' || npa.starts_with("37") || npa.starts_with("96") {
        return Err(NanpError::AreaCodeReserved);
    }
    if matches!(nxx.as_bytes()[0], b'0' | b'1') {
        return Err(NanpError::ExchangeStart);
    }
    if is_n11(nxx) {
        return Err(NanpError::ExchangeN11);
    }
    let code: u16 = npa.parse().map_err(|_| NanpError::Length)?;
    let class = if NANP_TOLL_FREE.contains(&code) {
        NanpClass::TollFree
    } else if npa == "900" {
        NanpClass::Premium
    } else if let Some(&(_, purpose)) = NANP_SERVICE.iter().find(|(service, _)| *service == code) {
        NanpClass::NonGeographic(purpose)
    } else {
        NanpClass::Geographic
    };
    // The dialling-prefix table is the one list of which plan country holds an area code.
    let region = (class == NanpClass::Geographic).then(|| {
        let (prefix, iso, name) =
            match_country(&format!("1{national}")).unwrap_or((1, "US", "United States"));
        (iso, name, prefix > 9)
    });
    Ok(Nanp {
        npa: npa.to_owned(),
        nxx: nxx.to_owned(),
        line: line.to_owned(),
        class,
        region,
        fictional: nxx == "555" && line.starts_with("01"),
    })
}

/// The service a `+971` number carries, by the range of the UAE plan that holds it.
///
/// The ranges are those Google's libphonenumber records for the UAE (`PhoneNumberMetadata.xml`,
/// territory `AE`), the metadata Android validates numbers by: fixed lines `[2-4679][2-8]` and six
/// digits, mobiles `5[02-68]` and seven, toll-free `400` and six or `800` and two to nine, premium
/// rate `900[02]` and five, shared cost `700[05]` and five, universal access `600[25]` and five.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UaeClass {
    Geographic,
    Mobile,
    TollFree,
    Premium,
    SharedCost,
    /// A `600` number: one number a business or government service answers across the country.
    UniversalAccess,
}

impl UaeClass {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Geographic => "geographic",
            Self::Mobile => "mobile",
            Self::TollFree => "toll-free",
            Self::Premium => "premium-rate",
            Self::SharedCost => "shared-cost",
            Self::UniversalAccess => "universal-access",
        }
    }
}

/// A UAE fixed-line area: the digit after `+971` (dialled `0` and that digit at home), what it
/// serves, and the ISO 3166-2 codes of the emirates in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UaeArea {
    pub digit: u8,
    pub name: &'static str,
    pub emirates: &'static [&'static str],
}

impl UaeArea {
    /// The area code as dialled within the UAE: `04` for Dubai.
    #[must_use]
    pub fn trunk_code(self) -> String {
        format!("0{}", char::from(self.digit))
    }
}

/// Every UAE fixed-line area. Al Ain has its own area within the emirate of Abu Dhabi; one area
/// serves Sharjah, Ajman and Umm Al Quwain.
const UAE_AREAS: [UaeArea; 6] = [
    UaeArea {
        digit: b'2',
        name: "Abu Dhabi",
        emirates: &["AE-AZ"],
    },
    UaeArea {
        digit: b'3',
        name: "Al Ain",
        emirates: &["AE-AZ"],
    },
    UaeArea {
        digit: b'4',
        name: "Dubai",
        emirates: &["AE-DU"],
    },
    UaeArea {
        digit: b'6',
        name: "Sharjah, Ajman and Umm Al Quwain",
        emirates: &["AE-SH", "AE-AJ", "AE-UQ"],
    },
    UaeArea {
        digit: b'7',
        name: "Ras Al Khaimah",
        emirates: &["AE-RK"],
    },
    UaeArea {
        digit: b'9',
        name: "Fujairah",
        emirates: &["AE-FU"],
    },
];

/// What the UAE numbering plan says about a `+971` number, offline: its national number, the kind
/// of service its range carries and, for a fixed line, its area. Nothing here names an operator,
/// a subscriber or an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uae {
    /// The national significant number: the digits after `+971`.
    pub national: String,
    pub class: UaeClass,
    pub area: Option<UaeArea>,
}

/// Why a `+971` number cannot be a UAE number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UaeError {
    #[error(
        "no range of the UAE plan holds it: a fixed line is 8 digits after +971 starting 2, 3, 4, 6, 7 or 9, a mobile 9 starting 50, 52 to 56 or 58, and a service number starts 400, 600, 700, 800 or 900"
    )]
    NotInPlan,
}

impl Uae {
    /// The national number in the groups the plan writes it in: `4 123 4567`, `50 123 4567`,
    /// `800 123456`, `900 2 12345`.
    fn groups(&self) -> Vec<&str> {
        let national = self.national.as_str();
        match self.class {
            UaeClass::Geographic => vec![&national[..1], &national[1..4], &national[4..]],
            UaeClass::Mobile => vec![&national[..2], &national[2..5], &national[5..]],
            UaeClass::UniversalAccess => vec![&national[..3], &national[3..]],
            UaeClass::TollFree if national.starts_with('8') => {
                vec![&national[..3], &national[3..]]
            }
            UaeClass::TollFree | UaeClass::Premium | UaeClass::SharedCost => {
                vec![&national[..3], &national[3..4], &national[4..]]
            }
        }
    }

    /// The national form, as dialled within the UAE: a fixed line or mobile with its trunk `0`
    /// (`04 123 4567`, `050 123 4567`), a service number without one (`800 123456`).
    #[must_use]
    pub fn local(&self) -> String {
        let written = self.groups().join(" ");
        if matches!(self.class, UaeClass::Geographic | UaeClass::Mobile) {
            format!("0{written}")
        } else {
            written
        }
    }

    /// The ITU-T E.123 international form: `+971 4 123 4567`.
    #[must_use]
    pub fn international(&self) -> String {
        format!("+971 {}", self.groups().join(" "))
    }
}

/// The UAE plan's reading of a canonical E.164 number: `None` when it is not a `+971` number, else
/// its class and area or the plan rule it breaks. **Pure.**
///
/// # Errors
/// [`UaeError::NotInPlan`] for a `+971` number no range of the plan holds.
#[must_use]
pub fn uae(e164: &str) -> Option<Result<Uae, UaeError>> {
    let national = e164.strip_prefix("+971")?;
    Some(uae_national(national))
}

fn uae_national(national: &str) -> Result<Uae, UaeError> {
    let digits = national.as_bytes();
    if digits.len() < 5 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(UaeError::NotInPlan);
    }
    let (first, second, fourth) = (digits[0], digits[1], digits[3]);
    let (class, area) = match (digits.len(), first) {
        (8, b'2' | b'3' | b'4' | b'6' | b'7' | b'9') if (b'2'..=b'8').contains(&second) => (
            UaeClass::Geographic,
            UAE_AREAS.iter().find(|area| area.digit == first).copied(),
        ),
        (9, b'5') if matches!(second, b'0' | b'2'..=b'6' | b'8') => (UaeClass::Mobile, None),
        (9, _) if national.starts_with("400") => (UaeClass::TollFree, None),
        (5..=12, _) if national.starts_with("800") => (UaeClass::TollFree, None),
        (9, _) if national.starts_with("900") && matches!(fourth, b'0' | b'2') => {
            (UaeClass::Premium, None)
        }
        (9, _) if national.starts_with("700") && matches!(fourth, b'0' | b'5') => {
            (UaeClass::SharedCost, None)
        }
        (9, _) if national.starts_with("600") && matches!(fourth, b'2' | b'5') => {
            (UaeClass::UniversalAccess, None)
        }
        _ => return Err(UaeError::NotInPlan),
    };
    Ok(Uae {
        national: national.to_owned(),
        class,
        area,
    })
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
                    !begins_with_code(&later.to_string(), *earlier),
                    "{later} is shadowed by earlier {earlier}"
                );
            }
        }
    }

    fn plan(e164: &str) -> Nanp {
        nanp(e164).expect("a +1 number").expect("a NANP number")
    }

    #[test]
    fn a_nanp_number_has_its_local_and_international_forms_and_area_code_country() {
        let us = plan("+12025550123");
        assert_eq!(us.local(), "(202) 555-0123");
        assert_eq!(us.international(), "+1 202 555 0123");
        assert_eq!(us.class, NanpClass::Geographic);
        assert_eq!(us.region, Some(("US", "United States", false)));
        assert!(us.fictional, "555-0100..0199 is set aside for fiction");

        assert_eq!(plan("+14165550199").region, Some(("CA", "Canada", true)));
        assert_eq!(plan("+18765550100").region, Some(("JM", "Jamaica", true)));
        assert_eq!(
            plan("+17875550100").region,
            Some(("PR", "Puerto Rico", true))
        );
        assert!(
            !plan("+12025550200").fictional,
            "555-0200 is outside the fictional block"
        );
        assert_eq!(
            nanp("+61412345678"),
            None,
            "only +1 numbers are read by the plan"
        );
    }

    #[test]
    fn toll_free_premium_and_service_codes_are_not_geographic() {
        for code in ["800", "833", "888", "822"] {
            let number = plan(&format!("+1{code}5550100"));
            assert_eq!(number.class, NanpClass::TollFree, "{code}");
            assert_eq!(number.region, None, "{code}");
        }
        assert_eq!(plan("+19005550100").class, NanpClass::Premium);
        assert_eq!(
            plan("+16005550100").class,
            NanpClass::NonGeographic("Canadian non-geographic service")
        );
    }

    #[test]
    fn a_number_the_plan_cannot_hold_is_refused_with_its_rule() {
        for (number, rule) in [
            ("+11235550100", NanpError::AreaCodeStart),
            ("+19115550100", NanpError::AreaCodeN11),
            ("+12905550100", NanpError::AreaCodeReserved),
            ("+13725550100", NanpError::AreaCodeReserved),
            ("+19655550100", NanpError::AreaCodeReserved),
            ("+12021550100", NanpError::ExchangeStart),
            ("+12024110100", NanpError::ExchangeN11),
            ("+1202555010", NanpError::Length),
        ] {
            assert_eq!(nanp(number), Some(Err(rule)), "{number}");
        }
    }

    #[test]
    fn every_listed_area_code_is_a_valid_geographic_code_of_its_country() {
        for &(prefix, iso, _) in COUNTRIES.iter().filter(|&&(code, ..)| code >= 1000) {
            let text = prefix.to_string();
            let Some(npa) = text.strip_prefix('1') else {
                continue;
            };
            let number = plan(&format!("+1{npa}5550100"));
            assert_eq!(number.class, NanpClass::Geographic, "{prefix}");
            assert_eq!(number.region.map(|(code, ..)| code), Some(iso), "{prefix}");
        }
        let mut prefixes: Vec<u16> = COUNTRIES.iter().map(|(prefix, ..)| *prefix).collect();
        prefixes.sort_unstable();
        assert!(
            prefixes.windows(2).all(|pair| pair[0] != pair[1]),
            "a prefix is listed twice"
        );
    }

    #[test]
    fn the_calling_code_is_the_shared_code_not_an_area_code_or_a_share_of_one() {
        assert_eq!(calling_code("+14165550199"), Some(1));
        assert_eq!(calling_code("+18765550100"), Some(1));
        assert_eq!(calling_code("+77012345678"), Some(7));
        assert_eq!(calling_code("+61412345678"), Some(61));
        assert_eq!(calling_code("+442071838750"), Some(44));
        assert_eq!(calling_code("61412345678"), None);
    }

    fn emirati(e164: &str) -> Uae {
        uae(e164).expect("a +971 number").expect("in the plan")
    }

    #[test]
    fn a_uae_fixed_line_names_its_area_and_emirates() {
        let dubai = emirati("+97143123456");
        assert_eq!(dubai.class, UaeClass::Geographic);
        let area = dubai.area.expect("a fixed line has an area");
        assert_eq!(
            (area.name, area.emirates, area.trunk_code().as_str()),
            ("Dubai", &["AE-DU"][..], "04")
        );
        assert_eq!(dubai.local(), "04 312 3456");
        assert_eq!(dubai.international(), "+971 4 312 3456");
        for (e164, name, emirates) in [
            ("+97122345678", "Abu Dhabi", &["AE-AZ"][..]),
            ("+97137654321", "Al Ain", &["AE-AZ"][..]),
            (
                "+97165432100",
                "Sharjah, Ajman and Umm Al Quwain",
                &["AE-SH", "AE-AJ", "AE-UQ"][..],
            ),
            ("+97172345678", "Ras Al Khaimah", &["AE-RK"][..]),
            ("+97192223333", "Fujairah", &["AE-FU"][..]),
        ] {
            let area = emirati(e164).area.expect(e164);
            assert_eq!((area.name, area.emirates), (name, emirates), "{e164}");
        }
    }

    #[test]
    fn a_uae_mobile_has_no_area_and_keeps_its_prefix() {
        for prefix in ["50", "52", "53", "54", "55", "56", "58"] {
            let number = emirati(&format!("+971{prefix}1234567"));
            assert_eq!(number.class, UaeClass::Mobile, "{prefix}");
            assert_eq!(number.area, None);
            assert_eq!(number.local(), format!("0{prefix} 123 4567"));
        }
        assert_eq!(emirati("+971501234567").international(), "+971 50 123 4567");
        // 51, 57 and 59 are no mobile range of the plan.
        for unassigned in ["+971511234567", "+971571234567", "+971591234567"] {
            assert_eq!(
                uae(unassigned),
                Some(Err(UaeError::NotInPlan)),
                "{unassigned}"
            );
        }
    }

    #[test]
    fn uae_service_numbers_are_read_by_their_range() {
        for (e164, class, local) in [
            ("+971800123456", UaeClass::TollFree, "800 123456"),
            ("+97180012", UaeClass::TollFree, "800 12"),
            ("+971400123456", UaeClass::TollFree, "400 1 23456"),
            ("+971900212345", UaeClass::Premium, "900 2 12345"),
            ("+971700012345", UaeClass::SharedCost, "700 0 12345"),
            ("+971600212345", UaeClass::UniversalAccess, "600 212345"),
        ] {
            let number = emirati(e164);
            assert_eq!(
                (number.class, number.local().as_str()),
                (class, local),
                "{e164}"
            );
            assert_eq!(number.area, None, "{e164}");
        }
        for outside in [
            // A fixed line whose second digit is 0, 1 or 9 is in no range.
            "+97141234567",
            "+97149234567",
            // Wrong lengths for a fixed line and a mobile.
            "+9714312345",
            "+9715012345678",
            // 900, 700 and 600 numbers outside their assigned blocks.
            "+971901123456",
            "+971701123456",
            "+971601123456",
            // Area 1, 5 and 8 hold no fixed line.
            "+97112345678",
        ] {
            assert_eq!(uae(outside), Some(Err(UaeError::NotInPlan)), "{outside}");
        }
        assert_eq!(uae("+61412345678"), None);
    }
}
