//! Offline lookup tables and pure prefix logic for [`super::PhoneGeo`].
//!
//! Two complementary inference layers on a phone number, fused from the former
//! `phone_area_geo` and `phone_carrier_geo` modules:
//!
//! - [`lookup_area_code`] — country dialling prefix + geographic area code →
//!   city/region (Australia, UK, US/Canada, Germany, France, Japan, NZ).
//! - [`identify_carrier`] — Australian (04xx) and UK (07xxx) mobile prefix →
//!   allocated carrier plus a coarse market-share network hint.
//!
//! Pure data + functions: no I/O, no allocation beyond the digit string the
//! caller already holds. The tables, prefixes, confidences and network hints are
//! preserved verbatim from the two source modules.

// ── Area-code geolocation (former `phone_area_geo`) ─────────────────────────

/// A resolved area-code geolocation: the city/region a number's country dialling
/// prefix + area code maps to, with the ISO country and the confidence the
/// emitting pass stamps onto its entities.
pub(super) struct AreaCodeGeo {
    pub(super) location: &'static str,
    pub(super) country: &'static str,
    pub(super) country_code: &'static str,
    pub(super) area_code: &'static str,
    pub(super) confidence: f64,
}

pub(super) fn lookup_area_code(digits: &str) -> Option<AreaCodeGeo> {
    // First country whose dialling prefix the number carries AND whose table has
    // a matching area code; a prefix match with no area hit falls through to the
    // next country (nested find_map mirrors the original break-to-outer-loop).
    AREA_CODE_TABLES
        .iter()
        .find_map(|&(country_prefix, table)| {
            let national = digits.strip_prefix(country_prefix)?;
            table.iter().find_map(|&(area, city, cc)| {
                national.starts_with(area).then(|| AreaCodeGeo {
                    location: city,
                    country: country_name(cc),
                    country_code: cc,
                    area_code: area,
                    confidence: 0.58,
                })
            })
        })
}

pub(super) fn country_name(cc: &str) -> &'static str {
    // Reuse the canonical ISO→name table (55 countries) rather than maintain a
    // divergent 8-entry copy; every ISO this module's area tables use is covered.
    crate::util::geohash::country_name_for_iso(cc).unwrap_or("Unknown")
}

const AU_AREAS: &[(&str, &str, &str)] = &[
    ("2", "Sydney / NSW / ACT", "AU"),
    ("3", "Melbourne / VIC / TAS", "AU"),
    ("7", "Brisbane / QLD", "AU"),
    ("8", "Perth / SA / NT", "AU"),
];

const GB_AREAS: &[(&str, &str, &str)] = &[
    ("20", "London", "GB"),
    ("121", "Birmingham", "GB"),
    ("131", "Edinburgh", "GB"),
    ("141", "Glasgow", "GB"),
    ("151", "Liverpool", "GB"),
    ("161", "Manchester", "GB"),
    ("113", "Leeds", "GB"),
    ("114", "Sheffield", "GB"),
    ("115", "Nottingham", "GB"),
    ("116", "Leicester", "GB"),
    ("117", "Bristol", "GB"),
    ("118", "Reading", "GB"),
    ("191", "Newcastle upon Tyne", "GB"),
    ("23", "Southampton / Portsmouth", "GB"),
    ("24", "Coventry", "GB"),
    ("28", "Northern Ireland", "GB"),
    ("29", "Cardiff", "GB"),
];

const DE_AREAS: &[(&str, &str, &str)] = &[
    ("30", "Berlin", "DE"),
    ("40", "Hamburg", "DE"),
    ("69", "Frankfurt", "DE"),
    ("89", "Munich", "DE"),
    ("221", "Cologne", "DE"),
    ("211", "Duesseldorf", "DE"),
    ("711", "Stuttgart", "DE"),
    ("511", "Hannover", "DE"),
    ("341", "Leipzig", "DE"),
    ("351", "Dresden", "DE"),
];

const FR_AREAS: &[(&str, &str, &str)] = &[
    ("1", "Paris / Ile-de-France", "FR"),
    ("2", "Northwest France", "FR"),
    ("3", "Northeast France", "FR"),
    ("4", "Southeast France", "FR"),
    ("5", "Southwest France", "FR"),
];

const JP_AREAS: &[(&str, &str, &str)] = &[
    ("3", "Tokyo", "JP"),
    ("6", "Osaka", "JP"),
    ("45", "Yokohama", "JP"),
    ("52", "Nagoya", "JP"),
    ("11", "Sapporo", "JP"),
    ("22", "Sendai", "JP"),
    ("75", "Kyoto", "JP"),
    ("78", "Kobe", "JP"),
    ("82", "Hiroshima", "JP"),
    ("92", "Fukuoka", "JP"),
];

const NZ_AREAS: &[(&str, &str, &str)] = &[
    ("9", "Auckland", "NZ"),
    ("4", "Wellington", "NZ"),
    ("3", "Christchurch / South Island", "NZ"),
    ("7", "Hamilton / Waikato", "NZ"),
];

pub(super) type AreaTable = &'static [(&'static str, &'static str, &'static str)];

const NANP_AREAS: &[(&str, &str, &str)] = &[
    // US
    ("212", "New York City", "US"),
    ("213", "Los Angeles", "US"),
    ("312", "Chicago", "US"),
    ("415", "San Francisco", "US"),
    ("202", "Washington DC", "US"),
    ("305", "Miami", "US"),
    ("713", "Houston", "US"),
    ("214", "Dallas", "US"),
    ("404", "Atlanta", "US"),
    ("617", "Boston", "US"),
    ("206", "Seattle", "US"),
    ("303", "Denver", "US"),
    ("602", "Phoenix", "US"),
    ("215", "Philadelphia", "US"),
    ("313", "Detroit", "US"),
    ("612", "Minneapolis", "US"),
    ("314", "St. Louis", "US"),
    ("702", "Las Vegas", "US"),
    ("503", "Portland", "US"),
    ("512", "Austin", "US"),
    ("619", "San Diego", "US"),
    ("704", "Charlotte", "US"),
    ("808", "Hawaii", "US"),
    ("907", "Alaska", "US"),
    // Canada
    ("416", "Toronto", "CA"),
    ("604", "Vancouver", "CA"),
    ("514", "Montreal", "CA"),
    ("613", "Ottawa", "CA"),
    ("403", "Calgary", "CA"),
    ("780", "Edmonton", "CA"),
    ("204", "Winnipeg", "CA"),
    ("306", "Saskatchewan", "CA"),
];

pub(super) const AREA_CODE_TABLES: &[(&str, AreaTable)] = &[
    ("61", AU_AREAS),
    ("44", GB_AREAS),
    ("1", NANP_AREAS),
    ("49", DE_AREAS),
    ("33", FR_AREAS),
    ("81", JP_AREAS),
    ("64", NZ_AREAS),
];

// ── Carrier geolocation (former `phone_carrier_geo`) ────────────────────────

/// A resolved mobile-carrier signal: the allocated carrier for a number's mobile
/// prefix, the country it belongs to, the confidence the emitting pass stamps,
/// and a coarse market-share `network_hint` (rural/metro/MVNO).
pub(super) struct CarrierInfo {
    pub(super) carrier: &'static str,
    pub(super) country: &'static str,
    pub(super) confidence: f64,
    pub(super) network_hint: &'static str,
}

pub(super) fn identify_carrier(digits: &str) -> Option<CarrierInfo> {
    if let Some(national) = digits.strip_prefix("61")
        && national.starts_with('4')
        && national.len() >= 9
    {
        return au_carrier(&national[..3]);
    }
    if let Some(national) = digits.strip_prefix("44")
        && national.starts_with('7')
        && national.len() >= 10
    {
        return uk_carrier(&national[..4]);
    }
    None
}

pub(super) fn au_carrier(prefix_3: &str) -> Option<CarrierInfo> {
    let carrier = match prefix_3 {
        "400" | "401" | "402" | "403" | "404" | "405" | "406" => "Telstra",
        "410" | "411" | "412" | "413" | "414" | "415" | "416" | "417" | "418" | "419" => "Telstra",
        "420" | "421" | "422" | "423" | "424" | "425" => "Vodafone",
        "430" | "431" | "432" | "433" | "434" | "435" => "Optus",
        "450" | "451" | "452" | "453" => "Pivotel/MVNOs",
        "470" | "471" | "472" | "473" | "474" | "475" | "476" | "477" | "478" | "479" => "Telstra",
        "480" | "481" | "482" | "483" | "484" => "Optus",
        "490" | "491" => "Optus",
        _ => return None,
    };
    Some(CarrierInfo {
        carrier,
        country: "Australia",
        confidence: 0.42,
        network_hint: match carrier {
            "Telstra" => "dominant_rural_regional",
            "Optus" => "metro_suburban",
            "Vodafone" => "metro_only",
            _ => "mvno",
        },
    })
}

pub(super) fn uk_carrier(prefix_4: &str) -> Option<CarrierInfo> {
    let carrier = match prefix_4 {
        "7400" | "7401" | "7402" | "7403" | "7404" | "7405" => "EE",
        "7410" | "7411" | "7412" | "7413" | "7414" | "7415" => "Vodafone UK",
        "7420" | "7421" | "7422" | "7423" | "7424" | "7425" => "Three UK",
        "7430" | "7431" | "7432" | "7433" | "7434" | "7435" => "EE",
        "7440" | "7441" | "7442" | "7443" | "7444" | "7445" => "Three UK",
        "7450" | "7451" | "7452" | "7453" | "7454" | "7455" => "O2 UK",
        "7460" | "7461" | "7462" | "7463" | "7464" | "7465" => "Vodafone UK",
        "7500" | "7501" | "7502" | "7503" | "7504" | "7505" => "Vodafone UK",
        "7700" | "7701" | "7702" | "7703" | "7704" | "7705" => "O2 UK",
        "7710" | "7711" | "7712" | "7713" | "7714" | "7715" => "Vodafone UK",
        "7720" | "7721" | "7722" | "7723" | "7724" | "7725" => "Three UK",
        "7730" | "7731" | "7732" | "7733" | "7734" | "7735" => "O2 UK",
        "7740" | "7741" | "7742" | "7743" | "7744" | "7745" => "Vodafone UK",
        "7750" | "7751" | "7752" | "7753" | "7754" | "7755" => "Vodafone UK",
        "7760" | "7761" | "7762" | "7763" | "7764" | "7765" => "O2 UK",
        "7770" | "7771" | "7772" | "7773" | "7774" | "7775" => "Vodafone UK",
        "7780" | "7781" | "7782" | "7783" | "7784" | "7785" => "Three UK",
        "7800" | "7801" | "7802" | "7803" | "7804" | "7805" => "O2 UK",
        "7850" | "7851" | "7852" | "7853" | "7854" | "7855" => "Vodafone UK",
        "7900" | "7901" | "7902" | "7903" | "7904" | "7905" => "EE",
        _ => return None,
    };
    Some(CarrierInfo {
        carrier,
        country: "United Kingdom",
        confidence: 0.40,
        network_hint: "mobile",
    })
}
