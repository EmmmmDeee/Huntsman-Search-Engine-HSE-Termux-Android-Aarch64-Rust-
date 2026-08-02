//! Phone number geolocation via E.164 country prefix (offline lookup).

use std::collections::HashSet;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{ModuleContext, ModuleResult},
    scan::Target,
};

// ─── Phone number geolocation (free — E.164 prefix only) ────────────────────

pub(super) async fn process_phone_prefix_only(
    target: &Target,
    ctx: &ModuleContext,
) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();
    let mut seen = HashSet::new();

    // Country geolocation requires an EXPLICIT international form ('+' or the
    // '00' prefix) — shared with `phone_intl` so both agree on what counts as
    // international. Without it the leading digits are ambiguous: a US national
    // number ("202-555-0100") begins with an area code that the bare-prefix
    // scan would otherwise read as a country code ("20" → Egypt) and emit a
    // wrong-country coordinate. National/ambiguous → no coarse geo.
    let Some(phone) = crate::modules::phone_intl::international_digits(&target.value) else {
        return Ok(result);
    };
    if let Some((country, cc, lat, lon)) = phone_prefix_to_country(&phone) {
        let coords = format!("{lat:.4},{lon:.4}");
        if seen.insert(format!("@phone-geo:{coords}")) {
            let mut e = Entity::new(
                EntityKind::Coordinates,
                &coords,
                confidence::MEDIUM_LIGHT,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag("phone-prefix");
            e.tag(crate::core::tags::COARSE);
            e.tag(format!("country:{cc}"));
            e.add_evidence(
                Evidence::new(
                    "geo_intel",
                    format!("Phone prefix -> {country} for {}", target.value),
                )
                .with_attr("country", country)
                .with_attr("country_code", cc)
                .with_attr("method", "e164-prefix"),
            );
            result.push(e);
        }
    }

    Ok(result)
}

// ─── Phone prefix -> country ────────────────────────────────────────────────

/// Resolve an E.164 phone number's dialling prefix to a country-centroid fix:
/// `(country_name, ISO-3166, lat, lon)`, or `None` when no prefix matches. Scans
/// longest-prefix-first (3→2→1 digits). Caribbean NANP territories (`+1242`,
/// `+1876`, …) share `+1` with the US but are delegated to `phone_intl` so they
/// return `None` rather than a misleading US-centroid fix. Non-ASCII input is
/// rejected up front.
pub(super) fn phone_prefix_to_country(
    phone: &str,
) -> Option<(&'static str, &'static str, f64, f64)> {
    if !phone.is_ascii() {
        return None;
    }
    // Caribbean NANP territories share country code +1 but use a 4-digit dialling
    // prefix (1242 Bahamas, 1876 Jamaica, …). The `[3, 2, 1]` scan below can only
    // see up to `1` and would geolocate every one of them to the US centroid —
    // an actively misleading wrong-country fix. `phone_intl` is the source of
    // truth for these 4-digit codes: if it identifies a non-US/CA NANP territory,
    // return `None` (honest "no precise location") rather than a wrong "US".
    if phone.starts_with('1')
        && let Some((prefix, iso, _)) = crate::modules::phone_intl::match_country(phone)
        && prefix.len() == 4
        && iso != "US"
        && iso != "CA"
    {
        return None;
    }
    for len in [3, 2, 1] {
        if phone.len() >= len {
            let prefix = &phone[..len];
            if !prefix.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Some(result) = match prefix {
                // 1-digit
                "1" => Some(("United States/Canada", "US", 39.8283, -98.5795)),
                "7" => Some(("Russia", "RU", 61.5240, 105.3188)),
                // 2-digit
                "20" => Some(("Egypt", "EG", 26.8206, 30.8025)),
                "27" => Some(("South Africa", "ZA", -30.5595, 22.9375)),
                "30" => Some(("Greece", "GR", 39.0742, 21.8243)),
                "31" => Some(("Netherlands", "NL", 52.1326, 5.2913)),
                "32" => Some(("Belgium", "BE", 50.5039, 4.4699)),
                "33" => Some(("France", "FR", 46.6034, 1.8883)),
                "34" => Some(("Spain", "ES", 40.4637, -3.7492)),
                "36" => Some(("Hungary", "HU", 47.1625, 19.5033)),
                "39" => Some(("Italy", "IT", 41.8719, 12.5674)),
                "40" => Some(("Romania", "RO", 45.9432, 24.9668)),
                "41" => Some(("Switzerland", "CH", 46.8182, 8.2275)),
                "43" => Some(("Austria", "AT", 47.5162, 14.5501)),
                "44" => Some(("United Kingdom", "GB", 55.3781, -3.4360)),
                "45" => Some(("Denmark", "DK", 56.2639, 9.5018)),
                "46" => Some(("Sweden", "SE", 60.1282, 18.6435)),
                "47" => Some(("Norway", "NO", 60.4720, 8.4689)),
                "48" => Some(("Poland", "PL", 51.9194, 19.1451)),
                "49" => Some(("Germany", "DE", 51.1657, 10.4515)),
                "51" => Some(("Peru", "PE", -9.1900, -75.0152)),
                "52" => Some(("Mexico", "MX", 23.6345, -102.5528)),
                "53" => Some(("Cuba", "CU", 21.5218, -77.7812)),
                "54" => Some(("Argentina", "AR", -38.4161, -63.6167)),
                "55" => Some(("Brazil", "BR", -14.2350, -51.9253)),
                "56" => Some(("Chile", "CL", -35.6751, -71.5430)),
                "57" => Some(("Colombia", "CO", 4.5709, -74.2973)),
                "58" => Some(("Venezuela", "VE", 6.4238, -66.5897)),
                "60" => Some(("Malaysia", "MY", 4.2105, 101.9758)),
                "61" => Some(("Australia", "AU", -25.2744, 133.7751)),
                "62" => Some(("Indonesia", "ID", -0.7893, 113.9213)),
                "63" => Some(("Philippines", "PH", 12.8797, 121.7740)),
                "64" => Some(("New Zealand", "NZ", -41.2865, 174.7762)),
                "65" => Some(("Singapore", "SG", 1.3521, 103.8198)),
                "66" => Some(("Thailand", "TH", 15.8700, 100.9925)),
                "81" => Some(("Japan", "JP", 36.2048, 138.2529)),
                "82" => Some(("South Korea", "KR", 35.9078, 127.7669)),
                "84" => Some(("Vietnam", "VN", 14.0583, 108.2772)),
                "86" => Some(("China", "CN", 35.8617, 104.1954)),
                "90" => Some(("Turkey", "TR", 38.9637, 35.2433)),
                "91" => Some(("India", "IN", 20.5937, 78.9629)),
                "92" => Some(("Pakistan", "PK", 30.3753, 69.3451)),
                "93" => Some(("Afghanistan", "AF", 33.9391, 67.7100)),
                "94" => Some(("Sri Lanka", "LK", 7.8731, 80.7718)),
                "95" => Some(("Myanmar", "MM", 21.9162, 95.9560)),
                "98" => Some(("Iran", "IR", 32.4279, 53.6880)),
                // 3-digit
                "212" => Some(("Morocco", "MA", 31.7917, -7.0926)),
                "213" => Some(("Algeria", "DZ", 28.0339, 1.6596)),
                "216" => Some(("Tunisia", "TN", 33.8869, 9.5375)),
                "218" => Some(("Libya", "LY", 26.3351, 17.2283)),
                "220" => Some(("Gambia", "GM", 13.4432, -15.3101)),
                "234" => Some(("Nigeria", "NG", 9.0820, 8.6753)),
                "254" => Some(("Kenya", "KE", -0.0236, 37.9062)),
                "255" => Some(("Tanzania", "TZ", -6.3690, 34.8888)),
                "256" => Some(("Uganda", "UG", 1.3733, 32.2903)),
                "351" => Some(("Portugal", "PT", 39.3999, -8.2245)),
                "353" => Some(("Ireland", "IE", 53.4129, -8.2439)),
                "354" => Some(("Iceland", "IS", 64.9631, -19.0208)),
                "358" => Some(("Finland", "FI", 61.9241, 25.7482)),
                "380" => Some(("Ukraine", "UA", 48.3794, 31.1656)),
                "852" => Some(("Hong Kong", "HK", 22.3193, 114.1694)),
                "853" => Some(("Macau", "MO", 22.1987, 113.5439)),
                "855" => Some(("Cambodia", "KH", 12.5657, 104.9910)),
                "856" => Some(("Laos", "LA", 19.8563, 102.4955)),
                "880" => Some(("Bangladesh", "BD", 23.6850, 90.3563)),
                "886" => Some(("Taiwan", "TW", 23.6978, 120.9605)),
                "960" => Some(("Maldives", "MV", 3.2028, 73.2207)),
                "961" => Some(("Lebanon", "LB", 33.8547, 35.8623)),
                "962" => Some(("Jordan", "JO", 30.5852, 36.2384)),
                "963" => Some(("Syria", "SY", 34.8021, 38.9968)),
                "964" => Some(("Iraq", "IQ", 33.2232, 43.6793)),
                "965" => Some(("Kuwait", "KW", 29.3117, 47.4818)),
                "966" => Some(("Saudi Arabia", "SA", 23.8859, 45.0792)),
                "971" => Some(("UAE", "AE", 23.4241, 53.8478)),
                "972" => Some(("Israel", "IL", 31.0461, 34.8516)),
                _ => None,
            } {
                return Some(result);
            }
        }
    }
    None
}
