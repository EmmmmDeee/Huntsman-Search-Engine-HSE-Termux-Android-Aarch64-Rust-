//! Offline city→coordinate lookup used for inline geocoding of address strings
//! without a network call. Covers AU capitals, major regional centres, NT/SA/
//! WA/TAS hubs, key QLD suburbs (Lockyer Valley corridor, inner Brisbane, Gold
//! Coast strip), plus representative US/UK/NZ cities. Returns the first match
//! whose name is contained in the lowercased input.

/// Look up approximate `(lat, lon)` for the city/suburb named in `addr`.
/// Returns `None` when no entry matches — callers should treat a miss as
/// "unknown city" rather than an error.
///
/// Matches city names as whole words or phrases (split on comma/space delimiters),
/// not substrings — prevents "Logan Square, Chicago" from matching the "logan" QLD
/// entry. Multi-word cities ("North Lakes", "Sunshine Coast") are matched as
/// phrases.
///
/// Falls back to [`postcode_coords`] when `addr` is a bare 4-digit AU
/// postcode (e.g. `"4000"` → Brisbane CBD) so postcode-only addresses from
/// breach records and search snippets still resolve offline.
pub fn city_coords(addr: &str) -> Option<(f64, f64)> {
    let trimmed = addr.trim();
    let lower = trimmed.to_lowercase();

    // Split on comma + space (common address delimiter), then on space alone
    // for entries like "North Lakes". Check each possible phrase/word match
    // against the full CITIES table.
    for &(city, lat, lon) in CITIES {
        // Check for exact multi-word phrase match first (e.g. "North Lakes", "Sunshine Coast").
        if city.contains(' ') && lower.contains(city) {
            return Some((lat, lon));
        }
        // For single-word entries, check whole-word match via comma/space delimiters.
        if !city.contains(' ') {
            for part in lower.split(|c: char| c == ',' || c.is_whitespace()) {
                if part == city {
                    return Some((lat, lon));
                }
            }
        }
    }
    // Last-resort: treat a bare 4-digit string as a postcode — the exact suburb
    // centroid when tabulated, else the region centroid by leading digits so the
    // whole AU postcode space resolves offline.
    if trimmed.len() == 4 && trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return postcode_coords(trimmed).or_else(|| au_postcode_region(trimmed));
    }
    // Full address string with no tabulated suburb: pull the embedded AU
    // postcode (`"12 Smith St, Maleny QLD 4552"`) and resolve it offline. This
    // closes the common gap where a real address carries a resolvable postcode
    // but its suburb is in the long tail CITIES doesn't tabulate — the address
    // still earns a coordinate (exact suburb centroid when known, else region
    // grain) instead of silently dropping out of the geo footprint.
    // The embedded-postcode fallback is an *Australian* heuristic, so it must not
    // fire on an address that explicitly names a non-AU country: a foreign suburb
    // we don't tabulate must earn no coordinate rather than borrow an Australian
    // one. (The final-run anchoring above already rejects the common case — a
    // foreign 5-digit ZIP leaves no 4-digit trailing run — and this guard closes
    // the residual where an overseas postcode is itself 4 digits.)
    if !mentions_non_au_country(&lower)
        && let Some(pc) = au_postcode_in(trimmed)
    {
        return postcode_coords(pc).or_else(|| au_postcode_region(pc));
    }
    None
}

/// Whether `lower` (an already-lowercased address/location string) explicitly
/// names a country or nation that is definitively NOT Australia.
///
/// Used to gate the embedded-AU-postcode fallback in [`city_coords`] so a clearly
/// overseas address never borrows an Australian coordinate from a 4-digit token
/// that merely falls in an AU postcode range. Multi-word nations are matched as
/// phrases; the short ISO-style codes are matched as whole alphanumeric tokens so
/// they cannot fire inside an ordinary word. Australia and its state names are
/// never listed, so a genuine AU address is never gated. Pure; no I/O.
fn mentions_non_au_country(lower: &str) -> bool {
    const PHRASES: &[&str] = &["united states", "united kingdom", "new zealand"];
    if PHRASES.iter().any(|p| lower.contains(p)) {
        return true;
    }
    // Whole-token codes/names. "wales" is deliberately absent — it is a substring
    // of "New South Wales" and would gate legitimate NSW addresses.
    const TOKENS: &[&str] = &[
        "usa", "us", "uk", "gb", "nz", "canada", "england", "scotland", "ireland", "germany",
        "france",
    ];
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| TOKENS.contains(&tok))
}

/// Resolve a bare 4-digit AU postcode to an approximate `(lat, lon)`.
///
/// Delegates to the single source of truth — the ground-truth offline gazetteer
/// in [`crate::util::postcode_au::offline_centroid`] (~100 AU postcodes: capital
/// CBDs, capital-city suburbs across every state, and the high-traffic regional
/// centres) — returning its principal-locality centroid. Previously this carried
/// its own 22-entry subset that could drift from the gazetteer; sharing the one
/// table both widens coverage and removes that risk. Returns `None` for a
/// postcode the gazetteer doesn't tabulate (callers then fall back to the
/// leading-digits region centroid via [`au_postcode_region`]).
pub fn postcode_coords(postcode: &str) -> Option<(f64, f64)> {
    crate::util::postcode_au::offline_centroid(postcode)
}

/// Coarse REGION centroid for *any* AU postcode, by its leading two digits.
///
/// AU postcodes are allocated geographically and contiguously, so the first two
/// digits localise a postcode to a region (state + part of state) even when its
/// exact centroid isn't tabulated in [`postcode_coords`]. This gives offline,
/// keyless geocoding for the whole AU postcode space at region grain — enough to
/// answer "is this relative's postcode in the subject's area?" for the free
/// family geo-corroboration. Prefer [`postcode_coords`] (exact suburb) when it
/// has the postcode; fall back to this for the long tail. `None` for a non-AU or
/// malformed postcode.
#[must_use]
pub fn au_postcode_region(postcode: &str) -> Option<(f64, f64)> {
    let pc = postcode.trim();
    if pc.len() != 4 || !pc.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // (leading two digits) -> approximate region centroid.
    const REGIONS: &[(&str, f64, f64)] = &[
        // QLD (4xxx) — finest grain: the AU family-finding use case.
        ("40", -27.47, 153.03), // Brisbane
        ("41", -27.70, 153.15), // Logan / Redland / GC hinterland
        ("42", -28.01, 153.40), // Gold Coast
        ("43", -27.60, 152.55), // Ipswich / Lockyer / eastern Downs
        ("44", -26.30, 152.70), // Sunshine Coast north / Gympie
        ("45", -26.45, 152.80), // Sunshine Coast / Moreton north / Wide Bay
        ("46", -27.55, 151.90), // Toowoomba / Darling Downs
        ("47", -22.50, 148.50), // Central QLD (Rockhampton / Mackay)
        ("48", -18.50, 146.00), // North QLD (Townsville / Cairns)
        ("49", -17.00, 144.50), // Far North / Gulf
        // NSW + ACT (2xxx).
        ("20", -33.87, 151.21),
        ("21", -33.80, 151.00),
        ("22", -34.00, 151.10),
        ("23", -34.43, 150.89),
        ("24", -32.50, 152.00),
        ("25", -34.50, 149.50),
        ("26", -35.28, 149.13), // ACT / south coast
        ("27", -35.10, 147.37), // Riverina
        ("28", -31.00, 150.90), // north-west
        ("29", -29.00, 152.50), // northern rivers
        // VIC (3xxx).
        ("30", -37.81, 144.96),
        ("31", -37.80, 145.10),
        ("32", -38.15, 144.36),
        ("33", -36.76, 144.28),
        ("34", -38.10, 146.40),
        ("35", -36.40, 145.40),
        ("36", -36.40, 142.20),
        ("38", -34.18, 142.16),
        ("39", -37.50, 144.50),
        // SA (5xxx).
        ("50", -34.93, 138.60),
        ("51", -34.90, 138.60),
        ("52", -35.20, 138.60),
        ("53", -34.20, 140.34),
        ("54", -33.00, 137.50),
        ("55", -32.49, 137.77),
        ("56", -37.83, 140.78),
        ("57", -34.70, 135.86),
        // WA (6xxx).
        ("60", -31.95, 115.86),
        ("61", -31.90, 115.90),
        ("62", -32.05, 115.74),
        ("63", -33.33, 115.64),
        ("64", -33.65, 115.34),
        ("65", -28.77, 114.62),
        ("66", -30.75, 121.47),
        ("67", -17.96, 122.24),
        // TAS (7xxx).
        ("70", -42.88, 147.33),
        ("72", -41.18, 146.35),
        ("73", -41.44, 147.14),
        // NT (08xx / 09xx).
        ("08", -12.46, 130.84),
        ("09", -19.65, 134.19),
    ];
    let prefix = &pc[..2];
    if let Some(&(_, lat, lon)) = REGIONS.iter().find(|(pre, _, _)| *pre == prefix) {
        return Some((lat, lon));
    }
    // Capital fallback for the ranges with no dedicated region row: the
    // non-geographic large-volume-receiver / PO-box spans (NSW 1xxx, VIC 8xxx,
    // QLD 9xxx) and the sparse state tails (e.g. VIC 37xx alpine, SA 58/59xx, WA
    // 68/69xx, TAS 71/74–79xx). These are all allocated from the state capital,
    // so the capital centroid is the correct coarse fix — and resolving to it
    // (rather than `None`) makes the documented promise that the WHOLE AU
    // postcode space geocodes offline literally true, so no AU address silently
    // drops out of the geo footprint. Only reached after the 2-digit miss, so it
    // never overrides a more precise region row.
    let capital = match pc.as_bytes()[0] {
        b'1' => (-33.87, 151.21), // NSW large-volume receiver → Sydney
        b'3' => (-37.81, 144.96), // VIC alpine / fringe tail → Melbourne
        b'5' => (-34.93, 138.60), // SA tail → Adelaide
        b'6' => (-31.95, 115.86), // WA tail → Perth
        b'7' => (-42.88, 147.33), // TAS tail → Hobart
        b'8' => (-37.81, 144.96), // VIC large-volume receiver → Melbourne
        b'9' => (-27.47, 153.03), // QLD large-volume receiver → Brisbane
        _ => return None,
    };
    Some(capital)
}

/// Extract the AU postcode embedded in a free-text address string.
///
/// An AU address places its 4-digit postcode LAST (`"… SUBURB STATE 4000"`) — it
/// is the *final* run of digits in the string, with the street number leading.
/// So this takes only the LAST numeric run and accepts it solely when it is a
/// real assigned 4-digit AU postcode ([`crate::util::address_au::state_for_postcode`]).
///
/// Anchoring on the final run (rather than the last 4-digit token *anywhere*) is
/// what keeps a 4-digit STREET number from being mistaken for the postcode. The
/// previous "last 4-digit token" heuristic broke on overseas addresses: a US
/// address ends in a 5-digit ZIP (not a 4-digit token), so the only 4-digit token
/// left was the leading street number — `"5528 North 73rd Avenue, Glendale, AZ,
/// 85303"` resolved `5528` as an SA postcode and manufactured a false Australian
/// coordinate (observed across real breach records). Now the final run there is
/// `"85303"` (5 digits → rejected) and the leading `5528` is never considered, so
/// the address earns no AU fix. A genuine AU address still resolves: `"4000 Gold
/// Coast Hwy, … QLD 4217"` → final run `4217` (the street number `4000` leads, so
/// it is not the final run). Returns `None` when the trailing run is not an
/// assigned 4-digit AU postcode, or when that run is the `+4` add-on of a US
/// ZIP+4 (`NNNNN-NNNN`) — there the trailing four digits are a US ZIP extension,
/// never an AU postcode, so `"…, NV, 89436-9322"` must not borrow the QLD region
/// for `9322`. Pure; no I/O.
fn au_postcode_in(addr: &str) -> Option<&str> {
    let bytes = addr.as_bytes();
    // The FINAL run of ASCII digits — an AU postcode trails the suburb and state.
    let end = bytes.iter().rposition(u8::is_ascii_digit)? + 1;
    let mut start = end;
    while start > 0 && bytes[start - 1].is_ascii_digit() {
        start -= 1;
    }
    let last_run = &addr[start..end];
    if last_run.len() != 4 || crate::util::address_au::state_for_postcode(last_run).is_none() {
        return None;
    }
    // US ZIP+4 guard: a trailing 4-digit run immediately preceded by `<5 digits>-`
    // is the `+4` extension of a US ZIP, not an AU postcode. A genuine AU postcode
    // follows the state after a space/comma ("… QLD 4217"), never a `#####-`.
    if start >= 6
        && bytes[start - 1] == b'-'
        && bytes[start - 6..start - 1].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    Some(last_run)
}

const CITIES: &[(&str, f64, f64)] = &[
    // Australian capitals + major cities
    ("brisbane", -27.4698, 153.0251),
    ("sydney", -33.8688, 151.2093),
    ("melbourne", -37.8136, 144.9631),
    ("perth", -31.9505, 115.8605),
    ("adelaide", -34.9285, 138.6007),
    ("canberra", -35.2809, 149.1300),
    ("hobart", -42.8821, 147.3272),
    ("darwin", -12.4634, 130.8456),
    ("gold coast", -28.0167, 153.4000),
    ("sunshine coast", -26.6500, 153.0667),
    ("cairns", -16.9186, 145.7781),
    ("townsville", -19.2590, 146.8169),
    ("toowoomba", -27.5598, 151.9507),
    ("rockhampton", -23.3791, 150.5100),
    // QLD suburbs + regional
    ("gatton", -27.5567, 152.2767),
    ("laidley", -27.6333, 152.3833),
    ("lockyer valley", -27.5567, 152.2767),
    ("helidon", -27.5500, 152.1167),
    ("plainland", -27.5667, 152.4167),
    ("forest hill", -27.5833, 152.3500),
    ("nundah", -27.4017, 153.0600),
    ("redcliffe", -27.2289, 153.1050),
    ("caboolture", -27.0847, 152.9511),
    ("chermside", -27.3861, 153.0331),
    ("aspley", -27.3650, 153.0167),
    ("strathpine", -27.3050, 152.9900),
    ("north lakes", -27.2281, 153.0019),
    ("ipswich", -27.6167, 152.7667),
    ("logan", -27.6389, 153.1092),
    ("springfield", -27.6667, 152.9167),
    ("surfers paradise", -28.0029, 153.4300),
    ("broadbeach", -28.0264, 153.4307),
    ("robina", -28.0744, 153.3842),
    ("coolangatta", -28.1667, 153.5333),
    ("nerang", -27.9897, 153.3372),
    ("bundaberg", -24.8661, 152.3489),
    ("hervey bay", -25.2881, 152.8411),
    ("gladstone", -23.8488, 151.2673),
    ("mount isa", -20.7264, 139.4928),
    ("mackay", -21.1411, 149.1861),
    ("maryborough", -25.5411, 152.7028),
    ("warwick", -28.2167, 152.0333),
    ("dalby", -27.1833, 151.2667),
    ("kingaroy", -26.5400, 151.8400),
    ("stanthorpe", -28.6567, 151.9333),
    ("goondiwindi", -28.5500, 150.3000),
    ("chinchilla", -26.7333, 150.6333),
    ("morayfield", -27.1167, 152.9667),
    ("burpengary", -27.1667, 152.9667),
    ("narangba", -27.2000, 152.9667),
    ("kallangur", -27.2667, 152.9833),
    ("petrie", -27.2667, 152.9833),
    ("bracken ridge", -27.3333, 153.0333),
    ("sandgate", -27.3239, 153.0672),
    ("shorncliffe", -27.3300, 153.0800),
    ("deagon", -27.3500, 153.0667),
    ("fortitude valley", -27.4570, 153.0320),
    ("new farm", -27.4661, 153.0510),
    ("teneriffe", -27.4556, 153.0444),
    ("woolloongabba", -27.4939, 153.0333),
    ("south brisbane", -27.4800, 153.0200),
    ("west end", -27.4800, 153.0133),
    ("kangaroo point", -27.4833, 153.0400),
    ("spring hill", -27.4600, 153.0233),
    ("paddington", -27.4600, 152.9900),
    ("milton", -27.4667, 152.9833),
    ("toowong", -27.4833, 152.9833),
    ("indooroopilly", -27.5000, 152.9667),
    ("st lucia", -27.4986, 153.0036),
    ("taringa", -27.5000, 152.9833),
    ("beenleigh", -27.7167, 153.2000),
    ("capalaba", -27.5167, 153.2000),
    ("cleveland", -27.5333, 153.2667),
    ("wynnum", -27.4333, 153.1667),
    ("tweed heads", -28.1781, 153.5506),
    ("withcott", -27.5667, 152.2167),
    ("caboolture south", -27.1167, 152.9667),
    // NT
    ("alice springs", -23.6980, 133.8807),
    ("katherine", -14.4650, 132.2635),
    ("nhulunbuy", -12.1811, 136.7756),
    // SA
    ("mount gambier", -37.8307, 140.7828),
    ("whyalla", -33.0350, 137.5667),
    ("port augusta", -32.4939, 137.7650),
    ("port pirie", -33.1858, 138.0178),
    ("victor harbor", -35.5572, 138.6172),
    // WA
    ("fremantle", -32.0569, 115.7439),
    ("mandurah", -32.5264, 115.7239),
    ("bunbury", -33.3258, 115.6397),
    ("albany", -35.0269, 117.8836),
    ("geraldton", -28.7744, 114.6153),
    ("kalgoorlie", -30.7490, 121.4658),
    // TAS
    ("launceston", -41.4388, 147.1347),
    ("devonport", -41.1769, 146.3506),
    ("burnie", -41.0553, 145.9058),
    // NSW regional
    ("newcastle", -32.9283, 151.7817),
    ("wollongong", -34.4278, 150.8931),
    ("central coast", -33.3000, 151.3500),
    ("tamworth", -31.0833, 150.9167),
    ("wagga wagga", -35.1083, 147.3598),
    ("albury", -36.0737, 146.9135),
    ("orange", -33.2833, 149.1000),
    ("bathurst", -33.4167, 149.5833),
    ("dubbo", -32.2569, 148.6011),
    // VIC regional
    ("geelong", -38.1499, 144.3617),
    ("ballarat", -37.5622, 143.8503),
    ("bendigo", -36.7570, 144.2794),
    ("shepparton", -36.3833, 145.3833),
    // US cities
    ("new york", 40.7128, -74.0060),
    ("los angeles", 33.9425, -118.2551),
    ("chicago", 41.8781, -87.6298),
    ("houston", 29.7604, -95.3698),
    ("phoenix", 33.4484, -111.9490),
    ("san francisco", 37.7749, -122.4194),
    ("seattle", 47.6062, -122.3321),
    ("denver", 39.7392, -104.9903),
    ("colorado springs", 38.8339, -104.8214),
    ("colo springs", 38.8339, -104.8214),
    ("philadelphia", 39.9526, -75.1652),
    ("san antonio", 29.4241, -98.4936),
    ("dallas", 32.7767, -96.7970),
    ("san jose", 37.3382, -121.8863),
    ("austin", 30.2672, -97.7431),
    ("jacksonville", 30.3322, -81.6557),
    ("columbus", 39.9612, -82.9988),
    ("miami", 25.7617, -80.1918),
    ("boston", 42.3601, -71.0589),
    ("atlanta", 33.7490, -84.3880),
    ("portland", 45.5152, -122.6784),
    ("las vegas", 36.1699, -115.1398),
    ("nashville", 36.1627, -86.7816),
    ("minneapolis", 44.9778, -93.2650),
    // UK cities
    ("london", 51.5074, -0.1278),
    ("manchester", 53.4808, -2.2426),
    ("birmingham", 52.4862, -1.8904),
    ("leeds", 53.8008, -1.5491),
    ("glasgow", 55.8642, -4.2518),
    ("liverpool", 53.4084, -2.9916),
    ("edinburgh", 55.9533, -3.1883),
    ("bristol", 51.4545, -2.5879),
    // NZ cities
    ("auckland", -36.8485, 174.7633),
    ("wellington", -41.2865, 174.7762),
    ("christchurch", -43.5321, 172.6362),
];

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
