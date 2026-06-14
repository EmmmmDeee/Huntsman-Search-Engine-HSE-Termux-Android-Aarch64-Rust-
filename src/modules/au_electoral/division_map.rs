//! Offline electoral division → geographic centroid mapping.
//!
//! Carries a static table of the 48 most-populous AEC electoral divisions so
//! that a confirmed division fires coordinates without an extra geocoding
//! round-trip. Same offline-first, API-second strategy used by au_unclaimed.

pub(super) struct DivisionInfo {
    pub(super) state: &'static str,
    pub(super) suburb: &'static str,
    pub(super) lat: f64,
    pub(super) lon: f64,
}

/// Offline centroid table for the 48 most-populous AEC electoral divisions.
/// Each entry is the geographic centroid of the division, tagged to its state.
/// Division names are lowercase-normalised for matching. Pure.
pub(super) fn division_centroid(division: &str) -> Option<DivisionInfo> {
    // Lowercase the input once for case-insensitive matching.
    let div = division.to_lowercase();
    // Table: (division_lc, state, suburb_label, lat, lon)
    const TABLE: &[(&str, &str, &str, f64, f64)] = &[
        // NSW
        ("sydney", "NSW", "Sydney CBD", -33.8688, 151.2093),
        ("north sydney", "NSW", "North Sydney", -33.8404, 151.2072),
        ("chifley", "NSW", "Fairfield", -33.8784, 150.9530),
        ("grayndler", "NSW", "Marrickville", -33.9099, 151.1577),
        ("kingsford smith", "NSW", "Botany", -33.9484, 151.1928),
        ("barton", "NSW", "Rockdale", -33.9518, 151.1330),
        ("watson", "NSW", "Eastlakes", -33.9273, 151.2167),
        ("reid", "NSW", "Camperdown", -33.8901, 151.1827),
        ("banks", "NSW", "Revesby", -33.9482, 151.0120),
        ("blaxland", "NSW", "Auburn", -33.8652, 150.9961),
        ("werriwa", "NSW", "Liverpool", -33.9200, 150.9239),
        ("fowler", "NSW", "Cabramatta", -33.8988, 150.9467),
        ("greenway", "NSW", "Quakers Hill", -33.7270, 150.8760),
        ("mitchell", "NSW", "Blacktown", -33.7690, 150.9068),
        ("parramatta", "NSW", "Parramatta", -33.8148, 151.0017),
        ("macquarie", "NSW", "Penrith", -33.7514, 150.6942),
        ("eden-monaro", "NSW", "Queanbeyan", -35.3530, 149.2340),
        ("newcastle", "NSW", "Newcastle", -32.9283, 151.7817),
        ("hunter", "NSW", "Cessnock", -32.8312, 151.3560),
        ("page", "NSW", "Lismore", -28.8133, 153.2752),
        // VIC
        ("melbourne", "VIC", "Melbourne CBD", -37.8136, 144.9631),
        ("wills", "VIC", "Coburg", -37.7408, 144.9651),
        ("batman", "VIC", "Preston", -37.7473, 145.0166),
        ("kooyong", "VIC", "Hawthorn", -37.8264, 145.0385),
        ("goldstein", "VIC", "Brighton", -37.9065, 145.0023),
        ("isaacs", "VIC", "Dandenong", -37.9870, 145.2150),
        ("holt", "VIC", "Cranbourne", -38.1098, 145.2828),
        ("bruce", "VIC", "Clayton", -37.9271, 145.1224),
        ("chisholm", "VIC", "Box Hill", -37.8191, 145.1239),
        ("deakin", "VIC", "Ringwood", -37.8148, 145.2300),
        ("lalor", "VIC", "Werribee", -37.9035, 144.6593),
        ("gorton", "VIC", "Sunshine", -37.7898, 144.8313),
        ("maribyrnong", "VIC", "Footscray", -37.8007, 144.9032),
        ("geelong", "VIC", "Geelong", -38.1499, 144.3617),
        ("ballarat", "VIC", "Ballarat", -37.5622, 143.8503),
        // QLD
        ("brisbane", "QLD", "Brisbane CBD", -27.4698, 153.0251),
        ("griffith", "QLD", "South Brisbane", -27.4869, 153.0222),
        ("ryan", "QLD", "Toowong", -27.4836, 152.9978),
        ("moreton", "QLD", "Springwood", -27.6170, 153.1220),
        ("bonner", "QLD", "Clayfield", -27.4097, 153.0487),
        ("lilley", "QLD", "Chermside", -27.3870, 153.0269),
        ("petrie", "QLD", "Redcliffe", -27.2310, 153.0990),
        ("dickson", "QLD", "Aspley", -27.3450, 153.0070),
        ("mcpherson", "QLD", "Robina", -28.0740, 153.3620),
        ("gold coast", "QLD", "Surfers Paradise", -28.0023, 153.4145),
        // SA
        ("boothby", "SA", "Mitcham", -35.0104, 138.5985),
        ("sturt", "SA", "West Lakes", -34.8820, 138.5038),
        ("adelaide", "SA", "Adelaide CBD", -34.9285, 138.6007),
        ("hindmarsh", "SA", "Hindmarsh", -34.9000, 138.5600),
        // WA
        ("perth", "WA", "Perth CBD", -31.9505, 115.8605),
        ("curtin", "WA", "Cottesloe", -31.9926, 115.7621),
        ("cowan", "WA", "Joondalup", -31.7440, 115.7680),
        ("burt", "WA", "Armadale", -32.1529, 116.0136),
        ("hasluck", "WA", "Midland", -31.8882, 116.0065),
        ("swan", "WA", "Midvale", -31.8800, 116.0360),
        ("fremantle", "WA", "Fremantle", -32.0569, 115.7439),
        ("canning", "WA", "Cannington", -32.0153, 115.9381),
        // ACT
        ("bean", "ACT", "Tuggeranong", -35.4244, 149.0886),
        ("canberra", "ACT", "Canberra", -35.2809, 149.1300),
        ("fenner", "ACT", "Gungahlin", -35.1823, 149.1332),
        // TAS
        ("bass", "TAS", "Launceston", -41.4332, 147.1441),
        ("braddon", "TAS", "Devonport", -41.1800, 146.3500),
        ("clark", "TAS", "Hobart", -42.8821, 147.3272),
        ("franklin", "TAS", "Kingston", -42.9773, 147.2804),
        ("lyons", "TAS", "New Norfolk", -42.7820, 147.0580),
        // NT
        ("lingiari", "NT", "Darwin", -12.4634, 130.8456),
        ("solomon", "NT", "Darwin CBD", -12.4578, 130.8413),
    ];
    TABLE
        .iter()
        .find(|(d, _, _, _, _)| *d == div.as_str())
        .map(|(_, state, suburb, lat, lon)| DivisionInfo {
            state,
            suburb,
            lat: *lat,
            lon: *lon,
        })
}

/// Cheap heuristic: map common division name suffixes to an AU state. Used
/// when the division isn't in the offline centroid table. Pure.
pub(super) fn infer_state_from_division(division: &str) -> Option<&'static str> {
    let lc = division.to_lowercase();
    // Some divisions carry clear state signals in their name.
    if lc.contains("sydney")
        || lc.contains("parramatta")
        || lc.contains("hunter")
        || lc.contains("newcastle")
    {
        Some("NSW")
    } else if lc.contains("melbourne") || lc.contains("geelong") || lc.contains("ballarat") {
        Some("VIC")
    } else if lc.contains("brisbane") || lc.contains("gold coast") {
        Some("QLD")
    } else if lc.contains("perth") || lc.contains("fremantle") {
        Some("WA")
    } else if lc.contains("adelaide") {
        Some("SA")
    } else if lc.contains("hobart") || lc.contains("launceston") {
        Some("TAS")
    } else if lc.contains("canberra") || lc.contains("darwin") {
        Some("ACT")
    } else {
        None
    }
}
