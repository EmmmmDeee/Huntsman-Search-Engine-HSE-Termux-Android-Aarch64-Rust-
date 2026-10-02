//! Static lookup tables for email domain geolocation.

/// Consumer webmail providers — domains that carry no geographic signal
/// because the SAME provider is reachable identically from anywhere (unlike
/// [`crate::util::domains::is_freemail`], which this list deliberately does
/// NOT delegate to: that canonical check also treats REGIONAL ISP webmail
/// brands — `bigpond.com`, `bigpond.net.au` — as freemail, but this module's
/// own `REGIONAL_PROVIDERS` table correctly treats them as a genuine AU geo
/// signal. `is_freemail`'s "no employer/ownership signal" and this list's "no
/// LOCATION signal" are different axes; consolidating them collapsed the
/// distinction and silently broke bigpond.com's geolocation).
///
/// Includes each brand's country-flavoured aliases (`hotmail.co.uk`,
/// `yahoo.de`, …) alongside the bare `.com` form — omitting them let the
/// identical globally-hosted provider fall through to ccTLD inference and be
/// geolocated as if the country-flavoured domain carried a real signal.
pub(super) const CONSUMER_PROVIDERS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "hotmail.co.uk",
    "hotmail.fr",
    "hotmail.de",
    "hotmail.it",
    "hotmail.es",
    "live.com",
    "live.co.uk",
    "live.fr",
    "live.de",
    "yahoo.com",
    "yahoo.co.uk",
    "yahoo.co.jp",
    "yahoo.co.in",
    "yahoo.fr",
    "yahoo.de",
    "yahoo.es",
    "yahoo.it",
    "yahoo.com.br",
    "yahoo.com.mx",
    "yahoo.com.ar",
    "aol.com",
    "icloud.com",
    "me.com",
    "protonmail.com",
    "proton.me",
    "mail.com",
    "gmx.com",
    "gmx.de",
    "yandex.ru",
    "yandex.com",
    "tutanota.com",
    "zoho.com",
    "fastmail.com",
];

/// Country-code TLD → region mappings. AU second-level TLDs are checked first
/// so they take priority over the bare `.au` entry.
pub(super) const CCTLD_REGIONS: &[(&str, &str)] = &[
    (".com.au", "Australia"),
    (".edu.au", "Australia"),
    (".gov.au", "Australia"),
    (".org.au", "Australia"),
    (".net.au", "Australia"),
    (".id.au", "Australia"),
    (".asn.au", "Australia"),
    // Catch-all for a direct `.au` registration and every other `.*.au` shape
    // (`.csiro.au`, …). MUST stay after the specific rows above:
    // `infer_geo_from_email_domain` returns the FIRST `ends_with` match, so the
    // specific second-level TLDs win first and this only backstops the residue.
    (".au", "Australia"),
    (".co.uk", "United Kingdom"),
    (".ac.uk", "United Kingdom"),
    (".gov.uk", "United Kingdom"),
    (".co.nz", "New Zealand"),
    (".co.za", "South Africa"),
    (".co.jp", "Japan"),
    (".co.kr", "South Korea"),
    (".com.br", "Brazil"),
    (".com.sg", "Singapore"),
    (".com.my", "Malaysia"),
    (".com.tr", "Turkey"),
    (".de", "Germany"),
    (".fr", "France"),
    (".it", "Italy"),
    (".es", "Spain"),
    (".nl", "Netherlands"),
    (".se", "Sweden"),
    (".no", "Norway"),
    (".dk", "Denmark"),
    (".fi", "Finland"),
    (".pl", "Poland"),
    (".ru", "Russia"),
    (".jp", "Japan"),
    (".kr", "South Korea"),
    (".cn", "China"),
    (".in", "India"),
    (".ca", "Canada"),
];

/// `(brand_token, provider_name, region)` — matched at label boundary.
pub(super) const REGIONAL_PROVIDERS: &[(&str, &str, &str)] = &[
    ("bigpond", "Telstra BigPond", "Australia"),
    ("optusnet", "Optus", "Australia"),
    ("iinet", "iiNet", "Australia"),
    ("internode", "Internode", "Australia"),
    ("tpg.com", "TPG", "Australia"),
    ("ozemail", "OzEmail", "Australia"),
    ("y7mail", "Yahoo7", "Australia"),
    ("btinternet", "BT Internet", "United Kingdom"),
    ("sky.com", "Sky UK", "United Kingdom"),
    ("virginmedia", "Virgin Media", "United Kingdom"),
    ("talktalk", "TalkTalk", "United Kingdom"),
    ("comcast", "Comcast", "United States"),
    ("charter", "Spectrum/Charter", "United States"),
    ("cox.net", "Cox", "United States"),
    ("verizon.net", "Verizon", "United States"),
    ("att.net", "AT&T", "United States"),
    ("t-online", "Deutsche Telekom", "Germany"),
    ("web.de", "WEB.DE", "Germany"),
    ("wanadoo", "Orange France", "France"),
    ("free.fr", "Free/Iliad", "France"),
    ("sfr.fr", "SFR", "France"),
    ("rogers.com", "Rogers", "Canada"),
    ("shaw.ca", "Shaw", "Canada"),
    ("bell.net", "Bell", "Canada"),
];
