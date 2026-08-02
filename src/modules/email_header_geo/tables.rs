//! Static lookup tables for email domain geolocation.

/// Consumer webmail providers — domains that carry no geographic signal.
pub(super) const CONSUMER_PROVIDERS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "yahoo.co.uk",
    "yahoo.co.jp",
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

/// Recognised second-level-domain conventions under a ccTLD (`.com.au`,
/// `.co.uk`, …) — distinct from [`crate::util::cctld::CCTLD_COUNTRY`]'s
/// bare-TLD-only facts, since these encode a country's own SLD registration
/// convention, not just its TLD. Checked first by
/// [`super::infer::infer_geo_from_email_domain`] so a convention match wins
/// over the generic bare-TLD fallback (matters once a bare `.au`/`.uk`/…
/// entry is reachable via that fallback, so the more specific match must be
/// tried first).
pub(super) const SLD_CONVENTIONS: &[(&str, &str)] = &[
    (".com.au", "Australia"),
    (".edu.au", "Australia"),
    (".gov.au", "Australia"),
    (".org.au", "Australia"),
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
