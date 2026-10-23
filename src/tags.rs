//! Canonical entity tag constants.

pub const BREACH: &str = "breach";
pub const STEALER_LOG: &str = "stealer-log";
/// The address is listed in a breach incident that its source flags as fabricated: unlikely to
/// have come from the named service, with little or no legitimate data. It describes the
/// incident, not the person.
pub const FABRICATED_BREACH: &str = "fabricated-breach";
/// The address is listed in an incident that its source flags as a spam list: the data did not
/// come from a security compromise. It describes the incident, not the person.
pub const SPAM_LIST: &str = "spam-list";
pub const WEB: &str = "web";
pub const SUBDOMAIN: &str = "subdomain";
/// The host has neither an A nor an AAAA record: its zone answered both queries with none.
/// Spiderfoot reports such a name as `INTERNET_NAME_UNRESOLVED`.
pub const UNRESOLVED: &str = "unresolved";
/// Another registered domain whose name is one edit or one look-alike character from the looked-up
/// domain's (`githuh.com`, `g00gle.com`); Spiderfoot reports it as `SIMILARDOMAIN`. It says the
/// names are confusable, not who holds either.
pub const LOOKALIKE: &str = "lookalike";
pub const WEB_SCRAPED: &str = "web-scraped";
pub const CT_LOG: &str = "ct-log";
pub const PTR: &str = "ptr";
pub const HIGH_EXPOSURE: &str = "high-exposure";
pub const PASTE_EXPOSED: &str = "paste-exposed";
pub const PASSWORD_AT_RISK: &str = "password-at-risk";
pub const MULTI_DEVICE: &str = "multi-device";
pub const MALICIOUS: &str = "malicious";
/// A Tor exit relay's address.
pub const TOR_EXIT: &str = "tor-exit";
pub const VULNERABLE: &str = "vulnerable";
pub const SOCIAL_PROFILE: &str = "social-profile";
pub const CANDIDATE: &str = "candidate";
pub const SEARCH_DISCOVERED: &str = "search-discovered";
pub const DERIVED: &str = "derived";
pub const NAME_DERIVED: &str = "name-derived";
pub const GEOINT: &str = "geoint";
/// The organisation a registration record names as the registrar.
pub const REGISTRAR: &str = "registrar";
/// A mailbox or telephone a registration record names for abuse reports.
pub const ABUSE_CONTACT: &str = "abuse-contact";
/// A mailbox or telephone a registration record names for another contact role.
pub const WHOIS_CONTACT: &str = "whois-contact";
/// A URL that is one public Wikipedia page edit, typed as `WIKIPEDIA_PAGE_EDIT`.
pub const WIKIPEDIA_EDIT: &str = "wikipedia-edit";
/// A URL that is one Apple App Store app page, typed as `APPSTORE_ENTRY`.
pub const APP_STORE_ENTRY: &str = "app-store";
