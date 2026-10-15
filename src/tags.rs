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
pub const CRAWLED: &str = "crawled";
pub const SUBDOMAIN: &str = "subdomain";
/// The host has neither an A nor an AAAA record: its zone answered both queries with none.
/// Spiderfoot reports such a name as `INTERNET_NAME_UNRESOLVED`.
pub const UNRESOLVED: &str = "unresolved";
pub const EXTERNAL: &str = "external";
pub const WEB_SCRAPED: &str = "web-scraped";
pub const CT_LOG: &str = "ct-log";
pub const PTR: &str = "ptr";
pub const HIGH_EXPOSURE: &str = "high-exposure";
pub const PASTE_EXPOSED: &str = "paste-exposed";
pub const PASSWORD_AT_RISK: &str = "password-at-risk";
pub const MULTI_DEVICE: &str = "multi-device";
pub const MALICIOUS: &str = "malicious";
pub const VULNERABLE: &str = "vulnerable";
pub const SOCIAL_PROFILE: &str = "social-profile";
pub const CANDIDATE: &str = "candidate";
pub const SEARCH_DISCOVERED: &str = "search-discovered";
pub const BREACH_DERIVED: &str = "breach-derived";
pub const RECALLED: &str = "recalled";
pub const DERIVED: &str = "derived";
pub const RECYCLED: &str = "recycled";
pub const NAME_DERIVED: &str = "name-derived";
pub const SOURCE_DOCUMENT: &str = "source-document";
pub const GEOINT: &str = "geoint";
pub const COARSE: &str = "coarse";
pub const HOSTING: &str = "hosting";
/// The organisation a registration record names as the registrar.
pub const REGISTRAR: &str = "registrar";
/// A mailbox or telephone a registration record names for abuse reports.
pub const ABUSE_CONTACT: &str = "abuse-contact";
/// A mailbox or telephone a registration record names for another contact role.
pub const WHOIS_CONTACT: &str = "whois-contact";
