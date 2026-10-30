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
/// The address is announced by an Australian consumer internet provider's AS (Telstra, Optus,
/// TPG, …): the operator's market, not proof that the address is a home connection.
pub const AU_CONSUMER_ISP: &str = "au-consumer-isp";
/// The address is announced by `AARNet`, Australia's research and education network.
pub const AU_ACADEMIC_NETWORK: &str = "au-academic-network";
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
/// A pivot that matched only by a name search — a knowledge-base or charity-register hit resolved
/// from a name alone — is a lead to review, not an identity match. [`crate::recursion`] never
/// dispatches an entity carrying this tag, whatever its confidence and whatever the operator's
/// expansion floor, because a name-only match is not corroborated enough to pursue a potentially
/// unrelated third party on its own; it still appears in the report as a lead.
pub const NAME_SEARCH_LEAD: &str = "name-search-lead";

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
/// An origin AS announces the prefix covering the address or block against a published ROA
/// (RPKI `invalid_asn` or `invalid_length`): a misconfiguration, a stale ROA or a hijack, not
/// proof of any.
pub const RPKI_INVALID_ORIGIN: &str = "rpki_invalid_origin";
/// RIS peers saw origin AS numbers other than the current ones announcing a prefix touching the
/// address or block: a transfer, an anycast or multi-homed operator, a leak or a hijack, not
/// proof of any.
pub const PREFIX_ORIGIN_HISTORY: &str = "prefix_origin_history";
