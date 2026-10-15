//! Spiderfoot 4.0's data-element types, and the ones Huntsman adds.
//!
//! The catalogue is Spiderfoot's own `tbl_event_types` (spiderfoot/db.py, MIT), in its order, with
//! each type's description, whether it is raw data, and its category. Huntsman types that
//! Spiderfoot has no name for start with `HSE_`. This is the one list of type names: `sf -T`, the
//! `-t` filter, the saved-scan elements and `/api/eventtypes` all read it.

use serde::Serialize;

use crate::entity::EntityKind;

/// Spiderfoot's grouping of a type: what kind of thing an element of it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Category {
    /// The scan's root.
    Internal,
    /// A thing: a host, an address, a name.
    Entity,
    /// Something said about an entity: malicious, vulnerable, compromised.
    Descriptor,
    /// Content found while scanning: pages, records, raw answers.
    Data,
    /// Part of an entity: a port, a banner.
    Subentity,
}

impl Category {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "INTERNAL",
            Self::Entity => "ENTITY",
            Self::Descriptor => "DESCRIPTOR",
            Self::Data => "DATA",
            Self::Subentity => "SUBENTITY",
        }
    }
}

/// One data-element type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SfType {
    #[serde(rename = "type")]
    pub code: &'static str,
    pub description: &'static str,
    /// Raw data (a page, a record) rather than a parsed value.
    pub raw: bool,
    pub category: Category,
}

impl SfType {
    const fn new(
        code: &'static str,
        description: &'static str,
        raw: bool,
        category: Category,
    ) -> Self {
        Self {
            code,
            description,
            raw,
            category,
        }
    }
}

/// The types Huntsman finds that Spiderfoot has no name for.
const HUNTSMAN_TYPES: [SfType; 8] = [
    SfType::new("HSE_API_KEY", "API Key (HSE)", false, Category::Descriptor),
    SfType::new(
        "HSE_COMPANY_REGISTRATION",
        "Company Registration Number (HSE)",
        false,
        Category::Entity,
    ),
    SfType::new(
        "HSE_CRYPTO_ADDRESS",
        "Crypto Address (HSE)",
        false,
        Category::Entity,
    ),
    SfType::new(
        "HSE_DEVICE_ID",
        "Device Identifier (HSE)",
        false,
        Category::Entity,
    ),
    SfType::new("HSE_DOCUMENT", "Document (HSE)", false, Category::Data),
    SfType::new(
        "HSE_MAC_ADDRESS",
        "MAC Address (HSE)",
        false,
        Category::Entity,
    ),
    SfType::new("HSE_OTHER", "Other (HSE)", false, Category::Data),
    SfType::new(
        "HSE_WIFI_SSID",
        "Wi-Fi Network Name (HSE)",
        false,
        Category::Entity,
    ),
];

/// Spiderfoot 4.0's types, in its order.
const SPIDERFOOT_TYPES: [SfType; 172] = [
    SfType::new(
        "ROOT",
        "Internal SpiderFoot Root event",
        true,
        Category::Internal,
    ),
    SfType::new(
        "ACCOUNT_EXTERNAL_OWNED",
        "Account on External Site",
        false,
        Category::Entity,
    ),
    SfType::new(
        "ACCOUNT_EXTERNAL_OWNED_COMPROMISED",
        "Hacked Account on External Site",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED",
        "Hacked User Account on External Site",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "AFFILIATE_EMAILADDR",
        "Affiliate - Email Address",
        false,
        Category::Entity,
    ),
    SfType::new(
        "AFFILIATE_INTERNET_NAME",
        "Affiliate - Internet Name",
        false,
        Category::Entity,
    ),
    SfType::new(
        "AFFILIATE_INTERNET_NAME_HIJACKABLE",
        "Affiliate - Internet Name Hijackable",
        false,
        Category::Entity,
    ),
    SfType::new(
        "AFFILIATE_INTERNET_NAME_UNRESOLVED",
        "Affiliate - Internet Name - Unresolved",
        false,
        Category::Entity,
    ),
    SfType::new(
        "AFFILIATE_IPADDR",
        "Affiliate - IP Address",
        false,
        Category::Entity,
    ),
    SfType::new(
        "AFFILIATE_IPV6_ADDRESS",
        "Affiliate - IPv6 Address",
        false,
        Category::Entity,
    ),
    SfType::new(
        "AFFILIATE_WEB_CONTENT",
        "Affiliate - Web Content",
        true,
        Category::Data,
    ),
    SfType::new(
        "AFFILIATE_DOMAIN_NAME",
        "Affiliate - Domain Name",
        false,
        Category::Entity,
    ),
    SfType::new(
        "AFFILIATE_DOMAIN_UNREGISTERED",
        "Affiliate - Domain Name Unregistered",
        false,
        Category::Entity,
    ),
    SfType::new(
        "AFFILIATE_COMPANY_NAME",
        "Affiliate - Company Name",
        false,
        Category::Entity,
    ),
    SfType::new(
        "AFFILIATE_DOMAIN_WHOIS",
        "Affiliate - Domain Whois",
        true,
        Category::Data,
    ),
    SfType::new(
        "AFFILIATE_DESCRIPTION_CATEGORY",
        "Affiliate Description - Category",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "AFFILIATE_DESCRIPTION_ABSTRACT",
        "Affiliate Description - Abstract",
        false,
        Category::Descriptor,
    ),
    SfType::new("APPSTORE_ENTRY", "App Store Entry", false, Category::Entity),
    SfType::new(
        "CLOUD_STORAGE_BUCKET",
        "Cloud Storage Bucket",
        false,
        Category::Entity,
    ),
    SfType::new(
        "CLOUD_STORAGE_BUCKET_OPEN",
        "Cloud Storage Bucket Open",
        false,
        Category::Descriptor,
    ),
    SfType::new("COMPANY_NAME", "Company Name", false, Category::Entity),
    SfType::new(
        "CREDIT_CARD_NUMBER",
        "Credit Card Number",
        false,
        Category::Entity,
    ),
    SfType::new("BASE64_DATA", "Base64-encoded Data", true, Category::Data),
    SfType::new(
        "BITCOIN_ADDRESS",
        "Bitcoin Address",
        false,
        Category::Entity,
    ),
    SfType::new(
        "BITCOIN_BALANCE",
        "Bitcoin Balance",
        false,
        Category::Descriptor,
    ),
    SfType::new("BGP_AS_OWNER", "BGP AS Ownership", false, Category::Entity),
    SfType::new(
        "BGP_AS_MEMBER",
        "BGP AS Membership",
        false,
        Category::Entity,
    ),
    SfType::new(
        "BLACKLISTED_COHOST",
        "Blacklisted Co-Hosted Site",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "BLACKLISTED_INTERNET_NAME",
        "Blacklisted Internet Name",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "BLACKLISTED_AFFILIATE_INTERNET_NAME",
        "Blacklisted Affiliate Internet Name",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "BLACKLISTED_IPADDR",
        "Blacklisted IP Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "BLACKLISTED_AFFILIATE_IPADDR",
        "Blacklisted Affiliate IP Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "BLACKLISTED_SUBNET",
        "Blacklisted IP on Same Subnet",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "BLACKLISTED_NETBLOCK",
        "Blacklisted IP on Owned Netblock",
        false,
        Category::Descriptor,
    ),
    SfType::new("COUNTRY_NAME", "Country Name", false, Category::Entity),
    SfType::new("CO_HOSTED_SITE", "Co-Hosted Site", false, Category::Entity),
    SfType::new(
        "CO_HOSTED_SITE_DOMAIN",
        "Co-Hosted Site - Domain Name",
        false,
        Category::Entity,
    ),
    SfType::new(
        "CO_HOSTED_SITE_DOMAIN_WHOIS",
        "Co-Hosted Site - Domain Whois",
        true,
        Category::Data,
    ),
    SfType::new(
        "DARKNET_MENTION_URL",
        "Darknet Mention URL",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "DARKNET_MENTION_CONTENT",
        "Darknet Mention Web Content",
        true,
        Category::Data,
    ),
    SfType::new("DATE_HUMAN_DOB", "Date of Birth", false, Category::Entity),
    SfType::new(
        "DEFACED_INTERNET_NAME",
        "Defaced",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "DEFACED_IPADDR",
        "Defaced IP Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "DEFACED_AFFILIATE_INTERNET_NAME",
        "Defaced Affiliate",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "DEFACED_COHOST",
        "Defaced Co-Hosted Site",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "DEFACED_AFFILIATE_IPADDR",
        "Defaced Affiliate IP Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "DESCRIPTION_CATEGORY",
        "Description - Category",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "DESCRIPTION_ABSTRACT",
        "Description - Abstract",
        false,
        Category::Descriptor,
    ),
    SfType::new("DEVICE_TYPE", "Device Type", false, Category::Descriptor),
    SfType::new("DNS_TEXT", "DNS TXT Record", false, Category::Data),
    SfType::new("DNS_SRV", "DNS SRV Record", false, Category::Data),
    SfType::new("DNS_SPF", "DNS SPF Record", false, Category::Data),
    SfType::new("DOMAIN_NAME", "Domain Name", false, Category::Entity),
    SfType::new(
        "DOMAIN_NAME_PARENT",
        "Domain Name (Parent)",
        false,
        Category::Entity,
    ),
    SfType::new(
        "DOMAIN_REGISTRAR",
        "Domain Registrar",
        false,
        Category::Entity,
    ),
    SfType::new("DOMAIN_WHOIS", "Domain Whois", true, Category::Data),
    SfType::new("EMAILADDR", "Email Address", false, Category::Entity),
    SfType::new(
        "EMAILADDR_COMPROMISED",
        "Hacked Email Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "EMAILADDR_DELIVERABLE",
        "Deliverable Email Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "EMAILADDR_DISPOSABLE",
        "Disposable Email Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "EMAILADDR_GENERIC",
        "Email Address - Generic",
        false,
        Category::Entity,
    ),
    SfType::new(
        "EMAILADDR_UNDELIVERABLE",
        "Undeliverable Email Address",
        false,
        Category::Descriptor,
    ),
    SfType::new("ERROR_MESSAGE", "Error Message", false, Category::Data),
    SfType::new(
        "ETHEREUM_ADDRESS",
        "Ethereum Address",
        false,
        Category::Entity,
    ),
    SfType::new(
        "ETHEREUM_BALANCE",
        "Ethereum Balance",
        false,
        Category::Descriptor,
    ),
    SfType::new("GEOINFO", "Physical Location", false, Category::Descriptor),
    SfType::new("HASH", "Hash", false, Category::Data),
    SfType::new(
        "HASH_COMPROMISED",
        "Compromised Password Hash",
        false,
        Category::Data,
    ),
    SfType::new("HTTP_CODE", "HTTP Status Code", false, Category::Data),
    SfType::new("HUMAN_NAME", "Human Name", false, Category::Entity),
    SfType::new("IBAN_NUMBER", "IBAN Number", false, Category::Entity),
    SfType::new(
        "INTERESTING_FILE",
        "Interesting File",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "INTERESTING_FILE_HISTORIC",
        "Historic Interesting File",
        false,
        Category::Descriptor,
    ),
    SfType::new("JUNK_FILE", "Junk File", false, Category::Descriptor),
    SfType::new(
        "INTERNAL_IP_ADDRESS",
        "IP Address - Internal Network",
        false,
        Category::Entity,
    ),
    SfType::new("INTERNET_NAME", "Internet Name", false, Category::Entity),
    SfType::new(
        "INTERNET_NAME_UNRESOLVED",
        "Internet Name - Unresolved",
        false,
        Category::Entity,
    ),
    SfType::new("IP_ADDRESS", "IP Address", false, Category::Entity),
    SfType::new("IPV6_ADDRESS", "IPv6 Address", false, Category::Entity),
    SfType::new("LEI", "Legal Entity Identifier", false, Category::Entity),
    SfType::new("JOB_TITLE", "Job Title", false, Category::Descriptor),
    SfType::new(
        "LINKED_URL_INTERNAL",
        "Linked URL - Internal",
        false,
        Category::Subentity,
    ),
    SfType::new(
        "LINKED_URL_EXTERNAL",
        "Linked URL - External",
        false,
        Category::Subentity,
    ),
    SfType::new("MALICIOUS_ASN", "Malicious AS", false, Category::Descriptor),
    SfType::new(
        "MALICIOUS_BITCOIN_ADDRESS",
        "Malicious Bitcoin Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "MALICIOUS_IPADDR",
        "Malicious IP Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "MALICIOUS_COHOST",
        "Malicious Co-Hosted Site",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "MALICIOUS_EMAILADDR",
        "Malicious E-mail Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "MALICIOUS_INTERNET_NAME",
        "Malicious Internet Name",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "MALICIOUS_AFFILIATE_INTERNET_NAME",
        "Malicious Affiliate",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "MALICIOUS_AFFILIATE_IPADDR",
        "Malicious Affiliate IP Address",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "MALICIOUS_NETBLOCK",
        "Malicious IP on Owned Netblock",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "MALICIOUS_PHONE_NUMBER",
        "Malicious Phone Number",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "MALICIOUS_SUBNET",
        "Malicious IP on Same Subnet",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "NETBLOCK_OWNER",
        "Netblock Ownership",
        false,
        Category::Entity,
    ),
    SfType::new(
        "NETBLOCKV6_OWNER",
        "Netblock IPv6 Ownership",
        false,
        Category::Entity,
    ),
    SfType::new(
        "NETBLOCK_MEMBER",
        "Netblock Membership",
        false,
        Category::Entity,
    ),
    SfType::new(
        "NETBLOCKV6_MEMBER",
        "Netblock IPv6 Membership",
        false,
        Category::Entity,
    ),
    SfType::new("NETBLOCK_WHOIS", "Netblock Whois", true, Category::Data),
    SfType::new(
        "OPERATING_SYSTEM",
        "Operating System",
        false,
        Category::Descriptor,
    ),
    SfType::new("LEAKSITE_URL", "Leak Site URL", false, Category::Entity),
    SfType::new(
        "LEAKSITE_CONTENT",
        "Leak Site Content",
        true,
        Category::Data,
    ),
    SfType::new(
        "PASSWORD_COMPROMISED",
        "Compromised Password",
        false,
        Category::Data,
    ),
    SfType::new("PHONE_NUMBER", "Phone Number", false, Category::Entity),
    SfType::new(
        "PHONE_NUMBER_COMPROMISED",
        "Phone Number Compromised",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "PHONE_NUMBER_TYPE",
        "Phone Number Type",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "PHYSICAL_ADDRESS",
        "Physical Address",
        false,
        Category::Entity,
    ),
    SfType::new(
        "PHYSICAL_COORDINATES",
        "Physical Coordinates",
        false,
        Category::Entity,
    ),
    SfType::new("PGP_KEY", "PGP Public Key", false, Category::Data),
    SfType::new("PROXY_HOST", "Proxy Host", false, Category::Descriptor),
    SfType::new(
        "PROVIDER_DNS",
        "Name Server (DNS NS Records)",
        false,
        Category::Entity,
    ),
    SfType::new(
        "PROVIDER_JAVASCRIPT",
        "Externally Hosted Javascript",
        false,
        Category::Entity,
    ),
    SfType::new(
        "PROVIDER_MAIL",
        "Email Gateway (DNS MX Records)",
        false,
        Category::Entity,
    ),
    SfType::new(
        "PROVIDER_HOSTING",
        "Hosting Provider",
        false,
        Category::Entity,
    ),
    SfType::new(
        "PROVIDER_TELCO",
        "Telecommunications Provider",
        false,
        Category::Entity,
    ),
    SfType::new(
        "PUBLIC_CODE_REPO",
        "Public Code Repository",
        false,
        Category::Entity,
    ),
    SfType::new(
        "RAW_RIR_DATA",
        "Raw Data from RIRs/APIs",
        true,
        Category::Data,
    ),
    SfType::new("RAW_DNS_RECORDS", "Raw DNS Records", true, Category::Data),
    SfType::new(
        "RAW_FILE_META_DATA",
        "Raw File Meta Data",
        true,
        Category::Data,
    ),
    SfType::new(
        "SEARCH_ENGINE_WEB_CONTENT",
        "Search Engine Web Content",
        true,
        Category::Data,
    ),
    SfType::new(
        "SOCIAL_MEDIA",
        "Social Media Presence",
        false,
        Category::Entity,
    ),
    SfType::new(
        "SIMILAR_ACCOUNT_EXTERNAL",
        "Similar Account on External Site",
        false,
        Category::Entity,
    ),
    SfType::new("SIMILARDOMAIN", "Similar Domain", false, Category::Entity),
    SfType::new(
        "SIMILARDOMAIN_WHOIS",
        "Similar Domain - Whois",
        true,
        Category::Data,
    ),
    SfType::new("SOFTWARE_USED", "Software Used", false, Category::Subentity),
    SfType::new(
        "SSL_CERTIFICATE_RAW",
        "SSL Certificate - Raw Data",
        true,
        Category::Data,
    ),
    SfType::new(
        "SSL_CERTIFICATE_ISSUED",
        "SSL Certificate - Issued to",
        false,
        Category::Entity,
    ),
    SfType::new(
        "SSL_CERTIFICATE_ISSUER",
        "SSL Certificate - Issued by",
        false,
        Category::Entity,
    ),
    SfType::new(
        "SSL_CERTIFICATE_MISMATCH",
        "SSL Certificate Host Mismatch",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "SSL_CERTIFICATE_EXPIRED",
        "SSL Certificate Expired",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "SSL_CERTIFICATE_EXPIRING",
        "SSL Certificate Expiring",
        false,
        Category::Descriptor,
    ),
    SfType::new("TARGET_WEB_CONTENT", "Web Content", true, Category::Data),
    SfType::new(
        "TARGET_WEB_CONTENT_TYPE",
        "Web Content Type",
        false,
        Category::Descriptor,
    ),
    SfType::new("TARGET_WEB_COOKIE", "Cookies", false, Category::Data),
    SfType::new("TCP_PORT_OPEN", "Open TCP Port", false, Category::Subentity),
    SfType::new(
        "TCP_PORT_OPEN_BANNER",
        "Open TCP Port Banner",
        false,
        Category::Data,
    ),
    SfType::new(
        "TOR_EXIT_NODE",
        "TOR Exit Node",
        false,
        Category::Descriptor,
    ),
    SfType::new("UDP_PORT_OPEN", "Open UDP Port", false, Category::Subentity),
    SfType::new(
        "UDP_PORT_OPEN_INFO",
        "Open UDP Port Information",
        false,
        Category::Data,
    ),
    SfType::new(
        "URL_ADBLOCKED_EXTERNAL",
        "URL (AdBlocked External)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_ADBLOCKED_INTERNAL",
        "URL (AdBlocked Internal)",
        false,
        Category::Descriptor,
    ),
    SfType::new("URL_FORM", "URL (Form)", false, Category::Descriptor),
    SfType::new("URL_FLASH", "URL (Uses Flash)", false, Category::Descriptor),
    SfType::new(
        "URL_JAVASCRIPT",
        "URL (Uses Javascript)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_WEB_FRAMEWORK",
        "URL (Uses a Web Framework)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_JAVA_APPLET",
        "URL (Uses Java Applet)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_STATIC",
        "URL (Purely Static)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_PASSWORD",
        "URL (Accepts Passwords)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_UPLOAD",
        "URL (Accepts Uploads)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_FORM_HISTORIC",
        "Historic URL (Form)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_FLASH_HISTORIC",
        "Historic URL (Uses Flash)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_JAVASCRIPT_HISTORIC",
        "Historic URL (Uses Javascript)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_WEB_FRAMEWORK_HISTORIC",
        "Historic URL (Uses a Web Framework)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_JAVA_APPLET_HISTORIC",
        "Historic URL (Uses Java Applet)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_STATIC_HISTORIC",
        "Historic URL (Purely Static)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_PASSWORD_HISTORIC",
        "Historic URL (Accepts Passwords)",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "URL_UPLOAD_HISTORIC",
        "Historic URL (Accepts Uploads)",
        false,
        Category::Descriptor,
    ),
    SfType::new("USERNAME", "Username", false, Category::Entity),
    SfType::new("VPN_HOST", "VPN Host", false, Category::Descriptor),
    SfType::new(
        "VULNERABILITY_DISCLOSURE",
        "Vulnerability - Third Party Disclosure",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "VULNERABILITY_CVE_CRITICAL",
        "Vulnerability - CVE Critical",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "VULNERABILITY_CVE_HIGH",
        "Vulnerability - CVE High",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "VULNERABILITY_CVE_MEDIUM",
        "Vulnerability - CVE Medium",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "VULNERABILITY_CVE_LOW",
        "Vulnerability - CVE Low",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "VULNERABILITY_GENERAL",
        "Vulnerability - General",
        false,
        Category::Descriptor,
    ),
    SfType::new("WEB_ANALYTICS_ID", "Web Analytics", false, Category::Entity),
    SfType::new("WEBSERVER_BANNER", "Web Server", false, Category::Data),
    SfType::new(
        "WEBSERVER_HTTPHEADERS",
        "HTTP Headers",
        true,
        Category::Data,
    ),
    SfType::new(
        "WEBSERVER_STRANGEHEADER",
        "Non-Standard HTTP Header",
        false,
        Category::Data,
    ),
    SfType::new(
        "WEBSERVER_TECHNOLOGY",
        "Web Technology",
        false,
        Category::Descriptor,
    ),
    SfType::new(
        "WIFI_ACCESS_POINT",
        "WiFi Access Point Nearby",
        false,
        Category::Entity,
    ),
    SfType::new(
        "WIKIPEDIA_PAGE_EDIT",
        "Wikipedia Page Edit",
        false,
        Category::Descriptor,
    ),
];

/// Every type: Spiderfoot's, then Huntsman's own.
pub fn all() -> impl Iterator<Item = &'static SfType> {
    SPIDERFOOT_TYPES.iter().chain(HUNTSMAN_TYPES.iter())
}

/// The type named `code`, ignoring case.
#[must_use]
pub fn find(code: &str) -> Option<&'static SfType> {
    all().find(|kind| kind.code.eq_ignore_ascii_case(code))
}

/// The description of `code`, or the code itself when it is not a known type.
#[must_use]
pub fn describe(code: &str) -> &str {
    find(code).map_or(code, |kind| kind.description)
}

/// The type an entity of `kind` is, before any target-relative refinement.
#[must_use]
pub const fn base_type(kind: &EntityKind) -> &'static str {
    match kind {
        EntityKind::Person => "HUMAN_NAME",
        EntityKind::Organisation => "COMPANY_NAME",
        EntityKind::Email => "EMAILADDR",
        EntityKind::Phone => "PHONE_NUMBER",
        EntityKind::Username => "USERNAME",
        EntityKind::Domain => "DOMAIN_NAME",
        EntityKind::Url => "LINKED_URL_EXTERNAL",
        EntityKind::IpAddress => "IP_ADDRESS",
        EntityKind::Coordinates => "PHYSICAL_COORDINATES",
        EntityKind::Address => "PHYSICAL_ADDRESS",
        EntityKind::Credential => "PASSWORD_COMPROMISED",
        EntityKind::ApiKey => "HSE_API_KEY",
        EntityKind::Other => "HSE_OTHER",
        EntityKind::Document => "HSE_DOCUMENT",
        EntityKind::CryptoAddress => "HSE_CRYPTO_ADDRESS",
        EntityKind::DeviceId => "HSE_DEVICE_ID",
        EntityKind::Ssid => "HSE_WIFI_SSID",
        EntityKind::TrackingId => "WEB_ANALYTICS_ID",
        EntityKind::AbnAcn => "HSE_COMPANY_REGISTRATION",
        EntityKind::MacAddress => "HSE_MAC_ADDRESS",
        EntityKind::Asn => "BGP_AS_MEMBER",
    }
}

/// The entity kind each type is the base type of, for `sf -T`.
#[must_use]
pub fn base_kind(code: &str) -> Option<&'static str> {
    const KINDS: [EntityKind; 21] = [
        EntityKind::Person,
        EntityKind::Organisation,
        EntityKind::Email,
        EntityKind::Phone,
        EntityKind::Username,
        EntityKind::Domain,
        EntityKind::Url,
        EntityKind::IpAddress,
        EntityKind::Coordinates,
        EntityKind::Address,
        EntityKind::Credential,
        EntityKind::Document,
        EntityKind::CryptoAddress,
        EntityKind::DeviceId,
        EntityKind::Ssid,
        EntityKind::TrackingId,
        EntityKind::AbnAcn,
        EntityKind::ApiKey,
        EntityKind::MacAddress,
        EntityKind::Asn,
        EntityKind::Other,
    ];
    KINDS
        .iter()
        .find(|kind| base_type(kind) == code)
        .map(EntityKind::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_catalogue_is_spiderfoots_172_types_plus_huntsmans_own_with_no_repeat() {
        assert_eq!(SPIDERFOOT_TYPES.len(), 172);
        assert_eq!(SPIDERFOOT_TYPES[0].code, "ROOT");
        let codes: BTreeSet<&str> = all().map(|kind| kind.code).collect();
        assert_eq!(codes.len(), 172 + HUNTSMAN_TYPES.len());
        assert!(
            HUNTSMAN_TYPES
                .iter()
                .all(|kind| kind.code.starts_with("HSE_"))
        );
        assert!(
            SPIDERFOOT_TYPES
                .iter()
                .all(|kind| !kind.code.starts_with("HSE_"))
        );
    }

    #[test]
    fn every_entity_kind_has_a_catalogued_base_type() {
        for kind in [
            EntityKind::Person,
            EntityKind::Credential,
            EntityKind::ApiKey,
            EntityKind::Asn,
            EntityKind::Other,
        ] {
            assert!(find(base_type(&kind)).is_some(), "{kind}");
        }
        assert_eq!(base_kind("EMAILADDR"), Some("email"));
        assert_eq!(base_kind("TCP_PORT_OPEN"), None);
    }

    #[test]
    fn lookups_ignore_case_and_unknown_codes_describe_themselves() {
        assert_eq!(
            find("tcp_port_open").map(|kind| kind.code),
            Some("TCP_PORT_OPEN")
        );
        assert_eq!(describe("EMAILADDR"), "Email Address");
        assert_eq!(describe("NOT_A_TYPE"), "NOT_A_TYPE");
        assert_eq!(
            find("ROOT").map(|kind| kind.category),
            Some(Category::Internal)
        );
    }
}
