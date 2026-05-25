//! Well-known entity tag constants. Using these instead of bare string
//! literals prevents typo-driven bugs (the compiler catches a misspelled
//! constant but not a misspelled `"brecah"` tag) and makes tag usage
//! discoverable via grep/IDE "find usages".

pub const BREACH: &str = "breach";
pub const STEALER_LOG: &str = "stealer-log";
pub const WEB: &str = "web";
pub const CRAWLED: &str = "crawled";
pub const SUBDOMAIN: &str = "subdomain";
pub const EXTERNAL: &str = "external";
pub const WEB_SCRAPED: &str = "web-scraped";
pub const CT_LOG: &str = "ct-log";
pub const PTR: &str = "ptr";
pub const HIGH_EXPOSURE: &str = "high-exposure";
pub const PASTE_EXPOSED: &str = "paste-exposed";
pub const PASSWORD_AT_RISK: &str = "password-at-risk";
pub const MULTI_DEVICE: &str = "multi-device";
pub const MISSING_SECURITY_HEADERS: &str = "missing-security-headers";
