//! Domain classification helpers — shared across modules.
//!
//! Centralises the freemail and social-platform lists so adding a new
//! freemail provider only touches one file. Modules call `is_freemail`
//! / `is_social_platform` rather than maintaining their own copies.

const FREEMAIL: &[&str] = &[
    // Global providers
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "mail.com",
    "protonmail.com",
    "proton.me",
    "tutanota.com",
    "tutanota.de",
    "tuta.io",
    "zoho.com",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "gmx.com",
    "gmx.de",
    "gmx.net",
    "fastmail.com",
    "fastmail.fm",
    // Country-flavoured freemail / ISP webmail
    "yahoo.com.au",
    "hotmail.com.au",
    "live.com.au",
    "bigpond.com",
    "bigpond.net.au",
    "optusnet.com.au",
    "iinet.net.au",
    "internode.on.net",
    "tpg.com.au",
    "comcast.net",
    "verizon.net",
];

const SOCIAL: &[&str] = &[
    "facebook.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "linkedin.com",
    "tiktok.com",
    "youtube.com",
    "reddit.com",
    "pinterest.com",
    "github.com",
    "gitlab.com",
    "medium.com",
];

/// True if `domain` is a known consumer mailbox provider — modules that
/// pivot on the assumption "domain == employer" should skip these.
pub fn is_freemail(domain: &str) -> bool {
    FREEMAIL.contains(&domain)
}

/// True if `domain` is a social platform or one of its country
/// subdomains (e.g. `au.linkedin.com`). Modules that follow a domain
/// to its "contact" page should skip these.
pub fn is_social_platform(domain: &str) -> bool {
    SOCIAL
        .iter()
        .any(|s| domain == *s || domain.ends_with(&format!(".{}", s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freemail_basics() {
        assert!(is_freemail("gmail.com"));
        assert!(is_freemail("bigpond.com"));
        assert!(!is_freemail("acme.com.au"));
        assert!(!is_freemail(""));
    }

    #[test]
    fn social_includes_country_subdomains() {
        assert!(is_social_platform("linkedin.com"));
        assert!(is_social_platform("au.linkedin.com"));
        assert!(is_social_platform("m.facebook.com"));
        assert!(!is_social_platform("acme.com"));
    }
}
