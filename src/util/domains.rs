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

/// Multi-label public suffixes (eTLDs) common in OSINT data. A host ending
/// in one of these needs THREE labels to be registrable (`foo.com.au`), not
/// two (`com.au`). Not the full PSL — covers the AU set HSE targets plus the
/// most frequent international second-level suffixes seen in live scans.
const MULTI_SUFFIXES: &[&str] = &[
    // Australia
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "asn.au",
    "id.au",
    "act.au",
    "nsw.au",
    "qld.au",
    "vic.au",
    "wa.au",
    "sa.au",
    "tas.au",
    "nt.au",
    // United Kingdom
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "me.uk",
    "net.uk",
    "sch.uk",
    "ltd.uk",
    // New Zealand
    "co.nz",
    "net.nz",
    "org.nz",
    "govt.nz",
    "ac.nz",
    "geek.nz",
    "school.nz",
    // Other frequently-seen
    "com.sg",
    "edu.sg",
    "gov.sg",
    "co.in",
    "gov.in",
    "ac.in",
    "co.za",
    "com.br",
    "co.jp",
    "ne.jp",
    "or.jp",
    "com.cn",
    "gov.cn",
];

/// Extract the registrable domain (eTLD+1) from a host, honouring common
/// multi-label public suffixes. Returns `None` when the host is *itself* only
/// a public suffix (`com.au`, `gov.au`, `co.uk`) or is otherwise not a real
/// registrable domain — the guard that stops public-suffix fragments from
/// being emitted as Domain entities.
pub fn registrable_domain(host: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.contains(' ') || h.contains('@') {
        return None;
    }
    let labels: Vec<&str> = h.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None; // bare TLD or single label — never registrable
    }
    let last2 = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if MULTI_SUFFIXES.contains(&last2.as_str()) {
        // Needs a third label to be registrable; otherwise host IS the suffix.
        if labels.len() < 3 {
            return None;
        }
        return Some(format!("{}.{}", labels[labels.len() - 3], last2));
    }
    Some(last2)
}

/// True if `host` contains a real registrable domain — i.e. it is not a bare
/// TLD or public-suffix fragment. Use before emitting a `Domain` entity.
pub fn is_registrable_domain(host: &str) -> bool {
    registrable_domain(host).is_some()
}

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
    fn registrable_rejects_public_suffix_fragments() {
        // Public-suffix-only strings are never a registrable domain.
        for s in [
            "com.au", "edu.au", "gov.au", "co.uk", "co.nz", "au", "com", "",
        ] {
            assert_eq!(registrable_domain(s), None, "{s} should be rejected");
            assert!(!is_registrable_domain(s), "{s}");
        }
    }

    #[test]
    fn registrable_extracts_etld_plus_one() {
        assert_eq!(
            registrable_domain("uni.edu.au").as_deref(),
            Some("uni.edu.au")
        );
        assert_eq!(
            registrable_domain("www.example.com.au").as_deref(),
            Some("example.com.au")
        );
        assert_eq!(
            registrable_domain("sub.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("deep.sub.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("example.com").as_deref(),
            Some("example.com")
        );
        assert!(is_registrable_domain("acme.com.au"));
    }

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
