//! Domain, email-domain, URL-host, and DNS-label helpers rebuilt from the monolith.
//!
//! Public-suffix decision: keep the monolith's curated multi-label suffix table,
//! not the full PSL. This crate stays dependency-light and offline; the table is
//! intentionally small, documented, and biased toward suffixes that actually
//! occur in the corpus.

const FREEMAIL: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.com.au",
    "hotmail.com",
    "hotmail.com.au",
    "outlook.com",
    "live.com",
    "live.com.au",
    "icloud.com",
    "protonmail.com",
    "proton.me",
    "pm.me",
    "mail.com",
    "fastmail.com",
    "qq.com",
    "163.com",
    "126.com",
    "rediffmail.com",
    "bigpond.com",
    "bigpond.net.au",
    "optusnet.com.au",
    "iinet.net.au",
    "internode.on.net",
    "tpg.com.au",
    "aapt.net.au",
    "westnet.com.au",
    "dodo.com.au",
    "ozemail.com.au",
    "y7mail.com",
    "exemail.com.au",
    "iprimus.com.au",
    "netspace.net.au",
    "comcast.net",
    "verizon.net",
    "att.net",
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
    "github.com",
    "gitlab.com",
    "medium.com",
    "threads.net",
    "bsky.app",
    "discord.com",
    "telegram.org",
    "t.me",
    "whatsapp.com",
    "twitch.tv",
    "peekyou.com",
    "spokeo.com",
    "nuwber.com",
    "pipl.com",
    "whitepages.com",
    "whitepages.com.au",
    "locatefamily.com",
    "truecaller.com",
    "bitbucket.org",
    "steamcommunity.com",
    "spotify.com",
    "signal.org",
    "vk.com",
];

pub const INFRA_PROVIDER_ROOTS: &[&str] = &[
    "cloudflare.com",
    "amazonaws.com",
    "google.com",
    "azure.com",
    "fastly.com",
    "akamai.com",
    "incapsula.com",
    "imperva.com",
    "sucuri.net",
    "stackpath.com",
    "secureserver.net",
    "domaincontrol.com",
    "name.com",
    "namecheap.com",
    "gandi.net",
    "digitalocean.com",
    "linode.com",
    "hetzner.com",
    "hetzner.de",
    "ovh.net",
    "ovh.com",
    "sendgrid.net",
    "sendgrid.com",
    "mailgun.org",
];

const ROLE_LOCALPARTS: &[&str] = &[
    "admin",
    "administrator",
    "info",
    "support",
    "help",
    "helpdesk",
    "contact",
    "sales",
    "abuse",
    "postmaster",
    "hostmaster",
    "webmaster",
    "noreply",
    "donotreply",
    "dns",
    "root",
    "mail",
    "mailer",
    "mailerdaemon",
    "security",
    "privacy",
    "legal",
    "billing",
    "accounts",
    "marketing",
    "hello",
    "team",
    "office",
    "service",
    "services",
    "notifications",
    "notify",
    "news",
    "newsletter",
    "robot",
    "automated",
    "system",
    "daemon",
    "feedback",
    "enquiries",
    "enquiry",
    "generalenquiry",
    "generalenquiries",
    "inquiries",
    "inquiry",
    "careers",
    "jobs",
    "press",
    "media",
    "webmail",
    "namehost",
    "dmca",
    "domains",
    "domain",
    "registrar",
    "whois",
    "nic",
    "noc",
    "registry",
    "soa",
    "ssladmin",
    "sysadmin",
    "tech",
];

const SYSTEM_LOCALPART_SEGMENTS: &[&str] = &[
    "hostmaster",
    "postmaster",
    "webmaster",
    "namehost",
    "mailerdaemon",
    "noreply",
    "donotreply",
    "abuse",
    "dns",
];

const VN_REGISTRANTS: &[(&str, &str, &str)] = &[
    (
        ".gov.vn",
        "government",
        "a Vietnamese government body (gov.vn)",
    ),
    (
        ".edu.vn",
        "education",
        "a Vietnamese education/training institution (edu.vn)",
    ),
    (
        ".ac.vn",
        "education",
        "a Vietnamese research/academic institution (ac.vn)",
    ),
    (
        ".org.vn",
        "non-profit",
        "a Vietnamese political/social/professional organisation (org.vn)",
    ),
    (
        ".com.vn",
        "commercial",
        "a Vietnamese commercial registrant (com.vn)",
    ),
    (
        ".biz.vn",
        "commercial",
        "a Vietnamese business registrant (biz.vn)",
    ),
    (
        ".net.vn",
        "commercial",
        "a Vietnamese network-service registrant (net.vn)",
    ),
    (
        ".name.vn",
        "individual",
        "a natural-person Vietnamese registrant (name.vn)",
    ),
];

const INFRA_MAIL_ONLY: &[&str] = &[
    "amazon.com",
    "microsoft.com",
    "godaddy.com",
    "mailgun.net",
    "markmonitor.com",
    "csc.com",
    "cscglobal.com",
    "ripe.net",
    "arin.net",
    "apnic.net",
    "worldnic.com",
    "networksolutions.com",
    "web.com",
    "tucows.com",
    "enom.com",
    "wildwestdomains.com",
    "publicdomainregistry.com",
    "key-systems.net",
    "ascio.com",
    "nominet.uk",
    "verisign.com",
    "register.com",
    "ionos.com",
    "1and1.com",
    "bluehost.com",
    "hostgator.com",
    "dreamhost.com",
    "siteground.com",
    "hover.com",
    "porkbun.com",
    "dynadot.com",
    "namecheap.email",
    "ausregistry.com.au",
    "auda.org.au",
    "melbourne.it",
    "crazydomains.com.au",
    "ventraip.com.au",
];

pub const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "ac.in", "ac.jp", "ac.nz", "ac.uk", "asn.au", "co.id", "co.in", "co.jp", "co.nz", "co.uk",
    "co.za", "com.au", "com.br", "com.cn", "com.sg", "edu.au", "edu.sg", "go.jp", "gov.au",
    "gov.br", "gov.in", "gov.sg", "gov.uk", "govt.nz", "id.au", "me.uk", "ne.jp", "net.au",
    "net.br", "net.nz", "net.sg", "or.jp", "org.au", "org.br", "org.nz", "org.sg", "org.uk",
    "org.za", "sch.uk",
];

#[must_use]
pub fn is_absolute_http_url(s: &str) -> bool {
    crate::http::parse_http_uri(s).is_ok()
}

#[must_use]
pub fn host_only(s: &str) -> &str {
    let trimmed = s.trim();
    let after_scheme = ["https://", "http://"]
        .iter()
        .find_map(|scheme| {
            trimmed
                .get(..scheme.len())
                .filter(|prefix| prefix.eq_ignore_ascii_case(scheme))
                .map(|_| &trimmed[scheme.len()..])
        })
        .unwrap_or(trimmed);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if let Some(close) = authority
        .strip_prefix('[')
        .and_then(|without_open| without_open.find(']'))
    {
        return &authority[..close + 2];
    }
    authority.split(':').next().unwrap_or("")
}

#[must_use]
pub fn host_from_url(url: &str) -> Option<String> {
    let host = host_only(url).to_ascii_lowercase();
    (!host.is_empty() && host.contains('.')).then_some(host)
}

#[must_use]
pub fn is_tracking_param_key(key: &str) -> bool {
    crate::canonical::is_tracking_param_key(key)
}

#[must_use]
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    let take = if labels.len() >= 3
        && MULTI_LABEL_SUFFIXES
            .binary_search(&last_two.as_str())
            .is_ok()
    {
        3
    } else {
        2
    };
    Some(labels[labels.len() - take..].join("."))
}

#[must_use]
pub fn is_app_package_id(s: &str) -> bool {
    let cleaned = s.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = cleaned
        .split('.')
        .filter(|label| !label.is_empty())
        .collect();
    labels.len() >= 3 && matches!(labels.first(), Some(&"com" | &"org" | &"net" | &"io"))
}

#[must_use]
pub fn looks_like_domain(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.contains('@') || trimmed.contains(char::is_whitespace) {
        return false;
    }
    if trimmed.parse::<std::net::IpAddr>().is_ok() || is_app_package_id(trimmed) {
        return false;
    }
    let labels: Vec<&str> = trimmed.trim_end_matches('.').split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| !label.is_empty())
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= 2 && tld.chars().any(|c| c.is_ascii_alphabetic()))
}

#[must_use]
pub fn is_or_subdomain_of(host: &str, domain: &str) -> bool {
    host == domain || is_proper_subdomain_of(host, domain)
}

#[must_use]
pub fn is_proper_subdomain_of(host: &str, domain: &str) -> bool {
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

#[must_use]
pub fn canonical_domain_host(host: &str) -> Option<String> {
    crate::canonical::canonical_domain_host(host).filter(|domain| looks_like_domain(domain))
}

#[must_use]
pub fn classify_domain_candidate(candidate: &str, base: &str) -> (String, bool) {
    let canonical = canonical_domain_host(candidate)
        .unwrap_or_else(|| candidate.trim().trim_end_matches('.').to_ascii_lowercase());
    let canonical_base = canonical_domain_host(base)
        .unwrap_or_else(|| base.trim().trim_end_matches('.').to_ascii_lowercase());
    let is_subdomain = is_proper_subdomain_of(&canonical, &canonical_base);
    (canonical, is_subdomain)
}

#[must_use]
pub fn is_freemail(domain: &str) -> bool {
    FREEMAIL.contains(&domain)
}

#[must_use]
pub fn is_role_localpart(local: &str) -> bool {
    let detagged = local.split('+').next().unwrap_or(local);
    let base: String = detagged
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if ROLE_LOCALPARTS.contains(&base.as_str()) {
        return true;
    }
    detagged.split(['-', '.', '_']).any(|segment| {
        let folded: String = segment
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        SYSTEM_LOCALPART_SEGMENTS.contains(&folded.as_str())
    })
}

#[must_use]
pub fn is_infrastructure_email(email: &str) -> bool {
    let email = email.trim().trim_end_matches('.').to_ascii_lowercase();
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if is_role_localpart(local) {
        return true;
    }
    let registrable = registrable_domain(domain).unwrap_or_else(|| domain.to_string());
    if is_freemail(domain) || is_freemail(&registrable) {
        return false;
    }
    INFRA_PROVIDER_ROOTS
        .iter()
        .chain(INFRA_MAIL_ONLY)
        .any(|root| registrable == *root || is_or_subdomain_of(domain, root))
}

#[must_use]
pub fn is_noreply_email_domain(email: &str) -> bool {
    let Some((_, domain)) = email.trim().rsplit_once('@') else {
        return false;
    };
    domain.to_ascii_lowercase().split('.').any(|label| {
        let folded: String = label.chars().filter(char::is_ascii_alphanumeric).collect();
        folded == "noreply" || folded == "donotreply"
    })
}

#[must_use]
pub fn is_social_platform(domain: &str) -> bool {
    SOCIAL.iter().any(|root| is_or_subdomain_of(domain, root))
}

#[must_use]
pub fn is_proxy_registrant(value: &str, is_email: bool) -> bool {
    crate::validation::is_whois_privacy_placeholder(value)
        || (is_email && is_infrastructure_email(value))
}

#[must_use]
pub fn vn_domain_registrant(domain: &str) -> Option<(&'static str, &'static str)> {
    let lowered = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if lowered != "vn"
        && lowered
            .rsplit('.')
            .next()
            .is_none_or(|segment| segment != "vn")
    {
        return None;
    }
    VN_REGISTRANTS
        .iter()
        .find(|(suffix, _, _)| lowered.ends_with(suffix))
        .map(|&(_, tag, label)| (tag, label))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_helpers_match_contract() {
        assert!(is_absolute_http_url("https://example.com"));
        assert_eq!(host_only("HTTPS://Up.Example.com/p"), "Up.Example.com");
        assert_eq!(host_only("https://example.com?x=1"), "example.com");
        assert_eq!(host_only("https://[2001:db8::1]?x=1"), "[2001:db8::1]");
        assert_eq!(
            host_from_url("https://Example.com#frag"),
            Some("example.com".into())
        );
        assert!(is_tracking_param_key("UTM_Campaign"));
        assert!(is_tracking_param_key("fbclid"));
        assert!(!is_tracking_param_key("page"));
    }

    #[test]
    fn domain_shape_and_subdomain_helpers_work() {
        assert_eq!(
            registrable_domain("shop.example.com.au").as_deref(),
            Some("example.com.au")
        );
        assert_eq!(registrable_domain("a.b.co.uk").as_deref(), Some("b.co.uk"));
        assert!(looks_like_domain("a-zfastfitcentre.co.uk"));
        assert!(!looks_like_domain("192.168.0.1"));
        assert!(!looks_like_domain("com.facebook.katana"));
        assert!(is_or_subdomain_of("sub.example.com", "example.com"));
        assert!(!is_or_subdomain_of("notexample.com", "example.com"));
        let (canonical, is_subdomain) = classify_domain_candidate("www.example.com", "example.com");
        assert_eq!(canonical, "example.com");
        assert!(!is_subdomain);
    }

    #[test]
    fn email_domain_classifiers_merge_legacy_lists() {
        assert!(is_role_localpart("No-Reply"));
        assert!(is_role_localpart("AWSDNS-Hostmaster"));
        assert!(!is_role_localpart("nic.smith"));
        assert!(is_infrastructure_email("Abuse@Cloudflare.com."));
        assert!(is_infrastructure_email("network-ops@amazonaws.com"));
        assert!(!is_infrastructure_email("jane@outlook.com"));
        assert!(is_noreply_email_domain("alice@users.noreply.github.com"));
        assert!(is_social_platform("au.linkedin.com"));
        assert!(is_freemail("exemail.com.au"));
        assert!(!is_freemail("acme.com.au"));
    }

    #[test]
    fn vn_and_dns_helpers_cover_pure_cases() {
        assert_eq!(
            vn_domain_registrant("MPS.GOV.VN.").map(|(kind, _)| kind),
            Some("government")
        );
        assert_eq!(vn_domain_registrant("doctor.pro.vn"), None);
        assert_eq!(
            crate::dns::unescape_dns_label(r"hostmaster\.ops"),
            "hostmaster.ops"
        );
        assert_eq!(crate::dns::unescape_dns_label(r"\038"), "&");
        assert_eq!(
            crate::dns::soa_rname_to_email(r"hostmaster\.ops.example.com."),
            "hostmaster.ops@example.com"
        );
    }

    #[test]
    fn package_ids_and_platform_lists_stay_precise() {
        assert!(is_app_package_id("com.facebook.katana"));
        assert!(!is_app_package_id("app.example.com"));
        assert!(!is_app_package_id("dev.portal.com"));
        assert!(looks_like_domain("app.example.com"));
        assert!(MULTI_LABEL_SUFFIXES.is_sorted());
    }
}
