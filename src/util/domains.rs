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
    "myspace.com",
    "soundcloud.com",
    "tumblr.com",
    "vimeo.com",
    "flickr.com",
    "snapchat.com",
    "threads.net",
    "mastodon.social",
    "bsky.app",
];

/// Common **multi-label public suffixes** under which the public registers a
/// name (so the registrable domain is `<label>.<suffix>`, not `<suffix>`). This
/// is a deliberately small curated table — **not** the full Public Suffix List
/// (which would be a ~9 000-entry dependency the project avoids). It covers the
/// suffixes that actually appear in this AU-focused tool's data: the `.au`
/// second levels plus the common international ones, so `example.com.au` and
/// `example.co.uk` resolve to themselves instead of collapsing to the bare
/// suffix. Sorted for `binary_search`.
const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "ac.in", "ac.jp", "ac.nz", "ac.uk", "asn.au", "co.id", "co.in", "co.jp", "co.nz", "co.uk",
    "co.za", "com.au", "com.br", "com.cn", "com.sg", "edu.au", "edu.sg", "go.jp", "gov.au",
    "gov.br", "gov.in", "gov.sg", "gov.uk", "govt.nz", "id.au", "me.uk", "ne.jp", "net.au",
    "net.br", "net.nz", "net.sg", "or.jp", "org.au", "org.br", "org.nz", "org.sg", "org.uk",
    "org.za", "sch.uk",
];

/// The registrable domain (eTLD+1) of `host`: the registered name plus its
/// public suffix. **Pure.** Trims, lowercases, and drops a trailing dot, then
/// keeps the last two labels — or the last three when the trailing two form a
/// known [`MULTI_LABEL_SUFFIXES`] entry, so `shop.example.com.au` →
/// `example.com.au` rather than the bare `com.au`. Returns `None` when `host` has
/// fewer than two labels (e.g. `localhost`).
#[must_use]
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
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

/// True if `host` is `domain` itself or a subdomain of it — the host-label-safe
/// "belongs to this domain" test. **Pure**, and allocation-free: it replaces the
/// `host == d || host.ends_with(&format!(".{d}"))` idiom that was hand-rolled
/// (and occasionally mis-written as a bare `ends_with`, matching `notexample.com`
/// against `example.com`) across the modules. Comparison is as-given — callers
/// that need case-insensitivity lowercase both sides first.
///
/// `sub.example.com` and `example.com` belong to `example.com`; `notexample.com`
/// and `example.com.au` do not.
#[must_use]
pub fn is_or_subdomain_of(host: &str, domain: &str) -> bool {
    host == domain || is_proper_subdomain_of(host, domain)
}

/// True if `host` is a strict subdomain of `domain` (i.e. `sub.example.com` of
/// `example.com`), but **not** `domain` itself. The label-boundary half of
/// [`is_or_subdomain_of`], for the call sites that must exclude the apex.
#[must_use]
pub fn is_proper_subdomain_of(host: &str, domain: &str) -> bool {
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
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
    SOCIAL.iter().any(|s| is_or_subdomain_of(domain, s))
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
    fn is_or_subdomain_of_respects_label_boundaries() {
        // Equal and genuine subdomains belong.
        assert!(is_or_subdomain_of("example.com", "example.com"));
        assert!(is_or_subdomain_of("sub.example.com", "example.com"));
        assert!(is_or_subdomain_of("a.b.example.com", "example.com"));
        // Mid-label and different-TLD do NOT (the bug the helper prevents).
        assert!(!is_or_subdomain_of("notexample.com", "example.com"));
        assert!(!is_or_subdomain_of("example.com.au", "example.com"));
        assert!(!is_or_subdomain_of("example.com", "sub.example.com"));
        // Proper-subdomain excludes the apex.
        assert!(!is_proper_subdomain_of("example.com", "example.com"));
        assert!(is_proper_subdomain_of("sub.example.com", "example.com"));
        assert!(!is_proper_subdomain_of("notexample.com", "example.com"));
    }

    #[test]
    fn domain_helpers_cross_function_invariants() {
        // Generative invariant check over a constructed host corpus: example tests
        // pin individual cases, this pins the *relationships* between the helpers,
        // so a future change to one that desyncs from another is caught.
        let labels = ["a", "sub", "mail", "shop", "www", "deeply", "nested"];
        let bases = ["example", "acme", "target-co"];
        // Single-label TLDs plus every curated multi-label suffix.
        let mut suffixes: Vec<String> = vec!["com".into(), "org".into(), "io".into()];
        suffixes.extend(MULTI_LABEL_SUFFIXES.iter().map(|s| (*s).to_string()));

        let mut corpus: Vec<String> = Vec::new();
        for base in bases {
            for suf in &suffixes {
                let apex = format!("{base}.{suf}"); // registrable form
                corpus.push(apex.clone());
                // Build a few subdomains of varying depth.
                for depth in 1..=3 {
                    let prefix = labels[..depth].join(".");
                    corpus.push(format!("{prefix}.{apex}"));
                }
            }
        }

        for host in &corpus {
            // Reflexive / irreflexive.
            assert!(is_or_subdomain_of(host, host), "reflexive: {host}");
            assert!(!is_proper_subdomain_of(host, host), "irreflexive: {host}");

            let r = registrable_domain(host).expect("corpus hosts have >= 2 labels");

            // INVARIANT 1: the registrable domain is always an equal-or-subdomain
            // of its host (a label-aligned suffix), never an unrelated string.
            // `registrable_domain` lowercases; the corpus is already lowercase.
            assert!(
                is_or_subdomain_of(host, &r),
                "registrable {r} must be an equal-or-subdomain of host {host}"
            );

            // INVARIANT 2: idempotence — the registrable domain of a registrable
            // domain is itself (collapsing twice changes nothing).
            assert_eq!(
                registrable_domain(&r).as_deref(),
                Some(r.as_str()),
                "registrable_domain not idempotent for {host} (r={r})"
            );

            // INVARIANT 3: proper-subdomain implies equal-or-subdomain, and the
            // two agree except exactly at equality.
            for other in &corpus {
                let sub = is_proper_subdomain_of(host, other);
                let eq_or_sub = is_or_subdomain_of(host, other);
                if sub {
                    assert!(eq_or_sub, "proper-subdomain must imply or-subdomain");
                }
                assert_eq!(
                    eq_or_sub,
                    host == other || sub,
                    "or-subdomain must be exactly (equal OR proper-subdomain): {host} vs {other}"
                );
            }
        }
    }

    #[test]
    fn social_includes_country_subdomains() {
        assert!(is_social_platform("linkedin.com"));
        assert!(is_social_platform("au.linkedin.com"));
        assert!(is_social_platform("m.facebook.com"));
        assert!(!is_social_platform("acme.com"));
    }

    #[test]
    fn multi_label_suffix_table_is_sorted_for_binary_search() {
        assert!(
            MULTI_LABEL_SUFFIXES.is_sorted(),
            "MULTI_LABEL_SUFFIXES must stay sorted (binary_search)"
        );
    }

    #[test]
    fn registrable_domain_single_label_tlds() {
        assert_eq!(
            registrable_domain("www.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("cdn.assets.example.org").as_deref(),
            Some("example.org")
        );
        // Fewer than two labels → no registrable domain.
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(registrable_domain(""), None);
    }

    #[test]
    fn registrable_domain_multi_label_suffixes() {
        // The whole point: AU + common international multi-label suffixes resolve
        // to the registered name, not the bare suffix.
        assert_eq!(
            registrable_domain("shop.example.com.au").as_deref(),
            Some("example.com.au")
        );
        assert_eq!(
            registrable_domain("example.com.au").as_deref(),
            Some("example.com.au")
        );
        assert_eq!(registrable_domain("a.b.co.uk").as_deref(), Some("b.co.uk"));
        assert_eq!(
            registrable_domain("dept.gov.au").as_deref(),
            Some("dept.gov.au")
        );
        // The bare suffix itself has no registered label in front → kept as-is
        // (two labels, not in a 3-label position).
        assert_eq!(registrable_domain("com.au").as_deref(), Some("com.au"));
    }

    #[test]
    fn registrable_domain_normalises_case_and_trailing_dot() {
        assert_eq!(
            registrable_domain("WWW.Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("  Shop.Example.Com.AU  ").as_deref(),
            Some("example.com.au")
        );
    }
}
