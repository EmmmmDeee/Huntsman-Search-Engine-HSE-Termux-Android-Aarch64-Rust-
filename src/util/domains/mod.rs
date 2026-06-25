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
    "rocketmail.com",
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
    "pm.me",
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
    "hey.com",
    "mailfence.com",
    // Yahoo country variants (common in breach data)
    "yahoo.co.uk",
    "yahoo.co.in",
    "yahoo.co.jp",
    "yahoo.fr",
    "yahoo.de",
    "yahoo.es",
    "yahoo.it",
    "yahoo.com.br",
    "yahoo.com.mx",
    "yahoo.com.ar",
    // Hotmail/Live country variants
    "hotmail.co.uk",
    "hotmail.fr",
    "hotmail.de",
    "hotmail.it",
    "hotmail.es",
    "live.co.uk",
    "live.fr",
    "live.de",
    // Chinese providers (high volume in breach data)
    "qq.com",
    "163.com",
    "126.com",
    "sina.com",
    "sina.cn",
    // Indian providers
    "rediffmail.com",
    "indiatimes.com",
    // European providers
    "web.de",
    "t-online.de",
    "freenet.de",
    "libero.it",
    "virgilio.it",
    "laposte.net",
    "orange.fr",
    "sfr.fr",
    "wanadoo.fr",
    "naver.com",
    "daum.net",
    "seznam.cz",
    "wp.pl",
    "o2.pl",
    "interia.pl",
    // Country-flavoured AU ISP webmail
    "yahoo.com.au",
    "hotmail.com.au",
    "live.com.au",
    "bigpond.com",
    "bigpond.net.au",
    "optusnet.com.au",
    "iinet.net.au",
    "internode.on.net",
    "tpg.com.au",
    "aapt.net.au",
    "westnet.com.au",
    "adam.com.au",
    "dodo.com.au",
    // US ISP webmail (common in US-breach data)
    "comcast.net",
    "verizon.net",
    "att.net",
    "sbcglobal.net",
    "bellsouth.net",
    "cox.net",
    "charter.net",
    "earthlink.net",
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
    // Messaging / community platforms whose contact pages are not useful crawl targets
    "discord.com",
    "telegram.org",
    "t.me",
    "whatsapp.com",
    "twitch.tv",
    "substack.com",
    "patreon.com",
    "quora.com",
    "meetup.com",
    "behance.net",
    "dribbble.com",
    "deviantart.com",
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

/// True if `s` looks like an Android / iOS **reverse-DNS application identifier**
/// (`com.facebook.katana`, `com.google.android.gms`, `org.mozilla.firefox`)
/// rather than a registrable web domain. Stealer logs record the app a credential
/// was captured in using this reverse-DNS form, and its dotted shape otherwise
/// sails through a bare `contains('.')` check — minting a bogus `Domain` entity
/// whose final label (`katana`, `gms`, `firefox`) is not a real TLD, which then
/// wastes DNS/cert/wayback expansion budget and pollutes the graph.
///
/// Discriminator (dependency-free — no Public Suffix List): a real registrable
/// domain never *begins* with a generic top-level label; `com`/`org`/`net`/… are
/// suffixes and appear *last*. A string with three or more labels whose *first*
/// label is one of those generic TLDs is therefore reverse-DNS, i.e. an app id.
/// Requiring 3+ labels keeps ordinary two-label domains (`net.au` is a suffix,
/// not a candidate here) and apex domains safe. **Pure.**
#[must_use]
pub fn is_app_package_id(s: &str) -> bool {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = s.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 3 {
        return false;
    }
    // Reverse-DNS package ids lead with a generic gTLD-style label. A genuine
    // hostname can technically have a subdomain literally named `com`, but in the
    // breach/stealer domain feeds this gates, that is vanishingly rare next to the
    // flood of `com.*`/`org.*` Android package ids.
    const RDNS_PREFIXES: &[&str] = &["com", "org", "net", "io", "app", "dev"];
    RDNS_PREFIXES.contains(&labels[0])
}

/// True when `s` is structurally a registrable DNS domain worth minting as a
/// `Domain` entity — as opposed to the noise breach/stealer `domain` fields
/// routinely carry. The single gate every module's provider-`domain`-field →
/// `Domain` path shares, so the same junk can't slip in through one parser. It
/// rejects, in order:
///   * empty values, or any with embedded whitespace or an `@`;
///   * a bare IP literal (`192.168.0.1`, `79.98.132.222`) — a router / C2 / panel
///     host, not a registrable domain, and a false lead that sends
///     `dns_intel`/`cert_intel`/`wayback` chasing a non-host;
///   * a reverse-DNS app package id (`com.facebook.katana`) — [`is_app_package_id`].
///
/// What survives needs ≥ 2 non-empty dot-separated labels and a final label (TLD)
/// of ≥ 2 chars bearing at least one letter (so `1.2.3` and other numeric junk are
/// rejected while `co.uk`, `xn--p1ai` pass). **Pure**, offline.
///
/// ```
/// use huntsman_search_engine::util::domains::looks_like_domain;
///
/// assert!(looks_like_domain("discord.com"));
/// assert!(looks_like_domain("a-zfastfitcentre.co.uk"));
/// assert!(!looks_like_domain("192.168.0.1"));        // private IP, not a domain
/// assert!(!looks_like_domain("79.98.132.222"));      // public IP, not a domain
/// assert!(!looks_like_domain("com.facebook.katana")); // android app package
/// assert!(!looks_like_domain("1.2.3"));               // numeric junk, no real TLD
/// assert!(!looks_like_domain("localhost"));           // single label, no dot
/// ```
#[must_use]
pub fn looks_like_domain(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.contains('@') || s.contains(char::is_whitespace) {
        return false;
    }
    // An IP literal is a host, not a registrable domain (IPv6 has no dots, so the
    // dotted-label check below would already drop it; the parse also rejects v4).
    if s.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    if is_app_package_id(s) {
        return false;
    }
    let labels: Vec<&str> = s.trim_end_matches('.').split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| !l.is_empty())
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= 2 && tld.chars().any(|c| c.is_ascii_alphabetic()))
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

/// True if a mailbox local-part is a generic role/automation address rather than
/// a person's handle (`info@`, `dns@`, `noreply@`, `abuse@`, …). Such local-parts
/// are never individualised PII — they are registrar/provider/automation desks —
/// so they must not seed Username/Person entities nor be expanded as the subject.
#[must_use]
pub fn is_role_localpart(local: &str) -> bool {
    // Compare the de-tagged, separator-stripped form so `no-reply`/`no_reply`
    // also match `noreply`.
    let base = local
        .split('+')
        .next()
        .unwrap_or(local)
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>();
    const ROLE: &[&str] = &[
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
        // Registrar / DNS provider system mailboxes seen in live WHOIS records
        // (Network Solutions `namehost@`, copyright `dmca@`, generic `domains@`).
        "namehost",
        "dmca",
        "domains",
        "domain",
        "registrar",
        "whois",
        "nic",
    ];
    ROLE.contains(&base.as_str())
}

/// True if a full email address is **infrastructure contact** rather than the
/// subject's personal mail: a role local-part (`abuse@`, `dns@`, …) OR a mailbox
/// on a CDN/registrar/cloud/ESP provider domain (`*.cloudflare.com`,
/// `*.amazonaws.com`, …). WHOIS/RDAP/RIPE abuse desks resolve to exactly these,
/// and merging them into the subject's identity is a false positive. The split is
/// case-insensitive and tolerant of a trailing dot.
#[must_use]
pub fn is_infrastructure_email(email: &str) -> bool {
    let email = email.trim().trim_end_matches('.').to_ascii_lowercase();
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if is_role_localpart(local) {
        return true;
    }
    // A consumer freemail mailbox (gmail / googlemail / yahoo / outlook / …) is
    // personal PII, never provider infrastructure — only its automated desks (an
    // `abuse@`/`postmaster@` role local-part, caught above) are. Without this guard
    // a freemail domain that also reads provider-ish — `googlemail.com` is literally
    // Gmail — would mislabel every personal mailbox on it as infrastructure and
    // suppress real subject emails from SERP/WHOIS/RIPE discovery.
    let registrable = registrable_domain(domain).unwrap_or_else(|| domain.to_string());
    if is_freemail(domain) || is_freemail(&registrable) {
        return false;
    }
    // Provider/infra mail domains: any registrable-domain match against the
    // curated infra set. Kept here (util) so both whois and ripestat can gate
    // emission without depending on `core`.
    INFRA_MAIL
        .iter()
        .any(|d| registrable == *d || domain == *d || domain.ends_with(&format!(".{d}")))
}

/// Registrable domains of CDN / cloud / registrar / DNS / ESP providers whose
/// role mailboxes (`abuse@`, `noc@`, …) surface from WHOIS/RDAP/RIPE lookups.
/// Mirrors the `INFRA_DOMAINS` intent in `core::scan` but lives in util so the
/// module layer can gate email emission without importing core.
const INFRA_MAIL: &[&str] = &[
    "cloudflare.com",
    "amazonaws.com",
    "amazon.com",
    // NB: googlemail.com is NOT here — it is consumer freemail (Gmail's alias),
    // handled by the is_freemail short-circuit above. google.com stays: it is
    // Google's corporate/infra domain (noc@, dns-admin@, …), not a user mailbox.
    "google.com",
    "azure.com",
    "microsoft.com",
    "fastly.com",
    "akamai.com",
    "incapsula.com",
    "imperva.com",
    "sucuri.net",
    "stackpath.com",
    "godaddy.com",
    "namecheap.com",
    "gandi.net",
    "ovh.net",
    "ovh.com",
    "digitalocean.com",
    "linode.com",
    "hetzner.com",
    "hetzner.de",
    "sendgrid.net",
    "sendgrid.com",
    "mailgun.net",
    "mailgun.org",
    "secureserver.net",
    "markmonitor.com",
    "csc.com",
    "cscglobal.com",
    "ripe.net",
    "arin.net",
    "apnic.net",
    // Registrars / registry operators whose contact mailboxes surface from
    // WHOIS/RDAP (live scan: namehost@worldnic.com — Network Solutions).
    "worldnic.com",
    "networksolutions.com",
    "web.com",
    "tucows.com",
    "enom.com",
    "name.com",
    "domaincontrol.com",
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
    // AU registrars / ccTLD operators
    "ausregistry.com.au",
    "auda.org.au",
    "melbourne.it",
    "crazydomains.com.au",
    "ventraip.com.au",
];

/// True if `domain` is a social platform or one of its country
/// subdomains (e.g. `au.linkedin.com`). Modules that follow a domain
/// to its "contact" page should skip these.
pub fn is_social_platform(domain: &str) -> bool {
    SOCIAL.iter().any(|s| is_or_subdomain_of(domain, s))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
