//! Domain and identity classification: mega-/infra-domain matching (so a scan
//! doesn't burn rounds mapping a platform's own estate), identity normalisation
//! and overlap (tying an alias back to the subject), and the wrong-identity-pivot
//! gate. Pure matching over strings + the curated INFRA/MEGA domain lists.

/// Dampening factor for domain targets. Mega-domains (top internet
/// properties that appear in nearly every search result) get a 0.15×
/// penalty so they expand after target-specific entities.
///
/// Calibrated from JLM scan: facebook.com (corr=337), reddit.com (111),
/// whitepages.com (83) are noise. Target-specific domains like
/// welcometothejungle.com (corr=262) are valuable but indistinguishable
/// by corroboration alone, so we blocklist by known mega-domain.
/// True if `domain` is — or is a subdomain of — a known mega-domain (a top
/// internet property that shows up in nearly every SERP). Used both to dampen
/// such a domain's expansion weight and (in the engine) to skip expanding one
/// that was only *incidentally* discovered, so a person/profile scan doesn't
/// burn rounds mapping a platform's own DNS/mail infrastructure.
/// Registrable-suffix match: `d == m` or `d` ends with `.m` (www-stripped).
fn matches_domain_suffix(domain: &str, list: &[&str]) -> bool {
    let d = domain.trim().to_lowercase();
    let d = d.strip_prefix("www.").unwrap_or(&d);
    list.iter().any(|m| {
        d == *m
            || (d.len() > m.len() && d.as_bytes()[d.len() - m.len() - 1] == b'.' && d.ends_with(m))
    })
}

pub(crate) fn is_mega_domain(domain: &str) -> bool {
    matches_domain_suffix(domain, MEGA_DOMAINS)
}

/// Shared third-party infrastructure (managed DNS, registrar control-plane, CDN
/// apexes, ESP/transactional mail) that surfaces via NS/MX/SOA/reverse lookups
/// but is incidental to any subject — `ns10.dnsmadeeasy.com`,
/// `cns1.secureserver.net`, `u123.sendgrid.net`, `ns-664.awsdns-19.net`, … map
/// the provider's estate, not the target, so they are never worth deep-expanding.
pub(crate) fn is_infra_domain(domain: &str) -> bool {
    let d = domain.trim().to_lowercase();
    let d = d.strip_prefix("www.").unwrap_or(&d);
    // AWS Route 53 nameservers — ns-N.awsdns-NN.{com,net,org,co.uk} — whose root
    // varies with the shard number, so a plain suffix list can't catch them.
    if d.contains(".awsdns-") || d.starts_with("awsdns-") {
        return true;
    }
    matches_domain_suffix(d, INFRA_DOMAINS)
}

/// Either a mega/social platform or shared infrastructure — the haystack a lead
/// sits in, not a lead itself. The engine skips these as incidental (non-seed)
/// expansion targets so a scan doesn't map a provider's whole estate.
pub(crate) fn is_noncentral_domain(domain: &str) -> bool {
    is_mega_domain(domain) || is_infra_domain(domain)
}

/// True when `entity` should receive the `platform-infra` tag at engine admission.
///
/// Tags the entity only when *every* evidence record that carries a
/// `source_domain` attribute points to a mega/shared-infra domain. Mixed-
/// provenance entities — discovered from both a platform page AND a
/// subject-controlled domain — are NOT tagged, so they remain in default output.
/// Direct-probe results (social_probe, oathnet_pro, …) never set `source_domain`
/// and are always exempt.
pub(crate) fn should_tag_platform_infra(entity: &crate::core::entity::Entity) -> bool {
    let sourced: Vec<&str> = entity
        .evidence
        .iter()
        .filter_map(|ev| ev.attributes.get("source_domain").map(String::as_str))
        .collect();
    !sourced.is_empty() && sourced.iter().all(|d| is_noncentral_domain(d))
}

/// Identity fingerprint of a name / handle / email-local: lowercase ASCII
/// alphanumerics only (an email's local part is taken before `@`). Used to tie a
/// discovered alias back to the subject without a dictionary name-split.
pub(crate) fn identity_norm(s: &str) -> String {
    let local = s.split('@').next().unwrap_or(s);
    local
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

/// Minimum shared-substring length for two identities to be considered the same
/// person. 4 ties real aliases to the subject (`matt`↔`jordanavery`,
/// `becky`↔`avery`) while rejecting unrelated handles (`arizonambb`).
pub(crate) const IDENTITY_OVERLAP_MIN: usize = 4;

/// True if two identity strings share a common substring of at least
/// [`IDENTITY_OVERLAP_MIN`] characters — a cheap, dictionary-free way to decide
/// whether a discovered Username/Person plausibly belongs to the subject. Inputs
/// are normalised via [`identity_norm`]. Short identities (< MIN) must match
/// exactly. O(n·m) over the two short strings — negligible for handles/names.
pub(crate) fn identity_overlaps(a: &str, b: &str) -> bool {
    let (a, b) = (identity_norm(a), identity_norm(b));
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a.len() < IDENTITY_OVERLAP_MIN || b.len() < IDENTITY_OVERLAP_MIN {
        return a == b;
    }
    // Longest-common-substring ≥ MIN via a rolling DP row.
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let mut prev = vec![0usize; bb.len() + 1];
    let mut cur = vec![0usize; bb.len() + 1];
    for &ca in ab {
        for (j, &cb) in bb.iter().enumerate() {
            cur[j + 1] = if ca == cb { prev[j] + 1 } else { 0 };
            if cur[j + 1] >= IDENTITY_OVERLAP_MIN {
                return true;
            }
        }
        std::mem::swap(&mut prev, &mut cur);
        cur.iter_mut().for_each(|v| *v = 0);
    }
    false
}

/// Decide whether a discovered identity entity is a *wrong-identity* pivot —
/// one that should be recorded but not expanded, because pivoting on it would
/// pull a stranger's footprint into the scan.
///
/// An entity is gated only when ALL of these hold:
///   * it is a `Username` or `Person` (the kinds that fan out into a whole
///     online footprint when searched);
///   * it is below the Verified confidence tier (`c_effective < 0.75`) — a
///     verified identity has earned its expansion;
///   * it is single-source (`source_count <= 1`) — corroboration by a second
///     independent module is itself evidence the alias is real;
///   * its handle/name shares no [`IDENTITY_OVERLAP_MIN`]-char overlap with ANY
///     of the subject's confirmed identities (`subject_identities`).
///
/// Kept as a pure function (separate from the engine loop) so the decision is
/// unit-testable in isolation and the operator override (`expand_all_identities`)
/// is the only thing layered on top of it.
pub(crate) fn is_wrong_identity_pivot(
    kind: &crate::core::entity::EntityKind,
    c_effective: f64,
    source_count: u32,
    value: &str,
    subject_identities: &[String],
) -> bool {
    use crate::core::entity::{Classification, EntityKind};
    matches!(kind, EntityKind::Username | EntityKind::Person)
        && c_effective < Classification::VERIFIED_MIN
        && source_count <= 1
        && !subject_identities
            .iter()
            .any(|s| identity_overlaps(s, value))
}

pub(super) fn domain_expansion_factor(domain: &str) -> f64 {
    if is_noncentral_domain(domain) {
        0.15
    } else {
        1.0
    }
}

/// Shared infrastructure providers (see [`is_infra_domain`]). Suffix-matched.
const INFRA_DOMAINS: &[&str] = &[
    // Managed DNS & nameserver infrastructure
    "dnsmadeeasy.com",
    "nsone.net",
    "ultradns.net",
    "akam.net",
    "akamaiedge.net",
    "akamai.net",
    "edgekey.net",
    "edgesuite.net",
    // Registrar / hosting control-plane
    "secureserver.net",
    "domaincontrol.com",
    "registrar-servers.com",
    // CDN apex roots (edge IPs are gated by validation::is_cdn_edge_ip)
    "cloudfront.net",
    "fastly.net",
    "fastlylb.net",
    // CDN / cloud / DNS *provider corporate domains* — discovered incidentally
    // via a WHOIS registrar/abuse/dns field, a nameserver, or a role mailbox
    // (`dns@cloudflare.com`). Never the subject's own infrastructure, so
    // expanding them floods the graph with the provider's estate (a real scan
    // pulled Cloudflare's CDN IPs + role mailboxes to the top of the results).
    "cloudflare.com",
    "cloudflare.net",
    "cloudflare-dns.com",
    "fastly.com",
    "akamai.com",
    "incapsula.com",
    "imperva.com",
    "sucuri.net",
    "stackpath.com",
    "google.com",
    "googleusercontent.com",
    "googleapis.com",
    "gstatic.com",
    "1e100.net",
    "amazonaws.com",
    "azurewebsites.net",
    "windows.net",
    "azure.com",
    // ESP / transactional mail
    "sendgrid.net",
    "sendgrid.com",
    "mailgun.org",
    "mandrillapp.com",
    "sparkpostmail.com",
    "amazonses.com",
    "mcsv.net",
    "mcdlv.net",
    "rsgsv.net",
    // Hosted-mail security gateways
    "mimecast.com",
    "pphosted.com",
    "messagelabs.com",
];

const MEGA_DOMAINS: &[&str] = &[
    // Major platforms & social media
    "amazon.com",
    "amazon.com.au",
    "apple.com",
    "discord.com",
    "facebook.com",
    "github.com",
    "google.com",
    "google.com.au",
    "instagram.com",
    "linkedin.com",
    "microsoft.com",
    "netflix.com",
    "pinterest.com",
    "quora.com",
    "reddit.com",
    "spotify.com",
    "stackoverflow.com",
    "tiktok.com",
    "tumblr.com",
    "twitch.tv",
    "twitter.com",
    "whatsapp.com",
    "wikipedia.org",
    "x.com",
    "yahoo.com",
    "youtube.com",
    // Search engines & AI
    "bing.com",
    "chatgpt.com",
    "duckduckgo.com",
    "openai.com",
    // Content platforms & blogs
    "blogspot.com",
    "medium.com",
    "telegram.org",
    "wordpress.com",
    // News & media
    "bbc.co.uk",
    "bbc.com",
    "businessinsider.com",
    "cnn.com",
    "forbes.com",
    "nytimes.com",
    "reuters.com",
    "techcrunch.com",
    "theguardian.com",
    "washingtonpost.com",
    // Commerce & entertainment
    "aliexpress.com",
    "ebay.com",
    "ebay.com.au",
    "imdb.com",
    "pornhub.com",
    "xhamster.com",
    "xvideos.com",
    // CDN / infrastructure
    "akamai.com",
    "cloudflare.com",
    "fastly.com",
    // People-search / OSINT aggregators
    "anywho.com",
    "beenverified.com",
    "idcrawl.com",
    "intelius.com",
    "mylife.com",
    "nuwber.com",
    "peekyou.com",
    "pipl.com",
    "radaris.com",
    "socialcatfish.com",
    "spokeo.com",
    "truepeoplesearch.com",
    "usphonebook.com",
    "whitepages.com",
    "zabasearch.com",
    // Email providers (freemail) — never the subject's own infrastructure, so a
    // discovered freemail domain must not be deep-expanded.
    "gmail.com",
    "googlemail.com",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "msn.com",
    "office365.com",
    "outlook.com",
    "protonmail.com",
    "proton.me",
    "ymail.com",
    "aol.com",
    "me.com",
    "mac.com",
    "mail.com",
    "gmx.com",
    "gmx.de",
    "gmx.net",
    "zoho.com",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "tutanota.com",
    "fastmail.com",
    "fastmail.fm",
    "web.de",
    "myway.com",
    // ISP / telco webmail (US + AU) — shared mailbox providers, not a subject's
    // own domain. These flooded a real scan as stranger co-occurrence addresses.
    "comcast.net",
    "verizon.net",
    "att.net",
    "sbcglobal.net",
    "bellsouth.net",
    "cox.net",
    "charter.net",
    "earthlink.net",
    "windstream.net",
    "frontier.net",
    "swbell.net",
    "rr.com",
    "q.com",
    "bigpond.com",
    "bigpond.net.au",
    "optusnet.com.au",
    "iinet.net.au",
    "tpg.com.au",
    "internode.on.net",
    // DNS / IP lookup tools
    "dnschecker.org",
    "domaintools.com",
    "ip2location.com",
    "ipaddress.com",
    "iplocation.io",
    "whatismyip.com",
    "whatismyipaddress.com",
    "whois.com",
    // Australian mega-sites (common noise in AU OSINT)
    "abc.net.au",
    "news.com.au",
    "smh.com.au",
    "nine.com.au",
    "realestate.com.au",
    "seek.com.au",
    "yellowpages.com.au",
    // Additional global platforms
    "archive.org",
    "mastodon.social",
    "paypal.com",
    "snapchat.com",
    "threads.net",
];
