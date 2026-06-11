//! Domain and identity classification: mega-/infra-domain matching (so a scan
//! doesn't burn rounds mapping a platform's own estate), identity normalisation
//! and overlap (tying an alias back to the subject), and the wrong-identity-pivot
//! gate. Pure matching over strings + the curated INFRA/MEGA domain lists.
//!
//! ## Allocation budget (Termux/aarch64)
//! Every function here is on a hot path during expansion: called once per entity
//! per corroboration pass. All common paths are zero- or near-zero-allocation:
//!
//! - **Domain suffix checks** — `eq_ignore_ascii_case` byte scans; no `String`
//!   allocation (the old `to_lowercase()` allocated a fresh heap `String` per
//!   domain on every check).
//! - **`identity_overlaps`** — fast-path via `str::contains` for the common case
//!   (one identity is a substring of the other: `"bamford"` in `"haigenbamford"`),
//!   then a stack-allocated DP for the general case. No heap allocation for strings
//!   ≤ `MAX_ID_DP_COLS` chars (128); pathological inputs fall back to `Vec`.
//! - **DP row type** — `u8` (was `usize`): match-run counts for handle-length
//!   strings fit in a byte, halving the row footprint on both stack and heap.

// ── Domain suffix matching ────────────────────────────────────────────────────

/// Strip a `www.` prefix case-insensitively without allocating.
#[inline]
fn strip_www(d: &str) -> &str {
    match d.as_bytes().get(..4) {
        Some(p) if p.eq_ignore_ascii_case(b"www.") => &d[4..],
        _ => d,
    }
}

/// `d` (already www-stripped, trimmed) equals `suffix` or ends with `"." + suffix`,
/// both compared ASCII-case-insensitively. Zero allocation.
#[inline]
fn domain_suffix_ci(d: &str, suffix: &str) -> bool {
    if d.len() == suffix.len() {
        return d.eq_ignore_ascii_case(suffix);
    }
    if d.len() > suffix.len() {
        let split = d.len() - suffix.len();
        // The byte before the suffix must be '.' — ASCII, so this is a valid
        // char boundary. `split > 0` is guaranteed by `d.len() > suffix.len()`.
        return d.as_bytes()[split - 1] == b'.' && d[split..].eq_ignore_ascii_case(suffix);
    }
    false
}

/// True if `domain` is — or is a subdomain of — any entry in `list`.
/// Zero allocation: preprocessing is done via `strip_www` (a slice) + case-insensitive
/// comparison, no `to_lowercase()` String needed.
fn matches_domain_suffix(domain: &str, list: &[&str]) -> bool {
    let d = strip_www(domain.trim());
    list.iter().any(|m| domain_suffix_ci(d, m))
}

/// True if `domain` is — or is a subdomain of — a known mega-domain.
///
/// Mega-domains are top internet properties that appear in nearly every SERP.
/// Used to dampen a domain's expansion weight and (in the engine) to skip
/// expanding one that was only *incidentally* discovered, so a scan doesn't
/// burn rounds mapping a platform's own estate.
pub(crate) fn is_mega_domain(domain: &str) -> bool {
    matches_domain_suffix(domain, MEGA_DOMAINS)
}

/// True if `domain` is shared third-party infrastructure: managed DNS,
/// registrar control-plane, CDN apexes, ESP/transactional mail, or
/// AWS Route 53 nameservers (gated by a regex-free prefix scan since the
/// root suffix varies per shard: `ns-664.awsdns-19.net`).
///
/// These surface via NS/MX/SOA/reverse lookups but are incidental to any
/// subject; expanding them floods the graph with the provider's estate.
pub(crate) fn is_infra_domain(domain: &str) -> bool {
    let d = strip_www(domain.trim());
    // AWS Route 53: ns-N.awsdns-NN.{com,net,org,co.uk} — shard suffix varies.
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

/// Dampening factor for domain targets. Mega/infra domains get a 0.15× penalty
/// so they expand only after target-specific entities.
pub(super) fn domain_expansion_factor(domain: &str) -> f64 {
    if is_noncentral_domain(domain) {
        0.15
    } else {
        1.0
    }
}

// ── Identity normalisation & overlap ─────────────────────────────────────────

/// Identity fingerprint of a name / handle / email-local: lowercase ASCII
/// alphanumerics only (an email's local part is taken before `@`). Used to tie
/// a discovered alias back to the subject without a dictionary name-split.
pub(crate) fn identity_norm(s: &str) -> String {
    // For emails, use only the local part (before `@`). `split` always
    // returns at least one element, so `next()` is infallible.
    let local = s.split('@').next().unwrap_or(s);
    local
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

/// Minimum shared-substring length for two identities to be considered the same
/// person. 4 ties real aliases to the subject (`matt`↔`bamford`,
/// `bamf`↔`haigenbamford`) while rejecting unrelated handles.
pub(crate) const IDENTITY_OVERLAP_MIN: usize = 4;

/// Stack column limit for the LCS DP: covers any real-world handle or name.
/// Inputs longer than this fall back to heap allocation.
const MAX_ID_DP_COLS: usize = 128;

/// True if two identity strings share a common substring of at least
/// [`IDENTITY_OVERLAP_MIN`] characters — a cheap, dictionary-free way to decide
/// whether a discovered Username/Person plausibly belongs to the subject.
///
/// Both inputs are normalised via [`identity_norm`]. Short identities (< MIN)
/// must match exactly. O(n·m) over the two short strings — negligible for
/// handles/names.
///
/// ## Optimisations for Termux/aarch64
/// 1. **Fast path**: when one normalised identity is a full substring of the
///    other (`str::contains`, no allocation), the answer is immediate without
///    entering the DP. Catches the most common case (`"bamf"` in
///    `"haigenbamford"`, `"bamford"` in `"haigenbamford"`).
/// 2. **Stack DP**: for strings ≤ 128 chars the two rolling rows are fixed-size
///    `[u8; MAX_ID_DP_COLS]` arrays on the stack — no heap allocation at all.
///    `u8` (not `usize`) halves the row footprint; match counts never exceed the
///    string length, well within 255.
pub(crate) fn identity_overlaps(a: &str, b: &str) -> bool {
    let (a, b) = (identity_norm(a), identity_norm(b));
    if a.is_empty() || b.is_empty() {
        return false;
    }
    // Short identities: exact match only (no meaningful substring at < MIN).
    if a.len() < IDENTITY_OVERLAP_MIN || b.len() < IDENTITY_OVERLAP_MIN {
        return a == b;
    }
    // Fast path: full substring containment (zero-allocation).
    // The contained string is itself a common substring ≥ MIN chars.
    if b.contains(a.as_str()) || a.contains(b.as_str()) {
        return true;
    }
    // General LCS-DP: find a shared run ≥ IDENTITY_OVERLAP_MIN.
    let (aa, bb) = (a.as_bytes(), b.as_bytes());
    let cols = bb.len() + 1;
    if cols <= MAX_ID_DP_COLS {
        let mut prev = [0u8; MAX_ID_DP_COLS];
        let mut cur = [0u8; MAX_ID_DP_COLS];
        lcs_dp(aa, bb, &mut prev[..cols], &mut cur[..cols])
    } else {
        let mut prev = vec![0u8; cols];
        let mut cur = vec![0u8; cols];
        lcs_dp(aa, bb, &mut prev, &mut cur)
    }
}

/// Rolling LCS DP over two byte slices; returns true when a run of
/// `IDENTITY_OVERLAP_MIN` matching bytes is found. Operates on caller-supplied
/// row buffers (stack or heap) — no allocation inside.
fn lcs_dp(aa: &[u8], bb: &[u8], prev: &mut [u8], cur: &mut [u8]) -> bool {
    debug_assert_eq!(cur.len(), bb.len() + 1);
    debug_assert_eq!(prev.len(), bb.len() + 1);
    let min = IDENTITY_OVERLAP_MIN as u8;
    for &ca in aa {
        for (j, &cb) in bb.iter().enumerate() {
            cur[j + 1] = if ca == cb {
                // `saturating_add` prevents wrapping on pathological inputs.
                prev[j].saturating_add(1)
            } else {
                0
            };
            if cur[j + 1] >= min {
                return true;
            }
        }
        prev.copy_from_slice(cur);
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
/// unit-testable in isolation; the operator override (`expand_all_identities`)
/// is the only thing layered on top.
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

// ── Domain lists ──────────────────────────────────────────────────────────────

/// Shared infrastructure providers. Suffix-matched by [`is_infra_domain`].
/// CDN/cloud *corporate domains* (cloudflare.com, akamai.com, …) are here so
/// an incidental WHOIS/DNS discovery doesn't expand into the provider's estate.
/// Note: some entries also appear in [`MEGA_DOMAINS`]; `is_noncentral_domain`
/// is the authoritative composed check — a domain in either list is non-central.
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
    "name-services.com",
    "above.com",
    // CDN apex roots
    "cloudfront.net",
    "fastly.net",
    "fastlylb.net",
    "b-cdn.net", // BunnyCDN
    "kxcdn.com", // KeyCDN
    // CDN / cloud / DNS *provider corporate domains*
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
    "digitaloceanspaces.com",
    "fly.io",      // Fly.io hosting — surfaces in NS/cert records
    "vercel.app",  // Vercel — common in modern web
    "netlify.app", // Netlify — common in modern web
    "pages.dev",   // Cloudflare Pages
    "github.io",   // GitHub Pages — the platform, not the user
    "surge.sh",
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
    "klaviyomail.com",
    "postmarkapp.com",
    // Hosted-mail security gateways
    "mimecast.com",
    "pphosted.com",
    "messagelabs.com",
    "ppe-hosted.com",
    "hydra.sophos.com",
];

/// Known mega-domains (top internet properties). Suffix-matched by
/// [`is_mega_domain`]. Used for expansion dampening and incidental-discovery
/// suppression. An entry here means the domain is *ambient noise* in SERP
/// and WHOIS results — never the subject's own infrastructure for a
/// person/profile scan.
const MEGA_DOMAINS: &[&str] = &[
    // Major platforms & social media
    "amazon.com",
    "amazon.com.au",
    "apple.com",
    "discord.com",
    "discordapp.com", // Discord legacy domain
    "fb.com",         // Facebook short domain
    "facebook.com",
    "github.com",
    "google.com",
    "google.com.au",
    "instagram.com",
    "linkedin.com",
    "lnkd.in", // LinkedIn link shortener
    "microsoft.com",
    "netflix.com",
    "pinterest.com",
    "quora.com",
    "reddit.com",
    "redd.it", // Reddit short domain
    "spotify.com",
    "stackoverflow.com",
    "tiktok.com",
    "tumblr.com",
    "twitch.tv",
    "twitter.com",
    "t.co", // Twitter/X link shortener
    "whatsapp.com",
    "wikipedia.org",
    "x.com",
    "yahoo.com",
    "youtube.com",
    "youtu.be", // YouTube short domain
    // Messaging / community
    "t.me", // Telegram link shortener
    "telegram.org",
    "signal.org",
    "slack.com",
    "discord.gg", // Discord invite shortener
    "mastodon.social",
    "threads.net",
    "snapchat.com",
    // Search engines & AI
    "bing.com",
    "chatgpt.com",
    "duckduckgo.com",
    "openai.com",
    "perplexity.ai",
    "claude.ai",
    // URL shorteners (never the subject's own asset)
    "bit.ly",
    "goo.gl",
    "tinyurl.com",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    // Content platforms & blogs
    "blogspot.com",
    "medium.com",
    "substack.com",
    "wordpress.com",
    "wix.com",
    "squarespace.com",
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
    "etsy.com",
    "imdb.com",
    "pornhub.com",
    "xhamster.com",
    "xvideos.com",
    // People-search / OSINT aggregators (useful as *sources* but never the
    // subject's own domain — deep-expanding them maps the aggregator, not the person)
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
    "whitepages.com.au",
    "zabasearch.com",
    // Email providers (freemail) — never the subject's own infrastructure
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
    "tuta.io",
    "fastmail.com",
    "fastmail.fm",
    "hey.com",
    "web.de",
    "myway.com",
    // ISP / telco webmail (US + AU) — shared mailbox providers that flooded a
    // real scan as stranger co-occurrence addresses
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
    "dodo.com.au",
    // DNS / IP lookup tools
    "dnschecker.org",
    "domaintools.com",
    "ip2location.com",
    "ipaddress.com",
    "iplocation.io",
    "whatismyip.com",
    "whatismyipaddress.com",
    "whois.com",
    "shodan.io", // Common in SERP noise but is the provider, not subject
    "censys.io",
    // Australian mega-sites (common noise in AU OSINT)
    "abc.net.au",
    "ato.gov.au", // ATO — floods AU name searches
    "myaccount.ato.gov.au",
    "news.com.au",
    "smh.com.au",
    "nine.com.au",
    "realestate.com.au",
    "domain.com.au",
    "seek.com.au",
    "yellowpages.com.au",
    "truelocal.com.au",
    "localsearch.com.au",
    // Misc
    "archive.org",
    "paypal.com",
    "patreon.com",
    "ko-fi.com",
    "linktree.com", // Linktree — ubiquitous in AU social bios
    "linktr.ee",
];

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── strip_www ────────────────────────────────────────────────────────────

    #[test]
    fn strip_www_removes_lowercase_prefix() {
        assert_eq!(strip_www("www.example.com"), "example.com");
    }

    #[test]
    fn strip_www_removes_mixed_case_prefix() {
        assert_eq!(strip_www("WWW.example.com"), "example.com");
        assert_eq!(strip_www("Www.example.com"), "example.com");
    }

    #[test]
    fn strip_www_leaves_non_www_unchanged() {
        assert_eq!(strip_www("mail.example.com"), "mail.example.com");
        assert_eq!(strip_www("example.com"), "example.com");
        assert_eq!(strip_www("www"), "www"); // too short for "www."
    }

    // ── domain_suffix_ci ─────────────────────────────────────────────────────

    #[test]
    fn domain_suffix_ci_exact_match() {
        assert!(domain_suffix_ci("example.com", "example.com"));
        assert!(domain_suffix_ci("EXAMPLE.COM", "example.com"));
    }

    #[test]
    fn domain_suffix_ci_subdomain_match() {
        assert!(domain_suffix_ci("mail.example.com", "example.com"));
        assert!(domain_suffix_ci("a.b.example.com", "example.com"));
    }

    #[test]
    fn domain_suffix_ci_no_dot_boundary_is_not_a_match() {
        // "notexample.com" must NOT match suffix "example.com" — no dot boundary.
        assert!(!domain_suffix_ci("notexample.com", "example.com"));
    }

    #[test]
    fn domain_suffix_ci_shorter_than_suffix_is_not_a_match() {
        assert!(!domain_suffix_ci("ex.com", "example.com"));
    }

    // ── is_mega_domain ───────────────────────────────────────────────────────

    #[test]
    fn mega_domain_exact() {
        assert!(is_mega_domain("facebook.com"));
        assert!(is_mega_domain("reddit.com"));
        assert!(is_mega_domain("gmail.com"));
    }

    #[test]
    fn mega_domain_www_prefixed() {
        assert!(is_mega_domain("www.facebook.com"));
        assert!(is_mega_domain("www.linkedin.com"));
    }

    #[test]
    fn mega_domain_subdomain() {
        // Any subdomain of a mega should also be non-central.
        assert!(is_mega_domain("news.ycombinator.reddit.com")); // hypothetical
        assert!(is_mega_domain("support.twitter.com"));
    }

    #[test]
    fn mega_domain_au_specific() {
        assert!(is_mega_domain("seek.com.au"));
        assert!(is_mega_domain("realestate.com.au"));
        assert!(is_mega_domain("ato.gov.au"));
    }

    #[test]
    fn mega_domain_shorteners() {
        assert!(is_mega_domain("bit.ly"));
        assert!(is_mega_domain("t.co"));
        assert!(is_mega_domain("youtu.be"));
        assert!(is_mega_domain("t.me"));
    }

    #[test]
    fn non_mega_domain_passes_through() {
        assert!(!is_mega_domain("welcometothejungle.com"));
        assert!(!is_mega_domain("targetco.com.au"));
        assert!(!is_mega_domain("example.net"));
    }

    // ── is_infra_domain ──────────────────────────────────────────────────────

    #[test]
    fn infra_domain_awsdns_special_case() {
        // All Route 53 shard variants — can't be caught by suffix list alone.
        assert!(is_infra_domain("ns-664.awsdns-19.net"));
        assert!(is_infra_domain("ns-1234.awsdns-56.co.uk"));
        assert!(is_infra_domain("awsdns-01.com"));
    }

    #[test]
    fn infra_domain_cdn_and_esp() {
        assert!(is_infra_domain("u123.sendgrid.net"));
        assert!(is_infra_domain("cns1.secureserver.net"));
        assert!(is_infra_domain("ns10.dnsmadeeasy.com"));
        assert!(is_infra_domain("cloudflare.com"));
        assert!(is_infra_domain("edge.fastly.net"));
    }

    #[test]
    fn infra_domain_modern_hosting() {
        assert!(is_infra_domain("myapp.vercel.app"));
        assert!(is_infra_domain("site.netlify.app"));
        assert!(is_infra_domain("myapp.fly.io"));
    }

    #[test]
    fn non_infra_domain_passes_through() {
        assert!(!is_infra_domain("example.com"));
        assert!(!is_infra_domain("targetcompany.net"));
    }

    // ── is_noncentral_domain ─────────────────────────────────────────────────

    #[test]
    fn noncentral_combines_mega_and_infra() {
        assert!(is_noncentral_domain("gmail.com")); // mega
        assert!(is_noncentral_domain("fastly.net")); // infra
        assert!(!is_noncentral_domain("exampleco.com.au"));
    }

    // ── domain_expansion_factor ──────────────────────────────────────────────

    #[test]
    fn expansion_factor_mega_is_dampened() {
        assert_eq!(domain_expansion_factor("facebook.com"), 0.15);
        assert_eq!(domain_expansion_factor("ns-1.awsdns-1.com"), 0.15);
    }

    #[test]
    fn expansion_factor_target_specific_is_one() {
        assert_eq!(domain_expansion_factor("welcometothejungle.com"), 1.0);
    }

    // ── identity_norm ────────────────────────────────────────────────────────

    #[test]
    fn identity_norm_strips_non_alnum() {
        assert_eq!(identity_norm("haigen.bamford"), "haigenbamford");
        assert_eq!(identity_norm("haigen_bamford"), "haigenbamford");
        assert_eq!(identity_norm("haigen-bamford"), "haigenbamford");
    }

    #[test]
    fn identity_norm_email_uses_local_part() {
        assert_eq!(identity_norm("jordanavery@gmail.com"), "jordanavery");
    }

    #[test]
    fn identity_norm_uppercased_to_lower() {
        assert_eq!(identity_norm("HAIGEN"), "haigen");
        assert_eq!(identity_norm("HaigenBamford"), "haigenbamford");
    }

    #[test]
    fn identity_norm_empty_and_symbol_only() {
        assert_eq!(identity_norm(""), "");
        assert_eq!(identity_norm("---"), "");
        assert_eq!(identity_norm("@gmail.com"), ""); // no local part → empty
    }

    #[test]
    fn identity_norm_unicode_ascii_only() {
        // Non-ASCII unicode is filtered; only ASCII alnum survives.
        assert_eq!(identity_norm("café"), "caf");
        assert_eq!(identity_norm("naïve"), "nave");
    }

    // ── identity_overlaps ────────────────────────────────────────────────────

    #[test]
    fn identity_overlaps_exact_short_match() {
        // Both < MIN (4) → exact match required.
        assert!(identity_overlaps("abc", "abc"));
        assert!(!identity_overlaps("abc", "abd"));
        assert!(!identity_overlaps("ab", "abcd")); // different lengths
    }

    #[test]
    fn identity_overlaps_substring_fast_path() {
        // Common case: one is a substring of the other.
        assert!(identity_overlaps("bamford", "haigenbamford"));
        assert!(identity_overlaps("haigenbamford", "bamford"));
        assert!(identity_overlaps("haig", "haigenbamford"));
    }

    #[test]
    fn identity_overlaps_shared_middle_run() {
        // Neither is a substring of the other, but they share a ≥4-char run.
        assert!(identity_overlaps("xbcdefx", "abcdefy")); // shared "bcde" (4)
        assert!(!identity_overlaps("xbcdx", "abcdy")); // shared "bcd" only (3)
    }

    #[test]
    fn identity_overlaps_real_alias_scenario() {
        // "haigenbamford" vs "h.bamford" → normalises to "haigenbamford" vs
        // "hbamford" → shared "bamford" (7 chars) → overlap.
        assert!(identity_overlaps("haigenbamford", "h.bamford"));
        // Unrelated handle with no 4-char shared run.
        assert!(!identity_overlaps("haigenbamford", "arizonambb"));
    }

    #[test]
    fn identity_overlaps_empty_inputs_are_not_overlapping() {
        assert!(!identity_overlaps("", "haigen"));
        assert!(!identity_overlaps("haigen", ""));
        assert!(!identity_overlaps("", ""));
    }

    #[test]
    fn identity_overlaps_normalises_before_comparing() {
        // Emails: local parts compared.
        assert!(identity_overlaps(
            "haigen@example.com",
            "haigenbamford@work.com"
        ));
        // Case differences don't block overlap.
        assert!(identity_overlaps("BAMFORD", "haigenbamford"));
    }

    #[test]
    fn identity_overlaps_uses_stack_for_normal_length_inputs() {
        // Verify no panic for inputs near MAX_ID_DP_COLS (indirectly — just
        // run a 100-char input pair and assert correctness).
        let a = "a".repeat(100);
        let b = "b".repeat(50) + &"a".repeat(50);
        // They share a 50-char run of 'a' at the end of b → overlap.
        assert!(identity_overlaps(&a, &b));
    }

    // ── is_wrong_identity_pivot ──────────────────────────────────────────────

    #[test]
    fn wrong_pivot_requires_username_or_person_kind() {
        use crate::core::entity::EntityKind;
        let subjects = vec!["haigenbamford".to_string()];
        // Email is never gated as a wrong-identity pivot regardless.
        assert!(!is_wrong_identity_pivot(
            &EntityKind::Email,
            0.50,
            1,
            "stranger@example.com",
            &subjects
        ));
    }

    #[test]
    fn wrong_pivot_verified_confidence_always_expands() {
        use crate::core::entity::EntityKind;
        let subjects = vec!["haigenbamford".to_string()];
        // c_effective = 0.80 ≥ VERIFIED_MIN → not gated even if no overlap.
        assert!(!is_wrong_identity_pivot(
            &EntityKind::Username,
            0.80,
            1,
            "totalstranger",
            &subjects
        ));
    }

    #[test]
    fn wrong_pivot_corroborated_entity_always_expands() {
        use crate::core::entity::EntityKind;
        let subjects = vec!["haigenbamford".to_string()];
        // source_count = 2 → not gated.
        assert!(!is_wrong_identity_pivot(
            &EntityKind::Username,
            0.55,
            2,
            "totalstranger",
            &subjects
        ));
    }

    #[test]
    fn wrong_pivot_overlap_with_subject_always_expands() {
        use crate::core::entity::EntityKind;
        let subjects = vec!["haigenbamford".to_string()];
        // "bamf" overlaps with "haigenbamford" → not gated.
        assert!(!is_wrong_identity_pivot(
            &EntityKind::Username,
            0.55,
            1,
            "bamf",
            &subjects
        ));
    }

    #[test]
    fn wrong_pivot_gated_when_all_conditions_met() {
        use crate::core::entity::EntityKind;
        let subjects = vec!["haigenbamford".to_string()];
        // Unverified, single-source, no overlap → gated.
        assert!(is_wrong_identity_pivot(
            &EntityKind::Username,
            0.50,
            1,
            "arizonambb",
            &subjects
        ));
        assert!(is_wrong_identity_pivot(
            &EntityKind::Person,
            0.40,
            1,
            "John Smith",
            &subjects
        ));
    }

    #[test]
    fn wrong_pivot_empty_subject_list_gates_everything_unverified() {
        use crate::core::entity::EntityKind;
        // No subjects to compare against → no overlap possible → always gated
        // if unverified + single-source.
        assert!(is_wrong_identity_pivot(
            &EntityKind::Username,
            0.55,
            1,
            "haigenbamford",
            &[]
        ));
    }
}
