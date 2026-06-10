//! Correlation rule set (AU-001 … AU-044): each rule scans the persisted
//! entity graph for one high-signal pattern and emits a `Correlation`.
//!
//! Rules are grouped into thematic submodules (breach/identity/infra/geo/org/
//! crypto); this module holds the shared helpers they all draw on and
//! re-exports every rule so the dispatcher's `use rules::*` is unchanged.

use std::collections::{HashMap, HashSet};

use super::{Correlation, Severity};
use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::{Relation, RelationKind};

fn entities_of_kind(entities: &[Entity], kind: EntityKind) -> Vec<&Entity> {
    entities.iter().filter(|e| e.kind == kind).collect()
}

fn tagged_matching_sources<'a>(entity: &'a Entity, allowed: &[&str]) -> HashSet<&'a str> {
    entity
        .evidence_sources()
        .into_iter()
        .filter(|s| allowed.contains(s))
        .collect()
}

/// Authoritative "known-benign infrastructure" verdicts — GreyNoise RIOT (a
/// catalogued benign service: a CDN/cloud/SaaS edge) and GreyNoise's `benign`
/// classification. Both are IP-level.
///
/// When a node carries one of these, the blocklist/scanner tags it ALSO carries
/// (`vulnerable`, `threat-intel`, `malicious`, `blocklisted`, …) are shared-edge
/// or scan artefacts, not a real threat: a Cloudflare anycast IP picks up
/// `vulnerable` from a CVE scan of the *shared* edge while GreyNoise correctly
/// catalogues it RIOT, and an emitted-on-every-co-hosted-domain explosion
/// follows. A benign verdict therefore VETOES those tags for the threat
/// correlations (AU-004/008/015/031) — the data's own ground truth, rather than
/// inferring "shared infra" from edge fan-out. Because the veto tags are IP-only,
/// a malicious *domain* behind a CDN is unaffected (it carries no benign
/// verdict); only the shared-edge IP is exonerated.
const BENIGN_INFRA_TAGS: &[&str] = &["greynoise-riot", "greynoise-benign"];

/// True if `e` carries an authoritative known-benign-infrastructure verdict that
/// vetoes bad-infra tags for threat classification (see [`BENIGN_INFRA_TAGS`]).
fn is_benign_infra(e: &Entity) -> bool {
    BENIGN_INFRA_TAGS.iter().any(|t| e.has_tag(t))
}

/// True if `text` mentions `ip` as a whole address, not as a substring of a
/// longer one. A bare `contains` is wrong: `"11.2.3.45".contains("1.2.3.4")`
/// is `true`, so an unrelated IP in an evidence summary would falsely chain. We
/// reject a match flanked by an IP-*extending* char. The extending set is
/// shape-aware: for IPv4 it is digits and `.` (a following `:`/space/`)` is a
/// legitimate boundary — `"1.2.3.4:8080"`, `"1.2.3.4: City"`); for IPv6 (the
/// needle contains `:`) it is hex digits and `:`, since `2001:db8::1` inside
/// `2001:db8::1a` is a different address — the v4-only set treated the hex
/// letter as a boundary and falsely chained. IPv6 also compares
/// ASCII-case-insensitively (entity values are normalised lowercase; module
/// summaries may spell hextets uppercase). `ip`/`text` index by byte safely —
/// `ip` is ASCII and the lowercase fold is length-preserving.
fn text_mentions_ip(text: &str, ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    let is_v6 = ip.contains(':');
    let lowered;
    let text = if is_v6 {
        lowered = text.to_ascii_lowercase();
        lowered.as_str()
    } else {
        text
    };
    let bytes = text.as_bytes();
    let n = ip.len();
    let extends = |b: u8| {
        if is_v6 {
            b.is_ascii_hexdigit() || b == b':'
        } else {
            b.is_ascii_digit() || b == b'.'
        }
    };
    let mut from = 0;
    while let Some(rel) = text[from..].find(ip) {
        let i = from + rel;
        let before_ok = i == 0 || !extends(bytes[i - 1]);
        let after_ok = i + n >= bytes.len() || !extends(bytes[i + n]);
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

/// Approximate the absolute day gap between two `YYYY-MM-DD` strings.
///
/// Intentionally dependency-free (no `chrono`/`time`): days are estimated as
/// `y*365 + m*30 + d`, so the result is **not** an exact calendar difference.
/// Error is bounded to a few days near month/year boundaries (e.g. `2020-01-31`
/// vs `2020-02-01` reads as 0). Every caller (AU-019 temporal clustering) uses a
/// coarse window (≥30 days) where this noise is irrelevant — do not reuse this
/// where exact-day precision matters. Returns `u64::MAX` if either side fails to
/// parse, which sorts/compares as "infinitely far apart" (never clusters).
pub(super) fn date_diff_days(a: &str, b: &str) -> u64 {
    let parse = |s: &str| -> Option<u64> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            return None;
        }
        let y: u64 = parts[0].parse().ok()?;
        let m: u64 = parts[1].parse().ok()?;
        let d: u64 = parts[2].parse().ok()?;
        Some(y * 365 + m * 30 + d)
    };
    match (parse(a), parse(b)) {
        (Some(da), Some(db)) => da.abs_diff(db),
        _ => u64::MAX,
    }
}

/// Role-mailbox / shared-inbox handles that identify an organisation function,
/// not a person — matching identities on these links unrelated people, so they
/// are excluded from AU-034. Complements `preflight::is_placeholder_username`
/// (admin/test/guest/…) with the shared-mailbox local-parts that pad email
/// sets. Entries are stored in canonical (separator-free, lowercase) form to
/// match [`canonical_handle`] output.
const GENERIC_HANDLES: &[&str] = &[
    "info",
    "contact",
    "support",
    "sales",
    "help",
    "hello",
    "office",
    "mail",
    "team",
    "noreply",
    "donotreply",
    "service",
    "services",
    "billing",
    "marketing",
    "press",
    "media",
    "jobs",
    "careers",
    "abuse",
    "postmaster",
    "webmaster",
    "hostmaster",
    "enquiries",
    "enquiry",
    "general",
    "accounts",
    "account",
    "newsletter",
    "subscribe",
];

/// Canonical comparison form of a handle: ASCII-lowercased with the handle
/// separators (`.`, `_`, `-`) removed, so the same handle written with
/// inconsistent punctuation collapses to one token (`jordan.meyers`,
/// `jordan_meyers`, `jordanmeyers` → `jordanmeyers`). People reuse a single
/// handle across services with different separators; this is the comparison
/// the match needs.
fn canonical_handle(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '.' | '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// True if `handle` (already canonicalised) is too generic to identify a
/// person — a placeholder username or a role mailbox.
fn is_generic_handle(handle: &str) -> bool {
    crate::util::preflight::is_placeholder_username(handle) || GENERIC_HANDLES.contains(&handle)
}

/// Modules that *derive* a username by inference — a name permutation, an email
/// local-part, or a handle variant — rather than observing it on a platform.
const USERNAME_DERIVATION_SOURCES: &[&str] = &["name_intel", "email_parse", "username_variants"];

/// Modules that *discover* a username by observing it live on a real platform /
/// corpus, confirming the handle exists.
const USERNAME_DISCOVERY_SOURCES: &[&str] = &[
    "username_search",
    "github_user",
    "keybase",
    "social_probe",
    "proxycurl",
    "epieos",
    "see_know",
    "oathnet_pro",
];

/// Tags that mark an entity as known-bad for adjacency analysis.
const ADJACENCY_BAD_TAGS: &[&str] = &["malicious", "threat-intel", "vulnerable"];

/// Minimum members for a co-location cluster to be reported.
const COLOCATION_CLUSTER_MIN: usize = 3;

// ─── Crypto / identity / exposure rules (AU-039 … AU-043) ────────────────────
//
// These exploit signal that earlier rules never saw: first-class crypto wallet
// addresses (`chain_intel`, breach-harvested), ENS-derived handles, PGP-key
// linked emails, and public paste exposure (`psbdmp`). Each turns a raw
// enrichment into a ranked, actionable finding.

/// True when a wallet was genuinely *recovered from breach/stealer data* — not
/// merely seen in some API response. Precision matters: the universal
/// `found_keys` scanner harvests crypto addresses from EVERY response body
/// (including `chain_intel`'s own blockchain-explorer replies, which list
/// contract/related addresses), so a bare `retrieved` tag would mislabel an
/// explorer artifact as a leak. We therefore require either:
///   * a breach-record-field harvest (`key_harvest::emit_key`, whose evidence
///     source is `oathnet_pro` — the shared path both breach pools use), or
///   * a `found_keys` hit whose `source_provider` is an actual breach pool.
fn is_breach_exposed_wallet(e: &Entity) -> bool {
    e.evidence.iter().any(|ev| {
        let src = ev.source.as_str();
        src == "oathnet_pro"
            || src == "see_know"
            || (src == "found_keys"
                && ev
                    .attributes
                    .get("source_provider")
                    .is_some_and(|p| matches!(p.as_str(), "see-know" | "oathnet")))
    })
}

/// Coarse provenance *family* of an evidence/module source name. Used to measure
/// CROSS-SERVICE agreement, which is stronger than a raw source count: two
/// sources in the same family (e.g. two breach DBs) can echo the same leaked
/// record, so they corroborate weakly; agreement ACROSS families (a breach DB +
/// a social platform + a search engine all naming one identifier) is genuinely
/// independent confirmation. `"other"` is the catch-all for unclassified sources
/// and is excluded from family-diversity counts. Matching is lowercase-substring
/// over the module names actually in the registry, most-specific first.
pub(super) fn source_family(source: &str) -> &'static str {
    let s = source.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| s.contains(n));
    if has(&[
        "hibp",
        "dehashed",
        "oathnet",
        "xposed",
        "leakcheck",
        "leakix",
        "snusbase",
        "intelx",
        "pwned",
        "breach",
        "stealer",
    ]) {
        "breach"
    } else if has(&[
        "github",
        "gitlab",
        "bitbucket",
        "sourceforge",
        "codeberg",
        "npm_author",
        "npm",
    ]) {
        // Code-hosting is its own provider family: a handle present here is an
        // independent signal from a forum or social account (different platforms,
        // different populations) — so it counts toward cross-service diversity.
        "code"
    } else if has(&[
        "reddit",
        "hacker_news",
        "lobsters",
        "stackoverflow",
        "stackexchange",
    ]) {
        // Discussion forums — independent of both code-hosting and social media.
        "forum"
    } else if has(&[
        "social_probe",
        "twitter",
        "instagram",
        "tiktok",
        "mastodon",
        "keybase",
        "gravatar",
    ]) {
        "social"
    } else if has(&[
        "username_search",
        "see_know",
        "holehe",
        "epieos",
        "sherlock",
        "maigret",
        "whatsmyname",
    ]) {
        "presence"
    } else if has(&[
        "google",
        "bing",
        "duckduckgo",
        "yandex",
        "brave",
        "mojeek",
        "startpage",
        "searx",
        "search_engines",
    ]) {
        "search"
    } else if has(&[
        "smtp",
        "disposable",
        "email_parse",
        "emailrep",
        "hunter",
        "mailbox",
    ]) {
        "email_intel"
    } else if has(&[
        "name_intel",
        "proxycurl",
        "opencorporates",
        "linkedin",
        "abn",
        "whoisxml",
    ]) {
        "identity_registry"
    } else if has(&[
        "dns",
        "doh",
        "whois",
        "rdap",
        "crtsh",
        "cert",
        "shodan",
        "censys",
        "greynoise",
        "hackertarget",
        "urlscan",
        "webserver",
        "waf",
        "ip_",
        "ipinfo",
        "ipquery",
        "ipapi",
        "ip2location",
        "geo",
        "wigle",
        "mylnikov",
        "overpass",
        "registry",
    ]) {
        "infra"
    } else {
        "other"
    }
}

mod assoc;
mod breach;
mod crypto;
mod geo;
mod identity;
mod infra;
mod location;
mod org;

pub(super) use assoc::*;
pub(super) use breach::*;
pub(super) use crypto::*;
pub(super) use geo::*;
pub(super) use identity::*;
pub(super) use infra::*;
pub(super) use location::*;
pub(super) use org::*;

#[cfg(test)]
mod helper_tests {
    use super::{source_family, text_mentions_ip};

    #[test]
    fn text_mentions_ip_is_whole_address_for_v4() {
        assert!(text_mentions_ip("seen at 1.2.3.4: Brisbane", "1.2.3.4"));
        assert!(text_mentions_ip("origin 1.2.3.4:8080", "1.2.3.4"));
        // Substring of a longer address must not match.
        assert!(!text_mentions_ip("host 11.2.3.45 responded", "1.2.3.4"));
        assert!(!text_mentions_ip("host 1.2.3.45 responded", "1.2.3.4"));
    }

    #[test]
    fn text_mentions_ip_is_whole_address_for_v6() {
        assert!(text_mentions_ip(
            "AAAA 2001:db8::1 for example.com",
            "2001:db8::1"
        ));
        // Bracketed-with-port spelling: ']' is a legitimate boundary.
        assert!(text_mentions_ip("via [2001:db8::1]:443", "2001:db8::1"));
        // Hex letters and ':' EXTEND a v6 address — these are different
        // addresses, and the v4-only boundary set falsely chained them.
        assert!(!text_mentions_ip("AAAA 2001:db8::1a for x", "2001:db8::1"));
        assert!(!text_mentions_ip("AAAA 2001:db8::12 for x", "2001:db8::1"));
        assert!(!text_mentions_ip("AAAA 2001:db8::1:2 for x", "2001:db8::1"));
        // Entity values are normalised lowercase; summaries may be uppercase.
        assert!(text_mentions_ip("AAAA 2001:DB8::1 for x", "2001:db8::1"));
    }

    #[test]
    fn source_family_covers_every_registered_coarse_geo_provider() {
        // The sibling providers of the already-listed ipinfo/ipquery/wigle —
        // these fell through to "other" and were excluded from cross-family
        // diversity counts, contrary to the classifier's stated intent.
        assert_eq!(source_family("ipapi"), "infra");
        assert_eq!(source_family("ip2location"), "infra");
        assert_eq!(source_family("mylnikov"), "infra");
    }
}
