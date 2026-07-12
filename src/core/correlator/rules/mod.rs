//! Correlation rule set (AU-001 … AU-044): each rule scans the persisted
//! entity graph for one high-signal pattern and emits a `Correlation`.
//!
//! Rules are grouped into thematic submodules (breach/identity/infra/geo/org/
//! crypto); this module holds the shared helpers they all draw on and
//! re-exports every rule so the dispatcher's `use rules::*` is unchanged.

use std::collections::{BTreeSet, HashMap, HashSet};

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

/// Tokens that are never a person's chosen handle — protocol / markup / header
/// noise (`http`, `https`, `www`, `dns`, `mailto`) or bare function words
/// (`from`) that scrapers and breach-dump parsers routinely mis-extract as a
/// "username". Unlike a role mailbox these are not even an organisational
/// function; they are extraction artifacts, so any identity rule that keys on
/// them fuses unrelated records. Stored canonical (separator-free, lowercase) to
/// match [`canonical_handle`] output.
const NON_IDENTITY_TOKENS: &[&str] = &[
    "from", "dns", "www", "http", "https", "html", "href", "mailto", "tel", "url",
];

/// Canonical comparison form of a handle: ASCII-lowercased with the handle
/// separators (`.`, `_`, `-`) removed, so the same handle written with
/// inconsistent punctuation collapses to one token (`jordan.meyers`,
/// `jordan_meyers`, `jordanmeyers` → `jordanmeyers`). People reuse a single
/// handle across services with different separators; this is the comparison
/// the match needs.
///
/// `pub(in crate::core)` (re-exported from `correlator::mod`): shared with
/// `core::relation::builders::derive_reused_secret_link`, which folds handles
/// identically to AU-047/AU-048/AU-106 so the graph edge and the correlations
/// agree on which handles are the same account.
pub(in crate::core) fn canonical_handle(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '.' | '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Join at most `cap` of `values` with ", ", appending "(+N more)" when there
/// are more — the single disclosure policy for every rule that names a
/// handful of the identifiers/sources behind a finding (AU-047, AU-048,
/// AU-076, AU-106, …) while stating the TRUE total count elsewhere in the same
/// description. Shared here (rather than re-derived per rule file) so a rule
/// can never silently enumerate a capped list with no indication that more
/// exist — the failure mode this fixes: a Critical finding whose description
/// states "controls 9 accounts" but lists only 6, with nothing telling the
/// operator 3 were omitted.
///
/// Takes a `Clone` iterator (not a `BTreeSet` directly, and not
/// `ExactSizeIterator` — `std::iter::Chain` never implements it, even when
/// both sides do) so a caller who must preserve a deliberate relative order —
/// e.g. "emails first, then usernames" — can pass `a.iter().chain(b.iter())`
/// without the values being silently re-sorted into one merged set.
fn join_capped<'a>(values: impl Iterator<Item = &'a str> + Clone, cap: usize) -> String {
    let total = values.clone().count();
    let shown: Vec<&str> = values.take(cap).collect();
    let mut s = shown.join(", ");
    if total > cap {
        s.push_str(&format!(" (+{} more)", total - cap));
    }
    s
}

/// True if `handle` (already canonicalised) is too generic to identify a
/// person — a placeholder username, a role mailbox, or a non-identity
/// extraction artifact (`from`, `dns`, `http`, …).
fn is_generic_handle(handle: &str) -> bool {
    crate::util::preflight::is_placeholder_username(handle)
        || GENERIC_HANDLES.contains(&handle)
        || NON_IDENTITY_TOKENS.contains(&handle)
}

/// Modules that *derive* a username by inference — a name permutation, an email
/// local-part, or a handle variant — rather than observing it on a platform.
/// Sources that *derive* a candidate username from a seed without independently
/// confirming the handle exists on a live platform.  `gravatar` is included
/// because it maps a seed email to the owner's stated `preferredUsername` —
/// derived from the account owner's own assertion, not an independent
/// platform observation.
const USERNAME_DERIVATION_SOURCES: &[&str] =
    &["name_intel", "email_parse", "username_variants", "gravatar"];

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

/// Modules that *confirm an email exists in real data* — breach corpora,
/// account-presence probes and profile lookups. A name-derived email GUESS
/// (`name_intel`'s `firstname.lastname@provider` permutation) that any of these
/// independently corroborates is almost certainly the subject's actual address —
/// the "prediction confirmed" signal for emails (AU-086), the email analogue of
/// the username bridge AU-077. Search-snippet recycling is deliberately excluded
/// (a guessed string echoed in a result page is not confirmation).
const EMAIL_CONFIRMATION_SOURCES: &[&str] = &[
    "hibp",
    "oathnet_pro",
    "comb_search",
    "dehashed",
    "xposed_or_not",
    "epieos",
    "emailrep",
    "gravatar",
    "holehe",
    "hunter_io",
    "seon",
    "fullcontact",
    "see_know",
    "intelx",
    "psbdmp",
    "leakix",
];

/// Tags that mark an entity as known-bad for adjacency analysis.
const ADJACENCY_BAD_TAGS: &[&str] = &[
    crate::core::tags::MALICIOUS,
    crate::core::tags::THREAT_INTEL,
    crate::core::tags::VULNERABLE,
];

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

/// The distinct provenance families under an entity's **corroborating** sources —
/// the orthogonality measure shared by the multi-pathway (AU-062) and gap (AU-063)
/// link-analysis detectors, so "which independent source families back this
/// entity" has a single definition. The unclassified `"other"` bucket is
/// retained here; callers that need genuine cross-family diversity drop it.
///
/// Built on [`Entity::corroborating_sources`], NOT `evidence_sources`: the
/// non-corroborating replay/derivation passes
/// ([`crate::core::entity::is_non_corroborating_source`] — `recall`,
/// `cross_scan_history`, and the enrichment sources `name_intel` /
/// `geo_normalize`) must not manufacture a "second orthogonal family". Two of
/// them map to real families (`name_intel` → `identity_registry`, `geo_normalize`
/// → `infra`), so counting them would let a seed-derivation or a geo-replay pose
/// as independent cross-family corroboration — the exact over-credit the AU-010
/// and `c_effective` fixes already removed from the source-count side.
fn source_families(e: &Entity) -> BTreeSet<&'static str> {
    e.corroborating_sources()
        .into_iter()
        .map(source_family)
        .collect()
}

/// Coarse provenance *family* of an evidence/module source name. Used to measure
/// CROSS-SERVICE agreement, which is stronger than a raw source count: two
/// sources in the same family (e.g. two breach DBs) can echo the same leaked
/// record, so they corroborate weakly; agreement ACROSS families (a breach DB +
/// a social platform + a search engine all naming one identifier) is genuinely
/// independent confirmation. `"other"` is the catch-all for unclassified sources
/// and is excluded from family-diversity counts. Matching is lowercase-substring
/// over the module names actually in the registry, most-specific first.
pub(in crate::core) fn source_family(source: &str) -> &'static str {
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
        "hudsonrock", // infostealer-log intelligence (exact module name)
    ]) {
        "breach"
    } else if has(&[
        "github",
        "gitlab",
        "bitbucket", // Bitbucket Cloud (exact module: bitbucket_user)
        "sourceforge",
        "codeberg",
        "npm_author",
        "npm",
        "crates",      // crates.io — Rust package registry (exact module: crates_io)
        "huggingface", // HuggingFace model/dataset registry (exact module: huggingface_user)
        "hexpm",       // hex.pm Elixir/Erlang package registry (exact module: hexpm_user)
        "codewars",    // Codewars kata platform (exact module: codewars_user)
        "launchpad",   // Launchpad Ubuntu/Debian dev platform (exact module: launchpad_user)
        "gitea",       // Gitea.com hosted git service (exact module: gitea_user)
        "cpan",        // CPAN/MetaCPAN Perl package registry (exact module: cpan_user)
        "rubygems",    // RubyGems package registry (exact module: rubygems_user)
        "pypi",        // Python Package Index (exact module: pypi_user)
    ]) {
        // Code-hosting is its own provider family: a handle present here is an
        // independent signal from a forum or social account (different platforms,
        // different populations) — so it counts toward cross-service diversity.
        "code"
    } else if has(&[
        "reddit",
        "hacker_news",
        "lobsters",
        "devto",
        "stackoverflow",
        "stackexchange",
    ]) {
        // Discussion forums / developer community blogs — independent of both
        // code-hosting and social media.
        "forum"
    } else if has(&[
        "social_probe",
        "twitter",
        "instagram",
        "tiktok",
        "mastodon",
        "bluesky",
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
        "exa_search", // Exa neural search (exact module name)
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
        // Authoritative people / business / professional registries and identity
        // enrichers (exact registry module names) — independent identity sources
        // that were falling to `other`. A subject confirmed by, e.g., an electoral
        // roll AND a breach is genuine cross-family corroboration (AU-045).
        "fullcontact",
        "contact_enrich",
        "gleif_lei",
        "asic_director",
        "au_electoral",
        "au_people",
        "ahpra",
        "acnc",
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
        "ip2location",
        "geo",
        "wigle",
        "mylnikov",
        "overpass",
        "registry",
        // Internet-wide asset/IP scanners and IP-reputation feeds — exact registry
        // module names whose forms don't contain an earlier needle. All resolve
        // network infrastructure (host/port/ASN/route/reputation), so they belong
        // to `infra`; leaving them in `other` silently under-counted infra
        // orthogonality (AU-062/063) and let `source_family`'s "covers the registry"
        // contract drift.
        "abuseipdb",
        "bgpview",
        "criminal_ip",
        "ipqs",
        "netblock",
        "netlas",
        "onyphe",
        "portscan",
        "ripestat",
        "securitytrails",
        "zoomeye",
        "domainsdb",
        "dockerhub", // Docker Hub container registry (exact module: dockerhub_user)
    ]) {
        "infra"
    } else {
        "other"
    }
}

/// Do two entities share at least one *corroborating* evidence source — i.e. was
/// there a single collection module that surfaced BOTH of them? This is the
/// concrete "co-location" tie that separates a genuine co-occurrence (a stealer
/// log / breach record naming a person and their wallet in one pass stamps the
/// same `source` on each entity it mints) from mere co-existence in the same scan
/// (two unrelated findings from two unrelated modules). Built on
/// [`Entity::corroborating_sources`], not the full evidence set, so a
/// non-corroborating replay/enrichment pass (`recall` / `cross_scan_history` /
/// `geo_normalize` / `name_intel`) can't manufacture a shared-source tie out of a
/// memory replay or a self-derivation — the same honesty rule
/// [`source_families`] already enforces for cross-family diversity.
fn shares_corroborating_source(a: &Entity, b: &Entity) -> bool {
    let b_sources = b.corroborating_sources();
    a.corroborating_sources()
        .iter()
        .any(|s| b_sources.contains(s))
}

mod assoc;
mod breach;
pub(crate) mod breach_pii;
mod broker;
mod crypto;
pub(crate) mod gap;
mod geo;
mod identity;
mod infra;
mod integrity;
mod locale;
pub(crate) mod location;
pub(crate) mod multipath;
mod org;
mod payid;
mod resolved;
mod robust;
mod sim;
mod template;
mod transitive;

pub(super) use assoc::*;
pub(super) use breach::*;
// Narrow re-export at the enum's own `pub(in crate::core)` visibility — the
// blanket glob above is only `pub(super)` (correlator-internal), which would
// otherwise cap `Secret` there too and block `core::relation::builders` from
// reaching it via `correlator::mod`'s own re-export.
pub(in crate::core) use breach::Secret;
pub(super) use breach_pii::*;
pub(super) use broker::*;
pub(super) use crypto::*;
pub(super) use gap::*;
pub(super) use geo::*;
pub(super) use identity::*;
pub(super) use infra::*;
pub(super) use integrity::*;
pub(super) use locale::*;
pub(super) use location::*;
pub(super) use multipath::*;
pub(super) use org::*;
pub(super) use payid::*;
pub(super) use resolved::*;
pub(super) use robust::*;
pub(super) use sim::*;
pub(super) use template::*;
pub(super) use transitive::*;

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
