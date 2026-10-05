//! AT Protocol identity grammar — handles, DIDs, and the platform namespaces
//! that must not be mistaken for a subject's own infrastructure.
//!
//! Every function here is **pure**: no network, no IO, no global state. The
//! knowledge encoded is about the *protocol and the network operators*, not
//! about any one module, so `bluesky_user` and `plc_directory` share it rather
//! than each carrying a private copy that can drift.
//!
//! The distinctions this file draws are the ones that decide whether a finding
//! is true. An AT Protocol handle *looks* like a domain in every case, but
//! `alice.bsky.social` is a name Bluesky issued to alice, whereas `alice.dev` is
//! a domain alice had to prove control of. Attributing the first to alice as
//! infrastructure would be fabrication; failing to attribute the second would
//! throw away one of the few places on the open web where domain control is
//! cryptographically demonstrated as a side effect of having an account.

use crate::core::confidence;

/// Handle namespaces issued *by a platform*, where the domain belongs to the
/// operator and not to the account holder.
///
/// Deliberately **not** exhaustive, and it cannot be: any PDS operator may hand
/// out subdomains of a domain it owns, and new ones appear continuously. These
/// are the namespaces large enough that mis-attributing them would be a routine
/// error rather than an edge case:
///
///   * `.bsky.social` / `.bsky.team` — Bluesky's own default and staff handles.
///   * `.brid.gy` — Bridgy Fed's bridged fediverse/Web accounts.
///   * `.translate.goog` — Google Translate's proxy, which mirrors a site's
///     `/.well-known/atproto-did` and so satisfies handle verification for a
///     domain Google owns. A known verification loophole, not domain control.
///
/// Because the list is incomplete by construction, callers must not treat
/// "absent from this list" as "the subject controls it" — see
/// [`handle_labels`] for the structural tier that covers the remainder.
pub const PLATFORM_HANDLE_SUFFIXES: &[&str] =
    &[".bsky.social", ".bsky.team", ".brid.gy", ".translate.goog"];

/// True if `s` is a single valid DNS label per the AT Protocol handle grammar:
/// 1–63 chars, ASCII alphanumerics and hyphens only, not starting or ending with
/// a hyphen.
///
/// Underscores — common in usernames (`_ryno_23`) — are **not** permitted, so
/// such a username can never form a valid handle and callers can skip the
/// round-trip entirely rather than issue a request guaranteed to 400.
pub fn is_dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// True if `s` is a plausible dotted AT Protocol handle (`alice.dev`,
/// `alice.bsky.social`): it contains a dot and every dot-separated label is a
/// valid DNS label.
///
/// A bare single token (`alice`) is not a valid handle — it is at most the local
/// part of one — so it returns `false`.
pub fn is_handle(s: &str) -> bool {
    s.len() <= 253 && s.contains('.') && s.split('.').all(is_dns_label)
}

/// True if `s` is a syntactically valid `did:plc:` identifier.
///
/// The PLC method fixes the suffix at 24 characters of base32-sortable alphabet
/// (`a`–`z`, `2`–`7`). This is a **security gate as much as a validity check**:
/// the DID is interpolated into a URL *path*, so anything that could carry a
/// `/`, `?`, `#`, `%`, or whitespace must be rejected before it can redirect the
/// request to a different resource — the same discipline `gleif_lei`'s LEI check
/// applies for the same reason.
pub fn is_plc_did(s: &str) -> bool {
    let Some(suffix) = s.strip_prefix("did:plc:") else {
        return false;
    };
    suffix.len() == 24
        && suffix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// The host of a `did:web:` identifier, if `s` is one.
///
/// `did:web:example.com` anchors an identity to a domain by serving
/// `/.well-known/did.json` from it, so the host is a domain the subject
/// demonstrably controlled. Percent-encoded ports (`did:web:example.com%3A8443`)
/// and path-bearing forms (`did:web:example.com:user:alice`) are rejected rather
/// than half-parsed: a partially-understood identifier is exactly the kind of
/// input that yields a confident wrong host.
pub fn web_did_host(s: &str) -> Option<&str> {
    let host = s.strip_prefix("did:web:")?;
    is_handle(host).then_some(host)
}

/// The platform namespace `handle` sits in, if any — see
/// [`PLATFORM_HANDLE_SUFFIXES`].
pub fn platform_handle_suffix(handle: &str) -> Option<&'static str> {
    let lower = handle.to_ascii_lowercase();
    PLATFORM_HANDLE_SUFFIXES
        .iter()
        .copied()
        .find(|suf| lower.ends_with(suf))
}

/// The handle reduced to the identifier worth pivoting on.
///
/// A platform-issued handle collapses to its local part (`alice.bsky.social` →
/// `alice`) so it deduplicates with the same username discovered anywhere else,
/// which is the entire point of emitting it. A self-owned handle is returned
/// whole (`alice.dev` → `alice.dev`), because there the domain *is* the
/// identity and truncating it would invent a username the subject never used.
pub fn bare_handle(handle: &str) -> &str {
    match platform_handle_suffix(handle) {
        Some(suf) => &handle[..handle.len() - suf.len()],
        None => handle,
    }
}

/// Number of dot-separated labels in a handle — the structural tier that stands
/// in for the platform list where the list runs out.
///
/// An apex handle (`pfrazee.com`, 2 labels) is a registrable domain the subject
/// had to obtain; a deeper one (`alice.pds.example.org`, 4 labels) is far more
/// often a subdomain some operator issued out of a domain the subject has no
/// claim to. Callers grade the two differently rather than guessing which
/// operators exist.
pub fn handle_labels(handle: &str) -> usize {
    handle.split('.').filter(|l| !l.is_empty()).count()
}

/// How much a domain handle says about the subject, on the two axes that matter.
///
/// Both are about how likely the domain is to be *theirs*, not how likely the
/// record is to be real — the record is authoritative either way:
///
///   * **apex vs subdomain.** `pfrazee.com` is a registrable domain the subject
///     had to obtain. `alice.pds.example.org` is far more often a subdomain some
///     operator issued out of a domain the subject has no claim to.
///     [`PLATFORM_HANDLE_SUFFIXES`] catches the large namespaces by name;
///     [`handle_labels`] is what covers the long tail it cannot enumerate.
///   * **current vs former.** A handle in force now is corroborated by every
///     other source that sees the account. A handle dropped in 2023 was true
///     then, and control may since have moved.
///
/// A former subdomain handle lands *below* the noisy-OR expansion floor
/// deliberately: it is reported, and it does not go on to pull a stranger's
/// infrastructure into the graph on its own authority.
///
/// Shared rather than per-module so the same handle cannot be graded two ways —
/// two sources disagreeing about one fact is exactly what noisy-OR cannot see.
pub fn handle_domain_confidence(current: bool, handle: &str) -> f64 {
    match (current, handle_labels(handle) <= 2) {
        (true, true) => confidence::HIGH_PLUSPLUS,
        (true, false) | (false, true) => confidence::MEDIUM_PLUS,
        (false, false) => confidence::LOW_MEDIUM,
    }
}

/// What a domain handle demonstrates, for the evidence of any entity derived
/// from one.
pub const DOMAIN_HANDLE_ATTRIBUTION: &str = "AT Protocol verifies a domain handle by DNS TXT record at _atproto.<domain> or by HTTPS \
     /.well-known/atproto-did, so control of the domain was demonstrated while the handle was in \
     force";

/// What it does **not** demonstrate. Rides on every domain derived from a
/// handle, in every module that derives one.
pub const DOMAIN_HANDLE_CAVEAT: &str = "A domain handle proves the holder controlled the domain's DNS or web root at the time. It \
     does NOT prove they own the registration, and some hosting providers issue handles as \
     subdomains of a domain they own — subdomain handles are graded lower for that reason. \
     Corroborate against WHOIS/DNS before asserting ownership.";

/// True if `host` is a personal-data server operated by Bluesky Social PBC.
///
/// Accounts on these hosts are hosted, not self-hosted: the machine belongs to
/// Bluesky and tens of millions of unrelated accounts share it, so treating the
/// host as the subject's infrastructure would attribute a company's servers to
/// an individual. Covers the original monolith (`bsky.social`) and the sharded
/// estate it was migrated onto (`*.host.bsky.network`).
pub fn is_bluesky_operated_pds(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    // `.bsky.network` subsumes the `*.host.bsky.network` shards observed live;
    // matching the parent keeps new shard families from slipping through.
    host == "bsky.social" || host == "bsky.network" || host.ends_with(".bsky.network")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_token_is_a_label_but_not_a_handle() {
        assert!(is_dns_label("alice"));
        assert!(!is_handle("alice"));
        assert!(is_handle("alice.dev"));
    }

    #[test]
    fn an_underscore_username_can_never_form_a_handle() {
        // The reason the caller skips the request rather than issuing it.
        assert!(!is_dns_label("_ryno_23"));
        assert!(!is_handle("_ryno_23.bsky.social"));
    }

    #[test]
    fn a_hyphen_is_legal_inside_a_label_only() {
        assert!(is_dns_label("retr0-id"));
        assert!(!is_dns_label("-lead"));
        assert!(!is_dns_label("trail-"));
    }

    #[test]
    fn plc_dids_accept_only_the_base32_sortable_alphabet() {
        assert!(is_plc_did("did:plc:oky5czdrnfjpqslsw2a5iclo"));
        // Wrong length.
        assert!(!is_plc_did("did:plc:short"));
        // `1`, `8`, `9` and `0` are outside base32-sortable.
        assert!(!is_plc_did("did:plc:1ky5czdrnfjpqslsw2a5iclo"));
        assert!(!is_plc_did("did:plc:8ky5czdrnfjpqslsw2a5iclo"));
        // Uppercase is not the PLC alphabet.
        assert!(!is_plc_did("did:plc:OKY5CZDRNFJPQSLSW2A5ICLO"));
        // Wrong method entirely.
        assert!(!is_plc_did("did:web:example.com"));
    }

    #[test]
    fn a_plc_did_that_could_redirect_the_request_is_refused() {
        // Each is exactly 24 characters after the prefix, so only the alphabet
        // check stands between these and a URL path they were never meant to
        // address.
        for hostile in [
            "did:plc:../../../../etc/passwd/xx",
            "did:plc:aaaaaaaaaa/log/auditxxxxx",
            "did:plc:aaaaaaaaaaaa?admin=1xxxxx",
            "did:plc:aaaaaaaaaaaa#fragmentxxxx",
            "did:plc:aaaaaaaaaaaa%2Fadminxxxxx",
            "did:plc:aaaaaaaaaaaa\naaaaaaaaaaa",
            "did:plc:aaaaaaaaaaaa aaaaaaaaaaaa",
        ] {
            assert!(!is_plc_did(hostile), "accepted hostile DID: {hostile:?}");
        }
    }

    #[test]
    fn a_web_did_yields_its_host_and_nothing_stranger() {
        assert_eq!(web_did_host("did:web:example.com"), Some("example.com"));
        // Port and path forms are not half-parsed.
        assert_eq!(web_did_host("did:web:example.com%3A8443"), None);
        assert_eq!(web_did_host("did:web:example.com:user:alice"), None);
        assert_eq!(web_did_host("did:plc:oky5czdrnfjpqslsw2a5iclo"), None);
    }

    #[test]
    fn a_platform_handle_collapses_to_the_username_inside_it() {
        assert_eq!(bare_handle("alice.bsky.social"), "alice");
        assert_eq!(bare_handle("bnewbold.bsky.team"), "bnewbold");
        assert_eq!(bare_handle("someone.brid.gy"), "someone");
        assert_eq!(bare_handle("retr0-id.translate.goog"), "retr0-id");
    }

    #[test]
    fn a_self_owned_handle_is_never_truncated() {
        // Truncating `pfrazee.com` to `pfrazee` would invent a username the
        // subject never used; the domain IS the identity here.
        assert_eq!(bare_handle("pfrazee.com"), "pfrazee.com");
        assert_eq!(bare_handle("danabra.mov"), "danabra.mov");
        assert!(platform_handle_suffix("pfrazee.com").is_none());
    }

    #[test]
    fn platform_matching_ignores_case() {
        assert_eq!(bare_handle("Alice.BSKY.Social"), "Alice");
    }

    #[test]
    fn apex_and_subdomain_handles_are_distinguishable() {
        assert_eq!(handle_labels("pfrazee.com"), 2);
        assert_eq!(handle_labels("alice.pds.example.org"), 4);
        // A trailing dot is not an extra label.
        assert_eq!(handle_labels("pfrazee.com."), 2);
    }

    #[test]
    fn a_domain_handle_is_graded_on_both_axes() {
        // A registrable domain in force: the strong case.
        let strong = handle_domain_confidence(true, "pfrazee.com");
        assert!((strong - confidence::HIGH_PLUSPLUS).abs() < f64::EPSILON);
        // One weak axis each lands in the middle, still above the floor.
        for mid in [
            handle_domain_confidence(false, "pfrazee.com"),
            handle_domain_confidence(true, "alice.pds.example.org"),
        ] {
            assert!((mid - confidence::MEDIUM_PLUS).abs() < f64::EPSILON);
            assert!(mid > confidence::MEDIUM, "must stay expandable");
        }
        // Both weak: reported, and inert by construction.
        let weak = handle_domain_confidence(false, "alice.pds.example.org");
        assert!((weak - confidence::LOW_MEDIUM).abs() < f64::EPSILON);
        assert!(
            weak < confidence::MEDIUM,
            "a dropped subdomain handle must not pull a stranger's infrastructure into the graph"
        );
    }

    #[test]
    fn bluesky_operated_hosts_are_recognised_across_the_estate() {
        // Observed live: the original monolith and the sharded hosts accounts
        // were migrated onto.
        assert!(is_bluesky_operated_pds("bsky.social"));
        assert!(is_bluesky_operated_pds("morel.us-east.host.bsky.network"));
        assert!(is_bluesky_operated_pds(
            "shiitake.us-east.host.bsky.network"
        ));
        assert!(is_bluesky_operated_pds(
            "PUFFBALL.us-east.host.bsky.network"
        ));
    }

    #[test]
    fn a_third_party_host_is_not_claimed_as_blueskys() {
        // Both observed live as real PDS endpoints; neither is Bluesky's.
        assert!(!is_bluesky_operated_pds("pds.robocracy.org"));
        assert!(!is_bluesky_operated_pds("eurosky.social"));
        // Suffix matching must not be fooled by a lookalike registrable domain.
        assert!(!is_bluesky_operated_pds("bsky.social.evil.example"));
    }
}
