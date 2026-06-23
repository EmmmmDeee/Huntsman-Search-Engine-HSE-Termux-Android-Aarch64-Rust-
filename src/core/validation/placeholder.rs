use crate::core::entity::EntityKind;

/// True if `host` is a reserved/documentation/placeholder domain that can never
/// be a real OSINT target: the RFC 2606/6761 reserved names (via
/// [`is_local_domain`](crate::util::preflight::is_local_domain)) plus the
/// ubiquitous `example.*` documentation domains and the fake `*.tld` placeholder.
///
/// Matched on whole DNS labels after stripping a leading `www.` and trailing
/// dot, so genuine domains that merely *contain* the substring — `exampleshop.com`,
/// `myexample.io`, `testflight.apple.com` — are deliberately NOT rejected.
pub fn is_placeholder_domain(host: &str) -> bool {
    let owned = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = owned.strip_prefix("www.").unwrap_or(owned.as_str());
    if h.is_empty() {
        return true;
    }
    // RFC 2606/6761 reserved TLDs + the localhost/.local/.test/.invalid family.
    if crate::util::preflight::is_local_domain(h) {
        return true;
    }
    // Any whole label literally "example": example.com/.org/.net, foo.example.co.uk…
    if h.split('.').any(|l| l == "example") {
        return true;
    }
    // Fake `*.tld` placeholder + a curated set of pure doc placeholders.
    let tld = h.rsplit('.').next().unwrap_or("");
    tld == "tld"
        || matches!(
            h,
            "domain.tld" | "yourdomain.com" | "yourdomain.tld" | "mydomain.com"
        )
}

/// Host of a URL value is a [`is_placeholder_domain`]. Cheap hand-parse (no `url`
/// crate dependency here): strips scheme, userinfo, port, and path/query/frag.
pub(super) fn url_host_is_placeholder(u: &str) -> bool {
    let after_scheme = u.split_once("://").map_or(u, |(_, r)| r);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    !host.is_empty() && is_placeholder_domain(host)
}

/// Canonical placeholder person names (synthetic "John Doe"-style values that
/// breach/permutation modules surface). Kept tight to avoid rejecting real
/// people who happen to share a common name.
pub(super) fn is_placeholder_person(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    matches!(
        n.as_str(),
        "john doe"
            | "jane doe"
            | "john q. public"
            | "john q public"
            | "test user"
            | "first last"
            | "firstname lastname"
            | "first name last name"
            | "full name"
            | "your name"
            | "name surname"
    )
}

/// Canonical documentation/template email **local-parts** — the `firstname` in
/// `firstname@gmail.com`, the `your.email` in `your.email@domain`, … These are
/// form-field templates and tutorial placeholders scraped from web pages, never
/// a real person's mailbox, yet their host is a real provider (`gmail.com`), so
/// the domain check alone can't catch them. A live `firstname@gmail.com` reached
/// VERIFIED (0.85) before this gate. Deliberately tight — only unambiguous
/// templates, compared both verbatim and separator-stripped (so `first.last`,
/// `first_last` and `firstlast` all match) — so a real handle like `matt` or a
/// real `john.smith` is never rejected.
pub(super) fn is_placeholder_email_local(local: &str) -> bool {
    let l = local.trim().to_ascii_lowercase();
    let stripped: String = l.chars().filter(char::is_ascii_alphanumeric).collect();
    const TEMPLATE: &[&str] = &[
        "firstname",
        "lastname",
        "firstnamelastname",
        "firstlast",
        "namesurname",
        "yourname",
        "fullname",
        "youremail",
        "emailaddress",
        "yourusername",
        "johndoe",
        "janedoe",
        "example",
        "sample",
    ];
    TEMPLATE.contains(&l.as_str()) || TEMPLATE.contains(&stripped.as_str())
}

/// True if a discovered entity is a documentation/placeholder artifact that
/// should never enter the graph — `example.com`, `jordan@example.com`,
/// `firstname@gmail.com`, `http://example.com`, the `example` username,
/// `John Doe`, … Enforced at the engine's admission gate alongside
/// [`is_bogus_ip`](super::ip::is_bogus_ip) so it covers every module.
///
/// Exception (the operator's rule): kinds whose VALUE is inherently unique —
/// passwords, API keys, raw credentials — are NEVER rejected, even if the value
/// happens to contain the word "example", because the secret itself is the
/// signal and is overwhelmingly unlikely to be a placeholder.
pub fn is_placeholder_entity(kind: &EntityKind, value: &str) -> bool {
    match kind {
        // Inherently-unique secrets: always kept.
        EntityKind::Password | EntityKind::ApiKey | EntityKind::Credential => false,
        EntityKind::Domain => is_placeholder_domain(value),
        EntityKind::Email => value.rsplit_once('@').is_some_and(|(local, host)| {
            is_placeholder_domain(host) || is_placeholder_email_local(local)
        }),
        EntityKind::Url => url_host_is_placeholder(value),
        EntityKind::Username => crate::util::preflight::is_placeholder_username(value),
        EntityKind::Person => is_placeholder_person(value),
        _ => false,
    }
}

/// True when an address string is specific enough to identify a *residence*
/// rather than a region. Requires a street-number signal (an ASCII digit) and at
/// least three comma/whitespace tokens, so `"123 Main St, Springfield"` qualifies
/// while a bare `"USA"` / `"California"` does not.
///
/// Single-sourced here so the breach importer (which decides whether to promote
/// an `address` field to a first-class `Address` entity) and the household
/// correlation rules (AU-049/051, which cluster co-residents by address) apply
/// the *same* definition. If they diverged, the importer could emit addresses
/// the rules never group, or the rules could expect a specificity the importer
/// never enforced. Accepts either a raw or a normalised address — the
/// comma/whitespace split and the digit/length checks are invariant under the
/// punctuation-stripping the household rule applies first.
pub fn is_specific_residence(s: &str) -> bool {
    let tokens = s
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .count();
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    tokens >= 3 && has_digit && s.trim().len() >= 8
}

/// True when `value` is a truncated / incomplete reference that cannot be
/// verified without reconstruction — the `@gmail`-style fragment the user must
/// never see in results. Centralised here so the engine (which rejects these at
/// admission) and the auditor (which flags any that slip through) judge them
/// identically. Conservative: only the kinds with an unambiguous "complete"
/// shape are checked, and inherently-opaque kinds are never fragments.
pub fn is_fragment_value(kind: &EntityKind, value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    // A trailing ellipsis or a dangling `@`/`@…prefix` is a truncation artifact
    // for ANY textual kind — except inherently-unique secrets, which may contain
    // arbitrary bytes and must never be dropped.
    if matches!(
        kind,
        EntityKind::Password | EntityKind::ApiKey | EntityKind::Credential
    ) {
        return false;
    }
    if v.ends_with('…') || v.ends_with("...") || v.ends_with('@') {
        return true;
    }
    match kind {
        EntityKind::Email => {
            // Must be local@domain.tld — reject "@gmail", "matthew@", "a@b".
            match v.split_once('@') {
                Some((local, domain)) => {
                    local.is_empty() || !domain.contains('.') || domain.starts_with('.')
                }
                None => true,
            }
        }
        // A label with no dot ("gmail" — the "@gmail" fragment in domain form)
        // or shorter than the shortest real registrable domain ("a.b") is a
        // fragment. A COMPLETE freemail provider domain (gmail.com) is
        // deliberately kept: it is a verifiable host — keeping the subject off
        // it is the expansion gate's job (`is_noncentral_domain`), not
        // admission's.
        EntityKind::Domain => v.len() < 4 || !v.contains('.'),
        // A leading `@` is a real truncation only on non-handle kinds — usernames
        // are normalised to strip a `@handle` prefix, so by the time a Username
        // reaches here a leading `@` would be a genuine fragment.
        EntityKind::Username => v.starts_with('@'),
        // A real address always carries an alphabetic locality — a suburb or
        // street name. A value with NO alphabetic character is a breach record's
        // numeric `city` field (a postcode) glued to a street number, e.g.
        // "4125, 327" (seen from an ashleymadison `city=4125` row); not a place.
        //
        // A BARE 2-letter code ("AU", "US", "PK", "WA") is likewise not an address
        // — it is a COUNTRY (ISO 3166-1 alpha-2, what breach `country` fields emit)
        // or a region/state abbreviation. Because the 2-letter code is shared across
        // hundreds of unrelated co-occurrence rows it corroborates into a VERIFIED
        // phantom address (a live QLD-subject scan produced "US" at
        // corroboration=106). A genuine address carries locality beyond the
        // country/region; the country itself survives on the `country:XX` tag and
        // evidence attributes, so nothing is lost by refusing the entity.
        //
        // Reject EVERY bare 2-letter alpha token, not only the ~54 codes the
        // `country_name_for_iso` display table happens to name: that table is a
        // deliberately-partial human-readable list, and breach corpora carry codes
        // from every country (PK, BD, VE, IR, BG, HR, LT, LV, EE, LK, QA, …). Gating
        // on the display table left every unlisted code reproducing the exact "US"
        // phantom-address pathology unblocked.
        EntityKind::Address => {
            let t = v.trim();
            !t.chars().any(char::is_alphabetic)
                || (t.len() == 2 && t.bytes().all(|b| b.is_ascii_alphabetic()))
        }
        _ => false,
    }
}
