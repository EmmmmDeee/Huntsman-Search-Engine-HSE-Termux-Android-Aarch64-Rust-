/// The bare host substring of a URL-ish string: strip a leading `http(s)://`
/// scheme (case-insensitively — `HTTPS://` is valid per RFC 3986 §3.1), then
/// everything from the first `/` (path), `?` (query), `#` (fragment), and `:`
/// (port). Borrows; applies **no** case-folding or validity policy on the host
/// itself — callers layer that on (see [`host_from_url`]). A plain host or
/// `host:port` passes through as its host. Returns `""` when nothing host-like
/// remains.
///
/// The authority ends at the first `/`, `?`, or `#` (RFC 3986 §3.2) — all
/// three, not just the path slash. Cutting on `/` alone only *appears* to
/// handle a query, because the common URL shape carries a path slash first
/// (`…/a/b?x=1`); with an EMPTY path (`https://site.com?utm=x`,
/// `https://site.com#about` — commonplace for the bio/profile links several
/// callers feed in) nothing cut the query and the whole `site.com?utm=x` was
/// returned as the host, then minted downstream as a `Domain` entity that is
/// not a domain.
///
/// A **bracketed IPv6 literal** (`[2606:4700::1]:443`) is returned intact
/// **with** its brackets (matching `Url::host_str`): the colons inside the
/// brackets are part of the address, not the `:port` separator, so the naive
/// "split on the first colon" would otherwise truncate it to `[2606`.
#[must_use]
pub fn host_only(s: &str) -> &str {
    let trimmed = s.trim();
    let after_scheme = ["https://", "http://"]
        .iter()
        .find_map(|scheme| {
            trimmed
                .get(..scheme.len())
                .filter(|p| p.eq_ignore_ascii_case(scheme))
                .map(|_| &trimmed[scheme.len()..])
        })
        .unwrap_or(trimmed);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    // Bracketed IPv6 literal: the host is the whole `[...]`; its inner colons
    // are not a port delimiter. Return it (brackets included) before the
    // port split below would cut it at the first colon.
    if let Some(after_open) = authority.strip_prefix('[')
        && let Some(close) = after_open.find(']')
    {
        // `close` indexes into `after_open` (one past the `[`), so the `]`
        // sits at `close + 1` in `authority`; include it.
        return &authority[..close + 2];
    }
    authority.split(':').next().unwrap_or("")
}

/// The lowercased host of a URL, or `None` unless it looks like a real domain
/// (non-empty and contains a `.`). Built on [`host_only`].
#[must_use]
pub fn host_from_url(url: &str) -> Option<String> {
    let host = host_only(url).to_lowercase();
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    Some(host)
}

/// Pure-tracking URL query-parameter keys that are safe to drop when building
/// a dedup key for a URL, so two discoveries of the same resource — one with a
/// tracking suffix, one without — key identically instead of fragmenting.
///
/// Shared by [`crate::core::entity`]'s `Url` entity-UID normalisation and
/// `modules::search_engines::helpers::urls::canonicalize_url`'s SERP
/// cross-engine dedup key: before this list moved here, each kept its own
/// independently-curated copy, and they had already drifted — the search
/// module's local list was missing several of these (`twclid`, `igsh`,
/// `mibextid`, `vero_id`, `spm`, `icid`, …), so a URL varying only in one of
/// those params deduplicated as one entity but as two distinct search
/// results. One list means the two consumers can no longer silently disagree
/// on what counts as tracking noise.
///
/// Curated conservatively from the widely-used ClearURLs / Brave / Firefox
/// strip-lists: only params that are *unambiguously* tracking are listed.
/// Resource-identifying params (YouTube `v`, generic `id`/`p`/`q`/`page`) are
/// deliberately ABSENT and always preserved — dropping one would alias two
/// genuinely different resources into one key (a false merge), the opposite
/// and worse failure. The `utm_*` family is matched by prefix in
/// [`is_tracking_param_key`] rather than enumerated here.
pub const URL_TRACKING_PARAMS: &[&str] = &[
    // Google / Ads
    "gclid",
    "gclsrc",
    "dclid",
    "gbraid",
    "wbraid",
    "_ga",
    "_gl",
    // Facebook / Instagram / Meta
    "fbclid",
    "fb_action_ids",
    "fb_action_types",
    "fb_ref",
    "fb_source",
    "igshid",
    "igsh",
    "mibextid",
    // Microsoft / Bing, Twitter/X, Yandex
    "msclkid",
    "twclid",
    "ref_src",
    "ref_url",
    "yclid",
    // Email / marketing automation
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    "_hsenc",
    "_hsmi",
    "hsctatracking",
    "vero_id",
    "vero_conv",
    "oly_anon_id",
    "oly_enc_id",
    "wickedid",
    // Misc analytics
    "spm",
    "scm",
    "s_kwcid",
    "_openstat",
    "icid",
];

/// True when a query-parameter key is pure tracking and safe to drop during URL
/// canonicalisation: the `utm_*` family (case-insensitive prefix) or an exact
/// (case-insensitive) match in [`URL_TRACKING_PARAMS`]. Uses `get(..4)` rather
/// than slicing so a non-ASCII key can never panic on a char boundary.
#[must_use]
pub fn is_tracking_param_key(key: &str) -> bool {
    if key.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("utm_")) {
        return true;
    }
    URL_TRACKING_PARAMS
        .iter()
        .any(|p| key.eq_ignore_ascii_case(p))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
