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

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
