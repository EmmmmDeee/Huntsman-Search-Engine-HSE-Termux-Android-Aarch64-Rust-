/// Derive `(endpoint, query)` labels from a request URL: the endpoint is the
/// last one or two non-empty path segments (e.g. `…/v3/breachedaccount/x` →
/// `breachedaccount`), and the query is the first query-string value, else the
/// last path segment, else the host. Pure, so it is unit-testable.
pub(super) fn describe_url(url: &str) -> (String, String) {
    let after_scheme = url.splitn(2, "://").last().unwrap_or(url);
    let (host_path, query_str) = match after_scheme.split_once('?') {
        Some((hp, q)) => (hp, q),
        None => (after_scheme, ""),
    };
    let (host, path) = match host_path.split_once('/') {
        Some((h, p)) => (h, p),
        None => (host_path, ""),
    };
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let urldecode = crate::util::http::urldecode;
    // First NON-credential query value. Picking the first value blindly would
    // write our OWN auth key into the filename + `_meta.query` for endpoints that
    // put credentials first (`?api_key=…&q=…`) — archiving is on by default, so
    // that would leak the operator's key onto disk. Credential-named params are
    // skipped; the value we surface is the actual lookup term.
    const CRED_PARAMS: &[&str] = &[
        "key",
        "api_key",
        "apikey",
        "api-key",
        "token",
        "access_token",
        "auth",
        "auth_token",
        "secret",
        "password",
        "pass",
        "apptoken",
        "app_token",
        "x-api-key",
    ];
    let first_qval = query_str.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if v.is_empty() || CRED_PARAMS.contains(&k.trim().to_lowercase().as_str()) {
            return None;
        }
        Some(v)
    });

    if let Some(qv) = first_qval {
        // Query-string API (`…/search?q=value`): endpoint is the last path
        // segment (or host), the looked-up value is the first query parameter.
        let endpoint = segs
            .last()
            .map(|s| (*s).to_string())
            .unwrap_or_else(|| host.to_string());
        (endpoint, urldecode(qv))
    } else if segs.len() >= 2 {
        // Path-style API (`…/breachedaccount/<value>`): the last segment is the
        // value, the one before names the endpoint.
        (
            segs[segs.len() - 2].to_string(),
            urldecode(segs[segs.len() - 1]),
        )
    } else if let Some(last) = segs.last() {
        (host.to_string(), urldecode(last))
    } else {
        (host.to_string(), host.to_string())
    }
}
