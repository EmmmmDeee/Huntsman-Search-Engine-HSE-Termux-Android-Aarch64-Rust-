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
    let urldecode = crate::util::http::urldecode;
    // The operator's OWN configured API keys. A key can sit ANYWHERE in a request
    // URL — a PATH segment (`…/ip/<KEY>/<value>`, IPQS/ABR-style) or a query value
    // under a non-obvious param name (`?guid=<KEY>`) — and archiving is on by
    // default, so surfacing any of them as the endpoint/query label would write the
    // key into the archive FILENAME, `_meta`, and every dossier / one-click debug
    // bundle that renders raw source records. Exclude them everywhere (the same set
    // `found_keys` uses); this complements the CRED_PARAMS param-NAME skip below,
    // which only catches conventionally-named query keys.
    let own_keys = crate::util::keys::own_api_keys();
    let is_own_key = |s: &str| !own_keys.is_empty() && own_keys.contains(urldecode(s).as_str());
    // Path segments, EXCLUDING any that is one of our own keys, so a path-embedded
    // key can never become the endpoint label (IPQS `/api/json/ip/<KEY>/<IP>` →
    // endpoint `ip`, value `<IP>`, never the key).
    let segs: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty() && !is_own_key(s))
        .collect();
    // First NON-credential query value. Picking the first value blindly would
    // write our OWN auth key into the filename + `_meta.query` for endpoints that
    // put credentials first (`?api_key=…&q=…`) — archiving is on by default, so
    // that would leak the operator's key onto disk. Credential-named params AND any
    // value that is one of our own keys are skipped; the value we surface is the
    // actual lookup term.
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
        if v.is_empty() || CRED_PARAMS.contains(&k.trim().to_lowercase().as_str()) || is_own_key(v)
        {
            return None;
        }
        Some(v)
    });

    if let Some(qv) = first_qval {
        // Query-string API (`…/search?q=value`): endpoint is the last path
        // segment (or host), the looked-up value is the first query parameter.
        let endpoint = segs
            .last()
            .map_or_else(|| host.to_string(), |s| (*s).to_string());
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
