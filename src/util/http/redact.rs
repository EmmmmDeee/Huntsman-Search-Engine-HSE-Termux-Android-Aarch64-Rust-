//! Credential and secret redaction for HTTP error bodies and URLs.

/// Mask values for common credential query-param names inside an
/// arbitrary text blob. Used by [`super::fetch::error_snippet`] before embedding
/// upstream error bodies in module errors — many providers echo the
/// request URL in their error response, and HSE keys often ride in
/// the URL as a `?api_key=…` / `?apiKey=…` query parameter.
///
/// The matched names (`api_key`, `apiKey`, `key`, `token`, `secret`,
/// `access_token`, `auth`) cover the providers HSE keys directly
/// (Hunter, WhoisXML, OpenCellID, Shodan, etc.). The redaction
/// replaces the value with `***` and preserves the surrounding
/// delimiters so the error message still reads naturally.
pub(crate) fn redact_credentials(text: &str) -> String {
    // Each literal already carries its trailing `=` so the match loop below
    // compares directly against these bytes — no `format!("{name}=")` needed
    // (and no per-position, per-name heap allocation: the old code built that
    // string fresh at EVERY cursor position for EVERY name, up to
    // `text.len() * CREDENTIAL_PARAMS.len()` allocations for a body with no
    // credential match at all).
    const CREDENTIAL_PARAMS: &[&str] = &[
        "api_key=",
        "apiKey=",
        "access_token=",
        "accessToken=",
        "secret=",
        "token=",
        "auth=",
        // `key` deliberately masks ANY `key=<value>` that follows a query
        // boundary (the `preceded_by_boundary` check below stops it tripping on
        // mid-word matches like `monkey=`). We accept over-redacting a benign
        // `?key=…` rather than risk leaking a credential that rides as `?key=…`
        // — over-redaction in an error string is harmless; under-redaction leaks.
        "key=",
    ];
    // Build on bytes, not chars: copying one byte at a time into a `String`
    // via `byte as char` would reinterpret every multi-byte UTF-8 sequence as
    // Latin-1 codepoints and mojibake any non-ASCII error text (e.g. a
    // provider's localised message). Each redacted run is bounded by an ASCII
    // delimiter (`name=` … `& \n \r "` / EOF), so copying verbatim byte-runs
    // never splits a char and the assembled buffer is always valid UTF-8.
    let mut out: Vec<u8> = Vec::with_capacity(text.len());
    let mut cursor = 0;
    let bytes = text.as_bytes();
    'outer: while cursor < bytes.len() {
        for name in CREDENTIAL_PARAMS {
            if bytes[cursor..].starts_with(name.as_bytes()) {
                // Boundary check: the preceding char (if any) should be
                // a query separator or whitespace — `apiKey=` mid-word
                // (`monKey=`) shouldn't trip.
                let preceded_by_boundary = cursor == 0
                    || matches!(
                        bytes[cursor - 1],
                        b'?' | b'&' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\''
                    );
                if !preceded_by_boundary {
                    continue;
                }
                let val_start = cursor + name.len();
                let mut end = val_start;
                while end < bytes.len() {
                    let b = bytes[end];
                    if b == b'&' || b == b' ' || b == b'\n' || b == b'\r' || b == b'"' {
                        break;
                    }
                    end += 1;
                }
                if end > val_start {
                    out.extend_from_slice(&bytes[cursor..val_start]);
                    out.extend_from_slice(b"***");
                    cursor = end;
                    continue 'outer;
                }
            }
        }
        out.push(bytes[cursor]);
        cursor += 1;
    }
    // Valid UTF-8 by construction (see above); lossy is a defensive fallback
    // that can't be reached for valid-UTF-8 input.
    let query_masked = String::from_utf8(out)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
    // Second pass: mask any configured secret value appearing VERBATIM. This
    // closes the gap where a key embedded in a URL *path* (e.g. IPQS
    // `/api/json/ip/<KEY>/...`) is echoed back by an upstream error body — the
    // query-param pass above only catches `name=value` shapes, so a path key
    // would otherwise survive into the persisted `events` table and SSE stream.
    redact_literal_secrets(&query_masked, env_secret_values())
}

/// `HUNTSMAN_*` values from the process environment — the operator's configured
/// keys (loaded via dotenvy at startup). Cheap in-memory read, consulted only on
/// the error path.
fn env_secret_values() -> impl Iterator<Item = String> {
    std::env::vars()
        .filter(|(k, _)| k.starts_with("HUNTSMAN_"))
        .map(|(_, v)| v)
}

/// Mask every `secret` wherever it appears in `text`, regardless of position
/// (path, query, header echo, body). Length-gated (>= 8) so short non-secret
/// values aren't touched. Split out from [`redact_credentials`] so it is
/// unit-testable without mutating the process environment (which is `unsafe`
/// under `#![forbid(unsafe_code)]`).
pub(super) fn redact_literal_secrets(text: &str, secrets: impl Iterator<Item = String>) -> String {
    let mut out = text.to_string();
    for v in secrets {
        if v.len() >= 8 && out.contains(v.as_str()) {
            out = out.replace(v.as_str(), "***");
        }
    }
    out
}
