//! Credential and secret redaction for HTTP error bodies and URLs.

/// Mask values for common credential query-param names inside an
/// arbitrary text blob. Used by [`super::fetch::error_snippet`] before embedding
/// upstream error bodies in module errors — many providers echo the
/// request URL in their error response, and HSE keys often ride in
/// the URL as a `?api_key=…` / `?apiKey=…` query parameter.
///
/// The matched names (`api_key`, `apiKey`, `key`, `token`, `secret`,
/// `access_token`, `auth`, plus `authorization`/`bearer` header echoes,
/// signature/SAS params, and password params) cover the providers HSE keys
/// directly (Hunter, WhoisXML, OpenCellID, Shodan, etc.) and the common token
/// shapes upstreams echo back in error bodies. The redaction replaces the value
/// with `***` and preserves the surrounding delimiters so the error message
/// still reads naturally. URL userinfo (`scheme://user:pass@host`) is masked in
/// a separate pass below.
pub(crate) fn redact_credentials(text: &str) -> String {
    const CREDENTIAL_PARAMS: &[&str] = &[
        "api_key",
        "apiKey",
        "access_token",
        "accessToken",
        "secret",
        "token",
        "auth",
        // Header echoes and signature/SAS/password shapes that several APIs
        // reflect into error bodies. `bearer` catches an echoed
        // `Authorization: Bearer <jwt>` (the helper treats `name=` and the
        // header `name<sep>value` forms; the JWT-shape pass below covers the
        // bare `Bearer eyJ…` case where no `=`/`:` delimiter follows).
        "authorization",
        "bearer",
        "sig",
        "signature",
        "sas_token",
        "sas",
        "password",
        "pwd",
        // `key` deliberately masks ANY `key=<value>` that follows a query
        // boundary (the `preceded_by_boundary` check below stops it tripping on
        // mid-word matches like `monkey=`). We accept over-redacting a benign
        // `?key=…` rather than risk leaking a credential that rides as `?key=…`
        // — over-redaction in an error string is harmless; under-redaction leaks.
        "key",
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
            let needle_eq = format!("{name}=");
            if bytes[cursor..].starts_with(needle_eq.as_bytes()) {
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
                let val_start = cursor + needle_eq.len();
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
    // Pass 2: mask URL userinfo (`scheme://user:pass@host`) and bare token
    // shapes (`Bearer eyJ…`, raw `eyJ…` JWTs) that the `name=value` query pass
    // can't see. Both reach the persisted `events` table and the SSE stream.
    let shape_masked = redact_token_shapes(&query_masked);
    // Pass 3: mask any configured secret value appearing VERBATIM. This closes
    // the gap where a key embedded in a URL *path* (e.g. IPQS
    // `/api/json/ip/<KEY>/...`) is echoed back by an upstream error body — the
    // query-param pass above only catches `name=value` shapes, so a path key
    // would otherwise survive into the persisted `events` table and SSE stream.
    redact_literal_secrets(&shape_masked, env_secret_values())
}

/// Mask credential shapes that the `name=value` query-param pass cannot catch:
/// URL userinfo (`scheme://user:pass@host` → `scheme://***@host`) and bare
/// bearer/JWT tokens (`Bearer eyJ…`, or a raw `eyJ…` JWT echoed in a body). These
/// forms have no `name=` delimiter, so they slip past the param matcher yet still
/// reach the persisted `events` table and the SSE stream. Operates on already
/// valid UTF-8 and only ever splits on ASCII anchors, so the result stays valid.
fn redact_token_shapes(text: &str) -> String {
    // 1. URL userinfo: `://user:pass@host` → `://***@host`. Anchor on `://` then
    //    mask up to the next `@`, refusing to cross a `/`, whitespace, or quote
    //    (which would mean there is no userinfo — `@` belongs to a later path or
    //    a `user@host` with no credential we shouldn't touch).
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"://") {
            let auth_start = i + 3;
            let mut j = auth_start;
            let mut at = None;
            while j < bytes.len() {
                match bytes[j] {
                    b'@' => {
                        at = Some(j);
                        break;
                    }
                    // No userinfo region — stop scanning at the host/path boundary.
                    b'/' | b'?' | b'#' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' => break,
                    _ => j += 1,
                }
            }
            if let Some(at) = at
                && at > auth_start
            {
                out.push_str("://***");
                i = at; // resume at the `@`, kept verbatim next iteration
                continue;
            }
        }
        // Copy one whole UTF-8 char. The ASCII anchors above only advance past
        // `://` / userinfo (all ASCII), so we never land mid-sequence here; the
        // char is reassembled in one `push_str` to keep the buffer valid.
        let ch_len = utf8_char_len(bytes[i]);
        let end = (i + ch_len).min(bytes.len());
        // Copy the whole char in one go to avoid emitting a partial sequence.
        if let Ok(s) = std::str::from_utf8(&bytes[i..end]) {
            out.push_str(s);
        } else {
            out.push('\u{FFFD}');
        }
        i = end;
    }
    // 2. Bare JWT / `Bearer <jwt>` shapes: a JWT is three base64url segments
    //    joined by '.', and always starts `eyJ` (base64url of `{"`). Mask any
    //    `eyJ…` run (and a preceding `Bearer `/`bearer ` if present) — these
    //    appear in echoed Authorization headers and decoded error bodies.
    mask_jwt_runs(&out)
}

/// Length of the UTF-8 char beginning at lead byte `b` (1–4). A continuation
/// byte (`0b10xx_xxxx`) or invalid lead returns 1 so the caller still advances.
fn utf8_char_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

/// Replace every `eyJ…` JWT-shaped run (optionally preceded by a `Bearer `
/// prefix) with `***`. A JWT char run is `[A-Za-z0-9_.\-]` — all ASCII, so the
/// scan never splits a multi-byte char and the result stays valid UTF-8.
fn mask_jwt_runs(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        // Optional `Bearer ` / `bearer ` prefix immediately before a JWT.
        let bearer_len = if bytes[i..].starts_with(b"Bearer ") || bytes[i..].starts_with(b"bearer ")
        {
            7
        } else {
            0
        };
        let jwt_at = i + bearer_len;
        if bytes[jwt_at..].starts_with(b"eyJ") {
            let mut end = jwt_at + 3;
            while end < bytes.len() {
                let c = bytes[end];
                if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-') {
                    end += 1;
                } else {
                    break;
                }
            }
            // Only treat as a JWT if it has at least one `.` separator in the run
            // (distinguishes a real token from an `eyJ…`-prefixed identifier).
            if text[jwt_at..end].contains('.') {
                if bearer_len > 0 {
                    out.push_str(&text[i..jwt_at]); // keep the `Bearer ` prefix
                }
                out.push_str("***");
                i = end;
                continue;
            }
        }
        let ch_len = utf8_char_len(bytes[i]);
        let stop = (i + ch_len).min(bytes.len());
        if let Ok(s) = std::str::from_utf8(&bytes[i..stop]) {
            out.push_str(s);
        } else {
            out.push('\u{FFFD}');
        }
        i = stop;
    }
    out
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
