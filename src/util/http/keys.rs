//! API key harvesting from arbitrary HTTP response text.

/// Scan arbitrary text for API key patterns and store any discoveries
/// in the global key pool. Call on any raw text that passes through the
/// system — HTTP response bodies, WHOIS output, certificate fields, etc.
pub fn scan_for_api_keys(text: &str) {
    scan_for_api_keys_with_source(text, "http_response");
}

/// Separators that bound a key-candidate token in arbitrary scanned text.
/// No real API key contains any of these, so splitting on them can never
/// break a key — but omitting one corrupts the harvest: without `&`/`?` a
/// query-string echo (`?api_key=AKIA…&b=2`, the most common shape an upstream
/// reflects) tokenised to `AKIA…&b` — which still PASSED the vendor-prefix
/// match (`starts_with` + min-length) and was stored in the pool with the
/// trailing `&b=2` garbage attached: a corrupted key that can never
/// authenticate. `,` similarly bounds CSV-style dump rows.
pub(super) fn is_key_token_separator(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '`' | '>' | '<' | '=' | ';' | '&' | '?' | ','
        )
}

pub fn scan_for_api_keys_with_source(text: &str, source: &str) {
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;
    let pool = crate::util::key_pool::global_pool();
    let now = crate::core::entity::unix_now();
    for word in text.split(is_key_token_separator) {
        let t = word.trim();
        if t.len() >= 16
            && t.len() <= 200
            && let Some((service, key_val)) = identify_api_key(t)
        {
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.status = crate::util::key_pool::KeyStatus::Untested;
            entry.discovered_at = Some(now);
            entry.discovered_by = Some(source.to_string());
            pool.add(service, entry);
        }
    }
}
