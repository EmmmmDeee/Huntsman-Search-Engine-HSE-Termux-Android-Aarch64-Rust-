//! API key harvesting from arbitrary HTTP response text.

/// Scan arbitrary text for API key patterns and store any discoveries
/// in the global key pool. Call on any raw text that passes through the
/// system — HTTP response bodies, WHOIS output, certificate fields, etc.
pub fn scan_for_api_keys(text: &str) {
    scan_for_api_keys_with_source(text, "http_response");
}

pub fn scan_for_api_keys_with_source(text: &str, source: &str) {
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;
    use crate::util::found_keys::key_tokens;
    // Conservative upper bound (200) for the generic-inclusive classifier
    // (`identify_api_key` includes the hex heuristic, which produces noise on
    // long tokens such as password hashes). The shared `key_tokens` tokenizer
    // (incl. `?`/`&`/`{}`/`[]` delimiters) prevents query-string corruption.
    const MAX_HTTP_TOKEN: usize = 200;
    let pool = crate::util::key_pool::global_pool();
    let now = crate::core::entity::unix_now();
    for t in key_tokens(text, MAX_HTTP_TOKEN) {
        if let Some((service, key_val)) = identify_api_key(t) {
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.status = crate::util::key_pool::KeyStatus::Untested;
            entry.discovered_at = Some(now);
            entry.discovered_by = Some(source.to_string());
            pool.add(service, entry);
        }
    }
}
