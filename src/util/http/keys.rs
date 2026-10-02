//! API key harvesting from arbitrary HTTP response text.

/// Scan arbitrary text for API key patterns and store any discoveries
/// in the global key pool. Call on any raw text that passes through the
/// system — HTTP response bodies, WHOIS output, certificate fields, etc.
pub fn scan_for_api_keys(text: &str) {
    scan_for_api_keys_with_source(text, "http_response");
}

pub fn scan_for_api_keys_with_source(text: &str, source: &str) {
    use crate::util::found_keys::key_tokens;
    use crate::util::key_harvest::identify_api_key;
    // Upper bound on the length of a token fed to the generic-inclusive
    // classifier. `key_tokens` *filters* on length (it skips longer tokens, it
    // does not truncate), so a too-low bound silently DROPS — i.e. hides — any
    // longer credential the body actually contained. The previous 200 dropped
    // every JWT (`eyJ…`, routinely 200–2000+ chars) and long vendor PAT (GitLab
    // ~256), all of which `identify_api_key` recognises by prefix. The cap's
    // original rationale — avoiding hex-heuristic noise on long password hashes —
    // does NOT apply above 64: `identify_api_key`'s generic-hex path fires only
    // on tokens of EXACTLY 32 or 64 hex chars, so raising the bound adds zero hex
    // noise and a random long non-key token still classifies to `None`. 4096
    // matches the harvester's DoS-safe window (`EXTRACTED_VALUE_MAX`) — well above
    // any real key, while still bounding per-token entropy cost on a hostile body.
    // The shared `key_tokens` tokenizer (incl. `?`/`&`/`{}`/`[]` delimiters) still
    // prevents query-string corruption.
    const MAX_HTTP_TOKEN: usize = 4096;
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
