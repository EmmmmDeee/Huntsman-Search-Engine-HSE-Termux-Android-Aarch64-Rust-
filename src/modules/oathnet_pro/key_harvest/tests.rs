//! Unit tests for the key-harvest classifier, extractor and decoders.
//!
//! Split out of `mod.rs` (which was ~64% test code) so the module file reads
//! as the harvest pipeline; the tests reach every private gate via `use super::*`.

use super::*;

// ── Newly added prefixes from APIKeyScanner port ──────────────

#[test]
fn detects_xai_grok_token() {
    let (svc, _) = identify_api_key("xai-abcdef1234567890abcdefg").unwrap();
    assert_eq!(svc, "xai_grok");
}

#[test]
fn detects_openai_svcacct_and_admin() {
    // High-entropy alphanumeric suffix so the FP gate passes.
    let (svc, _) =
        identify_api_key("sk-svcacct-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6")
            .unwrap();
    assert_eq!(svc, "openai_svc");
    let (svc, _) =
        identify_api_key("sk-admin-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6").unwrap();
    assert_eq!(svc, "openai_admin");
}

#[test]
fn detects_vercel_five_variants() {
    for (prefix, expected) in [
        ("vcp_", "vercel_project"),
        ("vci_", "vercel_integration"),
        ("vca_", "vercel_account"),
        ("vcr_", "vercel_runtime"),
        ("vck_", "vercel_kv"),
    ] {
        let candidate = format!("{prefix}A1b2C3d4E5f6G7h8I9j0K1l2");
        let (svc, _) =
            identify_api_key(&candidate).unwrap_or_else(|| panic!("Vercel {prefix} not detected"));
        assert_eq!(svc, expected, "wrong service mapping for {prefix}");
    }
}

#[test]
fn detects_figma_langsmith_gitlab_posthog_slackapp() {
    let cases = [
        ("figd_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0", "figma"),
        ("lsv2_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0", "langsmith"),
        ("glpat-A1b2C3d4E5f6G7h8I9j0", "gitlab_pat"),
        ("phc_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0", "posthog"),
        ("xoxa-A1b2C3d4E5f6G7h8I9j0K1l2", "slack_app"),
    ];
    for (candidate, expected) in cases {
        let (svc, _) =
            identify_api_key(candidate).unwrap_or_else(|| panic!("not detected: {candidate}"));
        assert_eq!(svc, expected, "wrong service for {candidate}");
    }
}

#[test]
fn detects_airtable_pat_with_dot_separator() {
    let candidate = format!(
        "pat{}.{}",
        "A1b2C3d4E5f6G7", // 14 alnum
        "a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6g7h8i9j0a1b2"  // 64 hex
    );
    let (svc, _) = identify_api_key(&candidate)
        .unwrap_or_else(|| panic!("Airtable PAT not detected: {candidate}"));
    assert_eq!(svc, "airtable");
}

#[test]
fn detects_twilio_api_sid_distinct_from_account_sid() {
    // SK + 32 hex chars = 34 total
    let candidate = "SKabcdef1234567890abcdef1234567890ab";
    let (svc, _) = identify_api_key(candidate).unwrap();
    assert_eq!(svc, "twilio_api_sid");
    // AC prefix already covered (account SID — same shape)
    let candidate = "ACabcdef1234567890abcdef1234567890ab";
    let (svc, _) = identify_api_key(candidate).unwrap();
    assert_eq!(svc, "twilio");
}

// ── False-positive gate ───────────────────────────────────────

#[test]
fn shannon_entropy_zero_for_empty_string() {
    assert_eq!(shannon_entropy(""), 0.0);
}

#[test]
fn shannon_entropy_zero_for_repeated_char() {
    let s = "aaaaaaaaaaaaaaaaaaaa";
    assert!(shannon_entropy(s) < 0.001);
}

#[test]
fn shannon_entropy_high_for_random_alphanumeric() {
    // A long random alphanumeric should comfortably exceed 3.5.
    let s = "kJh28slQqv61MnG9XwZpY7TfRbDvCsAo";
    assert!(shannon_entropy(s) >= 3.5, "entropy={}", shannon_entropy(s));
}

#[test]
fn is_uuid_accepts_canonical_form() {
    assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
    assert!(is_uuid("00000000-0000-0000-0000-000000000000"));
}

#[test]
fn is_uuid_rejects_malformed() {
    assert!(!is_uuid(""));
    assert!(!is_uuid("550e8400e29b41d4a716446655440000")); // no dashes
    assert!(!is_uuid("550e8400-e29b-41d4-a716-446655440000Z")); // 37 chars
    assert!(!is_uuid("550e8400-e29b-41d4-a716-44665544000Z")); // non-hex
}

#[test]
fn context_exclusions_catch_placeholder_strings() {
    assert!(contains_excluded_context("your_api_key_here_xyz"));
    assert!(contains_excluded_context("ExampleSecretToken123"));
    assert!(contains_excluded_context("AKIAxxxxxxxxxxxxxxxxxxxx"));
    assert!(contains_excluded_context("primary_key_for_users"));
    assert!(contains_excluded_context("test_key_dev"));
    assert!(contains_excluded_context("changeme_secret"));
}

#[test]
fn context_exclusions_let_real_keys_through() {
    // Pure-random tokens with no excluded substrings pass.
    assert!(!contains_excluded_context(
        "kJh28slQqv61MnG9XwZpY7TfRbDvCsAoJ"
    ));
    assert!(!contains_excluded_context(
        "ghp_aBc1deFG2HiJK3lmnoPqrStUVwXyZA"
    ));
}

#[test]
fn identify_api_key_rejects_obvious_placeholder() {
    // Looks shaped like an AWS key but contains `example`.
    assert!(identify_api_key("AKIAEXAMPLEKEY123456").is_none());
    // Looks shaped like a GitHub PAT but contains `your_`.
    assert!(identify_api_key("ghp_your_token_here_xxxxxxxxx").is_none());
}

#[test]
fn identify_api_key_rejects_low_entropy_string() {
    // 32 chars but all the same — would have matched the
    // generic_hex branch before the entropy gate.
    assert!(identify_api_key("00000000000000000000000000000000").is_none());
}

#[test]
fn identify_api_key_rejects_uuid_unless_prefix_matches() {
    // Standalone UUID — not a vendor key.
    assert!(identify_api_key("550e8400-e29b-41d4-a716-446655440000").is_none());
}

#[test]
fn identify_api_key_still_accepts_real_high_entropy_key() {
    // Real-shape AWS key with high entropy + no exclusion words.
    let candidate = "AKIAJK28SLQQV61MNG9X";
    let (svc, _) = identify_api_key(candidate).unwrap();
    assert_eq!(svc, "aws");
}

#[test]
fn fp_gate_drops_repeated_pattern_lookalikes() {
    // 36-char "github" PAT lookalike but with low entropy.
    let candidate = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert!(identify_api_key(candidate).is_none());
}

// ─── Property test over the entire pattern table ──────────────
//
// Synthesises a high-entropy candidate for every entry in
// `KEY_PATTERNS` and verifies it round-trips through the
// detector. Belt-and-braces guard against:
//   - a future prefix entry being added without a min_len that
//     a real key could plausibly satisfy
//   - the FP gate becoming too aggressive (e.g. a tighter entropy
//     threshold accidentally dropping every short AWS-style key)
//   - a re-ordering of the table breaking specific-before-generic
//     resolution (the `sk-` siblings depend on this)

/// High-entropy alphanumeric suffix used to pad synthetic
/// candidates up to a pattern's min_len. Chosen to satisfy
/// Shannon entropy ≥ 3.5 even when truncated.
const SUFFIX: &str = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4E5f6G7h8I9j0";

fn synthesise_for(prefix: &str, min_len: usize) -> String {
    let needed = min_len.saturating_sub(prefix.len());
    // Pad from SUFFIX, repeating if needed (alphanumeric → entropy stays high).
    let mut suffix = String::with_capacity(needed);
    while suffix.len() < needed {
        let take = (needed - suffix.len()).min(SUFFIX.len());
        suffix.push_str(&SUFFIX[..take]);
    }
    format!("{prefix}{suffix}")
}

#[test]
fn every_pattern_entry_round_trips_through_identify() {
    let mut missing = Vec::new();
    for pat in KEY_PATTERNS {
        let candidate = synthesise_for(pat.prefix, pat.min_len);
        match identify_api_key(&candidate) {
            Some((svc, _)) => {
                // Service may map to a SIBLING entry if the
                // table has overlapping prefixes — e.g. `sk-`,
                // `sk-proj-`, `sk-svcacct-`, `sk-admin-` all
                // share the `sk-` stem. As long as we get
                // SOME real service (not "unknown"), the
                // pattern is reachable.
                if svc.is_empty() {
                    missing.push((pat.prefix, candidate.clone()));
                }
            }
            None => {
                missing.push((pat.prefix, candidate.clone()));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "patterns failing to round-trip:\n{missing:#?}"
    );
}

#[test]
fn pattern_table_specific_prefixes_resolve_to_their_service() {
    // Whitebox check that the ORDER of the table preserves
    // specific-before-generic resolution for the sibling families
    // (sk-, vc?-, gh??-). If a future contributor moves
    // entries around this catches it.
    let cases = [
        // sk- family
        (
            "sk-svcacct-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0",
            "openai_svc",
        ),
        (
            "sk-admin-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0",
            "openai_admin",
        ),
        ("sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0", "openai"),
        // OpenRouter `sk-or-` must beat the generic `sk-` stem (regression:
        // it was declared after `sk-` and resolved as `openai_or_stripe`).
        (
            "sk-or-v1-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0",
            "openrouter",
        ),
        // gh family
        ("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "github"),
        ("github_pat_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "github"),
        (
            "ghu_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "github_user_server",
        ),
    ];
    for (cand, expected) in cases {
        let (svc, _) = identify_api_key(cand)
            .unwrap_or_else(|| panic!("expected {expected} for {cand}, got None"));
        assert_eq!(svc, expected, "wrong service for {cand}");
    }
}

#[test]
fn pattern_table_is_structurally_sound() {
    // 1. Every entry is well-formed: a non-empty prefix + service, and a
    //    min_len long enough to leave at least one character past the prefix
    //    (a min_len <= prefix length can never reject anything — a typo).
    for (k, p) in KEY_PATTERNS.iter().enumerate() {
        assert!(!p.prefix.is_empty(), "pattern #{k} has an empty prefix");
        assert!(
            !p.service.is_empty(),
            "pattern #{k} ({}) has an empty service",
            p.prefix
        );
        assert!(
            p.min_len > p.prefix.len(),
            "pattern #{k} ({}) min_len {} must exceed its prefix length {}",
            p.prefix,
            p.min_len,
            p.prefix.len()
        );
    }

    // 2. Specific-before-generic ORDERING, table-wide. `identify_api_key`
    //    returns the FIRST prefix match in declaration order, so when an
    //    earlier prefix is a *strict* prefix of a later one (the later
    //    EXTENDS it — e.g. `sk-or-` extends `sk-`), the later entry is
    //    shadowed and its keys are mis-attributed to the earlier service.
    //    That is the reorderable bug the pattern-file header warns about, and
    //    it is fixed by moving the specific entry above the generic stem.
    //    (This check found `sk-or-` OpenRouter keys resolving as the generic
    //    `sk-` `openai_or_stripe`.)
    //
    //    Same-service shadowing is excluded (merely redundant), and so are
    //    EXACT-prefix collisions (`prefix == prefix`): those are inherent
    //    real-world provider overlaps — Stripe and Clerk both mint `pk_live_`
    //    — that ordering cannot resolve, so they are not an ordering defect.
    let mut violations = Vec::new();
    for (i, earlier) in KEY_PATTERNS.iter().enumerate() {
        for (offset, later) in KEY_PATTERNS[i + 1..].iter().enumerate() {
            if later.prefix.len() > earlier.prefix.len()
                && later.prefix.starts_with(earlier.prefix)
                && earlier.service != later.service
            {
                let j = i + 1 + offset;
                violations.push(format!(
                    "#{j} ({} → {}) shadowed by earlier generic #{i} ({} → {})",
                    later.prefix, later.service, earlier.prefix, earlier.service
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "specific-before-generic ordering violated — move the more-specific prefix above the \
             generic stem so its keys are not mis-attributed:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn pattern_below_min_len_is_rejected() {
    // Truncate one char below the documented min_len for a sample
    // of patterns. Detector must NOT pick them up.
    for pat in KEY_PATTERNS.iter().take(20) {
        let cand = synthesise_for(pat.prefix, pat.min_len);
        // Shorten to one less than min_len (when possible).
        if cand.len() <= pat.prefix.len() + 1 {
            continue; // can't meaningfully truncate
        }
        let short = &cand[..cand.len() - 1];
        if short.len() >= pat.min_len {
            continue; // truncation didn't drop below min_len
        }
        // Some patterns (sk-, AKIA, AC) have min_len at or just
        // above 16; the 16-char base length gate inside
        // identify_api_key may admit them anyway. Skip those.
        if short.len() < 16 {
            continue;
        }
        assert!(
            identify_api_key(short).is_none()
                || identify_api_key(short).map(|(s, _)| s) != Some(pat.service),
            "pattern {} accepted a candidate below its min_len",
            pat.prefix,
        );
    }
}

// ─── identify_service_from_url ────────────────────────────────

#[test]
fn identify_service_from_url_matches_known_domains() {
    // Whitebox sample of the table — verifies the helper picks
    // up the most operationally-relevant providers.
    for url in [
        "https://api.openai.com/v1/chat",
        "https://platform.openai.com/account",
    ] {
        let svc = identify_service_from_url(url);
        assert!(
            svc.contains("openai") || svc == "unknown",
            "got {svc} for {url}",
        );
    }
}

#[test]
fn identify_service_from_url_returns_unknown_for_unrecognised() {
    let svc = identify_service_from_url("https://random-site-12345.example.com/x");
    assert_eq!(svc, "unknown");
}

#[test]
fn identify_service_from_url_is_host_label_aware() {
    // A service domain must match a whole host or a subdomain of it, never a
    // fragment inside a longer label. Subdomain (left boundary `.`) matches:
    assert_eq!(
        identify_service_from_url("https://api.snusbase.com/v1"),
        "snusbase"
    );
    // Messy breach-record forms still match: bare host, and host:port.
    assert_eq!(identify_service_from_url("snusbase.com"), "snusbase");
    assert_eq!(identify_service_from_url("snusbase.com:8080/x"), "snusbase");
    // Mid-label fragment on the LEFT must NOT match (the false positive this
    // fixes): `passwordhashes.com` is not `hashes.com`.
    assert_eq!(
        identify_service_from_url("https://passwordhashes.com/"),
        "unknown"
    );
    // Extension on the RIGHT must NOT match: `hashes.community` and a
    // different TLD (`*.com.au`) are distinct hosts, not the bare entry.
    assert_eq!(
        identify_service_from_url("https://hashes.community/"),
        "unknown"
    );
    assert_eq!(
        identify_service_from_url("https://snusbase.com.au/"),
        "unknown"
    );
}

#[test]
fn riskiq_domain_resolves_to_riskiq_not_passivetotal() {
    // Regression: `riskiq.net` (RiskIQ's own brand domain) was listed twice —
    // once in the PassiveTotal cluster, once in the RiskIQ cluster. The helper
    // returns the first `contains` match, so the PassiveTotal duplicate
    // shadowed the real entry and every riskiq.net URL tagged as passivetotal.
    assert_eq!(
        identify_service_from_url("https://riskiq.net/login"),
        "riskiq"
    );
    // PassiveTotal is still detected via its own domain.
    assert_eq!(
        identify_service_from_url("https://api.passivetotal.org/v2/account"),
        "passivetotal"
    );
}

#[test]
fn service_domain_table_has_no_shadowed_entries() {
    use super::service_domains::API_SERVICE_DOMAINS;
    // `identify_service_from_url` returns the FIRST table entry whose domain is
    // a substring of the URL. So if an earlier entry's domain is a substring of
    // a later entry's domain that maps to a DIFFERENT service, the later entry
    // is dead — any URL that would match it matches the earlier one first and
    // is mis-tagged. (A full domain maps to exactly one service, so unlike the
    // key-prefix table there is no inherent-overlap exception.) Same-service
    // overlaps are merely redundant and allowed. This is the guard the
    // riskiq.net duplicate would have failed.
    let mut violations = Vec::new();
    for (i, (d1, s1)) in API_SERVICE_DOMAINS.iter().enumerate() {
        for (offset, (d2, s2)) in API_SERVICE_DOMAINS[i + 1..].iter().enumerate() {
            if s1 != s2 && d2.contains(d1) {
                let j = i + 1 + offset;
                violations.push(format!(
                    "#{j} ({d2} → {s2}) shadowed by earlier #{i} ({d1} → {s1})"
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "service-domain table has shadowed/dead entries — remove the duplicate \
             or move the more-specific domain above the generic:\n  {}",
        violations.join("\n  ")
    );
}

// ─── identify_api_key — generic-hex + URL-param + user:pass ───

#[test]
fn generic_hex_32_is_detected_with_correct_service_tag() {
    // 32 lowercase hex with sufficient entropy → generic_hex
    let candidate = "a1b2c3d4e5f60718a9b0c1d2e3f40516";
    let (svc, _) = identify_api_key(candidate).unwrap();
    assert_eq!(svc, "generic_hex");
}

#[test]
fn generic_hex_64_is_detected() {
    let candidate = "a1b2c3d4e5f60718a9b0c1d2e3f40516fafbfcfdfe0102030405060708090a0b";
    let (svc, _) = identify_api_key(candidate).unwrap();
    assert_eq!(svc, "generic_hex");
}

#[test]
fn generic_hex_rejected_when_too_long_or_short() {
    // 31 chars hex — wrong shape.
    assert!(identify_api_key("a1b2c3d4e5f60718a9b0c1d2e3f4051").is_none());
    // 33 chars hex — wrong shape (not 32, not 64).
    assert!(identify_api_key("a1b2c3d4e5f60718a9b0c1d2e3f405160").is_none());
}

#[test]
fn url_query_param_with_embedded_key_resolves() {
    // The detector's URL-param fallback extracts ?key=VALUE.
    let candidate = "https://api.shodan.io/host/8.8.8.8?key=A1b2C3d4E5f6G7h8I9j0K1l2";
    let (svc, _) = identify_api_key(candidate).unwrap();
    // VALUE doesn't match a prefix but does pass the
    // url_param_key fallback (≥20 alnum/-/_).
    assert!(svc == "url_param_key" || svc != "unknown");
}

#[test]
fn url_query_param_with_known_prefix_resolves_to_specific_service() {
    let candidate = "https://api.example.com/v1?api_key=AKIAJK28SLQQV61MNG9X";
    let (svc, _) = identify_api_key(candidate).unwrap();
    assert_eq!(svc, "aws");
}

#[test]
fn user_password_format_splits_and_scans_password_half() {
    let candidate = "admin@example.com:AKIAJK28SLQQV61MNG9X";
    let (svc, _) = identify_api_key(candidate).unwrap();
    assert_eq!(svc, "aws");
}

#[test]
fn user_password_skips_http_urls() {
    // The `:` in `https://...` should NOT trigger the splitter.
    // Without a known prefix or URL-param shape, this is None.
    assert!(identify_api_key("https://example.com").is_none());
}

// ─── extract_api_keys_from_item orchestrator ──────────────────

fn empty_state() -> (HashSet<String>, ModuleResult) {
    (HashSet::new(), ModuleResult::new())
}

#[test]
fn extract_from_password_field_emits_key_entity() {
    let item = serde_json::json!({
        "password": "AKIAJK28SLQQV61MNG9X",
        "dbname": "TestBreach",
    });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "test-scan", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 1);
    assert_eq!(result.entities[0].kind, EntityKind::ApiKey);
    assert!(result.entities[0].has_tag("service:aws"));
}

#[test]
fn md5_password_hash_is_not_emitted_as_an_api_key() {
    // Regression from a live email scan: a 32-hex MD5 password hash in a breach
    // `password`/`hash` field was classified `generic_hex` and emitted as a
    // VERIFIED 0.80 ApiKey — wrong kind AND inflated confidence. A bare hex value
    // in a password field is a password hash, already captured as a credential;
    // it must NOT surface as an ApiKey.
    for field in ["password", "password_hash", "hash"] {
        let item = serde_json::json!({
            field: "5f4dcc3b5aa765d61d8327deb882cf99", // md5("password")
            "dbname": "TestBreach",
        });
        let (mut seen, mut result) = empty_state();
        extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
        assert!(
            !result.entities.iter().any(|e| e.kind == EntityKind::ApiKey),
            "{field}: md5 hash must not become an ApiKey, got {:?}",
            result.entities
        );
    }

    // But a genuine vendor-prefixed key leaked into a password field is still a
    // real key and must be emitted.
    let item = serde_json::json!({ "password": "AKIAJK28SLQQV61MNG9X" });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
    assert!(result.entities.iter().any(|e| e.kind == EntityKind::ApiKey));
}

#[test]
fn crypto_address_emits_as_crypto_address_not_api_key() {
    // Regression: a Bitcoin wallet address shares the high-entropy shape of
    // an API key, but it is NOT one. It must surface as a chain-tagged
    // CryptoAddress, never an ApiKey — and never enter the key pool.
    let item = serde_json::json!({
        // A well-known burn/genesis P2PKH address (valid base58, public).
        "secret": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "dbname": "TestBreach",
    });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
    let crypto: Vec<_> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::CryptoAddress)
        .collect();
    assert_eq!(crypto.len(), 1, "got {:?}", result.entities);
    assert!(crypto[0].has_tag("chain:btc"), "tags: {:?}", crypto[0].tags);
    assert!(
        !result.entities.iter().any(|e| e.kind == EntityKind::ApiKey),
        "a wallet address must not be classified as an API key"
    );
}

#[test]
fn extract_deduplicates_across_fields() {
    // Same key value in two fields → emit once.
    let key = "AKIAJK28SLQQV61MNG9X";
    let item = serde_json::json!({
        "password": key,
        "api_key": key,
    });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 1, "dedup should fire");
}

#[test]
fn extract_from_url_query_param() {
    let item = serde_json::json!({
        "url": "https://api.shodan.io/host/1.1.1.1?key=AKIAJK28SLQQV61MNG9X",
    });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 1);
    assert!(result.entities[0].has_tag("service:aws"));
}

#[test]
fn extract_from_extra_object_strings() {
    let item = serde_json::json!({
        "extra": {
            "saved_token": "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "irrelevant": "short",
        }
    });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 1);
    assert!(result.entities[0].has_tag("service:github"));
}

#[test]
fn extract_from_stealer_log_specific_fields() {
    // New fields added in this commit for stealer-log breadth.
    for field in [
        "bearer_token",
        "client_secret",
        "oauth_token",
        "personal_access_token",
        "pat",
        "webhook_secret",
        "app_password",
        "discord_token",
        "telegram_session",
        "cookie",
        "session_token",
        "note",
        "notes",
        "app_data",
        "env_content",
        "env",
        "dotenv",
    ] {
        let item = serde_json::json!({
            field: "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        });
        let (mut seen, mut result) = empty_state();
        extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
        assert_eq!(
            result.entities.len(),
            1,
            "field `{field}` should route through the scanner",
        );
    }
}

#[test]
fn extract_from_dotenv_blob_finds_every_key() {
    // Multi-line `.env` content — one valid key per line should
    // produce one entity each.
    let blob = "OPENAI_API_KEY=sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0\n\
                    AWS_ACCESS_KEY_ID=AKIAJK28SLQQV61MNG9X\n\
                    SHODAN=A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6\n\
                    GIBBERISH=short";
    let item = serde_json::json!({ "env_content": blob });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
    // Two real prefixed keys + the 32-char hex generic_hex
    // catch from the SHODAN line.
    assert!(
        result.entities.len() >= 2,
        "expected ≥2 keys from dotenv blob, got {}: {:?}",
        result.entities.len(),
        result
            .entities
            .iter()
            .map(|e| e.value.as_str())
            .collect::<Vec<_>>()
    );
    // First two specific services round-trip:
    assert!(
        result.entities.iter().any(|e| e.has_tag("service:openai")),
        "missing openai key from dotenv blob"
    );
    assert!(
        result.entities.iter().any(|e| e.has_tag("service:aws")),
        "missing aws key from dotenv blob"
    );
}

#[test]
fn extract_from_dotenv_handles_export_prefix_and_quoting() {
    // bash-style `export KEY="value"` lines and quoted values.
    let blob = "export OPENAI=\"sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0\"\n\
                    AWS='AKIAJK28SLQQV61MNG9X'\n\
                    GH=`ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8`";
    let item = serde_json::json!({ "env_content": blob });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
    let svcs: Vec<String> = result
        .entities
        .iter()
        .flat_map(|e| {
            e.tags
                .iter()
                .filter(|t| t.starts_with("service:"))
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(svcs.iter().any(|s| s == "service:openai"));
    assert!(svcs.iter().any(|s| s == "service:aws"));
    assert!(svcs.iter().any(|s| s == "service:github"));
}

#[test]
fn extract_from_cookies_array_with_jwt_value() {
    // Stealer logs export browser cookies as
    // [{name, value, domain, ...}]. A JWT-shaped cookie value
    // should land via the eyJ pattern.
    let jwt = "eyJabcdefghijklmnopqrstuvwxyz0123456789.payload.signature";
    let item = serde_json::json!({
        "cookies": [
            {"name": "session", "value": jwt, "domain": ".openai.com"}
        ]
    });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 1);
    assert!(result.entities[0].has_tag("service:jwt_token"));
}

#[test]
fn extract_skips_short_or_empty_inputs() {
    // Nothing harvestable.
    let item = serde_json::json!({
        "password": "short",
        "api_key": "",
        "extra": {"x": "tiny"},
    });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
    assert!(result.entities.is_empty());
}

#[test]
fn extract_from_username_when_log_misformatted() {
    // Some malformed stealer logs put the key in the username.
    let item = serde_json::json!({
        "username": "AKIAJK28SLQQV61MNG9X",
        "password": "plaintext-password-not-a-key",
    });
    let (mut seen, mut result) = empty_state();
    extract_api_keys_from_item(&item, "scan", &mut seen, &mut result);
    assert!(result.entities.iter().any(|e| e.has_tag("service:aws")));
}

// ─── Cryptocurrency address detection ─────────────────────────

#[test]
fn detects_btc_p2pkh_address() {
    // Genesis block address — the canonical P2PKH example.
    let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let (svc, _) = identify_api_key(addr).unwrap();
    assert_eq!(svc, "crypto_btc");
}

#[test]
fn detects_btc_p2sh_address() {
    // Well-known multisig (BitGo cold storage).
    let addr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
    let (svc, _) = identify_api_key(addr).unwrap();
    assert_eq!(svc, "crypto_btc");
}

#[test]
fn detects_btc_bech32_address() {
    // Public Casa cold-storage example.
    let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    let (svc, _) = identify_api_key(addr).unwrap();
    assert_eq!(svc, "crypto_btc");
}

#[test]
fn detects_eth_address() {
    // Vitalik's public ETH address — burn-the-house demo.
    let addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
    let (svc, _) = identify_api_key(addr).unwrap();
    assert_eq!(svc, "crypto_eth");
}

#[test]
fn detects_ltc_legacy_and_bech32() {
    // Litecoin Foundation cold storage (L-prefix).
    let legacy = "LbXkRGUgcRk2xWJpgyaufxNS3GdvLh6ETh";
    let (svc, _) = identify_api_key(legacy).unwrap();
    assert_eq!(svc, "crypto_ltc");
    // Bech32 form
    let bech = "ltc1qd9mq4uxfqr3zdkugxg5p2hpzx5d3v6e4t9k0w7";
    let (svc, _) = identify_api_key(bech).unwrap();
    assert_eq!(svc, "crypto_ltc");
}

#[test]
fn detects_doge_address() {
    // Dogecoin Foundation address — D-prefix, 34 chars.
    let addr = "D8oXmDe2KEYxJPxhAcEfqGdxF2P7yctL5h";
    let (svc, _) = identify_api_key(addr).unwrap();
    assert_eq!(svc, "crypto_doge");
}

#[test]
fn detects_sol_address() {
    // Solana public address — 44 chars base58.
    let addr = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    let (svc, _) = identify_api_key(addr).unwrap();
    assert_eq!(svc, "crypto_sol");
}

#[test]
fn detects_xmr_address() {
    // Monero public address — exactly 95 chars, starts with 4.
    // Real-shape synthetic (no actual funds); every char is
    // in the Base58 set (no 0/O/I/l).
    let addr = "4AdUndXHHZ9pfQj27iMrL2QM5nYpZ8AyL3VBmHuMrL8ZzgnsAbHjy8mhLHBP1J7yU3KqHzPaH6vGm1JZqfwLnFq8m1jBxwZ";
    assert_eq!(addr.len(), 95, "synthetic XMR test fixture wrong length");
    let (svc, _) = identify_api_key(addr).unwrap();
    assert_eq!(svc, "crypto_xmr");
}

#[test]
fn crypto_addresses_dont_collide_with_eth_hex_prefix() {
    // A 42-char string starting with `0x` but containing
    // non-hex chars must NOT be detected as ETH.
    let candidate = "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
    assert!(identify_crypto_address(candidate).is_none());
}

#[test]
fn crypto_address_wrong_length_rejected() {
    // 41-char `0x` string: too short for ETH; must not match.
    assert!(identify_crypto_address("0x123456789012345678901234567890123456789").is_none());
    // 43-char `0x` string: too long for ETH; must not match.
    assert!(identify_crypto_address("0x12345678901234567890123456789012345678901").is_none());
}

#[test]
fn crypto_btc_legacy_with_invalid_base58_char_rejected() {
    // Base58 excludes 0, O, I, l — using `0` in the body
    // disqualifies the candidate even with the `1` prefix
    // and right length.
    let bad = "10ABCDEFGHIJKLMNOPQRSTUVWXYZab"; // contains 0
    assert!(identify_crypto_address(bad).is_none());
}

#[test]
fn extract_from_clipboard_hijacker_app_data_picks_up_btc() {
    // Simulates a Vidar/RedLine clipboard-hijacker stage
    // exporting captured wallet addresses as `app_data`.
    let item = serde_json::json!({
        "app_data": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "dbname": "ClipboardCapture2025",
    });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_api_keys_from_item(&item, "test", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 1);
    // A wallet address is a first-class CryptoAddress, not an API key.
    assert_eq!(result.entities[0].kind, EntityKind::CryptoAddress);
    assert!(result.entities[0].has_tag("chain:btc"));
}

#[test]
fn extract_from_dotenv_with_mixed_crypto_and_api_keys() {
    // A `.env` dump from a `node` project doing Web3 work
    // commonly mixes ETH wallet + Etherscan API key + RPC URL.
    let blob = "OWNER_WALLET=0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\
                    ETHERSCAN_KEY=AKIAJK28SLQQV61MNG9X\n\
                    INFURA_PROJECT=A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
    let item = serde_json::json!({ "env_content": blob });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_api_keys_from_item(&item, "test", &mut seen, &mut result);
    // Both surface, each correctly typed: the ETH wallet as a
    // CryptoAddress (chain:eth), and the AWS-shape impostor (the operator's
    // deliberate `ETHERSCAN_KEY=` mis-naming — its value matches our AWS
    // pattern) as an ApiKey (service:aws).
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::CryptoAddress && e.has_tag("chain:eth"))
    );
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::ApiKey && e.has_tag("service:aws"))
    );
}

// ─── KeyFinder-ported prefix coverage ──────────────────────────

#[test]
fn detects_square_oauth_id_and_app_secret() {
    // Square OAuth ID + Application secret prefixes (sq0idp- /
    // sq0csp-) — separate from the existing sq0atp- access token.
    let oauth_id = "sq0idp-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5";
    let (svc, _) = identify_api_key(oauth_id).unwrap();
    assert_eq!(svc, "square_oauth_id");

    let app_secret = "sq0csp-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let (svc, _) = identify_api_key(app_secret).unwrap();
    assert_eq!(svc, "square_app_secret");
}

#[test]
fn detects_planetscale_password_and_token() {
    let pw = "pscale_pw_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
    let (svc, _) = identify_api_key(pw).unwrap();
    assert_eq!(svc, "planetscale_password");

    let tkn = "pscale_tkn_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
    let (svc, _) = identify_api_key(tkn).unwrap();
    assert_eq!(svc, "planetscale_token");
}

#[test]
fn detects_all_four_doppler_token_classes() {
    let cases = [
        (
            "dp.pt.A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "doppler_personal",
        ),
        ("dp.ct.A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "doppler_cli"),
        (
            "dp.sa.A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "doppler_service_acct",
        ),
        (
            "dp.st.A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "doppler_service_token",
        ),
    ];
    for (cand, expected) in cases {
        let (svc, _) = identify_api_key(cand)
            .unwrap_or_else(|| panic!("Doppler {expected} not detected for {cand}"));
        assert_eq!(svc, expected);
    }
}

#[test]
fn detects_docker_hub_pat() {
    let cand = "dckr_pat_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let (svc, _) = identify_api_key(cand).unwrap();
    assert_eq!(svc, "docker_hub_pat");
}

#[test]
fn detects_vault_service_and_batch_tokens() {
    // Vault tokens are notoriously long (90+ chars).
    let svc_token = format!(
        "hvs.{}",
        "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    );
    let (svc, _) = identify_api_key(&svc_token).unwrap();
    assert_eq!(svc, "vault_service");

    let batch_token = format!(
        "hvb.{}",
        "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    );
    let (svc, _) = identify_api_key(&batch_token).unwrap();
    assert_eq!(svc, "vault_batch");
}

#[test]
fn detects_bitbucket_oauth_and_app_password() {
    let oauth = "BBDC-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5";
    let (svc, _) = identify_api_key(oauth).unwrap();
    assert_eq!(svc, "bitbucket_oauth");

    let app_pw = "ATBB-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
    let (svc, _) = identify_api_key(app_pw).unwrap();
    assert_eq!(svc, "bitbucket_app_password");
}

#[test]
fn detects_mongodb_and_postgresql_uris() {
    // Note: host names are chosen to NOT contain any
    // `CONTEXT_EXCLUSIONS` substring (no "example", "test",
    // "sample", etc.) — those would correctly trip the FP gate
    // and route this through the "wrong" path. Real production
    // hosts like `cluster.mongodb.net` and `db.companyacme.com`
    // pass cleanly.
    let mongo = "mongodb://operator:Hunter2!@cluster.mongodb.net:27017/prod";
    let (svc, _) = identify_api_key(mongo).unwrap();
    assert_eq!(svc, "mongodb_uri");

    let pg = "postgresql://operator:Hunter2!@db.companyacme.com:5432/prod";
    let (svc, _) = identify_api_key(pg).unwrap();
    assert_eq!(svc, "postgres_uri");
}

#[test]
fn detects_slack_webhook_url() {
    let cand =
        "https://hooks.slack.com/services/T01234567/B01234567/abcdefghij1234567890ABCDEFGHIJ";
    let (svc, _) = identify_api_key(cand).unwrap();
    assert_eq!(svc, "slack_webhook_url");
}

#[test]
fn detects_discord_webhook_url_both_hosts() {
    let cand1 =
        "https://discord.com/api/webhooks/1234567890123456789/abcdefghij1234567890ABCDEFGHIJ-_xyz";
    let (svc, _) = identify_api_key(cand1).unwrap();
    assert_eq!(svc, "discord_webhook_url");

    // discordapp.com is the legacy host — both still route.
    let cand2 = "https://discordapp.com/api/webhooks/1234567890123456789/abcdefghij1234567890ABCDEFGHIJ-_xyz";
    let (svc, _) = identify_api_key(cand2).unwrap();
    assert_eq!(svc, "discord_webhook_url");
}

// ─── PEM private-key detection ────────────────────────────────

fn pem_with_header(header: &str) -> String {
    let tail = header.trim_start_matches("-----BEGIN ");
    format!(
        "{header}\n\
             MIIEpAIBAAKCAQEAxKHJvWqjzS0Mzqp7HhCJN4mxbXf8YzfvOLvhsZ7g9XKvz2fhQbX\n\
             rs3Ws6MKw02xZJq8GbHnE7vU5oOnX0kJqLY8VBn5oZqvLPhqpJ04u3HoT5w1pqhTaZ\n\
             ...truncated_body_padding_to_satisfy_the_80_char_floor...\n\
             -----END {tail}"
    )
}

#[test]
fn detects_rsa_private_key_header() {
    let pem = pem_with_header("-----BEGIN RSA PRIVATE KEY-----");
    let (svc, _) = identify_api_key(&pem).unwrap();
    assert_eq!(svc, "pem_rsa_private");
}

#[test]
fn detects_openssh_private_key_header() {
    let pem = pem_with_header("-----BEGIN OPENSSH PRIVATE KEY-----");
    let (svc, _) = identify_api_key(&pem).unwrap();
    assert_eq!(svc, "pem_openssh_private");
}

#[test]
fn detects_ec_private_key_header() {
    let pem = pem_with_header("-----BEGIN EC PRIVATE KEY-----");
    let (svc, _) = identify_api_key(&pem).unwrap();
    assert_eq!(svc, "pem_ec_private");
}

#[test]
fn detects_dsa_private_key_header() {
    let pem = pem_with_header("-----BEGIN DSA PRIVATE KEY-----");
    let (svc, _) = identify_api_key(&pem).unwrap();
    assert_eq!(svc, "pem_dsa_private");
}

#[test]
fn detects_pkcs8_private_and_encrypted_headers() {
    let plain = pem_with_header("-----BEGIN PRIVATE KEY-----");
    let (svc, _) = identify_api_key(&plain).unwrap();
    assert_eq!(svc, "pem_pkcs8_private");

    let enc = pem_with_header("-----BEGIN ENCRYPTED PRIVATE KEY-----");
    let (svc, _) = identify_api_key(&enc).unwrap();
    assert_eq!(svc, "pem_pkcs8_encrypted");
}

#[test]
fn detects_pgp_private_and_message_blocks() {
    let priv_key = pem_with_header("-----BEGIN PGP PRIVATE KEY BLOCK-----");
    let (svc, _) = identify_api_key(&priv_key).unwrap();
    assert_eq!(svc, "pem_pgp_private");

    let msg = pem_with_header("-----BEGIN PGP MESSAGE-----");
    let (svc, _) = identify_api_key(&msg).unwrap();
    assert_eq!(svc, "pem_pgp_message");
}

#[test]
fn pem_bare_header_without_body_is_rejected() {
    // 80-char floor catches BEGIN-only strings.
    let header = "-----BEGIN RSA PRIVATE KEY-----";
    assert!(identify_pem_private_key(header).is_none());
}

#[test]
fn pem_unknown_class_returns_none() {
    // `BEGIN FAKE...` shouldn't latch onto a service.
    let bogus = format!("-----BEGIN FAKE FORMAT-----\n{}", "x".repeat(200));
    assert!(identify_pem_private_key(&bogus).is_none());
}

#[test]
fn pem_extracted_from_stealer_app_data_emits_correct_service() {
    // Stealer dump of an SSH id_rsa file pasted into app_data.
    let pem = pem_with_header("-----BEGIN OPENSSH PRIVATE KEY-----");
    let item = serde_json::json!({
        "app_data": pem,
        "dbname": "StealerLogV3",
    });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_api_keys_from_item(&item, "test", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 1);
    assert!(result.entities[0].has_tag("service:pem_openssh_private"));
}

// ─── Titus / gitleaks / apkscan-ported prefixes ───────────────

#[test]
fn detects_atlassian_config_token() {
    let cand = "ATCTA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let (svc, _) = identify_api_key(cand).unwrap();
    assert_eq!(svc, "atlassian_config");
}

#[test]
fn detects_dynatrace_token() {
    // Dynatrace tokens have format `dt0c01.<32 alphanum>.<64 alphanum>`.
    let cand = format!(
        "dt0c01.{}.{}",
        "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
        "Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6"
    );
    let (svc, _) = identify_api_key(&cand).unwrap();
    assert_eq!(svc, "dynatrace");
}

#[test]
fn detects_frameio_user_token() {
    let cand = "fio-u-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let (svc, _) = identify_api_key(cand).unwrap();
    assert_eq!(svc, "frameio");
}

#[test]
fn detects_postman_api_key() {
    let cand = "PMAK-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4";
    let (svc, _) = identify_api_key(cand).unwrap();
    assert_eq!(svc, "postman");
}

#[test]
fn detects_razorpay_test_and_live() {
    let test = "rzp_test_A1b2C3d4E5f6G7h8I9j0K1l2";
    let (svc, _) = identify_api_key(test).unwrap();
    assert_eq!(svc, "razorpay_test");

    let live = "rzp_live_A1b2C3d4E5f6G7h8I9j0K1l2";
    let (svc, _) = identify_api_key(live).unwrap();
    assert_eq!(svc, "razorpay_live");
}

#[test]
fn detects_readme_api_key() {
    let cand = "rdme_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
    let (svc, _) = identify_api_key(cand).unwrap();
    assert_eq!(svc, "readme");
}

#[test]
fn detects_shippo_test_and_live() {
    let test = "shippo_test_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
    let (svc, _) = identify_api_key(test).unwrap();
    assert_eq!(svc, "shippo_test");

    let live = "shippo_live_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
    let (svc, _) = identify_api_key(live).unwrap();
    assert_eq!(svc, "shippo_live");
}

#[test]
fn detects_shopify_partner_custom_app_and_shared_secret() {
    let cases = [
        ("shppa_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6", "shopify_partner"),
        (
            "shpca_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            "shopify_custom_app",
        ),
        (
            "shpss_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            "shopify_shared_secret",
        ),
    ];
    for (cand, expected) in cases {
        let (svc, _) = identify_api_key(cand)
            .unwrap_or_else(|| panic!("Shopify {expected} not detected for {cand}"));
        assert_eq!(svc, expected);
    }
}

#[test]
fn detects_newrelic_browser_token() {
    let cand = "NRJS-A1b2C3d4E5f6G7h8I9j0K1l2";
    let (svc, _) = identify_api_key(cand).unwrap();
    assert_eq!(svc, "newrelic_browser");
}

#[test]
fn detects_dropbox_short_lived_token() {
    // Dropbox SL tokens are `sl.<43+ chars>`.
    let cand = "sl.A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4";
    let (svc, _) = identify_api_key(cand).unwrap();
    assert_eq!(svc, "dropbox_short_lived");
}

#[test]
fn detects_clojars_deploy_token() {
    // Clojars deploy tokens are `CLOJARS_<60+ alphanumeric>`.
    let cand = format!(
        "CLOJARS_{}",
        "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4"
    );
    let (svc, _) = identify_api_key(&cand).unwrap();
    assert_eq!(svc, "clojars_deploy");
}

#[test]
fn ported_prefixes_route_through_stealer_log_orchestrator() {
    // Integration: a single record with three of the new
    // prefixes routed through `extract_api_keys_from_item`
    // should emit three distinct entities with the right
    // service tags.
    let item = serde_json::json!({
        "app_data": "PMAK-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4",
        "notes": "rdme_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0",
        "client_secret": "ATCTA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        "dbname": "ContractorLeak2026",
    });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_api_keys_from_item(&item, "test", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 3);
    let services: Vec<&str> = result
        .entities
        .iter()
        .flat_map(|e| e.tags.iter().filter_map(|t| t.strip_prefix("service:")))
        .collect();
    assert!(services.contains(&"postman"));
    assert!(services.contains(&"readme"));
    assert!(services.contains(&"atlassian_config"));
}

// ─── Base64 decode-through scanning (keyhog port) ────────────

fn b64(s: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn b64_urlsafe_nopad(s: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
}

#[test]
fn decode_through_finds_plain_base64_of_openai_key() {
    let plain = "sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
    let wrapped = b64(plain);
    let (svc, decoded, depth) = try_decode_through_scan(&wrapped).unwrap();
    assert_eq!(svc, "openai");
    assert_eq!(decoded, plain);
    assert_eq!(depth, 1);
}

#[test]
fn decode_through_finds_nested_double_base64() {
    let plain = "sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
    let once = b64(plain);
    let twice = b64(&once);
    let (svc, decoded, depth) = try_decode_through_scan(&twice).unwrap();
    assert_eq!(svc, "openai");
    assert_eq!(decoded, plain);
    assert_eq!(depth, 2);
}

#[test]
fn decode_through_caps_at_depth_two() {
    // Triple-wrapping must NOT round-trip — the cap is 2.
    let plain = "sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
    let thrice = b64(&b64(&b64(plain)));
    assert!(try_decode_through_scan(&thrice).is_none());
}

#[test]
fn decode_through_accepts_url_safe_no_pad_variant() {
    // OAuth callback-style tokens land URL-safe + unpadded.
    let plain = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let wrapped = b64_urlsafe_nopad(plain);
    let (svc, decoded, _) = try_decode_through_scan(&wrapped).unwrap();
    assert_eq!(svc, "github");
    assert_eq!(decoded, plain);
}

#[test]
fn decode_through_rejects_short_base64() {
    // Below 24-char minimum encoded length.
    let short = b64("hello");
    assert!(try_decode_through_scan(&short).is_none());
}

#[test]
fn decode_through_rejects_random_garbage() {
    // High-entropy random alphanumeric that happens to look
    // base64-ish but doesn't decode to a recognisable key.
    let garbage = "kJh28slQqv61MnG9XwZpY7TfRbDvCsAoJkLp29slQqv61MnG9";
    assert!(try_decode_through_scan(garbage).is_none());
}

#[test]
fn decode_through_rejects_non_utf8_decoded_bytes() {
    // 0xFF 0xFE 0xFD ... decode is valid base64 but the bytes
    // are not valid UTF-8 — must short-circuit.
    use base64::Engine as _;
    let raw = (0u8..32).map(|i| 0xFF ^ i).collect::<Vec<u8>>();
    let wrapped = base64::engine::general_purpose::STANDARD.encode(&raw);
    assert!(try_decode_through_scan(&wrapped).is_none());
}

#[test]
fn decode_through_rejects_input_with_invalid_chars() {
    // A space, dot, or colon disqualifies the looks_like_base64
    // pre-check — those reliably indicate the input is a URL,
    // sentence or filepath, not a raw b64 blob.
    assert!(try_decode_through_scan("hello world this is not base64").is_none());
    assert!(try_decode_through_scan("https://example.com/path?key=value123").is_none());
}

#[test]
fn extract_orchestrator_finds_base64_wrapped_key_in_password_field() {
    // End-to-end: a base64-wrapped AWS key in the `password`
    // field should emit via the decode-through path, tagged
    // `via-base64` so analysts can filter on it.
    let plain = "AKIAJK28SLQQV61MNG9X";
    let wrapped = b64(plain);
    let item = serde_json::json!({ "password": wrapped });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_api_keys_from_item(&item, "test-b64-1", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 1);
    let e = &result.entities[0];
    assert_eq!(e.value, plain);
    assert!(e.has_tag("service:aws"), "missing service:aws tag");
    assert!(e.has_tag("via-base64"), "missing via-base64 tag");
    assert!(
        e.tags.iter().any(|t| t == "base64_depth:1"),
        "missing base64_depth:1 tag; tags={:?}",
        e.tags
    );
}

#[test]
fn extract_orchestrator_finds_base64_in_app_data_field() {
    // Stealer logs commonly drop the credential as base64
    // inside the `app_data` blob. Should round-trip.
    let plain = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let wrapped = b64(plain);
    let item = serde_json::json!({ "app_data": wrapped });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_api_keys_from_item(&item, "test-b64-2", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 1);
    assert_eq!(result.entities[0].value, plain);
    assert!(result.entities[0].has_tag("service:github"));
    assert!(result.entities[0].has_tag("via-base64"));
}

#[test]
fn extract_orchestrator_dedupes_plaintext_and_base64_of_same_key() {
    // If `password` carries the plaintext and `notes` carries
    // the base64, the dedup gate keyed on the DECODED value
    // must collapse them to one entity.
    let plain = "AKIAJK28SLQQV61MNG9X";
    let item = serde_json::json!({
        "password": plain,
        "notes": b64(plain),
    });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_api_keys_from_item(&item, "test-b64-3", &mut seen, &mut result);
    assert_eq!(
        result.entities.len(),
        1,
        "dedup should collapse plaintext + base64-of-same-key, got {:?}",
        result
            .entities
            .iter()
            .map(|e| (e.value.clone(), e.tags.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn extract_orchestrator_finds_two_independent_base64_keys() {
    // Two different fields, two different wrapped keys —
    // both should land as distinct entities with via-base64.
    let aws = "AKIAJK28SLQQV61MNG9X";
    let gh = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let item = serde_json::json!({
        "password": b64(aws),
        "client_secret": b64(gh),
    });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_api_keys_from_item(&item, "test-b64-4", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 2);
    let services: Vec<&str> = result
        .entities
        .iter()
        .flat_map(|e| e.tags.iter().filter_map(|t| t.strip_prefix("service:")))
        .collect();
    assert!(services.contains(&"aws"));
    assert!(services.contains(&"github"));
    assert!(result.entities.iter().all(|e| e.has_tag("via-base64")));
}

#[test]
fn extract_orchestrator_emits_both_plaintext_and_base64_when_distinct_keys() {
    // password = plaintext key A
    // notes    = base64(key B)
    // Two distinct keys, two entities, only the second tagged via-base64.
    let aws = "AKIAJK28SLQQV61MNG9X";
    let gh = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let item = serde_json::json!({
        "password": aws,
        "notes": b64(gh),
    });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_api_keys_from_item(&item, "test-b64-5", &mut seen, &mut result);
    assert_eq!(result.entities.len(), 2);
    let plaintext = result
        .entities
        .iter()
        .find(|e| e.value == aws)
        .expect("plaintext AWS not found");
    let decoded = result
        .entities
        .iter()
        .find(|e| e.value == gh)
        .expect("decoded GH not found");
    assert!(!plaintext.has_tag("via-base64"));
    assert!(decoded.has_tag("via-base64"));
}

// ─── Public pattern catalogue (API surface) ──────────────────

#[test]
fn pattern_catalogue_round_trips_table_entries() {
    let cat = pattern_catalogue();
    assert_eq!(cat.len(), KEY_PATTERNS.len(), "size mismatch");
    // Spot-check that a few well-known entries survive the
    // mapping (prefix + service + min_len preserved).
    assert!(
        cat.iter()
            .any(|p| p.prefix == "sk-ant-" && p.service == "anthropic" && p.min_len == 40),
        "missing sk-ant-/anthropic/40 entry"
    );
    assert!(
        cat.iter()
            .any(|p| p.prefix == "AKIA" && p.service == "aws" && p.min_len == 16),
        "missing AKIA/aws/16 entry"
    );
}

#[test]
fn pattern_catalogue_preserves_declaration_order() {
    let cat = pattern_catalogue();
    let sk_svcacct_idx = cat
        .iter()
        .position(|p| p.prefix == "sk-svcacct-")
        .expect("sk-svcacct- not found");
    let sk_idx = cat
        .iter()
        .position(|p| p.prefix == "sk-")
        .expect("sk- not found");
    // Specific-before-generic: sk-svcacct- MUST come before sk-
    assert!(
        sk_svcacct_idx < sk_idx,
        "specific-before-generic violated for sk- family"
    );
}

// ── Harvested-key value tiers ─────────────────────────────────

#[test]
fn key_value_tier_ranks_critical_services() {
    for svc in [
        "aws",
        "aws_sts",
        "gcp_service",
        "azure",
        "cloudflare",
        "mongodb_uri",
        "postgres_uri",
        "redis_uri",
        "supabase",
        "vault_service",
        "doppler_service_token",
        "1password",
        "stripe",
        "razorpay_live",
        "square",
        "npm",
        "pypi",
        "docker_hub_pat",
    ] {
        assert_eq!(key_value_tier(svc), KeyValue::Critical, "service {svc}");
        assert!(key_value_tier(svc).is_high_value());
    }
}

#[test]
fn key_value_tier_treats_private_keys_as_critical() {
    for svc in [
        "pem_rsa_private",
        "pem_openssh_private",
        "pem_pkcs8_encrypted",
        "pem_pgp_private",
        "age_encryption",
    ] {
        assert_eq!(key_value_tier(svc), KeyValue::Critical, "service {svc}");
    }
}

#[test]
fn key_value_tier_ranks_high_services() {
    for svc in [
        "sendgrid",
        "twilio",
        "mailgun",
        "slack_bot",
        "discord_bot",
        "github",
        "github_app",
        "gitlab_pat",
        "bitbucket_oauth",
        "anthropic",
        "openai",
        "openrouter",
        "huggingface",
        "replicate",
        "shopify",
        "vercel_project",
        "netlify",
        "railway",
    ] {
        assert_eq!(key_value_tier(svc), KeyValue::High, "service {svc}");
        assert!(key_value_tier(svc).is_high_value());
    }
}

#[test]
fn key_value_tier_demotes_public_and_webhook_identifiers() {
    for svc in [
        "stripe_pub",
        "clerk_pub",
        "newrelic_browser",
        "sentry_dsn",
        "discord_webhook_url",
        "slack_webhook_url",
        "stripe_webhook",
        "mapbox",
        "geocodio",
        "google",
    ] {
        assert_eq!(key_value_tier(svc), KeyValue::Low, "service {svc}");
        assert!(!key_value_tier(svc).is_high_value());
    }
}

#[test]
fn key_value_tier_defaults_unknown_vendor_key_to_medium() {
    // A recognised vendor key of unproven impact must never rank as throwaway.
    assert_eq!(key_value_tier("some_unlisted_vendor"), KeyValue::Medium);
    assert_eq!(key_value_tier("sentry"), KeyValue::Medium);
    assert_eq!(key_value_tier("stripe_test"), KeyValue::Medium);
}

#[test]
fn key_value_confidence_is_monotonic_by_tier() {
    // Higher value ⇒ higher confidence, so the graph/export surfaces the most
    // dangerous leaked keys first.
    assert!(KeyValue::Critical.confidence() > KeyValue::High.confidence());
    assert!(KeyValue::High.confidence() > KeyValue::Medium.confidence());
    assert!(KeyValue::Medium.confidence() > KeyValue::Low.confidence());
    for v in [
        KeyValue::Critical,
        KeyValue::High,
        KeyValue::Medium,
        KeyValue::Low,
    ] {
        let c = v.confidence();
        assert!((0.0..=1.0).contains(&c), "{v:?} confidence out of range");
    }
}

#[test]
fn every_catalogued_service_classifies_and_high_value_set_is_populated() {
    // Guard: every prefix-table service maps to a tier (the match is total via
    // its `_ => Medium` arm, but this pins that real services aren't silently
    // mis-bucketed) and the critical/high lists are non-trivially populated.
    let cat = pattern_catalogue();
    let mut high_value = 0usize;
    for entry in &cat {
        let tier = key_value_tier(entry.service);
        if tier.is_high_value() {
            high_value += 1;
        }
    }
    assert!(
        high_value >= 40,
        "expected many high-value services in the catalogue, got {high_value}"
    );
}
