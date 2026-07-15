//! Key/credential emission + persistence: builds the Credential/ApiKey
//! entities and writes them through the store. Split from the harvester core;
//! parent items (DetectionConfidence, tags, …) via `use super::*`.

use super::*;

/// Emit a key whose provenance is the schema/shape baseline (the direct
/// [`identify_api_key`] paths, which carry no corroborating context). Delegates
/// to [`emit_key_with`] after deriving [`super::DetectionConfidence::for_service`].
pub(super) fn emit_key(
    ctx: &HarvestCtx,
    service: &'static str,
    key_val: &str,
    source: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let detection = DetectionConfidence::for_service(service);
    emit_key_with(ctx, service, key_val, source, detection, seen, result);
}

/// Emit a key with an explicit [`super::DetectionConfidence`] — used by the
/// context-attribution sites, which can assign [`DetectionConfidence::Proven`]
/// that the service tag alone cannot prove (Shodan/Censys also have prefix
/// entries). Stamps a `detection:` tag and `detection_confidence` evidence attr.
pub(super) fn emit_key_with(
    ctx: &HarvestCtx,
    service: &'static str,
    key_val: &str,
    source: &str,
    detection: DetectionConfidence,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let HarvestCtx { src, scan_id } = *ctx;
    // A cryptocurrency wallet address is NOT an API key — `identify_*` groups
    // it here only because both are high-entropy tokens. Emit it as a
    // first-class CryptoAddress (chain-tagged) and skip the API-key/ROI/key-pool
    // machinery entirely: it can't authenticate anything.
    if let Some(chain) = service.strip_prefix("crypto_") {
        if seen.insert(format!("@crypto:{key_val}")) {
            let mut e = Entity::new(EntityKind::CryptoAddress, key_val, 0.80, scan_id);
            e.tag("crypto-address");
            e.tag(format!("chain:{chain}"));
            e.add_evidence(
                Evidence::new(src, format!("{chain} wallet address from {source}"))
                    .with_attr("chain", chain),
            );
            result.push(e);
        }
        return;
    }
    let dedup = format!(
        "@apikey:{service}:{}",
        crate::util::str_util::truncate_safe(key_val, 16)
    );
    if !seen.insert(dedup) {
        return;
    }
    // Practical, offline JWT validation — synergy with the provenance tier. For a
    // `jwt_token`, decode the header and confirm it really is a JWT. A confirmed
    // structure keeps the schema-level baseline; an `eyJ`-shaped blob that does
    // NOT decode to a JWT header is just high-entropy text → drop to Potential.
    let jwt_alg = (service == "jwt_token")
        .then(|| validate_jwt_alg(key_val))
        .flatten();
    let detection = if service == "jwt_token" && jwt_alg.is_none() {
        DetectionConfidence::Potential
    } else {
        detection
    };
    let mut entity = Entity::new(EntityKind::ApiKey, key_val, 0.80, scan_id);
    entity.tag("api-key");
    entity.tag(format!("service:{service}"));
    // Hyphenated form, matching the caller's own entity-tagging convention
    // elsewhere (e.g. `oathnet_pro::stealer`/`breach`'s `.tag("oathnet-pro")`,
    // `see_know`'s `.tag("see-know")` — see `modules::breach_rich`'s identical
    // "caller supplies its own source tag" pattern).
    entity.tag(src.replace('_', "-"));
    entity.tag("auto-discovered");
    // Detection provenance (orthogonal to ROI/value): proven > probable > potential.
    entity.tag(format!("detection:{}", detection.as_str()));
    if let Some(alg) = &jwt_alg {
        entity.tag("jwt:structure-valid");
        entity.tag(format!("jwt:alg:{}", alg.to_ascii_lowercase()));
        // `alg: none` is an unsigned token — anyone can forge its claims (the
        // classic JWT authentication-bypass). Surface it as a vulnerability.
        if alg.eq_ignore_ascii_case("none") {
            entity.tag("jwt:alg-none");
            entity.tag(crate::core::tags::VULNERABLE);
        }
    }
    // Tag with ROI tier so operators can prioritise multiplier keys.
    // Multiplier-tier keys discover infrastructure/identities that
    // cascade into MORE keys via web_crawler and search_engines.
    let roi = crate::util::key_roi::classify(service);
    entity.tag(format!("roi:{}", roi.label()));
    if roi == crate::util::key_roi::KeyRoi::Multiplier {
        entity.tag("force-multiplier");
    }
    // Exposure CRITICALITY (orthogonal to ROI and detection): how grave the leak
    // is if abused — an AWS root secret or a live Stripe key dwarfs a low-impact
    // analytics token. The classifier already computes this tier (it drives the
    // entity confidence); stamping it as an explicit tag makes the retained-key
    // intelligence sortable in the web UI and lets the correlator rank the
    // exposure portfolio (AU-095) — a revoke-this-first order rather than a flat
    // list. No new classification: same `key_value_tier` single source of truth.
    let value_tier = key_value_tier(service);
    entity.tag(format!("key-criticality:{}", value_tier.as_str()));
    if value_tier.is_high_value() {
        entity.tag("high-value");
    }
    // OSINT-practitioner attribution: a key for a recon/breach/threat-intel
    // provider (Shodan, Dehashed, IntelX, Maltego, Hunter …) found on a victim
    // identifies its owner as an OSINT operator — the provider category IS the
    // pivot (their tradecraft, tooling, intent). Tag it so the correlator can
    // flag practitioners and the operator can compare against their own keys.
    // Classification only — the key is never used to authenticate.
    let osint_category = crate::util::osint_providers::osint_category(service);
    if let Some(category) = osint_category {
        entity.tag("osint-practitioner");
        entity.tag(format!("osint-category:{}", category.slug()));
    }
    entity.add_evidence(
        Evidence::new(src, format!("API key ({service}) from {source}"))
            .with_attr("service", service)
            .with_attr("detection_confidence", detection.as_str())
            .with_attr("roi_tier", roi.label())
            .with_attr("key_criticality", value_tier.as_str())
            .with_attr(
                "osint_category",
                osint_category.map_or("none", |c| c.slug()),
            )
            .with_attr(
                "key_prefix",
                crate::util::str_util::truncate_safe(key_val, 8),
            )
            .with_attr("key_length", key_val.len().to_string()),
    );
    result.push(entity);

    // Skip the global key-pool side-effect when called from unit
    // tests. The pool is persisted to `~/.huntsman/key_pool.json`,
    // so unconditionally writing in tests pollutes state across
    // test binaries (`cargo test` runs each crate in its own
    // process, but the on-disk pool is shared). Conservatively
    // gate on a scan_id `"test"` / `"scan"` prefix — both used by
    // the test orchestrators in this module and the smoke crate.
    if scan_id == "test" || scan_id.starts_with("test-") || scan_id == "scan" {
        return;
    }

    // Pool ONLY a recognised keyed provider's key — one the cascade can reuse.
    // The `generic_hex` catch-all (and `jwt_token`, `crypto_*`, foreign logins)
    // is surfaced as the ApiKey entity above but is never injected by
    // `hot_inject_keys`, so pooling it just grew key_pool.json without bound
    // (a live run accumulated 8668 `generic_hex` blobs → a 4 MB pool).
    if !crate::util::service_defs::is_poolable_service(service) {
        return;
    }

    let pool = crate::util::key_pool::global_pool();
    let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
    entry.notes = Some(format!(
        "Auto-discovered {service} key from {source} ({} tier)",
        roi.label()
    ));
    pool.add(service, entry);
    crate::util::key_pool::save_pool_best_effort(&pool);
}

/// Routes a stealer/breach record to the key pool when the URL matches
/// a known service domain. See [`emit_key`] for `src`.
pub fn store_api_credential(item: &Value, src: &str) {
    let url = val_str(item, "url")
        .or_else(|| val_str(item, "url_str"))
        .or_else(|| val_str(item, "domain"))
        .unwrap_or_default();
    let username = val_str(item, "username")
        .or_else(|| val_str(item, "email"))
        .or_else(|| val_str(item, "login"))
        .unwrap_or_default();
    let password = val_str(item, "password")
        .or_else(|| val_str(item, "pass"))
        .or_else(|| val_str(item, "pwd"))
        .or_else(|| val_str(item, "passwd"))
        .or_else(|| val_str(item, "credential"))
        .or_else(|| val_str(item, "api_key"))
        .or_else(|| val_str(item, "token"))
        .or_else(|| val_str(item, "secret"))
        .unwrap_or_default();

    if password.is_empty() || password.contains("***") || password.contains("UPGRADE") {
        return;
    }

    let service = if !url.is_empty() {
        let svc = identify_service_from_url(&url);
        if svc != "unknown" {
            svc
        } else {
            return;
        }
    } else if !username.is_empty() && username.contains('@') {
        let domain = username.split('@').nth(1).unwrap_or("");
        let svc = identify_service_from_url(domain);
        if svc != "unknown" {
            svc
        } else {
            return;
        }
    } else {
        return;
    };

    let pool = crate::util::key_pool::global_pool();

    let mut entry = crate::util::key_pool::KeyEntry::new(&password);
    entry.notes = Some(format!(
        "{src} stealer: user={} url={}",
        crate::util::str_util::truncate_safe(&username, 30),
        crate::util::str_util::truncate_safe(&url, 60)
    ));
    if pool.add(service, entry) {
        crate::util::key_pool::save_pool_best_effort(&pool);
    }

    let user_entry = crate::util::key_pool::KeyEntry::new(format!("{username}:{password}"));
    pool.add(&format!("{service}_login"), user_entry);
    crate::util::key_pool::save_pool_best_effort(&pool);
}
