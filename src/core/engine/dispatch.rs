//! Per-target dispatch gating: decide whether a module runs against a given
//! target this round, and how much cross-correlation a target has accumulated.
//! Pure free functions consulted by the sequential and concurrent dispatch loops
//! (which remain in the engine impl); split out so the gate policy reads in one
//! place. The dispatch loops themselves and the panic-guarded module runner stay
//! in `engine` until a later increment moves them here too.

use std::collections::HashMap;

use crate::core::entity::{Entity, normalise};
use crate::core::module::{Module, ModuleCost};
use crate::core::scan::{ScanOptions, Target, TargetKind};

/// Distinct corroborating evidence-source count for the entity a `target`
/// resolves to (0 if it isn't in the working set yet). Drives the high-value-API
/// gate: a discovered entity must reach real cross-correlation, not just a bumped
/// corroboration counter, before the heaviest paid modules fire on it.
pub(super) fn target_distinct_sources(
    entity_map: &HashMap<String, Entity>,
    target: &Target,
) -> usize {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    let uid = crate::core::entity::derive_uid(&entity_kind, &normalised);
    entity_map
        .get(&uid)
        .map_or(0, |e| e.evidence_sources().len())
}

pub(super) fn module_skip_reason(
    module: &dyn Module,
    target: &Target,
    opts: &ScanOptions,
    is_expansion: bool,
    target_distinct_sources: usize,
) -> Option<&'static str> {
    let name = module.name();
    // The allowlist means "ONLY these modules run" (docs/USAGE.md) — and that
    // must hold on EVERY round, not just the seed. Gating it with `!is_expansion`
    // let every non-allowlisted module run on discovered entities during
    // expansion, contradicting the documented contract and (on the Termux target)
    // turning a focused `--modules name_intel` scan into a full network sweep the
    // moment it expanded. `--exclude` already applies in all rounds; the allowlist
    // now matches.
    if let Some(allow) = &opts.modules
        && !allow.iter().any(|n| n == name)
    {
        return Some("not in allowlist");
    }
    if opts.exclude_modules.iter().any(|n| n == name) {
        return Some("excluded");
    }
    // Persistent per-module toggle (universal toggleability): `hse config
    // module.<name> off` disables a module across ALL scans until re-enabled.
    // Default on, so an unset module behaves exactly as before.
    if !crate::util::settings::get_bool(&format!("module.{name}"), true) {
        return Some("disabled in config");
    }
    if opts.free_only && !matches!(module.cost(), ModuleCost::Free) {
        return Some("requires key/payment");
    }
    if opts.passive_only && !module.is_passive() {
        return Some("not passive");
    }
    if is_expansion && module.is_passive() && super::LOCAL_PASSIVE_MODULES.contains(&name) {
        return Some("sensor (already ran on seed round)");
    }
    // High-value-only modules: the heaviest paid API (oathnet_pro, priority
    // 127, Paid, 30s) burns one query per target and a low-specificity seed
    // fans out into a large unrelated corpus — a live `name="Onur Ada"` scan
    // pulled 172 unrelated US-banking breach records that buried the real
    // findings. Per the operator's rule, such a module may fire when the
    // target is EITHER the initial seed query OR a discovered entity that has
    // reached *sufficient cross-correlation* — i.e. corroborated by at least
    // `CROSS_CORRELATION_MIN_SOURCES` DISTINCT evidence sources, not just a
    // bumped corroboration counter. On the live scan this admits the genuinely
    // on-target pivots (the breach email at 4 sources, the person at 3, the
    // employer domain at 2) while excluding the 97 single-source banking
    // emails that would otherwise trigger fresh fan-out. SeekNow (`see_know`)
    // is intentionally NOT gated here: its own per-scan budget in
    // `util::see_know` bounds the quota while letting it pivot freely.
    const HIGH_VALUE_ONLY_MODULES: &[&str] = &["oathnet_pro"];
    const CROSS_CORRELATION_MIN_SOURCES: usize = 2;
    if is_expansion
        && HIGH_VALUE_ONLY_MODULES.contains(&name)
        && target_distinct_sources < CROSS_CORRELATION_MIN_SOURCES
    {
        return Some("high-value API — awaiting cross-correlation (>=2 sources)");
    }
    // ── Universal preflight: reject private IPs / local domains for
    // modules that talk to external APIs. Sensor modules opt out via
    // LOCAL_PASSIVE_MODULES — they legitimately scan the local
    // network. Every other module is treated as "may reach an external
    // service" so we save its quota / suppress its "HTTP 400 invalid
    // IP" responses before the dispatch even fires.
    //
    // Modules with non-IP/Domain accepts (Email, Phone, Username, etc.)
    // fall through the `_` arm and run normally — there's no concept
    // of a "private email".
    if !super::LOCAL_PASSIVE_MODULES.contains(&name) {
        use crate::util::preflight;
        match target.kind {
            // Use the v6-tolerant gate — public IPv6 must pass through
            // (shodan, censys, RDAP, abuseipdb, etc. all support v6).
            // `should_skip_external_ipv4` rejects ANY `:`-containing
            // string and is reserved for the small set of IPv4-only
            // modules (ipapi, ip-api.com, ipinfo.io, ipquery.io)
            // that route through it inside their own `process`.
            TargetKind::IpAddress if preflight::should_skip_external_ip(&target.value) => {
                return Some("private/reserved IP — external API would reject");
            }
            TargetKind::Domain if preflight::is_local_domain(&target.value) => {
                return Some("local/reserved domain — external API would reject");
            }
            // SSRF gate: a URL whose host is a private IP or local
            // domain must not reach a URL-accepting external module
            // (dns_intel, doh_resolver, exif_geo, geo_domain_classifier,
            // web_crawler). Without this, an autonomously-discovered
            // `http://192.168.1.1/admin` would coerce HSE into
            // hitting the operator's internal network.
            TargetKind::Url if crate::util::preflight::url_host_is_private(&target.value) => {
                return Some("URL with private host — external API would reject (SSRF gate)");
            }
            _ => {}
        }
    }
    None
}
