//! Per-target module dispatch: the sequential and concurrent loops that run a
//! target's accepting modules, the gate that decides whether each module runs,
//! the panic/timeout-guarded module runner, and the per-result finalize step.
//! Split out of `engine` so the round loop (in `mod.rs`) reads as orchestration —
//! it just calls `self.dispatch_target(..)` — while all the per-module dispatch
//! mechanics live here. The `impl super::ScanEngine` block carries the methods;
//! sibling engine methods (`emit`, `emit_skipped`) and free helpers are reached
//! via `self`/`super::`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{sleep, timeout};
use tracing::{Instrument, debug, warn};

use super::{DispatchLog, ModuleStats};
use crate::core::entity::{Entity, normalise};
use crate::core::error::{Error, Result};
use crate::core::event::EventKind;
use crate::core::module::{Module, ModuleContext, ModuleCost, ModuleResult};
use crate::core::scan::{ScanOptions, Target, TargetKind};

/// Maximum entities a single module can contribute per scan. Prevents a
/// misbehaving or exploitable module from exhausting memory and crashing
/// the hse serve process on resource-constrained Termux (typically ~2GB RAM).
/// Modules that legitimately exceed this would need a redesign; ordinary
/// modules (searches, API probes, lookups) return far fewer results.
const MAX_ENTITIES_PER_MODULE: usize = 50_000;

/// Dispatch-dedup key: a module is invoked at most once per `(module, normalised
/// target)` across the whole scan. The value is normalised the same way
/// `Entity::new` does, so the same target reached two ways dedups to one run.
pub(super) fn dispatch_key(
    module_name: &'static str,
    target: &Target,
) -> (&'static str, TargetKind, String) {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    (module_name, target.kind, normalised)
}

/// True if `entity` is *incidental infrastructure* noise on a scan with this
/// `seed_kind` — a shared CDN edge IP, a provider / registrar / DNS / mega
/// domain, or a role / provider mailbox (`abuse@`, `dns@`) that surfaces while
/// hunting an identity but never belongs to the subject, so the engine drops it
/// at admission (it never reaches the graph, correlator, or view). Exempt when
/// the seed itself IS infrastructure (`Domain` / `IpAddress` / `Cidr` / `Asn` /
/// `Url`): there the provider estate is the subject, so nothing is incidental.
///
/// Note the asymmetry between `Domain` and `Email`. A bare `Domain` node is gated
/// on [`is_noncentral_domain`](crate::core::scan::is_noncentral_domain) (mega +
/// infra) — `facebook.com` / `gmail.com` as a standalone node is noise on a
/// person scan. An `Email` is gated only on shared mail *infrastructure*
/// ([`is_infra_domain`](crate::core::scan::is_infra_domain), plus the role-local
/// check), because a subject's personal freemail address (`…@gmail.com`) is a
/// prime finding, never noise.
///
/// Kept pure (no engine state) so the seed-aware decision is unit-testable in
/// isolation — mirroring [`is_wrong_identity_pivot`](crate::core::scan::is_wrong_identity_pivot).
pub(super) fn is_incidental_infra_entity(seed_kind: TargetKind, entity: &Entity) -> bool {
    use crate::core::entity::EntityKind;
    if matches!(
        seed_kind,
        TargetKind::Domain
            | TargetKind::IpAddress
            | TargetKind::Cidr
            | TargetKind::Asn
            | TargetKind::Url
    ) {
        return false;
    }
    match &entity.kind {
        EntityKind::IpAddress => crate::core::validation::is_cdn_edge_ip(&entity.value),
        EntityKind::Domain => crate::core::scan::is_noncentral_domain(&entity.value),
        EntityKind::Email => {
            crate::core::validation::is_role_mailbox(&entity.value)
                || entity
                    .value
                    .rsplit('@')
                    .next()
                    .is_some_and(crate::core::scan::is_infra_domain)
        }
        _ => false,
    }
}

/// The engine's entity-admission policy as a PURE decision: given the scan's
/// `seed_kind`, the effective `min_confidence` floor, and a freshly-emitted
/// `entity`, return the `entity_excluded` reason string if the entity should be
/// refused, or `None` if it is admitted. No `self`, no events, no mutation — so
/// the whole drop-filter policy is unit-testable in isolation;
/// `finalise_module_result` wraps it with the `emit_excluded` side effect and the
/// `continue`.
///
/// The order is load-bearing (cheapest / most-decisive gates first) and three of
/// the eight filters carry kind-specific preconditions (`IpAddress`, `Phone`, the
/// four human-text kinds), so this is a straight-line sequence of guards rather
/// than a predicate table — the exact ordering stays legible and no closures are
/// needed.
pub(super) fn admission_rejection(
    seed_kind: TargetKind,
    min_confidence: Option<f64>,
    entity: &Entity,
) -> Option<&'static str> {
    use crate::core::entity::EntityKind;
    use crate::core::validation;

    if let Some(min) = min_confidence
        && entity.confidence < min
    {
        // Visible like every other admission drop ("never a black box") — this
        // was the one silent rejection.
        return Some("below_min_confidence");
    }
    // Drop guaranteed-bogus IPs (documentation / reserved / benchmark ranges,
    // e.g. 192.0.2.1 scraped off a tutorial page) at admission so they never
    // enter the graph, fire correlations, or appear as findings. RFC1918 private
    // and loopback are intentionally kept — local sensors surface those
    // legitimately on-device.
    if entity.kind == EntityKind::IpAddress && validation::is_bogus_ip(&entity.value) {
        return Some("bogus_ip");
    }
    // Drop documentation / placeholder artifacts (example.com,
    // jordan@example.com, http://example.com, the `example` username, "John
    // Doe", …) at admission so they never enter the graph, expand into whole
    // infrastructure rounds, or fire correlations. Inherently-unique secrets
    // (passwords / API keys / credentials) are exempt — see
    // `validation::is_placeholder_entity`.
    if validation::is_placeholder_entity(&entity.kind, &entity.value) {
        return Some("placeholder_artifact");
    }
    // Drop truncated / incomplete values (`@gmail`, a domain-less email, a bare
    // dotless host, a `@`-prefixed handle that failed to normalise) at admission
    // so the user never sees an unverifiable fragment. The auditor independently
    // flags any that somehow slip through (`fragment-values`).
    if validation::is_fragment_value(&entity.kind, &entity.value) {
        return Some("fragment_value");
    }
    // Drop an implausible phone at admission. A value that CLAIMS E.164 (leading
    // `+`) but fails the country-code/length rules — e.g. "+1240893", a NANP
    // number with only 6 national digits — is a scrape artifact, never a dialable
    // number. Gated here so it holds for every module and every expansion round;
    // national/ambiguous (no `+`) phones are left alone, since the modules already
    // emit E.164.
    if entity.kind == EntityKind::Phone
        && entity.value.starts_with('+')
        && !validation::validate_phone_e164(&entity.value).valid
    {
        return Some("implausible_phone");
    }
    // Incidental-infrastructure / role-mailbox noise gate: a CDN-edge IP, shared
    // provider / registrar / DNS / mega domain, or role/provider mailbox
    // surfacing on an identity-seeded scan maps a provider's estate, not the
    // subject. Dropped at admission (never enters the graph, correlator, or view),
    // like the other admission filters. The seed-aware decision lives in
    // `is_incidental_infra_entity` (infrastructure-seeded scans are exempt — there
    // the infrastructure IS the subject).
    if is_incidental_infra_entity(seed_kind, entity) {
        return Some("incidental_infra");
    }
    // Spam / homoglyph content gate. A breach co-occurrence dump mints junk: scam
    // Address text and "names" built from Cyrillic/Greek glyphs that spoof ASCII
    // (`Bеcоme а bitcоin milliоnairе`), or random consonant strings
    // (`ZonJZRJHHWD`). Drop a cross-script homograph for any human-text kind, and
    // a gibberish random string for Person, at admission — neither is ever the
    // subject. Both gates are conservative (a real accented name never trips them
    // — see the validators).
    if matches!(
        entity.kind,
        EntityKind::Person | EntityKind::Address | EntityKind::Username | EntityKind::Organisation
    ) && validation::is_confusable_mixed_script(&entity.value)
    {
        return Some("confusable_homoglyph");
    }
    if entity.kind == EntityKind::Person && validation::looks_like_gibberish_name(&entity.value) {
        return Some("gibberish_value");
    }
    None
}

/// Emit the uniform per-module dispatch trace, paired with the `ModuleStart` bus
/// event at every dispatch site (sequential + both concurrent phases). Without it
/// the raw debug log showed a module's outcome (done/skipped/errored/timeout) but
/// never its *start*, so a module that hung or vanished mid-flight left no trace.
/// Keyed by `module=<name>` (+ the target) so `grep module=hibp` reconstructs that
/// one module's entire lifecycle from the logs alone.
#[inline]
pub(super) fn log_module_dispatch(name: &str, target: &Target) {
    debug!(
        module = name,
        kind = ?target.kind,
        value = %target.value,
        "dispatch"
    );
}

/// Run one module's `process()` under both a timeout AND a panic guard.
///
/// A panicking module (an `unwrap`/slice on a hostile/drifted upstream response,
/// or a panic deep in a dependency) would otherwise unwind into the sequential
/// loop or a `JoinSet` task and, under `panic = "abort"`, take down a long-lived
/// `hse serve`. Wrapping the timed future in `catch_unwind` maps a caught panic to
/// `Ok(Err(Error::module(name, "panicked: …")))`, so it flows through
/// `finalise_module_result`'s `errored` arm exactly like a returned error —
/// counted, named, and non-fatal to the scan.
pub(super) async fn run_module_guarded(
    timeout_ms: u64,
    name: &'static str,
    fut: impl std::future::Future<Output = Result<ModuleResult>>,
) -> TimeoutResult {
    use futures::FutureExt;
    match std::panic::AssertUnwindSafe(timeout(Duration::from_millis(timeout_ms), fut))
        .catch_unwind()
        .await
    {
        Ok(timeout_result) => timeout_result,
        Err(payload) => {
            let msg = panic_payload_to_string(&payload);
            warn!(module = name, %msg, "module panic contained");
            Ok(Err(Error::module(name, format!("panicked: {msg}"))))
        }
    }
}

/// Best-effort human-readable message from a caught panic payload — the
/// `&str`/`String` cases `panic!`/`.unwrap()`/`.expect()` produce, or a
/// generic fallback for anything else (a custom payload type via
/// `panic_any`). Shared by every `catch_unwind` site in the engine so the
/// extraction logic can't drift between them.
pub(super) fn panic_payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panicked with a non-string payload".to_string())
}

/// What a spawned per-module task returns to the consumer loop.
pub(super) struct DispatchOutcome {
    pub(super) name: &'static str,
    pub(super) result: TimeoutResult,
    /// Mirrors `module.cache_ttl_secs()` captured before spawning. Zero
    /// means no caching; the join loop skips the archive write.
    pub(super) ttl_secs: u64,
    /// Pre-computed `archive_key(name, target)` captured before spawning
    /// (the module and target are no longer available at join time). Empty
    /// when `ttl_secs == 0`.
    pub(super) cache_key: String,
    /// The producing module's ATT&CK Reconnaissance technique IDs
    /// (`module.attack_techniques()`), captured before spawning because the
    /// `Module` object is gone by join time. `finalise_module_result` stamps
    /// each admitted entity with an `attack:<ID>` tag per technique.
    pub(super) attack_techniques: &'static [&'static str],
}

/// Stable archive key for the inter-scan entity cache: `module:kind:value`
/// where `value` is normalised identically to the dispatch dedup key so a
/// repeat scan of the same target always hits the same entry.
#[inline]
fn archive_key(name: &str, target: &Target) -> String {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    format!("{}:{}:{}", name, target.kind.canonical_str(), normalised)
}

/// Distinct *corroborating* evidence-source count for the entity a `target`
/// resolves to (0 if it isn't in the working set yet). Drives the high-value-API
/// gate: a discovered entity must reach real cross-correlation, not just a bumped
/// corroboration counter, before the heaviest paid modules fire on it.
///
/// Uses [`Entity::corroborating_sources`], NOT `evidence_sources`: the
/// deterministic `geo_normalize` enrichment pass writes a source to every
/// `Coordinates`/`Address` entity, so counting raw evidence sources would credit
/// a one-real-source coordinate as two — letting the WiGLE finaliser gate fire on
/// an uncorroborated coordinate (the very thing it exists to prevent). For the
/// oathnet gate's Email/Person/Domain targets this is a no-op (they never carry
/// an enrichment source), so the count is unchanged there.
pub(super) fn target_distinct_sources(
    entity_map: &HashMap<String, Entity>,
    target: &Target,
) -> usize {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    let uid = crate::core::entity::derive_uid(&entity_kind, &normalised);
    entity_map
        .get(&uid)
        .map_or(0, |e| e.corroborating_sources().len())
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
    // Live device-sensor modules read the OPERATOR's own real-time RF/network
    // environment (GPS fix, visible Wi-Fi APs, serving cell towers, LAN ARP) — so
    // attributing them to a scanned subject is contamination, and pure noise on a
    // remote target. They are an ENTIRELY SEPARATE activation: they run ONLY when
    // `hse radar` opts in via `allow_live_sensors`, never on an ordinary
    // `hse scan` / API / `hse live` run, on any round (seed or expansion).
    if super::LOCAL_PASSIVE_MODULES.contains(&name) && !opts.allow_live_sensors {
        return Some("live sensor — radar-only activation");
    }
    // Category focus: when a profile restricts the scan to a set of functional
    // categories (e.g. `skiptrace` → person-locating: People/Phone/Geo/Email/
    // Social/Corporate/Search), a module outside that set is skipped on every
    // round. Empty focus = no restriction. Gated by the type-owned
    // `module.category()`, so the focus follows module renames and automatically
    // picks up new in-category modules.
    if !opts.category_focus.is_empty() && !opts.category_focus.contains(&module.category()) {
        return Some("outside category focus");
    }
    // Circuit breaker: a module that already hit a rate-limit/quota wall or
    // failed repeatedly this run is skipped until its cooldown elapses. Retrying
    // a 429'd or quota-exhausted provider on the next target is guaranteed waste
    // (and extends the ban); skipping it hands that dispatch slot to a source
    // that still works — the budget the alias scan needs to find more. Checked
    // here (not as a hard exclusion) so it auto-recovers when the window passes.
    if super::circuit::is_open(name) {
        return Some("circuit-open — rate-limited/quota/repeated failure (cooling down)");
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
    // WiGLE is the paid GEOINT *finaliser*: it spends a query to confirm and
    // enrich a coordinate with real WiFi-density observations. On a discovered
    // `Coordinates` target it must fire only AFTER the free GEOINT layer
    // (ip_geo / geocode / overpass / mylnikov / breach lat-lon) has produced
    // and recursion has CORROBORATED that coordinate — i.e. ≥
    // `CROSS_CORRELATION_MIN_SOURCES` distinct sources agree on it (high
    // confidence) — so the daily WiGLE allowance is spent confirming the
    // subject's real location, not chasing every single-source coordinate a
    // scan throws off. A `MacAddress`/BSSID target is exempt: WiGLE is the
    // PRIMARY resolver there (nothing else geolocates a BSSID), so the
    // cross-correlation precondition can never be met and gating it would
    // disable the pivot entirely; its own BSSID sub-budget bounds it instead.
    // The seed round is exempt (a `Coordinates` seed is the operator's explicit
    // target), exactly as the oathnet gate admits the seed.
    if is_expansion
        && name == "wigle"
        && target.kind == TargetKind::Coordinates
        && target_distinct_sources < CROSS_CORRELATION_MIN_SOURCES
    {
        return Some("WiGLE finaliser — awaiting GEOINT corroboration (>=2 geo sources)");
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
            // modules (ip-api.com, ipinfo.io, ipquery.io)
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

/// The output of one `module.process()` call after the engine wraps it
/// in `tokio::time::timeout` — either `Elapsed` (outer timeout fired),
/// `Err` (module returned an error), or `Ok(ModuleResult)` (success).
pub(super) type TimeoutResult =
    std::result::Result<Result<crate::core::module::ModuleResult>, tokio::time::error::Elapsed>;

/// Immutable per-dispatch context: the scan identity, the target being
/// dispatched, the governing options, and whether this is an expansion round
/// (vs. the seed). These four always travel together through
/// [`ScanEngine::dispatch_target`](super::ScanEngine::dispatch_target) and its
/// sequential/concurrent inner loops, the gate, and the finaliser — so bundling
/// them into one shared borrow keeps those signatures honest (and removes the
/// `clippy::too_many_arguments` cause rather than muting the symptom). Borrowed,
/// never owned: it carries no state, only references the caller already holds.
pub(super) struct DispatchCx<'a> {
    pub(super) scan_id: &'a str,
    pub(super) target: &'a Target,
    pub(super) opts: &'a ScanOptions,
    pub(super) is_expansion: bool,
    /// The kind of the scan's ORIGINAL seed (not the current dispatch target).
    /// Drives the incidental-infrastructure admission gate: a CDN/registrar/DNS
    /// artifact is the legitimate subject only when the scan itself targets
    /// infrastructure (Domain/IP/CIDR/ASN/URL), and is noise on an identity scan.
    pub(super) seed_kind: TargetKind,
    /// Modules quarantined for THIS scan by capability-aware dispatch — those
    /// whose parser has provably gone dead (persistent drift; see
    /// [`crate::util::scraper_health::quarantined_modules`]). Empty unless the
    /// scan enabled `skip_dead_modules` on the automatic comprehensive fan-out,
    /// so an explicit allowlist / `--full` run carries an empty set and skips
    /// nothing. Computed once per scan and borrowed by every round.
    pub(super) quarantined: &'a std::collections::HashSet<String>,
}

/// Mutable per-scan dispatch accumulators threaded through every module run: the
/// working entity set (merged by uid), the run/skip/error/dedup tallies, the
/// paid-dedup ledger (each `module × normalised-target` fired at most once), and
/// the UIDs of entities genuinely NEW this dispatch (never merged into an
/// existing one) — lets a caller attribute lineage (`DerivedFrom`) without
/// re-diffing the whole `entity_map` before and after. One `&mut` borrow
/// replaces four always-together out-parameters; the fields are borrowed
/// separately at their use sites so the entity merge, the stat bump, the
/// ledger insert, and the new-uid record never contend.
pub(super) struct DispatchState<'a> {
    pub(super) entity_map: &'a mut super::TrackedEntityMap,
    pub(super) stats: &'a mut ModuleStats,
    pub(super) dispatched: &'a mut DispatchLog,
    pub(super) newly_inserted: &'a mut Vec<String>,
}

impl super::ScanEngine {
    /// Translate one module's `process()` result into engine events
    /// (`ModuleError` / `EntityFound` / `ModuleDone`) and merge any
    /// emitted entities into the per-scan `entity_map`. Shared by
    /// `dispatch_target_sequential` and `dispatch_target_concurrent`
    /// so the event payload shape is identical between the two paths.
    ///
    /// `attack_techniques` is the producing module's
    /// [`Module::attack_techniques`] —
    /// every admitted entity is stamped with an `attack:<ID>` tag per technique,
    /// so the ATT&CK Reconnaissance technique that collected each datum travels
    /// with the finding. Sourced from the dispatched `Module` object at the call
    /// site (never `crate::modules`, which `core` may not name), so the engine
    /// stays module-agnostic.
    pub(super) fn finalise_module_result(
        &self,
        cx: &DispatchCx,
        name: &'static str,
        result: TimeoutResult,
        state: &mut DispatchState,
        attack_techniques: &'static [&'static str],
        from_cache: bool,
    ) {
        // A cache replay is tallied in `stats.cached` by `replay_cached_result`; it
        // is NOT a module run (no provider call was made), and `ModuleStats.run` is
        // documented "Not counted in run" for cached results. Gating here keeps the
        // reported `modules_run` honest instead of double-counting every replay.
        if !from_cache {
            state.stats.run += 1;
        }
        match result {
            Err(_) => {
                state.stats.timed_out += 1;
                // A timeout carries no message to classify, so it's a soft
                // failure: trips only after a streak (one slow round is transient).
                super::circuit::record_soft_failure(name);
                super::health::record_failure(name);
                warn!(module = name, "timeout");
                self.emit(
                    cx.scan_id,
                    EventKind::ModuleError {
                        module: name.into(),
                        error: "timeout".into(),
                    },
                );
            }
            Ok(Err(Error::MissingKey(key))) => {
                // An unconfigured optional provider is NOT a failure. Surface it
                // as a clean "needs key" skip (with a free-signup hint where
                // known) instead of a scary module error, and count it under
                // `skipped` rather than `errored`.
                state.stats.skipped += 1;
                // Release the dedup-ledger entry: the dedup contract is "each
                // API key/service is utilised at most once per target", and a
                // module that opted out for want of a key utilised NOTHING.
                // Leaving the entry blocked the retry for the whole scan (and
                // the whole radar session), so a key discovered later by the
                // hot-inject cascade could never be applied to this target —
                // defeating the cascade's purpose. No-op for free modules,
                // which never enter the ledger.
                state.dispatched.remove(&dispatch_key(name, cx.target));
                let reason = match crate::util::keys::signup_hint(&key) {
                    Some(hint) => format!("needs API key {key} — {hint}"),
                    None => format!("needs API key {key}"),
                };
                debug!(module = name, %key, "skipped — needs key");
                self.emit(
                    cx.scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason,
                    },
                );
            }
            Ok(Err(e)) => {
                state.stats.errored += 1;
                // Feed the breaker: a rate-limit/quota error trips immediately; any
                // other hard error counts toward the soft streak. Classify the
                // TYPED `RateLimited` variant directly — the string path
                // (`record_error`) only trips it today because `RateLimited`'s
                // Display happens to contain "rate limited", so an edit to that
                // Display would silently downgrade a real throttle to a 3-strike
                // soft failure with no compile error. Non-typed errors that still
                // carry a "429"/quota message in their text keep the string path.
                if matches!(e, crate::core::error::Error::RateLimited(_)) {
                    super::circuit::record_rate_limit(name);
                } else {
                    super::circuit::record_error(name, &e.to_string());
                }
                super::health::record_failure(name);
                warn!(module = name, error = %e, "module error");
                self.emit(
                    cx.scan_id,
                    EventKind::ModuleError {
                        module: name.into(),
                        error: e.to_string(),
                    },
                );
            }
            Ok(Ok(mut mr)) => {
                // A completed *dispatch* (even an empty one) proves the provider is
                // reachable — clear any failure streak so a recovered source is
                // trusted again immediately. A CACHE REPLAY, however, made no
                // provider call: recording a success on it would clear a failure
                // streak the live calls legitimately earned this scan (masking a
                // degrading provider, or resetting a soft-trip countdown), so the
                // breaker's success path is skipped for replays. A replay is
                // neither success nor failure to the breaker — it is invisible.
                // `health::record_success` mirrors `circuit::record_success`'s
                // recovery philosophy by design (see its own doc comment), so the
                // same cache-replay exclusion applies to it too.
                if !from_cache {
                    super::circuit::record_success(name);
                    super::health::record_success(name);
                }
                let mut found = 0usize;
                for mut entity in mr.entities.drain(..) {
                    // Safety limit: a misbehaving module must not exhaust RAM on
                    // Termux and crash the serve process. Cap results per module;
                    // any module genuinely needing more would require a
                    // paginated/streaming API redesign.
                    if found >= MAX_ENTITIES_PER_MODULE {
                        break;
                    }
                    // Admission drop-filters (pure policy in `admission_rejection`);
                    // emit the reason & skip on rejection, exactly as the inline
                    // chain did — same order, same reason strings, same continue.
                    if let Some(reason) = admission_rejection(
                        cx.seed_kind,
                        cx.opts.effective_min_confidence(),
                        &entity,
                    ) {
                        self.emit_excluded(cx.scan_id, &entity, reason);
                        continue;
                    }
                    // Universal MITRE ATT&CK provenance: stamp every ADMITTED
                    // entity with the Reconnaissance technique(s) it represents
                    // and the module that collected it, as inline `attack:<ID>`
                    // tags. This makes the technique that collected each datum
                    // travel with the data (JSON `tags`, the full dossier, the DB)
                    // — MITRE alignment lives in the findings themselves, not a
                    // separate coverage report. Tagging happens at two layers:
                    // 1. Module-level: what kind of collection the module does
                    // 2. Entity-type-level: what kind of data this entity is
                    // `Entity::tag` de-dupes so overlaps (e.g., a Username from a
                    // Social module tagged with both `T1593.001`) are idempotent.
                    // Done at the single admission point AFTER every drop filter so
                    // only surviving findings are stamped.
                    for id in attack_techniques {
                        entity.tag(format!("attack:{id}"));
                    }
                    for id in crate::core::attack::techniques_for_entity_kind(&entity.kind) {
                        entity.tag(format!("attack:{id}"));
                    }
                    // Universal breach-sector wiring: stamp the source's sector
                    // (`sector:real-estate`, …) on every breach finding — one
                    // chokepoint connects EVERY pool to `util::breach_sector`.
                    // Before the emit so the event log (and the recovery rebuild)
                    // carries it too.
                    super::tag_breach_sector(&mut entity);
                    // Categorise shared/third-party infrastructure (cloud buckets,
                    // hosting/CDN endpoints, analytics ids) as platform-infra so the
                    // default report shows only subject-owned entities. Before the
                    // emit so the event log + recovery rebuild carry the tag too.
                    super::tag_platform_infra(&mut entity);
                    self.emit(
                        cx.scan_id,
                        EventKind::EntityFound {
                            entity: entity.clone(),
                        },
                    );
                    super::scan_entity_for_keys(&entity);
                    super::enrich_geospatial(&mut entity);
                    if let Some(existing) = state.entity_map.get_mut(&entity.uid) {
                        existing.merge(entity);
                    } else {
                        state.newly_inserted.push(entity.uid.clone());
                        state.entity_map.insert(entity.uid.clone(), entity);
                    }
                    found += 1;
                }
                self.emit(
                    cx.scan_id,
                    EventKind::ModuleDone {
                        module: name.into(),
                        found,
                    },
                );
                // `debug!`, not `info!`: the structured `EventKind::ModuleDone`
                // emitted just above is the real per-module completion signal
                // (UI / SSE / metrics consume it). This log line is raw-tier
                // detail — at info it fired once per module per scan (dozens of
                // lines) and buried the handful of events that explain a scan.
                debug!(module = name, found, "done");
            }
        }
    }

    /// Replay an inter-scan cache hit for `module`: re-stamp the archived
    /// entities to the CURRENT scan and finalise them WITHOUT feeding the circuit
    /// breaker (no provider call was made). Single source of what were three
    /// byte-for-byte copies — the sequential path and both concurrent phases —
    /// so the scan_id re-stamp and the `from_cache = true` flag (the
    /// count-vs-list-consistency invariant) can never drift between them. Each
    /// call site keeps only its own divergent tail (hot-inject / cancel / throttle).
    fn replay_cached_result(
        &self,
        cx: &DispatchCx,
        module: &dyn Module,
        cached: Vec<Entity>,
        state: &mut DispatchState,
    ) {
        let name = module.name();
        state.stats.cached += 1;
        debug!(module = name, "cache hit — replaying archived entities");
        // Re-stamp replayed entities to the CURRENT scan. The cache returns
        // entities carrying the ARCHIVING scan's scan_id, and the
        // observation-junction insert keys on entity.scan_id; without this the
        // current scan's observation collides (INSERT OR IGNORE) with the
        // archiving scan's row and is dropped, so the finding silently vanishes
        // from this scan's read-back (entities_for_scan) while still being counted
        // — a count-vs-list inconsistency.
        let mut cached = cached;
        for e in &mut cached {
            e.scan_id = cx.scan_id.to_owned();
        }
        // from_cache = true: a replay must not feed the circuit breaker's success
        // path (no provider call was made).
        self.finalise_module_result(
            cx,
            name,
            Ok(Ok(ModuleResult { entities: cached })),
            state,
            module.attack_techniques(),
            true,
        );
    }

    /// Archive a successful, non-empty module result to the inter-scan entity
    /// cache under `cache_key` with `ttl_secs`, when caching is enabled for the
    /// module (`cache_key` is `Some`). Best-effort — a store failure is ignored (a
    /// cache miss only costs a re-query, never correctness). Single source of the
    /// three archive-on-success guards (sequential path, concurrent Phase 1, and
    /// the concurrent join drain).
    fn archive_if_eligible(&self, cache_key: Option<&str>, ttl_secs: u64, result: &TimeoutResult) {
        if let Some(key) = cache_key
            && let Ok(Ok(mr)) = result
            && !mr.entities.is_empty()
        {
            let _ = self
                .store
                .archive_module_result(key, ttl_secs, &mr.entities);
        }
    }

    /// Dispatch every accepting module against `cx.target`. Picks the
    /// sequential or concurrent codepath based on `cx.opts.max_concurrent`.
    pub(super) async fn dispatch_target(
        &self,
        cx: &DispatchCx<'_>,
        ctx: &mut ModuleContext,
        state: &mut DispatchState<'_>,
    ) -> Result<()> {
        if cx.opts.max_concurrent == 0 {
            self.dispatch_target_sequential(cx, ctx, state).await
        } else {
            self.dispatch_target_concurrent(cx, ctx, state).await
        }
    }

    /// Gate check shared by the sequential path and both concurrent phases: if
    /// `module` is filtered out for this `target` (excluded / disabled-in-config /
    /// not-in-allowlist / free-only / passive-only / sensor / insufficient
    /// cross-correlation), count it in `modules_skipped`, emit the `ModuleSkipped`
    /// event, and return `true` so the caller skips to the next module.
    ///
    /// One definition keeps the skip tally faithful and identical across all
    /// three dispatch loops — toggling a module off is observable in the scan
    /// summary, not just the event stream, and the counting can't drift between
    /// the sequential and the two concurrent phases.
    fn gate_skips(
        &self,
        cx: &DispatchCx<'_>,
        module: &dyn Module,
        target_sources: usize,
        stats: &mut ModuleStats,
    ) -> bool {
        if let Some(reason) =
            module_skip_reason(module, cx.target, cx.opts, cx.is_expansion, target_sources)
        {
            stats.skipped += 1;
            self.emit_skipped(cx.scan_id, module.name(), reason);
            return true;
        }
        // Capability-aware dispatch — the cross-scan, persisted counterpart of
        // the in-scan circuit breaker. Checked LAST, only for a module that
        // every standard gate above cleared to run: if its parser has provably
        // gone dead across recent scans (persistent hard failures or silent
        // zero-yield drift, see `util::scraper_health::quarantined_modules`),
        // skip it so its dispatch slot goes to a source that still works — the
        // budget the scan needs to find more. `cx.quarantined` is empty (so this
        // never fires) unless the scan enabled `skip_dead_modules` on the
        // automatic comprehensive fan-out; an explicit `--modules` allowlist or
        // `--full` run carries an empty set and quarantines nothing. Placed last
        // so a module filtered for a more specific reason still reports THAT
        // reason. Self-recovering: a module leaves the set the moment it emits
        // one healthy result.
        if cx.quarantined.contains(module.name()) {
            stats.skipped += 1;
            self.emit_skipped(
                cx.scan_id,
                module.name(),
                "capability-quarantined — persistent drift (auto-retries once it recovers)",
            );
            return true;
        }
        false
    }

    /// Sequential dispatcher (max_concurrent == 0).
    async fn dispatch_target_sequential(
        &self,
        cx: &DispatchCx<'_>,
        ctx: &mut ModuleContext,
        state: &mut DispatchState<'_>,
    ) -> Result<()> {
        // O(1) dispatch-index lookup replaces the O(M) accepts() scan. Each
        // bucket is pre-sorted — by plain module priority, or (under
        // `convex_budget`) by convex query value so the cheapest, highest-
        // optionality queries fire first and a budget-truncated sequence keeps
        // the most valuable ones; `dispatch_order_for` picks the order from the
        // flag. Iterating index-by-index (instead of pre-allocating a
        // `Vec<Arc<dyn Module>>` and Arc-cloning per target) avoids a heap
        // allocation + N atomic increments per dispatch — meaningful on the hot
        // path that runs once per expansion candidate.
        // Distinct-source count of the target entity (for the high-value-API
        // cross-correlation gate); computed once per target, not per module.
        let target_sources = target_distinct_sources(state.entity_map, cx.target);
        for &idx in self
            .graph
            .dispatch_order_for(cx.target.kind, cx.opts.convex_budget)
        {
            let Some(module) = self.modules.get(idx) else {
                continue;
            };
            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            if cx
                .opts
                .max_entities
                .is_some_and(|cap| state.entity_map.len() >= cap)
            {
                return Ok(());
            }
            let name = module.name();

            // Belt-and-braces: a module whose `consumes()` declaration
            // diverges from its runtime `accepts()` would otherwise
            // slip through. Cheap re-check on the hit path.
            if !module.accepts(cx.target) {
                continue;
            }
            if self.gate_skips(cx, &**module, target_sources, state.stats) {
                continue;
            }
            if !matches!(module.cost(), ModuleCost::Free)
                && !state.dispatched.insert(dispatch_key(name, cx.target))
            {
                state.stats.deduped += 1;
                self.emit_skipped(cx.scan_id, name, "already dispatched for this target");
                continue;
            }

            // Inter-scan entity cache (C9): check before dispatching.
            let ttl = module.cache_ttl_secs();
            let cache_key = (ttl > 0).then(|| archive_key(name, cx.target));
            if let Some(ref key) = cache_key
                && let Ok(Some(cached)) = self.store.lookup_module_result_fresh(key)
            {
                self.replay_cached_result(cx, &**module, cached, state);
                super::hot_inject_keys(&mut ctx.keys);
                if ctx.cancel.is_cancelled() {
                    return Ok(());
                }
                if cx.opts.effective_throttle_ms() > 0 {
                    sleep(Duration::from_millis(cx.opts.effective_throttle_ms())).await;
                }
                continue;
            }

            log_module_dispatch(name, cx.target);
            self.emit(
                cx.scan_id,
                EventKind::ModuleStart {
                    module: name.into(),
                },
            );

            // Per-module trace span: every log emitted inside `process()` —
            // including the external HTTP calls in `util::http` — inherits
            // {scan_id, module, target} in its NDJSON span chain, so a finding,
            // the provider call that produced it, and the log line are followable
            // end-to-end. scan_id is the correlation id (unique per scan).
            let result = run_module_guarded(
                super::resolve_timeout(cx.opts, &**module),
                name,
                module.process(cx.target, ctx),
            )
            .instrument(tracing::info_span!(
                "module",
                module = name,
                scan_id = cx.scan_id,
                target = %cx.target.value
            ))
            .await;

            // Inter-scan entity cache (C9): archive a successful result.
            self.archive_if_eligible(cache_key.as_deref(), ttl, &result);

            self.finalise_module_result(cx, name, result, state, module.attack_techniques(), false);

            super::hot_inject_keys(&mut ctx.keys);

            // Re-check the cancel flag before the throttle sleep so an
            // operator cancel between modules doesn't pay the full
            // `throttle_ms` latency before the next gate at the top of
            // the loop is reached. The throttle exists to be polite to
            // upstreams; once the operator has asked us to stop there's
            // nothing left to be polite about.
            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            if cx.opts.effective_throttle_ms() > 0 {
                sleep(Duration::from_millis(cx.opts.effective_throttle_ms())).await;
            }
        }
        Ok(())
    }

    /// Concurrent dispatcher (max_concurrent > 0). Launches up to `opts.max_concurrent`
    /// modules at a time via a Semaphore; collects results as tasks complete.
    ///
    /// Paid modules run synchronously first (key-discovery-first pattern):
    /// oathnet_pro, dehashed, intelx discover API keys that hot-inject into
    /// ctx before the remaining modules are spawned concurrently. Without this,
    /// all modules launch with a cloned ctx that lacks discovered keys.
    async fn dispatch_target_concurrent(
        &self,
        cx: &DispatchCx<'_>,
        ctx: &mut ModuleContext,
        state: &mut DispatchState<'_>,
    ) -> Result<()> {
        // Key-discovery-first: this target's Paid modules run synchronously first
        // so any keys they discover hot-inject into `ctx` BEFORE the free/key-gated
        // modules are spawned concurrently against a snapshot of it. Both phases
        // share the same O(1) dispatch-index walk (`graph.modules_for`) rather than
        // allocating a per-target `Vec<Arc<dyn Module>>`.
        self.run_paid_phase(cx, ctx, state).await;
        self.spawn_free_phase(cx, ctx, state).await
    }

    /// Phase 1 of the concurrent dispatcher: run this target's **Paid** modules
    /// synchronously, in priority order. Paid providers (oathnet_pro, dehashed,
    /// intelx, …) discover API keys that `hot_inject_keys` folds into `ctx`, so
    /// running them first lets the concurrently-spawned Phase 2 modules see those
    /// keys. Mutates `state` (entity_map / stats / dedup ledger) in place; the
    /// whole phase is best-effort per module, so it never returns an error.
    async fn run_paid_phase(
        &self,
        cx: &DispatchCx<'_>,
        ctx: &mut ModuleContext,
        state: &mut DispatchState<'_>,
    ) {
        let target_sources = target_distinct_sources(state.entity_map, cx.target);
        for &idx in self
            .graph
            .dispatch_order_for(cx.target.kind, cx.opts.convex_budget)
        {
            let Some(module) = self.modules.get(idx) else {
                continue;
            };
            if !matches!(module.cost(), ModuleCost::Paid) {
                continue;
            }
            if ctx.cancel.is_cancelled() {
                break;
            }
            // Same entity-budget short-circuit the sequential path and Phase 2
            // apply. Without it, a scan already AT max_entities kept burning
            // the most expensive dispatches there are — paid per-query APIs.
            if cx
                .opts
                .max_entities
                .is_some_and(|cap| state.entity_map.len() >= cap)
            {
                break;
            }
            let name = module.name();
            if !module.accepts(cx.target) {
                continue;
            }
            if self.gate_skips(cx, &**module, target_sources, state.stats) {
                continue;
            }
            if !state.dispatched.insert(dispatch_key(name, cx.target)) {
                state.stats.deduped += 1;
                self.emit_skipped(cx.scan_id, name, "already dispatched for this target");
                continue;
            }
            // Inter-scan entity cache (C9): check before dispatching.
            let ttl = module.cache_ttl_secs();
            let cache_key = (ttl > 0).then(|| archive_key(name, cx.target));
            if let Some(ref key) = cache_key
                && let Ok(Some(cached)) = self.store.lookup_module_result_fresh(key)
            {
                self.replay_cached_result(cx, &**module, cached, state);
                super::hot_inject_keys(&mut ctx.keys);
                continue;
            }

            log_module_dispatch(name, cx.target);
            self.emit(
                cx.scan_id,
                EventKind::ModuleStart {
                    module: name.into(),
                },
            );
            let result = run_module_guarded(
                super::resolve_timeout(cx.opts, &**module),
                name,
                module.process(cx.target, ctx),
            )
            .instrument(tracing::info_span!(
                "module",
                module = name,
                scan_id = cx.scan_id,
                target = %cx.target.value
            ))
            .await;
            // Inter-scan entity cache (C9): archive a successful result.
            self.archive_if_eligible(cache_key.as_deref(), ttl, &result);
            self.finalise_module_result(cx, name, result, state, module.attack_techniques(), false);
            // Hot-inject discovered keys so Phase 2 modules can use them.
            // Multiplier-tier keys (Shodan, Censys, Hunter, Proxycurl etc.)
            // cascade — their outputs feed web_crawler/search_engines, which
            // discover MORE keys.
            super::hot_inject_keys(&mut ctx.keys);
        }
    }

    /// Phase 2 of the concurrent dispatcher: spawn this target's remaining (Free +
    /// KeyGated) modules concurrently — bounded by a `Semaphore` sized to
    /// `effective_max_concurrent()` — and finalise their results as they complete.
    /// Runs AFTER [`run_paid_phase`](Self::run_paid_phase), so `ctx` already
    /// carries any keys the paid providers discovered. Mutates `state` in place.
    async fn spawn_free_phase(
        &self,
        cx: &DispatchCx<'_>,
        ctx: &mut ModuleContext,
        state: &mut DispatchState<'_>,
    ) -> Result<()> {
        use tokio::sync::Semaphore;
        use tokio::task::JoinSet;

        // ctx now contains any keys discovered in Phase 1. Same index-iteration
        // pattern as Phase 1 — Arc::clone moves to the single spawn site below,
        // instead of being paid for every candidate during candidate-list
        // construction.
        // `effective_max_concurrent()` bounds the operator-supplied value to
        // `MAX_CONCURRENT`: a raw `max_concurrent` reaches here straight from
        // API/CLI input, and `Semaphore::new` panics above `MAX_PERMITS`, so the
        // clamp is what stops a config value from crashing the scan (and from
        // defeating the gentle-pacing default). The `== 0` sequential branch (see
        // `dispatch_target`) is unaffected (the clamp preserves 0).
        let sem = Arc::new(Semaphore::new(cx.opts.effective_max_concurrent()));
        let mut set: JoinSet<DispatchOutcome> = JoinSet::new();
        let scan_id_arc: Arc<str> = cx.scan_id.into();
        // Share one context across all spawned modules in this round instead of
        // deep-cloning the keys map + scan_id per dispatch. Modules take
        // `&ModuleContext` (read-only) and ctx is stable within a round, so an
        // Arc bump per spawn replaces N HashMap/String clones — a real win on a
        // low-RAM phone with ~80 modules/round.
        let ctx_shared: Arc<ModuleContext> = Arc::new(ctx.clone());

        let target_sources = target_distinct_sources(state.entity_map, cx.target);
        for &idx in self
            .graph
            .dispatch_order_for(cx.target.kind, cx.opts.convex_budget)
        {
            // Opportunistically absorb any modules that already finished so
            // `entity_map.len()` below is live, not the round-start snapshot —
            // otherwise every module accepted for this target gets spawned
            // even after a sibling result (already joinable right here) has
            // pushed the scan past `max_entities` (PROBLEM_TREE T2.11 LOW:
            // over-dispatch by up to one target's module set).
            while let Some(joined) = set.try_join_next() {
                self.absorb_dispatch_outcome(cx, joined, state);
            }
            let Some(module) = self.modules.get(idx) else {
                continue;
            };
            if matches!(module.cost(), ModuleCost::Paid) {
                continue;
            }
            if ctx.cancel.is_cancelled() {
                break;
            }
            if cx
                .opts
                .max_entities
                .is_some_and(|cap| state.entity_map.len() >= cap)
            {
                break;
            }
            let name = module.name();

            if !module.accepts(cx.target) {
                continue;
            }
            if self.gate_skips(cx, &**module, target_sources, state.stats) {
                continue;
            }
            if !matches!(module.cost(), ModuleCost::Free)
                && !state.dispatched.insert(dispatch_key(name, cx.target))
            {
                state.stats.deduped += 1;
                self.emit_skipped(cx.scan_id, name, "already dispatched for this target");
                continue;
            }

            // Inter-scan entity cache (C9): capture TTL + key before spawning
            // (module and target are moved into the task and unavailable at join).
            let ttl_secs = module.cache_ttl_secs();
            let cache_key = if ttl_secs > 0 {
                archive_key(name, cx.target)
            } else {
                String::new()
            };

            // Cache hit: feed result directly without spawning a task.
            if ttl_secs > 0
                && let Ok(Some(cached)) = self.store.lookup_module_result_fresh(&cache_key)
            {
                self.replay_cached_result(cx, &**module, cached, state);
                continue;
            }

            let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
                break;
            };

            let module_arc: Arc<dyn Module> = Arc::clone(module);
            let target = cx.target.clone();
            let ctx = Arc::clone(&ctx_shared);
            let emitter = self.emitter.clone();
            let sid = Arc::clone(&scan_id_arc);
            let throttle_ms = cx.opts.effective_throttle_ms();
            let module_timeout_ms = super::resolve_timeout(cx.opts, &*module_arc);
            // Capture the producing module's ATT&CK Reconnaissance techniques
            // before the spawn: `module` is unavailable at the join site (only a
            // `DispatchOutcome` is). `&'static [&'static str]` is Copy, so it
            // moves into the task for free and rides back out in the outcome,
            // where `finalise_module_result` stamps each admitted entity.
            let attack_techniques = module.attack_techniques();

            // Re-set the foreign-key scan-scope AND regional-search ambients
            // INSIDE the spawned task: tokio task-locals do NOT propagate
            // across `spawn`, so without this the concurrent path's
            // `scan_body` calls would land in the unscoped bucket and be lost
            // at drain, and `search_engines::regional_enabled()` would
            // silently read the unscoped `false` default instead of this
            // scan's actual setting (PROBLEM_TREE T2.11). Both `with_scan`
            // and `with_regional` are allow-listed pure `core → util` leaves.
            // `regional_enabled()` reads the CURRENT task's ambient — still
            // valid here since dispatch runs on the same task `with_regional`
            // was established on in `run_with_ledger`, right up to this spawn.
            let scope_sid = sid.to_string();
            let regional_on = crate::util::regional::regional_enabled();
            set.spawn(crate::util::found_keys::with_scan(
                scope_sid,
                crate::util::regional::with_regional(regional_on, async move {
                    let _permit = permit;

                    log_module_dispatch(name, &target);
                    emitter.emit(
                        &sid,
                        EventKind::ModuleStart {
                            module: name.into(),
                        },
                    );

                    // `.instrument()` (not an ambient span) because a spawned task
                    // does NOT inherit the dispatcher's current span — without it the
                    // external HTTP logs from this concurrently-running module would
                    // be context-less. Carries {scan_id, module, target} for the same
                    // end-to-end trace the sequential path gets.
                    let result = run_module_guarded(
                        module_timeout_ms,
                        name,
                        module_arc.process(&target, &ctx),
                    )
                    .instrument(tracing::info_span!(
                        "module",
                        module = name,
                        scan_id = %sid,
                        target = %target.value
                    ))
                    .await;

                    if throttle_ms > 0 {
                        sleep(Duration::from_millis(throttle_ms)).await;
                    }

                    DispatchOutcome {
                        name,
                        result,
                        ttl_secs,
                        cache_key,
                        attack_techniques,
                    }
                }),
            ));
        }

        while let Some(joined) = set.join_next().await {
            // Operator/wall-time cancel during the drain: abort the remaining
            // in-flight modules so a single dispatch's post-cancel tail is
            // bounded to near-zero instead of up to one module-timeout (8
            // modules × a 20 s timeout is 20 s of dead wait per candidate after
            // the deadline). The just-joined result below is still finalised —
            // we keep everything already collected; the aborted tasks come back
            // as cancelled joins on the next iterations and are skipped.
            // `abort_all` is idempotent and a no-op on tasks that already
            // finished, so re-calling it each iteration is harmless.
            if ctx.cancel.is_cancelled() {
                set.abort_all();
            }
            self.absorb_dispatch_outcome(cx, joined, state);
        }
        Ok(())
    }

    /// Absorb one joined concurrent-dispatch result: archive it to the
    /// inter-scan cache if eligible, then finalise it into `state` (which
    /// grows `entity_map`, the count the `max_entities` gate in both the
    /// spawn loop and its non-blocking interleave read). Shared by the
    /// blocking join-drain after the spawn loop and the non-blocking drain
    /// inside it, so a completed module is finalised exactly once, from one
    /// place, however it was collected. A cancelled or panicked join has
    /// nothing to finalise.
    fn absorb_dispatch_outcome(
        &self,
        cx: &DispatchCx<'_>,
        joined: std::result::Result<DispatchOutcome, tokio::task::JoinError>,
        state: &mut DispatchState<'_>,
    ) {
        let outcome = match joined {
            Ok(o) => o,
            Err(e) if e.is_cancelled() => {
                tracing::debug!("concurrent module task cancelled");
                return;
            }
            Err(e) => {
                warn!(error = %e, "concurrent module task panicked");
                self.emit(
                    cx.scan_id,
                    EventKind::ModuleError {
                        module: "unknown (panicked)".into(),
                        error: e.to_string(),
                    },
                );
                return;
            }
        };
        // Inter-scan entity cache (C9): archive before finalise consumes the result.
        self.archive_if_eligible(
            (outcome.ttl_secs > 0).then_some(outcome.cache_key.as_str()),
            outcome.ttl_secs,
            &outcome.result,
        );
        // A joined outcome is always a real spawned dispatch — the concurrent
        // cache-hit path replays and finalises inline before ever spawning, so it
        // never reaches here. from_cache = false.
        self.finalise_module_result(
            cx,
            outcome.name,
            outcome.result,
            state,
            outcome.attack_techniques,
            false,
        );
    }
}
