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
use tracing::{Instrument, debug, info, warn};

use super::{DispatchLog, ModuleStats};
use crate::core::entity::{Entity, normalise};
use crate::core::error::{Error, Result};
use crate::core::event::EventKind;
use crate::core::module::{Module, ModuleContext, ModuleCost, ModuleResult};
use crate::core::scan::{ScanOptions, Target, TargetKind};

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
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "module panicked".to_string());
            warn!(module = name, %msg, "module panic contained");
            Ok(Err(Error::module(name, format!("panicked: {msg}"))))
        }
    }
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

/// Re-stamp cache-replayed entities with the CURRENT scan's id.
///
/// Archived entities carry the `scan_id` of the scan that first produced and
/// archived them. On a cache hit they are replayed into a *different* scan, but
/// their per-scan observation is keyed by `entity.scan_id`
/// (`entity_observations(entity_uid, scan_id)`, written `INSERT OR IGNORE`).
/// Left unstamped, that write collides with the archiving scan's existing row
/// and is silently ignored, so the cache-served finding records no observation
/// under the current scan and drops out of its dossier / export / correlator
/// input — even though it is still tallied in `ScanComplete.entity_count`.
/// Re-stamping attributes each replayed entity to the current scan so the
/// observation is written and the finding stays queryable. The archive copy is
/// owned (freshly deserialised per lookup) and the `scan_id` is not part of the
/// UID, so this neither mutates the stored archive nor changes entity identity /
/// merge behaviour.
fn restamp_cached(mut cached: Vec<Entity>, scan_id: &str) -> Vec<Entity> {
    for e in &mut cached {
        e.scan_id = scan_id.to_string();
    }
    cached
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
}

/// Mutable per-scan dispatch accumulators threaded through every module run: the
/// working entity set (merged by uid), the run/skip/error/dedup tallies, and the
/// paid-dedup ledger (each `module × normalised-target` fired at most once). One
/// `&mut` borrow replaces three always-together out-parameters; the fields are
/// borrowed separately at their use sites so the entity merge, the stat bump,
/// and the ledger insert never contend.
pub(super) struct DispatchState<'a> {
    pub(super) entity_map: &'a mut HashMap<String, Entity>,
    pub(super) stats: &'a mut ModuleStats,
    pub(super) dispatched: &'a mut DispatchLog,
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
    fn finalise_module_result(
        &self,
        cx: &DispatchCx,
        name: &'static str,
        result: TimeoutResult,
        state: &mut DispatchState,
        attack_techniques: &'static [&'static str],
    ) {
        state.stats.run += 1;
        match result {
            Err(_) => {
                state.stats.timed_out += 1;
                // A timeout carries no message to classify, so it's a soft
                // failure: trips only after a streak (one slow round is transient).
                super::circuit::record_soft_failure(name);
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
                // Feed the breaker: a rate-limit/quota message trips immediately;
                // any other hard error counts toward the soft streak.
                super::circuit::record_error(name, &e.to_string());
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
                // A completed dispatch (even an empty one) proves the provider is
                // reachable — clear any failure streak so a recovered source is
                // trusted again immediately.
                super::circuit::record_success(name);
                let mut found = 0usize;
                for mut entity in mr.entities.drain(..) {
                    if let Some(min) = cx.opts.min_confidence
                        && entity.confidence < min
                    {
                        // Visible like every other admission drop ("never a
                        // black box") — this was the one silent rejection.
                        self.emit_excluded(cx.scan_id, &entity, "below_min_confidence");
                        continue;
                    }
                    // Drop guaranteed-bogus IPs (documentation / reserved /
                    // benchmark ranges, e.g. 192.0.2.1 scraped off a tutorial
                    // page) at admission so they never enter the graph, fire
                    // correlations, or appear as findings. RFC1918 private and
                    // loopback are intentionally kept — local sensors surface
                    // those legitimately on-device.
                    if entity.kind == crate::core::entity::EntityKind::IpAddress
                        && crate::core::validation::is_bogus_ip(&entity.value)
                    {
                        self.emit_excluded(cx.scan_id, &entity, "bogus_ip");
                        continue;
                    }
                    // Drop documentation / placeholder artifacts (example.com,
                    // jordan@example.com, http://example.com, the `example`
                    // username, "John Doe", …) at admission so they never enter
                    // the graph, expand into whole infrastructure rounds, or
                    // fire correlations. Inherently-unique secrets (passwords /
                    // API keys / credentials) are exempt — see
                    // `validation::is_placeholder_entity`.
                    if crate::core::validation::is_placeholder_entity(&entity.kind, &entity.value) {
                        self.emit_excluded(cx.scan_id, &entity, "placeholder_artifact");
                        continue;
                    }
                    // Drop truncated / incomplete values (`@gmail`, a domain-less
                    // email, a bare dotless host, a `@`-prefixed handle that
                    // failed to normalise) at admission so the user never sees an
                    // unverifiable fragment. The auditor independently flags any
                    // that somehow slip through (`fragment-values`).
                    if crate::core::validation::is_fragment_value(&entity.kind, &entity.value) {
                        self.emit_excluded(cx.scan_id, &entity, "fragment_value");
                        continue;
                    }
                    // Drop an implausible phone at admission. A value that CLAIMS
                    // E.164 (leading `+`) but fails the country-code/length rules
                    // — e.g. "+1240893", a NANP number with only 6 national
                    // digits — is a scrape artifact, never a dialable number.
                    // Gated here so it holds for every module and every expansion
                    // round; national/ambiguous (no `+`) phones are left alone,
                    // since the modules already emit E.164.
                    if entity.kind == crate::core::entity::EntityKind::Phone
                        && entity.value.starts_with('+')
                        && !crate::core::validation::validate_phone_e164(&entity.value).valid
                    {
                        self.emit_excluded(cx.scan_id, &entity, "implausible_phone");
                        continue;
                    }
                    // Incidental-infrastructure / role-mailbox noise gate: a
                    // CDN-edge IP, shared provider / registrar / DNS / mega domain,
                    // or role/provider mailbox surfacing on an identity-seeded scan
                    // maps a provider's estate, not the subject. Dropped at
                    // admission (never enters the graph, correlator, or view), like
                    // the other admission filters. The seed-aware decision lives in
                    // `is_incidental_infra_entity` (infrastructure-seeded scans are
                    // exempt — there the infrastructure IS the subject).
                    if is_incidental_infra_entity(cx.seed_kind, &entity) {
                        self.emit_excluded(cx.scan_id, &entity, "incidental_infra");
                        continue;
                    }
                    // Spam / homoglyph content gate. A breach co-occurrence dump
                    // mints junk: scam Address text and "names" built from
                    // Cyrillic/Greek glyphs that spoof ASCII (`Bеcоme а bitcоin
                    // milliоnairе`), or random consonant strings (`ZonJZRJHHWD`).
                    // Drop a cross-script homograph for any human-text kind, and a
                    // gibberish random string for Person, at admission — neither is
                    // ever the subject. Both gates are conservative (a real
                    // accented name never trips them — see the validators).
                    if matches!(
                        entity.kind,
                        crate::core::entity::EntityKind::Person
                            | crate::core::entity::EntityKind::Address
                            | crate::core::entity::EntityKind::Username
                            | crate::core::entity::EntityKind::Organisation
                    ) && crate::core::validation::is_confusable_mixed_script(&entity.value)
                    {
                        self.emit_excluded(cx.scan_id, &entity, "confusable_homoglyph");
                        continue;
                    }
                    if entity.kind == crate::core::entity::EntityKind::Person
                        && crate::core::validation::looks_like_gibberish_name(&entity.value)
                    {
                        self.emit_excluded(cx.scan_id, &entity, "gibberish_value");
                        continue;
                    }
                    // Universal MITRE ATT&CK provenance: stamp every ADMITTED
                    // entity with the Reconnaissance technique(s) of the module
                    // that produced it, as inline `attack:<ID>` tags. This makes
                    // the technique that collected each datum travel with the data
                    // (JSON `tags`, the full dossier, the DB) — MITRE alignment
                    // lives in the findings themselves, not a separate coverage
                    // report. `Entity::tag` de-dupes and `Entity::merge` unions
                    // tags, so an entity collected via several modules carries all
                    // of their techniques. Done at the single admission point AFTER
                    // every drop filter so only surviving findings are stamped.
                    for id in attack_techniques {
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
                info!(module = name, found, "done");
            }
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
            true
        } else {
            false
        }
    }

    /// Sequential dispatcher (max_concurrent == 0).
    async fn dispatch_target_sequential(
        &self,
        cx: &DispatchCx<'_>,
        ctx: &mut ModuleContext,
        state: &mut DispatchState<'_>,
    ) -> Result<()> {
        // O(1) dispatch-index lookup replaces the O(M) accepts() scan.
        // Modules are already priority-sorted within each bucket so we
        // walk them in the same order the legacy `for module in &self.modules`
        // loop did. Iterating index-by-index (instead of pre-allocating
        // a `Vec<Arc<dyn Module>>` and Arc-cloning per target) avoids
        // a heap allocation + N atomic increments per dispatch — meaningful
        // on the hot path that runs once per expansion candidate.
        // Distinct-source count of the target entity (for the high-value-API
        // cross-correlation gate); computed once per target, not per module.
        let target_sources = target_distinct_sources(state.entity_map, cx.target);
        for &idx in self.graph.modules_for(cx.target.kind) {
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
                state.stats.cached += 1;
                debug!(module = name, "cache hit — replaying archived entities");
                let mr = ModuleResult {
                    entities: restamp_cached(cached, cx.scan_id),
                };
                self.finalise_module_result(
                    cx,
                    name,
                    Ok(Ok(mr)),
                    state,
                    module.attack_techniques(),
                );
                super::hot_inject_keys(&mut ctx.keys);
                if ctx.cancel.is_cancelled() {
                    return Ok(());
                }
                if cx.opts.throttle_ms > 0 {
                    sleep(Duration::from_millis(cx.opts.throttle_ms)).await;
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
            if let Some(ref key) = cache_key
                && let Ok(Ok(ref mr)) = result
                && !mr.entities.is_empty()
            {
                let _ = self.store.archive_module_result(key, ttl, &mr.entities);
            }

            self.finalise_module_result(cx, name, result, state, module.attack_techniques());

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
            if cx.opts.throttle_ms > 0 {
                sleep(Duration::from_millis(cx.opts.throttle_ms)).await;
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
        use tokio::sync::Semaphore;
        use tokio::task::JoinSet;

        // O(1) dispatch-index lookup — only modules accepting `target.kind`
        // are even considered. Phase 1 then filters to Paid. We iterate
        // indices directly rather than allocating a `Vec<Arc<dyn Module>>`
        // and Arc-cloning per target; on the hot path this saves a heap
        // allocation + N atomic increments per dispatch.

        // Phase 1: Run Paid modules synchronously so discovered keys are
        // available via hot-inject before the concurrent phase begins.
        let target_sources = target_distinct_sources(state.entity_map, cx.target);
        for &idx in self.graph.modules_for(cx.target.kind) {
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
                state.stats.cached += 1;
                debug!(module = name, "cache hit — replaying archived entities");
                let mr = ModuleResult {
                    entities: restamp_cached(cached, cx.scan_id),
                };
                self.finalise_module_result(
                    cx,
                    name,
                    Ok(Ok(mr)),
                    state,
                    module.attack_techniques(),
                );
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
            if let Some(ref key) = cache_key
                && let Ok(Ok(ref mr)) = result
                && !mr.entities.is_empty()
            {
                let _ = self.store.archive_module_result(key, ttl, &mr.entities);
            }
            self.finalise_module_result(cx, name, result, state, module.attack_techniques());
            // Hot-inject discovered keys so Phase 2 modules can use them.
            // Multiplier-tier keys (Shodan, Censys, Hunter, Proxycurl etc.)
            // cascade — their outputs feed web_crawler/search_engines, which
            // discover MORE keys.
            super::hot_inject_keys(&mut ctx.keys);
        }

        // Phase 2: Spawn remaining (Free + KeyGated) modules concurrently.
        // ctx now contains any keys discovered in Phase 1. Same
        // index-iteration pattern as Phase 1 — Arc::clone moves to the
        // single spawn site below, instead of being paid for every
        // candidate during candidate-list construction.
        let sem = Arc::new(Semaphore::new(cx.opts.max_concurrent));
        let mut set: JoinSet<DispatchOutcome> = JoinSet::new();
        let scan_id_arc: Arc<str> = cx.scan_id.into();
        // Share one context across all spawned modules in this round instead of
        // deep-cloning the keys map + scan_id per dispatch. Modules take
        // `&ModuleContext` (read-only) and ctx is stable within a round, so an
        // Arc bump per spawn replaces N HashMap/String clones — a real win on a
        // low-RAM phone with ~80 modules/round.
        let ctx_shared: Arc<ModuleContext> = Arc::new(ctx.clone());

        let target_sources = target_distinct_sources(state.entity_map, cx.target);
        for &idx in self.graph.modules_for(cx.target.kind) {
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
                state.stats.cached += 1;
                debug!(module = name, "cache hit — replaying archived entities");
                let mr = ModuleResult {
                    entities: restamp_cached(cached, cx.scan_id),
                };
                self.finalise_module_result(
                    cx,
                    name,
                    Ok(Ok(mr)),
                    state,
                    module.attack_techniques(),
                );
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
            let throttle_ms = cx.opts.throttle_ms;
            let module_timeout_ms = super::resolve_timeout(cx.opts, &*module_arc);
            // Capture the producing module's ATT&CK Reconnaissance techniques
            // before the spawn: `module` is unavailable at the join site (only a
            // `DispatchOutcome` is). `&'static [&'static str]` is Copy, so it
            // moves into the task for free and rides back out in the outcome,
            // where `finalise_module_result` stamps each admitted entity.
            let attack_techniques = module.attack_techniques();

            // Re-set the foreign-key scan-scope ambient INSIDE the spawned task:
            // tokio task-locals do NOT propagate across `spawn`, so without this the
            // concurrent path's `scan_body` calls would land in the unscoped bucket
            // and be lost at drain (PROBLEM_TREE T2.11). `with_scan` is the
            // allow-listed pure `core → util::found_keys` leaf.
            let scope_sid = sid.to_string();
            set.spawn(crate::util::found_keys::with_scan(scope_sid, async move {
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
                let result =
                    run_module_guarded(module_timeout_ms, name, module_arc.process(&target, &ctx))
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
            }));
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
        if outcome.ttl_secs > 0
            && let Ok(Ok(ref mr)) = outcome.result
            && !mr.entities.is_empty()
        {
            let _ = self.store.archive_module_result(
                &outcome.cache_key,
                outcome.ttl_secs,
                &mr.entities,
            );
        }
        self.finalise_module_result(
            cx,
            outcome.name,
            outcome.result,
            state,
            outcome.attack_techniques,
        );
    }
}
