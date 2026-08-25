//! Module trait + context types. This is the only contract modules need to
//! satisfy. The engine knows nothing else about any specific module.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    event::EventBus,
    scan::{Target, TargetKind},
};

/// Module funding/access cost — drives the `free_only` filter on a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCost {
    /// Public endpoint, no key, no rate-limit billing.
    Free,
    /// Requires an API key, but the key is free to register for.
    KeyGated,
    /// Requires a paid subscription.
    Paid,
}

impl ModuleCost {
    /// Stable snake_case identifier (matches serde output) — the canonical
    /// machine-readable form, owned by the type exactly as
    /// [`ModuleCategory::as_str`] is. (Previously this mapping lived as a
    /// private helper in `dependency.rs`, a second source of truth beside the
    /// serde derive that could drift.) The CLI's hyphenated "key-gated" table
    /// label is a deliberate human-display variant, not this identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::KeyGated => "key_gated",
            Self::Paid => "paid",
        }
    }
}

/// Coarse functional category for a module. Drives UI grouping in the
/// module-picker and the module-graph view. Spiderfoot 4.0 ships
/// equivalent labels (`Footprint`, `Investigate`, `Passive`) attached
/// to each `sfp_*` plugin; this enum is HSE's analogue.
///
/// Categories are derived metadata only — the engine does not gate
/// dispatch on them. They exist so the operator can filter the module
/// catalogue (`hse modules --category geo`) and so the SPA can render
/// the registry as a tabbed grid rather than one long list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCategory {
    /// DNS, certificate transparency, WHOIS, subdomain enumeration.
    DnsRecon,
    /// Breach corpora, paste exposure, stealer logs, leaked credentials.
    Breach,
    /// IP / ASN / BGP / Shodan-style infrastructure intel.
    Infrastructure,
    /// Search-engine scraping (Google, Bing, DuckDuckGo, ...).
    Search,
    /// Geolocation, geocoding, address resolution, BSSID lookup.
    Geo,
    /// Social profiles and username-search across platforms.
    Social,
    /// Email parsing, header geo, locale, verification.
    Email,
    /// Phone-number metadata, carrier, area code geo.
    Phone,
    /// Corporate / company registry / business intel.
    Corporate,
    /// Threat intel: malware, C2, abuse lists.
    Threat,
    /// Local device sensors (GPS, WiFi, cell, ARP, local interfaces).
    Sensor,
    /// People-centric enrichment (proxycurl, keybase, epieos).
    People,
    /// Site / app web-crawling, web-server fingerprinting.
    Web,
    /// Anything that doesn't fit a more specific bucket.
    Other,
}

impl ModuleCategory {
    /// Stable snake_case identifier (matches serde output).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DnsRecon => "dns_recon",
            Self::Breach => "breach",
            Self::Infrastructure => "infrastructure",
            Self::Search => "search",
            Self::Geo => "geo",
            Self::Social => "social",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Corporate => "corporate",
            Self::Threat => "threat",
            Self::Sensor => "sensor",
            Self::People => "people",
            Self::Web => "web",
            Self::Other => "other",
        }
    }
}

/// Public information about a module — exposed via `hse modules` and
/// `GET /api/v1/modules`.
///
/// Marked `#[non_exhaustive]` so future per-module metadata (e.g. tags,
/// example targets) can be added without forcing a major-version bump
/// on downstream consumers that exhaustively destructure this struct.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ModuleInfo {
    pub name: &'static str,
    pub priority: u8,
    pub cost: ModuleCost,
    pub passive: bool,
    /// One-sentence operator-facing summary of what the module does.
    /// Drives the wizard's per-row tooltip (`title="..."`). May be empty
    /// for modules added without a description, but the
    /// `all_registered_modules_have_descriptions` regression test in
    /// `tests/smoke.rs` blocks that in CI.
    pub description: &'static str,
    /// Functional category — group label for the UI module picker.
    pub category: ModuleCategory,
    /// `TargetKind`s this module dispatches on (the explicit declaration
    /// from `Module::consumes()`, not the probed default). Drives the
    /// dispatch index in `crate::core::dependency::ModuleGraph` and the
    /// `/api/v1/modules/graph` payload.
    pub consumes: Vec<&'static str>,
    /// `EntityKind`s this module is documented to emit. Empty when the
    /// module hasn't declared its output. Used by the UI to render the
    /// pivot-chain flow.
    pub produces: Vec<String>,
    /// MITRE ATT&CK® Reconnaissance (TA0043) technique IDs this module's
    /// collection implements (e.g. `["T1596.002"]` for WHOIS). Lets a finding be
    /// reported in ATT&CK terms and the catalogue's Reconnaissance coverage be
    /// assessed. Defaults from the module's category; see
    /// [`Module::attack_techniques`].
    pub attack_techniques: Vec<&'static str>,
}

/// All modules implement this trait. Default methods give sensible answers
/// so existing modules can be added without ceremony.
#[async_trait]
pub trait Module: Send + Sync {
    /// Short, stable, snake_case identifier.
    fn name(&self) -> &'static str;

    /// Higher = run earlier. 0..=255.
    fn priority(&self) -> u8;

    /// True if this module produces meaningful output for the given target.
    fn accepts(&self, target: &Target) -> bool;

    /// Run the module. Returns the entities found.
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult>;

    /// Default: `Free`. Override for key-gated or paid sources.
    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    /// Default: `false`. Override `true` for local-sensor / no-network modules
    /// (e.g. arp_scan, gps_fix, email_to_username).
    fn is_passive(&self) -> bool {
        false
    }

    /// Maximum time the engine will wait for one `process()` call before
    /// emitting `ModuleError { error: "timeout" }`.
    ///
    /// Default is the crate-wide `MODULE_TIMEOUT_MS` (3 s). Modules that
    /// legitimately need longer (GPS fixes can take 15 s, two-stage
    /// WHOIS referrals can take ~8 s) override this so the engine
    /// doesn't kill them prematurely.
    ///
    /// User-supplied `ScanOptions::module_timeout_ms` still wins — this
    /// is only consulted when the user hasn't pinned a global cap.
    fn max_timeout_ms(&self) -> u64 {
        crate::MODULE_TIMEOUT_MS
    }

    /// Per-`process()` budget the engine allows **on Termux** (Android, no
    /// root) when the user hasn't pinned a global timeout. Defaults to
    /// [`max_timeout_ms`](Module::max_timeout_ms) — almost every module
    /// behaves identically on a phone. Override DOWN for modules that are
    /// reliably slow-and-low-yield over a mobile/captive network (heavy SERP
    /// scrapers, deep crawlers): live device transcripts showed such modules
    /// burning the full cap for zero results, wall-time the phone could spend
    /// on modules that actually resolve.
    ///
    /// The engine clamps the result to its Termux cap unless the module is
    /// [cap-exempt](Module::termux_timeout_cap_exempt); an explicit
    /// `ScanOptions::module_timeout_ms` overrides this entirely. Modules that
    /// genuinely need their time on a phone too — e.g. a GPS cold-fix — simply
    /// keep the default and are bounded only by the cap.
    fn termux_timeout_ms(&self) -> u64 {
        self.max_timeout_ms()
    }

    /// Whether this module's Termux timeout is **exempt** from the engine's
    /// Termux per-module cap (`TERMUX_MODULE_TIMEOUT_CAP_MS`, 45 s).
    ///
    /// Almost every module is capped (default `false`): the cap reclaims the
    /// dead tail of hung mobile requests so one slow module can't stall a phone
    /// scan. Return `true` ONLY when the module's *happy path* legitimately
    /// exceeds the cap on a phone too, so clamping it would guarantee a
    /// zero-data timeout on every Termux run rather than reclaim waste. The
    /// canonical case is `see_know`: its `/search` endpoint has a ~55 s
    /// server-side processing cap and routinely answers in 50–60 s, so a 45 s
    /// clamp kills it before the upstream ever responds. An exempt module is
    /// bounded by its own [`termux_timeout_ms`](Module::termux_timeout_ms)
    /// instead (still finite — never unbounded).
    fn termux_timeout_cap_exempt(&self) -> bool {
        false
    }

    /// One-sentence summary of what this module does, in operator
    /// language. Shown as the wizard's hover tooltip on the module-
    /// picker grid (issue #28). Default empty for backward compat —
    /// the `all_registered_modules_have_descriptions` regression test
    /// in `tests/smoke.rs` asserts every registered module overrides
    /// this with a non-empty string so new modules can't silently slip
    /// through review without one.
    fn description(&self) -> &'static str {
        ""
    }

    /// Functional category for the module-picker UI. Default `Other`.
    ///
    /// This is metadata only — the engine does not gate dispatch on
    /// category. Override to group the module under one of the
    /// named [`ModuleCategory`] buckets so it appears under the right
    /// tab in the SPA's module grid.
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Other
    }

    /// The `TargetKind`s this module dispatches on.
    ///
    /// Default: probe every `TargetKind` against `accepts()` and
    /// return the matches. Modules whose `accepts()` gate is purely
    /// `matches!(t.kind, ...)` (the vast majority) get correct
    /// behaviour for free. Modules that gate by value shape MUST
    /// override this method explicitly so the dependency graph and
    /// dispatch index reflect their true input set.
    ///
    /// Returned vec is small (≤ 14) so allocation cost is negligible
    /// — this is invoked once per module at engine construction.
    fn consumes(&self) -> Vec<TargetKind> {
        crate::core::dependency::ALL_TARGET_KINDS
            .iter()
            .copied()
            .filter(|k| self.accepts(&Target::new(*k, crate::core::dependency::PROBE_VALUE)))
            .collect()
    }

    /// The `EntityKind`s this module is documented to emit.
    ///
    /// Default: empty. Override to document the module's outputs so
    /// the dependency-graph view in the UI can render the full pivot
    /// chain. Empty doesn't mean the module produces nothing — it
    /// means the module hasn't declared its outputs yet (back-compat).
    fn produces(&self) -> &'static [EntityKind] {
        &[]
    }

    /// How long (seconds) the inter-scan entity cache may serve a previous
    /// result for this module instead of re-querying the provider. Zero (the
    /// default) disables caching. Override for paid / key-gated modules whose
    /// data is stable within a known window (IP intel: 24 h, HLR: 24 h).
    fn cache_ttl_secs(&self) -> u64 {
        0
    }

    /// The MITRE ATT&CK® Reconnaissance (TA0043) technique IDs this module's
    /// collection implements.
    ///
    /// Default: derived from the module's [`category`](Module::category) via
    /// [`crate::core::attack::techniques_for_category`] — the category already
    /// encodes what kind of OSINT collection the module performs, so the mapping
    /// lives in one place. Override only when the category is too coarse for the
    /// module's actual technique (e.g. an *active* scanner sitting in the
    /// `Infrastructure` category maps to Active Scanning, not Search Open
    /// Technical Databases). Returned IDs must exist in the ATT&CK catalogue
    /// ([`crate::core::attack::technique`]); an architecture test enforces it.
    fn attack_techniques(&self) -> &'static [&'static str] {
        crate::core::attack::techniques_for_category(self.category())
    }

    /// Built from the other methods — don't override.
    fn info(&self) -> ModuleInfo {
        ModuleInfo {
            name: self.name(),
            priority: self.priority(),
            cost: self.cost(),
            passive: self.is_passive(),
            description: self.description(),
            category: self.category(),
            consumes: self
                .consumes()
                .into_iter()
                .map(|k| k.canonical_str())
                .collect(),
            produces: self
                .produces()
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            attack_techniques: self.attack_techniques().to_vec(),
        }
    }
}

/// Shared per-scan context handed to every module invocation.
#[derive(Clone)]
pub struct ModuleContext {
    pub scan_id: String,
    pub bus: EventBus,
    pub http: reqwest::Client,
    pub keys: HashMap<String, String>,
    /// Engine-wide cancellation flag for this scan (issue #23). The
    /// engine checks `cancel.is_cancelled()` between modules; modules
    /// running long-running internal loops MAY poll it themselves to
    /// abort mid-process for faster cancel latency. Default-constructed
    /// handles never fire.
    pub cancel: crate::core::cancel::CancelHandle,
}

impl ModuleContext {
    /// Fetch a required key by env-var name. Returns `Error::MissingKey` if
    /// absent — the engine logs this and moves on without aborting the scan.
    ///
    /// A present-but-blank value counts as absent: an env file carrying
    /// `HUNTSMAN_FOO=` is an unconfigured slot, not a credential. Routing that
    /// through [`crate::util::keys::resolve_key`] keeps the "what counts as a
    /// configured key" rule in one place, shared with the modules that resolve
    /// credentials themselves (WiGLE's user/token pair).
    pub fn key(&self, name: &str) -> Result<&str> {
        crate::util::keys::resolve_key(self.key_opt(name))
            .ok_or_else(|| Error::MissingKey(name.into()))
    }

    /// Fetch an optional key — None if absent (no error).
    pub fn key_opt(&self, name: &str) -> Option<&str> {
        self.keys.get(name).map(String::as_str)
    }

    /// Fetch the next pooled key for `service` that isn't already in `tried` —
    /// the in-scan **key cascade**. A keyed module whose current key hits a
    /// terminal 401/403/429 records that value in `tried` and calls this to get
    /// the next usable credential the pool holds, retrying the same request with
    /// it. This spends every key the pool has for the service within one
    /// `process()` call instead of stranding sibling keys until a later expansion
    /// round re-injects one. Returns `None` once no untried, usable key remains.
    ///
    /// The caller seeds `tried` with the key it started on (the one hot-injected
    /// into `ctx.keys`) so the cascade never re-hands the key that just failed.
    pub fn next_pooled_key(
        &self,
        service: &str,
        tried: &std::collections::HashSet<String>,
    ) -> Option<String> {
        crate::util::key_pool::global_pool().next_key_excluding(service, tried)
    }

    /// Report that a key received a rate-limit (429) or auth failure (401/403).
    /// Marks the key in the global pool so subsequent scans rotate to the next one.
    pub fn report_key_exhausted(&self, service: &str, key_value: &str, status: u16) {
        let pool = crate::util::key_pool::global_pool();
        pool.record_error(service, key_value);
        let key_status = if status == 429 {
            crate::util::key_pool::KeyStatus::RateLimited
        } else {
            crate::util::key_pool::KeyStatus::Invalid
        };
        pool.mark_status(service, key_value, key_status);
        // The in-memory marks above are immediate; persistence is offloaded (see
        // `key_pool::persist_off_thread` — the canonical off-runtime persist path
        // every opportunistic save site shares).
        crate::util::key_pool::persist_off_thread(pool);
    }
}

/// The entities a module produced from one target — the accumulator every
/// [`Module::process`] fills and returns. The engine merges these into the scan
/// store (GREATEST-semantics) and feeds them to the next expansion round.
#[derive(Debug, Default)]
pub struct ModuleResult {
    /// The discovered entities, in module-emission order.
    pub entities: Vec<Entity>,
}

impl ModuleResult {
    /// An empty result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty result with room pre-reserved for `cap` entities — for a module
    /// that knows its output size up front (one entity per breach row, etc.).
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entities: Vec::with_capacity(cap),
        }
    }

    /// Append one discovered entity.
    pub fn push(&mut self, entity: Entity) {
        self.entities.push(entity);
    }

    /// Tag `e` with each of `fixed` (its provenance tags) then `extra` (per-record
    /// tags), attach `ev`, and append it.
    ///
    /// The one shape behind the breach/stealer record emitters that each module
    /// had copied verbatim — `dehashed`/`breach_rich`/`see_know`'s
    /// `push_breach_entity` and `oathnet_pro`'s `push_stealer_entity`: stamp a
    /// couple of fixed provenance tags plus any per-record extras, clone in the
    /// shared evidence, and push. Each module keeps a thin wrapper that fixes its
    /// own provenance tags and calls this, so the tag-then-evidence-then-push
    /// shape lives in exactly one place. `fixed` is tagged before `extra`, so a
    /// caller's tag order is preserved.
    pub fn push_with_tags(&mut self, mut e: Entity, ev: &Evidence, fixed: &[&str], extra: &[&str]) {
        for t in fixed.iter().chain(extra) {
            e.tag(*t);
        }
        e.add_evidence(ev.clone());
        self.push(e);
    }

    /// Append every entity from an iterator.
    pub fn extend(&mut self, entities: impl IntoIterator<Item = Entity>) {
        self.entities.extend(entities);
    }

    /// True when the module produced nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// Number of entities produced.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    /// Fold a module's outcome across several *independent* concurrent
    /// sub-fetches into its final `process()` return value: if nothing was
    /// collected AND a genuine hard failure occurred among the sub-fetches,
    /// surface that failure as a real `Error` (a `ModuleError` event the
    /// operator and circuit breaker can react to) instead of a silent empty
    /// success — a total outage must never be indistinguishable from a clean
    /// negative. But if ANY sub-fetch already produced real evidence, that
    /// evidence is always kept even when a *different* sub-fetch failed, so a
    /// partial outage can never discard a genuine finding. `hard_failure` is
    /// typically the last (or first) `Err` observed across the sub-fetches —
    /// callers don't need to distinguish which one, since this only fires
    /// when nothing was found at all. Shared by every module with
    /// independent concurrent sub-fetches (`ip_reputation`, T2.111;
    /// `niamonx`, T2.114) so this evidentiary-integrity invariant is defined
    /// once, not re-derived per module.
    pub fn or_hard_failure(self, hard_failure: Option<Error>) -> Result<Self> {
        if self.is_empty()
            && let Some(e) = hard_failure
        {
            return Err(e);
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
