//! Proactive capability self-audit — probe keyless modules against their real
//! providers and classify each as alive / drifted / unreachable.
//!
//! ## Why this exists
//!
//! Every collector module parses a third-party response into entities. A
//! module's unit tests run against **canned fixtures**, so when a provider
//! silently changes its wire shape the parser starts yielding nothing while the
//! fixture tests stay green — the capability is gone and nothing says so. HSE
//! already catches this **reactively**: [`crate::util::scraper_health`]
//! aggregates real-scan outcomes and flags a source as
//! [`is_yield_drifted`](crate::util::scraper_health::SourceHealth::is_yield_drifted)
//! after ≥3 trailing zero-yield runs on a source that once produced data. That
//! only fires *after* an operator has already run several fruitless scans.
//!
//! This module is the **proactive** complement: it fires one bounded probe per
//! keyless module against a canonical, stable sample target and reports the
//! outcome up front, before an investigation is staked on a dead capability.
//! One implementation backs both callers:
//!   * `hse doctor --live` — an on-device capability preflight (opt-in; the
//!     default `hse doctor` never touches the network).
//!   * `tests/live_drift.rs` — the weekly CI drift sweep.
//!
//! ## Outcome semantics (why empty ≠ always drift)
//!
//! Reaching a provider and parsing **zero** entities only means *drift* when the
//! sample target is one the healthy provider is **guaranteed** to answer. A
//! generic `test@example.com` legitimately returns no breaches from a breach
//! module — an empty result there is normal, not drift. So the fleet sweep is a
//! **reachability + parse-sanity** signal for every keyless module, and a
//! strict **must-yield drift assertion** only for the curated [`CANARY_PROBES`]
//! whose `(module, target)` pair a live provider cannot answer emptily. That
//! keeps the CI sweep faithful to the workflow's contract — a red run is an
//! actionable drift, never a flaky endpoint — while giving the operator a
//! full-fleet view in `doctor --live`.
//!
//! ## Dead canaries (why unreachable ≠ always tolerated)
//!
//! A transport failure on an arbitrary module is tolerated: the provider may be
//! down for an hour, the runner's egress may be blocked. A canary is different —
//! it is chosen *because* its provider is expected to answer — so its probe is
//! retried ([`CANARY_ATTEMPTS`] attempts, [`CANARY_RETRY_PAUSE`] apart), and a
//! canary that answers nothing on any attempt is a **dead canary**
//! ([`ProbeReport::is_dead_canary`]): the provider is down for the whole run or
//! its endpoint is retired, and the capability is gone as surely as under drift.
//! Before this the sweep tolerated it forever — `api.bgpview.io` lost its DNS
//! and the (since retired) `bgpview` canary read "unreachable" on every weekly run while the
//! workflow stayed green.

use std::collections::HashMap;
use std::time::Duration;

use crate::core::{
    cancel::CancelHandle,
    module::{Module, ModuleContext, ModuleCost},
    scan::{Target, TargetKind},
};
use crate::util::http::build_client;

/// Result of probing one module against its live provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Provider reached; its parser produced ≥1 entity — capability healthy.
    Alive {
        /// How many entities the parser produced.
        found: usize,
    },
    /// Provider reached but the parse yielded **zero** entities. For a
    /// [`CANARY_PROBES`] module this is drift (the wire shape likely changed);
    /// for any other module it is only *suspected* — the sample may simply have
    /// no data. [`ProbeReport::is_confirmed_drift`] draws that line.
    Empty,
    /// Transport failure (DNS/TLS/connect/HTTP) — provider down or the device is
    /// offline. **Never** treated as drift.
    Unreachable {
        /// The module's error text (URL-stripped and credential-redacted).
        reason: String,
    },
    /// Exceeded the module's own timeout budget — provider slow/hung. **Never**
    /// treated as drift.
    TimedOut,
    /// The provider answered with a throttle (the typed
    /// [`crate::core::error::Error::RateLimited`]): alive, but asking for
    /// less. **Never** drift (the wire shape was not seen), **never** a dead
    /// canary (the provider plainly exists), and never retried within a run —
    /// a retry would only deepen the throttle. Before this variant a throttle
    /// was `Unreachable`, so a throttled canary read as a dead one.
    RateLimited {
        /// The throttle as the module reported it (status line and body snippet).
        reason: String,
    },
    /// The provider's edge refused this client with an anti-bot challenge,
    /// CAPTCHA or WAF block page (the typed
    /// [`crate::core::error::Error::BotChallenge`]): up and answering, but not
    /// to this client. **Never** drift (the wire shape was not seen), **never**
    /// a dead canary (the provider plainly exists), and never retried within a
    /// run — the wall is per client and a retry only re-reads it. Before this
    /// variant a challenge was `Unreachable`: the 2026-09-15 sweep filed
    /// `anubis`'s `HTTP 403 Forbidden: Attention Required! | Cloudflare` and
    /// `austlii`'s `Just a moment...` as the providers being down.
    Blocked {
        /// The refusal as the module reported it (status line and page title).
        reason: String,
    },
    /// The module declined the sample target in-band (the typed
    /// [`crate::core::error::Error::Skipped`]): the provider structurally has
    /// nothing to say about it (`NotApplicable` — an Australia-only register
    /// probed with the fleet's New York coordinate, auDA's RDAP with a `.com`)
    /// or could not be used from this host (`Unavailable`). Not a probe of the
    /// wire shape at all: **never** drift, **never** a dead canary, never
    /// retried. Before this variant a skip was `Unreachable` — "provider down"
    /// for a provider that was never asked.
    Skipped {
        /// What the silence means for coverage.
        class: crate::core::event::SkipClass,
        /// The module's own reason: what was not asked and why.
        reason: String,
    },
    /// The module's `process()` panicked while handling the live response — a
    /// hostile/malformed payload, or a bug the canned fixture tests never
    /// exercised. **Always** [`ProbeReport::is_confirmed_drift`], independent of
    /// [`CANARY_PROBES`] membership: unlike `Empty` (which needs the canary's
    /// guaranteed-data heuristic to separate signal from "this sample simply has
    /// no data"), a panic on a real provider response has no benign
    /// explanation — the module is unconditionally broken.
    Panicked {
        /// The panic payload, rendered as text.
        message: String,
    },
}

impl ProbeOutcome {
    /// Compact, stable label for the `doctor --live` table.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Alive { .. } => "alive",
            Self::Empty => "empty",
            Self::Unreachable { .. } => "unreachable",
            Self::TimedOut => "timed-out",
            Self::RateLimited { .. } => "rate-limited",
            Self::Blocked { .. } => "blocked",
            Self::Skipped { .. } => "skipped",
            Self::Panicked { .. } => "panicked",
        }
    }
}

/// Attempts a canary's probe gets before its transport outcome is final.
///
/// A canary is a curated known-positive whose provider is expected to answer,
/// so one failed connect or one timeout is not yet a verdict: the probe is
/// repeated, this many times in all with [`CANARY_RETRY_PAUSE`] between, and
/// only a provider that answers nothing for the whole run — down, or its
/// endpoint retired — is the dead-canary verdict ([`ProbeReport::is_dead_canary`])
/// the sweep fails on. Every other module keeps a single attempt: its transport
/// failure is reported and tolerated, never escalated.
pub const CANARY_ATTEMPTS: usize = 3;

/// Pause between a canary's attempts — long enough for a transient blip to
/// pass, short enough that every canary retrying twice adds well under a
/// minute to the sweep.
const CANARY_RETRY_PAUSE: Duration = Duration::from_secs(3);

/// How many attempts `module`'s probe gets — see [`CANARY_ATTEMPTS`].
#[must_use]
pub fn attempts_for(module: &str) -> usize {
    if is_canary(module) {
        CANARY_ATTEMPTS
    } else {
        1
    }
}

/// One module's probe result, with the target it was probed against.
#[derive(Debug, Clone)]
pub struct ProbeReport {
    /// Registry name of the probed module.
    pub module: &'static str,
    /// Seed kind of the sample target it was probed against.
    pub kind: TargetKind,
    /// The sample target's value.
    pub value: &'static str,
    /// What happened.
    pub outcome: ProbeOutcome,
}

impl ProbeReport {
    /// True for a [`ProbeOutcome::Panicked`] outcome unconditionally, or for a
    /// [`CANARY_PROBES`] entry that reached its provider yet parsed zero
    /// entities — the two cases a healthy system can never produce, so both are
    /// real wire-format drift. A non-canary `Empty`, or any transport/timeout
    /// outcome, is **not** confirmed drift. Exhaustive over [`ProbeOutcome`] so
    /// a future variant forces an explicit call here rather than silently
    /// defaulting to "not drift".
    pub fn is_confirmed_drift(&self) -> bool {
        match &self.outcome {
            ProbeOutcome::Panicked { .. } => true,
            ProbeOutcome::Empty => is_canary(self.module),
            ProbeOutcome::Alive { .. }
            | ProbeOutcome::Unreachable { .. }
            | ProbeOutcome::TimedOut
            | ProbeOutcome::RateLimited { .. }
            | ProbeOutcome::Blocked { .. }
            | ProbeOutcome::Skipped { .. } => false,
        }
    }

    /// True for a [`CANARY_PROBES`] entry whose provider gave no answer at all
    /// — unreachable or timed out on every one of its [`CANARY_ATTEMPTS`]
    /// (the probe itself retries, so a report carrying either outcome for a
    /// canary is already the persistent case). Not drift: the wire shape was
    /// never seen. Not tolerable either: a canary is chosen because its
    /// provider is expected to answer, so a provider that answers nothing for
    /// a whole run is down or retired, and the capability is gone just as
    /// surely. A non-canary's transport failure is never a dead canary, and a
    /// throttle ([`ProbeOutcome::RateLimited`]) or a refusal
    /// ([`ProbeOutcome::Blocked`]) never is either: the provider answered.
    pub fn is_dead_canary(&self) -> bool {
        is_canary(self.module)
            && matches!(
                self.outcome,
                ProbeOutcome::Unreachable { .. } | ProbeOutcome::TimedOut
            )
    }
}

/// Canonical, stable, public sample value for a target kind, used to exercise a
/// module's live parser. `None` for kinds with no safe fixed public sample
/// (opaque credentials/identifiers, or free-form values that no provider keys
/// on) — a module consuming only those kinds is skipped by the sweep.
///
/// Values are deliberately well-known and long-lived (Google's public DNS,
/// RFC/IANA example domains, the Bitcoin genesis address) so a probe exercises
/// the transport + parser without depending on volatile data.
pub fn canonical_sample(kind: TargetKind) -> Option<&'static str> {
    Some(match kind {
        TargetKind::Email => "test@example.com",
        TargetKind::Username => "torvalds",
        TargetKind::Phone => "+12025550123",
        TargetKind::FullName => "Fletcher Moreau",
        TargetKind::IpAddress => "8.8.8.8",
        TargetKind::Domain => "example.com",
        TargetKind::Url => "https://example.com",
        TargetKind::Asn => "AS15169",
        TargetKind::Cidr => "8.8.8.0/24",
        TargetKind::Coordinates => "40.7128,-74.0060",
        TargetKind::Organisation => "Google LLC",
        // ATO's published sample ABN (Australian Business Number).
        TargetKind::AbnAcn => "51824753556",
        TargetKind::MacAddress => "00:1A:2B:3C:4D:5E",
        // Bitcoin genesis address — permanent, always present on-chain.
        TargetKind::CryptoAddress => "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        // Free-form / opaque / device-local kinds: no fixed public value that a
        // provider would resolve, so a probe would be meaningless.
        TargetKind::Address
        | TargetKind::ApiKey
        | TargetKind::DeviceId
        | TargetKind::Ssid
        | TargetKind::TrackingId => return None,
    })
}

/// Curated **must-yield** probes: `(module name, kind, value)` triples where a
/// healthy provider is guaranteed to return ≥1 entity, so an `Empty` outcome is
/// unambiguous wire-format drift. This is the set `tests/live_drift.rs` asserts
/// on — the generalisation of the file's original single hand-picked probe
/// (`ip_geo` / ip-api.com / `8.8.8.8`) into a list.
///
/// Grow it by adding a module here **only** once its `(kind, value)` pair is
/// verified to yield deterministically against a stable public target — a
/// mis-chosen canary would make the weekly sweep flap. Everything not listed is
/// still probed by the fleet sweep for reachability; it simply isn't asserted.
pub const CANARY_PROBES: &[(&str, TargetKind, &str)] = &[
    // ip-api.com geolocation of a stable, well-known public IP — the original.
    ("ip_geo", TargetKind::IpAddress, "8.8.8.8"),
    // crt.sh Certificate Transparency logs for a domain that has issued certs.
    ("crtsh", TargetKind::Domain, "example.com"),
    // BGPView ASN → prefix enumeration for Google's well-known ASN.
    ("ip_registry", TargetKind::Asn, "AS15169"),
    // RIPEstat network info for a public IP — always resolves a holder/prefix.
    ("ripestat", TargetKind::IpAddress, "8.8.8.8"),
    // WikiTree profile search for a name the single family tree certainly
    // holds (51 profiles on 2026-09-06).
    ("wikitree", TargetKind::FullName, "Abraham Lincoln"),
    // Chronicling America: 261 886 digitised newspaper pages name him.
    (
        "chronicling_america",
        TargetKind::FullName,
        "Abraham Lincoln",
    ),
    // Open Archives: the commonest name in two centuries of Dutch registers
    // (126 802 entries on 2026-09-06).
    ("openarch", TargetKind::FullName, "Jan Jansen"),
    // wifidb's own header records this BSSID as a live-verified hit
    // (`cryptic24g`, 2026-09). On 2026-09-15 the provider answered every query
    // with an HTTP-200 HTML error template (a server-side type error in its
    // export code); a canary makes that a dead-canary verdict rather than a
    // tolerated "unreachable" line until WiFiDB recovers or the module is
    // retired.
    ("wifidb", TargetKind::MacAddress, "00:13:10:69:EF:11"),
    // ── Per-module known-positive samples ──────────────────────────────────
    // The fleet's per-kind samples can never observe these providers: the
    // username-family modules legitimately hold no `torvalds` account and read
    // `empty` on every sweep, and the Australia-only registers decline the
    // New York point in-band (`skipped`), so their drift was invisible. Each
    // pair below was verified live from the project's sandbox on 2026-09-15
    // (`hse scan -m <module> -d 0`; the entity count is noted) against a
    // long-lived, prominent public account or a public-register anchor, so it
    // yields deterministically while the provider is up.
    // GitLab's founder — 2 entities.
    ("gitlab_user", TargetKind::Username, "sytses"),
    // Hacker News' founder — 13.
    ("hacker_news", TargetKind::Username, "pg"),
    // DEV's founder — 6.
    ("devto", TargetKind::Username, "ben"),
    // Lobsters' administrator — 20.
    ("lobsters", TargetKind::Username, "pushcx"),
    // Elixir's creator — 3.
    ("hexpm_user", TargetKind::Username, "josevalim"),
    // A PAUSE id with hundreds of distributions — 8.
    ("cpan_user", TargetKind::Username, "RJBS"),
    // Ubuntu's founder — 3.
    ("launchpad_user", TargetKind::Username, "sabdfl"),
    // A prolific PyPI maintainer — 5.
    ("pypi_user", TargetKind::Username, "hugovk"),
    // serde's maintainer — 68.
    ("crates_io", TargetKind::Username, "dtolnay"),
    // The ABC's own registration, auDA RDAP with eligibility data — 13.
    ("au_rdap", TargetKind::Domain, "abc.net.au"),
    // Sydney CBD: every ABS ASGS layer resolves — 10.
    ("au_geo", TargetKind::Coordinates, "-33.8688,151.2093"),
    // Brisbane CBD: a DCDB cadastral parcel — 6.
    ("qld_cadastre", TargetKind::Coordinates, "-27.4698,153.0251"),
    // ── Second batch, verified live from the sandbox on 2026-09-15 17:01 UTC
    // (the AU registers' per-kind sample, `Google LLC`, holds nothing in
    // them; `Fletcher Moreau` is a synthetic name). `data_gov_au` / `Telstra`
    // and `asic_banned_orgs` / `Telstra` yielded nothing and are not canaries.
    // The ACNC register's own entry for the Red Cross — 5.
    (
        "acnc_charities",
        TargetKind::Organisation,
        "Australian Red Cross Society",
    ),
    // ASIC business names registered by Telstra — 143.
    ("asic_business_names", TargetKind::Organisation, "Telstra"),
    // Works BY Einstein (`query.author=`, REQ-ATTR-001) — 5.
    ("crossref_search", TargetKind::FullName, "Albert Einstein"),
    // Wikidata's item for Lincoln — 8.
    ("wikidata", TargetKind::FullName, "Abraham Lincoln"),
    // GitHub's published `assetlinks.json` — 7.
    ("app_links", TargetKind::Domain, "github.com"),
];

/// Whether `module` is a curated must-yield canary (see [`CANARY_PROBES`]).
pub fn is_canary(module: &str) -> bool {
    CANARY_PROBES.iter().any(|(name, _, _)| *name == module)
}

/// A real, network-capable, keyless module context: the production
/// SSRF-guarded client and an empty key set (these probes only ever run keyless
/// modules). The client is cloned per context — `reqwest::Client` is internally
/// `Arc`, so the connection pool / DNS resolver are shared, not rebuilt.
fn probe_ctx(http: &reqwest::Client) -> ModuleContext {
    ModuleContext {
        scan_id: "capability-probe".into(),
        bus: tokio::sync::broadcast::channel(8).0,
        http: http.clone(),
        keys: HashMap::new(),
        cancel: CancelHandle::new(),
    }
}

/// Pick the `(kind, value)` this module should be probed with: the first kind it
/// [`consumes`](Module::consumes) that has a [`canonical_sample`] **and** that
/// the module actually [`accepts`](Module::accepts). A canary's curated pair
/// wins outright so its assertion probes exactly the intended target.
///
/// Returns `None` when no consumed kind has a usable sample — the module is then
/// skipped (not an error): there is simply no safe fixed target to probe it on.
fn probe_target(m: &dyn Module) -> Option<(TargetKind, &'static str)> {
    if let Some((_, kind, value)) = CANARY_PROBES.iter().find(|(name, ..)| *name == m.name()) {
        return Some((*kind, value));
    }
    m.consumes().into_iter().find_map(|k| {
        let v = canonical_sample(k)?;
        m.accepts(&Target::new(k, v)).then_some((k, v))
    })
}

/// Probe a single module, if it is a network keyless module with a usable
/// sample target. Returns `None` when the module is skipped — key-gated/paid,
/// [passive](Module::is_passive) (local sensor, no network), or without a
/// canonical sample for any kind it consumes.
///
/// The probe is bounded by the module's own [`max_timeout_ms`](Module::max_timeout_ms),
/// mirroring how the engine wraps `process()` in production, so a stalled
/// provider can never hang the sweep.
pub async fn probe_module(m: &dyn Module, http: &reqwest::Client) -> Option<ProbeReport> {
    probe_module_impl(m, http).await
}

/// Owned-`Arc` wrapper so the fleet sweep's stream closure captures no borrow of
/// the trait object — passing `Arc<dyn Module>` (which is `'static`) by value
/// sidesteps the higher-ranked-lifetime inference failure a `|m| async move {
/// probe_module(m.as_ref(), …) }` closure hits over `&dyn Module`.
async fn probe_arc(m: std::sync::Arc<dyn Module>, http: reqwest::Client) -> Option<ProbeReport> {
    probe_module_impl(m.as_ref(), &http).await
}

async fn probe_module_impl(m: &dyn Module, http: &reqwest::Client) -> Option<ProbeReport> {
    probe_with_policy(m, http, attempts_for(m.name()), CANARY_RETRY_PAUSE).await
}

/// [`probe_module`] under an explicit retry policy: a transport outcome
/// (`Unreachable` / `TimedOut`) is tried again until `attempts` are spent,
/// `pause` apart; any other outcome is final at once. Bounded by construction —
/// exactly `attempts` calls at most. Production callers go through
/// [`attempts_for`]; the policy's own tests inject the counts.
pub(crate) async fn probe_with_policy(
    m: &dyn Module,
    http: &reqwest::Client,
    attempts: usize,
    pause: Duration,
) -> Option<ProbeReport> {
    if m.cost() != ModuleCost::Free || m.is_passive() {
        return None;
    }
    let (kind, value) = probe_target(m)?;
    let target = Target::new(kind, value);
    let ctx = probe_ctx(http);
    let budget = Duration::from_millis(m.max_timeout_ms());
    let name = m.name();
    let attempts = attempts.max(1);

    let mut outcome = probe_once(m, &target, &ctx, budget, name).await;
    for attempt in 2..=attempts {
        if !matches!(
            outcome,
            ProbeOutcome::Unreachable { .. } | ProbeOutcome::TimedOut
        ) {
            break;
        }
        tracing::debug!(
            module = name,
            attempt,
            of = attempts,
            outcome = outcome.label(),
            "capability probe: no answer — trying again"
        );
        tokio::time::sleep(pause).await;
        outcome = probe_once(m, &target, &ctx, budget, name).await;
    }
    Some(ProbeReport {
        module: name,
        kind,
        value,
        outcome,
    })
}

/// One bounded attempt: run `process` under the module's own timeout budget
/// and classify what came back.
async fn probe_once(
    m: &dyn Module,
    target: &Target,
    ctx: &ModuleContext,
    budget: Duration,
    name: &'static str,
) -> ProbeOutcome {
    use futures::FutureExt;

    // A module's parser panicking on a hostile/drifted live response must be
    // reported, not silently dropped — this is precisely the "capability is
    // gone and nothing says so" failure this whole module exists to catch (see
    // the module doc comment), so losing it here would defeat the point.
    // Mirrors `core::engine::dispatch::run_module_guarded`'s guard exactly
    // (including its exact `AssertUnwindSafe` shape) and shares its
    // message-extraction helper so the two sites can't drift apart.
    let timeout_result =
        match std::panic::AssertUnwindSafe(tokio::time::timeout(budget, m.process(target, ctx)))
            .catch_unwind()
            .await
        {
            Ok(timeout_result) => timeout_result,
            Err(payload) => {
                let message = crate::core::engine::panic_payload_to_string(&payload);
                tracing::warn!(module = name, %message, "capability probe: module panic contained");
                return ProbeOutcome::Panicked { message };
            }
        };
    match timeout_result {
        Ok(Ok(r)) if r.entities.is_empty() => ProbeOutcome::Empty,
        Ok(Ok(r)) => ProbeOutcome::Alive {
            found: r.entities.len(),
        },
        Ok(Err(crate::core::error::Error::RateLimited(reason))) => {
            ProbeOutcome::RateLimited { reason }
        }
        Ok(Err(crate::core::error::Error::BotChallenge(reason))) => {
            ProbeOutcome::Blocked { reason }
        }
        Ok(Err(crate::core::error::Error::Skipped { class, reason })) => {
            ProbeOutcome::Skipped { class, reason }
        }
        Ok(Err(e)) => ProbeOutcome::Unreachable {
            reason: e.to_string(),
        },
        Err(_) => ProbeOutcome::TimedOut,
    }
}

/// Probe every keyless, network module in the registry, `concurrency` at a time,
/// and return one [`ProbeReport`] per probed module (skipped modules omitted).
///
/// Results are sorted by module name so the output is stable run-to-run
/// (`registry()` order is construction-defined, not alphabetical). Bounded
/// concurrency keeps a full-fleet sweep from opening ~100 sockets at once on a
/// low-power phone while still finishing far faster than a serial pass.
pub async fn probe_keyless_fleet(concurrency: usize) -> Vec<ProbeReport> {
    use std::sync::Arc;
    use tokio::{sync::Semaphore, task::JoinSet};

    let http = build_client();
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    // Each probe future is `Send + 'static` — `dyn Module: Send + Sync` so
    // `Arc<dyn Module>` and the cloned client both cross the spawn boundary — so
    // a JoinSet gives bounded concurrency without the higher-ranked-lifetime
    // inference a `buffer_unordered` stream trips over `Arc<dyn Module>`.
    let mut set: JoinSet<Option<ProbeReport>> = JoinSet::new();
    for m in crate::modules::registry() {
        let http = http.clone();
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            probe_arc(m, http).await
        });
    }
    let mut reports = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(report)) = joined {
            reports.push(report);
        }
    }
    reports.sort_by(|a, b| a.module.cmp(b.module));
    reports
}

/// `~/.huntsman/capability_drift.json` — module name → unix timestamp of the
/// most recent live probe that confirmed drift on it.
fn drift_path() -> std::path::PathBuf {
    crate::util::paths::data_file("capability_drift.json")
}

/// Read the persisted drift map from `path`. Empty on missing/corrupt — this
/// is a cache of past confirmations, never load-bearing state, so a parse
/// error is non-fatal (mirrors `crate::util::settings`'s own `read_map`).
fn read_drift_map(path: &std::path::Path) -> HashMap<String, u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_drift_map_at(path: &std::path::Path, map: &HashMap<String, u64>) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(map).map_err(std::io::Error::other)?;
    crate::util::atomic_file::write(path, json.as_bytes())
}

/// Merge this sweep's confirmed-drift modules into the map at `path`, stamped
/// `now`, and persist. A module absent from THIS sweep (probed clean, or not
/// probed at all) keeps whatever it already had — a single clean re-probe
/// should not erase a real drift history the operator hasn't acted on yet;
/// [`recent_confirmed_drift`]'s TTL is what ages an entry out, not a
/// same-run overwrite.
fn record_confirmed_drift_at(path: &std::path::Path, reports: &[ProbeReport], now: u64) {
    if !reports.iter().any(ProbeReport::is_confirmed_drift) {
        return;
    }
    let mut map = read_drift_map(path);
    for r in reports.iter().filter(|r| r.is_confirmed_drift()) {
        map.insert(r.module.to_string(), now);
    }
    // Disclosed rather than discarded. This store is the ONLY thing that carries
    // a confirmed-drift finding past the printout that reported it — the next
    // offline `hse doctor` reads it instead of re-probing. A silent write
    // failure therefore does not just lose a file: it makes the next run report
    // a module as healthy that this run proved was drifting, with nothing
    // anywhere saying the finding was dropped. Still best-effort (a probe result
    // is worth printing even when it cannot be persisted), so the return value
    // stays discarded and only the silence is fixed.
    if let Err(e) = write_drift_map_at(path, &map) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "could not persist confirmed-drift findings — the next offline run will \
             not see them and may report these modules as healthy"
        );
    }
}

/// Persist this sweep's confirmed-drift modules to the on-device store. Called
/// after every live probe run — `hse doctor --live` and the Web UI's
/// `POST /api/v1/capabilities/probe` alike — so a drift finding survives past
/// the single response/printout that reported it, and the next (offline, free)
/// `hse doctor` can surface it without re-touching the network. Best-effort:
/// a write failure here must never fail the probe request itself.
pub fn record_confirmed_drift(reports: &[ProbeReport]) {
    record_confirmed_drift_at(&drift_path(), reports, crate::core::entity::unix_now());
}

/// Confirmed-drift modules still within `ttl_secs` of when a live probe last
/// caught them, sorted by module name. Pure over an explicit map + `now` so
/// the aging logic is unit-testable without touching the filesystem or clock.
fn recent_confirmed_drift_pure(
    map: &HashMap<String, u64>,
    ttl_secs: u64,
    now: u64,
) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = map
        .iter()
        .filter(|&(_, &ts)| now.saturating_sub(ts) <= ttl_secs)
        .map(|(m, &ts)| (m.clone(), ts))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Confirmed-drift modules a live probe caught within the last `ttl_secs`,
/// read from the on-device store, sorted by module name. Empty if no live
/// probe has ever run, or every prior finding has aged out — a stale entry
/// past `ttl_secs` (the provider may well have been fixed since) is silently
/// dropped rather than nagging the operator forever about a possibly-resolved
/// issue.
#[must_use]
pub fn recent_confirmed_drift(ttl_secs: u64) -> Vec<(String, u64)> {
    let map = read_drift_map(&drift_path());
    recent_confirmed_drift_pure(&map, ttl_secs, crate::core::entity::unix_now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canary_report(module: &'static str) -> ProbeReport {
        // `is_confirmed_drift` requires BOTH a canary module AND `Empty` — use
        // a real curated canary name so these tests exercise the real gate,
        // not a hand-picked module the drift persistence doesn't actually see
        // in production.
        ProbeReport {
            module,
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Empty,
        }
    }

    #[test]
    fn record_confirmed_drift_persists_only_confirmed_entries() {
        let dir = tempfile::tempdir().expect("should succeed");
        let path = dir.path().join("capability_drift.json");
        let reports = vec![
            canary_report("ip_geo"),
            ProbeReport {
                module: "some_breach_module",
                kind: TargetKind::Email,
                value: "test@example.com",
                outcome: ProbeOutcome::Empty, // not a canary — not confirmed drift
            },
            ProbeReport {
                module: "ip_geo",
                kind: TargetKind::IpAddress,
                value: "8.8.8.8",
                outcome: ProbeOutcome::Alive { found: 3 }, // healthy — no entry
            },
        ];
        record_confirmed_drift_at(&path, &reports, 1_000);
        let map = read_drift_map(&path);
        assert_eq!(map.get("ip_geo"), Some(&1_000));
        assert!(
            !map.contains_key("some_breach_module"),
            "a non-canary Empty outcome must never be persisted as drift"
        );
    }

    #[test]
    fn record_confirmed_drift_is_a_no_op_when_nothing_confirmed() {
        let dir = tempfile::tempdir().expect("should succeed");
        let path = dir.path().join("capability_drift.json");
        let reports = vec![ProbeReport {
            module: "ip_geo",
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Alive { found: 1 },
        }];
        record_confirmed_drift_at(&path, &reports, 1_000);
        assert!(
            !path.exists(),
            "a clean sweep must not create the drift file at all"
        );
    }

    #[test]
    fn record_confirmed_drift_keeps_a_prior_entry_a_clean_resweep_did_not_touch() {
        // A single re-probe run where module A comes back clean must not erase
        // module B's still-unresolved drift from an earlier run.
        let dir = tempfile::tempdir().expect("should succeed");
        let path = dir.path().join("capability_drift.json");
        record_confirmed_drift_at(&path, &[canary_report("crtsh")], 1_000);
        record_confirmed_drift_at(
            &path,
            &[ProbeReport {
                module: "ip_geo",
                kind: TargetKind::IpAddress,
                value: "8.8.8.8",
                outcome: ProbeOutcome::Alive { found: 1 },
            }],
            2_000,
        );
        let map = read_drift_map(&path);
        assert_eq!(
            map.get("crtsh"),
            Some(&1_000),
            "crtsh's earlier drift finding must survive an unrelated clean re-probe"
        );
    }

    #[test]
    fn record_confirmed_drift_updates_the_timestamp_on_repeat_confirmation() {
        let dir = tempfile::tempdir().expect("should succeed");
        let path = dir.path().join("capability_drift.json");
        record_confirmed_drift_at(&path, &[canary_report("ip_geo")], 1_000);
        record_confirmed_drift_at(&path, &[canary_report("ip_geo")], 5_000);
        let map = read_drift_map(&path);
        assert_eq!(
            map.get("ip_geo"),
            Some(&5_000),
            "must reflect the LATEST confirmation"
        );
    }

    #[test]
    fn recent_confirmed_drift_pure_keeps_within_ttl_and_drops_stale() {
        let mut map = HashMap::new();
        map.insert("fresh".to_string(), 9_500u64);
        map.insert("stale".to_string(), 1_000u64);
        let now = 10_000u64;
        let ttl = 1_000u64; // window: [9_000, 10_000]
        let out = recent_confirmed_drift_pure(&map, ttl, now);
        assert_eq!(out, vec![("fresh".to_string(), 9_500u64)]);
    }

    #[test]
    fn recent_confirmed_drift_pure_is_sorted_by_module_name() {
        let mut map = HashMap::new();
        map.insert("zeta".to_string(), 100u64);
        map.insert("alpha".to_string(), 100u64);
        let out = recent_confirmed_drift_pure(&map, 1_000, 100);
        assert_eq!(
            out,
            vec![("alpha".to_string(), 100u64), ("zeta".to_string(), 100u64)]
        );
    }

    #[test]
    fn read_drift_map_is_empty_on_missing_file() {
        let dir = tempfile::tempdir().expect("should succeed");
        let path = dir.path().join("does_not_exist.json");
        assert!(read_drift_map(&path).is_empty());
    }

    #[test]
    fn every_canary_has_a_sample_and_is_flagged() {
        let registry = crate::modules::registry();
        for (name, kind, value) in CANARY_PROBES {
            assert!(!name.is_empty(), "canary module name must be non-empty");
            assert!(!value.is_empty(), "canary {name} must have a probe value");
            // A canary's kind must be a real, sample-backed kind so the sweep
            // can construct its target.
            assert!(
                canonical_sample(*kind).is_some(),
                "canary {name} uses a kind with no canonical sample"
            );
            assert!(is_canary(name), "{name} must report as a canary");
            // The sweep probes a canary with the canary's OWN value (that is
            // what lets a per-module known-positive sample observe a provider
            // the per-kind sample never could), so the value must be a target
            // its module accepts, and the module must be one the keyless sweep
            // runs at all — a canary that is never probed asserts nothing.
            let m = registry
                .iter()
                .find(|m| m.name() == *name)
                .unwrap_or_else(|| panic!("canary {name} is not a registered module"));
            assert!(
                m.accepts(&Target::new(*kind, *value)),
                "canary {name} does not accept its own sample {value:?}"
            );
            assert_eq!(
                probe_target(m.as_ref()),
                Some((*kind, *value)),
                "the sweep must probe canary {name} with its own value"
            );
            assert!(
                matches!(m.cost(), crate::core::module::ModuleCost::Free) && !m.is_passive(),
                "canary {name} must be a keyless network module, or the sweep never probes it"
            );
        }
    }

    #[test]
    fn non_canary_is_not_flagged() {
        assert!(!is_canary("definitely_not_a_module"));
    }

    #[test]
    fn empty_is_confirmed_drift_only_for_canaries() {
        let canary = ProbeReport {
            module: "ip_geo",
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Empty,
        };
        assert!(canary.is_confirmed_drift());

        let non_canary = ProbeReport {
            module: "some_breach_module",
            kind: TargetKind::Email,
            value: "test@example.com",
            outcome: ProbeOutcome::Empty,
        };
        assert!(!non_canary.is_confirmed_drift());

        // Transport failures are never drift, even for a canary.
        let unreachable = ProbeReport {
            module: "ip_geo",
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Unreachable {
                reason: "connect".into(),
            },
        };
        assert!(!unreachable.is_confirmed_drift());
    }

    #[test]
    fn panicked_is_confirmed_drift_regardless_of_canary_status() {
        // Unlike `Empty`, a panic has no benign explanation, so it must be
        // confirmed drift even for a module that isn't a curated canary.
        let non_canary_panicked = ProbeReport {
            module: "some_breach_module",
            kind: TargetKind::Email,
            value: "test@example.com",
            outcome: ProbeOutcome::Panicked {
                message: "index out of bounds".into(),
            },
        };
        assert!(non_canary_panicked.is_confirmed_drift());

        let canary_panicked = ProbeReport {
            module: "ip_geo",
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Panicked {
                message: "called `Option::unwrap()` on a `None` value".into(),
            },
        };
        assert!(canary_panicked.is_confirmed_drift());
    }

    /// A module whose `process()` panics on a live response must not vanish
    /// from the sweep — it must come back as a normal `Some(ProbeReport)`
    /// carrying `ProbeOutcome::Panicked`, not `None` and not an unwound panic
    /// that kills the caller. `probe_module` is the single function both the
    /// public single-module probe AND `probe_keyless_fleet`'s per-module
    /// `JoinSet` task funnel through (see `probe_arc`), so proving the guard
    /// here transitively proves the fleet sweep can no longer silently drop a
    /// panicking module via a swallowed `JoinError` — no separate fleet-level
    /// test is needed to cover that path.
    ///
    /// Falsified: reverting `probe_module_impl`'s `catch_unwind` guard makes
    /// this test itself panic (the unwind propagates straight through the
    /// `#[tokio::test]` body) instead of observing `ProbeOutcome::Panicked` —
    /// confirmed manually, then the guard was restored.
    #[tokio::test]
    async fn a_panicking_module_is_reported_not_dropped() {
        use crate::core::{module::ModuleContext, scan::Target};

        struct PanicsOnProcess;

        #[async_trait::async_trait]
        impl Module for PanicsOnProcess {
            fn name(&self) -> &'static str {
                "test_panics_on_process"
            }
            fn priority(&self) -> u8 {
                50
            }
            fn accepts(&self, _: &Target) -> bool {
                true
            }
            fn consumes(&self) -> Vec<TargetKind> {
                vec![TargetKind::IpAddress]
            }
            async fn process(
                &self,
                _: &Target,
                _: &ModuleContext,
            ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
                panic!("kaboom: hostile upstream tripped a slice index")
            }
        }

        let http = build_client();
        let report = probe_module(&PanicsOnProcess, &http)
            .await
            .expect("a Free, non-passive module with a sampled kind must be probed, not skipped");

        match report.outcome {
            ProbeOutcome::Panicked { ref message } => {
                assert!(
                    message.contains("kaboom: hostile upstream tripped a slice index"),
                    "message: {message}"
                );
            }
            other => panic!("expected ProbeOutcome::Panicked, got {other:?}"),
        }
        assert!(
            report.is_confirmed_drift(),
            "a panicking module must be confirmed drift"
        );
    }

    #[test]
    fn canonical_samples_cover_the_network_kinds() {
        // Opaque / device-local / free-form kinds intentionally have no sample.
        for kind in [
            TargetKind::Address,
            TargetKind::ApiKey,
            TargetKind::DeviceId,
            TargetKind::Ssid,
            TargetKind::TrackingId,
        ] {
            assert!(canonical_sample(kind).is_none());
        }
        // Everything a public provider keys on must have one.
        for kind in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::Url,
            TargetKind::Asn,
            TargetKind::Cidr,
        ] {
            assert!(canonical_sample(kind).is_some(), "{kind:?} needs a sample");
        }
    }

    #[test]
    fn attempts_for_gives_a_canary_three_and_any_other_module_one() {
        assert_eq!(attempts_for("ip_registry"), CANARY_ATTEMPTS);
        assert_eq!(attempts_for("ip_geo"), 3);
        assert_eq!(attempts_for("gravatar"), 1);
        assert_eq!(attempts_for("not_a_module"), 1);
    }

    #[test]
    fn a_dead_canary_is_a_canary_that_gave_no_answer() {
        let report = |module, outcome| ProbeReport {
            module,
            kind: TargetKind::Asn,
            value: "AS15169",
            outcome,
        };
        let dns = || ProbeOutcome::Unreachable {
            reason: "dns error: Name or service not known".into(),
        };
        assert!(report("ip_registry", dns()).is_dead_canary());
        assert!(report("ip_registry", ProbeOutcome::TimedOut).is_dead_canary());
        assert!(
            !report("ip_registry", ProbeOutcome::Empty).is_dead_canary(),
            "an answer that parsed to nothing is drift, not a dead provider"
        );
        assert!(!report("ip_registry", ProbeOutcome::Alive { found: 1 }).is_dead_canary());
        assert!(
            !report("gravatar", dns()).is_dead_canary(),
            "a non-canary's transport failure stays tolerated"
        );
        assert!(!report("gravatar", ProbeOutcome::TimedOut).is_dead_canary());
        // Drift and death are disjoint verdicts.
        assert!(!report("ip_registry", dns()).is_confirmed_drift());
    }

    /// A module that fails its first `fail_first` calls at the transport level
    /// and answers on the next — the shape of a transient blip (or, with
    /// `usize::MAX`, of a provider that never answers).
    struct Flaky {
        fail_first: usize,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Module for Flaky {
        fn name(&self) -> &'static str {
            "flaky_probe_fixture"
        }
        fn priority(&self) -> u8 {
            50
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain)
        }
        async fn process(
            &self,
            t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < self.fail_first {
                return Err(crate::core::error::Error::module(
                    "flaky_probe_fixture",
                    "error sending request: dns error",
                ));
            }
            let mut r = crate::core::module::ModuleResult::new();
            r.push(crate::core::entity::Entity::new(
                crate::core::entity::EntityKind::Domain,
                &t.value,
                0.5,
                "probe",
            ));
            Ok(r)
        }
    }

    #[tokio::test]
    async fn a_transient_transport_failure_is_retried_and_a_persistent_one_is_final() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let http = reqwest::Client::new();

        // Fails once, answers on the second attempt: under a three-attempt
        // policy the blip is absorbed and the module is alive.
        let m = Flaky {
            fail_first: 1,
            calls: AtomicUsize::new(0),
        };
        let r = probe_with_policy(&m, &http, 3, Duration::ZERO)
            .await
            .expect("probeable");
        assert!(
            matches!(r.outcome, ProbeOutcome::Alive { found: 1 }),
            "{:?}",
            r.outcome
        );
        assert_eq!(m.calls.load(Ordering::SeqCst), 2);

        // The same blip under a single attempt (every non-canary's policy):
        // unreachable, and no second call is ever made.
        let m = Flaky {
            fail_first: 1,
            calls: AtomicUsize::new(0),
        };
        let r = probe_with_policy(&m, &http, 1, Duration::ZERO)
            .await
            .expect("probeable");
        assert!(
            matches!(r.outcome, ProbeOutcome::Unreachable { .. }),
            "{:?}",
            r.outcome
        );
        assert_eq!(m.calls.load(Ordering::SeqCst), 1);

        // Never answers: every attempt is spent, then the verdict is final —
        // bounded at exactly the attempts allowed, never more.
        let m = Flaky {
            fail_first: usize::MAX,
            calls: AtomicUsize::new(0),
        };
        let r = probe_with_policy(&m, &http, 3, Duration::ZERO)
            .await
            .expect("probeable");
        assert!(
            matches!(r.outcome, ProbeOutcome::Unreachable { .. }),
            "{:?}",
            r.outcome
        );
        assert_eq!(m.calls.load(Ordering::SeqCst), 3);
    }

    /// Declines every call with a typed not-applicable skip.
    struct OutOfScope {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Module for OutOfScope {
        fn name(&self) -> &'static str {
            "out_of_scope_probe_fixture"
        }
        fn priority(&self) -> u8 {
            50
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain)
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(crate::core::error::Error::skipped(
                crate::core::event::SkipClass::NotApplicable,
                "example.com is not in the .au namespace; auDA's RDAP publishes nothing about it",
            ))
        }
    }

    #[tokio::test]
    async fn a_typed_skip_is_its_own_outcome_never_retried_never_dead_never_drift() {
        // An Australia-only register probed with the fleet's New York sample,
        // or auDA's RDAP with a `.com`, declines in-band. That used to map to
        // `Unreachable` — "provider down" for a provider never asked — and
        // would have been re-read three times and reported as a dead canary.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let http = reqwest::Client::new();
        let m = OutOfScope {
            calls: AtomicUsize::new(0),
        };
        let r = probe_with_policy(&m, &http, 3, Duration::ZERO)
            .await
            .expect("probeable");
        assert!(
            matches!(
                &r.outcome,
                ProbeOutcome::Skipped { class: crate::core::event::SkipClass::NotApplicable, reason }
                    if reason.contains(".au")
            ),
            "{:?}",
            r.outcome
        );
        assert_eq!(r.outcome.label(), "skipped");
        assert_eq!(
            m.calls.load(Ordering::SeqCst),
            1,
            "a skip is final on the first attempt"
        );
        let canary = ProbeReport {
            module: "crtsh",
            kind: TargetKind::Domain,
            value: "example.com",
            outcome: ProbeOutcome::Skipped {
                class: crate::core::event::SkipClass::Unavailable,
                reason: "TCP/43 not routable here".into(),
            },
        };
        assert!(is_canary(canary.module));
        assert!(
            !canary.is_dead_canary(),
            "a canary that declined was never asked"
        );
        assert!(!canary.is_confirmed_drift(), "no wire shape was seen");
    }

    /// Answers every call with the typed anti-bot refusal.
    struct Challenged {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Module for Challenged {
        fn name(&self) -> &'static str {
            "challenged_probe_fixture"
        }
        fn priority(&self) -> u8 {
            50
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain)
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(crate::core::error::Error::BotChallenge(
                "challenged_probe_fixture: HTTP 403 Forbidden: Attention Required! | Cloudflare"
                    .into(),
            ))
        }
    }

    #[tokio::test]
    async fn a_bot_challenge_is_its_own_outcome_never_retried_never_dead_never_drift() {
        // The 2026-09-15 live sweep read anubis's and austlii's Cloudflare
        // challenge pages as "unreachable" — the class of a provider that is
        // down. A refused client is not a dead provider; a challenged canary
        // must never be reported as one, and hammering the wall three times
        // 3 s apart would only re-read it.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let http = reqwest::Client::new();
        let m = Challenged {
            calls: AtomicUsize::new(0),
        };
        let r = probe_with_policy(&m, &http, 3, Duration::ZERO)
            .await
            .expect("probeable");
        assert!(
            matches!(&r.outcome, ProbeOutcome::Blocked { reason } if reason.contains("Attention Required")),
            "{:?}",
            r.outcome
        );
        assert_eq!(r.outcome.label(), "blocked");
        assert_eq!(
            m.calls.load(Ordering::SeqCst),
            1,
            "a refusal is final on the first attempt"
        );
        // A canary carrying the refusal is neither dead nor drifted.
        let canary = ProbeReport {
            module: "crtsh",
            kind: TargetKind::Domain,
            value: "example.com",
            outcome: ProbeOutcome::Blocked {
                reason: "crtsh: HTTP 403 Forbidden: Just a moment...".into(),
            },
        };
        assert!(is_canary(canary.module));
        assert!(!canary.is_dead_canary(), "a refused canary answered");
        assert!(!canary.is_confirmed_drift(), "no wire shape was seen");
    }

    /// Answers every call with a typed throttle.
    struct Throttled {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Module for Throttled {
        fn name(&self) -> &'static str {
            "throttled_probe_fixture"
        }
        fn priority(&self) -> u8 {
            50
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain)
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(crate::core::error::Error::RateLimited(
                "throttled_probe_fixture: HTTP 429 Too Many Requests: slow down".into(),
            ))
        }
    }

    #[tokio::test]
    async fn a_throttle_is_its_own_outcome_never_retried_never_dead_never_drift() {
        // The 2026-09-15 live sweep read reddit_user's and steam_profile's
        // HTTP 429 as "unreachable" — the class of a provider that is down.
        // A throttled provider answered; a throttled canary is alive.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let http = reqwest::Client::new();
        let m = Throttled {
            calls: AtomicUsize::new(0),
        };
        let r = probe_with_policy(&m, &http, 3, Duration::ZERO)
            .await
            .expect("probeable");
        assert!(
            matches!(&r.outcome, ProbeOutcome::RateLimited { reason } if reason.contains("429")),
            "{:?}",
            r.outcome
        );
        assert_eq!(
            m.calls.load(Ordering::SeqCst),
            1,
            "a throttle is final at once — retrying would deepen it"
        );
        assert_eq!(r.outcome.label(), "rate-limited");

        let throttled = ProbeReport {
            module: "ip_registry",
            kind: TargetKind::Asn,
            value: "AS15169",
            outcome: ProbeOutcome::RateLimited {
                reason: "ip_registry: HTTP 429 Too Many Requests: <empty>".into(),
            },
        };
        assert!(!throttled.is_dead_canary(), "a throttled canary answered");
        assert!(
            !throttled.is_confirmed_drift(),
            "the wire shape was not seen"
        );
    }
}
