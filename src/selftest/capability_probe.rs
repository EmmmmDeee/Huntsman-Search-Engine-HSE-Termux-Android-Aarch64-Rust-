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
//!
//! One sweep's dead reading is three attempts over six seconds, and a live
//! provider can fail all three: on 2026-09-15 `crtsh` answered `502` on every
//! attempt at 22:01 and `200` four minutes later, `chronicling_america` timed
//! out three times at 20:33 and answered every other sweep of the day. So a
//! dead reading is **provisional** until the memory of earlier sweeps
//! ([`judge_dead_canaries`]) shows the same canary dead at least
//! [`DEAD_CANARY_CONFIRMATION_SECS`] earlier with no answer between: only that
//! **confirmed** verdict fails the sweep. Every live sweep records its readings
//! (`~/.huntsman/capability_dead_canaries.json`; the live-drift workflow
//! carries the file between runs as an artifact), any answer ends a canary's
//! run of dead readings, and a sweep in which no canary answered at all is a
//! reading of the vantage, not of the providers, and records nothing.

use std::collections::{BTreeMap, HashMap};
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
/// endpoint retired — is a dead-canary reading ([`ProbeReport::is_dead_canary`]),
/// which the sweep fails on once [`judge_dead_canaries`] confirms it across
/// sweeps. Every other module keeps a single attempt: its transport failure is
/// reported and tolerated, never escalated.
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
    ///
    /// One sweep's reading. Whether it is an outage or a retired endpoint is
    /// [`judge_dead_canaries`]'s call, over the memory of earlier sweeps.
    pub fn is_dead_canary(&self) -> bool {
        is_canary(self.module)
            && matches!(
                self.outcome,
                ProbeOutcome::Unreachable { .. } | ProbeOutcome::TimedOut
            )
    }

    /// True when the provider answered at all — data, nothing, a throttle, a
    /// refusal, or a body that crashed the parser. False for a transport
    /// failure or a timeout (no answer) and for a skip (never asked).
    /// Exhaustive over [`ProbeOutcome`] so a new variant must say which side
    /// it is on.
    pub fn answered(&self) -> bool {
        match &self.outcome {
            ProbeOutcome::Alive { .. }
            | ProbeOutcome::Empty
            | ProbeOutcome::RateLimited { .. }
            | ProbeOutcome::Blocked { .. }
            | ProbeOutcome::Panicked { .. } => true,
            ProbeOutcome::Unreachable { .. }
            | ProbeOutcome::TimedOut
            | ProbeOutcome::Skipped { .. } => false,
        }
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
    // SQLAlchemy's author's workspace: Bitbucket resolves a handle as a
    // workspace since its 2019 username deprecation (REQ-BITBUCKET-001) — 3.
    ("bitbucket_user", TargetKind::Username, "zzzeek"),
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
    // ── Third batch, verified live from the sandbox on 2026-09-15 21:5x UTC
    // (the per-kind samples `Fletcher Moreau`, `Google LLC` and `example.com`
    // hold nothing in these corpora, so none was observable before). Not
    // canaries, and why: `dns_axfr` / `zonetransfer.me` (TCP/53 is closed
    // from the sandbox and unreliable from mobile vantages, so a dead
    // reading would say nothing about the module), `subdomain_takeover` (a
    // dangling record is nobody's stable sample), the email modules and
    // `asic_persons` (a real person's identifier as a checked-in sample),
    // `greynoise` / `ip_reputation` (scanner addresses and Tor exits move),
    // `ransomlook` (a real victim's domain), `beacondb` (a real BSSID).
    // OFAC's SDN entry for a DPRK trading corporation (program NPWMD): the
    // subject re-emitted tagged `ofac-sdn` — 1.
    (
        "sanctions_ofac",
        TargetKind::Organisation,
        "KOREA HYOKSIN TRADING CORPORATION",
    ),
    // data.gov.au's own organisation entry for the ATO and its datasets — 11.
    (
        "data_gov_au",
        TargetKind::Organisation,
        "Australian Taxation Office",
    ),
    // The Python documentation's sitemap: one URL per documented version — 8.
    ("sitemap", TargetKind::Domain, "docs.python.org"),
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
    Some(probe_target_with_policy(m, http, kind, value, attempts, pause).await)
}

/// Probe `m` with an explicit `(kind, value)` under an explicit retry policy —
/// the one probe every path shares: the fleet sweep and `probe_module` hand
/// it the module's sample or canary target, the known-negative controls a
/// target nobody holds. Bounded by construction — exactly `attempts` calls at
/// most, each under the module's own timeout budget.
pub(crate) async fn probe_target_with_policy(
    m: &dyn Module,
    http: &reqwest::Client,
    kind: TargetKind,
    value: &'static str,
    attempts: usize,
    pause: Duration,
) -> ProbeReport {
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
    ProbeReport {
        module: name,
        kind,
        value,
        outcome,
    }
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
    classify_run(run_once(m, target, ctx, budget, name).await)
}

/// What one bounded attempt came back with, before classification.
enum RunOutcome {
    /// `process` returned.
    Answered(crate::core::error::Result<crate::core::module::ModuleResult>),
    /// The module's own budget ran out.
    TimedOut,
    /// `process` panicked; the payload as text.
    Panicked(String),
}

/// A `RunOutcome` as a [`ProbeOutcome`].
fn classify_run(run: RunOutcome) -> ProbeOutcome {
    match run {
        RunOutcome::Panicked(message) => ProbeOutcome::Panicked { message },
        RunOutcome::TimedOut => ProbeOutcome::TimedOut,
        RunOutcome::Answered(Ok(r)) if r.entities.is_empty() => ProbeOutcome::Empty,
        RunOutcome::Answered(Ok(r)) => ProbeOutcome::Alive {
            found: r.entities.len(),
        },
        RunOutcome::Answered(Err(crate::core::error::Error::RateLimited(reason))) => {
            ProbeOutcome::RateLimited { reason }
        }
        RunOutcome::Answered(Err(crate::core::error::Error::BotChallenge(reason))) => {
            ProbeOutcome::Blocked { reason }
        }
        RunOutcome::Answered(Err(crate::core::error::Error::Skipped { class, reason })) => {
            ProbeOutcome::Skipped { class, reason }
        }
        RunOutcome::Answered(Err(e)) => ProbeOutcome::Unreachable {
            reason: e.to_string(),
        },
    }
}

/// One bounded attempt, unclassified: run `process` under the module's own
/// timeout budget with its panic contained.
async fn run_once(
    m: &dyn Module,
    target: &Target,
    ctx: &ModuleContext,
    budget: Duration,
    name: &'static str,
) -> RunOutcome {
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
                return RunOutcome::Panicked(message);
            }
        };
    match timeout_result {
        Ok(answer) => RunOutcome::Answered(answer),
        Err(_) => RunOutcome::TimedOut,
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

// ── Known-negative controls ────────────────────────────────────────────────
//
// A canary proves a parser yields for a target its provider holds; it says
// nothing about what the parser yields for a target nobody holds. Observed
// 2026-09-15 from the project's sandbox (REQ-PROBE-001): three presence probes
// minted profiles — two of them body-"verified" — for a twelve-character
// handle no platform had ever seen, and every username scan had carried those
// fabrications. A known-negative control is the sweep's other half: the same
// modules probed with a target nobody holds, where the only honest yield is
// nothing — a handle for the Username family (REQ-CANARY-002), and a domain,
// a mailbox and a name nobody holds for the Domain, Email and FullName
// families (REQ-CANARY-003), one control per kind a module consumes.

/// The kinds the sweep has a control for, in the order a module's controls
/// are probed and reported. A Phone or an IpAddress has none: what a module
/// says about a number nobody holds (its numbering-plan region) or an address
/// nobody announces (its geolocation, its registry) is a fact of the value
/// itself, as honest for an unheld value as for a held one, so a yield there
/// is no fabrication and a control would prove nothing.
pub const CONTROLLED_KINDS: [TargetKind; 5] = [
    TargetKind::Username,
    TargetKind::Domain,
    TargetKind::Email,
    TargetKind::FullName,
    TargetKind::Organisation,
];

/// The control value for a target kind — a well-formed target nobody holds —
/// or `None` for a kind the sweep has no control for ([`CONTROLLED_KINDS`]).
/// Every value is read from the process's second handle nobody holds
/// ([`crate::util::probe::sweep_control_handle`], distinct from the handle the
/// presence probes judge their own presences against), so one process asks
/// every kind about one nonce: the handle itself for a Username; the handle
/// as a `.com` label for a Domain (a registrable namespace with no wildcard,
/// so an unregistered label answers NXDOMAIN and "no match" everywhere — a
/// reserved namespace is refused by the CLI's own validation and read as a
/// placeholder by every provider); the handle at Gmail for an Email (a real
/// mailbox provider, so every provider-facing parser is read against a real
/// mail domain instead of skipping on a missing MX); the handle read as a
/// pronounceable two-token name for a FullName (letters only, capitalised, so
/// every register's name rule accepts it); and that name as a proprietary
/// company for an Organisation (`<name> Pty Ltd` — the suffix every
/// Australian register and the engines' organisation queries expect, on a
/// name no register holds).
pub fn control_value(kind: TargetKind) -> Option<&'static str> {
    match kind {
        TargetKind::Username => Some(crate::util::probe::sweep_control_handle()),
        TargetKind::Domain => Some(sweep_control_domain()),
        TargetKind::Email => Some(sweep_control_email()),
        TargetKind::FullName => Some(sweep_control_name()),
        TargetKind::Organisation => Some(sweep_control_org()),
        _ => None,
    }
}

/// `<name> Pty Ltd` — the sweep's name nobody holds as a company nobody
/// registered, drawn once per process.
fn sweep_control_org() -> &'static str {
    static ORG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ORG.get_or_init(|| format!("{} Pty Ltd", sweep_control_name()))
}

/// `<handle>.com` — the sweep's handle nobody holds as a domain nobody
/// registered, drawn once per process.
fn sweep_control_domain() -> &'static str {
    static DOMAIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DOMAIN.get_or_init(|| format!("{}.com", crate::util::probe::sweep_control_handle()))
}

/// `<handle>@gmail.com` — the sweep's handle nobody holds as a mailbox nobody
/// holds at a provider every email parser knows, drawn once per process.
fn sweep_control_email() -> &'static str {
    static EMAIL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    EMAIL.get_or_init(|| format!("{}@gmail.com", crate::util::probe::sweep_control_handle()))
}

/// The sweep's handle nobody holds read as a name nobody holds
/// ([`name_from_handle`]), drawn once per process.
fn sweep_control_name() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| name_from_handle(crate::util::probe::sweep_control_handle()))
}

/// A handle's twelve characters read as two six-letter tokens, consonant and
/// vowel alternating so each is pronounceable, each capitalised — `Nepiro
/// Sutave` for `a1b2c3d4e5f6`. Letters only, so every register's name rule
/// accepts it; a pure function of the handle, so the name a process asks
/// about is the same nonce its other controls ask about.
fn name_from_handle(handle: &str) -> String {
    const CONSONANTS: &[u8] = b"bcdfghjklmnprstvwxyz";
    const VOWELS: &[u8] = b"aeiou";
    let mut name = String::with_capacity(13);
    for (i, b) in handle.bytes().take(12).enumerate() {
        let v = match b {
            b'0'..=b'9' => usize::from(b - b'0'),
            _ => usize::from(b.to_ascii_lowercase().wrapping_sub(b'a')) + 10,
        };
        let letter = if i % 2 == 0 {
            CONSONANTS[v % CONSONANTS.len()]
        } else {
            VOWELS[v % VOWELS.len()]
        };
        if i == 6 {
            name.push(' ');
        }
        if i == 0 || i == 6 {
            name.push(letter.to_ascii_uppercase() as char);
        } else {
            name.push(letter as char);
        }
    }
    name
}

/// The `(kind, value)` pairs this module's known-negative controls probe: one
/// for every kind of [`CONTROLLED_KINDS`], in that order, that the module
/// [`consumes`](Module::consumes) **and** [`accepts`](Module::accepts) with
/// the kind's [`control_value`]. Empty for a key-gated or paid module, a
/// passive one, or one consuming no controllable kind — the module then has
/// no control, which the sweep says in its count, never a passing one.
pub fn control_targets(m: &dyn Module) -> Vec<(TargetKind, &'static str)> {
    if m.cost() != ModuleCost::Free || m.is_passive() {
        return Vec::new();
    }
    let consumed = m.consumes();
    CONTROLLED_KINDS
        .into_iter()
        .filter(|k| consumed.contains(k))
        .filter_map(|k| {
            let v = control_value(k)?;
            m.accepts(&Target::new(k, v)).then_some((k, v))
        })
        .collect()
}

/// Where `kind` sits in [`CONTROLLED_KINDS`] — the order a module's controls
/// are reported in.
fn control_rank(kind: TargetKind) -> usize {
    CONTROLLED_KINDS
        .iter()
        .position(|k| *k == kind)
        .unwrap_or(CONTROLLED_KINDS.len())
}

/// A known-negative control's reading: the probe report, and — when the
/// module yielded — what it minted for the target nobody holds and which of
/// that is fabrication, so a fabrication names the entities the parser made
/// up (a red run is triageable from its log; the engines' answers vary run
/// to run, so the entities are the only record of what was minted).
#[derive(Debug, Clone)]
pub struct ControlReport {
    /// The probe's reading.
    pub report: ProbeReport,
    /// `kind value (confidence)` for each entity minted, in the module's
    /// order, at most [`MINTED_NAMED`] of them — empty unless the outcome is
    /// `Alive`.
    pub minted: Vec<String>,
    /// The subset of the answer that is fabrication ([`fabricated_names`]):
    /// every entity other than the target itself, and the target itself when
    /// re-emitted at or above [`SEED_PRESENT_RUNG`]. Empty for an honest
    /// answer — nothing, or the target alone carrying an annotation.
    pub fabricated: Vec<String>,
}

impl ControlReport {
    /// The module yielded the target itself and nothing else, below
    /// [`SEED_PRESENT_RUNG`]: an annotation of a target nobody holds (a
    /// rejected mailbox, an unreachable MX, a provider class), which says
    /// nothing about whether anyone holds it — honest, not a fabrication.
    pub fn is_annotation(&self) -> bool {
        matches!(self.report.outcome, ProbeOutcome::Alive { .. }) && self.fabricated.is_empty()
    }
}

/// How many minted entities a control names.
pub const MINTED_NAMED: usize = 8;

/// The confidence at which a module that re-emits the target itself asserts
/// the target is real. The engine merges by uid with GREATEST semantics, so a
/// module that re-emits a found identifier at a rung raises the identifier to
/// that rung whatever its own evidence was: `disposable_check` re-emitting a
/// mailbox nobody holds at 0.75 because Gmail is a real provider raised every
/// Gmail address a scan found, however weakly, to 0.75 (REQ-CANARY-003, the
/// sweep's known-negative control). Below this rung the target carries an
/// annotation and no presence claim; at or above it, a target nobody holds
/// re-emitted is fabrication. [`crate::core::confidence::MEDIUM`] is the
/// ladder's "reasonable context or solid source" — the first rung a finding
/// stands on by itself.
pub const SEED_PRESENT_RUNG: f64 = crate::core::confidence::MEDIUM;

/// `kind value (confidence)` for an entity.
fn entity_name(e: &crate::core::entity::Entity) -> String {
    format!("{} {} ({:.2})", e.kind, e.value, e.confidence)
}

/// [`entity_name`] for each entity of an answer, at most [`MINTED_NAMED`].
fn minted_names(answer: &crate::core::module::ModuleResult) -> Vec<String> {
    answer
        .entities
        .iter()
        .take(MINTED_NAMED)
        .map(entity_name)
        .collect()
}

/// The fabricated entities of an answer to the control `(kind, value)`,
/// named, at most [`MINTED_NAMED`]: every entity that is not the target
/// itself (the uid the engine merges by, so case and the engine's own
/// normalisation are not a new entity), and the target itself when re-emitted
/// at or above [`SEED_PRESENT_RUNG`]. Empty for nothing, and for the target
/// alone below the rung — an annotation.
pub fn fabricated_names(
    answer: &crate::core::module::ModuleResult,
    kind: TargetKind,
    value: &str,
) -> Vec<String> {
    let seed = Target::new(kind, value).to_entity(SEED_PRESENT_RUNG, "control");
    answer
        .entities
        .iter()
        .filter(|e| e.uid != seed.uid || e.confidence >= SEED_PRESENT_RUNG)
        .take(MINTED_NAMED)
        .map(entity_name)
        .collect()
}

/// Probe every module that has known-negative controls with each of them
/// ([`control_targets`]), `concurrency` at a time — one attempt each: a
/// control's transport failure is uninformative and tolerated, never retried
/// — and return one [`ControlReport`] per controlled `(module, kind)`, sorted
/// by module name and then in [`CONTROLLED_KINDS`] order. The reports are the
/// controls' own: never a canary reading, never drift, never a dead canary —
/// [`fabrications`] is their one verdict.
pub async fn probe_negative_controls(concurrency: usize) -> Vec<ControlReport> {
    probe_controls_of(crate::modules::registry(), build_client(), concurrency).await
}

/// [`probe_negative_controls`] over `modules` with `http` — the registry's
/// controls in production, a fixture's under test.
pub(crate) async fn probe_controls_of(
    modules: Vec<std::sync::Arc<dyn Module>>,
    http: reqwest::Client,
    concurrency: usize,
) -> Vec<ControlReport> {
    use std::sync::Arc;
    use tokio::{sync::Semaphore, task::JoinSet};

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set: JoinSet<Option<ControlReport>> = JoinSet::new();
    for m in modules {
        for (kind, value) in control_targets(m.as_ref()) {
            let m = Arc::clone(&m);
            let http = http.clone();
            let sem = Arc::clone(&sem);
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                Some(probe_control(m.as_ref(), &http, kind, value).await)
            });
        }
    }
    let mut reports = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(report)) = joined {
            reports.push(report);
        }
    }
    reports.sort_by_key(|c| (c.report.module, control_rank(c.report.kind)));
    reports
}

/// One control attempt of `m` with `(kind, value)`: the same bounded run
/// every probe makes, classified the same way, plus the names of what it
/// minted.
pub(crate) async fn probe_control(
    m: &dyn Module,
    http: &reqwest::Client,
    kind: TargetKind,
    value: &'static str,
) -> ControlReport {
    let target = Target::new(kind, value);
    let ctx = probe_ctx(http);
    let budget = Duration::from_millis(m.max_timeout_ms());
    let name = m.name();
    let run = run_once(m, &target, &ctx, budget, name).await;
    let (minted, fabricated) = match &run {
        RunOutcome::Answered(Ok(answer)) => {
            (minted_names(answer), fabricated_names(answer, kind, value))
        }
        _ => (Vec::new(), Vec::new()),
    };
    ControlReport {
        report: ProbeReport {
            module: name,
            kind,
            value,
            outcome: classify_run(run),
        },
        minted,
        fabricated,
    }
}

/// The controls that fabricated: a module that minted, for a target nobody
/// holds, anything but the target itself below [`SEED_PRESENT_RUNG`] — the
/// false-evidence class the sweep exists to catch, and the one verdict a
/// control carries. `Empty` is the honest answer, and the target alone,
/// annotated below the rung, is honest too ([`ControlReport::is_annotation`]);
/// a throttle, a refusal, a skip or a transport failure is no reading of the
/// parser at all and is reported, never counted either way.
#[must_use]
pub fn fabrications(controls: &[ControlReport]) -> Vec<&ControlReport> {
    controls
        .iter()
        .filter(|c| !c.fabricated.is_empty())
        .collect()
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

// ── Dead-canary memory ─────────────────────────────────────────────────────
//
// A dead reading is one sweep's observation: three attempts over six seconds.
// Observed 2026-09-15 on GitHub's runner: `crtsh` answered `502` on all three
// attempts at 22:01 and `200` from the sandbox four minutes later;
// `chronicling_america` timed out three times at 20:33 and answered every
// other sweep of the day. Each reading failed the run with the instruction to
// retire the capability. A retired endpoint is dead on every sweep; an outage
// on one. The memory below tells them apart: every live sweep records which
// canaries it read dead and since when, and a dead reading is confirmed only
// when the same canary was dead on a sweep at least
// `DEAD_CANARY_CONFIRMATION_SECS` earlier with no answer in between.

/// How far apart two dead readings of one canary must be before the second
/// confirms the first. A day's dispatches are one reading (sweeps minutes
/// apart see the same outage); the weekly sweep's readings are seven days
/// apart. Twenty hours rather than twenty-four so a dispatch the next day at
/// roughly the same time counts.
pub const DEAD_CANARY_CONFIRMATION_SECS: u64 = 20 * 60 * 60;

/// A remembered run of dead readings whose last reading is older than this is
/// forgotten: the canary was retired or renamed since, or the memory is from
/// another life of this install.
const DEAD_CANARY_MEMORY_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// One canary's unbroken run of dead readings, unix seconds: the first sweep
/// to read it dead and the most recent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeadSpan {
    /// The first sweep of the run to read the canary dead.
    pub first: u64,
    /// The most recent sweep to read it dead.
    pub last: u64,
}

/// Module name → its unbroken run of dead readings. A `BTreeMap` so the
/// persisted JSON is byte-stable between sweeps that record the same state.
pub type DeadCanaryMemory = BTreeMap<String, DeadSpan>;

/// What the memory makes of a canary this sweep read dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadVerdict {
    /// The first reading, or one within [`DEAD_CANARY_CONFIRMATION_SECS`] of
    /// the first: an outage until a later sweep says otherwise. Reported,
    /// never a failure.
    Provisional {
        /// When the canary was first read dead.
        since: u64,
    },
    /// Dead on this sweep and on one at least
    /// [`DEAD_CANARY_CONFIRMATION_SECS`] earlier, with no answer in between:
    /// the provider is down across sweeps, or its endpoint is retired. The
    /// verdict the sweep fails on.
    Confirmed {
        /// When the canary was first read dead.
        since: u64,
    },
}

/// A canary this sweep read dead, judged against the memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadCanary {
    /// Registry name of the canary.
    pub module: &'static str,
    /// What the attempts met, as the last one reported it.
    pub reason: String,
    /// Not yet confirmed, or confirmed.
    pub verdict: DeadVerdict,
}

impl DeadCanary {
    /// True for [`DeadVerdict::Confirmed`].
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        matches!(self.verdict, DeadVerdict::Confirmed { .. })
    }

    /// When the canary was first read dead, unix seconds.
    #[must_use]
    pub fn since(&self) -> u64 {
        match self.verdict {
            DeadVerdict::Provisional { since } | DeadVerdict::Confirmed { since } => since,
        }
    }

    /// One line for a verdict table: the module, since when it has been read
    /// dead, whether that is confirmed, and what the attempts met.
    #[must_use]
    pub fn describe(&self) -> String {
        let since = crate::util::timefmt::ymd_hm_utc(self.since());
        let standing = if self.is_confirmed() {
            "confirmed"
        } else {
            "not yet confirmed"
        };
        format!(
            "{} — dead since {since}, {standing}: {}",
            self.module, self.reason
        )
    }
}

/// What a dead canary's attempts met, from its report.
fn dead_reason(outcome: &ProbeOutcome) -> String {
    match outcome {
        ProbeOutcome::Unreachable { reason } => {
            format!("no answer on any of {CANARY_ATTEMPTS} attempts: {reason}")
        }
        ProbeOutcome::TimedOut => format!("timed out on all {CANARY_ATTEMPTS} attempts"),
        // `is_dead_canary` admits only the two shapes above.
        _ => outcome.label().to_string(),
    }
}

/// Judge this sweep's dead canaries against `memory` (the earlier sweeps'
/// readings) at `now`, and return the verdicts with the memory to carry to
/// the next sweep. Pure over explicit inputs so the arithmetic is
/// unit-testable without the filesystem or the clock.
///
/// * A canary read dead now is [`DeadVerdict::Provisional`] on its first
///   reading and [`DeadVerdict::Confirmed`] once its run of dead readings
///   began at least [`DEAD_CANARY_CONFIRMATION_SECS`] ago.
/// * A canary that [`ProbeReport::answered`] ends its run: the memory forgets
///   it. A skipped canary (never asked) leaves its run untouched, as does one
///   this sweep did not probe.
/// * A non-canary never enters the memory: its transport failure is never a
///   dead canary.
/// * A sweep in which no canary answered is a reading of the vantage (no
///   egress, no signal), not of the providers: every dead canary is
///   provisional and the memory is returned unchanged.
/// * A run whose last reading is older than `DEAD_CANARY_MEMORY_TTL_SECS` is
///   forgotten.
#[must_use]
pub fn judge_dead_canaries_pure(
    memory: &DeadCanaryMemory,
    reports: &[ProbeReport],
    now: u64,
) -> (Vec<DeadCanary>, DeadCanaryMemory) {
    let dead_now: Vec<&ProbeReport> = reports.iter().filter(|r| r.is_dead_canary()).collect();
    let vantage_reached_a_canary = reports.iter().any(|r| is_canary(r.module) && r.answered());
    if !vantage_reached_a_canary {
        let verdicts = dead_now
            .into_iter()
            .map(|r| DeadCanary {
                module: r.module,
                reason: dead_reason(&r.outcome),
                verdict: DeadVerdict::Provisional { since: now },
            })
            .collect();
        return (verdicts, memory.clone());
    }
    let mut next: DeadCanaryMemory = memory
        .iter()
        .filter(|(_, span)| now.saturating_sub(span.last) <= DEAD_CANARY_MEMORY_TTL_SECS)
        .map(|(module, span)| (module.clone(), *span))
        .collect();
    for r in reports
        .iter()
        .filter(|r| is_canary(r.module) && r.answered())
    {
        next.remove(r.module);
    }
    let mut verdicts: Vec<DeadCanary> = dead_now
        .into_iter()
        .map(|r| {
            let first = next.get(r.module).map_or(now, |span| span.first.min(now));
            next.insert(r.module.to_string(), DeadSpan { first, last: now });
            let verdict = if now.saturating_sub(first) >= DEAD_CANARY_CONFIRMATION_SECS {
                DeadVerdict::Confirmed { since: first }
            } else {
                DeadVerdict::Provisional { since: first }
            };
            DeadCanary {
                module: r.module,
                reason: dead_reason(&r.outcome),
                verdict,
            }
        })
        .collect();
    verdicts.sort_by(|a, b| a.module.cmp(b.module));
    (verdicts, next)
}

/// `~/.huntsman/capability_dead_canaries.json` — module name → its unbroken
/// run of dead readings ([`DeadSpan`]), written by every live sweep. On GitHub's
/// runner the live-drift workflow carries it between runs as an artifact.
#[must_use]
pub fn dead_canary_memory_path() -> std::path::PathBuf {
    crate::util::paths::data_file("capability_dead_canaries.json")
}

/// Read the memory at `path`. Empty on missing or corrupt: a memory that
/// cannot be read makes every dead reading a first reading, the verdict that
/// never fails a sweep — the safe side, and the policy [`read_drift_map`]
/// already applies to its cache.
fn read_dead_canary_memory(path: &std::path::Path) -> DeadCanaryMemory {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_dead_canary_memory(
    path: &std::path::Path,
    memory: &DeadCanaryMemory,
) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(memory).map_err(std::io::Error::other)?;
    crate::util::atomic_file::write(path, json.as_bytes())
}

/// Judge against the memory at `path` and carry the result forward. Only a
/// memory that changed is written (a clean sweep with nothing remembered
/// creates no file); a write failure is disclosed, never fatal — the verdicts
/// stand for this sweep either way.
fn judge_dead_canaries_at(
    path: &std::path::Path,
    reports: &[ProbeReport],
    now: u64,
) -> Vec<DeadCanary> {
    let memory = read_dead_canary_memory(path);
    let (verdicts, next) = judge_dead_canaries_pure(&memory, reports, now);
    if next != memory
        && let Err(e) = write_dead_canary_memory(path, &next)
    {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "could not persist the dead-canary memory — the next live sweep will read \
             every dead canary as a first reading"
        );
    }
    verdicts
}

/// Judge this sweep's dead canaries against the on-device memory and carry it
/// forward — called after every live sweep (the live-drift test, `hse doctor
/// --live`, the Web UI's probe) so the readings accumulate wherever the sweep
/// runs. Returns the verdicts; only a [`DeadVerdict::Confirmed`] one is the
/// sweep's failure.
pub fn judge_dead_canaries(reports: &[ProbeReport]) -> Vec<DeadCanary> {
    judge_dead_canaries_at(
        &dead_canary_memory_path(),
        reports,
        crate::core::entity::unix_now(),
    )
}

/// The runs of dead readings the memory still holds, sorted by module, for an
/// offline `hse doctor`: what earlier live sweeps read dead and since when,
/// without touching the network. Runs older than `DEAD_CANARY_MEMORY_TTL_SECS`
/// are left out, as [`judge_dead_canaries`] would forget them.
#[must_use]
pub fn remembered_dead_canaries() -> Vec<(String, DeadSpan)> {
    let now = crate::core::entity::unix_now();
    read_dead_canary_memory(&dead_canary_memory_path())
        .into_iter()
        .filter(|(_, span)| now.saturating_sub(span.last) <= DEAD_CANARY_MEMORY_TTL_SECS)
        .collect()
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

    // ── Dead-canary memory ─────────────────────────────────────────────────

    fn dead(module: &'static str) -> ProbeReport {
        ProbeReport {
            module,
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Unreachable {
                reason: "HTTP 502 Bad Gateway".into(),
            },
        }
    }

    fn alive(module: &'static str) -> ProbeReport {
        ProbeReport {
            module,
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Alive { found: 1 },
        }
    }

    fn span(first: u64, last: u64) -> DeadSpan {
        DeadSpan { first, last }
    }

    #[test]
    fn a_first_dead_reading_is_provisional_and_one_a_day_later_confirms_it() {
        let now = 1_000_000;
        let sweep = [dead("crtsh"), alive("ip_geo")];
        let (verdicts, memory) = judge_dead_canaries_pure(&DeadCanaryMemory::new(), &sweep, now);
        assert_eq!(
            verdicts,
            vec![DeadCanary {
                module: "crtsh",
                reason: "no answer on any of 3 attempts: HTTP 502 Bad Gateway".into(),
                verdict: DeadVerdict::Provisional { since: now },
            }],
            "the first reading is an outage until a later sweep says otherwise"
        );
        assert_eq!(memory.get("crtsh"), Some(&span(now, now)));

        // An hour later the reading is still provisional and the run still
        // dates from its first reading.
        let hour = now + 3_600;
        let (verdicts, memory) = judge_dead_canaries_pure(&memory, &sweep, hour);
        assert_eq!(verdicts[0].verdict, DeadVerdict::Provisional { since: now });
        assert_eq!(memory.get("crtsh"), Some(&span(now, hour)));

        // A sweep DEAD_CANARY_CONFIRMATION_SECS after the first reading
        // confirms it; the run keeps its start.
        let day = now + DEAD_CANARY_CONFIRMATION_SECS;
        let (verdicts, memory) = judge_dead_canaries_pure(&memory, &sweep, day);
        assert_eq!(verdicts[0].verdict, DeadVerdict::Confirmed { since: now });
        assert!(verdicts[0].is_confirmed());
        assert_eq!(memory.get("crtsh"), Some(&span(now, day)));
        assert_eq!(
            verdicts[0].describe(),
            "crtsh — dead since 1970-01-12 13:46 UTC, confirmed: no answer on any of 3 \
             attempts: HTTP 502 Bad Gateway"
        );
    }

    #[test]
    fn a_canary_that_answers_ends_its_run_and_a_skipped_one_keeps_it() {
        let mut memory = DeadCanaryMemory::new();
        memory.insert("crtsh".into(), span(1, 2));
        memory.insert("wifidb".into(), span(1, 2));
        memory.insert("ripestat".into(), span(1, 2));
        let sweep = [
            alive("crtsh"),
            ProbeReport {
                module: "wifidb",
                kind: TargetKind::IpAddress,
                value: "8.8.8.8",
                outcome: ProbeOutcome::Skipped {
                    class: crate::core::event::SkipClass::Unavailable,
                    reason: "not asked".into(),
                },
            },
        ];
        let now = 2 + DEAD_CANARY_CONFIRMATION_SECS;
        let (verdicts, next) = judge_dead_canaries_pure(&memory, &sweep, now);
        assert!(verdicts.is_empty(), "nothing was read dead");
        assert!(
            !next.contains_key("crtsh"),
            "an answer ends the run: the next dead reading is a first reading again"
        );
        assert_eq!(
            next.get("wifidb"),
            Some(&span(1, 2)),
            "a skipped canary was never asked, so its run is neither ended nor extended"
        );
        assert_eq!(
            next.get("ripestat"),
            Some(&span(1, 2)),
            "a canary this sweep did not probe keeps its run"
        );
    }

    #[test]
    fn a_non_canary_transport_failure_never_enters_the_memory() {
        let sweep = [dead("gravatar"), alive("ip_geo")];
        let (verdicts, memory) = judge_dead_canaries_pure(&DeadCanaryMemory::new(), &sweep, 10);
        assert!(verdicts.is_empty());
        assert!(memory.is_empty());
    }

    #[test]
    fn a_sweep_in_which_no_canary_answered_is_a_reading_of_the_vantage_not_the_providers() {
        let mut memory = DeadCanaryMemory::new();
        memory.insert("wifidb".into(), span(1, 2));
        let sweep = [
            dead("crtsh"),
            dead("wifidb"),
            ProbeReport {
                module: "ip_geo",
                kind: TargetKind::IpAddress,
                value: "8.8.8.8",
                outcome: ProbeOutcome::TimedOut,
            },
            alive("gravatar"), // a non-canary answering is not the proof
        ];
        let now = 2 + DEAD_CANARY_CONFIRMATION_SECS;
        let (verdicts, next) = judge_dead_canaries_pure(&memory, &sweep, now);
        assert_eq!(verdicts.len(), 3);
        assert!(
            verdicts
                .iter()
                .all(|d| d.verdict == DeadVerdict::Provisional { since: now }),
            "an offline vantage confirms nothing, not even a run old enough: {verdicts:?}"
        );
        assert_eq!(next, memory, "and records nothing");
    }

    #[test]
    fn a_run_of_readings_older_than_the_memory_ttl_is_forgotten() {
        let mut memory = DeadCanaryMemory::new();
        memory.insert("wifidb".into(), span(0, 0));
        let now = DEAD_CANARY_MEMORY_TTL_SECS + 1;
        let (_, next) = judge_dead_canaries_pure(&memory, &[alive("ip_geo")], now);
        assert!(
            next.is_empty(),
            "a run last read dead a month ago is forgotten"
        );
        let (_, kept) = judge_dead_canaries_pure(&memory, &[alive("ip_geo")], now - 1);
        assert_eq!(
            kept.get("wifidb"),
            Some(&span(0, 0)),
            "one still within the month is kept"
        );
    }

    #[test]
    fn the_memory_is_carried_between_sweeps_through_the_store() {
        let dir = tempfile::tempdir().expect("should succeed");
        let path = dir.path().join("capability_dead_canaries.json");

        let clean = judge_dead_canaries_at(&path, &[alive("crtsh"), alive("ip_geo")], 1_000);
        assert!(clean.is_empty());
        assert!(
            !path.exists(),
            "a clean sweep with nothing remembered creates no file"
        );

        let first = judge_dead_canaries_at(&path, &[dead("crtsh"), alive("ip_geo")], 1_000);
        assert_eq!(first[0].verdict, DeadVerdict::Provisional { since: 1_000 });
        let stored = std::fs::read_to_string(&path).expect("should succeed");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stored).expect("should succeed"),
            serde_json::json!({ "crtsh": { "first": 1_000, "last": 1_000 } }),
            "the memory is the persisted JSON the workflow carries between runs"
        );

        let later = 1_000 + DEAD_CANARY_CONFIRMATION_SECS;
        let second = judge_dead_canaries_at(&path, &[dead("crtsh"), alive("ip_geo")], later);
        assert_eq!(
            second[0].verdict,
            DeadVerdict::Confirmed { since: 1_000 },
            "the second sweep reads the first sweep's memory from the store"
        );

        let recovered =
            judge_dead_canaries_at(&path, &[alive("crtsh"), alive("ip_geo")], later + 1);
        assert!(recovered.is_empty());
        assert!(
            !read_dead_canary_memory(&path).contains_key("crtsh"),
            "an answer ends the run in the store too"
        );

        std::fs::write(&path, "not json").expect("should succeed");
        let unreadable =
            judge_dead_canaries_at(&path, &[dead("crtsh"), alive("ip_geo")], later + 2);
        assert_eq!(
            unreadable[0].verdict,
            DeadVerdict::Provisional { since: later + 2 },
            "a memory that cannot be read makes every dead reading a first reading"
        );
    }

    // ── Known-negative controls ────────────────────────────────────────────

    #[test]
    fn every_keyless_network_module_has_one_control_per_controllable_kind_and_no_other_does() {
        let handle = crate::util::probe::sweep_control_handle();
        assert_ne!(
            handle,
            crate::util::probe::control_handle(),
            "the sweep's target must not be the handle the presence probes judge against"
        );
        let mut per_kind: HashMap<TargetKind, usize> = HashMap::new();
        let mut by_module: HashMap<&'static str, Vec<TargetKind>> = HashMap::new();
        for m in crate::modules::registry() {
            let m = m.as_ref();
            let network = m.cost() == ModuleCost::Free && !m.is_passive();
            let consumed = m.consumes();
            let expected: Vec<(TargetKind, &'static str)> = CONTROLLED_KINDS
                .into_iter()
                .filter(|k| network && consumed.contains(k))
                .filter_map(|k| {
                    let v = control_value(k).expect("a controlled kind has a value");
                    m.accepts(&Target::new(k, v)).then_some((k, v))
                })
                .collect();
            let controls = control_targets(m);
            assert_eq!(
                controls,
                expected,
                "{}: one control per controllable kind a keyless network module consumes and \
                 accepts, in CONTROLLED_KINDS order, and none for any other module",
                m.name()
            );
            for (k, _) in &controls {
                *per_kind.entry(*k).or_default() += 1;
            }
            by_module.insert(m.name(), controls.into_iter().map(|(k, _)| k).collect());
        }
        // Concrete members of each family, and the modules that have none.
        let kinds = |name: &str| by_module.get(name).cloned().unwrap_or_default();
        assert_eq!(kinds("github_user"), vec![TargetKind::Username]);
        assert_eq!(kinds("whois"), vec![TargetKind::Domain]);
        assert_eq!(kinds("gravatar"), vec![TargetKind::Email]);
        assert_eq!(kinds("wikitree"), vec![TargetKind::FullName]);
        assert_eq!(
            kinds("search_engines"),
            CONTROLLED_KINDS.to_vec(),
            "the engines answer every kind, so they are controlled for every kind"
        );
        assert_eq!(kinds("crtsh"), vec![TargetKind::Domain, TargetKind::Email]);
        assert_eq!(kinds("acnc_charities"), vec![TargetKind::Organisation]);
        assert_eq!(
            kinds("wikidata"),
            vec![TargetKind::FullName, TargetKind::Organisation]
        );
        assert!(kinds("see_know").is_empty(), "a paid module has no control");
        assert!(kinds("ip_geo").is_empty(), "an IpAddress has no control");
        for (kind, at_least) in [
            (TargetKind::Username, 20),
            (TargetKind::Domain, 20),
            (TargetKind::Email, 10),
            (TargetKind::FullName, 10),
            (TargetKind::Organisation, 10),
        ] {
            let n = per_kind.get(&kind).copied().unwrap_or(0);
            assert!(
                n >= at_least,
                "the {kind:?} family is at least {at_least} modules; {n} controlled"
            );
        }
    }

    /// Every control is a well-formed target nobody holds, read from the one
    /// handle, never the sweep's sample or a canary; a kind outside
    /// `CONTROLLED_KINDS` has none.
    #[test]
    fn every_control_is_a_well_formed_target_nobody_holds_read_from_one_handle() {
        let handle = crate::util::probe::sweep_control_handle();
        for kind in CONTROLLED_KINDS {
            let value = control_value(kind).expect("a controlled kind has a value");
            assert_eq!(
                Target::new(kind, value).validate(),
                Ok(()),
                "{kind:?} `{value}` passes the CLI's own validation"
            );
            assert_ne!(
                Some(value),
                canonical_sample(kind),
                "{kind:?}: never the sample"
            );
            assert!(
                !CANARY_PROBES
                    .iter()
                    .any(|(_, k, v)| *k == kind && *v == value),
                "{kind:?}: never a canary"
            );
            assert_eq!(control_value(kind), Some(value), "drawn once per process");
        }
        assert_eq!(control_value(TargetKind::Username), Some(handle));
        assert_eq!(
            control_value(TargetKind::Domain),
            Some(format!("{handle}.com").as_str())
        );
        assert_eq!(
            control_value(TargetKind::Email),
            Some(format!("{handle}@gmail.com").as_str())
        );
        assert_eq!(
            control_value(TargetKind::FullName),
            Some(name_from_handle(handle).as_str())
        );
        let name = control_value(TargetKind::FullName).expect("a name");
        let tokens: Vec<&str> = name.split(' ').collect();
        assert_eq!(tokens.len(), 2, "{name}");
        for t in &tokens {
            assert_eq!(t.len(), 6, "{name}");
            assert!(t.starts_with(|c: char| c.is_ascii_uppercase()), "{name}");
            assert!(t[1..].bytes().all(|b| b.is_ascii_lowercase()), "{name}");
        }
        assert_eq!(name_from_handle("a1b2c3d4e5f6"), "Nepiro Sutave");
        assert_eq!(name_from_handle("zzzzzzzzzzzz"), "Vavava Vavava");
        assert_eq!(
            control_value(TargetKind::Organisation),
            Some(format!("{name} Pty Ltd").as_str())
        );
        // A fact of the value is not a fabrication: no control for these.
        assert_eq!(control_value(TargetKind::Phone), None);
        assert_eq!(control_value(TargetKind::IpAddress), None);
        assert_eq!(control_value(TargetKind::Url), None);
    }

    #[test]
    fn a_control_that_fabricates_is_a_fabrication_and_any_other_reading_is_not() {
        let control = |module, outcome| ProbeReport {
            module,
            kind: TargetKind::Username,
            value: "nobodyholds1",
            outcome,
        };
        let controls = vec![
            control("github_user", ProbeOutcome::Alive { found: 2 }),
            // The target alone, annotated below the present rung.
            control("gravatar", ProbeOutcome::Alive { found: 1 }),
            control("gitlab_user", ProbeOutcome::Empty),
            control(
                "reddit_user",
                ProbeOutcome::RateLimited {
                    reason: "429".into(),
                },
            ),
            control(
                "steam_profile",
                ProbeOutcome::Blocked {
                    reason: "wall".into(),
                },
            ),
            control(
                "devto",
                ProbeOutcome::Unreachable {
                    reason: "dns".into(),
                },
            ),
            control("lobsters", ProbeOutcome::TimedOut),
            control(
                "hacker_news",
                ProbeOutcome::Skipped {
                    class: crate::core::event::SkipClass::NotApplicable,
                    reason: "declined".into(),
                },
            ),
            control(
                "pypi_user",
                ProbeOutcome::Panicked {
                    message: "boom".into(),
                },
            ),
        ];
        let controls: Vec<ControlReport> = controls
            .into_iter()
            .map(|report| {
                let (minted, fabricated) = match report.module {
                    "github_user" => (
                        vec![
                            "username nobodyholds1 (0.82)".to_string(),
                            "url https://github.com/nobodyholds1 (0.70)".to_string(),
                        ],
                        vec![
                            "username nobodyholds1 (0.82)".to_string(),
                            "url https://github.com/nobodyholds1 (0.70)".to_string(),
                        ],
                    ),
                    "gravatar" => (vec!["username nobodyholds1 (0.30)".to_string()], Vec::new()),
                    _ => (Vec::new(), Vec::new()),
                };
                ControlReport {
                    report,
                    minted,
                    fabricated,
                }
            })
            .collect();
        let fabricated: Vec<&str> = fabrications(&controls)
            .iter()
            .map(|c| c.report.module)
            .collect();
        assert_eq!(
            fabricated,
            vec!["github_user"],
            "only a control that fabricated is a fabrication"
        );
        let annotated: Vec<&str> = controls
            .iter()
            .filter(|c| c.is_annotation())
            .map(|c| c.report.module)
            .collect();
        assert_eq!(
            annotated,
            vec!["gravatar"],
            "the target alone below the rung is an annotation, and only that"
        );
    }

    /// The pure verdict on an answer: nothing is honest; the target itself
    /// below the present rung is an annotation, whatever the engine's own
    /// normalisation did to its spelling; the target at the rung asserts it is
    /// real; anything else is fabrication at any rung.
    #[test]
    fn the_target_re_emitted_below_the_present_rung_is_an_annotation_and_anything_else_is_not() {
        use crate::core::confidence;
        use crate::core::entity::{Entity, EntityKind};
        let value = "nobodyholds1@gmail.com";
        let mut answer = crate::core::module::ModuleResult::new();
        assert!(fabricated_names(&answer, TargetKind::Email, value).is_empty());
        answer.push(Entity::new(
            EntityKind::Email,
            value,
            confidence::TENTATIVE,
            "s",
        ));
        assert!(fabricated_names(&answer, TargetKind::Email, value).is_empty());
        answer.push(Entity::new(
            EntityKind::Email,
            " NobodyHolds1@Gmail.com ",
            confidence::SPECULATIVE,
            "s",
        ));
        assert!(fabricated_names(&answer, TargetKind::Email, value).is_empty());
        answer.push(Entity::new(
            EntityKind::Email,
            value,
            SEED_PRESENT_RUNG,
            "s",
        ));
        assert_eq!(
            fabricated_names(&answer, TargetKind::Email, value),
            vec![format!("email {value} (0.50)")]
        );
        let mut stranger = crate::core::module::ModuleResult::new();
        stranger.push(Entity::new(
            EntityKind::Domain,
            "partnerfirm.com",
            confidence::VERY_LOW,
            "s",
        ));
        stranger.push(Entity::new(
            EntityKind::Domain,
            "nobodyholds1.com",
            confidence::VERY_LOW,
            "s",
        ));
        assert_eq!(
            fabricated_names(&stranger, TargetKind::Domain, "nobodyholds1.com"),
            vec!["domain partnerfirm.com (0.25)".to_string()]
        );
        let mut many = crate::core::module::ModuleResult::new();
        for i in 0..(MINTED_NAMED + 3) {
            many.push(Entity::new(
                EntityKind::Domain,
                format!("host{i}.example.com"),
                confidence::LOW_MEDIUM,
                "s",
            ));
        }
        assert_eq!(
            fabricated_names(&many, TargetKind::Domain, "nobodyholds1.com").len(),
            MINTED_NAMED
        );
    }

    /// A module that answers any Username with one entity and records the
    /// handle it was asked about.
    struct Echo {
        asked: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Module for Echo {
        fn name(&self) -> &'static str {
            "echo_probe_fixture"
        }
        fn priority(&self) -> u8 {
            50
        }
        fn consumes(&self) -> Vec<TargetKind> {
            vec![TargetKind::Username]
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Username)
        }
        async fn process(
            &self,
            t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
            self.asked
                .lock()
                .expect("should succeed")
                .push(t.value.clone());
            let mut r = crate::core::module::ModuleResult::new();
            r.push(crate::core::entity::Entity::new(
                crate::core::entity::EntityKind::Username,
                &t.value,
                0.5,
                "probe",
            ));
            Ok(r)
        }
    }

    /// A module answering two controllable kinds is controlled once per kind,
    /// each control asking that kind's value; the wave reports them sorted by
    /// module and then in `CONTROLLED_KINDS` order, and a module with no
    /// control has no row.
    #[tokio::test]
    async fn the_control_wave_asks_every_controllable_kind_a_module_answers_in_order() {
        struct Two;
        #[async_trait::async_trait]
        impl Module for Two {
            fn name(&self) -> &'static str {
                "two_kinds_fixture"
            }
            fn priority(&self) -> u8 {
                50
            }
            fn consumes(&self) -> Vec<TargetKind> {
                vec![TargetKind::Domain, TargetKind::Username]
            }
            fn accepts(&self, t: &Target) -> bool {
                matches!(t.kind, TargetKind::Domain | TargetKind::Username)
            }
            async fn process(
                &self,
                t: &Target,
                _ctx: &ModuleContext,
            ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
                let mut r = crate::core::module::ModuleResult::new();
                if t.kind == TargetKind::Domain {
                    r.push(crate::core::entity::Entity::new(
                        crate::core::entity::EntityKind::Domain,
                        &t.value,
                        0.5,
                        "probe",
                    ));
                }
                Ok(r)
            }
        }
        struct Paid;
        #[async_trait::async_trait]
        impl Module for Paid {
            fn name(&self) -> &'static str {
                "a_paid_fixture"
            }
            fn priority(&self) -> u8 {
                50
            }
            fn cost(&self) -> ModuleCost {
                ModuleCost::Paid
            }
            fn accepts(&self, t: &Target) -> bool {
                matches!(t.kind, TargetKind::Username)
            }
            async fn process(
                &self,
                _t: &Target,
                _ctx: &ModuleContext,
            ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
                Ok(crate::core::module::ModuleResult::new())
            }
        }
        // A module that annotates the mailbox it was asked about — an SMTP
        // rejection, a provider class — below the present rung.
        struct Annotator;
        #[async_trait::async_trait]
        impl Module for Annotator {
            fn name(&self) -> &'static str {
                "annotator_fixture"
            }
            fn priority(&self) -> u8 {
                50
            }
            fn consumes(&self) -> Vec<TargetKind> {
                vec![TargetKind::Email]
            }
            fn accepts(&self, t: &Target) -> bool {
                matches!(t.kind, TargetKind::Email)
            }
            async fn process(
                &self,
                t: &Target,
                _ctx: &ModuleContext,
            ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
                let mut r = crate::core::module::ModuleResult::new();
                r.push(crate::core::entity::Entity::new(
                    crate::core::entity::EntityKind::Email,
                    &t.value,
                    crate::core::confidence::SPECULATIVE,
                    "probe",
                ));
                Ok(r)
            }
        }
        let modules: Vec<std::sync::Arc<dyn Module>> = vec![
            std::sync::Arc::new(Two),
            std::sync::Arc::new(Paid),
            std::sync::Arc::new(Annotator),
            std::sync::Arc::new(Echo {
                asked: std::sync::Mutex::new(Vec::new()),
            }),
        ];
        let controls = probe_controls_of(modules, reqwest::Client::new(), 2).await;
        let rows: Vec<(&str, TargetKind, &str)> = controls
            .iter()
            .map(|c| (c.report.module, c.report.kind, c.report.value))
            .collect();
        let handle = crate::util::probe::sweep_control_handle();
        let domain = control_value(TargetKind::Domain).expect("a domain control");
        let email = control_value(TargetKind::Email).expect("an email control");
        assert_eq!(
            rows,
            vec![
                ("annotator_fixture", TargetKind::Email, email),
                ("echo_probe_fixture", TargetKind::Username, handle),
                ("two_kinds_fixture", TargetKind::Username, handle),
                ("two_kinds_fixture", TargetKind::Domain, domain),
            ],
            "one row per (module, kind), sorted by module then CONTROLLED_KINDS order; the \
             paid module has none"
        );
        // The verdict is per control: the two-kind fixture fabricates for a
        // domain nobody registered and not for a handle nobody holds; the
        // echo re-emits the handle at the present rung; the annotator's
        // mailbox alone, below it, is no fabrication.
        let fabricated: Vec<(&str, TargetKind)> = fabrications(&controls)
            .iter()
            .map(|c| (c.report.module, c.report.kind))
            .collect();
        assert_eq!(
            fabricated,
            vec![
                ("echo_probe_fixture", TargetKind::Username),
                ("two_kinds_fixture", TargetKind::Domain)
            ]
        );
        assert!(controls[0].is_annotation(), "{:?}", controls[0]);
        assert_eq!(controls[0].minted, vec![format!("email {email} (0.30)")]);
        assert!(controls[0].fabricated.is_empty());
        assert_eq!(controls[3].minted, vec![format!("domain {domain} (0.50)")]);
        assert_eq!(controls[3].fabricated, controls[3].minted);
    }

    #[tokio::test]
    async fn a_control_probes_the_module_with_the_handle_nobody_holds_not_its_sample() {
        let http = reqwest::Client::new();
        let m = Echo {
            asked: std::sync::Mutex::new(Vec::new()),
        };
        let controls = control_targets(&m);
        assert_eq!(
            controls,
            vec![(
                TargetKind::Username,
                crate::util::probe::sweep_control_handle()
            )],
            "a Username module has exactly its Username control"
        );
        let (kind, value) = controls[0];
        let control = probe_control(&m, &http, kind, value).await;
        assert_eq!(
            control.report.value,
            crate::util::probe::sweep_control_handle()
        );
        assert!(
            matches!(control.report.outcome, ProbeOutcome::Alive { found: 1 }),
            "{:?}",
            control.report.outcome
        );
        assert_eq!(
            control.minted,
            vec![format!(
                "username {} (0.50)",
                crate::util::probe::sweep_control_handle()
            )],
            "a fabrication names what was minted"
        );
        assert_eq!(
            control.fabricated, control.minted,
            "the target re-emitted at the present rung asserts it is real"
        );
        assert_eq!(fabrications(std::slice::from_ref(&control)).len(), 1);
        let control = control.report;

        // The positive probe of the same module asks about its sample, never
        // the control handle: the two paths are different questions.
        let positive = probe_with_policy(&m, &http, 1, Duration::ZERO)
            .await
            .expect("probeable");
        assert_ne!(positive.value, control.value);
        let asked = m.asked.lock().expect("should succeed").clone();
        assert_eq!(
            asked,
            vec![control.value.to_string(), positive.value.to_string()],
            "the module was asked the control handle, then its sample"
        );
    }
}
