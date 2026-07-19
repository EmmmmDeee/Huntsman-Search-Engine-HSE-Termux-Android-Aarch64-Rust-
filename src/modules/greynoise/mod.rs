//! GreyNoise — free Community API, or the richer keyed `v3/ip` endpoint when
//! `HUNTSMAN_GREYNOISE_KEY` is set.
//!
//! **Free path (always):**
//! `GET https://api.greynoise.io/v3/community/{ip}` — no key required.
//!
//! **Paid path (when `HUNTSMAN_GREYNOISE_KEY` is set):**
//! `GET https://api.greynoise.io/v3/ip/{ip}`, header `key: <KEY>`. This is
//! the exact endpoint `api_key_probe`'s own GreyNoise key-validation probe
//! already calls (its own comment: "the community endpoint works without
//! auth and would cause false positives" for a validity check) — reused here
//! so the operator's configured key is finally used for a real scan, not
//! only for key validation. Both tiers share the `classification`/`name`/
//! `link`/`message` fields; the paid tier additionally confirms `seen`
//! (ever observed, independent of the community `noise`/`riot` flags).
//!
//! Returns whether an IP is observed scanning the internet ("noise"), is
//! part of a known-benign service ("RIOT"), and a classification label
//! (benign / malicious / unknown).
//!
//! Only one path runs per IP (paid supersedes free — same policy as the
//! Shodan module's InternetDB/host-API split).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const KEY_ENV: &str = "HUNTSMAN_GREYNOISE_KEY";

// ── Response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct CommunityResp {
    /// `true` if the IP has been observed scanning the internet.
    #[serde(default)]
    pub noise: bool,
    /// `true` if the IP belongs to a known-benign service (RIOT dataset).
    #[serde(default)]
    pub riot: bool,
    /// `"benign"`, `"malicious"`, or `"unknown"`.
    #[serde(default)]
    pub classification: Option<String>,
    /// Human-readable name (e.g. "Cloudflare", "Shodan.io").
    #[serde(default)]
    pub name: Option<String>,
    /// Link to the GreyNoise visualiser page for this IP.
    #[serde(default)]
    pub link: Option<String>,
    /// Human-readable status message (e.g. "IP not observed scanning the internet").
    #[serde(default)]
    pub message: Option<String>,
}

/// The keyed `v3/ip/{ip}` response. A superset of [`CommunityResp`]'s fields
/// (same classification/name/link/message semantics — confirmed by
/// `api_key_probe`'s own probe of this endpoint), plus `seen` which the
/// community tier doesn't return. `#[serde(default)]` throughout: an
/// unrecognised or renamed field degrades to "not present" rather than a
/// parse failure, so an unexpected upstream field never breaks the scan.
#[derive(Debug, Deserialize)]
pub(crate) struct PaidResp {
    /// `true` if GreyNoise has ever observed this IP (independent of the
    /// community tier's more recent-activity-scoped `noise`/`riot`).
    #[serde(default)]
    pub seen: bool,
    #[serde(default)]
    pub noise: bool,
    #[serde(default)]
    pub riot: bool,
    #[serde(default)]
    pub classification: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub link: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

// ── Module ────────────────────────────────────────────────────────

const SRC: &str = "greynoise";

/// The noise/riot/classification/name/link/message fields both endpoints
/// share (confirmed identical in shape by `api_key_probe`'s own probe of the
/// paid endpoint) — bundled so the shared builder below takes one argument
/// instead of tripping `clippy::too_many_arguments`.
struct Signal<'a> {
    noise: bool,
    riot: bool,
    classification: Option<&'a str>,
    name: Option<&'a str>,
    link: Option<&'a str>,
    message: Option<&'a str>,
    /// An extra positive signal the community tier never sets (the paid
    /// tier's `seen`) — folded into the no-findings gate so a paid record
    /// that's `seen` but otherwise unclassified still surfaces, tagged
    /// `greynoise-seen` by the caller.
    extra_signal: bool,
}

/// Map a decoded GreyNoise record to its entities. **Pure** (no network/IO),
/// so the noise/riot/classification → tag → evidence → operator mapping is
/// unit-testable directly off JSON fixtures. Shared by both the free
/// Community and paid `v3/ip` response types via [`Signal`].
///
/// Gates internally: GreyNoise answers 200 with only a `message` for IPs not in
/// its dataset, so a record with no noise, no RIOT, no classification, and no
/// `extra_signal` yields an empty `Vec` (the caller's prior no-findings
/// short-circuit). When a finding is present the subject `IpAddress` is
/// always emitted; the operator `Organisation` pivot only when `name` is a
/// usable (≥2 chars, non-"unknown") value.
fn build_entities_from_signal(sig: &Signal, ip: &str, scan_id: &str) -> Vec<Entity> {
    // GreyNoise returns 200 with `message: "IP not observed ..."` for IPs not in
    // its dataset. Treat those as no-findings.
    if !sig.noise && !sig.riot && sig.classification.is_none() && !sig.extra_signal {
        return Vec::new();
    }

    let confidence = match sig.classification {
        Some("malicious") => confidence::HIGH_PLUSPLUS,
        Some("benign") => confidence::HIGH_PLUS,
        _ => confidence::MEDIUM_HIGH,
    };

    let mut entity = Entity::new(EntityKind::IpAddress, ip, confidence, scan_id);

    // ── Tags ──────────────────────────────────────────────────
    if sig.noise {
        entity.tag("greynoise-noise");
    }
    if sig.riot {
        entity.tag("greynoise-riot");
    }
    match sig.classification {
        Some("malicious") => {
            entity.tag(crate::core::tags::MALICIOUS);
            entity.tag("greynoise-malicious");
        }
        Some("benign") => entity.tag("greynoise-benign"),
        _ => entity.tag("greynoise-unknown"),
    }

    // ── Evidence ──────────────────────────────────────────────
    let classification = sig.classification.unwrap_or("unknown");
    let summary = format!(
        "GreyNoise: classification={classification}, noise={}, riot={}",
        sig.noise, sig.riot
    );

    let base = Evidence::new(SRC, summary)
        .with_attr("classification", classification)
        .with_attr("noise", sig.noise.to_string())
        .with_attr("riot", sig.riot.to_string());
    let ev = [
        ("name", sig.name),
        ("link", sig.link),
        // GreyNoise's own status text (e.g. the RIOT service description) —
        // surfaced as the API's words, not synthesised from the booleans.
        ("message", sig.message),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.filter(|s| !s.is_empty()).map(|v| (key, v)))
    .fold(base, |ev, (key, v)| ev.with_attr(key, v));
    entity.add_evidence(ev);

    let mut out = vec![entity];

    // The operator/actor name (e.g. "Cloudflare", "Shodan.io") is a real
    // Organisation pivot — surface it, don't leave it in evidence only.
    if let Some(name) = sig
        .name
        .map(str::trim)
        .filter(|n| n.len() >= 2 && !n.eq_ignore_ascii_case("unknown"))
    {
        let mut o = Entity::new(EntityKind::Organisation, name, 0.62, scan_id);
        o.tag("greynoise");
        o.tag("ip-operator");
        o.add_evidence(
            Evidence::new(SRC, format!("Operator/actor of {ip} per GreyNoise")).with_attr("ip", ip),
        );
        out.push(o);
    }

    out
}

/// Community-tier wrapper: no `extra_signal` — the free endpoint's own
/// noise/riot/classification are the only positive signals it has.
fn build_entities(data: &CommunityResp, ip: &str, scan_id: &str) -> Vec<Entity> {
    build_entities_from_signal(
        &Signal {
            noise: data.noise,
            riot: data.riot,
            classification: data.classification.as_deref(),
            name: data.name.as_deref(),
            link: data.link.as_deref(),
            message: data.message.as_deref(),
            extra_signal: false,
        },
        ip,
        scan_id,
    )
}

/// Paid-tier wrapper: `seen` is folded in as the extra positive signal, and
/// (when true) tags the subject `IpAddress` beyond what the shared builder
/// already tags — a paid-only fact the community tier has no equivalent for.
fn build_paid_entities(data: &PaidResp, ip: &str, scan_id: &str) -> Vec<Entity> {
    let mut entities = build_entities_from_signal(
        &Signal {
            noise: data.noise,
            riot: data.riot,
            classification: data.classification.as_deref(),
            name: data.name.as_deref(),
            link: data.link.as_deref(),
            message: data.message.as_deref(),
            extra_signal: data.seen,
        },
        ip,
        scan_id,
    );
    if data.seen
        && let Some(subject) = entities
            .iter_mut()
            .find(|e| e.kind == EntityKind::IpAddress)
    {
        subject.tag("greynoise-seen");
    }
    entities
}

pub struct GreyNoise;

#[async_trait]
impl Module for GreyNoise {
    fn name(&self) -> &'static str {
        "greynoise"
    }

    fn description(&self) -> &'static str {
        "GreyNoise IP reputation — classifies internet noise and RIOT status (paid v3/ip lookup when keyed)"
    }

    fn priority(&self) -> u8 {
        30
    }

    fn cost(&self) -> ModuleCost {
        // Functions free (Community tier) with no key; a configured key
        // upgrades to the paid v3/ip lookup instead — same policy as Shodan.
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // GreyNoise is an internet-noise classification / scan database (T1596.005)
        // and gathers IP address info (T1590.005). It also identifies the
        // ISP/network operator as an Organisation (T1591.002 Business Relationships)
        // — absent from the Infrastructure default.
        &["T1590.005", "T1591.002", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Organisation];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Single network request with no per-request timeout (governed only
        // by the client's 5s connect timeout). On the 3s default the engine
        // killed a slow-but-connected response as a spurious "timeout".
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        if let Some(key) = ctx.key_opt(KEY_ENV) {
            // Paid v3/ip lookup returns the same classification fields plus a
            // confirmed `seen` flag — skip the free path (same policy as the
            // Shodan module's InternetDB/host-API split).
            let url = format!("https://api.greynoise.io/v3/ip/{}", urlencode(ip));
            let resp = ctx
                .http
                .get(&url)
                .header("key", key)
                .send()
                .await
                .map_err(|e| crate::core::error::Error::module(SRC, e.without_url().to_string()))?;
            let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
                return Ok(ModuleResult::new());
            };
            let data: PaidResp = crate::util::http::json_decode(SRC, resp).await?;
            let mut result = ModuleResult::new();
            result.entities = build_paid_entities(&data, ip, &ctx.scan_id);
            return Ok(result);
        }

        let url = format!("https://api.greynoise.io/v3/community/{}", urlencode(ip));

        let Some(data): Option<CommunityResp> = fetch_json_or_404(&ctx.http, SRC, &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(&data, ip, &ctx.scan_id);
        Ok(result)
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
