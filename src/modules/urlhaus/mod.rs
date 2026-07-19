//! abuse.ch URLhaus — known-malicious URL/host check.
//!
//! Endpoint: `POST https://urlhaus-api.abuse.ch/v1/host/`
//! Form body: `host=<domain or ip>`
//! Auth:      HTTP header `Auth-Key: <abuse.ch key>`
//!
//! As of 2024 abuse.ch deprecated anonymous access — every query now needs a
//! free Auth-Key (register once at <https://auth.abuse.ch>). The SAME key
//! powers URLhaus, ThreatFox and MalwareBazaar, so this module reads
//! `HUNTSMAN_ABUSECH_KEY` and falls back to `HUNTSMAN_THREATFOX_KEY`. Without a
//! key it skips cleanly (no doomed 401s). The response carries a `url_count`
//! per host plus per-URL threat tags — we surface the aggregate (count, threat
//! families seen, third-party blocklist hits) and never store the individual
//! malicious URLs (they're often still live).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "urlhaus";

/// Canonical abuse.ch Auth-Key env var (shared across all abuse.ch services).
const KEY_ENV: &str = "HUNTSMAN_ABUSECH_KEY";
/// Fallback: the ThreatFox key is the same abuse.ch account key.
const KEY_ENV_FALLBACK: &str = "HUNTSMAN_THREATFOX_KEY";

pub struct UrlHaus;

/// Resolve which abuse.ch key to use and which `ServiceDef` a rejection of it
/// should be reported against: the dedicated `urlhaus` key if set, else the
/// `threatfox` fallback (same abuse.ch account, different pool entry) — see
/// the module doc comment. Pure and total over its inputs so the precedence
/// and empty-string handling are unit-testable without a live HTTP round-trip.
fn resolve_key<'a>(
    primary: Option<&'a str>,
    fallback: Option<&'a str>,
) -> Option<(&'a str, &'static str)> {
    primary
        .filter(|k| !k.is_empty())
        .map(|k| (k, "urlhaus"))
        .or_else(|| fallback.filter(|k| !k.is_empty()).map(|k| (k, "threatfox")))
}

#[derive(Deserialize)]
struct UrlhausResp {
    query_status: String,
    #[serde(default)]
    urlhaus_reference: Option<String>,
    #[serde(default)]
    url_count: Option<String>,
    #[serde(default)]
    blacklists: Option<Blacklists>,
    #[serde(default)]
    urls: Option<Vec<UrlEntry>>,
    #[serde(default)]
    firstseen: Option<String>,
    #[serde(default)]
    lastseen: Option<String>,
}

#[derive(Deserialize)]
struct Blacklists {
    #[serde(default)]
    surbl: Option<String>,
    #[serde(default)]
    spamhaus_dbl: Option<String>,
}

#[derive(Deserialize)]
struct UrlEntry {
    #[serde(default)]
    threat: Option<String>,
    #[serde(default)]
    url_status: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

/// Build the malicious-host entity from an URLhaus `host` response. **Pure** (no
/// network/IO): records the malicious-URL count, the urlhaus reference, the
/// first/last-seen window, the third-party blocklist verdicts, the online/offline
/// URL split, every distinct threat family (lexically sorted), and every URL tag
/// ordered by frequency. The individual malicious URLs are never stored — they
/// are routinely still live. `url_count` is the parsed host-level count; caller
/// guarantees it is non-zero.
fn build_threat_entity(
    kind: EntityKind,
    host: &str,
    body: &UrlhausResp,
    url_count: u64,
    scan_id: &str,
) -> Entity {
    use std::collections::{BTreeMap, BTreeSet};

    let mut entity = Entity::new(kind, host, confidence::VERY_HIGH_PLUS, scan_id);
    entity.tag(crate::core::tags::MALICIOUS);
    entity.tag("urlhaus");

    let mut ev = Evidence::new(
        SRC,
        format!("URLhaus reports {url_count} malicious URL(s) hosted on {host}"),
    )
    .with_attr("url_count", url_count.to_string());

    if let Some(r) = body.urlhaus_reference.as_deref() {
        ev = ev.with_attr("reference", r);
    }
    if let Some(f) = body.firstseen.as_deref() {
        ev = ev.with_attr("first_seen", f);
    }
    if let Some(l) = body.lastseen.as_deref() {
        ev = ev.with_attr("last_seen", l);
    }
    if let Some(bl) = &body.blacklists {
        if let Some(s) = bl.surbl.as_deref() {
            ev = ev.with_attr("surbl", s);
        }
        if let Some(s) = bl.spamhaus_dbl.as_deref() {
            ev = ev.with_attr("spamhaus_dbl", s);
        }
    }
    if let Some(urls) = body.urls.as_ref() {
        let online = urls
            .iter()
            .filter(|u| u.url_status.as_deref() == Some("online"))
            .count();
        ev = ev.with_attr("urls_online", online.to_string());

        let offline = urls
            .iter()
            .filter(|u| u.url_status.as_deref() == Some("offline"))
            .count();
        ev = ev.with_attr("urls_offline", offline.to_string());

        // Distinct threat families (e.g. "malware_download", "phishing"),
        // deterministically lexically sorted (BTreeSet). Full-fidelity policy:
        // every distinct family is surfaced, never a capped subset.
        let threats: BTreeSet<&str> = urls.iter().filter_map(|u| u.threat.as_deref()).collect();
        if !threats.is_empty() {
            ev = ev.with_attr("threats", threats.into_iter().collect::<Vec<_>>().join(","));
        }

        // Aggregate tags across URL entries; surface ALL tags ordered by count
        // (ties broken lexically) as `tag(count)` — full-fidelity, no top-N cap.
        let mut tag_counts: BTreeMap<&str, usize> = BTreeMap::new();
        urls.iter()
            .filter_map(|u| u.tags.as_ref())
            .flatten()
            .map(|tag| tag.trim())
            .filter(|trimmed| !trimmed.is_empty())
            .for_each(|trimmed| *tag_counts.entry(trimmed).or_insert(0) += 1);
        if !tag_counts.is_empty() {
            let mut sorted_tags: Vec<(&str, usize)> = tag_counts.into_iter().collect();
            sorted_tags.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
            let top: Vec<String> = sorted_tags
                .iter()
                .map(|(tag, count)| format!("{tag}({count})"))
                .collect();
            ev = ev.with_attr("top_tags", top.join(", "));
        }
    }
    entity.add_evidence(ev);
    entity
}

#[async_trait]
impl Module for UrlHaus {
    fn name(&self) -> &'static str {
        "urlhaus"
    }

    fn description(&self) -> &'static str {
        "abuse.ch URLhaus recon — probes a URL against the malware-URL threat corpus"
    }

    fn priority(&self) -> u8 {
        // High-signal threat intel — runs early so other modules see
        // the "malicious" tag in correlations they emit.
        110
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Threat
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::IpAddress];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Single network POST with no per-request timeout; the 3s default
        // would kill a slow-but-connected response as a spurious "timeout".
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let host = target.value.trim();
        if host.is_empty() {
            return Ok(ModuleResult::new());
        }

        // abuse.ch requires a free Auth-Key on every request since 2024. Without
        // one, skip cleanly instead of erroring on every host with a 401.
        let Some((key, key_service)) =
            resolve_key(ctx.key_opt(KEY_ENV), ctx.key_opt(KEY_ENV_FALLBACK))
        else {
            tracing::debug!(
                target: "module.urlhaus",
                "skipped — set HUNTSMAN_ABUSECH_KEY (free at auth.abuse.ch) to enable"
            );
            return Ok(ModuleResult::new());
        };

        let resp = ctx
            .http
            .post("https://urlhaus-api.abuse.ch/v1/host/")
            .header("Auth-Key", key)
            .form(&[("host", host)])
            .send_tagged(SRC)
            .await?;

        let status = resp.status();
        // A present-but-rejected key (401/403) degrades to a clean skip rather
        // than spamming a module error on every host in the scan — but the
        // key pool must still learn about it, or a dead/rotated-away key
        // silently degrades every host forever with no operator-visible
        // signal and no chance to rotate to another pooled key.
        if matches!(status.as_u16(), 401 | 403) {
            crate::util::http::note_keyed_error(status.as_u16(), key_service, key, ctx);
            tracing::warn!(target: "module.urlhaus", %status, "abuse.ch rejected the Auth-Key");
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(crate::util::http::http_status_error(SRC, resp).await);
        }

        let body: UrlhausResp = crate::util::http::json_decode(SRC, resp).await?;

        // "no_results" is the common case for clean hosts — not an error.
        if body.query_status != "ok" {
            return Ok(ModuleResult::new());
        }

        let url_count: u64 = body
            .url_count
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if url_count == 0 {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        result.push(build_threat_entity(
            target.kind.to_entity_kind(),
            host,
            &body,
            url_count,
            &ctx.scan_id,
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
