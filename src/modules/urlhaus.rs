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
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "urlhaus";

/// Canonical abuse.ch Auth-Key env var (shared across all abuse.ch services).
const KEY_ENV: &str = "HUNTSMAN_ABUSECH_KEY";
/// Fallback: the ThreatFox key is the same abuse.ch account key.
const KEY_ENV_FALLBACK: &str = "HUNTSMAN_THREATFOX_KEY";

/// Distinct threat families to surface (lexically-first), keeping the row tidy.
const MAX_THREATS: usize = 8;
/// Top URL tags to surface, ranked by frequency.
const MAX_TAGS: usize = 10;

pub struct UrlHaus;

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
/// URL split, the distinct threat families (lexically-first [`MAX_THREATS`]), and
/// the top URL tags by frequency ([`MAX_TAGS`]). The individual malicious URLs
/// are never stored — they are routinely still live. `url_count` is the parsed
/// host-level count; caller guarantees it is non-zero.
fn build_threat_entity(
    kind: EntityKind,
    host: &str,
    body: &UrlhausResp,
    url_count: u64,
    scan_id: &str,
) -> Entity {
    use std::collections::{BTreeMap, BTreeSet};

    let mut entity = Entity::new(kind, host, 0.90, scan_id);
    entity.tag("malicious");
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
        // deterministically the lexically-first MAX_THREATS regardless of the
        // order URLhaus returned the URLs in.
        let threats: BTreeSet<&str> = urls.iter().filter_map(|u| u.threat.as_deref()).collect();
        if !threats.is_empty() {
            ev = ev.with_attr(
                "threats",
                threats
                    .into_iter()
                    .take(MAX_THREATS)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        // Aggregate tags across URL entries; surface the top MAX_TAGS by count
        // (ties broken lexically) as `tag(count)`.
        let mut tag_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for u in urls {
            if let Some(tag_list) = &u.tags {
                for tag in tag_list {
                    let trimmed = tag.trim();
                    if !trimmed.is_empty() {
                        *tag_counts.entry(trimmed).or_insert(0) += 1;
                    }
                }
            }
        }
        if !tag_counts.is_empty() {
            let mut sorted_tags: Vec<(&str, usize)> = tag_counts.into_iter().collect();
            sorted_tags.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
            let top: Vec<String> = sorted_tags
                .iter()
                .take(MAX_TAGS)
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
        "Abuse.ch URLhaus malware URL threat check"
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

    fn max_timeout_ms(&self) -> u64 {
        // Single network POST with no per-request timeout; the 3s default
        // would kill a slow-but-connected response as a spurious "timeout".
        10_000
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::IpAddress];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let host = target.value.trim();
        if host.is_empty() {
            return Ok(ModuleResult::new());
        }

        // abuse.ch requires a free Auth-Key on every request since 2024. Without
        // one, skip cleanly instead of erroring on every host with a 401.
        let Some(key) = ctx
            .key_opt(KEY_ENV)
            .or_else(|| ctx.key_opt(KEY_ENV_FALLBACK))
            .filter(|k| !k.is_empty())
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
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        // A present-but-rejected key (401/403) degrades to a clean skip rather
        // than spamming a module error on every host in the scan.
        if matches!(status.as_u16(), 401 | 403) {
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
    use super::*;

    #[test]
    fn accepts_domain_and_ip() {
        let m = UrlHaus;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn parse_clean_response() {
        let raw = r#"{"query_status":"no_results"}"#;
        let r: UrlhausResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.query_status, "no_results");
        assert!(r.urls.is_none());
    }

    #[test]
    fn parse_hit_response() {
        let raw = r#"{
            "query_status":"ok",
            "urlhaus_reference":"https://urlhaus.abuse.ch/host/example.com/",
            "url_count":"3",
            "firstseen":"2024-01-01 00:00:00 UTC",
            "lastseen":"2024-06-01 00:00:00 UTC",
            "blacklists":{"surbl":"not_listed","spamhaus_dbl":"listed"},
            "urls":[
              {"threat":"malware_download","url_status":"online"},
              {"threat":"phishing","url_status":"offline"}
            ]
        }"#;
        let r: UrlhausResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.query_status, "ok");
        assert_eq!(r.url_count.as_deref(), Some("3"));
        assert_eq!(r.urls.as_ref().unwrap().len(), 2);
    }

    fn resp(json: &str) -> UrlhausResp {
        serde_json::from_str(json).unwrap()
    }

    fn attr<'a>(e: &'a crate::core::entity::Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn threat_entity_aggregates_counts_window_and_blocklists() {
        let body = resp(
            r#"{
              "query_status":"ok",
              "urlhaus_reference":"https://urlhaus.abuse.ch/host/evil.test/",
              "url_count":"3",
              "firstseen":"2024-01-01 00:00:00 UTC",
              "lastseen":"2024-06-01 00:00:00 UTC",
              "blacklists":{"surbl":"not_listed","spamhaus_dbl":"listed"},
              "urls":[
                {"threat":"malware_download","url_status":"online","tags":["elf","mirai"]},
                {"threat":"phishing","url_status":"offline","tags":["elf"]},
                {"threat":"malware_download","url_status":"online","tags":["elf"]}
              ]
            }"#,
        );
        let e = build_threat_entity(EntityKind::Domain, "evil.test", &body, 3, "s");
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("malicious") && e.has_tag("urlhaus"));
        assert!((e.confidence - 0.90).abs() < 1e-9);
        assert_eq!(attr(&e, "url_count"), Some("3"));
        assert_eq!(
            attr(&e, "reference"),
            Some("https://urlhaus.abuse.ch/host/evil.test/")
        );
        assert_eq!(attr(&e, "first_seen"), Some("2024-01-01 00:00:00 UTC"));
        assert_eq!(attr(&e, "surbl"), Some("not_listed"));
        assert_eq!(attr(&e, "spamhaus_dbl"), Some("listed"));
        assert_eq!(attr(&e, "urls_online"), Some("2"));
        assert_eq!(attr(&e, "urls_offline"), Some("1"));
        // Distinct threat families, lexically sorted.
        assert_eq!(attr(&e, "threats"), Some("malware_download,phishing"));
        // top_tags by frequency: elf(3) before mirai(1).
        assert_eq!(attr(&e, "top_tags"), Some("elf(3), mirai(1)"));
    }

    #[test]
    fn threats_are_deterministic_lexical_first_under_cap() {
        // More distinct families than the cap, supplied out of order — the
        // result must be the lexically-first MAX_THREATS regardless of input order.
        let urls: String = ["m", "z", "a", "c", "b", "y", "x", "d", "e", "f"]
            .iter()
            .map(|t| format!(r#"{{"threat":"{t}","url_status":"online"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let body = resp(&format!(r#"{{"query_status":"ok","urls":[{urls}]}}"#));
        let e = build_threat_entity(EntityKind::Domain, "h", &body, 10, "s");
        let threats = attr(&e, "threats").unwrap();
        assert_eq!(threats.split(',').count(), MAX_THREATS);
        assert_eq!(threats, "a,b,c,d,e,f,m,x");
    }

    #[test]
    fn no_urls_array_omits_url_aggregates() {
        // A host hit with a count but no per-URL array (abuse.ch can omit it).
        let e = build_threat_entity(
            EntityKind::IpAddress,
            "1.2.3.4",
            &resp(r#"{"query_status":"ok","url_count":"5"}"#),
            5,
            "s",
        );
        assert_eq!(attr(&e, "url_count"), Some("5"));
        assert_eq!(attr(&e, "urls_online"), None);
        assert_eq!(attr(&e, "threats"), None);
        assert_eq!(attr(&e, "top_tags"), None);
    }
}
