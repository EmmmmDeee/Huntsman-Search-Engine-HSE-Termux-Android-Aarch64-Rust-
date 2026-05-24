//! abuse.ch URLhaus — known-malicious URL/host check. Free, no key.
//!
//! Endpoint: `POST https://urlhaus-api.abuse.ch/v1/host/`
//! Form body: `host=<domain or ip>`
//!
//! Anonymous queries are subject to abuse.ch's standard rate limit
//! (no key required for low-volume use). The response carries a
//! `url_count` per host plus per-URL threat tags — we surface the
//! aggregate (count, threat families seen, third-party blocklist
//! hits) and never store the individual malicious URLs (they're often
//! still live).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

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

    fn description(&self) -> &'static str {
        "abuse.ch URLhaus malicious-host check for a domain or IP (free); aggregate count + threat families."
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let host = target.value.trim();
        if host.is_empty() {
            return Ok(ModuleResult::new());
        }

        let resp = ctx
            .http
            .post("https://urlhaus-api.abuse.ch/v1/host/")
            .form(&[("host", host)])
            .send()
            .await
            .map_err(|e| Error::module("urlhaus", e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(
                "urlhaus",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: UrlhausResp = resp
            .json()
            .await
            .map_err(|e| Error::module("urlhaus", e.to_string()))?;

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

        let mut entity = target.to_entity(0.90, &ctx.scan_id);
        entity.tag("malicious");
        entity.tag("urlhaus");

        let mut ev = Evidence::new(
            "urlhaus",
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

            // Distinct threat families seen (e.g. "malware_download",
            // "phishing"). Capped at the first 8 to keep the row tidy.
            let mut threats: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
            for u in urls {
                if let Some(t) = u.threat.as_deref() {
                    threats.insert(t);
                    if threats.len() >= 8 {
                        break;
                    }
                }
            }
            if !threats.is_empty() {
                let threat_vec: Vec<&str> = threats.into_iter().collect();
                ev = ev.with_attr("threats", threat_vec.join(","));
            }

            // Aggregate tags across URL entries and surface the top ones.
            let mut tag_counts: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for u in urls {
                if let Some(ref tag_list) = u.tags {
                    for tag in tag_list {
                        let trimmed = tag.trim();
                        if !trimmed.is_empty() {
                            *tag_counts.entry(trimmed.to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }
            if !tag_counts.is_empty() {
                let mut sorted_tags: Vec<(String, usize)> = tag_counts.into_iter().collect();
                sorted_tags.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                let top: Vec<String> = sorted_tags
                    .iter()
                    .take(10)
                    .map(|(tag, count)| format!("{tag}({count})"))
                    .collect();
                ev = ev.with_attr("top_tags", top.join(", "));
            }
        }
        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);
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
}
