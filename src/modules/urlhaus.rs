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
        110
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

        ev = ev
            .with_opt_attr("reference", body.urlhaus_reference.as_deref())
            .with_opt_attr("first_seen", body.firstseen.as_deref())
            .with_opt_attr("last_seen", body.lastseen.as_deref());
        if let Some(bl) = &body.blacklists {
            ev = ev
                .with_opt_attr("surbl", bl.surbl.as_deref())
                .with_opt_attr("spamhaus_dbl", bl.spamhaus_dbl.as_deref());
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
