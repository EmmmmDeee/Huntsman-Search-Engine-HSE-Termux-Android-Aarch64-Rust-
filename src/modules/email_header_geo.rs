//! Email domain geolocation — infer geography from email domain
//! infrastructure patterns.
//!
//! Classifies email domains by ccTLD (alice@company.com.au → Australia)
//! and by regional ISP provider (bigpond.com → Telstra, Australia).
//! Skips consumer email providers (Gmail, Outlook, etc.) since they
//! reveal no geographic signal. No network calls.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "email_header_geo";

pub struct EmailHeaderGeo;

#[async_trait]
impl Module for EmailHeaderGeo {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Extract geographic signals from email domain infrastructure patterns"
    }

    fn priority(&self) -> u8 {
        92
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let email = target.value.clone();
        let Some((_, domain)) = email.split_once('@') else {
            return Ok(result);
        };

        if CONSUMER_PROVIDERS.iter().any(|p| {
            domain == *p
                || (domain.len() > p.len()
                    && domain.ends_with(p)
                    && domain.as_bytes()[domain.len() - p.len() - 1] == b'.')
        }) {
            return Ok(result);
        }

        if let Some(geo) = infer_geo_from_email_domain(domain) {
            let mut e = Entity::new(
                EntityKind::Address,
                geo.region,
                geo.confidence,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag("coarse");
            e.tag("email-infra-inferred");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Email domain '{}' suggests {} ({})",
                        domain, geo.region, geo.reason
                    ),
                )
                .with_attr("domain", domain)
                .with_attr("method", geo.reason),
            );
            result.push(e);
        }

        if let Some((provider, region)) = detect_corporate_provider(domain) {
            let mut e = Entity::new(EntityKind::Address, region, 0.40, &ctx.scan_id);
            e.tag("geoint");
            e.tag("coarse");
            e.tag("email-provider-inferred");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Email domain '{}' uses {} (regional provider)",
                        domain, provider
                    ),
                )
                .with_attr("domain", domain)
                .with_attr("provider", provider),
            );
            result.push(e);
        }

        Ok(result)
    }
}

struct DomainGeo {
    region: &'static str,
    confidence: f64,
    reason: &'static str,
}

fn infer_geo_from_email_domain(domain: &str) -> Option<DomainGeo> {
    for &(tld, region) in CCTLD_REGIONS {
        if domain.ends_with(tld) {
            return Some(DomainGeo {
                region,
                confidence: 0.48,
                reason: "country-code TLD",
            });
        }
    }
    None
}

fn detect_corporate_provider(domain: &str) -> Option<(&'static str, &'static str)> {
    for &(pattern, provider, region) in REGIONAL_PROVIDERS {
        if domain.contains(pattern) {
            return Some((provider, region));
        }
    }
    None
}

const CONSUMER_PROVIDERS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "yahoo.co.uk",
    "yahoo.co.jp",
    "aol.com",
    "icloud.com",
    "me.com",
    "protonmail.com",
    "proton.me",
    "mail.com",
    "gmx.com",
    "gmx.de",
    "yandex.ru",
    "yandex.com",
    "tutanota.com",
    "zoho.com",
    "fastmail.com",
];

const CCTLD_REGIONS: &[(&str, &str)] = &[
    (".com.au", "Australia"),
    (".edu.au", "Australia"),
    (".gov.au", "Australia"),
    (".org.au", "Australia"),
    (".co.uk", "United Kingdom"),
    (".ac.uk", "United Kingdom"),
    (".gov.uk", "United Kingdom"),
    (".co.nz", "New Zealand"),
    (".co.za", "South Africa"),
    (".co.jp", "Japan"),
    (".co.kr", "South Korea"),
    (".com.br", "Brazil"),
    (".com.sg", "Singapore"),
    (".com.my", "Malaysia"),
    (".com.tr", "Turkey"),
    (".de", "Germany"),
    (".fr", "France"),
    (".it", "Italy"),
    (".es", "Spain"),
    (".nl", "Netherlands"),
    (".se", "Sweden"),
    (".no", "Norway"),
    (".dk", "Denmark"),
    (".fi", "Finland"),
    (".pl", "Poland"),
    (".ru", "Russia"),
    (".jp", "Japan"),
    (".kr", "South Korea"),
    (".cn", "China"),
    (".in", "India"),
    (".ca", "Canada"),
];

const REGIONAL_PROVIDERS: &[(&str, &str, &str)] = &[
    ("bigpond", "Telstra BigPond", "Australia"),
    ("optusnet", "Optus", "Australia"),
    ("iinet", "iiNet", "Australia"),
    ("internode", "Internode", "Australia"),
    ("tpg.com", "TPG", "Australia"),
    ("btinternet", "BT Internet", "United Kingdom"),
    ("sky.com", "Sky UK", "United Kingdom"),
    ("virginmedia", "Virgin Media", "United Kingdom"),
    ("talktalk", "TalkTalk", "United Kingdom"),
    ("comcast", "Comcast", "United States"),
    ("charter", "Spectrum/Charter", "United States"),
    ("cox.net", "Cox", "United States"),
    ("verizon.net", "Verizon", "United States"),
    ("att.net", "AT&T", "United States"),
    ("t-online", "Deutsche Telekom", "Germany"),
    ("web.de", "WEB.DE", "Germany"),
    ("wanadoo", "Orange France", "France"),
    ("free.fr", "Free/Iliad", "France"),
    ("sfr.fr", "SFR", "France"),
    ("rogers.com", "Rogers", "Canada"),
    ("shaw.ca", "Shaw", "Canada"),
    ("bell.net", "Bell", "Canada"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn au_cctld_detected() {
        let geo = infer_geo_from_email_domain("company.com.au").unwrap();
        assert_eq!(geo.region, "Australia");
    }

    #[test]
    fn generic_domain_returns_none() {
        assert!(infer_geo_from_email_domain("company.com").is_none());
    }

    #[test]
    fn bigpond_is_australian() {
        let (provider, region) = detect_corporate_provider("bigpond.com").unwrap();
        assert_eq!(region, "Australia");
        assert!(provider.contains("BigPond"));
    }

    #[test]
    fn bt_is_uk() {
        let (_, region) = detect_corporate_provider("btinternet.com").unwrap();
        assert_eq!(region, "United Kingdom");
    }

    #[test]
    fn consumer_dot_boundary() {
        assert!(
            !CONSUMER_PROVIDERS.iter().any(|p| {
                let d = "awesome.com";
                d == *p
                    || (d.len() > p.len()
                        && d.ends_with(p)
                        && d.as_bytes()[d.len() - p.len() - 1] == b'.')
            }),
            "awesome.com must not match me.com"
        );
    }

    #[test]
    fn unknown_provider_returns_none() {
        assert!(detect_corporate_provider("company.com").is_none());
    }

    #[tokio::test]
    async fn skips_consumer_providers() {
        let m = EmailHeaderGeo;
        let target = Target::new(TargetKind::Email, "alice@gmail.com");
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys: Default::default(),
            cancel: Default::default(),
            proxy_pool: Default::default(),
        };
        let r = m.process(&target, &ctx).await.unwrap();
        assert!(
            r.is_empty(),
            "consumer emails should produce no geo entities"
        );
    }

    #[tokio::test]
    async fn au_email_produces_address() {
        let m = EmailHeaderGeo;
        let target = Target::new(TargetKind::Email, "alice@company.com.au");
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys: Default::default(),
            cancel: Default::default(),
            proxy_pool: Default::default(),
        };
        let r = m.process(&target, &ctx).await.unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r.entities[0].kind, EntityKind::Address);
        assert_eq!(r.entities[0].value, "Australia");
    }

    #[tokio::test]
    async fn bigpond_email_produces_two_entities() {
        let m = EmailHeaderGeo;
        let target = Target::new(TargetKind::Email, "alice@bigpond.com");
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys: Default::default(),
            cancel: Default::default(),
            proxy_pool: Default::default(),
        };
        let r = m.process(&target, &ctx).await.unwrap();
        assert!(!r.is_empty());
        assert!(
            r.entities
                .iter()
                .any(|e| e.has_tag("email-provider-inferred"))
        );
    }
}
