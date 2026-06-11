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
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
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
        // DNS labels are case-insensitive (RFC 4343); fold the domain so the
        // lowercase ccTLD / regional-provider tables still match a mixed-case
        // address such as `User@Bigpond.COM.AU` instead of missing entirely.
        let domain = domain.to_ascii_lowercase();
        let domain = domain.as_str();

        if CONSUMER_PROVIDERS
            .iter()
            .any(|p| crate::util::domains::is_or_subdomain_of(domain, p))
        {
            return Ok(result);
        }

        if let Some(geo) = infer_geo_from_email_domain(domain) {
            let mut e = Entity::new(
                EntityKind::Address,
                geo.region,
                geo.confidence,
                &ctx.scan_id,
            );
            e.tag(crate::core::tags::GEOINT);
            e.tag(crate::core::tags::COARSE);
            e.tag("email-infra-inferred");
            if let Some(tag) = geo.extra_tag {
                e.tag(tag);
                e.tag(crate::core::tags::AU_RELEVANT);
            }
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
            e.tag(crate::core::tags::GEOINT);
            e.tag(crate::core::tags::COARSE);
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
    /// Optional AU-specific tag (`au-state:QLD`, `au-lga:logan-city`, etc.)
    /// applied to the entity in addition to the standard geoint/coarse tags.
    extra_tag: Option<&'static str>,
}

fn infer_geo_from_email_domain(domain: &str) -> Option<DomainGeo> {
    // AU-specific subdomain patterns take priority (more precise than raw ccTLD).
    for &(pattern, region, extra_tag) in AU_SPECIFIC_DOMAINS {
        if crate::util::domains::is_or_subdomain_of(domain, pattern) {
            return Some(DomainGeo {
                region,
                confidence: 0.62,
                reason: "au-specific-domain",
                extra_tag: Some(extra_tag),
            });
        }
    }
    for &(tld, region) in CCTLD_REGIONS {
        if domain.ends_with(tld) {
            // A `.com.au` / `.gov.au` / `.edu.au` address is AU-relevant.
            let extra_tag = if tld.ends_with(".au") {
                Some(crate::core::tags::AU_RELEVANT)
            } else {
                None
            };
            return Some(DomainGeo {
                region,
                confidence: 0.48,
                reason: "country-code TLD",
                extra_tag,
            });
        }
    }
    None
}

fn detect_corporate_provider(domain: &str) -> Option<(&'static str, &'static str)> {
    for &(pattern, provider, region) in REGIONAL_PROVIDERS {
        if domain_has_label_prefix(domain, pattern) {
            return Some((provider, region));
        }
    }
    None
}

/// AU-specific organisation domain patterns that carry finer-grained geographic
/// signal than a bare `.com.au` ccTLD match. Ordered most-specific first so
/// `logan.qld.gov.au` matches before `qld.gov.au`.
// extra_tag values are the canonical `crate::core::tags` constants so a matched
// domain emits the exact tag the GEOINT correlator matches on — no drift.
const AU_SPECIFIC_DOMAINS: &[(&str, &str, &str)] = &[
    // Logan City Council — strongest LGA signal.
    (
        "logan.qld.gov.au",
        "Logan City, Queensland, Australia",
        crate::core::tags::AU_LGA_LOGAN_CITY,
    ),
    (
        "logancity.qld.gov.au",
        "Logan City, Queensland, Australia",
        crate::core::tags::AU_LGA_LOGAN_CITY,
    ),
    // SE QLD councils.
    (
        "brisbane.qld.gov.au",
        "Brisbane, Queensland, Australia",
        crate::core::tags::AU_SE_QLD,
    ),
    (
        "ipswich.qld.gov.au",
        "Ipswich, Queensland, Australia",
        crate::core::tags::AU_SE_QLD,
    ),
    (
        "goldcoast.qld.gov.au",
        "Gold Coast, Queensland, Australia",
        crate::core::tags::AU_SE_QLD,
    ),
    // QLD state government (any *.qld.gov.au not matched above).
    (
        "qld.gov.au",
        "Queensland, Australia",
        crate::core::tags::AU_STATE_QLD,
    ),
    // QLD Education department.
    (
        "eq.edu.au",
        "Queensland, Australia",
        crate::core::tags::AU_STATE_QLD,
    ),
    (
        "education.qld.gov.au",
        "Queensland, Australia",
        crate::core::tags::AU_STATE_QLD,
    ),
    // QLD Health.
    (
        "health.qld.gov.au",
        "Queensland, Australia",
        crate::core::tags::AU_STATE_QLD,
    ),
];

/// True if `pattern` (a provider brand token such as `bigpond` or `tpg.com`)
/// begins a host label in `domain` — i.e. it occurs at the start, or right after
/// a label separator. Unlike the suffix-anchored `CONSUMER_PROVIDERS` check, the
/// regional brand tokens carry no fixed TLD (`bigpond` → `bigpond.com.au`,
/// `bigpond.net.au`), so the match stays substring-based but must start a label.
///
/// The left boundary is the fix for the mid-label false positives a plain
/// `contains` produced: `campbell.net` does not match `bell.net`, `platt.net`
/// does not match `att.net`, while `bigpond.com.au` and `mail.bigpond.com`
/// (subdomain) still match.
fn domain_has_label_prefix(domain: &str, pattern: &str) -> bool {
    let h = domain.as_bytes();
    let mut from = 0;
    while let Some(rel) = domain[from..].find(pattern) {
        let at = from + rel;
        // Start of string, or the preceding char cannot be part of a label
        // (`.`/`/`/`@`/… qualify; an alphanumeric or `-` means we are mid-label).
        let starts_label = at == 0 || {
            let p = h[at - 1];
            !(p.is_ascii_alphanumeric() || p == b'-')
        };
        if starts_label {
            return true;
        }
        from = at + 1;
    }
    false
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
    // Australia — major ISPs / carriers
    ("bigpond", "Telstra BigPond", "Australia"),
    ("optusnet", "Optus", "Australia"),
    ("iinet", "iiNet", "Australia"),
    ("internode", "Internode", "Australia"),
    ("tpg.com", "TPG", "Australia"),
    ("aussiebroadband", "Aussie Broadband", "Australia"),
    ("exetel", "Exetel", "Australia"),
    ("dodo.com", "Dodo", "Australia"),
    ("spintel", "Spintel", "Australia"),
    ("belong.com", "Belong (Telstra)", "Australia"),
    ("westnet", "WestNet (iiNet)", "Australia"),
    ("aapt.net", "AAPT", "Australia"),
    ("primus.com", "Primus", "Australia"),
    ("chariot.net", "Chariot", "Australia"),
    ("netspace.net", "Netspace", "Australia"),
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
        assert_eq!(geo.extra_tag, Some("au-relevant"));
    }

    #[test]
    fn logan_city_council_domain_detected() {
        let geo = infer_geo_from_email_domain("staff.logan.qld.gov.au").unwrap();
        assert!(geo.region.contains("Logan City"));
        assert_eq!(geo.extra_tag, Some("au-lga:logan-city"));
        assert!(geo.confidence >= 0.60);
    }

    #[test]
    fn qld_state_domain_detected() {
        let geo = infer_geo_from_email_domain("employee.qld.gov.au").unwrap();
        assert_eq!(geo.extra_tag, Some("au-state:QLD"));
        assert!(geo.region.contains("Queensland"));
    }

    #[test]
    fn se_qld_council_domain_detected() {
        let geo = infer_geo_from_email_domain("staff.brisbane.qld.gov.au").unwrap();
        assert_eq!(geo.extra_tag, Some("au-se-qld"));
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

    #[test]
    fn corporate_provider_matches_at_label_boundary_only() {
        // Brand token at the start of the domain, and across the provider's
        // several TLDs, still matches.
        assert_eq!(
            detect_corporate_provider("bigpond.com.au").map(|(_, r)| r),
            Some("Australia")
        );
        assert_eq!(
            detect_corporate_provider("bigpond.net.au").map(|(_, r)| r),
            Some("Australia")
        );
        // Subdomain (token after a `.`) matches.
        assert_eq!(
            detect_corporate_provider("mail.bigpond.com").map(|(_, r)| r),
            Some("Australia")
        );
        assert_eq!(
            detect_corporate_provider("tpg.com.au").map(|(_, r)| r),
            Some("Australia")
        );
        // Mid-label fragments must NOT match (the false positives this fixes):
        // these are unrelated domains that merely contain a provider token.
        for fp in [
            "campbell.net",  // contains bell.net
            "platt.net",     // contains att.net
            "foxcox.net",    // contains cox.net
            "brisksky.com",  // contains sky.com
            "myverizon.net", // contains verizon.net
        ] {
            assert!(
                detect_corporate_provider(fp).is_none(),
                "{fp} must not match a provider mid-label"
            );
        }
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

    #[tokio::test]
    async fn mixed_case_domain_is_detected() {
        // DNS is case-insensitive; a mixed-case address must geolocate the same
        // as its lowercase form (the ccTLD table is lowercase, so without folding
        // this produced nothing).
        let m = EmailHeaderGeo;
        let target = Target::new(TargetKind::Email, "Alice@Company.COM.AU");
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
        assert!(r.entities.iter().any(|e| e.value == "Australia"));
    }
}
