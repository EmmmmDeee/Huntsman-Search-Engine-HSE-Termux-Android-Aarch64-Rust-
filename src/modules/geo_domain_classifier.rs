//! Geo-indicative domain classifier — zero-API geolocation from domain names.
//!
//! Stealer logs and breach data produce hundreds of domain entities. Many of
//! these encode geographic signals: country-code TLDs (`.com.au`, `.co.uk`),
//! country-specific services (commbank.com.au → Australia), and regional
//! platforms (seek.com.au → Australian employment). This module classifies
//! domains against a static table and emits Address entities at coarse
//! (country/city) granularity.
//!
//! No network calls. Runs in < 1ms. Priority 94 so it fires before
//! geocoding modules that would forward-geocode the addresses it emits.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "geo_domain_classifier";

pub struct GeoDomainClassifier;

#[async_trait]
impl Module for GeoDomainClassifier {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Infer country/region from geo-indicative domain names and TLDs"
    }

    fn priority(&self) -> u8 {
        94
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let domain = match target.kind {
            TargetKind::Url => crate::util::url_util::host_from_url(&target.value)
                .map(|h| h.to_lowercase())
                .unwrap_or_default(),
            _ => target.value.trim().to_lowercase(),
        };

        if domain.is_empty() {
            return Ok(result);
        }

        if let Some(geo) = classify_domain(&domain) {
            let mut e = Entity::new(
                EntityKind::Address,
                geo.location,
                geo.confidence,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag("coarse");
            e.tag("domain-inferred");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Domain '{}' indicates {}", domain, geo.location),
                )
                .with_attr("domain", &domain)
                .with_attr("country_code", geo.country_code)
                .with_attr("method", geo.method),
            );
            result.push(e);
        }

        Ok(result)
    }
}

struct GeoClassification {
    location: &'static str,
    country_code: &'static str,
    confidence: f64,
    method: &'static str,
}

fn classify_domain(domain: &str) -> Option<GeoClassification> {
    if let Some(geo) = classify_by_known_service(domain) {
        return Some(geo);
    }
    classify_by_cctld(domain)
}

fn classify_by_known_service(domain: &str) -> Option<GeoClassification> {
    let d = domain.strip_prefix("www.").unwrap_or(domain);

    for &(pattern, location, cc) in GEO_SERVICES {
        if d == pattern
            || d.ends_with(pattern) && d.as_bytes().get(d.len() - pattern.len() - 1) == Some(&b'.')
        {
            return Some(GeoClassification {
                location,
                country_code: cc,
                confidence: 0.60,
                method: "known_service",
            });
        }
    }
    None
}

fn classify_by_cctld(domain: &str) -> Option<GeoClassification> {
    for &(tld, location, cc) in CCTLD_MAP {
        if domain.ends_with(tld) {
            return Some(GeoClassification {
                location,
                country_code: cc,
                confidence: 0.45,
                method: "cctld",
            });
        }
    }
    None
}

const GEO_SERVICES: &[(&str, &str, &str)] = &[
    // Australia
    ("commbank.com.au", "Australia", "AU"),
    ("westpac.com.au", "Australia", "AU"),
    ("anz.com.au", "Australia", "AU"),
    ("nab.com.au", "Australia", "AU"),
    ("realestate.com.au", "Australia", "AU"),
    ("domain.com.au", "Australia", "AU"),
    ("seek.com.au", "Australia", "AU"),
    ("gumtree.com.au", "Australia", "AU"),
    ("afterpay.com", "Australia", "AU"),
    ("zip.co", "Australia", "AU"),
    ("bunnings.com.au", "Australia", "AU"),
    ("woolworths.com.au", "Australia", "AU"),
    ("coles.com.au", "Australia", "AU"),
    ("telstra.com.au", "Australia", "AU"),
    ("optus.com.au", "Australia", "AU"),
    ("centrelink.gov.au", "Australia", "AU"),
    ("myob.com", "Australia", "AU"),
    ("xero.com", "New Zealand", "NZ"),
    // United Kingdom
    ("hsbc.co.uk", "United Kingdom", "GB"),
    ("barclays.co.uk", "United Kingdom", "GB"),
    ("lloydsbank.co.uk", "United Kingdom", "GB"),
    ("natwest.com", "United Kingdom", "GB"),
    ("rightmove.co.uk", "United Kingdom", "GB"),
    ("autotrader.co.uk", "United Kingdom", "GB"),
    ("nhs.uk", "United Kingdom", "GB"),
    ("gov.uk", "United Kingdom", "GB"),
    // United States
    ("chase.com", "United States", "US"),
    ("bankofamerica.com", "United States", "US"),
    ("wellsfargo.com", "United States", "US"),
    ("capitalone.com", "United States", "US"),
    ("zillow.com", "United States", "US"),
    ("realtor.com", "United States", "US"),
    ("craigslist.org", "United States", "US"),
    ("usps.com", "United States", "US"),
    ("irs.gov", "United States", "US"),
    ("dmv.org", "United States", "US"),
    // Germany
    ("sparkasse.de", "Germany", "DE"),
    ("commerzbank.de", "Germany", "DE"),
    ("postbank.de", "Germany", "DE"),
    ("immobilienscout24.de", "Germany", "DE"),
    ("mobile.de", "Germany", "DE"),
    // France
    ("labanquepostale.fr", "France", "FR"),
    ("leboncoin.fr", "France", "FR"),
    ("impots.gouv.fr", "France", "FR"),
    // Canada
    ("td.com", "Canada", "CA"),
    ("rbc.com", "Canada", "CA"),
    ("scotiabank.com", "Canada", "CA"),
    ("kijiji.ca", "Canada", "CA"),
    // Japan
    ("rakuten.co.jp", "Japan", "JP"),
    ("yahoo.co.jp", "Japan", "JP"),
    ("mercari.com", "Japan", "JP"),
    // Brazil
    ("mercadolivre.com.br", "Brazil", "BR"),
    ("itau.com.br", "Brazil", "BR"),
    ("bradesco.com.br", "Brazil", "BR"),
    // India
    ("flipkart.com", "India", "IN"),
    ("paytm.com", "India", "IN"),
    ("hdfc.com", "India", "IN"),
    ("icicibank.com", "India", "IN"),
];

const CCTLD_MAP: &[(&str, &str, &str)] = &[
    (".com.au", "Australia", "AU"),
    (".net.au", "Australia", "AU"),
    (".org.au", "Australia", "AU"),
    (".gov.au", "Australia", "AU"),
    (".edu.au", "Australia", "AU"),
    (".co.uk", "United Kingdom", "GB"),
    (".org.uk", "United Kingdom", "GB"),
    (".ac.uk", "United Kingdom", "GB"),
    (".gov.uk", "United Kingdom", "GB"),
    (".co.nz", "New Zealand", "NZ"),
    (".co.za", "South Africa", "ZA"),
    (".com.br", "Brazil", "BR"),
    (".co.jp", "Japan", "JP"),
    (".co.kr", "South Korea", "KR"),
    (".co.in", "India", "IN"),
    (".com.sg", "Singapore", "SG"),
    (".com.my", "Malaysia", "MY"),
    (".co.id", "Indonesia", "ID"),
    (".com.ph", "Philippines", "PH"),
    (".com.tw", "Taiwan", "TW"),
    (".com.hk", "Hong Kong", "HK"),
    (".com.mx", "Mexico", "MX"),
    (".com.ar", "Argentina", "AR"),
    (".com.co", "Colombia", "CO"),
    (".com.pe", "Peru", "PE"),
    (".com.ng", "Nigeria", "NG"),
    (".com.eg", "Egypt", "EG"),
    (".com.pk", "Pakistan", "PK"),
    (".com.bd", "Bangladesh", "BD"),
    (".com.vn", "Vietnam", "VN"),
    (".com.tr", "Turkey", "TR"),
    (".com.ua", "Ukraine", "UA"),
    // Simple ccTLDs (lower confidence — many are used internationally)
    (".de", "Germany", "DE"),
    (".fr", "France", "FR"),
    (".it", "Italy", "IT"),
    (".es", "Spain", "ES"),
    (".pt", "Portugal", "PT"),
    (".nl", "Netherlands", "NL"),
    (".be", "Belgium", "BE"),
    (".at", "Austria", "AT"),
    (".ch", "Switzerland", "CH"),
    (".se", "Sweden", "SE"),
    (".no", "Norway", "NO"),
    (".dk", "Denmark", "DK"),
    (".fi", "Finland", "FI"),
    (".pl", "Poland", "PL"),
    (".cz", "Czech Republic", "CZ"),
    (".hu", "Hungary", "HU"),
    (".ro", "Romania", "RO"),
    (".bg", "Bulgaria", "BG"),
    (".hr", "Croatia", "HR"),
    (".sk", "Slovakia", "SK"),
    (".ie", "Ireland", "IE"),
    (".ru", "Russia", "RU"),
    (".jp", "Japan", "JP"),
    (".kr", "South Korea", "KR"),
    (".cn", "China", "CN"),
    (".in", "India", "IN"),
    (".za", "South Africa", "ZA"),
    (".ca", "Canada", "CA"),
    (".mx", "Mexico", "MX"),
    (".br", "Brazil", "BR"),
    (".ar", "Argentina", "AR"),
    (".cl", "Chile", "CL"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_australian_service() {
        let geo = classify_domain("commbank.com.au").unwrap();
        assert_eq!(geo.country_code, "AU");
        assert_eq!(geo.method, "known_service");
        assert!((geo.confidence - 0.60).abs() < 1e-9);
    }

    #[test]
    fn classifies_cctld_fallback() {
        let geo = classify_domain("example.com.au").unwrap();
        assert_eq!(geo.country_code, "AU");
        assert_eq!(geo.method, "cctld");
        assert!((geo.confidence - 0.45).abs() < 1e-9);
    }

    #[test]
    fn strips_www() {
        let geo = classify_by_known_service("www.chase.com").unwrap();
        assert_eq!(geo.country_code, "US");
    }

    #[test]
    fn unknown_domain_returns_none() {
        assert!(classify_domain("example.com").is_none());
    }

    #[test]
    fn german_tld() {
        let geo = classify_domain("sparkasse.de").unwrap();
        assert_eq!(geo.country_code, "DE");
        assert_eq!(geo.method, "known_service");
    }

    #[test]
    fn simple_cctld() {
        let geo = classify_domain("random-site.fr").unwrap();
        assert_eq!(geo.country_code, "FR");
        assert_eq!(geo.method, "cctld");
    }

    #[tokio::test]
    async fn module_accepts_domain_and_url() {
        let m = GeoDomainClassifier;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com.au")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com.au")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "test@example.com")));
    }

    #[tokio::test]
    async fn module_produces_address_entity() {
        let m = GeoDomainClassifier;
        let target = Target::new(TargetKind::Domain, "seek.com.au");
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
        assert!(r.entities[0].has_tag("domain-inferred"));
    }
}
