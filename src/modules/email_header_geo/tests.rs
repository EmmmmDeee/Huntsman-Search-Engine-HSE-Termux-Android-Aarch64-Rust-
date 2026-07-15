use super::EmailHeaderGeo;
use super::infer::{detect_corporate_provider, infer_geo_from_email_domain};
use super::tables::CONSUMER_PROVIDERS;
use crate::core::{
    entity::EntityKind,
    module::{Module, ModuleContext},
    scan::{Target, TargetKind},
};

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
fn y7mail_is_australian() {
    // Yahoo7 (y7mail.com) is a `.com` AU webmail brand, so — like bigpond.com —
    // it needs an explicit REGIONAL_PROVIDERS entry to carry an Australian geo
    // signal, since the `.com.au` TLD rule can't reach it.
    let (provider, region) = detect_corporate_provider("y7mail.com").unwrap();
    assert_eq!(region, "Australia");
    assert!(provider.contains("Yahoo7"));
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
    };
    let r = m.process(&target, &ctx).await.unwrap();
    assert!(!r.is_empty(), "bigpond.com (AU ISP) must geolocate");
    // Every emission is an Address per `produces()` — never some other kind.
    assert!(
        r.entities.iter().all(|e| e.kind == EntityKind::Address),
        "email_header_geo only emits Address entities, got {:?}",
        r.entities.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
    // The provider-inferred coarse-geo Address must be present, carry a non-empty
    // region value, and the geoint/coarse tags that downstream geo-fusion keys on.
    let provider = r
        .entities
        .iter()
        .find(|e| e.has_tag("email-provider-inferred"))
        .expect("bigpond.com must yield a provider-inferred Address");
    assert!(!provider.value.is_empty(), "region value must not be blank");
    assert!(
        provider.has_tag("geoint") && provider.has_tag(crate::core::tags::COARSE),
        "provider-inferred Address must carry geoint+coarse tags, got {:?}",
        provider.tags
    );
    assert!(
        !provider.evidence.is_empty(),
        "provider-inferred Address must carry its inference evidence"
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
    };
    let r = m.process(&target, &ctx).await.unwrap();
    assert!(r.entities.iter().any(|e| e.value == "Australia"));
}
