//! SEON email and phone enrichment — cross-platform presence detection.
//!
//! **Email path:**
//! `POST https://api.seon.io/SeonRestService/email-api/v3`
//! Resolves email domain registration and checks presence across 250+ platforms.
//!
//! **Phone path:**
//! `POST https://api.seon.io/SeonRestService/phone-api/v2`
//! Resolves carrier details, HLR network lookup, and cross-platform presence.
//!
//! Auth: `X-API-KEY` header. Key-gated (`HUNTSMAN_SEON_KEY`).
//!
//! Every registered platform that reports a profile URL becomes a `Url` entity
//! (a direct lead), not just a name in a CSV. The two response → entity mappings
//! live in the pure [`build_email_entities`] / [`build_phone_entities`] so they
//! are unit-tested without a live API; the `*_lookup` methods own only transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const KEY_ENV: &str = "HUNTSMAN_SEON_KEY";
const SRC: &str = "seon";

/// A fraud score at/above this (0–100) flags the identity high-risk.
const HIGH_RISK_SCORE: f64 = 80.0;
/// Email platforms whose self-reported display name is worth a `Person` lead.
const PERSON_PLATFORMS: &[&str] = &["facebook", "twitter", "linkedin", "github"];

pub struct Seon;

#[derive(Deserialize)]
struct SeonEmailResp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    data: Option<SeonEmailData>,
}

#[derive(Deserialize)]
struct SeonEmailData {
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    deliverable: Option<bool>,
    #[serde(default)]
    domain_details: Option<DomainDetails>,
    #[serde(default)]
    account_details: Option<AccountDetails>,
}

#[derive(Deserialize)]
struct DomainDetails {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    registered: Option<bool>,
    #[serde(default)]
    disposable: Option<bool>,
    #[serde(default)]
    free: Option<bool>,
    #[serde(default)]
    custom: Option<bool>,
}

#[derive(Deserialize)]
struct AccountDetails {
    #[serde(default)]
    facebook: Option<AccountPresence>,
    #[serde(default)]
    twitter: Option<AccountPresence>,
    #[serde(default)]
    linkedin: Option<AccountPresence>,
    #[serde(default)]
    instagram: Option<AccountPresence>,
    #[serde(default)]
    github: Option<AccountPresence>,
    #[serde(default)]
    google: Option<AccountPresence>,
    #[serde(default)]
    apple: Option<AccountPresence>,
    #[serde(default)]
    microsoft: Option<AccountPresence>,
    #[serde(default)]
    spotify: Option<AccountPresence>,
    #[serde(default)]
    skype: Option<AccountPresence>,
}

#[derive(Deserialize)]
struct AccountPresence {
    #[serde(default)]
    registered: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize)]
struct SeonPhoneResp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    data: Option<SeonPhoneData>,
}

#[derive(Deserialize)]
struct SeonPhoneData {
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    carrier: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default, rename = "type")]
    line_type: Option<String>,
    #[serde(default)]
    account_details: Option<PhoneAccountDetails>,
}

#[derive(Deserialize)]
struct PhoneAccountDetails {
    #[serde(default)]
    whatsapp: Option<AccountPresence>,
    #[serde(default)]
    viber: Option<AccountPresence>,
    #[serde(default)]
    telegram: Option<AccountPresence>,
}

use crate::util::str_util::nonempty;

/// The platforms a presence map reports as `registered: true`, in declared order.
fn registered_accounts<'a>(
    pairs: &[(&'static str, &'a Option<AccountPresence>)],
) -> Vec<(&'static str, &'a AccountPresence)> {
    pairs
        .iter()
        .filter_map(|(name, opt)| {
            opt.as_ref()
                .filter(|p| p.registered == Some(true))
                .map(|p| (*name, p))
        })
        .collect()
}

/// A `Url` entity for a social/messaging profile discovered via SEON — the lead
/// the old code dropped on the floor.
fn profile_url_entity(platform: &str, url: &str, who: &str, scan_id: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Url, url, 0.70, scan_id);
    e.tag("seon");
    e.tag("social-profile");
    e.tag(format!("platform:{platform}"));
    e.add_evidence(Evidence::new(
        SRC,
        format!("{platform} profile via SEON for {who}"),
    ));
    e
}

/// Build entities from a SEON **email** enrichment: the enriched email itself,
/// a `Person` lead from the best-named platform, and a `Url` for every platform
/// that reported a profile link. Pure — unit-tested without a live API.
fn build_email_entities(target: &Target, data: &SeonEmailData, scan_id: &str) -> Vec<Entity> {
    let email = target.value.trim();
    let mut out = Vec::new();
    let mut entity = target.to_entity(0.88, scan_id);
    entity.tag("seon");

    let mut ev = Evidence::new(SRC, format!("SEON email enrichment for {email}"));
    if let Some(score) = data.score {
        ev = ev.with_attr("fraud_score", format!("{score:.1}"));
        if score >= HIGH_RISK_SCORE {
            entity.tag("high-risk");
        }
    }
    if let Some(d) = data.deliverable {
        ev = ev.with_attr("deliverable", d.to_string());
    }
    if let Some(dd) = &data.domain_details {
        if let Some(d) = nonempty(&dd.domain) {
            ev = ev.with_attr("domain", d);
        }
        if dd.registered == Some(true) {
            ev = ev.with_attr("domain_registered", "true");
        }
        if dd.custom == Some(true) {
            ev = ev.with_attr("custom_domain", "true");
            entity.tag("custom-domain");
        }
        if dd.disposable == Some(true) {
            entity.tag("disposable");
            ev = ev.with_attr("disposable", "true");
        }
        if dd.free == Some(true) {
            entity.tag("freemail");
            ev = ev.with_attr("freemail", "true");
        }
    }

    let registered = data
        .account_details
        .as_ref()
        .map(|a| {
            registered_accounts(&[
                ("facebook", &a.facebook),
                ("twitter", &a.twitter),
                ("linkedin", &a.linkedin),
                ("instagram", &a.instagram),
                ("github", &a.github),
                ("google", &a.google),
                ("apple", &a.apple),
                ("microsoft", &a.microsoft),
                ("spotify", &a.spotify),
                ("skype", &a.skype),
            ])
        })
        .unwrap_or_default();

    if !registered.is_empty() {
        let names: Vec<&str> = registered.iter().map(|(n, _)| *n).collect();
        ev = ev.with_attr("platforms_registered", names.join(","));
        ev = ev.with_attr("platform_count", names.len().to_string());
    }
    entity.add_evidence(ev);
    out.push(entity);

    // One Person from the best-named identity platform.
    if let Some((platform, name)) = registered.iter().find_map(|(plat, p)| {
        nonempty(&p.name)
            .filter(|n| PERSON_PLATFORMS.contains(plat) && n.len() >= 3 && n.contains(' '))
            .map(|n| (*plat, n))
    }) {
        let mut pe = Entity::new(EntityKind::Person, name, 0.65, scan_id);
        pe.tag("seon");
        pe.tag(format!("platform:{platform}"));
        pe.add_evidence(Evidence::new(
            SRC,
            format!("Name from {platform} via SEON for {email}"),
        ));
        out.push(pe);
    }

    // A Url for every platform that reported a profile link.
    out.extend(registered.iter().filter_map(|(platform, p)| {
        nonempty(&p.url).map(|url| profile_url_entity(platform, url, email, scan_id))
    }));

    out
}

/// Build entities from a SEON **phone** enrichment: the enriched phone (carrier,
/// line type, geo) plus a `Url` for any messaging-app profile link. Pure.
fn build_phone_entities(target: &Target, data: &SeonPhoneData, scan_id: &str) -> Vec<Entity> {
    let phone = target.value.trim();
    let mut out = Vec::new();
    let mut entity = target.to_entity(0.88, scan_id);
    entity.tag("seon");

    let mut ev = Evidence::new(SRC, format!("SEON phone enrichment for {phone}"));
    if let Some(score) = data.score {
        ev = ev.with_attr("fraud_score", format!("{score:.1}"));
        if score >= HIGH_RISK_SCORE {
            entity.tag("high-risk");
        }
    }
    if let Some(v) = data.valid {
        ev = ev.with_attr("valid", v.to_string());
    }
    if let Some(c) = nonempty(&data.carrier) {
        ev = ev.with_attr("carrier", c);
    }
    if let Some(c) = nonempty(&data.country) {
        ev = ev.with_attr("country", c);
    }
    if let Some(cc) = nonempty(&data.country_code) {
        ev = ev.with_attr("country_code", cc);
        entity.tag(format!("country:{}", cc.to_uppercase()));
    }
    if let Some(lt) = nonempty(&data.line_type) {
        ev = ev.with_attr("line_type", lt);
        entity.tag(format!("line:{lt}"));
    }

    let registered = data
        .account_details
        .as_ref()
        .map(|a| {
            registered_accounts(&[
                ("whatsapp", &a.whatsapp),
                ("viber", &a.viber),
                ("telegram", &a.telegram),
            ])
        })
        .unwrap_or_default();
    if !registered.is_empty() {
        let names: Vec<&str> = registered.iter().map(|(n, _)| *n).collect();
        ev = ev.with_attr("messaging_platforms", names.join(","));
    }
    entity.add_evidence(ev);
    out.push(entity);

    out.extend(registered.iter().filter_map(|(platform, p)| {
        nonempty(&p.url).map(|url| profile_url_entity(platform, url, phone, scan_id))
    }));

    out
}

#[async_trait]
impl Module for Seon {
    fn name(&self) -> &'static str {
        "seon"
    }
    fn description(&self) -> &'static str {
        "SEON email/phone enrichment — cross-platform presence across 250+ services"
    }
    fn priority(&self) -> u8 {
        95
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Phone)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // SEON detects an identity's presence across 250+ social/messaging
        // platforms (emitting profile Urls), so beyond the People default
        // (T1589.003 Employee Names + T1591.004 Identify Roles) it is Search
        // Open Websites/Domains: Social Media (T1593.001). Superset of the
        // default — coverage cannot regress.
        &["T1589.003", "T1591.004", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person, EntityKind::Url];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        match target.kind {
            TargetKind::Email => self.email_lookup(target, key, ctx).await,
            TargetKind::Phone => self.phone_lookup(target, key, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

impl Seon {
    async fn email_lookup(
        &self,
        target: &Target,
        key: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let email = target.value.trim();
        if !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let resp = ctx
            .http
            .post("https://api.seon.io/SeonRestService/email-api/v3")
            .header("X-API-KEY", key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "email": email }))
            .send_tagged(SRC)
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            crate::util::http::note_keyed_error(code, SRC, key, ctx);
            return Err(crate::util::http::http_status_error(SRC, resp).await);
        }

        let body: SeonEmailResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| Error::module(SRC, e))?;

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.extend(build_email_entities(target, &data, &ctx.scan_id));
        Ok(result)
    }

    async fn phone_lookup(
        &self,
        target: &Target,
        key: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let phone = target.value.trim();
        if phone.is_empty() {
            return Ok(ModuleResult::new());
        }

        let resp = ctx
            .http
            .post("https://api.seon.io/SeonRestService/phone-api/v2")
            .header("X-API-KEY", key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "phone": phone }))
            .send_tagged(SRC)
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            crate::util::http::note_keyed_error(code, SRC, key, ctx);
            return Err(crate::util::http::http_status_error(SRC, resp).await);
        }

        let body: SeonPhoneResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| Error::module(SRC, e))?;

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.extend(build_phone_entities(target, &data, &ctx.scan_id));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Module surface ──────────────────────────────────────────────────
    #[test]
    fn accepts_email_and_phone() {
        let m = Seon;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+1234")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(Seon.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Seon.name(), "seon");
        assert_eq!(Seon.priority(), 95);
        assert_eq!(Seon.max_timeout_ms(), 8_000);
        assert!(!Seon.description().is_empty());
        // produces() advertises the Url leads it now emits.
        assert!(Seon.produces().contains(&EntityKind::Url));
        assert!(Seon.produces().contains(&EntityKind::Person));
    }

    #[test]
    fn parse_email_response() {
        let raw = r#"{"success":true,"data":{"score":12.5,"deliverable":true,
            "domain_details":{"domain":"example.com","registered":true,"disposable":false,"free":false,"custom":true},
            "account_details":{"facebook":{"registered":true,"name":"John Doe"},"twitter":{"registered":false},"github":{"registered":true}}}}"#;
        let r: SeonEmailResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.success, Some(true));
        let data = r.data.unwrap();
        assert!((data.score.unwrap() - 12.5).abs() < 0.01);
        assert_eq!(data.domain_details.unwrap().disposable, Some(false));
    }

    // ── Core: email entity building (incl. the recovered profile URLs) ──
    fn email(json: &str) -> Vec<Entity> {
        let r: SeonEmailResp = serde_json::from_str(json).unwrap();
        build_email_entities(
            &Target::new(TargetKind::Email, "jane@acme.com"),
            &r.data.unwrap(),
            "s",
        )
    }

    #[test]
    fn email_emits_url_entities_for_each_profile_link() {
        let es = email(
            r#"{"data":{
                "domain_details":{"domain":"acme.com","registered":true,"custom":true,"free":false},
                "account_details":{
                    "facebook":{"registered":true,"name":"Jane Doe","url":"https://facebook.com/jane"},
                    "github":{"registered":true,"url":"https://github.com/jane"},
                    "twitter":{"registered":false,"url":"https://twitter.com/ghost"}
                }}}"#,
        );
        // The enriched email entity carries the domain flags + platform CSV.
        let email_e = &es[0];
        let ev = &email_e.evidence[0];
        assert!(email_e.has_tag("custom-domain"));
        assert_eq!(
            ev.attributes.get("domain_registered").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ev.attributes.get("custom_domain").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ev.attributes.get("platform_count").map(String::as_str),
            Some("2")
        );

        // Two Url leads (facebook, github) — NOT the unregistered twitter.
        let urls: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Url).collect();
        assert_eq!(urls.len(), 2);
        let vals: Vec<&str> = urls.iter().map(|e| e.value.as_str()).collect();
        assert!(vals.contains(&"https://facebook.com/jane"));
        assert!(vals.contains(&"https://github.com/jane"));
        assert!(
            urls.iter()
                .all(|e| e.has_tag("social-profile") && e.has_tag("seon"))
        );
        let fb = urls.iter().find(|e| e.value.contains("facebook")).unwrap();
        assert!(fb.has_tag("platform:facebook"));

        // One Person from the best-named identity platform (facebook).
        let people: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Person).collect();
        assert_eq!(people.len(), 1);
        assert_eq!(people[0].value, "Jane Doe");
        assert!(people[0].has_tag("platform:facebook"));
    }

    #[test]
    fn email_high_score_is_flagged_high_risk() {
        let es = email(r#"{"data":{"score":92.0}}"#);
        assert!(es[0].has_tag("high-risk"));
        let low = email(r#"{"data":{"score":10.0}}"#);
        assert!(!low[0].has_tag("high-risk"));
    }

    #[test]
    fn email_no_accounts_yields_only_the_enriched_email() {
        let es = email(r#"{"data":{"deliverable":true}}"#);
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].kind, EntityKind::Email);
        assert!(
            es.iter()
                .all(|e| !matches!(e.kind, EntityKind::Url | EntityKind::Person))
        );
    }

    #[test]
    fn email_person_skips_handles_and_partial_names() {
        // A registered platform whose "name" is a handle (no space) is not a Person.
        let es = email(
            r#"{"data":{"account_details":{"github":{"registered":true,"name":"janedoe"}}}}"#,
        );
        assert!(es.iter().all(|e| e.kind != EntityKind::Person));
    }

    // ── Core: phone entity building ─────────────────────────────────────
    #[test]
    fn phone_enriches_and_emits_messaging_profile_urls() {
        let r: SeonPhoneResp = serde_json::from_str(
            r#"{"data":{"score":5.0,"valid":true,"carrier":"Telstra","country_code":"au","type":"mobile",
                "account_details":{
                    "whatsapp":{"registered":true,"url":"https://wa.me/61400"},
                    "telegram":{"registered":true},
                    "viber":{"registered":false,"url":"https://viber/x"}
                }}}"#,
        )
        .unwrap();
        let es = build_phone_entities(
            &Target::new(TargetKind::Phone, "+61400000000"),
            &r.data.unwrap(),
            "s",
        );
        let phone_e = &es[0];
        assert_eq!(phone_e.kind, EntityKind::Phone);
        assert!(phone_e.has_tag("country:AU"));
        assert!(phone_e.has_tag("line:mobile"));
        let ev = &phone_e.evidence[0];
        assert_eq!(
            ev.attributes.get("carrier").map(String::as_str),
            Some("Telstra")
        );
        assert_eq!(
            ev.attributes.get("messaging_platforms").map(String::as_str),
            Some("whatsapp,telegram")
        );

        // Only whatsapp had a URL (telegram had none; viber unregistered).
        let urls: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Url).collect();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].value, "https://wa.me/61400");
        assert!(urls[0].has_tag("platform:whatsapp"));
    }
}
