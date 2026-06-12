//! EmailRep — email reputation, breach history, and social media presence.
//!
//! Endpoint: `GET https://emailrep.io/{email_address}`
//! Auth:     `Key` header. Key-gated (`HUNTSMAN_EMAILREP_KEY`).
//!
//! Rate limit: 2 req/hour on the free tier. Returns domain reputation, breach
//! exposure, fraud/abuse flags, and social-media presence. Every reputation
//! field is surfaced as an evidence attribute, and the *actionable* ones
//! (breach, blacklist, malicious/spam, disposable/new/non-existent domain) also
//! become tags so downstream rules and the UI can pivot on them.
//!
//! The response → entity mapping lives in the pure [`build_email_entity`] so it
//! is unit-tested without a live API; `process` owns only auth/transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

const KEY_ENV: &str = "HUNTSMAN_EMAILREP_KEY";
const SRC: &str = "emailrep";

/// Cap on the social-profile platform list surfaced inline.
const MAX_PROFILES: usize = 20;

pub struct EmailRep;

#[derive(Deserialize)]
struct RepResp {
    #[serde(default)]
    reputation: Option<String>,
    #[serde(default)]
    suspicious: Option<bool>,
    #[serde(default)]
    references: Option<u64>,
    #[serde(default)]
    details: Option<RepDetails>,
}

#[derive(Deserialize)]
struct RepDetails {
    #[serde(default)]
    blacklisted: Option<bool>,
    #[serde(default)]
    malicious_activity: Option<bool>,
    #[serde(default)]
    credential_leaked: Option<bool>,
    #[serde(default)]
    data_breach: Option<bool>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    domain_exists: Option<bool>,
    #[serde(default)]
    domain_reputation: Option<String>,
    #[serde(default)]
    new_domain: Option<bool>,
    #[serde(default)]
    days_since_domain_creation: Option<u64>,
    #[serde(default)]
    free_provider: Option<bool>,
    #[serde(default)]
    disposable: Option<bool>,
    #[serde(default)]
    deliverable: Option<bool>,
    #[serde(default)]
    spam: Option<bool>,
    #[serde(default)]
    profiles: Vec<String>,
}

#[async_trait]
impl Module for EmailRep {
    fn name(&self) -> &'static str {
        "emailrep"
    }
    fn description(&self) -> &'static str {
        "Email reputation scoring — breach exposure, blacklists, and social profiles"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn max_timeout_ms(&self) -> u64 {
        5_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Email
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Beyond the Email default (T1589.002 Email Addresses), EmailRep reports
        // credential-leak / data-breach status (T1589.001 Credentials) and the
        // address's social-media presence (T1593.001 Social Media). Superset of
        // the default — coverage cannot regress.
        &["T1589.002", "T1589.001", "T1593.001"]
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[EntityKind::Email];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        let email = target.value.trim();
        if !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://emailrep.io/{}", urlencode(email));

        let resp = ctx
            .http
            .get(&url)
            .header("Key", key)
            .header("Accept", "application/json")
            .header(
                "User-Agent",
                "huntsman-search-engine (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)",
            )
            .send_tagged(SRC).await?;

        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: RepResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut result = ModuleResult::new();
        result.push(build_email_entity(target, &body, &ctx.scan_id));
        Ok(result)
    }
}

/// Enrich the email target with its EmailRep reputation report. **Pure** (no
/// network/IO) so every flag → tag/attribute decision is unit-tested directly.
///
/// A `true` boolean flag becomes both an evidence attribute and a pivotable tag;
/// `domain_exists` is the inverse — a `false` (the domain doesn't resolve) is
/// the actionable, suspicious case and is what gets tagged.
fn build_email_entity(target: &Target, body: &RepResp, scan_id: &str) -> Entity {
    let email = target.value.trim();
    let mut entity = target.to_entity(0.85, scan_id);
    entity.tag("emailrep");

    let mut ev = Evidence::new(SRC, format!("EmailRep report for {email}"));
    if let Some(rep) = body.reputation.as_deref() {
        ev = ev.with_attr("reputation", rep);
        entity.tag(format!("reputation:{rep}"));
    }
    if let Some(s) = body.suspicious {
        ev = ev.with_attr("suspicious", s.to_string());
        if s {
            entity.tag("suspicious");
        }
    }
    if let Some(refs) = body.references {
        ev = ev.with_attr("references", refs.to_string());
    }

    if let Some(d) = &body.details {
        // `(field == Some(true))` flags → attribute + a pivotable tag.
        for (flag, attr, tag) in [
            (d.credential_leaked, "credential_leaked", "breach"),
            (d.data_breach, "data_breach", "breach"),
            (d.blacklisted, "blacklisted", "blacklisted"),
            (d.malicious_activity, "malicious_activity", "malicious"),
            (d.spam, "spam", "spam-source"),
            (d.disposable, "disposable", "disposable"),
            (d.free_provider, "free_provider", "freemail"),
            (d.new_domain, "new_domain", "new-domain"),
        ] {
            if flag == Some(true) {
                ev = ev.with_attr(attr, "true");
                entity.tag(tag);
            }
        }

        // The inverse case: a domain that does NOT exist is the suspicious one.
        if let Some(exists) = d.domain_exists {
            ev = ev.with_attr("domain_exists", exists.to_string());
            if !exists {
                entity.tag("domain-nonexistent");
            }
        }

        // Soft / informational attributes (no tag).
        if let Some(deliverable) = d.deliverable {
            ev = ev.with_attr("deliverable", deliverable.to_string());
        }
        if let Some(fs) = d.first_seen.as_deref() {
            ev = ev.with_attr("first_seen", fs);
        }
        if let Some(ls) = d.last_seen.as_deref() {
            ev = ev.with_attr("last_seen", ls);
        }
        if let Some(dr) = d.domain_reputation.as_deref() {
            ev = ev.with_attr("domain_reputation", dr);
        }
        if let Some(days) = d.days_since_domain_creation {
            ev = ev.with_attr("domain_age_days", days.to_string());
        }
        if !d.profiles.is_empty() {
            let csv = d
                .profiles
                .iter()
                .take(MAX_PROFILES)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",");
            ev = ev
                .with_attr("profiles", csv)
                .with_attr("profile_count", d.profiles.len().to_string());
        }
    }

    entity.add_evidence(ev);
    entity
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email_target() -> Target {
        Target::new(TargetKind::Email, "test@example.com")
    }

    // ── Module surface ──────────────────────────────────────────────────
    #[test]
    fn accepts_email_only() {
        let m = EmailRep;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Phone, "+1")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(EmailRep.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(EmailRep.name(), "emailrep");
        assert_eq!(EmailRep.priority(), 90);
        assert_eq!(EmailRep.max_timeout_ms(), 5_000);
    }

    #[test]
    fn parse_response() {
        let raw = r#"{
            "email": "test@example.com",
            "reputation": "high",
            "suspicious": false,
            "references": 15,
            "details": {"credential_leaked": true, "data_breach": true, "profiles": ["linkedin"]}
        }"#;
        let r: RepResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.reputation.as_deref(), Some("high"));
        let d = r.details.unwrap();
        assert_eq!(d.credential_leaked, Some(true));
        assert_eq!(d.profiles.len(), 1);
    }

    // ── The core: build_email_entity surfaces every signal ───────────────
    fn build(json: &str) -> Entity {
        let body: RepResp = serde_json::from_str(json).unwrap();
        build_email_entity(&email_target(), &body, "scan")
    }

    #[test]
    fn surfaces_breach_blacklist_and_reputation() {
        let e = build(
            r#"{"reputation":"low","suspicious":true,"references":42,
                "details":{"credential_leaked":true,"data_breach":true,
                           "blacklisted":true,"malicious_activity":true,
                           "first_seen":"2010-01-01","last_seen":"2024-06-01",
                           "domain_reputation":"high","days_since_domain_creation":5000,
                           "deliverable":true,"profiles":["linkedin","twitter","github"]}}"#,
        );
        assert!(e.has_tag("emailrep"));
        assert!(e.has_tag("reputation:low"));
        assert!(e.has_tag("suspicious"));
        assert!(e.has_tag("breach"));
        assert!(e.has_tag("blacklisted"));
        assert!(e.has_tag("malicious"));
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("reputation").map(String::as_str),
            Some("low")
        );
        assert_eq!(
            ev.attributes.get("references").map(String::as_str),
            Some("42")
        );
        assert_eq!(
            ev.attributes.get("credential_leaked").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ev.attributes.get("domain_age_days").map(String::as_str),
            Some("5000")
        );
        assert_eq!(
            ev.attributes.get("profiles").map(String::as_str),
            Some("linkedin,twitter,github")
        );
        assert_eq!(
            ev.attributes.get("profile_count").map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn surfaces_the_previously_discarded_fraud_signals() {
        // spam / new_domain / domain_exists=false — the three fields the old
        // code parsed then threw away.
        let e = build(
            r#"{"details":{"spam":true,"new_domain":true,"domain_exists":false,"disposable":true}}"#,
        );
        assert!(e.has_tag("spam-source"));
        assert!(e.has_tag("new-domain"));
        assert!(e.has_tag("domain-nonexistent"));
        assert!(e.has_tag("disposable"));
        let ev = &e.evidence[0];
        assert_eq!(ev.attributes.get("spam").map(String::as_str), Some("true"));
        assert_eq!(
            ev.attributes.get("new_domain").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ev.attributes.get("domain_exists").map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn existing_domain_is_recorded_but_not_flagged() {
        let e = build(r#"{"details":{"domain_exists":true}}"#);
        assert!(!e.has_tag("domain-nonexistent"));
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("domain_exists")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn clean_email_gets_only_the_source_tag() {
        // A spotless report adds no risk tags — just the module tag.
        let e = build(r#"{"reputation":"high","suspicious":false,"details":{"deliverable":true}}"#);
        assert!(e.has_tag("emailrep"));
        assert!(e.has_tag("reputation:high"));
        for risk in [
            "suspicious",
            "breach",
            "blacklisted",
            "malicious",
            "spam-source",
            "new-domain",
            "domain-nonexistent",
            "disposable",
        ] {
            assert!(!e.has_tag(risk), "clean email must not be tagged {risk}");
        }
    }

    #[test]
    fn false_flags_do_not_tag() {
        // EmailRep returns explicit `false` for absent abuse — must not tag.
        let e =
            build(r#"{"details":{"credential_leaked":false,"spam":false,"blacklisted":false}}"#);
        assert!(!e.has_tag("breach"));
        assert!(!e.has_tag("spam-source"));
        assert!(!e.has_tag("blacklisted"));
    }

    #[test]
    fn profiles_are_capped() {
        let profiles: Vec<String> = (0..30).map(|i| format!(r#""p{i}""#)).collect();
        let e = build(&format!(
            r#"{{"details":{{"profiles":[{}]}}}}"#,
            profiles.join(",")
        ));
        let csv = e.evidence[0].attributes.get("profiles").unwrap();
        assert_eq!(csv.split(',').count(), MAX_PROFILES);
        // …but the reported count is the true total.
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("profile_count")
                .map(String::as_str),
            Some("30")
        );
    }
}
