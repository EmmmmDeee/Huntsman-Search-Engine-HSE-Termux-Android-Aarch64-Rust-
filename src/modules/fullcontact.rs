//! FullContact Person Enrich — email/phone → a person's identity graph.
//!
//! Endpoint: `POST https://api.fullcontact.com/v3/person.enrich`
//! Auth:     `Authorization: Bearer <key>`. Key-gated (`HUNTSMAN_FULLCONTACT_KEY`,
//!           free developer tier available). Inert with no key.
//!
//! This is the single highest-yield people-centric source: one email resolves to
//! the owner's **real name, employer, location, and linked social handles** — the
//! biggest cross-correlation multiplier in the toolkit, since one seed explodes
//! into several corroborating entity types that fire the identity/geo
//! correlators. Synergises with `name_intel`, `employer_pivot`, `username_search`
//! and the geocoders.
//!
//! The response→entity mapping is the pure [`build_entities`] (unit-tested
//! against a fixture); `process` owns only auth/transport.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const SRC: &str = "fullcontact";
const KEY_ENV: &str = "HUNTSMAN_FULLCONTACT_KEY";

pub struct FullContact;

/// FullContact v3 person.enrich response (the fields we map; all optional).
#[derive(Deserialize, Default)]
#[serde(default)]
struct FcResp {
    #[serde(rename = "fullName")]
    full_name: Option<String>,
    location: Option<String>,
    title: Option<String>,
    organization: Option<String>,
    details: Details,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Details {
    locations: Vec<Located>,
    employment: Vec<Employment>,
    /// Map of network name (`twitter`, `linkedin`, …) → profile.
    profiles: BTreeMap<String, Profile>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Located {
    formatted: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Employment {
    name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Profile {
    username: Option<String>,
    url: Option<String>,
}

#[async_trait]
impl Module for FullContact {
    fn name(&self) -> &'static str {
        "fullcontact"
    }

    fn description(&self) -> &'static str {
        "FullContact person enrichment — email/phone → name, employer, location, socials"
    }

    fn priority(&self) -> u8 {
        89
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Phone)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn max_timeout_ms(&self) -> u64 {
        9_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Username,
            EntityKind::Url,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(key) = ctx.key_opt(KEY_ENV) else {
            return Ok(ModuleResult::new());
        };
        let v = target.value.trim();
        let field = match target.kind {
            TargetKind::Email if v.contains('@') => "email",
            TargetKind::Phone => "phone",
            _ => return Ok(ModuleResult::new()),
        };
        let body = format!(r#"{{"{field}":"{}"}}"#, escape_json(v));

        let resp = ctx
            .http
            .post("https://api.fullcontact.com/v3/person.enrich")
            .header("Authorization", format!("Bearer {key}"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        // 404 = no person matched — a clean miss, not an error.
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            let code = status.as_u16();
            if matches!(code, 401 | 403 | 429) {
                ctx.report_key_exhausted(SRC, key, code);
            }
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }
        // Via json_scanned: the response is retained in the raw archive and
        // scanned for leaked keys, then deserialised.
        let parsed: FcResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| Error::module(SRC, e))?;

        let mut result = ModuleResult::new();
        result
            .entities
            .extend(build_entities(&parsed, &ctx.scan_id));
        Ok(result)
    }
}

/// Minimal JSON string-escape for the request body (the seed value is trusted
/// CLI/API input, but a quote or backslash must not break the body).
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Map a person.enrich response to entities. Pure of I/O (unit-tested).
fn build_entities(r: &FcResp, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let ev = || Evidence::new(SRC, "FullContact person enrichment");

    let push = |out: &mut Vec<Entity>, kind: EntityKind, value: &str, conf: f64, tags: &[&str]| {
        let v = value.trim();
        if v.len() < 2 {
            return;
        }
        let mut e = Entity::new(kind, v, conf, scan_id);
        e.tag(SRC);
        for t in tags {
            e.tag(*t);
        }
        e.add_evidence(ev());
        out.push(e);
    };

    if let Some(name) = r.full_name.as_deref().filter(|n| n.contains(' ')) {
        push(&mut out, EntityKind::Person, name, 0.75, &[]);
    }
    // Employer(s): the top-level `organization` plus structured employment.
    let mut orgs: Vec<&str> = Vec::new();
    if let Some(o) = r.organization.as_deref() {
        orgs.push(o);
    }
    orgs.extend(
        r.details
            .employment
            .iter()
            .filter_map(|e| e.name.as_deref()),
    );
    for (i, o) in orgs.iter().enumerate() {
        // First (current) employer highest; later/historical slightly lower.
        let conf = if i == 0 { 0.65 } else { 0.55 };
        push(&mut out, EntityKind::Organisation, o, conf, &["employer"]);
    }
    // Location(s): top-level convenience string + structured formatted addresses.
    let mut seen_loc = std::collections::HashSet::new();
    let locs = r.location.iter().map(String::as_str).chain(
        r.details
            .locations
            .iter()
            .filter_map(|l| l.formatted.as_deref()),
    );
    for loc in locs {
        if seen_loc.insert(loc.to_lowercase()) {
            // Free-text AU enrichment (shared producer) so an Australian
            // location feeds AU-056/060 without a geocode round-trip.
            let mut tags: Vec<&str> = vec!["geo-hint"];
            tags.extend(crate::util::geo::au_location_tags(loc));
            push(&mut out, EntityKind::Address, loc, 0.60, &tags);
        }
    }
    // Social profiles: platform-prefixed Username pivots + their profile URLs.
    for (network, p) in &r.details.profiles {
        let net = network.trim();
        if let Some(u) = p
            .username
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            push(
                &mut out,
                EntityKind::Username,
                &format!("{net}:{u}"),
                0.60,
                &[net],
            );
        }
        if let Some(url) = p
            .url
            .as_deref()
            .map(str::trim)
            .filter(|u| u.starts_with("http"))
        {
            push(&mut out, EntityKind::Url, url, 0.55, &[net]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> FcResp {
        let json = serde_json::json!({
            "fullName": "Jordan Avery",
            "location": "Brisbane, Queensland, Australia",
            "title": "Engineer",
            "organization": "Acme Pty Ltd",
            "details": {
                "locations": [{ "formatted": "Brisbane, QLD, AU" }],
                "employment": [{ "name": "Acme Pty Ltd" }, { "name": "Globex" }],
                "profiles": {
                    "twitter": { "username": "mattd", "url": "https://twitter.com/mattd" },
                    "linkedin": { "username": "matthew-avery", "url": "https://linkedin.com/in/matthew-avery" }
                }
            }
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn build_entities_resolves_the_identity_graph() {
        let r = fixture();
        let es = build_entities(&r, "scan");
        let has = |k: EntityKind, v: &str| es.iter().any(|e| e.kind == k && e.value == v);
        assert!(has(EntityKind::Person, "Jordan Avery"));
        assert!(has(EntityKind::Organisation, "Acme Pty Ltd"));
        assert!(has(EntityKind::Organisation, "Globex"));
        assert!(has(EntityKind::Address, "Brisbane, Queensland, Australia"));
        assert!(has(EntityKind::Username, "twitter:mattd"));
        assert!(has(EntityKind::Username, "linkedin:matthew-avery"));
        assert!(has(
            EntityKind::Url,
            "https://linkedin.com/in/matthew-avery"
        ));
        // Every entity carries the source tag.
        assert!(es.iter().all(|e| e.has_tag("fullcontact")));
        // The Brisbane location is AU-enriched (shared free-text producer) so
        // it feeds the AU correlator.
        let bne = es
            .iter()
            .find(|e| e.value == "Brisbane, Queensland, Australia")
            .unwrap();
        assert!(bne.has_tag("au-relevant"));
        assert!(bne.has_tag("au-state:QLD"));
        assert!(bne.has_tag("au-se-qld"));
        // Current employer outranks historical.
        let acme = es.iter().find(|e| e.value == "Acme Pty Ltd").unwrap();
        let globex = es.iter().find(|e| e.value == "Globex").unwrap();
        assert!(acme.confidence > globex.confidence);
    }

    #[test]
    fn build_entities_is_quiet_on_empty_response() {
        assert!(build_entities(&FcResp::default(), "scan").is_empty());
    }

    #[test]
    fn metadata_is_keygated_people() {
        let m = FullContact;
        assert_eq!(m.cost(), ModuleCost::KeyGated);
        assert_eq!(m.category(), ModuleCategory::People);
        assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }
}
