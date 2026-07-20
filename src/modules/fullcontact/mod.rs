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
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

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
    /// Contact emails the enrichment resolved (`{value, label}`) — a direct
    /// Email BFS pivot, previously decoded nowhere.
    emails: Vec<LabeledValue>,
    /// Contact phones the enrichment resolved (`{value, label}`).
    phones: Vec<LabeledValue>,
    /// Map of network name (`twitter`, `linkedin`, …) → profile.
    profiles: BTreeMap<String, Profile>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LabeledValue {
    value: Option<String>,
    label: Option<String>,
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
        "FullContact enrichment — pivots an email/phone to name, employer, location, and social accounts"
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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // person.enrich resolves the owner's name + title (the People default
        // T1589.003 + T1591.004), their employer(s) (T1591.002 Business
        // Relationships), location (T1591.001 Physical Locations), and linked
        // social handles (T1593.001 Social Media). Superset of the default —
        // coverage cannot regress.
        &[
            "T1589.003",
            "T1591.004",
            "T1591.002",
            "T1591.001",
            "T1593.001",
        ]
    }

    fn max_timeout_ms(&self) -> u64 {
        9_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Username,
            EntityKind::Url,
            // Contact emails/phones the enrichment `details` resolve.
            EntityKind::Email,
            EntityKind::Phone,
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
            .bearer_auth(key)
            .header("Content-Type", "application/json")
            .body(body)
            .send_tagged(SRC)
            .await?;

        // 404 = no person matched — a clean miss, not an error.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };
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
        tags.iter().for_each(|t| e.tag(*t));
        e.add_evidence(ev());
        out.push(e);
    };

    if let Some(name) = r.full_name.as_deref().filter(|n| n.contains(' ')) {
        push(
            &mut out,
            EntityKind::Person,
            name,
            confidence::VERY_HIGH,
            &[],
        );
        // Attach the job title to the Person entity as a tag + evidence attribute.
        if let Some(title) = r.title.as_deref().map(str::trim).filter(|t| !t.is_empty())
            && let Some(e) = out.last_mut()
        {
            e.tag(format!("role:{}", title.to_lowercase().replace(' ', "-")));
            e.add_evidence(
                Evidence::new(SRC, format!("FullContact job title: {title}"))
                    .with_attr("title", title),
            );
        }
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
    orgs.iter().enumerate().for_each(|(i, o)| {
        let conf = if i == 0 {
            confidence::HIGH
        } else {
            confidence::MEDIUM_HIGH
        };
        push(&mut out, EntityKind::Organisation, o, conf, &["employer"]);
    });
    // Location(s): top-level convenience string + structured formatted addresses.
    let mut seen_loc = std::collections::HashSet::new();
    let locs = r.location.iter().map(String::as_str).chain(
        r.details
            .locations
            .iter()
            .filter_map(|l| l.formatted.as_deref()),
    );
    // Collect into a Vec so we can iterate twice (once for Address, once for
    // Coordinates) without re-borrowing the chained iterator.
    let loc_list: Vec<&str> = locs.filter(|l| seen_loc.insert(l.to_lowercase())).collect();
    for loc in &loc_list {
        let mut extra_tags: Vec<&str> = vec!["geo-hint", "geoint"];
        let mut au_state_tag = String::new();
        if let Some(sc) = crate::util::address_au::state_code(loc) {
            au_state_tag = format!("au-state:{sc}");
        }
        if !au_state_tag.is_empty() {
            extra_tags.push("country:AU");
        }
        let tags_refs: Vec<&str> = extra_tags;
        push(
            &mut out,
            EntityKind::Address,
            loc,
            confidence::MEDIUM_PLUS,
            &tags_refs,
        );
        if !au_state_tag.is_empty()
            && let Some(last) = out.last_mut()
        {
            last.tag(au_state_tag);
        }
        // Inline Coordinates via offline city lookup.
        if let Some((lat, lon)) = crate::util::city_coords::city_coords(loc) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                confidence::MEDIUM_HIGH,
                scan_id,
            );
            c.tag(SRC);
            c.tag("addr-derived");
            c.tag("geoint");
            if let Some(sc) = crate::util::address_au::state_code(loc) {
                c.tag(format!("au-state:{sc}"));
                c.tag("country:AU");
            }
            c.add_evidence(ev());
            out.push(c);
        }
    }
    // Social profiles: platform-prefixed Username pivots + their profile URLs.
    r.details.profiles.iter().for_each(|(network, p)| {
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
                confidence::MEDIUM_PLUS,
                &[net],
            );
        }
        if let Some(url) = p
            .url
            .as_deref()
            .map(str::trim)
            .filter(|u| u.starts_with("http"))
        {
            push(
                &mut out,
                EntityKind::Url,
                url,
                confidence::MEDIUM_HIGH,
                &[net],
            );
        }
    });

    // Contact emails/phones from the enrichment `details`. An email is validated
    // with the shared `looks_like_email` gate (so a malformed value can't mint a
    // bogus Email); a phone needs ≥7 digits (Entity::new normalises formatting).
    // The FullContact label (work/home/…) is kept as an evidence attribute.
    for lv in &r.details.emails {
        let Some(v) = lv.value.as_deref().map(str::trim) else {
            continue;
        };
        if !crate::util::extract::looks_like_email(&v.to_lowercase()) {
            continue;
        }
        push(&mut out, EntityKind::Email, v, 0.70, &[]);
        if let Some(label) = lv.label.as_deref().map(str::trim).filter(|s| !s.is_empty())
            && let Some(e) = out.last_mut()
        {
            e.tag(format!("label:{}", label.to_lowercase()));
        }
    }
    for lv in &r.details.phones {
        let Some(v) = lv.value.as_deref().map(str::trim) else {
            continue;
        };
        if v.chars().filter(char::is_ascii_digit).count() < 7 {
            continue;
        }
        push(&mut out, EntityKind::Phone, v, 0.65, &[]);
        if let Some(label) = lv.label.as_deref().map(str::trim).filter(|s| !s.is_empty())
            && let Some(e) = out.last_mut()
        {
            e.tag(format!("label:{}", label.to_lowercase()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
