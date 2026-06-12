//! Epieos email-to-identity resolution. Key-gated (Bearer Token).
//!
//! Endpoint: `POST https://api.epieos.com/api/v1/email`
//! Auth:     Bearer Token (`HUNTSMAN_EPIEOS_KEY`).
//!
//! Extracts the Google profile (id, name, picture), Google Maps reviews (place,
//! rating, and the review text — GEOINT context on where the subject has been),
//! and Skype identity (handle, name, location) from an email address. Both the
//! Google and Skype display names are surfaced as `Person` leads — they are
//! independent sources, so a divergence is itself a signal.
//!
//! The response → entity mapping lives in the pure [`build_entities`] so it is
//! unit-tested without a live API; `process` owns only auth/transport.

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::str_util::truncate_safe;

const KEY_ENV: &str = "HUNTSMAN_EPIEOS_KEY";
const SRC: &str = "epieos";

/// Maps-review places surfaced inline on the email entity / emitted as Address.
const MAX_PLACES_INLINE: usize = 5;
const MAX_PLACE_ENTITIES: usize = 3;
/// Review text is free-form user content; cap it before persisting.
const REVIEW_TEXT_CAP: usize = 200;

pub struct Epieos;

#[derive(Deserialize)]
struct EpieosResp {
    #[serde(default)]
    google_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    profile_picture: Option<String>,
    #[serde(default)]
    maps_reviews: Option<Vec<MapsReview>>,
    #[serde(default)]
    skype: Option<SkypeInfo>,
    #[serde(default)]
    calendar: Option<CalendarInfo>,
}

#[derive(Deserialize)]
struct MapsReview {
    #[serde(default)]
    place_name: Option<String>,
    #[serde(default)]
    rating: Option<f64>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    date: Option<String>,
}

#[derive(Deserialize)]
struct SkypeInfo {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    country: Option<String>,
}

#[derive(Deserialize)]
struct CalendarInfo {
    #[serde(default)]
    name: Option<String>,
}

use crate::util::str_util::nonempty;

/// A display string that is plausibly a real person name (a multi-word label),
/// not a handle — the bar for promoting it to a `Person` entity.
fn is_person_name(s: &str) -> bool {
    let s = s.trim();
    s.chars().count() >= 3 && s.contains(' ')
}

/// Build all entities from a parsed Epieos response. **Pure** (no network/IO) so
/// every field → entity/tag/confidence decision is unit-tested directly.
///
/// Confidence encodes source authority: the Google-confirmed name is strong
/// (0.75); a Skype name slightly less (0.70); a *reviewed* place is a weak
/// location lead (0.48 — it's somewhere the subject has been, not where they
/// live).
fn build_entities(target: &Target, body: &EpieosResp, scan_id: &str) -> Vec<Entity> {
    let email = target.value.trim();
    let mut out = Vec::new();

    // ── Enriched email (the anchor) ──────────────────────────────────────
    let mut entity = target.to_entity(0.85, scan_id);
    entity.tag("epieos");
    let mut ev = Evidence::new(SRC, format!("Epieos identity resolution for {email}"));
    if let Some(gid) = nonempty(&body.google_id) {
        ev = ev.with_attr("google_id", gid);
        entity.tag("google-account");
    }
    if let Some(name) = nonempty(&body.name) {
        ev = ev.with_attr("name", name);
    }
    if let Some(pic) = nonempty(&body.profile_picture) {
        ev = ev.with_attr("profile_picture", pic);
    }
    let skype = body.skype.as_ref();
    if let Some(h) = skype.and_then(|s| nonempty(&s.handle)) {
        ev = ev.with_attr("skype_handle", h);
        entity.tag("skype");
    }
    if let Some(sn) = skype.and_then(|s| nonempty(&s.name)) {
        ev = ev.with_attr("skype_name", sn);
    }
    if let Some(cn) = body.calendar.as_ref().and_then(|c| nonempty(&c.name)) {
        ev = ev.with_attr("calendar_name", cn);
    }
    if let Some(reviews) = &body.maps_reviews
        && !reviews.is_empty()
    {
        ev = ev.with_attr("maps_review_count", reviews.len().to_string());
        let places: Vec<&str> = reviews
            .iter()
            .filter_map(|r| nonempty(&r.place_name))
            .take(MAX_PLACES_INLINE)
            .collect();
        if !places.is_empty() {
            ev = ev.with_attr("maps_places", places.join("; "));
            entity.tag("has-maps-reviews");
        }
    }
    entity.add_evidence(ev);
    out.push(entity);

    // ── Person leads from each DISTINCT real name (Google + Skype) ────────
    let mut seen_names = HashSet::new();
    for (label, conf, name) in [
        ("google", 0.75, nonempty(&body.name)),
        (
            "platform:skype",
            0.70,
            skype.and_then(|s| nonempty(&s.name)),
        ),
    ] {
        if let Some(name) = name.filter(|n| is_person_name(n))
            && seen_names.insert(name.to_lowercase())
        {
            let mut pe = Entity::new(EntityKind::Person, name, conf, scan_id);
            pe.tag("epieos");
            pe.tag(label);
            pe.add_evidence(Evidence::new(SRC, format!("{label} name for {email}")));
            out.push(pe);
        }
    }

    // ── Skype handle → Username, Skype location → Address ─────────────────
    if let Some(s) = skype {
        if let Some(handle) = nonempty(&s.handle).filter(|h| h.chars().count() >= 3) {
            let mut ue = Entity::new(EntityKind::Username, handle, 0.70, scan_id);
            ue.tag("epieos");
            ue.tag("platform:skype");
            ue.add_evidence(Evidence::new(SRC, format!("Skype handle for {email}")));
            out.push(ue);
        }
        if let Some(city) = nonempty(&s.city).filter(|c| c.chars().count() >= 3) {
            let location = match nonempty(&s.country) {
                Some(c) => format!("{city}, {c}"),
                None => city.to_string(),
            };
            let mut ae = Entity::new(EntityKind::Address, &location, 0.52, scan_id);
            ae.tag("epieos");
            ae.tag("skype");
            ae.tag("geoint");
            if let Some(sc) = crate::util::address_au::state_code(&location) {
                ae.tag(format!("au-state:{sc}"));
                ae.tag("country:AU");
            }
            ae.add_evidence(Evidence::new(SRC, format!("Skype location for {email}")));
            out.push(ae);
        }
    }

    // ── Reviewed places → Address, now carrying the rating + review text ──
    if let Some(reviews) = &body.maps_reviews {
        for review in reviews.iter().take(MAX_PLACE_ENTITIES) {
            let Some(place) = nonempty(&review.place_name).filter(|p| p.chars().count() >= 3)
            else {
                continue;
            };
            let mut ae = Entity::new(EntityKind::Address, place, 0.52, scan_id);
            ae.tag("epieos");
            ae.tag("google-maps");
            ae.tag("geoint");
            if let Some(sc) = crate::util::address_au::state_code(place) {
                ae.tag(format!("au-state:{sc}"));
                ae.tag("country:AU");
            }
            let mut rev_ev =
                Evidence::new(SRC, format!("Google Maps review at \"{place}\" by {email}"));
            if let Some(rating) = review.rating {
                rev_ev = rev_ev.with_attr("rating", format!("{rating:.1}"));
            }
            if let Some(text) = nonempty(&review.text) {
                rev_ev = rev_ev.with_attr("review_text", truncate_safe(text, REVIEW_TEXT_CAP));
            }
            if let Some(d) = nonempty(&review.date) {
                rev_ev = rev_ev.with_attr("review_date", d);
            }
            ae.add_evidence(rev_ev);
            out.push(ae);
        }
    }

    out
}

#[async_trait]
impl Module for Epieos {
    fn name(&self) -> &'static str {
        "epieos"
    }
    fn description(&self) -> &'static str {
        "Email-to-identity: Google profile, Maps reviews, Skype handle via Epieos"
    }
    fn priority(&self) -> u8 {
        92
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn produces(&self) -> &'static [EntityKind] {
        // The anchor entity is the Email seed re-emitted with enrichment
        // (`target.to_entity` → `EntityKind::Email`, since this module accepts
        // only Email), so Email must be declared here too — the dependency
        // planner and the orphaned-pivot smoke guard read producer kinds from it.
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Person,
            EntityKind::Username,
            EntityKind::Address,
        ];
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

        let resp = ctx
            .http
            .post("https://api.epieos.com/api/v1/email")
            .bearer_auth(key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "email": email }))
            .send_tagged(SRC)
            .await?;

        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: EpieosResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut result = ModuleResult::new();
        for e in build_entities(target, &body, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email_target() -> Target {
        Target::new(TargetKind::Email, "jane@example.com")
    }

    fn build(json: &str) -> Vec<Entity> {
        let body: EpieosResp = serde_json::from_str(json).unwrap();
        build_entities(&email_target(), &body, "s")
    }

    // ── Module surface ──────────────────────────────────────────────────
    #[test]
    fn accepts_email_only() {
        let m = Epieos;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(Epieos.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Epieos.name(), "epieos");
        assert_eq!(Epieos.priority(), 92);
        assert_eq!(Epieos.max_timeout_ms(), 15_000);
        assert!(!Epieos.description().is_empty());
    }

    #[test]
    fn parse_response() {
        let raw = r#"{"google_id":"123","name":"John Smith",
            "maps_reviews":[{"place_name":"Sydney Opera House","rating":5.0,"date":"2024-01-15"}],
            "skype":{"handle":"john.smith.au","name":"John Smith","city":"Sydney","country":"AU"}}"#;
        let r: EpieosResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.name.as_deref(), Some("John Smith"));
        assert_eq!(r.maps_reviews.unwrap().len(), 1);
    }

    // ── Core: full extraction incl. the recovered fields ─────────────────
    #[test]
    fn extracts_full_profile_with_review_rating_and_text() {
        let es = build(
            r#"{
                "google_id":"1234567890","name":"Jane Doe",
                "profile_picture":"https://lh3.googleusercontent.com/p",
                "maps_reviews":[
                    {"place_name":"Sydney Opera House","rating":5.0,"text":"Stunning, came with family.","date":"2024-01-15"}
                ],
                "skype":{"handle":"jane.doe","name":"Jane Q Doe","city":"Sydney","country":"AU"},
                "calendar":{"name":"Jane Doe"}
            }"#,
        );

        // Enriched email anchor carries the Skype name (previously discarded).
        let anchor = es.iter().find(|e| e.kind == EntityKind::Email).unwrap();
        let ev = &anchor.evidence[0];
        assert!(
            anchor.has_tag("google-account")
                && anchor.has_tag("skype")
                && anchor.has_tag("has-maps-reviews")
        );
        assert_eq!(
            ev.attributes.get("skype_name").map(String::as_str),
            Some("Jane Q Doe")
        );
        assert_eq!(
            ev.attributes.get("skype_handle").map(String::as_str),
            Some("jane.doe")
        );

        // Two DISTINCT Person leads (Google "Jane Doe" + Skype "Jane Q Doe").
        let people: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Person).collect();
        assert_eq!(people.len(), 2);
        assert!(
            people
                .iter()
                .any(|p| p.value == "Jane Doe" && p.has_tag("google"))
        );
        assert!(
            people
                .iter()
                .any(|p| p.value == "Jane Q Doe" && p.has_tag("platform:skype"))
        );

        // Skype handle → Username.
        let users: Vec<&Entity> = es
            .iter()
            .filter(|e| e.kind == EntityKind::Username)
            .collect();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].value, "jane.doe");

        // Addresses: the Skype location + the reviewed place (with rating + text).
        let addrs: Vec<&Entity> = es
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .collect();
        let skype_loc = addrs.iter().find(|a| a.value == "Sydney, AU").unwrap();
        assert!(skype_loc.has_tag("skype"));
        let place = addrs
            .iter()
            .find(|a| a.value == "Sydney Opera House")
            .unwrap();
        assert!(place.has_tag("google-maps"));
        let pev = &place.evidence[0];
        assert_eq!(
            pev.attributes.get("rating").map(String::as_str),
            Some("5.0")
        );
        assert_eq!(
            pev.attributes.get("review_text").map(String::as_str),
            Some("Stunning, came with family.")
        );
        assert_eq!(
            pev.attributes.get("review_date").map(String::as_str),
            Some("2024-01-15")
        );
    }

    #[test]
    fn identical_google_and_skype_names_yield_one_person() {
        let es = build(r#"{"name":"Sam Vimes","skype":{"name":"Sam Vimes"}}"#);
        assert_eq!(
            es.iter().filter(|e| e.kind == EntityKind::Person).count(),
            1
        );
    }

    #[test]
    fn handle_like_names_are_not_persons() {
        // "janedoe" (no space) and a short skype name must not become Person.
        let es = build(r#"{"name":"janedoe","skype":{"name":"jd"}}"#);
        assert!(es.iter().all(|e| e.kind != EntityKind::Person));
    }

    #[test]
    fn review_text_is_truncated_at_a_char_boundary() {
        let long = "x".repeat(400);
        let es = build(&format!(
            r#"{{"maps_reviews":[{{"place_name":"Café ☕","text":"{long}"}}]}}"#
        ));
        let place = es.iter().find(|e| e.value == "Café ☕").unwrap();
        let text = place.evidence[0].attributes.get("review_text").unwrap();
        assert_eq!(text.chars().count(), REVIEW_TEXT_CAP);
    }

    #[test]
    fn empty_response_yields_only_the_anchor() {
        let es = build("{}");
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].kind, EntityKind::Email);
    }
}
