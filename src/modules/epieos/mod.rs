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

#[cfg(test)]
mod tests;

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

pub(super) const KEY_ENV: &str = "HUNTSMAN_EPIEOS_KEY";
pub(super) const SRC: &str = "epieos";

/// Maps-review places surfaced inline on the email entity / emitted as Address.
pub(super) const MAX_PLACES_INLINE: usize = 5;
pub(super) const MAX_PLACE_ENTITIES: usize = 3;

pub struct Epieos;

#[derive(Deserialize)]
pub(super) struct EpieosResp {
    #[serde(default)]
    pub(super) google_id: Option<String>,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) profile_picture: Option<String>,
    #[serde(default)]
    pub(super) maps_reviews: Option<Vec<MapsReview>>,
    #[serde(default)]
    pub(super) skype: Option<SkypeInfo>,
    #[serde(default)]
    pub(super) calendar: Option<CalendarInfo>,
}

#[derive(Deserialize)]
pub(super) struct MapsReview {
    #[serde(default)]
    pub(super) place_name: Option<String>,
    #[serde(default)]
    pub(super) rating: Option<f64>,
    #[serde(default)]
    pub(super) text: Option<String>,
    #[serde(default)]
    pub(super) date: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct SkypeInfo {
    #[serde(default)]
    pub(super) handle: Option<String>,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) city: Option<String>,
    #[serde(default)]
    pub(super) country: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct CalendarInfo {
    #[serde(default)]
    pub(super) name: Option<String>,
}

use crate::util::str_util::nonempty;

/// A display string that is plausibly a real person name (a multi-word label),
/// not a handle — the bar for promoting it to a `Person` entity.
pub(super) fn is_person_name(s: &str) -> bool {
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
pub(super) fn build_entities(target: &Target, body: &EpieosResp, scan_id: &str) -> Vec<Entity> {
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

    // ── Person leads from each DISTINCT real name (Google + Skype + Calendar) ─
    let mut seen_names = HashSet::new();
    for (label, conf, name) in [
        ("google", 0.75, nonempty(&body.name)),
        (
            "platform:skype",
            0.70,
            skype.and_then(|s| nonempty(&s.name)),
        ),
        (
            "google-calendar",
            0.68,
            body.calendar.as_ref().and_then(|c| nonempty(&c.name)),
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
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&location) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.42, scan_id);
                c.tag("epieos");
                c.tag("addr-derived");
                c.tag("geoint");
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Geocode of Skype location for {email}"),
                ));
                out.push(c);
            }
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
                // Full-fidelity policy: the review is stored verbatim, never
                // truncated — the operator sees the authentic discovered content.
                rev_ev = rev_ev.with_attr("review_text", text);
            }
            if let Some(d) = nonempty(&review.date) {
                rev_ev = rev_ev.with_attr("review_date", d);
            }
            ae.add_evidence(rev_ev);
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(place) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.42, scan_id);
                c.tag("epieos");
                c.tag("addr-derived");
                c.tag("geoint");
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Geocode of Maps review place '{place}' for {email}"),
                ));
                out.push(c);
            }
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

    /// Email-to-identity resolution is stable for ~24h per target; cache to avoid re-burning key-gated Epieos quota.
    fn cache_ttl_secs(&self) -> u64 {
        86_400
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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // People default (T1589.003 Employee Names + T1591.004 Identify Roles).
        // Epieos also surfaces the email address itself (T1589.002) and maps the
        // owner's location to an Address entity (T1591.001 Physical Locations).
        // T1591.004 is dropped — epieos carries no role/job information.
        &["T1589.002", "T1589.003", "T1591.001"]
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
            EntityKind::Coordinates,
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

        // json_scanned: epieos responses include Google review text (free-form
        // user content) that may contain embedded API keys.
        let body: EpieosResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| crate::core::error::Error::module(SRC, e))?;

        let mut result = ModuleResult::new();
        result.extend(build_entities(target, &body, &ctx.scan_id));
        Ok(result)
    }
}
