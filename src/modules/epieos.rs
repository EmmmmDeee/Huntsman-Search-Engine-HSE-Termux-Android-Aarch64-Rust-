//! Epieos email-to-identity resolution. Key-gated (Bearer Token).
//!
//! Endpoint: `POST https://api.epieos.com/api/v1/email`
//! Auth:     Bearer Token (`HUNTSMAN_EPIEOS_KEY`).
//!
//! Extracts Google profile ID, Google Maps reviews, Skype handle,
//! and registered name from an email address.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_EPIEOS_KEY";
const SRC: &str = "epieos";

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
    #[allow(dead_code)]
    #[serde(default)]
    rating: Option<f64>,
    #[allow(dead_code)]
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    date: Option<String>,
}

#[derive(Deserialize)]
struct SkypeInfo {
    #[serde(default)]
    handle: Option<String>,
    #[allow(dead_code)]
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
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Person,
            EntityKind::Username,
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
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            let code = status.as_u16();
            if code == 429 || code == 401 || code == 403 {
                ctx.report_key_exhausted(SRC, key, code);
            }
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: EpieosResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let mut result = ModuleResult::new();
        let mut entity = target.to_entity(0.85, &ctx.scan_id);
        entity.tag("epieos");

        let mut ev = Evidence::new(SRC, format!("Epieos identity resolution for {email}"));

        if let Some(gid) = body.google_id.as_deref() {
            ev = ev.with_attr("google_id", gid);
            entity.tag("google-account");
        }
        if let Some(name) = body.name.as_deref() {
            ev = ev.with_attr("name", name);
        }
        if let Some(pic) = body.profile_picture.as_deref() {
            ev = ev.with_attr("profile_picture", pic);
        }

        if let Some(reviews) = &body.maps_reviews
            && !reviews.is_empty()
        {
            ev = ev.with_attr("maps_review_count", reviews.len().to_string());
            let places: Vec<&str> = reviews
                .iter()
                .filter_map(|r| r.place_name.as_deref())
                .take(5)
                .collect();
            if !places.is_empty() {
                ev = ev.with_attr("maps_places", places.join("; "));
                entity.tag("has-maps-reviews");
            }
        }

        if let Some(skype) = &body.skype
            && let Some(h) = skype.handle.as_deref()
        {
            ev = ev.with_attr("skype_handle", h);
            entity.tag("skype");
        }
        if let Some(cal) = &body.calendar
            && let Some(n) = cal.name.as_deref()
        {
            ev = ev.with_attr("calendar_name", n);
        }

        entity.add_evidence(ev);
        result.push(entity);

        if let Some(name) = body.name.as_deref()
            && name.len() >= 3
            && name.contains(' ')
        {
            let mut pe = Entity::new(EntityKind::Person, name, 0.75, &ctx.scan_id);
            pe.tag("epieos");
            pe.tag("google");
            pe.add_evidence(Evidence::new(
                SRC,
                format!("Google profile name for {email}"),
            ));
            result.push(pe);
        }

        if let Some(skype) = &body.skype {
            if let Some(handle) = skype.handle.as_deref()
                && handle.len() >= 3
            {
                let mut ue = Entity::new(EntityKind::Username, handle, 0.70, &ctx.scan_id);
                ue.tag("epieos");
                ue.tag("platform:skype");
                ue.add_evidence(Evidence::new(SRC, format!("Skype handle for {email}")));
                result.push(ue);
            }

            if let Some(city) = skype.city.as_deref()
                && city.len() >= 3
            {
                let location = match skype.country.as_deref() {
                    Some(c) if !c.is_empty() => format!("{city}, {c}"),
                    _ => city.to_string(),
                };
                let mut ae = Entity::new(EntityKind::Address, &location, 0.50, &ctx.scan_id);
                ae.tag("epieos");
                ae.tag("skype");
                ae.tag("geoint");
                ae.add_evidence(Evidence::new(SRC, format!("Skype location for {email}")));
                result.push(ae);
            }
        }

        if let Some(reviews) = &body.maps_reviews {
            for review in reviews.iter().take(3) {
                if let Some(place) = review.place_name.as_deref()
                    && place.len() >= 3
                {
                    let mut ae = Entity::new(EntityKind::Address, place, 0.48, &ctx.scan_id);
                    ae.tag("epieos");
                    ae.tag("google-maps");
                    ae.tag("geoint");
                    let mut rev_ev =
                        Evidence::new(SRC, format!("Google Maps review at \"{place}\" by {email}"));
                    if let Some(d) = review.date.as_deref() {
                        rev_ev = rev_ev.with_attr("review_date", d);
                    }
                    ae.add_evidence(rev_ev);
                    result.push(ae);
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let raw = r#"{
            "google_id": "1234567890",
            "name": "John Smith",
            "profile_picture": "https://lh3.googleusercontent.com/photo",
            "maps_reviews": [
                {"place_name": "Sydney Opera House", "rating": 5.0, "date": "2024-01-15"}
            ],
            "skype": {"handle": "john.smith.au", "name": "John Smith", "city": "Sydney", "country": "AU"},
            "calendar": {"name": "John Smith"}
        }"#;
        let r: EpieosResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.google_id.as_deref(), Some("1234567890"));
        assert_eq!(r.name.as_deref(), Some("John Smith"));
        assert_eq!(r.maps_reviews.unwrap().len(), 1);
        assert_eq!(r.skype.unwrap().handle.as_deref(), Some("john.smith.au"));
    }
}
