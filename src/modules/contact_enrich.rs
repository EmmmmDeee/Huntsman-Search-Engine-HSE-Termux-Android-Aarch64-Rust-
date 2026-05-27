//! Merged contact-enrichment module: phone validation via Numverify
//! and email profile lookup via Gravatar.
//!
//! `Phone` targets are dispatched to the Numverify API (key-gated,
//! env `HUNTSMAN_NUMVERIFY_KEY`, gracefully skipped when absent).
//! `Email` targets are dispatched to Gravatar (free, no key).
//!
//! Numverify endpoint:
//!   `GET https://apilayer.net/api/validate?access_key={KEY}&number={E164}`
//!
//! Gravatar endpoint:
//!   `GET https://www.gravatar.com/{md5}.json`

use async_trait::async_trait;
use md5::{Digest, Md5};
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, urlencode};

// ---------------------------------------------------------------------------
// Public module struct
// ---------------------------------------------------------------------------

pub struct ContactEnrich;

// ---------------------------------------------------------------------------
// Numverify response type
// ---------------------------------------------------------------------------

const NUMVERIFY_KEY_ENV: &str = "HUNTSMAN_NUMVERIFY_KEY";

#[derive(Deserialize)]
struct NumverifyResp {
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    number: Option<String>,
    #[serde(default)]
    local_format: Option<String>,
    #[serde(default)]
    international_format: Option<String>,
    #[serde(default)]
    country_prefix: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    carrier: Option<String>,
    #[serde(default)]
    line_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Gravatar response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ProfileResp {
    entry: Vec<ProfileEntry>,
}

#[derive(Deserialize)]
struct ProfileEntry {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "preferredUsername")]
    preferred_username: Option<String>,
    #[serde(default)]
    name: Option<NameField>,
    #[serde(default)]
    urls: Vec<UrlEntry>,
    #[serde(rename = "currentLocation")]
    location: Option<String>,
    #[serde(rename = "aboutMe")]
    about_me: Option<String>,
    #[serde(default)]
    photos: Option<Vec<PhotoEntry>>,
}

#[derive(Deserialize)]
struct NameField {
    formatted: Option<String>,
}

#[derive(Deserialize)]
struct UrlEntry {
    value: Option<String>,
    title: Option<String>,
}

#[derive(Deserialize)]
struct PhotoEntry {
    value: Option<String>,
}

// ---------------------------------------------------------------------------
// Evidence source constant
// ---------------------------------------------------------------------------

const SRC: &str = "contact_enrich";

// ---------------------------------------------------------------------------
// Module trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl Module for ContactEnrich {
    fn name(&self) -> &'static str {
        "contact_enrich"
    }

    fn description(&self) -> &'static str {
        "Contact validation: phone via Numverify, email via Gravatar"
    }

    fn priority(&self) -> u8 {
        85
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Phone | TargetKind::Email)
    }

    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::Phone => process_phone(target, ctx).await,
            TargetKind::Email => process_email(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Phone path: Numverify (key-gated, graceful skip)
// ---------------------------------------------------------------------------

async fn process_phone(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    // Graceful skip when the API key is not configured.
    let key = match ctx.key(NUMVERIFY_KEY_ENV) {
        Ok(k) => k,
        Err(_) => return Ok(ModuleResult::new()),
    };

    let mut phone = String::with_capacity(target.value.len());
    phone.extend(
        target
            .value
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '+'),
    );
    if phone.is_empty() {
        return Ok(ModuleResult::new());
    }
    // Numverify accepts both formats; strip leading '+' since their
    // examples use E.164 without it.
    let q = phone.trim_start_matches('+');
    if q.is_empty() {
        return Ok(ModuleResult::new());
    }
    let qs = format!(
        "/api/validate?access_key={}&number={}",
        urlencode(key),
        urlencode(q),
    );

    // HTTPS first. If the call fails outright (free-tier rejection,
    // TLS refusal), fall back to HTTP and remember the transport
    // we ended up using.
    let try_url = |url: String| async move {
        let resp = ctx
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::module("contact_enrich", e.to_string()))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            let code = status.as_u16();
            if code == 429 || code == 401 || code == 403 {
                ctx.report_key_exhausted("numverify", key, code);
            }
            return Err(Error::module(
                "contact_enrich",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }
        let data: NumverifyResp = resp
            .json()
            .await
            .map_err(|e| Error::module("contact_enrich", e.to_string()))?;
        Ok(Some(data))
    };

    let https = format!("https://apilayer.net{qs}");
    let (body_opt, transport): (Option<NumverifyResp>, &'static str) = match try_url(https).await {
        Ok(b) => (b, "https"),
        Err(_) => {
            let http = format!("http://apilayer.net{qs}");
            (try_url(http).await?, "http")
        }
    };

    let Some(body) = body_opt else {
        return Ok(ModuleResult::new());
    };
    if body.valid != Some(true) {
        return Ok(ModuleResult::new());
    }

    let mut entity = target.to_entity(0.92, &ctx.scan_id);
    entity.tag("numverify");
    entity.tag("validated");
    entity.tag(format!("transport:{transport}"));
    if let Some(c) = body.country_code.as_deref() {
        entity.tag(format!("country:{}", c.to_uppercase()));
    }
    if let Some(lt) = body.line_type.as_deref()
        && !lt.is_empty()
    {
        entity.tag(format!("line:{lt}"));
    }

    let mut ev = Evidence::new(
        SRC,
        format!("Numverify confirmed valid phone {}", target.value),
    )
    .with_attr("transport", transport);
    if let Some(v) = body.number.as_deref() {
        ev = ev.with_attr("normalised", v);
    }
    if let Some(v) = body.international_format.as_deref() {
        ev = ev.with_attr("international", v);
    }
    if let Some(v) = body.local_format.as_deref() {
        ev = ev.with_attr("local", v);
    }
    if let Some(v) = body.country_prefix.as_deref() {
        ev = ev.with_attr("country_prefix", v);
    }
    if let Some(v) = body.country_name.as_deref() {
        ev = ev.with_attr("country", v);
    }
    if let Some(v) = body.location.as_deref() {
        ev = ev.with_attr("location", v);
    }
    if let Some(v) = body.carrier.as_deref() {
        ev = ev.with_attr("carrier", v);
    }
    if let Some(v) = body.line_type.as_deref() {
        ev = ev.with_attr("line_type", v);
    }
    entity.add_evidence(ev);

    let mut result = ModuleResult::new();
    result.push(entity);
    Ok(result)
}

// ---------------------------------------------------------------------------
// Email path: Gravatar (free, no key)
// ---------------------------------------------------------------------------

async fn process_email(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let normalised = target.value.trim().to_lowercase();
    if !normalised.contains('@') {
        return Ok(ModuleResult::new());
    }

    let mut hasher = Md5::new();
    hasher.update(normalised.as_bytes());
    let hash = hex::encode(hasher.finalize());

    let url = format!("https://www.gravatar.com/{hash}.json");

    // Intentionally manual rather than using `util::http::fetch_json_or_404`:
    // Gravatar's placeholder profiles return 200 + non-JSON body, and
    // the helper would surface that as a `module_error`. The
    // silent-treat-as-empty behaviour below is the documented contract.
    let resp = ctx
        .http
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::module("contact_enrich", e.to_string()))?;

    let status = resp.status();
    if status.as_u16() == 404 {
        // No Gravatar profile -- not a finding.
        return Ok(ModuleResult::new());
    }
    if !status.is_success() {
        return Err(Error::module(
            "contact_enrich",
            format!("HTTP {status}: {}", error_snippet(resp).await),
        ));
    }

    let data: ProfileResp = match resp.json().await {
        Ok(d) => d,
        // Placeholder profile -> no findings (not a module error).
        Err(_) => return Ok(ModuleResult::new()),
    };

    let Some(entry) = data.entry.into_iter().next() else {
        return Ok(ModuleResult::new());
    };

    let mut entity = target.to_entity(0.88, &ctx.scan_id);
    entity.tag("gravatar");
    let mut ev = Evidence::new(SRC, format!("Gravatar profile for {normalised}"))
        .with_attr("md5", &hash)
        .with_attr("profile_url", format!("https://www.gravatar.com/{hash}"));
    if let Some(d) = entry.display_name.as_deref() {
        ev = ev.with_attr("display_name", d);
    }
    if let Some(u) = entry.preferred_username.as_deref() {
        ev = ev.with_attr("preferred_username", u);
    }
    if let Some(n) = entry.name.as_ref().and_then(|n| n.formatted.as_deref()) {
        ev = ev.with_attr("name", n);
    }
    if let Some(loc) = entry.location.as_deref() {
        ev = ev.with_attr("location", loc);
    }
    if let Some(bio) = entry.about_me.as_deref() {
        ev = ev.with_attr("bio", bio);
    }
    if let Some(avatar) = entry
        .photos
        .as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.value.as_deref())
    {
        ev = ev.with_attr("avatar_url", avatar);
    }
    if !entry.urls.is_empty() {
        let mut urls_iter = entry.urls.iter().filter_map(|u| {
            let v = u.value.as_deref()?;
            let t = u.title.as_deref().unwrap_or("link");
            Some(format!("{t}: {v}"))
        });
        if let Some(first) = urls_iter.next() {
            let mut joined = first;
            for item in urls_iter {
                joined.push_str(" | ");
                joined.push_str(&item);
            }
            ev = ev.with_attr("urls", joined);
        }
    }
    entity.add_evidence(ev);

    let mut result = ModuleResult::new();
    result.push(entity);

    if let Some(name) = entry.name.as_ref().and_then(|n| n.formatted.as_deref()) {
        if name.len() >= 3 && name.contains(' ') {
            let mut pe = Entity::new(EntityKind::Person, name, 0.75, &ctx.scan_id);
            pe.tag("gravatar");
            pe.add_evidence(Evidence::new(SRC, format!("Gravatar name for {normalised}")));
            result.push(pe);
        }
    }
    if let Some(username) = entry.preferred_username.as_deref() {
        if username.len() >= 3 {
            let mut ue = Entity::new(EntityKind::Username, username, 0.70, &ctx.scan_id);
            ue.tag("gravatar");
            ue.add_evidence(Evidence::new(SRC, format!("Gravatar username for {normalised}")));
            result.push(ue);
        }
    }
    if let Some(loc) = entry.location.as_deref() {
        if loc.len() >= 3 {
            let mut ae = Entity::new(EntityKind::Address, loc, 0.55, &ctx.scan_id);
            ae.tag("gravatar");
            ae.tag("geoint");
            ae.add_evidence(Evidence::new(SRC, format!("Gravatar location for {normalised}")));
            result.push(ae);
        }
    }
    for url_entry in &entry.urls {
        if let Some(url) = url_entry.value.as_deref() {
            if url.starts_with("http") {
                let mut ue = Entity::new(EntityKind::Url, url, 0.60, &ctx.scan_id);
                ue.tag("gravatar");
                ue.add_evidence(Evidence::new(SRC, format!("Gravatar link for {normalised}")));
                result.push(ue);
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests (preserved from numverify.rs + gravatar.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_phone_and_email() {
        let m = ContactEnrich;
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+1")));
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(ContactEnrich.cost(), ModuleCost::Free));
    }

    #[test]
    fn priority_and_timeout() {
        let m = ContactEnrich;
        assert_eq!(m.priority(), 85);
        assert_eq!(m.max_timeout_ms(), 6_000);
    }

    #[test]
    fn parse_numverify_response() {
        let raw = r#"{
          "valid": true,
          "number": "14158586273",
          "local_format": "4158586273",
          "international_format": "+14158586273",
          "country_prefix": "+1",
          "country_code": "US",
          "country_name": "United States of America",
          "location": "Novato",
          "carrier": "AT&T Mobility LLC",
          "line_type": "mobile"
        }"#;
        let r: NumverifyResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.valid, Some(true));
        assert_eq!(r.country_code.as_deref(), Some("US"));
        assert_eq!(r.carrier.as_deref(), Some("AT&T Mobility LLC"));
        assert_eq!(r.line_type.as_deref(), Some("mobile"));
    }

    #[test]
    fn parse_gravatar_response() {
        let raw = r#"{
          "entry": [{
            "displayName": "John Doe",
            "preferredUsername": "johndoe",
            "name": {"formatted": "John Doe"},
            "urls": [{"value": "https://example.com", "title": "Blog"}],
            "currentLocation": "NYC",
            "aboutMe": "dev",
            "photos": [{"value": "https://gravatar.com/avatar/abc"}]
          }]
        }"#;
        let r: ProfileResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.entry.len(), 1);
        let e = &r.entry[0];
        assert_eq!(e.display_name.as_deref(), Some("John Doe"));
        assert_eq!(e.location.as_deref(), Some("NYC"));
    }
}
