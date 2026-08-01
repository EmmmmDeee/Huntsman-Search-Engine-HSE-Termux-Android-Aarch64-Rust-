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

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
// The Gravatar request-hash + response schema are the shared Gravatar API
// contract, single-sourced in `util::gravatar` (T2.124) — imported here under
// this module's established local names so the entity-building body and its
// tests are unchanged. Only `Entry`/`Profile`/`hash` are named; the nested
// `Name`/`UrlEntry`/`PhotoEntry` are reached through field access, never by
// name, so importing them would be an unused import.
use crate::util::gravatar::{Entry as ProfileEntry, Profile as ProfileResp, hash as gravatar_hash};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

// ---------------------------------------------------------------------------
// Public module struct
// ---------------------------------------------------------------------------

pub struct ContactEnrich;

// ---------------------------------------------------------------------------
// Numverify response type
// ---------------------------------------------------------------------------

pub(super) const NUMVERIFY_KEY_ENV: &str = "HUNTSMAN_NUMVERIFY_KEY";

#[derive(Deserialize)]
pub(super) struct NumverifyResp {
    #[serde(default)]
    pub(super) valid: Option<bool>,
    #[serde(default)]
    pub(super) number: Option<String>,
    #[serde(default)]
    pub(super) local_format: Option<String>,
    #[serde(default)]
    pub(super) international_format: Option<String>,
    #[serde(default)]
    pub(super) country_prefix: Option<String>,
    #[serde(default)]
    pub(super) country_code: Option<String>,
    #[serde(default)]
    pub(super) country_name: Option<String>,
    #[serde(default)]
    pub(super) location: Option<String>,
    #[serde(default)]
    pub(super) carrier: Option<String>,
    #[serde(default)]
    pub(super) line_type: Option<String>,
}

// The Gravatar response types (`ProfileResp`/`ProfileEntry` and the nested
// name/url/photo shapes) are the shared `util::gravatar` contract, imported
// above — see that module for why they are single-sourced (T2.124).

// ---------------------------------------------------------------------------
// Evidence source constant
// ---------------------------------------------------------------------------

pub(super) const SRC: &str = "contact_enrich";

// ---------------------------------------------------------------------------
// Module trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl Module for ContactEnrich {
    fn name(&self) -> &'static str {
        "contact_enrich"
    }

    fn description(&self) -> &'static str {
        "Contact validation recon — verifies phone via Numverify and email via Gravatar"
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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Contact validation/enrichment: the People default (T1589.003 Employee
        // Names + T1591.004 Identify Roles) plus T1591.001 (Physical Locations)
        // for the Numverify/Gravatar location → Address output. Superset of the
        // default — coverage cannot regress.
        &["T1589.003", "T1591.004", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Phone,
            EntityKind::Email,
            EntityKind::Person,
            EntityKind::Username,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Url,
        ];
        KINDS
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
        let resp = ctx.http.get(&url).send_tagged(SRC).await?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            let code = status.as_u16();
            // Only mark the key exhausted for 401/403/429 — a 500 server error
            // must not evict the key from the pool.
            if crate::util::http::is_keyed_error_status(code) {
                crate::util::http::note_keyed_error(code, "numverify", key, ctx);
            }
            return Err(crate::util::http::http_status_error("contact_enrich", resp).await);
        }
        let data: NumverifyResp = crate::util::http::json_decode(SRC, resp).await?;
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

    let mut result = ModuleResult::new();
    result.entities = build_phone_entities(&body, target, transport, &ctx.scan_id);
    Ok(result)
}

/// Map a decoded Numverify validation to its entities. **Pure** (no
/// network/IO), so the validity gate, tags, and evidence folding are
/// unit-testable directly off JSON fixtures.
///
/// Returns empty unless the number is `valid`; the subject `Phone` carries the
/// `numverify`/`validated`/`transport:`/`country:`/`line:` tags and folds the
/// present optional fields into one evidence record. `transport` is the scheme
/// the caller's request actually succeeded over (https/http fallback).
pub(super) fn build_phone_entities(
    body: &NumverifyResp,
    target: &Target,
    transport: &'static str,
    scan_id: &str,
) -> Vec<Entity> {
    if body.valid != Some(true) {
        return Vec::new();
    }

    let mut entity = target.to_entity(0.92, scan_id);
    entity.tag("numverify");
    entity.tag("validated");
    entity.tag(format!("transport:{transport}"));
    // Skip a blank country code (no `country:` tag for an empty string).
    if let Some(c) = body.country_code.as_deref().filter(|c| !c.is_empty()) {
        entity.tag(format!("country:{}", c.to_uppercase()));
    }
    if let Some(lt) = body.line_type.as_deref()
        && !lt.is_empty()
    {
        entity.tag(format!("line:{lt}"));
    }

    // Fold the present optional fields into the evidence in one pass.
    let ev = [
        ("normalised", body.number.as_deref()),
        ("international", body.international_format.as_deref()),
        ("local", body.local_format.as_deref()),
        ("country_prefix", body.country_prefix.as_deref()),
        ("country", body.country_name.as_deref()),
        ("location", body.location.as_deref()),
        ("carrier", body.carrier.as_deref()),
        ("line_type", body.line_type.as_deref()),
    ]
    .into_iter()
    // Skip blank/empty evidence attributes (dead-field hygiene).
    .filter_map(|(k, v)| v.filter(|val| !val.is_empty()).map(|val| (k, val)))
    .fold(
        Evidence::new(
            SRC,
            format!("Numverify confirmed valid phone {}", target.value),
        )
        .with_attr("transport", transport),
        |ev, (k, val)| ev.with_attr(k, val),
    );
    entity.add_evidence(ev);

    let mut result = vec![entity];

    // A Numverify `location` reflects the phone's registration/porting
    // record, not necessarily the subject's current physical location —
    // tagged distinctly and at a lower confidence than the Gravatar
    // `current_location` -> Address promotion below.
    if let Some(loc) = body.location.as_deref()
        && loc.trim().len() >= 3
    {
        let mut ae = Entity::new(EntityKind::Address, loc, confidence::LOW, scan_id);
        ae.tag("numverify");
        ae.tag("geoint");
        ae.tag("phone-registration");
        if let Some(sc) = crate::util::address_au::single_state_code(loc) {
            ae.tag(format!("au-state:{sc}"));
            ae.tag("country:AU");
        }
        ae.add_evidence(Evidence::new(
            SRC,
            format!("Numverify location for {}", target.value),
        ));
        if let Some((lat, lon)) = crate::util::city_coords::city_coords(loc) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                confidence::TENTATIVE,
                scan_id,
            );
            c.tag("numverify");
            c.tag("addr-derived");
            c.tag("geoint");
            c.add_evidence(Evidence::new(
                SRC,
                format!("Geocode of Numverify location for {}", target.value),
            ));
            result.push(c);
        }
        result.push(ae);
    }

    result
}

// ---------------------------------------------------------------------------
// Email path: Gravatar (free, no key)
// ---------------------------------------------------------------------------

async fn process_email(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    if !target.value.contains('@') {
        return Ok(ModuleResult::new());
    }

    // Canonical Gravatar form — trimmed + lowercased (the spec) — used for BOTH
    // the lookup hash and the evidence display so they agree. (Previously the
    // `normalised` binding was never normalised and the hash missed.)
    let normalised = target.value.trim().to_lowercase();
    let hash = gravatar_hash(&normalised);
    let url = format!("https://www.gravatar.com/{hash}.json");

    // Intentionally manual rather than using `util::http::fetch_json_or_404`:
    // Gravatar's placeholder profiles return 200 + non-JSON body, and
    // the helper would surface that as a `module_error`. The
    // silent-treat-as-empty behaviour below is the documented contract.
    let resp = ctx.http.get(&url).send_tagged(SRC).await?;

    let status = resp.status();
    if status.as_u16() == 404 {
        // No Gravatar profile -- not a finding.
        return Ok(ModuleResult::new());
    }
    if !status.is_success() {
        return Err(crate::util::http::http_status_error("contact_enrich", resp).await);
    }

    let data: ProfileResp = match crate::util::http::json_scanned(resp, SRC).await {
        Ok(d) => d,
        // Placeholder profile -> no findings (not a module error).
        Err(_) => return Ok(ModuleResult::new()),
    };

    let Some(entry) = data.entry.into_iter().next() else {
        return Ok(ModuleResult::new());
    };

    let mut result = ModuleResult::new();
    result.entities = build_email_entities(&entry, target, &normalised, &hash, &ctx.scan_id);
    Ok(result)
}

/// Map a decoded Gravatar profile entry to its entities. **Pure** (no
/// network/IO), so the profile→Person/Username/Address/Url derivation is
/// unit-testable directly off JSON fixtures.
///
/// `normalised` is the queried email (used in evidence summaries) and `hash`
/// its md5 (used for the profile URL). The subject email entity is always
/// emitted; the `Person` (formatted name with a space, ≥3 chars), `Username`
/// (≥3 chars), `Address` (location ≥3 chars, AU-state-tagged when recognised),
/// and `Url` pivots (http(s) links) each appear only when present.
pub(super) fn build_email_entities(
    entry: &ProfileEntry,
    target: &Target,
    normalised: &str,
    hash: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut entity = target.to_entity(confidence::EXPERT, scan_id);
    entity.tag("gravatar");
    let mut ev = Evidence::new(SRC, format!("Gravatar profile for {normalised}"))
        .with_attr("md5", hash)
        .with_attr("profile_url", format!("https://www.gravatar.com/{hash}"));
    // Skip blank/empty evidence attributes (dead-field hygiene).
    if let Some(d) = entry.display_name.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("display_name", d);
    }
    if let Some(u) = entry
        .preferred_username
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        ev = ev.with_attr("preferred_username", u);
    }
    if let Some(n) = entry
        .name
        .as_ref()
        .and_then(|n| n.formatted.as_deref())
        .filter(|s| !s.is_empty())
    {
        ev = ev.with_attr("name", n);
    }
    if let Some(loc) = entry.current_location.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("location", loc);
    }
    if let Some(bio) = entry.about_me.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("bio", bio);
    }
    if let Some(avatar) = entry
        .photos
        .first()
        .and_then(|p| p.value.as_deref())
        .filter(|s| !s.is_empty())
    {
        ev = ev.with_attr("avatar_url", avatar);
    }
    let urls: Vec<String> = entry
        .urls
        .iter()
        .filter_map(|u| {
            let v = u.value.as_deref()?;
            let t = u.title.as_deref().unwrap_or("link");
            Some(format!("{t}: {v}"))
        })
        .collect();
    if !urls.is_empty() {
        ev = ev.with_attr("urls", urls.join(" | "));
    }
    entity.add_evidence(ev);

    let mut result = ModuleResult::new();
    result.push(entity);

    if let Some(name) = entry.name.as_ref().and_then(|n| n.formatted.as_deref())
        && name.len() >= 3
        && name.contains(' ')
    {
        let mut pe = Entity::new(EntityKind::Person, name, confidence::VERY_HIGH, scan_id);
        pe.tag("gravatar");
        pe.add_evidence(Evidence::new(
            SRC,
            format!("Gravatar name for {normalised}"),
        ));
        result.push(pe);
    }
    if let Some(username) = entry.preferred_username.as_deref()
        && username.len() >= 3
    {
        let mut ue = Entity::new(
            EntityKind::Username,
            username,
            confidence::HIGH_PLUS,
            scan_id,
        );
        ue.tag("gravatar");
        ue.add_evidence(Evidence::new(
            SRC,
            format!("Gravatar username for {normalised}"),
        ));
        result.push(ue);
    }
    if let Some(loc) = entry.current_location.as_deref()
        && loc.len() >= 3
    {
        let mut ae = Entity::new(EntityKind::Address, loc, confidence::MEDIUM_HIGH, scan_id);
        ae.tag("gravatar");
        ae.tag("geoint");
        if let Some(sc) = crate::util::address_au::single_state_code(loc) {
            ae.tag(format!("au-state:{sc}"));
            ae.tag("country:AU");
        }
        ae.add_evidence(Evidence::new(
            SRC,
            format!("Gravatar location for {normalised}"),
        ));
        if let Some((lat, lon)) = crate::util::city_coords::city_coords(loc) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                confidence::LOW_MEDIUM,
                scan_id,
            );
            c.tag("gravatar");
            c.tag("addr-derived");
            c.tag("geoint");
            c.add_evidence(Evidence::new(
                SRC,
                format!("Geocode of Gravatar location for {normalised}"),
            ));
            result.push(c);
        }
        result.push(ae);
    }
    result.extend(entry.urls.iter().filter_map(|url_entry| {
        let url = url_entry.value.as_deref()?;
        if !url.starts_with("http") {
            return None;
        }
        let mut ue = Entity::new(EntityKind::Url, url, confidence::MEDIUM_PLUS, scan_id);
        ue.tag("gravatar");
        ue.add_evidence(Evidence::new(
            SRC,
            format!("Gravatar link for {normalised}"),
        ));
        Some(ue)
    }));

    result.entities
}
