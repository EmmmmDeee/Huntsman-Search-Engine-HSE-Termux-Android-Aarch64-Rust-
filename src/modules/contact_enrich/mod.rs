//! Contact enrichment: email profile lookup via Gravatar.
//!
//! `Email` targets are dispatched to Gravatar (free, no key).
//!
//! Gravatar endpoint:
//!   `GET https://www.gravatar.com/{md5}.json`
//!
//! **No phone leg (REQ-CRED-001).** This module used to validate `Phone`
//! targets against Numverify's legacy `apilayer.net` host itself. It sent the
//! key in the query string (`?access_key=`), and on ANY failure resent the
//! same URL over plaintext `http://`, so the key and the subject's number
//! crossed the network in cleartext. It marked the shared `numverify` pool key
//! Invalid whenever the legacy host answered `200 {"success":false}`. That is
//! the legacy host's answer to a key it does not recognise, while the key the
//! `numverify` `ServiceDef` validates is the APILayer gateway's. Whether the
//! legacy host recognises a gateway key is unverified; where it does not,
//! every `Phone` target invalidated a working key. And it ran beside the
//! `numverify` module on the same target, so every `Phone` cost two calls of
//! the free tier. Phone validation, and the validated-`Phone` entity this
//! module used to mint, now belong to the `numverify` module alone.

#[cfg(test)]
mod tests;

use async_trait::async_trait;

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

// ---------------------------------------------------------------------------
// Public module struct
// ---------------------------------------------------------------------------

pub struct ContactEnrich;

// The Gravatar response types (`ProfileResp`/`ProfileEntry` and the nested
// name/url/photo shapes) are the shared `util::gravatar` contract, imported
// above — see that module for why they are single-sourced (T2.124).

// ---------------------------------------------------------------------------
// Evidence source constant
// ---------------------------------------------------------------------------

/// This module's name — on its HTTP requests and its errors only. Every
/// entity it mints comes from a corpus another registered module also serves
/// (Gravatar's profile document), so the EVIDENCE is attributed to that
/// provider's `SRC`: stamping `contact_enrich` on a Gravatar row let the same
/// record, fetched by both modules, merge into one entity carrying two
/// "independent" sources (SOURCE COUNT ≠ SOURCE INDEPENDENCE — the class
/// `tests/architecture_parts/architecture_part7.rs` guards).
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
        "Contact enrichment recon — resolves an email's public Gravatar profile"
    }

    fn priority(&self) -> u8 {
        85
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // Email only. A `Phone` is the `numverify` module's (REQ-CRED-001).
        matches!(t.kind, TargetKind::Email)
    }

    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Contact enrichment: the People default (T1589.003 Employee Names +
        // T1591.004 Identify Roles) plus T1591.001 (Physical Locations) for the
        // Gravatar location → Address output. Superset of the default —
        // coverage cannot regress.
        &["T1589.003", "T1591.004", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
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
            TargetKind::Email => process_email(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
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

    // Manual rather than `util::http::fetch_json_or_404` so the 404 arm can be spelled out:
    // Gravatar answers a plain 404 (`"User not found"`) for an address with no public profile,
    // which is the common case and a real absence, not a failure.
    //
    // This previously carried a second rationale — that Gravatar's "placeholder profiles return
    // 200 + non-JSON body" — used to justify swallowing a JSON decode failure. Probing the live
    // endpoint could not reproduce it: every response observed was `application/json`, either a
    // 200 profile document or a 404 `"User not found"`. Note `www.gravatar.com` answers 302 to a
    // localized host; our client follows redirects (see `util::http::ssrf::client_builder`), so
    // the final response is what reaches the decode below.
    let resp = ctx.http.get(&url).send_tagged(SRC).await?;

    let status = resp.status();
    if status.as_u16() == 404 {
        // No Gravatar profile -- not a finding.
        return Ok(ModuleResult::new());
    }
    if !status.is_success() {
        return Err(crate::util::http::http_status_error("contact_enrich", resp).await);
    }

    // Fail closed on a body that does not decode. A 2xx from a JSON API that is not JSON is
    // anomalous — schema drift, a truncated body, an interstitial — not an absence of profile
    // data, and the absence case already returned above on the 404. This was the ONLY one of the
    // ~20 `json_scanned` call sites in `src/modules/` that swallowed the decode error into an
    // empty result; every other propagates it.
    let data: ProfileResp = crate::util::http::json_scanned(resp, SRC).await?;

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
    let mut ev = Evidence::new(
        crate::modules::gravatar::SRC,
        format!("Gravatar profile for {normalised}"),
    )
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
            crate::modules::gravatar::SRC,
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
            crate::modules::gravatar::SRC,
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
            crate::modules::gravatar::SRC,
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
                crate::modules::gravatar::SRC,
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
            crate::modules::gravatar::SRC,
            format!("Gravatar link for {normalised}"),
        ));
        Some(ue)
    }));

    result.entities
}
