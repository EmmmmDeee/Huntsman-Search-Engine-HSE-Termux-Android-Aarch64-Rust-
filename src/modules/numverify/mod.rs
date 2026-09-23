//! NumVerify phone validation — live carrier, line type & region for a number.
//!
//! Endpoint: `GET https://api.apilayer.com/number_verification/validate?number=…`
//! Auth:     `apikey` header. Key-gated (`HUNTSMAN_NUMVERIFY_KEY`, free tier
//!           available). Inert with no key.
//!
//! Upgrades the project's *offline* phone-geo tables (`phone_intl`,
//! `phone_geo`) to authoritative live data: for a `+61` (or any) number
//! it returns validity, **carrier**, **line type** (mobile/landline/voip), and
//! **region** — emitted as a geocodable `Address` plus carrier/line evidence,
//! and the subject `Phone` itself confirmed `validated`.
//!
//! **The one Numverify caller (REQ-CRED-001).** `contact_enrich` used to query
//! Numverify's legacy `apilayer.net` host for the same `Phone` targets. It put
//! the key in the query string (`?access_key=`), resent that URL over
//! plaintext `http://` on any failure, and marked the shared `numverify` pool
//! key Invalid when the legacy host answered `200 {"success":false}`. The
//! legacy host gives that answer to a key it does not recognise (live,
//! 2026-09-23: code 101 `invalid_access_key`), while the key the `numverify`
//! `ServiceDef` validates is this gateway's. Each `Phone` also cost two calls
//! of the free tier. Its validated-`Phone` entity now comes from here, over
//! one host and one auth contract, so `HUNTSMAN_NUMVERIFY_KEY` is sent nowhere
//! else.
//!
//! The response→entity mapping is the pure `build_entities` (unit-tested); the
//! network shell, `validate`, owns only auth/transport and the status verdict.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

/// The evidence source for everything minted from a Numverify answer. Private:
/// this module is the only one that asks Numverify (REQ-CRED-001), so no other
/// module has a Numverify answer to attribute.
const SRC: &str = "numverify";
const KEY_ENV: &str = "HUNTSMAN_NUMVERIFY_KEY";

/// The APILayer gateway's Number Verification API: the one host and auth
/// contract `HUNTSMAN_NUMVERIFY_KEY` is used under, and the one the `numverify`
/// `ServiceDef` probes. HTTPS only. The vendor's reference says "All API
/// requests must be made over HTTPS. Calls made over plain HTTP will fail."
/// There is deliberately no plaintext fallback (REQ-CRED-001).
const API_BASE: &str = "https://api.apilayer.com/number_verification";

pub struct NumVerify;

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct NvResp {
    valid: bool,
    /// The number as Numverify normalised it (E.164 digits, no `+`).
    number: Option<String>,
    local_format: Option<String>,
    country_prefix: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    location: Option<String>,
    carrier: Option<String>,
    line_type: Option<String>,
    international_format: Option<String>,
}

#[async_trait]
impl Module for NumVerify {
    fn name(&self) -> &'static str {
        "numverify"
    }

    fn description(&self) -> &'static str {
        "NumVerify phone validation — confirms the number and probes live carrier, line type, and region (key-gated)"
    }

    fn priority(&self) -> u8 {
        139
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Phone)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Phone
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Phone default (T1589 Gather Victim Identity Information) is correct for
        // phone number lookup, but numverify also maps the carrier country to an
        // Address entity — Determine Physical Locations (T1591.001).
        &["T1589", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Phone,
            EntityKind::Address,
            EntityKind::Organisation,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let Some(parsed) = validate(ctx, API_BASE, key, target.value.trim()).await? else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result
            .entities
            .extend(build_entities(&parsed, target, &ctx.scan_id));
        Ok(result)
    }
}

/// Ask Numverify about `number`: the request and its status verdict, in one
/// place (REQ-CRED-001).
///
/// The key travels only in the `apikey` header, never in the URL. A URL is
/// what proxies, access logs and archive labels record. `contact_enrich`'s
/// `?access_key=` did exactly that, then repeated it in cleartext. The verdict
/// is the shared keyed one ([`crate::util::http::keyed_ok_or_404`]): 401/403/429
/// burn the key, 404 is a clean miss (`None`), any other non-2xx is an error.
/// The gateway reports a refused key as a 401 (live, 2026-09-23: `{"message":
/// "Invalid authentication credentials"}`), not as a 200 envelope, so the
/// legacy host's in-body `success:false` check has no counterpart here.
///
/// `base` is a parameter only so the loopback tests can drive the real request
/// path; `process` always passes [`API_BASE`].
async fn validate(
    ctx: &ModuleContext,
    base: &str,
    key: &str,
    number: &str,
) -> Result<Option<NvResp>> {
    let url = format!("{base}/validate?number={}", urlencode(number));
    let resp = ctx
        .http
        .get(&url)
        .header("apikey", key)
        .send_tagged(SRC)
        .await?;
    let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
        return Ok(None);
    };
    crate::util::http::json_scanned(resp, SRC).await.map(Some)
}

/// Map a validation response to entities. **Pure** (no network/IO).
///
/// Returns an empty `Vec` when the number is not `valid`. Otherwise the
/// subject `Phone`, confirmed ([`validated_phone`]), then the
/// [`region_entities`].
fn build_entities(r: &NvResp, target: &Target, scan_id: &str) -> Vec<Entity> {
    if !r.valid {
        return Vec::new();
    }
    let mut out = vec![validated_phone(r, target, scan_id)];
    out.extend(region_entities(r, scan_id));
    out
}

/// The subject `Phone`, confirmed valid by Numverify, tagged
/// `numverify`/`validated`/`country:`/`line:`, with the present optional
/// fields folded into one evidence record. `contact_enrich` minted this entity
/// until REQ-CRED-001 moved it here, beside the only Numverify request.
///
/// EXPERT is the crate-wide tier for "a third-party API confirmed the target is
/// valid" (`criminal_ip` and `contact_enrich`'s Gravatar path use it too); the
/// earlier bare 0.92 scored the same claim a full tier above every sibling.
/// There is no `transport:` tag. The only transport is HTTPS, so the tag could
/// only ever say one thing.
fn validated_phone(r: &NvResp, target: &Target, scan_id: &str) -> Entity {
    let mut entity = target.to_entity(confidence::EXPERT, scan_id);
    entity.tag(SRC);
    entity.tag("validated");
    // Skip a blank country code (no `country:` tag for an empty string).
    if let Some(c) = r.country_code.as_deref().filter(|c| !c.is_empty()) {
        entity.tag(format!("country:{}", c.to_uppercase()));
    }
    if let Some(lt) = r.line_type.as_deref().filter(|lt| !lt.is_empty()) {
        entity.tag(format!("line:{lt}"));
    }
    let ev = [
        ("normalised", r.number.as_deref()),
        ("international", r.international_format.as_deref()),
        ("local", r.local_format.as_deref()),
        ("country_prefix", r.country_prefix.as_deref()),
        ("country", r.country_name.as_deref()),
        ("location", r.location.as_deref()),
        ("carrier", r.carrier.as_deref()),
        ("line_type", r.line_type.as_deref()),
    ]
    .into_iter()
    // Skip blank/empty evidence attributes (dead-field hygiene).
    .filter_map(|(k, v)| v.filter(|val| !val.is_empty()).map(|val| (k, val)))
    .fold(
        Evidence::new(
            SRC,
            format!("Numverify confirmed valid phone {}", target.value),
        ),
        |ev, (k, val)| ev.with_attr(k, val),
    );
    entity.add_evidence(ev);
    entity
}

/// The place a valid number is registered to: an `Address` (geocodable
/// region/country), its `Coordinates` when the place is a known city, and,
/// when the carrier is present, an `Organisation` for the carrier —
/// consistent with ip2location/ipquery which emit the ISP as an Organisation
/// pivot. Empty when the answer carries no usable region or country.
fn region_entities(r: &NvResp, scan_id: &str) -> Vec<Entity> {
    // A geocodable place string from region + country (either may be absent).
    let region = r
        .location
        .as_deref()
        .map(str::trim)
        .filter(|s| s.len() >= 2);
    let country = r
        .country_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let place = match (region, country) {
        (Some(reg), Some(c)) => format!("{reg}, {c}"),
        (Some(reg), None) => reg.to_string(),
        (None, Some(c)) => c.to_string(),
        (None, None) => return Vec::new(),
    };

    let mut out = Vec::new();

    let mut e = Entity::new(
        EntityKind::Address,
        &place,
        confidence::MEDIUM_HIGH,
        scan_id,
    );
    e.tag(SRC);
    e.tag("geo-hint");
    e.tag("phone-region");
    let mut ev = Evidence::new(SRC, "NumVerify phone metadata");
    if let Some(c) = r.carrier.as_deref().filter(|c| !c.is_empty()) {
        e.tag("carrier-known");
        ev = ev.with_attr("carrier", c);
    }
    if let Some(lt) = r.line_type.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("line_type", lt);
        e.tag(format!("line:{lt}"));
    }
    if let Some(cc) = &r.country_code {
        ev = ev.with_attr("country_code", cc);
    }
    if let Some(intl) = &r.international_format {
        ev = ev.with_attr("international_format", intl);
    }
    e.add_evidence(ev.clone());
    out.push(e);
    if let Some((lat, lon)) = crate::util::city_coords::city_coords(&place) {
        let coord_val = format!("{lat:.4},{lon:.4}");
        out.push(
            Entity::builder(
                EntityKind::Coordinates,
                &coord_val,
                confidence::LOW_MEDIUM,
                scan_id,
            )
            .tags([SRC, "addr-derived", "geoint", "phone-region"])
            .evidence(ev)
            .build(),
        );
    }

    // Carrier → Organisation pivot (same pattern as ip2location ISP extraction).
    if let Some(carrier) = r.carrier.as_deref().map(str::trim).filter(|c| c.len() >= 2) {
        out.push(
            Entity::builder(
                EntityKind::Organisation,
                carrier,
                confidence::MEDIUM_PLUS,
                scan_id,
            )
            .tags([SRC, "carrier"])
            .evidence(Evidence::new(SRC, format!("Phone carrier: {carrier}")))
            .build(),
        );
    }

    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
