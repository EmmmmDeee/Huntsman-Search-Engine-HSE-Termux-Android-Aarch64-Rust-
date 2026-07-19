//! Keybase identity graph lookup. Free, no API key required.
//!
//! Endpoints:
//!   `GET https://keybase.io/_/api/1.0/user/lookup.json?username={user}`
//!   `GET https://keybase.io/_/api/1.0/user/lookup.json?github={user}`
//!
//! Pivots from a Username target to discover linked accounts across
//! platforms (Twitter, GitHub, Reddit, HN, personal sites, PGP keys).

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

pub(super) const SRC: &str = "keybase";

pub struct Keybase;

#[derive(Deserialize)]
pub(super) struct KbResp {
    #[serde(default)]
    pub(super) status: Option<KbStatus>,
    /// The subject profile. The singular `?username=` endpoint returns `them`
    /// as a **single object** (not an array — arrays only come from the plural
    /// `?usernames=a,b` form this module never uses), so this must be a bare
    /// `Option<KbUser>`. It was previously `Option<Vec<KbUser>>`, which made
    /// serde fail every real lookup with "invalid type: map, expected a
    /// sequence" — the module yielded nothing for all inputs.
    #[serde(default)]
    pub(super) them: Option<KbUser>,
}

#[derive(Deserialize)]
pub(super) struct KbStatus {
    #[serde(default)]
    pub(super) code: Option<i32>,
}

#[derive(Deserialize)]
pub(super) struct KbUser {
    #[serde(default)]
    pub(super) id: Option<String>,
    #[serde(default)]
    pub(super) basics: Option<KbBasics>,
    #[serde(default)]
    pub(super) profile: Option<KbProfile>,
    #[serde(default)]
    pub(super) proofs_summary: Option<KbProofs>,
}

#[derive(Deserialize)]
pub(super) struct KbBasics {
    #[serde(default)]
    pub(super) username: Option<String>,
    #[serde(default)]
    pub(super) ctime: Option<i64>,
}

#[derive(Deserialize)]
pub(super) struct KbProfile {
    #[serde(default)]
    pub(super) full_name: Option<String>,
    #[serde(default)]
    pub(super) location: Option<String>,
    #[serde(default)]
    pub(super) bio: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KbProofs {
    #[serde(default)]
    pub(super) all: Vec<KbProof>,
}

#[derive(Deserialize)]
pub(super) struct KbProof {
    #[serde(default)]
    pub(super) proof_type: Option<String>,
    #[serde(default)]
    pub(super) nametag: Option<String>,
    #[serde(default)]
    pub(super) service_url: Option<String>,
    #[serde(default)]
    pub(super) state: Option<i32>,
}

#[async_trait]
impl Module for Keybase {
    fn name(&self) -> &'static str {
        "keybase"
    }
    fn description(&self) -> &'static str {
        "Keybase identity-graph recon — cross-links linked accounts, PGP keys, and cryptographic proofs"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }
    fn max_timeout_ms(&self) -> u64 {
        4_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Social default (T1593.001 Social Media + T1589.003 Employee Names) but
        // Keybase profiles surface a user-declared location string and an inline
        // geocoded Coordinates entity — both mapping to T1591.001 Physical
        // Locations, absent from the Social default.
        &["T1591.001", "T1593.001", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Username,
            EntityKind::Url,
            EntityKind::Email,
            EntityKind::Domain,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let username = target.value.trim();
        if username.is_empty() || username.len() > 64 {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://keybase.io/_/api/1.0/user/lookup.json?username={}",
            urlencode(username)
        );

        // A genuine "no such user" is a 200 body carrying `status.code != 0`
        // (Keybase never 404s a `user/lookup`), which `build_entities` already
        // maps to an empty result. So every failure `fetch_json` surfaces —
        // transport error, non-2xx status, or malformed JSON — is a real source
        // outage, not a clean miss. Propagate it via `?` instead of collapsing
        // all three into the same silent empty result a real "user absent"
        // produces, matching how sibling single-fetch modules (`urlscan`,
        // `npm_author`, …) already handle the primitive. Contract pinned by
        // `util::http::tests::fetch_json_propagates_a_non_2xx_status_as_err_not_a_silent_default`.
        let body: KbResp = crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;

        let mut result = ModuleResult::new();
        result.entities = build_entities(body, username, &ctx.scan_id);
        Ok(result)
    }
}

/// Pure profile→entity mapping for a Keybase `user/lookup` response. Owns the
/// whole record→entity transform — the `status.code == 0` gate, first-user
/// selection, the subject [`EntityKind::Username`] entity (+ folded profile
/// evidence), the `full_name` [`EntityKind::Person`] pivot, the self-reported
/// [`EntityKind::Address`] (AU-state-tagged) with its inline-geocoded
/// [`EntityKind::Coordinates`], and the verified-proof links via
/// [`extract_proofs`] — so [`Keybase::process`] is left a thin fetch→build shell
/// and every branch here is unit-testable without I/O.
pub(super) fn build_entities(body: KbResp, query_username: &str, scan_id: &str) -> Vec<Entity> {
    if body.status.as_ref().and_then(|s| s.code) != Some(0) {
        return Vec::new();
    }
    let Some(user) = body.them else {
        return Vec::new();
    };

    let mut result = ModuleResult::new();

    let kb_username = user
        .basics
        .as_ref()
        .and_then(|b| b.username.as_deref())
        .unwrap_or(query_username);

    let mut entity = Entity::new(EntityKind::Username, kb_username, confidence::VERY_HIGH_PLUS, scan_id);
    entity.tag("keybase");

    let proof_count = user.proofs_summary.as_ref().map_or(0, |p| p.all.len());
    let profile = user.profile.as_ref();
    let ev = [
        (
            "created_at_unix",
            user.basics
                .as_ref()
                .and_then(|b| b.ctime)
                .map(|c| c.to_string()),
        ),
        ("keybase_id", user.id.clone()),
        ("full_name", profile.and_then(|p| p.full_name.clone())),
        ("location", profile.and_then(|p| p.location.clone())),
        ("bio", profile.and_then(|p| p.bio.clone())),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v)))
    .fold(
        Evidence::new(SRC, format!("Keybase profile for {kb_username}"))
            .with_attr("profile_url", format!("https://keybase.io/{kb_username}"))
            .with_attr("proof_count", proof_count.to_string()),
        |ev, (key, v)| ev.with_attr(key, v),
    );

    entity.add_evidence(ev);
    result.push(entity);

    if let Some(profile) = &user.profile {
        if let Some(name) = profile.full_name.as_deref()
            && name.len() >= 3
            && name.contains(' ')
        {
            let mut pe = Entity::new(EntityKind::Person, name, confidence::VERY_HIGH, scan_id);
            pe.tag("keybase");
            pe.add_evidence(Evidence::new(
                SRC,
                format!("Name from Keybase profile {kb_username}"),
            ));
            result.push(pe);
        }

        if let Some(loc) = profile.location.as_deref()
            && loc.len() >= 3
        {
            let mut ae = Entity::new(EntityKind::Address, loc, 0.52, scan_id);
            ae.tag("keybase");
            ae.tag("geoint");
            ae.tag("self-reported");
            if let Some(sc) = crate::util::address_au::state_code(loc) {
                ae.tag(format!("au-state:{sc}"));
                ae.tag("country:AU");
            }
            ae.add_evidence(Evidence::new(
                SRC,
                format!("Location from Keybase profile {kb_username}"),
            ));
            result.push(ae);

            if let Some((lat, lon)) = crate::util::city_coords::city_coords(loc) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, confidence::MEDIUM, scan_id);
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("keybase");
                if let Some(sc) = crate::util::address_au::state_code(loc) {
                    c.tag(format!("au-state:{sc}"));
                    c.tag("country:AU");
                }
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Inline geocode of Keybase location '{loc}' → {coord_val}"),
                ));
                result.push(c);
            }
        }
    }

    if let Some(proofs) = &user.proofs_summary {
        extract_proofs(&proofs.all, kb_username, scan_id, &mut result);
    }

    result.entities
}

/// Fold the verified Keybase proofs into entities. Pure (no I/O) so the
/// proof→entity mapping is unit-tested. Only `state == 1` (active) proofs are
/// emitted; each cross-platform handle is a cryptographically-verified pivot,
/// so we ALSO surface its `service_url` as a first-class (confirmed) profile
/// link rather than discarding it.
pub(super) fn extract_proofs(
    proofs: &[KbProof],
    kb_username: &str,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    // Emit the verified profile URL a proof points at (when present + http).
    let push_service_url = |result: &mut ModuleResult, ptype: &str, url: Option<&str>| {
        if let Some(u) = url.filter(|u| u.starts_with("http")) {
            let mut ue = Entity::new(EntityKind::Url, u, confidence::HIGH_PLUSPLUS_PLUS, scan_id);
            ue.tag("keybase");
            ue.tag("social-profile");
            ue.tag("verified");
            ue.add_evidence(Evidence::new(
                SRC,
                format!("Keybase-verified {ptype} profile of {kb_username}"),
            ));
            result.push(ue);
        }
    };

    for proof in proofs {
        if proof.state != Some(1) {
            continue;
        }
        let Some(ptype) = proof.proof_type.as_deref() else {
            continue;
        };
        let Some(nametag) = proof
            .nametag
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        else {
            continue;
        };
        let service_url = proof.service_url.as_deref();

        match ptype {
            "twitter" | "github" | "reddit" | "hackernews" | "gitlab" | "mastodon" | "facebook"
            | "twitch" => {
                let mut ue = Entity::new(EntityKind::Username, nametag, confidence::HIGH_PLUSPLUS, scan_id);
                ue.tag("keybase");
                ue.tag("verified");
                ue.tag(format!("platform:{ptype}"));
                ue.add_evidence(
                    Evidence::new(
                        SRC,
                        format!(
                            "Cryptographic proof: {ptype}/@{nametag} linked to Keybase/{kb_username}"
                        ),
                    )
                    .with_attr("proof_type", ptype)
                    .with_attr("keybase_user", kb_username),
                );
                result.push(ue);
                push_service_url(result, ptype, service_url);
            }
            "dns" | "generic_web_site" | "https" | "http" | "web" => {
                // nametag may be a bare host or a URL — reduce to the host.
                let domain = nametag
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or(nametag);
                let mut de = Entity::new(EntityKind::Domain, domain, confidence::VERY_HIGH, scan_id);
                de.tag("keybase");
                de.tag("verified");
                de.tag("personal-site");
                de.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Domain proof: {domain} linked to Keybase/{kb_username}"),
                    )
                    .with_attr("keybase_user", kb_username),
                );
                result.push(de);
            }
            _ if nametag.contains('@') && nametag.contains('.') => {
                let mut ee = Entity::new(EntityKind::Email, nametag, confidence::HIGH_PLUS, scan_id);
                ee.tag("keybase");
                ee.tag(format!("proof:{ptype}"));
                ee.add_evidence(
                    Evidence::new(
                        SRC,
                        format!(
                            "Verified {ptype} proof: {nametag} linked to Keybase/{kb_username}"
                        ),
                    )
                    .with_attr("proof_type", ptype)
                    .with_attr("keybase_user", kb_username),
                );
                result.push(ee);
            }
            _ => push_service_url(result, ptype, service_url),
        }
    }
}
