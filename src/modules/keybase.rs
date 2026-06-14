//! Keybase identity graph lookup. Free, no API key required.
//!
//! Endpoints:
//!   `GET https://keybase.io/_/api/1.0/user/lookup.json?username={user}`
//!   `GET https://keybase.io/_/api/1.0/user/lookup.json?github={user}`
//!
//! Pivots from a Username target to discover linked accounts across
//! platforms (Twitter, GitHub, Reddit, HN, personal sites, PGP keys).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

const SRC: &str = "keybase";

pub struct Keybase;

#[derive(Deserialize)]
struct KbResp {
    #[serde(default)]
    status: Option<KbStatus>,
    #[serde(default)]
    them: Option<Vec<KbUser>>,
}

#[derive(Deserialize)]
struct KbStatus {
    #[serde(default)]
    code: Option<i32>,
}

#[derive(Deserialize)]
struct KbUser {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    basics: Option<KbBasics>,
    #[serde(default)]
    profile: Option<KbProfile>,
    #[serde(default)]
    proofs_summary: Option<KbProofs>,
}

#[derive(Deserialize)]
struct KbBasics {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    ctime: Option<i64>,
}

#[derive(Deserialize)]
struct KbProfile {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    bio: Option<String>,
}

#[derive(Deserialize)]
struct KbProofs {
    #[serde(default)]
    all: Vec<KbProof>,
}

#[derive(Deserialize)]
struct KbProof {
    #[serde(default)]
    proof_type: Option<String>,
    #[serde(default)]
    nametag: Option<String>,
    #[serde(default)]
    service_url: Option<String>,
    #[serde(default)]
    state: Option<i32>,
}

#[async_trait]
impl Module for Keybase {
    fn name(&self) -> &'static str {
        "keybase"
    }
    fn description(&self) -> &'static str {
        "Keybase identity graph — linked accounts, PGP keys, and cryptographic proofs"
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

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(_) => return Ok(ModuleResult::new()),
        };

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body: KbResp = match crate::util::http::json_scanned(resp, SRC).await {
            Ok(b) => b,
            Err(_) => return Ok(ModuleResult::new()),
        };

        if body.status.as_ref().and_then(|s| s.code) != Some(0) {
            return Ok(ModuleResult::new());
        }

        let users = body.them.unwrap_or_default();
        let Some(user) = users.into_iter().next() else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();

        let kb_username = user
            .basics
            .as_ref()
            .and_then(|b| b.username.as_deref())
            .unwrap_or(username);

        let mut entity = Entity::new(EntityKind::Username, kb_username, 0.90, &ctx.scan_id);
        entity.tag("keybase");

        let proof_count = user
            .proofs_summary
            .as_ref()
            .map(|p| p.all.len())
            .unwrap_or(0);
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
                let mut pe = Entity::new(EntityKind::Person, name, 0.75, &ctx.scan_id);
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
                let mut ae = Entity::new(EntityKind::Address, loc, 0.52, &ctx.scan_id);
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
                    let mut c =
                        Entity::new(EntityKind::Coordinates, &coord_val, 0.50, &ctx.scan_id);
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
            extract_proofs(&proofs.all, kb_username, &ctx.scan_id, &mut result);
        }

        Ok(result)
    }
}

/// Fold the verified Keybase proofs into entities. Pure (no I/O) so the
/// proof→entity mapping is unit-tested. Only `state == 1` (active) proofs are
/// emitted; each cross-platform handle is a cryptographically-verified pivot,
/// so we ALSO surface its `service_url` as a first-class (confirmed) profile
/// link rather than discarding it.
fn extract_proofs(proofs: &[KbProof], kb_username: &str, scan_id: &str, result: &mut ModuleResult) {
    // Emit the verified profile URL a proof points at (when present + http).
    let push_service_url = |result: &mut ModuleResult, ptype: &str, url: Option<&str>| {
        if let Some(u) = url.filter(|u| u.starts_with("http")) {
            let mut ue = Entity::new(EntityKind::Url, u, 0.85, scan_id);
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
                let mut ue = Entity::new(EntityKind::Username, nametag, 0.80, scan_id);
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
                let mut de = Entity::new(EntityKind::Domain, domain, 0.75, scan_id);
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
                let mut ee = Entity::new(EntityKind::Email, nametag, 0.70, scan_id);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_username_only() {
        let m = Keybase;
        assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Keybase.name(), "keybase");
        assert_eq!(Keybase.priority(), 100);
        assert_eq!(Keybase.max_timeout_ms(), 4_000);
        assert!(!Keybase.description().is_empty());
    }

    #[test]
    fn parse_response() {
        let raw = r#"{
            "status": {"code": 0, "name": "OK"},
            "them": [{
                "id": "abc123",
                "basics": {"username": "alice", "ctime": 1500000000},
                "profile": {"full_name": "Alice Smith", "location": "Sydney, AU", "bio": "dev"},
                "proofs_summary": {
                    "all": [
                        {"proof_type": "twitter", "nametag": "alice_s", "state": 1},
                        {"proof_type": "github", "nametag": "alicesmith", "state": 1},
                        {"proof_type": "dns", "nametag": "alice.dev", "state": 1}
                    ]
                }
            }]
        }"#;
        let r: KbResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.status.unwrap().code, Some(0));
        let user = &r.them.unwrap()[0];
        assert_eq!(
            user.basics.as_ref().unwrap().username.as_deref(),
            Some("alice")
        );
        assert_eq!(
            user.profile.as_ref().unwrap().full_name.as_deref(),
            Some("Alice Smith")
        );
        assert_eq!(user.proofs_summary.as_ref().unwrap().all.len(), 3);
    }

    #[test]
    fn extract_proofs_maps_verified_links_and_urls() {
        // Shape captured from the live keybase.io lookup for `chris`.
        let proofs: Vec<KbProof> = serde_json::from_str(
            r#"[
                {"proof_type":"twitter","nametag":"malgorithms","state":1,"service_url":"https://twitter.com/malgorithms"},
                {"proof_type":"github","nametag":"malgorithms","state":1,"service_url":"https://github.com/malgorithms"},
                {"proof_type":"gitlab","nametag":"mal","state":1,"service_url":"https://gitlab.com/mal"},
                {"proof_type":"dns","nametag":"chriscoyne.com","state":1,"service_url":"http://chriscoyne.com"},
                {"proof_type":"twitter","nametag":"revoked","state":2,"service_url":"https://twitter.com/revoked"}
            ]"#,
        )
        .unwrap();
        let mut r = ModuleResult::new();
        extract_proofs(&proofs, "chris", "scan", &mut r);
        let has = |k: EntityKind, v: &str| r.entities.iter().any(|e| e.kind == k && e.value == v);

        // Cross-platform handles (incl. the newly-supported gitlab).
        assert!(has(EntityKind::Username, "malgorithms"));
        assert!(
            has(EntityKind::Username, "mal"),
            "gitlab proof now supported"
        );
        // Verified service_url surfaced as a first-class profile link.
        assert!(has(EntityKind::Url, "https://github.com/malgorithms"));
        // DNS proof → owned domain.
        assert!(has(EntityKind::Domain, "chriscoyne.com"));
        // Revoked (state != 1) proof dropped entirely.
        assert!(!has(EntityKind::Username, "revoked"));
        assert!(!has(EntityKind::Url, "https://twitter.com/revoked"));
        // Verified handles carry the `verified` tag.
        let gh = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "malgorithms")
            .unwrap();
        assert!(gh.has_tag("verified") && gh.has_tag("keybase"));
    }
}
