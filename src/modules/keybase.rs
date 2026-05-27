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
    module::{Module, ModuleContext, ModuleResult},
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
#[allow(dead_code)]
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

        let body: KbResp = match resp.json().await {
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

        let mut ev = Evidence::new(SRC, format!("Keybase profile for {kb_username}"))
            .with_attr("profile_url", format!("https://keybase.io/{kb_username}"));

        if let Some(basics) = &user.basics
            && let Some(ctime) = basics.ctime
        {
            ev = ev.with_attr("created_at_unix", ctime.to_string());
        }
        if let Some(id) = &user.id {
            ev = ev.with_attr("keybase_id", id);
        }
        if let Some(profile) = &user.profile {
            if let Some(name) = profile.full_name.as_deref() {
                ev = ev.with_attr("full_name", name);
            }
            if let Some(loc) = profile.location.as_deref() {
                ev = ev.with_attr("location", loc);
            }
            if let Some(bio) = profile.bio.as_deref() {
                ev = ev.with_attr("bio", bio);
            }
        }

        let proof_count = user
            .proofs_summary
            .as_ref()
            .map(|p| p.all.len())
            .unwrap_or(0);
        ev = ev.with_attr("proof_count", proof_count.to_string());

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
                let mut ae = Entity::new(EntityKind::Address, loc, 0.50, &ctx.scan_id);
                ae.tag("keybase");
                ae.tag("geoint");
                ae.add_evidence(Evidence::new(
                    SRC,
                    format!("Location from Keybase profile {kb_username}"),
                ));
                result.push(ae);
            }
        }

        if let Some(proofs) = &user.proofs_summary {
            for proof in &proofs.all {
                if proof.state != Some(1) {
                    continue;
                }
                let Some(ptype) = proof.proof_type.as_deref() else {
                    continue;
                };
                let Some(nametag) = proof.nametag.as_deref() else {
                    continue;
                };
                if nametag.is_empty() {
                    continue;
                }

                match ptype {
                    "twitter" | "github" | "reddit" | "hackernews" => {
                        let mut ue = Entity::new(EntityKind::Username, nametag, 0.80, &ctx.scan_id);
                        ue.tag("keybase");
                        ue.tag(format!("platform:{ptype}"));
                        ue.add_evidence(
                            Evidence::new(
                                SRC,
                                format!("Cryptographic proof: {ptype}/@{nametag} linked to Keybase/{kb_username}"),
                            )
                            .with_attr("proof_type", ptype)
                            .with_attr("keybase_user", kb_username),
                        );
                        result.push(ue);
                    }
                    "dns" | "generic_web_site" => {
                        let mut de = Entity::new(EntityKind::Domain, nametag, 0.75, &ctx.scan_id);
                        de.tag("keybase");
                        de.add_evidence(
                            Evidence::new(
                                SRC,
                                format!("Domain proof: {nametag} linked to Keybase/{kb_username}"),
                            )
                            .with_attr("keybase_user", kb_username),
                        );
                        result.push(de);
                    }
                    _ if nametag.contains('@') && nametag.contains('.') => {
                        let mut ee = Entity::new(EntityKind::Email, nametag, 0.70, &ctx.scan_id);
                        ee.tag("keybase");
                        ee.tag(format!("proof:{ptype}"));
                        ee.add_evidence(
                            Evidence::new(
                                SRC,
                                format!("Verified {ptype} proof: {nametag} linked to Keybase/{kb_username}"),
                            )
                            .with_attr("proof_type", ptype)
                            .with_attr("keybase_user", kb_username),
                        );
                        result.push(ee);
                    }
                    _ => {}
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
}
