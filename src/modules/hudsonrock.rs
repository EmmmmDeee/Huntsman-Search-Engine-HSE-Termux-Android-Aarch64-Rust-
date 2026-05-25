//! HudsonRock free stealer-log lookup. Public endpoint, no API key required.
//!
//! Endpoints:
//!   /api/json/v2/osint-tools/search-by-login?username=<email>
//!   /api/json/v2/osint-tools/search-by-domain?domain=<domain>
//!
//! Security: stealer credentials are NEVER stored in evidence — only the
//! aggregate compromise metadata (machine name, OS, date, count).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

pub struct HudsonRock;

#[derive(Deserialize)]
struct CavalierResp {
    #[serde(default)]
    stealers: Vec<Stealer>,
}

#[derive(Deserialize)]
struct Stealer {
    computer_name: Option<String>,
    operating_system: Option<String>,
    date_compromised: Option<String>,
    malware_path: Option<String>,
    #[serde(default)]
    credentials: Vec<serde_json::Value>, // count only — content never read
}

#[async_trait]
impl Module for HudsonRock {
    fn name(&self) -> &'static str {
        "hudsonrock"
    }

    fn priority(&self) -> u8 {
        130
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Domain)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = match target.kind {
            TargetKind::Email => format!(
                "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?username={}",
                urlencode(&target.value)
            ),
            TargetKind::Domain => format!(
                "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={}",
                urlencode(&target.value)
            ),
            _ => return Ok(ModuleResult::new()),
        };

        let Some(data): Option<CavalierResp> =
            fetch_json_or_404(&ctx.http, "hudsonrock", &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        if data.stealers.is_empty() {
            return Ok(ModuleResult::new());
        }

        let kind = match target.kind {
            TargetKind::Email => EntityKind::Email,
            TargetKind::Domain => EntityKind::Domain,
            _ => unreachable!(),
        };

        let mut entity = Entity::new(kind, &target.value, 0.78, &ctx.scan_id);
        entity.tag("breach");
        entity.tag("stealer-log");

        for stealer in &data.stealers {
            let cred_count = stealer.credentials.len();
            let cred_count_str = cred_count.to_string();
            entity.add_evidence(
                Evidence::new(
                    "hudsonrock",
                    format!(
                        "Stealer log: {cred_count} credentials on compromised machine",
                    ),
                )
                .with_attr(
                    "computer_name",
                    stealer.computer_name.as_deref().unwrap_or("-"),
                )
                .with_attr(
                    "operating_system",
                    stealer.operating_system.as_deref().unwrap_or("-"),
                )
                .with_attr(
                    "date_compromised",
                    stealer.date_compromised.as_deref().unwrap_or("-"),
                )
                .with_attr(
                    "malware_path",
                    stealer.malware_path.as_deref().unwrap_or("-"),
                )
                .with_attr("credential_count", cred_count_str),
                // credential content intentionally NEVER stored
            );
        }

        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email_and_domain() {
        let m = HudsonRock;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
    }
}
