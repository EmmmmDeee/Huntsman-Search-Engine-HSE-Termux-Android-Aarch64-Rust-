//! Stolen.tax — credential breach & data exposure intelligence.
//!
//! Queries the Stolen.tax API for exposed credentials, breach intelligence,
//! and data exposure records. Retrieves breach metadata, associated email
//! addresses, usernames, and exposed data categories. Emits entities for
//! discovered identities and correlates with existing scan targets.
//! Key-gated (`HUNTSMAN_STOLEN_TAX_KEY`).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "stolen_tax";

pub struct StolenTax;

#[derive(Debug, Deserialize)]
struct StolenTaxResponse {
    success: bool,
    data: Option<StolenTaxData>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StolenTaxData {
    breaches: Option<Vec<BreachRecord>>,
    exposures: Option<Vec<ExposureRecord>>,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    usernames: Vec<String>,
    #[serde(default)]
    associated_accounts: Vec<AssociatedAccount>,
}

#[derive(Debug, Deserialize)]
struct BreachRecord {
    id: Option<String>,
    name: Option<String>,
    title: Option<String>,
    date: Option<String>,
    record_count: Option<i64>,
    description: Option<String>,
    #[serde(default)]
    affected_categories: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ExposureRecord {
    id: Option<String>,
    source: Option<String>,
    date_published: Option<String>,
    record_count: Option<i64>,
    #[serde(default)]
    exposed_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AssociatedAccount {
    username: Option<String>,
    email: Option<String>,
    platform: Option<String>,
    first_seen: Option<String>,
}

#[async_trait]
impl Module for StolenTax {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Stolen.tax credential breach intelligence — queries for exposed credentials, breach records, and data exposure incidents"
    }

    fn priority(&self) -> u8 {
        65
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email | TargetKind::Username | TargetKind::Domain | TargetKind::Organisation
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1589.001", "T1589.002", "T1589.003", "T1596.004", "T1598.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Domain,
            EntityKind::Organisation,
            EntityKind::Credential,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let query_param = crate::util::http::urlencode(&target.value);
        let url = match target.kind {
            TargetKind::Email => {
                format!("https://api.stolen.tax/api/v1/search/email?query={}", query_param)
            }
            TargetKind::Username => {
                format!("https://api.stolen.tax/api/v1/search/username?query={}", query_param)
            }
            TargetKind::Domain => {
                format!("https://api.stolen.tax/api/v1/search/domain?query={}", query_param)
            }
            TargetKind::Organisation => {
                format!("https://api.stolen.tax/api/v1/search/org?query={}", query_param)
            }
            _ => return Ok(result),
        };

        let Some(response) = crate::util::http::fetch_keyed_json::<StolenTaxResponse>(
            ctx,
            SRC,
            &url,
            "HUNTSMAN_STOLEN_TAX_KEY",
            "Api-Key",
        )
        .await?
        else {
            return Ok(result);
        };

        if !response.success {
            if let Some(err) = response.error {
                tracing::debug!("stolen_tax API error: {}", err);
            }
            return Ok(result);
        }

        if let Some(data) = response.data {
            result.entities = build_entities(&data, &target.value, &ctx.scan_id);
        }

        Ok(result)
    }
}

fn build_entities(
    data: &StolenTaxData,
    query_value: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut entities = Vec::new();

    for email in &data.emails {
        if email != query_value {
            let mut entity = Entity::new(EntityKind::Email, email, confidence::MEDIUM, scan_id);
            entity.add_evidence(Evidence::new(
                SRC,
                format!("Exposed in breach: correlated with {}", query_value),
            ));
            entities.push(entity);
        }
    }

    for username in &data.usernames {
        if username != query_value {
            let mut entity = Entity::new(
                EntityKind::Username,
                username,
                confidence::MEDIUM,
                scan_id,
            );
            entity.add_evidence(Evidence::new(
                SRC,
                format!("Exposed in breach: correlated with {}", query_value),
            ));
            entities.push(entity);
        }
    }

    for account in &data.associated_accounts {
        if let Some(email) = &account.email {
            if email != query_value {
                let mut entity = Entity::new(EntityKind::Email, email, confidence::MEDIUM, scan_id);
                let evidence_text = if let Some(platform) = &account.platform {
                    format!(
                        "Associated account on {} (first seen: {})",
                        platform,
                        account.first_seen.as_deref().unwrap_or("unknown")
                    )
                } else {
                    "Associated account in breach data".to_string()
                };
                entity.add_evidence(Evidence::new(SRC, evidence_text));
                entities.push(entity);
            }
        }

        if let Some(username) = &account.username {
            if username != query_value {
                let mut entity = Entity::new(
                    EntityKind::Username,
                    username,
                    confidence::MEDIUM,
                    scan_id,
                );
                let evidence_text = if let Some(platform) = &account.platform {
                    format!(
                        "Associated account on {} (first seen: {})",
                        platform,
                        account.first_seen.as_deref().unwrap_or("unknown")
                    )
                } else {
                    "Associated account in breach data".to_string()
                };
                entity.add_evidence(Evidence::new(SRC, evidence_text));
                entities.push(entity);
            }
        }
    }

    for breach in data.breaches.as_ref().iter().flat_map(|b| b.iter()) {
        if let Some(name) = &breach.name {
            let evidence_text = format!(
                "Breach: {} (records: {}, date: {})",
                name,
                breach.record_count.unwrap_or(0),
                breach.date.as_deref().unwrap_or("unknown")
            );
            let mut entity = Entity::new(
                EntityKind::Credential,
                &format!("breach:{}", name),
                confidence::HIGH,
                scan_id,
            );
            entity.add_evidence(Evidence::new(SRC, evidence_text));
            entities.push(entity);
        }
    }

    entities
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_metadata() {
        let module = StolenTax;
        assert_eq!(module.name(), "stolen_tax");
        assert!(module.description().contains("credential"));
        assert!(module.cost() == ModuleCost::KeyGated);
    }

    #[test]
    fn test_accepts_email() {
        let module = StolenTax;
        let target = Target {
            kind: TargetKind::Email,
            value: "test@example.com".to_string(),
        };
        assert!(module.accepts(&target));
    }

    #[test]
    fn test_accepts_username() {
        let module = StolenTax;
        let target = Target {
            kind: TargetKind::Username,
            value: "testuser".to_string(),
        };
        assert!(module.accepts(&target));
    }

    #[test]
    fn test_accepts_domain() {
        let module = StolenTax;
        let target = Target {
            kind: TargetKind::Domain,
            value: "example.com".to_string(),
        };
        assert!(module.accepts(&target));
    }

    #[test]
    fn test_build_entities_deduplication() {
        let data = StolenTaxData {
            breaches: None,
            exposures: None,
            emails: vec!["user@example.com".to_string()],
            usernames: vec!["testuser".to_string()],
            associated_accounts: vec![],
        };

        let entities = build_entities(&data, "user@example.com", "test-scan");
        assert_eq!(entities.len(), 1);
        assert!(entities[0].value.contains("testuser"));
    }
}
