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
const API_BASE: &str = "https://api.stolen.tax/api/v1/search";

/// The Stolen.tax [`Module`] marker type — see the module-level docs above.
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
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    usernames: Vec<String>,
    #[serde(default)]
    associated_accounts: Vec<AssociatedAccount>,
}

#[derive(Debug, Deserialize)]
struct BreachRecord {
    name: Option<String>,
    date: Option<String>,
    record_count: Option<i64>,
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

    fn cache_ttl_secs(&self) -> u64 {
        // Breach/credential records are immutable once indexed — a repeat scan
        // of an already-queried identifier replays the cached result for FREE
        // within the window instead of re-spending a paid lookup, matching the
        // dehashed/see_know/oathnet_pro/intelx paid-breach-module convention.
        86_400
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::Domain
                | TargetKind::Organisation
        )
    }

    fn category(&self) -> ModuleCategory {
        // Breach corpora, same as hibp/dehashed/niamonx/osintcat — the default
        // Breach technique mapping (T1589.001 Credentials + T1589.002 Email
        // Addresses) already covers what this module collects, so no
        // `attack_techniques()` override is needed.
        ModuleCategory::Breach
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Only what `build_entities` actually constructs: correlated emails,
        // usernames, and a Credential marker per named breach. `accepts()`
        // also takes Domain/Organisation as query selectors (the API can
        // search by them), but the entities returned are always these three
        // kinds, never a Domain/Organisation entity itself.
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Credential,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let Some(initial_key) = ctx.key_opt("HUNTSMAN_STOLEN_TAX_KEY") else {
            return Ok(result);
        };
        let query_param = crate::util::http::urlencode(&target.value);
        let endpoint = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Domain => "domain",
            TargetKind::Organisation => "org",
            _ => return Ok(result),
        };

        // Key cascade via the shared primitive. Stolen.tax reports a dead or
        // exhausted key as an in-body `success:false` + `error` message on an
        // HTTP 200 — the same shape as ipqs/criminal_ip — so a status-only
        // cascade cannot see it: without this, a burned key read as a clean
        // empty result on every scan instead of rotating to the next pooled
        // credential or surfacing an operator-visible failure.
        let Some(response): Option<StolenTaxResponse> = crate::util::http::keyed_cascade_json(
            ctx,
            SRC,
            initial_key,
            &[],
            |key| {
                let url = format!("{API_BASE}/{endpoint}?query={query_param}");
                ctx.http.get(url).header("Api-Key", key)
            },
            |parsed: &StolenTaxResponse| {
                if parsed.success {
                    return crate::util::http::BodyVerdict::Accept;
                }
                let msg = parsed.error.as_deref().unwrap_or_default();
                if crate::util::http::is_key_or_quota_message(msg) {
                    return crate::util::http::BodyVerdict::KeyFailure {
                        code: 401,
                        detail: Some(msg.to_string()),
                    };
                }
                if !msg.is_empty() {
                    tracing::debug!("stolen_tax API error: {msg}");
                }
                crate::util::http::BodyVerdict::Absent
            },
        )
        .await?
        else {
            return Ok(result);
        };

        if let Some(data) = response.data {
            result.entities = build_entities(&data, &target.value, &ctx.scan_id);
        }

        Ok(result)
    }
}

fn build_entities(data: &StolenTaxData, query_value: &str, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    // The same email/username can legitimately appear in more than one of
    // these overlapping identity sources — a top-level rollup list AND a
    // detailed per-platform accounts array both naming the same address is a
    // plausible real API shape. Without this guard, the same (kind, value)
    // pair mints as two separate entities for one fact restated twice.
    let mut seen: std::collections::HashSet<(EntityKind, String)> =
        std::collections::HashSet::new();

    entities.extend(
        data.emails
            .iter()
            .filter(|e| *e != query_value)
            .filter(|e| seen.insert((EntityKind::Email, e.to_lowercase())))
            .map(|email| {
                let mut entity = Entity::new(EntityKind::Email, email, confidence::MEDIUM, scan_id);
                entity.add_evidence(Evidence::new(
                    SRC,
                    format!("Exposed in breach: correlated with {query_value}"),
                ));
                entity
            }),
    );

    entities.extend(
        data.usernames
            .iter()
            .filter(|u| *u != query_value)
            .filter(|u| seen.insert((EntityKind::Username, u.to_lowercase())))
            .map(|username| {
                let mut entity =
                    Entity::new(EntityKind::Username, username, confidence::MEDIUM, scan_id);
                entity.add_evidence(Evidence::new(
                    SRC,
                    format!("Exposed in breach: correlated with {query_value}"),
                ));
                entity
            }),
    );

    for account in &data.associated_accounts {
        let evidence_text = account.platform.as_ref().map_or_else(
            || "Associated account in breach data".to_string(),
            |platform| {
                format!(
                    "Associated account on {} (first seen: {})",
                    platform,
                    account.first_seen.as_deref().unwrap_or("unknown")
                )
            },
        );

        if let Some(email) = &account.email
            && email != query_value
            && seen.insert((EntityKind::Email, email.to_lowercase()))
        {
            let mut entity = Entity::new(EntityKind::Email, email, confidence::MEDIUM, scan_id);
            entity.add_evidence(Evidence::new(SRC, evidence_text.clone()));
            entities.push(entity);
        }

        if let Some(username) = &account.username
            && username != query_value
            && seen.insert((EntityKind::Username, username.to_lowercase()))
        {
            let mut entity =
                Entity::new(EntityKind::Username, username, confidence::MEDIUM, scan_id);
            entity.add_evidence(Evidence::new(SRC, evidence_text.clone()));
            entities.push(entity);
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
                format!("breach:{name}"),
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
            emails: vec!["user@example.com".to_string()],
            usernames: vec!["testuser".to_string()],
            associated_accounts: vec![],
        };

        let entities = build_entities(&data, "user@example.com", "test-scan");
        assert_eq!(entities.len(), 1);
        assert!(entities[0].value.contains("testuser"));
    }

    #[test]
    fn test_build_entities_dedups_a_value_restated_across_sources() {
        // Regression: the top-level `emails`/`usernames` rollup and the
        // detailed `associated_accounts[]` array can restate the SAME
        // email/username — a plausible real API shape — which previously
        // double-emitted it as two separate entities instead of one.
        let data = StolenTaxData {
            breaches: None,
            emails: vec!["Alt@Example.com".to_string()],
            usernames: vec!["altuser".to_string()],
            associated_accounts: vec![AssociatedAccount {
                username: Some("altuser".to_string()),
                email: Some("alt@example.com".to_string()),
                platform: Some("forum".to_string()),
                first_seen: None,
            }],
        };
        let entities = build_entities(&data, "user@example.com", "test-scan");
        let email_count = entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .count();
        let username_count = entities
            .iter()
            .filter(|e| e.kind == EntityKind::Username)
            .count();
        assert_eq!(
            email_count, 1,
            "the same email restated in emails[] and associated_accounts[] must not double-emit: {entities:?}"
        );
        assert_eq!(
            username_count, 1,
            "the same username restated in usernames[] and associated_accounts[] must not double-emit: {entities:?}"
        );
    }
}
