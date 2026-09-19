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
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "stolen_tax";
const API_BASE: &str = "https://api.stolen.tax/api/v1/search";

/// The Stolen.tax [`Module`] marker type — see the module-level docs above.
pub struct StolenTax;

/// What a 200 body means to the key cascade: a `success: true` answer is
/// accepted; a key/quota-shaped `error` burns the key and rotates; any other
/// `success: false` is ALSO accepted — and then failed by [`accepted`] — so
/// that a backend error, a degraded service or a rejected selector is never
/// [`BodyVerdict::Absent`](crate::util::http::BodyVerdict::Absent)'s "genuine miss" (backlog #40: on a key-gated paid
/// breach lookup that read as "this identity appears in no breach", and was
/// cached for a day). **Pure.**
fn body_verdict(parsed: &StolenTaxResponse) -> crate::util::http::BodyVerdict {
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
    crate::util::http::BodyVerdict::Accept
}

/// A `success: false` envelope that reached this far is not key-shaped: the
/// provider failed the query. Fail closed with the provider's own words —
/// the module has no documented `success: false` "no results" shape, and a
/// zero-hit search answers `success: true` with empty data. **Pure.**
fn accepted(response: StolenTaxResponse) -> Result<StolenTaxResponse> {
    if response.success {
        return Ok(response);
    }
    Err(Error::module(
        SRC,
        format!(
            "stolen.tax answered success=false: {}",
            response.error.as_deref().unwrap_or("no error text")
        ),
    ))
}

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
            // PROVIDER FAILURE != ZERO EVIDENCE — see REQ-KEYSKIP-001.
            return Err(crate::core::error::Error::MissingKey(
                "HUNTSMAN_STOLEN_TAX_KEY".into(),
            ));
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
            body_verdict,
        )
        .await?
        else {
            return Ok(result);
        };
        let response = accepted(response)?;

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
    // Case-insensitive, matching the `seen` dedup key below: an API that
    // restates the queried identity with different casing (e.g. queried
    // "User@Example.com", API echoes "user@example.com" in its own
    // emails[]) must still be recognised as the query itself, not
    // re-emitted as a new corroborating pivot.
    let query_lower = query_value.to_lowercase();

    entities.extend(
        data.emails
            .iter()
            .filter(|e| e.to_lowercase() != query_lower)
            // A bare `.to_lowercase()` doesn't replicate `core::entity::
            // normalise`'s fuller Email cleanup (quote/escape-tail strip), so
            // a dirty and a clean spelling of the same address each earned
            // their own dedup slot despite colliding on the same uid once
            // `Entity::new` constructs them.
            .filter(|e| {
                seen.insert((
                    EntityKind::Email,
                    crate::core::entity::normalise(&EntityKind::Email, e),
                ))
            })
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
            .filter(|u| u.to_lowercase() != query_lower)
            // A bare `.to_lowercase()` doesn't strip a leading `@` sigil or
            // wrapping quote the way `core::entity::normalise`'s Username arm
            // does, so a dirty and a clean spelling of the same handle each
            // earned their own dedup slot despite colliding on the same uid
            // once `Entity::new` constructs them.
            .filter(|u| {
                seen.insert((
                    EntityKind::Username,
                    crate::core::entity::normalise(&EntityKind::Username, u),
                ))
            })
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
            && email.to_lowercase() != query_lower
            && seen.insert((
                EntityKind::Email,
                crate::core::entity::normalise(&EntityKind::Email, email),
            ))
        {
            let mut entity = Entity::new(EntityKind::Email, email, confidence::MEDIUM, scan_id);
            entity.add_evidence(Evidence::new(SRC, evidence_text.clone()));
            entities.push(entity);
        }

        if let Some(username) = &account.username
            && username.to_lowercase() != query_lower
            && seen.insert((
                EntityKind::Username,
                crate::core::entity::normalise(&EntityKind::Username, username),
            ))
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

    #[test]
    fn test_build_entities_dedups_a_dirty_and_a_clean_username_spelling() {
        // Regression: a bare `.to_lowercase()` case-folds but does not strip a
        // leading `@` handle sigil the way `core::entity::normalise`'s
        // Username arm does, so a rollup spelling and an associated-account
        // spelling of the same handle each earned their own dedup slot
        // despite colliding on the same uid once `Entity::new` constructs
        // them.
        let data = StolenTaxData {
            breaches: None,
            emails: vec![],
            usernames: vec!["jordan_m".to_string()],
            associated_accounts: vec![AssociatedAccount {
                username: Some("@jordan_m".to_string()),
                email: None,
                platform: Some("forum".to_string()),
                first_seen: None,
            }],
        };
        let entities = build_entities(&data, "user@example.com", "test-scan");
        let unames: Vec<&Entity> = entities
            .iter()
            .filter(|e| e.kind == EntityKind::Username)
            .collect();
        assert_eq!(
            unames.len(),
            1,
            "a sigil-prefixed and a bare spelling of the same handle must dedup to one entity: {unames:?}"
        );
    }

    #[test]
    fn test_build_entities_dedups_a_dirty_and_a_clean_email_spelling() {
        // Same root cause, the Email arm: a bare `.to_lowercase()` doesn't
        // strip a stray leading quote (a breach-dump export artifact) the way
        // `core::entity::normalise`'s Email arm does.
        let data = StolenTaxData {
            breaches: None,
            emails: vec!["alt@example.com".to_string()],
            usernames: vec![],
            associated_accounts: vec![AssociatedAccount {
                username: None,
                email: Some("\"alt@example.com".to_string()),
                platform: Some("forum".to_string()),
                first_seen: None,
            }],
        };
        let entities = build_entities(&data, "user@example.com", "test-scan");
        let emails: Vec<&Entity> = entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .collect();
        assert_eq!(
            emails.len(),
            1,
            "a dirty and a clean spelling of the same address must dedup to one entity: {emails:?}"
        );
    }

    #[test]
    fn test_build_entities_excludes_the_query_value_regardless_of_casing() {
        // Regression: the query-value suppression check was case-sensitive
        // while the `seen` dedup key is case-insensitive. An API that
        // restates the queried identity with different casing (a common
        // real shape — the query was "User@Example.com", the API's own
        // emails[]/associated_accounts[] echo "user@example.com") was not
        // recognised as the query itself and got re-emitted as a new
        // corroborating pivot instead of being excluded.
        let data = StolenTaxData {
            breaches: None,
            emails: vec!["user@example.com".to_string()],
            usernames: vec![],
            associated_accounts: vec![AssociatedAccount {
                username: None,
                email: Some("USER@EXAMPLE.COM".to_string()),
                platform: None,
                first_seen: None,
            }],
        };
        let entities = build_entities(&data, "User@Example.com", "test-scan");
        assert!(
            entities.is_empty(),
            "the queried identity restated with different casing must not be re-emitted as a pivot: {entities:?}"
        );
    }

    #[test]
    fn a_non_key_error_envelope_fails_closed_instead_of_reading_as_no_breach() {
        // Backlog #40.
        let backend: StolenTaxResponse = serde_json::from_str(
            r#"{"success":false,"data":null,"error":"database temporarily unavailable"}"#,
        )
        .expect("decodes");
        assert!(matches!(
            body_verdict(&backend),
            crate::util::http::BodyVerdict::Accept
        ));
        let err = accepted(backend).expect_err("a failed query is not a clean negative");
        assert!(
            err.to_string().contains("database temporarily unavailable"),
            "{err}"
        );
        let dead_key: StolenTaxResponse =
            serde_json::from_str(r#"{"success":false,"data":null,"error":"Invalid API key"}"#)
                .expect("decodes");
        assert!(matches!(
            body_verdict(&dead_key),
            crate::util::http::BodyVerdict::KeyFailure { code: 401, .. }
        ));
        let hit: StolenTaxResponse = serde_json::from_str(
            r#"{"success":true,"data":{"breaches":[],"emails":[],"usernames":[]},"error":null}"#,
        )
        .expect("decodes");
        assert!(matches!(
            body_verdict(&hit),
            crate::util::http::BodyVerdict::Accept
        ));
        assert!(accepted(hit).is_ok());
    }
}
