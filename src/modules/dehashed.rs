//! DeHashed breach search. Paid; requires `HUNTSMAN_DEHASHED_USER`
//! (account email) + `HUNTSMAN_DEHASHED_KEY` (API key).
//!
//! Endpoint: `GET https://api.dehashed.com/search?query={selector}:{value}`
//! Auth:     HTTP Basic (`user:key`)
//!
//! Per the project's no-credentials-in-evidence invariant, we deliberately
//! do NOT deserialise password / hashed_password / passwords fields and
//! never surface them. Only aggregate metadata escapes: total entries,
//! top databases, indexed timestamp range.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{error_snippet, handle_keyed_error, urlencode};

const USER_ENV: &str = "HUNTSMAN_DEHASHED_USER";
const KEY_ENV: &str = "HUNTSMAN_DEHASHED_KEY";

#[derive(Deserialize)]
struct DehashedResp {
    #[serde(default)]
    entries: Option<Vec<Entry>>,
    #[serde(default)]
    total: Option<u64>,
}

/// Aggregate-safe field set — `password`, `hashed_password`, etc. are
/// deliberately omitted so we can't even accidentally surface them.
#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    database_name: Option<String>,
    #[serde(default)]
    obtained_from: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
}

const SRC: &str = "dehashed";

/// Top breach databases to surface by frequency.
const MAX_DATABASES: usize = 5;

/// The DeHashed query selector for a target kind, or `None` for a kind this
/// module does not search. **Pure** — kept in lockstep with [`DeHashed::accepts`].
fn selector_for(kind: TargetKind) -> Option<&'static str> {
    Some(match kind {
        TargetKind::Email => "email",
        TargetKind::Username => "username",
        TargetKind::Phone => "phone",
        TargetKind::FullName => "name",
        TargetKind::IpAddress => "ip_address",
        TargetKind::Domain => "domain",
        _ => return None,
    })
}

/// Build the breach entity from a DeHashed response. **Pure** (no network/IO):
/// folds the returned `entries` into aggregate-only evidence — total hit count,
/// rows returned, the top databases by frequency, and the created-at range — and
/// raises the breach tags. Per the no-credentials-in-evidence invariant, `Entry`
/// carries no password/hash fields, so none can leak here. `total` is the
/// server's full count (which can exceed the truncated `entries.len()`).
fn build_breach_entity(
    kind: EntityKind,
    value: &str,
    selector: &str,
    entries: &[Entry],
    total: u64,
    scan_id: &str,
) -> Entity {
    let mut entity = Entity::new(kind, value, 0.88, scan_id);
    entity.tag(tags::BREACH);
    entity.tag("dehashed");

    // Top databases by frequency; a record names its source in either
    // `database_name` or, failing that, `obtained_from`.
    let top = crate::util::freq::top_n(
        entries
            .iter()
            .filter_map(|e| e.database_name.as_deref().or(e.obtained_from.as_deref())),
        MAX_DATABASES,
    );

    let mut ev = Evidence::new(
        SRC,
        format!("DeHashed: {total} breach record(s) for {selector}={value}"),
    )
    .with_attr("hits", total.to_string())
    .with_attr("returned", entries.len().to_string())
    .with_attr("selector", selector);
    if !top.is_empty() {
        ev = ev.with_attr("top_databases", top);
    }
    if let Some(e) = entries.iter().filter_map(|e| e.created_at.as_deref()).min() {
        ev = ev.with_attr("earliest_record", e);
    }
    if let Some(l) = entries.iter().filter_map(|e| e.created_at.as_deref()).max() {
        ev = ev.with_attr("latest_record", l);
    }
    entity.add_evidence(ev);
    entity
}

pub struct DeHashed;

#[async_trait]
impl Module for DeHashed {
    fn name(&self) -> &'static str {
        "dehashed"
    }
    fn description(&self) -> &'static str {
        "Breach record search across leaked databases"
    }
    fn priority(&self) -> u8 {
        118
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::Phone
                | TargetKind::FullName
                | TargetKind::IpAddress
                | TargetKind::Domain
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (user, key) = match (ctx.key_opt(USER_ENV), ctx.key_opt(KEY_ENV)) {
            (Some(u), Some(k)) => (u, k),
            _ => return Ok(ModuleResult::new()),
        };
        let Some(selector) = selector_for(target.kind) else {
            return Ok(ModuleResult::new());
        };
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }
        let q = format!("{selector}:{value}");
        let url = format!("https://api.dehashed.com/search?query={}", urlencode(&q));
        let mut retries = 2u8;
        let body: DehashedResp = loop {
            let resp = ctx
                .http
                .get(&url)
                .basic_auth(user, Some(key))
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;
            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                return Err(Error::module(
                    "dehashed",
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            break resp
                .json()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;
        };

        let entries = body.entries.unwrap_or_default();
        let total = body.total.unwrap_or(entries.len() as u64);
        if entries.is_empty() && total == 0 {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        result.push(build_breach_entity(
            target.kind.to_entity_kind(),
            value,
            selector,
            &entries,
            total,
            &ctx.scan_id,
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_six_kinds() {
        let m = DeHashed;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::IpAddress,
            TargetKind::Domain,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
    }
    #[test]
    fn cost_is_paid() {
        assert!(matches!(DeHashed.cost(), ModuleCost::Paid));
    }

    #[test]
    fn selector_covers_every_accepted_kind() {
        // selector_for must answer for exactly the kinds accepts() admits.
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::FullName,
            TargetKind::IpAddress,
            TargetKind::Domain,
        ] {
            assert!(DeHashed.accepts(&Target::new(k, "x")));
            assert!(selector_for(k).is_some(), "no selector for {k:?}");
        }
        assert_eq!(selector_for(TargetKind::Email), Some("email"));
        assert_eq!(selector_for(TargetKind::FullName), Some("name"));
        assert_eq!(selector_for(TargetKind::IpAddress), Some("ip_address"));
        // A kind the module does not search.
        assert_eq!(selector_for(TargetKind::Url), None);
    }

    fn entry(db: Option<&str>, obtained: Option<&str>, created: Option<&str>) -> Entry {
        Entry {
            database_name: db.map(String::from),
            obtained_from: obtained.map(String::from),
            created_at: created.map(String::from),
        }
    }

    fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn aggregates_hits_databases_and_created_range() {
        let entries = [
            entry(Some("Collection#1"), None, Some("2019-01-01")),
            entry(Some("Collection#1"), None, Some("2021-06-15")),
            // No database_name → falls back to obtained_from.
            entry(None, Some("LinkedIn"), Some("2012-05-05")),
        ];
        // total (900) exceeds the returned/truncated rows (3).
        let e = build_breach_entity(EntityKind::Email, "a@b.com", "email", &entries, 900, "s");
        assert_eq!(e.kind, EntityKind::Email);
        assert!(e.has_tag(tags::BREACH) && e.has_tag("dehashed"));
        assert!((e.confidence - 0.88).abs() < 1e-9);
        assert_eq!(attr(&e, "hits"), Some("900")); // server total, not len
        assert_eq!(attr(&e, "returned"), Some("3"));
        assert_eq!(attr(&e, "selector"), Some("email"));
        // Collection#1 (2) ranks above the obtained_from fallback LinkedIn (1).
        assert_eq!(
            attr(&e, "top_databases"),
            Some("Collection#1×2, LinkedIn×1")
        );
        assert_eq!(attr(&e, "earliest_record"), Some("2012-05-05"));
        assert_eq!(attr(&e, "latest_record"), Some("2021-06-15"));
    }

    #[test]
    fn count_only_response_omits_optional_aggregates() {
        // total known but no entry rows returned (a bare count response).
        let e = build_breach_entity(EntityKind::Domain, "x.com", "domain", &[], 42, "s");
        assert!(e.has_tag(tags::BREACH));
        assert_eq!(attr(&e, "hits"), Some("42"));
        assert_eq!(attr(&e, "returned"), Some("0"));
        assert_eq!(attr(&e, "top_databases"), None);
        assert_eq!(attr(&e, "earliest_record"), None);
        assert_eq!(attr(&e, "latest_record"), None);
    }
}
