//! DeHashed breach search (v2 API). Paid; requires `HUNTSMAN_DEHASHED_KEY`
//! **and** an active DeHashed *search subscription* + API credits on the
//! account.
//!
//! Endpoint: `POST https://api.dehashed.com/v2/search`
//! Auth:     `Dehashed-Api-Key: <key>` header.
//!
//! v2 is **key-only**. The legacy v1 `GET /search` endpoint (HTTP Basic with
//! an account email + key) was sunset and now returns 404, so the old
//! account-email variable (formerly required alongside the key) is gone — a
//! single API key is all v2 needs.
//!
//! Per the project's no-credentials-in-evidence invariant, we deliberately do
//! NOT bind the `password` / `hashed_password` fields a v2 entry carries —
//! serde drops every field we don't name, so they can't even accidentally be
//! surfaced. Only aggregate metadata escapes: total hits, rows returned, the
//! top source databases, and the remaining API credit balance.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::handle_keyed_error;
use crate::util::http::RequestBuilderExt;

const KEY_ENV: &str = "HUNTSMAN_DEHASHED_KEY";

/// v2 search endpoint — POST, JSON body, key in the `Dehashed-Api-Key` header.
const V2_SEARCH_URL: &str = "https://api.dehashed.com/v2/search";

/// Results requested per page. The aggregate evidence only needs the server's
/// `total` count plus a representative sample of `database_name`s, so the page
/// is kept small to bound both the response size and the credit cost (v2 bills
/// against a per-account credit pool) rather than pulling up to 10,000 rows.
const PAGE_SIZE: u32 = 100;

#[derive(Deserialize)]
struct DehashedResp {
    #[serde(default)]
    entries: Option<Vec<Entry>>,
    #[serde(default)]
    total: Option<u64>,
    /// Remaining API credits after the call (v2 reports this top-level). Held
    /// as a raw JSON value so a number-or-string wire shape both render; it is
    /// operator-info only and never gates logic.
    #[serde(default)]
    balance: Option<serde_json::Value>,
}

/// Aggregate-safe subset of a v2 entry — `password`, `hashed_password`, etc.
/// are deliberately NOT bound so we can't even accidentally surface them. v2
/// returns most fields as arrays (e.g. `"database_name": ["Collection1"]`), so
/// `database_name` is captured as a raw JSON value and flattened by
/// [`db_names`], which tolerates a string, an array of strings, or null.
#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    database_name: serde_json::Value,
}

/// Flatten a v2 `database_name` value (`string | [string] | null`) into the
/// source-database names it carries. Non-string array members are skipped.
fn db_names(v: &serde_json::Value) -> Vec<&str> {
    match v {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(a) => a.iter().filter_map(serde_json::Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Render the v2 `balance` value for display, accepting either a JSON number
/// or string and rejecting anything else (or a blank string) as absent.
fn balance_str(v: &Option<serde_json::Value>) -> Option<String> {
    match v {
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    }
}

const SRC: &str = "dehashed";

/// Top breach databases to surface by frequency.
const MAX_DATABASES: usize = 5;

/// The DeHashed query selector for a target kind, or `None` for a kind this
/// module does not search. **Pure** — kept in lockstep with [`DeHashed::accepts`].
/// The v2 selector syntax is unchanged from v1 (`email:`, `username:`, …).
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

/// Build the breach entity from a v2 response. **Pure** (no network/IO): folds
/// the returned `entries` into aggregate-only evidence — total hit count, rows
/// returned, the top source databases by frequency, and the remaining credit
/// balance — and raises the breach tags. Per the no-credentials-in-evidence
/// invariant, `Entry` binds no password/hash fields, so none can leak here.
/// `total` is the server's full count (which can exceed the truncated
/// `entries.len()`).
fn build_breach_entity(
    kind: EntityKind,
    value: &str,
    selector: &str,
    entries: &[Entry],
    total: u64,
    balance: Option<&str>,
    scan_id: &str,
) -> Entity {
    let mut entity = Entity::new(kind, value, 0.88, scan_id);
    entity.tag(tags::BREACH);
    entity.tag("dehashed");

    // Top databases by frequency. v2 lists a record's source(s) in
    // `database_name` (an array), so flatten across all entries.
    let top = crate::util::freq::top_n(
        entries.iter().flat_map(|e| db_names(&e.database_name)),
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
    if let Some(b) = balance {
        ev = ev.with_attr("credit_balance", b);
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

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::Person,
            EntityKind::IpAddress,
            EntityKind::Domain,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(key) = ctx.key_opt(KEY_ENV) else {
            return Ok(ModuleResult::new());
        };
        let Some(selector) = selector_for(target.kind) else {
            return Ok(ModuleResult::new());
        };
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        // v2: POST a JSON body with the query string + pagination. The key
        // rides in the `Dehashed-Api-Key` header (no Basic auth, no email).
        let payload = serde_json::json!({
            "query": format!("{selector}:{value}"),
            "page": 1,
            "size": PAGE_SIZE,
        });

        let mut retries = 2u8;
        let body: DehashedResp = loop {
            let resp = ctx
                .http
                .post(V2_SEARCH_URL)
                .header("Dehashed-Api-Key", key)
                .header("Accept", "application/json")
                .json(&payload)
                .send_tagged(SRC).await?;
            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                // The body carries DeHashed's own reason — notably the 401
                // "You need a search subscription and API credits to use the
                // API" that an account without an active search plan returns —
                // so surface it verbatim for the operator.
                return Err(crate::util::http::http_status_error(SRC, resp).await);
            }
            break crate::util::http::json_decode(SRC, resp).await?;
        };

        let entries = body.entries.unwrap_or_default();
        let total = body.total.unwrap_or(entries.len() as u64);
        if entries.is_empty() && total == 0 {
            return Ok(ModuleResult::new());
        }

        let balance = balance_str(&body.balance);
        let mut result = ModuleResult::new();
        result.push(build_breach_entity(
            target.kind.to_entity_kind(),
            value,
            selector,
            &entries,
            total,
            balance.as_deref(),
            &ctx.scan_id,
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    fn entry(db: serde_json::Value) -> Entry {
        Entry { database_name: db }
    }

    fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn db_names_flattens_string_array_and_skips_non_strings() {
        assert_eq!(db_names(&json!("Collection1")), vec!["Collection1"]);
        assert_eq!(db_names(&json!(["A", "B"])), vec!["A", "B"]);
        assert!(db_names(&json!(null)).is_empty());
        assert!(db_names(&json!(42)).is_empty());
        // A mixed array keeps only the string members.
        assert_eq!(db_names(&json!(["A", 1, "B"])), vec!["A", "B"]);
    }

    #[test]
    fn balance_str_renders_number_and_string_only() {
        assert_eq!(balance_str(&Some(json!(500))), Some("500".to_string()));
        assert_eq!(balance_str(&Some(json!("498"))), Some("498".to_string()));
        assert_eq!(balance_str(&Some(json!("  12 "))), Some("12".to_string()));
        assert_eq!(balance_str(&Some(json!(null))), None);
        assert_eq!(balance_str(&Some(json!(""))), None);
        assert_eq!(balance_str(&None), None);
    }

    #[test]
    fn aggregates_hits_top_databases_and_balance_from_v2_arrays() {
        // v2 returns database_name as arrays; counts fold across entries, and a
        // bare scalar is tolerated too.
        let entries = [
            entry(json!(["Collection#1"])),
            entry(json!(["Collection#1"])),
            entry(json!("LinkedIn")),
        ];
        // total (900) exceeds the returned/truncated rows (3).
        let e = build_breach_entity(
            EntityKind::Email,
            "a@b.com",
            "email",
            &entries,
            900,
            Some("498"),
            "s",
        );
        assert_eq!(e.kind, EntityKind::Email);
        assert!(e.has_tag(tags::BREACH) && e.has_tag("dehashed"));
        assert!((e.confidence - 0.88).abs() < 1e-9);
        assert_eq!(attr(&e, "hits"), Some("900")); // server total, not len
        assert_eq!(attr(&e, "returned"), Some("3"));
        assert_eq!(attr(&e, "selector"), Some("email"));
        // Collection#1 (2) ranks above the scalar LinkedIn (1).
        assert_eq!(
            attr(&e, "top_databases"),
            Some("Collection#1×2, LinkedIn×1")
        );
        assert_eq!(attr(&e, "credit_balance"), Some("498"));
        // v2 carries no per-record timestamps, so no created range is surfaced.
        assert_eq!(attr(&e, "earliest_record"), None);
        assert_eq!(attr(&e, "latest_record"), None);
    }

    #[test]
    fn count_only_response_omits_optional_aggregates() {
        // total known but no entry rows + no balance (a bare count response).
        let e = build_breach_entity(EntityKind::Domain, "x.com", "domain", &[], 42, None, "s");
        assert!(e.has_tag(tags::BREACH));
        assert_eq!(attr(&e, "hits"), Some("42"));
        assert_eq!(attr(&e, "returned"), Some("0"));
        assert_eq!(attr(&e, "top_databases"), None);
        assert_eq!(attr(&e, "credit_balance"), None);
    }

    #[test]
    fn resp_parses_v2_shape_and_drops_credential_fields() {
        // The no-credentials invariant, structurally: a real v2 entry carries
        // password / hashed_password, but `Entry` binds only database_name, so
        // serde silently drops the rest — they can never reach evidence. Also
        // proves the v2 wire shape (array fields, top-level balance/total)
        // deserialises, which the inactive-subscription account blocks us from
        // observing live.
        let raw = r#"{
            "success": true,
            "total": 2,
            "balance": 498,
            "took": "5ms",
            "entries": [
                {
                    "id": "1",
                    "email": ["a@b.com"],
                    "username": ["alice"],
                    "password": ["hunter2"],
                    "hashed_password": ["5f4dcc3b5aa765d61d8327deb882cf99"],
                    "database_name": ["Collection#1"]
                }
            ]
        }"#;
        let r: DehashedResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.total, Some(2));
        let entries = r.entries.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(db_names(&entries[0].database_name), vec!["Collection#1"]);
        assert_eq!(balance_str(&r.balance), Some("498".to_string()));

        // Fold it through the builder: only aggregate metadata surfaces; no
        // password/hash attribute exists anywhere on the entity.
        let e = build_breach_entity(
            EntityKind::Email,
            "a@b.com",
            "email",
            &entries,
            r.total.unwrap(),
            balance_str(&r.balance).as_deref(),
            "s",
        );
        let all_attr_vals: String = e.evidence[0]
            .attributes
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .join("|");
        assert!(!all_attr_vals.contains("hunter2"));
        assert!(!all_attr_vals.contains("5f4dcc3b"));
        assert_eq!(attr(&e, "top_databases"), Some("Collection#1×1"));
    }
}
