//! OathNet Pro — paid premium breach-record search.
//!
//! Endpoint: `GET https://oathnet.org/api/service/v2/breach/search`
//! Auth:     `x-api-key: <HUNTSMAN_OATHNET_KEY>` (read from
//!           `$HOME/.huntsman.env` or the process environment).
//!
//! Maps every accepting `TargetKind` (Email / Username / Phone / IpAddress /
//! Domain) onto OathNet's typed array filters (`email[]`, `username[]`, ...)
//! and emits a single parent entity summarising the hits.
//!
//! Security: passwords and raw PII are NEVER stored in evidence — only
//! aggregate metadata (total hits, top dbnames, indexed-at bookends).
//! The API key is read once from `ModuleContext` and sent as a header;
//! it is never logged, persisted, or included in any event payload.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_OATHNET_KEY";
const ENDPOINT: &str = "https://oathnet.org/api/service/v2/breach/search";
const PAGE_SIZE: &str = "50";
const MAX_DBNAMES: usize = 5;

pub struct OathnetPro;

#[derive(Deserialize)]
struct Envelope {
    data: Option<Data>,
}

#[derive(Deserialize)]
struct Data {
    #[serde(default)]
    items: Vec<Item>,
    #[serde(default)]
    meta: Option<Meta>,
}

/// Only the aggregate-safe fields are deserialised. `email`, `password`,
/// `phone`, `username`, `address`, etc. are deliberately left off — the
/// architecture invariant forbids storing credential/PII content in
/// evidence, so we never read them in the first place.
#[derive(Deserialize)]
struct Item {
    #[serde(default)]
    dbname: Option<String>,
    #[serde(default)]
    indexed_at: Option<String>,
}

#[derive(Deserialize)]
struct Meta {
    #[serde(default)]
    total: u64,
    #[serde(default)]
    has_more: bool,
}

#[async_trait]
impl Module for OathnetPro {
    fn name(&self) -> &'static str {
        "oathnet_pro"
    }

    fn priority(&self) -> u8 {
        128
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
                | TargetKind::IpAddress
                | TargetKind::Domain
        )
    }

    // Paid endpoint with structured filtering can take longer than the
    // 3 s crate-wide default; give it room without blocking the scan.
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;

        let field = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Phone => "phone",
            TargetKind::IpAddress => "ip",
            TargetKind::Domain => "domain",
            _ => return Ok(ModuleResult::new()),
        };
        let array_param = format!("{field}[]");

        let resp = ctx
            .http
            .get(ENDPOINT)
            .header("x-api-key", key)
            .query(&[
                (array_param.as_str(), target.value.as_str()),
                ("page_size", PAGE_SIZE),
            ])
            .send()
            .await
            .map_err(|e| Error::module("oathnet_pro", e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(
                "oathnet_pro",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let env: Envelope = resp
            .json()
            .await
            .map_err(|e| Error::module("oathnet_pro", e.to_string()))?;

        let Some(data) = env.data else {
            return Ok(ModuleResult::new());
        };
        if data.items.is_empty() {
            return Ok(ModuleResult::new());
        }

        let total = data.meta.as_ref().map_or(data.items.len() as u64, |m| {
            m.total.max(data.items.len() as u64)
        });
        let has_more = data.meta.as_ref().is_some_and(|m| m.has_more);

        // ISO 8601 timestamps sort correctly as ASCII strings.
        let first_indexed = data
            .items
            .iter()
            .filter_map(|i| i.indexed_at.as_deref())
            .min();
        let last_indexed = data
            .items
            .iter()
            .filter_map(|i| i.indexed_at.as_deref())
            .max();

        let mut dbname_counts: std::collections::BTreeMap<&str, u32> =
            std::collections::BTreeMap::new();
        for item in &data.items {
            if let Some(db) = item.dbname.as_deref() {
                *dbname_counts.entry(db).or_insert(0) += 1;
            }
        }
        let mut ranked: Vec<(&str, u32)> = dbname_counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        ranked.truncate(MAX_DBNAMES);
        let top_dbnames = ranked
            .iter()
            .map(|(db, n)| format!("{db}×{n}"))
            .collect::<Vec<_>>()
            .join(", ");

        let kind = entity_kind_for(target.kind);
        let mut entity = Entity::new(kind, &target.value, 0.85, &ctx.scan_id);
        entity.tag("breach");
        entity.tag("oathnet-pro");
        if has_more {
            entity.tag("partial");
        }

        let summary = if has_more {
            format!("OathNet Pro: {total} breach record(s), more available")
        } else {
            format!("OathNet Pro: {total} breach record(s)")
        };
        let mut ev = Evidence::new("oathnet_pro", summary)
            .with_attr("hits", total.to_string())
            .with_attr("returned", data.items.len().to_string())
            .with_attr("page_size", PAGE_SIZE);
        if !top_dbnames.is_empty() {
            ev = ev.with_attr("top_dbnames", top_dbnames);
        }
        if let Some(t) = first_indexed {
            ev = ev.with_attr("first_indexed_at", t);
        }
        if let Some(t) = last_indexed {
            ev = ev.with_attr("last_indexed_at", t);
        }
        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

fn entity_kind_for(t: TargetKind) -> EntityKind {
    match t {
        TargetKind::Email => EntityKind::Email,
        TargetKind::Username => EntityKind::Username,
        TargetKind::Phone => EntityKind::Phone,
        TargetKind::IpAddress => EntityKind::IpAddress,
        TargetKind::Domain => EntityKind::Domain,
        // accepts() gates the call sites, so other kinds are unreachable
        // in practice; map to Other rather than panic for defensiveness
        // at the trait boundary.
        _ => EntityKind::Other("unknown".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_identity_and_infra_kinds() {
        let m = OathnetPro;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::IpAddress,
            TargetKind::Domain,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
        assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
        assert!(!m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
    }

    #[test]
    fn cost_is_paid() {
        assert!(matches!(OathnetPro.cost(), ModuleCost::Paid));
    }

    #[test]
    fn timeout_exceeds_default() {
        // Paid endpoint with structured filtering can be slower than the
        // 3 s crate default — verify the module asks for more headroom.
        assert!(OathnetPro.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
    }

    #[test]
    fn entity_kind_mapping_is_total_for_accepted_targets() {
        // Every kind accept()s on must map to a concrete EntityKind,
        // not the Other("unknown") fallback.
        for (tk, ek) in [
            (TargetKind::Email, EntityKind::Email),
            (TargetKind::Username, EntityKind::Username),
            (TargetKind::Phone, EntityKind::Phone),
            (TargetKind::IpAddress, EntityKind::IpAddress),
            (TargetKind::Domain, EntityKind::Domain),
        ] {
            assert_eq!(entity_kind_for(tk), ek);
        }
    }
}
