//! Australian Business Number (ABN/ACN) lookup via the ABR JSON API.
//!
//! Consumes `Organisation` and `AbnAcn` target kinds (enabled by
//! Phase 0.3). Searches the Australian Business Register for matching
//! entities and emits `AbnAcn`, `Person`, `Address`, `Coordinates`, and
//! `Organisation` entities from the results — never `Domain` (the ABR
//! register carries no website field).
//!
//! Free API — requires a GUID from <https://abr.business.gov.au/Tools/WebServicesRegister>
//! (instant, free registration). Set `HUNTSMAN_ABR_GUID` in the env file.

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

mod fetch;
pub(crate) mod parse;

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "abn_lookup";

const KEY_ENV: &str = "HUNTSMAN_ABR_GUID";
pub(super) const BASE_URL: &str = "https://abr.business.gov.au/json";

/// Cap on ABR `MatchingNames` candidates expanded into entities. Matches the
/// sibling AU government registers (`asic_persons`, `asic_business_names`,
/// `acnc_charities`, `gleif_lei` all bound at 100) — high enough that no genuine
/// API-ranked result is omitted, honouring the no-omission directive. The ABR
/// `MatchingNames.aspx` endpoint sets no server-side cap, so the full ranked
/// candidate set must be walked here.
pub(super) const MAX_NAME_HITS: usize = 100;

/// Cap on registered trading names (`BusinessName`) expanded per ABN. A single
/// ABN realistically holds far fewer; this only guards a pathological record.
pub(super) const MAX_TRADING_NAMES: usize = 25;

pub struct AbnLookup;

#[async_trait]
impl Module for AbnLookup {
    fn name(&self) -> &'static str {
        "abn_lookup"
    }

    fn description(&self) -> &'static str {
        "Australian Business Register ABN/ACN/name lookup"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): dispatched right after the
        // top enumerators (see_know 128, oathnet 127) and ahead of the generic
        // free modules, so authoritative registry data lands early. ABN/ACN is
        // the flagship AU government source — highest of the gov band.
        118
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Organisation | TargetKind::AbnAcn | TargetKind::FullName
        )
    }

    fn is_passive(&self) -> bool {
        // NOT passive: fetch_jsonp curls the Australian Business Register
        // API. Passive is defined as local-sensor / no-network, and
        // `--passive-only` is documented as skipping network-reaching
        // modules, so this outbound lookup must report false.
        false
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A business/entity registry: it establishes the organisation
        // (T1591.002 Business Relationships) and geocodes its registered address
        // to coordinates, so it also Determines Physical Locations (T1591.001) —
        // which the Corporate default omits. It surfaces no individual
        // officer/role, so the default's T1591.004 (Identify Roles) is dropped
        // (cf. au_people / oathnet_pro).
        &["T1591.001", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::AbnAcn,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Organisation,
            EntityKind::Person,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // fetch_jsonp does a curl with a 10s --max-time (wrapped in a 12s
        // tokio timeout) and, on a 429, sleeps 5s before a second identical
        // curl — a ~29s worst case. The default 3s MODULE_TIMEOUT_MS killed
        // process() before even the first fetch could complete, so this
        // module returned nothing on any real-latency network. Budget for
        // the full retry path with headroom.
        30_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let guid = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        match target.kind {
            TargetKind::AbnAcn => {
                let digits = crate::util::str_util::ascii_digits(value);
                if digits.len() == 11 {
                    if let Some(data) = fetch::fetch_abn(guid, &digits).await? {
                        parse::parse_abn_result(&data, &ctx.scan_id, &mut result);
                    }
                } else if digits.len() == 9 {
                    if let Some(data) = fetch::fetch_acn(guid, &digits).await? {
                        parse::parse_abn_result(&data, &ctx.scan_id, &mut result);
                    }
                } else {
                    return Err(crate::core::error::Error::module(
                        SRC,
                        format!("'{value}' is not a valid ABN (11 digits) or ACN (9 digits)"),
                    ));
                }
            }
            TargetKind::Organisation | TargetKind::FullName => {
                if let Some(data) = fetch::fetch_name(guid, value).await? {
                    parse::parse_name_results(&data, value, &ctx.scan_id, &mut result);
                }
            }
            _ => {}
        }

        Ok(result)
    }
}
