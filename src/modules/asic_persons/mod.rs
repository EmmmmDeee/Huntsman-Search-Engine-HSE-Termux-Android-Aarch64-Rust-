//! ASIC people registers — banned/disqualified persons, financial advisers, and
//! credit/finance-broker representatives. Free, **no API key** (the open
//! data.gov.au datastore, unlike the key-gated [`crate::modules::abn_lookup`]).
//!
//! For a personal name this queries three authoritative ASIC registers the
//! corporate regulator publishes as open data:
//!
//! * **Banned & Disqualified Persons** — people ASIC has banned from providing
//!   financial services or disqualified from managing corporations. A hit is a
//!   high-signal adverse finding (the ban type, period, and the person's
//!   suburb/state).
//! * **Financial Advisers Register** — every current/former licensed financial
//!   adviser: their role and registration status, the **licensee they operate
//!   under** (employer), its AFS licence number and ABN, and any recorded
//!   **disciplinary action**.
//! * **Credit Representatives** — mortgage and finance brokers authorised under
//!   a credit licence: the rep's ABN/ACN, the credit licence they act under, and
//!   their authorisation period and registered locality — a distinct lending
//!   industry the advisers register doesn't cover.
//!
//! Each is queried by name through the data.gov.au CKAN `datastore_search`
//! API (full-text, keyless) and matched on all of the target's name tokens. The
//! findings are synergistic: the licensee becomes an `Organisation`, its ABN an
//! `AbnAcn`, and the registered address an `Address`, each a pivot into the rest
//! of the AU stack ([`crate::modules::abn_lookup`], `asic_director`,
//! `au_property`, `geocode`). No mock: the JSON is fetched live from ASIC's own
//! open dataset.

mod adviser;
mod banned;
mod credit;
mod shared;

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

use adviser::emit_adviser;
use banned::emit_banned;
use credit::emit_credit_rep;
use shared::{ckan_query, name_tokens, record_name_matches};

const SRC: &str = "asic_persons";
/// data.gov.au CKAN action base — `datastore_search` is appended by
/// [`crate::util::ckan::datastore_search`].
const CKAN_BASE: &str = "https://data.gov.au/data/api/3/action";
/// ASIC – Banned and Disqualified Persons dataset (data.gov.au resource).
const BANNED_RES: &str = "741da9e3-7e0c-458e-830c-c518698e1788";
/// ASIC – Financial Advisers dataset (data.gov.au resource).
const ADVISER_RES: &str = "91d80440-5787-46fc-99de-0c1d93e6cc9f";
/// ASIC – Credit Representative dataset (mortgage/finance brokers).
const CREDIT_RES: &str = "999d9e92-df2c-4d6d-b580-321dcd205292";
/// Max matched records surfaced per register. Raised to the query `limit` so no
/// genuine register hit is omitted (directive: never omit an API-derived AU
/// government result); the per-row name classifier still gates quality.
const MAX_HITS: usize = 100;

pub struct AsicPersons;

#[async_trait]
impl Module for AsicPersons {
    fn name(&self) -> &'static str {
        "asic_persons"
    }

    fn description(&self) -> &'static str {
        "ASIC people-registers recon (keyless) — pivots a name across banned & disqualified, financial advisers, and credit/finance-broker representatives to regulatory status, licensee, disciplinary action, and address"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band, alongside the other AU registries.
        112
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only; the multi-token name gate is applied in process().
        matches!(t.kind, TargetKind::FullName)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Confirms a person's role (adviser/licensee — T1591.004), the business
        // relationship to that licensee (T1591.002), and their registered
        // location (T1591.001).
        &["T1591.002", "T1591.004", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let tokens = name_tokens(&target.value);
        // A single token is too ambiguous for a national name register.
        if tokens.len() < 2 {
            return Ok(result);
        }

        let (banned, advisers, credit) = tokio::join!(
            ckan_query(ctx, BANNED_RES, &target.value),
            ckan_query(ctx, ADVISER_RES, &target.value),
            ckan_query(ctx, CREDIT_RES, &target.value),
        );

        // The three registers are independent concurrent CKAN queries (T2.118),
        // so this mirrors `niamonx`'s multi-endpoint fold (T2.114): the last
        // hard failure across them is remembered, real evidence from any register
        // that DID answer is always kept, and only a genuine zero-evidence
        // outcome with at least one real failure surfaces as an error via
        // `ModuleResult::or_hard_failure` — a total data.gov.au outage no longer
        // reads as "this person is in none of ASIC's people registers".
        let mut hard_failure: Option<Error> = None;
        match banned {
            Ok(records) => {
                for rec in records
                    .iter()
                    .filter(|r| record_name_matches(r, "BD_PER_NAME", &tokens))
                    .take(MAX_HITS)
                {
                    emit_banned(rec, &ctx.scan_id, &mut result);
                }
            }
            Err(e) => {
                hard_failure.get_or_insert(e);
            }
        }
        match advisers {
            Ok(records) => {
                for rec in records
                    .iter()
                    .filter(|r| record_name_matches(r, "ADV_NAME", &tokens))
                    .take(MAX_HITS)
                {
                    emit_adviser(rec, &ctx.scan_id, &mut result);
                }
            }
            Err(e) => {
                hard_failure.get_or_insert(e);
            }
        }
        match credit {
            Ok(records) => {
                for rec in records
                    .iter()
                    .filter(|r| record_name_matches(r, "CRED_REP_NAME", &tokens))
                    .take(MAX_HITS)
                {
                    emit_credit_rep(rec, &ctx.scan_id, &mut result);
                }
            }
            Err(e) => {
                hard_failure.get_or_insert(e);
            }
        }

        result.or_hard_failure(hard_failure)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
