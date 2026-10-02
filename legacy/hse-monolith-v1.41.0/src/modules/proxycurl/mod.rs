//! Proxycurl LinkedIn profile extraction. Paid (Bearer Token).
//!
//! **Permanently dead** (2026-08-26): the vendor (`nubela.co`) sunset this
//! API entirely — "The Proxycurl API has been sunset and is no longer
//! available. The team behind Proxycurl has moved on to…" (confirmed live
//! against a real key). This is not a transient drift or a bad key: no key,
//! new or old, will ever work again. `process` short-circuits before making
//! a request so a scan never spends a dispatch slot / wall-clock budget on a
//! call that cannot succeed. The module stays registered — its entity/evidence
//! shape, ATT&CK mapping, and correlator/tests integration are left intact —
//! rather than a wider removal across the ~30 files that reference it, since
//! nothing about that shape is wrong, only the live endpoint. Revisit if the
//! vendor's stated successor turns out to expose a compatible API worth
//! wiring in (unverified — the sunset notice truncated the name), or delete
//! outright once someone has time to audit and update every reference.
//!
//! Dead endpoints (kept only as a paper trail, not called):
//! - username / URL → `GET …/api/v2/linkedin?url=https://linkedin.com/in/{id}`
//! - email          → `GET …/api/linkedin/profile/resolve/email?work_email=…`
//!
//! Auth: Bearer Token (`HUNTSMAN_PROXYCURL_KEY`).
//!
//! Every field the paid API returns is mapped to an entity or evidence
//! attribute — nothing harvested is discarded. The field → output mapping:
//!
//! | LinkedIn field                         | Output                              |
//! |----------------------------------------|-------------------------------------|
//! | `full_name` / `first`+`last`           | `Person` (name)                     |
//! | `headline`,`occupation`,`summary`,…    | evidence attrs on the `Person`      |
//! | `city`/`state`/`country_full_name`     | `Address` (+`country:` tag)         |
//! | `experiences[].company`/`title`/dates/`location` | `Organisation` (+attrs)   |
//! | `education[].school`/`degree`/`field`  | `education` attr on the `Person`    |
//! | `certifications[].name`/`authority`    | `certifications` attr on the `Person` |
//! | `personal_emails[]`                    | `Email` + derived non-freemail `Domain` |
//! | `personal_numbers[]`                   | `Phone`                             |
//!
//! The whole field→entity mapping lives in the pure `build::build_entities`,
//! kept `#[cfg(test)]`-only alongside its parsing types and URL builder since
//! nothing in the live path calls them anymore (`process` is a bare
//! short-circuit — see above). The tests keep the mapping logic validated and
//! ready to re-wire if this is ever pointed at a live endpoint again.

#[cfg(test)]
mod build;
#[cfg(test)]
mod types;
#[cfg(test)]
mod url;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct Proxycurl;

#[async_trait]
impl Module for Proxycurl {
    fn name(&self) -> &'static str {
        "proxycurl"
    }
    fn description(&self) -> &'static str {
        "LinkedIn profile recon via Proxycurl — harvests employment, education, and certifications to enrich a target"
    }
    fn priority(&self) -> u8 {
        88
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Username | TargetKind::Url | TargetKind::Email
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A LinkedIn profile yields the person's name + role (the People default
        // T1589.003 + T1591.004), their employers (T1591.002 Business
        // Relationships), and their city/state location (T1591.001 Physical
        // Locations). Superset of the default — coverage cannot regress.
        &["T1589.003", "T1591.004", "T1591.002", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Email,
            EntityKind::Domain,
            EntityKind::Phone,
            EntityKind::Organisation,
            EntityKind::Url,
            // The LinkedIn vanity handle (public_identifier) as a cross-platform
            // identity pivot.
            EntityKind::Username,
        ];
        KINDS
    }

    async fn process(&self, _target: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
        // Vendor sunset the whole API (see module doc) — never dispatch, key or
        // no key, so a scan never spends a slot on a call that cannot succeed.
        Ok(ModuleResult::new())
    }
}
