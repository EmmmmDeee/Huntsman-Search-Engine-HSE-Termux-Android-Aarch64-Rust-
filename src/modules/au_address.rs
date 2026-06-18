//! Australian address structural validation.
//!
//! A **passive, zero-network** module that parses a structured Australian
//! street address, validates its state/postcode combination, and emits a
//! confirmed `Address` entity with structured evidence attributes and any
//! phone numbers embedded in the value.
//!
//! Unlike the 47 modules that emit addresses as a side-effect of broader
//! collection, `au_address` runs when the *seed* is an address, giving the
//! engine a high-confidence, tagged entry point before `geocode` and the
//! geo correlators run. The `validated` and `au-state:XX` tags it adds are
//! what AU-026 ("multi-source validated address") and AU-056 ("jurisdiction
//! cross-check") consume to fire.
//!
//! No API key, no network call, no external process.
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (parse + validate address)

use async_trait::async_trait;

use crate::core::module::ModuleContext;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::address_au;

const SRC: &str = "au_address";

pub struct AuAddress;

#[async_trait]
impl Module for AuAddress {
    fn name(&self) -> &'static str {
        "au_address"
    }

    fn description(&self) -> &'static str {
        "Validates an Australian street address offline — parses suburb/state/postcode \
         consistency, tags the entity for geo correlation rules, and extracts embedded \
         phone numbers (no API key, no network)"
    }

    fn priority(&self) -> u8 {
        40
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::Address
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address, EntityKind::Phone];
        KINDS
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001"]
    }

    fn is_passive(&self) -> bool {
        true
    }

    async fn process(&self, target: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let Some(parsed) = address_au::extract_first(&target.value) else {
            return Ok(result);
        };

        let confidence = parsed.confidence();

        // Primary validated address entity.
        let mut addr = Entity::new(EntityKind::Address, &target.value, confidence, SRC);
        addr.tag("au:address");
        addr.tag("validated");
        addr.tag(format!("au-state:{}", parsed.state));

        let mut ev = Evidence::new(
            SRC,
            format!(
                "AU address parsed: {} {}, {} {} {}",
                parsed.street_number, parsed.street, parsed.suburb, parsed.state, parsed.postcode,
            ),
        );
        ev = ev
            .with_attr("street_number", &parsed.street_number)
            .with_attr("street", &parsed.street)
            .with_attr("suburb", &parsed.suburb)
            .with_attr("state", &parsed.state)
            .with_attr("postcode", &parsed.postcode);
        if let Some(ref lvl) = parsed.level {
            ev = ev.with_attr("level", lvl);
        }
        if let Some(ref unit) = parsed.unit {
            ev = ev.with_attr("unit", unit);
        }
        addr.add_evidence(ev);
        result.push(addr);

        // Phone numbers embedded alongside the address (some database dumps
        // include "133 Main St, Brisbane QLD 4000 — Ph: 07 3200 0000").
        for phone in address_au::extract_phones(&target.value) {
            let mut p = Entity::new(EntityKind::Phone, &phone, 0.70, SRC);
            p.tag("au-phone");
            p.add_evidence(Evidence::new(
                SRC,
                format!("Phone {phone} extracted from address value"),
            ));
            result.push(p);
        }

        Ok(result)
    }
}
