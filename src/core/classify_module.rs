//! `core::classify_module` — the [`Module`] that runs [`crate::core::classifier`] inside a
//! scan, turning unstructured input into typed, auto-queued seeds.
//!
//! This is the engine-facing half of the re-injection contract. Registered at the highest
//! priority (200) so it runs *first*, it accepts any value that looks like unstructured
//! text — a multi-word field, a pasted document, a scraped body, a prior scan's output,
//! or one of the project's own files — and emits every entity
//! [`extract`](crate::core::classifier::extract)ed from it. Each
//! emitted entity of a scannable kind is automatically re-queued by the engine
//! (`min_expand_confidence` gate → [`TargetKind::from_entity_kind`] → fresh dispatch), so
//! a pivot chain started from raw text runs to exhaustion. A candidate that is classified
//! but falls below the re-injection floor is **not silently dropped**: it is announced on
//! the event bus as [`EntityExcluded`](crate::core::event::EventKind::EntityExcluded) with
//! the reason, so expansion is never a black box.
//!
//! Passive and offline: the classifier does no network or disk I/O, so this module is
//! `is_passive() == true` and costs nothing on a metered Termux link.

use async_trait::async_trait;

use crate::core::classifier::{self};
use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::core::error::Result;
use crate::core::event::{Event, EventKind};
use crate::core::module::{Module, ModuleCategory, ModuleContext, ModuleResult};
use crate::core::scan::{Target, TargetKind};

/// The universal entity classifier as an engine module: types any value and extracts
/// embedded entities from unstructured text so every output is re-injectable as a seed.
pub struct ClassifyModule;

#[async_trait]
impl Module for ClassifyModule {
    fn name(&self) -> &'static str {
        "classifier"
    }

    fn description(&self) -> &'static str {
        "Universal entity classifier — types any value and extracts embedded entities from \
         unstructured text, so every output (the system's own included) becomes a seed"
    }

    /// Highest priority: classification runs before any collector, so embedded entities
    /// are on the queue from round one.
    fn priority(&self) -> u8 {
        200
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Other
    }

    /// Reconnaissance attribution: extracting identifiers from gathered text implements
    /// *Gather Victim Identity Information* (emails/usernames/phones) and *Gather Victim
    /// Host Information* (IPs/domains). The `Other` category default is empty, so this is
    /// the explicit override the architecture guard requires.
    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1589", "T1592"]
    }

    /// Accept the free-text target kinds — full name, organisation, address — which is
    /// where every unstructured value lands after the unified-scan detector runs (a
    /// multi-word field, a pasted document, a scraped body, a prior scan's textual
    /// output, one of the project's own source files). A clean single structured token
    /// (an email, an IP, a domain) is already typed by the detector and handled by its
    /// collectors, so re-extracting from it would add nothing — and gating by kind keeps
    /// `accepts` and [`consumes`](Module::consumes) identical, so the dispatch graph
    /// stays exact.
    fn accepts(&self, target: &Target) -> bool {
        matches!(
            target.kind,
            TargetKind::FullName | TargetKind::Organisation | TargetKind::Address
        )
    }

    /// Gates by value shape, not kind, so the default `accepts`-probe would misreport an
    /// empty consume set — declare the unstructured-text target kinds explicitly.
    fn consumes(&self) -> Vec<TargetKind> {
        vec![
            TargetKind::FullName,
            TargetKind::Organisation,
            TargetKind::Address,
        ]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::Asn,
            EntityKind::Cidr,
            EntityKind::Coordinates,
            EntityKind::AbnAcn,
            EntityKind::MacAddress,
            EntityKind::CryptoAddress,
            EntityKind::DeviceId,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let src_kind = target.kind.canonical_str();
        let mut result = ModuleResult::new();

        for c in classifier::extract(&target.value) {
            if c.is_actionable() {
                // A re-injectable seed: emit it as a typed entity. The engine publishes
                // `EntityFound` and (if its confidence clears the expansion gate) queues
                // it for a fresh scan cycle — the pivot loop.
                let mut e = Entity::new(c.kind, c.value, c.confidence, ctx.scan_id.as_str());
                e.tag("classified");
                e.tag("auto-seed");
                e.add_evidence(
                    Evidence::new(
                        self.name(),
                        format!("{} match in {src_kind} input", c.signal),
                    )
                    .with_attr("signal", c.signal)
                    .with_attr("source_kind", src_kind),
                );
                result.push(e);
            } else {
                // Classified but below the re-injection floor: announce it so the pruning
                // decision is visible — nothing is discarded without first being typed.
                let _ = ctx.bus.send(Event::new(
                    ctx.scan_id.as_str(),
                    EventKind::EntityExcluded {
                        kind: c.kind.to_string(),
                        value: c.value,
                        reason: format!("classified_below_reinjection_floor:{:.2}", c.confidence),
                    },
                ));
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("classify_module_tests.rs");
}
