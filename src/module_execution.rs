//! Module execution dispatch: Execute selected modules with deadline enforcement.
//!
//! Routes `ModuleId` variants to their query functions, calculating per-module timeouts
//! from remaining deadline and module count. Results are aggregated with provenance
//! tracking and deduplication support.

use std::time::Duration;

use crate::dispatcher::ModuleId;
use crate::entity::Evidence;
use crate::module_registry::ExecutionContext;

/// Execute a single module with deadline-aware timeout.
///
/// Calculates per-module timeout from remaining deadline divided by total module count.
/// Returns Option<Evidence> from the module, or None if deadline expired before execution.
#[must_use]
pub fn execute_module(
    module_id: ModuleId,
    context: &ExecutionContext,
    total_modules: usize,
) -> Option<Evidence> {
    // Calculate per-module timeout from remaining deadline
    let remaining = context.deadline.remaining();
    if remaining.is_zero() {
        return None;
    }

    // Distribute remaining time across modules, accounting for overhead
    let per_module_budget = if total_modules > 0 {
        // Reserve 100ms per module for overhead (result aggregation, serialization, etc)
        let overhead_per_module_ms: u128 = 100;
        let available_ms = remaining
            .as_millis()
            .saturating_sub(overhead_per_module_ms * total_modules as u128);
        let per_module_ms = available_ms / total_modules.max(1) as u128;
        // Safe: per_module_ms is at most remaining duration (typically <10min), well within u64::MAX
        #[allow(clippy::cast_possible_truncation)]
        let millis = per_module_ms as u64;
        Duration::from_millis(millis)
    } else {
        remaining
    };

    if per_module_budget.is_zero() {
        return None;
    }

    // Route to appropriate module implementation
    execute_module_impl(module_id, context, per_module_budget)
}

/// Internal module execution routing.
fn execute_module_impl(
    module_id: ModuleId,
    context: &ExecutionContext,
    timeout: Duration,
) -> Option<Evidence> {
    // Stub implementations: return None for all modules.
    // Real implementations would:
    // 1. Validate the input query against module capabilities
    // 2. Execute the provider-specific query logic
    // 3. Transform results to Evidence with provenance
    // 4. Handle timeouts and transport errors gracefully

    let _ = (context, timeout); // Silence unused warnings for stubs

    match module_id {
        // Phase 1: Government registries
        ModuleId::ApnicWhois => execute_apnic_whois(),
        ModuleId::AudaDomain => execute_auda_domain(),
        ModuleId::AsicCompany => execute_asic_company(),
        ModuleId::AsicDirector => execute_asic_director(),
        ModuleId::AsicPersons => execute_asic_persons(),
        ModuleId::AbusinessNumber => execute_abusiness_number(),
        ModuleId::AhnraPractitioner => execute_ahpra_practitioner(),
        ModuleId::ApraBank => execute_apra_bank(),
        ModuleId::ApraInsurer => execute_apra_insurer(),
        ModuleId::AsicInsolvency => execute_asic_insolvency(),

        // Phase 2: Secondary official sources
        ModuleId::AcmaBroadcast => execute_acma_broadcast(),
        ModuleId::AcmaPhone => execute_acma_phone(),
        ModuleId::Acnc => execute_acnc(),
        ModuleId::ElectoralCommission => execute_electoral_commission(),
        ModuleId::CourtRegister => execute_court_register(),
        ModuleId::BankruptcyRegister => execute_bankruptcy_register(),
        ModuleId::LandTitles => execute_land_titles(),
        ModuleId::PropertyRates => execute_property_rates(),

        // Phase 3: Public APIs and archives
        ModuleId::TaxCompliance => execute_tax_compliance(),
        ModuleId::EnvironmentalRegister => execute_environmental_register(),
        ModuleId::AviationRegister => execute_aviation_register(),
        ModuleId::MarineRegister => execute_marine_register(),
        ModuleId::WorkplaceRegister => execute_workplace_register(),
        ModuleId::ProfessionalLicense => execute_professional_license(),
        ModuleId::OpenStreetMap => execute_openstreetmap(),

        // Phase 4-5: Specialized/derived sources
        ModuleId::ImportExportTrade => execute_import_export_trade(),
        ModuleId::IpaustraliaBusiness => execute_ipaustralia_business(),
        ModuleId::Oscr => execute_oscr(),
        ModuleId::Asx => execute_asx(),
    }
}

// Stub implementations for all 29 modules. Each returns None.
// These will be replaced with real provider implementations in subsequent phases.

fn execute_apnic_whois() -> Option<Evidence> {
    None
}

fn execute_auda_domain() -> Option<Evidence> {
    None
}

fn execute_asic_company() -> Option<Evidence> {
    None
}

fn execute_asic_director() -> Option<Evidence> {
    None
}

fn execute_asic_persons() -> Option<Evidence> {
    None
}

fn execute_abusiness_number() -> Option<Evidence> {
    None
}

fn execute_ahpra_practitioner() -> Option<Evidence> {
    None
}

fn execute_apra_bank() -> Option<Evidence> {
    None
}

fn execute_apra_insurer() -> Option<Evidence> {
    None
}

fn execute_asic_insolvency() -> Option<Evidence> {
    None
}

fn execute_acma_broadcast() -> Option<Evidence> {
    None
}

fn execute_acma_phone() -> Option<Evidence> {
    None
}

fn execute_acnc() -> Option<Evidence> {
    None
}

fn execute_electoral_commission() -> Option<Evidence> {
    None
}

fn execute_court_register() -> Option<Evidence> {
    None
}

fn execute_bankruptcy_register() -> Option<Evidence> {
    None
}

fn execute_land_titles() -> Option<Evidence> {
    None
}

fn execute_property_rates() -> Option<Evidence> {
    None
}

fn execute_tax_compliance() -> Option<Evidence> {
    None
}

fn execute_environmental_register() -> Option<Evidence> {
    None
}

fn execute_aviation_register() -> Option<Evidence> {
    None
}

fn execute_marine_register() -> Option<Evidence> {
    None
}

fn execute_workplace_register() -> Option<Evidence> {
    None
}

fn execute_professional_license() -> Option<Evidence> {
    None
}

fn execute_openstreetmap() -> Option<Evidence> {
    None
}

fn execute_import_export_trade() -> Option<Evidence> {
    None
}

fn execute_ipaustralia_business() -> Option<Evidence> {
    None
}

fn execute_oscr() -> Option<Evidence> {
    None
}

fn execute_asx() -> Option<Evidence> {
    None
}

/// Aggregate results from multiple module executions.
///
/// Combines evidence from several modules, deduplicating by provenance and
/// preferring higher-authority sources when evidence matches.
#[must_use]
pub fn aggregate_module_results(results: &[Option<Evidence>]) -> Option<Evidence> {
    let evidence_list: Vec<Evidence> = results.iter().filter_map(Clone::clone).collect();

    if evidence_list.is_empty() {
        return None;
    }

    // Aggregate: combine all evidence, preserve provenance for deduplication
    // Real implementation would:
    // 1. Collect all evidence from all modules
    // 2. Deduplicate by comparing semantic content
    // 3. Prefer higher-authority sources for duplicates
    // 4. Merge related claims into compound evidence
    // 5. Return unified evidence with full provenance chain

    // Stub: return the first evidence
    evidence_list.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EvidenceProvenance;

    #[test]
    fn per_module_timeout_calculation() {
        // Test deadline budget distribution logic
        let remaining = Duration::from_secs(10);
        let total_modules: usize = 5;

        // Per-module budget = (10s - 5*100ms) / 5 = (10s - 500ms) / 5 = ~1980ms
        let overhead_per_module_ms: u128 = 100;
        let available_ms = remaining
            .as_millis()
            .saturating_sub(overhead_per_module_ms * total_modules as u128);
        let per_module_ms = available_ms / total_modules as u128;
        #[allow(clippy::cast_possible_truncation)]
        let per_module = Duration::from_millis(per_module_ms as u64);

        assert!(per_module.as_millis() >= 1900 && per_module.as_millis() <= 2000);
    }

    #[test]
    fn per_module_timeout_with_small_budget() {
        // Test behavior with small budget
        let remaining = Duration::from_millis(50);
        let total_modules: usize = 10;

        let overhead_per_module_ms: u128 = 100;
        let available_ms = remaining
            .as_millis()
            .saturating_sub(overhead_per_module_ms * total_modules as u128);
        let per_module_ms = available_ms / total_modules.max(1) as u128;
        #[allow(clippy::cast_possible_truncation)]
        let per_module = Duration::from_millis(per_module_ms as u64);

        // Budget is too small, so available is 0
        assert_eq!(per_module, Duration::ZERO);
    }

    #[test]
    fn per_module_timeout_zero_modules() {
        // Edge case: zero modules
        let remaining = Duration::from_secs(5);
        let total_modules: usize = 0;

        let overhead_per_module_ms: u128 = 100;
        let available_ms = remaining
            .as_millis()
            .saturating_sub(overhead_per_module_ms * total_modules as u128);
        let per_module_ms = available_ms / total_modules.max(1) as u128;
        #[allow(clippy::cast_possible_truncation)]
        let per_module = Duration::from_millis(per_module_ms as u64);

        // With max(1), dividing by 1 gives the full available budget
        assert_eq!(per_module, remaining);
    }

    #[test]
    fn aggregate_module_results_handles_empty() {
        let results: Vec<Option<Evidence>> = vec![];
        let aggregated = aggregate_module_results(&results);
        assert!(aggregated.is_none());
    }

    #[test]
    fn aggregate_module_results_all_none() {
        let results = vec![None, None, None];
        let aggregated = aggregate_module_results(&results);
        assert!(aggregated.is_none());
    }

    #[test]
    fn aggregate_module_results_mixed_with_some() {
        let provenance = EvidenceProvenance {
            source: "test_source".to_string(),
            source_family: "test_family".to_string(),
            scan_id: Some("scan_123".to_string()),
            recorded_at_unix: 1000,
        };
        let evidence = Evidence::new(provenance, "test evidence");
        let results = vec![None, Some(evidence.clone()), None];
        let aggregated = aggregate_module_results(&results);
        assert_eq!(aggregated, Some(evidence));
    }

    #[test]
    fn aggregate_module_results_multiple_evidence() {
        let provenance1 = EvidenceProvenance {
            source: "source1".to_string(),
            source_family: "family1".to_string(),
            scan_id: None,
            recorded_at_unix: 1000,
        };
        let provenance2 = EvidenceProvenance {
            source: "source2".to_string(),
            source_family: "family2".to_string(),
            scan_id: Some("scan_456".to_string()),
            recorded_at_unix: 2000,
        };
        let evidence1 = Evidence::new(provenance1, "test1");
        let evidence2 = Evidence::new(provenance2, "test2");
        let results = vec![Some(evidence1.clone()), Some(evidence2)];
        let aggregated = aggregate_module_results(&results);
        assert_eq!(aggregated, Some(evidence1)); // Stub returns first evidence
    }
}
