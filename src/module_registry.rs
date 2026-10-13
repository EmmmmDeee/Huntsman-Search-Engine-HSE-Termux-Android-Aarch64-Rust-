//! Module Integration Layer: Central registry for all OSINT modules.
//!
//! Provides module discovery, selection, and execution with deadline enforcement.
//! All 29 modules are registered with consistent signatures and timeout handling.

use std::collections::HashMap;
use std::time::Duration;

use crate::deadline::Deadline;
use crate::dispatcher::ModuleId;
use crate::http::Transport;

/// Query types that determine which modules to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    /// Domain name (e.g., example.com.au)
    Domain,
    /// Person name (individual)
    Person,
    /// Company name or ACN
    Company,
    /// IP address (v4 or v6)
    IpAddress,
    /// Phone number
    Phone,
    /// ABN (Australian Business Number)
    Abn,
    /// General/unclassified query
    General,
}

/// Phase identifier for module selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Phase 1: Government registries (high authority)
    Phase1,
    /// Phase 2: Secondary official sources (courts, land, electoral)
    Phase2,
    /// Phase 3: Public APIs and archives
    Phase3,
    /// Phase 4: Derived and pattern-based sources
    Phase4,
    /// Phase 5: Specialized/niche sources
    Phase5,
}

impl Phase {
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Phase1 => 1,
            Self::Phase2 => 2,
            Self::Phase3 => 3,
            Self::Phase4 => 4,
            Self::Phase5 => 5,
        }
    }

    #[must_use]
    pub const fn timeout_budget(self) -> Duration {
        match self {
            Self::Phase1 => Duration::from_secs(30),
            Self::Phase2 => Duration::from_secs(25),
            Self::Phase3 => Duration::from_secs(20),
            Self::Phase4 => Duration::from_secs(15),
            Self::Phase5 => Duration::from_secs(10),
        }
    }
}

/// Module execution context with deadline and transport.
pub struct ExecutionContext<'t> {
    pub query: String,
    pub query_type: QueryType,
    pub deadline: &'t Deadline<'t>,
    pub transport: &'t dyn Transport,
}

/// Central registry for all 29 OSINT modules.
pub struct ModuleRegistry {
    modules: HashMap<ModuleId, ModuleMetadata>,
}

/// Metadata about a module for selection and routing.
#[derive(Debug, Clone)]
pub struct ModuleMetadata {
    pub id: ModuleId,
    pub name: &'static str,
    pub phases: Vec<Phase>,
    pub supported_queries: Vec<QueryType>,
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleRegistry {
    /// Create a new module registry with all 29 modules registered.
    #[must_use]
    pub fn new() -> Self {
        Self {
            modules: Self::register_modules(),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn register_modules() -> HashMap<ModuleId, ModuleMetadata> {
        let mut modules = HashMap::new();

        // Phase 1: Government registries (highest authority, tier 1)
        modules.insert(
            ModuleId::ApnicWhois,
            ModuleMetadata {
                id: ModuleId::ApnicWhois,
                name: "APNIC WHOIS",
                phases: vec![Phase::Phase1],
                supported_queries: vec![QueryType::IpAddress],
            },
        );

        modules.insert(
            ModuleId::AudaDomain,
            ModuleMetadata {
                id: ModuleId::AudaDomain,
                name: "auDA Domain Registry",
                phases: vec![Phase::Phase1],
                supported_queries: vec![QueryType::Domain],
            },
        );

        modules.insert(
            ModuleId::AsicCompany,
            ModuleMetadata {
                id: ModuleId::AsicCompany,
                name: "ASIC Company Register",
                phases: vec![Phase::Phase1],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::AsicDirector,
            ModuleMetadata {
                id: ModuleId::AsicDirector,
                name: "ASIC Director Register",
                phases: vec![Phase::Phase1],
                supported_queries: vec![QueryType::Person, QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::AsicPersons,
            ModuleMetadata {
                id: ModuleId::AsicPersons,
                name: "ASIC Persons Register",
                phases: vec![Phase::Phase1],
                supported_queries: vec![QueryType::Person, QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::AbusinessNumber,
            ModuleMetadata {
                id: ModuleId::AbusinessNumber,
                name: "ABN Lookup",
                phases: vec![Phase::Phase1],
                supported_queries: vec![QueryType::Abn, QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::AhnraPractitioner,
            ModuleMetadata {
                id: ModuleId::AhnraPractitioner,
                name: "AHPRA Practitioner Register",
                phases: vec![Phase::Phase1],
                supported_queries: vec![QueryType::Person],
            },
        );

        modules.insert(
            ModuleId::ApraBank,
            ModuleMetadata {
                id: ModuleId::ApraBank,
                name: "APRA Bank Register",
                phases: vec![Phase::Phase1],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::ApraInsurer,
            ModuleMetadata {
                id: ModuleId::ApraInsurer,
                name: "APRA Insurer Register",
                phases: vec![Phase::Phase1],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::AsicInsolvency,
            ModuleMetadata {
                id: ModuleId::AsicInsolvency,
                name: "ASIC Insolvency Register",
                phases: vec![Phase::Phase1],
                supported_queries: vec![QueryType::Person, QueryType::Company],
            },
        );

        // Phase 2: Secondary official sources
        modules.insert(
            ModuleId::AcmaBroadcast,
            ModuleMetadata {
                id: ModuleId::AcmaBroadcast,
                name: "ACMA Broadcast Register",
                phases: vec![Phase::Phase2],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::AcmaPhone,
            ModuleMetadata {
                id: ModuleId::AcmaPhone,
                name: "ACMA Phone Intelligence",
                phases: vec![Phase::Phase2],
                supported_queries: vec![QueryType::Phone],
            },
        );

        modules.insert(
            ModuleId::Acnc,
            ModuleMetadata {
                id: ModuleId::Acnc,
                name: "ACNC Charity Register",
                phases: vec![Phase::Phase2],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::ElectoralCommission,
            ModuleMetadata {
                id: ModuleId::ElectoralCommission,
                name: "Electoral Commission",
                phases: vec![Phase::Phase2],
                supported_queries: vec![QueryType::Person, QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::CourtRegister,
            ModuleMetadata {
                id: ModuleId::CourtRegister,
                name: "Court Register",
                phases: vec![Phase::Phase2],
                supported_queries: vec![QueryType::Person, QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::BankruptcyRegister,
            ModuleMetadata {
                id: ModuleId::BankruptcyRegister,
                name: "Bankruptcy Register",
                phases: vec![Phase::Phase2],
                supported_queries: vec![QueryType::Person, QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::LandTitles,
            ModuleMetadata {
                id: ModuleId::LandTitles,
                name: "Land Titles Register",
                phases: vec![Phase::Phase2],
                supported_queries: vec![QueryType::Person, QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::PropertyRates,
            ModuleMetadata {
                id: ModuleId::PropertyRates,
                name: "Property Rates Register",
                phases: vec![Phase::Phase2],
                supported_queries: vec![QueryType::Person, QueryType::Company],
            },
        );

        // Phase 3: Public APIs and archives
        modules.insert(
            ModuleId::TaxCompliance,
            ModuleMetadata {
                id: ModuleId::TaxCompliance,
                name: "Tax Compliance Register",
                phases: vec![Phase::Phase3],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::EnvironmentalRegister,
            ModuleMetadata {
                id: ModuleId::EnvironmentalRegister,
                name: "Environmental Register",
                phases: vec![Phase::Phase3],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::AviationRegister,
            ModuleMetadata {
                id: ModuleId::AviationRegister,
                name: "Aviation Register",
                phases: vec![Phase::Phase3],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::MarineRegister,
            ModuleMetadata {
                id: ModuleId::MarineRegister,
                name: "Marine Register",
                phases: vec![Phase::Phase3],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::WorkplaceRegister,
            ModuleMetadata {
                id: ModuleId::WorkplaceRegister,
                name: "Workplace Register",
                phases: vec![Phase::Phase3],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::ProfessionalLicense,
            ModuleMetadata {
                id: ModuleId::ProfessionalLicense,
                name: "Professional License Register",
                phases: vec![Phase::Phase3],
                supported_queries: vec![QueryType::Person],
            },
        );

        modules.insert(
            ModuleId::OpenStreetMap,
            ModuleMetadata {
                id: ModuleId::OpenStreetMap,
                name: "OpenStreetMap",
                phases: vec![Phase::Phase3],
                supported_queries: vec![QueryType::General],
            },
        );

        // Phase 4 & 5: Specialized/derived sources
        modules.insert(
            ModuleId::ImportExportTrade,
            ModuleMetadata {
                id: ModuleId::ImportExportTrade,
                name: "Import/Export Trade Register",
                phases: vec![Phase::Phase4],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::IpaustraliaBusiness,
            ModuleMetadata {
                id: ModuleId::IpaustraliaBusiness,
                name: "IP Australia Business",
                phases: vec![Phase::Phase4],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::Oscr,
            ModuleMetadata {
                id: ModuleId::Oscr,
                name: "OSCR Register",
                phases: vec![Phase::Phase5],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules.insert(
            ModuleId::Asx,
            ModuleMetadata {
                id: ModuleId::Asx,
                name: "ASX Register",
                phases: vec![Phase::Phase5],
                supported_queries: vec![QueryType::Company],
            },
        );

        modules
    }

    /// Get all modules for a specific phase.
    #[must_use]
    pub fn modules_for_phase(&self, phase: Phase) -> Vec<ModuleId> {
        self.modules
            .values()
            .filter(|m| m.phases.contains(&phase))
            .map(|m| m.id)
            .collect()
    }

    /// Select modules based on query type and optional phase filter.
    #[must_use]
    pub fn select_modules(&self, query_type: QueryType, phase: Option<Phase>) -> Vec<ModuleId> {
        let mut selected: Vec<ModuleId> = self
            .modules
            .values()
            .filter(|m| {
                let query_matches = m.supported_queries.contains(&query_type)
                    || m.supported_queries.contains(&QueryType::General);
                #[allow(clippy::manual_is_variant_and)]
                let phase_matches = phase.is_none() || phase.is_some_and(|p| m.phases.contains(&p));
                query_matches && phase_matches
            })
            .map(|m| m.id)
            .collect();

        // Sort by phase priority (Phase 1 first, then 2, etc.)
        selected.sort_by_key(|id| self.modules[id].phases.first().map_or(999, |p| p.index()));

        selected
    }

    /// Get all phases in order.
    #[must_use]
    pub fn all_phases() -> Vec<Phase> {
        vec![
            Phase::Phase1,
            Phase::Phase2,
            Phase::Phase3,
            Phase::Phase4,
            Phase::Phase5,
        ]
    }

    /// Get module metadata by ID.
    #[must_use]
    pub fn get_module(&self, id: ModuleId) -> Option<&ModuleMetadata> {
        self.modules.get(&id)
    }

    /// Get total number of registered modules.
    #[must_use]
    pub fn total_modules(&self) -> usize {
        self.modules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_loads_all_29_modules() {
        let registry = ModuleRegistry::new();
        assert_eq!(registry.total_modules(), 29);
    }

    #[test]
    fn select_modules_for_domain_query() {
        let registry = ModuleRegistry::new();
        let domain_modules = registry.select_modules(QueryType::Domain, None);

        // Should include auDA (Phase 1)
        assert!(domain_modules.contains(&ModuleId::AudaDomain));
        // Should not be empty
        assert!(!domain_modules.is_empty());
    }

    #[test]
    fn select_modules_for_person_query() {
        let registry = ModuleRegistry::new();
        let person_modules = registry.select_modules(QueryType::Person, None);

        // Should include ASIC Director (Phase 1)
        assert!(person_modules.contains(&ModuleId::AsicDirector));
        // Should include ASIC Persons (Phase 1)
        assert!(person_modules.contains(&ModuleId::AsicPersons));
        // Should include AHPRA (Phase 1)
        assert!(person_modules.contains(&ModuleId::AhnraPractitioner));
        // Should not be empty
        assert!(!person_modules.is_empty());
    }

    #[test]
    fn select_modules_for_ip_query() {
        let registry = ModuleRegistry::new();
        let ip_modules = registry.select_modules(QueryType::IpAddress, None);

        // Should include APNIC (Phase 1)
        assert!(ip_modules.contains(&ModuleId::ApnicWhois));
        // Should not include domain-only modules
        assert!(!ip_modules.contains(&ModuleId::AudaDomain));
    }

    #[test]
    fn phase_filtering_works() {
        let registry = ModuleRegistry::new();

        let phase1_modules = registry.select_modules(QueryType::Company, Some(Phase::Phase1));
        let phase2_modules = registry.select_modules(QueryType::Company, Some(Phase::Phase2));

        // Phase 1 should have high-authority modules (ASIC, etc.)
        assert!(phase1_modules.contains(&ModuleId::AsicCompany));
        // Phase 2 should have secondary sources (Courts, etc.)
        assert!(phase2_modules.contains(&ModuleId::CourtRegister));
        // Phases should be different
        assert_ne!(phase1_modules, phase2_modules);
    }

    #[test]
    fn module_metadata_accessible() {
        let registry = ModuleRegistry::new();

        let apnic = registry.get_module(ModuleId::ApnicWhois);
        assert!(apnic.is_some());
        assert_eq!(apnic.unwrap().name, "APNIC WHOIS");
        assert!(apnic.unwrap().phases.contains(&Phase::Phase1));
    }

    #[test]
    fn phase_timeout_budgets_decrease() {
        let phase1_budget = Phase::Phase1.timeout_budget();
        let phase5_budget = Phase::Phase5.timeout_budget();

        // Later phases should have lower budgets
        assert!(phase1_budget > phase5_budget);
        assert_eq!(phase1_budget, Duration::from_secs(30));
        assert_eq!(phase5_budget, Duration::from_secs(10));
    }

    #[test]
    fn query_types_are_distinct() {
        let registry = ModuleRegistry::new();

        let domain_modules = registry.select_modules(QueryType::Domain, None);
        let ip_modules = registry.select_modules(QueryType::IpAddress, None);
        let phone_modules = registry.select_modules(QueryType::Phone, None);

        // Domain and IP modules should be different
        assert_ne!(domain_modules, ip_modules);
        // IP and phone modules should be different
        assert_ne!(ip_modules, phone_modules);
    }

    #[test]
    fn all_phases_have_modules() {
        let registry = ModuleRegistry::new();

        for phase in ModuleRegistry::all_phases() {
            let modules = registry.modules_for_phase(phase);
            assert!(!modules.is_empty(), "Phase {phase:?} has no modules");
        }
    }

    #[test]
    fn company_query_covers_multiple_phases() {
        let registry = ModuleRegistry::new();
        let company_modules = registry.select_modules(QueryType::Company, None);

        // Should have Phase 1 modules
        let phase1 = registry.modules_for_phase(Phase::Phase1);
        let phase1_company: Vec<_> = phase1
            .iter()
            .filter(|id| company_modules.contains(id))
            .collect();
        assert!(!phase1_company.is_empty());

        // Should have Phase 2 modules
        let phase2 = registry.modules_for_phase(Phase::Phase2);
        let phase2_company: Vec<_> = phase2
            .iter()
            .filter(|id| company_modules.contains(id))
            .collect();
        assert!(!phase2_company.is_empty());
    }
}
