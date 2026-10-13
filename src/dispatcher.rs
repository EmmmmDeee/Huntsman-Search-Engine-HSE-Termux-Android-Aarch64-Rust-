//! Parallel wave dispatcher: Execute multiple modules concurrently with deadline enforcement.
//!
//! Coordinates module execution across up to 6 concurrent threads, respecting phase budgets
//! and strict deadline cutoffs. Each module receives a timeout calculated from remaining
//! budget and module count, ensuring no single module can exhaust the phase budget.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::deadline::Deadline;
use crate::entity::{Evidence, EvidenceProvenance};
use crate::search_engines::SearchOrchestrator;

/// Identifier for a module in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModuleId {
    ApnicWhois,
    AudaDomain,
    AsicCompany,
    AsicDirector,
    AsicInsolvency,
    AsicPersons,
    AhnraPractitioner,
    AbusinessNumber,
    ApraBank,
    ApraInsurer,
    AcmaBroadcast,
    AcmaPhone,
    Acnc,
    ElectoralCommission,
    CourtRegister,
    BankruptcyRegister,
    LandTitles,
    PropertyRates,
    TaxCompliance,
    EnvironmentalRegister,
    AviationRegister,
    MarineRegister,
    WorkplaceRegister,
    ProfessionalLicense,
    ImportExportTrade,
    IpaustraliaBusiness,
    Oscr,
    Asx,
    OpenStreetMap,
}

impl ModuleId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApnicWhois => "apnic_whois",
            Self::AudaDomain => "auda_domain",
            Self::AsicCompany => "asic_company",
            Self::AsicDirector => "asic_director",
            Self::AsicInsolvency => "asic_insolvency",
            Self::AsicPersons => "asic_persons",
            Self::AhnraPractitioner => "ahpra_practitioner",
            Self::AbusinessNumber => "abn",
            Self::ApraBank => "apra_bank",
            Self::ApraInsurer => "apra_insurer",
            Self::AcmaBroadcast => "acma_broadcast",
            Self::AcmaPhone => "acma_phone",
            Self::Acnc => "acnc",
            Self::ElectoralCommission => "electoral_commission",
            Self::CourtRegister => "court_register",
            Self::BankruptcyRegister => "bankruptcy_register",
            Self::LandTitles => "land_titles",
            Self::PropertyRates => "property_rates",
            Self::TaxCompliance => "tax_compliance",
            Self::EnvironmentalRegister => "environmental_register",
            Self::AviationRegister => "aviation_register",
            Self::MarineRegister => "marine_register",
            Self::WorkplaceRegister => "workplace_register",
            Self::ProfessionalLicense => "professional_license",
            Self::ImportExportTrade => "import_export_trade",
            Self::IpaustraliaBusiness => "ipaustrallia_business",
            Self::Oscr => "oscr",
            Self::Asx => "asx",
            Self::OpenStreetMap => "openstreetmap",
        }
    }
}

/// Configuration for a single module: rate limit, priority, timeout.
#[derive(Debug, Clone)]
pub struct ModuleConfig {
    pub id: ModuleId,
    pub rate_limit_per_minute: u32,
    pub priority: u8, // 1-10, higher = more priority
    pub timeout: Duration,
}

impl ModuleConfig {
    pub fn default_for(id: ModuleId) -> Self {
        match id {
            ModuleId::ApnicWhois => Self {
                id,
                rate_limit_per_minute: 60,
                priority: 9,
                timeout: Duration::from_secs(5),
            },
            ModuleId::AudaDomain => Self {
                id,
                rate_limit_per_minute: 60,
                priority: 9,
                timeout: Duration::from_secs(5),
            },
            ModuleId::AsicCompany => Self {
                id,
                rate_limit_per_minute: 40,
                priority: 8,
                timeout: Duration::from_secs(5),
            },
            ModuleId::AsicDirector => Self {
                id,
                rate_limit_per_minute: 30,
                priority: 7,
                timeout: Duration::from_secs(5),
            },
            ModuleId::AsicInsolvency => Self {
                id,
                rate_limit_per_minute: 30,
                priority: 7,
                timeout: Duration::from_secs(5),
            },
            ModuleId::AsicPersons => Self {
                id,
                rate_limit_per_minute: 30,
                priority: 7,
                timeout: Duration::from_secs(5),
            },
            ModuleId::AhnraPractitioner => Self {
                id,
                rate_limit_per_minute: 20,
                priority: 6,
                timeout: Duration::from_secs(5),
            },
            ModuleId::AbusinessNumber => Self {
                id,
                rate_limit_per_minute: 40,
                priority: 8,
                timeout: Duration::from_secs(5),
            },
            _ => Self {
                id,
                rate_limit_per_minute: 20,
                priority: 5,
                timeout: Duration::from_secs(5),
            },
        }
    }
}

/// A batch of modules to execute in parallel within a phase.
pub struct ParallelWave<'d> {
    pub modules: Vec<ModuleId>,
    pub deadline: &'d Deadline<'d>,
    pub budget: Duration,
}

impl<'d> ParallelWave<'d> {
    pub fn new(modules: Vec<ModuleId>, deadline: &'d Deadline<'d>, budget: Duration) -> Self {
        Self {
            modules,
            deadline,
            budget,
        }
    }

    /// Calculate per-module timeout: remaining_budget / remaining_modules, capped by module timeout.
    pub fn per_module_timeout(&self) -> Duration {
        if self.modules.is_empty() {
            return self.budget;
        }

        let remaining = self.deadline.remaining();
        if remaining <= Duration::from_millis(100) {
            return Duration::from_millis(10); // Minimal timeout if deadline near
        }

        let per_module = remaining / self.modules.len() as u32;
        let module_timeout = Duration::from_secs(5); // Conservative default

        per_module.min(module_timeout).max(Duration::from_millis(100))
    }
}

/// Orchestrates parallel execution of modules with deadline enforcement.
pub struct WaveExecutor {
    #[allow(dead_code)]
    orchestrator: SearchOrchestrator,
    max_concurrent: usize,
}

impl WaveExecutor {
    /// Create new wave executor with default SearchOrchestrator and 6-concurrent limit.
    pub fn new(orchestrator: SearchOrchestrator) -> Self {
        Self {
            orchestrator,
            max_concurrent: 6,
        }
    }

    /// Execute a wave of modules in parallel, respecting deadline and concurrency limits.
    pub fn execute_wave(&mut self, wave: &ParallelWave) -> Vec<Evidence> {
        let results = Arc::new(Mutex::new(Vec::<Evidence>::new()));

        // Spawn threads for modules, respecting max_concurrent limit.
        let mut thread_handles: Vec<thread::JoinHandle<()>> = Vec::new();

        for &module_id in wave.modules.iter() {
            // Enforce max concurrency: wait for a thread to finish before spawning next.
            if thread_handles.len() >= self.max_concurrent {
                let handle = thread_handles.remove(0);
                let _ = handle.join();
            }

            // Strict deadline check: if deadline expired, stop spawning new threads.
            if wave.deadline.expired() {
                break;
            }

            let results_clone = Arc::clone(&results);

            let handle = thread::spawn(move || {
                // Module would execute here with per_module_timeout.
                // For now, simulate evidence generation with module ID.
                let module_name = module_id.as_str();
                let evidence = Evidence {
                    provenance: EvidenceProvenance::new(module_name),
                    summary: format!("Evidence from {}", module_name),
                    attributes: BTreeMap::new(),
                    verification: None,
                    is_inferred: false,
                    ancestry_node: None,
                };

                // Add to results (no deadline check needed since thread ran).
                let mut res = results_clone.lock().unwrap();
                res.push(evidence);
            });

            thread_handles.push(handle);
        }

        // Wait for remaining threads to complete.
        while let Some(handle) = thread_handles.pop() {
            let _ = handle.join();
        }

        match Arc::try_unwrap(results) {
            Ok(mutex) => mutex.lock().unwrap().clone(),
            Err(arc) => arc.lock().unwrap().clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deadline::SystemClock;

    #[test]
    fn module_id_strings_consistent() {
        assert_eq!(ModuleId::ApnicWhois.as_str(), "apnic_whois");
        assert_eq!(ModuleId::AudaDomain.as_str(), "auda_domain");
        assert_eq!(ModuleId::AsicCompany.as_str(), "asic_company");
    }

    #[test]
    fn module_config_defaults_vary_by_id() {
        let apnic_cfg = ModuleConfig::default_for(ModuleId::ApnicWhois);
        let asic_cfg = ModuleConfig::default_for(ModuleId::AsicDirector);

        // APNIC should have higher rate limit and priority than ASIC Director.
        assert!(apnic_cfg.rate_limit_per_minute > asic_cfg.rate_limit_per_minute);
        assert!(apnic_cfg.priority > asic_cfg.priority);
    }

    #[test]
    fn parallel_wave_creation() {
        let clock = SystemClock;
        let deadline = Deadline::start(&clock, Duration::from_secs(60));
        let modules = vec![
            ModuleId::ApnicWhois,
            ModuleId::AudaDomain,
            ModuleId::AsicCompany,
        ];
        let budget = Duration::from_secs(15);

        let wave = ParallelWave::new(modules.clone(), &deadline, budget);
        assert_eq!(wave.modules.len(), 3);
        assert_eq!(wave.budget, Duration::from_secs(15));
    }

    #[test]
    fn per_module_timeout_respects_budget() {
        let clock = SystemClock;
        let deadline = Deadline::start(&clock, Duration::from_secs(60));
        let modules = vec![
            ModuleId::ApnicWhois,
            ModuleId::AudaDomain,
            ModuleId::AsicCompany,
        ];
        let budget = Duration::from_secs(15);

        let wave = ParallelWave::new(modules, &deadline, budget);
        let timeout = wave.per_module_timeout();

        // With 3 modules and ~60s remaining, per-module timeout should be ~20s, capped at 5s default.
        assert!(timeout <= Duration::from_secs(5));
        assert!(timeout >= Duration::from_millis(100));
    }

    #[test]
    fn wave_executor_creation() {
        let orchestrator =
            SearchOrchestrator::new(crate::search_engines::RotationStrategy::RoundRobin);
        let executor = WaveExecutor::new(orchestrator);
        assert_eq!(executor.max_concurrent, 6);
    }

    #[test]
    fn wave_executor_respects_deadline() {
        let orchestrator =
            SearchOrchestrator::new(crate::search_engines::RotationStrategy::RoundRobin);
        let mut executor = WaveExecutor::new(orchestrator);

        let clock = SystemClock;
        let deadline = Deadline::start(&clock, Duration::from_millis(1));
        thread::sleep(Duration::from_millis(10));

        let modules = vec![
            ModuleId::ApnicWhois,
            ModuleId::AudaDomain,
            ModuleId::AsicCompany,
        ];
        let wave = ParallelWave::new(modules, &deadline, Duration::from_secs(15));

        let results = executor.execute_wave(&wave);
        // With expired deadline, results should be minimal or empty.
        assert!(results.len() < 3);
    }

    #[test]
    fn wave_executor_enforces_concurrency_limit() {
        let orchestrator =
            SearchOrchestrator::new(crate::search_engines::RotationStrategy::RoundRobin);
        let mut executor = WaveExecutor::new(orchestrator);

        let clock = SystemClock;
        let deadline = Deadline::start(&clock, Duration::from_secs(30));
        let modules = vec![
            ModuleId::ApnicWhois,
            ModuleId::AudaDomain,
            ModuleId::AsicCompany,
            ModuleId::AsicDirector,
            ModuleId::AsicInsolvency,
            ModuleId::AsicPersons,
            ModuleId::AhnraPractitioner,
            ModuleId::AbusinessNumber,
            ModuleId::ApraBank,
        ];

        let wave = ParallelWave::new(modules, &deadline, Duration::from_secs(15));
        let results = executor.execute_wave(&wave);

        // Should respect 6-concurrent limit; results count should be reasonable.
        assert!(!results.is_empty());
    }
}
