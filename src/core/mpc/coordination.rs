//! MPC Coordinator: orchestrates data sharing and enrichment across parties.

use crate::core::entity::Entity;
use crate::core::mpc::protocol::{MPCConfig, MPCPhase, Party, PartyId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Coordinates multi-party breach data sharing and enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coordinator {
    /// Configuration for this coordination
    config: MPCConfig,
    /// Parties registered in this coordination
    parties: HashMap<String, Party>,
    /// Current coordination phase
    current_phase: MPCPhase,
}

impl Coordinator {
    /// Create a new MPC coordinator.
    pub fn new(config: MPCConfig) -> Self {
        Self {
            config,
            parties: HashMap::new(),
            current_phase: MPCPhase::Registration,
        }
    }

    /// Register a party and their dataset metadata.
    pub fn register_party(&mut self, party: Party) -> Result<(), String> {
        if self.parties.len() >= self.config.max_parties {
            return Err("Maximum parties reached".to_string());
        }

        self.parties.insert(party.id.0.clone(), party);
        Ok(())
    }

    /// Check if minimum parties are registered.
    pub fn is_ready(&self) -> bool {
        self.parties.len() >= self.config.min_parties
    }

    /// Get all registered parties.
    pub fn parties(&self) -> Vec<&Party> {
        self.parties.values().collect()
    }

    /// Get party count.
    pub fn party_count(&self) -> usize {
        self.parties.len()
    }

    /// Advance to the next coordination phase.
    pub fn advance_phase(&mut self) -> Result<(), String> {
        if !self.all_parties_complete() {
            return Err("Not all parties ready for next phase".to_string());
        }

        self.current_phase = match self.current_phase {
            MPCPhase::Registration => MPCPhase::Discovery,
            MPCPhase::Discovery => MPCPhase::Enrichment,
            MPCPhase::Enrichment => MPCPhase::Completion,
            MPCPhase::Completion => return Err("Already in final phase".to_string()),
        };

        // Reset completion flags for next phase
        for party in self.parties.values_mut() {
            party.phase_complete = false;
        }

        Ok(())
    }

    /// Mark a party as complete with the current phase.
    pub fn mark_party_complete(&mut self, party_id: &PartyId) -> Result<(), String> {
        if let Some(party) = self.parties.get_mut(&party_id.0) {
            party.mark_complete();
            Ok(())
        } else {
            Err(format!("Unknown party: {}", party_id))
        }
    }

    /// Check if all parties have completed current phase.
    pub fn all_parties_complete(&self) -> bool {
        !self.parties.is_empty() && self.parties.values().all(|p| p.phase_complete)
    }

    /// Get current coordination phase.
    pub fn current_phase(&self) -> MPCPhase {
        self.current_phase
    }

    /// Generate a coordination summary.
    pub fn summary(&self) -> CoordinationSummary {
        CoordinationSummary {
            initiator: self.config.initiator.clone(),
            phase: self.current_phase,
            parties_registered: self.parties.len(),
            all_parties_ready: self.is_ready(),
            all_parties_complete: self.all_parties_complete(),
        }
    }
}

/// Summary of coordination state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationSummary {
    pub initiator: PartyId,
    pub phase: MPCPhase,
    pub parties_registered: usize,
    pub all_parties_ready: bool,
    pub all_parties_complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinator_creation() {
        let config = MPCConfig::default();
        let coordinator = Coordinator::new(config);
        assert_eq!(coordinator.party_count(), 0);
        assert_eq!(coordinator.current_phase(), MPCPhase::Registration);
    }

    #[test]
    fn test_register_party() {
        let config = MPCConfig::default();
        let mut coordinator = Coordinator::new(config);

        let party = Party::new(PartyId::new("party_a"), 100);
        assert!(coordinator.register_party(party).is_ok());
        assert_eq!(coordinator.party_count(), 1);
    }

    #[test]
    fn test_ready_check() {
        let config = MPCConfig {
            min_parties: 2,
            ..Default::default()
        };
        let mut coordinator = Coordinator::new(config);

        let party_a = Party::new(PartyId::new("party_a"), 100);
        coordinator.register_party(party_a).ok();
        assert!(!coordinator.is_ready());

        let party_b = Party::new(PartyId::new("party_b"), 150);
        coordinator.register_party(party_b).ok();
        assert!(coordinator.is_ready());
    }

    #[test]
    fn test_mark_party_complete() {
        let mut coordinator = Coordinator::new(MPCConfig::default());
        let party = Party::new(PartyId::new("party_a"), 100);
        let party_id = party.id.clone();

        coordinator.register_party(party).ok();
        assert!(coordinator.mark_party_complete(&party_id).is_ok());
        assert!(coordinator.all_parties_complete());
    }

    #[test]
    fn test_phase_advancement() {
        let config = MPCConfig {
            min_parties: 1,
            ..Default::default()
        };
        let mut coordinator = Coordinator::new(config);

        let party = Party::new(PartyId::new("party_a"), 100);
        let party_id = party.id.clone();
        coordinator.register_party(party).ok();

        assert_eq!(coordinator.current_phase(), MPCPhase::Registration);
        coordinator.mark_party_complete(&party_id).ok();
        assert!(coordinator.advance_phase().is_ok());
        assert_eq!(coordinator.current_phase(), MPCPhase::Discovery);
    }

    #[test]
    fn test_coordination_summary() {
        let coordinator = Coordinator::new(MPCConfig::default());
        let summary = coordinator.summary();
        assert_eq!(summary.phase, MPCPhase::Registration);
        assert_eq!(summary.parties_registered, 0);
    }
}
