//! Core MPC protocol traits and message types.
//!
//! Defines the communication protocol between parties in multi-party computation,
//! including message types, party roles, and coordination semantics.

use serde::{Deserialize, Serialize};

/// Identifier for a party in MPC coordination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PartyId(pub String);

impl PartyId {
    /// Create a new party identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Create a default local party.
    pub fn local() -> Self {
        Self("local".to_string())
    }
}

impl std::fmt::Display for PartyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Phase of MPC coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MPCPhase {
    /// Parties are registering and committing to datasets
    Registration,
    /// Computing private set intersection
    PSI,
    /// Computing secure aggregation
    Aggregation,
    /// Coordination complete
    Complete,
}

/// Role a party plays in MPC coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartyRole {
    /// Initiates the coordination
    Initiator,
    /// Participates as a peer
    Peer,
    /// Aggregator that collects and combines results
    Aggregator,
}

/// Message sent between parties in MPC coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MPCMessage {
    /// Request to initiate coordination
    InitiateCoordination {
        initiator: PartyId,
        protocol_version: String,
    },
    /// Register a commitment to a dataset
    RegisterCommitment {
        from: PartyId,
        commitment_hash: String,
        dataset_size: usize,
    },
    /// Request the next phase of computation
    AdvancePhase { to_phase: MPCPhase },
    /// Share hashed dataset for PSI
    PSIShare {
        from: PartyId,
        hashed_elements: Vec<String>,
    },
    /// Share statistics for aggregation
    StatisticsShare {
        from: PartyId,
        unique_count: usize,
        record_count: usize,
    },
    /// Acknowledge receipt of message
    Ack {
        message_id: String,
        from: PartyId,
    },
    /// Report completion of current phase
    PhaseComplete {
        phase: MPCPhase,
        from: PartyId,
    },
    /// Error in coordination
    Error {
        from: PartyId,
        message: String,
    },
}

/// State of a party in MPC coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyState {
    /// Party identifier
    pub party_id: PartyId,
    /// Party's role
    pub role: PartyRole,
    /// Current phase
    pub current_phase: MPCPhase,
    /// Whether this party has completed current phase
    pub phase_complete: bool,
    /// Messages received from this party
    pub message_count: u64,
}

impl Default for PartyState {
    fn default() -> Self {
        Self {
            party_id: PartyId::local(),
            role: PartyRole::Peer,
            current_phase: MPCPhase::Registration,
            phase_complete: false,
            message_count: 0,
        }
    }
}

impl PartyState {
    /// Create a new party state.
    pub fn new(party_id: PartyId, role: PartyRole) -> Self {
        Self {
            party_id,
            role,
            ..Default::default()
        }
    }

    /// Record receipt of a message.
    pub fn record_message(&mut self) {
        self.message_count += 1;
    }

    /// Mark current phase as complete.
    pub fn mark_phase_complete(&mut self) {
        self.phase_complete = true;
    }

    /// Advance to next phase.
    pub fn advance_phase(&mut self, next_phase: MPCPhase) {
        self.current_phase = next_phase;
        self.phase_complete = false;
    }
}

/// Coordination state tracking all parties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationState {
    /// States of all participating parties
    pub party_states: std::collections::HashMap<String, PartyState>,
    /// Current global phase
    pub current_phase: MPCPhase,
    /// Total messages exchanged
    pub total_messages: u64,
}

impl Default for CoordinationState {
    fn default() -> Self {
        Self {
            party_states: std::collections::HashMap::new(),
            current_phase: MPCPhase::Registration,
            total_messages: 0,
        }
    }
}

impl CoordinationState {
    /// Add a party to the coordination.
    pub fn add_party(&mut self, party_id: PartyId, role: PartyRole) {
        self.party_states.insert(
            party_id.0.clone(),
            PartyState::new(party_id, role),
        );
    }

    /// Record a message being processed.
    pub fn record_message(&mut self, from: &PartyId) -> Result<(), String> {
        if let Some(state) = self.party_states.get_mut(&from.0) {
            state.record_message();
            self.total_messages += 1;
            Ok(())
        } else {
            Err(format!("Unknown party: {}", from))
        }
    }

    /// Check if all parties have completed the current phase.
    pub fn all_parties_ready_for_next_phase(&self) -> bool {
        self.party_states.values().all(|state| state.phase_complete)
    }

    /// Advance all parties to the next phase.
    pub fn advance_all_parties(&mut self, next_phase: MPCPhase) {
        self.current_phase = next_phase;
        for state in self.party_states.values_mut() {
            state.advance_phase(next_phase);
        }
    }

    /// Get a summary of current coordination state.
    pub fn summary(&self) -> CoordinationSummary {
        CoordinationSummary {
            parties_count: self.party_states.len(),
            current_phase: self.current_phase,
            total_messages: self.total_messages,
            ready_for_next: self.all_parties_ready_for_next_phase(),
        }
    }
}

/// Summary of coordination state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationSummary {
    pub parties_count: usize,
    pub current_phase: MPCPhase,
    pub total_messages: u64,
    pub ready_for_next: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_party_id_creation() {
        let party = PartyId::new("party_a");
        assert_eq!(party.0, "party_a");
    }

    #[test]
    fn test_party_state_creation() {
        let party_id = PartyId::new("party_a");
        let state = PartyState::new(party_id.clone(), PartyRole::Peer);
        assert_eq!(state.party_id, party_id);
        assert_eq!(state.role, PartyRole::Peer);
        assert_eq!(state.current_phase, MPCPhase::Registration);
    }

    #[test]
    fn test_party_state_message_recording() {
        let mut state = PartyState::default();
        assert_eq!(state.message_count, 0);
        state.record_message();
        assert_eq!(state.message_count, 1);
    }

    #[test]
    fn test_party_state_phase_advance() {
        let mut state = PartyState::default();
        assert_eq!(state.current_phase, MPCPhase::Registration);
        state.advance_phase(MPCPhase::PSI);
        assert_eq!(state.current_phase, MPCPhase::PSI);
    }

    #[test]
    fn test_coordination_state_add_party() {
        let mut coord = CoordinationState::default();
        let party_a = PartyId::new("party_a");
        coord.add_party(party_a.clone(), PartyRole::Peer);
        assert!(coord.party_states.contains_key("party_a"));
    }

    #[test]
    fn test_coordination_state_record_message() {
        let mut coord = CoordinationState::default();
        let party_a = PartyId::new("party_a");
        coord.add_party(party_a.clone(), PartyRole::Peer);
        assert!(coord.record_message(&party_a).is_ok());
        assert_eq!(coord.total_messages, 1);
    }

    #[test]
    fn test_coordination_state_unknown_party() {
        let mut coord = CoordinationState::default();
        let unknown = PartyId::new("unknown");
        assert!(coord.record_message(&unknown).is_err());
    }

    #[test]
    fn test_coordination_state_ready_check() {
        let mut coord = CoordinationState::default();
        let party_a = PartyId::new("party_a");
        let party_b = PartyId::new("party_b");

        coord.add_party(party_a.clone(), PartyRole::Peer);
        coord.add_party(party_b.clone(), PartyRole::Peer);

        assert!(!coord.all_parties_ready_for_next_phase());

        if let Some(state) = coord.party_states.get_mut("party_a") {
            state.mark_phase_complete();
        }
        assert!(!coord.all_parties_ready_for_next_phase());

        if let Some(state) = coord.party_states.get_mut("party_b") {
            state.mark_phase_complete();
        }
        assert!(coord.all_parties_ready_for_next_phase());
    }

    #[test]
    fn test_coordination_state_advance() {
        let mut coord = CoordinationState::default();
        let party_a = PartyId::new("party_a");
        coord.add_party(party_a, PartyRole::Peer);

        assert_eq!(coord.current_phase, MPCPhase::Registration);
        coord.advance_all_parties(MPCPhase::PSI);
        assert_eq!(coord.current_phase, MPCPhase::PSI);
    }

    #[test]
    fn test_coordination_summary() {
        let mut coord = CoordinationState::default();
        coord.add_party(PartyId::new("party_a"), PartyRole::Initiator);
        coord.add_party(PartyId::new("party_b"), PartyRole::Peer);

        let summary = coord.summary();
        assert_eq!(summary.parties_count, 2);
        assert_eq!(summary.current_phase, MPCPhase::Registration);
    }
}
