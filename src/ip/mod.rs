//! Evidence-gated IP investigation subsystem.

pub mod claims;
pub mod model;
pub mod orchestrator;
pub mod provider;
pub mod providers;

pub use model::{
    ALL_IP_CLAIM_KINDS, IpActionRecord, IpBudgetUsage, IpClaim, IpClaimKind, IpClaimState,
    IpFailure, IpFailureKind, IpInputError, IpInvestigation, IpObservation, IpObservationKind,
    IpScope, IpTarget, TemporalState,
};
pub use provider::{
    IpCapability, IpProvider, IpProviderAction, IpProviderParseError, IpProviderResult,
    execute_provider_action,
};
