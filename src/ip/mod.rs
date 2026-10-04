//! Evidence-gated IP investigation subsystem.

pub mod model;

pub use model::{
    ALL_IP_CLAIM_KINDS, IpActionRecord, IpBudgetUsage, IpClaim, IpClaimKind, IpClaimState,
    IpFailure, IpFailureKind, IpInputError, IpInvestigation, IpObservation, IpObservationKind,
    IpScope, IpTarget, TemporalState,
};
