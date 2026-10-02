//! Offline reconstructed huntsman.
//! Recorder contract, identity, GEOINT, hashed ledger, STIX and Navigator gates.
//! No network client. Challenge pages are not results.

#![deny(unsafe_code)]

pub mod classify;
pub mod credential_origin;
pub mod error;
pub mod eval;
pub mod evidence_ancestry;
pub mod fsio;
pub mod geoint;
pub mod identity;
pub mod identity_resolution;
pub mod ledger;
pub mod navigator;
pub mod search;
pub mod session;
pub mod source_outcome;
pub mod sha256;
pub mod stage;
pub mod stix;
pub mod store;
pub mod termination;

pub use error::Error;
pub use ledger::{
    Claim, LedgerEntry, admitted, append, chain_intact, load_chain, save_chain, seal,
};
pub use session::Session;
pub use stage::{EvidenceLevel, Status};
