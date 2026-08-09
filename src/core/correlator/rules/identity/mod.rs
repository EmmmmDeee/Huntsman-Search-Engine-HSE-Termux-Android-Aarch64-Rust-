//! Identity correlation rules, split by domain:
//!
//! * [`cluster`] — entity-cluster and cross-source corroboration rules: multiple
//!   independent sources converging on one identity, plus the corroboration-gap
//!   checks that damp a single-source cluster.
//! * [`account`] — handle, platform, key, tracking and data-broker rules: reused
//!   usernames across platforms, leaked or rotated API keys, shared tracking IDs,
//!   and broker-listing pivots.
//!
//! Each rule declares its own `AU-0xx` id at its `Correlation::new` call site,
//! which is the authoritative list. This doc deliberately names the *domains*
//! rather than enumerating rule ids — a hand-maintained enumeration drifts every
//! time a rule is added (the `account` list had already fallen eight rules
//! behind before this was de-enumerated).

use super::*;

mod account;
mod cluster;

pub(in crate::core::correlator) use account::*;
pub(in crate::core::correlator) use cluster::*;
