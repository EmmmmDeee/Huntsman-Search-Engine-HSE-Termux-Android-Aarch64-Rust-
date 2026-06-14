//! Identity correlation rules, split by domain:
//!
//! * [`cluster`] — entity-cluster and cross-source corroboration rules
//!   (AU-002, AU-003, AU-020, AU-023, AU-045, AU-046)
//! * [`account`] — handle, platform, key, tracking and broker rules
//!   (AU-011, AU-034, AU-035, AU-036, AU-038, AU-042, AU-044, AU-048, AU-054, AU-055)

use super::*;

mod account;
mod cluster;

pub(in crate::core::correlator) use account::*;
pub(in crate::core::correlator) use cluster::*;
