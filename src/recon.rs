//! The seed kinds a host-recon lookup is asked about: `crtsh` shapes its query from one, and
//! the `recon crtsh` and `domain` front-ends choose it.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconTargetKind {
    Domain,
    Url,
    Email,
    Username,
}
