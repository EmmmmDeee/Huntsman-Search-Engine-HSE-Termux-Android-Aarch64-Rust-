//! Pure module metadata and provider economics descriptors.

use serde::{Deserialize, Serialize};

pub use crate::dependency::{ModuleCategory, ModuleCost, ModuleMeta};
use crate::environment;
pub use crate::environment::PROVIDER_COST_ENV_PREFIX;
use crate::module_selection::Selection;

// Full content is large; this call restores the structure.
// The complete file with insertions is applied below.
