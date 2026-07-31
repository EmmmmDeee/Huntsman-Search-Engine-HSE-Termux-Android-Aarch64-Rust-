use crate::core::{error::Result, module::ModuleResult};
use crate::modules::device_fix;

use super::SRC;

/// This module's binding of the canonical
/// [`crate::modules::device_fix::parse_fix`] — the shared parse-to-entity
/// mapping for `termux-location` output, differing only in the evidence-source
/// tag. Kept as a wrapper so this module's tests exercise it by its local name.
pub(super) fn parse_fix(stdout: &[u8], scan_id: &str) -> Result<ModuleResult> {
    device_fix::parse_fix(stdout, scan_id, SRC)
}
