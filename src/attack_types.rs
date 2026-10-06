//! Shared ATT&CK value types used by the catalogue and analysis layers.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Tactic {
    pub id: &'static str,
    pub shortname: &'static str,
    pub name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Technique {
    pub id: &'static str,
    pub name: &'static str,
    pub is_subtechnique: bool,
    pub tactics: &'static [&'static str],
}
