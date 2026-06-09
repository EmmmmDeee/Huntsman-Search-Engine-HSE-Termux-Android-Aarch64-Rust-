//! Shared helpers for the search-engine scrapers: fetch/parse primitives,
//! URL classification, text extraction and entity construction. Grouped into
//! cohesive submodules; the public surface is re-exported so sibling modules'
//! `use super::helpers::*` is unchanged.

pub(super) use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    scan::{Target, TargetKind},
    tags,
};
pub(super) use std::collections::HashSet;

pub(super) const SRC: &str = "search_engines";

pub(crate) struct SearchResult {
    pub(super) url: String,
    pub(super) title: String,
    pub(super) snippet: String,
    pub(super) engine: &'static str,
    pub(super) query: String,
}

mod entity;
mod parse;
mod text;
mod urls;

pub(super) use entity::*;
pub(super) use parse::*;
pub(super) use text::*;
pub(super) use urls::*;

#[cfg(test)]
mod tests;
