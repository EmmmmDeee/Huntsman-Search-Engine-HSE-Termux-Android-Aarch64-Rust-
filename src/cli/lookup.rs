//! Lookup-facing CLI facade.
//!
//! Selector enrichment, scan orchestration, and discovery/search adapters are
//! separated so each concern owns only the dependencies it needs.

mod discovery;
mod profiles;
mod scan;

pub(super) use discovery::{investigate_cmd, query_cmd, search_cmd, sf_cmd, sources_cmd};
pub(super) use profiles::{email_cmd, people_cmd, phone_cmd, username_cmd};
pub(super) use scan::scan_cmd;
