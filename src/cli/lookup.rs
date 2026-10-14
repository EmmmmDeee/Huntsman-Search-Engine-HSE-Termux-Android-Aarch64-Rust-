//! Lookup-facing CLI facade.
//!
//! Selector enrichment, scan orchestration, discovery/search adapters, and the offline
//! investigation spine (`plan`) are separated so each concern owns only the dependencies it needs.

mod discovery;
mod plan;
mod profiles;
mod scan;

pub(super) use discovery::{investigate_cmd, query_cmd, search_cmd, sf_cmd, sources_cmd};
pub(super) use plan::plan_cmd;
pub(super) use profiles::{
    Refused, collect, domain_cmd, email_cmd, exposure_cmd, network_cmd, people_cmd, phone_cmd,
    username_cmd,
};
pub(super) use scan::scan_cmd;
