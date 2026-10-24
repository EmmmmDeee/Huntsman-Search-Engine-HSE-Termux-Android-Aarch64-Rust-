//! Lookup-facing CLI facade.
//!
//! Selector enrichment, scan orchestration, discovery/search adapters, and the offline
//! investigation spine (`plan`) are separated so each concern owns only the dependencies it needs.

mod discovery;
mod plan;
mod profiles;
mod scan;

pub(super) use discovery::{
    investigate_cmd, investigate_entities, query_cmd, search_cmd, sf_cmd, sources_cmd,
};
pub(super) use plan::plan_cmd;
pub(super) use profiles::{
    Refused, asn_cmd, collect, crypto_cmd, docmeta_cmd, domain_cmd, email_cmd, exif_cmd,
    exposure_cmd, geocode_cmd, ip_cmd, itunes_cmd, netblock_cmd, network_cmd, people_cmd,
    phone_cmd, username_cmd,
};
pub(super) use scan::scan_cmd;
