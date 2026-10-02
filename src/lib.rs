//! Reconstructed huntsman.
//! Recorder contract, identity, GEOINT, hashed ledger, STIX and Navigator gates, plus a
//! guarded HTTP layer (`egress`, `http`, `fetch`, `keys`). Challenge pages are not results.
//! Pure logic stays separate from I/O so every decision can be tested without a network.

#![deny(unsafe_code)]
#![allow(
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

pub mod address_au;
pub mod atproto;
pub mod attack;
pub mod attack_catalog;
pub mod au_id;
pub mod breach;
pub mod canonical;
pub mod circuit;
pub mod ckan;
pub mod classifier;
pub mod classify;
pub mod classify_module;
pub mod community;
pub mod confidence;
pub mod coref;
pub mod correlator;
pub mod credential_origin;
pub mod cross_scan;
pub mod crtsh;
pub mod dependency;
pub mod diff;
pub mod dmarc;
pub mod dns;
pub mod domains;
pub mod egress;
pub mod entity;
pub mod error;
pub mod eval;
pub mod event;
pub mod evidence_ancestry;
pub mod exposure;
pub mod fetch;
pub mod fetch_cli;
pub mod fsio;
pub mod geo;
pub mod geohash;
pub mod geoint;
pub mod geometry;
pub mod gexf;
pub mod graph;
pub mod hibp;
pub mod http;
pub mod identity;
pub mod identity_resolution;
pub mod intelligence;
pub mod json;
pub mod key_health;
pub mod keys;
pub mod leads;
pub mod ledger;
pub mod mediawiki;
pub mod module;
pub mod navigator;
pub mod oui;
pub mod oui_ieee;
pub mod path;
pub mod pivot;
pub mod place;
pub mod postcode_au;
pub mod profiles;
pub mod radar;
pub mod recon;
pub mod redact;
pub mod relation;
pub mod resolve;
pub mod rf;
pub mod scraper_health;
pub mod search;
pub mod service_defs;
pub mod session;
pub mod sha256;
pub mod signals;
pub mod snake_graph;
pub mod source_outcome;
pub mod spf;
pub mod stage;
pub mod stix;
pub mod stolen_tax;
pub mod store;
pub mod tags;
pub mod termination;
pub mod textnorm;
pub mod timefmt;
pub mod timeline;
pub mod tlsrpt;
pub mod uid;
pub mod union_find;
pub mod validation;
pub mod xml;

pub use entity::{Entity, EntityKind, EntityRef, Evidence, EvidenceProvenance};
pub use error::Error;
pub use graph::{EntityRelation, RelationKind};
pub use ledger::{
    Claim, LedgerEntry, admitted, append, chain_intact, load_chain, save_chain, seal,
};
pub use session::Session;
pub use stage::{EvidenceLevel, Status};
