//! Stage 2 directory shim for the `application` home (see `docs/ARCHITECTURE.md`).
//!
//! Re-exports only. Every module still lives at its current `crate::<module>` path;
//! later stages move files here one at a time without changing those paths.

pub use crate::{
    artifacts, doctor, docx, dossier_view, evidence_register, gexf, graph_exec, ledger,
    lookup_modules, lookup_save, navigator, osint_blueprint, run_history, runtime, scan_alert,
    scan_compare, scan_coverage, scan_export, scan_retention, scan_search, scan_service,
    scan_store, scan_uncertainty, search, session, snake_graph, stix, store, xlsx,
};
