//! Ports of `src/web/js/views/*.js` — the top-level SPA pages (as opposed to
//! [`crate::scan_info`]'s scan-detail tabs). One module per JS file, named
//! identically, so the mapping between the two trees stays obvious as more
//! are ported.

pub mod dash;
pub mod scans;
