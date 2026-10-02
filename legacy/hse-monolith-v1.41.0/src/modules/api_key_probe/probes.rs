//! Builds the live-probe list from [`crate::util::service_defs`] — the same
//! registry `key_pool::validation` reads — rather than maintaining a second,
//! independent url/header/env_var table. Only the JSON-response parser
//! ([`ServiceDef::probe_parser`]) is genuinely per-vendor; the request shape
//! (url + auth header) is fully derivable from a `ServiceDef`'s `test_url` +
//! `key_header`, so [`request_for`] derives it generically instead of each
//! service repeating its own closure for it.

use crate::util::service_defs::{self, KeyPlacement, ProbeParser, ServiceDef};

pub(super) struct Probe {
    pub(super) service: &'static str,
    pub(super) category: &'static str,
    pub(super) env_var: &'static str,
    pub(super) def: &'static ServiceDef,
    pub(super) parse_info: ProbeParser,
}

/// The (url, headers) `probe_endpoint` needs to test `def` with `key` — every
/// [`KeyPlacement`] resolves to one of these shapes. `_basic_auth` and the
/// `Bearer`-prefixed header are sentinels `probe_endpoint` special-cases
/// (mirroring `key_pool::validation`'s own `validate_against_endpoint`, so
/// the two probes of the same service can't drift in how they authenticate).
pub(super) fn request_for(def: &ServiceDef, key: &str) -> (String, Vec<(&'static str, String)>) {
    match def.key_header {
        KeyPlacement::QueryParam(_) => (format!("{}{key}", def.test_url), vec![]),
        KeyPlacement::Header(name) => (def.test_url.to_string(), vec![(name, String::new())]),
        KeyPlacement::BasicAuth => (
            def.test_url.to_string(),
            vec![("_basic_auth", String::new())],
        ),
        KeyPlacement::BearerAuth => (
            def.test_url.to_string(),
            vec![("Authorization", "bearer".to_string())],
        ),
        // `def.key_header`'s prefix already embeds its own trailing space
        // (e.g. `"ApiKey "`, see `KeyPlacement::HeaderPrefixed`'s doc comment),
        // but `probe_endpoint`'s generic formatter inserts one more between
        // this prefix and the key (the same mechanism `BearerAuth`'s bare
        // `"bearer"` sentinel relies on) — trim it here so the header value
        // isn't double-spaced ("ApiKey  <key>").
        KeyPlacement::HeaderPrefixed(name, prefix) => (
            def.test_url.to_string(),
            vec![(name, prefix.trim_end().to_string())],
        ),
    }
}

/// Every [`ServiceDef`] that declares a [`ServiceDef::probe_parser`] — i.e.
/// one `api_key_probe` can enrich with live account metadata, not just a bare
/// pass/fail validation. Definitions with `probe_parser: None` exist purely
/// for pool validation/rotation and are skipped here.
pub(super) fn probes() -> Vec<Probe> {
    service_defs::service_defs()
        .iter()
        .filter_map(|def| {
            def.probe_parser.map(|parse_info| Probe {
                service: def.name,
                category: def.category,
                env_var: def.env_var,
                def,
                parse_info,
            })
        })
        .collect()
}
