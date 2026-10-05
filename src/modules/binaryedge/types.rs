//! API response types for BinaryEdge's `v2/query/ip/{target}` and
//! `v2/query/domains/subdomain/{target}` endpoints.
//!
//! Field shapes verified against BinaryEdge's own documented examples (see
//! `mod.rs`'s header for the exact source, since `docs.binaryedge.io` itself
//! now redirects). Only the fields this module actually consumes are
//! declared — everything is `#[serde(default)]` so an unexpected/renamed
//! upstream field degrades to "not present" rather than a parse failure.

use serde::Deserialize;

/// `v2/query/ip/{target}` response.
#[derive(Deserialize)]
pub(super) struct IpResp {
    /// BinaryEdge's own reported match count. Present in the documented
    /// example; kept as a distinct field from `events.len()` so a
    /// paginated/truncated future response can't silently understate the
    /// target's real footprint (mirrors `urlscan`'s `total`-vs-shown split).
    #[serde(default)]
    pub(super) total: Option<u64>,
    #[serde(default)]
    pub(super) events: Vec<PortEvent>,
}

/// One port grouping under `events[]`. Carries its own `port` plus the
/// per-result detail (usually one result per port, but the shape allows
/// more than one grabber result for the same port).
#[derive(Deserialize)]
pub(super) struct PortEvent {
    #[serde(default)]
    pub(super) port: Option<u32>,
    #[serde(default)]
    pub(super) results: Vec<ResultEntry>,
}

#[derive(Deserialize)]
pub(super) struct ResultEntry {
    #[serde(default)]
    pub(super) target: Option<TargetInfo>,
    #[serde(default)]
    pub(super) result: Option<ResultWrapper>,
}

/// The scanned port/protocol as BinaryEdge observed it — usually identical
/// to the parent [`PortEvent::port`], but read separately since it is the
/// authoritative per-result value.
#[derive(Deserialize)]
pub(super) struct TargetInfo {
    #[serde(default)]
    pub(super) protocol: Option<String>,
    #[serde(default)]
    pub(super) port: Option<u32>,
}

#[derive(Deserialize)]
pub(super) struct ResultWrapper {
    #[serde(default)]
    pub(super) data: Option<ResultData>,
}

#[derive(Deserialize)]
pub(super) struct ResultData {
    #[serde(default)]
    pub(super) service: Option<ServiceInfo>,
}

/// The `service-simple`/`service` grabber's identification of what is
/// listening on the port. `banner` is deliberately NOT modelled here —
/// raw banners can carry credentials or other sensitive text (the same
/// reason `leakix` never stores its raw service banners verbatim); the raw
/// response body is still scanned for embedded API keys regardless via
/// `json_scanned`, independent of which fields this struct extracts.
#[derive(Deserialize)]
pub(super) struct ServiceInfo {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) product: Option<String>,
    #[serde(default)]
    pub(super) version: Option<String>,
    #[serde(default)]
    pub(super) cpe: Vec<String>,
}

/// `v2/query/domains/subdomain/{target}` response — a flat list of full
/// subdomain hostnames (not bare labels), plus BinaryEdge's own total match
/// count (the page-capped `events` can under-report a heavily-indexed
/// domain's real subdomain count).
#[derive(Deserialize)]
pub(super) struct SubdomainResp {
    #[serde(default)]
    pub(super) total: Option<u64>,
    #[serde(default)]
    pub(super) events: Vec<String>,
}
