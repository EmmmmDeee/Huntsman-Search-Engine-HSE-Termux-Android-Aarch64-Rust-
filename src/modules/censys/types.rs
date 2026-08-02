//! API response types for the Censys host-search endpoint.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct CensysResp {
    #[serde(default)]
    pub(super) result: Option<HostResult>,
}

#[derive(Deserialize)]
pub(super) struct HostResult {
    #[serde(default)]
    pub(super) services: Vec<Service>,
    #[serde(default)]
    pub(super) location: Option<Location>,
    /// The host's announcing AS — the authoritative network-attribution block
    /// Censys returns but the module discarded, even though every cheaper
    /// sibling (shodan/criminal_ip/ipqs) extracts the equivalent.
    #[serde(default)]
    pub(super) autonomous_system: Option<AutonomousSystem>,
    #[serde(default)]
    pub(super) dns: Option<Dns>,
}

#[derive(Deserialize)]
pub(super) struct AutonomousSystem {
    #[serde(default)]
    pub(super) asn: Option<i64>,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) country_code: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct Dns {
    #[serde(default)]
    pub(super) reverse_dns: Option<ReverseDns>,
}

#[derive(Deserialize)]
pub(super) struct ReverseDns {
    #[serde(default)]
    pub(super) names: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct Service {
    #[serde(default)]
    pub(super) port: Option<u16>,
    #[serde(default)]
    pub(super) service_name: Option<String>,
    #[serde(default)]
    pub(super) transport_protocol: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct Location {
    #[serde(default)]
    pub(super) coordinates: Option<Coordinates>,
    #[serde(default)]
    pub(super) country: Option<String>,
    #[serde(default)]
    pub(super) country_code: Option<String>,
    #[serde(default)]
    pub(super) city: Option<String>,
    #[serde(default)]
    pub(super) province: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct Coordinates {
    #[serde(default)]
    pub(super) latitude: Option<f64>,
    #[serde(default)]
    pub(super) longitude: Option<f64>,
}
