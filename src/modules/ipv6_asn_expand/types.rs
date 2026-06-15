//! Serde types for the BGPView `/asn/{n}/prefixes` response (IPv6 subset).

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct PrefixResponse {
    pub data: Option<PrefixData>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PrefixData {
    #[serde(default)]
    pub ipv6_prefixes: Vec<Ipv6Prefix>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Ipv6Prefix {
    pub prefix: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub country_code: Option<String>,
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
