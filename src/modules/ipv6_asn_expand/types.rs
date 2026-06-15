use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct PrefixResp {
    pub status: Option<String>,
    pub data: Option<PrefixData>,
}

#[derive(Deserialize)]
pub(super) struct PrefixData {
    pub ipv6_prefixes: Vec<Ipv6Prefix>,
}

#[derive(Deserialize)]
pub(super) struct Ipv6Prefix {
    pub prefix: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub country_code: Option<String>,
}
