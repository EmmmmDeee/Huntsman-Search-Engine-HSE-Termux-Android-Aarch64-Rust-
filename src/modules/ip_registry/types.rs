use serde::Deserialize;

// RDAP types

#[derive(Deserialize)]
pub(super) struct RdapResp {
    #[serde(default)]
    pub(super) handle: Option<String>,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) country: Option<String>,
    #[serde(default, rename = "startAddress")]
    pub(super) start_address: Option<String>,
    #[serde(default, rename = "endAddress")]
    pub(super) end_address: Option<String>,
    #[serde(default, rename = "ipVersion")]
    pub(super) ip_version: Option<String>,
    #[serde(default, rename = "parentHandle")]
    pub(super) parent_handle: Option<String>,
    #[serde(default, rename = "cidr0_cidrs")]
    pub(super) cidr0_cidrs: Vec<CidrEntry>,
    #[serde(default)]
    pub(super) events: Vec<RdapEvent>,
}

#[derive(Deserialize)]
pub(super) struct CidrEntry {
    #[serde(default)]
    pub(super) v4prefix: Option<String>,
    #[serde(default)]
    pub(super) v6prefix: Option<String>,
    #[serde(default)]
    pub(super) length: Option<u8>,
}

#[derive(Deserialize)]
pub(super) struct RdapEvent {
    #[serde(rename = "eventAction")]
    pub(super) action: String,
    #[serde(default, rename = "eventDate")]
    pub(super) date: Option<String>,
}

// BGPView ASN types

#[derive(Deserialize)]
pub(super) struct AsnResp {
    pub(super) data: Option<AsnData>,
    pub(super) status: String,
}

#[derive(Deserialize)]
pub(super) struct AsnData {
    pub(super) name: Option<String>,
    pub(super) description_short: Option<String>,
    pub(super) country_code: Option<String>,
    pub(super) rir_allocation: Option<RirInfo>,
    pub(super) email_contacts: Option<Vec<String>>,
    pub(super) abuse_contacts: Option<Vec<String>>,
    pub(super) website: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct RirInfo {
    pub(super) rir_name: Option<String>,
    pub(super) date_allocated: Option<String>,
}

// BGPView IP types

#[derive(Deserialize)]
pub(super) struct IpResp {
    pub(super) data: Option<IpData>,
    pub(super) status: String,
}

#[derive(Deserialize)]
pub(super) struct IpData {
    pub(super) prefixes: Option<Vec<PrefixInfo>>,
}

#[derive(Deserialize)]
pub(super) struct PrefixInfo {
    pub(super) prefix: Option<String>,
    pub(super) asn: Option<AsnRef>,
}

#[derive(Deserialize)]
pub(super) struct AsnRef {
    pub(super) asn: Option<u64>,
    pub(super) name: Option<String>,
    pub(super) description: Option<String>,
    pub(super) country_code: Option<String>,
}
