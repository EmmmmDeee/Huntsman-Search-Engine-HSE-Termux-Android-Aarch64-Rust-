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
    /// Nested contact objects (registrant / abuse / technical / administrative).
    /// RDAP nests these — a registrant entity commonly carries its own child
    /// abuse/technical contacts — so [`RdapContact`] recurses.
    #[serde(default)]
    pub(super) entities: Vec<RdapContact>,
}

/// One RDAP contact entity. Only the `roles`, `vcardArray`, and nested
/// `entities` are modelled — the fields the registrant/abuse extraction needs.
#[derive(Deserialize)]
pub(super) struct RdapContact {
    #[serde(default)]
    pub(super) roles: Vec<String>,
    #[serde(default, rename = "vcardArray")]
    pub(super) vcard_array: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) entities: Vec<RdapContact>,
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

// RDAP autnum types

/// An RDAP `autnum` object (RFC 9083 §5.5) — the registry record of an ASN,
/// served by ARIN's RDAP root and redirected to the authoritative RIR. Only the
/// fields the ASN extraction reads are modelled; the contact tree reuses
/// [`RdapContact`] exactly as the IP allocation record does.
#[derive(Deserialize)]
pub(super) struct AutnumResp {
    #[serde(default)]
    pub(super) handle: Option<String>,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default, rename = "startAutnum")]
    pub(super) start_autnum: Option<u64>,
    #[serde(default, rename = "endAutnum")]
    pub(super) end_autnum: Option<u64>,
    #[serde(default)]
    pub(super) status: Vec<String>,
    /// The registry's WHOIS host (`whois.arin.net`, `whois.ripe.net`) — names
    /// which RIR answered after the bootstrap redirect.
    #[serde(default)]
    pub(super) port43: Option<String>,
    #[serde(default)]
    pub(super) events: Vec<RdapEvent>,
    #[serde(default)]
    pub(super) entities: Vec<RdapContact>,
}
