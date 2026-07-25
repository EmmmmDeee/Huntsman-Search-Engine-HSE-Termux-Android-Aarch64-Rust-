//! Serde types for the GLEIF JSON:API response.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct GleifResp {
    #[serde(default)]
    pub(super) data: Vec<GleifRecord>,
    #[serde(default)]
    pub(super) meta: Option<GleifMeta>,
}

#[derive(Deserialize)]
pub(super) struct GleifMeta {
    #[serde(default)]
    pub(super) pagination: Option<GleifPagination>,
}

#[derive(Deserialize)]
pub(super) struct GleifPagination {
    #[serde(default)]
    pub(super) total: Option<u64>,
}

/// A JSON:API response carrying exactly ONE record.
///
/// GLEIF's single-valued Level-2 links (`/direct-parent`, `/ultimate-parent`)
/// return `data` as an object, whereas a search or `/direct-children` returns it
/// as an array — the same field, two shapes, so they need two types.
#[derive(Deserialize)]
pub(super) struct GleifOneResp {
    #[serde(default)]
    pub(super) data: Option<GleifRecord>,
}

#[derive(Deserialize)]
pub(super) struct GleifRecord {
    #[serde(default)]
    pub(super) attributes: Option<GleifAttrs>,
}

#[derive(Deserialize)]
pub(super) struct GleifAttrs {
    #[serde(default)]
    pub(super) lei: Option<String>,
    #[serde(default)]
    pub(super) entity: Option<GleifEntity>,
}

#[derive(Deserialize)]
pub(super) struct GleifEntity {
    #[serde(rename = "legalName", default)]
    pub(super) legal_name: Option<GleifName>,
    #[serde(default)]
    pub(super) jurisdiction: Option<String>,
    #[serde(default)]
    pub(super) status: Option<String>,
    #[serde(rename = "registeredAs", default)]
    pub(super) registered_as: Option<String>,
    #[serde(rename = "legalAddress", default)]
    pub(super) legal_address: Option<GleifAddress>,
    #[serde(rename = "headquartersAddress", default)]
    pub(super) hq_address: Option<GleifAddress>,
}

#[derive(Deserialize)]
pub(super) struct GleifName {
    #[serde(default)]
    pub(super) name: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct GleifAddress {
    #[serde(rename = "addressLines", default)]
    pub(super) address_lines: Vec<String>,
    #[serde(default)]
    pub(super) city: Option<String>,
    #[serde(default)]
    pub(super) region: Option<String>,
    #[serde(rename = "postalCode", default)]
    pub(super) postal_code: Option<String>,
    #[serde(default)]
    pub(super) country: Option<String>,
}
