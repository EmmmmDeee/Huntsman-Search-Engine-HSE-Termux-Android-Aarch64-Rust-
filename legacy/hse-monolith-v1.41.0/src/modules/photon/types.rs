//! Serde types for the Photon (Komoot) geocoder API responses.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct PhotonResp {
    #[serde(default)]
    pub(super) features: Vec<Feature>,
}

#[derive(Deserialize)]
pub(super) struct Feature {
    #[serde(default)]
    pub(super) geometry: Option<Geometry>,
    #[serde(default)]
    pub(super) properties: Option<Props>,
}

#[derive(Deserialize)]
pub(super) struct Geometry {
    #[serde(default)]
    pub(super) coordinates: Vec<f64>,
}

#[derive(Deserialize)]
pub(super) struct Props {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) street: Option<String>,
    #[serde(default)]
    pub(super) housenumber: Option<String>,
    #[serde(default)]
    pub(super) postcode: Option<String>,
    #[serde(default)]
    pub(super) city: Option<String>,
    #[serde(default)]
    pub(super) state: Option<String>,
    #[serde(default)]
    pub(super) country: Option<String>,
    #[serde(default)]
    pub(super) countrycode: Option<String>,
    #[serde(rename = "type")]
    #[serde(default)]
    pub(super) place_type: Option<String>,
    #[serde(default)]
    pub(super) osm_key: Option<String>,
    #[serde(default)]
    pub(super) osm_value: Option<String>,
}
