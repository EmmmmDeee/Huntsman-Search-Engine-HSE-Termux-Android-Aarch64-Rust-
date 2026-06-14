use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub(super) struct SearchResp {
    #[serde(default)]
    pub(super) search: Vec<SearchHit>,
}

#[derive(Deserialize)]
pub(super) struct SearchHit {
    pub(super) id: String,
    #[serde(default)]
    pub(super) label: Option<String>,
    #[serde(default)]
    pub(super) description: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct EntitiesResp {
    /// Entity bodies kept as raw JSON: claim `datavalue.value` is a string for
    /// handle/website properties but an object (`{"id":"Q5"}`) for P31, so a
    /// flexible `Value` is more robust than a rigid typed model.
    #[serde(default)]
    pub(super) entities: serde_json::Map<String, Value>,
}
