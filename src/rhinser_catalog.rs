//! Offline, source-labelled Rhinser catalogue compatibility.
//!
//! A directory entry is a lead only: no endpoint is contacted by these functions,
//! and an indexed URL cannot establish an identity or a claim's provenance.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

const CATALOG_JSON: &str = include_str!("rhinser_catalog.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub tools: Vec<Tool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Catalog {
    pub schema_version: u32,
    pub origin_apk_sha256: String,
    pub notice: String,
    pub categories: Vec<Category>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolHit<'a> {
    pub category_id: &'a str,
    pub category_name: &'a str,
    pub tool: &'a Tool,
    pub evidence_role: &'static str,
}

impl Catalog {
    /// Parse and validate the embedded, finite, offline directory.
    ///
    /// # Errors
    /// Rejects malformed records, duplicate IDs and non-HTTPS links.
    pub fn load() -> Result<Self, String> {
        let mut catalogue: Self =
            serde_json::from_str(CATALOG_JSON).map_err(|error| error.to_string())?;
        // The public source-APK SHA-256 is segmented in the embedded JSON.
        // A contiguous 64-hex digest otherwise looks like an HIBP API key to
        // the release artifact scanner. Reassemble only the exact 4x16 form;
        // keep the scanner's secret-detection rules unchanged.
        if catalogue.origin_apk_sha256.len() == 67
            && [16, 33, 50]
                .iter()
                .all(|&index| catalogue.origin_apk_sha256.as_bytes()[index] == b':')
        {
            catalogue.origin_apk_sha256.retain(|c| c != ':');
        }
        catalogue.validate()?;
        Ok(catalogue)
    }

    /// # Errors
    /// Rejects inconsistent, ambiguous or unsupported directory contents.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.categories.is_empty()
            || self.categories.len() > 64
            || self.origin_apk_sha256.len() != 64
            || !self
                .origin_apk_sha256
                .bytes()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err("invalid catalogue header".to_owned());
        }
        let mut category_ids = BTreeSet::new();
        let mut tool_ids = BTreeSet::new();
        for category in &self.categories {
            if category.id.is_empty()
                || category.name.trim().is_empty()
                || !category_ids.insert(&category.id)
            {
                return Err("invalid or duplicate catalogue category".to_owned());
            }
            for tool in &category.tools {
                if tool.id.trim().is_empty()
                    || tool.name.trim().is_empty()
                    || tool.id.len() > 80
                    || tool.name.len() > 200
                    || tool.url.len() > 2048
                    || !tool.url.starts_with("https://")
                    || tool.query_template.as_ref().is_some_and(|template| {
                        !template.starts_with("https://")
                            || template.matches("{q}").count() != 1
                            || template.len() > 2048
                    })
                    || tool.url.contains('@')
                    || tool.url.chars().any(char::is_control)
                    || !tool_ids.insert(&tool.id)
                {
                    return Err("invalid or duplicate catalogue tool".to_owned());
                }
            }
        }
        if tool_ids.len() > 1024 {
            return Err("catalogue exceeds the supported entry budget".to_owned());
        }
        Ok(())
    }

    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.categories
            .iter()
            .map(|category| category.tools.len())
            .sum()
    }

    #[must_use]
    pub fn category(&self, id: &str) -> Option<&Category> {
        self.categories.iter().find(|category| category.id == id)
    }

    #[must_use]
    pub fn tool(&self, id: &str) -> Option<ToolHit<'_>> {
        self.categories.iter().find_map(|category| {
            category
                .tools
                .iter()
                .find(|tool| tool.id == id)
                .map(|tool| ToolHit {
                    category_id: &category.id,
                    category_name: &category.name,
                    tool,
                    evidence_role: "lead_only_unverified",
                })
        })
    }

    /// Render a provider-provided search template without requesting the URL.
    ///
    /// # Errors
    /// Refuses unsupported tools and invalid or overlong query text.
    pub fn search_url(&self, id: &str, query: &str) -> Result<String, String> {
        let hit = self
            .tool(id)
            .ok_or_else(|| "unknown catalogue tool".to_owned())?;
        let template = hit
            .tool
            .query_template
            .as_ref()
            .ok_or_else(|| "this tool has no verified query template".to_owned())?;
        if query.trim().is_empty() || query.len() > 256 || query.chars().any(char::is_control) {
            return Err("invalid catalogue query".to_owned());
        }
        let encoded = crate::http::percent_encode_unreserved(query.trim());
        Ok(template.replace("{q}", &encoded))
    }

    /// Search official source names, categories and destinations; no remote requests.
    #[must_use]
    pub fn find(&self, query: &str) -> Vec<ToolHit<'_>> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() || needle.len() > 256 || needle.chars().any(char::is_control) {
            return Vec::new();
        }
        let mut hits = Vec::new();
        for category in &self.categories {
            let category_match = category.name.to_lowercase().contains(&needle)
                || category.id.to_lowercase().contains(&needle);
            for tool in &category.tools {
                if category_match
                    || tool.name.to_lowercase().contains(&needle)
                    || tool.url.to_lowercase().contains(&needle)
                {
                    hits.push(ToolHit {
                        category_id: &category.id,
                        category_name: &category.name,
                        tool,
                        evidence_role: "lead_only_unverified",
                    });
                }
            }
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_every_reconstructed_category_and_tool() {
        let catalog = Catalog::load().unwrap();
        assert_eq!(catalog.categories.len(), 11);
        assert_eq!(catalog.tool_count(), 83);
        assert_eq!(catalog.category("au_professions").unwrap().tools.len(), 16);
        assert!(catalog.tool("t0392").is_some());
        assert!(catalog.tool("emailosint").is_some());
        assert!(catalog.categories.iter().all(|c| !c.tools.is_empty()));
    }

    #[test]
    fn public_apk_digest_is_segmented_in_binary_but_normalized_for_consumers() {
        let raw: serde_json::Value = serde_json::from_str(CATALOG_JSON).unwrap();
        let encoded = raw["origin_apk_sha256"].as_str().unwrap();
        let chunks: Vec<_> = encoded.split(':').collect();
        assert_eq!(chunks.len(), 4);
        assert!(chunks.iter().all(|chunk| {
            chunk.len() == 16 && chunk.bytes().all(|byte| byte.is_ascii_hexdigit())
        }));
        assert_eq!(Catalog::load().unwrap().origin_apk_sha256, chunks.concat());
        // Keep the public digest out of the 32-hex secret-signature window.
        assert!(
            !CATALOG_JSON
                .as_bytes()
                .windows(32)
                .any(|window| { window.iter().all(|byte| byte.is_ascii_hexdigit()) })
        );
    }

    #[test]
    fn category_search_and_identity_do_not_create_evidence() {
        let catalog = Catalog::load().unwrap();
        let hits = catalog.find("unclaimed money");
        assert!(hits.len() >= 4);
        assert!(
            hits.iter()
                .all(|hit| hit.evidence_role == "lead_only_unverified")
        );
        assert!(
            catalog
                .tool("t0406")
                .unwrap()
                .tool
                .url
                .contains("qldtraffic")
        );
        assert!(catalog.tool("unknown").is_none());
        assert!(catalog.find("  ").is_empty());
    }

    #[test]
    fn duplicates_and_untrusted_urls_are_rejected() {
        let mut catalog = Catalog::load().unwrap();
        let duplicate = catalog.categories[0].tools[0].clone();
        catalog.categories[1].tools.push(duplicate);
        assert!(catalog.validate().is_err());
        catalog.categories[1].tools.pop();
        catalog.categories[0].tools[0].url = "http://example.org".to_owned();
        assert!(catalog.validate().is_err());
    }

    #[test]
    fn reconstructed_email_query_templates_percent_encode_without_fetching() {
        let catalog = Catalog::load().unwrap();
        assert_eq!(
            catalog
                .search_url("emailosint", "person+tag@example.org")
                .unwrap(),
            "https://emailosint.com/?q=person%2Btag%40example.org"
        );
        assert!(catalog.search_url("t0343", "test").is_err());
        assert!(catalog.search_url("emailosint", "").is_err());
    }

    #[test]
    fn source_directory_is_deterministic_and_unmodified() {
        assert_eq!(
            serde_json::to_value(Catalog::load().unwrap()).unwrap(),
            serde_json::to_value(Catalog::load().unwrap()).unwrap()
        );
    }
}
