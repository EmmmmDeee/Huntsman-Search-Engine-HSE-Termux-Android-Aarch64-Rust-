//! JSON-LD / Schema.org structured-data extraction.
//!
//! Parses `<script type="application/ld+json">` blocks from raw HTML and
//! provides typed helpers for common Schema.org field lookups. The extractor
//! runs against raw HTML *before* any tag-stripping so the structured markup
//! (which lives inside `<script>` elements that `strip_html` discards) is not
//! lost.
//!
//! All helpers are pure functions — no HTTP, no I/O.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

/// Extract all `<script type="application/ld+json">` blocks from an HTML page.
///
/// - Blocks wrapped in a `@graph` array are flattened into individual items.
/// - Unparseable blocks are silently skipped.
/// - Returns an empty Vec when none are found.
pub fn extract_jsonld_blocks(html: &str) -> Vec<Value> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        // (?is): i = case-insensitive, s = DOTALL (. matches \n inside JSON body)
        Regex::new(
            r#"(?is)<script\b[^>]*\btype\s*=\s*["']application/ld\+json["'][^>]*>(.*?)</script>"#,
        )
        .unwrap()
    });
    let mut out = Vec::new();
    for cap in re.captures_iter(html) {
        let raw = match cap.get(1) {
            Some(m) => m.as_str().trim(),
            None => continue,
        };
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            // @graph is a JSON-LD convention for embedding multiple top-level nodes.
            if let Some(graph) = v.get("@graph").and_then(|g| g.as_array()) {
                out.extend(graph.iter().cloned());
            } else {
                out.push(v);
            }
        }
    }
    out
}

/// Return all blocks whose `@type` contains `schema_type` (case-insensitive
/// substring match). Handles `@type` as a plain string (`"RealEstateAgent"`),
/// a schema-prefixed string (`"schema:RealEstateAgent"`), a full URI, or an
/// array of any of the above.
pub fn blocks_of_type<'a>(blocks: &'a [Value], schema_type: &str) -> Vec<&'a Value> {
    let needle = schema_type.to_lowercase();
    blocks.iter().filter(|b| type_matches(b, &needle)).collect()
}

fn type_matches(v: &Value, needle: &str) -> bool {
    match v.get("@type") {
        Some(Value::String(t)) => t.to_lowercase().contains(needle),
        Some(Value::Array(ts)) => ts.iter().any(|t| {
            t.as_str()
                .is_some_and(|s| s.to_lowercase().contains(needle))
        }),
        _ => false,
    }
}

/// Get a field value as a non-empty owned `String`, else `None`.
///
/// If the field value is a JSON object rather than a string (common for nested
/// Schema.org types like `worksFor: { "@type": "Organization", "name": "…" }`),
/// returns the object's `name` or `@value` sub-field.
pub fn field_str(node: &Value, key: &str) -> Option<String> {
    match node.get(key)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Object(obj) => obj
            .get("name")
            .or_else(|| obj.get("@value"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        _ => None,
    }
}

/// Get `node[outer_key][inner_key]` as a non-empty owned `String`, else `None`.
///
/// Useful for patterns like `field_str_nested(block, "worksFor", "name")` when
/// `worksFor` is an embedded object.
pub fn field_str_nested(node: &Value, outer_key: &str, inner_key: &str) -> Option<String> {
    node.get(outer_key)
        .and_then(|v| v.get(inner_key))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Get a field as a `Vec<String>` (handles both a bare string and an array).
/// Empty strings and non-string entries are skipped.
pub fn field_strings(node: &Value, key: &str) -> Vec<String> {
    match node.get(key) {
        None => Vec::new(),
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_single_jsonld_block() {
        let html = r#"<html><head>
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"RealEstateAgent","name":"Test Agent","telephone":"+61400000000"}
</script></head></html>"#;
        let blocks = extract_jsonld_blocks(html);
        assert_eq!(blocks.len(), 1);
        assert_eq!(field_str(&blocks[0], "name").as_deref(), Some("Test Agent"));
    }

    #[test]
    fn flattens_graph_array() {
        let html = r#"<script type="application/ld+json">
{"@context":"https://schema.org","@graph":[{"@type":"Person","name":"Alice"},{"@type":"Organization","name":"ACME"}]}
</script>"#;
        let blocks = extract_jsonld_blocks(html);
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn blocks_of_type_case_insensitive() {
        let html = r#"<script type="application/ld+json">
{"@type":"RealEstateAgent","name":"Agent","telephone":"0400111222"}
</script>"#;
        let blocks = extract_jsonld_blocks(html);
        assert_eq!(blocks_of_type(&blocks, "realestateagent").len(), 1);
        assert_eq!(blocks_of_type(&blocks, "person").len(), 0);
    }

    #[test]
    fn field_str_nested_works() {
        let html = r#"<script type="application/ld+json">
{"@type":"Person","name":"Bob","worksFor":{"@type":"Organization","name":"ACME Corp"}}
</script>"#;
        let blocks = extract_jsonld_blocks(html);
        assert_eq!(
            field_str_nested(&blocks[0], "worksFor", "name").as_deref(),
            Some("ACME Corp")
        );
    }
}
