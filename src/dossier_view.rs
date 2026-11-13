//! Read-only, local evidence register page. No network requests or duplicate evidence storage.
//! Every record and field is rendered; invalid or oversized input fails explicitly.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

pub use bundle::{BundleReport, VerifiedBundle, verify_bundle};

mod bundle;
mod json;

use crate::textnorm::escape_html;

pub const MAX_DOSSIER_BYTES: u64 = 4 * 1024 * 1024;

/// Inline CSS hash is included in the dossier page's dedicated CSP by `web_server`.
pub const STYLE: &str = r"
:root{color-scheme:dark light;font-family:system-ui,Arial,sans-serif;background:#0c1118;color:#e1e8ef}
*{box-sizing:border-box}body{margin:0;line-height:1.55;font-size:15px}
a{color:#64d1ff;overflow-wrap:anywhere}a:focus-visible{outline:2px solid #64d1ff}
header,main,footer{max-width:1200px;margin:auto;padding:16px}header{border-bottom:1px solid #354454}
header h1{font-size:1.55rem;margin:0}p{margin:8px 0 14px}
nav{display:flex;gap:7px;flex-wrap:wrap;padding:13px 0}nav a{padding:7px 10px;border:1px solid #41556a;border-radius:7px;text-decoration:none}
section{margin:20px 0 38px}h2{border-bottom:1px solid #354454;padding-bottom:6px}
section h2{font-size:1.28rem}article{background:#16202c;border:1px solid #344254;border-radius:8px;margin:12px 0;padding:12px 15px;overflow-wrap:anywhere}
article:target{border-color:#64d1ff}h3{font-size:1rem;margin:0 0 7px}dl{margin:0;display:grid;grid-template-columns:minmax(9rem,21%) minmax(0,1fr);gap:6px 12px}
dt{color:#afc2d5;font-weight:600}dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
code{font-size:.9em;overflow-wrap:anywhere}small,.muted{color:#c5d1dc}
.summary{display:flex;gap:10px;flex-wrap:wrap}.summary span{background:#192637;border:1px solid #344254;border-radius:7px;padding:7px 12px}
.warning{border-left:4px solid #e4b75c;padding:10px 14px;background:#29251a}
@media(max-width:650px){header,main,footer{padding:12px}dl{display:block}dt{margin-top:9px}dd{padding-left:7px}article{padding:11px}}
@media(prefers-color-scheme:light){:root{background:#f7f9fc;color:#162030}article{background:#fff;border-color:#b3c2d1}dt,small,.muted{color:#3d536b}h2,header{border-color:#c9d4df}a{color:#055b8a}.summary span{background:#eef3f9;border-color:#bdcddd}nav a{border-color:#a8b8ca}.warning{background:#fff4de}}
";

const GROUPS: [(&str, &str); 6] = [
    ("claims", "Evidence claims"),
    (
        "cross_source_correlation",
        "Correlations and contradictions",
    ),
    ("uncertainties", "Uncertainties and blockers"),
    ("hypotheses", "Competing hypotheses"),
    ("actions", "Verification actions"),
    ("sources", "Sources and provenance"),
];

fn readable(key: &str) -> String {
    key.replace('_', " ")
}

/// A refusal from the shared CLI and HTTP dossier loader.
#[derive(Debug, thiserror::Error)]
pub enum DossierError {
    #[error("set HOME or HUNTSMAN_DOSSIER_PATH")]
    NoPath,
    #[error("dossier file not found")]
    Missing,
    #[error("dossier exceeds {MAX_DOSSIER_BYTES} bytes")]
    TooLarge,
    #[error("cannot read dossier: {0}")]
    Read(String),
    #[error("{0}")]
    Invalid(String),
    #[error("cannot install dossier: {0}")]
    Install(String),
}

/// A complete register whose indexed records have globally unique, validated IDs.
/// The exact source bytes and the parsed view share the same checked input.
pub struct Dossier {
    raw: Vec<u8>,
    root: Map<String, Value>,
    ids: BTreeSet<String>,
}

impl Dossier {
    pub fn from_bytes(raw: Vec<u8>) -> Result<Self, DossierError> {
        if raw.len() as u64 > MAX_DOSSIER_BYTES {
            return Err(DossierError::TooLarge);
        }
        let document = json::parse(&raw)
            .map_err(|error| DossierError::Invalid(format!("invalid dossier JSON: {error}")))?;
        let ids = indexed_ids(&document).map_err(DossierError::Invalid)?;
        let Value::Object(root) = document else {
            unreachable!("indexed_ids checked the root");
        };
        Ok(Self { raw, root, ids })
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.ids.len()
    }

    #[must_use]
    pub fn sha256(&self) -> String {
        crate::sha256::hex32(&crate::sha256::sha256(&self.raw))
    }

    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Publish the exact checked bytes to the configured file without overwriting it.
    /// A retry with identical bytes succeeds, including after a concurrent installation.
    pub fn install(&self) -> Result<(), DossierError> {
        let path = configured_path()?;
        match crate::fsio::install_atomic_private(&path, self.raw(), MAX_DOSSIER_BYTES) {
            Ok(()) => Ok(()),
            Err(_) if read(&path).is_ok_and(|existing| existing.raw() == self.raw()) => Ok(()),
            Err(error) => Err(DossierError::Install(error.to_string())),
        }
    }

    /// Render the same checked snapshot the API serves.
    #[must_use]
    pub fn html(&self) -> String {
        render_indexed(&self.root, &self.ids)
    }
}

fn indexed_ids(document: &Value) -> Result<BTreeSet<String>, String> {
    let object = document
        .as_object()
        .ok_or("dossier root must be a JSON object")?;
    let mut ids = BTreeSet::new();
    for (key, _) in GROUPS {
        let rows = object
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("required `{key}` array absent"))?;
        for (index, row) in rows.iter().enumerate() {
            let id = row
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{key}[{index}] lacks a string id"))?;
            if id.len() > 64
                || id.is_empty()
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                || id == "context"
                || GROUPS.iter().any(|(group, _)| id == *group)
            {
                return Err(format!("invalid or reserved evidence id in {key}[{index}]"));
            }
            if !ids.insert(id.to_owned()) {
                return Err(format!("duplicate evidence id `{id}`"));
            }
        }
    }
    Ok(ids)
}

/// Resolve the same path for CLI operations and the local web viewer.
pub fn configured_path() -> Result<PathBuf, DossierError> {
    crate::environment::dossier_path()
        .map(PathBuf::from)
        .or_else(|| {
            crate::environment::home()
                .map(|home| PathBuf::from(home).join(".huntsman/dossier/register.json"))
        })
        .ok_or(DossierError::NoPath)
}

pub fn load() -> Result<Dossier, DossierError> {
    read(&configured_path()?)
}

/// Read a regular file, refusing symlinks and a path swapped during open.
pub fn read(path: &Path) -> Result<Dossier, DossierError> {
    let file = open_regular(path)?;
    if file
        .metadata()
        .map_err(|error| DossierError::Read(error.to_string()))?
        .len()
        > MAX_DOSSIER_BYTES
    {
        return Err(DossierError::TooLarge);
    }
    let mut raw = Vec::new();
    file.take(MAX_DOSSIER_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| DossierError::Read(error.to_string()))?;
    Dossier::from_bytes(raw)
}

fn open_regular(path: &Path) -> Result<File, DossierError> {
    use crate::fsio::OpenRefusal;
    crate::fsio::open_checked(path, OpenOptions::new().read(true), false).map_err(|error| {
        match error {
            OpenRefusal::Io(error) if error.kind() == ErrorKind::NotFound => DossierError::Missing,
            OpenRefusal::Io(error) => DossierError::Read(error.to_string()),
            OpenRefusal::Linked | OpenRefusal::Changed | OpenRefusal::NotRegular => {
                DossierError::Read("expected a stable regular file".into())
            }
        }
    })
}

fn field(out: &mut String, key: &str, value: &Value, ids: &BTreeSet<String>) {
    let _ = write!(out, "<dt>{}</dt><dd>", escape_html(&readable(key)));
    // Reference arrays must be traversed as JSON values: serializing the whole array
    // first turns ["S01"] into a token that cannot match the validated id S01.
    // Preserve the complete JSON representation, linking only exact known IDs.
    let is_reference = [
        "sources",
        "related",
        "links",
        "resolves",
        "left",
        "right",
        "same_underlying_source_as",
    ]
    .contains(&key);
    if is_reference {
        if let Some(items) = value.as_array() {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                let serialized = item.to_string();
                if let Some(id) = item.as_str().filter(|id| ids.contains(*id)) {
                    let _ = write!(out, "<a href=\"#{id}\">{}</a>", escape_html(&serialized));
                } else {
                    out.push_str(&escape_html(&serialized));
                }
            }
            out.push(']');
            out.push_str("</dd>");
            return;
        }
    }
    let value = value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned);
    if key == "url" && (value.starts_with("https://") || value.starts_with("http://")) {
        let val = escape_html(&value);
        let _ = write!(
            out,
            "<a rel=\"noopener noreferrer\" referrerpolicy=\"no-referrer\" href=\"{val}\">{val}</a>"
        );
    } else if is_reference {
        // Keep the source text exactly as displayed, including whitespace and punctuation.
        for token in value.split_inclusive(char::is_whitespace) {
            let word = token.trim_end_matches(char::is_whitespace);
            if ids.contains(word) {
                let _ = write!(out, "<a href=\"#{word}\">{word}</a>");
                out.push_str(&token[word.len()..]);
            } else {
                out.push_str(&escape_html(token));
            }
        }
    } else {
        out.push_str(&escape_html(&value));
    }
    out.push_str("</dd>");
}

/// Render every record and field. Browser Find and anchored links work without JavaScript.
fn render_indexed(root: &Map<String, Value>, ids: &BTreeSet<String>) -> String {
    let count = ids.len();
    let mut out = String::with_capacity(count * 650);
    out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"referrer\" content=\"no-referrer\"><title>HUNTSMAN | Evidence dossier</title><style>");
    out.push_str(STYLE);
    out.push_str("</style></head><body><header><h1>HUNTSMAN — Evidence dossier</h1><p>Local, read-only, provenance-indexed. No results are hidden or paginated. <a href=\"/\">Return to Huntsman</a>.</p>");
    out.push_str("<p class=\"warning\">Recorded observations are not proof of source-device attribution, item authenticity, or substance identity. Absence of evidence is not evidence of absence.</p>");
    let _ = write!(
        out,
        "<p class=\"muted\">{} indexed records · {} </p>",
        count,
        escape_html(
            root.get("updated_at")
                .and_then(Value::as_str)
                .unwrap_or("date not supplied")
        )
    );
    out.push_str("<nav aria-label=\"Evidence index\">");
    for (key, title) in GROUPS {
        let len = root[key].as_array().map_or(0, Vec::len);
        let _ = write!(out, "<a href=\"#{key}\">{title} ({len})</a>");
    }
    out.push_str("</nav></header><main>");
    for (key, title) in GROUPS {
        let rows = root[key].as_array().expect("validate checked array");
        let _ = write!(
            out,
            "<section id=\"{key}\"><h2>{title} — {} records</h2>",
            rows.len()
        );
        for row in rows {
            let obj = row.as_object().expect("validate checked record");
            let id = obj["id"].as_str().expect("validate checked id");
            let heading = ["finding", "topic", "claim", "task", "title", "result"]
                .iter()
                .find_map(|name| obj.get(*name).and_then(Value::as_str))
                .unwrap_or("Evidence record");
            let _ = write!(
                out,
                "<article id=\"{id}\"><h3><code>{id}</code> — {}</h3><dl>",
                escape_html(heading)
            );
            for (field_name, value) in obj {
                if field_name != "id" {
                    field(&mut out, field_name, value, ids);
                }
            }
            out.push_str("</dl></article>");
        }
        out.push_str("</section>");
    }
    // Preserve non-indexed top-level provenance, original media hashes, audit trail,
    // verification metadata and limitations in the human-readable view as well as the API.
    // These fields are intentionally not minted new evidence IDs.
    out.push_str("<section id=\"context\"><h2>Additional provenance, media and audit data</h2>");
    for (key, value) in root {
        if !GROUPS.iter().any(|(group, _)| *group == key.as_str()) {
            let _ = write!(out, "<article><h3>{}</h3><dl>", escape_html(&readable(key)));
            field(&mut out, key, value, ids);
            out.push_str("</dl></article>");
        }
    }
    out.push_str("</section>");
    out.push_str("</main><footer><p>This viewer does not rewrite source records or infer unsupported conclusions.</p></footer></body></html>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn render(doc: &Value) -> String {
        Dossier::from_bytes(serde_json::to_vec(doc).unwrap())
            .unwrap()
            .html()
    }

    fn fixture() -> Value {
        serde_json::json!({
            "claims":[{"id":"E01","finding":"<script>alert(1)</script>","sources":"S01","raw":"<unsafe>"}],
            "cross_source_correlation":[],"uncertainties":[],"hypotheses":[],"actions":[],
            "sources":[{"id":"S01","title":"source","url":"https://example.org/?q=\"x\"&f=1"}],
        })
    }
    #[test]
    fn preserves_all_records_and_escapes_input() {
        let html = render(&fixture());
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;unsafe&gt;"));
        assert!(html.contains("href=\"#S01\""));
        assert!(html.contains("&quot;x&quot;&amp;f=1"));
        assert!(html.contains("2 indexed records"));
    }
    #[test]
    fn includes_nonindexed_provenance_and_original_media() {
        let mut doc = fixture();
        doc["media_manifest"] = serde_json::json!([{"filename":"original.jpg","sha256":"abc123"}]);
        doc["audit_changes_2026_10_24"] = serde_json::json!([{"action":"checked"}]);
        doc["verification"] = serde_json::json!({"media_hashed":6});
        let html = render(&doc);
        assert!(html.contains("original.jpg"));
        assert!(html.contains("abc123"));
        assert!(html.contains("checked"));
        assert!(html.contains("media_hashed"));
        assert!(html.contains("2 indexed records"));
    }

    #[test]
    fn links_array_references_without_dropping_unknown_evidence() {
        let mut doc = fixture();
        doc["claims"][0]["sources"] = serde_json::json!([
            "S01",
            "S99",
            {"external": "<unverified>"}
        ]);
        doc["claims"][0]["related"] = serde_json::json!(["E01"]);
        let html = render(&doc);
        assert!(html.contains("href=\"#S01\">&quot;S01&quot;</a>"));
        assert!(html.contains("href=\"#E01\">&quot;E01&quot;</a>"));
        assert!(html.contains("&quot;S99&quot;"));
        assert!(html.contains("&lt;unverified&gt;"));
    }

    #[test]
    fn rejects_duplicate_json_members_at_every_depth() {
        let raw = serde_json::to_vec(&fixture()).unwrap();
        let doc = Dossier::from_bytes(raw.clone()).unwrap();
        assert_eq!(doc.raw(), raw);
        for replacement in [
            r#""raw":"first","raw":"second""#,
            r#""raw":{"nested":[{"key":1,"key":2}]}"#,
        ] {
            let changed = String::from_utf8(raw.clone())
                .unwrap()
                .replace(r#""raw":"<unsafe>""#, replacement);
            assert!(matches!(
                Dossier::from_bytes(changed.into_bytes()),
                Err(DossierError::Invalid(message)) if message.contains("duplicate JSON object member")
            ));
        }
    }

    #[test]
    fn refuses_duplicate_and_missing_rows() {
        let mut doc = fixture();
        doc["claims"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"id":"S01"}));
        assert!(indexed_ids(&doc).unwrap_err().contains("duplicate"));
        doc.as_object_mut().unwrap().remove("actions");
        assert!(indexed_ids(&doc).is_err());
    }
}
