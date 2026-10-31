//! Local, deterministic OSINT workspace: cases, notes, source leads and tool history.
//! Nothing here fetches or verifies remote evidence. A source URL is a lead, not a fact.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const MAX_WORKSPACE_BYTES: u64 = 256 * 1024;
const MAX_CASES: usize = 128;
const MAX_ENTRIES: usize = 512;
const MAX_RECENT: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Note {
    pub text: String,
    pub recorded_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceLead {
    pub id: String,
    pub url: String,
    pub summary: String,
    pub recorded_at_unix: u64,
    pub evidence_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub title: String,
    pub notes: Vec<Note>,
    pub source_leads: Vec<SourceLead>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    pub schema_version: u32,
    pub cases: Vec<Case>,
    pub bookmarks: Vec<String>,
    pub favourites: Vec<String>,
    pub recent_tools: Vec<String>,
    pub search_history: Vec<String>,
    pub settings: BTreeMap<String, String>,
}

impl Default for Workspace {
    fn default() -> Self {
        Self {
            schema_version: 1,
            cases: Vec::new(),
            bookmarks: Vec::new(),
            favourites: Vec::new(),
            recent_tools: Vec::new(),
            search_history: Vec::new(),
            settings: BTreeMap::new(),
        }
    }
}

fn valid(value: &str, max_len: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

impl Workspace {
    /// Reject malformed persisted data before any mutation.
    ///
    /// # Errors
    /// Invalid schema, invalid links, oversized input or duplicate keys.
    pub fn from_json(data: &[u8]) -> Result<Self, String> {
        if u64::try_from(data.len()).unwrap_or(u64::MAX) > MAX_WORKSPACE_BYTES {
            return Err("workspace exceeds size limit".to_owned());
        }
        let workspace: Self = serde_json::from_slice(data).map_err(|error| error.to_string())?;
        workspace.validate()?;
        Ok(workspace)
    }

    /// # Errors
    /// Refuses malformed local or source identifiers.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.cases.len() > MAX_CASES
            || self.bookmarks.len() > MAX_ENTRIES
            || self.favourites.len() > MAX_ENTRIES
            || self.recent_tools.len() > MAX_RECENT
            || self.search_history.len() > MAX_RECENT
            || self.settings.len() > MAX_ENTRIES
        {
            return Err("unsupported or oversized workspace".to_owned());
        }
        let mut ids = std::collections::BTreeSet::new();
        for case in &self.cases {
            if !valid(&case.id, 100)
                || !valid(&case.title, 256)
                || !ids.insert(&case.id)
                || case.notes.len() > MAX_ENTRIES
                || case.source_leads.len() > MAX_ENTRIES
            {
                return Err("invalid or duplicate case".to_owned());
            }
            let mut leads = std::collections::BTreeSet::new();
            for lead in &case.source_leads {
                if !valid(&lead.id, 100)
                    || !valid(&lead.summary, 1024)
                    || !leads.insert(&lead.id)
                    || lead.evidence_status != "lead_only_unverified"
                    || crate::osint_casework::validate_public_source_url(&lead.url).is_err()
                {
                    return Err("invalid source lead".to_owned());
                }
            }
            if case.notes.iter().any(|note| !valid(&note.text, 4096)) {
                return Err("invalid case note".to_owned());
            }
        }
        for id in self
            .bookmarks
            .iter()
            .chain(&self.favourites)
            .chain(&self.recent_tools)
        {
            if !valid(id, 100) {
                return Err("invalid tool identifier".to_owned());
            }
        }
        if self.search_history.iter().any(|text| !valid(text, 1024))
            || self.settings.iter().any(|(key, value)| {
                !valid(key, 100) || value.len() > 4096 || value.chars().any(char::is_control)
            })
        {
            return Err("invalid history or setting".to_owned());
        }
        Ok(())
    }

    /// # Errors
    /// Empty, duplicate or excessive case identifiers.
    pub fn create_case(&mut self, id: &str, title: &str) -> Result<(), String> {
        if !valid(id, 100) || !valid(title, 256) {
            return Err("case id or title invalid".to_owned());
        }
        if self.cases.len() >= MAX_CASES || self.cases.iter().any(|case| case.id == id) {
            return Err("case duplicate or limit reached".to_owned());
        }
        self.cases.push(Case {
            id: id.to_owned(),
            title: title.to_owned(),
            notes: Vec::new(),
            source_leads: Vec::new(),
        });
        Ok(())
    }

    /// # Errors
    /// Unknown case, invalid text, or exceeded capacity.
    pub fn add_note(&mut self, id: &str, text: &str, now: u64) -> Result<(), String> {
        if !valid(text, 4096) {
            return Err("invalid note".to_owned());
        }
        let case = self
            .cases
            .iter_mut()
            .find(|case| case.id == id)
            .ok_or_else(|| "unknown case".to_owned())?;
        if case.notes.len() >= MAX_ENTRIES {
            return Err("case note limit reached".to_owned());
        }
        case.notes.push(Note {
            text: text.to_owned(),
            recorded_at_unix: now,
        });
        Ok(())
    }

    /// # Errors
    /// Unknown case, unsafe URL, duplicate lead, or exceeded capacity.
    pub fn add_lead(
        &mut self,
        case_id: &str,
        lead_id: &str,
        url: &str,
        summary: &str,
        now: u64,
    ) -> Result<(), String> {
        if !valid(lead_id, 100) || !valid(summary, 1024) {
            return Err("invalid source lead".to_owned());
        }
        crate::osint_casework::validate_public_source_url(url)
            .map_err(|error| error.to_string())?;
        let case = self
            .cases
            .iter_mut()
            .find(|case| case.id == case_id)
            .ok_or_else(|| "unknown case".to_owned())?;
        if case.source_leads.len() >= MAX_ENTRIES
            || case.source_leads.iter().any(|lead| lead.id == lead_id)
        {
            return Err("duplicate source lead or limit reached".to_owned());
        }
        case.source_leads.push(SourceLead {
            id: lead_id.to_owned(),
            url: url.to_owned(),
            summary: summary.to_owned(),
            recorded_at_unix: now,
            evidence_status: "lead_only_unverified".to_owned(),
        });
        Ok(())
    }

    /// # Errors
    /// Unknown catalogue tool ID or excessive entries.
    pub fn remember_tool(&mut self, tool_id: &str, mode: &str) -> Result<(), String> {
        if crate::rhinser_catalog::Catalog::load()?
            .tool(tool_id)
            .is_none()
        {
            return Err("tool absent from catalogue".to_owned());
        }
        let list = match mode {
            "bookmark" => &mut self.bookmarks,
            "favourite" => &mut self.favourites,
            "recent" => &mut self.recent_tools,
            _ => return Err("unknown tool action".to_owned()),
        };
        list.retain(|id| id != tool_id);
        let limit = if mode == "recent" {
            MAX_RECENT
        } else {
            MAX_ENTRIES
        };
        if list.len() >= limit {
            list.remove(0);
        }
        list.push(tool_id.to_owned());
        Ok(())
    }

    /// # Errors
    /// Invalid or overly long search history.
    pub fn remember_search(&mut self, query: &str) -> Result<(), String> {
        if !valid(query, 1024) {
            return Err("invalid search query".to_owned());
        }
        self.search_history.retain(|saved| saved != query);
        if self.search_history.len() >= MAX_RECENT {
            self.search_history.remove(0);
        }
        self.search_history.push(query.to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_offline_case_and_source_lead_roundtrip() {
        let mut workspace = Workspace::default();
        workspace
            .create_case("case-1", "Australian records")
            .unwrap();
        workspace
            .add_note("case-1", "Check historical business name", 5)
            .unwrap();
        workspace
            .add_lead(
                "case-1",
                "ref-1",
                "https://abr.business.gov.au/",
                "Unverified link, not a fact",
                6,
            )
            .unwrap();
        workspace.remember_tool("t0343", "favourite").unwrap();
        workspace.remember_tool("t0343", "bookmark").unwrap();
        workspace.remember_tool("t0343", "recent").unwrap();
        workspace.remember_search("company").unwrap();
        let bytes = serde_json::to_vec(&workspace).unwrap();
        let restored = Workspace::from_json(&bytes).unwrap();
        assert_eq!(restored, workspace);
        assert_eq!(
            restored.cases[0].source_leads[0].evidence_status,
            "lead_only_unverified"
        );
        assert_eq!(restored.search_history, vec!["company"]);
    }

    #[test]
    fn rejects_untrusted_source_urls_and_duplicate_cases() {
        let mut workspace = Workspace::default();
        workspace.create_case("a", "title").unwrap();
        assert!(workspace.create_case("a", "again").is_err());
        assert!(
            workspace
                .add_lead("a", "b", "https://user:password@example.com/", "unsafe", 1)
                .is_err()
        );
        assert!(
            workspace
                .add_lead("a", "b", "https://example.com/?token=hidden", "unsafe", 1)
                .is_err()
        );
        assert!(workspace.add_note("missing", "note", 1).is_err());
        assert!(workspace.remember_tool("unknown", "favourite").is_err());
    }
}
