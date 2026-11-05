//! Local, deterministic OSINT workspace: cases, notes, source leads and tool history.
//! Nothing here fetches or verifies remote evidence. A source URL is a lead, not a fact.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::textnorm::is_bounded_text;

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

/// A reference URL repeated in multiple cases. Reuse is NOT independent corroboration.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SharedSourceUrl {
    pub url: String,
    pub case_ids: Vec<String>,
}

/// Deterministic, read-only cross-case index of operator-supplied source leads.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorkspaceOverlapReport {
    pub cases_considered: usize,
    pub source_leads_considered: usize,
    pub shared_source_urls: Vec<SharedSourceUrl>,
    pub evidence_status: &'static str,
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
            if !is_bounded_text(&case.id, 100)
                || !is_bounded_text(&case.title, 256)
                || !ids.insert(&case.id)
                || case.notes.len() > MAX_ENTRIES
                || case.source_leads.len() > MAX_ENTRIES
            {
                return Err("invalid or duplicate case".to_owned());
            }
            let mut leads = std::collections::BTreeSet::new();
            for lead in &case.source_leads {
                if !is_bounded_text(&lead.id, 100)
                    || !is_bounded_text(&lead.summary, 1024)
                    || !leads.insert(&lead.id)
                    || lead.evidence_status != "lead_only_unverified"
                    || crate::osint_casework::validate_public_source_url(&lead.url).is_err()
                {
                    return Err("invalid source lead".to_owned());
                }
            }
            if case
                .notes
                .iter()
                .any(|note| !is_bounded_text(&note.text, 4096))
            {
                return Err("invalid case note".to_owned());
            }
        }
        for id in self
            .bookmarks
            .iter()
            .chain(&self.favourites)
            .chain(&self.recent_tools)
        {
            if !is_bounded_text(id, 100) {
                return Err("invalid tool identifier".to_owned());
            }
        }
        if self
            .search_history
            .iter()
            .any(|text| !is_bounded_text(text, 1024))
            || self.settings.iter().any(|(key, value)| {
                !is_bounded_text(key, 100)
                    || value.len() > 4096
                    || value.chars().any(char::is_control)
            })
        {
            return Err("invalid history or setting".to_owned());
        }
        Ok(())
    }

    /// Discover exact source URLs reused across distinct cases, without network access.
    ///
    /// Source overlap identifies repeated leads, not independent witnesses or proven identities.
    /// No URL normalization or fuzzy matching is used, avoiding false equivalence.
    ///
    /// # Errors
    /// Rejects an invalid workspace before analyzing its references.
    pub fn source_overlaps(&self) -> Result<WorkspaceOverlapReport, String> {
        self.validate()?;
        let mut references: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut lead_count = 0usize;
        for case in &self.cases {
            for lead in &case.source_leads {
                lead_count += 1;
                references.entry(&lead.url).or_default().insert(&case.id);
            }
        }
        let shared_source_urls = references
            .into_iter()
            .filter(|(_, case_ids)| case_ids.len() > 1)
            .map(|(url, case_ids)| SharedSourceUrl {
                url: url.to_owned(),
                case_ids: case_ids.into_iter().map(str::to_owned).collect(),
            })
            .collect();
        Ok(WorkspaceOverlapReport {
            cases_considered: self.cases.len(),
            source_leads_considered: lead_count,
            shared_source_urls,
            evidence_status: "reused_unverified_leads_not_independent_corroboration",
        })
    }

    /// # Errors
    /// Empty, duplicate or excessive case identifiers.
    pub fn create_case(&mut self, id: &str, title: &str) -> Result<(), String> {
        if !is_bounded_text(id, 100) || !is_bounded_text(title, 256) {
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
        if !is_bounded_text(text, 4096) {
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
        if !is_bounded_text(lead_id, 100) || !is_bounded_text(summary, 1024) {
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
        if !is_bounded_text(query, 1024) {
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
    #[test]
    fn exact_cross_case_overlap_is_sorted_and_not_corroboration() {
        let mut workspace = Workspace::default();
        workspace.create_case("case-b", "Second").unwrap();
        workspace.create_case("case-a", "First").unwrap();
        workspace
            .add_lead("case-b", "a", "https://example.org/a", "Lead", 1)
            .unwrap();
        workspace
            .add_lead("case-b", "b", "https://example.org/a", "Same case", 2)
            .unwrap();
        workspace
            .add_lead("case-a", "c", "https://example.org/a", "Another case", 3)
            .unwrap();
        workspace
            .add_lead("case-a", "d", "https://example.org/b", "Different page", 4)
            .unwrap();
        let report = workspace.source_overlaps().unwrap();
        assert_eq!(report.cases_considered, 2);
        assert_eq!(report.source_leads_considered, 4);
        assert_eq!(report.shared_source_urls.len(), 1);
        assert_eq!(report.shared_source_urls[0].url, "https://example.org/a");
        assert_eq!(report.shared_source_urls[0].case_ids, ["case-a", "case-b"]);
        assert_eq!(
            report.evidence_status,
            "reused_unverified_leads_not_independent_corroboration"
        );
        assert_eq!(workspace.source_overlaps().unwrap(), report);
    }

    #[test]
    fn no_cross_case_overlap_for_same_host_or_same_case_only() {
        let mut workspace = Workspace::default();
        workspace.create_case("a", "A").unwrap();
        workspace.create_case("b", "B").unwrap();
        workspace
            .add_lead("a", "a1", "https://example.org/one", "Lead", 1)
            .unwrap();
        workspace
            .add_lead("a", "a2", "https://example.org/one", "Repeat", 1)
            .unwrap();
        workspace
            .add_lead("b", "b1", "https://example.org/two", "Lead", 1)
            .unwrap();
        assert!(
            workspace
                .source_overlaps()
                .unwrap()
                .shared_source_urls
                .is_empty()
        );
        workspace.cases[1].source_leads[0].evidence_status = "verified".to_owned();
        assert!(workspace.source_overlaps().is_err());
    }
}
