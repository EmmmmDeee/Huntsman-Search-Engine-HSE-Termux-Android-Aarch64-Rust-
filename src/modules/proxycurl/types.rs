//! Serde-deserializable types for the Proxycurl / LinkedIn API response.

use serde::Deserialize;

use crate::util::str_util::nonempty;

#[derive(Deserialize)]
pub(super) struct LinkedInProfile {
    #[serde(default)]
    pub(super) full_name: Option<String>,
    #[serde(default)]
    pub(super) first_name: Option<String>,
    #[serde(default)]
    pub(super) last_name: Option<String>,
    #[serde(default)]
    pub(super) headline: Option<String>,
    #[serde(default)]
    pub(super) summary: Option<String>,
    #[serde(default)]
    pub(super) city: Option<String>,
    #[serde(default)]
    pub(super) state: Option<String>,
    #[serde(default)]
    pub(super) country_full_name: Option<String>,
    #[serde(default)]
    pub(super) country: Option<String>,
    #[serde(default)]
    pub(super) occupation: Option<String>,
    #[serde(default)]
    pub(super) public_identifier: Option<String>,
    #[serde(default)]
    pub(super) connections: Option<u64>,
    #[serde(default)]
    pub(super) experiences: Vec<Experience>,
    #[serde(default)]
    pub(super) education: Vec<Education>,
    #[serde(default)]
    pub(super) personal_emails: Vec<String>,
    #[serde(default)]
    pub(super) personal_numbers: Vec<String>,
}

impl LinkedInProfile {
    /// Best display name: prefer `full_name`, else compose `first`+`last`, else
    /// whichever single part exists. The email-resolve endpoint frequently
    /// returns only `first_name`/`last_name`, so the fallback is what makes that
    /// path yield a `Person` at all. `None` when no usable name is present.
    pub(super) fn display_name(&self) -> Option<String> {
        if let Some(n) = nonempty(&self.full_name).filter(|s| s.chars().count() >= 2) {
            return Some(n.to_string());
        }
        match (nonempty(&self.first_name), nonempty(&self.last_name)) {
            (Some(f), Some(l)) => Some(format!("{f} {l}")),
            (Some(s), None) | (None, Some(s)) => Some(s.to_string()),
            (None, None) => None,
        }
    }
}

#[derive(Deserialize)]
pub(super) struct Experience {
    #[serde(default)]
    pub(super) company: Option<String>,
    #[serde(default)]
    pub(super) title: Option<String>,
    #[serde(default)]
    pub(super) starts_at: Option<DateField>,
    #[serde(default)]
    pub(super) ends_at: Option<DateField>,
    #[serde(default)]
    pub(super) location: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct Education {
    #[serde(default)]
    pub(super) school: Option<String>,
    #[serde(default)]
    pub(super) degree_name: Option<String>,
    #[serde(default)]
    pub(super) field_of_study: Option<String>,
}

impl Education {
    /// `"School — Degree, Field"` (whichever parts are present), or `None` when
    /// there is no school to anchor the entry.
    pub(super) fn describe(&self) -> Option<String> {
        let school = nonempty(&self.school)?;
        let detail: Vec<&str> = [nonempty(&self.degree_name), nonempty(&self.field_of_study)]
            .into_iter()
            .flatten()
            .collect();
        Some(if detail.is_empty() {
            school.to_string()
        } else {
            format!("{school} — {}", detail.join(", "))
        })
    }
}

#[derive(Deserialize)]
pub(super) struct DateField {
    #[serde(default)]
    pub(super) year: Option<u32>,
    #[serde(default)]
    pub(super) month: Option<u32>,
}

impl DateField {
    pub(super) fn to_string_approx(&self) -> String {
        match (self.year, self.month) {
            (Some(y), Some(m)) => format!("{y}-{m:02}"),
            (Some(y), None) => y.to_string(),
            _ => String::new(),
        }
    }
}
