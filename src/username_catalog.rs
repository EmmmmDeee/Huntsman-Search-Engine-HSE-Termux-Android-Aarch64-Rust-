//! Fail-closed, offline catalogue contract for imported username-site definitions.
//!
//! This is a pure validation/interpretation layer, not a network client. The existing
//! guarded fetch/egress boundary remains the only place allowed to make requests.
//! An HTML result is merely a candidate until distinct negative controls, including
//! a same-length control, have explicitly demonstrated account absence. An exact
//! JSON identifier is evidence of account existence, never ownership of a person.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_CATALOGUE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SITES: usize = 20_000;
const MAX_TEMPLATE_BYTES: usize = 2048;
const MAX_MARKER_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteDefinition {
    pub id: String,
    pub url_template: String,
    pub detection: Detection,
}

/// Status-only detection is deliberately unsupported: HTTP 200 does not prove
/// a username exists. HTML matching cannot confirm a profile without controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Detection {
    JsonExact { pointer: String },
    HtmlMarkers { present: String, absent: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeObservation {
    /// A valid JSON account document explicitly names the exact requested handle.
    ExactAccount,
    /// An HTML page contains a site-specific positive marker and the handle.
    Candidate,
    /// An HTML page contains a site-specific explicit not-found marker.
    Absent,
    /// Missing, blocked, malformed, ambiguous or incomplete response.
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountVerdict {
    Exists,
    Absent,
    Unconfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlObservation {
    pub username: String,
    pub observation: ProbeObservation,
}

/// Parse a bounded, immutable catalogue with stable ordering and unique IDs.
///
/// # Errors
/// Invalid JSON, unsupported detectors, excessive inputs or unsafe templates.
pub fn parse_catalogue(bytes: &[u8]) -> Result<Vec<SiteDefinition>, String> {
    if bytes.len() > MAX_CATALOGUE_BYTES {
        return Err("catalogue exceeds byte budget".into());
    }
    let mut sites: Vec<SiteDefinition> =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid catalogue: {error}"))?;
    if sites.len() > MAX_SITES {
        return Err("catalogue exceeds site budget".into());
    }
    let mut ids = BTreeSet::new();
    for site in &sites {
        site.validate()?;
        if !ids.insert(site.id.as_str()) {
            return Err(format!("duplicate catalogue id: {}", site.id));
        }
    }
    sites.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(sites)
}

impl SiteDefinition {
    /// Validate only static syntax. The existing egress policy MUST additionally
    /// authorize DNS answers, target addresses and every redirect at request time.
    ///
    /// # Errors
    /// Rejects non-HTTPS, credentials, IP literals, invalid hostnames, unresolved
    /// placeholders, bare status rules and weak detection markers.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.len() < 2
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        {
            return Err("invalid source id".into());
        }
        let template = self.url_template.as_str();
        if template.len() > MAX_TEMPLATE_BYTES
            || !template.starts_with("https://")
            || template.matches("{username}").count() != 1
            || template.contains('#')
            || !template
                .bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'\\' | b'<' | b'>'))
        {
            return Err(format!("invalid URL template for {}", self.id));
        }
        let without_placeholder = template.replace("{username}", "");
        if without_placeholder
            .bytes()
            .any(|b| matches!(b, b'{' | b'}'))
        {
            return Err(format!("unresolved placeholder for {}", self.id));
        }
        let authority = template["https://".len()..]
            .split(['/', '?'])
            .next()
            .unwrap_or("");
        // Credentials, explicit ports, private literals and non-DNS names do not
        // belong in external catalogue definitions. Runtime egress still applies.
        let labels: Vec<&str> = authority.split('.').collect();
        if authority
            .bytes()
            .any(|b| matches!(b, b'@' | b':' | b'[' | b']'))
            || labels.len() < 2
            || labels.iter().any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            || labels
                .last()
                .is_none_or(|label| label.len() < 2 || label.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(format!("invalid catalogue host for {}", self.id));
        }
        match &self.detection {
            Detection::JsonExact { pointer } => {
                if pointer.len() < 2
                    || pointer.len() > 96
                    || !pointer.starts_with('/')
                    || pointer.split('/').skip(1).any(|segment| {
                        segment.is_empty()
                            || !segment
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                    })
                {
                    return Err(format!("invalid JSON identity pointer for {}", self.id));
                }
            }
            Detection::HtmlMarkers { present, absent } => {
                if present.len() < 8
                    || absent.len() < 8
                    || present.len() > MAX_MARKER_BYTES
                    || absent.len() > MAX_MARKER_BYTES
                    || present == absent
                    || !present.is_ascii()
                    || !absent.is_ascii()
                {
                    return Err(format!("invalid HTML markers for {}", self.id));
                }
            }
        }
        Ok(())
    }

    /// Render only handles that are safe as a URL path or query component.
    /// No other field of an imported definition may interpolate user input.
    #[must_use]
    pub fn url_for(&self, username: &str) -> Option<String> {
        (self.validate().is_ok()
            && !username.is_empty()
            && username.len() <= 64
            && username != "."
            && username != ".."
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')))
        .then(|| self.url_template.replace("{username}", username))
    }

    /// Interpret a bounded response, without guessing from HTTP success alone.
    #[must_use]
    pub fn observe(
        &self,
        username: &str,
        http_status: u16,
        body: &[u8],
        truncated: bool,
    ) -> ProbeObservation {
        if self.validate().is_err() || username.is_empty() || truncated || body.len() > 512 * 1024 {
            return ProbeObservation::Inconclusive;
        }
        match &self.detection {
            Detection::JsonExact { pointer } => {
                if http_status != 200 {
                    return ProbeObservation::Inconclusive;
                }
                serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|value| {
                        value
                            .pointer(pointer)
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .filter(|actual| actual == username)
                    .map_or(ProbeObservation::Inconclusive, |_| {
                        ProbeObservation::ExactAccount
                    })
            }
            Detection::HtmlMarkers { present, absent } => {
                if http_status != 200 && http_status != 404 {
                    return ProbeObservation::Inconclusive;
                }
                let Ok(html) = std::str::from_utf8(body) else {
                    return ProbeObservation::Inconclusive;
                };
                let has_present = html.contains(present);
                let has_absent = html.contains(absent);
                if has_present
                    && !has_absent
                    && http_status == 200
                    && contains_exact_handle(html, username)
                {
                    ProbeObservation::Candidate
                } else if has_absent && !has_present {
                    ProbeObservation::Absent
                } else {
                    ProbeObservation::Inconclusive
                }
            }
        }
    }
}

/// A handle must appear as its own token, not merely inside a longer account name.
/// This is still only candidate evidence: controls must also agree.
fn contains_exact_handle(page: &str, username: &str) -> bool {
    if username.is_empty() {
        return false;
    }
    page.match_indices(username).any(|(offset, _)| {
        let before = page.as_bytes().get(offset.wrapping_sub(1)).copied();
        let after = page.as_bytes().get(offset + username.len()).copied();
        let member = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.');
        (offset == 0 || before.is_none_or(|b| !member(b))) && after.is_none_or(|b| !member(b))
    })
}

/// Check same-length shape, prefix numbers and punctuation that can alter
/// endpoint routing. A mismatched control cannot establish absence for this name.
fn matches_shape(username: &str, control: &str) -> bool {
    if username.len() != control.len() {
        return false;
    }
    let prefix_len = username.bytes().take_while(u8::is_ascii_digit).count();
    username.as_bytes()[..prefix_len] == control.as_bytes()[..prefix_len]
        && username
            .bytes()
            .zip(control.bytes())
            .all(|(left, right)| !matches!(left, b'.' | b'-' | b'_') || left == right)
}

/// Final account-existence verdict. Exact-identity API documents do not need
/// synthetic controls. HTML candidates require at least three distinct explicit
/// negative controls, including a same-length control. A control that exists,
/// times out, or receives a challenge leaves the candidate UNCONFIRMED.
///
/// This verdict never asserts that the account belongs to the investigated person.
#[must_use]
pub fn verdict(
    username: &str,
    observation: ProbeObservation,
    controls: &[ControlObservation],
) -> AccountVerdict {
    match observation {
        ProbeObservation::ExactAccount => AccountVerdict::Exists,
        ProbeObservation::Absent => AccountVerdict::Absent,
        ProbeObservation::Inconclusive => AccountVerdict::Unconfirmed,
        ProbeObservation::Candidate => {
            let mut unique = BTreeSet::new();
            let mut same_shape = false;
            for control in controls {
                if control.username == username
                    || control.username.is_empty()
                    || control.observation != ProbeObservation::Absent
                    || !unique.insert(control.username.as_str())
                {
                    return AccountVerdict::Unconfirmed;
                }
                same_shape |= matches_shape(username, &control.username);
            }
            if unique.len() >= 3 && same_shape {
                AccountVerdict::Exists
            } else {
                AccountVerdict::Unconfirmed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html_site() -> SiteDefinition {
        SiteDefinition {
            id: "example_site".into(),
            url_template: "https://users.example.org/u/{username}".into(),
            detection: Detection::HtmlMarkers {
                present: "account-profile-header".into(),
                absent: "no-such-account-here".into(),
            },
        }
    }

    #[test]
    fn rejects_unsafe_and_ambiguous_catalogues() {
        for template in [
            "http://users.example.org/u/{username}",
            "https://127.0.0.1/u/{username}",
            "https://user:secret@users.example.org/u/{username}",
            "https://users.example.org/u/{username}/{other}",
            "https://users.example.org/u/{username}#ignored",
            "https://localhost/u/{username}",
        ] {
            let mut site = html_site();
            site.url_template = template.into();
            assert!(site.validate().is_err(), "{template}");
        }
        assert!(parse_catalogue(br#"[{"id":"a","url_template":"https://x.test/{username}","detection":{"kind":"http_status"}}]"#).is_err());
    }

    #[test]
    fn validates_sorts_and_rejects_duplicate_ids() {
        let mut second = html_site();
        second.id = "zeta".into();
        let mut first = html_site();
        first.id = "alpha".into();
        let data = serde_json::to_vec(&vec![second.clone(), first.clone()]).unwrap();
        assert_eq!(parse_catalogue(&data).unwrap(), vec![first.clone(), second]);
        let duplicates = serde_json::to_vec(&vec![first.clone(), first]).unwrap();
        assert!(parse_catalogue(&duplicates).is_err());
        assert!(parse_catalogue(&vec![b' '; MAX_CATALOGUE_BYTES + 1]).is_err());
    }

    #[test]
    fn exact_json_identifier_is_account_only() {
        let site = SiteDefinition {
            id: "identity_api".into(),
            url_template: "https://api.example.org/users/{username}".into(),
            detection: Detection::JsonExact {
                pointer: "/user/login".into(),
            },
        };
        let body = br#"{"user":{"login":"jack"}}"#;
        assert_eq!(
            site.observe("jack", 200, body, false),
            ProbeObservation::ExactAccount
        );
        assert_eq!(
            site.observe("jane", 200, body, false),
            ProbeObservation::Inconclusive
        );
        assert_eq!(
            site.observe("jack", 429, body, false),
            ProbeObservation::Inconclusive
        );
        assert_eq!(
            site.observe("jack", 200, body, true),
            ProbeObservation::Inconclusive
        );
        assert_eq!(
            verdict("jack", ProbeObservation::ExactAccount, &[]),
            AccountVerdict::Exists
        );
    }

    #[test]
    fn html_candidates_need_three_distinct_controls_with_matching_length() {
        let site = html_site();
        let page = b"<h1>account-profile-header jack</h1>";
        assert_eq!(
            site.observe("jack", 200, page, false),
            ProbeObservation::Candidate
        );
        let controls =
            ["xxxx", "zzzzzzzzzzzz", "yyyyyyyyyyyy"].map(|username| ControlObservation {
                username: username.into(),
                observation: ProbeObservation::Absent,
            });
        assert_eq!(
            verdict("jack", ProbeObservation::Candidate, &controls),
            AccountVerdict::Exists
        );
        let long_only = ["xxxxxxxx", "yyyyyyyy", "zzzzzzzz"].map(|username| ControlObservation {
            username: username.into(),
            observation: ProbeObservation::Absent,
        });
        assert_eq!(
            verdict("jack", ProbeObservation::Candidate, &long_only),
            AccountVerdict::Unconfirmed
        );
        let mut blocked = controls.clone();
        blocked[0].observation = ProbeObservation::Inconclusive;
        assert_eq!(
            verdict("jack", ProbeObservation::Candidate, &blocked),
            AccountVerdict::Unconfirmed
        );
        let mut repeated = controls.clone();
        repeated[1].username = repeated[0].username.clone();
        assert_eq!(
            verdict("jack", ProbeObservation::Candidate, &repeated),
            AccountVerdict::Unconfirmed
        );
        assert_eq!(
            verdict("jack", ProbeObservation::Candidate, &controls[..2]),
            AccountVerdict::Unconfirmed
        );
        let prefixed = ["4xxx", "4yyy", "4zzz"].map(|username| ControlObservation {
            username: username.into(),
            observation: ProbeObservation::Absent,
        });
        assert_eq!(
            verdict("4abc", ProbeObservation::Candidate, &prefixed),
            AccountVerdict::Exists
        );
        let wrong_prefix = ["1xxx", "2yyy", "3zzz"].map(|username| ControlObservation {
            username: username.into(),
            observation: ProbeObservation::Absent,
        });
        assert_eq!(
            verdict("4abc", ProbeObservation::Candidate, &wrong_prefix),
            AccountVerdict::Unconfirmed
        );
    }

    #[test]
    fn no_generic_title_or_soft_404_becomes_an_account() {
        let site = html_site();
        assert_eq!(
            site.observe("jack", 200, b"<h1>account-profile-header</h1>", false),
            ProbeObservation::Inconclusive
        );
        assert_eq!(
            site.observe("jack", 200, b"no-such-account-here", false),
            ProbeObservation::Absent
        );
        assert_eq!(
            site.observe(
                "jack",
                200,
                b"account-profile-header jack no-such-account-here",
                false
            ),
            ProbeObservation::Inconclusive
        );
        assert_eq!(
            site.observe("jack", 403, b"account-profile-header jack", false),
            ProbeObservation::Inconclusive
        );
        assert_eq!(
            site.url_for("jack"),
            Some("https://users.example.org/u/jack".into())
        );
        assert_eq!(site.url_for("../private"), None);
        assert_eq!(site.url_for(".."), None);
        assert_eq!(
            site.observe("jack", 200, b"account-profile-header jackie", false),
            ProbeObservation::Inconclusive
        );
    }
}
