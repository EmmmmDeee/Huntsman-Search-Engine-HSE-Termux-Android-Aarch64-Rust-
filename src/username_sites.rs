//! Keyless multi-site username presence checks.
//!
//! Checks a curated set of public profile endpoints for the existence of a username.
//! Each site that confirms the username emits a Username entity with the profile URL
//! and retains the full raw answer. A site that returns a documented miss is a valid zero
//! for that site; a transport or decode failure is recorded as an outcome, not swallowed.
//! No keys are required.
//!
//! Wired into `username_cli` alongside the existing GitHub and Bluesky collectors.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::http::Transport;
use crate::keys::Keys;
use crate::source_outcome::SourceExecutionOutcome;

pub const SOURCE: &str = "username_sites";

/// One public site that answers for a username.
struct Site {
    name: &'static str,
    origin: &'static str,
    /// Builds the request URL for `username`.
    url: fn(&str) -> String,
    /// Returns true when the body confirms the username exists.
    exists: fn(&[u8]) -> bool,
}

fn gitlab_url(username: &str) -> String {
    format!("https://gitlab.com/api/v4/users?username={username}")
}

fn keybase_url(username: &str) -> String {
    format!("https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}")
}

const SITES: &[Site] = &[
    Site {
        name: "gitlab",
        origin: "https://gitlab.com:443",
        url: gitlab_url,
        exists: |body| {
            let users: Vec<serde_json::Value> = serde_json::from_slice(body).unwrap_or_default();
            !users.is_empty()
        },
    },
    Site {
        name: "keybase",
        origin: "https://keybase.io:443",
        url: keybase_url,
        exists: |body| {
            #[derive(Deserialize)]
            struct Them {
                #[serde(default)]
                them: Vec<serde_json::Value>,
            }
            serde_json::from_slice::<Them>(body)
                .map(|t| !t.them.is_empty())
                .unwrap_or(false)
        },
    },
];

/// What one site reported about a username.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub site: &'static str,
    pub profile_url: String,
    pub raw: String,
}

/// Look the username up on every site. Returns the hits that confirmed existence.
/// A site that fails is skipped; the first transport error aborts the rest.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    now_unix: u64,
) -> Result<Vec<Hit>, LegError> {
    let mut hits = Vec::new();
    for site in SITES {
        let api = Api {
            source: SOURCE,
            provider: site.name,
            origin: site.origin,
            key: None,
        };
        let url = (site.url)(username);
        match api_leg::get(transport, &api, &Keys::default(), &url, now_unix) {
            Ok(Answer::Body(body)) if (site.exists)(&body) => {
                let raw = String::from_utf8_lossy(&body).into_owned();
                hits.push(Hit {
                    site: site.name,
                    profile_url: url,
                    raw,
                });
            }
            Ok(_) => {}
            Err(LegError::NotAnAnswer(_)) | Err(LegError::Unexpected(_)) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(hits)
}

/// Fold hits into entities for the username scan.
pub fn entities(hits: &[Hit], username: &str, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    for hit in hits {
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan(SOURCE, scan_id),
            format!("{} profile exists for {}", hit.site, username),
        )
        .with_attr("site", hit.site)
        .with_attr("profile_url", &hit.profile_url)
        .with_attr("raw_answer", &hit.raw);
        push_entity(
            &mut entities,
            EntityKind::Username,
            username,
            0.80,
            scan_id,
            evidence,
            &[hit.site, "public-profile"],
        );
    }
    entities
}

/// Outcome for the sites check.
pub fn outcome(hits: &[Hit], now_unix: u64) -> SourceExecutionOutcome {
    if hits.is_empty() {
        SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
    } else {
        SourceExecutionOutcome::success(SOURCE, now_unix, hits.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Request, Response, TransportFailure};
    use crate::source_outcome::SourceOutcomeKind;
    use std::sync::Mutex;

    struct Fake {
        replies: Mutex<Vec<Result<Response, TransportFailure>>>,
    }

    impl Transport for Fake {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            self.replies
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(Err(TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "empty".into(),
                    blocked: false,
                }))
        }
    }

    #[test]
    fn gitlab_hit_is_kept_and_keybase_miss_is_zero() {
        let fake = Fake {
            replies: Mutex::new(vec![
                Ok(Response {
                    status: 200,
                    headers: Vec::new(),
                    body: br#"[{"id":1,"username":"octocat"}]"#.to_vec(),
                    truncated: false,
                }),
                Ok(Response {
                    status: 200,
                    headers: Vec::new(),
                    body: br#"{"them":[]}"#.to_vec(),
                    truncated: false,
                }),
            ]),
        };
        let hits = lookup(&fake, "octocat", 1).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].site, "gitlab");
        assert!(hits[0].raw.contains("octocat"));
    }
}
