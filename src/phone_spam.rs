//! Keyless phone spam / reputation checks against public endpoints.
//!
//! Queries public spam databases that answer for a phone number without a key.
//! A hit emits evidence on the phone entity with the full raw answer retained.
//! Documented "not found" responses are valid zeros.
//!
//! Integrated into `phone_cli` when the transport asks for the module.

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::Transport;
use crate::keys::Keys;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "phone_spam";
pub const API: Api = Api {
    source: SOURCE,
    provider: "phone_spam",
    origin: "https://phone_spam.local:443",
    key: None,
};

/// One public spam source.
struct Source {
    name: &'static str,
    url: fn(&str) -> String,
    /// True when the body indicates the number is listed.
    listed: fn(&[u8]) -> bool,
}

fn stopforumspam_url(phone: &str) -> String {
    format!("https://api.stopforumspam.org/api?json&phone={phone}")
}

const SOURCES: &[Source] = &[Source {
    name: "stopforumspam",
    url: stopforumspam_url,
    listed: |body| {
        let value: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
        value
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            && value
                .pointer("/phone/appears")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
    },
}];

/// What one source reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub source: &'static str,
    pub listed: bool,
    pub raw: String,
}

/// Check the phone against every source.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    phone: &str,
    now_unix: u64,
) -> Result<Vec<Report>, LegError> {
    let mut reports = Vec::new();
    for source in SOURCES {
        let url = (source.url)(phone);
        match api_leg::get(transport, &API, &Keys::default(), &url, now_unix) {
            Ok(Answer::Body(body)) => {
                let listed = (source.listed)(&body);
                let raw = String::from_utf8_lossy(&body).into_owned();
                reports.push(Report {
                    source: source.name,
                    listed,
                    raw,
                });
            }
            Ok(Answer::NotFound(_)) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(reports)
}

/// Outcome for the spam checks.
pub fn outcome(reports: &[Report], now_unix: u64) -> SourceExecutionOutcome {
    let listed = reports.iter().filter(|r| r.listed).count();
    if listed == 0 {
        SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
    } else {
        SourceExecutionOutcome::success(SOURCE, now_unix, listed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Request, Response, TransportFailure};
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
    fn a_listed_number_is_reported() {
        let fake = Fake {
            replies: Mutex::new(vec![Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: br#"{"success":1,"phone":{"appears":1,"frequency":5}}"#.to_vec(),
                truncated: false,
            })]),
        };
        let reports = lookup(&fake, "+14155552671", 1).unwrap();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].listed);
        assert!(reports[0].raw.contains("appears"));
    }
}
