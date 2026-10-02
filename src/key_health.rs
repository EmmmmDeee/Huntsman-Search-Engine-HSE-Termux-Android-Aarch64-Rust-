//! Observed provider-key health from aggregated source outcomes.

use std::fmt::Write as _;

use crate::scraper_health::SourceHealth;
use crate::service_defs::{looks_like_auth_failure_text, service_defs};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAuthIssue {
    pub module: String,
    pub consecutive_failures: u32,
    pub detail: String,
    pub likely_env_var: Option<&'static str>,
}

impl KeyAuthIssue {
    #[must_use]
    pub fn detail_capped(&self, max_chars: usize) -> String {
        let mut chars = self.detail.chars();
        let mut out: String = chars.by_ref().take(max_chars).collect();
        let remainder = chars.count();
        if remainder > 0 {
            let _ = write!(out, "…(+{remainder} more chars)");
        }
        out
    }
}

#[must_use]
pub fn looks_like_auth_failure(message: &str) -> bool {
    looks_like_auth_failure_text(message)
}

#[must_use]
pub fn auth_failing_sources(health: &[SourceHealth]) -> Vec<KeyAuthIssue> {
    let mut issues: Vec<KeyAuthIssue> = health
        .iter()
        .filter(|source| source.is_drifted())
        .filter_map(|source| {
            let detail = source.last_error.as_deref()?;
            if !looks_like_auth_failure(detail) {
                return None;
            }
            Some(KeyAuthIssue {
                module: source.module.clone(),
                consecutive_failures: source.consecutive_failures,
                detail: detail.to_string(),
                likely_env_var: likely_env_var(&source.module),
            })
        })
        .collect();
    issues.sort_by(|left, right| {
        right
            .consecutive_failures
            .cmp(&left.consecutive_failures)
            .then_with(|| left.module.cmp(&right.module))
    });
    issues
}

#[must_use]
fn likely_env_var(module: &str) -> Option<&'static str> {
    let defs = service_defs();
    if let Some(service) = defs.iter().find(|service| service.name == module) {
        return Some(service.env_var);
    }
    defs.iter()
        .find(|service| module.starts_with(service.name) || service.name.starts_with(module))
        .map(|service| service.env_var)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(module: &str, failures: u32, error: Option<&str>) -> SourceHealth {
        SourceHealth {
            module: module.to_string(),
            last_success_at: None,
            consecutive_failures: failures,
            last_error: error.map(str::to_string),
            ever_yielded: false,
            consecutive_zero_yield: 0,
            newest_event_at: 0,
        }
    }

    #[test]
    fn recognises_real_auth_failures_only() {
        assert!(looks_like_auth_failure(
            "[onyphe] HTTP 400 Bad Request: {\"status\":\"nok\",\"text\":\"Invalid API key format\"}"
        ));
        assert!(looks_like_auth_failure(
            "[hunter_io] HTTP 401 Unauthorized: authentication_failed"
        ));
        assert!(!looks_like_auth_failure("timeout"));
        assert!(!looks_like_auth_failure("HTTP 500 Internal Server Error"));
    }

    #[test]
    fn diagnoses_drifted_auth_failures_and_resolves_env_vars() {
        let issues = auth_failing_sources(&[
            health("onyphe", 21, Some("HTTP 400: Invalid API key format")),
            health(
                "hunter_io",
                20,
                Some("HTTP 401 Unauthorized: authentication_failed"),
            ),
            health("crtsh", 3, Some("timeout")),
            health("shodan", 1, Some("HTTP 401 Unauthorized")),
        ]);
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].module, "onyphe");
        assert_eq!(issues[0].likely_env_var, Some("HUNTSMAN_ONYPHE_KEY"));
        assert_eq!(issues[1].likely_env_var, Some("HUNTSMAN_HUNTER_KEY"));
    }

    #[test]
    fn dehashed_health_maps_to_registered_env_var() {
        let issues = auth_failing_sources(&[health(
            "dehashed",
            30,
            Some("HTTP 403 Forbidden: { \"error\": \"Issue with API Key\" }"),
        )]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].likely_env_var, Some("HUNTSMAN_DEHASHED_KEY"));
    }

    #[test]
    fn capped_detail_discloses_truncation() {
        let issue = KeyAuthIssue {
            module: "onyphe".to_string(),
            consecutive_failures: 3,
            detail: "é".repeat(250),
            likely_env_var: Some("HUNTSMAN_ONYPHE_KEY"),
        };
        let capped = issue.detail_capped(200);
        assert!(capped.starts_with(&"é".repeat(200)));
        assert!(capped.contains("…(+50 more chars)"));
    }
}
