//! URL construction for the Proxycurl API endpoints.

use crate::core::scan::{Target, TargetKind};
use crate::util::http::urlencode;

/// The Proxycurl endpoint for a target, or `None` when the target can't address
/// a LinkedIn profile (so the module no-ops rather than spending a paid call).
pub(super) fn profile_url(target: &Target) -> Option<String> {
    match target.kind {
        TargetKind::Email => {
            let email = target.value.trim();
            email.contains('@').then(|| {
                format!(
                    "https://nubela.co/proxycurl/api/linkedin/profile/resolve/email?work_email={}",
                    urlencode(email),
                )
            })
        }
        TargetKind::Url => {
            let v = target.value.trim();
            v.to_lowercase()
                .contains("linkedin.com/in/")
                .then(|| linkedin_lookup_url(v))
        }
        TargetKind::Username => {
            let username = target.value.trim();
            (!username.is_empty() && username.len() <= 100)
                .then(|| linkedin_lookup_url(&format!("https://linkedin.com/in/{username}")))
        }
        _ => None,
    }
}

fn linkedin_lookup_url(linkedin_url: &str) -> String {
    format!(
        "https://nubela.co/proxycurl/api/v2/linkedin?url={}",
        urlencode(linkedin_url),
    )
}
