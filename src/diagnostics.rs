//! Offline operational diagnostics and build provenance.
//!
//! This module composes already-typed repository state. It opens no sockets and
//! never carries credential values, fingerprints, paths, or raw resolver errors
//! into its report.

use serde::Serialize;

use crate::keys::Keys;
use crate::module::reachable_modules;
use crate::provider_credentials;

const RAW_BUILD_SHA: &str = match option_env!("HUNTSMAN_BUILD_SHA") {
    Some(value) => value,
    None => "unknown",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialResolution {
    Ok,
    Warning,
    Error,
}

impl CredentialResolution {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostics {
    pub version: &'static str,
    pub build_sha: &'static str,
    pub build_sha_known: bool,
    pub target_os: &'static str,
    pub target_arch: &'static str,
    pub android_target: bool,
    pub termux_detected: bool,
    pub reachable_modules: usize,
    pub network_modules: usize,
    pub attack_mapped_modules: usize,
    pub providers_total: usize,
    pub providers_configured: usize,
    pub credential_resolution: CredentialResolution,
    pub credential_warning: bool,
    pub selfcheck_command: &'static str,
}

#[must_use]
pub fn normalized_build_sha(value: &str) -> &str {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        value
    } else {
        "unknown"
    }
}

#[must_use]
pub fn embedded_build_sha() -> &'static str {
    normalized_build_sha(RAW_BUILD_SHA)
}

/// Compose a non-sensitive, offline diagnostic snapshot.
///
/// The keys input may be absent when credential resolution itself failed. Only
/// provider completeness counts are retained; credential material never enters
/// the returned value.
#[must_use]
pub fn snapshot(
    keys: Option<&Keys>,
    credential_resolution: CredentialResolution,
    termux_detected: bool,
) -> Diagnostics {
    let modules = reachable_modules();
    let network_modules = modules.iter().filter(|module| module.network).count();
    let attack_mapped_modules = modules
        .iter()
        .filter(|module| !module.attack_techniques.is_empty())
        .count();
    let providers_configured = keys.map_or(0, |keys| {
        provider_credentials::status(keys)
            .into_iter()
            .filter(|provider| provider.configured)
            .count()
    });
    let build_sha = embedded_build_sha();

    Diagnostics {
        version: env!("CARGO_PKG_VERSION"),
        build_sha,
        build_sha_known: build_sha != "unknown",
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        android_target: cfg!(target_os = "android"),
        termux_detected,
        reachable_modules: modules.len(),
        network_modules,
        attack_mapped_modules,
        providers_total: provider_credentials::PROVIDERS.len(),
        providers_configured,
        credential_resolution,
        credential_warning: credential_resolution == CredentialResolution::Warning,
        selfcheck_command: "huntsman-recon check",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sha_accepts_only_canonical_lowercase_git_hashes() {
        let valid = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(normalized_build_sha(valid), valid);
        for invalid in [
            "",
            "unknown",
            "0123456789abcdef",
            "0123456789abcdef0123456789abcdef012345678",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            "g123456789abcdef0123456789abcdef01234567",
        ] {
            assert_eq!(normalized_build_sha(invalid), "unknown", "{invalid:?}");
        }
    }

    #[test]
    fn snapshot_counts_are_bounded_and_secret_free() {
        let secret = "diagnostics-test-secret-value-12345";
        let keys = Keys::parse(&format!("HUNTSMAN_BRAVE_KEY={secret}\n")).expect("keys");
        let report = snapshot(Some(&keys), CredentialResolution::Ok, false);
        assert!(report.reachable_modules > 0);
        assert!(report.network_modules <= report.reachable_modules);
        assert!(report.attack_mapped_modules <= report.network_modules);
        assert!(report.providers_configured <= report.providers_total);
        let json = serde_json::to_string(&report).expect("serialize diagnostics");
        assert!(!json.contains(secret));
        assert!(!json.contains("fingerprint"));
        assert!(!json.contains("HUNTSMAN_BRAVE_KEY"));
    }

    #[test]
    fn credential_resolution_error_carries_no_keys() {
        let report = snapshot(None, CredentialResolution::Error, false);
        assert_eq!(report.providers_configured, 0);
        assert_eq!(report.credential_resolution, CredentialResolution::Error);
        assert!(!report.credential_warning);
    }
}
