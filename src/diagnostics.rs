//! Offline operational diagnostics and build provenance.
//!
//! This module composes already-typed repository state. It opens no sockets and
//! never carries credential values, fingerprints, paths, or raw resolver errors
//! into its report.

use std::ffi::OsStr;
use std::path::Path;

use serde::Serialize;

use crate::environment;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TermuxState {
    Detected,
    NotDetected,
}

/// The Termux app's data directory. Its install prefix, `files/usr`, lies under it.
pub(crate) const TERMUX_APP_DATA: &str = "/data/data/com.termux";

impl TermuxState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::NotDetected => "not_detected",
        }
    }

    /// Termux, as `TERMUX_VERSION` and `PREFIX` show it: the app exports `TERMUX_VERSION` in every
    /// shell it starts, and its prefix lies under `/data/data/com.termux`. The prefix is compared by
    /// path component, so another app's directory such as `/data/data/com.termux.nix` is not Termux.
    #[must_use]
    pub fn from_values(termux_version: Option<&OsStr>, prefix: Option<&OsStr>) -> Self {
        if termux_version.is_some()
            || prefix.is_some_and(|prefix| Path::new(prefix).starts_with(TERMUX_APP_DATA))
        {
            Self::Detected
        } else {
            Self::NotDetected
        }
    }

    /// Termux, as this process's environment shows it.
    #[must_use]
    pub fn current() -> Self {
        Self::from_values(
            environment::termux_version().as_deref(),
            environment::prefix().as_deref(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostics {
    pub version: &'static str,
    pub build_sha: &'static str,
    pub target_os: &'static str,
    pub target_arch: &'static str,
    pub termux: TermuxState,
    pub reachable_modules: usize,
    pub network_modules: usize,
    pub attack_mapped_modules: usize,
    pub providers_total: usize,
    pub providers_configured: usize,
    pub credential_resolution: CredentialResolution,
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
    termux: TermuxState,
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
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        termux,
        reachable_modules: modules.len(),
        network_modules,
        attack_mapped_modules,
        providers_total: provider_credentials::PROVIDERS.len(),
        providers_configured,
        credential_resolution,
        selfcheck_command: "huntsman-recon check",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termux_is_its_version_variable_or_a_prefix_under_its_app_data() {
        let state = |version: Option<&str>, prefix: Option<&str>| {
            TermuxState::from_values(version.map(OsStr::new), prefix.map(OsStr::new))
        };
        assert_eq!(state(Some("0.118.3"), None), TermuxState::Detected);
        assert_eq!(state(Some(""), Some("/usr")), TermuxState::Detected);
        for prefix in [
            "/data/data/com.termux/files/usr",
            "/data/data/com.termux/files/usr/",
            "/data/data/com.termux",
        ] {
            assert_eq!(state(None, Some(prefix)), TermuxState::Detected, "{prefix}");
        }
        for prefix in [
            "/usr",
            "",
            "/data/data/com.termux.nix/files/usr",
            "/home/user/data/data/com.termux/files/usr",
            "data/data/com.termux/files/usr",
        ] {
            assert_eq!(
                state(None, Some(prefix)),
                TermuxState::NotDetected,
                "{prefix}"
            );
        }
        assert_eq!(state(None, None), TermuxState::NotDetected);
    }

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
        let report = snapshot(
            Some(&keys),
            CredentialResolution::Ok,
            TermuxState::NotDetected,
        );
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
        let report = snapshot(None, CredentialResolution::Error, TermuxState::NotDetected);
        assert_eq!(report.providers_configured, 0);
        assert_eq!(report.credential_resolution, CredentialResolution::Error);
    }
}
