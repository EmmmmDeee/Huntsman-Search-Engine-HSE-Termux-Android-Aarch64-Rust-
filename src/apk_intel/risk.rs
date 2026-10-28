//! The security-posture flags a decoded `AndroidManifest.xml` warrants: the facts `axml` already
//! read (debuggable, cleartext traffic, exported components, dangerous permissions) projected into
//! a ranked set an investigator can read at a glance, the way a mobile app-security review or
//! `MobSF`'s manifest analysis grades them.
//!
//! Every flag is a statement about what the manifest declares, graded by how much it widens the
//! app's attack surface or what it can collect — never a claim about what the app does at runtime.
//! Nothing here reads beyond the manifest `axml` already parsed.

use serde::Serialize;

use super::axml::{Exposure, Manifest};
use crate::sf_correlate::Risk;

/// One graded observation about the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flag {
    pub risk: Risk,
    /// A short, stable identifier for the flag.
    pub id: &'static str,
    /// What was found, in words.
    pub detail: String,
}

/// The runtime permissions worth surfacing: those Android classes as dangerous or that grant broad
/// reach over the device's data, communications, sensors or other apps. The label is how the flag
/// reads it.
const SENSITIVE_PERMISSIONS: &[(&str, &str)] = &[
    ("android.permission.READ_SMS", "read SMS messages"),
    ("android.permission.SEND_SMS", "send SMS messages"),
    ("android.permission.RECEIVE_SMS", "receive SMS messages"),
    ("android.permission.READ_CONTACTS", "read contacts"),
    ("android.permission.READ_CALL_LOG", "read the call log"),
    (
        "android.permission.PROCESS_OUTGOING_CALLS",
        "see outgoing calls",
    ),
    (
        "android.permission.ACCESS_FINE_LOCATION",
        "read precise location",
    ),
    (
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "read location in the background",
    ),
    ("android.permission.RECORD_AUDIO", "record audio"),
    ("android.permission.CAMERA", "use the camera"),
    (
        "android.permission.READ_PHONE_STATE",
        "read phone state and identifiers",
    ),
    (
        "android.permission.READ_PHONE_NUMBERS",
        "read the device phone numbers",
    ),
    ("android.permission.GET_ACCOUNTS", "list device accounts"),
    (
        "android.permission.READ_EXTERNAL_STORAGE",
        "read shared storage",
    ),
    (
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "manage all shared storage",
    ),
    (
        "android.permission.QUERY_ALL_PACKAGES",
        "see every installed app",
    ),
    (
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "install other apps",
    ),
    (
        "android.permission.SYSTEM_ALERT_WINDOW",
        "draw over other apps",
    ),
    (
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "run an accessibility service",
    ),
    (
        "android.permission.BIND_DEVICE_ADMIN",
        "act as a device administrator",
    ),
    (
        "android.permission.READ_PRIVILEGED_PHONE_STATE",
        "read privileged phone state",
    ),
];

/// The manifest's security-posture flags, highest risk first. Empty when the manifest declares
/// nothing of note.
#[must_use]
pub fn flags(manifest: &Manifest) -> Vec<Flag> {
    let mut flags = Vec::new();
    let mut add =
        |risk: Risk, id: &'static str, detail: String| flags.push(Flag { risk, id, detail });

    if manifest.debuggable == Some(true) {
        add(
            Risk::High,
            "debuggable",
            "the application declares itself debuggable; an authorized debugger may inspect its process, subject to device debugging access and Android restrictions".to_owned(),
        );
    }
    if manifest.uses_cleartext_traffic == Some(true) {
        add(
            Risk::Medium,
            "cleartext_traffic",
            "the application permits cleartext (unencrypted HTTP) network traffic".to_owned(),
        );
    }
    if manifest.test_only == Some(true) {
        add(
            Risk::Medium,
            "test_only",
            "the application is marked testOnly: a development build, not a store release"
                .to_owned(),
        );
    }
    // allowBackup defaults to true, but effective backup and device-transfer behavior depends on
    // Android version, device policy and extraction rules. This is a declaration, not proof of extraction.
    if manifest.allow_backup != Some(false) {
        add(
            Risk::Low,
            "backup_allowed",
            "the manifest does not disable backup (allowBackup is not false); actual cloud backup and device transfer depend on Android version, device policy and extraction rules".to_owned(),
        );
    }
    if manifest.shared_user_id.is_some() {
        add(
            Risk::Low,
            "shared_user_id",
            format!(
                "the application shares a Linux user id ({}) with other apps signed by the same key",
                manifest.shared_user_id.as_deref().unwrap_or_default()
            ),
        );
    }
    let exported = manifest
        .reachable_components
        .iter()
        .filter(|component| component.exposure == Exposure::Exported)
        .count();
    if exported > 0 {
        add(
            Risk::Low,
            "exported_components",
            format!(
                "{exported} components declare exported=true; other apps may invoke them subject to permissions and platform restrictions"
            ),
        );
    }
    let implicit = manifest
        .reachable_components
        .iter()
        .filter(|component| component.exposure == Exposure::ImplicitByIntentFilter)
        .count();
    if implicit > 0 {
        add(
            Risk::Info,
            "implicitly_reachable_components",
            format!(
                "{implicit} component{} reachable through an intent filter without an explicit exported flag (other apps can start them on Android 11 and earlier)",
                if implicit == 1 { " is" } else { "s are" }
            ),
        );
    }
    for (permission, label) in SENSITIVE_PERMISSIONS {
        if manifest.permissions.iter().any(|held| held == permission) {
            add(
                Risk::Info,
                "sensitive_permission",
                format!("requests permission to {label} ({permission})"),
            );
        }
    }
    flags.sort_by(|a, b| a.risk.cmp(&b.risk).then_with(|| a.id.cmp(b.id)));
    flags
}

/// The highest risk among `flags`, for a one-line summary; `None` when there are none.
#[must_use]
pub fn highest(flags: &[Flag]) -> Option<Risk> {
    flags.iter().map(|flag| flag.risk).min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apk_intel::axml::{Component, Exposure};

    fn manifest() -> Manifest {
        Manifest {
            debuggable: Some(true),
            uses_cleartext_traffic: Some(true),
            allow_backup: Some(true),
            permissions: vec![
                "android.permission.INTERNET".to_owned(),
                "android.permission.READ_SMS".to_owned(),
                "android.permission.ACCESS_FINE_LOCATION".to_owned(),
            ],
            reachable_components: vec![
                Component {
                    kind: "activity".to_owned(),
                    name: ".Main".to_owned(),
                    exposure: Exposure::Exported,
                },
                Component {
                    kind: "receiver".to_owned(),
                    name: ".Boot".to_owned(),
                    exposure: Exposure::ImplicitByIntentFilter,
                },
            ],
            ..Manifest::default()
        }
    }

    #[test]
    fn the_manifests_posture_is_graded_highest_risk_first() {
        let flags = flags(&manifest());
        let ids: Vec<(&str, &str)> = flags
            .iter()
            .map(|flag| (flag.risk.as_str(), flag.id))
            .collect();
        assert_eq!(
            ids,
            [
                ("HIGH", "debuggable"),
                ("MEDIUM", "cleartext_traffic"),
                ("LOW", "backup_allowed"),
                ("LOW", "exported_components"),
                ("INFO", "implicitly_reachable_components"),
                ("INFO", "sensitive_permission"), // ACCESS_FINE_LOCATION
                ("INFO", "sensitive_permission"), // READ_SMS
            ]
        );
        assert_eq!(highest(&flags), Some(Risk::High));
        // The INTERNET permission is not sensitive, so it raises no flag.
        assert!(
            !flags.iter().any(|flag| flag.detail.contains("INTERNET")),
            "{flags:?}"
        );
    }

    #[test]
    fn a_hardened_manifest_raises_only_what_it_declares() {
        let hardened = Manifest {
            debuggable: Some(false),
            uses_cleartext_traffic: Some(false),
            allow_backup: Some(false),
            permissions: vec!["android.permission.INTERNET".to_owned()],
            ..Manifest::default()
        };
        assert!(flags(&hardened).is_empty());
        assert_eq!(highest(&flags(&hardened)), None);
    }

    #[test]
    fn posture_flags_do_not_claim_unrestricted_device_access_or_confirmed_extraction() {
        let observations = flags(&manifest());
        let debuggable = observations
            .iter()
            .find(|flag| flag.id == "debuggable")
            .unwrap();
        assert!(debuggable.detail.contains("authorized debugger"));
        assert!(!debuggable.detail.contains("any user"));

        let backup = observations
            .iter()
            .find(|flag| flag.id == "backup_allowed")
            .unwrap();
        assert!(backup.detail.contains("device policy"));
        assert!(!backup.detail.contains("extracted over adb"));

        let exported = observations
            .iter()
            .find(|flag| flag.id == "exported_components")
            .unwrap();
        assert!(
            exported
                .detail
                .contains("permissions and platform restrictions")
        );
    }

    #[test]
    fn allow_backup_unset_is_itself_the_permissive_case() {
        let manifest = Manifest::default();
        let flags = flags(&manifest);
        assert!(flags.iter().any(|flag| flag.id == "backup_allowed"));
    }
}
