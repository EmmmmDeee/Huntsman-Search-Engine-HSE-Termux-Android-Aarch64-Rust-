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

/// Parse an Android SDK level string (typically "30", "31", etc.) to an integer.
fn parse_sdk(sdk_str: &str) -> Option<u32> {
    sdk_str.trim().parse().ok()
}

/// Check SDK version risks (target and minimum) and return flags.
fn check_sdk_versions(manifest: &Manifest) -> Vec<Flag> {
    let mut sdk_flags = Vec::new();
    if let Some(target_sdk_str) = manifest.target_sdk.as_deref() {
        if let Some(target_sdk) = parse_sdk(target_sdk_str) {
            if target_sdk < 28 {
                sdk_flags.push(Flag {
                    risk: Risk::High,
                    id: "target_sdk_too_old",
                    detail: format!("the application targets Android SDK {target_sdk} (below 9.0/API 28); it does not benefit from modern platform hardening, container isolation, scoped storage and other protections introduced in Android 9 and later"),
                });
            } else if target_sdk < 31 {
                let api_name = if target_sdk == 29 {
                    "10 (Q)"
                } else if target_sdk == 30 {
                    "11 (R)"
                } else {
                    "9 (P)"
                };
                sdk_flags.push(Flag {
                    risk: Risk::Medium,
                    id: "target_sdk_not_current",
                    detail: format!("the application targets Android SDK {target_sdk} (API {api_name}); it does not receive protections from Android 12 and later, including restricted implicit intents, package visibility, and restricted non-SDK interfaces"),
                });
            }
        }
    }
    if let Some(min_sdk_str) = manifest.min_sdk.as_deref() {
        if let Some(min_sdk) = parse_sdk(min_sdk_str) {
            if min_sdk < 21 {
                sdk_flags.push(Flag {
                    risk: Risk::Medium,
                    id: "min_sdk_too_old",
                    detail: format!("the application declares a minimum SDK {min_sdk} (below 5.0/API 21); it is compatible with Android versions that lack modern platform security features"),
                });
            }
        }
    }
    sdk_flags
}

/// The manifest's security-posture flags, highest risk first. Empty when the manifest declares
/// nothing of note.
#[must_use]
pub fn flags(manifest: &Manifest) -> Vec<Flag> {
    let mut flags = check_sdk_versions(manifest);
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
    if let Some(provider_flag) = check_provider_authorities(manifest) {
        add(provider_flag.risk, provider_flag.id, provider_flag.detail);
    }
    flags.sort_by(|a, b| a.risk.cmp(&b.risk).then_with(|| a.id.cmp(b.id)));
    flags
}

/// Check for reachable content providers with sensitive data and return a flag if found.
fn check_provider_authorities(manifest: &Manifest) -> Option<Flag> {
    let sensitive_count = manifest
        .explicitly_exported_provider_authorities
        .iter()
        .filter(|authority| is_sensitive_authority(authority))
        .count();
    (sensitive_count > 0).then(|| Flag {
        risk: Risk::Medium,
        id: "reachable_content_provider",
        detail: format!(
            "{sensitive_count} explicitly exported provider authorit{} contain sensitive-data name indicators; manifest names do not prove what data is stored or accessible, and provider permissions may restrict access",
            if sensitive_count == 1 { "y" } else { "ies" }
        ),
    })
}

/// Authority names are weak indicators, not evidence of actual content.
fn is_sensitive_authority(authority: &str) -> bool {
    authority
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|segment| {
            matches!(
                segment,
                "contacts"
                    | "sms"
                    | "mms"
                    | "calendar"
                    | "call_log"
                    | "calllog"
                    | "email"
                    | "gmail"
                    | "mtp"
                    | "media"
                    | "files"
                    | "document"
                    | "clipboard"
                    | "settings"
            )
        })
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

    #[test]
    fn reachable_providers_with_sensitive_data_are_flagged() {
        let manifest = Manifest {
            reachable_components: vec![Component {
                kind: "provider".to_owned(),
                name: ".ContentProvider".to_owned(),
                exposure: Exposure::Exported,
            }],
            explicitly_exported_provider_authorities: vec!["com.example.contacts".to_owned()],
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            observed
                .iter()
                .any(|flag| flag.id == "reachable_content_provider")
        );
        let provider_flag = observed
            .iter()
            .find(|flag| flag.id == "reachable_content_provider")
            .unwrap();
        assert_eq!(provider_flag.risk, Risk::Medium);
        assert!(provider_flag.detail.contains("manifest names do not prove"));
    }

    #[test]
    fn providers_without_sensitive_authorities_are_not_flagged() {
        let manifest = Manifest {
            reachable_components: vec![Component {
                kind: "provider".to_owned(),
                name: ".DataProvider".to_owned(),
                exposure: Exposure::Exported,
            }],
            explicitly_exported_provider_authorities: vec!["com.example.data".to_owned()],
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            !observed
                .iter()
                .any(|flag| flag.id == "reachable_content_provider")
        );
    }

    #[test]
    fn is_sensitive_authority_detects_contact_calendar_sms_email_patterns() {
        assert!(is_sensitive_authority("com.android.contacts.provider"));
        assert!(is_sensitive_authority("com.android.calendar"));
        assert!(is_sensitive_authority("com.android.sms"));
        assert!(is_sensitive_authority("com.android.call_log"));
        assert!(is_sensitive_authority(
            "com.google.android.gm.email.provider"
        ));
        assert!(!is_sensitive_authority("com.example.data"));
        assert!(!is_sensitive_authority("com.example.appdata"));
    }

    #[test]
    fn target_sdk_too_old_is_flagged_as_high_risk() {
        let manifest = Manifest {
            target_sdk: Some("27".to_owned()),
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            observed
                .iter()
                .any(|flag| flag.id == "target_sdk_too_old" && flag.risk == Risk::High),
            "target SDK 27 should be flagged as HIGH risk"
        );
    }

    #[test]
    fn target_sdk_between_28_and_30_is_flagged_as_medium_risk() {
        let manifest = Manifest {
            target_sdk: Some("29".to_owned()),
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            observed
                .iter()
                .any(|flag| flag.id == "target_sdk_not_current" && flag.risk == Risk::Medium),
            "target SDK 29 should be flagged as MEDIUM risk"
        );
    }

    #[test]
    fn target_sdk_31_or_above_does_not_trigger_sdk_flags() {
        let manifest = Manifest {
            target_sdk: Some("31".to_owned()),
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            !observed.iter().any(|flag| flag.id.contains("target_sdk")),
            "target SDK 31 should not trigger SDK flags"
        );
    }

    #[test]
    fn min_sdk_below_21_is_flagged() {
        let manifest = Manifest {
            min_sdk: Some("19".to_owned()),
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            observed
                .iter()
                .any(|flag| flag.id == "min_sdk_too_old" && flag.risk == Risk::Medium),
            "min SDK 19 should be flagged as MEDIUM risk"
        );
    }

    #[test]
    fn min_sdk_21_or_above_does_not_trigger_min_sdk_flag() {
        let manifest = Manifest {
            min_sdk: Some("21".to_owned()),
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            !observed.iter().any(|flag| flag.id == "min_sdk_too_old"),
            "min SDK 21 should not trigger min_sdk_too_old flag"
        );
    }

    #[test]
    fn target_sdk_boundary_28_triggers_medium_risk() {
        let manifest = Manifest {
            target_sdk: Some("28".to_owned()),
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            observed
                .iter()
                .any(|flag| flag.id == "target_sdk_not_current" && flag.risk == Risk::Medium),
            "target SDK 28 (boundary) should be flagged as MEDIUM risk"
        );
    }

    #[test]
    fn target_sdk_boundary_30_triggers_medium_risk() {
        let manifest = Manifest {
            target_sdk: Some("30".to_owned()),
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            observed
                .iter()
                .any(|flag| flag.id == "target_sdk_not_current" && flag.risk == Risk::Medium),
            "target SDK 30 (boundary) should be flagged as MEDIUM risk"
        );
    }

    #[test]
    fn target_sdk_boundary_27_triggers_high_risk() {
        let manifest = Manifest {
            target_sdk: Some("27".to_owned()),
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            observed
                .iter()
                .any(|flag| flag.id == "target_sdk_too_old" && flag.risk == Risk::High),
            "target SDK 27 (boundary) should be flagged as HIGH risk"
        );
    }

    #[test]
    fn target_sdk_boundary_31_does_not_trigger_flags() {
        let manifest = Manifest {
            target_sdk: Some("31".to_owned()),
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            !observed.iter().any(|flag| flag.id.contains("target_sdk")),
            "target SDK 31 (boundary) should not trigger SDK flags"
        );
    }

    #[test]
    fn min_sdk_boundary_20_triggers_medium_risk() {
        let manifest = Manifest {
            min_sdk: Some("20".to_owned()),
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        assert!(
            observed
                .iter()
                .any(|flag| flag.id == "min_sdk_too_old" && flag.risk == Risk::Medium),
            "min SDK 20 (boundary) should be flagged as MEDIUM risk"
        );
    }

    #[test]
    fn implicit_intent_filter_alone_does_not_prove_provider_export() {
        let manifest = Manifest {
            reachable_components: vec![Component {
                kind: "provider".to_owned(),
                name: ".SensitiveProvider".to_owned(),
                exposure: Exposure::ImplicitByIntentFilter,
            }],
            provider_authorities: vec!["com.android.contacts.provider".to_owned()],
            ..Manifest::default()
        };
        assert!(
            !flags(&manifest)
                .iter()
                .any(|flag| flag.id == "reachable_content_provider"),
            "an intent filter does not establish provider export or access"
        );
    }

    #[test]
    fn multiple_providers_with_mixed_sensitivities_flags_only_sensitive() {
        let manifest = Manifest {
            reachable_components: vec![
                Component {
                    kind: "provider".to_owned(),
                    name: ".ContactsProvider".to_owned(),
                    exposure: Exposure::Exported,
                },
                Component {
                    kind: "provider".to_owned(),
                    name: ".DataProvider".to_owned(),
                    exposure: Exposure::Exported,
                },
            ],
            explicitly_exported_provider_authorities: vec![
                "com.android.contacts.provider".to_owned(),
                "com.example.data".to_owned(),
            ],
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        let provider_flags: Vec<_> = observed
            .iter()
            .filter(|flag| flag.id == "reachable_content_provider")
            .collect();
        assert_eq!(
            provider_flags.len(),
            1,
            "only sensitive provider should be flagged"
        );
    }

    #[test]
    fn authority_patterns_detect_case_insensitive_matches() {
        assert!(is_sensitive_authority("COM.ANDROID.CONTACTS.PROVIDER"));
        assert!(is_sensitive_authority("Com.Android.Calendar"));
        assert!(is_sensitive_authority("com.ANDROID.sms"));
    }

    #[test]
    fn combined_high_and_medium_risks_maintains_order() {
        let manifest = Manifest {
            debuggable: Some(true),
            target_sdk: Some("29".to_owned()),
            min_sdk: Some("20".to_owned()),
            reachable_components: vec![Component {
                kind: "provider".to_owned(),
                name: ".Provider".to_owned(),
                exposure: Exposure::Exported,
            }],
            explicitly_exported_provider_authorities: vec!["com.android.sms".to_owned()],
            ..Manifest::default()
        };
        let observed = flags(&manifest);
        let risk_order: Vec<&str> = observed.iter().map(|f| f.risk.as_str()).collect();
        assert!(
            risk_order[0] == "HIGH",
            "first flag should be HIGH risk (debuggable), got: {risk_order:?}"
        );
        let medium_flags: Vec<_> = observed.iter().filter(|f| f.risk == Risk::Medium).collect();
        assert!(
            medium_flags.len() >= 2,
            "should have at least 2 MEDIUM flags"
        );
    }
    #[test]
    fn private_authority_does_not_contaminate_unrelated_exported_provider() {
        let manifest = Manifest {
            reachable_components: vec![Component {
                kind: "provider".to_owned(),
                name: ".Public".to_owned(),
                exposure: Exposure::Exported,
            }],
            provider_authorities: vec![
                "com.example.public".to_owned(),
                "com.example.contacts".to_owned(),
            ],
            explicitly_exported_provider_authorities: vec!["com.example.public".to_owned()],
            ..Manifest::default()
        };
        assert!(
            !flags(&manifest)
                .iter()
                .any(|flag| flag.id == "reachable_content_provider")
        );
    }

    #[test]
    fn sensitive_authority_matching_respects_name_boundaries() {
        assert!(!is_sensitive_authority("com.example.contactsimpostor"));
        assert!(!is_sensitive_authority("com.example.mysettings"));
        assert!(is_sensitive_authority("com.example.call_log"));
    }}
