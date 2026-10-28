//! Android Permission-to-Capability Mapping: Correlate declared permissions with actual sensitive data access capabilities.
//!
//! This module maps each Android runtime permission to the concrete capabilities it unlocks:
//! data access (contacts, SMS, call logs), device sensors (location, camera, microphone),
//! inter-app communication, package installation, and privileged operations. Capabilities are
//! identified at the Android API level (the actual code that permissions guard), not the
//! permission-group level. This enables correlation with intent filters and component exposure.

use serde::Serialize;

/// A single Android capability (data access, sensor, communication, privilege).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capability {
    /// Machine-readable identifier: e.g., "contacts_read", "location_precise", "camera_access".
    pub id: String,
    /// Human-readable capability name.
    pub name: String,
    /// What the capability provides: "data access", "sensor", "communication", "privilege", "installation".
    pub capability_kind: String,
    /// Sensitivity level: "critical" (PII/biometric), "high" (device state), "medium" (shared data), "low" (public).
    pub sensitivity: String,
    /// Permissions that unlock this capability.
    pub required_permissions: Vec<String>,
    /// Whether this capability is restricted by Android permission model (runtime permissions on API 23+).
    pub is_runtime_permission: bool,
}

/// Mapping of permission to the capabilities it controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PermissionCapability {
    /// Android permission constant name (e.g., "android.permission.READ_CONTACTS").
    pub permission: String,
    /// Capabilities this permission unlocks.
    pub capabilities: Vec<String>,
    /// Whether this is a runtime (dangerous) permission.
    pub is_dangerous: bool,
    /// Associated capability kind.
    pub capability_kind: String,
}

/// Permission-to-capability analysis results.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CapabilityAnalysis {
    /// All declared permissions mapped to capabilities.
    pub permission_capabilities: Vec<PermissionCapability>,
    /// Permission-capability mappings omitted from the list (when limit exceeded).
    pub permission_capabilities_omitted: usize,
    /// Capabilities the app declares permissions to access.
    pub declared_capabilities: Vec<String>,
    /// Capabilities omitted from the list.
    pub declared_capabilities_omitted: usize,
    /// Critical capabilities (PII, biometrics, identifiers).
    pub critical_capabilities: Vec<String>,
    /// Critical capabilities omitted from the list.
    pub critical_capabilities_omitted: usize,
    /// Dangerous permissions without corresponding intent handler (declared but possibly unused).
    pub unhandled_dangerous_permissions: Vec<String>,
    /// Intent handlers that match critical capabilities.
    pub critical_intent_handlers: Vec<String>,
    /// Overall capability risk score: sum of critical capabilities.
    pub capability_risk_score: u32,
}

/// Map a single permission to its capabilities and risk level.
pub fn permission_to_capabilities(
    permission: &str,
) -> Option<(&'static str, &'static [&'static str])> {
    match permission {
        // SMS & messaging
        "android.permission.READ_SMS" => Some(("sms_read", &["read_sms", "access_messages"])),
        "android.permission.SEND_SMS" => Some(("sms_send", &["send_sms", "control_messages"])),
        "android.permission.RECEIVE_SMS" => Some(("sms_receive", &["receive_sms"])),

        // Contacts & people
        "android.permission.READ_CONTACTS" => {
            Some(("contacts_read", &["read_contacts", "access_identity"]))
        }
        "android.permission.WRITE_CONTACTS" => Some(("contacts_write", &["modify_contacts"])),

        // Call logs & phone
        "android.permission.READ_CALL_LOG" => Some(("call_log_read", &["read_call_history"])),
        "android.permission.WRITE_CALL_LOG" => Some(("call_log_write", &["modify_call_history"])),
        "android.permission.PROCESS_OUTGOING_CALLS" => {
            Some(("call_interception", &["intercept_calls"]))
        }
        "android.permission.READ_PHONE_STATE" => {
            Some(("phone_state_read", &["read_phone_state", "access_identity"]))
        }
        "android.permission.READ_PHONE_NUMBERS" => Some((
            "phone_numbers_read",
            &["read_phone_numbers", "access_identity"],
        )),
        "android.permission.READ_PRIVILEGED_PHONE_STATE" => {
            Some(("phone_state_privileged", &["read_phone_state_privileged"]))
        }

        // Location
        "android.permission.ACCESS_FINE_LOCATION" => Some((
            "location_precise",
            &["read_location", "access_location_gps"],
        )),
        "android.permission.ACCESS_COARSE_LOCATION" => Some((
            "location_coarse",
            &["read_location", "access_location_network"],
        )),
        "android.permission.ACCESS_BACKGROUND_LOCATION" => {
            Some(("location_background", &["track_location_background"]))
        }

        // Biometrics & sensors
        "android.permission.CAMERA" => Some(("camera_access", &["capture_camera"])),
        "android.permission.RECORD_AUDIO" => Some(("microphone_access", &["capture_audio"])),
        "android.permission.BODY_SENSORS" => Some(("sensors_read", &["read_motion_sensors"])),

        // Accounts
        "android.permission.GET_ACCOUNTS" => Some(("accounts_enumerate", &["list_accounts"])),

        // Storage
        "android.permission.READ_EXTERNAL_STORAGE" => {
            Some(("storage_read", &["read_shared_storage"]))
        }
        "android.permission.WRITE_EXTERNAL_STORAGE" => {
            Some(("storage_write", &["write_shared_storage"]))
        }
        "android.permission.MANAGE_EXTERNAL_STORAGE" => {
            Some(("storage_manage", &["manage_all_storage"]))
        }

        // Package & app management
        "android.permission.QUERY_ALL_PACKAGES" => Some(("packages_enumerate", &["list_all_apps"])),
        "android.permission.REQUEST_INSTALL_PACKAGES" => {
            Some(("install_packages", &["install_apps"]))
        }
        "android.permission.REQUEST_DELETE_PACKAGES" => {
            Some(("uninstall_packages", &["uninstall_apps"]))
        }

        // System & privilege
        "android.permission.SYSTEM_ALERT_WINDOW" => Some(("overlay_draw", &["draw_over_apps"])),
        "android.permission.BIND_ACCESSIBILITY_SERVICE" => {
            Some(("accessibility_service", &["run_accessibility_service"]))
        }
        "android.permission.BIND_DEVICE_ADMIN" => {
            Some(("device_admin", &["device_administration"]))
        }

        // Communication
        "android.permission.INTERNET" => Some(("network_internet", &["network_access"])),

        // Other
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sms_read_maps_to_message_access_capability() {
        let result = permission_to_capabilities("android.permission.READ_SMS");
        assert!(result.is_some());
        let (kind, caps) = result.unwrap();
        assert_eq!(kind, "sms_read");
        assert!(caps.contains(&"read_sms"));
    }

    #[test]
    fn contacts_permission_maps_to_identity_access() {
        let result = permission_to_capabilities("android.permission.READ_CONTACTS");
        assert!(result.is_some());
        let (kind, caps) = result.unwrap();
        assert_eq!(kind, "contacts_read");
        assert!(caps.contains(&"access_identity"));
    }

    #[test]
    fn location_permissions_map_correctly() {
        let fine = permission_to_capabilities("android.permission.ACCESS_FINE_LOCATION");
        let coarse = permission_to_capabilities("android.permission.ACCESS_COARSE_LOCATION");

        assert!(fine.is_some());
        assert!(coarse.is_some());

        let (fine_kind, _) = fine.unwrap();
        let (coarse_kind, _) = coarse.unwrap();

        assert_eq!(fine_kind, "location_precise");
        assert_eq!(coarse_kind, "location_coarse");
    }

    #[test]
    fn camera_and_microphone_are_biometric_sensors() {
        let camera = permission_to_capabilities("android.permission.CAMERA");
        let audio = permission_to_capabilities("android.permission.RECORD_AUDIO");

        assert!(camera.is_some());
        assert!(audio.is_some());

        let (camera_kind, _) = camera.unwrap();
        let (audio_kind, _) = audio.unwrap();

        assert_eq!(camera_kind, "camera_access");
        assert_eq!(audio_kind, "microphone_access");
    }

    #[test]
    fn query_all_packages_enables_app_enumeration() {
        let result = permission_to_capabilities("android.permission.QUERY_ALL_PACKAGES");
        assert!(result.is_some());
        let (kind, caps) = result.unwrap();
        assert_eq!(kind, "packages_enumerate");
        assert!(caps.contains(&"list_all_apps"));
    }

    #[test]
    fn device_admin_permission_unlocks_privileged_control() {
        let result = permission_to_capabilities("android.permission.BIND_DEVICE_ADMIN");
        assert!(result.is_some());
        let (_, caps) = result.unwrap();
        assert!(caps.contains(&"device_administration"));
    }

    #[test]
    fn unknown_permission_returns_none() {
        let result = permission_to_capabilities("com.example.UNKNOWN_PERMISSION");
        assert!(result.is_none());
    }

    #[test]
    fn internet_permission_grants_network_access() {
        let result = permission_to_capabilities("android.permission.INTERNET");
        assert!(result.is_some());
        let (kind, _) = result.unwrap();
        assert_eq!(kind, "network_internet");
    }

    #[test]
    fn storage_permissions_distinguish_access_levels() {
        let read = permission_to_capabilities("android.permission.READ_EXTERNAL_STORAGE");
        let write = permission_to_capabilities("android.permission.WRITE_EXTERNAL_STORAGE");
        let manage = permission_to_capabilities("android.permission.MANAGE_EXTERNAL_STORAGE");

        assert!(read.is_some());
        assert!(write.is_some());
        assert!(manage.is_some());

        let (read_kind, _) = read.unwrap();
        let (write_kind, _) = write.unwrap();
        let (manage_kind, _) = manage.unwrap();

        assert_eq!(read_kind, "storage_read");
        assert_eq!(write_kind, "storage_write");
        assert_eq!(manage_kind, "storage_manage");
    }

    #[test]
    fn package_management_permissions_enable_installation_control() {
        let install = permission_to_capabilities("android.permission.REQUEST_INSTALL_PACKAGES");
        let uninstall = permission_to_capabilities("android.permission.REQUEST_DELETE_PACKAGES");

        assert!(install.is_some());
        assert!(uninstall.is_some());

        let (install_kind, _) = install.unwrap();
        let (uninstall_kind, _) = uninstall.unwrap();

        assert_eq!(install_kind, "install_packages");
        assert_eq!(uninstall_kind, "uninstall_packages");
    }

    #[test]
    fn capability_analysis_default_is_empty() {
        let analysis = CapabilityAnalysis::default();
        assert!(analysis.permission_capabilities.is_empty());
        assert!(analysis.declared_capabilities.is_empty());
        assert_eq!(analysis.capability_risk_score, 0);
    }

    #[test]
    fn permission_capability_struct_represents_mapping() {
        let perm_cap = PermissionCapability {
            permission: "android.permission.READ_CONTACTS".to_string(),
            capabilities: vec!["read_contacts".to_string(), "access_identity".to_string()],
            is_dangerous: true,
            capability_kind: "contacts_read".to_string(),
        };

        assert_eq!(perm_cap.permission, "android.permission.READ_CONTACTS");
        assert!(perm_cap.is_dangerous);
        assert_eq!(perm_cap.capabilities.len(), 2);
    }

    #[test]
    fn capability_struct_captures_complete_metadata() {
        let cap = Capability {
            id: "location_precise".to_string(),
            name: "Precise Location Access".to_string(),
            capability_kind: "sensor".to_string(),
            sensitivity: "critical".to_string(),
            required_permissions: vec!["android.permission.ACCESS_FINE_LOCATION".to_string()],
            is_runtime_permission: true,
        };

        assert_eq!(cap.id, "location_precise");
        assert_eq!(cap.capability_kind, "sensor");
        assert_eq!(cap.sensitivity, "critical");
        assert!(cap.is_runtime_permission);
    }
}
