// Unit tests for the pure SSID classifier. Moved verbatim from
// `modules::wigle::tests` when the classifier itself moved to `util::wifi` so
// the engine's autonomous-seeding gate and the WiGLE request gate share one
// implementation. The assertions are unchanged — they pin the same
// whole-token-vs-substring behaviour that protects `Freeman-Family` and friends.

use super::*;

#[test]
fn is_generic_ssid_matches_known_substrings_case_insensitively() {
    assert!(is_generic_ssid("linksys"));
    assert!(is_generic_ssid("xfinitywifi"));
    assert!(is_generic_ssid("NETGEAR-Guest"));
    assert!(is_generic_ssid("Telstra-Home-123"));
    assert!(is_generic_ssid("Free Public WiFi"));
}

#[test]
fn is_generic_ssid_rejects_custom_names() {
    assert!(!is_generic_ssid("Smith-Family"));
    assert!(!is_generic_ssid("Bamford-Residence"));
    assert!(!is_generic_ssid(""));
}

/// Personal names that a substring match wrongly classified as generic.
///
/// Each contains a short generic WORD as a letter-run: `free`man, se`att`le,
/// `test`a, `open`shaw, han`cox`. `ssid_search` consults this gate BEFORE
/// issuing any request, so every one of these subjects was silently skipped —
/// the module's whole "a unique SSID geolocates its owner" capability, dead for
/// an entire class of ordinary surnames.
#[test]
fn is_generic_ssid_admits_names_containing_generic_letter_runs() {
    for ssid in [
        "Freeman-Family",
        "Seattle-Cafe",
        "Testa-Household",
        "Openshaw-House",
        "Hancox-Home",
        "Attwood-Residence",
        "Nbnalla-House",
    ] {
        assert!(
            !is_generic_ssid(ssid),
            "{ssid} is a personal network, not a generic/default name"
        );
    }
}

/// The whole-token rule must not weaken real generic detection: carrier and
/// default names still match, whether the term is a standalone token or
/// concatenated into the name.
#[test]
fn is_generic_ssid_still_catches_real_defaults() {
    for ssid in [
        "ATT4G",         // carrier prefix split at the letter/digit boundary
        "ATT-WiFi-2461", // standalone token
        "Free Public WiFi",
        "NETGEAR47", // concatenated brand
        "xfinitywifi",
        "ASUS_5G",
        "Guest",
        "default",
        "TP-LINK_A1B2",
        "Optus_C3D4",
    ] {
        assert!(is_generic_ssid(ssid), "{ssid} must be treated as generic");
    }
}

/// `wifi`/`wlan` are descriptive suffixes on personal names, not generic terms.
#[test]
fn is_generic_ssid_admits_personal_name_with_wifi_suffix() {
    assert!(!is_generic_ssid("Smith-WiFi"));
    assert!(!is_generic_ssid("Johnson WLAN"));
}
